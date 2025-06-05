// Copyright 2024, 2025 RISC Zero, Inc.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

use crate::args::parse_address;
use crate::boundless::BoundlessArgs;
use crate::{bonsai, boundless, proof, witgen, zkvm};
use alloy_primitives::{Address, B256};
use anyhow::anyhow;
use clap::Parser;
use kailua_common::boot::StitchedBootInfo;
use kailua_common::client::stitching::split_executions;
use kailua_common::executor::Execution;
use kailua_common::journal::ProofJournal;
use kailua_common::oracle::vec::{PreimageVecEntry, VecOracle};
use kailua_common::witness::Witness;
use kona_preimage::{HintWriterClient, PreimageOracleClient};
use kona_proof::l1::OracleBlobProvider;
use kona_proof::CachingOracle;
use risc0_zkvm::{is_dev_mode, Receipt};
use std::fmt::Debug;
use std::sync::Arc;
use tokio::fs::File;
use tokio::io::AsyncWriteExt;
use tracing::{error, info, warn};

/// The size of the LRU cache in the oracle.
pub const ORACLE_LRU_SIZE: usize = 1024;

#[derive(Parser, Clone, Debug)]
pub struct ProvingArgs {
    #[clap(long, env, value_parser = parse_address)]
    pub payout_recipient_address: Option<Address>,
    #[clap(long, env, required = false, default_value_t = 21)]
    pub segment_limit: u32,
    #[clap(long, env, required = false, default_value_t = 2_684_354_560)]
    pub max_witness_size: usize,
    #[clap(long, env, default_value_t = false)]
    pub skip_derivation_proof: bool,
    #[clap(long, env, default_value_t = false)]
    pub skip_await_proof: bool,
}

#[derive(Debug, thiserror::Error)]
pub enum ProvingError {
    #[error("DerivationProofError error: execution proofs {0}")]
    DerivationProofError(usize),

    #[error("SeekProofError error: witness {0}")]
    SeekProofError(usize, Vec<Vec<Execution>>),

    #[error("WitnessSizeError error: size {0} limit {0}")]
    WitnessSizeError(usize, usize, Vec<Vec<Execution>>),

    #[error("ExecutionError error: ZKVM failed {0:?}")]
    ExecutionError(anyhow::Error),

    #[error("OtherError error: {0:?}")]
    OtherError(anyhow::Error),
}

/// Use our own version of SessionStats to avoid non-exhaustive issues (risc0_zkvm::SessionStats)
#[derive(Debug, Clone)]
pub struct KailuaSessionStats {
    pub segments: usize,
    pub total_cycles: u64,
    pub user_cycles: u64,
    pub paging_cycles: u64,
    pub reserved_cycles: u64,
}

/// Our own version of ProveInfo to avoid non-exhaustive issues (risc0_zkvm::ProveInfo)
#[derive(Debug)]
pub struct KailuaProveInfo {
    pub receipt: Receipt,
    pub stats: KailuaSessionStats,
}

#[allow(clippy::too_many_arguments)]
pub async fn run_proving_client<P, H>(
    proving: ProvingArgs,
    boundless: BoundlessArgs,
    oracle_client: P,
    hint_client: H,
    precondition_validation_data_hash: B256,
    stitched_executions: Vec<Vec<Execution>>,
    stitched_boot_info: Vec<StitchedBootInfo>,
    stitched_proofs: Vec<Receipt>,
    prove_snark: bool,
    force_attempt: bool,
    seek_proof: bool,
) -> Result<(), ProvingError>
where
    P: PreimageOracleClient + Send + Sync + Debug + Clone + 'static,
    H: HintWriterClient + Send + Sync + Debug + Clone + 'static,
{
    // preload all data into the vec oracle
    // 阶段1：准备输入的已经存在的执行轨迹，可能为空
    let (_, execution_cache) = split_executions(stitched_executions.clone());
    info!(
        "Running vec witgen client with {} cached executions ({} traces).",
        execution_cache.len(),
        stitched_executions.len()
    );
    // 阶段2：生成见证数据（包含区块链状态转换的有效性证明所需的所有输入）
    let (proof_journal, mut witness_vec): (ProofJournal, Witness<VecOracle>) = {
        // Instantiate oracles
        // 2.1 初始化预映像服务
        // 创建带缓存的预映像预言机（LRU缓存提升性能，降低重复请求开销）
        let preimage_oracle = Arc::new(CachingOracle::new(
            ORACLE_LRU_SIZE,
            oracle_client,
            hint_client,
        ));
        let blob_provider = OracleBlobProvider::new(preimage_oracle.clone());
        // Run witness generation with oracles
        // 2.2 证明记录集，区块执行轨迹，boot信息
        // 根据boot，blob，L1，L2数据等，生成完整的执行轨迹，验证boot数据的正确性，并返回witness。
        witgen::run_witgen_client(
            preimage_oracle,  // 共享预映像服务实例
            10 * 1024 * 1024, // 数据分块大小（10MB），优化内存使用
            blob_provider,    // blob数据加载器
            proving.payout_recipient_address.unwrap_or_default(), // 零地址表示无收益接收者
            precondition_validation_data_hash, // 执行前状态验证哈希（确保数据一致性）
            execution_cache.clone(), // 克隆执行轨迹缓存（避免所有权转移）
            stitched_boot_info.clone(), // 克隆启动配置信息（L1/L2初始状态）
        )
            .await
            .expect("Failed to run vec witgen client.")
    };

    let execution_trace =
        core::mem::replace(&mut witness_vec.stitched_executions, stitched_executions);

    // sanity check kzg proofs
    let _ = kailua_common::blobs::PreloadedBlobProvider::from(witness_vec.blobs_witness.clone());

    // check if we can prove this workload
    // 阶段3：资源检查
    let (main_witness_size, witness_size) = sum_witness_size(&witness_vec);
    info!("Witness size: {witness_size} ({main_witness_size} main)");
    // 当见证数据总大小超过安全阈值时触发
    if witness_size > proving.max_witness_size {
        warn!(
            "Witness size {} exceeds limit {}.",
            witness_size, proving.max_witness_size
        );
        // 安全控制分支，当force_attempt为false时，中止证明过程，返回WitnessSizeError错误。
        if !force_attempt {
            warn!("Aborting.");
            return Err(ProvingError::WitnessSizeError(
                witness_size,        // 实际见证数据大小
                proving.max_witness_size, // 配置的最大允许值
                execution_trace,     // 当前执行轨迹（用于后续分治处理）
            ));
        }
        warn!("Continuing..");
    }

    // 阶段4：证明生成控制
    if !seek_proof {
        return Err(ProvingError::SeekProofError(witness_size, execution_trace));
    }

    // 阶段5：序列化见证数据
    let (preloaded_frames, streamed_frames) =
        encode_witness_frames(witness_vec).expect("Failed to encode VecOracle");
    // 阶段6：执行证明生成
    seek_fpvm_proof(
        &proving,
        boundless,
        proof_journal,
        [preloaded_frames, streamed_frames].concat(),
        stitched_proofs,
        prove_snark,
    )
        .await
}

#[allow(clippy::type_complexity)]
pub fn encode_witness_frames(
    witness_vec: Witness<VecOracle>,
) -> anyhow::Result<(Vec<Vec<u8>>, Vec<Vec<u8>>)> {
    // 序列化预加载数据分片
    // serialize preloaded shards
    let mut preloaded_data = witness_vec.oracle_witness.preimages.lock().unwrap();
    let shards = shard_witness_data(&mut preloaded_data)?; // 将预加载数据分片序列化
    drop(preloaded_data); // 及时释放锁避免死锁

    // 序列化流式数据分片（逆序处理以适配后续消费顺序）
    // serialize streamed data
    let mut streamed_data = witness_vec.stream_witness.preimages.lock().unwrap();
    let mut streams = shard_witness_data(&mut streamed_data)?;
    streams.reverse(); // 反转流式数据顺序以保持原始执行时序
    streamed_data.clear(); // 清空原始数据避免内存泄漏
    drop(streamed_data);

    // 序列化主见证对象（包含元数据和核心执行轨迹）
    // serialize main witness object
    let main_frame = rkyv::to_bytes::<rkyv::rancor::Error>(&witness_vec)
        .map_err(|e| ProvingError::OtherError(anyhow!(e)))? // 转换序列化错误类型
        .to_vec(); // 转换为字节向量

    // 合并主帧与预加载分片数据
    let preloaded_data = [vec![main_frame], shards].concat();

    Ok((preloaded_data, streams)) // 返回预加载帧集合和流式帧集合
}

///将见证数据分片序列化
pub fn shard_witness_data(data: &mut [PreimageVecEntry]) -> anyhow::Result<Vec<Vec<u8>>> {
    let mut shards = vec![];
    // 遍历每个预映像数据条目
    for entry in data {
        // 使用内存置换获取条目内容（原位置置为默认值，避免所有权问题）
        let shard = core::mem::take(entry);
        // 序列化分片数据为二进制格式
        shards.push(
            rkyv::to_bytes::<rkyv::rancor::Error>(&shard)
                // 转换序列化错误为统一错误类型
                .map_err(|e| ProvingError::OtherError(anyhow!(e)))?
                .to_vec(), // 将序列化结果转换为字节向量
        )
    }
    // 返回序列化后的分片集合
    Ok(shards)
}

pub fn sum_witness_size(witness: &Witness<VecOracle>) -> (usize, usize) {
    // 将见证数据编码为分片帧
    let (witness_frames, _) =
        encode_witness_frames(witness.deep_clone()).expect("Failed to encode VecOracle");
    (
        // 计算主见证数据大小（第一个分片
        witness_frames.first().map(|f| f.len()).unwrap(),
        // 计算总见证大小（所有分片之和）
        witness_frames.iter().map(|f| f.len()).sum::<usize>(),
    )
}
pub async fn seek_fpvm_proof(
    proving: &ProvingArgs,           // 证明生成配置参数
    boundless: BoundlessArgs,        // 分布式证明市场相关参数
    proof_journal: ProofJournal,     // 包含执行日志和元数据的证明记录
    witness_frames: Vec<Vec<u8>>,    // 序列化后的见证数据分片集合
    stitched_proofs: Vec<Receipt>,   // 需要拼接的子证明集合
    prove_snark: bool,               // 是否生成SNARK证明的标志
) -> Result<(), ProvingError> {
    // 计算zkvm证明（核心证明生成逻辑）
    let proof = match boundless.market {
        // 使用分布式证明市场生成证明（生产环境）
        Some(marked_provider_config) if !is_dev_mode() => {
            boundless::run_boundless_client(
                marked_provider_config,  // 市场提供方配置
                boundless.storage,      // 存储后端配置
                proof_journal,           // 包含L2链状态转换的证明日志
                witness_frames,         // 序列化后的执行轨迹数据
                stitched_proofs,         // 需要组合的子证明
                proving,                 // 证明参数
            )
            .await?
        }
        // 本地证明生成模式
        _ => {
            if bonsai::should_use_bonsai() {
                // 使用Bonsai云服务生成证明
                bonsai::run_bonsai_client(
                    witness_frames,     // 输入见证数据
                    stitched_proofs,    // 待拼接的证明片段 
                    prove_snark,       // SNARK生成开关
                    proving,            // 性能参数（如分段限制）
                )
                .await?
            } else {
                // 使用本地zkvm生成证明
                zkvm::run_zkvm_client(
                    witness_frames,     // 序列化的见证数据分片
                    stitched_proofs,    // 需要组合的证明片段
                    prove_snark,       // 控制是否生成最终SNARK
                    proving.segment_limit, // 分段证明的最大长度
                )
                .await?
            }
        }
    };
    // 持久化存储证明文件
    // 将生成的证明序列化后写入磁盘，文件命名格式为：proof_<区块高度>_<输出根哈希>.bin
    save_proof_to_disk(&proof).await;

    Ok(())
}


pub async fn save_proof_to_disk(proof: &Receipt) {
    // Save proof file to disk
    let proof_journal = ProofJournal::decode_packed(proof.journal.as_ref());
    let mut output_file = File::create(proof::proof_file_name(&proof_journal))
        .await
        .expect("Failed to create proof output file");
    // Write proof data to file
    let proof_bytes = bincode::serialize(proof).expect("Could not serialize proof.");
    output_file
        .write_all(proof_bytes.as_slice())
        .await
        .expect("Failed to write proof to file");
    output_file
        .flush()
        .await
        .expect("Failed to flush proof output file data.");
}
