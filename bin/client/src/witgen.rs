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

use crate::witness::{BlobWitnessProvider, OracleWitnessProvider};
use alloy_primitives::{Address, B256};
use kailua_build::KAILUA_FPVM_ID;
use kailua_common::blobs::BlobWitnessData;
use kailua_common::boot::StitchedBootInfo;
use kailua_common::executor::Execution;
use kailua_common::journal::ProofJournal;
use kailua_common::oracle::WitnessOracle;
use kailua_common::witness::Witness;
use kona_derive::prelude::BlobProvider;
use kona_preimage::CommsClient;
use kona_proof::FlushableCache;
use std::fmt::Debug;
use std::ops::DerefMut;
use std::sync::{Arc, Mutex};
use tracing::info;

///生成boot信息以及执行轨迹的Witness。
/// 根据boot，blob，L1，L2数据等，生成完整的执行轨迹，验证boot数据的正确性，并返回witness。
pub async fn run_witgen_client<P, B, O>(
    preimage_oracle: Arc<P>,         // 预映像数据源（boot，blob，L1，L2数据等）
    preimage_oracle_shard_size: usize, // 数据分片大小（优化内存使用）
    blob_provider: B,               // Blob数据提供器（已加载KZG证明的blob）
    payout_recipient: Address,      // 收益接收地址（证明生成者的奖励地址）
    precondition_validation_data_hash: B256, // 验证数据哈希（确保执行前状态）
    
    
    execution_cache: Vec<Arc<Execution>>, // 预存的执行轨迹缓存
    stitched_boot_info: Vec<StitchedBootInfo>, // 虚拟机启动配置集合
) -> anyhow::Result<(ProofJournal, Witness<O>)>
where
    P: CommsClient + FlushableCache + Send + Sync + Debug + Clone,
    B: BlobProvider + Send + Sync + Debug + Clone,
    <B as BlobProvider>::Error: Debug,
    O: WitnessOracle + Send + Sync + Debug + Clone + Default,
{
    // 初始化三大见证数据存储（线程安全访问）
    let oracle_witness = Arc::new(Mutex::new(O::default()));
    let stream_witness = Arc::new(Mutex::new(O::default()));
    let blobs_witness = Arc::new(Mutex::new(BlobWitnessData::default()));
    info!("Preamble");
    // 构建三大数据提供器（桥接oracle与见证存储）
    let oracle = Arc::new(OracleWitnessProvider {
        oracle: preimage_oracle.clone(),
        witness: oracle_witness.clone(),
    });
    let stream = Arc::new(OracleWitnessProvider {
        oracle: preimage_oracle,
        witness: stream_witness.clone(),
    });
    let beacon = BlobWitnessProvider {
        provider: blob_provider,
        witness: blobs_witness.clone(),
    };
    // Run client
    // 运行客户端核心逻辑（收集执行轨迹）
    let collection_target = Arc::new(Mutex::new(Vec::new()));
    //逐个block运行，并根据 precondition_validation_data_hash 获取blob(还有block的root)验证执行轨迹的有效性，每个块的信息保存在collection_target中
  
    let (boot, precondition_hash) = kailua_common::client::core::run_core_client(
        precondition_validation_data_hash,
        oracle,
        stream,
        beacon,
        execution_cache,
        Some(collection_target.clone()),
    )?;
    // Fix claimed output of captured executions
    // todo: use common::core::recover_collected_executions
    // 修正执行轨迹的输出声明（确保状态连续性），claimed_output是默认的没有实际值，需要根据前一个执行的输出来设置

    let mut executions = collection_target.lock().unwrap();
    for i in 1..executions.len() {
        // 前一个执行的声明输出 = 当前执行的约定输出
        executions[i - 1].claimed_output = executions[i].agreed_output;
    }
    if let Some(last_exec) = executions.last_mut() {
        // 最后一个执行的声明输出指向启动配置的L2输出根
        last_exec.claimed_output = boot.claimed_l2_output_root;
    }
    let stitched_executions = vec![core::mem::take(executions.deref_mut())];
    // Construct witness
    // 构建完整见证数据结构
    let fpvm_image_id = B256::from(bytemuck::cast::<_, [u8; 32]>(KAILUA_FPVM_ID));
    let mut witness = Witness {
        oracle_witness: core::mem::take(oracle_witness.lock().unwrap().deref_mut()),
        stream_witness: core::mem::take(stream_witness.lock().unwrap().deref_mut()),
        blobs_witness: core::mem::take(blobs_witness.lock().unwrap().deref_mut()),
        payout_recipient_address: payout_recipient,
        precondition_validation_data_hash,
        stitched_executions,
        stitched_boot_info,
        fpvm_image_id,
    };
    // 固化预映像数据（分片处理优化ZK电路）
    witness
        .oracle_witness
        .finalize_preimages(preimage_oracle_shard_size, true);
    witness
        .stream_witness
        .finalize_preimages(preimage_oracle_shard_size, false);
    let journal_output =
        ProofJournal::new(fpvm_image_id, payout_recipient, precondition_hash, &boot);
    Ok((journal_output, witness))
}
