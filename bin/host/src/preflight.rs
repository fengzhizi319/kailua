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

use crate::args::KailuaHostArgs;
use crate::kv::RWLKeyValueStore;
use alloy::consensus::Transaction;
use alloy::providers::{Provider, RootProvider};
use alloy_eips::eip4844::IndexedBlobHash;
use alloy_eips::BlockNumberOrTag;
use alloy_primitives::B256;
use anyhow::bail;
use kailua_client::provider::OpNodeProvider;
use kailua_client::proving::ProvingError;
use kailua_common::blobs::BlobFetchRequest;
use kailua_common::precondition::PreconditionValidationData;
use kona_genesis::RollupConfig;
use kona_preimage::{PreimageKey, PreimageKeyType};
use kona_protocol::BlockInfo;
use std::env::set_var;
use std::iter::zip;
use tracing::{error, info, warn};

/// 获取指定 L1 区块中特定 Blob 的获取请求，返回block信息以及Blob索引以及blob哈希，不会获取实际的 blob 数据，它只会返回 blob 的索引和相关的区块元数据
///
/// # 参数
/// - `l1_provider`: L1 区块链数据提供者
/// - `block_hash`: 目标 L1 block哈希
/// - `blob_hash`: 需要查找的 Blob 哈希
///
/// # 流程
/// 1. 通过区块哈希获取完整区块数据
/// 2. 遍历区块中的所有交易，收集 Blob 版本化哈希
/// 3. 验证目标 Blob 哈希存在于区块中
/// 4. 返回包含区块元数据和 Blob 索引的请求结构
pub async fn get_blob_fetch_request(
    l1_provider: &RootProvider,
    block_hash: B256,
    blob_hash: B256,
) -> anyhow::Result<BlobFetchRequest> {
    // 获取指定哈希对应的完整区块数据
    /*
    pub header: H,
    pub transactions: BlockTransactions<T>,
    pub uncles: Vec<B256>,
    pub withdrawals: Option<Withdrawals>,
     */
    let block = l1_provider
        .get_block_by_hash(block_hash)
        .await?
        .expect("Failed to fetch block {block_hash}.");
    let mut blob_index = 0;
    let mut blob_found = false;

    // 遍历区块中所有交易的 Blob 哈希
    for blob in block.transactions.into_transactions().flat_map(|tx| {
        // 提取交易中的版本化 Blob 哈希（EIP-4844 规范）
        tx.blob_versioned_hashes()
            .map(|h| h.to_vec())  // 转换为字节数组
            .unwrap_or_default()  // 处理无 Blob 的交易
    }) {
        if blob == blob_hash {
            blob_found = true;
            break;
        }
        blob_index += 1;  // 记录 Blob 在区块中的顺序索引
    }

    // 未找到目标 Blob 时抛出错误
    if !blob_found {
        bail!("Could not find blob with hash {blob_hash} in block {block_hash}");
    }

    // 构造包含区块元数据和 Blob 索引
    Ok(BlobFetchRequest {
        block_ref: BlockInfo {
            hash: block.header.hash,         // 区块哈希
            number: block.header.number,     // 区块高度
            parent_hash: block.header.parent_hash, // 父区块哈希
            timestamp: block.header.timestamp,     // 区块时间戳
        },
        blob_hash: IndexedBlobHash {
            index: blob_index,    // Blob 在区块中的位置索引
            hash: blob_hash,     // 目标 Blob 的哈希值
        },
    })
}

pub async fn fetch_precondition_data(
    cfg: &KailuaHostArgs,
) -> anyhow::Result<Option<PreconditionValidationData>> {
    // Determine precondition hash
    // 验证三个必要参数组是否同时存在：
    // 1. precondition_params (验证参数)，
    // 2. precondition_block_hashes (关联区块哈希)
    // 3. precondition_blob_hashes (关联Blob哈希)
    let hash_arguments = [
        cfg.precondition_params.is_empty(),
        cfg.precondition_block_hashes.is_empty(),
        cfg.precondition_blob_hashes.is_empty(),
    ];

    // fetch necessary data to validate blob equivalence precondition
    // 当所有参数组都非空时进入主逻辑
    if hash_arguments.iter().all(|arg| !arg) {
        // 创建L1区块链提供者连接
        let providers = cfg.kona.create_providers().await?;

        // 校验区块哈希与Blob哈希数量匹配
        if cfg.precondition_block_hashes.len() != cfg.precondition_blob_hashes.len() {
            bail!(
                "Blob reference mismatch. Found {} block hashes and {} blob hashes",
                cfg.precondition_block_hashes.len(),
                cfg.precondition_blob_hashes.len()
            );
        }

        // 构建预处理验证数据结构
        let precondition_validation_data = if cfg.precondition_params.len() == 3 {
            // 并行获取所有Blob的获取请求
            let mut fetch_requests = Vec::with_capacity(cfg.precondition_block_hashes.len());
            for (block_hash, blob_hash) in zip(
                cfg.precondition_block_hashes.iter(),
                cfg.precondition_blob_hashes.iter(),
            ) {
                //根据区块哈希和Blob哈希获取Blob获取请求，不会获取实际的 blob 数据，它只会返回 blob 的索引和相关的区块元数据
                fetch_requests
                    .push(get_blob_fetch_request(&providers.l1, *block_hash, *blob_hash).await?);
            }
            PreconditionValidationData::Validity {
                proposal_l2_head_number: cfg.precondition_params[0],
                proposal_output_count: cfg.precondition_params[1],
                output_block_span: cfg.precondition_params[2],
                blob_hashes: fetch_requests,
            }
        } else {
            bail!("Too many precondition_params values provided");
        };

        // 将验证数据存储到KV数据库
        // 存储位置：由 cfg.kona.create_key_value_store() 创建的共享存储中
        let kv_store = cfg.kona.create_key_value_store()?;
        let mut store = kv_store.write().await;// 获取写入锁
        let hash = precondition_validation_data.hash();
        store.set(
            PreimageKey::new(*hash, PreimageKeyType::Sha256).into(),
            precondition_validation_data.to_vec(),
        )?;

        // 设置环境变量供后续流程使用
        set_var("PRECONDITION_VALIDATION_DATA_HASH", hash.to_string());
        info!("Precondition data hash: {hash}");
        Ok(Some(precondition_validation_data))
    } else if hash_arguments.iter().any(|arg| !arg) {
        bail!("Insufficient number of arguments provided for precondition hash.")
    } else {
        warn!("Proving without a precondition hash.");
        Ok(None)
    }
}

#[allow(clippy::too_many_arguments)]
/// 并发执行预检任务，用于并行处理多个区块链区块的证明计算
///
/// # 参数说明
/// - args: 宿主程序配置参数
/// - rollup_config: 区块链rollup配置
/// - op_node_provider: 操作节点服务提供者
/// - disk_kv_store: 磁盘键值存储（可选）
///
/// # 主要流程
/// 1. 初始化L2提供者并计算起始区块
/// 2. 根据并发数分割区块处理任务
/// 3. 并行生成多个证明计算任务
/// 4. 等待并处理所有任务结果
pub async fn concurrent_execution_preflight(
    args: &KailuaHostArgs,
    rollup_config: RollupConfig,
    op_node_provider: &OpNodeProvider,
    disk_kv_store: Option<RWLKeyValueStore>,
) -> anyhow::Result<()> {
    // 初始化L2区块链提供者
    let l2_provider = args.kona.create_providers().await?.l2;

    // 计算起始区块号和需要处理的总区块数
    let starting_block = l2_provider
        .get_block_by_hash(args.kona.agreed_l2_head_hash)
        .await?
        .unwrap()
        .header
        .number;
    let mut num_blocks = args.kona.claimed_l2_block_number - starting_block;

    // 无待处理区块时直接返回
    if num_blocks == 0 {
        return Ok(());
    }

    // 计算任务分配策略：每个线程处理的基准区块数 + 余数分配
    let blocks_per_thread = num_blocks / args.num_concurrent_preflights;
    let mut extra_blocks = num_blocks % args.num_concurrent_preflights;
    let mut jobs = vec![];
    let mut args = args.clone();

    // 分成很多块任务，每个任务都有开始的区块号，root，结束的区块号，root
    while num_blocks > 0 {
        // 如果额外区块 `extra_blocks` 仍然大于零
        // 则先将其值减 1，再在 `blocks_per_thread` 基础上加 1
        let processed_blocks = if extra_blocks > 0 {
            extra_blocks -= 1;
            blocks_per_thread + 1
        } else {
            // 否则直接使用 `blocks_per_thread` 作为本任务的区块数
            blocks_per_thread
        };

        // 使用 safe 的 `saturating_sub` 函数，防止出现负数下溢
        num_blocks = num_blocks.saturating_sub(processed_blocks);

        // update ending block
	// 更新声明的L2区块号（当前任务结束位置）
        args.kona.claimed_l2_block_number = l2_provider
            .get_block_by_hash(args.kona.agreed_l2_head_hash)
            .await?
            .unwrap()
            .header
            .number
            + processed_blocks;

        // 获取对应的L2输出根
        args.kona.claimed_l2_output_root = op_node_provider
            .output_at_block(args.kona.claimed_l2_block_number)
            .await?;
        // queue new job
	// 生成并行证明计算任务，开一个协程
        jobs.push(tokio::spawn(crate::prove::compute_cached_proof(
            args.clone(),          // 克隆配置参数
            rollup_config.clone(), // 克隆rollup配置
            disk_kv_store.clone(), // 克隆磁盘存储
            B256::ZERO,            // 父区块哈希初始值
            B256::ZERO,            // 父输出根初始值
            vec![],                // 
            vec![],                // 
            vec![],                // 
            false,                 // SNARK证明生成开关，true表示groth16证明，false表示succinct证明
            true,                  // 强制尝试模式，true表示忽略资源限制   
            false,                 // 证明生成开关
        )));
        // jobs.push(args.clone());
        // update starting block for next job
	    // 准备下一个任务的起始参数
        if num_blocks > 0 {
            // 获取新的起始区块哈希
            args.kona.agreed_l2_head_hash = l2_provider
                .get_block_by_number(BlockNumberOrTag::Number(args.kona.claimed_l2_block_number))
                .await?
                .unwrap()
                .header
                .hash;

            // 设置新任务的开始的output_root
            args.kona.agreed_l2_output_root = args.kona.claimed_l2_output_root;
        }
    }
    // Await all tasks
    // 等待所有并行任务完成
    for job in jobs {
        let result = job.await?;
        if let Err(e) = result {
            // 特殊处理SeekProofError，其他错误记录日志
            if !matches!(e, ProvingError::SeekProofError(..)) {
                error!("Error during preflight execution: {e:?}");
            }
        }
    }

    Ok(())
}
