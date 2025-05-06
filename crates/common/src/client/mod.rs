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

use crate::executor::{exec_precondition_hash, new_execution_cursor, CachedExecutor, Execution};
use crate::kona::chain::OracleL1ChainProvider;
use crate::kona::pipeline::OraclePipeline;
use crate::kona::sync::new_pipeline_cursor;
use crate::precondition;
use alloy_op_evm::OpEvmFactory;
use alloy_primitives::{Sealed, B256};
use anyhow::{bail, Context};
use kona_derive::traits::BlobProvider;
use kona_driver::{Driver, Executor};
use kona_executor::TrieDBProvider;
use kona_preimage::{CommsClient, PreimageKey};
use kona_proof::errors::OracleProviderError;
use kona_proof::executor::KonaExecutor;
use kona_proof::l2::OracleL2ChainProvider;
use kona_proof::{BootInfo, FlushableCache, HintType};
use std::fmt::Debug;
use std::sync::{Arc, Mutex};

pub mod stateless;
pub mod stitching;

/// Executes the Kona client to compute a list of subsequent outputs.
/// Modified to validate the Kailua Fault/Validity/Execution preconditions.
pub fn run_kailua_client<
    O: CommsClient + FlushableCache + Send + Sync + Debug,
    B: BlobProvider + Send + Sync + Debug + Clone,
>(
    precondition_validation_data_hash: B256, // blob在L1 block上的检索哈希，用于beacon数据的一致性检查，通常由l1链上获取
    oracle: Arc<O>,         // 预映像数据源（包括bootinfo，L1，L2）
    stream: Arc<O>,         // 流式数据通道（复用oracle实现）
    mut beacon: B,          // blob交易数据提供者（可变引用）
    execution_cache: Vec<Arc<Execution>>, // 预执行结果缓存（原子引用计数包装）
    collection_target: Option<Arc<Mutex<Vec<Execution>>>>, // 执行结果收集器（线程安全）
) -> anyhow::Result<(BootInfo, B256)> // 返回启动信息和预处理哈希
where
    <B as BlobProvider>::Error: Debug,
{
    let (boot, precondition_hash, output_hash) = kona_proof::block_on(async move {
        ////////////////////////////////////////////////////////////////
        //                          PROLOGUE                          //
        ////////////////////////////////////////////////////////////////
        log("BOOT");
        let boot = BootInfo::load(oracle.as_ref())
            .await
            .context("BootInfo::load")?;
        let rollup_config = Arc::new(boot.rollup_config.clone());

        log("SAFE HEAD HASH");
        // 获取L2安全头的区块哈希（基于达成共识的输出根，即前一个块的header）
        let safe_head_hash =
            fetch_safe_head_hash(oracle.as_ref(), boot.agreed_l2_output_root).await?;

        // 初始化L1/L2链数据提供者
        let mut l1_provider = OracleL1ChainProvider::new(boot.l1_head, stream).await?;
        let mut l2_provider =
            OracleL2ChainProvider::new(safe_head_hash, rollup_config.clone(), oracle.clone());

        // The claimed L2 block number must be greater than or equal to the L2 safe head.
        // Fetch the safe head's block header.
        ////////////////////////// 安全头验证 //////////////////////////

        log("SAFE HEAD");
        // 获取开始的block的前一个block 的header，从而可以求出开始的block的number
        let safe_head_hash =
            fetch_safe_head_hash(oracle.as_ref(), boot.agreed_l2_output_root).await?;
        let safe_head = l2_provider
            .header_by_hash(safe_head_hash)
            .map(|header| Sealed::new_unchecked(header, safe_head_hash))?;

        // 验证声明的L2区块号不小于安全头区块号
        if boot.claimed_l2_block_number < safe_head.number {
            bail!("Invalid claim"); // 关键断言失败直接终止
        }
        let safe_head_number = safe_head.number;
        //求出一共有多少个block需要执行
        let expected_output_count = (boot.claimed_l2_block_number - safe_head_number) as usize;

        //////////////////////// 纯执行模式处理，无需关注L1,EXECUTION CACHING     ////////////////////////
        if boot.l1_head.is_zero() { // 当L1头为空时进入纯执行模式

            log("EXECUTION ONLY");
            let cursor =
                new_execution_cursor(rollup_config.as_ref(), safe_head.clone(), &mut l2_provider)
                    .await?;
            l2_provider.set_cursor(cursor.clone());

            // 初始化Kona执行器（包含状态机）
            let mut kona_executor = KonaExecutor::new(
                rollup_config.as_ref(),
                l2_provider.clone(),
                l2_provider.clone(),
                OpEvmFactory::default(),
                None,
            );
            kona_executor.update_safe_head(safe_head);

            // Validate expected block count
            assert_eq!(expected_output_count, execution_cache.len());

            // Validate non-empty execution trace
            assert!(!execution_cache.is_empty());

            // Calculate precondition hash
            let precondition_hash = exec_precondition_hash(execution_cache.as_slice());

            // Validate terminating block number
            assert_eq!(
                execution_cache.last().unwrap().artifacts.header.number,
                boot.claimed_l2_block_number
            );

            // Validate executed chain
            // 遍历执行每个block，验证每个block的执行结果是否正确
            for execution in execution_cache {
                // 三重状态验证：初始状态 -> 执行转换 -> 最终状态
                // Verify initial state
                assert_eq!(
                    execution.agreed_output,
                    kona_executor.compute_output_root()?
                );
                // Verify transition
                assert_eq!(
                    execution.artifacts.header,
                    kona_executor
                        .execute_payload(execution.attributes.clone())
                        .await?
                        .header
                );
                assert_eq!(
                    execution.artifacts.execution_result,
                    kona_executor
                        .execute_payload(execution.attributes.clone())
                        .await?
                        .execution_result
                );
                // Update safe head
                kona_executor.update_safe_head(execution.artifacts.header.clone());
                // Verify post state
                assert_eq!(
                    execution.claimed_output,
                    kona_executor.compute_output_root()?
                );
                log(&format!(
                    "OUTPUT: {}/{}",
                    execution.artifacts.header.number, boot.claimed_l2_block_number
                ));
            }

            // Validate final output against claimed output hash
            return Ok((
                boot,
                precondition_hash,
                Some(kona_executor.compute_output_root()?),
            ));
        }

        ////////////////////////////////////////////////////////////////
        //                   DERIVATION & EXECUTION                   //
        ////////////////////////////////////////////////////////////////
        //////////////////////// 需要关注L1与L2 ////////////////////////
        log("PRECONDITION");
        // L2提案这笔交易在L1上的blob的检索信息以及完整的blob数据
        let precondition_data = precondition::load_precondition_data(
            precondition_validation_data_hash,
            oracle.clone(),
            &mut beacon,
        )
            .await?;

        log("DERIVATION & EXECUTION");
        // Create a new derivation driver with the given boot information and oracle.
        // 创建管道游标（连接L1/L2数据）
        let cursor = new_pipeline_cursor(
            rollup_config.as_ref(),
            safe_head,
            &mut l1_provider,
            &mut l2_provider,
        )
            .await?;
        l2_provider.set_cursor(cursor.clone());

        // 构建带缓存的执行器管道，存在l1关联
        let pipeline = OraclePipeline::new(
            rollup_config.clone(),
            cursor.clone(),
            oracle.clone(),
            beacon,
            l1_provider.clone(),
            l2_provider.clone(),
        )
            .await?;
        // 构建带缓存的执行器管道
        let cached_executor = CachedExecutor {
            cache: {
                // The cache elements will be popped from first to last
                // 倒序缓存
                let mut cache = execution_cache;
                cache.reverse();
                cache
            },
            executor: KonaExecutor::new(
                rollup_config.as_ref(),
                l2_provider.clone(),
                l2_provider.clone(),
                OpEvmFactory::default(),
                None,
            ),
            collection_target,
        };
        let mut driver = Driver::new(cursor, cached_executor, pipeline);

        // Run the derivation pipeline until we are able to produce the output root of the claimed
        // L2 block.
        // 推进到目标区块并收集输出根
        // 初始化输出根集合（预分配内存提升性能）
        let mut output_roots = Vec::with_capacity(expected_output_count);

        // 遍历从安全头到目标区块的所有区块号
        for starting_block in safe_head_number..boot.claimed_l2_block_number {
            // Advance to the next target
            // 驱动链状态推进到指定区块（异步操作），并保存执行结果到collection_target中。
            // - &boot.rollup_config: 当前rollup链配置
            // - Some(starting_block + 1): 目标区块号（当前+1）
            let (output_block, output_root) = driver
                .advance_to_target(&boot.rollup_config, Some(starting_block + 1))
                .await?;
            // Stop if nothing new was derived
            // 检查是否产生新区块（无新区块时终止推导）
            if output_block.block_info.number == starting_block {
                // A mismatch indicates that there is insufficient L1 data available to produce
                // an L2 output root at the claimed block number
                log("HALT");
                break;
            } else {
                // 记录执行进度（当前区块/总目标区块）
                log(&format!(
                    "OUTPUT: {}/{}",
                    output_block.block_info.number, boot.claimed_l2_block_number
                ));
            }
            // Append newly computed output root
            // 收集输出状态根（用于后续验证）
            // output_root包含：状态树根、收据根、区块哈希的哈希组合
            output_roots.push(output_root);
        }

        ////////////////////////////////////////////////////////////////
        //                          EPILOGUE                          //
        ////////////////////////////////////////////////////////////////
        log("EPILOGUE");
        // 如果验证正确，那么返回precondition_validation_data的hash，主要是blob检索信息的hash
        let precondition_hash = precondition_data
            .map(|(precondition_validation_data, blobs)| {
                precondition::validate_precondition(
                    precondition_validation_data,
                    blobs,
                    safe_head_number,
                    &output_roots,
                )
            })
            .unwrap_or(Ok(B256::ZERO))?;
        // 根据输出结果数量返回不同状态
        if output_roots.len() != expected_output_count {
            // Not enough data to derive output root at claimed height
            Ok((boot, precondition_hash, None))
        } else if output_roots.is_empty() {
            // Claimed output height is equal to agreed output height
            let real_output_hash = boot.agreed_l2_output_root;
            Ok((boot, precondition_hash, Some(real_output_hash)))
        } else {
            // Derived output root at future height
            Ok((boot, precondition_hash, output_roots.pop()))
        }
    })?;

    // Check output
    if let Some(computed_output) = output_hash {
        // With sufficient data, the input l2_claim must be true
        assert_eq!(boot.claimed_l2_output_root, computed_output);// 验证实际输出与声明一致
    } else {
        // We use the zero claim hash to denote that the data as of l1 head is insufficient
        assert_eq!(boot.claimed_l2_output_root, B256::ZERO);// 无输出时校验零值
    }

    Ok((boot, precondition_hash))
}


///获取agreed_l2_output_root对应的L2 header的hash
/// Fetches the safe head hash of the L2 chain based on the agreed upon L2 output root in the
/// [BootInfo].
pub async fn fetch_safe_head_hash<O>(
    caching_oracle: &O,          // 带缓存的预映像预言机（实现CommsClient协议）
    agreed_l2_output_root: B256, // 达成共识的L2输出根（来自BootInfo）
) -> Result<B256, OracleProviderError>
where
    O: CommsClient,
{
    // 初始化128字节缓冲区（根据Kona协议规范，L2输出根预映像需要128字节）
    let mut output_preimage = [0u8; 128];

    // 发送StartingL2Output类型的提示，通知预言机需要获取L2起始输出的预映像数据
    // 协议格式：HintType(1字节) + agreed_l2_output_root(32字节)
    HintType::StartingL2Output
        .with_data(&[agreed_l2_output_root.as_ref()])
        .send(caching_oracle)
        .await?;

    // 获取完整的预映像数据（Keccak256哈希对应的原始数据）
    // 根据Kona预映像规范，预映像键由哈希类型和哈希值组成
    caching_oracle
        .get_exact(
            PreimageKey::new_keccak256(*agreed_l2_output_root), // 构造Keccak256类型的预映像键
            output_preimage.as_mut(), // 写入预分配的128字节缓冲区
        )
        .await?;

    // 解析预映像数据中的安全头哈希（协议规定位于最后32字节位置）
    // 数据结构布局：
    // [0..96] - 保留字段（包含状态根、收据根等）
    // [96..128] - 安全头哈希（B256类型）
    output_preimage[96..128]
        .try_into() // 将[u8;32]转换为B256
        .map_err(OracleProviderError::SliceConversion) // 处理可能的转换错误
}

pub fn log(msg: &str) {
    #[cfg(target_os = "zkvm")]
    risc0_zkvm::guest::env::log(msg);
    #[cfg(not(target_os = "zkvm"))]
    tracing::info!("{msg}");
}
