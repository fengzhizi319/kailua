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
use crate::tasks;
use crate::tasks::{Cached, Oneshot};
use alloy_primitives::B256;
use anyhow::{anyhow, Context};
use async_channel::Sender;
use kailua_build::KAILUA_FPVM_ID;
use kailua_client::proof::{proof_file_name, read_proof_file};
use kailua_client::proving::ProvingError;
use kailua_common::boot::StitchedBootInfo;
use kailua_common::client::stitching::{split_executions, stitch_boot_info};
use kailua_common::executor::{exec_precondition_hash, Execution};
use kona_genesis::RollupConfig;
use kona_proof::BootInfo;
use risc0_zkvm::Receipt;
use std::collections::BinaryHeap;
use std::path::Path;
use std::sync::Arc;
use tracing::{info, warn};

/// Computes a receipt if it is not cached
#[allow(clippy::too_many_arguments)]
pub async fn compute_fpvm_proof(
    args: KailuaHostArgs,                     // 宿主程序配置参数
    rollup_config: RollupConfig,             // Rollup链配置信息
    disk_kv_store: Option<RWLKeyValueStore>,  // 磁盘键值存储（用于缓存中间数据）
    precondition_hash: B256,                  // 预处理数据完整性校验值
    precondition_validation_data_hash: B256,  // 预处理数据在L1上的存储证明
    stitched_boot_info: Vec<StitchedBootInfo>, // 已拼接的启动信息集合
    stitched_proofs: Vec<Receipt>,            // 已生成的子证明集合
    prove_snark: bool,                        // SNARK证明类型，true表示groth16，false表示succinct
    task_sender: Sender<Oneshot>,             // 异步任务发送通道
) -> Result<Option<Receipt>, ProvingError> {
    // report transaction count
    if !stitched_boot_info.is_empty() {
        info!("Stitching {} sub-proofs", stitched_boot_info.len());
    }

    //  1. try entire proof
    //      on failure, take execution trace
    //  2. try derivation-only proof
    //      on failure, report error
    //  3. compute series of execution-only proofs
    //  4. compute derivation-proof with stitched executions
    // 阶段1：完整证明尝试
    let stitching_only = args.kona.agreed_l2_output_root == args.kona.claimed_l2_output_root;
    // generate master proof
    info!("Attempting complete proof.");
    let complete_proof_result = tasks::compute_oneshot_task(
        args.clone(),                        // 宿主程序配置参数（克隆避免所有权问题）
        rollup_config.clone(),              // Rollup链配置信息（克隆保证线程安全）
        disk_kv_store.clone(),              // 磁盘KV存储实例（克隆用于多线程访问）
        precondition_hash,                  // 预处理数据完整性校验哈希
        precondition_validation_data_hash,  // 预处理验证数据的L1存储证明哈希
        vec![],            // 已执行的区块列表（此处为空表示完整运行）
        stitched_boot_info.clone(),         // 需要拼接的启动信息集合（克隆保证数据独立）
        stitched_proofs.clone(),            // 已有子证明集合（克隆用于安全拼接）
        prove_snark,                        // // SNARK证明类型，true表示groth16，false表示succinct
        stitching_only,                     // 强制证明尝试标志（跳过安全检查）
        !args.proving.skip_derivation_proof, // 派生证明查找标志（取反命令行参数配置）
        task_sender.clone(),                // 异步任务通道发送端（克隆用于多线程分发）
    )
    .await;

    // on WitnessSizeError or SeekProofError, extract execution trace
    // 处理完整证明结果：成功直接返回，失败则提取已执行区块
    let executed_blocks = match complete_proof_result {
        Err(ProvingError::WitnessSizeError(_, _, executed_blocks)) => executed_blocks,
        Err(ProvingError::SeekProofError(_, executed_blocks)) => executed_blocks,
        other_result => return Ok(Some(other_result?)),
    };
    // flatten executed l2 blocks
    let (_, execution_cache) = split_executions(executed_blocks.clone());

    // perform a derivation-only run to check its provability
    // 阶段2：派生derivation证明验证
    if !args.proving.skip_derivation_proof {
        info!(
            "Performing derivation-only run for {} executions.",
            execution_cache.len()
        );
        //先执行正确性验证，但不执行证明，同时验证是否发生WitnessSizeError错误
        let derivation_only_result = tasks::compute_oneshot_task(
            args.clone(),
            rollup_config.clone(),
            disk_kv_store.clone(),
            precondition_hash,
            precondition_validation_data_hash,
            executed_blocks.clone(),
            stitched_boot_info.clone(),
            stitched_proofs.clone(),
            false,
            false,
            false,
            task_sender.clone(),
        )
        .await;
        // propagate unexpected error up on failure to trigger higher-level division
        let Err(ProvingError::SeekProofError(witness_size, _)) = derivation_only_result else {
            warn!(
                "Unexpected derivation-only result (is_ok={}).",
                derivation_only_result.is_ok()
            );
            return Ok(Some(derivation_only_result?));
        };
        // abort if pure derivation may OOM
        // 当见证数据总大小超过安全阈值时触发
        if witness_size > args.proving.max_witness_size {
            warn!(
                "Derivation-only witness size {} exceeds limit {}.",
                witness_size, args.proving.max_witness_size
            );
        }
    }

    // create proofs channel
    // 阶段3：分治证明生成
    let result_channel = async_channel::unbounded();
    let mut result_pq = BinaryHeap::new();
    // start with full execution proof
    task_sender
        .send(Oneshot {
            cached_task: create_cached_execution_task(
                {
                    let mut args = args.clone();
                    args.kona.l1_head = B256::ZERO;
                    args
                },
                rollup_config.clone(),
                disk_kv_store.clone(),
                &execution_cache,
            ),
            result_sender: result_channel.0.clone(),
        })
        .await
        .expect("task_channel should not be closed");
    // divide and conquer executions
    // 分治处理循环（二分法拆分大任务）
    let mut num_proofs = 1;
    while result_pq.len() < num_proofs {
        // Wait for more proving results
        // 接收证明结果
        let oneshot_result = result_channel
            .1
            .recv()
            .await
            .expect("result_channel should not be closed");
        let Err(err) = oneshot_result.result else {
            result_pq.push(oneshot_result);
            continue;
        };
        // Require additional proof
        num_proofs += 1;
        let executed_blocks = oneshot_result.cached.stitched_executions[0].clone();
        let starting_block = executed_blocks[0].artifacts.header.number - 1;
        let num_blocks = oneshot_result.cached.args.kona.claimed_l2_block_number - starting_block;
        let force_attempt = num_blocks == 1;
        // divide or bail out on error
        match err {
            ProvingError::WitnessSizeError(f, t, e) => {
                if force_attempt {
                    return Err(ProvingError::WitnessSizeError(f, t, e));
                }
                warn!("Proof witness size {f} above safety threshold {t}. Splitting workload.")
            }
            ProvingError::ExecutionError(e) => {
                if force_attempt {
                    return Err(ProvingError::ExecutionError(e));
                }
                warn!("Splitting proof after ZKVM execution error: {e:?}")
            }
            ProvingError::OtherError(e) => {
                return Err(ProvingError::OtherError(e));
            }
            ProvingError::SeekProofError(_, _) => {
                unreachable!("Sought proof, found SeekProofError {err:?}")
            }
            ProvingError::DerivationProofError(_) => {
                unreachable!("Sought proof, found DerivationProofError {err:?}")
            }
        }
        // Split workload at midpoint (num_blocks > 1)
        // 根据错误类型拆分任务
        let mid_point = starting_block + num_blocks / 2;
        let mid_exec = executed_blocks
            .iter()
            .find(|e| e.artifacts.header.number == mid_point)
            .expect("Failed to find the midpoint of execution.");
        let mid_output = mid_exec.claimed_output;

        // Lower half workload ends at midpoint (inclusive)
        let mut lower_job_args = oneshot_result.cached.args.clone();
        lower_job_args.kona.claimed_l2_output_root = mid_output;
        lower_job_args.kona.claimed_l2_block_number = mid_point;
        // 创建下半区任务（包含中间点）
        task_sender
            .send(Oneshot {
                cached_task: create_cached_execution_task(
                    lower_job_args,
                    rollup_config.clone(),
                    disk_kv_store.clone(),
                    &execution_cache,
                ),
                result_sender: result_channel.0.clone(),
            })
            .await
            .expect("task_channel should not be closed");

        // upper half workload starts after midpoint
        // 创建上半区任务（中间点之后）
        let mut upper_job_args = oneshot_result.cached.args;
        upper_job_args.kona.agreed_l2_output_root = mid_output;
        upper_job_args.kona.agreed_l2_head_hash = mid_exec.artifacts.header.hash();
        task_sender
            .send(Oneshot {
                cached_task: create_cached_execution_task(
                    upper_job_args,
                    rollup_config.clone(),
                    disk_kv_store.clone(),
                    &execution_cache,
                ),
                result_sender: result_channel.0.clone(),
            })
            .await
            .expect("task_channel should not be closed");
    }
    // Read result_pq for stitched executions and proofs
    // 阶段4：最终证明合成
    let (proofs, stitched_executions): (Vec<_>, Vec<_>) = result_pq
        .into_sorted_vec()
        .into_iter()
        .map(|mut r| {
            (
                r.result.expect("pushed failing result to queue"),
                r.cached.stitched_executions.pop().unwrap(),
            )
        })
        .unzip();

    // Return no proof if derivation is not required
    if args.proving.skip_derivation_proof {
        return Ok(None);
    }

    // Combine execution proofs with derivation proof
    let total_blocks = stitched_executions.iter().map(|e| e.len()).sum::<usize>();
    info!(
        "Combining {}/{} execution proofs for {total_blocks} blocks with derivation proof.",
        proofs.len(),
        stitched_executions.len()
    );
    Ok(Some(
        tasks::compute_oneshot_task(
            args,
            rollup_config,
            disk_kv_store,
            precondition_hash,
            precondition_validation_data_hash,
            stitched_executions,
            stitched_boot_info,
            [stitched_proofs, proofs].concat(),
            prove_snark,
            true,
            true,
            task_sender.clone(),
        )
        .await?,
    ))
}

pub fn create_cached_execution_task(
    args: KailuaHostArgs,
    rollup_config: RollupConfig,
    disk_kv_store: Option<RWLKeyValueStore>,
    execution_cache: &[Arc<Execution>],
) -> Cached {
    let starting_block = execution_cache
        .iter()
        .find(|e| e.agreed_output == args.kona.agreed_l2_output_root)
        .expect("Failed to find the first execution.")
        .artifacts
        .header
        .number
        - 1;
    let num_blocks = args.kona.claimed_l2_block_number - starting_block;
    info!(
        "Processing execution-only job with {} blocks from block {}",
        num_blocks, starting_block
    );
    // Extract executed slice
    let executed_blocks = execution_cache
        .iter()
        .filter(|e| {
            let executed_block_number = e.artifacts.header.number;

            starting_block < executed_block_number
                && executed_block_number <= args.kona.claimed_l2_block_number
        })
        .cloned()
        .collect::<Vec<_>>();
    let precondition_hash = exec_precondition_hash(executed_blocks.as_slice());

    // Force the proving attempt regardless of witness size if we prove just one block
    let force_attempt = num_blocks == 1;
    let executed_blocks = executed_blocks
        .iter()
        .map(|a| a.as_ref().clone())
        .collect::<Vec<_>>();

    Cached {
        args,
        rollup_config,
        disk_kv_store,
        precondition_hash,
        precondition_validation_data_hash: B256::ZERO,
        stitched_executions: vec![executed_blocks],
        stitched_boot_info: vec![],
        stitched_proofs: vec![],
        prove_snark: false,
        force_attempt,
        seek_proof: true,
    }
}

#[allow(clippy::too_many_arguments)]
/// 计算并缓存零知识证明的核心函数
///
/// # 功能说明
/// 1. 构造区块链启动信息
/// 2. 生成唯一证明标识
/// 3. 检查本地缓存（存在则直接读取）
/// 4. 未缓存时生成新证明
/// 5. 返回最终的证明结果
///
/// # 参数说明
/// - args: 宿主程序配置参数
/// - rollup_config: 区块链rollup配置
/// - disk_kv_store: 磁盘键值存储（用于缓存）
/// - precondition_hash: 预处理条件哈希
/// - precondition_validation_data_hash: 预处理验证数据哈希
/// - stitched_*: 拼接的区块执行数据和证明
/// - prove_snark: SNARK证明类型，true表示groth16，false表示succinct
/// - force_attempt: 强制尝试生成证明（即使可能失败）
/// - seek_proof: 是否查找现有证明
pub async fn compute_cached_proof(
    args: KailuaHostArgs,// 宿主程序配置参数
    rollup_config: RollupConfig,// 区块链rollup配置
    disk_kv_store: Option<RWLKeyValueStore>,// 磁盘键值存储（用于缓存）
    precondition_hash: B256,// 预处理条件哈希
    precondition_validation_data_hash: B256,// precondition_hash在L1中的索引的hash


    stitched_executions: Vec<Vec<Execution>>,// 拼接的区块执行数据
    stitched_boot_info: Vec<StitchedBootInfo>,// 拼接的启动信息
    stitched_proofs: Vec<Receipt>,//拼接的区块执行数据和证明
    prove_snark: bool,// SNARK证明类型标志，true表示groth16证明，false表示succinct证明
    force_attempt: bool,// 强制尝试模式（忽略资源限制）
    seek_proof: bool,// 实际执行证明生成开关，true表示需要生成证明，false表示仅验证正确性，而不生成证明
) -> Result<Receipt, ProvingError> {
    // extract single chain kona config
    // 构建 区块开始时的启动信息（包含L1/L2状态）
    let boot = BootInfo {
        l1_head: args.kona.l1_head,
        agreed_l2_output_root: args.kona.agreed_l2_output_root,
        claimed_l2_output_root: args.kona.claimed_l2_output_root,
        claimed_l2_block_number: args.kona.claimed_l2_block_number,
        chain_id: rollup_config.l2_chain_id,
        rollup_config,
    };
    // Construct expected journal
    //拼接多个块的boot信息，包含L1/L2状态、链ID等，形成ProofJournal
    let proof_journal = stitch_boot_info(
        &boot,  // 区块链启动配置（包含L1/L2状态、链ID等）
        bytemuck::cast::<[u32; 8], [u8; 32]>(KAILUA_FPVM_ID).into(), // 虚拟机唯一标识
        args.proving.payout_recipient_address.unwrap_or_default(), // 收益地址（零地址表示无奖励）
        precondition_hash, // 预处理数据完整性校验值
        stitched_boot_info.clone(), // 多区块执行上下文拼接信息
    );
    // Skip computation if previously saved to disk
    // 对proof_journal计算keccak256哈希从而生成唯一的文件名
    let proof_file_name = proof_file_name(&proof_journal);
    if matches!(Path::new(&proof_file_name).try_exists(), Ok(true)) && seek_proof {
        info!("Proving skipped. Proof file {proof_file_name} already exists.");
    } else {
        info!("Computing uncached proof.");

        // generate a proof using the kailua client and kona server
        // （启动本地服务+客户端协作）
        crate::server::start_server_and_native_client(
            args, // 传递完整配置参数
            disk_kv_store, // 共享存储
            precondition_validation_data_hash, // 验证数据哈希
            stitched_executions, // 拼接的区块执行轨迹
            stitched_boot_info, // 启动配置信息
            stitched_proofs, // 已有证明片段
            prove_snark, // SNARK证明生成开关，true表示groth16证明，false表示succinct证明
            force_attempt, // 强制尝试模式，true表示忽略资源限制
            seek_proof, // 证明生成开关
        )
            .await?; // 异步等待证明生成，如果生成失败则返回错误
    }

    // 最终读取证明文件（统一入口）
    read_proof_file(&proof_file_name)
        .await
        .context(format!(
            "Failed to read proof file {proof_file_name} contents."
        ))
        .map_err(|e| ProvingError::OtherError(anyhow!(e)))
}
