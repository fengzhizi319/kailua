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

use alloy::providers::{Provider, RootProvider};
use alloy_eips::BlockNumberOrTag;
use alloy_primitives::B256;
use anyhow::{anyhow, bail, Context};
use clap::Parser;
use kailua_client::provider::OpNodeProvider;
use kailua_client::proving::ProvingError;
use kailua_common::boot::StitchedBootInfo;
use kailua_host::args::KailuaHostArgs;
use kailua_host::channel::AsyncChannel;
use kailua_host::config::generate_rollup_config;
use kailua_host::preflight::{concurrent_execution_preflight, fetch_precondition_data};
use kailua_host::server::create_disk_kv_store;
use kailua_host::tasks::{handle_oneshot_tasks, Cached, Oneshot, OneshotResult};
use std::collections::BinaryHeap;
use std::env::set_var;
use tempfile::tempdir;
use tracing::{info, warn};
use tracing_subscriber::EnvFilter;

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    // 解析命令行参数
    let mut args = KailuaHostArgs::parse();
    // 初始化日志订阅器
    kona_cli::init_tracing_subscriber(args.v, None::<EnvFilter>)?;
    // 设置环境变量
    set_var("KAILUA_VERBOSITY", args.v.to_string());
    // 获取 L2 提供者（如果是离线模式则为 None）
    /*. l2_provider跟op_node_provider区别
    1. 连接目标：
   - l2_provider连接到L2的执行层节点（如Geth或其他EVM客户端），提供标准的以太坊JSON-RPC接口。
   - op_node_provider连接到Optimism的Op-Node，专门处理Rollup相关的操作，如输出根的生成和验证。
    2. 数据获取：
       - l2_provider获取的是具体的区块数据，如区块号、哈希、交易详情等。
       - op_node_provider获取的是Rollup特有的数据，如特定区块的输出根，这是Optimism跨链通信的关键部分。
    3. 功能用途：
       - l2_provider用于验证区块的存在和正确性，支持证明生成过程中的数据需求。
       - op_node_provider用于在证明过程中获取必要的Rollup状态，特别是在工作负载拆分时确定中间点的状态，确保证明的连续性。
    4. 依赖关系：
       - l2_provider在离线模式下不可用，说明它依赖于外部网络连接。
       - op_node_provider的存在取决于是否提供了op_node_address参数，即使在线模式下也可能未配置，但某些功能（如预处理）必须依赖它。
    5. 架构角色：
       - l2_provider属于执行层客户端，处理链上实际交易和状态。
       - op_node_provider属于Rollup协调层，管理状态提交和跨链通信
     */
    // fetch starting block number
    
    let l2_provider = if args.kona.is_offline() {
        None
    } else {
        Some(args.kona.create_providers().await?.l2)
    };
        // 初始化 OpNode 提供者
    // 用于查询 L2 输出根（output root）和提交证明到链上
    /*
    op_node_provider 在这段代码中是与 Optimistic Rollup 节点通信的关键组件，主要有以下作用：
    查询 L2 输出根：从代码注释中可以看到，它被用来"查询 L2 输出根（output root）"。在代码执行过程中，当需要获取某个区块的输出根时会调用它的 output_at_block 方法。
    提交证明到链上：根据注释，它也用于"提交证明到链上"，虽然在当前代码中没有直接显示这部分功能的调用。
    支持工作负载拆分：在处理大量区块时，如果遇到错误需要拆分工作负载，会使用 op_node_provider 获取中间区块的输出根：
    let mid_output = op_node_provider
        .as_ref()
        .expect("Missing op_node_provider")
        .output_at_block(mid_point)
        .await?;
    预处理数据获取：在并行预处理阶段，op_node_provider 被传递给 concurrent_execution_preflight 函数，用于获取预处理所需的链上数据。
    本质上，op_node_provider 是证明系统与区块链网络之间的桥梁，使得证明程序能够获取必要的链上数据以生成有效的证明。它基于 HTTP 连接创建，连接到由命令行参数 op_node_address 指定的 OP-Node 端点。
     */
    let op_node_provider = args.op_node_address.as_ref().map(|addr| {
        OpNodeProvider(RootProvider::new_http(
            addr.as_str()
                .try_into()
                .expect("Failed to parse op_node_address"),
        ))
    });

    // set tmp data dir if data dir unset
    // 如果未设置数据目录，则创建临时目录
    let tmp_dir = tempdir().map_err(|e| ProvingError::OtherError(anyhow!(e)))?;
    if args.kona.data_dir.is_none() {
        args.kona.data_dir = Some(tmp_dir.path().to_path_buf());
    }
    // fetch rollup config
    let rollup_config = generate_rollup_config(&mut args, &tmp_dir)
        .await
        .context("generate_rollup_config")
        .map_err(|e| ProvingError::OtherError(anyhow!(e)))?;
    // preload precondition data into KV store
    // 预加载前置条件数据到 KV 存储
    // 处理预条件验证数据的哈希值
    let (precondition_hash, precondition_validation_data_hash) =
        match fetch_precondition_data(&args)
            .await
            .map_err(|e| ProvingError::OtherError(anyhow!(e)))?
        {
            // 当存在预条件数据时
            Some(data) => {
                // 计算验证数据的哈希值
                let precondition_validation_data_hash = data.hash();
                // 将哈希存储到环境变量供后续证明流程使用
                set_var(
                    "PRECONDITION_VALIDATION_DATA_HASH",
                    precondition_validation_data_hash.to_string(),
                );
                // 返回元组：(预条件哈希, blob数据在L1上的查找结果的hash)
                (data.precondition_hash(), precondition_validation_data_hash)
            }
            // 无预条件数据时使用零哈希作为默认值
            None => (B256::ZERO, B256::ZERO),
        };
    // create concurrent db
    // 创建并发数据库
    let disk_kv_store = create_disk_kv_store(&args.kona);
    // perform preflight to fetch data,执行预处理以获取数据
    if args.num_concurrent_preflights > 1 {
        // run parallelized preflight instances to populate kv store,并行运行预处理实例以填充 KV 存储
        info!(
            "Running concurrent preflights with {} threads",
            args.num_concurrent_preflights
        );
        //验证结果的正确性，将预处理数据(L1以及L2相关的数据)存储到 KV 存储中，没有生成证明
        concurrent_execution_preflight(
            &args,
            rollup_config.clone(),
            op_node_provider.as_ref().expect("Missing op_node_provider"),
            disk_kv_store.clone(),
        )
            .await
            .map_err(|e| ProvingError::OtherError(anyhow!(e)))?;
    }

    // spin up proving workers
    // 启动证明工作线程
    let task_channel: AsyncChannel<Oneshot> = async_channel::unbounded();
    let mut proving_handlers = vec![];
    for _ in 0..args.num_concurrent_proofs {
        proving_handlers.push(tokio::spawn(handle_oneshot_tasks(task_channel.1.clone())));
    }

    // create proofs channel
    // 创建证明结果通道
    let result_channel = async_channel::unbounded();
    let prover_channel = async_channel::unbounded();
    /*
    result_pq 是一个 BinaryHeap（优先队列），用于临时存储和排序各个子任务（区块区间）证明的结果（OneshotResult）。
    其主要作用是：
    1.收集并排序证明结果：每个子任务完成后，将其结果插入 result_pq，通过实现 Ord/PartialOrd，可以按区块号等关键字段自动排序。
    2.保证最终拼接顺序：在所有子任务完成后，通过 into_sorted_vec() 方法将结果按顺序取出，确保后续拼接（stitch）证明时区块顺序正确。
    3.支持任务拆分与并发：当任务因错误被拆分为多个子任务时，result_pq 能收集所有子任务的结果，最终统一处理。
    简言之，result_pq 保证了多段区块证明结果的有序收集与后续正确拼接。
     */
    let mut result_pq = BinaryHeap::new();
    let mut num_proofs = 1;
    // 初始任务发送（未拆分），初始任务have_split标记为 false
    prover_channel
        .0
        .send((false, args.clone()))
        .await
        .expect("Failed to send prover task");
    while result_pq.len() < num_proofs {
        // dispatch all pending proofs
        // 分发所有待处理的证明任务
        while !prover_channel.1.is_empty() {
            let (have_split, job_args) = prover_channel
                .1
                .recv()
                .await
                .expect("Failed to recv prover task");
            let starting_block = if let Some(l2_provider) = l2_provider.as_ref() { // 检查是否配置了L2数据源
                l2_provider
                    .get_block_by_hash(job_args.kona.agreed_l2_head_hash) // 通过区块哈希查询区块详情
                    .await? // 等待异步请求完成
                    .unwrap() // 确认查询结果存在（如果不存在会panic）
                    .header
                    .number // 提取区块号
            } else { // 离线模式情况
                0 // 默认从创世区块开始
            };

            let num_blocks = job_args.kona.claimed_l2_block_number - starting_block;
            if starting_block > 0 {
                info!(
                    "Processing job with {} blocks from block {}",
                    num_blocks, starting_block
                );
            }
            // Force the proving attempt regardless of witness size if we prove just one block
            // 如果只证明一个区块，则强制尝试
            let force_attempt = num_blocks == 1 || job_args.kona.is_offline();

            // spawn a job that computes the proof and sends back the result to result_channel
            // 启动任务计算证明并将结果发送到结果通道
            let rollup_config = rollup_config.clone();
            let disk_kv_store = disk_kv_store.clone();
            let task_channel = task_channel.clone();
            let result_channel = result_channel.clone();
            tokio::spawn(async move {
                let result = kailua_host::prove::compute_fpvm_proof(
                    job_args.clone(),
                    rollup_config,
                    disk_kv_store,
                    precondition_hash,
                    precondition_validation_data_hash,
                    vec![],
                    vec![],
                    !have_split,//false取反为true
                    task_channel.0.clone(),
                )
                    .await;

                result_channel
                    .0
                    .clone()
                    .send((starting_block, job_args, force_attempt, result))
                    .await
                    .expect("Failed to send fpvm proof result");
            });
        }

        // receive and process new results
        // 接收并处理新结果
        let (starting_block, job_args, force_attempt, result) = result_channel
            .1
            .recv()
            .await
            .expect("Failed to recv prover task");
        let num_blocks = job_args.kona.claimed_l2_block_number - starting_block;

        match result {
            Ok(proof) => {
                // 检查证明结果是否存在
                if let Some(proof) = proof {
                    // 将证明结果封装为 OneshotResult 结构体，并压入优先队列 result_pq 中
                    result_pq.push(OneshotResult {
                        // 缓存本次证明任务的相关参数，用于后续排序和可能的重新处理
                        cached: Cached {
                            // 用于优先队列排序的任务参数
			    // used for sorting
                            args: job_args,
                            // 以下参数在当前逻辑中未使用，但保留供后续可能的扩展
			    // all unused
                            rollup_config: rollup_config.clone(),
                            disk_kv_store: disk_kv_store.clone(),
                            precondition_hash,
                            precondition_validation_data_hash,
                            stitched_executions: vec![],
                            stitched_boot_info: vec![],
                            stitched_proofs: vec![],
                            // 是否生成 SNARK 证明，当前设置为 false
                            prove_snark: false,
                            // 强制尝试证明的标志
                            force_attempt,
                            // 是否查找现有证明，当前设置为 true
                            seek_proof: true,
                        },
                        // 封装证明结果，使用 Ok 表示证明成功
                        result: Ok(proof),
                    });
                }
            }
            Err(err) => {
                // Handle error case
                match err {
                    ProvingError::WitnessSizeError(f, t, ..) => {
                        if force_attempt {
                            bail!(
                                "Received WitnessSizeError({f},{t}) for a forced proving attempt: {err:?}"
                                );
                        }
                        warn!("Proof witness size {f} above safety threshold {t}. Splitting workload.")
                    }
                    ProvingError::ExecutionError(e) => {
                        if force_attempt {
                            bail!("Irrecoverable ZKVM execution error: {e:?}")
                        }
                        warn!("Splitting proof after ZKVM execution error: {e:?}")
                    }
                    ProvingError::OtherError(e) => {
                        bail!("Irrecoverable proving error: {e:?}")
                    }
                    ProvingError::SeekProofError(..) => {
                        unreachable!("SeekProofError bubbled up")
                    }
                    ProvingError::DerivationProofError(proofs) => {
                        info!("Computed {proofs} execution-only proofs.");
                        continue;
                    }
                }
                // Require additional proof
                num_proofs += 1;
                // Split workload at midpoint (num_blocks > 1)
                // 在中点拆分工作负载（num_blocks > 1）
                let mid_point = starting_block + num_blocks / 2;
                let mid_output = op_node_provider
                    .as_ref()
                    .expect("Missing op_node_provider")
                    .output_at_block(mid_point)
                    .await?;
                let mid_block = l2_provider
                    .as_ref()
                    .expect("Missing l2_provider")
                    .get_block_by_number(BlockNumberOrTag::Number(mid_point))
                    .await?
                    .unwrap_or_else(|| panic!("Block {mid_point} not found"));
                // Lower half workload ends at midpoint (inclusive)
                // 下半部分工作负载结束于中点（包含）
                let mut lower_job_args = job_args.clone();
                lower_job_args.kona.claimed_l2_output_root = mid_output;
                lower_job_args.kona.claimed_l2_block_number = mid_point;
                prover_channel
                    .0
                    .send((true, lower_job_args))
                    .await
                    .expect("Failed to send prover task");
                // upper half workload starts after midpoint
                // 上半部分工作负载从中点之后开始
                let mut upper_job_args = job_args;
                upper_job_args.kona.agreed_l2_output_root = mid_output;
                upper_job_args.kona.agreed_l2_head_hash = mid_block.header.hash;
                prover_channel
                    .0
                    .send((true, upper_job_args))
                    .await
                    .expect("Failed to send prover task");
            }
        }
    }
    // gather sorted proofs into vec
    // 将排序后的证明收集到向量中
    let proofs = result_pq
        .into_sorted_vec()
        .into_iter()
        .rev()
        .map(|r| r.result.expect("Failed to get result"))
        .collect::<Vec<_>>();

    // stitch contiguous proofs together
    // 将连续的证明拼接在一起
    if proofs.len() > 1 {
        info!("Composing {} proofs together.", proofs.len());
        // construct a proving instruction with no blocks to derive
        // 构造一个不包含区块的证明指令
        let mut base_args = args;
        {
            // set last block as starting point
            // 设置agreed_l2_output_root=claimed_l2_output_root，这样stitching_only就为true，就只会执行stitching
            // 这是因为stitching_only为true时，不会执行任何区块的验证和计算，只进行拼接
            base_args.kona.agreed_l2_output_root = base_args.kona.claimed_l2_output_root;
            base_args.kona.agreed_l2_head_hash = l2_provider
                .as_ref()
                .unwrap()
                .get_block_by_number(BlockNumberOrTag::Number(
                    base_args.kona.claimed_l2_block_number,
                ))
                .await?
                .unwrap_or_else(|| {
                    panic!("Block {} not found", base_args.kona.claimed_l2_block_number)
                })
                .header
                .hash;
        }
        // construct a list of boot info to backward stitch
        // 构造一个用于向后拼接的 boot 信息列表
        // 从排序好的证明结果 proofs 中生成用于拼接的启动信息列表
        let stitched_boot_info = proofs
            // 对 proofs 中的每个元素进行迭代
            .iter()
            // 对迭代中的每个元素应用 StitchedBootInfo::from 方法，
            // 这里假设 StitchedBootInfo 实现了 From 特质，能将 proofs 中的元素类型转换为 StitchedBootInfo 类型
            .map(StitchedBootInfo::from)
            // 将转换后的元素收集到一个 Vec<StitchedBootInfo> 向量中
            .collect::<Vec<_>>();

        kailua_host::prove::compute_fpvm_proof(
            base_args,
            rollup_config.clone(),
            disk_kv_store.clone(),
            precondition_hash,
            precondition_validation_data_hash,
            stitched_boot_info,
            proofs,
            true,
            task_channel.0.clone(),
        )
        .await
        .context("Failed to compute FPVM proof.")?;
    }

    info!("Exiting host program.");
    Ok(())
}
