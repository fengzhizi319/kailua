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

use crate::client::log;
use crate::executor::Execution;
use crate::journal::ProofJournal;
use crate::witness::StitchedBootInfo;
use alloy_primitives::map::HashSet;
use alloy_primitives::{Address, B256};
use kona_derive::prelude::BlobProvider;
use kona_preimage::CommsClient;
use kona_proof::{BootInfo, FlushableCache};
use risc0_zkvm::serde::Deserializer;
use risc0_zkvm::sha::{Digest, Digestible};
use risc0_zkvm::Receipt;
use serde::Deserialize;
use std::fmt::Debug;
use std::sync::Arc;

#[derive(Clone, Debug, Default, rkyv::Archive, rkyv::Serialize, rkyv::Deserialize)]
pub struct StitchedData {
    pub stitched_executions: Vec<Vec<Execution>>,
    pub stitched_boot_info: Vec<StitchedBootInfo>,
    #[rkyv(with = rkyv::with::Skip)]
    pub stitched_proofs: Vec<Receipt>,
}

#[allow(clippy::too_many_arguments)]
pub fn run_stitching_client<
    // Oracle客户端需要实现通信、缓存刷新、线程安全等特性
    O: CommsClient + FlushableCache + Send + Sync + Debug,
    // 批量数据提供者需要实现克隆和线程安全
    B: BlobProvider + Send + Sync + Debug + Clone,
>(
    precondition_validation_data_hash: B256, // 预验证数据哈希，用于beacon数据的一致性检查，通常由l1链上获取
    oracle: Arc<O>,         // 预映像数据访问器（包含MPT节点，BootInfo等）
    stream: Arc<O>,         // 空
    beacon: B,              // blob交易数据源等
    fpvm_image_id: B256,    // 虚拟机镜像ID，用于证明验证
    payout_recipient_address: Address, // 收益地址，用于激励分配
    stitched_executions: Vec<Vec<Execution>>, // 待缝合的执行轨迹（二维结构支持分片）
    stitched_boot_info: Vec<StitchedBootInfo>, // 虚拟机启动配置集合
) -> ProofJournal
where
    <B as BlobProvider>::Error: Debug,
{
    // Queue up precomputed executions
    // 将原始执行轨迹转换为带缓存的原子引用结构，避免深层复制大型 Execution 结构体
    let (stitched_executions, execution_cache) = split_executions(stitched_executions);

    // Attempt to recompute the output hash at the target block number using kona
    log("RUN");
    let (boot, precondition_hash) = crate::client::run_kailua_client(
        precondition_validation_data_hash,
        oracle,
        stream,
        beacon,
        execution_cache,    // 注入执行缓存
        None,
    )
        .expect("Failed to compute output hash."); // 关键路径失败直接panic

    // Verify proofs recursively for boundless composition
    // 核心步骤2：在ZKVM环境下加载已验证的zkvm证明journal的hash的集合
    #[cfg(target_os = "zkvm")]
    let proven_fpvm_journals = load_stitching_journals(fpvm_image_id);

    // Stitch recursively composed execution-only proofs
    // 核心步骤3：执行轨迹缝合
    stitch_executions(
        &boot,              // 开始执行时的配置信息
        fpvm_image_id,
        payout_recipient_address,
        &stitched_executions, // 原子引用包装的执行轨迹
        #[cfg(target_os = "zkvm")]
        &proven_fpvm_journals, // 仅zkvm环境需要验证集
    );

    // Stitch recursively composed proofs
    // 核心步骤4：启动配置缝合
    stitch_boot_info(
        &boot,
        fpvm_image_id,
        payout_recipient_address,
        precondition_hash,  // 来自run_kailua_client的预处理哈希，对执行轨迹的hash，可以验证中间执行过程的正确性
        stitched_boot_info, // 待缝合的启动配置集合
        #[cfg(target_os = "zkvm")]
        &proven_fpvm_journals,
    )
}

pub fn load_stitching_journals(fpvm_image_id: B256) -> HashSet<Digest> {
    log("VERIFY");  // 开始验证流程的日志标记

    // 将输入参数转换为RISC Zero使用的Digest类型
    let fpvm_image_id = Digest::from(fpvm_image_id.0);
    // 初始化存储已验证日志摘要的集合
    let mut proven_fpvm_journals = HashSet::new();
    // 缓存验证参数（用于SetBuilderReceipt类型的统一验证）
    let mut verifying_params: Option<Digest> = None;

    // 持续从标准输入读取证明数据
    loop {
        // 从zkvm环境的标准输入反序列化Proof对象，Proof是zkvm证明的核心数据结构
        let Ok(receipt) =
            Receipt::deserialize(&mut Deserializer::new(risc0_zkvm::guest::env::stdin()))
        else {
            // 当输入流结束时，输出已收集的证明数量并返回
            log(&format!("PROOFS {}", proven_fpvm_journals.len()));
            break proven_fpvm_journals;
        };

        // 计算当前证明journal的摘要，journal是zkvm运行的程序的结果，如zkvm执行3*4，那么journal=12
        let journal_digest = receipt.journal.digest();
        log(&format!("VERIFY {journal_digest}"));

        // Validate RISC Zero receipts natively
        // 原生验证：直接调用RISC Zero的验证方法
        receipt
            .verify(fpvm_image_id)
            .expect("Failed to verify receipt for {journal_digest}.");

        // 将验证通过的日志摘要加入集合
        proven_fpvm_journals.insert(journal_digest);
    }
}

#[cfg(target_os = "zkvm")]
pub fn verify_stitching_journal(
    fpvm_image_id: B256,      // 虚拟机镜像ID（作为验证域分隔符）
    proof_journal: Vec<u8>,   // 待验证的序列化证明日志（ABI编码格式）
    proven_fpvm_journals: &HashSet<Digest>, // 已通过验证的日志摘要缓存
) {
    // 计算证明日志的密码学摘要（作为唯一标识）
    let journal_digest = proof_journal.digest();

    // 验证缓存检查（避免重复验证）
    if proven_fpvm_journals.contains(&journal_digest) {
        // 命中缓存：记录验证状态
        log(&format!("FOUND {journal_digest}"));
    } else {
        // 缓存未命中：执行链下验证
        log(&format!("ASSUME {journal_digest}"));
        // 调用RISC Zero底层验证原语：
        risc0_zkvm::guest::env::verify(fpvm_image_id.0, &proof_journal)
            .expect("Failed to verify stitched journal assumption"); // 关键路径失败直接panic
    }
}

#[cfg(not(target_os = "zkvm"))]
pub fn verify_stitching_journal(_fpvm_image_id: B256, __proof_journal: Vec<u8>) {
    // noop
}

///执行轨迹的线程安全包装和缓存优化
pub fn split_executions(
    stitched_executions: Vec<Vec<Execution>>,
) -> (Vec<Vec<Arc<Execution>>>, Vec<Arc<Execution>>) {
    let stitched_executions = stitched_executions
        .into_iter()
        .map(|trace| trace.into_iter().map(Arc::new).collect::<Vec<_>>())
        .collect::<Vec<_>>();
    let execution_cache = stitched_executions
        .iter()
        .flatten()
        .cloned()
        .collect::<Vec<_>>();
    (stitched_executions, execution_cache)
}

pub fn stitch_executions(
    boot: &BootInfo,
    fpvm_image_id: B256,
    payout_recipient_address: Address,
    stitched_executions: &Vec<Vec<Arc<Execution>>>,
    #[cfg(target_os = "zkvm")] proven_fpvm_journals: &HashSet<Digest>,
) {
    // 计算Rollup配置的密码学哈希，用于后续一致性验证
    // 使用SHA-256算法对序列化的配置数据进行哈希
    let config_hash = crate::config::config_hash(&boot.rollup_config).unwrap();

    // 检查L1链头是否为初始状态（全零哈希）
    // 当运行纯执行证明时，只能处理单个批次的验证
    // When running an execution-only proof, we may only have one batch validated by the kailua client
    if boot.l1_head.is_zero() {
        assert_eq!(1, stitched_executions.len());  // 强制执行轨迹数量限制
        return;  // 提前返回避免后续处理
    };

    // 遍历每个执行轨迹批次（支持分片处理）
    for execution_trace in stitched_executions {
        // 计算当前批次的执行前置条件哈希
        // 包含交易列表、时间戳等元数据的哈希组合
        let precondition_hash = crate::executor::exec_precondition_hash(execution_trace.as_slice());

        // 验证收据根一致性（Merkle树验证）
        // 确保每个执行生成的收据根与区块头中的声明一致
        // Validate receipt roots
        for execution in execution_trace {
            assert_eq!(
                execution.artifacts.header.receipts_root,
                crate::executor::compute_receipts_root(
                    execution.artifacts.execution_result.receipts.as_slice(),
                    &boot.rollup_config,
                    execution.attributes.payload_attributes.timestamp
                )
            );
        }
        // 构建符合zkVM验证要求的证明日志
        // 结构包含：
        // - 虚拟机镜像ID
        // - 收益地址
        // - 前置条件哈希
        // - 配置哈希
        // - 输入/输出状态声明
        // Construct expected proof journal
        let encoded_journal = ProofJournal::new_stitched(
            fpvm_image_id,
            payout_recipient_address,
            precondition_hash,
            B256::from(config_hash),  // 转换为32字节哈希类型
            &StitchedBootInfo {
                l1_head: B256::ZERO,  // L1链头（当前批次未关联）
                agreed_l2_output_root: execution_trace  // 初始共识输出
                    .first()//批次的起始执行块
                    .expect("Empty execution trace")  // 确保执行轨迹非空
                    .agreed_output,
                claimed_l2_output_root: execution_trace  // 最终声明输出
                    .last()//批次的终止执行块
                    .expect("Empty execution trace")
                    .claimed_output,
                claimed_l2_block_number: execution_trace  // 关联的L2区块号
                    .last()
                    .expect("Empty execution trace")
                    .artifacts
                    .header
                    .number,
            },
        )
            .encode_packed();  // 使用紧凑编码格式序列化

        // 执行全批次的过渡证明验证
        // 在zkVM环境下会检查证明是否存在于已验证集合中
        // Require transition proof for entire batch
        verify_stitching_journal(
            fpvm_image_id,
            encoded_journal,
            #[cfg(target_os = "zkvm")]
            proven_fpvm_journals,
        )
    }
}

pub fn stitch_boot_info(
    boot: &BootInfo,
    fpvm_image_id: B256,
    payout_recipient_address: Address,
    precondition_hash: B256,
    stitched_boot_info: Vec<StitchedBootInfo>,
    #[cfg(target_os = "zkvm")] proven_fpvm_journals: &HashSet<Digest>,
) -> ProofJournal {
    // Stitch boots together into a journal
    // 创建基础证明日志（包含初始状态）
    let mut stitched_journal = ProofJournal::new(
        fpvm_image_id,
        payout_recipient_address,
        precondition_hash,
        boot,
    );

    // 遍历所有待缝合的启动配置
    for stitched_boot in stitched_boot_info {
        // Require equivalence in reference head
        // 检查L1链头一致性：确保所有配置引用相同的L1链状态
        assert_eq!(stitched_boot.l1_head, stitched_journal.l1_head);
        // Require progress in stitched boot
        // 有效性检查：声明输出必须与协定输出不同，证明状态实际变化
        assert_ne!(
            stitched_boot.agreed_l2_output_root,
            stitched_boot.claimed_l2_output_root
        );
        // Require proof assumption
        // 生成并验证当前配置的证明日志
        verify_stitching_journal(
            fpvm_image_id,
            ProofJournal::new_stitched(// 构造临时证明日志
                                       fpvm_image_id,
                                       payout_recipient_address,
                                       precondition_hash,
                                       stitched_journal.config_hash,// 继承配置哈希保证一致性
                                       &stitched_boot,
            )
                .encode_packed(),// 序列化为zkVM可验证格式
            #[cfg(target_os = "zkvm")]
            proven_fpvm_journals,
        );
        // Require continuity
        // 连续性缝合逻辑，即按照顺序进行状态变更
        // 确保状态变更是连续的，避免跳跃或回滚
        if stitched_boot.claimed_l2_output_root == stitched_journal.agreed_l2_output_root {
            // Backward stitch
            // 反向缝合：将协定输出回滚到更早的状态
            stitched_journal.agreed_l2_output_root = stitched_boot.agreed_l2_output_root;
        } else if stitched_boot.agreed_l2_output_root == stitched_journal.claimed_l2_output_root {
            // Forward stitch
            // 正向缝合：推进声明输出到新状态
            stitched_journal.claimed_l2_output_root = stitched_boot.claimed_l2_output_root;
            stitched_journal.claimed_l2_block_number = stitched_boot.claimed_l2_block_number;
        } else {
            // 非连续状态变更目前不支持
            unimplemented!("No support for non-contiguous stitching.");
        }
    }

    stitched_journal
}
