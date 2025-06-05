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

use crate::boot::StitchedBootInfo;
use crate::client::log;
use crate::executor::Execution;
use crate::journal::ProofJournal;
use alloy_primitives::{Address, B256};
use kona_derive::prelude::BlobProvider;
use kona_preimage::CommsClient;
use kona_proof::{BootInfo, FlushableCache};
use std::fmt::Debug;
use std::sync::Arc;
#[cfg(target_os = "zkvm")]
use {
    alloy_primitives::map::HashSet,
    risc0_zkvm::{
        serde::Deserializer,
        sha::{Digest, Digestible},
        Receipt,
    },
    serde::Deserialize,
};

/// Executes the primary operation of stitching together execution and boot information for a client,
/// while maintaining composable proofs for validation in a zero-knowledge environment.
///
/// # Arguments
///
/// * `precondition_validation_data_hash` - A `B256` hash used for precondition validation.
/// * `oracle` - An `Arc` wrapped client that implements the `CommsClient` and `FlushableCache`
///    traits. This serves as the provider for external data communication.
/// * `stream` - An `Arc` wrapped client, similar to `oracle`, used for additional communication
///    and streaming purposes.
/// * `beacon` - A generic blob provider `B`, used as a shared dependency for validation
///    operations.
/// * `fpvm_image_id` - A `B256` identifier for the FPVM image to associate with the operations performed.
/// * `payout_recipient_address` - The Ethereum address (`Address`) where payout rewards are allocated.
/// * `stitched_executions` - A nested vector of `Execution` objects containing precomputed execution
///    proofs to be stitched.
/// * `stitched_boot_info` - A vector of `StitchedBootInfo` objects containing boot proofs
///    to be stitched together.
///
/// # Returns
///
/// Returns a `ProofJournal` combining the stitched proofs.
///
/// # Functionality
///
/// - **Execution Queueing:** Precomputed executions are split into direct executables and cache components
///   for intermediate processing.
/// - **Output Validation:** Computes the output hash of the target block using a helper method
///   (`run_core_client`) and validates the precondition against the provided hash.
/// - **Proof Loading (Conditional):** For zero-knowledge validations (`zkvm`), loads previously
///   proven FPVM journals to maintain composability and recursive proof validation.
/// - **Execution Stitching:** Merges the precomputed execution proofs into a single verifiable
///   entity while associating it with a target address.
/// - **Boot Info Stitching:** Stitches together boot proofs based on the precondition hash and FPVM image ID.
///
/// # Platform Specific Behavior
///
/// This function behaves differently on platforms supporting `zkvm`:
/// - It loads proven FPVM journals (`load_stitching_journals`) to ensure recursive zero-knowledge proofs
///   are intact.
/// - Passes the proven journals to the execution and boot info stitching processes for extended validation.
///
/// # Panics
///
/// This function will panic if:
/// - The output hash computation (`run_core_client`) fails.
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
    let (boot, precondition_hash) = crate::client::core::run_core_client(
        precondition_validation_data_hash,
        oracle,
        stream,
        beacon,
        execution_cache,
        None,
    )
        .expect("Failed to compute output hash.");

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

/// Loads and verifies stitching journals for a given FPVM image.
///
/// This function continuously reads receipts representing the proofs of computations from the
/// standard input (stdin). Each receipt is validated against the provided `fpvm_image_id`,
/// representing the image digest of the FPVM. Validated receipts' journal digests are stored
/// in a `HashSet` ensuring uniqueness. If deserialization of the receipt fails, the function
/// terminates and returns the set of proven journal digests.
///
/// # Parameters
/// - `fpvm_image_id`: A `B256` type identifier representing the hashed image ID of the FPVM.
///
/// # Returns
/// - A `HashSet<Digest>` containing the unique journal digests of all verified receipts.
///
/// # Behavior
/// 1. Converts the `fpvm_image_id` into a `Digest` for verification purposes.
/// 2. Reads receipts in a loop from the standard input until an `Err` occurs during deserialization.
///    - While reading receipts:
///      - Logs the verification process.
///      - Deserializes and verifies receipts against the provided `fpvm_image_id`.
///      - Inserts successfully verified journal digests into the `HashSet`.
/// 3. Logs the total number of successfully verified journal digests and exits with the result.
///
/// # Panics
/// Panics if:
/// - Receipt verification fails, indicating an invalid or tampered proof. The panic message will
///   include which journal digest's verification failed.
///
/// # Logging
/// - Logs "VERIFY" at the start of the method.
/// - Logs "VERIFY {journal_digest}" after calculating journal digests.
/// - Logs "PROOFS {count}" denoting the number of proven journal digests before exiting.
///
/// # Notes
/// - The `Receipt::deserialize` and `risc0_zkvm::guest::env::stdin` are used to process input
///   receipts.
/// - This function is designed for environments where proofs generated externally are verified
///   within the FPVM.
#[cfg(target_os = "zkvm")]
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

/// Verifies the stitching journal of an FPVM image.
///
/// This function checks the validity of a journal based on its digest and the existing
/// set of proven FPVM journal digests. The behavior of this function depends on the
/// target OS being `zkvm`. If the journal's digest exists in the set of verified digests,
/// it logs that the digest was found. Otherwise, it assumes the journal and attempts to
/// verify it using the RISC Zero ZKVM environment.
///
/// # Parameters
/// - `_fpvm_image_id`: The ID of the FPVM image represented as a `B256` hash. This
///   ID is used during the journal verification process.
/// - `_proof_journal`: The serialized proof journal as a `Vec<u8>`. It serves as
///   the data to be verified.
/// - `proven_fpvm_journals`: A reference to a `HashSet` of digests (of type `Digest`)
///   containing the previously verified journals. This parameter is only used when
///   the target OS is `zkvm`.
///
/// # Logs
/// - Logs a message indicating whether the given journal digest was "FOUND" in the proven
///   set or "ASSUME" if it is not present.
///
/// # Panics
/// - If the verification process fails (i.e., the journal does not match the
///   expected criteria for verification), the function will panic with the message:
///   `"Failed to verify stitched journal assumption"`.
pub fn verify_stitching_journal(
    _fpvm_image_id: B256,
    _proof_journal: Vec<u8>,
    #[cfg(target_os = "zkvm")] proven_fpvm_journals: &HashSet<Digest>,
) {
    #[cfg(target_os = "zkvm")]
    {
        let journal_digest = _proof_journal.digest();
        // 验证缓存检查（避免重复验证）
        if proven_fpvm_journals.contains(&journal_digest) {
            // 命中缓存：记录验证状态
            crate::client::log(&format!("FOUND {journal_digest}"));
        } else {
            // 缓存未命中：执行链下验证
            crate::client::log(&format!("ASSUME {journal_digest}"));
            // 调用RISC Zero底层验证原语：
            risc0_zkvm::guest::env::verify(_fpvm_image_id.0, &_proof_journal)
                .expect("Failed to verify stitched journal assumption");
        }
    }
}

/// Splits a provided two-dimensional vector of `Execution` objects into two separate structures:
/// - A nested two-dimensional vector where each inner `Execution` is wrapped in an `Arc`.
/// - A flattened vector containing all the `Execution` objects, each wrapped in an `Arc`.
///
/// This function is useful for scenarios where you want to maintain the original structure
/// but also need a separate flattened cache to quickly access all `Execution` objects.
///
/// # Arguments
///
/// * `stitched_executions` - A two-dimensional vector of `Execution` objects (`Vec<Vec<Execution>>`)
///   representing grouped and stitched executions.
///
/// # Returns
///
/// A tuple containing:
/// 1. A two-dimensional vector (`Vec<Vec<Arc<Execution>>>`) where each `Execution` is wrapped in an `Arc`.
/// 2. A flattened vector (`Vec<Arc<Execution>>`) representing a cache of all `Execution` objects.
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

/// Stitches a collection of execution traces into a cohesive proof journal and validates the results.
/// This function ensures the integrity of execution traces and their compliance with the rollup configuration.
///
/// # Parameters
/// - `boot`: A reference to the `BootInfo` structure containing the rollup's configuration and state information.
/// - `fpvm_image_id`: The unique identifier of the FPVM (Fault-Proof Virtual Machine) image being used for proofs.
/// - `payout_recipient_address`: The address to receive the payout as a result of the execution.
/// - `stitched_executions`: A reference to a vector of vectors containing execution traces. Each inner vector represents
///     a sequence of linked execution steps (`Execution` objects).
/// - `proven_fpvm_journals` (*conditional*): A reference to a set of `Digest` values representing proven
///     journals from the FPVM. Only available when compiled for `zkvm` target (`#[cfg(target_os = "zkvm")]`).
///
/// # Behavior
/// - When the `boot.l1_head` is zero, it represents a special case where only one batch of execution is validated
///   by the Kailua client. If more than one batch is found, the function panics.
/// - Validates the `receipts_root` of each execution in all traces by comparing it with the computed root value
///   based on the execution result, rollup configuration, and payload attributes' timestamp.
/// - Constructs an expected proof journal for each execution trace, which includes precondition and configuration
///   hashes, and other state values derived from the execution trace (e.g., output roots and block numbers).
/// - When the system is targeting `zkvm`, the proof journal is verified using the `proven_fpvm_journals`.
///
/// # Panics
/// - When `boot.l1_head` is zero but the number of `stitched_executions` exceeds 1.
/// - When an execution trace is empty (used in `.first()` or `.last()` calls without valid elements).
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
                kona_executor::compute_receipts_root(
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

/// Stitches multiple boot information records into a unified `ProofJournal`.
///
/// This function consolidates and verifies multiple bootstrapping records, validating their
/// integrity and creating a coherent journal that reflects the intermediate states and outputs
/// of the bootstrapping process.
///
/// # Arguments
///
/// * `boot` - A reference to the base `BootInfo` structure used as the initial data point.
/// * `fpvm_image_id` - A 256-bit identifier representing the FPVM image being used.
/// * `payout_recipient_address` - The Ethereum address to which payouts should be sent.
/// * `precondition_hash` - A 256-bit hash representing the preconditions required for stitching.
/// * `stitched_boot_info` - A vector of `StitchedBootInfo` objects that are incrementally stitched
///   into the `ProofJournal`.
/// * `proven_fpvm_journals` - (Optional, only on `zkvm` platforms) A reference to a set of
///   precomputed and verified FPVM journal digests used for proof verification.
///
/// # Returns
///
/// A `ProofJournal` object that reflects the final stitched state after processing
/// all input records.
///
/// # Panics
///
/// This function will panic in the following scenarios:
///
/// 1. **Equivalence Check Failure**: If the `l1_head` values in the current and stitched boots
///    are inconsistent.
/// 2. **Progress Check Failure**: If there is no progress between the `agreed_l2_output_root` and
///    `claimed_l2_output_root` of a `stitched_boot` object.
/// 3. **Proof Assumption Failure**: If the stitching proof journal fails the `verify_stitching_journal`
///    check.
/// 4. **Non-contiguous Stitching**: If the claimed and agreed L2 output roots cannot be matched
///    in a forward or backward stitching configuration.
///
/// # Stitching Logic
///
/// 1. The function initializes a `ProofJournal` object using the base `BootInfo` structure and
///    additional parameters.
/// 2. For each `StitchedBootInfo` object in `stitched_boot_info`:
///     - Verify the equivalence of `l1_head`.
///     - Ensure progress is made between `agreed_l2_output_root` and `claimed_l2_output_root`.
///     - Validate the proof associated with the stitching via the `verify_stitching_journal` function.
///     - Perform continuity checks and update the journal in a forward or backward stitching
///       configuration. If stitching is non-contiguous, the function will panic.
///
/// # Platform-specific Behavior
///
/// * On `zkvm` platforms, the function requires access to `proven_fpvm_journals` to verify stitching
///   proofs. On other platforms, the verification step is omitted.
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

#[cfg(test)]
#[cfg_attr(coverage_nightly, coverage(off))]
pub mod tests {
    use super::*;
    use crate::client::core::tests::test_derivation;
    use crate::client::tests::TestOracle;
    use crate::precondition::PreconditionValidationData;
    use alloy_primitives::b256;
    use anyhow::Context;
    use kona_proof::l1::OracleBlobProvider;
    use rayon::prelude::{IntoParallelIterator, ParallelIterator};
    use tracing_subscriber::EnvFilter;

    fn setup() {
        let _ = kona_cli::init_tracing_subscriber(1, None::<EnvFilter>);
    }

    fn teardown() {
        let _ = kona_cli::init_tracing_subscriber(0, None::<EnvFilter>);
    }

    fn validate_proof_journal(
        proof_journal: ProofJournal,
        boot_info: BootInfo,
        precondition_hash: Option<B256>,
    ) {
        assert_eq!(proof_journal.l1_head, boot_info.l1_head);
        assert_eq!(
            proof_journal.agreed_l2_output_root,
            boot_info.agreed_l2_output_root
        );
        assert_eq!(
            proof_journal.claimed_l2_output_root,
            boot_info.claimed_l2_output_root
        );
        assert_eq!(
            proof_journal.claimed_l2_block_number,
            boot_info.claimed_l2_block_number
        );
        if let Some(expected_precondition_hash) = precondition_hash {
            assert_eq!(proof_journal.precondition_hash, expected_precondition_hash);
        }
        assert!(proof_journal.payout_recipient.is_zero());
        assert!(proof_journal.fpvm_image_id.is_zero());
    }

    pub fn test_stitching(
        boot_info: BootInfo,
        precondition_validation_data: Option<PreconditionValidationData>,
        stitched_executions: Vec<Vec<Execution>>,
        stitched_boot_info: Vec<StitchedBootInfo>,
    ) {
        let precondition_hash = precondition_validation_data
            .as_ref()
            .map(|d| d.precondition_hash());
        let proof_journal = test_stitching_client(
            boot_info.clone(),
            precondition_validation_data,
            stitched_executions,
            stitched_boot_info,
        );
        validate_proof_journal(proof_journal, boot_info, precondition_hash);
    }

    pub fn test_stitching_client(
        boot_info: BootInfo,
        precondition_validation_data: Option<PreconditionValidationData>,
        stitched_executions: Vec<Vec<Execution>>,
        stitched_boot_info: Vec<StitchedBootInfo>,
    ) -> ProofJournal {
        let oracle = Arc::new(TestOracle::new(boot_info.clone()));//根据boot_info创建测试oracle,包含存储等
        let precondition_validation_data_hash = match precondition_validation_data {
            None => B256::ZERO,
            Some(data) => oracle.add_precondition_data(data),
        };
        run_stitching_client(
            precondition_validation_data_hash,
            oracle.clone(),
            oracle.clone(),
            OracleBlobProvider::new(oracle.clone()),
            B256::ZERO,
            Address::ZERO,
            stitched_executions,
            stitched_boot_info,
        )
    }

    pub fn test_stitching_boots(
        boot_info: BootInfo,
        precondition_validation_data: Option<PreconditionValidationData>,
    ) -> anyhow::Result<()> {
        let stitched_executions =
            test_derivation(boot_info.clone(), precondition_validation_data.clone())
                .context("test_derivation")?
                .into_iter()
                .map(|e| e.as_ref().clone())
                .collect::<Vec<_>>();
        let stitched_boot_info = stitched_executions
            .iter()
            .map(|e| StitchedBootInfo {
                l1_head: boot_info.l1_head,
                agreed_l2_output_root: e.agreed_output,
                claimed_l2_output_root: e.claimed_output,
                claimed_l2_block_number: e.artifacts.header.number,
            })
            .collect::<Vec<_>>();
        let precondition_hash = precondition_validation_data
            .as_ref()
            .map(|d| d.precondition_hash());
        // forward stitching pass
        let starting_block_number = stitched_executions
            .first()
            .map(|e| e.artifacts.header.number - 1)
            .unwrap_or(boot_info.claimed_l2_block_number);
        let proof_journal = test_stitching_client(
            BootInfo {
                l1_head: boot_info.l1_head,
                agreed_l2_output_root: boot_info.agreed_l2_output_root,
                claimed_l2_output_root: boot_info.agreed_l2_output_root,
                claimed_l2_block_number: starting_block_number,
                chain_id: boot_info.chain_id,
                rollup_config: boot_info.rollup_config.clone(),
            },
            precondition_validation_data.clone(),
            vec![],
            stitched_boot_info.clone(),
        );
        validate_proof_journal(proof_journal, boot_info.clone(), precondition_hash);
        // backward stitching pass
        let ending_block_number = stitched_executions
            .last()
            .map(|e| e.artifacts.header.number)
            .unwrap_or(boot_info.claimed_l2_block_number);
        let proof_journal = test_stitching_client(
            BootInfo {
                l1_head: boot_info.l1_head,
                agreed_l2_output_root: boot_info.claimed_l2_output_root,
                claimed_l2_output_root: boot_info.claimed_l2_output_root,
                claimed_l2_block_number: ending_block_number,
                chain_id: boot_info.chain_id,
                rollup_config: boot_info.rollup_config.clone(),
            },
            precondition_validation_data.clone(),
            vec![],
            stitched_boot_info.clone().into_iter().rev().collect(),
        );
        validate_proof_journal(proof_journal, boot_info.clone(), precondition_hash);
        // fail out of order stitching
        let n = stitched_executions.len();
        (0..n).into_par_iter().for_each(|i| {
            (i + 1..n).into_par_iter().for_each(|j| {
                let mut stitched_boot_info = stitched_boot_info.clone();
                stitched_boot_info.swap(i, j);
                let result = std::panic::catch_unwind(|| {
                    test_stitching_client(
                        BootInfo {
                            l1_head: boot_info.l1_head,
                            agreed_l2_output_root: boot_info.claimed_l2_output_root,
                            claimed_l2_output_root: boot_info.claimed_l2_output_root,
                            claimed_l2_block_number: ending_block_number,
                            chain_id: boot_info.chain_id,
                            rollup_config: boot_info.rollup_config.clone(),
                        },
                        precondition_validation_data.clone(),
                        vec![],
                        stitched_boot_info.clone().into_iter().rev().collect(),
                    )
                });
                assert!(result.is_err());
            })
        });

        Ok(())
    }

    pub fn test_stitching_executions(
        boot_info: BootInfo,
        precondition_validation_data: Option<PreconditionValidationData>,
    ) -> anyhow::Result<()> {
        let stitched_executions =
            test_derivation(boot_info.clone(), precondition_validation_data.clone())
                .context("test_derivation")?
                .into_iter()
                .map(|e| e.as_ref().clone())
                .collect::<Vec<_>>();
        // flat pass
        test_stitching(
            boot_info.clone(),
            precondition_validation_data.clone(),
            vec![stitched_executions.clone()],
            vec![],
        );
        let n = stitched_executions.len();
        // don't test exec trace stitching if unnecessary or exec only mode
        if n == 1 {
            return Ok(());
        }
        // split pass
        let (left, right) = stitched_executions.split_at(n / 2);
        test_stitching(
            boot_info.clone(),
            precondition_validation_data.clone(),
            vec![left.to_vec(), right.to_vec()],
            vec![],
        );
        // fully fragmented pass
        test_stitching(
            boot_info.clone(),
            precondition_validation_data.clone(),
            stitched_executions.into_iter().map(|e| vec![e]).collect(),
            vec![],
        );
        Ok(())
    }

    pub fn test_stitching_execution_only(
        mut boot_info: BootInfo,
        precondition_validation_data: Option<PreconditionValidationData>,
        stitched_boot_info: Vec<StitchedBootInfo>,
    ) -> anyhow::Result<()> {
        let stitched_executions =
            test_derivation(boot_info.clone(), precondition_validation_data.clone())
                .context("test_derivation")?
                .into_iter()
                .map(|e| e.as_ref().clone())
                .collect::<Vec<_>>();
        // flat pass
        boot_info.l1_head = B256::ZERO;
        test_stitching(
            boot_info.clone(),
            precondition_validation_data.clone(),
            vec![stitched_executions.clone()],
            stitched_boot_info.clone(),
        );
        Ok(())
    }

    #[tokio::test(flavor = "multi_thread")]
    pub async fn test_op_sepolia_16491249_16491250() {
        setup();

        test_stitching(
            BootInfo {
                l1_head: b256!(
                    "0x417ffee9dd1ccbd35755770dd8c73dbdcd96ba843c532788850465bdd08ea495"
                ),
                agreed_l2_output_root: b256!(
                    "0x82da7204148ba4d8d59e587b6b3fdde5561dc31d9e726220f7974bf9f2158d75"
                ),
                claimed_l2_output_root: b256!(
                    "0xa130fbfa315391b28668609252e4c09c3df3b77562281b996af30bf056cbb2c1"
                ),
                claimed_l2_block_number: 16491250,
                chain_id: 11155420,
                rollup_config: Default::default(),
            },
            None,
            vec![],
            vec![],
        );

        teardown();
    }

    #[tokio::test(flavor = "multi_thread")]
    pub async fn test_op_sepolia_16491249_16491250_stitched_execution() {
        setup();

        test_stitching_executions(
            BootInfo {
                l1_head: b256!(
                    "0x417ffee9dd1ccbd35755770dd8c73dbdcd96ba843c532788850465bdd08ea495"
                ),
                agreed_l2_output_root: b256!(
                    "0x82da7204148ba4d8d59e587b6b3fdde5561dc31d9e726220f7974bf9f2158d75"
                ),
                claimed_l2_output_root: b256!(
                    "0xa130fbfa315391b28668609252e4c09c3df3b77562281b996af30bf056cbb2c1"
                ),
                claimed_l2_block_number: 16491250,
                chain_id: 11155420,
                rollup_config: Default::default(),
            },
            None,
        )
            .unwrap();

        teardown();
    }

    #[tokio::test(flavor = "multi_thread")]
    pub async fn test_op_sepolia_16491249_16491349() {
        setup();

        test_stitching(
            BootInfo {
                l1_head: b256!(
                    "0x417ffee9dd1ccbd35755770dd8c73dbdcd96ba843c532788850465bdd08ea495"
                ),
                agreed_l2_output_root: b256!(
                    "0x82da7204148ba4d8d59e587b6b3fdde5561dc31d9e726220f7974bf9f2158d75"
                ),
                claimed_l2_output_root: b256!(
                    "0x6984e5ae4d025562c8a571949b985692d80e364ddab46d5c8af5b36a20f611d1"
                ),
                claimed_l2_block_number: 16491349,
                chain_id: 11155420,
                rollup_config: Default::default(),
            },
            Some(PreconditionValidationData::Validity {
                proposal_l2_head_number: 16491249,
                proposal_output_count: 1,
                output_block_span: 100,
                blob_hashes: vec![],
            }),
            vec![],
            vec![],
        );

        teardown();
    }

    #[tokio::test(flavor = "multi_thread")]
    pub async fn test_op_sepolia_16491249_16491349_stitched_executions() {
        setup();

        test_stitching_executions(
            BootInfo {
                l1_head: b256!(
                    "0x417ffee9dd1ccbd35755770dd8c73dbdcd96ba843c532788850465bdd08ea495"
                ),
                agreed_l2_output_root: b256!(
                    "0x82da7204148ba4d8d59e587b6b3fdde5561dc31d9e726220f7974bf9f2158d75"
                ),
                claimed_l2_output_root: b256!(
                    "0x6984e5ae4d025562c8a571949b985692d80e364ddab46d5c8af5b36a20f611d1"
                ),
                claimed_l2_block_number: 16491349,
                chain_id: 11155420,
                rollup_config: Default::default(),
            },
            Some(PreconditionValidationData::Validity {
                proposal_l2_head_number: 16491249,
                proposal_output_count: 1,
                output_block_span: 100,
                blob_hashes: vec![],
            }),
        )
            .unwrap();

        teardown();
    }

    #[tokio::test(flavor = "multi_thread")]
    pub async fn test_op_sepolia_16491249_16491349_execution_only() {
        setup();

        test_stitching_execution_only(
            BootInfo {
                l1_head: b256!(
                    "0x417ffee9dd1ccbd35755770dd8c73dbdcd96ba843c532788850465bdd08ea495"
                ),
                agreed_l2_output_root: b256!(
                    "0x82da7204148ba4d8d59e587b6b3fdde5561dc31d9e726220f7974bf9f2158d75"
                ),
                claimed_l2_output_root: b256!(
                    "0x6984e5ae4d025562c8a571949b985692d80e364ddab46d5c8af5b36a20f611d1"
                ),
                claimed_l2_block_number: 16491349,
                chain_id: 11155420,
                rollup_config: Default::default(),
            },
            None,
            vec![],
        )
            .unwrap();

        teardown();
    }

    #[tokio::test(flavor = "multi_thread")]
    pub async fn test_op_sepolia_16491249_16491349_stitched_boots() {
        setup();

        test_stitching_boots(
            BootInfo {
                l1_head: b256!(
                    "0x417ffee9dd1ccbd35755770dd8c73dbdcd96ba843c532788850465bdd08ea495"
                ),
                agreed_l2_output_root: b256!(
                    "0x82da7204148ba4d8d59e587b6b3fdde5561dc31d9e726220f7974bf9f2158d75"
                ),
                claimed_l2_output_root: b256!(
                    "0x6984e5ae4d025562c8a571949b985692d80e364ddab46d5c8af5b36a20f611d1"
                ),
                claimed_l2_block_number: 16491349,
                chain_id: 11155420,
                rollup_config: Default::default(),
            },
            Some(PreconditionValidationData::Validity {
                proposal_l2_head_number: 16491249,
                proposal_output_count: 1,
                output_block_span: 100,
                blob_hashes: vec![],
            }),
        )
            .unwrap();

        teardown();
    }
}
