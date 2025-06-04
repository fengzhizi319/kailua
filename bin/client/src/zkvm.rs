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

use crate::proving::ProvingError;
use crate::proving::{KailuaProveInfo, KailuaSessionStats};
use anyhow::{anyhow, Context};
use kailua_build::{KAILUA_FPVM_ELF, KAILUA_FPVM_ID};
use risc0_zkvm::{default_prover, is_dev_mode, ExecutorEnv, InnerReceipt, ProverOpts, Receipt};
use tracing::info;
use tracing::log::warn;

/// 异步运行 ZKVM 客户端，根据提供的见证数据和已有证明生成新的证明。
///
/// # 参数
/// - `witness_frames`: 二维字节向量，包含原始见证数据，每个子向量对应一个输入通道。
/// - `stitched_proofs`: 已有证明的集合，用于递归证明处理。
/// - `prove_snark`: 布尔值，指示是否生成 Groth16 SNARK 证明，`true` 表示生成，`false` 表示生成简洁证明。
/// - `segment_limit`: 计算段大小限制，影响证明并行化和内存管理。
///
/// # 返回值
/// - 成功时返回包含新证明的 `Receipt`，失败时返回 `ProvingError`。
pub async fn run_zkvm_client(
    witness_frames: Vec<Vec<u8>>,
    stitched_proofs: Vec<Receipt>,
    prove_snark: bool,
    segment_limit: u32,
) -> Result<Receipt, ProvingError> {
    // 记录开始运行 ZKVM 客户端的日志
    info!("Running zkvm client.");
    // 使用 tokio::task::spawn_blocking 在阻塞线程池中执行耗时的证明生成任务
    let prove_info = tokio::task::spawn_blocking(move || {
        // 调用 build_zkvm_env 函数创建 ZKVM 执行环境，把witness和Receipt注入到执行环境中
        let env = build_zkvm_env(witness_frames, stitched_proofs, segment_limit)?;
        // 获取默认的证明生成器
        let prover = default_prover();
        // 根据 prove_snark 参数选择证明选项
        let prover_opts = if prove_snark {
            // 若为 true，选择 Groth16 SNARK 证明选项
            ProverOpts::groth16()
        } else {
            // 若为 false，选择简洁证明选项
            ProverOpts::succinct()
        };
        // 使用指定的执行环境、ELF 程序和证明选项进行证明生成
        let risc0_prove_info = prover
            .prove_with_opts(env, KAILUA_FPVM_ELF, &prover_opts)
            .context("prove_with_opts")?;

        // Convert to our own KailuaProveInfo
        // 将 RISC0 的证明信息转换为自定义的 KailuaProveInfo 结构
        let kailua_prove_info = KailuaProveInfo {
            receipt: risc0_prove_info.receipt,
            stats: KailuaSessionStats {
                segments: risc0_prove_info.stats.segments,
                total_cycles: risc0_prove_info.stats.total_cycles,
                user_cycles: risc0_prove_info.stats.user_cycles,
                paging_cycles: risc0_prove_info.stats.paging_cycles,
                reserved_cycles: risc0_prove_info.stats.reserved_cycles,
            },
        };

        // 返回转换后的 KailuaProveInfo 结构，若有错误则包装为 anyhow::Error
        Ok::<_, anyhow::Error>(kailua_prove_info)
    })
        // 等待阻塞任务完成
        .await
        // 处理任务执行过程中的错误，将其转换为 ProvingError::OtherError
        .map_err(|e| ProvingError::OtherError(anyhow!(e)))?
        // 处理证明生成过程中的错误，将其转换为 ProvingError::ExecutionError
        .map_err(|e| ProvingError::ExecutionError(anyhow!(e)))?;

    // 记录证明生成的总周期数和用户周期数日志
    info!(
        "Proof of {} total cycles ({} user cycles) computed.",
        prove_info.stats.total_cycles, prove_info.stats.user_cycles
    );
    // 验证生成的证明是否有效
    prove_info
        .receipt
        .verify(KAILUA_FPVM_ID)
        .context("receipt verification")
        // 处理验证过程中的错误，将其转换为 ProvingError::OtherError
        .map_err(|e| ProvingError::OtherError(anyhow!(e)))?;
    // 记录证明验证成功的日志
    info!("Receipt verified.");

    // 返回验证通过的证明
    Ok(prove_info.receipt)
}


///创建zkvm执行环境，把witness和Receipt注入到执行环境中
pub fn build_zkvm_env<'a>(
    witness_frames: Vec<Vec<u8>>,
    stitched_proofs: Vec<Receipt>,
    segment_limit: u32,
) -> anyhow::Result<ExecutorEnv<'a>> {
    // Execution environment
    // 创建基础执行环境构建器
    let mut builder = ExecutorEnv::builder();
    // Set segment po2
    // 设置计算段大小限制（影响证明并行化和内存管理）
    builder.segment_limit_po2(segment_limit);
    // Pass in witness data
    // 注入原始见证数据（每个frame对应一个输入通道）
    for frame in &witness_frames {
        builder.write_frame(frame);
    }
    // Dev-mode for recursive proofs
    // 开发模式配置（启用快速算法和调试支持）
    if is_dev_mode() {
        builder.env_var("RISC0_DEV_MODE", "1");
    }
    // Pass in proofs
    // 递归证明处理流水线
    for receipt in stitched_proofs {
        // Force in-guest verification (should be used for testing only)
        // 强制递归验证模式（绕过正常验证流程，用于集成测试）
        if std::env::var("KAILUA_FORCE_RECURSION").is_ok() {
            warn!("(KAILUA_FORCE_RECURSION) Forcibly loading receipt as guest input.");
            // Groth16 SNARK证明需要特殊处理（直接写入验证参数）
            builder.write(&receipt)?;
            continue;
        }

        if matches!(receipt.inner, InnerReceipt::Groth16(_)) {
            builder.write(&receipt)?;
        } else {
            // 其他证明类型作为假设条件添加（后续需要实际验证）
            builder.add_assumption(receipt);
        }
    }
    // 最终构建执行环境实例
    builder.build()
}
