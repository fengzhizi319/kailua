// Copyright 2025 RISC Zero, Inc.
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
use crate::prove;
use alloy_primitives::B256;
use anyhow::Context;
use async_channel::{Receiver, Sender};
use kailua_client::proving::ProvingError;
use kailua_common::boot::StitchedBootInfo;
use kailua_common::executor::Execution;
use kona_genesis::RollupConfig;
use risc0_zkvm::Receipt;
use std::cmp::Ordering;
use tracing::error;

#[derive(Clone, Debug)]
pub struct Cached {
    pub args: KailuaHostArgs,
    pub rollup_config: RollupConfig,
    pub disk_kv_store: Option<RWLKeyValueStore>,
    pub precondition_hash: B256,
    pub precondition_validation_data_hash: B256,
    pub stitched_executions: Vec<Vec<Execution>>,
    pub stitched_boot_info: Vec<StitchedBootInfo>,
    pub stitched_proofs: Vec<Receipt>,
    pub prove_snark: bool,
    pub force_attempt: bool,
    pub seek_proof: bool,
}

impl Cached {
    pub async fn compute_cached(self) -> Result<Receipt, ProvingError> {
        prove::compute_cached_proof(
            self.args,
            self.rollup_config,
            self.disk_kv_store,
            self.precondition_hash,
            self.precondition_validation_data_hash,
            self.stitched_executions,
            self.stitched_boot_info,
            self.stitched_proofs,
            self.prove_snark,
            self.force_attempt,
            self.seek_proof,
        )
        .await
    }

    pub async fn compute_fpvm(
        self,
        task_sender: Sender<Oneshot>,
    ) -> Result<Option<Receipt>, ProvingError> {
        prove::compute_fpvm_proof(
            self.args,
            self.rollup_config,
            self.disk_kv_store,
            self.precondition_hash,
            self.precondition_validation_data_hash,
            self.stitched_boot_info,
            self.stitched_proofs,
            self.prove_snark,
            task_sender,
        )
        .await
    }
}

impl PartialEq for Cached {
    fn eq(&self, other: &Self) -> bool {
        self.args.eq(&other.args)
    }
}

impl Eq for Cached {}

impl PartialOrd for Cached {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

impl Ord for Cached {
    fn cmp(&self, other: &Self) -> Ordering {
        self.args.cmp(&other.args)
    }
}

#[derive(Debug)]
pub struct OneshotResult {
    pub cached: Cached,
    pub result: Result<Receipt, ProvingError>,
}

impl PartialEq for OneshotResult {
    fn eq(&self, other: &Self) -> bool {
        self.cached.eq(&other.cached)
    }
}

impl Eq for OneshotResult {}

impl PartialOrd for OneshotResult {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

impl Ord for OneshotResult {
    fn cmp(&self, other: &Self) -> Ordering {
        self.cached.cmp(&other.cached)
    }
}

#[derive(Debug)]
pub struct Oneshot {
    pub cached_task: Cached,
    pub result_sender: Sender<OneshotResult>,
}

pub async fn handle_oneshot_tasks(task_receiver: Receiver<Oneshot>) -> anyhow::Result<()> {
    loop {// 持续处理任务的无限循环
        // 从通道接收证明任务（异步阻塞）
        let Oneshot {
            cached_task,
            result_sender,
        } = task_receiver
            .recv()
            .await
            .context("task receiver channel closed")?;

        // 执行证明计算并发送结果
        if let Err(res) = result_sender
            .send(OneshotResult {
                cached: cached_task.clone(),// 克隆任务元数据
                result: cached_task.compute_cached().await,// 执行核心计算
            })
            .await
        {
            error!("failed to send task result: {res:?}");// 错误处理
        }
    }
}

#[allow(clippy::too_many_arguments)]
/// 计算单次证明任务的异步函数，不进行计算分拆
pub async fn compute_oneshot_task(
    args: KailuaHostArgs,                      // 宿主程序配置参数（包含L2节点地址、证明参数等）
    rollup_config: RollupConfig,              // Rollup链配置（包含链ID、合约地址等）
    disk_kv_store: Option<RWLKeyValueStore>,  // 磁盘键值存储（用于缓存证明中间数据）
    precondition_hash: B256,                  // 预处理数据哈希（保证数据完整性）
    precondition_validation_data_hash: B256,  // 预处理验证数据哈希（L1上的存储证明）
    stitched_executions: Vec<Vec<Execution>>, // 已拼接的区块执行轨迹集合
    stitched_boot_info: Vec<StitchedBootInfo>,// 多个子证明的启动信息集合
    stitched_proofs: Vec<Receipt>,            // 已生成的子证明集合
    prove_snark: bool,                       // SNARK证明类型，true表示groth16，false表示succinct
    force_attempt: bool,                      // 强制证明尝试标志（跳过安全检查）
    seek_proof: bool,                         // 是否生成证明
    task_sender: Sender<Oneshot>,             // 异步任务发送通道（用于工作线程池）
) -> Result<Receipt, ProvingError> {
    // create proving task
    // 创建缓存任务实例（封装所有证明参数）
    let cached_task = Cached {
        args,
        rollup_config,
        disk_kv_store,
        precondition_hash,
        precondition_validation_data_hash,
        stitched_executions,
        stitched_boot_info,
        stitched_proofs,
        prove_snark,
        force_attempt,
        seek_proof,
    };
    // create onshot channel
    // 创建单次任务通信通道（容量1保证同步）
    let oneshot_channel = async_channel::bounded(1);
    // dispatch task to pool
    // 将任务发送到工作池（通过MPSC通道）
    task_sender
        .send(Oneshot {
            cached_task,                      // 包含完整证明参数的任务包
            result_sender: oneshot_channel.0,// 结果回传通道发送端
        })
        .await
        .expect("Oneshot channel closed");
    // wait for result
    // 等待并返回证明结果（异步阻塞）
    oneshot_channel
        .1
        .recv()
        .await
        .expect("oneshot_channel should never panic")
        .result                               // 提取最终证明结果
}
