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
use alloy_primitives::B256;
use anyhow::anyhow;
use kailua_client::proving::ProvingError;
use kailua_common::boot::StitchedBootInfo;
use kailua_common::executor::Execution;
use kona_host::single::{SingleChainHintHandler, SingleChainHost, SingleChainLocalInputs};
use kona_host::{
    DiskKeyValueStore, MemoryKeyValueStore, OfflineHostBackend, OnlineHostBackend, PreimageServer,
    PreimageServerError, SharedKeyValueStore, SplitKeyValueStore,
};
use kona_preimage::{
    BidirectionalChannel, Channel, HintReader, HintWriter, OracleReader, OracleServer,
};
use kona_proof::HintType;
use risc0_zkvm::Receipt;
use std::sync::Arc;
use tokio::sync::RwLock;
use tokio::task;
use tokio::task::JoinHandle;
use tracing::info;

/// Starts the [PreimageServer] and the client program in separate threads. The client program is
/// ran natively in this mode.
///
/// ## Takes
/// - `cfg`: The host configuration.
///
/// ## Returns
/// - `Ok(exit_code)` if the client program exits successfully.
/// - `Err(_)` if the client program failed to execute, was killed by a signal, or the host program
///   exited first.
#[allow(clippy::too_many_arguments)]
/// 启动预镜像服务器与本地客户端协同生成证明的核心入口函数
///
/// # 功能流程
/// 1. 创建双向通信通道
/// 2. 初始化存储服务
/// 3. 并行启动服务端和客户端
/// 4. 等待双端任务完成
///
/// # 参数说明
/// - disk_kv_store: 可选的磁盘存储（None时自动创建）
/// - precondition_validation_data_hash: 预处理验证数据哈希
/// - stitched_*: 多个区块执行数据的拼接结果
/// - prove_snark: SNARK证明类型
/// - force_attempt: 强制尝试生成证明模式
/// - seek_proof: 查找现有证明文件模式，当 seek_proof=true 时优先查找本地证明文件，当 seek_proof=false 时强制生成新证明
pub async fn start_server_and_native_client(
    args: KailuaHostArgs,//
    disk_kv_store: Option<RWLKeyValueStore>,//可选的磁盘存储（None时自动创建）
    precondition_validation_data_hash: B256,//预处理验证数据哈希
    stitched_executions: Vec<Vec<Execution>>,//多个区块执行数据的拼接结果
    stitched_boot_info: Vec<StitchedBootInfo>,//启动配置信息
    stitched_proofs: Vec<Receipt>,//已有证明片段
    prove_snark: bool,// SNARK证明类型，true表示groth16证明，false表示succinct证明
    force_attempt: bool,//强制尝试模式，true表示忽略资源限制
    seek_proof: bool,//证明生成开关
) -> Result<(), ProvingError> {
    // Instantiate data channels
    // 创建双向通信通道（hint用于发送数据请求，preimage用于处理数据请求）
    let hint = BidirectionalChannel::new().map_err(|e| ProvingError::OtherError(anyhow!(e)))?;
    let preimage = BidirectionalChannel::new().map_err(|e| ProvingError::OtherError(anyhow!(e)))?;
    // Create the server and start it.
    // 初始化存储服务（优先使用传入的disk_kv_store，不存在时创建新实例）
    let disk_kv_store = match disk_kv_store {
        None => create_disk_kv_store(&args.kona),  // 自动创建磁盘存储
        v => v,// 使用已有存储实例
    };
    let kv_store = create_key_value_store(&args.kona, disk_kv_store)
        .map_err(|e| ProvingError::OtherError(anyhow!(e)))?;

    // 启动预镜像服务器（异步任务）
    let server_task = start_server(
        &args.kona,       // 区块链配置参数
        kv_store,         // 混合存储（内存+磁盘）
        hint.host,        // 服务端到客户端的提示通道
        preimage.host     // 服务端到客户端的镜像数据通道
    )
        .await  // 异步等待服务启动
        .map_err(|e| ProvingError::OtherError(anyhow!(e)))?; // 错误类型转换
    // Start the client program in a separate child process.
    // 启动证明客户端（异步任务）
    let program_task = tokio::spawn(kailua_client::proving::run_proving_client(
        args.proving,
        args.boundless,
        OracleReader::new(preimage.client),
        HintWriter::new(hint.client),
        precondition_validation_data_hash,
        stitched_executions,
        stitched_boot_info,
        stitched_proofs,
        prove_snark,
        force_attempt,
        seek_proof,
    ));
    // Execute both tasks and wait for them to complete.
    // 并行执行双端任务并等待结果
    info!("Starting preimage server and client program.");
    let (_, client_result) = tokio::try_join!(server_task, program_task,)
        .map_err(|e| ProvingError::OtherError(anyhow!(e)))?;
    // 记录任务完成日志并返回最终结果
    info!(target: "kona_host", "Preimage server and client program have joined.");
    // Return execution result
    client_result
}

pub fn create_disk_kv_store(kona: &SingleChainHost) -> Option<RWLKeyValueStore> {
    /*
    当 data_dir 存在时：
        使用 DiskKeyValueStore::new 创建基于磁盘的键值存储
        通过 RWLKeyValueStore::from 转换为支持读写锁的存储类型
    当 data_dir 不存在时：
        返回 None 表示不使用磁盘存储
     */
    kona.data_dir
        .as_ref()
        .map(|data_dir| RWLKeyValueStore::from(DiskKeyValueStore::new(data_dir.clone())))
}

pub fn create_key_value_store(
    kona: &SingleChainHost,          // 区块链主机配置
    disk_kv_store: Option<RWLKeyValueStore>, // 可选磁盘存储
) -> anyhow::Result<SharedKeyValueStore> {
    // 创建本地链输入存储（包含区块头、交易等）
    let local_kv_store = SingleChainLocalInputs::new(kona.clone());

    // 分层存储结构：本地输入 + 磁盘/内存存储
    let kv_store: SharedKeyValueStore = if let Some(disk_kv_store) = disk_kv_store {
        // 磁盘模式：持久化存储重要数据（如执行轨迹、状态根）
        let split_kv_store = SplitKeyValueStore::new(local_kv_store, disk_kv_store);
        Arc::new(RwLock::new(split_kv_store))
    } else {
        // 内存模式：临时存储高频访问数据（如账户状态）
        let mem_kv_store = MemoryKeyValueStore::new();
        let split_kv_store = SplitKeyValueStore::new(local_kv_store, mem_kv_store);
        Arc::new(RwLock::new(split_kv_store))
    };

    Ok(kv_store)
}

pub async fn start_server<C>(
    kona: &SingleChainHost,
    kv_store: SharedKeyValueStore,
    hint: C,
    preimage: C,
) -> anyhow::Result<JoinHandle<Result<(), PreimageServerError>>>
where
    C: Channel + Send + Sync + 'static,
{
    // 根据运行模式选择不同的后端
    let task_handle = if kona.is_offline() {
        // 离线模式：使用本地存储数据
        task::spawn(
            PreimageServer::new(
                OracleServer::new(preimage),  // 预镜像服务端
                HintReader::new(hint),        // 提示信息读取器
                Arc::new(OfflineHostBackend::new(kv_store)), // 离线存储后端
            )
                .start(), // 启动服务
        )
    } else {
        // 在线模式：连接真实区块链节点
        let providers = kona.create_providers().await?; // 获取节点连接
        let backend = OnlineHostBackend::new(          // 创建在线后端
                                                       kona.clone(),
                                                       kv_store.clone(),
                                                       providers,
                                                       SingleChainHintHandler, // 单链提示处理器
        )
            .with_proactive_hint(HintType::L2PayloadWitness); // 

        task::spawn(
            PreimageServer::new(
                OracleServer::new(preimage),
                HintReader::new(hint),
                Arc::new(backend), // 在线存储后端
            )
                .start(),
        )
    };

    Ok(task_handle)
}
