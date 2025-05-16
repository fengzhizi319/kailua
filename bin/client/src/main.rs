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

use clap::Parser;
use kailua_client::args::KailuaClientArgs;
use kailua_client::oracle::{HINT_WRITER, ORACLE_READER};
use tracing_subscriber::EnvFilter;

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    // 解析命令行参数
    let args = KailuaClientArgs::parse();
    // 初始化日志订阅器
    kona_cli::init_tracing_subscriber(args.kailua_verbosity, None::<EnvFilter>)?;

    // 获取预条件验证数据哈希（若未指定则使用默认值）
    let precondition_validation_data_hash =
        args.precondition_validation_data_hash.unwrap_or_default();

    // 运行证明客户端
    kailua_client::proving::run_proving_client(
        args.proving,        //
        ORACLE_READER,       //
        HINT_WRITER,         // 提示写入接口
        precondition_validation_data_hash, // 验证数据哈希
        vec![],              // 预留输入参数1（当前为空）
        vec![],              // 预留输入参数2（当前为空）
        vec![],              // 预留输入参数3（当前为空）
        true,                // 启用功能开关1
        true,                // 启用功能开关2
        true,                // 是否证明开关
    )
    .await?;

    Ok(())
}
