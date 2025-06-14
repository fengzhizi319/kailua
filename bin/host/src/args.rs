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

use alloy_primitives::B256;
use clap::{ArgAction, Parser};
use kailua_client::args::parse_b256;
use kailua_client::boundless::BoundlessArgs;
use kailua_client::proving::ProvingArgs;
use kailua_client::telemetry::TelemetryArgs;
use std::cmp::Ordering;

/// The host binary CLI application arguments.
#[derive(Parser, Clone, Debug)]
pub struct KailuaHostArgs {
    #[clap(flatten)]
    pub kona: kona_host::single::SingleChainHost,

    /// Address of OP-NODE endpoint to use
    #[clap(long, env)]
    pub op_node_address: Option<String>,
    /// How many threads to use for fetching preflight data
    #[clap(long, env, default_value_t = 4)]
    pub num_concurrent_preflights: u64,
    /// How many threads to use for computing proofs
    #[clap(long, env, default_value_t = 1)]
    pub num_concurrent_proofs: u64,

    #[clap(flatten)]
    pub proving: ProvingArgs,
    #[clap(flatten)]
    pub boundless: BoundlessArgs,
    #[clap(long, env, default_value_t = false)]
    pub bypass_chain_registry: bool,

    #[clap(long, env, value_delimiter = ',')]
    ///precondition_params[0], 全局起始区块号（L2链的共识起点）
    ///precondition_params[1], 提案输出总数（预期验证的区块数量）
    /// precondition_params[2], 输出间隔（验证检查点的区块间隔）
    pub precondition_params: Vec<u64>,
    #[clap(long, env, value_parser = parse_b256, value_delimiter = ',')]
    ///l2提案被打包的l1的块的block hash
    pub precondition_block_hashes: Vec<B256>,
    #[clap(long, env, value_parser = parse_b256, value_delimiter = ',')]
    /// l2提案对应的交易，作为l1的一笔交易，其blob的hash，blob可能保存着中间区块的执行trace
    pub precondition_blob_hashes: Vec<B256>,

    #[clap(flatten)]
    pub telemetry: TelemetryArgs,

    /// Verbosity level (0-2)
    #[arg(long, short, action = ArgAction::Count)]
    pub v: u8,///用于指定日志的详细程度，范围是 0 到 2。
}

impl PartialEq<Self> for KailuaHostArgs {
    fn eq(&self, other: &Self) -> bool {
        self.kona
            .claimed_l2_block_number
            .eq(&other.kona.claimed_l2_block_number)
    }
}

impl Eq for KailuaHostArgs {}

impl PartialOrd<Self> for KailuaHostArgs {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

impl Ord for KailuaHostArgs {
    fn cmp(&self, other: &Self) -> Ordering {
        self.kona
            .claimed_l2_block_number
            .cmp(&other.kona.claimed_l2_block_number)
    }
}
