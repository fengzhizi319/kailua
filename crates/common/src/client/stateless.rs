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

use crate::blobs::PreloadedBlobProvider;
use crate::client::log;
use crate::journal::ProofJournal;
use crate::witness::{Witness, WitnessOracle};
use std::sync::Arc;
use tracing::log::warn;

pub fn run_stateless_client<O: WitnessOracle>(witness: Witness<O>) -> ProofJournal {
    // 阶段1：预映像验证
    log(&format!(
        "ORACLE: {} PREIMAGES",
        witness.oracle_witness.preimage_count()
    ));
    witness
        .oracle_witness
        .validate_preimages()
        .expect("Failed to validate preimages");
    // 阶段2：初始化核心组件
    let oracle = Arc::new(witness.oracle_witness);// 见证数据访问器
    // ignore the provided stream witness if any
    let stream = Arc::new(O::default());
    // 阶段3：加载批量数据
    log(&format!(// 流式数据通道（当前未使用）
                 "BEACON: {} BLOBS",
                 witness.blobs_witness.blobs.len()
    ));
    let beacon = PreloadedBlobProvider::from(witness.blobs_witness);
    // 阶段4：执行证明生成
    let proof_journal = crate::client::stitching::run_stitching_client(
        witness.precondition_validation_data_hash, // 验证数据哈希，用于验证beacon数据一致性
        oracle.clone(),        // 见证数据访问器，包含MPT节点，BootInfo等数据
        stream,                // 流式数据通道，当前未使用
        beacon,               // blob数据，主要是中间执行块的output_root数据
        witness.fpvm_image_id, // 虚拟机镜像ID
        witness.payout_recipient_address, // 收益地址
        witness.stitched_executions,      // 执行轨迹集合
        witness.stitched_boot_info,       // 启动配置信息
    );

    // 阶段5：后置检查
    if oracle.preimage_count() > 0 {
        warn!(
            "Found {} extra preimages in witness",
            oracle.preimage_count()
        );
    }

    proof_journal
}
