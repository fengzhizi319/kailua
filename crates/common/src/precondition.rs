// Copyright 2024 RISC Zero, Inc.
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

use crate::blobs::{hash_to_fe, BlobFetchRequest};
use alloy_eips::eip4844::{Blob, FIELD_ELEMENTS_PER_BLOB};
use alloy_primitives::B256;
use anyhow::bail;
use kona_derive::prelude::BlobProvider;
use kona_preimage::{CommsClient, PreimageKey, PreimageKeyType};
use kona_proof::errors::OracleProviderError;
use risc0_zkvm::sha::{Impl as SHA2, Sha256};
use serde::{Deserialize, Serialize};
use std::cmp::Ordering;
use std::fmt::Debug;
use std::iter::once;
use std::sync::Arc;

/* 数据结构定义
PreconditionValidationData::Validity(
param1: u64,      // L1 区块时间窗口起始时间戳
param2: u64,      // L1 区块时间窗口结束时间戳
param3: B256,     // 预期的 Blob 数据根哈希
fetch_requests: Vec<BlobFetchRequest> // L1 区块中的 Blob 位置证明
);
 */
#[derive(Clone, Debug, Serialize, Deserialize)]
pub enum PreconditionValidationData {
    ///全局起始区块号（L2链的共识起点）、提案输出总数（预期验证的区块数量）、输出间隔（验证检查点的区块间隔）、blob请求集合
    Validity(u64, u64, u64, Vec<BlobFetchRequest>),

}

impl PreconditionValidationData {
    pub fn to_vec(&self) -> Vec<u8> {
        pot::to_vec(self).unwrap()
    }

    pub fn hash(&self) -> B256 {
        let digest = *SHA2::hash_bytes(&self.to_vec());
        B256::from_slice(digest.as_bytes())
    }

    pub fn blob_fetch_requests(&self) -> &[BlobFetchRequest] {
        match self {
            PreconditionValidationData::Validity(_, _, _, requests) => requests.as_slice(),
        }
    }

    pub fn blobs_hash(&self) -> B256 {
        blobs_hash(self.blob_fetch_requests().iter().map(|b| &b.blob_hash.hash))
    }
    
    ///计算blobs索引信息的hash
    pub fn precondition_hash(&self) -> B256 {
        match self {
            PreconditionValidationData::Validity(
                global_l2_head_number,    // 全局起始区块号（L2链的共识起点）
                proposal_output_count,    // 提案输出总数（预期验证的区块数量）
                output_block_span,        // 输出间隔（验证检查点的区块间隔）
                blobs,     // 关联的blob请求集合
            ) => equivalence_precondition_hash(
                global_l2_head_number,     // 输入1：验证范围的起始点
                proposal_output_count,    // 输入2：预期生成的输出数量
                output_block_span,        // 输入3：输出间隔参数
                // 计算blob集合的哈希（聚合所有blob哈希）
                blobs_hash(blobs.iter().map(|b| &b.blob_hash.hash)),
            ),
        }
    }
}

pub fn divergence_precondition_hash(
    agreement_index: &u64,
    contender_blob_hash: &B256,
    opponent_blob_hash: &B256,
) -> B256 {
    let agreement_index_bytes = agreement_index.to_be_bytes();
    let digest = *SHA2::hash_bytes(
        &[
            agreement_index_bytes.as_slice(),
            contender_blob_hash.as_slice(),
            opponent_blob_hash.as_slice(),
        ]
            .concat(),
    );
    B256::from_slice(digest.as_bytes())
}

pub fn equivalence_precondition_hash(
    global_l2_head_number: &u64,
    proposal_output_count: &u64,
    output_block_span: &u64,
    blobs_hash: B256,
) -> B256 {
    let ghn_bytes = global_l2_head_number.to_be_bytes();
    let poc_bytes = proposal_output_count.to_be_bytes();
    let obs_bytes = output_block_span.to_be_bytes();
    let all_bytes = once(ghn_bytes.as_slice())
        .chain(once(poc_bytes.as_slice()))
        .chain(once(obs_bytes.as_slice()))
        .chain(once(blobs_hash.as_slice()))
        .collect::<Vec<_>>()
        .concat();
    let digest = *SHA2::hash_bytes(&all_bytes);
    B256::from_slice(digest.as_bytes())
}

pub fn blobs_hash<'a>(blob_hashes: impl Iterator<Item = &'a B256>) -> B256 {
    let blobs_hash_bytes = blob_hashes
        .map(|h| h.as_slice())
        .collect::<Vec<_>>()
        .concat();
    let digest = *SHA2::hash_bytes(&blobs_hash_bytes);
    B256::from_slice(digest.as_bytes())
}

///获取blob在L1的索引信息以及blob的值
pub async fn load_precondition_data<
    O: CommsClient + Send + Sync + Debug,
    B: BlobProvider + Send + Sync + Debug + Clone,
>(
    precondition_data_hash: B256,  // 预验证数据的哈希值（SHA256）
    oracle: Arc<O>,                // 预映像数据源（实现CommsClient接口）
    beacon: &mut B,                // 批量数据提供者（实现BlobProvider接口）
) -> anyhow::Result<Option<(PreconditionValidationData, Vec<Blob>)>>
where
    <B as BlobProvider>::Error: Debug,
{
    // 零值哈希表示不需要预验证，直接返回
    if precondition_data_hash.is_zero() {
        return Ok(None);
    }
    // Read the blob references to fetch
    // 从预映像预言机获取序列化的预验证数据
    // 使用pot（Pretty Object Trait）进行高效序列化/反序列化
    let precondition_validation_data: PreconditionValidationData = pot::from_slice(
        &oracle
            .get(PreimageKey::new(
                *precondition_data_hash,    // 构造SHA256类型的预映像键
                PreimageKeyType::Sha256,
            ))
            .await  // 异步等待数据获取
            .map_err(OracleProviderError::Preimage)?, // 转换预映像获取错误
    )?; // 处理反序列化错误

    let mut blobs = Vec::new();
    // Read the blobs to validate divergence
    // 遍历预验证数据中的每个blob请求
    for request in precondition_validation_data.blob_fetch_requests() {
        // 从beacon节点获取具体的blob数据
        // 使用块引用和blob哈希定位具体数据
        blobs.push(
            *beacon
                .get_blobs(
                    &request.block_ref,       // 目标区块引用（包含区块号/哈希）
                    &[request.blob_hash.clone()] // 需要获取的blob哈希列表
                )
                .await
                .unwrap()[0],  // 安全解包第一个blob（请求确保存在）
        );
    }

    // 返回元组：(预验证元数据, 关联的blob数据集合)
    Ok(Some((precondition_validation_data, blobs)))
}

pub fn validate_precondition(
    precondition_validation_data: PreconditionValidationData,
    blobs: Vec<Blob>,
    local_l2_head_number: u64,
    output_roots: &[B256],
) -> anyhow::Result<B256> {
    let precondition_hash = precondition_validation_data.precondition_hash();
    match precondition_validation_data {
        PreconditionValidationData::Validity(
            global_l2_head_number,  // 全局起始区块号
            proposal_output_count,   // 提案输出总数
            output_block_span,       // 输出间隔区块数
            _,                      // blob请求列表（已通过load_precondition_data获取）
        ) => {
	    // Ensure local and global block ranges match
            // 验证1：检查本地与全局区块范围一致性
            if global_l2_head_number > local_l2_head_number {
                bail!(
                    "Validity precondition global starting block #{} > local agreed l2 head #{}",
                    global_l2_head_number,
                    local_l2_head_number
                )
            } else if output_roots.is_empty() {
                // abort early if no validation is to take place
                return Ok(precondition_hash);
            }
            // Calculate blob index pointer
            let max_block_number =
                global_l2_head_number + proposal_output_count * output_block_span;
            // 遍历每个输出根进行密码学验
            for (i, output_hash) in output_roots.iter().enumerate() {
                let output_block_number = local_l2_head_number + i as u64 + 1;
                // 验证2：区块号不超过提案范围
                if output_block_number > max_block_number {
                    // We should not derive outputs beyond the proposal root claim
                    bail!("Output block #{output_block_number} > max block #{max_block_number}.");
                } else if output_block_number % output_block_span != 0 {
                    // 跳过非检查点的区块（根据输出间隔）
                    // We only check equivalence every output_block_span blocks
                    continue;
                }
                // 计算blob定位参数
                let output_offset =
                    ((output_block_number - global_l2_head_number) / output_block_span) - 1;
                let blob_index = (output_offset / FIELD_ELEMENTS_PER_BLOB) as usize;
                let fe_position = (output_offset % FIELD_ELEMENTS_PER_BLOB) as usize;
                let blob_fe_index = 32 * fe_position;// 每个域元素占32字节
                // Verify fe equivalence to computed outputs for all but last output
                // 密码学验证阶段
                match output_offset.cmp(&(proposal_output_count - 1)) {
                    Ordering::Less => {
                        // verify equivalence to blob
                        // 验证3：Blob数据等价性检查
                        // 步骤3a：从blob中提取密码学承诺
                        let blob_fe_slice = &blobs[blob_index][blob_fe_index..blob_fe_index + 32];
                        // 步骤3b：将输出根哈希转换为椭圆曲线域元素
                        let output_fe = hash_to_fe(*output_hash);
                        // 步骤3c：序列化域元素为32字节大端格式
                        let output_fe_bytes = output_fe.to_be_bytes::<32>();
                        // 步骤3d：比对blob承诺与实际计算值
                        if blob_fe_slice != output_fe_bytes.as_slice() {
                            bail!(
                                "Bad fe #{} in blob {} for block #{}: Expected {} found {} ",
                                fe_position,
                                blob_index,
                                output_block_number,
                                B256::try_from(output_fe_bytes.as_slice())?,
                                B256::try_from(blob_fe_slice)?
                            );
                        }
                    }
                    Ordering::Equal => {
                        // 验证4：尾部数据清零验证（防数据填充攻击）
                        // verify zeroed trail data
                        if blob_index != blobs.len() - 1 {
                            bail!(
                                "Expected trail data to begin at blob {blob_index}/{}",
                                blobs.len()
                            );
                        } else if blobs[blob_index][blob_fe_index..].iter().any(|b| b != &0u8) {
                            bail!("Found non-zero trail data in blob {blob_index}");
                        }
                    }
                    Ordering::Greater => {
                        // (output_block_number <= max_block_number) implies:
                        // (output_offset <= proposal_output_count)
                        unreachable!(
                            "Output offset {output_offset} > output count {proposal_output_count}."
                        );
                    }
                }
            }
        }
    }
    // Return the precondition hash
    Ok(precondition_hash)
}
