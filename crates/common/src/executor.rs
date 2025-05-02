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

use crate::client::log;
use crate::config::safe_default;
use crate::rkyv::optimism::OpPayloadAttributesRkyv;
use crate::rkyv::primitives::B256Def;
use crate::rkyv::BlockBuildingOutcomeRkyv;
use alloy_consensus::Header;
use alloy_eips::eip4895::Withdrawal;
use alloy_eips::Encodable2718;
use alloy_primitives::{Bytes, Sealed, B256, B64};
use anyhow::Context;
use async_trait::async_trait;
use kona_driver::{Executor, PipelineCursor, TipCursor};
use kona_executor::BlockBuildingOutcome;
use kona_genesis::RollupConfig;
use kona_mpt::ordered_trie_with_encoder;
use kona_preimage::CommsClient;
use kona_proof::errors::OracleProviderError;
use kona_proof::l2::OracleL2ChainProvider;
use kona_proof::FlushableCache;
use kona_protocol::{BatchValidationProvider, BlockInfo};
use op_alloy_consensus::OpReceiptEnvelope;
use op_alloy_rpc_types_engine::OpPayloadAttributes;
use risc0_zkvm::sha::{Impl as SHA2, Sha256};
use spin::RwLock;
use std::fmt::Debug;
use std::sync::{Arc, Mutex};

#[derive(Clone, Debug, rkyv::Archive, rkyv::Serialize, rkyv::Deserialize)]
pub struct Execution {
    /// Output root prior to execution
        /// 执行前的共识状态根（L2链的初始状态）
    /// - 类型: 256位哈希值 (B256)
    /// - 来源: 前序区块执行后的状态树根
    /// - 用途: 用于验证状态转换的正确性
    #[rkyv(with = B256Def)]
    pub agreed_output: B256,
    /// Derived attributes to be executed
    /// 待执行的交易属性集合
    /// - 包含: 时间戳、手续费接收地址、交易列表等
    /// - 来源: 从L1链的Batch数据解析得到
    /// - 序列化: 使用OpPayloadAttributesRkyv自定义格式
    #[rkyv(with = OpPayloadAttributesRkyv)]
    pub attributes: OpPayloadAttributes,
    /// Output block from execution
    #[rkyv(with = BlockBuildingOutcomeRkyv)]
    pub artifacts: BlockBuildingOutcome,
    /// Output root after execution
        /// 执行后的主张状态根（L2链的最终状态）
    /// - 计算: 基于artifacts中的执行结果生成
    /// - 用途: 作为下一个区块的agreed_output输入
    /// - 验证: 需与零知识证明的输出结果一致
    #[rkyv(with = B256Def)]
    pub claimed_output: B256,
}

#[derive(Debug)]
pub struct CachedExecutor<E: Executor + Send + Sync + Debug> {
    pub cache: Vec<Arc<Execution>>,
    pub executor: E,
    pub collection_target: Option<Arc<Mutex<Vec<Execution>>>>,
}

#[async_trait]
impl<E: Executor + Send + Sync + Debug> Executor for CachedExecutor<E> {
    type Error = <E as Executor>::Error;

    async fn wait_until_ready(&mut self) {
        self.executor.wait_until_ready().await;
    }

    fn update_safe_head(&mut self, header: Sealed<Header>) {
        self.executor.update_safe_head(header);
    }

///执行交易，并收集交易结果
    async fn execute_payload(
        &mut self,
        attributes: OpPayloadAttributes,
    ) -> Result<BlockBuildingOutcome, Self::Error> {
        let agreed_output = self.compute_output_root()?;
        if self
            .cache
            .last()
            .map(|e| Ok(agreed_output == e.agreed_output && attributes == e.attributes))
            .unwrap_or(Ok(false))?
        {
            let artifacts = self.cache.pop().unwrap().artifacts.clone();
            log(&format!("CACHE {}", artifacts.header.number));
            self.update_safe_head(artifacts.header.clone());
            return Ok(artifacts);
        }
        if let Some(collection_target) = &self.collection_target {
            let artifacts = self.executor.execute_payload(attributes.clone()).await?;
            let mut collection_target = collection_target.lock().unwrap();
	    // 当执行成功后会自动收集到 collection_target
            collection_target.push(Execution {
                agreed_output,
                attributes,
                artifacts: artifacts.clone(),
                claimed_output: Default::default(),
            });
            return Ok(artifacts);
        }
        self.executor.execute_payload(attributes).await
    }

    fn compute_output_root(&mut self) -> Result<B256, Self::Error> {
        self.executor.compute_output_root()
    }
}

pub async fn new_execution_cursor<O>(
    rollup_config: &RollupConfig,
    safe_header: Sealed<Header>,
    l2_chain_provider: &mut OracleL2ChainProvider<O>,
) -> Result<Arc<RwLock<PipelineCursor>>, OracleProviderError>
where
    O: CommsClient + FlushableCache + FlushableCache + Send + Sync + Debug,
{
    let safe_head_info = l2_chain_provider
        .l2_block_info_by_number(safe_header.number)
        .await?;

    // Walk back the starting L1 block by `channel_timeout` to ensure that the full channel is
    // captured.
    let channel_timeout = rollup_config.channel_timeout(safe_head_info.block_info.timestamp);

    // Construct the cursor.
    let mut cursor = PipelineCursor::new(channel_timeout, BlockInfo::default());
    let tip = TipCursor::new(safe_head_info, safe_header, B256::ZERO);
    cursor.advance(BlockInfo::default(), tip);

    // Wrap the cursor in a shared read-write lock
    Ok(Arc::new(RwLock::new(cursor)))
}

pub fn attributes_hash(attributes: &OpPayloadAttributes) -> anyhow::Result<B256> {
    let hashed_bytes = [
        attributes
            .payload_attributes
            .timestamp
            .to_be_bytes()
            .as_slice(),
        attributes.payload_attributes.prev_randao.as_slice(),
        attributes
            .payload_attributes
            .suggested_fee_recipient
            .as_slice(),
        safe_default(
            attributes
                .payload_attributes
                .withdrawals
                .as_ref()
                .map(|wds| withdrawals_hash(wds.as_slice())),
            B256::ZERO,
        )
        .context("safe_default withdrawals")?
        .as_slice(),
        safe_default(
            attributes.payload_attributes.parent_beacon_block_root,
            B256::ZERO,
        )
        .context("safe_default parent_beacon_block_root")?
        .as_slice(),
        safe_default(
            attributes.transactions.as_ref().map(transactions_hash),
            B256::ZERO,
        )
        .context("safe_default transactions_hash")?
        .as_slice(),
        &[safe_default(attributes.no_tx_pool, false).context("safe_default no_tx_pool")? as u8],
        safe_default(attributes.gas_limit, u64::MAX)
            .context("safe_default gas_limit")?
            .to_be_bytes()
            .as_slice(),
        safe_default(attributes.eip_1559_params, B64::new([0xff; 8]))
            .context("safe_default eip_1559_params")?
            .as_slice(),
    ]
    .concat();
    let digest: [u8; 32] = SHA2::hash_bytes(hashed_bytes.as_slice())
        .as_bytes()
        .try_into()?;
    Ok(digest.into())
}

pub fn withdrawals_hash(withdrawals: &[Withdrawal]) -> B256 {
    let hashed_bytes = withdrawals
        .iter()
        .map(|w| {
            [
                w.index.to_be_bytes().as_slice(),
                w.validator_index.to_be_bytes().as_slice(),
                w.address.as_slice(),
                w.amount.to_be_bytes().as_slice(),
            ]
            .concat()
        })
        .collect::<Vec<_>>()
        .concat();
    let digest: [u8; 32] = SHA2::hash_bytes(hashed_bytes.as_slice())
        .as_bytes()
        .try_into()
        .unwrap();
    digest.into()
}

pub fn transactions_hash(transactions: &Vec<Bytes>) -> B256 {
    let hashed_bytes = alloy_rlp::encode(transactions);
    let digest: [u8; 32] = SHA2::hash_bytes(hashed_bytes.as_slice())
        .as_bytes()
        .try_into()
        .unwrap();
    digest.into()
}

pub fn exec_precondition_hash(executions: &[Arc<Execution>]) -> B256 {
    // 步骤1：拼接所有执行记录的密码学要素
    let hashed_bytes = executions
        .iter()
        .map(|e| {
            // 每个执行记录包含四个验证要素：
            [
                e.agreed_output.0,  // 执行前状态根（初始状态承诺）
                attributes_hash(&e.attributes) // 执行参数哈希（交易/手续费等）
                    .expect("Unhashable attributes.") // 断言哈希计算成功
                    .0,
                e.artifacts.header.hash().0, // 区块头哈希（执行过程完整性）
                e.claimed_output.0, // 执行后状态根（最终状态承诺）
            ]
            .concat() // 将四个要素拼接为连续字节流
        })
        .collect::<Vec<_>>() // 收集所有执行记录的字节流
        .concat(); // 将所有记录拼接为单个字节数组

    // 步骤2：计算SHA-256哈希（使用RISC Zero的zkVM兼容实现）
    let digest: [u8; 32] = SHA2::hash_bytes(hashed_bytes.as_slice())
        .as_bytes()
        .try_into()
        .unwrap(); // 哈希结果转换为固定长度数组

    digest.into() // 转换为B256类型返回
}

/// Computes the receipts root from the given set of receipts.
///
/// ## Takes
/// - `receipts`: The receipts to compute the root for.
/// - `config`: The rollup config to use for the computation.
/// - `timestamp`: The timestamp to use for the computation.
///
/// ## Returns
/// The computed receipts root.
pub fn compute_receipts_root(
    receipts: &[OpReceiptEnvelope],
    config: &RollupConfig,
    timestamp: u64,
) -> B256 {
    // There is a minor bug in op-geth and op-erigon where in the Regolith hardfork,
    // the receipt root calculation does not inclide the deposit nonce in the
    // receipt encoding. In the Regolith hardfork, we must strip the deposit nonce
    // from the receipt encoding to match the receipt root calculation.
    if config.is_regolith_active(timestamp) && !config.is_canyon_active(timestamp) {
        let receipts = receipts
            .iter()
            .cloned()
            .map(|receipt| match receipt {
                OpReceiptEnvelope::Deposit(mut deposit_receipt) => {
                    deposit_receipt.receipt.deposit_nonce = None;
                    OpReceiptEnvelope::Deposit(deposit_receipt)
                }
                _ => receipt,
            })
            .collect::<Vec<_>>();

        ordered_trie_with_encoder(receipts.as_ref(), |receipt, mut buf| {
            receipt.encode_2718(&mut buf)
        })
        .root()
    } else {
        ordered_trie_with_encoder(receipts, |receipt, mut buf| receipt.encode_2718(&mut buf)).root()
    }
}
