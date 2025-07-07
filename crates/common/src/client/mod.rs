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

pub mod core;
pub mod stateless;
pub mod stitching;

/// Logs a given message under different logging mechanisms based on the target operating system.
///
/// # Parameters
/// - `msg`: A string slice representing the message to be logged.
///
/// # Platform-specific Behavior
/// - On a `zkvm` target operating system:
///   - Logs the message using the RISC Zero zkVM environment's logging mechanism (`risc0_zkvm::guest::env::log`).
/// - On other target operating systems:
///   - Logs the message using the `tracing` crate's `info!` macro.
pub fn log(msg: &str) {
    #[cfg(target_os = "zkvm")]
    risc0_zkvm::guest::env::log(msg);
    #[cfg(not(target_os = "zkvm"))]
    tracing::info!("{msg}");
}

#[cfg(test)]
#[cfg_attr(coverage_nightly, coverage(off))]
pub mod tests {
    use std::collections::BTreeMap;
    use crate::oracle::WitnessOracle;
    use crate::precondition::PreconditionValidationData;
    use alloy_primitives::{keccak256, B256};
    use async_trait::async_trait;
    use copy_dir::copy_dir;
    use kona_host::single::{SingleChainHost, SingleChainLocalInputs};
    use kona_host::{DiskKeyValueStore, KeyValueStore, OfflineHostBackend, SplitKeyValueStore};
    use kona_preimage::errors::PreimageOracleResult;
    use kona_preimage::{
        HintWriterClient, PreimageFetcher, PreimageKey, PreimageKeyType, PreimageOracleClient,
    };
    use kona_proof::{BootInfo, FlushableCache};
    use std::fmt::Debug;
    use std::sync::Arc;
    use serde::{Deserialize, Serialize};
    use tempfile::{tempdir, TempDir};
    use tokio::sync::RwLock;
    use tokio::task::block_in_place;

    // ... 已有类型定义 ...
    /////////////////////////添加salt、block witness相关的常量和类型定义///////////////
    pub type BucketId = u32;

    /// Represents the ID of a slot.
    pub type SlotId = u64;

    /// This variable type is used to represent the meta value of a bucket.
    #[derive(Clone, Copy, Debug, PartialEq, Eq, Deserialize, Serialize, PartialOrd, Ord, Hash)]
    pub struct BucketMeta {
        /// nonce value of a bucket.
        pub nonce: u32,
        /// The capacity size of the bucket.
        pub capacity: u64,
        /// The number of slots that are currently load.
        pub load: u64,
    }
    #[derive(
        Clone, Copy, Debug, Default, PartialEq, Eq, Deserialize, Serialize, PartialOrd, Ord, Hash,
    )]
    pub struct SaltKey(pub u64);
    pub const BUCKET_ID_BITS: usize = 24;
    /// Maximum number of bits to represent a slot index in a bucket. 2^40 slots per bucket should be
    /// more than enough.
    pub const BUCKET_SLOT_BITS: usize = 40;

    /// The degree of the polynomial used in the IPA proof.
    pub const POLY_DEGREE: usize = 256;

    impl From<(BucketId, SlotId)> for SaltKey {
        #[inline]
        fn from(value: (BucketId, SlotId)) -> Self {
            Self(((value.0 as u64) << BUCKET_SLOT_BITS) + value.1 as u64)
        }
    }

    impl From<u64> for SaltKey {
        fn from(value: u64) -> Self {
            Self(value)
        }
    }
    pub const MAX_SALT_VALUE_BYTES: usize = 94;

    /// Encodes PlainKey and PlainValue into a single byte array.

    #[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
    pub struct SaltValue {
        /// A byte array large enough to store any type of SaltValue.
        #[serde(with = "serde_bytes")]
        pub data: [u8; MAX_SALT_VALUE_BYTES],
    }
    #[derive(Clone, Debug, PartialEq, Eq, Serialize,Deserialize)]
    pub struct SaltProof {pub proof: Vec<u8>}
    #[derive(Clone, Debug, PartialEq, Eq, Serialize,Deserialize)]
    pub struct BlockWitness {
        /// bucket meta in sub state
        pub metas: BTreeMap<BucketId, BucketMeta>,
        /// kvs in sub state
        pub kvs: BTreeMap<SaltKey, Option<SaltValue>>,
        /// salt proof to prove the metas + kvs
        pub proof: SaltProof,
    }
    /////////////////////////结束添加salt、block witness相关的常量和类型定义///////////////

    #[derive(Debug)]
    pub struct TestOracle<T: KeyValueStore + Send + Sync + Debug> {
        pub kv: Arc<RwLock<T>>,
        pub backend: OfflineHostBackend<T>,
        pub temp_dir: Option<TempDir>,
    }

    impl Default for TestOracle<TestKeyValueStore> {
        fn default() -> Self {
            Self::new(BootInfo {
                l1_head: Default::default(),
                agreed_l2_output_root: Default::default(),
                claimed_l2_output_root: Default::default(),
                claimed_l2_block_number: 0,
                chain_id: 0,
                rollup_config: Default::default(),
            })
        }
    }

    impl WitnessOracle for TestOracle<TestKeyValueStore> {
        fn preimage_count(&self) -> usize {
            1
        }

        fn validate_preimages(&self) -> anyhow::Result<()> {
            Ok(())
        }

        fn insert_preimage(&mut self, _key: PreimageKey, _value: Vec<u8>) {}

        fn finalize_preimages(&mut self, _shard_size: usize, _with_validation_cache: bool) {}
    }

    impl<T: KeyValueStore + Send + Sync + Debug> Clone for TestOracle<T> {
        fn clone(&self) -> Self {
            Self {
                kv: self.kv.clone(),
                backend: OfflineHostBackend::new(self.kv.clone()),
                temp_dir: None,
            }
        }
    }

    pub type TestKeyValueStore = SplitKeyValueStore<SingleChainLocalInputs, DiskKeyValueStore>;

    impl TestOracle<TestKeyValueStore> {
        pub fn new(boot_info: BootInfo) -> Self {
            // 创建内存存储（SingleChainLocalInputs），用于模拟链的本地输入
            let scli = SingleChainLocalInputs::new(SingleChainHost {
                l1_head: boot_info.l1_head,
                agreed_l2_output_root: boot_info.agreed_l2_output_root,
                claimed_l2_output_root: boot_info.claimed_l2_output_root,
                claimed_l2_block_number: boot_info.claimed_l2_block_number,
                l2_chain_id: Some(boot_info.chain_id),
                // rollup_config_path: None, // 不支持自定义链
                ..Default::default()
            });
            // 在临时目录下创建一份 testdata 的磁盘存储副本
            let temp_dir = tempdir().unwrap();
            let dest = temp_dir.path().join("testdata");
            copy_dir(concat!(env!("CARGO_MANIFEST_DIR"), "/testdata"), &dest).unwrap();
            let disk = DiskKeyValueStore::new(dest);
            // 组合内存和磁盘存储为 SplitKeyValueStore，并用 Arc<RwLock> 包裹以支持多线程访问
            let kv = Arc::new(RwLock::new(SplitKeyValueStore::new(scli, disk)));

            // 返回 TestOracle 实例，包含 kv、backend 和临时目录句柄
            Self {
                kv: kv.clone(),
                backend: OfflineHostBackend::new(kv.clone()),
                temp_dir: Some(temp_dir),
            }
        }

        /// 将前置条件数据写入预言机存储，并返回其哈希值
        pub fn add_precondition_data(&self, data: PreconditionValidationData) -> B256 {
            // 在阻塞线程中执行写操作，避免异步上下文阻塞
            block_in_place(move || {
                // 获取底层存储的可写锁
                let mut kv = self.kv.blocking_write();
                // 计算前置条件数据的哈希
                let precondition_data_hash = data.hash();
                // 构造预镜像键（以哈希和类型为参数）
                let preimage_key =
                    PreimageKey::new(precondition_data_hash.0, PreimageKeyType::Sha256);
                // 将数据写入存储
                kv.set(B256::from(preimage_key), data.to_vec()).unwrap();
                // 写入后做一次校验，确保数据一致
                assert_eq!(kv.get(B256::from(preimage_key)).unwrap(), data.to_vec());
                // 返回数据哈希
                precondition_data_hash
            })
        }
        
        /// 插入 BlockWitness 到预言机存储中
        /// 
        /// # 参数
        /// - `block_hash`: 区块哈希，用于生成 witness key
        /// - `witness`: 要存储的 BlockWitness 数据
        /// 
        /// # 返回值
        /// 返回生成的 PreimageKey
        pub fn insert_blockwitness(&mut self, block_hash: [u8; 32], witness: BlockWitness) -> PreimageKey {
            // 序列化 BlockWitness
            let serialized_block_witness = bincode::serialize(&witness).unwrap();
            
            // 使用 block_hash 创建 blockwitness 类型的 PreimageKey
            let witness_key = PreimageKey::new_blockwitness(block_hash);
            
            // 调用现有的 insert_preimage 方法
            self.insert_preimage(witness_key, serialized_block_witness);
            
            witness_key
        }
        
        /// 从预言机存储中读取 BlockWitness
        /// 
        /// # 参数
        /// - `block_hash`: 区块哈希，用于生成 witness key
        /// 
        /// # 返回值
        /// 返回反序列化的 BlockWitness 数据
        pub fn get_blockwitness(&self, block_hash: [u8; 32]) -> anyhow::Result<BlockWitness> {
            // 使用 block_hash 创建 blockwitness 类型的 PreimageKey
            let witness_key = PreimageKey::new_blockwitness(block_hash);
            
            // 使用异步方式读取数据
            let serialized_data = block_in_place(|| {
                tokio::runtime::Runtime::new().unwrap().block_on(async {
                    self.get(witness_key).await
                })
            })?;
            
            // 反序列化并返回
            let witness: BlockWitness = bincode::deserialize(&serialized_data)?;
            Ok(witness)
        }
    }

    impl<T: KeyValueStore + Send + Sync + Debug> FlushableCache for TestOracle<T> {
        fn flush(&self) {
            // noop
        }
    }

    #[async_trait]
    impl<T: KeyValueStore + Send + Sync + Debug> PreimageOracleClient for TestOracle<T> {
        async fn get(&self, key: PreimageKey) -> PreimageOracleResult<Vec<u8>> {
            self.backend.get_preimage(key).await
        }

        async fn get_exact(&self, key: PreimageKey, buf: &mut [u8]) -> PreimageOracleResult<()> {
            let value = self.get(key).await?;
            buf.copy_from_slice(value.as_ref());
            Ok(())
        }
    }

    #[async_trait]
    impl<T: KeyValueStore + Send + Sync + Debug> HintWriterClient for TestOracle<T> {
        async fn write(&self, _hint: &str) -> PreimageOracleResult<()> {
            // just hit the noop
            self.flush();
            Ok(())
        }
    }
    #[test]
    fn test_oracle_cloning() {
        let oracle = TestOracle::new(BootInfo {
            l1_head: Default::default(),
            agreed_l2_output_root: Default::default(),
            claimed_l2_output_root: Default::default(),
            claimed_l2_block_number: 0,
            chain_id: 0,
            rollup_config: Default::default(),
        });
        let cloned = oracle.clone();
        // avoid double dropping
        assert!(cloned.temp_dir.is_none());
    }

    #[test]
    fn test_oracle_basic() {
        const MOCK_DATA_A: &[u8] = b"1234567890";
        const MOCK_DATA_B: &[u8] = b"FACADE";
        let key_a: PreimageKey =
            PreimageKey::new(*keccak256(MOCK_DATA_A), PreimageKeyType::Keccak256);
        let key_b: PreimageKey =
            PreimageKey::new(*keccak256(MOCK_DATA_B), PreimageKeyType::Keccak256);

        // 构造 TestOracle（假设它有 insert/get 方法）
        let mut oracle = TestOracle::default();

        // // 修复 1: 使用 blocking_write 写入数据
        // block_in_place(|| {
        //     let mut kv = oracle.kv.blocking_write();
        //     kv.set(B256::from(key_a), MOCK_DATA_A.to_vec()).unwrap();
        //     kv.set(B256::from(key_b), MOCK_DATA_B.to_vec()).unwrap();
        // });
        // 使用 trait 方法插入数据
        oracle.insert_preimage(key_a, MOCK_DATA_A.to_vec());
        oracle.insert_preimage(key_b, MOCK_DATA_B.to_vec());

        // 修复 2: 使用异步获取数据
        let contents_a = block_in_place(|| {
            tokio::runtime::Runtime::new().unwrap().block_on(async {
                oracle.get(key_a).await.unwrap()
            })
        });

        let contents_b = block_in_place(|| {
            tokio::runtime::Runtime::new().unwrap().block_on(async {
                oracle.get(key_b).await.unwrap()
            })
        });

        assert_eq!(contents_a, MOCK_DATA_A);
        assert_eq!(contents_b, MOCK_DATA_B);
    }

    // ... 已有测试用例 ...
    /*
        #[test]
        fn test_block_witness_io() {
            // 创建测试用的 BlockWitness 数据
            let mut metas = BTreeMap::new();
            metas.insert(1, BucketMeta { nonce: 42, capacity: 1024, load: 512 });

            let mut kvs = BTreeMap::new();
            kvs.insert(SaltKey(123), Some(SaltValue { data: [0xAA; 94] }));

            let witness = BlockWitness {
                metas,
                kvs,
                proof: SaltProof { proof: vec![0x11, 0x22, 0x33] },
            };

            // 序列化测试数据
            let serialized_block_witness = bincode::serialize(&witness).unwrap();

            // 创建测试 Oracle 并存储
            let mut oracle = TestOracle::default();
            let witness_key = PreimageKey::new(
                *keccak256(&serialized_block_witness),
                PreimageKeyType::Blockwitness,
            );
            oracle.insert_preimage(witness_key, serialized_block_witness.clone());

            // 从 Oracle 读取并验证
            let retrieved = block_in_place(|| {
                tokio::runtime::Runtime::new().unwrap().block_on(async {
                    oracle.get(witness_key).await.unwrap()
                })
            });

            // 反序列化并比较
            let deserialized: BlockWitness = bincode::deserialize(&retrieved).unwrap();
            assert_eq!(deserialized.metas.len(), 1);
            assert_eq!(deserialized.kvs.len(), 1);
            assert_eq!(deserialized.proof.proof, vec![0x11, 0x22, 0x33]);
        }

     */
    #[test]
    fn test_block_witness_io() {
        // 创建测试用的 BlockWitness 数据
        let mut metas = BTreeMap::new();
        metas.insert(1, BucketMeta { nonce: 42, capacity: 1024, load: 512 });

        let mut kvs = BTreeMap::new();
        kvs.insert(SaltKey(123), Some(SaltValue { data: [0xAA; 94] }));

        let witness = BlockWitness {
            metas,
            kvs,
            proof: SaltProof { proof: vec![0x11, 0x22, 0x33] },
        };
        let witness_hash:[u8; 32] = [0x01; 32];

        // 序列化测试数据
        let serialized_block_witness = bincode::serialize(&witness).unwrap();

        // 创建测试 Oracle 并存储
        let mut oracle = TestOracle::default();
        // let witness_key = PreimageKey::new(
        //     witness_hash,  // 使用计算出的哈希值
        //     PreimageKeyType::Blockwitness  // 明确指定密钥类型
        // );
        let witness_key = PreimageKey::new_blockwitness(witness_hash);
        oracle.insert_preimage(witness_key, serialized_block_witness.clone());

        // 从 Oracle 读取并验证
        let retrieved = block_in_place(|| {
            tokio::runtime::Runtime::new().unwrap().block_on(async {
                oracle.get(witness_key).await.unwrap()
            })
        });

        // 反序列化并比较
        let deserialized: BlockWitness = bincode::deserialize(&retrieved).unwrap();
        assert_eq!(deserialized.metas.len(), 1);
        assert_eq!(deserialized.kvs.len(), 1);
        assert_eq!(deserialized.proof.proof, vec![0x11, 0x22, 0x33]);
    }


    #[test]
    fn test_block_witness_insert_and_get() {
        // 创建测试用的 BlockWitness 数据
        let mut metas = BTreeMap::new();
        metas.insert(1, BucketMeta { nonce: 42, capacity: 1024, load: 512 });
        metas.insert(2, BucketMeta { nonce: 99, capacity: 2048, load: 1024 });

        let mut kvs = BTreeMap::new();
        kvs.insert(SaltKey(123), Some(SaltValue { data: [0xAA; 94] }));
        kvs.insert(SaltKey(456), Some(SaltValue { data: [0xBB; 94] }));

        let witness = BlockWitness {
            metas,
            kvs,
            proof: SaltProof { proof: vec![0x11, 0x22, 0x33, 0x44] },
        };

        // 使用测试区块哈希
        let block_hash: [u8; 32] = [0x01; 32];

        // 创建测试 Oracle 并插入 BlockWitness
        let mut oracle = TestOracle::default();
        let _witness_key = oracle.insert_blockwitness(block_hash, witness.clone());

        // 使用新方法读取 BlockWitness
        let retrieved_witness = oracle.get_blockwitness(block_hash).unwrap();

        // 验证数据一致性
        assert_eq!(retrieved_witness.metas.len(), 2);
        assert_eq!(retrieved_witness.kvs.len(), 2);
        assert_eq!(retrieved_witness.proof.proof, vec![0x11, 0x22, 0x33, 0x44]);
        
        // 验证具体数据
        assert_eq!(retrieved_witness.metas[&1].nonce, 42);
        assert_eq!(retrieved_witness.metas[&2].capacity, 2048);
        assert_eq!(retrieved_witness.kvs[&SaltKey(123)].as_ref().unwrap().data[0], 0xAA);
        assert_eq!(retrieved_witness.kvs[&SaltKey(456)].as_ref().unwrap().data[0], 0xBB);
    }
}
