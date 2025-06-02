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
    use crate::oracle::WitnessOracle;
    use crate::precondition::PreconditionValidationData;
    use alloy_primitives::B256;
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
    use tempfile::{tempdir, TempDir};
    use tokio::sync::RwLock;
    use tokio::task::block_in_place;

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
}
