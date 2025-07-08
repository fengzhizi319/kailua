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

pub mod vec;

use alloy_primitives::keccak256;
use kona_preimage::errors::{PreimageOracleError, PreimageOracleResult};
use kona_preimage::{CommsClient, PreimageKey, PreimageKeyType};
use kona_proof::FlushableCache;
use risc0_zkvm::sha::{Impl as SHA2, Sha256};
use std::fmt::Debug;

/// Determines if a given `PreimageKeyType` requires validation.
///
/// # Parameters
/// - `key_type`: A reference to a `PreimageKeyType` enum variant that specifies the type of key
///   involved.
///
/// # Returns
/// - `true` if the `key_type` requires validation.
/// - `false` if the `key_type` is either `PreimageKeyType::Local` or `PreimageKeyType::GlobalGeneric`,
///   as these types do not require validation.
pub fn needs_validation(key_type: &PreimageKeyType) -> bool {
    // 如果 key_type 不是 Local 或 GlobalGeneric，则需要验证，返回 true；否则返回 false
    !matches!(
        key_type,
        PreimageKeyType::Local | PreimageKeyType::GlobalGeneric |PreimageKeyType::Blockwitness
    )
}

/// Recomputes the [PreimageKey] for a piece of data to validate its authenticity
///
/// This function ensures that the provided `value` is consistent with the `key`
/// for the specified key type. It computes the hash of the `value` using the
/// appropriate hashing algorithm based on the specified key type, and compares
/// it against the given `key` to verify its validity.
///
/// # Arguments
///
/// * `key` - A reference to a `PreimageKey` that contains the hash and key type
///   against which the `value` should be validated.
/// * `value` - A byte slice representing the data whose hash will be calculated
///   and validated against the given `key`.
///
/// # Returns
///
/// * `Ok(())` - If the `key` is consistent with the hashed `value`.
/// * `Err(PreimageOracleError::InvalidPreimageKey)` - If the computed hash of
///   the `value` does not match the given `key`.
///
/// # Key Types
///
/// The function supports the following key types:
///
/// * `PreimageKeyType::Keccak256` - Computes a Keccak-256 hash of the `value`.
/// * `PreimageKeyType::Sha256` - Computes a SHA-256 hash of the `value`.
/// * `PreimageKeyType::Local` or `PreimageKeyType::GlobalGeneric` - These key
///   types bypass hash validation and do not compute or compare hashes.
///
/// # Panics
///
/// * Panics with `unimplemented!` if called with `PreimageKeyType::Precompile`,
///   as precompile acceleration is not yet supported.
/// * Panics with `unreachable!` if called with `PreimageKeyType::Blob`, since
///   blob key types should not be loaded.
///
pub fn validate_preimage(key: &PreimageKey, value: &[u8]) -> PreimageOracleResult<()> {
    // 获取 key 的类型
    let key_type = key.key_type();
    // 根据 key 类型选择相应的哈希算法，计算 value 的哈希值
    let image = match key_type {
        // Keccak256 类型，使用 keccak256 哈希
        PreimageKeyType::Keccak256 => Some(keccak256(value).0),
        // Sha256 类型，使用 SHA2 哈希
        PreimageKeyType::Sha256 => {
            let x = SHA2::hash_bytes(value);
            Some(x.as_bytes().try_into().unwrap())
        }
        // Precompile 类型暂不支持，直接报错
        PreimageKeyType::Precompile => {
            unimplemented!("Precompile acceleration is not yet supported.");
        }
        // Blob 类型不应被加载，直接 panic
        PreimageKeyType::Blob => {
            unreachable!("Blob key types should not be loaded.");
        }
        // Local 和 GlobalGeneric 类型无需校验哈希，直接跳过
        PreimageKeyType::Local | PreimageKeyType::GlobalGeneric | PreimageKeyType::Blockwitness => None,
    };
    // 如果需要校验哈希，则比较 key 是否与计算出的哈希一致
    if let Some(image) = image {
        if key != &PreimageKey::new(image, key_type) {
            return Err(PreimageOracleError::InvalidPreimageKey);
        }
    }
    // 校验通过
    Ok(())
}

/// A trait representing a Witness Oracle which manages and validates cryptographic preimages.
///
/// The `WitnessOracle` trait provides functionality to interact with and manage preimages.
/// Preimages are key-value pairs where the key is typically an identifier for the data,
/// and the value is the data itself stored as a `Vec<u8>`.
pub trait WitnessOracle: CommsClient + FlushableCache + Send + Sync + Debug + Default {
    /// Returns the count of preimages stored in the oracle.
    fn preimage_count(&self) -> usize;

    /// Ensures that the preimages stored in the oracle meet the required criteria or constraints
    /// defined by each `PreimageKeyType`. If the validation fails, an error is returned.
    fn validate_preimages(&self) -> anyhow::Result<()>;

    /// Inserts a preimage into the oracle.
    fn insert_preimage(&mut self, key: PreimageKey, value: Vec<u8>);

    /// This method finalizes the process of preparing the oracle preimages for a specific shard
    /// size and optional validation cache.
    fn finalize_preimages(&mut self, shard_size: usize, with_validation_cache: bool);
}
#[cfg(test)]
mod test_oracle {
    use alloy_primitives::keccak256;
    use std::collections::HashMap;
    use std::sync::Arc;
    use kona_preimage::errors::{PreimageOracleError, PreimageOracleResult};
    use kona_preimage::{BidirectionalChannel, OracleReader, OracleServer, PreimageFetcher, PreimageKey, PreimageKeyType, PreimageOracleClient, PreimageOracleServer};
    use tokio::sync::Mutex;

    struct TestFetcher {
        preimages: Arc<Mutex<HashMap<PreimageKey, Vec<u8>>>>,
    }

    #[async_trait::async_trait]
    impl PreimageFetcher for TestFetcher {
        async fn get_preimage(&self, key: PreimageKey) -> PreimageOracleResult<Vec<u8>> {
            let read_lock = self.preimages.lock().await;
            read_lock.get(&key).cloned().ok_or(PreimageOracleError::KeyNotFound)
        }
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn test_oracle_reader_get_exact() {
        // 定义两组模拟数据
        const MOCK_DATA_A: &[u8] = b"1234567890";
        const MOCK_DATA_B: &[u8] = b"FACADE";
        // 计算每组数据的 Keccak256 哈希，生成 PreimageKey
        let key_a: PreimageKey =
            PreimageKey::new(*keccak256(MOCK_DATA_A), PreimageKeyType::Keccak256);
        let key_b: PreimageKey =
            PreimageKey::new(*keccak256(MOCK_DATA_B), PreimageKeyType::Keccak256);

        // 构造线程安全的 HashMap 存储预言机数据
        let preimages = {
            let mut preimages = HashMap::default();
            preimages.insert(key_a, MOCK_DATA_A.to_vec());
            preimages.insert(key_b, MOCK_DATA_B.to_vec());
            Arc::new(Mutex::new(preimages))
        };

        // 创建双向通道，client 和 host 分别用于读写
        let preimage_channel = BidirectionalChannel::new().unwrap();

        // 启动 client 任务，模拟客户端通过 OracleReader 获取数据
        let client = tokio::task::spawn(async move {
            let oracle_reader = OracleReader::new(preimage_channel.client);
            // 为每组数据分配缓冲区
            let mut contents_a = [0u8; 10];
            let mut contents_b = [0u8; 6];
            // 通过 key 精确获取数据内容
            oracle_reader.get_exact(key_a, &mut contents_a).await.unwrap();
            oracle_reader.get_exact(key_b, &mut contents_b).await.unwrap();

            (contents_a, contents_b)
        });

        // 启动 host 任务，模拟服务端通过 OracleServer 响应请求
        tokio::task::spawn(async move {
            let oracle_server = OracleServer::new(preimage_channel.host);
            let test_fetcher = TestFetcher { preimages: Arc::clone(&preimages) };

            // 持续处理预言机请求，直到遇到 IO 错误（通道关闭）
            loop {
                match oracle_server.next_preimage_request(&test_fetcher).await {
                    Err(PreimageOracleError::IOError(_)) => break, // 通道关闭时退出循环
                    Err(e) => panic!("Unexpected error: {:?}", e), // 其他错误直接 panic
                    Ok(_) => {}
                }
            }
        });

        // 等待 client 任务完成，获取结果
        let (c,) = tokio::join!(client);
        let (contents_a, contents_b) = c.unwrap();
        // 校验获取到的数据与原始数据一致
        assert_eq!(contents_a, MOCK_DATA_A);
        assert_eq!(contents_b, MOCK_DATA_B);
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 1)]
    // 异步测试函数，验证 OracleReader 和 OracleServer 的端到端数据传递
    async fn test_oracle_client_and_host() {
        // 定义两组模拟数据
        const MOCK_DATA_A: &[u8] = b"1234567890";
        const MOCK_DATA_B: &[u8] = b"FACADE";
        // 计算每组数据的 Keccak256 哈希，生成 PreimageKey
        let key_a: PreimageKey =
            PreimageKey::new(*keccak256(MOCK_DATA_A), PreimageKeyType::Keccak256);
        let key_b: PreimageKey =
            PreimageKey::new(*keccak256(MOCK_DATA_B), PreimageKeyType::Keccak256);

        // 构造预言机数据存储（线程安全的 HashMap）
        let preimages = {
            let mut preimages = HashMap::default();
            preimages.insert(key_a, MOCK_DATA_A.to_vec());
            preimages.insert(key_b, MOCK_DATA_B.to_vec());
            Arc::new(Mutex::new(preimages))
        };

        // 创建双向通道，client 和 host 分别用于读写
        let preimage_channel = BidirectionalChannel::new().unwrap();

        // 启动 client 任务，模拟客户端通过 OracleReader 获取数据
        let client = tokio::task::spawn(async move {
            let oracle_reader = OracleReader::new(preimage_channel.client);
            // 通过 key 获取数据内容
            let contents_a = oracle_reader.get(key_a).await.unwrap();
            let contents_b = oracle_reader.get(key_b).await.unwrap();

            (contents_a, contents_b)
        });

        // 启动 host 任务，模拟服务端通过 OracleServer 响应请求
        tokio::task::spawn(async move {
            let oracle_server = OracleServer::new(preimage_channel.host);
            let test_fetcher = TestFetcher { preimages: Arc::clone(&preimages) };

            // 持续处理预言机请求，直到遇到 IO 错误（通道关闭）
            loop {
                match oracle_server.next_preimage_request(&test_fetcher).await {
                    Err(PreimageOracleError::IOError(_)) => break, // 通道关闭时退出循环
                    Err(e) => panic!("Unexpected error: {:?}", e), // 其他错误直接 panic
                    Ok(_) => {}
                }
            }
        });

        // 等待 client 任务完成，获取结果
        let (c,) = tokio::join!(client);
        let (contents_a, contents_b) = c.unwrap();
        // 校验获取到的数据与原始数据一致
        assert_eq!(contents_a, MOCK_DATA_A);
        assert_eq!(contents_b, MOCK_DATA_B);
    }
}

#[cfg(test)]
mod test_hint {
    use super::*;
    use kona_preimage::{BidirectionalChannel, HintReader, HintReaderServer, HintRouter, HintWriter, HintWriterClient, };
    use std::sync::Arc;
    use async_trait::async_trait;
    use tokio::sync::Mutex;

    struct TestRouter {
        incoming_hints: Arc<Mutex<Vec<String>>>,
    }

    #[async_trait]
    impl HintRouter for TestRouter {
        async fn route_hint(&self, hint: String) -> PreimageOracleResult<()> {
            self.incoming_hints.lock().await.push(hint);
            Ok(())
        }
    }

    struct TestFailRouter;

    #[async_trait]
    impl HintRouter for TestFailRouter {
        async fn route_hint(&self, _hint: String) -> PreimageOracleResult<()> {
            Err(PreimageOracleError::KeyNotFound)
        }
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn test_unblock_on_bad_utf8() {
        extern crate alloc;
        let mock_data = [0xf0, 0x90, 0x28, 0xbc];

        let hint_channel = BidirectionalChannel::new().unwrap();

        let client = tokio::task::spawn(async move {
            let hint_writer = HintWriter::new(hint_channel.client);

            #[allow(invalid_from_utf8_unchecked)]
            hint_writer.write(unsafe { std::str::from_utf8_unchecked(&mock_data) }).await
        });
        let host = tokio::task::spawn(async move {
            let router = TestRouter { incoming_hints: Default::default() };

            let hint_reader = HintReader::new(hint_channel.host);
            hint_reader.next_hint(&router).await
        });

        let (c, h) = tokio::join!(client, host);
        c.unwrap().unwrap();
        assert!(h.unwrap().is_err_and(|e| {
            let PreimageOracleError::Other(e) = e else {
                return false;
            };
            e.contains("Failed to decode hint payload")
        }));
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn test_unblock_on_fetch_failure() {
        const MOCK_DATA: &str = "test-hint 0xfacade";

        let hint_channel = BidirectionalChannel::new().unwrap();

        let client = tokio::task::spawn(async move {
            let hint_writer = HintWriter::new(hint_channel.client);

            hint_writer.write(MOCK_DATA).await
        });
        let host = tokio::task::spawn(async move {
            let hint_reader = HintReader::new(hint_channel.host);
            hint_reader.next_hint(&TestFailRouter).await
        });

        let (c, h) = tokio::join!(client, host);
        c.unwrap().unwrap();
        assert!(h.unwrap().is_err_and(|e| matches!(e, PreimageOracleError::KeyNotFound)));
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn test_hint_client_and_host() {
        const MOCK_DATA: &str = "test-hint 0xfacade";

        let incoming_hints = Arc::new(Mutex::new(Vec::new()));
        let hint_channel = BidirectionalChannel::new().unwrap();

        let client = tokio::task::spawn(async move {
            let hint_writer = HintWriter::new(hint_channel.client);

            hint_writer.write(MOCK_DATA).await
        });
        let host = tokio::task::spawn({
            let incoming_hints_ref = Arc::clone(&incoming_hints);
            async move {
                let router = TestRouter { incoming_hints: incoming_hints_ref };

                let hint_reader = HintReader::new(hint_channel.host);
                hint_reader.next_hint(&router).await.unwrap();
            }
        });

        let _ = tokio::join!(client, host);
        let mut hints = incoming_hints.lock().await;

        assert_eq!(hints.len(), 1);
        let h = hints.remove(0);
        assert_eq!(h, MOCK_DATA);
    }
}

#[cfg(test)]
#[cfg_attr(coverage_nightly, coverage(off))]
mod test_validate {
    use super::*;

    #[test]
    fn test_validate_preimage() {
        // Test Keccak256
        let key = PreimageKey::new(keccak256(b"test").0, PreimageKeyType::Keccak256);
        let value = b"test";
        assert!(validate_preimage(&key, value).is_ok());

        // Test invalid Keccak256
        let invalid_key = PreimageKey::new(keccak256(b"wrong").0, PreimageKeyType::Keccak256);
        assert!(validate_preimage(&invalid_key, value).is_err());

        // Test Sha256
        let sha_value = b"test";
        let sha_key = PreimageKey::new(
            SHA2::hash_bytes(sha_value).as_bytes().try_into().unwrap(),
            PreimageKeyType::Sha256,
        );
        assert!(validate_preimage(&sha_key, sha_value).is_ok());

        // Test invalid Sha256
        let invalid_sha_key = PreimageKey::new(
            SHA2::hash_bytes(b"wrong").as_bytes().try_into().unwrap(),
            PreimageKeyType::Sha256,
        );
        assert!(validate_preimage(&invalid_sha_key, sha_value).is_err());

        // Test Local (no validation)
        let local_key = PreimageKey::new([0u8; 32], PreimageKeyType::Local);
        assert!(validate_preimage(&local_key, b"any value").is_ok());

        // Test GlobalGeneric (no validation)
        let global_key = PreimageKey::new([0u8; 32], PreimageKeyType::GlobalGeneric);
        assert!(validate_preimage(&global_key, b"any value").is_ok());

        // Test Precompile (should panic)
        let precompile_key = PreimageKey::new([0u8; 32], PreimageKeyType::Precompile);
        let result = std::panic::catch_unwind(|| validate_preimage(&precompile_key, b"test"));
        assert!(result.is_err());

        // Test Blob (should panic)
        let blob_key = PreimageKey::new([0u8; 32], PreimageKeyType::Blob);
        let result = std::panic::catch_unwind(|| validate_preimage(&blob_key, b"test"));
        assert!(result.is_err());

        let _blockwitness_key = PreimageKey::new([0u8; 32], PreimageKeyType::Blockwitness);
        let result = std::panic::catch_unwind(|| validate_preimage(&blob_key, b"test"));
        assert!(result.is_err());
    }

    #[test]
    fn test_needs_validation() {
        // Test all PreimageKeyType variants
        assert!(needs_validation(&PreimageKeyType::Keccak256));
        assert!(needs_validation(&PreimageKeyType::Sha256));
        assert!(needs_validation(&PreimageKeyType::Precompile));
        assert!(needs_validation(&PreimageKeyType::Blob));
        assert!(!needs_validation(&PreimageKeyType::Local));
        assert!(!needs_validation(&PreimageKeyType::GlobalGeneric));
        assert!(!needs_validation(&PreimageKeyType::Blockwitness));
    }
}
#[cfg(test)]
mod test_store_ordered_trie {
    use std::collections::HashMap;
    use alloy_primitives::B256;
    use async_trait::async_trait;
    use kona_host::KeyValueStore;
    use tokio::sync::RwLock;

    // 简单的内存型 KeyValueStore 实现
    struct MemStore {
        map: HashMap<Vec<u8>, Vec<u8>>,
    }
    use alloy_consensus::EMPTY_ROOT_HASH;
    use alloy_primitives::keccak256;
    use alloy_rlp::EMPTY_STRING_CODE;
    use anyhow::Result;
    use kona_preimage::{PreimageKey, PreimageKeyType};


    /// 构建有序的 Merkle Patricia Trie，并将所有中间节点的编码内容存入 [KeyValueStore]。
    pub(crate) async fn store_ordered_trie<KV: KeyValueStore + ?Sized, T: AsRef<[u8]>>(
        kv: &RwLock<KV>,
        values: &[T],
    ) -> Result<()> {
        // 获取对 KeyValueStore 的可写锁，准备写入数据
        let mut kv_write_lock = kv.write().await;

        // 如果节点列表为空，直接存储空根哈希的预镜像并提前返回
        // 这样可以保证空 trie 也有对应的预镜像存储
        if values.is_empty() {
            // 构造空 trie 的根哈希对应的预镜像键
            let empty_key = PreimageKey::new(*EMPTY_ROOT_HASH, PreimageKeyType::Keccak256);
            // 空 trie 的值用 EMPTY_STRING_CODE 表示
            return kv_write_lock.set(empty_key.into(), [EMPTY_STRING_CODE].into());
        }

        // 构建有序的 Merkle Patricia Trie，并用 encoder 将每个节点内容写入 buf
        let mut hb = kona_mpt::ordered_trie_with_encoder(values, |node, buf| {
            buf.put_slice(node.as_ref());
        });
        let intermediates1 = hb.clone().take_proof_nodes().into_inner();
        println!("intermediates1: {:?}", intermediates1.len());

        // 计算 trie 的根节点（触发节点编码和哈希计算）
        hb.root();

        // 获取所有中间节点（包括叶子和中间节点）的原始内容
        let intermediates = hb.take_proof_nodes().into_inner();
        println!("intermediates len: {:?}", intermediates.len());
        let mut i = 0;

        // 遍历所有中间节点，将每个节点的哈希作为 key，节点内容作为 value 存入 kv
        for (_, value) in intermediates.into_iter() {
            i=i+1;
            // 计算节点内容的 keccak256 哈希
            let value_hash = keccak256(value.as_ref());
            // 构造预镜像键，类型为 Keccak256
            let key = PreimageKey::new(*value_hash, PreimageKeyType::Keccak256);

            // 存储到 kv，key 为节点哈希，value 为节点原始内容
            kv_write_lock.set(key.into(), value.into())?;
        }
        println!("i: {:?}", i);

        // 所有节点存储完成，返回 Ok
        Ok(())
    }
    #[async_trait]
    impl KeyValueStore for MemStore {
        fn get(&self, key: B256) -> Option<Vec<u8>> {
            todo!()
        }
        fn set(&mut self, key: B256, value: Vec<u8>) -> anyhow::Result<()> {
            self.map.insert(key.to_vec(), value);
            Ok(())
        }
    }

    #[tokio::test]
    async fn test_store_ordered_trie_basic() {
        let store = RwLock::new(MemStore { map: HashMap::new() });
        let values = vec![b"foo".as_ref(), b"bar".as_ref()];
        for v in &values {
            println!("{:02x?}", v);
            println!("{:?}", std::str::from_utf8(v).unwrap());
        }

        let result = store_ordered_trie(&store, &values).await;
        assert!(result.is_ok());

        // 检查 kv 是否写入了内容
        let store_read = store.read().await;
        for (k, v) in &store_read.map {
            println!("key: {:02x?}, value: {:02x?}", k, v);
            // println!("{:?}", std::str::from_utf8(v).unwrap());

        }
        assert!(!store_read.map.is_empty());
    }

    #[tokio::test]
    async fn test_store_ordered_trie_empty() {
        let store = RwLock::new(MemStore { map: HashMap::new() });
        let values: Vec<&[u8]> = vec![];
        let result = store_ordered_trie(&store, &values).await;
        assert!(result.is_ok());

        // 空 trie 也应写入一个节点
        let store_read = store.read().await;
        assert_eq!(store_read.map.len(), 1);
    }
}
