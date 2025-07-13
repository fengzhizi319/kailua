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

use crate::oracle::keccak256;
use crate::client::log;
use crate::oracle::WitnessOracle;
use crate::oracle::{needs_validation, validate_preimage};
use crate::precondition::PreconditionValidationData;
use crate::rkyv::vec::PreimageVecStoreRkyv;
use alloy_primitives::map::HashMap;
use anyhow::{anyhow, bail};
use async_trait::async_trait;
use kona_preimage::errors::PreimageOracleResult;
use kona_preimage::{HintWriterClient, PreimageKey, PreimageKeyType, PreimageOracleClient};
use kona_proof::{BootInfo, FlushableCache};
use lazy_static::lazy_static;
use std::collections::VecDeque;
use std::ops::{Deref, DerefMut};
use std::path::PathBuf;
use std::sync::{Arc, Mutex};
use alloy_consensus::Header;
use alloy_primitives::{hex, B256};
use alloy_rlp::{Decodable, Encodable};
use alloy_trie::EMPTY_ROOT_HASH;
use kona_proof::boot::{L1_HEAD_KEY, L2_OUTPUT_ROOT_KEY, L2_CLAIM_KEY, L2_CLAIM_BLOCK_NUMBER_KEY, L2_CHAIN_ID_KEY, L2_ROLLUP_CONFIG_KEY};
use kona_proof::errors::OracleProviderError;
use serde::{Deserialize, Serialize};
use serde::de::DeserializeOwned;
use tracing::info;
use crate::client;

/// A type alias representing an indexed preimage.
///
/// This type is a tuple consisting of the following elements:
///
/// 1. `PreimageKey`:
///    - The key associated with the preimage, serving as its identifier or unique reference.
///
/// 2. `Vec<u8>`:
///    - The actual bytes representing the preimage content.
///
/// 3. `Option<(usize, usize)>`:
///    - An optional tuple specifying metadata about a duplicate of the preimage:
///        - The first `usize` represents the shard index.
///        - The second `usize` represents the index within the shard.
///    - If `None`, the position metadata is not available.
pub type IndexedPreimage = (PreimageKey, Vec<u8>, Option<(usize, usize)>);
pub type PreimageVecEntry = Vec<IndexedPreimage>;
pub type PreimageVecStore = Arc<Mutex<Vec<PreimageVecEntry>>>;

/// A structure representing a vector-based oracle for storing preimages.
///
/// This struct is equipped with the necessary implementations to support cloning, debugging,
/// and (de)serialization using the `rkyv` crate. It defines a storage for preimages
/// with additional serialization handling.
#[derive(Clone, Debug, Default, rkyv::Serialize, rkyv::Archive, rkyv::Deserialize)]
pub struct VecOracle {
    /// A `PreimageVecStore` instance that contains the stored preimages.
    #[rkyv(with = PreimageVecStoreRkyv)]
    pub preimages: PreimageVecStore,
}

impl VecOracle {
    /// Creates a deep clone of the current instance.
    ///
    /// This method performs a deep clone of the object, ensuring that all
    /// nested data structures or components shared via `Arc` or `Mutex` are
    /// also uniquely cloned. This is particularly relevant for structures
    /// where a simple `clone` would result in shared references instead of
    /// creating truly independent copies.
    ///
    /// # Returns
    ///
    /// A new instance of the same type, containing independent clones of all
    /// fields, including those wrapped in `Arc` and `Mutex`.
    ///
    /// # Notes
    ///
    /// - For this method to work correctly, the types within the struct must
    ///   also support cloning (e.g., contained elements must implement `Clone`).
    ///
    /// - This method is useful in concurrent programming scenarios where `Arc`
    ///   and `Mutex` are frequently used to provide shared access while ensuring
    ///   thread safety. A deep clone ensures that the new instance does not
    ///   share any mutable state with the original.
    pub fn deep_clone(&self) -> Self {
        let mut cloned_with_arc = self.clone();
        cloned_with_arc.preimages = Arc::new(Mutex::new(self.preimages.lock().unwrap().clone()));
        cloned_with_arc
    }

    /// Validates the collection of preimage vector entries.
    ///
    /// # Arguments
    ///
    /// * `preimages` - A slice of `PreimageVecEntry`, where each entry consists of a vector
    ///   containing tuples of key, value, and potentially a reference (`prev`) to a prior key-value pair.
    ///
    /// # Returns
    ///
    /// * `Result<()>` - Returns `Ok(())` if all validations pass, or an error wrapped in `anyhow::Error` if any validation fails.
    ///
    /// # Behavior
    ///
    /// 1. Iterates through each `PreimageVecEntry` in the `preimages` slice.
    /// 2. For each entry, iterates through its pairs, extracting the key, value, and optionally a `prev` reference.
    /// 3. Skips validation for keys where `needs_validation` indicates validation is not required.
    /// 4. If a `prev` reference is present:
    ///     - Ensures that the reference does not point to a future entry or an invalid sequence in the current entry.
    ///     - Validates referenced key-value matches the cached preimage.
    /// 5. If no `prev` reference exists, validates the current key and value using `validate_preimage`.
    ///
    /// # Errors
    ///
    /// This function returns an error in the following cases:
    /// - If a `prev` reference points to a future entry or preimage, violating causal consistency.
    /// - If the key or value of the current pair does not match the cached preimage at the referenced location.
    /// - If `validate_preimage` fails for any key-value pair requiring validation.
    ///
    /// # Notes
    ///
    /// - The function assumes `key` and `value` in a `PreimageVecEntry` are consistent types.
    /// - It is the caller's responsibility to populate `prev` references accurately to ensure valid
    ///   preimage relationships.
    ///
    /// # Dependencies
    ///
    /// Requires the following external functions:
    /// - `needs_validation(key_type: &KeyType) -> bool`: Determines whether a key type requires validation.
    /// - `validate_preimage(key: &Key, value: &Value) -> Result<()>`: Performs validation on a single key-value pair.
    ///
    /// # See Also
    ///
    /// This function is part of a broader mechanism for ensuring data integrity in cryptographic or
    /// state-based systems relying on preimages for verification.
    pub fn validate(preimages: &[PreimageVecEntry]) -> anyhow::Result<()> {
        // 遍历每个分片（entry），e 表示分片索引
        for (e, entry) in preimages.iter().enumerate() {
            // 遍历分片内的每个预映像，p 表示在分片内的索引
            for (p, (key, value, prev)) in entry.iter().enumerate() {
                // 如果该 key 类型不需要验证，则跳过
                if !needs_validation(&key.key_type()) {
                    continue;
                // 如果有 prev 指针，说明该预映像引用了之前的某个预映像
                } else if let Some((i, j)) = prev {
                    // 检查 prev 指针不能指向未来的分片
                    if e < *i {
                        bail!("Attempted to validate preimage against future vec entry.");
                    // 检查 prev 指针不能指向当前或未来的预映像
                    } else if e == *i && p <= *j {
                        bail!(
                            "Attempted to validate preimage against future preimage in vec entry."
                        );
                    // 检查 prev 指向的 key 必须与当前 key 相同
                    } else if key != &preimages[*i][*j].0 {
                        bail!("Cached preimage key comparison failed");
                    // 检查 prev 指向的 value 必须与当前 value 相同
                    } else if value != &preimages[*i][*j].1 {
                        bail!("Cached preimage value comparison failed");
                    } else {
                        // 如果都通过，继续下一个
                        continue;
                    }
                }
                // 对没有 prev 指针的预映像，直接做常规验证
                validate_preimage(key, value)?;
            }
        }
        Ok(())
    }

    /// Inserts precondition validation data into the oracle.
    ///
    /// This method stores the given `key` and `value` as a precondition validation data entry.
    /// The `preimages` collection is thread-safe through the use of a mutex.
    ///
    /// # Parameters
    ///
    /// - `key`: A `PreimageKey` representing the identifier for the precondition validation data.
    /// - `value`: A `Vec<u8>` containing the data associated with the precondition validation.
    ///
    /// # Behavior
    ///
    /// - The precondition validation data (a tuple of `key`, `value`, and `None`) is appended to the last
    ///   vector inside the `preimages` collection.
    /// - If the `preimages` collection is empty, a new inner vector is initialized before
    ///   the insertion takes place.
    ///
    /// # Panics
    ///
    /// This function will panic if:
    /// - The `validate_preimage` function determines that the provided `key` and `value`
    ///   are invalid.
    /// - The mutex guarding the `preimages` collection is poisoned (i.e., another thread
    ///   panicked while holding the lock).
    ///
    /// Notes:
    /// - Ensure that the provided `key` and `value` adhere to the expected format, as
    ///   enforced by `validate_preimage`.
    /// - This method is not thread-safe on its own, so ensure that concurrent access
    ///   to the containing structure is properly synchronized if needed.
    pub fn insert_precondition_validation_data(&mut self, key: PreimageKey, value: Vec<u8>) {
        validate_preimage(&key, &value).expect("Attempted to save invalid preimage");
        let mut preimages = self.preimages.lock().unwrap();
        if preimages.is_empty() {
            preimages.push(Vec::new());
        }
        preimages.last_mut().unwrap().push((key, value, None));
    }
}

impl WitnessOracle for VecOracle {
    fn preimage_count(&self) -> usize {
        self.preimages.lock().unwrap().iter().map(Vec::len).sum()
    }

    fn validate_preimages(&self) -> anyhow::Result<()> {
        let preimages = self.preimages.lock().unwrap();
        Self::validate(preimages.deref())
    }

    /// Inserts a preimage into the preimages collection.
    ///
    /// This method validates the given `key` and `value` before inserting them into the
    /// collection. If the validation fails, the function will panic with an error message
    /// "Attempted to save invalid preimage". The `preimages` collection is thread-safe
    /// through the use of a mutex.
    ///
    /// # Parameters
    ///
    /// - `key`: A `PreimageKey` representing the identifier for the preimage.
    /// - `value`: A `Vec<u8>` containing the data associated with the preimage.
    ///
    /// # Behavior
    ///
    /// - The preimage (a tuple of `key`, `value`, and `None`) is appended to the last
    ///   vector inside the `preimages` collection.
    /// - If the `preimages` collection is empty, a new inner vector is initialized before
    ///   the insertion takes place.
    ///
    /// # Panics
    ///
    /// This function will panic if:
    /// - The `validate_preimage` function determines that the provided `key` and `value`
    ///   are invalid.
    /// - The mutex guarding the `preimages` collection is poisoned (i.e., another thread
    ///   panicked while holding the lock).
    ///
    /// Notes:
    /// - Ensure that the provided `key` and `value` adhere to the expected format, as
    ///   enforced by `validate_preimage`.
    /// - This method is not thread-safe on its own, so ensure that concurrent access
    ///   to the containing structure is properly synchronized if needed.
    fn insert_preimage(&mut self, key: PreimageKey, value: Vec<u8>) {
        validate_preimage(&key, &value).expect("Attempted to save invalid preimage");
        let mut preimages = self.preimages.lock().unwrap();
        if preimages.is_empty() {
            preimages.push(Vec::new());
        }
        preimages.last_mut().unwrap().push((key, value, None));
    }

    /// Finalizes pre-images by validating them, sorting, sharding, and optionally adding validation pointers.
    ///
    /// # Arguments
    /// - `shard_size` - Specifies the maximum size limit for each shard of pre-images.
    /// - `with_validation_ptrs` - A boolean flag to determine whether validation pointers should be added.
    ///
    /// # Process
    /// 1. Validates all existing pre-images. Panics if validation fails.
    /// 2. Flattens and sorts the pre-image data. This includes reversing the order to optimize expected access.
    /// 3. Splits the flattened pre-images into shards, each fitting within the given `shard_size`.
    /// 4. If `with_validation_ptrs` is `true`, adds validation pointers to pre-images where necessary:
    ///     - Maintains a cache for already processed pre-images.
    ///     - Assigns pointers to link pre-images that require validation.
    ///
    /// # Panics
    /// This function will panic if the validation of pre-images fails during the call to `validate_preimages`.
    ///
    /// # Logs
    /// Logs the number of pre-images, shard size, and whether validation pointers are included (`with_validation_ptrs`) at the start of finalization.
    ///
    /// # Notes
    /// - Sharding ensures that no shard exceeds the given `shard_size` by aggregating pre-images until the limit is reached.
    /// - Only pre-images requiring validation, as determined by `needs_validation`, will have validation pointers added.
    fn finalize_preimages(&mut self, shard_size: usize, with_validation_ptrs: bool) {
        // 在最终处理前验证预映像数据，若验证失败则触发 panic
        self.validate_preimages()
            .expect("Failed to validate preimages during finalization");
        // 获取预映像数据的可变引用
        let mut preimages = self.preimages.lock().unwrap();
        // flatten and sort
        // 扁平化并排序预映像数据
        // 将嵌套的预映像数据展平为一个一维向量
        let mut flat_vec = core::mem::take(preimages.deref_mut())
            .into_iter()
            .flatten()
            .collect::<Vec<_>>();
        // 记录日志，输出最终处理的预映像数量、分片大小和是否添加验证指针的信息
        info!("Finalizing {} preimages with shard size {shard_size} and validation ptrs {with_validation_ptrs}", flat_vec.len());
        // 按预期访问顺序对扁平化后的向量进行排序，这里通过反转向量实现
        // sort by expected access
        flat_vec.reverse();
        // 根据大小限制对向量进行分片
        // 初始化分片向量，包含一个空的分片
        // shard vectors by size limit
        let mut sharded_vec = vec![vec![]];
        // 记录当前分片的大小
        let mut last_shard_size = 0;
        // 遍历扁平化后的向量，将元素按分片大小限制分配到不同的分片中
        for value in flat_vec {
            // 如果当前元素的大小加上当前分片的大小超过分片大小限制，则创建一个新的分片
            if value.1.len() + last_shard_size > shard_size && last_shard_size > 0 {
                sharded_vec.push(vec![]);
                last_shard_size = 0;
            }
            // 更新当前分片的大小
            last_shard_size += value.1.len();
            // 将元素添加到当前分片的末尾
            sharded_vec.last_mut().unwrap().push(value);
        }
        // 用分片后的向量替换原始的预映像数据
        let _ = core::mem::replace(preimages.deref_mut(), sharded_vec);
        // 如果不需要添加验证指针，则直接返回
        // add validation pointers
        if !with_validation_ptrs {
            return;
        }
        // 初始化一个哈希表，用于缓存预映像键及其在分片中的位置
        let mut cache: HashMap<PreimageKey, (usize, usize)> =
            HashMap::with_capacity(preimages.len());
        // 遍历每个分片及其元素，为需要验证的预映像添加验证指针
        for (i, entry) in preimages.iter_mut().enumerate() {
            for (j, (key, _, pointer)) in entry.iter_mut().enumerate() {
                // 如果该预映像类型不需要验证，则跳过
                if !needs_validation(&key.key_type()) {
                    continue;
                } else if let Some(prev) = cache.insert(*key, (i, j)) {
                    // 如果哈希表中已经存在该预映像键，则更新其验证指针
                    pointer.replace(prev);
                }
            }
        }
    }

}

impl FlushableCache for VecOracle {
    fn flush(&self) {}
}

/// A type alias for a queue structure that stores `IndexedPreimage` elements.
pub type PreimageQueue = VecDeque<IndexedPreimage>;

lazy_static! {
    /// An object used for temporary storage of out-of-order preimages accessed randomly.
    static ref QUEUE: Arc<Mutex<PreimageQueue>> = Default::default();
}

#[async_trait]
impl PreimageOracleClient for VecOracle {
    /// Asynchronously retrieves a preimage for a given `key` using a `PreimageOracle`.
    ///
    /// # Arguments
    ///
    /// * `key` - The `PreimageKey` for which the associated preimage data is being sought.
    ///
    /// # Returns
    ///
    /// Returns a `PreimageOracleResult<Vec<u8>>` containing the corresponding preimage data
    /// if found, or an error if the lookup fails or the preimage is not available.
    ///
    /// # Logic
    ///
    /// - The method works with a locked mutable reference to `self.preimages`, which holds
    ///   precomputed preimages, and a global `QUEUE` used for temporarily queuing key-value
    ///   pairs for lookup.
    /// - Key preimages are validated and processed using various conditions governed by
    ///   target operating system configurations (`zkvm` vs. non-`zkvm` environments).
    ///     - On `zkvm` targets, if the preimage vector is empty, it logs a message, attempts
    ///       to deserialize a shard, validates the deserialized preimages, and adds them to
    ///       the preimage vector for further access.
    ///     - On non-`zkvm` targets, the function panics if the preimage vector is empty, with
    ///       a message indicating exhaustion of preimages in the oracle queue.
    /// - The outer loop checks and processes preimage vector entries until the desired preimage
    ///   is found or the vector is empty.
    /// - The inner loop iterates through preimage entries. If the desired key matches, the
    ///   associated preimage value is returned. Otherwise, the entry is shifted into the
    ///   temporary queue for later use.
    ///
    /// # Notes
    ///
    /// - Any variations in memory access operations or hashing requirements related to hash
    ///   maps are carefully handled, ensuring correctness and avoiding runtime errors.
    /// - Logging is triggered when the temporary queue is non-empty to inform about
    ///   queued elements.
    /// - If deserialization or validation operations fail on `zkvm` targets, the function
    ///   panics to notify an error in streamed shard processing.
    ///
    /// # Panics
    ///
    /// - If the method is called on a non-`zkvm` target and the preimages vector is empty, it
    ///   will panic with an appropriate error message.
    /// - If the shard validation fails (on `zkvm` targets), the function panics with a
    ///   descriptive message.
    ///
    /// # Configuration
    ///
    /// This function behavior depends on the target OS:
    /// - On `zkvm` targets: Processes shard deserialization and validation.
    /// - On non-`zkvm` targets: Panics when the preimages vector is depleted.
    /// 异步获取指定 key 的预映像值。
    ///
    /// 该方法会遍历内部的预映像分片（shard），查找与 key 匹配的值，
    /// 若未找到则会尝试反序列化新的分片（仅 zkvm 环境），
    /// 并使用全局队列缓存临时未命中的元素。
    async fn get(&self, key: PreimageKey) -> PreimageOracleResult<Vec<u8>> {
        // 获取预映像分片的可变锁
        let mut preimages = self.preimages.lock().unwrap();
        // 获取全局队列的可变锁，用于缓存临时未命中的元素
        let mut queue = QUEUE.lock().unwrap();
        // 主循环，直到找到目标 key 或耗尽所有分片
        loop {
            // 如果当前没有分片
            if preimages.is_empty() {
                // zkvm 环境下，尝试反序列化新的分片并校验
                #[cfg(target_os = "zkvm")]
                {
                    crate::client::log("DESERIALIZE STREAMED SHARD");
                    preimages.push(read_shard());
                    Self::validate(preimages.as_ref())
                        .expect("Failed to validate streamed preimages");
                    crate::client::log("STREAMED SHARD VALIDATED");
                }
                // 非 zkvm 环境直接 panic，表示预映像已耗尽
                #[cfg(not(target_os = "zkvm"))]
                panic!(
                    "Exhausted VecOracle seeking {key} ({} queued preimages)",
                    queue.len()
                )
            }

            // 获取当前最后一个分片（栈顶）
            let entry = preimages.last_mut().unwrap();
            // 遍历分片内的所有预映像
            loop {
                // 弹出分片中的最后一个元素
                let Some((last_key, value, _)) = entry.pop() else {
                    break;
                };

                // 如果 key 匹配，返回对应的 value
                if key == last_key {
                    // 如果队列中有临时元素，合并回当前分片
                    if !queue.is_empty() {
                        log(&format!("TEMP ELEMENTS: {}", queue.len()));
                        entry.extend(core::mem::take(queue.deref_mut()));
                    }

                    return Ok(value);
                }
                // 未命中则将该元素放入队列头部，等待后续查找
                queue.push_front((last_key, value, None));
            }
            // 当前分片已遍历完，弹出分片，进入下一个分片
            preimages.pop();
        }
    }

    /// Asynchronously retrieves an exact preimage value for the given key and copies it into the provided buffer.
    ///
    /// # Parameters
    /// - `key`: The `PreimageKey` for which the preimage value is to be retrieved.
    /// - `buf`: A mutable byte slice to store the retrieved preimage value. The buffer must be large enough
    ///   to fit the retrieved value; otherwise, this method will panic.
    ///
    /// # Returns
    /// - `Ok(())` if the value is successfully retrieved and copied into the buffer.
    /// - `Err(PreimageOracleError)` if an error occurs while retrieving the value (e.g., the key is not found).
    ///
    /// # Errors
    /// This function will return an error if the underlying `get` method fails to retrieve the value associated
    /// with the provided key.
    ///
    /// # Panics
    /// This function will panic if the size of the given buffer does not match the size of the retrieved value.
    ///
    /// # Notes
    /// This function assumes that the size of the `buf` matches the size of the preimage value.
    /// Ensure the buffer is allocated with the correct size to avoid panics.
    async fn get_exact(&self, key: PreimageKey, buf: &mut [u8]) -> PreimageOracleResult<()> {
        let value = self.get(key).await?;
        buf.copy_from_slice(value.as_ref());
        Ok(())
    }
}

#[async_trait]
impl HintWriterClient for VecOracle {
    /// Asynchronously writes data or performs an operation based on the provided hint.
    ///
    /// This function serves as a placeholder implementation that currently does nothing
    /// and always returns `Ok(())`.
    ///
    /// # Notes
    /// This function is currently a no-op and may be extended in the future to perform
    /// meaningful write operations based on the provided hint.
    async fn write(&self, _hint: &str) -> PreimageOracleResult<()> {
        Ok(())
    }
}

/// Reads and deserializes a shard into a `PreimageVecEntry` structure.
///
/// This function retrieves binary data representing a serialized shard from the environment.
/// It then attempts to deserialize the binary data into a `PreimageVecEntry` instance using the
/// `rkyv` deserialization framework. If the deserialization process fails, the function will panic
/// with an error message.
///
/// # Returns
/// - A `PreimageVecEntry` object that represents the deserialized shard.
///
/// # Panics
/// - The function panics if deserialization fails, with the message `"Failed to deserialize shard"`.
///
/// # Dependencies
/// This function uses:
/// - `env::read_frame()` to read binary data from the environment.
/// - `rkyv::from_bytes` for deserialization of the binary data into a `PreimageVecEntry`.
///
/// Ensure that the environment contains valid binary data for a `PreimageVecEntry` structure before
/// calling this function.
#[cfg(target_os = "zkvm")]
pub fn read_shard() -> PreimageVecEntry {
    let shard_data = risc0_zkvm::guest::env::read_frame();
    rkyv::from_bytes::<PreimageVecEntry, rkyv::rancor::Error>(&shard_data)
        .expect("Failed to deserialize shard")
}


pub fn load_json_file<T: DeserializeOwned>(data_dir: &PathBuf, file_name: &str) -> serde_json::Result<T> {
    use std::fs;
    let path = data_dir.join(file_name);
    if !path.exists() {
        // 文件不存在，进行相应处理
        println!("文件不存在: {:?}", path);
        log(&format!("file not found: {:#?}", path));
    } else {
        // 文件存在
        println!("文件存在: {:?}", path);
        log(&format!("file found: {:#?}", path));
    }
    let content = fs::read_to_string(path).map_err(serde_json::Error::io)?;
    serde_json::from_str(&content)
}
#[cfg(test)]
#[cfg_attr(coverage_nightly, coverage(off))]
pub mod test_vec_oracle {
    use super::*;
    use alloy_primitives::keccak256;
    use kona_preimage::PreimageKeyType;
    use kona_proof::block_on;
    use risc0_zkvm::sha::{Impl as SHA2, Sha256};
    use rkyv::rancor::Error;
    use std::collections::HashSet;

    // 生成一个带有指定数量和副本数的 VecOracle 及其值集合，一共 value_count * copies 个（key，value）
    pub fn prepare_vec_oracle(value_count: usize, copies: usize) -> (VecOracle, Vec<Vec<u8>>) {
        let mut oracle = VecOracle::default();
        assert_eq!(oracle.preimage_count(), 0);


        // 构造 value_count 个不同的 value，每个为 Vec<u8>
        let values = (0..value_count)
            .map(|i| format!("{i} test {i} value {i}").as_bytes().to_vec())
            .collect::<Vec<_>>();
        // insert sha3 keys
        // 为每个 value 插入 sha3（keccak256）类型的 key
        for value in &values {
            let sha3_key = PreimageKey::new_keccak256(keccak256(value).0);
            for _ in 0..copies {
                oracle.insert_preimage(sha3_key, value.clone());
            }
        }
        // 校验预映像
        oracle.validate_preimages().unwrap();
        assert_eq!(oracle.preimage_count(), values.len() * copies);
        // insert sha2 keys
        // 为每个 value 插入 sha2（sha256）类型的 key
        for value in &values {
            let sha2_key = PreimageKey::new(
                SHA2::hash_bytes(value).as_bytes().try_into().unwrap(),
                PreimageKeyType::Sha256,
            );
            for _ in 0..copies {
                oracle.insert_preimage(sha2_key, value.clone());
            }
        }
        // 再次校验
        oracle.validate_preimages().unwrap();
        assert_eq!(oracle.preimage_count(), values.len() * copies * 2);

        (oracle, values)
    }

    // 消耗 oracle 中的所有预映像，确保每个 key 都能被正确取出
    pub async fn exhaust_vec_oracle(copies: usize, oracle: VecOracle, values: Vec<Vec<u8>>) {
        let initial_size = oracle.preimage_count();
        // 逆序遍历 values，依次取出 sha3 和 sha2 key 对应的值
        for value in values.iter().rev() {
            let sha3_key = PreimageKey::new_keccak256(keccak256(value).0);
            let sha2_key = PreimageKey::new(
                SHA2::hash_bytes(value).as_bytes().try_into().unwrap(),
                PreimageKeyType::Sha256,
            );
            for _ in 0..copies {
                let mut sha3_val = vec![0u8; value.len()];
                oracle.get_exact(sha3_key, &mut sha3_val).await.unwrap();
                let mut sha2_val = vec![0u8; value.len()];
                oracle.get_exact(sha2_key, &mut sha2_val).await.unwrap();
                assert_eq!(sha3_val, sha2_val);
            }
        }
        // ensure exhaustion
        // 校验所有预映像已被消耗
        assert_eq!(
            oracle.preimage_count(),
            initial_size - 2 * copies * values.len()
        );
    }

    // 测试 deep_clone 的正确性
    #[tokio::test]
    async fn test_deep_clone() {
        // 构造 1024 个 value，每个有 3 个副本
        let (mut oracle, values) = prepare_vec_oracle(1024, 3);
        // 插入一个Local类型的 key
        oracle.insert_preimage(
            PreimageKey::new([0xff; 32], PreimageKeyType::Local),
            vec![0xff; 32],
        );
        // 每个分片只包含一个 key，并添加验证指针
        oracle.finalize_preimages(1, true);
        oracle.validate_preimages().unwrap();
        // 记录初始数量
        // assert initial equivalence
        let size = oracle.preimage_count();
        // 深拷贝
        let cloned = oracle.deep_clone();
        assert_eq!(size, cloned.preimage_count());
        // 普通 clone 与 deep_clone 的区别
        // regular cloning vs deep cloning
        exhaust_vec_oracle(3, oracle.clone(), values).await;
        // 原 oracle 只剩下 1 个（本地 key）
        assert_eq!(oracle.preimage_count(), 1);
        // deep_clone 后的副本仍然保持原始数量
        assert_eq!(size, cloned.preimage_count());
    }

    #[tokio::test]
    async fn test_vec_oracle_sharded() {
        let (mut oracle, values) = prepare_vec_oracle(1024, 1);
        // one key per shard
        oracle.finalize_preimages(1, true);
        oracle.validate_preimages().unwrap();
        // serde
        let oracle = rkyv::from_bytes::<VecOracle, Error>(
            rkyv::to_bytes::<Error>(&oracle).unwrap().as_ref(),
        )
            .unwrap();
        // validate
        {
            let preimage_vecs = oracle.preimages.lock().unwrap();
            assert_eq!(preimage_vecs.len(), values.len() * 2);
            for preimages in preimage_vecs.iter() {
                assert_eq!(preimages.len(), 1);
                for preimage in preimages.iter() {
                    assert_eq!(preimage.2, None);
                }
            }
        }
        // retrieve keys
        exhaust_vec_oracle(1, oracle, values).await;
    }

    #[tokio::test]
    async fn test_vec_oracle_unsharded() {
        let (mut oracle, values) = prepare_vec_oracle(1024, 1);
        // one shard for all keys
        oracle.finalize_preimages(usize::MAX, true);
        oracle.validate_preimages().unwrap();
        // serde
        let oracle = rkyv::from_bytes::<VecOracle, Error>(
            rkyv::to_bytes::<Error>(&oracle).unwrap().as_ref(),
        )
            .unwrap();
        // validate
        {
            let preimage_vecs = oracle.preimages.lock().unwrap();
            assert_eq!(preimage_vecs.len(), 1);
            for preimages in preimage_vecs.iter() {
                assert_eq!(preimages.len(), values.len() * 2);
                for preimage in preimages.iter() {
                    assert_eq!(preimage.2, None);
                }
            }
        }
        // retrieve keys
        exhaust_vec_oracle(1, oracle, values).await;
    }

    #[tokio::test]
    async fn test_vec_oracle_duplicates_sharded() {
        let (mut oracle, values) = prepare_vec_oracle(1024, 2);
        // one key per shard
        oracle.finalize_preimages(1, true);
        oracle.validate_preimages().unwrap();
        // serde
        let oracle = rkyv::from_bytes::<VecOracle, Error>(
            rkyv::to_bytes::<Error>(&oracle).unwrap().as_ref(),
        )
            .unwrap();
        // validate
        {
            let preimage_vecs = oracle.preimages.lock().unwrap();
            assert_eq!(preimage_vecs.len(), values.len() * 2 * 2);
            let mut seen_keys = HashSet::new();
            for preimages in preimage_vecs.iter() {
                assert_eq!(preimages.len(), 1);
                for preimage in preimages.iter() {
                    if seen_keys.contains(&preimage.0) {
                        let ptr = preimage.2.unwrap();
                        assert_eq!(&preimage_vecs[ptr.0][ptr.1].0, &preimage.0);
                    } else {
                        assert!(preimage.2.is_none());
                        seen_keys.insert(preimage.0);
                    }
                }
            }
        }
        // retrieve keys
        exhaust_vec_oracle(2, oracle, values).await;
    }

    #[tokio::test]
    async fn test_vec_oracle_duplicates_unsharded() {
        let (mut oracle, values) = prepare_vec_oracle(1024, 2);
        // one shard
        oracle.finalize_preimages(usize::MAX, true);
        oracle.validate_preimages().unwrap();
        // serde
        let oracle = rkyv::from_bytes::<VecOracle, Error>(
            rkyv::to_bytes::<Error>(&oracle).unwrap().as_ref(),
        )
            .unwrap();
        // validate
        {
            let preimage_vecs = oracle.preimages.lock().unwrap();
            assert_eq!(preimage_vecs.len(), 1);
            let mut seen_keys = HashSet::new();
            for preimages in preimage_vecs.iter() {
                assert_eq!(preimages.len(), values.len() * 2);
                for preimage in preimages.iter() {
                    if seen_keys.contains(&preimage.0) {
                        let ptr = preimage.2.unwrap();
                        assert_eq!(&preimage_vecs[ptr.0][ptr.1].0, &preimage.0);
                    } else {
                        assert!(preimage.2.is_none());
                        seen_keys.insert(preimage.0);
                    }
                }
            }
        }
        // retrieve keys
        exhaust_vec_oracle(2, oracle, values).await;
    }

    #[tokio::test]
    async fn test_vec_oracle_duplicates_unsharded_no_cache() {
        let (mut oracle, values) = prepare_vec_oracle(1024, 2);
        // one shard
        oracle.finalize_preimages(usize::MAX, false);
        oracle.validate_preimages().unwrap();
        // serde
        let oracle = rkyv::from_bytes::<VecOracle, Error>(
            rkyv::to_bytes::<Error>(&oracle).unwrap().as_ref(),
        )
            .unwrap();
        // validate
        {
            let preimage_vecs = oracle.preimages.lock().unwrap();
            assert_eq!(preimage_vecs.len(), 1);
            for preimages in preimage_vecs.iter() {
                assert_eq!(preimages.len(), values.len() * 2 * 2);
                for preimage in preimages.iter() {
                    assert!(preimage.2.is_none());
                }
            }
        }
        // retrieve keys
        exhaust_vec_oracle(2, oracle, values).await;
    }

    #[test]
    fn test_vec_oracle_tamper() {
        let (mut oracle, _) = prepare_vec_oracle(1, 4);
        // one key pre shard
        oracle.finalize_preimages(1, true);
        oracle.validate_preimages().unwrap();

        // point first entry to future entry
        {
            let oracle = oracle.deep_clone();
            {
                let mut preimages = oracle.preimages.lock().unwrap();
                let preimage_vec = preimages.first_mut().unwrap();
                let preimage = preimage_vec.first_mut().unwrap();
                preimage.2 = Some((1, 0));
            }
            // fail to validate
            let result = oracle.validate_preimages().unwrap_err();
            assert!(result.to_string().contains("future vec entry"));
        }
        // point first entry to self
        {
            let oracle = oracle.deep_clone();
            {
                let mut preimages = oracle.preimages.lock().unwrap();
                let preimage_vec = preimages.first_mut().unwrap();
                let preimage = preimage_vec.first_mut().unwrap();
                preimage.2 = Some((0, 0));
            }
            // fail to validate
            let result = oracle.validate_preimages().unwrap_err();
            assert!(result.to_string().contains("future preimage"));
        }
        // invalidate key
        {
            let oracle = oracle.deep_clone();
            {
                let mut preimages = oracle.preimages.lock().unwrap();
                let preimage_vec = preimages.first_mut().unwrap();
                let preimage = preimage_vec.first_mut().unwrap();
                preimage.0 = PreimageKey::new([0xff; 32], PreimageKeyType::Local);
            }
            // fail to validate
            let result = oracle.validate_preimages().unwrap_err();
            assert!(result.to_string().contains("key comparison failed"));
        }
        // invalidate value
        {
            let oracle = oracle.deep_clone();
            {
                let mut preimages = oracle.preimages.lock().unwrap();
                let preimage_vec = preimages.last_mut().unwrap();
                let preimage = preimage_vec.first_mut().unwrap();
                preimage.1 = vec![0xff; 32];
            }
            // fail to validate
            let result = oracle.validate_preimages().unwrap_err();
            assert!(result.to_string().contains("value comparison failed"));
        }
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn test_exhaustion() {
        let (mut oracle, values) = prepare_vec_oracle(1, 1);
        oracle.finalize_preimages(usize::MAX, true);
        oracle.validate_preimages().unwrap();
        // fail to refetch key after exhaustion
        let only_key = oracle
            .preimages
            .lock()
            .unwrap()
            .first()
            .unwrap()
            .first()
            .unwrap()
            .0;
        exhaust_vec_oracle(1, oracle.clone(), values).await;
        assert!(std::panic::catch_unwind(|| block_on(oracle.get(only_key))).is_err());
        // clear position state
        assert!(oracle.preimages.is_poisoned());
        QUEUE.clear_poison();
    }

    #[tokio::test]
    async fn test_noop() {
        let oracle = VecOracle::default();
        oracle.write("noop").await.unwrap();
        oracle.flush();
        assert_eq!(oracle.preimage_count(), 0);
    }



}
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub enum SaltWitnessState {
    /// Idle state, no processing
    Idle,
    /// Processing state, the block witness is being generated
    Processing,
    /// Witnessed state, the block witness has been generated
    Witnessed,
    /// Uploading state, the block witness is being uploaded Step 1
    UploadingStep1,
    /// Uploading state, the block witness is being uploaded Step 2
    UploadingStep2,
    /// Completed state, the block witness has been uploaded successfully
    Completed,
}
/// A block hash.
pub type BlockHash = B256;

/// A block number.
pub type BlockNumber = u64;

/// A block timestamp.
pub type BlockTimestamp = u64;
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct WitnessStatus {
    /// restore the block witness status
    pub status: SaltWitnessState,
    /// restore the block hash
    //9:0xf6e417d4f8dc0852f613d9292afd5f62323eb4779ef43d57f02840c322c3ff61
    //10:0xfc3c9527cab0b157942567b795faa1b3fc734c394159a9822509ddcafcb03b00
    pub block_hash: BlockHash,

    /// restore the block number
    pub block_number: BlockNumber,
    /// locking the task brefore the timeout
    pub lock_time: u64,
    /// record the blob ids
    pub blob_ids: Vec<[u8; 32]>,
    /// record the block witness data with bytes
    pub witness_data: Vec<u8>,
}
/// A structure representing a salt-based oracle for storing preimages with specialized BlockWitness support.
///
/// This struct provides functionality similar to VecOracle but with additional methods
/// for handling BlockWitness data specifically.
#[derive(Clone, Debug, Default)]
pub struct SaltVecOracle {
    /// Internal storage for preimages using a HashMap
    preimages: Arc<Mutex<std::collections::HashMap<PreimageKey, Vec<u8>>>>,
}

impl SaltVecOracle {
    /// Creates a new SaltVecOracle instance
    pub fn new() -> Self {
        Self {
            preimages: Arc::new(Mutex::new(std::collections::HashMap::new())),
        }
    }

    /// Creates a deep clone of the current instance.
    pub fn deep_clone(&self) -> Self {
        let preimages = self.preimages.lock().unwrap();
        Self {
            preimages: Arc::new(Mutex::new(preimages.clone())),
        }
    }

    /// Inserts a PreconditionValidationData into the oracle.
    ///
    /// This method serializes the PreconditionValidationData using pot serialization,
    /// creates a SHA256 hash as the key, and stores it in the oracle.
    ///
    /// # Arguments
    /// * `precondition_data` - The PreconditionValidationData to store
    ///
    /// # Returns
    /// * `B256` - The hash key that was generated and used for storage
    pub fn insert_precondition_validation_data(&mut self, precondition_data: PreconditionValidationData) -> B256 {
        // 序列化 PreconditionValidationData
        let serialized_data = precondition_data.to_vec();

        // 计算数据的哈希作为 key
        let data_hash = precondition_data.hash();

        // 创建 PreimageKey
        let preimage_key = PreimageKey::new(*data_hash, PreimageKeyType::Sha256);

        // 存储到 oracle 中
        self.insert_preimage(preimage_key, serialized_data);

        data_hash
    }

    /// Retrieves a PreconditionValidationData from the oracle.
    ///
    /// # Arguments
    /// * `precondition_data_hash` - The hash of the PreconditionValidationData to retrieve
    ///
    /// # Returns
    /// * `Option<PreconditionValidationData>` - The deserialized PreconditionValidationData if found, None otherwise
    pub async fn get_precondition_validation_data(&self, precondition_data_hash: B256) -> Option<PreconditionValidationData> {
        // 如果是零哈希，直接返回 None
        if precondition_data_hash.is_zero() {
            return None;
        }

        // 创建 PreimageKey
        let preimage_key = PreimageKey::new(*precondition_data_hash, PreimageKeyType::Sha256);

        // 从 oracle 获取数据
        if let Ok(serialized_data) = self.get(preimage_key).await {
            // 反序列化数据
            if let Ok(precondition_data) = pot::from_slice::<PreconditionValidationData>(&serialized_data) {
                return Some(precondition_data);
            }
        }

        None
    }

    /// Inserts a BlockWitness into the oracle.
    ///
    /// # Arguments
    /// * `block_hash` - The original block hash (32 bytes)
    /// * `serialized_block_witness` - The serialized BlockWitness data
    ///
    /// # Returns
    /// * `PreimageKey` - The witness key that was generated and used for storage
    pub fn insert_block_witness(&mut self, block_hash: [u8; 32], serialized_block_witness: Vec<u8>) -> PreimageKey {
        // 将 block_hash 转换为 witness_key
        let witness_key = PreimageKey::new_blockwitness(block_hash);

        // 使用内部的 insert_preimage 方法
        // self.insert_preimage(witness_key, serialized_block_witness);
        self.insert_preimage(witness_key, serialized_block_witness.clone());

        witness_key
    }

    /// Retrieves a BlockWitness from the oracle.
    ///
    /// # Arguments
    /// * `block_hash` - The original block hash (32 bytes)
    ///
    /// # Returns
    /// * `Option<Vec<u8>>` - The serialized BlockWitness data if found, None otherwise
    pub async fn get_block_witness(&self, block_hash: [u8; 32]) -> Option<Vec<u8>> {
        // 将 block_hash 转换为 witness_key
        let witness_key = PreimageKey::new_blockwitness(block_hash);

        // 使用内部的 get 方法
        self.get(witness_key).await.ok()
    }

    /// Validates the stored preimages
    pub fn validate_stored_preimages(&self) -> anyhow::Result<()> {
        let preimages = self.preimages.lock().unwrap();
        for (key, value) in preimages.iter() {
            if needs_validation(&key.key_type()) {
                validate_preimage(key, value)?;
            }
        }
        Ok(())
    }
    /// 将 BootInfo 写入 preimage oracle
    pub async fn insert_boot_info(&mut self, boot_info: BootInfo) -> Result<(), OracleProviderError> {
        let mut preimages = self.preimages.lock().unwrap();
        preimages.insert(PreimageKey::new_local(L1_HEAD_KEY.to()), boot_info.l1_head.0.to_vec());


        // 写入 l2_output_root
        preimages.insert(PreimageKey::new_local(L2_OUTPUT_ROOT_KEY.to()), boot_info.agreed_l2_output_root.0.to_vec());
        // 写入 l2_claim_key
        preimages.insert(PreimageKey::new_local(L2_CLAIM_KEY.to()), boot_info.claimed_l2_output_root.0.to_vec());
        // 写入 l2_claim_block_number
        preimages.insert(PreimageKey::new_local(L2_CLAIM_BLOCK_NUMBER_KEY.to()), boot_info.claimed_l2_block_number.to_be_bytes().to_vec());
        // 写入 l2_chain_id
        preimages.insert(PreimageKey::new_local(L2_CHAIN_ID_KEY.to()), boot_info.chain_id.to_be_bytes().to_vec());
        // 写入 rollup_config
        let ser_cfg = serde_json::to_vec(&boot_info.rollup_config)
            .map_err(OracleProviderError::Serde)?;
        preimages.insert(PreimageKey::new_local(L2_ROLLUP_CONFIG_KEY.to()), ser_cfg);
        Ok(())

    }
    /// 从 preimage oracle 加载 BootInfo
    pub async fn load_boot_info(&self) -> Result<BootInfo, OracleProviderError> {
        let preimages = self.preimages.lock().unwrap();

        // 读取 l1_head
        let l1_head = preimages
            .get(&PreimageKey::new_local(L1_HEAD_KEY.to()))
            .ok_or(OracleProviderError::Preimage(kona_preimage::errors::PreimageOracleError::KeyNotFound))?
            .as_slice();
        let l1_head = B256::try_from(l1_head)
            .map_err(|_| OracleProviderError::Preimage(kona_preimage::errors::PreimageOracleError::KeyNotFound))?;

        // 读取 l2_output_root
        let agreed_l2_output_root = preimages
            .get(&PreimageKey::new_local(L2_OUTPUT_ROOT_KEY.to()))
            .ok_or(OracleProviderError::Preimage(kona_preimage::errors::PreimageOracleError::KeyNotFound))?
            .as_slice();
        let agreed_l2_output_root = B256::try_from(agreed_l2_output_root)
            .map_err(|_| OracleProviderError::Preimage(kona_preimage::errors::PreimageOracleError::KeyNotFound))?;

        // 读取 l2_claim_key
        let claimed_l2_output_root = preimages
            .get(&PreimageKey::new_local(L2_CLAIM_KEY.to()))
            .ok_or(OracleProviderError::Preimage(kona_preimage::errors::PreimageOracleError::KeyNotFound))?
            .as_slice();
        let claimed_l2_output_root = B256::try_from(claimed_l2_output_root)
            .map_err(|_| OracleProviderError::Preimage(kona_preimage::errors::PreimageOracleError::KeyNotFound))?;

        // 读取 l2_claim_block_number
        let claimed_l2_block_number = preimages
            .get(&PreimageKey::new_local(L2_CLAIM_BLOCK_NUMBER_KEY.to()))
            .ok_or(OracleProviderError::Preimage(kona_preimage::errors::PreimageOracleError::KeyNotFound))?
            .as_slice();
        let claimed_l2_block_number = <[u8; 8]>::try_from(claimed_l2_block_number)
            .map_err(|_| OracleProviderError::Preimage(kona_preimage::errors::PreimageOracleError::KeyNotFound))?;
        let claimed_l2_block_number = u64::from_be_bytes(claimed_l2_block_number);

        // 读取 l2_chain_id
        let chain_id = preimages
            .get(&PreimageKey::new_local(L2_CHAIN_ID_KEY.to()))
            .ok_or(OracleProviderError::Preimage(kona_preimage::errors::PreimageOracleError::KeyNotFound))?
            .as_slice();
        let chain_id = <[u8; 8]>::try_from(chain_id)
            .map_err(|_| OracleProviderError::Preimage(kona_preimage::errors::PreimageOracleError::KeyNotFound))?;
        let chain_id = u64::from_be_bytes(chain_id);

        // 读取 rollup_config
        let rollup_config_bytes = preimages
            .get(&PreimageKey::new_local(L2_ROLLUP_CONFIG_KEY.to()))
            .ok_or(OracleProviderError::Preimage(kona_preimage::errors::PreimageOracleError::KeyNotFound))?;
        let rollup_config = serde_json::from_slice(rollup_config_bytes)
            .map_err(OracleProviderError::Serde)?;

        Ok(BootInfo {
            l1_head,
            agreed_l2_output_root,
            claimed_l2_output_root,
            claimed_l2_block_number,
            chain_id,
            rollup_config,
        })
    }
    /// 将 L1 区块头插入到 oracle 中
    ///
    /// # Arguments
    /// * `header` - 要存储的 Header 对象
    /// * `l1_head` - L1 区块头的哈希值，用作存储键
    pub async fn insert_header(&mut self, header: Header) -> B256 {
        // 将 Header 编码为 RLP 格式
        let mut encoded_rlp = Vec::new();
        header.encode(&mut encoded_rlp);
        let l1_head = keccak256(&encoded_rlp);

        // 创建 PreimageKey 并存储
        let preimage_key = PreimageKey::new(*l1_head, PreimageKeyType::Keccak256);
        self.insert_preimage(preimage_key, encoded_rlp);

        l1_head
    }
    /// 从 oracle 中加载 L1 区块头
    ///
    /// # Arguments
    /// * `l1_head` - L1 区块头的哈希值
    ///
    /// # Returns
    /// * `Option<Header>` - 如果找到则返回反序列化的 Header，否则返回 None
    pub async fn load_header(&self, l1_head: B256) -> Option<Header> {
        // 创建 PreimageKey
        let preimage_key = PreimageKey::new(*l1_head, PreimageKeyType::Keccak256);

        // 从 oracle 获取 RLP 编码的数据
        if let Ok(encoded_rlp) = self.get(preimage_key).await {
            // 使用 RLP 解码
            if let Ok(header) = Header::decode(&mut encoded_rlp.as_slice()) {
                return Some(header);
            }
        }

        None
    }
    pub fn compute_output_root(
        &self,
        state_root: B256,
        withdrawal_storage_root: B256,
        latest_block_hash: B256,
    ) -> B256 {
        // L2 输出根的计算公式：
        // keccak256(version_byte || state_root || withdrawal_storage_root || latest_block_hash)
        let mut encoded = [0u8; 128];
        encoded[31] = 0;
        encoded[32..64].copy_from_slice(state_root.as_slice());
        encoded[64..96].copy_from_slice(withdrawal_storage_root.as_slice());
        encoded[96..128].copy_from_slice(latest_block_hash.as_slice());

        keccak256(&encoded)
    }
    /// 将计算的输出根插入 oracle 存储
    ///
    /// # Arguments
    /// * `state_root` - 状态根
    /// * `withdrawal_storage_root` - 提款存储根
    /// * `latest_block_hash` - 最新区块哈希
    ///
    /// # Returns
    /// * `B256` - 计算得到的输出根哈希
    pub fn insert_output_root(
        &mut self,
        state_root: B256,
        withdrawal_storage_root: B256,
        latest_block_hash: B256,
    ) -> B256 {
        // 构造 encoded 数据 (version_byte || state_root || withdrawal_storage_root || latest_block_hash)
        let mut encoded = [0u8; 128];
        encoded[31] = 0; // version_byte
        encoded[32..64].copy_from_slice(state_root.as_slice());
        encoded[64..96].copy_from_slice(withdrawal_storage_root.as_slice());
        encoded[96..128].copy_from_slice(latest_block_hash.as_slice());
        // 计算输出根
        let output_root=keccak256(&encoded);

        // 使用 output_root 作为 key，encoded 数据作为 value
        let output_root_key = PreimageKey::new(*output_root, PreimageKeyType::Keccak256);
        self.insert_preimage(output_root_key, encoded.to_vec());

        output_root
    }
    /// 从测试数据文件中加载区块数据，提取交易并将交易数据存储到oracle中
    ///
    /// # Arguments
    /// * `block_number` - 要加载的区块号
    /// * `block_hash` - 区块哈希，用于构造文件名
    ///
    /// # Returns
    /// * `anyhow::Result<B256>` - 返回交易根哈希，如果成功的话
    pub fn load_file_insert_transaction(
        &mut self,
        block_number: u64,
        block_hash: B256,
    ) -> anyhow::Result<B256> {
        use std::sync::RwLock;
        use serde_json::Value;
        kona_cli::init_test_tracing();

        // 构造测试数据目录路径
        // let test_data_dir = PathBuf::from("./src/oracle/test_data/stateless/witness");
        let test_data_dir = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join("src/oracle/test_data/stateless/witness");
        if !test_data_dir.is_dir() {
            log(&format!("Witness directory not found: {:#?}", test_data_dir));
            return Err(anyhow!("Witness directory not found: {:?}", test_data_dir));
        }else{
            log(&format!("Witness directory found: {:#?}", test_data_dir));
            println!("Witness directory found: {:?}", test_data_dir);
        }

        // 构造文件名：{block_number}.{block_hash}.block.json
        let file_name = format!("{}.{:#x}.block.json", block_number, block_hash);

        // 读取并解析JSON文件
        let block_data: Value = load_json_file(&test_data_dir, &file_name)?;
        let transaction_root=block_data.get("transactionsRoot");

        // 提取交易数组
        let transactions = block_data
            .get("transactions")
            .ok_or_else(|| anyhow!("Missing transactions field in block data"))?
            .as_array()
            .ok_or_else(|| anyhow!("Transactions field is not an array"))?;

        // 将交易序列化为字节数组
        let encoded_transactions: Vec<Vec<u8>> = transactions
            .iter()
            .map(|tx| serde_json::to_vec(tx))
            .collect::<Result<Vec<_>, _>>()?;


        let mut hb = kona_mpt::ordered_trie_with_encoder(&*encoded_transactions, |node, buf| {
            buf.put_slice(node.as_ref());
        });
        hb.root();
        let intermediates = hb.take_proof_nodes().into_inner();

        for (_, value) in intermediates.into_iter() {
            let value_hash = keccak256(value.as_ref());
            let key = PreimageKey::new(*value_hash, PreimageKeyType::Keccak256);
            self.insert_preimage(key, Vec::from(value));
        }
        Ok(transaction_root.unwrap().as_str().unwrap().parse::<B256>().unwrap())
    }


}

impl WitnessOracle for SaltVecOracle {
    fn preimage_count(&self) -> usize {
        self.preimages.lock().unwrap().len()
    }

    fn validate_preimages(&self) -> anyhow::Result<()> {
        self.validate_stored_preimages()
    }

    fn insert_preimage(&mut self, key: PreimageKey, value: Vec<u8>) {
        validate_preimage(&key, &value).expect("Attempted to save invalid preimage");
        let mut preimages = self.preimages.lock().unwrap();
        preimages.insert(key, value);
    }

    fn finalize_preimages(&mut self, _shard_size: usize, _with_validation_ptrs: bool) {
        // For SaltVecOracle, we don't need complex sharding like VecOracle
        // Just validate the preimages
        self.validate_preimages()
            .expect("Failed to validate preimages during finalization");
        info!("Finalized {} preimages in SaltVecOracle", self.preimage_count());
    }
}

impl FlushableCache for SaltVecOracle {
    fn flush(&self) {
        // No-op for SaltVecOracle as it's in-memory
    }
}

#[async_trait]
impl PreimageOracleClient for SaltVecOracle {
    async fn get(&self, key: PreimageKey) -> PreimageOracleResult<Vec<u8>> {
        let preimages = self.preimages.lock().unwrap();
        preimages.get(&key).cloned().ok_or(kona_preimage::errors::PreimageOracleError::KeyNotFound)
    }

    async fn get_exact(&self, key: PreimageKey, buf: &mut [u8]) -> PreimageOracleResult<()> {
        let value = self.get(key).await?;
        if buf.len() != value.len() {
            return Err(kona_preimage::errors::PreimageOracleError::KeyNotFound);
        }
        buf.copy_from_slice(&value);
        Ok(())
    }
}

#[async_trait]
impl HintWriterClient for SaltVecOracle {
    async fn write(&self, _hint: &str) -> PreimageOracleResult<()> {
        Ok(())
    }
}

#[cfg(test)]
pub(crate) mod test_salt_vec_oracle {
    use super::*;
    use alloy_primitives::{b256, keccak256,U256};
    use kona_preimage::PreimageKeyType;
    use risc0_zkvm::sha::{Impl as SHA2, Sha256};
    pub fn prepare_salt_vec_oracle(beginblocknumber: usize, blockcount: usize) -> SaltVecOracle {
        let mut oracle = SaltVecOracle::default();
        assert_eq!(oracle.preimage_count(), 0);
        assert!(blockcount < 4, "blockcount 必须小于 4");

        let block_hash_8 = b256!("0xfa5a973957d70f5433ffc6564fa9361b3f0cd98fc0dd9fca79b97c5c6f3314be");
        let block_hash_9 = b256!("0x962ce2cad3cb7a3071e5f110548e093866ea4d6328272898aba72528769d1513");
        let block_hash_10 = b256!("0x06059400419a9b46b13d987fc5cf85bbe2d8b41fbc384e56ef88927812c0b862");


        // 定义 state_root 和 withdrawal_storage_root
        let state_root_8 = b256!("0xd0ca14bbe5b2ccb6aec5d091966881ac40086b647222c2d660e90b2076dde100");
        let state_root_9 = b256!("0xfc3c9527cab0b157942567b795faa1b3fc734c394159a9822509ddcafcb03b00");
        let state_root_10 = b256!("0x36357858790f80080cd75266b7a427dcf77b073626a5eda9c6b933d736008702");

        let withdrawal_storage_root = b256!("0xfedcba0987654321fedcba0987654321fedcba0987654321fedcba0987654321");

        let mut _output_root_8=B256::default();

        // 处理区块 8
        if beginblocknumber <= 8 && beginblocknumber + blockcount > 8 {
            // 使用 insert_output_root 插入 output_root 相关数据
            _output_root_8 = oracle.insert_output_root(state_root_8, withdrawal_storage_root, block_hash_8);

            println!("insert output_root8: {:?}", B256::from(_output_root_8));

            // 插入 block_witness 相关数据
            let witness_8 = WitnessStatus {
                status: SaltWitnessState::Witnessed,
                block_hash: block_hash_8,
                block_number: 8,
                lock_time: 0,
                blob_ids: vec![[0x08; 32]],
                witness_data: vec![0x8; 20],
            };
            let serialized_witness_8 = bincode::serialize(&witness_8).unwrap();
            oracle.insert_block_witness(*block_hash_8, serialized_witness_8.clone());

        }

        // 处理区块 9
        if beginblocknumber <= 9 && beginblocknumber + blockcount > 9 {
            let _output_root_9 = oracle.insert_output_root(state_root_9, withdrawal_storage_root, block_hash_9);
            println!("insert output_root_9: {:?}", B256::from(_output_root_9));

            let witness_9 = WitnessStatus {
                status: SaltWitnessState::Witnessed,
                block_hash: block_hash_9,
                block_number: 9,
                lock_time: 0,
                blob_ids: vec![[0x09; 32]],
                witness_data: vec![0x9; 20],
            };
            let serialized_witness_9 = bincode::serialize(&witness_9).unwrap();
            oracle.insert_block_witness(*block_hash_9, serialized_witness_9.clone());
        }

        // 处理区块 10
        if beginblocknumber <= 10 && beginblocknumber + blockcount > 10 {
            let _output_root_10 = oracle.insert_output_root(state_root_10, withdrawal_storage_root, block_hash_10);
            println!("insert output_root_10: {:?}", B256::from(_output_root_10));
            let witness_10 = WitnessStatus {
                status: SaltWitnessState::Witnessed,
                block_hash: block_hash_10,
                block_number: 10,
                lock_time: 0,
                blob_ids: vec![[0x0A; 32]],
                witness_data: vec![0xA; 20],
            };
            let serialized_witness_10 = bincode::serialize(&witness_10).unwrap();
            oracle.insert_block_witness(*block_hash_10, serialized_witness_10.clone());
        }
        oracle.load_file_insert_transaction(8, block_hash_8).unwrap();
        oracle.load_file_insert_transaction(9, block_hash_9).unwrap();
        oracle.load_file_insert_transaction(10, block_hash_10).unwrap();

        oracle.validate_preimages().unwrap();
        oracle
    }

    // 消耗 oracle 中的所有预映像，确保每个 key 都能被正确取出
    pub async fn exhaust_salt_vec_oracle(copies: usize, oracle: SaltVecOracle, values: Vec<Vec<u8>>) {
        let initial_size = oracle.preimage_count();
        // 逆序遍历 values，依次取出 sha3 和 sha2 key 对应的值
        for value in values.iter().rev() {
            let sha3_key = PreimageKey::new_keccak256(keccak256(value).0);
            let sha2_key = PreimageKey::new(
                SHA2::hash_bytes(value).as_bytes().try_into().unwrap(),
                PreimageKeyType::Sha256,
            );
            for _ in 0..copies {
                let mut sha3_val = vec![0u8; value.len()];
                oracle.get_exact(sha3_key, &mut sha3_val).await.unwrap();
                let mut sha2_val = vec![0u8; value.len()];
                oracle.get_exact(sha2_key, &mut sha2_val).await.unwrap();
                assert_eq!(sha3_val, sha2_val);
            }
        }
        // ensure exhaustion
        // 校验所有预映像已被消耗
        assert_eq!(
            oracle.preimage_count(),
            initial_size - 2 * copies * values.len()
        );
    }

    #[tokio::test]
    async fn test_prepare_salt_vec_oracle_basic() {
        // 构造一个包含2个区块的oracle和测试数据
        let oracle = prepare_salt_vec_oracle(8, 2);


        // 检查 blockwitness 读取和内容正确性
        use alloy_primitives::b256;
        let block_hashes = [
            b256!("b3bda63a35f00b666dc7dcb3542ebd4d2755ecbbb97d5b5b312b57b5124658fc"),
            b256!("f6e417d4f8dc0852f613d9292afd5f62323eb4779ef43d57f02840c322c3ff61"),
        ];
        for (i, &block_hash) in block_hashes.iter().enumerate() {
            let data = oracle.get_block_witness(*block_hash).await.unwrap();
            // 这里我们知道插入的是 vec![0x8 + i as u8; 20]
            let expected = vec![0x8 + i as u8; 20];
            assert_eq!(data, expected);
        }
    }
    #[tokio::test]
    async fn test_salt_oracle_insert_and_get_blockwitness() {
        // 创建测试用的 BlockWitness 数据
        let witness = WitnessStatus {
            status: SaltWitnessState::Witnessed,
            block_hash: Default::default(),
            block_number: 8,
            lock_time: 0,
            blob_ids: vec![[0x00; 32], [0x01; 32]],
            witness_data: vec![1, 2, 3, 4],
        };

        // 序列化测试数据
        let serialized_block_witness = bincode::serialize(&witness).unwrap();
        let block_hash = [0x01; 32];

        // 创建 SaltVecOracle 并插入 BlockWitness
        let mut oracle = SaltVecOracle::new();
        let witness_key = oracle.insert_block_witness(block_hash, serialized_block_witness.clone());

        // 验证插入的 key 是正确的
        let expected_key = PreimageKey::new_blockwitness(block_hash);
        assert_eq!(witness_key, expected_key);

        // 通过 get_block_witness 方法读取
        let retrieved_data = oracle.get_block_witness(block_hash).await.unwrap();
        assert_eq!(retrieved_data, serialized_block_witness);

        // 反序列化并验证数据完整性
        let deserialized: WitnessStatus = bincode::deserialize(&retrieved_data).unwrap();
        assert_eq!(deserialized.status, SaltWitnessState::Witnessed);
        assert_eq!(deserialized.block_number, 8);
        assert_eq!(deserialized.blob_ids, vec![[0x00; 32], [0x01; 32]]);
        assert_eq!(deserialized.witness_data, vec![1, 2, 3, 4]);

    }

    #[tokio::test]
    async fn test_salt_oracle_get_nonexistent_blockwitness() {
        let oracle = SaltVecOracle::new();
        let block_hash = [0xFF; 32];

        // 尝试获取不存在的 BlockWitness
        let result = oracle.get_block_witness(block_hash).await;
        assert!(result.is_none());
    }

    #[tokio::test]
    async fn test_salt_oracle_multiple_blockwitness() {
        let mut oracle = SaltVecOracle::new();

        // 插入多个 BlockWitness
        let witness1 = WitnessStatus {
            status: SaltWitnessState::Witnessed,
            block_hash: Default::default(),
            block_number: 8,
            lock_time: 0,
            blob_ids: vec![[0x00; 32], [0x01; 32]],
            witness_data: vec![1, 2, 3, 4],
        };
        let witness2 = WitnessStatus {
            status: SaltWitnessState::Witnessed,
            block_hash: Default::default(),
            block_number: 9,
            lock_time: 0,
            blob_ids: vec![[0x00; 32], [0x01; 32]],
            witness_data: vec![1, 2, 3, 4],
        };

        let serialized1 = bincode::serialize(&witness1).unwrap();
        let serialized2 = bincode::serialize(&witness2).unwrap();
        let hash1 = [0x01; 32];
        let hash2 = [0x02; 32];

        oracle.insert_block_witness(hash1, serialized1.clone());
        oracle.insert_block_witness(hash2, serialized2.clone());

        // 验证可以分别获取
        let retrieved1 = oracle.get_block_witness(hash1).await.unwrap();
        let retrieved2 = oracle.get_block_witness(hash2).await.unwrap();

        assert_eq!(retrieved1, serialized1);
        assert_eq!(retrieved2, serialized2);
        assert_eq!(oracle.preimage_count(), 2);
    }

    #[test]
    fn test_salt_oracle_deep_clone() {
        let mut oracle = SaltVecOracle::new();
        let block_hash = [0x03; 32];
        let test_data = vec![0x12, 0x34, 0x56, 0x78];

        oracle.insert_block_witness(block_hash, test_data.clone());

        // 深度克隆
        let cloned_oracle = oracle.deep_clone();
        assert_eq!(cloned_oracle.preimage_count(), 1);

        // 验证克隆的 oracle 包含相同的数据
        tokio::runtime::Runtime::new().unwrap().block_on(async {
            let retrieved = cloned_oracle.get_block_witness(block_hash).await.unwrap();
            assert_eq!(retrieved, test_data);
        });
    }

    #[tokio::test]
    async fn test_salt_oracle_write_and_load_bootinfo() {
        use kona_genesis::RollupConfig;
        use alloy_primitives::b256;

        let mut oracle = SaltVecOracle::new();

        // 创建测试用的 BootInfo
        let test_boot_info = BootInfo {
            l1_head: b256!("1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef"),
            agreed_l2_output_root: b256!("abcdef1234567890abcdef1234567890abcdef1234567890abcdef1234567890"),
            claimed_l2_output_root: b256!("fedcba0987654321fedcba0987654321fedcba0987654321fedcba0987654321"),
            claimed_l2_block_number: 12345,
            chain_id: 901,
            rollup_config: RollupConfig::default(),
        };

        // 测试写入 BootInfo
        let write_result = oracle.insert_boot_info(test_boot_info.clone()).await;
        assert!(write_result.is_ok(), "Failed to write BootInfo: {:?}", write_result);

        // 验证写入后预映像数量增加了（应该有6个key：l1_head, agreed_l2_output_root, claimed_l2_output_root, claimed_l2_block_number, chain_id, rollup_config）
        assert_eq!(oracle.preimage_count(), 6);

        // 测试加载 BootInfo
        let loaded_boot_info = oracle.load_boot_info().await;
        assert!(loaded_boot_info.is_ok(), "Failed to load BootInfo: {:?}", loaded_boot_info);

        let loaded_boot_info = loaded_boot_info.unwrap();

        // 验证加载的数据与原始数据一致
        assert_eq!(loaded_boot_info.l1_head, test_boot_info.l1_head);
        assert_eq!(loaded_boot_info.agreed_l2_output_root, test_boot_info.agreed_l2_output_root);
        assert_eq!(loaded_boot_info.claimed_l2_output_root, test_boot_info.claimed_l2_output_root);
        assert_eq!(loaded_boot_info.claimed_l2_block_number, test_boot_info.claimed_l2_block_number);
        assert_eq!(loaded_boot_info.chain_id, test_boot_info.chain_id);
        // RollupConfig 比较可能比较复杂，这里简单验证是否成功反序列化
        // 实际项目中可以根据 RollupConfig 的具体字段进行详细比较
    }

    #[tokio::test]
    async fn test_salt_oracle_load_missing_keys() {
        let oracle = SaltVecOracle::new();

        // 尝试从空的 oracle 加载 BootInfo，应该失败
        let result = oracle.load_boot_info().await;
        assert!(result.is_err());

        // 验证错误类型是 KeyNotFound
        match result {
            Err(OracleProviderError::Preimage(kona_preimage::errors::PreimageOracleError::KeyNotFound)) => {
                // 期望的错误类型
            }
            _ => panic!("Expected KeyNotFound error, got: {:?}", result),
        }
    }

    #[tokio::test]
    async fn test_salt_oracle_load_invalid_data_length() {
        let mut oracle = SaltVecOracle::new();

        // 插入长度不正确的 l1_head 数据（应该是32字节，但插入31字节）
        oracle.insert_preimage(
            PreimageKey::new_local(L1_HEAD_KEY.to()),
            vec![0u8; 31], // 错误的长度
        );

        // 尝试加载，应该因为长度不匹配而失败
        let result = oracle.load_boot_info().await;
        assert!(result.is_err());

        match result {
            Err(OracleProviderError::Preimage(kona_preimage::errors::PreimageOracleError::KeyNotFound)) => {
                // 期望的错误类型（我们用KeyNotFound代替InvalidInput）
            }
            _ => panic!("Expected KeyNotFound error for l1_head length, got: {:?}", result),
        }
    }

    #[tokio::test]
    async fn test_salt_oracle_load_invalid_u64_length() {
        use alloy_primitives::b256;

        let mut oracle = SaltVecOracle::new();

        // 插入正确的 B256 类型数据
        oracle.insert_preimage(
            PreimageKey::new_local(L1_HEAD_KEY.to()),
            b256!("1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef").0.to_vec(),
        );
        oracle.insert_preimage(
            PreimageKey::new_local(L2_OUTPUT_ROOT_KEY.to()),
            b256!("abcdef1234567890abcdef1234567890abcdef1234567890abcdef1234567890").0.to_vec(),
        );
        oracle.insert_preimage(
            PreimageKey::new_local(L2_CLAIM_KEY.to()),
            b256!("fedcba0987654321fedcba0987654321fedcba0987654321fedcba0987654321").0.to_vec(),
        );

        // 插入长度不正确的 u64 数据（应该是8字节，但插入4字节）
        oracle.insert_preimage(
            PreimageKey::new_local(L2_CLAIM_BLOCK_NUMBER_KEY.to()),
            vec![0u8; 4], // 错误的长度
        );

        // 尝试加载，应该因为 u64 长度不匹配而失败
        let result = oracle.load_boot_info().await;
        assert!(result.is_err());

        match result {
            Err(OracleProviderError::Preimage(kona_preimage::errors::PreimageOracleError::KeyNotFound)) => {
                // 期望的错误类型
            }
            _ => panic!("Expected KeyNotFound error for claimed_l2_block_number length, got: {:?}", result),
        }
    }

    #[tokio::test]
    async fn test_salt_oracle_load_invalid_json() {
        use alloy_primitives::b256;

        let mut oracle = SaltVecOracle::new();

        // 插入所有必需的字段，但 rollup_config 使用无效的 JSON
        oracle.insert_preimage(
            PreimageKey::new_local(L1_HEAD_KEY.to()),
            b256!("1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef").0.to_vec(),
        );
        oracle.insert_preimage(
            PreimageKey::new_local(L2_OUTPUT_ROOT_KEY.to()),
            b256!("abcdef1234567890abcdef1234567890abcdef1234567890abcdef1234567890").0.to_vec(),
        );
        oracle.insert_preimage(
            PreimageKey::new_local(L2_CLAIM_KEY.to()),
            b256!("fedcba0987654321fedcba0987654321fedcba0987654321fedcba0987654321").0.to_vec(),
        );
        oracle.insert_preimage(
            PreimageKey::new_local(L2_CLAIM_BLOCK_NUMBER_KEY.to()),
            12345u64.to_be_bytes().to_vec(),
        );
        oracle.insert_preimage(
            PreimageKey::new_local(L2_CHAIN_ID_KEY.to()),
            901u64.to_be_bytes().to_vec(),
        );

        // 插入无效的 JSON 数据
        oracle.insert_preimage(
            PreimageKey::new_local(L2_ROLLUP_CONFIG_KEY.to()),
            b"invalid json {".to_vec(),
        );

        // 尝试加载，应该因为 JSON 反序列化失败而失败
        let result = oracle.load_boot_info().await;
        assert!(result.is_err());

        match result {
            Err(OracleProviderError::Serde(_)) => {
                // 期望的错误类型
            }
            _ => panic!("Expected Serde error, got: {:?}", result),
        }
    }

    #[tokio::test]
    async fn test_salt_oracle_write_load_roundtrip() {
        use kona_genesis::RollupConfig;
        use alloy_primitives::b256;

        // 测试多次写入和加载的往返操作
        let mut oracle = SaltVecOracle::new();

        let boot_info1 = BootInfo {
            l1_head: b256!("1111111111111111111111111111111111111111111111111111111111111111"),
            agreed_l2_output_root: b256!("2222222222222222222222222222222222222222222222222222222222222222"),
            claimed_l2_output_root: b256!("3333333333333333333333333333333333333333333333333333333333333333"),
            claimed_l2_block_number: 100,
            chain_id: 1,
            rollup_config: RollupConfig::default(),
        };

        let boot_info2 = BootInfo {
            l1_head: b256!("4444444444444444444444444444444444444444444444444444444444444444"),
            agreed_l2_output_root: b256!("5555555555555555555555555555555555555555555555555555555555555555"),
            claimed_l2_output_root: b256!("6666666666666666666666666666666666666666666666666666666666666666"),
            claimed_l2_block_number: 200,
            chain_id: 2,
            rollup_config: RollupConfig::default(),
        };

        // 第一次写入和加载
        oracle.insert_boot_info(boot_info1.clone()).await.unwrap();
        let loaded1 = oracle.load_boot_info().await.unwrap();
        assert_eq!(loaded1.l1_head, boot_info1.l1_head);
        assert_eq!(loaded1.claimed_l2_block_number, boot_info1.claimed_l2_block_number);
        assert_eq!(loaded1.chain_id, boot_info1.chain_id);

        // 第二次写入（覆盖）和加载
        oracle.insert_boot_info(boot_info2.clone()).await.unwrap();
        let loaded2 = oracle.load_boot_info().await.unwrap();
        assert_eq!(loaded2.l1_head, boot_info2.l1_head);
        assert_eq!(loaded2.claimed_l2_block_number, boot_info2.claimed_l2_block_number);
        assert_eq!(loaded2.chain_id, boot_info2.chain_id);

        // 验证数据确实被覆盖了
        assert_ne!(loaded2.l1_head, boot_info1.l1_head);
        assert_ne!(loaded2.claimed_l2_block_number, boot_info1.claimed_l2_block_number);
    }

    #[tokio::test]
    async fn test_salt_oracle_insert_and_get_precondition_validation_data() {
        use crate::blobs::BlobFetchRequest;
        use alloy_eips::eip4844::IndexedBlobHash;
        use alloy_primitives::b256;

        let mut oracle = SaltVecOracle::new();

        // 创建测试用的 PreconditionValidationData
        let blob_hash = IndexedBlobHash {
            index: 0,
            hash: b256!("1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef"),
        };

        let blob_request = BlobFetchRequest {
            block_ref: Default::default(),
            blob_hash,
        };

        let precondition_data = PreconditionValidationData::Validity {
            proposal_l2_head_number: 100,
            proposal_output_count: 50,
            output_block_span: 1,
            blob_hashes: vec![blob_request],
        };

        // 插入 PreconditionValidationData
        let data_hash = oracle.insert_precondition_validation_data(precondition_data.clone());

        // 验证插入后的预映像数量增加了
        assert_eq!(oracle.preimage_count(), 1);

        // 验证返回的哈希与期望的哈希一致
        let expected_hash = precondition_data.hash();
        assert_eq!(data_hash, expected_hash);

        // 通过 get_precondition_validation_data 方法读取
        let retrieved_data = oracle.get_precondition_validation_data(data_hash).await.unwrap();
        assert_eq!(retrieved_data, precondition_data);

        // 验证各字段是否正确
        match retrieved_data {
            PreconditionValidationData::Validity {
                proposal_l2_head_number,
                proposal_output_count,
                output_block_span,
                blob_hashes,
            } => {
                assert_eq!(proposal_l2_head_number, 100);
                assert_eq!(proposal_output_count, 50);
                assert_eq!(output_block_span, 1);
                assert_eq!(blob_hashes.len(), 1);
                assert_eq!(blob_hashes[0].blob_hash.hash, b256!("1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef"));
            }
        }
    }

    #[tokio::test]
    async fn test_salt_oracle_get_nonexistent_precondition_validation_data() {
        let oracle = SaltVecOracle::new();
        let non_existent_hash = b256!("ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff");

        // 尝试获取不存在的 PreconditionValidationData
        let result = oracle.get_precondition_validation_data(non_existent_hash).await;
        assert!(result.is_none());
    }

    #[tokio::test]
    async fn test_salt_oracle_get_zero_hash_precondition_validation_data() {
        let oracle = SaltVecOracle::new();
        let zero_hash = B256::ZERO;

        // 尝试获取零哈希的 PreconditionValidationData，应该直接返回 None
        let result = oracle.get_precondition_validation_data(zero_hash).await;
        assert!(result.is_none());
    }

    #[tokio::test]
    async fn test_salt_oracle_multiple_precondition_validation_data() {
        use crate::blobs::BlobFetchRequest;
        use alloy_eips::eip4844::IndexedBlobHash;
        use alloy_primitives::b256;

        let mut oracle = SaltVecOracle::new();

        // 创建第一个测试数据
        let blob_hash1 = IndexedBlobHash {
            index: 0,
            hash: b256!("1111111111111111111111111111111111111111111111111111111111111111"),
        };
        let blob_request1 = BlobFetchRequest {
            block_ref: Default::default(),
            blob_hash: blob_hash1,
        };
        let precondition_data1 = PreconditionValidationData::Validity {
            proposal_l2_head_number: 100,
            proposal_output_count: 50,
            output_block_span: 1,
            blob_hashes: vec![blob_request1],
        };

        // 创建第二个测试数据
        let blob_hash2 = IndexedBlobHash {
            index: 1,
            hash: b256!("2222222222222222222222222222222222222222222222222222222222222222"),
        };
        let blob_request2 = BlobFetchRequest {
            block_ref: Default::default(),
            blob_hash: blob_hash2,
        };
        let precondition_data2 = PreconditionValidationData::Validity {
            proposal_l2_head_number: 200,
            proposal_output_count: 75,
            output_block_span: 2,
            blob_hashes: vec![blob_request2],
        };

        // 插入两个 PreconditionValidationData
        let hash1 = oracle.insert_precondition_validation_data(precondition_data1.clone());
        let hash2 = oracle.insert_precondition_validation_data(precondition_data2.clone());

        // 验证插入后的预映像数量
        assert_eq!(oracle.preimage_count(), 2);

        // 验证两个哈希不同
        assert_ne!(hash1, hash2);

        // 验证可以分别获取
        let retrieved1 = oracle.get_precondition_validation_data(hash1).await.unwrap();
        let retrieved2 = oracle.get_precondition_validation_data(hash2).await.unwrap();

        assert_eq!(retrieved1, precondition_data1);
        assert_eq!(retrieved2, precondition_data2);
    }

    #[tokio::test]
    async fn test_salt_oracle_precondition_validation_data_serialization_roundtrip() {
        use crate::blobs::BlobFetchRequest;
        use alloy_eips::eip4844::IndexedBlobHash;
        use alloy_primitives::b256;

        let mut oracle = SaltVecOracle::new();

        // 创建复杂的测试数据（包含多个 blob）
        let blob_hashes = vec![
            BlobFetchRequest {
                block_ref: Default::default(),
                blob_hash: IndexedBlobHash {
                    index: 0,
                    hash: b256!("1111111111111111111111111111111111111111111111111111111111111111"),
                },
            },
            BlobFetchRequest {
                block_ref: Default::default(),
                blob_hash: IndexedBlobHash {
                    index: 1,
                    hash: b256!("2222222222222222222222222222222222222222222222222222222222222222"),
                },
            },
            BlobFetchRequest {
                block_ref: Default::default(),
                blob_hash: IndexedBlobHash {
                    index: 2,
                    hash: b256!("3333333333333333333333333333333333333333333333333333333333333333"),
                },
            },
        ];

        let original_data = PreconditionValidationData::Validity {
            proposal_l2_head_number: 12345,
            proposal_output_count: 999,
            output_block_span: 10,
            blob_hashes,
        };

        // 测试序列化和反序列化的往返过程
        let data_hash = oracle.insert_precondition_validation_data(original_data.clone());
        let retrieved_data = oracle.get_precondition_validation_data(data_hash).await.unwrap();

        // 验证所有字段都正确恢复
        assert_eq!(retrieved_data, original_data);

        // 验证哈希计算是否一致
        assert_eq!(data_hash, original_data.hash());
        assert_eq!(retrieved_data.hash(), original_data.hash());

        // 验证blob数量
        assert_eq!(retrieved_data.blob_fetch_requests().len(), 3);
    }

    #[test]
    fn test_salt_oracle_precondition_validation_data_deep_clone() {
        use crate::blobs::BlobFetchRequest;
        use alloy_eips::eip4844::IndexedBlobHash;
        use alloy_primitives::b256;

        let mut oracle = SaltVecOracle::new();

        let blob_request = BlobFetchRequest {
            block_ref: Default::default(),
            blob_hash: IndexedBlobHash {
                index: 0,
                hash: b256!("1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef"),
            },
        };

        let precondition_data = PreconditionValidationData::Validity {
            proposal_l2_head_number: 500,
            proposal_output_count: 100,
            output_block_span: 5,
            blob_hashes: vec![blob_request],
        };

        oracle.insert_precondition_validation_data(precondition_data.clone());

        // 深度克隆
        let cloned_oracle = oracle.deep_clone();
        assert_eq!(cloned_oracle.preimage_count(), 1);

        // 验证克隆的 oracle 包含相同的数据
        let data_hash = precondition_data.hash();
        tokio::runtime::Runtime::new().unwrap().block_on(async {
            let retrieved = cloned_oracle.get_precondition_validation_data(data_hash).await.unwrap();
            assert_eq!(retrieved, precondition_data);
        });
    }

    #[tokio::test]
    async fn test_salt_oracle_precondition_validation_data_with_empty_blobs() {
        let mut oracle = SaltVecOracle::new();

        // 创建没有blob的测试数据
        let precondition_data = PreconditionValidationData::Validity {
            proposal_l2_head_number: 1000,
            proposal_output_count: 10,
            output_block_span: 1,
            blob_hashes: vec![], // 空的blob列表
        };

        // 插入和获取
        let data_hash = oracle.insert_precondition_validation_data(precondition_data.clone());
        let retrieved_data = oracle.get_precondition_validation_data(data_hash).await.unwrap();

        assert_eq!(retrieved_data, precondition_data);
        assert_eq!(retrieved_data.blob_fetch_requests().len(), 0);
    }

    #[tokio::test]
    async fn test_insert_output_root()
    {
        let mut oracle = SaltVecOracle::default();
        let block_hash_8 = b256!("0xa7d0bd55513f156e75d1ca79016491f706650e0c479319552e8e1d730c3c6f1a");
        let block_hash_9 = b256!("0x3c803d2882fb3633a530ed64c5b040acb4809f6576fcee97caa9b03ef850bc1b");
        let block_hash_10 = b256!("0x2b762c29c8f0b4b199b481d4ed283d8a35718374ffb2ae03a09b6f204a24a89e");

        // 定义 state_root 和 withdrawal_storage_root
        let state_root_8 = b256!("0xd0ca14bbe5b2ccb6aec5d091966881ac40086b647222c2d660e90b2076dde100");
        let state_root_9 = b256!("0xfc3c9527cab0b157942567b795faa1b3fc734c394159a9822509ddcafcb03b00");
        let state_root_10 = b256!("0x36357858790f80080cd75266b7a427dcf77b073626a5eda9c6b933d736008702");
        let withdrawal_storage_root = b256!("0xfedcba0987654321fedcba0987654321fedcba0987654321fedcba0987654321");

        let expected_root_8 = b256!("0xe70fe3e0a79fa1de96425e10255d071cf7b3960a2eccef1b0c78a83fdb700e5e");
        let expected_root_9 = b256!("0xaec20092208f340960cca761a34d6527fea30b0c7613ed9dd0d6b0cd419c693d");
        let expected_root_10 = b256!("0x2b32c441a10764f60bb2dda473f29d8686af71c4c072bc7b78b461bc0f63c656");


        let computed_root_8 = oracle.insert_output_root(state_root_8, withdrawal_storage_root, block_hash_8);
        let computed_root_9 = oracle.insert_output_root(state_root_9, withdrawal_storage_root, block_hash_9);
        let computed_root_10 = oracle.insert_output_root(state_root_10, withdrawal_storage_root, block_hash_10);

        println!("insert output_root_key_8: {:?}", B256::from(computed_root_8));
        println!("insert output_root_key_9: {:?}", B256::from(computed_root_9));
        println!("insert output_root_key_10: {:?}", B256::from(computed_root_10));
        assert_eq!(expected_root_8, computed_root_8);
        assert_eq!(expected_root_9, computed_root_9);
        assert_eq!(expected_root_10, computed_root_10);
        let mut output_preimage = [0u8; 128];
        oracle.get_exact(
            PreimageKey::new_keccak256(*computed_root_8), // 构造Keccak256类型的预映像键
            output_preimage.as_mut(), // 写入预分配的128字节缓冲区
        ).await.expect("TODO: panic message");
        //println!("insert output_preimage: {:?}", output_preimage);
        println!(
            "insert output_preimage: {}",
            output_preimage.iter().map(|b| format!("{:02x}", b)).collect::<String>()
        );

    }

    #[tokio::test]
    async fn test_compute_output_root() {
        let oracle = SaltVecOracle::default();

        let withdrawal_storage_root = b256!("0xfedcba0987654321fedcba0987654321fedcba0987654321fedcba0987654321");
        let block_hash_8 = b256!("b3bda63a35f00b666dc7dcb3542ebd4d2755ecbbb97d5b5b312b57b5124658fc");//
        let block_hash_9 = b256!("f6e417d4f8dc0852f613d9292afd5f62323eb4779ef43d57f02840c322c3ff61");//
        let block_hash_10 = b256!("e2f5c2448f2b30e3e875ed95f9c161bd8c3d6f9cb027ee32bc3d9045462c446c");//
        let block_hash_11 = b256!("1d739b3e2bad7fd62709aefdd418749abf35de4fbb547396c89ccf6c2ad427a7");//
        // let block_hash_12 = b256!("0x0b48c8432fbe81b02317b6a85ef176679c57b0177b8766f03091703040a0526d");//

        let state_root_8 = b256!("0xd0ca14bbe5b2ccb6aec5d091966881ac40086b647222c2d660e90b2076dde100");
        let state_root_9 = b256!("0xfc3c9527cab0b157942567b795faa1b3fc734c394159a9822509ddcafcb03b00");
        let state_root_10 = b256!("0x36357858790f80080cd75266b7a427dcf77b073626a5eda9c6b933d736008702");
        let state_root_11 = b256!("0x040374769fe853f2ecd55b532250d5064d27754a980ed7443e7ba1a5f1f1f716");
        // let state_root_12 = b256!("0x6de97ad7bec8d27d75bdd7cda9bd23ce4e3dd81ec5ee8e409f60dde8afb80703");


        let computed_root_8 = oracle.compute_output_root(
            state_root_8,
            withdrawal_storage_root,
            block_hash_8,
        );
        let computed_root_9 = oracle.compute_output_root(
            state_root_9,
            withdrawal_storage_root,
            block_hash_9,
        );
        let computed_root_10 = oracle.compute_output_root(
            state_root_10,
            withdrawal_storage_root,
            block_hash_10,
        );
        let computed_root_11 = oracle.compute_output_root(
            state_root_11,
            withdrawal_storage_root,
            block_hash_11,
        );
        let expected_root_8 = b256!(
            "0x2a540cccd7e7a22715978c5d469362546b8293f128ac9dd876318493b31f53c6"
        );
        let expected_root_9 = b256!(
            "0xe9b072c417fd16c3f51dd72d000a8829671531aa31af66a147fe8a81fc5228f1"
        );
        let expected_root_10 = b256!(
            "0x6274117310ab5884ec0e76252500991634c331da7a9acdbe7d0e56210fd72302"
        );
        let expected_root_11 = b256!(
            "0xe60ea7c0e0364788784d4d10e0485e64235509574a2772a40bbaaadb95521d5f"
        );
        assert_eq!(computed_root_8, expected_root_8);
        assert_eq!(computed_root_9, expected_root_9);
        assert_eq!(computed_root_10, expected_root_10);
        assert_eq!(computed_root_11, expected_root_11);

    }
    #[tokio::test]
    async fn test_prepare_salt_vec_oracle_with_output_roots() {
        let mut oracle = prepare_salt_vec_oracle(8, 2);

        // 验证可以通过 output_root 检索到对应的 encoded 数据
        let state_root_8 = b256!("0xd0ca14bbe5b2ccb6aec5d091966881ac40086b647222c2d660e90b2076dde100");
        let withdrawal_storage_root = b256!("0xfedcba0987654321fedcba0987654321fedcba0987654321fedcba0987654321");
        let block_hash_8 = b256!("0xb3bda63a35f00b666dc7dcb3542ebd4d2755ecbbb97d5b5b312b57b5124658fc");
        let expected_root_8 = b256!(
            "0x2a540cccd7e7a22715978c5d469362546b8293f128ac9dd876318493b31f53c6"
        );


        let computed_root_8 = oracle.insert_output_root(state_root_8, withdrawal_storage_root, block_hash_8);
        let output_root_key_8 = PreimageKey::new(*computed_root_8, PreimageKeyType::Keccak256);
        assert_eq!(computed_root_8,expected_root_8);
        println!("computed_root_8: {:?}", computed_root_8);
        println!("output_root_key_8: {:?}", B256::from(output_root_key_8));

        let retrieved_value = oracle.get(output_root_key_8).await.unwrap();
        let mut output_preimage = [0u8; 128];
        oracle.get_exact(
            PreimageKey::new_keccak256(*computed_root_8), // 构造Keccak256类型的预映像键
            output_preimage.as_mut(), // 写入预分配的128字节缓冲区
        ).await.expect("TODO: panic message");
        println!("output_preimage: {:?}", output_preimage);
        assert_eq!(retrieved_value.len(), 128);

        // 验证 encoded 数据的正确性
        assert_eq!(retrieved_value[31], 0); // version_byte
        assert_eq!(&retrieved_value[32..64], state_root_8.as_slice());
        assert_eq!(&retrieved_value[64..96], withdrawal_storage_root.as_slice());
        assert_eq!(&retrieved_value[96..128], block_hash_8.as_slice());
    }
    #[tokio::test]
    async fn test_insert_and_load_l1_header() {
        let mut oracle = SaltVecOracle::new();

        // 创建测试用的 Header
        let test_header = Header {
            parent_hash: b256!("0x1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef"),
            ommers_hash: b256!("0x1dcc4de8dec75d7aab85b567b6ccd41ad312451b948a7413f0a142fd40d49347"),
            beneficiary: alloy_primitives::Address::from([0xab, 0xcd, 0xef, 0xab, 0xcd, 0xef, 0xab, 0xcd, 0xef, 0xab, 0xcd, 0xef, 0xab, 0xcd, 0xef, 0xab, 0xcd, 0xef, 0xab, 0xcd]),
            state_root: b256!("0x56e81f171bcc55a6ff8345e692c0f86e5b48e01b996cadc001622fb5e363b421"),
            transactions_root: b256!("0x56e81f171bcc55a6ff8345e692c0f86e5b48e01b996cadc001622fb5e363b421"),
            receipts_root: b256!("0x56e81f171bcc55a6ff8345e692c0f86e5b48e01b996cadc001622fb5e363b421"),
            logs_bloom: Default::default(),
            difficulty: U256::from(100),
            number: 100,
            gas_limit: 8000000,
            gas_used: 7500000,
            timestamp: 1640995200,
            extra_data: Default::default(),
            mix_hash: Default::default(),
            nonce: [0u8; 8].into(),
            base_fee_per_gas: Some(20000000000),
            withdrawals_root: Some(EMPTY_ROOT_HASH),
            blob_gas_used: Some(0),
            excess_blob_gas: Some(0),
            parent_beacon_block_root: Some(EMPTY_ROOT_HASH),
            requests_hash: None,
        };
        //l1_head: 0x73bf9ba5b181c8828220f33d1b06347a60a80e47a2d05da880b2e3f4d9d3368a

        // 测试插入
        let l1_head =oracle.insert_header(test_header.clone()).await;
        println!("l1_head: {:?}", B256::from(l1_head));

        // 测试加载
        let loaded_header = oracle.load_header(l1_head).await;
        assert!(loaded_header.is_some());

        let loaded_header = loaded_header.unwrap();
        assert_eq!(loaded_header.parent_hash, test_header.parent_hash);
        assert_eq!(loaded_header.number, test_header.number);
        assert_eq!(loaded_header.state_root, test_header.state_root);
        assert_eq!(loaded_header.gas_limit, test_header.gas_limit);
        assert_eq!(loaded_header.timestamp, test_header.timestamp);
        assert_eq!(loaded_header.base_fee_per_gas, test_header.base_fee_per_gas);
    }

    #[tokio::test]
    async fn test_load_nonexistent_l1_header() {
        let oracle = SaltVecOracle::new();

        let nonexistent_hash = b256!("0x0000000000000000000000000000000000000000000000000000000000000000");

        // 测试加载不存在的头
        let result = oracle.load_header(nonexistent_hash).await;
        assert!(result.is_none());
    }

    #[tokio::test]
    async fn test_multiple_l1_headers() {
        let mut oracle = SaltVecOracle::new();

        // 创建多个不同的 Header
        let header1 = Header {
            number: 100,
            timestamp: 1640995200,
            gas_limit: 8000000,
            base_fee_per_gas: Some(20000000000),
            withdrawals_root: Some(EMPTY_ROOT_HASH),
            ..Default::default()
        };

        let header2 = Header {
            number: 101,
            timestamp: 1640995300,
            gas_limit: 8100000,
            base_fee_per_gas: Some(21000000000),
            withdrawals_root: Some(EMPTY_ROOT_HASH),
            ..Default::default()
        };

        // 插入两个不同的头
        let l1_head1=oracle.insert_header(header1.clone()).await;
        let l1_head2=oracle.insert_header(header2.clone() ).await;

        // 验证能正确加载各自的头
        let loaded_header1 = oracle.load_header(l1_head1).await.unwrap();
        let loaded_header2 = oracle.load_header(l1_head2).await.unwrap();

        assert_eq!(loaded_header1.number, 100);
        assert_eq!(loaded_header2.number, 101);
        assert_ne!(loaded_header1.timestamp, loaded_header2.timestamp);
    }
    #[tokio::test]
    async fn test_load_file_insert_transaction() {
        let mut oracle = SaltVecOracle::new();

        // 测试加载区块 8 的交易数据
        let block_number = 8;
        let block_hash = b256!("0xfa5a973957d70f5433ffc6564fa9361b3f0cd98fc0dd9fca79b97c5c6f3314be");

        // 调用 load_file_insert_transaction 方法
        let result = oracle.load_file_insert_transaction(block_number, block_hash);
        //assert!(result.is_ok(), "Failed to load transactions: {:?}", result);
        //
        // let transactions_root = result.unwrap();
        // let expected_transactions_root = b256!("0x4b5afecbbfd21b10e5c41f603092aee09ab69b51548dc3be0bec6ca51ca27245");
        // assert_eq!(transactions_root, expected_transactions_root);
        //
        // // 验证预映像数量增加了（应该包含交易数据的 trie 节点）
        // assert!(oracle.preimage_count() > 0, "Oracle should contain transaction trie data");
        //
        // println!("Successfully loaded {} transactions from block {}", 1, block_number);
        // println!("Transactions root: {:?}", transactions_root);
        // println!("Total preimages stored: {}", oracle.preimage_count());
    }
}

