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

use crate::oracle::{needs_validation, validate_preimage};
use crate::rkyv::vec::PreimageVecStoreRkyv;
use crate::witness::WitnessOracle;
use alloy_primitives::map::HashMap;
use anyhow::bail;
use async_trait::async_trait;
use kona_preimage::errors::PreimageOracleResult;
use kona_preimage::{HintWriterClient, PreimageKey, PreimageOracleClient};
use kona_proof::FlushableCache;
use lazy_static::lazy_static;
use risc0_zkvm::guest::env;
use rkyv::rancor::Error;
use std::collections::VecDeque;
use std::ops::{Deref, DerefMut};
use std::sync::{Arc, Mutex};
use tracing::{info, warn};

pub type IndexedPreimage = (PreimageKey, Vec<u8>, Option<(usize, usize)>);
pub type PreimageVecEntry = Vec<IndexedPreimage>;
pub type PreimageVecStore = Arc<Mutex<Vec<PreimageVecEntry>>>;

#[derive(Clone, Debug, Default, rkyv::Serialize, rkyv::Archive, rkyv::Deserialize)]
pub struct VecOracle {
    #[rkyv(with = PreimageVecStoreRkyv)]
    pub preimages: PreimageVecStore,
}

impl VecOracle {
    pub fn deep_clone(&self) -> Self {
        let mut cloned_with_arc = self.clone();
        cloned_with_arc.preimages = Arc::new(Mutex::new(self.preimages.lock().unwrap().clone()));
        cloned_with_arc
    }

    pub fn validate(preimages: &[PreimageVecEntry]) -> anyhow::Result<()> {
        for (e, entry) in preimages.iter().enumerate() {
            for (p, (key, value, prev)) in entry.iter().enumerate() {
                if !needs_validation(&key.key_type()) {
                    continue;
                } else if let Some((i, j)) = prev {
                    if e < *i {
                        bail!("Attempted to validate preimage against future vec entry.");
                    } else if e == *i && p <= *j {
                        bail!(
                            "Attempted to validate preimage against future preimage in vec entry."
                        );
                    } else if key != &preimages[*i][*j].0 {
                        bail!("Cached preimage key comparison failed");
                    } else if value != &preimages[*i][*j].1 {
                        bail!("Cached preimage value comparison failed");
                    } else {
                        continue;
                    }
                }
                validate_preimage(key, value)?;
            }
        }
        Ok(())
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

    fn insert_preimage(&mut self, key: PreimageKey, value: Vec<u8>) {
        validate_preimage(&key, &value).expect("Attempted to save invalid preimage");
        let mut preimages = self.preimages.lock().unwrap();
        if preimages.is_empty() {
            preimages.push(Vec::new());
        }
        preimages.last_mut().unwrap().push((key, value, None));
    }

    /// 对预映像数据进行最终处理，包括验证、扁平化、排序、分片以及添加验证指针。
    ///
    /// # 参数
    /// - `shard_size`: 每个数据分片的最大大小，单位为字节。
    /// - `with_validation_ptrs`: 一个布尔值，指示是否需要为预映像数据添加验证指针。
    fn finalize_preimages(&mut self, shard_size: usize, with_validation_ptrs: bool) {
        // 在最终处理前验证预映像数据，若验证失败则触发 panic
        self.validate_preimages()
            .expect("Failed to validate preimages during finalization");
        // 获取预映像数据的可变引用
        let mut preimages = self.preimages.lock().unwrap();
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
            if value.1.len() + last_shard_size > shard_size {
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

pub type PreimageQueue = VecDeque<IndexedPreimage>;

lazy_static! {
    static ref QUEUE: Arc<Mutex<PreimageQueue>> = Default::default();
}

#[async_trait]
impl PreimageOracleClient for VecOracle {
    async fn get(&self, key: PreimageKey) -> PreimageOracleResult<Vec<u8>> {
        let mut preimages = self.preimages.lock().unwrap();
        let mut queue = QUEUE.lock().unwrap();
        // handle variations in memory access operations due to hashmap usages
        loop {
            if preimages.is_empty() {
                #[cfg(target_os = "zkvm")]
                {
                    crate::client::log("DESERIALIZE STREAMED SHARD");
                    preimages.push(read_shard());
                    Self::validate(preimages.as_ref())
                        .expect("Failed to validate streamed preimages");
                    crate::client::log("STREAMED SHARD VALIDATED");
                }
                #[cfg(not(target_os = "zkvm"))]
                panic!(
                    "Exhausted VecOracle seeking {key} ({} queued preimages)",
                    queue.len()
                )
            }

            let entry = preimages.last_mut().unwrap();
            loop {
                let Some((last_key, value, _)) = entry.pop() else {
                    break;
                };

                if key == last_key {
                    if !queue.is_empty() {
                        warn!("VecOracle temp queue has {} elements", queue.len());
                        entry.extend(core::mem::take(queue.deref_mut()));
                    }

                    return Ok(value);
                }
                // keep entry in queue for later use, pointer is no longer necessary
                queue.push_front((last_key, value, None));
            }
            preimages.pop();
        }
    }

    async fn get_exact(&self, key: PreimageKey, buf: &mut [u8]) -> PreimageOracleResult<()> {
        let value = self.get(key).await?;
        buf.copy_from_slice(value.as_ref());
        Ok(())
    }
}

#[async_trait]
impl HintWriterClient for VecOracle {
    async fn write(&self, _hint: &str) -> PreimageOracleResult<()> {
        Ok(())
    }
}

pub fn read_shard() -> PreimageVecEntry {
    let shard_data = env::read_frame();
    rkyv::from_bytes::<PreimageVecEntry, Error>(&shard_data).expect("Failed to deserialize shard")
}
