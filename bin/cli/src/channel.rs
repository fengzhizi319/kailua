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

use tokio::sync::mpsc::{channel, Receiver, Sender};

/// A channel for two-way communication
#[derive(Debug)]
pub struct DuplexChannel<T> {
    /// Messages coming in
    pub receiver: Receiver<T>,
    /// Messages going out
    pub sender: Sender<T>,
}

impl<T> DuplexChannel<T> {
    /// Returns a pair of duplex channel instances, one for each endpoint
    /// 创建一对互联的双向通道
    /// channel_0.sender  --> pair_0 --> channel_1.receiver
    ///channel_1.sender  --> pair_1 --> channel_0.receiver
    pub fn new_pair(buffer: usize) -> (Self, Self) {
        // 创建两个独立的MPSC通道对
        let pair_0 = channel(buffer); // (sender0, receiver0)
        let pair_1 = channel(buffer); // (sender1, receiver1)
        
        // 构建第一个通道端点：
        // - 发送使用pair0的发送端
        // - 接收使用pair1的接收端
        let channel_0 = Self {
            receiver: pair_1.1,  // 接收来自channel_1的消息
            sender: pair_0.0,    // 发送到channel_1的接收端
        };
        
        // 构建第二个通道端点：
        // - 发送使用pair1的发送端 
        // - 接收使用pair0的接收端
        let channel_1 = Self {
            receiver: pair_0.1,  // 接收来自channel_0的消息
            sender: pair_1.0,    // 发送到channel_0的接收端
        };
        
        (channel_0, channel_1)
    }

}
