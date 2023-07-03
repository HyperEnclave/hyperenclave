// Copyright (C) 2023 Ant Group CO., Ltd. All rights reserved.
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

use core::mem::size_of;

use sha2::{Digest, Sha256};

use crate::enclave::sgx::SgxSecInfo;
use crate::memory::PAGE_SIZE;

#[derive(Copy, Clone, Debug, PartialEq, Eq, Ord, PartialOrd)]
enum State {
    None,
    Started,
    Update,
    Finished,
}

#[derive(Clone, Debug)]
pub struct Measure {
    state: State,
    hasher: Sha256,
}

impl Measure {
    const DATA_BLOCK_SIZE: usize = 64;
    const SIZE_NAMED_VALUE: usize = 8;

    pub fn new() -> Self {
        Self {
            state: State::None,
            hasher: Sha256::new(),
        }
    }

    pub fn start(&mut self, enclave_size: u64, ssa_frame_size: u32) {
        let ecreate_val = "ECREATE";
        let mut data_block = vec![0; Self::DATA_BLOCK_SIZE];
        let mut offset = 0;

        data_block[..ecreate_val.len()].clone_from_slice(ecreate_val.as_bytes());
        offset += Self::SIZE_NAMED_VALUE;
        data_block[offset..(offset + size_of::<u32>())]
            .clone_from_slice(&ssa_frame_size.to_ne_bytes());
        offset += size_of::<u32>();
        data_block[offset..(offset + size_of::<u64>())]
            .clone_from_slice(&enclave_size.to_ne_bytes());

        self.hasher.update(data_block.as_slice());
        self.state = State::Started;
    }

    pub fn update(
        &mut self,
        page_offset: u64,
        page_info: SgxSecInfo,
        page_data: Option<&[u8; PAGE_SIZE]>,
    ) {
        const EEXTEND_TIME: usize = 4;

        let eadd_val = "EADD";
        let mut data_block = vec![0; Self::DATA_BLOCK_SIZE];
        let mut offset = 0;

        data_block[..eadd_val.len()].clone_from_slice(eadd_val.as_bytes());
        offset += Self::SIZE_NAMED_VALUE;
        data_block[offset..(offset + size_of::<u64>())]
            .clone_from_slice(&page_offset.to_ne_bytes());
        offset += size_of::<u64>();
        data_block[offset..(offset + size_of::<u64>())]
            .clone_from_slice(&Into::<u64>::into(page_info).to_ne_bytes());

        self.hasher.update(data_block.as_slice());

        if let Some(page_data) = page_data {
            let eextend_val = "EEXTEND";
            let mut start = 0;
            let mut page_offset = page_offset;

            for _ in (0..PAGE_SIZE).step_by(Self::DATA_BLOCK_SIZE * EEXTEND_TIME) {
                offset = 0;
                data_block = vec![0; Self::DATA_BLOCK_SIZE];
                data_block[..eextend_val.len()].clone_from_slice(eextend_val.as_bytes());
                offset += Self::SIZE_NAMED_VALUE;
                data_block[offset..(offset + size_of::<u64>())]
                    .clone_from_slice(&page_offset.to_ne_bytes());

                self.hasher.update(data_block.as_slice());

                (0..EEXTEND_TIME).for_each(|_| {
                    self.hasher
                        .update(&page_data[start..(start + Self::DATA_BLOCK_SIZE)]);
                    start += Self::DATA_BLOCK_SIZE;
                    page_offset += Self::DATA_BLOCK_SIZE as u64;
                });
            }
        }
        self.state = State::Update;
    }

    pub fn finish(&mut self, output: &mut [u8]) {
        let hash = self.hasher.finalize_reset();
        output.clone_from_slice(hash.as_slice());
        self.state = State::Finished;
    }
}
