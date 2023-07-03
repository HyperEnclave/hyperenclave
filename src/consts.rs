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

pub use crate::memory::PAGE_SIZE;
pub use crate::percpu::PER_CPU_SIZE;

pub const HV_BASE: usize = 0xffff_ff00_0000_0000;

pub const TEMP_MAPPING_BASE: usize = 0xffff_f000_0000_0000;
pub const NUM_TEMP_PAGES: usize = 16;
pub const LOCAL_PER_CPU_BASE: usize = TEMP_MAPPING_BASE + NUM_TEMP_PAGES * PAGE_SIZE;

#[cfg(feature = "sme")]
pub const SME_C_BIT_OFFSET: usize = 1 << 47;
#[cfg(not(feature = "sme"))]
pub const SME_C_BIT_OFFSET: usize = 0;

pub const HV_STACK_SIZE: usize = 512 * 1024; // 512 KB
