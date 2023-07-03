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

//! Dynamic memory allocation.

use buddy_system_allocator::LockedHeap;

use crate::config::HvSystemConfig;
use crate::consts::{HV_BASE, PER_CPU_SIZE};
use crate::header::HvHeader;
use crate::memory::addr::{align_up, is_aligned, virt_to_phys};
use crate::memory::HostVirtAddr;

#[cfg_attr(not(test), global_allocator)]
static HEAP_ALLOCATOR: LockedHeap = LockedHeap::new();

/// Initialize the global heap allocator.
pub(super) fn init() {
    unsafe {
        HEAP_ALLOCATOR
            .lock()
            .init(*HV_HEAP_START_HVA, *HV_HEAP_SIZE);
    }
    info!(
        "Finish heap allocator init, va range: {:#x?}, pa range: {:#x?}",
        *HV_HEAP_START_HVA..*HV_HEAP_START_HVA + *HV_HEAP_SIZE,
        virt_to_phys(*HV_HEAP_START_HVA)..virt_to_phys(*HV_HEAP_START_HVA + *HV_HEAP_SIZE)
    );
}

lazy_static! {
    pub static ref HV_HEAP_START_HVA: HostVirtAddr = {
        let header = HvHeader::get();
        let sys_config = HvSystemConfig::get();
        align_up(
            HV_BASE as usize
                + header.core_size as usize
                + header.max_cpus as usize * PER_CPU_SIZE
                + sys_config.size(),
        )
    };
    pub static ref HV_HEAP_SIZE: usize = {
        let hv_heap_size = HvHeader::get().hv_heap_size;
        if !is_aligned(hv_heap_size) {
            error!(
                "heap size {:#x?} in Hypervisor Header is not 4kB align, enforce alignment",
                hv_heap_size
            );
        }
        hv_heap_size
    };
}
