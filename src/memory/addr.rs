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

//! Definition of phyical and virtual addresses.

#![allow(dead_code)]

use crate::consts::{HV_BASE, PAGE_SIZE, SME_C_BIT_OFFSET};

pub type VirtAddr = usize;
pub type PhysAddr = usize;

pub type GuestVirtAddr = usize;
pub type GuestPhysAddr = usize;

pub type HostVirtAddr = VirtAddr;
pub type HostPhysAddr = PhysAddr;

lazy_static! {
    static ref PHYS_VIRT_OFFSET: usize = HV_BASE
        - crate::config::HvSystemConfig::get()
            .hypervisor_memory
            .phys_start as usize;
}

pub fn phys_encrypted(paddr: PhysAddr) -> PhysAddr {
    paddr | SME_C_BIT_OFFSET
}

pub fn virt_to_phys(vaddr: VirtAddr) -> PhysAddr {
    vaddr - *PHYS_VIRT_OFFSET
}

pub fn phys_to_virt(paddr: PhysAddr) -> VirtAddr {
    (paddr & (SME_C_BIT_OFFSET.wrapping_sub(1))) + *PHYS_VIRT_OFFSET
}

pub const fn align_down(addr: usize) -> usize {
    addr & !(PAGE_SIZE - 1)
}

pub const fn align_up(addr: usize) -> usize {
    (addr + PAGE_SIZE - 1) & !(PAGE_SIZE - 1)
}

pub const fn is_aligned(addr: usize) -> bool {
    page_offset(addr) == 0
}

pub const fn page_count(size: usize) -> usize {
    align_up(size) / PAGE_SIZE
}

pub const fn page_offset(addr: usize) -> usize {
    addr & (PAGE_SIZE - 1)
}
