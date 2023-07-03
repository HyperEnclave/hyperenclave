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

pub mod addr;
pub mod cmr;
mod frame;
pub mod gaccess;
mod heap;
mod mapper;
mod mm;
mod mmio;
mod paging;

use crate::cell::ROOT_CELL;
use crate::error::HvResult;
use core::ops::{Deref, DerefMut};

use bitflags::bitflags;

pub use addr::{GuestPhysAddr, GuestVirtAddr, HostPhysAddr, HostVirtAddr, PhysAddr, VirtAddr};
pub use frame::Frame;
pub use heap::{HV_HEAP_SIZE, HV_HEAP_START_HVA};
pub use mm::{MemoryRegion, MemorySet};
pub use mmio::Mmio;
pub use paging::{EmptyPagingInstr, GenericPTE, PageSize, PageTableLevel, PagingInstr};
pub use paging::{
    GenericPageTable, GenericPageTableImmut, GenericPageTableMut, Level4PageTable,
    Level4PageTableImmut, Level4PageTableUnlocked,
};
pub use paging::{PagingError, PagingResult};

pub const PAGE_SIZE: usize = paging::PageSize::Size4K as usize;

bitflags! {
    pub struct MemFlags: u64 {
        const READ          = 1 << 0;
        const WRITE         = 1 << 1;
        const EXECUTE       = 1 << 2;
        const DMA           = 1 << 3;
        const IO            = 1 << 4;
        const COMM_REGION   = 1 << 5;
        const NO_HUGEPAGES  = 1 << 8;
        const USER          = 1 << 9;
        const ENCRYPTED     = 1 << 10;
        const NO_PRESENT    = 1 << 11;
    }
}

#[repr(align(4096))]
pub struct AlignedPage([u8; PAGE_SIZE]);

impl AlignedPage {
    #![allow(dead_code)]
    pub const fn new() -> Self {
        Self([0; PAGE_SIZE])
    }
}

impl Deref for AlignedPage {
    type Target = [u8; PAGE_SIZE];

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl DerefMut for AlignedPage {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.0
    }
}

#[repr(align(2097152))]
pub struct AlignedPage2M([u8; PAGE_SIZE * 512]);

impl AlignedPage2M {
    pub const fn new() -> Self {
        Self([0; PAGE_SIZE * 512])
    }
}

impl Deref for AlignedPage2M {
    type Target = [u8; PAGE_SIZE * 512];

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl DerefMut for AlignedPage2M {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.0
    }
}

pub fn init() -> HvResult {
    heap::init();
    cmr::init()?;
    frame::init();
    Ok(())
}

pub fn is_normal_memory(start: PhysAddr, size: usize) -> HvResult {
    for pa in (start..start + size).step_by(PAGE_SIZE) {
        let (_, npt_flags, _) = ROOT_CELL.gpm.page_table().query(pa)?;
        if !npt_flags.contains(MemFlags::READ | MemFlags::WRITE) {
            return hv_result_err!(EINVAL, "invalid page permission");
        }
    }

    Ok(())
}
