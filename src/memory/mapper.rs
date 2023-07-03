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

use super::addr::{align_down, phys_encrypted, virt_to_phys};
use super::{AlignedPage2M, MemFlags, MemoryRegion, PhysAddr};

static EMPTY_PAGE: AlignedPage2M = AlignedPage2M::new();

#[derive(Clone, Debug)]
pub(super) enum Mapper {
    Offset(usize),
    Fixed(usize),
}

impl Mapper {
    pub fn map_fn<VA: Into<usize>>(&self, vaddr: VA) -> PhysAddr {
        match self {
            Self::Offset(ref off) => vaddr.into() - *off,
            Self::Fixed(ref paddr) => *paddr,
        }
    }
}

impl<VA: From<usize> + Into<usize> + Copy> MemoryRegion<VA> {
    pub fn new_with_empty_mapper(start: VA, size: usize, flags: MemFlags) -> Self {
        let mut paddr = virt_to_phys(EMPTY_PAGE.as_ptr() as usize);
        if flags.contains(MemFlags::ENCRYPTED) {
            paddr = phys_encrypted(paddr);
        }
        Self::new(start, size, flags, Mapper::Fixed(paddr))
    }

    pub fn new_with_offset_mapper(
        start_vaddr: VA,
        start_paddr: PhysAddr,
        size: usize,
        flags: MemFlags,
    ) -> Self {
        let start_vaddr = align_down(start_vaddr.into());
        let mut start_paddr = align_down(start_paddr);
        if flags.contains(MemFlags::ENCRYPTED) {
            start_paddr = phys_encrypted(start_paddr);
        }
        let phys_virt_offset = start_vaddr - start_paddr;
        Self::new(
            start_vaddr.into(),
            size,
            flags,
            Mapper::Offset(phys_virt_offset),
        )
    }
}
