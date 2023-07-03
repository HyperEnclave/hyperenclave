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

use crate::arch::page_table::PTEntry;
use crate::memory::addr::{GuestPhysAddr, HostPhysAddr};
use crate::memory::{
    EmptyPagingInstr, GenericPTE, Level4PageTable, Level4PageTableUnlocked, MemFlags,
    PageTableLevel, PagingResult,
};

#[repr(transparent)]
#[derive(Clone, Debug)]
pub struct NPTEntry(PTEntry);

impl GenericPTE for NPTEntry {
    fn addr(&self) -> HostPhysAddr {
        self.0.addr()
    }
    fn flags(&self) -> MemFlags {
        self.0.flags()
    }
    fn is_unused(&self) -> bool {
        self.0.is_unused()
    }
    fn is_present(&self) -> bool {
        self.0.is_present()
    }
    fn is_leaf(&self) -> bool {
        self.0.is_leaf()
    }
    fn is_young(&self) -> bool {
        self.0.is_young()
    }
    fn set_old(&mut self) {
        self.0.set_old()
    }
    fn set_addr(&mut self, paddr: HostPhysAddr) {
        self.0.set_addr(paddr);
    }
    fn set_present(&mut self) -> PagingResult {
        self.0.set_present()
    }
    fn set_notpresent(&mut self) -> PagingResult {
        self.0.set_notpresent()
    }
    fn set_flags(&mut self, flags: MemFlags, is_huge: bool) -> PagingResult {
        // See APMv2, Section 15.25.5:
        // A table walk for the guest page itself is always treated as a user
        // access at the nested page table level.
        self.0.set_flags(flags | MemFlags::USER, is_huge)
    }
    fn set_table(
        &mut self,
        paddr: HostPhysAddr,
        next_level: PageTableLevel,
        is_present: bool,
    ) -> PagingResult {
        self.0.set_table(paddr, next_level, is_present)
    }
    fn clear(&mut self) {
        self.0.clear()
    }
}

pub type NestedPageTable = Level4PageTable<GuestPhysAddr, NPTEntry, EmptyPagingInstr>;
pub type EnclaveNestedPageTableUnlocked =
    Level4PageTableUnlocked<GuestPhysAddr, NPTEntry, EmptyPagingInstr>;
