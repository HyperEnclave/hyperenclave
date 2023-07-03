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

use core::fmt::{Debug, Formatter, Result};

use x86_64::{
    addr::{PhysAddr as X86PhysAddr, VirtAddr as X86VirtAddr},
    instructions::tlb,
    registers::control::{Cr3, Cr3Flags},
    structures::paging::page_table::PageTableFlags as PTF,
    structures::paging::PhysFrame,
};

use crate::memory::PagingResult;
use crate::memory::{GenericPTE, MemFlags, PageTableLevel, PagingInstr, PhysAddr, VirtAddr};
use crate::memory::{Level4PageTable, Level4PageTableImmut, Level4PageTableUnlocked};

impl From<MemFlags> for PTF {
    fn from(f: MemFlags) -> Self {
        if f.is_empty() {
            return Self::empty();
        }
        let mut ret = Self::empty();
        if !f.contains(MemFlags::NO_PRESENT) {
            ret |= Self::PRESENT;
        }
        if f.contains(MemFlags::WRITE) {
            ret |= Self::WRITABLE;
        }
        if !f.contains(MemFlags::EXECUTE) {
            ret |= Self::NO_EXECUTE;
        }
        if f.contains(MemFlags::USER) {
            ret |= Self::USER_ACCESSIBLE;
        }
        ret
    }
}

impl From<PTF> for MemFlags {
    fn from(f: PTF) -> Self {
        if f.is_empty() {
            return Self::empty();
        }
        let mut ret = Self::READ;
        if !f.contains(PTF::PRESENT) {
            ret |= Self::NO_PRESENT;
        }
        if f.contains(PTF::WRITABLE) {
            ret |= Self::WRITE;
        }
        if !f.contains(PTF::NO_EXECUTE) {
            ret |= Self::EXECUTE;
        }
        if f.contains(PTF::USER_ACCESSIBLE) {
            ret |= Self::USER;
        }
        ret
    }
}

const PHYS_ADDR_MASK: u64 = 0x000f_ffff_ffff_f000; // 12..52

#[derive(Clone)]
pub struct PTEntry(u64);

impl GenericPTE for PTEntry {
    fn addr(&self) -> PhysAddr {
        (self.0 & PHYS_ADDR_MASK) as _
    }
    fn flags(&self) -> MemFlags {
        PTF::from_bits_truncate(self.0).into()
    }
    fn is_unused(&self) -> bool {
        self.0 == 0
    }
    fn is_present(&self) -> bool {
        PTF::from_bits_truncate(self.0).contains(PTF::PRESENT)
    }
    fn is_leaf(&self) -> bool {
        PTF::from_bits_truncate(self.0).contains(PTF::HUGE_PAGE)
    }
    fn is_young(&self) -> bool {
        PTF::from_bits_truncate(self.0).contains(PTF::ACCESSED)
    }
    fn set_old(&mut self) {
        let flags: PTF = !PTF::ACCESSED;
        self.0 &= flags.bits() | PHYS_ADDR_MASK;
    }
    fn set_addr(&mut self, paddr: PhysAddr) {
        self.0 = (self.0 & !PHYS_ADDR_MASK) | (paddr as u64 & PHYS_ADDR_MASK);
    }
    fn set_flags(&mut self, flags: MemFlags, is_huge: bool) -> PagingResult {
        let mut flags = PTF::from(flags);
        if is_huge {
            flags |= PTF::HUGE_PAGE;
        }
        self.0 = self.addr() as u64 | flags.bits();
        Ok(())
    }
    fn set_table(
        &mut self,
        paddr: PhysAddr,
        _next_level: PageTableLevel,
        is_present: bool,
    ) -> PagingResult {
        let mut flags = PTF::WRITABLE | PTF::USER_ACCESSIBLE;
        if is_present {
            flags |= PTF::PRESENT;
        }
        self.0 = (paddr as u64 & PHYS_ADDR_MASK) | flags.bits();
        Ok(())
    }
    fn set_present(&mut self) -> PagingResult {
        self.0 |= PTF::PRESENT.bits();
        Ok(())
    }
    fn set_notpresent(&mut self) -> PagingResult {
        let mut flags = PTF::from_bits_truncate(self.0);
        flags -= PTF::PRESENT;
        self.0 = self.addr() as u64 | flags.bits();
        Ok(())
    }
    fn clear(&mut self) {
        self.0 = 0
    }
}

impl Debug for PTEntry {
    fn fmt(&self, f: &mut Formatter) -> Result {
        let mut f = f.debug_struct("PTEntry");
        f.field("raw", &self.0);
        f.field("addr", &self.addr());
        f.field("flags", &self.flags());
        f.finish()
    }
}

pub struct X86PagingInstr;

impl PagingInstr for X86PagingInstr {
    unsafe fn activate(root_paddr: PhysAddr) {
        Cr3::write(
            PhysFrame::containing_address(X86PhysAddr::new(root_paddr as u64)),
            Cr3Flags::empty(),
        );
    }

    fn flush(vaddr: Option<usize>) {
        if let Some(vaddr) = vaddr {
            tlb::flush(X86VirtAddr::new(vaddr as u64))
        } else {
            tlb::flush_all()
        }
    }
}

pub type PageTable = Level4PageTable<VirtAddr, PTEntry, X86PagingInstr>;
pub type EnclaveGuestPageTableUnlocked = Level4PageTableUnlocked<VirtAddr, PTEntry, X86PagingInstr>;
pub type PageTableImmut = Level4PageTableImmut<VirtAddr, PTEntry>;
