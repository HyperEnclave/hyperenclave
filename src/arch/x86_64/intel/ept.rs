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

use core::{convert::TryFrom, fmt};

use bit_field::BitField;
use bitflags::bitflags;
use numeric_enum_macro::numeric_enum;

use libvmm::msr::Msr;
use libvmm::vmx::flags::{EptpFlags, InvEptType, VmxEptVpidCap};

use crate::error::HvResult;
use crate::memory::addr::{GuestPhysAddr, HostPhysAddr};
use crate::memory::{
    GenericPTE, Level4PageTable, Level4PageTableUnlocked, MemFlags, PageTableLevel, PagingInstr,
};
use crate::memory::{PagingError, PagingResult};

bitflags! {
    struct EPTFlags: u64 {
        /// Read access.
        const READ =                1 << 0;
        /// Write access.
        const WRITE =               1 << 1;
        /// execute access.
        const EXECUTE =             1 << 2;
        /// Ignore PAT memory type
        const IGNORE_PAT =          1 << 6;
        /// Specifies that the entry maps a huge frame instead of a page table. Only allowed in
        /// P2 or P3 tables.
        const HUGE_PAGE =           1 << 7;
        /// If bit 6 of EPTP is 1, accessed flag for EPT.
        const ACCESSED =            1 << 8;
        /// If bit 6 of EPTP is 1, dirty flag for EPT;
        const DIRTY =               1 << 9;
        /// Execute access for user-mode linear addresses.
        const EXECUTE_FOR_USER =    1 << 10;
    }
}

numeric_enum! {
    #[repr(u8)]
    #[derive(Debug, PartialEq, Clone, Copy)]
    enum EPTMemType {
        Uncached = 0,
        WriteCombining = 1,
        WriteThrough = 4,
        WriteProtected = 5,
        WriteBack = 6,
    }
}

#[derive(Clone)]
pub struct EPTEntry(u64);

impl TryFrom<MemFlags> for EPTFlags {
    type Error = PagingError;

    fn try_from(f: MemFlags) -> PagingResult<Self> {
        if f.is_empty() {
            return Ok(Self::empty());
        }
        let mut ret = Self::empty();
        if f.contains(MemFlags::NO_PRESENT)
            && (f.contains(MemFlags::READ)
                || f.contains(MemFlags::WRITE)
                || f.contains(MemFlags::EXECUTE))
        {
            error!("If the EPT-E is non-present, it cannot be R or W or E.");
            return Err(PagingError::UnexpectedError);
        }
        if f.contains(MemFlags::READ) {
            ret |= Self::READ;
        }
        if f.contains(MemFlags::WRITE) {
            ret |= Self::WRITE;
        }
        if f.contains(MemFlags::EXECUTE) {
            ret |= Self::EXECUTE;
        }
        Ok(ret)
    }
}

impl From<EPTFlags> for MemFlags {
    fn from(f: EPTFlags) -> Self {
        if !f.contains(EPTFlags::READ)
            && !f.contains(EPTFlags::WRITE)
            && !f.contains(EPTFlags::EXECUTE)
        {
            return MemFlags::NO_PRESENT;
        }
        let mut ret = MemFlags::empty();
        if f.contains(EPTFlags::READ) {
            ret |= Self::READ;
        }
        if f.contains(EPTFlags::WRITE) {
            ret |= Self::WRITE;
        }
        if f.contains(EPTFlags::EXECUTE) {
            ret |= Self::EXECUTE;
        }
        ret
    }
}

impl EPTMemType {
    fn empty() -> Self {
        Self::try_from(0).unwrap()
    }
}

impl GenericPTE for EPTEntry {
    fn addr(&self) -> HostPhysAddr {
        (self.0.get_bits(12..52) << 12) as usize
    }
    fn flags(&self) -> MemFlags {
        self.ept_flags().into()
    }
    fn is_unused(&self) -> bool {
        self.0 == 0
    }
    fn is_present(&self) -> bool {
        self.0.get_bits(0..3) != 0
    }
    fn is_leaf(&self) -> bool {
        self.ept_flags().contains(EPTFlags::HUGE_PAGE)
    }
    fn is_young(&self) -> bool {
        self.ept_flags().contains(EPTFlags::ACCESSED)
    }

    fn set_old(&mut self) {
        let mem_type = self
            .memory_type()
            .map_err(|e| error!("Invalid mem_type: {:?}", e))
            .unwrap_or(EPTMemType::empty());
        let mut flags = self.ept_flags();
        flags -= EPTFlags::ACCESSED;
        self.set_flags_and_mem_type(flags, mem_type);
    }
    fn set_addr(&mut self, paddr: HostPhysAddr) {
        self.0.set_bits(12..52, paddr as u64 >> 12);
    }
    fn set_flags(&mut self, flags: MemFlags, is_huge: bool) -> PagingResult {
        let mut flags = EPTFlags::try_from(flags)?;
        if is_huge {
            flags |= EPTFlags::HUGE_PAGE;
        }
        self.set_flags_and_mem_type(flags, EPTMemType::WriteBack);
        Ok(())
    }
    fn set_table(
        &mut self,
        paddr: HostPhysAddr,
        _next_level: PageTableLevel,
        is_present: bool,
    ) -> PagingResult {
        if !is_present {
            error!("Illegal to set present for EPT intermediate entry");
            return Err(PagingError::UnexpectedError);
        }
        self.set_addr(paddr);
        self.set_flags_and_mem_type(
            EPTFlags::READ | EPTFlags::WRITE | EPTFlags::EXECUTE,
            EPTMemType::empty(),
        );
        Ok(())
    }
    fn set_present(&mut self) -> PagingResult {
        error!("Illegal to set present for EPT-E");
        Err(PagingError::UnexpectedError)
    }
    fn set_notpresent(&mut self) -> PagingResult {
        error!("Illegal to set not-present for EPT-E");
        Err(PagingError::UnexpectedError)
    }
    fn clear(&mut self) {
        self.0 = 0
    }
}

impl EPTEntry {
    fn ept_flags(&self) -> EPTFlags {
        EPTFlags::from_bits_truncate(self.0)
    }
    fn memory_type(&self) -> Result<EPTMemType, u8> {
        EPTMemType::try_from(self.0.get_bits(3..6) as u8)
    }
    fn set_flags_and_mem_type(&mut self, flags: EPTFlags, mem_type: EPTMemType) {
        self.0.set_bits(0..12, flags.bits());
        self.0.set_bits(3..6, mem_type as u64);
    }
}

impl fmt::Debug for EPTEntry {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        f.debug_struct("EPTEntry")
            .field("raw", &self.0)
            .field("hpaddr", &self.addr())
            .field("flags", &self.ept_flags())
            .field("memory_type", &self.memory_type())
            .finish()
    }
}

pub struct EPTInstr;

impl EPTInstr {
    pub fn set_ept_pointer(pml4_paddr: usize) -> HvResult {
        let mut eptp_flags = EptpFlags::empty();
        // TODO: support 5-level page tables
        if (*VMX_EPT_VIPD_CAP).contains(VmxEptVpidCap::WALK_LENGTH_4) {
            eptp_flags |= EptpFlags::WALK_LENGTH_4;
        }
        if (*VMX_EPT_VIPD_CAP).contains(VmxEptVpidCap::MEMORY_TYPE_WB) {
            eptp_flags |= EptpFlags::MEMORY_TYPE_WB;
        }
        if (*VMX_EPT_VIPD_CAP).contains(VmxEptVpidCap::ACCESSED_DIRTY) {
            eptp_flags |= EptpFlags::ENABLE_ACCESSED_DIRTY;
        }

        let invept_type = if (*VMX_EPT_VIPD_CAP).contains(VmxEptVpidCap::INVEPT_TYPE_SINGLE_CONTEXT)
        {
            InvEptType::SingleContext
        } else {
            InvEptType::Global
        };
        libvmm::vmx::Vmcs::set_ept_pointer(pml4_paddr, eptp_flags, invept_type)?;
        Ok(())
    }
}

impl PagingInstr for EPTInstr {
    unsafe fn activate(root_paddr: HostPhysAddr) {
        EPTInstr::set_ept_pointer(root_paddr).expect("Failed to set EPT_POINTER");
    }

    fn flush(_vaddr: Option<usize>) {
        // do nothing
    }
}

lazy_static! {
    pub static ref VMX_EPT_VIPD_CAP: VmxEptVpidCap =
        VmxEptVpidCap::from_bits_truncate(Msr::IA32_VMX_EPT_VPID_CAP.read());
}

pub type ExtendedPageTable = Level4PageTable<GuestPhysAddr, EPTEntry, EPTInstr>;
pub type EnclaveExtendedPageTableUnlocked =
    Level4PageTableUnlocked<GuestPhysAddr, EPTEntry, EPTInstr>;
