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

use core::convert::TryFrom;
use core::fmt;

use bitflags::bitflags;
use spin::Mutex;

use crate::error::HvResult;
use crate::iommu::{GenericIommu, IommuInfo};
use crate::memory::addr::{phys_encrypted, phys_to_virt, GuestPhysAddr, HostPhysAddr};
use crate::memory::PagingResult;
use crate::memory::{EmptyPagingInstr, GenericPTE, GenericPageTableImmut, Level4PageTable};
use crate::memory::{Frame, MemFlags, Mmio, PageTableLevel, PAGE_SIZE};

const DEV_TABLE_SIZE: usize = 2 * 1024 * 1024; // 2M bytes
const DEV_TABLE_ENTRY_COUNT: usize = DEV_TABLE_SIZE / core::mem::size_of::<DevTableEntry>();

/// IOMMU MMIO Registers.
///
/// Reference: Sec 3.4, AMD I/O Virtualization Technology (IOMMU) Specification.
#[repr(C)]
struct IommuMmioRegion {
    /// ( 0h) Device Table Base Address Register.
    dev_table_base: Mmio<u64>,
    /// ( 8h) Command Buffer Base Address Register.
    cmd_buf_base: Mmio<u64>,
    /// (10h) Event Log Base Address Register.
    event_log_base: Mmio<u64>,
    /// (18h) IOMMU Control Register.
    control: Mmio<u64>,
    /// (20h) IOMMU Exclusion Base Register / Completion Store Base Register.
    excl_base: Mmio<u64>,
    /// (28h) IOMMU Exclusion Range Limit Register / Completion Store Limit Register.
    excl_range_limit: Mmio<u64>,
    /// (30h) IOMMU Extended Feature Register.
    ext_feature: Mmio<u64>,
    /// (38h) PPR Log Base Address Register.
    ppr_log_base: Mmio<u64>,
    /// (40h) IOMMU Hardware Event Upper Register.
    hw_event_upper: Mmio<u64>,
    /// (48h) IOMMU Hardware Event Lower Register.
    hw_event_lower: Mmio<u64>,
    /// (50h) IOMMU Hardware Event Status Register.
    hw_event_status: Mmio<u64>,
    /// (60h-D8h) IOMMU SMI Filter Register.
    smi_filter: [Mmio<u64>; 16],
    /// (E0h-1FF8h) Unused.
    _reserved: [u64; 996],
    /// (2000h) Command Buffer Head Pointer Register.
    cmd_buf_head: Mmio<u64>,
    /// (2008h) Command Buffer Tail Pointer Register.
    cmd_buf_tail: Mmio<u64>,
    /// (2010h) Event Log Head Pointer Register.
    event_log_head: Mmio<u64>,
    /// (2018h) Event Log Tail Pointer Register.
    event_log_tail: Mmio<u64>,
    /// (2020h) IOMMU Status Register.
    status: Mmio<u64>,
}

bitflags! {
    struct IommuControlFlags: u64 {
        /// IOMMU enable.
        const IOMMU_EN =        1 << 0;
        /// HyperTransport tunnel translation enable.
        const HT_TUN_EN =       1 << 1;
        /// Event log enable.
        const EVENT_LOG_EN =    1 << 2;
        /// Event log interrupt enable.
        const EVENT_INT_EN =    1 << 3;
        /// Command buffer enable.
        const CMD_BUF_EN =      1 << 12;
        /// Peripheral page request log enable.
        const PPR_LOG_EN =      1 << 13;
        /// Peripheral page request interrupt enable
        const PPR_INT_EN =      1 << 14;
        /// Peripheral page request processing enable.
        const PPR_EN =          1 << 15;
        /// Guest translation enable.
        const GT_EN =           1 << 16;
    }
}

bitflags! {
    struct IoPTFlags: u64 {
        /// Valid.
        const V =       1 << 0;
        /// Translate information valid. (Device table only)
        const TV =      1 << 1;
        /// Sets Access bits in the host page table corresponding to peripheral
        /// requests. (Device table only)
        const HA =      1 << 7;
        /// Sets Dirty bits in the host page table corresponding to peripheral
        /// requests. (Device table only)
        const HD =      1 << 8;
        /// PPR enable. (Device table only)
        const PPR =     1 << 52;
        /// Guest PPR response with PASID. (Device table only)
        const GPPR =    1 << 53;
        /// Guest I/O protection valid. (Device table only)
        const GIOV =    1 << 54;
        /// Guest translation valid. (Device table only)
        const GV =      1 << 55;
        /// I/O read permission.
        const IR =      1 << 61;
        /// I/O write permission.
        const IW =      1 << 62;
    }
}

impl From<MemFlags> for IoPTFlags {
    fn from(f: MemFlags) -> Self {
        let mut ret = Self::empty();
        if !f.contains(MemFlags::NO_PRESENT) {
            ret |= Self::V;
        }
        if f.contains(MemFlags::READ) {
            ret |= Self::IR;
        }
        if f.contains(MemFlags::WRITE) {
            ret |= Self::IW;
        }
        ret
    }
}

impl From<IoPTFlags> for MemFlags {
    fn from(f: IoPTFlags) -> Self {
        let mut ret = Self::empty();
        if !f.contains(IoPTFlags::V) {
            ret |= Self::NO_PRESENT;
        }
        if f.contains(IoPTFlags::IR) {
            ret |= Self::READ;
        }
        if f.contains(IoPTFlags::IW) {
            ret |= Self::WRITE;
        }
        ret
    }
}

#[derive(Clone)]
pub struct IoPTEntry(u64);

impl IoPTEntry {
    const NEXT_LEVEL_MASK: u64 = 0b111 << 9; // 9..11
    const ADDR_MASK: u64 = 0x000f_ffff_ffff_f000; // 12..52

    fn next_level(&self) -> Result<PageTableLevel, u8> {
        let l = ((self.0 & Self::NEXT_LEVEL_MASK) >> 9) as u8;
        PageTableLevel::try_from(l)
    }

    fn set_next_level(&mut self, next_level: PageTableLevel) {
        self.0 = (self.0 & !Self::NEXT_LEVEL_MASK) | (next_level as u64) << 9;
    }
}

impl GenericPTE for IoPTEntry {
    fn addr(&self) -> HostPhysAddr {
        (self.0 & Self::ADDR_MASK) as _
    }
    fn flags(&self) -> MemFlags {
        IoPTFlags::from_bits_truncate(self.0).into()
    }
    fn is_unused(&self) -> bool {
        self.0 == 0
    }
    fn is_present(&self) -> bool {
        (self.0 & IoPTFlags::V.bits()) != 0
    }
    fn is_leaf(&self) -> bool {
        self.next_level() == Ok(PageTableLevel::L0)
    }
    fn is_young(&self) -> bool {
        (self.0 & IoPTFlags::HA.bits()) != 0
    }
    fn set_old(&mut self) {
        let mut flags = IoPTFlags::from_bits_truncate(self.0);
        flags -= IoPTFlags::HA;
        self.0 = self.addr() as u64 | flags.bits();
    }
    fn set_addr(&mut self, paddr: HostPhysAddr) {
        self.0 = (self.0 & !Self::ADDR_MASK) | (paddr as u64 & Self::ADDR_MASK);
    }
    fn set_flags(&mut self, flags: MemFlags, _is_huge: bool) -> PagingResult {
        let flags = IoPTFlags::from(flags);
        self.0 = self.addr() as u64 | flags.bits();
        Ok(())
    }
    fn set_table(
        &mut self,
        paddr: HostPhysAddr,
        next_level: PageTableLevel,
        is_present: bool,
    ) -> PagingResult {
        let mut flags = IoPTFlags::IR | IoPTFlags::IW;
        if is_present {
            flags |= IoPTFlags::V;
        }
        self.0 = (paddr as u64 & Self::ADDR_MASK) | flags.bits();
        self.set_next_level(next_level);
        Ok(())
    }
    fn set_present(&mut self) -> PagingResult {
        self.0 |= IoPTFlags::V.bits();
        Ok(())
    }
    fn set_notpresent(&mut self) -> PagingResult {
        let mut flags = IoPTFlags::from_bits_truncate(self.0);
        flags -= IoPTFlags::V;
        self.0 = self.addr() as u64 | flags.bits();
        Ok(())
    }
    fn clear(&mut self) {
        self.0 = 0;
    }
}

impl fmt::Debug for IoPTEntry {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        f.debug_struct("IoPTEntry")
            .field("raw", &self.0)
            .field("addr", &self.addr())
            .field("flags", &self.flags())
            .field("next_level", &self.next_level())
            .finish()
    }
}

#[repr(C)]
struct DevTableEntry {
    raw64_0: IoPTEntry,
    raw64_1: u64,
    raw64_2: u64,
    raw64_3: u64,
}

impl DevTableEntry {
    fn flags(&self) -> IoPTFlags {
        IoPTFlags::from_bits_truncate(self.raw64_0.0)
    }

    fn mode(&self) -> Result<PageTableLevel, u8> {
        self.raw64_0.next_level()
    }

    fn table_root(&self) -> HostPhysAddr {
        self.raw64_0.addr()
    }

    fn set_table_root(&mut self, root_paddr: HostPhysAddr) {
        self.raw64_0.0 = (IoPTFlags::V | IoPTFlags::TV | IoPTFlags::IR | IoPTFlags::IW).bits();
        self.raw64_0.set_addr(root_paddr);
        self.raw64_0.set_next_level(PageTableLevel::L4); // 4 Level Page Table (provides a 48-bit GPA space)
    }
}

impl fmt::Debug for DevTableEntry {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        f.debug_struct("DevTableEntry")
            .field(
                "raw",
                &[self.raw64_0.0, self.raw64_1, self.raw64_2, self.raw64_3],
            )
            .field("host_page_table_root", &self.table_root())
            .field("flags", &self.flags())
            .field("mode", &self.mode())
            .finish()
    }
}

struct IommuInner {
    regs: &'static mut IommuMmioRegion,
    dev_table_frame: Frame,
}

pub struct Iommu {
    inner: Mutex<IommuInner>,
}

impl IommuInner {
    fn dev_table_entries(&mut self) -> &mut [DevTableEntry] {
        let ptr = self.dev_table_frame.as_mut_ptr() as _;
        unsafe { core::slice::from_raw_parts_mut(ptr, DEV_TABLE_ENTRY_COUNT) }
    }
}

impl Iommu {
    pub fn new(info: &IommuInfo) -> HvResult<Self> {
        let iommu_base = phys_to_virt(info.base as HostPhysAddr);
        let regs: &mut IommuMmioRegion = unsafe { Mmio::<u64>::from_base_as(iommu_base) };

        let mut dev_table_frame = Frame::new_contiguous(DEV_TABLE_SIZE / PAGE_SIZE, 12)?;
        dev_table_frame.zero();
        let dev_table_base = phys_encrypted(dev_table_frame.start_paddr()) | 0x1FF;
        regs.dev_table_base.write(dev_table_base as u64);

        Ok(Self {
            inner: Mutex::new(IommuInner {
                regs,
                dev_table_frame,
            }),
        })
    }
}

impl GenericIommu for Iommu {
    fn set_io_page_table(&self, pt: &IoPageTable) -> HvResult {
        let mut inner = self.inner.lock();
        for entry in inner.dev_table_entries() {
            entry.set_table_root(pt.root_paddr());
        }
        Ok(())
    }

    fn set_enabled(&self, enabled: bool) -> HvResult {
        let flags = if enabled {
            IommuControlFlags::IOMMU_EN
        } else {
            IommuControlFlags::empty()
        };
        self.inner.lock().regs.control.write(flags.bits());
        Ok(())
    }
}

pub type IoPageTable = Level4PageTable<GuestPhysAddr, IoPTEntry, EmptyPagingInstr>;
