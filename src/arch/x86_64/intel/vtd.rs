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

// kernel flags: intel_iommu=off iommu=off intremap=off
use crate::error::HvResult;
use crate::iommu::{GenericIommu, IommuInfo};
use crate::memory::addr::{phys_to_virt, virt_to_phys, GuestPhysAddr, HostPhysAddr};
use crate::memory::{EmptyPagingInstr, GenericPTE, GenericPageTableImmut, Level4PageTable};
use crate::memory::{Frame, MemFlags, Mmio, PageTableLevel, PAGE_SIZE};
use crate::memory::{PagingError, PagingResult};
use alloc::vec::Vec;
use bitflags::bitflags;
use core::arch::x86_64::_mm_clflush;
use core::convert::TryFrom;
use core::fmt;
use spin::Mutex;

const CONTEXT_TABLE_SIZE: usize = 256 * 16; // 256 context table, each 256 context entry(128 bit each)
const ROOT_TABLE_SIZE: usize = 256 * 16;
const ROOT_TABLE_ENTRY_COUNT: usize = 256;
const CTX_TABLE_ENTRY_COUNT: usize = 256;
const INV_QUEUE_SIZE: usize = 4 * 1024; //size 4k

/// VT-d MMIO registers, 4KB
///
/// Reference: Sec 10.4 Register Descriptions, Intel® Virtualization Technology for Directed I/O  
#[repr(C)]
struct VtdMmioRegion {
    /// ( 0h) Version Register
    version: Mmio<u32>,
    /// ( 4h) Reserved
    _reserved004h: Mmio<u32>,
    /// ( 8h) Capability Register
    capability: Mmio<u64>,
    /// (10h) Extended Capability Register
    ext_capability: Mmio<u64>,
    /// (18h) Global Command Register
    global_command: Mmio<u32>,
    /// (1Ch) Global Status Register
    global_status: Mmio<u32>,
    /// (20h) Root Table Address Register
    root_table_addr: Mmio<u64>,
    /// (28h) Context Command Register
    context_command: Mmio<u64>,
    /// (30h) Reserved
    _reserved030h: Mmio<u32>,
    /// (34h) Fault Status Register
    fault_status: Mmio<u32>,
    /// (38h) Fault Event Control Register
    fault_evt_ctrl: Mmio<u32>,
    /// (3Ch) Fault Event Data Register
    fault_evt_data: Mmio<u32>,
    /// (40h) Fault Event Address Register
    fault_evt_addr: Mmio<u32>,
    /// (44h) Fault Event Upper Address Register
    fault_evt_upper_addr: Mmio<u32>,
    /// (48h - ) unused
    _reserved048h: [u64; 7], //4KB - 0x48
    /// (80h) Invalidation Queue Head Register
    inv_head: Mmio<u64>,
    /// (88h) Invalidation Queue Tail Register
    inv_tail: Mmio<u64>,
    /// (90h) Invalidation Queue Address Register
    inv_addr: Mmio<u64>,
    /// (98h--400h)
    _reserved: [u64; 109],
    // (400h) Fault Record[0].
    // notice the offset of fault recording is platform-specific (get the offset in capability register)
    fault_record_0: Mmio<u128>,
    // (410h -- 1000h)
    _reserved_last: [u64; 382],
}

bitflags! {
    struct CmdStsFlags:u32{
        /// Compatiblity Interrupt Format
        const CFI   =  1 << 23;
        /// Set Interrupt Remapping Table Pointer
        const SIRTP =  1 << 24;
        /// Interrupt Remapping Enable
        const IRE   =  1 << 25;
        /// Queued Invalidation Enable
        const QIE   =  1 << 26;
        /// Write Buffer Flush
        const WBF   =  1 << 27;
        /// Enable Advanced Fault Logging
        const EAFL  =  1 << 28;
        /// Set Fault Log
        const SFL   =  1 << 29;
        ///Set Root Table Pointer
        const SRTP  =  1 << 30;
        ///Translation Enable
        const TE    =  1 << 31;
    }
}

impl VtdMmioRegion {
    fn set_global_command(&mut self, flags: CmdStsFlags, set_flags: bool) {
        let flags = flags.bits();
        let mask: CmdStsFlags = CmdStsFlags::TE | CmdStsFlags::QIE | CmdStsFlags::IRE; //RTPS(1<<30) is always 0 before SRTP
        let origin_status: u32 = self.global_status.read() & mask.bits();

        let new_status: u32 = if set_flags {
            origin_status | flags
        } else {
            origin_status & (!flags)
        };
        self.global_command.write(new_status);

        while (self.global_status.read() & flags) != (new_status & flags) {
            core::hint::spin_loop();
        }
    }
    fn init_invalidation_queue(&mut self, queue_addr: HostPhysAddr) {
        // use Descriptor width 128bit, Queue Size 4KB
        self.inv_addr.write(queue_addr as u64);
        // invalidation queue head is read only
        self.inv_tail.write(0);
        self.set_global_command(CmdStsFlags::QIE, true);
    }
}

bitflags! {
    struct IoPTFlags:u64{
        const READ  = 1 << 0;
        const WRITE = 1 << 1;
        const EXEC  = 1 << 2;
        const HUGE  = 1 << 7;
        const ACCESS= 1 << 8;
        const DIRTY = 1 << 9;
    }
}

impl TryFrom<MemFlags> for IoPTFlags {
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
            error!("If the IOPT-E is non-present, it cannot be R or W or E.");
            return Err(PagingError::UnexpectedError);
        }
        if f.contains(MemFlags::READ) {
            ret |= Self::READ;
        }
        if f.contains(MemFlags::WRITE) {
            ret |= Self::WRITE;
        }
        Ok(ret)
    }
}

impl From<IoPTFlags> for MemFlags {
    fn from(f: IoPTFlags) -> Self {
        let mut ret = Self::empty();
        if f.contains(IoPTFlags::READ) {
            ret |= Self::READ;
        }
        if f.contains(IoPTFlags::WRITE) {
            ret |= Self::WRITE;
        }
        ret
    }
}
#[derive(Clone)]
pub struct IoPTEntry(u64);

const PHYS_ADDR_MASK: u64 = 0x000f_ffff_ffff_f000; // 12..52

impl GenericPTE for IoPTEntry {
    fn addr(&self) -> HostPhysAddr {
        (self.0 & PHYS_ADDR_MASK) as _
    }
    fn flags(&self) -> MemFlags {
        IoPTFlags::from_bits_truncate(self.0).into()
    }
    fn is_unused(&self) -> bool {
        self.0 == 0
    }
    fn is_present(&self) -> bool {
        (self.0 & IoPTFlags::READ.bits()) != 0
    }
    fn is_leaf(&self) -> bool {
        (self.0 & IoPTFlags::HUGE.bits()) != 0
    }
    fn is_young(&self) -> bool {
        (self.0 & IoPTFlags::ACCESS.bits()) != 0
    }

    fn set_old(&mut self) {
        let mut flags = IoPTFlags::from_bits_truncate(self.0);
        flags -= IoPTFlags::ACCESS;
        self.0 = self.addr() as u64 | flags.bits();
        flush_cpu_cache(self as *mut Self as usize, 8);
    }
    fn set_addr(&mut self, paddr: HostPhysAddr) {
        self.0 = (self.0 & !PHYS_ADDR_MASK) | (paddr as u64 & PHYS_ADDR_MASK);
        flush_cpu_cache(self as *mut Self as usize, 8);
    }
    fn set_flags(&mut self, flags: MemFlags, is_huge: bool) -> PagingResult {
        let mut flags = IoPTFlags::try_from(flags)?;
        if is_huge {
            flags |= IoPTFlags::HUGE; //amd: use next level
        }
        self.0 = self.addr() as u64 | flags.bits();
        flush_cpu_cache(self as *mut Self as usize, 8); //flush, or crash!
        Ok(())
    }
    fn set_table(
        &mut self,
        paddr: HostPhysAddr,
        _next_level: PageTableLevel,
        is_present: bool,
    ) -> PagingResult {
        if !is_present {
            error!("Illegal to set present for IoPT intermediate entry");
            return Err(PagingError::UnexpectedError);
        }
        self.0 = (paddr as u64 & PHYS_ADDR_MASK) | (IoPTFlags::READ | IoPTFlags::WRITE).bits();
        flush_cpu_cache(self as *mut Self as usize, 8);
        Ok(())
    }
    fn set_present(&mut self) -> PagingResult {
        error!("Illegal to set present for IoPT-E");
        Err(PagingError::UnexpectedError)
    }
    fn set_notpresent(&mut self) -> PagingResult {
        error!("Illegal to set not-present for IoPT-E");
        Err(PagingError::UnexpectedError)
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
            .finish()
    }
}

bitflags! {
    struct ContextEntryFlags:u64{//not directly corresponding to Context Entry bits, use set_flags()/get_flags()
        /// Present
        const P = 1 << 0;
        /// Fault Processing Disable
        const FPD =  1 << 1;
        //Translation Type, use 00 to translate, use 10 to pass through
        const TT00 = 1 << 2;
        const TT01 = 1 << 3;
        const TT10 = 1 << 4;
        //Page Table Level
        const LEVEL3 = 1 << 5;
        const LEVEL4 = 1 << 6;
        const LEVEL5 = 1 << 7;
    }
}
#[repr(C)]
struct CtxTableEntry {
    raw64_0: u64,
    raw64_1: u64,
}
impl CtxTableEntry {
    const ADDR_MASK: u64 = 0xffff_ffff_ffff_f000; // 12..64, raw64_0
    const DID_MASK: u64 = 0x0000_0000_00ff_ff00; // 08..24, raw64_1
    fn set_addr(&mut self, paddr: HostPhysAddr) {
        //set second level page table pointer
        self.raw64_0 = (self.raw64_0 & !Self::ADDR_MASK) | (paddr as u64 & Self::ADDR_MASK);
    }
    fn _get_flags(&self) -> ContextEntryFlags {
        let mut ret: ContextEntryFlags = ContextEntryFlags::empty();
        if self.raw64_0 & 1 != 0 {
            ret |= ContextEntryFlags::P;
        }
        if self.raw64_0 & (1 << 1) != 0 {
            ret |= ContextEntryFlags::FPD;
        }
        ret |= match (self.raw64_0 >> 2) & 0b11 {
            0b00 => ContextEntryFlags::TT00,
            0b01 => ContextEntryFlags::TT01,
            0b10 => ContextEntryFlags::TT10,
            _ => ContextEntryFlags::empty(),
        };
        ret |= match self.raw64_1 & 0x111b {
            0b001 => ContextEntryFlags::LEVEL3,
            0b010 => ContextEntryFlags::LEVEL4,
            0b011 => ContextEntryFlags::LEVEL5,
            _ => ContextEntryFlags::empty(),
        };
        ret
    }
    fn set_flags(&mut self, flags: ContextEntryFlags) {
        if flags.contains(ContextEntryFlags::P) {
            self.raw64_0 |= 1;
        } else {
            self.raw64_0 &= !1;
        }

        if flags.contains(ContextEntryFlags::FPD) {
            self.raw64_0 |= 2;
        } else {
            self.raw64_0 &= !2;
        }

        if flags.contains(ContextEntryFlags::TT00) {
            self.raw64_0 = (self.raw64_0 & (!0b1100)) | (0b00 << 2);
        } else if flags.contains(ContextEntryFlags::TT01) {
            self.raw64_0 = (self.raw64_0 & (!0b1100)) | (0b01 << 2);
        } else if flags.contains(ContextEntryFlags::TT10) {
            self.raw64_0 = (self.raw64_0 & (!0b1100)) | (0b10 << 2);
        }

        if flags.contains(ContextEntryFlags::LEVEL3) {
            self.raw64_1 = (self.raw64_1 & (!0b111)) | (0b001);
        } else if flags.contains(ContextEntryFlags::LEVEL4) {
            self.raw64_1 = (self.raw64_1 & (!0b111)) | (0b010);
        } else {
            self.raw64_1 = (self.raw64_1 & (!0b111)) | (0b011);
        }
    }
    fn _get_domain_id(&self) -> u64 {
        return (self.raw64_1 & Self::DID_MASK) >> 8;
    }
    fn set_domain_id(&mut self, did: u64) {
        self.raw64_1 = (self.raw64_1 & (!Self::DID_MASK)) | (did << 8);
    }
}
#[repr(C)]
struct RootTableEntry {
    raw64_0: u64,
    raw64_1: u64,
}
impl RootTableEntry {
    const ADDR_MASK: u64 = 0xffff_ffff_ffff_f000; // 12..64
    fn set_context_pointer(&mut self, paddr: HostPhysAddr) {
        self.raw64_0 = (self.raw64_0 & !Self::ADDR_MASK) | (paddr as u64 & Self::ADDR_MASK);
        self.raw64_1 = 0;
    }
    fn _get_present(&self) -> bool {
        self.raw64_0 & 1 != 0
    }
    fn set_present(&mut self, present: bool) {
        if present {
            self.raw64_0 |= 1;
        } else {
            self.raw64_0 &= !1;
        }
        self.raw64_1 = 0; //reserved
    }
}
pub struct Iommu {
    inner: Mutex<IommuInner>,
}
struct IommuInner {
    regs: &'static mut VtdMmioRegion,
    root_table_frame: Frame,
    ctx_table_frames: Vec<Frame>, //context table frames
    inv_queue_frame: Frame,
}
impl Iommu {
    pub fn new(iommu_info: &IommuInfo) -> HvResult<Self> {
        info!("enter Iommu::new");

        let iommu_base = iommu_info.base as HostPhysAddr;
        let regs: &mut VtdMmioRegion =
            unsafe { Mmio::<u64>::from_base_as(phys_to_virt(iommu_base)) };
        info!("capability is {:x}", regs.capability.read());
        let mut root_table_frame = Frame::new_contiguous(ROOT_TABLE_SIZE / PAGE_SIZE, 0)?;
        root_table_frame.zero();

        let mut ctx_table_frames = Vec::with_capacity(256); //context table frames
        for _i in 0..256 {
            let mut ctx_frame = Frame::new_contiguous(CONTEXT_TABLE_SIZE / PAGE_SIZE, 0)?;
            ctx_frame.zero();
            ctx_table_frames.push(ctx_frame);
        }

        let mut inv_queue_frame = Frame::new_contiguous(INV_QUEUE_SIZE, 0)?;
        inv_queue_frame.zero();
        Ok(Self {
            inner: Mutex::new(IommuInner {
                regs,
                root_table_frame,
                ctx_table_frames,
                inv_queue_frame,
            }),
        })
    }
}
const CACHE_LINE_SIZE: usize = 64; //TODO: get Cache Line Size from system config
fn flush_cpu_cache(addr: usize, length: usize) {
    //root entry, context entry, page table entry all need to be flushed
    let iter = (length + CACHE_LINE_SIZE - 1) / CACHE_LINE_SIZE;
    let mut target = addr as *mut u8;
    for _i in 0..iter {
        unsafe {
            _mm_clflush(target);
            target = target.offset(CACHE_LINE_SIZE as isize);
        }
    }
}
impl IommuInner {
    const CONTEXT_INV: u128 = (1) | (1 << 4); // 1: type =  context cache invalidation 1<<4: granularity = global
    const IOTLB_INV: u128 = (2) | (1 << 4) | (1 << 6) | (1 << 7); //2: type = iotlb 1<<4: global 1<<6: drain read 1<<7: drain write
    const WAIT_INV: u128 = (5) | (1 << 5) | (1 << 6) | (1 << 32); //5: type = wait  1<<5: status write 1<<6: fence 1<<32:status data
    fn root_table_entries(&mut self) -> &mut [RootTableEntry] {
        let ptr = self.root_table_frame.as_mut_ptr() as _;
        unsafe { core::slice::from_raw_parts_mut(ptr, ROOT_TABLE_ENTRY_COUNT) }
    }
    fn context_table_entries(&mut self, num: usize) -> &mut [CtxTableEntry] {
        let ptr = self.ctx_table_frames[num].as_mut_ptr() as _;
        unsafe { core::slice::from_raw_parts_mut(ptr, CTX_TABLE_ENTRY_COUNT) }
    }
    fn get_context_addr(&self, num: usize) -> HostPhysAddr {
        self.ctx_table_frames[num].start_paddr()
    }
    fn set_context_table(&mut self, num: usize, root_paddr: HostPhysAddr) {
        let ctx_entrys = self.context_table_entries(num);
        for i in 0..256 {
            ctx_entrys[i].set_addr(root_paddr);
            ctx_entrys[i].set_flags(
                ContextEntryFlags::P
                    | ContextEntryFlags::FPD
                    | ContextEntryFlags::TT00
                    | ContextEntryFlags::LEVEL4,
            ); // legacy mode translation enabled
               //  ContextEntryFlags::TT10  | ContextEntryFlags::LEVEL4);//pass through mode, no translation
            ctx_entrys[i].set_domain_id(1); //all devices use the same memory mapping, thus belongs to one domain
        }
        flush_cpu_cache(
            &ctx_entrys[0] as *const CtxTableEntry as usize,
            CONTEXT_TABLE_SIZE,
        ); //flush, or crash!
    }
    fn send_invalidation(&mut self, inv_command: u128) {
        let ptr = self.inv_queue_frame.as_mut_ptr() as _;
        let inv_queue = unsafe { core::slice::from_raw_parts_mut(ptr, INV_QUEUE_SIZE / 16) };
        let mut tail = self.regs.inv_tail.read() as usize;
        inv_queue[tail >> 4] = inv_command;
        flush_cpu_cache(&inv_queue[tail >> 4] as *const u128 as usize, 32);

        //add a wait descriptor after the request descriptor, ensure the command is finished
        tail = tail + (1 << 4);
        let mut status_write: u32 = 0;
        let wait_command: u128 = Self::WAIT_INV
            | ((virt_to_phys((&mut status_write) as *mut u32 as usize) as u128) << 64);
        //wait_command[64:127]: address for write back status
        inv_queue[tail >> 4] = wait_command;
        flush_cpu_cache(&inv_queue[tail >> 4] as *const u128 as usize, 32);
        tail = tail + (1 << 4);
        self.regs.inv_tail.write(tail as u64);
        while status_write == 0 {
            // question: use volatile here?
            core::hint::spin_loop();
            flush_cpu_cache(&status_write as *const u32 as usize, 32);
        }
    }
    fn set_enabled(&mut self, enabled: bool) {
        if enabled {
            self.regs.set_global_command(CmdStsFlags::QIE, false);
            self.regs.set_global_command(CmdStsFlags::IRE, false);
            self.regs.fault_record_0.write(0);
            self.regs.fault_status.write(0);
            let root_table_addr = self.root_table_frame.start_paddr();
            self.regs.root_table_addr.write(root_table_addr as u64); //here, we set Translation Mode to 00, legacy mode
            self.regs.set_global_command(CmdStsFlags::SRTP, true);

            // invalidation
            self.regs
                .init_invalidation_queue(self.inv_queue_frame.start_paddr());
            self.send_invalidation(Self::CONTEXT_INV); //context
            self.send_invalidation(Self::IOTLB_INV); //iotlb
        }

        self.regs.set_global_command(CmdStsFlags::TE, enabled); //when enabled = false: disabled
    }
    fn set_io_page_table(&mut self, pt: &IoPageTable) -> HvResult {
        //set root entry
        for i in 0..256 {
            let ctx_addr = self.get_context_addr(i);
            self.root_table_entries()[i].set_context_pointer(ctx_addr);
            self.root_table_entries()[i].set_present(true);
        }
        //flush, or crash!
        flush_cpu_cache(
            &(self.root_table_entries()[0]) as *const RootTableEntry as usize,
            ROOT_TABLE_SIZE,
        );
        //set context entry
        for i in 0..256 {
            self.set_context_table(i, pt.root_paddr());
        }
        Ok(())
    }
}

impl GenericIommu for Iommu {
    fn set_io_page_table(&self, pt: &IoPageTable) -> HvResult {
        //iterate each context table and iterate each context entry
        self.inner.lock().set_io_page_table(pt)?;
        Ok(())
    }

    fn set_enabled(&self, enabled: bool) -> HvResult {
        self.inner.lock().set_enabled(enabled);
        Ok(())
    }
}

pub type IoPageTable = Level4PageTable<GuestPhysAddr, IoPTEntry, EmptyPagingInstr>;
