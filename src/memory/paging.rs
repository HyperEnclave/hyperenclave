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

use alloc::{string::String, sync::Arc, vec::Vec};
use core::{cmp::Ordering, convert::TryFrom, fmt::Debug, marker::PhantomData, slice};

use numeric_enum_macro::numeric_enum;
use spin::Mutex;

use super::addr::{phys_to_virt, PhysAddr};
use super::{Frame, MemFlags, MemoryRegion, VirtAddr};
use crate::error::{HvError, HvResult};
use crate::header::MemRange;
use crate::hypercall::error::HyperCallError;

#[derive(Debug)]
pub enum PagingError {
    UnexpectedError,
    NoMemory,
    /// The PTE has not been associated to any physical page (PTE = 0)
    NotMapped(VirtAddr),
    /// The PTE has been associated to physical page,
    /// but the page is not in the memory now (PTE != 0, but PTE.P = 0)
    NotPresent((VirtAddr, PhysAddr, MemFlags, PageSize)),
    AlreadyMapped((VirtAddr, PhysAddr, MemFlags, PageSize)),
    MappedToHugePage((VirtAddr, PhysAddr, MemFlags, PageSize)),
}

pub type PagingResult<T = ()> = Result<T, PagingError>;

impl From<PagingError> for HvError {
    fn from(err: PagingError) -> Self {
        match err {
            PagingError::NoMemory => hv_err!(ENOMEM),
            _ => hv_err!(EFAULT, format!("{:?}", err)),
        }
    }
}

impl From<PagingError> for HyperCallError {
    fn from(err: PagingError) -> Self {
        match err {
            PagingError::NoMemory => hv_err!(ENOMEM).into(),
            _ => hv_err!(EFAULT, format!("{:?}", err)).into(),
        }
    }
}

numeric_enum! {
    #[repr(u8)]
    #[derive(Debug, Copy, Clone, Eq, PartialEq)]
    /// Page translation level.
    pub enum PageTableLevel {
        /// Level 0 (terminal).
        L0 = 0,
        /// level 1.
        L1 = 1,
        /// level 2.
        L2 = 2,
        /// level 3.
        L3 = 3,
        /// level 4.
        L4 = 4,
    }
}

impl PageTableLevel {
    pub const fn max_level() -> usize {
        Self::L4 as usize
    }

    fn page_size(&self) -> PagingResult<PageSize> {
        match *self {
            PageTableLevel::L1 => Ok(PageSize::Size4K),
            PageTableLevel::L2 => Ok(PageSize::Size2M),
            PageTableLevel::L3 => Ok(PageSize::Size1G),
            _ => {
                error!("Invalid conversion, page_table_level: {:?}", self);
                Err(PagingError::UnexpectedError)
            }
        }
    }

    fn next_level(&self) -> PagingResult<Self> {
        let level = *self as u8;
        if level > PageTableLevel::L4 as u8 || level <= PageTableLevel::L1 as u8 {
            error!("Invalid next_level() for {:?}", self);
            Err(PagingError::UnexpectedError)
        } else {
            let next_level = PageTableLevel::try_from(level - 1).map_err(|next_level| {
                error!(
                    "Bug, next_level is legal since it passes the value check {:?}",
                    next_level
                );
                PagingError::UnexpectedError
            })?;
            Ok(next_level)
        }
    }
}

#[repr(usize)]
#[derive(Debug, Copy, Clone, Eq, PartialEq)]
pub enum PageSize {
    Size4K = 0x1000,
    Size2M = 0x20_0000,
    Size1G = 0x4000_0000,
}

impl From<PageSize> for PageTableLevel {
    fn from(page_size: PageSize) -> Self {
        match page_size {
            PageSize::Size4K => PageTableLevel::L1,
            PageSize::Size2M => PageTableLevel::L2,
            PageSize::Size1G => PageTableLevel::L3,
        }
    }
}

#[derive(Debug, Copy, Clone)]
pub struct Page<VA> {
    vaddr: VA,
    size: PageSize,
}

impl PageSize {
    pub const fn is_aligned(self, addr: usize) -> bool {
        self.page_offset(addr) == 0
    }

    pub const fn align_up(self, addr: usize) -> usize {
        (addr + self as usize - 1) & !(self as usize - 1)
    }

    pub const fn align_down(self, addr: usize) -> usize {
        addr & !(self as usize - 1)
    }

    pub const fn page_offset(self, addr: usize) -> usize {
        addr & (self as usize - 1)
    }

    pub const fn is_huge(self) -> bool {
        matches!(self, Self::Size1G | Self::Size2M)
    }
}

impl<VA: Into<usize> + Copy> Page<VA> {
    pub fn new_aligned(vaddr: VA, size: PageSize) -> Self {
        debug_assert!(size.is_aligned(vaddr.into()));
        Self { vaddr, size }
    }
}

pub trait GenericPTE: Debug + Clone {
    /// Returns the physical address mapped by this entry.
    fn addr(&self) -> PhysAddr;
    /// Returns the flags of this entry.
    fn flags(&self) -> MemFlags;
    /// Returns whether this entry is zero.
    fn is_unused(&self) -> bool;
    /// Returns whether this entry flag indicates present.
    fn is_present(&self) -> bool;
    /// Returns whether this entry maps to a huge frame (terminate page translation).
    fn is_leaf(&self) -> bool;
    /// Returns whether this entry's ACCESSED bit is set.
    fn is_young(&self) -> bool;

    /// Mark the PTE as non-ACCESSED.
    fn set_old(&mut self);
    /// Set physical address for terminal entries.
    fn set_addr(&mut self, paddr: PhysAddr);
    /// Set flags for terminal entries.
    fn set_flags(&mut self, flags: MemFlags, is_huge: bool) -> PagingResult;
    /// Set physical address and flags for intermediate entry,
    /// `is_present` controls whether to setting its P bit.
    fn set_table(
        &mut self,
        paddr: PhysAddr,
        next_level: PageTableLevel,
        is_present: bool,
    ) -> PagingResult;
    /// Mark the intermediate or terminal entry as present (or valid), its other parts remain unchanged.
    fn set_present(&mut self) -> PagingResult;
    /// Mark the intermediate or terminal entry as non-present (or invalid), its other parts remain unchanged.
    fn set_notpresent(&mut self) -> PagingResult;
    /// Set this entry to zero.
    fn clear(&mut self);
}

const ENTRY_COUNT: usize = 512;

pub trait PagingInstr {
    unsafe fn activate(root_paddr: PhysAddr);
    fn flush(vaddr: Option<VirtAddr>);
}

pub struct EmptyPagingInstr;

impl PagingInstr for EmptyPagingInstr {
    unsafe fn activate(_root_paddr: PhysAddr) {}
    fn flush(_vaddr: Option<VirtAddr>) {}
}

/// A basic read-only page table for address query only.
pub trait GenericPageTableImmut: Sized {
    type VA: From<usize> + Into<usize> + Copy;

    unsafe fn from_root(root_paddr: PhysAddr) -> Self;
    fn root_paddr(&self) -> PhysAddr;

    /// Walk the page table to get a valid mapping information.
    ///
    /// Returns:
    ///
    /// 1. `Ok(pte, page_size)`, query successfully;
    /// 2. `PagingError::NotMapped`: The `vaddr` does not associate with a physical page;
    /// 3. `PagingError::NotPresent`: The `vaddr` associates with a physical page, but it is non-present.
    /// 4. `PagingError::UnexpectedError`: Intermediate page table is not zero but they are non-present.
    fn query(&self, vaddr: Self::VA) -> PagingResult<(PhysAddr, MemFlags, PageSize)>;
}

/// A extended mutable page table can change mappings.
pub trait GenericPageTable: GenericPageTableImmut {
    fn new() -> Self;
    fn map(&mut self, region: &MemoryRegion<Self::VA>) -> PagingResult;
    fn unmap(&mut self, region: &MemoryRegion<Self::VA>)
        -> PagingResult<Vec<(PhysAddr, PageSize)>>;
    fn update(&mut self, region: &MemoryRegion<Self::VA>) -> PagingResult;
    fn clone(&self) -> Self;

    unsafe fn activate(&self);
    fn flush(&self, vaddr: Option<Self::VA>);
}

pub trait GenericPageTableMut<PTE: GenericPTE>: GenericPageTable {
    /// Walk the page table, then returns the mutable reference of the PTE entry.
    ///
    /// Return values:
    ///
    /// 1. `Ok(pte, page_size)`, get the result successfully.
    ///
    /// 2. `PagingError::NotMapped`: intermediate page table entry is not present.
    /// It should be mentioned that if PTE = 0 and intermediate table entry is present,
    /// `get_pte_mut()` returns Ok(pte, page_size)
    ///
    fn get_pte_mut(&mut self, vaddr: Self::VA) -> PagingResult<&mut PTE>;
}

/// A immutable level-4 page table implements `GenericPageTableImmut`.
pub struct Level4PageTableImmut<VA, PTE: GenericPTE> {
    /// Root table frame.
    root: Frame,
    /// Phantom data.
    _phantom: PhantomData<(VA, PTE)>,
}

impl<VA, PTE> Level4PageTableImmut<VA, PTE>
where
    VA: From<usize> + Into<usize> + Copy,
    PTE: GenericPTE,
{
    fn new() -> Self {
        Self {
            root: Frame::new_zero().expect("failed to allocate root frame for host page table"),
            _phantom: PhantomData,
        }
    }

    /// Walk the page table, and get the entry.
    /// If an empty entry is encountered at walking,
    /// it returns the empty entry and the page table level it belongs to.
    fn get_entry_mut_internal(&self, vaddr: VA) -> PagingResult<(&mut PTE, PageTableLevel)> {
        use PageTableLevel::*;

        let vaddr = vaddr.into();
        let p4 = table_of_mut::<PTE>(self.root_paddr());
        let p4e = &mut p4[p4_index(vaddr)];
        if p4e.is_unused() {
            return Ok((p4e, L4));
        } else if !p4e.is_present() {
            // Illegal case: PGD is not zero and but non-present.
            return Err(PagingError::UnexpectedError);
        }

        let p3 = table_of_mut::<PTE>(p4e.addr());
        let p3e = &mut p3[p3_index(vaddr)];
        if p3e.is_unused() || p3e.is_leaf() {
            return Ok((p3e, L3));
        } else if !p3e.is_present() {
            // Illegal case: PUD is not zero and but non-present.
            return Err(PagingError::UnexpectedError);
        }

        let p2 = table_of_mut::<PTE>(p3e.addr());
        let p2e = &mut p2[p2_index(vaddr)];
        if p2e.is_unused() || p2e.is_leaf() {
            return Ok((p2e, L2));
        } else if !p2e.is_present() {
            // Illegal case: PMD is not zero and but non-present.
            return Err(PagingError::UnexpectedError);
        }

        let p1 = table_of_mut::<PTE>(p2e.addr());
        let p1e = &mut p1[p1_index(vaddr)];
        Ok((p1e, L1))
    }

    fn walk(
        &self,
        table: &[PTE],
        level: PageTableLevel,
        start_vaddr: usize,
        limit: usize,
        func: &impl Fn(PageTableLevel, usize, usize, &PTE),
    ) -> PagingResult {
        let mut n = 0;
        for (i, entry) in table.iter().enumerate() {
            let mut vaddr = start_vaddr + (i << (12 + (level as usize - 1) * 9));
            if vaddr & (1 << 47) != 0 {
                vaddr |= !((1 << 47) - 1);
            }
            if entry.is_present() {
                func(level, i, vaddr, entry);
                let level = level as u8;
                if !entry.is_leaf() && level > PageTableLevel::L1 as u8 {
                    // If the entry is intermediate.
                    let next_level = level - 1;
                    let next_level =
                        PageTableLevel::try_from(next_level).map_err(|next_level| {
                            error!(
                                "Level4PageTableImmut::walk(): Bug, invalid next_level: {:?}",
                                next_level
                            );
                            PagingError::UnexpectedError
                        })?;
                    let next_entry = table_of(entry.addr());
                    self.walk(next_entry, next_level, vaddr, limit, func)?;
                }
                n += 1;
                if n >= limit {
                    break;
                }
            }
        }
        Ok(())
    }

    fn dump(&self, limit: usize) -> PagingResult {
        static LOCK: Mutex<()> = Mutex::new(());
        let _lock = LOCK.lock();

        println!("Root: {:x?}", self.root_paddr());
        self.walk(
            table_of(self.root_paddr()),
            PageTableLevel::L4,
            0,
            limit,
            &|level: PageTableLevel, idx: usize, vaddr: usize, entry: &PTE| {
                let prefix_len = (PageTableLevel::L4 as usize - level as usize) * 2;
                let mut prefix_str = String::with_capacity(prefix_len);
                for _ in 0..prefix_len {
                    prefix_str.push(' ');
                }
                println!(
                    "{} [{} - {:x}], {:08x?}: {:x?}",
                    prefix_str.as_str(),
                    level as i32,
                    idx,
                    vaddr,
                    entry
                );
            },
        )
    }
}

impl<VA, PTE> GenericPageTableImmut for Level4PageTableImmut<VA, PTE>
where
    VA: From<usize> + Into<usize> + Copy,
    PTE: GenericPTE,
{
    type VA = VA;

    unsafe fn from_root(root_paddr: PhysAddr) -> Self {
        Self {
            root: Frame::from_paddr(root_paddr),
            _phantom: PhantomData,
        }
    }

    fn root_paddr(&self) -> PhysAddr {
        self.root.start_paddr()
    }

    fn query(&self, vaddr: VA) -> PagingResult<(PhysAddr, MemFlags, PageSize)> {
        let (entry, level) = self.get_entry_mut_internal(vaddr)?;
        if entry.is_unused() {
            return Err(PagingError::NotMapped(vaddr.into()));
        }
        let size = level.page_size()?;
        if !entry.is_present() {
            return Err(PagingError::NotPresent((
                vaddr.into(),
                entry.addr(),
                entry.flags(),
                size,
            )));
        }
        let off = size.page_offset(vaddr.into());
        Ok((entry.addr() + off, entry.flags(), size))
    }
}

/// A extended level-4 page table that can change its mapping. It also tracks all intermediate
/// level tables. Locks need to be used if change the same page table concurrently.
pub struct Level4PageTableUnlocked<VA, PTE: GenericPTE, I: PagingInstr> {
    inner: Level4PageTableImmut<VA, PTE>,
    /// Intermediate level table frames.
    intrm_tables: Vec<Frame>,
    /// Phantom data.
    _phantom: PhantomData<(VA, PTE, I)>,
}

impl<VA, PTE, I> Level4PageTableUnlocked<VA, PTE, I>
where
    VA: From<usize> + Into<usize> + Copy,
    PTE: GenericPTE,
    I: PagingInstr,
{
    pub fn all_frames(&self) -> Vec<&Frame> {
        let mut frames = self.intrm_tables.iter().collect::<Vec<_>>();
        frames.push(&self.inner.root);
        frames
    }

    fn alloc_intrm_table(&mut self) -> HvResult<PhysAddr> {
        let frame = Frame::new_zero()?;
        let paddr = frame.start_paddr();
        self.intrm_tables.push(frame);
        Ok(paddr)
    }

    fn _dealloc_intrm_table(&mut self, _paddr: PhysAddr) {}

    fn get_entry_mut_or_create<'pt>(&'pt mut self, page: Page<VA>) -> PagingResult<&'pt mut PTE> {
        use PageTableLevel::*;

        let vaddr = page.vaddr.into();
        let p4 = table_of_mut::<PTE>(self.inner.root_paddr());
        let p4e = &mut p4[p4_index(vaddr)];

        let p3 = next_table_mut_or_create(vaddr, p4e, L4, || self.alloc_intrm_table())?;
        let p3e = &mut p3[p3_index(vaddr)];
        if page.size == PageSize::Size1G {
            return Ok(p3e);
        }

        let p2 = next_table_mut_or_create(vaddr, p3e, L3, || self.alloc_intrm_table())?;
        let p2e = &mut p2[p2_index(vaddr)];
        if page.size == PageSize::Size2M {
            return Ok(p2e);
        }

        let p1 = next_table_mut_or_create(vaddr, p2e, L2, || self.alloc_intrm_table())?;
        let p1e = &mut p1[p1_index(vaddr)];
        Ok(p1e)
    }

    fn get_empty_entry_mut_or_create<'pt, 'vec>(
        &'pt mut self,
        page: Page<VA>,
    ) -> PagingResult<&'pt mut PTE> {
        let entry = self.get_entry_mut_or_create(page)?;
        if !entry.is_unused() {
            return Err(PagingError::AlreadyMapped((
                page.vaddr.into(),
                entry.addr(),
                entry.flags(),
                page.size,
            )));
        }
        Ok(entry)
    }

    fn unmap_page(&mut self, vaddr: VA) -> PagingResult<(PhysAddr, PageSize)> {
        let (entry, level) = self.inner.get_entry_mut_internal(vaddr)?;
        if entry.is_unused() {
            return Err(PagingError::NotMapped(vaddr.into()));
        }
        let size = level.page_size()?;
        let paddr = entry.addr();
        entry.clear();
        Ok((paddr, size))
    }
}

impl<VA, PTE, I> GenericPageTable for Level4PageTableUnlocked<VA, PTE, I>
where
    VA: From<usize> + Into<usize> + Copy,
    PTE: GenericPTE,
    I: PagingInstr,
{
    fn new() -> Self {
        Self {
            inner: Level4PageTableImmut::new(),
            intrm_tables: Vec::new(),
            _phantom: PhantomData,
        }
    }

    fn map(&mut self, region: &MemoryRegion<VA>) -> PagingResult {
        let mut vaddr = region.start.into();
        let mut size = region.size;
        while size > 0 {
            let paddr = region.mapper.map_fn(vaddr);
            let page_size = if PageSize::Size1G.is_aligned(vaddr)
                && PageSize::Size1G.is_aligned(paddr)
                && size >= PageSize::Size1G as usize
                && !region.flags.contains(MemFlags::NO_HUGEPAGES)
            {
                PageSize::Size1G
            } else if PageSize::Size2M.is_aligned(vaddr)
                && PageSize::Size2M.is_aligned(paddr)
                && size >= PageSize::Size2M as usize
                && !region.flags.contains(MemFlags::NO_HUGEPAGES)
            {
                PageSize::Size2M
            } else {
                PageSize::Size4K
            };
            let page = Page::new_aligned(vaddr.into(), page_size);
            let entry = self.get_empty_entry_mut_or_create(page).map_err(|e| {
                match e {
                    PagingError::AlreadyMapped(_) => {
                        debug!(
                            "failed to map page: {:#x?}({:?}) -> {:#x?}, {:?}",
                            vaddr, page_size, paddr, e
                        );
                    }
                    _ => {
                        error!(
                            "failed to map page: {:#x?}({:?}) -> {:#x?}, {:?}",
                            vaddr, page_size, paddr, e
                        );
                    }
                }
                e
            })?;
            entry.set_addr(page.size.align_down(paddr));
            entry.set_flags(region.flags, page_size.is_huge())?;

            vaddr += page_size as usize;
            size -= page_size as usize;
        }
        Ok(())
    }

    fn unmap(&mut self, region: &MemoryRegion<VA>) -> PagingResult<Vec<(PhysAddr, PageSize)>> {
        trace!(
            "destroy mapping in {}: {:#x?}",
            core::any::type_name::<Self>(),
            region
        );
        let mut paddr_collector: Vec<(PhysAddr, PageSize)> = Vec::new();
        let mut vaddr = region.start.into();
        let mut size = region.size;
        while size > 0 {
            let (paddr, page_size) = self.unmap_page(vaddr.into()).map_err(|e| {
                match e {
                    PagingError::NotMapped(_) => {
                        debug!("failed to unmap page: {:#x?}, {:?}", vaddr, e);
                    }
                    _ => {
                        error!("failed to unmap page: {:#x?}, {:?}", vaddr, e);
                    }
                }
                e
            })?;
            assert!(page_size.is_aligned(vaddr));
            assert!(page_size as usize <= size);
            vaddr += page_size as usize;
            size -= page_size as usize;
            paddr_collector.push((paddr, page_size));
        }
        Ok(paddr_collector)
    }

    fn update(&mut self, region: &MemoryRegion<Self::VA>) -> PagingResult {
        let vaddr = region.start;
        let paddr = region.mapper.map_fn(vaddr);
        let flags = region.flags;

        let (entry, pt_level) = self.inner.get_entry_mut_internal(vaddr)?;
        if entry.is_unused() {
            return Err(PagingError::NotMapped(vaddr.into()));
        }
        let entry_size = pt_level.page_size()?;
        match (entry_size as usize).cmp(&region.size) {
            Ordering::Greater => {
                return Err(PagingError::MappedToHugePage((
                    vaddr.into(),
                    entry.addr(),
                    entry.flags(),
                    entry_size,
                )))
            }
            Ordering::Less => {
                return Err(PagingError::AlreadyMapped((
                    vaddr.into(),
                    entry.addr(),
                    entry.flags(),
                    entry_size,
                )))
            }
            Ordering::Equal => {}
        }

        entry.set_addr(entry_size.align_down(paddr));
        entry.set_flags(flags, entry_size.is_huge())?;
        Ok(())
    }

    fn clone(&self) -> Self {
        unimplemented!("Unimplemented trait interface");
    }

    unsafe fn activate(&self) {
        I::activate(self.root_paddr())
    }

    fn flush(&self, vaddr: Option<Self::VA>) {
        I::flush(vaddr.map(Into::into))
    }
}

impl<VA, PTE, I> GenericPageTableMut<PTE> for Level4PageTableUnlocked<VA, PTE, I>
where
    VA: From<usize> + Into<usize> + Copy,
    PTE: GenericPTE,
    I: PagingInstr,
{
    fn get_pte_mut(&mut self, vaddr: VA) -> PagingResult<&mut PTE> {
        let (pte, pt_level) = self.inner.get_entry_mut_internal(vaddr)?;
        if pt_level != PageTableLevel::L1 {
            Err(PagingError::NotMapped(vaddr.into()))
        } else {
            Ok(pte)
        }
    }
}

impl<VA, PTE, I> GenericPageTableImmut for Level4PageTableUnlocked<VA, PTE, I>
where
    VA: From<usize> + Into<usize> + Copy,
    PTE: GenericPTE,
    I: PagingInstr,
{
    type VA = VA;

    unsafe fn from_root(root_paddr: PhysAddr) -> Self {
        Self {
            inner: Level4PageTableImmut::from_root(root_paddr),
            intrm_tables: Vec::new(),
            _phantom: PhantomData,
        }
    }

    fn root_paddr(&self) -> PhysAddr {
        self.inner.root_paddr()
    }

    fn query(&self, vaddr: Self::VA) -> PagingResult<(PhysAddr, MemFlags, PageSize)> {
        self.inner.query(vaddr)
    }
}

/// A extended level-4 page table implements `GenericPageTable`. It use locks to avoid data
/// racing between it and its clonees.
pub struct Level4PageTable<VA, PTE: GenericPTE, I: PagingInstr> {
    inner: Level4PageTableUnlocked<VA, PTE, I>,
    /// Make sure all accesses to the page table and its clonees is exclusive.
    clonee_lock: Arc<Mutex<()>>,
}

impl<VA, PTE, I> Level4PageTable<VA, PTE, I>
where
    VA: From<usize> + Into<usize> + Copy,
    PTE: GenericPTE,
    I: PagingInstr,
{
    #[allow(dead_code)]
    pub fn dump(&self, limit: usize) -> PagingResult {
        self.inner.inner.dump(limit)
    }

    /// Clone only the top level page table mapping from `src`.
    pub fn clone_from(src: &impl GenericPageTableImmut) -> Self {
        // XXX: The clonee won't track intermediate tables, must ensure it lives shorter than the
        // original page table.
        let pt = Self::new();
        let dst_p4_table = unsafe {
            slice::from_raw_parts_mut(phys_to_virt(pt.root_paddr()) as *mut PTE, ENTRY_COUNT)
        };
        let src_p4_table = unsafe {
            slice::from_raw_parts(phys_to_virt(src.root_paddr()) as *const PTE, ENTRY_COUNT)
        };
        dst_p4_table.clone_from_slice(src_p4_table);
        pt
    }

    /// Clone the top level (and second level if need) page table mapping from `src`, but skip the
    /// range starts from `vaddr`.
    #[allow(dead_code)]
    pub fn clone_from_and_skip(
        src: &impl GenericPageTableImmut,
        ranges: &[MemRange],
    ) -> HvResult<Self> {
        // XXX: The clonee won't track intermediate tables, must ensure it lives shorter than the
        // original page table.
        let mut pt = Self::clone_from(src);
        let p4_table = unsafe {
            slice::from_raw_parts_mut(phys_to_virt(pt.root_paddr()) as *mut PTE, ENTRY_COUNT)
        };

        for range in ranges {
            // align address with 1G to simplify implementation.
            let mut vaddr = PageSize::Size1G.align_down(range.start);
            let mut size = PageSize::Size1G.align_up(range.size);
            if vaddr + size >= (1 << 48) {
                return hv_result_err!(EINVAL);
            }

            let mut src_p3_table_paddr = 0;
            let mut dst_p3_table_paddr = 0;
            while size > 0 {
                let i4 = p4_index(vaddr);
                if p4_table[i4].is_present() {
                    if src_p3_table_paddr == 0 {
                        src_p3_table_paddr = p4_table[i4].addr();
                        dst_p3_table_paddr = pt.inner.alloc_intrm_table()?;
                        p4_table[i4].set_addr(dst_p3_table_paddr);
                        unsafe {
                            slice::from_raw_parts_mut(
                                phys_to_virt(dst_p3_table_paddr) as *mut PTE,
                                ENTRY_COUNT,
                            )
                            .clone_from_slice(slice::from_raw_parts(
                                phys_to_virt(src_p3_table_paddr) as *const PTE,
                                ENTRY_COUNT,
                            ))
                        };
                    }

                    let dst_p3_table = unsafe {
                        slice::from_raw_parts_mut(
                            phys_to_virt(dst_p3_table_paddr) as *mut PTE,
                            ENTRY_COUNT,
                        )
                    };
                    let i3 = p3_index(vaddr);
                    dst_p3_table[i3].clear();
                    if i3 == ENTRY_COUNT - 1 {
                        src_p3_table_paddr = 0;
                    }
                }

                vaddr += PageSize::Size1G as usize;
                size -= PageSize::Size1G as usize;
            }
        }
        Ok(pt)
    }
}

impl<VA, PTE, I> GenericPageTableImmut for Level4PageTable<VA, PTE, I>
where
    VA: From<usize> + Into<usize> + Copy,
    PTE: GenericPTE,
    I: PagingInstr,
{
    type VA = VA;

    unsafe fn from_root(root_paddr: PhysAddr) -> Self {
        Self {
            inner: Level4PageTableUnlocked::from_root(root_paddr),
            clonee_lock: Arc::new(Mutex::new(())),
        }
    }

    fn root_paddr(&self) -> PhysAddr {
        self.inner.root_paddr()
    }

    fn query(&self, vaddr: VA) -> PagingResult<(PhysAddr, MemFlags, PageSize)> {
        let _lock = self.clonee_lock.lock();
        self.inner.query(vaddr)
    }
}

impl<VA, PTE, I> GenericPageTable for Level4PageTable<VA, PTE, I>
where
    VA: From<usize> + Into<usize> + Copy,
    PTE: GenericPTE,
    I: PagingInstr,
{
    fn new() -> Self {
        Self {
            inner: Level4PageTableUnlocked::new(),
            clonee_lock: Arc::new(Mutex::new(())),
        }
    }

    fn map(&mut self, region: &MemoryRegion<VA>) -> PagingResult {
        trace!(
            "create mapping in {}: {:#x?}",
            core::any::type_name::<Self>(),
            region
        );
        let _lock = self.clonee_lock.lock();
        self.inner.map(region)
    }

    fn unmap(&mut self, region: &MemoryRegion<VA>) -> PagingResult<Vec<(PhysAddr, PageSize)>> {
        trace!(
            "destroy mapping in {}: {:#x?}",
            core::any::type_name::<Self>(),
            region
        );
        let _lock = self.clonee_lock.lock();
        self.inner.unmap(region)
    }

    fn clone(&self) -> Self {
        let mut pt = Self::clone_from(self);
        // clone with lock to avoid data racing between it and its clonees.
        pt.clonee_lock = self.clonee_lock.clone();
        pt
    }

    unsafe fn activate(&self) {
        self.inner.activate();
    }

    fn flush(&self, vaddr: Option<Self::VA>) {
        self.inner.flush(vaddr);
    }

    fn update(&mut self, region: &MemoryRegion<Self::VA>) -> PagingResult {
        let _lock = self.clonee_lock.lock();
        self.inner.update(region)
    }
}

const fn p4_index(vaddr: usize) -> usize {
    (vaddr >> (12 + 27)) & (ENTRY_COUNT - 1)
}

const fn p3_index(vaddr: usize) -> usize {
    (vaddr >> (12 + 18)) & (ENTRY_COUNT - 1)
}

const fn p2_index(vaddr: usize) -> usize {
    (vaddr >> (12 + 9)) & (ENTRY_COUNT - 1)
}

const fn p1_index(vaddr: usize) -> usize {
    (vaddr >> 12) & (ENTRY_COUNT - 1)
}

fn table_of<'a, E>(paddr: PhysAddr) -> &'a [E] {
    let ptr = phys_to_virt(paddr) as *const E;
    unsafe { slice::from_raw_parts(ptr, ENTRY_COUNT) }
}

fn table_of_mut<'a, E>(paddr: PhysAddr) -> &'a mut [E] {
    let ptr = phys_to_virt(paddr) as *mut E;
    unsafe { slice::from_raw_parts_mut(ptr, ENTRY_COUNT) }
}

/// Derefence the intermediate entry (`entry`),
/// to get the structure of the next level page table.
///
/// Returns:
///
/// 1. `Ok`
/// 2. `PagingError::MappedToHugePage`: The entry is a huge page entry,
///     no matter the P bit in it is set or not;
/// 3. `PagingError::NoMememory`: There is no enough frame for newly allocated page table page;
/// 4. `PagingError::UnexpectedError`: intermediate entry is not 0 but they are non-present.
fn next_table_mut_or_create<'pt, 'vec, VA: From<usize> + Into<usize> + Copy, E: GenericPTE>(
    vaddr: VA,
    entry: &'pt mut E,
    cur_level: PageTableLevel,
    mut allocator: impl FnMut() -> HvResult<PhysAddr>,
) -> PagingResult<&'pt mut [E]> {
    if entry.is_unused() {
        let paddr = allocator().map_err(|_| PagingError::NoMemory)?;
        let next_level = cur_level.next_level()?;
        entry.set_table(paddr, next_level, true)?;
        Ok(table_of_mut(paddr))
    } else {
        // Entry is not zero.
        if entry.is_leaf() {
            Err(PagingError::MappedToHugePage((
                vaddr.into(),
                entry.addr(),
                entry.flags(),
                cur_level.page_size()?,
            )))
        } else if entry.is_present() {
            Ok(table_of_mut(entry.addr()))
        } else {
            // Illegal case: entry points to the next level of page table,
            // but itself is non-present.
            Err(PagingError::UnexpectedError)
        }
    }
}
