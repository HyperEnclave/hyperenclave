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

//! Physical memory allocation.

use bitmap_allocator::BitAlloc;

use spin::Mutex;

use super::addr::{align_down, align_up, is_aligned, phys_encrypted, phys_to_virt, PhysAddr};
use crate::config::HvSystemConfig;
use crate::consts::{PAGE_SIZE, PER_CPU_SIZE};
use crate::error::HvResult;
use crate::header::HvHeader;
use crate::memory::addr::virt_to_phys;
use crate::memory::cmr::{CMRM_SIZE_ALIGNED, CMRM_START_HVA};
use crate::memory::HV_HEAP_SIZE;

// Support max 1M * 4096 = 4GB memory.
type FrameAlloc = bitmap_allocator::BitAlloc1M;

struct FrameAllocator {
    base: PhysAddr,
    inner: FrameAlloc,
}

/// A safe wrapper for physical frame allocation.
#[derive(Debug)]
pub struct Frame {
    start_paddr: PhysAddr,
    frame_count: usize,
}

static FRAME_ALLOCATOR: Mutex<FrameAllocator> = Mutex::new(FrameAllocator::empty());

impl FrameAllocator {
    const fn empty() -> Self {
        Self {
            base: 0,
            inner: FrameAlloc::DEFAULT,
        }
    }

    fn new(base: PhysAddr, size: usize) -> Self {
        let mut inner = FrameAlloc::DEFAULT;
        let base = align_up(base);
        let page_count = align_up(size) / PAGE_SIZE;
        inner.insert(0..page_count);
        Self { base, inner }
    }

    /// # Safety
    ///
    /// This function is unsafe because you need to deallocate manually.
    unsafe fn alloc(&mut self) -> Option<PhysAddr> {
        let ret = self.inner.alloc().map(|idx| idx * PAGE_SIZE + self.base);
        trace!("Allocate frame: {:x?}", ret);
        ret
    }

    /// # Safety
    ///
    /// This function is unsafe because your need to deallocate manually.
    unsafe fn alloc_contiguous(
        &mut self,
        frame_count: usize,
        align_log2: usize,
    ) -> Option<PhysAddr> {
        let ret = self
            .inner
            .alloc_contiguous(frame_count, align_log2)
            .map(|idx| idx * PAGE_SIZE + self.base);
        trace!(
            "Allocate {} frames with alignment {}: {:x?}",
            frame_count,
            1 << align_log2,
            ret
        );
        ret
    }

    /// # Safety
    ///
    /// This function is unsafe because the frame must have been allocated.
    unsafe fn dealloc(&mut self, target: PhysAddr) {
        trace!("Deallocate frame: {:x}", target);
        self.inner.dealloc((target - self.base) / PAGE_SIZE)
    }

    /// # Safety
    ///
    /// This function is unsafe because the frames must have been allocated.
    unsafe fn dealloc_contiguous(&mut self, target: PhysAddr, frame_count: usize) {
        trace!("Deallocate {} frames: {:x}", frame_count, target);
        let start_idx = (target - self.base) / PAGE_SIZE;
        for i in start_idx..start_idx + frame_count {
            self.inner.dealloc(i)
        }
    }
}

#[allow(dead_code)]
impl Frame {
    /// Allocate one physical frame.
    pub fn new() -> HvResult<Self> {
        unsafe {
            FRAME_ALLOCATOR
                .lock()
                .alloc()
                .map(|start_paddr| Self {
                    start_paddr,
                    frame_count: 1,
                })
                .ok_or(hv_err!(ENOMEM))
        }
    }

    /// Allocate one physical frame and fill with zero.
    pub fn new_zero() -> HvResult<Self> {
        let mut f = Self::new()?;
        f.zero();
        Ok(f)
    }

    /// Allocate contiguous physical frames.
    pub fn new_contiguous(frame_count: usize, align_log2: usize) -> HvResult<Self> {
        unsafe {
            FRAME_ALLOCATOR
                .lock()
                .alloc_contiguous(frame_count, align_log2)
                .map(|start_paddr| Self {
                    start_paddr,
                    frame_count,
                })
                .ok_or(hv_err!(ENOMEM))
        }
    }

    /// Constructs a frame from a raw physical address without automatically calling the destructor.
    ///
    /// # Safety
    ///
    /// This function is unsafe because the user must ensure that this is an available physical
    /// frame.
    pub unsafe fn from_paddr(start_paddr: PhysAddr) -> Self {
        assert!(is_aligned(start_paddr));
        Self {
            start_paddr,
            frame_count: 0,
        }
    }

    /// Get the start physical address of this frame.
    pub fn start_paddr(&self) -> PhysAddr {
        self.start_paddr
    }

    /// Get the total size (in bytes) of this frame.
    pub fn size(&self) -> usize {
        self.frame_count * PAGE_SIZE
    }

    /// convert to raw a pointer.
    pub fn as_ptr(&self) -> *const u8 {
        phys_to_virt(self.start_paddr) as *const u8
    }

    /// convert to a mutable raw pointer.
    pub fn as_mut_ptr(&self) -> *mut u8 {
        phys_to_virt(self.start_paddr) as *mut u8
    }

    /// Fill `self` with `byte`.
    pub fn fill(&mut self, byte: u8) {
        unsafe { core::ptr::write_bytes(self.as_mut_ptr(), byte, self.size()) }
    }

    /// Fill `self` with zero.
    pub fn zero(&mut self) {
        self.fill(0)
    }

    /// Forms a slice that can read data.
    pub fn as_slice(&self) -> &[u8] {
        unsafe { core::slice::from_raw_parts(self.as_ptr(), self.size()) }
    }

    /// Forms a mutable slice that can write data.
    pub fn as_slice_mut(&mut self) -> &mut [u8] {
        unsafe { core::slice::from_raw_parts_mut(self.as_mut_ptr(), self.size()) }
    }
}

impl Drop for Frame {
    fn drop(&mut self) {
        unsafe {
            match self.frame_count {
                0 => {} // Do not deallocate when use Frame::from_paddr()
                1 => FRAME_ALLOCATOR.lock().dealloc(self.start_paddr),
                _ => FRAME_ALLOCATOR
                    .lock()
                    .dealloc_contiguous(self.start_paddr, self.frame_count),
            }
        }
    }
}

/// Initialize the physical frame allocator.
pub(super) fn init() {
    let header = HvHeader::get();
    let sys_config = HvSystemConfig::get();
    let used_size = header.core_size as usize
        + header.max_cpus as usize * PER_CPU_SIZE
        + sys_config.size()
        + *HV_HEAP_SIZE
        + *CMRM_SIZE_ALIGNED;

    let mem_pool_start_vaddr = align_up(*CMRM_START_HVA + *CMRM_SIZE_ALIGNED);
    let mem_pool_start_paddr = virt_to_phys(mem_pool_start_vaddr);
    let mem_pool_size = align_down(sys_config.hypervisor_memory.size as usize - used_size);

    *FRAME_ALLOCATOR.lock() =
        FrameAllocator::new(phys_encrypted(mem_pool_start_paddr), mem_pool_size);

    info!(
        "Finish frame allocator init, va range: {:#x?}, pa range: {:#x?}",
        mem_pool_start_vaddr..mem_pool_start_vaddr + mem_pool_size,
        mem_pool_start_paddr..mem_pool_start_paddr + mem_pool_size
    );
}
