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

use crate::arch::GuestPageTableImmut;
use crate::error::{HvError, HvResult};
use crate::intervaltree::overlap;
use crate::memory::addr::{align_down, align_up, GuestVirtAddr};
use crate::memory::{
    GenericPageTable, GenericPageTableImmut, MemFlags, MemoryRegion, PagingError, PAGE_SIZE,
};
use crate::stats::Instant;
use alloc::vec::Vec;
use core::ops::Range;
use core::sync::atomic::Ordering;

use super::epcm::EpcmManager;
use super::{Enclave, EnclaveStatsId};

/// Shared Memory Range
pub type SharedMemRange = Range<GuestVirtAddr>;

#[derive(Debug)]
pub enum SharedMemSyncType {
    Valid(SharedMemRange),
    InvalidStart(Vec<SharedMemRange>),
    InvalidEnd,
}

impl Enclave {
    pub fn map_shared_memory_range(
        &self,
        mem_range: &SharedMemRange,
        gpt: &GuestPageTableImmut,
    ) -> HvResult {
        let start_addr = align_down(mem_range.start);
        let end_addr = align_up(mem_range.end);
        for gvaddr in (start_addr..end_addr).step_by(PAGE_SIZE) {
            let (gpaddr, gpt_flags) = match gpt.query(gvaddr) {
                Ok((gpaddr, gpt_flags, _page_size)) => (gpaddr, gpt_flags),
                // For add shared memory event, shared memory may not touch yet, so NotMapped is ok.
                // Normal pte may have cleared P bit by invalid, so NotPresent is ok.
                Err(PagingError::NotMapped(_)) | Err(PagingError::NotPresent(_)) => {
                    continue;
                }
                Err(_) => {
                    unreachable!("map_shared_memory_range(): query gpt");
                }
            };
            if EpcmManager::is_valid_epc(gpaddr) {
                return hv_result_err!(
                    EINVAL,
                    format!("map_shared_memory_range(): {:#x} is not valid EPC", gpaddr)
                );
            }
            {
                if let Err(e) = self.gpt.write().map(&MemoryRegion::new_with_offset_mapper(
                    gvaddr, gpaddr, PAGE_SIZE, gpt_flags,
                )) {
                    match e {
                        // In multi thread read case, the first thread has added entry by triggering #PF,
                        // following threads don't need to add entry again.
                        PagingError::AlreadyMapped(_) => continue,
                        e => {
                            error!("Enclave::map_shared_memory_range(): Ecounter error when new mapping, error: {:?}", e);
                            return Err(HvError::from(e));
                        }
                    }
                }
            }
        }
        Ok(())
    }
    pub fn unmap_shared_memory_range(&self, mem_range: &SharedMemRange) -> HvResult {
        let start_addr = align_down(mem_range.start);
        let end_addr = align_up(mem_range.end);
        for gvaddr in (start_addr..end_addr).step_by(PAGE_SIZE) {
            let gpaddr = match self
                .gpt
                .write()
                .unmap(&MemoryRegion::new_with_offset_mapper(
                    gvaddr,
                    0,
                    PAGE_SIZE,
                    MemFlags::empty(),
                )) {
                Ok(regions) => regions[0].0,
                Err(PagingError::NotMapped(_)) => {
                    continue;
                }
                Err(_) => {
                    unreachable!("unmap_shared_memory_range(): unmap enclave gpt");
                }
            };

            if let Err(e) = self
                .npt
                .write()
                .unmap(&MemoryRegion::new_with_offset_mapper(
                    gpaddr,
                    0,
                    PAGE_SIZE,
                    MemFlags::empty(),
                ))
            {
                match e {
                    PagingError::NotMapped(_) => continue,
                    e => return Err(HvError::from(e)),
                }
            }
        }
        Ok(())
    }

    pub fn sync_shared_memory(
        &self,
        event: &SharedMemSyncType,
        gpt: &GuestPageTableImmut,
    ) -> HvResult {
        let now = Instant::now();
        match event {
            SharedMemSyncType::InvalidStart(mem_ranges) => {
                // Unmap_shared_memory_range holds write-lock, while map_shared_memory_range holds read-lock.
                // This means that multiple threads can map shared-memory in parallel,
                // but can not unmap and map shared-memory in parallel.
                let _lock = self.shmem_lock.write();
                self.shmem_invalidating_cnt.fetch_add(1, Ordering::Release);
                for mem_range in mem_ranges.iter() {
                    if overlap(&self.elrange, mem_range).is_some() {
                        return hv_result_err!(EINVAL, "invalid range is append to ELRANGE");
                    }
                    self.unmap_shared_memory_range(mem_range)?;
                }
                self.atomic_add_stats(EnclaveStatsId::InvalidStartSharedMemory, now.elapsed());
            }
            SharedMemSyncType::InvalidEnd => {
                self.shmem_invalidating_cnt.fetch_sub(1, Ordering::Release);
                if self.shmem_invalidating_cnt.load(Ordering::Acquire) < 0 {
                    return hv_result_err!(EINVAL, "shmem_invalidating_cnt cannot be less than 0");
                }
                self.atomic_add_stats(EnclaveStatsId::InvalidEndSharedMemory, now.elapsed());
            }
            SharedMemSyncType::Valid(mem_range) => {
                if self.shmem_invalidating_cnt.load(Ordering::Acquire) == 0 {
                    let _lock = self.shmem_lock.read();
                    if overlap(&self.elrange, mem_range).is_some() {
                        return hv_result_err!(EINVAL, "valid range is append to ELRANGE");
                    }
                    self.map_shared_memory_range(mem_range, gpt)?;
                    self.atomic_add_stats(EnclaveStatsId::ResumeMapSharedMemory, now.elapsed());
                }
            }
        }
        Ok(())
    }

    pub fn add_shared_memory(
        &self,
        mem_range: &SharedMemRange,
        gpt: &GuestPageTableImmut,
    ) -> HvResult {
        if !self.is_init() {
            return hv_result_err!(EINVAL, "add_shared_memory(): enclave is not initialized");
        }
        if overlap(&self.elrange, mem_range).is_some() {
            return hv_result_err!(
                EINVAL,
                format!(
                    "add_shared_memory(): shared memory {:#x?} is append to ELRANGE {:#x?}",
                    mem_range, self.elrange
                )
            );
        }
        // Add new range to shared memory
        self.shmem.write().insert(mem_range.start..mem_range.end)?;
        // Map new range to GPT and NPT
        self.map_shared_memory_range(mem_range, gpt)?;
        Ok(())
    }

    pub fn remove_shared_memory(&self, mem_range: &SharedMemRange) -> HvResult {
        if overlap(&self.elrange, mem_range).is_some() {
            return hv_result_err!(
                EINVAL,
                format!(
                    "remove_shared_memory(): shared memory {:#x?} is append to ELRANGE {:#x?}",
                    mem_range, self.elrange
                )
            );
        }
        // Remove range from shared memory
        self.shmem.write().remove(mem_range)?;
        // Unmap range from GPT and NPT
        self.unmap_shared_memory_range(mem_range)?;
        Ok(())
    }
}
