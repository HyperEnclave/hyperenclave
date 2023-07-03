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

use core::mem::size_of;
use core::ops::Range;
use spin::{Once, RwLock};

use crate::arch::EnclaveExceptionInfo;
use crate::config::HvSystemConfig;
use crate::consts::PAGE_SIZE;
use crate::enclave::epcm::EpcmEntry;
use crate::error::{HvError, HvResult};
use crate::header::{HvHeader, MemRange};
use crate::hypercall::error::HyperCallResult;
use crate::intervaltree::IntervalTree;
use crate::memory::addr::{align_down, align_up, is_aligned, virt_to_phys};
use crate::memory::{HostVirtAddr, HV_HEAP_SIZE, HV_HEAP_START_HVA};
use crate::percpu::CpuState;

use super::{GuestPhysAddr, HostPhysAddr};

struct RangeTree {
    tree: IntervalTree,
}

impl RangeTree {
    /// Generate range tree from array of memory regions specified by `ranges`.
    /// The number of regions is specified by `range_num`.
    fn new(ranges: &[MemRange], range_num: usize) -> Self {
        let mut tree = IntervalTree::new();

        for idx in 0..range_num {
            let mem_range = ranges[idx];
            tree.insert(mem_range.start..(mem_range.start + mem_range.size))
                .expect("Cannot insert mem_range into the tree");
        }
        Self { tree }
    }

    fn contains(&self, range: Range<usize>) -> bool {
        self.tree.contains_range(range)
    }
}

#[repr(u8)]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
/// Status or type for tracking every page in [`CONV_MEM_START`, `CONV_MEM_END`).
pub enum PageStatus {
    /// The correponding page is reserved by BIOS, cannot used by software.
    /// CMRM entry with `PageStatus::Reserved` status is an invalid CMRM entry.
    Reserved = 0,
    /// The correponding page is being converting.
    _Pending = 1,
    /// The correponding page is normal memory.
    Normal = 2,
    /// The corresponding page is EPC,
    /// such CMRM is safe to be casted into EPCM.
    Secure = 3,
    /// The correponding page is internel used by hypervisor.
    Internal = 4,
}

struct CmrmEntry {
    page_status: PageStatus,
    _inner: [u8; 23],
}

static_assertions::const_assert_eq!(size_of::<CmrmEntry>(), 24);
static_assertions::assert_eq_size!(CmrmEntry, EpcmEntry);

impl CmrmEntry {
    fn to_epcm(&self) -> HvResult<&EpcmEntry> {
        if self.page_status != PageStatus::Secure {
            return Err(hv_err!(
                EINVAL,
                format!("page_status: {:?} is not valid", self.page_status)
            ));
        }
        let epcm_ptr = self as *const CmrmEntry as *const EpcmEntry;

        // SAFETY:
        // 1. The size of `EpcmEntry` equals to `CmrmEntry`;
        // 2. The 'status' is `PageStatus::Secure`, it indicates it can be interpreted as a valid `EpcmEntry`.
        // So it is safe to perform such conversion.
        let epcm = unsafe { &*epcm_ptr };

        Ok(epcm)
    }

    fn to_epcm_mut(&mut self) -> HvResult<&mut EpcmEntry> {
        if self.page_status != PageStatus::Secure {
            return Err(hv_err!(
                EINVAL,
                format!("page_status: {:?} is not valid", self.page_status)
            ));
        }

        let epcm_ptr = self as *const CmrmEntry as *mut EpcmEntry;

        // SAFETY:
        // 1. The size of `EpcmEntry` equals to `CmrmEntry`;
        // 2. The 'status' is `PageStatus::Secure`, it indicates it can be interpreted as a valid `EpcmEntry`.
        // So it is safe to perform such conversion.
        let epcm_mut = unsafe { &mut *epcm_ptr };
        Ok(epcm_mut)
    }
}

#[derive(Debug, PartialEq)]
enum CmrmManagerState {
    Uninit,
    Inited,
}

struct CmrmManager {
    /// The number of CMRM entry which have been initialized.
    /// Only used in the proccess of CMRM's initialization.
    inited_num: usize,
    state: CmrmManagerState,
    cmrm: &'static mut [CmrmEntry],
}

impl CmrmManager {
    /// Caller needs to ensure the `cmr_idx` is valid.
    fn with_epcm_entry<T, E: From<HvError>>(
        &self,
        cmr_idx: usize,
        func: impl FnOnce(&EpcmEntry) -> Result<T, E>,
    ) -> Result<T, E> {
        if self.state != CmrmManagerState::Inited {
            return Err(hv_err!(
                EINVAL,
                "CmrmManager::with_epcm_entry(): CmrmManager must be initialized first"
            )
            .into());
        }

        let epcm = self.cmrm[cmr_idx].to_epcm()?;
        func(epcm)
    }

    /// Caller needs to ensure the `cmr_idx` is valid.
    fn with_epcm_entry_mut<T, E: From<HvError>>(
        &mut self,
        cmr_idx: usize,
        func: impl FnOnce(&mut EpcmEntry) -> Result<T, E>,
    ) -> Result<T, E> {
        if self.state != CmrmManagerState::Inited {
            return Err(hv_err!(
                EINVAL,
                "CmrmManager::with_epcm_entry_mut(): CmrmManager must be initialized first"
            )
            .into());
        }

        let epcm = self.cmrm[cmr_idx].to_epcm_mut()?;
        func(epcm)
    }

    /// Initialize the CMRM.
    fn initialize_cmrm(&mut self, num: usize) -> HyperCallResult<usize> {
        if self.state != CmrmManagerState::Uninit {
            return Err(hypercall_excep_err!(
                EnclaveExceptionInfo::general_protection(0, &CpuState::HvEnabled),
                "CmrmManager::initialize_cmrm(): its status should be Uninit"
            ));
        }

        let start_idx = self.inited_num;

        if start_idx + num > self.cmrm.len() {
            return Err(hypercall_excep_err!(
                EnclaveExceptionInfo::general_protection(0, &CpuState::HvEnabled),
                format!(
                    "CmrmManager::initialize_cmrm(): addr {:#x?} is outside range",
                    *CONV_MEM_START + (start_idx + num) * PAGE_SIZE
                )
            ));
        }

        for idx in start_idx..start_idx + num {
            let paddr = *CONV_MEM_START + idx * PAGE_SIZE;
            self.cmrm[idx].page_status = {
                if ConvMemManager::in_init_hypervior_mem(paddr) {
                    PageStatus::Internal
                } else if ConvMemManager::in_init_epc(paddr, PAGE_SIZE) {
                    PageStatus::Secure
                } else if ConvMemManager::in_conv_mem(paddr, PAGE_SIZE) {
                    PageStatus::Normal
                } else {
                    PageStatus::Reserved
                }
            };

            self.inited_num += 1;
        }

        Ok(0)
    }

    /// Mark the process of CMRM's initialization as done.
    /// All the CMRM entry should be initialized at this point.
    fn set_init_cmrm_done(&mut self) -> HyperCallResult<usize> {
        if self.state != CmrmManagerState::Uninit || self.inited_num != self.cmrm.len() {
            return Err(hypercall_excep_err!(
                EnclaveExceptionInfo::general_protection(0, &CpuState::HvEnabled),
                format!("CmrmManager::set_init_mem_done(): its status {:?} is invalid or there exists cmrm have not been initialized",
                self.state
            )));
        }

        self.state = CmrmManagerState::Inited;
        Ok(0)
    }
}

/// Convertible Memory Manager.
///
/// # Motivation
///
/// All the physical memory software can use is called convertible memory.
/// The term **convert** indicates that the physical memory region can be
/// converted among different types: normal memory, secure memory (EPC)
/// and hypervisor memory .....
///
/// Such design greatly enhances the flexibility of Hyper Enclave memory's
/// management. The secure memory (EPC) and hypervisor memory can securely
/// be expanded or shrinked at runtime by driver according to its policy.
///
/// # Overview
///
/// The Convertible Memory Manager manages the convertible memory reigon of
/// the current platform. It uses CMRM (Convertible Memory Region Metadata)
/// to track every 4kB page in the **Convertible Memory Range**.
///
/// # Different page types in CMRM
///
/// Currently we have 4 types for each convertible page tracked by CMRM.
/// Please see `PageStatus` for details.
///
/// # The process of CMRM's initialization
///
/// Before starting hypervisor, driver performs `memset()` to set the content
/// of CMRM region to 0. So all the pages in convertible memory region
/// is considered to be reserved by BIOS (cannot used by software) when
/// CMRM has not been initialized, since the value of `PageStatus::Reserved` is 0.
/// Driver needs to initialize CMRM by several hypercalls.
///
/// In Hyper Enclave's design, platform vendor is allowed to reserve physical memory
/// regions (by 'memmap' in kernel command line) for Hyper Enclave. We introduce
/// two terms to desrcibe them:
///  - Initialized EPC Range
///  - Initialized Hypervisor Range
///
/// Note that **Initialized EPC Range** and **Initialized Hypervior Range** is valid only
/// util the completion of the CMRM's initialization, since hypervisor supports
/// converting every page in converible memory between different types at runtime.
///
/// At CMRM's initializing, driver needs to initialize (by invoking hypercalls) every
/// CMRM of the pages in **Initialized EPC Range**, **Initialized Hypervior Range** and
/// **Convertible Memory Range**, since its original status is `PageStatus::Reserved`.
///

pub struct ConvMemManager {
    cmrm_manager: RwLock<CmrmManager>,
}

impl ConvMemManager {
    /// Check regions in `ranges` are arranged in increased order, and they are not overlapped with each other.
    /// The number of regions in `ranges` is specified by `range_num`.
    fn check_ranges(ranges: &[MemRange], range_num: u32) -> HvResult {
        for idx in 0..(range_num as usize) {
            let mem_range = ranges[idx];

            if idx != 0 {
                let prev_mem = ranges[idx - 1];
                if prev_mem.start + prev_mem.size > mem_range.start {
                    let msg = format!(
                            "ConvMemManager::check_ranges(): The mem_range should be in increase order, \
                            and should not be overlapped, prev: {:#x?}, this: {:#x?}",
                            prev_mem, mem_range
                        );
                    return hv_result_err!(EINVAL, msg);
                }
            }
        }
        Ok(())
    }

    fn new() -> HvResult<Self> {
        let hv_header = HvHeader::get();

        // Verify the CMR range and initialized EPC range.
        {
            if hv_header.nr_conv_mem == 0 {
                return hv_result_err!(
                    EINVAL,
                    "ConvMemManager::new(): CMR range number cannot be 0"
                );
            }

            Self::check_ranges(&hv_header.conv_mem_ranges, hv_header.nr_conv_mem)?;
            Self::check_ranges(&hv_header.init_epc_ranges, hv_header.nr_init_epc)?;

            let nr_init_epc = hv_header.nr_init_epc as usize;
            if nr_init_epc != 0 {
                let init_epc_start = hv_header.init_epc_ranges[0].start;
                let init_epc_end = hv_header.init_epc_ranges[nr_init_epc - 1].start
                    + hv_header.init_epc_ranges[nr_init_epc].size;
                let conv_mem_ranges = *CONV_MEM_START..*CONV_MEM_END;
                // Sanity check: check that initialized EPC should be in convertible memory.
                if !conv_mem_ranges.contains(&init_epc_start)
                    || !conv_mem_ranges.contains(&(init_epc_end - 1))
                {
                    return hv_result_err!(
                        EINVAL,
                        format!("ConvMemManager::new(): initialized EPC {:#x?} should be in CMR range {:#x?}",
                            init_epc_start..init_epc_end, conv_mem_ranges
                        ));
                }
            }
        }

        let cmrm_cnt = (*CONV_MEM_END - *CONV_MEM_START) / PAGE_SIZE;
        Ok(Self {
            cmrm_manager: RwLock::new(CmrmManager {
                state: CmrmManagerState::Uninit,
                cmrm: unsafe {
                    core::slice::from_raw_parts_mut(*CMRM_START_HVA as *mut CmrmEntry, cmrm_cnt)
                },
                inited_num: 0,
            }),
        })
    }

    fn cmrm_offset(gpaddr: GuestPhysAddr) -> HvResult<usize> {
        let convertible_mem_range = *CONV_MEM_START..*CONV_MEM_END;

        if !convertible_mem_range.contains(&gpaddr) {
            return Err(hv_err!(
                EINVAL,
                format!(
                    "gpaddr {:#x?} is not in convertible memory range {:#x?}",
                    gpaddr, convertible_mem_range
                )
            ));
        }
        Ok((gpaddr - *CONV_MEM_START) / PAGE_SIZE)
    }

    /// Whether memory range: [`addr`, `addr` + PAGE_SIZE) is in **Initialized Hypervisor Range**.
    fn in_init_hypervior_mem(addr: HostPhysAddr) -> bool {
        INIT_HYPER_RANGE.contains(&addr)
    }

    /// Whether memory range: [`addr`, `addr` + `size`) is in **Initialized EPC Range**.
    fn in_init_epc(addr: HostPhysAddr, size: usize) -> bool {
        INIT_EPC_RANGE_TREE.contains(addr..addr + size)
    }

    /// Whether memory range: [`addr`, `addr` + `size`) is in **Convertible Memory Range**.
    fn in_conv_mem(addr: HostPhysAddr, size: usize) -> bool {
        CONV_MEM_RANGE_TREE.contains(addr..addr + size)
    }

    /// Get the global instance of `ConvMemManager`.
    pub fn get() -> &'static ConvMemManager {
        match CMR_MANAGER.get() {
            None => panic!("Bug! CMRM should be initialized first before we get"),
            Some(cmr_manager) => cmr_manager,
        }
    }

    pub fn initialize_cmrm(&self, size: usize) -> HyperCallResult<usize> {
        if !is_aligned(size) {
            return Err(hypercall_excep_err!(
                EnclaveExceptionInfo::general_protection(0, &CpuState::HvEnabled),
                format!(
                    "ConvMemManager::initialize_cmrm(): size {:#x?} is not 4kB align",
                    size
                )
            ));
        }

        self.cmrm_manager.write().initialize_cmrm(size / PAGE_SIZE)
    }

    pub fn set_init_cmrm_done(&self) -> HyperCallResult<usize> {
        self.cmrm_manager.write().set_init_cmrm_done()
    }

    pub fn with_epcm_entry_mut<T, E: From<HvError>>(
        &self,
        gpaddr: GuestPhysAddr,
        func: impl FnOnce(&mut EpcmEntry) -> Result<T, E>,
    ) -> Result<T, E> {
        let cmr_idx = Self::cmrm_offset(gpaddr)?;
        self.cmrm_manager.write().with_epcm_entry_mut(cmr_idx, func)
    }

    pub fn with_epcm_entry<T, E: From<HvError>>(
        &self,
        gpaddr: GuestPhysAddr,
        func: impl FnOnce(&EpcmEntry) -> Result<T, E>,
    ) -> Result<T, E> {
        let cmr_idx = Self::cmrm_offset(gpaddr)?;
        self.cmrm_manager.read().with_epcm_entry(cmr_idx, func)
    }
}

pub static CMR_MANAGER: Once<ConvMemManager> = Once::new();

/// Initialize the start address and end address of **Convertible Memory Range**,
/// then initialize the `CMR_MANAGER`.
pub fn init() -> HvResult {
    lazy_static::initialize(&CMRM_START_HVA);
    lazy_static::initialize(&CMRM_SIZE_ALIGNED);
    info!(
        "Finish cmrm range init, va range: {:#x?}, pa range: {:#x?}",
        *CMRM_START_HVA..*CMRM_START_HVA + *CMRM_SIZE_ALIGNED,
        virt_to_phys(*CMRM_START_HVA)..virt_to_phys(*CMRM_START_HVA + *CMRM_SIZE_ALIGNED)
    );

    CMR_MANAGER.try_call_once(ConvMemManager::new)?;

    Ok(())
}

lazy_static! {
    static ref CONV_MEM_START: usize = {
        let conv_mem_start = HvHeader::get().conv_mem_ranges[0].start;
        if !is_aligned(conv_mem_start) {
            error!(
                "min address of convertible EPC {:#x?} is not 4kB align, enforce alignment",
                conv_mem_start
            );
            align_up(conv_mem_start)
        } else {
            conv_mem_start
        }
    };
    static ref CONV_MEM_END: usize = {
        let header = HvHeader::get();
        let nr_conv_mem = header.nr_conv_mem as usize;
        let conv_mem_end = header.conv_mem_ranges[nr_conv_mem - 1].start
            + header.conv_mem_ranges[nr_conv_mem - 1].size;
        if !is_aligned(conv_mem_end) {
            error!(
                "max address of convertible memory {:#x?} is not 4kB align, enforce alignment",
                conv_mem_end
            );
            align_down(conv_mem_end)
        } else {
            conv_mem_end
        }
    };
    pub static ref CMRM_START_HVA: HostVirtAddr = *HV_HEAP_START_HVA + *HV_HEAP_SIZE;
    pub static ref CMRM_SIZE_ALIGNED: usize =
        align_up((*CONV_MEM_END - *CONV_MEM_START) / PAGE_SIZE * size_of::<CmrmEntry>());
    pub static ref NR_INIT_EPC_RANGES: usize = HvHeader::get().nr_init_epc as usize;
    /// Accelerate checking whether a memory region is in **Initialized Hypervisor Range**,
    /// only used in the proccess of CMRM's initialization.
    static ref INIT_HYPER_RANGE: Range<usize> = {
        let hyper_mem_phys_start =
            HvSystemConfig::get().hypervisor_memory.phys_start as HostPhysAddr;
        let hyper_mem_size = HvSystemConfig::get().hypervisor_memory.size as usize;
        hyper_mem_phys_start..hyper_mem_phys_start + hyper_mem_size
    };
    /// Accelerate checking whether a memory region is in **Initialized EPC Range**,
    /// only used in the proccess of CMRM's initialization.
    static ref INIT_EPC_RANGE_TREE : RangeTree = RangeTree::new(&HvHeader::get().init_epc_ranges, HvHeader::get().nr_init_epc as usize);
    /// Accelerate checking whether a memory region is in **Convertible Memory Range**,
    /// only used in the proccess of CMRM's initialization.
    static ref CONV_MEM_RANGE_TREE : RangeTree = RangeTree::new(&HvHeader::get().conv_mem_ranges, HvHeader::get().nr_conv_mem as usize);
}

#[cfg(test)]
mod tests {
    use memoffset::span_of;

    use crate::enclave::epcm::tests::get_epcm_page_status_span;
    use crate::enclave::epcm::EpcmEntry;
    use crate::memory::cmr::{CmrmEntry, PageStatus};

    #[test]
    fn test_cmr_and_epcm_layout() {
        assert_eq!(
            span_of!(CmrmEntry, page_status),
            get_epcm_page_status_span()
        );
    }

    #[test]
    fn test_empty_epcm() {
        let empty_epcm = unsafe { core::mem::transmute::<EpcmEntry, CmrmEntry>(EpcmEntry::EMPTY) };
        assert_eq!(empty_epcm.page_status, PageStatus::Secure);
        assert_eq!(empty_epcm._inner, [0; 23]);
    }
}
