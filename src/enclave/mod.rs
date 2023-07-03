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

mod edmm;
pub mod epcm;
mod manager;
mod measure;
pub mod reclaim;
pub mod report;
pub mod sgx;
pub mod shared_mem;
pub mod structs;
mod thread;
mod tlb_track;

use alloc::sync::Arc;
use core::cell::UnsafeCell;
use core::fmt::{Debug, Formatter, Result};
use core::mem::{size_of, transmute};
use core::sync::atomic::{AtomicIsize, AtomicUsize, Ordering};

use sha2::{Digest, Sha256};
use spin::{mutex::SpinMutex, RwLock};

use crate::arch::{
    EnclaveExceptionInfo, EnclaveGuestPageTableUnlocked, EnclaveNestedPageTableUnlocked,
    GuestPageTableImmut, PageFaultErrorCode,
};
use crate::error::HvResult;
use crate::hypercall::error::{HyperCallErrorType, HyperCallResult};
use crate::hypercall::PrivilegeLevel;
use crate::intervaltree::IntervalTree;
use crate::memory::addr::{is_aligned, phys_to_virt, GuestPhysAddr, GuestVirtAddr, HostPhysAddr};
use crate::memory::cmr::NR_INIT_EPC_RANGES;
use crate::memory::gaccess::{AsGuestPtr, GuestPtr};
use crate::memory::{GenericPTE, GenericPageTable, GenericPageTableImmut, GenericPageTableMut};
use crate::memory::{MemFlags, MemoryRegion, PageSize, PagingError, PhysAddr, PAGE_SIZE};
use crate::percpu::CpuState;
use crate::stats::{Instant, StatsValue};

use epcm::EpcmManager;
use measure::Measure;
use reclaim::{Nonce, VaSlot};
use sgx::{
    ElRange, EnclaveErrorCode, MiscSgx, SgxAttributeFlags, SgxEnclPageFlags, SgxEnclPageType,
    SgxPcmd, SgxSecInfo, SgxSecs, SgxTcs, SigStruct,
};
use structs::{
    EnclPageAttributes, HvEnclNewPageDesc, HvEnclRemovePagesAtDestroyPageArray,
    HvEnclRemovePagesAtDestroyResArray, Sha256Value,
};
use tlb_track::TLBFlushTrackingState;

pub use crate::arch::EnclaveThreadState;
pub use manager::ENCLAVE_MANAGER;
pub use thread::{EnclaveThread, VcpuAccessEnclaveState};

#[repr(usize)]
#[derive(Debug)]
pub enum EnclaveStatsId {
    Create = 0,
    AddPage = 1,
    Init = 2,
    Enter = 3,
    Exit = 4,
    Resume = 5,
    Aex = 6,
    EnterPageWalk = 7,
    EnterGetTcs = 8,
    EnterGetSsa = 9,
    EnterSwitchState = 10,
    AddVersionArray = 11,
    Block = 12,
    Track = 13,
    WriteBack = 14,
    LoadUnblocked = 15,

    WriteBackGetConfigPtr = 16,
    WriteBackFindEnclave = 17,
    WriteBackPreCheck = 18,
    WriteBackVerify = 19,
    WriteBackGetNonce = 20,
    WriteBackGetSecinfo = 21,
    WriteBackEncAndHmac = 22,
    WriteBackPostCheck = 23,
    WriteBackUnmap = 24,
    WriteBackRemove = 25,
    LoadUnblockedGetConfigPtr = 26,
    LoadUnblockedFindEnclave = 27,
    LoadUnblockedPreCheck = 28,
    LoadUnblockedGetNonce = 29,
    LoadUnblockedDecAndHmac = 30,
    LoadUnblockedAddPage = 31,
    LoadUnblockedMap = 32,
    EnterUpdateTrackingState = 33,
    EnterClearBlocked = 34,
    ResumeGetTcs = 35,
    ResumeGetSsa = 36,
    ResumeUpdateTrackingState = 37,
    ResumeClearBlocked = 38,
    ResumeMapSharedMemory = 39,
    InvalidStartSharedMemory = 40,
    InvalidEndSharedMemory = 41,
    AddSharedMemory = 42,
    RemoveSharedMemory = 43,

    AugmentPage = 44,
    ModifyPageType = 45,
    RestrictPagePerm = 46,
    RemovePageAtRuntime = 47,
    AcceptPage = 48,
    AcceptCopyPage = 49,
    ExtendPagePerm = 50,

    PrepareDestroy = 51,
    RemovePagesAtDestroy = 52,

    MaxId = 53,
}

#[derive(Debug, Copy, Clone)]
pub struct AexException {
    pub vec: u8,
    pub misc: Option<MiscSgx>,
}

/// Enclave state
const STATE_UNINIT: usize = 0x0;
const STATE_INIT_TRY: usize = 0x1;
const STATE_INIT_OK: usize = 0x2;
const STATE_TRY_DESTROY: usize = 0x3;
const STATE_IN_DESTROY: usize = 0x4;

struct ArrayStatsValue([StatsValue; EnclaveStatsId::MaxId as usize]);

impl Default for ArrayStatsValue {
    fn default() -> Self {
        unsafe { transmute([0_u8; size_of::<Self>()]) }
    }
}

pub struct Enclave {
    /// gPA of SECS. Usually, it does not change over the lifetime of the enclave,
    /// and therefore can be used to identify the enclave.
    id: usize,
    /// Guest linear address of SECS.
    secs_vaddr: GuestVirtAddr,

    /// SGX Enclave Control Structrue.
    secs: UnsafeCell<SgxSecs>,
    /// Enclave Linear Address Range (ELRANGE).
    elrange: ElRange,

    /// Enclave state
    state: AtomicUsize,
    /// SGX Enclave measurement.
    measure: RwLock<Measure>,

    /// Nested page table in S-world.
    npt: RwLock<EnclaveNestedPageTableUnlocked>,
    /// Guest page table in S-world.
    gpt: RwLock<EnclaveGuestPageTableUnlocked>,

    /// Track the number of EPC pages of this enclave.
    epc_page_num: AtomicIsize,

    /// Number of TCS pages.
    tcs_count: AtomicUsize,

    /// Statistics of enclave operation time.
    stats: ArrayStatsValue,

    /// Tracking cycle state.
    tracking_state: RwLock<TLBFlushTrackingState>,

    /// Concurrency control for all the memory transactions in elrange.
    ///
    /// For memory transactions (e.g. mark page blocked, restrict page permission),
    /// hypervisor always takes guest linear address as one of input,
    /// then gets and updates its page attributes in its page table.
    /// Besides modifying page attributes,
    /// hypervisor updates its corresponding EPCM's attributes,
    /// then updates the state for TLB flush track.
    /// Such lock is used to ensure the atomicity of all the operations above.
    encl_mem_lock: SpinMutex<()>,

    /// Shared memory Ranges
    shmem: RwLock<IntervalTree>,

    /// Sync between shared memory map and unmap
    shmem_lock: RwLock<()>,

    /// Number of in-process shared memory invalidation event.
    /// - Linux prepares to invalidate shared memory, and notifies hypervisor:
    ///     shmem_invalidating_cnt + 1
    /// - Linux finishes invalidating shared memory, and notifies hypervisor:
    ///     shmem_invalidating_cnt - 1
    shmem_invalidating_cnt: AtomicIsize,
}

unsafe impl Sync for Enclave {}

impl Enclave {
    pub fn new(
        secs_paddr: GuestPhysAddr,
        secs_vaddr: GuestVirtAddr,
        secs: SgxSecs,
    ) -> HvResult<Arc<Self>> {
        secs.validate()?;

        let elrange = secs.base_addr as _..(secs.base_addr + secs.size) as _;
        let mut measure = Measure::new();
        measure.start(secs.size, secs.ssa_frame_size);
        let mut secs_verified = secs;
        secs_verified.attributes.flags -= SgxAttributeFlags::INIT;
        let gpt = RwLock::new(EnclaveGuestPageTableUnlocked::new());
        let npt = RwLock::new(EnclaveNestedPageTableUnlocked::new());

        let enclave = Arc::new(Self {
            id: secs_paddr,
            secs_vaddr,
            secs: UnsafeCell::new(secs_verified),
            elrange,
            state: AtomicUsize::new(STATE_UNINIT),
            measure: RwLock::new(measure),
            npt,
            gpt,
            epc_page_num: AtomicIsize::new(0),
            tcs_count: AtomicUsize::new(0),
            stats: Default::default(),
            tracking_state: RwLock::new(Default::default()),
            encl_mem_lock: SpinMutex::new(()),
            shmem: RwLock::new(IntervalTree::new()),
            shmem_lock: RwLock::new(()),
            shmem_invalidating_cnt: AtomicIsize::new(0),
        });
        debug!("NR_INIT_EPC_RANGES: {:#x?}", *NR_INIT_EPC_RANGES);
        debug!("Enclave::new() OK: {:#x?}", enclave);
        Ok(enclave)
    }

    pub fn elrange(&self) -> &ElRange {
        &self.elrange
    }

    pub fn shmem(&self) -> &RwLock<IntervalTree> {
        &self.shmem
    }

    pub fn is_init(&self) -> bool {
        self.state.load(Ordering::SeqCst) == STATE_INIT_OK
    }

    fn is_in_destroy(&self) -> bool {
        self.state.load(Ordering::SeqCst) == STATE_IN_DESTROY
    }

    fn secs(&self) -> &SgxSecs {
        unsafe { &*self.secs.get() }
    }

    /// SECS will only be updated on EINIT.
    #[allow(clippy::mut_from_ref)]
    unsafe fn secs_mut(&self) -> &mut SgxSecs {
        &mut *self.secs.get()
    }

    pub fn measurement(&self) -> Sha256Value {
        self.secs().mr_enclave
    }

    pub fn mr_signer(&self) -> &[u8] {
        self.secs().mr_signer.as_slice()
    }

    // FIXME: use struct `SgxAttributes` instead of (u64, u64).
    pub fn attributes(&self) -> (u64, u64) {
        (
            self.secs().attributes.flags.bits(),
            self.secs().attributes.xfrm,
        )
    }

    pub fn isv(&self) -> (u16, u16) {
        (self.secs().isv_prod_id, self.secs().isv_svn)
    }

    pub fn nested_page_table_root(&self) -> HostPhysAddr {
        self.npt.read().root_paddr()
    }

    pub fn page_table_root(&self) -> GuestPhysAddr {
        self.gpt.read().root_paddr()
    }

    fn validate_state_and_vaddr(self: &Arc<Self>, gvaddr: GuestVirtAddr) -> HyperCallResult {
        if !self.is_init() {
            return Err(hypercall_excep_err!(
                EnclaveExceptionInfo::general_protection(0, &CpuState::EnclaveRunning),
                "Enclave::validate_state_and_vaddr(): enclave has not been initialized"
            ));
        }

        if !is_aligned(gvaddr) || !self.elrange.contains(&gvaddr) {
            return Err(hypercall_excep_err!(
                EnclaveExceptionInfo::general_protection(0, &CpuState::EnclaveRunning),
                format!(
                "Enclave::validate_state_and_vaddr(): gvaddr: {:#x?} not 4kB aligned or is out of ELRANGE {:#x?}",
                gvaddr, self.elrange
            )));
        }

        Ok(())
    }

    pub fn add_page(
        self: &Arc<Self>,
        page_desc: &HvEnclNewPageDesc,
        gpt: &GuestPageTableImmut,
    ) -> HyperCallResult<usize> {
        if self.state.load(Ordering::SeqCst) != STATE_UNINIT {
            return hypercall_hv_err_result!(
                EBUSY,
                "Enclave::add_page(): enclave is already initialized"
            );
        }

        if !page_desc.attr.contains(EnclPageAttributes::EADD) {
            return hypercall_hv_err_result!(
                EINVAL,
                format!(
                    "Enclave::add_page(): Bad page attributes {:#x?}",
                    page_desc.attr
                )
            );
        }

        let gvaddr = page_desc.enclave_lin_addr as usize;
        if !is_aligned(gvaddr) {
            return hypercall_hv_err_result!(
                EINVAL,
                format!(
                    "Enclave::add_page(): enclave_lin_addr {:#x} is not aligned",
                    gvaddr
                )
            );
        }
        if !self.elrange.contains(&gvaddr) {
            return hypercall_hv_err_result!(
                EINVAL,
                format!(
                    "Enclave::add_page(): enclave_lin_addr {:#x} is out of ELRANGE {:#x?}",
                    gvaddr, self.elrange
                )
            );
        }

        let gpaddr = page_desc.epc_page_pa as usize;
        let sec_info_ptr = page_desc
            .metadata
            .as_guest_ptr_ns::<SgxSecInfo>(gpt, PrivilegeLevel::Supervisor);
        let sec_info = sec_info_ptr.read()?;
        EpcmManager::add_page(gvaddr, gpaddr, &sec_info, self)?;

        let gpt_flags = sec_info.into();

        if sec_info.page_type == SgxEnclPageType::TCS {
            let tcs_gpaddr = page_desc.source_address as _;
            let tcs: &SgxTcs = GuestPtr::gpaddr_to_ref(&tcs_gpaddr, false)?;
            if !tcs.validate_at_creation() {
                return hypercall_hv_err_result!(
                    EINVAL,
                    format!("Enclave::add_page(): Invalid TCS: {:#x?}", tcs)
                );
            }
            info!("New enclave thread(tcs_vaddr={:#x}): {:#x?}", gvaddr, tcs);
            self.tcs_count.fetch_add(1, Ordering::Release);
        } else {
            let hpaddr = gpaddr;
            let npt_flags = gpt_flags | MemFlags::ENCRYPTED;
            self.npt.write().map(&MemoryRegion::new_with_offset_mapper(
                gpaddr, hpaddr, PAGE_SIZE, npt_flags,
            ))?;
        }
        self.gpt.write().map(&MemoryRegion::new_with_offset_mapper(
            gvaddr, gpaddr, PAGE_SIZE, gpt_flags,
        ))?;
        unsafe {
            core::ptr::copy_nonoverlapping(
                phys_to_virt(page_desc.source_address as _) as *const u8,
                phys_to_virt(gpaddr) as *mut u8,
                PAGE_SIZE,
            );
        }

        let page_data = if page_desc.attr.contains(EnclPageAttributes::EEXTEND) {
            Some(unsafe { &*(phys_to_virt(gpaddr) as *mut [u8; PAGE_SIZE]) })
        } else {
            None
        };
        self.measure
            .write()
            .update((gvaddr - self.elrange.start) as _, sec_info, page_data);

        Ok(0)
    }

    pub fn init(&self, sigstruct: &SigStruct) -> HvResult {
        let init_inner = || -> HvResult {
            // map page table frames of GPT of the enclave into NPT of the enclave
            for frame in self.gpt.read().all_frames() {
                let gpaddr = frame.start_paddr();
                let hpaddr = gpaddr;
                self.npt.write().map(&MemoryRegion::new_with_offset_mapper(
                    gpaddr,
                    hpaddr,
                    PAGE_SIZE,
                    MemFlags::READ | MemFlags::WRITE | MemFlags::USER,
                ))?;
            }

            debug!("{:#x?}", sigstruct);
            let secs_mut = unsafe { self.secs_mut() };
            self.measure
                .write()
                .finish(secs_mut.mr_enclave.as_mut_slice());

            // verify mr_enclave from sigstruct
            if secs_mut.mr_enclave != sigstruct.body.mr_enclave {
                return hv_result_err!(
                    EINVAL,
                    format!(
                        "Enclave::init(): mr_enclave not match {:#x?} {:#x?}",
                        secs_mut.mr_enclave, sigstruct.body.mr_enclave
                    )
                );
            }

            let mut hasher = Sha256::new();
            hasher.update(sigstruct.key.modules.as_slice());
            let hash = hasher.finalize_reset();
            secs_mut
                .mr_signer
                .as_mut_slice()
                .clone_from_slice(hash.as_slice());
            secs_mut.isv_prod_id = sigstruct.body.isv_prod_id;
            secs_mut.isv_svn = sigstruct.body.isv_svn;
            secs_mut.attributes.flags |= SgxAttributeFlags::INIT;
            info!("Enclave::init(): OK {:#x?}", secs_mut);
            Ok(())
        };

        if self
            .state
            .compare_exchange(
                STATE_UNINIT,
                STATE_INIT_TRY,
                Ordering::SeqCst,
                Ordering::SeqCst,
            )
            .is_ok()
        {
            let res = init_inner();
            if res.is_ok() {
                self.state.store(STATE_INIT_OK, Ordering::SeqCst);
            } else {
                self.state.store(STATE_UNINIT, Ordering::SeqCst);
            }
            res
        } else {
            hv_result_err!(EBUSY, "Enclave::init(): enclave is already initialized")
        }
    }

    pub fn add_version_array(self: &Arc<Self>, gpaddr: GuestPhysAddr) -> HyperCallResult<usize> {
        if !is_aligned(gpaddr) {
            return hypercall_hv_err_result!(
                EINVAL,
                format!(
                    "Enclave::add_version_array(): epc_page_pa {:#x} is not aligned",
                    gpaddr
                )
            );
        }

        let sec_info = SgxSecInfo::new(SgxEnclPageFlags::empty(), SgxEnclPageType::VA);
        // Version array page does not bind to any linear address in userspace.
        EpcmManager::add_page(0, gpaddr, &sec_info, self)?;
        unsafe { core::ptr::write_bytes(phys_to_virt(gpaddr) as *mut u8, 0, PAGE_SIZE) };

        Ok(0)
    }

    pub fn write_back_page_wrapper(
        self: &Arc<Self>,
        page_desc: &HvEnclNewPageDesc,
        gpt: &GuestPageTableImmut,
        va_slot_pa: usize,
    ) -> HyperCallResult<usize> {
        let clear_blocked_func = || {
            let gpaddr = page_desc.epc_page_pa as usize;
            EpcmManager::clear_blocked(gpaddr);
        };

        let ret = self.write_back_page(page_desc, gpt, va_slot_pa);
        if let Err(ref e) = ret {
            match e.error() {
                HyperCallErrorType::EnclaveError(enclave_error_code) => {
                    if *enclave_error_code != EnclaveErrorCode::ENOTTRACKED {
                        clear_blocked_func();
                    }
                }
                _ => clear_blocked_func(),
            }
        }
        ret
    }

    pub fn write_back_page(
        self: &Arc<Self>,
        page_desc: &HvEnclNewPageDesc,
        gpt: &GuestPageTableImmut,
        va_slot_pa: usize,
    ) -> HyperCallResult<usize> {
        let now = Instant::now();
        let gvaddr_src = page_desc.enclave_lin_addr as usize;
        if !is_aligned(gvaddr_src) {
            return hypercall_hv_err_result!(
                EINVAL,
                format!(
                    "Enclave::block(): enclave_lin_addr {:#x} is not aligned",
                    gvaddr_src
                )
            );
        }
        if !self.elrange.contains(&gvaddr_src) {
            return hypercall_hv_err_result!(
                EINVAL,
                format!(
                    "Enclave::block(): enclave_lin_addr {:#x} is out of ELRANGE {:#x?}",
                    gvaddr_src, self.elrange
                )
            );
        }
        let gpaddr_src = page_desc.epc_page_pa as usize;
        if !is_aligned(gpaddr_src) {
            return hypercall_hv_err_result!(
                EINVAL,
                format!(
                    "Enclave::write_back_page(): epc_page_pa {:#x} is not aligned",
                    gpaddr_src
                )
            );
        }

        let gpaddr_dst = page_desc.source_address as usize;
        if !is_aligned(gpaddr_dst) {
            return hypercall_hv_err_result!(
                EINVAL,
                format!(
                    "Enclave::write_back_page(): source_address {:#x} is not aligned",
                    gpaddr_dst
                )
            );
        }
        if EpcmManager::is_valid_epc(gpaddr_dst) {
            return hypercall_hv_err_result!(
                EINVAL,
                format!(
                    "Enclave::write_back_page(): can't access source_address {:#x?} as secure memory",
                    gpaddr_dst
                )
            );
        }
        let time_check = now.elapsed();

        self.write_back_verify(gpaddr_src)?;
        let time_verity = now.elapsed();
        let va_slot = VaSlot::from_paddr_mut(va_slot_pa)?;
        va_slot.is_empty()?;

        let nonce = Nonce::new().get_val();
        let time_nonce = now.elapsed();
        let sec_info = EpcmManager::query_sec_info(gpaddr_src)?;
        // TODO: We remain the BLOCKED state in PCMD in the current implemention.
        // But the PCMD should record the BLOCKED state,
        // since the semantics of ELDU is:
        // Loads, verifies an EPC page and marks the page as unblocked.
        let sec_info = SgxSecInfo::new(
            sec_info.flags - SgxEnclPageFlags::BLOCKED,
            sec_info.page_type,
        );
        let time_get_secinfo = now.elapsed();
        let mut alg = reclaim::create_alg_instance(&nonce, self.id, &sec_info, gvaddr_src);
        let mac = alg.encrypt_and_hmac_page(gpaddr_src, gpaddr_dst)?;
        let time_enc_and_hmac = now.elapsed();

        let time_post_check;
        {
            let _encl_mem_lock = self.encl_mem_lock.lock();

            let sec_info = EpcmManager::query_sec_info(gpaddr_src)?;
            // An EPC page's BLOCKED state is cleared to mark cancel reclaim it
            // when occur #PF or call load_page() for the page between EBLOCK
            // and EWB. Therefore, check BLOCKED state to decide if cancel reclaim
            // an EPC page before EWB finish.
            if !sec_info.flags.contains(SgxEnclPageFlags::BLOCKED) {
                return Err(hypercall_enclave_err!(
                    ECANCELRECLAIM,
                    format!(
                        "Enclave::write_back_page(): cancel reclaim, gpaddr: {:#x?}",
                        gpaddr_src
                    )
                ));
            }
            time_post_check = now.elapsed();
            self.gpt
                .write()
                .unmap(&MemoryRegion::new_with_offset_mapper(
                    gvaddr_src,
                    0,
                    PAGE_SIZE,
                    MemFlags::empty(),
                ))?;

            // Pages with TRIM type can be picked by reclaimer and can be reclaimed, but they have no NPT mapping.
            // In Hyper Enclave, only pages with REG type have NPT mapping.
            if sec_info.page_type == SgxEnclPageType::REG {
                self.npt
                    .write()
                    .unmap(&MemoryRegion::new_with_offset_mapper(
                        gpaddr_src,
                        0,
                        PAGE_SIZE,
                        MemFlags::empty(),
                    ))?;
            }
            EpcmManager::write_back_page(gvaddr_src, gpaddr_src, self)?;
        }
        let time_unmap = now.elapsed();

        let pcmd = SgxPcmd::new(sec_info, self.id, mac);
        let mut metadata_ptr = page_desc
            .metadata
            .as_guest_ptr_ns::<SgxPcmd>(gpt, PrivilegeLevel::Supervisor);
        metadata_ptr.write(pcmd)?;

        unsafe { core::ptr::write_bytes(phys_to_virt(gpaddr_src) as *mut u8, 0, PAGE_SIZE) };

        va_slot.set(nonce);
        let time_remove = now.elapsed();

        self.atomic_add_stats(EnclaveStatsId::WriteBackPreCheck, time_check);
        self.atomic_add_stats(EnclaveStatsId::WriteBackVerify, time_verity - time_check);
        self.atomic_add_stats(EnclaveStatsId::WriteBackGetNonce, time_nonce - time_verity);
        self.atomic_add_stats(
            EnclaveStatsId::WriteBackGetSecinfo,
            time_get_secinfo - time_nonce,
        );
        self.atomic_add_stats(
            EnclaveStatsId::WriteBackEncAndHmac,
            time_enc_and_hmac - time_get_secinfo,
        );
        self.atomic_add_stats(
            EnclaveStatsId::WriteBackPostCheck,
            time_post_check - time_enc_and_hmac,
        );
        self.atomic_add_stats(EnclaveStatsId::WriteBackUnmap, time_unmap - time_post_check);
        self.atomic_add_stats(EnclaveStatsId::WriteBackRemove, time_remove - time_unmap);

        Ok(0)
    }

    pub fn load_unblocked(
        self: &Arc<Self>,
        page_desc: &HvEnclNewPageDesc,
        gpt: &GuestPageTableImmut,
        va_slot_pa: usize,
    ) -> HyperCallResult<usize> {
        let now = Instant::now();
        let gvaddr = page_desc.enclave_lin_addr as usize;
        if !is_aligned(gvaddr) {
            return hypercall_hv_err_result!(
                EINVAL,
                format!(
                    "Enclave::load_unblocked(): enclave_lin_addr {:#x} is not aligned",
                    gvaddr
                )
            );
        }
        if !self.elrange.contains(&gvaddr) {
            return hypercall_hv_err_result!(
                EINVAL,
                format!(
                    "Enclave::load_unblocked(): enclave_lin_addr {:#x} is out of ELRANGE {:#x?}",
                    gvaddr, self.elrange
                )
            );
        }

        let gpaddr_dst = page_desc.epc_page_pa as usize;
        if !is_aligned(gpaddr_dst) {
            return hypercall_hv_err_result!(
                EINVAL,
                format!(
                    "Enclave::load_unblocked(): epc_page_pa {:#x} is not aligned",
                    gpaddr_dst
                )
            );
        }

        let gpaddr_src = page_desc.source_address as usize;
        if EpcmManager::is_valid_epc(gpaddr_src) {
            return hypercall_hv_err_result!(
                EINVAL,
                format!(
                    "Enclave::load_unblocked(): can't access source_address {:#x?} as secure memory",
                    gpaddr_src
                )
            );
        }
        let time_check = now.elapsed();

        let va_slot = VaSlot::from_paddr_mut(va_slot_pa)?;
        let metadata_ptr = page_desc
            .metadata
            .as_guest_ptr_ns::<SgxPcmd>(&gpt, PrivilegeLevel::Supervisor);
        let metadata = metadata_ptr.read()?;

        let nonce = va_slot.get();
        let time_nonce = now.elapsed();
        let mut alg = reclaim::create_alg_instance(&nonce, self.id, &metadata.sec_info, gvaddr);
        alg.decrypt_and_hmac_page(gpaddr_src, gpaddr_dst, &metadata.mac)?;
        let time_dec_and_hmac = now.elapsed();

        EpcmManager::add_page(gvaddr, gpaddr_dst, &metadata.sec_info, self)?;
        let time_add_page = now.elapsed();

        let gpt_flags = metadata.sec_info.into();

        if metadata.sec_info.page_type == SgxEnclPageType::REG {
            let npt_flags = (gpt_flags - MemFlags::NO_PRESENT) | MemFlags::ENCRYPTED;
            self.npt.write().map(&MemoryRegion::new_with_offset_mapper(
                gpaddr_dst, gpaddr_dst, PAGE_SIZE, npt_flags,
            ))?;
        }
        self.gpt.write().map(&MemoryRegion::new_with_offset_mapper(
            gvaddr, gpaddr_dst, PAGE_SIZE, gpt_flags,
        ))?;

        va_slot.clear();
        let time_map = now.elapsed();
        self.atomic_add_stats(EnclaveStatsId::LoadUnblockedPreCheck, time_check);
        self.atomic_add_stats(
            EnclaveStatsId::LoadUnblockedGetNonce,
            time_nonce - time_check,
        );
        self.atomic_add_stats(
            EnclaveStatsId::LoadUnblockedDecAndHmac,
            time_dec_and_hmac - time_nonce,
        );
        self.atomic_add_stats(
            EnclaveStatsId::LoadUnblockedAddPage,
            time_add_page - time_dec_and_hmac,
        );
        self.atomic_add_stats(EnclaveStatsId::LoadUnblockedMap, time_map - time_add_page);
        Ok(0)
    }

    pub fn block(&self, page_desc: &HvEnclNewPageDesc) -> HyperCallResult<usize> {
        let gvaddr = page_desc.enclave_lin_addr as usize;
        if !is_aligned(gvaddr) {
            return hypercall_hv_err_result!(
                EINVAL,
                format!(
                    "Enclave::block(): enclave_lin_addr {:#x} is not aligned",
                    gvaddr
                )
            );
        }
        if !self.elrange.contains(&gvaddr) {
            return hypercall_hv_err_result!(
                EINVAL,
                format!(
                    "Enclave::block(): enclave_lin_addr {:#x} is out of ELRANGE {:#x?}",
                    gvaddr, self.elrange
                )
            );
        }

        let gpaddr = page_desc.epc_page_pa as usize;
        if !is_aligned(gpaddr) {
            return hypercall_hv_err_result!(
                EINVAL,
                format!("Enclave::block(): epc_page_pa {:#x} is not aligned", gpaddr)
            );
        }
        if EpcmManager::is_blocked(gpaddr) {
            warn!(
                "Enclave::block(): paddr {:#x?} is already in BLOCKED state",
                gpaddr
            );
            return Err(hypercall_enclave_err!(EBLKSTATE));
        }

        {
            let mut tracking_state = self.tracking_state.write();
            if tracking_state.is_in_tracking() {
                return Err(hypercall_enclave_err!(
                    EENTRYEPOCHLOCKED,
                    format!("Enclave::block(): enclave is in tracking cycle")
                ));
            }
            tracking_state.require_track_for_write_back();
        }

        {
            let _encl_mem_lock = self.encl_mem_lock.lock();
            {
                let mut secure_gpt = self.gpt.write();

                let pte = match secure_gpt.get_pte_mut(gvaddr) {
                    Ok(pte) => pte,
                    Err(PagingError::NotMapped(_)) => {
                        return hypercall_hv_err_result!(
                            EFAULT,
                            "Internal page table is not mapped"
                        )
                    }
                    _ => return hypercall_hv_err_result!(EFAULT, "Error"),
                };
                pte.set_notpresent()?;
            }
            EpcmManager::set_blocked(gpaddr);
        }

        Ok(0)
    }

    pub fn track(&self) -> HyperCallResult<usize> {
        if !self.tracking_state.write().activate() {
            return Err(hypercall_enclave_err!(
                EPREVTRKINCMPL,
                format!("Enclave::track(): enclave is in tracking cycle")
            ));
        }

        Ok(0)
    }

    pub fn write_back_verify(&self, gpaddr: usize) -> HyperCallResult<usize> {
        if !EpcmManager::is_blocked(gpaddr) {
            return Err(hypercall_enclave_err!(
                EPAGENOTBLOCKED,
                format!(
                    "Enclave::write_back_verify(): paddr {:#x?} isn't in BLOCKED state",
                    gpaddr
                )
            ) as _);
        }

        if !self.tracking_state.read().is_write_back_tracking_done() {
            return Err(hypercall_enclave_err!(
                ENOTTRACKED,
                format!("Enclave::write_back_verify(): enclave tracking cycle isn't done")
            ));
        }

        Ok(0)
    }

    pub fn update_tracking_state(&self, is_enter: bool, cpuid: usize) {
        self.tracking_state.write().update(is_enter, cpuid);
    }

    pub fn inc_epc_page_num(&self) {
        self.epc_page_num.fetch_add(1, Ordering::Release);
    }

    pub fn dec_epc_page_num(&self) {
        self.epc_page_num.fetch_sub(1, Ordering::Release);
    }

    pub fn epc_page_num(&self) -> isize {
        self.epc_page_num.load(Ordering::Acquire)
    }

    pub fn handle_npt_violation(
        self: &Arc<Self>,
        gpaddr: GuestPhysAddr,
        final_translation: bool,
    ) -> HvResult {
        let npt_flags = if final_translation {
            if EpcmManager::is_valid_epc(gpaddr) {
                return hv_result_err!(
                    EFAULT,
                    "All the dynamically augmented EPC pages' NPT entry should be mapped at EACCEPT"
                );
            } else {
                MemFlags::READ | MemFlags::WRITE | MemFlags::USER
            }
        } else {
            MemFlags::READ | MemFlags::WRITE | MemFlags::USER
        };
        {
            let _encl_mem_lock = self.encl_mem_lock.lock();
            if let Err(e) = self.npt.write().map(&MemoryRegion::new_with_offset_mapper(
                gpaddr, gpaddr, PAGE_SIZE, npt_flags,
            )) {
                match e {
                    // In multi-threaded scenarios, threads may generate #NPF for the same physical address.
                    // One of the thread may handle the #PF (the first thread),
                    // and other threads may create get the `AlreadyMapped` error.
                    // In this case, simply return here.
                    PagingError::AlreadyMapped(_) => {}
                    e => {
                        error!("Enclave::handle_npt_violation(): Ecounter error when new mapping, error: {:?}, gpaddr: {:#x?}", e, gpaddr);
                        return hv_result_err!(EINVAL);
                    }
                }
            }
        }
        Ok(())
    }

    pub fn atomic_add_stats(&self, id: EnclaveStatsId, value: u64) {
        self.stats.0[id as usize].atomic_add(value)
    }

    pub fn load_page(
        self: &Arc<Self>,
        gvaddr: usize,
        is_encl_mode: bool,
    ) -> HyperCallResult<(PhysAddr, MemFlags, PageSize)> {
        let generate_pf = |error_code: u32,
                           fault_gvaddr: usize,
                           is_encl_mode: bool|
         -> HyperCallResult<(PhysAddr, MemFlags, PageSize)> {
            let exceptio_info = if is_encl_mode {
                EnclaveExceptionInfo::page_fault_in_encl(error_code, error_code, fault_gvaddr)
            } else {
                EnclaveExceptionInfo::page_fault_out_encl(error_code, fault_gvaddr)
            };
            Err(hypercall_excep_err!(exceptio_info))
        };

        debug!("load_page, {:#x?}", gvaddr);
        if !self.elrange.contains(&gvaddr) {
            return hypercall_hv_err_result!(
                EINVAL,
                format!(
                    "Enclave::load_page(): gvaddr {:#x} is out of ELRANGE {:#x?}",
                    gvaddr, self.elrange
                )
            );
        }

        {
            let _encl_mem_lock = self.encl_mem_lock.lock();
            {
                let mut secure_gpt = self.gpt.write();

                match secure_gpt.get_pte_mut(gvaddr) {
                    Ok(pte) => {
                        if pte.is_unused() {
                            debug!("Enclave::load_page(): PTEState::None, {:#x?}", gvaddr);
                            let error_code = PageFaultErrorCode::USER_MODE.bits();
                            generate_pf(error_code, gvaddr, is_encl_mode)
                        } else if !pte.is_present() {
                            let gpaddr_aligned = pte.addr();
                            debug!(
                                "Enclave::load_page(): page gvaddr: {:#x?} gpaddr_aligned: {:#x?} is being reclaimed, cancel reclaim",
                                gvaddr, gpaddr_aligned
                            );
                            let new_sec_info = EpcmManager::access_page_check(
                                gvaddr,
                                gpaddr_aligned,
                                self,
                                false,
                                is_encl_mode,
                            )?;
                            pte.set_flags(new_sec_info.into(), false)?;
                            Ok((
                                gpaddr_aligned + PageSize::Size4K.page_offset(gvaddr),
                                pte.flags(),
                                PageSize::Size4K,
                            ))
                        } else {
                            let gpfn = pte.addr();
                            Ok((
                                gpfn + PageSize::Size4K.page_offset(gvaddr),
                                pte.flags(),
                                PageSize::Size4K,
                            ))
                        }
                    }
                    // PagingError::NotMapped
                    // Internal Page table is not mapped
                    Err(PagingError::NotMapped(_)) => {
                        debug!("Enclave::load_page(): Internal Page table is not mapped");
                        let error_code = PageFaultErrorCode::USER_MODE.bits();
                        generate_pf(error_code, gvaddr, is_encl_mode)
                    }
                    _ => {
                        error!("Enclave::load_page(): Internal page error");
                        return hypercall_hv_err_result!(EFAULT);
                    }
                }
            }
        }
    }

    pub fn prepare_destroy(self: &Arc<Self>) -> HyperCallResult<usize> {
        self.state.store(STATE_TRY_DESTROY, Ordering::SeqCst);
        let active_thread_num = self.tracking_state.read().active_thread_num();
        if active_thread_num != 0 {
            let msg = format!(
                "Enclave::prepare_destroy(): There still exist thread (num = {:?}) in enclave mode",
                active_thread_num
            );
            warn!("{}", msg);
            return Err(hypercall_enclave_err!(EENCLAVEACT, msg));
        }
        self.state.store(STATE_IN_DESTROY, Ordering::SeqCst);
        Ok(0)
    }

    pub fn remove_pages_at_destroy(
        self: &Arc<Self>,
        batch_size: usize,
        pages_desc: &HvEnclRemovePagesAtDestroyPageArray,
        res_desc: &mut HvEnclRemovePagesAtDestroyResArray,
    ) {
        for idx in 0..batch_size {
            let gpaddr = pages_desc.gpaddr[idx];
            let ret_val = &mut res_desc.val[idx];

            // - For VA page,
            //      There is no page table entry in enclave's GPT and E/NPT for version array page.
            //      So we do not need to modify the enclave's GPT and E/NPT.
            //
            // - For other types of page,
            //      We do not need to remove the page table entry in enclave's GPT and E/NPT.
            //      Since enclave is in destroy state,
            //      there is no thread in enclave mode and access the memory.
            match EpcmManager::remove_page_at_destroy(gpaddr, self) {
                Ok(()) => {
                    unsafe {
                        core::ptr::write_bytes(phys_to_virt(gpaddr) as *mut u8, 0, PAGE_SIZE)
                    };
                    *ret_val = 0;
                }
                // Remove pages as more as possible,
                // and set the error code in the result descriptor.
                Err(e) => {
                    if let HyperCallErrorType::HvError(error_num) = e.error() {
                        *ret_val = error_num.code() as isize
                    }
                }
            }
        }
    }

    pub fn fixup_pf_in_elrange(
        &self,
        error_code: u32,
        fault_gvaddr: GuestPhysAddr,
    ) -> HvResult<Option<EnclaveExceptionInfo>> {
        let _encl_mem_lock = self.encl_mem_lock.lock();
        {
            let mut secure_gpt = self.gpt.write();
            let pte = match secure_gpt.get_pte_mut(fault_gvaddr) {
                Ok(pte) => pte,
                // Intermediate or terminal Page table is not mapped
                Err(PagingError::NotMapped(_)) => {
                    return Ok(Some(EnclaveExceptionInfo::page_fault_in_encl(
                        error_code,
                        error_code,
                        fault_gvaddr,
                    )));
                }
                _ => {
                    error!("Unexpected Error");
                    return hv_result_err!(EFAULT);
                }
            };

            if pte.is_unused() {
                Ok(Some(EnclaveExceptionInfo::page_fault_in_encl(
                    error_code,
                    error_code,
                    fault_gvaddr,
                )))
            } else {
                EpcmManager::fixup_page_fault(
                    fault_gvaddr,
                    pte,
                    PageFaultErrorCode::from_bits_truncate(error_code),
                )
            }
        }
    }

    #[cfg(feature = "stats")]
    fn print_stats(&self) {
        static LOCK: spin::Mutex<()> = spin::Mutex::new(());
        let _lock = LOCK.lock();

        println!("Enclave {:#x} stats:", self.id);
        println!("  TCS: count = {:?}", self.tcs_count);
        for (i, value) in self.stats.0.iter().enumerate() {
            let id: EnclaveStatsId = unsafe { core::mem::transmute(i) };
            println!("  {:?}: {}", id, value.as_string());
        }
    }

    pub fn reset_stats(&self) {
        #[cfg(feature = "stats")]
        self.print_stats();
        for (i, _) in self.stats.0.iter().enumerate() {
            self.stats.0[i as usize].atomic_reset()
        }
    }
}

impl Drop for Enclave {
    fn drop(&mut self) {
        #[cfg(feature = "stats")]
        self.print_stats();
    }
}

impl Debug for Enclave {
    fn fmt(&self, f: &mut Formatter) -> Result {
        f.debug_struct("Enclave")
            .field("id", &self.id)
            .field("secs_vaddr", &self.secs_vaddr)
            .field("secs", &self.secs())
            .field("elrange", &self.elrange)
            .field("epc_page_num", &self.epc_page_num.load(Ordering::Acquire))
            .field("tcs_count", &self.tcs_count)
            .field("shmem", &self.shmem)
            .finish()
    }
}
