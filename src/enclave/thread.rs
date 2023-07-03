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

use alloc::sync::Arc;
use core::fmt::{Debug, Formatter, Result};

use super::epcm::EpcmManager;
use super::sgx::{SgxTcs, StateSaveArea};
use super::shared_mem::SharedMemSyncType;
use super::{AexException, Enclave, EnclaveStatsId, EnclaveThreadState};
use crate::arch::vmm::VcpuAccessGuestState;
use crate::arch::{
    EnclaveExceptionInfo, EnclavePFErrorCode, GuestPageTableImmut, PageFaultErrorCode,
};
use crate::error::HvResult;
use crate::hypercall::error::HyperCallResult;
use crate::hypercall::PrivilegeLevel;
use crate::memory::addr::{align_down, GuestPhysAddr, GuestVirtAddr};
use crate::memory::gaccess::GuestPtr;
use crate::memory::{GenericPageTableImmut, MemFlags, PagingError, PAGE_SIZE};
use crate::percpu::CpuState;
use crate::stats::Instant;

pub trait VcpuAccessEnclaveState: VcpuAccessGuestState {
    fn load_enclave_thread_state(&self) -> HvResult<EnclaveThreadState>;
    fn store_enclave_thread_state(
        &mut self,
        entry_ip: u64,
        state: &EnclaveThreadState,
        is_enter: bool,
    ) -> HvResult;
}

/// Describes an execution thread of an enclave. Each enclave thread binds a CPU
/// (logical processor) to an enclave.
pub struct EnclaveThread {
    /// Whether The enclave is running.
    is_active: bool,
    /// Guest linear address of TCS.
    tcs_vaddr: GuestVirtAddr,
    /// Guest phyical address of TCS.
    tcs_paddr: GuestPhysAddr,
    /// Guest physical address of SSA.
    ssa_paddr: GuestPhysAddr,
    /// N world states, loaded onto the CPU on enclave exit.
    normal_world_state: EnclaveThreadState,
}

impl EnclaveThread {
    pub fn new() -> Self {
        Self {
            is_active: false,
            tcs_vaddr: 0,
            tcs_paddr: 0,
            ssa_paddr: 0,
            normal_world_state: Default::default(),
        }
    }

    pub fn enter(
        &mut self,
        tcs_vaddr: GuestVirtAddr,
        aep: u64,
        vcpu: &mut impl VcpuAccessEnclaveState,
        gpt: &GuestPageTableImmut,
        cpu_state: &CpuState,
    ) -> HyperCallResult<Arc<Enclave>> {
        if self.is_active {
            return hypercall_hv_err_result!(EBUSY);
        }

        let now = Instant::now();
        let tcs_paddr = Self::get_tcs_paddr(tcs_vaddr, gpt)?;
        let time_query = now.elapsed();

        let enclave = EpcmManager::get_enclave_out_encl(tcs_paddr, tcs_vaddr)?;
        let tcs: &mut SgxTcs = GuestPtr::gpaddr_to_ref_mut(&tcs_paddr, true)?;

        if !enclave.is_init() {
            return hypercall_hv_err_result!(
                EINVAL,
                "EnclaveThread::enter(): enclave is not initialized"
            );
        }
        let time_get_tcs = now.elapsed();

        let base = enclave.elrange().start as u64;
        let entry_ip = base + tcs.oentry;
        let fs_base = base + tcs.ofs_base;
        let gs_base = base + tcs.ogs_base;

        let mut ssa_ptr =
            StateSaveArea::ssa_ptr(&enclave, tcs, tcs.cssa, cpu_state, PrivilegeLevel::User)?;
        let ssa = ssa_ptr.as_mut()?;
        let ssa_paddr = GuestPtr::ref_to_gpaddr(ssa);

        let mut gpr = &mut ssa.gpr;

        let time_get_ssa = now.elapsed();

        tcs.aep = aep;
        gpr.urbp = vcpu.frame_pointer();
        gpr.ursp = vcpu.stack_pointer();
        self.normal_world_state = vcpu.load_enclave_thread_state()?;
        EnclaveThreadState::enclave_enter(
            vcpu,
            entry_ip,
            fs_base,
            gs_base,
            enclave.secs().attributes.xfrm,
            tcs.cssa,
            enclave.nested_page_table_root(),
            enclave.page_table_root(),
        )?;

        self.is_active = true;
        self.tcs_vaddr = tcs_vaddr;
        self.tcs_paddr = tcs_paddr;
        self.ssa_paddr = ssa_paddr;

        let time_total = now.elapsed();

        enclave.atomic_add_stats(EnclaveStatsId::EnterPageWalk, time_query);
        enclave.atomic_add_stats(EnclaveStatsId::EnterGetTcs, time_get_tcs - time_query);
        enclave.atomic_add_stats(EnclaveStatsId::EnterGetSsa, time_get_ssa - time_get_tcs);
        enclave.atomic_add_stats(EnclaveStatsId::EnterSwitchState, time_total - time_get_ssa);
        Ok(enclave)
    }

    pub fn resume(
        &mut self,
        tcs_vaddr: GuestVirtAddr,
        aep: u64,
        vcpu: &mut impl VcpuAccessEnclaveState,
        gpt: &GuestPageTableImmut,
        cpu_state: &CpuState,
    ) -> HyperCallResult<Arc<Enclave>> {
        if self.is_active {
            return hypercall_hv_err_result!(EBUSY);
        }

        let tcs_paddr = Self::get_tcs_paddr(tcs_vaddr, gpt)?;
        let now = Instant::now();

        let enclave = EpcmManager::get_enclave_out_encl(tcs_paddr, tcs_vaddr)?;
        let tcs: &mut SgxTcs = GuestPtr::gpaddr_to_ref_mut(&tcs_paddr, true)?;

        if !enclave.is_init() {
            return hypercall_hv_err_result!(
                EINVAL,
                "EnclaveThread::enter(): enclave is not in initialized state"
            );
        }
        if tcs.cssa == 0 {
            return hypercall_hv_err_result!(EIO, "EnclaveThread::resume(): tcs.cssa == 0");
        }
        let time_get_tcs = now.elapsed();

        let mut ssa_ptr =
            StateSaveArea::ssa_ptr(&enclave, tcs, tcs.cssa - 1, cpu_state, PrivilegeLevel::User)?;
        let ssa = ssa_ptr.as_mut()?;
        let ssa_paddr = GuestPtr::ref_to_gpaddr(ssa);
        let time_get_ssa = now.elapsed();

        let mut ssa_misc = &mut ssa.misc;
        if (ssa_misc.exinfo.errcd & EnclavePFErrorCode::SHARED_MEM_FETCH.bits()) != 0 {
            let fault_gvaddr = ssa_misc.exinfo.maddr as usize;
            let start_addr = align_down(fault_gvaddr);
            let end_addr = start_addr + PAGE_SIZE;
            enclave.sync_shared_memory(&SharedMemSyncType::Valid(start_addr..end_addr), gpt)?;
            ssa_misc.exinfo.maddr = 0;
            ssa_misc.exinfo.errcd = 0;
        }

        self.normal_world_state = vcpu.load_enclave_thread_state()?;
        EnclaveThreadState::enclave_resume(
            vcpu,
            enclave.secs().attributes.xfrm,
            enclave.nested_page_table_root(),
            enclave.page_table_root(),
            ssa,
        )?;
        tcs.aep = aep;
        tcs.cssa -= 1;

        self.is_active = true;
        self.tcs_vaddr = tcs_vaddr;
        self.tcs_paddr = tcs_paddr;
        self.ssa_paddr = ssa_paddr;

        enclave.atomic_add_stats(EnclaveStatsId::ResumeGetTcs, time_get_tcs);
        enclave.atomic_add_stats(EnclaveStatsId::ResumeGetSsa, time_get_ssa - time_get_tcs);
        Ok(enclave)
    }

    pub fn exit(
        &mut self,
        exit_ip: u64,
        vcpu: &mut impl VcpuAccessEnclaveState,
    ) -> HvResult<Arc<Enclave>> {
        if !self.is_active {
            return hv_result_err!(EIO);
        }
        let enclave = EpcmManager::get_enclave_in_encl(self.tcs_paddr)?;
        let tcs: &mut SgxTcs = GuestPtr::gpaddr_to_ref_mut(&self.tcs_paddr, true)?;
        EnclaveThreadState::enclave_exit(vcpu, exit_ip, tcs.aep, &self.normal_world_state)?;

        self.is_active = false;
        self.tcs_vaddr = 0;
        self.tcs_paddr = 0;
        self.ssa_paddr = 0;

        Ok(enclave)
    }

    /// Asynchronous Enclave eXit.
    pub fn aex(
        &mut self,
        aex_excep: AexException,
        vcpu: &mut impl VcpuAccessEnclaveState,
    ) -> HvResult<Arc<Enclave>> {
        if !self.is_active {
            return hv_result_err!(EIO);
        }
        let enclave = EpcmManager::get_enclave_in_encl(self.tcs_paddr)?;
        let tcs: &mut SgxTcs = GuestPtr::gpaddr_to_ref_mut(&self.tcs_paddr, true)?;
        let mut ssa = GuestPtr::gpaddr_to_ref_mut(&self.ssa_paddr, true)?;
        EnclaveThreadState::enclave_aex(
            vcpu,
            aex_excep,
            tcs.aep,
            enclave.secs().attributes.xfrm,
            self.tcs_vaddr,
            &mut ssa,
            &self.normal_world_state,
        )?;
        tcs.cssa += 1;

        self.is_active = false;
        self.tcs_vaddr = 0;
        self.tcs_paddr = 0;
        self.ssa_paddr = 0;

        Ok(enclave)
    }

    pub fn get_current_enclave(&self) -> HvResult<Arc<Enclave>> {
        if !self.is_active {
            return hv_result_err!(
                EINVAL,
                format!("EnclaveThread::get_current_enclave(): CPU is not running in enclave mode")
            );
        }
        EpcmManager::get_enclave_in_encl(self.tcs_paddr)
    }

    pub fn get_ssa_paddr(&self) -> usize {
        self.ssa_paddr
    }

    fn get_tcs_paddr(
        tcs_vaddr: GuestVirtAddr,
        gpt: &GuestPageTableImmut,
    ) -> HyperCallResult<GuestPhysAddr> {
        match gpt.query(tcs_vaddr) {
            Ok((paddr, flags, _page_size)) => {
                if !flags.contains(MemFlags::READ) || !flags.contains(MemFlags::WRITE) {
                    return Err(hypercall_excep_err!(
                        EnclaveExceptionInfo::page_fault_out_encl(
                            (PageFaultErrorCode::CAUSED_BY_WRITE
                                | PageFaultErrorCode::USER_MODE
                                | PageFaultErrorCode::PROTECTION_VIOLATION)
                                .bits(),
                            tcs_vaddr
                        ),
                        format!(
                            "EnclaveThread::get_tcs_paddr(): TCS page's premission is not R/W, \
                            vaddr: {:#x?}, paddr: {:#x?}, mem flags: {:?}",
                            tcs_vaddr, paddr, flags
                        )
                    ));
                }
                Ok(paddr)
            }
            Err(PagingError::NotPresent(_)) | Err(PagingError::NotMapped(_)) => {
                Err(hypercall_excep_err!(
                    EnclaveExceptionInfo::page_fault_out_encl(
                        (PageFaultErrorCode::CAUSED_BY_WRITE | PageFaultErrorCode::USER_MODE)
                            .bits(),
                        tcs_vaddr
                    ),
                    format!(
                        "EnclaveThread::get_tcs_paddr(): Cannot get paddr from vaddr: {:#x?} for TCS page",
                        tcs_vaddr
                    )
                ))
            }
            Err(e) => {
                hypercall_hv_err_result!(
                    EFAULT,
                    format!(
                        "EnclaveThread::get_tcs_paddr(): Hypervisor encounters error, e: {:?}",
                        e
                    )
                )
            }
        }
    }
}

impl Debug for EnclaveThread {
    fn fmt(&self, f: &mut Formatter) -> Result {
        if self.is_active {
            f.debug_struct("EnclaveThread")
                .field("tcs_vaddr", &self.tcs_vaddr)
                .field("tcs_paddr", &self.tcs_paddr)
                .field("ssa_paddr", &self.ssa_paddr)
                .field("normal_world_state", &self.normal_world_state)
                .finish()
        } else {
            write!(f, "Inactive")
        }
    }
}
