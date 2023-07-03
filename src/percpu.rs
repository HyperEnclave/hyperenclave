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
use core::mem::size_of;
use core::sync::atomic::{AtomicIsize, Ordering};

use crate::arch::vmm::{Vcpu, VcpuAccessGuestState};
use crate::arch::{ExceptionType, HostPageTable, LinuxContext};
use crate::cell::Cell;
use crate::consts::{HV_STACK_SIZE, LOCAL_PER_CPU_BASE};
use crate::enclave::epcm::EpcmManager;
use crate::enclave::{sgx::MiscSgx, AexException, Enclave, EnclaveStatsId, EnclaveThread};
use crate::error::HvResult;
use crate::ffi::PER_CPU_ARRAY_PTR;
use crate::header::HvHeader;
use crate::hypercall::error::HyperCallResult;
use crate::logging;
use crate::memory::addr::{virt_to_phys, GuestVirtAddr};
use crate::memory::{GenericPageTable, MemFlags, MemoryRegion, MemorySet};
use crate::stats::Instant;

pub const PER_CPU_SIZE: usize = size_of::<PerCpu>();

static ACTIVATED_CPUS: AtomicIsize = AtomicIsize::new(0);

#[derive(Debug, Eq, PartialEq)]
pub enum CpuState {
    HvDisabled,
    HvEnabled,
    EnclaveRunning,
}

#[repr(align(4096))]
pub struct PerCpu {
    pub cpu_id: usize,
    pub state: CpuState,
    pub vcpu: Vcpu,
    stack: [usize; HV_STACK_SIZE / size_of::<usize>()],
    linux: LinuxContext,
    hvm: MemorySet<HostPageTable>,
    enclave_thread: EnclaveThread,
}

impl PerCpu {
    pub fn from_id<'a>(cpu_id: usize) -> &'a Self {
        unsafe {
            &core::slice::from_raw_parts(PER_CPU_ARRAY_PTR, HvHeader::get().max_cpus as usize)
                [cpu_id]
        }
    }

    pub fn from_id_mut<'a>(cpu_id: usize) -> &'a mut Self {
        unsafe {
            &mut core::slice::from_raw_parts_mut(
                PER_CPU_ARRAY_PTR,
                HvHeader::get().max_cpus as usize,
            )[cpu_id]
        }
    }

    pub fn from_local_base<'a>() -> &'a Self {
        unsafe { &*(LOCAL_PER_CPU_BASE as *const Self) }
    }

    pub fn from_local_base_mut<'a>() -> &'a mut Self {
        unsafe { &mut *(LOCAL_PER_CPU_BASE as *mut Self) }
    }

    pub fn stack_top(&self) -> usize {
        self.stack.as_ptr_range().end as _
    }

    pub fn activated_cpus() -> usize {
        ACTIVATED_CPUS.load(Ordering::Acquire) as _
    }

    pub fn init(&mut self, cpu_id: usize, linux_sp: usize, cell: &Cell) -> HvResult {
        info!("CPU {} init...", cpu_id);

        self.cpu_id = cpu_id;
        self.state = CpuState::HvDisabled;
        self.linux = LinuxContext::load_from(linux_sp);

        let mut hvm = cell.hvm.clone();
        let vaddr = self as *const _ as usize;
        let paddr = virt_to_phys(vaddr);
        // Temporary mapping, will remove in Self::activate_vmm()
        hvm.insert(MemoryRegion::new_with_offset_mapper(
            vaddr,
            paddr,
            PER_CPU_SIZE,
            MemFlags::READ | MemFlags::WRITE | MemFlags::ENCRYPTED,
        ))?;
        hvm.insert(MemoryRegion::new_with_offset_mapper(
            LOCAL_PER_CPU_BASE,
            paddr,
            PER_CPU_SIZE,
            MemFlags::READ | MemFlags::WRITE | MemFlags::ENCRYPTED,
        ))?;
        trace!("PerCpu host virtual memory set: {:#x?}", hvm);
        unsafe {
            // avoid dropping, same below
            core::ptr::write(&mut self.hvm, hvm);
            core::ptr::write(&mut self.enclave_thread, EnclaveThread::new());
            self.hvm.activate();
            core::ptr::write(&mut self.vcpu, Vcpu::new(&self.linux, cell)?);
        }

        self.state = CpuState::HvEnabled;
        Ok(())
    }

    pub fn return_to_linux(&self) {
        logging::hhbox_disable();
        self.linux.restore();
    }

    #[inline(never)]
    fn activate_vmm_local(&mut self) -> HvResult {
        self.vcpu.activate_vmm(&self.linux)?;
        unreachable!()
    }

    #[inline(never)]
    fn deactivate_vmm_common(&mut self) -> HvResult {
        self.vcpu.exit(&mut self.linux)?;
        self.return_to_linux();
        self.state = CpuState::HvDisabled;
        self.vcpu.deactivate_vmm(&self.linux)?;
        unreachable!()
    }

    pub fn activate_vmm(&mut self) -> HvResult {
        println!("Activating hypervisor on CPU {}...", self.cpu_id);
        ACTIVATED_CPUS.fetch_add(1, Ordering::SeqCst);
        logging::set_vmm_state(self.cpu_id, 1);

        let local_cpu_data = Self::from_local_base_mut();
        let old_percpu_vaddr = self as *const _ as usize;
        // Switch stack to the private mapping.
        unsafe { asm!("add rsp, {}", in(reg) LOCAL_PER_CPU_BASE - old_percpu_vaddr) };
        local_cpu_data.hvm.delete(old_percpu_vaddr)?;
        local_cpu_data.hvm.page_table().flush(None);
        local_cpu_data.activate_vmm_local()
    }

    pub fn deactivate_vmm(&mut self, ret_code: usize) -> HvResult {
        println!("Deactivating hypervisor on CPU {}...", self.cpu_id);
        ACTIVATED_CPUS.fetch_add(-1, Ordering::SeqCst);
        logging::set_vmm_state(self.cpu_id, 0);

        self.vcpu.set_return_val(ret_code);

        // Restore full per_cpu region access so that we can switch
        // back to the common stack mapping and to Linux page tables.
        let common_cpu_data = Self::from_id_mut(self.cpu_id);
        let common_percpu_vaddr = common_cpu_data as *const _ as usize;

        let paddr = virt_to_phys(common_percpu_vaddr);
        self.hvm.insert(MemoryRegion::new_with_offset_mapper(
            common_percpu_vaddr,
            paddr,
            PER_CPU_SIZE,
            MemFlags::READ | MemFlags::WRITE | MemFlags::ENCRYPTED,
        ))?;
        self.hvm.page_table().flush(None);
        unsafe { asm!("add rsp, {}", in(reg) common_percpu_vaddr - LOCAL_PER_CPU_BASE) };
        common_cpu_data.deactivate_vmm_common()
    }

    pub fn fault(&mut self) -> HvResult {
        warn!("VCPU fault: {:#x?}", self);
        if self.state == CpuState::EnclaveRunning {
            let aex_excep = AexException {
                vec: ExceptionType::GeneralProtectionFault,
                misc: Some(MiscSgx::new(0, 0)),
            };
            if let Err(e) = self.enclave_aex(aex_excep) {
                warn!("PerCpu::fault(): AEX failed, error: {:?}", e);
            }
            self.state = CpuState::HvEnabled;
        }
        self.vcpu.inject_fault()?;
        Ok(())
    }

    pub fn enclave_enter(
        &mut self,
        tcs_vaddr: GuestVirtAddr,
        aep: u64,
    ) -> HyperCallResult<Arc<Enclave>> {
        if self.state == CpuState::EnclaveRunning {
            return hypercall_hv_err_result!(
                EBUSY,
                format!(
                    "PerCpu::enclave_enter(): CPU {} is already running in enclave mode",
                    self.cpu_id
                )
            );
        }
        let gpt = self.vcpu.guest_page_table();
        let enclave =
            self.enclave_thread
                .enter(tcs_vaddr, aep, &mut self.vcpu, &gpt, &self.state)?;
        let now = Instant::now();
        enclave.update_tracking_state(true, self.cpu_id);
        let time_update = now.elapsed();
        // Currently, the latency of EENTER is much less than EWB, clear ssa pages's
        // BLOCKED state when switch to enclave mode in case ssa pages are reclaimed.
        EpcmManager::clear_blocked(self.enclave_thread.get_ssa_paddr());
        let time_clear_blocked = now.elapsed();
        self.state = CpuState::EnclaveRunning;
        enclave.atomic_add_stats(EnclaveStatsId::EnterUpdateTrackingState, time_update);
        enclave.atomic_add_stats(
            EnclaveStatsId::EnterClearBlocked,
            time_clear_blocked - time_update,
        );
        Ok(enclave)
    }

    pub fn enclave_resume(
        &mut self,
        tcs_vaddr: GuestVirtAddr,
        aep: u64,
    ) -> HyperCallResult<Arc<Enclave>> {
        debug!(
            "enclave_resume(tcs_vaddr={:#x}, aep={:#x}): {:#x?}",
            tcs_vaddr, aep, self
        );
        if self.state == CpuState::EnclaveRunning {
            return hypercall_hv_err_result!(
                EBUSY,
                format!(
                    "PerCpu::enclave_resume(): CPU {} is already running in enclave mode",
                    self.cpu_id
                )
            );
        }

        let gpt = self.vcpu.guest_page_table();
        let enclave =
            self.enclave_thread
                .resume(tcs_vaddr, aep, &mut self.vcpu, &gpt, &self.state)?;
        let now = Instant::now();
        enclave.update_tracking_state(true, self.cpu_id);
        let time_update = now.elapsed();
        // Currently, the latency of ERESUME is much less than EWB, clear ssa pages's
        // BLOCKED state when switch to enclave mode in case ssa pages are reclaimed.
        EpcmManager::clear_blocked(self.enclave_thread.get_ssa_paddr());
        let time_clear_blocked = now.elapsed();
        self.state = CpuState::EnclaveRunning;
        enclave.atomic_add_stats(EnclaveStatsId::ResumeUpdateTrackingState, time_update);
        enclave.atomic_add_stats(
            EnclaveStatsId::ResumeClearBlocked,
            time_clear_blocked - time_update,
        );
        Ok(enclave)
    }

    pub fn enclave_exit(&mut self, exit_ip: u64) -> HvResult<Arc<Enclave>> {
        if self.state != CpuState::EnclaveRunning {
            return hv_result_err!(
                EINVAL,
                format!(
                    "PerCpu::enclave_exit(): CPU {} is not running in enclave mode",
                    self.cpu_id
                )
            );
        }
        let enclave = self.enclave_thread.exit(exit_ip, &mut self.vcpu)?;
        self.state = CpuState::HvEnabled;
        enclave.update_tracking_state(false, self.cpu_id);
        Ok(enclave)
    }

    pub fn enclave_aex(&mut self, aex_excep: AexException) -> HvResult<Arc<Enclave>> {
        debug!("enclave_aex(aex_excep={:?}): {:#x?}", aex_excep, self);
        if self.state != CpuState::EnclaveRunning {
            return hv_result_err!(
                EINVAL,
                format!(
                    "PerCpu::enclave_aex(): CPU {} is not running in enclave mode",
                    self.cpu_id
                )
            );
        }
        let enclave = self.enclave_thread.aex(aex_excep, &mut self.vcpu)?;
        self.state = CpuState::HvEnabled;
        enclave.update_tracking_state(false, self.cpu_id);
        Ok(enclave)
    }

    pub fn get_current_enclave(&self) -> HvResult<Arc<Enclave>> {
        if self.state != CpuState::EnclaveRunning {
            return hv_result_err!(
                EINVAL,
                format!(
                    "PerCpu::get_current_enclave(): CPU {} is not running in enclave mode",
                    self.cpu_id
                )
            );
        }
        let enclave = self.enclave_thread.get_current_enclave()?;
        Ok(enclave)
    }
}

impl Debug for PerCpu {
    fn fmt(&self, f: &mut Formatter) -> Result {
        let mut res = f.debug_struct("PerCpu");
        res.field("cpu_id", &self.cpu_id)
            .field("state", &self.state);
        if self.state != CpuState::HvDisabled {
            res.field("vcpu", &self.vcpu);
        } else {
            res.field("linux", &self.linux);
        }
        res.field("enclave_thread", &self.enclave_thread).finish()
    }
}
