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

use libvmm::vmx::flags::{InterruptInfo, InterruptType};
use libvmm::vmx::vmcs::{
    EptViolationInfo, ExitInterruptInfo, VmExitInfo, VmcsField32ReadOnly, VmcsField64ReadOnly,
};
use libvmm::vmx::{Vmcs, VmxExitReason};

use crate::arch::vmm::VmExit;
use crate::arch::{EnclaveExceptionInfo, ExceptionType};
use crate::enclave::{AexException, EnclaveStatsId};
use crate::error::HvResult;
use crate::percpu::CpuState;
use crate::stats::Instant;

impl VmExit<'_> {
    fn handle_exception_nmi(&mut self, exit_info: &VmExitInfo) -> HvResult {
        let intr_info = ExitInterruptInfo::new()?;
        info!(
            "VM exit: Exception or NMI @ RIP({:#x}, {}): {:#x?}",
            exit_info.guest_rip, exit_info.exit_instruction_length, intr_info
        );
        match intr_info.vector {
            ExceptionType::NonMaskableInterrupt => unsafe {
                asm!("int {}", const ExceptionType::NonMaskableInterrupt)
            },
            vec => {
                let error_code = if ExceptionType::has_error_code(vec) {
                    Some(VmcsField32ReadOnly::VM_EXIT_INTR_ERROR_CODE.read()?)
                } else {
                    None
                };
                let fault_gvaddr = if vec == ExceptionType::PageFault {
                    Some(VmcsField64ReadOnly::EXIT_QUALIFICATION.read()? as usize)
                } else {
                    None
                };

                let enclave = self.cpu_data.get_current_enclave()?;
                if let Some(exception_info) =
                    enclave.fixup_exception(vec, error_code, fault_gvaddr)?
                {
                    return self.inject_exception(exception_info);
                }
            }
        }
        Ok(())
    }

    fn handle_external_interrupt(&mut self, exit_info: &VmExitInfo) -> HvResult {
        let now = Instant::now();

        let intr_info = ExitInterruptInfo::new()?;
        debug!(
            "VM exit: External interrupt @ RIP({:#x}, {}): {:#x?}",
            exit_info.guest_rip, exit_info.exit_instruction_length, intr_info
        );
        if intr_info.interruption_type != 0 || !intr_info.valid {
            return hv_result_err!(EINVAL);
        }

        let vec = intr_info.vector;
        Vmcs::inject_interrupt(InterruptInfo::from(InterruptType::External, vec), None)?;
        if self.cpu_data.state == CpuState::EnclaveRunning {
            match self.cpu_data.enclave_aex(AexException { vec, misc: None }) {
                Ok(enclave) => enclave.atomic_add_stats(EnclaveStatsId::Aex, now.elapsed()),
                Err(e) => {
                    warn!("Enclave AEX failed!: {:x?}", e);
                    self.cpu_data.fault()?;
                }
            }
        } else {
            error!(
                "handle_external_interrupt cpu state {:?} is wrong",
                self.cpu_data.state
            );
            return hv_result_err!(EINVAL);
        }
        Ok(())
    }

    fn handle_ept_violation(&mut self, exit_info: &VmExitInfo) -> HvResult {
        let ept_vio_info = EptViolationInfo::new()?;
        let guest_paddr = ept_vio_info.guest_paddr;
        if self.cpu_data.state == CpuState::EnclaveRunning {
            let enclave = self.cpu_data.get_current_enclave()?;
            enclave.handle_npt_violation(guest_paddr, ept_vio_info.final_translation)?;
            return Ok(());
        }
        warn!(
            "VM exit: EPT violation @ {:#x} RIP({:#x}, {}): {:#x?}",
            guest_paddr, exit_info.guest_rip, exit_info.exit_instruction_length, ept_vio_info
        );
        hv_result_err!(ENOSYS)
    }

    pub fn inject_exception(&mut self, enclave_exception: EnclaveExceptionInfo) -> HvResult {
        let now = Instant::now();

        // Set VMCS's excepction information
        {
            let linux_info = enclave_exception.linux_info;
            Vmcs::inject_interrupt(
                InterruptInfo::from(InterruptType::HardException, linux_info.exception_type),
                linux_info.error_code,
            )?;

            if linux_info.exception_type == ExceptionType::PageFault {
                let cr2 = match linux_info.cr2 {
                    Some(cr2) => cr2,
                    None => {
                        error!(
                            "VmExit::inject_exception({:#x?}): CR2 is None for #PF",
                            enclave_exception
                        );
                        return hv_result_err!(EINVAL);
                    }
                };
                unsafe { asm!("mov cr2, {}", in(reg) cr2) };
            }
        }

        let aex_excep = if let Some(aex_excep) = enclave_exception.aex_excep {
            aex_excep
        } else {
            // In non-enclave mode
            return Ok(());
        };

        // In enclave mode
        if self.cpu_data.state == CpuState::EnclaveRunning {
            match self.cpu_data.enclave_aex(aex_excep) {
                Ok(enclave) => enclave.atomic_add_stats(EnclaveStatsId::Aex, now.elapsed()),
                Err(e) => {
                    warn!("Enclave AEX failed!: {:x?}", e);
                    self.cpu_data.fault()?;
                }
            }
        } else {
            error!(
                "handle_exception cpu state {:?} is wrong",
                self.cpu_data.state
            );
            return hv_result_err!(EINVAL);
        }

        Ok(())
    }

    pub fn handle_exit(&mut self) -> HvResult {
        let exit_info = VmExitInfo::new()?;
        trace!("VM exit: {:#x?}", exit_info);

        if exit_info.entry_failure {
            panic!("VM entry failed: {:#x?}", exit_info);
        }
        // self.test_read_guest_memory(
        //     exit_info.guest_rip as _,
        //     exit_info.exit_instruction_length as _,
        // )?;

        let res = match exit_info.exit_reason {
            VmxExitReason::EXCEPTION_NMI => self.handle_exception_nmi(&exit_info),
            VmxExitReason::EXTERNAL_INTERRUPT => self.handle_external_interrupt(&exit_info),
            VmxExitReason::CPUID => self.handle_cpuid(),
            VmxExitReason::VMCALL => self.handle_hypercall(),
            VmxExitReason::MSR_READ => self.handle_msr_read(),
            VmxExitReason::MSR_WRITE => self.handle_msr_write(),
            VmxExitReason::EPT_VIOLATION => self.handle_ept_violation(&exit_info),
            VmxExitReason::TRIPLE_FAULT => {
                error!("Triple fault: {:#x?}", exit_info);
                self.cpu_data.vcpu.inject_fault()?;
                Ok(())
            }
            _ => hv_result_err!(ENOSYS),
        };

        if res.is_err() {
            warn!(
                "VM exit handler for reason {:?} returned {:?}:\n\
                {:#x?}\n\n\
                Guest State Dump:\n\
                {:#x?}",
                exit_info.exit_reason, res, exit_info, self.cpu_data.vcpu,
            );
        }
        res
    }
}
