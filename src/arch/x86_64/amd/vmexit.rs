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

use libvmm::svm::flags::{InterruptType, VmcbCleanBits, VmcbIntInfo};
use libvmm::svm::{NptViolationInfo, SvmExitCode, VmExitInfo};

use crate::arch::vmm::{VcpuAccessGuestState, VmExit};
use crate::arch::{EnclaveExceptionInfo, ExceptionType};
use crate::enclave::{AexException, EnclaveStatsId};
use crate::error::HvResult;
use crate::percpu::CpuState;
use crate::stats::Instant;

impl VmExit<'_> {
    fn handle_nmi(&mut self) -> HvResult {
        unsafe { asm!("cli; stgi; clgi; sti") };
        Ok(())
    }

    fn handle_exception(&mut self, vec: u8, exit_info: &VmExitInfo) -> HvResult {
        info!(
            "#VMEXIT(EXCP {}) @ RIP({:#x}): {:#x?}",
            vec, exit_info.guest_rip, exit_info
        );

        let error_code = if ExceptionType::has_error_code(vec) {
            Some(exit_info.exit_info_1 as u32)
        } else {
            None
        };
        let fault_gvaddr = if vec == ExceptionType::PageFault {
            Some(exit_info.exit_info_2 as usize)
        } else {
            None
        };

        let enclave = self.cpu_data.get_current_enclave()?;
        if let Some(exception_info) = enclave.fixup_exception(vec, error_code, fault_gvaddr)? {
            self.inject_exception(exception_info)
        } else {
            Ok(())
        }
    }

    pub fn inject_exception(&mut self, enclave_exception: EnclaveExceptionInfo) -> HvResult {
        let now = Instant::now();

        // Write the exception information to VMCB.
        {
            let linux_info = enclave_exception.linux_info;
            let error_code = if ExceptionType::has_error_code(linux_info.exception_type) {
                match linux_info.error_code {
                    Some(error_code) => error_code,
                    None => {
                        error!(
                            "VmExit::inject_exception({:#x?}): error_code is None",
                            enclave_exception
                        );
                        return hv_result_err!(EINVAL);
                    }
                }
            } else {
                // Set to default value
                0
            };

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
                self.cpu_data.vcpu.vmcb.save.cr2 = cr2;
                self.cpu_data.vcpu.vmcb.control.clean_bits -= VmcbCleanBits::CR2;
            }

            self.cpu_data.vcpu.vmcb.inject_event(
                VmcbIntInfo::from(InterruptType::Exception, linux_info.exception_type),
                error_code,
            );
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

    fn handle_interrupt(&mut self, exit_info: &VmExitInfo) -> HvResult {
        let now = Instant::now();

        debug!(
            "#VMEXIT(INTR) @ RIP({:#x}): {:#x?}",
            exit_info.guest_rip, exit_info,
        );

        if self.cpu_data.state == CpuState::EnclaveRunning {
            match self.cpu_data.enclave_aex(AexException {
                vec: ExceptionType::IrqStart,
                misc: None,
            }) {
                Ok(enclave) => enclave.atomic_add_stats(EnclaveStatsId::Aex, now.elapsed()),
                Err(e) => {
                    warn!("Enclave AEX failed!: {:x?}", e);
                    self.cpu_data.fault()?;
                }
            }
        } else {
            error!(
                "handle_interrupt cpu state {:?} is wrong",
                self.cpu_data.state
            );
            return hv_result_err!(EINVAL);
        }
        Ok(())
    }

    fn handle_nested_page_fault(&mut self, exit_info: &VmExitInfo) -> HvResult {
        let npt_vio_info = NptViolationInfo::from_exit_info(exit_info);
        if self.cpu_data.state == CpuState::EnclaveRunning {
            let enclave = self.cpu_data.get_current_enclave()?;
            enclave
                .handle_npt_violation(npt_vio_info.guest_paddr, npt_vio_info.final_translation)?;
            return Ok(());
        }
        warn!(
            "#VMEXIT(NPF) @ {:#x?} RIP({:#x?})",
            npt_vio_info, exit_info.guest_rip,
        );
        hv_result_err!(ENOSYS)
    }

    pub fn handle_exit(&mut self) -> HvResult {
        let vcpu = &mut self.cpu_data.vcpu;
        vcpu.regs_mut().rax = vcpu.vmcb.save.rax;

        // All guest state is marked unmodified; individual handlers must clear
        // the bits as needed.
        vcpu.vmcb.control.clean_bits = VmcbCleanBits::UNMODIFIED;

        let exit_info = VmExitInfo::new(&vcpu.vmcb);
        let exit_code = match exit_info.exit_code {
            Ok(code) => code,
            Err(code) => {
                error!("Unknown #VMEXIT exit code: {:#x}", code);
                return hv_result_err!(EIO);
            }
        };

        let res = match exit_code {
            SvmExitCode::INVALID => panic!("VM entry failed: {:#x?}\n{:#x?}", exit_info, vcpu.vmcb),
            SvmExitCode::EXCP(vec) => self.handle_exception(vec, &exit_info),
            SvmExitCode::INTR => self.handle_interrupt(&exit_info),
            SvmExitCode::NMI => self.handle_nmi(),
            SvmExitCode::CPUID => self.handle_cpuid(),
            SvmExitCode::VMMCALL => self.handle_hypercall(),
            SvmExitCode::NPF => self.handle_nested_page_fault(&exit_info),
            SvmExitCode::MSR => match exit_info.exit_info_1 {
                0 => self.handle_msr_read(),
                1 => self.handle_msr_write(),
                _ => hv_result_err!(EIO),
            },
            SvmExitCode::SHUTDOWN => {
                error!("#VMEXIT(SHUTDOWN): {:#x?}", exit_info);
                self.cpu_data.vcpu.inject_fault()?;
                Ok(())
            }
            _ => hv_result_err!(ENOSYS),
        };

        let vcpu = &mut self.cpu_data.vcpu;
        if res.is_err() {
            warn!(
                "#VMEXIT handler returned {:?}:\n\
                {:#x?}\n\n\
                Guest State Dump:\n\
                {:#x?}",
                res, exit_info, vcpu,
            );
        }
        vcpu.vmcb.save.rax = vcpu.regs().rax;
        res
    }
}
