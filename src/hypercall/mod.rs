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

#[macro_use]
pub mod error;

mod enclave;
pub mod tc;

use core::convert::TryFrom;
use core::sync::atomic::{AtomicUsize, Ordering};

use bit_field::BitField;
use numeric_enum_macro::numeric_enum;

use crate::arch::vmm::VcpuAccessGuestState;
use crate::arch::{EnclaveExceptionInfo, GuestPageTableImmut};
use crate::memory::gaccess::AsGuestPtr;
use crate::percpu::{CpuState, PerCpu};

use self::error::HyperCallResult;

numeric_enum! {
    #[repr(u32)]
    #[derive(Debug, Eq, PartialEq, Copy, Clone)]
    pub enum HyperCallCode {
        HypervisorDisable = 0,
        EnclaveCreate = 0x10,
        EnclaveAddPage = 0x11,
        EnclaveInit = 0x12,
        EnclavePrepareDestroy = 0x13,
        EnclaveFinishDestroy = 0x14,
        TpmCmdSync = 0x16,
        EnclaveAddVersionArray = 0x18,
        EnclaveBlock = 0x19,
        EnclaveLoadUnblocked = 0x20,
        EnclaveTrack = 0x21,
        EnclaveWriteBack = 0x22,
        EnclaveReclaimPages = 0x23,
        EnclaveAugmentPage = 0x24,
        EnclaveModifyPageType = 0x25,
        EnlcaveRestrictPagePerm = 0x26,
        EnclaveRemovePageAtRuntime = 0x27,
        EnclaveRemovePagesAtDestroy = 0x28,
        EnclaveResetStats = 0x100,
        SharedMemoryAdd = 0x101,
        SharedMemoryRemove = 0x102,
        SharedMemoryInvalidStart = 0x103,
        SharedMemoryInvalidEnd = 0x104,

        InitCmrm = 0x200,
        SetInitCmrmDone = 0x201,

        EnclaveEnter            = 0x8000_0000,
        EnclaveExit             = 0x8000_0001,
        EnclaveAccept           = 0x8000_0002,
        EnclaveAcceptCopy       = 0x8000_0003,
        EnclaveExtendPagePerm   = 0x8000_0004,
        EnclaveResume           = 0x8000_0005,
        EnclaveReport           = 0x8000_000c,
        EnclaveQuote            = 0x8000_000d,
        EnclaveGetKey           = 0x8000_000b,
        EnclaveVerifyReport     = 0x8000_000a,

        HypervisorGetPubKeys = 0x8000_4000,
        HypervisorSignCSR = 0x8000_4001,
        HypervisorWriteCert =0x8000_4002,
        HypervisorActivateCredential =0x8000_4003,
    }
}

impl HyperCallCode {
    fn privilege_level(self) -> PrivilegeLevel {
        if (self as u32).get_bits(30..32) == 0 {
            PrivilegeLevel::Supervisor
        } else {
            PrivilegeLevel::User
        }
    }

    fn validate_state(&self, cpu_state: &CpuState) -> bool {
        match *self {
            HyperCallCode::HypervisorDisable
            | HyperCallCode::EnclaveCreate
            | HyperCallCode::EnclaveAddPage
            | HyperCallCode::EnclaveInit
            | HyperCallCode::EnclavePrepareDestroy
            | HyperCallCode::EnclaveFinishDestroy
            | HyperCallCode::TpmCmdSync
            | HyperCallCode::EnclaveAddVersionArray
            | HyperCallCode::EnclaveBlock
            | HyperCallCode::EnclaveLoadUnblocked
            | HyperCallCode::EnclaveTrack
            | HyperCallCode::EnclaveWriteBack
            | HyperCallCode::EnclaveReclaimPages
            | HyperCallCode::EnclaveAugmentPage
            | HyperCallCode::EnclaveModifyPageType
            | HyperCallCode::EnlcaveRestrictPagePerm
            | HyperCallCode::EnclaveRemovePageAtRuntime
            | HyperCallCode::EnclaveRemovePagesAtDestroy
            | HyperCallCode::EnclaveResetStats
            | HyperCallCode::SharedMemoryAdd
            | HyperCallCode::SharedMemoryRemove
            | HyperCallCode::SharedMemoryInvalidStart
            | HyperCallCode::SharedMemoryInvalidEnd
            | HyperCallCode::InitCmrm
            | HyperCallCode::SetInitCmrmDone
            | HyperCallCode::EnclaveEnter
            | HyperCallCode::EnclaveResume
            | HyperCallCode::EnclaveQuote
            | HyperCallCode::HypervisorGetPubKeys
            | HyperCallCode::HypervisorSignCSR
            | HyperCallCode::HypervisorWriteCert
            | HyperCallCode::HypervisorActivateCredential => *cpu_state == CpuState::HvEnabled,

            HyperCallCode::EnclaveExit
            | HyperCallCode::EnclaveAccept
            | HyperCallCode::EnclaveAcceptCopy
            | HyperCallCode::EnclaveExtendPagePerm
            | HyperCallCode::EnclaveReport
            | HyperCallCode::EnclaveGetKey
            | HyperCallCode::EnclaveVerifyReport => *cpu_state == CpuState::EnclaveRunning,
        }
    }
}

/// PrivilegeLevel describes the current privilege for the enclave's hypercall.
///
/// - PrivilegeLevel::Supervisor: Issued by privilege software, e.g. driver.
/// - PrivilegeLevel::User: Issued by user mode.

// PrivilegeLevel is not changed across hypercall, so we derive the `Copy` trait here.
#[derive(Debug, PartialEq, Clone, Copy)]
pub enum PrivilegeLevel {
    Supervisor,
    User,
}

pub struct HyperCall<'a> {
    cpu_data: &'a mut PerCpu,
    gpt: GuestPageTableImmut,
}

impl<'a> HyperCall<'a> {
    pub fn new(cpu_data: &'a mut PerCpu) -> Self {
        Self {
            gpt: cpu_data.vcpu.guest_page_table(),
            cpu_data,
        }
    }

    pub fn privilege_level(&self) -> PrivilegeLevel {
        if self.cpu_data.vcpu.guest_is_privileged() {
            PrivilegeLevel::Supervisor
        } else {
            PrivilegeLevel::User
        }
    }

    /// Handle the hypercall invoked by guest.
    ///
    /// In Hyper Enclave, all the hypercalls may:
    /// 1. Return value for success or fail;
    /// 2. Cause exceptions.
    ///
    /// The return value `Option<EnclaveExceptionInfo>` stores the result of hypercall's execution.
    ///
    /// If the hypercall returns value, such function sets the return value for guest,
    /// and returns `None` to its caller.
    ///
    /// If the hypercall causes exception,
    /// such function returns the infomation of the exception to its caller,
    /// by setting the result as `Some(EnclaveExceptionInfo)`.
    ///
    pub fn hypercall(&mut self, code: u32, arg0: u64, arg1: u64) -> Option<EnclaveExceptionInfo> {
        let code = match HyperCallCode::try_from(code) {
            Ok(code) => code,
            Err(_) => {
                warn!("Hypercall not supported: {}", code);
                return None;
            }
        };

        let code_privilege_level = code.privilege_level();
        let guest_privilege_level = self.privilege_level();
        if code_privilege_level != guest_privilege_level {
            warn!("Instruction privilege mismatch, code privilege level: {:?} guest privilege level {:?}", code.privilege_level(), guest_privilege_level);
            return Some(EnclaveExceptionInfo::invalid_opcode(
                self.cpu_data.state == CpuState::EnclaveRunning,
            ));
        }

        if !code.validate_state(&self.cpu_data.state) {
            return Some(EnclaveExceptionInfo::invalid_opcode(
                self.cpu_data.state == CpuState::EnclaveRunning,
            ));
        }

        let ret = match code {
            HyperCallCode::HypervisorDisable => self.hypervisor_disable(arg0),
            HyperCallCode::EnclaveCreate => {
                self.enclave_create(arg0.as_guest_ptr_ns(&self.gpt, guest_privilege_level))
            }
            HyperCallCode::EnclaveAddPage => {
                self.enclave_add_page(arg0.as_guest_ptr_ns(&self.gpt, guest_privilege_level))
            }
            HyperCallCode::EnclaveInit => {
                self.enclave_init(arg0.as_guest_ptr_ns(&self.gpt, guest_privilege_level))
            }
            HyperCallCode::EnclavePrepareDestroy => {
                self.enclave_prepare_destroy(arg0.as_guest_ptr_ns(&self.gpt, guest_privilege_level))
            }
            HyperCallCode::EnclaveFinishDestroy => {
                self.enclave_finish_destroy(arg0.as_guest_ptr_ns(&self.gpt, guest_privilege_level))
            }
            HyperCallCode::TpmCmdSync => self.tpm_command_sync(arg0),
            HyperCallCode::EnclaveAddVersionArray => self.enclave_add_version_array(
                arg0.as_guest_ptr_ns(&self.gpt, guest_privilege_level),
                arg1,
            ),
            HyperCallCode::EnclaveBlock => {
                self.enclave_block(arg0.as_guest_ptr_ns(&self.gpt, guest_privilege_level))
            }
            HyperCallCode::EnclaveTrack => {
                self.enclave_track(arg0.as_guest_ptr_ns(&self.gpt, guest_privilege_level))
            }
            HyperCallCode::EnclaveWriteBack => self
                .enclave_write_back(arg0.as_guest_ptr_ns(&self.gpt, guest_privilege_level), arg1),
            HyperCallCode::EnclaveLoadUnblocked => self.enclave_load_unblocked(
                arg0.as_guest_ptr_ns(&self.gpt, guest_privilege_level),
                arg1,
            ),
            HyperCallCode::EnclaveReclaimPages => {
                self.reclaim_encl_pages(arg0.as_guest_ptr_ns(&self.gpt, guest_privilege_level))
            }
            HyperCallCode::EnclaveAugmentPage => {
                self.enclave_augment_page(arg0.as_guest_ptr_ns(&self.gpt, guest_privilege_level))
            }
            HyperCallCode::EnclaveModifyPageType => self
                .enclave_modify_page_type(arg0.as_guest_ptr_ns(&self.gpt, guest_privilege_level)),
            HyperCallCode::EnlcaveRestrictPagePerm => self
                .enclave_restrict_page_perm(arg0.as_guest_ptr_ns(&self.gpt, guest_privilege_level)),
            HyperCallCode::EnclaveRemovePageAtRuntime => self.enclave_remove_page_at_runtime(
                arg0.as_guest_ptr_ns(&self.gpt, guest_privilege_level),
            ),
            HyperCallCode::EnclaveRemovePagesAtDestroy => self.enclave_remove_pages_at_destroy(
                arg0.as_guest_ptr_ns(&self.gpt, guest_privilege_level),
            ),
            HyperCallCode::EnclaveResetStats => {
                self.enclave_reset_stats(arg0.as_guest_ptr_ns(&self.gpt, guest_privilege_level))
            }
            HyperCallCode::SharedMemoryAdd => self
                .enclave_shared_memory_add(arg0.as_guest_ptr_ns(&self.gpt, guest_privilege_level)),
            HyperCallCode::SharedMemoryRemove => self.enclave_shared_memory_remove(
                arg0.as_guest_ptr_ns(&self.gpt, guest_privilege_level),
            ),
            HyperCallCode::SharedMemoryInvalidStart => self.enclave_shared_memory_invalid_start(
                arg0.as_guest_ptr_ns(&self.gpt, guest_privilege_level),
            ),
            HyperCallCode::SharedMemoryInvalidEnd => self.enclave_shared_memory_invalid_end(
                arg0.as_guest_ptr_ns(&self.gpt, guest_privilege_level),
            ),
            HyperCallCode::InitCmrm => self.init_cmrm(arg0),
            HyperCallCode::SetInitCmrmDone => self.set_init_cmrm_done(),
            HyperCallCode::EnclaveEnter => self.enclave_enter(),
            HyperCallCode::EnclaveExit => self.enclave_exit(),
            HyperCallCode::EnclaveAccept => self.enclave_accept(),
            HyperCallCode::EnclaveAcceptCopy => self.enclave_accept_copy(),
            HyperCallCode::EnclaveExtendPagePerm => self.enclave_extend_page_perm(),
            HyperCallCode::EnclaveResume => self.enclave_resume(),
            HyperCallCode::EnclaveReport => self.enclave_report(),
            HyperCallCode::EnclaveQuote => self.enclave_quote(),
            HyperCallCode::EnclaveGetKey => self.enclave_getkey(),
            HyperCallCode::HypervisorGetPubKeys => self.get_pub_keys(),
            HyperCallCode::HypervisorSignCSR => self.sign_csr(),
            HyperCallCode::HypervisorWriteCert => self.mng_tpm_cert(),
            HyperCallCode::EnclaveVerifyReport => self.verify_report(),
            HyperCallCode::HypervisorActivateCredential => self.activate_credential(),
        };

        debug!("HyperCall: {:?} <= {:x?}", code, ret);

        if code.privilege_level() == PrivilegeLevel::User {
            match ret {
                Ok(_) => {}
                Err(err) => match err.error() {
                    error::HyperCallErrorType::HvError(_) => {
                        warn!(
                            "Hypercall: {:?} encounters hypervisor error: {:?}, inject #GP",
                            code, err
                        );
                        return Some(EnclaveExceptionInfo::general_protection(
                            0,
                            &self.cpu_data.state,
                        ));
                    }
                    error::HyperCallErrorType::EnclaveError(err_code) => {
                        self.cpu_data.vcpu.set_return_val(err_code.code() as _)
                    }
                    error::HyperCallErrorType::Exception(info) => return Some(*info),
                },
            };
        } else {
            match ret {
                Ok(ret) => self.cpu_data.vcpu.set_return_val(ret),
                Err(err) => match err.error() {
                    error::HyperCallErrorType::HvError(_) => {
                        warn!(
                            "Hypercall: {:?} encounters hypervisor error: {:?}",
                            code, err
                        );
                        return Some(EnclaveExceptionInfo::general_protection(
                            0,
                            &self.cpu_data.state,
                        ));
                    }
                    error::HyperCallErrorType::EnclaveError(err_code) => {
                        self.cpu_data.vcpu.set_return_val(err_code.code() as _)
                    }
                    error::HyperCallErrorType::Exception(info) => {
                        warn!(
                            "Hypercall: {:?} from kernel encounters hypervisor exception: {:?} err: {:?}",
                            code, info, err
                        );
                        return Some(*info);
                    }
                },
            };
        }

        None
    }

    fn hypervisor_disable(&mut self, all: u64) -> HyperCallResult<usize> {
        if all != 0 && all != 1 {
            return hypercall_hv_err_result!(EINVAL);
        }

        static TRY_DISABLE_CPUS: AtomicUsize = AtomicUsize::new(0);
        let cpus = PerCpu::activated_cpus();
        let is_primary = TRY_DISABLE_CPUS.fetch_add(1, Ordering::SeqCst) == 0;

        if is_primary {
            crate::iommu::disable()?;
        }
        if all == 1 {
            while TRY_DISABLE_CPUS.load(Ordering::Acquire) < cpus {
                core::hint::spin_loop();
            }
        }

        self.cpu_data.deactivate_vmm(0)?;
        unreachable!();
    }
}
