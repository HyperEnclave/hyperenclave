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

use libvmm::msr::Msr;
use libvmm::svm::flags::{VmcbCleanBits, VmcbTlbControl};
use libvmm::svm::SvmIntercept;

use crate::arch::vmm::{Vcpu, VcpuAccessGuestState};
use crate::enclave::{EnclaveThreadState, VcpuAccessEnclaveState};
use crate::error::HvResult;
use crate::memory::addr::align_down;

impl VcpuAccessEnclaveState for Vcpu {
    fn load_enclave_thread_state(&self) -> HvResult<EnclaveThreadState> {
        Ok(EnclaveThreadState {
            rflags: self.rflags(),
            fs_base: self.fs_base(),
            gs_base: self.gs_base(),
            xcr0: self.xcr0(),
            hv_page_table_root: align_down(self.vmcb.control.nest_cr3 as _),
            page_table_root: align_down(self.vmcb.save.cr3 as _),
            efer: self.efer(),
            idtr_base: self.vmcb.save.idtr.base,
            idtr_limit: self.vmcb.save.idtr.limit,
        })
    }

    fn store_enclave_thread_state(
        &mut self,
        entry_ip: u64,
        state: &EnclaveThreadState,
        is_enter: bool,
    ) -> HvResult {
        self.vmcb.save.rip = entry_ip;
        self.vmcb.save.rflags = state.rflags;
        self.vmcb.save.cr3 = state.page_table_root as _;
        self.vmcb.save.idtr.base = state.idtr_base;
        self.vmcb.save.idtr.limit = state.idtr_limit;
        self.vmcb.save.efer = state.efer;

        self.vmcb.control.nest_cr3 = state.hv_page_table_root as _;
        self.vmcb.control.tlb_control = VmcbTlbControl::FlushAsid as _;
        self.vmcb.control.clean_bits -=
            VmcbCleanBits::I | VmcbCleanBits::DT | VmcbCleanBits::NP | VmcbCleanBits::CR_X;

        // Intercept enclave exceptions.
        if is_enter {
            self.vmcb.control.intercept_exceptions = 0xffff_ffff;
        } else {
            self.vmcb.control.intercept_exceptions = 0;
        }

        if cfg!(feature = "enclave_interrupt") {
            // Enable interrupts during enclave running.
            if is_enter {
                self.vmcb.set_intercept(SvmIntercept::INTR, true);
            } else {
                self.vmcb.set_intercept(SvmIntercept::INTR, false);
            }
        }

        self.set_xcr0(state.xcr0);
        unsafe {
            Msr::IA32_FS_BASE.write(state.fs_base);
            Msr::IA32_GS_BASE.write(state.gs_base);
        }
        Ok(())
    }
}
