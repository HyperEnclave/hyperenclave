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

use libvmm::vmx::vmcs::{
    VmcsField32Control, VmcsField32Guest, VmcsField64Control, VmcsField64Guest,
};

use crate::arch::vmm::{Vcpu, VcpuAccessGuestState};
use crate::enclave::{EnclaveThreadState, VcpuAccessEnclaveState};
use crate::error::HvResult;
use crate::memory::addr::align_down;

use super::ept::EPTInstr;

impl VcpuAccessEnclaveState for Vcpu {
    fn load_enclave_thread_state(&self) -> HvResult<EnclaveThreadState> {
        Ok(EnclaveThreadState {
            rflags: self.rflags(),
            fs_base: self.fs_base(),
            gs_base: self.gs_base(),
            xcr0: self.xcr0(),
            hv_page_table_root: align_down(VmcsField64Control::EPT_POINTER.read()? as _),
            page_table_root: align_down(VmcsField64Guest::CR3.read()? as _),
            efer: self.efer(),
            idtr_base: VmcsField64Guest::IDTR_BASE.read()?,
            idtr_limit: VmcsField32Guest::IDTR_LIMIT.read()?,
        })
    }

    fn store_enclave_thread_state(
        &mut self,
        entry_ip: u64,
        state: &EnclaveThreadState,
        is_enter: bool,
    ) -> HvResult {
        VmcsField64Guest::RIP.write(entry_ip)?;
        VmcsField64Guest::RFLAGS.write(state.rflags)?;
        VmcsField64Guest::FS_BASE.write(state.fs_base)?;
        VmcsField64Guest::GS_BASE.write(state.gs_base)?;
        self.set_xcr0(state.xcr0);

        // Switch EPT.
        EPTInstr::set_ept_pointer(state.hv_page_table_root)?;
        // Switch page table.
        VmcsField64Guest::CR3.write(state.page_table_root as _)?;

        // Switch syscall entry point and IDT.
        VmcsField64Guest::IA32_EFER.write(state.efer)?;
        VmcsField64Guest::IDTR_BASE.write(state.idtr_base)?;
        VmcsField32Guest::IDTR_LIMIT.write(state.idtr_limit)?;

        // Intercept enclave exceptions.
        if is_enter {
            VmcsField32Control::EXCEPTION_BITMAP.write(0xffff_ffff)?;
        } else {
            VmcsField32Control::EXCEPTION_BITMAP.write(0)?;
        }

        if cfg!(feature = "enclave_interrupt") {
            // Enable interrupts during enclave running.
            use libvmm::vmx::flags::PinVmExecControls as PinCtrl;
            use libvmm::vmx::flags::VmExitControls as ExitCtrl;
            let pin_based_exec_ctrl = VmcsField32Control::PIN_BASED_VM_EXEC_CONTROL.read()?;
            let vmexit_ctrl = VmcsField32Control::VM_EXIT_CONTROLS.read()?;
            if is_enter {
                VmcsField32Control::PIN_BASED_VM_EXEC_CONTROL
                    .write(pin_based_exec_ctrl | PinCtrl::INTR_EXITING.bits())?;
                VmcsField32Control::VM_EXIT_CONTROLS
                    .write(vmexit_ctrl | ExitCtrl::ACK_INTR_ON_EXIT.bits())?
            } else {
                VmcsField32Control::PIN_BASED_VM_EXEC_CONTROL
                    .write(pin_based_exec_ctrl & !PinCtrl::INTR_EXITING.bits())?;
                VmcsField32Control::VM_EXIT_CONTROLS
                    .write(vmexit_ctrl & !ExitCtrl::ACK_INTR_ON_EXIT.bits())?
            }
        }

        Ok(())
    }
}
