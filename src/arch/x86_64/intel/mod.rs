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

mod enclave;
mod ept;
mod structs;
mod vcpu;
mod vmexit;
mod vtd;

use libvmm::msr::Msr;
use libvmm::vmx::Vmcs;
use x86::vmx::VmFail;

use crate::arch::cpu::check_cpuid;
use crate::arch::cpuid::CpuFeatures;
use crate::error::{HvError, HvResult};

pub use ept::EPTEntry as NPTEntry;
pub use ept::EnclaveExtendedPageTableUnlocked as EnclaveNestedPageTableUnlocked;
pub use ept::ExtendedPageTable as NestedPageTable;
pub use vcpu::Vcpu;
pub use vtd::{IoPTEntry, IoPageTable, Iommu};

use libvmm::vmx::flags::VmExitControls as ExitCtrl;

const VMEXIT_CTRL_MIN: u32 = ExitCtrl::HOST_ADDR_SPACE_SIZE.bits()
    | ExitCtrl::SAVE_IA32_PAT.bits()
    | ExitCtrl::LOAD_IA32_PAT.bits()
    | ExitCtrl::SAVE_IA32_EFER.bits()
    | ExitCtrl::LOAD_IA32_EFER.bits();

impl From<VmFail> for HvError {
    fn from(err: VmFail) -> Self {
        match err {
            VmFail::VmFailValid => hv_err!(
                EIO,
                format!("{:?}: {:x?}", err, Vmcs::instruction_error().unwrap())
            ),
            _ => hv_err!(EIO, format!("{:?}", err)),
        }
    }
}

pub fn check_hypervisor_feature() -> HvResult {
    // Check cpuid
    check_cpuid()?;

    if !CpuFeatures::new().has_vmx() {
        warn!("Feature VMX not supported!");
        return hv_result_err!(ENODEV, "VMX feature checks failed!");
    }

    let vmexit_ctrl = (Msr::IA32_VMX_EXIT_CTLS.read() >> 32) as u32;
    if (!vmexit_ctrl) & VMEXIT_CTRL_MIN != 0 {
        return hv_result_err!(ENODEV, "required VmExitControls flags checks failed!");
    }

    Ok(())
}
