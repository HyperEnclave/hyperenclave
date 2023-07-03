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
mod iommu;
mod mem_encrypt;
mod npt;
mod vcpu;
mod vmexit;

use libvmm::svm::flags::{VmCr, VmCrFlags};

use crate::arch::cpu::check_cpuid;
use crate::error::HvResult;

pub use iommu::{IoPTEntry, IoPageTable, Iommu};
pub use mem_encrypt::{EncHW, HmacSWEncHW};
pub use npt::{EnclaveNestedPageTableUnlocked, NPTEntry, NestedPageTable};
pub use vcpu::Vcpu;

pub fn check_hypervisor_feature() -> HvResult {
    check_cpuid()?;
    if VmCr::read().contains(VmCrFlags::SVMDIS) {
        return hv_result_err!(ENODEV, "SVM disabled by BIOS!");
    }
    Ok(())
}
