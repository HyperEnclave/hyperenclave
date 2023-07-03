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

use super::cpuid::CpuFeatures;
use crate::error::HvResult;

pub fn id() -> usize {
    super::cpuid::CpuId::new()
        .get_feature_info()
        .unwrap()
        .initial_local_apic_id() as usize
}

pub fn time_now() -> u64 {
    unsafe { core::arch::x86_64::_rdtsc() }
}

pub fn check_cpuid() -> HvResult {
    let features = CpuFeatures::new();
    // CR4.PAE will be set in HOST_CR4
    if !features.has_pae() {
        return hv_result_err!(ENODEV, "PAE is not supported!");
    }
    // CR4.OSXSAVE will be set in HOST_CR4
    if !features.has_xsave() {
        return hv_result_err!(ENODEV, "OSXSAVE is not supported!");
    }
    Ok(())
}

#[allow(dead_code)]
const CACHE_LINE_SIZE: usize = 64;

#[allow(dead_code)]
pub fn clflush_cache_range(vaddr: usize, length: usize) {
    // clflush is an unordered instruction which needs fencing with mfence or
    // sfence to avoid ordering issues.
    unsafe { asm!("mfence") };
    for addr in (vaddr..(vaddr + length)).step_by(CACHE_LINE_SIZE) {
        unsafe {
            core::arch::x86_64::_mm_clflush(addr as *const u8);
        }
    }
    unsafe { asm!("mfence") };
}
