// Modified by Ant Group in 2023.

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

use x86::msr::{rdmsr, wrmsr};

#[repr(u32)]
#[allow(dead_code)]
#[derive(Debug, Copy, Clone)]
#[allow(non_camel_case_types)]
pub enum Msr {
    IA32_FEATURE_CONTROL = 0x3a,

    IA32_SYSENTER_CS = 0x174,
    IA32_SYSENTER_ESP = 0x175,
    IA32_SYSENTER_EIP = 0x176,

    IA32_PAT = 0x277,
    IA32_MTRR_DEF_TYPE = 0x2ff,
    IA32_PERF_GLOBAL_CTRL = 0x38f,

    IA32_VMX_BASIC = 0x480,
    IA32_VMX_PINBASED_CTLS = 0x481,
    IA32_VMX_PROCBASED_CTLS = 0x482,
    IA32_VMX_EXIT_CTLS = 0x483,
    IA32_VMX_ENTRY_CTLS = 0x484,
    IA32_VMX_MISC = 0x485,
    IA32_VMX_CR0_FIXED0 = 0x486,
    IA32_VMX_CR0_FIXED1 = 0x487,
    IA32_VMX_CR4_FIXED0 = 0x488,
    IA32_VMX_CR4_FIXED1 = 0x489,
    IA32_VMX_PROCBASED_CTLS2 = 0x48b,
    IA32_VMX_EPT_VPID_CAP = 0x48c,
    IA32_VMX_TRUE_PINBASED_CTLS = 0x48d,
    IA32_VMX_TRUE_PROCBASED_CTLS = 0x48e,
    IA32_VMX_TRUE_EXIT_CTLS = 0x48f,
    IA32_VMX_TRUE_ENTRY_CTLS = 0x490,

    IA32_EFER = 0xc000_0080,
    IA32_STAR = 0xc000_0081,
    IA32_LSTAR = 0xc000_0082,
    IA32_CSTAR = 0xc000_0083,
    IA32_FMASK = 0xc000_0084,
    IA32_FS_BASE = 0xc000_0100,
    IA32_GS_BASE = 0xc000_0101,
    IA32_KERNEL_GSBASE = 0xc000_0102,
    IA32_TSC_AUX = 0xc000_0103,

    // SVM Related MSRs:
    VM_CR = 0xc001_0114,
    IGNNE = 0xc001_0115,
    VM_HSAVE_PA = 0xc001_0117,

    PERF_EVT_SEL0 = 0xc001_0200,
    PERF_EVT_SEL1 = 0xc001_0202,
    PERF_EVT_SEL2 = 0xc001_0204,
    PERF_EVT_SEL3 = 0xc001_0206,
    PERF_EVT_SEL4 = 0xc001_0208,
    PERF_EVT_SEL5 = 0xc001_020a,
}

impl Msr {
    /// Read 64 bits msr register.
    pub fn read(self) -> u64 {
        unsafe { rdmsr(self as _) }
    }

    /// Write 64 bits to msr register.
    ///
    /// # Safety
    ///
    /// The caller must ensure that this write operation has no unsafe side
    /// effects.
    pub unsafe fn write(self, value: u64) {
        wrmsr(self as _, value)
    }
}

pub(super) trait MsrReadWrite {
    const MSR: Msr;

    fn read_raw() -> u64 {
        Self::MSR.read()
    }

    unsafe fn write_raw(flags: u64) {
        Self::MSR.write(flags);
    }
}
