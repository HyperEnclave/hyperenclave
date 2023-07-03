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

use core::convert::TryInto;

use bit_field::BitField;
use libvmm_macros::*;
use x86::{bits64::vmx, vmx::Result as VmResult};

use super::definitions::{VmxExitReason, VmxInstructionError};
use super::flags::{EptpFlags, InterruptInfo, InvEptType};

/// B.1.1 16-Bit Control Fields
#[vmcs_access(16, "RW")]
#[derive(Debug, Copy, Clone)]
#[allow(non_camel_case_types)]
pub enum VmcsField16Control {
    VIRTUAL_PROCESSOR_ID = 0x00000000,
    POSTED_INTR_NV = 0x00000002,
    EPTP_INDEX = 0x00000004,
}

/// B.1.2 16-Bit Guest-State Fields
#[vmcs_access(16, "RW")]
#[derive(Debug, Copy, Clone)]
#[allow(non_camel_case_types)]
pub enum VmcsField16Guest {
    ES_SELECTOR = 0x00000800,
    CS_SELECTOR = 0x00000802,
    SS_SELECTOR = 0x00000804,
    DS_SELECTOR = 0x00000806,
    FS_SELECTOR = 0x00000808,
    GS_SELECTOR = 0x0000080a,
    LDTR_SELECTOR = 0x0000080c,
    TR_SELECTOR = 0x0000080e,
    INTR_STATUS = 0x00000810,
    PML_INDEX = 0x00000812,
}

/// B.1.3 16-Bit Host-State Fields
#[vmcs_access(16, "RW")]
#[derive(Debug, Copy, Clone)]
#[allow(non_camel_case_types)]
pub enum VmcsField16Host {
    ES_SELECTOR = 0x00000c00,
    CS_SELECTOR = 0x00000c02,
    SS_SELECTOR = 0x00000c04,
    DS_SELECTOR = 0x00000c06,
    FS_SELECTOR = 0x00000c08,
    GS_SELECTOR = 0x00000c0a,
    TR_SELECTOR = 0x00000c0c,
}

/// B.3.1 32-Bit Control Fields
#[vmcs_access(32, "RW")]
#[derive(Debug, Copy, Clone)]
#[allow(non_camel_case_types)]
pub enum VmcsField32Control {
    PIN_BASED_VM_EXEC_CONTROL = 0x00004000,
    PROC_BASED_VM_EXEC_CONTROL = 0x00004002,
    EXCEPTION_BITMAP = 0x00004004,
    PAGE_FAULT_ERROR_CODE_MASK = 0x00004006,
    PAGE_FAULT_ERROR_CODE_MATCH = 0x00004008,
    CR3_TARGET_COUNT = 0x0000400a,
    VM_EXIT_CONTROLS = 0x0000400c,
    VM_EXIT_MSR_STORE_COUNT = 0x0000400e,
    VM_EXIT_MSR_LOAD_COUNT = 0x00004010,
    VM_ENTRY_CONTROLS = 0x00004012,
    VM_ENTRY_MSR_LOAD_COUNT = 0x00004014,
    VM_ENTRY_INTR_INFO_FIELD = 0x00004016,
    VM_ENTRY_EXCEPTION_ERROR_CODE = 0x00004018,
    VM_ENTRY_INSTRUCTION_LEN = 0x0000401a,
    TPR_THRESHOLD = 0x0000401c,
    SECONDARY_VM_EXEC_CONTROL = 0x0000401e,
    PLE_GAP = 0x00004020,
    PLE_WINDOW = 0x00004022,
}

/// B.3.2 32-Bit Read-Only Data Fields
#[vmcs_access(32, "R")]
#[derive(Debug, Copy, Clone)]
#[allow(non_camel_case_types)]
pub enum VmcsField32ReadOnly {
    VM_INSTRUCTION_ERROR = 0x00004400,
    VM_EXIT_REASON = 0x00004402,
    VM_EXIT_INTR_INFO = 0x00004404,
    VM_EXIT_INTR_ERROR_CODE = 0x00004406,
    IDT_VECTORING_INFO_FIELD = 0x00004408,
    IDT_VECTORING_ERROR_CODE = 0x0000440a,
    VM_EXIT_INSTRUCTION_LEN = 0x0000440c,
    VMX_INSTRUCTION_INFO = 0x0000440e,
}

/// B.3.3 32-Bit Guest-State Fields
#[vmcs_access(32, "RW")]
#[derive(Debug, Copy, Clone)]
#[allow(non_camel_case_types)]
pub enum VmcsField32Guest {
    ES_LIMIT = 0x00004800,
    CS_LIMIT = 0x00004802,
    SS_LIMIT = 0x00004804,
    DS_LIMIT = 0x00004806,
    FS_LIMIT = 0x00004808,
    GS_LIMIT = 0x0000480a,
    LDTR_LIMIT = 0x0000480c,
    TR_LIMIT = 0x0000480e,
    GDTR_LIMIT = 0x00004810,
    IDTR_LIMIT = 0x00004812,
    ES_AR_BYTES = 0x00004814,
    CS_AR_BYTES = 0x00004816,
    SS_AR_BYTES = 0x00004818,
    DS_AR_BYTES = 0x0000481a,
    FS_AR_BYTES = 0x0000481c,
    GS_AR_BYTES = 0x0000481e,
    LDTR_AR_BYTES = 0x00004820,
    TR_AR_BYTES = 0x00004822,
    INTERRUPTIBILITY_INFO = 0x00004824,
    ACTIVITY_STATE = 0x00004826,
    SYSENTER_CS = 0x0000482A,
    VMX_PREEMPTION_TIMER_VALUE = 0x0000482E,
}

/// B.3.4 32-Bit Host-State Field
#[vmcs_access(32, "RW")]
#[derive(Debug, Copy, Clone)]
#[allow(non_camel_case_types)]
pub enum VmcsField32Host {
    IA32_SYSENTER_CS = 0x00004c00,
}

/// B.2.1 64-Bit Control Fields
#[vmcs_access(64, "RW")]
#[derive(Debug, Copy, Clone)]
#[allow(non_camel_case_types)]
pub enum VmcsField64Control {
    IO_BITMAP_A = 0x00002000,
    IO_BITMAP_B = 0x00002002,
    MSR_BITMAP = 0x00002004,
    VM_EXIT_MSR_STORE_ADDR = 0x00002006,
    VM_EXIT_MSR_LOAD_ADDR = 0x00002008,
    VM_ENTRY_MSR_LOAD_ADDR = 0x0000200a,
    PML_ADDRESS = 0x0000200e,
    TSC_OFFSET = 0x00002010,
    VIRTUAL_APIC_PAGE_ADDR = 0x00002012,
    APIC_ACCESS_ADDR = 0x00002014,
    POSTED_INTR_DESC_ADDR = 0x00002016,
    VM_FUNCTION_CONTROL = 0x00002018,
    EPT_POINTER = 0x0000201a,
    EOI_EXIT_BITMAP0 = 0x0000201c,
    EOI_EXIT_BITMAP1 = 0x0000201e,
    EOI_EXIT_BITMAP2 = 0x00002020,
    EOI_EXIT_BITMAP3 = 0x00002022,
    EPTP_LIST_ADDRESS = 0x00002024,
    VMREAD_BITMAP = 0x00002026,
    VMWRITE_BITMAP = 0x00002028,
    XSS_EXIT_BITMAP = 0x0000202c,
    ENCLS_EXITING_BITMAP = 0x0000202e,
    TSC_MULTIPLIER = 0x00002032,

    /* Natural Width */
    CR0_GUEST_HOST_MASK = 0x00006000,
    CR4_GUEST_HOST_MASK = 0x00006002,
    CR0_READ_SHADOW = 0x00006004,
    CR4_READ_SHADOW = 0x00006006,
    CR3_TARGET_VALUE0 = 0x00006008,
    CR3_TARGET_VALUE1 = 0x0000600a,
    CR3_TARGET_VALUE2 = 0x0000600c,
    CR3_TARGET_VALUE3 = 0x0000600e,
}

/// B.2.2 64-Bit Read-Only Data Field
#[vmcs_access(64, "R")]
#[derive(Debug, Copy, Clone)]
#[allow(non_camel_case_types)]
pub enum VmcsField64ReadOnly {
    GUEST_PHYSICAL_ADDRESS = 0x00002400,

    /* Natural Width */
    EXIT_QUALIFICATION = 0x00006400,
    IO_RCX = 0x00006402,
    IO_RSI = 0x00006404,
    IO_RDI = 0x00006406,
    IO_RIP = 0x00006408,
    GUEST_LINEAR_ADDRESS = 0x0000640a,
}

/// B.2.3 64-Bit Guest-State Fields
#[vmcs_access(64, "RW")]
#[derive(Debug, Copy, Clone)]
#[allow(non_camel_case_types)]
pub enum VmcsField64Guest {
    VMCS_LINK_POINTER = 0x00002800,
    IA32_DEBUGCTL = 0x00002802,
    IA32_PAT = 0x00002804,
    IA32_EFER = 0x00002806,
    IA32_PERF_GLOBAL_CTRL = 0x00002808,
    PDPTR0 = 0x0000280a,
    PDPTR1 = 0x0000280c,
    PDPTR2 = 0x0000280e,
    PDPTR3 = 0x00002810,
    BNDCFGS = 0x00002812,

    /* Natural Width */
    CR0 = 0x00006800,
    CR3 = 0x00006802,
    CR4 = 0x00006804,
    ES_BASE = 0x00006806,
    CS_BASE = 0x00006808,
    SS_BASE = 0x0000680a,
    DS_BASE = 0x0000680c,
    FS_BASE = 0x0000680e,
    GS_BASE = 0x00006810,
    LDTR_BASE = 0x00006812,
    TR_BASE = 0x00006814,
    GDTR_BASE = 0x00006816,
    IDTR_BASE = 0x00006818,
    DR7 = 0x0000681a,
    RSP = 0x0000681c,
    RIP = 0x0000681e,
    RFLAGS = 0x00006820,
    PENDING_DBG_EXCEPTIONS = 0x00006822,
    SYSENTER_ESP = 0x00006824,
    SYSENTER_EIP = 0x00006826,
}

/// B.2.4 64-Bit Host-State Fields
#[vmcs_access(64, "RW")]
#[derive(Debug, Copy, Clone)]
#[allow(non_camel_case_types)]
pub enum VmcsField64Host {
    IA32_PAT = 0x00002c00,
    IA32_EFER = 0x00002c02,
    IA32_PERF_GLOBAL_CTRL = 0x00002c04,

    /* Natural Width */
    CR0 = 0x00006c00,
    CR3 = 0x00006c02,
    CR4 = 0x00006c04,
    FS_BASE = 0x00006c06,
    GS_BASE = 0x00006c08,
    TR_BASE = 0x00006c0a,
    GDTR_BASE = 0x00006c0c,
    IDTR_BASE = 0x00006c0e,
    IA32_SYSENTER_ESP = 0x00006c10,
    IA32_SYSENTER_EIP = 0x00006c12,
    RSP = 0x00006c14,
    RIP = 0x00006c16,
}

pub struct Vmcs;

impl Vmcs {
    pub fn load(paddr: usize) -> VmResult<()> {
        unsafe { vmx::vmptrld(paddr as _) }
    }

    pub fn clear(paddr: usize) -> VmResult<()> {
        unsafe { vmx::vmclear(paddr as _) }
    }

    pub fn instruction_error() -> VmResult<VmxInstructionError> {
        Ok(VmcsField32ReadOnly::VM_INSTRUCTION_ERROR.read()?.into())
    }

    pub fn exit_reason() -> VmResult<VmxExitReason> {
        Ok(VmcsField32ReadOnly::VM_EXIT_REASON
            .read()?
            .get_bits(0..16)
            .try_into()
            .expect("Unknown VM-exit reason"))
    }

    pub fn set_ept_pointer(pml4_paddr: usize, eptp_flags: EptpFlags, invept_type: InvEptType) -> VmResult<()> {
        let aligned_addr = pml4_paddr & !0xfff;
        let eptp = aligned_addr as u64 | eptp_flags.bits();
        VmcsField64Control::EPT_POINTER.write(eptp)?;
        unsafe { super::invept(invept_type, eptp)? };
        Ok(())
    }

    pub fn inject_interrupt(info: InterruptInfo, error_code: Option<u32>) -> VmResult<()> {
        if info.contains(InterruptInfo::ERROR_CODE) {
            let error_code =
                error_code.unwrap_or(VmcsField32ReadOnly::VM_EXIT_INTR_ERROR_CODE.read()?);
            VmcsField32Control::VM_ENTRY_EXCEPTION_ERROR_CODE.write(error_code)?;
        }
        VmcsField32Control::VM_ENTRY_INTR_INFO_FIELD.write(info.bits())?;
        if info.intr_type().is_soft() {
            VmcsField32Control::VM_ENTRY_INSTRUCTION_LEN
                .write(VmcsField32ReadOnly::VM_EXIT_INSTRUCTION_LEN.read()?)?;
        }
        Ok(())
    }

    pub fn set_control(
        field: VmcsField32Control,
        old_msr: u64,
        set: u32,
        clear: u32,
    ) -> VmResult<()> {
        assert_eq!((set & clear), 0);
        field.write((old_msr as u32) & !clear | set)
    }
}

#[derive(Debug)]
pub struct VmExitInfo {
    pub entry_failure: bool,
    pub exit_reason: VmxExitReason,
    pub exit_instruction_length: u32,
    pub guest_rip: u64,
}

impl VmExitInfo {
    pub fn new() -> VmResult<Self> {
        let full_reason = VmcsField32ReadOnly::VM_EXIT_REASON.read()?;
        Ok(Self {
            exit_reason: full_reason
                .get_bits(0..16)
                .try_into()
                .expect("Unknown VM-exit reason"),
            entry_failure: full_reason.get_bit(31),
            exit_instruction_length: VmcsField32ReadOnly::VM_EXIT_INSTRUCTION_LEN.read()?,
            guest_rip: VmcsField64Guest::RIP.read()?,
        })
    }
}

#[derive(Debug)]
pub struct ExitInterruptInfo {
    pub vector: u8,
    pub interruption_type: u8,
    pub valid: bool,
}

impl ExitInterruptInfo {
    pub fn new() -> VmResult<Self> {
        let info = VmcsField32ReadOnly::VM_EXIT_INTR_INFO.read()?;
        Ok(Self {
            vector: info.get_bits(0..8) as u8,
            interruption_type: info.get_bits(8..11) as u8,
            valid: info.get_bit(31),
        })
    }
}

#[derive(Debug)]
pub struct EptViolationInfo {
    pub read: bool,
    pub write: bool,
    pub instruction: bool,
    pub final_translation: bool,
    pub guest_paddr: usize,
}

impl EptViolationInfo {
    pub fn new() -> VmResult<Self> {
        let qualification = VmcsField64ReadOnly::EXIT_QUALIFICATION.read()?;
        Ok(Self {
            read: qualification.get_bit(0),
            write: qualification.get_bit(1),
            instruction: qualification.get_bit(2),
            // Intel SDM, Volume 3, 27.2.1, Table 27-7:
            // We donnot support PAE paging adnd TAPT, such bit is always valid.
            final_translation: qualification.get_bit(8),
            guest_paddr: VmcsField64ReadOnly::GUEST_PHYSICAL_ADDRESS.read()? as _,
        })
    }
}
