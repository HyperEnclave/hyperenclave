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

use bit_field::BitField;
use bitflags::bitflags;

use crate::x86_64::msr::{Msr, MsrReadWrite};

bitflags! {
    /// 24.6.1 Pin-Based VM-Execution Controls.
    pub struct PinVmExecControls: u32 {
        /// VM-Exit on vectored interrupts
        #[allow(clippy::identity_op)]
        const INTR_EXITING      = 1 << 0;
        /// VM-Exit on NMIs
        const NMI_EXITING       = 1 << 3;
        /// NMI virtualization
        const VIRTUAL_NMIS      = 1 << 5;
        /// VMX Preemption Timer
        const PREEMPTION_TIMER  = 1 << 6;
        /// Posted Interrupts
        const POSTED_INTR       = 1 << 7;
    }
}

bitflags! {
    /// 24.6.2 Primary Processor-Based VM-Execution Controls.
    pub struct PrimaryVmExecControls: u32 {
        /// VM-Exit if INTRs are unblocked in guest
        const INTR_WINDOW_EXITING   = 1 <<  2;
        /// Offset hardware TSC when read in guest
        const USE_TSC_OFFSETTING    = 1 <<  3;
        /// VM-Exit on HLT
        const HLT_EXITING           = 1 <<  7;
        /// VM-Exit on INVLPG
        const INVLPG_EXITING        = 1 <<  9;
        /// VM-Exit on MWAIT
        const MWAIT_EXITING         = 1 << 10;
        /// VM-Exit on RDPMC
        const RDPMC_EXITING         = 1 << 11;
        /// VM-Exit on RDTSC
        const RDTSC_EXITING         = 1 << 12;
        /// VM-Exit on writes to CR3
        const CR3_LOAD_EXITING      = 1 << 15;
        /// VM-Exit on reads from CR3
        const CR3_STORE_EXITING     = 1 << 16;
        /// VM-Exit on writes to CR8
        const CR8_LOAD_EXITING      = 1 << 19;
        /// VM-Exit on reads from CR8
        const CR8_STORE_EXITING     = 1 << 20;
        /// TPR virtualization, a.k.a. TPR shadow
        const VIRTUAL_TPR           = 1 << 21;
        /// VM-Exit if NMIs are unblocked in guest
        const NMI_WINDOW_EXITING    = 1 << 22;
        /// VM-Exit on accesses to debug registers
        const MOV_DR_EXITING        = 1 << 23;
        /// VM-Exit on *all* IN{S} and OUT{S}
        const UNCOND_IO_EXITING     = 1 << 24;
        /// VM-Exit based on I/O port
        const USE_IO_BITMAPS        = 1 << 25;
        /// VMX single-step VM-Exits
        const MONITOR_TRAP_FLAG     = 1 << 27;
        /// VM-Exit based on MSR index
        const USE_MSR_BITMAPS       = 1 << 28;
        /// M-Exit on MONITOR (MWAIT's accomplice)
        const MONITOR_EXITING       = 1 << 29;
        /// VM-Exit on PAUSE (unconditionally)
        const PAUSE_EXITING         = 1 << 30;
        /// Enable Secondary VM-Execution Controls
        const SEC_CONTROLS          = 1 << 31;
    }
}

bitflags! {
    /// 24.6.2 Secondary Primary Processor-Based VM-Execution Controls.
    pub struct SecondaryVmExecControls: u32 {
        /// Virtualize memory mapped APIC accesses
        #[allow(clippy::identity_op)]
        const VIRT_APIC_ACCESSES    = 1 <<  0;
        /// Extended Page Tables, a.k.a. Two-Dimensional Paging
        const EPT                   = 1 <<  1;
        /// VM-Exit on {S,L}*DT instructions
        const DESC_EXITING          = 1 <<  2;
        /// Enable RDTSCP in guest
        const RDTSCP                = 1 <<  3;
        /// Virtualize X2APIC for the guest
        const VIRTUAL_X2APIC        = 1 <<  4;
        /// Virtual Processor ID (TLB ASID modifier)
        const VPID                  = 1 <<  5;
        /// VM-Exit on WBINVD
        const WBINVD_EXITING        = 1 <<  6;
        /// Allow Big Real Mode and other "invalid" states
        const UNRESTRICTED_GUEST    = 1 <<  7;
        /// Hardware emulation of reads to the virtual-APIC
        const APIC_REGISTER_VIRT    = 1 <<  8;
        /// Evaluation and delivery of pending virtual interrupts
        const VIRT_INTR_DELIVERY    = 1 <<  9;
        /// Conditionally VM-Exit on PAUSE at CPL0
        const PAUSE_LOOP_EXITING    = 1 << 10;
        /// VM-Exit on RDRAND
        const RDRAND_EXITING        = 1 << 11;
        /// Enable INVPCID in guest
        const INVPCID               = 1 << 12;
        /// Enable VM-Functions (leaf dependent)
        const VMFUNC                = 1 << 13;
        /// VMREAD/VMWRITE in guest can access shadow VMCS
        const SHADOW_VMCS           = 1 << 14;
        /// VM-Exit on ENCLS (leaf dependent)
        const ENCLS_EXITING         = 1 << 15;
        /// VM-Exit on RDSEED
        const RDSEED_EXITING        = 1 << 16;
        /// Log dirty pages into buffer
        const PAGE_MOD_LOGGING      = 1 << 17;
        /// Conditionally reflect EPT violations as #VE exceptions
        const EPT_VIOLATION_VE      = 1 << 18;
        /// Suppress VMX indicators in Processor Trace
        const PT_CONCEAL_VMX        = 1 << 19;
        /// Enable XSAVES and XRSTORS in guest
        const XSAVES                = 1 << 20;
        /// Enable separate EPT EXEC bits for supervisor vs. user
        const MODE_BASED_EPT_EXEC   = 1 << 22;
        /// Processor Trace logs GPAs
        const PT_USE_GPA            = 1 << 24;
        /// Scale hardware TSC when read in guest
        const TSC_SCALING           = 1 << 25;
        /// Enable TPAUSE, UMONITOR, UMWAIT in guest
        const USR_WAIT_PAUSE        = 1 << 26;
        /// VM-Exit on ENCLV (leaf dependent)
        const ENCLV_EXITING         = 1 << 28;
    }
}

bitflags! {
    /// 24.7.1 VM-Exit Controls.
    pub struct VmExitControls: u32 {
        const SAVE_DEBUG_CONTROLS           = 1 <<  2;
        /// Logical processor is in 64-bit mode after VM exit.
        const HOST_ADDR_SPACE_SIZE          = 1 <<  9;
        const LOAD_IA32_PERF_GLOBAL_CTRL    = 1 << 12;
        /// Acknowledge external interrupt on exit.
        const ACK_INTR_ON_EXIT              = 1 << 15;
        /// Save the guest IA32_PAT MSR on exit.
        const SAVE_IA32_PAT                 = 1 << 18;
        /// Load the guest IA32_PAT MSR on exit.
        const LOAD_IA32_PAT                 = 1 << 19;
        /// Save the guest IA32_EFER MSR on exit.
        const SAVE_IA32_EFER                = 1 << 20;
        /// LoaLoad the host IA32_EFER MSR on exit.
        const LOAD_IA32_EFER                = 1 << 21;
        const SAVE_VMX_PREEMPTION_TIMER     = 1 << 22;
        const CLEAR_BNDCFGS                 = 1 << 23;
        const PT_CONCEAL_PIP                = 1 << 24;
        const CLEAR_IA32_RTIT_CTL           = 1 << 25;
        const LOAD_CET_STATE                = 1 << 28;
    }
}

bitflags! {
    /// 24.8.1 VM-Entry Controls.
    pub struct VmEntryControls: u32 {
        const LOAD_DEBUG_CONTROLS           = 1 <<  2;
        const IA32E_MODE                    = 1 <<  9;
        const SMM                           = 1 << 10;
        const DEACT_DUAL_MONITOR            = 1 << 11;
        const LOAD_IA32_PERF_GLOBAL_CTRL    = 1 << 13;
        /// Load the guest IA32_PAT MSR on entry.
        const LOAD_IA32_PAT                 = 1 << 14;
        /// Load the guest IA32_EFER MSR on entry.
        const LOAD_IA32_EFER                = 1 << 15;
        const LOAD_BNDCFGS                  = 1 << 16;
        const PT_CONCEAL_PIP                = 1 << 17;
        const LOAD_IA32_RTIT_CTL            = 1 << 18;
        const LOAD_CET_STATE                = 1 << 20;
    }
}

bitflags! {
    /// Contains the address of the base of EPT PML4 table, as well as other EPT
    /// configuration information.
    pub struct EptpFlags: u64 {
        /// EPT paging-structure memory type Uncacheable (UC)
        #[allow(clippy::identity_op)]
        const MEMORY_TYPE_UC = 0 << 0;
        /// EPT paging-structure memory type Write-back (WB)
        #[allow(clippy::identity_op)]
        const MEMORY_TYPE_WB = 6 << 0;
        /// EPT page-walk length 1
        const WALK_LENGTH_1 = 0 << 3;
        /// EPT page-walk length 2
        const WALK_LENGTH_2 = 1 << 3;
        /// EPT page-walk length 3
        const WALK_LENGTH_3 = 2 << 3;
        /// EPT page-walk length 4
        const WALK_LENGTH_4 = 3 << 3;
        /// Setting this control to 1 enables accessed and dirty flags for EPT
        const ENABLE_ACCESSED_DIRTY = 1 << 6;
    }
}

bitflags! {
    /// MSR_IA32_VMX_EPT_VPID_CAP.
    /// The capabilities of the logical processor with regard to
    /// virtual-processor identifiers and extended page tables.
    pub struct VmxEptVpidCap: u64 {
        /// If bit 0 is read as 1, the processor supports execute-only
        /// translations by EPT.
        const EXECUTE_ONLY = 1 << 0;
        /// Indicates support for a page-walk length of 4.
        const WALK_LENGTH_4 = 1 << 6;
        /// If bit 8 is read as 1, the logical processor allows software to
        /// configure the EPT paging-structure memory type to be uncacheable (UC).
        const MEMORY_TYPE_UC = 1 << 8;
        /// If bit 14 is read as 1, the logical processor allows software to
        /// configure the EPT paging-structure memory type to be write-back (WB).
        const MEMORY_TYPE_WB = 1 << 14;
        /// If bit 16 is read as 1, the logical processor allows software to
        /// configure a EPT PDE to map a 2-Mbyte page.
        const HUGE_PAGE_2M = 1 << 16;
        /// If bit 17 is read as 1, the logical processor allows software to
        /// configure a EPT PDPTE to map a 1-Gbyte page.
        const HUGE_PAGE_1G = 1 << 17;
        /// If bit 20 is read as 1, the INVEPT instruction is supported.
        const INVEPT_INSTRUCTION = 1 << 20;
        /// If bit 21 is read as 1, accessed and dirty flags for EPT are supported.
        const ACCESSED_DIRTY = 1 << 21;
        /// If bit 22 is read as 1, the processor reports advanced VM-exit
        /// information for EPT violations.
        const REPORT_ADVANCED_VMEXIT = 1 << 22;
        /// If bit 23 is read as 1, supervisor shadow-stack control is supported.
        const SUPERVISOR_SHADOW_STACK = 1 << 23;
        /// If bit 25 is read as 1, the single-context INVEPT type is supported.
        const INVEPT_TYPE_SINGLE_CONTEXT = 1 << 25;
        /// If bit 26 is read as 1, the all-context INVEPT type is supported.
        const INVEPT_TYPE_GLOBAL = 1 << 26;
    }
}

bitflags! {
    /// MSR_IA32_FEATURE_CONTROL flags.
   pub struct VmxBasicFlags: u64 {
       /// The processor reports information in the VM-exit instruction-
       /// information field on VM exits due to execution of the INS and OUTS
       /// instructions (see Section 27.2.5). This reporting is done only if
       /// this bit is read as 1.
       const IO_EXIT_INFO = 1 << 54;
       /// Any VMX controls that default to 1 may be cleared to 0. See Appendix
       /// A.2 for details. It also reports support for the VMX capability MSRs
       /// IA32_VMX_TRUE_PINBASED_CTLS, IA32_VMX_TRUE_PROCBASED_CTLS,
       /// IA32_VMX_TRUE_EXIT_CTLS, and IA32_VMX_TRUE_ENTRY_CTLS.
       const VMX_FLEX_CONTROLS = 1 << 55;
   }
}

/// Stores VMX info from the IA32_VMX_BASIC MSR.
#[derive(Debug)]
pub struct VmxBasic {
    pub revision_id: u32,
    pub region_size: u16,
    pub write_back: bool,
    pub io_exit_info: bool,
    pub vmx_flex_controls: bool,
}

impl MsrReadWrite for VmxBasic {
    const MSR: Msr = Msr::IA32_VMX_BASIC;
}

impl VmxBasic {
    /// Read the current IA32_VMX_BASIC flags.
    pub fn read() -> Self {
        const VMX_MEMORY_TYPE_WRITE_BACK: u64 = 6;
        let msr = Self::read_raw();
        let flags = VmxBasicFlags::from_bits_truncate(msr);
        Self {
            revision_id: msr.get_bits(0..31) as u32,
            region_size: msr.get_bits(32..45) as u16,
            write_back: msr.get_bits(50..54) == VMX_MEMORY_TYPE_WRITE_BACK,
            io_exit_info: flags.contains(VmxBasicFlags::IO_EXIT_INFO),
            vmx_flex_controls: flags.contains(VmxBasicFlags::VMX_FLEX_CONTROLS),
        }
    }
}

bitflags! {
    /// MSR_IA32_FEATURE_CONTROL flags.
    pub struct FeatureControlFlags: u64 {
       /// Lock bit: when set, locks this MSR from being written.
       const LOCKED = 1 << 0;
       /// Enable VMX inside SMX operation.
       const VMXON_ENABLED_INSIDE_SMX = 1 << 1;
       /// Enable VMX outside SMX operation.
       const VMXON_ENABLED_OUTSIDE_SMX = 1 << 2;
   }
}

/// Control Features in Intel 64 Processor: MSR_IA32_FEATURE_CONTROL
pub struct FeatureControl;

impl MsrReadWrite for FeatureControl {
    const MSR: Msr = Msr::IA32_FEATURE_CONTROL;
}

impl FeatureControl {
    /// Read the current MSR_IA32_FEATURE_CONTROL flags.
    pub fn read() -> FeatureControlFlags {
        FeatureControlFlags::from_bits_truncate(Self::read_raw())
    }

    pub fn write(flags: FeatureControlFlags) {
        let old_value = Self::read_raw();
        let reserved = old_value & !(FeatureControlFlags::all().bits());
        let new_value = reserved | flags.bits();

        unsafe { Self::write_raw(new_value) };
    }
}

bitflags! {
    /// This field provides details about the event to be injected.
    pub struct InterruptInfo: u32 {
        /// Deliver error code
        const ERROR_CODE    = 1 << 11;
        /// Valid
        const VALID         = 1 << 31;
    }
}

/// The interruption type (bits 10:8) determines details of how the injection is performed.
#[repr(u32)]
#[derive(Debug)]
pub enum InterruptType {
    /// External interrupt
    External = 0,
    /// Reserved
    Reserved = 1,
    /// Non-maskable interrupt (NMI)
    NMI = 2,
    /// Hardware exception (e.g,. #PF)
    HardException = 3,
    /// Software interrupt (INT n)
    SoftIntr = 4,
    /// Privileged software exception (INT1)
    PrivSoftException = 5,
    /// Software exception (INT3 or INTO)
    SoftException = 6,
    /// Other event
    Other = 7,
}

impl InterruptType {
    pub fn from_vector(vector: u8) -> Self {
        use x86::irq::*;
        match vector {
            NONMASKABLE_INTERRUPT_VECTOR => Self::NMI,
            // From Volume 3, Section 24.8.3. A VMM should use type hardware exception for all
            // exceptions other than breakpoints and overflows, which should be software exceptions.
            BREAKPOINT_VECTOR | OVERFLOW_VECTOR => Self::SoftException,
            // From Volume 3, Section 6.15. All other vectors from 0 to 21 are exceptions.
            0..=VIRTUALIZATION_VECTOR => Self::HardException,
            32..=255 => Self::External,
            _ => Self::Other,
        }
    }

    pub fn is_soft(&self) -> bool {
        matches!(
            *self,
            Self::SoftIntr | Self::PrivSoftException | Self::SoftException
        )
    }
}

impl InterruptInfo {
    fn has_error_code(vector: u8) -> bool {
        use x86::irq::*;
        matches!(
            vector,
            DOUBLE_FAULT_VECTOR
                | INVALID_TSS_VECTOR
                | SEGMENT_NOT_PRESENT_VECTOR
                | STACK_SEGEMENT_FAULT_VECTOR
                | GENERAL_PROTECTION_FAULT_VECTOR
                | PAGE_FAULT_VECTOR
                | ALIGNMENT_CHECK_VECTOR
        )
    }

    pub fn from(int_type: InterruptType, vector: u8) -> Self {
        let mut bits = vector as u32;
        bits.set_bits(8..11, int_type as u32);
        let mut info = unsafe { Self::from_bits_unchecked(bits) } | Self::VALID;
        if Self::has_error_code(vector) {
            info |= Self::ERROR_CODE;
        }
        info
    }

    pub fn from_vector(vector: u8) -> Self {
        Self::from(InterruptType::from_vector(vector), vector)
    }

    pub fn intr_type(&self) -> InterruptType {
        unsafe { core::mem::transmute(self.bits().get_bits(8..11) & 0x7) }
    }
}

#[repr(C, packed)]
#[derive(Debug, Clone, Copy)]
pub struct InvEptDescriptor {
    /// EPT pointer (EPTP)
    eptp: u64,
    /// Reserved (must be zero)
    _reserved: u64,
}

impl InvEptDescriptor {
    pub fn new(eptp: u64) -> Self {
        Self { eptp, _reserved: 0 }
    }
}

#[repr(u64)]
#[derive(Debug)]
pub enum InvEptType {
    /// The logical processor invalidates all mappings associated with bits
    /// 51:12 of the EPT pointer (EPTP) specified in the INVEPT descriptor.
    /// It may invalidate other mappings as well.
    SingleContext = 1,

    /// The logical processor invalidates mappings associated with all EPTPs.
    Global = 2,
}
