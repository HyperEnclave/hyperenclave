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
    /// VM_CR MSR flags.
   pub struct VmCrFlags: u64 {
       /// If set, disables HDT and certain internal debug features.
       const DPD        = 1 << 0;
       /// If set, non-intercepted INIT signals are converted into an #SX
       /// exception.
       const R_INIT     = 1 << 1;
       /// If set, disables A20 masking.
       const DIS_A20M   = 1 << 2;
       /// When this bit is set, writes to LOCK and SVMDIS are silently ignored.
       /// When this bit is clear, VM_CR bits 3 and 4 can be written. Once set,
       /// LOCK can only be cleared using the SVM_KEY MSR (See Section 15.31.)
       /// This bit is not affected by INIT or SKINIT.
       const LOCK       = 1 << 3;
       /// When this bit is set, writes to EFER treat the SVME bit as MBZ. When
       /// this bit is clear, EFER.SVME can be written normally. This bit does
       ///  not prevent CPUID from reporting that SVM is available. Setting
       /// SVMDIS while EFER.SVME is 1 generates a #GP fault, regardless of the
       /// current state of VM_CR.LOCK. This bit is not affected by SKINIT. It
       /// is cleared by INIT when LOCK is cleared to 0; otherwise, it is not
       /// affected.
       const SVMDIS     = 1 << 4;
   }
}

/// The VM_CR MSR controls certain global aspects of SVM.
pub struct VmCr;

impl MsrReadWrite for VmCr {
    const MSR: Msr = Msr::VM_CR;
}

impl VmCr {
    pub fn read() -> VmCrFlags {
        VmCrFlags::from_bits_truncate(Self::read_raw())
    }
}

bitflags! {
    /// The VMCB Clean field (VMCB offset 0C0h, bits 31:0) controls which guest
    /// register values are loaded from the VMCB state cache on VMRUN.
   pub struct VmcbCleanBits: u32 {
       /// Intercepts: all the intercept vectors, TSC offset, Pause Filter Count
       const I          = 1 << 0;
       /// IOMSRPM: IOPM_BASE, MSRPM_BASE
       const IOPM       = 1 << 1;
       /// ASID
       const ASID       = 1 << 2;
       /// V_TPR, V_IRQ, V_INTR_PRIO, V_IGN_TPR, V_INTR_MASKING, V_INTR_VECTOR
       /// (Offset 60h–67h)
       const TPR        = 1 << 3;
       /// Nested Paging: NCR3, G_PAT
       const NP         = 1 << 4;
       /// CR0, CR3, CR4, EFER
       const CR_X        = 1 << 5;
       /// DR6, DR7
       const DR_X        = 1 << 6;
       /// GDT/IDT Limit and Base
       const DT         = 1 << 7;
       /// CS/DS/SS/ES Sel/Base/Limit/Attr, CPL
       const SEG        = 1 << 8;
       /// CR2
       const CR2        = 1 << 9;
       /// DbgCtlMsr, br_from/to, lastint_from/to
       const LBR        = 1 << 10;
       /// AVIC APIC_BAR; AVIC APIC_BACKING_PAGE, AVIC PHYSICAL_TABLE and AVIC
       /// LOGICAL_TABLE Pointers
       const AVIC       = 1 << 11;
       /// S_CET, SSP, ISST_ADDR
       const CET        = 1 << 12;
       /// The hypervisor has not modified the VMCB.
       const UNMODIFIED = 0xffff_ffff;
   }
}

bitflags! {
    /// EXITINTINFO/EVENTINJ field in the VMCB.
    pub struct VmcbIntInfo: u32 {
        /// Error Code Valid
        const ERROR_CODE    = 1 << 11;
        /// Valid
        const VALID         = 1 << 31;
    }
}

#[repr(u32)]
#[derive(Debug)]
pub enum InterruptType {
    /// External or virtual interrupt (INTR)
    External = 0,
    /// Non-maskable interrupt (NMI)
    NMI = 2,
    /// Exception (fault or trap)
    Exception = 3,
    /// Software interrupt (caused by INTn instruction)
    SoftIntr = 4,
}

impl VmcbIntInfo {
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
}

#[repr(u8)]
#[derive(Debug)]
pub enum VmcbTlbControl {
    /// Do not flush
    DoNotFlush = 0,
    /// Flush entire TLB (Should be used only on legacy hardware.)
    FlushAll = 0x01,
    /// Flush this guest's TLB entries
    FlushAsid = 0x03,
    /// Flush this guest's non-global TLB entries
    FlushAsidNonGlobal = 0x07,
}
