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

#![cfg_attr(not(feature = "intel"), allow(dead_code))]

use bitflags::bitflags;

pub use raw_cpuid::{cpuid, CpuId};

#[repr(u32)]
#[derive(Debug)]
#[allow(dead_code)]
pub(super) enum CpuIdEax {
    VendorInfo = 0x0,
    FeatureInfo = 0x1,
    ExtendedStateInfo = 0xD,
    HypervisorInfo = 0x4000_0000,
    HypervisorFeatures = 0x4000_0001,
    AmdFeatureInfo = 0x8000_0001,
}

bitflags! {
    /// Copied from https://docs.rs/raw-cpuid/8.1.2/src/raw_cpuid/lib.rs.html#1290-1294
    pub(super) struct FeatureInfoFlags: u64 {

        // ECX flags

        /// Streaming SIMD Extensions 3 (SSE3). A value of 1 indicates the processor supports this technology.
        #[allow(clippy::identity_op)]
        const SSE3 = 1 << 0;
        /// PCLMULQDQ. A value of 1 indicates the processor supports the PCLMULQDQ instruction
        const PCLMULQDQ = 1 << 1;
        /// 64-bit DS Area. A value of 1 indicates the processor supports DS area using 64-bit layout
        const DTES64 = 1 << 2;
        /// MONITOR/MWAIT. A value of 1 indicates the processor supports this feature.
        const MONITOR = 1 << 3;
        /// CPL Qualified Debug Store. A value of 1 indicates the processor supports the extensions to the  Debug Store feature to allow for branch message storage qualified by CPL.
        const DSCPL = 1 << 4;
        /// Virtual Machine Extensions. A value of 1 indicates that the processor supports this technology.
        const VMX = 1 << 5;
        /// Safer Mode Extensions. A value of 1 indicates that the processor supports this technology. See Chapter 5, Safer Mode Extensions Reference.
        const SMX = 1 << 6;
        /// Enhanced Intel SpeedStep® technology. A value of 1 indicates that the processor supports this technology.
        const EIST = 1 << 7;
        /// Thermal Monitor 2. A value of 1 indicates whether the processor supports this technology.
        const TM2 = 1 << 8;
        /// A value of 1 indicates the presence of the Supplemental Streaming SIMD Extensions 3 (SSSE3). A value of 0 indicates the instruction extensions are not present in the processor
        const SSSE3 = 1 << 9;
        /// L1 Context ID. A value of 1 indicates the L1 data cache mode can be set to either adaptive mode or shared mode. A value of 0 indicates this feature is not supported. See definition of the IA32_MISC_ENABLE MSR Bit 24 (L1 Data Cache Context Mode) for details.
        const CNXTID = 1 << 10;
        /// A value of 1 indicates the processor supports FMA extensions using YMM state.
        const FMA = 1 << 12;
        /// CMPXCHG16B Available. A value of 1 indicates that the feature is available. See the CMPXCHG8B/CMPXCHG16B Compare and Exchange Bytes section. 14
        const CMPXCHG16B = 1 << 13;
        /// Perfmon and Debug Capability: A value of 1 indicates the processor supports the performance   and debug feature indication MSR IA32_PERF_CAPABILITIES.
        const PDCM = 1 << 15;
        /// Process-context identifiers. A value of 1 indicates that the processor supports PCIDs and the software may set CR4.PCIDE to 1.
        const PCID = 1 << 17;
        /// A value of 1 indicates the processor supports the ability to prefetch data from a memory mapped device.
        const DCA = 1 << 18;
        /// A value of 1 indicates that the processor supports SSE4.1.
        const SSE41 = 1 << 19;
        /// A value of 1 indicates that the processor supports SSE4.2.
        const SSE42 = 1 << 20;
        /// A value of 1 indicates that the processor supports x2APIC feature.
        const X2APIC = 1 << 21;
        /// A value of 1 indicates that the processor supports MOVBE instruction.
        const MOVBE = 1 << 22;
        /// A value of 1 indicates that the processor supports the POPCNT instruction.
        const POPCNT = 1 << 23;
        /// A value of 1 indicates that the processors local APIC timer supports one-shot operation using a TSC deadline value.
        const TSC_DEADLINE = 1 << 24;
        /// A value of 1 indicates that the processor supports the AESNI instruction extensions.
        const AESNI = 1 << 25;
        /// A value of 1 indicates that the processor supports the XSAVE/XRSTOR processor extended states feature, the XSETBV/XGETBV instructions, and XCR0.
        const XSAVE = 1 << 26;
        /// A value of 1 indicates that the OS has enabled XSETBV/XGETBV instructions to access XCR0, and support for processor extended state management using XSAVE/XRSTOR.
        const OSXSAVE = 1 << 27;
        /// A value of 1 indicates the processor supports the AVX instruction extensions.
        const AVX = 1 << 28;
        /// A value of 1 indicates that processor supports 16-bit floating-point conversion instructions.
        const F16C = 1 << 29;
        /// A value of 1 indicates that processor supports RDRAND instruction.
        const RDRAND = 1 << 30;
        /// A value of 1 indicates the indicates the presence of a hypervisor.
        const HYPERVISOR = 1 << 31;


        // EDX flags

        /// Floating Point Unit On-Chip. The processor contains an x87 FPU.
        #[allow(clippy::identity_op)]
        const FPU = 1 << (32 + 0);
        /// Virtual 8086 Mode Enhancements. Virtual 8086 mode enhancements, including CR4.VME for controlling the feature, CR4.PVI for protected mode virtual interrupts, software interrupt indirection, expansion of the TSS with the software indirection bitmap, and EFLAGS.VIF and EFLAGS.VIP flags.
        const VME = 1 << (32 + 1);
        /// Debugging Extensions. Support for I/O breakpoints, including CR4.DE for controlling the feature, and optional trapping of accesses to DR4 and DR5.
        const DE = 1 << (32 + 2);
        /// Page Size Extension. Large pages of size 4 MByte are supported, including CR4.PSE for controlling the feature, the defined dirty bit in PDE (Page Directory Entries), optional reserved bit trapping in CR3, PDEs, and PTEs.
        const PSE = 1 << (32 + 3);
        /// Time Stamp Counter. The RDTSC instruction is supported, including CR4.TSD for controlling privilege.
        const TSC = 1 << (32 + 4);
        /// Model Specific Registers RDMSR and WRMSR Instructions. The RDMSR and WRMSR instructions are supported. Some of the MSRs are implementation dependent.
        const MSR = 1 << (32 + 5);
        /// Physical Address Extension. Physical addresses greater than 32 bits are supported: extended page table entry formats, an extra level in the page translation tables is defined, 2-MByte pages are supported instead of 4 Mbyte pages if PAE bit is 1.
        const PAE = 1 << (32 + 6);
        /// Machine Check Exception. Exception 18 is defined for Machine Checks, including CR4.MCE for controlling the feature. This feature does not define the model-specific implementations of machine-check error logging, reporting, and processor shutdowns. Machine Check exception handlers may have to depend on processor version to do model specific processing of the exception, or test for the presence of the Machine Check feature.
        const MCE = 1 << (32 + 7);
        /// CMPXCHG8B Instruction. The compare-and-exchange 8 bytes (64 bits) instruction is supported (implicitly locked and atomic).
        const CX8 = 1 << (32 + 8);
        /// APIC On-Chip. The processor contains an Advanced Programmable Interrupt Controller (APIC), responding to memory mapped commands in the physical address range FFFE0000H to FFFE0FFFH (by default - some processors permit the APIC to be relocated).
        const APIC = 1 << (32 + 9);
        /// SYSENTER and SYSEXIT Instructions. The SYSENTER and SYSEXIT and associated MSRs are supported.
        const SEP = 1 << (32 + 11);
        /// Memory Type Range Registers. MTRRs are supported. The MTRRcap MSR contains feature bits that describe what memory types are supported, how many variable MTRRs are supported, and whether fixed MTRRs are supported.
        const MTRR = 1 << (32 + 12);
        /// Page Global Bit. The global bit is supported in paging-structure entries that map a page, indicating TLB entries that are common to different processes and need not be flushed. The CR4.PGE bit controls this feature.
        const PGE = 1 << (32 + 13);
        /// Machine Check Architecture. The Machine Check exArchitecture, which provides a compatible mechanism for error reporting in P6 family, Pentium 4, Intel Xeon processors, and future processors, is supported. The MCG_CAP MSR contains feature bits describing how many banks of error reporting MSRs are supported.
        const MCA = 1 << (32 + 14);
        /// Conditional Move Instructions. The conditional move instruction CMOV is supported. In addition, if x87 FPU is present as indicated by the CPUID.FPU feature bit, then the FCOMI and FCMOV instructions are supported
        const CMOV = 1 << (32 + 15);
        /// Page Attribute Table. Page Attribute Table is supported. This feature augments the Memory Type Range Registers (MTRRs), allowing an operating system to specify attributes of memory accessed through a linear address on a 4KB granularity.
        const PAT = 1 << (32 + 16);
        /// 36-Bit Page Size Extension. 4-MByte pages addressing physical memory beyond 4 GBytes are supported with 32-bit paging. This feature indicates that upper bits of the physical address of a 4-MByte page are encoded in bits 20:13 of the page-directory entry. Such physical addresses are limited by MAXPHYADDR and may be up to 40 bits in size.
        const PSE36 = 1 << (32 + 17);
        /// Processor Serial Number. The processor supports the 96-bit processor identification number feature and the feature is enabled.
        const PSN = 1 << (32 + 18);
        /// CLFLUSH Instruction. CLFLUSH Instruction is supported.
        const CLFSH = 1 << (32 + 19);
        /// Debug Store. The processor supports the ability to write debug information into a memory resident buffer. This feature is used by the branch trace store (BTS) and precise event-based sampling (PEBS) facilities (see Chapter 23, Introduction to Virtual-Machine Extensions, in the Intel® 64 and IA-32 Architectures Software Developers Manual, Volume 3C).
        const DS = 1 << (32 + 21);
        /// Thermal Monitor and Software Controlled Clock Facilities. The processor implements internal MSRs that allow processor temperature to be monitored and processor performance to be modulated in predefined duty cycles under software control.
        const ACPI = 1 << (32 + 22);
        /// Intel MMX Technology. The processor supports the Intel MMX technology.
        const MMX = 1 << (32 + 23);
        /// FXSAVE and FXRSTOR Instructions. The FXSAVE and FXRSTOR instructions are supported for fast save and restore of the floating point context. Presence of this bit also indicates that CR4.OSFXSR is available for an operating system to indicate that it supports the FXSAVE and FXRSTOR instructions.
        const FXSR = 1 << (32 + 24);
        /// SSE. The processor supports the SSE extensions.
        const SSE = 1 << (32 + 25);
        /// SSE2. The processor supports the SSE2 extensions.
        const SSE2 = 1 << (32 + 26);
        /// Self Snoop. The processor supports the management of conflicting memory types by performing a snoop of its own cache structure for transactions issued to the bus.
        const SS = 1 << (32 + 27);
        /// Max APIC IDs reserved field is Valid. A value of 0 for HTT indicates there is only a single logical processor in the package and software should assume only a single APIC ID is reserved.  A value of 1 for HTT indicates the value in CPUID.1.EBX[23:16] (the Maximum number of addressable IDs for logical processors in this package) is valid for the package.
        const HTT = 1 << (32 + 28);
        /// Thermal Monitor. The processor implements the thermal monitor automatic thermal control circuitry (TCC).
        const TM = 1 << (32 + 29);
        /// Pending Break Enable. The processor supports the use of the FERR#/PBE# pin when the processor is in the stop-clock state (STPCLK# is asserted) to signal the processor that an interrupt is pending and that the processor should return to normal operation to handle the interrupt. Bit 10 (PBE enable) in the IA32_MISC_ENABLE MSR enables this capability.
        const PBE = 1 << (32 + 31);


        // 0x80000001, AMD Extended Processor Info and Feature Bits.

        /// Secure Virtual Machine.
        const SVM = 1 << 2;
    }
}

pub struct CpuFeatures {
    cpuid: CpuId,
}

impl CpuFeatures {
    pub fn new() -> Self {
        Self {
            cpuid: CpuId::new(),
        }
    }

    pub fn perf_monitor_version_id(&self) -> u8 {
        if let Some(info) = self.cpuid.get_performance_monitoring_info() {
            info.version_id()
        } else {
            0
        }
    }

    pub fn has_vmx(&self) -> bool {
        if let Some(info) = self.cpuid.get_feature_info() {
            info.has_vmx()
        } else {
            false
        }
    }

    pub fn has_xsave(&self) -> bool {
        if let Some(info) = self.cpuid.get_feature_info() {
            info.has_xsave()
        } else {
            false
        }
    }

    pub fn has_pae(&self) -> bool {
        if let Some(info) = self.cpuid.get_feature_info() {
            info.has_pae()
        } else {
            false
        }
    }

    pub fn has_rdtscp(&self) -> bool {
        if let Some(info) = self.cpuid.get_extended_processor_and_feature_identifiers() {
            info.has_rdtscp()
        } else {
            false
        }
    }

    pub fn has_invpcid(&self) -> bool {
        if let Some(info) = self.cpuid.get_extended_feature_info() {
            info.has_invpcid()
        } else {
            false
        }
    }

    pub fn has_xsaves_xrstors(&self) -> bool {
        if let Some(info) = self.cpuid.get_extended_state_info() {
            info.has_xsaves_xrstors()
        } else {
            false
        }
    }

    /// Information (`offset`, `size`) for extended state component specified by `sub_leaf`,
    /// if it is supported in XCR0
    pub fn xsave_state_info(&self, sub_leaf: u32) -> (usize, usize) {
        if self.cpuid.get_extended_state_info().is_some() && sub_leaf > 1 {
            let res = cpuid!(CpuIdEax::ExtendedStateInfo, sub_leaf);
            // If ECX contains an invalid sub-leaf index, EAX/EBX/ECX/EDX return 0
            if res.eax != 0 && res.ebx != 0 && res.ecx != 0 && res.edx != 0 {
                // Bit 00 in ECX is clear if sub_leaf n is supported in XCR0
                if res.ecx & 0b1 == 0b0 {
                    let size = res.eax;
                    let offset = res.ebx;
                    return (offset as _, size as _);
                }
            }
        }

        (0, 0)
    }

    pub fn xcr0_supported_bits(&self) -> u64 {
        if self.cpuid.get_extended_state_info().is_some() {
            let res = cpuid!(CpuIdEax::ExtendedStateInfo, 0);
            (res.eax as u64) | (res.edx as u64) << 32
        } else {
            0
        }
    }
}
