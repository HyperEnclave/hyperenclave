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

use core::convert::TryFrom;

#[derive(Debug, Clone, Copy)]
#[allow(non_camel_case_types)]
pub enum SvmExitCode {
    CR_READ(u8),
    CR_WRITE(u8),
    DR_READ(u8),
    DR_WRITE(u8),
    EXCP(u8),
    INTR,
    NMI,
    SMI,
    INIT,
    VINTR,
    CR0_SEL_WRITE,
    IDTR_READ,
    GDTR_READ,
    LDTR_READ,
    TR_READ,
    IDTR_WRITE,
    GDTR_WRITE,
    LDTR_WRITE,
    TR_WRITE,
    RDTSC,
    RDPMC,
    PUSHF,
    POPF,
    CPUID,
    RSM,
    IRET,
    SWINT,
    INVD,
    PAUSE,
    HLT,
    INVLPG,
    INVLPGA,
    IOIO,
    MSR,
    TASK_SWITCH,
    FERR_FREEZE,
    SHUTDOWN,
    VMRUN,
    VMMCALL,
    VMLOAD,
    VMSAVE,
    STGI,
    CLGI,
    SKINIT,
    RDTSCP,
    ICEBP,
    WBINVD,
    MONITOR,
    MWAIT,
    MWAIT_CONDITIONAL,
    XSETBV,
    RDPRU,
    EFER_WRITE_TRAP,
    CR_WRITE_TRAP(u8),
    INVLPGB,
    INVLPGB_ILLEGAL,
    INVPCID,
    MCOMMIT,
    TLBSYNC,
    NPF,
    AVIC_INCOMPLETE_IPI,
    AVIC_NOACCEL,
    VMGEXIT,
    INVALID,
    BUSY,
}

impl TryFrom<u64> for SvmExitCode {
    type Error = u64;
    fn try_from(val: u64) -> Result<Self, Self::Error> {
        match val as i64 {
            0x00..=0x0F => Ok(Self::CR_READ(val as u8)),
            0x10..=0x1F => Ok(Self::CR_WRITE(val as u8 - 0x10)),
            0x20..=0x2F => Ok(Self::DR_READ(val as u8 - 0x20)),
            0x30..=0x3F => Ok(Self::DR_WRITE(val as u8 - 0x30)),
            0x40..=0x5F => Ok(Self::EXCP(val as u8 - 0x40)),
            0x60 => Ok(Self::INTR),
            0x61 => Ok(Self::NMI),
            0x62 => Ok(Self::SMI),
            0x63 => Ok(Self::INIT),
            0x64 => Ok(Self::VINTR),
            0x65 => Ok(Self::CR0_SEL_WRITE),
            0x66 => Ok(Self::IDTR_READ),
            0x67 => Ok(Self::GDTR_READ),
            0x68 => Ok(Self::LDTR_READ),
            0x69 => Ok(Self::TR_READ),
            0x6A => Ok(Self::IDTR_WRITE),
            0x6B => Ok(Self::GDTR_WRITE),
            0x6C => Ok(Self::LDTR_WRITE),
            0x6D => Ok(Self::TR_WRITE),
            0x6E => Ok(Self::RDTSC),
            0x6F => Ok(Self::RDPMC),
            0x70 => Ok(Self::PUSHF),
            0x71 => Ok(Self::POPF),
            0x72 => Ok(Self::CPUID),
            0x73 => Ok(Self::RSM),
            0x74 => Ok(Self::IRET),
            0x75 => Ok(Self::SWINT),
            0x76 => Ok(Self::INVD),
            0x77 => Ok(Self::PAUSE),
            0x78 => Ok(Self::HLT),
            0x79 => Ok(Self::INVLPG),
            0x7A => Ok(Self::INVLPGA),
            0x7B => Ok(Self::IOIO),
            0x7C => Ok(Self::MSR),
            0x7D => Ok(Self::TASK_SWITCH),
            0x7E => Ok(Self::FERR_FREEZE),
            0x7F => Ok(Self::SHUTDOWN),
            0x80 => Ok(Self::VMRUN),
            0x81 => Ok(Self::VMMCALL),
            0x82 => Ok(Self::VMLOAD),
            0x83 => Ok(Self::VMSAVE),
            0x84 => Ok(Self::STGI),
            0x85 => Ok(Self::CLGI),
            0x86 => Ok(Self::SKINIT),
            0x87 => Ok(Self::RDTSCP),
            0x88 => Ok(Self::ICEBP),
            0x89 => Ok(Self::WBINVD),
            0x8A => Ok(Self::MONITOR),
            0x8B => Ok(Self::MWAIT),
            0x8C => Ok(Self::MWAIT_CONDITIONAL),
            0x8D => Ok(Self::XSETBV),
            0x8E => Ok(Self::RDPRU),
            0x8F => Ok(Self::EFER_WRITE_TRAP),
            0x90..=0x9F => Ok(Self::CR_WRITE_TRAP(val as u8 - 0x90)),
            0xA0 => Ok(Self::INVLPGB),
            0xA1 => Ok(Self::INVLPGB_ILLEGAL),
            0xA2 => Ok(Self::INVPCID),
            0xA3 => Ok(Self::MCOMMIT),
            0xA4 => Ok(Self::TLBSYNC),
            0x400 => Ok(Self::NPF),
            0x401 => Ok(Self::AVIC_INCOMPLETE_IPI),
            0x402 => Ok(Self::AVIC_NOACCEL),
            0x403 => Ok(Self::VMGEXIT),
            -1 => Ok(Self::INVALID),
            -2 => Ok(Self::BUSY),
            _ => Err(val),
        }
    }
}

#[repr(u8)]
#[derive(Debug, Clone, Copy)]
#[allow(non_camel_case_types)]
pub enum SvmIntercept {
    // 0x0C (vector 3)
    INTR = 0x60,
    NMI = 0x61,
    SMI = 0x62,
    INIT = 0x63,
    VINTR = 0x64,
    CR0_SEL_WRITE = 0x65,
    IDTR_READ = 0x66,
    GDTR_READ = 0x67,
    LDTR_READ = 0x68,
    TR_READ = 0x69,
    IDTR_WRITE = 0x6A,
    GDTR_WRITE = 0x6B,
    LDTR_WRITE = 0x6C,
    TR_WRITE = 0x6D,
    RDTSC = 0x6E,
    RDPMC = 0x6F,
    PUSHF = 0x70,
    POPF = 0x71,
    CPUID = 0x72,
    RSM = 0x73,
    IRET = 0x74,
    SWINT = 0x75,
    INVD = 0x76,
    PAUSE = 0x77,
    HLT = 0x78,
    INVLPG = 0x79,
    INVLPGA = 0x7A,
    IOIO_PROT = 0x7B,
    MSR_PROT = 0x7C,
    TASK_SWITCH = 0x7D,
    FERR_FREEZE = 0x7E,
    SHUTDOWN = 0x7F,
    // 0x10 (vector 4)
    VMRUN = 0x80,
    VMMCALL = 0x81,
    VMLOAD = 0x82,
    VMSAVE = 0x83,
    STGI = 0x84,
    CLGI = 0x85,
    SKINIT = 0x86,
    RDTSCP = 0x87,
    ICEBP = 0x88,
    WBINVD = 0x89,
    MONITOR = 0x8A,
    MWAIT = 0x8B,
    MWAIT_CONDITIONAL = 0x8C,
    XSETBV = 0x8D,
    RDPRU = 0x8E,
    EFER_WRITE_TRAP = 0x8F,
    // 0x14 (vector 5)
    INVLPGB = 0xA0,
    INVLPGB_ILLEGAL = 0xA1,
    INVPCID = 0xA2,
    MCOMMIT = 0xA3,
    TLBSYNC = 0xA4,
}
