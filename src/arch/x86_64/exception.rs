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

use bitflags::bitflags;

use super::context::GuestRegisters;

global_asm!(include_str!(concat!(env!("OUT_DIR"), "/exception.S")));

#[allow(dead_code)]
#[allow(non_snake_case)]
#[allow(non_upper_case_globals)]
pub mod ExceptionType {
    pub const DivideError: u8 = 0;
    pub const Debug: u8 = 1;
    pub const NonMaskableInterrupt: u8 = 2;
    pub const Breakpoint: u8 = 3;
    pub const Overflow: u8 = 4;
    pub const BoundRangeExceeded: u8 = 5;
    pub const InvalidOpcode: u8 = 6;
    pub const DeviceNotAvailable: u8 = 7;
    pub const DoubleFault: u8 = 8;
    pub const CoprocessorSegmentOverrun: u8 = 9;
    pub const InvalidTSS: u8 = 10;
    pub const SegmentNotPresent: u8 = 11;
    pub const StackSegmentFault: u8 = 12;
    pub const GeneralProtectionFault: u8 = 13;
    pub const PageFault: u8 = 14;
    pub const FloatingPointException: u8 = 16;
    pub const AlignmentCheck: u8 = 17;
    pub const MachineCheck: u8 = 18;
    pub const SIMDFloatingPointException: u8 = 19;
    pub const VirtualizationException: u8 = 20;
    pub const ControlProtectionException: u8 = 21;
    pub const SecurityException: u8 = 30;

    pub const IrqStart: u8 = 32;
    pub const IrqEnd: u8 = 255;

    pub fn has_error_code(exception_type: u8) -> bool {
        matches!(
            exception_type,
            DoubleFault
                | InvalidTSS
                | SegmentNotPresent
                | StackSegmentFault
                | GeneralProtectionFault
                | PageFault
                | AlignmentCheck
                | ControlProtectionException
        )
    }
}

#[repr(C)]
#[derive(Debug)]
pub struct ExceptionFrame {
    // Pushed by `common_exception_entry`
    regs: GuestRegisters,

    // Pushed by 'exception.S'
    num: usize,
    error_code: usize,

    // Pushed by CPU
    rip: usize,
    cs: usize,
    rflags: usize,

    rsp: usize,
    ss: usize,
}

bitflags! {
    /// Describes an page fault error code.
    ///
    /// This structure is defined by the following manual sections:
    ///   * AMD Volume 2: 8.4.2
    ///   * Intel Volume 3A: 4.7
    #[repr(transparent)]
    pub struct PageFaultErrorCode: u32 {
        /// If this flag is set, the page fault was caused by a page-protection violation,
        /// else the page fault was caused by a not-present page.
        const PROTECTION_VIOLATION = 1 << 0;

        /// If this flag is set, the memory access that caused the page fault was a write.
        /// Else the access that caused the page fault is a memory read. This bit does not
        /// necessarily indicate the cause of the page fault was a read or write violation.
        const CAUSED_BY_WRITE = 1 << 1;

        /// If this flag is set, an access in user mode (CPL=3) caused the page fault. Else
        /// an access in supervisor mode (CPL=0, 1, or 2) caused the page fault. This bit
        /// does not necessarily indicate the cause of the page fault was a privilege violation.
        const USER_MODE = 1 << 2;

        /// If this flag is set, the page fault is a result of the processor reading a 1 from
        /// a reserved field within a page-translation-table entry.
        const MALFORMED_TABLE = 1 << 3;

        /// If this flag is set, it indicates that the access that caused the page fault was an
        /// instruction fetch.
        const INSTRUCTION_FETCH = 1 << 4;
    }
}

#[derive(Copy, Clone, Debug)]
pub struct ExceptionInfo {
    pub exception_type: u8,
    pub error_code: Option<u32>,
    pub cr2: Option<u64>,
}

impl ExceptionInfo {
    pub fn new(exception_type: u8, error_code: Option<u32>, cr2: Option<u64>) -> Self {
        ExceptionInfo {
            exception_type,
            error_code,
            cr2,
        }
    }
}

fn exception_handler(frame: &ExceptionFrame) {
    trace!("Exception or interrupt #{:#x}", frame.num);
    match frame.num as u8 {
        ExceptionType::NonMaskableInterrupt => handle_nmi(),
        ExceptionType::PageFault => handle_page_fault(frame),
        ExceptionType::IrqStart..=ExceptionType::IrqEnd => {
            error!("{:#x?}", frame);
            panic!("Unhandled interrupt #{:#x}", frame.num);
        }
        _ => {
            error!("{:#x?}", frame);
            panic!("Unhandled exception #{:#x}", frame.num);
        }
    }
}

fn handle_nmi() {
    warn!("Unhandled exception: NMI");
}

fn handle_page_fault(frame: &ExceptionFrame) {
    panic!(
        "Unhandled hypervisor page fault @ {:#x?}, error_code={:#x}: {:#x?}",
        x86_64::registers::control::Cr2::read(),
        frame.error_code,
        frame
    );
}

#[naked]
#[no_mangle]
#[inline(never)]
unsafe extern "sysv64" fn common_exception_entry() -> ! {
    asm!(
        save_regs_to_stack!(),
        "mov rdi, rsp",
        "call {0}",
        restore_regs_from_stack!(),
        "add rsp, 16",  // skip num, error_code
        "iretq",
        sym exception_handler,
        options(noreturn),
    );
}
