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

use spin::Mutex;
use x86::{segmentation::SegmentSelector, task, Ring};
use x86_64::addr::VirtAddr;
use x86_64::instructions::tables::{lgdt, lidt, sidt};
use x86_64::structures::gdt::{Descriptor, DescriptorFlags};
use x86_64::structures::idt::{Entry, HandlerFunc, InterruptDescriptorTable};
use x86_64::structures::{tss::TaskStateSegment, DescriptorTablePointer};

use super::segmentation::SegmentAccessRights;

const TSS: TaskStateSegment = TaskStateSegment::new();

lazy_static! {
    pub(super) static ref GDT: Mutex<GDTStruct> = Mutex::new(GDTStruct::new());
    pub(super) static ref IDT: Mutex<IDTStruct> = Mutex::new(IDTStruct::new());
}

#[derive(Debug)]
pub(super) struct GDTStruct {
    table: [u64; 16],
    pointer: DescriptorTablePointer,
}

impl GDTStruct {
    pub const KCODE_SELECTOR: SegmentSelector = SegmentSelector::new(1, Ring::Ring0);
    pub const TSS_SELECTOR: SegmentSelector = SegmentSelector::new(2, Ring::Ring0);

    pub fn new() -> Self {
        let mut table = [0; 16];
        table[1] = DescriptorFlags::KERNEL_CODE64.bits();
        let tss_desc = Descriptor::tss_segment(&TSS);
        match tss_desc {
            Descriptor::SystemSegment(low, high) => {
                table[2] = low;
                table[3] = high;
            }
            _ => unreachable!(),
        }
        Self {
            table,
            pointer: DescriptorTablePointer {
                limit: 0,
                base: VirtAddr::new(0),
            },
        }
    }

    pub fn sgdt() -> DescriptorTablePointer {
        let mut gdt_ptr = DescriptorTablePointer {
            limit: 0,
            base: VirtAddr::new(0),
        };
        unsafe { asm!("sgdt [{0}]", in(reg) &mut gdt_ptr, options(nostack, preserves_flags)) };
        gdt_ptr
    }

    pub fn lgdt(pointer: &DescriptorTablePointer) {
        unsafe { lgdt(pointer) };
    }

    pub fn table_of(pointer: &DescriptorTablePointer) -> &[u64] {
        let entry_count = (pointer.limit as usize + 1) / core::mem::size_of::<u64>();
        unsafe { core::slice::from_raw_parts(pointer.base.as_ptr(), entry_count) }
    }

    #[allow(clippy::mut_from_ref)]
    pub fn table_of_mut(pointer: &DescriptorTablePointer) -> &mut [u64] {
        let entry_count = (pointer.limit as usize + 1) / core::mem::size_of::<u64>();
        unsafe { core::slice::from_raw_parts_mut(pointer.base.as_mut_ptr(), entry_count) }
    }

    pub fn pointer(&self) -> &DescriptorTablePointer {
        &self.pointer
    }

    pub fn load(&mut self) {
        self.pointer = DescriptorTablePointer {
            base: VirtAddr::new(self.table.as_ptr() as u64),
            limit: core::mem::size_of_val(&self.table) as u16 - 1,
        };
        Self::lgdt(self.pointer());
    }

    pub fn load_tss(&mut self, selector: SegmentSelector) {
        assert_ne!(self.pointer.base.as_u64(), 0);
        SegmentAccessRights::set_descriptor_type(
            &mut Self::table_of_mut(&self.pointer)[selector.index() as usize],
            SegmentAccessRights::TSS_AVAIL,
        );
        unsafe { task::load_tr(selector) };
    }
}

pub(super) struct IDTStruct {
    table: InterruptDescriptorTable,
    pointer: DescriptorTablePointer,
}

impl IDTStruct {
    pub fn new() -> Self {
        extern "C" {
            #[link_name = "exception_entries"]
            static ENTRIES: [extern "C" fn(); 256];
        }

        let mut ret = Self {
            table: InterruptDescriptorTable::new(),
            pointer: DescriptorTablePointer {
                limit: 0,
                base: VirtAddr::new(0),
            },
        };
        let entries = unsafe {
            core::slice::from_raw_parts_mut(
                &mut ret.table as *mut _ as *mut Entry<HandlerFunc>,
                256,
            )
        };
        for i in 0..256 {
            entries[i].set_handler_fn(unsafe { core::mem::transmute(ENTRIES[i]) });
        }
        ret
    }

    pub fn sidt() -> DescriptorTablePointer {
        sidt()
    }

    pub fn lidt(pointer: &DescriptorTablePointer) {
        unsafe { lidt(pointer) };
    }

    #[allow(dead_code)]
    pub fn pointer(&self) -> &DescriptorTablePointer {
        &self.pointer
    }

    pub fn load(&mut self) {
        unsafe { self.table.load_unsafe() };
        self.pointer = Self::sidt();
    }
}
