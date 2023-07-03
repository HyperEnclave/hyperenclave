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

use crate::error::HvResult;
use crate::memory::addr::{phys_encrypted, virt_to_phys};
use crate::memory::{AlignedPage, Frame, PhysAddr};

pub(super) struct VmxRegion {
    frame: Frame,
}

impl VmxRegion {
    pub fn new(revision_id: u32, shadow_indicator: bool) -> HvResult<Self> {
        let frame = Frame::new()?;
        unsafe {
            (*(frame.as_mut_ptr() as *mut u32))
                .set_bits(0..=30, revision_id)
                .set_bit(31, shadow_indicator);
        }
        Ok(Self { frame })
    }

    pub fn paddr(&self) -> PhysAddr {
        self.frame.start_paddr()
    }
}

pub(super) struct MsrBitmap(AlignedPage);

impl MsrBitmap {
    fn mask_range(&mut self, msr_range: core::ops::RangeInclusive<u32>, is_write: bool) {
        for msr in msr_range {
            self.mask(msr, is_write);
        }
    }

    fn mask(&mut self, msr: u32, is_write: bool) {
        // (Intel SDM Volume 3, Section 24.6.9, MSR-Bitmap Address)
        // There are four contiguous MSR bitmaps, which are each 1-KByte in size:
        // 1. Read bitmap for low MSRs (0x0000_0000..0x0000_1FFF)
        // 2. Read bitmap for high MSRs (0xC000_0000..0xC000_1FFF)
        // 3. Write bitmap for low MSRs (0x0000_0000..0x0000_1FFF)
        // 4. Write bitmap for high MSRs (0xC000_0000..0xC000_1FFF)
        let mut ptr = self.0.as_mut_ptr();
        let msr_low = msr & 0x1fff;
        let msr_byte = (msr_low / 8) as usize;
        let msr_bit = (msr_low % 8) as u8;

        unsafe {
            if msr >= 0xc000_0000 {
                ptr = ptr.add(1 << 10);
            }
            if is_write {
                ptr = ptr.add(2 << 10);
            }
            core::slice::from_raw_parts_mut(ptr, 1024)[msr_byte] &= 1 << msr_bit;
        }
    }

    pub fn paddr(&self) -> usize {
        phys_encrypted(virt_to_phys(self.0.as_ptr() as usize))
    }
}

impl Default for MsrBitmap {
    fn default() -> Self {
        let mut map = Self(AlignedPage::new());
        // read
        map.mask(0x277, false); // IA32_PAT
        map.mask(0x2FF, false); // IA32_MTRR_DEF_TYPE

        map.mask(0x802, false); // IA32_X2APIC_APICID
        map.mask(0x803, false); // IA32_X2APIC_VERSION
        map.mask(0x808, false); // IA32_X2APIC_TPR
        map.mask(0x80A, false); // IA32_X2APIC_PPR
        map.mask(0x80D, false); // IA32_X2APIC_LDR
        map.mask(0x80F, false); // IA32_X2APIC_SIVR
        map.mask_range(0x810..=0x817, false); // IA32_X2APIC_ISR0..IA32_X2APIC_ISR7
        map.mask_range(0x818..=0x81F, false); // IA32_X2APIC_TMR0..IA32_X2APIC_TMR7
        map.mask_range(0x820..=0x827, false); // IA32_X2APIC_IRR0..IA32_X2APIC_IRR7
        map.mask(0x828, false); // IA32_X2APIC_ESR
        map.mask(0x82F, false); // IA32_X2APIC_LVT_CMCI
        map.mask(0x830, false); // IA32_X2APIC_ICR
        map.mask_range(0x832..=0x837, false); // IA32_X2APIC_LVT_*
        map.mask(0x838, false); // IA32_X2APIC_INIT_COUNT
        map.mask(0x839, false); // IA32_X2APIC_CUR_COUNT
        map.mask(0x83E, false); // IA32_X2APIC_DIV_CONF

        // write
        map.mask(0x1B, true); // IA32_APIC_BASE
        map.mask_range(0x200..=0x277, true); // IA32_MTRR_*
        map.mask(0x277, true); // IA32_PAT
        map.mask(0x2FF, true); // IA32_MTRR_DEF_TYPE
        map.mask(0x38F, true); // IA32_PERF_GLOBAL_CTRL
        map.mask_range(0xC80..=0xD8F, true);

        map.mask(0x808, true); // IA32_X2APIC_TPR
        map.mask(0x80B, true); // IA32_X2APIC_EOI
        map.mask(0x80F, true); // IA32_X2APIC_SIVR
        map.mask(0x828, true); // IA32_X2APIC_ESR
        map.mask(0x82F, true); // IA32_X2APIC_LVT_CMCI
        map.mask(0x830, true); // IA32_X2APIC_ICR
        map.mask_range(0x832..=0x837, true); // IA32_X2APIC_LVT_*
        map.mask(0x838, true); // IA32_X2APIC_INIT_COUNT
        map.mask(0x839, true); // IA32_X2APIC_CUR_COUNT
        map.mask(0x83E, true); // IA32_X2APIC_DIV_CONF

        map
    }
}
