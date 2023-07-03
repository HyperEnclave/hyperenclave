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

use core::fmt::{Debug, Formatter, Result};
use core::mem::MaybeUninit;

use bit_field::BitField;

use super::flags::{VmcbCleanBits, VmcbIntInfo};
use super::{SvmExitCode, SvmIntercept};

#[repr(C, align(1024))]
pub struct VmcbControlArea {
    pub intercept_cr: u32,
    pub intercept_dr: u32,
    pub intercept_exceptions: u32,
    pub intercept_vector3: u32,
    pub intercept_vector4: u32,
    pub intercept_vector5: u32,
    _reserved1: [u32; 9],
    pub pause_filter_thresh: u16,
    pub pause_filter_count: u16,
    pub iopm_base_pa: u64,
    pub msrpm_base_pa: u64,
    pub tsc_offset: u64,
    pub guest_asid: u32,
    pub tlb_control: u8,
    _reserved2: [u8; 3],
    pub int_control: u32,
    pub int_vector: u32,
    pub int_state: u32,
    _reserved3: [u8; 4],
    pub exit_code: u64,
    pub exit_info_1: u64,
    pub exit_info_2: u64,
    pub exit_int_info: u32,
    pub exit_int_info_err: u32,
    pub np_enable: u8,
    _reserved4: [u8; 3],
    pub avic_vapic_bar: u64,
    _reserved5: [u8; 8],
    pub event_inj: u32,
    pub event_inj_err: u32,
    pub nest_cr3: u64,
    pub lbr_control: u64,
    pub clean_bits: VmcbCleanBits,
    _reserved6: u32,
    pub next_rip: u64,
    pub insn_len: u8,
    pub insn_bytes: [u8; 15],
    pub avic_backing_page: u64,
    _reserved7: [u8; 8],
    pub avic_logical_id: u64,
    pub avic_physical_id: u64,
}

#[repr(C)]
#[derive(Debug)]
pub struct VmcbSegment {
    pub selector: u16,
    pub attr: u16,
    pub limit: u32,
    pub base: u64,
}

#[repr(C, align(1024))]
pub struct VmcbStateSaveArea {
    pub es: VmcbSegment,
    pub cs: VmcbSegment,
    pub ss: VmcbSegment,
    pub ds: VmcbSegment,
    pub fs: VmcbSegment,
    pub gs: VmcbSegment,
    pub gdtr: VmcbSegment,
    pub ldtr: VmcbSegment,
    pub idtr: VmcbSegment,
    pub tr: VmcbSegment,
    _reserved1: [u8; 43],
    pub cpl: u8,
    _reserved2: [u8; 4],
    pub efer: u64,
    _reserved3: [u8; 112],
    pub cr4: u64,
    pub cr3: u64,
    pub cr0: u64,
    pub dr7: u64,
    pub dr6: u64,
    pub rflags: u64,
    pub rip: u64,
    _reserved4: [u8; 88],
    pub rsp: u64,
    pub s_cet: u64,
    pub ssp: u64,
    pub isst_addr: u64,
    pub rax: u64,
    pub star: u64,
    pub lstar: u64,
    pub cstar: u64,
    pub sfmask: u64,
    pub kernel_gs_base: u64,
    pub sysenter_cs: u64,
    pub sysenter_esp: u64,
    pub sysenter_eip: u64,
    pub cr2: u64,
    _reserved5: [u8; 32],
    pub g_pat: u64,
    pub dbgctl: u64,
    pub br_from: u64,
    pub br_to: u64,
    pub last_excp_from: u64,
    pub last_excp_to: u64,
}

#[derive(Debug)]
#[repr(C, align(4096))]
pub struct Vmcb {
    pub control: VmcbControlArea,
    pub save: VmcbStateSaveArea,
}

impl Vmcb {
    pub fn set_intercept(&mut self, which: SvmIntercept, set: bool) {
        let val = which as u8;
        if set {
            match val {
                0x60..=0x7F => self.control.intercept_vector3 |= 1 << (val - 0x60),
                0x80..=0x8F => self.control.intercept_vector4 |= 1 << (val - 0x80),
                0xA0..=0xA4 => self.control.intercept_vector5 |= 1 << (val - 0xA0),
                _ => {}
            }
        } else {
            match val {
                0x60..=0x7F => self.control.intercept_vector3 &= !(1 << (val - 0x60)),
                0x80..=0x8F => self.control.intercept_vector4 &= !(1 << (val - 0x80)),
                0xA0..=0xA4 => self.control.intercept_vector5 &= !(1 << (val - 0xA0)),
                _ => {}
            }
        }
    }

    pub fn inject_event(&mut self, info: VmcbIntInfo, error_code: u32) {
        self.control.event_inj = info.bits();
        self.control.event_inj_err = error_code;
    }
}

#[derive(Debug)]
pub struct VmExitInfo {
    pub exit_code: core::result::Result<SvmExitCode, u64>,
    pub exit_info_1: u64,
    pub exit_info_2: u64,
    pub guest_rip: u64,
}

impl VmExitInfo {
    pub fn new(vmcb: &Vmcb) -> Self {
        use core::convert::TryInto;
        Self {
            exit_code: vmcb.control.exit_code.try_into(),
            exit_info_1: vmcb.control.exit_info_1,
            exit_info_2: vmcb.control.exit_info_2,
            guest_rip: vmcb.save.rip,
        }
    }
}

#[derive(Debug)]
pub struct NptViolationInfo {
    pub guest_paddr: usize,
    pub present: bool,
    pub write: bool,
    pub user_mode: bool,
    pub reserved_bits_used: bool,
    pub execute: bool,
    pub shadow_stack_access: bool,
    pub final_translation: bool,
}

impl NptViolationInfo {
    pub fn from_exit_info(vm_exit_info: &VmExitInfo) -> Self {
        Self {
            guest_paddr: vm_exit_info.exit_info_2 as usize,
            present: vm_exit_info.exit_info_1.get_bit(0),
            write: vm_exit_info.exit_info_1.get_bit(1),
            user_mode: vm_exit_info.exit_info_1.get_bit(2),
            reserved_bits_used: vm_exit_info.exit_info_1.get_bit(3),
            execute: vm_exit_info.exit_info_1.get_bit(4),
            shadow_stack_access: vm_exit_info.exit_info_1.get_bit(6),
            final_translation: vm_exit_info.exit_info_1.get_bit(32),
        }
    }
}

impl Default for Vmcb {
    fn default() -> Self {
        unsafe { MaybeUninit::zeroed().assume_init() }
    }
}

impl Debug for VmcbControlArea {
    fn fmt(&self, f: &mut Formatter) -> Result {
        f.debug_struct("VmcbControlArea")
            .field("intercept_cr", &self.intercept_cr)
            .field("intercept_dr", &self.intercept_dr)
            .field("intercept_exceptions", &self.intercept_exceptions)
            .field("intercept_vector3", &self.intercept_vector3)
            .field("intercept_vector4", &self.intercept_vector4)
            .field("intercept_vector5", &self.intercept_vector5)
            .field("pause_filter_thresh", &self.pause_filter_thresh)
            .field("pause_filter_count", &self.pause_filter_count)
            .field("iopm_base_pa", &self.iopm_base_pa)
            .field("msrpm_base_pa", &self.msrpm_base_pa)
            .field("tsc_offset", &self.tsc_offset)
            .field("guest_asid", &self.guest_asid)
            .field("tlb_control", &self.tlb_control)
            .field("int_control", &self.int_control)
            .field("int_vector", &self.int_vector)
            .field("int_state", &self.int_state)
            .field("exit_code", &self.exit_code)
            .field("exit_info_1", &self.exit_info_1)
            .field("exit_info_2", &self.exit_info_2)
            .field("exit_int_info", &self.exit_int_info)
            .field("exit_int_info_err", &self.exit_int_info_err)
            .field("np_enable", &self.np_enable)
            .field("avic_vapic_bar", &self.avic_vapic_bar)
            .field("event_inj", &self.event_inj)
            .field("event_inj_err", &self.event_inj_err)
            .field("nest_cr3", &self.nest_cr3)
            .field("lbr_control", &self.lbr_control)
            .field("clean_bits", &self.clean_bits)
            .field("next_rip", &self.next_rip)
            .field("insn_len", &self.insn_len)
            .field("insn_bytes", &self.insn_bytes)
            .field("avic_backing_page", &self.avic_backing_page)
            .field("avic_logical_id", &self.avic_logical_id)
            .field("avic_physical_id", &self.avic_physical_id)
            .finish()
    }
}

impl Debug for VmcbStateSaveArea {
    fn fmt(&self, f: &mut Formatter) -> Result {
        f.debug_struct("VmcbStateSaveArea")
            .field("es", &self.es)
            .field("cs", &self.cs)
            .field("ss", &self.ss)
            .field("ds", &self.ds)
            .field("fs", &self.fs)
            .field("gs", &self.gs)
            .field("gdtr", &self.gdtr)
            .field("ldtr", &self.ldtr)
            .field("idtr", &self.idtr)
            .field("tr", &self.tr)
            .field("cpl", &self.cpl)
            .field("efer", &self.efer)
            .field("cr4", &self.cr4)
            .field("cr3", &self.cr3)
            .field("cr0", &self.cr0)
            .field("dr7", &self.dr7)
            .field("dr6", &self.dr6)
            .field("rflags", &self.rflags)
            .field("rip", &self.rip)
            .field("rsp", &self.rsp)
            .field("s_cet", &self.s_cet)
            .field("ssp", &self.ssp)
            .field("isst_addr", &self.isst_addr)
            .field("rax", &self.rax)
            .field("star", &self.star)
            .field("lstar", &self.lstar)
            .field("cstar", &self.cstar)
            .field("sfmask", &self.sfmask)
            .field("kernel_gs_base", &self.kernel_gs_base)
            .field("sysenter_cs", &self.sysenter_cs)
            .field("sysenter_esp", &self.sysenter_esp)
            .field("sysenter_eip", &self.sysenter_eip)
            .field("cr2", &self.cr2)
            .field("g_pat", &self.g_pat)
            .field("dbgctl", &self.dbgctl)
            .field("br_from", &self.br_from)
            .field("br_to", &self.br_to)
            .field("last_excp_from", &self.last_excp_from)
            .field("last_excp_to", &self.last_excp_to)
            .finish()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use core::mem::size_of;
    use memoffset::offset_of;

    macro_rules! assert_vmcb_ctrl_offset {
        ($field: ident, $offset: expr) => {
            assert_eq!(offset_of!(VmcbControlArea, $field), $offset)
        };
    }

    macro_rules! assert_vmcb_save_offset {
        ($field: ident, $offset: expr) => {
            assert_eq!(offset_of!(VmcbStateSaveArea, $field), $offset)
        };
    }

    #[test]
    fn test_vmcb_size() {
        assert_eq!(size_of::<Vmcb>(), 0x1000);
        assert_eq!(offset_of!(Vmcb, control), 0);
        assert_eq!(offset_of!(Vmcb, save), 0x400);
    }

    #[test]
    fn test_vmcb_layout() {
        let f = Vmcb::default();
        println!("{:#x?}", f);
        assert_vmcb_ctrl_offset!(intercept_cr, 0x00);
        assert_vmcb_ctrl_offset!(intercept_dr, 0x04);
        assert_vmcb_ctrl_offset!(intercept_exceptions, 0x08);
        assert_vmcb_ctrl_offset!(intercept_vector3, 0x0C);
        assert_vmcb_ctrl_offset!(intercept_vector4, 0x10);
        assert_vmcb_ctrl_offset!(intercept_vector5, 0x14);
        assert_vmcb_ctrl_offset!(pause_filter_thresh, 0x3C);
        assert_vmcb_ctrl_offset!(pause_filter_count, 0x3E);
        assert_vmcb_ctrl_offset!(iopm_base_pa, 0x40);
        assert_vmcb_ctrl_offset!(msrpm_base_pa, 0x48);
        assert_vmcb_ctrl_offset!(tsc_offset, 0x50);
        assert_vmcb_ctrl_offset!(guest_asid, 0x58);
        assert_vmcb_ctrl_offset!(tlb_control, 0x5C);
        assert_vmcb_ctrl_offset!(int_control, 0x60);
        assert_vmcb_ctrl_offset!(int_vector, 0x64);
        assert_vmcb_ctrl_offset!(int_state, 0x68);
        assert_vmcb_ctrl_offset!(exit_code, 0x70);
        assert_vmcb_ctrl_offset!(exit_info_1, 0x78);
        assert_vmcb_ctrl_offset!(exit_info_2, 0x80);
        assert_vmcb_ctrl_offset!(exit_int_info, 0x88);
        assert_vmcb_ctrl_offset!(exit_int_info_err, 0x8C);
        assert_vmcb_ctrl_offset!(np_enable, 0x90);
        assert_vmcb_ctrl_offset!(avic_vapic_bar, 0x98);
        assert_vmcb_ctrl_offset!(event_inj, 0xA8);
        assert_vmcb_ctrl_offset!(event_inj_err, 0xAC);
        assert_vmcb_ctrl_offset!(nest_cr3, 0xB0);
        assert_vmcb_ctrl_offset!(lbr_control, 0xB8);
        assert_vmcb_ctrl_offset!(clean_bits, 0xC0);
        assert_vmcb_ctrl_offset!(next_rip, 0xC8);
        assert_vmcb_ctrl_offset!(insn_len, 0xD0);
        assert_vmcb_ctrl_offset!(insn_bytes, 0xD1);
        assert_vmcb_ctrl_offset!(avic_backing_page, 0xE0);
        assert_vmcb_ctrl_offset!(avic_logical_id, 0xF0);
        assert_vmcb_ctrl_offset!(avic_physical_id, 0xF8);

        assert_vmcb_save_offset!(es, 0x00);
        assert_vmcb_save_offset!(cs, 0x10);
        assert_vmcb_save_offset!(ss, 0x20);
        assert_vmcb_save_offset!(ds, 0x30);
        assert_vmcb_save_offset!(fs, 0x40);
        assert_vmcb_save_offset!(gs, 0x50);
        assert_vmcb_save_offset!(gdtr, 0x60);
        assert_vmcb_save_offset!(ldtr, 0x70);
        assert_vmcb_save_offset!(idtr, 0x80);
        assert_vmcb_save_offset!(tr, 0x90);
        assert_vmcb_save_offset!(cpl, 0xCB);
        assert_vmcb_save_offset!(efer, 0xD0);
        assert_vmcb_save_offset!(cr4, 0x148);
        assert_vmcb_save_offset!(cr3, 0x150);
        assert_vmcb_save_offset!(cr0, 0x158);
        assert_vmcb_save_offset!(dr7, 0x160);
        assert_vmcb_save_offset!(dr6, 0x168);
        assert_vmcb_save_offset!(rflags, 0x170);
        assert_vmcb_save_offset!(rip, 0x178);
        assert_vmcb_save_offset!(rsp, 0x1D8);
        assert_vmcb_save_offset!(s_cet, 0x1E0);
        assert_vmcb_save_offset!(ssp, 0x1E8);
        assert_vmcb_save_offset!(isst_addr, 0x1F0);
        assert_vmcb_save_offset!(rax, 0x1F8);
        assert_vmcb_save_offset!(star, 0x200);
        assert_vmcb_save_offset!(lstar, 0x208);
        assert_vmcb_save_offset!(cstar, 0x210);
        assert_vmcb_save_offset!(sfmask, 0x218);
        assert_vmcb_save_offset!(kernel_gs_base, 0x220);
        assert_vmcb_save_offset!(sysenter_cs, 0x228);
        assert_vmcb_save_offset!(sysenter_esp, 0x230);
        assert_vmcb_save_offset!(sysenter_eip, 0x238);
        assert_vmcb_save_offset!(cr2, 0x240);
        assert_vmcb_save_offset!(g_pat, 0x268);
        assert_vmcb_save_offset!(dbgctl, 0x270);
        assert_vmcb_save_offset!(br_from, 0x278);
        assert_vmcb_save_offset!(br_to, 0x280);
        assert_vmcb_save_offset!(last_excp_from, 0x288);
        assert_vmcb_save_offset!(last_excp_to, 0x290);
    }
}
