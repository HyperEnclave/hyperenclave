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

use libvmm::msr::Msr;
use libvmm::vmx::{
    self,
    flags::{FeatureControl, FeatureControlFlags, InterruptInfo, VmxBasic},
    vmcs::{VmcsField16Guest, VmcsField32Guest, VmcsField64Guest},
    vmcs::{VmcsField16Host, VmcsField32Host, VmcsField64Host},
    vmcs::{VmcsField32Control, VmcsField64Control},
    Vmcs, VmxExitReason,
};
use x86::segmentation::SegmentSelector;
use x86_64::addr::VirtAddr;
use x86_64::registers::control::{Cr0, Cr0Flags, Cr3, Cr4, Cr4Flags};
use x86_64::registers::rflags::RFlags;

use super::structs::{MsrBitmap, VmxRegion};
use crate::arch::cpuid::CpuFeatures;
use crate::arch::segmentation::{Segment, SegmentAccessRights};
use crate::arch::tables::{GDTStruct, GDT, IDT};
use crate::arch::vmm::VcpuAccessGuestState;
use crate::arch::{GuestPageTableImmut, GuestRegisters, LinuxContext};
use crate::cell::Cell;
use crate::error::HvResult;

#[repr(C)]
pub struct Vcpu {
    /// VMXON region, required by VMX
    _vmxon_region: VmxRegion,
    /// VMCS of this CPU, required by VMX
    vmcs_region: VmxRegion,
    /// Save guest general registers when handle VM exits.
    guest_regs: GuestRegisters,
    /// RSP will be loaded from here when handle VM exits.
    host_stack_top: u64,
}

lazy_static! {
    static ref MSR_BITMAP: MsrBitmap = MsrBitmap::default();
}

macro_rules! set_guest_segment {
    ($seg: expr, $reg: ident) => {{
        use VmcsField16Guest::*;
        use VmcsField32Guest::*;
        use VmcsField64Guest::*;
        concat_idents!($reg, _SELECTOR).write($seg.selector.bits())?;
        concat_idents!($reg, _BASE).write($seg.base)?;
        concat_idents!($reg, _LIMIT).write($seg.limit)?;
        concat_idents!($reg, _AR_BYTES).write($seg.access_rights.bits())?;
    }};
}

impl Vcpu {
    pub fn new(linux: &LinuxContext, cell: &Cell) -> HvResult<Self> {
        super::check_hypervisor_feature()?;

        // make sure all perf counters are off
        if CpuFeatures::new().perf_monitor_version_id() > 0 {
            unsafe { Msr::IA32_PERF_GLOBAL_CTRL.write(0) };
        }

        // Check control registers.
        let _cr0 = linux.cr0;
        let cr4 = linux.cr4;
        // TODO: check reserved bits
        if cr4.contains(Cr4Flags::VIRTUAL_MACHINE_EXTENSIONS) {
            return hv_result_err!(EBUSY, "VMX is already turned on!");
        }
        if cr4.contains(Cr4Flags::L5_PAGING) {
            error!("L5_PAGING isn't supported by hypervisor!");
        }

        // Enable VMXON, if required.
        let ctrl = FeatureControl::read();
        let locked = ctrl.contains(FeatureControlFlags::LOCKED);
        let vmxon_outside = ctrl.contains(FeatureControlFlags::VMXON_ENABLED_OUTSIDE_SMX);
        if !locked {
            FeatureControl::write(
                ctrl | FeatureControlFlags::LOCKED | FeatureControlFlags::VMXON_ENABLED_OUTSIDE_SMX,
            );
        } else if !vmxon_outside {
            return hv_result_err!(ENODEV, "VMX disabled by BIOS!");
        }

        // Init VMX regions.
        let vmx_basic = VmxBasic::read();
        let vmxon_region = VmxRegion::new(vmx_basic.revision_id, false)?;
        let vmcs_region = VmxRegion::new(vmx_basic.revision_id, false)?;

        // bring CR0 and CR4 into well-defined states.
        let cr4 = Cr4::read() | super::super::HOST_CR4 | Cr4Flags::VIRTUAL_MACHINE_EXTENSIONS;
        unsafe {
            Cr0::write(Cr0::read());
            Cr4::write(cr4);
        }

        // Execute VMXON.
        unsafe { vmx::vmxon(vmxon_region.paddr() as _)? };
        info!("successed to turn on VMX.");

        // Setup VMCS.
        let mut ret = Self {
            _vmxon_region: vmxon_region,
            vmcs_region,
            host_stack_top: 0,
            guest_regs: Default::default(),
        };
        ret.vmcs_setup(linux, cell)?;

        Ok(ret)
    }

    pub fn exit(&self, linux: &mut LinuxContext) -> HvResult {
        self.load_vmcs_guest(linux)?;
        Vmcs::clear(self.vmcs_region.paddr())?;
        unsafe { vmx::vmxoff()? };
        info!("successed to turn off VMX.");
        Ok(())
    }

    pub fn activate_vmm(&mut self, linux: &LinuxContext) -> HvResult {
        let regs = self.regs_mut();
        regs.rax = 0;
        regs.rbx = linux.rbx;
        regs.rbp = linux.rbp;
        regs.r12 = linux.r12;
        regs.r13 = linux.r13;
        regs.r14 = linux.r14;
        regs.r15 = linux.r15;
        unsafe {
            asm!(
                "mov rsp, {0}",
                restore_regs_from_stack!(),
                "vmlaunch",
                in(reg) &self.guest_regs as * const _ as usize,
            );
        }
        // Never return if successful
        error!(
            "Activate hypervisor failed: {:?}",
            Vmcs::instruction_error()
        );
        hv_result_err!(EIO)
    }

    pub fn deactivate_vmm(&self, linux: &LinuxContext) -> HvResult {
        self.guest_regs.return_to_linux(linux)
    }

    pub fn inject_fault(&mut self) -> HvResult {
        Vmcs::inject_interrupt(
            InterruptInfo::from_vector(crate::arch::ExceptionType::GeneralProtectionFault),
            Some(0),
        )?;
        Ok(())
    }

    pub fn rollback_rip(&mut self, instr_len: u8) -> HvResult {
        VmcsField64Guest::RIP.write(VmcsField64Guest::RIP.read()? - instr_len as u64)?;
        Ok(())
    }

    pub fn advance_rip(&mut self, instr_len: u8) -> HvResult {
        VmcsField64Guest::RIP.write(VmcsField64Guest::RIP.read()? + instr_len as u64)?;
        Ok(())
    }

    pub fn guest_is_privileged(&self) -> bool {
        SegmentAccessRights::from_bits_truncate(VmcsField32Guest::CS_AR_BYTES.read().unwrap()).dpl()
            == 0
    }

    pub fn in_hypercall(&self) -> bool {
        matches!(Vmcs::exit_reason(), Ok(VmxExitReason::VMCALL))
    }

    pub fn guest_page_table(&self) -> GuestPageTableImmut {
        use crate::memory::{addr::align_down, GenericPageTableImmut};
        unsafe { GuestPageTableImmut::from_root(align_down(self.cr(3) as _)) }
    }
}

impl Vcpu {
    fn vmcs_setup(&mut self, linux: &LinuxContext, cell: &Cell) -> HvResult {
        let paddr = self.vmcs_region.paddr();
        Vmcs::clear(paddr)?;
        Vmcs::load(paddr)?;
        self.setup_vmcs_host()?;
        self.setup_vmcs_guest(linux)?;
        self.setup_vmcs_control(cell)?;
        Ok(())
    }

    fn setup_vmcs_host(&mut self) -> HvResult {
        VmcsField64Host::IA32_PAT.write(Msr::IA32_PAT.read())?;
        VmcsField64Host::IA32_EFER.write(Msr::IA32_EFER.read())?;

        VmcsField64Host::CR0.write(Cr0::read_raw())?;
        VmcsField64Host::CR3.write(Cr3::read().0.start_address().as_u64())?;
        VmcsField64Host::CR4.write(Cr4::read_raw())?;

        VmcsField16Host::CS_SELECTOR.write(GDTStruct::KCODE_SELECTOR.bits())?;
        VmcsField16Host::DS_SELECTOR.write(0)?;
        VmcsField16Host::ES_SELECTOR.write(0)?;
        VmcsField16Host::SS_SELECTOR.write(0)?;
        VmcsField16Host::FS_SELECTOR.write(0)?;
        VmcsField16Host::GS_SELECTOR.write(0)?;
        VmcsField16Host::TR_SELECTOR.write(GDTStruct::TSS_SELECTOR.bits())?;
        VmcsField64Host::FS_BASE.write(0)?;
        VmcsField64Host::GS_BASE.write(Msr::IA32_GS_BASE.read())?;
        VmcsField64Host::TR_BASE.write(0)?;

        VmcsField64Host::GDTR_BASE.write(GDT.lock().pointer().base.as_u64())?;
        VmcsField64Host::IDTR_BASE.write(IDT.lock().pointer().base.as_u64())?;

        VmcsField64Host::IA32_SYSENTER_ESP.write(0)?;
        VmcsField64Host::IA32_SYSENTER_EIP.write(0)?;
        VmcsField32Host::IA32_SYSENTER_CS.write(0)?;

        let cpu_local = crate::PerCpu::from_local_base();
        let rsp = &cpu_local.vcpu.host_stack_top as *const _ as u64;
        VmcsField64Host::RSP.write(rsp)?; // used for saving guest registers
        self.host_stack_top = cpu_local.stack_top() as _; // the real host stack
        VmcsField64Host::RIP.write(vmx_exit as usize as _)?;
        assert_eq!(
            unsafe { (&cpu_local.vcpu.guest_regs as *const GuestRegisters).add(1) as u64 },
            rsp
        );
        Ok(())
    }

    fn setup_vmcs_guest(&mut self, linux: &LinuxContext) -> HvResult {
        VmcsField64Guest::IA32_PAT.write(linux.pat)?;
        VmcsField64Guest::IA32_EFER.write(linux.efer)?;

        self.set_cr(0, linux.cr0.bits());
        self.set_cr(4, linux.cr4.bits());
        self.set_cr(3, linux.cr3);

        set_guest_segment!(linux.cs, CS);
        set_guest_segment!(linux.ds, DS);
        set_guest_segment!(linux.es, ES);
        set_guest_segment!(linux.fs, FS);
        set_guest_segment!(linux.gs, GS);
        set_guest_segment!(linux.tss, TR);
        set_guest_segment!(Segment::invalid(), SS);
        set_guest_segment!(Segment::invalid(), LDTR);

        VmcsField64Guest::GDTR_BASE.write(linux.gdt.base.as_u64())?;
        VmcsField32Guest::GDTR_LIMIT.write(linux.gdt.limit as _)?;
        VmcsField64Guest::IDTR_BASE.write(linux.idt.base.as_u64())?;
        VmcsField32Guest::IDTR_LIMIT.write(linux.idt.limit as _)?;

        VmcsField64Guest::RSP.write(linux.rsp)?;
        VmcsField64Guest::RIP.write(linux.rip)?;
        VmcsField64Guest::RFLAGS.write(0x2)?;

        VmcsField32Guest::SYSENTER_CS.write(Msr::IA32_SYSENTER_CS.read() as _)?;
        VmcsField64Guest::SYSENTER_ESP.write(Msr::IA32_SYSENTER_ESP.read())?;
        VmcsField64Guest::SYSENTER_EIP.write(Msr::IA32_SYSENTER_EIP.read())?;

        VmcsField64Guest::DR7.write(0x400)?;
        VmcsField64Guest::IA32_DEBUGCTL.write(0)?;

        VmcsField32Guest::ACTIVITY_STATE.write(0)?;
        VmcsField32Guest::INTERRUPTIBILITY_INFO.write(0)?;
        VmcsField64Guest::PENDING_DBG_EXCEPTIONS.write(0)?;

        VmcsField64Guest::VMCS_LINK_POINTER.write(core::u64::MAX)?;
        VmcsField32Guest::VMX_PREEMPTION_TIMER_VALUE.write(0)?;
        Ok(())
    }

    fn load_vmcs_guest(&self, linux: &mut LinuxContext) -> HvResult {
        linux.rip = VmcsField64Guest::RIP.read()?;
        linux.rsp = VmcsField64Guest::RSP.read()?;
        linux.cr0 = Cr0Flags::from_bits_truncate(VmcsField64Guest::CR0.read()?);
        linux.cr3 = VmcsField64Guest::CR3.read()?;
        linux.cr4 = Cr4Flags::from_bits_truncate(VmcsField64Guest::CR4.read()?)
            - Cr4Flags::VIRTUAL_MACHINE_EXTENSIONS;

        linux.cs.selector = SegmentSelector::from_raw(VmcsField16Guest::CS_SELECTOR.read()?);
        linux.ds.selector = SegmentSelector::from_raw(VmcsField16Guest::DS_SELECTOR.read()?);
        linux.es.selector = SegmentSelector::from_raw(VmcsField16Guest::ES_SELECTOR.read()?);
        linux.fs.selector = SegmentSelector::from_raw(VmcsField16Guest::FS_SELECTOR.read()?);
        linux.fs.base = VmcsField64Guest::FS_BASE.read()?;
        linux.gs.selector = SegmentSelector::from_raw(VmcsField16Guest::GS_SELECTOR.read()?);
        linux.gs.base = VmcsField64Guest::GS_BASE.read()?;
        linux.tss.selector = SegmentSelector::from_raw(VmcsField16Guest::TR_SELECTOR.read()?);

        linux.gdt.base = VirtAddr::new(VmcsField64Guest::GDTR_BASE.read()?);
        linux.gdt.limit = VmcsField32Guest::GDTR_LIMIT.read()? as _;
        linux.idt.base = VirtAddr::new(VmcsField64Guest::IDTR_BASE.read()?);
        linux.idt.limit = VmcsField32Guest::IDTR_LIMIT.read()? as _;

        unsafe {
            Msr::IA32_SYSENTER_CS.write(VmcsField32Guest::SYSENTER_CS.read()? as _);
            Msr::IA32_SYSENTER_ESP.write(VmcsField64Guest::SYSENTER_ESP.read()?);
            Msr::IA32_SYSENTER_EIP.write(VmcsField64Guest::SYSENTER_EIP.read()?);
        }

        Ok(())
    }

    fn setup_vmcs_control(&mut self, cell: &Cell) -> HvResult {
        use vmx::flags::PinVmExecControls as PinCtrl;
        Vmcs::set_control(
            VmcsField32Control::PIN_BASED_VM_EXEC_CONTROL,
            Msr::IA32_VMX_PINBASED_CTLS.read(),
            // NO INTR_EXITING to pass-through interrupts
            PinCtrl::NMI_EXITING.bits(),
            0,
        )?;

        use vmx::flags::PrimaryVmExecControls as CpuCtrl;
        Vmcs::set_control(
            VmcsField32Control::PROC_BASED_VM_EXEC_CONTROL,
            Msr::IA32_VMX_PROCBASED_CTLS.read(),
            // NO UNCOND_IO_EXITING to pass-through PIO
            (CpuCtrl::USE_MSR_BITMAPS | CpuCtrl::SEC_CONTROLS).bits(),
            (CpuCtrl::CR3_LOAD_EXITING | CpuCtrl::CR3_STORE_EXITING).bits(),
        )?;

        use vmx::flags::SecondaryVmExecControls as CpuCtrl2;
        let mut val = CpuCtrl2::EPT | CpuCtrl2::UNRESTRICTED_GUEST;
        let features = CpuFeatures::new();
        if features.has_rdtscp() {
            val |= CpuCtrl2::RDTSCP;
        }
        if features.has_invpcid() {
            val |= CpuCtrl2::INVPCID;
        }
        if features.has_xsaves_xrstors() {
            val |= CpuCtrl2::XSAVES;
        }
        Vmcs::set_control(
            VmcsField32Control::SECONDARY_VM_EXEC_CONTROL,
            Msr::IA32_VMX_PROCBASED_CTLS2.read(),
            val.bits(),
            0,
        )?;

        Vmcs::set_control(
            VmcsField32Control::VM_EXIT_CONTROLS,
            Msr::IA32_VMX_EXIT_CTLS.read(),
            super::VMEXIT_CTRL_MIN,
            0,
        )?;

        use vmx::flags::VmEntryControls as EntryCtrl;
        Vmcs::set_control(
            VmcsField32Control::VM_ENTRY_CONTROLS,
            Msr::IA32_VMX_ENTRY_CTLS.read(),
            (EntryCtrl::IA32E_MODE | EntryCtrl::LOAD_IA32_PAT | EntryCtrl::LOAD_IA32_EFER).bits(),
            0,
        )?;

        VmcsField32Control::VM_EXIT_MSR_STORE_COUNT.write(0)?;
        VmcsField32Control::VM_EXIT_MSR_LOAD_COUNT.write(0)?;
        VmcsField32Control::VM_ENTRY_MSR_LOAD_COUNT.write(0)?;

        VmcsField64Control::CR4_GUEST_HOST_MASK.write(0)?;
        VmcsField32Control::CR3_TARGET_COUNT.write(0)?;

        unsafe { cell.gpm.activate() }; // Set EPT_POINTER

        VmcsField64Control::MSR_BITMAP.write(MSR_BITMAP.paddr() as _)?;
        VmcsField32Control::EXCEPTION_BITMAP.write(0)?;

        Ok(())
    }
}

impl VcpuAccessGuestState for Vcpu {
    fn regs(&self) -> &GuestRegisters {
        &self.guest_regs
    }

    fn regs_mut(&mut self) -> &mut GuestRegisters {
        &mut self.guest_regs
    }

    fn instr_pointer(&self) -> u64 {
        VmcsField64Guest::RIP.read().unwrap()
    }

    fn stack_pointer(&self) -> u64 {
        VmcsField64Guest::RSP.read().unwrap()
    }

    fn set_stack_pointer(&mut self, sp: u64) {
        VmcsField64Guest::RSP.write(sp).unwrap()
    }

    fn rflags(&self) -> u64 {
        VmcsField64Guest::RFLAGS.read().unwrap()
    }

    fn fs_base(&self) -> u64 {
        VmcsField64Guest::FS_BASE.read().unwrap()
    }

    fn gs_base(&self) -> u64 {
        VmcsField64Guest::GS_BASE.read().unwrap()
    }

    fn efer(&self) -> u64 {
        VmcsField64Guest::IA32_EFER.read().unwrap()
    }

    fn cr(&self, cr_idx: usize) -> u64 {
        (|| -> HvResult<u64> {
            Ok(match cr_idx {
                0 => VmcsField64Guest::CR0.read()?,
                3 => VmcsField64Guest::CR3.read()?,
                4 => {
                    let host_mask = VmcsField64Control::CR4_GUEST_HOST_MASK.read()?;
                    (VmcsField64Control::CR4_READ_SHADOW.read()? & host_mask)
                        | (VmcsField64Guest::CR4.read()? & !host_mask)
                }
                _ => unreachable!(),
            })
        })()
        .expect("Failed to read guest control register")
    }

    fn set_cr(&mut self, cr_idx: usize, val: u64) {
        (|| -> HvResult {
            match cr_idx {
                0 => {
                    // Retrieve/validate restrictions on CR0
                    //
                    // In addition to what the VMX MSRs tell us, make sure that
                    // - NW and CD are kept off as they are not updated on VM exit and we
                    //   don't want them enabled for performance reasons while in root mode
                    // - PE and PG can be freely chosen (by the guest) because we demand
                    //   unrestricted guest mode support anyway
                    // - ET is ignored
                    let must0 = Msr::IA32_VMX_CR0_FIXED1.read()
                        & !(Cr0Flags::NOT_WRITE_THROUGH | Cr0Flags::CACHE_DISABLE).bits();
                    let must1 = Msr::IA32_VMX_CR0_FIXED0.read()
                        & !(Cr0Flags::PAGING | Cr0Flags::PROTECTED_MODE_ENABLE).bits();
                    VmcsField64Guest::CR0.write((val & must0) | must1)?;
                    VmcsField64Control::CR0_READ_SHADOW.write(val)?;
                    VmcsField64Control::CR0_GUEST_HOST_MASK.write(must1 | !must0)?;
                }
                3 => VmcsField64Guest::CR3.write(val)?,
                4 => {
                    // Retrieve/validate restrictions on CR4
                    let must0 = Msr::IA32_VMX_CR4_FIXED1.read();
                    let must1 = Msr::IA32_VMX_CR4_FIXED0.read();
                    let val = val | Cr4Flags::VIRTUAL_MACHINE_EXTENSIONS.bits();
                    VmcsField64Guest::CR4.write((val & must0) | must1)?;
                    VmcsField64Control::CR4_READ_SHADOW.write(val)?;
                    VmcsField64Control::CR4_GUEST_HOST_MASK.write(must1 | !must0)?;
                }
                _ => unreachable!(),
            };
            Ok(())
        })()
        .expect("Failed to write guest control register")
    }
}

impl Debug for Vcpu {
    fn fmt(&self, f: &mut Formatter) -> Result {
        (|| -> HvResult<Result> {
            Ok(f.debug_struct("Vcpu")
                .field("guest_regs", &self.guest_regs)
                .field("rip", &self.instr_pointer())
                .field("rsp", &self.stack_pointer())
                .field("rflags", unsafe {
                    &RFlags::from_bits_unchecked(self.rflags())
                })
                .field("cr0", unsafe { &Cr0Flags::from_bits_unchecked(self.cr(0)) })
                .field("cr3", &self.cr(3))
                .field("cr4", unsafe { &Cr4Flags::from_bits_unchecked(self.cr(4)) })
                .field("cs", &VmcsField16Guest::CS_SELECTOR.read()?)
                .field("fs_base", &VmcsField64Guest::FS_BASE.read()?)
                .field("gs_base", &VmcsField64Guest::GS_BASE.read()?)
                .field("tss", &VmcsField16Guest::TR_SELECTOR.read()?)
                .finish())
        })()
        .unwrap()
    }
}

#[naked]
unsafe extern "sysv64" fn vmx_exit() -> ! {
    asm!(
        save_regs_to_stack!(),
        "mov r15, rsp",         // save temporary RSP to r15
        "mov rsp, [rsp + {0}]", // set RSP to Vcpu::host_stack_top
        "call {1}",             // call vmexit_handler
        "mov rsp, r15",         // load temporary RSP from r15
        restore_regs_from_stack!(),
        "vmresume",
        "jmp {2}",
        const core::mem::size_of::<GuestRegisters>(),
        sym crate::arch::vmm::vmexit_handler,
        sym vmresume_failed,
        options(noreturn),
    );
}

fn vmresume_failed() -> ! {
    panic!("VM resume failed: {:?}", Vmcs::instruction_error());
}
