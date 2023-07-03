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

use alloc::sync::Arc;
use core::fmt::{Debug, Formatter, Result};
use core::marker::PhantomData;
use core::mem::size_of;

use super::addr::{page_offset, phys_to_virt, virt_to_phys, GuestPhysAddr, GuestVirtAddr};
use super::{GenericPageTableImmut, MemFlags, PageSize, PagingError, PhysAddr};
use crate::arch::{EnclaveExceptionInfo, GuestPageTableImmut, PageFaultErrorCode};
use crate::cell::ROOT_CELL;
use crate::enclave::epcm::EpcmManager;
use crate::enclave::Enclave;
use crate::error::{HvError, HvResult};
use crate::hypercall::error::HyperCallResult;
use crate::hypercall::PrivilegeLevel;
use crate::percpu::CpuState;

enum PtrType<'a> {
    /// The memory address pointed by the `GuestPtr` is in the normal memory.
    NonSecure(&'a GuestPageTableImmut),
    /// The memory address pointed by the `GuestPtr` is in the secure memory.
    Secure(&'a Arc<Enclave>),
}

impl<'a> PtrType<'a> {
    fn is_secure(&self) -> bool {
        match self {
            PtrType::NonSecure(_) => false,
            PtrType::Secure(_) => true,
        }
    }
}

pub struct GuestPtr<'a, T> {
    gvaddr: GuestVirtAddr,
    ptr_type: PtrType<'a>,
    cpu_state: &'a CpuState,
    privilege_level: PrivilegeLevel,
    mark: PhantomData<T>,
}

pub trait AsGuestPtr {
    fn as_guest_ptr_ns<T>(
        self,
        guest_pt: &'_ GuestPageTableImmut,
        privilege_level: PrivilegeLevel,
    ) -> GuestPtr<'_, T>;

    fn as_guest_ptr_s<'a, T>(
        self,
        enclave: &'a Arc<Enclave>,
        cpu_state: &'a CpuState,
        privilege_level: PrivilegeLevel,
    ) -> GuestPtr<'a, T>;
}

impl AsGuestPtr for GuestVirtAddr {
    fn as_guest_ptr_ns<T>(
        self,
        guest_pt: &'_ GuestPageTableImmut,
        privilege_level: PrivilegeLevel,
    ) -> GuestPtr<'_, T> {
        GuestPtr {
            gvaddr: self,
            ptr_type: PtrType::NonSecure(guest_pt),
            cpu_state: &CpuState::HvEnabled,
            privilege_level,
            mark: PhantomData,
        }
    }

    fn as_guest_ptr_s<'a, T>(
        self,
        enclave: &'a Arc<Enclave>,
        cpu_state: &'a CpuState,
        privilege_level: PrivilegeLevel,
    ) -> GuestPtr<'a, T> {
        GuestPtr {
            gvaddr: self,
            ptr_type: PtrType::Secure(enclave),
            cpu_state,
            privilege_level,
            mark: PhantomData,
        }
    }
}

impl AsGuestPtr for u64 {
    fn as_guest_ptr_ns<T>(
        self,
        guest_pt: &'_ GuestPageTableImmut,
        privilege_level: PrivilegeLevel,
    ) -> GuestPtr<'_, T> {
        (self as GuestVirtAddr).as_guest_ptr_ns(guest_pt, privilege_level)
    }

    fn as_guest_ptr_s<'a, T>(
        self,
        enclave: &'a Arc<Enclave>,
        cpu_state: &'a CpuState,
        privilege_level: PrivilegeLevel,
    ) -> GuestPtr<'a, T> {
        (self as GuestVirtAddr).as_guest_ptr_s(enclave, cpu_state, privilege_level)
    }
}

impl<T> Debug for GuestPtr<'_, T> {
    fn fmt(&self, f: &mut Formatter<'_>) -> Result {
        write!(f, "{:#x?}", self.gvaddr)
    }
}

impl<T> GuestPtr<'_, T> {
    pub fn guest_vaddr(&self) -> GuestVirtAddr {
        self.gvaddr
    }

    pub fn as_guest_paddr(&self) -> HyperCallResult<GuestPhysAddr> {
        let gpaddr = Self::translate_to_gpa(
            self.gvaddr,
            &self.ptr_type,
            self.cpu_state,
            self.privilege_level,
            MemFlags::READ,
        )?
        .0;
        Ok(gpaddr)
    }

    /// Perform sanity checks on paddr:
    /// 1. Check the memory region the `gpaddr` points to matches the pointer type;
    /// 2. Check whether hypervisor is able to access the host physical translated from `gpaddr`.
    fn check_gpaddr(gpaddr: GuestPhysAddr, is_secure: bool) -> HvResult {
        if is_secure {
            if !EpcmManager::is_valid_epc(gpaddr) {
                return hv_result_err!(
                    EINVAL,
                    format!("Cannot access guest paddr {:#x?} as secure memory", gpaddr)
                );
            }
            // If the `gpaddr` points to a valid EPC region,
            // it indicates that hypervisor is able to access the host physical memory.
        } else if EpcmManager::is_valid_epc(gpaddr)
            || !ROOT_CELL.is_valid_normal_world_gpaddr(gpaddr)
        {
            return hv_result_err!(
                EINVAL,
                format!(
                    "Cannot access guest paddr {:#x?} as non-secure memory",
                    gpaddr
                )
            );
        }
        Ok(())
    }

    fn check_addr_alignment(&self) -> HyperCallResult {
        if self.gvaddr % core::mem::align_of::<T>() != 0 {
            Err(hypercall_excep_err!(
                EnclaveExceptionInfo::general_protection(0, self.cpu_state),
                format!(
                    "GuestPtr::check_addr_alignment(): gvaddr {:#x?} is not {:#x?}",
                    self.gvaddr,
                    core::mem::align_of::<T>()
                )
            ))
        } else {
            Ok(())
        }
    }

    /// Query page table and translate from guest virtual address(GVA) to guest physical address(GPA).
    /// When we get the GPA, we perform additional checks:
    ///     1. Make sure the PTE flags is valid;
    ///     2. Make sure the area GPA points to is consistent with `ptr_type`;
    ///     3. The GPA may be invalid, so we must make sure hypervisor is able to access the memory pointed by the GPA.
    fn translate_to_gpa<'a>(
        gvaddr: GuestVirtAddr,
        ptr_type: &PtrType<'a>,
        cpu_state: &'a CpuState,
        privilige_level: PrivilegeLevel,
        flags_required: MemFlags,
    ) -> HyperCallResult<(PhysAddr, PageSize)> {
        let generate_pf = |is_present: bool| -> EnclaveExceptionInfo {
            let mut error_code = PageFaultErrorCode::USER_MODE;
            if is_present {
                error_code |= PageFaultErrorCode::PROTECTION_VIOLATION;
            }
            if privilige_level == PrivilegeLevel::User {
                error_code |= PageFaultErrorCode::USER_MODE;
            }
            if flags_required.contains(MemFlags::WRITE) {
                error_code |= PageFaultErrorCode::CAUSED_BY_WRITE;
            }
            let error_code = error_code.bits();
            if *cpu_state == CpuState::EnclaveRunning {
                EnclaveExceptionInfo::page_fault_in_encl(error_code, error_code, gvaddr)
            } else {
                EnclaveExceptionInfo::page_fault_out_encl(error_code, gvaddr)
            }
        };

        let (gpaddr, pte_flags, pg_size) = match *ptr_type {
            PtrType::NonSecure(untrusted_gpt) => match untrusted_gpt.query(gvaddr) {
                Ok((gpaddr, mem_flags, pg_size)) => (gpaddr, mem_flags, pg_size),
                Err(PagingError::NotMapped(_)) | Err(PagingError::NotPresent(_)) => {
                    return Err(hypercall_excep_err!(
                        generate_pf(false),
                        format!("GuestPtr::translate_to_gpa(): Cannot get gpaddr for gvaddr: {:#x?}, inject #PF", gvaddr)
                    ));
                }
                Err(e) => return Err(HvError::from(e).into()),
            },
            PtrType::Secure(enclave) => {
                enclave.load_page(gvaddr, *cpu_state == CpuState::EnclaveRunning)?
            }
        };

        if !pte_flags.contains(flags_required) {
            return Err(hypercall_excep_err!(
                generate_pf(true),
                format!("GuestPtr::translate_to_gpa(): Flags mismatch: flags in PTE: {:?}, flags must contain: {:?}", pte_flags, flags_required)
            ));
        }

        let is_secure = ptr_type.is_secure();
        if let Err(e) = Self::check_gpaddr(gpaddr, is_secure) {
            let msg = format!(
                "GuestPtr::translate_to_gpa(): ptr is_secure {:?} is and paddr {:#x?} mismatches, error: {:?}",
                is_secure, gpaddr, e
            );
            return if is_secure {
                // The enclave's GPT is managed by hypervisor, so such check should pass.
                warn!("{:?}", msg);
                hypercall_hv_err_result!(EFAULT, msg)
            } else {
                // The Linux's GPT is managed normal world software (untrusted),
                // so we inject #GP if the target gpa is not valid.
                Err(hypercall_excep_err!(
                    EnclaveExceptionInfo::general_protection(0, cpu_state),
                    msg
                ))
            };
        }

        Ok((gpaddr, pg_size))
    }

    pub fn as_ref(&self) -> HyperCallResult<&T> {
        self.check_addr_alignment()?;
        let size = size_of::<T>();
        let (gpaddr, pg_size) = Self::translate_to_gpa(
            self.gvaddr,
            &self.ptr_type,
            self.cpu_state,
            self.privilege_level,
            MemFlags::READ,
        )?;
        if page_offset(gpaddr) + size > pg_size as usize {
            return Err(hypercall_excep_err!(
                EnclaveExceptionInfo::general_protection(0, self.cpu_state),
                "GuestPtr::as_ref() requires data layout not to cross pages"
            ));
        }
        let ptr = phys_to_virt(gpaddr) as *const _;
        unsafe { Ok(&*ptr) }
    }

    pub fn as_mut(&mut self) -> HyperCallResult<&mut T> {
        self.check_addr_alignment()?;
        let size = size_of::<T>();
        let (gpaddr, pg_size) = Self::translate_to_gpa(
            self.gvaddr,
            &self.ptr_type,
            self.cpu_state,
            self.privilege_level,
            MemFlags::READ | MemFlags::WRITE,
        )?;
        if page_offset(gpaddr) + size > pg_size as usize {
            return Err(hypercall_excep_err!(
                EnclaveExceptionInfo::general_protection(0, self.cpu_state),
                "GuestPtr::as_mut() requires data layout not to cross pages"
            ));
        }
        let ptr = phys_to_virt(gpaddr) as *mut _;
        unsafe { Ok(&mut *ptr) }
    }

    pub fn read(&self) -> HyperCallResult<T> {
        self.check_addr_alignment()?;
        let mut ret = core::mem::MaybeUninit::uninit();
        let mut dst = ret.as_mut_ptr() as *mut u8;

        let mut gvaddr = self.gvaddr;
        let mut size = size_of::<T>();
        while size > 0 {
            let (gpaddr, pg_size) = Self::translate_to_gpa(
                gvaddr,
                &self.ptr_type,
                self.cpu_state,
                self.privilege_level,
                MemFlags::READ,
            )?;
            let pgoff = pg_size.page_offset(gvaddr);
            let read_size = (pg_size as usize - pgoff).min(size);
            gvaddr += read_size;
            size -= read_size;
            unsafe {
                dst.copy_from_nonoverlapping(phys_to_virt(gpaddr) as *const _, read_size);
                dst = dst.add(read_size);
            }
        }
        unsafe { Ok(ret.assume_init()) }
    }

    pub fn write(&mut self, data: T) -> HyperCallResult {
        self.check_addr_alignment()?;
        let mut src = &data as *const _ as *const u8;

        let mut gvaddr = self.gvaddr;
        let mut size = size_of::<T>();
        while size > 0 {
            let (gpaddr, pg_size) = Self::translate_to_gpa(
                gvaddr,
                &self.ptr_type,
                self.cpu_state,
                self.privilege_level,
                MemFlags::READ | MemFlags::WRITE,
            )?;
            let pgoff = pg_size.page_offset(gvaddr);
            let write_size = (pg_size as usize - pgoff).min(size);
            gvaddr += write_size;
            size -= write_size;
            let dst = phys_to_virt(gpaddr) as *mut u8;
            unsafe {
                dst.copy_from_nonoverlapping(src, write_size);
                src = src.add(write_size);
            }
        }
        Ok(())
    }

    pub fn gpaddr_to_ref(gpaddr: &'_ GuestPhysAddr, is_secure: bool) -> HvResult<&'_ T> {
        Self::check_gpaddr(*gpaddr, is_secure)?;
        let ptr = unsafe { &*(phys_to_virt(*gpaddr) as *const T) };
        Ok(ptr)
    }

    pub fn gpaddr_to_ref_mut(gpaddr: &'_ GuestPhysAddr, is_secure: bool) -> HvResult<&'_ mut T> {
        Self::check_gpaddr(*gpaddr, is_secure)?;
        let ptr = unsafe { &mut *(phys_to_virt(*gpaddr) as *mut T) };
        Ok(ptr)
    }

    pub fn ref_to_gpaddr(data_ref: &T) -> GuestPhysAddr {
        let ptr: *const T = data_ref as _;
        virt_to_phys(ptr as _)
    }
}
