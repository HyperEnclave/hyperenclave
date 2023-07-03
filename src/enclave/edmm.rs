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
use core::convert::TryFrom;

use crate::arch::{EnclaveExceptionInfo, PageFaultErrorCode};
use crate::consts::PAGE_SIZE;
use crate::hypercall::error::HyperCallResult;
use crate::memory::addr::{is_aligned, phys_to_virt, GuestPhysAddr, GuestVirtAddr};
use crate::memory::gaccess::GuestPtr;
use crate::memory::{
    GenericPTE, GenericPageTable, GenericPageTableMut, MemFlags, MemoryRegion, PagingError,
};
use crate::percpu::CpuState;

use super::epcm::EpcmManager;
use super::{Enclave, SgxEnclPageFlags, SgxEnclPageType, SgxSecInfo, SgxTcs};

pub(crate) enum PageTypeModifyType {
    RegToTcs,
    RegToTrim,
    TcsToTrim,
}

#[derive(PartialEq)]
pub(crate) enum PageAcceptType {
    Augment,
    TypeModify,
    PermRestrict,
}

impl Enclave {
    pub fn augment_page(
        self: &Arc<Self>,
        gvaddr: GuestVirtAddr,
        gpaddr: GuestPhysAddr,
        sec_info: usize,
    ) -> HyperCallResult<usize> {
        self.validate_state_and_vaddr(gvaddr)?;

        if !is_aligned(gpaddr) {
            return hypercall_hv_err_result!(
                EINVAL,
                format!(
                    "Enclave::augment_page(): guest physical address {:#x} is not aligned",
                    gpaddr,
                )
            );
        }

        if sec_info != 0 {
            return hypercall_hv_err_result!(
                EINVAL,
                format!(
                    "Enclave::augment_page(): The sec_info is not 0: {:#x?}",
                    sec_info
                )
            );
        }

        {
            let _encl_mem_lock = self.encl_mem_lock.lock();

            let gpt_flags = EpcmManager::augment_page(gvaddr, gpaddr, self)?.into();
            unsafe {
                core::ptr::write_bytes(phys_to_virt(gpaddr as _) as *mut u8, 0_u8, PAGE_SIZE);
            }
            self.gpt.write().map(&MemoryRegion::new_with_offset_mapper(
                gvaddr, gpaddr, PAGE_SIZE, gpt_flags,
            ))?;
        }

        Ok(0)
    }

    pub(crate) fn modify_page_type(
        self: &Arc<Self>,
        gvaddr: GuestVirtAddr,
        sec_info: usize,
    ) -> HyperCallResult {
        self.validate_state_and_vaddr(gvaddr)?;
        let sec_info = SgxSecInfo::try_from(sec_info)?;

        {
            let _encl_mem_lock = self.encl_mem_lock.lock();

            {
                let mut secure_gpt = self.gpt.write();

                let pte = match secure_gpt.get_pte_mut(gvaddr) {
                    Ok(pte) => pte,
                    Err(PagingError::NotMapped(_)) => {
                        return hypercall_hv_err_result!(EFAULT, format!("Enclave::modify_page_type(): Intermediate page is not mapped, gvaddr: {:#x?}", gvaddr));
                    }
                    Err(e) => {
                        return hypercall_hv_err_result!(
                            EFAULT,
                            format!("Enclave::modify_page_type(): Unexpected error: {:?}", e)
                        );
                    }
                };

                if pte.is_unused() {
                    return hypercall_hv_err_result!(
                        EINVAL,
                        format!(
                            "Enclave::modify_page_type(): PTE is empty, gvaddr: {:#x?}",
                            gvaddr
                        )
                    );
                }

                let gpaddr_aligned = pte.addr();
                let (new_sec_info, page_type_modify_type) = EpcmManager::modify_page_type(
                    gvaddr,
                    gpaddr_aligned,
                    sec_info.page_type,
                    self,
                )?;
                match page_type_modify_type {
                    PageTypeModifyType::RegToTcs | PageTypeModifyType::RegToTrim => {
                        self.npt
                            .write()
                            .unmap(&MemoryRegion::new_with_offset_mapper(
                                gpaddr_aligned,
                                0,
                                PAGE_SIZE,
                                MemFlags::empty(),
                            ))?;
                    }
                    // There is no NPT mapping for TCS, so do nothing here
                    _ => {}
                }
                pte.set_flags(new_sec_info.into(), false)?;
            } // Release secure GPT lock

            // Mark issuing TLB flush track is needed
            self.tracking_state.write().require_track_for_accept();
        }
        Ok(())
    }

    pub(crate) fn restrict_page_perm(
        self: &Arc<Self>,
        gvaddr: GuestVirtAddr,
        sec_info: usize,
    ) -> HyperCallResult {
        self.validate_state_and_vaddr(gvaddr)?;

        let sec_info = SgxSecInfo::try_from(sec_info)?;
        if sec_info.flags.contains(SgxEnclPageFlags::W)
            && !sec_info.flags.contains(SgxEnclPageFlags::R)
        {
            return hypercall_hv_err_result!(
                EINVAL,
                format!(
                    "Enclave::restrict_page_perm(): invalid sec_info: {:?}",
                    sec_info
                )
            );
        }

        {
            let _encl_mem_lock = self.encl_mem_lock.lock();

            {
                let mut secure_gpt = self.gpt.write();

                let pte = match secure_gpt.get_pte_mut(gvaddr) {
                    Ok(pte) => pte,
                    Err(PagingError::NotMapped(_)) => {
                        return hypercall_hv_err_result!(EFAULT, format!("Enclave::restrict_page_perm(): Intermidate page table is not mapped, gvaddr: {:#x?}", gvaddr));
                    }
                    Err(e) => {
                        return hypercall_hv_err_result!(
                            EFAULT,
                            format!("Enclave::restrict_page_perm(): Unexpected error: {:?}", e)
                        );
                    }
                };

                if pte.is_unused() {
                    return hypercall_hv_err_result!(
                        EINVAL,
                        format!(
                            "Enclave::restrict_page_perm(): PTE is empty, gvaddr: {:#x?}",
                            gvaddr
                        )
                    );
                }

                let gpaddr_aligned = pte.addr();
                let new_sec_info = EpcmManager::restrict_page_perm(
                    gvaddr,
                    gpaddr_aligned,
                    sec_info.flags & SgxEnclPageFlags::PERM_MASK,
                    self,
                )?;

                let old_gpt_flags = pte.flags();
                let new_gpt_flags = new_sec_info.into();
                debug!(
                    "Enclave::restrict_page_perm(), gvadddr: {:#x?}, flags: {:?}",
                    gvaddr, new_gpt_flags
                );
                if old_gpt_flags != new_gpt_flags {
                    pte.set_flags(new_gpt_flags, false)?;

                    // Perform NPT-E's permission restriction after Guest PTE's to avoid #NPF
                    let hpaddr_aligned = gpaddr_aligned;
                    let new_npt_flags = new_gpt_flags | MemFlags::ENCRYPTED;
                    if let Err(e) = self
                        .npt
                        .write()
                        .update(&MemoryRegion::new_with_offset_mapper(
                            gpaddr_aligned,
                            hpaddr_aligned,
                            PAGE_SIZE,
                            new_npt_flags,
                        ))
                    {
                        return hypercall_hv_err_result!(
                            EFAULT,
                            format!(
                                "Enclave::restrict_page_perm(): Update NPT mappings error, {:?}",
                                e
                            )
                        );
                    }
                }
            } // Release secure GPT lock.

            // Mark issuing TLB flush track is needed.
            self.tracking_state.write().require_track_for_accept();
        }

        Ok(())
    }

    pub fn remove_page_at_runtime(self: &Arc<Self>, gvaddr: GuestVirtAddr) -> HyperCallResult {
        self.validate_state_and_vaddr(gvaddr)?;

        {
            let _encl_mem_lock = self.encl_mem_lock.lock();

            {
                let mut secure_gpt = self.gpt.write();

                let pte = match secure_gpt.get_pte_mut(gvaddr) {
                    Ok(pte) => pte,
                    Err(PagingError::NotMapped(_)) => {
                        return hypercall_hv_err_result!(
                            EFAULT,
                            format!(
                                "Enclave::remove_page_at_runtime(): Intermediate page table is not mapped, gvaddr: {:#x?}",
                                gvaddr
                            )
                        );
                    }
                    Err(e) => {
                        return hypercall_hv_err_result!(
                            EFAULT,
                            format!(
                                "Enclave::remove_page_at_runtime(): Unexpected error: {:?}",
                                e
                            )
                        );
                    }
                };

                if pte.is_unused() || pte.is_present() {
                    return hypercall_hv_err_result!(
                        EINVAL,
                        format!(
                            "Enclave::remove_page_at_runtime(): Invalid gvaddr: {:#x?}, PTE should be non-zero and with P-bit unset",
                            gvaddr
                        )
                    );
                }

                let gpaddr_aligned = pte.addr();
                EpcmManager::remove_page_at_runtime(gvaddr, gpaddr_aligned, self)?;
                pte.clear();
            }
        }

        Ok(())
    }

    pub(crate) fn accept_page(
        self: &Arc<Self>,
        sec_info: usize,
        gvaddr: GuestVirtAddr,
    ) -> HyperCallResult {
        self.validate_state_and_vaddr(gvaddr)?;

        let sec_info = match SgxSecInfo::try_from(sec_info) {
            Ok(sec_info) => sec_info,
            Err(_) => {
                return Err(hypercall_excep_err!(
                    EnclaveExceptionInfo::general_protection(0, &CpuState::EnclaveRunning),
                    format!("Enclave::accept_page(): Invalid sec_info: {:x}", sec_info)
                ));
            }
        };

        let page_accept_type = {
            if sec_info.page_type == SgxEnclPageType::REG
                && sec_info.flags.contains(SgxEnclPageFlags::PENDING)
                && !sec_info.flags.contains(SgxEnclPageFlags::MODIFIED)
                && !sec_info.flags.contains(SgxEnclPageFlags::PR)
            {
                PageAcceptType::Augment
            } else if (sec_info.page_type == SgxEnclPageType::TCS
                || sec_info.page_type == SgxEnclPageType::TRIM)
                && sec_info.flags.contains(SgxEnclPageFlags::MODIFIED)
                && !sec_info.flags.contains(SgxEnclPageFlags::PENDING)
                && !sec_info.flags.contains(SgxEnclPageFlags::PR)
            {
                PageAcceptType::TypeModify
            } else if sec_info.page_type == SgxEnclPageType::REG
                && sec_info.flags.contains(SgxEnclPageFlags::PR)
                && !sec_info.flags.contains(SgxEnclPageFlags::MODIFIED)
                && !sec_info.flags.contains(SgxEnclPageFlags::PENDING)
            {
                PageAcceptType::PermRestrict
            } else {
                let msg = format!("Enclave::accept_page(): Invalid sec_info: {:?}", sec_info);
                warn!("{:?}", msg);
                return Err(hypercall_excep_err!(
                    EnclaveExceptionInfo::general_protection(0, &CpuState::EnclaveRunning),
                    msg
                ));
            }
        };

        {
            let _encl_mem_lock = self.encl_mem_lock.lock();
            {
                let mut secure_gpt = self.gpt.write();

                let pte = match secure_gpt.get_pte_mut(gvaddr) {
                    Ok(pte) => pte,
                    Err(PagingError::NotMapped(_)) => {
                        let error_code = PageFaultErrorCode::USER_MODE.bits();
                        let enclave_excep = EnclaveExceptionInfo::page_fault_in_encl(
                            error_code, error_code, gvaddr,
                        );
                        return Err(hypercall_excep_err!(
                            enclave_excep,
                            format!("Enclave::accept_page(): Intermediate page table is not mapped, gvaddr: {:#x?}", gvaddr)
                        ));
                    }
                    Err(e) => {
                        return hypercall_hv_err_result!(
                            EFAULT,
                            format!("Enclave::accept_page(): Unexpected error: {:?}", e)
                        );
                    }
                };
                if pte.is_unused() {
                    let error_code = PageFaultErrorCode::USER_MODE.bits();
                    let enclave_excep =
                        EnclaveExceptionInfo::page_fault_in_encl(error_code, error_code, gvaddr);
                    return Err(hypercall_excep_err!(
                        enclave_excep,
                        format!(
                            "Enclave::accept_page(): PTE is empty, gvaddr: {:#x?}",
                            gvaddr
                        )
                    ));
                }

                // Ensure there is no stale TLB for EPC page accept.
                match page_accept_type {
                    PageAcceptType::TypeModify | PageAcceptType::PermRestrict => {
                        if !self.tracking_state.read().is_accept_tracking_done() {
                            return Err(hypercall_enclave_err!(
                                EPREVTRKINCMPL,
                                "Enclave::accept_page(): Previous tracking cycle is not done"
                            ));
                        }
                    }
                    // No need to check the state of TLB Flush Track, do nothing.
                    PageAcceptType::Augment => {}
                }

                // TCS page can only be created by EMODT at runtime.
                // If the target page is TCS,
                // make sure the its reserved bits are not set by enclave.
                if page_accept_type == PageAcceptType::TypeModify
                    && sec_info.page_type == SgxEnclPageType::TCS
                {
                    let tcs_gpaddr = pte.addr();
                    let tcs: &SgxTcs = GuestPtr::gpaddr_to_ref(&tcs_gpaddr, true)?;
                    if !tcs.validate_at_creation() {
                        return Err(hypercall_excep_err!(
                            EnclaveExceptionInfo::general_protection(0, &CpuState::EnclaveRunning),
                            format!("Enclave::accept_page(): Invalid TCS: {:#x?}", tcs)
                        ));
                    }
                }

                let gpaddr_aligned = pte.addr();
                let new_sec_info = EpcmManager::accept_page(
                    gvaddr,
                    gpaddr_aligned,
                    &sec_info,
                    &page_accept_type,
                    self,
                )?;

                if page_accept_type == PageAcceptType::Augment {
                    let npt_flags: MemFlags = new_sec_info.into();
                    self.npt.write().map(&MemoryRegion::new_with_offset_mapper(
                        gpaddr_aligned,
                        gpaddr_aligned,
                        PAGE_SIZE,
                        npt_flags | MemFlags::ENCRYPTED,
                    ))?;
                }
                pte.set_flags(new_sec_info.into(), false)?;
            } // Release secure GPT lock.
        } // Release encl_mem_lock.
        Ok(())
    }

    pub(crate) fn accept_and_copy_page(
        self: &Arc<Self>,
        sec_info: usize,
        gvaddr_src: GuestVirtAddr,
        gvaddr_des: GuestVirtAddr,
    ) -> HyperCallResult {
        self.validate_state_and_vaddr(gvaddr_src)?;
        self.validate_state_and_vaddr(gvaddr_des)?;

        let sec_info = match SgxSecInfo::try_from(sec_info) {
            Ok(sec_info) => sec_info,
            Err(_) => {
                return Err(hypercall_excep_err!(
                    EnclaveExceptionInfo::general_protection(0, &CpuState::EnclaveRunning),
                    format!(
                        "Enclave::accept_and_copy_page(): Invalid sec_info: {:x}",
                        sec_info
                    )
                ));
            }
        };

        if (sec_info.flags.contains(SgxEnclPageFlags::W)
            && !sec_info.flags.contains(SgxEnclPageFlags::R))
            || sec_info.page_type != SgxEnclPageType::REG
        {
            return Err(hypercall_excep_err!(
                EnclaveExceptionInfo::general_protection(0, &CpuState::EnclaveRunning),
                format!(
                    "Enclave::accept_and_copy_page(): Invalid sec_info: {:?}",
                    sec_info
                )
            ));
        }

        {
            let _encl_mem_lock = self.encl_mem_lock.lock();
            {
                let mut secure_gpt = self.gpt.write();

                // Walk the secure GPT and EPCM, then get the valid gpaddr for source page first.
                let gpaddr_src = {
                    let pte = match secure_gpt.get_pte_mut(gvaddr_src) {
                        Ok(pte) => pte,
                        Err(PagingError::NotMapped(_)) => {
                            let error_code = PageFaultErrorCode::USER_MODE.bits();
                            let enclave_excep = EnclaveExceptionInfo::page_fault_in_encl(
                                error_code, error_code, gvaddr_src,
                            );
                            return Err(hypercall_excep_err!(
                                enclave_excep,
                                format!("Enclave::accept_and_copy_page(): Intermediate page table is not mapped, gvaddr_src: {:#x?}", gvaddr_src)
                            ));
                        }
                        Err(e) => {
                            return hypercall_hv_err_result!(
                                EFAULT,
                                format!(
                                    "Enclave::accept_and_copy_page(): Unexpected error: {:?}",
                                    e
                                )
                            );
                        }
                    };
                    if pte.is_unused() {
                        let error_code = PageFaultErrorCode::USER_MODE.bits();
                        let enclave_excep = EnclaveExceptionInfo::page_fault_in_encl(
                            error_code, error_code, gvaddr_src,
                        );
                        return Err(hypercall_excep_err!(
                            enclave_excep,
                            format!(
                                "Enclave::accept_page(): PTE is empty, gvaddr_src: {:#x?}",
                                gvaddr_src
                            )
                        ));
                    }
                    let new_sec_info =
                        EpcmManager::access_page_check(gvaddr_src, pte.addr(), self, false, true)?;
                    pte.set_flags(new_sec_info.into(), false)?;
                    pte.addr()
                };

                // Walk the secure GPT to get the PTE for destination page.
                let pte_des = {
                    let pte = match secure_gpt.get_pte_mut(gvaddr_des) {
                        Ok(pte) => pte,
                        Err(PagingError::NotMapped(_)) => {
                            let error_code = (PageFaultErrorCode::USER_MODE
                                | PageFaultErrorCode::CAUSED_BY_WRITE)
                                .bits();
                            let enclave_excep = EnclaveExceptionInfo::page_fault_in_encl(
                                error_code, error_code, gvaddr_des,
                            );
                            return Err(hypercall_excep_err!(
                                enclave_excep,
                                format!("Enclave::accept_and_copy_page(): Intermediate page table is not mapped, gvaddr_des: {:#x?}", gvaddr_des)
                            ));
                        }
                        Err(e) => {
                            return hypercall_hv_err_result!(
                                EFAULT,
                                format!(
                                    "Enclave::accept_and_copy_page(): Unexpected error: {:?}",
                                    e
                                )
                            );
                        }
                    };
                    if pte.is_unused() {
                        let error_code = (PageFaultErrorCode::USER_MODE
                            | PageFaultErrorCode::CAUSED_BY_WRITE)
                            .bits();
                        let enclave_excep = EnclaveExceptionInfo::page_fault_in_encl(
                            error_code, error_code, gvaddr_src,
                        );
                        return Err(hypercall_excep_err!(
                            enclave_excep,
                            format!(
                                "Enclave::accept_and_copy_page(): PTE is empty, gvaddr_des: {:#x?}",
                                gvaddr_src
                            )
                        ));
                    }
                    pte
                };

                // Update the destination EPCM.
                let new_sec_info =
                    EpcmManager::accept_and_copy_page(gvaddr_des, pte_des.addr(), sec_info, self)?;
                unsafe {
                    core::ptr::copy_nonoverlapping(
                        phys_to_virt(gpaddr_src) as *const u8,
                        phys_to_virt(pte_des.addr() as _) as *mut u8,
                        PAGE_SIZE,
                    );
                }
                pte_des.set_flags(new_sec_info.into(), false)?;
            }
        }
        Ok(())
    }

    pub(crate) fn extend_page_perm(
        self: &Arc<Self>,
        sec_info: usize,
        gvaddr: GuestVirtAddr,
    ) -> HyperCallResult {
        self.validate_state_and_vaddr(gvaddr)?;

        let sec_info = match SgxSecInfo::try_from(sec_info) {
            Ok(sec_info) => sec_info,
            Err(_) => {
                return Err(hypercall_excep_err!(
                    EnclaveExceptionInfo::general_protection(0, &CpuState::EnclaveRunning),
                    format!(
                        "Enclave::extend_page_perm(): Invalid sec_info: {:x}",
                        sec_info
                    )
                ));
            }
        };

        if sec_info.flags.contains(SgxEnclPageFlags::W)
            && !sec_info.flags.contains(SgxEnclPageFlags::R)
        {
            return Err(hypercall_excep_err!(
                EnclaveExceptionInfo::general_protection(0, &CpuState::EnclaveRunning),
                format!(
                    "Enclave::extend_page_perm(): Invalid sec_info: {:?}",
                    sec_info
                )
            ));
        }

        {
            let _encl_mem_lock = self.encl_mem_lock.lock();

            {
                let mut secure_gpt = self.gpt.write();

                let pte = match secure_gpt.get_pte_mut(gvaddr) {
                    Ok(pte) => pte,
                    Err(PagingError::NotMapped(_)) => {
                        let error_code = PageFaultErrorCode::USER_MODE.bits();
                        let enclave_excep = EnclaveExceptionInfo::page_fault_in_encl(
                            error_code, error_code, gvaddr,
                        );
                        return Err(hypercall_excep_err!(
                            enclave_excep,
                            format!("Enclave::extend_page_perm(): Intermediate page table is not mapped, gvaddr: {:#x?}", gvaddr)
                        ));
                    }
                    Err(e) => {
                        return hypercall_hv_err_result!(
                            EFAULT,
                            format!("Enclave::extend_page_perm(): Unexpected error: {:?}", e)
                        );
                    }
                };

                if pte.is_unused() {
                    let error_code = PageFaultErrorCode::USER_MODE.bits();
                    let enclave_excep =
                        EnclaveExceptionInfo::page_fault_in_encl(error_code, error_code, gvaddr);
                    return Err(hypercall_excep_err!(
                        enclave_excep,
                        format!(
                            "Enclave::extend_page_perm(): PTE is empty, gvaddr: {:#x?}",
                            gvaddr
                        )
                    ));
                }

                let gpaddr_aligned = pte.addr();
                let new_sec_info = EpcmManager::extend_page_perm(
                    gvaddr,
                    gpaddr_aligned,
                    sec_info.flags & SgxEnclPageFlags::PERM_MASK,
                    self,
                )?;

                let old_gpt_flag = pte.flags();
                let new_gpt_flags = new_sec_info.into();
                if old_gpt_flag != new_gpt_flags {
                    // Perform NPT-E's permission extension before Guest PTE's to avoid #NPF
                    let hpaddr_aligned = gpaddr_aligned;
                    let new_npt_flags = new_gpt_flags | MemFlags::ENCRYPTED;
                    if let Err(ref e) =
                        self.npt
                            .write()
                            .update(&MemoryRegion::new_with_offset_mapper(
                                gpaddr_aligned,
                                hpaddr_aligned,
                                PAGE_SIZE,
                                new_npt_flags,
                            ))
                    {
                        return hypercall_hv_err_result!(
                            EFAULT,
                            format!(
                                "Enclave::extend_page_perm(): Update NPT mappings error, {:?}",
                                e
                            )
                        );
                    }

                    pte.set_flags(new_gpt_flags, false)?;
                }
            }
        }

        Ok(())
    }
}
