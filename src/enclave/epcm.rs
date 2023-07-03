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

use crate::arch::{EnclaveExceptionInfo, EnclavePFErrorCode, PageFaultErrorCode};
use crate::error::{HvError, HvResult};
use crate::hypercall::error::HyperCallResult;
use crate::memory::cmr::{ConvMemManager, PageStatus};
use crate::memory::{GenericPTE, GuestPhysAddr, GuestVirtAddr};
use crate::percpu::CpuState;

use super::edmm::{PageAcceptType, PageTypeModifyType};
use super::sgx::SgxSecInfo;
use super::{Enclave, SgxEnclPageFlags, SgxEnclPageType};

/// Enclave Page Cache Map Entry
#[derive(Debug)]
#[repr(C)]
pub struct EpcmEntry {
    /// The page status of the EPCM, can only be PageStatus::Secure.
    /// It is set in cmr.rs.
    page_status: PageStatus,
    /// R, W, X, PENDING, MODIFIED, PR and VALID fields.
    flags: SgxEnclPageFlags,
    /// EPCM page type (PT_SECS, PT_TCS, PT_REG, PT_VA, PT_TRIM, PT_SS_FIRST, PT_SS_REST).
    page_type: SgxEnclPageType,
    /// Reserved area.
    _reserved: [u8; 5],
    /// Linear enclave address of the EPC page.
    vaddr: GuestVirtAddr,
    /// Smart pointer of the `Enclave` owning the page, `None` if not initialized.
    enclave: Option<Arc<Enclave>>,
}

impl EpcmEntry {
    pub const EMPTY: Self = Self {
        page_status: PageStatus::Secure,
        flags: SgxEnclPageFlags::empty(),
        _reserved: [0; 5],
        page_type: SgxEnclPageType::SECS,
        enclave: None,
        vaddr: 0,
    };

    pub fn set(
        &mut self,
        flags: SgxEnclPageFlags,
        page_type: SgxEnclPageType,
        vaddr: GuestVirtAddr,
        enclave: &Arc<Enclave>,
    ) {
        self.flags = flags;
        self.page_type = page_type;
        self.vaddr = vaddr;
        self.enclave = Some(Arc::clone(enclave));
    }
}

pub struct EpcmManager;

impl EpcmManager {
    fn validate_epcm_entry_and_mut<T, E: From<HvError>>(
        gvaddr: GuestPhysAddr,
        gpaddr: GuestPhysAddr,
        enclave: &Arc<Enclave>,
        func: impl FnOnce(&mut EpcmEntry) -> Result<T, E>,
    ) -> Result<T, E> {
        ConvMemManager::get().with_epcm_entry_mut(gpaddr, |entry| {
            if !entry.flags.contains(SgxEnclPageFlags::VALID) {
                return hypercall_hv_err_result!(
                    EINVAL,
                    format!(
                        "EpcmManager::validate_epcm_entry_and_mut(): page ({:#x} -> {:#x}) does not exist in EPC",
                        gvaddr, gpaddr
                    )
                );
            }

            if entry.enclave.is_none() {
                return Err(hv_err!(
                    EINVAL,
                    format!(
                        "EpcmManager::validate_epcm_entry_and_mut(): the enclave epcm entry points to is none, gpaddr: {:#x?}",
                        gpaddr
                    )
                ).into());
            }

            if !Arc::ptr_eq(entry.enclave.as_ref().unwrap(), enclave) {
                return Err(hv_err!(
                    EINVAL,
                    format!(
                        "EpcmManager::validate_epcm_entry_and_mut(): enclave mismatches, gpaddr: {:#x?}, enclave in epcm: {:#?}, enclave from user {:#?}",
                        gpaddr, entry.enclave.as_ref().unwrap(), enclave
                    )
                ).into());
            }

            if gvaddr != entry.vaddr {
                return Err(hv_err!(
                    EINVAL,
                    format!(
                        "EpcmManager::validate_epcm_entry_and_mut(): gvaddr mismatcheds, gpaddr: {:#x?}, gvaddr in epcm: {:#x?}, gvaddr from user {:#x?}",
                        gpaddr, entry.vaddr, gvaddr
                    )
                ).into());
            }

            func(entry)
        })
    }

    pub fn is_valid_epc(gpaddr: GuestPhysAddr) -> bool {
        let res: Result<(), HvError> = ConvMemManager::get().with_epcm_entry(gpaddr, |_| Ok(()));
        res.is_ok()
    }

    pub fn is_valid_va_slot(gpaddr: GuestPhysAddr) -> bool {
        ConvMemManager::get()
            .with_epcm_entry(gpaddr, |entry| {
                if !entry.flags.contains(SgxEnclPageFlags::VALID)
                    || entry.page_type != SgxEnclPageType::VA
                {
                    return hv_result_err!(EINVAL);
                }
                Ok(())
            })
            .is_ok()
    }

    pub fn is_blocked(gpaddr: GuestPhysAddr) -> bool {
        ConvMemManager::get()
            .with_epcm_entry(gpaddr, |entry| {
                if !entry.flags.contains(SgxEnclPageFlags::VALID)
                    || !entry.flags.contains(SgxEnclPageFlags::BLOCKED)
                {
                    return hv_result_err!(EINVAL);
                }
                Ok(())
            })
            .is_ok()
    }

    pub fn query_sec_info(gpaddr: GuestPhysAddr) -> HvResult<SgxSecInfo> {
        ConvMemManager::get().with_epcm_entry(gpaddr, |entry| {
            if !entry.flags.contains(SgxEnclPageFlags::VALID) {
                return hv_result_err!(EINVAL);
            }
            Ok(SgxSecInfo::new(entry.flags, entry.page_type))
        })
    }

    pub fn set_blocked(gpaddr: GuestPhysAddr) {
        let _res: HyperCallResult = ConvMemManager::get().with_epcm_entry_mut(gpaddr, |entry| {
            entry.flags |= SgxEnclPageFlags::BLOCKED;
            Ok(())
        });
    }

    pub fn clear_blocked(gpaddr: GuestPhysAddr) {
        let _res: HyperCallResult = ConvMemManager::get().with_epcm_entry_mut(gpaddr, |entry| {
            entry.flags -= SgxEnclPageFlags::BLOCKED;
            Ok(())
        });
    }

    pub fn add_page(
        gvaddr: GuestVirtAddr,
        gpaddr: GuestPhysAddr,
        sec_info: &SgxSecInfo,
        enclave: &Arc<Enclave>,
    ) -> HyperCallResult {
        ConvMemManager::get().with_epcm_entry_mut(gpaddr, |entry| {
            if entry.flags.contains(SgxEnclPageFlags::VALID) {
                return hypercall_hv_err_result!(
                    EINVAL,
                    format!(
                        "EpcmManager::add_page(): page ({:#x} -> {:#x}) is already in EPC",
                        gvaddr, gpaddr
                    )
                );
            }
            enclave.inc_epc_page_num();
            entry.set(
                sec_info.flags | SgxEnclPageFlags::VALID,
                sec_info.page_type,
                gvaddr,
                enclave,
            );
            Ok(())
        })
    }

    pub fn write_back_page(
        gvaddr: GuestVirtAddr,
        gpaddr: GuestPhysAddr,
        enclave: &Arc<Enclave>,
    ) -> HyperCallResult {
        ConvMemManager::get().with_epcm_entry_mut(gpaddr, |entry| {
                if gvaddr != entry.vaddr {
                    return hypercall_hv_err_result!(
                        EINVAL,
                        format!(
                            "EpcmManager::write_back_page(): gvaddr mismatches, gvaddr from user: {:#x}, gvaddr in epcm: {:#x}",
                            gvaddr, entry.vaddr
                        )
                    );
                }

                if entry.enclave.is_none() {
                    return hypercall_hv_err_result!(
                        EINVAL,
                        format!(
                            "EpcmManager::write_back_page(): the enclave epcm entry points to is none gpaddr: {:#x}",
                            gpaddr
                        )
                    );
                }

                if !Arc::ptr_eq(entry.enclave.as_ref().unwrap(), enclave) {
                    return hypercall_hv_err_result!(
                        EINVAL,
                        format!(
                            "EpcmManager::write_back_page(): enclave mismatches, gpaddr: {:#x}, enclave in epcm: {:?}, enclave from user {:?}",
                            gpaddr, entry.enclave.as_ref().unwrap(), enclave
                        )
                    );
                }

                enclave.dec_epc_page_num();
                *entry = EpcmEntry::EMPTY;

                Ok(())
            })
    }

    pub fn remove_page_at_destroy(
        gpaddr: GuestPhysAddr,
        enclave: &Arc<Enclave>,
    ) -> HyperCallResult {
        ConvMemManager::get().with_epcm_entry_mut(gpaddr, |entry| {
            if entry.enclave.is_none() {
                return hypercall_hv_err_result!(
                    EINVAL,
                    format!(
                        "EpcmManager::remove_page_at_destroy(): the enclave epcm entry points to is none, gpaddr: {:#x?}",
                        gpaddr
                    )
                );
            }

            if !Arc::ptr_eq(entry.enclave.as_ref().unwrap(), enclave) {
                return hypercall_hv_err_result!(
                    EINVAL,
                    format!(
                        "EpcmManager::remove_page_at_destroy(): enclave mismatches, gpaddr: {:#x?}, enclave in epcm: {:?}, enclave from user {:?}",
                        gpaddr, entry.enclave.as_ref().unwrap(), enclave
                    )
                );
            }

            let page_type = entry.page_type;
            if page_type != SgxEnclPageType::VA && page_type != SgxEnclPageType::TCS && page_type != SgxEnclPageType::REG && page_type != SgxEnclPageType::TRIM {
                return hypercall_hv_err_result!(
                    EINVAL,
                    format!(
                        "EpcmManager::remove_page_at_destroy(): Invalid page_type: {:?}",
                        page_type
                    )
                );
            }

            enclave.dec_epc_page_num();
            *entry = EpcmEntry::EMPTY;

            Ok(())
        })
    }

    pub fn augment_page(
        gvaddr: GuestVirtAddr,
        gpaddr: GuestPhysAddr,
        enclave: &Arc<Enclave>,
    ) -> HyperCallResult<SgxSecInfo> {
        ConvMemManager::get().with_epcm_entry_mut(gpaddr, |entry| {
            if entry.flags.contains(SgxEnclPageFlags::VALID) {
                return hypercall_hv_err_result!(
                    EINVAL,
                    format!(
                        "EpcmManager::augment_page(): page ({:#x?} -> {:#x?}) is already in EPC",
                        gvaddr, gpaddr
                    )
                );
            }

            entry.set(
                SgxEnclPageFlags::R
                    | SgxEnclPageFlags::W
                    | SgxEnclPageFlags::PENDING
                    | SgxEnclPageFlags::VALID,
                SgxEnclPageType::REG,
                gvaddr,
                enclave,
            );
            enclave.inc_epc_page_num();
            Ok(SgxSecInfo::new(entry.flags, entry.page_type))
        })
    }

    pub(crate) fn modify_page_type(
        gvaddr: GuestVirtAddr,
        gpaddr: GuestPhysAddr,
        page_type: SgxEnclPageType,
        enclave: &Arc<Enclave>,
    ) -> HyperCallResult<(SgxSecInfo, PageTypeModifyType)> {
        Self::validate_epcm_entry_and_mut(gvaddr, gpaddr, enclave, |entry| {
            if entry.flags.contains(SgxEnclPageFlags::PENDING)
                || entry.flags.contains(SgxEnclPageFlags::MODIFIED)
            {
                return Err(hypercall_enclave_err!(
                    PAGENOTMODIFIABLE,
                    format!(
                        "EpcmManager::modify_page_type(): The page is in MODIFED or PENDING state, gvaddr: {:#x?}, flags: {:?}, page_type: {:?}",
                        gvaddr, entry.flags, page_type
                    )
                ));
            }

            if entry.flags.contains(SgxEnclPageFlags::BLOCKED) {
                return hypercall_hv_err_result!(
                    EINVAL,
                    format!(
                        "EpcmManager::modify_page_type(): Do not support modify page type when it is being reclaimed, gvaddr: {:#x?}, flags: {:?}, type: {:?}",
                        gvaddr, entry.flags, entry.page_type
                    )
                );
            }

            let page_type_modify_type = {
                if entry.page_type == SgxEnclPageType::REG && page_type == SgxEnclPageType::TCS {
                    PageTypeModifyType::RegToTcs
                } else if entry.page_type == SgxEnclPageType::REG
                    && page_type == SgxEnclPageType::TRIM
                {
                    PageTypeModifyType::RegToTrim
                } else if entry.page_type == SgxEnclPageType::TCS
                    && page_type == SgxEnclPageType::TRIM
                {
                    PageTypeModifyType::TcsToTrim
                } else {
                    return hypercall_hv_err_result!(
                        EINVAL,
                        format!(
                            "EpcmManager::modify_page_type(): invalid conversion procedure, from: {:?}, to: {:?}",
                            entry.page_type, page_type
                        )
                    );
                }
            };

            entry.flags |= SgxEnclPageFlags::MODIFIED;
            entry.page_type = page_type;

            Ok((
                SgxSecInfo::new(entry.flags, entry.page_type),
                page_type_modify_type,
            ))
        })
    }

    pub(crate) fn restrict_page_perm(
        gvaddr: GuestVirtAddr,
        gpaddr: GuestPhysAddr,
        page_flags: SgxEnclPageFlags,
        enclave: &Arc<Enclave>,
    ) -> HyperCallResult<SgxSecInfo> {
        Self::validate_epcm_entry_and_mut(gvaddr, gpaddr, enclave, |entry| {
            if entry.page_type != SgxEnclPageType::REG {
                return hypercall_hv_err_result!(
                    EINVAL,
                    format!(
                        "EpcmManager::restrict_page_perm(): Page type is not REG, gvaddr: {:#x?}, page_type: {:?}",
                        gvaddr, entry.page_type
                    )
                );
            }

            if entry.flags.contains(SgxEnclPageFlags::PENDING)
                || entry.flags.contains(SgxEnclPageFlags::MODIFIED)
            {
                return Err(hypercall_enclave_err!(
                    PAGENOTMODIFIABLE,
                    format!(
                        "EpcmManager::restrict_page_perm(): The page is in MODIFED or PENDING state, gvaddr: {:#x?}, flags: {:?}, page_flags: {:?}",
                        gvaddr, entry.flags, page_flags
                    )
                ));
            }

            if entry.flags.contains(SgxEnclPageFlags::BLOCKED) {
                return hypercall_hv_err_result!(
                    EINVAL,
                    format!(
                        "EpcmManager::restrict_page_perm(): Do not support resctrcting page permissions when it is being reclaimed, gvaddr: {:#x?}, flags: {:?}, type: {:?}",
                        gvaddr, entry.flags, entry.page_type
                    )
                );
            }

            entry.flags |= SgxEnclPageFlags::PR;

            let new_perm = SgxEnclPageFlags::PERM_MASK & page_flags & entry.flags;
            entry.flags -= SgxEnclPageFlags::PERM_MASK;
            entry.flags |= new_perm;

            Ok(SgxSecInfo::new(entry.flags, entry.page_type))
        })
    }

    pub(crate) fn remove_page_at_runtime(
        gvaddr: GuestVirtAddr,
        gpaddr: GuestPhysAddr,
        enclave: &Arc<Enclave>,
    ) -> HyperCallResult {
        Self::validate_epcm_entry_and_mut(gvaddr, gpaddr, enclave, |entry| {
            if entry.flags.contains(SgxEnclPageFlags::MODIFIED)
                || entry.page_type != SgxEnclPageType::TRIM
            {
                return hypercall_hv_err_result!(
                    EINVAL,
                    format!(
                        "EpcmManager::remove_page_at_runtime(): Invalid page type or page state, gvaddr: {:#x?}, flags: {:?}, type: {:?}",
                        gvaddr, entry.flags, entry.page_type
                    )
                );
            }

            if entry.flags.contains(SgxEnclPageFlags::BLOCKED) {
                return hypercall_hv_err_result!(
                    EINVAL,
                    format!(
                        "EpcmManager::remove_page_at_runtime(): Do not support removing paga when it is being reclaimed, gvaddr: {:#x?}, flags: {:?}, type: {:?}",
                        gvaddr, entry.flags, entry.page_type
                    )
                );
            }

            *entry = EpcmEntry::EMPTY;
            enclave.dec_epc_page_num();
            Ok(())
        })
    }

    pub(crate) fn accept_page(
        gvaddr: GuestVirtAddr,
        gpaddr: GuestPhysAddr,
        sec_info: &SgxSecInfo,
        page_accept_type: &PageAcceptType,
        enclave: &Arc<Enclave>,
    ) -> HyperCallResult<SgxSecInfo> {
        Self::validate_epcm_entry_and_mut(gvaddr, gpaddr, enclave, |entry| {
            if entry.page_type != SgxEnclPageType::REG
                && entry.page_type != SgxEnclPageType::TCS
                && entry.page_type != SgxEnclPageType::TRIM
            {
                return hypercall_hv_err_result!(
                    EINVAL,
                    format!(
                        "EpcmManager::accept_page(): invalid page type: {:?}, gpaddr: {:#x}",
                        entry.page_type, gpaddr
                    )
                );
            }

            if sec_info.page_type != entry.page_type {
                return Err(hypercall_enclave_err!(
                    EPAGEATTRIBUTESMISMATCH,
                    format!(
                        "EpcmManager::accept_page(): page_type mismatches, gpaddr: {:#x?}, page_type from user: {:?}, page_type in epcm: {:?}",
                        gpaddr, sec_info.page_type, entry.page_type
                    )
                ));
            }

            match *page_accept_type {
                PageAcceptType::Augment | PageAcceptType::PermRestrict => {
                    let flags_mask = SgxEnclPageFlags::PERM_MASK
                        | SgxEnclPageFlags::MODIFIED
                        | SgxEnclPageFlags::PENDING
                        | SgxEnclPageFlags::PR;
                    if entry.flags & flags_mask != sec_info.flags & flags_mask {
                        return Err(hypercall_enclave_err!(
                            EPAGEATTRIBUTESMISMATCH,
                            format!(
                                "EpcmManager::accept_page(): page flags mismatches, gpaddr: {:#x?}, flags from user: {:?}, flags in epcm: {:?}",
                                gpaddr, sec_info.flags, entry.flags
                            )
                        ));
                    }
                }
                PageAcceptType::TypeModify => {
                    if !entry.flags.contains(SgxEnclPageFlags::MODIFIED) {
                        return Err(hypercall_enclave_err!(
                            EPAGEATTRIBUTESMISMATCH,
                            format!(
                                "EpcmManager::accept_page(): Modified bit is not set in, gpaddr: {:#x?}, flags from user: {:?}, flags in epcm: {:?}",
                                gpaddr, sec_info.flags, entry.flags
                            )
                        ));
                    }
                }
            }

            // If page is being reclaimed, cancel its reclaim by unmark the BLOCKED state in EPCM
            entry.flags -= SgxEnclPageFlags::BLOCKED;

            entry.flags -= SgxEnclPageFlags::PENDING;
            entry.flags -= SgxEnclPageFlags::MODIFIED;
            entry.flags -= SgxEnclPageFlags::PR;
            Ok(SgxSecInfo::new(entry.flags, entry.page_type))
        })
    }

    pub(crate) fn accept_and_copy_page(
        gvaddr_des: GuestVirtAddr,
        gpaddr_des: GuestPhysAddr,
        sec_info: SgxSecInfo,
        enclave: &Arc<Enclave>,
    ) -> HyperCallResult<SgxSecInfo> {
        Self::validate_epcm_entry_and_mut(gvaddr_des, gpaddr_des, enclave, |entry| {
            if !entry.flags.contains(SgxEnclPageFlags::PENDING)
                || entry.flags.contains(SgxEnclPageFlags::MODIFIED)
                || (entry.flags & SgxEnclPageFlags::PERM_MASK)
                    != (SgxEnclPageFlags::R | SgxEnclPageFlags::W)
                || entry.page_type != sec_info.page_type
            {
                return Err(hypercall_enclave_err!(
                    EPAGEATTRIBUTESMISMATCH,
                    format!(
                        "EpcmManager::accept_and_copy_page(): page is not valid, gpaddr_des {:#x}",
                        gpaddr_des
                    )
                ));
            }

            entry.flags -= SgxEnclPageFlags::BLOCKED;
            entry.flags -= SgxEnclPageFlags::PENDING;

            entry.flags -= SgxEnclPageFlags::PERM_MASK;
            entry.flags |= SgxEnclPageFlags::PERM_MASK & sec_info.flags;

            Ok(SgxSecInfo::new(entry.flags, entry.page_type))
        })
    }

    pub(crate) fn extend_page_perm(
        gvaddr: GuestVirtAddr,
        gpaddr: GuestPhysAddr,
        page_flags: SgxEnclPageFlags,
        enclave: &Arc<Enclave>,
    ) -> HyperCallResult<SgxSecInfo> {
        Self::validate_epcm_entry_and_mut(gvaddr, gpaddr, enclave, |entry| {
            if entry.page_type != SgxEnclPageType::REG
                || entry.flags.contains(SgxEnclPageFlags::PENDING)
                || entry.flags.contains(SgxEnclPageFlags::MODIFIED)
            {
                let errcd_for_linux = (PageFaultErrorCode::USER_MODE
                    | PageFaultErrorCode::PROTECTION_VIOLATION)
                    .bits();
                let errcd_for_misc =
                    errcd_for_linux | EnclavePFErrorCode::EPCM_ATTR_MISMATCH.bits();
                let enclave_excep = EnclaveExceptionInfo::page_fault_in_encl(
                    errcd_for_linux,
                    errcd_for_misc,
                    gvaddr,
                );
                return Err(hypercall_excep_err!(
                    enclave_excep,
                    format!(
                        "EpcmManager::extend_page_perm(): Invalid page type or flags, gvaddr {:#x?}, gpaddr: {:#x}, page_type: {:?} flags: {:?}",
                        gvaddr, gpaddr, entry.page_type, entry.flags
                    )
                ));
            }

            // If page is beng reclaimed, cancel its reclaim by unmark the BLOCKED state in EPCM
            entry.flags -= SgxEnclPageFlags::BLOCKED;

            let new_perm = SgxEnclPageFlags::PERM_MASK & (page_flags | entry.flags);
            entry.flags -= SgxEnclPageFlags::PERM_MASK;
            entry.flags |= new_perm;

            Ok(SgxSecInfo::new(entry.flags, entry.page_type))
        })
    }

    pub fn get_enclave_out_encl(
        tcs_gpaddr: GuestPhysAddr,
        tcs_gvaddr: GuestVirtAddr,
    ) -> HyperCallResult<Arc<Enclave>> {
        // #PF returned in the function is caused by EPCM attribute mismatch, inject SIGSEGV to userspace App.
        let page_fault_excep = EnclaveExceptionInfo::page_fault_out_encl(
            (PageFaultErrorCode::USER_MODE | PageFaultErrorCode::PROTECTION_VIOLATION).bits(),
            tcs_gvaddr,
        );
        let enclave_cloned = ConvMemManager::get().with_epcm_entry(tcs_gpaddr, |entry| {
            if !entry.flags.contains(SgxEnclPageFlags::VALID) {
                return Err(hypercall_excep_err!(
                    page_fault_excep,
                    format!(
                        "EpcmManager::get_enclave_out_encl(): invalid page {:#x}",
                        tcs_gpaddr
                    )
                ));
            }
            if entry.page_type != SgxEnclPageType::TCS {
                return Err(hypercall_excep_err!(
                    page_fault_excep,
                    format!(
                        "EpcmManager::get_enclave_out_encl(): \
                        type of page {:#x} is not satisfied: {:?}",
                        tcs_gpaddr, entry.page_type,
                    )
                ));
            }
            if entry.flags.contains(SgxEnclPageFlags::PENDING) || entry.flags.contains(SgxEnclPageFlags::MODIFIED) {
                return Err(hypercall_excep_err!(
                    page_fault_excep,
                    format!(
                        "EpcmManager::get_enclave_out_encl(): \
                        Invalid page {:#x} state: {:?}",
                        tcs_gpaddr, entry.page_type,
                    )
                ));
            }
            if tcs_gvaddr != entry.vaddr {
                return Err(hypercall_excep_err!(
                    page_fault_excep,
                    format!(
                        "EpcmManager::get_enclave_out_encl(): \
                        virtual address of page {:#x} does not match (requested: {:#x}, entry: {:#x})",
                        tcs_gpaddr, tcs_gvaddr, entry.vaddr
                    )
                ));
            }
            Ok(entry.enclave.as_ref().expect("entry.enclave is None").clone())
        })?;
        Ok(enclave_cloned)
    }

    pub fn get_enclave_in_encl(tcs_gpaddr: GuestPhysAddr) -> HvResult<Arc<Enclave>> {
        let enclave_cloned = ConvMemManager::get().with_epcm_entry(tcs_gpaddr, |entry| {
            if !entry.flags.contains(SgxEnclPageFlags::VALID) {
                return hv_result_err!(
                    EINVAL,
                    format!(
                        "EpcmManager::get_enclave_by_page(): invalid page {:#x}",
                        tcs_gpaddr
                    )
                );
            }
            Ok(entry
                .enclave
                .as_ref()
                .expect("entry.enclave is None")
                .clone())
        })?;
        Ok(enclave_cloned)
    }

    /// The EPCM is virtualized by hypervisor in Hyper Enclave.
    /// If the page table walk is performed by hypervisor's function(software) rather than hardware,
    /// the caller needs to check or update the EPCM's attributes.
    ///
    /// There are two types of software(hypervisor) page table walk:
    /// 1. Normal page table walk: There is no EPCM attributes modification during the walk;
    /// 2. Special page table walk: Walk the page table and update the EPCM attributes,
    ///    when handling enclave's hypercall.
    ///
    /// If there is a special software page table walk, callers need to invoke such function, in order to:
    /// 1. Verify whether the page is legal to access;
    /// 2. Cancel reclaim by clearing the `BLOCKED` state if the page is being reclaimed.
    ///
    /// By doing so, the virtualized EPCM is able to take effect on the page table walk by hypervisor.
    pub(crate) fn access_page_check(
        gvaddr: GuestVirtAddr,
        gpaddr: GuestPhysAddr,
        enclave: &Arc<Enclave>,
        write: bool,
        is_encl_mode: bool,
    ) -> HyperCallResult<SgxSecInfo> {
        Self::validate_epcm_entry_and_mut(gvaddr, gpaddr, enclave, |entry| {
            if write && !entry.flags.contains(SgxEnclPageFlags::W) {
                let errcd =
                    (PageFaultErrorCode::USER_MODE | PageFaultErrorCode::CAUSED_BY_WRITE).bits();
                let excep = if is_encl_mode {
                    EnclaveExceptionInfo::page_fault_in_encl(errcd, errcd, gvaddr)
                } else {
                    EnclaveExceptionInfo::page_fault_out_encl(errcd, gvaddr)
                };
                return Err(hypercall_excep_err!(
                    excep,
                    format!(
                        "EpcmManager::access_page_check(): gvaddr: {:#x?} has no permission of W",
                        gvaddr
                    )
                ));
            }

            if entry.flags.contains(SgxEnclPageFlags::MODIFIED)
                || entry.flags.contains(SgxEnclPageFlags::PENDING)
                || entry.page_type != SgxEnclPageType::REG
            {
                let excep = {
                    let errcd_for_linux = (PageFaultErrorCode::USER_MODE
                        | PageFaultErrorCode::PROTECTION_VIOLATION)
                        .bits();
                    let errcd_for_linux = if write {
                        errcd_for_linux | PageFaultErrorCode::CAUSED_BY_WRITE.bits()
                    } else {
                        errcd_for_linux
                    };
                    if is_encl_mode {
                        let errcd_for_misc =
                            errcd_for_linux | EnclavePFErrorCode::EPCM_ATTR_MISMATCH.bits();
                        EnclaveExceptionInfo::page_fault_in_encl(
                            errcd_for_linux,
                            errcd_for_misc,
                            gvaddr,
                        )
                    } else {
                        EnclaveExceptionInfo::page_fault_out_encl(errcd_for_linux, gvaddr)
                    }
                };
                return Err(hypercall_excep_err!(
                    excep,
                    "EpcmManager::access_page_check(): page is not valid"
                ));
            }

            entry.flags -= SgxEnclPageFlags::BLOCKED;
            Ok(SgxSecInfo::new(entry.flags, entry.page_type))
        })
    }

    pub fn fixup_page_fault<PTE: GenericPTE>(
        fault_gvaddr: GuestVirtAddr,
        pte: &mut PTE,
        error_code: PageFaultErrorCode,
    ) -> HvResult<Option<EnclaveExceptionInfo>> {
        let gpaddr_aligned = pte.addr();
        ConvMemManager::get().with_epcm_entry_mut(gpaddr_aligned, |entry| {
            let res = if !entry.flags.contains(SgxEnclPageFlags::VALID)
                || !entry.flags.contains(SgxEnclPageFlags::R)
            {
                error!(
                    "Hypervisor error, invalid flag configuration, gvaddr: {:#?}, entry flags: {:?}",
                    fault_gvaddr, entry.flags
                );
                Ok(Some(EnclaveExceptionInfo::general_protection(0, &CpuState::EnclaveRunning)))
            } else if entry.flags.contains(SgxEnclPageFlags::BLOCKED) {
                // Cancel reclaim, and resume execution (do no inject exception).
                pte.set_present()?;
                entry.flags -= SgxEnclPageFlags::BLOCKED;
                Ok(None)
            } else if entry.flags.contains(SgxEnclPageFlags::PENDING) || entry.flags.contains(SgxEnclPageFlags::MODIFIED)
                || entry.page_type == SgxEnclPageType::TRIM || entry.page_type == SgxEnclPageType::TCS {
                // Illegal access to page in the process of augmentation or type modification,
                // or illegal access to page whose type is not PT_REG,
                // inject SIGSEGV to userspace App.
                Ok(Some(EnclaveExceptionInfo::page_fault_in_encl(
                    (PageFaultErrorCode::PROTECTION_VIOLATION | PageFaultErrorCode::USER_MODE)
                        .bits(),
                    (error_code | PageFaultErrorCode::PROTECTION_VIOLATION).bits() |
                        EnclavePFErrorCode::EPCM_ATTR_MISMATCH.bits(),
                    fault_gvaddr,
                )))
            } else if entry.page_type != SgxEnclPageType::REG {
                error!(
                    "Hypervisor error, invalid page type configuration, fault_gvaddr: {:#x?}, page_type: {:?}",
                    fault_gvaddr, entry.page_type
                );
                Ok(Some(EnclaveExceptionInfo::general_protection(0, &CpuState::EnclaveRunning)))
            } else if (error_code.contains(PageFaultErrorCode::CAUSED_BY_WRITE) && !entry.flags.contains(SgxEnclPageFlags::W)) ||
                (error_code.contains(PageFaultErrorCode::INSTRUCTION_FETCH) && !entry.flags.contains(SgxEnclPageFlags::X)) {
                // Illegal write or illegal code execution.
                Ok(Some(EnclaveExceptionInfo::page_fault_in_encl(
                    error_code
                        .bits(),
                    error_code.bits(),
                    fault_gvaddr,
                )))
            } else {
                // In multi-threaded scenarios, threads may generate #PF from the same address,
                // and one of the thread may handle the #PF (the first thread).
                // Other threads may arrive here, so here resume execution.
                Ok(None)
            };

            res
        })
    }
}

#[cfg(test)]
pub(crate) mod tests {
    use core::ops::Range;
    use memoffset::span_of;

    use crate::enclave::epcm::EpcmEntry;

    pub fn get_epcm_page_status_span() -> Range<usize> {
        span_of!(EpcmEntry, page_status)
    }
}
