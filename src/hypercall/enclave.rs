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

use addr::GuestPhysAddr;

use super::error::HyperCallResult;
use super::tc;
use super::tc::TPM_LOCK;
use super::HyperCall;
use crate::arch::vmm::VcpuAccessGuestState;
use crate::enclave::reclaim;
use crate::enclave::report::{
    CSRRequest, Cert, EncBlob, EncSecret, KeyPubArea, PCRList, SM2Sig, SM4Key, SgxKey128Bit,
    SgxKeyRequest, SgxQuote, SgxReport, SgxReportData, SgxTargetInfo,
};
use crate::enclave::sgx::SigStruct;
use crate::enclave::shared_mem::SharedMemSyncType;
use crate::enclave::structs::{
    HvEnclAugPageDesc, HvEnclDesc, HvEnclInitDesc, HvEnclModtPageDesc, HvEnclNewPageDesc,
    HvEnclRemovePageAtRuntimeDesc, HvEnclRemovePagesAtDestroyDesc,
    HvEnclRemovePagesAtDestroyPageArray, HvEnclRemovePagesAtDestroyResArray,
    HvEnclRestrictPageDesc, HvReclaimerPageDesc, HvReclaimerPagesDesc, HvSharedMemoryDesc,
    NR_RECLAIM_EPC_PAGES,
};
use crate::enclave::{Enclave, EnclaveStatsId, ENCLAVE_MANAGER};
use crate::memory::cmr::ConvMemManager;
use crate::memory::gaccess::{AsGuestPtr, GuestPtr};
use crate::memory::{addr, GenericPageTableImmut, GuestVirtAddr};
use crate::stats::Instant;
use core::mem::size_of;

impl HyperCall<'_> {
    pub(super) fn enclave_create(
        &self,
        config_ptr: GuestPtr<HvEnclDesc>,
    ) -> HyperCallResult<usize> {
        let now = Instant::now();
        let secs_gpaddr = config_ptr.as_guest_paddr()?;
        let secs = *GuestPtr::gpaddr_to_ref(&secs_gpaddr, false)?;
        info!("enclave_create({:#x?}): {:#x?}", config_ptr, secs);
        let enclave = Enclave::new(secs_gpaddr, config_ptr.guest_vaddr(), secs)?;
        ENCLAVE_MANAGER.add_enclave(enclave.clone())?;
        enclave.atomic_add_stats(EnclaveStatsId::Create, now.elapsed());
        Ok(0)
    }

    pub(super) fn enclave_add_page(
        &self,
        page_desc_ptr: GuestPtr<HvEnclNewPageDesc>,
    ) -> HyperCallResult<usize> {
        let now = Instant::now();
        let page_desc = page_desc_ptr.read()?;
        debug!("enclave_add_page({:#x?}): {:#x?}", page_desc_ptr, page_desc);
        let config_ptr = page_desc
            .config_address
            .as_guest_ptr_ns::<HvEnclDesc>(&self.gpt, self.privilege_level());
        let enclave = ENCLAVE_MANAGER.find_enclave(config_ptr.as_guest_paddr()?)?;
        enclave.add_page(&page_desc, &self.gpt)?;
        enclave.atomic_add_stats(EnclaveStatsId::AddPage, now.elapsed());

        Ok(0)
    }

    pub(super) fn enclave_init(
        &self,
        init_desc_ptr: GuestPtr<HvEnclInitDesc>,
    ) -> HyperCallResult<usize> {
        let now = Instant::now();
        let init_desc = init_desc_ptr.read()?;
        info!("enclave_init({:#x?}): {:#x?}", init_desc_ptr, init_desc);
        let config_ptr = init_desc
            .config_address
            .as_guest_ptr_ns::<HvEnclDesc>(&self.gpt, self.privilege_level());
        let enclave = ENCLAVE_MANAGER.find_enclave(config_ptr.as_guest_paddr()?)?;
        let sigstruct_ptr = init_desc
            .sigstruct
            .as_guest_ptr_ns::<SigStruct>(&self.gpt, self.privilege_level());
        enclave.init(&sigstruct_ptr.read()?)?;
        enclave.atomic_add_stats(EnclaveStatsId::Init, now.elapsed());
        Ok(0)
    }

    pub(super) fn enclave_prepare_destroy(
        &self,
        config_ptr: GuestPtr<HvEnclDesc>,
    ) -> HyperCallResult<usize> {
        let now = Instant::now();
        let enclave = ENCLAVE_MANAGER.find_enclave(config_ptr.as_guest_paddr()?)?;
        debug!(
            "enclave_prepare_destroy, config_ptr: {:#x?}), encalve: {:?}",
            config_ptr, enclave
        );
        enclave.prepare_destroy()?;
        enclave.atomic_add_stats(EnclaveStatsId::PrepareDestroy, now.elapsed());
        Ok(0)
    }

    pub(super) fn enclave_finish_destroy(
        &self,
        config_ptr: GuestPtr<HvEnclDesc>,
    ) -> HyperCallResult<usize> {
        let config = config_ptr.read()?;
        info!("enclave_finish_destroy({:#x?}): {:#x?}", config_ptr, config);
        ENCLAVE_MANAGER.remove_enclave(config_ptr.as_guest_paddr()?)?;
        Ok(0)
    }

    pub(super) fn enclave_enter(&mut self) -> HyperCallResult<usize> {
        let now = Instant::now();
        let guest_regs = self.cpu_data.vcpu.regs();
        let tcs_vaddr = guest_regs.rbx as GuestVirtAddr;
        let aep = guest_regs.rcx;
        debug!("enclave_enter(tcs_vaddr={:#x?}, aep={:#x})", tcs_vaddr, aep);
        let enclave = self.cpu_data.enclave_enter(tcs_vaddr, aep)?;
        enclave.atomic_add_stats(EnclaveStatsId::Enter, now.elapsed());
        Ok(0)
    }

    pub(super) fn enclave_accept(&mut self) -> HyperCallResult<usize> {
        let now = Instant::now();
        let enclave = self.cpu_data.get_current_enclave()?;
        let guest_regs = self.cpu_data.vcpu.regs();
        let sec_info = guest_regs.rbx as usize;
        let gvaddr = guest_regs.rcx as usize;
        enclave.accept_page(sec_info, gvaddr)?;

        // Set the return value
        self.cpu_data.vcpu.regs_mut().rax = 0;
        enclave.atomic_add_stats(EnclaveStatsId::AcceptPage, now.elapsed());
        Ok(0)
    }

    pub(super) fn enclave_accept_copy(&mut self) -> HyperCallResult<usize> {
        let now = Instant::now();
        let enclave = self.cpu_data.get_current_enclave()?;
        let guest_regs = self.cpu_data.vcpu.regs();
        let sec_info = guest_regs.rbx as usize;
        let gvaddr_des = guest_regs.rcx as usize;
        let gvaddr_src = guest_regs.rdx as usize;
        enclave.accept_and_copy_page(sec_info, gvaddr_src, gvaddr_des)?;

        // Set the return value
        self.cpu_data.vcpu.regs_mut().rax = 0;
        enclave.atomic_add_stats(EnclaveStatsId::AcceptCopyPage, now.elapsed());
        Ok(0)
    }

    pub(super) fn enclave_extend_page_perm(&mut self) -> HyperCallResult<usize> {
        let now = Instant::now();
        let guest_regs = self.cpu_data.vcpu.regs();

        let enclave = self.cpu_data.get_current_enclave()?;
        let sec_info = guest_regs.rbx as usize;
        let gvaddr = guest_regs.rcx as usize;
        enclave.extend_page_perm(sec_info, gvaddr)?;

        // Set the return value of EMODPE
        self.cpu_data.vcpu.regs_mut().rax = 0;
        enclave.atomic_add_stats(EnclaveStatsId::ExtendPagePerm, now.elapsed());
        Ok(0)
    }

    pub(super) fn enclave_resume(&mut self) -> HyperCallResult<usize> {
        let now = Instant::now();
        let guest_regs = self.cpu_data.vcpu.regs();
        let tcs_vaddr = guest_regs.rbx as GuestVirtAddr;
        let aep = guest_regs.rcx;
        debug!(
            "enclave_resume(tcs_vaddr={:#x?}, aep={:#x})",
            tcs_vaddr, aep
        );
        let enclave = self.cpu_data.enclave_resume(tcs_vaddr, aep)?;
        enclave.atomic_add_stats(EnclaveStatsId::Resume, now.elapsed());
        Ok(0)
    }

    pub(super) fn enclave_exit(&mut self) -> HyperCallResult<usize> {
        let now = Instant::now();
        let exit_ip = self.cpu_data.vcpu.regs().rbx;
        debug!("enclave_exit(exit_ip={:#x})", exit_ip);
        let enclave = self.cpu_data.enclave_exit(exit_ip)?;
        enclave.atomic_add_stats(EnclaveStatsId::Exit, now.elapsed());
        Ok(0)
    }

    pub(super) fn enclave_report(&mut self) -> HyperCallResult<usize> {
        info!("enclave_report");
        let enclave = self.cpu_data.get_current_enclave()?;
        if !enclave.is_init() {
            return Ok(0);
        }

        let guest_regs = self.cpu_data.vcpu.regs();
        let target_info_ptr: GuestPtr<SgxTargetInfo> =
            guest_regs
                .rbx
                .as_guest_ptr_s(&enclave, &self.cpu_data.state, self.privilege_level());
        let report_data_ptr: GuestPtr<SgxReportData> =
            guest_regs
                .rcx
                .as_guest_ptr_s(&enclave, &self.cpu_data.state, self.privilege_level());
        let mut report_ptr: GuestPtr<SgxReport> =
            guest_regs
                .rdx
                .as_guest_ptr_s(&enclave, &self.cpu_data.state, self.privilege_level());
        let target_info = target_info_ptr.read()?;
        let report_data = report_data_ptr.read()?;
        let mut tmp_report: SgxReport = Default::default();
        let report_size = tc::create_report(&target_info, &report_data, &mut tmp_report, &enclave);
        info!("enclave_report size={}", report_size);
        report_ptr.write(tmp_report)?;

        self.cpu_data.vcpu.set_return_val(0);
        Ok(report_size as usize)
    }

    pub(super) fn enclave_quote(&mut self) -> HyperCallResult<usize> {
        let guest_regs = self.cpu_data.vcpu.regs();
        let report_ptr: GuestPtr<SgxReport> = guest_regs
            .rdi
            .as_guest_ptr_ns(&self.gpt, self.privilege_level());
        let mut quote_ptr: GuestPtr<SgxQuote> = guest_regs
            .rsi
            .as_guest_ptr_ns(&self.gpt, self.privilege_level());
        let quote_buffer_size: usize = guest_regs.rdx as usize;
        let mut ret_len_ptr: GuestPtr<u64> = guest_regs
            .rcx
            .as_guest_ptr_ns(&self.gpt, self.privilege_level());
        let report = report_ptr.read()?;
        let mut tmp_quote: SgxQuote = Default::default();
        let quote_len = tc::create_quote(&report, &mut tmp_quote, quote_buffer_size as u32);
        info!("the size of the whole quote={}", quote_len);
        quote_ptr.write(tmp_quote)?;
        ret_len_ptr.write(quote_len as u64)?;

        self.cpu_data.vcpu.set_return_val(0);
        Ok(0 as usize)
    }

    pub(super) fn enclave_getkey(&mut self) -> HyperCallResult<usize> {
        let enclave = self.cpu_data.get_current_enclave()?;
        if !enclave.is_init() {
            return Ok(0);
        }

        let guest_regs = self.cpu_data.vcpu.regs();
        let key_request_ptr: GuestPtr<SgxKeyRequest> =
            guest_regs
                .rbx
                .as_guest_ptr_s(&enclave, &self.cpu_data.state, self.privilege_level());
        let mut key_ptr: GuestPtr<SgxKey128Bit> =
            guest_regs
                .rcx
                .as_guest_ptr_s(&enclave, &self.cpu_data.state, self.privilege_level());
        let key_request = key_request_ptr.read()?;
        let mut tmp_key: SgxKey128Bit = Default::default();
        let key_len = tc::create_key(&key_request, &enclave, &mut tmp_key);
        info!("the size of the key created ={}", key_len);
        key_ptr.write(tmp_key)?;

        self.cpu_data.vcpu.set_return_val(0);
        Ok(key_len as usize)
    }

    pub(super) fn sign_csr(&self) -> HyperCallResult<usize> {
        let guest_regs = self.cpu_data.vcpu.regs();
        let csr_ptr: GuestPtr<CSRRequest> = guest_regs
            .rdi
            .as_guest_ptr_ns(&self.gpt, self.privilege_level());
        let csr_len: usize = guest_regs.rsi as usize;
        let mut sig_ptr: GuestPtr<SM2Sig> = guest_regs
            .rdx
            .as_guest_ptr_ns(&self.gpt, self.privilege_level());
        let mut ret_len_ptr: GuestPtr<u64> = guest_regs
            .rcx
            .as_guest_ptr_ns(&self.gpt, self.privilege_level());
        if csr_len == 0 || csr_len > size_of::<CSRRequest>() {
            error!("HyperEnclave:sign_csr invalid csr length {}", csr_len)
        }
        let csr = csr_ptr.read()?;
        let mut tmp_sig: SM2Sig = Default::default();
        let sig_len = tc::sign_csr(&csr.content, csr_len as u32, &mut tmp_sig.0);
        sig_ptr.write(tmp_sig)?;
        ret_len_ptr.write(sig_len as u64)?;
        Ok(0)
    }

    pub(super) fn get_pub_keys(&self) -> HyperCallResult<usize> {
        let guest_regs = self.cpu_data.vcpu.regs();
        let mut tpm_pub_key_ptr: GuestPtr<SM2Sig> = guest_regs
            .rdi
            .as_guest_ptr_ns(&self.gpt, self.privilege_level());
        let mut hv_pub_key_ptr: GuestPtr<SM2Sig> = guest_regs
            .rsi
            .as_guest_ptr_ns(&self.gpt, self.privilege_level());
        let mut pcr_list_ptr: GuestPtr<PCRList> = guest_regs
            .rdx
            .as_guest_ptr_ns(&self.gpt, self.privilege_level());
        let mut key_area_ptr: GuestPtr<KeyPubArea> = guest_regs
            .rcx
            .as_guest_ptr_ns(&self.gpt, self.privilege_level());
        let mut ret_len_ptr: GuestPtr<u64> = guest_regs
            .r8
            .as_guest_ptr_ns(&self.gpt, self.privilege_level());

        let mut tmp_tpm_pub_key: SM2Sig = Default::default();
        let mut tmp_hv_pub_key: SM2Sig = Default::default();
        let mut tmp_pcr_list: PCRList = Default::default();
        let mut pub_area: KeyPubArea = Default::default();
        let pk_len = tc::get_pub_keys(
            &mut tmp_tpm_pub_key.0,
            &mut tmp_hv_pub_key.0,
            &mut tmp_pcr_list.0,
            &mut pub_area.0,
        );
        tpm_pub_key_ptr.write(tmp_tpm_pub_key)?;
        hv_pub_key_ptr.write(tmp_hv_pub_key)?;
        pcr_list_ptr.write(tmp_pcr_list)?;
        key_area_ptr.write(pub_area)?;
        ret_len_ptr.write(pk_len as u64)?;
        Ok(0)
    }

    pub(super) fn mng_tpm_cert(&self) -> HyperCallResult<usize> {
        let guest_regs = self.cpu_data.vcpu.regs();
        let read = guest_regs.r8 as usize;
        let mut ret_len_ptr: GuestPtr<u64> = guest_regs
            .rcx
            .as_guest_ptr_ns(&self.gpt, self.privilege_level());
        let ret_len: u64;
        if read <= 0 {
            //write ak cert
            let cert_ptr: GuestPtr<Cert> = guest_regs
                .rdi
                .as_guest_ptr_ns(&self.gpt, self.privilege_level());
            let cert_len: usize = guest_regs.rsi as usize;
            if cert_len == 0 || cert_len > size_of::<Cert>() {
                error!("HyperEnclave:invalid cert length {}", cert_len)
            }
            let cert = cert_ptr.read()?;
            ret_len = tc::write_cert(&cert.content, cert_len as u32) as u64;
        } else {
            let mut cert_ptr: GuestPtr<Cert> = guest_regs
                .rdx
                .as_guest_ptr_ns(&self.gpt, self.privilege_level());
            let mut cert: Cert = Default::default();
            ret_len = tc::read_cert(&mut cert.content, read as u32) as u64;
            cert_ptr.write(cert)?;
        }
        ret_len_ptr.write(ret_len)?;
        println!("mng_tpm_cert ret_len={}", ret_len);
        Ok(0)
    }

    pub(super) fn verify_report(&self) -> HyperCallResult<usize> {
        let enclave = self.cpu_data.get_current_enclave()?;
        if !enclave.is_init() {
            return Ok(0);
        }

        let guest_regs = self.cpu_data.vcpu.regs();
        let report_ptr: GuestPtr<SgxReport> =
            guest_regs
                .rbx
                .as_guest_ptr_s(&enclave, &self.cpu_data.state, self.privilege_level());
        let report = report_ptr.read()?;
        let result = tc::enclave_verify_report(&report, &enclave);
        println!("report_verificaton result={}", result);
        Ok(result as usize)
    }

    pub(super) fn tpm_command_sync(&self, locked: u64) -> HyperCallResult<usize> {
        info!("+tpm_lock {} -> {}", TPM_LOCK.is_locked(), locked > 0);
        let result = tc::tpm_command_sync(locked);
        info!("-tpm_lock {} -> {}", TPM_LOCK.is_locked(), locked > 0);
        result
    }

    pub(super) fn activate_credential(&self) -> HyperCallResult<usize> {
        let guest_regs = self.cpu_data.vcpu.regs();
        let blob_ptr: GuestPtr<EncBlob> = guest_regs
            .rdi
            .as_guest_ptr_ns(&self.gpt, self.privilege_level());
        let enc_blob = blob_ptr.read()?;
        let enc_blob_size: usize = guest_regs.rsi as usize;
        let enc_secret_ptr: GuestPtr<EncSecret> = guest_regs
            .rdx
            .as_guest_ptr_ns(&self.gpt, self.privilege_level());
        let enc_secret = enc_secret_ptr.read()?;
        let enc_sec_size = guest_regs.rcx as usize;
        if enc_sec_size != size_of::<EncSecret>() || enc_blob_size != size_of::<EncBlob>() {
            error!(
                "HyperEnclave:activate_credential invalid parameter {}{}",
                enc_blob_size, enc_sec_size
            )
        }
        let mut key_ptr: GuestPtr<SM4Key> = guest_regs
            .r8
            .as_guest_ptr_ns(&self.gpt, self.privilege_level());
        let mut ret_len_ptr: GuestPtr<u64> = guest_regs
            .r9
            .as_guest_ptr_ns(&self.gpt, self.privilege_level());
        let mut sm4_key: SM4Key = Default::default();
        let result = tc::activate_credential(&enc_blob.0, &enc_secret.0, &mut sm4_key.0);
        key_ptr.write(sm4_key)?;
        ret_len_ptr.write(result as u64)?;
        Ok(0 as usize)
    }

    pub(super) fn enclave_add_version_array(
        &self,
        config_ptr: GuestPtr<HvEnclDesc>,
        va_paddr: u64,
    ) -> HyperCallResult<usize> {
        let now = Instant::now();
        debug!(
            "enclave_add_version_array, config_ptr: {:#x?}, va_paddr: {:#x?}",
            config_ptr, va_paddr
        );
        let enclave = ENCLAVE_MANAGER.find_enclave(config_ptr.as_guest_paddr()?)?;

        enclave.add_version_array(va_paddr as GuestPhysAddr)?;
        enclave.atomic_add_stats(EnclaveStatsId::AddVersionArray, now.elapsed());

        Ok(0)
    }

    pub(super) fn enclave_block(
        &self,
        page_desc_ptr: GuestPtr<HvEnclNewPageDesc>,
    ) -> HyperCallResult<usize> {
        let now = Instant::now();
        let page_desc = page_desc_ptr.read()?;
        debug!("enclave_block ({:#x?}): {:#x?}", page_desc_ptr, page_desc);
        let config_ptr = page_desc
            .config_address
            .as_guest_ptr_ns::<HvEnclDesc>(&self.gpt, self.privilege_level());
        let enclave = ENCLAVE_MANAGER.find_enclave(config_ptr.as_guest_paddr()?)?;

        enclave.block(&page_desc)?;
        enclave.atomic_add_stats(EnclaveStatsId::Block, now.elapsed());

        Ok(0)
    }

    pub(super) fn enclave_track(&self, config_ptr: GuestPtr<HvEnclDesc>) -> HyperCallResult<usize> {
        let now = Instant::now();
        let config = config_ptr.read()?;
        debug!("enclave_track({:#x?}): {:#x?}", config_ptr, config);
        let enclave = ENCLAVE_MANAGER.find_enclave(config_ptr.as_guest_paddr()?)?;
        enclave.track()?;
        enclave.atomic_add_stats(EnclaveStatsId::Track, now.elapsed());

        Ok(0)
    }

    pub(super) fn enclave_write_back(
        &self,
        page_desc_ptr: GuestPtr<HvEnclNewPageDesc>,
        va_slot_pa: u64,
    ) -> HyperCallResult<usize> {
        let now = Instant::now();
        let page_desc = page_desc_ptr.read()?;
        debug!(
            "enclave_write_back({:#x?}): {:#x?}",
            page_desc_ptr, page_desc
        );
        let config_ptr = page_desc
            .config_address
            .as_guest_ptr_ns::<HvEnclDesc>(&self.gpt, self.privilege_level());
        let time_get_config_ptr = now.elapsed();

        let enclave = ENCLAVE_MANAGER.find_enclave(config_ptr.as_guest_paddr()?)?;
        let time_find_enclave = now.elapsed();

        enclave.write_back_page_wrapper(&page_desc, &self.gpt, va_slot_pa as usize)?;
        enclave.atomic_add_stats(EnclaveStatsId::WriteBack, now.elapsed());
        enclave.atomic_add_stats(EnclaveStatsId::WriteBackGetConfigPtr, time_get_config_ptr);
        enclave.atomic_add_stats(
            EnclaveStatsId::WriteBackFindEnclave,
            time_find_enclave - time_get_config_ptr,
        );

        Ok(0)
    }

    pub(super) fn enclave_load_unblocked(
        &self,
        page_desc_ptr: GuestPtr<HvEnclNewPageDesc>,
        va_slot_pa: u64,
    ) -> HyperCallResult<usize> {
        let now = Instant::now();
        let page_desc = page_desc_ptr.read()?;
        debug!(
            "enclave_write_back({:#x?}): {:#x?}",
            page_desc_ptr, page_desc
        );
        let config_ptr = page_desc
            .config_address
            .as_guest_ptr_ns::<HvEnclDesc>(&self.gpt, self.privilege_level());
        let time_get_config_ptr = now.elapsed();

        let enclave = ENCLAVE_MANAGER.find_enclave(config_ptr.as_guest_paddr()?)?;
        let time_find_enclave = now.elapsed();
        enclave.load_unblocked(&page_desc, &self.gpt, va_slot_pa as usize)?;
        enclave.atomic_add_stats(EnclaveStatsId::LoadUnblocked, now.elapsed());
        enclave.atomic_add_stats(
            EnclaveStatsId::LoadUnblockedGetConfigPtr,
            time_get_config_ptr,
        );
        enclave.atomic_add_stats(
            EnclaveStatsId::LoadUnblockedFindEnclave,
            time_find_enclave - time_get_config_ptr,
        );

        Ok(0)
    }

    pub(super) fn reclaim_encl_pages(
        &self,
        page_desc_ptr: GuestPtr<HvReclaimerPagesDesc>,
    ) -> HyperCallResult<usize> {
        let gvaddr = page_desc_ptr.guest_vaddr();
        let (gpaddr, _, _) = self.gpt.query(gvaddr)?;

        let pages: &mut [HvReclaimerPageDesc] = unsafe {
            core::slice::from_raw_parts_mut(
                addr::phys_to_virt(gpaddr) as *mut HvReclaimerPageDesc,
                NR_RECLAIM_EPC_PAGES,
            )
        };

        debug!("pages: {:#x?}", pages);
        reclaim::reclaim_pages(pages, &self.gpt)?;
        debug!("pages: {:#x?}", pages);

        Ok(0)
    }

    pub(super) fn enclave_remove_pages_at_destroy(
        &self,
        remove_desc_ptr: GuestPtr<HvEnclRemovePagesAtDestroyDesc>,
    ) -> HyperCallResult<usize> {
        let now = Instant::now();
        let remove_desc = remove_desc_ptr.read()?;

        let config_ptr = remove_desc
            .config_address
            .as_guest_ptr_ns::<HvEnclDesc>(&self.gpt, self.privilege_level());
        let enclave = ENCLAVE_MANAGER.find_enclave(config_ptr.as_guest_paddr()?)?;

        let page_array_ptr = remove_desc
            .page_array_addr
            .as_guest_ptr_ns::<HvEnclRemovePagesAtDestroyPageArray>(
                &self.gpt,
                self.privilege_level(),
            );
        let page_array = page_array_ptr.as_ref()?;

        let mut res_array_ptr = remove_desc
            .res_array_addr
            .as_guest_ptr_ns::<HvEnclRemovePagesAtDestroyResArray>(
                &self.gpt,
                self.privilege_level(),
            );
        let res_array = res_array_ptr.as_mut()?;

        enclave.remove_pages_at_destroy(remove_desc.batch_size as usize, page_array, res_array);
        enclave.atomic_add_stats(EnclaveStatsId::RemovePagesAtDestroy, now.elapsed());

        Ok(0)
    }

    pub(super) fn enclave_reset_stats(
        &self,
        config_ptr: GuestPtr<HvEnclDesc>,
    ) -> HyperCallResult<usize> {
        let config = config_ptr.read()?;
        debug!("enclave_reset_stats({:#x?}): {:#x?}", config_ptr, config);
        let enclave = ENCLAVE_MANAGER.find_enclave(config_ptr.as_guest_paddr()?)?;
        enclave.reset_stats();
        Ok(0)
    }

    pub(super) fn enclave_augment_page(
        &self,
        page_desc_ptr: GuestPtr<HvEnclAugPageDesc>,
    ) -> HyperCallResult<usize> {
        let now = Instant::now();
        let page_desc = page_desc_ptr.read()?;
        let config_ptr = page_desc
            .config_address
            .as_guest_ptr_ns::<HvEnclDesc>(&self.gpt, self.privilege_level());
        let enclave = ENCLAVE_MANAGER.find_enclave(config_ptr.as_guest_paddr()?)?;
        enclave.augment_page(
            page_desc.enclave_lin_addr as usize,
            page_desc.enclave_phys_addr as usize,
            page_desc.sec_info as usize,
        )?;
        enclave.atomic_add_stats(EnclaveStatsId::AugmentPage, now.elapsed());

        Ok(0)
    }

    pub(super) fn enclave_modify_page_type(
        &self,
        page_desc_ptr: GuestPtr<HvEnclModtPageDesc>,
    ) -> HyperCallResult<usize> {
        let now = Instant::now();
        let page_desc = page_desc_ptr.read()?;
        let config_ptr = page_desc
            .config_address
            .as_guest_ptr_ns::<HvEnclDesc>(&self.gpt, self.privilege_level());
        let enclave = ENCLAVE_MANAGER.find_enclave(config_ptr.as_guest_paddr()?)?;
        enclave.modify_page_type(
            page_desc.enclave_lin_addr as usize,
            page_desc.sec_info as usize,
        )?;
        enclave.atomic_add_stats(EnclaveStatsId::ModifyPageType, now.elapsed());

        Ok(0)
    }

    pub(super) fn enclave_restrict_page_perm(
        &self,
        page_desc_ptr: GuestPtr<HvEnclRestrictPageDesc>,
    ) -> HyperCallResult<usize> {
        let now = Instant::now();
        let page_desc = page_desc_ptr.read()?;
        let config_ptr = page_desc
            .config_address
            .as_guest_ptr_ns::<HvEnclDesc>(&self.gpt, self.privilege_level());
        let enclave = ENCLAVE_MANAGER.find_enclave(config_ptr.as_guest_paddr()?)?;
        enclave.restrict_page_perm(
            page_desc.enclave_lin_addr as usize,
            page_desc.sec_info as usize,
        )?;

        enclave.atomic_add_stats(EnclaveStatsId::RestrictPagePerm, now.elapsed());

        Ok(0)
    }

    pub(super) fn enclave_remove_page_at_runtime(
        &self,
        page_desc_ptr: GuestPtr<HvEnclRemovePageAtRuntimeDesc>,
    ) -> HyperCallResult<usize> {
        let now = Instant::now();
        let page_desc = page_desc_ptr.read()?;
        let config_ptr = page_desc
            .config_address
            .as_guest_ptr_ns::<HvEnclDesc>(&self.gpt, self.privilege_level());
        let enclave = ENCLAVE_MANAGER.find_enclave(config_ptr.as_guest_paddr()?)?;
        enclave.remove_page_at_runtime(page_desc.enclave_lin_addr as usize)?;
        enclave.atomic_add_stats(EnclaveStatsId::RemovePageAtRuntime, now.elapsed());

        Ok(0)
    }

    pub(super) fn enclave_shared_memory_add(
        &self,
        mem_add_desc_ptr: GuestPtr<HvSharedMemoryDesc>,
    ) -> HyperCallResult<usize> {
        let now = Instant::now();
        let mem_desc = mem_add_desc_ptr.read()?;
        let config_ptr = mem_desc
            .config_addr
            .as_guest_ptr_ns::<HvEnclDesc>(&self.gpt, self.privilege_level());
        let start_addr = mem_desc.start_addr as GuestVirtAddr;
        let end_addr = mem_desc.end_addr as GuestVirtAddr;
        let enclave = ENCLAVE_MANAGER.find_enclave(config_ptr.as_guest_paddr()?)?;
        enclave.add_shared_memory(&(start_addr..end_addr), &self.gpt)?;
        enclave.atomic_add_stats(EnclaveStatsId::AddSharedMemory, now.elapsed());
        Ok(0)
    }

    pub(super) fn enclave_shared_memory_remove(
        &self,
        mem_remove_desc_ptr: GuestPtr<HvSharedMemoryDesc>,
    ) -> HyperCallResult<usize> {
        let now = Instant::now();
        let mem_desc = mem_remove_desc_ptr.read()?;
        let config_ptr = mem_desc
            .config_addr
            .as_guest_ptr_ns::<HvEnclDesc>(&self.gpt, self.privilege_level());
        let start_addr = mem_desc.start_addr as GuestVirtAddr;
        let end_addr = mem_desc.end_addr as GuestVirtAddr;
        let enclave = ENCLAVE_MANAGER.find_enclave(config_ptr.as_guest_paddr()?)?;
        enclave.remove_shared_memory(&(start_addr..end_addr))?;
        enclave.atomic_add_stats(EnclaveStatsId::RemoveSharedMemory, now.elapsed());
        Ok(0)
    }

    pub(super) fn enclave_shared_memory_invalid_start(
        &self,
        mem_invalid_desc_ptr: GuestPtr<HvSharedMemoryDesc>,
    ) -> HyperCallResult<usize> {
        let mem_desc = mem_invalid_desc_ptr.read()?;
        let config_ptr = mem_desc
            .config_addr
            .as_guest_ptr_ns::<HvEnclDesc>(&self.gpt, self.privilege_level());
        let start_addr = mem_desc.start_addr as GuestVirtAddr;
        let end_addr = mem_desc.end_addr as GuestVirtAddr;
        let enclave = ENCLAVE_MANAGER.find_enclave(config_ptr.as_guest_paddr()?)?;
        let mem_ranges = enclave
            .shmem()
            .read()
            .get_overlap(&(start_addr..end_addr))?;
        enclave.sync_shared_memory(&SharedMemSyncType::InvalidStart(mem_ranges), &self.gpt)?;
        Ok(0)
    }

    pub(super) fn enclave_shared_memory_invalid_end(
        &self,
        config_ptr: GuestPtr<HvEnclDesc>,
    ) -> HyperCallResult<usize> {
        let enclave = ENCLAVE_MANAGER.find_enclave(config_ptr.as_guest_paddr()?)?;
        enclave.sync_shared_memory(&SharedMemSyncType::InvalidEnd, &self.gpt)?;
        Ok(0)
    }

    pub(super) fn init_cmrm(&self, size: u64) -> HyperCallResult<usize> {
        ConvMemManager::get().initialize_cmrm(size as _)
    }

    pub(super) fn set_init_cmrm_done(&self) -> HyperCallResult<usize> {
        ConvMemManager::get().set_init_cmrm_done()
    }
}
