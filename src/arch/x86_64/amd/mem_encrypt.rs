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

use crate::arch::cpu::clflush_cache_range;
use crate::enclave::sgx::SgxSecInfo;
use crate::error::HvResult;
use crate::memory::addr::{phys_to_virt, GuestPhysAddr};
use crate::memory::{GuestVirtAddr, PAGE_SIZE};
use crate::reclaim::{CryptoAlg, HmacValue, NonceValue, WriteBackInfo};

use core::convert::TryInto;
use core::mem::size_of;
use core::slice;
use yogcrypt::sm3::sm3_enc;

pub struct HmacSWEncHW {
    nonce: NonceValue,
    enclave_id: usize,
    sec_info: SgxSecInfo,
    vaddr: GuestVirtAddr,
}

impl HmacSWEncHW {
    #[allow(dead_code)]
    pub fn new(
        nonce: &NonceValue,
        enclave_id: usize,
        sec_info: &SgxSecInfo,
        vaddr: GuestVirtAddr,
    ) -> Self {
        Self {
            nonce: *nonce,
            enclave_id,
            sec_info: *sec_info,
            vaddr,
        }
    }
}

impl CryptoAlg for HmacSWEncHW {
    fn encrypt_and_hmac_page(
        &mut self,
        gpaddr_src: GuestPhysAddr,
        gpaddr_dst: GuestPhysAddr,
    ) -> HvResult<HmacValue> {
        let src =
            unsafe { slice::from_raw_parts(phys_to_virt(gpaddr_src) as *const u8, PAGE_SIZE) };
        let wb_info = WriteBackInfo::new(
            self.nonce,
            self.enclave_id,
            self.sec_info,
            self.vaddr,
            src.try_into().unwrap(),
        );
        let info_bytes = unsafe {
            slice::from_raw_parts(
                &wb_info as *const WriteBackInfo as *const u8,
                size_of::<WriteBackInfo>(),
            )
        };
        let hash = sm3_enc(info_bytes);

        // Flush cacheline of the low addr from linux vm
        clflush_cache_range(phys_to_virt(gpaddr_dst), PAGE_SIZE);
        // Copy src page data to the guest RAM page with c-bit set
        unsafe {
            core::ptr::copy_nonoverlapping(
                phys_to_virt(gpaddr_src) as *const u8,
                gpaddr_dst as *mut u8,
                PAGE_SIZE,
            );
        }
        // Flush cacheline of the high addr with c-bit set, then linux vm will
        // get ciphertext from the low addr without c-bit set
        clflush_cache_range(gpaddr_dst, PAGE_SIZE);

        Ok(hash)
    }

    fn decrypt_and_hmac_page(
        &mut self,
        gpaddr_src: GuestPhysAddr,
        gpaddr_dst: GuestPhysAddr,
        mac: &HmacValue,
    ) -> HvResult {
        // Copy the guest RAM page with c-bit set to dst page, and get plaintext
        unsafe {
            core::ptr::copy_nonoverlapping(
                gpaddr_src as *const u8,
                phys_to_virt(gpaddr_dst) as *mut u8,
                PAGE_SIZE,
            );
        }

        let dst =
            unsafe { slice::from_raw_parts(phys_to_virt(gpaddr_dst) as *const u8, PAGE_SIZE) };
        let wb_info = WriteBackInfo::new(
            self.nonce,
            self.enclave_id,
            self.sec_info,
            self.vaddr,
            dst.try_into().unwrap(),
        );
        let info_bytes = unsafe {
            slice::from_raw_parts(
                &wb_info as *const WriteBackInfo as *const u8,
                size_of::<WriteBackInfo>(),
            )
        };
        let hash = sm3_enc(info_bytes);

        if *mac != hash {
            return hv_result_err!(
                EINVAL,
                format!("HmacSWEncHW::decrypt_and_hmac_page(): invalid Hmac value")
            );
        }

        Ok(())
    }
}

#[derive(Debug, Default)]
pub struct EncHW {}

impl CryptoAlg for EncHW {
    fn encrypt_and_hmac_page(
        &mut self,
        gpaddr_src: GuestPhysAddr,
        gpaddr_dst: GuestPhysAddr,
    ) -> HvResult<HmacValue> {
        // Flush cacheline of the low addr from linux vm
        clflush_cache_range(phys_to_virt(gpaddr_dst), PAGE_SIZE);
        // Copy src page data to the guest RAM page with c-bit set
        unsafe {
            core::ptr::copy_nonoverlapping(
                phys_to_virt(gpaddr_src) as *const u8,
                gpaddr_dst as *mut u8,
                PAGE_SIZE,
            );
        }
        // Flush cacheline of the high addr with c-bit set, then linux vm will
        // get ciphertext from the low addr without c-bit set
        clflush_cache_range(gpaddr_dst, PAGE_SIZE);

        Ok(Default::default())
    }

    fn decrypt_and_hmac_page(
        &mut self,
        gpaddr_src: GuestPhysAddr,
        gpaddr_dst: GuestPhysAddr,
        _mac: &HmacValue,
    ) -> HvResult {
        // Copy the guest RAM page with c-bit set to dst page, and get plaintext
        unsafe {
            core::ptr::copy_nonoverlapping(
                gpaddr_src as *const u8,
                phys_to_virt(gpaddr_dst) as *mut u8,
                PAGE_SIZE,
            );
        }

        Ok(())
    }
}
