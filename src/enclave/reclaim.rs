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

#[cfg(feature = "sme")]
use crate::arch::vmm::{EncHW, HmacSWEncHW};
use crate::arch::GuestPageTableImmut;
use crate::enclave::sgx::SgxSecInfo;
use crate::enclave::structs::{HvEnclDesc, HvReclaimerPageDesc};
use crate::enclave::ENCLAVE_MANAGER;
use crate::error::HvResult;
use crate::hypercall::error::HyperCallResult;
use crate::hypercall::PrivilegeLevel;
use crate::memory::addr::{is_aligned, phys_to_virt, GuestPhysAddr};
use crate::memory::gaccess::AsGuestPtr;
use crate::memory::{GenericPTE, GenericPageTableMut, GuestVirtAddr, PAGE_SIZE};
use crate::HvHeader;

use alloc::boxed::Box;
use core::convert::TryInto;
use core::mem::{size_of, transmute};
use core::slice;
use core::sync::atomic::{AtomicU64, Ordering};
use yogcrypt::sm2::U64x4;
use yogcrypt::sm3::sm3_enc;
use yogcrypt::sm4::*;

use super::epcm::EpcmManager;

pub const RECLAIM_NONCE_LEN: usize = 8;
pub const RECLAIM_KEY_LEN: usize = 16;

pub const RECLAIM_CRYPTO_ALG_SHIFT: u64 = 2;
pub const RECLAIM_CRYPTO_ALG_MASK: u64 = 0b1100;

lazy_static! {
    pub static ref RECLAIM_KEY: [u8; RECLAIM_KEY_LEN] = {
        let mut key = [0_u8; RECLAIM_KEY_LEN];
        get_random(&mut key);
        key
    };
    pub static ref NONCE_SEED: u64 = {
        let mut seed = [0_u8; RECLAIM_NONCE_LEN];
        get_random(&mut seed);
        unsafe { transmute::<[u8; RECLAIM_NONCE_LEN], u64>(seed) }
    };
    pub static ref CRYPTO_ALG: CryptoAlgType = get_crypto_alg();
}

static NONCE_VAL: AtomicU64 = AtomicU64::new(0);

pub fn get_crypto_alg() -> CryptoAlgType {
    let header = HvHeader::get();
    let crypto_alg_val =
        (header.feature_mask.bits() as u64 & RECLAIM_CRYPTO_ALG_MASK) >> RECLAIM_CRYPTO_ALG_SHIFT;
    let mut ret = CryptoAlgType::EncSWHmacSW;

    if cfg!(feature = "sme") {
        ret = match crypto_alg_val {
            0b00 => CryptoAlgType::HmacSWEncHW,
            0b01 => CryptoAlgType::EncSWHmacSW,
            0b10 => CryptoAlgType::EncHW,
            _ => {
                warn!("invalid reclaim crypto algorithm configuration, use default HmacSWEncHW");
                CryptoAlgType::HmacSWEncHW
            }
        };
    }

    println!("reclaim crypto algorithm: {:x?}", ret);

    ret
}

pub fn init() {
    lazy_static::initialize(&CRYPTO_ALG);
    NONCE_VAL.store(*NONCE_SEED, Ordering::Release);
}

pub fn get_random(buf: &mut [u8]) {
    let len = buf.len();
    assert!(len <= 256);

    let key = U64x4::random();
    let key_bytes = unsafe { slice::from_raw_parts(&key as *const U64x4 as *const u8, len) };

    buf.copy_from_slice(key_bytes);
}

pub fn reclaim_pages(
    pages: &mut [HvReclaimerPageDesc],
    gpt: &GuestPageTableImmut,
) -> HyperCallResult {
    for page in pages {
        if page.encl_addr == 0 {
            break;
        }

        let gvaddr = page.gva as usize;
        if !is_aligned(gvaddr) {
            return hypercall_hv_err_result!(
                EINVAL,
                format!("reclaim_pages(): gvaddr {:#x} is not aligned", gvaddr)
            );
        }

        let gpaddr = page.gpa as usize;
        let encl_ptr = page
            .encl_addr
            .as_guest_ptr_ns::<HvEnclDesc>(&gpt, PrivilegeLevel::Supervisor);
        let enclave = ENCLAVE_MANAGER.find_enclave(encl_ptr.as_guest_paddr()?)?;
        if !enclave.elrange.contains(&gvaddr) {
            return hypercall_hv_err_result!(
                EINVAL,
                format!(
                    "reclaim_pages(): gva {:#x} is out of ELRANGE {:#x?}",
                    gvaddr, enclave.elrange
                )
            );
        }

        let is_young = {
            let mut gpt = enclave.gpt.write();
            let pte = gpt.get_pte_mut(gvaddr)?;
            if pte.is_young() {
                pte.set_old();
                true
            } else {
                false
            }
        };
        debug!("{:#x?}, {:#x?} is_young: {}", gvaddr, gpaddr, is_young);
        if !is_young {
            page.valid = 1;
        }
    }

    Ok(())
}

pub type NonceValue = u64;
pub type HmacValue = [u32; 8];

#[repr(C)]
pub struct Nonce(NonceValue);

impl Nonce {
    pub fn new() -> Self {
        let nonce = NONCE_VAL.fetch_add(1, Ordering::Release);
        Self(nonce)
    }

    pub fn get_val(&self) -> NonceValue {
        self.0
    }
}

#[repr(C)]
#[derive(Debug)]
pub struct WriteBackInfo {
    /// Nonce used to guarantee the freshness.
    nonce: NonceValue,
    /// Enclave identifier.
    enclave_id: usize,
    /// SecInfo of the write back page.
    sec_info: SgxSecInfo,
    /// Guest linear address of the write back page.
    vaddr: GuestVirtAddr,
    /// Page contents of the write back page.
    contents: [u8; PAGE_SIZE],
}

impl WriteBackInfo {
    pub fn new(
        nonce: NonceValue,
        enclave_id: usize,
        sec_info: SgxSecInfo,
        vaddr: GuestVirtAddr,
        contents: [u8; PAGE_SIZE],
    ) -> Self {
        Self {
            nonce,
            enclave_id,
            sec_info,
            vaddr,
            contents,
        }
    }
}

#[repr(C)]
#[derive(Debug)]
pub struct VaSlot(u64);

impl VaSlot {
    pub fn from_paddr_mut<'a>(paddr: usize) -> HvResult<&'a mut Self> {
        if !EpcmManager::is_valid_va_slot(paddr) {
            return hv_result_err!(
                EINVAL,
                format!("VaSlot::from_paddr_mut(): invalid paddr {:#x?}", paddr)
            );
        }

        let ptr = phys_to_virt(paddr) as *mut _;
        unsafe { Ok(&mut *ptr) }
    }

    pub fn is_empty(&self) -> HvResult {
        if self.0 != 0 {
            return hv_result_err!(
                EINVAL,
                format!("VaSlot::is_empty(): va slot {:#x?} is already in use", self)
            );
        }
        Ok(())
    }

    pub fn set(&mut self, val: NonceValue) {
        self.0 = val;
    }

    pub fn get(&self) -> NonceValue {
        self.0
    }

    pub fn clear(&mut self) {
        self.0 = 0;
    }
}

#[derive(Debug)]
pub enum CryptoAlgType {
    HmacSWEncHW,
    EncSWHmacSW,
    EncHW,
}

pub trait CryptoAlg {
    fn encrypt_and_hmac_page(
        &mut self,
        gpaddr_src: GuestPhysAddr,
        gpaddr_dst: GuestPhysAddr,
    ) -> HvResult<HmacValue>;

    fn decrypt_and_hmac_page(
        &mut self,
        gpaddr_src: GuestPhysAddr,
        gpaddr_dst: GuestPhysAddr,
        mac: &HmacValue,
    ) -> HvResult;
}

pub struct EncSWHmacSW {
    nonce: NonceValue,
    enclave_id: usize,
    sec_info: SgxSecInfo,
    vaddr: GuestVirtAddr,
}

impl EncSWHmacSW {
    fn new(
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

impl CryptoAlg for EncSWHmacSW {
    fn encrypt_and_hmac_page(
        &mut self,
        gpaddr_src: GuestPhysAddr,
        gpaddr_dst: GuestPhysAddr,
    ) -> HvResult<HmacValue> {
        let mut left_len = PAGE_SIZE;
        let mut offset = 0_usize;
        let src =
            unsafe { slice::from_raw_parts(phys_to_virt(gpaddr_src) as *const u8, PAGE_SIZE) };
        let mut res = [0_u8; PAGE_SIZE];
        while left_len > 0 {
            let block: [u8; BLOCK_SIZE] = src[offset..offset + BLOCK_SIZE].try_into().unwrap();
            res[offset..offset + BLOCK_SIZE].copy_from_slice(&sm4_enc(&RECLAIM_KEY, &block));
            left_len -= BLOCK_SIZE;
            offset += BLOCK_SIZE;
        }

        let wb_info = WriteBackInfo::new(
            self.nonce,
            self.enclave_id,
            self.sec_info,
            self.vaddr,
            res.try_into().unwrap(),
        );
        let info_bytes = unsafe {
            slice::from_raw_parts(
                &wb_info as *const WriteBackInfo as *const u8,
                size_of::<WriteBackInfo>(),
            )
        };
        let hash = sm3_enc(info_bytes);

        unsafe {
            core::ptr::copy_nonoverlapping(
                res.as_ptr(),
                phys_to_virt(gpaddr_dst) as *mut u8,
                PAGE_SIZE,
            );
        }

        Ok(hash)
    }

    fn decrypt_and_hmac_page(
        &mut self,
        gpaddr_src: GuestPhysAddr,
        gpaddr_dst: GuestPhysAddr,
        mac: &HmacValue,
    ) -> HvResult {
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

        if *mac != hash {
            return hv_result_err!(
                EINVAL,
                format!("EncSWHmacSW::decrypt_and_hmac_page(): invalid Hmac value")
            );
        }

        let mut left_len = PAGE_SIZE;
        let mut offset = 0_usize;
        let mut res = [0_u8; PAGE_SIZE];
        while left_len > 0 {
            let block: [u8; BLOCK_SIZE] = src[offset..offset + BLOCK_SIZE].try_into().unwrap();
            res[offset..offset + BLOCK_SIZE].copy_from_slice(&sm4_dec(&RECLAIM_KEY, &block));
            left_len -= BLOCK_SIZE;
            offset += BLOCK_SIZE;
        }

        unsafe {
            core::ptr::copy_nonoverlapping(
                res.as_ptr(),
                phys_to_virt(gpaddr_dst) as *mut u8,
                PAGE_SIZE,
            );
        }

        Ok(())
    }
}

pub fn create_alg_instance(
    nonce: &NonceValue,
    enclave_id: usize,
    sec_info: &SgxSecInfo,
    vaddr: GuestVirtAddr,
) -> Box<dyn CryptoAlg> {
    #[cfg(feature = "sme")]
    match *CRYPTO_ALG {
        CryptoAlgType::EncSWHmacSW => {
            return Box::new(EncSWHmacSW::new(&nonce, enclave_id, &sec_info, vaddr))
        }
        CryptoAlgType::HmacSWEncHW => {
            return Box::new(HmacSWEncHW::new(&nonce, enclave_id, &sec_info, vaddr))
        }
        CryptoAlgType::EncHW => return Box::new(EncHW {}),
    };
    #[cfg(not(feature = "sme"))]
    return Box::new(EncSWHmacSW::new(&nonce, enclave_id, &sec_info, vaddr));
}
