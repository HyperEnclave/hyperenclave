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

extern crate cstr_core;
extern crate cty;
extern crate yogcrypt;
use alloc::vec::Vec;

use crate::enclave::report::{
    bytes_to_u64x4, convert_sm3_hash_bytes_order, reverse_byte_array_copy, u64x4_to_bytes,
    DerivationData, SgxKey128Bit, SgxKeyRequest, SgxQuote, SgxReport, SgxReportData, SgxTargetInfo,
    HE_HV_ATT_KEY_LEN, SGX_ENCLAVE_KEY_SIZE, SGX_HASH_SIZE, SGX_QUOTE_SIZE,
};

use super::error::HyperCallResult;
use crate::enclave::Enclave;
use crate::header::HvHeader;
use crate::memory::addr::*;
use core::convert::TryInto;
use core::{mem::size_of, slice};
use cstr_core::CStr;
use cty::{c_char, uint32_t, uint64_t, uint8_t, uintptr_t};
use spin::mutex::SpinMutex;
use yogcrypt::sm2::*;
use yogcrypt::sm3::sm3_enc;

extern "C" {
    fn tpm_detect(tpm_type: uint32_t, mmio_va: uint64_t) -> bool;
    fn he_get_secret() -> bool;
    //fn he_get_enclave_secret(ptr: *mut uintptr_t) -> uint32_t;
    fn he_get_ak_seed(ptr: *mut uintptr_t) -> uint32_t;
    fn he_extend_ak_pub(buf: *const uint8_t, len: uint32_t) -> uint32_t;
    //fn he_extend_image() -> c_int;
    //fn he_get_tpm_signing_pub() -> uintptr_t;
    fn he_get_quote(user_data: *const uint8_t, data_len: uint32_t, ptr: *mut uint8_t) -> uint32_t;
    fn he_activate_credential(
        enc_blob: *const uint8_t,
        enc_len: uint32_t,
        enc_secret: *const uint8_t,
        enc_sec_size: uint32_t,
        secret: *mut uint8_t,
    ) -> uint32_t;
    fn he_sign_csr(p10: *const uint8_t, p10_len: uint32_t, csr: *mut uint8_t) -> uint32_t;
    fn he_get_tpm_ak_pub(ak_buf: *mut uint8_t) -> uint32_t;
    fn he_get_pcr_list(pcr_buf: *mut uint8_t) -> uint32_t;
    fn he_write_tpm_ak_cert(cert_buf: *const uint8_t, cert_len: uint32_t) -> uint32_t;
    fn he_read_cert(cert_buf: *mut uint8_t, buf_len: uint32_t, read: uint32_t) -> uint32_t;
    fn he_get_ak_pub_area(pub_area: *mut uint8_t) -> uint32_t;
}

pub fn tc_init() -> bool {
    unsafe {
        //he_gen_ak_ex();
        if !tpm_detect(
            HvHeader::get().tpm_type,
            HvHeader::get().tpm_mmio_pa as uint64_t,
        ) {
            println!("HyperEnclave: failed to detect the tpm chip");
            return false;
        }
        //ask the hyperenclave and TPM to generate or recover the root secret
        if !he_get_secret() {
            println!("HyperEnclave: failed to recover secret");
            return false;
        }
        if !he_extend_ak() {
            println!("HyperEnclave: failed to extend hv ak pub");
            return false;
        }
        //println!("sizeof(sgxquote)={}",size_of::<SgxQuote>());
        println!("HyperEnclave: root of trust initialized!");
    };
    true
}

pub static TPM_LOCK: SpinMutex<()> = SpinMutex::new(());

pub fn tpm_command_sync(locked: u64) -> HyperCallResult<usize> {
    if locked > 0 {
        core::mem::forget(TPM_LOCK.lock());
    } else {
        if TPM_LOCK.is_locked() {
            unsafe {
                TPM_LOCK.force_unlock();
            }
        }
    }
    Ok(0)
}

fn gen_att_key(sk: &mut SecKey, pk: &mut PubKey) -> bool {
    let seed;
    unsafe {
        let mut secret_ptr: uintptr_t = 0;
        let secret_len = he_get_ak_seed(&mut secret_ptr) as usize;
        if secret_len == 0 {
            return false;
        }
        seed = slice::from_raw_parts(secret_ptr as *const u64, secret_len / 8);
    };
    let hv_sec_key: SecKey = U64x4::new(seed[0], seed[1], seed[2], seed[3]);
    let hv_pub_key: PubKey = get_pub_key(hv_sec_key);
    *sk = hv_sec_key;
    *pk = hv_pub_key;
    true
}

pub fn create_report(
    target_info: &SgxTargetInfo,
    report_data: &SgxReportData,
    report: &mut SgxReport,
    enclave: &Enclave,
) -> u32 {
    let mr_enclave = enclave.measurement();
    let mr_signer = enclave.mr_signer();
    let (flags, xfrm) = enclave.attributes();
    let (isv_prod_id, isv_svn) = enclave.isv();
    report.set_basics(isv_prod_id, isv_svn, flags, xfrm);
    report.set_mr_enclave_signer(mr_enclave.as_slice(), mr_signer);
    report.set_report_data(report_data);
    report.set_key_id();
    let mut report_key: SgxKey128Bit = [0; SGX_ENCLAVE_KEY_SIZE as usize];
    let mut dd: DerivationData = Default::default();
    if !dd.init_with_target_info(target_info, report) {
        println!("HyperEnclave:DerivationData.init_with_target_info failed");
        return 0;
    }
    derive_enclave_key(&dd, &mut report_key);
    report.mac(&report_key);
    // report.print();
    info!(
        "create_report target_info = {:#x?} {:#x?}",
        target_info.attributes.flags, target_info.attributes.xfrm
    );
    info!("target_info mr_enclave {:#x?}", &target_info.mr_enclave);
    size_of::<SgxReport>() as u32
}

pub fn create_quote(report: &SgxReport, quote: &mut SgxQuote, quote_buffer_size: u32) -> u32 {
    let mut quote_len: u32;
    if (quote_buffer_size as usize) < size_of::<SgxQuote>() {
        println!("quote buffer is not big enough!");
        return 0;
    }
    if !qe_verify_report(report) {
        println!("qe_verify_report failed");
        return 0;
    }
    quote_len = he_create_enclave_quote(report, quote);
    if quote_len == 0 {
        println!("he_create_enclave_quote failed!");
        return 0;
    }
    let pub_len = he_fill_quote_ak_pub(quote);
    if pub_len == 0 {
        println!("he_create_enclave_quote failed!");
        return 0;
    }
    quote_len += pub_len;
    unsafe {
        let report_data_hash = sm3_enc(report.get_report_data());
        let mut converted_hash: [u8; SGX_HASH_SIZE as usize] = [0; SGX_HASH_SIZE as usize];
        let report_hash_slice = slice::from_raw_parts(
            report_data_hash.as_ptr() as *const u8,
            report_data_hash.len() * 4,
        );
        convert_sm3_hash_bytes_order(&mut converted_hash[..], report_hash_slice);
        let _lock = TPM_LOCK.lock();
        let tpm_quote_len = he_get_quote(
            converted_hash.as_ptr(),
            converted_hash.len() as u32,
            quote.get_hv_quote_mut_ptr(),
        );
        if tpm_quote_len == 0 {
            println!("HyperEnclave: failed to get platform quote");
            return 0;
        }
        let cert_len = he_read_cert(
            quote.certificate.as_mut_ptr(),
            quote.certificate.len() as u32,
            1,
        );
        if cert_len == 0 {
            println!("HyperEnclave: no platform cert");
        }
        quote_len = SGX_QUOTE_SIZE + tpm_quote_len + quote_len + cert_len;
    }
    quote.sig_len = quote_len - SGX_QUOTE_SIZE;
    //quote.print_mem_layout();
    println!("quote len ={} sig_len = {}", quote_len, quote.sig_len);
    quote_len
}

pub fn he_create_enclave_quote(report: &SgxReport, quote: &mut SgxQuote) -> u32 {
    quote.report_body = report.body;
    // quote.report_body.print();
    let data_to_sign = quote.get_data_to_sign();
    let mut hv_sec_key = get_sec_key();
    let mut hv_pub_key = get_pub_key(hv_sec_key);
    if !gen_att_key(&mut hv_sec_key, &mut hv_pub_key) {
        return 0;
    }
    let sig = sm2_gen_sign(data_to_sign, hv_sec_key, hv_pub_key, true);
    quote.set_encl_quote(&sig)
}

pub fn create_key(key_request: &SgxKeyRequest, enclave: &Enclave, key: &mut SgxKey128Bit) -> u32 {
    let mut dd: DerivationData = Default::default();
    let mr_enclave = enclave.measurement();
    let mr_signer = enclave.mr_signer();
    let (flags, xfrm) = enclave.attributes();
    let (isv_prod_id, _isv_svn) = enclave.isv();
    if !dd.init_with_key_request(
        key_request,
        mr_enclave.as_slice(),
        mr_signer,
        isv_prod_id,
        flags,
        xfrm,
    ) {
        println!("HyperEnclave:DerivationData.init_with_key_request failed");
        return 0;
    }
    derive_enclave_key(&dd, key)
}

pub fn derive_enclave_key(dd: &DerivationData, key: &mut SgxKey128Bit) -> u32 {
    unsafe {
        let dd_bytes = slice::from_raw_parts(
            dd as *const DerivationData as *const u8,
            size_of::<DerivationData>(),
        );
        let hash = sm3_enc(dd_bytes);
        let hash_bytes =
            slice::from_raw_parts(hash.as_ptr() as *const u8, size_of::<SgxKey128Bit>());
        key.copy_from_slice(hash_bytes);
    }
    key.len() as u32
}

pub fn enclave_verify_report(report: &SgxReport, enclave: &Enclave) -> bool {
    let mut dd: DerivationData = Default::default();
    let (flags, xfrm) = enclave.attributes();
    let mr_enclave = enclave.measurement();
    let (isv_prod_id, _isv_svn) = enclave.isv();
    let mut kr: SgxKeyRequest = Default::default();
    kr.key_id.copy_from_slice(report.get_key_id());
    if !dd.init_with_key_request(
        &kr,
        mr_enclave.as_slice(),
        enclave.mr_signer(),
        isv_prod_id,
        flags,
        xfrm,
    ) {
        println!("HyperEnclave: DerivationData.init_with_key_request failed");
        return false;
    }
    verify_report(report, &dd)
}

fn verify_report(report: &SgxReport, dd: &DerivationData) -> bool {
    let mut report_key: SgxKey128Bit = [0; SGX_ENCLAVE_KEY_SIZE as usize];
    derive_enclave_key(dd, &mut report_key);
    let mut report_replica = *report;
    report_replica.mac(&report_key);
    report_replica.mac_equal(&report.mac)
}

pub fn qe_verify_report(report: &SgxReport) -> bool {
    let qe: SgxTargetInfo = Default::default();
    let mut dd: DerivationData = Default::default();
    let mut kr: SgxKeyRequest = Default::default();
    debug!("{:?}", qe);
    debug!("{:?}", dd);
    debug!("{:?}", kr);
    kr.key_id.copy_from_slice(report.get_key_id());
    let mr_signer: [u8; SGX_HASH_SIZE as usize] = [0; SGX_HASH_SIZE as usize];
    let (flags, xfrm) = qe.get_attributes();
    if !dd.init_with_key_request(&kr, qe.get_mr_enclave(), &mr_signer, 0, flags, xfrm) {
        //shoud be changed to flags, xfrm
        println!("HyperEnclave: DerivationData.init_with_key_request failed");
        return false;
    }
    verify_report(report, &dd)
}

fn he_fill_quote_ak_pub(quote: &mut SgxQuote) -> u32 {
    let mut hv_sec_key = get_sec_key();
    let mut hv_pub_key = get_pub_key(hv_sec_key);
    if !gen_att_key(&mut hv_sec_key, &mut hv_pub_key) {
        return 0;
    }
    quote.set_hv_att_pub(&hv_pub_key)
}

fn copy_hv_pub_ak_buf(buf: &mut [u8]) -> usize {
    let mut hv_sec_key = get_sec_key();
    let mut hv_pub_key = get_pub_key(hv_sec_key);
    if !gen_att_key(&mut hv_sec_key, &mut hv_pub_key) {
        return 0;
    }
    let mut start_index: usize = 0;
    let x_slice;
    unsafe {
        //convert x coordinate from little endian to big endian
        x_slice = slice::from_raw_parts(
            hv_pub_key.x.num.value.as_ptr() as *const u8,
            size_of::<PubKey>() / 2,
        );
    };
    start_index = reverse_byte_array_copy(buf, start_index, x_slice);
    let y_slice;
    unsafe {
        //concert y coordinate from little endian to big endian
        y_slice = slice::from_raw_parts(
            hv_pub_key.y.num.value.as_ptr() as *const u8,
            size_of::<PubKey>() / 2,
        );
    };
    start_index = reverse_byte_array_copy(buf, start_index, y_slice);
    start_index
}

// extend hash of hypervisor ak pub into pcr 13
fn he_extend_ak() -> bool {
    let mut pk_buf: [u8; HE_HV_ATT_KEY_LEN as usize] = [0; HE_HV_ATT_KEY_LEN as usize];
    if copy_hv_pub_ak_buf(&mut pk_buf) != HE_HV_ATT_KEY_LEN as usize {
        println!("HyperEnclave: failed to get attestation key");
        return false;
    }
    unsafe {
        if he_extend_ak_pub(pk_buf.as_ptr() as *const u8, HE_HV_ATT_KEY_LEN as u32) == 0 {
            println!("HyperEnclave: failed to extend attestation key");
            return false;
        }
    }
    true
}

pub fn sign_csr(csr: &[u8], csr_len: u32, sig: &mut [u8]) -> u32 {
    let _lock = TPM_LOCK.lock();
    let sign_len;
    unsafe {
        sign_len = he_sign_csr(csr.as_ptr(), csr_len as uint32_t, sig.as_mut_ptr()) as u32;
    }
    sign_len
}

pub fn get_pub_keys(
    tpm_ak_pub: &mut [u8],
    hv_ak_pub: &mut [u8],
    pcr_buf: &mut [u8],
    pub_area: &mut [u8],
) -> u32 {
    let _lock = TPM_LOCK.lock();
    if copy_hv_pub_ak_buf(hv_ak_pub) != HE_HV_ATT_KEY_LEN as usize {
        println!("HyperEnclave: failed to get hvattestation key");
        return 0;
    }
    unsafe {
        if he_get_tpm_ak_pub(tpm_ak_pub.as_mut_ptr() as *mut u8) != HE_HV_ATT_KEY_LEN as u32 {
            println!("HyperEnclave: failed to get tpm attestation key");
            return 0;
        }
    }
    let pcr_list_size;
    let area_size;
    unsafe {
        pcr_list_size = he_get_pcr_list(pcr_buf.as_mut_ptr() as *mut u8);
        area_size = he_get_ak_pub_area(pub_area.as_mut_ptr() as *mut u8);
    }
    println!(
        "pcr_list_size={} pub_area_size={}",
        pcr_list_size, area_size
    );

    (HE_HV_ATT_KEY_LEN * 2 + pcr_list_size + area_size) as u32
}

pub fn write_cert(cert_buf: &[u8], cert_len: u32) -> u32 {
    let _lock = TPM_LOCK.lock();
    unsafe {
        if he_write_tpm_ak_cert(cert_buf.as_ptr(), cert_len) != cert_len {
            error!("HyperEnclave: failed to write certificate to TPM NV");
            return 0;
        }
    }
    cert_len
}

pub fn read_cert(cert_buf: &mut [u8], read: u32) -> u32 {
    let _lock = TPM_LOCK.lock();
    unsafe { he_read_cert(cert_buf.as_mut_ptr(), cert_buf.len() as u32, read) as u32 }
}

pub fn activate_credential(blob: &[u8], enc_secret: &[u8], key: &mut [u8]) -> u32 {
    let _lock = TPM_LOCK.lock();
    unsafe {
        he_activate_credential(
            blob.as_ptr(),
            blob.len() as u32,
            enc_secret.as_ptr(),
            enc_secret.len() as u32,
            key.as_mut_ptr(),
        )
    }
}
#[no_mangle]
pub extern "C" fn hv_va_to_pa(va: uint64_t) -> uint64_t {
    virt_to_phys(va as usize) as uint64_t
}

#[no_mangle]
pub extern "C" fn println_str(s: *const c_char) {
    let c_str = unsafe {
        assert!(!s.is_null());
        CStr::from_ptr(s)
    };
    let r_str = c_str.to_str().unwrap();
    println!("{}", r_str);
}

#[no_mangle]
pub extern "C" fn println_u32(s: *const c_char, num1: uint32_t, num2: uint32_t) {
    let c_str = unsafe {
        assert!(!s.is_null());
        CStr::from_ptr(s)
    };
    let r_str = c_str.to_str().unwrap();
    println!("{} :{} :{}", r_str, num1, num2);
}

#[no_mangle]
pub extern "C" fn println_u64(s: *const c_char, addr: uint64_t) {
    let c_str = unsafe {
        assert!(!s.is_null());
        CStr::from_ptr(s)
    };
    let r_str = c_str.to_str().unwrap();
    println!("{} :{:#x}", r_str, addr);
}

#[no_mangle]
pub extern "C" fn println_hex(s: *const c_char, hex_ptr: *const uint8_t, len: uint32_t) {
    let c_str = unsafe {
        assert!(!s.is_null());
        CStr::from_ptr(s)
    };
    let r_str = c_str.to_str().unwrap();
    println!("{}:{}", r_str, len);
    unsafe {
        let mut pos: u32 = 0;
        let mut pointer: uintptr_t = hex_ptr as uintptr_t;
        while pos < len {
            print!("{:#04x}", *(pointer as *const uint8_t));
            pointer += 1;
            pos += 1;
        }
    }
    println!(":hex_end");
}

#[no_mangle]
pub extern "C" fn hv_gen_sm3_hash(
    data_ptr: *const uint8_t,
    data_size: usize,
    hash_ptr: *mut uint8_t,
) -> bool {
    if data_ptr.is_null() || hash_ptr.is_null() || data_size == 0 {
        return false;
    }
    let data = unsafe { slice::from_raw_parts(data_ptr, data_size) };
    let hash = sm3_enc(data);
    let hash_bytes: Vec<u8> = hash.iter().flat_map(|var| var.to_be_bytes()).collect();
    unsafe {
        core::ptr::copy_nonoverlapping(
            hash_bytes.as_ptr() as *const u8,
            hash_ptr,
            hash_bytes.len(),
        );
    }
    true
}

#[no_mangle]
pub extern "C" fn hv_gen_key(
    seed_ptr: *const uint8_t,
    seed_size: usize,
    sk_ptr: *mut uint8_t,
    pk_x_ptr: *mut uint8_t,
    pk_y_ptr: *mut uint8_t,
) -> bool {
    if seed_ptr.is_null()
        || sk_ptr.is_null()
        || pk_x_ptr.is_null()
        || pk_y_ptr.is_null()
        || seed_size != size_of::<SecKey>()
    {
        return false;
    }
    let seed_bytes = unsafe { slice::from_raw_parts(seed_ptr, seed_size) };
    let seed = bytes_to_u64x4(seed_bytes.try_into().unwrap());
    let sec_key: SecKey = U64x4 { value: seed };
    let pub_key: PubKey = get_pub_key(sec_key);
    let sec_key_bytes = u64x4_to_bytes(&sec_key.value);
    let pub_key_x_bytes = u64x4_to_bytes(&pub_key.x.num.value);
    let pub_key_y_bytes = u64x4_to_bytes(&pub_key.y.num.value);
    unsafe {
        core::ptr::copy_nonoverlapping(
            sec_key_bytes.as_ptr() as *const u8,
            sk_ptr,
            sec_key_bytes.len(),
        );
        core::ptr::copy_nonoverlapping(
            pub_key_x_bytes.as_ptr() as *const u8,
            pk_x_ptr,
            pub_key_x_bytes.len(),
        );
        core::ptr::copy_nonoverlapping(
            pub_key_y_bytes.as_ptr() as *const u8,
            pk_y_ptr,
            pub_key_y_bytes.len(),
        );
    }
    true
}

#[no_mangle]
pub extern "C" fn hv_gen_sm2_sign(
    data_ptr: *const uint8_t,
    data_size: usize,
    sk_ptr: *const uint8_t,
    pk_x_ptr: *const uint8_t,
    pk_y_ptr: *const uint8_t,
    use_z: bool,
    sign_ptr: *mut uint8_t,
) -> bool {
    if data_ptr.is_null()
        || sk_ptr.is_null()
        || pk_x_ptr.is_null()
        || pk_y_ptr.is_null()
        || sign_ptr.is_null()
        || data_size == 0
    {
        return false;
    }

    let data = unsafe { slice::from_raw_parts(data_ptr, data_size) };
    let sk_bytes = unsafe { slice::from_raw_parts(sk_ptr, size_of::<SecKey>()) };
    let pk_x_bytes = unsafe { slice::from_raw_parts(pk_x_ptr, size_of::<PubKey>() / 2) };
    let pk_y_bytes = unsafe { slice::from_raw_parts(pk_y_ptr, size_of::<PubKey>() / 2) };

    let sk = bytes_to_u64x4(sk_bytes.try_into().unwrap());
    let pk_x = bytes_to_u64x4(pk_x_bytes.try_into().unwrap());
    let pk_y = bytes_to_u64x4(pk_y_bytes.try_into().unwrap());

    let sec_key: SecKey = U64x4 { value: sk };
    let pub_key = PubKey::new(
        Coordinate::new(U64x4 { value: pk_x }),
        Coordinate::new(U64x4 { value: pk_y }),
    );

    let sig = sm2_gen_sign(data, sec_key, pub_key, use_z);

    unsafe {
        core::ptr::copy_nonoverlapping(
            u64x4_to_bytes(&sig.r.value).as_ptr() as *const u8,
            sign_ptr,
            size_of::<PubKey>() / 2,
        );
        core::ptr::copy_nonoverlapping(
            u64x4_to_bytes(&sig.s.value).as_ptr() as *const u8,
            sign_ptr.add(size_of::<PubKey>() / 2),
            size_of::<PubKey>() / 2,
        );
    }
    true
}
