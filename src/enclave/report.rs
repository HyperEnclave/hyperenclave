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

extern crate yogcrypt;
use alloc::vec::Vec;
use core::convert::TryInto;
use core::{mem::size_of, slice};
use cty::{uint32_t, uint8_t};
use yogcrypt::sm2::*;
use yogcrypt::sm3::sm3_enc;

pub const SGX_HASH_SIZE: u32 = 32;
pub const SGX_MAC_SIZE: u32 = 16;
pub const SGX_KEYID_SIZE: u32 = 32;
pub const SGX_REPORT_DATA_SIZE: u32 = 64;
pub const SGX_ISV_FAMILY_ID_SIZE: u32 = 16;
pub const SGX_CONFIGID_SIZE: u32 = 64;
pub const SGX_TARGET_INFO_RESERVED1_BYTES: u32 = 2;
pub const SGX_TARGET_INFO_RESERVED2_BYTES: u32 = 8;
pub const SGX_TARGET_INFO_RESERVED3_BYTES: u32 = 384;
pub const SGX_CPUSVN_SIZE: u32 = 16;
pub const SGX_ENCLAVE_KEY_SIZE: u32 = 16;
pub const SGX_REPORT_BODY_RESERVED1_BYTES: u32 = 12;
pub const SGX_REPORT_BODY_RESERVED2_BYTES: u32 = 32;
pub const SGX_REPORT_BODY_RESERVED3_BYTES: u32 = 32;
pub const SGX_REPORT_BODY_RESERVED4_BYTES: u32 = 42;
pub const SGX_ISVEXT_PROD_ID_SIZE: u32 = 16;
//pub const SGX_REPORT_SIZE: u32 = 432;
//pub const SGX_TARGET_INFO_SIZE: u32 = 512;
pub const SGX_BASE_NAME_SIZE: u32 = 32;
pub const SM4_KEY_SIZE: u32 = 16;
pub const TPM_AK_PUBAREA_SIZE: u32 = 0x0078;
pub const SGX_QUOTE_SIZE: u32 = 436; //size of sgx_quoe_t
pub const HE_ENCL_QUOTE_SIZE: u32 = 64; //signature 512bit
pub const HE_HV_ATT_KEY_LEN: u32 = 64; //256+256 bit
pub const HE_TPM_ATT_DATA_LEN: u32 = 147; //0x93 tpm attest_data len under ecc 256/sm2 when user_data=32 bytes
pub const HE_TPM_SIG_LEN: u32 = 64; //TPM SM2 SIG LEN
pub const HE_CERT_BUF_LEN: u32 = 1280;
pub const HE_ENC_BLOB_LEN: u32 = 50;
pub const SGX_KEY_REQUEST_RESERVED2_BYTES: u32 = 434;
pub const OWNEREPOCH_SIZE: u32 = 32;
pub const SGX_KEYPOLICY_MRENCLAVE: u16 = 0x0001;
pub const SGX_KEYPOLICY_MRSIGNER: u16 = 0x0002;
pub const SGX_KEYSELECT_SEAL: u16 = 0x0004;
pub const SGX_KEYSELECT_REPORT: u16 = 0x0003;
pub const CSR_BUF_LEN: u32 = 512;
pub const PCR_LIST_BUF_SIZE: u32 = 96; //3*32
pub const TPM_AK_CERT_BUF_LEN: u32 = HE_CERT_BUF_LEN;
pub const HE_QUOTE_VER: u16 = 1;
pub const HE_SIGN_TYPE: u16 = 4;
pub type SgxMeasurement = [u8; SGX_HASH_SIZE as usize];
pub type SgxMac = [u8; SGX_MAC_SIZE as usize];
pub type SgxReportData = [u8; SGX_REPORT_DATA_SIZE as usize];
pub type SgxConfigId = [u8; SGX_CONFIGID_SIZE as usize];
pub type SgxKeyId = [u8; SGX_KEYID_SIZE as usize];
pub type SgxBasename = [u8; SGX_BASE_NAME_SIZE as usize];
//pub type SMSignBuf = [u8; SGX_REPORT_DATA_SIZE as usize + SGX_HASH_SIZE as usize];
pub type SgxKey128Bit = [u8; SGX_ENCLAVE_KEY_SIZE as usize];
pub type SgxOwnerEpoch = [u8; OWNEREPOCH_SIZE as usize];

extern "C" {
    pub fn he_get_key_derivation_secret(buf_ptr: *mut uint8_t, buf_size: uint32_t) -> uint32_t;
    pub fn he_get_report_key_id(buf: *mut uint8_t, buf_len: uint32_t) -> uint32_t;
}

#[repr(C)]
#[derive(Copy, Clone, Debug, Default)]
pub struct SgxAttrs {
    pub flags: u64,
    pub xfrm: u64,
}

#[repr(C)]
#[derive(Debug)]
pub struct SgxTargetInfo {
    pub mr_enclave: SgxMeasurement,
    pub attributes: SgxAttrs,
    reserved1: [u8; SGX_TARGET_INFO_RESERVED1_BYTES as usize],
    config_svn: u16,
    misc_select: u32,
    reserved2: [u8; SGX_TARGET_INFO_RESERVED2_BYTES as usize],
    config_id: SgxConfigId,
    reserved3: [u8; SGX_TARGET_INFO_RESERVED3_BYTES as usize],
}

impl Default for SgxTargetInfo {
    fn default() -> Self {
        SgxTargetInfo {
            mr_enclave: [0xee; SGX_HASH_SIZE as usize],
            attributes: SgxAttrs { flags: 1, xfrm: 3 },
            reserved1: [0; SGX_TARGET_INFO_RESERVED1_BYTES as usize],
            config_svn: 0,
            misc_select: 0,
            reserved2: [0; SGX_TARGET_INFO_RESERVED2_BYTES as usize],
            config_id: [0; SGX_CONFIGID_SIZE as usize],
            reserved3: [0; SGX_TARGET_INFO_RESERVED3_BYTES as usize],
        }
    }
}

impl SgxTargetInfo {
    pub fn get_attributes(&self) -> (u64, u64) {
        (self.attributes.flags, self.attributes.xfrm)
    }

    pub fn get_mr_enclave(&self) -> &[u8] {
        &self.mr_enclave
    }
}

#[repr(C)]
#[derive(Copy, Clone, Debug)]
pub struct SgxReportBody {
    cpu_svn: [u8; SGX_CPUSVN_SIZE as usize],
    misc_select: u32, //reserved
    reserved1: [u8; SGX_REPORT_BODY_RESERVED1_BYTES as usize],
    isv_ext_prod_id: [u8; SGX_ISVEXT_PROD_ID_SIZE as usize], //reserved
    pub attributes: SgxAttrs,
    pub mr_enclave: SgxMeasurement,
    reserved2: [u8; SGX_REPORT_BODY_RESERVED2_BYTES as usize],
    pub mr_signer: SgxMeasurement,
    reserved3: [u8; SGX_REPORT_BODY_RESERVED3_BYTES as usize],
    config_id: SgxConfigId, //reserved
    pub isv_prod_id: u16,
    pub isv_svn: u16,
    config_svn: u16, //reserved
    reserved4: [u8; SGX_REPORT_BODY_RESERVED4_BYTES as usize],
    isv_family_id: [u8; SGX_ISV_FAMILY_ID_SIZE as usize], //reserved
    pub report_data: SgxReportData,
}

#[repr(C)]
#[derive(Copy, Clone, Debug)]
pub struct SgxReport {
    pub body: SgxReportBody,
    pub key_id: SgxKeyId,
    pub mac: SgxMac,
}

//sgx_quote_t =436, enclave_quote=64, att_pub_len=64 , attest_data= 155, platform signature=256
#[repr(C)]
#[derive(Debug)]
pub struct SgxQuote {
    version: u16,
    sign_type: u16,
    epid_group_id: [u8; 4],
    qe_svn: u16,
    pce_svn: u16,
    xeid: u32,
    basename: SgxBasename,
    pub report_body: SgxReportBody,
    pub sig_len: u32,
    pub encl_quote: [u8; HE_ENCL_QUOTE_SIZE as usize], //offset=436
    pub hv_att_pub: [u8; HE_HV_ATT_KEY_LEN as usize],  // offset=500
    pub hv_quote: [u8; HE_TPM_ATT_DATA_LEN as usize + HE_TPM_SIG_LEN as usize], //offset=564
    pub certificate: [u8; TPM_AK_CERT_BUF_LEN as usize], // offfset= 776
} //size_of(SgxQuote)=776(instead of)  the last byte is not used

pub fn reverse_byte_array_copy(dest: &mut [u8], start_index: usize, src: &[u8]) -> usize {
    if start_index >= dest.len() || src.len() > (dest.len() - start_index) {
        error!("reverse_byte_array_copy:0 byte is copied");
        println!("reverse_byte_array_copy:0 byte is copied");
        return 0;
    }
    let mut dest_pos = start_index;
    let mut src_pos: usize = src.len() - 1;
    while dest_pos < dest.len() {
        dest[dest_pos] = src[src_pos];
        dest_pos += 1;
        if src_pos > 0 {
            src_pos -= 1;
        } else {
            break;
        }
    }
    dest_pos
}

pub fn convert_sm3_hash_bytes_order(dest: &mut [u8], src: &[u8]) -> usize {
    if dest.len() != src.len() {
        return 0;
    }
    let step: usize = 4;
    let mut dst_pos: usize = 0;
    let mut src_pos: usize;
    let mut remain: usize;
    while dst_pos < dest.len() {
        remain = dst_pos % step;
        src_pos = (dst_pos - remain) + (step - remain - 1);
        dest[dst_pos] = src[src_pos];
        dst_pos += 1;
    }

    dest.len()
}

pub fn u64x4_to_bytes(l: &[u64; 4]) -> [u8; 32] {
    let result: Vec<u8> = l.iter().rev().flat_map(|var| var.to_be_bytes()).collect();
    result.try_into().unwrap()
}

pub fn bytes_to_u64x4(l: &[u8; 32]) -> [u64; 4] {
    let result: Vec<u64> = l
        .rchunks_exact(8)
        .map(|var| u64::from_be_bytes(var.try_into().unwrap()))
        .collect();
    result.try_into().unwrap()
}

impl Default for SgxReportBody {
    fn default() -> Self {
        SgxReportBody {
            cpu_svn: [0; SGX_CPUSVN_SIZE as usize],
            misc_select: 0, //reserved
            reserved1: [0; SGX_REPORT_BODY_RESERVED1_BYTES as usize],
            isv_ext_prod_id: Default::default(), //reserved
            attributes: Default::default(),
            mr_enclave: Default::default(),
            reserved2: [0; SGX_REPORT_BODY_RESERVED2_BYTES as usize],
            mr_signer: Default::default(),
            reserved3: [0; SGX_REPORT_BODY_RESERVED3_BYTES as usize],
            config_id: [0; SGX_CONFIGID_SIZE as usize], //reserved
            isv_prod_id: 0,
            isv_svn: 0,
            config_svn: 0, //reserved
            reserved4: [0; SGX_REPORT_BODY_RESERVED4_BYTES as usize],
            isv_family_id: Default::default(), //reserved
            report_data: [0; SGX_REPORT_DATA_SIZE as usize],
        }
    }
}

impl SgxReportBody {
    pub fn set_basics(&mut self, isv_prod_id: u16, isv_svn: u16, attr_flags: u64, attr_xfrm: u64) {
        let cpu_svn: [u8; SGX_CPUSVN_SIZE as usize] = [0; SGX_CPUSVN_SIZE as usize];
        self.cpu_svn.copy_from_slice(&cpu_svn);
        self.misc_select = 0; // reserved in sgx
        let reserved1: [u8; SGX_REPORT_BODY_RESERVED1_BYTES as usize] =
            [0; SGX_REPORT_BODY_RESERVED1_BYTES as usize];
        self.reserved1.copy_from_slice(&reserved1);
        let isv_ext_prod_id: [u8; SGX_ISVEXT_PROD_ID_SIZE as usize] =
            [0; SGX_ISVEXT_PROD_ID_SIZE as usize];
        self.isv_ext_prod_id.copy_from_slice(&isv_ext_prod_id);
        let reserved2: [u8; SGX_REPORT_BODY_RESERVED2_BYTES as usize] =
            [0; SGX_REPORT_BODY_RESERVED2_BYTES as usize];
        self.reserved2.copy_from_slice(&reserved2);
        let reserved3: [u8; SGX_REPORT_BODY_RESERVED3_BYTES as usize] =
            [0; SGX_REPORT_BODY_RESERVED3_BYTES as usize];
        self.reserved3.copy_from_slice(&reserved3);
        let config_id: [u8; SGX_CONFIGID_SIZE as usize] = [0; SGX_CONFIGID_SIZE as usize];
        self.config_id.copy_from_slice(&config_id);
        self.isv_prod_id = isv_prod_id;
        self.isv_svn = isv_svn;
        self.config_svn = 0;
        self.attributes.flags = attr_flags;
        self.attributes.xfrm = attr_xfrm;
        let reserved4: [u8; SGX_REPORT_BODY_RESERVED4_BYTES as usize] =
            [0; SGX_REPORT_BODY_RESERVED4_BYTES as usize];
        self.reserved4.copy_from_slice(&reserved4);
        let isv_family_id: [u8; SGX_ISV_FAMILY_ID_SIZE as usize] =
            [0; SGX_ISV_FAMILY_ID_SIZE as usize];
        self.isv_family_id.copy_from_slice(&isv_family_id);
    }

    pub fn mac(&mut self, key: &[u8], key_id_size: usize, mac: &mut [u8]) -> usize {
        if self.cpu_svn.len() == key.len() {
            self.cpu_svn.copy_from_slice(key);
        }
        let hash_bytes;
        unsafe {
            let body_bytes = slice::from_raw_parts(
                self.cpu_svn.as_ptr() as *const u8,
                size_of::<SgxReportBody>() + key_id_size,
            );
            let hash = sm3_enc(body_bytes);
            hash_bytes = slice::from_raw_parts(hash.as_ptr() as *const u8, SGX_MAC_SIZE as usize);
        }
        if mac.len() == hash_bytes.len() {
            mac.copy_from_slice(hash_bytes);
        }
        let cpu_svn: [u8; SGX_CPUSVN_SIZE as usize] = [0; SGX_CPUSVN_SIZE as usize];
        self.cpu_svn.copy_from_slice(&cpu_svn);
        hash_bytes.len()
    }
}

unsafe fn consttime_memequal(p1: &[u8], p2: &[u8]) -> i32 {
    let mut res: i32 = 0;
    let mut len = p1.len();
    while len > 0 {
        len -= 1;
        res |= (p1[len] ^ p2[len]) as i32;
    }
    1 & ((res - 1) >> 8)
}

impl Default for SgxReport {
    fn default() -> Self {
        SgxReport {
            body: Default::default(),
            key_id: Default::default(),
            mac: Default::default(),
        }
    }
}

impl SgxReport {
    pub fn set_mr_enclave_signer(&mut self, mr_enclave: &[u8], mr_signer: &[u8]) -> u32 {
        if !mr_enclave.len() == self.body.mr_enclave.len()
            || !mr_signer.len() == self.body.mr_signer.len()
        {
            return 0;
        }
        self.body.mr_enclave.copy_from_slice(mr_enclave);
        self.body.mr_signer.copy_from_slice(mr_signer);
        mr_enclave.len() as u32
    }

    #[allow(dead_code)]
    pub fn get_mr_enclave(&self) -> &[u8] {
        &self.body.mr_enclave
    }

    #[allow(dead_code)]
    pub fn get_mr_signer(&self) -> &[u8] {
        &self.body.mr_signer
    }

    pub fn set_report_data(&mut self, report_data: &[u8]) -> u32 {
        if !report_data.len() == self.body.report_data.len() {
            return 0;
        }
        self.body.report_data.copy_from_slice(report_data);
        report_data.len() as u32
    }
    // return the whole report_data 64 bytes
    pub fn get_report_data(&self) -> &[u8] {
        &self.body.report_data
    }

    #[allow(dead_code)]
    pub fn set_attributes(&mut self, flags: u64, xfrm: u64) {
        self.body.attributes.flags = flags;
        self.body.attributes.xfrm = xfrm;
    }
    pub fn set_basics(&mut self, isv_prod_id: u16, isv_svn: u16, attr_flags: u64, attr_xfrm: u64) {
        self.body
            .set_basics(isv_prod_id, isv_svn, attr_flags, attr_xfrm);
    }

    pub fn set_key_id(&mut self) {
        unsafe {
            he_get_report_key_id(self.key_id.as_mut_ptr(), self.key_id.len() as uint32_t);
        }
    }
    pub fn get_key_id(&self) -> &[u8] {
        &self.key_id
    }
    #[allow(dead_code)]
    pub fn get_prod_id(&self) -> u16 {
        self.body.isv_prod_id
    }
    #[allow(dead_code)]
    pub fn get_attributes(&self) -> (u64, u64) {
        (self.body.attributes.flags, self.body.attributes.xfrm)
    }

    pub fn mac_equal(&self, mac_value: &[u8]) -> bool {
        let res = unsafe { consttime_memequal(&self.mac, mac_value) };
        res != 0
    }
    pub fn mac(&mut self, key: &SgxKey128Bit) -> u32 {
        let mut mac_buf: [u8; SGX_MAC_SIZE as usize] = [0; SGX_MAC_SIZE as usize];
        let mac_len = self.body.mac(key, size_of::<SgxKeyId>(), &mut mac_buf);
        if mac_len == 0 {
            return 0;
        }
        self.mac.copy_from_slice(&mac_buf);
        mac_len as u32
    }
}

impl Default for SgxQuote {
    fn default() -> Self {
        SgxQuote {
            version: HE_QUOTE_VER,
            sign_type: HE_SIGN_TYPE,
            epid_group_id: [0; 4],
            qe_svn: 0,
            pce_svn: 0,
            xeid: 0,
            basename: [0; SGX_BASE_NAME_SIZE as usize],
            report_body: Default::default(),
            sig_len: 0,
            encl_quote: [0; HE_ENCL_QUOTE_SIZE as usize], //offset=436
            hv_att_pub: [0; HE_HV_ATT_KEY_LEN as usize],  // offset=500
            hv_quote: [0; HE_TPM_ATT_DATA_LEN as usize + HE_TPM_SIG_LEN as usize], //offset=564
            certificate: [0; TPM_AK_CERT_BUF_LEN as usize], // offfset= 776
        }
    }
}

impl SgxQuote {
    pub fn set_hv_att_pub(&mut self, hv_pub_key: &PubKey) -> u32 {
        let mut start_index: usize = 0;
        let x_slice;
        unsafe {
            //convert x coordinate from little endian to big endian
            x_slice = slice::from_raw_parts(
                hv_pub_key.x.num.value.as_ptr() as *const u8,
                size_of::<PubKey>() / 2,
            );
        };
        start_index = reverse_byte_array_copy(&mut self.hv_att_pub, start_index, x_slice);
        let y_slice;
        unsafe {
            //concert y coordinate from little endian to big endian
            y_slice = slice::from_raw_parts(
                hv_pub_key.y.num.value.as_ptr() as *const u8,
                size_of::<PubKey>() / 2,
            );
        };
        start_index = reverse_byte_array_copy(&mut self.hv_att_pub, start_index, y_slice);
        start_index as u32
    }

    pub fn set_encl_quote(&mut self, sig: &Signature) -> u32 {
        let mut start_index: usize = 0;
        let r_slice;
        unsafe {
            //convert x coordinate from little endian to big endian
            r_slice = slice::from_raw_parts(
                sig.r.value.as_ptr() as *const u8,
                size_of::<Signature>() / 2,
            );
        };
        start_index = reverse_byte_array_copy(&mut self.encl_quote, start_index, r_slice);
        let s_slice;
        unsafe {
            //concert y coordinate from little endian to big endian
            s_slice = slice::from_raw_parts(
                sig.s.value.as_ptr() as *const u8,
                size_of::<Signature>() / 2,
            );
        };
        start_index = reverse_byte_array_copy(&mut self.encl_quote, start_index, s_slice);
        start_index as u32
    }

    #[allow(dead_code)]
    pub fn print_mem_layout(&self) {
        let start = &self.version as *const u16 as *const u8 as usize;
        let encl_quote = self.encl_quote.as_ptr() as *const u8 as usize;
        let hv_att_pub = self.hv_att_pub.as_ptr() as *const u8 as usize;
        let hv_quote = self.hv_quote.as_ptr() as *const u8 as usize;
        println!(
            "encl_quote offset ={} hv_att_pub offset={} hv_quote offset ={}",
            encl_quote - start,
            hv_att_pub - start,
            hv_quote - start
        );
        println!("enclave sig: {:?}", &self.encl_quote);
    }
    #[allow(dead_code)]
    pub fn set_hv_quote(&mut self, hv_quote: &[u8]) -> u32 {
        if !hv_quote.len() == self.hv_quote.len() {
            return 0;
        }
        self.hv_quote.copy_from_slice(hv_quote);
        hv_quote.len() as u32
    }

    pub fn get_hv_quote_mut_ptr(&mut self) -> *mut u8 {
        self.hv_quote.as_mut_ptr() as *mut u8
    }

    pub fn get_data_to_sign(&self) -> &[u8] {
        unsafe {
            slice::from_raw_parts(
                self.report_body.cpu_svn.as_ptr() as *const u8,
                size_of::<SgxReportBody>(),
            )
        }
    }
}

#[repr(C)]
#[derive(Debug)]
pub struct SgxKeyRequest {
    pub key_name: u16,
    pub key_policy: u16,
    pub isv_svn: u16,
    pub reserved1: u16,
    pub cpu_svn: [u8; SGX_CPUSVN_SIZE as usize],
    pub attr_mask: SgxAttrs,
    pub key_id: SgxKeyId,
    pub misc_mask: u32,
    pub config_svn: u16,
    pub reserved2: [u8; SGX_KEY_REQUEST_RESERVED2_BYTES as usize],
}

impl Default for SgxKeyRequest {
    fn default() -> Self {
        SgxKeyRequest {
            key_name: SGX_KEYSELECT_REPORT,
            key_policy: 0,
            isv_svn: 0,
            reserved1: 0,
            cpu_svn: [0; SGX_CPUSVN_SIZE as usize],
            attr_mask: SgxAttrs { flags: 0, xfrm: 0 },
            key_id: [0; SGX_KEYID_SIZE as usize],
            misc_mask: 0,
            config_svn: 0,
            reserved2: [0; SGX_KEY_REQUEST_RESERVED2_BYTES as usize],
        }
    }
}

#[repr(C)]
#[derive(Debug, Default)]
pub struct DerivationData {
    key_name: u16,
    isv_svn: u16,
    isv_prod_id: u16,
    tcb_svn: u16,
    attributes: SgxAttrs,
    attr_mask: SgxAttrs,
    mr_enclave: SgxMeasurement,
    mr_signer: SgxMeasurement,
    key_id: SgxKeyId,
    epoch: SgxOwnerEpoch,
}

impl DerivationData {
    pub fn init_with_target_info(
        &mut self,
        target_info: &SgxTargetInfo,
        report: &SgxReport,
    ) -> bool {
        self.key_name = SGX_KEYSELECT_REPORT;
        self.isv_prod_id = 0; // defined by SGX speficiation
        self.isv_svn = 0; //defined by SGX speficiation
        let mr_signer: [u8; SGX_HASH_SIZE as usize] = [0; SGX_HASH_SIZE as usize]; // mr_signer must be 0
        unsafe {
            if he_get_key_derivation_secret(
                self.epoch.as_mut_ptr() as *mut uint8_t,
                OWNEREPOCH_SIZE,
            ) != OWNEREPOCH_SIZE
            {
                return false;
            }
        }
        self.attributes.flags = target_info.attributes.flags;
        self.attributes.xfrm = target_info.attributes.xfrm;
        self.attr_mask.flags = 0;
        self.attr_mask.xfrm = 0;
        self.mr_enclave.copy_from_slice(&target_info.mr_enclave);
        self.mr_signer.copy_from_slice(&mr_signer);
        self.key_id.copy_from_slice(report.get_key_id());

        true
    }

    pub fn init_with_key_request(
        &mut self,
        kr: &SgxKeyRequest,
        mr_enclave: &[u8],
        mr_signer: &[u8],
        isv_prod_id: u16,
        flags: u64,
        xfrm: u64,
    ) -> bool {
        self.key_name = kr.key_name;
        if kr.key_name != SGX_KEYSELECT_REPORT && kr.key_name != SGX_KEYSELECT_SEAL {
            error!("HyperEnclave:the enclave key type is not supported");
            println!(
                "HyperEnclave:the enclave key type is not supported {}",
                kr.key_name
            );
            return false;
        }
        if kr.key_name == SGX_KEYSELECT_REPORT {
            self.isv_prod_id = 0; // all those four values are defined by SGX specification
            self.isv_svn = 0;
            self.attr_mask.flags = 0;
            self.attr_mask.xfrm = 0;
        }
        if kr.key_name == SGX_KEYSELECT_SEAL {
            self.isv_prod_id = isv_prod_id;
            self.isv_svn = kr.isv_svn;
            self.attr_mask.flags = kr.attr_mask.flags;
            self.attr_mask.xfrm = kr.attr_mask.xfrm;
        }
        self.attributes.flags = flags;
        self.attributes.xfrm = xfrm;
        self.key_id.copy_from_slice(&kr.key_id);
        unsafe {
            if he_get_key_derivation_secret(
                self.epoch.as_mut_ptr() as *mut uint8_t,
                OWNEREPOCH_SIZE,
            ) != OWNEREPOCH_SIZE
            {
                error!("HyperEnclave: he_get_key_derivation_secret failed");
                return false;
            }
        }
        if kr.key_name == SGX_KEYSELECT_REPORT {
            self.mr_enclave.copy_from_slice(mr_enclave);
            let mr_signer: [u8; SGX_HASH_SIZE as usize] = [0; SGX_HASH_SIZE as usize]; // for report_key, signer must be zero
            self.mr_signer.copy_from_slice(&mr_signer);
        }
        if kr.key_name == SGX_KEYSELECT_SEAL {
            if kr.key_policy & SGX_KEYPOLICY_MRENCLAVE > 0 {
                self.mr_enclave.copy_from_slice(mr_enclave);
            }
            if kr.key_policy & SGX_KEYPOLICY_MRSIGNER > 0 {
                self.mr_signer.copy_from_slice(mr_signer);
            }
        }
        true
    }
}

#[repr(C)]
#[derive(Debug)]
pub struct CSRRequest {
    pub content: [u8; CSR_BUF_LEN as usize],
}

#[repr(C)]
#[derive(Debug)]
pub struct SM2Sig(pub [u8; HE_TPM_SIG_LEN as usize]);

impl Default for SM2Sig {
    fn default() -> Self {
        SM2Sig([0; HE_TPM_SIG_LEN as usize])
    }
}

#[repr(C)]
#[derive(Debug)]
pub struct Cert {
    pub content: [u8; HE_CERT_BUF_LEN as usize],
}

impl Default for Cert {
    fn default() -> Self {
        Cert {
            content: [0; HE_CERT_BUF_LEN as usize],
        }
    }
}

#[repr(C)]
#[derive(Debug)]
pub struct EncBlob(pub [u8; HE_ENC_BLOB_LEN as usize]);

#[repr(C)]
#[derive(Debug)]
pub struct EncSecret(pub [u8; HE_TPM_SIG_LEN as usize]);

#[repr(C)]
#[derive(Debug)]
pub struct SM4Key(pub [u8; SM4_KEY_SIZE as usize]);

impl Default for SM4Key {
    fn default() -> Self {
        SM4Key([0; SM4_KEY_SIZE as usize])
    }
}

#[repr(C)]
#[derive(Debug)]
pub struct KeyPubArea(pub [u8; TPM_AK_PUBAREA_SIZE as usize]);

impl Default for KeyPubArea {
    fn default() -> Self {
        KeyPubArea([0; TPM_AK_PUBAREA_SIZE as usize])
    }
}

#[repr(C)]
#[derive(Debug)]
pub struct PCRList(pub [u8; PCR_LIST_BUF_SIZE as usize]);

impl Default for PCRList {
    fn default() -> Self {
        PCRList([0; PCR_LIST_BUF_SIZE as usize])
    }
}
