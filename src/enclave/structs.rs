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

//! Custom structures for enclave management.

use bitflags::bitflags;
use core::fmt::{Debug, Formatter, Result};
use core::mem::size_of;

use crate::consts::PAGE_SIZE;
use crate::enclave::sgx::SgxSecs;
use crate::memory::GuestPhysAddr;

bitflags! {
    /// Possible attributes for an enclave page.
    pub struct EnclPageAttributes: u32 {
        const EADD          = 1 << 0;
        const EEXTEND       = 1 << 1;
        const EREMOVE       = 1 << 2;
        const POST_ADD      = 1 << 3;
        const POST_REMOVE   = 1 << 4;
        const DYN_THREAD    = 1 << 5;
        const GROW_DOWN     = 1 << 6;
    }
}

/// Each enclave descriptor occupies exactly one page, as does the SGX SECS.
/// Just leverage SGX secs_t directly except that this page is not hidden from
/// either N or S world, since no secret is stored in it yet. However, if we do
/// decide to store sensitive information (such as the enclave's measurement) in
/// it later, we can simply unmap this page from EPT-N and EPT-S.
pub type HvEnclDesc = SgxSecs;

#[derive(Debug)]
#[repr(C, packed)]
pub struct HvEnclNewPageDesc {
    pub config_address: u64,
    pub source_address: u64,
    pub enclave_lin_addr: u64,
    pub epc_page_pa: u64,
    pub metadata: u64,
    pub attr: EnclPageAttributes,
}

#[derive(Debug)]
#[repr(C, packed)]
pub struct HvEnclInitDesc {
    pub config_address: u64,
    pub sigstruct: u64,
}

#[derive(Debug)]
#[repr(C, packed)]
pub struct HvReclaimerPageDesc {
    pub gva: u64,
    pub gpa: u64,
    pub encl_addr: u64,
    pub valid: u8,
}

pub const NR_RECLAIM_EPC_PAGES: usize = 16;

#[repr(C)]
pub struct HvReclaimerPagesDesc {
    pub pages: [HvReclaimerPageDesc; NR_RECLAIM_EPC_PAGES],
}

#[derive(Debug)]
#[repr(C)]
pub struct HvEnclRemovePagesAtDestroyDesc {
    pub config_address: u64,
    pub page_array_addr: u64,
    pub res_array_addr: u64,
    pub batch_size: u64,
}

#[repr(C)]
pub struct HvEnclRemovePagesAtDestroyPageArray {
    pub gpaddr: [GuestPhysAddr; PAGE_SIZE / size_of::<GuestPhysAddr>()],
}

#[repr(C)]
pub struct HvEnclRemovePagesAtDestroyResArray {
    pub val: [isize; PAGE_SIZE / size_of::<isize>()],
}

#[derive(Debug)]
#[repr(C, packed)]
pub struct HvSharedMemoryDesc {
    pub config_addr: u64,
    pub start_addr: u64,
    pub end_addr: u64,
}

#[derive(Debug)]
#[repr(C, packed)]
pub struct HvEnclAugPageDesc {
    /// Guest linear address of SECS the page belongs to
    pub config_address: u64,
    /// Guest linear address of the page that needs augmentation
    pub enclave_lin_addr: u64,
    /// Guest physical address of the page that needs augmentation
    pub enclave_phys_addr: u64,
    /// Attributes of the page that needs augmentation
    pub sec_info: u64,
}

#[derive(Debug)]
#[repr(C, packed)]
pub struct HvEnclModtPageDesc {
    /// Guest linear address of SECS the page belongs to
    pub config_address: u64,
    /// Guest linear address of the page that needs type modification
    pub enclave_lin_addr: u64,
    /// Attributes of the page that needs type modification
    pub sec_info: u64,
}

#[derive(Debug)]
#[repr(C, packed)]
pub struct HvEnclRestrictPageDesc {
    /// Guest linear address of SECS the page belongs to
    pub config_address: u64,
    /// Guest linear address of the page that needs permission restriction
    pub enclave_lin_addr: u64,
    /// Attributes of the page that needs permission restriction
    pub sec_info: u64,
}

#[derive(Debug)]
#[repr(C, packed)]
pub struct HvEnclRemovePageAtRuntimeDesc {
    /// Guest linear address of SECS the page belongs to
    pub config_address: u64,
    /// Guest linear address of the page that needs removal
    pub enclave_lin_addr: u64,
}

pub const SHA256_HASH_SIZE: usize = 32;

#[repr(transparent)]
#[derive(Clone, Copy, Default, PartialEq)]
pub struct Sha256Value([u8; SHA256_HASH_SIZE]);

impl Sha256Value {
    pub fn as_mut_slice(&mut self) -> &mut [u8] {
        &mut self.0
    }

    pub fn as_slice(&self) -> &[u8] {
        &self.0
    }
}

impl Debug for Sha256Value {
    fn fmt(&self, f: &mut Formatter) -> Result {
        write!(f, "Sha256Value(")?;
        for byte in &self.0 {
            write!(f, "{:02x}", byte)?;
        }
        write!(f, ")")
    }
}

#[repr(transparent)]
#[derive(Clone, Copy)]
pub struct SigKey3072Value([u8; 384]);

impl SigKey3072Value {
    pub fn as_slice(&self) -> &[u8] {
        &self.0
    }
}

impl Debug for SigKey3072Value {
    fn fmt(&self, f: &mut Formatter) -> Result {
        write!(f, "SigKey3072Value(")?;
        for byte in &self.0 {
            write!(f, "{:02x}", byte)?;
        }
        write!(f, ")")
    }
}
