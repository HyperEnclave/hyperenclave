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

//! Original SGX structures.

use alloc::string::String;
use alloc::sync::Arc;
use bitflags::bitflags;
use core::fmt::{Debug, Formatter, Result};
use core::{convert::TryFrom, mem::MaybeUninit, ops::Range};

use super::structs::{Sha256Value, SigKey3072Value};
use crate::arch::XsaveRegion;
use crate::enclave::reclaim::HmacValue;
use crate::enclave::Enclave;
use crate::error::{HvError, HvResult};
use crate::hypercall::PrivilegeLevel;
use crate::memory::gaccess::{AsGuestPtr, GuestPtr};
use crate::memory::{addr::is_aligned, GuestVirtAddr, MemFlags, PAGE_SIZE};
use crate::percpu::CpuState;

/// Enclave Linear Address Range (ELRANGE).
pub type ElRange = Range<GuestVirtAddr>;

bitflags! {
    /// The ATTRIBUTES data structure is comprised of bit-granular fields that are used in the SECS.
    pub struct SgxAttributeFlags: u64 {
        /// This bit indicates if the enclave has been initialized by EINIT.
        const INIT              = 1 << 0;
        /// If 1, the enclave permit debugger to read and write enclave data using EDBGRD and EDBGWR.
        const DEBUG             = 1 << 1;
        /// Enclave runs in 64-bit mode.
        const MODE64BIT         = 1 << 2;
        /// Provisioning Key is available from EGETKEY.
        const PROVISIONKEY      = 1 << 4;
        /// EINIT token key is available from EGETKEY.
        const EINITTOKEN_KEY    = 1 << 5;
        /// Enable CET attributes.
        const CET               = 1 << 6;
        /// Key Separation and Sharing Enabled.
        const KSS               = 1 << 7;
    }
}

/// ATTRIBUTES data structure in the SECS.
#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct SgxAttributes {
    /// First 8 bits of ATTRIBUTES structure.
    pub flags: SgxAttributeFlags,
    /// XSAVE Feature Request Mask.
    pub xfrm: u64,
}

bitflags! {
    /// Flags describing the state of the enclave page.
    pub struct SgxEnclPageFlags: u8 {
        /// The page can be read from inside the enclave.
        const R         = 1 << 0;
        /// The page can be written from inside the enclave.
        const W         = 1 << 1;
        /// The page can be executed from inside the enclave.
        const X         = 1 << 2;
        /// The page is in the PENDING state.
        const PENDING   = 1 << 3;
        /// The page is in the MODIFIED state.
        const MODIFIED  = 1 << 4;
        /// A permission restriction operation on the page is in progress.
        const PR        = 1 << 5;
        /// The page is in the BLOCKED state.
        const BLOCKED   = 1 << 6;
        /// For EPCM entries, indicates whether the EPCM entry is valid.
        const VALID     = 1 << 7;
    }
}

impl SgxEnclPageFlags {
    pub const PERM_MASK: Self = Self {
        bits: Self::R.bits() | Self::W.bits() | Self::X.bits(),
    };
}

#[repr(u8)]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[allow(non_camel_case_types, dead_code, clippy::upper_case_acronyms)]
pub enum SgxEnclPageType {
    /// Page is an SECS.
    SECS = 0,
    /// Page is a TCS.
    TCS = 1,
    /// Page is a regular page.
    REG = 2,
    /// Page is a Version Array.
    VA = 3,
    /// Page is in trimmed state.
    TRIM = 4,
    /// Page is first page of a shadow stack.
    SS_FIRST = 5,
    /// Page is not first page of a shadow stack.
    SS_REST = 6,
}

impl TryFrom<u8> for SgxEnclPageType {
    type Error = HvError;

    fn try_from(page_type: u8) -> HvResult<SgxEnclPageType> {
        match page_type {
            0 => Ok(SgxEnclPageType::SECS),
            1 => Ok(SgxEnclPageType::TCS),
            2 => Ok(SgxEnclPageType::REG),
            3 => Ok(SgxEnclPageType::VA),
            4 => Ok(SgxEnclPageType::TRIM),
            5 => Ok(SgxEnclPageType::SS_FIRST),
            6 => Ok(SgxEnclPageType::SS_REST),
            _ => hv_result_err!(EINVAL, format!("Invalid page_type={:#x}", page_type)),
        }
    }
}

/// Paging Crypto Metadata (PCMD).
#[repr(C, packed)]
#[derive(Copy, Clone)]
pub struct SgxPcmd {
    /// SECINFO.
    pub sec_info: SgxSecInfo,
    /// Enclave identifier.
    pub enclave_id: usize,
    /// MAC over PCMD, page contents and nonce.
    pub mac: HmacValue,
    _reserved: [u8; 16],
}

impl SgxPcmd {
    pub fn new(sec_info: SgxSecInfo, enclave_id: usize, mac: HmacValue) -> Self {
        Self {
            sec_info,
            enclave_id,
            mac,
            _reserved: [0; 16],
        }
    }
}

/// Security Information (SECINFO).
#[repr(C)]
#[derive(Copy, Clone)]
pub struct SgxSecInfo {
    /// Flags describing the state of the enclave page.
    pub flags: SgxEnclPageFlags,
    /// The type of page that the SECINFO is associated with.
    pub page_type: SgxEnclPageType,
    /// Must be zero.
    _reserved: [u16; 3],
}

impl SgxSecInfo {
    pub fn new(flags: SgxEnclPageFlags, page_type: SgxEnclPageType) -> Self {
        Self {
            flags,
            page_type,
            _reserved: [0; 3],
        }
    }
}

impl From<SgxSecInfo> for MemFlags {
    fn from(sec_info: SgxSecInfo) -> MemFlags {
        let mut ret = MemFlags::USER;
        if sec_info.flags.contains(SgxEnclPageFlags::R) {
            ret |= MemFlags::READ;
        }
        if sec_info.flags.contains(SgxEnclPageFlags::W) {
            ret |= MemFlags::WRITE;
        }
        if sec_info.flags.contains(SgxEnclPageFlags::X) {
            ret |= MemFlags::EXECUTE;
        }

        // If the page is in the process of:
        //     - Augmentation
        //     - Type modification
        //     - Eviction to main memory
        // Enclave cannot access it. We achive it by marking it as non-present.
        if sec_info.flags.contains(SgxEnclPageFlags::PENDING)
            || sec_info.flags.contains(SgxEnclPageFlags::MODIFIED)
            || sec_info.flags.contains(SgxEnclPageFlags::BLOCKED)
        {
            ret |= MemFlags::NO_PRESENT;
        }

        if sec_info.page_type == SgxEnclPageType::TCS
            || sec_info.page_type == SgxEnclPageType::VA
            || sec_info.page_type == SgxEnclPageType::TRIM
        {
            ret |= MemFlags::NO_PRESENT;

            if sec_info.page_type == SgxEnclPageType::TCS {
                ret |= MemFlags::READ | MemFlags::WRITE;
            }
        }

        ret
    }
}

impl From<SgxSecInfo> for u64 {
    fn from(info: SgxSecInfo) -> u64 {
        ((info.page_type as u64) << 8) | (info.flags.bits() as u64)
    }
}

impl TryFrom<usize> for SgxSecInfo {
    type Error = HvError;

    fn try_from(sec_info: usize) -> HvResult<SgxSecInfo> {
        // All the bits in `SgxEnclPageFlags` are defined, so we use `from_bits_truncate()` here.
        let flags = SgxEnclPageFlags::from_bits_truncate(sec_info as u8);
        let page_type = (sec_info >> 8) as u8;
        let page_type = SgxEnclPageType::try_from(page_type)?;
        Ok(Self {
            flags,
            page_type,
            _reserved: [0_u16; 3],
        })
    }
}

bitflags! {
    /// Contains information about exceptions that cause AEXs.
    pub struct SgxExitInfo: u32 {
        const TYPE_HARD_EXCEPTION   = 3 << 8;
        /// Software exception (INT3 or INTO)
        const TYPE_SOFT_EXCEPTION   = 6 << 8;
        /// Valid
        const VALID                 = 1 << 31;
    }
}

impl SgxExitInfo {
    pub fn from_vector(vector: u8) -> Self {
        use crate::arch::ExceptionType;
        let mut info = unsafe { Self::from_bits_unchecked(vector as u32) };
        match vector {
            ExceptionType::Breakpoint => info |= Self::TYPE_SOFT_EXCEPTION | Self::VALID,
            ExceptionType::DivideError
            | ExceptionType::Debug
            | ExceptionType::BoundRangeExceeded
            | ExceptionType::InvalidOpcode
            | ExceptionType::GeneralProtectionFault
            | ExceptionType::PageFault
            | ExceptionType::FloatingPointException
            | ExceptionType::AlignmentCheck
            | ExceptionType::SIMDFloatingPointException => {
                info |= Self::TYPE_HARD_EXCEPTION | Self::VALID
            }
            _ => {}
        };
        info
    }
}

/// SGX Enclave Control Structrue (SECS).
#[repr(C)]
#[derive(Clone, Copy)]
pub struct SgxSecs {
    /// (  0) Size of the enclave in bytes; must be power of 2.
    pub size: u64,
    /// (  8) Enclave Base Linear Address must be naturally aligned to size.
    pub base_addr: u64,
    /// ( 16) Size of 1 SSA frame in pages.
    pub ssa_frame_size: u32,
    /// ( 20) Bit vector specifying which extended features are saved to the MISC region of the SSA
    /// frame when an AEX occurs.
    pub misc_select: u32,
    /// ( 24) Reserved
    _reserved1: [u8; 16],
    /// ( 40) Marshalling buffer size for each TCS.
    pub ms_buf_size: u64,
    /// ( 48) Attributes of the Enclave.
    pub attributes: SgxAttributes,
    /// ( 64) Measurement Register of enclave build process.
    pub mr_enclave: Sha256Value,
    /// ( 96) Reserved
    _reserved2: [u8; 32],
    /// (128) Measurement Register extended with the public key that verified the enclave.
    pub mr_signer: Sha256Value,
    /// (160) Reserved
    _reserved3: [u8; 32],
    /// (192) Post EINIT configuration identity.
    config_id: [u32; 16],
    /// (256) Product ID of enclave.
    pub isv_prod_id: u16,
    /// (258) Security version number (SVN) of the enclave.
    pub isv_svn: u16,
    /// (260) Post EINIT configuration security version number (SVN).
    config_svn: u16,
}

/// Thread Control Structure (TCS).
#[repr(C, align(4096))]
pub struct SgxTcs {
    /// ( 0) Enclave execution state of the thread controlled by this TCS. Must be 0 at creation.
    stage: u64,
    /// ( 8) The thread’s execution flags.
    flags: u64,
    /// (16) Offset of the base of the State Save Area stack, relative to the enclave base. Must be page
    /// aligned.
    pub ossa: u64,
    /// (24) Current slot index of an SSA frame.
    pub cssa: u32,
    /// (28) Number of available slots for SSA frames.
    pub nssa: u32,
    /// (32) Offset in enclave to which control is transferred on EENTER relative to the base of the
    /// enclave.
    pub oentry: u64,
    /// (40) The value of the Asynchronous Exit Pointer that was saved at EENTER time. Must be 0 at creation.
    pub aep: u64,
    /// (48) Offset to add to the base address of the enclave for producing the base address of FS
    /// segment inside the enclave. Must be page aligned.
    pub ofs_base: u64,
    /// (56) Offset to add to the base address of the enclave for producing the base address of GS
    /// segment inside the enclave. Must be page aligned.
    pub ogs_base: u64,
    /// (64) Size to become the new FS limit in 32-bit mode.
    fs_limit: u32,
    /// (68) Size to become the new GS limit in 32-bit mode.
    gs_limit: u32,
    /// (72) Rerserved field in TCS, must be 0 at creation.
    _reserved: [u8; 4024],
}
static_assertions::const_assert_eq!(core::mem::size_of::<SgxTcs>(), 4096);

impl SgxTcs {
    /// Check whether the MBZ(Must Be Zero) bits and reserved bits is 0
    /// when newing a TCS.
    pub fn validate_at_creation(&self) -> bool {
        if self.stage != 0 || self.aep != 0 {
            return false;
        }
        for i in self._reserved {
            if i != 0 {
                return false;
            }
        }
        true
    }
}

/// The size of SSA region equals to PAGE_SIZE (4096 bytes) now,
/// since the `SSA_FRAME_SIZE` input from SDK always equals to one 4k page (4096 bytes).
/// With such constriction, it is easy to specify the size of `XsaveRegion` at its definition.
/// Another benefit we gain from that is there only needs one GVA -> GPA (Walk GPT) translation when
/// switching from normal world to secure world.
pub const SSA_FRAME_SIZE: usize = PAGE_SIZE;

#[repr(C)]
pub struct StateSaveArea {
    pub xsave: XsaveRegion,
    pub misc: MiscSgx,
    pub gpr: GprSgx,
}
static_assertions::const_assert_eq!(core::mem::size_of::<StateSaveArea>(), 4096);

impl StateSaveArea {
    pub fn ssa_ptr<'a>(
        enclave: &'a Arc<Enclave>,
        tcs: &SgxTcs,
        cssa: u32,
        cpu_state: &'a CpuState,
        privilege_level: PrivilegeLevel,
    ) -> HvResult<GuestPtr<'a, StateSaveArea>> {
        if cssa >= tcs.nssa {
            return hv_result_err!(
                EINVAL,
                format!("tcs.cssa {:#x?} >= tcs.nssa {:#x?}", cssa, tcs.nssa)
            );
        }
        let start_addr =
            enclave.secs().base_addr as usize + tcs.ossa as usize + cssa as usize * SSA_FRAME_SIZE;
        if !is_aligned(start_addr) {
            return hv_result_err!(EINVAL, format!("tcs.ossa {:#x?} is not aligned", tcs.ossa));
        }
        Ok(start_addr.as_guest_ptr_s(enclave, cpu_state, privilege_level))
    }
}

#[repr(C)]
#[derive(Debug, Copy, Clone)]
pub struct SgxExInfo {
    pub maddr: u64,
    pub errcd: u32,
    _reserved: u32,
}

#[repr(C)]
#[derive(Debug, Copy, Clone)]
pub struct MiscSgx {
    pub exinfo: SgxExInfo,
}

impl MiscSgx {
    pub fn new(maddr: usize, errcd: u32) -> Self {
        Self {
            exinfo: SgxExInfo {
                maddr: maddr as _,
                errcd,
                _reserved: 0,
            },
        }
    }
}

/// General Purpose Registers in SGX.
#[repr(C)]
#[derive(Debug)]
pub struct GprSgx {
    pub rax: u64,
    pub rcx: u64,
    pub rdx: u64,
    pub rbx: u64,
    pub rsp: u64,
    pub rbp: u64,
    pub rsi: u64,
    pub rdi: u64,
    pub r8: u64,
    pub r9: u64,
    pub r10: u64,
    pub r11: u64,
    pub r12: u64,
    pub r13: u64,
    pub r14: u64,
    pub r15: u64,
    /// Flag register.
    pub rflags: u64,
    /// Instruction pointer.
    pub rip: u64,
    /// Non-Enclave (outside) stack pointer. Saved by EENTER, restored on AEX.
    pub ursp: u64,
    /// Non-Enclave (outside) RBP pointer. Saved by EENTER, restored on AEX.
    pub urbp: u64,
    /// Contains information about exceptions that cause AEXs, which might be needed by enclave software.
    pub exit_info: SgxExitInfo,
    _reserved: u32,
    /// FS BASE.
    pub fs_base: u64,
    /// GS BASE.
    pub gs_base: u64,
}

#[repr(C)]
pub struct SigStructHeader {
    /// (0) must be (06000000E100000000000100H)
    pub header1: [u8; 12],
    /// (12) bit 31: 0 = prod, 1 = debug; Bit 30-0: Must be zero
    pub types: u32,
    /// (16) Intel=0x8086, ISV=0x0000
    pub module_vendor: u32,
    /// (20) build date as yyyymmdd
    date: u32,
    /// (24) must be (01010000600000006000000001000000H)
    pub header2: [u8; 16],
    /// (40) For Launch Enclaves: HWVERSION != 0. Others, HWVERSION = 0
    pub hw_version: u32,
    /// (44) Must be 0
    _reserved1: [u8; 84],
}

#[repr(C)]
pub struct SigStructKey {
    /// (128) Module Public Key (keylength=3072 bits)
    pub modules: SigKey3072Value,
    /// (512) RSA Exponent = 3
    pub exponent: [u8; 4],
    /// (516) Signature over Header and Body
    pub signature: SigKey3072Value,
}

#[repr(C)]
pub struct SigStructBody {
    /// (900) The MISCSELECT that must be set
    pub misc_select: u32,
    /// (904) Mask of MISCSELECT to enforce
    pub misc_mask: u32,
    /// (908) Reserved. Must be 0.
    _reserved: [u8; 4],
    /// (912) ISV assigned Family ID
    pub isv_family_id: [u8; 16],
    /// (928) Enclave Attributes that must be set
    pub attributes: [u8; 16],
    /// (944) Mask of Attributes to Enforce
    pub attributes_mask: [u8; 16],
    /// (960) MRENCLAVE - (32 bytes)
    pub mr_enclave: Sha256Value,
    /// (992) Must be 0
    _reserved2: [u8; 16],
    /// (1008) ISV assigned Extended Product ID
    pub isvext_prod_id: [u8; 16],
    /// (1024) ISV assigned Product ID
    pub isv_prod_id: u16,
    /// (1026) ISV assigned SVN
    pub isv_svn: u16,
}

#[repr(C)]
pub struct SigStructBuffer {
    /// (1028) Must be 0
    _reserved: [u8; 12],
    /// (1040) Q1 value for RSA Signature Verification
    pub q1: SigKey3072Value,
    /// (1424) Q2 value for RSA Signature Verification
    pub q2: SigKey3072Value,
}

/// ENCLAVE SIGNATURE STRUCTURE
#[repr(C)]
pub struct SigStruct {
    pub header: SigStructHeader,
    pub key: SigStructKey,
    pub body: SigStructBody,
    pub buffer: SigStructBuffer,
}

#[repr(u32)]
#[derive(PartialEq, Copy, Clone)]
#[allow(clippy::upper_case_acronyms)]
pub enum EnclaveErrorCode {
    EBLKSTATE = 0x4000_0003,
    EPAGENOTBLOCKED = 0x4000_000a,
    ENOTTRACKED = 0x4000_000b,
    EENCLAVEACT = 0x4000_000e,
    EENTRYEPOCHLOCKED = 0x4000_000f,
    EPREVTRKINCMPL = 0x4000_0011,
    EPAGEATTRIBUTESMISMATCH = 0x4000_0013,
    PAGENOTMODIFIABLE = 0x4000_0014,
    ECANCELRECLAIM = 0x4000_001d,
}

impl EnclaveErrorCode {
    pub fn as_string(&self) -> String {
        use EnclaveErrorCode::*;

        let msg = match self {
            EBLKSTATE => "Page is already in blocked state",
            EPAGENOTBLOCKED => "Page is not marked as blocked",
            ENOTTRACKED => "Tracking cycle isn't done",
            EENCLAVEACT => "Exists logical processors executing inside the enclave",
            EENTRYEPOCHLOCKED => "SECS locked for Entry Epoch update",
            EPREVTRKINCMPL => "Previous tracking cycle isn't done",
            EPAGEATTRIBUTESMISMATCH => "Page attribute mismatches",
            PAGENOTMODIFIABLE => {
                "Page cannot be modified because it is in the PENDING or MODIFIED state"
            }
            ECANCELRECLAIM => "Cancel reclaim EPC page",
        };
        String::from(msg)
    }

    pub fn code(&self) -> i32 {
        -(*self as u32 as i32)
    }
}

impl Default for SgxSecs {
    fn default() -> Self {
        unsafe { MaybeUninit::zeroed().assume_init() }
    }
}

impl Default for SgxTcs {
    fn default() -> Self {
        unsafe { MaybeUninit::zeroed().assume_init() }
    }
}

impl Default for SigStructHeader {
    fn default() -> Self {
        unsafe { MaybeUninit::zeroed().assume_init() }
    }
}

impl Default for SigStructKey {
    fn default() -> Self {
        unsafe { MaybeUninit::zeroed().assume_init() }
    }
}

impl Default for SigStructBody {
    fn default() -> Self {
        unsafe { MaybeUninit::zeroed().assume_init() }
    }
}

impl Default for SigStructBuffer {
    fn default() -> Self {
        unsafe { MaybeUninit::zeroed().assume_init() }
    }
}

impl Default for SigStruct {
    fn default() -> Self {
        unsafe { MaybeUninit::zeroed().assume_init() }
    }
}

impl Debug for SgxPcmd {
    fn fmt(&self, f: &mut Formatter) -> Result {
        f.debug_struct("SgxPcmd")
            .field("sec_info", &self.sec_info)
            .field("mac", &self.mac)
            .finish()
    }
}

impl Debug for SgxSecInfo {
    fn fmt(&self, f: &mut Formatter) -> Result {
        f.debug_struct("SgxSecInfo")
            .field("flags", &self.flags)
            .field("page_type", &self.page_type)
            .finish()
    }
}

impl Debug for SgxSecs {
    fn fmt(&self, f: &mut Formatter) -> Result {
        f.debug_struct("SgxSecs")
            .field("size", &self.size)
            .field("base_addr", &self.base_addr)
            .field("ssa_frame_size", &self.ssa_frame_size)
            .field("misc_select", &self.misc_select)
            .field("ms_buf_size", &self.ms_buf_size)
            .field("attributes", &self.attributes)
            .field("mr_enclave", &self.mr_enclave)
            .field("mr_signer", &self.mr_signer)
            .field("config_id", &self.config_id)
            .field("isv_prod_id", &self.isv_prod_id)
            .field("isv_svn", &self.isv_svn)
            .field("config_svn", &self.config_svn)
            .finish()
    }
}

impl Debug for SgxTcs {
    fn fmt(&self, f: &mut Formatter) -> Result {
        f.debug_struct("SgxTcs")
            .field("stage", &self.stage)
            .field("flags", &self.flags)
            .field("ossa", &self.ossa)
            .field("cssa", &self.cssa)
            .field("nssa", &self.nssa)
            .field("oentry", &self.oentry)
            .field("aep", &self.aep)
            .field("ofs_base", &self.ofs_base)
            .field("ogs_base", &self.ogs_base)
            .field("fs_limit", &self.fs_limit)
            .field("gs_limit", &self.gs_limit)
            .finish()
    }
}

impl Debug for SigStructHeader {
    fn fmt(&self, f: &mut Formatter) -> Result {
        f.debug_struct("SigStructHeader")
            .field("header1", &self.header1)
            .field("types", &self.types)
            .field("module_vendor", &self.module_vendor)
            .field("date", &self.date)
            .field("header2", &self.header2)
            .field("hw_version", &self.hw_version)
            .finish()
    }
}

impl Debug for SigStructKey {
    fn fmt(&self, f: &mut Formatter) -> Result {
        f.debug_struct("SigStructKey")
            .field("modules", &self.modules)
            .field("exponent", &self.exponent)
            .field("signature", &self.signature)
            .finish()
    }
}

impl Debug for SigStructBody {
    fn fmt(&self, f: &mut Formatter) -> Result {
        f.debug_struct("SigStructBody")
            .field("misc_select", &self.misc_select)
            .field("misc_mask", &self.misc_mask)
            .field("isv_family_id", &self.isv_family_id)
            .field("attributes", &self.attributes)
            .field("attributes_mask", &self.attributes_mask)
            .field("mrenclave", &self.mr_enclave)
            .field("isvext_prod_id", &self.isvext_prod_id)
            .field("isv_prod_id", &self.isv_prod_id)
            .field("isvsvn", &self.isv_svn)
            .finish()
    }
}

impl Debug for SigStructBuffer {
    fn fmt(&self, f: &mut Formatter) -> Result {
        f.debug_struct("SigStructKey")
            .field("q1", &self.q1)
            .field("q2", &self.q2)
            .finish()
    }
}

impl Debug for SigStruct {
    fn fmt(&self, f: &mut Formatter) -> Result {
        f.debug_struct("SigStruct")
            .field("header", &self.header)
            .field("key", &self.key)
            .field("body", &self.body)
            .field("buffer", &self.buffer)
            .finish()
    }
}
