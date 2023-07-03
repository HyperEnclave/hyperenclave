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

use crate::enclave::sgx::{GprSgx, MiscSgx, SSA_FRAME_SIZE};
use crate::error::HvResult;
use core::convert::TryInto;
use core::fmt::{Debug, Formatter, Result};

/// XSAVE legacy region: 512 bytes
pub const XSAVE_LEGACY_REGION_SIZE: usize = 512;
/// XSAVE header: 64 bytes
pub const XSAVE_HEADER_SIZE: usize = 64;
/// XSAVE region: SSA_FRAME_SIZE - sizeof(MiscSgx) - sizeof(GprSgx) = 3896 bytes
pub const XSAVE_REGION_SIZE: usize =
    SSA_FRAME_SIZE - core::mem::size_of::<MiscSgx>() - core::mem::size_of::<GprSgx>();

pub static XSAVE_SYNTHETIC_STATE: XsaveSynteticStateRegion = XsaveSynteticStateRegion::new();

#[repr(C, align(4096))]
pub struct XsaveSynteticStateRegion(XsaveRegion);

impl XsaveSynteticStateRegion {
    pub const fn new() -> Self {
        Self(XsaveRegion::new_synthetic_state())
    }

    pub fn restore(&self, xfrm: u64) {
        self.0.restore(xfrm)
    }
}

#[repr(C)]
pub struct XsaveRegion([u8; XSAVE_REGION_SIZE]);

impl XsaveRegion {
    pub const fn new_synthetic_state() -> Self {
        Self([0; XSAVE_REGION_SIZE])
    }

    pub fn save(&mut self, xfrm: u64) {
        unsafe { core::arch::x86_64::_xsave(self.0.as_mut_ptr(), xfrm) };
    }

    pub fn restore(&self, xfrm: u64) {
        unsafe { core::arch::x86_64::_xrstor(self.0.as_ptr(), xfrm) };
    }

    pub fn validate_at_resume(&self, xfrm: u64) -> HvResult {
        let xstate_bv = &self.0[512..520].try_into().unwrap();
        let xstate_bv = u64::from_ne_bytes(*xstate_bv);
        if xstate_bv & xfrm != xstate_bv {
            return hv_result_err!(
                EINVAL,
                "XsaveRegion::validate_at_resume(): xstate_bv must be a subset of xfrm"
            );
        }

        let slice: &[u8; 16] = &self.0[520..536].try_into().unwrap();
        for i in (0..slice.len()).step_by(8) {
            let arr: [u8; 8] = slice[i..i + 8].try_into().unwrap();
            if u64::from_ne_bytes(arr) != 0 {
                return hv_result_err!(
                    EINVAL,
                    "XsaveRegion::validate_at_resume(): Offsets 520 - 535 of XSAVE area should be 0"
                );
            }
        }

        Ok(())
    }
}

impl Debug for XsaveRegion {
    fn fmt(&self, f: &mut Formatter) -> Result {
        f.debug_tuple("XsaveRegion")
            .field(unsafe { &core::mem::transmute::<_, [u8; XSAVE_REGION_SIZE]>(self.0) })
            .finish()
    }
}
