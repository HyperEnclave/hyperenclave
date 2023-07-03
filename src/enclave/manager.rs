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
use core::convert::Into;
use spin::RwLock;

use super::Enclave;

use crate::error::HvResult;

const MAX_ENCLAVE_NUM: usize = 32;

#[derive(Debug)]
pub struct EnclaveManager {
    enclaves: [RwLock<Option<Arc<Enclave>>>; MAX_ENCLAVE_NUM],
}

impl EnclaveManager {
    fn position(
        arr: &[RwLock<Option<Arc<Enclave>>>],
        enclave_id: usize,
    ) -> HvResult<(usize, Arc<Enclave>)> {
        for (idx, e) in arr.iter().enumerate() {
            if let Some(e) = e.read().as_ref() {
                if e.id == enclave_id {
                    return Ok((idx, e.clone()));
                }
            }
        }
        hv_result_err!(
            EFAULT,
            format!("Enclave with id {:#x} not found", enclave_id)
        )
    }

    pub fn add_enclave(&self, enclave: Arc<Enclave>) -> HvResult {
        if Self::position(&self.enclaves, enclave.id).is_ok() {
            return hv_result_err!(EEXIST, format!("Enclave with id {:#x} exists", enclave.id));
        }
        for e in self.enclaves.iter() {
            let mut e = e.write();
            if e.is_none() {
                *e = Some(enclave);
                return Ok(());
            }
        }
        hv_result_err!(ENOMEM, "No enough room for enclave")
    }

    pub fn find_enclave(&self, enclave_id: usize) -> HvResult<Arc<Enclave>> {
        let (_, enclave) = Self::position(&self.enclaves, enclave_id)?;
        Ok(enclave)
    }

    pub fn remove_enclave(&self, enclave_id: usize) -> HvResult {
        let (idx, enclave) = Self::position(&self.enclaves, enclave_id)?;
        if !enclave.is_in_destroy() {
            error!("Enclave must be in destroy state");
            return hv_result_err!(EINVAL, "Enclave must be in destroy state");
        }
        let epc_page_num = enclave.epc_page_num();
        if epc_page_num != 0 {
            error!("epc_page_num: {:?}", epc_page_num);
            return hv_result_err!(
                EBUSY,
                format!(
                    "Enclave's EPC page num({:?}) != 0, cannot remove the enclave, EPC leak may occur",
                    epc_page_num
                )
            );
        }
        *self.enclaves[idx].write() = None;
        Ok(())
    }
}

const BUFFER_LEN: usize = core::mem::size_of::<EnclaveManager>() / core::mem::size_of::<usize>();
static mut EMPTY_BUFFER: [usize; BUFFER_LEN] = [0; BUFFER_LEN];

pub static ENCLAVE_MANAGER: &EnclaveManager = unsafe { core::mem::transmute(&EMPTY_BUFFER) };
