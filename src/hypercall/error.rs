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

use alloc::string::{String, ToString};
use core::fmt::{Debug, Formatter, Result};

use crate::arch::EnclaveExceptionInfo;
use crate::enclave::sgx::EnclaveErrorCode;
use crate::error::{HvError, HvErrorNum};

pub enum HyperCallErrorType {
    HvError(HvErrorNum),
    EnclaveError(EnclaveErrorCode),
    Exception(EnclaveExceptionInfo),
}

impl HyperCallErrorType {
    fn as_string(&self) -> String {
        match &*self {
            HyperCallErrorType::HvError(hv_err_num) => hv_err_num.as_str().to_string(),
            HyperCallErrorType::EnclaveError(enclave_error_code) => enclave_error_code.as_string(),
            HyperCallErrorType::Exception(exceptio_info) => format!("{:?}", exceptio_info),
        }
    }
}

pub struct HyperCallError {
    error: HyperCallErrorType,
    loc_file: &'static str,
    loc_line: u32,
    loc_col: u32,
    msg: Option<String>,
}

pub type HyperCallResult<T = ()> = core::result::Result<T, HyperCallError>;

impl HyperCallError {
    pub fn new_from_exception(
        exception_info: EnclaveExceptionInfo,
        loc_file: &'static str,
        loc_line: u32,
        loc_col: u32,
        msg: Option<String>,
    ) -> Self {
        Self {
            error: HyperCallErrorType::Exception(exception_info),
            loc_file,
            loc_line,
            loc_col,
            msg,
        }
    }

    pub fn new_from_enclave_error(
        enclave_error_code: EnclaveErrorCode,
        loc_file: &'static str,
        loc_line: u32,
        loc_col: u32,
        msg: Option<String>,
    ) -> Self {
        Self {
            error: HyperCallErrorType::EnclaveError(enclave_error_code),
            loc_file,
            loc_line,
            loc_col,
            msg,
        }
    }

    pub fn error(&self) -> &HyperCallErrorType {
        &self.error
    }
}

impl From<HvError> for HyperCallError {
    fn from(err: HvError) -> Self {
        HyperCallError {
            error: HyperCallErrorType::HvError(err.num()),
            loc_file: err.loc_file(),
            loc_line: err.loc_line(),
            loc_col: err.loc_col(),
            msg: err.msg(),
        }
    }
}

impl Debug for HyperCallError {
    fn fmt(&self, f: &mut Formatter) -> Result {
        write!(
            f,
            "[{}:{}:{}] {}",
            self.loc_file,
            self.loc_line,
            self.loc_col,
            self.error.as_string()
        )?;
        if let Some(ref msg) = self.msg {
            write!(f, ": {}", msg)?;
        }
        Ok(())
    }
}

#[macro_export]
macro_rules! hypercall_excep_err {
    ($exception_info: expr) => {{
        use crate::hypercall::error::HyperCallError;
        HyperCallError::new_from_exception($exception_info, file!(), line!(), column!(), None)
    }};
    ($exception_info: expr, $msg: expr) => {{
        use crate::hypercall::error::HyperCallError;
        HyperCallError::new_from_exception(
            $exception_info,
            file!(),
            line!(),
            column!(),
            Some($msg.into()),
        )
    }};
}

#[macro_export]
macro_rules! hypercall_enclave_err {
    ($enclave_error_code: ident) => {{
        use crate::enclave::EnclaveErrorCode;
        use crate::hypercall::error::HyperCallError;
        HyperCallError::new_from_enclave_error(
            EnclaveErrorCode::$enclave_error_code,
            file!(),
            line!(),
            column!(),
            None,
        )
    }};
    ($enclave_error_code: ident, $msg: expr) => {{
        use crate::enclave::EnclaveErrorCode;
        use crate::hypercall::error::HyperCallError;
        HyperCallError::new_from_enclave_error(
            EnclaveErrorCode::$enclave_error_code,
            file!(),
            line!(),
            column!(),
            Some($msg.into()),
        )
    }};
}

#[macro_export]
macro_rules! hypercall_hv_err {
    ($hypercall_err_num: ident) => {{
        hv_err!($hypercall_err_num).into()
    }};
    ($hypercall_err_num: ident, $msg: expr) => {{
        hv_err!($hypercall_err_num, $msg).into()
    }};
}

#[macro_export]
macro_rules! hypercall_hv_err_result {
    ($hypercall_err_num: ident) => {{
        use crate::hypercall_hv_err;
        Err(hypercall_hv_err!($hypercall_err_num))
    }};
    ($hypercall_err_num: ident, $msg: expr) => {{
        use crate::hypercall_hv_err;
        Err(hypercall_hv_err!($hypercall_err_num, $msg))
    }};
}
