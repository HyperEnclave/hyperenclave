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

use alloc::string::String;
use core::fmt::{Debug, Formatter, Result};

/// POSIX errno
#[repr(u32)]
#[derive(Clone, Copy, Debug, PartialEq)]
#[allow(dead_code, clippy::upper_case_acronyms)]
pub enum HvErrorNum {
    EPERM = 1,
    ENOENT = 2,
    EIO = 5,
    E2BIG = 7,
    ENOMEM = 12,
    EFAULT = 14,
    EBUSY = 16,
    EEXIST = 17,
    ENODEV = 19,
    EINVAL = 22,
    ERANGE = 34,
    ENOSYS = 38,
}

pub struct HvError {
    num: HvErrorNum,
    loc_file: &'static str,
    loc_line: u32,
    loc_col: u32,
    msg: Option<String>,
}

pub type HvResult<T = ()> = core::result::Result<T, HvError>;

impl HvErrorNum {
    pub fn as_str(&self) -> &'static str {
        use HvErrorNum::*;
        match *self {
            EPERM => "Operation not permitted",
            ENOENT => "No such file or directory",
            EIO => "I/O error",
            E2BIG => "Argument list too long",
            ENOMEM => "Out of memory",
            EFAULT => "Bad address",
            EBUSY => "Device or resource busy",
            EEXIST => "File exists",
            ENODEV => "No such device",
            EINVAL => "Invalid argument",
            ERANGE => "Math result not representable",
            ENOSYS => "Function not implemented",
        }
    }

    pub fn code(&self) -> i32 {
        -(*self as u32 as i32)
    }
}

impl HvError {
    pub fn new(
        num: HvErrorNum,
        loc_file: &'static str,
        loc_line: u32,
        loc_col: u32,
        msg: Option<String>,
    ) -> Self {
        Self {
            num,
            loc_file,
            loc_line,
            loc_col,
            msg,
        }
    }

    pub fn num(&self) -> HvErrorNum {
        self.num
    }

    pub fn loc_line(&self) -> u32 {
        self.loc_line
    }

    pub fn loc_col(&self) -> u32 {
        self.loc_col
    }

    pub fn loc_file(&self) -> &'static str {
        self.loc_file
    }

    pub fn msg(&self) -> Option<String> {
        self.msg.as_ref().map(|string| string.into())
    }

    pub fn code(&self) -> i32 {
        self.num.code()
    }
}

impl Debug for HvError {
    fn fmt(&self, f: &mut Formatter) -> Result {
        write!(
            f,
            "[{}:{}:{}] {}",
            self.loc_file,
            self.loc_line,
            self.loc_col,
            self.num.as_str()
        )?;
        if let Some(ref msg) = self.msg {
            write!(f, ": {}", msg)?;
        }
        Ok(())
    }
}

#[macro_export]
macro_rules! hv_err {
    ($num: ident) => {{
        use crate::error::{HvError, HvErrorNum::*};
        HvError::new($num, file!(), line!(), column!(), None)
    }};
    ($num: ident, $msg: expr) => {{
        use crate::error::{HvError, HvErrorNum::*};
        HvError::new($num, file!(), line!(), column!(), Some($msg.into()))
    }};
}

#[macro_export]
macro_rules! hv_result_err {
    ($num: ident) => {
        Err(hv_err!($num))
    };
    ($num: ident, $msg: expr) => {
        Err(hv_err!($num, $msg))
    };
}
