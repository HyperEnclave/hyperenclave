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

#![allow(dead_code)]

use super::VirtAddr;
use core::mem::MaybeUninit;

#[repr(transparent)]
pub struct Mmio<T> {
    value: MaybeUninit<T>,
}

impl<T> Mmio<T> {
    /// # Safety
    ///
    /// This function is unsafe because `base_addr` may be an arbitrary address.
    pub unsafe fn from_base_as<'a, R>(base_addr: VirtAddr) -> &'a mut R {
        assert_eq!(base_addr % core::mem::size_of::<T>(), 0);
        &mut *(base_addr as *mut R)
    }

    /// # Safety
    ///
    /// This function is unsafe because `base_addr` may be an arbitrary address.
    pub unsafe fn from_base<'a>(base_addr: VirtAddr) -> &'a mut Self {
        Self::from_base_as(base_addr)
    }

    pub fn add<'a>(&self, offset: usize) -> &'a mut Self {
        unsafe {
            Self::from_base(self.value.as_ptr() as usize + offset * core::mem::size_of::<T>())
        }
    }

    pub fn read(&self) -> T {
        unsafe { core::ptr::read_volatile(self.value.as_ptr()) }
    }

    pub fn write(&mut self, value: T) {
        unsafe { core::ptr::write_volatile(self.value.as_mut_ptr(), value) };
    }

    pub fn get_addr(&self) -> VirtAddr {
        self.value.as_ptr() as VirtAddr
    }
}
