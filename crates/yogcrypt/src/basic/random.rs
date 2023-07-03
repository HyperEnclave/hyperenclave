// Modified by Ant Group in 2023.

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

use core::cmp;
use core::fmt;
use core::mem;

global_asm!(include_str!("rand.S"), options(att_syntax));

#[inline]
fn getrandom(buf: &mut [u8]) {
    extern "C" {
        fn do_rdrand(rand: *mut u32) -> u32;
    }

    let mut rand_num = [0_u8; mem::size_of::<u32>()];
    let mut left_len = buf.len();
    let mut offset = 0_usize;

    while left_len > 0 {
        if unsafe { do_rdrand(&mut rand_num as *mut _ as *mut u32) } == 0 {
            core::intrinsics::abort()
        }

        let copy_len = cmp::min(left_len, mem::size_of::<u32>());
        buf[offset..offset + copy_len].copy_from_slice(&rand_num[..copy_len]);

        left_len -= copy_len;
        offset += copy_len;
    }
}

fn next_u32(fill_buf: &mut dyn FnMut(&mut [u8])) -> u32 {
    let mut buf: [u8; 4] = [0; 4];
    fill_buf(&mut buf);
    unsafe { mem::transmute::<[u8; 4], u32>(buf) }
}

fn next_u64(fill_buf: &mut dyn FnMut(&mut [u8])) -> u64 {
    let mut buf: [u8; 8] = [0; 8];
    fill_buf(&mut buf);
    unsafe { mem::transmute::<[u8; 8], u64>(buf) }
}

fn next_usize(fill_buf: &mut dyn FnMut(&mut [u8])) -> usize {
    let mut buf: [u8; mem::size_of::<usize>()] = [0; mem::size_of::<usize>()];
    fill_buf(&mut buf);
    unsafe { mem::transmute::<[u8; mem::size_of::<usize>()], usize>(buf) }
}

// A random number generator
pub struct Rng;

impl Rng {
    pub fn new() -> Rng {
        Rng
    }

    pub fn next_u32(&mut self) -> u32 {
        next_u32(&mut getrandom)
    }

    pub fn next_u64(&mut self) -> u64 {
        next_u64(&mut getrandom)
    }

    pub fn next_usize(&mut self) -> usize {
        next_usize(&mut getrandom)
    }

    pub fn fill_bytes(&mut self, buf: &mut [u8]) {
        getrandom(buf)
    }
}

impl fmt::Debug for Rng {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "Rng {{}}")
    }
}

impl Default for Rng {
    fn default() -> Self {
        Self::new()
    }
}
