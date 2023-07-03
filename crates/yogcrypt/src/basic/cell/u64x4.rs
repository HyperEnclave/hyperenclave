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

//! An internal class for 256-bit numbers
//!
//! **NOTE**: the 64-bits are stored in little endian
use core::fmt;
use core::fmt::Display;

use core::ops::{Add, Neg, Sub};
use core::ops::{BitAnd, BitOr, BitXor, Not};
use core::ops::{BitAndAssign, BitOrAssign, BitXorAssign};

use core::cmp::Ordering;

use basic::cell::u64x8::*;

use basic::random::Rng;

/// A 256-bit number represented using four `u64`'s.
///
/// ## Usage
/// ```no_run
///     extern crate yogcrypt;
///     use yogcrypt::sm2::*;
///
///     let some_num = U64x4::new(0xd8cb4986_918e9375, 0x3055dfcc_d2870256, 0x973ccca3_1d33bd55, 0xf6fed50c_fd14ede7);
/// ```
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub struct U64x4 {
    // value[0] is the lower order 64 bits
    pub value: [u64; 4],
}

macro_rules! overflowing_add {
    ($x:expr, $y:expr, $result:ident, $overflow_flag:ident) => {
        let car = if $overflow_flag { 1 } else { 0 };

        let r1 = u64::overflowing_add($x, $y);
        let r2 = u64::overflowing_add(r1.0, car);
        $result = r2.0;
        $overflow_flag = r1.1 | r2.1;
    };
}

impl U64x4 {
    /// Create a number with 4 64-bits, with x0 being the less significant digits
    pub fn new(x0: u64, x1: u64, x2: u64, x3: u64) -> Self {
        Self {
            value: [x0, x1, x2, x3],
        }
    }

    /// The representation for 0
    pub fn zero() -> Self {
        Self {
            value: [0, 0, 0, 0],
        }
    }

    /// Return a random 256-bit number
    pub fn random() -> Self {
        let mut rng = Rng::new();
        Self {
            value: [
                rng.next_u64(),
                rng.next_u64(),
                rng.next_u64(),
                rng.next_u64(),
            ],
        }
    }

    /// Construct the number from 8 `u32`
    pub fn from_u32(x: [u32; 8]) -> Self {
        Self {
            value: [
                (u64::from(x[1]) << 32) + u64::from(x[0]),
                (u64::from(x[3]) << 32) + u64::from(x[2]),
                (u64::from(x[5]) << 32) + u64::from(x[4]),
                (u64::from(x[7]) << 32) + u64::from(x[6]),
            ],
        }
    }

    /// Access the `i`-th lowest bit
    pub fn get(&self, i: usize) -> u64 {
        let n = i / 64;
        let x = i % 64;
        match n {
            0 => (self.value[0] >> x) % 2,
            1 => (self.value[1] >> x) % 2,
            2 => (self.value[2] >> x) % 2,
            3 => (self.value[3] >> x) % 2,
            _ => (panic!("unknown n")),
        }
    }
}

impl Display for U64x4 {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(
            f,
            "{:016X} {:016X} {:016X} {:016X}",
            self.value[3], self.value[2], self.value[1], self.value[0]
        )
    }
}

impl Not for U64x4 {
    type Output = Self;

    fn not(self) -> Self {
        Self {
            value: [
                !self.value[0],
                !self.value[1],
                !self.value[2],
                !self.value[3],
            ],
        }
    }
}

impl BitAnd for U64x4 {
    type Output = Self;

    fn bitand(self, rhs: Self) -> Self {
        Self {
            value: [
                self.value[0] & rhs.value[0],
                self.value[1] & rhs.value[1],
                self.value[2] & rhs.value[2],
                self.value[3] & rhs.value[3],
            ],
        }
    }
}

impl BitOr for U64x4 {
    type Output = Self;

    fn bitor(self, rhs: Self) -> Self {
        Self {
            value: [
                self.value[0] | rhs.value[0],
                self.value[1] | rhs.value[1],
                self.value[2] | rhs.value[2],
                self.value[3] | rhs.value[3],
            ],
        }
    }
}

impl BitXor for U64x4 {
    type Output = Self;

    fn bitxor(self, rhs: Self) -> Self {
        Self {
            value: [
                self.value[0] ^ rhs.value[0],
                self.value[1] ^ rhs.value[1],
                self.value[2] ^ rhs.value[2],
                self.value[3] ^ rhs.value[3],
            ],
        }
    }
}

impl BitAndAssign for U64x4 {
    fn bitand_assign(&mut self, rhs: Self) {
        self.value[0] &= rhs.value[0];
        self.value[1] &= rhs.value[1];
        self.value[2] &= rhs.value[2];
        self.value[3] &= rhs.value[3];
    }
}

impl BitOrAssign for U64x4 {
    fn bitor_assign(&mut self, rhs: Self) {
        self.value[0] |= rhs.value[0];
        self.value[1] |= rhs.value[1];
        self.value[2] |= rhs.value[2];
        self.value[3] |= rhs.value[3];
    }
}

impl BitXorAssign for U64x4 {
    fn bitxor_assign(&mut self, rhs: Self) {
        self.value[0] ^= rhs.value[0];
        self.value[1] ^= rhs.value[1];
        self.value[2] ^= rhs.value[2];
        self.value[3] ^= rhs.value[3];
    }
}

impl Neg for U64x4 {
    type Output = Self;

    fn neg(self) -> U64x4 {
        let mut x = self;

        if x.value[0] != 0 {
            x.value[0] = u64::wrapping_neg(x.value[0]);
            x.value[1] = !x.value[1];
            x.value[2] = !x.value[2];
            x.value[3] = !x.value[3];
        } else if x.value[1] != 0 {
            x.value[1] = u64::wrapping_neg(x.value[1]);
            x.value[2] = !x.value[2];
            x.value[3] = !x.value[3];
        } else if x.value[2] != 0 {
            x.value[2] = u64::wrapping_neg(x.value[2]);
            x.value[3] = !x.value[3];
        } else if x.value[3] != 0 {
            x.value[3] = u64::wrapping_neg(x.value[3]);
        }

        x
    }
}

impl Add for U64x4 {
    type Output = Self;

    fn add(self, rhs: U64x4) -> U64x4 {
        U64x4::add_no_mod(self, rhs).0
    }
}

impl Sub for U64x4 {
    type Output = Self;

    fn sub(self, rhs: U64x4) -> U64x4 {
        self + (-rhs)
    }
}

impl U64x4 {
    pub fn left_rotate_to_u64x8(self, sh: usize) -> U64x8 {
        let shn = sh / 64;
        let shx = sh % 64;

        let t = (64 - shx) as u32;

        let mut r = U64x8 {
            value: [
                0,
                if t != 64 { self.value[0] >> t } else { 0 },
                if t != 64 { self.value[1] >> t } else { 0 },
                if t != 64 { self.value[2] >> t } else { 0 },
                if t != 64 { self.value[3] >> t } else { 0 },
                0,
                0,
                0,
            ],
        };

        r.value[0] |= self.value[0] << shx;
        r.value[1] |= self.value[1] << shx;
        r.value[2] |= self.value[2] << shx;
        r.value[3] |= self.value[3] << shx;

        match shn {
            0 => (),
            1 => {
                r.value[5] = r.value[4];
                r.value[4] = r.value[3];
                r.value[3] = r.value[2];
                r.value[2] = r.value[1];
                r.value[1] = r.value[0];
                r.value[0] = 0;
            }
            2 => {
                r.value[5] = r.value[3];
                r.value[4] = r.value[2];
                r.value[3] = r.value[1];
                r.value[2] = r.value[0];
                r.value[1] = 0;
                r.value[0] = 0;
            }
            3 => {
                r.value[5] = r.value[2];
                r.value[4] = r.value[1];
                r.value[3] = r.value[0];
                r.value[2] = 0;
                r.value[1] = 0;
                r.value[0] = 0;
            }
            4 => {
                r.value[5] = r.value[1];
                r.value[4] = r.value[0];
                r.value[3] = 0;
                r.value[2] = 0;
                r.value[1] = 0;
                r.value[0] = 0;
            }
            _ => {
                panic!("cannot hold in yU64x8!");
            }
        };

        r
    }
}

impl U64x4 {
    pub fn left_shift_by_one(&mut self) {
        self.value[3] <<= 1;
        self.value[3] |= self.value[2] >> 63;
        self.value[2] <<= 1;
        self.value[2] |= self.value[1] >> 63;
        self.value[1] <<= 1;
        self.value[1] |= self.value[0] >> 63;
        self.value[0] <<= 1;
    }

    pub fn right_shift_by_one(&mut self) {
        self.value[0] >>= 1;
        self.value[0] |= self.value[1] << 63;
        self.value[1] >>= 1;
        self.value[1] |= self.value[2] << 63;
        self.value[2] >>= 1;
        self.value[2] |= self.value[3] << 63;
        self.value[3] >>= 1;
    }
}

impl Ord for U64x4 {
    fn cmp(&self, other: &Self) -> Ordering {
        if self.value[3] > other.value[3] {
            return Ordering::Greater;
        };
        if self.value[3] < other.value[3] {
            return Ordering::Less;
        };
        if self.value[2] > other.value[2] {
            return Ordering::Greater;
        };
        if self.value[2] < other.value[2] {
            return Ordering::Less;
        };
        if self.value[1] > other.value[1] {
            return Ordering::Greater;
        };
        if self.value[1] < other.value[1] {
            return Ordering::Less;
        };
        if self.value[0] > other.value[0] {
            return Ordering::Greater;
        };
        if self.value[0] < other.value[0] {
            return Ordering::Less;
        };
        Ordering::Equal
    }
}

impl PartialOrd for U64x4 {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(&other))
    }
}
impl U64x4 {
    pub fn equal_to_zero(&self) -> bool {
        self.value[0] == 0 && self.value[1] == 0 && self.value[2] == 0 && self.value[3] == 0
    }

    pub fn equal_to_one(&self) -> bool {
        self.value[0] == 1 && self.value[1] == 0 && self.value[2] == 0 && self.value[3] == 0
    }
}

impl U64x4 {
    /// 256-bit addition with carry bit
    pub fn add_no_mod(x: U64x4, y: U64x4) -> (U64x4, bool) {
        let res0: u64;
        let res1: u64;
        let res2: u64;
        let res3: u64;
        let mut overflow_flag = false;

        overflowing_add!(x.value[0], y.value[0], res0, overflow_flag);
        overflowing_add!(x.value[1], y.value[1], res1, overflow_flag);
        overflowing_add!(x.value[2], y.value[2], res2, overflow_flag);
        overflowing_add!(x.value[3], y.value[3], res3, overflow_flag);

        let m = U64x4 {
            value: [res0, res1, res2, res3],
        };

        (m, overflow_flag)
    }
}
