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

//! Implementations for field operations on the field of order `MODULO_P`
//!
//! The underlying struct is `U64x4`
use basic::cell::u64x4::*;
use basic::random::Rng;
use core::fmt;
use core::fmt::Display;
use core::ops::{Add, Div, Mul, Neg, Sub};

/// Modulus
pub const MODULO_P: U64x4 = U64x4 {
    value: [
        0xFFFFFFFFFFFFFFFF,
        0xFFFFFFFF00000000,
        0xFFFFFFFFFFFFFFFF,
        0xFFFFFFFEFFFFFFFF,
    ],
};

/// The remainder of `1 << 256` in the field
const RHO_P: U64x4 = U64x4 {
    value: [
        0x0000000000000001,
        0x00000000FFFFFFFF,
        0x0000000000000000,
        0x0000000100000000,
    ],
};

/// Inverse of 2
pub const INV_2P: FieldElement = FieldElement {
    num: U64x4 {
        value: [
            0x8000000000000000,
            0xFFFFFFFF80000000,
            0xFFFFFFFFFFFFFFFF,
            0x7FFFFFFF7FFFFFFF,
        ],
    },
};

impl Display for FieldElement {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "{}", self.num)
    }
}

/// A `FieldElement` represents an element of the prime field of order `MODULO_P`
///
/// # Note
/// The underlying implementation uses functionality prvided by `U64x4`.
///
/// This type should not be used outside of the module `sm2`.
#[derive(Copy, Clone, Debug)]
pub struct FieldElement {
    // the numerical value
    pub num: U64x4,
}

impl FieldElement {
    /// Construct an element directly from `U64x4`
    pub fn new(num: U64x4) -> Self {
        to_mod_p(num)
    }

    /// Construct an element from 4 `u64`'s
    pub fn from_u64(value: [u64; 4]) -> Self {
        to_mod_p(U64x4 { value })
    }

    /// Construct an element from 8 `u32`'s
    pub fn from_u32(value: [u32; 8]) -> Self {
        to_mod_p(U64x4::from_u32(value))
    }

    /// A wrapper method for accessing the `u64` blocks
    pub fn value(self, i: usize) -> u64 {
        self.num.value[i]
    }

    /// Return a random element from the field
    pub fn random() -> Self {
        let mut rng = Rng::new();
        FieldElement::from_u64([
            rng.next_u64(),
            rng.next_u64(),
            rng.next_u64(),
            rng.next_u64(),
        ])
    }
}

impl Add for FieldElement {
    type Output = Self;

    fn add(self, rhs: Self) -> Self {
        let (mut m, mut overflow_flag) = U64x4::add_no_mod(self.num, rhs.num);

        //overflow
        while overflow_flag {
            let rst = U64x4::add_no_mod(RHO_P, m);
            m = rst.0;
            overflow_flag = rst.1;
        }

        to_mod_p(m)
    }
}

impl Neg for FieldElement {
    type Output = Self;

    fn neg(self) -> Self {
        Self::new(MODULO_P - to_mod_p(self.num).num)
    }
}

impl Sub for FieldElement {
    type Output = Self;

    fn sub(self, rhs: Self) -> Self {
        self + (-rhs)
    }
}

impl Mul for FieldElement {
    type Output = Self;

    fn mul(self, rhs: Self) -> Self {
        #[inline(always)]
        fn helper_mul(x: u64, y: u64) -> (u128, u128) {
            /* a helper overflowing multiplication for u64 */
            let z: u128 = u128::from(x) * u128::from(y);
            let carry = z >> 64;
            let rst = z ^ (carry << 64);

            (rst, carry)
        }

        fn raw_mul(x: U64x4, y: U64x4) -> [u64; 8] {
            /* Perform long multiplication */
            let mut result: [u64; 8] = [0; 8];
            let mut carry: u128 = 0;

            // for each result block
            for (block_i, cell) in result.iter_mut().enumerate().take(7) {
                // temporary value
                let mut cur: u128 = carry;
                carry = 0;

                // enumerate each block of y
                let low = if block_i > 3 { block_i - 3 } else { 0 };
                let high = if block_i > 3 { 3 } else { block_i };

                for y_i in low..=high {
                    let (rst, c) = helper_mul(x.value[block_i - y_i], y.value[y_i]);
                    carry += c;
                    cur += rst;
                }

                // check addition overlow carry
                let c = cur >> 64;
                carry += c;

                *cell = (cur ^ (c << 64)) as u64;
            }
            result[7] = carry as u64;

            result
        }

        fn helper_split_u64(x: u64) -> (u32, u32) {
            let high = x >> 32;
            let low = x ^ (high << 32);
            (low as u32, high as u32)
        }

        fn reduce(n: [u64; 8]) -> FieldElement {
            /* fast reduction 256bit to 128bit*/
            /* ref: http://cacr.uwaterloo.ca/techreports/1999/corr99-39.pdf */

            // first split the input
            let mut a: [u32; 16] = [0; 16];
            for i in 0..8 {
                let (low, high) = helper_split_u64(n[i]);
                a[2 * i] = low;
                a[(2 * i) ^ 1] = high;
            }

            // prepare the summands
            // given by LFSR with [1,0,0,0,1,-1,0,1] and proper re-combination
            // of digits
            let s = FieldElement::from_u64([n[0], n[1], n[2], n[3]]); // lower parts of n

            // the following should be added twice (suffix d)
            let s15_d = FieldElement::from_u32([a[15], a[15], 0, 0, 0, a[15], 0, a[15]]);
            let s14_d = FieldElement::from_u32([a[14], a[14], 0, 0, a[14], 0, 0, a[14]]);
            let s13_d = FieldElement::from_u32([a[13], 0, 0, a[13], 0, 0, 0, a[13]]);
            let s12_d = FieldElement::from_u32([0, 0, 0, 0, 0, 0, 0, a[12]]);
            // find the sum
            let sum_d = (s15_d + s14_d) + (s13_d + s12_d);

            // find other sum (hard coded by sight)
            let s8_13 = FieldElement::from_u32([a[8], a[13], 0, a[8], a[13], a[13], 0, a[8]]);
            let s9_14 = FieldElement::from_u32([a[9], a[9], 0, a[14], a[9], a[14], a[14], a[9]]);
            let s10_12 = FieldElement::from_u32([a[10], a[10], 0, a[12], a[12], a[10], 0, a[10]]);
            let s11 = FieldElement::from_u32([a[11], a[11], 0, a[11], 0, 0, a[11], a[11]]);
            let s15_12 = FieldElement::from_u32([a[12], a[12], 0, a[15], a[15], 0, a[15], a[15]]);

            // sum all the stuffs together
            let s = (s + sum_d) + ((s8_13 + s9_14) + (s10_12 + s11)) + (s15_12 + sum_d);

            // find the subtrahend
            let subtra: u64 =
                u64::from(a[8]) + u64::from(a[9]) + u64::from(a[13]) + u64::from(a[14]);
            let upper = subtra >> 32;
            let lower = subtra ^ (upper << 32);

            let s = s - FieldElement::from_u32([0, 0, lower as u32, upper as u32, 0, 0, 0, 0]);

            to_mod_p(s.num)
        }

        reduce(raw_mul(self.num, rhs.num))
    }
}

impl Div for FieldElement {
    type Output = Self;

    fn div(self, rhs: Self) -> Self {
        let q = get_mul_inv(rhs);
        self * q
    }
}

pub(crate) fn to_mod_p(mut num: U64x4) -> FieldElement {
    while num >= MODULO_P {
        num = num - MODULO_P;
    }

    FieldElement { num }
}

pub fn get_mul_inv(x: FieldElement) -> FieldElement {
    if x.num.equal_to_zero() {
        return FieldElement::from_u64([0, 0, 0, 0]);
    }

    let mut u = x.num;
    let mut v = MODULO_P;
    let mut x1 = U64x4::new(1, 0, 0, 0);
    let mut x2 = U64x4::zero();

    while (!u.equal_to_one()) && (!v.equal_to_one()) {
        while u.value[0] % 2 == 0 {
            u.right_shift_by_one();

            if x1.value[0] % 2 == 0 {
                x1.right_shift_by_one();
            } else {
                let (u, overflow_flag) = U64x4::add_no_mod(x1, MODULO_P);
                x1 = u;
                x1.right_shift_by_one();
                if overflow_flag {
                    x1.value[3] |= 0x8000000000000000;
                }
            }
        }

        while v.value[0] % 2 == 0 {
            v.right_shift_by_one();

            if x2.value[0] % 2 == 0 {
                x2.right_shift_by_one();
            } else {
                let (u, overflow_flag) = U64x4::add_no_mod(x2, MODULO_P);
                x2 = u;
                x2.right_shift_by_one();
                if overflow_flag {
                    x2.value[3] |= 0x8000000000000000;
                }
            }
        }

        if u >= v {
            u = (FieldElement::new(u) - FieldElement::new(v)).num;
            x1 = (FieldElement::new(x1) - FieldElement::new(x2)).num;
        } else {
            v = (FieldElement::new(v) - FieldElement::new(u)).num;
            x2 = (FieldElement::new(x2) - FieldElement::new(x1)).num;
        }
    }

    if u.equal_to_one() {
        to_mod_p(x1)
    } else {
        to_mod_p(x2)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_mul() {
        let ra = u64::from(Rng::new().next_u32());
        let rb = u64::from(Rng::new().next_u32());
        let (mut a, f1) = U64x4::add_no_mod(MODULO_P, U64x4::new(ra, 0, 0, 0));
        let (mut b, f2) = U64x4::add_no_mod(MODULO_P, U64x4::new(rb, 0, 0, 0));
        a = if f1 { a + RHO_P } else { a };
        b = if f2 { b + RHO_P } else { b };
        let c = FieldElement::new(a) * FieldElement::new(b);
        assert_eq!(c.num, U64x4::new(ra * rb, 0, 0, 0));
    }

    #[test]
    fn test_inversion() {
        let a = FieldElement::random();
        let b = get_mul_inv(a);
        assert_eq!((a * b).num, U64x4::new(1, 0, 0, 0));
    }
}
