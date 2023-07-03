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

use core::fmt;
use core::fmt::Display;

use core::ops::{BitAnd, BitOr, BitXor, Not};
use core::ops::{BitAndAssign, BitOrAssign, BitXorAssign};

#[derive(Copy, Clone)]
pub struct U64x8 {
    pub value: [u64; 8],
}

impl U64x8 {
    pub fn new(x: [u64; 8]) -> Self {
        Self { value: x }
    }
}

impl Display for U64x8 {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(
            f,
            "{:016X} {:016X} {:016X} {:016X} {:016X} {:016X} {:016X} {:016X}",
            self.value[7],
            self.value[6],
            self.value[5],
            self.value[4],
            self.value[3],
            self.value[2],
            self.value[1],
            self.value[0]
        )
    }
}

impl Not for U64x8 {
    type Output = Self;

    fn not(self) -> Self {
        Self {
            value: [
                !self.value[0],
                !self.value[1],
                !self.value[2],
                !self.value[3],
                !self.value[4],
                !self.value[5],
                !self.value[6],
                !self.value[7],
            ],
        }
    }
}

impl BitAnd for U64x8 {
    type Output = Self;

    fn bitand(self, rhs: Self) -> Self {
        Self {
            value: [
                self.value[0] & rhs.value[0],
                self.value[1] & rhs.value[1],
                self.value[2] & rhs.value[2],
                self.value[3] & rhs.value[3],
                self.value[4] & rhs.value[4],
                self.value[5] & rhs.value[5],
                self.value[6] & rhs.value[6],
                self.value[7] & rhs.value[7],
            ],
        }
    }
}

impl BitOr for U64x8 {
    type Output = Self;

    fn bitor(self, rhs: Self) -> Self {
        Self {
            value: [
                self.value[0] | rhs.value[0],
                self.value[1] | rhs.value[1],
                self.value[2] | rhs.value[2],
                self.value[3] | rhs.value[3],
                self.value[4] | rhs.value[4],
                self.value[5] | rhs.value[5],
                self.value[6] | rhs.value[6],
                self.value[7] | rhs.value[7],
            ],
        }
    }
}

impl BitXor for U64x8 {
    type Output = Self;

    fn bitxor(self, rhs: Self) -> Self {
        Self {
            value: [
                self.value[0] ^ rhs.value[0],
                self.value[1] ^ rhs.value[1],
                self.value[2] ^ rhs.value[2],
                self.value[3] ^ rhs.value[3],
                self.value[4] ^ rhs.value[4],
                self.value[5] ^ rhs.value[5],
                self.value[6] ^ rhs.value[6],
                self.value[7] ^ rhs.value[7],
            ],
        }
    }
}

impl BitAndAssign for U64x8 {
    fn bitand_assign(&mut self, rhs: Self) {
        self.value[0] &= rhs.value[0];
        self.value[1] &= rhs.value[1];
        self.value[2] &= rhs.value[2];
        self.value[3] &= rhs.value[3];
        self.value[4] &= rhs.value[4];
        self.value[5] &= rhs.value[5];
        self.value[6] &= rhs.value[6];
        self.value[7] &= rhs.value[7];
    }
}

impl BitOrAssign for U64x8 {
    fn bitor_assign(&mut self, rhs: Self) {
        self.value[0] |= rhs.value[0];
        self.value[1] |= rhs.value[1];
        self.value[2] |= rhs.value[2];
        self.value[3] |= rhs.value[3];
        self.value[4] |= rhs.value[4];
        self.value[5] |= rhs.value[5];
        self.value[6] |= rhs.value[6];
        self.value[7] |= rhs.value[7];
    }
}

impl BitXorAssign for U64x8 {
    fn bitxor_assign(&mut self, rhs: Self) {
        self.value[0] ^= rhs.value[0];
        self.value[1] ^= rhs.value[1];
        self.value[2] ^= rhs.value[2];
        self.value[3] ^= rhs.value[3];
        self.value[4] ^= rhs.value[4];
        self.value[5] ^= rhs.value[5];
        self.value[6] ^= rhs.value[6];
        self.value[7] ^= rhs.value[7];
    }
}
