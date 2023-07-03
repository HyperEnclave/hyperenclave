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

//! A helper module for commonly used internal functions

use alloc::vec::Vec;

/// Convert bytes into `[u32]` blocks for internal representations.
///
/// ## Example
/// ``
/// let msg = b"abcde";
/// let (msg, bit_len) = bytes_to_u32_blocks(msg);
/// assert_eq!(msg, vec![0x61626364, 0x65000000]);
/// assert_eq!(bit_len, 40);
/// ``
pub fn bytes_to_u32_blocks(msg: &[u8]) -> (Vec<u32>, usize) {
    // bit length = msg.len() * 8
    let bit_len = msg.len() << 3;
    // length for [u32] is ceil(msg.len() / 4)
    let mut msg2: Vec<u32> = vec![];
    for index in 0..((msg.len() + 3) / 4) {
        #[inline(always)]
        fn group_as_u32(msg: &[u8], i: usize) -> u32 {
            #[inline(always)]
            fn unpack(o: Option<&u8>) -> u32 {
                match o {
                    None => 0u32,
                    Some(&a) => u32::from(a),
                }
            }
            let start = i * 4;
            (unpack(msg.get(start)) << 24)
                + (unpack(msg.get(start + 1)) << 16)
                + (unpack(msg.get(start + 2)) << 8)
                + unpack(msg.get(start + 3))
        }
        msg2.push(group_as_u32(msg, index));
    }
    (msg2, bit_len)
}

/// Converts representation of 128-bit number from `[u8;16]` to blocks of `[u32;8]`.
///
/// ## Example
/// ``
/// let key = b"Hello, World!123";
/// let u32_blocks = bytes_to_four_u32(key);
/// assert_eq!(u32_blocks, [1214606444, 1865162839, 1869769828, 556872243]);
/// ``
pub fn bytes_to_four_u32(b: &[u8; 16]) -> [u32; 4] {
    [
        (u32::from(b[0]) << 24)
            + (u32::from(b[1]) << 16)
            + (u32::from(b[2]) << 8)
            + u32::from(b[3]),
        (u32::from(b[4]) << 24)
            + (u32::from(b[5]) << 16)
            + (u32::from(b[6]) << 8)
            + u32::from(b[7]),
        (u32::from(b[8]) << 24)
            + (u32::from(b[9]) << 16)
            + (u32::from(b[10]) << 8)
            + u32::from(b[11]),
        (u32::from(b[12]) << 24)
            + (u32::from(b[13]) << 16)
            + (u32::from(b[14]) << 8)
            + u32::from(b[15]),
    ]
}

/// Converts representation of 128-bit number from `[u32;8]` to blocks of `[u8;16]`.
///
/// ## Example
/// ``
/// let u32_blocks = [1214606444, 1865162839, 1869769828, 556872243];
/// let key = four_u32_to_bytes(&u32_blocks);
/// assert_eq!(&key, b"Hello, World!123");
/// ``
pub fn four_u32_to_bytes(l: &[u32; 4]) -> [u8; 16] {
    [
        (l[0] >> 24) as u8,
        (l[0] >> 16) as u8,
        (l[0] >> 8) as u8,
        l[0] as u8,
        (l[1] >> 24) as u8,
        (l[1] >> 16) as u8,
        (l[1] >> 8) as u8,
        l[1] as u8,
        (l[2] >> 24) as u8,
        (l[2] >> 16) as u8,
        (l[2] >> 8) as u8,
        l[2] as u8,
        (l[3] >> 24) as u8,
        (l[3] >> 16) as u8,
        (l[3] >> 8) as u8,
        l[3] as u8,
    ]
}
