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

//! An implementation of the SM3 cryptographic hash standard.
//!
//! ## Usage
//! ```
//! extern crate yogcrypt;
//! use yogcrypt::sm3::{sm3_enc};
//!
//! let msg = b"abcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcd";
//!
//! let hash = sm3_enc(msg);
//! assert_eq!(
//!     hash,
//!     [
//!         0xdebe9ff9, 0x2275b8a1, 0x38604889, 0xc18e5a4d, 0x6fdb70e5, 0x387e5765, 0x293dcba3,
//!         0x9c0c5732
//!     ]
//! );
//! ```
//!
//! ## Reference
//! Most variable's name in the source code are in accordance with the document.
//!
//! [OSCCA: SM3 document](http://www.oscca.gov.cn/sca/xxgk/2010-12/17/1002389/files/302a3ada057c4a73830536d03e683110.pdf)

use basic::util::bytes_to_u32_blocks;
use core::num::Wrapping;

pub type HashValue = [u32; 8];
static IV: [u32; 8] = [
    0x7380166f, 0x4914b2b9, 0x172442d7, 0xda8a0600, 0xa96f30bc, 0x163138aa, 0xe38dee4d, 0xb0fb0e4e,
];

#[inline]
fn sm3_t(j: u32) -> u32 {
    if j <= 15 {
        0x79cc4519
    } else {
        0x7a879d8a
    }
}

#[inline]
fn sm3_ff(x: u32, y: u32, z: u32, j: u32) -> u32 {
    if j <= 15 {
        x ^ y ^ z
    } else {
        (x & y) | (x & z) | (y & z)
    }
}

#[inline]
fn sm3_gg(x: u32, y: u32, z: u32, j: u32) -> u32 {
    if j <= 15 {
        x ^ y ^ z
    } else {
        (x & y) | ((!x) & z)
    }
}

#[inline]
fn sm3_p_0(x: u32) -> u32 {
    x ^ x.rotate_left(9) ^ x.rotate_left(17)
}

#[inline]
fn sm3_p_1(x: u32) -> u32 {
    x ^ x.rotate_left(15) ^ x.rotate_left(23)
}

fn sm3_extend(b: [u32; 16]) -> ([u32; 68], [u32; 64]) {
    let mut w: [u32; 68] = [0; 68];
    let mut w_p: [u32; 64] = [0; 64];
    w[..16].clone_from_slice(&b[..16]);
    for j in 16..68 {
        w[j] = sm3_p_1(w[j - 16] ^ w[j - 9] ^ w[j - 3].rotate_left(15))
            ^ w[j - 13].rotate_left(7)
            ^ w[j - 6];
    }
    for j in 0..64 {
        w_p[j] = w[j] ^ w[j + 4];
    }

    (w, w_p)
}

fn sm3_cf(vi: [u32; 8], bi: [u32; 16]) -> [u32; 8] {
    let ws = sm3_extend(bi);
    let w = ws.0;
    let w_p = ws.1;

    let mut a = vi[0];
    let mut b = vi[1];
    let mut c = vi[2];
    let mut d = vi[3];
    let mut e = vi[4];
    let mut f = vi[5];
    let mut g = vi[6];
    let mut h = vi[7];

    let mut ss1;
    let mut ss2;
    let mut tt1;
    let mut tt2;

    for j in 0..64 {
        ss1 = (Wrapping(a.rotate_left(12)) + Wrapping(e) + Wrapping(sm3_t(j).rotate_left(j % 32)))
            .0
            .rotate_left(7);
        ss2 = ss1 ^ (a.rotate_left(12));
        tt1 = (Wrapping(sm3_ff(a, b, c, j))
            + Wrapping(d)
            + Wrapping(ss2)
            + Wrapping(w_p[j as usize]))
        .0;
        tt2 =
            (Wrapping(sm3_gg(e, f, g, j)) + Wrapping(h) + Wrapping(ss1) + Wrapping(w[j as usize]))
                .0;
        d = c;
        c = b.rotate_left(9);
        b = a;
        a = tt1;
        h = g;
        g = f.rotate_left(19);
        f = e;
        e = sm3_p_0(tt2);
    }

    let mut vs: [u32; 8] = [0; 8];
    vs[0] = a ^ vi[0];
    vs[1] = b ^ vi[1];
    vs[2] = c ^ vi[2];
    vs[3] = d ^ vi[3];
    vs[4] = e ^ vi[4];
    vs[5] = f ^ vi[5];
    vs[6] = g ^ vi[6];
    vs[7] = h ^ vi[7];

    vs
}

/// Compute the hash of the given message
pub fn sm3_enc(msg: &[u8]) -> HashValue {
    let (msg, bit_len) = bytes_to_u32_blocks(msg);
    sm3_enc_inner(&msg[..], bit_len)
}

/// Core function for sm3 with specified input length
pub(crate) fn sm3_enc_inner(msg: &[u32], prim_len: usize) -> HashValue {
    let mut msg_len = prim_len;
    msg_len += 1; // Add "1" to the end of msg

    // to long
    if msg_len % 512 > 448 {
        msg_len += 512 - (msg_len % 512) + 512; // modified to make the padding right
    } else {
        msg_len += 512 - msg_len % 512; //modified to make the padding right
    }

    let msg_len1: u32 = ((prim_len as u64) >> 32) as u32;
    let msg_len2: u32 = (prim_len & 0xFFFF_FFFF) as u32;

    // set V to IV
    let mut v: [u32; 8] = IV;

    // msg blocks' index;
    // the operations are the same except the last block
    for i in 0..msg_len / 512 {
        //println!("i={}",i);
        let mut b: [u32; 16] = [0; 16];

        // words' index in a block
        for j in 0..16 {
            if (i * 16 + j) < msg.len() {
                b[j] = msg[(i * 16 + j)];
            }
        }

        // add "1" somewhere in this block
        if prim_len >= 512 * i && prim_len < 512 * (i + 1) {
            let bias = prim_len % 512;

            let bias_of_word = bias / 32;
            let bias_of_bit = (bias % 32) as u32;
            b[bias_of_word] += 0x80000000u32.rotate_right(bias_of_bit);
        }

        // the last block should store the length of msg
        if i == (msg_len / 512 - 1) {
            b[14] = msg_len1;
            b[15] = msg_len2;
        }

        v = sm3_cf(v, b);
    }

    v
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test() {
        // the following examples are from the standard documentation
        // of SM3 found at http://www.oscca.gov.cn/sca/xxgk/bzgf.shtml
        let msg = b"abc";

        let hash = sm3_enc(msg);
        assert_eq!(
            hash,
            [
                0x66c7f0f4, 0x62eeedd9, 0xd1f2d46b, 0xdc10e4e2, 0x4167c487, 0x5cf2f7a2, 0x297da02b,
                0x8f4ba8e0
            ]
        );

        let msg = b"abcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcd";

        let hash = sm3_enc(msg);
        assert_eq!(
            hash,
            [
                0xdebe9ff9, 0x2275b8a1, 0x38604889, 0xc18e5a4d, 0x6fdb70e5, 0x387e5765, 0x293dcba3,
                0x9c0c5732
            ]
        );
    }
}
