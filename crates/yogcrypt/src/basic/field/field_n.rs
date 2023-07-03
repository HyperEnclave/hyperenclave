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

//! Field operations on the field of order `MODULO_N`
//!
//! The underlying struct is `U64x4`.
use basic::cell::u64x4::*;

pub const MODULO_N: U64x4 = U64x4 {
    value: [
        0x53BBF40939D54123,
        0x7203DF6B21C6052B,
        0xFFFFFFFFFFFFFFFF,
        0xFFFFFFFEFFFFFFFF,
    ],
};
const RHO_N: U64x4 = U64x4 {
    value: [
        0xAC440BF6C62ABEDD,
        0x8DFC2094DE39FAD4,
        0x0000000000000000,
        0x0000000100000000,
    ],
};
const RHO_N2: U64x4 = U64x4 {
    value: [
        0x901192af7c114f20,
        0x3464504ade6fa2fa,
        0x620fc84c3affe0d4,
        0x1eb5e412a22b3d3b,
    ],
};

macro_rules! overflowing_add {
    ($x:expr, $y:expr, $result:ident, $overflow_flag:ident) => {
        let car = if $overflow_flag { 1 } else { 0 };

        let r1 = u64::overflowing_add($x, $y);
        let r2 = u64::overflowing_add(r1.0, car);
        $result = r2.0;
        $overflow_flag = r1.1 | r2.1;
    };
}

pub(crate) fn to_mod_n(mut x: U64x4) -> U64x4 {
    while x >= MODULO_N {
        x = x - MODULO_N;
    }

    x
}

pub fn get_add_inv_mod_n(x: U64x4) -> U64x4 {
    MODULO_N - x
}

pub fn get_mul_inv_mod_n(x: U64x4) -> U64x4 {
    if x.equal_to_zero() {
        return U64x4::zero();
    }

    let mut u = x;
    let mut v = MODULO_N;
    let mut x1 = U64x4::new(1, 0, 0, 0);
    let mut x2 = U64x4::zero();

    while (!u.equal_to_one()) && (!v.equal_to_one()) {
        while u.value[0] % 2 == 0 {
            u.right_shift_by_one();

            if x1.value[0] % 2 == 0 {
                x1.right_shift_by_one();
            } else {
                let (u, overflow_flag) = U64x4::add_no_mod(x1, MODULO_N);
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
                let (u, overflow_flag) = U64x4::add_no_mod(x2, MODULO_N);
                x2 = u;
                x2.right_shift_by_one();
                if overflow_flag {
                    x2.value[3] |= 0x8000000000000000;
                }
            }
        }

        if u >= v {
            u = sub_mod_n(u, v);
            x1 = sub_mod_n(x1, x2);
        } else {
            v = sub_mod_n(v, u);
            x2 = sub_mod_n(x2, x1);
        }
    }

    if u.equal_to_one() {
        while x1 >= MODULO_N {
            x1 = x1 - MODULO_N;
        }
        x1
    } else {
        while x2 >= MODULO_N {
            x2 = x2 - MODULO_N;
        }
        x2
    }
}

pub fn add_mod_n(x: U64x4, y: U64x4) -> U64x4 {
    let res0: u64;
    let res1: u64;
    let res2: u64;
    let res3: u64;
    let mut overflow_flag = false;

    overflowing_add!(x.value[0], y.value[0], res0, overflow_flag);
    overflowing_add!(x.value[1], y.value[1], res1, overflow_flag);
    overflowing_add!(x.value[2], y.value[2], res2, overflow_flag);
    overflowing_add!(x.value[3], y.value[3], res3, overflow_flag);

    let mut m = U64x4 {
        value: [res0, res1, res2, res3],
    };

    //overflow
    if overflow_flag {
        m = add_mod_n(RHO_N, m);
    }

    if m >= MODULO_N {
        m - MODULO_N
    } else {
        m
    }
}

pub fn sub_mod_n(x: U64x4, y: U64x4) -> U64x4 {
    add_mod_n(x, get_add_inv_mod_n(y))
}

pub fn mul_mod_n(x: U64x4, y: U64x4) -> U64x4 {
    let x_bar = mont_mul(x, RHO_N2);
    let y_bar = mont_mul(y, RHO_N2);
    let t_bar = mont_mul(x_bar, y_bar);
    mont_red(t_bar)
}

fn mont_mul(x: U64x4, y: U64x4) -> U64x4 {
    let mut z = U64x4::zero();

    for i in 0..256 {
        z = if y.get(i) == 1 { add_mod_n(z, x) } else { z };

        if z.value[0] % 2 == 1 {
            let (u, overflow_flag) = U64x4::add_no_mod(z, MODULO_N);
            z = u;
            z.right_shift_by_one();
            if overflow_flag {
                z.value[3] |= 0x8000000000000000;
            }
        } else {
            z.right_shift_by_one();
        }
    }

    if z >= MODULO_N {
        z - MODULO_N
    } else {
        z
    }
}

// get t * 2^(-256) mod p
fn mont_red(mut t: U64x4) -> U64x4 {
    for _ in 0..256 {
        if t.value[0] % 2 == 1 {
            let (u, overflow_flag) = U64x4::add_no_mod(t, MODULO_N);
            t = u;
            t.right_shift_by_one();
            if overflow_flag {
                t.value[3] |= 0x8000000000000000;
            }
        } else {
            t.right_shift_by_one();
        }
    }

    if t >= MODULO_N {
        add_mod_n(t, MODULO_N)
    } else {
        t
    }
}
