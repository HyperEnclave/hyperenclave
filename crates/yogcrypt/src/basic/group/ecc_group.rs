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

//! Elliptic curve group operations
//!
//! Underlying structs are `fieldElement` in `field_p.rs`.
use alloc::vec::Vec;
use basic::cell::u64x4::*;
use basic::field::field_p::*;
use core::fmt;
use core::fmt::Display;

/// A coordinate is an element from the field with order `MODULO_P`.
///
/// ## Usage
/// ```no_run
///     extern crate yogcrypt;
///     use yogcrypt::sm2::*;
///
///     let x = Coordinate::from_u64([0x7b706375_42fb998e, 0x00f78ba4_e992817f, 0x6fcbd376_2040ded0, 0xa06c2b7e_e7b810bd]);
/// ```
pub type Coordinate = FieldElement;

/// Coefficient a of the curves as in y^2 = x^3 + ax + b
pub const ECC_A: Coordinate = Coordinate {
    num: U64x4 {
        value: [
            0xFFFFFFFFFFFFFFFC,
            0xFFFFFFFF00000000,
            0xFFFFFFFFFFFFFFFF,
            0xFFFFFFFEFFFFFFFF,
        ],
    },
};

/// Coefficient b of the curves as in y^2 = x^3 + ax + b
pub const ECC_B: Coordinate = Coordinate {
    num: U64x4 {
        value: [
            0xDDBCBD414D940E93,
            0xF39789F515AB8F92,
            0x4D5A9E4BCF6509A7,
            0x28E9FA9E9D9F5E34,
        ],
    },
};

/// `x` index of base point on the curve (recommended parameters for `sm2`)
pub const ECC_GX: Coordinate = Coordinate {
    num: U64x4 {
        value: [
            0x715A4589334C74C7,
            0x8FE30BBFF2660BE1,
            0x5F9904466A39C994,
            0x32C4AE2C1F198119,
        ],
    },
};

/// `y` index of base point on the curve (recommended parameters for `sm2`)
pub const ECC_GY: Coordinate = Coordinate {
    num: U64x4 {
        value: [
            0x02DF32E52139F0A0,
            0xD0A9877CC62A4740,
            0x59BDCEE36B692153,
            0xBC3736A2F4F6779C,
        ],
    },
};

/// Base point on the curve (recommended parameters for `sm2`)
pub const ECC_G: Point = Point {
    x: ECC_GX,
    y: ECC_GY,
};

/// Representation for point at infinity is (1,1,0) in Jacobi coordinates
pub const ZERO_JACOBI: JacobiPoint = JacobiPoint {
    x: Coordinate {
        num: U64x4 {
            value: [1, 0, 0, 0],
        },
    },
    y: Coordinate {
        num: U64x4 {
            value: [1, 0, 0, 0],
        },
    },
    z: Coordinate {
        num: U64x4 {
            value: [0, 0, 0, 0],
        },
    },
};

/// Pre-computation for base point multiplications
lazy_static! {
    static ref LOW_TABLE: Vec<Point> = {
        // save G, 2G, 4G, ... for later use
        let g_jacobi = affine_to_jacobi(ECC_G);
        let mut pow_g: Vec<JacobiPoint> = vec![g_jacobi];
        for _ in 1..256
        {
            if let Some(&t) = pow_g.last()
            {
                pow_g.push(add_jacobi_point(t, t));
            }
        }

        // find the desired values
        let mut table: Vec<Point> = Vec::new();
        for i in 0..256
        {
            let mut j = i;
            let mut t = ZERO_JACOBI;
            let mut k = 0;
            while j != 0
            {
                if j & 1 != 0
                {
                    // t = t + 2^{32p} * G
                    t = add_jacobi_point(t, pow_g[k << 5]);
                }
                j >>= 1;
                k += 1;
            }
            table.push(jacobi_to_affine(t));
        }
        table
    };

    static ref HIGH_TABLE: Vec<Point> = {
        // save G, 2G, 4G, ... for later use
        let g_jacobi = affine_to_jacobi(ECC_G);
        let mut pow_g: Vec<JacobiPoint> = vec![g_jacobi];
        for _ in 1..256
        {
            if let Some(&t) = pow_g.last()
            {
                pow_g.push(add_jacobi_point(t, t));
            }
        }

        // find the desired values
        let mut table: Vec<Point> = Vec::new();
        for i in 0..256
        {
            let mut j = i;
            let mut t = ZERO_JACOBI;
            let mut k = 0;
            while j != 0
            {
                if j & 1 != 0
                {
                    // T = T + 2^{32p + 16} * G
                    t = add_jacobi_point(t, pow_g[(k << 5) + (1 << 4)]);
                }
                j >>= 1;
                k += 1;
            }
            table.push(jacobi_to_affine(t));
        }
        table
    };
}

/// Point on curve with affine coordinates
#[derive(Copy, Clone)]
pub struct Point {
    pub x: Coordinate,
    pub y: Coordinate,
}

impl Display for Point {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "({} ,{})", self.x, self.y)
    }
}

/// Point on curve with Jacobi coordinates
#[derive(Copy, Clone)]
pub struct JacobiPoint {
    pub x: Coordinate,
    pub y: Coordinate,
    pub z: Coordinate,
}

impl Display for JacobiPoint {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "({} ,{}, {})", self.x, self.y, self.z)
    }
}

impl Point {
    pub fn new(x: Coordinate, y: Coordinate) -> Point {
        Point { x, y }
    }
}

/// Return if the point is on curve
pub fn is_on_curve(p: Point) -> bool {
    // is y^2 = x^3 + ax + b ?
    point_equal_to_zero(p) || (p.y * p.y).num == (((p.x * p.x * p.x) + (ECC_A * p.x)) + ECC_B).num
}

/// Return if the point is the point at infinity
pub fn point_equal_to_zero(p: Point) -> bool {
    p.x.num.equal_to_zero() && p.y.num.equal_to_zero()
}

/// Return if the point (in Jacobi coordinates) is the point at infinity
pub fn jacobi_point_equal_to_zero(p: JacobiPoint) -> bool {
    p.x.num.equal_to_one() && p.y.num.equal_to_one() && p.z.num.equal_to_zero()
}

/// Convert a point from affine coordinates to Jacobi coordinates
pub fn affine_to_jacobi(p: Point) -> JacobiPoint {
    if !point_equal_to_zero(p) {
        JacobiPoint {
            x: p.x,
            y: p.y,
            z: Coordinate::from_u64([1, 0, 0, 0]),
        }
    } else {
        ZERO_JACOBI
    }
}

/// Convert a point from Jacobi coordinates to affine coordinates
pub fn jacobi_to_affine(p: JacobiPoint) -> Point {
    let u = get_mul_inv(p.z);
    let u2 = u * u;
    let u3 = u2 * u;

    Point {
        x: p.x * u2,
        y: p.y * u3,
    }
}

/// Addition (group operation) of two points (in affine-Jacobi coordinates)
///
/// **Note**: this function should be called with different points
pub fn add_jacobi_affine(p: JacobiPoint, q: Point) -> JacobiPoint {
    if jacobi_point_equal_to_zero(p) {
        affine_to_jacobi(q)
    } else if point_equal_to_zero(q) {
        p
    } else {
        let z2 = p.z * p.z;
        let a = q.x * z2;
        let b = q.y * z2 * p.z;
        let c = a - p.x;
        let d = b - p.y;
        let c2 = c * c;
        let c3 = c2 * c;
        let x1c2 = p.x * c2;
        let x = (d * d) - (x1c2 + x1c2) - c3;
        let y = (d * (x1c2 - x)) - (p.y * c3);
        let z = p.z * c;
        JacobiPoint { x, y, z }
    }
}

/// Addition (group operation) of two points (in Jacobi-Jacobi coordinates)
pub fn add_jacobi_point(p: JacobiPoint, q: JacobiPoint) -> JacobiPoint {
    if jacobi_point_equal_to_zero(p) {
        q
    } else if jacobi_point_equal_to_zero(q) {
        p
    } else {
        let pz2 = p.z * p.z;
        let qz2 = q.z * q.z;
        let pz3 = pz2 * p.z;
        let qz3 = qz2 * q.z;
        let lambda1 = p.x * qz2;
        let lambda2 = q.x * pz2;

        //P != Q
        if lambda1.num != lambda2.num {
            let lambda4 = p.y * qz3;
            let lambda5 = q.y * pz3;
            if lambda4.num != lambda5.num {
                let lambda3 = lambda1 - lambda2;
                let lambda6 = lambda4 - lambda5;
                let lambda7 = lambda1 + lambda2;
                let lambda8 = lambda4 + lambda5;
                let l6l6 = lambda6 * lambda6;
                let l3l3 = lambda3 * lambda3;
                let l7l3l3 = lambda7 * l3l3;
                let x = l6l6 - l7l3l3;
                let lambda9 = l7l3l3 - (x + x);
                let l9l6 = lambda9 * lambda6;
                let l8l3l3l3 = lambda8 * l3l3 * lambda3;

                let mut y = l9l6 - l8l3l3l3;
                y = y * INV_2P;
                let z = p.z * q.z * lambda3;

                JacobiPoint { x, y, z }
            } else {
                ZERO_JACOBI
            }
        } else {
            //P=Q
            let px2 = p.x * p.x; // px2 = px^2
            let pz4 = pz2 * pz2; // pz4 = pz^4
            let px2_2 = px2 + px2; // px2_2 = 2px^2
            let px2_3 = px2_2 + px2; // px2_3 = 3px^2
            let lambda1 = px2_3 + ECC_A * pz4; // l1 = 3*px^2+a*pz^4
            let py2 = p.y * p.y; // py2 = py^2
            let py_2 = p.y + p.y; // py_2 = 2*py
            let py2_2 = py2 + py2; // py2_2 = 2*py^2
            let py2_4 = py2_2 + py2_2; // py2_4 = 4*py^2
            let lambda2 = py2_4 * p.x; // l2 = 4*px*py^2
            let l2_2 = lambda2 + lambda2; // l2 = 2*l2
            let py4_4 = py2_2 * py2_2; // py4_4 = 4*py^4
            let lambda3 = py4_4 + py4_4; // l3 = 8^py^4
            let l1l1 = lambda1 * lambda1; // l1l1 = l1^2
            let x = l1l1 - l2_2; // x3 = l1^2 - 2*l2
            let m1 = lambda2 - x; // m1 = l2 - x3
            let m2 = lambda1 * m1; // m2 = l1*(l2-x3
            let y = m2 - lambda3; // y = l1*(l2-x3-l3
            let z = py_2 * p.z; // z = 2*py*pz

            JacobiPoint { x, y, z }
        }
    }
}

/// Scalar multiplication of a point
///
/// This operation is also known as `exponentiation` and is the core operation of elliptic curve cryptography.
///
/// **Note**: this function return A `JacobiPoint`.
pub fn times_point(p: Point, times: U64x4) -> JacobiPoint {
    let mut t = ZERO_JACOBI;

    for blocki in (0..4).rev() {
        for i in (0..64).rev() {
            t = add_jacobi_point(t, t);
            if (times.value[blocki] & (1 << i)) != 0 {
                t = add_jacobi_affine(t, p);
            }
        }
    }
    t
}

//#[inline]
fn get_bit(u: u64, i: usize) -> usize {
    ((u >> i) & 1) as usize
}

//#[inline]
fn to_index(u: U64x4, i: usize) -> usize {
    get_bit(u.value[0], i)
        + (get_bit(u.value[0], 32 + i) << 1)
        + (get_bit(u.value[1], i) << 2)
        + (get_bit(u.value[1], 32 + i) << 3)
        + (get_bit(u.value[2], i) << 4)
        + (get_bit(u.value[2], 32 + i) << 5)
        + (get_bit(u.value[3], i) << 6)
        + (get_bit(u.value[3], 32 + i) << 7)
}

/// Scalar multiplication of the base point
///
/// The implemenation is faster than `times_point` by Speeding up using Fixed-base comb described in
/// "Software Implementation of the NIST Elliptic Curves Over Prime Fields" by M Brown et. al.
pub fn times_base_point(times: U64x4) -> JacobiPoint {
    let mut t = ZERO_JACOBI;
    for i in (0..16).rev() {
        t = add_jacobi_point(t, t);
        let index_low = to_index(times, i);
        let index_high = to_index(times, i + 16);
        t = add_jacobi_affine(t, LOW_TABLE[index_low]);
        t = add_jacobi_affine(t, HIGH_TABLE[index_high]);
    }
    t
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Return if the point (in Jacobi coordinates) are equal
    fn jacobi_point_equal_to(p: JacobiPoint, q: JacobiPoint) -> bool {
        let pz2 = p.z * p.z;
        let pz3 = pz2 * p.z;
        let qz2 = q.z * q.z;
        let qz3 = qz2 * q.z;

        let u1 = p.x * qz2;
        let u2 = q.x * pz2;
        let s1 = p.y * qz3;
        let s2 = q.y * pz3;
        //return x1==x2*u^2 && y1==y2*u^3
        u1.num == u2.num && s1.num == s2.num
    }

    #[test]
    fn test_add_jacobi_affine() {
        let l = affine_to_jacobi(ECC_G);
        let g2 = add_jacobi_point(l, l);
        let s1 = add_jacobi_point(g2, l);
        let s2 = add_jacobi_affine(g2, ECC_G);
        assert!(jacobi_point_equal_to(s1, s2));
    }

    #[test]
    fn test_zero_add_jacobi_affine() {
        let l = affine_to_jacobi(ECC_G);
        let z = ZERO_JACOBI;
        let s1 = add_jacobi_point(z, l);
        let s2 = add_jacobi_affine(z, ECC_G);
        assert!(jacobi_point_equal_to(s1, s2));
    }

    #[test]
    fn test_times3() {
        let l = affine_to_jacobi(ECC_G);
        let g2 = add_jacobi_point(l, l);
        let s1 = add_jacobi_point(g2, l);
        let s2 = times_point(ECC_G, U64x4::new(3, 0, 0, 0));
        assert!(jacobi_point_equal_to(s1, s2));
    }

    #[test]
    fn test_base_times() {
        let r = U64x4::random();
        let s1 = times_point(ECC_G, r);
        let s2 = times_base_point(r);
        assert!(jacobi_point_equal_to(s1, s2));
    }
}
