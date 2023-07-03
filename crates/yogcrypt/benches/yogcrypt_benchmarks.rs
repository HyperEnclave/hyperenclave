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

#[macro_use]
extern crate criterion;
extern crate yogcrypt;

use criterion::Criterion;

mod sm2_benches {
    use super::*;
    use yogcrypt::sm2::*;

    fn bench_gen_sign(c: &mut Criterion) {
        c.bench_function("sm2::gen_sign", move |b| {
            b.iter_with_setup(
                || {
                    let d_a = U64x4::random();

                    let msg = b"Hello World!";
                    let q = get_pub_key(d_a);
                    (d_a, msg, q)
                },
                |(d_a, msg, q)| sm2_gen_sign(msg, d_a, q, true),
            )
        });
    }

    fn bench_ver_sign(c: &mut Criterion) {
        c.bench_function("sm2::ver_sign", move |b| {
            b.iter_with_setup(
                || {
                    let d_a = U64x4::random();

                    let msg = b"Hello World!";

                    let q = get_pub_key(d_a);

                    (msg, q, sm2_gen_sign(msg, d_a, q, true))
                },
                |(msg, q, signature)| {
                    let t = sm2_ver_sign(msg, q, &signature);
                    assert!(t);
                },
            )
        });
    }

    criterion_group!(
        benches,
        sm2_benches::bench_gen_sign,
        sm2_benches::bench_ver_sign
    );
}

mod sm3_benches {
    use super::*;
    use yogcrypt::sm3::*;

    fn bench(c: &mut Criterion) {
        c.bench_function("sm3::hash", move |b| {
            b.iter(|| {
                let msg = b"abcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcd";

                sm3_enc(msg)
            });
        });
    }
    criterion_group!(benches, sm3_benches::bench);
}

mod sm4_benches {
    use super::*;
    use yogcrypt::sm4::*;

    fn bench_enc(c: &mut Criterion) {
        let m = b"ajfkdljfldsjkfsd";
        let p_txt = b"1234567890abcdef";

        c.bench_function("sm4::enc", move |b| {
            b.iter(|| {
                sm4_enc(m, p_txt);
            });
        });
    }

    fn bench_dec(c: &mut Criterion) {
        let m = b"ajfkdljfldsjkfsd";
        let p_txt = b"1234567890abcdef";

        c.bench_function("sm4::dec", move |b| {
            b.iter_with_setup(
                || sm4_enc(m, p_txt),
                |c_txt| {
                    let p_txt2 = sm4_dec(m, &c_txt);
                    assert_eq!(p_txt, &p_txt2);
                },
            )
        });
    }
    criterion_group!(benches, sm4_benches::bench_enc, sm4_benches::bench_dec);
}

criterion_main!(
    sm2_benches::benches,
    sm3_benches::benches,
    sm4_benches::benches,
);
