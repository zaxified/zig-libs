// SPDX-License-Identifier: MIT
//! Freeze Rust's `str::to_lowercase` / `to_uppercase` answers (Unicode 17.0.0 in Rust
//! 1.93, the module's version) as `src/testdata/rust_vectors.txt`.
//!
//!     rustc --edition 2021 -O tools/rust_case.rs -o <scratch>/rust_case
//!     <scratch>/rust_case src/testdata/cpython_vectors.txt > src/testdata/rust_vectors.txt
//!
//! std only, no crates. Lines: `C;cp;lower;upper` for every scalar value whose lowercase
//! or uppercase is not itself (hex code points, space separated), and `S;cps;lower;upper`
//! for every string line of the CPython vector file (its field 1), so the Final_Sigma
//! contexts are compared with Rust's own implementation of the rule.
use std::fs;

fn hex(s: &str) -> String {
    s.chars().map(|c| format!("{:X}", c as u32)).collect::<Vec<_>>().join(" ")
}

fn main() {
    let path = std::env::args().nth(1).expect("usage: rust_case <cpython_vectors.txt>");
    println!("# unitext: Rust {:?} str::to_lowercase / to_uppercase (char::UNICODE_VERSION), frozen by tools/rust_case.rs.", char::UNICODE_VERSION);
    println!("# C;cp;lower;upper (only where either differs from the code point) and S;cps;lower;upper.");
    for cp in 0..=0x10FFFFu32 {
        if let Some(c) = char::from_u32(cp) {
            let s = c.to_string();
            let (l, u) = (s.to_lowercase(), s.to_uppercase());
            if l != s || u != s {
                println!("C;{:X};{};{}", cp, hex(&l), hex(&u));
            }
        }
    }
    for line in fs::read_to_string(&path).expect("read").lines() {
        if let Some(rest) = line.strip_prefix("S;") {
            let cps = rest.split(';').next().unwrap();
            let s: String = cps.split(' ').map(|h| char::from_u32(u32::from_str_radix(h, 16).unwrap()).unwrap()).collect();
            println!("S;{};{};{}", cps, hex(&s.to_lowercase()), hex(&s.to_uppercase()));
        }
    }
}
