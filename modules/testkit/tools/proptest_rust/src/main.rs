// SPDX-License-Identifier: MIT

//! The reference side of `bench-testkit`: proptest 1.11.0's `TestRunner`
//! driving the same trivial property as `tools/bench.zig` -- a byte string
//! of the driver's length distribution (half the draws up to 64 bytes, half
//! up to 160), mapped to hex digits and decoded. One op = one `run` of
//! 10 000 cases on a fresh runner (what one `proptest!` test pays), so the
//! per-op time over 10 000 is proptest's cost per input.
//!
//! Usage: `proptest_bench <work dir> <workload>`; workloads `hex` and
//! `alloc` (the same plus two heap allocations per input). Prints
//! `name \t ns/op \t count` (wall time; no cycle counter on this side) and
//! a banner on stderr. Timing as `testkit.bench.timeIt`: double the batch
//! until it takes over 100 ms, then the best of five.

use proptest::collection::vec;
use proptest::prelude::*;
use proptest::test_runner::{Config, TestRunner};
use std::hint::black_box;
use std::time::Instant;

const CASES: u32 = 10_000;
const DIGITS: &[u8; 16] = b"0123456789abcdef";

fn nibble(c: u8) -> Option<u8> {
    match c {
        b'0'..=b'9' => Some(c - b'0'),
        b'a'..=b'f' => Some(c - b'a' + 10),
        b'A'..=b'F' => Some(c - b'A' + 10),
        _ => None,
    }
}

fn hex_into(out: &mut [u8], s: &[u8]) -> Option<usize> {
    if s.len() % 2 != 0 || out.len() < s.len() / 2 {
        return None;
    }
    for (i, p) in s.chunks_exact(2).enumerate() {
        out[i] = (nibble(p[0])? << 4) | nibble(p[1])?;
    }
    Some(s.len() / 2)
}

fn hex_case(mut v: Vec<u8>) -> Result<(), TestCaseError> {
    for b in v.iter_mut() {
        *b = DIGITS[(*b & 15) as usize];
    }
    let mut out = [0u8; 80];
    let even = v.len() & !1;
    hex_into(&mut out, &v[..even]).unwrap();
    black_box(&out);
    Ok(())
}

fn alloc_case(mut v: Vec<u8>) -> Result<(), TestCaseError> {
    for b in v.iter_mut() {
        *b = DIGITS[(*b & 15) as usize];
    }
    let mut a = vec![0u8; v.len() / 2 + 1];
    let c = v.clone();
    let even = c.len() & !1;
    hex_into(&mut a, &c[..even]).unwrap();
    black_box(&a);
    Ok(())
}

fn once(alloc: bool) -> u64 {
    let mut runner = TestRunner::new(Config {
        cases: CASES,
        failure_persistence: None,
        ..Config::default()
    });
    let strat = prop_oneof![vec(any::<u8>(), 0..=64), vec(any::<u8>(), 0..=160)];
    let r = if alloc {
        runner.run(&strat, alloc_case)
    } else {
        runner.run(&strat, hex_case)
    };
    r.unwrap();
    CASES as u64
}

fn main() {
    let args: Vec<String> = std::env::args().collect();
    if args.len() != 3 {
        eprintln!("usage: proptest_bench <work dir> <hex|alloc>");
        std::process::exit(2);
    }
    let name = args[2].as_str();
    let alloc = match name {
        "hex" => false,
        "alloc" => true,
        _ => {
            eprintln!("proptest_bench: unknown workload {name}");
            std::process::exit(2);
        }
    };
    eprintln!("proptest 1.11.0 (Rust), TestRunner, {CASES} cases per op");

    let mut n: u64 = 1;
    loop {
        let t = Instant::now();
        for _ in 0..n {
            black_box(once(alloc));
        }
        if t.elapsed().as_nanos() > 100_000_000 {
            break;
        }
        n *= 2;
    }
    let mut best = u128::MAX;
    let mut count = 0;
    for _ in 0..5 {
        let t = Instant::now();
        for _ in 0..n {
            count = black_box(once(alloc));
        }
        best = best.min(t.elapsed().as_nanos());
    }
    println!("{name}\t{:.1}\t{count}", best as f64 / n as f64);
}
