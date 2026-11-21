// SPDX-License-Identifier: MIT

// Rust side of `zig build bench-entropy` (modules/entropy/tools/bench.zig):
// times the `getrandom` crate's `fill` on the same three buffer sizes, with
// the Go side's timing (double the batch until it takes over 100 ms, best of
// five). One line per workload: name, ns/op, length.
use std::hint::black_box;
use std::time::{Duration, Instant};

fn main() {
    let names = ["fill_32", "fill_4k", "fill_1m"];
    let sizes = [32usize, 4096, 1 << 20];
    for (name, size) in names.iter().zip(sizes) {
        let mut buf = vec![0u8; size];
        let mut n: u64 = 1;
        loop {
            let t = Instant::now();
            for _ in 0..n {
                getrandom::fill(&mut buf).unwrap();
                black_box(buf[0]);
            }
            if t.elapsed() > Duration::from_millis(100) {
                break;
            }
            n *= 2;
        }
        let mut best = Duration::MAX;
        for _ in 0..5 {
            let t = Instant::now();
            for _ in 0..n {
                getrandom::fill(&mut buf).unwrap();
                black_box(buf[0]);
            }
            best = best.min(t.elapsed());
        }
        println!("{}\t{:.1}\t{}", name, best.as_nanos() as f64 / n as f64, size);
    }
}
