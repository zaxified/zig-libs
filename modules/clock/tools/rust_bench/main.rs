// SPDX-License-Identifier: MIT

// Rust side of `zig build bench-clock` (modules/clock/tools/bench.zig): times
// Rust std's `Instant::now` (CLOCK_MONOTONIC) and `SystemTime::now` (CLOCK_REALTIME,
// as Unix nanoseconds). One line per workload: name, ns/op. Timing matches the
// Zig side: double the batch until it takes over 100 ms, best of five.
// Standard library only; built with `rustc -O`.
use std::hint::black_box;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

fn time_it<F: Fn() -> u64>(f: F) -> f64 {
    let mut n: u64 = 1;
    loop {
        let t = Instant::now();
        for _ in 0..n {
            black_box(f());
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
            black_box(f());
        }
        best = best.min(t.elapsed());
    }
    best.as_nanos() as f64 / n as f64
}

fn main() {
    let origin = Instant::now();
    let mono = time_it(|| Instant::now().duration_since(origin).as_nanos() as u64);
    let real = time_it(|| SystemTime::now().duration_since(UNIX_EPOCH).map(|d| d.as_nanos() as u64).unwrap_or(0));
    println!("monotonic\t{:.2}", mono);
    println!("realtime\t{:.2}", real);
}
