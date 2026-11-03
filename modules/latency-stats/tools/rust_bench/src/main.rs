// SPDX-License-Identifier: MIT
//
// Rust side of `zig build bench-latency-stats` (modules/latency-stats/tools/bench.zig):
// `hdrhistogram` 7.6.0 doing the same work as c_bench/foreign_bench.c and
// go_bench/main.go; the workload list and what one op does are in the C file's
// header. Config: lowest 1, highest 3.6e12, 3 significant figures, u64 counts.
//
//   latency_stats_rust_bench <work dir> <workload>     name \t ns/op \t count
use hdrhistogram::Histogram;
use std::time::Instant;

const HIGHEST: u64 = 3_600_000_000_000;
const INTERVAL: u64 = 1_000_000;

fn main() {
    let args: Vec<String> = std::env::args().collect();
    if args.len() != 3 {
        std::process::exit(2);
    }
    let raw = std::fs::read(format!("{}/values.bin", args[1])).expect("values.bin");
    let vals: Vec<u64> = raw.chunks_exact(8).map(|c| u64::from_le_bytes(c.try_into().unwrap())).collect();
    let mut h: Histogram<u64> = Histogram::new_with_bounds(1, HIGHEST, 3).unwrap();
    let mut src: Histogram<u64> = Histogram::new_with_bounds(1, HIGHEST, 3).unwrap();
    for &v in &vals {
        src.record(v).unwrap();
    }
    let name = args[2].as_str();
    let mut op: Box<dyn FnMut() -> u64> = match name {
        "record" => Box::new(|| {
            h.reset();
            for &v in &vals {
                h.record(v).unwrap();
            }
            h.len()
        }),
        "record_corrected" => Box::new(|| {
            h.reset();
            for &v in &vals {
                h.record_correct(v, INTERVAL).unwrap();
            }
            h.len()
        }),
        "percentiles" => Box::new(|| {
            let mut sum = 0u64;
            for j in 0..1000 {
                sum += src.value_at_quantile((100.0 * j as f64 + 0.7) / 1000.0 / 100.0);
            }
            sum
        }),
        "merge" => Box::new(|| {
            h.reset();
            h.record(1).unwrap();
            h.add(&src).unwrap();
            h.len()
        }),
        "merge_empty" => Box::new(|| {
            h.reset();
            h.add(&src).unwrap();
            h.len()
        }),
        "mean_stddev" => Box::new(|| src.mean() as u64 + src.stdev() as u64),
        _ => std::process::exit(5),
    };
    let mut n = 1u64;
    loop {
        let t = Instant::now();
        for _ in 0..n {
            std::hint::black_box(op());
        }
        if t.elapsed().as_nanos() > 100_000_000 {
            break;
        }
        n *= 2;
    }
    let mut best = f64::MAX;
    let mut count = 0u64;
    for _ in 0..5 {
        let t = Instant::now();
        for _ in 0..n {
            count = std::hint::black_box(op());
        }
        let d = t.elapsed().as_nanos() as f64 / n as f64;
        if d < best {
            best = d;
        }
    }
    eprintln!("hdrhistogram 7.6.0 (Rust, default-features = false, lto fat, opt-level 3)");
    println!("{}\t{:.3}\t{}", name, best, count);
}
