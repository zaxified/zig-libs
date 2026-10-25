// SPDX-License-Identifier: MIT

//! Fastest-in-the-field side of `zig build bench-metrics`
//! (modules/metrics/tools/bench.zig): times prometheus-client 0.25.1
//! (prometheus/client_rust, the official Rust client; pinned by Cargo.lock)
//! for the one workload named by the second argument, through its public API
//! only. The first argument is the work directory (unused; kept so the argv
//! matches go_bench). Prints one line: name, ns/op, result count
//! (tab-separated). Workloads as in go_bench, in client_rust's idiom:
//!
//!   counter_inc   4096 x Counter::inc on a held counter
//!   observe       4096 x Histogram::observe (client_golang's default buckets)
//!   counter_vec   4096 x Family::get_or_create(&[("method", m), ("code", c)]).inc()
//!                 (the 20 label sets are built once)
//!   scrape        encoding::text::encode of the registry go_bench builds;
//!                 result = number of sample lines (195), since the libraries
//!                 format floats and order series differently
//!
//! Timing matches the Zig side: double the batch until one batch takes over
//! 100 ms, then keep the best of five.

use prometheus_client::encoding::text::encode;
use prometheus_client::metrics::counter::Counter;
use prometheus_client::metrics::family::Family;
use prometheus_client::metrics::gauge::Gauge;
use prometheus_client::metrics::histogram::Histogram;
use prometheus_client::registry::Registry;
use std::hint::black_box;
use std::sync::atomic::AtomicU64;
use std::time::{Duration, Instant};

const N_OBS: usize = 4096;
const METHODS: [&str; 4] = ["GET", "POST", "PUT", "DELETE"];
const CODES: [&str; 5] = ["200", "201", "400", "404", "500"];
// client_golang's DefBuckets, the buckets every side of the bench uses.
const DEF_BUCKETS: [f64; 11] = [0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1.0, 2.5, 5.0, 10.0];

type Labels = [(&'static str, &'static str); 2];

fn obs_value(k: usize) -> f64 {
    ((k * 37) % 700) as f64 / 64.0
}

fn time_it(mut f: impl FnMut() -> u64) -> (f64, u64) {
    let mut n: u64 = 1;
    let mut sink: u64 = 0;
    loop {
        let t = Instant::now();
        for _ in 0..n {
            sink = sink.wrapping_add(f());
        }
        if t.elapsed() > Duration::from_millis(100) {
            break;
        }
        n *= 2;
    }
    black_box(sink);
    let mut best = Duration::MAX;
    let mut count = 0;
    for _ in 0..5 {
        let t = Instant::now();
        for _ in 0..n {
            count = black_box(f());
        }
        best = best.min(t.elapsed());
    }
    (best.as_nanos() as f64 / n as f64, count)
}

fn sample_lines(s: &str) -> u64 {
    s.lines().filter(|l| !l.is_empty() && !l.starts_with('#')).count() as u64
}

/// `<dir> probe`: the six rows of `tools/go_field_probe` (which judges them),
/// each exposition written to `<dir>/rust_<row>.txt`.
fn probe(dir: &str) {
    for row in ["quote", "newline", "backslash", "help", "negative", "big"] {
        let mut reg = Registry::default();
        match row {
            "quote" | "newline" | "backslash" => {
                let v = match row {
                    "quote" => "a\"b",
                    "newline" => "a\nb",
                    _ => "a\\b",
                };
                let fam = Family::<[(&'static str, &'static str); 1], Counter>::default();
                fam.get_or_create(&[("path", v)]).inc();
                reg.register("probe", "probe", fam);
            }
            "help" => {
                let c: Counter = Counter::default();
                c.inc();
                reg.register("probe", "x\nprobe_injected 7", c);
            }
            "negative" => {
                let h = Histogram::new(DEF_BUCKETS);
                h.observe(-1.0);
                reg.register("probe_seconds", "probe", h);
            }
            _ => {
                let c: Counter = Counter::default();
                c.inc_by(1 << 53);
                c.inc();
                reg.register("probe", "probe", c);
            }
        }
        let mut out = String::new();
        encode(&mut out, &reg).unwrap();
        std::fs::write(format!("{dir}/rust_{row}.txt"), out).unwrap();
    }
}

fn main() {
    let args: Vec<String> = std::env::args().collect();
    if args.len() != 3 {
        eprintln!("usage: rust_fast_bench <work dir> <workload>");
        std::process::exit(2);
    }
    let name = args[2].as_str();
    let (ns, count) = match name {
        "counter_inc" => {
            let c: Counter = Counter::default();
            time_it(|| {
                for _ in 0..N_OBS {
                    black_box(&c).inc();
                }
                N_OBS as u64
            })
        }
        "observe" => {
            let h = Histogram::new(DEF_BUCKETS);
            let vals: Vec<f64> = (0..N_OBS).map(obs_value).collect();
            time_it(|| {
                for &v in &vals {
                    h.observe(v);
                }
                N_OBS as u64
            })
        }
        "counter_vec" => {
            let fam = Family::<Labels, Counter>::default();
            let sets: Vec<Labels> = (0..20).map(|i| [("method", METHODS[i & 3]), ("code", CODES[i >> 2])]).collect();
            time_it(|| {
                for i in 0..N_OBS {
                    fam.get_or_create(&sets[(i & 3) + 4 * ((i >> 2) % 5)]).inc();
                }
                N_OBS as u64
            })
        }
        "scrape" => {
            let mut reg = Registry::default();
            let req = Family::<Labels, Counter>::default();
            for (mi, m) in METHODS.iter().enumerate() {
                for (ci, c) in CODES.iter().enumerate() {
                    req.get_or_create(&[("method", *m), ("code", *c)]).inc_by((1 + (mi * 5 + ci) * 37) as u64);
                }
            }
            let g: Gauge<f64, AtomicU64> = Gauge::default();
            g.set(3.0);
            let temp = Family::<[(&'static str, String); 1], Gauge<f64, AtomicU64>>::default();
            for i in 0..6 {
                temp.get_or_create(&[("room", format!("room{i}"))]).set(i as f64 * 0.5);
            }
            let dur = Family::<[(&'static str, &'static str); 1], Histogram>::new_with_constructor(|| Histogram::new(DEF_BUCKETS));
            for (mi, m) in METHODS.iter().enumerate() {
                let h = dur.get_or_create(&[("method", *m)]);
                for k in 0..100 {
                    h.observe(obs_value(mi * 100 + k));
                }
            }
            let op = Family::<[(&'static str, String); 1], Histogram>::new_with_constructor(|| Histogram::new(DEF_BUCKETS));
            for oi in 0..8 {
                let h = op.get_or_create(&[("op", format!("op{oi}"))]);
                for k in 0..100 {
                    h.observe(obs_value(oi * 100 + k + 7));
                }
            }
            reg.register("http_requests", "Total HTTP requests served.", req);
            reg.register("app_in_flight", "Requests in flight.", g);
            reg.register("app_temp_celsius", "Room temperature.", temp);
            reg.register("http_request_duration_seconds", "Request latency.", dur);
            reg.register("app_op_seconds", "Operation latency.", op);
            let mut out = String::with_capacity(64 * 1024);
            time_it(|| {
                out.clear();
                encode(&mut out, &reg).unwrap();
                sample_lines(&out)
            })
        }
        "probe" => {
            probe(&args[1]);
            return;
        }
        _ => {
            eprintln!("unknown workload {name}");
            std::process::exit(2);
        }
    };
    println!("{name}\t{ns:.1}\t{count}");
}
