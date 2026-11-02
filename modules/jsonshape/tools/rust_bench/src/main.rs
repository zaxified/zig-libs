// SPDX-License-Identifier: MIT

//! Rust side of `zig build bench-jsonshape` (modules/jsonshape/tools/bench.zig):
//! times serde_json_path 0.7.2 (workload names as they are) and jsonpath-rust
//! 1.0.12 (names with the prefix `jpr_`) over the doc.json and paths.txt the Zig
//! program writes into the directory given as the first argument, for the workload
//! named by the second. Prints one line: name, ns/op, count (tab-separated). See
//! bench.zig for what each workload does.
//!
//! Timing matches the Zig side: double the batch until it takes over 100 ms, then
//! keep the best of five.

use jsonpath_rust::parser::parse_json_path;
use jsonpath_rust::query::js_path_process;
use serde_json::Value;
use serde_json_path::JsonPath;
use std::hint::black_box;
use std::time::{Duration, Instant};

fn measure(mut f: impl FnMut() -> u64) -> (f64, u64) {
    let mut n: u64 = 1;
    let mut count = 0;
    loop {
        let t = Instant::now();
        for _ in 0..n {
            count = black_box(f());
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
            count = black_box(f());
        }
        best = best.min(t.elapsed());
    }
    (best.as_nanos() as f64 / n as f64, count)
}

fn main() {
    let args: Vec<String> = std::env::args().collect();
    let (dir, full) = (&args[1], &args[2]);
    let (use_jpr, name) = match full.strip_prefix("jpr_") {
        Some(n) => (true, n),
        None => (false, full.as_str()),
    };
    let raw = std::fs::read_to_string(format!("{dir}/doc.json")).unwrap();
    let listing = std::fs::read_to_string(format!("{dir}/paths.txt")).unwrap();
    let text = listing
        .lines()
        .filter_map(|l| l.split_once('\t'))
        .find(|(n, _)| *n == name)
        .map(|(_, p)| p)
        .unwrap_or("");
    let doc: Value = serde_json::from_str(&raw).unwrap();

    let (ns, count) = if name == "doc_parse" {
        measure(|| {
            let v: Value = serde_json::from_str(&raw).unwrap();
            black_box(&v);
            raw.len() as u64
        })
    } else if name.starts_with("compile_") && use_jpr {
        measure(|| {
            black_box(parse_json_path(text).unwrap());
            text.len() as u64
        })
    } else if name.starts_with("compile_") {
        measure(|| {
            black_box(JsonPath::parse(text).unwrap());
            text.len() as u64
        })
    } else if use_jpr {
        let p = parse_json_path(text).unwrap();
        measure(|| js_path_process(&p, &doc).unwrap().len() as u64)
    } else if name.starts_with("located_") {
        let p = JsonPath::parse(text).unwrap();
        measure(|| {
            p.query_located(&doc)
                .iter()
                .map(|n| n.location().to_string().len() as u64)
                .sum()
        })
    } else {
        let p = JsonPath::parse(text).unwrap();
        measure(|| p.query(&doc).len() as u64)
    };
    eprintln!(
        "{}",
        if use_jpr {
            "jsonpath-rust 1.0.12"
        } else {
            "serde_json_path 0.7.2"
        }
    );
    println!("{full}\t{ns:.1}\t{count}");
}
