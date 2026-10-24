// SPDX-License-Identifier: MIT

// "Fastest in the field" side of `zig build bench-json5`
// (modules/json5/tools/bench.zig): times one Rust JSON5 crate reading the files
// the Zig program writes into the directory given as the first argument, for
// the workload named by the second and the contender named by the third
// (`json5` = the json5 crate 1.3.1, callum-oakley/json5-rs; `json-five` =
// json-five 0.3.1, spyoungtech/json-five-rs). Each op is `from_str` into a
// `serde_json::Value` (the counterpart of the Zig side's `std.json.Value`);
// same timing method as bench_ref.js: double the batch until it takes over
// 100 ms, then the best of five batches, per op. Prints `name \t ns \t count`,
// count = object members + array elements of the parsed tree (summed over the
// 1000 parses of `small_config`), which must equal the Zig side's.

use serde_json::Value;
use std::time::Instant;

fn count(v: &Value) -> u64 {
    match v {
        Value::Array(a) => a.len() as u64 + a.iter().map(count).sum::<u64>(),
        Value::Object(o) => o.len() as u64 + o.values().map(count).sum::<u64>(),
        _ => 0,
    }
}

fn main() {
    let args: Vec<String> = std::env::args().collect();
    if args.len() != 4 {
        eprintln!("usage: json5_rs_field <work dir> <workload> <json5|json-five>");
        std::process::exit(2);
    }
    let (file, reps) = match args[2].as_str() {
        "small_config" => ("small_config.json5", 1000),
        "large_json" => ("large_json.json", 1),
        "large_json5" => ("large_json5.json5", 1),
        _ => {
            eprintln!("unknown workload {}", args[2]);
            std::process::exit(2)
        }
    };
    let five = match args[3].as_str() {
        "json5" => false,
        "json-five" => true,
        _ => {
            eprintln!("unknown contender {}", args[3]);
            std::process::exit(2)
        }
    };
    let text = std::fs::read_to_string(format!("{}/{}", args[1], file)).expect("read workload file");
    let once = || -> u64 {
        let mut sum = 0;
        for _ in 0..reps {
            let v: Value = if five {
                json_five::from_str(&text).expect("json-five parse")
            } else {
                json5::from_str(&text).expect("json5 parse")
            };
            sum += count(&v);
        }
        sum
    };
    let mut sink = 0u64;
    let mut n = 1u64;
    loop {
        let t = Instant::now();
        for _ in 0..n {
            sink = sink.wrapping_add(once());
        }
        if t.elapsed().as_nanos() > 100_000_000 {
            break;
        }
        n *= 2;
    }
    let mut best = f64::INFINITY;
    let mut result = 0;
    for _ in 0..5 {
        let t = Instant::now();
        for _ in 0..n {
            result = once();
        }
        best = best.min(t.elapsed().as_nanos() as f64);
    }
    std::hint::black_box(sink);
    eprintln!("{}, serde_json 1.0.154 Value", if five { "json-five 0.3.1" } else { "json5 crate 1.3.1" });
    println!("{}\t{}\t{}", args[2], best / n as f64, result);
}
