// SPDX-License-Identifier: MIT

// Rust side of `zig build bench-ini` (modules/ini/tools/bench.zig): times the
// `configparser` crate 3.3.0 and `ini_core` 0.2.0 over the texts the Zig
// program writes into the directory given as the first argument, for the
// workload named by the second. Prints one line: name, ns/op, result count
// (tab-separated). See bench.zig for what each workload does.

use configparser::ini::{Ini, IniDefault, WriteOptions};
use std::time::{Duration, Instant};

fn time_it<F: FnMut() -> u64>(mut f: F) -> (f64, u64) {
    let mut n = 1u64;
    let mut sink = 0u64;
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
    let mut best = Duration::MAX;
    let mut count = 0;
    for _ in 0..5 {
        let t = Instant::now();
        for _ in 0..n {
            count = f();
        }
        best = best.min(t.elapsed());
    }
    std::hint::black_box(sink);
    (best.as_nanos() as f64 / n as f64, count)
}

struct Probe {
    section: String,
    key: String,
    miss: String,
}

fn read_probes(path: String) -> Vec<Probe> {
    std::fs::read_to_string(path)
        .unwrap()
        .lines()
        .map(|l| {
            let f: Vec<&str> = l.split('\t').collect();
            Probe { section: f[0].into(), key: f[1].into(), miss: f[2].into() }
        })
        .collect()
}

fn new_ini() -> Ini {
    // The same reading as the other sides: see bench.zig.
    let mut d = IniDefault::default();
    d.case_sensitive = true;
    d.enable_inline_comments = false;
    d.multiline = false;
    d.delimiters = vec!['='];
    d.comment_symbols = vec!['#'];
    Ini::new_from_defaults(d)
}

fn parse_probes(text: &str, probes: &[Probe]) -> u64 {
    let mut ini = new_ini();
    ini.read(text.to_string()).unwrap();
    let mut t = 0u64;
    for p in probes {
        t += ini.get(&p.section, &p.key).unwrap().len() as u64;
    }
    t
}

fn main() {
    let args: Vec<String> = std::env::args().collect();
    let (dir, name) = (&args[1], args[2].as_str());
    let small = std::fs::read_to_string(format!("{dir}/small.ini")).unwrap();
    let large = std::fs::read_to_string(format!("{dir}/large.ini")).unwrap();
    let probes = read_probes(format!("{dir}/probes.txt"));
    let small_probes = read_probes(format!("{dir}/small_probes.txt"));
    let mut doc = new_ini();
    doc.read(large.clone()).unwrap();

    let (ns, count) = match name {
        "parse_small" => time_it(|| parse_probes(&small, &small_probes)),
        "parse_large" => time_it(|| parse_probes(&large, &probes[..16])),
        "get_hit" => time_it(|| {
            let mut t = 0u64;
            for p in &probes {
                t += doc.get(&p.section, &p.key).unwrap().len() as u64;
            }
            t
        }),
        "get_miss" => time_it(|| {
            let mut t = 0u64;
            for p in &probes {
                if doc.get(&p.section, &p.miss).is_none() {
                    t += 1;
                }
            }
            t
        }),
        "write" => time_it(|| {
            let out = doc.pretty_writes(&WriteOptions::new());
            out.bytes().filter(|&b| b == b'=').count() as u64
        }),
        "scan_ini_core" => time_it(|| {
            let mut t = 0u64;
            for item in ini_core::Parser::new(&large).comment_char(b'#').auto_trim(true) {
                match item {
                    ini_core::Item::Section(s) => t += s.len() as u64,
                    ini_core::Item::Property(k, Some(v)) => t += (k.len() + v.len()) as u64,
                    _ => {}
                }
            }
            t
        }),
        other => panic!("no workload {other}"),
    };
    eprintln!("configparser 3.3.0 / ini_core 0.2.0");
    println!("{name}\t{ns:.1}\t{count}");
}
