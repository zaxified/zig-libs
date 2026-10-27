// SPDX-License-Identifier: MIT

// Rust side of `zig build bench-regex` (modules/regex/tools/bench.zig): times
// the `regex` crate (the fastest-in-the-field candidate) over the workloads
// and texts that program writes into the directory given as the only
// argument, and prints one line per workload: name, ns/op, result count --
// tab-separated, the same as tools/go_bench.
//
// Timing matches the other sides: double the iteration count until one batch
// takes over 100 ms, then keep the best of five batches.
//
// The workloads are Go syntax. Go's `\d`, `\w`, `\s` and `\b` are ASCII; the
// crate's are Unicode by default, so they are rewritten to the crate's ASCII
// forms (`(?-u:\w)` ...) before compiling. The result counts the Zig side
// compares catch any other difference in meaning.

use regex::Regex;
use std::hint::black_box;
use std::time::{Duration, Instant};

fn time_it(mut f: impl FnMut() -> usize) -> (f64, usize) {
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

/// Go's ASCII-only Perl classes and word boundary in the crate's spelling.
fn go_to_rust(pattern: &str) -> String {
    let mut out = String::with_capacity(pattern.len() + 16);
    let mut it = pattern.chars();
    while let Some(c) = it.next() {
        if c != '\\' {
            out.push(c);
            continue;
        }
        match it.next() {
            Some(e @ ('d' | 'D' | 'w' | 'W' | 's' | 'S' | 'b' | 'B')) => {
                out.push_str("(?-u:\\");
                out.push(e);
                out.push(')');
            }
            Some(e) => {
                out.push('\\');
                out.push(e);
            }
            None => out.push('\\'),
        }
    }
    out
}

fn main() {
    let args: Vec<String> = std::env::args().collect();
    if args.len() != 2 {
        eprintln!("usage: rust_regex_bench <work dir>");
        std::process::exit(2);
    }
    let dir = std::path::Path::new(&args[1]);
    let list = std::fs::read_to_string(dir.join("workloads.tsv")).unwrap_or_else(|e| {
        eprintln!("{e}");
        std::process::exit(1)
    });
    let mut texts = std::collections::HashMap::<String, String>::new();
    for line in list.lines() {
        let f: Vec<&str> = line.split('\t').collect();
        if f.len() != 4 {
            eprintln!("bad workload line {line:?}");
            std::process::exit(1);
        }
        let (name, mode, pattern, file) = (f[0], f[1], go_to_rust(f[2]), f[3]);
        let s = texts
            .entry(file.to_string())
            .or_insert_with(|| {
                std::fs::read_to_string(dir.join(file)).unwrap_or_else(|e| {
                    eprintln!("{e}");
                    std::process::exit(1)
                })
            })
            .as_str();
        let re = Regex::new(&pattern).unwrap_or_else(|e| {
            eprintln!("{name}: {e}");
            std::process::exit(1)
        });
        let (ns, count) = match mode {
            "match" => time_it(|| re.is_match(black_box(s)) as usize),
            "findall" => time_it(|| re.find_iter(black_box(s)).count()),
            "findallsub" => time_it(|| re.captures_iter(black_box(s)).count()),
            "submatch" => time_it(|| match re.captures(black_box(s)) {
                Some(c) => 2 * c.len(),
                None => 0,
            }),
            "compile_submatch" => time_it(|| {
                let re = Regex::new(black_box(&pattern)).unwrap();
                match re.captures(black_box(s)) {
                    Some(c) => 2 * c.len(),
                    None => 0,
                }
            }),
            _ => {
                eprintln!("unknown mode {mode:?}");
                std::process::exit(1)
            }
        };
        println!("{name}\t{ns:.1}\t{count}");
    }
}
