// SPDX-License-Identifier: MIT

// "Fastest in the field" side of `zig build bench-cookies`
// (modules/cookies/tools/bench.zig): times the `cookie` crate 0.18.2 over the
// headers and cookie specs the Zig program writes into the directory given as
// the first argument, for the one workload named by the second and the
// contender named by the third (only "cookie" today). Prints one line,
// tab-separated: name, ns/op, count. One op = every header / spec once.
//
//   parse_find  Cookie::split_parse(header), first pair named "sid";
//               count = value bytes found + hits
//   parse_all   Cookie::split_parse(header), every pair;
//               count = sum of name+value bytes
//   build       Display of a prebuilt Cookie (CookieBuilder) into one reused
//               String; count = sum of output bytes
//
// The crate has no "find one cookie in a Cookie header" call: split_parse is
// its parser, so parse_find walks it until the name matches (what a caller
// does). Parsing is lenient (no charset validation); the Display side does no
// validation either (our side and Go's reject invalid cookies; the inputs are
// valid for all). Attribute ORDER differs from Go and from ours; the byte sum
// of the output does not (same names, same case, same separators).
//
// Timing matches the Zig side: double the batch until it takes over 100 ms,
// then keep the best of five.

use cookie::time::Duration;
use cookie::{Cookie, SameSite};
use std::fmt::Write;
use std::hint::black_box;
use std::time::Instant;

fn time_it(mut f: impl FnMut() -> u64) -> (f64, u64) {
    let mut n: u64 = 1;
    let mut sink = 0u64;
    loop {
        let t = Instant::now();
        for _ in 0..n {
            sink = sink.wrapping_add(f());
        }
        if t.elapsed().as_millis() > 100 {
            break;
        }
        n *= 2;
    }
    let mut best = u128::MAX;
    let mut count = 0;
    for _ in 0..5 {
        let t = Instant::now();
        for _ in 0..n {
            count = f();
        }
        best = best.min(t.elapsed().as_nanos());
    }
    black_box(sink);
    (best as f64 / n as f64, count)
}

fn sum(s: &str) -> u64 {
    s.bytes().map(u64::from).sum()
}

fn lines(path: &std::path::Path) -> Vec<String> {
    let text = std::fs::read_to_string(path).unwrap_or_else(|e| {
        eprintln!("{}: {}", path.display(), e);
        std::process::exit(1);
    });
    text.trim_end_matches('\n').split('\n').map(String::from).collect()
}

fn main() {
    let args: Vec<String> = std::env::args().collect();
    if args.len() != 4 {
        eprintln!("usage: cookies_fast_bench <work dir> <workload> <contender>");
        std::process::exit(2);
    }
    let (dir, name, who) = (std::path::Path::new(&args[1]), args[2].as_str(), args[3].as_str());
    if who != "cookie" {
        eprintln!("unknown contender {who}");
        std::process::exit(2);
    }
    let headers = lines(&dir.join("headers.txt"));
    let specs: Vec<Cookie<'static>> = lines(&dir.join("specs.tsv"))
        .iter()
        .map(|l| {
            let f: Vec<&str> = l.split('\t').collect();
            let age: i64 = f[4].parse().unwrap();
            let ss: u8 = f[7].parse().unwrap();
            let mut b = Cookie::build((f[0].to_string(), f[1].to_string()));
            if !f[2].is_empty() {
                b = b.path(f[2].to_string());
            }
            if !f[3].is_empty() {
                b = b.domain(f[3].to_string());
            }
            if age != 0 {
                b = b.max_age(Duration::seconds(age));
            }
            b = b.secure(f[5] == "1").http_only(f[6] == "1");
            b = match ss {
                1 => b.same_site(SameSite::Lax),
                2 => b.same_site(SameSite::Strict),
                3 => b.same_site(SameSite::None),
                _ => b,
            };
            b.build()
        })
        .collect();

    let (ns, count) = match name {
        "parse_find" => time_it(|| {
            let mut t = 0;
            for h in &headers {
                for c in Cookie::split_parse(black_box(h.as_str())) {
                    let c = c.unwrap();
                    if c.name() == "sid" {
                        t += sum(c.value()) + 1;
                        break;
                    }
                }
            }
            t
        }),
        "parse_all" => time_it(|| {
            let mut t = 0;
            for h in &headers {
                for c in Cookie::split_parse(black_box(h.as_str())) {
                    let c = c.unwrap();
                    t += sum(c.name()) + sum(c.value());
                }
            }
            t
        }),
        "build" => {
            let mut buf = String::with_capacity(1024);
            time_it(|| {
                let mut t = 0;
                for c in black_box(&specs) {
                    buf.clear();
                    write!(buf, "{}", c).unwrap();
                    t += sum(&buf);
                }
                t
            })
        }
        _ => {
            eprintln!("unknown workload {name}");
            std::process::exit(2);
        }
    };
    println!("{name}\t{ns:.1}\t{count}");
}
