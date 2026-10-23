// SPDX-License-Identifier: MIT

// Rust side of the "fastest in the field" part of `zig build bench-router`
// (modules/router/tools/bench.zig): times matchit (the router under axum),
// pinned in Cargo.toml, over the route table and the requests that program
// writes into the directory given as the only argument.
//
// matchit matches paths only. The method is handled the way axum does it: one
// path router whose value says which methods the path has, checked after the
// path matched. So a request counts as a match only if the path matched AND the
// method is registered for the node matchit picked (a 405 is a miss).
//
// Reads routes_plain.tsv / requests_plain.tsv: the subset the colon-free
// whole-segment syntax can express (static segments, whole-segment `{name}`
// captures, a trailing `*`). A route outside it is an error (exit 3,
// `unsupported` on stdout), never dropped or rewritten: `{name}` is kept as it
// is, a final `*` becomes `{*rest}`.
//
// Output: `lookup<TAB>ns/op<TAB>count`; one op is every request once. Timing
// matches go_bench: double the batch until it takes over 100 ms, best of five.
use std::collections::HashMap;
use std::hint::black_box;
use std::process::exit;
use std::time::{Duration, Instant};

fn method_bit(m: &str) -> u8 {
    match m {
        "GET" => 1,
        "POST" => 2,
        "PUT" => 4,
        "DELETE" => 8,
        "PATCH" => 16,
        _ => {
            eprintln!("unknown method {m}");
            exit(2);
        }
    }
}

fn read_tsv(path: &str) -> Vec<(String, String)> {
    let text = std::fs::read_to_string(path).unwrap_or_else(|e| {
        eprintln!("{path}: {e}");
        exit(1);
    });
    text.lines()
        .map(|l| {
            let mut f = l.split('\t');
            match (f.next(), f.next(), f.next()) {
                (Some(m), Some(p), None) => (m.to_string(), p.to_string()),
                _ => {
                    eprintln!("bad line {l:?}");
                    exit(1);
                }
            }
        })
        .collect()
}

// `{name}` as a whole segment stays; a final `*` becomes `{*rest}`; anything
// else with a brace, colon or star is refused.
fn translate(pattern: &str) -> Option<String> {
    let segs: Vec<&str> = pattern.split('/').collect();
    let mut out = Vec::with_capacity(segs.len());
    for (i, s) in segs.iter().enumerate() {
        if s.len() > 2 && s.starts_with('{') && s.ends_with('}') {
            let name = &s[1..s.len() - 1];
            if name.contains(['{', '}', ':', '*']) {
                return None;
            }
            out.push(s.to_string());
        } else if *s == "*" {
            if i != segs.len() - 1 {
                return None;
            }
            out.push("{*rest}".to_string());
        } else if s.contains(['{', '}', ':', '*']) {
            return None;
        } else {
            out.push(s.to_string());
        }
    }
    Some(out.join("/"))
}

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

fn main() {
    let args: Vec<String> = std::env::args().collect();
    if args.len() != 2 {
        eprintln!("usage: rust_fast_bench <work dir>");
        exit(2);
    }
    let routes = read_tsv(&format!("{}/routes_plain.tsv", args[1]));
    let reqs = read_tsv(&format!("{}/requests_plain.tsv", args[1]));

    let mut router: matchit::Router<usize> = matchit::Router::new();
    let mut masks: Vec<u8> = Vec::new();
    let mut index: HashMap<String, usize> = HashMap::new();
    for (m, p) in &routes {
        let Some(t) = translate(p) else {
            eprintln!("unsupported route {m} {p}: pattern outside the supported syntax");
            println!("lookup\tunsupported");
            exit(3);
        };
        let i = *index.entry(t.clone()).or_insert_with(|| {
            masks.push(0);
            masks.len() - 1
        });
        if masks[i] == 0 {
            router.insert(t, i).unwrap(); // a conflicting table is a refusal, not a silent change
        }
        masks[i] |= method_bit(m);
    }
    let reqs: Vec<(u8, String)> = reqs.into_iter().map(|(m, p)| (method_bit(&m), p)).collect();

    let (ns, count) = time_it(|| {
        let mut found = 0;
        for (bit, path) in &reqs {
            if let Ok(hit) = router.at(black_box(path)) {
                if masks[*hit.value] & bit != 0 {
                    found += 1;
                }
            }
        }
        found
    });
    println!("lookup\t{ns:.1}\t{count}");
}
