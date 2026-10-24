// SPDX-License-Identifier: MIT

//! "Fastest in the field" side of `zig build bench-ratelimit`
//! (modules/ratelimit/tools/bench.zig): times governor 0.10.4 (GCRA, pinned in
//! Cargo.toml, no default features) over the request sequence the Zig program
//! writes into the directory given as the first argument, for the one workload
//! named by the second, through its public API only. Prints one line: name,
//! ns/op, result count (tab-separated). One op = the whole sequence once.
//!
//!   bucket  one direct `RateLimiter`, `check()` at each step's time
//!   keyed   one keyed `RateLimiter` over its HashMap store (a spinlock around
//!           a hashbrown HashMap with its default foldhash), `check_key` --
//!           governor keeps every key forever (no cap, no LRU, no idle
//!           expiry unless the caller runs `retain_recent`); this module's
//!           Limiter does all three per call.
//!
//! The clock is injected like the Zig side's `allowAt(now)`: a `Clock` whose
//! `now()` reads a plain cell the loop sets, so neither side pays for a clock
//! read (governor's own FakeRelativeClock advances with an atomic CAS loop).
//! GCRA admits exactly what a token bucket of the same rate and burst admits,
//! so the count must equal the Zig side's.
//!
//! Timing matches the Zig side: double the batch until it takes over 100 ms,
//! then keep the best of five.

use governor::clock::Clock;
use governor::nanos::Nanos;
use governor::{Quota, RateLimiter};
use std::cell::Cell;
use std::hint::black_box;
use std::num::NonZeroU32;
use std::rc::Rc;
use std::time::Instant;

#[derive(Clone)]
struct CellClock(Rc<Cell<u64>>);

impl Clock for CellClock {
    type Instant = Nanos;
    fn now(&self) -> Nanos {
        self.0.get().into()
    }
}

fn time_it(mut f: impl FnMut() -> u64) -> (f64, u64) {
    let mut n: u64 = 1;
    loop {
        let t = Instant::now();
        for _ in 0..n {
            black_box(f());
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
            count = black_box(f());
        }
        best = best.min(t.elapsed().as_nanos());
    }
    (best as f64 / n as f64, count)
}

fn lines(path: &std::path::Path) -> Vec<String> {
    let s = std::fs::read_to_string(path).unwrap_or_else(|e| {
        eprintln!("{}: {e}", path.display());
        std::process::exit(1)
    });
    s.trim_end_matches('\n').split('\n').map(str::to_owned).collect()
}

fn quota(rate: f64, burst: u32) -> Quota {
    // rate is whole tokens per second in both workloads (20000, 5).
    assert!(rate.fract() == 0.0 && rate >= 1.0, "rate {rate} is not a whole number");
    Quota::per_second(NonZeroU32::new(rate as u32).unwrap()).allow_burst(NonZeroU32::new(burst).unwrap())
}

fn main() {
    let args: Vec<String> = std::env::args().collect();
    if args.len() != 3 {
        eprintln!("usage: ratelimit_fast_bench <work dir> <workload>");
        std::process::exit(2);
    }
    let dir = std::path::Path::new(&args[1]);
    let name = args[2].as_str();
    let keys = lines(&dir.join("keys.txt"));
    let mut idx: Vec<usize> = Vec::new();
    let mut at: Vec<u64> = Vec::new();
    for l in lines(&dir.join("seq.tsv")) {
        let mut f = l.split('\t');
        idx.push(f.next().unwrap().parse().unwrap());
        at.push(f.next().unwrap().parse().unwrap());
    }
    let cfg_line = lines(&dir.join("cfg.txt")).remove(0);
    let cfg: Vec<&str> = cfg_line.split('\t').collect();
    let bucket_rate: f64 = cfg[0].parse().unwrap();
    let bucket_burst: u32 = cfg[1].parse().unwrap();
    let keyed_rate: f64 = cfg[2].parse().unwrap();
    let keyed_burst: u32 = cfg[3].parse().unwrap();
    eprintln!("governor 0.10.4 (GCRA; feature no_std: hashbrown HashMap store behind spinning_top)");

    let now = Rc::new(Cell::new(1_000_000_000_000u64));
    let clock = CellClock(now.clone());
    let mut pass: u64 = 0;
    let (ns, count) = match name {
        "bucket" => {
            let lim = RateLimiter::direct_with_clock(quota(bucket_rate, bucket_burst), clock);
            time_it(|| {
                pass += 1;
                let base = 1_000_000_000_000 + pass * 1_000_000_000;
                let mut n = 0;
                for &a in &at {
                    now.set(base + a);
                    if lim.check().is_ok() {
                        n += 1;
                    }
                }
                n
            })
        }
        "keyed" => {
            let lim = RateLimiter::hashmap_with_clock(quota(keyed_rate, keyed_burst), clock);
            time_it(|| {
                pass += 1;
                let base = 1_000_000_000_000 + pass * 1_000_000_000;
                let mut n = 0;
                for (&i, &a) in idx.iter().zip(&at) {
                    now.set(base + a);
                    if lim.check_key(&keys[i]).is_ok() {
                        n += 1;
                    }
                }
                n
            })
        }
        _ => {
            eprintln!("unknown workload {name}");
            std::process::exit(2)
        }
    };
    println!("{name}\t{ns:.1}\t{count}");
}
