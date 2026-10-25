// SPDX-License-Identifier: MIT

// Fastest-in-the-field side of `zig build bench-ramcache`
// (modules/ramcache/tools/bench.zig): times the Rust caches quick_cache
// (`sync::Cache`, S3-FIFO-like CLOCK-Pro, ahash) and moka (`sync::Cache`,
// a Caffeine port, W-TinyLFU) through their public APIs -- default hashers,
// pinned by Cargo.lock -- on the same workloads as the Go side
// (`go_bench/main.go`): same key names, same splitmix64 zipf trace, same
// caps. The first argument (the Zig program's work directory) is unused;
// the second picks the cache, the third the workload. Prints one line:
// workload, ns per pass, result count (tab-separated), or `n/a` where the
// cache has no API for it (quick_cache has no TTL).
//
// Values are `Arc<[u8]>`: a hit hands out a reference-count bump, not a copy
// (the Zig side copies its 64 bytes out with `getBuf`; otter returns the
// stored slice). moka maintains asynchronously, like otter:
// `run_pending_tasks` runs before the clock starts and before it stops, as
// otter's `CleanUp` does on the Go side. Timing as the other sides: double
// the batch until it takes over 100 ms, keep the best of five.

use std::hint::black_box;
use std::sync::Arc;
use std::time::{Duration, Instant};

const CAPACITY: usize = 10_000;
const PRELOAD: usize = 8_000;
const PASS_OPS: usize = 10_000;
const VALUE_LEN: usize = 64;
const FRESH_KEYS: usize = 1 << 20;
const ZIPF_UNIVERSE: usize = 100_000;
const ZIPF_OPS: usize = 100_000;
const ZIPF_SEED: u64 = 0x853C49E6748FEA9B;

type Val = Arc<[u8]>;

/// The two caches behind one small interface.
enum C {
    Quick(quick_cache::sync::Cache<String, Val>),
    Moka(moka::sync::Cache<String, Val>),
}

impl C {
    fn new(who: &str, ttl: bool) -> Option<C> {
        match who {
            "quick_cache" => {
                if ttl {
                    return None;
                }
                Some(C::Quick(quick_cache::sync::Cache::new(CAPACITY)))
            }
            "moka" => {
                let mut b = moka::sync::Cache::builder().max_capacity(CAPACITY as u64);
                if ttl {
                    b = b.time_to_live(Duration::from_secs(3600));
                }
                Some(C::Moka(b.build()))
            }
            _ => None,
        }
    }
    fn get(&self, k: &str) -> Option<Val> {
        match self {
            C::Quick(c) => c.get(k),
            C::Moka(c) => c.get(k),
        }
    }
    fn set(&self, k: &str, v: &Val) {
        match self {
            C::Quick(c) => c.insert(k.to_owned(), v.clone()),
            C::Moka(c) => c.insert(k.to_owned(), v.clone()),
        }
    }
    fn settle(&self) {
        if let C::Moka(c) = self {
            c.run_pending_tasks();
        }
    }
    fn len(&self) -> usize {
        self.settle();
        match self {
            C::Quick(c) => c.len(),
            C::Moka(c) => c.entry_count() as usize,
        }
    }
}

fn time_it(mut f: impl FnMut() -> usize, settle: &dyn Fn()) -> (f64, usize) {
    let mut batch = |n: u64| {
        settle();
        let t = Instant::now();
        for _ in 0..n {
            black_box(f());
        }
        settle();
        t.elapsed()
    };
    let mut n: u64 = 1;
    while batch(n) <= Duration::from_millis(100) {
        n *= 2;
    }
    let mut best = Duration::MAX;
    for _ in 0..5 {
        best = best.min(batch(n));
    }
    (best.as_nanos() as f64 / n as f64, f())
}

fn splitmix(s: &mut u64) -> u64 {
    *s = s.wrapping_add(0x9E3779B97F4A7C15);
    let mut z = *s;
    z = (z ^ (z >> 30)).wrapping_mul(0xBF58476D1CE4E5B9);
    z = (z ^ (z >> 27)).wrapping_mul(0x94D049BB133111EB);
    z ^ (z >> 31)
}

fn keys(prefix: &str, n: usize) -> Vec<String> {
    (0..n).map(|i| format!("{prefix}{i}")).collect()
}

fn get_pass(c: &C, ks: &[String]) -> usize {
    let (mut hits, mut bytes, mut misses) = (0, 0, 0);
    for i in 0..PASS_OPS {
        match c.get(&ks[i % ks.len()]) {
            Some(v) => {
                hits += 1;
                bytes += v.len();
            }
            None => misses += 1,
        }
    }
    hits + bytes + misses
}

fn main() {
    let args: Vec<String> = std::env::args().collect();
    if args.len() != 4 {
        eprintln!("usage: rust_fast_bench <work dir> <cache> <workload>");
        std::process::exit(2);
    }
    let (who, name) = (args[2].as_str(), args[3].as_str());
    let value: Val = (0..VALUE_LEN).map(|i| b'a' + (i % 26) as u8).collect::<Vec<u8>>().into();
    let hot = keys("k", PRELOAD);
    let preloaded = |ttl: bool| -> Option<C> {
        let c = C::new(who, ttl)?;
        for k in &hot {
            c.set(k, &value);
        }
        c.settle();
        Some(c)
    };
    let na = || {
        println!("{name}\tn/a\t0");
        std::process::exit(0);
    };

    let (ns, count) = match name {
        "get_hit" | "ttl_get_hit" | "get_miss" | "put_update" => {
            let c = preloaded(name == "ttl_get_hit").unwrap_or_else(|| na());
            let missing = keys("m", PASS_OPS);
            let (ns, count) = match name {
                "get_miss" => time_it(|| get_pass(&c, &missing), &|| c.settle()),
                "put_update" => time_it(
                    || {
                        for i in 0..PASS_OPS {
                            c.set(&hot[i % hot.len()], &value);
                        }
                        PASS_OPS * VALUE_LEN
                    },
                    &|| c.settle(),
                ),
                _ => time_it(|| get_pass(&c, &hot), &|| c.settle()),
            };
            (ns, count + c.len())
        }
        "put_evict" => {
            let c = C::new(who, false).unwrap_or_else(|| na());
            for k in keys("w", CAPACITY) {
                c.set(&k, &value);
            }
            c.settle();
            let fresh = keys("f", FRESH_KEYS);
            let mut pos = 0;
            time_it(
                || {
                    for _ in 0..PASS_OPS {
                        c.set(&fresh[pos], &value);
                        pos = (pos + 1) & (FRESH_KEYS - 1);
                    }
                    PASS_OPS * VALUE_LEN
                },
                &|| c.settle(),
            )
        }
        "zipf_mixed" => {
            let mut cdf = vec![0f64; ZIPF_UNIVERSE];
            let mut total = 0.0;
            for (i, slot) in cdf.iter_mut().enumerate() {
                total += 1.0 / (i + 1) as f64;
                *slot = total;
            }
            let mut ids = vec![0usize; ZIPF_OPS];
            let mut writes = vec![false; ZIPF_OPS];
            let mut state = ZIPF_SEED;
            for i in 0..ZIPF_OPS {
                let u = (splitmix(&mut state) >> 11) as f64 * (1.0 / 9007199254740992.0) * total;
                let (mut lo, mut hi) = (0, ZIPF_UNIVERSE - 1);
                while lo < hi {
                    let mid = (lo + hi) / 2;
                    if cdf[mid] < u {
                        lo = mid + 1;
                    } else {
                        hi = mid;
                    }
                }
                ids[i] = lo;
                writes[i] = splitmix(&mut state) % 10 == 0;
            }
            let zk = keys("z", ZIPF_UNIVERSE);
            let c = C::new(who, false).unwrap_or_else(|| na());
            time_it(
                || {
                    let mut hits = 0;
                    for (i, &id) in ids.iter().enumerate() {
                        let k = &zk[id];
                        if writes[i] {
                            c.set(k, &value);
                        } else if c.get(k).is_some() {
                            hits += 1;
                        } else {
                            c.set(k, &value);
                        }
                    }
                    hits
                },
                &|| c.settle(),
            )
        }
        _ => {
            eprintln!("unknown workload {name}");
            std::process::exit(2);
        }
    };
    println!("{name}\t{ns:.1}\t{count}");
}
