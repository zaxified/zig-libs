// SPDX-License-Identifier: MIT

//! Fastest-in-the-field side of `zig build bench-workerpool`
//! (modules/workerpool/tools/bench.zig): the rows of tools/c_bench/main.c on
//! two Rust pools, through their public APIs only (pinned by Cargo.lock):
//!
//!   rayon       rayon-core 1.13.0 `ThreadPool` (4 threads, work stealing).
//!               A row is one `pool.scope(...)`: the scope body runs on a pool
//!               thread and `s.spawn`s the jobs; the scope's end is the wait.
//!               multi_producer: 4 std threads inside the scope each spawn
//!               25 000 jobs into it (the scope body's pool thread waits for
//!               them, so 3 threads run jobs while they produce).
//!   threadpool  threadpool 1.8.1 (4 threads, an mpsc channel; the classic
//!               fire-and-forget shape, like thpool): `execute`, then `join`.
//!
//! Usage: rust_fast_bench <rayon|threadpool> <workload>. Prints one line:
//! name, ns/op, count, sum (tab-separated), as the C side does. Timing as the
//! C side: double the batch until it takes over 100 ms, best of five.

use std::alloc::{GlobalAlloc, Layout, System};
use std::sync::atomic::{AtomicU64, Ordering::Relaxed};
use std::time::{Duration, Instant};

/// The system allocator, counting allocations: the `allocs` workload reads it.
struct Counting;
static ALLOCS: AtomicU64 = AtomicU64::new(0);
unsafe impl GlobalAlloc for Counting {
    unsafe fn alloc(&self, l: Layout) -> *mut u8 {
        ALLOCS.fetch_add(1, Relaxed);
        System.alloc(l)
    }
    unsafe fn dealloc(&self, p: *mut u8, l: Layout) {
        System.dealloc(p, l)
    }
    unsafe fn realloc(&self, p: *mut u8, l: Layout, n: usize) -> *mut u8 {
        ALLOCS.fetch_add(1, Relaxed);
        System.realloc(p, l, n)
    }
}
#[global_allocator]
static GLOBAL: Counting = Counting;

const BURST: u64 = 100_000;
const PINGPONG_N: u64 = 10_000;
const PRODUCERS: u64 = 4;
const PER_PRODUCER: u64 = 25_000;

static COUNT: AtomicU64 = AtomicU64::new(0);
static SUM: AtomicU64 = AtomicU64::new(0);

fn splitmix64(x: &mut u64) -> u64 {
    *x = x.wrapping_add(0x9e3779b97f4a7c15);
    let mut z = *x;
    z = (z ^ (z >> 30)).wrapping_mul(0xbf58476d1ce4e5b9);
    z = (z ^ (z >> 27)).wrapping_mul(0x94d049bb133111eb);
    z ^ (z >> 31)
}

fn job_noop(arg: u64) {
    COUNT.fetch_add(1, Relaxed);
    SUM.fetch_add(arg, Relaxed);
}

fn job_work(arg: u64) {
    let mut s = arg;
    let mut h = 0u64;
    for _ in 0..64 {
        h ^= splitmix64(&mut s);
    }
    COUNT.fetch_add(1, Relaxed);
    SUM.fetch_add(h, Relaxed);
}

/// `<pool> allocs`: heap allocations per job in the steady state -- a warm-up
/// burst_noop, then the allocations of a second one over its 100 000 jobs.
/// Prints `allocs \t <per job> \t <jobs> \t <allocations>`.
fn allocs(which: &str) {
    let rayon = rayon_core::ThreadPoolBuilder::new().num_threads(4).build().unwrap();
    let tp = threadpool::ThreadPool::new(4);
    let burst = || match which {
        "rayon" => rayon.scope(|s| {
            for i in 0..BURST {
                s.spawn(move |_| job_noop(i + 1));
            }
        }),
        _ => {
            for i in 0..BURST {
                tp.execute(move || job_noop(i + 1));
            }
            tp.join();
        }
    };
    burst();
    let before = ALLOCS.load(Relaxed);
    burst();
    let n = ALLOCS.load(Relaxed) - before;
    println!("allocs\t{:.3}\t{}\t{}", n as f64 / BURST as f64, BURST, n);
}

fn main() {
    let args: Vec<String> = std::env::args().collect();
    if args.len() != 3 {
        eprintln!("usage: rust_fast_bench <rayon|threadpool> <workload>");
        std::process::exit(2);
    }
    let (which, name) = (args[1].as_str(), args[2].as_str());
    if name == "allocs" {
        allocs(which);
        return;
    }
    let job: fn(u64) = match name {
        "burst_work" => job_work,
        "burst_noop" | "pingpong" | "multi_producer" => job_noop,
        _ => {
            eprintln!("unknown workload {name}");
            std::process::exit(2);
        }
    };
    let op: Box<dyn Fn()> = match which {
        "rayon" => {
            let pool = rayon_core::ThreadPoolBuilder::new().num_threads(4).build().unwrap();
            let name = name.to_owned();
            Box::new(move || match name.as_str() {
                "pingpong" => {
                    for i in 0..PINGPONG_N {
                        pool.scope(|s| s.spawn(move |_| job(i + 1)));
                    }
                }
                "multi_producer" => pool.scope(|s| {
                    std::thread::scope(|ts| {
                        for k in 0..PRODUCERS {
                            ts.spawn(move || {
                                for i in 0..PER_PRODUCER {
                                    s.spawn(move |_| job(k * PER_PRODUCER + i + 1));
                                }
                            });
                        }
                    })
                }),
                _ => pool.scope(|s| {
                    for i in 0..BURST {
                        s.spawn(move |_| job(i + 1));
                    }
                }),
            })
        }
        "threadpool" => {
            let pool = threadpool::ThreadPool::new(4);
            let name = name.to_owned();
            Box::new(move || match name.as_str() {
                "pingpong" => {
                    for i in 0..PINGPONG_N {
                        pool.execute(move || job(i + 1));
                        pool.join();
                    }
                }
                "multi_producer" => {
                    std::thread::scope(|ts| {
                        for k in 0..PRODUCERS {
                            let p = pool.clone();
                            ts.spawn(move || {
                                for i in 0..PER_PRODUCER {
                                    p.execute(move || job(k * PER_PRODUCER + i + 1));
                                }
                            });
                        }
                    });
                    pool.join();
                }
                _ => {
                    for i in 0..BURST {
                        pool.execute(move || job(i + 1));
                    }
                    pool.join();
                }
            })
        }
        _ => {
            eprintln!("unknown pool {which}");
            std::process::exit(2);
        }
    };
    let once = || {
        COUNT.store(0, Relaxed);
        SUM.store(0, Relaxed);
        op();
    };
    let mut n = 1u32;
    loop {
        let t = Instant::now();
        for _ in 0..n {
            once();
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
            once();
        }
        best = best.min(t.elapsed());
    }
    println!("{name}\t{:.1}\t{}\t{}", best.as_nanos() as f64 / n as f64, COUNT.load(Relaxed), SUM.load(Relaxed));
}
