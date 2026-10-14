// SPDX-License-Identifier: MIT

// Reference side of `zig build bench-lockfree` (modules/lockfree/tools/bench.zig):
// times crossbeam-queue 0.3.14, crossbeam-deque 0.8.8 and crossbeam-epoch 0.9.21
// (pinned in Cargo.toml) through their public API on the SAME workloads the Zig
// program runs. `lockfree_bench <row>` prints one line, tab separated:
//
//	row, ns per op, count, sum
//
// One op is the whole row. count and sum are the row's result checksum (items
// received, wrapping sum of their values), compared by the Zig program.
// Producer p sends (p << 32) | seq for seq in 1..=n/producers.
//
//	bounded_1x1     ArrayQueue(1024), 1 producer, 1 consumer, 4 Mi items
//	bounded_4x4     ArrayQueue(1024), 4 producers, 4 consumers, 4 Mi items
//	bounded_4x1     ArrayQueue(1024), 4 producers, 1 consumer, 4 Mi items
//	unbounded_1x1   SegQueue, 1 producer, 1 consumer, 4 Mi items
//	unbounded_4x4   SegQueue, 4 producers, 4 consumers, 4 Mi items
//	deque_owner     Worker::new_lifo: push 1 Mi then pop all, one thread
//	deque_steal     Worker::new_lifo: push 1 Mi, then the owner pops while 3
//	                stealers steal one at a time until all are taken
//	epoch_pin       1 Mi pin + unpin on a registered LocalHandle, one thread
//
// A full push / empty pop spins (spin_loop hint) and retries, on both sides.
// Threads wait at a start flag; the clock runs from the flag to the last join.
// Each row runs once to warm up, then five times; the best time is printed.

use crossbeam_deque::{Steal, Worker};
use crossbeam_epoch::Collector;
use crossbeam_queue::{ArrayQueue, SegQueue};
use std::hint::{black_box, spin_loop};
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::time::Instant;

const N_QUEUE: u64 = 4 << 20;
const N_DEQUE: u64 = 1 << 20;
const N_PIN: u64 = 1 << 20;
const RING: usize = 1024;

#[derive(Clone, Copy)]
struct Res {
    count: u64,
    sum: u64,
}

fn wait_start(go: &AtomicBool) {
    while !go.load(Ordering::Acquire) {
        spin_loop();
    }
}

/// Producers/consumers over any push/pop pair; returns (elapsed ns, result).
fn mpmc<Q: Sync>(
    q: &Q,
    producers: u64,
    consumers: u64,
    n: u64,
    push: fn(&Q, u64) -> bool,
    pop: fn(&Q) -> Option<u64>,
) -> (u128, Res) {
    let go = AtomicBool::new(false);
    let received = AtomicU64::new(0);
    let total_sum = AtomicU64::new(0);
    let per = n / producers;
    let mut elapsed = 0;
    std::thread::scope(|s| {
        for p in 0..producers {
            let go = &go;
            s.spawn(move || {
                wait_start(go);
                for seq in 1..=per {
                    let v = (p << 32) | seq;
                    while !push(q, v) {
                        spin_loop();
                    }
                }
            });
        }
        let mut hs = Vec::new();
        for _ in 0..consumers {
            let (go, received, total_sum) = (&go, &received, &total_sum);
            hs.push(s.spawn(move || {
                wait_start(go);
                let mut sum = 0u64;
                let mut got = 0u64;
                loop {
                    match pop(q) {
                        Some(v) => {
                            sum = sum.wrapping_add(v);
                            got += 1;
                            if received.fetch_add(1, Ordering::Relaxed) + 1 == per * producers {
                                break;
                            }
                        }
                        None => {
                            if received.load(Ordering::Relaxed) == per * producers {
                                break;
                            }
                            spin_loop();
                        }
                    }
                }
                total_sum.fetch_add(sum, Ordering::Relaxed);
                black_box(got);
            }));
        }
        let t = Instant::now();
        go.store(true, Ordering::Release);
        for h in hs {
            h.join().unwrap();
        }
        elapsed = t.elapsed().as_nanos();
    });
    (
        elapsed,
        Res {
            count: received.load(Ordering::Relaxed),
            sum: total_sum.load(Ordering::Relaxed),
        },
    )
}

fn bounded(p: u64, c: u64) -> (u128, Res) {
    let q = ArrayQueue::<u64>::new(RING);
    mpmc(&q, p, c, N_QUEUE, |q, v| q.push(v).is_ok(), |q| q.pop())
}

fn unbounded(p: u64, c: u64) -> (u128, Res) {
    let q = SegQueue::<u64>::new();
    mpmc(
        &q,
        p,
        c,
        N_QUEUE,
        |q, v| {
            q.push(v);
            true
        },
        |q| q.pop(),
    )
}

fn deque_owner() -> (u128, Res) {
    let w = Worker::<u64>::new_lifo();
    let t = Instant::now();
    for v in 1..=N_DEQUE {
        w.push(v);
    }
    let (mut count, mut sum) = (0u64, 0u64);
    while let Some(v) = w.pop() {
        count += 1;
        sum = sum.wrapping_add(v);
    }
    (t.elapsed().as_nanos(), Res { count, sum })
}

fn deque_steal() -> (u128, Res) {
    let w = Worker::<u64>::new_lifo();
    for v in 1..=N_DEQUE {
        w.push(v);
    }
    let go = AtomicBool::new(false);
    let total = AtomicU64::new(0);
    let total_sum = AtomicU64::new(0);
    let mut elapsed = 0;
    std::thread::scope(|s| {
        let mut hs = Vec::new();
        for _ in 0..3 {
            let st = w.stealer();
            let (go, total, total_sum) = (&go, &total, &total_sum);
            hs.push(s.spawn(move || {
                wait_start(go);
                let (mut count, mut sum) = (0u64, 0u64);
                loop {
                    match st.steal() {
                        Steal::Success(v) => {
                            count += 1;
                            sum = sum.wrapping_add(v);
                        }
                        Steal::Retry => spin_loop(),
                        Steal::Empty => break,
                    }
                }
                total.fetch_add(count, Ordering::Relaxed);
                total_sum.fetch_add(sum, Ordering::Relaxed);
            }));
        }
        let t = Instant::now();
        go.store(true, Ordering::Release);
        let (mut count, mut sum) = (0u64, 0u64);
        while let Some(v) = w.pop() {
            count += 1;
            sum = sum.wrapping_add(v);
        }
        for h in hs {
            h.join().unwrap();
        }
        elapsed = t.elapsed().as_nanos();
        total.fetch_add(count, Ordering::Relaxed);
        total_sum.fetch_add(sum, Ordering::Relaxed);
    });
    (
        elapsed,
        Res {
            count: total.load(Ordering::Relaxed),
            sum: total_sum.load(Ordering::Relaxed),
        },
    )
}

fn epoch_pin() -> (u128, Res) {
    let c = Collector::new();
    let h = c.register();
    let t = Instant::now();
    for _ in 0..N_PIN {
        let g = h.pin();
        black_box(&g);
    }
    (t.elapsed().as_nanos(), Res { count: N_PIN, sum: 0 })
}

fn run(row: &str) -> Option<(u128, Res)> {
    Some(match row {
        "bounded_1x1" => bounded(1, 1),
        "bounded_4x4" => bounded(4, 4),
        "bounded_4x1" => bounded(4, 1),
        "unbounded_1x1" => unbounded(1, 1),
        "unbounded_4x4" => unbounded(4, 4),
        "deque_owner" => deque_owner(),
        "deque_steal" => deque_steal(),
        "epoch_pin" => epoch_pin(),
        _ => return None,
    })
}

fn main() {
    let row = std::env::args().nth(1).expect("usage: lockfree_bench <row>");
    let (_, warm) = run(&row).unwrap_or_else(|| panic!("unknown row {row}"));
    let mut best = u128::MAX;
    for _ in 0..5 {
        let (ns, r) = run(&row).unwrap();
        assert!(r.count == warm.count && r.sum == warm.sum, "unstable checksum");
        best = best.min(ns);
    }
    println!("{}\t{}\t{}\t{}", row, best, warm.count, warm.sum);
}
