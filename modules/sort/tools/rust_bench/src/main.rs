// SPDX-License-Identifier: MIT

// Reference side of `zig build bench-sort` (modules/sort/tools/bench.zig):
// Rust std `sort_unstable` (ipnsort), `sort` (driftsort) and
// `select_nth_unstable` -- the algorithms `sort` ports. Usage:
// `rust_bench <work dir> <workload>`; the workload name and the input
// generator are specified in bench.zig's header, and this file follows it.
// Prints `workload \t ns/op \t user-mode cycles/op \t count`; the banner
// goes to stderr. Timing as testkit.bench: double the batch until it takes
// over 100 ms, keep the best of five.

use std::hint::black_box;
use std::time::{Duration, Instant};

struct SplitMix(u64);
impl SplitMix {
    fn next(&mut self) -> u64 {
        self.0 = self.0.wrapping_add(0x9e3779b97f4a7c15);
        let mut z = self.0;
        z = (z ^ (z >> 30)).wrapping_mul(0xbf58476d1ce4e5b9);
        z = (z ^ (z >> 27)).wrapping_mul(0x94d049bb133111eb);
        z ^ (z >> 31)
    }
}

fn value(r: &mut SplitMix, pat: &str, i: usize, n: usize) -> u64 {
    match pat {
        "rand" => r.next(),
        "dup16" => r.next() % 16,
        "asc" => i as u64,
        "desc" => (n - i) as u64,
        "saw" => (i % 1000) as u64,
        "tail" => if i < n - n / 100 { i as u64 } else { r.next() },
        _ => panic!("pattern {pat}"),
    }
}

#[derive(Clone, Copy)]
struct Rec {
    key: u64,
    a: u64,
    #[allow(dead_code)]
    b: u64,
    #[allow(dead_code)]
    c: u64,
}

// User-mode cycles of this thread, via perf_event_open(2); 0 when refused.
extern "C" {
    fn syscall(n: i64, ...) -> i64;
    fn read(fd: i32, buf: *mut u8, n: usize) -> isize;
}
#[cfg(target_arch = "x86_64")]
const SYS_PERF_EVENT_OPEN: i64 = 298;
#[cfg(target_arch = "aarch64")]
const SYS_PERF_EVENT_OPEN: i64 = 241;

struct Cycles(i32);
impl Cycles {
    fn open() -> Cycles {
        let mut attr = [0u8; 128];
        attr[0..4].copy_from_slice(&0u32.to_ne_bytes()); // PERF_TYPE_HARDWARE
        attr[4..8].copy_from_slice(&128u32.to_ne_bytes()); // size
        attr[8..16].copy_from_slice(&0u64.to_ne_bytes()); // PERF_COUNT_HW_CPU_CYCLES
        let flags: u64 = (1 << 5) | (1 << 6); // exclude_kernel, exclude_hv
        attr[40..48].copy_from_slice(&flags.to_ne_bytes());
        let fd = unsafe { syscall(SYS_PERF_EVENT_OPEN, attr.as_ptr(), 0i32, -1i32, -1i32, 0u64) };
        Cycles(if fd < 0 { -1 } else { fd as i32 })
    }
    fn read(&self) -> u64 {
        if self.0 < 0 {
            return 0;
        }
        let mut v = [0u8; 8];
        unsafe { read(self.0, v.as_mut_ptr(), 8) };
        u64::from_ne_bytes(v)
    }
}

fn time_it(cyc: &Cycles, mut f: impl FnMut() -> u64) -> (f64, f64, u64) {
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
    let mut best_cyc = u64::MAX;
    let mut count = 0;
    for _ in 0..5 {
        let t = Instant::now();
        let c0 = cyc.read();
        for _ in 0..n {
            count = black_box(f());
        }
        best_cyc = best_cyc.min(cyc.read() - c0);
        best = best.min(t.elapsed());
    }
    (best.as_nanos() as f64 / n as f64, best_cyc as f64 / n as f64, count)
}

// Every 61st position, as bench.zig.
fn sum_by<T>(v: &[T], key: impl Fn(&T) -> u64) -> u64 {
    let mut k = 0u64;
    for (i, x) in v.iter().enumerate().step_by(61) {
        k = k.wrapping_add(((i + 1) as u64).wrapping_mul(key(x)));
    }
    k
}

fn run<T: Copy>(alg: &str, input: &[T], less: impl Fn(&T, &T) -> std::cmp::Ordering + Copy, sum: impl Fn(&[T]) -> u64, sel_key: impl Fn(&T) -> u64) -> (f64, f64, u64) {
    let cyc = Cycles::open();
    let mut w = input.to_vec();
    time_it(&cyc, || {
        w.copy_from_slice(input);
        match alg {
            "u" => { w.sort_unstable_by(less); sum(&w) }
            "s" => { w.sort_by(less); sum(&w) }
            "sel" => { let m = w.len() / 2; w.select_nth_unstable_by(m, less); sel_key(&w[m]) }
            _ => panic!("alg {alg}"),
        }
    })
}

fn main() {
    let args: Vec<String> = std::env::args().collect();
    let name = &args[2];
    let parts: Vec<&str> = name.split('_').collect();
    let (alg, ty, pat, ns) = (parts[0], parts[1], parts[2], parts[3]);
    let n: usize = ns[..ns.len() - 1].parse::<usize>().unwrap() * if ns.ends_with('k') { 1000 } else { 1_000_000 };
    let mut r = SplitMix(0x5eed);
    eprintln!("Rust std (sort_unstable / sort / select_nth_unstable)");
    let (ns_op, cyc_op, count) = match ty {
        "u64" => {
            let v: Vec<u64> = (0..n).map(|i| value(&mut r, pat, i, n)).collect();
            run(alg, &v, |a, b| a.cmp(b), |w| sum_by(w, |x| *x), |x| *x)
        }
        "u32" => {
            let v: Vec<u32> = (0..n).map(|i| { let x = value(&mut r, pat, i, n); if pat == "rand" { (x >> 32) as u32 } else { x as u32 } }).collect();
            run(alg, &v, |a, b| a.cmp(b), |w| sum_by(w, |x| *x as u64), |x| *x as u64)
        }
        "rec" => {
            let v: Vec<Rec> = (0..n).map(|i| Rec { key: value(&mut r, pat, i, n), a: i as u64, b: !(i as u64), c: (i as u64).wrapping_mul(3) }).collect();
            let stable = alg == "s";
            run(alg, &v, |a, b| a.key.cmp(&b.key), move |w| sum_by(w, |x| if stable { x.a } else { x.key }), |x| x.key)
        }
        "str" => {
            let owned: Vec<Vec<u8>> = (0..n).map(|_| {
                let len = 4 + (r.next() % 21) as usize;
                (0..len).map(|_| b'a' + (r.next() % 26) as u8).collect()
            }).collect();
            let v: Vec<&[u8]> = owned.iter().map(|s| s.as_slice()).collect();
            run(alg, &v, |a, b| a.cmp(b), |w| sum_by(w, |x| x.len() as u64 + x[0] as u64), |x| x[0] as u64)
        }
        _ => panic!("type {ty}"),
    };
    println!("{name}\t{ns_op}\t{cyc_op}\t{count}");
}
