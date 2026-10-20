// SPDX-License-Identifier: MIT

// Rust side of `zig build bench-procrun` (modules/procrun/tools/bench.zig):
// times std::process (standard library only) on the same child commands as the
// Zig and Go sides. Usage: rust_bench <work dir> <workload>; prints one line:
// name, ns/op, count (tab-separated). The work dir is unused.
//
//   spawn_true         200 x /bin/true, sequential: Command::status() with stdin,
//                      stdout, stderr = Stdio::null(). count = 200 clean exits
//   capture_100m       `head -c 104857600 /dev/zero`, Command::output() (stdout
//                      AND stderr piped, read by one poll loop in the calling
//                      thread, no helper thread). count = bytes
//   cat_roundtrip      32 MiB through `cat`: piped stdin written by a helper
//                      thread, Child::wait_with_output(). count = bytes + byte
//                      sum (the sum is computed on the first op only, outside
//                      the timing; later ops check the length)
//   capture_small_cap  the 100 MiB producer, stdout piped: read 1 KiB, then
//                      io::copy to io::sink to drain; count = the 1024 kept bytes
//   concurrent_true    8 threads x 50 x /bin/true status(). count = 400 clean exits
//
// Timing matches the Zig side: double the batch until one batch takes over
// 100 ms, then keep the best of five.

use std::hint::black_box;
use std::io::{self, Read, Write};
use std::process::{Command, Stdio};
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{Duration, Instant};

const BIG: usize = 100 << 20;
const CAT: usize = 32 << 20;
const SMALL_CAP: usize = 1024;

fn time_it(mut f: impl FnMut() -> u64) -> (f64, u64) {
    let mut n = 1u32;
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
            count = f();
        }
        best = best.min(t.elapsed());
    }
    (best.as_nanos() as f64 / n as f64, count)
}

fn run_true() -> bool {
    Command::new("/bin/true")
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()
        .map(|s| s.success())
        .unwrap_or(false)
}

fn big_producer() -> Command {
    let mut c = Command::new("/usr/bin/head");
    c.args(["-c", &BIG.to_string(), "/dev/zero"]);
    c
}

fn main() {
    let args: Vec<String> = std::env::args().collect();
    if args.len() != 3 {
        eprintln!("usage: rust_bench <work dir> <workload>");
        std::process::exit(2);
    }
    let name = args[2].as_str();
    eprintln!("Rust std::process (rustc release, lto)");

    let (ns, count) = match name {
        "spawn_true" => time_it(|| (0..200).filter(|_| run_true()).count() as u64),
        "capture_100m" => time_it(|| {
            let out = big_producer().stdin(Stdio::null()).output().unwrap();
            out.stdout.len() as u64
        }),
        "cat_roundtrip" => {
            let input: Vec<u8> = (0..CAT).map(|i| (i.wrapping_mul(31).wrapping_add(7)) as u8).collect();
            let mut sum = 0u64;
            let mut first = true;
            time_it(|| {
                let mut child = Command::new("/bin/cat")
                    .stdin(Stdio::piped())
                    .stdout(Stdio::piped())
                    .stderr(Stdio::null())
                    .spawn()
                    .unwrap();
                let mut stdin = child.stdin.take().unwrap();
                let out = std::thread::scope(|s| {
                    s.spawn(|| {
                        stdin.write_all(&input).unwrap();
                        drop(stdin);
                    });
                    child.wait_with_output().unwrap()
                });
                assert_eq!(out.stdout.len(), input.len());
                if first {
                    first = false;
                    assert!(out.stdout == input);
                    sum = out.stdout.iter().map(|&b| b as u64).sum();
                }
                out.stdout.len() as u64 + sum
            })
        }
        "capture_small_cap" => time_it(|| {
            let mut child = big_producer().stdin(Stdio::null()).stdout(Stdio::piped()).stderr(Stdio::null()).spawn().unwrap();
            let mut p = child.stdout.take().unwrap();
            let mut kept = vec![0u8; SMALL_CAP];
            p.read_exact(&mut kept).unwrap();
            io::copy(&mut p, &mut io::sink()).unwrap();
            child.wait().unwrap();
            kept.len() as u64
        }),
        "concurrent_true" => time_it(|| {
            let n = AtomicU64::new(0);
            std::thread::scope(|s| {
                for _ in 0..8 {
                    s.spawn(|| {
                        for _ in 0..50 {
                            if run_true() {
                                n.fetch_add(1, Ordering::Relaxed);
                            }
                        }
                    });
                }
            });
            n.load(Ordering::Relaxed)
        }),
        _ => {
            eprintln!("unknown workload {name}");
            std::process::exit(2);
        }
    };
    println!("{name}\t{ns:.1}\t{count}");
}
