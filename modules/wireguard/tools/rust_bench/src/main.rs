// SPDX-License-Identifier: MIT

// Rust side of `zig build bench-wireguard` (modules/wireguard/tools/bench.zig):
// boringtun 0.7.1 `noise::Tunn` (ring's ChaCha20-Poly1305, x25519-dalek), the
// sans-IO core of Cloudflare's userspace WireGuard, over the inputs the Zig
// program wrote into the directory given as the first argument, for the workload
// named by the second. Prints one line: name, ns/op, count (tab-separated).
//
//   rt.seal_<n>   Tunn::encapsulate on an established session
//   rt.open_<n>   Tunn::decapsulate of the next of 1024 messages sealed with
//                 counters in order. Tunn has no way to reset a replay window, so
//                 a new pair of tunnels, a handshake and new messages come every
//                 1024 opens, outside the time. (Our side and Go's reset their
//                 window once per 64, inside it. A touch in boringtun's favour.)
//   rt.handshake  format_handshake_initiation, decapsulate (the responder's),
//                 decapsulate (the initiator's, which seals the first keepalive),
//                 decapsulate (the responder's, of that keepalive). A new pair of
//                 tunnels per op, outside the time: a Tunn refuses a repeat of its
//                 peer's timestamp and has no way to reset it. The rate limiter is
//                 given a limit it never reaches, so it checks mac1 and nothing else.
//
// Timing matches the Zig side: double the batch until it takes over 100 ms, then
// keep the best of five. Wall time only, as Go's side counts no cycles.

use boringtun::noise::rate_limiter::RateLimiter;
use boringtun::noise::{Tunn, TunnResult};
use boringtun::x25519::{PublicKey, StaticSecret};
use std::hint::black_box;
use std::path::Path;
use std::sync::Arc;
use std::time::{Duration, Instant};

const CHUNK: usize = 1024;

fn read32(dir: &str, name: &str) -> [u8; 32] {
    std::fs::read(Path::new(dir).join(name))
        .expect("input")
        .try_into()
        .expect("32 bytes")
}

struct Keys {
    si: [u8; 32],
    sr: [u8; 32],
}

fn pair(k: &Keys) -> (Tunn, Tunn) {
    let si = StaticSecret::from(k.si);
    let sr = StaticSecret::from(k.sr);
    let pi = PublicKey::from(&si);
    let pr = PublicKey::from(&sr);
    let limit_i = Arc::new(RateLimiter::new(&pi, u64::MAX));
    let limit_r = Arc::new(RateLimiter::new(&pr, u64::MAX));
    (
        Tunn::new(si, pr, None, None, 1, Some(limit_i)),
        Tunn::new(sr, pi, None, None, 2, Some(limit_r)),
    )
}

/// One whole handshake; the count of handshake bytes on the wire.
fn handshake(a: &mut Tunn, b: &mut Tunn, buf1: &mut [u8], buf2: &mut [u8]) -> u64 {
    let m1 = match a.format_handshake_initiation(buf1, false) {
        TunnResult::WriteToNetwork(p) => p,
        _ => panic!("no initiation"),
    };
    let l1 = m1.len();
    let m2 = match b.decapsulate(None, m1, buf2) {
        TunnResult::WriteToNetwork(p) => p,
        _ => panic!("initiation refused"),
    };
    let l2 = m2.len();
    let k = match a.decapsulate(None, m2, buf1) {
        TunnResult::WriteToNetwork(p) => p,
        _ => panic!("response refused"),
    };
    match b.decapsulate(None, k, buf2) {
        TunnResult::Done => {}
        _ => panic!("keepalive refused"),
    }
    (l1 + l2) as u64
}

/// `step` runs `n` ops and returns the time they took (setup stays outside).
fn time_it(mut step: impl FnMut(u64) -> (Duration, u64)) -> (f64, u64) {
    let mut n = 1u64;
    loop {
        if step(n).0 > Duration::from_millis(100) {
            break;
        }
        n *= 2;
    }
    let mut best = Duration::MAX;
    let mut count = 0;
    for _ in 0..5 {
        let (d, c) = step(n);
        count = c;
        best = best.min(d);
    }
    (best.as_nanos() as f64 / n as f64, count)
}

fn main() {
    let args: Vec<String> = std::env::args().collect();
    if args.len() != 3 {
        panic!("usage: rust_bench <work dir> <workload>");
    }
    let (dir, name) = (&args[1], args[2].as_str());
    eprintln!("boringtun 0.7.1");
    let keys = Keys {
        si: read32(dir, "s_i.bin"),
        sr: read32(dir, "s_r.bin"),
    };
    let mut buf1 = vec![0u8; 2048];
    let mut buf2 = vec![0u8; 2048];

    let (ns, count) = if let Some(size) = name.strip_prefix("rt.seal_") {
        let msg = std::fs::read(Path::new(dir).join(format!("msg{size}.bin"))).expect("input");
        let (mut a, mut b) = pair(&keys);
        handshake(&mut a, &mut b, &mut buf1, &mut buf2);
        time_it(|n| {
            let mut count = 0;
            let t = Instant::now();
            for _ in 0..n {
                match a.encapsulate(black_box(&msg), &mut buf1) {
                    TunnResult::WriteToNetwork(p) => count = p.len() as u64,
                    _ => panic!("no session"),
                }
            }
            (t.elapsed(), count)
        })
    } else if let Some(size) = name.strip_prefix("rt.open_") {
        let msg = std::fs::read(Path::new(dir).join(format!("msg{size}.bin"))).expect("input");
        let mut ring: Vec<Vec<u8>> = vec![Vec::new(); CHUNK];
        time_it(|n| {
            let mut left = n;
            let mut spent = Duration::ZERO;
            let mut count = 0;
            while left > 0 {
                let (mut a, mut b) = pair(&keys);
                handshake(&mut a, &mut b, &mut buf1, &mut buf2);
                let take = left.min(CHUNK as u64) as usize;
                for slot in ring.iter_mut().take(take) {
                    match a.encapsulate(&msg, &mut buf1) {
                        TunnResult::WriteToNetwork(p) => {
                            slot.clear();
                            slot.extend_from_slice(p);
                        }
                        _ => panic!("no session"),
                    }
                }
                let t = Instant::now();
                for m in ring.iter().take(take) {
                    match b.decapsulate(None, black_box(m), &mut buf2) {
                        TunnResult::WriteToTunnelV4(p, _) => count = p.len() as u64,
                        _ => panic!("refused"),
                    }
                }
                spent += t.elapsed();
                left -= take as u64;
            }
            (spent, count)
        })
    } else if name == "rt.handshake" {
        time_it(|n| {
            let mut spent = Duration::ZERO;
            let mut count = 0;
            for _ in 0..n {
                let (mut a, mut b) = pair(&keys);
                let t = Instant::now();
                count = handshake(&mut a, &mut b, &mut buf1, &mut buf2);
                spent += t.elapsed();
            }
            (spent, count)
        })
    } else {
        panic!("unknown workload {name}");
    };
    println!("{name}\t{ns:.1}\t{count}");
}
