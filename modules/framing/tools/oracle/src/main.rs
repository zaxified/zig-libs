// SPDX-License-Identifier: MIT
//! Differential oracle and foreign bench side for the `framing` module: drives
//! tokio-util 0.7.19's `LengthDelimitedCodec` (MIT) through its public builder
//! API; the bench also runs asynchronous-codec 0.7.0's `LengthCodec` (MIT).
//!
//! stdin, one case per line, hex without separators ("-" = empty):
//!   E <width 1..8> <l|b> <adj_t> <max_t> <payload>   -> hex of the encoded frame, or "E"
//!   D <width 1..8> <l|b> <offset> <adj_t> <skip> <max_t> <stream>
//!                                                    -> "F:<hex>" per frame, then "N" (need more) or "E"
//! `adj_t` is tokio's length_adjustment, `max_t` its max_frame_length (which
//! bounds the raw field). The Zig driver translates its own Prefix/Limits.
//! With two arguments (`<work dir> <name>`) it is the foreign side of tools/bench.zig.
use bytes::{Bytes, BytesMut};
use std::io::{BufRead, Write};
use std::time::Instant;
use tokio_util::codec::{Decoder, Encoder, LengthDelimitedCodec};

fn unhex(s: &str) -> Vec<u8> {
    if s == "-" {
        return Vec::new();
    }
    (0..s.len() / 2).map(|i| u8::from_str_radix(&s[2 * i..2 * i + 2], 16).unwrap()).collect()
}

fn hex(b: &[u8]) -> String {
    if b.is_empty() {
        return "-".into();
    }
    b.iter().map(|x| format!("{:02x}", x)).collect()
}

fn builder(width: usize, endian: &str, adj: isize, max: usize) -> tokio_util::codec::length_delimited::Builder {
    let mut b = LengthDelimitedCodec::builder();
    b.length_field_length(width).length_adjustment(adj).max_frame_length(max);
    if endian == "l" {
        b.little_endian();
    } else {
        b.big_endian();
    }
    b
}

const N: usize = 64;
/// Largest max_frame_length the stdin cases may declare (16 MiB).
const MAX_DECLARED: u64 = 16 << 20;

fn payload_of(frame: usize, i: usize) -> u8 {
    (i * 31 + frame * 7) as u8
}

fn best_ns(mut once: impl FnMut() -> u64) -> (f64, u64) {
    let mut n = 1usize;
    loop {
        let t = Instant::now();
        for _ in 0..n {
            std::hint::black_box(once());
        }
        if t.elapsed().as_nanos() > 100_000_000 {
            break;
        }
        n *= 2;
    }
    let mut best = f64::MAX;
    let mut count = 0;
    for _ in 0..5 {
        let t = Instant::now();
        for _ in 0..n {
            count = std::hint::black_box(once());
        }
        best = best.min(t.elapsed().as_nanos() as f64 / n as f64);
    }
    (best, count)
}

/// `framing-oracle <work dir> <name>`: one bench workload, the foreign side of
/// tools/bench.zig. One op = N=64 frames with a u64 big-endian length field
/// (the one wire both libraries speak: asynchronous-codec's LengthCodec is
/// fixed to it). Per op, both sides do the same work (bench.zig's header):
///   dec_*      the stream (read from `<dir>/stream_<size>.bin`) is copied
///              into the codec's own buffer type (BytesMut::clear +
///              extend_from_slice), then `decode` yields the 64 frames, each
///              handed out without copying; count = sum of len + first +
///              last byte of every frame.
///   enc_*      64 `encode` calls of a refcounted `Bytes` payload into a
///              BytesMut cleared between ops (capacity kept); count =
///              output length + its last byte.
/// A name with the prefix `alt:` runs asynchronous-codec 0.7.0 instead of
/// tokio-util.
fn bench_main(dir: &str, name: &str) {
    let (alt, bare) = match name.strip_prefix("alt:") {
        Some(n) => (true, n),
        None => (false, name),
    };
    let size: usize = bare[4..].parse().unwrap();
    let payloads: Vec<Bytes> = (0..N).map(|f| Bytes::from((0..size).map(|i| payload_of(f, i)).collect::<Vec<u8>>())).collect();
    let mut tk = LengthDelimitedCodec::builder().big_endian().length_field_length(8).max_frame_length(usize::MAX >> 1).new_codec();
    let mut ac = asynchronous_codec::LengthCodec;
    let (ns, count) = if bare.starts_with("dec_") {
        let stream = std::fs::read(format!("{}/stream_{}.bin", dir, size)).unwrap();
        let mut src = BytesMut::with_capacity(stream.len());
        best_ns(|| {
            src.clear();
            src.extend_from_slice(&stream);
            let mut t = 0u64;
            if alt {
                while let Some(f) = asynchronous_codec::Decoder::decode(&mut ac, &mut src).unwrap() {
                    t += f.len() as u64 + f[0] as u64 + f[f.len() - 1] as u64;
                }
            } else {
                while let Some(f) = tk.decode(&mut src).unwrap() {
                    t += f.len() as u64 + f[0] as u64 + f[f.len() - 1] as u64;
                }
            }
            t
        })
    } else {
        let mut dst = BytesMut::with_capacity(N * (size + 8));
        best_ns(|| {
            dst.clear();
            for p in &payloads {
                if alt {
                    asynchronous_codec::Encoder::encode(&mut ac, p.clone(), &mut dst).unwrap();
                } else {
                    tk.encode(p.clone(), &mut dst).unwrap();
                }
            }
            dst.len() as u64 + dst[dst.len() - 1] as u64
        })
    };
    println!("{}\t{:.2}\t{}", name, ns, count);
    eprintln!("{} (Rust, release, lto)", if alt { "asynchronous-codec 0.7.0 LengthCodec" } else { "tokio-util 0.7.19 LengthDelimitedCodec" });
}

fn main() {
    let args: Vec<String> = std::env::args().collect();
    if args.len() == 3 {
        bench_main(&args[1], &args[2]);
        return;
    }
    let stdin = std::io::stdin();
    let mut out = std::io::stdout().lock();
    for line in stdin.lock().lines() {
        let line = line.unwrap();
        let f: Vec<&str> = line.split(' ').collect();
        // Bound: tokio reserves by the declared length, so a case whose
        // max_frame_length exceeds MAX_DECLARED is refused ("R"), not run.
        // A refusal is not agreement: tools/diff.zig counts it separately.
        let max_t: u64 = match f[0] {
            "E" => f[4].parse().unwrap_or(u64::MAX),
            "D" => f[6].parse().unwrap_or(u64::MAX),
            _ => 0,
        };
        let res = if max_t > MAX_DECLARED {
            "R".to_string()
        } else {
          match f[0] {
            "E" => {
                let width: usize = f[1].parse().unwrap();
                let mut c = builder(width, f[2], f[3].parse().unwrap(), f[4].parse().unwrap()).new_codec();
                let mut dst = BytesMut::new();
                let payload = unhex(f[5]);
                // tokio's encoder panics (put_uint) when the field does not fit
                // its width; that is the caller's contract there, answered "E".
                let n = payload.len() as i128 - f[3].parse::<i128>().unwrap();
                if n >= 0 && n < (1i128 << (8 * width)) {
                    match c.encode(Bytes::from(payload), &mut dst) {
                        Ok(()) => hex(&dst),
                        Err(_) => "E".into(),
                    }
                } else {
                    "E".into()
                }
            }
            "D" => {
                let width: usize = f[1].parse().unwrap();
                let offset: usize = f[3].parse().unwrap();
                let mut b = builder(width, f[2], f[4].parse().unwrap(), f[6].parse().unwrap());
                b.length_field_offset(offset).num_skip(f[5].parse().unwrap());
                let mut c = b.new_codec();
                let mut src = BytesMut::from(&unhex(f[7])[..]);
                let mut parts: Vec<String> = Vec::new();
                loop {
                    match c.decode(&mut src) {
                        Ok(Some(fr)) => {
                            parts.push(format!("F:{}", hex(&fr)));
                            // tokio hands out a frame without consuming input when
                            // num_skip + n == 0 (num_skip below the head): endless.
                            if parts.len() > 4096 {
                                parts.push("L".into());
                                break;
                            }
                        }
                        Ok(None) => {
                            parts.push("N".into());
                            break;
                        }
                        Err(_) => {
                            parts.push("E".into());
                            break;
                        }
                    }
                }
                parts.join(" ")
            }
            _ => "?".into(),
          }
        };
        writeln!(out, "{}", res).unwrap();
    }
}
