// SPDX-License-Identifier: MIT

// Reference side of `zig build bench-encoding` (modules/encoding/tools/bench.zig):
// encoding_rs over the SAME generated files the Zig side reads.
//
//   rust_bench <work dir> <workload>           time it: name, ns/op, count (stderr: banner)
//   rust_bench <work dir> <workload> check     print "output-length fnv1a64" once
//
// The workload table (name, kind, input file) is mirrored in bench.zig and
// go_bench/main.go. One op = the whole input, whole-buffer API, the result an
// OWNED buffer allocated per op (`into_owned()` where encoding_rs would hand
// back a borrowed Cow: the contract on our side is an owned copy). The count
// is the output length in bytes.
//
//   dec1250    WINDOWS_1250.decode_without_bom_handling
//   decutf8    UTF_8.decode_without_bom_handling (malformed -> U+FFFD)
//   u16dec     UTF_16LE.decode_without_bom_handling
//   u16enc     mem::convert_str_to_utf16 into a Vec<u16> (encoding_rs has no
//              UTF-16 encoder in the Encoding API: UTF_16LE.output_encoding()
//              is UTF-8); the little-endian host's u16 bytes are the LE output
//   enc1250    WINDOWS_1250.encode (HTML NCR on unmappable -- none in the input)
//   enc1250u   Encoder::encode_from_utf8_without_replacement in a loop; every
//              Unmappable(c) writes '?' (our replacement) and goes on. This is
//              how the row is made comparable: the default `encode` would write
//              `&#128512;` and the lengths would differ.
//   stream*    Decoder::decode_to_utf8 over 4 KiB chunks into one reused
//              buffer (the stream is consumed per chunk, nothing accumulates)
//   celldec    one decode_without_bom_handling per 20-byte cell, 1 000 000 cells
//   cellenc    one WINDOWS_1250.encode per cell
use encoding_rs::{Encoding, EncoderResult, CoderResult, UTF_16LE, UTF_8, WINDOWS_1250};
use std::time::Instant;

const CHUNK: usize = 4096;

#[derive(Clone, Copy, PartialEq)]
enum Kind { Dec1250, DecUtf8, U16Dec, U16Enc, Enc1250, Enc1250U, Stream1250, StreamUtf8, CellDec, CellEnc }

const WORKS: &[(&str, Kind, &str)] = &[
    ("dec_1250_ascii", Kind::Dec1250, "ascii-v1.bin"),
    ("dec_1250_czech", Kind::Dec1250, "cz1250-v1.bin"),
    ("enc_1250_ascii", Kind::Enc1250, "ascii-v1.bin"),
    ("enc_1250_czech", Kind::Enc1250, "czutf8-v1.txt"),
    ("enc_1250_unmap", Kind::Enc1250U, "unmap-v1.txt"),
    ("dec_utf8_ascii", Kind::DecUtf8, "ascii-v1.bin"),
    ("dec_utf8_multi", Kind::DecUtf8, "multi-v1.txt"),
    ("dec_utf8_bad", Kind::DecUtf8, "bad-v1.txt"),
    ("u16_to_utf8", Kind::U16Dec, "multi16-v1.bin"),
    ("utf8_to_u16", Kind::U16Enc, "multi-v1.txt"),
    ("stream_1250", Kind::Stream1250, "cz1250-v1.bin"),
    ("stream_utf8", Kind::StreamUtf8, "multi-v1.txt"),
    ("cell_dec", Kind::CellDec, "cells1250-v1.bin"),
    ("cell_enc", Kind::CellEnc, "cellsutf8-v1.bin"),
];

/// Output sink: length always, FNV-1a-64 only in check mode.
struct Out { n: u64, h: u64, hashing: bool }
impl Out {
    fn new(hashing: bool) -> Out { Out { n: 0, h: 0xcbf29ce484222325, hashing } }
    #[inline]
    fn take(&mut self, s: &[u8]) {
        self.n += s.len() as u64;
        if self.hashing {
            for &b in s { self.h = (self.h ^ b as u64).wrapping_mul(0x100000001b3); }
        } else if let Some(&l) = s.last() {
            std::hint::black_box(l);
        }
    }
}

/// Cells file: per cell one length byte, then the bytes.
fn cells(data: &[u8]) -> Vec<&[u8]> {
    let mut v = Vec::new();
    let mut i = 0;
    while i < data.len() {
        let n = data[i] as usize;
        v.push(&data[i + 1..i + 1 + n]);
        i += 1 + n;
    }
    v
}

fn run(kind: Kind, data: &[u8], cs: &[&[u8]], strs: &[&str], whole: Option<&str>, out: &mut Out) {
    match kind {
        Kind::Dec1250 => {
            let s = WINDOWS_1250.decode_without_bom_handling(std::hint::black_box(data)).0.into_owned();
            out.take(s.as_bytes());
        }
        Kind::DecUtf8 => {
            let s = UTF_8.decode_without_bom_handling(std::hint::black_box(data)).0.into_owned();
            out.take(s.as_bytes());
        }
        Kind::U16Dec => {
            let s = UTF_16LE.decode_without_bom_handling(std::hint::black_box(data)).0.into_owned();
            out.take(s.as_bytes());
        }
        Kind::U16Enc => {
            let s = whole.unwrap();
            let mut v = vec![0u16; s.len() + 1];
            let n = encoding_rs::mem::convert_str_to_utf16(std::hint::black_box(s), &mut v);
            // SAFETY: u16 -> u8 view of an initialised buffer; the benchmark
            // host is little-endian (checked by the hash against the Zig side).
            let b = unsafe { std::slice::from_raw_parts(v.as_ptr() as *const u8, n * 2) };
            out.take(b);
        }
        Kind::Enc1250 => {
            let (c, _, _) = WINDOWS_1250.encode(std::hint::black_box(whole.unwrap()));
            let v = c.into_owned();
            out.take(&v);
        }
        Kind::Enc1250U => {
            let s = std::hint::black_box(whole.unwrap());
            let mut enc = WINDOWS_1250.new_encoder();
            let mut dst = vec![0u8; s.len() + 16];
            let (mut i, mut o) = (0usize, 0usize);
            loop {
                let (r, read, written) = enc.encode_from_utf8_without_replacement(&s[i..], &mut dst[o..], true);
                i += read;
                o += written;
                match r {
                    EncoderResult::InputEmpty => break,
                    EncoderResult::Unmappable(_) => { dst[o] = b'?'; o += 1; }
                    EncoderResult::OutputFull => panic!("output full"),
                }
            }
            out.take(&dst[..o]);
        }
        Kind::Stream1250 | Kind::StreamUtf8 => {
            let enc: &'static Encoding = if kind == Kind::Stream1250 { WINDOWS_1250 } else { UTF_8 };
            let mut dec = enc.new_decoder_without_bom_handling();
            let mut dst = vec![0u8; dec.max_utf8_buffer_length(CHUNK).unwrap()];
            let n = data.len().div_ceil(CHUNK);
            for k in 0..n {
                let chunk = &data[k * CHUNK..((k + 1) * CHUNK).min(data.len())];
                let last = k + 1 == n;
                let (r, read, written, _) = dec.decode_to_utf8(chunk, &mut dst, last);
                assert!(r == CoderResult::InputEmpty && read == chunk.len());
                out.take(&dst[..written]);
            }
        }
        Kind::CellDec => {
            for c in cs {
                let s = WINDOWS_1250.decode_without_bom_handling(std::hint::black_box(c)).0.into_owned();
                out.take(s.as_bytes());
            }
        }
        Kind::CellEnc => {
            for s in strs {
                let v = WINDOWS_1250.encode(std::hint::black_box(s)).0.into_owned();
                out.take(&v);
            }
        }
    }
}

fn fail(msg: &str) -> ! {
    eprintln!("rust_bench: {msg}");
    std::process::exit(1);
}

fn main() {
    let args: Vec<String> = std::env::args().collect();
    if args.len() != 3 && !(args.len() == 4 && args[3] == "check") {
        eprintln!("usage: rust_bench <work dir> <workload> [check]");
        std::process::exit(2);
    }
    let check = args.len() == 4;
    let Some(&(name, kind, file)) = WORKS.iter().find(|w| w.0 == args[2]) else {
        fail(&format!("unknown workload {:?}", args[2]));
    };
    let data = std::fs::read(format!("{}/{}", args[1], file)).unwrap_or_else(|e| fail(&format!("{file}: {e}")));
    let (cs, strs): (Vec<&[u8]>, Vec<&str>) = if matches!(kind, Kind::CellDec | Kind::CellEnc) {
        let cs = cells(&data);
        let strs = if kind == Kind::CellEnc { cs.iter().map(|c| std::str::from_utf8(c).unwrap()).collect() } else { vec![] };
        (cs, strs)
    } else {
        (vec![], vec![])
    };
    // &str input of the encoders: validated once, untimed.
    let whole = if matches!(kind, Kind::Enc1250 | Kind::Enc1250U | Kind::U16Enc) {
        Some(std::str::from_utf8(&data).unwrap_or_else(|e| fail(&format!("{file}: {e}"))))
    } else {
        None
    };

    if check {
        let mut o = Out::new(true);
        run(kind, &data, &cs, &strs, whole, &mut o);
        println!("{} {}", o.n, o.h);
        return;
    }

    let op = || {
        let mut o = Out::new(false);
        run(kind, &data, &cs, &strs, whole, &mut o);
        o.n
    };
    let mut n = 1usize;
    loop {
        let t = Instant::now();
        for _ in 0..n { std::hint::black_box(op()); }
        if t.elapsed().as_millis() > 100 { break; }
        n *= 2;
    }
    let mut best = u128::MAX;
    let mut count = 0;
    for _ in 0..5 {
        let t = Instant::now();
        for _ in 0..n { count = op(); }
        best = best.min(t.elapsed().as_nanos());
    }
    eprintln!("encoding_rs 0.8.42 (rustc release, lto, target-cpu per RUSTFLAGS; whole-buffer API)");
    println!("{}\t{:.1}\t{}", name, best as f64 / n as f64, count);
}
