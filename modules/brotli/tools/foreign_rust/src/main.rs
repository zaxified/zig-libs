// SPDX-License-Identifier: MIT
//
// Rust side of `zig build bench-brotli` (modules/brotli/tools/bench.zig):
// dropbox/rust-brotli 9.1.1, the reference since 2026-10-27 (google/brotli is
// the fastest; owner: the two roles are two implementations). Same protocol
// as tools/c_bench/foreign_bench.c: `<work dir> <workload>`, workloads
//   c<Q>_<payload>   the whole payload compressed in one FINISH call at
//                    quality Q, lgwin 22, size hint = the payload (rust-brotli
//                    has no public one-shot call; this is its nearest)
//   d_<payload>      brotli_decode of <payload>.ref.br into a buffer
// and one line out: name, ns/op, user-mode cycles/op, uncompressed bytes.
use brotli::enc::encode::{BrotliEncoderOperation, BrotliEncoderParameter, BrotliEncoderStateStruct};
use brotli::enc::StandardAlloc;
use std::fs::File;
use std::io::Read;
use std::os::unix::io::FromRawFd;
use std::time::Instant;

// perf_event_open(2) for this thread's user-mode cycles, without a libc crate.
fn cycles_open() -> Option<File> {
    let mut attr = [0u8; 128];
    attr[4..8].copy_from_slice(&128u32.to_le_bytes()); // size; type 0 = HARDWARE, config 0 = CPU_CYCLES
    attr[40..48].copy_from_slice(&((1u64 << 5) | (1u64 << 6)).to_le_bytes()); // exclude_kernel, exclude_hv
    let ret: isize;
    unsafe {
        std::arch::asm!("syscall", inlateout("rax") 298isize => ret, in("rdi") attr.as_ptr(), in("rsi") 0usize,
            in("rdx") -1isize, in("r10") -1isize, in("r8") 0usize, lateout("rcx") _, lateout("r11") _, options(nostack));
    }
    if ret < 0 { None } else { Some(unsafe { File::from_raw_fd(ret as i32) }) }
}

fn cycles_read(f: &mut Option<File>) -> u64 {
    let mut b = [0u8; 8];
    match f {
        Some(f) => if f.read_exact(&mut b).is_ok() { u64::from_le_bytes(b) } else { 0 },
        None => 0,
    }
}

fn bench(name: &str, mut f: impl FnMut() -> usize) {
    let mut cyc = cycles_open();
    let mut n = 1usize;
    loop {
        let t = Instant::now();
        for _ in 0..n { std::hint::black_box(f()); }
        if t.elapsed().as_nanos() > 100_000_000 { break; }
        n *= 2;
    }
    let (mut best, mut bestc, mut count) = (f64::MAX, f64::MAX, 0usize);
    for _ in 0..5 {
        let t = Instant::now();
        let c0 = cycles_read(&mut cyc);
        for _ in 0..n { count = std::hint::black_box(f()); }
        let c = (cycles_read(&mut cyc) - c0) as f64;
        best = best.min(t.elapsed().as_nanos() as f64);
        bestc = bestc.min(c);
    }
    let cpo = if cyc.is_none() { 0.0 } else { bestc / n as f64 };
    println!("{}\t{:.1}\t{:.1}\t{}", name, best / n as f64, cpo, count);
}

fn compress(input: &[u8], q: u32, out: &mut [u8]) -> usize {
    let mut s = BrotliEncoderStateStruct::new(StandardAlloc::default());
    s.set_parameter(BrotliEncoderParameter::BROTLI_PARAM_QUALITY, q);
    s.set_parameter(BrotliEncoderParameter::BROTLI_PARAM_LGWIN, 22);
    s.set_parameter(BrotliEncoderParameter::BROTLI_PARAM_SIZE_HINT, input.len() as u32);
    let (mut avail_in, mut in_off, mut avail_out, mut out_off, mut total) = (input.len(), 0usize, out.len(), 0usize, None);
    let ok = s.compress_stream(BrotliEncoderOperation::BROTLI_OPERATION_FINISH, &mut avail_in, input, &mut in_off,
        &mut avail_out, out, &mut out_off, &mut total, &mut |_, _, _, _| ());
    if !ok || !s.is_finished() { eprintln!("compress_stream did not finish"); std::process::exit(1); }
    out_off
}

fn main() {
    let a: Vec<String> = std::env::args().collect();
    if a.len() != 3 { eprintln!("usage: foreign_rust <work dir> <workload>"); std::process::exit(2); }
    eprintln!("dropbox/rust-brotli 9.1.1");
    let w = a[2].as_str();
    if let Some(threads) = w.strip_prefix("multi") {
        // `multi<N> <file>`: compress_multi over N threads, quality 9, lgwin
        // 22; prints the size and an FNV-1a hash of the stream (the S1 row:
        // do the bytes depend on N?).
        let input = std::fs::read(&a[1]).unwrap();
        let n: usize = threads.parse().expect("threads");
        let mut params = brotli::enc::BrotliEncoderParams::default();
        params.quality = 9;
        params.lgwin = 22;
        let mut alloc: Vec<_> = (0..n)
            .map(|_| brotli::enc::threading::SendAlloc::new(StandardAlloc::default(), brotli::enc::UnionHasher::Uninit))
            .collect();
        let mut out = vec![0u8; brotli::enc::BrotliEncoderMaxCompressedSizeMulti(input.len(), n)];
        let mut owned = brotli::enc::threading::Owned::new(alloc_stdlib::heap_alloc::WrapBox::from(input.clone()));
        let size = brotli::enc::compress_multi(&params, &mut owned, &mut out, &mut alloc[..]).expect("compress_multi");
        let mut back = vec![0u8; input.len() + 1];
        let info = brotli_decompressor::brotli_decode(&out[..size], &mut back);
        if info.decoded_size != input.len() || back[..input.len()] != input[..] { eprintln!("round trip failed"); std::process::exit(1); }
        let mut h: u64 = 0xcbf29ce484222325;
        for &b in &out[..size] { h = (h ^ b as u64).wrapping_mul(0x100000001b3); }
        println!("rust-brotli threads={n} size={size} fnv={h:016x}");
        return;
    }
    let (pay, q) = if let Some(rest) = w.strip_prefix('c') {
        let (qs, p) = rest.split_once('_').expect("workload");
        (p, Some(qs.parse::<u32>().expect("quality")))
    } else if let Some(p) = w.strip_prefix("d_") { (p, None) } else { eprintln!("unknown workload {w}"); std::process::exit(2) };
    let input = std::fs::read(format!("{}/{}.bin", a[1], pay)).unwrap();
    match q {
        Some(q) => {
            let mut out = vec![0u8; input.len() * 2 + 1024];
            // Checked once, outside the timing: the stream decodes back.
            let n = compress(&input, q, &mut out);
            let mut back = vec![0u8; input.len() + 1];
            let info = brotli_decompressor::brotli_decode(&out[..n], &mut back);
            if info.decoded_size != input.len() || back[..input.len()] != input[..] { eprintln!("round trip failed"); std::process::exit(1); }
            bench(w, || { std::hint::black_box(compress(&input, q, &mut out)); input.len() });
        }
        None => {
            let br = std::fs::read(format!("{}/{}.ref.br", a[1], pay)).unwrap();
            let mut out = vec![0u8; input.len() + 1];
            // Checked once, outside the timing, as the C side's length check.
            let info = brotli_decompressor::brotli_decode(&br, &mut out);
            if info.decoded_size != input.len() || out[..input.len()] != input[..] { eprintln!("decode mismatch"); std::process::exit(1); }
            bench(w, || {
                let info = brotli_decompressor::brotli_decode(&br, &mut out);
                if info.decoded_size != input.len() { eprintln!("brotli_decode failed"); std::process::exit(1); }
                info.decoded_size
            });
        }
    }
}
