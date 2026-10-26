// SPDX-License-Identifier: MIT

// "Fastest in the field" side of `zig build bench-tlsresume`
// (modules/tlsresume/tools/bench.zig): the same computations as the OpenSSL
// side (`tools/c_bench/foreign_bench.c`, read its header), written against
// aws-lc-rs 1.18.0 -- the crypto rustls uses by default.
//
//   tlsresume_fast_bench <work dir> seal_<N> | open_<N> | binder
//                                one line on stdout: name \t ns/op \t user
//                                cycles/op \t output bytes per op
//   tlsresume_fast_bench <work dir> interop
//                                writes aws_seal_<N>.bin and aws_binder.bin
//
// seal: AES-256-GCM (LessSafeKey, explicit nonce) of an N-byte state under the
// STEK, AAD = the 1-byte key id, blob = id || nonce || ct || tag. open: the
// inverse on the blob the Zig side sealed (tag checked; aws-lc-rs opens in
// place, so the blob body is copied into the work buffer first). binder: the
// RFC 8446 chain PSK = Expand-Label(rms, "resumption", 0x0000), early =
// Extract(0^32, PSK), binder key = Expand-Label(early, "res binder", Hash("")),
// finished key = Expand-Label(binder key, "finished", ""), binder =
// HMAC(finished key, transcript hash), with aws_lc_rs::hkdf and ::hmac.
// Each call re-keys the cipher / PRK / MAC, as the other sides do.
//
// Timing matches them: user-mode cycles of the calling thread
// (perf_event_open), batch doubled until it takes over 100 ms, best of five.

use aws_lc_rs::aead::{Aad, LessSafeKey, Nonce, UnboundKey, AES_256_GCM};
use aws_lc_rs::hkdf::{KeyType, Prk, Salt, HKDF_SHA256};
use aws_lc_rs::hmac;
use std::fs;
use std::hint::black_box;
use std::io::Read;
use std::time::Instant;

const BANNER: &str = "aws-lc-rs 1.18.0";
const LENS: [usize; 2] = [128, 512];

fn die(msg: String) -> ! {
    eprintln!("{msg}");
    std::process::exit(1)
}

// ---- cycle counter: perf_event_open, user mode only ----

#[cfg(target_arch = "x86_64")]
fn perf_open() -> Option<fs::File> {
    use std::os::fd::FromRawFd;
    // struct perf_event_attr, first 128 octets: type = HARDWARE (0) at 0,
    // size at 4, config = CPU_CYCLES (0) at 8, flags at 40 (bit 5
    // exclude_kernel, bit 6 exclude_hv).
    let mut attr = [0u64; 16];
    attr[0] = 128 << 32;
    attr[5] = (1 << 5) | (1 << 6);
    let fd: i64;
    // SAFETY: perf_event_open(attr, pid 0, cpu -1, group -1, flags 0); the
    // attr buffer outlives the call and the kernel only reads `size` octets.
    unsafe {
        std::arch::asm!(
            "syscall",
            inlateout("rax") 298i64 => fd,
            in("rdi") attr.as_ptr(),
            in("rsi") 0i64,
            in("rdx") -1i64,
            in("r10") -1i64,
            in("r8") 0i64,
            lateout("rcx") _,
            lateout("r11") _,
            options(nostack)
        );
    }
    if fd < 0 {
        return None;
    }
    // SAFETY: a fresh descriptor we own.
    Some(unsafe { fs::File::from_raw_fd(fd as i32) })
}

#[cfg(not(target_arch = "x86_64"))]
fn perf_open() -> Option<fs::File> {
    None
}

fn read_cycles(f: &mut Option<fs::File>) -> u64 {
    let mut b = [0u8; 8];
    match f.as_mut() {
        Some(f) => match f.read_exact(&mut b) {
            Ok(()) => u64::from_ne_bytes(b),
            Err(_) => 0,
        },
        None => 0,
    }
}

fn time_it(mut f: impl FnMut() -> usize) -> (f64, f64, usize) {
    let mut cyc = perf_open();
    let mut n: u64 = 1;
    let mut sink = 0usize;
    loop {
        let t = Instant::now();
        for _ in 0..n {
            sink = sink.wrapping_add(f());
        }
        if t.elapsed().as_millis() > 100 {
            break;
        }
        n *= 2;
    }
    let (mut best, mut bestc) = (u128::MAX, u64::MAX);
    let mut count = 0;
    for _ in 0..5 {
        let t = Instant::now();
        let c0 = read_cycles(&mut cyc);
        for _ in 0..n {
            count = f();
        }
        let c = read_cycles(&mut cyc).wrapping_sub(c0);
        best = best.min(t.elapsed().as_nanos());
        bestc = bestc.min(c);
    }
    black_box(sink);
    let cycles = if cyc.is_some() { bestc as f64 / n as f64 } else { 0.0 };
    (best as f64 / n as f64, cycles, count)
}

// ---- the recipe ----

fn read(dir: &str, name: &str) -> Vec<u8> {
    fs::read(format!("{dir}/{name}")).unwrap_or_else(|e| die(format!("{dir}/{name}: {e}")))
}

fn arr<const N: usize>(v: &[u8]) -> [u8; N] {
    v.try_into().unwrap_or_else(|_| die(format!("expected {N} bytes, got {}", v.len())))
}

struct Len(usize);
impl KeyType for Len {
    fn len(&self) -> usize {
        self.0
    }
}

const KEY_ID: u8 = 1;

/// blob = id || nonce || ct || tag into `out`; returns the blob length.
fn seal(key: &[u8; 32], nonce: &[u8; 12], pt: &[u8], out: &mut [u8]) -> usize {
    out[0] = KEY_ID;
    out[1..13].copy_from_slice(nonce);
    let k = LessSafeKey::new(UnboundKey::new(&AES_256_GCM, key).unwrap_or_else(|_| die("seal key".into())));
    let body = &mut out[13..13 + pt.len()];
    body.copy_from_slice(pt);
    let tag = k
        .seal_in_place_separate_tag(Nonce::assume_unique_for_key(*nonce), Aad::from([KEY_ID]), body)
        .unwrap_or_else(|_| die("seal".into()));
    out[13 + pt.len()..29 + pt.len()].copy_from_slice(tag.as_ref());
    pt.len() + 29
}

/// Opens `blob` (tag checked) into `work`; returns the plaintext length.
fn open(key: &[u8; 32], blob: &[u8], work: &mut [u8]) -> usize {
    let k = LessSafeKey::new(UnboundKey::new(&AES_256_GCM, key).unwrap_or_else(|_| die("open key".into())));
    let body = &blob[13..];
    work[..body.len()].copy_from_slice(body);
    let nonce = Nonce::assume_unique_for_key(arr(&blob[1..13]));
    let pt = k
        .open_in_place(nonce, Aad::from([blob[0]]), &mut work[..body.len()])
        .unwrap_or_else(|_| die("open (tag)".into()));
    pt.len()
}

/// HKDF-Expand-Label (RFC 8446 7.1) for a 32-byte output.
fn expand_label(prk: &Prk, label: &str, ctx: &[u8], out: &mut [u8; 32]) {
    let head = [0u8, 32, (6 + label.len()) as u8];
    let ctx_len = [ctx.len() as u8];
    let info: [&[u8]; 5] = [&head, b"tls13 ", label.as_bytes(), &ctx_len, ctx];
    prk.expand(&info, Len(32)).and_then(|okm| okm.fill(out)).unwrap_or_else(|_| die("expand".into()));
}

fn binder(rms: &[u8; 32], th: &[u8; 32], empty_hash: &[u8; 32], out: &mut [u8; 32]) {
    let (mut psk, mut bkey, mut fkey) = ([0u8; 32], [0u8; 32], [0u8; 32]);
    expand_label(&Prk::new_less_safe(HKDF_SHA256, rms), "resumption", &[0, 0], &mut psk);
    let early = Salt::new(HKDF_SHA256, &[0u8; 32]).extract(&psk);
    expand_label(&early, "res binder", empty_hash, &mut bkey);
    expand_label(&Prk::new_less_safe(HKDF_SHA256, &bkey), "finished", &[], &mut fkey);
    out.copy_from_slice(hmac::sign(&hmac::Key::new(hmac::HMAC_SHA256, &fkey), th).as_ref());
}

fn main() {
    let args: Vec<String> = std::env::args().collect();
    if args.len() != 3 {
        die("usage: tlsresume_fast_bench <work dir> interop|seal_<N>|open_<N>|binder".into());
    }
    let (dir, work) = (&args[1], args[2].as_str());
    eprintln!("{BANNER}");
    let key: [u8; 32] = arr(&read(dir, "key32.bin"));
    let nonce: [u8; 12] = arr(&read(dir, "nonce12.bin"));
    let rms: [u8; 32] = arr(&read(dir, "rms32.bin"));
    let th: [u8; 32] = arr(&read(dir, "th32.bin"));
    let eh: [u8; 32] = arr(&read(dir, "empty_hash32.bin"));
    let mut bout = [0u8; 32];

    if work == "interop" {
        for n in LENS {
            let pt = read(dir, &format!("pt{n}.bin"));
            let mut out = vec![0u8; n + 64];
            let l = seal(&key, &nonce, &pt, &mut out);
            fs::write(format!("{dir}/aws_seal_{n}.bin"), &out[..l]).unwrap_or_else(|e| die(format!("{e}")));
            // Also prove open round-trips here.
            let mut w = vec![0u8; n + 64];
            if open(&key, &out[..l], &mut w) != n || w[..n] != pt[..] {
                die(format!("open_{n}: round trip differs"));
            }
        }
        binder(&rms, &th, &eh, &mut bout);
        fs::write(format!("{dir}/aws_binder.bin"), bout).unwrap_or_else(|e| die(format!("{e}")));
        return;
    }
    let (ns, cyc, count) = if work == "binder" {
        time_it(|| {
            binder(&rms, &th, &eh, &mut bout);
            black_box(&bout);
            32
        })
    } else if let Some(n) = work.strip_prefix("seal_").and_then(|s| s.parse::<usize>().ok()) {
        let pt = read(dir, &format!("pt{n}.bin"));
        let mut out = vec![0u8; n + 64];
        time_it(|| {
            let l = seal(&key, &nonce, &pt, &mut out);
            black_box(&out);
            l
        })
    } else if let Some(n) = work.strip_prefix("open_").and_then(|s| s.parse::<usize>().ok()) {
        let blob = read(dir, &format!("blob{n}.bin"));
        let mut w = vec![0u8; n + 64];
        time_it(|| {
            let l = open(&key, &blob, &mut w);
            black_box(&w);
            l
        })
    } else {
        die(format!("unknown workload {work}"))
    };
    println!("{work}\t{ns:.1}\t{cyc:.1}\t{count}");
}
