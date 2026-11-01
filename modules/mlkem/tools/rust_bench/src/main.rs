// SPDX-License-Identifier: MIT
//
// Alt side of `zig build bench-mlkem` (modules/mlkem/tools/bench.zig):
// aws-lc-rs 1.18.0 (Rust over AWS-LC, the fastest ML-KEM in the field), through
// its public `kem` API only, doing the work `mlkem` does on the same inputs as
// `c_bench/foreign_bench.c` (read its header for the workload list).
//
//   rust_bench <work dir> <workload>   name \t ns/op \t user cycles/op \t count
//   rust_bench <work dir> interop      check against the files the Zig side wrote
//   rust_bench <work dir> interop2     second half of the check
//
// Workloads: keygen_<n>, encaps_<n>, decaps_<n>, ek_parse_<n>, n = 512 | 768 | 1024.
//  * keygen:   `DecapsulationKey::generate` + `encapsulation_key().key_bytes()`.
//  * encaps:   `EncapsulationKey::new(ek bytes)` + `encapsulate()`.
//  * decaps:   `decapsulate` with an already loaded key (the one `generate` made).
//  * ek_parse: `EncapsulationKey::new` alone. aws-lc-rs does NOT run the FIPS 203
//    §7.2 modulus check there (it hands the octets to AWS-LC's raw-public-key
//    constructor), so this row is not like for like with a validating parser.
//  Allocation: the API returns owned buffers (Vec / Box); that cost stays in.
//  Randomness: aws-lc's own DRBG.
//
// The cycle counter is perf_event_open, user mode only, read outside the
// monotonic-clock window of a batch.

use aws_lc_rs::kem::{self, Ciphertext, DecapsulationKey, EncapsulationKey};
use std::fs;
use std::hint::black_box;
use std::io::Read;
use std::process::exit;
use std::time::Instant;

const BANNER: &str = "aws-lc-rs 1.18.0 (AWS-LC, public API)";

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

fn cycles(f: &mut Option<fs::File>) -> u64 {
    let mut b = [0u8; 8];
    match f.as_mut() {
        Some(f) => match f.read_exact(&mut b) {
            Ok(()) => u64::from_ne_bytes(b),
            Err(_) => 0,
        },
        None => 0,
    }
}

/// Double the batch until it takes over 100 ms, keep the best of five.
fn bench(name: &str, mut f: impl FnMut() -> usize) {
    let mut cyc = perf_open();
    let mut n: u64 = 1;
    loop {
        let t = Instant::now();
        for _ in 0..n {
            black_box(f());
        }
        if t.elapsed().as_nanos() > 100_000_000 {
            break;
        }
        n *= 2;
    }
    let (mut best, mut bestc, mut count) = (f64::MAX, f64::MAX, 0usize);
    for _ in 0..5 {
        let c0 = cycles(&mut cyc);
        let t = Instant::now();
        for _ in 0..n {
            count = f();
        }
        let d = t.elapsed().as_nanos() as f64;
        let c = cycles(&mut cyc).wrapping_sub(c0) as f64;
        best = best.min(d);
        bestc = bestc.min(c);
    }
    let cc = if cyc.is_some() { bestc / n as f64 } else { 0.0 };
    println!("{}\t{:.1}\t{:.1}\t{}", name, best / n as f64, cc, count);
}

fn die(msg: &str) -> ! {
    eprintln!("{}", msg);
    exit(1);
}

fn slurp(dir: &str, name: &str) -> Vec<u8> {
    fs::read(format!("{}/{}", dir, name)).unwrap_or_else(|e| die(&format!("{}/{}: {}", dir, name, e)))
}

fn spit(dir: &str, name: &str, b: &[u8]) {
    fs::write(format!("{}/{}", dir, name), b).unwrap_or_else(|e| die(&format!("{}/{}: {}", dir, name, e)));
}

// ---- ML-KEM ----

struct Set {
    name: &'static str,
    alg: &'static kem::Algorithm<kem::AlgorithmId>,
    ct: usize,
}

const SETS: [Set; 3] = [
    Set { name: "512", alg: &kem::ML_KEM_512, ct: 768 },
    Set { name: "768", alg: &kem::ML_KEM_768, ct: 1088 },
    Set { name: "1024", alg: &kem::ML_KEM_1024, ct: 1568 },
];

fn find_set(n: &str) -> Option<&'static Set> {
    SETS.iter().find(|s| s.name == n)
}

/// Generate a key pair and encode the encapsulation key.
fn gen(s: &Set) -> (DecapsulationKey<kem::AlgorithmId>, Vec<u8>) {
    let dk = DecapsulationKey::generate(s.alg).unwrap_or_else(|_| die("kem generate"));
    let ek = dk
        .encapsulation_key()
        .unwrap_or_else(|_| die("encapsulation_key"))
        .key_bytes()
        .unwrap_or_else(|_| die("ek key_bytes"))
        .as_ref()
        .to_vec();
    (dk, ek)
}

/// Parse ek octets and encapsulate.
fn encaps(s: &Set, ek: &[u8]) -> (Vec<u8>, Vec<u8>) {
    let ek = EncapsulationKey::new(s.alg, ek).unwrap_or_else(|_| die("kem encapsulation key rejected"));
    let (ct, ss) = ek.encapsulate().unwrap_or_else(|_| die("kem encapsulate"));
    (ct.as_ref().to_vec(), ss.as_ref().to_vec())
}

fn decaps(dk: &DecapsulationKey<kem::AlgorithmId>, ct: &[u8]) -> Vec<u8> {
    dk.decapsulate(Ciphertext::from(ct)).unwrap_or_else(|_| die("kem decapsulate")).as_ref().to_vec()
}

fn interop(dir: &str) {
    for s in SETS.iter() {
        let n = s.name;
        let zek = slurp(dir, &format!("zin_mlkem{}.ek", n));
        let zdk = slurp(dir, &format!("zin_mlkem{}.dk", n));
        let zct = slurp(dir, &format!("zin_mlkem{}.ct", n));
        let zss = slurp(dir, &format!("zin_mlkem{}.ss", n));
        // Our key pair, loaded here: our ciphertext must decapsulate to our secret.
        let dk = DecapsulationKey::new(s.alg, &zdk).unwrap_or_else(|_| die(&format!("{}: our dk rejected", n)));
        if decaps(&dk, &zct) != zss {
            die(&format!("{}: aws-lc decapsulates our ciphertext to another secret", n));
        }
        // Encapsulate to our ek.
        let (ct, ss) = encaps(s, &zek);
        spit(dir, &format!("aws_mlkem{}.ct", n), &ct);
        spit(dir, &format!("aws_mlkem{}.ss", n), &ss);
        // A key pair of its own.
        let (dk, ek) = gen(s);
        spit(dir, &format!("aws_mlkem{}.ek", n), &ek);
        spit(dir, &format!("aws_mlkem{}.dk", n), dk.key_bytes().unwrap_or_else(|_| die("dk key_bytes")).as_ref());
    }
}

fn interop2(dir: &str) {
    for s in SETS.iter() {
        let n = s.name;
        let dkb = slurp(dir, &format!("aws_mlkem{}.dk", n));
        let ct = slurp(dir, &format!("zigA_mlkem{}.ct", n));
        let ss = slurp(dir, &format!("zigA_mlkem{}.ss", n));
        let dk = DecapsulationKey::new(s.alg, &dkb).unwrap_or_else(|_| die(&format!("{}: own dk rejected", n)));
        if ct.len() != s.ct || decaps(&dk, &ct) != ss {
            die(&format!("{}: the shared secrets differ (aws-lc decapsulating our ciphertext)", n));
        }
    }
}

fn main() {
    let a: Vec<String> = std::env::args().collect();
    if a.len() != 3 {
        die(&format!("usage: {} <work dir> <workload>", a[0]));
    }
    let (dir, w) = (a[1].as_str(), a[2].as_str());
    eprintln!("{}", BANNER);
    match w {
        "interop" => return interop(dir),
        "interop2" => return interop2(dir),
        _ => {}
    }
    let Some((op, sn)) = w.rsplit_once('_') else { die(&format!("unknown workload {}", w)) };
    let s = find_set(sn).unwrap_or_else(|| die(&format!("unknown parameter set in {}", w)));
    let (dk, ek) = gen(s);
    let (ct, _) = encaps(s, &ek);
    match op {
        "keygen" => bench(w, || {
            let (k, e) = gen(s);
            black_box(&k);
            black_box(&e);
            e.len()
        }),
        "encaps" => bench(w, || {
            let (c, x) = encaps(s, &ek);
            black_box(&x);
            c.len()
        }),
        "decaps" => bench(w, || black_box(decaps(&dk, &ct)).len()),
        "ek_parse" => bench(w, || {
            let k = EncapsulationKey::new(s.alg, &ek).unwrap_or_else(|_| die("kem encapsulation key rejected"));
            black_box(&k);
            ek.len()
        }),
        _ => die(&format!("unknown workload {}", w)),
    }
}
