// SPDX-License-Identifier: MIT
//
// AWS-LC side of `zig build bench-hpke -- --vs=awslc`
// (modules/hpke/tools/bench.zig): AWS-LC 0.44.0's EVP_HPKE_* API (the
// BoringSSL-derived HPKE of RFC 9180, base mode), called through the raw
// bindings of aws-lc-sys, doing the work `hpke` does on the same keys, info and
// messages as `c_bench/foreign_bench.c` (OpenSSL) and `go_bench/main.go`.
//
//   rust_bench <work dir> <workload>   name \t ns/op \t user cycles/op \t count
//   rust_bench <work dir> interop      check against the files the Zig side wrote
//
// What AWS-LC HPKE has (checked in the bindings and include/openssl/hpke.h of
// aws-lc-sys 0.44.0): ONE KEM, DHKEM(X25519, HKDF-SHA256); ONE KDF,
// HKDF-SHA256; AEADs AES-128-GCM, AES-256-GCM, ChaCha20-Poly1305. No P-256,
// P-384 or P-521 KEM, no post-quantum KEM. So only the suites x25519
// (AES-128-GCM) and x25519cc (ChaCha20-Poly1305) exist here; the others have
// no AWS-LC row.
//
// Workloads: <suite>_<op>, op = keygen, setupS, setupR, seal64, open64, seal16k,
// open16k, export (as in the C side), plus ctxcopy (see below).
//   keygen    EVP_HPKE_KEY_generate (random scalar drawn inside) and the public
//             key read out, key cleaned up
//   setupS    EVP_HPKE_CTX_new + EVP_HPKE_CTX_setup_sender (ephemeral key, encap,
//             key schedule) + free
//   setupR    EVP_HPKE_CTX_new + EVP_HPKE_CTX_setup_recipient + free
//   seal64, seal16k   EVP_HPKE_CTX_seal on an established sender context
//   open64, open16k   EVP_HPKE_CTX_open on an established receiver context
//   export    EVP_HPKE_CTX_export (32 B)
//
// Forced difference (open): the API has no way to rewind a context's sequence
// number (OpenSSL has OSSL_HPKE_CTX_set_seq, ours assigns `seq = 0`; Go's side
// cannot rewind and opens chunks sealed by a fresh sender). Each open here
// first copies a pristine, established receiver context (the whole
// evp_hpke_ctx_st, a plain struct with no pointer into itself; the AEAD state is
// kept at a fixed offset and both copies are 64-aligned) over the working one.
// That copy is on the clock. Its cost alone is the workload `<suite>_ctxcopy`,
// reported separately so it can be subtracted: it is a bias AGAINST AWS-LC.
//
// The cycle counter is perf_event_open, user mode only, read outside the
// monotonic-clock window of a batch.

use aws_lc_sys as sys;
use std::fs;
use std::hint::black_box;
use std::io::Read;
use std::mem::MaybeUninit;
use std::process::exit;
use std::time::Instant;

const BANNER: &str = "AWS-LC 0.44.0 (aws-lc-sys, EVP_HPKE_*)";

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


// ---- HPKE ----

const INFO: &[u8] = b"bench info";
const AAD: &[u8] = b"interop-aad";
const EXPORTER_CX: &[u8] = b"interop-export";
const TAG: usize = 16;
const NPK: usize = 32;

#[derive(Clone, Copy)]
struct Suite {
    name: &'static str,
    chacha: bool,
}
const SUITES: [Suite; 2] = [
    Suite { name: "x25519", chacha: false },
    Suite { name: "x25519cc", chacha: true },
];

fn find_suite(n: &str) -> Option<Suite> {
    SUITES.iter().copied().find(|s| s.name == n)
}

fn ok(r: i32, what: &str) {
    if r != 1 {
        die(&format!("{} failed", what));
    }
}

#[repr(align(64))]
struct Ctx(sys::EVP_HPKE_CTX);
#[repr(align(64))]
struct Key(sys::EVP_HPKE_KEY);

fn kem() -> *const sys::EVP_HPKE_KEM {
    // SAFETY: returns a static.
    unsafe { sys::EVP_hpke_x25519_hkdf_sha256() }
}
fn kdf() -> *const sys::EVP_HPKE_KDF {
    // SAFETY: returns a static.
    unsafe { sys::EVP_hpke_hkdf_sha256() }
}
fn aead(s: Suite) -> *const sys::EVP_HPKE_AEAD {
    // SAFETY: returns a static.
    unsafe {
        if s.chacha {
            sys::EVP_hpke_chacha20_poly1305()
        } else {
            sys::EVP_hpke_aes_128_gcm()
        }
    }
}

/// A recipient key from the raw secret key the Zig side wrote.
fn load_key(dir: &str, s: Suite) -> Box<Key> {
    let sk = slurp(dir, &format!("{}.sk", s.name));
    let pk = slurp(dir, &format!("{}.pk", s.name));
    if sk.len() != 32 || pk.len() != NPK {
        die(&format!("{}: key sizes {}/{}", s.name, sk.len(), pk.len()));
    }
    let mut k: Box<Key> = Box::new(unsafe { MaybeUninit::zeroed().assume_init() });
    // SAFETY: `k` is a zeroed EVP_HPKE_KEY; sk is 32 readable octets.
    unsafe {
        sys::EVP_HPKE_KEY_zero(&mut k.0);
        ok(sys::EVP_HPKE_KEY_init(&mut k.0, kem(), sk.as_ptr(), sk.len()), "EVP_HPKE_KEY_init");
    }
    let mut got = [0u8; 64];
    let mut n = 0usize;
    // SAFETY: got has 64 octets of room.
    unsafe { ok(sys::EVP_HPKE_KEY_public_key(&k.0, got.as_mut_ptr(), &mut n, got.len()), "public_key") };
    if got[..n] != pk[..] {
        die(&format!("{}: the public key derived here differs from the Zig side's", s.name));
    }
    k
}

fn new_ctx() -> *mut sys::EVP_HPKE_CTX {
    // SAFETY: plain allocation.
    let c = unsafe { sys::EVP_HPKE_CTX_new() };
    if c.is_null() {
        die("EVP_HPKE_CTX_new");
    }
    c
}

/// Sender setup on `c`: returns the encapsulated key.
fn setup_sender(c: *mut sys::EVP_HPKE_CTX, s: Suite, pk: &[u8]) -> Vec<u8> {
    let mut enc = [0u8; 64];
    let mut n = 0usize;
    // SAFETY: enc has room for max_enc, pk and INFO are valid for their lengths.
    unsafe {
        ok(
            sys::EVP_HPKE_CTX_setup_sender(c, enc.as_mut_ptr(), &mut n, enc.len(), kem(), kdf(), aead(s), pk.as_ptr(), pk.len(), INFO.as_ptr(), INFO.len()),
            "EVP_HPKE_CTX_setup_sender",
        );
    }
    enc[..n].to_vec()
}

fn setup_recipient(c: *mut sys::EVP_HPKE_CTX, s: Suite, key: &Key, enc: &[u8]) {
    // SAFETY: valid pointers and lengths.
    unsafe {
        ok(
            sys::EVP_HPKE_CTX_setup_recipient(c, &key.0, kdf(), aead(s), enc.as_ptr(), enc.len(), INFO.as_ptr(), INFO.len()),
            "EVP_HPKE_CTX_setup_recipient",
        );
    }
}

fn seal(c: *mut sys::EVP_HPKE_CTX, out: &mut [u8], aad: &[u8], pt: &[u8]) -> usize {
    let mut n = 0usize;
    // SAFETY: out has out.len() octets of room.
    unsafe {
        ok(sys::EVP_HPKE_CTX_seal(c, out.as_mut_ptr(), &mut n, out.len(), pt.as_ptr(), pt.len(), aad.as_ptr(), aad.len()), "EVP_HPKE_CTX_seal");
    }
    n
}

fn open(c: *mut sys::EVP_HPKE_CTX, out: &mut [u8], aad: &[u8], ct: &[u8]) -> Option<usize> {
    let mut n = 0usize;
    // SAFETY: out has out.len() octets of room.
    let r = unsafe { sys::EVP_HPKE_CTX_open(c, out.as_mut_ptr(), &mut n, out.len(), ct.as_ptr(), ct.len(), aad.as_ptr(), aad.len()) };
    if r == 1 {
        Some(n)
    } else {
        None
    }
}

fn export(c: *mut sys::EVP_HPKE_CTX) -> [u8; 32] {
    let mut e = [0u8; 32];
    // SAFETY: e has 32 octets.
    unsafe { ok(sys::EVP_HPKE_CTX_export(c, e.as_mut_ptr(), e.len(), EXPORTER_CX.as_ptr(), EXPORTER_CX.len()), "EVP_HPKE_CTX_export") };
    e
}

// Plaintexts: the same bytes as on the Zig, Go and C sides.
fn plain() -> (Vec<u8>, Vec<u8>) {
    let short = (0..64usize).map(|i| (i * 7 + 1) as u8).collect();
    let long = (0..16384usize).map(|i| (i * 31 + 5) as u8).collect();
    (short, long)
}

fn same(s: Suite, what: &str, a: &[u8], b: &[u8]) {
    if a != b {
        die(&format!("{}: {} differs", s.name, what));
    }
}

fn interop(dir: &str) {
    let (pt_short, pt_long) = plain();
    for s in SUITES {
        let key = load_key(dir, s);
        let pk = slurp(dir, &format!("{}.pk", s.name));
        // Zig sealed, AWS-LC opens.
        let enc = slurp(dir, &format!("zig_{}.enc", s.name));
        let ct0 = slurp(dir, &format!("zig_{}.ct0", s.name));
        let ct1 = slurp(dir, &format!("zig_{}.ct1", s.name));
        let exp = slurp(dir, &format!("zig_{}.exp", s.name));
        if enc.len() != NPK || ct0.len() != 64 + TAG || ct1.len() != 16384 + TAG || exp.len() != 32 {
            die(&format!("{}: the Zig side's files have unexpected sizes", s.name));
        }
        let r = new_ctx();
        setup_recipient(r, s, &key, &enc);
        let mut o0 = [0u8; 64];
        let mut o1 = vec![0u8; 16384];
        if open(r, &mut o0, AAD, &ct0) != Some(64) {
            die(&format!("{}: AWS-LC cannot open the Zig side's message 0", s.name));
        }
        same(s, "message 0 (Zig sealed)", &o0, &pt_short);
        if open(r, &mut o1, AAD, &ct1) != Some(16384) {
            die(&format!("{}: AWS-LC cannot open the Zig side's message 1", s.name));
        }
        same(s, "message 1 (Zig sealed)", &o1, &pt_long);
        same(s, "export (Zig sealed)", &export(r), &exp);
        // SAFETY: allocated by EVP_HPKE_CTX_new above.
        unsafe { sys::EVP_HPKE_CTX_free(r) };
        // AWS-LC seals, Zig opens.
        let c = new_ctx();
        let enc2 = setup_sender(c, s, &pk);
        let mut b0 = vec![0u8; 64 + TAG];
        let mut b1 = vec![0u8; 16384 + TAG];
        let n0 = seal(c, &mut b0, AAD, &pt_short);
        let n1 = seal(c, &mut b1, AAD, &pt_long);
        spit(dir, &format!("awslc_{}.enc", s.name), &enc2);
        spit(dir, &format!("awslc_{}.ct0", s.name), &b0[..n0]);
        spit(dir, &format!("awslc_{}.ct1", s.name), &b1[..n1]);
        spit(dir, &format!("awslc_{}.exp", s.name), &export(c));
        // SAFETY: allocated by EVP_HPKE_CTX_new above.
        unsafe { sys::EVP_HPKE_CTX_free(c) };
    }
}

fn main() {
    let a: Vec<String> = std::env::args().collect();
    if a.len() != 3 {
        die(&format!("usage: {} <work dir> <workload>", a[0]));
    }
    let (dir, w) = (a[1].as_str(), a[2].as_str());
    eprintln!("{}", BANNER);
    if w == "interop" {
        return interop(dir);
    }
    let (sn, op) = w.rsplit_once('_').unwrap_or_else(|| die(&format!("unknown workload {}", w)));
    let s = find_suite(sn).unwrap_or_else(|| die(&format!("unknown workload {}", w)));
    let key = load_key(dir, s);
    let pk = slurp(dir, &format!("{}.pk", s.name));
    let (pt_short, pt_long) = plain();
    // A sender context (seal / export) and the first message a receiver opens.
    let snd = new_ctx();
    let enc = setup_sender(snd, s, &pk);
    let mut seal_short = vec![0u8; 64 + TAG];
    let mut seal_long = vec![0u8; 16384 + TAG];
    match op {
        "keygen" => {
            let mut k: Box<Key> = Box::new(unsafe { MaybeUninit::zeroed().assume_init() });
            bench(w, || {
                let mut out = [0u8; 64];
                let mut n = 0usize;
                // SAFETY: `k` is a zeroed / cleaned-up EVP_HPKE_KEY; out has 64 octets.
                unsafe {
                    ok(sys::EVP_HPKE_KEY_generate(&mut k.0, kem()), "EVP_HPKE_KEY_generate");
                    ok(sys::EVP_HPKE_KEY_public_key(&k.0, out.as_mut_ptr(), &mut n, out.len()), "public_key");
                    sys::EVP_HPKE_KEY_cleanup(&mut k.0);
                }
                black_box(&out);
                n
            });
        }
        "setupS" => bench(w, || {
            let c = new_ctx();
            let e = setup_sender(c, s, &pk);
            // SAFETY: allocated by EVP_HPKE_CTX_new above.
            unsafe { sys::EVP_HPKE_CTX_free(c) };
            e.len()
        }),
        "setupR" => bench(w, || {
            let c = new_ctx();
            setup_recipient(c, s, &key, &enc);
            // SAFETY: allocated by EVP_HPKE_CTX_new above.
            unsafe { sys::EVP_HPKE_CTX_free(c) };
            1
        }),
        "seal64" => bench(w, || seal(snd, &mut seal_short, &[], &pt_short)),
        "seal16k" => bench(w, || seal(snd, &mut seal_long, &[], &pt_long)),
        "export" => bench(w, || export(snd).len()),
        "open64" | "open16k" | "ctxcopy" => {
            // The ciphertext comes from a fresh sender at seq 0; a pristine
            // receiver context is copied over the working one before each open
            // (see the header).
            let short = op != "open16k";
            let s2 = new_ctx();
            let enc2 = setup_sender(s2, s, &pk);
            let mut ct = vec![0u8; if short { 64 + TAG } else { 16384 + TAG }];
            let n = seal(s2, &mut ct, &[], if short { &pt_short } else { &pt_long });
            ct.truncate(n);
            let mut pristine: Box<Ctx> = Box::new(unsafe { MaybeUninit::zeroed().assume_init() });
            let mut work: Box<Ctx> = Box::new(unsafe { MaybeUninit::zeroed().assume_init() });
            // SAFETY: zero state, then established by setup_recipient.
            unsafe { sys::EVP_HPKE_CTX_zero(&mut pristine.0) };
            setup_recipient(&mut pristine.0, s, &key, &enc2);
            work.0 = pristine.0;
            let mut out = vec![0u8; ct.len()];
            if op == "ctxcopy" {
                bench(w, || {
                    work.0 = black_box(&pristine.0).clone();
                    black_box(&work.0);
                    1
                });
            } else {
                bench(w, || {
                    work.0 = pristine.0;
                    open(&mut work.0, &mut out, &[], &ct).unwrap_or_else(|| die("open"))
                });
            }
        }
        _ => die(&format!("unknown workload {}", w)),
    }
}
