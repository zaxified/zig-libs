// SPDX-License-Identifier: MIT
//
// Alt side of `zig build bench-tls13` (modules/tls13/tools/bench.zig):
// aws-lc-rs 1.18.0 (Rust over AWS-LC), through its public API only, doing the
// work `tls13` does -- the RFC 8446 key schedule, the key-exchange groups of a
// TLS 1.3 handshake and the CertificateVerify signatures -- on the same inputs
// as `c_bench/foreign_bench.c` (read its header for the workload list).
//
//   rust_bench <work dir> <workload>   name \t ns/op \t user cycles/op \t count
//   rust_bench <work dir> interop      check against the files the Zig side wrote
//   rust_bench <work dir> interop2     second half of the key-exchange check
//
// Differences from the C side (forced by the API):
//  * Key schedule: aws-lc-rs has no one-call HKDF-Extract returning the PRK
//    bytes (`hkdf::Prk` hides them), so Extract is HMAC(salt, ikm) via
//    `hmac::sign` -- the definition of HKDF-Extract -- and Expand is
//    `hkdf::Prk::new_less_safe(..).expand(info).fill(..)`, a fresh key object
//    per call; the HkdfLabel is built in Rust. Derive-Secret's transcript hash
//    of the empty string and the exporter's context hash are `digest::digest`.
//  * Hybrid groups are composed from their parts in the draft's layout, as on
//    the C side (aws-lc-rs has ML-KEM and ECDH/X25519 but no hybrid group).
//  * ML-KEM: `kem::DecapsulationKey::generate` / `EncapsulationKey::new` +
//    `encapsulate` / `DecapsulationKey::decapsulate`. A peer's ECDH public key
//    is parsed inside `agreement::agree` (checked there), as OpenSSL's import is.
//  * Signatures: the key is parsed once (EcdsaKeyPair / Ed25519KeyPair /
//    RsaKeyPair; ParsedPublicKey for verify); there is no per-call context
//    object. ECDSA signatures are ASN.1 DER, RSA is PSS-SHA256 with the salt
//    length of the digest. Randomness: aws-lc's own DRBG.
//  * Allocation: the API returns owned buffers (Vec / Box); that cost stays in.
//
// The cycle counter is perf_event_open, user mode only, read outside the
// monotonic-clock window of a batch.

use aws_lc_rs::agreement::{self, PrivateKey, UnparsedPublicKey};
use aws_lc_rs::digest;
use aws_lc_rs::encoding::AsBigEndian;
use aws_lc_rs::hkdf;
use aws_lc_rs::hmac;
use aws_lc_rs::kem::{self, Ciphertext, DecapsulationKey, EncapsulationKey};
use aws_lc_rs::rand::SystemRandom;
use aws_lc_rs::signature::{
    self, EcdsaKeyPair, Ed25519KeyPair, KeyPair, ParsedPublicKey, RsaKeyPair, RsaPublicKeyComponents,
};
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

// ---- key schedule (RFC 8446 section 7.1) ----

struct Ks {
    alg: hkdf::Algorithm,
    hmac: hmac::Algorithm,
    dg: &'static digest::Algorithm,
    l: usize,
    empty: Vec<u8>,
    dhe: Vec<u8>,
    th_hs: Vec<u8>,
    th_ap: Vec<u8>,
}

struct Len(usize);
impl hkdf::KeyType for Len {
    fn len(&self) -> usize {
        self.0
    }
}

const KS_CTX: &[u8; 16] = b"bench-exporter-c";
const KS_LABEL: &str = "EXPERIMENTAL bench";

impl Ks {
    fn new(sha384: bool) -> Ks {
        let (alg, hm, dg, l) = if sha384 {
            (hkdf::HKDF_SHA384, hmac::HMAC_SHA384, &digest::SHA384, 48)
        } else {
            (hkdf::HKDF_SHA256, hmac::HMAC_SHA256, &digest::SHA256, 32)
        };
        Ks {
            alg,
            hmac: hm,
            dg,
            l,
            empty: digest::digest(dg, b"").as_ref().to_vec(),
            dhe: (0..l).map(|j| (j * 3 + 1) as u8).collect(),
            th_hs: (0..l).map(|j| (0x40 + j) as u8).collect(),
            th_ap: (0..l).map(|j| (0x80 + j) as u8).collect(),
        }
    }
    fn extract(&self, out: &mut [u8], salt: &[u8], ikm: &[u8]) {
        let k = hmac::Key::new(self.hmac, salt);
        out.copy_from_slice(hmac::sign(&k, ikm).as_ref());
    }
    /// HKDF-Expand-Label (RFC 8446 7.1): the HkdfLabel is built here.
    fn expand(&self, out: &mut [u8], secret: &[u8], label: &str, data: &[u8]) {
        let outlen = (out.len() as u16).to_be_bytes();
        let llen = [(6 + label.len()) as u8];
        let dlen = [data.len() as u8];
        let info: [&[u8]; 6] = [&outlen, &llen, b"tls13 ", label.as_bytes(), &dlen, data];
        let prk = hkdf::Prk::new_less_safe(self.alg, secret);
        prk.expand(&info, Len(out.len())).unwrap().fill(out).unwrap();
    }
    /// out: early, hs, hs_c, hs_s, ms, ap_c, ap_s, exp (L each), then 32 exported.
    fn run(&self, out: &mut [u8]) {
        let l = self.l;
        let zeros = [0u8; 48];
        let mut derived = [0u8; 48];
        let mut dm = [0u8; 48];
        let (early, rest) = out.split_at_mut(l);
        let (hs, rest) = rest.split_at_mut(l);
        let (hs_c, rest) = rest.split_at_mut(l);
        let (hs_s, rest) = rest.split_at_mut(l);
        let (ms, rest) = rest.split_at_mut(l);
        let (ap_c, rest) = rest.split_at_mut(l);
        let (ap_s, rest) = rest.split_at_mut(l);
        let (exp, exported) = rest.split_at_mut(l);
        self.extract(early, &zeros[..l], &zeros[..l]);
        self.expand(&mut derived[..l], early, "derived", &self.empty);
        self.extract(hs, &derived[..l], &self.dhe);
        self.expand(hs_c, hs, "c hs traffic", &self.th_hs);
        self.expand(hs_s, hs, "s hs traffic", &self.th_hs);
        self.expand(&mut derived[..l], hs, "derived", &self.empty);
        self.extract(ms, &derived[..l], &zeros[..l]);
        self.expand(ap_c, ms, "c ap traffic", &self.th_ap);
        self.expand(ap_s, ms, "s ap traffic", &self.th_ap);
        self.expand(exp, ms, "exp master", &self.th_ap);
        self.expand(&mut dm[..l], exp, KS_LABEL, &self.empty);
        let ch = digest::digest(self.dg, KS_CTX);
        self.expand(&mut exported[..32], &dm[..l], "exporter", ch.as_ref());
    }
}

// ---- key exchange ----

#[derive(Clone, Copy, PartialEq)]
enum P {
    X25519,
    P256,
    P384,
    K768,
    K1024,
}

impl P {
    fn cpub(self) -> usize {
        match self {
            P::X25519 => 32,
            P::P256 => 65,
            P::P384 => 97,
            P::K768 => 1184,
            P::K1024 => 1568,
        }
    }
    fn spub(self) -> usize {
        match self {
            P::K768 => 1088,
            P::K1024 => 1568,
            p => p.cpub(),
        }
    }
    fn ss(self) -> usize {
        match self {
            P::P384 => 48,
            _ => 32,
        }
    }
    fn ecdh(self) -> &'static agreement::Algorithm {
        match self {
            P::X25519 => &agreement::X25519,
            P::P256 => &agreement::ECDH_P256,
            P::P384 => &agreement::ECDH_P384,
            _ => unreachable!(),
        }
    }
    fn kem(self) -> &'static kem::Algorithm {
        match self {
            P::K768 => &kem::ML_KEM_768,
            P::K1024 => &kem::ML_KEM_1024,
            _ => unreachable!(),
        }
    }
    fn is_kem(self) -> bool {
        matches!(self, P::K768 | P::K1024)
    }
}

struct Group {
    name: &'static str,
    parts: &'static [P],
}

const GROUPS: [Group; 7] = [
    Group { name: "x25519", parts: &[P::X25519] },
    Group { name: "secp256r1", parts: &[P::P256] },
    Group { name: "secp384r1", parts: &[P::P384] },
    Group { name: "x25519mlkem768", parts: &[P::K768, P::X25519] },
    Group { name: "secp256r1mlkem768", parts: &[P::P256, P::K768] },
    Group { name: "secp384r1mlkem1024", parts: &[P::P384, P::K1024] },
    Group { name: "mlkem1024", parts: &[P::K1024] },
];

impl Group {
    fn cpub(&self) -> usize {
        self.parts.iter().map(|p| p.cpub()).sum()
    }
    fn spub(&self) -> usize {
        self.parts.iter().map(|p| p.spub()).sum()
    }
    fn ss(&self) -> usize {
        self.parts.iter().map(|p| p.ss()).sum()
    }
}

enum Key {
    Ecdh(PrivateKey),
    Kem(DecapsulationKey),
}

fn part_gen(p: P) -> (Key, Vec<u8>) {
    if p.is_kem() {
        let k = DecapsulationKey::generate(p.kem()).unwrap_or_else(|_| die("kem generate"));
        let b = k.encapsulation_key().unwrap().key_bytes().unwrap().as_ref().to_vec();
        (Key::Kem(k), b)
    } else {
        let k = PrivateKey::generate(p.ecdh()).unwrap_or_else(|_| die("ecdh generate"));
        let b = k.compute_public_key().unwrap().as_ref().to_vec();
        (Key::Ecdh(k), b)
    }
}

fn ecdh(local: &PrivateKey, p: P, peer: &[u8]) -> Vec<u8> {
    agreement::agree(local, UnparsedPublicKey::new(p.ecdh(), peer), (), |s| Ok(s.to_vec()))
        .unwrap_or_else(|_| die("ecdh agree"))
}

/// The server: parse the client's part, encapsulate / generate, encode, derive.
fn part_server(p: P, cpub: &[u8]) -> (Vec<u8>, Vec<u8>) {
    if p.is_kem() {
        let ek = EncapsulationKey::new(p.kem(), cpub).unwrap_or_else(|_| die("kem encapsulation key rejected"));
        let (ct, ss) = ek.encapsulate().unwrap_or_else(|_| die("kem encapsulate"));
        (ct.as_ref().to_vec(), ss.as_ref().to_vec())
    } else {
        let (k, spub) = part_gen(p);
        let Key::Ecdh(k) = k else { unreachable!() };
        (spub, ecdh(&k, p, cpub))
    }
}

fn part_client(p: P, local: &Key, spub: &[u8]) -> Vec<u8> {
    match local {
        Key::Kem(k) => k.decapsulate(Ciphertext::from(spub)).unwrap_or_else(|_| die("kem decapsulate")).as_ref().to_vec(),
        Key::Ecdh(k) => ecdh(k, p, spub),
    }
}

fn group_gen(g: &Group) -> (Vec<Key>, Vec<u8>) {
    let mut keys = Vec::with_capacity(2);
    let mut share = Vec::with_capacity(g.cpub());
    for &p in g.parts {
        let (k, b) = part_gen(p);
        keys.push(k);
        share.extend_from_slice(&b);
    }
    (keys, share)
}

fn group_server(g: &Group, cshare: &[u8]) -> (Vec<u8>, Vec<u8>) {
    let (mut sshare, mut ss) = (Vec::with_capacity(g.spub()), Vec::with_capacity(g.ss()));
    let mut co = 0;
    for &p in g.parts {
        let (s, x) = part_server(p, &cshare[co..co + p.cpub()]);
        sshare.extend_from_slice(&s);
        ss.extend_from_slice(&x);
        co += p.cpub();
    }
    (sshare, ss)
}

fn group_client(g: &Group, keys: &[Key], sshare: &[u8]) -> Vec<u8> {
    let mut ss = Vec::with_capacity(g.ss());
    let mut so = 0;
    for (i, &p) in g.parts.iter().enumerate() {
        ss.extend_from_slice(&part_client(p, &keys[i], &sshare[so..so + p.spub()]));
        so += p.spub();
    }
    ss
}

fn find_group(n: &str) -> Option<&'static Group> {
    GROUPS.iter().find(|g| g.name == n)
}

/// The private key of one part as octets: the scalar / seed, or the KEM key.
fn key_bytes(p: P, k: &Key) -> Vec<u8> {
    match k {
        Key::Kem(k) => k.key_bytes().unwrap().as_ref().to_vec(),
        Key::Ecdh(k) => {
            if p == P::X25519 {
                let b: aws_lc_rs::encoding::Curve25519SeedBin = k.as_be_bytes().unwrap();
                b.as_ref().to_vec()
            } else {
                let b: aws_lc_rs::encoding::EcPrivateKeyBin = k.as_be_bytes().unwrap();
                b.as_ref().to_vec()
            }
        }
    }
}

fn key_from_bytes(p: P, b: &[u8]) -> Key {
    if p.is_kem() {
        Key::Kem(DecapsulationKey::new(p.kem(), b).unwrap_or_else(|_| die("kem private key rejected")))
    } else {
        Key::Ecdh(PrivateKey::from_private_key(p.ecdh(), b).unwrap_or_else(|_| die("ecdh private key rejected")))
    }
}

// ---- CertificateVerify ----

const SCH: [&str; 4] = ["ecdsa_secp256r1_sha256", "ecdsa_secp384r1_sha384", "rsa_pss_rsae_sha256", "ed25519"];
const SCH_TH: [usize; 4] = [32, 48, 32, 32];
const SCH_THBYTE: [u8; 4] = [0x11, 0x22, 0x11, 0x11];

enum Signer {
    Ec(EcdsaKeyPair),
    Rsa(RsaKeyPair),
    Ed(Ed25519KeyPair),
}

struct Verifier {
    keys: Vec<ParsedPublicKey>,
}

struct Sch {
    signer: Vec<Signer>,
    verify: Verifier,
    content: Vec<Vec<u8>>,
}

fn load_keys(dir: &str) -> Sch {
    let ec = |name: &str, alg| EcdsaKeyPair::from_private_key_der(alg, &slurp(dir, name)).unwrap_or_else(|_| die(&format!("{} rejected", name)));
    let p256 = ec("ec256.der", &signature::ECDSA_P256_SHA256_ASN1_SIGNING);
    let p384 = ec("ec384.der", &signature::ECDSA_P384_SHA384_ASN1_SIGNING);
    let rsa = RsaKeyPair::from_der(&slurp(dir, "rsa_pkcs1.der")).unwrap_or_else(|_| die("rsa_pkcs1.der rejected"));
    let ed = Ed25519KeyPair::from_seed_unchecked(&slurp(dir, "ed25519.seed")).unwrap_or_else(|_| die("ed25519 seed rejected"));
    let (n, e) = (slurp(dir, "rsa_n.bin"), slurp(dir, "rsa_e.bin"));
    let pk = |alg: &'static dyn signature::VerificationAlgorithm, b: &[u8]| ParsedPublicKey::new(alg, b).unwrap_or_else(|_| die("public key rejected"));
    let keys = vec![
        pk(&signature::ECDSA_P256_SHA256_ASN1, p256.public_key().as_ref()),
        pk(&signature::ECDSA_P384_SHA384_ASN1, p384.public_key().as_ref()),
        RsaPublicKeyComponents { n: &n, e: &e }
            .to_parsed_public_key(&signature::RSA_PSS_2048_8192_SHA256)
            .unwrap_or_else(|_| die("rsa public key rejected")),
        pk(&signature::ED25519, ed.public_key().as_ref()),
    ];
    // 64 x 0x20 || context string || 0x00 || transcript hash (RFC 8446 4.4.3)
    let content = (0..4)
        .map(|i| {
            let mut c = vec![0x20u8; 64];
            c.extend_from_slice(b"TLS 1.3, server CertificateVerify");
            c.push(0);
            c.extend(std::iter::repeat(SCH_THBYTE[i]).take(SCH_TH[i]));
            c
        })
        .collect();
    Sch { signer: vec![Signer::Ec(p256), Signer::Ec(p384), Signer::Rsa(rsa), Signer::Ed(ed)], verify: Verifier { keys }, content }
}

fn sig_sign(s: &Sch, rng: &SystemRandom, i: usize) -> Vec<u8> {
    let m = &s.content[i];
    match &s.signer[i] {
        Signer::Ec(k) => k.sign(rng, m).unwrap_or_else(|_| die("ecdsa sign")).as_ref().to_vec(),
        Signer::Ed(k) => k.sign(m).as_ref().to_vec(),
        Signer::Rsa(k) => {
            let mut sig = vec![0u8; k.public_modulus_len()];
            k.sign(&signature::RSA_PSS_SHA256, rng, m, &mut sig).unwrap_or_else(|_| die("rsa sign"));
            sig
        }
    }
}

fn sig_verify(s: &Sch, i: usize, sig: &[u8]) -> bool {
    s.verify.keys[i].verify_sig(&s.content[i], sig).is_ok()
}

fn find_sch(n: &str) -> Option<usize> {
    SCH.iter().position(|s| *s == n)
}

// ---- interop ----

fn interop(dir: &str) {
    for sha384 in [false, true] {
        let ks = Ks::new(sha384);
        let name = if sha384 { "zig_ks384.bin" } else { "zig_ks256.bin" };
        let theirs = slurp(dir, name);
        let mut mine = vec![0u8; 8 * ks.l + 32];
        ks.run(&mut mine);
        if theirs.len() != mine.len() {
            die(&format!("key schedule {}: the Zig side wrote {} octets", name, theirs.len()));
        }
        const NAMES: [&str; 9] = ["early", "handshake", "client hs traffic", "server hs traffic", "master", "client ap traffic", "server ap traffic", "exporter master", "exported"];
        let mut bad = false;
        for (s, nm) in NAMES.iter().enumerate() {
            let off = s * ks.l;
            let len = if s == 8 { 32 } else { ks.l };
            if theirs[off..off + len] != mine[off..off + len] {
                eprintln!("key schedule {}: {} differs", name, nm);
                bad = true;
            }
        }
        if bad {
            exit(1);
        }
    }
    for g in GROUPS.iter() {
        let cs = slurp(dir, &format!("zig_{}.cshare", g.name));
        if cs.len() != g.cpub() {
            die(&format!("{}: client share is {} octets", g.name, cs.len()));
        }
        let (sshare, ss) = group_server(g, &cs);
        spit(dir, &format!("aws_{}.sshare", g.name), &sshare);
        spit(dir, &format!("aws_{}.sss", g.name), &ss);
        let (keys, cshare) = group_gen(g);
        spit(dir, &format!("aws_{}.cshare", g.name), &cshare);
        for (i, k) in keys.iter().enumerate() {
            spit(dir, &format!("aws_{}.cpriv{}", g.name, i), &key_bytes(g.parts[i], k));
        }
    }
    let s = load_keys(dir);
    let rng = SystemRandom::new();
    for i in 0..4 {
        let sg = slurp(dir, &format!("zig_sig_{}.sig", SCH[i]));
        if !sig_verify(&s, i, &sg) {
            die(&format!("{}: aws-lc does not verify our signature", SCH[i]));
        }
        let mine = sig_sign(&s, &rng, i);
        if !sig_verify(&s, i, &mine) {
            die(&format!("{}: aws-lc does not verify its own signature", SCH[i]));
        }
        spit(dir, &format!("aws_sig_{}.sig", SCH[i]), &mine);
    }
}

fn interop2(dir: &str) {
    for g in GROUPS.iter() {
        let keys: Vec<Key> = g
            .parts
            .iter()
            .enumerate()
            .map(|(i, &p)| key_from_bytes(p, &slurp(dir, &format!("aws_{}.cpriv{}", g.name, i))))
            .collect();
        let sshare = slurp(dir, &format!("zigA_{}.sshare", g.name));
        let theirs = slurp(dir, &format!("zigA_{}.sss", g.name));
        if sshare.len() != g.spub() || theirs.len() != g.ss() {
            die(&format!("{}: bad server share or secret length", g.name));
        }
        if group_client(g, &keys, &sshare) != theirs {
            die(&format!("{}: the shared secrets differ (aws-lc client, Zig server)", g.name));
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
        "ks256" | "ks384" => {
            let ks = Ks::new(w == "ks384");
            let mut out = vec![0u8; 8 * ks.l + 32];
            return bench(w, || {
                ks.run(&mut out);
                1
            });
        }
        _ => {}
    }
    if let Some(gn) = w.strip_prefix("gen_").or(w.strip_prefix("srv_")).or(w.strip_prefix("cli_")) {
        let g = find_group(gn).unwrap_or_else(|| die(&format!("unknown group in {}", w)));
        if w.starts_with('g') {
            return bench(w, || {
                let (k, s) = group_gen(g);
                black_box(&k);
                black_box(&s);
                1
            });
        }
        let (keys, cshare) = group_gen(g);
        if w.starts_with('s') {
            return bench(w, || {
                let (s, x) = group_server(g, &cshare);
                black_box(&s);
                black_box(&x);
                1
            });
        }
        let (sshare, _) = group_server(g, &cshare);
        return bench(w, || {
            black_box(group_client(g, &keys, &sshare));
            1
        });
    }
    if let Some(sn) = w.strip_prefix("sign_").or(w.strip_prefix("verify_")) {
        let i = find_sch(sn).unwrap_or_else(|| die(&format!("unknown scheme in {}", w)));
        let s = load_keys(dir);
        let rng = SystemRandom::new();
        let sig = sig_sign(&s, &rng, i);
        if w.starts_with('s') {
            return bench(w, || {
                black_box(sig_sign(&s, &rng, i));
                1
            });
        }
        return bench(w, || {
            if !sig_verify(&s, i, &sig) {
                die("verify");
            }
            1
        });
    }
    die(&format!("unknown workload {}", w));
}
