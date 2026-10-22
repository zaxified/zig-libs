// SPDX-License-Identifier: MIT

// Alt side of `zig build bench-tlsserver` (modules/tlsserver/tools/bench.zig):
// a rustls 0.23.43 + aws-lc-rs 1.18.0 TLS 1.3 SERVER doing the same
// server-side work as `c_bench/foreign_bench.c` (read its header).
//
//   rust_bench <work dir> <workload>   one line on stdout:
//                                      name \t ns/op \t user cycles/op \t count
//   rust_bench <work dir> interop      every workload once, untimed, checked
//
// Workloads (TLS13_AES_256_GCM_SHA384 only, forced on the server):
//   hs_p256 / hs_p256_mlkem / hs_rsa2048 / resumed / send_16k / recv_16k
//
// How only the server is timed. rustls + aws-lc cannot replay a recorded
// session (aws-lc draws ECDSA nonces, RSA-PSS salts and ephemeral keys from
// its own RNG), so unlike the C and Zig sides every handshake op is a fresh
// rustls CLIENT talking to a fresh rustls SERVER through memory buffers, and
// ONLY the server's calls sit between a start and a stop of the meter:
// ServerConnection::new, read_tls, process_new_packets, write_tls, the
// writer/reader and the drop of the connection. The client's work, the
// copying of its octets and its sealing of the recv pool are untimed.
// ServerConfig / ClientConfig are built once (= SSL_CTX). The client offers
// exactly one key exchange group and (through its certificate verifier) one
// signature scheme, so the server's choice is forced.
//
// The meter reads the cycle counter (perf_event_open, user mode only) OUTSIDE
// the monotonic-clock window of a segment, so the counter's syscalls are in
// neither number.

use rustls::client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier};
use rustls::crypto::aws_lc_rs::{self, cipher_suite, kx_group, Ticketer};
use rustls::crypto::{CryptoProvider, SupportedKxGroup};
use rustls::pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs1KeyDer, PrivateSec1KeyDer, ServerName, UnixTime};
use rustls::server::NoServerSessionStorage;
use rustls::{
    ClientConfig, ClientConnection, DigitallySignedStruct, Error, HandshakeKind, NamedGroup, ServerConfig,
    ServerConnection, SignatureScheme,
};
use std::fs;
use std::hint::black_box;
use std::io::{self, Read, Write};
use std::sync::{Arc, Mutex};
use std::time::Instant;

const BANNER: &str = "rustls 0.23.43 + aws-lc-rs 1.18.0";
const POOL: usize = 2048;
const REC: usize = 16384;

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

struct Meter {
    cyc: Option<fs::File>,
    ns: f64,
    cycles: u64,
    running: bool,
    t0: Instant,
    c0: u64,
}

impl Meter {
    fn new() -> Self {
        Meter { cyc: perf_open(), ns: 0.0, cycles: 0, running: false, t0: Instant::now(), c0: 0 }
    }
    fn have_cycles(&self) -> bool {
        self.cyc.is_some()
    }
    fn read_cycles(&mut self) -> u64 {
        let mut b = [0u8; 8];
        match self.cyc.as_mut() {
            Some(f) => match f.read_exact(&mut b) {
                Ok(()) => u64::from_ne_bytes(b),
                Err(_) => 0,
            },
            None => 0,
        }
    }
    fn reset(&mut self) {
        self.ns = 0.0;
        self.cycles = 0;
        self.running = false;
    }
    fn start(&mut self) {
        debug_assert!(!self.running);
        self.c0 = self.read_cycles();
        self.running = true;
        self.t0 = Instant::now();
    }
    fn stop(&mut self) {
        let t = self.t0.elapsed();
        let c1 = self.read_cycles();
        debug_assert!(self.running);
        self.running = false;
        self.ns += t.as_nanos() as f64;
        self.cycles += c1.wrapping_sub(self.c0);
    }
    // Stops if running; the returned flag tells `resume` to start again.
    fn pause(&mut self) -> bool {
        let was = self.running;
        if was {
            self.stop();
        }
        was
    }
    fn resume(&mut self, was: bool) {
        if was {
            self.start();
        }
    }
}

// ---- the client's certificate verifier: accepts the cert, one scheme ----

#[derive(Debug)]
struct OneScheme {
    scheme: SignatureScheme,
    seen: Mutex<Option<SignatureScheme>>,
}

impl ServerCertVerifier for OneScheme {
    fn verify_server_cert(
        &self,
        _: &CertificateDer<'_>,
        _: &[CertificateDer<'_>],
        _: &ServerName<'_>,
        _: &[u8],
        _: UnixTime,
    ) -> Result<ServerCertVerified, Error> {
        Ok(ServerCertVerified::assertion())
    }
    fn verify_tls12_signature(&self, _: &[u8], _: &CertificateDer<'_>, _: &DigitallySignedStruct) -> Result<HandshakeSignatureValid, Error> {
        Err(Error::General("TLS 1.2 is off".into()))
    }
    fn verify_tls13_signature(&self, _: &[u8], _: &CertificateDer<'_>, dss: &DigitallySignedStruct) -> Result<HandshakeSignatureValid, Error> {
        *self.seen.lock().unwrap() = Some(dss.scheme);
        Ok(HandshakeSignatureValid::assertion())
    }
    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        vec![self.scheme]
    }
}

// ---- the case ----

struct Case {
    name: &'static str,
    group_name: NamedGroup,
    scheme: SignatureScheme,
    resumed: bool,
    server: Arc<ServerConfig>,
    client: Arc<ClientConfig>,
    verifier: Arc<OneScheme>,
}

fn slurp(dir: &str, name: &str) -> Vec<u8> {
    let p = format!("{dir}/{name}");
    fs::read(&p).unwrap_or_else(|e| panic!("{p}: {e}"))
}

fn provider(group: &'static dyn SupportedKxGroup) -> Arc<CryptoProvider> {
    let mut p = aws_lc_rs::default_provider();
    p.cipher_suites = vec![cipher_suite::TLS13_AES_256_GCM_SHA384];
    p.kx_groups = vec![group];
    Arc::new(p)
}

fn make_case(dir: &str, w: &str) -> Option<Case> {
    let (mut group, mut group_name): (&'static dyn SupportedKxGroup, NamedGroup) = (kx_group::X25519, NamedGroup::X25519);
    let (mut cert, mut key, mut scheme) = ("p256_cert.der", "p256_key.der", SignatureScheme::ECDSA_NISTP256_SHA256);
    let mut rsa = false;
    let mut resumed = false;
    match w {
        "hs_p256" | "send_16k" | "recv_16k" => {}
        "hs_p256_mlkem" => (group, group_name) = (kx_group::X25519MLKEM768, NamedGroup::X25519MLKEM768),
        "hs_rsa2048" => {
            (cert, key, scheme, rsa) = ("rsa2048_cert.der", "rsa2048_key.der", SignatureScheme::RSA_PSS_SHA256, true)
        }
        "resumed" => resumed = true,
        _ => return None,
    }
    let chain = vec![CertificateDer::from(slurp(dir, cert))];
    let k = slurp(dir, key);
    let key: PrivateKeyDer<'static> =
        if rsa { PrivatePkcs1KeyDer::from(k).into() } else { PrivateSec1KeyDer::from(k).into() };
    let prov = provider(group);
    let mut server = ServerConfig::builder_with_provider(prov.clone())
        .with_protocol_versions(&[&rustls::version::TLS13])
        .unwrap()
        .with_no_client_auth()
        .with_single_cert(chain, key)
        .unwrap();
    server.session_storage = Arc::new(NoServerSessionStorage {});
    server.send_tls13_tickets = 1;
    server.alpn_protocols = Vec::new();
    if resumed {
        server.ticketer = Ticketer::new().unwrap();
    }
    let verifier = Arc::new(OneScheme { scheme, seen: Mutex::new(None) });
    let mut client = ClientConfig::builder_with_provider(prov)
        .with_protocol_versions(&[&rustls::version::TLS13])
        .unwrap()
        .dangerous()
        .with_custom_certificate_verifier(verifier.clone())
        .with_no_client_auth();
    // 64 sessions = 8 servers: a cache sized for a single server evicts the
    // ticket it has just stored (limited_cache.rs).
    client.resumption =
        if resumed { rustls::client::Resumption::in_memory_sessions(64) } else { rustls::client::Resumption::disabled() };
    Some(Case { name: static_name(w), group_name, scheme, resumed, server: Arc::new(server), client: Arc::new(client), verifier })
}

fn static_name(w: &str) -> &'static str {
    ["hs_p256", "hs_p256_mlkem", "hs_rsa2048", "resumed", "send_16k", "recv_16k"]
        .into_iter()
        .find(|n| *n == w)
        .unwrap()
}

// Pumps client <-> server until neither has anything to send. Only the
// server's calls are timed.
struct Wire {
    c2s: Vec<u8>,
    s2c: Vec<u8>,
}

fn drain_client(c: &mut ClientConnection, out: &mut Vec<u8>) {
    out.clear();
    while c.wants_write() {
        c.write_tls(out).unwrap();
    }
}

fn pump(m: &mut Meter, w: &mut Wire, c: &mut ClientConnection, s: &mut ServerConnection) {
    loop {
        let mut moved = false;
        drain_client(c, &mut w.c2s);
        w.s2c.clear();
        if !w.c2s.is_empty() {
            moved = true;
            m.start();
            let mut rd: &[u8] = &w.c2s;
            while !rd.is_empty() {
                let n = s.read_tls(&mut rd).unwrap();
                black_box(s.process_new_packets().unwrap());
                if n == 0 {
                    break;
                }
            }
            while s.wants_write() {
                s.write_tls(&mut w.s2c).unwrap();
            }
            m.stop();
        }
        if !w.s2c.is_empty() {
            moved = true;
            let mut rd: &[u8] = &w.s2c;
            while !rd.is_empty() {
                let n = c.read_tls(&mut rd).unwrap();
                c.process_new_packets().unwrap();
                if n == 0 {
                    break;
                }
            }
        }
        if !moved {
            break;
        }
    }
}

// One connection, server timed. Returns both ends, connected.
fn connect(m: &mut Meter, w: &mut Wire, k: &Case) -> (ClientConnection, ServerConnection) {
    let mut c = ClientConnection::new(k.client.clone(), ServerName::try_from("localhost").unwrap()).unwrap();
    m.start();
    let mut s = ServerConnection::new(k.server.clone()).unwrap();
    m.stop();
    pump(m, w, &mut c, &mut s);
    assert!(!s.is_handshaking() && !c.is_handshaking(), "handshake did not complete");
    (c, s)
}

fn drop_server(m: &mut Meter, s: ServerConnection) {
    m.start();
    drop(s);
    m.stop();
}

// ---- workload state ----

struct Bulk {
    c: ClientConnection,
    s: ServerConnection,
    left: usize,
    recs: Vec<u8>,
    off: usize,
}

struct Run {
    k: Case,
    m: Meter,
    w: Wire,
    plain: Vec<u8>,
    rbuf: Vec<u8>,
    bulk: Option<Bulk>,
}

struct Sink;
impl Write for Sink {
    fn write(&mut self, b: &[u8]) -> io::Result<usize> {
        Ok(b.len())
    }
    fn write_vectored(&mut self, bufs: &[io::IoSlice<'_>]) -> io::Result<usize> {
        Ok(bufs.iter().map(|b| b.len()).sum())
    }
    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

impl Run {
    fn new(k: Case) -> Run {
        let plain = (0..REC).map(|i| (i as u8).wrapping_mul(7).wrapping_add(1)).collect();
        let mut r = Run { k, m: Meter::new(), w: Wire { c2s: Vec::new(), s2c: Vec::new() }, plain, rbuf: vec![0; REC], bulk: None };
        if r.k.resumed {
            // The first, untimed full handshake leaves the client a ticket;
            // every resumed handshake then hands it the next one.
            r.m.reset();
            let (c, s) = connect(&mut r.m, &mut r.w, &r.k);
            assert_eq!(s.handshake_kind(), Some(HandshakeKind::Full));
            drop((c, s));
        }
        r
    }

    // Checks of one finished server connection (suite, group, scheme, kind).
    fn check(&self, s: &ServerConnection) -> Result<(), String> {
        let suite = s.negotiated_cipher_suite().map(|c| format!("{:?}", c.suite()));
        if suite.as_deref() != Some("TLS13_AES_256_GCM_SHA384") {
            return Err(format!("suite {suite:?}"));
        }
        let g = s.negotiated_key_exchange_group().map(|g| g.name());
        if g != Some(self.k.group_name) {
            return Err(format!("group {g:?}, not {:?}", self.k.group_name));
        }
        let want = if self.k.resumed { HandshakeKind::Resumed } else { HandshakeKind::Full };
        if s.handshake_kind() != Some(want) {
            return Err(format!("handshake kind {:?}, not {want:?}", s.handshake_kind()));
        }
        Ok(())
    }

    fn op_handshake(&mut self) -> usize {
        let (c, s) = connect(&mut self.m, &mut self.w, &self.k);
        if s.handshake_kind() != Some(if self.k.resumed { HandshakeKind::Resumed } else { HandshakeKind::Full }) {
            panic!("unexpected handshake kind {:?}", s.handshake_kind());
        }
        drop(c);
        drop_server(&mut self.m, s);
        1
    }

    fn renew(&mut self, recv: bool) {
        let was = self.m.pause();
        let mut recs = Vec::new();
        if let Some(b) = self.bulk.take() {
            drop(b.c);
            drop_server(&mut self.m, b.s);
            recs = b.recs;
        }
        let (mut c, s) = connect(&mut self.m, &mut self.w, &self.k);
        recs.clear();
        if recv {
            // The client seals the pool: untimed.
            for _ in 0..POOL {
                c.writer().write_all(&self.plain).unwrap();
                while c.wants_write() {
                    c.write_tls(&mut recs).unwrap();
                }
            }
        }
        self.bulk = Some(Bulk { c, s, left: POOL, recs, off: 0 });
        self.m.resume(was);
    }

    fn op_send(&mut self) -> usize {
        if self.bulk.as_ref().map_or(true, |b| b.left == 0) {
            self.renew(false);
        }
        let b = self.bulk.as_mut().unwrap();
        b.left -= 1;
        b.s.writer().write_all(&self.plain).unwrap();
        while b.s.wants_write() {
            black_box(b.s.write_tls(&mut Sink).unwrap());
        }
        REC
    }

    fn op_recv(&mut self) -> usize {
        if self.bulk.as_ref().map_or(true, |b| b.left == 0) {
            self.renew(true);
        }
        let b = self.bulk.as_mut().unwrap();
        b.left -= 1;
        let n = 5 + u16::from_be_bytes([b.recs[b.off + 3], b.recs[b.off + 4]]) as usize;
        let mut rd: &[u8] = &b.recs[b.off..b.off + n];
        b.off += n;
        while !rd.is_empty() {
            b.s.read_tls(&mut rd).unwrap();
            black_box(b.s.process_new_packets().unwrap());
        }
        let mut got = 0;
        while got < REC {
            let r = b.s.reader().read(&mut self.rbuf[got..]).unwrap();
            assert!(r > 0, "short read");
            got += r;
        }
        REC
    }
}

// ---- timing: double the batch until it takes over 100 ms of timed time,
// keep the best of five ----

fn bench(r: &mut Run, f: fn(&mut Run) -> usize, bulk: bool) {
    let run = |r: &mut Run, n: usize| -> usize {
        r.m.reset();
        if bulk {
            r.m.start();
        }
        let mut count = 0;
        for _ in 0..n {
            count = black_box(f(r));
        }
        if bulk {
            r.m.stop();
        }
        count
    };
    let mut n = 1;
    loop {
        run(r, n);
        if r.m.ns > 1e8 {
            break;
        }
        n *= 2;
    }
    let (mut best, mut bestc, mut count) = (f64::MAX, f64::MAX, 0);
    for _ in 0..5 {
        count = run(r, n);
        best = best.min(r.m.ns);
        bestc = bestc.min(r.m.cycles as f64);
    }
    let have = r.m.have_cycles();
    println!("{}\t{:.1}\t{:.1}\t{}", r.k.name, best / n as f64, if have { bestc / n as f64 } else { 0.0 }, count);
}

fn interop(dir: &str, w: &str) -> Result<(), String> {
    let k = make_case(dir, w).ok_or("unknown workload")?;
    let mut r = Run::new(k);
    let ctx = |e: String| format!("{w}: {e}");
    match w {
        "send_16k" | "recv_16k" => {
            let recv = w == "recv_16k";
            r.renew(recv);
            let plain = r.plain.clone();
            let g = r.bulk.as_ref().unwrap().s.negotiated_key_exchange_group().map(|g| g.name());
            if g != Some(NamedGroup::X25519) {
                return Err(ctx(format!("group {g:?}")));
            }
            if recv {
                for _ in 0..3 {
                    r.op_recv();
                    if r.rbuf != plain {
                        return Err(ctx("plaintext mismatch".into()));
                    }
                }
                eprintln!("{w}: server opened 3 records, plaintext identical, X25519, TLS13_AES_256_GCM_SHA384");
            } else {
                // The client opens what the server sealed.
                let b = r.bulk.as_mut().unwrap();
                b.s.writer().write_all(&plain).unwrap();
                let mut wire = Vec::new();
                while b.s.wants_write() {
                    b.s.write_tls(&mut wire).unwrap();
                }
                let mut rd: &[u8] = &wire;
                while !rd.is_empty() {
                    b.c.read_tls(&mut rd).unwrap();
                    b.c.process_new_packets().unwrap();
                }
                let mut got = vec![0u8; REC];
                b.c.reader().read_exact(&mut got).unwrap();
                if got != plain || wire.len() != REC + 5 + 1 + 16 {
                    return Err(ctx(format!("client got different plaintext or {} wire octets", wire.len())));
                }
                eprintln!("{w}: client opened the server's record, plaintext identical, {} wire octets, X25519", wire.len());
            }
        }
        _ => {
            let (c, s) = connect(&mut r.m, &mut r.w, &r.k);
            r.check(&s).map_err(ctx)?;
            let scheme = *r.k.verifier.seen.lock().unwrap();
            if !r.k.resumed && scheme != Some(r.k.scheme) {
                return Err(ctx(format!("signature scheme {scheme:?}, not {:?}", r.k.scheme)));
            }
            if r.k.resumed && c.handshake_kind() != Some(HandshakeKind::Resumed) {
                return Err(ctx("client did not resume".into()));
            }
            eprintln!(
                "{w}: TLS13_AES_256_GCM_SHA384, {:?}, {}, {:?}",
                r.k.group_name,
                if r.k.resumed { "resumed (psk_dhe_ke)".to_string() } else { format!("{:?}", scheme.unwrap()) },
                s.handshake_kind().unwrap()
            );
        }
    }
    Ok(())
}

fn main() {
    let args: Vec<String> = std::env::args().collect();
    if args.len() != 3 {
        eprintln!("usage: rust_bench <work dir> <workload>");
        std::process::exit(2);
    }
    eprintln!("{BANNER}");
    let (dir, w) = (args[1].as_str(), args[2].as_str());
    if w == "interop" {
        for n in ["hs_p256", "hs_p256_mlkem", "hs_rsa2048", "resumed", "send_16k", "recv_16k"] {
            if let Err(e) = interop(dir, n) {
                eprintln!("interop mismatch: {e}");
                std::process::exit(1);
            }
        }
        return;
    }
    let Some(k) = make_case(dir, w) else {
        eprintln!("unknown workload {w}");
        std::process::exit(2);
    };
    let mut r = Run::new(k);
    match w {
        "send_16k" => bench(&mut r, Run::op_send, true),
        "recv_16k" => bench(&mut r, Run::op_recv, true),
        _ => bench(&mut r, Run::op_handshake, false),
    }
}
