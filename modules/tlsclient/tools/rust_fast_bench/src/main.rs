// SPDX-License-Identifier: MIT

// "Fastest in the field" side of `zig build bench-tlsclient`
// (modules/tlsclient/tools/bench.zig): a rustls 0.23.43 CLIENT over
// aws-lc-rs 1.18.0 doing the work the other two clients do against the same
// Go crypto/tls server (`tools/go_bench serve`, read its header).
//
//   tlsclient_fast_bench <work dir> handshake_<kind>   one line on stdout:
//                                                      name \t ns/op \t user cycles/op \t 1
//   tlsclient_fast_bench <work dir> check              every kind once with the
//                                                      right name (must pass, TLS 1.3)
//                                                      and a wrong one (must fail)
//
// One op = TCP connect to 127.0.0.1:<port_<kind>.txt>, a fresh
// ClientConnection driven over the blocking socket until the handshake is done
// and the client Finished is written, close. The chain is verified by rustls'
// own WebPkiServerVerifier against the root (`root_<kind>.der`) and the name
// bench.example.test. The ClientConfig (= Go's tls.Config, our Bundle) is
// built once; resumption is off, as on the other sides. Key exchange groups
// are rustls' defaults with `prefer-post-quantum` (X25519MLKEM768 first).
//
// What is counted matches the other sides: the user-mode CPU cycles of the
// calling thread (perf_event_open), the whole op included; the server runs in
// another process. Timing: double the batch until it takes over 100 ms, then
// keep the best of five.

use rustls::crypto::aws_lc_rs;
use rustls::pki_types::{CertificateDer, ServerName};
use rustls::{ClientConfig, ClientConnection, ProtocolVersion, RootCertStore};
use std::fs;
use std::hint::black_box;
use std::io::Read;
use std::net::TcpStream;
use std::sync::Arc;
use std::time::Instant;

const BANNER: &str = "rustls 0.23.43 + aws-lc-rs 1.18.0";
const HOST: &str = "bench.example.test";
const KINDS: [&str; 2] = ["ecdsa256", "rsa2048"];

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

fn time_it(mut f: impl FnMut() -> u64) -> (f64, f64, u64) {
    let mut cyc = perf_open();
    let mut n: u64 = 1;
    let mut sink = 0u64;
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

// ---- the client ----

fn read(dir: &str, name: &str) -> Vec<u8> {
    fs::read(format!("{dir}/{name}")).unwrap_or_else(|e| die(format!("{dir}/{name}: {e}")))
}

struct Kind {
    addr: String,
    config: Arc<ClientConfig>,
}

fn load(dir: &str, kind: &str) -> Kind {
    let port = String::from_utf8(read(dir, &format!("port_{kind}.txt"))).unwrap_or_else(|_| die("port".into()));
    let mut roots = RootCertStore::empty();
    roots
        .add(CertificateDer::from(read(dir, &format!("root_{kind}.der"))))
        .unwrap_or_else(|e| die(format!("{kind}: root: {e:?}")));
    let mut config = ClientConfig::builder_with_provider(Arc::new(aws_lc_rs::default_provider()))
        .with_protocol_versions(&[&rustls::version::TLS13])
        .unwrap_or_else(|e| die(format!("config: {e:?}")))
        .with_root_certificates(roots)
        .with_no_client_auth();
    config.resumption = rustls::client::Resumption::disabled();
    Kind { addr: format!("127.0.0.1:{}", port.trim()), config: Arc::new(config) }
}

/// One handshake; the negotiated group's name on success.
fn handshake(k: &Kind, name: &ServerName<'static>) -> Result<String, String> {
    let mut sock = TcpStream::connect(&k.addr).map_err(|e| format!("connect: {e}"))?;
    let mut conn = ClientConnection::new(k.config.clone(), name.clone()).map_err(|e| format!("{e:?}"))?;
    while conn.is_handshaking() {
        conn.complete_io(&mut sock).map_err(|e| format!("{e}"))?;
    }
    while conn.wants_write() {
        conn.write_tls(&mut sock).map_err(|e| format!("{e}"))?;
    }
    if conn.protocol_version() != Some(ProtocolVersion::TLSv1_3) {
        return Err("not TLS 1.3".into());
    }
    Ok(format!("{:?}", conn.negotiated_key_exchange_group().map(|g| g.name())))
}

fn main() {
    let args: Vec<String> = std::env::args().collect();
    if args.len() != 3 {
        die("usage: tlsclient_fast_bench <work dir> check|handshake_<kind>".into());
    }
    let (dir, work) = (&args[1], &args[2]);
    eprintln!("{BANNER}");
    let host = ServerName::try_from(HOST).unwrap();
    if work == "check" {
        let other = ServerName::try_from("other.example.test").unwrap();
        for kind in KINDS {
            let k = load(dir, kind);
            match handshake(&k, &host) {
                Ok(g) => eprintln!("{kind}: ok, group {g}"),
                Err(e) => die(format!("{kind}: rustls cannot handshake with the Go server: {e}")),
            }
            if handshake(&k, &other).is_ok() {
                die(format!("{kind}: rustls accepts a wrong server name"));
            }
        }
        return;
    }
    let kind = work.strip_prefix("handshake_").filter(|k| KINDS.contains(k)).unwrap_or_else(|| die(format!("unknown workload {work}")));
    let k = load(dir, kind);
    let (ns, cyc, count) = time_it(|| {
        handshake(&k, &host).unwrap_or_else(|e| die(format!("handshake: {e}")));
        1
    });
    println!("{work}\t{ns:.1}\t{cyc:.1}\t{count}");
}
