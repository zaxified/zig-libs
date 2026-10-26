// SPDX-License-Identifier: MIT

// "Fastest in the field" side of `zig build bench-x509`
// (modules/x509/tools/bench.zig): times rustls-webpki 0.103.15 (over ring
// 0.17) verifying the chains the Go side wrote into the directory given as the
// first argument (`<kind>_{leaf,inter,root}.der`, `now.txt`), for the one
// workload named by the second argument (`verify_<kind>`). Prints one line,
// tab-separated: name, ns/op, 0 (no cycle counter on this side), and the
// certificates in the verified path (leaf, intermediate, anchor: 3). The run
// named `check` instead verifies every chain with the right host (must pass)
// and a wrong one (must fail), and exits non-zero otherwise.
//
// verify = what a TLS client does, the shape of the other sides: parse the
// leaf (`EndEntityCert::try_from`), `verify_for_usage` with every algorithm
// webpki has over ring, the intermediate as presented, the trust anchor
// extracted once from the root (as Go's root pool holds a parsed root), the
// verification time and serverAuth, then `verify_is_valid_for_subject_name`.
//
// Timing matches the Zig side: double the batch until it takes over 100 ms,
// then keep the best of five.

use pki_types::{CertificateDer, ServerName, UnixTime};
use rustls_pki_types as pki_types;
use std::hint::black_box;
use std::time::{Duration, Instant};
use webpki::{anchor_from_trusted_cert, EndEntityCert, KeyUsage, ALL_VERIFICATION_ALGS};

const KINDS: [&str; 3] = ["ecdsa256", "rsa2048", "mixed"];
const HOST: &str = "bench.example.test";

fn time_it(mut f: impl FnMut() -> u64) -> (f64, u64) {
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
    let mut best = u128::MAX;
    let mut count = 0;
    for _ in 0..5 {
        let t = Instant::now();
        for _ in 0..n {
            count = f();
        }
        best = best.min(t.elapsed().as_nanos());
    }
    black_box(sink);
    (best as f64 / n as f64, count)
}

fn die(msg: String) -> ! {
    eprintln!("{msg}");
    std::process::exit(1)
}

fn read(dir: &str, name: &str) -> Vec<u8> {
    std::fs::read(format!("{dir}/{name}")).unwrap_or_else(|e| die(format!("{dir}/{name}: {e}")))
}

struct Chain {
    leaf: Vec<u8>,
    inter: Vec<u8>,
    root: Vec<u8>,
}

/// One verification: the number of certificates in the verified path, or the error.
fn verify(c: &Chain, anchors: &[pki_types::TrustAnchor<'_>], now: UnixTime, host: &ServerName<'_>) -> Result<u64, webpki::Error> {
    let leaf = CertificateDer::from(c.leaf.as_slice());
    let ee = EndEntityCert::try_from(&leaf)?;
    let inters = [CertificateDer::from(c.inter.as_slice())];
    let path = ee.verify_for_usage(ALL_VERIFICATION_ALGS, anchors, &inters, now, KeyUsage::server_auth(), None, None)?;
    ee.verify_is_valid_for_subject_name(host)?;
    Ok(2 + path.intermediate_certificates().count() as u64)
}

fn main() {
    let args: Vec<String> = std::env::args().collect();
    if args.len() != 3 {
        die("usage: x509_fast_bench <work dir> <workload>".into());
    }
    let dir = &args[1];
    let work = &args[2];
    eprintln!("rustls-webpki 0.103.15 (ring 0.17.14)");
    let now_txt = String::from_utf8(read(dir, "now.txt")).unwrap_or_else(|_| die("now.txt".into()));
    let now = UnixTime::since_unix_epoch(Duration::from_secs(now_txt.trim().parse().unwrap_or_else(|_| die("now.txt".into()))));
    let load = |k: &str| Chain {
        leaf: read(dir, &format!("{k}_leaf.der")),
        inter: read(dir, &format!("{k}_inter.der")),
        root: read(dir, &format!("{k}_root.der")),
    };
    let host = ServerName::try_from(HOST).unwrap();
    if work == "check" {
        let other = ServerName::try_from("other.example.test").unwrap();
        for k in KINDS {
            let c = load(k);
            let root = CertificateDer::from(c.root.as_slice());
            let anchors = [anchor_from_trusted_cert(&root).unwrap_or_else(|e| die(format!("{k}: anchor: {e:?}")))];
            match verify(&c, &anchors, now, &host) {
                Ok(3) => {}
                Ok(n) => die(format!("{k}: path of {n} certificates")),
                Err(e) => die(format!("{k}: webpki refuses the chain: {e:?}")),
            }
            if verify(&c, &anchors, now, &other).is_ok() {
                die(format!("{k}: webpki accepts a wrong host"));
            }
        }
        return;
    }
    let kind = work.strip_prefix("verify_").filter(|k| KINDS.contains(k)).unwrap_or_else(|| die(format!("unknown workload {work}")));
    let c = load(kind);
    let root = CertificateDer::from(c.root.as_slice());
    let anchors = [anchor_from_trusted_cert(&root).unwrap_or_else(|e| die(format!("anchor: {e:?}")))];
    let (ns, count) = time_it(|| verify(black_box(&c), &anchors, now, &host).unwrap_or_else(|e| die(format!("verify: {e:?}"))));
    println!("{work}\t{ns:.1}\t0\t{count}");
}
