// SPDX-License-Identifier: MIT
//! Foreign side of `zig build bench-mls` (modules/mls/tools/bench.zig):
//! OpenMLS 0.9.0 (MIT, the card's reference) with `openmls_rust_crypto` and
//! basic credentials, suite 0x0001.
//!
//! `mls-oracle <work dir> <name>` times one workload and prints
//! `name \t ns/op \t 0 \t count` (benchkit's protocol; wall time only), its
//! banner on stderr. Setup (untimed): alice creates a group and adds bob; bob
//! joins from the Welcome. Workloads, per op:
//!   rt_<size>    alice `create_message` of `size` bytes, serialised to wire
//!                bytes; bob deserialises them and `process_message`s them to
//!                the plaintext. count = plaintext length + its last byte.
//!   seal_<size>  alice's half alone: `create_message` + serialisation.
//!                count = wire length.
use openmls::prelude::*;
use openmls_basic_credential::SignatureKeyPair;
use openmls_rust_crypto::OpenMlsRustCrypto;
use std::time::Instant;
use tls_codec::{Deserialize, Serialize};

const CS: Ciphersuite = Ciphersuite::MLS_128_DHKEMX25519_AES128GCM_SHA256_Ed25519;

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

fn identity(provider: &OpenMlsRustCrypto, name: &[u8]) -> (SignatureKeyPair, CredentialWithKey) {
    let sig = SignatureKeyPair::new(CS.signature_algorithm()).unwrap();
    sig.store(provider.storage()).unwrap();
    let cred = BasicCredential::new(name.to_vec());
    let cwk = CredentialWithKey { credential: cred.into(), signature_key: sig.public().into() };
    (sig, cwk)
}

fn payload(size: usize) -> Vec<u8> {
    (0..size).map(|i| (i * 31 + 7) as u8).collect()
}

fn main() {
    let args: Vec<String> = std::env::args().collect();
    let name = args[2].as_str();
    eprintln!("OpenMLS 0.9.0 (openmls_rust_crypto 0.6.0), suite 0x0001");
    let alice_p = OpenMlsRustCrypto::default();
    let bob_p = OpenMlsRustCrypto::default();
    let (alice_sig, alice_cwk) = identity(&alice_p, b"alice");
    let (bob_sig, bob_cwk) = identity(&bob_p, b"bob");
    let bob_kp = KeyPackage::builder().build(CS, &bob_p, &bob_sig, bob_cwk).unwrap();
    let config = MlsGroupCreateConfig::builder().ciphersuite(CS).use_ratchet_tree_extension(true).build();
    let mut alice = MlsGroup::new(&alice_p, &alice_sig, &config, alice_cwk).unwrap();
    let (_commit, welcome, _gi) = alice.add_members(&alice_p, &alice_sig, &[bob_kp.key_package().clone()]).unwrap();
    alice.merge_pending_commit(&alice_p).unwrap();
    let welcome_bytes = welcome.tls_serialize_detached().unwrap();
    let welcome_in = MlsMessageIn::tls_deserialize_exact(welcome_bytes.as_slice()).unwrap();
    let welcome = match welcome_in.extract() {
        MlsMessageBodyIn::Welcome(w) => w,
        _ => panic!("not a welcome"),
    };
    let mut bob = StagedWelcome::new_from_welcome(&bob_p, &MlsGroupJoinConfig::default(), welcome, None)
        .unwrap()
        .into_group(&bob_p)
        .unwrap();

    let (kind, size) = name.split_once('_').unwrap();
    let size: usize = size.parse().unwrap();
    let data = payload(size);
    let (ns, count) = match kind {
        "rt" => best_ns(|| {
            let out = alice.create_message(&alice_p, &alice_sig, &data).unwrap();
            let wire = out.tls_serialize_detached().unwrap();
            let inmsg = MlsMessageIn::tls_deserialize_exact(wire.as_slice()).unwrap();
            let pm = inmsg.try_into_protocol_message().unwrap();
            let processed = bob.process_message(&bob_p, pm).unwrap();
            match processed.into_content() {
                ProcessedMessageContent::ApplicationMessage(m) => {
                    let b = m.into_bytes();
                    b.len() as u64 + b[b.len() - 1] as u64
                }
                _ => panic!("not an application message"),
            }
        }),
        "seal" => best_ns(|| {
            let out = alice.create_message(&alice_p, &alice_sig, &data).unwrap();
            out.tls_serialize_detached().unwrap().len() as u64
        }),
        _ => panic!("unknown workload {}", name),
    };
    println!("{}\t{}\t0\t{}", name, ns, count);
}
