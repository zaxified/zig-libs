// SPDX-License-Identifier: MIT

// "Fastest in the field" side of `zig build bench-jwt`
// (modules/jwt/tools/bench.zig): times Keats/jsonwebtoken 9.3.1 (over ring
// 0.17) signing and verifying the same access token as the Zig and Go sides,
// for the one workload named by the second argument (`rs.<alg>_<sign|verify>`,
// alg = hs256, es256, es384, eddsa, rs256, ps256; jsonwebtoken 9 has no ES512).
// The first argument is the directory the Zig program wrote its keys into.
// Prints one line, tab-separated: name, ns/op, 0 (no cycle counter on this
// side), and the token length (sign) or 1 (verify).
//
// Keys: the HMAC key and the RSA key are the Zig side's (the RSA key is
// RFC 7520 §3.4's, embedded below as PKCS#1 DER because ring takes no raw
// components without the CRT values; checked against the Zig side's `rsa.n`
// at start). The EC and Ed25519 keys are generated here: the cost of a
// signature does not depend on which key signs it, and every side verifies a
// token it signed itself.
//
// verify = `decode::<Value>` with the algorithm pinned, issuer and audience
// required, exp required and checked, nbf checked -- the checks of the Zig
// side's `parseAndVerify` and of golang-jwt's `Parse` options.
//
// Timing matches the Zig side: double the batch until it takes over 100 ms,
// then keep the best of five.

use jsonwebtoken::{decode, encode, Algorithm, DecodingKey, EncodingKey, Header, Validation};
use ring::rand::SystemRandom;
use ring::signature::{self, KeyPair};
use serde_json::Value;
use std::hint::black_box;
use std::time::Instant;

const ISSUER: &str = "https://issuer.example.com";
const AUDIENCE: &str = "api.example.com";
const CLAIMS: &str = r#"{"aud":"api.example.com","exp":4102444800,"iat":1700000000,"iss":"https://issuer.example.com","nbf":1700000000,"scope":"read write","sub":"user-1234567890"}"#;

/// RFC 7520 §3.4's RSA key as PKCS#1 RSAPrivateKey DER (n, e, d, p, q and the
/// CRT values derived from them), base64.
const RSA_DER_B64: &str = "MIIEowIBAAKCAQEAn4EPtAOCc9AlkeQHPzHStgAbgs7bTZLwUBZdR8/KuKPEHLd4rHVTeT+O+XV2jRojdNhxJWTDvNd7nqQ0VEiZQHz/AJmSCpMaJMRBSFKrKb2wqVwGU/NsYOYL+QtiWN2lbzcEe6XC0dApr5ydQLrHqkHHig3RBordaZ6Aj+oBHqFEHYpPe7Tpe+OfVfHd1E6cS6M1FZcD1NNLYD5lFHpPI9bTwJlsde3uhGqC0ZCuEHg8lhzwOHrtIQbS0FVbb9k3+tVTU4fg/3L/vniUFAKwuCLqKnS2BYwdq/mzSnbLY7h/qixoR7jig3//kRhuaxwUkRz5iaiQkqgc5gHdrNP5zwIDAQABAoIBAG1lAvQfhBUSKPJKRn4dGbshj7zDSr2FjbQf4pIh/ZNtHk/jtavyO/HomZKV8V0NFExLNi7DUUvvLiW70PgNYq5MDEjJCtSd10xoHa4QpLvYEZXWO7DQPwCmRofkOutf+NqyDS0QnvFvp2d+Lov6jn5C5yvUFgw6qWiLAPmzMFlkgxbtjFAWMJB0zBMy2BqjntOJ6KnqtYRMQUxwTgXZDF4rhYVKtQVOpfg6hIlsaoPNrF7dofizJ099OOgDmCaEYqM++bUlEHxgrIVkwZz+bg43dfJCocr9O5YX0iXaz3TOT5cpdtYbBX+C/5hwrqBWru4HbD3xz8cY1TnDqQa0M8ECgYEA3Slxg/DwTXJcb6095RoXygQCAZ5RnAvZlno1yhHtnUex/fp7AZ/9nRaO7HX/+SFfGQeutao2TDjDAWU4Vupk8rw9JR0AzZ0N2fvuIAmr/WCsmGpeNqQnev1T7IyEsnh8UMt+n5CafhkikzhEsrmndH6LxOrvRJlsPp6Zv8bUq0kCgYEAuKE2dh+cTf6ERF4k4e/jy78GfPYUIaUyoSSJuBzp3Cubk3OCqs6grT8bR/cu0Dm1MZwWmtdqDyI95HrUeq3MP15vMMON8lHTeZu2lmKvwqW7anV5UzhM1iZ7z4yMkuUwFWoBvyY898EXvRD+hdqRxHlSqAZ192zB3pVFJ0s7pFcCgYAHw9W9eS8muPYv4ZhDu/fL2vorDmD1JqFcHCxZTOnX1NWWAj5hXzmrU0hvWvFC0P4ixddHf5Nqd6+5E9G3k4E52IwZCnylu3bqCWNh8pT8T3Gf5FQsfPT5530T2BcsoPhUaeCnP499D+rb2mTnFYegmnTT1B/Ue8KGLFFfn16GKQKBgAiw5gxnbocpXPaO6/OKxFFZ+6c0OjxfN2PogWceTU/k6ZzmShdaRKwDFXisxRJeNQ5Rx6qgS0jNFtbDhW8E8WFmQ5urCOqIOYk28EBiAt4JySm4v+5P7yYBh8B8YD2l9j57z/s8hJAxEbn/q8uHP2ddQqvQKgtsni+pHSk9XGBfAoGBANz4qr10DdM8DHhPrAb2YItvPVz/VwkBd1Vqj8zCpyIEKe/07oKOvjWQSgkLDH9x2hBgY01SbP43CvPk0V72invu2TGkI/FXwXWJLLG7tDSgw4YyfhrYrHmg1Vre3XB9HH8MYBVB6UIexaAq4xSeoemRKTBesZro7OKjKT8/GmiO";

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

/// Standard base64 (with padding) -- only for the constant above.
fn b64_decode(s: &str) -> Vec<u8> {
    let val = |c: u8| -> u32 {
        match c {
            b'A'..=b'Z' => (c - b'A') as u32,
            b'a'..=b'z' => (c - b'a' + 26) as u32,
            b'0'..=b'9' => (c - b'0' + 52) as u32,
            b'+' => 62,
            b'/' => 63,
            _ => die(format!("bad base64 byte {c}")),
        }
    };
    let bytes: Vec<u8> = s.bytes().filter(|&c| c != b'=').collect();
    let mut out = Vec::with_capacity(bytes.len() * 3 / 4);
    for chunk in bytes.chunks(4) {
        let mut acc = 0u32;
        for (i, &c) in chunk.iter().enumerate() {
            acc |= val(c) << (18 - 6 * i);
        }
        for i in 0..chunk.len() - 1 {
            out.push((acc >> (16 - 8 * i)) as u8);
        }
    }
    out
}

struct Alg {
    alg: Algorithm,
    enc: EncodingKey,
    dec: DecodingKey,
}

fn main() {
    let args: Vec<String> = std::env::args().collect();
    if args.len() != 3 {
        die("usage: jwt_fast_bench <work dir> <workload>".into());
    }
    let dir = std::path::Path::new(&args[1]);
    let w = args[2].as_str();
    eprintln!("Keats/jsonwebtoken 9.3.1 (ring 0.17.14)");
    let slurp = |name: &str| std::fs::read(dir.join(name)).unwrap_or_else(|e| die(format!("{name}: {e}")));

    let rng = SystemRandom::new();
    let ec = |a: &'static signature::EcdsaSigningAlgorithm, alg: Algorithm| {
        let pkcs8 = signature::EcdsaKeyPair::generate_pkcs8(a, &rng).unwrap();
        let kp = signature::EcdsaKeyPair::from_pkcs8(a, pkcs8.as_ref(), &rng).unwrap();
        Alg { alg, enc: EncodingKey::from_ec_der(pkcs8.as_ref()), dec: DecodingKey::from_ec_der(kp.public_key().as_ref()) }
    };
    let rsa = |alg: Algorithm| {
        let der = b64_decode(RSA_DER_B64);
        let kp = signature::RsaKeyPair::from_der(&der).unwrap_or_else(|e| die(format!("rsa key: {e}")));
        let public: signature::RsaPublicKeyComponents<Vec<u8>> = kp.public().into();
        if public.n != slurp("rsa.n") {
            die("the embedded RSA key is not the Zig side's (rsa.n differs)".into());
        }
        Alg { alg, enc: EncodingKey::from_rsa_der(&der), dec: DecodingKey::from_rsa_der(kp.public().as_ref()) }
    };

    let (name, op) = w
        .strip_prefix("rs.")
        .and_then(|s| s.split_once('_'))
        .unwrap_or_else(|| die(format!("unknown workload {w}")));
    let a = match name {
        "hs256" => {
            let hmac = slurp("hs256.key");
            Alg { alg: Algorithm::HS256, enc: EncodingKey::from_secret(&hmac), dec: DecodingKey::from_secret(&hmac) }
        }
        "es256" => ec(&signature::ECDSA_P256_SHA256_FIXED_SIGNING, Algorithm::ES256),
        "es384" => ec(&signature::ECDSA_P384_SHA384_FIXED_SIGNING, Algorithm::ES384),
        "eddsa" => {
            let pkcs8 = signature::Ed25519KeyPair::generate_pkcs8(&rng).unwrap();
            let kp = signature::Ed25519KeyPair::from_pkcs8(pkcs8.as_ref()).unwrap();
            Alg { alg: Algorithm::EdDSA, enc: EncodingKey::from_ed_der(pkcs8.as_ref()), dec: DecodingKey::from_ed_der(kp.public_key().as_ref()) }
        }
        "rs256" => rsa(Algorithm::RS256),
        "ps256" => rsa(Algorithm::PS256),
        _ => die(format!("unknown workload {w}")),
    };
    let claims: Value = serde_json::from_str(CLAIMS).unwrap();
    let header = Header::new(a.alg);
    let sign = || encode(&header, &claims, &a.enc).unwrap_or_else(|e| die(format!("sign: {e}")));
    let mut v = Validation::new(a.alg);
    v.set_issuer(&[ISSUER]);
    v.set_audience(&[AUDIENCE]);
    v.set_required_spec_claims(&["exp", "iss", "aud"]);
    v.validate_exp = true;
    v.validate_nbf = true;

    let (ns, count) = match op {
        "sign" => time_it(|| sign().len() as u64),
        "verify" => {
            let tok = sign();
            time_it(|| {
                let d = decode::<Value>(&tok, &a.dec, &v).unwrap_or_else(|e| die(format!("verify: {e}")));
                black_box(d);
                1
            })
        }
        _ => die(format!("unknown workload {w}")),
    };
    println!("{w}\t{ns:.1}\t0\t{count}");
}
