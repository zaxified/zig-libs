// SPDX-License-Identifier: MIT

//! Test fixtures for `certauth.zig` — a small real X.509 certificate chain
//! generated with OpenSSL 3.5.5 (`openssl req -x509 ...` / `openssl x509
//! -req ... -CA ...`), NOT hand-transcribed ASN.1: an ECDSA P-256 trust
//! anchor ("dtls-test-anchor"), a leaf signed by it ("dtls-test-server"),
//! a second leaf signed by it ("dtls-test-client"), and an UNRELATED anchor
//! + leaf pair ("dtls-test-evil-anchor" / "dtls-test-server") sharing the
//! server leaf's subject name but chaining to a DIFFERENT key — for the
//! "wrong/untrusted chain is rejected" test. All certificates are
//! `notBefore` 2026-07-21 / `notAfter` 2036-07-18 (10-year validity); tests
//! use a fixed `now_sec` inside that window. An RSA-2048 self-signed
//! certificate is included separately to exercise the RSA leaf-key bridge
//! (`rsa.PublicKey.fromDer`). None of these keys/certificates are used
//! anywhere outside this repo's own tests.
//!
//! **The bytes live in `testdata/certs/`, not in hex literals here** (moved
//! 2026-09-06). `tools/interop.zig` — the live wolfSSL harness, which is a
//! standalone program outside this module — has to hand wolfSSL the SAME
//! anchor, leaf and key that the Zig side trusts, or "wolfSSL accepted it"
//! degrades into "wolfSSL trusted something else". It cannot `@import` this
//! file (a module may not import across its own package root), so the only
//! way to keep ONE copy of each blob is to put the copy where both can read
//! it: the module `@embedFile`s it, the tool opens it. A second hex literal
//! in `tools/` would have been a second thing to keep in step, and the whole
//! point of these fixtures is that the two sides cannot drift.
//!
//! DER is also more inspectable than hex, not less: `openssl x509 -inform
//! der -in src/testdata/certs/server-cert.der -text` reads them.

/// `@embedFile` gives a `*const [N:0]u8`; the tests want a plain `[N]u8`
/// value they can take the address of, so the sentinel is dropped here once
/// rather than at every use site.
fn der(comptime path: []const u8) [@embedFile(path).len]u8 {
    const raw = @embedFile(path);
    return raw[0..raw.len].*;
}

/// A `now_sec` (Unix epoch seconds) inside every fixture certificate's
/// validity window (2026-07-21 .. 2036-07-18): 2026-08-01T00:00:00Z.
pub const valid_now_sec: i64 = 1785542400;

/// The trust anchor: a self-signed ECDSA P-256 certificate, CN=dtls-test-anchor.
pub const anchor_cert_der = der("testdata/certs/anchor-cert.der");

/// Server leaf: ECDSA P-256, CN=dtls-test-server, issued (real signature)
/// by `anchor_cert_der`'s key.
pub const server_cert_der = der("testdata/certs/server-cert.der");
/// `server_cert_der`'s raw 32-byte ECDSA P-256 private scalar.
pub const server_secret_key_bytes = der("testdata/certs/server-key.bin");

/// Client leaf: ECDSA P-256, CN=dtls-test-client, issued by the SAME anchor.
pub const client_cert_der = der("testdata/certs/client-cert.der");
/// `client_cert_der`'s raw 32-byte ECDSA P-256 private scalar.
pub const client_secret_key_bytes = der("testdata/certs/client-key.bin");

/// A DIFFERENT self-signed anchor (CN=dtls-test-evil-anchor) with NO
/// relationship to `anchor_cert_der` — for the "untrusted chain" reject test.
pub const evil_anchor_cert_der = der("testdata/certs/evil-anchor-cert.der");

/// A leaf with the SAME subject name as `server_cert_der`
/// (CN=dtls-test-server) but signed by `evil_anchor_cert_der`'s key, not
/// `anchor_cert_der`'s — verifying this against `anchor_cert_der` MUST fail
/// (issuer-name / signature mismatch), proving `verifyLeafAgainstAnchor`
/// does not accept "same-looking name, wrong key".
pub const evil_server_cert_der = der("testdata/certs/evil-server-cert.der");

/// RSA-2048 self-signed certificate, CN=dtls-test-rsa — used ONLY to prove
/// `parseLeafPublicKey`'s RSA path (`rsa.PublicKey.fromDer` bridging) parses
/// a real X.509-embedded RSA key, not for chain verification.
pub const rsa_cert_der = der("testdata/certs/rsa-cert.der");
