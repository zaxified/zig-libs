// SPDX-License-Identifier: MIT
//! ECDSA P-384 responder signatures (2026-09-30), anchored on responses that
//! OpenSSL 3 produced AND verified itself — the external half: this module
//! never built these bytes.
//!
//! Recipe (run once in a scratch directory; the keys were throwaway):
//!
//! ```sh
//! openssl ecparam -name secp384r1 -genkey -noout -out ca.key
//! openssl req -x509 -new -key ca.key -sha384 -days 3650 -subj "/CN=Test P-384 CA" -out ca.pem \
//!     -addext "basicConstraints=critical,CA:TRUE" -addext "keyUsage=critical,keyCertSign,cRLSign"
//! # leaf1 (serial 0x1001, valid) and leaf2 (serial 0x1002, revoked keyCompromise): P-256 keys,
//! # signed by the CA with -sha384. resp: a P-384 delegated responder with
//! # extendedKeyUsage=OCSPSigning, serial 0x2001, signed by the CA.
//! openssl ocsp -index index.txt -rsigner ca.pem   -rkey ca.key   -CA ca.pem -reqin req1.der \
//!     -respout direct384.der -rmd sha384 -ndays 3650 -resp_key_id
//! openssl ocsp -index index.txt -rsigner ca.pem   -rkey ca.key   -CA ca.pem -reqin req1.der \
//!     -respout direct256.der -rmd sha256 -ndays 3650
//! openssl ocsp -index index.txt -rsigner resp.pem -rkey resp.key -CA ca.pem -reqin req2.der \
//!     -respout deleg384.der -rmd sha384 -ndays 3650
//! ```
//!
//! `openssl ocsp -respin <r>.der -issuer ca.pem -cert leafN.pem -CAfile ca.pem -text` printed
//! "Response verify OK" for all three, and:
//!   direct384: Responder Id byKey 0BCF28901BE5EB0E85352CF5A97485683ED4DC12,
//!              Signature Algorithm ecdsa-with-SHA384, Cert Status good;
//!   direct256: Responder Id CN = Test P-384 CA, ecdsa-with-SHA256 (on the P-384 key), good;
//!   deleg384:  Responder Id CN = Test P-384 OCSP Responder, ecdsa-with-SHA384, revoked,
//!              Revocation Time Sep 29 05:22:17 2026 GMT, Reason keyCompromise (0x1).
//! All: This Update Sep 30 05:22:17 2026 GMT, Next Update Sep 27 05:22:17 2036 GMT. Epochs by
//! `date -u -d <t> +%s`: 1790745737, 2106105737, revocation 1790659337.

const std = @import("std");
const testing = std.testing;
const ocsp = @import("root.zig");

const ca = @embedFile("testdata/p384/ca.der");
const leaf1 = @embedFile("testdata/p384/leaf1.der");
const leaf2 = @embedFile("testdata/p384/leaf2.der");
const direct384 = @embedFile("testdata/p384/direct384.der");
const direct256 = @embedFile("testdata/p384/direct256.der");
const deleg384 = @embedFile("testdata/p384/deleg384.der");

const this_update: i64 = 1790745737;
const next_update: i64 = 2106105737;
/// thisUpdate + 1 h: inside the response window and every certificate's validity.
const now: i64 = this_update + 3600;

test "P-384: direct responder, ecdsa-with-SHA384, byKey (OpenSSL-made)" {
    const v = try ocsp.verify(try ocsp.parseResponse(direct384), ca, leaf1, .{ .now_unix = now });
    try testing.expect(v.status == .good);
    try testing.expect(!v.delegated);
    try testing.expect(v.responder == .by_key);
    try testing.expectEqual(this_update, v.this_update_unix);
    try testing.expectEqual(@as(?i64, next_update), v.next_update_unix);
}

test "P-384: direct responder, ecdsa-with-SHA256 on the P-384 key, byName" {
    const v = try ocsp.verify(try ocsp.parseResponse(direct256), ca, leaf1, .{ .now_unix = now });
    try testing.expect(v.status == .good);
    try testing.expect(v.responder == .by_name);
}

test "P-384: delegated P-384 responder (cert signed ecdsa-with-SHA384), revoked keyCompromise" {
    const v = try ocsp.verify(try ocsp.parseResponse(deleg384), ca, leaf2, .{ .now_unix = now });
    try testing.expect(v.delegated);
    switch (v.status) {
        .revoked => |r| {
            try testing.expectEqual(@as(i64, 1790659337), r.revocation_time_unix);
            try testing.expectEqual(@as(?u8, 1), r.reason);
        },
        else => return error.TestUnexpectedResult,
    }
}

test "P-384: a changed signed byte or signature byte is SignatureInvalid, not accepted" {
    // One digit of producedAt/thisUpdate ("20260930…") inside tbsResponseData.
    var tampered: [direct384.len]u8 = direct384.*;
    const at = std.mem.indexOf(u8, &tampered, "20260930").?;
    tampered[at + 7] = '1'; // …30 → …31: still a valid GeneralizedTime
    try testing.expectError(error.SignatureInvalid, ocsp.verify(try ocsp.parseResponse(&tampered), ca, leaf1, .{ .now_unix = now }));
    // A byte of r inside the response's signature BIT STRING. (Not the file's
    // last octet: after the signature come the embedded `certs`, which a
    // direct responder never consults — this test's first draft flipped one
    // of those and, rightly, still verified.) The first ecdsa-with-SHA384
    // AlgorithmIdentifier in the file is the response's signatureAlgorithm;
    // the BIT STRING follows: 03 67 00 | 30 64 | 02 30 <r…>.
    var bad_sig: [direct384.len]u8 = direct384.*;
    const alg = [_]u8{ 0x30, 0x0a, 0x06, 0x08, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x04, 0x03, 0x03 };
    const sig_at = std.mem.indexOf(u8, &bad_sig, &alg).? + alg.len;
    try testing.expectEqual(@as(u8, 0x03), bad_sig[sig_at]); // BIT STRING
    bad_sig[sig_at + 3 + 2 + 2 + 5] ^= 0x01; // 6th octet of r
    try testing.expectError(error.SignatureInvalid, ocsp.verify(try ocsp.parseResponse(&bad_sig), ca, leaf1, .{ .now_unix = now }));
}

test "P-384: the answer is for leaf1, not leaf2 (same issuer, other serial)" {
    try testing.expectError(error.CertIdMismatch, ocsp.verify(try ocsp.parseResponse(direct384), ca, leaf2, .{ .now_unix = now }));
}
