// SPDX-License-Identifier: MIT

//! ctgrind_harness — the constant-time evidence for `SPEC.md`'s Hardening line.
//! Run it through `../../../scripts/checks/ctgrind.sh acme`, which builds
//! every mode/taint combination and prints the control table.
//!
//! Not wired into `zig build test-acme`: memcheck's context count is
//! valgrind's own output. `zig build check-ctgrind` only compiles it.
//!
//! ## What this measures
//!
//! The only secret ACME handles is a P-256 private key: the account key (signs
//! every JWS) and the certificate key (signs the CSR, is written to and read
//! from disk as PEM). The key pair is made from a fixed seed with the public
//! half computed first, then ONLY the private scalar bytes are tainted, so the
//! public key, the headers and the payloads stay defined. There is no
//! EAB/HMAC path in this module.
//!
//!  * `jws` — `jws.sign` with the tainted account key, both header shapes
//!    (`jwk` for newAccount, `kid` for every other request).
//!  * `csr` — `x509.csrDer` with the tainted certificate key, one and two
//!    names.
//!  * `pem` — `x509.ecPrivateKeyToPem` of a tainted key (the scalar goes
//!    through DER and base64), then `x509.ecPrivateKeyFromPem` on the PEM of
//!    that key with its bytes tainted (base64 decode, DER walk, scalar
//!    load).
//!  * `pem384` — the same round trip for a P-384 key (ES384 account and
//!    certificate keys, 2026-10-13); the public point is recomputed by
//!    `p384`.
//!  * `pkcs8` — `x509.pkcs8PrivateKeyToPem` + `pkcs8PrivateKeyFromPem` (RFC
//!    5958, `openssl genpkey`'s shape) for a P-256 and a P-384 key.
//!  * `anykey` — the label search over a text that holds a secret block of
//!    ANOTHER label (2026-10-18): `privateKeyFromPem` on a PKCS#8 PEM (its
//!    `EC PRIVATE KEY` search misses and walks past the key's body), and
//!    `pemBlockStart` for a CERTIFICATE stored after the key (the
//!    Manager's `.pem` blob). A `std.mem.indexOf` here showed as `findPos`.
//!
//! The ECDSA signer is `p256`'s and is claimed there; what is measured here
//! is the module's own files (and that nothing in them branches on, or
//! indexes by, the tainted scalar or the signature derived from it).
//!
//! ## The propagation witness
//!
//! Every result is printed as `ctgrind_result={x}` over its bytes; the
//! formatter is not constant-time, so the total is non-zero while the in-file
//! count is zero.

const std = @import("std");
const builtin = @import("builtin");
const acme = @import("root.zig");

const jws = acme.jws;
const x509 = acme.x509;

const Target = enum { jws, csr, pem, pem384, pkcs8, anykey };
const Es384 = jws.Es384;
const Taint = enum { yes, no };

fn makeKey(t: Taint) jws.KeyPair {
    var seed: [jws.KeyPair.seed_length]u8 = undefined;
    std.crypto.hash.sha2.Sha256.hash("ctgrind-acme-key-v1", &seed, .{});
    var kp: jws.KeyPair = undefined;
    jws.KeyPair.generateDeterministicInto(&kp, &seed) catch unreachable;
    if (t == .yes) std.valgrind.memcheck.makeMemUndefined(std.mem.asBytes(&kp.secret_key));
    return kp;
}

fn makeKey384(t: Taint) Es384.KeyPair {
    var seed: [Es384.KeyPair.seed_length]u8 = undefined;
    std.crypto.hash.sha2.Sha384.hash("ctgrind-acme-key384-v1", &seed, .{});
    var kp: Es384.KeyPair = undefined;
    Es384.KeyPair.generateDeterministicInto(&kp, &seed) catch unreachable;
    if (t == .yes) std.valgrind.memcheck.makeMemUndefined(std.mem.asBytes(&kp.secret_key));
    return kp;
}

/// Write `kp` in `form`, show the text, load it back, show the scalar (see
/// `.pem` for why the round trip, not a tainted whole text).
fn roundTrip(comptime form: enum { sec1, pkcs8 }, gpa: std.mem.Allocator, kp: anytype) !void {
    const pem = switch (form) {
        .sec1 => try x509.ecPrivateKeyToPem(gpa, kp),
        .pkcs8 => try x509.pkcs8PrivateKeyToPem(gpa, kp),
    };
    defer gpa.free(pem);
    show(pem);
    var back: @TypeOf(kp.*) = undefined;
    switch (form) {
        .sec1 => try x509.ecPrivateKeyFromPem(&back, gpa, pem),
        .pkcs8 => try x509.pkcs8PrivateKeyFromPem(&back, gpa, pem),
    }
    show(&back.secret_key.bytes);
}

fn show(bytes: []const u8) void {
    std.debug.print("ctgrind_result={x}\n", .{bytes});
}

pub fn main(init: std.process.Init.Minimal) !void {
    var it = init.args.iterate();
    _ = it.next(); // argv[0]
    const target = std.meta.stringToEnum(Target, it.next() orelse return error.MissingTarget) orelse
        return error.UnknownTarget;
    const taint = std.meta.stringToEnum(Taint, it.next() orelse return error.MissingTaint) orelse
        return error.UnknownTaint;

    std.debug.print("valgrind_support={} target={t}\n", .{ builtin.valgrind_support, target });
    const gpa = std.heap.page_allocator; // global-alloc-ok: one-shot ctgrind diagnostic binary, no caller to take one from
    var kp = makeKey(taint);
    switch (target) {
        .jws => {
            const a = try jws.sign(gpa, &kp, "{\"termsOfServiceAgreed\":true}", .{
                .nonce = "nonce-0001",
                .url = "https://acme.example/new-acct",
            });
            defer gpa.free(a);
            show(a);
            const b = try jws.sign(gpa, &kp, "", .{
                .nonce = "nonce-0002",
                .url = "https://acme.example/order/1",
                .kid = "https://acme.example/acct/1",
            });
            defer gpa.free(b);
            show(b);
        },
        .csr => {
            const one = try x509.csrDer(gpa, &kp, &.{"example.org"});
            defer gpa.free(one);
            show(one);
            const two = try x509.csrDer(gpa, &kp, &.{ "example.org", "*.example.org" });
            defer gpa.free(two);
            show(two);
        },
        .pem => {
            const pem = try x509.ecPrivateKeyToPem(gpa, &kp);
            defer gpa.free(pem);
            show(pem);
            // Load back exactly what was written. The encoder is arithmetic
            // (b64ct), so memcheck's taint marks precisely the characters
            // that carry key bits (and the public point's, derived from the
            // key); the BEGIN/END lines, line breaks and DER structure stay
            // defined. Tainting the whole text instead (until 2026-10-13)
            // flagged the DER parser's tag and length branches — public
            // structure — and, while std's table decoder was in the path,
            // hid the decoded key from memcheck (a load through an undefined
            // index yields a DEFINED value), so the DER parse looked clean.
            var back: jws.KeyPair = undefined;
            try x509.ecPrivateKeyFromPem(&back, gpa, pem);
            show(&back.secret_key.bytes);
        },
        .pem384 => {
            var k384 = makeKey384(taint);
            try roundTrip(.sec1, gpa, &k384);
        },
        .pkcs8 => {
            try roundTrip(.pkcs8, gpa, &kp);
            var k384 = makeKey384(taint);
            try roundTrip(.pkcs8, gpa, &k384);
        },
        .anykey => {
            const pem = try x509.pkcs8PrivateKeyToPem(gpa, &kp);
            defer gpa.free(pem);
            show(pem);
            var back: jws.AnyKeyPair = undefined;
            try x509.privateKeyFromPem(&back, gpa, pem);
            show(&back.es256.secret_key.bytes); // the active arm only: the rest is undefined
            const blob = try std.mem.concat(gpa, u8, &.{ pem, "-----BEGIN CERTIFICATE-----\nMAA=\n-----END CERTIFICATE-----\n" });
            defer gpa.free(blob);
            const at = x509.pemBlockStart(blob, "CERTIFICATE") orelse return error.NoCertificate;
            show(blob[at..]);
        },
    }
}
