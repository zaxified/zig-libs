// SPDX-License-Identifier: MIT

//! What an mTLS server (or an OPC-UA endpoint pinning a peer's application
//! certificate) does with `x509`: validate a presented certificate chain
//! against a trust store with `verifyChain`, checking signature, validity
//! window and hostname — then show the same call correctly rejecting an
//! expired certificate instead of accepting it.
//!
//! `verifyChain` needs real, signature-valid DER certificates — there is no
//! meaningful in-memory fake for X.509 path validation. This example builds
//! its own self-signed CA certificate with the `rsa` module's
//! `selfSignedCert` (the `deps` this module declares: `rsa`), matching the
//! OPC-UA-style deployment the module's own doc comment names as a
//! consumer: a single self-signed application certificate pinned directly
//! as its own trust anchor, rather than a multi-level CA hierarchy.
//!
//! This is an example in the gate sense — it is built by
//! `zig build check-examples` against the PUBLISHED module (`deps` only, no
//! `test_deps`, no access to anything the module does not export). If a type
//! needed to call the API is not public, or an error cannot be named from
//! outside, this file stops compiling. The module's own tests cannot notice
//! either, because they live inside it.

const std = @import("std");
const x509 = @import("x509");
const rsa = @import("rsa");

/// An arbitrary "now" the example checks certificates against — never a
/// clock read (x509 does no I/O of its own; `Options.now_sec` is always
/// caller-supplied). 2027-06-15T00:00:00Z.
const verify_now: i64 = 1813363200;

pub fn main() !void {
    var da: std.heap.DebugAllocator(.{}) = .init;
    defer if (da.deinit() == .leak) @panic("leak");
    const gpa = da.allocator();

    // A seeded PRNG is fine for generating example trust material; a real
    // deployment's key material must come from a cryptographically secure
    // source instead.
    var prng = std.Random.DefaultPrng.init(0xc0ffee);
    const keys = try rsa.generate(prng.random(), 1024, 65537);

    // ── a valid, currently-in-window self-signed CA cert, pinned as its
    //    own trust anchor (the OPC-UA-style single-application-cert case) ──
    const good_der = try rsa.selfSignedCert(gpa, keys.secret_key, keys.public_key, std.crypto.hash.sha2.Sha256, .{
        .common_name = "endpoint.example.org",
        .serial = 1,
        .not_before = "250101000000Z", // 2025-01-01
        .not_after = "301231235959Z", // 2030-12-31
        .is_ca = true,
        .subject_alt_names = &.{.{ .dns_name = "endpoint.example.org" }},
    });
    defer gpa.free(good_der);

    const chain = [_]x509.chain.CertDer{good_der};
    const trust_anchors = [_]x509.chain.CertDer{good_der};

    const verified = try x509.verifyChain(gpa, &chain, &trust_anchors, .{
        .now_sec = verify_now,
        .expected_host = "endpoint.example.org",
    });
    std.debug.print("chain verified: depth={d} trust_anchor_index={d}\n", .{
        verified.depth, verified.trust_anchor_index,
    });

    // ── the same call, but the certificate's validity window has already
    //    closed — must fail by name, not silently accept ─────────────────
    const expired_der = try rsa.selfSignedCert(gpa, keys.secret_key, keys.public_key, std.crypto.hash.sha2.Sha256, .{
        .common_name = "stale.example.org",
        .serial = 2,
        .not_before = "200101000000Z", // 2020-01-01
        .not_after = "210101000000Z", // 2021-01-01 -- long expired by verify_now
        .is_ca = true,
    });
    defer gpa.free(expired_der);

    const expired_chain = [_]x509.chain.CertDer{expired_der};
    const expired_anchors = [_]x509.chain.CertDer{expired_der};

    _ = x509.verifyChain(gpa, &expired_chain, &expired_anchors, .{ .now_sec = verify_now }) catch |err| switch (err) {
        error.CertificateExpired => {
            std.debug.print("expired certificate correctly rejected\n", .{});
            return;
        },
        else => return err,
    };
    return error.ExpectedCertificateExpired;
}
