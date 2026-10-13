// SPDX-License-Identifier: MIT

//! Dead-stack probe (`testkit.stackprobe`) for the entry points burned in the
//! 2026-10-09 `check-secret-api` pass: `jws.sign`, `x509.csrDer` and
//! `x509.tlsAlpnCertDer`. The older `stackprobe_test.zig` (hand-made engine,
//! with the per-call nonce needles) is left as it was. ReleaseFast only.

const std = @import("std");
const jws = @import("jws.zig");
const x509 = @import("x509.zig");
const sp = @import("testkit").stackprobe;
const Sha256 = std.crypto.hash.sha2.Sha256;

// The burn is 32 KiB; the window must exceed it.
const P = sp.Probe(.{ .window = 128 * 1024 });

var heap_buf: [512 * 1024]u8 = undefined;
var heap_fba: std.heap.FixedBufferAllocator = undefined;
var pair: jws.KeyPair = undefined;
var seed: [32]u8 = undefined;
var sk_bytes: [32]u8 = undefined;

const header: jws.Header = .{ .nonce = "n-0123", .url = "https://ca.example/new-order" };
const domains: []const []const u8 = &.{ "example.com", "www.example.com" };
const acme_id: [32]u8 = @splat(0x5a);
const serial: [16]u8 = .{0x01} ++ @as([15]u8, @splat(0x33));

// The entry points take their key as `anytype` (any curve); the probe needs
// concrete function types, so it goes through these P-256 instances.
fn signP256(gpa: std.mem.Allocator, kp: *const jws.KeyPair, payload: []const u8, h: jws.Header) jws.SignError![]u8 {
    return jws.sign(gpa, kp, payload, h);
}

fn csrP256(gpa: std.mem.Allocator, kp: *const jws.KeyPair, names: []const []const u8) x509.CsrError![]u8 {
    return x509.csrDer(gpa, kp, names);
}

fn alpnP256(
    gpa: std.mem.Allocator,
    kp: *const jws.KeyPair,
    domain: []const u8,
    id: [32]u8,
    ser: []const u8,
    not_before: []const u8,
    not_after: []const u8,
) x509.TlsAlpnError![]u8 {
    return x509.tlsAlpnCertDer(gpa, kp, domain, id, ser, not_before, not_after);
}

test "STACKPROBE: acme signing entry points leave no account-key residue" {
    try sp.skipUnlessOptimized();
    Sha256.hash("acme probe seed", &seed, .{});
    try jws.Es256.KeyPair.generateDeterministicInto(&pair, &seed);
    sk_bytes = pair.secret_key.toBytes();
    const secrets = &[_][]const u8{ &seed, &sk_bytes };

    heap_fba = .init(&heap_buf);
    const gpa = heap_fba.allocator();
    _ = try P.run("jws.sign", signP256, .{ gpa, &pair, "{\"termsOfServiceAgreed\":true}", header }, secrets, .{});
    heap_fba.reset();
    _ = try P.run("x509.csrDer", csrP256, .{ gpa, &pair, domains }, secrets, .{});
    heap_fba.reset();
    _ = try P.run("x509.tlsAlpnCertDer", alpnP256, .{ gpa, &pair, "example.com", acme_id, &serial, x509.tls_alpn_not_before, x509.tls_alpn_not_after }, secrets, .{});
}
