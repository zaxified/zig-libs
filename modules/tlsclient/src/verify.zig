// SPDX-License-Identifier: MIT

//! The one thing this module changes about std's TLS client: how the chain a
//! server sends is judged against the caller's CA bundle.
//!
//! std 0.16 walks the chain link by link with `Certificate.Parsed.verify`,
//! which checks the issuer name, the validity period and the signature --
//! never basicConstraints, pathLenConstraint or keyUsage (ziglang/zig #35877,
//! open since 2026-06-21). Whoever holds one valid certificate for any name
//! can sign a leaf for any other name with its key and put it in front of
//! its own chain: every link verifies, and std's client talks to the
//! impostor. It also parses each peer certificate with std's element parser,
//! which reads out of bounds on malformed DER (`x509` SPEC, `safe.zig`).
//!
//! Here the whole chain is collected first, every certificate is proven
//! well-formed by `x509.safe` before anything parses it, and the decision is
//! `x509.verifyChain` -- RFC 5280 §6.1 path validation (basicConstraints,
//! keyUsage, pathLen, nameConstraints) plus extKeyUsage serverAuth on the
//! leaf. The hostname stays std's `verifyHostName`, done by the caller on the
//! leaf exactly as before.

const std = @import("std");
const x509 = @import("x509");
const testkit = @import("testkit");
const Certificate = std.crypto.Certificate;

/// The most certificates a server's Certificate message may carry. Real
/// chains are 2-4; `x509.Options.max_intermediates` (8) plus the leaf and a
/// stray anchor fit.
pub const max_chain_len = 10;

/// Stack room for `x509.verifyChain`'s bookkeeping (the built path and its
/// candidate lists -- a few hundred bytes for a real chain).
const scratch_len = 16 * 1024;

pub const Error = error{
    /// The chain does not lead to the bundle under RFC 5280, or a
    /// certificate in it is malformed.
    TlsCertificateNotVerified,
};

/// Refuse a certificate std's parser must not see (see the file header).
pub fn checkWellFormed(der: []const u8) Error!void {
    if (der.len > x509.safe.max_certificate_len) return error.TlsCertificateNotVerified;
    x509.safe.validateCertificate(der) catch return error.TlsCertificateNotVerified;
}

/// Verify `chain` (leaf first, as the server sent it, each one already
/// through `checkWellFormed`) against `bundle` at `now_sec`.
pub fn verifyAgainstBundle(chain: []const []const u8, bundle: *const Certificate.Bundle, now_sec: i64) Error!void {
    if (chain.len == 0 or chain.len > max_chain_len) return error.TlsCertificateNotVerified;
    // Trust anchors: the bundle's certificate for every issuer name the chain
    // mentions. `Bundle` keys one certificate per subject, which is all a
    // path can end in.
    var anchors: [max_chain_len][]const u8 = undefined;
    var n: usize = 0;
    for (chain) |der| {
        const parsed = (Certificate{ .buffer = der, .index = 0 }).parse() catch return error.TlsCertificateNotVerified;
        const at = bundle.find(parsed.issuer()) orelse continue;
        const anchor = anchorDer(bundle, at) orelse continue;
        for (anchors[0..n]) |a| {
            if (a.ptr == anchor.ptr) break;
        } else {
            anchors[n] = anchor;
            n += 1;
        }
    }
    if (n == 0) return error.TlsCertificateNotVerified;

    var scratch: [scratch_len]u8 = undefined;
    var fba: std.heap.FixedBufferAllocator = .init(&scratch);
    _ = x509.verifyChain(fba.allocator(), chain, anchors[0..n], .{
        .now_sec = now_sec,
        .required_eku = .server_auth,
    }) catch return error.TlsCertificateNotVerified;
}

/// The whole DER of the bundle certificate starting at `at`. The bundle's
/// bytes came from the caller's trust store and were parsed by std when it
/// was loaded; the length is still read with a check against the buffer.
fn anchorDer(bundle: *const Certificate.Bundle, at: u32) ?[]const u8 {
    const bytes = bundle.bytes.items;
    if (at + 2 > bytes.len) return null;
    var i: usize = at + 1;
    const first = bytes[i];
    i += 1;
    var len: usize = first;
    if (first & 0x80 != 0) {
        const k = first & 0x7f;
        if (k == 0 or k > 4 or i + k > bytes.len) return null;
        len = 0;
        for (bytes[i..][0..k]) |b| len = (len << 8) | b;
        i += k;
    }
    if (i + len > bytes.len) return null;
    return bytes[at .. i + len];
}

// ── tests ───────────────────────────────────────────────────────────────────

const testing = std.testing;

fn pemToDer(pem: []const u8, out: []u8) ![]const u8 {
    const begin = "-----BEGIN CERTIFICATE-----";
    const a = (std.mem.indexOf(u8, pem, begin) orelse return error.NoPem) + begin.len;
    const b = std.mem.indexOfPos(u8, pem, a, "-----END CERTIFICATE-----") orelse return error.NoPem;
    return out[0..try std.base64.standard.decoderWithIgnore(" \t\r\n").decode(out, pem[a..b])];
}

/// A bundle holding the test root, loaded the way a consumer loads one.
fn rootBundle(gpa: std.mem.Allocator) !Certificate.Bundle {
    var bundle: Certificate.Bundle = .empty;
    errdefer bundle.deinit(gpa);
    var buf: [4096]u8 = undefined;
    const der = try pemToDer(@embedFile("testdata/root.pem"), &buf);
    const start: u32 = @intCast(bundle.bytes.items.len);
    try bundle.bytes.appendSlice(gpa, der);
    try bundle.parseCert(gpa, start, 0);
    return bundle;
}

// Fixed "now" inside every fixture's validity window (2026-09-25).
const now: i64 = 1_790_300_000;

const Chain = struct {
    bufs: [4][4096]u8 = undefined,
    ders: [4][]const u8 = undefined,
    fn of(c: *Chain, pems: []const []const u8) ![]const []const u8 {
        for (pems, 0..) |p, i| {
            c.ders[i] = try pemToDer(p, &c.bufs[i]);
            try checkWellFormed(c.ders[i]);
        }
        return c.ders[0..pems.len];
    }
};

test "an honest chain (leaf, intermediate) verifies against its root" {
    var bundle = try rootBundle(testing.allocator);
    defer bundle.deinit(testing.allocator);
    var c: Chain = .{};
    try verifyAgainstBundle(try c.of(&.{ @embedFile("testdata/leaf.pem"), @embedFile("testdata/inter.pem") }), &bundle, now);
}

test "a leaf signed by another leaf's key is refused (ziglang/zig #35877)" {
    // forged.pem: CN/SAN victim.example.test, issuer = leaf.pem's subject,
    // signed with leaf.pem's key. Every link verifies; leaf.pem is CA:FALSE.
    var bundle = try rootBundle(testing.allocator);
    defer bundle.deinit(testing.allocator);
    var c: Chain = .{};
    const chain = try c.of(&.{ @embedFile("testdata/forged.pem"), @embedFile("testdata/leaf.pem"), @embedFile("testdata/inter.pem") });
    // std's own per-link check accepts every link -- the hole this closes.
    for (chain[0 .. chain.len - 1], chain[1..]) |sub, iss| {
        const s = try (Certificate{ .buffer = sub, .index = 0 }).parse();
        const i = try (Certificate{ .buffer = iss, .index = 0 }).parse();
        try s.verify(i, now);
    }
    try testing.expectError(error.TlsCertificateNotVerified, verifyAgainstBundle(chain, &bundle, now));
}

test "a leaf restricted to clientAuth is no server" {
    var bundle = try rootBundle(testing.allocator);
    defer bundle.deinit(testing.allocator);
    var c: Chain = .{};
    const chain = try c.of(&.{ @embedFile("testdata/leaf-client.pem"), @embedFile("testdata/inter.pem") });
    try testing.expectError(error.TlsCertificateNotVerified, verifyAgainstBundle(chain, &bundle, now));
}

test "a chain to a root the bundle does not hold is refused" {
    var bundle: Certificate.Bundle = .empty;
    defer bundle.deinit(testing.allocator);
    var c: Chain = .{};
    const chain = try c.of(&.{ @embedFile("testdata/leaf.pem"), @embedFile("testdata/inter.pem") });
    try testing.expectError(error.TlsCertificateNotVerified, verifyAgainstBundle(chain, &bundle, now));
}

test "malformed DER never reaches std's parser" {
    const cases = [_][]const u8{ "", "\x30", "\x30\x84\xff\xff\xff\xff", "\x30\x03\x30\x01", "not a certificate" };
    for (cases) |d| try testing.expectError(error.TlsCertificateNotVerified, checkWellFormed(d));
}

// ── fuzz: a server's Certificate message is attacker bytes ──────────────────

/// Split `input` into certificates the way a fuzzer can steer: each one is a
/// 2-byte big-endian length and that many bytes.
fn splitChain(input: []const u8, out: *[max_chain_len][]const u8) usize {
    var i: usize = 0;
    var n: usize = 0;
    while (n < max_chain_len and i + 2 <= input.len) {
        const len = std.mem.readInt(u16, input[i..][0..2], .big);
        i += 2;
        const end = @min(input.len, i + len);
        out[n] = input[i..end];
        n += 1;
        i = end;
    }
    return n;
}

fn fuzzChain(bundle: *Certificate.Bundle, smith: *std.testing.Smith) anyerror!void {
    var buf: [4 * 4096]u8 = undefined;
    const input = buf[0..smith.slice(&buf)];
    var chain: [max_chain_len][]const u8 = undefined;
    const n = splitChain(input, &chain);
    for (chain[0..n]) |der| checkWellFormed(der) catch return;
    verifyAgainstBundle(chain[0..n], bundle, now) catch {};
}

/// A corpus seed for `fuzzChain`: the chain frame (2-byte length + DER per
/// certificate) wrapped by `testkit.fuzz.seedInto`, because `Smith.slice`
/// reads a 4-byte little-endian length first. A raw frame would lose its
/// first four bytes to that length and never reach the verifier.
fn seed(gpa: std.mem.Allocator, pems: []const []const u8) ![]u8 {
    var frame: std.ArrayList(u8) = .empty;
    defer frame.deinit(gpa);
    var der_buf: [4096]u8 = undefined;
    for (pems) |p| {
        const der = try pemToDer(p, &der_buf);
        var len: [2]u8 = undefined;
        std.mem.writeInt(u16, &len, @intCast(der.len), .big);
        try frame.appendSlice(gpa, &len);
        try frame.appendSlice(gpa, der);
    }
    const out = try gpa.alloc(u8, 4 + frame.items.len);
    return @constCast(testkit.fuzz.seedInto(out, frame.items));
}

test "fuzz: arbitrary chains through the guard and the verifier never panic" {
    const gpa = testing.allocator;
    var bundle = try rootBundle(gpa);
    defer bundle.deinit(gpa);
    const honest = try seed(gpa, &.{ @embedFile("testdata/leaf.pem"), @embedFile("testdata/inter.pem") });
    defer gpa.free(honest);
    const forged = try seed(gpa, &.{ @embedFile("testdata/forged.pem"), @embedFile("testdata/leaf.pem"), @embedFile("testdata/inter.pem") });
    defer gpa.free(forged);
    try testing.fuzz(&bundle, fuzzChain, .{ .corpus = &.{ honest, forged } });
}

/// Reads a corpus seed back exactly as `fuzzChain` does, through `Smith`.
fn chainFromSeed(entry: []const u8, buf: *[4 * 4096]u8, chain: *[max_chain_len][]const u8) usize {
    var smith: std.testing.Smith = .{ .in = entry };
    return splitChain(buf[0..smith.slice(buf)], chain);
}

test "corpus: the seeds reach the verifier through Smith -- honest verifies, forged is refused" {
    const gpa = testing.allocator;
    var bundle = try rootBundle(gpa);
    defer bundle.deinit(gpa);
    var buf: [4 * 4096]u8 = undefined;
    var chain: [max_chain_len][]const u8 = undefined;

    const honest = try seed(gpa, &.{ @embedFile("testdata/leaf.pem"), @embedFile("testdata/inter.pem") });
    defer gpa.free(honest);
    const n = chainFromSeed(honest, &buf, &chain);
    try testing.expectEqual(@as(usize, 2), n);
    for (chain[0..n]) |der| try checkWellFormed(der);
    try verifyAgainstBundle(chain[0..n], &bundle, now);

    const forged = try seed(gpa, &.{ @embedFile("testdata/forged.pem"), @embedFile("testdata/leaf.pem"), @embedFile("testdata/inter.pem") });
    defer gpa.free(forged);
    const m = chainFromSeed(forged, &buf, &chain);
    try testing.expectEqual(@as(usize, 3), m);
    for (chain[0..m]) |der| try checkWellFormed(der);
    try testing.expectError(error.TlsCertificateNotVerified, verifyAgainstBundle(chain[0..m], &bundle, now));
}
