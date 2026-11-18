// SPDX-License-Identifier: MIT

//! ctgrind_harness — the constant-time evidence for `SPEC.md`'s Hardening line.
//! Run it through `../../../scripts/checks/ctgrind.sh isis`, which builds
//! every mode/taint combination and prints the control table.
//!
//! Not wired into `zig build test-isis`: memcheck's context count is
//! valgrind's own output. `zig build check-ctgrind` only compiles it.
//!
//! ## What this measures
//!
//! The module's only secret is the authentication key (`auth.Key.secret`):
//!
//!  * `md5` — an RFC 5304 HMAC-MD5 key, tainted, through `auth.sign` of a
//!    P2P IIH and `auth.verify` of that PDU and of a copy with one Area
//!    Addresses octet flipped (refused on the digest compare, not on parsing).
//!  * `sha256` — the same for an RFC 5310 HMAC-SHA-256 key, both key
//!    preparations: a 40-octet key (L < |K| <= B) plain, and strict, where
//!    the key is first hashed (`Ko = H(K)`).
//!  * `clear` — a cleartext password, tainted, through `auth.verify`'s
//!    compare against a PDU carrying the same password and a wrong one of the
//!    same length. The PDU's own copy of the password is public (it is on
//!    the wire); only the configured key is the secret.
//!
//! A P2P IIH, not an LSP: an LSP's ISO 8473 checksum is computed over the
//! (secret-derived, then public) digest, and its zero normalisation is a
//! branch on it that says nothing about the key.
//!
//! ## The propagation witness
//!
//! Every result is printed as `ctgrind_result={x}` over its bytes; the hex
//! formatter is not constant-time, so the total is non-zero while the in-file
//! count is zero.

const std = @import("std");
const builtin = @import("builtin");
const isis = @import("root.zig");
const auth = isis.auth;

const Target = enum { md5, sha256, clear };
const Taint = enum { yes, no };

/// A runtime (not comptime-foldable) stand-in for a secret.
fn secretBytes(comptime n: usize, label: []const u8) [n]u8 {
    var full: [64]u8 = undefined;
    std.crypto.hash.sha2.Sha512.hash(label, &full, .{});
    return full[0..n].*;
}

fn reloadVolatile(comptime n: usize, src: *const [n]u8) [n]u8 {
    var out: [n]u8 = undefined;
    for (&out, src) |*o, *b| {
        const vb: *const volatile u8 = b;
        o.* = vb.*;
    }
    return out;
}

const sys = [6]u8{ 0x19, 0x21, 0x68, 0x00, 0x00, 0xff };
const area = [_]u8{ 0x49, 0x00, 0x01 };

/// Builds a P2P IIH with `key`'s Authentication TLV first and an Area
/// Addresses TLV after it; returns its length.
fn buildHello(buf: []u8, key: auth.Key) !usize {
    var b = try isis.pdu.P2pHelloBuilder.init(buf, .{ .source_id = sys, .holding_time = 30 });
    try auth.addPlaceholder(&b.tlvs, key);
    try isis.tlvs.addAreaAddresses(&b.tlvs, &.{&area});
    return b.finish().len;
}

/// sign + verify good + verify tampered; prints the digest and both verdicts.
fn macRound(key: auth.Key) !void {
    var buf: [256]u8 = undefined;
    const n = try buildHello(&buf, key);
    try auth.sign(buf[0..n], key);
    const ok_good = if (auth.verify(buf[0..n], &.{key})) |_| true else |_| false;
    var tampered: [256]u8 = undefined;
    @memcpy(tampered[0..n], buf[0..n]);
    tampered[n - 1] ^= 0x01; // the last area-address octet
    const ok_bad = if (auth.verify(tampered[0..n], &.{key})) |_| true else |_| false;

    const l = key.algorithm.digestLen();
    const off: usize = isis.pdu.p2p_iih_fixed_len + 2 + (if (key.algorithm == .hmac_md5) @as(usize, 1) else 3);
    var res: [auth.max_digest_len + 2]u8 = @splat(0);
    @memcpy(res[0..l], buf[off..][0..l]);
    res[l] = @intFromBool(ok_good);
    res[l + 1] = @intFromBool(ok_bad);
    std.debug.print("ctgrind_result={x}\n", .{res[0 .. l + 2]});
}

pub fn main(init: std.process.Init.Minimal) !void {
    var it = init.args.iterate();
    _ = it.next(); // argv[0]
    const target = std.meta.stringToEnum(Target, it.next() orelse return error.MissingTarget) orelse
        return error.UnknownTarget;
    const taint = std.meta.stringToEnum(Taint, it.next() orelse return error.MissingTaint) orelse
        return error.UnknownTaint;

    std.debug.print("valgrind_support={} target={t}\n", .{ builtin.valgrind_support, target });

    switch (target) {
        .md5 => {
            var raw = secretBytes(16, "ctgrind-isis-md5-key-v1");
            if (taint == .yes) std.valgrind.memcheck.makeMemUndefined(&raw);
            const key = reloadVolatile(16, &raw);
            try macRound(.{ .algorithm = .hmac_md5, .secret = &key });
        },
        .sha256 => {
            var raw = secretBytes(40, "ctgrind-isis-sha256-key-v1");
            if (taint == .yes) std.valgrind.memcheck.makeMemUndefined(&raw);
            const key = reloadVolatile(40, &raw);
            try macRound(.{ .algorithm = .hmac_sha256, .id = 7, .secret = &key });
            try macRound(.{ .algorithm = .hmac_sha256, .id = 7, .secret = &key, .strict_rfc5310 = true });
        },
        .clear => {
            var raw = secretBytes(12, "ctgrind-isis-clear-pw-v1");
            if (taint == .yes) std.valgrind.memcheck.makeMemUndefined(&raw);
            const pw = reloadVolatile(12, &raw);
            // The PDUs carry public copies: the same password, and another.
            const public_same = secretBytes(12, "ctgrind-isis-clear-pw-v1");
            var public_other = public_same;
            public_other[11] ^= 0x01;
            var buf: [256]u8 = undefined;
            const n1 = try buildHello(&buf, .{ .algorithm = .cleartext, .secret = &public_same });
            const ok_good = if (auth.verify(buf[0..n1], &.{.{ .algorithm = .cleartext, .secret = &pw }})) |_| true else |_| false;
            const n2 = try buildHello(&buf, .{ .algorithm = .cleartext, .secret = &public_other });
            const ok_bad = if (auth.verify(buf[0..n2], &.{.{ .algorithm = .cleartext, .secret = &pw }})) |_| true else |_| false;
            std.debug.print("ctgrind_result={x}\n", .{[2]u8{ @intFromBool(ok_good), @intFromBool(ok_bad) }});
        },
    }
}
