// SPDX-License-Identifier: MIT
//! `h2c.zig` against RFC 9380: Appendix J.1.1 / J.2.1 / J.3.1 (every
//! published intermediate of `P{256,384,521}_XMD:SHA-*_SSWU_RO_`) and
//! Appendix K.1 / K.3 (`expand_message_xmd` over SHA-256 and SHA-512, both
//! published lengths, i.e. `ell = 1` and the multi-block loop).

const std = @import("std");
const voprf = @import("root.zig");
const h2c = voprf.h2c;
const groups = voprf.groups;
const vec = @import("h2c_vectors.zig");

const testing = std.testing;

fn expectHex(expected: []const u8, actual: []const u8) !void {
    var buf: [256]u8 = undefined;
    const want = try std.fmt.hexToBytes(buf[0 .. expected.len / 2], expected);
    try testing.expectEqualSlices(u8, want, actual);
}

fn runSuite(comptime B: type, comptime suite: vec.H2cSuite) !void {
    const H = B.hash_to_curve;
    try testing.expectEqual(@as(usize, 5), suite.vectors.len);
    for (suite.vectors) |v| {
        const u = H.hashToField(2, &.{v.msg}, suite.dst);
        try expectHex(v.u0, &u[0].toBytes(.big));
        try expectHex(v.u1, &u[1].toBytes(.big));
        const q0 = H.mapToCurve(u[0]);
        const q1 = H.mapToCurve(u[1]);
        try expectHex(v.q0x, &q0.x.toBytes(.big));
        try expectHex(v.q0y, &q0.y.toBytes(.big));
        try expectHex(v.q1x, &q1.x.toBytes(.big));
        try expectHex(v.q1y, &q1.y.toBytes(.big));
        const p = H.hashToCurve(&.{v.msg}, suite.dst).affineCoordinates();
        try expectHex(v.px, &p.x.toBytes(.big));
        try expectHex(v.py, &p.y.toBytes(.big));
        // The message given as parts hashes like the concatenation.
        const half = v.msg.len / 2;
        const p2 = H.hashToCurve(&.{ v.msg[0..half], v.msg[half..] }, suite.dst).affineCoordinates();
        try expectHex(v.px, &p2.x.toBytes(.big));
    }
}

test "RFC 9380 J.1.1 P256_XMD:SHA-256_SSWU_RO_ (u, Q0, Q1, P for all 5 messages)" {
    try runSuite(groups.P256Sha256, vec.p256);
}

test "RFC 9380 J.2.1 P384_XMD:SHA-384_SSWU_RO_ (u, Q0, Q1, P for all 5 messages)" {
    try runSuite(groups.P384Sha384, vec.p384);
}

test "RFC 9380 J.3.1 P521_XMD:SHA-512_SSWU_RO_ (u, Q0, Q1, P for all 5 messages)" {
    try runSuite(groups.P521Sha512, vec.p521);
}

fn runXmd(comptime Hash: type, comptime suite: vec.XmdSuite) !void {
    try testing.expectEqual(@as(usize, 10), suite.vectors.len);
    inline for (suite.vectors) |v| {
        const out = h2c.expandMessageXmd(Hash, v.len_in_bytes, &.{v.msg}, suite.dst);
        try expectHex(v.uniform_bytes, &out);
    }
}

test "RFC 9380 K.1 expand_message_xmd(SHA-256), len 0x20 and 0x80" {
    try runXmd(std.crypto.hash.sha2.Sha256, vec.xmd_sha256);
}

test "RFC 9380 K.3 expand_message_xmd(SHA-512), len 0x20 and 0x80; agrees with the ell = 1 top-level expander" {
    try runXmd(std.crypto.hash.sha2.Sha512, vec.xmd_sha512);
    const a = h2c.expandMessageXmd(std.crypto.hash.sha2.Sha512, 64, &.{ "ab", "c" }, "DST");
    const b = voprf.expandMessageXmd(64, &.{"abc"}, "DST");
    try testing.expectEqualSlices(u8, &b, &a);
}

test "SSWU constants: c2^2 == -Z for every NIST suite (Appendix F.2.1.2)" {
    inline for (.{ groups.P256Sha256, groups.P384Sha384, groups.P521Sha512 }) |B| {
        const H = B.hash_to_curve;
        try testing.expect(H.c2.sq().equivalent(H.Z.neg()));
    }
}

test "mapToCurve lands on the curve for u = 0 (the exceptional tv2 == 0 case)" {
    inline for (.{ groups.P256Sha256, groups.P384Sha384, groups.P521Sha512 }) |B| {
        const H = B.hash_to_curve;
        const q = H.mapToCurve(H.Fe.zero);
        // y^2 == x^3 - 3x + B
        const rhs = q.x.sq().mul(q.x).sub(q.x.dbl().add(q.x)).add(B.Point.B);
        try testing.expect(q.y.sq().equivalent(rhs));
    }
}
