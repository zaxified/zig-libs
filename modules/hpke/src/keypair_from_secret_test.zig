// SPDX-License-Identifier: MIT
//! `keyPairFromSecret` for the four DHKEMs: every published private key
//! (RFC 9180 Appendix A's `skEm`/`skRm`/`skSm`, the Go vector set's `skRm`,
//! which is the only external anchor P-384 has) rebuilds its published
//! public key; every key `deriveKeyPair` produces round-trips; the NIST
//! curves refuse a scalar outside `[1, n-1]` and accept both ends of it.

const std = @import("std");
const testing = std.testing;
const dhkem = @import("dhkem.zig");
const rfc = @import("kat_rfc9180.zig");
const rfc_a6 = @import("kat_rfc9180_a6.zig");
const go = @import("testdata/go_vectors.zig");

fn KemOf(comptime id: u16) type {
    return switch (id) {
        0x0010 => dhkem.P256Kem,
        0x0011 => dhkem.P384Kem,
        0x0012 => dhkem.P521Kem,
        0x0020 => dhkem.X25519Kem,
        else => @compileError("not a DHKEM"),
    };
}

fn expectRebuilds(comptime K: type, sk: *const [K.Nsk]u8, pk: *const [K.Npk]u8) !void {
    var kp: K.KeyPair = undefined;
    try K.keyPairFromSecret(&kp, sk);
    try testing.expectEqualSlices(u8, sk, &kp.secret_key);
    try testing.expectEqualSlices(u8, pk, &kp.public_key);
}

test "keyPairFromSecret: every RFC 9180 Appendix A private key rebuilds its public key" {
    var checked: usize = 0;
    inline for (.{
        rfc.a1,          rfc.a2,             rfc.a3,      rfc.a4,          rfc.a1_psk, rfc.a1_auth,
        rfc.a1_auth_psk, rfc.a3_psk,         rfc.a3_auth, rfc.a3_auth_psk, rfc_a6.a6,  rfc_a6.a6_psk,
        rfc_a6.a6_auth,  rfc_a6.a6_auth_psk,
    }) |V| {
        const K = KemOf(V.kem_id);
        inline for (.{ .{ "skEm", "pkEm" }, .{ "skRm", "pkRm" }, .{ "skSm", "pkSm" } }) |names| {
            if (@hasDecl(V, names[0])) {
                try expectRebuilds(K, &@field(V, names[0]), &@field(V, names[1]));
                checked += 1;
            }
        }
    }
    // 14 vector sets, each with E and R keys, the six auth-mode sets with S too.
    try testing.expectEqual(@as(usize, 34), checked);
}

test "keyPairFromSecret: every Go vector's skRm rebuilds pkRm, P-384 included" {
    var per_kem: [4]usize = @splat(0);
    for (go.vectors) |v| {
        inline for (.{ 0x0010, 0x0011, 0x0012, 0x0020 }, 0..) |id, i| {
            if (v.kem_id == id and v.skRm.len != 0) {
                const K = KemOf(id);
                var sk: [K.Nsk]u8 = undefined;
                var pk: [K.Npk]u8 = undefined;
                try testing.expectEqual(@as(usize, K.Nsk), (try std.fmt.hexToBytes(&sk, v.skRm)).len);
                try testing.expectEqual(@as(usize, K.Npk), (try std.fmt.hexToBytes(&pk, v.pkRm)).len);
                try expectRebuilds(K, &sk, &pk);
                per_kem[i] += 1;
            }
        }
    }
    for (per_kem) |n| try testing.expect(n >= 1);
}

test "keyPairFromSecret: equals deriveKeyPair's own output for every DHKEM" {
    inline for (.{ dhkem.X25519Kem, dhkem.P256Kem, dhkem.P384Kem, dhkem.P521Kem }) |K| {
        for (0..32) |i| {
            const ikm: [K.Nsk]u8 = @splat(@intCast(i));
            var derived: K.KeyPair = undefined;
            K.deriveKeyPair(&derived, &ikm);
            try expectRebuilds(K, &derived.secret_key, &derived.public_key);
        }
    }
}

fn hexTo(comptime n: usize, comptime s: []const u8) [n]u8 {
    var out: [n]u8 = undefined;
    _ = std.fmt.hexToBytes(&out, s) catch unreachable;
    return out;
}

test "keyPairFromSecret: the NIST curves refuse 0, n and all-ones, and accept 1 and n-1" {
    inline for (.{
        .{ dhkem.P256Kem, "ffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc632551" },
        .{ dhkem.P384Kem, "ffffffffffffffffffffffffffffffffffffffffffffffffc7634d81f4372ddf581a0db248b0a77aecec196accc52973" },
        .{ dhkem.P521Kem, "01fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffa51868783bf2f966b7fcc0148f709a5d03bb5c9b8899c47aebb6fb71e91386409" },
    }) |c| {
        const K = c[0];
        const n = comptime hexTo(K.Nsk, c[1]);
        var kp: K.KeyPair = undefined;
        const zero: [K.Nsk]u8 = @splat(0);
        const ones: [K.Nsk]u8 = @splat(0xff);
        var n_plus_1 = n;
        n_plus_1[K.Nsk - 1] +%= 1; // n ends in an odd byte below 0xff on all three curves
        for ([_][K.Nsk]u8{ zero, n, n_plus_1, ones }) |bad| {
            try testing.expectError(error.DeserializeError, K.keyPairFromSecret(&kp, &bad));
        }
        var n_minus_1 = n;
        n_minus_1[K.Nsk - 1] -= 1;
        var one = zero;
        one[K.Nsk - 1] = 1;
        for ([_][K.Nsk]u8{ one, n_minus_1 }) |good| {
            try K.keyPairFromSecret(&kp, &good);
            try testing.expectEqualSlices(u8, &good, &kp.secret_key);
            try testing.expectEqual(@as(u8, 0x04), kp.public_key[0]);
        }
    }
}

test "keyPairFromSecret: X25519 accepts every 32-byte string, as RFC 7748 clamping makes it a key" {
    const K = dhkem.X25519Kem;
    var kp: K.KeyPair = undefined;
    for ([_][K.Nsk]u8{ @splat(0), @splat(0xff), @splat(0x42) }) |sk| {
        try K.keyPairFromSecret(&kp, &sk);
        try testing.expectEqualSlices(u8, &sk, &kp.secret_key);
        const want = std.crypto.dh.X25519.recoverPublicKey(sk);
        try testing.expectEqualSlices(u8, &want, &kp.public_key);
    }
}
