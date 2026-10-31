// SPDX-License-Identifier: MIT

//! Boundary and negative tests for `kex.zig`'s NIST hybrids and `Expanded`,
//! added by the 2026-10-31 delta mutation audit: each pins a behaviour that a
//! mutant of the new code survived without (secret/share length edges, `exp`
//! reset on every path, an `exp` that is not the key pair's own, fresh
//! encapsulation randomness).

const std = @import("std");
const testing = std.testing;
const kex = @import("kex.zig");

const nist_hybrids = [_]u16{ kex.secp256r1_mlkem768_group, kex.secp384r1_mlkem1024_group };
const kem_groups = [_]u16{ kex.x25519_mlkem768_group, kex.secp256r1_mlkem768_group, kex.mlkem1024_group, kex.secp384r1_mlkem1024_group };

test "scalarLen: exact prefix per group" {
    try testing.expectEqual(@as(usize, 32), kex.scalarLen(kex.x25519_group));
    try testing.expectEqual(@as(usize, 32), kex.scalarLen(kex.secp256r1_group));
    try testing.expectEqual(@as(usize, 48), kex.scalarLen(kex.secp384r1_group));
    try testing.expectEqual(@as(usize, 96), kex.scalarLen(kex.x25519_mlkem768_group));
    try testing.expectEqual(@as(usize, 96), kex.scalarLen(kex.secp256r1_mlkem768_group));
    try testing.expectEqual(@as(usize, 64), kex.scalarLen(kex.mlkem1024_group));
    try testing.expectEqual(@as(usize, 112), kex.scalarLen(kex.secp384r1_mlkem1024_group));
    try testing.expectEqual(@as(usize, 0), kex.scalarLen(0x0abc));
    try testing.expectEqual(@as(usize, 112), kex.secret_len);
}

test "NIST hybrids: a share one octet too long is refused, on both sides" {
    var prng = std.Random.DefaultPrng.init(0x4101);
    const rnd = prng.random();
    for (nist_hybrids) |g| {
        var kp: kex.KeyPair = undefined;
        try kex.generate(g, rnd, &kp);
        var ex: kex.ServerExchange = undefined;
        try kex.serverExchange(g, kp.public[0..kp.public_len], rnd, &ex);
        var long_client: [kex.max_share_len + 1]u8 = undefined;
        @memcpy(long_client[0..kp.public_len], kp.public[0..kp.public_len]);
        long_client[kp.public_len] = 0;
        var scratch: kex.ServerExchange = undefined;
        try testing.expectError(error.MissingKeyShare, kex.serverExchange(g, long_client[0 .. kp.public_len + 1], rnd, &scratch));
        var long_server: [kex.max_share_len + 1]u8 = undefined;
        @memcpy(long_server[0..ex.public_len], ex.public[0..ex.public_len]);
        long_server[ex.public_len] = 0;
        var ss: kex.SharedSecret = undefined;
        try testing.expectError(error.MissingKeyShare, kex.sharedSecret(g, kp.secret[0..kex.scalarLen(g)], long_server[0 .. ex.public_len + 1], &ss));
        // And the exact lengths still work.
        try kex.sharedSecret(g, kp.secret[0..kex.scalarLen(g)], ex.public[0..ex.public_len], &ss);
    }
}

test "NIST hybrids: the server's encapsulation is fresh per exchange" {
    var prng = std.Random.DefaultPrng.init(0x4102);
    const rnd = prng.random();
    for (nist_hybrids) |g| {
        var kp: kex.KeyPair = undefined;
        try kex.generate(g, rnd, &kp);
        var a: kex.ServerExchange = undefined;
        var b: kex.ServerExchange = undefined;
        try kex.serverExchange(g, kp.public[0..kp.public_len], rnd, &a);
        try kex.serverExchange(g, kp.public[0..kp.public_len], rnd, &b);
        const point_len: usize = if (g == kex.secp256r1_mlkem768_group) 65 else 97;
        // Different ephemeral point AND different ML-KEM ciphertext / secret.
        try testing.expect(!std.mem.eql(u8, a.public[0..point_len], b.public[0..point_len]));
        try testing.expect(!std.mem.eql(u8, a.public[point_len..a.public_len], b.public[point_len..b.public_len]));
        try testing.expect(!std.mem.eql(u8, a.shared.slice(), b.shared.slice()));
        // The ML-KEM half of the secret differs although the client key is the same.
        const ec_len = point_len / 2; // 32 or 48 (coordinate length)
        try testing.expect(!std.mem.eql(u8, a.shared.slice()[ec_len..], b.shared.slice()[ec_len..]));
    }
}

test "NIST hybrids: secret one byte short is KeyExchangeFailed, the whole scalarLen works" {
    var prng = std.Random.DefaultPrng.init(0x4103);
    const rnd = prng.random();
    for (nist_hybrids ++ [_]u16{kex.x25519_mlkem768_group}) |g| {
        var kp: kex.KeyPair = undefined;
        try kex.generate(g, rnd, &kp);
        var ex: kex.ServerExchange = undefined;
        try kex.serverExchange(g, kp.public[0..kp.public_len], rnd, &ex);
        var ss: kex.SharedSecret = undefined;
        const n = kex.scalarLen(g);
        try kex.sharedSecret(g, kp.secret[0..n], ex.public[0..ex.public_len], &ss);
        try testing.expectError(error.KeyExchangeFailed, kex.sharedSecret(g, kp.secret[0 .. n - 1], ex.public[0..ex.public_len], &ss));
        try testing.expectEqual(@as(usize, 0), ss.len);
        try testing.expect(std.mem.allEqual(u8, &ss.bytes, 0));
    }
}

test "Expanded: exp is reset on every path of generateExpanded and expand" {
    var prng = std.Random.DefaultPrng.init(0x4104);
    const rnd = prng.random();
    // A live expanded key to be overwritten by the calls below.
    var live: kex.KeyPair = undefined;
    var exp: kex.Expanded = .none;
    defer exp.wipe();
    try kex.generateExpanded(kex.mlkem1024_group, rnd, &live, &exp);
    try testing.expect(exp != .none);
    // Classical group: generateExpanded yields .none.
    var kp: kex.KeyPair = undefined;
    try kex.generateExpanded(kex.x25519_group, rnd, &kp, &exp);
    try testing.expect(exp == .none);
    // expand of a classical group yields .none.
    try kex.generateExpanded(kex.mlkem1024_group, rnd, &live, &exp);
    try testing.expect(exp != .none);
    try kex.expand(kex.secp256r1_group, kp.secret[0..32], &exp);
    try testing.expect(exp == .none);
    // An unknown group is refused and leaves .none.
    try kex.generateExpanded(kex.mlkem1024_group, rnd, &live, &exp);
    try testing.expectError(error.MissingKeyShare, kex.expand(0x0abc, kp.secret[0..32], &exp));
    try testing.expect(exp == .none);
    // A failing generateExpanded (unknown group) leaves .none.
    try kex.generateExpanded(kex.mlkem1024_group, rnd, &live, &exp);
    try testing.expectError(error.MissingKeyShare, kex.generateExpanded(0x0abc, rnd, &kp, &exp));
    try testing.expect(exp == .none);
    // A failing expand (short seed) leaves .none.
    try kex.generateExpanded(kex.mlkem1024_group, rnd, &live, &exp);
    try testing.expectError(error.KeyExchangeFailed, kex.expand(kex.mlkem1024_group, live.secret[0..10], &exp));
    try testing.expect(exp == .none);
}

test "expand: the seed length is the exact boundary, per KEM size" {
    var prng = std.Random.DefaultPrng.init(0x4105);
    const rnd = prng.random();
    for (kem_groups) |g| {
        var kp: kex.KeyPair = undefined;
        try kex.generate(g, rnd, &kp);
        var exp: kex.Expanded = .none;
        defer exp.wipe();
        // ML-KEM seeds are 64 bytes for both sizes; the curve scalar is not needed to expand.
        try kex.expand(g, kp.secret[0..64], &exp);
        try testing.expect(exp != .none);
        exp.wipe();
        try testing.expectError(error.KeyExchangeFailed, kex.expand(g, kp.secret[0..63], &exp));
        try testing.expect(exp == .none);
    }
}

test "expand: each group yields its own KEM size" {
    var prng = std.Random.DefaultPrng.init(0x4106);
    const rnd = prng.random();
    for (kem_groups) |g| {
        var kp: kex.KeyPair = undefined;
        var exp: kex.Expanded = .none;
        defer exp.wipe();
        try kex.generateExpanded(g, rnd, &kp, &exp);
        var again: kex.Expanded = .none;
        defer again.wipe();
        try kex.expand(g, kp.secret[0..kex.scalarLen(g)], &again);
        const big = (g == kex.mlkem1024_group or g == kex.secp384r1_mlkem1024_group);
        try testing.expect(if (big) exp == .mlkem1024 else exp == .mlkem768);
        try testing.expect(if (big) again == .mlkem1024 else again == .mlkem768);
    }
}

test "sharedSecretExpanded: .none falls back to the seed; a foreign exp is used as given (garbage secret, no error)" {
    var prng = std.Random.DefaultPrng.init(0x4107);
    const rnd = prng.random();
    for (kem_groups) |g| {
        var kp: kex.KeyPair = undefined;
        try kex.generate(g, rnd, &kp);
        var other: kex.KeyPair = undefined;
        var other_exp: kex.Expanded = .none;
        defer other_exp.wipe();
        try kex.generateExpanded(g, rnd, &other, &other_exp);
        var ex: kex.ServerExchange = undefined;
        try kex.serverExchange(g, kp.public[0..kp.public_len], rnd, &ex);
        const secret = kp.secret[0..kex.scalarLen(g)];
        var via_seed: kex.SharedSecret = undefined;
        try kex.sharedSecret(g, secret, ex.public[0..ex.public_len], &via_seed);
        // exp == .none: identical to the seed path.
        var none: kex.Expanded = .none;
        var got: kex.SharedSecret = undefined;
        try kex.sharedSecretExpanded(g, secret, &none, ex.public[0..ex.public_len], &got);
        try testing.expectEqualSlices(u8, via_seed.slice(), got.slice());
        // Another key pair's exp: decapsulation uses IT (implicit rejection), so the secret differs.
        try kex.sharedSecretExpanded(g, secret, &other_exp, ex.public[0..ex.public_len], &got);
        try testing.expectEqual(via_seed.len, got.len);
        try testing.expect(!std.mem.eql(u8, via_seed.slice(), got.slice()));
        // The caller's exp is not consumed.
        try testing.expect(other_exp != .none);
        // The matching exp reproduces the seed path.
        var own: kex.Expanded = .none;
        defer own.wipe();
        try kex.expand(g, secret, &own);
        try kex.sharedSecretExpanded(g, secret, &own, ex.public[0..ex.public_len], &got);
        try testing.expectEqualSlices(u8, via_seed.slice(), got.slice());
    }
}

test "sharedSecretExpanded: an exp of the other KEM size is KeyExchangeFailed for every ML-KEM group" {
    var prng = std.Random.DefaultPrng.init(0x4108);
    const rnd = prng.random();
    var e768: kex.Expanded = .none;
    var e1024: kex.Expanded = .none;
    defer e768.wipe();
    defer e1024.wipe();
    var tmp: kex.KeyPair = undefined;
    try kex.generateExpanded(kex.x25519_mlkem768_group, rnd, &tmp, &e768);
    try kex.generateExpanded(kex.mlkem1024_group, rnd, &tmp, &e1024);
    for (kem_groups) |g| {
        var kp: kex.KeyPair = undefined;
        try kex.generate(g, rnd, &kp);
        var ex: kex.ServerExchange = undefined;
        try kex.serverExchange(g, kp.public[0..kp.public_len], rnd, &ex);
        const big = (g == kex.mlkem1024_group or g == kex.secp384r1_mlkem1024_group);
        var ss: kex.SharedSecret = undefined;
        try testing.expectError(error.KeyExchangeFailed, kex.sharedSecretExpanded(g, kp.secret[0..kex.scalarLen(g)], if (big) &e768 else &e1024, ex.public[0..ex.public_len], &ss));
        try testing.expectEqual(@as(usize, 0), ss.len);
    }
}
