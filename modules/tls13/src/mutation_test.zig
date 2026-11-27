// SPDX-License-Identifier: MIT

//! Boundary and negative tests for `kex.zig`'s NIST hybrids and `Expanded`,
//! added by the 2026-10-31 delta mutation audit: each pins a behaviour that a
//! mutant of the new code survived without (secret/share length edges, `exp`
//! reset on every path, an `exp` that is not the key pair's own, fresh
//! encapsulation randomness). The 2026-11-01 delta audit (secp521r1, ML-KEM-512/768,
//! `Ed25519Signer`, P-384) added the tests at the end of the file.

const std = @import("std");
const testing = std.testing;
const rsa = @import("rsa");
const kex = @import("kex.zig");
const certverify = @import("certverify.zig");
const kat = @import("certverify_kat_vectors.zig");

const nist_hybrids = [_]u16{ kex.secp256r1_mlkem768_group, kex.secp384r1_mlkem1024_group };
const kem_groups = [_]u16{ kex.x25519_mlkem768_group, kex.secp256r1_mlkem768_group, kex.mlkem1024_group, kex.mlkem512_group, kex.mlkem768_group, kex.secp384r1_mlkem1024_group };

test "scalarLen: exact prefix per group" {
    try testing.expectEqual(@as(usize, 32), kex.scalarLen(kex.x25519_group));
    try testing.expectEqual(@as(usize, 32), kex.scalarLen(kex.secp256r1_group));
    try testing.expectEqual(@as(usize, 48), kex.scalarLen(kex.secp384r1_group));
    try testing.expectEqual(@as(usize, 66), kex.scalarLen(kex.secp521r1_group));
    try testing.expectEqual(@as(usize, 64), kex.scalarLen(kex.mlkem512_group));
    try testing.expectEqual(@as(usize, 64), kex.scalarLen(kex.mlkem768_group));
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
        if (g == kex.mlkem512_group) {
            try testing.expect(exp == .mlkem512 and again == .mlkem512);
            continue;
        }
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

test "expand: every curve group, P-521 included, yields .none from a live key" {
    var prng = std.Random.DefaultPrng.init(0x4109);
    const rnd = prng.random();
    var live: kex.KeyPair = undefined;
    var exp: kex.Expanded = .none;
    defer exp.wipe();
    for ([_]u16{ kex.x25519_group, kex.secp256r1_group, kex.secp384r1_group, kex.secp521r1_group }) |g| {
        try kex.generateExpanded(kex.mlkem768_group, rnd, &live, &exp);
        try testing.expect(exp != .none);
        try kex.expand(g, live.secret[0..kex.scalarLen(g)], &exp);
        try testing.expect(exp == .none);
    }
}

test "sharedSecretExpanded: an ML-KEM-512 exp is refused by every other KEM size" {
    var prng = std.Random.DefaultPrng.init(0x410a);
    const rnd = prng.random();
    var e512: kex.Expanded = .none;
    defer e512.wipe();
    var tmp: kex.KeyPair = undefined;
    try kex.generateExpanded(kex.mlkem512_group, rnd, &tmp, &e512);
    try testing.expect(e512 == .mlkem512);
    for (kem_groups) |g| {
        if (g == kex.mlkem512_group) continue;
        var kp: kex.KeyPair = undefined;
        try kex.generate(g, rnd, &kp);
        var ex: kex.ServerExchange = undefined;
        try kex.serverExchange(g, kp.public[0..kp.public_len], rnd, &ex);
        var ss: kex.SharedSecret = undefined;
        try testing.expectError(error.KeyExchangeFailed, kex.sharedSecretExpanded(g, kp.secret[0..kex.scalarLen(g)], &e512, ex.public[0..ex.public_len], &ss));
    }
}

test "Expanded.wipe zeroes the whole union, not only the tag" {
    var prng = std.Random.DefaultPrng.init(0x410b);
    const rnd = prng.random();
    var kp: kex.KeyPair = undefined;
    for ([_]u16{ kex.mlkem512_group, kex.mlkem768_group, kex.mlkem1024_group }) |g| {
        var exp: kex.Expanded = .none;
        try kex.generateExpanded(g, rnd, &kp, &exp);
        try testing.expect(!std.mem.allEqual(u8, std.mem.asBytes(&exp), 0));
        exp.wipe();
        try testing.expect(exp == .none);
        try testing.expect(std.mem.allEqual(u8, std.mem.asBytes(&exp), 0));
    }
}

test "verify ed25519: a signature one octet longer or shorter is InvalidSignature" {
    const pk = certverify.PublicKey{ .ed25519 = try std.crypto.sign.Ed25519.PublicKey.fromBytes(kat.ed25519_client.public_key_bytes) };
    const th = &kat.ed25519_client.transcript_hash;
    try certverify.verify(.ed25519, pk, .client, th, &kat.ed25519_client.signature);
    var longer: [65]u8 = undefined;
    @memcpy(longer[0..64], &kat.ed25519_client.signature);
    longer[64] = 0;
    try testing.expectError(error.InvalidSignature, certverify.verify(.ed25519, pk, .client, th, &longer));
    try testing.expectError(error.InvalidSignature, certverify.verify(.ed25519, pk, .client, th, kat.ed25519_client.signature[0..63]));
}

test "sign ecdsa_secp384r1_sha384: hedged noise changes the signature, and it verifies" {
    const ec_sk = try kat.ecdsa_p384_server.secretKey();
    const sk = certverify.SecretKey{ .ecdsa_p384 = &ec_sk };
    const th = &kat.ecdsa_p384_server.transcript_hash;
    var det_buf: [certverify.max_signature_len]u8 = undefined;
    var h1_buf: [certverify.max_signature_len]u8 = undefined;
    var h2_buf: [certverify.max_signature_len]u8 = undefined;
    const det = try certverify.sign(.ecdsa_secp384r1_sha384, sk, .server, th, null, &det_buf);
    var prng = std.Random.DefaultPrng.init(0x410c);
    const h1 = try certverify.sign(.ecdsa_secp384r1_sha384, sk, .server, th, prng.random(), &h1_buf);
    const h2 = try certverify.sign(.ecdsa_secp384r1_sha384, sk, .server, th, prng.random(), &h2_buf);
    try testing.expect(!std.mem.eql(u8, det, h1));
    try testing.expect(!std.mem.eql(u8, h1, h2));
    // Each hedged signature still verifies under the key.
    const pk = certverify.PublicKey{ .ecdsa_p384 = try kat.ecdsa_p384_server.publicKey() };
    try certverify.verify(.ecdsa_secp384r1_sha384, pk, .server, th, det);
    try certverify.verify(.ecdsa_secp384r1_sha384, pk, .server, th, h1);
    try certverify.verify(.ecdsa_secp384r1_sha384, pk, .server, th, h2);
}

// 2026-11-14 delta mutation audit (certverify `signRsaPss` EntropyFailure arm).

const ZeroRandom = struct {
    fn fill(_: *ZeroRandom, buf: []u8) void {
        @memset(buf, 0);
    }
    fn random(self: *ZeroRandom) std.Random {
        return std.Random.init(self, fill);
    }
};

test "sign: an all-zero `random` (rsa's bounded blinding draw gives up) is error.EntropyFailure on every RSA-PSS scheme" {
    var rsa_sk: rsa.SecretKey = undefined;
    try kat.rsa_pss_sha256_server.secretKey(&rsa_sk);
    const sk = certverify.SecretKey{ .rsa = &rsa_sk };
    var out: [rsa.max_modulus_len]u8 = undefined;
    var z = ZeroRandom{};
    for ([_]certverify.SignatureScheme{ .rsa_pss_rsae_sha256, .rsa_pss_rsae_sha384, .rsa_pss_rsae_sha512 }) |scheme| {
        try testing.expectError(error.EntropyFailure, certverify.sign(scheme, sk, .server, &kat.rsa_pss_sha256_server.transcript_hash, z.random(), &out));
    }
}

// ── 2026-11-25 delta mutation audit: publicKeyFromSpkiDer arms, P-521 signing options ──

fn derTlv(a: std.mem.Allocator, tag: u8, parts: []const []const u8) ![]u8 {
    var len: usize = 0;
    for (parts) |p| len += p.len;
    var hdr: [4]u8 = undefined;
    hdr[0] = tag;
    var hl: usize = 2;
    if (len < 0x80) {
        hdr[1] = @intCast(len);
    } else if (len < 0x100) {
        hdr[1] = 0x81;
        hdr[2] = @intCast(len);
        hl = 3;
    } else {
        hdr[1] = 0x82;
        hdr[2] = @intCast(len >> 8);
        hdr[3] = @intCast(len & 0xff);
        hl = 4;
    }
    const out = try a.alloc(u8, hl + len);
    @memcpy(out[0..hl], hdr[0..hl]);
    var o: usize = hl;
    for (parts) |p| {
        @memcpy(out[o..][0..p.len], p);
        o += p.len;
    }
    return out;
}

/// SubjectPublicKeyInfo { AlgorithmIdentifier { oid, [params] }, BIT STRING key }.
fn spkiOf(a: std.mem.Allocator, oid: []const u8, params: ?[]const u8, key: []const u8) ![]u8 {
    const o = try derTlv(a, 0x06, &.{oid});
    const alg = if (params) |p| try derTlv(a, 0x30, &.{ o, p }) else try derTlv(a, 0x30, &.{o});
    const bits = try derTlv(a, 0x03, &.{ &.{0x00}, key });
    return derTlv(a, 0x30, &.{ alg, bits });
}

const oid_ec = [_]u8{ 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x02, 0x01 };
const oid_secp384r1 = [_]u8{ 0x2b, 0x81, 0x04, 0x00, 0x22 };
const oid_secp521r1 = [_]u8{ 0x2b, 0x81, 0x04, 0x00, 0x23 };
const oid_rsa = [_]u8{ 0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01, 0x01 };
const oid_ed25519 = [_]u8{ 0x2b, 0x65, 0x70 };

test "mutation 2026-11-25: publicKeyFromSpkiDer: RSA and P-521 keys decode and verify the KAT signatures, bad key bytes are InvalidPublicKey" {
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();
    const null_params = [_]u8{ 0x05, 0x00 };

    // RSA: RSAPublicKey ::= SEQUENCE { n INTEGER, e INTEGER }.
    const n_int = try derTlv(a, 0x02, &.{ &.{0x00}, &kat.rsa_pss_sha256_server.n });
    const e_int = try derTlv(a, 0x02, &.{&kat.rsa_pss_sha256_server.e});
    const rsa_pub = try derTlv(a, 0x30, &.{ n_int, e_int });
    const rsa_key = try certverify.publicKeyFromSpkiDer(try spkiOf(a, &oid_rsa, &null_params, rsa_pub));
    try testing.expect(rsa_key == .rsa);
    try certverify.verify(.rsa_pss_rsae_sha256, rsa_key, .server, &kat.rsa_pss_sha256_server.transcript_hash, &kat.rsa_pss_sha256_server.signature);
    // An RSAPublicKey that does not decode is a bad key, not an unsupported algorithm.
    try testing.expectError(error.InvalidPublicKey, certverify.publicKeyFromSpkiDer(try spkiOf(a, &oid_rsa, &null_params, &.{ 0x30, 0x00 })));

    // P-521.
    const curve521 = try derTlv(a, 0x06, &.{&oid_secp521r1});
    const k521 = try certverify.publicKeyFromSpkiDer(try spkiOf(a, &oid_ec, curve521, &kat.ecdsa_p521_server.public_key_uncompressed_sec1));
    try testing.expect(k521 == .ecdsa_p521);
    try certverify.verify(.ecdsa_secp521r1_sha512, k521, .server, &kat.ecdsa_p521_server.transcript_hash, &kat.ecdsa_p521_server.signature_der);
    // A point that is not on the curve: P-384 and P-521 refuse it as InvalidPublicKey.
    const curve384 = try derTlv(a, 0x06, &.{&oid_secp384r1});
    const off384: [97]u8 = @splat(4);
    try testing.expectError(error.InvalidPublicKey, certverify.publicKeyFromSpkiDer(try spkiOf(a, &oid_ec, curve384, &off384)));
    const off521: [133]u8 = @splat(4);
    try testing.expectError(error.InvalidPublicKey, certverify.publicKeyFromSpkiDer(try spkiOf(a, &oid_ec, curve521, &off521)));

    // An Ed25519 key that is not a canonical point encoding (y >= p).
    const bad_ed: [32]u8 = @splat(0xff);
    try testing.expectError(error.InvalidPublicKey, certverify.publicKeyFromSpkiDer(try spkiOf(a, &oid_ed25519, null, &bad_ed)));
}

test "mutation 2026-11-25: publicKeyFromSpkiDer: ML-DSA-44/65/87 map to their own arm, length-checked, parameters absent" {
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();
    const base = [_]u8{ 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x03 };
    const Case = struct { last: u8, len: usize };
    const cases = [_]Case{ .{ .last = 0x11, .len = 1312 }, .{ .last = 0x12, .len = 1952 }, .{ .last = 0x13, .len = 2592 } };
    for (cases) |c| {
        const oid = base ++ [_]u8{c.last};
        const key = try a.alloc(u8, c.len);
        @memset(key, 0x5a);
        const pk = try certverify.publicKeyFromSpkiDer(try spkiOf(a, &oid, null, key));
        switch (c.last) {
            0x11 => try testing.expectEqual(@as(usize, 1312), pk.mldsa44.len),
            0x12 => try testing.expectEqual(@as(usize, 1952), pk.mldsa65.len),
            0x13 => try testing.expectEqual(@as(usize, 2592), pk.mldsa87.len),
            else => unreachable,
        }
        // One octet short and one too long: a malformed key.
        try testing.expectError(error.InvalidPublicKey, certverify.publicKeyFromSpkiDer(try spkiOf(a, &oid, null, key[0 .. c.len - 1])));
        const longer = try a.alloc(u8, c.len + 1);
        @memset(longer, 0x5a);
        try testing.expectError(error.InvalidPublicKey, certverify.publicKeyFromSpkiDer(try spkiOf(a, &oid, null, longer)));
        // RFC 9881 §2: the parameters MUST be absent.
        try testing.expectError(error.InvalidPublicKey, certverify.publicKeyFromSpkiDer(try spkiOf(a, &oid, &.{ 0x05, 0x00 }, key)));
    }
}

test "mutation 2026-11-25: sign (P-521): noise from `random` changes the signature, both verify; a scalar outside [1, n-1] is KeyMismatch" {
    const p521 = @import("p521");
    const EcdsaP521 = p521.EcdsaP521Sha512;
    var b521: [66]u8 = undefined;
    @memset(&b521, 0x11);
    b521[0] = 0;
    const sk = try EcdsaP521.SecretKey.fromBytes(b521);
    var kp: EcdsaP521.KeyPair = undefined;
    try EcdsaP521.KeyPair.fromSecretKeyInto(&kp, &sk);
    const th: [64]u8 = @splat(0x33);
    var det1: [certverify.max_signature_len]u8 = undefined;
    var det2: [certverify.max_signature_len]u8 = undefined;
    var rnd_out: [certverify.max_signature_len]u8 = undefined;
    const d1 = try certverify.sign(.ecdsa_secp521r1_sha512, .{ .ecdsa_p521 = &sk }, .server, &th, null, &det1);
    const d2 = try certverify.sign(.ecdsa_secp521r1_sha512, .{ .ecdsa_p521 = &sk }, .server, &th, null, &det2);
    try testing.expectEqualSlices(u8, d1, d2); // RFC 6979 without noise
    var prng = std.Random.DefaultPrng.init(0x521);
    const r1 = try certverify.sign(.ecdsa_secp521r1_sha512, .{ .ecdsa_p521 = &sk }, .server, &th, prng.random(), &rnd_out);
    try testing.expect(!std.mem.eql(u8, d1, r1)); // §3.6 additional data
    const pk: certverify.PublicKey = .{ .ecdsa_p521 = kp.public_key };
    try certverify.verify(.ecdsa_secp521r1_sha512, pk, .server, &th, d1);
    try certverify.verify(.ecdsa_secp521r1_sha512, pk, .server, &th, r1);
    // The zero scalar is no key.
    const zero: EcdsaP521.SecretKey = .{ .bytes = @splat(0) };
    try testing.expectError(error.KeyMismatch, certverify.sign(.ecdsa_secp521r1_sha512, .{ .ecdsa_p521 = &zero }, .server, &th, null, &det1));
}

// ── 2026-11-25 delta (the Ed25519 signer moved onto `ct25519`, 2026-11-27) ──

test "mutation 2026-11-25: Ed25519Signer.deinit wipes the whole prepared signer" {
    const kp = try std.crypto.sign.Ed25519.KeyPair.generateDeterministic(@splat(0x55));
    var s = try certverify.Ed25519Signer.init(&kp.secret_key);
    try testing.expect(!std.mem.allEqual(u8, std.mem.asBytes(&s), 0));
    s.deinit();
    try testing.expect(std.mem.allEqual(u8, std.mem.asBytes(&s), 0));
}

const sp = @import("testkit").stackprobe;
const NoiseProbe = sp.Probe(.{ .window = 64 * 1024 });
var noise_out: [certverify.max_signature_len]u8 = undefined;
var noise_signer: certverify.Ed25519Signer = undefined;
const noise_th: [48]u8 = @splat(0x6b);

/// The hedging noise is this pattern (non-uniform, so the needle windows see
/// it); the source has no buffer of its own, unlike a CSPRNG whose state holds
/// the bytes it just handed out (that copy sits in the probe's frame).
fn noiseFill(_: *anyopaque, buf: []u8) void {
    for (buf, 0..) |*b, i| b.* = @truncate(i *% 37 +% 0x29);
}
const noise_random = std.Random{ .ptr = undefined, .fillFn = noiseFill };

fn signWithNoise(sk: *const std.crypto.sign.Ed25519.SecretKey) !void {
    _ = try certverify.sign(.ed25519, .{ .ed25519 = sk }, .server, &noise_th, noise_random, &noise_out);
}

fn signPreparedWithNoise() !void {
    _ = try noise_signer.sign(.server, &noise_th, noise_random, &noise_out);
}

test "mutation 2026-11-25: STACKPROBE: the Ed25519 hedging noise does not stay on the dead stack (per-call key and prepared signer)" {
    try sp.skipUnlessOptimized();
    const kp = try std.crypto.sign.Ed25519.KeyPair.generateDeterministic(@splat(0x55));
    var noise: [32]u8 = undefined;
    noiseFill(undefined, &noise);
    const needles = &[_][]const u8{&noise};
    _ = try NoiseProbe.run("ed25519 sign, noise", signWithNoise, .{&kp.secret_key}, needles, .{});
    noise_signer = try certverify.Ed25519Signer.init(&kp.secret_key);
    defer noise_signer.deinit();
    _ = try NoiseProbe.run("ed25519 prepared sign, noise", signPreparedWithNoise, .{}, needles, .{});
}
