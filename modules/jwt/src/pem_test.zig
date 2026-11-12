// SPDX-License-Identifier: MIT

//! `PrivateKey.fromPem` and `Key.fromPem` against OpenSSL-written keys
//! (`pem_vectors.zig`, `tools/pem_vectors.py`): a token signed with the
//! loaded private key verifies under the public key OpenSSL derived for it.
//! That pairing is the external anchor -- a wrongly read scalar, seed or
//! RSA key cannot produce it.

const std = @import("std");
const root = @import("root.zig");
const vectors = @import("pem_vectors.zig");
const testing = std.testing;

const Claims = struct {
    iss: []const u8 = "https://issuer.test",
    sub: []const u8 = "user-1",
    exp: i64 = 4_102_444_800,
};
const opts: root.Options = .{ .now_s = 1_790_000_000, .issuer = .{ .required = "https://issuer.test" }, .audience = .any };

fn signAndVerify(sk: root.SigningKey, vk: root.Key) !void {
    const token = try root.encode(testing.allocator, Claims{}, sk, .{});
    defer testing.allocator.free(token);
    var parsed = try root.parseAndVerify(testing.allocator, token, vk, opts);
    defer parsed.deinit();
    try testing.expectEqualStrings("user-1", parsed.claims.claimStr("sub").?);
}

test "pem: every OpenSSL key signs a token its OpenSSL public key verifies" {
    const k = try testing.allocator.create(root.PrivateKey); // ML-DSA pairs are large
    defer testing.allocator.destroy(k);
    for (vectors.cases) |c| {
        errdefer std.debug.print("case {s}\n", .{c.name});
        try root.PrivateKey.fromPem(k, c.key_pem);
        defer k.deinit();
        const sk = k.signingKey();
        try testing.expectEqualStrings(c.alg, @tagName(sk.alg()));
        const vk = try root.Key.fromPem(c.pub_pem);
        try signAndVerify(sk, vk);
    }
}

test "pem: a token signed with one key does not verify under another's public key" {
    const k = try testing.allocator.create(root.PrivateKey);
    defer testing.allocator.destroy(k);
    // p256-pkcs8 and p256-sec1 are the same key; p384 is another curve.
    try root.PrivateKey.fromPem(k, vectors.cases[0].key_pem);
    defer k.deinit();
    const same = try root.Key.fromPem(vectors.cases[1].pub_pem);
    try signAndVerify(k.signingKey(), same);
    const token = try root.encode(testing.allocator, Claims{}, k.signingKey(), .{});
    defer testing.allocator.free(token);
    const rsa_case = for (vectors.cases) |c| {
        if (std.mem.eql(u8, c.name, "rsa-pkcs8")) break c;
    } else unreachable;
    try testing.expectError(error.AlgKeyMismatch, root.parseAndVerify(testing.allocator, token, try root.Key.fromPem(rsa_case.pub_pem), opts));
}

test "pem: RSA picks RS*/PS* by alg, PS* needs a CSPRNG" {
    const k = try testing.allocator.create(root.PrivateKey);
    defer testing.allocator.destroy(k);
    const c = for (vectors.cases) |c| {
        if (std.mem.eql(u8, c.name, "rsa-pkcs1")) break c;
    } else unreachable;
    try root.PrivateKey.fromPem(k, c.key_pem);
    defer k.deinit();
    const vk = try root.Key.fromPem(c.pub_pem);
    var csprng = std.Random.DefaultCsprng.init(@splat(3)); // a fixed seed is fine for a test
    for ([_]root.Alg{ .RS256, .RS384, .RS512, .PS256, .PS384, .PS512 }) |alg| {
        const sk = try k.rsaSigningKey(alg, csprng.random());
        try testing.expectEqual(alg, sk.alg());
        try signAndVerify(sk, vk);
    }
    try testing.expectError(error.InvalidKey, k.rsaSigningKey(.PS256, null));
    try testing.expectError(error.InvalidKey, k.rsaSigningKey(.ES256, null));
    _ = try k.rsaSigningKey(.RS256, null);
    // The verification key derived from the private key is OpenSSL's.
    try signAndVerify(k.signingKey(), k.verificationKey());
    // A non-RSA key has no RSA signing key.
    try root.PrivateKey.fromPem(k, vectors.cases[0].key_pem);
    try testing.expectError(error.InvalidKey, k.rsaSigningKey(.RS256, null));
}

test "pem: refused private keys leave the key zeroed" {
    const k = try testing.allocator.create(root.PrivateKey);
    defer testing.allocator.destroy(k);
    for (vectors.refused) |r| {
        errdefer std.debug.print("case {s}\n", .{r.name});
        @memset(std.mem.asBytes(k), 0xaa);
        try testing.expectError(error.InvalidKey, root.PrivateKey.fromPem(k, r.key_pem));
        try testing.expect(std.mem.allEqual(u8, std.mem.asBytes(k), 0));
    }
    try testing.expectError(error.InvalidKey, root.PrivateKey.fromPem(k, ""));
    try testing.expectError(error.InvalidKey, root.PrivateKey.fromPem(k, vectors.cases[0].pub_pem));
}

test "pem: an ML-DSA both key whose halves disagree is refused" {
    const c = for (vectors.cases) |c| {
        if (std.mem.eql(u8, c.name, "mldsa44-both")) break c;
    } else unreachable;
    const keycodec = @import("keycodec");
    var der: [keycodec.max_private_der_len]u8 = undefined;
    const parsed = try keycodec.parsePrivateKeyPem(c.key_pem, &der);
    // Flip one byte of the expanded half and write the key back.
    const off = @intFromPtr(parsed.expanded.ptr) - @intFromPtr(&der);
    der[off + 100] ^= 1;
    var broken = parsed;
    broken.expanded = der[off..][0..parsed.expanded.len];
    var pem_buf: [keycodec.max_private_pem_len]u8 = undefined;
    const text = try keycodec.writePrivateKeyPem(&pem_buf, broken);
    const k = try testing.allocator.create(root.PrivateKey);
    defer testing.allocator.destroy(k);
    try testing.expectError(error.InvalidKey, root.PrivateKey.fromPem(k, text));
}

test "pem: public keys -- PKCS#1, SPKI DER, refusals" {
    const pkcs1 = try root.Key.fromPem(vectors.rsa_pkcs1_pub_pem);
    try testing.expect(pkcs1 == .rsa);
    try testing.expectError(error.InvalidKey, root.Key.fromPem(vectors.rsa1024_pub_pem));
    try testing.expectError(error.InvalidKey, root.Key.fromPem(vectors.cases[0].key_pem)); // a private key
    try testing.expectError(error.InvalidKey, root.Key.fromPem(""));
    // fromSpki reads the DER inside the PEM.
    const keycodec = @import("keycodec");
    var buf: [keycodec.max_public_der_len]u8 = undefined;
    const b = (try keycodec.pem.find(vectors.cases[0].pub_pem, "PUBLIC KEY")).?;
    const k = try root.Key.fromSpki(try b.decode(&buf));
    try testing.expect(k == .ecdsa_p256);
    // An off-curve point: valid SPKI shape, refused by the curve module.
    const der = try b.decode(&buf);
    der[der.len - 1] ^= 1;
    try testing.expectError(error.InvalidKey, root.Key.fromSpki(der));
}

test "pem: PrivateKey.deinit leaves no copy of the secret scalar in the value" {
    // In Debug/ReleaseSafe the trailing `self.* = undefined` paints 0xaa over
    // the value anyway; in ReleaseFast it emits nothing, and only the explicit
    // secureZero keeps the scalar from surviving in the caller's storage.
    const k = try testing.allocator.create(root.PrivateKey);
    defer testing.allocator.destroy(k);
    try root.PrivateKey.fromPem(k, vectors.cases[0].key_pem); // p256-pkcs8
    const secret = k.ecdsa_p256.secret_key.bytes;
    try testing.expect(std.mem.find(u8, std.mem.asBytes(k), &secret) != null);
    k.deinit();
    try testing.expect(std.mem.find(u8, std.mem.asBytes(k), &secret) == null);
}

test "pem: an SPKI ML-DSA-44/65/87 public key reads as its own parameter set and verifies what that set signed (mutation run 2026-11-12)" {
    const keycodec = @import("keycodec");
    inline for (.{
        .{ root.MlDsa44, keycodec.Algorithm.ml_dsa_44, "ml_dsa_44" },
        .{ root.MlDsa65, keycodec.Algorithm.ml_dsa_65, "ml_dsa_65" },
        .{ root.MlDsa87, keycodec.Algorithm.ml_dsa_87, "ml_dsa_87" },
    }) |c| {
        const kp = try testing.allocator.create(c[0].KeyPair);
        defer testing.allocator.destroy(kp);
        kp.* = try c[0].KeyPair.generateDeterministic(@splat(7));
        const raw = kp.public_key.toBytes();
        var buf: [keycodec.max_public_der_len]u8 = undefined;
        const der = try keycodec.writeSpki(&buf, .{ .algorithm = c[1], .key = &raw });
        const vk = try root.Key.fromSpki(der);
        try testing.expectEqualStrings(c[2], @tagName(vk));
        try signAndVerify(@unionInit(root.SigningKey, c[2], kp), vk);
    }
}

test "pem: an RSA private key signs RS*/PS* only; every other alg is InvalidKey (mutation run 2026-11-12)" {
    const k = try testing.allocator.create(root.PrivateKey);
    defer testing.allocator.destroy(k);
    const rsa_case = for (vectors.cases) |c| {
        if (std.mem.eql(u8, c.name, "rsa-pkcs8")) break c;
    } else unreachable;
    try root.PrivateKey.fromPem(k, rsa_case.key_pem);
    defer k.deinit();
    var csprng = std.Random.DefaultCsprng.init(@as([32]u8, @splat(3)));
    for ([_]root.Alg{ .HS256, .HS384, .HS512, .ES256, .ES384, .ES512, .EdDSA, .none, .unknown, .@"ML-DSA-44", .@"ML-DSA-65", .@"ML-DSA-87" }) |alg| {
        try testing.expectError(error.InvalidKey, k.rsaSigningKey(alg, csprng.random()));
        try testing.expectError(error.InvalidKey, k.rsaSigningKey(alg, null));
    }
}

test "pem: an SPKI of an algorithm JWS has no use for is InvalidKey (X25519/X448/Ed448/ML-KEM), never read as another key type (mutation run 2026-11-12)" {
    const keycodec = @import("keycodec");
    const cases = [_]struct { a: keycodec.Algorithm, len: usize }{
        .{ .a = .x25519, .len = 32 },
        .{ .a = .x448, .len = 56 },
        .{ .a = .ed448, .len = 57 },
        .{ .a = .ml_kem_512, .len = 800 },
        .{ .a = .ml_kem_768, .len = 1184 },
        .{ .a = .ml_kem_1024, .len = 1568 },
    };
    var raw: [2048]u8 = @splat(0x42);
    for (cases) |c| {
        var buf: [keycodec.max_public_der_len]u8 = undefined;
        const der = keycodec.writeSpki(&buf, .{ .algorithm = c.a, .key = raw[0..c.len] }) catch continue;
        try testing.expectError(error.InvalidKey, root.Key.fromSpki(der));
    }
}
