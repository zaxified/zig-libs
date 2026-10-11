// SPDX-License-Identifier: MIT
//! kat_test — all twelve SLH-DSA parameter sets against the official NIST
//! ACVP FIPS 205 known-answer vectors (see kat_vectors.zig for provenance),
//! plus keygen->sign->verify round-trips and tamper-rejection checks.

const std = @import("std");
const params = @import("params.zig");
const engine = @import("engine.zig");
const v = @import("kat_vectors.zig");

const Scheme = engine.SlhDsa(params.sha2_128f);
const sig_len = Scheme.signature_length;

fn hex(comptime len: usize, hex_str: []const u8) [len]u8 {
    var out: [len]u8 = undefined;
    const decoded = std.fmt.hexToBytes(&out, hex_str) catch unreachable;
    std.debug.assert(decoded.len == len);
    return out;
}

fn hexAlloc(gpa: std.mem.Allocator, hex_str: []const u8) ![]u8 {
    const out = try gpa.alloc(u8, hex_str.len / 2);
    _ = std.fmt.hexToBytes(out, hex_str) catch unreachable;
    return out;
}

/// keyGen KAT: the vector's seeds must produce its exact pk and sk, and the
/// deterministic-internal sigGen KAT: the vector's sk must produce its exact
/// signature, which the vector's pk must accept.
fn katSet(comptime P: params.Params, comptime V: type) !void {
    const S = engine.SlhDsa(P);
    const gpa = std.testing.allocator;

    // keyGen: seeds -> byte-exact pk + sk.
    var kp: S.KeyPair = undefined;
    S.keyGenFromSeed(
        &kp,
        &hex(S.n, V.keygen_sk_seed),
        &hex(S.n, V.keygen_sk_prf),
        &hex(S.n, V.keygen_pk_seed),
    );
    var kp_sk_bytes: [S.secret_key_length]u8 = undefined;
    kp.sk.toBytes(&kp_sk_bytes);
    try std.testing.expectEqualSlices(u8, &hex(S.public_key_length, V.keygen_pk), &kp.pk.toBytes());
    try std.testing.expectEqualSlices(u8, &hex(S.secret_key_length, V.keygen_sk), &kp_sk_bytes);

    // sigGen (internal interface, deterministic): byte-exact signature.
    var sk: S.SecretKey = undefined;
    S.SecretKey.fromBytes(&sk, &hex(S.secret_key_length, V.det_sk));
    const pk = S.PublicKey.fromBytes(hex(S.public_key_length, V.det_pk));
    try std.testing.expectEqualSlices(u8, &pk.toBytes(), &sk.pk.toBytes());
    const msg = try hexAlloc(gpa, V.det_msg);
    defer gpa.free(msg);
    const expected = try hexAlloc(gpa, V.det_sig);
    defer gpa.free(expected);
    try std.testing.expectEqual(@as(usize, S.signature_length), expected.len);
    const sig = try gpa.alloc(u8, S.signature_length);
    defer gpa.free(sig);
    S.signInternal(sig[0..S.signature_length], msg, &sk, null);
    try std.testing.expectEqualSlices(u8, expected, sig);
    try std.testing.expect(S.verifyInternal(sig, msg, pk));
}

test "NIST ACVP KAT: SLH-DSA-SHA2-128s" {
    try katSet(params.sha2_128s, v.sha2_128s);
}

test "NIST ACVP KAT: SLH-DSA-SHA2-128f" {
    try katSet(params.sha2_128f, v.sha2_128f);
}

test "NIST ACVP KAT: SLH-DSA-SHA2-192s" {
    try katSet(params.sha2_192s, v.sha2_192s);
}

test "NIST ACVP KAT: SLH-DSA-SHA2-192f" {
    try katSet(params.sha2_192f, v.sha2_192f);
}

test "NIST ACVP KAT: SLH-DSA-SHA2-256s" {
    try katSet(params.sha2_256s, v.sha2_256s);
}

test "NIST ACVP KAT: SLH-DSA-SHA2-256f" {
    try katSet(params.sha2_256f, v.sha2_256f);
}

test "NIST ACVP KAT: SLH-DSA-SHAKE-128s" {
    try katSet(params.shake_128s, v.shake_128s);
}

test "NIST ACVP KAT: SLH-DSA-SHAKE-128f" {
    try katSet(params.shake_128f, v.shake_128f);
}

test "NIST ACVP KAT: SLH-DSA-SHAKE-192s" {
    try katSet(params.shake_192s, v.shake_192s);
}

test "NIST ACVP KAT: SLH-DSA-SHAKE-192f" {
    try katSet(params.shake_192f, v.shake_192f);
}

test "NIST ACVP KAT: SLH-DSA-SHAKE-256s" {
    try katSet(params.shake_256s, v.shake_256s);
}

test "NIST ACVP KAT: SLH-DSA-SHAKE-256f" {
    try katSet(params.shake_256f, v.shake_256f);
}

test "NIST ACVP sigGen tcId 2: deterministic pure signature with context is byte-exact" {
    var sk: Scheme.SecretKey = undefined;
    Scheme.SecretKey.fromBytes(&sk, &hex(64, v.sha2_128f.pure_sk));
    const pk = Scheme.PublicKey.fromBytes(hex(32, v.sha2_128f.pure_pk));
    const msg = hex(1, v.sha2_128f.pure_msg);
    const ctx = hex(110, v.sha2_128f.pure_ctx);
    const expected = hex(sig_len, v.sha2_128f.pure_sig);

    var sig: [sig_len]u8 = undefined;
    try Scheme.sign(&sig, &msg, &sk, &ctx, null);
    try std.testing.expectEqualSlices(u8, &expected, &sig);
    try std.testing.expect(Scheme.verify(&sig, &msg, pk, &ctx));

    // Same bytes must NOT verify under a different or missing context.
    try std.testing.expect(!Scheme.verify(&sig, &msg, pk, ""));
    var ctx2 = ctx;
    ctx2[0] ^= 1;
    try std.testing.expect(!Scheme.verify(&sig, &msg, pk, &ctx2));
}

test "NIST ACVP sigGen tcId 433: hedged internal signature is byte-exact" {
    var sk: Scheme.SecretKey = undefined;
    Scheme.SecretKey.fromBytes(&sk, &hex(64, v.sha2_128f.rand_sk));
    const pk = Scheme.PublicKey.fromBytes(hex(32, v.sha2_128f.rand_pk));
    const msg = hex(1, v.sha2_128f.rand_msg);
    const addrnd = hex(16, v.sha2_128f.rand_addrnd);
    const expected = hex(sig_len, v.sha2_128f.rand_sig);

    var sig: [sig_len]u8 = undefined;
    Scheme.signInternal(&sig, &msg, &sk, addrnd);
    try std.testing.expectEqualSlices(u8, &expected, &sig);
    try std.testing.expect(Scheme.verifyInternal(&sig, &msg, pk));
}

test "keygen -> sign -> verify round-trip; tampering rejects, never panics" {
    const gpa = std.testing.allocator;
    var seed: [48]u8 = undefined;
    for (&seed, 0..) |*b, i| b.* = @truncate(i * 37 + 5);
    var kp: Scheme.KeyPair = undefined;
    Scheme.keyGen(&kp, &seed);

    const msg = "zig-libs slhdsa round-trip message";
    const ctx = "ctx";
    const sig = try gpa.alloc(u8, sig_len);
    defer gpa.free(sig);
    try Scheme.sign(sig[0..sig_len], msg, &kp.sk, ctx, null);
    try std.testing.expect(Scheme.verify(sig, msg, kp.pk, ctx));

    // Flip one byte in each structural region of the signature:
    // R, FORS, and the hypertree tail. All must reject.
    for ([_]usize{ 0, 20, sig_len - 1 }) |pos| {
        sig[pos] ^= 0x01;
        try std.testing.expect(!Scheme.verify(sig, msg, kp.pk, ctx));
        sig[pos] ^= 0x01;
    }
    // Tampered message / wrong context / wrong key must reject.
    try std.testing.expect(!Scheme.verify(sig, "zig-libs slhdsa round-trip messagf", kp.pk, ctx));
    try std.testing.expect(!Scheme.verify(sig, msg, kp.pk, "ctx2"));
    var seed2 = seed;
    seed2[0] +%= 1;
    var kp2: Scheme.KeyPair = undefined;
    Scheme.keyGen(&kp2, &seed2);
    try std.testing.expect(!Scheme.verify(sig, msg, kp2.pk, ctx));

    // Malformed signature lengths: false, never a panic.
    try std.testing.expect(!Scheme.verify(sig[0 .. sig_len - 1], msg, kp.pk, ctx));
    try std.testing.expect(!Scheme.verify("", msg, kp.pk, ctx));
    const long = try gpa.alloc(u8, sig_len + 1);
    defer gpa.free(long);
    @memcpy(long[0..sig_len], sig);
    long[sig_len] = 0;
    try std.testing.expect(!Scheme.verify(long, msg, kp.pk, ctx));

    // Oversized context: sign errors, verify returns false.
    const big_ctx = try gpa.alloc(u8, 256);
    defer gpa.free(big_ctx);
    @memset(big_ctx, 0xAB);
    try std.testing.expectError(error.ContextTooLong, Scheme.sign(sig[0..sig_len], msg, &kp.sk, big_ctx, null));
    try std.testing.expect(!Scheme.verify(sig, msg, kp.pk, big_ctx));

    // Exactly at the boundary: ctx.len == 255 is the FIPS 205 §10.2 LIMIT,
    // not past it -- must still succeed. No prior test probed this boundary
    // from the accepted side (only 256, well past it, was ever tried), so an
    // off-by-one (`> 255` mutated to `>= 255`) went uncaught.
    const max_ctx = try gpa.alloc(u8, 255);
    defer gpa.free(max_ctx);
    @memset(max_ctx, 0xCD);
    try Scheme.sign(sig[0..sig_len], msg, &kp.sk, max_ctx, null);
    try std.testing.expect(Scheme.verify(sig, msg, kp.pk, max_ctx));
}

test "SHAKE-128f keygen -> pure sign -> verify round-trip with context" {
    const S = engine.SlhDsa(params.shake_128f);
    var seed: [48]u8 = undefined;
    for (&seed, 0..) |*b, i| b.* = @truncate(i *% 91 + 3);
    var kp: S.KeyPair = undefined;
    S.keyGen(&kp, &seed);
    const msg = "zig-libs slhdsa shake round-trip";
    var sig: [S.signature_length]u8 = undefined;
    try S.sign(&sig, msg, &kp.sk, "ctx", null);
    try std.testing.expect(S.verify(&sig, msg, kp.pk, "ctx"));
    try std.testing.expect(!S.verify(&sig, msg, kp.pk, "ctx2"));
    sig[0] ^= 1;
    try std.testing.expect(!S.verify(&sig, msg, kp.pk, "ctx"));
}

test "hedged and deterministic signatures differ but both verify" {
    var seed: [48]u8 = undefined;
    for (&seed, 0..) |*b, i| b.* = @truncate(i +% 200);
    var kp: Scheme.KeyPair = undefined;
    Scheme.keyGen(&kp, &seed);
    const msg = "same message";

    var det_sig: [sig_len]u8 = undefined;
    var hedged_sig: [sig_len]u8 = undefined;
    try Scheme.sign(&det_sig, msg, &kp.sk, "", null);
    try Scheme.sign(&hedged_sig, msg, &kp.sk, "", @splat(0x5C));
    try std.testing.expect(!std.mem.eql(u8, &det_sig, &hedged_sig));
    try std.testing.expect(Scheme.verify(&det_sig, msg, kp.pk, ""));
    try std.testing.expect(Scheme.verify(&hedged_sig, msg, kp.pk, ""));
}

test "kat vector hex decodes to the FIPS 205 lengths for every set" {
    const cases = .{
        .{ params.sha2_128s, v.sha2_128s },   .{ params.sha2_128f, v.sha2_128f },
        .{ params.sha2_192s, v.sha2_192s },   .{ params.sha2_192f, v.sha2_192f },
        .{ params.sha2_256s, v.sha2_256s },   .{ params.sha2_256f, v.sha2_256f },
        .{ params.shake_128s, v.shake_128s }, .{ params.shake_128f, v.shake_128f },
        .{ params.shake_192s, v.shake_192s }, .{ params.shake_192f, v.shake_192f },
        .{ params.shake_256s, v.shake_256s }, .{ params.shake_256f, v.shake_256f },
    };
    inline for (cases) |case| {
        const P = case[0];
        const V = case[1];
        try std.testing.expectEqual(comptime P.sigLen(), V.det_sig.len / 2);
        try std.testing.expectEqual(4 * P.n, V.keygen_sk.len / 2);
        try std.testing.expectEqual(2 * P.n, V.keygen_pk.len / 2);
    }
}

// ── HashSLH-DSA (pre-hash, FIPS 205 §10.2.2) ───────────────────────────────

fn phOf(alg: v.PrehashAlg) Scheme.PreHash {
    return switch (alg) {
        .sha2_224 => .sha2_224,
        .sha2_256 => .sha2_256,
        .sha2_384 => .sha2_384,
        .sha2_512 => .sha2_512,
        .sha2_512_224 => .sha2_512_224,
        .sha2_512_256 => .sha2_512_256,
        .sha3_224 => .sha3_224,
        .sha3_256 => .sha3_256,
        .sha3_384 => .sha3_384,
        .sha3_512 => .sha3_512,
        .shake_128 => .shake128,
        .shake_256 => .shake256,
    };
}

/// ACVP sigGen pre-hash cases: byte-exact signature from the module-hashed
/// message, which then verifies through both the message and the digest entry
/// points; the same bytes must not verify under another PH, as a pure
/// signature, or under a damaged context.
fn prehashGen(comptime P: params.Params, comptime cases: []const v.PrehashSigGen) !void {
    const S = engine.SlhDsa(P);
    const gpa = std.testing.allocator;
    const sig = try gpa.alloc(u8, S.signature_length);
    defer gpa.free(sig);
    for (cases) |c| {
        const ph: S.PreHash = phOf(c.ph);
        var sk: S.SecretKey = undefined;
        S.SecretKey.fromBytes(&sk, &hex(S.secret_key_length, c.sk));
        const pk = S.PublicKey.fromBytes(hex(S.public_key_length, c.pk));
        try std.testing.expectEqualSlices(u8, &pk.toBytes(), &sk.pk.toBytes());
        const msg = try hexAlloc(gpa, c.msg);
        defer gpa.free(msg);
        const ctx = try hexAlloc(gpa, c.ctx);
        defer gpa.free(ctx);
        const addrnd: ?[S.n]u8 = if (c.addrnd) |a| hex(S.n, a) else null;

        try S.signPrehash(sig[0..S.signature_length], msg, &sk, ctx, ph, addrnd);
        var got: [32]u8 = undefined;
        std.crypto.hash.sha2.Sha256.hash(sig, &got, .{});
        std.testing.expectEqualSlices(u8, &hex(32, c.sig_sha256), &got) catch |err| {
            std.debug.print("prehash sigGen tgId {d} tcId {d} ({t})\n", .{ c.tg_id, c.tc_id, c.ph });
            return err;
        };
        try std.testing.expect(S.verifyPrehash(sig, msg, pk, ctx, ph));
        var dbuf: [64]u8 = undefined;
        try std.testing.expect(S.verifyPrehashDigest(sig, ph.hash(msg, &dbuf), pk, ctx, ph));

        // Domain separation: other PH, pure interface, other context.
        const other: S.PreHash = if (ph == .sha2_256) .sha3_256 else .sha2_256;
        try std.testing.expect(!S.verifyPrehash(sig, msg, pk, ctx, other));
        try std.testing.expect(!S.verify(sig, msg, pk, ctx));
        const ctx2 = try gpa.alloc(u8, ctx.len + 1);
        defer gpa.free(ctx2);
        @memcpy(ctx2[0..ctx.len], ctx);
        ctx2[ctx.len] = 0;
        try std.testing.expect(!S.verifyPrehash(sig, msg, pk, ctx2, ph));
    }
}

test "NIST ACVP sigGen pre-hash: SLH-DSA-SHA2-128f, byte-exact" {
    try prehashGen(params.sha2_128f, &v.prehash_sha2_128f_gen);
}

test "NIST ACVP sigGen pre-hash: SLH-DSA-SHAKE-128f, byte-exact" {
    try prehashGen(params.shake_128f, &v.prehash_shake_128f_gen);
}

test "NIST ACVP sigGen pre-hash: all twelve PH functions are covered" {
    var covered = std.EnumSet(v.PrehashAlg).initEmpty();
    for (v.prehash_sha2_128f_gen) |c| covered.insert(c.ph);
    for (v.prehash_shake_128f_gen) |c| covered.insert(c.ph);
    try std.testing.expectEqual(@typeInfo(v.PrehashAlg).@"enum".fields.len, covered.count());
}

fn prehashVer(comptime P: params.Params, comptime cases: []const v.PrehashSigVer) !void {
    const S = engine.SlhDsa(P);
    const gpa = std.testing.allocator;
    for (cases) |c| {
        const pk = S.PublicKey.fromBytes(hex(S.public_key_length, c.pk));
        const msg = try hexAlloc(gpa, c.msg);
        defer gpa.free(msg);
        const ctx = try hexAlloc(gpa, c.ctx);
        defer gpa.free(ctx);
        const sig = try hexAlloc(gpa, c.sig);
        defer gpa.free(sig);
        const ph = phOf(c.ph);
        std.testing.expectEqual(c.passed, S.verifyPrehash(sig, msg, pk, ctx, ph)) catch |err| {
            std.debug.print("prehash sigVer tgId {d} tcId {d} ({t})\n", .{ c.tg_id, c.tc_id, c.ph });
            return err;
        };
        var dbuf: [64]u8 = undefined;
        try std.testing.expectEqual(c.passed, S.verifyPrehashDigest(sig, ph.hash(msg, &dbuf), pk, ctx, ph));
    }
}

test "NIST ACVP sigVer pre-hash: SLH-DSA-SHA2-128f, valid and invalid" {
    try prehashVer(params.sha2_128f, &v.prehash_sha2_128f_ver);
}

test "NIST ACVP sigVer pre-hash: SLH-DSA-SHAKE-128f, invalid" {
    try prehashVer(params.shake_128f, &v.prehash_shake_128f_ver);
}

test "pre-hash: digest entry points check lengths; sign(digest) == sign(msg); size boundaries" {
    var seed: [48]u8 = undefined;
    for (&seed, 0..) |*b, i| b.* = @truncate(i *% 13 + 7);
    var kp: Scheme.KeyPair = undefined;
    Scheme.keyGen(&kp, &seed);
    const msg = "pre-hash message";
    var dbuf: [64]u8 = undefined;
    const digest = Scheme.PreHash.sha3_384.hash(msg, &dbuf);
    try std.testing.expectEqual(@as(usize, 48), digest.len);

    var a: [sig_len]u8 = undefined;
    var b: [sig_len]u8 = undefined;
    try Scheme.signPrehash(&a, msg, &kp.sk, "c", .sha3_384, null);
    try Scheme.signPrehashDigest(&b, digest, &kp.sk, "c", .sha3_384, null);
    try std.testing.expectEqualSlices(u8, &a, &b);
    try std.testing.expect(Scheme.verifyPrehashDigest(&a, digest, kp.pk, "c", .sha3_384));

    // Digest of the wrong length for the named PH.
    try std.testing.expectError(error.DigestLengthMismatch, Scheme.signPrehashDigest(&b, digest[0..47], &kp.sk, "c", .sha3_384, null));
    try std.testing.expectError(error.DigestLengthMismatch, Scheme.signPrehashDigest(&b, digest, &kp.sk, "c", .sha3_256, null));
    try std.testing.expect(!Scheme.verifyPrehashDigest(&a, digest[0..47], kp.pk, "c", .sha3_384));
    try std.testing.expect(!Scheme.verifyPrehashDigest(&a, "", kp.pk, "c", .sha3_384));

    // Context: 256 bytes refused on both sides, 255 accepted.
    const big: [256]u8 = @splat(0xAB);
    try std.testing.expectError(error.ContextTooLong, Scheme.signPrehash(&b, msg, &kp.sk, &big, .sha2_256, null));
    try std.testing.expectError(error.ContextTooLong, Scheme.signPrehashDigest(&b, digest, &kp.sk, &big, .sha3_384, null));
    try std.testing.expect(!Scheme.verifyPrehash(&a, msg, kp.pk, &big, .sha3_384));
    try Scheme.signPrehash(&b, msg, &kp.sk, big[0..255], .sha2_256, @splat(9));
    try std.testing.expect(Scheme.verifyPrehash(&b, msg, kp.pk, big[0..255], .sha2_256));

    // Wrong-length signatures: false, never a panic.
    try std.testing.expect(!Scheme.verifyPrehash(a[0 .. sig_len - 1], msg, kp.pk, "c", .sha3_384));
    try std.testing.expect(!Scheme.verifyPrehash("", msg, kp.pk, "c", .sha3_384));
}
