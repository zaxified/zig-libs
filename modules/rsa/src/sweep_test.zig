// SPDX-License-Identifier: MIT
//! No-panic sweep tests (wave GP). Each test names the finding it kills.

const std = @import("std");
const rsa = @import("root.zig");

fn testKey() !rsa.KeyPair {
    var prng = std.Random.DefaultPrng.init(0x5eed_9b01);
    var kp: rsa.KeyPair = undefined;
    try rsa.generate(&kp, prng.random(), 512, 65537);
    return kp;
}

test "fromDer: a bare PKCS#1 key and a plain SPKI parse; an SPKI inside an SPKI is rejected, at any depth (sweep RS-1)" {
    var kp = try testKey();
    defer kp.secret_key.deinit();
    var b1: [rsa.max_pkcs1_public_der_len]u8 = undefined;
    var b2: [rsa.max_spki_der_len]u8 = undefined;
    const pkcs1 = try kp.public_key.toPkcs1Der(&b1);
    const spki = try kp.public_key.toSpkiDer(&b2);

    // Pinned: what is accepted today stays accepted.
    try std.testing.expect((try rsa.PublicKey.fromDer(pkcs1)).equal(&kp.public_key));
    try std.testing.expect((try rsa.PublicKey.fromDer(spki)).equal(&kp.public_key));
    _ = try rsa.VerifyKey.fromDer(pkcs1);
    _ = try rsa.VerifyKey.fromDer(spki);

    // SPKI(BIT STRING(SPKI)) used to recurse, one level per wrapper.
    var arena_state = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena_state.deinit();
    const d: rsa.der_writer.Builder = .{ .a = arena_state.allocator() };
    var cur: []const u8 = spki;
    for (0..40) |depth| {
        const alg = try d.seq(&.{ try d.oid(&.{ 0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01, 0x01 }), try d.null() });
        cur = try d.seq(&.{ alg, try d.bitString(cur) });
        try std.testing.expectError(error.InvalidDer, rsa.PublicKey.fromDer(cur));
        try std.testing.expectError(error.InvalidDer, rsa.VerifyKey.fromDer(cur));
        _ = depth;
    }
}

test "rsa primitives: a modulus_len below the key's modulus length is an error, not a panic or a truncation (sweep RS-2)" {
    var kp = try testKey();
    defer kp.secret_key.deinit();
    const short: [32]u8 = @splat(0x01);
    try std.testing.expectError(error.MessageRepresentativeOutOfRange, rsa.rsaep(32, short, kp.public_key));
    try std.testing.expectError(error.MessageRepresentativeOutOfRange, rsa.rsavp1(32, short, kp.public_key));
    try std.testing.expectError(error.MessageRepresentativeOutOfRange, rsa.rsadp(32, short, &kp.secret_key));
    try std.testing.expectError(error.MessageRepresentativeOutOfRange, rsa.rsadpCrt(32, short, &kp.secret_key));
    try std.testing.expectError(error.MessageRepresentativeOutOfRange, rsa.rsadpCrtBlinded(32, short, &kp.secret_key, .none));
    try std.testing.expectError(error.MessageRepresentativeOutOfRange, rsa.rsasp1(32, short, &kp.secret_key));

    // The exact length and a wider one still work (blindrsa uses the wide form).
    const m64: [64]u8 = .{0} ++ @as([63]u8, @splat(0x02));
    const c64 = try rsa.rsaep(64, m64, kp.public_key);
    try std.testing.expectEqual(m64, try rsa.rsadpCrt(64, c64, &kp.secret_key));
    const m96: [96]u8 = @as([32]u8, @splat(0)) ++ m64;
    const c96 = try rsa.rsaep(96, m96, kp.public_key);
    try std.testing.expectEqualSlices(u8, &c64, c96[32..]);
}

test "emsaPssEncode: em.len != ceil(em_bits/8) is an error, not an assert (sweep RS-3)" {
    const Sha256 = std.crypto.hash.sha2.Sha256;
    var em65: [65]u8 = undefined;
    try std.testing.expectError(error.EncodedMessageTooShort, rsa.emsaPssEncode(Sha256, "m", "", 511, &em65));
    var em63: [63]u8 = undefined;
    try std.testing.expectError(error.EncodedMessageTooShort, rsa.emsaPssEncode(Sha256, "m", "", 511, &em63));
    var em64: [64]u8 = undefined;
    try rsa.emsaPssEncode(Sha256, "m", "", 511, &em64);
    try std.testing.expectEqual(@as(u8, 0xbc), em64[63]);
}

test "bigModInverse: a zero modulus is an error, not a divide-by-zero panic (sweep RS-4)" {
    var arena_state = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena_state.deinit();
    const a = arena_state.allocator();
    var e = try std.math.big.int.Managed.initSet(a, 1);
    var m = try std.math.big.int.Managed.initSet(a, 0);
    try std.testing.expectError(error.InvalidPrivateKey, rsa.bigModInverse(a, &e, &m));
    var m7 = try std.math.big.int.Managed.initSet(a, 7);
    var e3 = try std.math.big.int.Managed.initSet(a, 3);
    const inv = try rsa.bigModInverse(a, &e3, &m7);
    try std.testing.expect(inv.toConst().orderAgainstScalar(5) == .eq);
}

fn primeBytes(m: anytype, buf: []u8) []const u8 {
    const n = (m.bits() + 7) / 8;
    m.toBytes(buf[0..n], .big) catch unreachable;
    return buf[0..n];
}

test "fromPrimes and the DER parsers reject e >= 2^32 (sweep REV-RS-1)" {
    var kp = try testKey();
    defer kp.secret_key.deinit();
    var pb: [64]u8 = undefined;
    var qb: [64]u8 = undefined;
    const p = primeBytes(kp.secret_key.p, &pb);
    const q = primeBytes(kp.secret_key.q, &qb);
    const e5 = [_]u8{ 0x01, 0x00, 0x00, 0x00, 0x01 }; // 2^32 + 1: odd, > u32
    var sk: rsa.SecretKey = undefined;
    try std.testing.expectError(error.InvalidPrivateKey, rsa.SecretKey.fromPrimes(&sk, p, q, &e5));
    // Leading zeros do not make a small e big; 65537 with padding still works.
    try rsa.SecretKey.fromPrimes(&sk, p, q, &.{ 0, 0, 0x01, 0x00, 0x01 });
    sk.deinit();

    // The same e inside a PKCS#1 RSAPrivateKey: the other fields only have to be INTEGERs.
    var arena_state = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena_state.deinit();
    const d: rsa.der_writer.Builder = .{ .a = arena_state.allocator() };
    const one = try d.integerU64(1);
    const der = try d.seq(&.{
        try d.integerU64(0), one, try d.integer(&e5), one, try d.integer(p), try d.integer(q), one, one, one,
    });
    try std.testing.expectError(error.InvalidPrivateKey, rsa.SecretKey.fromDer(&sk, der));
}

test "maxPssSaltLen / emsaPssEncode with extreme bit counts do not overflow (sweep REV-RS-3)" {
    const Sha256 = std.crypto.hash.sha2.Sha256;
    _ = rsa.maxPssSaltLen(std.math.maxInt(usize), Sha256);
    _ = rsa.maxPssSaltLen(std.math.maxInt(usize) - 6, Sha256);
    var em: [64]u8 = undefined;
    try std.testing.expectError(error.EncodedMessageTooShort, rsa.emsaPssEncode(Sha256, "m", "", std.math.maxInt(usize), &em));
}

test "fromPrimes accepts a four-byte public exponent below 2^32 (sweep audit GP-RS-1)" {
    var kp = try testKey();
    defer kp.secret_key.deinit();
    var pb: [64]u8 = undefined;
    var qb: [64]u8 = undefined;
    const p = primeBytes(kp.secret_key.p, &pb);
    const q = primeBytes(kp.secret_key.q, &qb);
    // Odd 32-bit values; an e sharing a factor with lambda(n) is refused for that
    // reason alone, so try a few. The key is fixed, so the outcome is deterministic.
    var accepted: usize = 0;
    for ([_]u32{ 0xFFFF_FFFF, 0x8000_0001, 0x1000_0001, 0x1234_5679, 0xCAFE_BABF, 0x0100_0003 }) |e| {
        var eb: [4]u8 = undefined;
        std.mem.writeInt(u32, &eb, e, .big);
        var sk: rsa.SecretKey = undefined;
        if (rsa.SecretKey.fromPrimes(&sk, p, q, &eb)) {
            accepted += 1;
            sk.deinit();
        } else |err| try std.testing.expectEqual(error.InvalidPrivateKey, err);
    }
    try std.testing.expect(accepted >= 1);
}
