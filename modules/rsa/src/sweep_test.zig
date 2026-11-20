// SPDX-License-Identifier: MIT
//! No-panic sweep tests (wave GP). Each test names the finding it kills.

const std = @import("std");
const rsa = @import("root.zig");

/// The tests here run on 512-bit and smaller keys (`testKey`, hand-made primes):
/// the testing-only escape from the 1024-bit floors.
const small: rsa.SecretKey.FromPrimesOptions = .{ .insecure_allow_small_modulus = true };
const small_pub: rsa.PublicKeyOptions = .{ .insecure_allow_small_modulus = true };

fn testKey() !rsa.KeyPair {
    var prng = std.Random.DefaultPrng.init(0x5eed_9b01);
    var kp: rsa.KeyPair = undefined;
    try rsa.generateWith(&kp, prng.random(), 512, 65537, small_pub);
    return kp;
}

test "fromDer: a bare PKCS#1 key and a plain SPKI parse; an SPKI inside an SPKI is rejected, at any depth (sweep RS-1)" {
    // 1024 bits: the smallest key the default constructors accept.
    var prng0 = std.Random.DefaultPrng.init(0x5eed_9b02);
    var kp: rsa.KeyPair = undefined;
    try rsa.generate(&kp, prng0.random(), 1024, 65537);
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
    try std.testing.expectError(error.InvalidPrivateKey, rsa.SecretKey.fromPrimesWith(&sk, p, q, &e5, small));
    // Leading zeros do not make a small e big; 65537 with padding still works.
    try rsa.SecretKey.fromPrimesWith(&sk, p, q, &.{ 0, 0, 0x01, 0x00, 0x01 }, small);
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
    // reason alone. Each verdict is predicted independently: e is invertible
    // mod lambda(n) iff gcd(e, p - 1) = gcd(e, q - 1) = 1, and gcd(e, x) =
    // gcd(e, x mod e). Every accepted key must carry e and round-trip RSAEP/RSADP.
    var accepted: usize = 0;
    var refused: usize = 0;
    for ([_]u32{ 0xFFFF_FFFF, 0x8000_0001, 0x1000_0001, 0x1234_5679, 0xCAFE_BABF, 0x0100_0003 }) |e| {
        var eb: [4]u8 = undefined;
        std.mem.writeInt(u32, &eb, e, .big);
        const want = std.math.gcd(e, minusOneMod(p, e)) == 1 and std.math.gcd(e, minusOneMod(q, e)) == 1;
        var sk: rsa.SecretKey = undefined;
        if (rsa.SecretKey.fromPrimesWith(&sk, p, q, &eb, small)) {
            defer sk.deinit();
            if (!want) {
                std.debug.print("e=0x{x} accepted but gcd(e, lambda) != 1\n", .{e});
                return error.TestUnexpectedResult;
            }
            accepted += 1;
            try std.testing.expectEqual(e, try sk.e.toPrimitive(u32));
            var m: [64]u8 = @splat(0);
            m[63] = 0x2a;
            m[1] = 0x5c;
            const c = try rsa.rsaep(64, m, sk.publicKey());
            try std.testing.expectEqualSlices(u8, &m, &(try rsa.rsadp(64, c, &sk)));
        } else |err| {
            try std.testing.expectEqual(error.InvalidPrivateKey, err);
            if (want) {
                std.debug.print("e=0x{x} refused but gcd(e, lambda) = 1\n", .{e});
                return error.TestUnexpectedResult;
            }
            refused += 1;
        }
    }
    // Both verdicts occur over this fixed key, so neither branch is vacuous.
    try std.testing.expect(accepted >= 1);
    try std.testing.expect(refused >= 1);
}

/// (x - 1) mod e for a big-endian x >= 1 (u128 intermediates; e < 2^32).
fn minusOneMod(x: []const u8, e: u32) u64 {
    var r: u64 = 0;
    for (x) |b| r = @intCast(((@as(u128, r) << 8) | b) % e);
    return (r + e - 1) % e;
}

// ── mutation audit 2026-11-13 (delta over bb4efd9a9): tests asked for by survivors ──

test "bigModInverse: a value sharing a factor with the modulus has no inverse (mutation audit)" {
    var arena_state = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena_state.deinit();
    const a = arena_state.allocator();
    var e2 = try std.math.big.int.Managed.initSet(a, 2);
    var m4 = try std.math.big.int.Managed.initSet(a, 4);
    try std.testing.expectError(error.InvalidPrivateKey, rsa.bigModInverse(a, &e2, &m4));
}

test "fromPrimes: empty, zero, one and even exponents, a composite p, p == q and a product past the size cap are refused (mutation audit)" {
    var kp = try testKey();
    defer kp.secret_key.deinit();
    var pb: [64]u8 = undefined;
    var qb: [64]u8 = undefined;
    const p = primeBytes(kp.secret_key.p, &pb);
    const q = primeBytes(kp.secret_key.q, &qb);
    var sk: rsa.SecretKey = undefined;
    const bad_e = [_][]const u8{ &.{}, &.{0}, &.{ 0, 0 }, &.{1}, &.{ 0, 0, 1 }, &.{4}, &.{ 1, 0, 0 } };
    for (bad_e) |e| try std.testing.expectError(error.InvalidPrivateKey, rsa.SecretKey.fromPrimesWith(&sk, p, q, e, small));
    // 15 is not prime: only the final q * q^-1 = 1 (mod p) check sees it.
    try std.testing.expectError(error.InvalidPrivateKey, rsa.SecretKey.fromPrimesWith(&sk, &.{15}, &.{7}, &.{5}, small));
    try std.testing.expectError(error.InvalidPrivateKey, rsa.SecretKey.fromPrimesWith(&sk, p, p, &.{ 1, 0, 1 }, small));

    // p * q past max_modulus_bits: q need not be prime for the derivation to run
    // on, so only the size check stops it (the product would be cut to 8192 bits).
    var big_q: [rsa.max_modulus_len]u8 = @splat(0xB7);
    var refused: usize = 0;
    var tried: usize = 0;
    for ([_]u8{ 3, 5, 7, 11, 13, 17 }) |e| {
        tried += 1;
        if (rsa.SecretKey.fromPrimesWith(&sk, p, &big_q, &.{e}, small)) {
            sk.deinit();
            return error.AcceptedAnOversizedModulus;
        } else |err| {
            try std.testing.expectEqual(error.InvalidPrivateKey, err);
            refused += 1;
        }
    }
    try std.testing.expectEqual(tried, refused);
}

test "fromPrimes: leading zeros on p, q and e, however many, do not change the key (mutation audit)" {
    var kp = try testKey();
    defer kp.secret_key.deinit();
    var pb: [64]u8 = undefined;
    var qb: [64]u8 = undefined;
    const p = primeBytes(kp.secret_key.p, &pb);
    const q = primeBytes(kp.secret_key.q, &qb);
    var pad_p: [rsa.max_modulus_len + 40]u8 = @splat(0);
    var pad_q: [rsa.max_modulus_len + 40]u8 = @splat(0);
    @memcpy(pad_p[pad_p.len - p.len ..], p);
    @memcpy(pad_q[pad_q.len - q.len ..], q);
    var sk: rsa.SecretKey = undefined;
    try rsa.SecretKey.fromPrimesWith(&sk, &pad_p, q, &.{ 1, 0, 1 }, small);
    sk.deinit();
    try rsa.SecretKey.fromPrimesWith(&sk, p, &pad_q, &.{ 1, 0, 1 }, small);
    sk.deinit();
}

fn mulmod256(a: u512, b: u512, m: u512) u512 {
    return @intCast((@as(u1024, a) * b) % m);
}

fn powmod256(base: u512, exp: u512, m: u512) u512 {
    var r: u512 = 1;
    var b = base % m;
    var e = exp;
    while (e != 0) : (e >>= 1) {
        if (e & 1 == 1) r = mulmod256(r, b, m);
        b = mulmod256(b, b, m);
    }
    return r;
}

/// Miller-Rabin with the first twelve primes as bases (exact below 3.3e24; above that
/// a composite would have to be a strong pseudoprime to all twelve).
fn isPrimeWide(n: u512) bool {
    const bases = [_]u512{ 2, 3, 5, 7, 11, 13, 17, 19, 23, 29, 31, 37 };
    for (bases) |b| {
        if (n == b) return true;
        if (n % b == 0) return false;
    }
    var t: u512 = 41;
    while (t < 2000) : (t += 2) {
        if (n % t == 0) return false;
    }
    var d = n - 1;
    var s: u32 = 0;
    while (d & 1 == 0) : (d >>= 1) s += 1;
    outer: for (bases) |b| {
        var x = powmod256(b, d, n);
        if (x == 1 or x == n - 1) continue;
        var i: u32 = 1;
        while (i < s) : (i += 1) {
            x = mulmod256(x, x, n);
            if (x == n - 1) continue :outer;
        }
        return false;
    }
    return true;
}

test "BlindingCache: shared between keys that differ only in the second prime, or in the order of the same two primes, it never serves a pair drawn for another key (mutation audit)" {
    // Three primes p, q, q2 of 65..70 bits that share their low 64-bit limb: the
    // keys (p,q) and (q,p) have the same n and e and primes that differ only in
    // the upper limb; (p,q) and (p,q2) share the first prime but not n.
    var primes: [3]u128 = undefined;
    var found: usize = 0;
    var a: u128 = 1;
    while (found < 3) : (a += 1) {
        const cand = (a << 64) | 0x9e37_79b9_7f4a_7c15;
        if (!isPrimeWide(cand) or (cand - 1) % 65537 == 0) continue;
        primes[found] = cand;
        found += 1;
    }
    var pbuf: [3][16]u8 = undefined;
    for (primes, 0..) |v, i| std.mem.writeInt(u128, &pbuf[i], v, .big);
    const e: []const u8 = &.{ 1, 0, 1 };
    var ska: rsa.SecretKey = undefined; // (p, q)
    var skb: rsa.SecretKey = undefined; // (q, p)
    var skc: rsa.SecretKey = undefined; // (p, q2)
    try rsa.SecretKey.fromPrimesWith(&ska, &pbuf[0], &pbuf[1], e, small);
    defer ska.deinit();
    try rsa.SecretKey.fromPrimesWith(&skb, &pbuf[1], &pbuf[0], e, small);
    defer skb.deinit();
    try rsa.SecretKey.fromPrimesWith(&skc, &pbuf[0], &pbuf[2], e, small);
    defer skc.deinit();

    var m24: [24]u8 = @splat(0);
    std.mem.writeInt(u128, m24[8..], 0x0123_4567_89ab_cdef_0123_4567_89ab_cdef, .big);
    const keys = [_]*const rsa.SecretKey{ &ska, &ska, &skb, &skb, &ska, &skc, &skc, &ska, &skb, &skc };
    var prng = std.Random.DefaultPrng.init(0xb11d);
    var cache = rsa.BlindingCache.init(prng.random());
    defer cache.deinit();
    for (keys) |sk| {
        const c = try rsa.rsaep(24, m24, sk.publicKey());
        const got = try rsa.rsadpCrtBlinded(24, c, sk, .{ .cached = &cache });
        try std.testing.expectEqualSlices(u8, &m24, &got);
    }
}

test "BlindingCache: a shorter key whose modulus equals the cached one in its low limbs is not served the cached pair (mutation audit)" {
    // X = (p, q) and W = (p, q2) with q = q2 + 2^256: the same first prime and
    // e, n_W = n_X mod 2^256, but n_W has four limbs (one 256-bit slot) and n_X eight. After W the
    // cache holds W's four limbs over X's stale upper ones, so only the limb
    // count tells the cache that the pair it holds is not X's.
    var p: u128 = 0;
    var a: u128 = 1;
    while (true) : (a += 1) {
        const cand = (a << 64) | 0x9e37_79b9_7f4a_7c15;
        if (isPrimeWide(cand) and (cand - 1) % 65537 != 0) {
            p = cand;
            break;
        }
    }
    const q2: u512 = 1_000_003;
    var q: u512 = 0;
    var k: u512 = 1;
    while (true) : (k += 1) {
        const cand = q2 + (k << 256);
        if (isPrimeWide(cand) and (cand - 1) % 65537 != 0) {
            q = cand;
            break;
        }
    }
    var pb: [16]u8 = undefined;
    std.mem.writeInt(u128, &pb, p, .big);
    var qb: [64]u8 = undefined;
    std.mem.writeInt(u512, &qb, q, .big);
    var q2b: [64]u8 = undefined;
    std.mem.writeInt(u512, &q2b, q2, .big);
    const e: []const u8 = &.{ 1, 0, 1 };
    var skx: rsa.SecretKey = undefined;
    var skw: rsa.SecretKey = undefined;
    try rsa.SecretKey.fromPrimesWith(&skx, &pb, &qb, e, small);
    defer skx.deinit();
    try rsa.SecretKey.fromPrimesWith(&skw, &pb, &q2b, e, small);
    defer skw.deinit();

    var m48: [48]u8 = @splat(0);
    std.mem.writeInt(u64, m48[40..], 0x0123_4567_89ab_cdef, .big);
    var prng = std.Random.DefaultPrng.init(0xb12d);
    var cache = rsa.BlindingCache.init(prng.random());
    defer cache.deinit();
    for ([_]*const rsa.SecretKey{ &skx, &skw, &skx, &skx, &skw, &skx }) |sk| {
        const c = try rsa.rsaep(48, m48, sk.publicKey());
        const got = try rsa.rsadpCrtBlinded(48, c, sk, .{ .cached = &cache });
        try std.testing.expectEqualSlices(u8, &m48, &got);
    }
}

/// A generator that always writes `fill_byte`; counts the modulus-length
/// draws and panics past 10_000 so an unbounded redraw loop fails fast.
const StuckRandom = struct {
    fill_byte: u8,
    n_len: usize,
    draws: usize = 0,
    fn fill(self: *StuckRandom, buf: []u8) void {
        @memset(buf, self.fill_byte);
        if (buf.len != self.n_len) return;
        self.draws += 1;
        if (self.draws > 10_000) @panic("drawBlindingPair: unbounded redraw loop");
    }
    fn random(self: *StuckRandom) std.Random {
        return std.Random.init(self, fill);
    }
};

test "a blinding generator that only yields zeros or values >= n is error.EntropyFailure after 128 draws, on every blinded entry (sweep BRSA-3)" {
    var kp = try testKey();
    defer kp.secret_key.deinit();
    const sk = &kp.secret_key;
    const k = 64;
    var c: [k]u8 = @splat(0);
    c[k - 1] = 0x2a;
    // 0x00: r == 0; 0xff: r >= n (the top byte is masked to n's bit length,
    // so all-ones is still >= n).
    for ([_]u8{ 0x00, 0xff }) |byte| {
        var g = StuckRandom{ .fill_byte = byte, .n_len = k };
        try std.testing.expectError(error.EntropyFailure, rsa.rsadpCrtBlinded(k, c, sk, .{ .csprng = g.random() }));
        try std.testing.expectEqual(@as(usize, 128), g.draws);

        var g2 = StuckRandom{ .fill_byte = byte, .n_len = k };
        var cache = rsa.BlindingCache.init(g2.random());
        defer cache.deinit();
        try std.testing.expectError(error.EntropyFailure, rsa.rsadpCrtBlinded(k, c, sk, .{ .cached = &cache }));
        try std.testing.expectEqual(@as(usize, 128), g2.draws);

        var g3 = StuckRandom{ .fill_byte = byte, .n_len = k };
        var sig: [k]u8 = undefined;
        try std.testing.expectError(error.EntropyFailure, rsa.signPss(sk, std.crypto.hash.sha2.Sha256, g3.random(), "m", 8, &sig));
        try std.testing.expectEqual(@as(usize, 128), g3.draws); // the salt draw is shorter than n_len

        var g4 = StuckRandom{ .fill_byte = byte, .n_len = k };
        try std.testing.expectError(error.EntropyFailure, rsa.signPkcs1v15Blinded(sk, std.crypto.hash.sha2.Sha256, .{ .csprng = g4.random() }, "m", &sig));
        try std.testing.expectEqual(@as(usize, 128), g4.draws);
    }
}

test "a failed draw leaves a BlindingCache usable once the generator recovers (sweep BRSA-3)" {
    var kp = try testKey();
    defer kp.secret_key.deinit();
    const sk = &kp.secret_key;
    const k = 64;
    var c: [k]u8 = @splat(0);
    c[k - 1] = 0x2a;
    // 200 stuck draws, then the real generator.
    const Recovering = struct {
        inner: std.Random,
        stuck_left: usize,
        fn fill(self: *@This(), buf: []u8) void {
            if (self.stuck_left > 0) {
                self.stuck_left -= 1;
                @memset(buf, 0);
                return;
            }
            self.inner.bytes(buf);
        }
    };
    var prng = std.Random.DefaultPrng.init(0x3b5a);
    var rec = Recovering{ .inner = prng.random(), .stuck_left = 200 };
    var cache = rsa.BlindingCache.init(std.Random.init(&rec, Recovering.fill));
    defer cache.deinit();
    try std.testing.expectError(error.EntropyFailure, rsa.rsadpCrtBlinded(k, c, sk, .{ .cached = &cache }));
    try std.testing.expectEqual(@as(usize, 72), rec.stuck_left);
    // The next op consumes the 72 remaining zero draws, then succeeds.
    const want = try rsa.rsadpCrt(k, c, sk);
    const got = try rsa.rsadpCrtBlinded(k, c, sk, .{ .cached = &cache });
    try std.testing.expectEqualSlices(u8, &want, &got);
}

test "an honest generator never hits the draw bound, even for a modulus whose top byte is small (sweep BRSA-3)" {
    // 514-bit key: n_len = 65, top byte 0x02 or 0x03. Without masking the
    // draw to n's bit length only ~1/128 of the draws would be < n and 128
    // draws would fail about a third of the time.
    var prng = std.Random.DefaultPrng.init(0x5eed_514);
    var kp: rsa.KeyPair = undefined;
    try rsa.generateWith(&kp, prng.random(), 514, 65537, small_pub);
    defer kp.secret_key.deinit();
    const sk = &kp.secret_key;
    const k = 65;
    var c: [k]u8 = @splat(0);
    c[k - 1] = 0x2a;
    const want = try rsa.rsadpCrt(k, c, sk);
    for (0..60) |_| {
        const got = try rsa.rsadpCrtBlinded(k, c, sk, .{ .csprng = prng.random() });
        try std.testing.expectEqualSlices(u8, &want, &got);
    }
}

test "a failed draw does not make an exhausted BlindingCache pair look fresh: the next op redraws (sweep BRSA-3)" {
    var kp = try testKey();
    defer kp.secret_key.deinit();
    const sk = &kp.secret_key;
    const k = 64;
    var c: [k]u8 = @splat(0);
    c[k - 1] = 0x2a;
    const Switch = struct {
        inner: std.Random,
        stuck: bool = false,
        draws: usize = 0,
        fn fill(self: *@This(), buf: []u8) void {
            if (buf.len == k and !self.stuck) self.draws += 1;
            if (self.stuck) @memset(buf, 0) else self.inner.bytes(buf);
        }
    };
    var prng = std.Random.DefaultPrng.init(0x3b5b);
    var sw = Switch{ .inner = prng.random() };
    var cache = rsa.BlindingCache.init(std.Random.init(&sw, Switch.fill));
    defer cache.deinit();
    // refresh_every ops use up the pair (one draw), `left` is then 0.
    for (0..rsa.BlindingCache.refresh_every) |_| _ = try rsa.rsadpCrtBlinded(k, c, sk, .{ .cached = &cache });
    try std.testing.expectEqual(@as(usize, 1), sw.draws);
    sw.stuck = true;
    try std.testing.expectError(error.EntropyFailure, rsa.rsadpCrtBlinded(k, c, sk, .{ .cached = &cache }));
    sw.stuck = false;
    sw.draws = 0;
    _ = try rsa.rsadpCrtBlinded(k, c, sk, .{ .cached = &cache });
    // The exhausted pair must not be served again: a fresh draw happened.
    try std.testing.expect(sw.draws >= 1);
}

// ── 2026-11-18: the 1024-bit private-key floor (Go 1.24 `rsa1024min`) ──

test "private-key floor: 1024 bits pass, 1023 are refused by fromPrimes and every parser; the escape admits them" {
    var prng = std.Random.DefaultPrng.init(0x1024_f100);
    var k1024: rsa.KeyPair = undefined;
    try rsa.generate(&k1024, prng.random(), 1024, 65537); // two 512-bit primes, top two bits set
    defer k1024.secret_key.deinit();
    var k1022: rsa.KeyPair = undefined;
    try rsa.generateWith(&k1022, prng.random(), 1022, 65537, small_pub); // below the floor: needs the escape
    defer k1022.secret_key.deinit();
    var pb: [64]u8 = undefined;
    var qb: [64]u8 = undefined;
    var q2b: [64]u8 = undefined;
    const p = primeBytes(k1024.secret_key.p, &pb);
    const q = primeBytes(k1024.secret_key.q, &qb);
    // A 512-bit and a 511-bit prime (both >= 0.75 * 2^bits): a 1023-bit modulus.
    const q511 = primeBytes(k1022.secret_key.q, &q2b);
    const e: []const u8 = &.{ 1, 0, 1 };

    var sk: rsa.SecretKey = undefined;
    try rsa.SecretKey.fromPrimes(&sk, p, q, e);
    try std.testing.expectEqual(@as(usize, 1024), sk.n.bits());
    var der_buf: [rsa.max_pkcs8_der_len]u8 = undefined;
    var back: rsa.SecretKey = undefined;
    try rsa.SecretKey.fromDer(&back, try sk.toPkcs1Der(&der_buf));
    back.deinit();
    sk.deinit();

    @memset(std.mem.asBytes(&sk), 0xaa);
    try std.testing.expectError(error.InvalidPrivateKey, rsa.SecretKey.fromPrimes(&sk, p, q511, e));
    for (std.mem.asBytes(&sk)) |b| try std.testing.expectEqual(@as(u8, 0), b); // wiped on refusal
    @memset(std.mem.asBytes(&sk), 0xaa);
    try std.testing.expectError(error.InvalidPrivateKey, rsa.SecretKey.fromPrimesWith(&sk, p, q511, e, .{}));
    for (std.mem.asBytes(&sk)) |b| try std.testing.expectEqual(@as(u8, 0), b);

    var small_sk: rsa.SecretKey = undefined;
    try rsa.SecretKey.fromPrimesWith(&small_sk, p, q511, e, small);
    defer small_sk.deinit();
    try std.testing.expectEqual(@as(usize, 1023), small_sk.n.bits());
    // Its own encodings do not load back: every private-key parser holds the floor.
    try std.testing.expectError(error.InvalidPrivateKey, rsa.SecretKey.fromDer(&back, try small_sk.toPkcs1Der(&der_buf)));
    try std.testing.expectError(error.InvalidPrivateKey, rsa.fromPkcs8(&back, try small_sk.toPkcs8Der(&der_buf)));
    var pem_buf: [rsa.max_private_pem_len]u8 = undefined;
    try std.testing.expectError(error.InvalidPrivateKey, rsa.SecretKey.fromPem(&back, try small_sk.toPem(.pkcs1, &pem_buf)));
    try std.testing.expectError(error.InvalidPrivateKey, rsa.SecretKey.fromPem(&back, try small_sk.toPem(.pkcs8, &pem_buf)));
    try std.testing.expectError(error.InvalidPrivateKey, rsa.SecretKey.fromPemEncrypted(&back, try small_sk.toPem(.pkcs1, &pem_buf), ""));
    // The public half is a plain struct copy (no parse): it keeps its size.
    const pk = small_sk.publicKey();
    try std.testing.expectEqual(@as(usize, 1023), pk.bits());
}

// ── 2026-11-19: the 1024-bit floor on generate and public keys (Go 1.24) ──

test "public-key floor: 1023 bits refused by every public constructor, 1024 accepted; the escape admits 512 up" {
    var prng = std.Random.DefaultPrng.init(0x1024_f101);
    var k1024: rsa.KeyPair = undefined;
    try rsa.generate(&k1024, prng.random(), 1024, 65537);
    defer k1024.secret_key.deinit();
    var k1022: rsa.KeyPair = undefined;
    try rsa.generateWith(&k1022, prng.random(), 1022, 65537, small_pub);
    defer k1022.secret_key.deinit();
    // A 1023-bit modulus: 512-bit p times 511-bit q.
    var pb: [64]u8 = undefined;
    var q2b: [64]u8 = undefined;
    var sk23: rsa.SecretKey = undefined;
    try rsa.SecretKey.fromPrimesWith(&sk23, primeBytes(k1024.secret_key.p, &pb), primeBytes(k1022.secret_key.q, &q2b), &.{ 1, 0, 1 }, small);
    defer sk23.deinit();
    const pk23 = sk23.publicKey();
    try std.testing.expectEqual(@as(usize, 1023), pk23.bits());

    var n23: [128]u8 = undefined;
    var n24: [128]u8 = undefined;
    try sk23.n.toBytes(&n23, .big);
    try k1024.secret_key.n.toBytes(&n24, .big);
    const e: []const u8 = &.{ 1, 0, 1 };

    // 1024: every constructor, default options.
    try std.testing.expectEqual(@as(usize, 1024), (try rsa.PublicKey.fromBytes(&n24, e)).bits());
    try std.testing.expectEqual(@as(usize, 1024), (try rsa.VerifyKey.fromBytes(&n24, e)).bits());
    var d1: [rsa.max_pkcs1_public_der_len]u8 = undefined;
    var d2: [rsa.max_spki_der_len]u8 = undefined;
    var pem: [rsa.max_public_pem_len]u8 = undefined;
    _ = try rsa.PublicKey.fromDer(try k1024.public_key.toPkcs1Der(&d1));
    _ = try rsa.PublicKey.fromDer(try k1024.public_key.toSpkiDer(&d2));
    _ = try rsa.VerifyKey.fromDer(try k1024.public_key.toSpkiDer(&d2));
    _ = try rsa.PublicKey.fromPem(try k1024.public_key.toPem(.spki, &pem));

    // 1023: refused everywhere by default ...
    try std.testing.expectError(error.InvalidPublicKey, rsa.PublicKey.fromBytes(&n23, e));
    try std.testing.expectError(error.InvalidPublicKey, rsa.VerifyKey.fromBytes(&n23, e));
    const der1 = try pk23.toPkcs1Der(&d1);
    try std.testing.expectError(error.InvalidDer, rsa.PublicKey.fromDer(der1));
    try std.testing.expectError(error.InvalidDer, rsa.VerifyKey.fromDer(der1));
    try std.testing.expectError(error.InvalidDer, rsa.PublicKey.fromDer(try pk23.toSpkiDer(&d2)));
    try std.testing.expectError(error.InvalidDer, rsa.VerifyKey.fromDer(try pk23.toSpkiDer(&d2)));
    try std.testing.expectError(error.InvalidDer, rsa.PublicKey.fromPem(try pk23.toPem(.spki, &pem)));
    try std.testing.expectError(error.InvalidDer, rsa.PublicKey.fromPem(try pk23.toPem(.pkcs1, &pem)));
    // ... and admitted by the escape on each of them.
    try std.testing.expectEqual(@as(usize, 1023), (try rsa.PublicKey.fromBytesWith(&n23, e, small_pub)).bits());
    try std.testing.expectEqual(@as(usize, 1023), (try rsa.VerifyKey.fromBytesWith(&n23, e, small_pub)).bits());
    try std.testing.expect((try rsa.PublicKey.fromDerWith(der1, small_pub)).equal(&pk23));
    try std.testing.expectEqual(@as(usize, 1023), (try rsa.VerifyKey.fromDerWith(der1, small_pub)).bits());
    try std.testing.expect((try rsa.PublicKey.fromPemWith(try pk23.toPem(.spki, &pem), small_pub)).equal(&pk23));

    // The escape has its own floor: 511 bits stays refused.
    var n511: [64]u8 = @splat(0xff);
    n511[0] = 0x7f;
    n511[63] = 0xfd;
    try std.testing.expectError(error.InvalidPublicKey, rsa.PublicKey.fromBytesWith(&n511, e, small_pub));
    try std.testing.expectError(error.InvalidPublicKey, rsa.VerifyKey.fromBytesWith(&n511, e, small_pub));
}

test "generate: below 1024 bits is InvalidBits, 1024 works, the escape generates 512 and its public half loads only through the escape" {
    var prng = std.Random.DefaultPrng.init(0x1024_f102);
    var kp: rsa.KeyPair = undefined;
    try std.testing.expectError(error.InvalidBits, rsa.generate(&kp, prng.random(), 1022, 65537));
    try std.testing.expectError(error.InvalidBits, rsa.generate(&kp, prng.random(), 512, 65537));
    try std.testing.expectError(error.InvalidBits, rsa.generateWith(&kp, prng.random(), 510, 65537, small_pub));
    for (std.mem.asBytes(&kp)) |b| try std.testing.expectEqual(@as(u8, 0), b); // wiped on refusal
    try rsa.generate(&kp, prng.random(), 1024, 65537);
    kp.secret_key.deinit();
    try rsa.generateWith(&kp, prng.random(), 1024, 65537, .{}); // the default options are `generate`
    kp.secret_key.deinit();

    try rsa.generateWith(&kp, prng.random(), 512, 65537, small_pub);
    defer kp.secret_key.deinit();
    try std.testing.expectEqual(@as(usize, 512), kp.public_key.bits());
    var der: [rsa.max_spki_der_len]u8 = undefined;
    const spki = try kp.public_key.toSpkiDer(&der);
    try std.testing.expectError(error.InvalidDer, rsa.PublicKey.fromDer(spki));
    try std.testing.expect((try rsa.PublicKey.fromDerWith(spki, small_pub)).equal(&kp.public_key));
}
