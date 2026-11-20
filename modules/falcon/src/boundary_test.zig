// SPDX-License-Identifier: MIT
//! Boundary and model tests added by the whole-module mutation
//! audit. Every test here exists because a mutant of the module survived the
//! KAT, codec and fuzz suites: the verdicts are the ones a KAT cannot reach
//! (an exact-bound norm, a draw that lands on a rejection threshold, a
//! saturation that a real sampler almost never triggers, dead public
//! entry points).

const std = @import("std");
const falcon = @import("root.zig");
const poly = @import("poly.zig");
const codec = @import("codec.zig");
const fft = @import("fft.zig");
const fpr = @import("fpr.zig");
const gaussian = @import("gaussian.zig");
const ffsampling = @import("ffsampling.zig");
const sign = @import("sign.zig");

const q = poly.q;

// ---- hashToPoint against an independent model -------------------------------

fn modelHash(comptime Ring: type, nonce: []const u8, msg: []const u8, out: *Ring.Poly, seen: *[6]bool) void {
    var sh = std.crypto.hash.sha3.Shake256.init(.{});
    sh.update(nonce);
    sh.update(msg);
    var u: usize = 0;
    while (u < Ring.n) {
        var b: [2]u8 = undefined;
        sh.squeeze(&b);
        const w: u32 = std.mem.readInt(u16, &b, .big);
        const specials = [6]u32{ 61444, 61445, 12289, 24578, 36867, 49156 };
        for (specials, 0..) |s, i| {
            if (w == s) seen[i] = true;
        }
        if (w >= 61445) continue;
        out[u] = @intCast(w % q);
        u += 1;
    }
}

test "hashToPoint equals the independent model, including the 5q and multiple-of-q draws" {
    var seen: [6]bool = @splat(false);
    var prng = std.Random.DefaultPrng.init(0x4a5b);
    const random = prng.random();
    var nonce: [40]u8 = undefined;
    var msg: [24]u8 = undefined;
    var n: usize = 0;
    // Draws equal to 61444, 61445 or a multiple of q are 2^-16 events; keep
    // hashing until every one of them was met (bounded, deterministic seed).
    while (n < 20000) : (n += 1) {
        random.bytes(&nonce);
        random.bytes(&msg);
        var want512: poly.Ring512.Poly = undefined;
        var got512: poly.Ring512.Poly = undefined;
        modelHash(poly.Ring512, &nonce, &msg, &want512, &seen);
        codec.Codec512.hashToPoint(&nonce, &msg, &got512);
        try std.testing.expectEqualSlices(u16, &want512, &got512);
        var want1024: poly.Ring1024.Poly = undefined;
        var got1024: poly.Ring1024.Poly = undefined;
        modelHash(poly.Ring1024, &nonce, &msg, &want1024, &seen);
        codec.Codec1024.hashToPoint(&nonce, &msg, &got1024);
        try std.testing.expectEqualSlices(u16, &want1024, &got1024);
        if (std.mem.allEqual(bool, &seen, true) and n >= 300) break;
    }
    for (seen) |s| try std.testing.expect(s);
}

// ---- compEncode / compDecode edges -------------------------------------------

const BitWriter = struct {
    buf: [4096]u8 = @splat(0),
    nbits: usize = 0,

    fn put(self: *BitWriter, bit: u1) void {
        if (bit == 1) self.buf[self.nbits / 8] |= @as(u8, 0x80) >> @intCast(self.nbits % 8);
        self.nbits += 1;
    }

    /// One compressed coefficient: sign, 7 low bits, `hi` zeros, a one.
    fn coef(self: *BitWriter, sign_bit: u1, low: u8, hi: usize) void {
        self.put(sign_bit);
        var k: usize = 7;
        while (k > 0) : (k -= 1) self.put(@truncate(low >> @intCast(k - 1)));
        for (0..hi) |_| self.put(0);
        self.put(1);
    }

    fn bytes(self: *const BitWriter) []const u8 {
        return self.buf[0 .. (self.nbits + 7) / 8];
    }
};

test "compDecode: |s| = 2047 accepted, 2048 refused, exactly (both degrees)" {
    inline for (.{ codec.Codec512, codec.Codec1024 }) |C| {
        const n = C.modq_encoded_len * 8 / 14;
        var w = BitWriter{};
        w.coef(1, 127, 15); // -2047
        w.coef(0, 127, 15); // +2047
        for (2..n) |_| w.coef(0, 0, 0);
        var out: [n]i16 = undefined;
        try C.compDecode(&out, w.bytes());
        try std.testing.expectEqual(@as(i16, -2047), out[0]);
        try std.testing.expectEqual(@as(i16, 2047), out[1]);

        var w2 = BitWriter{};
        w2.coef(0, 0, 16); // 2048
        for (1..n) |_| w2.coef(0, 0, 0);
        try std.testing.expectError(error.InvalidEncoding, C.compDecode(&out, w2.bytes()));
        var w3 = BitWriter{};
        w3.coef(1, 0, 16); // -2048
        for (1..n) |_| w3.coef(0, 0, 0);
        try std.testing.expectError(error.InvalidEncoding, C.compDecode(&out, w3.bytes()));
        // +0 is a legal coefficient, -0 is not.
        var w4 = BitWriter{};
        for (0..n) |_| w4.coef(0, 0, 0);
        try C.compDecode(&out, w4.bytes());
    }
}

test "compEncode: +-2047 encode, -2048 is refused, and the output buffer fits exactly" {
    inline for (.{ codec.Codec512, codec.Codec1024 }) |C| {
        const n = C.modq_encoded_len * 8 / 14;
        var s: [n]i16 = undefined;
        for (&s, 0..) |*x, i| x.* = @intCast(@as(i32, @intCast((i * 37) % 301)) - 150);
        s[0] = -2047;
        s[1] = 2047;
        var big: [4096]u8 = undefined;
        const len = try C.compEncode(&big, &s);
        // exact fit works and equals the roomy encoding
        var exact: [4096]u8 = undefined;
        const len2 = try C.compEncode(exact[0..len], &s);
        try std.testing.expectEqual(len, len2);
        try std.testing.expectEqualSlices(u8, big[0..len], exact[0..len]);
        // one byte short fails
        try std.testing.expectError(error.NoSpaceLeft, C.compEncode(exact[0 .. len - 1], &s));
        // the encoder's own output decodes
        var back: [n]i16 = undefined;
        try C.compDecode(&back, big[0..len]);
        try std.testing.expectEqualSlices(i16, &s, &back);
        s[3] = -2048;
        try std.testing.expectError(error.CoefficientOutOfRange, C.compEncode(&big, &s));
        s[3] = 2048;
        try std.testing.expectError(error.CoefficientOutOfRange, C.compEncode(&big, &s));
        // an all-zero polynomial ends on a byte boundary (9 bits per coefficient, n % 8 == 0):
        // no spare byte may be written.
        const zeros: [n]i16 = @splat(0);
        const zl = try C.compEncode(&big, &zeros);
        try std.testing.expectEqual(n * 9 / 8, zl);
        try std.testing.expectError(error.NoSpaceLeft, C.compEncode(big[0 .. zl - 1], &zeros));
        _ = try C.compEncode(big[0..zl], &zeros);
        // a polynomial that leaves a partial last byte
        var t = zeros;
        t[0] = 1; // sign + 7 bits + stop = 9 bits: unchanged
        t[1] = 200; // one extra unary zero: 10 bits
        const tl = try C.compEncode(&big, &t);
        try std.testing.expectEqual(zl + 1, tl);
        try std.testing.expectError(error.NoSpaceLeft, C.compEncode(big[0 .. tl - 1], &t));
        var tback: [n]i16 = undefined;
        try C.compDecode(&tback, big[0..tl]);
        try std.testing.expectEqualSlices(i16, &t, &tback);
    }
}

// ---- verify: the norm bound is inclusive, and the centring is exact ------------

fn isqrt(x: u64) u64 {
    return @as(u64, std.math.sqrt(x));
}

fn fourSquares(rem: u64) [4]u64 {
    var a: u64 = @min(isqrt(rem), @as(u64, q / 2));
    while (true) : (a -= 1) {
        const r1 = rem - a * a;
        var b: u64 = @min(a, isqrt(r1));
        while (true) : (b -= 1) {
            const r2 = r1 - b * b;
            var c: u64 = @min(b, isqrt(r2));
            while (true) : (c -= 1) {
                const r3 = r2 - c * c;
                const d = isqrt(r3);
                if (d * d == r3 and d <= c) return .{ a, b, c, d };
                if (c == 0) break;
            }
            if (b == 0) break;
        }
        if (a == 0) break;
    }
    unreachable;
}

fn centered(w: u32) i64 {
    return if (w > q / 2) @as(i64, w) - q else w;
}

/// Verify a signature whose norm is exactly `bound + plus`. s2 = 1 (constant),
/// so s2*h = h, and h = c + w makes -s1 = w. `w0` is the raw residue of
/// coefficient 0 (6144 and 6145 sit on the centring boundary); the other
/// residues carry the remaining squares.
fn verifyWithNorm(comptime Ring: type, comptime PK: type, bound: u64, plus: u64, w0: u32) !void {
    const Codec = codec.Codec(Ring);
    const nonce: [40]u8 = @splat(0x5a);
    const msg = "norm boundary";
    var c: Ring.Poly = undefined;
    Codec.hashToPoint(&nonce, msg, &c);
    var wv: [Ring.n]u32 = @splat(0);
    wv[0] = w0;
    const rem = bound + plus - 1 - @as(u64, @intCast(centered(w0) * centered(w0)));
    const fs = fourSquares(rem);
    for (fs, 1..) |v, i| wv[i] = @intCast(v);
    var pk: PK = undefined;
    for (&pk.h, c, wv) |*h, cc, w| h.* = @intCast((@as(u32, cc) + w) % q);
    pk.h_ntt = pk.h;
    Ring.ntt(&pk.h_ntt);
    var s2: [Ring.n]i16 = @splat(0);
    s2[0] = 1;
    var sig: [1 + 3 * Ring.n]u8 = undefined;
    sig[0] = 0x20 + @as(u8, Ring.logn);
    const len = try Codec.compEncode(sig[1..], &s2);
    try pk.verify(msg, &nonce, sig[0 .. 1 + len]);
}

test "verify: norm == bound is accepted, bound + 1 refused (Falcon-512)" {
    try verifyWithNorm(poly.Ring512, falcon.PublicKey, falcon.sig_bound, 0, 0);
    try std.testing.expectError(error.SignatureVerificationFailed, verifyWithNorm(poly.Ring512, falcon.PublicKey, falcon.sig_bound, 1, 0));
}

test "verify: norm == bound is accepted, bound + 1 refused (Falcon-1024)" {
    try verifyWithNorm(poly.Ring1024, falcon.PublicKey1024, falcon.sig_bound_1024, 0, 0);
    try std.testing.expectError(error.SignatureVerificationFailed, verifyWithNorm(poly.Ring1024, falcon.PublicKey1024, falcon.sig_bound_1024, 1, 0));
}

test "verify: residues q/2 and q/2 + 1 are centred exactly (Falcon-1024; a coefficient there is under the bound)" {
    // 6144 stays +6144, 6145 becomes -6144: both square to 6144^2.
    inline for (.{ 6144, 6145 }) |w0| {
        try verifyWithNorm(poly.Ring1024, falcon.PublicKey1024, falcon.sig_bound_1024, 0, w0);
        try std.testing.expectError(error.SignatureVerificationFailed, verifyWithNorm(poly.Ring1024, falcon.PublicKey1024, falcon.sig_bound_1024, 1, w0));
    }
}

// ---- sign: the norm bound is inclusive ------------------------------------------

const Norms = struct { n1: u64, n2: u64 };

fn normOf(comptime Ring: type, h_ntt: *const Ring.Poly, msg: []const u8, nonce: *const [40]u8, sig_field: []const u8) !Norms {
    const Codec = codec.Codec(Ring);
    var s2: [Ring.n]i16 = undefined;
    try Codec.compDecode(&s2, sig_field[1..]);
    var c: Ring.Poly = undefined;
    Codec.hashToPoint(nonce, msg, &c);
    var tt: Ring.Poly = undefined;
    for (&tt, s2) |*x, v| x.* = @intCast(if (v < 0) @as(i32, v) + @as(i32, q) else @as(i32, v));
    Ring.ntt(&tt);
    Ring.pointwiseMul(&tt, h_ntt);
    Ring.intt(&tt);
    var r = Norms{ .n1 = 0, .n2 = 0 };
    for (tt, c, s2) |hs2, cc, v| {
        const w = centered(@intCast(@mod(@as(i64, hs2) - @as(i64, cc), @as(i64, q))));
        r.n1 += @intCast(w * w);
        r.n2 += @intCast(@as(i64, v) * @as(i64, v));
    }
    return r;
}

test "signWithRng accepts a candidate whose norm equals the bound and rejects one above it" {
    const Ring = poly.Ring512;
    const S = sign.Signer(Ring);
    var kprng: sign.ShakePrng = undefined;
    kprng.init("boundary-test key");
    defer kprng.deinit();
    var sk: falcon.SigningKey = undefined;
    var pk: falcon.PublicKey = undefined;
    try falcon.generateKeyPair(kprng.random(), &sk, &pk);
    defer sk.secureZero();

    const msg = "sign boundary";
    var sp: sign.ShakePrng = undefined;
    var nonce0: [40]u8 = undefined;
    var sig0: [700]u8 = undefined;
    sp.init("sign seed");
    const len0 = try S.signWithRng(&sk.tree, msg, sp.random(), &nonce0, &sig0, std.math.maxInt(u64));
    sp.deinit();
    const parts = try normOf(Ring, &pk.h_ntt, msg, &nonce0, sig0[0..len0]);
    const norm0 = parts.n1 + parts.n2;
    try std.testing.expect(norm0 <= falcon.sig_bound);
    try std.testing.expect(parts.n1 > 0 and parts.n2 > 0);

    // bound == norm: the very same first candidate is accepted
    var nonce1: [40]u8 = undefined;
    var sig1: [700]u8 = undefined;
    sp.init("sign seed");
    const len1 = try S.signWithRng(&sk.tree, msg, sp.random(), &nonce1, &sig1, norm0);
    sp.deinit();
    try std.testing.expectEqualSlices(u8, &nonce0, &nonce1);
    try std.testing.expectEqualSlices(u8, sig0[0..len0], sig1[0..len1]);

    // bound == norm - 1: that candidate is refused, the signer draws another
    var nonce2: [40]u8 = undefined;
    var sig2: [700]u8 = undefined;
    sp.init("sign seed");
    if (S.signWithRng(&sk.tree, msg, sp.random(), &nonce2, &sig2, norm0 - 1)) |len2| {
        try std.testing.expect(!std.mem.eql(u8, &nonce0, &nonce2));
        const parts2 = try normOf(Ring, &pk.h_ntt, msg, &nonce2, sig2[0..len2]);
        try std.testing.expect(parts2.n1 + parts2.n2 < norm0);
    } else |err| {
        try std.testing.expectEqual(error.TooManyRetries, err);
    }
    sp.deinit();

    // Both halves of the norm count: a bound equal to one half alone refuses the
    // first candidate (its norm is the sum), whichever half it is.
    inline for (.{ parts.n1, parts.n2 }) |half| {
        var nonce3: [40]u8 = undefined;
        var sig3: [700]u8 = undefined;
        sp.init("sign seed");
        const r3 = S.signWithRng(&sk.tree, msg, sp.random(), &nonce3, &sig3, half);
        sp.deinit();
        if (r3) |_| {
            try std.testing.expect(!std.mem.eql(u8, &nonce0, &nonce3));
        } else |err| {
            try std.testing.expectEqual(error.TooManyRetries, err);
        }
    }

    // An empty output buffer is refused up front.
    sp.init("sign seed");
    try std.testing.expectError(error.NoSpaceLeft, S.signWithRng(&sk.tree, msg, sp.random(), &nonce0, sig0[0..0], falcon.sig_bound));
    sp.deinit();

    // The generated key's fields satisfy the NTRU equation f*G - g*F = q.
    try expectNtruEquation(Ring, &sk.f, &sk.g, &sk.big_f, &sk.big_g);
    try std.testing.expectEqualSlices(i8, &sk.big_g, &sk.tree.big_g);
}

test "open: an empty message and a one-byte message open; the sig-length field bounds are exact" {
    var kprng: sign.ShakePrng = undefined;
    kprng.init("open test key");
    defer kprng.deinit();
    var sk: falcon.SigningKey = undefined;
    var pk: falcon.PublicKey = undefined;
    try falcon.generateKeyPair(kprng.random(), &sk, &pk);
    defer sk.secureZero();
    var srng: sign.ShakePrng = undefined;
    srng.init("open test sign");
    defer srng.deinit();

    inline for (.{ "", "x" }) |msg| {
        var nonce: [40]u8 = undefined;
        var sig: [700]u8 = undefined;
        const len = try falcon.signRandomized(&sk, msg, srng.random(), &nonce, &sig);
        var sm: [2 + 40 + msg.len + 700]u8 = undefined;
        sm[0] = @intCast(len >> 8);
        sm[1] = @intCast(len & 0xff);
        @memcpy(sm[2..42], &nonce);
        @memcpy(sm[42 .. 42 + msg.len], msg);
        @memcpy(sm[42 + msg.len ..][0..len], sig[0..len]);
        const total = 42 + msg.len + len;
        const opened = try falcon.openNistSignedMessage(&pk, sm[0..total]);
        try std.testing.expectEqualStrings(msg, opened);
        // the length field one too large / one too small is refused
        var bad = sm;
        bad[1] +%= 1;
        try std.testing.expectError(error.InvalidSignature, falcon.openNistSignedMessage(&pk, bad[0..total]));
        bad = sm;
        bad[1] -%= 1;
        try std.testing.expectError(error.InvalidSignature, falcon.openNistSignedMessage(&pk, bad[0..total]));
        // length field set so the signature would start inside the nonce
        bad = sm;
        bad[0] = 0x7f;
        try std.testing.expectError(error.InvalidSignature, falcon.openNistSignedMessage(&pk, bad[0..total]));
        // the big-endian high byte counts: swapping the two bytes is a different length
        bad = sm;
        const hi = bad[0];
        bad[0] = bad[1];
        bad[1] = hi;
        try std.testing.expectError(error.InvalidSignature, falcon.openNistSignedMessage(&pk, bad[0..total]));
        // envelopes shorter than 2 + 40 + 1 bytes
        try std.testing.expectError(error.InvalidSignature, falcon.openNistSignedMessage(&pk, sm[0..42]));
        try std.testing.expectError(error.InvalidSignature, falcon.openNistSignedMessage(&pk, sm[0..43]));
    }
}

// ---- wipes with a direct, safe-build-visible effect ------------------------------

test "SecretKey.fromBytes zeroes the output on every refusal; ShakePrng.deinit wipes its state" {
    var good: [falcon.SecretKey.encoded_length]u8 = undefined;
    var sk0: falcon.SigningKey = undefined;
    var pk0: falcon.PublicKey = undefined;
    var kprng: sign.ShakePrng = undefined;
    kprng.init("wipe test key");
    try falcon.generateKeyPair(kprng.random(), &sk0, &pk0);
    sk0.toSecretKeyBytes(&good);
    defer sk0.secureZero();

    var out: falcon.SecretKey = undefined;
    var bad = good;
    bad[0] ^= 0x01; // wrong header
    @memset(std.mem.asBytes(&out), 0xaa);
    try std.testing.expectError(error.InvalidSecretKey, falcon.SecretKey.fromBytes(&out, &bad));
    try std.testing.expect(std.mem.allEqual(u8, std.mem.asBytes(&out), 0));

    // forbidden -32 in g's first 6-bit field: f and part of g decode first
    bad = good;
    bad[1 + 384] = 0b10000000 | (bad[1 + 384] & 0b00000011);
    @memset(std.mem.asBytes(&out), 0xaa);
    try std.testing.expectError(error.InvalidSecretKey, falcon.SecretKey.fromBytes(&out, &bad));
    try std.testing.expect(std.mem.allEqual(u8, std.mem.asBytes(&out), 0));

    // ShakePrng.deinit
    var p: sign.ShakePrng = undefined;
    p.init("deinit");
    var junk: [16]u8 = undefined;
    p.random().bytes(&junk);
    p.deinit();
    try std.testing.expect(std.mem.allEqual(u8, std.mem.asBytes(&p), 0));
    kprng.deinit();
}

// ---- the sampler's saturation and the dead public entry points --------------------

test "berExp saturates the shift at 63: an exponent of 65 ln 2 never accepts" {
    var seed: [56]u8 = undefined;
    for (&seed, 0..) |*b, i| b.* = @truncate(i * 7 + 1);
    var prng = gaussian.Prng.init(&seed);
    const ccs: f64 = 0.5;
    const x = fpr.mul(fpr.of(65), fpr.log2);
    for (0..400) |_| try std.testing.expect(!gaussian.berExp(&prng, x, ccs));
    // and the small-exponent end really does accept now and then
    var hits: usize = 0;
    for (0..400) |_| {
        if (gaussian.berExp(&prng, fpr.of(0), ccs)) hits += 1;
    }
    try std.testing.expect(hits > 100);
}

fn randomFftPoly(random: std.Random, buf: []f64) void {
    for (buf) |*x| x.* = fpr.of(random.intRangeAtMost(i32, -2000, 2000));
}

test "ffsampling.splitFft / mergeFft are the fft.poly* routines; merge inverts split" {
    var prng = std.Random.DefaultPrng.init(0x59117);
    const random = prng.random();
    inline for (.{ 4, 6, 9 }) |logn| {
        const n = 1 << logn;
        var f: [n]f64 = undefined;
        randomFftPoly(random, &f);
        fft.fftRaw(&f, logn);
        var a0: [n / 2]f64 = undefined;
        var a1: [n / 2]f64 = undefined;
        var b0: [n / 2]f64 = undefined;
        var b1: [n / 2]f64 = undefined;
        ffsampling.splitFft(logn, &f, &a0, &a1);
        fft.polySplitFft(&b0, &b1, &f, logn);
        try std.testing.expectEqualSlices(f64, &b0, &a0);
        try std.testing.expectEqualSlices(f64, &b1, &a1);
        var m1: [n]f64 = undefined;
        var m2: [n]f64 = undefined;
        ffsampling.mergeFft(logn, &a0, &a1, &m1);
        fft.polyMergeFft(&m2, &b0, &b1, logn);
        try std.testing.expectEqualSlices(f64, &m2, &m1);
        for (m1, f) |x, y| try std.testing.expect(@abs(x - y) < 1e-6);
    }
}

test "fft.polyLdlmvFft gives the same d11 / l10 as polyLdlFft" {
    var prng = std.Random.DefaultPrng.init(0x1d17);
    const random = prng.random();
    inline for (.{ 3, 5, 9 }) |logn| {
        const n = 1 << logn;
        var g00: [n]f64 = undefined;
        var g01: [n]f64 = undefined;
        var g11: [n]f64 = undefined;
        randomFftPoly(random, &g00);
        randomFftPoly(random, &g01);
        randomFftPoly(random, &g11);
        for (g00[0 .. n / 2]) |*x| x.* = fpr.of(random.intRangeAtMost(i32, 1, 2000));
        var d11: [n]f64 = undefined;
        var l10: [n]f64 = undefined;
        fft.polyLdlmvFft(&d11, &l10, &g00, &g01, &g11, logn);
        var g01b = g01;
        var g11b = g11;
        fft.polyLdlFft(&g00, &g01b, &g11b, logn);
        for (0..n / 2) |u| {
            try std.testing.expectEqual(@as(u64, @bitCast(g11b[u])), @as(u64, @bitCast(d11[u])));
            try std.testing.expectEqual(@as(u64, @bitCast(g11b[u + n / 2])), @as(u64, @bitCast(d11[u + n / 2])));
            try std.testing.expectEqual(@as(u64, @bitCast(g01b[u])), @as(u64, @bitCast(l10[u])));
            try std.testing.expectEqual(@as(u64, @bitCast(g01b[u + n / 2])), @as(u64, @bitCast(l10[u + n / 2])));
        }
    }
}

test "fft.Fft(Ring) adapters agree with fftRaw / ifftRaw" {
    var prng = std.Random.DefaultPrng.init(0xada9);
    const random = prng.random();
    const F = fft.Fft(poly.Ring512);
    var a: [512]f64 = undefined;
    randomFftPoly(random, &a);
    var out: F.FftPoly = undefined;
    F.fft(&a, &out);
    var raw = a;
    fft.fftRaw(&raw, 9);
    for (out, 0..) |cx, k| {
        try std.testing.expectEqual(@as(u64, @bitCast(raw[k])), @as(u64, @bitCast(cx.re)));
        try std.testing.expectEqual(@as(u64, @bitCast(raw[k + 256])), @as(u64, @bitCast(cx.im)));
    }
    var back: [512]f64 = undefined;
    F.ifft(&out, &back);
    var raw2 = raw;
    fft.ifftRaw(&raw2, 9);
    try std.testing.expectEqualSlices(f64, &raw2, &back);
    for (back, a) |x, y| try std.testing.expect(@abs(x - y) < 1e-6);
}

// ---- the NTRU equation, over the integers -------------------------------------------

fn expectNtruEquation(comptime Ring: type, f: *const [Ring.n]i8, g: *const [Ring.n]i8, big_f: *const [Ring.n]i8, big_g: *const [Ring.n]i8) !void {
    // (f*G - g*F) mod (x^n + 1) must be the constant q.
    var acc: [Ring.n]i64 = @splat(0);
    for (0..Ring.n) |i| {
        for (0..Ring.n) |j| {
            const k = i + j;
            const t = @as(i64, f[i]) * big_g[j] - @as(i64, g[i]) * big_f[j];
            if (k < Ring.n) acc[k] += t else acc[k - Ring.n] -= t;
        }
    }
    try std.testing.expectEqual(@as(i64, q), acc[0]);
    for (acc[1..]) |x| try std.testing.expectEqual(@as(i64, 0), x);
}

test "generateKeyPair: the Falcon-1024 key satisfies the NTRU equation and round-trips" {
    var kprng: sign.ShakePrng = undefined;
    kprng.init("ntru equation 1024");
    defer kprng.deinit();
    var sk: falcon.SigningKey1024 = undefined;
    var pk: falcon.PublicKey1024 = undefined;
    try falcon.generateKeyPair1024(kprng.random(), &sk, &pk);
    defer sk.secureZero();
    try expectNtruEquation(poly.Ring1024, &sk.f, &sk.g, &sk.big_f, &sk.big_g);
    try std.testing.expectEqualSlices(i8, &sk.big_g, &sk.tree.big_g);
    var bytes: [falcon.SecretKey1024.encoded_length]u8 = undefined;
    sk.toSecretKeyBytes(&bytes);
    var dec: falcon.SecretKey1024 = undefined;
    try falcon.SecretKey1024.fromBytes(&dec, &bytes);
    const pk2 = try dec.publicKey();
    try std.testing.expectEqualSlices(u16, &pk.h, &pk2.h);
    try std.testing.expectEqualSlices(u16, &pk.h_ntt, &pk2.h_ntt);
}

// ---- a short s1 with a long s2 must still be refused ------------------------------------

fn longS2Case(comptime Ring: type, comptime PK: type) !void {
    const Codec = codec.Codec(Ring);
    const nonce: [40]u8 = @splat(0x33);
    const msg = "long s2";
    var c: Ring.Poly = undefined;
    Codec.hashToPoint(&nonce, msg, &c);
    // s2 with every coefficient near +-2000: ||s2||^2 is far above the bound.
    var s2: [Ring.n]i16 = undefined;
    var prng = std.Random.DefaultPrng.init(0x10ca1);
    for (&s2) |*x| x.* = @intCast(prng.random().intRangeAtMost(i32, 1500, 2000) * (if (prng.random().boolean()) @as(i32, 1) else -1));
    // h = c / s2 in the ring, so that s2 * h = c and s1 = 0.
    var h = c;
    Ring.ntt(&h);
    var t: Ring.Poly = undefined;
    for (&t, s2) |*x, v| x.* = @intCast(if (v < 0) @as(i32, v) + @as(i32, q) else @as(i32, v));
    Ring.ntt(&t);
    // pointwiseDiv(a, b) sets a = b * a^-1: with a = NTT(s2), b = NTT(c) this is NTT(c) / NTT(s2).
    try Ring.pointwiseDiv(&t, &h);
    var pk: PK = undefined;
    pk.h_ntt = t;
    pk.h = t;
    Ring.intt(&pk.h);
    var sig: [1 + 3 * Ring.n]u8 = undefined;
    sig[0] = 0x20 + @as(u8, Ring.logn);
    const len = try Codec.compEncode(sig[1..], &s2);
    try std.testing.expectError(error.SignatureVerificationFailed, pk.verify(msg, &nonce, sig[0 .. 1 + len]));
}

test "verify: s1 = 0 with a large s2 is refused (the s2 half of the norm)" {
    try longS2Case(poly.Ring512, falcon.PublicKey);
    try longS2Case(poly.Ring1024, falcon.PublicKey1024);
}

// ---- fpr: zero operands, flush-to-zero, structured mantissas and ties ------------------------

const native = struct {
    fn add(a: f64, b: f64) f64 {
        @setFloatMode(.strict);
        return a + b;
    }
    fn mul(a: f64, b: f64) f64 {
        @setFloatMode(.strict);
        return a * b;
    }
    fn div(a: f64, b: f64) f64 {
        @setFloatMode(.strict);
        return a / b;
    }
    fn sqrt(a: f64) f64 {
        @setFloatMode(.strict);
        return @sqrt(a);
    }
};

fn fbits(x: f64) u64 {
    return @bitCast(x);
}

/// Equal as numbers, with every zero equal to every other zero (the emulation
/// follows the reference's choice of zero sign, which no consumer reads).
fn same(want: f64, got: f64) !void {
    if (want == 0.0 and got == 0.0) return;
    try std.testing.expectEqual(fbits(want), fbits(got));
}

test "fpr: zero operands and exact cancellation" {
    const zeros = [_]f64{ 0.0, -0.0 };
    const vals = [_]f64{ 1.0, -1.0, 3.5, -123456.789, 2.0e-100, -7.0e150 };
    for (zeros) |z| {
        for (vals ++ zeros) |y| {
            try same(native.mul(z, y), fpr.mul(z, y));
            try same(native.mul(y, z), fpr.mul(y, z));
            try same(native.add(z, y), fpr.add(z, y));
            try same(native.add(y, z), fpr.add(y, z));
            try same(native.add(z, -y), fpr.sub(z, y));
        }
        for (vals) |y| try same(0.0, fpr.div(z, y));
        try same(0.0, fpr.sqrt(z));
        try same(0.0, fpr.half(z));
        try same(0.0, fpr.double(z));
        try std.testing.expectEqual(@as(i64, 0), fpr.rint(z));
        // (floor(-0.0) is -1 in the emulation, as in the reference; no caller passes -0)
        try std.testing.expectEqual(@as(i64, 0), fpr.trunc(z));
        if (fbits(z) == 0) try std.testing.expectEqual(@as(i64, 0), fpr.floor(z));
    }
    for (vals) |y| {
        try same(0.0, fpr.add(y, -y));
        try same(0.0, fpr.add(-y, y));
        try same(0.0, fpr.sub(y, y));
    }
    try std.testing.expectEqual(@as(u64, 0), fbits(fpr.of(0)));
    try std.testing.expectEqual(@as(f64, 1.0), fpr.div(vals[2], vals[2]));
    try std.testing.expectEqual(@as(f64, 1.0), fpr.inv(1.0));
    try std.testing.expectEqual(@as(f64, 0.25), fpr.inv(4.0));
}

test "fpr: results below the normal range flush to zero, the smallest normal survives" {
    const a = std.math.ldexp(@as(f64, 1.0), -600);
    try std.testing.expectEqual(@as(f64, 0.0), fpr.mul(a, std.math.ldexp(@as(f64, 1.0), -430))); // 2^-1030: native subnormal
    try std.testing.expectEqual(@as(f64, 0.0), fpr.mul(a, std.math.ldexp(@as(f64, 1.0), -600))); // 2^-1200
    try std.testing.expectEqual(@as(u64, 0x0010000000000000), fbits(fpr.mul(a, std.math.ldexp(@as(f64, 1.0), -422)))); // 2^-1022
    try std.testing.expectEqual(@as(f64, 0.0), fpr.div(a, std.math.ldexp(@as(f64, 1.0), 430)));
    try std.testing.expectEqual(@as(f64, 0.0), fpr.add(std.math.ldexp(@as(f64, 1.0), -1022), -std.math.ldexp(@as(f64, 1.0), -1022)));
    try std.testing.expectEqual(@as(f64, 0.0), fpr.half(std.math.ldexp(@as(f64, 1.0), -1022)));
}

fn sparse(i: u6, e: u64, neg: bool) f64 {
    const mant: u64 = if (i == 52) 0 else (@as(u64, 1) << @intCast(i));
    return @bitCast((@as(u64, @intFromBool(neg)) << 63) | (e << 52) | mant);
}

test "fpr: single-bit mantissas (ties and sticky bits) against the hardware, all exponent gaps" {
    const gaps = [_]u64{ 0, 1, 2, 3, 26, 50, 51, 52, 53, 54, 55, 56, 57, 58, 59, 60, 61, 62, 63, 64, 65 };
    for ([_]u64{ 1023, 1100 }) |ex| {
        for (0..53) |i| {
            for (0..53) |j| {
                for (gaps) |gap| {
                    for ([_]bool{ false, true }) |ny| {
                        const x = sparse(@intCast(i), ex, false);
                        const y = sparse(@intCast(j), ex - gap, ny);
                        try same(native.add(x, y), fpr.add(x, y));
                        try same(native.add(y, x), fpr.add(y, x));
                        try same(native.add(x, -y), fpr.sub(x, y));
                    }
                }
                const x = sparse(@intCast(i), ex, false);
                const y = sparse(@intCast(j), ex, false);
                try same(native.mul(x, y), fpr.mul(x, y));
                try same(native.div(x, y), fpr.div(x, y));
            }
            const x = sparse(@intCast(i), ex, false);
            try same(native.sqrt(x), fpr.sqrt(x));
        }
    }
}

test "fpr: rint rounds to nearest even around every tie, floor and trunc agree with the hardware" {
    const bases = [_]f64{ 0, 1, 2, 3, 12345, 4094, 4095 };
    for (bases) |b| {
        var t: u6 = 1;
        while (t <= 40) : (t += 1) {
            const eps = std.math.ldexp(@as(f64, 1.0), -@as(i32, t));
            for ([_]f64{ eps, -eps, 0 }) |d| {
                for ([_]f64{ 1, -1 }) |sg| {
                    const x = sg * (b + 0.5 + d);
                    if (x == 0.0) continue;
                    const fl = @floor(x);
                    const diff = x - fl;
                    const want_f: f64 = if (diff > 0.5) fl + 1 else if (diff < 0.5) fl else if (@mod(fl, 2.0) == 0) fl else fl + 1;
                    try std.testing.expectEqual(@as(i64, @intFromFloat(want_f)), fpr.rint(x));
                    try std.testing.expectEqual(@as(i64, @intFromFloat(@floor(x))), fpr.floor(x));
                    try std.testing.expectEqual(@as(i64, @intFromFloat(@trunc(x))), fpr.trunc(x));
                }
            }
        }
    }
    // magnitudes below one, and the integer boundary at 2^52
    for ([_]f64{ 0.25, 0.5, 0.75, 0.999999, 1.0, 1.5, 2.5, 4503599627370495.5, 4503599627370496.0 }) |x| {
        for ([_]f64{ 1, -1 }) |sg| {
            try std.testing.expectEqual(@as(i64, @intFromFloat(@floor(sg * x))), fpr.floor(sg * x));
            try std.testing.expectEqual(@as(i64, @intFromFloat(@trunc(sg * x))), fpr.trunc(sg * x));
        }
    }
}

fn mulhi(a: u64, b: u64) u64 {
    return @truncate((@as(u128, a) * b) >> 64);
}

test "fpr.expm_p63 equals the exact 128-bit evaluation of the reference polynomial" {
    const C = [_]u64{
        0x00000004741183A3, 0x00000036548CFC06, 0x0000024FDCBF140A,
        0x0000171D939DE045, 0x0000D00CF58F6F84, 0x000680681CF796E3,
        0x002D82D8305B0FEA, 0x011111110E066FD0, 0x0555555555070F00,
        0x155555555581FF00, 0x400000000002B400, 0x7FFFFFFFFFFF4800,
        0x8000000000000000,
    };
    var prng = std.Random.DefaultPrng.init(0xe3b5);
    const random = prng.random();
    for (0..4000) |_| {
        const x = random.float(f64) * 0.693147;
        const ccs = random.float(f64);
        var y: u64 = C[0];
        const z: u64 = @as(u64, @intFromFloat(x * 9223372036854775808.0)) << 1;
        for (C[1..]) |c| y = c -% mulhi(z, y);
        const zc: u64 = @as(u64, @intFromFloat(ccs * 9223372036854775808.0)) << 1;
        y = mulhi(zc, y);
        try std.testing.expectEqual(y, fpr.expm_p63(x, ccs));
    }
}

// ---- fft.polyLdlFft / polyLdlmvFft on general complex input ---------------------------------

test "polyLdlFft and polyLdlmvFft equal the textbook complex LDL on inputs with a non-real g00" {
    var prng = std.Random.DefaultPrng.init(0x1d1d);
    const random = prng.random();
    inline for (.{ 4, 9 }) |logn| {
        const n = 1 << logn;
        const hn = n / 2;
        var g00: [n]f64 = undefined;
        var g01: [n]f64 = undefined;
        var g11: [n]f64 = undefined;
        for (0..n) |u| {
            g00[u] = @floatFromInt(random.intRangeAtMost(i32, -2000, 2000));
            g01[u] = @floatFromInt(random.intRangeAtMost(i32, -2000, 2000));
            g11[u] = @floatFromInt(random.intRangeAtMost(i32, -2000, 2000));
        }
        g00[0] = 7;
        g00[hn] = 11;
        var d11: [n]f64 = undefined;
        var l10: [n]f64 = undefined;
        fft.polyLdlmvFft(&d11, &l10, &g00, &g01, &g11, logn);
        var g01b = g01;
        var g11b = g11;
        fft.polyLdlFft(&g00, &g01b, &g11b, logn);
        for (0..hn) |u| {
            const inv_m = native.div(1.0, native.add(native.mul(g00[u], g00[u]), native.mul(g00[u + hn], g00[u + hn])));
            const b_re = native.mul(g00[u], inv_m);
            const b_im = native.mul(-g00[u + hn], inv_m);
            const mu_re = native.add(native.mul(g01[u], b_re), -native.mul(g01[u + hn], b_im));
            const mu_im = native.add(native.mul(g01[u], b_im), native.mul(g01[u + hn], b_re));
            const p_re = native.add(native.mul(mu_re, g01[u]), -native.mul(mu_im, -g01[u + hn]));
            const p_im = native.add(native.mul(mu_re, -g01[u + hn]), native.mul(mu_im, g01[u]));
            try same(native.add(g11[u], -p_re), g11b[u]);
            try same(native.add(g11[u + hn], -p_im), g11b[u + hn]);
            try same(mu_re, g01b[u]);
            try same(-mu_im, g01b[u + hn]);
            try same(native.add(g11[u], -p_re), d11[u]);
            try same(native.add(g11[u + hn], -p_im), d11[u + hn]);
            try same(mu_re, l10[u]);
            try same(-mu_im, l10[u + hn]);
        }
    }
}

// ---- computePublic refuses exactly the non-invertible f --------------------------------------

fn powmodQ(b: u64, e: u64) u64 {
    var r: u64 = 1;
    var x = b % q;
    var k = e;
    while (k != 0) : (k >>= 1) {
        if (k & 1 != 0) r = r * x % q;
        x = x * x % q;
    }
    return r;
}

fn noninvertibleOracle(comptime Ring: type, f: *const [Ring.n]i8) bool {
    // g = smallest generator of Z_q^*; psi a primitive 2n-th root of unity
    var gen: u64 = 2;
    while (powmodQ(gen, (q - 1) / 2) == 1 or powmodQ(gen, (q - 1) / 3) == 1) gen += 1;
    const psi = powmodQ(gen, (q - 1) / (2 * Ring.n));
    var r: u64 = psi;
    const psi2 = psi * psi % q;
    for (0..Ring.n) |_| {
        var acc: u64 = 0;
        var i: usize = Ring.n;
        while (i > 0) {
            i -= 1;
            const fi: u64 = @intCast(@as(i64, f[i]) + q);
            acc = (acc * r + fi) % q;
        }
        if (acc == 0) return true;
        r = r * psi2 % q;
    }
    return false;
}

test "computePublic reports NotInvertible exactly when f vanishes at a root of x^n + 1" {
    var prng = std.Random.DefaultPrng.init(0x0111);
    const random = prng.random();
    inline for (.{ .{ poly.Ring512, 220 }, .{ poly.Ring1024, 70 } }) |cfg| {
        const Ring = cfg[0];
        var noninv: usize = 0;
        var inv: usize = 0;
        for (0..cfg[1]) |_| {
            var f: [Ring.n]i8 = undefined;
            var g: [Ring.n]i8 = undefined;
            for (&f) |*x| x.* = @intCast(random.intRangeAtMost(i32, -31, 31));
            for (&g) |*x| x.* = @intCast(random.intRangeAtMost(i32, -31, 31));
            const bad = noninvertibleOracle(Ring, &f);
            if (bad) {
                noninv += 1;
                try std.testing.expectError(error.NotInvertible, Ring.computePublic(&f, &g));
            } else {
                inv += 1;
                _ = try Ring.computePublic(&f, &g);
            }
        }
        try std.testing.expect(noninv >= 1 and inv >= 1);
    }
}

// ---- the retry budget -------------------------------------------------------------------------

const CountingRng = struct {
    inner: *sign.ShakePrng,
    nonces: usize = 0,

    fn fill(self: *CountingRng, buf: []u8) void {
        if (buf.len == 40) self.nonces += 1;
        self.inner.random().bytes(buf);
    }

    fn random(self: *CountingRng) std.Random {
        return std.Random.init(self, fill);
    }
};

test "signWithRng draws exactly max_attempts nonces before giving up on a key that never signs" {
    const S = sign.Signer(poly.Ring512);
    var sk: falcon.SigningKey = undefined;
    @memset(std.mem.asBytes(&sk), 0);
    var sp: sign.ShakePrng = undefined;
    sp.init("retry budget");
    defer sp.deinit();
    var cr = CountingRng{ .inner = &sp };
    var nonce: [40]u8 = undefined;
    var sig: [700]u8 = undefined;
    try std.testing.expectError(error.TooManyRetries, S.signWithRng(&sk.tree, "m", cr.random(), &nonce, &sig, falcon.sig_bound));
    try std.testing.expectEqual(S.max_attempts, cr.nonces);
}

// ---- late additions: codec padding / -0 / q, berExp mid-range shift ------------------------

test "modqDecode refuses a coefficient equal to q" {
    inline for (.{ codec.Codec512, codec.Codec1024 }) |C| {
        var a: [C.modq_encoded_len * 8 / 14]u16 = @splat(0);
        a[3] = q - 1;
        var buf: [C.modq_encoded_len]u8 = undefined;
        C.modqEncode(&buf, &a);
        var out: [a.len]u16 = undefined;
        try C.modqDecode(&out, &buf);
        // 14-bit field 3 is q = 12289 instead of q - 1: refused
        a[3] = q - 1;
        var bad = buf;
        const bit = 3 * 14;
        // add one to the field (q - 1 -> q)
        var field: u16 = 0;
        for (0..14) |k| field = (field << 1) | ((bad[(bit + k) / 8] >> @intCast(7 - (bit + k) % 8)) & 1);
        field += 1;
        for (0..14) |k| {
            const b: u8 = @intCast((field >> @intCast(13 - k)) & 1);
            const i = (bit + k) / 8;
            const sh: u3 = @intCast(7 - (bit + k) % 8);
            bad[i] = (bad[i] & ~(@as(u8, 1) << sh)) | (b << sh);
        }
        try std.testing.expectError(error.InvalidEncoding, C.modqDecode(&out, &bad));
    }
}

test "compDecode: -0 is refused anywhere, padding bits must be zero, wide random polynomials round-trip" {
    inline for (.{ codec.Codec512, codec.Codec1024 }) |C| {
        const n = C.modq_encoded_len * 8 / 14;
        var out: [n]i16 = undefined;
        var w = BitWriter{};
        w.coef(1, 0, 0); // -0 first
        for (1..n) |_| w.coef(0, 0, 0);
        try std.testing.expectError(error.InvalidEncoding, C.compDecode(&out, w.bytes()));
        var w2 = BitWriter{};
        for (0..5) |_| w2.coef(0, 3, 1);
        w2.coef(1, 0, 0); // -0 later
        for (6..n) |_| w2.coef(0, 3, 1);
        try std.testing.expectError(error.InvalidEncoding, C.compDecode(&out, w2.bytes()));

        var prng = std.Random.DefaultPrng.init(0x7a11);
        const random = prng.random();
        var buf: [4096]u8 = undefined;
        for (0..60) |_| {
            var s: [n]i16 = undefined;
            for (&s) |*x| x.* = random.intRangeAtMost(i16, -2047, 2047);
            const len = try C.compEncode(&buf, &s);
            try C.compDecode(&out, buf[0..len]);
            try std.testing.expectEqualSlices(i16, &s, &out);
            // a set padding bit in the last byte is refused when there is padding
            const used = blk: {
                var bits: usize = 0;
                for (s) |x| bits += 8 + (@abs(x) >> 7) + 1;
                break :blk bits;
            };
            if (used % 8 != 0) {
                buf[len - 1] |= 1;
                try std.testing.expectError(error.InvalidEncoding, C.compDecode(&out, buf[0..len]));
            }
        }
    }
}

test "berExp: a mid-range exponent (33 ln 2) never accepts" {
    var seed: [56]u8 = undefined;
    for (&seed, 0..) |*b, i| b.* = @truncate(i * 11 + 3);
    var prng = gaussian.Prng.init(&seed);
    const x = fpr.mul(fpr.of(33), fpr.log2);
    for (0..400) |_| try std.testing.expect(!gaussian.berExp(&prng, x, 0.5));
}
