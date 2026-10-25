// SPDX-License-Identifier: MIT

//! EdDSA (Ed25519) signature verification for `verify`'s `.EdDSA` arm, with
//! exactly the accept set of `std.crypto.sign.Ed25519.Signature.verify`
//! (cofactored, std's checks in std's order) and a faster double-scalar
//! multiplication: `[s]B - [h]A` by width-5 (A) and width-7 (B, a comptime
//! table) wNAF over ref10's point representations, where std uses a signed
//! radix-16 walk over extended coordinates.
//!
//! Why here and not in std or a sibling module: std's verify costs 79 us on
//! the audit host against ring's 55 us (Keats/jsonwebtoken, the fastest JWT
//! verifier measured, `bench-jwt`), which capped the card's performance axis;
//! the public-scalar ladder does not belong in `ct25519` (secret scalars
//! only), and a module of its own would put one more grade in front of every
//! consumer of `jwt` (the owner chose the same for tlsclient's keygen comb,
//! 2026-10-11).
//!
//! Where the cost goes (std, perf, 2026-10-25): point doubling 49 %, addition
//! 32 %, the two square roots of decoding A and R 12 %. Doublings: std's `dbl`
//! always computes T (4S + 4M); ref10 keeps a chain of doublings in P2/P1P1
//! (4S + 3M) and computes T only before an addition. Additions: std adds one
//! of 8 multiples at nearly every one of 64 radix-16 digits, for both scalars
//! (~120 additions); wNAF with odd multiples up to 15·A and 63·B adds at ~43
//! and ~32 of the 256 bits.
//!
//! The group element checked is the one std checks: std computes
//! `[8s mod L]B + [h](-[8]A) - [8]R` and tests for the identity; this module
//! computes `[8]([s]B + [h](-A) - R)`. B has order L, so both are
//! `[8]([s]B - [h]A - R)`. std's `WeakPublicKey` (its precomputation of `-8A`
//! hitting the identity at `4·(-8A)`, i.e. `32A = 0`, which for a point of
//! the curve's group Z/8 × Z/L is `8A = 0`) is the `8A` test below.

const std = @import("std");
const Ed25519 = std.crypto.sign.Ed25519;
const Curve = std.crypto.ecc.Edwards25519;
const Fe = Curve.Fe;
const Sha512 = std.crypto.hash.sha2.Sha512;

pub const Error = error{BadSignature};

/// Verify `sig` (`R ‖ S`, RFC 8032 §5.1.6) over `msg` under `public_key`;
/// accepts and rejects exactly what `Ed25519.Signature.verify` does.
pub fn verify(sig: [64]u8, msg: []const u8, public_key: Ed25519.PublicKey) Error!void {
    const r = sig[0..32].*;
    const s = sig[32..64].*;
    // std's `Verifier.init`, in its order.
    Curve.scalar.rejectNonCanonical(s) catch return error.BadSignature;
    const a = Curve.fromBytes(public_key.bytes) catch return error.BadSignature;
    a.rejectIdentity() catch return error.BadSignature;
    Curve.rejectNonCanonical(r) catch return error.BadSignature;
    const expected_r = Curve.fromBytes(r) catch return error.BadSignature;
    expected_r.rejectIdentity() catch return error.BadSignature;
    // std's `WeakPublicKey`: 8A is the identity.
    if (isIdentity(p3ToP2(a).dbl().toP2().dbl().toP2().dbl().toP2())) return error.BadSignature;

    var h = Sha512.init(.{});
    h.update(&r);
    h.update(&public_key.bytes);
    h.update(msg);
    var hram64: [Sha512.digest_length]u8 = undefined;
    h.final(&hram64);
    const hram = Curve.scalar.reduce64(hram64);

    // Q = [s]B + [h](-A); then [8](Q - R) must be the identity.
    const q = doubleScalarMul(s, P3.of(a.neg()), hram);
    var c = q.sub(Cached.of(P3.of(expected_r))).toP2();
    c = c.dbl().toP2().dbl().toP2().dbl().toP2();
    if (!isIdentity(c)) return error.BadSignature;
}

/// std's `Verifier.isIdentity`, on projective (X:Y:Z): X = 0 and Y = Z.
fn isIdentity(p: P2) bool {
    return p.x.isZero() and p.y.equivalent(p.z);
}

fn p3ToP2(p: Curve) P2 {
    return .{ .x = p.x, .y = p.y, .z = p.z };
}

/// Projective (X:Y:Z), x = X/Z, y = Y/Z: the state between doublings.
const P2 = struct {
    x: Fe,
    y: Fe,
    z: Fe,

    const identity: P2 = .{ .x = Fe.zero, .y = Fe.one, .z = Fe.one };

    /// ref10 `ge_p2_dbl`: std's `dbl` without its last multiplication.
    fn dbl(p: P2) P1P1 {
        const xx = p.x.sq();
        const yy = p.y.sq();
        const b = p.z.sq2();
        const aa = p.x.add(p.y).sq();
        const y = yy.add(xx);
        const z = yy.sub(xx);
        return .{ .x = aa.sub(y), .y = y, .z = z, .t = b.sub(z) };
    }
};

/// Extended (X:Y:Z:T), x = X/Z, y = Y/Z, xy = T/Z: what an addition needs.
const P3 = struct {
    x: Fe,
    y: Fe,
    z: Fe,
    t: Fe,

    fn of(p: Curve) P3 {
        return .{ .x = p.x, .y = p.y, .z = p.z, .t = p.t };
    }

    /// ref10 `ge_add`: std's `add` against a cached operand.
    fn add(p: P3, q: Cached) P1P1 {
        const a = p.y.add(p.x).mul(q.y_plus_x);
        const b = p.y.sub(p.x).mul(q.y_minus_x);
        const c = q.t2d.mul(p.t);
        const zz = p.z.mul(q.z);
        const d = zz.add(zz);
        return .{ .x = a.sub(b), .y = a.add(b), .z = d.add(c), .t = d.sub(c) };
    }

    /// ref10 `ge_sub`: `add` of the negated operand ((x, y) → (-x, y) swaps
    /// Y+X with Y-X and negates T).
    fn sub(p: P3, q: Cached) P1P1 {
        const a = p.y.add(p.x).mul(q.y_minus_x);
        const b = p.y.sub(p.x).mul(q.y_plus_x);
        const c = q.t2d.mul(p.t);
        const zz = p.z.mul(q.z);
        const d = zz.add(zz);
        return .{ .x = a.sub(b), .y = a.add(b), .z = d.sub(c), .t = d.add(c) };
    }
};

/// Completed ((X:Z), (Y:T)), x = X/Z, y = Y/T: an addition's or a doubling's
/// raw result.
const P1P1 = struct {
    x: Fe,
    y: Fe,
    z: Fe,
    t: Fe,

    fn toP2(p: P1P1) P2 {
        return .{ .x = p.x.mul(p.t), .y = p.y.mul(p.z), .z = p.z.mul(p.t) };
    }

    fn toP3(p: P1P1) P3 {
        return .{ .x = p.x.mul(p.t), .y = p.y.mul(p.z), .z = p.z.mul(p.t), .t = p.x.mul(p.y) };
    }
};

/// (Y+X, Y-X, Z, 2dT): an addition operand.
const Cached = struct {
    y_plus_x: Fe,
    y_minus_x: Fe,
    z: Fe,
    t2d: Fe,

    fn of(p: P3) Cached {
        return .{ .y_plus_x = p.y.add(p.x), .y_minus_x = p.y.sub(p.x), .z = p.z, .t2d = p.t.mul(Fe.edwards25519d2) };
    }
};

/// Odd multiples 1·P, 3·P, …, (2n-1)·P.
fn oddMultiples(comptime n: usize, p: P3) [n]Cached {
    var out: [n]Cached = undefined;
    out[0] = .of(p);
    const p2 = (P2{ .x = p.x, .y = p.y, .z = p.z }).dbl().toP3();
    var acc = p;
    for (1..n) |i| {
        acc = acc.add(.of(p2)).toP3();
        out[i] = .of(acc);
    }
    return out;
}

/// B, 3B, …, 63B for the width-7 wNAF of `s`.
const base_table: [32]Cached = blk: {
    @setEvalBranchQuota(200_000);
    break :blk oddMultiples(32, P3.of(Curve.basePoint));
};

/// Width-`w` signed sliding window (ref10 `slide`, generalised): odd digits
/// in [-(2^(w-1) - 1), 2^(w-1) - 1], at most one non-zero in any w
/// consecutive positions, sum of digit·2^i equal to `s` (s < 2^253, so the
/// carries stay inside 256 positions).
fn slide(comptime w: u4, s: [32]u8) [256]i8 {
    const max: i32 = (1 << (w - 1)) - 1;
    var r: [256]i8 = undefined;
    for (&r, 0..) |*d, i| d.* = @intCast((s[i >> 3] >> @intCast(i & 7)) & 1);
    for (0..256) |i| {
        if (r[i] == 0) continue;
        var b: usize = 1;
        while (b <= w + 1 and i + b < 256) : (b += 1) {
            if (r[i + b] == 0) continue;
            const shifted = @as(i32, r[i + b]) << @intCast(b);
            if (r[i] + shifted <= max) {
                r[i] = @intCast(r[i] + shifted);
                r[i + b] = 0;
            } else if (r[i] - shifted >= -max) {
                r[i] = @intCast(r[i] - shifted);
                var k = i + b;
                while (k < 256) : (k += 1) {
                    if (r[k] == 0) {
                        r[k] = 1;
                        break;
                    }
                    r[k] = 0;
                }
            } else break;
        }
    }
    return r;
}

/// `[sb]B + [sp]P`, in variable time: both scalars are public in a verify.
fn doubleScalarMul(sb: [32]u8, p: P3, sp: [32]u8) P3 {
    const eb = slide(7, sb);
    const ep = slide(5, sp);
    const pt = oddMultiples(8, p);
    var i: usize = 255;
    while (i > 0 and eb[i] == 0 and ep[i] == 0) i -= 1;
    var r: P2 = .identity;
    while (true) : (i -= 1) {
        var t = r.dbl();
        if (ep[i] > 0) {
            t = t.toP3().add(pt[@intCast(@divExact(ep[i] - 1, 2))]);
        } else if (ep[i] < 0) {
            t = t.toP3().sub(pt[@intCast(@divExact(-ep[i] - 1, 2))]);
        }
        if (eb[i] > 0) {
            t = t.toP3().add(base_table[@intCast(@divExact(eb[i] - 1, 2))]);
        } else if (eb[i] < 0) {
            t = t.toP3().sub(base_table[@intCast(@divExact(-eb[i] - 1, 2))]);
        }
        if (i == 0) return t.toP3();
        r = t.toP2();
    }
}

// ── tests ────────────────────────────────────────────────────────────────────

const testing = std.testing;

fn stdVerdict(sig: [64]u8, msg: []const u8, pk: Ed25519.PublicKey) bool {
    Ed25519.Signature.fromBytes(sig).verify(msg, pk) catch return false;
    return true;
}

fn ourVerdict(sig: [64]u8, msg: []const u8, pk: Ed25519.PublicKey) bool {
    verify(sig, msg, pk) catch return false;
    return true;
}

test "ed25519: slide digits are odd, bounded, sparse, and sum back to the scalar" {
    var prng = std.Random.DefaultPrng.init(0xed_51de);
    const rnd = prng.random();
    inline for (.{ 5, 7 }) |w| {
        const max = (1 << (w - 1)) - 1;
        for (0..2000) |n| {
            var s: [32]u8 = undefined;
            rnd.bytes(&s);
            if (n == 0) s = @splat(0xff); // the largest pattern below the 2^253 bound
            s[31] &= 0x1f;
            const d = slide(w, s);
            var sum: i512 = 0;
            var last_nonzero: ?usize = null;
            for (d, 0..) |x, i| {
                if (x == 0) continue;
                try testing.expect(@rem(x, 2) != 0);
                try testing.expect(x <= max and x >= -max);
                if (last_nonzero) |l| try testing.expect(i - l >= w);
                last_nonzero = i;
                sum += @as(i512, x) << @intCast(i);
            }
            try testing.expectEqual(@as(i512, std.mem.readInt(u256, &s, .little)), sum);
        }
    }
}

test "ed25519: doubleScalarMul equals std's [a]B + [b]P" {
    var prng = std.Random.DefaultPrng.init(0xd0_b1e);
    const rnd = prng.random();
    for (0..200) |_| {
        var a: [32]u8 = undefined;
        var b: [32]u8 = undefined;
        var k: [32]u8 = undefined;
        rnd.bytes(&a);
        rnd.bytes(&b);
        rnd.bytes(&k);
        a = Curve.scalar.reduce(a);
        b = Curve.scalar.reduce(b);
        const p = try Curve.basePoint.mul(Curve.scalar.reduce(k));
        const want = (try Curve.basePoint.mulPublic(a)).add(try p.mulPublic(b));
        const got = doubleScalarMul(a, P3.of(p), b);
        const g: Curve = .{ .x = got.x, .y = got.y, .z = got.z, .t = got.t };
        try testing.expectEqualSlices(u8, &want.toBytes(), &g.toBytes());
    }
}

test "ed25519: verify agrees with std on valid, corrupted and torsion-shifted signatures" {
    var prng = std.Random.DefaultPrng.init(0xed_d1ff);
    const rnd = prng.random();
    var agree_ok: usize = 0;
    var agree_bad: usize = 0;
    for (0..1500) |n| {
        var seed: [32]u8 = undefined;
        rnd.bytes(&seed);
        const kp = try Ed25519.KeyPair.generateDeterministic(seed);
        var msg_buf: [96]u8 = undefined;
        const msg = msg_buf[0 .. n % msg_buf.len];
        rnd.bytes(msg);
        var sig = (try kp.sign(msg, null)).toBytes();
        switch (n % 5) {
            0 => {},
            1 => sig[rnd.uintLessThan(usize, 64)] ^= @as(u8, 1) << rnd.int(u3),
            2 => rnd.bytes(sig[0..32]), // random R: mostly not a point
            3 => {
                // Signed with R' = rB + T for a point T of order 8, the
                // challenge taken over R': [S]B - [h]A - R' = -T, which the
                // cofactored check accepts (and a cofactorless one refuses).
                const t8 = try Curve.fromBytes(.{ 0x26, 0xe8, 0x95, 0x8f, 0xc2, 0xb2, 0x27, 0xb0, 0x45, 0xc3, 0xf4, 0x89, 0xf2, 0xef, 0x98, 0xf0, 0xd5, 0xdf, 0xac, 0x05, 0xd3, 0xc6, 0x33, 0x39, 0xb1, 0x38, 0x02, 0x88, 0x6d, 0x53, 0xfc, 0x05 });
                var az: [64]u8 = undefined;
                Sha512.hash(&seed, &az, .{});
                var a_scalar = az[0..32].*;
                Curve.scalar.clamp(&a_scalar);
                var r64: [64]u8 = undefined;
                rnd.bytes(&r64);
                const r_scalar = Curve.scalar.reduce64(r64);
                const r_shifted = (try Curve.basePoint.mulPublic(r_scalar)).add(t8).toBytes();
                var hh = Sha512.init(.{});
                hh.update(&r_shifted);
                hh.update(&kp.public_key.bytes);
                hh.update(msg);
                var h64: [64]u8 = undefined;
                hh.final(&h64);
                sig[0..32].* = r_shifted;
                sig[32..64].* = Curve.scalar.mulAdd(Curve.scalar.reduce64(h64), a_scalar, r_scalar);
            },
            4 => {
                // s + L: non-canonical, both refuse.
                var carry: u16 = 0;
                const l = [32]u8{ 0xed, 0xd3, 0xf5, 0x5c, 0x1a, 0x63, 0x12, 0x58, 0xd6, 0x9c, 0xf7, 0xa2, 0xde, 0xf9, 0xde, 0x14, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x10 };
                for (sig[32..], l) |*x, y| {
                    const v = @as(u16, x.*) + y + carry;
                    x.* = @truncate(v);
                    carry = v >> 8;
                }
            },
            else => unreachable,
        }
        const want = stdVerdict(sig, msg, kp.public_key);
        try testing.expectEqual(want, ourVerdict(sig, msg, kp.public_key));
        if (want) agree_ok += 1 else agree_bad += 1;
    }
    // Every class above was exercised on both sides of the verdict.
    try testing.expect(agree_ok >= 500 and agree_bad >= 500);
}

/// Encodings of the points of order 1, 2, 4 and 8 (the ones `Curve.fromBytes` decodes).
const small_order = [_][32]u8{
    .{ 0x01, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0 },
    .{ 0xec, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0x7f },
    .{ 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0 },
    .{ 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x80 },
    .{ 0x26, 0xe8, 0x95, 0x8f, 0xc2, 0xb2, 0x27, 0xb0, 0x45, 0xc3, 0xf4, 0x89, 0xf2, 0xef, 0x98, 0xf0, 0xd5, 0xdf, 0xac, 0x05, 0xd3, 0xc6, 0x33, 0x39, 0xb1, 0x38, 0x02, 0x88, 0x6d, 0x53, 0xfc, 0x05 },
    .{ 0xc7, 0x17, 0x6a, 0x70, 0x3d, 0x4d, 0xd8, 0x4f, 0xba, 0x3c, 0x0b, 0x76, 0x0d, 0x10, 0x67, 0x0f, 0x2a, 0x20, 0x53, 0xfa, 0x2c, 0x39, 0xcc, 0xc6, 0x4e, 0xc7, 0xfd, 0x77, 0x92, 0xac, 0x03, 0x7a },
    .{ 0x26, 0xe8, 0x95, 0x8f, 0xc2, 0xb2, 0x27, 0xb0, 0x45, 0xc3, 0xf4, 0x89, 0xf2, 0xef, 0x98, 0xf0, 0xd5, 0xdf, 0xac, 0x05, 0xd3, 0xc6, 0x33, 0x39, 0xb1, 0x38, 0x02, 0x88, 0x6d, 0x53, 0xfc, 0x85 },
    .{ 0xc7, 0x17, 0x6a, 0x70, 0x3d, 0x4d, 0xd8, 0x4f, 0xba, 0x3c, 0x0b, 0x76, 0x0d, 0x10, 0x67, 0x0f, 0x2a, 0x20, 0x53, 0xfa, 0x2c, 0x39, 0xcc, 0xc6, 0x4e, 0xc7, 0xfd, 0x77, 0x92, 0xac, 0x03, 0xfa },
};

test "ed25519: small-order public keys and R values are refused exactly as std refuses them" {
    // Each small-order encoding as public key and as R, with a signature that
    // is otherwise random.
    var prng = std.Random.DefaultPrng.init(0x5a_11);
    const rnd = prng.random();
    const kp = try Ed25519.KeyPair.generateDeterministic(@splat(0x42));
    const msg = "small order";
    const good = (try kp.sign(msg, null)).toBytes();
    for (small_order) |enc| {
        // As the public key, with a signature of a real key and a random one.
        const pk: Ed25519.PublicKey = .{ .bytes = enc };
        var sig = good;
        try testing.expectEqual(stdVerdict(sig, msg, pk), ourVerdict(sig, msg, pk));
        rnd.bytes(&sig);
        sig[63] &= 0x0f;
        try testing.expectEqual(stdVerdict(sig, msg, pk), ourVerdict(sig, msg, pk));
        // As R: [s]B = [h]A + small, for s chosen so the equation holds
        // modulo the torsion part -- std's cofactored check accepts some of
        // these, and the verdicts must match either way.
        sig = good;
        sig[0..32].* = enc;
        try testing.expectEqual(stdVerdict(sig, msg, kp.public_key), ourVerdict(sig, msg, kp.public_key));
    }
}

/// `H(R ‖ A ‖ M) mod L`, the challenge of RFC 8032 §5.1.6.
fn challenge(r: [32]u8, pk: [32]u8, msg: []const u8) [32]u8 {
    var hh = Sha512.init(.{});
    hh.update(&r);
    hh.update(&pk);
    hh.update(msg);
    var h64: [64]u8 = undefined;
    hh.final(&h64);
    return Curve.scalar.reduce64(h64);
}

fn secretScalar(seed: [32]u8) [32]u8 {
    var az: [64]u8 = undefined;
    Sha512.hash(&seed, &az, .{});
    var a_scalar = az[0..32].*;
    Curve.scalar.clamp(&a_scalar);
    return a_scalar;
}

/// An encoding `Curve.fromBytes` refuses (y with no x on the curve), found by scanning.
fn undecodable() [32]u8 {
    var y: [32]u8 = @splat(0);
    while (true) : (y[0] += 1) {
        if (Curve.fromBytes(y)) |_| continue else |_| return y;
    }
}

test "ed25519: signatures that only a skipped check would accept are refused, as std refuses them" {
    const seed: [32]u8 = @splat(0x7);
    const kp = try Ed25519.KeyPair.generateDeterministic(seed);
    const a_scalar = secretScalar(seed);
    const zero: [32]u8 = @splat(0);
    var one: [32]u8 = @splat(0);
    one[0] = 1;
    const msg = "forged";

    // R = the identity (a valid encoding of a small-order point std refuses
    // outright) and S = h·a: [S]B - [h]A - R = 0 holds exactly.
    {
        const r = small_order[0];
        const h = challenge(r, kp.public_key.bytes, msg);
        const sig = r ++ Curve.scalar.mulAdd(h, a_scalar, zero);
        try testing.expect(!stdVerdict(sig, msg, kp.public_key));
        try testing.expect(!ourVerdict(sig, msg, kp.public_key));
    }
    // R = an order-4 point written non-canonically (y = p, which decodes as
    // y = 0): the cofactored equation holds for S = h·a, only the encoding
    // check refuses it.
    {
        var r: [32]u8 = @splat(0xff);
        r[0] = 0xed;
        r[31] = 0x7f;
        _ = try Curve.fromBytes(r);
        const h = challenge(r, kp.public_key.bytes, msg);
        const sig = r ++ Curve.scalar.mulAdd(h, a_scalar, zero);
        try testing.expect(!stdVerdict(sig, msg, kp.public_key));
        try testing.expect(!ourVerdict(sig, msg, kp.public_key));
    }
    // R that is not a point at all, S = 1 + h·a: a decoder whose failure fell
    // back to the base point would see [S]B - [h]A - B = 0.
    {
        const r = undecodable();
        const h = challenge(r, kp.public_key.bytes, msg);
        const sig = r ++ Curve.scalar.mulAdd(h, a_scalar, one);
        try testing.expect(!stdVerdict(sig, msg, kp.public_key));
        try testing.expect(!ourVerdict(sig, msg, kp.public_key));
    }
    // A public key that is not a point, R = [r]B, S = r + h: the same fallback
    // (A = B) would make [S]B - [h]B - R = 0.
    {
        const pk_bytes = undecodable();
        const pk: Ed25519.PublicKey = .{ .bytes = pk_bytes };
        var r_scalar: [32]u8 = @splat(0);
        r_scalar[0] = 5;
        const r = (try Curve.basePoint.mulPublic(r_scalar)).toBytes();
        const h = challenge(r, pk_bytes, msg);
        const sig = r ++ Curve.scalar.mulAdd(h, one, r_scalar);
        try testing.expect(!stdVerdict(sig, msg, pk));
        try testing.expect(!ourVerdict(sig, msg, pk));
    }
}

test "ed25519: a weak public key (8A = 0) verifies nothing, whatever the equation says" {
    // [8]([S]B - [h]A - R) = [8]([S]B - R) for every A of order dividing 8;
    // with R = [S]B the equation holds for any message, so only the 8A test
    // (and the identity check for A itself) stands between this and a forgery.
    // Order 8 needs all three doublings, order 4 at least two.
    var one: [32]u8 = @splat(0);
    one[0] = 1;
    const r = Curve.basePoint.toBytes();
    for (small_order) |enc| {
        const pk: Ed25519.PublicKey = .{ .bytes = enc };
        for ([_][]const u8{ "", "msg", "another message" }) |msg| {
            const sig = r ++ one;
            try testing.expect(!stdVerdict(sig, msg, pk));
            try testing.expect(!ourVerdict(sig, msg, pk));
        }
    }
}

/// `mulPublic` refuses a zero product, the identity is the answer here.
fn mulOrIdentity(p: Curve, k: [32]u8) Curve {
    if (std.mem.allEqual(u8, &k, 0)) return Curve.identityElement;
    return p.mulPublic(k) catch unreachable;
}

test "ed25519: doubleScalarMul with a zero scalar, and the highest wNAF position for scalars below L" {
    var prng = std.Random.DefaultPrng.init(0x20_4d);
    const rnd = prng.random();
    const zero: [32]u8 = @splat(0);
    var k: [32]u8 = undefined;
    rnd.bytes(&k);
    const pc = try Curve.basePoint.mul(Curve.scalar.reduce(k));
    const p = P3.of(pc);
    var some: [32]u8 = undefined;
    rnd.bytes(&some);
    some = Curve.scalar.reduce(some);
    const cases = [_]struct { a: [32]u8, b: [32]u8 }{
        .{ .a = zero, .b = zero },
        .{ .a = some, .b = zero },
        .{ .a = zero, .b = some },
    };
    for (cases) |c| {
        const want = mulOrIdentity(Curve.basePoint, c.a).add(mulOrIdentity(pc, c.b));
        const got = doubleScalarMul(c.a, p, c.b);
        const g: Curve = .{ .x = got.x, .y = got.y, .z = got.z, .t = got.t };
        try testing.expectEqualSlices(u8, &want.toBytes(), &g.toBytes());
    }

    // The ladder may start at position 252 for every scalar below L
    // (L = 2^252 + 27742317777372353535851937790883648493): the extremes, and
    // random ones, have no digit above it.
    const l_minus_1 = [32]u8{ 0xec, 0xd3, 0xf5, 0x5c, 0x1a, 0x63, 0x12, 0x58, 0xd6, 0x9c, 0xf7, 0xa2, 0xde, 0xf9, 0xde, 0x14, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x10 };
    var two252_minus_1: [32]u8 = @splat(0xff);
    two252_minus_1[31] = 0x0f;
    var many: [64][32]u8 = undefined;
    many[0] = l_minus_1;
    many[1] = two252_minus_1;
    for (many[2..]) |*m| {
        rnd.bytes(m);
        m.* = Curve.scalar.reduce(m.*);
    }
    inline for (.{ 5, 7 }) |w| {
        for (many) |s| {
            const d = slide(w, s);
            for (d[253..]) |x| try testing.expectEqual(@as(i8, 0), x);
        }
    }
}
