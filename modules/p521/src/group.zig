// SPDX-License-Identifier: MIT

//! The NIST P-521 group (secp521r1, FIPS 186-5 / SP 800-186 §3.2.1.5):
//! y² = x³ − 3x + b over GF(2^521 − 1), prime order n, cofactor 1.
//!
//! Points are projective (X : Y : Z) and every addition and doubling uses the
//! complete formulas of Renes–Costello–Batina 2016 (eprint 2015/1060,
//! Algorithms 4, 5 and 6 for a = −3): no exceptional cases, so no branch on
//! whether two points coincide or one is the identity.
//!
//! Scalar multiplication:
//!   * `mul` (secret scalar): fixed 4-bit windows from the top, a 16-point
//!     table built from the public point, and every lookup a masked scan of
//!     the whole table — the same sequence of operations and memory accesses
//!     for every scalar. The scalar is any 66 bytes (no reduction needed:
//!     n·P = O). One code path for every secret, the base point included —
//!     no precomputed base table in phase 1 (SPEC.md § Backlog).
//!   * `mulPublic` / `mulDoubleBasePublic` (public scalars only, signature
//!     verification): signed 4-bit windows, VARIABLE TIME.
//!
//! The surface mirrors `std.crypto.ecc.P384` with 66-byte scalars and
//! coordinates, so code generic over std's curves reads the same.

const std = @import("std");
const field = @import("field.zig");
const ct = @import("ct.zig");
const burn = @import("burn.zig");
const scalar_mod = @import("scalar.zig");

const errors = std.crypto.errors;
const EncodingError = errors.EncodingError;
const IdentityElementError = errors.IdentityElementError;
const NonCanonicalError = errors.NonCanonicalError;
const NotSquareError = errors.NotSquareError;

/// A P-521 point in projective coordinates.
pub const P521 = struct {
    x: Fe,
    y: Fe,
    z: Fe = Fe.one,

    /// The base field.
    pub const Fe = field.Fe;
    /// The scalar field (the group order n).
    pub const scalar = scalar_mod;

    /// The curve constant b.
    pub const B = Fe.fromInt(0x0051953eb9618e1c9a1f929a21a0b68540eea2da725b99b315f3b8b489918ef109e156193951ec7e937b1652c0bd3bb1bf073573df883d2c34f1ef451fd46b503f00) catch unreachable;

    /// The base point G.
    pub const basePoint: P521 = .{
        .x = Fe.fromInt(0x00c6858e06b70404e9cd9e3ecb662395b4429c648139053fb521f828af606b4d3dbaa14b5e77efe75928fe1dc127a2ffa8de3348b3c1856a429bf97e7e31c2e5bd66) catch unreachable,
        .y = Fe.fromInt(0x011839296a789a3bc0045c8a5fb42c7d1bd998f54449579b446817afbd17273e662c97ee72995ef42640c550b9013fad0761353c7086a272c24088be94769fd16650) catch unreachable,
        .z = Fe.one,
    };

    /// The neutral element.
    pub const identityElement: P521 = .{ .x = Fe.zero, .y = Fe.one, .z = Fe.zero };

    /// Reject the neutral element.
    pub fn rejectIdentity(p: P521) IdentityElementError!void {
        if (p.z.isZero()) return error.IdentityElement;
    }

    /// 1 iff `p` is the neutral element, without a branch.
    fn isIdentityCt(p: P521) u1 {
        return @intFromBool(p.z.isZero());
    }

    /// A point from affine coordinates, after checking the curve equation.
    /// (0, 0) is accepted as the affine encoding of the identity, as std does.
    pub fn fromAffineCoordinates(p: AffineCoordinates) EncodingError!P521 {
        const on_curve = @intFromBool(rhs(p.x).equivalent(p.y.sq()));
        const is_identity = @intFromBool(p.x.isZero()) & @intFromBool(p.y.isZero());
        if ((on_curve | is_identity) == 0) return error.InvalidEncoding;
        var ret: P521 = .{ .x = p.x, .y = p.y, .z = Fe.one };
        ret.cMov(identityElement, is_identity);
        return ret;
    }

    /// x³ − 3x + b.
    fn rhs(x: Fe) Fe {
        return x.sq().mul(x).sub(x.mulSmall(3)).add(B);
    }

    /// A point from serialized affine coordinates.
    pub fn fromSerializedAffineCoordinates(xs: [66]u8, ys: [66]u8, endian: std.builtin.Endian) (NonCanonicalError || EncodingError)!P521 {
        const x = try Fe.fromBytes(xs, endian);
        const y = try Fe.fromBytes(ys, endian);
        return fromAffineCoordinates(.{ .x = x, .y = y });
    }

    /// Recover y from x and the parity of y.
    pub fn recoverY(x: Fe, is_odd: bool) NotSquareError!Fe {
        var y = try rhs(x).sqrt();
        const yn = y.neg();
        y.cMov(yn, @intFromBool(is_odd) ^ @intFromBool(y.isOdd()));
        return y;
    }

    /// Decode a SEC1 point: `0x04 ‖ X ‖ Y` (133 bytes), `0x02/0x03 ‖ X`
    /// (67 bytes), or `0x00` (the identity, as std accepts it — key decoders
    /// on top of this refuse it). Coordinates must be canonical (< p) and the
    /// point on the curve; cofactor 1, so on the curve means in the group.
    pub fn fromSec1(s: []const u8) (EncodingError || NotSquareError || NonCanonicalError)!P521 {
        if (s.len < 1) return error.InvalidEncoding;
        const encoded = s[1..];
        switch (s[0]) {
            0 => {
                if (encoded.len != 0) return error.InvalidEncoding;
                return identityElement;
            },
            2, 3 => {
                if (encoded.len != 66) return error.InvalidEncoding;
                const x = try Fe.fromBytes(encoded[0..66].*, .big);
                const y = try recoverY(x, s[0] == 3);
                return .{ .x = x, .y = y };
            },
            4 => {
                if (encoded.len != 132) return error.InvalidEncoding;
                const x = try Fe.fromBytes(encoded[0..66].*, .big);
                const y = try Fe.fromBytes(encoded[66..132].*, .big);
                return fromAffineCoordinates(.{ .x = x, .y = y });
            },
            else => return error.InvalidEncoding,
        }
    }

    /// Compressed SEC1 encoding (67 bytes).
    pub fn toCompressedSec1(p: P521) [67]u8 {
        var out: [67]u8 = undefined;
        const xy = p.affineCoordinates();
        out[0] = if (xy.y.isOdd()) 3 else 2;
        out[1..].* = xy.x.toBytes(.big);
        return out;
    }

    /// Uncompressed SEC1 encoding (133 bytes).
    pub fn toUncompressedSec1(p: P521) [133]u8 {
        var out: [133]u8 = undefined;
        out[0] = 4;
        const xy = p.affineCoordinates();
        out[1..67].* = xy.x.toBytes(.big);
        out[67..133].* = xy.y.toBytes(.big);
        return out;
    }

    /// A random point (a random multiple of G).
    pub fn random(io: std.Io) error{EntropyUnavailable}!P521 {
        var s = (try scalar.Scalar.random(io)).toBytes(.big);
        defer std.crypto.secureZero(u8, &s);
        var out: P521 = undefined;
        mulInto(&out, basePoint, &s, .big) catch unreachable;
        return out;
    }

    /// −p.
    pub fn neg(p: P521) P521 {
        return .{ .x = p.x, .y = p.y.neg(), .z = p.z };
    }

    /// 2p (RCB Algorithm 6, a = −3).
    pub fn dbl(p: P521) P521 {
        var t0 = p.x.sq();
        const t1 = p.y.sq();
        var t2 = p.z.sq();
        var t3 = p.x.mul(p.y);
        t3 = t3.dbl();
        var z3 = p.x.mul(p.z);
        z3 = z3.dbl();
        var y3 = B.mul(t2);
        y3 = y3.sub(z3);
        var x3 = y3.dbl();
        y3 = x3.add(y3);
        x3 = t1.sub(y3);
        y3 = t1.add(y3);
        y3 = x3.mul(y3);
        x3 = x3.mul(t3);
        t3 = t2.dbl();
        t2 = t2.add(t3);
        z3 = B.mul(z3);
        z3 = z3.sub(t2);
        z3 = z3.sub(t0);
        t3 = z3.dbl();
        z3 = z3.add(t3);
        t3 = t0.dbl();
        t0 = t3.add(t0);
        t0 = t0.sub(t2);
        t0 = t0.mul(z3);
        y3 = y3.add(t0);
        t0 = p.y.mul(p.z);
        t0 = t0.dbl();
        z3 = t0.mul(z3);
        x3 = x3.sub(z3);
        z3 = t0.mul(t1);
        z3 = z3.mulSmall(4);
        return .{ .x = x3, .y = y3, .z = z3 };
    }

    /// p + q (RCB Algorithm 4, a = −3; complete).
    pub fn add(p: P521, q: P521) P521 {
        var t0 = p.x.mul(q.x);
        var t1 = p.y.mul(q.y);
        var t2 = p.z.mul(q.z);
        var t3 = p.x.add(p.y);
        var t4 = q.x.add(q.y);
        t3 = t3.mul(t4);
        t4 = t0.add(t1);
        t3 = t3.sub(t4);
        t4 = p.y.add(p.z);
        var x3 = q.y.add(q.z);
        t4 = t4.mul(x3);
        x3 = t1.add(t2);
        t4 = t4.sub(x3);
        x3 = p.x.add(p.z);
        var y3 = q.x.add(q.z);
        x3 = x3.mul(y3);
        y3 = t0.add(t2);
        y3 = x3.sub(y3);
        var z3 = B.mul(t2);
        x3 = y3.sub(z3);
        z3 = x3.dbl();
        x3 = x3.add(z3);
        z3 = t1.sub(x3);
        x3 = t1.add(x3);
        y3 = B.mul(y3);
        t1 = t2.dbl();
        t2 = t1.add(t2);
        y3 = y3.sub(t2);
        y3 = y3.sub(t0);
        t1 = y3.dbl();
        y3 = t1.add(y3);
        t1 = t0.dbl();
        t0 = t1.add(t0);
        t0 = t0.sub(t2);
        t1 = t4.mul(y3);
        t2 = t0.mul(y3);
        y3 = x3.mul(z3);
        y3 = y3.add(t2);
        x3 = t3.mul(x3);
        x3 = x3.sub(t1);
        z3 = t4.mul(z3);
        t1 = t3.mul(t0);
        z3 = z3.add(t1);
        return .{ .x = x3, .y = y3, .z = z3 };
    }

    /// p + q with q affine (RCB Algorithm 5). q must not be the identity
    /// unless given as (0, 0), which this handles by a masked move.
    pub fn addMixed(p: P521, q: AffineCoordinates) P521 {
        var t0 = p.x.mul(q.x);
        var t1 = p.y.mul(q.y);
        var t3 = q.x.add(q.y);
        var t4 = p.x.add(p.y);
        t3 = t3.mul(t4);
        t4 = t0.add(t1);
        t3 = t3.sub(t4);
        t4 = q.y.mul(p.z);
        t4 = t4.add(p.y);
        var y3 = q.x.mul(p.z);
        y3 = y3.add(p.x);
        var z3 = B.mul(p.z);
        var x3 = y3.sub(z3);
        z3 = x3.dbl();
        x3 = x3.add(z3);
        z3 = t1.sub(x3);
        x3 = t1.add(x3);
        y3 = B.mul(y3);
        t1 = p.z.dbl();
        var t2 = t1.add(p.z);
        y3 = y3.sub(t2);
        y3 = y3.sub(t0);
        t1 = y3.dbl();
        y3 = t1.add(y3);
        t1 = t0.dbl();
        t0 = t1.add(t0);
        t0 = t0.sub(t2);
        t1 = t4.mul(y3);
        t2 = t0.mul(y3);
        y3 = x3.mul(z3);
        y3 = y3.add(t2);
        x3 = t3.mul(x3);
        x3 = x3.sub(t1);
        z3 = t4.mul(z3);
        t1 = t3.mul(t0);
        z3 = z3.add(t1);
        var ret: P521 = .{ .x = x3, .y = y3, .z = z3 };
        ret.cMov(p, @intFromBool(q.x.isZero()) & @intFromBool(q.y.isZero()));
        return ret;
    }

    /// p − q.
    pub fn sub(p: P521, q: P521) P521 {
        return p.add(q.neg());
    }

    /// p − q with q affine.
    pub fn subMixed(p: P521, q: AffineCoordinates) P521 {
        return p.addMixed(q.neg());
    }

    /// Affine coordinates; the identity maps to (0, 0). One field inversion,
    /// constant time.
    pub fn affineCoordinates(p: P521) AffineCoordinates {
        const zinv = p.z.invert();
        // z = 0 gives zinv = 0 and so (0, 0) on its own.
        return .{ .x = p.x.mul(zinv), .y = p.y.mul(zinv) };
    }

    /// Whether both represent the same point (projective cross-multiply).
    pub fn equivalent(a: P521, b: P521) bool {
        const x_eq = a.x.mul(b.z).equivalent(b.x.mul(a.z));
        const y_eq = a.y.mul(b.z).equivalent(b.y.mul(a.z));
        return x_eq and y_eq;
    }

    fn cMov(p: *P521, a: P521, c: u1) void {
        p.x.cMov(a.x, c);
        p.y.cMov(a.y, c);
        p.z.cMov(a.z, c);
    }

    /// `pc[b]` by a masked scan of all 16 entries.
    fn pcSelect(pc: *const [16]P521, b: u8) P521 {
        var t = pc[0];
        inline for (1..16) |i| {
            const d: u64 = b ^ @as(u8, i);
            t.cMov(pc[i], @truncate((d -% 1) >> 63));
        }
        return t;
    }

    fn precompute(p: P521, comptime count: usize) [1 + count]P521 {
        var pc: [1 + count]P521 = undefined;
        pc[0] = identityElement;
        pc[1] = p;
        var i: usize = 2;
        while (i <= count) : (i += 1) {
            pc[i] = if (i % 2 == 0) pc[i / 2].dbl() else pc[i - 1].add(p);
        }
        return pc;
    }

    /// The constant-time core: s (little-endian, 66 bytes) · p.
    fn mulCt(p: P521, s: *const [66]u8) P521 {
        const pc = precompute(p, 15);
        var q = identityElement;
        var pos: usize = 132;
        while (pos > 0) {
            pos -= 1;
            // `pos` is public: the first window skips the doublings of the
            // identity, every scalar alike.
            if (pos != 131) q = q.dbl().dbl().dbl().dbl();
            const nib: u8 = (s[pos >> 1] >> @as(u3, @intCast((pos & 1) * 4))) & 0xf;
            q = q.add(pcSelect(&pc, nib));
        }
        return q;
    }

    /// Multiply by a (secret) scalar, constant time. `error.IdentityElement`
    /// if `p` or the result is the identity. std's shape (scalar by value);
    /// `mulInto` is the dead-stack-clean form.
    pub fn mul(p: P521, s_: [66]u8, endian: std.builtin.Endian) IdentityElementError!P521 {
        var out: P521 = undefined;
        try mulInto(&out, p, &s_, endian);
        return out;
    }

    /// `mul` with the scalar by pointer and the product into `out` (zeroed
    /// on error). Burned (`burn.mul_burn`).
    pub fn mulInto(out: *P521, p: P521, s: *const [66]u8, endian: std.builtin.Endian) IdentityElementError!void {
        return burn.run(burn.mul_burn, IdentityElementError!void, mulIntoBody, .{ out, &p, s, endian });
    }

    fn mulIntoBody(out: *P521, p: *const P521, s: *const [66]u8, endian: std.builtin.Endian) IdentityElementError!void {
        errdefer out.* = identityElement;
        try p.rejectIdentity();
        var le = s.*;
        defer std.crypto.secureZero(u8, &le);
        if (endian == .big) std.mem.reverse(u8, &le);
        out.* = mulCt(p.*, &le);
        // The identity verdict on the product: revealed by the error.
        var id: u8 = out.isIdentityCt();
        ct.declassify(&id);
        if (id != 0) return error.IdentityElement;
    }

    /// The constant-time `s·G` for callers already running under a burn
    /// with a scalar already range-checked (ECDSA key derivation and the
    /// nonce commitment): no identity check, no burn of its own. `s` is
    /// little-endian. Not for direct use; `mulInto` is the API.
    pub fn mulBaseCtUnburned(s: *const [66]u8) P521 {
        return mulCt(basePoint, s);
    }

    /// Signed 4-bit digits of a little-endian scalar, each in [−8, 8].
    fn slide(s: [66]u8) [133]i8 {
        var e: [133]i8 = undefined;
        for (s, 0..) |x, i| {
            e[i * 2 + 0] = @as(i8, @as(u4, @truncate(x)));
            e[i * 2 + 1] = @as(i8, @as(u4, @truncate(x >> 4)));
        }
        var carry: i8 = 0;
        for (e[0..132]) |*x| {
            x.* += carry;
            carry = (x.* + 8) >> 4;
            x.* -= carry * 16;
        }
        e[132] = carry;
        return e;
    }

    /// Multiply by a PUBLIC scalar, IN VARIABLE TIME (verification only).
    pub fn mulPublic(p: P521, s_: [66]u8, endian: std.builtin.Endian) IdentityElementError!P521 {
        var s = s_;
        if (endian == .big) std.mem.reverse(u8, &s);
        try p.rejectIdentity();
        const pc = precompute(p, 8);
        const e = slide(s);
        var q = identityElement;
        var pos: usize = e.len;
        while (pos > 0) {
            pos -= 1;
            q = q.dbl().dbl().dbl().dbl();
            const d = e[pos];
            if (d > 0) q = q.add(pc[@intCast(d)]) else if (d < 0) q = q.sub(pc[@intCast(-d)]);
        }
        try q.rejectIdentity();
        return q;
    }

    /// p1·s1 + p2·s2 for PUBLIC scalars, IN VARIABLE TIME (verification).
    pub fn mulDoubleBasePublic(p1: P521, s1_: [66]u8, p2: P521, s2_: [66]u8, endian: std.builtin.Endian) IdentityElementError!P521 {
        var s1 = s1_;
        var s2 = s2_;
        if (endian == .big) {
            std.mem.reverse(u8, &s1);
            std.mem.reverse(u8, &s2);
        }
        try p1.rejectIdentity();
        try p2.rejectIdentity();
        const pc1 = precompute(p1, 8);
        const pc2 = precompute(p2, 8);
        const e1 = slide(s1);
        const e2 = slide(s2);
        var q = identityElement;
        var pos: usize = e1.len;
        while (pos > 0) {
            pos -= 1;
            q = q.dbl().dbl().dbl().dbl();
            const d1 = e1[pos];
            if (d1 > 0) q = q.add(pc1[@intCast(d1)]) else if (d1 < 0) q = q.sub(pc1[@intCast(-d1)]);
            const d2 = e2[pos];
            if (d2 > 0) q = q.add(pc2[@intCast(d2)]) else if (d2 < 0) q = q.sub(pc2[@intCast(-d2)]);
        }
        try q.rejectIdentity();
        return q;
    }
};

/// What `ecdh` can fail with.
pub const EcdhError = IdentityElementError || NonCanonicalError || EncodingError || NotSquareError;

/// ECDH (SP 800-56A §5.7.1.2 / SEC 1 §3.3.1): the x-coordinate of
/// `secret · peer`, 66 bytes big-endian. `secret` must be in [1, n − 1]
/// (`error.NonCanonical` above, `error.IdentityElement` for 0); `peer_sec1`
/// is a compressed or uncompressed SEC1 point, validated (canonical, on the
/// curve, not the identity). std's shape (secret by value, result returned);
/// `ecdhInto` is the dead-stack-clean form.
pub fn ecdh(secret: [66]u8, peer_sec1: []const u8) EcdhError![66]u8 {
    var out: [66]u8 = undefined;
    try ecdhInto(&out, &secret, peer_sec1);
    return out;
}

/// `ecdh` with the secret by pointer and the shared secret into `out`
/// (zeroed on error). Burned (`burn.mul_burn`); constant time in `secret`.
pub fn ecdhInto(out: *[66]u8, secret: *const [66]u8, peer_sec1: []const u8) EcdhError!void {
    return burn.run(burn.mul_burn, EcdhError!void, ecdhBody, .{ out, secret, peer_sec1 });
}

fn ecdhBody(out: *[66]u8, secret: *const [66]u8, peer_sec1: []const u8) EcdhError!void {
    errdefer out.* = @splat(0);
    const peer = try P521.fromSec1(peer_sec1);
    try peer.rejectIdentity();
    // Range verdicts on the secret: revealed by the error, declassified.
    var ok: u8 = 0;
    const s = scalar_mod.Scalar.fromBytesCt(secret, .big, &ok);
    var zero: u8 = s.isZeroCt();
    ct.declassify(&ok);
    ct.declassify(&zero);
    if (ok == 0) return error.NonCanonical;
    if (zero != 0) return error.IdentityElement;
    var le = secret.*;
    defer std.crypto.secureZero(u8, &le);
    std.mem.reverse(u8, &le);
    const q = P521.mulCt(peer, &le);
    // Never the identity for s in [1, n − 1] and a point of prime order;
    // checked anyway, on a verdict the error would reveal.
    var id: u8 = q.isIdentityCt();
    ct.declassify(&id);
    if (id != 0) return error.IdentityElement;
    out.* = q.affineCoordinates().x.toBytes(.big);
}

/// A point in affine coordinates.
pub const AffineCoordinates = struct {
    x: P521.Fe,
    y: P521.Fe,

    /// The identity in affine form, (0, 0) — what `affineCoordinates`
    /// returns for it.
    pub const identityElement: AffineCoordinates = .{ .x = P521.Fe.zero, .y = P521.Fe.zero };

    pub fn neg(p: AffineCoordinates) AffineCoordinates {
        return .{ .x = p.x, .y = p.y.neg() };
    }
};

// ── tests ───────────────────────────────────────────────────────────────────

const testing = std.testing;

fn nBytes() [66]u8 {
    var b: [66]u8 = undefined;
    std.mem.writeInt(u528, &b, scalar_mod.field_order, .big);
    return b;
}

test "group: G is on the curve and has order n" {
    _ = try P521.fromAffineCoordinates(P521.basePoint.affineCoordinates());
    try testing.expectError(error.IdentityElement, P521.basePoint.mul(nBytes(), .big));
    var nm1 = nBytes();
    nm1[65] -= 1; // n − 1: −G
    const q = try P521.basePoint.mul(nm1, .big);
    try testing.expect(q.equivalent(P521.basePoint.neg()));
    try testing.expectError(error.IdentityElement, P521.basePoint.mulPublic(nBytes(), .big));
}

test "group: complete addition (doubling via add, identity both sides)" {
    const g = P521.basePoint;
    try testing.expect(g.add(g).equivalent(g.dbl()));
    try testing.expect(g.add(P521.identityElement).equivalent(g));
    try testing.expect(P521.identityElement.add(g).equivalent(g));
    try testing.expect(g.sub(g).equivalent(P521.identityElement));
    try testing.expect(P521.identityElement.dbl().z.isZero());
    const g2 = g.dbl();
    try testing.expect(g2.add(g).equivalent(g.add(g2)));
    try testing.expect(g2.addMixed(g.affineCoordinates()).equivalent(g2.add(g)));
    try testing.expect(g2.addMixed(AffineCoordinates.identityElement).equivalent(g2));
}

test "group: constant-time, vartime and double-base multiplies agree" {
    var prng = std.Random.DefaultPrng.init(0x5213);
    const r = prng.random();
    for (0..6) |_| {
        var a: [66]u8 = undefined;
        var b: [66]u8 = undefined;
        r.bytes(&a);
        r.bytes(&b);
        a[0] &= 1;
        b[0] &= 1;
        const pa = try P521.basePoint.mul(a, .big);
        try testing.expect(pa.equivalent(try P521.basePoint.mulPublic(a, .big)));
        const pb = try pa.mul(b, .big);
        const ab = scalar_mod.mul(a, b, .big) catch continue; // ≥ n: probability 2^-260
        const pab = try P521.basePoint.mul(ab, .big);
        try testing.expect(pb.equivalent(pab));
        const dbp = try P521.mulDoubleBasePublic(P521.basePoint, a, pa, b, .big);
        try testing.expect(dbp.equivalent(pa.add(pb)));
        // Little-endian input is the same scalar.
        var al = a;
        std.mem.reverse(u8, &al);
        try testing.expect(pa.equivalent(try P521.basePoint.mul(al, .little)));
    }
}

test "group: SEC1 round trips and refusals" {
    const g = P521.basePoint;
    const u = g.toUncompressedSec1();
    const c = g.toCompressedSec1();
    try testing.expect((try P521.fromSec1(&u)).equivalent(g));
    try testing.expect((try P521.fromSec1(&c)).equivalent(g));
    const g3 = g.dbl().add(g);
    try testing.expect((try P521.fromSec1(&g3.toCompressedSec1())).equivalent(g3));
    // Off the curve.
    var bad = u;
    bad[132] ^= 1;
    try testing.expectError(error.InvalidEncoding, P521.fromSec1(&bad));
    // Wrong lengths / prefixes.
    try testing.expectError(error.InvalidEncoding, P521.fromSec1(u[0..132]));
    try testing.expectError(error.InvalidEncoding, P521.fromSec1(&.{}));
    bad = u;
    bad[0] = 5;
    try testing.expectError(error.InvalidEncoding, P521.fromSec1(&bad));
    // x = p: non-canonical.
    var nc: [67]u8 = @splat(0xff);
    nc[0] = 2;
    nc[1] = 1;
    try testing.expectError(error.NonCanonical, P521.fromSec1(&nc));
    // The identity encoding decodes to the identity (std's behaviour).
    try testing.expect((try P521.fromSec1(&.{0})).z.isZero());
}
