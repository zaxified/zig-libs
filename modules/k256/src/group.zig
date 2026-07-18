// SPDX-License-Identifier: MIT

//! group — the secp256k1 curve group over k256's base field `Fe`.
//!
//! Points are homogeneous projective `(X : Y : Z)` with affine `(X/Z, Y/Z)`, and
//! the add/double use the **Renes–Costello–Batina complete formulas**
//! (eprint 2015/1060, algorithms 7 & 9) — the same exception-free, branch-free
//! law `std.crypto.ecc.Secp256k1` uses. secp256k1 has prime order (cofactor 1),
//! so these formulas are complete for ALL inputs (identity, equal points,
//! inverses), which is exactly what makes the constant-time `mul` ladder below
//! safe with no special cases. Because the arithmetic is identical to std's and
//! runs over `Fe` (which is byte-exact vs std's field), the whole group is
//! byte-exact vs `std.crypto.ecc.Secp256k1` at the point level — the oracle
//! differential in `oracle_test.zig` pins it.
//!
//! Scalar multiplication:
//!   * `mul` — CONSTANT-TIME fixed 256-bit double-and-add with a `cMov` bit
//!     select (secret scalars: key derivation, signing nonce).
//!   * `mulPublic` — VARIABLE-TIME single-base multiply for public scalars, the
//!     dispatch point for the gated GLV core (`mulPublicGlv`); portable fallback
//!     is a plain vartime double-and-add.
//!   * `mulDoubleBasePublic` — VARIABLE-TIME `s1·P1 + s2·P2`, the verifier's
//!     `s·G − e·P` workhorse.
//!
//! SPEC.md documents the fast-path design the Fable phase targets (fixed-base
//! wNAF table for `G`, GLV for variable-base); this scaffold ships the simple
//! double-and-add forms as the proven portable oracle those must match.

const std = @import("std");
const gate = @import("gate.zig");
const field = @import("field.zig");
const scalarmod = @import("scalar.zig");

const Fe = field.Fe;

const IdentityElementError = std.crypto.errors.IdentityElementError;
const EncodingError = std.crypto.errors.EncodingError;
const NonCanonicalError = std.crypto.errors.NonCanonicalError;
const NotSquareError = std.crypto.errors.NotSquareError;

/// A point on secp256k1 in projective coordinates.
pub const Secp256k1 = struct {
    x: Fe,
    y: Fe,
    z: Fe = Fe.one,

    /// The curve constant `b` in `y² = x³ + b`.
    pub const B = Fe.fromInt(7) catch unreachable;

    /// The standard base point `G`.
    pub const basePoint = Secp256k1{
        .x = Fe.fromInt(55066263022277343669578718895168534326250603453777594175500187360389116729240) catch unreachable,
        .y = Fe.fromInt(32670510020758816978083085130507043184471273380659243275938904335757337482424) catch unreachable,
        .z = Fe.one,
    };

    /// The neutral element `(0 : 1 : 0)`.
    pub const identityElement = Secp256k1{ .x = Fe.zero, .y = Fe.one, .z = Fe.zero };

    /// Reject the neutral element (mirrors std's check: `z = 0`, or the affine
    /// identity `(0, 0/1)` a formula could produce).
    pub fn rejectIdentity(p: Secp256k1) IdentityElementError!void {
        const affine_0 = @intFromBool(p.x.equivalent(AffineCoordinates.identityElement.x)) &
            (@intFromBool(p.y.isZero()) | @intFromBool(p.y.equivalent(AffineCoordinates.identityElement.y)));
        const is_identity = @intFromBool(p.z.isZero()) | affine_0;
        if (is_identity != 0) return error.IdentityElement;
    }

    /// Build a point from affine coordinates, checking the curve equation.
    pub fn fromAffineCoordinates(p: AffineCoordinates) EncodingError!Secp256k1 {
        const x = p.x;
        const y = p.y;
        const x3B = x.sq().mul(x).add(B);
        const yy = y.sq();
        const on_curve = @intFromBool(x3B.equivalent(yy));
        const is_identity = @intFromBool(x.equivalent(AffineCoordinates.identityElement.x)) &
            @intFromBool(y.equivalent(AffineCoordinates.identityElement.y));
        if ((on_curve | is_identity) == 0) return error.InvalidEncoding;
        var ret = Secp256k1{ .x = x, .y = y, .z = Fe.one };
        ret.z.cMov(Secp256k1.identityElement.z, is_identity);
        return ret;
    }

    /// Build a point from serialized affine coordinates.
    pub fn fromSerializedAffineCoordinates(xs: [32]u8, ys: [32]u8, endian: std.builtin.Endian) (NonCanonicalError || EncodingError)!Secp256k1 {
        const x = try Fe.fromBytes(xs, endian);
        const y = try Fe.fromBytes(ys, endian);
        return fromAffineCoordinates(.{ .x = x, .y = y });
    }

    /// Recover the `y` coordinate for a given `x` and parity, i.e. BIP340's
    /// `lift_x` when `is_odd = false`. `error.NotSquare` if `x³ + 7` is not a QR.
    pub fn recoverY(x: Fe, is_odd: bool) NotSquareError!Fe {
        const x3B = x.sq().mul(x).add(B);
        var y = try x3B.sqrt();
        const yn = y.neg();
        y.cMov(yn, @intFromBool(is_odd) ^ @intFromBool(y.isOdd()));
        return y;
    }

    /// Deserialize a SEC1-encoded point (compressed 02/03, uncompressed 04, or
    /// the single-byte 00 identity).
    pub fn fromSec1(s: []const u8) (EncodingError || NotSquareError || NonCanonicalError)!Secp256k1 {
        if (s.len < 1) return error.InvalidEncoding;
        const encoded = s[1..];
        switch (s[0]) {
            0 => {
                if (encoded.len != 0) return error.InvalidEncoding;
                return Secp256k1.identityElement;
            },
            2, 3 => {
                if (encoded.len != 32) return error.InvalidEncoding;
                const x = try Fe.fromBytes(encoded[0..32].*, .big);
                const y = try recoverY(x, s[0] == 3);
                return Secp256k1{ .x = x, .y = y };
            },
            4 => {
                if (encoded.len != 64) return error.InvalidEncoding;
                const x = try Fe.fromBytes(encoded[0..32].*, .big);
                const y = try Fe.fromBytes(encoded[32..64].*, .big);
                return fromAffineCoordinates(.{ .x = x, .y = y });
            },
            else => return error.InvalidEncoding,
        }
    }

    /// Serialize using the compressed SEC1 format.
    pub fn toCompressedSec1(p: Secp256k1) [33]u8 {
        var out: [33]u8 = undefined;
        const xy = p.affineCoordinates();
        out[0] = if (xy.y.isOdd()) 3 else 2;
        out[1..].* = xy.x.toBytes(.big);
        return out;
    }

    /// Serialize using the uncompressed SEC1 format.
    pub fn toUncompressedSec1(p: Secp256k1) [65]u8 {
        var out: [65]u8 = undefined;
        out[0] = 4;
        const xy = p.affineCoordinates();
        out[1..33].* = xy.x.toBytes(.big);
        out[33..65].* = xy.y.toBytes(.big);
        return out;
    }

    /// Negate a point.
    pub fn neg(p: Secp256k1) Secp256k1 {
        return .{ .x = p.x, .y = p.y.neg(), .z = p.z };
    }

    /// Double a point (RCB algorithm 9, complete for `a = 0`).
    pub fn dbl(p: Secp256k1) Secp256k1 {
        var t0 = p.y.sq();
        var Z3 = t0.dbl();
        Z3 = Z3.dbl();
        Z3 = Z3.dbl();
        var t1 = p.y.mul(p.z);
        var t2 = p.z.sq();
        const t2_4 = t2.dbl().dbl();
        t2 = t2_4.dbl().dbl().add(t2_4).add(t2);
        var X3 = t2.mul(Z3);
        var Y3 = t0.add(t2);
        Z3 = t1.mul(Z3);
        t1 = t2.dbl();
        t2 = t1.add(t2);
        t0 = t0.sub(t2);
        Y3 = t0.mul(Y3);
        Y3 = X3.add(Y3);
        t1 = p.x.mul(p.y);
        X3 = t0.mul(t1);
        X3 = X3.dbl();
        return .{ .x = X3, .y = Y3, .z = Z3 };
    }

    /// Add two points (RCB algorithm 7, complete for all inputs on this
    /// prime-order curve).
    pub fn add(p: Secp256k1, q: Secp256k1) Secp256k1 {
        var t0 = p.x.mul(q.x);
        var t1 = p.y.mul(q.y);
        var t2 = p.z.mul(q.z);
        var t3 = p.x.add(p.y);
        var t4 = q.x.add(q.y);
        t3 = t3.mul(t4);
        t4 = t0.add(t1);
        t3 = t3.sub(t4);
        t4 = p.y.add(p.z);
        var X3 = q.y.add(q.z);
        t4 = t4.mul(X3);
        X3 = t1.add(t2);
        t4 = t4.sub(X3);
        X3 = p.x.add(p.z);
        var Y3 = q.x.add(q.z);
        X3 = X3.mul(Y3);
        Y3 = t0.add(t2);
        Y3 = X3.sub(Y3);
        X3 = t0.dbl();
        t0 = X3.add(t0);
        const t2_4 = t2.dbl().dbl();
        t2 = t2_4.dbl().dbl().add(t2_4).add(t2);
        var Z3 = t1.add(t2);
        t1 = t1.sub(t2);
        const Y3_4 = Y3.dbl().dbl();
        Y3 = Y3_4.dbl().dbl().add(Y3_4).add(Y3);
        X3 = t4.mul(Y3);
        t2 = t3.mul(t1);
        X3 = t2.sub(X3);
        Y3 = Y3.mul(t0);
        t1 = t1.mul(Z3);
        Y3 = t1.add(Y3);
        t0 = t0.mul(t3);
        Z3 = Z3.mul(t4);
        Z3 = Z3.add(t0);
        return .{ .x = X3, .y = Y3, .z = Z3 };
    }

    /// Subtract points.
    pub fn sub(p: Secp256k1, q: Secp256k1) Secp256k1 {
        return p.add(q.neg());
    }

    /// Return affine coordinates (one field inversion).
    pub fn affineCoordinates(p: Secp256k1) AffineCoordinates {
        const affine_0 = @intFromBool(p.x.equivalent(AffineCoordinates.identityElement.x)) &
            (@intFromBool(p.y.isZero()) | @intFromBool(p.y.equivalent(AffineCoordinates.identityElement.y)));
        const is_identity = @intFromBool(p.z.isZero()) | affine_0;
        const zinv = p.z.invert();
        var ret = AffineCoordinates{ .x = p.x.mul(zinv), .y = p.y.mul(zinv) };
        ret.cMov(AffineCoordinates.identityElement, is_identity);
        return ret;
    }

    /// True iff both represent the same point.
    pub fn equivalent(a: Secp256k1, b: Secp256k1) bool {
        if (a.sub(b).rejectIdentity()) {
            return false;
        } else |_| {
            return true;
        }
    }

    fn cMov(p: *Secp256k1, a: Secp256k1, c: u1) void {
        p.x.cMov(a.x, c);
        p.y.cMov(a.y, c);
        p.z.cMov(a.z, c);
    }

    // ── scalar multiplication ───────────────────────────────────────────────

    inline fn scalarValue(s_: [32]u8, endian: std.builtin.Endian) u256 {
        return std.mem.readInt(u256, &s_, endian);
    }

    /// CONSTANT-TIME scalar multiply `s·p` for a possibly-SECRET scalar: a fixed
    /// 256-bit double-and-add with a branch-free `cMov` bit select (the complete
    /// formulas make every step exception-free). `error.IdentityElement` if the
    /// result is the neutral element.
    pub fn mul(p: Secp256k1, s_: [32]u8, endian: std.builtin.Endian) IdentityElementError!Secp256k1 {
        const s = scalarValue(s_, endian);
        var q = Secp256k1.identityElement;
        var i: usize = 256;
        while (i > 0) {
            i -= 1;
            q = q.dbl();
            const added = q.add(p);
            const bit: u1 = @truncate(s >> @intCast(i));
            q.cMov(added, bit);
        }
        try q.rejectIdentity();
        return q;
    }

    /// VARIABLE-TIME scalar multiply for a PUBLIC scalar. Dispatches to the
    /// gated GLV core (`mulPublicGlv`) when `gate.glv_scalarmul_implemented`,
    /// else the plain double-and-add fallback below.
    pub fn mulPublic(p: Secp256k1, s_: [32]u8, endian: std.builtin.Endian) IdentityElementError!Secp256k1 {
        if (comptime gate.glv_scalarmul_implemented) {
            return mulPublicGlv(p, s_, endian);
        }
        return mulPublicDoubleAdd(p, s_, endian);
    }

    /// Portable variable-time single-base double-and-add (the GLV fallback +
    /// differential oracle).
    fn mulPublicDoubleAdd(p: Secp256k1, s_: [32]u8, endian: std.builtin.Endian) IdentityElementError!Secp256k1 {
        try p.rejectIdentity();
        const s = scalarValue(s_, endian);
        var q = Secp256k1.identityElement;
        var i: usize = 256;
        while (i > 0) {
            i -= 1;
            q = q.dbl();
            if (@as(u1, @truncate(s >> @intCast(i))) == 1) q = q.add(p);
        }
        try q.rejectIdentity();
        return q;
    }

    /// GATED Fable core #2 — the GLV-decomposition variable-base scalarmul.
    ///
    /// SCAFFOLD STUB: never reached (the caller only routes here when
    /// `gate.glv_scalarmul_implemented`, which is `false`). The Fable agent
    /// replaces this with: `(r1, r2) = scalar.splitScalar(s)` (already REAL +
    /// tested), `φ(p) = (β·p.x, p.y)` for the `λ`-multiple, then an interleaved
    /// half-length wNAF combine of `r1·p + r2·φ(p)`. `oracle_test.zig`'s gated
    /// differential pins it to `mulPublicDoubleAdd`.
    pub fn mulPublicGlv(p: Secp256k1, s_: [32]u8, endian: std.builtin.Endian) IdentityElementError!Secp256k1 {
        _ = p;
        _ = s_;
        _ = endian;
        @panic("TODO(fable/core): k256 GLV+wNAF variable-base scalarmul not implemented");
    }

    /// VARIABLE-TIME double-base multiply `s1·p1 + s2·p2` for PUBLIC scalars —
    /// the verifier's `s·G − e·P` workhorse. `error.IdentityElement` if the
    /// result is neutral (the BIP340 "sG − eP is infinite" reject).
    pub fn mulDoubleBasePublic(p1: Secp256k1, s1_: [32]u8, p2: Secp256k1, s2_: [32]u8, endian: std.builtin.Endian) IdentityElementError!Secp256k1 {
        try p1.rejectIdentity();
        try p2.rejectIdentity();
        const s1 = scalarValue(s1_, endian);
        const s2 = scalarValue(s2_, endian);
        var q = Secp256k1.identityElement;
        var i: usize = 256;
        while (i > 0) {
            i -= 1;
            q = q.dbl();
            if (@as(u1, @truncate(s1 >> @intCast(i))) == 1) q = q.add(p1);
            if (@as(u1, @truncate(s2 >> @intCast(i))) == 1) q = q.add(p2);
        }
        try q.rejectIdentity();
        return q;
    }
};

/// A point in affine coordinates.
pub const AffineCoordinates = struct {
    x: Fe,
    y: Fe,

    pub const identityElement = AffineCoordinates{
        .x = Secp256k1.identityElement.x,
        .y = Secp256k1.identityElement.y,
    };

    pub fn neg(p: AffineCoordinates) AffineCoordinates {
        return .{ .x = p.x, .y = p.y.neg() };
    }

    fn cMov(p: *AffineCoordinates, a: AffineCoordinates, c: u1) void {
        p.x.cMov(a.x, c);
        p.y.cMov(a.y, c);
    }
};

// ── tests: the group-level oracle differential vs std ───────────────────────

const Std = std.crypto.ecc.Secp256k1;

fn eqAffine(k: Secp256k1, s: Std) !void {
    const ka = k.affineCoordinates();
    const sa = s.affineCoordinates();
    try std.testing.expectEqualSlices(u8, &sa.x.toBytes(.big), &ka.x.toBytes(.big));
    try std.testing.expectEqualSlices(u8, &sa.y.toBytes(.big), &ka.y.toBytes(.big));
}

test "base point + identity match std" {
    try eqAffine(Secp256k1.basePoint, Std.basePoint);
    try std.testing.expectError(error.IdentityElement, Secp256k1.identityElement.rejectIdentity());
}

test "differential vs std: dbl/add/scalarmul on random scalars" {
    var prng = std.Random.DefaultPrng.init(0x60D_C0DE_11);
    const rand = prng.random();
    var i: usize = 0;
    while (i < 400) : (i += 1) {
        var s1b: [32]u8 = undefined;
        var s2b: [32]u8 = undefined;
        rand.bytes(&s1b);
        rand.bytes(&s2b);
        // Two random curve points via base-point multiples (agree with std).
        const kp1 = Secp256k1.basePoint.mul(s1b, .big) catch continue;
        const sp1 = Std.basePoint.mul(s1b, .big) catch continue;
        const kp2 = Secp256k1.basePoint.mul(s2b, .big) catch continue;
        const sp2 = Std.basePoint.mul(s2b, .big) catch continue;
        try eqAffine(kp1, sp1);

        // dbl + add.
        try eqAffine(kp1.dbl(), sp1.dbl());
        try eqAffine(kp1.add(kp2), sp1.add(sp2));

        // variable-base public multiply + double-base (verify path).
        const kv = kp1.mulPublic(s2b, .big) catch continue;
        const sv = sp1.mulPublic(s2b, .big) catch continue;
        try eqAffine(kv, sv);

        const kd = Secp256k1.mulDoubleBasePublic(kp1, s2b, kp2, s1b, .big) catch continue;
        const sd = Std.mulDoubleBasePublic(sp1, s2b, sp2, s1b, .big) catch continue;
        try eqAffine(kd, sd);
    }
}

test "GLV endomorphism: (β·x, y) == λ·P (validates β and λ against the curve)" {
    const beta = Fe.fromInt(scalarmod.beta) catch unreachable;
    var lambda_le: [32]u8 = undefined;
    std.mem.writeInt(u256, &lambda_le, scalarmod.lambda, .little);
    var prng = std.Random.DefaultPrng.init(0xBE7A_1A3D);
    const rand = prng.random();
    var i: usize = 0;
    while (i < 200) : (i += 1) {
        var kb: [32]u8 = undefined;
        rand.bytes(&kb);
        const p = Secp256k1.basePoint.mul(kb, .big) catch continue;
        const a = p.affineCoordinates();
        // φ(P) = (β·x, y)
        const phi = Secp256k1.fromAffineCoordinates(.{ .x = beta.mul(a.x), .y = a.y }) catch continue;
        // λ·P
        const lam_p = p.mul(lambda_le, .little) catch continue;
        try std.testing.expect(phi.equivalent(lam_p));
    }
}

test "recoverY / lift_x matches std" {
    var prng = std.Random.DefaultPrng.init(0x11F7_0011);
    const rand = prng.random();
    var i: usize = 0;
    while (i < 1500) : (i += 1) {
        var xb: [32]u8 = undefined;
        rand.bytes(&xb);
        const kx = Fe.fromBytes(xb, .big) catch continue;
        const sx = Std.Fe.fromBytes(xb, .big) catch unreachable;
        if (Std.recoverY(sx, false)) |sy| {
            const ky = try Secp256k1.recoverY(kx, false);
            try std.testing.expectEqualSlices(u8, &sy.toBytes(.big), &ky.toBytes(.big));
        } else |_| {
            try std.testing.expectError(error.NotSquare, Secp256k1.recoverY(kx, false));
        }
    }
}
