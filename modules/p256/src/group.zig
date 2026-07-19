// SPDX-License-Identifier: MIT

//! group — the NIST P-256 curve group over p256's base field `Fe`.
//!
//! The curve is `y² = x³ − 3x + b` (short Weierstrass with `a = −3`). Points are
//! homogeneous projective `(X : Y : Z)` with affine `(X/Z, Y/Z)`, and the
//! add/double use the **Renes–Costello–Batina complete formulas** specialised to
//! `a = −3` (eprint 2015/1060: Algorithm 6 doubling, Algorithm 4 addition) — the
//! same exception-free, branch-free law `std.crypto.ecc.P256` uses. P-256 has
//! prime order (cofactor 1), so these formulas are complete for ALL inputs
//! (identity, equal points, inverses), which is exactly what makes the
//! constant-time `mul` ladder safe with no special cases. Because the arithmetic
//! is identical to std's and runs over `Fe` (byte-exact vs std's field), the
//! whole group is byte-exact vs `std.crypto.ecc.P256` at the point level — the
//! oracle differential in `oracle_test.zig` pins it.
//!
//! Scalar multiplication (NO GLV — P-256 has no efficient endomorphism):
//!   * `mul` — CONSTANT-TIME variable-base multiply for a possibly-SECRET scalar.
//!     Scaffold: fixed 256-bit double-and-add with a `cMov` bit select. Gated
//!     fast core: `mulCtWindowed` (windowed with a blackBox-guarded masked table
//!     scan).
//!   * `combMulBase` — CONSTANT-TIME fixed-base multiply `s·G` (the signing
//!     path). Scaffold: falls back to the double-and-add ladder. Gated fast core:
//!     `combMulBaseFast` (precomputed comb, masked CT gather).
//!   * `mulPublic` / `mulDoubleBasePublic` — VARIABLE-TIME public-scalar
//!     multiplies (signature verification), plain double-and-add here; a wNAF
//!     `slide` acceleration is future owner-phase work (see SPEC backlog).

const std = @import("std");
const gate = @import("gate.zig");
const field = @import("field.zig");
const scalarmod = @import("scalar.zig");

const IdentityElementError = std.crypto.errors.IdentityElementError;
const EncodingError = std.crypto.errors.EncodingError;
const NonCanonicalError = std.crypto.errors.NonCanonicalError;
const NotSquareError = std.crypto.errors.NotSquareError;

/// A point on NIST P-256 in projective coordinates.
pub const P256 = struct {
    x: Fe,
    y: Fe,
    z: Fe = Fe.one,

    /// The curve constant `b` in `y² = x³ − 3x + b`.
    pub const B = Fe.fromInt(41058363725152142129326129780047268409114441015993725554835256314039467401291) catch unreachable;

    /// The base-field element type, exposed as `P256.Fe` to mirror
    /// `std.crypto.ecc.P256.Fe` so consumers aliasing `const Fe = P256.Fe;` are
    /// drop-in on p256.
    pub const Fe = field.Fe;
    /// The scalar field (mod the group order `n`), exposed as `P256.scalar` to
    /// mirror `std.crypto.ecc.P256.scalar` (std's constant-time scalar field
    /// verbatim; see `scalar.zig`'s scope note).
    pub const scalar = scalarmod.scalar;

    /// The standard base point `G`.
    pub const basePoint = P256{
        .x = Fe.fromInt(48439561293906451759052585252797914202762949526041747995844080717082404635286) catch unreachable,
        .y = Fe.fromInt(36134250956749795798585127919587881956611106672985015071877198253568414405109) catch unreachable,
        .z = Fe.one,
    };

    /// The neutral element `(0 : 1 : 0)`.
    pub const identityElement = P256{ .x = Fe.zero, .y = Fe.one, .z = Fe.zero };

    /// Reject the neutral element (mirrors std's check: `z = 0`, or the affine
    /// identity a formula could produce).
    pub fn rejectIdentity(p: P256) IdentityElementError!void {
        const affine_0 = @intFromBool(p.x.equivalent(AffineCoordinates.identityElement.x)) &
            (@intFromBool(p.y.isZero()) | @intFromBool(p.y.equivalent(AffineCoordinates.identityElement.y)));
        const is_identity = @intFromBool(p.z.isZero()) | affine_0;
        if (is_identity != 0) return error.IdentityElement;
    }

    /// Build a point from affine coordinates, checking the curve equation
    /// `y² = x³ − 3x + b`.
    pub fn fromAffineCoordinates(p: AffineCoordinates) EncodingError!P256 {
        const x = p.x;
        const y = p.y;
        const x3AxB = x.sq().mul(x).sub(x).sub(x).sub(x).add(B);
        const yy = y.sq();
        const on_curve = @intFromBool(x3AxB.equivalent(yy));
        const is_identity = @intFromBool(x.equivalent(AffineCoordinates.identityElement.x)) &
            @intFromBool(y.equivalent(AffineCoordinates.identityElement.y));
        if ((on_curve | is_identity) == 0) return error.InvalidEncoding;
        var ret = P256{ .x = x, .y = y, .z = Fe.one };
        ret.z.cMov(P256.identityElement.z, is_identity);
        return ret;
    }

    /// Build a point from serialized affine coordinates.
    pub fn fromSerializedAffineCoordinates(xs: [32]u8, ys: [32]u8, endian: std.builtin.Endian) (NonCanonicalError || EncodingError)!P256 {
        const x = try Fe.fromBytes(xs, endian);
        const y = try Fe.fromBytes(ys, endian);
        return fromAffineCoordinates(.{ .x = x, .y = y });
    }

    /// Recover the `y` coordinate for a given `x` and parity.
    /// `error.NotSquare` if `x³ − 3x + b` is not a quadratic residue.
    pub fn recoverY(x: Fe, is_odd: bool) NotSquareError!Fe {
        const x3AxB = x.sq().mul(x).sub(x).sub(x).sub(x).add(B);
        var y = try x3AxB.sqrt();
        const yn = y.neg();
        y.cMov(yn, @intFromBool(is_odd) ^ @intFromBool(y.isOdd()));
        return y;
    }

    /// Deserialize a SEC1-encoded point (compressed 02/03, uncompressed 04, or
    /// the single-byte 00 identity).
    pub fn fromSec1(s: []const u8) (EncodingError || NotSquareError || NonCanonicalError)!P256 {
        if (s.len < 1) return error.InvalidEncoding;
        const encoded = s[1..];
        switch (s[0]) {
            0 => {
                if (encoded.len != 0) return error.InvalidEncoding;
                return P256.identityElement;
            },
            2, 3 => {
                if (encoded.len != 32) return error.InvalidEncoding;
                const x = try Fe.fromBytes(encoded[0..32].*, .big);
                const y = try recoverY(x, s[0] == 3);
                return P256{ .x = x, .y = y };
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
    pub fn toCompressedSec1(p: P256) [33]u8 {
        var out: [33]u8 = undefined;
        const xy = p.affineCoordinates();
        out[0] = if (xy.y.isOdd()) 3 else 2;
        out[1..].* = xy.x.toBytes(.big);
        return out;
    }

    /// Serialize using the uncompressed SEC1 format.
    pub fn toUncompressedSec1(p: P256) [65]u8 {
        var out: [65]u8 = undefined;
        out[0] = 4;
        const xy = p.affineCoordinates();
        out[1..33].* = xy.x.toBytes(.big);
        out[33..65].* = xy.y.toBytes(.big);
        return out;
    }

    /// Negate a point.
    pub fn neg(p: P256) P256 {
        return .{ .x = p.x, .y = p.y.neg(), .z = p.z };
    }

    /// Double a point — RCB Algorithm 6 (complete for `a = −3`). Body mirrors
    /// `std.crypto.ecc.P256.dbl` verbatim over p256's `Fe`.
    pub fn dbl(p: P256) P256 {
        var t0 = p.x.sq();
        var t1 = p.y.sq();
        var t2 = p.z.sq();
        var t3 = p.x.mul(p.y);
        t3 = t3.dbl();
        var Z3 = p.x.mul(p.z);
        Z3 = Z3.add(Z3);
        var Y3 = B.mul(t2);
        Y3 = Y3.sub(Z3);
        var X3 = Y3.dbl();
        Y3 = X3.add(Y3);
        X3 = t1.sub(Y3);
        Y3 = t1.add(Y3);
        Y3 = X3.mul(Y3);
        X3 = X3.mul(t3);
        t3 = t2.dbl();
        t2 = t2.add(t3);
        Z3 = B.mul(Z3);
        Z3 = Z3.sub(t2);
        Z3 = Z3.sub(t0);
        t3 = Z3.dbl();
        Z3 = Z3.add(t3);
        t3 = t0.dbl();
        t0 = t3.add(t0);
        t0 = t0.sub(t2);
        t0 = t0.mul(Z3);
        Y3 = Y3.add(t0);
        t0 = p.y.mul(p.z);
        t0 = t0.dbl();
        Z3 = t0.mul(Z3);
        X3 = X3.sub(Z3);
        Z3 = t0.mul(t1);
        Z3 = Z3.dbl().dbl();
        return .{ .x = X3, .y = Y3, .z = Z3 };
    }

    /// Add two points — RCB Algorithm 4 (complete for `a = −3`). Body mirrors
    /// `std.crypto.ecc.P256.add` verbatim over p256's `Fe`.
    pub fn add(p: P256, q: P256) P256 {
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
        var Z3 = B.mul(t2);
        X3 = Y3.sub(Z3);
        Z3 = X3.dbl();
        X3 = X3.add(Z3);
        Z3 = t1.sub(X3);
        X3 = t1.add(X3);
        Y3 = B.mul(Y3);
        t1 = t2.dbl();
        t2 = t1.add(t2);
        Y3 = Y3.sub(t2);
        Y3 = Y3.sub(t0);
        t1 = Y3.dbl();
        Y3 = t1.add(Y3);
        t1 = t0.dbl();
        t0 = t1.add(t0);
        t0 = t0.sub(t2);
        t1 = t4.mul(Y3);
        t2 = t0.mul(Y3);
        Y3 = X3.mul(Z3);
        Y3 = Y3.add(t2);
        X3 = t3.mul(X3);
        X3 = X3.sub(t1);
        Z3 = t4.mul(Z3);
        t1 = t3.mul(t0);
        Z3 = Z3.add(t1);
        return .{ .x = X3, .y = Y3, .z = Z3 };
    }

    /// Subtract points.
    pub fn sub(p: P256, q: P256) P256 {
        return p.add(q.neg());
    }

    /// Return affine coordinates (one field inversion).
    pub fn affineCoordinates(p: P256) AffineCoordinates {
        const affine_0 = @intFromBool(p.x.equivalent(AffineCoordinates.identityElement.x)) &
            (@intFromBool(p.y.isZero()) | @intFromBool(p.y.equivalent(AffineCoordinates.identityElement.y)));
        const is_identity = @intFromBool(p.z.isZero()) | affine_0;
        const zinv = p.z.invert();
        var ret = AffineCoordinates{ .x = p.x.mul(zinv), .y = p.y.mul(zinv) };
        ret.cMov(AffineCoordinates.identityElement, is_identity);
        return ret;
    }

    /// True iff both represent the same point.
    pub fn equivalent(a: P256, b: P256) bool {
        if (a.sub(b).rejectIdentity()) {
            return false;
        } else |_| {
            return true;
        }
    }

    fn cMov(p: *P256, a: P256, c: u1) void {
        p.x.cMov(a.x, c);
        p.y.cMov(a.y, c);
        p.z.cMov(a.z, c);
    }

    // ── scalar multiplication ───────────────────────────────────────────────

    inline fn scalarValue(s_: [32]u8, endian: std.builtin.Endian) u256 {
        return std.mem.readInt(u256, &s_, endian);
    }

    /// CONSTANT-TIME variable-base multiply `s·p` for a possibly-SECRET scalar.
    /// Dispatches to the gated fast windowed core when
    /// `gate.fast_scalarmul_implemented`, else the proven double-and-add ladder.
    /// `error.IdentityElement` if the result is the neutral element.
    pub fn mul(p: P256, s_: [32]u8, endian: std.builtin.Endian) IdentityElementError!P256 {
        if (comptime gate.fast_scalarmul_implemented) {
            return mulCtWindowed(p, s_, endian);
        }
        return mulDoubleAddCt(p, s_, endian);
    }

    /// Portable CONSTANT-TIME fixed 256-bit double-and-add with a branch-free
    /// `cMov` bit select (the complete formulas make every step exception-free).
    /// This is the correctness oracle the gated windowed core is pinned to, and
    /// the non-gated fallback. `pub` for the harness/bench.
    pub fn mulDoubleAddCt(p: P256, s_: [32]u8, endian: std.builtin.Endian) IdentityElementError!P256 {
        const s = scalarValue(s_, endian);
        var q = P256.identityElement;
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

    /// GATED Fable core #2a — CONSTANT-TIME windowed variable-base multiply
    /// (secret scalars). SCAFFOLD: panic stub. The Fable author fills this with a
    /// fixed-window (e.g. w = 4) scan whose per-window table gather is a
    /// `blackBox`-guarded masked linear scan (so LLVM cannot lower the select to
    /// a secret-indexed jump table — the k256 comb lesson), pinned bit-for-bit to
    /// `mulDoubleAddCt` by the gated differential. Never reached while
    /// `gate.fast_scalarmul_implemented` is `false`.
    pub fn mulCtWindowed(p: P256, s_: [32]u8, endian: std.builtin.Endian) IdentityElementError!P256 {
        _ = p;
        _ = s_;
        _ = endian;
        @panic("TODO(fable/core): P-256 constant-time windowed variable-base scalarmul");
    }

    /// CONSTANT-TIME fixed-base multiply `s·G` for a possibly-SECRET scalar (the
    /// ECDSA signing nonce commitment `k·G` + pubkey derivation `d·G`).
    /// Dispatches to the gated comb core when `gate.fast_scalarmul_implemented`,
    /// else the double-and-add ladder over `G`. `error.IdentityElement` iff
    /// `s ≡ 0 (mod n)`.
    pub fn combMulBase(s_: [32]u8, endian: std.builtin.Endian) IdentityElementError!P256 {
        if (comptime gate.fast_scalarmul_implemented) {
            return combMulBaseFast(s_, endian);
        }
        return basePoint.mulDoubleAddCt(s_, endian);
    }

    /// GATED Fable core #2b — the fixed-base comb for `k·G` (the fast signing
    /// path). SCAFFOLD: panic stub. The Fable author fills this with a
    /// comptime-generated comb table (magnitudes `{1..2^{w−1}}·2^{w·i}·G`, stored
    /// projective) and a signed-digit online phase whose table gather is the same
    /// `blackBox`-guarded masked linear scan as `mulCtWindowed`. Pinned to
    /// `basePoint.mulDoubleAddCt` by the gated differential. Never reached while
    /// `gate.fast_scalarmul_implemented` is `false`.
    pub fn combMulBaseFast(s_: [32]u8, endian: std.builtin.Endian) IdentityElementError!P256 {
        _ = s_;
        _ = endian;
        @panic("TODO(fable/core): P-256 fixed-base comb constant-time k·G");
    }

    /// VARIABLE-TIME scalar multiply for a PUBLIC scalar (verification). Plain
    /// double-and-add in this scaffold; a wNAF `slide` acceleration is
    /// owner-phase work (SPEC backlog). `error.IdentityElement` if the input or
    /// result is the neutral element.
    pub fn mulPublic(p: P256, s_: [32]u8, endian: std.builtin.Endian) IdentityElementError!P256 {
        try p.rejectIdentity();
        const s = scalarValue(s_, endian);
        var q = P256.identityElement;
        var i: usize = 256;
        while (i > 0) {
            i -= 1;
            q = q.dbl();
            if (@as(u1, @truncate(s >> @intCast(i))) == 1) q = q.add(p);
        }
        try q.rejectIdentity();
        return q;
    }

    /// VARIABLE-TIME double-base multiply `s1·p1 + s2·p2` for PUBLIC scalars —
    /// the verifier's `u1·G + u2·Q` workhorse. `error.IdentityElement` if the
    /// result is neutral. Plain interleaved double-and-add in this scaffold;
    /// wNAF is owner-phase work (SPEC backlog).
    pub fn mulDoubleBasePublic(p1: P256, s1_: [32]u8, p2: P256, s2_: [32]u8, endian: std.builtin.Endian) IdentityElementError!P256 {
        try p1.rejectIdentity();
        try p2.rejectIdentity();
        const s1 = scalarValue(s1_, endian);
        const s2 = scalarValue(s2_, endian);
        var q = P256.identityElement;
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
    x: field.Fe,
    y: field.Fe,

    pub const identityElement = AffineCoordinates{
        .x = P256.identityElement.x,
        .y = P256.identityElement.y,
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

const Std = std.crypto.ecc.P256;

fn eqAffine(k: P256, s: Std) !void {
    const ka = k.affineCoordinates();
    const sa = s.affineCoordinates();
    try std.testing.expectEqualSlices(u8, &sa.x.toBytes(.big), &ka.x.toBytes(.big));
    try std.testing.expectEqualSlices(u8, &sa.y.toBytes(.big), &ka.y.toBytes(.big));
}

test "base point + identity + curve constant B match std" {
    try eqAffine(P256.basePoint, Std.basePoint);
    try std.testing.expectError(error.IdentityElement, P256.identityElement.rejectIdentity());
    try std.testing.expectEqualSlices(u8, &Std.B.toBytes(.big), &P256.B.toBytes(.big));
}

test "differential vs std: dbl/add/scalarmul/combMulBase on random scalars" {
    var prng = std.Random.DefaultPrng.init(0x60D_C0DE_9256);
    const rand = prng.random();
    var i: usize = 0;
    while (i < 400) : (i += 1) {
        var s1b: [32]u8 = undefined;
        var s2b: [32]u8 = undefined;
        rand.bytes(&s1b);
        rand.bytes(&s2b);
        // Two random curve points via base-point multiples (agree with std).
        const kp1 = P256.combMulBase(s1b, .big) catch continue;
        const sp1 = Std.basePoint.mul(s1b, .big) catch continue;
        const kp2 = P256.combMulBase(s2b, .big) catch continue;
        const sp2 = Std.basePoint.mul(s2b, .big) catch continue;
        try eqAffine(kp1, sp1);

        // dbl + add.
        try eqAffine(kp1.dbl(), sp1.dbl());
        try eqAffine(kp1.add(kp2), sp1.add(sp2));

        // CT variable-base multiply of a non-base point.
        const kv = kp1.mul(s2b, .big) catch continue;
        const sv = sp1.mul(s2b, .big) catch continue;
        try eqAffine(kv, sv);

        // variable-base public multiply + double-base (verify path).
        const kpub = kp1.mulPublic(s2b, .big) catch continue;
        const spub = sp1.mulPublic(s2b, .big) catch continue;
        try eqAffine(kpub, spub);

        const kd = P256.mulDoubleBasePublic(kp1, s2b, kp2, s1b, .big) catch continue;
        const sd = Std.mulDoubleBasePublic(sp1, s2b, sp2, s1b, .big) catch continue;
        try eqAffine(kd, sd);
    }
}

test "recoverY / lift_x matches std (a = −3 curve equation)" {
    var prng = std.Random.DefaultPrng.init(0x11F7_9256);
    const rand = prng.random();
    var i: usize = 0;
    while (i < 1500) : (i += 1) {
        var xb: [32]u8 = undefined;
        rand.bytes(&xb);
        const kx = field.Fe.fromBytes(xb, .big) catch continue;
        const sx = Std.Fe.fromBytes(xb, .big) catch unreachable;
        if (Std.recoverY(sx, false)) |sy| {
            const ky = try P256.recoverY(kx, false);
            try std.testing.expectEqualSlices(u8, &sy.toBytes(.big), &ky.toBytes(.big));
        } else |_| {
            try std.testing.expectError(error.NotSquare, P256.recoverY(kx, false));
        }
    }
}

test "SEC1 round-trip (compressed + uncompressed) matches std" {
    var prng = std.Random.DefaultPrng.init(0x5EC1_9256);
    const rand = prng.random();
    var i: usize = 0;
    while (i < 300) : (i += 1) {
        var sb: [32]u8 = undefined;
        rand.bytes(&sb);
        const kp = P256.combMulBase(sb, .big) catch continue;
        const sp = Std.basePoint.mul(sb, .big) catch continue;
        // compressed + uncompressed encodings must match std byte-for-byte.
        try std.testing.expectEqualSlices(u8, &sp.toCompressedSec1(), &kp.toCompressedSec1());
        try std.testing.expectEqualSlices(u8, &sp.toUncompressedSec1(), &kp.toUncompressedSec1());
        // and decode back to the same point through p256.
        const back = try P256.fromSec1(&kp.toCompressedSec1());
        try eqAffine(back, sp);
    }
}
