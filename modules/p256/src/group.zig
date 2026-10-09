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
//!     Fallback: fixed 256-bit double-and-add with a `cMov` bit select. Gated
//!     fast core: `mulCtWindowed` (windowed with a blackBox-guarded masked table
//!     scan).
//!   * `combMulBase` — CONSTANT-TIME fixed-base multiply `s·G` (the signing
//!     path). Fallback: the double-and-add ladder. Gated fast core:
//!     `combMulBaseFast` (precomputed comb, masked CT gather).
//!   * `mulPublic` / `mulDoubleBasePublic` — VARIABLE-TIME public-scalar
//!     multiplies (signature verification), accelerated with an interleaved
//!     **wNAF (Straus–Shamir)** double-scalar mult: one shared doubling chain +
//!     a precomputed odd-multiple table per base, ~`l/(w+1)` adds per scalar.
//!     Vartime (all inputs public); byte-exact vs the plain ladder + std.

const std = @import("std");
const builtin = @import("builtin");
const gate = @import("gate.zig");
const field = @import("field.zig");
const scalarmod = @import("scalar.zig");
const burn = @import("burn.zig");

const IdentityElementError = std.crypto.errors.IdentityElementError;
const EncodingError = std.crypto.errors.EncodingError;
const NonCanonicalError = std.crypto.errors.NonCanonicalError;
const NotSquareError = std.crypto.errors.NotSquareError;

/// A point on NIST P-256 in projective coordinates.
/// How many times `combMulBase` ran, in test builds only (`void` otherwise, so
/// no shipped or measured binary carries it). Both branches of `P256.mul`
/// return the same point by construction, so this is the only way a test can
/// see that `basePoint.mul` took the comb redirect: a deleted redirect passed
/// every test in this module (checked 2026-09-18 by deleting it).
pub var comb_calls_for_testing: if (builtin.is_test) usize else void = if (builtin.is_test) 0 else {};

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
    pub const scalar = scalarmod;

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

    /// Mixed addition `P + Q` with `Q` AFFINE — RCB Algorithm 5 (`a = −3`),
    /// complete for every projective `P` (the identity included) and every
    /// affine `Q` (an affine point is never the identity). It is Algorithm 4
    /// with `Z2 = 1` folded in: `t2 = Z1`, `(Y1+Z1)(Y2+1) − t1 − Z1 = Y1 + Y2·Z1`
    /// and `(X1+Z1)(X2+1) − t0 − Z1 = X1 + X2·Z1`, so 11M + 2·m_b instead of
    /// 12M + 2·m_b — and, more to the point, it lets the fixed-base table be
    /// stored affine. Fixed schedule, no branch: constant-time, used by the
    /// SECRET comb. Pinned to `add` by the differential below.
    pub fn addMixed(p: P256, q: AffineCoordinates) P256 {
        var t0 = p.x.mul(q.x);
        var t1 = p.y.mul(q.y);
        var t3 = q.x.add(q.y);
        var t4 = p.x.add(p.y);
        t3 = t3.mul(t4);
        t4 = t0.add(t1);
        t3 = t3.sub(t4);
        t4 = q.y.mul(p.z);
        t4 = t4.add(p.y);
        var Y3 = q.x.mul(p.z);
        Y3 = Y3.add(p.x);
        var Z3 = B.mul(p.z);
        var X3 = Y3.sub(Z3);
        Z3 = X3.dbl();
        X3 = X3.add(Z3);
        Z3 = t1.sub(X3);
        X3 = t1.add(X3);
        Y3 = B.mul(Y3);
        t1 = p.z.dbl();
        var t2 = t1.add(p.z);
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
    ///
    /// Burned like `mul`: on an ECDH result the point is the shared secret,
    /// and the inversion left its `y` on the dead stack (`stackprobe_test.zig`,
    /// 2026-10-08). The burn is ~1 % of the inversion's cost.
    pub fn affineCoordinates(p: P256) AffineCoordinates {
        const r = affineCoordinatesUnburned(p);
        burn.stack(burn.affine_burn);
        return r;
    }

    noinline fn affineCoordinatesUnburned(p: P256) AffineCoordinates {
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
    ///
    /// Burned: the body runs one frame down and the stack it dirtied is zeroed
    /// after it (`burn.zig`). Without it, ECDH left the secret scalar and the
    /// shared point's `y` on the dead stack (`stackprobe_test.zig`, 2026-10-08).
    pub fn mul(p: P256, s_: [32]u8, endian: std.builtin.Endian) IdentityElementError!P256 {
        const r = mulUnburned(p, s_, endian);
        burn.stack(burn.mul_burn);
        return r;
    }

    /// `mul` with the scalar by pointer and the product into `out` (zeroed on
    /// error) — for a caller whose scalar or product is secret (ECDH). `mul`
    /// keeps std's curve shape (std's `Ecdsa` calls `Curve.basePoint.mul(k,
    /// .big)`), so the caller's frame keeps a copy of the scalar it passed
    /// and of the point it got back; this form leaves neither
    /// (`stackprobe_test.zig`, 2026-10-08). Burned like `mul`.
    pub fn mulInto(p: P256, out: *P256, s_: *const [32]u8, endian: std.builtin.Endian) IdentityElementError!void {
        const r = mulIntoUnburned(p, out, s_, endian);
        burn.stack(burn.mul_burn);
        return r;
    }

    noinline fn mulIntoUnburned(p: P256, out: *P256, s_: *const [32]u8, endian: std.builtin.Endian) IdentityElementError!void {
        errdefer std.crypto.secureZero(u8, std.mem.asBytes(out));
        out.* = try mulUnburned(p, s_.*, endian);
    }

    noinline fn mulUnburned(p: P256, s_: [32]u8, endian: std.builtin.Endian) IdentityElementError!P256 {
        // `s·G` has a dedicated fixed-base comb roughly 4x faster than the
        // variable-base path below, and this is the only door to it for the
        // most important caller there is: `std.crypto.sign.ecdsa.Ecdsa.sign`
        // computes its `R` as `Curve.basePoint.mul(k, .big)`. Since this
        // module exports `EcdsaP256Sha256` as `Ecdsa(P256, Sha256)`, without
        // the redirect below `combMulBase` has **no call site on the signing
        // path at all** -- the comb was built for signing and signing never
        // reached it. Measured on the audited host: 235 us through the
        // windowed core against 56 us through the comb, i.e. most of an ECDSA
        // signature.
        //
        // The test is on the POINT, which is public in every caller (here it
        // is a compile-time constant), never on the scalar, which is the
        // secret. So this adds no secret-dependent branch. `combMulBase` is
        // pinned bit-for-bit to `mulDoubleAddCt` by the gated differential, so
        // it cannot answer differently either.
        if (p.isBasePointRepr()) return combMulBaseUnburned(s_, endian);
        if (comptime gate.fast_scalarmul_implemented) {
            return mulCtWindowed(p, s_, endian);
        }
        return mulDoubleAddCt(p, s_, endian);
    }

    /// Structural test for "this *is* the `basePoint` constant" -- three field
    /// comparisons, not a point equality.
    ///
    /// Deliberately not `equivalent`, which costs a point subtraction on every
    /// scalar multiply to catch a case nobody hits: a caller holding G in some
    /// other projective representation misses the fast path and gets the
    /// correct answer the slow way.
    ///
    /// `pub` for the harness: this predicate is the whole of the redirect's
    /// mechanism, and it is the only part of it a test can observe -- both
    /// branches of `mul` return the same answer by construction, so no
    /// assertion on the *result* can tell which one ran.
    pub fn isBasePointRepr(p: P256) bool {
        return p.x.equivalent(basePoint.x) and
            p.y.equivalent(basePoint.y) and
            p.z.equivalent(basePoint.z);
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
    /// (secret scalars). A fixed-window (w = 4) signed-digit form: the scalar is
    /// recoded branch-free into 65 signed digits d_i ∈ [−8, 7], a runtime table
    /// of the magnitudes {1..8}·p is built with a PUBLIC schedule, and the
    /// online phase does 4 doublings + one table add per digit, top-down. The
    /// per-digit gather is a `blackBox`-guarded masked linear scan over ALL
    /// eight entries at fixed offsets (never secret-indexed — the k256/powMont
    /// lesson), and the digit sign is applied by a masked point negation.
    /// Stays on the complete projective formulas (full `add`, projective
    /// runtime table): its table is built per call from a secret-derived
    /// point, so there is no comptime affine table to gather from.
    /// Pinned bit-for-bit to `mulDoubleAddCt` by the gated differential.
    pub fn mulCtWindowed(p: P256, s_: [32]u8, endian: std.builtin.Endian) IdentityElementError!P256 {
        const k = scalarValue(s_, endian);
        const half: u64 = 1 << (comb_w - 1); // 8
        const twow: u64 = 1 << comb_w; // 16
        const wmask: u64 = twow - 1;

        // Magnitude table {1..8}·p — the schedule is public (fixed loop), only
        // the VALUES are secret-derived, so this is constant-time.
        var tab: [comb_teeth]P256 = undefined;
        tab[0] = p;
        tab[1] = p.dbl();
        var j: usize = 2;
        while (j < comb_teeth) : (j += 1) tab[j] = tab[j - 1].add(p);

        // Branch-free signed-digit (Booth-style) recoding, bottom-up (the
        // carry propagates upward), stored for the top-down consumption below.
        // Secret VALUES in the arrays, but every access is at a PUBLIC index.
        var mags: [comb_t]u64 = undefined;
        var negs: [comb_t]u64 = undefined;
        var carry: u64 = 0;
        var i: usize = 0;
        while (i < comb_t) : (i += 1) {
            const shift: usize = i * comb_w; // PUBLIC (loop-derived) shift
            const wv: u64 = if (shift < 256) (@as(u64, @truncate(k >> @intCast(shift))) & wmask) else 0;
            const x = wv + carry; // 0 .. 2^w
            const is_neg: u64 = @intFromBool(x >= half); // setcc, not a branch
            carry = is_neg;
            // The select mask is laundered through `blackBox`: without it LLVM
            // recovers `is_neg = (x >= 8)` and lowers the select to a CMOV (or
            // worse, a branch) on the secret digit — observed in ReleaseFast
            // disasm before the barrier was added.
            const negmask: u64 = blackBox(0 -% is_neg);
            mags[i] = ((twow - x) & negmask) | (x & ~negmask); // |d| ∈ [0, 8]
            negs[i] = is_neg;
        }

        // Top-down: acc = 2^w·acc + d_i·p. Fixed trip count; the complete
        // formulas make identity doublings/additions exception-free.
        var acc = P256.identityElement;
        i = comb_t;
        while (i > 0) {
            i -= 1;
            acc = acc.dbl().dbl().dbl().dbl();
            var g = P256.identityElement;
            j = 0;
            while (j < comb_teeth) : (j += 1) {
                const match: u64 = @intFromBool(@as(u64, j + 1) == mags[i]);
                const mask = blackBox(0 -% match);
                blendLimbs(&g.x, tab[j].x, mask);
                blendLimbs(&g.y, tab[j].y, mask);
                blendLimbs(&g.z, tab[j].z, mask);
            }
            // Signed digit ⇒ conditional point negation as a masked blend of
            // the unconditionally-computed −y, with the sign mask laundered
            // through `blackBox` — a plain `cMov` here was observed to lower
            // to a secret-dependent branch skipping the negation (the montint
            // b199192 leak class) in ReleaseFast disasm.
            const yneg = g.y.neg();
            const smask = blackBox(0 -% negs[i]);
            blendLimbs(&g.y, yneg, smask);
            acc = acc.add(g);
        }
        try acc.rejectIdentity();
        return acc;
    }

    /// CONSTANT-TIME fixed-base multiply `s·G` for a possibly-SECRET scalar (the
    /// ECDSA signing nonce commitment `k·G` + pubkey derivation `d·G`).
    /// Dispatches to the gated comb core when `gate.fast_scalarmul_implemented`,
    /// else the double-and-add ladder over `G`. `error.IdentityElement` iff
    /// `s ≡ 0 (mod n)`.
    /// Burned like `mul`.
    pub fn combMulBase(s_: [32]u8, endian: std.builtin.Endian) IdentityElementError!P256 {
        const r = combMulBaseUnburned(s_, endian);
        burn.stack(burn.mul_burn);
        return r;
    }

    noinline fn combMulBaseUnburned(s_: [32]u8, endian: std.builtin.Endian) IdentityElementError!P256 {
        if (builtin.is_test) comb_calls_for_testing += 1;
        if (comptime gate.fast_scalarmul_implemented) {
            return combMulBaseFast(s_, endian);
        }
        return basePoint.mulDoubleAddCt(s_, endian);
    }

    /// GATED Fable core #2b — the fixed-base comb for `k·G` (the fast signing
    /// path). The comptime-generated AFFINE table (`base_table`: magnitudes
    /// `{1..2^{w−1}}·2^{w·i}·G`, `w = 6`, 43 windows) makes the online phase
    /// `fb_t` mixed point additions with NO doublings — each window's table
    /// already carries the `2^{w·i}` factor. The signed-digit recoding is
    /// branch-free and the table gather is the same `blackBox`-guarded masked
    /// linear scan as `mulCtWindowed` (see the table section below for the CT
    /// contract). Pinned to `basePoint.mulDoubleAddCt` + std by the gated
    /// differential. `error.IdentityElement` iff `s ≡ 0 (mod n)`.
    pub fn combMulBaseFast(s_: [32]u8, endian: std.builtin.Endian) IdentityElementError!P256 {
        return combMulBaseFastWithTable(&base_table, s_, endian);
    }

    /// `combMulBaseFast` parameterised on the table, so the positive-control
    /// test in `oracle_test.zig` can pass a deliberately-corrupted table and
    /// prove the differential has teeth. The table index `[i][j]` is driven
    /// only by the PUBLIC loop counters — never by a secret — so this stays
    /// constant-time for any table. `pub` for that harness.
    pub fn combMulBaseFastWithTable(tab: *const BaseTable, s_: [32]u8, endian: std.builtin.Endian) IdentityElementError!P256 {
        const k = scalarValue(s_, endian);

        var acc = P256.identityElement;
        // Signed-digit (Booth-style) recoding with a running carry, folded into
        // the same loop that consumes the digits — fully branchless in `k`.
        // Digit d_i ∈ [−2^(w−1), 2^(w−1)−1], so Σ d_i·2^(w·i) = k exactly and
        // the magnitude |d_i| ∈ [0, 2^(w−1)] indexes the half-size table. The
        // top window holds only 256 − 42·6 = 4 scalar bits, so `x ≤ 16 < 32`
        // there and no carry escapes (asserted at comptime below the table).
        var carry: u64 = 0;
        var i: usize = 0;
        while (i < fb_t) : (i += 1) {
            const shift: usize = i * fb_w; // PUBLIC (loop-derived) shift
            const wv: u64 = if (shift < 256) (@as(u64, @truncate(k >> @intCast(shift))) & fb_wmask) else 0;
            const x = wv + carry; // 0 .. 2^w
            // is_neg ⟺ x ≥ 2^(w−1): then d = x − 2^w (< 0) and carry propagates.
            // A `>=` compare lowers to setcc (data-independent), not a branch.
            const is_neg: u64 = @intFromBool(x >= fb_half);
            carry = is_neg;
            // The select mask is laundered through `blackBox`: without it LLVM
            // recovers `is_neg = (x >= half)` and lowers the select to a CMOV
            // on the secret digit — observed in ReleaseFast disasm before the
            // barrier was added.
            const negmask: u64 = blackBox(0 -% is_neg);
            // |d| = is_neg ? (2^w − x) : x  — masked, no branch.
            const m = ((fb_twow - x) & negmask) | (x & ~negmask); // 0 .. 2^(w−1)

            // CONSTANT-TIME gather of the table entry for magnitude `m`: a
            // masked linear scan touching EVERY entry of window `i`. The
            // per-entry select mask is laundered through `blackBox` so LLVM
            // cannot recover "pick the entry where j+1 == m" and lower it to a
            // secret-indexed jump table (`jmp *tbl(,%reg,8)`) — the exact
            // powMont-gather leak class (montint b199192). `m == 0` (digit 0)
            // matches no entry and leaves `g = (0, 0)`, which is NOT a curve
            // point — so that case is undone by the masked blend at the end.
            var g = AffineCoordinates{ .x = Fe.zero, .y = Fe.zero };
            var j: usize = 0;
            while (j < fb_teeth) : (j += 1) {
                const match: u64 = @intFromBool(@as(u64, j + 1) == m);
                const mask = blackBox(0 -% match);
                blendLimbs(&g.x, tab[i][j].x, mask);
                blendLimbs(&g.y, tab[i][j].y, mask);
            }
            // Signed digit ⇒ conditional point negation as a masked blend of
            // the unconditionally-computed −y, with the sign mask laundered
            // through `blackBox` — a plain `cMov` here was observed to lower
            // to a secret-dependent branch skipping the negation (the montint
            // b199192 leak class) in ReleaseFast disasm.
            const yneg = g.y.neg();
            const smask = blackBox(0 -% is_neg);
            blendLimbs(&g.y, yneg, smask);

            // Always add (fixed schedule), keep the sum iff the digit was
            // nonzero. The mixed complete formula handles `acc = identity`.
            const sum = acc.addMixed(g);
            const nonzero: u64 = @intFromBool(m != 0);
            const keep = blackBox(0 -% nonzero);
            blendLimbs(&acc.x, sum.x, keep);
            blendLimbs(&acc.y, sum.y, keep);
            blendLimbs(&acc.z, sum.z, keep);
        }
        try acc.rejectIdentity();
        return acc;
    }

    /// VARIABLE-TIME scalar multiply for a PUBLIC scalar (verification). All
    /// inputs public, so plain branches are fine. `error.IdentityElement` if
    /// the input or result is the neutral element. Matches `mulDoubleAddCt`/std
    /// exactly (same point; the projective representation differs).
    ///
    /// Two paths, both in Jacobian coordinates (`Jac` below):
    ///   * `p` IS the base point (the structural `isBasePointRepr` test, the
    ///     same public-point test `mul` uses) → the fixed-base table: one
    ///     mixed addition per nonzero signed digit, NO doublings. This is the
    ///     `u1·G` of every ECDSA verify, including std's generic `Ecdsa`
    ///     verifier over this curve, which calls exactly `basePoint.mulPublic`.
    ///   * otherwise → width-`wnaf_w` NAF with a batch-normalised affine
    ///     odd-multiple table: 256 doublings + ~`l/(w+1)` mixed additions.
    pub fn mulPublic(p: P256, s_: [32]u8, endian: std.builtin.Endian) IdentityElementError!P256 {
        try p.rejectIdentity();
        const s = scalarValue(s_, endian);
        const q = if (p.isBasePointRepr()) mulBasePublicJac(s) else mulPublicJac(p, s);
        const r = q.toProjective();
        try r.rejectIdentity();
        return r;
    }

    /// VARIABLE-TIME double-base multiply `s1·p1 + s2·p2` for PUBLIC scalars —
    /// the verifier's `u1·G + u2·Q` workhorse (JWT ES256 verify hot path).
    /// Vartime (all inputs public); plain branches. `error.IdentityElement`
    /// if an input or the result is neutral. Byte-exact vs the plain ladder +
    /// std at the point level.
    ///
    /// When one base is `G` its share comes from the fixed-base table (no
    /// doublings at all) and is added to the other base's wNAF result — that
    /// beats sharing one doubling chain, because the fixed-base side then
    /// costs nothing but its ~43 mixed additions. Two arbitrary bases take
    /// the interleaved wNAF (Straus–Shamir): one shared doubling chain, one
    /// affine odd-multiple table per base.
    pub fn mulDoubleBasePublic(p1: P256, s1_: [32]u8, p2: P256, s2_: [32]u8, endian: std.builtin.Endian) IdentityElementError!P256 {
        try p1.rejectIdentity();
        try p2.rejectIdentity();
        const s1 = scalarValue(s1_, endian);
        const s2 = scalarValue(s2_, endian);
        const q = if (p1.isBasePointRepr())
            mulBasePublicJac(s1).add(mulPublicJac(p2, s2))
        else if (p2.isBasePointRepr())
            mulBasePublicJac(s2).add(mulPublicJac(p1, s1))
        else
            mulDoubleBaseJac(p1, s1, p2, s2);
        const r = q.toProjective();
        try r.rejectIdentity();
        return r;
    }

    /// `s·G` from the fixed-base affine table, vartime: skips zero digits.
    fn mulBasePublicJac(s: u256) Jac {
        var acc = Jac.identity;
        var carry: u64 = 0;
        var i: usize = 0;
        while (i < fb_t) : (i += 1) {
            const shift: usize = i * fb_w;
            const wv: u64 = if (shift < 256) (@as(u64, @truncate(s >> @intCast(shift))) & fb_wmask) else 0;
            const x = wv + carry;
            const is_neg = x >= fb_half;
            carry = @intFromBool(is_neg);
            const m = if (is_neg) fb_twow - x else x;
            if (m == 0) continue;
            var q = base_table[i][m - 1];
            if (is_neg) q.y = q.y.neg();
            acc = acc.addMixed(q);
        }
        return acc;
    }

    /// `s·p` by width-`wnaf_w` NAF over a batch-normalised affine table of the
    /// odd multiples. `p` must not be the identity (caller-checked).
    fn mulPublicJac(p: P256, s: u256) Jac {
        var naf: [wnaf_len]i8 = [_]i8{0} ** wnaf_len;
        const l = computeWnaf(s, &naf);
        const tab = oddMultiplesAffine(p);
        var q = Jac.identity;
        var i: usize = l;
        while (i > 0) {
            i -= 1;
            q = q.dbl();
            if (naf[i] != 0) q = q.addMixed(wnafPoint(&tab, naf[i]));
        }
        return q;
    }

    /// Interleaved wNAF (Straus–Shamir) for two arbitrary non-identity bases.
    fn mulDoubleBaseJac(p1: P256, s1: u256, p2: P256, s2: u256) Jac {
        var naf1: [wnaf_len]i8 = [_]i8{0} ** wnaf_len;
        var naf2: [wnaf_len]i8 = [_]i8{0} ** wnaf_len;
        const l1 = computeWnaf(s1, &naf1);
        const l2 = computeWnaf(s2, &naf2);
        const l = @max(l1, l2);
        const t1 = oddMultiplesAffine(p1);
        const t2 = oddMultiplesAffine(p2);
        var q = Jac.identity;
        var i: usize = l;
        while (i > 0) {
            i -= 1;
            q = q.dbl();
            if (naf1[i] != 0) q = q.addMixed(wnafPoint(&t1, naf1[i]));
            if (naf2[i] != 0) q = q.addMixed(wnafPoint(&t2, naf2[i]));
        }
        return q;
    }
};

// ── Jacobian coordinates for the VARIABLE-TIME public paths ──────────────────
//
// Affine `(X/Z², Y/Z³)`, identity ⟺ `Z = 0`. Cheaper than the complete
// projective formulas the rest of the file uses (doubling 3M+5S vs 8M+3S+2m_b;
// mixed addition 7M+4S vs 11M+2m_b — measured 2026-09-28: verify's 256
// doublings went from ~540 ns to ~340 ns each) but NOT exception-free:
// `add`/`addMixed` branch on the identity and the `P = ±Q` cases. That is
// fine here because every input is PUBLIC (verification), and it is exactly
// why the SECRET paths (`mul`, `combMulBase`) never touch this type — they
// stay on the complete formulas.
const Jac = struct {
    x: field.Fe,
    y: field.Fe,
    z: field.Fe,

    const identity = Jac{ .x = field.Fe.one, .y = field.Fe.one, .z = field.Fe.zero };

    fn isIdentity(p: Jac) bool {
        return p.z.isZero();
    }

    /// Projective `(X : Y : Z)` → Jacobian with the same `Z`: `(X·Z : Y·Z² : Z)`.
    fn fromProjective(p: P256) Jac {
        const z2 = p.z.sq();
        return .{ .x = p.x.mul(p.z), .y = p.y.mul(z2), .z = p.z };
    }

    fn fromAffine(a: AffineCoordinates) Jac {
        return .{ .x = a.x, .y = a.y, .z = field.Fe.one };
    }

    /// Jacobian → projective: `(X·Z : Y : Z³)`; the identity maps to std's
    /// `(0 : 1 : 0)`.
    fn toProjective(p: Jac) P256 {
        if (p.isIdentity()) return P256.identityElement;
        const z2 = p.z.sq();
        return .{ .x = p.x.mul(p.z), .y = p.y, .z = z2.mul(p.z) };
    }

    /// Doubling, `a = −3` (EFD dbl-2001-b): 3M + 5S. `Z = 0` stays `Z = 0`.
    fn dbl(p: Jac) Jac {
        const delta = p.z.sq();
        const gamma = p.y.sq();
        const beta = p.x.mul(gamma);
        var alpha = p.x.sub(delta).mul(p.x.add(delta));
        alpha = alpha.dbl().add(alpha); // 3·(X − δ)·(X + δ)
        const beta4 = beta.dbl().dbl();
        const x3 = alpha.sq().sub(beta4.dbl()); // α² − 8β
        const z3 = p.y.add(p.z).sq().sub(gamma).sub(delta);
        const gamma2_8 = gamma.sq().dbl().dbl().dbl(); // 8γ²
        const y3 = alpha.mul(beta4.sub(x3)).sub(gamma2_8);
        return .{ .x = x3, .y = y3, .z = z3 };
    }

    /// Mixed addition, `Q` affine (EFD madd-2007-bl): 7M + 4S, plus the
    /// exceptional cases (`P = O`, `P = Q`, `P = −Q`) as vartime branches.
    fn addMixed(p: Jac, q: AffineCoordinates) Jac {
        if (p.isIdentity()) return fromAffine(q);
        const z1z1 = p.z.sq();
        const uu2 = q.x.mul(z1z1);
        const s2 = q.y.mul(p.z).mul(z1z1);
        const h = uu2.sub(p.x);
        const r = s2.sub(p.y).dbl();
        if (h.isZero()) {
            if (r.isZero()) return p.dbl(); // P = Q
            return identity; // P = −Q
        }
        const hh = h.sq();
        const i = hh.dbl().dbl(); // 4·HH
        const j = h.mul(i);
        const v = p.x.mul(i);
        const x3 = r.sq().sub(j).sub(v.dbl());
        const y3 = r.mul(v.sub(x3)).sub(p.y.mul(j).dbl());
        const z3 = p.z.add(h).sq().sub(z1z1).sub(hh);
        return .{ .x = x3, .y = y3, .z = z3 };
    }

    /// General addition (EFD add-2007-bl): 11M + 5S, plus the exceptional
    /// cases. Used to build the odd-multiple tables and to join the two
    /// halves of a double-base multiply — a handful of calls per multiply.
    fn add(p: Jac, q: Jac) Jac {
        if (p.isIdentity()) return q;
        if (q.isIdentity()) return p;
        const z1z1 = p.z.sq();
        const z2z2 = q.z.sq();
        const uu1 = p.x.mul(z2z2);
        const uu2 = q.x.mul(z1z1);
        const s1 = p.y.mul(q.z).mul(z2z2);
        const s2 = q.y.mul(p.z).mul(z1z1);
        const h = uu2.sub(uu1);
        const r = s2.sub(s1).dbl();
        if (h.isZero()) {
            if (r.isZero()) return p.dbl(); // P = Q
            return identity; // P = −Q
        }
        const i = h.dbl().sq(); // (2H)²
        const j = h.mul(i);
        const v = uu1.mul(i);
        const x3 = r.sq().sub(j).sub(v.dbl());
        const y3 = r.mul(v.sub(x3)).sub(s1.mul(j).dbl());
        const z3 = p.z.add(q.z).sq().sub(z1z1).sub(z2z2).mul(h);
        return .{ .x = x3, .y = y3, .z = z3 };
    }
};

/// Convert `n` NON-identity Jacobian points to affine with ONE field
/// inversion (Montgomery's trick): prefix products of the `Z`s, one inverse,
/// then peel it back. Vartime (public points).
fn batchToAffine(comptime n: usize, pts: [n]Jac) [n]AffineCoordinates {
    var prefix: [n]field.Fe = undefined; // prefix[i] = z_0 ⋯ z_i
    prefix[0] = pts[0].z;
    var i: usize = 1;
    while (i < n) : (i += 1) prefix[i] = prefix[i - 1].mul(pts[i].z);
    var inv = prefix[n - 1].invert(); // (z_0 ⋯ z_{n−1})⁻¹
    var out: [n]AffineCoordinates = undefined;
    i = n;
    while (i > 0) {
        i -= 1;
        const zinv = if (i == 0) inv else inv.mul(prefix[i - 1]); // z_i⁻¹
        if (i > 0) inv = inv.mul(pts[i].z); // → (z_0 ⋯ z_{i−1})⁻¹
        const zinv2 = zinv.sq();
        out[i] = .{ .x = pts[i].x.mul(zinv2), .y = pts[i].y.mul(zinv2).mul(zinv) };
    }
    return out;
}

// ── vartime wNAF helpers for the PUBLIC paths ────────────────────────────────
//
// P-256 has no endomorphism, so a variable-base public multiply is a plain
// wNAF: the public scalar is recoded into signed digits
// d ∈ {0, ±1, ±3, …, ±(2^(w−1)−1)} with ≥ w−1 zeros between nonzeros, so the
// online phase averages one addition every `w+1` positions (vs every 2 for
// double-and-add). This path handles only PUBLIC values (public key, signature,
// message hash), so the data-dependent branches below are not a leak — the
// SECRET paths (`mul`/`combMulBase`) never touch this code.

/// wNAF window width (bits). w = 5 ⇒ digits {±1,±3,…,±15}, table of 8 points.
/// Measured against w = 6 for one 256-bit scalar: the 8 extra table points
/// (full Jacobian adds + normalisation) cost more than the 6 additions saved.
const wnaf_w: usize = 5;
/// Odd-multiple table length per base: {1,3,…,2^(w−1)−1}·p ⇒ 2^(w−2) entries.
const wnaf_tab_len: usize = 1 << (wnaf_w - 2); // 8
/// Max wNAF length for a 256-bit scalar (t+1 digits).
const wnaf_len: usize = 257;

/// Width-`w` NAF of a public scalar `s`. Writes digits into `out[0..len]`
/// (low-order first) and returns `len`. Vartime.
fn computeWnaf(s: u256, out: *[wnaf_len]i8) usize {
    const two_w: u64 = 1 << wnaf_w; // 32
    const half: u64 = 1 << (wnaf_w - 1); // 16
    // ⭐ WIDER THAN THE SCALAR, and that is the whole point. A negative digit
    // is subtracted by ADDING `two_w - mod` to the accumulator, which for a
    // scalar near the top of the range carries past 2^256. In a `u256` that
    // wrapped: `s = 2^256 - 1` has `mod = 31`, so `d += 1` became 0, the loop
    // stopped after ONE digit, and the recoding encoded `-1` instead of
    // `s` — `mulPublic` then returned `-P` where the constant-time ladder and
    // std both return `(2^256 - 1)·P`. Silent wrong answer, no panic (the
    // digit array was never overrun), for the eight scalars `2^256 - k`,
    // k ∈ {1,3,…,15}. Three doc sites and SPEC.md claim byte-exactness with
    // std, and the random differential could not find it: the trigger set has
    // probability 2^-253.
    //
    // Non-wrapping operators below, so that a future width mistake is a loud
    // overflow in safe builds rather than another silent recoding.
    var d: u264 = s;
    var i: usize = 0;
    while (d != 0) : (i += 1) {
        var digit: i8 = 0;
        if ((@as(u64, @truncate(d)) & 1) == 1) {
            const mod: u64 = @as(u64, @truncate(d)) & (two_w - 1); // d mod 2^w (odd)
            if (mod >= half) {
                digit = @intCast(@as(i64, @intCast(mod)) - @as(i64, @intCast(two_w)));
                d += two_w - mod; // d -= digit (digit < 0)
            } else {
                digit = @intCast(mod);
                d -= mod;
            }
        }
        out[i] = digit;
        d >>= 1;
    }
    return i;
}

/// Odd multiples `1·p, 3·p, …, (2·wnaf_tab_len−1)·p`, batch-normalised to
/// affine. `p` must not be the identity (then no odd multiple is either, the
/// group order being prime). Vartime.
fn oddMultiplesAffine(p: P256) [wnaf_tab_len]AffineCoordinates {
    var jac: [wnaf_tab_len]Jac = undefined;
    jac[0] = Jac.fromProjective(p);
    const p2 = jac[0].dbl();
    var i: usize = 1;
    while (i < wnaf_tab_len) : (i += 1) jac[i] = jac[i - 1].add(p2); // (2i+1)·p
    return batchToAffine(wnaf_tab_len, jac);
}

/// The affine point for a NONZERO wNAF digit: `tab[(|d|−1)/2]`, negated iff `d<0`.
inline fn wnafPoint(tab: *const [wnaf_tab_len]AffineCoordinates, digit: i8) AffineCoordinates {
    const mag: usize = @intCast(if (digit < 0) -@as(i32, digit) else digit);
    const pt = tab[(mag - 1) / 2];
    return if (digit < 0) pt.neg() else pt;
}

// ── fixed-base table (CT comb `k·G` AND vartime `u1·G`) ─────────────────────
//
// The signing path multiplies the FIXED base point G by a secret scalar twice
// per signature (the nonce commitment R = k·G and the pubkey P = d·G); the
// verifying path multiplies it by a public one (u1·G). A naive double-and-add
// pays 256 doublings + 256 conditional adds; a precomputed table of window
// multiples removes every doubling — the online phase is one addition per
// window (the technique behind OpenSSL nistz256's and libsecp256k1's
// fixed-base multiplies). P-256 has no endomorphism, so — unlike k256 — the
// table is the ONLY structural speedup for `k·G`; there is no GLV split on top.
//
// Design (w = 6): the scalar is recoded into `fb_t = 43` signed digits of `w`
// bits, d_i ∈ [−2^(w−1), 2^(w−1)−1] (a running-carry Booth recoding, so
// Σ d_i·2^(w·i) = k exactly for every raw 256-bit scalar: the top window holds
// only 4 scalar bits, so its digit is at most 16 and never carries out).
// Window `i` owns the magnitudes {1,…,2^(w−1)}·2^(w·i)·G; the sign of a digit
// is applied by a masked point negation, which halves the table. Entries are
// stored AFFINE (batch-normalised at comptime with one inversion), so the
// online addition is the mixed form (RCB Algorithm 5 for the CT comb, Jacobian
// madd for the vartime path) and each entry is 64 B, not 96.
//
//   memory: fb_t · fb_teeth affine points = 43 · 32 · 64 B = 88 064 B of
//   .rodata (was 65 · 8 · 96 B = 49 920 B with w = 4 projective). Measured
//   2026-09-28: CT `k·G` 41 µs → ~27 µs; the table also serves verify's
//   `u1·G` at ~43 mixed additions and no doublings.
//
// The table is generated at COMPTIME (via the portable field path — the
// `@inComptime()` guard in `field.zig` keeps the runtime asm core out of the
// comptime interpreter), on the complete projective formulas, then converted
// to affine with ONE comptime inversion (Montgomery's trick).

/// Fixed-base window width in bits.
const fb_w: usize = 6;
/// Table entries per window: magnitudes 1..2^(w−1).
const fb_teeth: usize = 1 << (fb_w - 1); // 32
/// Number of windows covering 256 bits (the last one partial).
const fb_t: usize = (256 + fb_w - 1) / fb_w; // 43
const fb_half: u64 = 1 << (fb_w - 1); // 32
const fb_twow: u64 = 1 << fb_w; // 64
const fb_wmask: u64 = fb_twow - 1;

comptime {
    // No carry can leave the top window: its raw value plus the incoming
    // carry must stay below 2^(w−1). Otherwise `fb_t` needs one more window.
    std.debug.assert((@as(u64, 1) << @intCast(256 - (fb_t - 1) * fb_w)) <= fb_half);
}

/// Window width of the CT variable-base core `mulCtWindowed` (its runtime
/// magnitude table is {1..8}·p, built per call — a wider window would cost
/// more in table construction than it saves).
const comb_w: usize = 4;
const comb_teeth: usize = 1 << (comb_w - 1); // 8
const comb_t: usize = (256 / comb_w) + 1; // 65

/// The precomputed fixed-base table type: `[window][magnitude−1]` affine points.
pub const BaseTable = [fb_t][fb_teeth]AffineCoordinates;

/// Build the fixed-base table at comptime. `tab[i][j] = (j+1)·2^(w·i)·G`.
fn buildBaseTable() BaseTable {
    @setEvalBranchQuota(100_000_000);
    const n = fb_t * fb_teeth;
    var proj: [n]P256 = undefined;
    var base = P256.basePoint; // 2^(w·i)·G, starting at G
    var i: usize = 0;
    while (i < fb_t) : (i += 1) {
        proj[i * fb_teeth] = base;
        var j: usize = 1;
        while (j < fb_teeth) : (j += 1) {
            // (j+1)·base: even multiples as a doubling of the half, odd ones as
            // one more addition of `base` — fewer comptime field multiplies.
            proj[i * fb_teeth + j] = if ((j + 1) % 2 == 0)
                proj[i * fb_teeth + (j + 1) / 2 - 1].dbl()
            else
                proj[i * fb_teeth + j - 1].add(base);
        }
        var d: usize = 0;
        while (d < fb_w) : (d += 1) base = base.dbl();
    }
    // Batch-normalise (projective: affine = (X/Z, Y/Z)) with one inversion.
    var prefix: [n]field.Fe = undefined;
    prefix[0] = proj[0].z;
    i = 1;
    while (i < n) : (i += 1) prefix[i] = prefix[i - 1].mul(proj[i].z);
    var inv = prefix[n - 1].invert();
    var tab: BaseTable = undefined;
    i = n;
    while (i > 0) {
        i -= 1;
        const zinv = if (i == 0) inv else inv.mul(prefix[i - 1]);
        if (i > 0) inv = inv.mul(proj[i].z);
        tab[i / fb_teeth][i % fb_teeth] = .{ .x = proj[i].x.mul(zinv), .y = proj[i].y.mul(zinv) };
    }
    return tab;
}

/// The fixed-base table for G (public constant; see `combMulBaseFast`,
/// `mulPublic`).
pub const base_table: BaseTable = buildBaseTable();

/// Optimization barrier (montint `b199192`): launder a value through an empty
/// inline-asm so LLVM loses all equality/range knowledge about it. Applied to
/// the per-entry gather mask so the branchless masked scan cannot be recovered
/// and lowered to a secret-indexed jump table. No-op at runtime.
inline fn blackBox(x: u64) u64 {
    return asm volatile (""
        : [ret] "=r" (-> u64),
        : [x] "0" (x),
    );
}

/// Masked limb blend: `dst = (dst & ~mask) | (src & mask)`. `mask` is 0 or all
/// ones (laundered by `blackBox`).
inline fn blendLimbs(dst: *field.Fe, src: field.Fe, mask: u64) void {
    for (&dst.limbs, src.limbs) |*d, s| d.* = (s & mask) | (d.* & ~mask);
}

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

test "wNAF: the top of the scalar range recodes without wrapping" {
    // ⭐ The eight scalars the random differential below can never draw
    // (probability 2^-253) and that the redirect test masks away outright
    // (`s[0] &= 0x7f`). A negative wNAF digit is applied by ADDING to the
    // accumulator, so `s = 2^256 - k` for odd k <= 15 carried past 2^256; in
    // a u256 that wrapped to zero, ending the recoding after one digit and
    // encoding -k instead of s. `mulPublic` then answered `-k·P` while the
    // constant-time ladder — and std — answered `s·P`.
    //
    // Checked against BOTH oracles: the module's own CT ladder (so the two
    // paths of this module agree) and std (so neither is wrong in the same
    // way).
    var s1b: [32]u8 = undefined;
    var prng = std.Random.DefaultPrng.init(0x2A6F_1E55_C0DE);
    prng.random().bytes(&s1b);
    const p = try P256.combMulBase(s1b, .big);
    const sp = try Std.basePoint.mul(s1b, .big);

    var k: u9 = 1;
    while (k <= 31) : (k += 2) {
        const s: u256 = @as(u256, 0) -% @as(u256, k); // 2^256 - k
        var sb: [32]u8 = undefined;
        std.mem.writeInt(u256, &sb, s, .big);

        // The scalar is above the group order, so only the raw point-level
        // multiplies accept it — which is exactly the surface `mulPublic` and
        // `mulDoubleBasePublic` document as std-equivalent.
        const got = try p.mulPublic(sb, .big);
        const want_ct = try p.mul(sb, .big);
        const want_std = try sp.mul(sb, .big);
        // Both of this module's paths against std: they therefore also agree
        // with each other, and a shared mistake cannot hide in the pair.
        try eqAffine(got, want_std);
        try eqAffine(want_ct, want_std);
    }
}

test "addMixed (RCB Alg. 5) == add (RCB Alg. 4) with Z2 = 1, incl. O, P = Q, P = −Q" {
    var prng = std.Random.DefaultPrng.init(0xA11_F1E5_9256);
    const rand = prng.random();
    var i: usize = 0;
    while (i < 300) : (i += 1) {
        var s1b: [32]u8 = undefined;
        var s2b: [32]u8 = undefined;
        rand.bytes(&s1b);
        rand.bytes(&s2b);
        const p = P256.combMulBase(s1b, .big) catch continue;
        const q = P256.combMulBase(s2b, .big) catch continue;
        const qa = q.affineCoordinates();
        const q1 = P256{ .x = qa.x, .y = qa.y, .z = field.Fe.one };
        // Random P (non-trivial Z) + affine Q.
        try std.testing.expect(p.addMixed(qa).equivalent(p.add(q1)));
        // The identity, P = Q, P = −Q — the cases an incomplete formula breaks on.
        try std.testing.expect(P256.identityElement.addMixed(qa).equivalent(q));
        try std.testing.expect(q.addMixed(qa).equivalent(q.dbl()));
        try std.testing.expectError(error.IdentityElement, q.neg().addMixed(qa).rejectIdentity());
        // Projective result must be exactly Alg. 4's for the same inputs
        // (the same formula with Z2 = 1 folded in), not just the same point.
        const a = p.addMixed(qa);
        const b = p.add(q1);
        try std.testing.expectEqual(a.x.limbs, b.x.limbs);
        try std.testing.expectEqual(a.y.limbs, b.y.limbs);
        try std.testing.expectEqual(a.z.limbs, b.z.limbs);
    }
}

test "basePoint.mulPublic takes the fixed-base table and agrees with std + the CT comb" {
    // The vartime `u1·G` path of every ECDSA verify — std's generic verifier
    // included — never appeared in the differential above, whose `mulPublic`
    // base is a random point. Random scalars plus the edges of the recoding:
    // 1, 2, n−1, n, 2^256−1, 2^256−k (the carry chain at the top window), and
    // every single-window value.
    var prng = std.Random.DefaultPrng.init(0xF1_BA5E_9256);
    const rand = prng.random();
    const n = scalarmod.field_order;
    var i: usize = 0;
    while (i < 300) : (i += 1) {
        var sb: [32]u8 = undefined;
        rand.bytes(&sb);
        const got = P256.basePoint.mulPublic(sb, .big) catch continue;
        try eqAffine(got, try Std.basePoint.mul(sb, .big));
        try std.testing.expect(got.equivalent(try P256.combMulBase(sb, .big)));
    }
    const edges = [_]u256{ 1, 2, 3, 31, 32, 33, 63, 64, 65, n - 1, n, n + 1, (1 << 255), (1 << 256) - 1, (1 << 256) - 17, (1 << 252) - 1, 1 << 252, (1 << 252) + 1 };
    for (edges) |s| {
        var sb: [32]u8 = undefined;
        std.mem.writeInt(u256, &sb, s, .big);
        // `n·G` is the identity: both sides must refuse it, everything else
        // must agree.
        const got = P256.basePoint.mulPublic(sb, .big);
        if (Std.basePoint.mul(sb, .big)) |want| {
            try eqAffine(try got, want);
        } else |_| {
            try std.testing.expectError(error.IdentityElement, got);
        }
    }
    // Zero → the identity → rejected, like std.
    try std.testing.expectError(error.IdentityElement, P256.basePoint.mulPublic([_]u8{0} ** 32, .big));
    try std.testing.expectError(error.IdentityElement, Std.basePoint.mul([_]u8{0} ** 32, .big));
}

test "mulDoubleBasePublic with G in either slot, and with neither, matches std" {
    var prng = std.Random.DefaultPrng.init(0xD0B_1E_9256);
    const rand = prng.random();
    var i: usize = 0;
    while (i < 150) : (i += 1) {
        var s1b: [32]u8 = undefined;
        var s2b: [32]u8 = undefined;
        var s3b: [32]u8 = undefined;
        rand.bytes(&s1b);
        rand.bytes(&s2b);
        rand.bytes(&s3b);
        const q = P256.combMulBase(s3b, .big) catch continue;
        const sq = Std.basePoint.mul(s3b, .big) catch continue;
        const g1 = P256.mulDoubleBasePublic(P256.basePoint, s1b, q, s2b, .big) catch continue;
        try eqAffine(g1, try Std.mulDoubleBasePublic(Std.basePoint, s1b, sq, s2b, .big));
        const g2 = P256.mulDoubleBasePublic(q, s2b, P256.basePoint, s1b, .big) catch continue;
        try eqAffine(g2, try Std.mulDoubleBasePublic(sq, s2b, Std.basePoint, s1b, .big));
        // The Jacobian join's exceptional cases: s1·G = ±s2·Q, i.e. Q = G with
        // s2 = ±s1 (mod n) — sum 2·s1·G, or the identity (rejected).
        const g_dup = try P256.mulDoubleBasePublic(P256.basePoint, s1b, P256.basePoint.dbl(), s1b, .big);
        try eqAffine(g_dup, try Std.mulDoubleBasePublic(Std.basePoint, s1b, Std.basePoint.dbl(), s1b, .big));
    }
    // s·G + (n−s)·G = O → error, both sides.
    const n = scalarmod.field_order;
    var s: u256 = 0x1234_5678_9abc_def0;
    var sb: [32]u8 = undefined;
    var nb: [32]u8 = undefined;
    std.mem.writeInt(u256, &sb, s, .big);
    std.mem.writeInt(u256, &nb, n - s, .big);
    try std.testing.expectError(error.IdentityElement, P256.mulDoubleBasePublic(P256.basePoint, sb, P256.basePoint.dbl().add(P256.basePoint.neg()), nb, .big));
    // And s·G + s·G (Q given as another representation of G) = 2s·G.
    s = 7;
    std.mem.writeInt(u256, &sb, s, .big);
    const g_other = P256.basePoint.dbl().add(P256.basePoint.neg()); // G, but not `isBasePointRepr`
    try std.testing.expect(!g_other.isBasePointRepr());
    const got = try P256.mulDoubleBasePublic(P256.basePoint, sb, g_other, sb, .big);
    try eqAffine(got, try Std.basePoint.mul([_]u8{0} ** 31 ++ [_]u8{14}, .big));
}

// Debug: this test (7 std-touching point ops per draw: two basePoint muls,
// dbl, add, CT mul, mulPublic, mulDoubleBasePublic) hit the full gate's
// per-test 3-minute timeout (`gate-all-20260917e.log:118-143`,
// "timed out after 3m0.938ms"). Isolated under this session's own machine
// load, the unscaled 400-iteration loop alone measured ~90s -- std's
// unoptimized Debug `basePoint.mul` (plain double-and-add, no comb table
// there) is the cost, not a bug in the code under test (same shape as the
// k256 `oracle_test.comb` fix, `14b2e983`). ReleaseFast/ReleaseSafe/
// ReleaseSmall keep the full count -- they are fast enough already.
const group_diff_iters: usize = if (builtin.mode == .Debug) 30 else 400;

test "differential vs std: dbl/add/scalarmul/combMulBase on random scalars" {
    var prng = std.Random.DefaultPrng.init(0x60D_C0DE_9256);
    const rand = prng.random();
    var i: usize = 0;
    while (i < group_diff_iters) : (i += 1) {
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

// Debug: measured ~16s for this test ALONE, isolated -- each draw is a
// std.basePoint.mul plus module combMulBase, over the campaign's 10s
// per-test budget. Fixed-vector coverage of the SEC1 decode paths (identity/
// compressed/uncompressed/malformed) lives separately in "corpus: every
// SEC1 seed reaches fromSec1" below, unconditionally in every mode -- this
// only trims the random-sample count.
const sec1_roundtrip_iters: usize = if (builtin.mode == .Debug) 100 else 300;

test "SEC1 round-trip (compressed + uncompressed) matches std" {
    var prng = std.Random.DefaultPrng.init(0x5EC1_9256);
    const rand = prng.random();
    var i: usize = 0;
    while (i < sec1_roundtrip_iters) : (i += 1) {
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

// ── fuzz: fromSec1 never panics on arbitrary attacker-supplied encodings ──
//
// `fromSec1` is the entry point for every externally-supplied P-256 point
// this repo's protocols decode (TLS key shares, JWK/COSE keys, HPKE's
// P-256 DHKEM `enc`/public keys, X.509 SubjectPublicKeyInfo) — the tag byte
// selects three structurally different decode paths (identity / compressed
// / uncompressed), so the harness biases toward each valid tag with random
// payload bytes, plus fully random bytes for the tag-rejection path.

/// A corpus entry carrying the SEC1 encoding spelled by `h`. A corpus entry is
/// NOT the encoding: `Smith.slice` reads a little-endian `u32` length first, so
/// a raw point would arrive minus its own first four octets — which for SEC1 is
/// the tag and three octets of `x`.
///
/// ⛔ This is `testkit.fuzz.seedHex`, copied. `testkit` is the right home for
/// it and every other module in this burn-down imports it from there — but
/// putting it in `p256`'s `test_deps` enrols the module in
/// `zig build check-testonly`, and p256's probe does not compile: the gate's
/// 3-deep public-decl walk reaches `P256.scalar` (std's P-256 scalar field) and
/// forces `sqrt`, which is `@compileError("unimplemented")` in
/// `std/crypto/pcurves/common.zig:280` because the group order is 1 mod 4.
/// Measured 2026-09-07 on an UNMODIFIED p256 tree with only the `test_deps`
/// line added: `check-testonly` goes from 3 failing probes to 4. So the choice
/// was a nine-line copy here or a new red probe in a shared gate, and the copy
/// is the smaller debt. Delete it the day p256's published surface stops
/// re-exporting a scalar field std cannot take a square root in.
fn seedHex(comptime h: []const u8) []const u8 {
    return &struct {
        const frame = blk: {
            if (h.len % 2 != 0) @compileError("odd-length hex seed: " ++ h);
            @setEvalBranchQuota(@max(1000, 40 * h.len));
            var out: [h.len / 2]u8 = undefined;
            _ = std.fmt.hexToBytes(&out, h) catch @compileError("bad hex seed: " ++ h);
            break :blk out;
        };
        const bytes = std.mem.toBytes(@as(u32, @intCast(frame.len))) ++ frame;
    }.bytes;
}

test "seedHex matches testkit.fuzz.seedHex's framing, which is what Smith.slice reads" {
    // The copy above has to stay byte-identical to the shared helper, and the
    // only thing that makes that testable without importing it is driving the
    // real `std.testing.Smith` over the produced seed — the same anchor
    // `testkit/src/fuzz.zig` carries for the original.
    const s = seedHex("6f0016000100a5a5");
    var smith: std.testing.Smith = .{ .in = s };
    var buf: [64]u8 = undefined;
    const n = smith.slice(&buf);
    try std.testing.expectEqualSlices(
        u8,
        &.{ 0x6f, 0x00, 0x16, 0x00, 0x01, 0x00, 0xa5, 0xa5 },
        buf[0..n],
    );
}

/// Real SEC1 encodings, one per decode path and one per typed refusal.
///
/// ⚠ 65 octets is the longest entry here and the harness's buffer is exactly
/// 65, which is deliberate: a seed longer than the buffer is not a big seed,
/// it is the EMPTY one (`Smith.slice` falls back to the range minimum). The
/// uncompressed form is the largest encoding `fromSec1` accepts, so the buffer
/// cannot be shortened without making the only 65-octet path unreachable.
const sec1_seeds = [_][]const u8{
    // ── the three accepting paths ──
    seedHex("00"), // the identity element: tag 0 with an empty body
    seedHex("036b17d1f2e12c4247f8bce6e563a440f277037d812deb33a0f4a13945d898c296"), // G compressed (y odd → tag 3)
    seedHex("026b17d1f2e12c4247f8bce6e563a440f277037d812deb33a0f4a13945d898c296"), // the same x, tag 2 → −G, the other recoverY branch
    seedHex("047cf27b188d034f7e8a52380304b51ac3c08969e277f21b35a60b48fc4766997807775510db8ed040293d9ac69f7430dbba7dade63ce982299e04b79d227873d1"), // 2G uncompressed: the 65-octet path
    seedHex("046b17d1f2e12c4247f8bce6e563a440f277037d812deb33a0f4a13945d898c2964fe342e2fe1a7f9b8ee7eb4a7c0f9e162bce33576b315ececbb6406837bf51f5"), // G uncompressed
    seedHex("037cf27b188d034f7e8a52380304b51ac3c08969e277f21b35a60b48fc47669978"), // 2G compressed
    // ── the refusals, one per error the signature declares ──
    seedHex("030000000000000000000000000000000000000000000000000000000000000001"), // x = 1: x³−3x+b is a non-residue → NotSquare
    seedHex("03ffffffff00000001000000000000000000000000ffffffffffffffffffffffff"), // x = p exactly → NonCanonical
    seedHex("046b17d1f2e12c4247f8bce6e563a440f277037d812deb33a0f4a13945d898c2966b17d1f2e12c4247f8bce6e563a440f277037d812deb33a0f4a13945d898c296"), // y := x, a well-formed pair that is not on the curve
    seedHex("056b17d1f2e12c4247f8bce6e563a440f277037d812deb33a0f4a13945d898c296"), // tag 5 is not a SEC1 tag
    seedHex("0000"), // tag 0 with a body: the identity is exactly one octet
    seedHex("036b17d1f2e12c4247f8bce6e563a440f277037d812deb33a0f4a13945d898c2"), // compressed, one octet short
    seedHex("04"), // a bare uncompressed tag with no coordinates
    seedHex(""), // the zero-length encoding
};

test "fuzz: fromSec1 never panics on arbitrary bytes" {
    try std.testing.fuzz({}, fuzzFromSec1, .{ .corpus = &sec1_seeds });
}

fn fuzzFromSec1(_: void, smith: *std.testing.Smith) !void {
    return sec1Harness(std.testing.Smith, smith, std.testing.allocator);
}

const fuzz_driver = @import("testkit").fuzz.driver;
const FuzzLabel = enum { raw_rejected, raw_accepted, roundtrip, flip_rejected };
var fuzz_reach: [@typeInfo(FuzzLabel).@"enum".fields.len]usize = @splat(0);

fn mark(comptime l: FuzzLabel) void {
    fuzz_reach[@intFromEnum(l)] += 1;
    fuzz_driver.hit(@tagName(l));
}

test "fuzz driver: P256_FUZZ (p256-sec1)" {
    try fuzz_driver.run(sec1Harness, .{ .prefix = "P256_FUZZ", .name = "p256-sec1" });
}

test "fuzz harness: 300 seeds in every test run, and they get everywhere" {
    fuzz_reach = @splat(0);
    for (0..300) |seed| {
        var prng = std.Random.DefaultPrng.init(seed);
        var rng: fuzz_driver.Rng = .{ .r = prng.random() };
        sec1Harness(fuzz_driver.Rng, &rng, std.testing.allocator) catch |err| {
            std.debug.print("p256-sec1 seed {d}: {t}\n", .{ seed, err });
            return err;
        };
    }
    for (fuzz_reach, 0..) |n, i| {
        const l: FuzzLabel = @enumFromInt(i);
        // A random SEC1 string is accepted only as the lone tag 0x00 (the
        // identity), which is 1 in ~2^8 per input; the roundtrip overlay below
        // covers the accepting paths, so `raw_accepted` is not demanded.
        if (l == .raw_accepted) continue;
        if (n == 0) {
            std.debug.print("reach: label {t} never hit in 300 seeds\n", .{l});
            return error.HarnessDoesNotReach;
        }
    }
}

/// Generic over its source (`Smith` under `--fuzz`, `fuzz_driver.Rng` under the
/// driver). Raw bytes go to `fromSec1` (any outcome, no panic). Then a genuine
/// point `k*G` (k from the same drawn octets) must survive both encodings, the
/// opposite compressed tag must decode to its negation, and an uncompressed
/// encoding with one `y` bit flipped must be refused (a single flipped bit can
/// never turn `y` into `-y`, so it is off the curve).
fn sec1Harness(comptime S: type, smith: *S, gpa: std.mem.Allocator) anyerror!void {
    _ = gpa;
    var buf: [65]u8 = undefined;
    // ⚠ `smith.slice` in ONE call, never `bytes` and then a ranged length.
    // What stood here did both, and also chose the tag from a ranged draw
    // AFTER `bytes` had eaten the input. A `Smith` ranged draw reads eight
    // octets as a little-endian `u64` and returns the range MINIMUM when
    // fewer remain, so outside `--fuzz` the tag was always 0 and `len` was
    // always 0 — every run of this target called `fromSec1(&.{})` and
    // returned on the `s.len < 1` line. The whole SEC1 decoder, three paths
    // and four typed refusals, was reached by nothing.
    const len: usize = smith.slice(&buf);
    if (P256.fromSec1(buf[0..len])) |_| {
        mark(.raw_accepted);
    } else |_| {
        mark(.raw_rejected);
    }

    // Pristine overlay: k = the drawn octets (zero-padded) as a scalar.
    var k: [32]u8 = @splat(0);
    @memcpy(k[0..@min(len, 32)], buf[0..@min(len, 32)]);
    k[0] &= 0x7f; // below the group order's leading octet 0xff: any k < n
    k[31] |= 1; // nonzero
    const pt = P256.basePoint.mulPublic(k, .big) catch return;
    pt.rejectIdentity() catch return;

    const comp = pt.toCompressedSec1();
    const back_c = P256.fromSec1(&comp) catch return error.GenuineEncodingRejected;
    if (!back_c.equivalent(pt)) return error.RoundTripMismatch;
    const unc = pt.toUncompressedSec1();
    const back_u = P256.fromSec1(&unc) catch return error.GenuineEncodingRejected;
    if (!back_u.equivalent(pt)) return error.RoundTripMismatch;
    mark(.roundtrip);

    var other = comp;
    other[0] ^= 1; // 02 <-> 03: the point with the other y parity
    const neg_pt = P256.fromSec1(&other) catch return error.GenuineEncodingRejected;
    if (!neg_pt.equivalent(pt.neg())) return error.NegationMismatch;
    if (neg_pt.equivalent(pt)) return error.NegationMismatch;

    var bad = unc;
    bad[33 + buf[1] % 32] ^= @as(u8, 1) << @intCast(buf[2] % 8);
    if (P256.fromSec1(&bad)) |_| {
        return error.ForgedPointAccepted;
    } else |_| {}
    mark(.flip_rejected);
}

test "corpus: every SEC1 seed reaches fromSec1, and the points decoded are pinned" {
    // ⭐ The measurement, executable rather than asserted in prose. It draws
    // exactly the way the harness does, because the defect WAS the draw.
    //
    // `on_curve` is the second number and it is the one that matters: an
    // empty input cannot produce a point at all, so it cannot inflate this
    // count the way "did not crash" would be satisfied by anything.
    var nonempty: usize = 0;
    var accepted: usize = 0;
    var on_curve: usize = 0;
    var non_identity: usize = 0;
    for (sec1_seeds) |sd| {
        var smith: std.testing.Smith = .{ .in = sd };
        var buf: [65]u8 = undefined;
        const len: usize = smith.slice(&buf);
        if (len != 0) nonempty += 1;
        const pt = P256.fromSec1(buf[0..len]) catch continue;
        accepted += 1;
        pt.rejectIdentity() catch continue;
        non_identity += 1;
        // Re-encoding and decoding again is the cheap on-curve confirmation:
        // `fromSec1` of a compressed form only admits points that satisfy the
        // curve equation, so a round trip that survives is one.
        _ = P256.fromSec1(&pt.toCompressedSec1()) catch continue;
        on_curve += 1;
    }
    // Measured 2026-09-07. Before the draw was fixed: 1 round, 0 non-empty,
    // 0 accepted, 0 on-curve — the target only ever ran `fromSec1("")`.
    try std.testing.expectEqual(sec1_seeds.len - 1, nonempty); // the deliberate empty encoding
    try std.testing.expectEqual(@as(usize, 6), accepted);
    try std.testing.expectEqual(@as(usize, 5), non_identity);
    try std.testing.expectEqual(@as(usize, 5), on_curve);
}
