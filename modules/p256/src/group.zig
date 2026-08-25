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
        if (p.isBasePointRepr()) return combMulBase(s_, endian);
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
    pub fn combMulBase(s_: [32]u8, endian: std.builtin.Endian) IdentityElementError!P256 {
        if (comptime gate.fast_scalarmul_implemented) {
            return combMulBaseFast(s_, endian);
        }
        return basePoint.mulDoubleAddCt(s_, endian);
    }

    /// GATED Fable core #2b — the fixed-base comb for `k·G` (the fast signing
    /// path). The comptime-generated comb table (`comb_table`: magnitudes
    /// `{1..2^{w−1}}·2^{w·i}·G`, stored projective) makes the online phase
    /// `comb_t` point additions with NO doublings — each window's table already
    /// carries the `2^{w·i}` factor. The signed-digit recoding is branch-free
    /// and the table gather is the same `blackBox`-guarded masked linear scan
    /// as `mulCtWindowed` (see the comb section below for the CT contract).
    /// Pinned to `basePoint.mulDoubleAddCt` + std by the gated differential.
    /// `error.IdentityElement` iff `s ≡ 0 (mod n)`.
    pub fn combMulBaseFast(s_: [32]u8, endian: std.builtin.Endian) IdentityElementError!P256 {
        return combMulBaseFastWithTable(&comb_table, s_, endian);
    }

    /// `combMulBaseFast` parameterised on the table, so the positive-control
    /// test in `oracle_test.zig` can pass a deliberately-corrupted table and
    /// prove the differential has teeth. The table index `[i][j]` is driven
    /// only by the PUBLIC loop counters — never by a secret — so this stays
    /// constant-time for any table. `pub` for that harness.
    pub fn combMulBaseFastWithTable(tab: *const CombTable, s_: [32]u8, endian: std.builtin.Endian) IdentityElementError!P256 {
        const k = scalarValue(s_, endian);
        const half: u64 = 1 << (comb_w - 1); // 2^(w−1)
        const twow: u64 = 1 << comb_w; // 2^w
        const wmask: u64 = twow - 1;

        var acc = P256.identityElement;
        // Signed-digit (Booth-style) recoding with a running carry, folded into
        // the same loop that consumes the digits — fully branchless in `k`.
        // Digit d_i ∈ [−2^(w−1), 2^(w−1)−1], so Σ d_i·2^(w·i) = k exactly and
        // the magnitude |d_i| ∈ [0, 2^(w−1)] indexes the half-size table.
        var carry: u64 = 0;
        var i: usize = 0;
        while (i < comb_t) : (i += 1) {
            const shift: usize = i * comb_w; // PUBLIC (loop-derived) shift
            const wv: u64 = if (shift < 256) (@as(u64, @truncate(k >> @intCast(shift))) & wmask) else 0;
            const x = wv + carry; // 0 .. 2^w
            // is_neg ⟺ x ≥ 2^(w−1): then d = x − 2^w (< 0) and carry propagates.
            // A `>=` compare lowers to setcc (data-independent), not a branch.
            const is_neg: u64 = @intFromBool(x >= half);
            carry = is_neg;
            // The select mask is laundered through `blackBox`: without it LLVM
            // recovers `is_neg = (x >= half)` and lowers the select to a CMOV
            // on the secret digit — observed in ReleaseFast disasm before the
            // barrier was added.
            const negmask: u64 = blackBox(0 -% is_neg);
            // |d| = is_neg ? (2^w − x) : x  — masked, no branch.
            const m = ((twow - x) & negmask) | (x & ~negmask); // 0 .. 2^(w−1)

            // CONSTANT-TIME gather of the table entry for magnitude `m`: a
            // masked linear scan touching EVERY entry of window `i`. The
            // per-entry select mask is laundered through `blackBox` so LLVM
            // cannot recover "pick the entry where j+1 == m" and lower it to a
            // secret-indexed jump table (`jmp *tbl(,%reg,8)`) — the exact
            // powMont-gather leak class (montint b199192). `m == 0` (digit 0)
            // matches no entry, leaving `g` the neutral element (adds nothing).
            var g = P256.identityElement;
            var j: usize = 0;
            while (j < comb_teeth) : (j += 1) {
                const match: u64 = @intFromBool(@as(u64, j + 1) == m);
                const mask = blackBox(0 -% match);
                blendLimbs(&g.x, tab[i][j].x, mask);
                blendLimbs(&g.y, tab[i][j].y, mask);
                blendLimbs(&g.z, tab[i][j].z, mask);
            }
            // Signed digit ⇒ conditional point negation as a masked blend of
            // the unconditionally-computed −y, with the sign mask laundered
            // through `blackBox` — a plain `cMov` here was observed to lower
            // to a secret-dependent branch skipping the negation (the montint
            // b199192 leak class) in ReleaseFast disasm.
            const yneg = g.y.neg();
            const smask = blackBox(0 -% is_neg);
            blendLimbs(&g.y, yneg, smask);

            acc = acc.add(g);
        }
        try acc.rejectIdentity();
        return acc;
    }

    /// VARIABLE-TIME scalar multiply for a PUBLIC scalar (verification) via a
    /// width-`wnaf_w` NAF: ~`l/(w+1)` additions instead of ~`l/2`. All inputs
    /// public, so plain branches are fine. `error.IdentityElement` if the input
    /// or result is the neutral element. Matches `mulDoubleAddCt`/std exactly.
    pub fn mulPublic(p: P256, s_: [32]u8, endian: std.builtin.Endian) IdentityElementError!P256 {
        try p.rejectIdentity();
        const s = scalarValue(s_, endian);
        var naf: [wnaf_len]i8 = [_]i8{0} ** wnaf_len;
        const l = computeWnaf(s, &naf);
        const tab = precompOdd(p);

        var q = P256.identityElement;
        var i: usize = l;
        while (i > 0) {
            i -= 1;
            q = q.dbl();
            if (naf[i] != 0) q = q.add(wnafPoint(&tab, naf[i]));
        }
        try q.rejectIdentity();
        return q;
    }

    /// VARIABLE-TIME double-base multiply `s1·p1 + s2·p2` for PUBLIC scalars —
    /// the verifier's `u1·G + u2·Q` workhorse (JWT ES256 verify hot path). Uses
    /// **interleaved wNAF (Straus–Shamir)**: a single shared doubling chain, one
    /// precomputed odd-multiple table per base, and ~`l/(w+1)` additions per
    /// scalar. Vartime (all inputs public); plain branches. `error.IdentityElement`
    /// if the result is neutral. Byte-exact vs the plain ladder + std.
    pub fn mulDoubleBasePublic(p1: P256, s1_: [32]u8, p2: P256, s2_: [32]u8, endian: std.builtin.Endian) IdentityElementError!P256 {
        try p1.rejectIdentity();
        try p2.rejectIdentity();
        const s1 = scalarValue(s1_, endian);
        const s2 = scalarValue(s2_, endian);

        var naf1: [wnaf_len]i8 = [_]i8{0} ** wnaf_len;
        var naf2: [wnaf_len]i8 = [_]i8{0} ** wnaf_len;
        const l1 = computeWnaf(s1, &naf1);
        const l2 = computeWnaf(s2, &naf2);
        const l = @max(l1, l2);
        const t1 = precompOdd(p1);
        const t2 = precompOdd(p2);

        var q = P256.identityElement;
        var i: usize = l;
        while (i > 0) {
            i -= 1;
            q = q.dbl();
            if (naf1[i] != 0) q = q.add(wnafPoint(&t1, naf1[i]));
            if (naf2[i] != 0) q = q.add(wnafPoint(&t2, naf2[i]));
        }
        try q.rejectIdentity();
        return q;
    }
};

// ── vartime wNAF (Straus–Shamir) helpers for the PUBLIC verify path ──────────
//
// P-256 has no endomorphism, so the verifier's `u1·G + u2·Q` is accelerated with
// a plain interleaved wNAF: each public scalar is recoded into signed digits
// d ∈ {0, ±1, ±3, …, ±(2^(w−1)−1)} with ≥ w−1 zeros between nonzeros, so the
// online phase averages one addition every `w+1` positions (vs every 2 for
// double-and-add). This path handles only PUBLIC values (public key, signature,
// message hash), so the data-dependent branches below are not a leak — the
// SECRET paths (`mul`/`combMulBase`) never touch this code.

/// wNAF window width (bits). w = 5 ⇒ digits {±1,±3,…,±15}, table of 8 points.
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
    var d = s;
    var i: usize = 0;
    while (d != 0) : (i += 1) {
        var digit: i8 = 0;
        if ((@as(u64, @truncate(d)) & 1) == 1) {
            const mod: u64 = @as(u64, @truncate(d)) & (two_w - 1); // d mod 2^w (odd)
            if (mod >= half) {
                digit = @intCast(@as(i64, @intCast(mod)) - @as(i64, @intCast(two_w)));
                d +%= two_w - mod; // d -= digit (digit < 0)
            } else {
                digit = @intCast(mod);
                d -%= mod;
            }
        }
        out[i] = digit;
        d >>= 1;
    }
    return i;
}

/// Odd multiples `1·p, 3·p, …, (2·wnaf_tab_len−1)·p` (projective). Vartime.
fn precompOdd(p: P256) [wnaf_tab_len]P256 {
    var tab: [wnaf_tab_len]P256 = undefined;
    tab[0] = p; // 1·p
    const p2 = p.dbl(); // 2·p
    var i: usize = 1;
    while (i < wnaf_tab_len) : (i += 1) tab[i] = tab[i - 1].add(p2); // (2i+1)·p
    return tab;
}

/// The curve point for a NONZERO wNAF digit: `tab[(|d|−1)/2]`, negated iff `d<0`.
inline fn wnafPoint(tab: *const [wnaf_tab_len]P256, digit: i8) P256 {
    const mag: usize = @intCast(if (digit < 0) -@as(i32, digit) else digit);
    const pt = tab[(mag - 1) / 2];
    return if (digit < 0) pt.neg() else pt;
}

// ── fixed-base comb table (CONSTANT-TIME base-point multiply k·G) ────────────
//
// The signing path multiplies the FIXED base point G by a secret scalar twice
// per signature (the nonce commitment R = k·G and the pubkey P = d·G). A naive
// constant-time double-and-add pays 256 doublings + 256 conditional adds; the
// fixed-base **windowed comb** replaces that with a precomputed table so the
// online phase does NO doublings at all — just `comb_t` point additions, one
// per signed digit, gathered constant-time from the table (the technique behind
// OpenSSL nistz256's and libsecp256k1's fixed-base multiplies). P-256 has no
// endomorphism, so — unlike k256 — the comb is the ONLY structural speedup for
// `k·G`; there is no GLV split on top.
//
// Design (w = 4): the scalar is recoded into `comb_t` signed digits of `w`
// bits, d_i ∈ [−2^(w−1), 2^(w−1)−1] (a running-carry Booth recoding, so
// Σ d_i·2^(w·i) = k exactly, including the raw-scalar range up to 2^256−1 — the
// extra window absorbs the final carry). Window `i` owns a table of the
// magnitudes {1,2,…,2^(w−1)}·2^(w·i)·G; the sign of a digit is applied by a
// masked point negation, which halves the table. Online cost = comb_t adds.
//
//   memory: comb_t · comb_teeth projective points
//         = 65 · 8 · (3 × 32 B) = 48.75 KiB of .rodata (a comptime constant).
//
// The table is generated at COMPTIME (via the portable field path — the
// `@inComptime()` guard in `field.zig` keeps the runtime asm core out of the
// comptime interpreter), stored PROJECTIVE so no comptime field inversions are
// needed (affine conversion would run a Fermat inverse per entry).

/// Comb window width in bits. `256 % comb_w == 0` keeps the window layout exact.
const comb_w: usize = 4;
/// Table entries per window: magnitudes 1..2^(w−1) (the signed digit folds the
/// sign out, halving the table). Also the table size of `mulCtWindowed`.
const comb_teeth: usize = 1 << (comb_w - 1); // 8
/// Number of windows: 256/w low windows plus one to absorb the recoding carry.
const comb_t: usize = (256 / comb_w) + 1; // 65

/// The precomputed comb table type: `[window][magnitude−1]` projective points.
pub const CombTable = [comb_t][comb_teeth]P256;

/// Build the comb table at comptime. `tab[i][j] = (j+1)·2^(w·i)·G`, projective.
fn buildCombTable() CombTable {
    @setEvalBranchQuota(100_000_000);
    var tab: CombTable = undefined;
    var base = P256.basePoint; // 2^(w·i)·G, starting at G
    var i: usize = 0;
    while (i < comb_t) : (i += 1) {
        var acc = base; // 1·base
        tab[i][0] = acc;
        var j: usize = 1;
        while (j < comb_teeth) : (j += 1) {
            acc = acc.add(base); // (j+1)·base
            tab[i][j] = acc;
        }
        // base ← 2^w · base for the next window.
        var d: usize = 0;
        while (d < comb_w) : (d += 1) base = base.dbl();
    }
    return tab;
}

/// The fixed-base comb table for G (public constant; see `combMulBaseFast`).
pub const comb_table: CombTable = buildCombTable();

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

// ── fuzz: fromSec1 never panics on arbitrary attacker-supplied encodings ──
//
// `fromSec1` is the entry point for every externally-supplied P-256 point
// this repo's protocols decode (TLS key shares, JWK/COSE keys, HPKE's
// P-256 DHKEM `enc`/public keys, X.509 SubjectPublicKeyInfo) — the tag byte
// selects three structurally different decode paths (identity / compressed
// / uncompressed), so the harness biases toward each valid tag with random
// payload bytes, plus fully random bytes for the tag-rejection path.

test "fuzz: fromSec1 never panics on arbitrary bytes" {
    try std.testing.fuzz({}, fuzzFromSec1, .{});
}

fn fuzzFromSec1(_: void, smith: *std.testing.Smith) !void {
    var buf: [65]u8 = undefined;
    smith.bytes(&buf);
    const tag: u8 = switch (smith.valueRangeAtMost(u8, 0, 4)) {
        0 => 0,
        1 => 2,
        2 => 3,
        3 => 4,
        else => smith.value(u8), // fully arbitrary, including invalid tags
    };
    buf[0] = tag;
    const len: usize = smith.valueRangeAtMost(u8, 0, buf.len);
    if (len == 0) {
        _ = P256.fromSec1(&.{}) catch return;
        return;
    }
    _ = P256.fromSec1(buf[0..len]) catch {};
}
