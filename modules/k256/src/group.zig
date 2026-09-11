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
//!     dispatch point for the gated GLV core (`mulPublicGlv`, IMPLEMENTED);
//!     portable fallback is a plain vartime double-and-add.
//!   * `mulDoubleBasePublic` — VARIABLE-TIME `s1·P1 + s2·P2`, the verifier's
//!     `s·G − e·P` workhorse; under the same gate it runs the GLV 4-way
//!     interleaved combine.
//!
//! The simple double-and-add forms remain as the proven portable oracle the
//! GLV paths are differentially pinned to (and the non-gated fallback).

const std = @import("std");
/// Test-only (`build.zig`'s `test_deps`, never `deps`): fuzz corpus framing.
const gate = @import("gate.zig");
const field = @import("field.zig");
const scalarmod = @import("scalar.zig");

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

    /// The base-field element type, exposed as `Secp256k1.Fe` to mirror
    /// `std.crypto.ecc.Secp256k1.Fe` so the Bitcoin/LN consumers that alias
    /// `const Fe = Secp256k1.Fe;` are drop-in on k256.
    pub const Fe = field.Fe;
    /// The scalar field (mod the group order `n`), exposed as
    /// `Secp256k1.scalar` to mirror `std.crypto.ecc.Secp256k1.scalar`. This is
    /// std's constant-time scalar field verbatim (see `scalar.zig`'s scope
    /// note), so consumers aliasing `const scalar = Secp256k1.scalar;` are
    /// drop-in.
    pub const scalar = scalarmod.scalar;

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

    /// CONSTANT-TIME fixed-base multiply `s·G` for a possibly-SECRET scalar,
    /// via the precomputed comb table (`comb_table`) — the fast signing path
    /// (BIP340/ECDSA nonce commitment + pubkey derivation). Bit-exact to
    /// `basePoint.mul(s)` (the naive CT ladder) but ~4× faster: the online phase
    /// is `comb_t` point additions with NO doublings, because each window's
    /// table already carries the `2^(w·i)` factor. `error.IdentityElement` iff
    /// `s ≡ 0 (mod n)`. See the comb section below for the CT-gather contract.
    pub fn combMulBase(s_: [32]u8, endian: std.builtin.Endian) IdentityElementError!Secp256k1 {
        return combMulBaseWithTable(&comb_table, s_, endian);
    }

    /// `combMulBase` parameterised on the table, so the positive-control test in
    /// `oracle_test.zig` can pass a deliberately-corrupted table and prove the
    /// differential has teeth. The table index `[i][j]` is driven only by the
    /// PUBLIC loop counters — never by a secret — so this stays constant-time
    /// for any table. `pub` for that harness (cf. `mulPublicDoubleAdd`).
    pub fn combMulBaseWithTable(tab: *const CombTable, s_: [32]u8, endian: std.builtin.Endian) IdentityElementError!Secp256k1 {
        const k = scalarValue(s_, endian);
        const half: u64 = 1 << (comb_w - 1); // 2^(w−1)
        const twow: u64 = 1 << comb_w; // 2^w
        const wmask: u64 = twow - 1;

        var acc = Secp256k1.identityElement;
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
            const negmask: u64 = 0 -% is_neg;
            // |d| = is_neg ? (2^w − x) : x  — masked, no branch.
            const m = ((twow - x) & negmask) | (x & ~negmask); // 0 .. 2^(w−1)

            // CONSTANT-TIME gather of the table entry for magnitude `m`: a
            // masked linear scan touching EVERY entry of window `i`. The
            // per-entry select mask is laundered through `blackBox` so LLVM
            // cannot recover "pick the entry where j+1 == m" and lower it to a
            // secret-indexed jump table (`jmp *tbl(,%reg,8)`) — the exact
            // powMont-gather leak class (montint b199192). `m == 0` (digit 0)
            // matches no entry, leaving `g` the neutral element (adds nothing).
            var g = Secp256k1.identityElement;
            var j: usize = 0;
            while (j < comb_teeth) : (j += 1) {
                const match: u64 = @intFromBool(@as(u64, j + 1) == m);
                const mask = blackBox(0 -% match);
                blendLimbs(&g.x, tab[i][j].x, mask);
                blendLimbs(&g.y, tab[i][j].y, mask);
                blendLimbs(&g.z, tab[i][j].z, mask);
            }
            // Signed digit ⇒ conditional point negation via masked field-negate
            // (compute −y unconditionally, select with a branch-free cMov).
            var gneg = g;
            gneg.y = g.y.neg();
            g.cMov(gneg, @intCast(is_neg));

            acc = acc.add(g);
        }
        try acc.rejectIdentity();
        return acc;
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
    /// differential oracle). `pub` so the harness/bench can pin the GLV core
    /// against it directly.
    pub fn mulPublicDoubleAdd(p: Secp256k1, s_: [32]u8, endian: std.builtin.Endian) IdentityElementError!Secp256k1 {
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

    /// GATED Fable core #2 — the GLV-decomposition variable-base scalarmul
    /// (IMPLEMENTED). VARIABLE-TIME; PUBLIC scalars only.
    ///
    /// `s` is first reduced mod the group order `n` (legal for any raw 256-bit
    /// scalar because the curve has prime order `n`, so `s·P = (s mod n)·P` —
    /// the portable double-and-add scans raw bits and agrees for the same
    /// reason). Then `(r1, r2) = scalar.splitScalar(s)` (proven byte-exact vs
    /// std), each half resolved to a signed magnitude `|r_i| ≈ √n`, and the
    /// result computed as an interleaved width-5 wNAF combine of
    /// `r1·p + r2·φ(p)` with `φ(p) = (β·x, y)` — ~half the doublings of a full
    /// scalarmul. `oracle_test.zig`'s gated differential pins it to the proven
    /// constant-time ladder.
    pub fn mulPublicGlv(p: Secp256k1, s_: [32]u8, endian: std.builtin.Endian) IdentityElementError!Secp256k1 {
        try p.rejectIdentity();
        const halves = splitToSignedHalves(scalarValue(s_, endian)) orelse return error.IdentityElement;
        const e1 = wnafDigits(halves[0]);
        const e2 = wnafDigits(halves[1]);
        var tabs: [2][glv_table_len]Secp256k1 = undefined;
        tabs[0] = oddMultiples(p);
        tabs[1] = phiTable(&tabs[0]);
        return glvCombine(2, &tabs, &.{ e1, e2 });
    }

    /// GLV+wNAF double-base multiply — `mulDoubleBasePublic`'s dispatch target
    /// under the same gate (SPEC: "extending GLV to the double-base
    /// `s·G − e·P` path"). Both scalars are split, giving a 4-way interleaved
    /// half-length combine `r11·p1 + r12·φ(p1) + r21·p2 + r22·φ(p2)`.
    fn mulDoubleBaseGlv(p1: Secp256k1, s1_: [32]u8, p2: Secp256k1, s2_: [32]u8, endian: std.builtin.Endian) IdentityElementError!Secp256k1 {
        try p1.rejectIdentity();
        try p2.rejectIdentity();
        // A zero scalar contributes nothing (all-zero digits), but s1 = s2 = 0
        // must still reject — the final rejectIdentity in the combine does.
        const zero_halves = [2]GlvHalf{ .{ .mag = 0, .negative = false }, .{ .mag = 0, .negative = false } };
        const h1 = splitToSignedHalves(scalarValue(s1_, endian)) orelse zero_halves;
        const h2 = splitToSignedHalves(scalarValue(s2_, endian)) orelse zero_halves;
        var tabs: [4][glv_table_len]Secp256k1 = undefined;
        tabs[0] = oddMultiples(p1);
        tabs[1] = phiTable(&tabs[0]);
        tabs[2] = oddMultiples(p2);
        tabs[3] = phiTable(&tabs[2]);
        return glvCombine(4, &tabs, &.{
            wnafDigits(h1[0]), wnafDigits(h1[1]),
            wnafDigits(h2[0]), wnafDigits(h2[1]),
        });
    }

    /// VARIABLE-TIME double-base multiply `s1·p1 + s2·p2` for PUBLIC scalars —
    /// the verifier's `s·G − e·P` workhorse. `error.IdentityElement` if the
    /// result is neutral (the BIP340 "sG − eP is infinite" reject). Dispatches
    /// to the GLV core when `gate.glv_scalarmul_implemented`, else the plain
    /// interleaved double-and-add below.
    pub fn mulDoubleBasePublic(p1: Secp256k1, s1_: [32]u8, p2: Secp256k1, s2_: [32]u8, endian: std.builtin.Endian) IdentityElementError!Secp256k1 {
        if (comptime gate.glv_scalarmul_implemented) {
            return mulDoubleBaseGlv(p1, s1_, p2, s2_, endian);
        }
        return mulDoubleBasePublicDoubleAdd(p1, s1_, p2, s2_, endian);
    }

    /// Portable variable-time interleaved double-and-add for two bases (the
    /// GLV fallback + differential oracle). `pub` for the harness/bench.
    pub fn mulDoubleBasePublicDoubleAdd(p1: Secp256k1, s1_: [32]u8, p2: Secp256k1, s2_: [32]u8, endian: std.builtin.Endian) IdentityElementError!Secp256k1 {
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

// ── GLV helpers (VARIABLE-TIME — public scalars only) ───────────────────────

/// Odd-multiple table size for width-5 wNAF: {1,3,5,…,15}·P.
const glv_table_len = 8;
/// wNAF digit-string length: a 256-bit magnitude yields at most 257 digits.
const glv_wnaf_len = 257;

const GlvHalf = struct { mag: u256, negative: bool };

/// Reduce a raw 256-bit scalar mod `n` and split it into the two signed GLV
/// halves of `k ≡ r1 + r2·λ (mod n)`. Returns null when `k ≡ 0 (mod n)` (the
/// multiple is the identity). Reducing first is legal for any raw scalar
/// because the curve group has prime order `n` (`s·P = (s mod n)·P`) — the
/// portable double-and-add scans raw bits and agrees for the same reason.
fn splitToSignedHalves(s_raw: u256) ?[2]GlvHalf {
    const n = scalarmod.field_order;
    // 2^256 < 2n, so a single conditional subtract fully reduces.
    const s = if (s_raw >= n) s_raw - n else s_raw;
    if (s == 0) return null;
    var sb: [32]u8 = undefined;
    std.mem.writeInt(u256, &sb, s, .little);
    // s < n is canonical and every intermediate of the split is in range.
    const split = scalarmod.splitScalar(sb, .little) catch unreachable;
    return .{ glvHalf(split.r1), glvHalf(split.r2) };
}

/// Resolve one split residue to a signed magnitude. A residue with any high
/// bit set represents the negative `−(n − r)` (the balanced split guarantees
/// |r| ≈ √n, so the two cases are cleanly separated by bit 128). Either
/// interpretation is ≡ r (mod n), so correctness never depends on the
/// threshold — only the ~128-bit magnitude (and hence the halved doubling
/// count) does.
fn glvHalf(r_le: [32]u8) GlvHalf {
    const v = std.mem.readInt(u256, &r_le, .little);
    if ((v >> 128) != 0) return .{ .mag = scalarmod.field_order - v, .negative = true };
    return .{ .mag = v, .negative = false };
}

/// Width-5 wNAF digit string: nonzero digits are odd, in [−15, 15], at least
/// 4 zeros apart. The half's sign is folded into the digits.
fn wnafDigits(h: GlvHalf) [glv_wnaf_len]i8 {
    var e = [_]i8{0} ** glv_wnaf_len;
    var v = h.mag;
    var i: usize = 0;
    while (v != 0) : (i += 1) {
        if (@as(u1, @truncate(v)) == 1) {
            const w: i32 = @intCast(v & 31);
            const d: i32 = if (w >= 16) w - 32 else w;
            if (d >= 0) {
                v -= @as(u256, @intCast(d));
            } else {
                v += @as(u256, @intCast(-d));
            }
            e[i] = @intCast(if (h.negative) -d else d);
        }
        v >>= 1;
    }
    return e;
}

/// The odd multiples {1,3,…,15}·p (projective).
fn oddMultiples(p: Secp256k1) [glv_table_len]Secp256k1 {
    var tab: [glv_table_len]Secp256k1 = undefined;
    tab[0] = p;
    const p2 = p.dbl();
    var i: usize = 1;
    while (i < glv_table_len) : (i += 1) tab[i] = tab[i - 1].add(p2);
    return tab;
}

/// φ applied to a whole table: φ(X:Y:Z) = (β·X : Y : Z), and because φ is an
/// endomorphism, φ((2i+1)·p) = (2i+1)·φ(p) — one field mul per entry instead
/// of rebuilding the table from φ(p).
fn phiTable(tab: *const [glv_table_len]Secp256k1) [glv_table_len]Secp256k1 {
    const beta_fe = comptime (field.Fe.fromInt(scalarmod.beta) catch unreachable);
    var out: [glv_table_len]Secp256k1 = undefined;
    for (tab, &out) |t, *o| o.* = .{ .x = t.x.mul(beta_fe), .y = t.y, .z = t.z };
    return out;
}

/// Interleaved (Straus/Shamir) wNAF combine of `k` digit strings over `k`
/// odd-multiple tables: one shared doubling chain (its length = the highest
/// nonzero digit position, ~128 for the balanced halves), one point add or
/// sub per nonzero digit. `error.IdentityElement` if the result is neutral.
fn glvCombine(comptime k: usize, tabs: *const [k][glv_table_len]Secp256k1, es: *const [k][glv_wnaf_len]i8) IdentityElementError!Secp256k1 {
    // Number of digit positions up to the highest nonzero across all strings.
    var top: usize = 0;
    for (es) |e| {
        var i: usize = glv_wnaf_len;
        while (i > 0) {
            i -= 1;
            if (e[i] != 0) {
                if (i + 1 > top) top = i + 1;
                break;
            }
        }
    }
    var q = Secp256k1.identityElement;
    var i = top;
    while (i > 0) {
        i -= 1;
        q = q.dbl();
        inline for (0..k) |j| {
            const d: i32 = es[j][i];
            if (d > 0) {
                q = q.add(tabs[j][@intCast(@divExact(d - 1, 2))]);
            } else if (d < 0) {
                q = q.sub(tabs[j][@intCast(@divExact(-d - 1, 2))]);
            }
        }
    }
    try q.rejectIdentity();
    return q;
}

// ── fixed-base comb table (CONSTANT-TIME base-point multiply k·G) ────────────
//
// The signing path multiplies the FIXED base point G by a secret scalar twice
// per signature (the nonce commitment R = k·G and the pubkey P = d·G). A naive
// constant-time double-and-add pays 256 doublings + 256 conditional adds; the
// fixed-base **windowed comb** replaces that with a precomputed table so the
// online phase does NO doublings at all — just `comb_t` point additions, one
// per signed digit, gathered constant-time from the table (the technique behind
// libsecp256k1's `ecmult_gen`).
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
/// sign out, halving the table).
const comb_teeth: usize = 1 << (comb_w - 1); // 8
/// Number of windows: 256/w low windows plus one to absorb the recoding carry.
const comb_t: usize = (256 / comb_w) + 1; // 65

/// The precomputed comb table type: `[window][magnitude−1]` projective points.
pub const CombTable = [comb_t][comb_teeth]Secp256k1;

/// Build the comb table at comptime. `tab[i][j] = (j+1)·2^(w·i)·G`, projective.
fn buildCombTable() CombTable {
    @setEvalBranchQuota(100_000_000);
    var tab: CombTable = undefined;
    var base = Secp256k1.basePoint; // 2^(w·i)·G, starting at G
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

/// The fixed-base comb table for G (public constant; see `combMulBase`).
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
    for (&dst._limbs, src._limbs) |*d, s| d.* = (s & mask) | (d.* & ~mask);
}

/// A point in affine coordinates.
pub const AffineCoordinates = struct {
    x: field.Fe,
    y: field.Fe,

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
    const beta = field.Fe.fromInt(scalarmod.beta) catch unreachable;
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
        const kx = field.Fe.fromBytes(xb, .big) catch continue;
        const sx = Std.Fe.fromBytes(xb, .big) catch unreachable;
        if (Std.recoverY(sx, false)) |sy| {
            const ky = try Secp256k1.recoverY(kx, false);
            try std.testing.expectEqualSlices(u8, &sy.toBytes(.big), &ky.toBytes(.big));
        } else |_| {
            try std.testing.expectError(error.NotSquare, Secp256k1.recoverY(kx, false));
        }
    }
}

// ── fuzz: fromSec1 never panics on arbitrary attacker-supplied encodings ──
//
// The SEC1 point decoder underneath `ecdsaVerify`'s `pubkey_sec1` and every
// Bitcoin/secp256k1 public-key input this repo will ever parse. Same shape
// as `p256`'s equivalent harness: bias the tag byte toward each of the three
// valid encodings (identity/compressed/uncompressed) plus fully random
// bytes for the invalid-tag/short-input path.

/// ⛔ A secp256k1 point in the form `fromSec1` accepts is not reachable from
/// arbitrary bytes — the x-coordinate has to have a square `y` — so the
/// accepted frames come from the module's own `toCompressedSec1` /
/// `toUncompressedSec1`. Each seed is the encoding as a `testkit.fuzz` slice
/// seed followed by the `u64` word the tag knob after it reads; without that
/// word the knob is dead on a corpus replay and would rewrite `buf[0]` to 0 on
/// every seed, turning each of them into the identity encoding.
const Sec1Corpus = struct {
    store: [11 * (4 + 65 + 16)]u8 = undefined,
    used: usize = 0,
    entries: [11][]const u8 = undefined,
    n: usize = 0,

    /// `tag`: 0..3 rewrite `buf[0]` to `0`/`2`/`3`/`4`, 4 draws an arbitrary
    /// octet, 5 leaves the frame alone.
    fn push(self: *Sec1Corpus, frame: []const u8, tag: u64) void {
        self.pushWith(frame, tag, null);
    }

    /// ⛔ `tag == 4` opens a SECOND knob — `smith.value(u8)`, which decides
    /// the arbitrary octet `buf[0]` becomes — and a seed that stops after the
    /// tag word leaves it reading an exhausted input, i.e. the range minimum,
    /// i.e. `0x00`. Measured 2026-09-08: the seed labelled "an arbitrary tag
    /// octet" produced `0x00` on every replay, indistinguishable from the
    /// `tag == 0` seed beside it, while the guard below still recorded the
    /// branch as taken. `octet` is the word that knob reads.
    fn pushWith(self: *Sec1Corpus, frame: []const u8, tag: u64, octet: ?u64) void {
        const start = self.used;
        var at = start + fuzzSeedIntoLocal(self.store[start..], frame).len;
        std.mem.writeInt(u64, self.store[at..][0..8], tag, .little);
        at += 8;
        if (octet) |o| {
            std.mem.writeInt(u64, self.store[at..][0..8], o, .little);
            at += 8;
        }
        self.entries[self.n] = self.store[start..at];
        self.used = at;
        self.n += 1;
    }

    fn build(self: *Sec1Corpus) []const []const u8 {
        const g = Secp256k1.basePoint;
        const g2 = g.dbl();
        const comp = g.toCompressedSec1();
        const uncomp = g.toUncompressedSec1();
        self.push(&comp, 5); // 02/03 ‖ x — the base point, untouched
        self.push(&uncomp, 5); // 04 ‖ x ‖ y
        self.push(&g2.toCompressedSec1(), 5); // 2·G, a DIFFERENT point
        self.push(&[_]u8{0}, 5); // the one-octet identity encoding
        // The tag rewritten to each of the four valid values over a body that
        // does not match it — the disagreement path.
        self.push(&uncomp, 1); // 04-length body relabelled compressed
        self.push(&comp, 3); // 33-octet body relabelled uncompressed
        var bad_x = comp;
        bad_x[1] ^= 0x01; // an x with no square y: `recoverY` must refuse
        self.push(&bad_x, 5);
        self.push(comp[0..16], 5); // truncated mid-x
        self.pushWith(&uncomp, 4, 0x99); // an arbitrary tag octet, really drawn
        self.pushWith(&comp, 4, 0x02); // ...and one that lands back on a VALID
        // tag over a body that matches it: the arbitrary-octet branch is not
        // only a refusal path
        self.push("", 5); // and the input this target used to run for ever
        return self.entries[0..self.n];
    }
};

test "fuzz: fromSec1 never panics on arbitrary bytes" {
    var corpus: Sec1Corpus = .{};
    try std.testing.fuzz({}, fuzzFromSec1, .{ .corpus = corpus.build() });
}

fn fuzzFromSec1(_: void, smith: *std.testing.Smith) !void {
    // ⚠ One `smith.slice` call, never `bytes` followed by a ranged length: the
    // latter drew `len == 0` on every input this target ever ran outside
    // `--fuzz` (a ranged draw needs eight octets and `bytes` had eaten them),
    // so `fromSec1` was handed a zero-length slice every round and returned
    // `InvalidEncoding` off its length check with the point unread in `buf`.
    var buf: [65]u8 = undefined;
    const len: usize = smith.slice(&buf);
    if (len != 0) buf[0] = switch (smith.valueRangeAtMost(u8, 0, 5)) {
        0 => 0,
        1 => 2,
        2 => 3,
        3 => 4,
        4 => smith.value(u8),
        // Leave the frame's own tag alone — what a seeded real encoding needs.
        else => buf[0],
    };
    _ = Secp256k1.fromSec1(buf[0..len]) catch {};
}

fn distinctOctets(flags: []const bool) usize {
    var n: usize = 0;
    for (flags) |f| {
        if (f) n += 1;
    }
    return n;
}

test "corpus: every SEC1 seed reaches the decoder, and the counts are pinned" {
    var corpus: Sec1Corpus = .{};
    var nonempty: usize = 0;
    var accepted: usize = 0;
    // ⛔ The number the collapsed draw could not produce, and that
    // `accepted > 0` could not have held up: DISTINCT points decoded. The
    // one-octet identity encoding is legal and decodes while carrying no
    // coordinate at all, so acceptance alone says nothing about reach.
    var seen: [4][33]u8 = undefined;
    var distinct: usize = 0;
    var tags_seen: [6]bool = @splat(false);
    var octets: [256]bool = @splat(false);
    for (corpus.build()) |sd| {
        var smith: std.testing.Smith = .{ .in = sd };
        var buf: [65]u8 = undefined;
        const len: usize = smith.slice(&buf);
        if (len != 0) nonempty += 1;
        if (len != 0) {
            const which = smith.valueRangeAtMost(u8, 0, 5);
            tags_seen[which] = true;
            buf[0] = switch (which) {
                0 => 0,
                1 => 2,
                2 => 3,
                3 => 4,
                4 => smith.value(u8),
                else => buf[0],
            };
            if (which == 4) octets[buf[0]] = true;
        }
        const p = Secp256k1.fromSec1(buf[0..len]) catch continue;
        accepted += 1;
        const enc = p.toCompressedSec1();
        var already = false;
        for (seen[0..distinct]) |prev| {
            if (std.mem.eql(u8, &prev, &enc)) already = true;
        }
        if (!already) {
            seen[distinct] = enc;
            distinct += 1;
        }
    }
    try std.testing.expectEqual(corpus.n - 1, nonempty); // all but the empty seed
    try std.testing.expectEqual(@as(usize, 5), accepted);
    try std.testing.expectEqual(@as(usize, 3), distinct);
    // The tag knob is alive on a corpus replay, not pinned at 0.
    try std.testing.expectEqual(true, tags_seen[1]);
    try std.testing.expectEqual(true, tags_seen[3]);
    try std.testing.expectEqual(true, tags_seen[4]);
    try std.testing.expectEqual(true, tags_seen[5]);
    // ⛔ And the SECOND knob, behind `which == 4`. `tags_seen[4]` above says
    // the branch was TAKEN; it says nothing about what the branch drew, and
    // until 2026-09-08 the answer was `0x00` on every seed because no seed
    // carried the word `smith.value(u8)` reads. Distinct octets actually
    // written into `buf[0]` is the number that notices.
    try std.testing.expectEqual(@as(usize, 2), distinctOctets(&octets)); // 0x99 and 0x02

    // The "before" state, executable rather than asserted in prose: a seed
    // that stops after the tag word leaves `smith.value(u8)` reading an
    // exhausted input, and a `Smith` scalar draw over one returns its range
    // minimum. So the "arbitrary tag octet" seed drew 0x00 — 1 distinct
    // octet, and the same rewrite the `tag == 0` seed beside it performs.
    var before: Sec1Corpus = .{};
    const g_uncomp = Secp256k1.basePoint.toUncompressedSec1();
    before.push(&g_uncomp, 4);
    var bsmith: std.testing.Smith = .{ .in = before.entries[0] };
    var bbuf: [65]u8 = undefined;
    try std.testing.expectEqual(@as(u32, 65), bsmith.slice(&bbuf));
    try std.testing.expectEqual(@as(u8, 4), bsmith.valueRangeAtMost(u8, 0, 5));
    try std.testing.expectEqual(@as(u8, 0), bsmith.value(u8));
}

/// ⛔ A LOCAL COPY of `testkit.fuzz.seedInto`, and it has to be one. Enrolling this
/// module in `test_deps` puts it into `zig build check-testonly`, whose probe
/// imports the PUBLISHED module and references every declaration three levels
/// deep. That reaches `std.crypto.pcurves`'s secp256k1 scalar `sqrt`, which is a
/// `@compileError("unimplemented")` because the group order is 1 mod 4 — so the
/// probe cannot compile, through no fault of this module. Two of this
/// repository's own gates contradict each other for any module with a
/// declaration that refuses to be referenced outside a test build.
///
/// The anchor test below is what stops this copy drifting from
/// `modules/testkit/src/fuzz.zig`: it drives the real `std.testing.Smith` over
/// what this produces, exactly as testkit's own tests do.
fn fuzzSeedIntoLocal(out: []u8, frame: []const u8) []const u8 {
    std.debug.assert(out.len >= 4 + frame.len);
    std.mem.writeInt(u32, out[0..4], @intCast(frame.len), .little);
    @memcpy(out[4..][0..frame.len], frame);
    return out[0 .. 4 + frame.len];
}

test "the local seedInto helper produces what Smith.slice reads back" {
    var storage: [32]u8 = undefined;
    const s = fuzzSeedIntoLocal(&storage, "abcdef");
    var smith: std.testing.Smith = .{ .in = s };
    var buf: [32]u8 = undefined;
    const n = smith.slice(&buf);
    try std.testing.expectEqualStrings("abcdef", buf[0..n]);
}
