// SPDX-License-Identifier: MIT

//! element — the decaf448 group element (RFC 9496 §5), its wire codec, and
//! the four irreducible field-math cores the scaffold pass left
//! `@panic`-stubbed and a Fable pass then implemented: `sqrtRatioM1`
//! (§5.2), `Element.encode` (§5.3.2), `Element.decode` (§5.3.1), and
//! `mapToElement` (§5.3.4's inner "MAP" primitive, backing the REAL
//! `oneWayMap` orchestration below — see that function's own doc comment
//! for why the split is drawn there).
//! See `gate.zig` for what stays real vs. gated when `core_implemented ==
//! false` (now `true`), and `sqrt_ratio_m1` below for why decaf448's variant of this
//! function needs no `-1`-twist constant at all (unlike ristretto255's,
//! which `std.crypto.ecc.Ristretto255.sqrtRatioM1` — this module's best
//! structural reference — must fold in via `Fe.sqrtm1`).
//!
//! ## Internal representation: `ed448.ed448.Point`, no extra `t` field
//!
//! RFC 9496 §2 represents every decaf448/ristretto255 internal point in
//! FOUR-coordinate extended Edwards form `(x, y, z, t)` with `t = x*y/z`
//! (`[Twisted]`'s "extended homogeneous coordinates", the same shape
//! `std.crypto.ecc.Edwards25519` stores natively). `ed448.ed448.Point`
//! does NOT carry a `t` field — edwards448 is UNTWISTED (`a = 1`), so its
//! complete addition/doubling formulas (RFC 8032 §5.2.4, transcribed
//! in `ed448.zig`) never need one (see that module's own doc comment).
//! This module deliberately does NOT add a fourth coordinate to `Element`
//! either: every one of THIS module's own mechanical group operations
//! below (`add`/`sub`/`negate`/`scalarMul`, `identity`/`generator`) only
//! ever calls `Point`'s already-real `add`/`dbl`/`neg`/`mul`, none of
//! which touch `t` — and `Element.equals` (§5.3.3) needs only `x`/`y`
//! (see that function's own doc comment for why the formula is
//! `z`-scale-invariant without ever reading `z`). The ONLY RFC formulas
//! that reference `t0`/`z0` together (`encode`, and `decode`'s own
//! construction of `t` from scratch) are exactly the four Fable cores
//! below; `encode` derives `t0 = x0*y0*z0^-1` (one inversion) from
//! `Element.p`'s three stored coordinates, since none of the mechanical
//! group ops maintain it incrementally.
//!
//! ## Provenance
//!
//! Clean-room from RFC 9496 §5 (decaf448) + §5.1's implementation
//! constants; `std.crypto.ecc.Ristretto255` (this module's sibling
//! construction, one field down) consulted as a STRUCTURAL reference for
//! how a decaf/ristretto group wraps a curve point and shapes its
//! encode/decode/equals/derivation API — no source copied, decaf448
//! differs from ristretto255 in its constants, its curve, AND (per RFC
//! 9496 §5.2 vs §4.2) its simpler `p ≡ 3 (mod 4)` `SQRT_RATIO_M1` (no
//! `sqrt(-1)`-twist branch at all, unlike Curve25519's `p ≡ 5 (mod 8)`
//! case). See `../SPEC.md` for the full design note and `../NOTICE`
//! policy §0 (this is pure clean-room-from-spec; the RFC citation lives
//! here and in SPEC.md, not in the repo's root NOTICE — see that file's
//! own policy header for when an entry is/isn't required).

const std = @import("std");
const ed448 = @import("ed448");
const scalar = @import("scalar.zig");

const field = ed448.field;
const Fe = field.Fe;
const Point = ed448.ed448.Point;

// ── RFC 9496 §5.1 implementation constants ─────────────────────────────
//
// All five are PLAIN NUMBERS the RFC states outright (not derived by any
// square-root computation of this module's own), so declaring them needs
// no Fable core — only `SQRT_MINUS_D`/`INVSQRT_MINUS_D`'s DEFINING
// relations (checked by the tests below) depend on square-root math, and
// that math was done once, offline, to produce the RFC's own published
// constants — this module merely transcribes and re-verifies them.

/// Build a small (`< 2^32`) non-negative integer as a canonical `Fe`.
/// REAL: pure byte layout, no field arithmetic — `ONE_MINUS_D`/
/// `ONE_MINUS_TWO_D` below are both `< 2^17`, comfortably `< p`.
fn smallFe(comptime n: u32) Fe {
    var bytes = [_]u8{0} ** field.encoded_bytes;
    bytes[0] = @truncate(n);
    bytes[1] = @truncate(n >> 8);
    bytes[2] = @truncate(n >> 16);
    bytes[3] = @truncate(n >> 24);
    return Fe.fromBytes(bytes) catch unreachable;
}

fn hexBytes(comptime n: usize, comptime hex: *const [2 * n:0]u8) [n]u8 {
    @setEvalBranchQuota(100_000);
    var out: [n]u8 = undefined;
    _ = std.fmt.hexToBytes(&out, hex) catch unreachable;
    return out;
}

/// `D` — the edwards448 `d` parameter (RFC 7748 §4.2: `-39081`), reused
/// directly from `ed448.ed448.d` (bit-identical constant — cross-checked
/// by the "D matches ed448.ed448.d" test below); RFC 9496 §5.1 restates
/// it under this name purely for decaf448's own formulas to reference.
pub const D: Fe = ed448.ed448.d;
/// `ONE_MINUS_D = 39082` (RFC 9496 §5.1).
pub const ONE_MINUS_D: Fe = smallFe(39082);
/// `ONE_MINUS_TWO_D = 78163` (RFC 9496 §5.1).
pub const ONE_MINUS_TWO_D: Fe = smallFe(78163);
/// `SQRT_MINUS_D = sqrt(-D) mod p` (RFC 9496 §5.1's full decimal value,
/// transcribed to little-endian bytes and independently re-verified by
/// the "SQRT_MINUS_D^2 == -D" test below — see `NOTICE`'s "Verification
/// performed" convention, mirrored here in-file since this module has no
/// NOTICE entry of its own, see the module doc comment's Provenance
/// note).
pub const SQRT_MINUS_D: Fe = Fe.fromBytes(hexBytes(field.encoded_bytes, "362757450fef429652ce20aaf67b3360d2de6efdf4669a83ba148c9680d7a2644bd5b8a5b8a7f1a1a06aa22f728df63b68f724ebfb62d922")) catch
    @compileError("decaf448: malformed SQRT_MINUS_D constant bytes");
/// `INVSQRT_MINUS_D = 1/sqrt(-D) mod p` (RFC 9496 §5.1's full decimal
/// value); re-verified against `SQRT_MINUS_D` by the tests below.
pub const INVSQRT_MINUS_D: Fe = Fe.fromBytes(hexBytes(field.encoded_bytes, "2c6878b85ebbaf53f3949ef17924bbef15ba1fc2e27e70be1a52a628f156bad6a7275b3a0c95905a07c8ca0b5ae32b9057c022e25206f46e")) catch
    @compileError("decaf448: malformed INVSQRT_MINUS_D constant bytes");

// ── RFC 9496 §2.1/§2.2 primitives already real on `Fe` ─────────────────
//
// `field.zig`'s `Fe.isOdd` IS `IS_NEGATIVE` (RFC 9496 §2.1: "given a field
// element e, define IS_NEGATIVE(e) as TRUE if the least nonnegative
// integer representing e is odd" — `Fe.isOdd`'s own doc comment defines
// it identically, parity of the canonical little-endian representative).
// `Fe.eql` is `CT_EQ`. `Fe.ctSelect` is `CT_SELECT`. Only `CT_ABS` has no
// existing `Fe` method; it is trivial to build from the other three
// (REAL, not a Fable core — the RFC's own §2.2 note spells out exactly
// this construction: "CT_ABS MAY be implemented as: CT_SELECT(-u IF
// IS_NEGATIVE(u) ELSE u)").
fn ctAbs(u: Fe) Fe {
    return Fe.ctSelect(u.isOdd(), u.neg(), u);
}

/// `(p-3)/4 = 2^446 - 2^222 - 1`, big-endian, 56 bytes — `sqrtRatioM1`'s
/// fixed public exponent (RFC 9496 §5.2: "(p - 3) / 4 is an integer" for
/// decaf448's `p ≡ 3 (mod 4)`). Exactly `field.zig`'s `(p+1)/4`
/// square-root exponent minus one (`...c0 00...00` -> `...bf ff...ff`),
/// declared here (not in `field.zig`) because it is decaf-specific —
/// see `sqrtRatioM1`'s doc comment.
const sqrt_ratio_exponent_be: [field.encoded_bytes]u8 = hexBytes(field.encoded_bytes, "3fffffffffffffffffffffffffffffffffffffffffffffffffffffffbfffffffffffffffffffffffffffffffffffffffffffffffffffffff");

/// Result of `sqrtRatioM1` — RFC 9496 §5.2's `(was_square, r)` pair.
pub const SqrtRatioResult = struct {
    was_square: bool,
    root: Fe,
};

/// `SQRT_RATIO_M1(u, v)` (RFC 9496 §5.2) — THE FABLE CORE every one of
/// `encode`/`decode`/`mapToElement` below is built on. On field elements
/// `u`, `v`, returns:
///   - `(TRUE, +sqrt(u/v))` if `u`, `v` nonzero and `u/v` is square;
///   - `(TRUE, zero)` if `u` is zero;
///   - `(FALSE, zero)` if `v` is zero and `u` is nonzero; and
///   - `(FALSE, +sqrt(-u/v))` if `u`, `v` nonzero and `u/v` is
///     NON-square (so `-(u/v)` IS square) —
/// where `+sqrt(x)` is the NONNEGATIVE (per `IS_NEGATIVE`/`Fe.isOdd`)
/// square root. NOTE the name is inherited from ristretto255's
/// `SQRT_RATIO_M1` (RFC 9496 §4.2, which folds in a `sqrt(-1)` twist
/// because Curve25519's `p ≡ 5 (mod 8)`) purely for cross-document
/// symmetry — decaf448's OWN `p = 2^448 - 2^224 - 1 ≡ 3 (mod 4)` (see
/// `ed448.field`'s own "p is 448 bits, odd, and ≡ 3 (mod 4)" test) needs
/// NO twist constant at all; RFC 9496 §5.2 gives the p≡3(mod 4) formula
/// directly:
///
/// ```text
/// r = u * (u * v)^((p - 3) / 4)   // (p-3)/4 is an integer since p ≡ 3 (mod 4)
/// check = v * r^2
/// was_square = CT_EQ(check, u)
/// r = CT_ABS(r)                   // ctAbs, above — already real
/// return (was_square, r)
/// ```
///
/// This is a close cousin of `ed448.field.Fe.sqrt`'s own `p ≡ 3 (mod 4)`
/// candidate-and-verify recipe (`a^((p+1)/4)`, verify by squaring) but is
/// NOT a mechanical rewrite of it: `Fe.sqrt` returns `?Fe` (null on a
/// non-residue), whereas this function must additionally return a
/// WELL-DEFINED root (`+sqrt(-u/v)`, not null/garbage) on the non-square
/// branch — `encode`/`decode`'s own formulas rely on that defined
/// relationship to stay branch-count-constant and never `null`-propagate.
/// Fixed exponent `(p-3)/4` is a new comptime constant this core must add
/// (analogous to `field.zig`'s own `sqrt_exponent_be = (p+1)/4`), NOT a
/// re-use of `field.zig`'s existing `(p+1)/4` exponent.
pub fn sqrtRatioM1(u: Fe, v: Fe) SqrtRatioResult {
    // RFC 9496 §5.2 (decaf448, p ≡ 3 (mod 4)):
    //   r = u * (u * v)^((p - 3) / 4)
    // Edge cases fall out of the formula itself, no special-casing:
    // u == 0 -> r = 0, check = 0 == u -> (TRUE, 0); v == 0, u != 0 ->
    // (u*v)^e = 0 -> r = 0, check = 0 != u -> (FALSE, 0). Constant-time:
    // `pow` is CT in the base (and exponent), `eql`/`ctAbs` are CT.
    const r0 = u.mul(u.mul(v).pow(sqrt_ratio_exponent_be));
    const check = v.mul(r0.square());
    const was_square = check.eql(u);
    return .{ .was_square = was_square, .root = ctAbs(r0) };
}

/// A decaf448 group element (RFC 9496 §5's abstract element, opaque to
/// callers per §6's API guidance — the two fields below are `pub` only
/// because Zig has no module-private-but-sibling-file-visible mechanism;
/// `kat_test.zig`/callers outside this file should treat `Element` as
/// opaque and go through the named operations, never construct/inspect
/// `.p` directly). Internally an `ed448.ed448.Point` — see the module doc
/// comment's "Internal representation" section for why no extra `t`
/// coordinate is stored.
pub const Element = struct {
    p: Point,

    /// The group identity (RFC 9496 §5.3's `B[0]` in the multiples-of-
    /// generator test vectors — encodes to 56 zero bytes per Appendix
    /// B.1, asserted byte-exact by `kat_test.zig`'s now-ungated suite).
    pub const identity: Element = .{ .p = Point.identityElement };

    /// The canonical decaf448 generator (RFC 9496 §5: "this generator can
    /// be internally represented by `2*B`, where `B` is the edwards448
    /// base point, enabling reuse of existing precomputation for scalar
    /// multiplication" — REAL, `ed448.ed448.Point.basePoint.dbl()` is
    /// already-implemented curve arithmetic; evaluated at comptime, hence
    /// the raised branch quota — a single `Fe`-level point doubling
    /// unrolls past the default 1000-branch comptime budget).
    pub const generator: Element = blk: {
        @setEvalBranchQuota(1_000_000);
        break :blk .{ .p = Point.basePoint.dbl() };
    };

    /// Group addition (RFC 9496 §3: "Element addition ... [is]
    /// implemented by applying the corresponding operation[] directly to
    /// the internal representation" — §5's opening paragraph, restated
    /// for decaf448 specifically). REAL: pure delegation to `ed448`'s
    /// already-real, already-KAT-validated `Point.add`.
    pub fn add(a: Element, b: Element) Element {
        return .{ .p = a.p.add(b.p) };
    }

    /// Group subtraction: "the addition of a negated element" (RFC 9496
    /// §3). REAL: `add` + `negate`, both already real.
    pub fn sub(a: Element, b: Element) Element {
        return .{ .p = a.p.add(b.p.neg()) };
    }

    /// Group negation: "returns an element that, when added to the
    /// negation input, gives the identity element" (RFC 9496 §3). REAL:
    /// pure delegation to `Point.neg` (edwards curve negation, `(-x, y)`
    /// — already real and, since decaf448's internal representation is a
    /// plain edwards448 point, correct for the WRAPPING group too: RFC
    /// 9496 §3 defines decaf negation as applying the curve operation
    /// directly to the internal representation, with no decaf-specific
    /// adjustment needed).
    pub fn negate(a: Element) Element {
        return .{ .p = a.p.neg() };
    }

    /// Scalar multiplication (RFC 9496 §3: "repeated addition of an
    /// element"). REAL: converts decaf448's 56-byte `scalar.
    /// CompressedScalar` to `ed448.scalar`'s 57-byte width (`scalar.
    /// toEd448` — pure zero-pad, see `scalar.zig`) and delegates to
    /// `Point.mul`, which is a constant-time 4-bit fixed window (a masked
    /// 16-entry table scan per nibble; it stopped being a double-and-add
    /// when ed448 F1 landed). Unlike `std.crypto.ecc.Edwards25519.mul`,
    /// which ends in a `rejectIdentity` branch on a scalar-derived value
    /// and so cannot be handed a secret scalar without leaking whether it
    /// was zero, `Point.mul` returns a `Point` — no rejection, no error
    /// union, nothing for a caller to branch on. Confirmed by measurement,
    /// not by reading: a ctgrind-style run with the scalar marked
    /// `MAKE_MEM_UNDEFINED` reports 0 memcheck errors through this
    /// function, and re-introducing a `if (nibble != 0)` table lookup in
    /// `Point.mul` makes the same run report 860.
    pub fn scalarMul(a: Element, s: scalar.CompressedScalar) Element {
        return .{ .p = Point.mul(a.p, scalar.toEd448(s)) };
    }

    /// Group equality (RFC 9496 §5.3.3): for internal representations
    /// `(x1,y1,z1,t1)`/`(x2,y2,z2,t2)`, `CT_EQ(x1*y2, y1*x2)`. Unlike
    /// `ed448.ed448.Point.equivalent` (which checks SAME-CURVE-POINT
    /// equality, `x1*z2==x2*z1 AND y1*z2==y2*z1` — a STRICTER relation),
    /// this checks decaf GROUP equality (same coset of the curve's
    /// 4-torsion subgroup) and needs only `x`/`y`, no `z`/`t` at all.
    /// REAL: this IS the mechanical formula RFC 9496 hands us directly —
    /// no Fable core needed (task guidance: "just uses field mul +
    /// equality"). Scale-invariance argument (why `z1`/`z2` need not be
    /// normalized first): writing `x_i = z_i * x_i_affine`, `y_i = z_i *
    /// y_i_affine`, `x1*y2 = z1*z2*(x1_affine*y2_affine)` and `y1*x2 =
    /// z1*z2*(y1_affine*x2_affine)` share the identical `z1*z2` factor,
    /// so the equality is independent of both `z`s' magnitudes whenever
    /// they are nonzero (always true for a valid point) — this is the
    /// SAME cross-multiplication trick `Point.equivalent`'s own doc
    /// comment uses for its stricter check, one level down.
    pub fn equals(a: Element, b: Element) bool {
        return a.p.x.mul(b.p.y).eql(b.p.x.mul(a.p.y));
    }

    /// Wire width of an encoded element (RFC 9496 §5.3.1: "All elements
    /// are encoded as 56-byte strings").
    pub const encoded_length = 56;
    pub const EncodedBytes = [encoded_length]u8;

    /// Encode (RFC 9496 §5.3.2) — THE FABLE CORE. Given an internal
    /// representation `(x0, y0, z0, t0)` (this module's `Element.p` only
    /// stores `x0`/`y0`/`z0` — see the module doc comment's "Internal
    /// representation" section; a full implementation's FIRST step must
    /// derive `t0 = x0*y0*z0^-1 mod p` via `Fe.invert`, one inversion,
    /// since none of the mechanical group ops above maintain `t`
    /// incrementally):
    ///
    /// ```text
    /// u1 = (x0 + t0) * (x0 - t0)
    /// (_, invsqrt) = SQRT_RATIO_M1(1, u1 * ONE_MINUS_D * x0^2)   // always square
    /// ratio = CT_ABS(invsqrt * u1 * SQRT_MINUS_D)
    /// u2 = INVSQRT_MINUS_D * ratio * z0 - t0
    /// s = CT_ABS(ONE_MINUS_D * invsqrt * x0 * u2)
    /// return the 56-byte little-endian encoding of s
    ///        (canonical representative, 0 <= s < p)
    /// ```
    ///
    /// Never fails (unlike `decode`) — the RFC's own note: "Ignore
    /// was_square since this is always square" for a valid internal
    /// representation. "Decoding and then re-encoding a valid group
    /// element will yield an identical byte string" (RFC 9496 §5.3.2) —
    /// the round-trip property `kat_test.zig`'s gated suite checks.
    pub fn encode(e: Element) EncodedBytes {
        const x0 = e.p.x;
        const y0 = e.p.y;
        const z0 = e.p.z;
        // Derive t0 = x0*y0*z0^-1 — the one inversion the module doc
        // comment's "Internal representation" section budgets for. z0 is
        // never zero for a valid internal representation (identity is
        // (0, z, z)), so the error arm is unreachable in practice; Fe.zero
        // is a safe defensive fallback (no UB path, unlike `unreachable`).
        const z_inv = z0.invert() catch Fe.zero;
        const t0 = x0.mul(y0).mul(z_inv);

        // RFC 9496 §5.3.2. Local names carry a trailing underscore only
        // because `u1`/`u2` are Zig primitive integer type names.
        const uu1 = x0.add(t0).mul(x0.sub(t0));
        // "Ignore was_square since this is always square" (RFC 9496
        // §5.3.2) — for the identity (u1 == 0, x0 == 0) sqrtRatioM1
        // returns (FALSE, 0) and the formula still yields s = 0, the
        // correct all-zero encoding.
        const invsqrt = sqrtRatioM1(Fe.one, uu1.mul(ONE_MINUS_D).mul(x0.square())).root;
        const ratio = ctAbs(invsqrt.mul(uu1).mul(SQRT_MINUS_D));
        const uu2 = INVSQRT_MINUS_D.mul(ratio).mul(z0).sub(t0);
        const s = ctAbs(ONE_MINUS_D.mul(invsqrt).mul(x0).mul(uu2));
        return s.toBytes();
    }

    pub const DecodeError = error{ NonCanonical, InvalidEncoding };

    /// Decode (RFC 9496 §5.3.1) — THE FABLE CORE:
    ///
    /// 1. Interpret `bytes` as an unsigned little-endian integer `s`. If
    ///    `s >= p`, fail (`error.NonCanonical` — UNLIKE RFC 7748's field
    ///    decode, RFC 9496 explicitly REJECTS non-canonical values here;
    ///    Appendix B.2's "Non-canonical field encodings" vectors exercise
    ///    this).
    /// 2. If `IS_NEGATIVE(s)` (`Fe.isOdd`) is TRUE, fail (`error.
    ///    InvalidEncoding` — Appendix B.2's "Negative field elements"
    ///    vectors).
    /// 3. Compute:
    ///    ```text
    ///    ss = s^2
    ///    u1 = 1 + ss
    ///    u2 = u1^2 - 4*D*ss
    ///    (was_square, invsqrt) = SQRT_RATIO_M1(1, u2 * u1^2)
    ///    u3 = CT_ABS(2*s*invsqrt*u1*SQRT_MINUS_D)
    ///    x = u3 * invsqrt * u2 * INVSQRT_MINUS_D
    ///    y = (1 - ss) * invsqrt * u1
    ///    t = x * y
    ///    ```
    /// 4. If `was_square` is FALSE, fail (`error.InvalidEncoding` —
    ///    Appendix B.2's "Non-square x^2" vectors). Otherwise return the
    ///    internal representation `(x, y, 1, t)` — note `z0 = 1` here,
    ///    so a freshly-decoded `Element` needs NO inversion for `encode`
    ///    to later recover `t0` (it already has it, though this module's
    ///    `Element.p` still only stores `x`/`y`/`z` — see the module doc
    ///    comment).
    pub fn decode(bytes: EncodedBytes) DecodeError!Element {
        // Steps 1+2: reject non-canonical (s >= p), then negative s.
        // These reject paths branch on PUBLIC validity of wire bytes
        // (this function's doc contract), not on any secret.
        const s = Fe.fromBytes(bytes) catch return error.NonCanonical;
        if (s.isOdd()) return error.InvalidEncoding;

        // Step 3 (RFC 9496 §5.3.1). Trailing underscores: `u1`/`u2`/`u3`
        // are Zig primitive integer type names.
        const ss = s.square();
        const uu1 = Fe.one.add(ss);
        const d_ss = D.mul(ss);
        const four_d_ss = d_ss.add(d_ss).add(d_ss).add(d_ss);
        const uu2 = uu1.square().sub(four_d_ss);
        const sr = sqrtRatioM1(Fe.one, uu2.mul(uu1.square()));
        const invsqrt = sr.root;
        const uu3 = ctAbs(s.add(s).mul(invsqrt).mul(uu1).mul(SQRT_MINUS_D));
        const x = uu3.mul(invsqrt).mul(uu2).mul(INVSQRT_MINUS_D);
        const y = Fe.one.sub(ss).mul(invsqrt).mul(uu1);

        // Step 4: non-square u2*u1^2 -> not a valid encoding. z = 1, and
        // t = x*y is directly available but not stored (module doc
        // comment's "Internal representation" section).
        if (!sr.was_square) return error.InvalidEncoding;
        return .{ .p = .{ .x = x, .y = y, .z = Fe.one } };
    }

    /// Byte-exact wire codec round-trip helpers over the now-real
    /// `encode`/`decode` — kept here (not in `kat_test.zig`) as the one
    /// obvious place callers look for the codec entry points.
    pub fn toBytes(e: Element) EncodedBytes {
        return encode(e);
    }
    pub fn fromBytes(bytes: EncodedBytes) DecodeError!Element {
        return decode(bytes);
    }
};

/// Element derivation / hash-to-group (RFC 9496 §5.3.4) — REAL
/// orchestration: "Compute P1 as MAP(b[0:56]). Compute P2 as
/// MAP(b[56:112]). Return P1 + P2." The split-and-add shape needs no
/// field-math core of its own (`Element.add` is already real); ONLY the
/// inner `mapToElement` (this file's private `MAP`) is the Fable core —
/// see that function's own doc comment. `kat_test.zig` exercises this
/// from behind `gate.core_implemented` (now `true`), per the scaffold
/// convention that gated tests guard the once-stubbed cores. Note:
/// decaf448's derivation function takes
/// ALREADY-UNIFORM 112-byte input — no hash function inside; a caller
/// wanting `hash_to_decaf448` (RFC 9380 Appendix C) supplies its own
/// domain-separated expand-message step before calling this, out of
/// scope for this module (RFC 9496 §5.3.4's own note).
pub fn oneWayMap(b: [112]u8) Element {
    const p1 = mapToElement(b[0..56].*);
    const p2 = mapToElement(b[56..112].*);
    return p1.add(p2);
}

/// `MAP` (RFC 9496 §5.3.4, the inner per-56-byte-half primitive) — THE
/// FABLE CORE `oneWayMap` is built on:
///
/// 1. Interpret `bytes` as a little-endian unsigned integer `r_raw`;
///    reduce modulo `p` to obtain field element `t` (non-canonical input
///    IS accepted here, unlike `Element.decode` — RFC 9496's own note:
///    "unlike the field element decoding described in Section 5.3.1,
///    non-canonical values are accepted").
/// 2. Compute:
///    ```text
///    r = -t^2
///    u0 = D * (r - 1)
///    u1 = (u0 + 1) * (u0 - r)
///    (was_square, v) = SQRT_RATIO_M1(ONE_MINUS_TWO_D, (r + 1) * u1)
///    v_prime = CT_SELECT(v IF was_square ELSE t * v)
///    sgn     = CT_SELECT(1 IF was_square ELSE -1)
///    s = v_prime * (r + 1)
///    w0 = 2 * CT_ABS(s)
///    w1 = s^2 + 1
///    w2 = s^2 - 1
///    w3 = v_prime * s * (r - 1) * ONE_MINUS_TWO_D + sgn
///    ```
/// 3. Return the internal representation `(w0*w3, w2*w1, w1*w3, w0*w2)`
///    — again note `t0 = w0*w2` is directly AVAILABLE from this
///    construction (unlike a fresh `add`/`dbl` result), even though this
///    module's `Element.p` does not persist it; a crypto-core pass filling
///    this in only needs `x0 = w0*w3`, `y0 = w2*w1`, `z0 = w1*w3` to
///    populate `Element{ .p = .{ .x=.., .y=.., .z=.. } }`.
///
/// Step 1's modular reduction of an arbitrary 56-byte string into a
/// canonical `Fe` is itself a small mechanical piece a crypto-core pass
/// may want to hoist into `field.zig` as a `Fe.reduceWide`-style helper
/// (mirroring `ed448.scalar.reduceWide`'s shape one field over) — `Fe`
/// today only exposes `fromBytes`, which REJECTS non-canonical input,
/// the opposite of what this step needs.
/// Reduce an arbitrary little-endian 56-byte string modulo `p` into a
/// canonical `Fe` — `mapToElement`'s step 1, which (unlike `Element.
/// decode`) must ACCEPT non-canonical input. Any 448-bit value is
/// `< 2^448 < 2p` (`2p = 2^449 - 2^225 - 2`), so a single conditional
/// subtraction of `p` canonicalizes. Branch-free: computes the trial
/// `bytes - p` with byte-wise borrow propagation, then mask-selects
/// between original and subtracted forms on the final borrow — the same
/// shape as `field.zig`'s own `condSubP`, one representation up (wire
/// bytes instead of limbs, since `Fe`'s limb internals are private to
/// this module's view).
fn feFromBytesReduced(bytes: [56]u8) Fe {
    var diff: [field.encoded_bytes]u8 = undefined;
    var borrow: u16 = 0;
    for (0..field.encoded_bytes) |i| {
        // Operands < 2^8 and borrow <= 1, so a negative true result wraps
        // into [0xff00, 0xffff] (bit 15 set); non-negative stays < 2^8.
        const d = @as(u16, bytes[i]) -% field.p_bytes[i] -% borrow;
        diff[i] = @truncate(d);
        borrow = d >> 15;
    }
    // borrow == 1 -> bytes < p -> keep the original bytes.
    const keep: u8 = 0 -% @as(u8, @truncate(borrow));
    var out: [field.encoded_bytes]u8 = undefined;
    for (&out, bytes, diff) |*o, b, dm| o.* = (b & keep) | (dm & ~keep);
    // Canonical by construction: bytes < p keeps bytes; bytes >= p keeps
    // bytes - p < 2^448 - p = 2^224 + 1 < p.
    return Fe.fromBytes(out) catch unreachable;
}

fn mapToElement(bytes: [56]u8) Element {
    // Step 1: reduce mod p, accepting non-canonical input (RFC 9496
    // §5.3.4's own note, contrast Element.decode's rejection).
    const t = feFromBytesReduced(bytes);

    // Step 2 (RFC 9496 §5.3.4). All ops constant-time (Fe ops + ctSelect
    // + ctAbs); was_square feeds only CT selects, never a branch.
    const r = t.square().neg();
    const uu0 = D.mul(r.sub(Fe.one));
    const uu1 = uu0.add(Fe.one).mul(uu0.sub(r));
    const sr = sqrtRatioM1(ONE_MINUS_TWO_D, r.add(Fe.one).mul(uu1));
    const v_prime = Fe.ctSelect(sr.was_square, sr.root, t.mul(sr.root));
    const sgn = Fe.ctSelect(sr.was_square, Fe.one, Fe.one.neg());
    const s = v_prime.mul(r.add(Fe.one));
    const s_abs = ctAbs(s);
    const w0 = s_abs.add(s_abs);
    const s2 = s.square();
    const w1 = s2.add(Fe.one);
    const w2 = s2.sub(Fe.one);
    const w3 = v_prime.mul(s).mul(r.sub(Fe.one)).mul(ONE_MINUS_TWO_D).add(sgn);

    // Step 3: internal representation (w0*w3, w2*w1, w1*w3, w0*w2) —
    // t0 = w0*w2 is available but not stored (module doc comment).
    return .{ .p = .{ .x = w0.mul(w3), .y = w2.mul(w1), .z = w1.mul(w3) } };
}

// ── tests (ungated — mechanical/group-op layer only) ────────────────────

const testing = std.testing;

test "D matches ed448.ed448.d bit-for-bit (RFC 9496 §5.1's own restatement)" {
    try testing.expect(D.eql(ed448.ed448.d));
}

test "SQRT_MINUS_D^2 == -D (mod p) -- independent re-verification of the hardcoded RFC constant" {
    try testing.expect(SQRT_MINUS_D.square().eql(D.neg()));
}

test "INVSQRT_MINUS_D is the multiplicative inverse of SQRT_MINUS_D" {
    try testing.expect(INVSQRT_MINUS_D.mul(SQRT_MINUS_D).eql(Fe.one));
}

test "INVSQRT_MINUS_D^2 * (-D) == 1 -- INVSQRT_MINUS_D really is 1/sqrt(-D)" {
    try testing.expect(INVSQRT_MINUS_D.square().mul(D.neg()).eql(Fe.one));
}

test "ONE_MINUS_D / ONE_MINUS_TWO_D match their small-integer definitions" {
    try testing.expect(Fe.one.sub(D).eql(ONE_MINUS_D));
    const two_d = D.add(D);
    try testing.expect(Fe.one.sub(two_d).eql(ONE_MINUS_TWO_D));
}

test "ctAbs: IS_NEGATIVE(ctAbs(x)) is always false, and ctAbs(x) is x or -x" {
    const one = Fe.one;
    try testing.expect(!ctAbs(one).isOdd());
    const neg_one = one.neg();
    try testing.expect(ctAbs(neg_one).eql(one) or ctAbs(neg_one).eql(neg_one));
    try testing.expect(!ctAbs(neg_one).isOdd());
    try testing.expect(!ctAbs(Fe.zero).isOdd());
}

test "identity is the group identity: add(identity, generator) == generator" {
    try testing.expect(Element.add(Element.identity, Element.generator).equals(Element.generator));
}

test "generator != identity (equals distinguishes distinct elements)" {
    try testing.expect(!Element.generator.equals(Element.identity));
}

test "sub/negate: a - a == identity; negate is its own inverse under add" {
    const g = Element.generator;
    try testing.expect(Element.sub(g, g).equals(Element.identity));
    try testing.expect(Element.add(g, Element.negate(g)).equals(Element.identity));
    try testing.expect(Element.negate(Element.negate(g)).equals(g));
}

test "equals is reflexive and symmetric across differently-scaled internal representations" {
    // Two DIFFERENT internal (x,y,z) triples for the SAME curve point,
    // built by taking the generator through add(g,g) two different ways
    // (dbl-equivalent via add, and via the curve's own dbl()) -- both
    // are the identical curve point, so both z's differ from a fresh
    // Point.basePoint.dbl() construction's z, exercising equals's
    // z-scale-invariance argument (this function's own doc comment).
    const g = Element.generator;
    const via_add = Element.add(g, g);
    const via_dbl = Element{ .p = g.p.dbl() };
    try testing.expect(via_add.equals(via_dbl));
    try testing.expect(via_dbl.equals(via_add));
}

test "repeated addition matches RFC 9496 Appendix B.1's own recipe shape: [k]G via k-1 additions of G, for a few small k" {
    // Appendix B.1: "the first entry is the encoding of the identity
    // element, and each successive entry is obtained by adding the
    // generator to the previous entry." This checks that RECIPE
    // (group-law only, no encode/decode) matches scalarMul's result for
    // small k -- an ungated cross-check between the two mechanical ways
    // this module can reach the same element.
    var acc = Element.identity;
    var k: u8 = 0;
    while (k < 5) : (k += 1) {
        var s = scalar.zero;
        s[0] = k;
        const via_scalar_mul = Element.scalarMul(Element.generator, s);
        try testing.expect(acc.equals(via_scalar_mul));
        acc = Element.add(acc, Element.generator);
    }
}

test "scalarMul: [0]G == identity, [1]G == G" {
    try testing.expect(Element.scalarMul(Element.generator, scalar.zero).equals(Element.identity));
    var one = scalar.zero;
    one[0] = 1;
    try testing.expect(Element.scalarMul(Element.generator, one).equals(Element.generator));
}

// ── fuzz harness (untrusted-wire decoder) ───────────────────────────────

test "fuzz: Element.decode never crashes on arbitrary 56-byte input" {
    try testing.fuzz({}, fuzzElementDecode, .{});
}

fn fuzzElementDecode(_: void, smith: *std.testing.Smith) !void {
    var buf: Element.EncodedBytes = undefined;
    smith.bytes(&buf);
    const e = Element.decode(buf) catch return;
    _ = e.encode();
    _ = e.equals(Element.identity);
}
