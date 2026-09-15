// SPDX-License-Identifier: MIT
//! `G1` — the prime-order-`r` subgroup of `E(Fp): y^2 = x^3 + 4`, the
//! FIRST of BLS12-381's two pairing groups (`e: G1 x G2 -> Gt`). This is
//! the group BLS signatures (and most other consumers — see
//! `README.md`'s arc) put either the smaller, cheaper-to-verify element
//! in (public keys, typically) or the message-hash element in (signatures
//! themselves), depending on the scheme variant — Part 4's job to decide,
//! not this file's.
//!
//! **Status: implemented.** Complete (branchless-degenerate-case)
//! Jacobian addition, doubling, constant-time double-and-add-always
//! scalar multiplication, on-curve/subgroup checks, cofactor clearing
//! and full (de)serialization including decompression. See `SPEC.md`
//! for the BLS subgroup-check pitfall this module's design is built
//! around, and the constant-time notes there for the ctSelect-based
//! branchless discipline used throughout.

const std = @import("std");
const fp = @import("fp.zig");
const scalarmod = @import("scalar.zig");

pub const Fp = fp.Fp;
pub const Fr = scalarmod.Fr;

/// `|x|`, the BLS12-381 seed magnitude (`x = -0xd201000000010000`) —
/// one definition, owned by `pairing.zig`'s Miller loop.
const bls_x_abs: u64 = @import("pairing.zig").bls_x_abs;
comptime {
    std.debug.assert(bls_x_abs >> 63 == 1); // mulByAbsXPublic starts at bit 62
}

/// `β`, the primitive cube root of unity in `Fp` for which the GLV map
/// `φ(x, y) = (βx, y)` acts on `G1` as multiplication by `λ = -x²`
/// (the OTHER root, `β²`, acts as `λ² = x² - 1`). Derived at comptime,
/// never transcribed: `2^((p-1)/3)` (`p ≡ 1 mod 3`, exact division
/// enforced by `pExponentBytes`) — `2` is a cubic non-residue, which
/// the `!= 1` guard below enforces. Which of the two roots is the right
/// one is pinned by the "φ acts as [-x²] on G1" test below — the
/// generator test, since `G1` is cyclic.
const endomorphism_beta: Fp = blk: {
    @setEvalBranchQuota(50_000_000);
    const two = Fp.fromInt(u8, 2) catch unreachable;
    const root = two.pow(fp.pExponentBytes(-1, 3));
    if (root.eql(Fp.one)) @compileError("bls12_381: 2 is a cube mod p; pick another base for β");
    break :blk root;
};

/// The curve equation constant: `E: y^2 = x^3 + b`, `b = 4`. REAL:
/// `Fp.fromInt` is pure `std.crypto.ff` delegation (see `fp.zig`).
pub const b: Fp = Fp.fromInt(u8, 4) catch @compileError("bls12_381: bad G1 b constant");

/// `G1`'s cofactor `h1 = #E(Fp) / r`, big-endian, 16 bytes:
/// `0x396c8c005555e1568c00aaab0000aaab`. Used by `clearCofactor`.
///
/// Provenance: independently RE-DERIVED (not merely transcribed) from
/// the defining BLS polynomial family with `z = -0xd201000000010000` —
/// `#E(Fp) = p + 1 - (z+1)`, `h1 = #E(Fp) / r` — and confirmed the
/// division is EXACT (zero remainder). See `NOTICE`'s "Verification
/// performed" section for the recomputation.
pub const cofactor_bytes: [16]u8 = blk: {
    @setEvalBranchQuota(2000);
    var out: [16]u8 = undefined;
    _ = std.fmt.hexToBytes(&out, "396c8c005555e1568c00aaab0000aaab") catch unreachable;
    break :blk out;
};

pub const G1Error = error{
    /// Byte length / flag-bit shape is invalid (e.g. the reserved
    /// combination `compression=0, sort=1`, or a nonzero coordinate
    /// paired with the infinity flag).
    InvalidEncoding,
    /// A coordinate failed `Fp.fromBytes` (non-canonical, i.e. `>= p`).
    InvalidFieldElement,
    /// The decoded `(x, y)` (or, for compressed input, the recovered
    /// `y`) does not satisfy `y^2 = x^3 + b`.
    NotOnCurve,
    /// The point is on the curve `E(Fp)` but not in the order-`r`
    /// subgroup `G1` (see `SPEC.md`'s subgroup-check pitfall note).
    NotInSubgroup,
};

/// An affine `G1` point: `(x, y)`, or the point at infinity
/// (`infinity = true`, in which case `x`/`y` are unspecified — per the
/// ZCash/IETF wire convention, encoded as all-zero, see `toBytesCompressed`/
/// `toBytesUncompressed`).
pub const Affine = struct {
    x: Fp,
    y: Fp,
    infinity: bool = false,

    /// `G1`'s standard fixed generator point (the one every BLS12-381
    /// implementation and spec calls "the" `G1` generator — used as the
    /// base point for all published test vectors this module's siblings
    /// will KAT against in later parts).
    ///
    /// Coordinates (hex, big-endian):
    /// ```
    /// x = 0x17f1d3a73197d7942695638c4fa9ac0fc3688c4f9774b905a14e3a3f171
    ///       bac586c55e83ff97a1aeffb3af00adb22c6bb
    /// y = 0x08b3f481e3aaa0f1a09e30ed741d8ae4fcf5e095d5d00af600db18cb2c0
    ///       4b3edd03cc744a2888ae40caa232946c5e7e1
    /// ```
    ///
    /// Provenance: fetched from TWO independent copies of `py_ecc`
    /// (`ethereum/py_ecc`, MIT) — `optimized_bls12_381/optimized_curve.py`
    /// and `bls12_381/bls12_381_curve.py` — which agreed byte-for-byte,
    /// then INDEPENDENTLY VERIFIED on-curve (`y^2 == x^3+4 mod p`) by
    /// direct computation, not merely trusted. See `NOTICE`'s
    /// "Verification performed" section.
    pub const generator: Affine = .{
        .x = Fp.fromBytes(hexBytes(48, "17f1d3a73197d7942695638c4fa9ac0fc3688c4f9774b905a14e3a3f171bac586c55e83ff97a1aeffb3af00adb22c6bb")) catch
            @compileError("bls12_381: bad G1 generator x"),
        .y = Fp.fromBytes(hexBytes(48, "08b3f481e3aaa0f1a09e30ed741d8ae4fcf5e095d5d00af600db18cb2c04b3edd03cc744a2888ae40caa232946c5e7e1")) catch
            @compileError("bls12_381: bad G1 generator y"),
    };

    /// The point at infinity (`G1`'s group identity).
    pub const identity: Affine = .{ .x = Fp.zero, .y = Fp.zero, .infinity = true };
};

/// A `G1` point in Jacobian projective coordinates `(X, Y, Z)`,
/// representing the affine point `(X/Z^2, Y/Z^3)` — the working
/// representation for `add`/`double`/`scalarMul` (avoids an `Fp.inv` per
/// operation; only `toAffine` needs one).
pub const Jacobian = struct {
    x: Fp,
    y: Fp,
    z: Fp,

    /// The point at infinity, conventionally `(1, 1, 0)` in Jacobian
    /// coordinates (`Z = 0` is infinity regardless of `X`/`Y`; `(1,1,0)`
    /// is the customary normalized representative). REAL: a plain
    /// comptime struct literal, no arithmetic.
    pub const identity: Jacobian = .{ .x = Fp.one, .y = Fp.one, .z = Fp.zero };

    /// `true` iff this represents the point at infinity. REAL: `Z == 0`
    /// is the defining condition, needing only `Fp.isZero` (already
    /// REAL, `fp.zig`) — no multiplication.
    pub fn isIdentity(self: Jacobian) bool {
        return self.z.isZero();
    }

    /// Lifts an affine point into Jacobian coordinates: `(x, y, 1)`, or
    /// `identity` if `p.infinity`. REAL: mechanical embedding, no field
    /// arithmetic (`Fp.one`/`Fp.zero` are comptime constants, not
    /// computed here).
    pub fn fromAffine(p: Affine) Jacobian {
        if (p.infinity) return identity;
        return .{ .x = p.x, .y = p.y, .z = Fp.one };
    }

    /// Converts back to affine: `(X/Z^2, Y/Z^3)`, or `Affine.identity`
    /// if `isIdentity()`. The `Fp.inv` here inverts a Z coordinate —
    /// public in every current caller (serialization of a public
    /// point); revisit with a blinded/batch inversion if an affine
    /// conversion of a secret point ever appears.
    pub fn toAffine(self: Jacobian) Affine {
        if (self.isIdentity()) return Affine.identity;
        const z_inv = self.z.inv() catch unreachable; // z != 0 checked above
        const z_inv2 = z_inv.square();
        return .{
            .x = self.x.mul(z_inv2),
            .y = self.y.mul(z_inv2).mul(z_inv),
        };
    }

    /// Constant-time select: returns `a` if `cond`, else `b` —
    /// coordinate-wise `Fp.ctSelect`. Used by `add` (branchless
    /// degenerate-case resolution) and `scalarMul` (branchless
    /// double-and-add-always accumulator update).
    fn ctSelect(cond: bool, on_true: Jacobian, on_false: Jacobian) Jacobian {
        return .{
            .x = Fp.ctSelect(cond, on_true.x, on_false.x),
            .y = Fp.ctSelect(cond, on_true.y, on_false.y),
            .z = Fp.ctSelect(cond, on_true.z, on_false.z),
        };
    }

    // ── group arithmetic ────────────────────────────────────────────

    /// Jacobian point addition (general case, `a != b`, neither the
    /// identity). Construction: the standard `add-2007-bl`-family
    /// formula (12M+4S — see e.g. the Bernstein–Lange "Explicit-
    /// Formulas Database" `shortw/jacobian` addition formulas, or any
    /// of the reference implementations cited in `NOTICE`) — MUST
    /// handle the degenerate cases correctly and EXPLICITLY: either
    /// operand being the identity, and `a == b`/`a == -b` (which the
    /// general formula divides by zero on) by delegating to `double`/
    /// returning `identity` respectively. Constant-time with respect to
    /// which case fires is a real concern if either operand can be
    /// secret-dependent (e.g. scalar-mul's accumulator) — see
    /// `SPEC.md`'s threat model.
    pub fn add(a: Jacobian, other: Jacobian) Jacobian {
        // General case: the add-2007-bl formula (Bernstein-Lange EFD,
        // shortw/jacobian-0/addition/add-2007-bl). Degenerate cases are
        // resolved BRANCHLESSLY afterwards via ctSelect (constant-time
        // with respect to which case fired — the accumulator's state in
        // scalarMul is secret-dependent): the general formula's output
        // is garbage when h == 0 or an operand is the identity, but it
        // is fully computed either way and then masked out.
        const z1z1 = a.z.square();
        const z2z2 = other.z.square();
        const ua = a.x.mul(z2z2); // U1
        const ub = other.x.mul(z1z1); // U2
        const sa = a.y.mul(other.z).mul(z2z2); // S1
        const sb = other.y.mul(a.z).mul(z1z1); // S2
        const h = ub.sub(ua); // 0 iff same x (P == Q or P == -Q)
        const s_diff = sb.sub(sa); // 0 (given h == 0) iff P == Q

        const i = h.add(h).square();
        const j = h.mul(i);
        const rr = s_diff.add(s_diff);
        const v = ua.mul(i);
        const x3 = rr.square().sub(j).sub(v.add(v));
        const s1j = sa.mul(j);
        const y3 = rr.mul(v.sub(x3)).sub(s1j.add(s1j));
        const z3 = a.z.add(other.z).square().sub(z1z1).sub(z2z2).mul(h);

        var out: Jacobian = .{ .x = x3, .y = y3, .z = z3 };
        // Degenerate-case resolution, lowest to highest precedence.
        const dbl = a.double();
        const h_zero: u1 = @intFromBool(h.isZero());
        const s_zero: u1 = @intFromBool(s_diff.isZero());
        out = ctSelect((h_zero & (1 - s_zero)) == 1, identity, out); // P == -Q
        out = ctSelect((h_zero & s_zero) == 1, dbl, out); // P == Q
        out = ctSelect(other.isIdentity(), a, out);
        out = ctSelect(a.isIdentity(), other, out);
        return out;
    }

    /// Jacobian point doubling. Construction: the standard
    /// `dbl-2009-l`-family formula (specialized for `a = 0` in `y^2 =
    /// x^3 + a*x + b`, which BLS12-381's `G1`/`G2` both have — same
    /// reference as `add`).
    pub fn double(a: Jacobian) Jacobian {
        // dbl-2009-l (EFD, shortw/jacobian-0/doubling), valid for the
        // a=0 curve coefficient. Exception-free: for the identity
        // (Z = 0) — and for a hypothetical Y = 0 point of order 2 —
        // Z3 = 2*Y1*Z1 = 0, i.e. the result is (correctly) the
        // identity, with no branch needed.
        const xx = a.x.square(); // A
        const yy = a.y.square(); // B
        const yyyy = yy.square(); // C
        const d0 = a.x.add(yy).square().sub(xx).sub(yyyy);
        const d = d0.add(d0); // D = 2((X1+B)^2 - A - C)
        const e = xx.add(xx).add(xx); // E = 3A
        const f = e.square(); // F = E^2
        const x3 = f.sub(d.add(d));
        const c8 = blk: { // 8C
            const c2 = yyyy.add(yyyy);
            const c4 = c2.add(c2);
            break :blk c4.add(c4);
        };
        const y3 = e.mul(d.sub(x3)).sub(c8);
        const yz = a.y.mul(a.z);
        return .{ .x = x3, .y = y3, .z = yz.add(yz) };
    }

    /// Negation: `(X, Y, Z) -> (X, -Y, Z)`.
    pub fn negate(a: Jacobian) Jacobian {
        return .{ .x = a.x, .y = a.y.neg(), .z = a.z };
    }

    /// Scalar multiplication `[s]P`. Construction: constant-time
    /// double-and-add (e.g. a fixed-window or Montgomery-ladder variant
    /// — `s` is very often SECRET here, e.g. a BLS secret key times the
    /// generator, or a share value times a point in threshold BLS,
    /// `README.md`'s Part 6) over `s`'s 32-byte (`Fr.encoded_bytes`)
    /// encoding. Public-scalar call sites (if any downstream) may use a
    /// faster variable-time ladder instead — a caller-side choice, not
    /// this function's; consider exposing a separate `scalarMulPublic`
    /// if/when such a call site materializes, mirroring
    /// `fp.zig`/`scalar.zig`'s `pow`/`powPublic` split.
    pub fn scalarMul(p: Jacobian, s: Fr) Jacobian {
        return scalarMulBytes(p, &s.toBytes());
    }

    /// `[s]P` for an arbitrary-width big-endian scalar byte string —
    /// the shared engine behind `scalarMul` (32-byte `Fr` scalars),
    /// `subgroupCheck` (the 32-byte group order `r` itself, NOT a
    /// canonical `Fr` value) and `clearCofactor` (the 16-byte cofactor
    /// `h1`, not `Fr`-reduced). Constant-time double-and-add-ALWAYS:
    /// every bit performs one `double` and one (complete, branchless)
    /// `add`, and the accumulator update is a `ctSelect` — no
    /// secret-dependent branch or memory access; the only quantity
    /// leaked is `s.len`, which is static at every call site.
    pub fn scalarMulBytes(p: Jacobian, s: []const u8) Jacobian {
        var acc = identity;
        for (s) |byte| {
            var bit: u3 = 7;
            while (true) : (bit -= 1) {
                acc = acc.double();
                const sum = acc.add(p);
                acc = ctSelect((byte >> bit) & 1 == 1, sum, acc);
                if (bit == 0) break;
            }
        }
        return acc;
    }

    /// `true` iff this point satisfies the curve equation `y^2 = x^3 +
    /// b` (Jacobian form: `Y^2 = X^3 + b*Z^6`), OR is the identity
    /// (vacuously on-curve). Needed by BOTH decompression (`recoverY`,
    /// below) and as a defensive re-check anywhere an already-parsed
    /// point re-enters this module from an untrusted boundary. Does
    /// NOT imply subgroup membership — see `subgroupCheck` and
    /// `SPEC.md`'s pitfall note.
    pub fn isOnCurve(self: Jacobian) bool {
        if (self.isIdentity()) return true;
        const z2 = self.z.square();
        const z6 = z2.square().mul(z2);
        const rhs = self.x.square().mul(self.x).add(b.mul(z6));
        return self.y.square().eql(rhs);
    }

    /// `true` iff this point is ON THE CURVE and in the order-`r`
    /// SUBGROUP `G1` (not merely on `E(Fp)`, which has a much larger
    /// order `r * h1` — see `cofactor_bytes`). THE classic BLS pitfall
    /// this module's `SPEC.md` centers its threat model on: skipping
    /// this check on an externally-supplied point lets an attacker
    /// submit a small-subgroup point and force a degenerate/predictable
    /// pairing result (a real, exploited class of bug in early BLS
    /// implementations). The identity passes (it is in `G1`).
    ///
    /// Construction (2026-09-15, A1 `drand` F4): the GLV-endomorphism
    /// membership test `φ(P) == [-x²]P`, `φ(x, y) = (βx, y)`, `x` the
    /// BLS seed — Scott, "A note on group membership tests for G1, G2
    /// and GT on BLS pairing-friendly curves" (ePrint 2021/1130) §6, with
    /// the corrected proof in El Housni–Guillevic–Piellard, "Co-factor
    /// clearing and subgroup membership testing on pairing-friendly
    /// curves" (ePrint 2022/352) §4.3, Proposition 4: "For the BLS12
    /// family, if Q ∈ E(Fp), φ(Q) = [−u²]Q =⇒ Q ∈ E(Fp)[r]." (their
    /// Proposition 2 needs `φ` to act as `λ = −u²` on `E(Fp)[r]` and
    /// `gcd(χ(λ), c1) = 1`; both are re-checked for THIS curve by the
    /// tests below, not taken on trust). The premise `Q ∈ E(Fp)` is why
    /// the curve equation is checked first. Cost: two multiplications
    /// by the 64-bit `|x|` instead of one by the 255-bit `r`; the old
    /// `[r]P == O` form is kept as `subgroupCheckByOrder`, the test-only
    /// reference every differential test compares against.
    ///
    /// Timing: the only data-dependent control flow is the identity
    /// early-out in `isOnCurve`/`eqlPoints` and the bit pattern of the
    /// fixed public constant `|x|` — nothing depends on the point's
    /// coordinates beyond "is it the identity". The inputs of this
    /// check are public points in every caller (keys, signatures,
    /// proofs, setup points).
    pub fn subgroupCheck(self: Jacobian) bool {
        if (!self.isOnCurve()) return false;
        // x is negative, but [x²] = [|x|]∘[|x|], so the sign drops out.
        const x2p = mulByAbsXPublic(mulByAbsXPublic(self));
        return eqlPoints(endomorphismPhi(self), x2p.negate());
    }

    /// The pre-2026-09-15 subgroup check, `[r]P == O` via the
    /// constant-time 255-bit ladder. Kept ONLY as the reference the
    /// differential tests hold `subgroupCheck` against (it is the
    /// definition of the subgroup, so it needs no cited theorem); no
    /// production caller.
    fn subgroupCheckByOrder(self: Jacobian) bool {
        return scalarMulBytes(self, &scalarmod.r_bytes).isIdentity();
    }

    /// `φ(X, Y, Z) = (βX, Y, Z)` — the GLV endomorphism of `y² = x³ + b`
    /// (`β` a primitive cube root of unity in `Fp`, `endomorphism_beta`),
    /// written on Jacobian coordinates: affine `x = X/Z²` scales by `β`
    /// exactly when `X` does.
    fn endomorphismPhi(p: Jacobian) Jacobian {
        return .{ .x = p.x.mul(endomorphism_beta), .y = p.y, .z = p.z };
    }

    /// `[|x|]P` for the BLS seed magnitude `|x| = 0xd201000000010000`
    /// (`pairing.bls_x_abs`). Variable-time ONLY in that fixed public
    /// constant (six set bits: an `add` on those, a `double` on every
    /// bit); the point arithmetic itself is the same complete,
    /// branchless `double`/`add`, so a point of small order hitting a
    /// degenerate case (`acc == ±P`) is handled. Not a general scalar
    /// multiplication and never used with a secret scalar — the
    /// secret-scalar engine is `scalarMulBytes`, unchanged.
    fn mulByAbsXPublic(p: Jacobian) Jacobian {
        var acc = p; // the leading 1 of |x| (bit 63)
        var bit: u6 = 62;
        while (true) : (bit -= 1) {
            acc = acc.double();
            if ((bls_x_abs >> bit) & 1 == 1) acc = acc.add(p);
            if (bit == 0) break;
        }
        return acc;
    }

    /// Projective equality: `X1·Z2² == X2·Z1²` and `Y1·Z2³ == Y2·Z1³`,
    /// the identity equal only to itself.
    fn eqlPoints(a: Jacobian, other: Jacobian) bool {
        const a_inf = a.isIdentity();
        const b_inf = other.isIdentity();
        if (a_inf or b_inf) return a_inf and b_inf;
        const z1z1 = a.z.square();
        const z2z2 = other.z.square();
        const x_eq = a.x.mul(z2z2).eql(other.x.mul(z1z1));
        const y_eq = a.y.mul(z2z2).mul(other.z).eql(other.y.mul(z1z1).mul(a.z));
        return x_eq and y_eq;
    }

    /// Multiplies an arbitrary `E(Fp)` point by the cofactor `h1`
    /// (`cofactor_bytes`) to land it in the order-`r` subgroup `G1` —
    /// the usual step after hashing an arbitrary message onto the curve
    /// (Part 3's hash-to-curve, `README.md`) and BEFORE trusting the
    /// result is a valid `G1` element. Construction: `scalarMul` by
    /// `h1`'s 16-byte value (zero-extended to `Fr`'s width is WRONG
    /// here — `h1` is a cofactor, not reduced mod `r`; this needs a
    /// plain big-integer scalar-mul over `h1`'s own 126-bit value, not
    /// `Fr` arithmetic — consider a separate small-scalar `scalarMul`
    /// overload, or zero-pad `h1` into whatever fixed-width type
    /// `scalarMul`'s eventual implementation settles on).
    pub fn clearCofactor(self: Jacobian) Jacobian {
        // Plain big-integer scalar-mul by h1's own 126-bit value (see
        // doc comment for why zero-extending into Fr would be wrong) —
        // scalarMulBytes takes the raw 16-byte cofactor directly.
        // TODO: the faster Bowe cofactor-clearing endomorphism trick is
        // a deferred optimization, per SPEC.md's Backlog.
        return scalarMulBytes(self, &cofactor_bytes);
    }
};

// ── wire codec (ZCash/IETF BLS12-381 serialization format) ─────────────
//
// Flag bits live in the TOP 3 bits of the very first serialized byte:
// bit 7 = compression flag, bit 6 = infinity flag, bit 5 = sort flag
// (sign of y, compressed encoding only). See `NOTICE` for the spec
// citation and `fp2.zig`'s doc comment for the analogous — and easier to
// get backwards — Fp2 component-order pitfall in `G2`.

const Flags = struct {
    compression: bool,
    infinity: bool,
    sort: bool,
};

/// Extracts the flag bits from a serialized point's first byte and
/// returns them alongside that byte with the flag bits cleared (i.e.
/// the true high byte of the first coordinate). REAL: pure bit
/// manipulation, no field arithmetic.
fn splitFlags(b0: u8) struct { flags: Flags, byte: u8 } {
    return .{
        .flags = .{
            .compression = (b0 & 0x80) != 0,
            .infinity = (b0 & 0x40) != 0,
            .sort = (b0 & 0x20) != 0,
        },
        .byte = b0 & 0x1f,
    };
}

/// Packs flag bits into a coordinate's already-serialized first byte.
/// REAL: pure bit manipulation.
fn packFlags(byte: u8, flags: Flags) u8 {
    var b0 = byte & 0x1f;
    if (flags.compression) b0 |= 0x80;
    if (flags.infinity) b0 |= 0x40;
    if (flags.sort) b0 |= 0x20;
    return b0;
}

/// Uncompressed encoding: 96 bytes, `flags|x (48B) || y (48B)`.
pub const uncompressed_bytes = 2 * Fp.encoded_bytes;

/// Compressed encoding: 48 bytes, `flags|x (48B)` (`y`'s sign is the
/// `sort` flag; its magnitude is recovered on decode via `recoverY`).
pub const compressed_bytes = Fp.encoded_bytes;

/// Serializes `p` in the 96-byte uncompressed form. REAL: mechanical
/// flag-packing plus `Fp.toBytes` (itself REAL) — no curve arithmetic.
pub fn toBytesUncompressed(p: Affine) [uncompressed_bytes]u8 {
    var out: [uncompressed_bytes]u8 = undefined;
    if (p.infinity) {
        @memset(&out, 0);
        out[0] = packFlags(0, .{ .compression = false, .infinity = true, .sort = false });
        return out;
    }
    var x_bytes = p.x.toBytes();
    x_bytes[0] = packFlags(x_bytes[0], .{ .compression = false, .infinity = false, .sort = false });
    out[0..Fp.encoded_bytes].* = x_bytes;
    out[Fp.encoded_bytes..uncompressed_bytes].* = p.y.toBytes();
    return out;
}

/// Serializes `p` in the 48-byte compressed form. REAL: mechanical
/// flag-packing (including the `sort` bit, via `Fp.isLexicographically
/// Largest` — itself REAL, `fp.zig`) plus `Fp.toBytes` — no curve
/// arithmetic, and NO `Fp.sqrt` needed (unlike decoding).
pub fn toBytesCompressed(p: Affine) [compressed_bytes]u8 {
    if (p.infinity) {
        var out: [compressed_bytes]u8 = [_]u8{0} ** compressed_bytes;
        out[0] = packFlags(0, .{ .compression = true, .infinity = true, .sort = false });
        return out;
    }
    var x_bytes = p.x.toBytes();
    x_bytes[0] = packFlags(x_bytes[0], .{
        .compression = true,
        .infinity = false,
        .sort = p.y.isLexicographicallyLargest(),
    });
    return x_bytes;
}

/// Recovers `y` from `x` for compressed decoding: `y = sqrt(x^3 + b)`,
/// then negate if the recovered candidate's sign does not match `sort`.
/// Public-input path (deserialization) — branching on the sqrt result
/// and the sort bit is fine here.
fn recoverY(x: Fp, sort: bool) G1Error!Fp {
    var y = x.square().mul(x).add(b).sqrt() orelse return error.NotOnCurve;
    if (y.isLexicographicallyLargest() != sort) y = y.neg();
    return y;
}

/// Parses the 96-byte uncompressed form, including the on-curve check.
/// Does NOT check subgroup membership — callers that need a validated
/// `G1` element (e.g. anything crossing a network/deserialization
/// boundary) MUST additionally call `Jacobian.subgroupCheck` (see
/// `SPEC.md`).
pub fn fromBytesUncompressed(bytes: [uncompressed_bytes]u8) G1Error!Affine {
    const split = splitFlags(bytes[0]);
    if (split.flags.compression) return error.InvalidEncoding;
    if (split.flags.infinity) {
        // Spec requires the remaining bits/bytes to be all-zero.
        if (split.byte != 0) return error.InvalidEncoding;
        for (bytes[1..]) |byte| if (byte != 0) return error.InvalidEncoding;
        return Affine.identity;
    }
    var x_bytes = bytes[0..Fp.encoded_bytes].*;
    x_bytes[0] = split.byte;
    const x = Fp.fromBytes(x_bytes) catch return error.InvalidFieldElement;
    const y = Fp.fromBytes(bytes[Fp.encoded_bytes..uncompressed_bytes].*) catch return error.InvalidFieldElement;
    const p = Affine{ .x = x, .y = y };
    if (!Jacobian.fromAffine(p).isOnCurve()) return error.NotOnCurve;
    return p;
}

/// Parses the 48-byte compressed form (`y` recovered via `recoverY`,
/// i.e. `Fp.sqrt`). Like `fromBytesUncompressed`, does NOT check
/// subgroup membership.
pub fn fromBytesCompressed(bytes: [compressed_bytes]u8) G1Error!Affine {
    const split = splitFlags(bytes[0]);
    if (!split.flags.compression) return error.InvalidEncoding;
    if (split.flags.infinity) {
        if (split.flags.sort) return error.InvalidEncoding; // reserved combination
        if (split.byte != 0) return error.InvalidEncoding;
        for (bytes[1..]) |byte| if (byte != 0) return error.InvalidEncoding;
        return Affine.identity;
    }
    var x_bytes = bytes;
    x_bytes[0] = split.byte;
    const x = Fp.fromBytes(x_bytes) catch return error.InvalidFieldElement;
    const y = try recoverY(x, split.flags.sort);
    return .{ .x = x, .y = y };
}

fn hexBytes(comptime n: usize, comptime hex: *const [2 * n:0]u8) [n]u8 {
    @setEvalBranchQuota(100_000);
    var out: [n]u8 = undefined;
    _ = std.fmt.hexToBytes(&out, hex) catch unreachable;
    return out;
}

// ── tests ────────────────────────────────────────────────────────────────

test "b == 4" {
    try std.testing.expectEqual(@as(u8, 4), b.toBytes()[47]);
}

test "generator components are nonzero (constant sanity; on-curve tested below)" {
    try std.testing.expect(!Affine.generator.x.isZero());
    try std.testing.expect(!Affine.generator.y.isZero());
}

test "Jacobian.identity.isIdentity" {
    try std.testing.expect(Jacobian.identity.isIdentity());
    try std.testing.expect(!Jacobian.fromAffine(Affine.generator).isIdentity());
}

test "cofactor_bytes decodes to the expected 16-byte value" {
    var expected: [16]u8 = undefined;
    _ = try std.fmt.hexToBytes(&expected, "396c8c005555e1568c00aaab0000aaab");
    try std.testing.expectEqualSlices(u8, &expected, &cofactor_bytes);
}

// KAT: the generator's compressed/uncompressed serialization, per the
// ZCash/IETF flag-bit format. Computed independently for this scaffold
// by direct application of the documented encoding rule to the
// (independently verified — see above) generator coordinates; NOT
// copied from any third-party test suite (see NOTICE). Both flag bytes
// start with 0x17/0x97 (uncompressed/compressed) rather than 0x1f/0x9f
// because `x`'s own top bits happen to be `0b00010111` — the flag bits
// are OR'd into, not prepended to, that same byte (see `packFlags`).
const generator_uncompressed_hex =
    "17f1d3a73197d7942695638c4fa9ac0fc3688c4f9774b905a14e3a3f171bac586c55e83ff97a1aeffb3af00adb22c6bb" ++
    "08b3f481e3aaa0f1a09e30ed741d8ae4fcf5e095d5d00af600db18cb2c04b3edd03cc744a2888ae40caa232946c5e7e1";
const generator_compressed_hex =
    "97f1d3a73197d7942695638c4fa9ac0fc3688c4f9774b905a14e3a3f171bac586c55e83ff97a1aeffb3af00adb22c6bb";

test "generator toBytesUncompressed matches the computed KAT" {
    const expected = hexBytes(uncompressed_bytes, generator_uncompressed_hex);
    try std.testing.expectEqualSlices(u8, &expected, &toBytesUncompressed(Affine.generator));
}

test "generator toBytesCompressed matches the computed KAT (sort bit = 0)" {
    const expected = hexBytes(compressed_bytes, generator_compressed_hex);
    try std.testing.expectEqualSlices(u8, &expected, &toBytesCompressed(Affine.generator));
}

test "identity toBytesUncompressed / toBytesCompressed are all-zero plus the infinity flag" {
    const u = toBytesUncompressed(Affine.identity);
    try std.testing.expectEqual(@as(u8, 0x40), u[0]);
    try std.testing.expect(std.mem.allEqual(u8, u[1..], 0));

    const c = toBytesCompressed(Affine.identity);
    try std.testing.expectEqual(@as(u8, 0xc0), c[0]);
    try std.testing.expect(std.mem.allEqual(u8, c[1..], 0));
}

test "fromBytesUncompressed rejects the compression flag set" {
    var bytes = hexBytes(uncompressed_bytes, generator_uncompressed_hex);
    bytes[0] |= 0x80;
    try std.testing.expectError(error.InvalidEncoding, fromBytesUncompressed(bytes));
}

test "fromBytesCompressed rejects the compression flag unset" {
    var bytes = hexBytes(compressed_bytes, generator_compressed_hex);
    bytes[0] &= 0x7f;
    try std.testing.expectError(error.InvalidEncoding, fromBytesCompressed(bytes));
}

test "fromBytesUncompressed round-trips the generator's flag/coordinate parsing" {
    const bytes = hexBytes(uncompressed_bytes, generator_uncompressed_hex);
    const p = try fromBytesUncompressed(bytes);
    try std.testing.expect(p.x.eql(Affine.generator.x));
    try std.testing.expect(p.y.eql(Affine.generator.y));
}

// ── group arithmetic tests ──────────────────────────────────────────────

fn jacGen() Jacobian {
    return Jacobian.fromAffine(Affine.generator);
}

// Affine equality through toAffine (Jacobian representations of the
// same point differ coordinate-wise).
fn expectSamePoint(lhs: Jacobian, rhs: Jacobian) !void {
    const aa = lhs.toAffine();
    const bb = rhs.toAffine();
    try std.testing.expectEqual(aa.infinity, bb.infinity);
    if (!aa.infinity) {
        try std.testing.expect(aa.x.eql(bb.x));
        try std.testing.expect(aa.y.eql(bb.y));
    }
}

test "G1 generator is on the curve (real isOnCurve)" {
    try std.testing.expect(jacGen().isOnCurve());
    try std.testing.expect(Jacobian.identity.isOnCurve());
    // ... and a corrupted point is not.
    var bad = jacGen();
    bad.x = bad.x.add(Fp.one);
    try std.testing.expect(!bad.isOnCurve());
}

test "G1 group law: identity element, inverses, add/double consistency" {
    const g = jacGen();
    // G + O == G, O + G == G
    try expectSamePoint(g.add(Jacobian.identity), g);
    try expectSamePoint(Jacobian.identity.add(g), g);
    // G + (-G) == O
    try std.testing.expect(g.add(g.negate()).isIdentity());
    // G + G == double(G) (the a == b degenerate case of add)
    try expectSamePoint(g.add(g), g.double());
    // double(O) == O
    try std.testing.expect(Jacobian.identity.double().isIdentity());
    // results stay on the curve
    try std.testing.expect(g.double().isOnCurve());
    try std.testing.expect(g.double().add(g).isOnCurve());
}

test "G1 group law: associativity and commutativity ((G+2G)+4G == G+(2G+4G))" {
    const g = jacGen();
    const g2 = g.double();
    const g4 = g2.double();
    try expectSamePoint(g.add(g2).add(g4), g.add(g2.add(g4)));
    try expectSamePoint(g.add(g2), g2.add(g));
}

// Cross-check vectors: compressed serializations of [2]G and [k]G for
// k = 0x0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef,
// computed with an INDEPENDENT from-scratch implementation (textbook
// affine-coordinate formulas over Python big integers — a different
// algorithm family from this module's Jacobian/Montgomery arithmetic;
// see NOTICE's "Verification performed").
const two_g_compressed_hex =
    "a572cbea904d67468808c8eb50a9450c9721db309128012543902d0ac358a62ae28f75bb8f1c7c42c39a8c5529bf0f4e";
const k_scalar_hex = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";
const k_g_compressed_hex =
    "86b50179774296419b7e8375118823ddb06940d9a28ea045ab418c7ecbe6da84d416cb55406eec6393db97ac26e38bd4";

test "G1 KAT: [2]G compressed matches the independent cross-check vector" {
    const expected = hexBytes(compressed_bytes, two_g_compressed_hex);
    const two_g = jacGen().double().toAffine();
    try std.testing.expectEqualSlices(u8, &expected, &toBytesCompressed(two_g));
}

test "G1 KAT: [k]G compressed matches the independent cross-check vector" {
    const k = try Fr.fromBytes(hexBytes(32, k_scalar_hex));
    const expected = hexBytes(compressed_bytes, k_g_compressed_hex);
    const kg = jacGen().scalarMul(k).toAffine();
    try std.testing.expectEqualSlices(u8, &expected, &toBytesCompressed(kg));
}

test "G1 scalarMul edge cases: [0]P = O, [1]P = P, [2]P = double(P)" {
    const g = jacGen();
    try std.testing.expect(g.scalarMul(Fr.zero).isIdentity());
    try expectSamePoint(g.scalarMul(Fr.one), g);
    const two = Fr.one.add(Fr.one);
    try expectSamePoint(g.scalarMul(two), g.double());
    // [s]O == O
    try std.testing.expect(Jacobian.identity.scalarMul(two).isIdentity());
}

test "G1 scalarMul distributes: [a+b]G == [a]G + [b]G and [a*b]G == [a]([b]G)" {
    var a_bytes = [_]u8{0} ** 32;
    a_bytes[31] = 0x35;
    a_bytes[16] = 0x9c;
    const sa = try Fr.fromBytes(a_bytes);
    var b_bytes = [_]u8{0} ** 32;
    b_bytes[31] = 0x0b;
    b_bytes[8] = 0x77;
    const sb = try Fr.fromBytes(b_bytes);
    const g = jacGen();
    try expectSamePoint(g.scalarMul(sa.add(sb)), g.scalarMul(sa).add(g.scalarMul(sb)));
    try expectSamePoint(g.scalarMul(sa.mul(sb)), g.scalarMul(sb).scalarMul(sa));
}

test "G1 subgroupCheck: generator passes ([r]G == O), non-subgroup curve point fails" {
    try std.testing.expect(jacGen().subgroupCheck());
    // x = 4 gives an on-curve point that is NOT in the order-r subgroup
    // (verified independently: [r]P != O — see NOTICE). Constructed via
    // decompression to also exercise recoverY on a non-generator x.
    var comp = [_]u8{0} ** compressed_bytes;
    comp[0] = 0x80; // compression flag, sort = 0
    comp[compressed_bytes - 1] = 4;
    const p = try fromBytesCompressed(comp);
    const jac = Jacobian.fromAffine(p);
    try std.testing.expect(jac.isOnCurve());
    try std.testing.expect(!jac.subgroupCheck());

    // clearCofactor([h1]P) lands it in the subgroup (and not at O).
    const cleared = jac.clearCofactor();
    try std.testing.expect(!cleared.isIdentity());
    try std.testing.expect(cleared.isOnCurve());
    try std.testing.expect(cleared.subgroupCheck());
}

test "G1 decompression: generator and [2]G round-trip (sort bit both values)" {
    // Generator: sort = 0 (its y is the lexicographically smaller root).
    const g_bytes = hexBytes(compressed_bytes, generator_compressed_hex);
    const g = try fromBytesCompressed(g_bytes);
    try std.testing.expect(g.x.eql(Affine.generator.x));
    try std.testing.expect(g.y.eql(Affine.generator.y));

    // [2]G: its compressed form has the sort bit SET (first byte 0xa5),
    // exercising the y-negation path in recoverY.
    const two_g_bytes = hexBytes(compressed_bytes, two_g_compressed_hex);
    try std.testing.expectEqual(@as(u8, 0xa5), two_g_bytes[0]);
    const two_g = try fromBytesCompressed(two_g_bytes);
    const expected = jacGen().double().toAffine();
    try std.testing.expect(two_g.x.eql(expected.x));
    try std.testing.expect(two_g.y.eql(expected.y));

    // Round-trip: compress what we decompressed, byte-identical.
    try std.testing.expectEqualSlices(u8, &two_g_bytes, &toBytesCompressed(two_g));
}

test "G1 decompression rejects an x with no square root (not on curve)" {
    // x = 1: 1^3 + 4 = 5 is a quadratic non-residue mod p (verified
    // independently — see NOTICE), so decompression must fail with
    // NotOnCurve.
    var comp = [_]u8{0} ** compressed_bytes;
    comp[0] = 0x80;
    comp[compressed_bytes - 1] = 1;
    try std.testing.expectError(G1Error.NotOnCurve, fromBytesCompressed(comp));
}

test "G1 uncompressed round-trip through Jacobian arithmetic" {
    const g5 = jacGen().double().double().add(jacGen()).toAffine(); // [5]G
    const bytes = toBytesUncompressed(g5);
    const back = try fromBytesUncompressed(bytes);
    try std.testing.expect(back.x.eql(g5.x));
    try std.testing.expect(back.y.eql(g5.y));
}

// ── F4 fast subgroup check: preconditions, endomorphism, differential ────
//
// `subgroupCheck` is `φ(P) == [-x²]P` (see its doc comment). These tests
// (1) re-derive, from this file's own constants, the two conditions the
// cited proposition needs, (2) pin `β` and `mulByAbsXPublic` against the
// constant-time ladder, and (3) hold the fast check against the
// definition `[r]P == O` (`subgroupCheckByOrder`) on points in AND out of
// the subgroup — every out-of-subgroup point is confirmed out by the
// reference first, so no classification is assumed.

fn beInt(comptime bytes: []const u8) comptime_int {
    comptime var v: comptime_int = 0;
    for (bytes) |byte| v = v * 256 + @as(comptime_int, byte);
    return v;
}

fn beBytes(comptime n: usize, comptime v: comptime_int) [n]u8 {
    return comptime blk: {
        var out: [n]u8 = undefined;
        var rest: comptime_int = v;
        var i: usize = n;
        while (i > 0) {
            i -= 1;
            out[i] = @intCast(@mod(rest, 256));
            rest = @divFloor(rest, 256);
        }
        if (rest != 0) @compileError("beBytes: value does not fit");
        break :blk out;
    };
}

fn gcdInt(comptime lhs: comptime_int, comptime rhs: comptime_int) comptime_int {
    var x = lhs;
    var y = rhs;
    while (y != 0) {
        const t = @mod(x, y);
        x = y;
        y = t;
    }
    return x;
}

const seed_u: comptime_int = -@as(comptime_int, bls_x_abs);
const p_int_t: comptime_int = beInt(&fp.p_bytes);
const r_int_t: comptime_int = beInt(&scalarmod.r_bytes);
const h1_int_t: comptime_int = beInt(&cofactor_bytes);

test "F4 subgroup G1: EHGP 2022/352 Proposition 4 preconditions hold for this curve" {
    const u = seed_u;
    // The BLS12 family polynomials at this seed (EHGP Example 2): the
    // module's p, r and h1 are exactly q(u), r(u), c1(u).
    try std.testing.expect(r_int_t == u * u * u * u - u * u + 1);
    try std.testing.expect(3 * h1_int_t == (u - 1) * (u - 1));
    try std.testing.expect(3 * (p_int_t - u) == (u - 1) * (u - 1) * r_int_t);
    // #E(Fp) = p + 1 - t, t = u + 1, and it is h1 * r.
    try std.testing.expect(h1_int_t * r_int_t == p_int_t + 1 - (u + 1));
    // χ = X² + X + 1, λ = -u²: χ(λ) = u⁴ - u² + 1 = r, so the gcd
    // condition of Proposition 2 is gcd(h1, r) = 1 — and r does not
    // divide h1, so E(Fp)[r] is exactly the order-r group G1.
    const lambda = -(u * u);
    try std.testing.expect(lambda * lambda + lambda + 1 == r_int_t);
    try std.testing.expect(gcdInt(h1_int_t, r_int_t) == 1);
    // β is a PRIMITIVE cube root of unity: β² + β + 1 = 0 (so β ≠ 1).
    try std.testing.expect(endomorphism_beta.square().add(endomorphism_beta).add(Fp.one).isZero());
}

test "F4 subgroup G1: φ acts as [-x²] on G1 (pins β) and [|x|] matches the constant-time ladder" {
    const g = jacGen();
    const x_abs = beBytes(8, bls_x_abs);
    const x_abs_int: comptime_int = bls_x_abs;
    const x_sq = comptime beBytes(16, x_abs_int * x_abs_int);
    try expectSamePoint(Jacobian.mulByAbsXPublic(g), g.scalarMulBytes(&x_abs));
    try expectSamePoint(Jacobian.endomorphismPhi(g), g.scalarMulBytes(&x_sq).negate());
    // G1 is cyclic, so the eigenvalue fixed on the generator holds for
    // every member; the other root β² would give λ² = x² - 1 instead.
    const other_root = comptime beBytes(16, x_abs_int * x_abs_int - 1);
    try std.testing.expect(!Jacobian.eqlPoints(Jacobian.endomorphismPhi(g), g.scalarMulBytes(&other_root)));
}

test "F4 subgroup G1: an off-curve isomorphic image of a member — old [r]P == O accepts, subgroupCheck refuses" {
    // (x, y) ↦ (a²x, a³y), a ∈ Fp, is an isomorphism onto y² = x³ + a⁶·b.
    // It commutes with the group law AND with φ (β scales x only), so the
    // image of a G1 member has order r and satisfies φ(P) = [−x²]P on its
    // own curve: the endomorphism equation alone cannot see that it is off
    // E. Only the curve-equation premise does — the definition-only
    // reference does not either, which is why this is the one input class
    // where the fast check is deliberately STRICTER than [r]P == O.
    const two = try Fp.fromInt(u8, 2);
    var k: [32]u8 = @splat(0);
    k[31] = 0x2b;
    const m = jacGen().scalarMulBytes(&k);
    const img: Jacobian = .{ .x = m.x.mul(two.square()), .y = m.y.mul(two.square().mul(two)), .z = m.z };
    try std.testing.expect(!img.isOnCurve());
    try std.testing.expect(img.subgroupCheckByOrder());
    const x2p = Jacobian.mulByAbsXPublic(Jacobian.mulByAbsXPublic(img));
    try std.testing.expect(Jacobian.eqlPoints(Jacobian.endomorphismPhi(img), x2p.negate()));
    try std.testing.expect(!img.subgroupCheck());
}

fn randomCurvePoint(rng: std.Random) Jacobian {
    while (true) {
        var buf: [Fp.encoded_bytes]u8 = undefined;
        rng.bytes(&buf);
        buf[0] &= 0x1f;
        const x = Fp.fromBytes(buf) catch continue;
        const y = x.square().mul(x).add(b).sqrt() orelse continue;
        return Jacobian.fromAffine(.{ .x = x, .y = y });
    }
}

fn expectMembership(p: Jacobian, member: bool) !void {
    // The reference decides what the point IS; the fast check must agree.
    try std.testing.expectEqual(member, p.subgroupCheckByOrder());
    try std.testing.expectEqual(member, p.subgroupCheck());
}

test "F4 subgroup G1: fast check == [r]P == O on members, non-members and off-curve points" {
    var prng = std.Random.DefaultPrng.init(0xf4_5b9_2026_0915);
    const rng = prng.random();
    var members: usize = 0;
    var outsiders: usize = 0;

    // Members: identity, generator, random multiples, cleared cofactors.
    try expectMembership(Jacobian.identity, true);
    try expectMembership(jacGen(), true);
    members += 2;
    for (0..12) |_| {
        var k: [32]u8 = undefined;
        rng.bytes(&k);
        try expectMembership(jacGen().scalarMulBytes(&k), true);
        members += 1;
    }
    for (0..4) |_| {
        try expectMembership(randomCurvePoint(rng).clearCofactor(), true);
        members += 1;
    }

    // Non-members: random curve points (no cofactor clearing) — each one
    // confirmed outside by the reference inside expectMembership.
    for (0..40) |_| {
        try expectMembership(randomCurvePoint(rng), false);
        outsiders += 1;
    }
    // Pure cofactor-torsion T = [r]R, and member + T (the malleation shape).
    for (0..8) |_| {
        const t = randomCurvePoint(rng).scalarMulBytes(&scalarmod.r_bytes);
        try std.testing.expect(!t.isIdentity());
        try expectMembership(t, false);
        var k: [32]u8 = undefined;
        rng.bytes(&k);
        try expectMembership(jacGen().scalarMulBytes(&k).add(t), false);
        outsiders += 2;
    }
    // Small-order points: for every prime l < 100 dividing h1, a point of
    // order exactly l, alone and added to the generator. Built from the
    // l-PRIMARY part, [#E/l^v]R (v = l's multiplicity in #E), then
    // multiplied by l until the next step would be O. ⚠ [#E/l]R is NOT
    // enough: 11² | h1, and when that part is Z/11 × Z/11 the group
    // exponent lacks one factor 11, so [#E/11]R = O for EVERY R (a first
    // draft of this test looped forever on exactly that).
    const small_primes = [_]comptime_int{ 2, 3, 5, 7, 11, 13, 17, 19, 23, 29, 31, 37, 41, 43, 47, 53, 59, 61, 67, 71, 73, 79, 83, 89, 97 };
    var small_orders: usize = 0;
    inline for (small_primes) |l| {
        if (comptime @mod(h1_int_t, l) == 0) {
            const k = comptime blk: {
                var m: comptime_int = h1_int_t * r_int_t;
                while (@mod(m, l) == 0) m = @divExact(m, l);
                break :blk beBytes(64, m);
            };
            const l_bytes = comptime beBytes(1, l);
            var t = Jacobian.identity;
            var tries: usize = 0;
            while (t.isIdentity()) : (tries += 1) {
                try std.testing.expect(tries < 8);
                t = randomCurvePoint(rng).scalarMulBytes(&k);
            }
            while (!t.scalarMulBytes(&l_bytes).isIdentity()) t = t.scalarMulBytes(&l_bytes);
            try std.testing.expect(!t.isIdentity());
            try expectMembership(t, false);
            try expectMembership(t.add(jacGen()), false);
            outsiders += 2;
            small_orders += 1;
        }
    }
    try std.testing.expectEqual(@as(usize, 2), small_orders); // h1 = 3 · 11² · (larger primes)²
    // The order-3 point (0, 2): x = 0 is the fixed line of φ itself.
    const two = try Fp.fromInt(u8, 2);
    try expectMembership(Jacobian.fromAffine(.{ .x = Fp.zero, .y = two }), false);
    outsiders += 1;

    // Off-curve points: both refuse (the fast check by its curve-equation
    // premise, the reference because [r]P lands nowhere near O).
    var off_curve: usize = 0;
    while (off_curve < 8) {
        const p = randomCurvePoint(rng);
        const bad: Jacobian = .{ .x = p.x.add(Fp.one), .y = p.y, .z = p.z };
        if (bad.isOnCurve()) continue;
        try expectMembership(bad, false);
        off_curve += 1;
    }
    var bad_gen = jacGen().scalarMulBytes(&beBytes(1, 7));
    bad_gen.y = bad_gen.y.add(Fp.one);
    try std.testing.expect(!bad_gen.isOnCurve());
    try expectMembership(bad_gen, false);

    try std.testing.expectEqual(@as(usize, 18), members);
    try std.testing.expectEqual(@as(usize, 61), outsiders);
}
