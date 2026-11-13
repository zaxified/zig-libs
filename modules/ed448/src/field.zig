// SPDX-License-Identifier: MIT
//! `Fp448` — the "Goldilocks" prime field `GF(p)`, `p = 2^448 - 2^224 - 1`
//! (RFC 7748 §4.2, "curve448"). This is the single base field shared by
//! BOTH `x448.zig` (RFC 7748 §5, the Montgomery ladder over curve448) and
//! `ed448.zig` (RFC 8032 §5.2, EdDSA over edwards448) — mirroring how
//! `std.crypto.ecc`'s `curve25519.zig`/`edwards25519.zig` both sit on one
//! shared `field.zig` for Curve25519/Edwards25519.
//!
//! **Status: implemented.** The byte codec (`fromBytes`/`toBytes`,
//! `rejectNonCanonical`), the constant-time `ctSelect`/`ctSwap`, AND the
//! full field arithmetic (`add`/`sub`/`neg`/`mul`/`square`/`invert`/
//! `pow`/`sqrt`, all constant-time over the base) are real — the
//! Goldilocks/Solinas reduction described below is what `mul`/`add`/`sub`
//! implement (see `reduceAfterFold`'s bounds argument). Validated
//! transitively by the RFC 7748/8032 KATs in `../kat_test.zig` plus the
//! field self-checks at the bottom of this file.
//!
//! ## Limb representation (the open design choice this scaffold settles)
//!
//! `Fe` stores **8 limbs of `u64`, each holding a 56-bit "digit"** —
//! `value = sum(limbs[i] * 2^(56*i) for i in 0..8)`. This is the classic
//! "Goldilocks" choice (e.g. `libdecaf`'s 64-bit backend, Mike Hamburg's
//! original curve448 papers): `p`'s two terms `2^448` and `2^224` both
//! land EXACTLY on a limb boundary (448 = 8*56, 224 = 4*56), so the
//! Solinas-style reduction `x mod p` for a double-width product reduces to
//! a handful of limb-aligned shifted additions (`hi_448 + hi_224 + lo`,
//! roughly) with NO cross-limb bit-shifting inside the reduction step
//! itself — unlike, say, a 32-bit-limb or byte-aligned-but-not-56
//! representation, which would need a shift by a non-limb-boundary amount
//! at the fold point. 56 bits also leaves 8 spare bits of headroom in each
//! `u64` limb for CARRY ACCUMULATION across several unreduced
//! adds/subtracts before a renormalization pass is needed (the same
//! "lazy reduction" trick `std.crypto.ecc.field.zig`'s 51-bit
//! Curve25519/Edwards25519 limbs use, scaled up for the wider modulus) —
//! this is the main reason 56-bit limbs are the standard choice over, say,
//! 8 raw 56-bit-PACKED (no headroom) limbs. The alternative this module
//! deliberately did NOT take is delegating to `std.crypto.ff.Modulus(448)`
//! (the way `bls12_381/src/fp.zig` does for its field) — that generic
//! Montgomery big-integer path is CORRECT and would make this field REAL
//! today, but is measurably slower than a modulus-specific Solinas
//! reduction for a prime shaped exactly like this one (the entire reason
//! `p = 2^448 - 2^224 - 1` was chosen for curve448 over an arbitrary
//! 448-bit prime — RFC 7748 §4.2's own stated rationale, "recommended for
//! performance on a wide range of architectures"); using it here would
//! throw away the one performance property that makes this specific prime
//! interesting. Byte layout is UNCHANGED by this choice either way — see
//! `fromBytes`/`toBytes` below — so a future switch to `ff` (or to 16
//! limbs of 28 bits for a 32-bit-word target) would not change this
//! module's public API.
//!
//! ## Weak reduction (since 2026-11-13)
//!
//! An `Fe` is WEAKLY reduced: every limb `< 2^57`, value any representative
//! of its residue class below `2^457`. `add`/`sub`/`mulSmall` end with one
//! parallel carry step (`carryWeak`) and `mul`/`square` with one carry pass
//! after the Goldilocks fold (`reduceColumns`); none of them subtracts `p`.
//! The CANONICAL representative (`0 <= value < p`) is produced only where a
//! value leaves the arithmetic or is compared — `toBytes`, `isOdd` (through
//! `toBytes`), `isZero`, `eql`, all via `canonical` — so those, and the
//! byte codec, behave exactly as before. `fromBytes` and the constants are
//! canonical, which is also weak. `ctSelect`/`ctSwap` are limb-wise and need
//! no canonical form. Until 2026-11-13 every operation returned the
//! canonical form (three carry rounds and a conditional subtraction after
//! each `add`, `sub` and `mul`): 43 % of an Ed448/X448 profile was that
//! reduction. Code outside this file never reads `limbs`.
//!
//! Source: RFC 7748 §4.2 (the prime, in the "curve448" parameter table)
//! and RFC 8032 §5.2.1 ("Modular Arithmetic" — inversion via `a^(p-2)`,
//! square roots via the `p ≡ 3 (mod 4)` candidate-and-verify recipe).

const std = @import("std");

/// Errors from parsing/decoding an `Fe` from bytes.
pub const FieldError = error{NonCanonical};

/// Fixed-size little-endian wire encoding of an `Fp448` element — 56 bytes
/// (448 bits exactly; `p` has no spare high bit, unlike Curve25519's
/// 255-bit `p` inside a 32-byte/256-bit container). This is the SAME
/// width RFC 7748 §5 uses for X448's `u`-coordinates; RFC 8032's
/// point/scalar codecs (`ed448.zig`) use a WIDER 57-byte encoding of
/// their own (`b = 456` bits) to make room for a point's sign bit — that
/// extra byte is `ed448.zig`'s concern, not this field's native width.
pub const encoded_bytes = 56;

/// Number of `u64` limbs `Fe` is stored as. See the module doc comment's
/// "Limb representation" section for why 8×56-bit was chosen.
pub const num_limbs = 8;

/// Bits per limb (see module doc comment).
pub const limb_bits = 56;
const limb_mask: u64 = (1 << limb_bits) - 1;

/// Parses a fixed-length compile-time hex string into bytes — same
/// comptime helper `bls12_381/src/fp.zig` uses for its own embedded
/// constants (`hexBytes`), duplicated locally per that module's own
/// precedent (no shared `_template`-style helper module exists yet for
/// this purpose).
fn hexBytes(comptime n: usize, comptime hex: *const [2 * n:0]u8) [n]u8 {
    @setEvalBranchQuota(100_000);
    var out: [n]u8 = undefined;
    _ = std.fmt.hexToBytes(&out, hex) catch unreachable;
    return out;
}

/// `p = 2^448 - 2^224 - 1`, little-endian, 56 bytes (RFC 7748 §4.2).
/// Independently re-derivable as `2**448 - 2**224 - 1`; the hex below was
/// cross-checked against that computation at scaffold time (see
/// `NOTICE`'s "Verification performed" section).
pub const p_bytes: [encoded_bytes]u8 = hexBytes(encoded_bytes, "fffffffffffffffffffffffffffffffffffffffffffffffffffffffffeffffffffffffffffffffffffffffffffffffffffffffffffffffff");

/// `p - 2`, big-endian, 56 bytes — the Fermat inversion exponent
/// (`Fe.invert`, RFC 8032 §5.2.1: "it is recommended to use the identity
/// x^-1 = x^(p-2) (mod p)"). Exponents to `Fe.pow` are BIG-endian by
/// convention (distinct from the field's own little-endian VALUE
/// encoding in `fromBytes`/`toBytes` — see `pow`'s doc comment).
const inv_exponent_be: [encoded_bytes]u8 = hexBytes(encoded_bytes, "fffffffffffffffffffffffffffffffffffffffffffffffffffffffefffffffffffffffffffffffffffffffffffffffffffffffffffffffd");

/// `(p+1)/4`, big-endian, 56 bytes — the square-root candidate exponent
/// for the `p ≡ 3 (mod 4)` case (RFC 8032 §5.2.1: "square roots modulo p
/// ... can be computed by first computing candidate root
/// x = a^((p+1)/4) (mod p) and then checking if x^2 = a"). `p`'s low byte
/// is `0xff` (`p_bytes[0]`, little-endian) i.e. `p ≡ 3 (mod 4)` — the
/// simple case applies, no Tonelli-Shanks needed.
const sqrt_exponent_be: [encoded_bytes]u8 = hexBytes(encoded_bytes, "3fffffffffffffffffffffffffffffffffffffffffffffffffffffffc0000000000000000000000000000000000000000000000000000000");

/// `p` in the 8×56-bit limb layout: `p = (2^448 - 1) - 2^224`, i.e. every
/// limb is `2^56 - 1` except limb 4 (the one whose bit 0 is bit 224 of
/// the value), which is `2^56 - 2`. Cross-checked against `p_bytes` by
/// the "p limb form matches p_bytes" test below.
const p_limbs: [num_limbs]u64 = .{
    limb_mask,     limb_mask, limb_mask, limb_mask,
    limb_mask - 1, limb_mask, limb_mask, limb_mask,
};

/// An element of `GF(p)`, `p = 2^448 - 2^224 - 1`. See the module doc
/// comment for the 8×56-bit limb layout.
pub const Fe = struct {
    /// `value = sum(limbs[i] * 2^(56*i) for i in 0..8)`. Each limb SHOULD
    /// be kept `< 2^56` (canonical/normalized) at every public API
    /// boundary — see the module doc comment's storage-convention note.
    /// The extra 8 high bits per `u64` are headroom for lazy-reduction
    /// carry accumulation inside the arithmetic implementation
    /// (`reduceAfterFold` and friends), not part of the field value
    /// itself.
    limbs: [num_limbs]u64,

    /// The additive identity.
    pub const zero: Fe = .{ .limbs = @as([num_limbs]u64, @splat(0)) };

    /// The multiplicative identity.
    pub const one: Fe = .{ .limbs = blk: {
        var l = @as([num_limbs]u64, @splat(0));
        l[0] = 1;
        break :blk l;
    } };

    /// Parses a little-endian 56-byte value, REJECTING anything `>= p`
    /// (non-canonical) — same convention as `Edwards25519`'s
    /// `rejectNonCanonical` / `bls12_381.Fp.fromBytes`. REAL: pure byte
    /// unpacking into 8×56-bit limbs (56 bits = exactly 7 bytes, so each
    /// limb maps onto a byte-aligned 7-byte window with no cross-limb bit
    /// splitting — the whole point of the 56-bit choice) plus the
    /// canonical-range check below.
    pub fn fromBytes(bytes: [encoded_bytes]u8) FieldError!Fe {
        try rejectNonCanonical(bytes);
        var limbs: [num_limbs]u64 = undefined;
        inline for (0..num_limbs) |i| {
            var limb: u64 = 0;
            inline for (0..7) |j| {
                limb |= @as(u64, bytes[i * 7 + j]) << (8 * j);
            }
            limbs[i] = limb;
        }
        return .{ .limbs = limbs };
    }

    /// Serializes the canonical representative (`canonical`, see "Weak
    /// reduction" in the module doc comment) to little-endian 56 bytes:
    /// the inverse of `fromBytes`'s limb packing.
    pub fn toBytes(fe: Fe) [encoded_bytes]u8 {
        const c = fe.canonical();
        var out: [encoded_bytes]u8 = undefined;
        inline for (0..num_limbs) |i| {
            const limb = c.limbs[i];
            inline for (0..7) |j| {
                out[i * 7 + j] = @intCast((limb >> (8 * j)) & 0xff);
            }
        }
        return out;
    }

    /// Check that a 56-byte encoding is canonical (`< p`), REAL:
    /// constant-time big-integer byte-array comparison against `p_bytes`
    /// (little-endian, so compare from the most-significant byte, index
    /// `encoded_bytes - 1`, downward) — same shape as
    /// `std.crypto.ecc.Edwards25519.Fe`'s own `rejectNonCanonical` (which
    /// does the analogous comparison against `2^255-19`) and
    /// `bls12_381.Fp.fromBytes`'s delegated `std.crypto.ff` canonical
    /// check.
    pub fn rejectNonCanonical(bytes: [encoded_bytes]u8) FieldError!void {
        var i: usize = encoded_bytes;
        var is_less: u8 = 0; // 1 once a strictly-smaller byte has been seen
        var is_equal_so_far: u8 = 1;
        while (i > 0) {
            i -= 1;
            const b = bytes[i];
            const pb = p_bytes[i];
            // Constant-time-ish byte compare (no early return / branch on
            // secret data — canonical-range checks operate on
            // caller-supplied wire bytes, which are public in every call
            // site this module anticipates, but the same discipline as
            // std's own field codecs is followed here regardless).
            const lt: u8 = @intFromBool(b < pb);
            const eq: u8 = @intFromBool(b == pb);
            is_less |= is_equal_so_far & lt;
            is_equal_so_far &= eq;
        }
        if (is_less == 0) return error.NonCanonical; // bytes >= p
    }

    /// The canonical representative (`0 <= value < p`, every limb
    /// `< 2^56`) of a weakly reduced `fe` (see "Weak reduction" in the
    /// module doc comment). Constant-time: a FIXED three carry-propagate +
    /// fold rounds, then one branch-free conditional subtraction of `p`.
    ///
    /// Bounds argument (why exactly three rounds always suffice; written
    /// for input limbs `< 2^58`, and every weakly reduced `Fe` has them
    /// `< 2^57`):
    /// - Round 1: the running carry never exceeds 3 and the final carry-out
    ///   `c1 <= 3`. Folding (`2^448 ≡ 2^224 + 1 (mod p)`: add `c1` to limbs
    ///   0 and 4) leaves limbs `<= 2^56 + 2` and total value
    ///   `< 2^448 + 4*(2^224 + 1) < 2^449`.
    /// - Round 2 therefore carries out `c2 <= 1`; if `c2 == 1` the
    ///   remaining value is `< 4*2^224 + 4` (limbs 5..7 zero, limb 4
    ///   tiny), so folding `c2` cannot push any limb past `2^56 - 1`.
    /// - Round 3 consequently has no carry-out at all; it exists only to
    ///   renormalize the (at most) two limbs round 2's fold touched.
    /// After round 3 every limb is `< 2^56` and the value is `< 2^448 <
    /// 2p`, so ONE conditional subtract of `p` canonicalizes.
    pub fn canonical(fe: Fe) Fe {
        var r = fe.limbs;
        inline for (0..3) |_| {
            var carry: u64 = 0;
            inline for (0..num_limbs) |i| {
                const cur = r[i] + carry;
                r[i] = cur & limb_mask;
                carry = cur >> limb_bits;
            }
            // Fold the carry-out: carry * 2^448 ≡ carry * (2^224 + 1).
            r[0] += carry;
            r[4] += carry;
        }
        return condSubP(r);
    }

    /// `true` iff `fe == 0` (mod p). Constant-time: ORs every limb of the
    /// CANONICAL representative into one accumulator, then does a single
    /// data-independent comparison. No early exit, no branch on individual
    /// limb values.
    pub fn isZero(fe: Fe) bool {
        var acc: u64 = 0;
        for (fe.canonical().limbs) |l| acc |= l;
        return acc == 0;
    }

    /// Constant-time field equality: XOR every limb pair of the two
    /// CANONICAL representatives into one accumulator, single final
    /// comparison — no early exit, no branch on secret limb values.
    pub fn eql(a: Fe, b: Fe) bool {
        var acc: u64 = 0;
        for (a.canonical().limbs, b.canonical().limbs) |x, y| acc |= x ^ y;
        return acc == 0;
    }

    /// Branch-free `if (v >= p) v -= p` over canonical-width limbs (each
    /// `< 2^56`, value `< 2^448 < 2p`). Computes the trial subtraction
    /// with borrow propagation, then mask-selects between the original
    /// and subtracted limb sets based on the final borrow — same shape as
    /// `ctSelect`'s byte-mask merge, no data-dependent branch.
    fn condSubP(limbs: [num_limbs]u64) Fe {
        var diff: [num_limbs]u64 = undefined;
        var borrow: u64 = 0;
        inline for (0..num_limbs) |i| {
            // limbs[i] < 2^56 and p_limbs[i] < 2^56, so a negative true
            // result wraps into [2^64 - 2^56 - 1, 2^64), i.e. bit 63 set;
            // a non-negative result is < 2^56, bit 63 clear.
            const t = limbs[i] -% p_limbs[i] -% borrow;
            borrow = t >> 63;
            diff[i] = t & limb_mask;
        }
        // borrow == 1 -> v < p -> keep the original limbs.
        const keep: u64 = 0 -% borrow;
        var out: [num_limbs]u64 = undefined;
        inline for (0..num_limbs) |i| out[i] = (limbs[i] & keep) | (diff[i] & ~keep);
        return .{ .limbs = out };
    }

    /// One PARALLEL carry step back to the weak bound: every limb keeps its
    /// low 56 bits plus the carry out of the limb below it, and the carry
    /// out of limb 7 folds into limbs 0 and 4 (`2^448 ≡ 2^224 + 1`). For
    /// input limbs `< 2^(56+k)` the output limbs are `< 2^56 + 2^(k+1)`
    /// (limb 4 takes two carries) — weakly reduced for any `k <= 55`. No
    /// carry chain: the eight limbs are independent.
    inline fn carryWeak(r: [num_limbs]u64) Fe {
        var out: [num_limbs]u64 = undefined;
        const top = r[num_limbs - 1] >> limb_bits;
        out[0] = (r[0] & limb_mask) + top;
        inline for (1..num_limbs) |i| out[i] = (r[i] & limb_mask) + (r[i - 1] >> limb_bits);
        out[4] += top;
        return .{ .limbs = out };
    }

    /// `a + b (mod p)`, weakly reduced: a limb-wise sum (limbs `< 2^58`)
    /// and one `carryWeak` step (limbs `< 2^56 + 8`). Constant-time.
    pub fn add(a: Fe, b: Fe) Fe {
        var r: [num_limbs]u64 = undefined;
        inline for (0..num_limbs) |i| r[i] = a.limbs[i] + b.limbs[i];
        return carryWeak(r);
    }

    /// `4p` limb-wise: every limb `4 * (2^56 - 1)`, limb 4 `4 * (2^56 - 2)`
    /// — each at least `2^58 - 8`, above any weakly reduced limb.
    const four_p: [num_limbs]u64 = blk: {
        var l: [num_limbs]u64 = undefined;
        for (0..num_limbs) |i| l[i] = 4 * p_limbs[i];
        break :blk l;
    };

    /// `a - b (mod p)`, weakly reduced: per limb `a[i] + 4p[i] - b[i]`,
    /// which is never negative (`4p[i] >= 2^58 - 8 > 2^57 > b[i]`) and
    /// `< 2^59`, so no borrow chain; the value `a + 4p - b ≡ a - b`. Then
    /// one `carryWeak` step (limbs `< 2^56 + 16`). Constant-time.
    pub fn sub(a: Fe, b: Fe) Fe {
        var r: [num_limbs]u64 = undefined;
        inline for (0..num_limbs) |i| r[i] = a.limbs[i] + four_p[i] - b.limbs[i];
        return carryWeak(r);
    }

    /// `-a (mod p)`, i.e. `sub(Fe.zero, a)`.
    pub fn neg(a: Fe) Fe {
        return sub(Fe.zero, a);
    }

    /// `a * b (mod p)`, weakly reduced. Construction: full 8×8-limb
    /// schoolbook multiplication into 15 `u128` column accumulators, then
    /// `reduceColumns` (the Goldilocks fold `2^448 ≡ 2^224 + 1` applied to
    /// the columns, one carry pass). Design references: Mike Hamburg's
    /// Goldilocks paper / `libdecaf`'s 64-bit `p448` backend, cited in
    /// `NOTICE`; NOT ported source. Constant-time.
    ///
    /// Bound: weakly reduced inputs have limbs `< 2^57`, so each product is
    /// `< 2^114` and a column of at most 8 products `< 2^117`.
    pub fn mul(a: Fe, b: Fe) Fe {
        var cols = @as([15]u128, @splat(0));
        inline for (0..num_limbs) |i| {
            inline for (0..num_limbs) |j| {
                cols[i + j] += @as(u128, a.limbs[i]) * b.limbs[j];
            }
        }
        return reduceColumns(cols);
    }

    /// Shared tail of `mul`/`square`: 15 double-width columns (each
    /// `< 2^118`) to a weakly reduced `Fe`.
    ///
    /// 1. Fold the high columns, highest first: column `k >= 8` stands for
    ///    `2^(56k) = 2^448 * 2^(56(k-8)) ≡ 2^(56(k-4)) + 2^(56(k-8))`, so it
    ///    is added to columns `k-4` and `k-8`; columns 12..14 land on 8..10,
    ///    which are folded in turn. No limb shifting: every term lands on a
    ///    limb boundary (the point of the 56-bit layout). Each of columns
    ///    0..7 ends as a sum of at most four inputs: `< 2^120`.
    /// 2. ONE sequential carry pass over the 8 columns. Its carry-out is
    ///    `< 2^65`; folded into limbs 0 and 4, and the (`< 2^10`) carries
    ///    out of those two into limbs 1 and 5. Every limb ends `< 2^57`.
    ///
    /// Until 2026-11-13 every product was carried through all 15 columns
    /// and then FULLY reduced (three carry rounds and a conditional
    /// subtraction of `p`): 43 % of an Ed448/X448 profile.
    inline fn reduceColumns(cols_in: [15]u128) Fe {
        var c = cols_in;
        inline for (0..7) |t| {
            const k = 14 - t;
            c[k - 4] += c[k];
            c[k - 8] += c[k];
        }
        var out: [num_limbs]u64 = undefined;
        var carry: u128 = 0;
        inline for (0..num_limbs) |i| {
            const cur = c[i] + carry;
            out[i] = @as(u64, @truncate(cur)) & limb_mask;
            carry = cur >> limb_bits;
        }
        const l0 = @as(u128, out[0]) + carry;
        out[0] = @as(u64, @truncate(l0)) & limb_mask;
        out[1] += @intCast(l0 >> limb_bits);
        const l4 = @as(u128, out[4]) + carry;
        out[4] = @as(u64, @truncate(l4)) & limb_mask;
        out[5] += @intCast(l4 >> limb_bits);
        return .{ .limbs = out };
    }

    /// `a^2 (mod p)`, weakly reduced. Dedicated squaring: each off-diagonal
    /// cross product is computed ONCE and doubled (28 cross products + 8
    /// diagonals vs 64). Structurally symmetric and data-independent ⇒
    /// constant-time in the base. Column bound for limbs `< 2^57`: one
    /// diagonal (`< 2^114`) plus ≤ 4 doubled cross products (`< 2^115`
    /// each) ⇒ `< 2^118`, inside `reduceColumns`'s contract.
    pub fn square(a: Fe) Fe {
        var cols = @as([15]u128, @splat(0));
        inline for (0..num_limbs) |i| {
            cols[2 * i] += @as(u128, a.limbs[i]) * a.limbs[i];
            inline for (i + 1..num_limbs) |j| {
                cols[i + j] += 2 * (@as(u128, a.limbs[i]) * a.limbs[j]);
            }
        }
        return reduceColumns(cols);
    }

    /// `a^(2^n)`: `n` successive squarings (`n` public, comptime).
    fn squareN(a: Fe, comptime n: usize) Fe {
        var r = a;
        for (0..n) |_| r = r.square();
        return r;
    }

    /// `a * s (mod p)` for a small (`< 2^32`) PUBLIC comptime scalar `s`,
    /// weakly reduced. Much cheaper than a full `mul` against a field
    /// element: one 57×32-bit partial product per limb (8 multiplies)
    /// instead of the 8×8 schoolbook (64). Used by `x448.zig`'s ladder for
    /// the `a24 * E` step (`a24 = 39081`), which was a full `Fe.mul`
    /// against a comptime-built field element (audit F5). Constant-time:
    /// `s` is a public compile-time constant and the schedule is fixed.
    ///
    /// Bound: each product is `< 2^57 * 2^32 = 2^89`; its high part
    /// (`>> 56`) `< 2^33` moves one limb up (limb 7's folds into 0 and 4),
    /// so every limb ends `< 2^56 + 2^34`.
    pub fn mulSmall(a: Fe, comptime s: u32) Fe {
        var lo: [num_limbs]u64 = undefined;
        var hi: [num_limbs]u64 = undefined;
        inline for (0..num_limbs) |i| {
            const pr = @as(u128, a.limbs[i]) * s;
            lo[i] = @as(u64, @truncate(pr)) & limb_mask;
            hi[i] = @intCast(pr >> limb_bits);
        }
        var out: [num_limbs]u64 = undefined;
        out[0] = lo[0] + hi[num_limbs - 1];
        inline for (1..num_limbs) |i| out[i] = lo[i] + hi[i - 1];
        out[4] += hi[num_limbs - 1];
        return .{ .limbs = out };
    }

    /// `e222 = a^(2^222 - 1)`, the shared head of `invert`'s and `sqrt`'s
    /// addition chains (`e_k = a^(2^k - 1)`, built by
    /// `e_(j+k) = e_j^(2^k) * e_k`), and `e2` for `sqrt`'s tail. 227
    /// squarings, 10 multiplications.
    fn chainHead(a: Fe) struct { e2: Fe, e222: Fe } {
        const e2 = a.square().mul(a);
        const e3 = e2.square().mul(a);
        const e6 = e3.squareN(3).mul(e3);
        const e12 = e6.squareN(6).mul(e6);
        const e24 = e12.squareN(12).mul(e12);
        const e30 = e24.squareN(6).mul(e6);
        const e48 = e24.squareN(24).mul(e24);
        const e96 = e48.squareN(48).mul(e48);
        const e192 = e96.squareN(96).mul(e96);
        const e222 = e192.squareN(30).mul(e30);
        return .{ .e2 = e2, .e222 = e222 };
    }

    /// Multiplicative inverse; `error.NotInvertible` if `a == 0`.
    /// Fermat's little theorem, `a^(p-2) mod p` (RFC 8032 §5.2.1: "it is
    /// recommended to use the identity x^-1 = x^(p-2) (mod p)"), by a fixed
    /// addition chain: `p - 2 = 2^225 * (2^223 - 1) + 4 * (2^222 - 1) + 1`,
    /// so `a^(p-2) = e223^(2^225) * e222^4 * a` with `e223 = e222^2 * a`
    /// (`chainHead`). 455 squarings and 13 multiplications —
    /// `pow(a, p - 2)`, the generic
    /// square-and-always-multiply this was until 2026-11-13, spends 448 of
    /// each. The chain is fixed and public: constant-time in `a`.
    pub fn invert(a: Fe) error{NotInvertible}!Fe {
        if (a.isZero()) return error.NotInvertible;
        const h = chainHead(a);
        const e223 = h.e222.square().mul(a);
        return e223.squareN(225).mul(h.e222.squareN(2).mul(a));
    }

    /// `a^e (mod p)`, `e` a BIG-ENDIAN 56-byte exponent (note: the
    /// OPPOSITE endianness from `fromBytes`/`toBytes`'s little-endian
    /// VALUE encoding — a deliberate convention split, matching
    /// `bls12_381.Fp.pow`'s own big-endian-exponent choice). Square-and-
    /// ALWAYS-multiply, MSB-to-LSB: constant-time in the base AND in the
    /// exponent (the multiply is computed every bit and mask-selected).
    /// `invert` and `sqrt` use fixed addition chains instead (2026-11-13);
    /// this stays for callers with other exponents (`decaf448`).
    pub fn pow(a: Fe, e: [encoded_bytes]u8) Fe {
        var result = Fe.one;
        for (e) |byte| {
            var k: u4 = 0;
            while (k < 8) : (k += 1) {
                result = result.square();
                const bit = (byte >> @intCast(7 - k)) & 1;
                result = ctSelect(bit == 1, result.mul(a), result);
            }
        }
        return result;
    }

    /// Square root, or `null` if `a` is not a quadratic residue.
    /// RFC 8032 §5.2.1's recipe for `p ≡ 3 (mod 4)` (`p_bytes[0] == 0xff`):
    /// candidate `c = a^((p+1)/4)`, verified by `c^2 == a`. The exponent
    /// is `(p+1)/4 = 2^446 - 2^222 = 2^222 * (2^224 - 1)`, so
    /// `c = e224^(2^222)` with `e224 = e222^4 * e2` (`chainHead`): 451
    /// squarings, 11 multiplications
    /// (the generic `pow` until 2026-11-13: 448 of each). Constant-time in
    /// `a` up to the residue verdict.
    pub fn sqrt(a: Fe) ?Fe {
        const h = chainHead(a);
        const c = h.e222.squareN(2).mul(h.e2).squareN(222);
        return if (c.square().eql(a)) c else null;
    }

    /// `sqrt(u / v)`, or `null` if `u / v` is not a square (or `v == 0`
    /// while `u != 0`), with no separate inversion: RFC 8032 §5.2.3's
    /// combined power for edwards448, `x = u^3 * v * (u^5 * v^3)^((p-3)/4)`,
    /// accepted iff `v * x^2 == u`. `(p-3)/4 = 2^223 * (2^223 - 1) +
    /// (2^222 - 1)`, so the power is `e223^(2^223) * e222` over `chainHead`
    /// — one 451-squaring chain where `invert` + `sqrt` took two. Used by
    /// point decoding (`ed448.zig`). Constant-time in `u`, `v` up to the
    /// verdict.
    pub fn sqrtRatio(u: Fe, v: Fe) ?Fe {
        const u_sq = u.square();
        const u_cu = u_sq.mul(u);
        const v_cu = v.square().mul(v);
        const t = u_cu.mul(u_sq).mul(v_cu); // u^5 v^3
        const h = chainHead(t);
        const e223 = h.e222.square().mul(t);
        const pw = e223.squareN(223).mul(h.e222);
        const x = u_cu.mul(v).mul(pw);
        return if (v.mul(x.square()).eql(u)) x else null;
    }

    /// `true` iff the canonical representative of `a` is odd — the "x_0"
    /// / sign bit RFC 8032 §5.2.2's point encoding copies into a point's
    /// final byte's top bit (`ed448.zig`'s `Point.toBytes`/`fromBytes`
    /// call this on the recovered `x` coordinate). Valid PROVIDED `a` is
    /// already canonical (storage convention, module doc comment): the
    /// parity of a little-endian integer's canonical representative is
    /// simply its lowest bit, i.e. `toBytes()[0] & 1` — no field
    /// arithmetic needed.
    pub fn isOdd(a: Fe) bool {
        return (a.toBytes()[0] & 1) == 1;
    }

    /// Constant-time select: returns `a` if `cond`, else `b` — the
    /// building block a constant-time Montgomery ladder (`x448.zig`) or
    /// constant-time windowed scalar multiplication (`ed448.zig`) needs
    /// for its conditional swaps and masked table scans. Operates
    /// LIMB-LEVEL (a single 64-bit mask merge per limb, no branch, no
    /// secret-dependent index): the result is whichever operand's limbs
    /// were chosen, weakly reduced like both inputs. This
    /// replaces an earlier `toBytes`/`fromBytes` round-trip merge: the
    /// masked select sits on the hot path of every windowed scalarmul, so
    /// the two serializations + reparse per select were a real cost
    /// (audit F5).
    pub fn ctSelect(cond: bool, a: Fe, b: Fe) Fe {
        const mask: u64 = @as(u64, 0) -% @intFromBool(cond);
        var out: [num_limbs]u64 = undefined;
        inline for (0..num_limbs) |i| out[i] = (a.limbs[i] & mask) | (b.limbs[i] & ~mask);
        return .{ .limbs = out };
    }

    /// Constant-time conditional swap of `a` and `b` — the Montgomery
    /// ladder's `cswap` (RFC 7748 §5), built directly on `ctSelect`. REAL
    /// for the same reason `ctSelect` is.
    pub fn ctSwap(cond: bool, a: *Fe, b: *Fe) void {
        const na = ctSelect(cond, b.*, a.*);
        const nb = ctSelect(cond, a.*, b.*);
        a.* = na;
        b.* = nb;
    }

    /// A uniformly random field element. Construction: rejection-sample
    /// 56 random bytes from `io` until `fromBytes` accepts — same
    /// technique/rationale as `bls12_381.Fp.random`'s own doc comment
    /// (must NOT use a biased `bytes mod p` reduction over a same-width
    /// sample). REAL: delegates entirely to `fromBytes`'s already-real
    /// canonical check, no field arithmetic of its own.
    pub fn random(io: std.Io) Fe {
        var buf: [encoded_bytes]u8 = undefined;
        while (true) {
            io.random(&buf);
            return Fe.fromBytes(buf) catch continue;
        }
    }
};

// ── tests ────────────────────────────────────────────────────────────────

test "p is 448 bits, odd, and ≡ 3 (mod 4)" {
    try std.testing.expectEqual(@as(u8, 0xff), p_bytes[0]); // low byte
    try std.testing.expect(p_bytes[0] & 1 == 1);
    try std.testing.expect(p_bytes[0] & 3 == 3); // p mod 4 == 3
    try std.testing.expectEqual(@as(u8, 0xff), p_bytes[encoded_bytes - 1]); // high byte nonzero -> 448 bits
}

test "Fe.zero / Fe.one round-trip through bytes (REAL codec)" {
    const z = Fe.zero.toBytes();
    try std.testing.expect(std.mem.allEqual(u8, &z, 0));
    const o = Fe.one.toBytes();
    var expected = @as([encoded_bytes]u8, @splat(0));
    expected[0] = 1;
    try std.testing.expectEqualSlices(u8, &expected, &o);
}

test "Fe.fromBytes rejects p itself (non-canonical) and accepts p-1" {
    try std.testing.expectError(error.NonCanonical, Fe.fromBytes(p_bytes));

    var p_minus_1 = p_bytes;
    p_minus_1[0] -= 1; // p's low byte is 0xff, no borrow needed
    _ = try Fe.fromBytes(p_minus_1);
}

test "Fe.isZero and Fe.eql read every limb" {
    // 2^440 (only the top byte set; < p, so canonical) is not zero, and it
    // differs from 0 and 2^440 + 1 from 1 although their low limbs agree.
    var bytes = @as([encoded_bytes]u8, @splat(0));
    bytes[encoded_bytes - 1] = 1;
    const top = try Fe.fromBytes(bytes);
    try std.testing.expect(!top.isZero());
    try std.testing.expect(!top.eql(Fe.zero));
    bytes[0] = 1;
    const top_plus_one = try Fe.fromBytes(bytes);
    try std.testing.expect(!top_plus_one.eql(Fe.one));
}

test "Fe.fromBytes / toBytes round-trip on an arbitrary canonical value (REAL codec)" {
    var bytes = @as([encoded_bytes]u8, @splat(0));
    bytes[0] = 0x12;
    bytes[1] = 0x34;
    bytes[27] = 0xab; // well below p's high byte, stays canonical
    const fe = try Fe.fromBytes(bytes);
    try std.testing.expectEqualSlices(u8, &bytes, &fe.toBytes());
}

test "Fe.isOdd reads the low bit of the canonical encoding (REAL)" {
    try std.testing.expect(!Fe.zero.isOdd());
    try std.testing.expect(Fe.one.isOdd());
    var two_bytes = @as([encoded_bytes]u8, @splat(0));
    two_bytes[0] = 2;
    try std.testing.expect(!(try Fe.fromBytes(two_bytes)).isOdd());
}

test "Fe.ctSelect / Fe.ctSwap pick the right operand (REAL)" {
    var a_bytes = @as([encoded_bytes]u8, @splat(0));
    a_bytes[0] = 7;
    var b_bytes = @as([encoded_bytes]u8, @splat(0));
    b_bytes[0] = 9;
    const a = try Fe.fromBytes(a_bytes);
    const b = try Fe.fromBytes(b_bytes);
    try std.testing.expectEqualSlices(u8, &a.toBytes(), &Fe.ctSelect(true, a, b).toBytes());
    try std.testing.expectEqualSlices(u8, &b.toBytes(), &Fe.ctSelect(false, a, b).toBytes());

    var sa = a;
    var sb = b;
    Fe.ctSwap(true, &sa, &sb);
    try std.testing.expectEqualSlices(u8, &b.toBytes(), &sa.toBytes());
    try std.testing.expectEqualSlices(u8, &a.toBytes(), &sb.toBytes());

    var na = a;
    var nb = b;
    Fe.ctSwap(false, &na, &nb);
    try std.testing.expectEqualSlices(u8, &a.toBytes(), &na.toBytes());
    try std.testing.expectEqualSlices(u8, &b.toBytes(), &nb.toBytes());
}

test "Fe.random produces canonical, (overwhelmingly) distinct elements (REAL)" {
    var threaded = std.Io.Threaded.init(std.testing.allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();

    const a = Fe.random(io);
    const b = Fe.random(io);
    _ = try Fe.fromBytes(a.toBytes()); // round-trips => canonical
    try std.testing.expect(!std.mem.eql(u8, &a.toBytes(), &b.toBytes())); // collide w/ prob ~2^-448
}

test "Fe arithmetic: a + a == 2" {
    const a = Fe.one;
    var expected = @as([encoded_bytes]u8, @splat(0));
    expected[0] = 2;
    try std.testing.expectEqualSlices(u8, &expected, &a.add(a).toBytes());
}

test "p limb form matches p_bytes" {
    // p_limbs is an internal constant (condSubP's subtrahend); check it
    // against the independently-derived p_bytes wire form by packing it
    // through the same codec an Fe uses.
    // `toBytes` canonicalizes since 2026-11-13 (p itself encodes as 0), so
    // the limbs are packed here directly, 7 bytes each.
    var packed_p: [encoded_bytes]u8 = undefined;
    for (p_limbs, 0..) |limb, i| {
        for (0..7) |j| packed_p[i * 7 + j] = @truncate(limb >> @intCast(8 * j));
    }
    try std.testing.expectEqualSlices(u8, &p_bytes, &packed_p);
    // And as a (weakly reduced) field element p is zero.
    const p_as_fe = Fe{ .limbs = p_limbs };
    try std.testing.expect(p_as_fe.isZero());
    try std.testing.expect(std.mem.allEqual(u8, &p_as_fe.toBytes(), 0));
}

/// A fixed, arbitrary canonical test element used by the self-checks
/// below (bytes deliberately spread across several limbs; high byte kept
/// well below p's).
fn testElement() Fe {
    var bytes = @as([encoded_bytes]u8, @splat(0));
    for (&bytes, 0..) |*b, i| b.* = @intCast((i * 37 + 11) % 251);
    bytes[encoded_bytes - 1] = 0x3a; // < 0xff, comfortably canonical
    return Fe.fromBytes(bytes) catch unreachable;
}

test "Fe arithmetic: add/sub/neg round-trip and identities" {
    const a = testElement();
    // a - a == 0, a + (-a) == 0
    try std.testing.expect(a.sub(a).isZero());
    try std.testing.expect(a.add(a.neg()).isZero());
    // (a + a) - a == a
    try std.testing.expect(a.add(a).sub(a).eql(a));
    // p - 1 + 2 == 1 (wraps the modulus)
    var pm1_bytes = p_bytes;
    pm1_bytes[0] -= 1;
    const pm1 = try Fe.fromBytes(pm1_bytes);
    var two_bytes = @as([encoded_bytes]u8, @splat(0));
    two_bytes[0] = 2;
    const two = try Fe.fromBytes(two_bytes);
    try std.testing.expect(pm1.add(two).eql(Fe.one));
}

test "Fe arithmetic: mul identities and mul/square agreement" {
    const a = testElement();
    try std.testing.expect(a.mul(Fe.one).eql(a));
    try std.testing.expect(a.mul(Fe.zero).isZero());
    try std.testing.expect(a.square().eql(a.mul(a)));
    // (a+1)^2 == a^2 + 2a + 1
    const a1 = a.add(Fe.one);
    const lhs = a1.square();
    const rhs = a.square().add(a.add(a)).add(Fe.one);
    try std.testing.expect(lhs.eql(rhs));
}

test "Fe arithmetic: a * a^-1 == 1; invert(0) errors" {
    const a = testElement();
    const a_inv = try a.invert();
    try std.testing.expect(a.mul(a_inv).eql(Fe.one));
    try std.testing.expectError(error.NotInvertible, Fe.zero.invert());
}

test "Fe arithmetic: sqrt(a^2) squares back to a^2; a known non-residue has no root" {
    const a = testElement();
    const a2 = a.square();
    const root = a2.sqrt() orelse return error.TestUnexpectedResult;
    try std.testing.expect(root.square().eql(a2));
    // -(a^2) is a non-residue: p ≡ 3 (mod 4) makes -1 a non-residue, so
    // exactly one of x, -x is a QR for any nonzero x.
    try std.testing.expect(a2.neg().sqrt() == null);
}

// ── weak reduction against an independent oracle (2026-11-13) ─────────────
//
// `std.crypto.ff` over the same prime is the oracle: an unrelated generic
// Montgomery implementation. Operands include the values next to `0`, `p`
// and `2^224`, and long chains of operations that never canonicalize in
// between, so the bounds in "Weak reduction" are exercised at their edges.

const OracleM = std.crypto.ff.Modulus(448);

fn oracleFe(m: OracleM, fe: Fe) !OracleM.Fe {
    return OracleM.Fe.fromBytes(m, &fe.toBytes(), .little);
}

fn expectMatches(got: Fe, want: OracleM.Fe) !void {
    var wb: [encoded_bytes]u8 = undefined;
    try want.toBytes(&wb, .little);
    try std.testing.expectEqualSlices(u8, &wb, &got.toBytes());
}

fn feFromP(minus: u8) !Fe {
    var b = p_bytes;
    b[0] -= minus;
    return Fe.fromBytes(b);
}

test "weak reduction: add/sub/mul/square/mulSmall/neg match std.crypto.ff on edge values and long unreduced chains" {
    const m = try OracleM.fromBytes(&p_bytes, .little);
    var edge: [7]Fe = undefined;
    edge[0] = Fe.zero;
    edge[1] = Fe.one;
    edge[2] = try feFromP(1); // p - 1
    edge[3] = try feFromP(2); // p - 2
    var b224 = @as([encoded_bytes]u8, @splat(0));
    b224[28] = 1; // 2^224
    edge[4] = try Fe.fromBytes(b224);
    var b224m1 = @as([encoded_bytes]u8, @splat(0));
    @memset(b224m1[0..28], 0xff); // 2^224 - 1
    edge[5] = try Fe.fromBytes(b224m1);
    edge[6] = testElement();

    for (edge) |a| for (edge) |b| {
        const oa = try oracleFe(m, a);
        const ob = try oracleFe(m, b);
        try expectMatches(a.add(b), m.add(oa, ob));
        try expectMatches(a.sub(b), m.sub(oa, ob));
        try expectMatches(a.mul(b), m.mul(oa, ob));
        try std.testing.expectEqual(a.eql(b), oa.eql(ob));
    };
    const s1 = try OracleM.Fe.fromPrimitive(u32, m, 39081);
    const s2 = try OracleM.Fe.fromPrimitive(u32, m, 0xffffffff);
    for (edge) |a| {
        const oa = try oracleFe(m, a);
        try expectMatches(a.square(), m.sq(oa));
        try expectMatches(a.neg(), m.sub(m.zero, oa));
        try expectMatches(a.mulSmall(39081), m.mul(oa, s1));
        try expectMatches(a.mulSmall(0xffffffff), m.mul(oa, s2));
    }

    // Chains with no canonical form in between: every intermediate is only
    // weakly reduced, and each step feeds the next.
    const opm1 = try oracleFe(m, edge[2]);
    var x = edge[2];
    var ox = opm1;
    var y = edge[6];
    var oy = try oracleFe(m, y);
    for (0..3000) |i| {
        switch (i % 6) {
            0 => {
                x = x.add(y);
                ox = m.add(ox, oy);
            },
            1 => {
                y = y.sub(x);
                oy = m.sub(oy, ox);
            },
            2 => {
                x = x.mul(y).add(x);
                ox = m.add(m.mul(ox, oy), ox);
            },
            3 => {
                y = y.square().sub(edge[2]);
                oy = m.sub(m.sq(oy), opm1);
            },
            4 => {
                x = x.neg().mulSmall(0xffffffff);
                ox = m.mul(m.sub(m.zero, ox), s2);
            },
            else => {
                y = y.add(y).add(y).add(y).sub(edge[2]).sub(edge[2]);
                oy = m.sub(m.sub(m.add(m.add(m.add(oy, oy), oy), oy), opm1), opm1);
            },
        }
    }
    try expectMatches(x, ox);
    try expectMatches(y, oy);
}

test "addition-chain invert and sqrt agree with the generic pow" {
    var a = testElement();
    for (0..16) |_| {
        const inv = try a.invert();
        try std.testing.expect(inv.eql(a.pow(inv_exponent_be)));
        try std.testing.expect(inv.mul(a).eql(Fe.one));
        const sq = a.square();
        const r = sq.sqrt() orelse return error.TestUnexpectedResult;
        try std.testing.expect(r.eql(sq.pow(sqrt_exponent_be)));
        try std.testing.expect(r.square().eql(sq));
        a = a.mul(a).add(Fe.one);
    }
    try std.testing.expectError(error.NotInvertible, Fe.zero.invert());
    try std.testing.expectError(error.NotInvertible, Fe.zero.sub(Fe.zero).invert());
}

test "sqrtRatio matches sqrt(u * v^-1), rejects non-squares" {
    var u = testElement();
    var v = testElement().square().add(Fe.one);
    for (0..16) |_| {
        const want = u.mul(try v.invert()).sqrt();
        const got = Fe.sqrtRatio(u, v);
        try std.testing.expectEqual(want == null, got == null);
        if (got) |x| {
            // Either root is acceptable; both square to u/v.
            try std.testing.expect(x.square().mul(v).eql(u));
            try std.testing.expect(x.eql(want.?) or x.eql(want.?.neg()));
        }
        u = u.mul(v).add(Fe.one);
        v = v.square().sub(u);
    }
    try std.testing.expect(Fe.sqrtRatio(Fe.zero, Fe.one).?.isZero());
}
