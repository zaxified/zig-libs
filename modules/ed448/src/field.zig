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
//! Every stored `Fe` is a CANONICAL representative (`0 <= value < p`) —
//! the same storage convention `bls12_381/src/fp.zig` documents for its
//! own field (see that module's "MONTGOMERY-STORAGE CONVENTION" note):
//! `fromBytes` rejects non-canonical input outright, and every arithmetic
//! op below must return a fully-reduced (not just "less than 2^456") limb
//! set — carrying unreduced headroom ACROSS a public API boundary (e.g. in
//! `toBytes`, or in `isOdd`'s parity read) would silently break both.
//! This is a contract the arithmetic below upholds (every op finishes
//! with `reduceAfterFold`'s full renormalization + canonical subtract),
//! not an optional optimization.
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
    pub const zero: Fe = .{ .limbs = [_]u64{0} ** num_limbs };

    /// The multiplicative identity.
    pub const one: Fe = .{ .limbs = blk: {
        var l = [_]u64{0} ** num_limbs;
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

    /// Serializes to little-endian 56 bytes. REAL, PROVIDED `fe` is
    /// already canonical (`< p` per-limb-and-in-aggregate) — the storage
    /// convention every arithmetic op must uphold (module doc comment).
    /// Pure inverse of `fromBytes`'s limb packing: no reduction performed
    /// here.
    pub fn toBytes(fe: Fe) [encoded_bytes]u8 {
        var out: [encoded_bytes]u8 = undefined;
        inline for (0..num_limbs) |i| {
            const limb = fe.limbs[i];
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

    /// `true` iff `fe == 0`. Constant-time: ORs every limb of the
    /// CANONICAL representative (storage convention, module doc comment —
    /// every `Fe` reaching a public API boundary is fully reduced, so the
    /// zero element has exactly one limb pattern) into one accumulator,
    /// then does a single data-independent comparison. No early exit, no
    /// branch on individual limb values.
    pub fn isZero(fe: Fe) bool {
        var acc: u64 = 0;
        for (fe.limbs) |l| acc |= l;
        return acc == 0;
    }

    /// Constant-time equality of two CANONICAL representatives: XOR every
    /// limb pair into one accumulator (canonical storage makes limb-wise
    /// equality equivalent to field equality), single final comparison —
    /// no early exit, no branch on secret limb values.
    pub fn eql(a: Fe, b: Fe) bool {
        var acc: u64 = 0;
        for (a.limbs, b.limbs) |x, y| acc |= x ^ y;
        return acc == 0;
    }

    /// Shared reduction tail for `add`/`sub`/`mul`: takes 8 unreduced
    /// limb accumulators, each `< 2^58` (the widest any caller produces —
    /// `mul`'s post-fold limbs are sums of at most 4 terms `< 2^56`),
    /// and returns the fully-reduced canonical `Fe`. Constant-time: fixed
    /// three carry-propagate+fold rounds followed by one branch-free
    /// conditional subtraction of `p`.
    ///
    /// Bounds argument (why exactly three rounds always suffice):
    /// - Round 1 input limbs `< 2^58`, so the running carry never exceeds
    ///   3 and the final carry-out `c1 <= 3`. Folding (`2^448 ≡ 2^224 + 1
    ///   (mod p)`: add `c1` to limbs 0 and 4) leaves limbs `<= 2^56 + 2`
    ///   and total value `< 2^448 + 4*(2^224 + 1) < 2^449`.
    /// - Round 2 therefore carries out `c2 <= 1`; if `c2 == 1` the
    ///   remaining value is `< 4*2^224 + 4` (limbs 5..7 zero, limb 4
    ///   tiny), so folding `c2` cannot push any limb past `2^56 - 1`.
    /// - Round 3 consequently has no carry-out at all; it exists only to
    ///   renormalize the (at most) two limbs round 2's fold touched.
    /// After round 3 every limb is `< 2^56` and the value is `< 2^448 <
    /// 2p`, so ONE conditional subtract of `p` canonicalizes.
    fn reduceAfterFold(r_in: [num_limbs]u128) Fe {
        var r = r_in;
        inline for (0..3) |_| {
            var carry: u128 = 0;
            inline for (0..num_limbs) |i| {
                const cur = r[i] + carry;
                r[i] = cur & limb_mask;
                carry = cur >> limb_bits;
            }
            // Fold the carry-out: carry * 2^448 ≡ carry * (2^224 + 1).
            r[0] += carry;
            r[4] += carry;
        }
        var limbs: [num_limbs]u64 = undefined;
        inline for (0..num_limbs) |i| limbs[i] = @intCast(r[i]);
        return condSubP(limbs);
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

    /// `a + b (mod p)`. Construction: schoolbook 8-limb addition followed
    /// by a Solinas-style reduction exploiting `2^448 ≡ 2^224 + 1 (mod
    /// p)` — i.e. any bit set above position 447 folds back in as a
    /// shifted-by-224 addition plus a unit addition, NOT a generic
    /// division. See the module doc comment's "Limb representation"
    /// section for why 56-bit limbs make this fold land on a limb
    /// boundary (no partial-limb shifting needed at the fold point).
    /// Must be constant-time (no branch on limb values) and MUST leave
    /// `limbs` fully renormalized (`< 2^56` each, `< p` in aggregate) per
    /// the storage convention — a lazily-reduced intermediate result
    /// (allowed mid-computation, using the limbs' 8 spare high bits) must
    /// be fully carried/folded before this function returns.
    pub fn add(a: Fe, b: Fe) Fe {
        var r: [num_limbs]u128 = undefined;
        inline for (0..num_limbs) |i| r[i] = @as(u128, a.limbs[i]) + b.limbs[i]; // < 2^57
        return reduceAfterFold(r);
    }

    /// `a - b (mod p)`. Construction: add a fixed multiple of `p` to `a`
    /// first (to guarantee no borrow below zero across the whole
    /// subtraction — the standard "add 2p or a comptime-chosen multiple
    /// of p before subtracting" trick used by essentially every
    /// constant-time modular-subtraction implementation, including
    /// `std.crypto.ecc.Edwards25519.Fe.sub`'s own 25519 analogue), then
    /// subtract `b` limb-wise with borrow propagation, then fold per
    /// `add`'s reduction. Constant-time; fully renormalized on return.
    pub fn sub(a: Fe, b: Fe) Fe {
        // Per-limb `a[i] + 2*p[i] - b[i]` is always non-negative
        // (2*p_limbs[i] >= 2^57 - 4 > 2^56 - 1 >= b.limbs[i]) so no
        // borrow chain is needed at all; the aggregate value is
        // `a + 2p - b ≡ a - b (mod p)` with every limb < 2^58, exactly
        // reduceAfterFold's input contract.
        var r: [num_limbs]u128 = undefined;
        inline for (0..num_limbs) |i| {
            r[i] = @as(u128, a.limbs[i]) + 2 * @as(u128, p_limbs[i]) - b.limbs[i];
        }
        return reduceAfterFold(r);
    }

    /// `-a (mod p)`, i.e. `p - a` (or `0` if `a == 0`). Construction:
    /// `sub(Fe.zero, a)` — no separate primitive needed, mirroring
    /// `bls12_381.Fp.neg`'s identical delegation.
    pub fn neg(a: Fe) Fe {
        return sub(Fe.zero, a);
    }

    /// `a * b (mod p)`. Construction: full 8×8-limb schoolbook
    /// multiplication into a 16-limb (896-bit) double-width accumulator,
    /// THEN a Solinas/Goldilocks reduction exploiting `2^448 ≡ 2^224 + 1
    /// (mod p)` to fold the high 8 limbs back into the low 8 — the
    /// standard technique for this exact prime shape (see e.g. Mike
    /// Hamburg's original Goldilocks paper / `libdecaf`'s 64-bit `p448`
    /// backend, both cited as design references in `NOTICE`; NOT ported
    /// source — this module's own limb layout/API is independent).
    /// Constant-time; fully renormalized (`< 2^56` per limb) on return.
    /// This — along with `square` — is the PERFORMANCE-CRITICAL inner
    /// loop the whole 56-bit/Solinas-reduction design choice (module doc
    /// comment) exists to make fast; a correct-but-slow fallback via
    /// `std.crypto.ff.Modulus(448)` is a legitimate STOPGAP if a
    /// crypto-core pass wants field arithmetic working before optimizing,
    /// but that is a deliberate trade against this module's stated
    /// design rationale, not the intended end state.
    pub fn mul(a: Fe, b: Fe) Fe {
        // 8×8 schoolbook into 15 u128 column accumulators (column i+j
        // sums at most 8 products of 56-bit limbs: < 8 * 2^112 < 2^115).
        var cols = [_]u128{0} ** 15;
        inline for (0..num_limbs) |i| {
            inline for (0..num_limbs) |j| {
                cols[i + j] += @as(u128, a.limbs[i]) * b.limbs[j];
            }
        }
        return reduceProduct(cols);
    }

    /// Shared carry-propagate + Goldilocks fold tail for `mul`/`square`:
    /// takes the 15 double-width column accumulators of an 8×8 (or
    /// symmetric-8×8) product (each `< 2^116`, the widest either caller
    /// produces) and returns the fully-reduced canonical `Fe`.
    ///
    /// Carry-propagate the columns into 16 clean 56-bit limbs. The full
    /// product is `< 2^896 = 2^(16*56)`, so the carry out of column 14 is
    /// the entire limb 15 (`< 2^56`) and nothing spills past it. Then the
    /// Goldilocks fold: writing the 896-bit product as four 224-bit
    /// (4-limb) chunks `A + B*2^224 + C*2^448 + D*2^672` and using
    /// `2^448 ≡ 2^224 + 1`, `2^672 ≡ 2*2^224 + 1 (mod p)`:
    ///   `product ≡ (A + C + D) + (B + C + 2D) * 2^224`
    /// — every term lands exactly on a limb boundary (the whole point of
    /// the 56-bit layout; no cross-limb shifting), leaving 8 accumulators
    /// each `< 4 * 2^56 = 2^58`, `reduceAfterFold`'s input contract.
    fn reduceProduct(cols: [15]u128) Fe {
        var t: [16]u64 = undefined;
        var carry: u128 = 0;
        inline for (0..15) |i| {
            const cur = cols[i] + carry;
            t[i] = @intCast(cur & limb_mask);
            carry = cur >> limb_bits;
        }
        t[15] = @intCast(carry);
        var r: [num_limbs]u128 = undefined;
        inline for (0..4) |i| {
            r[i] = @as(u128, t[i]) + t[8 + i] + t[12 + i];
            r[4 + i] = @as(u128, t[4 + i]) + t[8 + i] + 2 * @as(u128, t[12 + i]);
        }
        return reduceAfterFold(r);
    }

    /// `a^2 (mod p)`. Construction: identical to `mul(a, a)` but a
    /// dedicated squaring routine skips the ~half of the schoolbook
    /// cross-terms that are exact duplicates under `a*b == b*a` (the
    /// usual squaring speedup — same idea `std.crypto.ecc.Edwards25519.
    /// Fe.sq`/`bls12_381.Fp.square` (`modulus.sq`) both apply for their
    /// own fields). A correct-but-unoptimized fallback of literally
    /// `mul(a, a)` is acceptable as a first pass; the dedicated
    /// half-schoolbook version is a documented follow-up, not a
    /// correctness requirement.
    pub fn square(a: Fe) Fe {
        // Dedicated squaring: exploit `a[i]*a[j] == a[j]*a[i]` so each
        // off-diagonal cross product is computed ONCE and doubled, halving
        // the 8×8 schoolbook's multiplies (28 cross products + 8 diagonals
        // vs 64). Structurally symmetric and data-independent ⇒ still
        // constant-time in the base. Column bound: at most one diagonal
        // (`a[k/2]^2 < 2^112`) plus ≤4 doubled cross products
        // (`2*a[i]*a[j] < 2^113`) ⇒ each column `< 2^112 + 4*2^113 < 2^116`,
        // inside `reduceProduct`'s input contract.
        var cols = [_]u128{0} ** 15;
        inline for (0..num_limbs) |i| {
            cols[2 * i] += @as(u128, a.limbs[i]) * a.limbs[i];
            inline for (i + 1..num_limbs) |j| {
                cols[i + j] += 2 * (@as(u128, a.limbs[i]) * a.limbs[j]);
            }
        }
        return reduceProduct(cols);
    }

    /// `a * s (mod p)` for a small (`< 2^32`) PUBLIC comptime scalar `s`.
    /// Much cheaper than a full `mul` against a field element: a single
    /// 56×≤32-bit partial product per limb (8 multiplies) instead of the
    /// 8×8 schoolbook (64). Used by `x448.zig`'s ladder for the `a24 * E`
    /// step (`a24 = 39081`), which was a full `Fe.mul` against a
    /// comptime-built field element (audit F5). Constant-time: `s` is a
    /// public compile-time constant and the per-limb schedule is fixed.
    ///
    /// Bound: each `a.limbs[i] * s < 2^56 * 2^32 = 2^88`; the running
    /// carry stays `< 2^32`, so the final carry-out of limb 7 is `< 2^33`.
    /// Folding it via `2^448 ≡ 2^224 + 1` into limbs 0 and 4 leaves those
    /// `< 2^56 + 2^33 < 2^58`, `reduceAfterFold`'s input contract.
    pub fn mulSmall(a: Fe, comptime s: u32) Fe {
        var r: [num_limbs]u128 = undefined;
        var carry: u128 = 0;
        inline for (0..num_limbs) |i| {
            const cur = @as(u128, a.limbs[i]) * s + carry;
            r[i] = cur & limb_mask;
            carry = cur >> limb_bits;
        }
        r[0] += carry;
        r[4] += carry;
        return reduceAfterFold(r);
    }

    /// Multiplicative inverse; `error.NotInvertible` if `a == 0`.
    /// Construction: Fermat's little theorem, `a^(p-2) mod p`, via
    /// `pow(a, inv_exponent_be)` — RFC 8032 §5.2.1's own recommended
    /// construction ("it is recommended to use the identity
    /// x^-1 = x^(p-2) (mod p). Inverting zero should never happen").
    /// `p-2`'s bytes are a FIXED PUBLIC exponent (`inv_exponent_be`,
    /// precomputed above), so this needs no runtime `Fe` subtraction; the
    /// EXPONENT is public either way, so no separate "public vs
    /// constant-time-secret exponent" variant is needed here (contrast
    /// `bls12_381.Fp.inv`'s doc comment, which discusses that same
    /// distinction for `std.crypto.ff`'s two `pow` variants — this
    /// module's own `pow` need not expose the distinction until a
    /// crypto-core pass decides it wants the public-exponent speed
    /// optimization).
    pub fn invert(a: Fe) error{NotInvertible}!Fe {
        if (a.isZero()) return error.NotInvertible;
        return a.pow(inv_exponent_be); // a^(p-2), Fermat (RFC 8032 §5.2.1)
    }

    /// `a^e (mod p)`, `e` a BIG-ENDIAN 56-byte exponent (note: the
    /// OPPOSITE endianness from `fromBytes`/`toBytes`'s little-endian
    /// VALUE encoding — a deliberate convention split, matching
    /// `bls12_381.Fp.pow`'s own big-endian-exponent choice, so a
    /// crypto-core pass does not need to invent a fresh convention).
    /// Construction: square-and-multiply (or a fixed-window variant) over
    /// `mul`/`square`, MSB-to-LSB. `invert` and `sqrt` are this
    /// function's only current callers, both with FIXED PUBLIC exponents
    /// (`inv_exponent_be`, `sqrt_exponent_be`), so a fully
    /// constant-time-in-the-BASE (branch only on public exponent bits,
    /// never on `a`'s value) square-and-multiply is sufficient — no
    /// constant-time-in-the-exponent requirement exists for THIS module's
    /// own two callers, though a general-purpose `pow` intended for
    /// future secret-exponent callers (there are none yet) would want
    /// that property too.
    pub fn pow(a: Fe, e: [encoded_bytes]u8) Fe {
        // Square-and-ALWAYS-multiply, MSB-to-LSB: constant-time in the
        // base (mul/square are), and — beyond this module's own two
        // fixed-public-exponent callers' needs — constant-time in the
        // exponent too, by computing the multiply unconditionally and
        // mask-selecting the result (defense-in-depth for hypothetical
        // future secret-exponent callers; costs one extra mul per bit).
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
    /// Construction: RFC 8032 §5.2.1's own recipe — `p ≡ 3 (mod 4)`
    /// (confirmed: `p_bytes[0] == 0xff`, i.e. `p mod 4 == 3` reading the
    /// little-endian low byte), so the simple case applies directly:
    /// candidate `c = a^((p+1)/4) mod p` via `pow(a, sqrt_exponent_be)`;
    /// verify `c^2 == a` (`c.square().eql(a)`) — if it doesn't, `a` has
    /// no square root, return `null`. Identical shape to
    /// `bls12_381.Fp.sqrt`'s own `p ≡ 3 (mod 4)` case (that field is
    /// ALSO `3 mod 4`) — no Tonelli-Shanks general case is needed for
    /// either.
    pub fn sqrt(a: Fe) ?Fe {
        const c = a.pow(sqrt_exponent_be); // a^((p+1)/4), p ≡ 3 (mod 4)
        return if (c.square().eql(a)) c else null;
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
    /// secret-dependent index) — both inputs are canonical by the storage
    /// convention (module doc comment), so limb-wise selection yields the
    /// canonical representative of whichever operand was chosen. This
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
    var expected = [_]u8{0} ** encoded_bytes;
    expected[0] = 1;
    try std.testing.expectEqualSlices(u8, &expected, &o);
}

test "Fe.fromBytes rejects p itself (non-canonical) and accepts p-1" {
    try std.testing.expectError(error.NonCanonical, Fe.fromBytes(p_bytes));

    var p_minus_1 = p_bytes;
    p_minus_1[0] -= 1; // p's low byte is 0xff, no borrow needed
    _ = try Fe.fromBytes(p_minus_1);
}

test "Fe.fromBytes / toBytes round-trip on an arbitrary canonical value (REAL codec)" {
    var bytes = [_]u8{0} ** encoded_bytes;
    bytes[0] = 0x12;
    bytes[1] = 0x34;
    bytes[27] = 0xab; // well below p's high byte, stays canonical
    const fe = try Fe.fromBytes(bytes);
    try std.testing.expectEqualSlices(u8, &bytes, &fe.toBytes());
}

test "Fe.isOdd reads the low bit of the canonical encoding (REAL)" {
    try std.testing.expect(!Fe.zero.isOdd());
    try std.testing.expect(Fe.one.isOdd());
    var two_bytes = [_]u8{0} ** encoded_bytes;
    two_bytes[0] = 2;
    try std.testing.expect(!(try Fe.fromBytes(two_bytes)).isOdd());
}

test "Fe.ctSelect / Fe.ctSwap pick the right operand (REAL)" {
    var a_bytes = [_]u8{0} ** encoded_bytes;
    a_bytes[0] = 7;
    var b_bytes = [_]u8{0} ** encoded_bytes;
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
    var expected = [_]u8{0} ** encoded_bytes;
    expected[0] = 2;
    try std.testing.expectEqualSlices(u8, &expected, &a.add(a).toBytes());
}

test "p limb form matches p_bytes" {
    // p_limbs is an internal constant (condSubP's subtrahend); check it
    // against the independently-derived p_bytes wire form by packing it
    // through the same codec an Fe uses.
    const p_as_fe = Fe{ .limbs = p_limbs };
    try std.testing.expectEqualSlices(u8, &p_bytes, &p_as_fe.toBytes());
}

/// A fixed, arbitrary canonical test element used by the self-checks
/// below (bytes deliberately spread across several limbs; high byte kept
/// well below p's).
fn testElement() Fe {
    var bytes = [_]u8{0} ** encoded_bytes;
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
    var two_bytes = [_]u8{0} ** encoded_bytes;
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
