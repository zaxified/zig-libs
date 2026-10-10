// SPDX-License-Identifier: MIT

//! field — the NIST P-256 base field `Fe` over the Solinas prime
//! `p = 2^256 − 2^224 + 2^192 + 2^96 − 1`, stored as four full 2^64 limbs
//! (little-endian), NORMAL domain (not Montgomery — the special reduction is
//! used directly, as OpenSSL's nistz256 does for its field).
//!
//! The multiply/square hot path uses the curve-specific **P-256 Solinas
//! reduction**: a 256×256→512-bit schoolbook product, then the fold
//! `2^256 ≡ 2^224 − 2^192 − 2^96 + 1 (mod p)` collapses the high half back into
//! 256 bits (repeat until < 2^257), then two conditional folds of the final
//! carry bit + one constant-time conditional subtract of `p`. The portable path
//! ships that reduction written straightforwardly on wide (`u256`/`u512`)
//! integers — it is the correctness ORACLE, byte-exact against
//! `std.crypto.ecc.P256.Fe`. The irreducible `MULX/ADX` core
//! (`fast_core.fieldMul`/`fieldSq`, IMPLEMENTED, gated by
//! `gate.field_asm_implemented`) computes the same reduction via the NIST
//! word-shuffle and is pinned to this oracle by the gated differential; on
//! non-amd64 targets `mul`/`sq` dispatch to the portable reduction below.
//!
//! The API mirrors `std.crypto.ecc.P256.Fe` (same method names/semantics) so
//! `group.zig` is a drop-in over this field and the oracle differential is a
//! direct `p256.Fe.op(...) == std.Fe.op(...)` comparison via `toBytes`.

const std = @import("std");
const builtin = @import("builtin");
const gate = @import("gate.zig");
const fast_core = @import("fast_core.zig");
const modinv = @import("modinv.zig");

const NonCanonicalError = std.crypto.errors.NonCanonicalError;
const NotSquareError = std.crypto.errors.NotSquareError;

/// The NIST P-256 base-field prime `p = 2^256 − 2^224 + 2^192 + 2^96 − 1`.
pub const field_order: u256 = (1 << 256) - (1 << 224) + (1 << 192) + (1 << 96) - 1;

/// The P-256 Solinas fold constant `M = 2^224 − 2^192 − 2^96 + 1`, chosen so
/// that `2^256 ≡ M (mod p)`. Unlike secp256k1's tiny `c = 2^32+977`, P-256's
/// fold multiplier is ~2^224 (the reduction folds a *wide* value, not a small
/// one) — this is the defining curve-specific difference and the reason the
/// carry pattern of the gated asm core differs from k256's.
const m_fold: u256 = (1 << 224) - (1 << 192) - (1 << 96) + 1;

/// True iff `mul`/`sq` route to the gated amd64 asm core (`fast_core`) rather
/// than the portable Solinas reduction — i.e. on x86-64 with ADX+BMI2 now that
/// the gate is on; portable everywhere else.
pub const field_asm_active = fast_core.supported and gate.field_asm_implemented;

/// The safegcd constants for `p` (see `modinv.zig`).
const field_modinfo = modinv.ModInfo.init(field_order);

// ── constant-time barrier ───────────────────────────────────────────────────
//
// Launder a value through an empty inline-asm so LLVM loses all range/equality
// knowledge about it (montint `b199192`; the k256 powMont/normalize lesson).
// The portable `normalize`/`sub` select on a 0/1 carry/borrow bit via
// `mask = 0 − bit`; without this barrier LLVM recovers `bit ∈ {0,1}` and lowers
// the masked select to a data-dependent branch (`test/jne`) — a secret-dependent
// branch on any constant-time scalar-multiply path built over this field. The
// `@inComptime()` guard keeps it out of the comptime interpreter (inline asm
// cannot run there); it is a no-op at runtime otherwise.
inline fn blackBox(x: u64) u64 {
    if (@inComptime()) return x;
    return asm volatile (""
        : [ret] "=r" (-> u64),
        : [x] "0" (x),
    );
}

// ── wide-integer helpers (portable reduction substrate) ─────────────────────

inline fn toU256(l: [4]u64) u256 {
    return @as(u256, l[0]) | (@as(u256, l[1]) << 64) |
        (@as(u256, l[2]) << 128) | (@as(u256, l[3]) << 192);
}

inline fn fromU256(x: u256) [4]u64 {
    return .{ @truncate(x), @truncate(x >> 64), @truncate(x >> 128), @truncate(x >> 192) };
}

/// Reduce a value `s0 + carry·2^256` (with `s0 < 2^256`, `carry ∈ {0,1}`) into a
/// canonical field element `< p`. Constant-time: no branch on the value.
///
/// `2^256 ≡ M (mod p)` with `M < 2^224`, so the extra `carry·2^256` folds in as
/// `carry·M`. That first fold can re-overflow 2^256 (since `s0 < 2^256` and we
/// add `< 2^224`); the second fold of that new carry bit cannot overflow again
/// (its low word is then `< M < 2^224`, so `+M < 2^225`). After both folds the
/// value is `< 2^256 ≤ p + (2^256−p)`, so a single masked conditional subtract
/// of `p` lands it in `[0, p)`.
fn normalize(s0: u256, carry: u1) [4]u64 {
    const M: u256 = m_fold;
    // Fold the 257th bit: v = s0 + carry·M. Expressed as a MASK (`M & (0−carry)`,
    // bit-identical to `M·carry`) with the bit laundered through `blackBox` so
    // LLVM cannot recover carry ∈ {0,1} and emit a data-dependent branch.
    const cmask: u256 = @as(u256, 0) -% @as(u256, blackBox(@as(u64, carry)));
    const f = @addWithOverflow(s0, M & cmask);
    // A carry out here means the true sum reached 2^256, i.e. another `·M`; the
    // wrapped value is then `< M`, so `+M` cannot overflow again.
    const fmask: u256 = @as(u256, 0) -% @as(u256, blackBox(@as(u64, f[1])));
    var v: u256 = f[0] +% (M & fmask);
    // v < 2^256: one constant-time conditional subtract of p.
    const d = @subWithOverflow(v, field_order); // borrow ⇒ v < p (keep v)
    const keep: u256 = @as(u256, 0) -% @as(u256, blackBox(@as(u64, d[1])));
    v = (v & keep) | (d[0] & ~keep);
    return fromU256(v);
}

/// The portable P-256 Solinas reduction of a 512-bit product into a canonical
/// field element `< p`. This is what `fast_core.fieldMul`/`fieldSq` must
/// reproduce bit-for-bit with `MULX/ADX` limb arithmetic.
///
/// Each fold replaces the value by `(low 256 bits) + M·(high bits)`. Because
/// `M < 2^224`, the high part shrinks by ~32 bits per fold (NOT ~223 like
/// k256's tiny constant), so it takes more folds: from a `< 2^512` input, nine
/// folds provably reach `< 2^257` (a value with at most one excess bit), after
/// which `normalize` finishes. Eleven folds are used for margin; the assert
/// pins the bound. Fixed trip count ⇒ constant-time.
fn reduceWideFold(wide: u512) [4]u64 {
    const M: u512 = m_fold;
    const mask: u512 = (@as(u512, 1) << 256) - 1;
    var x = wide;
    inline for (0..11) |_| {
        x = (x & mask) + M * (x >> 256);
    }
    std.debug.assert((x >> 257) == 0); // ≤ one excess bit remains after the folds
    return normalize(@truncate(x & mask), @truncate(x >> 256));
}

/// Eight 32-bit words into a 256-bit value, most significant first — the order
/// the NIST reduction tables below are written in, so that each `s_i` reads
/// like its row in the reference rather than backwards.
inline fn words(a7: u32, a6: u32, a5: u32, a4: u32, a3: u32, a2: u32, a1: u32, a0: u32) u256 {
    return (@as(u256, a7) << 224) | (@as(u256, a6) << 192) |
        (@as(u256, a5) << 160) | (@as(u256, a4) << 128) |
        (@as(u256, a3) << 96) | (@as(u256, a2) << 64) |
        (@as(u256, a1) << 32) | @as(u256, a0);
}

/// The NIST/Solinas word-shuffle reduction, in portable Zig.
///
/// ⭐⭐⭐ **This exists because the fold above is linear in a fold count of
/// eleven, and that was measured, not guessed.** Dropping two of the eleven
/// folds moved the portable multiply from 2.40x `std`'s to 2.00x — exactly the
/// 2/11 the change removed — so the whole cost was the reduction and almost
/// none of it was the 512-bit product. Eleven passes of 512-bit arithmetic is
/// what made this module's *portable* path 2.4x slower than `std`'s portable
/// path, on a machine where the amd64 assembly hid it. On aarch64 there is no
/// assembly to hide behind, which is what made it worth fixing.
///
/// The algorithm is the one `fast_core.zig`'s assembly already implements
/// (HMV "Guide to ECC" Alg. 2.29): over the sixteen 32-bit product words,
///
///     r ≡ s1 + 2·s2 + 2·s3 + s4 + s5 − s6 − s7 − s8 − s9   (mod p)
///
/// where each `s_i` is a fixed permutation. One pass, no loop.
///
/// Constant-time: straight-line arithmetic over fixed-width integers, a fixed
/// number of operations, no branch and no secret-dependent index. The final
/// canonicalisation is `normalize`, which was already written for this and is
/// masked rather than branched.
fn reduceWideShuffle(wide: u512) [4]u64 {
    var c: [16]u32 = undefined;
    inline for (0..16) |i| c[i] = @truncate(wide >> (32 * i));

    const s1 = words(c[7], c[6], c[5], c[4], c[3], c[2], c[1], c[0]);
    const s2 = words(c[15], c[14], c[13], c[12], c[11], 0, 0, 0);
    const s3 = words(0, c[15], c[14], c[13], c[12], 0, 0, 0);
    const s4 = words(c[15], c[14], 0, 0, 0, c[10], c[9], c[8]);
    const s5 = words(c[8], c[13], c[15], c[14], c[13], c[11], c[10], c[9]);
    const s6 = words(c[10], c[8], 0, 0, 0, c[13], c[12], c[11]);
    const s7 = words(c[11], c[9], 0, 0, c[15], c[14], c[13], c[12]);
    const s8 = words(c[12], 0, c[10], c[9], c[8], c[15], c[14], c[13]);
    const s9 = words(c[13], 0, c[11], c[10], c[9], 0, c[15], c[14]);

    // Signed, because s6..s9 are subtracted and any of them can exceed the
    // running total. The sum lies in (−4·2^256, +7·2^256).
    const acc: i512 = @as(i512, s1) +
        2 * @as(i512, s2) + 2 * @as(i512, s3) +
        @as(i512, s4) + @as(i512, s5) -
        @as(i512, s6) - @as(i512, s7) - @as(i512, s8) - @as(i512, s9);

    // Shift into non-negative territory by a multiple of p, which changes
    // nothing mod p. Five is the smallest that works: the most negative
    // accumulator is > −4·2^256, and 5p > 4·2^256 because p > 2^256 − 2^224.
    const biased = acc + 5 * @as(i512, field_order);
    std.debug.assert(biased >= 0);
    // `@bitCast`, not `@intCast`: two's complement reinterpretation of a value
    // already proven non-negative, with no check to branch on.
    const v: u512 = @bitCast(biased);

    // v < 12·2^256, so the top is a handful of bits. Fold them with the one
    // identity this whole file rests on, 2^256 ≡ M (mod p).
    const top: u512 = v >> 256;
    const folded: u512 = (v & ((@as(u512, 1) << 256) - 1)) + top * @as(u512, m_fold);
    // top ≤ 11 and M < 2^224, so top·M < 2^228: the sum can carry into bit 256
    // but no further, which is exactly the shape `normalize` takes.
    std.debug.assert((folded >> 257) == 0);
    return normalize(@truncate(folded), @truncate(folded >> 256));
}

/// The portable reduction.
///
/// ⚠ **Where the independent oracle actually lives, since this is easy to get
/// wrong and the consequence is silent.** `oracle_test.zig`'s gated
/// differential pins the asm core against `mulPortable`/`sqPortable`, which
/// come through here — so both sides of that comparison now run the SAME
/// word-shuffle algorithm with the same `s_i` tables. It proves the assembly
/// implements the shuffle; it can no longer catch a shared misreading of the
/// shuffle itself.
///
/// The one comparison that still provides algorithmic independence is
/// `reduceWideFold` vs `reduceWideShuffle` in this file's own test
/// ("the word-shuffle reduction agrees with the fold, bit for bit"), which is
/// also the expensive one. **Do not trim it believing `oracle_test` covers the
/// fold — it does not reach `reduceWideFold` at all.**
fn reduceWide(wide: u512) [4]u64 {
    return reduceWideShuffle(wide);
}

// ── Montgomery domain (R = 2^256) — what `Fe` stores since 2026-10-10 ──────
//
// `Fe` holds `a·R mod p`, canonical (`< p`). The multiply is a 256×256→512
// product followed by a Montgomery REDC, which for this prime is the cheap
// reduction: `p ≡ −1 (mod 2^64)`, so `n0' = −p⁻¹ mod 2^64 = 1` and each of the
// four rounds' quotient digit is just the current low limb, and `m·p` is two
// shifts plus ONE 64×64 multiply (by `p₃ = 2^64 − 2^32 + 1`). Measured on the
// bench host (i7-7920HQ, ReleaseFast, chained): the MULX/ADX Montgomery
// multiply 68 TSC cycles against 131 for the word-shuffle Solinas multiply
// (`fast_core.fieldMul`, kept with its differential as a second normal-domain
// reduction). Constants, codecs and `isOdd`/`toInt` convert at the edges.

/// `R mod p` (`R = 2^256`) — the Montgomery form of 1.
const r_mod_p: u256 = @truncate((@as(u512, 1) << 256) % field_order);
/// `R² mod p` — `toMont(x) = REDC(x·R²)`.
const r2_mod_p: u256 = @truncate((@as(u512, r_mod_p) * r_mod_p) % field_order);
/// `R³ mod p` — turns safegcd's `(aR)⁻¹ = a⁻¹R⁻¹` into `a⁻¹R` in one REDC.
const r3_mod_p: u256 = @truncate((@as(u512, r2_mod_p) * r_mod_p) % field_order);
/// `(p + 1) / 2^64`: the REDC round `(t + m·p)/2^64` with `m = t mod 2^64` is
/// exactly `⌊t/2^64⌋ + m·((p+1)/2^64)` because `p + 1 ≡ 0 (mod 2^96)`.
const p1_shr64: u256 = (field_order + 1) >> 64;

/// The portable Montgomery reduction `REDC(t) = t·R⁻¹ mod p` for `t < p·R`
/// (any product of two canonical elements). Four rounds of the identity above,
/// then one masked conditional subtract: after the rounds `t < 2p`. Comptime-
/// evaluable (the comb table is built through it). The asm core
/// (`fast_core.montMul`/`montSq`) must reproduce it bit for bit.
fn montReducePortable(wide: u512) [4]u64 {
    var t = wide;
    inline for (0..4) |_| {
        const m: u64 = @truncate(t);
        t = (t >> 64) + @as(u512, m) * p1_shr64;
    }
    std.debug.assert((t >> 257) == 0);
    const lo: u256 = @truncate(t);
    const hi: u64 = @truncate(t >> 256); // 0 or 1
    const d = @subWithOverflow(lo, field_order);
    // keep `lo` iff the true value `hi·2^256 + lo` is < p: no high bit AND a borrow.
    const keep_bit: u64 = @as(u64, d[1]) & ~hi;
    const keep: u256 = @as(u256, 0) -% @as(u256, blackBox(keep_bit));
    return fromU256((lo & keep) | (d[0] & ~keep));
}

/// `z = a·b·R⁻¹ mod p`, portable (the oracle the Montgomery asm mirrors).
pub fn montMulPortable(a: [4]u64, b: [4]u64) [4]u64 {
    return montReducePortable(@as(u512, toU256(a)) * @as(u512, toU256(b)));
}

/// `z = a²·R⁻¹ mod p`, portable.
pub fn montSqPortable(a: [4]u64) [4]u64 {
    const av: u512 = toU256(a);
    return montReducePortable(av * av);
}

inline fn montMulLimbs(a: [4]u64, b: [4]u64) [4]u64 {
    if (field_asm_active and !@inComptime()) {
        var z: [4]u64 = undefined;
        fast_core.montMul(&z, &a, &b);
        return z;
    }
    return montMulPortable(a, b);
}

/// Normal → Montgomery form of a canonical value (`x·R mod p`).
inline fn toMont(x: u256) [4]u64 {
    if (@inComptime()) return fromU256(@truncate((@as(u512, x) << 256) % field_order));
    return montMulLimbs(fromU256(x), fromU256(r2_mod_p));
}

/// Montgomery → normal form (`REDC(x)`; canonical in, canonical out).
///
/// Written on scalars rather than through `montMulLimbs(l, 1)`: the asm core
/// takes its operands and result by pointer, so every `toBytes` of a secret
/// (an ECDH shared `x`) parked both forms in the CALLER's frame, outside any
/// burn — the ECDH stack probe found them (2026-10-10). Four REDC rounds of
/// `t ← ⌊t/2^64⌋ + m·((p+1)/2^64)`, `m = t mod 2^64`, with `(p+1)/2^64 =
/// p₃·2^128 + 2^32`. No final subtract: for an input `x < p` the result
/// `(x + M·p)/2^256 < p + 1`, and `= p` would need `x ≡ 0`, i.e. `x = M = 0`;
/// so it is already canonical (the differential against the portable REDC in
/// `oracle_test.zig` pins it). Constant-time; comptime-evaluable.
inline fn fromMontLimbs(l: [4]u64) [4]u64 {
    const p3: u64 = 0xFFFF_FFFF_0000_0001;
    var a0 = l[0];
    var a1 = l[1];
    var a2 = l[2];
    var a3 = l[3];
    inline for (0..4) |_| {
        const m = a0;
        const x = @as(u128, m) * p3;
        const s0 = @as(u128, a1) + (m << 32);
        const s1 = @as(u128, a2) + (m >> 32) + (s0 >> 64);
        const s2 = @as(u128, a3) + @as(u64, @truncate(x)) + (s1 >> 64);
        const s3 = (x >> 64) + (s2 >> 64);
        a0 = @truncate(s0);
        a1 = @truncate(s1);
        a2 = @truncate(s2);
        a3 = @truncate(s3);
    }
    return .{ a0, a1, a2, a3 };
}

inline fn fromMont(l: [4]u64) u256 {
    return toU256(fromMontLimbs(l));
}

/// `z = a·b mod p`, portable Solinas path (the oracle the asm core mirrors).
pub fn mulPortable(a: [4]u64, b: [4]u64) [4]u64 {
    const wide: u512 = @as(u512, toU256(a)) * @as(u512, toU256(b));
    return reduceWide(wide);
}

/// `z = a² mod p`, portable Solinas path.
pub fn sqPortable(a: [4]u64) [4]u64 {
    const av: u512 = toU256(a);
    return reduceWide(av * av);
}

// ── the field element type ──────────────────────────────────────────────────

/// A NIST P-256 base-field element: four full 2^64 little-endian limbs, always
/// canonical (`value < p`) between operations.
pub const Fe = struct {
    limbs: [4]u64,

    pub const encoded_length = 32;

    pub const zero = Fe{ .limbs = .{ 0, 0, 0, 0 } };
    /// 1 in Montgomery form (`R mod p`).
    pub const one = Fe{ .limbs = fromU256(r_mod_p) };

    /// The field prime as an integer type, for parity with std's `Fe.IntRepr`.
    pub const IntRepr = u256;

    /// The raw Montgomery-form limbs as an integer (`a·R mod p`) — what the
    /// domain-agnostic `add`/`sub` operate on. NOT the element's value: that
    /// is `toInt`.
    inline fn value(fe: Fe) u256 {
        return toU256(fe.limbs);
    }

    /// Swap the byte order of a 32-byte encoded element.
    pub fn orderSwap(s: [encoded_length]u8) [encoded_length]u8 {
        var t = s;
        for (s, 0..) |x, i| t[t.len - 1 - i] = x;
        return t;
    }

    /// Reject an encoding of a value `>= p` (non-canonical), matching std.
    pub fn rejectNonCanonical(s: [encoded_length]u8, endian: std.builtin.Endian) NonCanonicalError!void {
        const v = std.mem.readInt(u256, &s, endian);
        if (v >= field_order) return error.NonCanonical;
    }

    /// Unpack a field element, rejecting a non-canonical (`>= p`) encoding.
    pub fn fromBytes(s: [encoded_length]u8, endian: std.builtin.Endian) NonCanonicalError!Fe {
        const v = std.mem.readInt(u256, &s, endian);
        if (v >= field_order) return error.NonCanonical;
        return .{ .limbs = toMont(v) };
    }

    /// Pack a field element.
    pub fn toBytes(fe: Fe, endian: std.builtin.Endian) [encoded_length]u8 {
        // Limb by limb from registers (see `fromMontLimbs` for why).
        const l = fromMontLimbs(fe.limbs);
        var s: [encoded_length]u8 = undefined;
        inline for (0..4) |i| switch (endian) {
            .little => std.mem.writeInt(u64, s[8 * i ..][0..8], l[i], .little),
            .big => std.mem.writeInt(u64, s[24 - 8 * i ..][0..8], l[i], .big),
        };
        return s;
    }

    /// Create a field element from a comptime integer `< p`.
    pub fn fromInt(comptime x: u256) NonCanonicalError!Fe {
        if (x >= field_order) return error.NonCanonical;
        const l = comptime toMont(x);
        return .{ .limbs = l };
    }

    /// Return the element as an integer.
    pub fn toInt(fe: Fe) u256 {
        return fromMont(fe.limbs);
    }

    pub fn isZero(fe: Fe) bool {
        return (fe.limbs[0] | fe.limbs[1] | fe.limbs[2] | fe.limbs[3]) == 0;
    }

    pub fn isOdd(fe: Fe) bool {
        return (fromMont(fe.limbs) & 1) != 0;
    }

    pub fn equivalent(a: Fe, b: Fe) bool {
        return a.sub(b).isZero();
    }

    /// Constant-time conditional move: `fe = a` iff `c == 1`.
    ///
    /// ⭐ The barrier is not optional here — this is the ONE operation in the
    /// file whose condition bit is a secret (a scalar bit, in a ladder). `c`
    /// is a `u1`, so without laundering it LLVM keeps the `c ∈ {0,1}` range
    /// fact and lowers the masked select exactly as the note above this file's
    /// `blackBox` predicts: `test dl,1 / je` on x86-64 and `tbz w2,#0` on
    /// aarch64 in both release modes, and in ReleaseSmall a `cmove` on the
    /// LOAD ADDRESS — a secret-dependent branch, and then a secret-dependent
    /// memory access, once per scalar bit.
    ///
    /// `normalize` and `sub` already launder their bits. `group.zig`'s
    /// windowed and comb cores had hit this and worked around it with a local
    /// laundered blend, leaving the shared primitive — the one the "proven
    /// constant-time double-and-add" fallback and every external caller of
    /// `p256.Fe` uses — still branching.
    pub fn cMov(fe: *Fe, a: Fe, c: u1) void {
        const mask: u64 = @as(u64, 0) -% blackBox(@as(u64, c));
        for (&fe.limbs, a.limbs) |*w, aw| {
            w.* = (aw & mask) | (w.* & ~mask);
        }
    }

    /// `(a + b) mod p`, constant-time.
    ///
    /// Both inputs are canonical, so `a + b < 2p < 2^257` and ONE conditional
    /// subtract of `p` lands the sum in `[0, p)`: keep the raw sum iff it did
    /// not carry out of 2^256 AND the subtract borrowed (sum `< p`). This
    /// replaced the general `normalize` (two 2^256 ≡ M folds plus the same
    /// subtract) on 2026-09-28: 10.5 ns → ~3.5 ns per add, and a point
    /// double/add has ~15 of them, so every scalar multiply gained ~15 %.
    /// `normalize` is still what the wide reduction feeds, where a full fold
    /// is needed. The 0/1 keep bit is laundered through `blackBox` so the
    /// masked select cannot become a branch (see the barrier note above).
    pub fn add(a: Fe, b: Fe) Fe {
        const s = @addWithOverflow(a.value(), b.value());
        const d = @subWithOverflow(s[0], field_order);
        // keep the sum iff no carry and a borrow (i.e. the true sum is < p).
        const keep_bit: u64 = @as(u64, d[1]) & ~@as(u64, s[1]);
        const keep: u256 = @as(u256, 0) -% @as(u256, blackBox(keep_bit));
        return .{ .limbs = fromU256((s[0] & keep) | (d[0] & ~keep)) };
    }

    /// `2a mod p`.
    pub fn dbl(a: Fe) Fe {
        return a.add(a);
    }

    /// `(a − b) mod p`, constant-time.
    pub fn sub(a: Fe, b: Fe) Fe {
        const d = @subWithOverflow(a.value(), b.value());
        // On borrow, add p back once (a,b < p ⇒ result lands in [0, p)). The
        // borrow bit is laundered through `blackBox` so the masked add does not
        // become a data-dependent branch (see the barrier note above).
        const mask: u256 = @as(u256, 0) -% @as(u256, blackBox(@as(u64, d[1])));
        const v = d[0] +% (field_order & mask);
        return .{ .limbs = fromU256(v) };
    }

    /// `-a mod p`.
    pub fn neg(a: Fe) Fe {
        return Fe.zero.sub(a);
    }

    /// `a·b mod p` (Montgomery: `aR·bR·R⁻¹ = abR`). Dispatches to the gated
    /// amd64 Montgomery core when active, else the portable REDC. The
    /// `@inComptime()` guard routes comptime evaluation to the portable path
    /// (the asm core cannot execute in the comptime interpreter); at runtime
    /// that branch is comptime-dead.
    pub fn mul(a: Fe, b: Fe) Fe {
        return .{ .limbs = montMulLimbs(a.limbs, b.limbs) };
    }

    /// `a² mod p`. Dispatches like `mul` (same comptime/asm split).
    pub fn sq(a: Fe) Fe {
        if (field_asm_active and !@inComptime()) {
            var z: [4]u64 = undefined;
            fast_core.montSq(&z, &a.limbs);
            return .{ .limbs = z };
        }
        return .{ .limbs = montSqPortable(a.limbs) };
    }

    /// `a` squared `n` times.
    fn sqn(a: Fe, n: usize) Fe {
        var fe = a;
        var i: usize = 0;
        while (i < n) : (i += 1) fe = fe.sq();
        return fe;
    }

    /// `a^e mod p` for a PUBLIC exponent `e` (the sq/mul schedule depends only on
    /// `e`, a fixed constant at every call site here, so this is constant-time in
    /// the SECRET element `a`). A runtime bit loop, not a comptime unroll. Used
    /// for inversion and square roots below.
    fn powConst(a: Fe, e: u256) Fe {
        var result = Fe.one;
        var base = a;
        var ee = e;
        while (ee != 0) {
            if (ee & 1 == 1) result = result.mul(base);
            base = base.sq();
            ee >>= 1;
        }
        return result;
    }

    /// Multiplicative inverse, `invert(0) == 0` (matching std). Constant-time
    /// in `a`. Dispatches to the constant-time safegcd (`modinv.zig`) when
    /// `gate.fast_invert_implemented`, else the Fermat oracle below. Measured
    /// 2026-09-28 (i7-7920HQ, ReleaseFast): 12.1 µs (Fermat, 384 multiplies)
    /// → ~3 µs (590 divsteps in ten 62-bit batches).
    pub fn invert(a: Fe) Fe {
        if (comptime gate.fast_invert_implemented) {
            // safegcd inverts the stored limbs: (aR)⁻¹ = a⁻¹R⁻¹; one REDC
            // against R³ lands on a⁻¹R, the Montgomery form of a⁻¹.
            const inv = Fe{ .limbs = modinv.invert(a.limbs, field_modinfo) };
            return inv.mul(.{ .limbs = fromU256(r3_mod_p) });
        }
        return a.invertFermat();
    }

    /// The inverse via Fermat's little theorem, `a^(p−2) mod p`: a public
    /// fixed-exponent square-and-multiply, constant-time in `a`. This is the
    /// correctness ORACLE the safegcd inverse is pinned to (and the fallback
    /// with the gate off). `pub` for the differential + bench.
    pub fn invertFermat(a: Fe) Fe {
        return a.powConst(field_order - 2);
    }

    /// Square root via `a^((p+1)/4)` (valid because `p ≡ 3 (mod 4)` for P-256),
    /// returning `error.NotSquare` if `a` is not a quadratic residue.
    pub fn sqrt(a: Fe) NotSquareError!Fe {
        const x = a.powConst((field_order + 1) / 4);
        if (x.sq().equivalent(a)) return x;
        return error.NotSquare;
    }
};

// ── tests: the field-level oracle differential vs std ───────────────────────

const StdFe = std.crypto.ecc.P256.Fe;

test "field prime matches std.crypto.ecc.P256.Fe.field_order + p ≡ 3 (mod 4)" {
    try std.testing.expectEqual(@as(u256, StdFe.field_order), field_order);
    try std.testing.expectEqual(@as(u256, 3), field_order % 4);
    // 2^256 ≡ M (mod p): the fold constant is exactly the reduced 2^256.
    try std.testing.expectEqual(m_fold, @as(u256, @truncate((@as(u512, 1) << 256) % field_order)));
}

test "fromBytes/toBytes round-trip + rejects non-canonical (>= p)" {
    var prng = std.Random.DefaultPrng.init(0x9256_02561);
    const rand = prng.random();
    var i: usize = 0;
    while (i < 2000) : (i += 1) {
        var s: [32]u8 = undefined;
        rand.bytes(&s);
        const k = Fe.fromBytes(s, .big);
        const j = StdFe.fromBytes(s, .big);
        try std.testing.expectEqual(isErr(j), isErr(k));
        if (k) |kfe| {
            const jfe = j catch unreachable;
            try std.testing.expectEqualSlices(u8, &jfe.toBytes(.big), &kfe.toBytes(.big));
        } else |_| {}
    }
    // p, p+1 rejected; p-1 accepted.
    var pbytes: [32]u8 = undefined;
    std.mem.writeInt(u256, &pbytes, field_order, .big);
    try std.testing.expectError(error.NonCanonical, Fe.fromBytes(pbytes, .big));
    std.mem.writeInt(u256, &pbytes, field_order - 1, .big);
    _ = try Fe.fromBytes(pbytes, .big);
}

fn isErr(v: anytype) bool {
    _ = v catch return true;
    return false;
}

// Draw a random canonical field element in BOTH representations.
fn randFe(rand: std.Random) struct { k: Fe, s: StdFe } {
    while (true) {
        var b: [32]u8 = undefined;
        rand.bytes(&b);
        const k = Fe.fromBytes(b, .big) catch continue;
        const s = StdFe.fromBytes(b, .big) catch unreachable;
        return .{ .k = k, .s = s };
    }
}

// Debug: measured ~12s for this test ALONE, isolated (`scripts/modtest p256
// -Dtest-filter="mul/sq/add/sub/neg/invert"`), just over the campaign's 10s
// per-test budget -- audit A1, 2026-09-15 full-gate attempts. Field ops here
// are cheap relative to a full point multiply, so a modest trim suffices;
// ReleaseFast/ReleaseSafe/ReleaseSmall keep the full count (they are not the
// problem).
const field_diff_iters: usize = if (builtin.mode == .Debug) 2000 else 4000;

test "differential vs std.Fe: mul/sq/add/sub/neg/invert on random inputs" {
    var prng = std.Random.DefaultPrng.init(0xC0FFEE_9256D);
    const rand = prng.random();
    var i: usize = 0;
    while (i < field_diff_iters) : (i += 1) {
        const a = randFe(rand);
        const b = randFe(rand);

        try std.testing.expectEqualSlices(u8, &a.s.mul(b.s).toBytes(.big), &a.k.mul(b.k).toBytes(.big));
        try std.testing.expectEqualSlices(u8, &a.s.sq().toBytes(.big), &a.k.sq().toBytes(.big));
        try std.testing.expectEqualSlices(u8, &a.s.add(b.s).toBytes(.big), &a.k.add(b.k).toBytes(.big));
        try std.testing.expectEqualSlices(u8, &a.s.sub(b.s).toBytes(.big), &a.k.sub(b.k).toBytes(.big));
        try std.testing.expectEqualSlices(u8, &a.s.neg().toBytes(.big), &a.k.neg().toBytes(.big));
        try std.testing.expectEqualSlices(u8, &a.s.invert().toBytes(.big), &a.k.invert().toBytes(.big));
    }
}

test "safegcd inverse == Fermat inverse == std, random + edges (0 → 0)" {
    // The gated inverse against BOTH oracles: the module's own Fermat chain
    // (algorithmically independent — a fixed-exponent power, not a gcd) and
    // std's fiat Bernstein–Yang inverse. Random draws plus the values a
    // divstep implementation gets wrong first: 0 (must give 0, not garbage or
    // a hang), 1, p−1, p−2, single-bit values, and values just below/above
    // the 62-bit limb seams.
    var prng = std.Random.DefaultPrng.init(0x1AF_E6CD_9256);
    const rand = prng.random();
    const edges = [_]u256{
        0,          1,              2,         3,              field_order - 1,  field_order - 2,
        1 << 62,    (1 << 62) - 1,  1 << 124,  (1 << 124) - 1, 1 << 186,         1 << 248,
        (1 << 255), (1 << 255) - 1, (1 << 64), (1 << 128) - 1, field_order >> 1, (field_order >> 1) + 1,
    };
    for (edges) |x| {
        const a = Fe{ .limbs = fromU256(x) };
        const sa = StdFe.fromBytes(a.toBytes(.big), .big) catch unreachable;
        const got = a.invert();
        try std.testing.expectEqualSlices(u8, &a.invertFermat().toBytes(.big), &got.toBytes(.big));
        try std.testing.expectEqualSlices(u8, &sa.invert().toBytes(.big), &got.toBytes(.big));
        if (x != 0) try std.testing.expect(a.mul(got).equivalent(Fe.one));
    }
    try std.testing.expect(Fe.zero.invert().isZero());
    for (0..field_diff_iters) |_| {
        const a = randFe(rand);
        const got = a.k.invert();
        try std.testing.expectEqualSlices(u8, &a.k.invertFermat().toBytes(.big), &got.toBytes(.big));
        try std.testing.expectEqualSlices(u8, &a.s.invert().toBytes(.big), &got.toBytes(.big));
    }
}

test "differential vs std.Fe: sqrt agrees on residues and non-residues" {
    var prng = std.Random.DefaultPrng.init(0x5417_9256);
    const rand = prng.random();
    var i: usize = 0;
    while (i < 2000) : (i += 1) {
        const a = randFe(rand);
        if (a.s.sqrt()) |sroot| {
            const kroot = try a.k.sqrt();
            try std.testing.expectEqualSlices(u8, &sroot.sq().toBytes(.big), &kroot.sq().toBytes(.big));
            try std.testing.expect(kroot.sq().equivalent(a.k));
        } else |_| {
            try std.testing.expectError(error.NotSquare, a.k.sqrt());
        }
    }
}

test "algebraic identities: a·a⁻¹ = 1, a − a = 0, (a·b) = (b·a)" {
    var prng = std.Random.DefaultPrng.init(0xA1_9E_9256);
    const rand = prng.random();
    var i: usize = 0;
    while (i < 1000) : (i += 1) {
        const a = randFe(rand);
        const b = randFe(rand);
        if (!a.k.isZero()) try std.testing.expect(a.k.mul(a.k.invert()).equivalent(Fe.one));
        try std.testing.expect(a.k.sub(a.k).isZero());
        try std.testing.expect(a.k.mul(b.k).equivalent(b.k.mul(a.k)));
    }
}

// Stress the reduction carry chain directly: fold-boundary and max-limb
// patterns where the M-fold's re-overflow path (the 2^224-scale addend) is
// most likely to misbehave — these are the values the gated asm core will also
// need to survive. All must match std bit-for-bit.
test "reduction edge patterns match std (fold-boundary + max-limb)" {
    const p = field_order;
    const edges = [_]u256{
        0,         1,             2,          p - 1,      p - 2,
        (1 << 96), (1 << 96) - 1, (1 << 192), (1 << 224), (1 << 224) - 1,
        (1 << 256) - 1 - ((1 << 224) - (1 << 192) - (1 << 96) + 1), // ≈ p boundary
        (1 << 128) - 1,
        1 << 128,
        (1 << 255),
        (1 << 255) + 1,
        0xFFFFFFFF00000000FFFFFFFF00000000FFFFFFFF00000000FFFFFFFF00000000 % p,
        0x00000000FFFFFFFF00000000FFFFFFFF00000000FFFFFFFF00000000FFFFFFFF % p,
    };
    for (edges) |av| {
        if (av >= p) continue;
        const a = Fe{ .limbs = fromU256(av) };
        const sa = StdFe.fromBytes(a.toBytes(.big), .big) catch continue;
        for (edges) |bv| {
            if (bv >= p) continue;
            const b = Fe{ .limbs = fromU256(bv) };
            const sb = StdFe.fromBytes(b.toBytes(.big), .big) catch continue;
            try std.testing.expectEqualSlices(u8, &sa.mul(sb).toBytes(.big), &a.mul(b).toBytes(.big));
        }
        try std.testing.expectEqualSlices(u8, &sa.sq().toBytes(.big), &a.sq().toBytes(.big));
    }
}

test "the word-shuffle reduction agrees with the fold, bit for bit" {
    // The fold is the oracle: slow, obviously correct, and already the thing
    // the asm core is pinned to. Anything the shuffle gets wrong shows up here
    // as a mismatch rather than as a wrong signature months later.
    var prng: std.Random.DefaultPrng = .init(0x5EED_5AFE_F1E1_D000);
    const rand = prng.random();

    // The edges first, because a random 512-bit value never lands on one: a
    // zero product, the largest possible product, and values that sit exactly
    // on the 2^256 boundary the fold is about.
    const p: u512 = field_order;
    for ([_]u512{
        0,
        1,
        std.math.maxInt(u512),
        (@as(u512, 1) << 256),
        (@as(u512, 1) << 256) - 1,
        p,
        p - 1,
        p + 1,
        @as(u512, @truncate(@as(u1024, p) * @as(u1024, p))),
        (@as(u512, 1) << 511),
    }) |wide| {
        try std.testing.expectEqual(reduceWideFold(wide), reduceWideShuffle(wide));
    }

    // Then products of real field elements, which is the only input shape the
    // callers can actually produce, and then unrestricted 512-bit values,
    // which is what a bug in a length or a shift would produce.
    // 20_000 in the ordinary gate, 200_000 with P256_SHUFFLE_SWEEP=1.
    const draws: usize = if (std.testing.environ.getPosix("P256_SHUFFLE_SWEEP") != null) 200_000 else 20_000;
    for (0..draws) |_| {
        var a: u256 = undefined;
        var b: u256 = undefined;
        rand.bytes(std.mem.asBytes(&a));
        rand.bytes(std.mem.asBytes(&b));
        a %= field_order;
        b %= field_order;
        const prod = @as(u512, a) * @as(u512, b);
        try std.testing.expectEqual(reduceWideFold(prod), reduceWideShuffle(prod));

        var wide: u512 = undefined;
        rand.bytes(std.mem.asBytes(&wide));
        try std.testing.expectEqual(reduceWideFold(wide), reduceWideShuffle(wide));
    }
}
