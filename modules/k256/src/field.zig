// SPDX-License-Identifier: MIT

//! field — the secp256k1 base field `Fe` over the special prime
//! `p = 2^256 − 2^32 − 977`, stored as four full 2^64 limbs (little-endian).
//!
//! The multiply/square hot path uses the curve-specific **Solinas reduction**:
//! a 256×256→512-bit schoolbook product, then the fold `2^256 ≡ 2^32 + 977
//! (mod p)` collapses the high half back into 256 bits (repeat until < 2^256),
//! then one constant-time conditional subtract of `p`. The portable path ships
//! that reduction written straightforwardly on wide (`u256`/`u512`) integers —
//! it is the correctness ORACLE, byte-exact against
//! `std.crypto.ecc.Secp256k1.Fe`. The irreducible `MULX/ADX` limb-level version
//! of the SAME fold is the gated Fable core (`fast_core.fieldMul`/`fieldSq`),
//! now implemented: on amd64 `mul`/`sq` dispatch to it, elsewhere to the
//! portable reduction below.
//!
//! The API mirrors `std.crypto.ecc.Secp256k1.Fe` (same method names/semantics)
//! so `group.zig` is a drop-in over this field and the oracle differential is a
//! direct `k256.Fe.op(...) == std.Fe.op(...)` comparison via `toBytes`.

const std = @import("std");
/// Test-only (`build.zig`'s `test_deps`, never `deps`): fuzz corpus framing.
const builtin = @import("builtin");
const gate = @import("gate.zig");
const fast_core = @import("fast_core.zig");

const NonCanonicalError = std.crypto.errors.NonCanonicalError;
const NotSquareError = std.crypto.errors.NotSquareError;

/// The secp256k1 base field prime `p = 2^256 − 2^32 − 977`.
pub const field_order: u256 = (1 << 256) - (1 << 32) - 977;

/// The Solinas fold constant `c = 2^32 + 977`, so that `2^256 ≡ c (mod p)`.
const c_fold: u64 = (1 << 32) + 977;

/// True iff `mul`/`sq` route to the gated amd64 asm core (`fast_core`) rather
/// than the portable Solinas reduction.
pub const field_asm_active = fast_core.supported and gate.field_asm_implemented;

// ── constant-time barrier ───────────────────────────────────────────────────
//
// Launder a value through an empty inline-asm so LLVM loses all range/equality
// knowledge about it (montint `b199192`). The portable `normalize`/`sub` select
// on a 0/1 carry/borrow bit via `mask = 0 − bit`; without this barrier LLVM
// recovers `bit ∈ {0,1}` and lowers the masked select to a data-dependent
// branch (`test/jne`) — a secret-dependent branch on the constant-time k·G
// signing path (`group.combMulBase`), confirmed by disassembly. Laundering the
// bit before it becomes a mask forces the branch-free form to survive. The
// `@inComptime()` guard keeps it out of the comptime interpreter (the comb
// table is built at comptime, where inline asm cannot run); it is a no-op at
// runtime otherwise.
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
/// `2^256 ≡ c (mod p)`, so the extra `carry·2^256` folds in as `carry·c`. After
/// that fold the value is `< 2^256`, hence `< p + c`, so a single masked
/// conditional subtract of `p` lands it in `[0, p)`.
fn normalize(s0: u256, carry: u1) [4]u64 {
    const C: u256 = c_fold;
    // Fold the 257th bit: v = s0 + carry·c. `carry·c ≤ c < 2^33`. Expressed as a
    // MASK (`C & (0 − carry)`, bit-identical to `C · carry`) with the bit
    // laundered through `blackBox` so LLVM cannot recover carry ∈ {0,1} and emit
    // a data-dependent branch — see the barrier note above.
    const cmask: u256 = @as(u256, 0) -% @as(u256, blackBox(@as(u64, carry)));
    const f = @addWithOverflow(s0, C & cmask);
    // A carry out here means the true sum reached 2^256, i.e. another `·c`;
    // the wrapped value is then `< c`, so `+c` cannot overflow again.
    const fmask: u256 = @as(u256, 0) -% @as(u256, blackBox(@as(u64, f[1])));
    var v: u256 = f[0] +% (C & fmask);
    // v < 2^256 ≤ p + c: one constant-time conditional subtract of p.
    const d = @subWithOverflow(v, field_order); // borrow ⇒ v < p (keep v)
    const keep: u256 = @as(u256, 0) -% @as(u256, blackBox(@as(u64, d[1])));
    v = (v & keep) | (d[0] & ~keep);
    return fromU256(v);
}

/// The portable special-prime (Solinas) reduction of a 512-bit product into a
/// canonical field element `< p`. This is what `fast_core.fieldMul`/`fieldSq`
/// must reproduce bit-for-bit with `MULX/ADX` limb arithmetic.
///
/// Each fold replaces the value by `(low 256 bits) + c·(high bits)`; the high
/// part shrinks by ~223 bits per fold, so four folds provably reach `< 2^256`
/// (loose per-fold bounds: `<2^290 → <2^257 → <2^256+c → <2^256`), after
/// which `normalize` finishes the canonicalisation.
///
/// A1 audit F7 (2026-09-11): the 4th fold is provably **dead code** for
/// every input this function is ever actually called with, not merely
/// untested. Both callers (`mulPortable`/`sqPortable`) only ever feed a
/// product of two CANONICAL field elements (`< p = 2^256 - 2^32 - 977`), so
/// `wide < p^2`. Computing the EXACT (not sampled) maximum of one fold step
/// `f(x) = (x mod 2^256) + c·(x div 2^256)` over an input range `[0, N)` —
/// the max is always at `x = N-1` itself or at the end of the preceding
/// full "band" `(k-1)·2^256 + (2^256-1)`, since `f` is increasing within a
/// band and the per-band maxima increase with the band index — and
/// chaining that exact bound through three folds starting from
/// `N_0 = (p-1)^2` gives, after fold 3, a maximum of EXACTLY `2^256 - 1`:
/// strictly less than `2^256`. Since this is an upper bound on the true
/// (achievable) maximum, `x >> 256` is `0` after three folds for every
/// valid input — the 4th fold's `(x & mask) + C * (x >> 256)` always
/// degenerates to the identity `x + C·0 = x`. This is a proof, not a
/// mutation-survival observation: the audit's own randomized/adversarial
/// search (1,000,000 random canonical products + a 40,000-pair adversarial
/// sweep + the full `oracle_test.zig` edge matrix) found 0 hits, matching.
/// The 4th fold is kept anyway as an explicit safety margin against the
/// loose bound above (defense in depth, not a live path) — removing it
/// would touch this module's pinned ctgrind fingerprint for no measured
/// benefit.
fn reduceWide(wide: u512) [4]u64 {
    const C: u512 = c_fold;
    const mask: u512 = (@as(u512, 1) << 256) - 1;
    var x = wide;
    inline for (0..4) |_| {
        x = (x & mask) + C * (x >> 256);
    }
    std.debug.assert((x >> 256) == 0); // provably reduced to < 2^256 by 4 folds
    return normalize(@truncate(x), 0);
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

/// A secp256k1 base-field element: four full 2^64 little-endian limbs, always
/// canonical (`value < p`) between operations.
///
/// A1 audit F8 (2026-09-11): the backing limbs used to be a plain public
/// field (`limbs`), so anything could construct `Fe{ .limbs = raw }` and skip
/// every canonicalizing constructor below — and `isZero`/`isOdd`/`toBytes`
/// would then silently report the wrong answer for that value (e.g.
/// `Fe{ .limbs = toLimbs(field_order) }.isZero()` was `false`, not `true`).
/// Renamed to `_limbs` so the field no longer reads as an ordinary public
/// member. ⚠ This is a NAMING convention, not a language guarantee — Zig has
/// no field-level access control (confirmed: an unmarked field is reachable
/// by field-literal syntax from any file that names the type), so `_limbs`
/// does not make construction impossible, only unidiomatic and clearly
/// against the grain. The actual guarantee is structural: every constructor
/// in this file (`fromBytes`, `fromInt`, `add`, `sub`, `mul`, `sq`, `zero`,
/// `one`) already produces a canonical value; there is no reason for any
/// caller, inside this module or out, to ever write `_limbs` directly.
pub const Fe = struct {
    _limbs: [4]u64,

    pub const encoded_length = 32;

    pub const zero = Fe{ ._limbs = .{ 0, 0, 0, 0 } };
    pub const one = Fe{ ._limbs = .{ 1, 0, 0, 0 } };

    /// The field prime as an integer type, for parity with std's `Fe.IntRepr`.
    pub const IntRepr = u256;

    inline fn value(fe: Fe) u256 {
        return toU256(fe._limbs);
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
        return .{ ._limbs = fromU256(v) };
    }

    /// Pack a field element.
    pub fn toBytes(fe: Fe, endian: std.builtin.Endian) [encoded_length]u8 {
        var s: [encoded_length]u8 = undefined;
        std.mem.writeInt(u256, &s, fe.value(), endian);
        return s;
    }

    /// Create a field element from a comptime integer `< p`.
    pub fn fromInt(comptime x: u256) NonCanonicalError!Fe {
        if (x >= field_order) return error.NonCanonical;
        return .{ ._limbs = fromU256(x) };
    }

    /// Return the element as an integer.
    pub fn toInt(fe: Fe) u256 {
        return fe.value();
    }

    pub fn isZero(fe: Fe) bool {
        return (fe._limbs[0] | fe._limbs[1] | fe._limbs[2] | fe._limbs[3]) == 0;
    }

    pub fn isOdd(fe: Fe) bool {
        return (fe._limbs[0] & 1) != 0;
    }

    pub fn equivalent(a: Fe, b: Fe) bool {
        return a.sub(b).isZero();
    }

    /// Constant-time conditional move: `fe = a` iff `c == 1`.
    ///
    /// The select bit `c` is laundered through `blackBox` before it becomes a
    /// mask — exactly as `normalize`/`sub` do — so LLVM cannot recover
    /// `c ∈ {0,1}` and lower the masked blend to a data-dependent branch
    /// (`Jcc`). Without the barrier the "constant-time" scalar-mul paths leaked
    /// the secret: `group.mul`'s per-bit select became `test cl,1; je` on each
    /// scalar bit, and `combMulBase`'s per-window sign select became `cmp;jbe`
    /// on the secret signed-digit sign — both reproduced by disassembly. See
    /// the barrier note above.
    pub fn cMov(fe: *Fe, a: Fe, c: u1) void {
        const mask: u64 = @as(u64, 0) -% @as(u64, blackBox(@as(u64, c)));
        for (&fe._limbs, a._limbs) |*w, aw| {
            w.* = (aw & mask) | (w.* & ~mask);
        }
    }

    /// `(a + b) mod p`, constant-time.
    ///
    /// With `a, b < p` the sum is `< 2p < 2^257`. Let `t = s + c` over 256
    /// bits (`c = 2^256 − p`); then `s ≥ p` exactly when the add carried out
    /// or `t` did, and in that case `t` is `s − p`: two carry chains and one
    /// masked select, where `normalize` (written for a general carry) spends
    /// three chains and two selects. Kept on `u256` on purpose: per-limb
    /// `@addWithOverflow` chains measured 30% SLOWER on verify (2026-10-07)
    /// despite half the instructions — LLVM turns them into setc/or carry
    /// chains instead of `adc`.
    pub fn add(a: Fe, b: Fe) Fe {
        const s = @addWithOverflow(a.value(), b.value());
        const t = @addWithOverflow(s[0], @as(u256, c_fold));
        const mask: u256 = @as(u256, 0) -% @as(u256, blackBox(@as(u64, s[1] | t[1])));
        return .{ ._limbs = fromU256((t[0] & mask) | (s[0] & ~mask)) };
    }

    /// `k·a mod p` for a small comptime `k` (the curve formulas' `3b = 21`).
    /// One 256×64 product and one Solinas fold instead of a chain of `add`s:
    /// `k·a < 2^261`, its high word `h < 2^5`, and `lo + c·h` then fits
    /// `normalize`'s `s0 + carry·2^256` contract.
    pub fn mulSmall(a: Fe, comptime k: u64) Fe {
        comptime std.debug.assert(k < 32);
        const w: u320 = @as(u320, a.value()) * k;
        const lo: u256 = @truncate(w);
        const hi: u256 = @intCast(w >> 256);
        const s = @addWithOverflow(lo, hi * c_fold);
        return .{ ._limbs = normalize(s[0], s[1]) };
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
        return .{ ._limbs = fromU256(v) };
    }

    /// `-a mod p`.
    pub fn neg(a: Fe) Fe {
        return Fe.zero.sub(a);
    }

    /// `a·b mod p`. Dispatches to the gated amd64 core when active, else the
    /// portable Solinas reduction. The `@inComptime()` guard routes comptime
    /// evaluation (e.g. the fixed-base comb-table build in `group.zig`) to the
    /// portable path, because the asm core cannot execute in the comptime
    /// interpreter; at runtime that branch is comptime-dead (`@inComptime()` is
    /// then a comptime-false constant), so it costs nothing.
    pub fn mul(a: Fe, b: Fe) Fe {
        if (field_asm_active and !@inComptime()) {
            var z: [4]u64 = undefined;
            fast_core.fieldMul(&z, &a._limbs, &b._limbs);
            return .{ ._limbs = z };
        }
        return .{ ._limbs = mulPortable(a._limbs, b._limbs) };
    }

    /// `a² mod p`. Dispatches like `mul` (same comptime/asm split).
    pub fn sq(a: Fe) Fe {
        if (field_asm_active and !@inComptime()) {
            var z: [4]u64 = undefined;
            fast_core.fieldSq(&z, &a._limbs);
            return .{ ._limbs = z };
        }
        return .{ ._limbs = sqPortable(a._limbs) };
    }

    /// `a` squared `n` times.
    fn sqn(a: Fe, n: usize) Fe {
        var fe = a;
        var i: usize = 0;
        while (i < n) : (i += 1) fe = fe.sq();
        return fe;
    }

    /// `a^e mod p` for a PUBLIC exponent `e` (the sq/mul schedule depends only on
    /// `e`, which is a fixed constant at every call site here, so this is
    /// constant-time in the SECRET element `a`). A runtime bit loop, not a
    /// comptime unroll — the 256-iteration unroll of 512-bit ops was pathological
    /// for the optimizer. Used for inversion and square roots below.
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

    /// `a^(2^223 − 1)` and the shorter runs of ones it is built from — the
    /// shared prefix of the `p − 2` and `(p + 1)/4` addition chains. Both
    /// exponents are, in binary, 223 ones followed by a short tail, so a
    /// run-of-ones chain (`x_k = a^(2^k − 1)`, `x_{j+k} = x_j^(2^k)·x_k`)
    /// reaches the head in 218 squarings and 11 multiplies, where the bit loop
    /// in `powConst` multiplies on every one bit. Same chain as libsecp256k1's
    /// `secp256k1_fe_inv`/`fe_sqrt`. The schedule is fixed, so constant-time.
    const OnesRuns = struct { x2: Fe, x3: Fe, x22: Fe, x223: Fe };

    fn onesRuns(a: Fe) OnesRuns {
        const x2 = a.sq().mul(a);
        const x3 = x2.sq().mul(a);
        const x6 = x3.sqn(3).mul(x3);
        const x9 = x6.sqn(3).mul(x3);
        const x11 = x9.sqn(2).mul(x2);
        const x22 = x11.sqn(11).mul(x11);
        const x44 = x22.sqn(22).mul(x22);
        const x88 = x44.sqn(44).mul(x44);
        const x176 = x88.sqn(88).mul(x88);
        const x220 = x176.sqn(44).mul(x44);
        const x223 = x220.sqn(3).mul(x3);
        return .{ .x2 = x2, .x3 = x3, .x22 = x22, .x223 = x223 };
    }

    /// Multiplicative inverse via Fermat's little theorem: `a^(p−2) mod p`
    /// (`invert(0) == 0`, matching std). Constant-time in `a`.
    ///
    /// `p − 2` = 223 ones, a zero, 22 ones, 4 zeros, `101101` — the
    /// `onesRuns` head plus a fixed tail: 255 squarings + 15 multiplies, about
    /// half the cost of the square-and-multiply loop it replaced (2026-10-07).
    /// `powConst` stays as its differential oracle in the tests.
    pub fn invert(a: Fe) Fe {
        const r = onesRuns(a);
        var t = r.x223.sqn(23).mul(r.x22);
        t = t.sqn(5).mul(a);
        t = t.sqn(3).mul(r.x2);
        return t.sqn(2).mul(a);
    }

    /// Multiplicative inverse for a PUBLIC element — VARIABLE-TIME
    /// (`invertPublic(0) == 0`, as `invert`). Never call it on a secret: its
    /// running time depends on the value. The verifier's affine conversion
    /// of `s·G − e·P` is what it is for.
    ///
    /// Bernstein–Yang safegcd ("Fast constant-time gcd computation and
    /// modular inversion", 2019) in libsecp256k1's variable-time form
    /// (`secp256k1_modinv64_var`, MIT): batches of 62 divsteps on the low
    /// limbs build a 2×2 transition matrix, which is applied to `(f, g)`
    /// (shrinking them) and to `(d, e)` (tracking the inverse mod p) in
    /// signed 62-bit limbs. ~3× faster than the addition chain here.
    pub fn invertPublic(a: Fe) Fe {
        return .{ ._limbs = fromU256(safegcd.inverse(a.value())) };
    }

    /// Square root via `a^((p+1)/4)` (valid because `p ≡ 3 (mod 4)`), returning
    /// `error.NotSquare` if `a` is not a quadratic residue. This is BIP340's
    /// `lift_x` square root.
    ///
    /// `(p + 1)/4` = 223 ones, a zero, 22 ones, `000011`, `00`: the
    /// `onesRuns` head plus 31 squarings and 2 multiplies (253 S + 13 M).
    pub fn sqrt(a: Fe) NotSquareError!Fe {
        const r = onesRuns(a);
        var t = r.x223.sqn(23).mul(r.x22);
        t = t.sqn(6).mul(r.x2);
        const x = t.sqn(2);
        if (x.sq().equivalent(a)) return x;
        return error.NotSquare;
    }
};

// ── safegcd (variable-time inversion of PUBLIC values) ──────────────────────
//
// Signed 62-bit limbs: `v[0] + v[1]·2^62 + … + v[4]·2^248`, each limb in
// (−2^62, 2^62) between steps. Ported from libsecp256k1's `modinv64_impl.h`
// (MIT) — `divsteps_62_var`, `update_de_62`, `update_fg_62_var`,
// `normalize_62` and the `modinv64_var` loop — with its bounds: `d, e` stay in
// (−2p, p), the matrix entries satisfy `|u| + |v| ≤ 2^62`.
const safegcd = struct {
    const S62 = [5]i64;
    const m62: u64 = std.math.maxInt(u64) >> 2;
    /// `p = 2^256 − 2^32 − 977` as `−(2^32 + 977) + 256·2^248`.
    const modulus: S62 = .{ -0x1000003D1, 0, 0, 0, 256 };
    /// `p^−1 mod 2^62` by Newton's iteration (each step doubles the correct
    /// low bits, starting from 1 bit: p is odd).
    const modulus_inv62: u64 = blk: {
        const pl: u64 = @truncate(field_order);
        var x: u64 = 1;
        for (0..6) |_| x = x *% (2 -% pl *% x);
        break :blk x & m62;
    };
    const Trans = struct { u: i64, v: i64, q: i64, r: i64 };

    fn fromInt(x: u256) S62 {
        var out: S62 = undefined;
        for (0..4) |i| out[i] = @intCast(@as(u64, @truncate(x >> @intCast(62 * i))) & m62);
        out[4] = @intCast(x >> 248);
        return out;
    }

    fn toInt(v: S62) u256 {
        var x: u256 = 0;
        for (0..5) |i| x |= @as(u256, @as(u64, @intCast(v[i]))) << @intCast(62 * i);
        return x;
    }

    inline fn lo62(x: i128) i64 {
        return @intCast(@as(u64, @truncate(@as(u128, @bitCast(x)))) & m62);
    }

    /// 62 divsteps on the low bits of `f` (odd) and `g`, returning the new
    /// `eta = −delta` and the transition matrix scaled by 2^62.
    fn divsteps62Var(eta_in: i64, f0: u64, g0: u64, t: *Trans) i64 {
        var u: u64 = 1;
        var v: u64 = 0;
        var q: u64 = 0;
        var r: u64 = 1;
        var f = f0;
        var g = g0;
        var eta = eta_in;
        var i: u32 = 62;
        while (true) {
            // Count zeros only up to i (sentinel bit at position i).
            const zeros: u6 = @intCast(@ctz(g | (@as(u64, std.math.maxInt(u64)) << @intCast(i))));
            g >>= zeros;
            u <<= zeros;
            v <<= zeros;
            eta -= zeros;
            i -= zeros;
            if (i == 0) break;
            var w: u64 = undefined;
            if (eta < 0) {
                // eta < 0: negate it and replace (f, g) with (g, −f).
                eta = -eta;
                const tf = f;
                f = g;
                g = 0 -% tf;
                const tu = u;
                u = q;
                q = 0 -% tu;
                const tv = v;
                v = r;
                r = 0 -% tv;
                // Cancel up to 6 bits of g (no more than i, nor eta + 1).
                const limit: u32 = @intCast(@min(eta + 1, @as(i64, i)));
                const m = (@as(u64, std.math.maxInt(u64)) >> @intCast(64 - limit)) & 63;
                w = (f *% g *% (f *% f -% 2)) & m;
            } else {
                // Cancel up to 4 bits of g.
                const limit: u32 = @intCast(@min(eta + 1, @as(i64, i)));
                const m = (@as(u64, std.math.maxInt(u64)) >> @intCast(64 - limit)) & 15;
                w = f +% (((f +% 1) & 4) << 1);
                w = ((0 -% w) *% g) & m;
            }
            g +%= f *% w;
            q +%= u *% w;
            r +%= v *% w;
        }
        t.* = .{ .u = @bitCast(u), .v = @bitCast(v), .q = @bitCast(q), .r = @bitCast(r) };
        return eta;
    }

    /// `(d, e) ← (t·(d, e) + p·(md, me)) / 2^62`, with `md, me` chosen so the
    /// division is exact and the results stay in (−2p, p).
    fn updateDe(d: *S62, e: *S62, t: Trans) void {
        const sd = d[4] >> 63;
        const se = e[4] >> 63;
        var md = (t.u & sd) + (t.v & se);
        var me = (t.q & sd) + (t.r & se);
        var cd: i128 = @as(i128, t.u) * d[0] + @as(i128, t.v) * e[0];
        var ce: i128 = @as(i128, t.q) * d[0] + @as(i128, t.r) * e[0];
        md -= @intCast((modulus_inv62 *% @as(u64, @truncate(@as(u128, @bitCast(cd)))) +% @as(u64, @bitCast(md))) & m62);
        me -= @intCast((modulus_inv62 *% @as(u64, @truncate(@as(u128, @bitCast(ce)))) +% @as(u64, @bitCast(me))) & m62);
        cd += @as(i128, modulus[0]) * md;
        ce += @as(i128, modulus[0]) * me;
        cd >>= 62;
        ce >>= 62;
        for (1..5) |i| {
            cd += @as(i128, t.u) * d[i] + @as(i128, t.v) * e[i] + @as(i128, modulus[i]) * md;
            ce += @as(i128, t.q) * d[i] + @as(i128, t.r) * e[i] + @as(i128, modulus[i]) * me;
            d[i - 1] = lo62(cd);
            e[i - 1] = lo62(ce);
            cd >>= 62;
            ce >>= 62;
        }
        d[4] = @intCast(cd);
        e[4] = @intCast(ce);
    }

    /// `(f, g) ← t·(f, g) / 2^62` over the first `len` limbs.
    fn updateFgVar(len: usize, f: *S62, g: *S62, t: Trans) void {
        var cf: i128 = @as(i128, t.u) * f[0] + @as(i128, t.v) * g[0];
        var cg: i128 = @as(i128, t.q) * f[0] + @as(i128, t.r) * g[0];
        cf >>= 62;
        cg >>= 62;
        for (1..len) |i| {
            cf += @as(i128, t.u) * f[i] + @as(i128, t.v) * g[i];
            cg += @as(i128, t.q) * f[i] + @as(i128, t.r) * g[i];
            f[i - 1] = lo62(cf);
            g[i - 1] = lo62(cg);
            cf >>= 62;
            cg >>= 62;
        }
        f[len - 1] = @intCast(cf);
        g[len - 1] = @intCast(cg);
    }

    /// Bring `r` from (−2p, p) to [0, p), negated first when `sign < 0`.
    fn normalize62(r: *S62, sign: i64) void {
        var cond_add = r[4] >> 63;
        for (r, modulus) |*ri, mi| ri.* += mi & cond_add;
        const cond_negate = sign >> 63;
        for (r) |*ri| ri.* = (ri.* ^ cond_negate) - cond_negate;
        for (0..4) |i| {
            r[i + 1] += r[i] >> 62;
            r[i] &= @as(i64, @intCast(m62));
        }
        cond_add = r[4] >> 63;
        for (r, modulus) |*ri, mi| ri.* += mi & cond_add;
        for (0..4) |i| {
            r[i + 1] += r[i] >> 62;
            r[i] &= @as(i64, @intCast(m62));
        }
    }

    /// `x^−1 mod p` for `x < p` (0 ↦ 0). Variable-time.
    fn inverse(x: u256) u256 {
        var d: S62 = .{ 0, 0, 0, 0, 0 };
        var e: S62 = .{ 1, 0, 0, 0, 0 };
        var f: S62 = modulus;
        var g: S62 = fromInt(x);
        var len: usize = 5;
        var eta: i64 = -1; // eta = −delta; delta starts at 1
        while (true) {
            var t: Trans = undefined;
            eta = divsteps62Var(eta, @bitCast(f[0]), @bitCast(g[0]), &t);
            updateDe(&d, &e, t);
            updateFgVar(len, &f, &g, t);
            if (g[0] == 0) {
                var cond: i64 = 0;
                for (g[1..len]) |gi| cond |= gi;
                if (cond == 0) break;
            }
            // Drop the top limb once both f and g fit in one fewer.
            const fn_ = f[len - 1];
            const gn = g[len - 1];
            var cond: i64 = @as(i64, @intCast(len)) - 2;
            cond >>= 63;
            cond |= fn_ ^ (fn_ >> 63);
            cond |= gn ^ (gn >> 63);
            if (cond == 0) {
                f[len - 2] |= @bitCast(@as(u64, @bitCast(fn_)) << 62);
                g[len - 2] |= @bitCast(@as(u64, @bitCast(gn)) << 62);
                len -= 1;
            }
        }
        // f = ±1 now; d·x ≡ f.
        normalize62(&d, f[len - 1]);
        return toInt(d);
    }
};

// ── tests: the field-level oracle differential vs std ───────────────────────

const StdFe = std.crypto.ecc.Secp256k1.Fe;

test "field prime matches std.crypto.ecc.Secp256k1.Fe.field_order" {
    try std.testing.expectEqual(@as(u256, StdFe.field_order), field_order);
}

// A1 audit F7: the 4th Solinas fold in `reduceWide` had no test exercising
// it (mutating it away, or the whole `inline for (0..4)` down to `0..3`,
// left the suite 100% green) -- and the audit's own randomized/adversarial
// search never reached it either. This is a proof, permanently re-checked,
// that "no reach found" is not a gap in the search: the 4th fold is
// mathematically UNREACHABLE for any input `reduceWide` is ever actually
// called with, and this test would fail if that ever stopped being true
// (e.g. `field_order`/`c_fold` were ever changed).
test "A1 F7: the 4th Solinas fold is mathematically dead code, not merely untested (exact bound, not sampled)" {
    const mask: u512 = (@as(u512, 1) << 256) - 1;
    const C: u512 = c_fold;

    // The EXACT (not sampled) maximum of one fold step
    // `f(x) = (x mod 2^256) + c*(x div 2^256)` over `x` in `[0, n)`.
    // `f` is increasing within each 2^256-wide "band" (constant high part,
    // increasing low part) and the per-band maxima `(2^256-1) + c*hi`
    // increase with the band index `hi`, so the true global max over any
    // prefix range is always one of exactly two candidates: the range's own
    // top element, or the end of the immediately preceding FULL band.
    const maxFoldOutput = struct {
        fn call(n: u512) u512 {
            const x = n - 1;
            const hi = x >> 256;
            const lo = x & mask;
            const f_top = lo + C * hi;
            if (hi >= 1) {
                const f_prev_full_band = mask + C * (hi - 1);
                return @max(f_top, f_prev_full_band);
            }
            return f_top;
        }
    }.call;

    // `reduceWide` is only ever fed `a*b` for canonical field elements
    // `a, b <= p - 1`, so the true maximum possible input is `(p-1)^2`
    // (inclusive) -- pass `(p-1)^2 + 1` as the exclusive upper bound.
    const p: u512 = field_order;
    const n0_exclusive: u512 = (p - 1) * (p - 1) + 1;

    const m1 = maxFoldOutput(n0_exclusive);
    const m2 = maxFoldOutput(m1 + 1);
    const m3 = maxFoldOutput(m2 + 1);

    // This is an upper bound on the TRUE achievable maximum after 3 real
    // folds (each stage widens the range to the full `[0, m_{k-1}]`, a
    // superset of what 3 real folds can actually produce) -- so if even
    // this loose bound stays under 2^256, the real post-fold-3 value does
    // too, for every possible input. Computed value: exactly `2^256 - 1`.
    try std.testing.expect(m3 < (@as(u512, 1) << 256));
    try std.testing.expectEqual(mask, m3); // == 2^256 - 1, right at the edge

    // And the 4th fold on that exact worst case is the identity (hi == 0
    // going in, so nothing changes) -- the loop's 4th iteration never has
    // any effect to verify against, for any real input.
    try std.testing.expectEqual(m3, maxFoldOutput(m3 + 1));
}

test "fromBytes/toBytes round-trip + rejects non-canonical (>= p)" {
    var prng = std.Random.DefaultPrng.init(0x5EC_02561);
    const rand = prng.random();
    var i: usize = 0;
    while (i < 2000) : (i += 1) {
        var s: [32]u8 = undefined;
        rand.bytes(&s);
        // k256 and std must agree on canonicality AND on the round-trip bytes.
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

// Debug's std.crypto.ecc.Secp256k1.Fe path is unoptimized like the group-level
// differentials elsewhere in this module (see group.zig's
// `random_scalars_iters`) -- cut in Debug, full count elsewhere.
const field_diff_iters: usize = if (builtin.mode == .Debug) 500 else 4000;
const sqrt_diff_iters: usize = if (builtin.mode == .Debug) 300 else 2000;

test "differential vs std.Fe: mul/sq/add/sub/neg/invert on random inputs" {
    var prng = std.Random.DefaultPrng.init(0xC0FFEE_F1E1D);
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

test "differential vs std.Fe: sqrt agrees on residues and non-residues" {
    var prng = std.Random.DefaultPrng.init(0x5417_5417);
    const rand = prng.random();
    var i: usize = 0;
    while (i < sqrt_diff_iters) : (i += 1) {
        const a = randFe(rand);
        // Only compare where std says it's a square; both must then produce a
        // root of the same square (roots may differ by sign, so compare x²).
        if (a.s.sqrt()) |sroot| {
            const kroot = try a.k.sqrt();
            try std.testing.expectEqualSlices(u8, &sroot.sq().toBytes(.big), &kroot.sq().toBytes(.big));
            try std.testing.expect(kroot.sq().equivalent(a.k));
        } else |_| {
            try std.testing.expectError(error.NotSquare, a.k.sqrt());
        }
    }
}

// The addition chains in `invert`/`sqrt` against the plain exponentiation
// they replaced, on the edge elements the random draws above never hit.
test "invert/sqrt addition chains == powConst(p−2) / powConst((p+1)/4)" {
    const edges = [_]u256{ 0, 1, 2, 3, 7, 1 << 32, (1 << 255), field_order - 2, field_order - 1 };
    inline for (edges) |e| try expectChainsMatch(try Fe.fromInt(e));
    var prng = std.Random.DefaultPrng.init(0xC4A1_0B5E);
    const rand = prng.random();
    var i: usize = 0;
    while (i < 200) : (i += 1) try expectChainsMatch(randFe(rand).k);
}

fn expectChainsMatch(a: Fe) !void {
    try std.testing.expectEqual(a.powConst(field_order - 2).toInt(), a.invert().toInt());
    const root = a.powConst((field_order + 1) / 4);
    if (a.sqrt()) |x| {
        try std.testing.expectEqual(root.toInt(), x.toInt());
    } else |_| {
        try std.testing.expect(!root.sq().equivalent(a));
    }
}

test "invertPublic (safegcd) == invert on edges, structured and random elements" {
    const edges = [_]u256{
        0,                                                                  1,                2,               3,               977,
        1 << 32,                                                            (1 << 62) - 1,    1 << 62,         (1 << 124) + 1,  1 << 248,
        (1 << 255),                                                         field_order >> 1, field_order - 2, field_order - 1, field_order - (1 << 62),
        0x5555555555555555555555555555555555555555555555555555555555555555,
    };
    inline for (edges) |v| {
        const a = try Fe.fromInt(v);
        try std.testing.expectEqual(a.invert().toInt(), a.invertPublic().toInt());
    }
    var prng = std.Random.DefaultPrng.init(0x5AFE_6CD);
    const rand = prng.random();
    const iters: usize = if (builtin.mode == .Debug) 3000 else 30000;
    for (0..iters) |i| {
        // Random, plus sparse values (few set bits) that stress long runs of
        // zero divsteps and the limb-shrinking path.
        var v: u256 = rand.int(u256);
        if (i % 3 == 1) v = @as(u256, 1) << rand.int(u8) | @as(u256, rand.int(u64));
        if (i % 3 == 2) v = field_order - 1 - rand.int(u128);
        if (v >= field_order) v -= field_order;
        const a = Fe{ ._limbs = fromU256(v) };
        const inv = a.invertPublic();
        if (v == 0) {
            try std.testing.expect(inv.isZero());
        } else {
            try std.testing.expect(a.mul(inv).equivalent(Fe.one));
            try std.testing.expect(inv.toInt() < field_order);
        }
    }
}

test "safegcd: p^-1 mod 2^62 matches libsecp256k1's constant" {
    // `secp256k1_const_modinfo_fe.modulus_inv62` in libsecp256k1's field_5x52_impl.h.
    try std.testing.expectEqual(@as(u64, 0x27C7F6E22DDACACF), safegcd.modulus_inv62);
}

test "algebraic identities: a·a⁻¹ = 1, a − a = 0, (a·b) = (b·a)" {
    var prng = std.Random.DefaultPrng.init(0xA1_9E_B4A);
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

// ── fuzz: Fe.fromBytes never panics on arbitrary attacker-supplied bytes ──
//
// `Fe.fromBytes` is the field-element byte-loader every point/scalar
// decoder above it (SEC1 in `group.zig`, x-only pubkeys and `r` in
// `sign.zig`'s `bip340Verify`) ultimately calls — a 32-byte string is
// attacker-controlled wherever a public key, signature component or Bitcoin
// script value crosses the wire. `rejectNonCanonical` (>= p) is the only
// rejection this loader has, so the harness biases toward the boundary
// (values at/near `p`) as well as fully random 32-byte strings.

/// ⛔ The four knobs below are all drawn AFTER the byte draw, and this target
/// had no corpus — so outside `--fuzz` the input was exhausted by
/// `smith.bytes` and every `smith.value(bool)` returned FALSE. The
/// boundary bias the comment above is entirely about had **never executed**:
/// `p`, `p-1` and `p+1` were never handed to `rejectNonCanonical`, and the
/// little-endian branch was never taken either. One all-zero big-endian string
/// was the only input this harness ever ran.
///
/// ⚠ A `smith.bytes(&s)` harness reads its corpus entry RAW — no length
/// header — so a seed is the 32 octets themselves followed by the `u64` words
/// the knobs read (`1` is `true`, `0` is `false`).
///
/// ⚠ How MANY words a seed needs is not fixed: the second and third are read
/// only inside the branches the first and second open. The word lists below
/// are therefore per-seed, not a uniform four.
const fe_seeds = [_][]const u8{
    // Ordinary value, no boundary override: [bias=0, endian=big].
    rawSeed(&([_]u8{0} ** 31 ++ [_]u8{1} ++ leWords(&.{ 0, 1 }))),
    // The same, read little-endian: [bias=0, endian=little].
    rawSeed(&([_]u8{0} ** 31 ++ [_]u8{1} ++ leWords(&.{ 0, 0 }))),
    // `p` exactly, which `rejectNonCanonical` refuses:
    // [bias=1, offset=0, endian=big]. The byte payload is overwritten by the
    // bias branch, so its content does not matter here.
    rawSeed(&([_]u8{0} ** 32 ++ leWords(&.{ 1, 0, 1 }))),
    // `p - 1`, the largest canonical element: [bias=1, offset=1, plus=0]
    // (`+%= 0xff`), then endian=big.
    rawSeed(&([_]u8{0} ** 32 ++ leWords(&.{ 1, 1, 0, 1 }))),
    // `p + 1`, refused: [bias=1, offset=1, plus=1], then endian=big.
    rawSeed(&([_]u8{0} ** 32 ++ leWords(&.{ 1, 1, 1, 1 }))),
    // All-0xff: above `p` in either endianness.
    rawSeed(&([_]u8{0xff} ** 32 ++ leWords(&.{ 0, 1 }))),
    // The all-zero, big-endian, no-bias input this target used to run for ever.
    rawSeed(&([_]u8{0} ** 32 ++ leWords(&.{ 0, 0 }))),
};

/// The `u64` tail a `smith.bytes` seed needs so the knobs after it are alive.
fn leWords(comptime ws: []const u64) [ws.len * 8]u8 {
    var out: [ws.len * 8]u8 = undefined;
    for (ws, 0..) |w, i| std.mem.writeInt(u64, out[i * 8 ..][0..8], w, .little);
    return out;
}

/// ⛔ NOT `fuzzSeedLocal`. That helper prepends the little-endian `u32`
/// length `Smith.slice` reads, and this harness opens with `smith.bytes`,
/// which reads no header at all. Written with `seed` first: the four-octet
/// prefix shifted the whole payload, `bytes` swallowed the first 28 octets of
/// the word tail, and every knob still read `false` — `boundary` stayed at 0
/// and the guard said so. The static `struct {}` namespace is what gives the
/// returned slice a lifetime (a `const` local is not promoted).
fn rawSeed(comptime frame: []const u8) []const u8 {
    return &struct {
        const bytes = frame[0..frame.len].*;
    }.bytes;
}

test "fuzz: Fe.fromBytes never panics on arbitrary bytes" {
    try std.testing.fuzz({}, fuzzFeFromBytes, .{ .corpus = &fe_seeds });
}

fn fuzzFeFromBytes(_: void, smith: *std.testing.Smith) !void {
    var s: [Fe.encoded_length]u8 = undefined;
    smith.bytes(&s);
    if (smith.value(bool)) {
        // Bias toward the p / p-1 / p+1 boundary in big-endian form.
        s = std.mem.toBytes(std.mem.nativeToBig(u256, field_order));
        if (smith.value(bool)) s[Fe.encoded_length - 1] +%= if (smith.value(bool)) 1 else 0xff;
    }
    const endian: std.builtin.Endian = if (smith.value(bool)) .big else .little;
    _ = Fe.fromBytes(s, endian) catch {};
}

test "corpus: the Fe seeds drive every knob, and the counts are pinned" {
    var accepted: usize = 0;
    var boundary: usize = 0;
    var offset: usize = 0;
    var plus_one: usize = 0;
    var little: usize = 0;
    for (fe_seeds) |sd| {
        var smith: std.testing.Smith = .{ .in = sd };
        var s: [Fe.encoded_length]u8 = undefined;
        smith.bytes(&s);
        if (smith.value(bool)) {
            boundary += 1;
            s = std.mem.toBytes(std.mem.nativeToBig(u256, field_order));
            if (smith.value(bool)) {
                offset += 1;
                const plus = smith.value(bool);
                if (plus) plus_one += 1;
                s[Fe.encoded_length - 1] +%= if (plus) 1 else 0xff;
            }
        }
        const endian: std.builtin.Endian = if (smith.value(bool)) .big else .little;
        if (endian == .little) little += 1;
        _ = Fe.fromBytes(s, endian) catch continue;
        accepted += 1;
    }
    // ⛔ `boundary` and `little` were both **0** for every input this target
    // had ever run — the branch the harness's comment is about, and the
    // little-endian loader, had never executed. Those, not `accepted`, are
    // what this guard exists to hold.
    try std.testing.expectEqual(@as(usize, 3), boundary);
    try std.testing.expectEqual(@as(usize, 2), little);
    try std.testing.expectEqual(@as(usize, 4), accepted);
    // The two knobs INSIDE the boundary branch, pinned separately rather than
    // left to be inferred from `accepted`: without them a seed list that
    // stopped exercising `p - 1` and `p + 1` — the two values the whole bias
    // exists to produce — could keep every number above unchanged by trading
    // one refusal for another.
    try std.testing.expectEqual(@as(usize, 2), offset); // the `p - 1` and `p + 1` seeds
    try std.testing.expectEqual(@as(usize, 1), plus_one); // of which one adds 1, one 0xff
}

/// ⛔ A LOCAL COPY of `testkit.fuzz.seed`, and it has to be one. Enrolling this
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
fn fuzzSeedLocal(comptime frame: []const u8) []const u8 {
    return &struct {
        const bytes = std.mem.toBytes(@as(u32, @intCast(frame.len))) ++ frame[0..frame.len].*;
    }.bytes;
}

test "the local seed helper produces what Smith.slice reads back" {
    const s = fuzzSeedLocal("abcdef");
    var smith: std.testing.Smith = .{ .in = s };
    var buf: [32]u8 = undefined;
    const n = smith.slice(&buf);
    try std.testing.expectEqualStrings("abcdef", buf[0..n]);
}

// Mutation run 2026-10-08: dropping either carry of `add`'s select, or the
// carry of `mulSmall`'s fold, left the suite green — random draws reach a sum
// in [p, 2^256) or a fold that overflows 2^256 with probability ~2^-220. These
// inputs reach each case on purpose; std is the oracle.
test "add/mulSmall: sums in [p, 2^256), sums past 2^256, folds past 2^256" {
    const c: u256 = c_fold;
    const add_cases = [_][2]u256{
        .{ field_order - 1, 1 }, // = p: no 257th bit, must reduce to 0
        .{ field_order - 1, c }, // = 2^256 − 1: no 257th bit, ≥ p
        .{ field_order - 1, field_order - 1 }, // past 2^256
        .{ 1 << 255, 1 << 255 }, // exactly 2^256
        .{ field_order - 2, 2 },
    };
    for (add_cases) |ab| {
        const a = Fe{ ._limbs = fromU256(ab[0]) };
        const b = Fe{ ._limbs = fromU256(ab[1]) };
        var sa: [32]u8 = undefined;
        var sb: [32]u8 = undefined;
        std.mem.writeInt(u256, &sa, ab[0], .big);
        std.mem.writeInt(u256, &sb, ab[1], .big);
        const want = (try StdFe.fromBytes(sa, .big)).add(try StdFe.fromBytes(sb, .big));
        try std.testing.expectEqualSlices(u8, &want.toBytes(.big), &a.add(b).toBytes(.big));
        try std.testing.expectEqualSlices(u8, &want.toBytes(.big), &b.add(a).toBytes(.big));
    }
    // a = ⌊(j·2^256 + 2^256 − 1)/21⌋: 21·a has high word j and a low word
    // within 21 of 2^256, so `lo + j·c` carries out for every j ≥ 1.
    for (0..21) |j| {
        const a_int: u256 = @intCast(((@as(u512, j) << 256) + ((@as(u512, 1) << 256) - 1)) / 21);
        if (a_int >= field_order) continue;
        const a = Fe{ ._limbs = fromU256(a_int) };
        try std.testing.expectEqual(a.mul(try Fe.fromInt(21)).toInt(), a.mulSmall(21).toInt());
    }
}
