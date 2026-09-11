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
    pub fn add(a: Fe, b: Fe) Fe {
        const s = @addWithOverflow(a.value(), b.value());
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

    /// Multiplicative inverse via Fermat's little theorem: `a^(p−2) mod p`
    /// (`invert(0) == 0`, matching std). Constant-time in `a`.
    ///
    /// A short addition chain (libsecp256k1 uses ~255 squarings + 15 multiplies)
    /// is the fast path a later phase can substitute; this scaffold uses the
    /// straightforward public-exponent square-and-multiply — correctness over
    /// cleverness, since inversion is amortised (one per affine conversion).
    pub fn invert(a: Fe) Fe {
        return a.powConst(field_order - 2);
    }

    /// Square root via `a^((p+1)/4)` (valid because `p ≡ 3 (mod 4)`), returning
    /// `error.NotSquare` if `a` is not a quadratic residue. This is BIP340's
    /// `lift_x` square root.
    pub fn sqrt(a: Fe) NotSquareError!Fe {
        const x = a.powConst((field_order + 1) / 4);
        if (x.sq().equivalent(a)) return x;
        return error.NotSquare;
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

test "differential vs std.Fe: mul/sq/add/sub/neg/invert on random inputs" {
    var prng = std.Random.DefaultPrng.init(0xC0FFEE_F1E1D);
    const rand = prng.random();
    var i: usize = 0;
    while (i < 4000) : (i += 1) {
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
    while (i < 2000) : (i += 1) {
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
