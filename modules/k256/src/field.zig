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
/// (bounds: `<2^290 → <2^257 → <2^256+c → <2^256`), after which `normalize`
/// finishes the canonicalisation.
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
pub const Fe = struct {
    limbs: [4]u64,

    pub const encoded_length = 32;

    pub const zero = Fe{ .limbs = .{ 0, 0, 0, 0 } };
    pub const one = Fe{ .limbs = .{ 1, 0, 0, 0 } };

    /// The field prime as an integer type, for parity with std's `Fe.IntRepr`.
    pub const IntRepr = u256;

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
        return .{ .limbs = fromU256(v) };
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
        return .{ .limbs = fromU256(x) };
    }

    /// Return the element as an integer.
    pub fn toInt(fe: Fe) u256 {
        return fe.value();
    }

    pub fn isZero(fe: Fe) bool {
        return (fe.limbs[0] | fe.limbs[1] | fe.limbs[2] | fe.limbs[3]) == 0;
    }

    pub fn isOdd(fe: Fe) bool {
        return (fe.limbs[0] & 1) != 0;
    }

    pub fn equivalent(a: Fe, b: Fe) bool {
        return a.sub(b).isZero();
    }

    /// Constant-time conditional move: `fe = a` iff `c == 1`.
    pub fn cMov(fe: *Fe, a: Fe, c: u1) void {
        const mask: u64 = @as(u64, 0) -% @as(u64, c);
        for (&fe.limbs, a.limbs) |*w, aw| {
            w.* = (aw & mask) | (w.* & ~mask);
        }
    }

    /// `(a + b) mod p`, constant-time.
    pub fn add(a: Fe, b: Fe) Fe {
        const s = @addWithOverflow(a.value(), b.value());
        return .{ .limbs = normalize(s[0], s[1]) };
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

    /// `a·b mod p`. Dispatches to the gated amd64 core when active, else the
    /// portable Solinas reduction. The `@inComptime()` guard routes comptime
    /// evaluation (e.g. the fixed-base comb-table build in `group.zig`) to the
    /// portable path, because the asm core cannot execute in the comptime
    /// interpreter; at runtime that branch is comptime-dead (`@inComptime()` is
    /// then a comptime-false constant), so it costs nothing.
    pub fn mul(a: Fe, b: Fe) Fe {
        if (field_asm_active and !@inComptime()) {
            var z: [4]u64 = undefined;
            fast_core.fieldMul(&z, &a.limbs, &b.limbs);
            return .{ .limbs = z };
        }
        return .{ .limbs = mulPortable(a.limbs, b.limbs) };
    }

    /// `a² mod p`. Dispatches like `mul` (same comptime/asm split).
    pub fn sq(a: Fe) Fe {
        if (field_asm_active and !@inComptime()) {
            var z: [4]u64 = undefined;
            fast_core.fieldSq(&z, &a.limbs);
            return .{ .limbs = z };
        }
        return .{ .limbs = sqPortable(a.limbs) };
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
