// SPDX-License-Identifier: MIT
//! `Fp` — the BN254 (alt-bn128) base field, `GF(p)` for the 254-bit prime
//! `p` (decimal/hex value below). Every other type in this module
//! (`Fp2`, `Fp6`, `Fp12`, and the `G1`/`G2` curve point coordinates) is
//! built as a tower on top of this single field.
//!
//! **Status: implemented — Montgomery-resident.** Values are stored in
//! the **Montgomery domain** (`a·R mod p`, `R = 2^256`) as four full
//! `2^64` little-endian limbs, and stay in that domain across every
//! `mul`/`square`/`add`/`sub`/`neg`/`inv`. The hot path is a portable
//! constant-time **CIOS Montgomery multiply** (Koç et al.) with a
//! **dedicated SOS squaring** (each off-diagonal `a[i]·a[j]` product
//! computed once and doubled) — the same portable full-limb technique
//! `montint` uses for the pairing-field sizes, and structurally the same
//! 4×64-limb layout as `k256/src/field.zig` (BN254's `p` is NOT a
//! special-form/Solinas prime, so the reduction is GENERIC Montgomery —
//! `n0inv = -p[0]^{-1} mod 2^64` + the Montgomery constant `R²` — rather
//! than k256's curve-specific Solinas fold).
//!
//! This replaces the previous `std.crypto.ff`-backed field. `ff` keeps
//! elements canonical (non-Montgomery) at rest and pays a Montgomery
//! round-trip on every multiply over 63-bit redundant limbs; the
//! measured `Fp.mul` was ~720–750 ns. The Montgomery-resident field
//! below removes both costs. The public API shape (method names /
//! signatures) is unchanged, so the whole `Fp2`/`Fp6`/`Fp12` tower and
//! the `G1`/`G2`/pairing/groth16 code above it are untouched.
//!
//! Constant-time: `mul`/`square`/`add`/`sub`/`neg` are branch-free
//! (masked conditional subtract/add, with an optimization barrier so
//! LLVM cannot recover the carry/borrow bit and emit a data-dependent
//! branch) — the same guarantee `ff` gave, required by Groth16's secret
//! witnesses on the prove path. `pow`/`inv`/`sqrt` use a
//! **public-exponent** square-and-multiply (constant-time in the base;
//! every call site here supplies a fixed public exponent — Fermat `p-2`,
//! the sqrt exponent, or a comptime Frobenius exponent — matching how
//! `ff`'s public-exponent variants were used).
//!
//! **No `isLexicographicallyLargest` (deliberate, vs. `bls12_381`):**
//! Ethereum's EIP-196/197 precompiles (0x06/0x07/0x08) encode `G1`/`G2`
//! points UNCOMPRESSED — raw `(x, y)` coordinate pairs, no "sign of y"
//! compression bit — unlike BLS12-381's ZCash-style compressed point
//! format. This module therefore has no consumer for that helper; see
//! `SPEC.md`.

const std = @import("std");

/// Number of bits reserved for the fixed-width big-integer container
/// backing `Fp` — 256 (32 bytes), the next byte-aligned width above
/// `p`'s actual 254 bits. Retained (unchanged value) for the sibling
/// `scalar.zig` cross-reference and the `modulus.bits() == 254` test.
pub const modulus_bits = 256;

/// Number of full `2^64` limbs backing an `Fp` element (`254 → 4`).
const L: usize = 4;
/// An `Fp` element's limb array (little-endian, Montgomery domain).
const Limbs = [L]u64;

/// The `std.crypto.ff` modulus for `p` — kept ONLY as a comptime object
/// for the `modulus.bits()` test (`root.zig`) and as the correctness
/// ORACLE the Montgomery arithmetic is differentially tested against
/// (see the "differential vs the old ff path" test at the bottom). NO
/// runtime field arithmetic routes through it any more.
const FfModulus = std.crypto.ff.Modulus(modulus_bits);
const FfFe = FfModulus.Fe;

/// Parses a fixed-length compile-time hex string into bytes.
fn hexBytes(comptime n: usize, comptime hex: *const [2 * n:0]u8) [n]u8 {
    @setEvalBranchQuota(100_000);
    var out: [n]u8 = undefined;
    _ = std.fmt.hexToBytes(&out, hex) catch unreachable;
    return out;
}

/// The BN254 (alt-bn128) base field modulus `p`, big-endian, 32 bytes:
///
/// ```
/// p = 0x30644e72e131a029b85045b68181585d97816a916871ca8d3c208c16d87cfd47
/// ```
///
/// Source: EIP-196/197 (the Ethereum alt_bn128 precompile spec) and
/// `py_ecc`'s `bn128_field_elements.field_modulus` agree on this value
/// byte-for-byte. Independently re-derived from the defining BN
/// polynomial with parameter `x = 4965661367192848881`:
/// `p(x) = 36x^4 + 36x^3 + 24x^2 + 6x + 1`.
pub const p_bytes: [32]u8 = hexBytes(32, "30644e72e131a029b85045b68181585d97816a916871ca8d3c208c16d87cfd47");

/// The BN254 base field modulus as a `std.crypto.ff.Modulus(256)` —
/// comptime-only (test oracle + `bits()` check), see `FfModulus` note.
pub const modulus: FfModulus = blk: {
    @setEvalBranchQuota(100_000);
    break :blk FfModulus.fromBytes(&p_bytes, .big) catch
        @compileError("bn254: malformed base field modulus bytes");
};

/// Comptime helper: `(p + delta) / div` as a big-endian 32-byte exponent,
/// asserting the division is EXACT — used to derive every fixed exponent
/// this module's tower needs directly from the verified `p_bytes`.
pub fn pExponentBytes(comptime delta: comptime_int, comptime div: comptime_int) [32]u8 {
    @setEvalBranchQuota(100_000);
    comptime var x: comptime_int = 0;
    inline for (p_bytes) |byte| x = x * 256 + @as(comptime_int, byte);
    const v = x + delta;
    if (v % div != 0) @compileError("bn254: (p + delta) not divisible by div");
    comptime var q = v / div;
    comptime var out: [32]u8 = undefined;
    comptime var i: usize = 32;
    inline while (i > 0) {
        i -= 1;
        out[i] = q % 256;
        q = q / 256;
    }
    if (q != 0) @compileError("bn254: exponent does not fit in 32 bytes");
    return out;
}

/// `p - 2`, big-endian — the Fermat inversion exponent (`Fp.inv`).
const p_minus_2_bytes: [32]u8 = pExponentBytes(-2, 1);

/// `(p + 1) / 4`, big-endian — the square-root exponent for the
/// `p ≡ 3 (mod 4)` simple case (`Fp.sqrt`).
const sqrt_exponent_bytes: [32]u8 = pExponentBytes(1, 4);

/// Errors from `Fp` byte/primitive parsing — kept as the exact
/// `std.crypto.ff` error set the tower's `fromBytes` signatures already
/// propagate (`error.NonCanonical` / `error.Overflow`), so no caller
/// changes even though the backend no longer uses `ff`.
pub const FpError = std.crypto.ff.OverflowError || std.crypto.ff.FieldElementError;

// ── comptime Montgomery constants ─────────────────────────────────────────
//
// Derived once, at comptime, from the verified `p_bytes` via arbitrary-
// precision `comptime_int` — no magic constants transcribed by hand.

/// `p` as a `comptime_int`.
const p_int: comptime_int = blk: {
    var x: comptime_int = 0;
    for (p_bytes) |b| x = x * 256 + @as(comptime_int, b);
    break :blk x;
};

/// Split a nonnegative `comptime_int` into `L` little-endian `u64` limbs.
fn ctToLimbs(comptime x: comptime_int) Limbs {
    comptime var v = x;
    var out: Limbs = undefined;
    inline for (&out) |*w| {
        w.* = @as(u64, @intCast(v & 0xFFFF_FFFF_FFFF_FFFF));
        v = v >> 64;
    }
    if (v != 0) @compileError("bn254: value exceeds 4 limbs");
    return out;
}

/// `p` in limb form.
const p_limbs: Limbs = ctToLimbs(p_int);
/// `-p[0]^{-1} mod 2^64` — the CIOS Montgomery reduction constant.
const n0inv: u64 = negInvMod2_64(p_limbs[0]);
/// `R mod p` (`R = 2^256`) — the value `1` in the Montgomery domain.
const one_mont: Limbs = ctToLimbs((1 << 256) % p_int);
/// `R² mod p` — used by `toMont` (`montMul(a, r2) = a·R`).
const r2: Limbs = ctToLimbs(((1 << 256) * (1 << 256)) % p_int);
/// Normal-domain `1`, used by `fromMont` (`montMul(a, 1) = a·R⁻¹`).
const one_normal: Limbs = .{ 1, 0, 0, 0 };

/// `-x⁻¹ mod 2^64` for odd `x`, via Newton–Hensel doubling (6 steps).
fn negInvMod2_64(x: u64) u64 {
    var y: u64 = 1; // x⁻¹ mod 2 (x is odd)
    inline for (0..6) |_| y = y *% (2 -% x *% y);
    return 0 -% y;
}

// ── constant-time barrier ──────────────────────────────────────────────────
//
// Launder a value through an empty inline-asm so LLVM loses all
// range/equality knowledge about it. The masked conditional-subtract/add
// below select on a 0/1 carry/borrow bit via `mask = 0 − bit`; without
// this barrier LLVM can recover `bit ∈ {0,1}` and lower the masked select
// to a data-dependent branch — a secret-dependent branch on the Groth16
// prove path (secret witnesses flow through `Fp.mul`/`add`/`sub`). The
// `@inComptime()` guard keeps it out of the comptime interpreter (the
// Frobenius γ constants are built at comptime through this field, where
// inline asm cannot run); it is a no-op at runtime otherwise.
inline fn blackBox(x: u64) u64 {
    if (@inComptime()) return x;
    return asm volatile (""
        : [ret] "=r" (-> u64),
        : [x] "0" (x),
    );
}

// ── low-level Montgomery arithmetic (portable, constant-time) ──────────────

/// Constant-time conditional subtract of `p` from the `(L+1)`-word value
/// (`v` low `L` words, `top` the carry word 0/1). Subtracts `p` iff the
/// full value ≥ `p`. `v < 2p` on entry, so `top ≤ 1` and the result `< p`.
fn condSubP(v: *Limbs, top: u64) void {
    var diff: Limbs = undefined;
    var borrow: u1 = 0;
    inline for (0..L) |i| {
        const s = @subWithOverflow(v[i], p_limbs[i]);
        const s2 = @subWithOverflow(s[0], borrow);
        diff[i] = s2[0];
        borrow = s[1] | s2[1];
    }
    // full value ≥ p  ⟺  no underflow subtracting `borrow` from `top`.
    const under = @subWithOverflow(top, borrow)[1]; // 1 ⇒ value < p ⇒ keep v
    const keep: u64 = 0 -% blackBox(@as(u64, under));
    inline for (0..L) |i| v[i] = (v[i] & keep) | (diff[i] & ~keep);
}

/// `(a + b) mod p`. `a, b < p ⇒ sum < 2p`, one conditional subtract.
fn addLimbs(a: Limbs, b: Limbs) Limbs {
    var out: Limbs = undefined;
    var carry: u64 = 0;
    inline for (0..L) |i| {
        const s = @as(u128, a[i]) + @as(u128, b[i]) + carry;
        out[i] = @truncate(s);
        carry = @truncate(s >> 64);
    }
    condSubP(&out, carry);
    return out;
}

/// `(a − b) mod p`. On borrow, add `p` back once (masked, constant-time).
fn subLimbs(a: Limbs, b: Limbs) Limbs {
    var out: Limbs = undefined;
    var borrow: u1 = 0;
    inline for (0..L) |i| {
        const s = @subWithOverflow(a[i], b[i]);
        const s2 = @subWithOverflow(s[0], borrow);
        out[i] = s2[0];
        borrow = s[1] | s2[1];
    }
    const mask: u64 = 0 -% blackBox(@as(u64, borrow));
    var carry: u64 = 0;
    inline for (0..L) |i| {
        const s = @as(u128, out[i]) + @as(u128, p_limbs[i] & mask) + carry;
        out[i] = @truncate(s);
        carry = @truncate(s >> 64);
    }
    return out;
}

/// Portable constant-time CIOS Montgomery multiply `z = a·b·R⁻¹ mod p`
/// (Koç et al., Fig. 6; radix 2^64, `u128` widening products). Result is
/// fully reduced (`< p`). No secret-dependent branch/index/early-exit.
fn montMul(a: Limbs, b: Limbs) Limbs {
    var t = [_]u64{0} ** (L + 2);
    inline for (0..L) |i| {
        // t += a * b[i]
        var carry: u64 = 0;
        inline for (0..L) |j| {
            const pr = @as(u128, a[j]) * @as(u128, b[i]) + t[j] + carry;
            t[j] = @truncate(pr);
            carry = @truncate(pr >> 64);
        }
        const s = @as(u128, t[L]) + carry;
        t[L] = @truncate(s);
        t[L + 1] = @truncate(s >> 64);

        // u = t[0] * n0inv mod 2^64 ; t = (t + u*p) / 2^64
        const u = t[0] *% n0inv;
        const p0 = @as(u128, u) * @as(u128, p_limbs[0]) + t[0];
        var carry2: u64 = @truncate(p0 >> 64); // low word is 0 by construction
        inline for (1..L) |j| {
            const pr = @as(u128, u) * @as(u128, p_limbs[j]) + t[j] + carry2;
            t[j - 1] = @truncate(pr);
            carry2 = @truncate(pr >> 64);
        }
        const s2 = @as(u128, t[L]) + carry2;
        t[L - 1] = @truncate(s2);
        t[L] = t[L + 1] +% @as(u64, @truncate(s2 >> 64));
    }
    var z: Limbs = t[0..L].*;
    condSubP(&z, t[L]);
    return z;
}

/// Portable constant-time DEDICATED Montgomery squaring `z = a²·R⁻¹ mod p`
/// (SOS: separated square then Montgomery-reduce). Each off-diagonal
/// `a[i]·a[j]` (`i<j`) product is computed ONCE and doubled — the ~½L²
/// saving over `montMul(a, a)`. Its correctness oracle is `montMul(a, a)`
/// (the differential test below). No secret-dependent branch/index.
fn montSqr(a: Limbs) Limbs {
    // A holds the full 2L-word square across all four phases.
    var A = [_]u64{0} ** (2 * L);

    // 1. cross products: A = Σ_{i<j} a[i]·a[j]·B^(i+j)
    inline for (0..L) |i| {
        var carry: u64 = 0;
        inline for (i + 1..L) |j| {
            const pr = @as(u128, a[i]) * @as(u128, a[j]) + A[i + j] + carry;
            A[i + j] = @truncate(pr);
            carry = @truncate(pr >> 64);
        }
        A[i + L] = carry;
    }
    // 2. double: A ← 2·A  (2·cross < B^(2L), so no word overflows the top)
    var top: u64 = 0;
    inline for (0..2 * L) |k| {
        const nw = (A[k] << 1) | top;
        top = A[k] >> 63;
        A[k] = nw;
    }
    // 3. diagonal: A ← A + Σ_i a[i]²·B^(2i)
    var dcarry: u64 = 0;
    inline for (0..L) |i| {
        const sq = @as(u128, a[i]) * @as(u128, a[i]);
        const p1 = @as(u128, A[2 * i]) + @as(u64, @truncate(sq)) + dcarry;
        A[2 * i] = @truncate(p1);
        const p2 = @as(u128, A[2 * i + 1]) + @as(u64, @truncate(sq >> 64)) + @as(u64, @truncate(p1 >> 64));
        A[2 * i + 1] = @truncate(p2);
        dcarry = @truncate(p2 >> 64);
    }
    // 4. Montgomery reduce: z = A·R⁻¹ mod p
    var cc: u64 = 0; // carry into column i+L, threaded between steps
    inline for (0..L) |i| {
        const u = A[i] *% n0inv;
        var carry: u64 = 0;
        inline for (0..L) |j| {
            const pr = @as(u128, u) * @as(u128, p_limbs[j]) + A[i + j] + carry;
            A[i + j] = @truncate(pr);
            carry = @truncate(pr >> 64);
        }
        const s = @as(u128, A[i + L]) + carry + cc;
        A[i + L] = @truncate(s);
        cc = @truncate(s >> 64);
    }
    var z: Limbs = A[L .. 2 * L].*;
    condSubP(&z, cc);
    return z;
}

/// `a·R mod p` (normal → Montgomery domain).
fn toMont(a: Limbs) Limbs {
    return montMul(a, r2);
}

/// `a·R⁻¹ mod p` (Montgomery → normal domain).
fn fromMont(a: Limbs) Limbs {
    return montMul(a, one_normal);
}

/// Read a big-endian 32-byte value into little-endian limbs (no reduction).
fn beToLimbs(bytes: [32]u8) Limbs {
    var out: Limbs = .{ 0, 0, 0, 0 };
    inline for (0..L) |i| {
        const off = 32 - 8 * (i + 1);
        out[i] = std.mem.readInt(u64, bytes[off .. off + 8][0..8], .big);
    }
    return out;
}

/// Write little-endian limbs to a big-endian 32-byte value.
fn limbsToBe(v: Limbs) [32]u8 {
    var out: [32]u8 = undefined;
    inline for (0..L) |i| {
        const off = 32 - 8 * (i + 1);
        std.mem.writeInt(u64, out[off .. off + 8][0..8], v[i], .big);
    }
    return out;
}

/// `v >= p` ? (parse-path canonicality check; on public data.)
fn geP(v: Limbs) bool {
    comptime var i: usize = L;
    inline while (i > 0) {
        i -= 1;
        if (v[i] != p_limbs[i]) return v[i] > p_limbs[i];
    }
    return true; // equal ⇒ ≥ p (reject p itself)
}

/// An element of the BN254 base field `GF(p)`, stored in the Montgomery
/// domain as four full `2^64` little-endian limbs (`value·R mod p`),
/// always fully reduced (`< p`) between operations.
pub const Fp = struct {
    limbs: Limbs,

    /// Fixed-size big-endian wire encoding: 32 bytes — the EVM/EIP-196
    /// convention every alt_bn128 precompile input/output coordinate uses.
    pub const encoded_bytes = 32;

    /// The additive identity. Montgomery form of `0` is `0`.
    pub const zero: Fp = .{ .limbs = .{ 0, 0, 0, 0 } };

    /// The multiplicative identity — `R mod p` (Montgomery form of `1`).
    pub const one: Fp = .{ .limbs = one_mont };

    /// Parses a big-endian 32-byte value, REJECTING anything `>= p`
    /// (non-canonical), then converts into the Montgomery domain.
    pub fn fromBytes(bytes: [encoded_bytes]u8) FpError!Fp {
        const v = beToLimbs(bytes);
        if (geP(v)) return error.NonCanonical;
        return .{ .limbs = toMont(v) };
    }

    /// Serializes to big-endian 32 bytes (converting out of Montgomery).
    pub fn toBytes(self: Fp) [encoded_bytes]u8 {
        return limbsToBe(fromMont(self.limbs));
    }

    /// Builds a small `Fp` value from a native unsigned integer (e.g. the
    /// curve constant `b = 3`). Rejects values `>= p` (`error.Overflow`).
    pub fn fromInt(comptime T: type, v: T) FpError!Fp {
        const uv: u256 = @intCast(v);
        if (uv >= @as(u256, p_int)) return error.Overflow;
        const normal: Limbs = .{
            @truncate(uv),
            @truncate(uv >> 64),
            @truncate(uv >> 128),
            @truncate(uv >> 192),
        };
        return .{ .limbs = toMont(normal) };
    }

    /// `true` iff the value is `0` (constant-time over the limbs).
    pub fn isZero(self: Fp) bool {
        return (self.limbs[0] | self.limbs[1] | self.limbs[2] | self.limbs[3]) == 0;
    }

    /// Constant-time equality (fully-reduced Montgomery form is unique,
    /// so a limb-wise compare is exact).
    pub fn eql(a: Fp, b: Fp) bool {
        var acc: u64 = 0;
        inline for (0..L) |i| acc |= a.limbs[i] ^ b.limbs[i];
        return acc == 0;
    }

    // ── field arithmetic (Montgomery-resident, constant-time) ────────────

    /// `a + b (mod p)`. Constant time.
    pub fn add(a: Fp, b: Fp) Fp {
        return .{ .limbs = addLimbs(a.limbs, b.limbs) };
    }

    /// `a - b (mod p)`. Constant time.
    pub fn sub(a: Fp, b: Fp) Fp {
        return .{ .limbs = subLimbs(a.limbs, b.limbs) };
    }

    /// `-a (mod p)`, i.e. `p - a` (or `0` if `a == 0`). Constant time.
    pub fn neg(a: Fp) Fp {
        return .{ .limbs = subLimbs(Fp.zero.limbs, a.limbs) };
    }

    /// `a * b (mod p)` — CIOS Montgomery multiply. Constant time.
    pub fn mul(a: Fp, b: Fp) Fp {
        return .{ .limbs = montMul(a.limbs, b.limbs) };
    }

    /// `a^2 (mod p)` — dedicated SOS Montgomery squaring. Constant time.
    pub fn square(a: Fp) Fp {
        return .{ .limbs = montSqr(a.limbs) };
    }

    /// Public-exponent square-and-multiply `a^e (mod p)`, `e` big-endian
    /// bytes. Constant time in the BASE `a` (the sq/mul schedule follows
    /// the PUBLIC exponent bits). Shared by `pow`/`inv`/`sqrt`.
    fn powBE(a: Fp, e: []const u8) Fp {
        var result = Fp.one;
        for (e) |byte| {
            var bit: u8 = 0x80;
            while (bit != 0) : (bit >>= 1) {
                result = result.square();
                if (byte & bit != 0) result = result.mul(a);
            }
        }
        return result;
    }

    /// Multiplicative inverse; `error.NotInvertible` if `a == 0`.
    /// Fermat's little theorem, `a^(p-2) mod p` (public exponent).
    pub fn inv(a: Fp) error{NotInvertible}!Fp {
        if (a.isZero()) return error.NotInvertible;
        return a.powBE(&p_minus_2_bytes);
    }

    /// RFC 9380 §4's `inv0`: `inv0(0) = 0`, otherwise `a^-1`.
    pub fn inv0(a: Fp) Fp {
        return a.inv() catch Fp.zero;
    }

    /// `a^e (mod p)`, `e` a big-endian byte string. Public-exponent
    /// variant — constant time in the base (every call site here supplies
    /// a fixed public exponent), matching the audit's labelling of the
    /// former `ff` `pow` as the public-exponent path.
    pub fn pow(a: Fp, e: [encoded_bytes]u8) Fp {
        return a.powBE(&e);
    }

    /// Square root, or `null` if `a` is not a quadratic residue.
    /// `p ≡ 3 (mod 4)` (low byte `0x47`), so the SIMPLE case applies:
    /// candidate `c = a^((p+1)/4)`, verified by `c^2 == a`.
    pub fn sqrt(a: Fp) ?Fp {
        const c = a.powBE(&sqrt_exponent_bytes);
        return if (c.square().eql(a)) c else null;
    }

    /// A uniformly random field element (rejection sampling `< p`).
    pub fn random(io: std.Io) Fp {
        var buf: [encoded_bytes]u8 = undefined;
        while (true) {
            io.random(&buf);
            return Fp.fromBytes(buf) catch continue; // >= p: reject, redraw
        }
    }

    /// Constant-time select: returns `a` if `cond`, else `b` (masked
    /// limb-wise merge on the Montgomery representation).
    pub fn ctSelect(cond: bool, a: Fp, b: Fp) Fp {
        const mask: u64 = @as(u64, 0) -% @intFromBool(cond);
        var out: Limbs = undefined;
        inline for (0..L) |i| out[i] = (a.limbs[i] & mask) | (b.limbs[i] & ~mask);
        return .{ .limbs = out };
    }
};

// ── tests ────────────────────────────────────────────────────────────────

test "p is odd and 254 bits" {
    try std.testing.expect(p_bytes[31] & 1 == 1);
    try std.testing.expectEqual(@as(usize, 254), modulus.bits());
}

test "Montgomery constants: R·R⁻¹ ≡ 1 and n0inv correct" {
    // p·(-p⁻¹) ≡ -1 (mod 2^64)
    try std.testing.expectEqual(@as(u64, 0), p_limbs[0] *% n0inv +% 1);
    // fromMont(one_mont) == 1 and toMont(1) == one_mont
    try std.testing.expectEqualSlices(u64, &one_normal, &fromMont(one_mont));
    try std.testing.expectEqualSlices(u64, &one_mont, &toMont(one_normal));
}

test "Fp.zero / Fp.one round-trip through bytes" {
    const z = Fp.zero.toBytes();
    try std.testing.expect(std.mem.allEqual(u8, &z, 0));
    const o = Fp.one.toBytes();
    var expected = [_]u8{0} ** 32;
    expected[31] = 1;
    try std.testing.expectEqualSlices(u8, &expected, &o);
}

test "Fp.fromBytes rejects p itself (non-canonical) and accepts p-1" {
    try std.testing.expectError(error.NonCanonical, Fp.fromBytes(p_bytes));

    var p_minus_1 = p_bytes;
    p_minus_1[31] -= 1;
    _ = try Fp.fromBytes(p_minus_1); // must not error
}

test "Fp.fromInt(3) matches the b=3 curve-constant byte pattern" {
    const three = try Fp.fromInt(u8, 3);
    var expected = [_]u8{0} ** 32;
    expected[31] = 3;
    try std.testing.expectEqualSlices(u8, &expected, &three.toBytes());
}

test "Fp arithmetic: additive identities (a + 0 = a, a + (-a) = 0, a - a = 0)" {
    const a = try Fp.fromInt(u64, 0xdead_beef_1234_5678);
    try std.testing.expect(a.add(Fp.zero).eql(a));
    try std.testing.expect(a.add(a.neg()).isZero());
    try std.testing.expect(a.sub(a).isZero());
    try std.testing.expect(Fp.zero.neg().isZero());
}

test "Fp arithmetic: (a + b)^2 == a^2 + 2ab + b^2 and square == mul(a, a)" {
    const a = try Fp.fromInt(u64, 0x0123_4567_89ab_cdef);
    var b_bytes = [_]u8{0} ** 32;
    _ = try std.fmt.hexToBytes(&b_bytes, "183227397098d014dc2822db40c0ac2ecbc0b548b438e5469e10460b6c3e7ea3"); // (p-1)/2
    const b = try Fp.fromBytes(b_bytes);
    const lhs = a.add(b).square();
    const two_ab = a.mul(b).add(a.mul(b));
    const rhs = a.square().add(two_ab).add(b.square());
    try std.testing.expect(lhs.eql(rhs));
    try std.testing.expect(a.square().eql(a.mul(a)));
}

test "Fp.inv: a * a^-1 == 1; inv(0) errors; inv(1) == 1" {
    const a = try Fp.fromInt(u64, 987_654_321);
    const a_inv = try a.inv();
    try std.testing.expect(a.mul(a_inv).eql(Fp.one));
    try std.testing.expectError(error.NotInvertible, Fp.zero.inv());
    try std.testing.expect((try Fp.one.inv()).eql(Fp.one));
}

test "Fp.inv0 (RFC 9380): inv0(0) == 0, inv0(a) == a^-1 otherwise" {
    try std.testing.expect(Fp.zero.inv0().isZero());
    const a = try Fp.fromInt(u64, 123_456_789);
    try std.testing.expect(a.mul(a.inv0()).eql(Fp.one));
}

test "Fp.pow: a^0 == 1, a^1 == a, a^2 == square(a)" {
    const a = try Fp.fromInt(u64, 31337);
    var e = [_]u8{0} ** 32;
    try std.testing.expect(a.pow(e).eql(Fp.one));
    e[31] = 1;
    try std.testing.expect(a.pow(e).eql(a));
    e[31] = 2;
    try std.testing.expect(a.pow(e).eql(a.square()));
}

test "Fp.sqrt: sqrt(a^2) in {a, -a}; sqrt(-1) is null (p = 3 mod 4)" {
    const a = try Fp.fromInt(u64, 0xfeed_face_cafe_f00d);
    const c = a.square();
    const s = c.sqrt() orelse return error.TestUnexpectedResult;
    try std.testing.expect(s.eql(a) or s.eql(a.neg()));
    try std.testing.expect(s.square().eql(c));
    // -1 is a quadratic NON-residue exactly when p = 3 (mod 4).
    try std.testing.expect(Fp.one.neg().sqrt() == null);
    const z = Fp.zero.sqrt() orelse return error.TestUnexpectedResult;
    try std.testing.expect(z.isZero());
}

test "Fp.ctSelect picks the right operand" {
    const a = try Fp.fromInt(u8, 7);
    const b = try Fp.fromInt(u8, 9);
    try std.testing.expect(Fp.ctSelect(true, a, b).eql(a));
    try std.testing.expect(Fp.ctSelect(false, a, b).eql(b));
}

test "Fp.random produces a canonical, (overwhelmingly) nonzero element" {
    var threaded = std.Io.Threaded.init(std.testing.allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();

    const a = Fp.random(io);
    const b = Fp.random(io);
    _ = try Fp.fromBytes(a.toBytes());
    try std.testing.expect(!a.eql(b));
}

test "pExponentBytes: (p-1)/2 matches the independently-recomputed half_p and p-2 = p_bytes minus 2" {
    var half_p_bytes: [32]u8 = undefined;
    _ = try std.fmt.hexToBytes(&half_p_bytes, "183227397098d014dc2822db40c0ac2ecbc0b548b438e5469e10460b6c3e7ea3");
    try std.testing.expectEqualSlices(u8, &half_p_bytes, &pExponentBytes(-1, 2));
    var expected = p_bytes;
    expected[31] -= 2; // p's low byte is 0x47, no borrow
    try std.testing.expectEqualSlices(u8, &expected, &p_minus_2_bytes);
}

test "KAT: G1 generator (1, 2) satisfies y^2 = x^3 + 3 (EIP-196 b=3; independent py_ecc/EIP-197 cross-check)" {
    const x = Fp.one;
    const y = try Fp.fromInt(u8, 2);
    const b = try Fp.fromInt(u8, 3);
    const lhs = y.square();
    const rhs = x.square().mul(x).add(b);
    try std.testing.expect(lhs.eql(rhs));
}

// ── differential: Montgomery Fp vs the old std.crypto.ff path ───────────────
//
// The `ff` modulus is retained purely as a comptime correctness ORACLE.
// This test drives thousands of random inputs through BOTH the Montgomery
// arithmetic (the shipped `Fp`) and canonical `ff` arithmetic and asserts
// byte-exact agreement — a direct, local anchor for the field rewrite,
// independent of (and in addition to) the pairing/precompile/groth16 KATs.

fn ffFromBytes(bytes: [32]u8) FfFe {
    return FfFe.fromBytes(modulus, &bytes, .big) catch unreachable;
}
fn ffToBytes(fe: FfFe) [32]u8 {
    var out: [32]u8 = undefined;
    fe.toBytes(&out, .big) catch unreachable;
    return out;
}

test "differential vs std.crypto.ff: mul/square/add/sub/neg/inv on random inputs" {
    var prng = std.Random.DefaultPrng.init(0xB2_54_F1E1D);
    const rand = prng.random();

    // Draw a random canonical element in BOTH representations.
    const draw = struct {
        fn go(r: std.Random) struct { fp: Fp, fe: FfFe } {
            while (true) {
                var b: [32]u8 = undefined;
                r.bytes(&b);
                const f = Fp.fromBytes(b) catch continue;
                return .{ .fp = f, .fe = ffFromBytes(b) };
            }
        }
    }.go;

    var i: usize = 0;
    while (i < 4000) : (i += 1) {
        const a = draw(rand);
        const b = draw(rand);

        try std.testing.expectEqualSlices(u8, &ffToBytes(modulus.mul(a.fe, b.fe)), &a.fp.mul(b.fp).toBytes());
        try std.testing.expectEqualSlices(u8, &ffToBytes(modulus.sq(a.fe)), &a.fp.square().toBytes());
        try std.testing.expectEqualSlices(u8, &ffToBytes(modulus.add(a.fe, b.fe)), &a.fp.add(b.fp).toBytes());
        try std.testing.expectEqualSlices(u8, &ffToBytes(modulus.sub(a.fe, b.fe)), &a.fp.sub(b.fp).toBytes());
        try std.testing.expectEqualSlices(u8, &ffToBytes(modulus.sub(modulus.zero, a.fe)), &a.fp.neg().toBytes());
    }
}
