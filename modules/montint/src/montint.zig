// SPDX-License-Identifier: MIT

//! montint — constant-time Montgomery modular arithmetic over arbitrary ODD
//! moduli (prime OR composite: RSA/Paillier N, VDF group order, pairing-field
//! primes), on full radix-2^64 limbs.
//!
//! `Modint(max_bits)` is the analogue of `std.crypto.ff.Modulus`, built to
//! *beat* it: `ff` reserves a carry bit per limb (63-bit redundant limbs) and
//! does a 4-way half-limb `mulWide`, which forecloses the host add-with-carry
//! and widening-multiply instructions — the measured ~8–29× gap vs OpenSSL
//! across `rsa`/`paillier`/`vdf` (see `SPEC.md`). This module uses full 2^64
//! limbs so the amd64 `MULX/ADCX/ADOX` core (gated, `asm_core.zig`) can reach
//! OpenSSL-competitive speed, with this portable CIOS path as the fallback on
//! every other arch AND as the correctness oracle the asm core is diffed
//! against.
//!
//! Representation: values are `[limbs_len]u64`, little-endian. Montgomery-domain
//! and normal-domain values share the type; the domain is tracked by naming
//! convention (`*_mont`), like the internal helpers of `ff`. Convert at the
//! boundary with `toMontgomery`/`fromMontgomery`; keep values Montgomery-
//! resident across a modexp.

const std = @import("std");
const builtin = @import("builtin");
const limbs = @import("limbs.zig");
const gate = @import("gate.zig");
const asm_core = @import("asm_core.zig");

/// Errors surfaced when constructing a modulus or reducing an input.
pub const Error = error{ EvenModulus, ModulusTooSmall, NonCanonical, Overflow };

/// Whether the accelerated amd64 core is BOTH available on this target and
/// switched on. While `gate.asm_core_implemented` is `false` this is always
/// `false` and every operation runs on the portable CIOS oracle.
pub const asm_active = asm_core.supported and gate.asm_core_implemented;

/// Small-L dispatch cutoff (limb count `L`, i.e. `bits/64`). The
/// `MULX/ADCX/ADOX` asm core only pays off for LARGE moduli: the asm block runs
/// runtime-`n` loops (trip-count setup, remainder handling, the cross-row
/// register shuffle), whereas the portable CIOS is comptime-fully-unrolled with
/// zero loop bookkeeping, so at small L the asm overhead dominates the handful
/// of limb products. Measured on this repo's host (Kaby Lake, ReleaseFast; see
/// `SPEC.md` "256-bit regression / small-L dispatch") the asm modmul is:
///   L=4  (256b): ~2.4× SLOWER · L=8 (512b): ~1.06× slower · L=16 (1024b):
///   ~1.07× slower · L=32 (2048b): ~1.43× FASTER · L=64 (4096b): ~1.75× faster.
/// So breakeven is ~1.5–2k bit here (higher than the canonical ~512b, a
/// mobile-CPU/turbo effect), and we route to the asm core only at `L >= 32`
/// (≥2048-bit: RSA/Paillier/VDF), where the win is robust. Every smaller
/// modulus uses the portable CIOS — critically our pairing fields
/// (`bn254` Fp = 254b → L=4, `bls12_381` Fp = 381b → L=6), which MUST stay
/// portable. The asm core is still correct at every L (the differential proves
/// it) — this is purely a speed dispatch.
pub const asm_min_limbs: usize = 32;

/// A modulus + its Montgomery constants, parameterized by an upper bound on the
/// modulus bit-width. `L = ceil(max_bits/64)` full 2^64 limbs; the modulus
/// occupies exactly `L` limbs (leading zero limbs are allowed as long as the
/// value is odd and ≥ 3).
pub fn Modint(comptime max_bits: comptime_int) type {
    comptime std.debug.assert(max_bits >= 8);
    return struct {
        const Self = @This();

        /// Number of full 2^64 limbs.
        pub const L: usize = (max_bits + 63) / 64;
        /// Byte width of a serialized element.
        pub const encoded_bytes: usize = (max_bits + 7) / 8;
        /// A field/ring element: `L` little-endian 2^64 limbs.
        pub const Elem = [L]u64;

        /// The odd modulus (little-endian, `L` limbs).
        m: Elem,
        /// `-m[0]⁻¹ mod 2^64`, the CIOS reduction constant.
        n0inv: u64,
        /// `R² mod m` where `R = 2^(64·L)` — used by `toMontgomery`.
        r2: Elem,
        /// `R mod m` — the value `1` in the Montgomery domain.
        one_mont: Elem,

        // ── construction ────────────────────────────────────────────────────

        /// Build a modulus from a big-endian byte string. Rejects even moduli,
        /// moduli < 3, and values that do not fit in `max_bits`.
        pub fn fromBytesBE(bytes: []const u8) Error!Self {
            const v = try elemFromBytesBE(Self, bytes);
            return fromElem(v);
        }

        /// Build a modulus from an `L`-limb little-endian value.
        pub fn fromElem(v: Elem) Error!Self {
            if (v[0] & 1 == 0) return error.EvenModulus;
            // reject < 3 (only limb 0, value 1) — 1 is not a valid modulus.
            var nonzero_high: u64 = 0;
            for (v[1..]) |w| nonzero_high |= w;
            if (nonzero_high == 0 and v[0] < 3) return error.ModulusTooSmall;

            var self: Self = .{
                .m = v,
                .n0inv = negInvMod2_64(v[0]),
                .r2 = undefined,
                .one_mont = undefined,
            };
            self.computeConstants();
            return self;
        }

        /// Actual bit-length of the modulus.
        pub fn bits(self: *const Self) usize {
            var i: usize = L;
            while (i > 0) : (i -= 1) {
                if (self.m[i - 1] != 0) {
                    return (i - 1) * 64 + (64 - @clz(self.m[i - 1]));
                }
            }
            return 0;
        }

        // Compute R mod m (= one_mont) and R² mod m (= r2) by repeated doubling
        // mod m. R² needs 128·L doublings; obviously-correct and cheap at setup.
        fn computeConstants(self: *Self) void {
            // acc = 1, double 64·L times -> 2^(64L) mod m = R mod m.
            var acc = std.mem.zeroes(Elem);
            acc[0] = 1;
            var i: usize = 0;
            while (i < 64 * L) : (i += 1) self.doubleMod(&acc);
            self.one_mont = acc;
            // continue another 64·L doublings -> 2^(128L) mod m = R² mod m.
            while (i < 128 * L) : (i += 1) self.doubleMod(&acc);
            self.r2 = acc;
        }

        // acc = 2·acc mod m, with acc < m on entry and exit. CT-shaped.
        fn doubleMod(self: *const Self, acc: *Elem) void {
            var top: u64 = 0;
            for (acc) |*w| {
                const nw = (w.* << 1) | top;
                top = w.* >> 63;
                w.* = nw;
            }
            condSubTop(acc, top, &self.m);
        }

        // ── domain conversion ───────────────────────────────────────────────

        /// Reduce a big-endian byte string into a normal-domain element `< m`.
        pub fn elementFromBytesBE(self: *const Self, bytes: []const u8) Error!Elem {
            const v = try elemFromBytesBE(Self, bytes);
            if (limbs.cmp(&v, &self.m) != .lt) return error.NonCanonical;
            return v;
        }

        /// Serialize a normal-domain element to a big-endian byte string.
        pub fn toBytesBE(self: *const Self, v: *const Elem, out: []u8) void {
            _ = self;
            std.debug.assert(out.len == encoded_bytes);
            var bit: usize = 0;
            var oi: usize = out.len;
            @memset(out, 0);
            while (bit < max_bits) : (bit += 8) {
                const limb = bit / 64;
                const shift: u6 = @intCast(bit % 64);
                oi -= 1;
                out[oi] = @truncate(v[limb] >> shift);
            }
        }

        /// `a` (normal domain) → Montgomery domain (`a·R mod m`).
        pub fn toMontgomery(self: *const Self, a: *const Elem) Elem {
            return self.montMul(a, &self.r2);
        }

        /// `a` (Montgomery domain) → normal domain (`a·R⁻¹ mod m`).
        pub fn fromMontgomery(self: *const Self, a_mont: *const Elem) Elem {
            var one = std.mem.zeroes(Elem);
            one[0] = 1;
            return self.montMul(a_mont, &one);
        }

        // ── modular arithmetic ──────────────────────────────────────────────

        /// `(a + b) mod m`, domain-agnostic (both operands same domain).
        pub fn add(self: *const Self, a: *const Elem, b: *const Elem) Elem {
            var out = a.*;
            const carry = limbs.addInto(&out, b);
            condSubTop(&out, carry, &self.m);
            return out;
        }

        /// `(a − b) mod m`, domain-agnostic (both operands same domain).
        pub fn sub(self: *const Self, a: *const Elem, b: *const Elem) Elem {
            var out = a.*;
            const borrow = limbs.subInto(&out, b);
            // if it underflowed, add m back (CT).
            var addm = self.m;
            const mask: u64 = 0 -% @as(u64, borrow);
            for (&addm) |*w| w.* &= mask;
            _ = limbs.addInto(&out, &addm);
            return out;
        }

        /// `(a · b) mod m` in the NORMAL domain (the user-facing modmul the KAT
        /// pins). Costs two Montgomery multiplies: `montMul(toMont(a), b)`.
        pub fn mul(self: *const Self, a: *const Elem, b: *const Elem) Elem {
            const a_mont = self.toMontgomery(a);
            return self.montMul(&a_mont, b);
        }

        /// Montgomery multiply `z = a·b·R⁻¹ mod m`. Dispatches to the gated
        /// amd64 core when active, else the portable CIOS oracle. Both operands
        /// and the result are `L` full-limb values; the result is fully reduced
        /// (`z < m`).
        pub fn montMul(self: *const Self, a: *const Elem, b: *const Elem) Elem {
            var z: Elem = undefined;
            // Small-L cutoff: asm only pays off for large moduli (see
            // `asm_min_limbs`); pairing fields (L=4/6) stay portable.
            if (comptime asm_active and L >= asm_min_limbs) {
                asm_core.montMul(&z, a, b, &self.m, self.n0inv);
            } else {
                z = self.montMulCios(a, b);
            }
            return z;
        }

        /// True iff `montMul` on this `Modint` routes to the amd64 asm core
        /// (asm available+on AND the modulus is large enough to clear the
        /// `asm_min_limbs` small-L cutoff). Used by the bench harness.
        pub fn dispatchesToAsm() bool {
            return asm_active and L >= asm_min_limbs;
        }

        /// Montgomery squaring `a²·R⁻¹ mod m`. Portable path reuses `montMul`;
        /// a dedicated asm squaring is an optional future core.
        pub fn montSqr(self: *const Self, a: *const Elem) Elem {
            return self.montMul(a, a);
        }

        /// The PORTABLE constant-time CIOS Montgomery multiply — the oracle.
        /// Coarsely Integrated Operand Scanning (Koç et al., Fig. 6), radix
        /// 2^64, with `u128` widening products. No secret-dependent branch,
        /// index, or early exit; the final reduction is a constant-time
        /// conditional subtract.
        pub fn montMulCios(self: *const Self, a: *const Elem, b: *const Elem) Elem {
            const m = &self.m;
            // t holds L+2 words across the interleaved multiply/reduce passes.
            var t = [_]u64{0} ** (L + 2);
            var i: usize = 0;
            while (i < L) : (i += 1) {
                // t += a * b[i]
                var carry: u64 = 0;
                var j: usize = 0;
                while (j < L) : (j += 1) {
                    const p = @as(u128, a[j]) * @as(u128, b[i]) + t[j] + carry;
                    t[j] = @truncate(p);
                    carry = @truncate(p >> 64);
                }
                const s = @as(u128, t[L]) + carry;
                t[L] = @truncate(s);
                t[L + 1] = @truncate(s >> 64);

                // u = t[0] * n0inv mod 2^64 ; t = (t + u*m) / 2^64
                const u = t[0] *% self.n0inv;
                const p0 = @as(u128, u) * @as(u128, m[0]) + t[0];
                var carry2: u64 = @truncate(p0 >> 64); // low word is 0 by construction
                j = 1;
                while (j < L) : (j += 1) {
                    const p = @as(u128, u) * @as(u128, m[j]) + t[j] + carry2;
                    t[j - 1] = @truncate(p);
                    carry2 = @truncate(p >> 64);
                }
                const s2 = @as(u128, t[L]) + carry2;
                t[L - 1] = @truncate(s2);
                t[L] = t[L + 1] +% @as(u64, @truncate(s2 >> 64));
            }
            // result = t[0..L] with possible top word t[L] (0 or 1); reduce.
            var z: Elem = undefined;
            @memcpy(&z, t[0..L]);
            condSubTop(&z, t[L], m);
            return z;
        }

        // ── modular exponentiation ──────────────────────────────────────────

        /// `base^exp mod m` (normal domain in and out), constant-time in the
        /// exponent VALUE: fixed 5-bit window, every window does a multiply
        /// (digit 0 multiplies by `1`), the table gather is a branchless CT
        /// select over all 32 entries, and all `L·64` exponent bits are always
        /// processed. This is the analogue of the `ff` secret-modexp path and
        /// the guarantee the `rsa`/`paillier` audits rely on.
        ///
        /// `exp` is an `L`-limb little-endian value.
        pub fn powMont(self: *const Self, base: *const Elem, exp: *const Elem) Elem {
            const w: usize = 5;
            const table_len: usize = 1 << w;

            const base_mont = self.toMontgomery(base);
            // table[k] = base^k in the Montgomery domain.
            var table: [table_len]Elem = undefined;
            table[0] = self.one_mont;
            table[1] = base_mont;
            var k: usize = 2;
            while (k < table_len) : (k += 1) {
                table[k] = self.montMul(&table[k - 1], &base_mont);
            }

            var acc = self.one_mont;
            const total_bits = L * 64;
            // number of windows, MSB-aligned (top window may be partly zero).
            const nwin = (total_bits + w - 1) / w;
            var win: usize = nwin;
            while (win > 0) {
                win -= 1;
                // square w times (no-op on the very first, acc == 1).
                var s: usize = 0;
                while (s < w) : (s += 1) acc = self.montSqr(&acc);
                const digit = getBits(exp, win * w, w);
                // constant-time gather of table[digit].
                var g = std.mem.zeroes(Elem);
                var idx: usize = 0;
                while (idx < table_len) : (idx += 1) {
                    const on: u1 = @intFromBool(idx == digit);
                    for (&g, &table[idx]) |*gl, tl| gl.* = limbs.select(on, tl, gl.*);
                }
                acc = self.montMul(&acc, &g);
            }
            return self.fromMontgomery(&acc);
        }

        // ── internal CT helpers ─────────────────────────────────────────────

        // Constant-time conditional subtract of `m` from the (L+1)-word value
        // (`v` low L words, `top` the carry word 0/1). Subtracts m iff the full
        // value ≥ m. `v < 2m` on entry, so `top ≤ 1` and the result is `< m`.
        fn condSubTop(v: *Elem, top: u64, m: *const Elem) void {
            var diff: Elem = undefined;
            var borrow: u1 = 0;
            for (&diff, v, m) |*d, vi, mi| {
                const s = @subWithOverflow(vi, mi);
                const s2 = @subWithOverflow(s[0], borrow);
                d.* = s2[0];
                borrow = s[1] | s2[1];
            }
            // full value ≥ m  ⟺  no underflow when subtracting borrow from top.
            const under = @subWithOverflow(top, borrow)[1]; // 1 ⇒ value < m
            const keep_orig: u64 = 0 -% @as(u64, under);
            for (v, &diff) |*vi, di| {
                vi.* = (vi.* & keep_orig) | (di & ~keep_orig);
            }
        }

        // Extract `count` (≤ 8) bits from an L-limb value starting at bit `off`
        // (bits at/above `L·64` read as 0). Not secret-branching on the value.
        fn getBits(v: *const Elem, off: usize, count: usize) usize {
            var out: usize = 0;
            var b: usize = 0;
            while (b < count) : (b += 1) {
                const pos = off + b;
                var bit: u1 = 0;
                if (pos < L * 64) {
                    const limb = pos / 64;
                    const sh: u6 = @intCast(pos % 64);
                    bit = @truncate(v[limb] >> sh);
                }
                out |= @as(usize, bit) << @intCast(b);
            }
            return out;
        }
    };
}

// ── free helpers ────────────────────────────────────────────────────────────

/// `-x⁻¹ mod 2^64` for odd `x`, via Newton–Hensel doubling (6 steps: correct
/// bits double 1→2→4→…→64).
pub fn negInvMod2_64(x: u64) u64 {
    var y: u64 = 1; // x⁻¹ mod 2 (x is odd)
    inline for (0..6) |_| y = y *% (2 -% x *% y);
    return 0 -% y; // -(x⁻¹)
}

fn elemFromBytesBE(comptime M: type, bytes: []const u8) M.Error!M.Elem {
    var v = std.mem.zeroes(M.Elem);
    if (bytes.len == 0) return v;
    var bit: usize = 0;
    var i: usize = bytes.len;
    while (i > 0) : (bit += 8) {
        i -= 1;
        const byte = bytes[i];
        if (byte == 0) continue;
        const limb = bit / 64;
        const sh: u6 = @intCast(bit % 64);
        if (limb >= M.L) return error.Overflow;
        const wide = @as(u128, byte) << sh;
        v[limb] |= @as(u64, @truncate(wide));
        if (sh != 0 and (wide >> 64) != 0) {
            if (limb + 1 >= M.L) return error.Overflow;
            v[limb + 1] |= @as(u64, @truncate(wide >> 64));
        }
    }
    return v;
}

test "negInvMod2_64: m·(-m⁻¹) ≡ -1 mod 2^64" {
    for ([_]u64{ 3, 5, 0xffff_ffff_ffff_ffff, 0x1234_5678_9abc_def1 }) |m| {
        const ni = negInvMod2_64(m);
        try std.testing.expectEqual(@as(u64, 0), m *% ni +% 1);
    }
}
