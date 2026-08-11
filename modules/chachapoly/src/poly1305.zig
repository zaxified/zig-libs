// SPDX-License-Identifier: MIT

//! poly1305 — lane-parallel Poly1305 one-time authenticator (RFC 8439 §2.5).
//!
//! `std.crypto.onetimeauth.Poly1305` evaluates the polynomial one 16-byte block
//! at a time in a 2×64-bit + 2-bit limb layout, using 64×64→128 multiplies. That
//! is a good *scalar* shape, but it is strictly serial: block `i+1`'s multiply
//! depends on block `i`'s. On this repo's AEAD hot path (ChaCha20-Poly1305 for
//! WireGuard / Noise / TLS bulk) the MAC is roughly half the total cost, and it
//! is the half that does not vectorise for free.
//!
//! ## The parallel form
//!
//! Poly1305 computes `H = Σ mᵢ · r^(n−i+1)` in GF(2^130−5). Split the blocks
//! across `L` lanes by index mod `L` and run a Horner recurrence per lane with
//! the *same* multiplier `r^L`:
//!
//!     A ← A · r^L + M      (lane-wise, M = the L blocks of one group)
//!
//! then fold the lanes at the very end with the power vector
//! `(r^L, r^(L−1), …, r^1)` and a horizontal sum. Lane `j` holding block
//! `i = j+1+tL` then contributes `r^(L(G−1−t)) · r^(L−j) = r^(n−i+1)` — the
//! required exponent. The running accumulator carried in from earlier `update`
//! calls is seeded into lane 0 of the *first* group, which gives it `r^n`.
//!
//! ## Limb layout: 5×26 bits, not 2×64
//!
//! The scalar layout cannot be vectorised on x86: there is no 64×64→128 SIMD
//! multiply. The one wide multiply SSE2/AVX2/AVX-512 do have is
//! `PMULUDQ` — 32×32→64, on the even 32-bit lanes. So the field element is held
//! as **five 26-bit limbs**: every operand then fits in 32 bits, every partial
//! product in 64, and the reduction `2^130 ≡ 5` is a shift-and-multiply-by-5.
//!
//! `PMULUDQ` is reached without an intrinsic: the limbs live in
//! `@Vector(L, u32)` and are widened with `@intCast` to `@Vector(L, u64)`
//! before multiplying, so LLVM sees `mul (zext a), (zext b)` — the exact pattern
//! its x86 backend folds into `vpmuludq`. Keeping the *stored* limbs `u32`
//! (rather than `u64` masked to 26 bits) is what makes the upper half provably
//! zero at every use, instead of hoping known-bits analysis survives the carry
//! chain.
//!
//! ## Deferred-carry bounds (the part these implementations get wrong)
//!
//! Invariant entering a multiply: every limb `< 2^27.6`, `rᵢ < 2^26`,
//! `sᵢ = 5rᵢ < 2^28.33`. Each `dᵢ` is a sum of five products, so
//! `dᵢ < 5 · 2^27.6 · 2^28.33 < 2^58.3` — comfortably inside u64 with ~5 bits of
//! headroom. The carry chain masks limbs 0..4 to 26 bits, folds the top carry
//! `c < 2^32.3` back as `5c` into limb 0 (`< 2^35`), re-carries once, and leaves
//! limb 1 `< 2^26 + 2^9 < 2^27`. Adding the next message block's limb
//! (`< 2^26`) restores `< 2^27.6`. The arithmetic uses checked `*`/`+`, not
//! `*%`/`+%`, precisely so that a bounds mistake panics in Debug/ReleaseSafe
//! rather than silently forging a tag.
//!
//! ## Hybrid, because the vector form has a floor
//!
//! Lane-parallelism is not free: the `r^1..r^L` power table costs `L−1` field
//! multiplies before the first group, and the 5×26-bit layout that makes SIMD
//! possible is *worse* than 2×64 when run serially (five schoolbook rows
//! instead of one `mulx`). A pure-vector Poly1305 measured **0.47×** std at 64
//! bytes on this host — a real regression on precisely the short-packet traffic
//! (WireGuard keepalives, handshakes) that the data-plane case cares about.
//!
//! So `Generic(L)` *contains* `std.crypto.onetimeauth.Poly1305` and delegates
//! to it for the key, the leftover buffer, the tail, the final reduction and
//! the tag. It intercepts only runs of at least `wide_min_groups` whole lane
//! groups, hands those to the vector engine, and folds the accumulator back.
//! Below that threshold the code path is std's, byte for byte and cycle for
//! cycle. Measured: parity (0.94–1.01×) at ≤ 128 B, crossing over around 256 B,
//! 2.0× at 1 KiB, 2.5–2.7× at 8 KiB.
//!
//! ## Portability
//!
//! `lanes` is chosen at **comptime** from the target's features; on anything
//! without a wide integer SIMD multiply worth using it is 1, and `Poly1305` is
//! then a direct alias of `std.crypto.onetimeauth.Poly1305` — the scalar
//! 64-bit path, which beats a 26-bit-limb scalar emulation. There is no runtime
//! CPU dispatch and no x86 assumption in the vector code itself: `Generic(L)`
//! is written against `@Vector` alone and is exercised by the tests at
//! L ∈ {1,2,4,8} on every target, including ones where `lanes == 1` means the
//! shipped MAC never runs it.
//!
//! ## Constant time
//!
//! Add / multiply / shift / mask only. No secret-dependent branch, no
//! secret-indexed load; the final conditional subtraction of `2^130−5` is std's
//! borrow-mask select, unchanged. The only branches added here are on message
//! length and buffer occupancy, which are public.

const std = @import("std");
const builtin = @import("builtin");
const mem = std.mem;

/// Number of blocks authenticated per multiply step. Comptime-selected; 1 means
/// "no SIMD win available here, use the std scalar MAC".
///
/// * AVX-512F: `@Vector(8, u64)` is one zmm → 8 `vpmuludq` lanes.
/// * AVX2:     `@Vector(4, u64)` is one ymm → 4 `vpmuludq` lanes.
/// * else:     scalar. SSE2 would give 2 lanes, and NEON's `umull` likewise,
///             but 2×26-bit lanes does not beat a 64×64→128 scalar multiply, so
///             claiming it would be a pessimisation dressed as portability.
pub const lanes: usize = if (builtin.cpu.has(.x86, .avx512f))
    8
else if (builtin.cpu.has(.x86, .avx2))
    4
else
    1;

/// True when `Poly1305` below is the vector implementation rather than std's.
pub const simd_active = lanes > 1;

/// The MAC this module's AEAD uses. API-identical to
/// `std.crypto.onetimeauth.Poly1305` either way.
pub const Poly1305 = if (simd_active) Generic(lanes) else std.crypto.onetimeauth.Poly1305;

const limb_mask: u32 = 0x3ff_ffff; // 2^26 − 1

/// Widen a `[5]@Vector(W, u32)` limb set to u64 lanes. The `@intCast` is a
/// zero-extend, which is what makes the `mul` foldable into `vpmuludq`.
fn widen(comptime W: usize, v: [5]@Vector(W, u32)) [5]@Vector(W, u64) {
    var out: [5]@Vector(W, u64) = undefined;
    inline for (0..5) |i| out[i] = @intCast(v[i]);
    return out;
}

/// `h · r mod 2^130−5`, lane-wise, in 5×26-bit limbs. `s[i]` must be `5·r[i]`.
/// Returns limbs satisfying the deferred-carry invariant documented above.
fn mulRed(
    comptime W: usize,
    h: [5]@Vector(W, u32),
    r: [5]@Vector(W, u32),
    s: [5]@Vector(W, u32),
) [5]@Vector(W, u32) {
    const V64 = @Vector(W, u64);
    const mask: V64 = @splat(limb_mask);
    const sh26: @Vector(W, u6) = @splat(26);

    const a = widen(W, h);
    const b = widen(W, r);
    const c5 = widen(W, s);

    // Schoolbook 5×5 with the 2^130 ≡ 5 wrap already folded in via s = 5r.
    var d: [5]V64 = .{
        a[0] * b[0] + a[1] * c5[4] + a[2] * c5[3] + a[3] * c5[2] + a[4] * c5[1],
        a[0] * b[1] + a[1] * b[0] + a[2] * c5[4] + a[3] * c5[3] + a[4] * c5[2],
        a[0] * b[2] + a[1] * b[1] + a[2] * b[0] + a[3] * c5[4] + a[4] * c5[3],
        a[0] * b[3] + a[1] * b[2] + a[2] * b[1] + a[3] * b[0] + a[4] * c5[4],
        a[0] * b[4] + a[1] * b[3] + a[2] * b[2] + a[3] * b[1] + a[4] * b[0],
    };

    // Deferred carry: propagate once through the limbs, wrap the top back as 5c.
    var carry: V64 = d[0] >> sh26;
    d[0] &= mask;
    inline for (1..5) |i| {
        d[i] += carry;
        carry = d[i] >> sh26;
        d[i] &= mask;
    }
    const five: V64 = @splat(5);
    d[0] += carry * five;
    carry = d[0] >> sh26;
    d[0] &= mask;
    d[1] += carry; // < 2^26 + 2^9; the invariant allows < 2^27.6

    var out: [5]@Vector(W, u32) = undefined;
    inline for (0..5) |i| out[i] = @truncate(d[i]);
    return out;
}

/// Split `W` consecutive 16-byte blocks into 5×26-bit limbs, one block per lane,
/// with the implicit 2^128 bit set. The wide path only ever sees *whole*
/// blocks — the zero-padded final block is the serial engine's job — so the
/// high bit is unconditional here.
fn loadBlocks(comptime W: usize, m: *const [16 * W]u8) [5]@Vector(W, u32) {
    var cols: [4][W]u32 = undefined;
    inline for (0..W) |j| {
        inline for (0..4) |k| {
            cols[k][j] = mem.readInt(u32, m[16 * j + 4 * k ..][0..4], .little);
        }
    }
    const V = @Vector(W, u32);
    const t0: V = cols[0];
    const t1: V = cols[1];
    const t2: V = cols[2];
    const t3: V = cols[3];
    const mask: V = @splat(limb_mask);
    const hi: V = @splat(1 << 24);
    const s6: @Vector(W, u5) = @splat(6);
    const s8: @Vector(W, u5) = @splat(8);
    const s12: @Vector(W, u5) = @splat(12);
    const s14: @Vector(W, u5) = @splat(14);
    const s18: @Vector(W, u5) = @splat(18);
    const s20: @Vector(W, u5) = @splat(20);
    const s26: @Vector(W, u5) = @splat(26);
    return .{
        t0 & mask,
        ((t0 >> s26) | (t1 << s6)) & mask,
        ((t1 >> s20) | (t2 << s12)) & mask,
        ((t2 >> s14) | (t3 << s18)) & mask,
        (t3 >> s8) | hi,
    };
}

/// Carry a 5-limb value whose limbs may be up to ~2^32 back into the
/// `< 2^26` (limb 1: `< 2^27`) invariant. Used after the lane fold and on the
/// scalar accumulator.
fn carryLimbs(x: [5]u64) [5]u32 {
    var d = x;
    var carry: u64 = d[0] >> 26;
    d[0] &= limb_mask;
    inline for (1..5) |i| {
        d[i] += carry;
        carry = d[i] >> 26;
        d[i] &= limb_mask;
    }
    d[0] += carry * 5;
    carry = d[0] >> 26;
    d[0] &= limb_mask;
    d[1] += carry;

    var out: [5]u32 = undefined;
    inline for (0..5) |i| out[i] = @truncate(d[i]);
    return out;
}

/// Lane-parallel Poly1305 over `L` blocks per step.
///
/// **Hybrid, on purpose.** The lane-parallel engine only wins once there are
/// enough blocks to amortise the `r^1..r^L` power table, and the 5×26-bit limb
/// layout that makes SIMD possible is *worse* than a 2×64-bit layout when run
/// serially (five schoolbook rows instead of one 64×64→128 multiply). Measured
/// on this repo's bench, a pure-vector Poly1305 authenticating 64 bytes ran at
/// **0.47×** the std scalar MAC — a real regression on exactly the short-packet
/// traffic (WireGuard keepalives, handshakes) the data-plane case cares about.
///
/// So the serial engine here *is* `std.crypto.onetimeauth.Poly1305`: it owns
/// the clamped key, the leftover buffer, the final reduction and the tag. This
/// type intercepts only long runs of whole blocks, hands them to the vector
/// engine, and folds the result back. Short inputs are then bit-for-bit std at
/// std's speed, and the SIMD win applies where it is actually a win.
///
/// `L = 1` degenerates to plain std (the `L > 1` guard removes the wide path
/// entirely); it is still instantiated by the tests as a control.
pub fn Generic(comptime L: usize) type {
    return struct {
        const Self = @This();
        const V = @Vector(L, u32);

        pub const block_length: usize = 16;
        pub const mac_length = 16;
        pub const key_length = 32;

        /// Whole lane-groups required before the wide path is taken. Below this
        /// the power-table build (L−1 field multiplies plus normalisation)
        /// costs more than the lanes save. Tuned by measurement — see the
        /// module bench's `poly1305 64B` / `aead 1420B packet` lines.
        const wide_min_groups = 3;
        const wide_min_bytes = block_length * L * wide_min_groups;

        /// The serial engine and the single source of truth for the
        /// accumulator, the leftover buffer, the key and the tag.
        ///
        /// Three of its fields are read across the seam, all public, all with a
        /// meaning forced by the algorithm rather than by std's choices:
        ///
        ///   * `h` — the partially-reduced accumulator
        ///     `h[0] + h[1]·2^64 + h[2]·2^128`, `h[2]` small. Read on entry to
        ///     the wide path and written back on exit.
        ///   * `r` — the *clamped* key half, `r[0] + r[1]·2^64`. Re-split into
        ///     26-bit limbs when the power table is built. Taking it from here
        ///     rather than re-clamping means there is exactly one clamp in the
        ///     program.
        ///   * `leftover` — how full the partial-block buffer is, so the wide
        ///     path can tell whether it is on a block boundary.
        ///
        /// Any drift in those meanings fails the length-sweep differential in
        /// this file immediately — it is not a silent coupling.
        inner: std.crypto.onetimeauth.Poly1305,

        /// r^L and 5·r^L, for the lane-wise Horner step.
        rl: [5]u32 = undefined,
        sl: [5]u32 = undefined,
        /// Lane j holds r^(L−j) / 5·r^(L−j), for the final lane fold.
        rp: [5]V = undefined,
        sp: [5]V = undefined,
        /// Built lazily on first use of the wide path.
        powers_ready: bool = false,

        /// Nothing here but std's own init: a message that never reaches the
        /// wide path must cost exactly what std costs, setup included.
        pub fn init(key: *const [key_length]u8) Self {
            return .{ .inner = std.crypto.onetimeauth.Poly1305.init(key) };
        }

        /// Fully normalise to `< 2^26` per limb, so that `5·limb` stays under
        /// the `s < 2^28.33` bound `mulRed` assumes. Two carry passes suffice:
        /// the first leaves limb 1 `< 2^26 + 2^9`, the second drains it.
        fn normalize(x: [5]u32) [5]u32 {
            var w: [5]u64 = undefined;
            inline for (0..5) |i| w[i] = x[i];
            const a = carryLimbs(w);
            inline for (0..5) |i| w[i] = a[i];
            return carryLimbs(w);
        }

        /// One field multiply at width 1 — the same `mulRed` the wide path
        /// uses, so the power table cannot diverge from the loop's arithmetic.
        fn mul1(a: [5]u32, b: [5]u32, b5: [5]u32) [5]u32 {
            var av: [5]@Vector(1, u32) = undefined;
            var bv: [5]@Vector(1, u32) = undefined;
            var b5v: [5]@Vector(1, u32) = undefined;
            inline for (0..5) |i| {
                av[i] = @splat(a[i]);
                bv[i] = @splat(b[i]);
                b5v[i] = @splat(b5[i]);
            }
            const p = mulRed(1, av, bv, b5v);
            var out: [5]u32 = undefined;
            inline for (0..5) |i| out[i] = p[i][0];
            return out;
        }

        fn buildPowers(st: *Self) void {
            // Re-split std's already-clamped r (RFC 8439 §2.5) into 26-bit
            // limbs. `inner.r` is `r[0] + r[1]·2^64`, so r < 2^124 and every
            // limb below is < 2^26 without a further carry.
            const rlo = st.inner.r[0];
            const rhi = st.inner.r[1];
            const r: [5]u32 = .{
                @truncate(rlo & limb_mask),
                @truncate((rlo >> 26) & limb_mask),
                @truncate(((rlo >> 52) | (rhi << 12)) & limb_mask),
                @truncate((rhi >> 14) & limb_mask),
                @truncate((rhi >> 40) & limb_mask),
            };
            var s: [5]u32 = undefined;
            inline for (0..5) |i| s[i] = r[i] * 5;

            var pw: [L][5]u32 = undefined;
            pw[0] = r;
            inline for (1..L) |k| pw[k] = normalize(mul1(pw[k - 1], r, s));

            st.rl = pw[L - 1];
            inline for (0..5) |i| st.sl[i] = st.rl[i] * 5;

            // Lane j gets r^(L−j): lane 0 → r^L, lane L−1 → r^1.
            var rp: [5][L]u32 = undefined;
            var sp: [5][L]u32 = undefined;
            inline for (0..L) |j| {
                const p = pw[L - 1 - j];
                inline for (0..5) |i| {
                    rp[i][j] = p[i];
                    sp[i][j] = p[i] * 5;
                }
            }
            inline for (0..5) |i| {
                st.rp[i] = rp[i];
                st.sp[i] = sp[i];
            }
            st.powers_ready = true;
        }

        /// std's `[3]u64` accumulator → 5×26-bit limbs. `h[2] < 8` holds for
        /// std's partial reduction, so limb 4 stays under 2^27 and the
        /// subsequent carry brings everything back into range.
        fn importAcc(h: [3]u64) [5]u32 {
            const w: [5]u64 = .{
                h[0] & limb_mask,
                (h[0] >> 26) & limb_mask,
                ((h[0] >> 52) | (h[1] << 12)) & limb_mask,
                (h[1] >> 14) & limb_mask,
                (h[1] >> 40) | (h[2] << 24),
            };
            return carryLimbs(w);
        }

        /// 5×26-bit limbs → std's `[3]u64`. The input is fully normalised first,
        /// so the result satisfies `h < 2^130` and `h[2] <= 3` — well inside
        /// what std's block loop expects to be handed.
        fn exportAcc(limbs: [5]u32) [3]u64 {
            const f = normalize(limbs);
            return .{
                @as(u64, f[0]) | (@as(u64, f[1]) << 26) | (@as(u64, f[2]) << 52),
                (@as(u64, f[2]) >> 12) | (@as(u64, f[3]) << 14) | (@as(u64, f[4]) << 40),
                @as(u64, f[4]) >> 24,
            };
        }

        /// Absorb `m` (a whole number of lane groups) through the vector engine.
        fn wide(st: *Self, m: []const u8) void {
            std.debug.assert(m.len % (block_length * L) == 0 and m.len > 0);
            if (!st.powers_ready) st.buildPowers();

            // Group 0: A = M₀, with the carried-in accumulator seeded into lane
            // 0 so that it ends up multiplied by r^n like every other term.
            const seed_limbs = importAcc(st.inner.h);
            var acc = loadBlocks(L, m[0..][0 .. block_length * L]);
            inline for (0..5) |k| {
                var seed: [L]u32 = .{0} ** L;
                seed[0] = seed_limbs[k];
                acc[k] += @as(V, seed);
            }

            var rlv: [5]V = undefined;
            var slv: [5]V = undefined;
            inline for (0..5) |k| {
                rlv[k] = @splat(st.rl[k]);
                slv[k] = @splat(st.sl[k]);
            }

            var i: usize = block_length * L;
            while (i < m.len) : (i += block_length * L) {
                acc = mulRed(L, acc, rlv, slv);
                const lm = loadBlocks(L, m[i..][0 .. block_length * L]);
                inline for (0..5) |k| acc[k] += lm[k];
            }

            // Fold the lanes: multiply lane j by r^(L−j), then sum lanes.
            const folded = mulRed(L, acc, st.rp, st.sp);
            var sum: [5]u64 = .{ 0, 0, 0, 0, 0 };
            inline for (0..5) |k| {
                inline for (0..L) |j| sum[k] += folded[k][j];
            }
            st.inner.h = exportAcc(carryLimbs(sum));
        }

        pub fn update(st: *Self, m: []const u8) void {
            // Fast path: too short for the wide engine even after the current
            // partial block is filled, so this is pure std. One predictable
            // branch — the short-packet case must not pay for the wide path's
            // bookkeeping.
            if (L == 1 or m.len + block_length < wide_min_bytes) {
                st.inner.update(m);
                return;
            }

            var mb = m;

            // 1. Top up any partial block through the serial engine, so the
            //    wide path always starts on a block boundary.
            if (st.inner.leftover > 0) {
                const want = @min(block_length - st.inner.leftover, mb.len);
                st.inner.update(mb[0..want]);
                mb = mb[want..];
            }

            // 2. Long run of whole blocks → vector engine, whole groups only.
            if (L > 1 and st.inner.leftover == 0 and mb.len >= wide_min_bytes) {
                const groups = mb.len / (block_length * L);
                st.wide(mb[0 .. groups * block_length * L]);
                mb = mb[groups * block_length * L ..];
            }

            // 3. The remainder (< L blocks, plus any trailing partial) is
            //    serial: std's 2×64-bit core beats the 26-bit layout here.
            if (mb.len > 0) st.inner.update(mb);
        }

        /// Zero-pad to align the next input to the first byte of a block.
        pub fn pad(st: *Self) void {
            st.inner.pad();
        }

        pub fn final(st: *Self, out: *[mac_length]u8) void {
            st.inner.final(out); // wipes `inner`, including the key material

            // The power table is r^1..r^L — secret-derived, and outside
            // `inner`, so std's wipe does not reach it. Wiped only if it was
            // ever built: a short message never touches it, and an
            // unconditional wipe of ~180 bytes is a measurable tax on exactly
            // the short-packet path this hybrid exists to protect.
            if (st.powers_ready) {
                std.crypto.secureZero(u32, &st.rl);
                std.crypto.secureZero(u32, &st.sl);
                std.crypto.secureZero(u8, mem.asBytes(&st.rp));
                std.crypto.secureZero(u8, mem.asBytes(&st.sp));
                st.powers_ready = false;
            }
        }

        pub fn create(out: *[mac_length]u8, msg: []const u8, key: *const [key_length]u8) void {
            var st = Self.init(key);
            st.update(msg);
            st.final(out);
        }
    };
}

// ── tests ────────────────────────────────────────────────────────────────────

const testing = std.testing;
const StdPoly = std.crypto.onetimeauth.Poly1305;

/// Every width, on every target: L = 1 is the degenerate scalar case, 2 and 4
/// straddle the SSE2/AVX2 shapes, 8 is the AVX-512 shape. Instantiating all of
/// them here means the vector code is differentially anchored even on a build
/// where `lanes == 1` selects the std MAC.
const widths = [_]usize{ 1, 2, 4, 8 };

// RFC 8439 §2.5.2 — the worked Poly1305 example.
test "RFC 8439 §2.5.2 worked example, every lane width" {
    const key = [_]u8{
        0x85, 0xd6, 0xbe, 0x78, 0x57, 0x55, 0x6d, 0x33, 0x7f, 0x44, 0x52, 0xfe, 0x42, 0xd5, 0x06, 0xa8,
        0x01, 0x03, 0x80, 0x8a, 0xfb, 0x0d, 0xb2, 0xfd, 0x4a, 0xbf, 0xf6, 0xaf, 0x41, 0x49, 0xf5, 0x1b,
    };
    const msg = "Cryptographic Forum Research Group";
    const expected = [_]u8{
        0xa8, 0x06, 0x1d, 0xc1, 0x30, 0x51, 0x36, 0xc6, 0xc2, 0x2b, 0x8b, 0xaf, 0x0c, 0x01, 0x27, 0xa9,
    };
    inline for (widths) |L| {
        var tag: [16]u8 = undefined;
        Generic(L).create(&tag, msg, &key);
        try testing.expectEqualSlices(u8, &expected, &tag);
    }
}

// RFC 8439 §A.3 — the Poly1305 test-vector table. These are exactly the edge
// cases a parallel implementation breaks on: an all-zero r (every product
// vanishes), an all-zero s, r = 2^130−6 with a message that forces the final
// conditional subtraction, and the two "imperfect carry propagation" vectors
// #10/#11 that were written to catch a wrong carry chain.
const A3Vector = struct { key: [32]u8, msg: []const u8, tag: [16]u8 };

fn hex(comptime s: []const u8) [s.len / 2]u8 {
    var out: [s.len / 2]u8 = undefined;
    _ = std.fmt.hexToBytes(&out, s) catch unreachable;
    return out;
}

test "RFC 8439 §A.3 Poly1305 vectors, every lane width" {
    // #1: r = 0, s = 0 over 64 zero bytes → zero tag.
    const v1_key = [_]u8{0} ** 32;
    const v1_msg = [_]u8{0} ** 64;
    const v1_tag = [_]u8{0} ** 16;

    // #2: r = 0, s ≠ 0 → the tag is s itself, whatever the message.
    const v2_key = hex("0000000000000000000000000000000036e5f6b5c5e06070f0efca96227a863e");
    const v2_msg = "Any submission to the IETF intended by the Contributor for publication as all or part of an IETF Internet-Draft or RFC and any statement made within the context of an IETF activity is considered an \"IETF Contribution\". Such statements include oral statements in IETF sessions, as well as written and electronic communications made at any time or place, which are addressed to";
    const v2_tag = hex("36e5f6b5c5e06070f0efca96227a863e");

    // #3: the mirror of #2 — r ≠ 0, s = 0.
    const v3_key = hex("36e5f6b5c5e06070f0efca96227a863e00000000000000000000000000000000");
    const v3_msg = v2_msg;
    const v3_tag = hex("f3477e7cd95417af89a6b8794c310cf0");

    // #4: 127 bytes — an odd length that lands mid-lane for every L.
    const v4_key = hex("1c9240a5eb55d38af333888604f6b5f0473917c1402b80099dca5cbc207075c0");
    const v4_msg = "'Twas brillig, and the slithy toves\nDid gyre and gimble in the wabe:\nAll mimsy were the borogoves,\nAnd the mome raths outgrabe.";
    const v4_tag = hex("4541669a7eaaee61e708dc7cbcc5eb62");

    // #5: r = 2 and a 2^128−1 message — forces the top-limb wrap.
    const v5_key = hex("0200000000000000000000000000000000000000000000000000000000000000");
    const v5_msg = hex("ffffffffffffffffffffffffffffffff");
    const v5_tag = hex("03000000000000000000000000000000");

    // #6: s = 2^130−6 exercises the final addition's carry out of 128 bits.
    const v6_key = hex("02000000000000000000000000000000ffffffffffffffffffffffffffffffff");
    const v6_msg = hex("02000000000000000000000000000000");
    const v6_tag = hex("03000000000000000000000000000000");

    // #7 / #8: the two "imperfect carry propagation" vectors.
    const v7_key = hex("0100000000000000000000000000000000000000000000000000000000000000");
    const v7_msg = hex("fffffffffffffffffffffffffffffffff0ffffffffffffffffffffffffffffff") ++ hex("11000000000000000000000000000000");
    const v7_tag = hex("05000000000000000000000000000000");

    const v8_key = v7_key;
    const v8_msg = hex("fffffffffffffffffffffffffffffffffbfefefefefefefefefefefefefefefe") ++ hex("01010101010101010101010101010101");
    const v8_tag = hex("00000000000000000000000000000000");

    // #9: h = 2^130−6 exactly (no final subtraction).
    const v9_key = hex("0200000000000000000000000000000000000000000000000000000000000000");
    const v9_msg = hex("fdffffffffffffffffffffffffffffff");
    const v9_tag = hex("faffffffffffffffffffffffffffffff");

    // #10 / #11: the long "carry propagation" pair from §A.3.
    const v10_key = hex("0100000000000000040000000000000000000000000000000000000000000000");
    const v10_msg = hex("e33594d7505e43b900000000000000003394d7505e4379cd0100000000000000") ++
        hex("0000000000000000000000000000000001000000000000000000000000000000");
    const v10_tag = hex("14000000000000005500000000000000");

    const v11_key = v10_key;
    const v11_msg = hex("e33594d7505e43b900000000000000003394d7505e4379cd010000000000000000000000000000000000000000000000");
    const v11_tag = hex("13000000000000000000000000000000");

    const vectors = [_]A3Vector{
        .{ .key = v1_key, .msg = &v1_msg, .tag = v1_tag },
        .{ .key = v2_key, .msg = v2_msg, .tag = v2_tag },
        .{ .key = v3_key, .msg = v3_msg, .tag = v3_tag },
        .{ .key = v4_key, .msg = v4_msg, .tag = v4_tag },
        .{ .key = v5_key, .msg = &v5_msg, .tag = v5_tag },
        .{ .key = v6_key, .msg = &v6_msg, .tag = v6_tag },
        .{ .key = v7_key, .msg = &v7_msg, .tag = v7_tag },
        .{ .key = v8_key, .msg = &v8_msg, .tag = v8_tag },
        .{ .key = v9_key, .msg = &v9_msg, .tag = v9_tag },
        .{ .key = v10_key, .msg = &v10_msg, .tag = v10_tag },
        .{ .key = v11_key, .msg = &v11_msg, .tag = v11_tag },
    };

    inline for (widths) |L| {
        for (vectors, 1..) |v, n| {
            var tag: [16]u8 = undefined;
            Generic(L).create(&tag, v.msg, &v.key);
            testing.expectEqualSlices(u8, &v.tag, &tag) catch |e| {
                std.debug.print("A.3 vector #{d} failed at L={d}\n", .{ n, L });
                return e;
            };
        }
    }
}

test "differential vs std over every length 0..=2048, every lane width" {
    // The partial-final-block path and the lane-boundary straddle are where
    // parallel Poly1305 breaks, so sweep EVERY length rather than sampling
    // edges: this covers 0, 1, one block, one block + 1, exactly N blocks for
    // N ∈ {1,2,4,8}, N blocks + partial, and — crucially — every length on both
    // sides of `wide_min_bytes` for every width, up to many whole lane groups.
    // The upper bound is 2048 so that even L = 8 (whose wide path only starts
    // at 384 bytes) gets a long run of multi-group inputs.
    var prng = std.Random.DefaultPrng.init(0x9E3779B9);
    const rand = prng.random();
    var msg: [2048]u8 = undefined;
    rand.bytes(&msg);
    var key: [32]u8 = undefined;
    rand.bytes(&key);

    inline for (widths) |L| {
        for (0..msg.len + 1) |len| {
            var ours: [16]u8 = undefined;
            var theirs: [16]u8 = undefined;
            Generic(L).create(&ours, msg[0..len], &key);
            StdPoly.create(&theirs, msg[0..len], &key);
            testing.expectEqualSlices(u8, &theirs, &ours) catch |e| {
                std.debug.print("length sweep mismatch at len={d}, L={d}\n", .{ len, L });
                return e;
            };
        }
    }
}

test "differential vs std with random keys (carry-chain stress)" {
    // A fixed key exercises one r; random keys probe the carry chain where the
    // deferred-carry bounds are tightest (r near 2^124, limbs near 2^26).
    var prng = std.Random.DefaultPrng.init(0xDEADC0DE);
    const rand = prng.random();
    var msg: [1400]u8 = undefined;
    inline for (widths) |L| {
        for (0..200) |_| {
            var key: [32]u8 = undefined;
            rand.bytes(&key);
            rand.bytes(&msg);
            const len = rand.uintAtMost(usize, msg.len);
            var ours: [16]u8 = undefined;
            var theirs: [16]u8 = undefined;
            Generic(L).create(&ours, msg[0..len], &key);
            StdPoly.create(&theirs, msg[0..len], &key);
            try testing.expectEqualSlices(u8, &theirs, &ours);
        }
    }
}

test "all-ones key and message (maximal limbs)" {
    // r clamps to its largest legal value and every message limb is maximal;
    // this is the worst case for the deferred-carry bound.
    const key = [_]u8{0xff} ** 32;
    var msg: [1024]u8 = undefined;
    @memset(&msg, 0xff);
    inline for (widths) |L| {
        for (0..msg.len + 1) |len| {
            var ours: [16]u8 = undefined;
            var theirs: [16]u8 = undefined;
            Generic(L).create(&ours, msg[0..len], &key);
            StdPoly.create(&theirs, msg[0..len], &key);
            try testing.expectEqualSlices(u8, &theirs, &ours);
        }
    }
}

test "streaming update splits agree with one-shot (leftover + pad)" {
    // The AEAD calls update/pad/update/final; every split point must land on
    // the same tag, including splits that leave a partial block straddling a
    // lane group.
    var prng = std.Random.DefaultPrng.init(0x5150);
    const rand = prng.random();
    var msg: [1200]u8 = undefined;
    rand.bytes(&msg);
    var key: [32]u8 = undefined;
    rand.bytes(&key);

    inline for (widths) |L| {
        var one_shot: [16]u8 = undefined;
        Generic(L).create(&one_shot, &msg, &key);
        for (0..msg.len + 1) |split| {
            var st = Generic(L).init(&key);
            st.update(msg[0..split]);
            st.update(msg[split..]);
            var tag: [16]u8 = undefined;
            st.final(&tag);
            testing.expectEqualSlices(u8, &one_shot, &tag) catch |e| {
                std.debug.print("split mismatch at split={d}, L={d}\n", .{ split, L });
                return e;
            };
        }
    }
}

test "pad() after a WIDE run, every lane width" {
    // The test below only ever pads an accumulator the *serial* engine last
    // touched (its `a` is at most 70 bytes). But the AEAD's own shape is
    // `update(ad) / pad / update(ct) / pad / update(lens) / final`, and with AD
    // longer than `wide_min_bytes` the pad lands directly on an accumulator the
    // vector engine just wrote back — a seam nothing else exercises.
    var prng = std.Random.DefaultPrng.init(0xBEEF_5A5A);
    const rand = prng.random();
    var key: [32]u8 = undefined;
    rand.bytes(&key);
    var a: [1500]u8 = undefined;
    var b: [1500]u8 = undefined;
    rand.bytes(&a);
    rand.bytes(&b);

    const lens = [_]usize{ 176, 177, 191, 192, 193, 255, 256, 383, 384, 385, 512, 1024, 1500 };
    inline for (widths) |L| {
        for (lens) |n| {
            for (lens) |m| {
                var ours = Generic(L).init(&key);
                ours.update(a[0..n]);
                ours.pad();
                ours.update(b[0..m]);
                ours.pad();
                ours.update(a[0..17]);
                var ot: [16]u8 = undefined;
                ours.final(&ot);

                var theirs = StdPoly.init(&key);
                theirs.update(a[0..n]);
                theirs.pad();
                theirs.update(b[0..m]);
                theirs.pad();
                theirs.update(a[0..17]);
                var tt: [16]u8 = undefined;
                theirs.final(&tt);

                testing.expectEqualSlices(u8, &tt, &ot) catch |e| {
                    std.debug.print("pad-after-wide mismatch L={d} n={d} m={d}\n", .{ L, n, m });
                    return e;
                };
            }
        }
    }
}

test "pad() matches std's pad() across leftover states" {
    var prng = std.Random.DefaultPrng.init(0xFEED_BEEF);
    const rand = prng.random();
    // `a` sweeps every leftover state; `b` is long enough that the input after
    // the pad still reaches the wide path at every width.
    var a: [70]u8 = undefined;
    var b: [900]u8 = undefined;
    rand.bytes(&a);
    rand.bytes(&b);
    var key: [32]u8 = undefined;
    rand.bytes(&key);

    inline for (widths) |L| {
        for (0..a.len + 1) |n| {
            var ours = Generic(L).init(&key);
            ours.update(a[0..n]);
            ours.pad();
            ours.update(&b);
            var ot: [16]u8 = undefined;
            ours.final(&ot);

            var theirs = StdPoly.init(&key);
            theirs.update(a[0..n]);
            theirs.pad();
            theirs.update(&b);
            var tt: [16]u8 = undefined;
            theirs.final(&tt);

            try testing.expectEqualSlices(u8, &tt, &ot);
        }
    }
}

test "selected lane count matches the target's features" {
    // Documents (and pins) the comptime selection: no runtime dispatch.
    if (builtin.cpu.has(.x86, .avx512f)) {
        try testing.expectEqual(@as(usize, 8), lanes);
    } else if (builtin.cpu.has(.x86, .avx2)) {
        try testing.expectEqual(@as(usize, 4), lanes);
    } else {
        try testing.expectEqual(@as(usize, 1), lanes);
        try testing.expect(Poly1305 == StdPoly);
    }
    try testing.expectEqual(simd_active, lanes > 1);
}

test "fuzz: MAC agrees with std on arbitrary key/message" {
    try testing.fuzz({}, fuzzAgainstStd, .{});
}

fn fuzzAgainstStd(_: void, smith: *std.testing.Smith) !void {
    var key: [32]u8 = undefined;
    smith.bytes(&key);
    var msg: [640]u8 = undefined;
    smith.bytes(&msg);
    const len: usize = smith.valueRangeAtMost(u16, 0, msg.len);

    var ours: [16]u8 = undefined;
    var theirs: [16]u8 = undefined;
    Poly1305.create(&ours, msg[0..len], &key);
    StdPoly.create(&theirs, msg[0..len], &key);
    try testing.expectEqualSlices(u8, &theirs, &ours);
}
