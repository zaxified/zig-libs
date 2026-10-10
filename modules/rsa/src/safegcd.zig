// SPDX-License-Identifier: MIT

//! safegcd — constant-time `x⁻¹ mod m` for an odd RUNTIME modulus of up to
//! `max_bits`, by Bernstein–Yang divsteps (eprint 2019/266) batched 59 at a
//! time in the libsecp256k1 `modinv64` shape: each batch runs on the low 64
//! bits of `f`/`g` only, collapses into a 2×2 transition matrix scaled by
//! 2^62, and that matrix is applied ONCE to the multi-limb signed-62 vectors
//! `(f, g)` and `(d, e)`. It is `p256/src/modinv.zig` with the limb count
//! made a runtime (public) value and the modulus a runtime value.
//!
//! ## Why this exists (2026-10-10)
//!
//! The F2 base blinding of every blinded private op needs `r⁻¹ mod n` for a
//! fresh random `r`. That inverse was a `std.math.big` extended Euclid
//! (`invModN`): variable-time, and measured as the dominant blinding cost —
//! the blinded rows of `bench-rsa` sat ~0.45 ms (2048) to ~1.3 ms (4096)
//! above the unblinded ones, 1.8–2.3× OpenSSL against ~1.5× unblinded. This
//! inverse costs a few tens of µs and is constant-time in `x` besides.
//!
//! ## Shape
//!
//! Values are `Signed62` vectors of `K` signed 64-bit limbs holding 62 bits
//! each (`Σ v[i]·2^(62·i)`; intermediate limbs may go negative, the top limb
//! carries the sign). Only the first `k` limbs are live, `k` derived from the
//! PUBLIC modulus bit length — `f, g` never grow past the modulus and `d, e`
//! stay in `(−2m, m)`, so the limbs above `k` are never touched.
//!
//! Trip count: `⌊(49·b + 57)/17⌋` divsteps for a `b`-bit modulus (Bernstein–
//! Yang Theorem 11.2's bound for the original divstep, `b ≥ 46`), rounded up
//! to whole batches. The half-delta variant used here converges at least as
//! fast in practice (libsecp256k1 proves 590 for 256 bits where this formula
//! gives 741), and the result is NOT trusted on the bound alone: `invert`
//! returns `false` unless `g = 0` and `f = ±1` at the end, and the caller
//! (`makeBlinding`) additionally checks `x·x⁻¹ ≡ 1` and redraws otherwise.
//!
//! ## Constant-time contract
//!
//! Fixed trip counts derived from the public bit length only; every data-
//! dependent decision (`zeta < 0`, `g` odd, the signs of `d`/`e`/`f`, the
//! two conditional modulus adds in `normalize`) is a masked select whose mask
//! is laundered through `blackBox` (the montint `b199192` leak class);
//! multiplies are `i64×i64→i128`. The final `g = 0 ∧ f = ±1` verdict is an
//! OR-accumulated compare read once — it reveals only whether `x` was a unit.

const std = @import("std");

const M62: u64 = (1 << 62) - 1;
const M62i: i64 = @intCast(M62);

inline fn blackBox(x: u64) u64 {
    if (@inComptime()) return x;
    return asm volatile (""
        : [ret] "=r" (-> u64),
        : [x] "0" (x),
    );
}

inline fn blackBoxI(x: i64) i64 {
    return @bitCast(blackBox(@bitCast(x)));
}

inline fn mul128(a: i64, b: i64) i128 {
    return @as(i128, a) * @as(i128, b);
}

inline fn low62(c: i128) i64 {
    return @as(i64, @truncate(c)) & M62i;
}

/// An inverter for odd moduli of up to `max_bits` bits.
pub fn Inverter(comptime max_bits: usize) type {
    return struct {
        /// 64-bit limbs of an input/output value.
        pub const N: usize = (max_bits + 63) / 64;
        /// Signed-62 limbs: enough for `2·m` plus a sign.
        const K: usize = (max_bits + 2 + 61) / 62 + 1;
        const S62 = [K]i64;

        const Trans = struct { u: i64, v: i64, q: i64, r: i64 };

        fn fromLimbs(a: *const [N]u64, k: usize) S62 {
            var out = [_]i64{0} ** K;
            for (0..k) |i| {
                const bit = 62 * i;
                const w = bit / 64;
                const sh: u6 = @intCast(bit % 64);
                var v: u64 = if (w < N) a[w] >> sh else 0;
                if (sh > 2 and w + 1 < N) v |= a[w + 1] << @intCast(64 - @as(u7, sh));
                out[i] = @intCast(v & M62);
            }
            return out;
        }

        /// Requires a normalized value: limbs in `[0, 2^62)`, value `< 2^(64·N)`.
        fn toLimbs(s: *const S62, k: usize) [N]u64 {
            var out = [_]u64{0} ** N;
            for (0..k) |i| {
                const v: u64 = @bitCast(s[i]);
                const bit = 62 * i;
                const w = bit / 64;
                const sh: u6 = @intCast(bit % 64);
                if (w < N) out[w] |= v << sh;
                if (sh > 2 and w + 1 < N) out[w + 1] |= v >> @intCast(64 - @as(u7, sh));
            }
            return out;
        }

        /// 59 divsteps on the low words (the `p256/modinv.zig` body).
        fn divsteps59(zeta_in: i64, f0: u64, g0: u64) struct { zeta: i64, t: Trans } {
            var u: u64 = 8;
            var v: u64 = 0;
            var q: u64 = 0;
            var r: u64 = 8;
            var f = f0;
            var g = g0;
            var zeta = zeta_in;
            var i: usize = 3;
            while (i < 62) : (i += 1) {
                var mask1: u64 = blackBox(@bitCast(zeta >> 63));
                const mask2: u64 = blackBox(0 -% (g & 1));
                const x = (f ^ mask1) -% mask1;
                const y = (u ^ mask1) -% mask1;
                const z = (v ^ mask1) -% mask1;
                g +%= x & mask2;
                q +%= y & mask2;
                r +%= z & mask2;
                mask1 &= mask2;
                zeta = (zeta ^ @as(i64, @bitCast(mask1))) -% 1;
                f +%= g & mask1;
                u +%= q & mask1;
                v +%= r & mask1;
                g >>= 1;
                u <<= 1;
                v <<= 1;
            }
            return .{ .zeta = zeta, .t = .{ .u = @bitCast(u), .v = @bitCast(v), .q = @bitCast(q), .r = @bitCast(r) } };
        }

        fn updateDE(d: *S62, e: *S62, t: Trans, m: *const S62, minv62: u64, k: usize) void {
            const sd: i64 = blackBoxI(d[k - 1] >> 63);
            const se: i64 = blackBoxI(e[k - 1] >> 63);
            var md: i64 = (t.u & sd) +% (t.v & se);
            var me: i64 = (t.q & sd) +% (t.r & se);
            var cd: i128 = mul128(t.u, d[0]) + mul128(t.v, e[0]);
            var ce: i128 = mul128(t.q, d[0]) + mul128(t.r, e[0]);
            md -%= @intCast((minv62 *% @as(u64, @truncate(@as(u128, @bitCast(cd)))) +% @as(u64, @bitCast(md))) & M62);
            me -%= @intCast((minv62 *% @as(u64, @truncate(@as(u128, @bitCast(ce)))) +% @as(u64, @bitCast(me))) & M62);
            cd += mul128(m[0], md);
            ce += mul128(m[0], me);
            std.debug.assert(low62(cd) == 0);
            std.debug.assert(low62(ce) == 0);
            cd >>= 62;
            ce >>= 62;
            for (1..k) |i| {
                cd += mul128(t.u, d[i]) + mul128(t.v, e[i]) + mul128(m[i], md);
                ce += mul128(t.q, d[i]) + mul128(t.r, e[i]) + mul128(m[i], me);
                d[i - 1] = low62(cd);
                e[i - 1] = low62(ce);
                cd >>= 62;
                ce >>= 62;
            }
            d[k - 1] = @intCast(cd);
            e[k - 1] = @intCast(ce);
        }

        fn updateFG(f: *S62, g: *S62, t: Trans, k: usize) void {
            var cf: i128 = mul128(t.u, f[0]) + mul128(t.v, g[0]);
            var cg: i128 = mul128(t.q, f[0]) + mul128(t.r, g[0]);
            std.debug.assert(low62(cf) == 0);
            std.debug.assert(low62(cg) == 0);
            cf >>= 62;
            cg >>= 62;
            for (1..k) |i| {
                cf += mul128(t.u, f[i]) + mul128(t.v, g[i]);
                cg += mul128(t.q, f[i]) + mul128(t.r, g[i]);
                f[i - 1] = low62(cf);
                g[i - 1] = low62(cg);
                cf >>= 62;
                cg >>= 62;
            }
            f[k - 1] = @intCast(cf);
            g[k - 1] = @intCast(cg);
        }

        fn carryNorm(v: *S62, k: usize) void {
            for (0..k - 1) |i| {
                v[i + 1] +%= v[i] >> 62;
                v[i] &= M62i;
            }
        }

        /// `(−2m, m)` → `[0, m)`, negating first iff `sign < 0`.
        fn normalize(r: *S62, sign: i64, m: *const S62, k: usize) void {
            var cond_add: i64 = blackBoxI(r[k - 1] >> 63);
            for (0..k) |i| r[i] +%= m[i] & cond_add;
            const cond_negate: i64 = blackBoxI(sign >> 63);
            for (0..k) |i| r[i] = (r[i] ^ cond_negate) -% cond_negate;
            carryNorm(r, k);
            cond_add = blackBoxI(r[k - 1] >> 63);
            for (0..k) |i| r[i] +%= m[i] & cond_add;
            carryNorm(r, k);
        }

        /// `out = x⁻¹ mod m` for an odd modulus `m` of exactly `nbits` bits
        /// (public) and `0 ≤ x < m`. Returns `false` (and `out` is garbage)
        /// iff `x` is not a unit mod `m` — or if the divstep bound ever fell
        /// short, which then reads as "not a unit", never as a wrong inverse.
        /// Constant-time in `x` and in `m`'s value.
        pub fn invert(x: *const [N]u64, m_limbs: *const [N]u64, nbits: usize, out: *[N]u64) bool {
            std.debug.assert(nbits >= 3 and nbits <= max_bits);
            std.debug.assert(m_limbs[0] & 1 == 1);
            const k: usize = @min(K, (nbits + 2 + 61) / 62 + 1);
            // m⁻¹ mod 2^64 by Newton (m odd ⇒ m⁻¹ ≡ m mod 8; 3→6→…→96 bits).
            var minv: u64 = m_limbs[0];
            for (0..5) |_| minv *%= 2 -% m_limbs[0] *% minv;
            const m = fromLimbs(m_limbs, k);
            var d = [_]i64{0} ** K;
            var e = [_]i64{0} ** K;
            e[0] = 1;
            var f = m;
            var g = fromLimbs(x, k);
            var zeta: i64 = -1;
            const b = @max(nbits, 46);
            const steps = (49 * b + 57) / 17;
            const batches = (steps + 58) / 59;
            for (0..batches) |_| {
                const st = divsteps59(zeta, @bitCast(f[0]), @bitCast(g[0]));
                zeta = st.zeta;
                updateDE(&d, &e, st.t, &m, minv & M62, k);
                updateFG(&f, &g, st.t, k);
            }
            // Verdict: g = 0 and f = ±1 (f's limbs are normalized by updateFG
            // except the top, which holds the sign: f = 1 ⟺ [1,0,…,0],
            // f = −1 ⟺ [M62, …, M62, −1]).
            var acc: u64 = 0;
            for (0..k) |i| acc |= @bitCast(g[i]);
            const fs: i64 = f[k - 1] >> 63; // 0 or −1
            var fn_ = f;
            for (0..k) |i| fn_[i] = (fn_[i] ^ fs) -% fs; // |f| if f's sign limb is the only sign
            carryNorm(&fn_, k);
            acc |= @as(u64, @bitCast(fn_[0])) ^ 1;
            for (1..k) |i| acc |= @bitCast(fn_[i]);
            normalize(&d, f[k - 1], &m, k);
            out.* = toLimbs(&d, k);
            return acc == 0;
        }
    };
}

// ── tests ───────────────────────────────────────────────────────────────────

const Managed = std.math.big.int.Managed;

fn bigFromLimbs(gpa: std.mem.Allocator, l: []const u64) !Managed {
    var r = try Managed.initCapacity(gpa, l.len + 1);
    @memcpy(r.limbs[0..l.len], l);
    r.setMetadata(true, l.len);
    r.normalize(l.len);
    return r;
}

fn checkOne(comptime I: type, gpa: std.mem.Allocator, x: *const [I.N]u64, m: *const [I.N]u64, nbits: usize) !void {
    var out: [I.N]u64 = undefined;
    const ok = I.invert(x, m, nbits, &out);
    var xb = try bigFromLimbs(gpa, x);
    defer xb.deinit();
    var mb = try bigFromLimbs(gpa, m);
    defer mb.deinit();
    // gcd by plain Euclid on divFloor (std's Lehmer `gcd` trips an index
    // bound on some multi-limb inputs in 0.16.0, which this test hit).
    var ga = try xb.clone();
    defer ga.deinit();
    var gb = try mb.clone();
    defer gb.deinit();
    var gq = try Managed.init(gpa);
    defer gq.deinit();
    var gr = try Managed.init(gpa);
    defer gr.deinit();
    while (!ga.eqlZero()) {
        try gq.divFloor(&gr, &gb, &ga);
        try gb.copy(ga.toConst());
        try ga.copy(gr.toConst());
    }
    const unit = gb.toConst().orderAgainstScalar(1) == .eq;
    try std.testing.expectEqual(unit, ok);
    if (!ok) return;
    var ob = try bigFromLimbs(gpa, &out);
    defer ob.deinit();
    try std.testing.expect(ob.toConst().order(mb.toConst()) == .lt);
    var p = try Managed.init(gpa);
    defer p.deinit();
    try p.mul(&xb, &ob);
    var q = try Managed.init(gpa);
    defer q.deinit();
    var r = try Managed.init(gpa);
    defer r.deinit();
    try q.divFloor(&r, &p, &mb);
    try std.testing.expect(r.toConst().orderAgainstScalar(1) == .eq);
}

test "safegcd Inverter: x·x⁻¹ ≡ 1 against big-int, random odd moduli 64..4096 bits, edges, non-units" {
    const gpa = std.testing.allocator;
    const I = Inverter(4096);
    var prng = std.Random.DefaultPrng.init(0x5AFE_6CD_45A);
    const rand = prng.random();
    const sizes = [_]usize{ 64, 65, 127, 512, 1000, 1024, 1536, 2048, 3072, 4095, 4096 };
    for (sizes) |nbits| {
        for (0..6) |t| {
            var m = [_]u64{0} ** I.N;
            const nl = (nbits + 63) / 64;
            for (0..nl) |i| m[i] = rand.int(u64);
            const topbits: u6 = @intCast(nbits - 64 * (nl - 1) - 1);
            m[nl - 1] &= (@as(u64, 2) << topbits) -% 1;
            m[nl - 1] |= @as(u64, 1) << topbits; // exactly nbits bits
            m[0] |= 1;
            var x = [_]u64{0} ** I.N;
            switch (t) {
                0 => x[0] = 1,
                1 => x[0] = 2,
                2 => { // m − 1
                    x = m;
                    x[0] -= 1;
                },
                3 => {}, // 0: not a unit
                else => {
                    for (0..nl) |i| x[i] = rand.int(u64);
                    x[nl - 1] %= m[nl - 1];
                },
            }
            try checkOne(I, gpa, &x, &m, nbits);
        }
    }
    // A non-unit that is not 0: m = 3·5·(odd), x = 15.
    var m = [_]u64{0} ** I.N;
    m[0] = 15 * 0x1234567;
    var x = [_]u64{0} ** I.N;
    x[0] = 15;
    try checkOne(I, gpa, &x, &m, 64 - @clz(m[0]));
}
