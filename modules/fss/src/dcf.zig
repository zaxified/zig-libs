// SPDX-License-Identifier: MIT

//! dcf — 2-party Distributed Comparison Function (DCF): additive shares of
//! `f^<_{α,β}(x) = β if x < α else 0` over the domain `{0,1}^n`, output group
//! `Z_{2^{8L}}` — Boyle, Chandran, Gilboa, Gupta, Ishai, Kumar, Rathee,
//! "Function Secret Sharing for Mixed-Mode and Fixed-Point Secure Computation"
//! (Eurocrypt 2021), Fig. 1.
//!
//! It is the DPF tree (`dpf.zig`, BGI16) with one extra group element per
//! level: next to each child seed the PRG yields a value `v`, and every level
//! carries a value correction word `V_cw`. Walking toward `x`, a party sums
//! `(-1)^b·(Convert(v) + t·V_cw)` over the levels and the leaf; the
//! corrections make the two parties' sums differ by exactly `β` on every node
//! where the path to `x` leaves the path to `α` to the LEFT (`x_i = 0 < α_i =
//! 1`, so `x < α`), and agree everywhere else.
//!
//! The PRG is the module's (`prg.zig`): `expand(s)` gives the child seeds and
//! control bits, and the values come from a second expansion of the seed with
//! its last byte flipped (`value_tweak`), each child converted into the group —
//! an input domain disjoint from `expand(s)`'s and from the leaf `convert`.
//!
//! An interval `[a, b)` is `Dcf(b) − Dcf(a)`: two key pairs, the shares
//! subtracted (the paper's §3.2 construction).
//!
//! Constant time: `α`, `β`, the seeds and every control bit are secret; each
//! use is a masked select, never a branch or an index. `x` is public to the
//! evaluator, but the walk still selects by mask, as `dpf.eval` does.

const std = @import("std");
const prg_mod = @import("prg.zig");
const group = @import("group.zig");
const burn = @import("burn.zig");
const dpf = @import("dpf.zig");

const Seed = prg_mod.Seed;
const seed_len = prg_mod.seed_len;
const secretMask = dpf.secretMask;

/// Byte XORed into the last seed byte to derive the value expansion.
const value_tweak: u8 = 0x5a;

inline fn selectSeed(cond: u1, a: Seed, b: Seed) Seed {
    const m: u8 = secretMask(u8, cond);
    var out: Seed = undefined;
    for (&out, a, b) |*o, x, y| o.* = (x & m) | (y & ~m);
    return out;
}

inline fn selectBit(cond: u1, a: u1, b: u1) u1 {
    return (a & cond) | (b & ~cond);
}

inline fn xorMasked(dst: *Seed, src: Seed, cond: u1) void {
    const m: u8 = secretMask(u8, cond);
    for (dst, src) |*d, q| d.* ^= q & m;
}

/// A DCF over `{0,1}^n_bits`, output group `Z_{2^{8·out_bytes}}`, with the
/// module's default PRG.
pub fn Dcf(comptime n_bits: usize, comptime out_bytes: usize) type {
    return DcfWith(prg_mod.default, n_bits, out_bytes);
}

/// `Dcf` with an explicitly chosen PRG (`prg.Aes128Mmo` or `prg.Sha256Prg`).
pub fn DcfWith(comptime P: type, comptime n_bits: usize, comptime out_bytes: usize) type {
    if (n_bits < 1 or n_bits > 31) @compileError("Dcf: n_bits must be in 1..31");
    if (out_bytes < 1 or out_bytes > 32) @compileError("Dcf: out_bytes must be in 1..32");
    return struct {
        pub const n = n_bits;
        pub const Prg = P;
        pub const G = group.Z2k(out_bytes);
        pub const Elem = G.Int;
        pub const Index = @Int(.unsigned, n_bits);
        pub const domain_size: usize = @as(usize, 1) << @intCast(n_bits);

        /// One level's correction word: the seed CW, the value CW and the two
        /// control-bit CWs.
        pub const Cw = struct {
            s_cw: Seed,
            v_cw: Elem,
            t_cw_l: u1,
            t_cw_r: u1,
        };

        /// A party's DCF key. `cw`/`cw_final` are the same in both keys; only
        /// `seed` differs.
        pub const Key = struct {
            seed: Seed,
            cw: [n_bits]Cw,
            cw_final: Elem,

            /// `seed(16) || per level: s_cw(16) || v_cw(L, LE) || t_cw_l(1) ||
            /// t_cw_r(1) || cw_final(L, LE)`.
            pub const serialized_len = seed_len + n_bits * (seed_len + out_bytes + 2) + out_bytes;

            pub fn toBytes(self: *const Key, buf: *[serialized_len]u8) void {
                return burn.run(burn.codec_burn, void, toBytesBody, .{ self, buf });
            }

            fn toBytesBody(self: *const Key, buf: *[serialized_len]u8) void {
                @memcpy(buf[0..seed_len], &self.seed);
                var off: usize = seed_len;
                for (self.cw) |c| {
                    @memcpy(buf[off..][0..seed_len], &c.s_cw);
                    off += seed_len;
                    std.mem.writeInt(Elem, buf[off..][0..out_bytes], c.v_cw, .little);
                    off += out_bytes;
                    buf[off] = c.t_cw_l;
                    buf[off + 1] = c.t_cw_r;
                    off += 2;
                }
                std.mem.writeInt(Elem, buf[off..][0..out_bytes], self.cw_final, .little);
            }

            /// Decode `toBytes` output into `out` (a control-bit byte keeps
            /// only its low bit, as `Dpf.Key.fromBytes` does).
            pub fn fromBytes(out: *Key, buf: *const [serialized_len]u8) void {
                return burn.run(burn.codec_burn, void, fromBytesBody, .{ out, buf });
            }

            fn fromBytesBody(out: *Key, buf: *const [serialized_len]u8) void {
                out.seed = buf[0..seed_len].*;
                var off: usize = seed_len;
                for (&out.cw) |*c| {
                    c.s_cw = buf[off..][0..seed_len].*;
                    off += seed_len;
                    c.v_cw = std.mem.readInt(Elem, buf[off..][0..out_bytes], .little);
                    off += out_bytes;
                    c.t_cw_l = @truncate(buf[off]);
                    c.t_cw_r = @truncate(buf[off + 1]);
                    off += 2;
                }
                out.cw_final = std.mem.readInt(Elem, buf[off..][0..out_bytes], .little);
            }
        };

        fn bitOf(a: Index, i: usize) u1 {
            const shift: std.math.Log2Int(Index) = @intCast(n_bits - i);
            return @truncate(a >> shift);
        }

        /// The two children's values `v^L`, `v^R` of seed `s`.
        fn values(p: P, s: Seed) [2]Elem {
            var tw = s;
            tw[seed_len - 1] ^= value_tweak;
            const e = p.expand(tw);
            return .{ p.convert(out_bytes, e.s_l), p.convert(out_bytes, e.s_r) };
        }

        /// `(-1)^t · x` without a branch on `t`.
        inline fn signed(t: u1, x: Elem) Elem {
            const m = secretMask(Elem, t);
            return (G.neg(x) & m) | (x & ~m);
        }

        /// **Gen** — the key pair for `f^<_{α,β}` from two caller-supplied
        /// root seeds (cryptographically random, secret, independent — the
        /// construction's only randomness, as for `Dpf.genWithSeeds`). Keys
        /// are written through `out`.
        pub fn genWithSeeds(alpha: *const Index, beta: *const Elem, s0: *const Seed, s1: *const Seed, out: *[2]Key) void {
            return burn.run(burn.gen_burn, void, genBody, .{ alpha, beta, s0, s1, out });
        }

        fn genBody(alpha_p: *const Index, beta_p: *const Elem, s0p: *const Seed, s1p: *const Seed, out: *[2]Key) void {
            const alpha = alpha_p.*;
            const beta = beta_p.*;
            const p = P.init();
            var cur0 = s0p.*;
            var cur1 = s1p.*;
            var t0: u1 = 0;
            var t1: u1 = 1;
            var v_alpha: Elem = 0;
            var cw: [n_bits]Cw = undefined;

            var i: usize = 1;
            while (i <= n_bits) : (i += 1) {
                const e0 = p.expand(cur0);
                const e1 = p.expand(cur1);
                const v0 = values(p, cur0);
                const v1 = values(p, cur1);
                const a_i = bitOf(alpha, i);
                // Keep = the child toward α, Lose = its sibling (α_i = 0: Keep L).
                const s_lose0 = selectSeed(a_i, e0.s_l, e0.s_r);
                const s_lose1 = selectSeed(a_i, e1.s_l, e1.s_r);
                var s_cw: Seed = undefined;
                for (&s_cw, s_lose0, s_lose1) |*d, x, y| d.* = x ^ y;

                const am = secretMask(Elem, a_i);
                const v_lose0 = (v0[0] & am) | (v0[1] & ~am);
                const v_lose1 = (v1[0] & am) | (v1[1] & ~am);
                const v_keep0 = (v0[1] & am) | (v0[0] & ~am);
                const v_keep1 = (v1[1] & am) | (v1[0] & ~am);
                // V_cw = (-1)^{t1}·(v1_Lose − v0_Lose − V_α), plus (-1)^{t1}·β
                // when Lose = L (α_i = 1: every x going left here is < α).
                var v_cw = signed(t1, G.sub(G.sub(v_lose1, v_lose0), v_alpha));
                v_cw = G.add(v_cw, signed(t1, beta) & am);
                // V_α = V_α − v1_Keep + v0_Keep + (-1)^{t1}·V_cw
                v_alpha = G.add(G.add(G.sub(v_alpha, v_keep1), v_keep0), signed(t1, v_cw));

                const t_cw_l: u1 = e0.t_l ^ e1.t_l ^ a_i ^ 1;
                const t_cw_r: u1 = e0.t_r ^ e1.t_r ^ a_i;
                cw[i - 1] = .{ .s_cw = s_cw, .v_cw = v_cw, .t_cw_l = t_cw_l, .t_cw_r = t_cw_r };

                const s_keep0 = selectSeed(a_i, e0.s_r, e0.s_l);
                const s_keep1 = selectSeed(a_i, e1.s_r, e1.s_l);
                const t_keep0: u1 = selectBit(a_i, e0.t_r, e0.t_l);
                const t_keep1: u1 = selectBit(a_i, e1.t_r, e1.t_l);
                const t_cw_keep: u1 = selectBit(a_i, t_cw_r, t_cw_l);
                cur0 = s_keep0;
                xorMasked(&cur0, s_cw, t0);
                cur1 = s_keep1;
                xorMasked(&cur1, s_cw, t1);
                const nt0 = t_keep0 ^ (t0 & t_cw_keep);
                const nt1 = t_keep1 ^ (t1 & t_cw_keep);
                t0 = nt0;
                t1 = nt1;
            }
            // CW^{n+1} = (-1)^{t1}·(Convert(s1) − Convert(s0) − V_α)
            const c0 = p.convert(out_bytes, cur0);
            const c1 = p.convert(out_bytes, cur1);
            const cw_final = signed(t1, G.sub(G.sub(c1, c0), v_alpha));
            out[0] = .{ .seed = s0p.*, .cw = cw, .cw_final = cw_final };
            out[1] = .{ .seed = s1p.*, .cw = cw, .cw_final = cw_final };
        }

        /// **Eval** — party `b`'s additive share of `f^<_{α,β}(x)`:
        /// `eval(0, k0, x) + eval(1, k1, x) = β·[x < α]` in `Z_{2^{8L}}`.
        pub fn eval(b: u1, key: *const Key, x: Index) Elem {
            return burn.run(burn.eval_burn, Elem, evalBody, .{ b, key, x });
        }

        fn evalBody(b: u1, key: *const Key, x: Index) Elem {
            const p = P.init();
            var s = key.seed;
            var t: u1 = b;
            var acc: Elem = 0;
            var i: usize = 1;
            while (i <= n_bits) : (i += 1) {
                const e = p.expand(s);
                const v = values(p, s);
                const c = key.cw[i - 1];
                const x_i = bitOf(x, i);
                const xm = secretMask(Elem, x_i);
                const v_x = (v[1] & xm) | (v[0] & ~xm);
                // V += (-1)^b·(Convert(v_x) + t·V_cw)
                acc = G.add(acc, signed(b, G.add(v_x, c.v_cw & secretMask(Elem, t))));
                s = selectSeed(x_i, e.s_r, e.s_l);
                const e_t = selectBit(x_i, e.t_r, e.t_l);
                const t_cw = selectBit(x_i, c.t_cw_r, c.t_cw_l);
                const nt = e_t ^ (t & t_cw);
                xorMasked(&s, c.s_cw, t);
                t = nt;
            }
            const leaf = G.add(p.convert(out_bytes, s), key.cw_final & secretMask(Elem, t));
            return G.add(acc, signed(b, leaf));
        }

        /// Party `b` at every domain point into `out` (`out.len ==
        /// domain_size`): a loop over `eval`.
        pub fn evalAll(b: u1, key: *const Key, out: []Elem) void {
            return burn.run(burn.walk_burn, void, evalAllBody, .{ b, key, out });
        }

        fn evalAllBody(b: u1, key: *const Key, out: []Elem) void {
            std.debug.assert(out.len == domain_size);
            for (out, 0..) |*o, x| o.* = evalBody(b, key, @intCast(x));
        }
    };
}

// ── tests ────────────────────────────────────────────────────────────────

const testing = std.testing;

fn checkAll(comptime D: type, alpha: D.Index, beta: D.Elem, seed: u64) !void {
    var prng = std.Random.DefaultPrng.init(seed);
    const rnd = prng.random();
    var s0: Seed = undefined;
    var s1: Seed = undefined;
    rnd.bytes(&s0);
    rnd.bytes(&s1);
    var keys: [2]D.Key = undefined;
    D.genWithSeeds(&alpha, &beta, &s0, &s1, &keys);
    var y0: [D.domain_size]D.Elem = undefined;
    var y1: [D.domain_size]D.Elem = undefined;
    D.evalAll(0, &keys[0], &y0);
    D.evalAll(1, &keys[1], &y1);
    for (0..D.domain_size) |x| {
        const want: D.Elem = if (x < alpha) beta else 0;
        try testing.expectEqual(want, D.G.add(y0[x], y1[x]));
    }
}

test "dcf: every point of every alpha reconstructs beta·[x < alpha], both PRGs" {
    inline for (.{ prg_mod.Aes128Mmo, prg_mod.Sha256Prg }) |P| {
        const D = DcfWith(P, 4, 4);
        for (0..D.domain_size) |a| try checkAll(D, @intCast(a), 0xdead_beef, a);
        // A one-bit domain, and a wide group.
        try checkAll(DcfWith(P, 1, 1), 1, 200, 1);
        try checkAll(DcfWith(P, 1, 1), 0, 200, 2);
        try checkAll(DcfWith(P, 6, 32), 37, std.math.maxInt(u256) - 5, 3);
    }
}

test "dcf: random alpha, beta over a 10-bit domain; beta = 0 shares zero everywhere" {
    const D = Dcf(10, 8);
    var prng = std.Random.DefaultPrng.init(0xdcf);
    const rnd = prng.random();
    for (0..6) |k| try checkAll(D, rnd.int(D.Index), rnd.int(D.Elem), k);
    try checkAll(D, 513, 0, 99);
    try checkAll(D, std.math.maxInt(D.Index), 1, 100);
}

test "dcf: an interval [a, b) is the difference of two DCFs" {
    const D = Dcf(6, 4);
    var s: [4]Seed = undefined;
    for (&s, 0..) |*x, i| x.* = @splat(@intCast(i * 17 + 1));
    const beta: D.Elem = 7;
    const a: D.Index = 13;
    const b: D.Index = 41;
    var ka: [2]D.Key = undefined;
    var kb: [2]D.Key = undefined;
    D.genWithSeeds(&a, &beta, &s[0], &s[1], &ka);
    D.genWithSeeds(&b, &beta, &s[2], &s[3], &kb);
    for (0..D.domain_size) |xi| {
        const x: D.Index = @intCast(xi);
        const sh0 = D.G.sub(D.eval(0, &kb[0], x), D.eval(0, &ka[0], x));
        const sh1 = D.G.sub(D.eval(1, &kb[1], x), D.eval(1, &ka[1], x));
        try testing.expectEqual(@as(D.Elem, if (x >= a and x < b) beta else 0), D.G.add(sh0, sh1));
    }
}

test "dcf: a single key's shares look unrelated to alpha (no share is beta·[x<alpha] alone)" {
    const D = Dcf(5, 4);
    var s0: Seed = @splat(3);
    var s1: Seed = @splat(9);
    const alpha: D.Index = 20;
    const beta: D.Elem = 1;
    var keys: [2]D.Key = undefined;
    D.genWithSeeds(&alpha, &beta, &s0, &s1, &keys);
    var y0: [D.domain_size]D.Elem = undefined;
    D.evalAll(0, &keys[0], &y0);
    var small: usize = 0;
    for (y0) |v| small += @intFromBool(v <= 1);
    try testing.expect(small < 4); // pseudorandom 32-bit shares, not 0/1
    _ = &s0;
    _ = &s1;
}

test "dcf: key codec round-trips and the decoded key evaluates the same" {
    const D = Dcf(7, 3);
    var s0: Seed = @splat(0x11);
    var s1: Seed = @splat(0x22);
    const alpha: D.Index = 77;
    const beta: D.Elem = 0x123456;
    var keys: [2]D.Key = undefined;
    D.genWithSeeds(&alpha, &beta, &s0, &s1, &keys);
    var buf: [D.Key.serialized_len]u8 = undefined;
    keys[1].toBytes(&buf);
    var back: D.Key = undefined;
    D.Key.fromBytes(&back, &buf);
    try testing.expectEqualDeep(keys[1], back);
    try testing.expectEqual(@as(usize, 16 + 7 * (16 + 3 + 2) + 3), D.Key.serialized_len);
    for (0..D.domain_size) |x| try testing.expectEqual(D.eval(1, &keys[1], @intCast(x)), D.eval(1, &back, @intCast(x)));
    _ = &s0;
    _ = &s1;
}
