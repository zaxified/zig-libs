// SPDX-License-Identifier: MIT

//! idpf — incremental (hierarchical) DPF: one key pair shares, for every
//! level `ℓ ∈ 1..n`, the point function on `ℓ`-bit prefixes
//! `f_ℓ(x) = β_ℓ if x = α[0..ℓ) else 0` (Boneh, Boyle, Corrigan-Gibbs, Gilboa,
//! Ishai, "Lightweight Techniques for Private Heavy Hitters", IEEE S&P 2021,
//! §4 — the IDPF under Poplar and the VDAF `Poplar1`).
//!
//! It is the BGI16 DPF tree of `dpf.zig` with an output correction word at
//! EVERY level instead of only at the leaf: the node of prefix `p` at depth
//! `ℓ` converts its seed into the group and adds `t·ocw[ℓ]`, exactly the DPF
//! leaf rule. Off the α path the two parties' `(seed, t)` agree, so their
//! shares cancel; on it `t0 ⊕ t1 = 1` and `ocw[ℓ]` steers the difference to
//! `β_ℓ`. The node value uses the PRG's `convert`, an input domain disjoint
//! from the `expand` that continues the walk. Level `n` is the plain DPF: the
//! same seeds, correction words and leaf as `DpfWith(P, n, L)`.
//!
//! Constant time: as `dpf.zig` — `α`, every `β_ℓ`, the seeds and the control
//! bits only drive masked selects.

const std = @import("std");
const prg_mod = @import("prg.zig");
const group = @import("group.zig");
const burn = @import("burn.zig");
const dpf = @import("dpf.zig");

const Seed = prg_mod.Seed;
const seed_len = prg_mod.seed_len;
const secretMask = dpf.secretMask;

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

/// An incremental DPF over `{0,1}^n_bits`, output group `Z_{2^{8·out_bytes}}`
/// at every level, with the module's default PRG.
pub fn Idpf(comptime n_bits: usize, comptime out_bytes: usize) type {
    return IdpfWith(prg_mod.default, n_bits, out_bytes);
}

pub fn IdpfWith(comptime P: type, comptime n_bits: usize, comptime out_bytes: usize) type {
    if (n_bits < 1 or n_bits > 31) @compileError("Idpf: n_bits must be in 1..31");
    if (out_bytes < 1 or out_bytes > 32) @compileError("Idpf: out_bytes must be in 1..32");
    return struct {
        pub const n = n_bits;
        pub const Prg = P;
        pub const G = group.Z2k(out_bytes);
        pub const Elem = G.Int;
        pub const Index = @Int(.unsigned, n_bits);

        pub const Cw = struct {
            s_cw: Seed,
            t_cw_l: u1,
            t_cw_r: u1,
        };

        /// A party's key: its root seed, the per-level seed/control CWs and
        /// the per-level output CWs (`ocw[ℓ−1]` for level `ℓ`).
        pub const Key = struct {
            seed: Seed,
            cw: [n_bits]Cw,
            ocw: [n_bits]Elem,

            /// `seed(16) || per level: s_cw(16) || t_cw_l(1) || t_cw_r(1) ||
            /// ocw(L, LE)`.
            pub const serialized_len = seed_len + n_bits * (seed_len + 2 + out_bytes);

            pub fn toBytes(self: *const Key, buf: *[serialized_len]u8) void {
                return burn.run(burn.codec_burn, void, toBytesBody, .{ self, buf });
            }

            fn toBytesBody(self: *const Key, buf: *[serialized_len]u8) void {
                @memcpy(buf[0..seed_len], &self.seed);
                var off: usize = seed_len;
                for (self.cw, self.ocw) |c, o| {
                    @memcpy(buf[off..][0..seed_len], &c.s_cw);
                    buf[off + seed_len] = c.t_cw_l;
                    buf[off + seed_len + 1] = c.t_cw_r;
                    off += seed_len + 2;
                    std.mem.writeInt(Elem, buf[off..][0..out_bytes], o, .little);
                    off += out_bytes;
                }
            }

            pub fn fromBytes(out: *Key, buf: *const [serialized_len]u8) void {
                return burn.run(burn.codec_burn, void, fromBytesBody, .{ out, buf });
            }

            fn fromBytesBody(out: *Key, buf: *const [serialized_len]u8) void {
                out.seed = buf[0..seed_len].*;
                var off: usize = seed_len;
                for (&out.cw, &out.ocw) |*c, *o| {
                    c.s_cw = buf[off..][0..seed_len].*;
                    c.t_cw_l = @truncate(buf[off + seed_len]);
                    c.t_cw_r = @truncate(buf[off + seed_len + 1]);
                    off += seed_len + 2;
                    o.* = std.mem.readInt(Elem, buf[off..][0..out_bytes], .little);
                    off += out_bytes;
                }
            }
        };

        fn bitOf(a: Index, i: usize) u1 {
            const shift: std.math.Log2Int(Index) = @intCast(n_bits - i);
            return @truncate(a >> shift);
        }

        inline fn signed(t: u1, x: Elem) Elem {
            const m = secretMask(Elem, t);
            return (G.neg(x) & m) | (x & ~m);
        }

        /// **Gen** — keys for the point `α` with level outputs `betas[ℓ−1]`,
        /// from two caller-supplied root seeds (random, secret, independent).
        pub fn genWithSeeds(alpha: *const Index, betas: *const [n_bits]Elem, s0: *const Seed, s1: *const Seed, out: *[2]Key) void {
            return burn.run(burn.gen_burn, void, genBody, .{ alpha, betas, s0, s1, out });
        }

        fn genBody(alpha_p: *const Index, betas: *const [n_bits]Elem, s0p: *const Seed, s1p: *const Seed, out: *[2]Key) void {
            const alpha = alpha_p.*;
            const p = P.init();
            var cur0 = s0p.*;
            var cur1 = s1p.*;
            var t0: u1 = 0;
            var t1: u1 = 1;
            var cw: [n_bits]Cw = undefined;
            var ocw: [n_bits]Elem = undefined;
            var i: usize = 1;
            while (i <= n_bits) : (i += 1) {
                const e0 = p.expand(cur0);
                const e1 = p.expand(cur1);
                const a_i = bitOf(alpha, i);
                const s_lose0 = selectSeed(a_i, e0.s_l, e0.s_r);
                const s_lose1 = selectSeed(a_i, e1.s_l, e1.s_r);
                var s_cw: Seed = undefined;
                for (&s_cw, s_lose0, s_lose1) |*d, x, y| d.* = x ^ y;
                const t_cw_l: u1 = e0.t_l ^ e1.t_l ^ a_i ^ 1;
                const t_cw_r: u1 = e0.t_r ^ e1.t_r ^ a_i;
                cw[i - 1] = .{ .s_cw = s_cw, .t_cw_l = t_cw_l, .t_cw_r = t_cw_r };
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
                // ocw_ℓ = (-1)^{t1}·(β_ℓ − Convert(s0) + Convert(s1)) on the path node.
                const c0 = p.convert(out_bytes, cur0);
                const c1 = p.convert(out_bytes, cur1);
                ocw[i - 1] = signed(t1, G.add(G.sub(betas[i - 1], c0), c1));
            }
            out[0] = .{ .seed = s0p.*, .cw = cw, .ocw = ocw };
            out[1] = .{ .seed = s1p.*, .cw = cw, .ocw = ocw };
        }

        /// **Eval** at level `level` (`1..n`) on the `level`-bit prefix
        /// `prefix`: party `b`'s share of `f_level(prefix)`;
        /// `evalPrefix(0, k0, ℓ, p) + evalPrefix(1, k1, ℓ, p) = β_ℓ·[p = α[0..ℓ)]`.
        /// `prefix` must be `< 2^level`.
        pub fn evalPrefix(b: u1, key: *const Key, level: usize, prefix: Index) Elem {
            return burn.run(burn.eval_burn, Elem, evalBody, .{ b, key, level, prefix });
        }

        fn evalBody(b: u1, key: *const Key, level: usize, prefix: Index) Elem {
            std.debug.assert(level >= 1 and level <= n_bits);
            std.debug.assert(@as(usize, prefix) >> @intCast(level) == 0);
            const p = P.init();
            // Align the prefix to the top of an n-bit index so `bitOf`'s
            // MSB-first numbering reads it.
            const x: Index = @truncate(@as(usize, prefix) << @intCast(n_bits - level));
            var s = key.seed;
            var t: u1 = b;
            var i: usize = 1;
            while (i <= level) : (i += 1) {
                const e = p.expand(s);
                const c = key.cw[i - 1];
                const x_i = bitOf(x, i);
                s = selectSeed(x_i, e.s_r, e.s_l);
                const e_t = selectBit(x_i, e.t_r, e.t_l);
                const t_cw = selectBit(x_i, c.t_cw_r, c.t_cw_l);
                const nt = e_t ^ (t & t_cw);
                xorMasked(&s, c.s_cw, t);
                t = nt;
            }
            const v = G.add(p.convert(out_bytes, s), key.ocw[level - 1] & secretMask(Elem, t));
            return signed(b, v);
        }
    };
}

// ── tests ────────────────────────────────────────────────────────────────

const testing = std.testing;

test "idpf: every prefix at every level reconstructs beta_l at alpha's prefix, 0 elsewhere (both PRGs)" {
    inline for (.{ prg_mod.Aes128Mmo, prg_mod.Sha256Prg }) |P| {
        const D = IdpfWith(P, 6, 4);
        var prng = std.Random.DefaultPrng.init(0x1df);
        const rnd = prng.random();
        for (0..8) |_| {
            const alpha = rnd.int(D.Index);
            var betas: [6]D.Elem = undefined;
            for (&betas) |*x| x.* = rnd.int(D.Elem);
            var s0: Seed = undefined;
            var s1: Seed = undefined;
            rnd.bytes(&s0);
            rnd.bytes(&s1);
            var keys: [2]D.Key = undefined;
            D.genWithSeeds(&alpha, &betas, &s0, &s1, &keys);
            for (1..7) |lvl| {
                const want_p = @as(usize, alpha) >> @intCast(6 - lvl);
                for (0..@as(usize, 1) << @intCast(lvl)) |pre| {
                    const got = D.G.add(D.evalPrefix(0, &keys[0], lvl, @intCast(pre)), D.evalPrefix(1, &keys[1], lvl, @intCast(pre)));
                    try testing.expectEqual(if (pre == want_p) betas[lvl - 1] else 0, got);
                }
            }
        }
    }
}

test "idpf: the last level is the plain DPF (same seeds give the same leaf shares)" {
    const I = IdpfWith(prg_mod.Sha256Prg, 5, 8);
    const D = dpf.DpfWith(prg_mod.Sha256Prg, 5, 8);
    const s0: Seed = @splat(0x44);
    const s1: Seed = @splat(0x99);
    const alpha: I.Index = 19;
    const betas = [5]I.Elem{ 1, 2, 3, 4, 0xfeed };
    var ik: [2]I.Key = undefined;
    I.genWithSeeds(&alpha, &betas, &s0, &s1, &ik);
    var dk: [2]D.Key = undefined;
    D.genWithSeeds(&alpha, &betas[4], &s0, &s1, &dk);
    for (0..32) |x| {
        try testing.expectEqual(D.eval(0, &dk[0], @intCast(x)), I.evalPrefix(0, &ik[0], 5, @intCast(x)));
        try testing.expectEqual(D.eval(1, &dk[1], @intCast(x)), I.evalPrefix(1, &ik[1], 5, @intCast(x)));
    }
}

test "idpf: key codec round-trips" {
    const I = Idpf(9, 2);
    const s0: Seed = @splat(1);
    const s1: Seed = @splat(2);
    const alpha: I.Index = 300;
    var betas: [9]I.Elem = undefined;
    for (&betas, 0..) |*x, i| x.* = @intCast(i + 1);
    var keys: [2]I.Key = undefined;
    I.genWithSeeds(&alpha, &betas, &s0, &s1, &keys);
    var buf: [I.Key.serialized_len]u8 = undefined;
    keys[0].toBytes(&buf);
    var back: I.Key = undefined;
    I.Key.fromBytes(&back, &buf);
    try testing.expectEqualDeep(keys[0], back);
    try testing.expectEqual(@as(usize, 16 + 9 * (18 + 2)), I.Key.serialized_len);
}
