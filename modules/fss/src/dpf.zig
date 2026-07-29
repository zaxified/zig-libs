// SPDX-License-Identifier: MIT

//! dpf — Distributed Point Function (2-party single-point Function Secret
//! Sharing) via the Boyle–Gilboa–Ishai optimized tree construction
//! ("Function Secret Sharing: Improvements and Extensions", ACM CCS 2016,
//! Fig. 1). A point function `f_{α,β}(x) = β if x==α else 0` is secret-shared
//! into two keys `(k0,k1)` such that for every input `x`,
//! `Eval(0,k0,x) + Eval(1,k1,x) == f_{α,β}(x)` in the output group Z_{2^{8L}},
//! while each key ALONE hides `(α,β)`.
//!
//! `Dpf(n, L)` fixes the domain to `{0,1}^n` (indices `0..2^n`) and the
//! output group to `Z2k(L) = Z_{2^{8L}}`.
//!
//! ## The Fable boundary (see gate.zig / SPEC.md)
//!
//! **Fable-irreducible core (IMPLEMENTED; `gate.core_implemented = true`):**
//!   - `genWithSeeds` — the per-level correction-word derivation (seed CW +
//!     two control-bit CWs maintaining the on-path-differ / off-path-equal
//!     invariant) and the final output correction word.
//!   - `eval` — the matching root-to-leaf traversal applying each level's CW
//!     gated by the running control bit, then the output word.
//!
//! **Mechanical scaffold (REAL today):** the `Cw`/`Key` types, `serializeCw`
//! + the byte codec, `evalAll` (a mechanical loop over `eval`), `evalFull`/
//! `evalFullWith` (the tree-reuse prefix evaluator — `eval`'s exact per-level
//! formulas batched over the shared tree, ~`out.len` PRG calls instead of
//! `out.len·n`; SPEC.md §"Tree-reuse prefix evaluation"), the `firstMismatch`
//! full-domain checker, and everything in `prg.zig`/`group.zig`. `evalAll`
//! stays the naive loop over `eval` deliberately: it is the structurally
//! independent oracle the tree-reuse evaluator is tested against
//! element-for-element.

const std = @import("std");
const prg_mod = @import("prg.zig");
const group = @import("group.zig");

const Seed = prg_mod.Seed;
const seed_len = prg_mod.seed_len;

/// A 2-party single-point DPF over domain `{0,1}^n_bits`, output group
/// Z_{2^{8*out_bytes}}. `n_bits ∈ 1..31`, `out_bytes ∈ 1..32`.
pub fn Dpf(comptime n_bits: usize, comptime out_bytes: usize) type {
    if (n_bits < 1 or n_bits > 31) @compileError("Dpf: n_bits must be in 1..31");
    if (out_bytes < 1 or out_bytes > 32) @compileError("Dpf: out_bytes must be in 1..32");
    return struct {
        pub const n = n_bits;
        pub const G = group.Z2k(out_bytes);
        /// output-group element type (Z_{2^{8*out_bytes}})
        pub const Elem = G.Int;
        /// domain index type: an `n`-bit unsigned integer in `0..2^n`
        pub const Index = std.meta.Int(.unsigned, n_bits);
        /// number of points in the domain (`2^n`)
        pub const domain_size: usize = @as(usize, 1) << @intCast(n_bits);

        /// one level's correction word: a seed CW plus the two control-bit CWs.
        pub const Cw = struct {
            s_cw: Seed,
            t_cw_l: u1,
            t_cw_r: u1,
        };

        /// a party's DPF key. `cw`/`cw_final` are SHARED by both parties;
        /// only `seed` (the party's root seed) differs between k0 and k1.
        pub const Key = struct {
            seed: Seed,
            cw: [n_bits]Cw,
            cw_final: Elem,

            /// serialized length of the CW portion (per-level CWs + final word),
            /// EXCLUDING the party-specific root seed.
            pub const cw_serialized_len = n_bits * (seed_len + 2) + out_bytes;
            /// serialized length of a full key (root seed + CW portion).
            pub const serialized_len = seed_len + cw_serialized_len;

            /// Serialize the CW portion (shared between k0/k1): for each level
            /// `s_cw(16) || t_cw_l(1) || t_cw_r(1)`, then `cw_final` (LE). This
            /// is the byte layout the external KAT vectors pin. REAL/ungated.
            pub fn serializeCw(self: Key, buf: *[cw_serialized_len]u8) void {
                var off: usize = 0;
                for (self.cw) |c| {
                    @memcpy(buf[off .. off + seed_len], &c.s_cw);
                    off += seed_len;
                    buf[off] = c.t_cw_l;
                    off += 1;
                    buf[off] = c.t_cw_r;
                    off += 1;
                }
                std.mem.writeInt(Elem, buf[off..][0..out_bytes], self.cw_final, .little);
            }

            /// Serialize a full key: `seed(16) || serializeCw`. REAL/ungated.
            pub fn toBytes(self: Key, buf: *[serialized_len]u8) void {
                @memcpy(buf[0..seed_len], &self.seed);
                self.serializeCw(buf[seed_len..][0..cw_serialized_len]);
            }

            /// Decode a full key from `toBytes` output. REAL/ungated.
            pub fn fromBytes(buf: *const [serialized_len]u8) Key {
                var key: Key = undefined;
                key.seed = buf[0..seed_len].*;
                var off: usize = seed_len;
                for (&key.cw) |*c| {
                    c.s_cw = buf[off..][0..seed_len].*;
                    off += seed_len;
                    c.t_cw_l = @truncate(buf[off]);
                    off += 1;
                    c.t_cw_r = @truncate(buf[off]);
                    off += 1;
                }
                key.cw_final = std.mem.readInt(Elem, buf[off..][0..out_bytes], .little);
                return key;
            }
        };

        /// bit `i` (1-indexed, MSB-first: i=1 is the top of the tree) of `a`.
        fn bitOf(a: Index, i: usize) u1 {
            const shift: std.math.Log2Int(Index) = @intCast(n_bits - i);
            return @truncate(a >> shift);
        }

        // ── Fable-irreducible core (GATED) ────────────────────────────────

        /// **Gen** — deterministically derive `(k0,k1)` for the point function
        /// `f_{α,β}` from two caller-supplied root seeds `s0`,`s1`.
        ///
        /// The caller MUST supply cryptographically-random, secret, mutually
        /// independent 16-byte seeds (this is the DPF's only source of
        /// randomness; keeping it caller-supplied is what makes this module
        /// pure `.any` computation — see README). Determinism given the seeds
        /// is what the byte-exact KAT vectors rely on.
        ///
        /// BGI16 Fig. 1. Root state: `(s_b^0, t_b^0) = (s_b, b)`. Invariant
        /// maintained down the α-path: the two parties' `(seed, t)` states are
        /// pseudorandom and DIFFER (with `t0⊕t1 == 1`) on the path node, and
        /// are byte-EQUAL on every node off the path — so off-path leaves
        /// convert to identical group elements that cancel, while the α leaf
        /// differs and the final CW steers the difference to exactly `β`.
        ///
        /// Per level `i` (with `α_i` the MSB-first path bit, Keep the child
        /// toward α, Lose the sibling):
        ///   `s_cw    = s^0_Lose ⊕ s^1_Lose`   (equalizes the off-path child)
        ///   `t_cw_l  = t^0_L ⊕ t^1_L ⊕ α_i ⊕ 1`
        ///   `t_cw_r  = t^0_R ⊕ t^1_R ⊕ α_i`
        ///   `s_b^i   = s^b_Keep ⊕ t_b^{i-1}·s_cw`
        ///   `t_b^i   = t^b_Keep ⊕ t_b^{i-1}·t_cw_Keep`
        /// Final word: `cw_final = (-1)^{t1^n}·(β − Convert(s0^n) + Convert(s1^n))`.
        pub fn genWithSeeds(alpha: Index, beta: Elem, s0: Seed, s1: Seed) [2]Key {
            var cur0 = s0;
            var cur1 = s1;
            var t0: u1 = 0;
            var t1: u1 = 1;
            var cw: [n_bits]Cw = undefined;

            var i: usize = 1;
            while (i <= n_bits) : (i += 1) {
                const e0 = prg_mod.prg(cur0);
                const e1 = prg_mod.prg(cur1);
                const a_i = bitOf(alpha, i);

                // Keep = child toward α (α_i=0 → Left); Lose = the sibling.
                const s_lose0 = if (a_i == 0) e0.s_r else e0.s_l;
                const s_lose1 = if (a_i == 0) e1.s_r else e1.s_l;
                var s_cw: Seed = undefined;
                for (&s_cw, s_lose0, s_lose1) |*d, a, b| d.* = a ^ b;
                const t_cw_l: u1 = e0.t_l ^ e1.t_l ^ a_i ^ 1;
                const t_cw_r: u1 = e0.t_r ^ e1.t_r ^ a_i;
                cw[i - 1] = .{ .s_cw = s_cw, .t_cw_l = t_cw_l, .t_cw_r = t_cw_r };

                const s_keep0 = if (a_i == 0) e0.s_l else e0.s_r;
                const s_keep1 = if (a_i == 0) e1.s_l else e1.s_r;
                const t_keep0: u1 = if (a_i == 0) e0.t_l else e0.t_r;
                const t_keep1: u1 = if (a_i == 0) e1.t_l else e1.t_r;
                const t_cw_keep: u1 = if (a_i == 0) t_cw_l else t_cw_r;

                // s_b^i = s^b_Keep ⊕ t_b^{i-1}·s_cw ; t_b^i = t^b_Keep ⊕ t_b^{i-1}·t_cw_Keep
                cur0 = s_keep0;
                if (t0 == 1) for (&cur0, s_cw) |*d, c| {
                    d.* ^= c;
                };
                cur1 = s_keep1;
                if (t1 == 1) for (&cur1, s_cw) |*d, c| {
                    d.* ^= c;
                };
                const nt0 = t_keep0 ^ (t0 & t_cw_keep);
                const nt1 = t_keep1 ^ (t1 & t_cw_keep);
                t0 = nt0;
                t1 = nt1;
            }

            // cw_final = (-1)^{t1^n} · (β − Convert(s0^n) + Convert(s1^n))
            const c0 = prg_mod.convert(out_bytes, cur0);
            const c1 = prg_mod.convert(out_bytes, cur1);
            var cw_final: Elem = G.add(G.sub(beta, c0), c1);
            if (t1 == 1) cw_final = G.neg(cw_final);

            return .{
                .{ .seed = s0, .cw = cw, .cw_final = cw_final },
                .{ .seed = s1, .cw = cw, .cw_final = cw_final },
            };
        }

        /// **Eval** — evaluate party `b`'s share of `f_{α,β}` at input `x`.
        /// Returns this party's additive share; `eval(0,k0,x) + eval(1,k1,x)`
        /// reconstructs `f_{α,β}(x)` in `Z_{2^{8L}}`.
        ///
        /// The traversal matching `genWithSeeds`: start at `(key.seed, b)`,
        /// then per level expand with the PRG, XOR in the level CW iff the
        /// running control bit `t` is 1, and descend by `x_i` (MSB-first).
        /// At the leaf: `share = (-1)^b · (Convert(s) + t·cw_final)`.
        pub fn eval(b: u1, key: Key, x: Index) Elem {
            var s = key.seed;
            var t: u1 = b;
            var i: usize = 1;
            while (i <= n_bits) : (i += 1) {
                const e = prg_mod.prg(s);
                const c = key.cw[i - 1];
                if (bitOf(x, i) == 0) {
                    s = e.s_l;
                    const nt = e.t_l ^ (t & c.t_cw_l);
                    if (t == 1) for (&s, c.s_cw) |*d, q| {
                        d.* ^= q;
                    };
                    t = nt;
                } else {
                    s = e.s_r;
                    const nt = e.t_r ^ (t & c.t_cw_r);
                    if (t == 1) for (&s, c.s_cw) |*d, q| {
                        d.* ^= q;
                    };
                    t = nt;
                }
            }
            var out: Elem = prg_mod.convert(out_bytes, s);
            if (t == 1) out = G.add(out, key.cw_final);
            if (b == 1) out = G.neg(out);
            return out;
        }

        // ── Mechanical scaffold (REAL) ────────────────────────────────────

        /// **EvalAll** — evaluate party `b` at every domain point into `out`
        /// (`out.len` must equal `domain_size`). Mechanical loop over `eval`,
        /// `O(domain_size · n)` PRG calls. Kept naive ON PURPOSE even though
        /// `evalFull` exists: this loop is structurally independent of the
        /// tree-reuse walk, which makes it the differential oracle the
        /// equivalence tests compare `evalFull` against. Use `evalFull` when
        /// you want the result fast.
        pub fn evalAll(b: u1, key: Key, out: []Elem) void {
            std.debug.assert(out.len == domain_size);
            var x: usize = 0;
            while (x < domain_size) : (x += 1) {
                out[x] = eval(b, key, @intCast(x));
            }
        }

        /// **EvalFull** — tree-reuse evaluation of party `b` over the domain
        /// **prefix** `[0, out.len)`, `out.len <= domain_size`. Fills `out[x]`
        /// with bit-for-bit what `eval(b, key, x)` returns, for every `x` in
        /// the prefix, in one walk of the GGM tree: each internal node's PRG
        /// expansion is computed once and BOTH children are kept, so the cost
        /// is ~`out.len` PRG calls (plus at most `n` for nodes straddling the
        /// prefix boundary) instead of `eval`'s `out.len · n`.
        ///
        /// The prefix contract — rather than full-domain-only — is
        /// load-bearing for the `pir` consumer: a PIR domain is normally sized
        /// generously above the record count and the unused tail must never be
        /// evaluated (`pir/SPEC.md` §"Truncating the domain is safe"). A
        /// subtree lying entirely at/past `out.len` is skipped BEFORE its PRG
        /// call, so the tail costs zero hashes and the cost is `O(out.len)`,
        /// not `O(2^n)`.
        pub fn evalFull(b: u1, key: Key, out: []Elem) void {
            std.debug.assert(out.len <= domain_size);
            const sink = struct {
                fn emit(o: []Elem, x: usize, v: Elem) void {
                    o[x] = v;
                }
            };
            walkPrefix([]Elem, sink.emit, &key, b, key.seed, b, 0, 0, out.len, out);
        }

        /// **EvalFullWith** — the same tree-reuse prefix walk as `evalFull`,
        /// streaming: `emit(context, x, elem)` is called once for each
        /// `x ∈ [0, count)`, in ascending order, and nothing is materialized.
        /// For consumers that must stay allocator-free over runtime-sized
        /// prefixes (`pir`'s server loop): each evaluation is consumed as the
        /// walk produces it, so no `count`-sized buffer exists anywhere.
        pub fn evalFullWith(
            b: u1,
            key: Key,
            count: usize,
            context: anytype,
            comptime emit: fn (@TypeOf(context), usize, Elem) void,
        ) void {
            std.debug.assert(count <= domain_size);
            walkPrefix(@TypeOf(context), emit, &key, b, key.seed, b, 0, 0, count, context);
        }

        /// The shared walk under `evalFull`/`evalFullWith`. Recursive; depth
        /// is bounded by `n <= 31` with a small frame, so stack use is
        /// trivial. Per level this applies exactly `eval`'s formulas — the
        /// seed CW XOR gated by the PARENT's control bit, the child control
        /// bits from `t_cw_l`/`t_cw_r` — and at a leaf exactly `eval`'s output
        /// step (`convert`, `t`-gated `cw_final`, `(-1)^b`). Equivalence to
        /// `eval` is asserted element-for-element in `kat_test.zig`, with
        /// `evalAll`'s independent naive loop as the oracle.
        fn walkPrefix(
            comptime Context: type,
            comptime emit: fn (Context, usize, Elem) void,
            key: *const Key,
            b: u1,
            s: Seed,
            t: u1,
            level: usize,
            base: usize,
            count: usize,
            context: Context,
        ) void {
            // This node's subtree covers leaves [base, base + 2^(n-level)).
            // If that lies entirely at/past the prefix end, skip before the
            // PRG call — the unused tail of the domain costs zero hashes.
            if (base >= count) return;
            if (level == n_bits) {
                var v: Elem = prg_mod.convert(out_bytes, s);
                if (t == 1) v = G.add(v, key.cw_final);
                if (b == 1) v = G.neg(v);
                emit(context, base, v);
                return;
            }
            const e = prg_mod.prg(s);
            const c = key.cw[level];
            const half = @as(usize, 1) << @intCast(n_bits - 1 - level);

            var s_l = e.s_l;
            const t_l = e.t_l ^ (t & c.t_cw_l);
            if (t == 1) for (&s_l, c.s_cw) |*d, q| {
                d.* ^= q;
            };
            walkPrefix(Context, emit, key, b, s_l, t_l, level + 1, base, count, context);

            var s_r = e.s_r;
            const t_r = e.t_r ^ (t & c.t_cw_r);
            if (t == 1) for (&s_r, c.s_cw) |*d, q| {
                d.* ^= q;
            };
            walkPrefix(Context, emit, key, b, s_r, t_r, level + 1, base + half, count, context);
        }

        /// Full-domain correctness checker (REAL/ungated). Given both parties'
        /// full-domain evaluations, return the first index `x` where
        /// `eval0[x] + eval1[x] != f_{α,β}(x)`, or `null` if the pair is a
        /// correct sharing of `f_{α,β}` everywhere. This is the deterministic
        /// oracle the KAT harness and the broken-positive-controls both use.
        pub fn firstMismatch(eval0: []const Elem, eval1: []const Elem, alpha: Index, beta: Elem) ?usize {
            std.debug.assert(eval0.len == domain_size and eval1.len == domain_size);
            var x: usize = 0;
            while (x < domain_size) : (x += 1) {
                const got = G.add(eval0[x], eval1[x]);
                const want: Elem = if (x == @as(usize, alpha)) beta else 0;
                if (got != want) return x;
            }
            return null;
        }
    };
}

// ── tests (REAL scaffold pieces; core-dependent tests live in kat_test) ───

test "Key serialize/deserialize round-trips (REAL, no core)" {
    const D = Dpf(8, 4);
    var key: D.Key = undefined;
    // fill with arbitrary but deterministic bytes
    for (&key.seed, 0..) |*byte, i| byte.* = @truncate(i * 7 + 1);
    for (&key.cw, 0..) |*c, i| {
        for (&c.s_cw, 0..) |*byte, j| byte.* = @truncate(i * 13 + j);
        c.t_cw_l = @truncate(i);
        c.t_cw_r = @truncate(i + 1);
    }
    key.cw_final = 0xCAFEBABE;

    var buf: [D.Key.serialized_len]u8 = undefined;
    key.toBytes(&buf);
    const back = D.Key.fromBytes(&buf);

    try std.testing.expectEqualSlices(u8, &key.seed, &back.seed);
    try std.testing.expectEqual(key.cw_final, back.cw_final);
    for (key.cw, back.cw) |a, b| {
        try std.testing.expectEqualSlices(u8, &a.s_cw, &b.s_cw);
        try std.testing.expectEqual(a.t_cw_l, b.t_cw_l);
        try std.testing.expectEqual(a.t_cw_r, b.t_cw_r);
    }
}

test "cw_serialized_len matches the pinned layout (REAL, no core)" {
    // n=4,L=4 → 4*(16+2)+4 = 76 bytes (matches the Python reference vectors).
    try std.testing.expectEqual(@as(usize, 76), Dpf(4, 4).Key.cw_serialized_len);
    try std.testing.expectEqual(@as(usize, 148), Dpf(8, 4).Key.cw_serialized_len);
}

test "firstMismatch: a correct sharing passes, a wrong one is caught (REAL, no core)" {
    const D = Dpf(3, 4); // domain 8
    const alpha: D.Index = 5;
    const beta: D.Elem = 99;
    // A hand-built CORRECT sharing: eval0 = arbitrary r[x]; eval1 = f(x) - r[x].
    var e0: [8]D.Elem = undefined;
    var e1: [8]D.Elem = undefined;
    for (0..8) |x| {
        e0[x] = @intCast(x * 1234567 + 7);
        const f: D.Elem = if (x == alpha) beta else 0;
        e1[x] = D.G.sub(f, e0[x]);
    }
    try std.testing.expect(D.firstMismatch(&e0, &e1, alpha, beta) == null);
    // Corrupt one point → must be caught.
    e1[2] = D.G.add(e1[2], 1);
    try std.testing.expectEqual(@as(?usize, 2), D.firstMismatch(&e0, &e1, alpha, beta));
}
