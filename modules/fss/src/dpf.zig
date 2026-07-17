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
//! **Fable-irreducible core (GATED behind `gate.core_implemented`):**
//!   - `genWithSeeds` — the per-level correction-word derivation (seed CW +
//!     two control-bit CWs maintaining the on-path-differ / off-path-equal
//!     invariant) and the final output correction word.
//!   - `eval` — the matching root-to-leaf traversal applying each level's CW
//!     gated by the running control bit, then the output word.
//!
//! **Mechanical scaffold (REAL today):** the `Cw`/`Key` types, `serializeCw`
//! + the byte codec, `evalAll` (a mechanical loop over `eval`), the
//! `firstMismatch` full-domain checker, and everything in `prg.zig`/
//! `group.zig`. `evalAll` is intentionally NOT the efficient tree-reuse
//! full-domain evaluator (that shares `eval`'s core logic and is a scoped-out
//! optimization — SPEC.md §"Scoped out"); the naive loop is correct once
//! `eval` is and keeps the Fable surface minimal.

const std = @import("std");
const prg_mod = @import("prg.zig");
const group = @import("group.zig");
const gate = @import("gate.zig");

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
        /// **TODO(fable/core):** implement the BGI16 per-level correction-word
        /// derivation + final output word (see this file's module doc + SPEC).
        pub fn genWithSeeds(alpha: Index, beta: Elem, s0: Seed, s1: Seed) [2]Key {
            if (!gate.core_implemented) {
                _ = .{ alpha, beta, s0, s1 };
                @panic("TODO(fable/core): BGI16 correction-word Gen not yet implemented — see modules/fss/SPEC.md");
            }
            // Fable pass implements the real construction here (and removes the
            // panic branch above). Signature + types are final.
            @panic("unreachable once implemented");
        }

        /// **Eval** — evaluate party `b`'s share of `f_{α,β}` at input `x`.
        /// Returns this party's additive share; `eval(0,k0,x) + eval(1,k1,x)`
        /// reconstructs `f_{α,β}(x)` in `Z_{2^{8L}}`.
        ///
        /// **TODO(fable/core):** implement the root-to-leaf traversal applying
        /// each level's CW gated by the running control bit, then the output
        /// correction word.
        pub fn eval(b: u1, key: Key, x: Index) Elem {
            if (!gate.core_implemented) {
                _ = .{ b, key, x };
                @panic("TODO(fable/core): BGI16 Eval traversal not yet implemented — see modules/fss/SPEC.md");
            }
            @panic("unreachable once implemented");
        }

        // ── Mechanical scaffold (REAL) ────────────────────────────────────

        /// **EvalAll** — evaluate party `b` at every domain point into `out`
        /// (`out.len` must equal `domain_size`). Mechanical loop over `eval`
        /// (so it panics through `eval` while the core is gated). Correct once
        /// `eval` is; an efficient tree-reuse variant is scoped out (SPEC).
        pub fn evalAll(b: u1, key: Key, out: []Elem) void {
            std.debug.assert(out.len == domain_size);
            var x: usize = 0;
            while (x < domain_size) : (x += 1) {
                out[x] = eval(b, key, @intCast(x));
            }
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
