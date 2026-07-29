// SPDX-License-Identifier: MIT

//! mpf — **multi-point** Function Secret Sharing: two keys sharing
//! `f_{A,B}(x) = Σ_j β_j · 1{x == α_j}`, a function non-zero at `k` chosen
//! points and zero everywhere else. `dpf.zig` is the `k == 1` case.
//!
//! ```
//! Eval(0,K0,x) + Eval(1,K1,x) == f_{A,B}(x)   for every x    (correctness)
//! ```
//!
//! in the same output group `Z_{2^{8L}}`, with either key alone computationally
//! independent of `(A,B)`.
//!
//! ## The construction, and why this one
//!
//! **`k` independent DPF instances, summed.** `Gen` runs `dpf`'s `Gen` `k`
//! times on `k` independent seed pairs; the key is the bundle of the `k`
//! sub-keys; `Eval` adds the `k` sub-evaluations in the group. Correctness is
//! one line of distributivity: each instance contributes `β_j·1{x==α_j}` to the
//! sum at every `x`, so the sum of the two parties' sums is `f_{A,B}(x)`.
//!
//! The literature has better *asymptotics*. Batch-code and cuckoo-hashing
//! multi-point FSS (the constructions under modern batch-PIR and PSI work)
//! partition the domain into ~`1.5k` buckets, put one point in each, and
//! evaluate every bucket over a `1/1.5k` slice of the domain — turning the
//! server's `O(k·N)` into `O(N)`, one pass total, with keys over shorter trees.
//! That is a real win and it is not what this module does. The trade-off
//! accepted here, stated so it can be argued with:
//!
//! | | sum-of-`k`-DPFs (this) | cuckoo / batch-code |
//! |---|---|---|
//! | key size | `k · O(λ·n)` — linear | `~1.5k · O(λ·(n − log k))` — mildly sublinear |
//! | server work | `k` evaluations per record | ~1 evaluation per record |
//! | failure probability | **none** — correct for every input | placement failure; a parameter to get wrong |
//! | new cryptographic surface | **none** — `k` uses of an anchored primitive | bucketing, stash handling, hash choice |
//! | auditability | the whole thing is the paragraph above | a construction in its own right |
//!
//! For a library whose consumer (`pir`) has no throughput requirement yet, the
//! last three rows decide it. A construction with a failure probability buys
//! nothing here except a number someone has to calibrate and a test someone has
//! to believe; a construction with no failure probability at all and no new
//! assumption beyond "`dpf` is a DPF" is auditable by reading it. The
//! sub-keys are also individually byte-exactly anchored — each one is a `dpf`
//! key, and `dpf`'s KAT vectors come from an independent re-derivation — so
//! this scheme inherits an external anchor that a cuckoo construction would
//! have to establish from scratch.
//!
//! **What would justify revisiting it.** One thing, measured rather than
//! guessed: a consumer for which `k` full passes over the database dominate.
//! The server cost is `k·N` DPF evaluations of `n` SHA-256 calls each; at
//! `k=100, N=2^20` that is ~2·10^9 hashes per query, and at that point the
//! bucketed construction is worth its failure probability. Note the cheaper
//! fix comes first: `fss`'s scoped-out tree-reuse `evalFull` cuts each pass
//! from `O(N·n)` to `O(N)` hashes with **no** new cryptography, so it should be
//! spent before the cuckoo complexity budget is.
//!
//! ## Why the bundle is not compressed, and what that buys
//!
//! `Key` is `[k]dpf.Key` laid end to end. Nothing is shared between the
//! instances — deliberately, because sharing anything between them is exactly
//! what would make the indices' *relationship* observable (see below). The
//! consequence is that the `k` components stay individually addressable, which
//! is what `evalEach` exposes and what a `k`-record retrieval consumer needs:
//! the summed `eval` is the multi-point function, but a consumer wanting `k`
//! *separate* results needs the components, not their sum.
//!
//! ## Seed independence is load-bearing, and is checked
//!
//! The `2k` seeds MUST be mutually independent. This is not the usual
//! boilerplate: with the *same* seed pair used for two instances, `Gen`'s state
//! at every level is a function of the seeds and the index bits consumed so
//! far, so two indices sharing a `p`-bit prefix produce **byte-identical
//! correction words for those `p` levels**. A server holding one key would read
//! off the pairwise common-prefix length of the client's indices directly from
//! the bytes. `genWithSeeds` therefore *rejects* duplicate seeds
//! (`error.SeedReuse`) — a guard against the plumbing bug (a caller looping
//! wrong, or passing one seed pair `k` times), **not** a test of randomness
//! quality, which no library can perform on its caller's behalf. Distinct but
//! correlated seeds pass the check and are still the caller's bug.
//! `mpf_test.zig` demonstrates the leak as an executable negative control.
//!
//! ## No new Fable surface
//!
//! Every cryptographic decision here was already made in `dpf.zig`: this file
//! is `k` calls, a group sum, a concatenation and a distinctness check. There
//! is no gate because there is nothing gate-worthy — the correction-word
//! construction is not touched. That is a property of the chosen construction,
//! not a claim about this file's importance.

const std = @import("std");
const prg_mod = @import("prg.zig");
const dpf_mod = @import("dpf.zig");

const Seed = prg_mod.Seed;

/// The only way `Gen` can fail. Not a cryptographic failure — a caller
/// contract violation, caught because its consequence is a direct leak of the
/// relationship between the shared points (see the module doc).
pub const GenError = error{
    /// two of the `2k` root seeds are byte-identical. See the module doc:
    /// seed reuse across instances makes shared index prefixes visible in the
    /// correction words.
    SeedReuse,
};

/// A 2-party `k`-point FSS scheme over domain `{0,1}^n_bits`, output group
/// `Z_{2^{8*out_bytes}}`. `k == 1` is exactly `Dpf(n_bits, out_bytes)`
/// wrapped in a one-element bundle; `k == 0` is the degenerate all-zero
/// function with a zero-byte key (a boundary case, not a use case).
///
/// `k` is a **compile-time** parameter, matching `n_bits`/`out_bytes`. That is
/// what keeps the key encoding free of any count field: `serialized_len` is a
/// compile-time constant and `fromBytes` takes a fixed-size array pointer, so
/// there is no length in the bytes for a parser to trust. `k` is public
/// protocol geometry — both parties compile the same instantiation — and the
/// serialized length reveals it. What it does not reveal is the points.
pub fn Mpf(comptime n_bits: usize, comptime out_bytes: usize, comptime k: usize) type {
    // The `2k`-seed distinctness check is O(k²) and `Gen` holds `k` sub-keys;
    // both are fine at the scale this construction is the right one for. A `k`
    // this large is itself the signal to revisit the construction (module doc).
    if (k > 1024) @compileError("Mpf: k must be <= 1024");
    return struct {
        /// the single-point DPF this is `k` independent instances of
        pub const Dpf = dpf_mod.Dpf(n_bits, out_bytes);
        pub const G = Dpf.G;
        /// output-group element type (`Z_{2^{8*out_bytes}}`)
        pub const Elem = Dpf.Elem;
        /// domain index type: an `n_bits`-bit unsigned integer
        pub const Index = Dpf.Index;
        pub const n = n_bits;
        /// number of shared points
        pub const points = k;
        pub const domain_size: usize = Dpf.domain_size;

        /// A party's multi-point key: the `k` sub-keys end to end.
        ///
        /// As in `dpf`, the two parties' keys differ **only** in the `k` root
        /// seeds; every correction word is shared. Two colluding parties
        /// therefore recover all `k` points, exactly as one colluding pair
        /// recovers the single point in `dpf`.
        pub const Key = struct {
            keys: [k]Dpf.Key,

            /// bytes per sub-key
            pub const sub_serialized_len = Dpf.Key.serialized_len;
            /// serialized length of a full multi-point key. A compile-time
            /// constant: `k` sub-keys of a compile-time-constant size, with no
            /// header, no separator and **no count field**.
            pub const serialized_len = k * sub_serialized_len;

            /// Serialize: sub-key `0 || 1 || … || k-1`, each in `dpf`'s own
            /// `Key.toBytes` layout.
            pub fn toBytes(self: Key, buf: *[serialized_len]u8) void {
                for (self.keys, 0..) |key, j| {
                    key.toBytes(buf[j * sub_serialized_len ..][0..sub_serialized_len]);
                }
            }

            /// Decode. Takes a **fixed-size array pointer**, so — exactly as in
            /// `dpf` — there is no length or count anywhere in the input for a
            /// parser to believe: every sub-key is a fixed-width read at a
            /// compile-time-known offset. Total on all `serialized_len`-byte
            /// inputs; an input that is not a real key decodes to a key that
            /// evaluates to garbage, which is not this layer's problem.
            pub fn fromBytes(buf: *const [serialized_len]u8) Key {
                var out: Key = undefined;
                for (&out.keys, 0..) |*key, j| {
                    key.* = Dpf.Key.fromBytes(buf[j * sub_serialized_len ..][0..sub_serialized_len]);
                }
                return out;
            }
        };

        /// Reject byte-identical seeds among the `2k` supplied. See the module
        /// doc for why this specific failure is worth a check when "use good
        /// randomness" is otherwise left to the caller.
        fn requireDistinctSeeds(s0: [k]Seed, s1: [k]Seed) GenError!void {
            var all: [2 * k]Seed = undefined;
            for (s0, 0..) |s, j| all[j] = s;
            for (s1, 0..) |s, j| all[k + j] = s;
            for (all, 0..) |a, i| {
                for (all[0..i]) |b| {
                    if (std.mem.eql(u8, &a, &b)) return error.SeedReuse;
                }
            }
        }

        /// **Gen** — keys for `f_{A,B}(x) = Σ_j β_j·1{x==α_j}`.
        ///
        /// `s0[j]`/`s1[j]` are instance `j`'s root seeds and must ALL be
        /// cryptographically random, secret and mutually independent — across
        /// instances as well as within a pair. Byte-identical seeds are
        /// rejected; see the module doc for the leak that motivates it.
        ///
        /// **Repeated points are a multiset, not an error.** If `α_j == α_l`,
        /// the shared function takes the value `β_j + β_l` there, because the
        /// instances sum. That is the definition of the multi-point function
        /// this shares, and it is what `firstMismatch` checks against. A
        /// consumer for which that is the wrong semantic (`pir`'s `k`-record
        /// retrieval is one — it wants `k` separate results) must use
        /// `evalEach`, where the instances never meet.
        pub fn genWithSeeds(
            alphas: [k]Index,
            betas: [k]Elem,
            s0: [k]Seed,
            s1: [k]Seed,
        ) GenError![2]Key {
            try requireDistinctSeeds(s0, s1);
            var key0: Key = undefined;
            var key1: Key = undefined;
            for (0..k) |j| {
                const pair = Dpf.genWithSeeds(alphas[j], betas[j], s0[j], s1[j]);
                key0.keys[j] = pair[0];
                key1.keys[j] = pair[1];
            }
            return .{ key0, key1 };
        }

        /// **Eval** — party `b`'s share of `f_{A,B}(x)`: the group sum of the
        /// `k` instances' shares. `eval(0,K0,x) + eval(1,K1,x) == f_{A,B}(x)`.
        pub fn eval(b: u1, key: Key, x: Index) Elem {
            var acc: Elem = 0;
            for (key.keys) |sub| acc = G.add(acc, Dpf.eval(b, sub, x));
            return acc;
        }

        /// Party `b`'s **per-instance** shares at `x`, unsummed:
        /// `out[j] = Dpf.eval(b, key.keys[j], x)`.
        ///
        /// Not a different security claim — the same key material, decomposed
        /// as it is stored. A consumer needing `k` separable results (rather
        /// than the multi-point function's single value) evaluates here and
        /// keeps the components apart; summing `out` reproduces `eval`.
        pub fn evalEach(b: u1, key: Key, x: Index, out: *[k]Elem) void {
            for (out, key.keys) |*o, sub| o.* = Dpf.eval(b, sub, x);
        }

        /// **EvalAll** — `eval` at every domain point into `out`
        /// (`out.len == domain_size`). Naive loop, for the same reason
        /// `dpf.evalAll` is (SPEC.md §"Scoped out").
        pub fn evalAll(b: u1, key: Key, out: []Elem) void {
            std.debug.assert(out.len == domain_size);
            var x: usize = 0;
            while (x < domain_size) : (x += 1) out[x] = eval(b, key, @intCast(x));
        }

        /// Full-domain correctness oracle: the first `x` where
        /// `eval0[x] + eval1[x]` differs from `f_{A,B}(x)`, or `null`.
        ///
        /// The reference value accumulates over repeated points
        /// (`want[x] = Σ_{j : α_j == x} β_j`), which is the multiset semantic
        /// `genWithSeeds` documents — a checker that instead took "the" β at a
        /// repeated point would disagree with the construction and hide the
        /// case rather than test it.
        pub fn firstMismatch(
            eval0: []const Elem,
            eval1: []const Elem,
            alphas: [k]Index,
            betas: [k]Elem,
        ) ?usize {
            std.debug.assert(eval0.len == domain_size and eval1.len == domain_size);
            var x: usize = 0;
            while (x < domain_size) : (x += 1) {
                var want: Elem = 0;
                for (alphas, betas) |a, b| {
                    if (@as(usize, a) == x) want = G.add(want, b);
                }
                if (G.add(eval0[x], eval1[x]) != want) return x;
            }
            return null;
        }
    };
}
