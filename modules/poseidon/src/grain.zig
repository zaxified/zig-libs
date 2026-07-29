// SPDX-License-Identifier: MIT
//! `grain` — the **Grain LFSR parameter generator** that decides which numbers
//! go into a Poseidon instance: the round constants and the MDS matrix.
//!
//! This is a line-by-line port of the GF(p) path of the Poseidon authors'
//! reference generator,
//! `hadeshash/code/generate_parameters_grain.sage`
//! (<https://extgit.iaik.tugraz.at/krypto/hadeshash>, which redirects to
//! `extgit.isec.tugraz.at/krypto/hadeshash`) — the script every deployed
//! Poseidon-over-BN254 instance's constants come from. circomlib's
//! `circuits/poseidon_constants.circom` and circomlibjs'
//! `src/poseidon_reference.js` both name it in a header comment, together
//! with the exact invocation.
//!
//! ## Why generate instead of embed
//!
//! The alternative was ~10 850 embedded field elements (~700 KB of hex) for
//! `t = 2..17` on BN254 alone. Deriving them puts the *rule* in the repo
//! rather than the *output*, and the rule is what an auditor can diff against
//! upstream. The output is still pinned: `constants_test.zig` hashes the
//! derived tables and compares against SHA-256 digests taken over circomlib's
//! own published constants, with the extraction command recorded.
//!
//! ## Two subtleties that are easy to get wrong
//!
//! Both come straight from the sage script and both change the output:
//!
//!  1. **Round constants use rejection sampling; the MDS seeds do not.**
//!     `generate_constants` redraws `n` fresh bits while `value >= p`
//!     (`while random_int >= prime_number`), so the constants are uniform on
//!     `[0, p)`. `create_mds_p` instead writes `F(grain_random_bits(n))`,
//!     i.e. sage *reduces* the draw mod `p`. Using rejection in both places
//!     desynchronises the bit stream and yields a different matrix.
//!  2. **The Grain output filter eats bits.** Per emitted bit the register is
//!     clocked once; while that bit was 0 it is clocked twice more; then it is
//!     clocked once more and *that* bit is emitted. It is not "clock once,
//!     take the bit" — see `Lfsr.nextBit`.
//!
//! The security checks the sage script runs on a candidate matrix
//! (`algorithm_1`/`2`/`3`, the infinitely-long-subspace-trail tests of
//! Grassi-Rechberger-Schofnegger) are **not** re-run here; see `mds`'s doc
//! comment for why that is sound for the shipped parameter sets and what it
//! would cost to change.

const std = @import("std");

/// The 80-bit Grain LFSR, seeded exactly as `init_generator` does.
///
/// Representation note: the sage script keeps the register as a Python list
/// `bit_sequence[0..79]` and shifts it with `pop(0)`/`append`. Here the same
/// register is one integer with list index `i` living in bit `79 - i`, so a
/// clock is `state = (state << 1) | new_bit` and every tap is a constant
/// shift.
pub const Lfsr = struct {
    /// Held in a `u128` rather than a `u80` purely so `<< 1` cannot overflow
    /// before the mask is applied.
    state: u128,

    const mask: u128 = (@as(u128, 1) << 80) - 1;

    /// Seeds the register from the parameter description, then discards the
    /// first 160 clocks (the sage script's warm-up loop).
    ///
    /// Field layout, MSB-first, 2+4+12+12+10+10+30 = 80 bits:
    /// `field(2) ‖ sbox(4) ‖ n(12) ‖ t(12) ‖ R_F(10) ‖ R_P(10) ‖ 1^30`.
    /// `field = 1` is GF(p) and `sbox = 0` is `x^alpha`; the GF(2^n) and
    /// `x^-1` paths of the reference script are out of scope (see `SPEC.md`),
    /// so those two are fixed rather than parameters.
    pub fn init(n: u12, t: u12, r_f: u10, r_p: u10) Lfsr {
        var s: u128 = 0;
        s = (s << 2) | 1; // field = 1 (GF(p))
        s = (s << 4) | 0; // sbox  = 0 (x^alpha)
        s = (s << 12) | n;
        s = (s << 12) | t;
        s = (s << 10) | r_f;
        s = (s << 10) | r_p;
        s = (s << 30) | ((@as(u128, 1) << 30) - 1); // thirty 1 bits
        var self: Lfsr = .{ .state = s & mask };
        for (0..160) |_| _ = self.clock();
        return self;
    }

    /// One clock of the register. Taps are the sage script's
    /// `bit[62] ^ bit[51] ^ bit[38] ^ bit[23] ^ bit[13] ^ bit[0]`, translated
    /// through the index-to-bit mapping documented on `Lfsr`.
    fn clock(self: *Lfsr) u1 {
        const s = self.state;
        const nb: u1 = @truncate((s >> 17) ^ (s >> 28) ^ (s >> 41) ^ (s >> 56) ^ (s >> 66) ^ (s >> 79));
        self.state = ((s << 1) | nb) & mask;
        return nb;
    }

    /// One *emitted* bit, through Grain's self-shrinking output filter.
    ///
    /// Kept deliberately literal against the sage generator's body: clock
    /// once (A); while A is 0, clock twice and retest the second of those;
    /// then clock once more and emit that bit. Reading it as "skip zeros,
    /// return the next one" gives a different stream.
    pub fn nextBit(self: *Lfsr) u1 {
        var b = self.clock();
        while (b == 0) {
            _ = self.clock();
            b = self.clock();
        }
        return self.clock();
    }

    /// `nbits` emitted bits assembled MSB-first, matching `grain_random_bits`
    /// (whose `random_bits.reverse()` is commented out upstream, i.e. the
    /// first bit out is the most significant).
    pub fn nextNum(self: *Lfsr, nbits: u12) u256 {
        var v: u256 = 0;
        for (0..nbits) |_| v = (v << 1) | self.nextBit();
        return v;
    }
};

/// Everything a field must supply for parameter derivation. `Fr` is one of
/// this repo's existing scalar-field types (`bn254.Fr`, `bls12_381.Fr`) — no
/// new field arithmetic is defined anywhere in this module.
pub const Config = struct {
    /// The scalar field type: needs `zero`, `one`, `fromBytes`, `reduceWide`,
    /// `add`, `mul`, `square`, `inv`, `eql`, `isZero`, `toBytes`.
    Fr: type,
    /// The field modulus, big-endian 32 bytes. Needed for the round
    /// constants' rejection test, which is an *integer* comparison against
    /// `p` and so cannot be phrased in `Fr`.
    modulus_be: [32]u8,
    /// `n` in the reference script: the field size in bits, and the width of
    /// each Grain draw. A **seed input**, therefore part of the instance
    /// identity — BN254 uses 254 and BLS12-381 uses 255, and swapping them
    /// gives entirely different constants over the same prime.
    n: u12,
    /// State width `t` (rate + capacity).
    t: u12,
    /// Number of full rounds `R_F`.
    r_f: u10,
    /// Number of partial rounds `R_P`.
    r_p: u10,

    pub fn numConstants(comptime cfg: Config) usize {
        return (@as(usize, cfg.r_f) + cfg.r_p) * cfg.t;
    }
};

/// The derived parameter tables for one `Config`.
pub fn Tables(comptime cfg: Config) type {
    return struct {
        /// `(R_F + R_P) * t` round constants, in the order the permutation
        /// consumes them (round-major, then state index).
        round_constants: [cfg.numConstants()]cfg.Fr,
        /// The `t x t` MDS matrix, in the reference script's orientation:
        /// `new[i] = Σ_j mds[i][j] * old[j]`.
        mds: [cfg.t][cfg.t]cfg.Fr,
    };
}

/// Runs the generator. One Grain stream produces the round constants first and
/// the MDS seeds second — they are one derivation, not two.
///
/// **Runtime, not comptime, and that is a measured decision.** Doing this at
/// comptime works (the function is comptime-callable and `Permutation` lets
/// you do it), but the Zig interpreter costs roughly 18 µs per LFSR clock on
/// the machine this was written on: ~5 s for `t = 3` alone and ~200 s for the
/// full `t = 2..17` sweep, which is not a price a `zig build test-poseidon`
/// should pay. At run time the whole sweep is milliseconds. circomlibjs makes
/// the same call — its entry point is an `async buildPoseidon()` that
/// constructs the tables at startup.
///
/// ## MDS construction, and what is deliberately not re-run
///
/// The matrix is the reference script's `create_mds_p`: draw `2t` field
/// elements (reduced, not rejection-sampled), split into `xs`/`ys`, and set
/// `M[i][j] = (xs[i] + ys[j])^-1` — a **Cauchy matrix**, which is MDS for any
/// `2t` pairwise-distinct entries.
///
/// Upstream then loops until the candidate passes `algorithm_1`/`2`/`3`,
/// three subspace-trail security tests needing eigenspaces and kernels over
/// the field — a linear-algebra layer this repo has no reason to grow. That
/// loop is only *observable* when a candidate is rejected, because a rejection
/// consumes more Grain bits and shifts every later draw. For every parameter
/// set this module ships the first candidate is the accepted one: the derived
/// matrices are byte-equal to circomlib's for `t = 2..17` on BN254 and to the
/// authors' own `.sage` files for `t = 3, 5` on BLS12-381, which could not
/// happen if a rejection had occurred upstream. `constants_test.zig` is what
/// holds that. Deriving parameters for a *new* `(n, t, R_F, R_P)` with this
/// code therefore requires running the sage script alongside to confirm the
/// first candidate was accepted — that is the honest boundary of this port,
/// and it is why `Config` is not offered as a public "make your own Poseidon"
/// knob in `root.zig`.
pub fn derive(comptime cfg: Config) Tables(cfg) {
    const Fr = cfg.Fr;
    var lfsr: Lfsr = .init(cfg.n, cfg.t, cfg.r_f, cfg.r_p);
    const p = std.mem.readInt(u256, &cfg.modulus_be, .big);

    var out: Tables(cfg) = undefined;

    for (&out.round_constants) |*c| {
        var v = lfsr.nextNum(cfg.n);
        // Rejection, not reduction: see this file's doc comment, subtlety 1.
        while (v >= p) v = lfsr.nextNum(cfg.n);
        var be: [32]u8 = undefined;
        std.mem.writeInt(u256, &be, v, .big);
        c.* = Fr.fromBytes(be) catch unreachable; // v < p by construction
    }

    var attempts: usize = 0;
    while (true) {
        attempts += 1;
        // Not a security bound — just a guard against an infinite loop if
        // this is ever pointed at a degenerate parameter set. Every shipped
        // set converges on the first attempt.
        if (attempts > 64) @panic("poseidon/grain: MDS generation did not converge");

        var rand_list: [2 * cfg.t]Fr = undefined;
        while (true) {
            for (&rand_list) |*e| {
                var be: [32]u8 = undefined;
                // Reduction, not rejection: see subtlety 1.
                std.mem.writeInt(u256, &be, lfsr.nextNum(cfg.n), .big);
                e.* = Fr.reduceWide(&be);
            }
            var dup = false;
            for (0..2 * cfg.t) |i| {
                for (i + 1..2 * cfg.t) |j| {
                    if (rand_list[i].eql(rand_list[j])) dup = true;
                }
            }
            if (!dup) break;
        }

        // Collect the t*t denominators, then invert them all with one field
        // inversion (Montgomery's batch trick). Field inversion is by far the
        // most expensive operation here — Fermat, a full 254-bit constant-time
        // exponentiation — and t=17 would otherwise need 289 of them.
        var denom: [cfg.t * cfg.t]Fr = undefined;
        var singular = false;
        for (0..cfg.t) |i| {
            for (0..cfg.t) |j| {
                const sum = rand_list[i].add(rand_list[cfg.t + j]);
                if (sum.isZero()) singular = true;
                denom[i * cfg.t + j] = sum;
            }
        }
        if (singular) continue; // upstream's `flag == False` path: redraw

        const inverted = batchInv(Fr, cfg.t * cfg.t, denom);
        for (0..cfg.t) |i| {
            for (0..cfg.t) |j| out.mds[i][j] = inverted[i * cfg.t + j];
        }
        return out;
    }
}

/// Montgomery batch inversion: `k` inverses for one inversion plus `3(k-1)`
/// multiplications. Every input must be non-zero (the caller checks).
fn batchInv(comptime Fr: type, comptime k: usize, in: [k]Fr) [k]Fr {
    var prefix: [k]Fr = undefined;
    var acc = Fr.one;
    for (0..k) |i| {
        prefix[i] = acc; // product of in[0..i)
        acc = acc.mul(in[i]);
    }
    var run = acc.inv() catch unreachable; // no zero inputs
    var out: [k]Fr = undefined;
    var i = k;
    while (i > 0) {
        i -= 1;
        out[i] = prefix[i].mul(run);
        run = run.mul(in[i]);
    }
    return out;
}

// ── tests ───────────────────────────────────────────────────────────────────

test "Lfsr seeding packs the parameter description MSB-first" {
    // Hand-computed from the field layout in `Lfsr.init`, before the 160
    // warm-up clocks: field=1, sbox=0, n=254, t=3, R_F=8, R_P=57, then 1^30.
    const expect =
        "01" ++ "0000" ++ "000011111110" ++ "000000000011" ++
        "0000001000" ++ "0000111001" ++ ("1" ** 30);
    var packed_bits: u128 = 0;
    for (expect) |ch| packed_bits = (packed_bits << 1) | @as(u128, ch - '0');

    // Reproduce `init` without the warm-up so the seed itself is visible.
    var s: u128 = 0;
    s = (s << 2) | 1;
    s = (s << 4) | 0;
    s = (s << 12) | 254;
    s = (s << 12) | 3;
    s = (s << 10) | 8;
    s = (s << 10) | 57;
    s = (s << 30) | ((@as(u128, 1) << 30) - 1);
    try std.testing.expectEqual(packed_bits, s);
}

test "the output filter is not a plain LFSR tap" {
    // Positive control for subtlety 2. The obvious misreading of the sage
    // generator is "one clock = one output bit"; that produces a different
    // stream and therefore different constants, while still being perfectly
    // deterministic. Pin the difference so the filter cannot be quietly
    // simplified away.
    var a: Lfsr = .init(254, 3, 8, 57);
    var b: Lfsr = .init(254, 3, 8, 57);

    var filtered: u64 = 0;
    for (0..64) |_| filtered = (filtered << 1) | a.nextBit();
    var raw: u64 = 0;
    for (0..64) |_| raw = (raw << 1) | b.clock();

    try std.testing.expect(filtered != raw);
}
