// SPDX-License-Identifier: MIT

//! generators — deterministic (nothing-up-my-sleeve, NUMS) generator points
//! for Bulletproofs range proofs over Ristretto255 (`std.crypto.ecc
//! .Ristretto255`).
//!
//! **REAL — not a Fable stub.** Bulletproofs (Bünz, Bootle, Boneh,
//! Poelstra, Wuille, Maxwell, "Bulletproofs: Short Proofs for Confidential
//! Transactions and More", IEEE S&P 2018) needs, for an `n`-bit range
//! proof: two base points `G`, `H`, and two length-`n` vectors of
//! independent generators `G_vec`, `H_vec` (§4.1's range-proof commitment
//! `A = alpha*H + <a_L, G_vec> + <a_R, H_vec>`, and §3's Inner-Product
//! Argument reuses `G_vec`/`H_vec` directly). "Independent" means: no
//! party — including the prover — may know a discrete-log relation
//! between any two of these points; if it did, it could forge a range
//! proof for an out-of-range value (that is exactly what the Pedersen
//! commitment's binding property rests on). The standard way to get that
//! property without a trusted setup is a NUMS construction: derive every
//! point deterministically from a public label via a hash-to-curve map, so
//! nobody can have chosen it to hide a known relation.
//!
//! ## Construction
//!
//! `SHA-512(domain || label || suffix)` -> 64 bytes ->
//! `Ristretto255.fromUniform` (the Elligator2-based one-way map RFC 9496
//! §4.3.4 specifies for ristretto255 — the sibling `voprf` module's
//! `root.zig` doc comment documents the identical primitive backing RFC
//! 9497's `HashToGroup`). `fromUniform` only requires uniformly-random-
//! looking INPUT bytes; since there is no cross-implementation KAT this
//! module's generators need to hit (see `transcript.zig`'s "no dalek
//! byte-compatibility" note — the same reasoning applies here: every
//! Bulletproofs implementation picks its own generator-derivation scheme),
//! a plain domain-separated `SHA-512(label)` is exactly as sound as a more
//! elaborate XOF-based chain, and simpler to implement and audit.
//!
//! dalek's `bulletproofs` crate derives its own generators in the same
//! SPIRIT (a `GeneratorsChain` seeded from a fixed label, read through
//! `RistrettoPoint::from_uniform_bytes` — see its `generators.rs`) — cited
//! here as a design reference for the SHAPE (two base points + two
//! per-index vectors, NUMS-derived, no trusted setup), not for the exact
//! hash construction (dalek's chain runs a SHAKE256 XOF; this module uses
//! fixed-label SHA-512 per point instead, deliberately simpler since no
//! cross-implementation byte-exactness is a goal — see SPEC.md and NOTICE).

const std = @import("std");
const Ristretto255 = std.crypto.ecc.Ristretto255;
const Sha512 = std.crypto.hash.sha2.Sha512;

/// Domain-separation prefix for every generator this module derives.
/// Bumping this string to a "v2" value would silently repoint EVERY
/// commitment made under "v1" onto different, unrelated points — a
/// deliberate versioning seam, the same discipline this repo's
/// `threshold_ecdsa` module documents for its own `pi_mod_domain`/
/// `pi_prm_domain` tags.
pub const domain = "zig-libs/bulletproofs/generators/v1";

/// `SHA-512(domain || label || suffix)` -> `Ristretto255.fromUniform`.
/// Ordinary hashing plus the std NUMS map — no secret-dependent branching,
/// no "irreducible" cryptographic judgment.
fn hashToPoint(label: []const u8, suffix: []const u8) Ristretto255 {
    var h = Sha512.init(.{});
    h.update(domain);
    h.update(label);
    h.update(suffix);
    var wide: [64]u8 = undefined;
    h.final(&wide);
    return Ristretto255.fromUniform(wide);
}

/// One deterministically-derived generator with no index suffix — used for
/// the two BASE points `g`/`h` (see `Generators.init`).
fn basePointFor(label: []const u8) Ristretto255 {
    return hashToPoint(label, &.{});
}

/// The `i`-th deterministically-derived vector generator: `hashToPoint
/// (label, index_LE64(i))`. `i` is encoded little-endian, matching
/// `std.crypto.ecc.Ristretto255.scalar`'s own byte order convention used
/// throughout this module.
fn vectorPointFor(label: []const u8, i: usize) Ristretto255 {
    var suffix: [8]u8 = undefined;
    std.mem.writeInt(u64, &suffix, @intCast(i), .little);
    return hashToPoint(label, &suffix);
}

/// The full generator set an `n`-bit range proof needs: two base points
/// `g`/`h` (the value commitment `V = v*g + gamma*h`, and the range
/// proof's own `T1`/`T2` commitments — see `rangeproof.zig`) plus
/// length-`n` vectors `g_vec`/`h_vec` (the vector Pedersen commitments `A`/
/// `S`, and the Inner-Product Argument's own generators, see `ipa.zig`).
pub const Generators = struct {
    g: Ristretto255,
    h: Ristretto255,
    g_vec: []Ristretto255,
    h_vec: []Ristretto255,
    n: usize,

    /// Derives a fresh `n`-wide generator set. `g_vec`/`h_vec` are
    /// allocated via `allocator` (freed by `deinit`). Every point is
    /// INDEPENDENTLY re-derivable from `(domain, label, i)` alone — no
    /// randomness, no shared mutable state — so two callers (e.g. a
    /// prover and a verifier in different processes) that call `init`
    /// with the same `n` always get byte-identical generators, which is
    /// the entire point of a NUMS construction: neither party need
    /// transmit or trust the other's copy.
    pub fn init(allocator: std.mem.Allocator, n: usize) std.mem.Allocator.Error!Generators {
        const g_vec = try allocator.alloc(Ristretto255, n);
        errdefer allocator.free(g_vec);
        const h_vec = try allocator.alloc(Ristretto255, n);
        errdefer allocator.free(h_vec);
        for (g_vec, 0..) |*p, i| p.* = vectorPointFor("G", i);
        for (h_vec, 0..) |*p, i| p.* = vectorPointFor("H", i);
        return .{
            .g = basePointFor("g"),
            .h = basePointFor("h"),
            .g_vec = g_vec,
            .h_vec = h_vec,
            .n = n,
        };
    }

    pub fn deinit(self: Generators, allocator: std.mem.Allocator) void {
        allocator.free(self.g_vec);
        allocator.free(self.h_vec);
    }
};

// ── tests ─────────────────────────────────────────────────────────────────

test "init is deterministic: two independent derivations agree byte-exact" {
    const gens1 = try Generators.init(std.testing.allocator, 8);
    defer gens1.deinit(std.testing.allocator);
    const gens2 = try Generators.init(std.testing.allocator, 8);
    defer gens2.deinit(std.testing.allocator);

    try std.testing.expectEqualSlices(u8, &gens1.g.toBytes(), &gens2.g.toBytes());
    try std.testing.expectEqualSlices(u8, &gens1.h.toBytes(), &gens2.h.toBytes());
    for (gens1.g_vec, gens2.g_vec) |a, b| try std.testing.expectEqualSlices(u8, &a.toBytes(), &b.toBytes());
    for (gens1.h_vec, gens2.h_vec) |a, b| try std.testing.expectEqualSlices(u8, &a.toBytes(), &b.toBytes());
}

test "g and h are distinct, non-identity points" {
    const gens = try Generators.init(std.testing.allocator, 4);
    defer gens.deinit(std.testing.allocator);
    try std.testing.expect(!gens.g.equivalent(gens.h));
    try gens.g.rejectIdentity();
    try gens.h.rejectIdentity();
}

test "every g_vec/h_vec entry is pairwise distinct and non-identity" {
    const n = 16;
    const gens = try Generators.init(std.testing.allocator, n);
    defer gens.deinit(std.testing.allocator);

    var all = std.ArrayList(Ristretto255).empty;
    defer all.deinit(std.testing.allocator);
    try all.append(std.testing.allocator, gens.g);
    try all.append(std.testing.allocator, gens.h);
    try all.appendSlice(std.testing.allocator, gens.g_vec);
    try all.appendSlice(std.testing.allocator, gens.h_vec);

    for (all.items) |p| try p.rejectIdentity();

    for (all.items, 0..) |a, i| {
        for (all.items[i + 1 ..]) |b| {
            try std.testing.expect(!a.equivalent(b));
        }
    }
}

test "different n values still agree on the shared prefix" {
    const small = try Generators.init(std.testing.allocator, 4);
    defer small.deinit(std.testing.allocator);
    const big = try Generators.init(std.testing.allocator, 8);
    defer big.deinit(std.testing.allocator);

    try std.testing.expectEqualSlices(u8, &small.g.toBytes(), &big.g.toBytes());
    try std.testing.expectEqualSlices(u8, &small.h.toBytes(), &big.h.toBytes());
    for (small.g_vec, big.g_vec[0..small.n]) |a, b| try std.testing.expectEqualSlices(u8, &a.toBytes(), &b.toBytes());
    for (small.h_vec, big.h_vec[0..small.n]) |a, b| try std.testing.expectEqualSlices(u8, &a.toBytes(), &b.toBytes());
}

test "n = 0 gives empty vectors without error" {
    const gens = try Generators.init(std.testing.allocator, 0);
    defer gens.deinit(std.testing.allocator);
    try std.testing.expectEqual(@as(usize, 0), gens.g_vec.len);
    try std.testing.expectEqual(@as(usize, 0), gens.h_vec.len);
}
