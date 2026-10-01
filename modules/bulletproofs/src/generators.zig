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
//! ## Construction — dalek's (`bulletproofs` 4.0 `src/generators.rs`)
//!
//! - `g` (dalek `PedersenGens::B`): the Ristretto255 base point.
//! - `h` (dalek `PedersenGens::B_blinding`):
//!   `fromUniform(SHA3-512(encode(g)))` — dalek's
//!   `RistrettoPoint::hash_from_bytes::<Sha3_512>` of the compressed base
//!   point.
//! - `g_vec` / `h_vec` (dalek `BulletproofGens` party 0): one SHAKE256 XOF
//!   per vector, absorbing `"GeneratorsChain" || label` with
//!   `label = 'G' || LE32(0)` resp. `'H' || LE32(0)`; each generator is
//!   `fromUniform` of the next 64 squeezed bytes. The chain is one stream,
//!   so a larger `n` extends a smaller one (the shared-prefix test below).
//!
//! `fromUniform` is RFC 9496 §4.3.4's one-way map, the same function as
//! dalek's `RistrettoPoint::from_uniform_bytes`. Until 2026-09-30 the points
//! came from a module-defined SHA-512 construction; they were moved to
//! dalek's so that proofs interoperate (`interop_test.zig` pins them against
//! values printed by the crate itself).
//!
//! An aggregated proof over `m` values (`rangeproof.proveMultiple`) gives
//! value `j` its own pair of chains, `'G' || LE32(j)` and `'H' || LE32(j)`
//! (dalek's `BulletproofGens` party `j`), and concatenates them party by
//! party: `g_vec[j*n + i]` is party `j`'s `i`-th generator (dalek's
//! `BulletproofGens::G(n, m)` order). `Generators.initParties` builds that;
//! `init` is its one-party case.

const std = @import("std");
const Ristretto255 = std.crypto.ecc.Ristretto255;
const Sha3_512 = std.crypto.hash.sha3.Sha3_512;
const Shake256 = std.crypto.hash.sha3.Shake256;

/// dalek's `GeneratorsChain`: SHAKE256 over `"GeneratorsChain" || label`,
/// read 64 bytes per point.
const GeneratorsChain = struct {
    xof: Shake256,

    fn init(label: []const u8) GeneratorsChain {
        var xof = Shake256.init(.{});
        xof.update("GeneratorsChain");
        xof.update(label);
        return .{ .xof = xof };
    }

    fn next(self: *GeneratorsChain) Ristretto255 {
        var wide: [64]u8 = undefined;
        self.xof.squeeze(&wide);
        return Ristretto255.fromUniform(wide);
    }
};

/// Party `party`'s chain label: the tag byte, then the index as LE32.
fn chainLabel(tag: u8, party: u32) [5]u8 {
    var label: [5]u8 = undefined;
    label[0] = tag;
    std.mem.writeInt(u32, label[1..5], party, .little);
    return label;
}

/// dalek's `PedersenGens::default().B_blinding`.
fn blindingBase() Ristretto255 {
    var wide: [64]u8 = undefined;
    Sha3_512.hash(&Ristretto255.basePoint.toBytes(), &wide, .{});
    return Ristretto255.fromUniform(wide);
}

/// The full generator set an `n`-bit range proof needs: two base points
/// `g`/`h` (the value commitment `V = v*g + gamma*h`, and the range
/// proof's own `T1`/`T2` commitments — see `rangeproof.zig`) plus
/// length-`n * parties` vectors `g_vec`/`h_vec` (the vector Pedersen
/// commitments `A`/`S`, and the Inner-Product Argument's own generators, see
/// `ipa.zig`), party-major (module doc comment).
pub const Generators = struct {
    g: Ristretto255,
    h: Ristretto255,
    g_vec: []Ristretto255,
    h_vec: []Ristretto255,
    /// Bits per value.
    n: usize,
    /// How many values one aggregated proof over this set may carry
    /// (dalek's `party_capacity`). A proof over `m <= parties` values uses
    /// the first `n * m` entries of each vector.
    parties: usize = 1,

    /// Derives a fresh `n`-wide generator set. `g_vec`/`h_vec` are
    /// allocated via `allocator` (freed by `deinit`). Every point is
    /// INDEPENDENTLY re-derivable from the fixed chain labels alone — no
    /// randomness, no shared mutable state — so two callers (e.g. a
    /// prover and a verifier in different processes) that call `init`
    /// with the same `n` always get byte-identical generators, which is
    /// the entire point of a NUMS construction: neither party need
    /// transmit or trust the other's copy.
    pub fn init(allocator: std.mem.Allocator, n: usize) std.mem.Allocator.Error!Generators {
        return initParties(allocator, n, 1);
    }

    /// `init` for aggregated proofs of up to `parties` values: party `j`'s
    /// `n` generators come from its own chains and sit at `j*n ..
    /// (j+1)*n`. Party 0 is exactly `init(n)`'s set, so a single-value
    /// proof verifies over either.
    pub fn initParties(allocator: std.mem.Allocator, n: usize, parties: usize) std.mem.Allocator.Error!Generators {
        const len = std.math.mul(usize, n, parties) catch return error.OutOfMemory;
        const g_vec = try allocator.alloc(Ristretto255, len);
        errdefer allocator.free(g_vec);
        const h_vec = try allocator.alloc(Ristretto255, len);
        errdefer allocator.free(h_vec);
        for (0..parties) |j| {
            const party: u32 = std.math.cast(u32, j) orelse return error.OutOfMemory;
            var g_chain = GeneratorsChain.init(&chainLabel('G', party));
            for (g_vec[j * n ..][0..n]) |*p| p.* = g_chain.next();
            var h_chain = GeneratorsChain.init(&chainLabel('H', party));
            for (h_vec[j * n ..][0..n]) |*p| p.* = h_chain.next();
        }
        return .{
            .g = Ristretto255.basePoint,
            .h = blindingBase(),
            .g_vec = g_vec,
            .h_vec = h_vec,
            .n = n,
            .parties = parties,
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

// B7 (A1 audit) asked for a value-level KAT here, because every test above
// only checks relations. The values are now dalek's and are pinned against
// the crate's own output in `interop_test.zig`.

test "initParties: party 0 is init's set, each further party its own chain" {
    const one = try Generators.init(std.testing.allocator, 8);
    defer one.deinit(std.testing.allocator);
    const four = try Generators.initParties(std.testing.allocator, 8, 4);
    defer four.deinit(std.testing.allocator);
    try std.testing.expectEqual(@as(usize, 32), four.g_vec.len);
    try std.testing.expectEqual(@as(usize, 32), four.h_vec.len);
    for (one.g_vec, four.g_vec[0..8]) |a, b| try std.testing.expect(a.equivalent(b));
    for (one.h_vec, four.h_vec[0..8]) |a, b| try std.testing.expect(a.equivalent(b));

    // Party 2's first G is the first point of chain 'G' || LE32(2), derived
    // here by hand rather than through `initParties`.
    var xof = Shake256.init(.{});
    xof.update("GeneratorsChain");
    xof.update(&[_]u8{ 'G', 2, 0, 0, 0 });
    var wide: [64]u8 = undefined;
    xof.squeeze(&wide);
    try std.testing.expect(Ristretto255.fromUniform(wide).equivalent(four.g_vec[16]));

    // No point repeats across parties.
    for (four.g_vec, 0..) |a, i| {
        for (four.g_vec[i + 1 ..]) |b| try std.testing.expect(!a.equivalent(b));
        for (four.h_vec) |b| try std.testing.expect(!a.equivalent(b));
    }
}

test "n = 0 gives empty vectors without error" {
    const gens = try Generators.init(std.testing.allocator, 0);
    defer gens.deinit(std.testing.allocator);
    try std.testing.expectEqual(@as(usize, 0), gens.g_vec.len);
    try std.testing.expectEqual(@as(usize, 0), gens.h_vec.len);
}
