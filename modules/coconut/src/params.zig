// SPDX-License-Identifier: MIT

//! params — Coconut system parameters over the `bls12_381` type-3 pairing
//! (Sonnino-Bano-Al-Bassam-Danezis, NDSS 2019, §4.1 `Setup`). For a fixed
//! attribute count `q` the parameters are the pairing group generators
//! (`g1 ∈ G1`, `g2 ∈ G2` — the curve's canonical generators, constants
//! from `bls12_381`) plus a vector of independent attribute generators
//! `hs = (h₁, …, h_q) ∈ G1`, derived deterministically by hashing an
//! index tag to the curve (RFC 9380 `hashToCurveG1`). The `hs` are what a
//! Coconut attribute commitment `cm = Σ [mᵢ] hᵢ` is built over; the
//! common signing base of a credential is then `h = hashToCurveG1(cm)`,
//! so every threshold authority derives the SAME `h` from the same public
//! commitment (this is what makes the partial signatures Lagrange-
//! aggregatable — they share a base point).
//!
//! Everything here is mechanical and REAL: no gated core. The `hs` are
//! nothing-up-my-sleeve (hash of a fixed domain-separated tag), on-curve
//! and in the prime-order subgroup by construction of `hashToCurveG1`.

const std = @import("std");
const bls = @import("bls12_381");

const g1 = bls.g1;
const g2 = bls.g2;
const Fr = bls.Fr;

/// DST for the attribute generators `hᵢ` (RFC 9380 `hash_to_curve` DST).
pub const gen_dst = "COCONUT-BLS12381G1_XMD:SHA-256_SSWU_RO_ATTRGEN_";
/// DST for the per-credential common base `h = hashToCurveG1(cm)`.
pub const base_dst = "COCONUT-BLS12381G1_XMD:SHA-256_SSWU_RO_CMBASE_";

pub const ParamsError = error{
    /// `q == 0` — a credential needs at least one attribute.
    NoAttributes,
} || std.mem.Allocator.Error;

/// Coconut public parameters for `q` attributes. `hs` is heap-owned;
/// call `deinit`. `g1`/`g2` bases are the `bls12_381` canonical
/// generators, referenced via `g1Base()`/`g2Base()`.
pub const Parameters = struct {
    q: usize,
    hs: []g1.Affine,

    /// §4.1 `Setup(1^λ, q)`: derive the `q` attribute generators. Real.
    pub fn generate(allocator: std.mem.Allocator, q: usize) ParamsError!Parameters {
        if (q == 0) return error.NoAttributes;
        const hs = try allocator.alloc(g1.Affine, q);
        errdefer allocator.free(hs);
        for (hs, 0..) |*h, i| {
            var tag: [8]u8 = undefined;
            std.mem.writeInt(u64, &tag, @as(u64, i), .big);
            h.* = bls.hash_to_curve.hashToCurveG1(&tag, gen_dst);
        }
        return .{ .q = q, .hs = hs };
    }

    pub fn deinit(self: Parameters, allocator: std.mem.Allocator) void {
        allocator.free(self.hs);
    }

    /// The canonical `G1` generator `g1`.
    pub fn g1Base() g1.Affine {
        return g1.Affine.generator;
    }

    /// The canonical `G2` generator `g2`.
    pub fn g2Base() g2.Affine {
        return g2.Affine.generator;
    }

    /// The Pedersen-style attribute commitment `cm = Σ [mᵢ] hᵢ ∈ G1` over
    /// the attribute scalars (public-attribute path; the blind-issuance
    /// ElGamal path — deferred, see SPEC — would additionally blind this
    /// with a `[o] g1` term). REAL, mechanical.
    pub fn commitAttributes(self: Parameters, attributes: []const Fr) g1.Jacobian {
        std.debug.assert(attributes.len == self.q);
        var acc = g1.Jacobian.identity;
        for (self.hs, attributes) |h, m| {
            acc = acc.add(g1.Jacobian.fromAffine(h).scalarMul(m));
        }
        return acc;
    }

    /// The common signing base `h = hashToCurveG1(cm)` every authority
    /// derives from the public commitment — the shared base point that
    /// makes the partial PS signatures Lagrange-aggregatable. REAL.
    pub fn commonBase(self: Parameters, attributes: []const Fr) g1.Affine {
        const cm = self.commitAttributes(attributes).toAffine();
        const cm_bytes = g1.toBytesCompressed(cm);
        return bls.hash_to_curve.hashToCurveG1(&cm_bytes, base_dst);
    }
};

test "params: generators are distinct, on-curve, and in the prime-order subgroup" {
    const allocator = std.testing.allocator;
    const p = try Parameters.generate(allocator, 4);
    defer p.deinit(allocator);
    try std.testing.expectEqual(@as(usize, 4), p.hs.len);
    for (p.hs, 0..) |h, i| {
        const j = g1.Jacobian.fromAffine(h);
        try std.testing.expect(j.isOnCurve());
        try std.testing.expect(j.subgroupCheck());
        for (p.hs[i + 1 ..]) |h2| {
            try std.testing.expect(!(h.x.eql(h2.x) and h.y.eql(h2.y)));
        }
    }
}

test "params: commonBase is deterministic + attribute-sensitive; rejects q=0" {
    const allocator = std.testing.allocator;
    const p = try Parameters.generate(allocator, 2);
    defer p.deinit(allocator);
    const a = [_]Fr{ frOf(11), frOf(22) };
    const b = [_]Fr{ frOf(11), frOf(23) };
    const ha1 = p.commonBase(&a);
    const ha2 = p.commonBase(&a);
    const hb = p.commonBase(&b);
    try std.testing.expect(ha1.x.eql(ha2.x) and ha1.y.eql(ha2.y)); // deterministic
    try std.testing.expect(!(ha1.x.eql(hb.x) and ha1.y.eql(hb.y))); // changes with attrs
    try std.testing.expectError(error.NoAttributes, Parameters.generate(allocator, 0));
}

fn frOf(v: u64) Fr {
    var buf: [32]u8 = [_]u8{0} ** 32;
    std.mem.writeInt(u64, buf[24..32], v, .big);
    return Fr.fromBytes(buf) catch unreachable;
}
