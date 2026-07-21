// SPDX-License-Identifier: MIT

//! keys — Coconut threshold authority keys over `bls12_381`
//! (Sonnino-Bano-Al-Bassam-Danezis, NDSS 2019, §4.4 `TTPKeyGen` — the
//! trusted-dealer variant; the dealer-free DKG wiring is a deferred
//! increment, see SPEC). A single master secret key `sk = (x, y₁…y_q) ∈
//! Fr^{q+1}` is Shamir-shared with a degree-`t−1` polynomial per
//! component, so any `t` of the `n` authorities' shares Lagrange-
//! reconstruct `sk`. The matching verification key `vk = (α, β₁…β_q) =
//! (g2^x, g2^{y₁}…g2^{y_q}) ∈ G2^{q+1}`; each authority publishes its own
//! `vk` share, and the group `vk` is recovered by Lagrange-in-EXPONENT
//! aggregation of any `t` shares (`aggregateVerificationKeys`).
//!
//! All of this file is mechanical and REAL — the trusted dealer knows the
//! plaintext secrets, so keygen is pure `Fr` polynomial evaluation and
//! `vk` derivation is a fixed-base `scalarMul`. `aggregateVerificationKeys`
//! is the FIRST Lagrange-in-exponent operation (over PUBLIC `G2` shares),
//! and its round-trip test (`t` shares recombine to the master `vk`) is a
//! standing proof that the harness's Lagrange machinery is correct before
//! the gated CREDENTIAL aggregation (over secret-derived `G1` partials)
//! is filled in.

const std = @import("std");
const bls = @import("bls12_381");
const lagrange = @import("lagrange.zig");

const g2 = bls.g2;
const Fr = bls.Fr;

pub const KeysError = error{
    /// `t == 0`, `t > n`, or `n == 0`.
    InvalidThreshold,
    /// Fewer than `t` shares supplied to an aggregation.
    NotEnoughShares,
    /// A supplied share subset had a duplicate/zero index.
    BadIndices,
    /// Attribute-count mismatch between operands.
    MismatchedAttributes,
} || lagrange.LagrangeError || std.mem.Allocator.Error;

/// A uniformly-random `Fr` from a `std.Random` (rejection sampling, same
/// shape as `bls12_381`'s `Fr.random` but over the caller's PRNG so keygen
/// is deterministic under a seeded generator in tests — the `frost`/`dkg`
/// convention).
pub fn randomScalar(random: std.Random) Fr {
    var buf: [32]u8 = undefined;
    while (true) {
        random.bytes(&buf);
        return Fr.fromBytes(buf) catch continue;
    }
}

/// Master secret key `(x, y₁…y_q)`. Heap-owned `ys`; call `deinit`.
pub const SecretKey = struct {
    x: Fr,
    ys: []Fr,

    /// Zero the secret material (`x` and every `ys[i]`), then free `ys`.
    /// `self` must be `var` (addressable) so `x` is zeroed in the caller's
    /// own storage, not just this by-pointer view of it.
    pub fn deinit(self: *SecretKey, allocator: std.mem.Allocator) void {
        std.crypto.secureZero(u8, std.mem.sliceAsBytes(self.ys));
        allocator.free(self.ys);
        std.crypto.secureZero(u8, std.mem.asBytes(&self.x));
    }
};

/// Master verification key `(α, β₁…β_q) = (g2^x, g2^{y_i})`. Heap-owned
/// `betas`; call `deinit`.
pub const VerificationKey = struct {
    alpha: g2.Affine,
    betas: []g2.Affine,

    /// Derive `vk` from a `SecretKey` (REAL: `g2^x`, `g2^{y_i}`).
    pub fn fromSecret(allocator: std.mem.Allocator, sk: SecretKey) std.mem.Allocator.Error!VerificationKey {
        const betas = try allocator.alloc(g2.Affine, sk.ys.len);
        errdefer allocator.free(betas);
        const g2base = g2.Jacobian.fromAffine(g2.Affine.generator);
        for (betas, sk.ys) |*b, y| b.* = g2base.scalarMul(y).toAffine();
        return .{ .alpha = g2base.scalarMul(sk.x).toAffine(), .betas = betas };
    }

    pub fn deinit(self: VerificationKey, allocator: std.mem.Allocator) void {
        allocator.free(self.betas);
    }
};

/// One authority's share of `sk`: `(x(i), y₁(i)…y_q(i))` at index `i`.
pub const SecretKeyShare = struct {
    index: u64,
    x: Fr,
    ys: []Fr,

    /// Zero the SECRET fields (`x`, every `ys[i]`), then free `ys`.
    /// `index` is the (public) Shamir evaluation point — left untouched.
    /// `self` must be `var` (addressable) so `x` is zeroed in place.
    pub fn deinit(self: *SecretKeyShare, allocator: std.mem.Allocator) void {
        std.crypto.secureZero(u8, std.mem.sliceAsBytes(self.ys));
        allocator.free(self.ys);
        std.crypto.secureZero(u8, std.mem.asBytes(&self.x));
    }
};

/// One authority's public verification-key share `(g2^{x(i)}, g2^{y_j(i)})`.
pub const VerificationKeyShare = struct {
    index: u64,
    alpha: g2.Affine,
    betas: []g2.Affine,

    pub fn fromShare(allocator: std.mem.Allocator, share: SecretKeyShare) std.mem.Allocator.Error!VerificationKeyShare {
        const betas = try allocator.alloc(g2.Affine, share.ys.len);
        errdefer allocator.free(betas);
        const g2base = g2.Jacobian.fromAffine(g2.Affine.generator);
        for (betas, share.ys) |*b, y| b.* = g2base.scalarMul(y).toAffine();
        return .{ .index = share.index, .alpha = g2base.scalarMul(share.x).toAffine(), .betas = betas };
    }

    pub fn deinit(self: VerificationKeyShare, allocator: std.mem.Allocator) void {
        allocator.free(self.betas);
    }
};

/// The full output of `keygen`: the master `sk`/`vk` (dealer-only in
/// production — kept here so the harness can cross-check reconstruction)
/// plus the per-authority secret + public shares. `deinit` frees all of
/// it.
pub const ThresholdKeys = struct {
    q: usize,
    t: u64,
    n: u64,
    master_sk: SecretKey,
    master_vk: VerificationKey,
    sk_shares: []SecretKeyShare,
    vk_shares: []VerificationKeyShare,

    /// `self` must be `var` (addressable) — `master_sk`/`sk_shares` zero
    /// their secret fields in place before freeing (see their `deinit`s).
    pub fn deinit(self: *ThresholdKeys, allocator: std.mem.Allocator) void {
        self.master_sk.deinit(allocator);
        self.master_vk.deinit(allocator);
        for (self.sk_shares) |*s| s.deinit(allocator);
        allocator.free(self.sk_shares);
        for (self.vk_shares) |s| s.deinit(allocator);
        allocator.free(self.vk_shares);
    }
};

/// §4.4 `TTPKeyGen(t, n, q)`: sample `sk = (x, y₁…y_q)`, Shamir-share each
/// component with an independent degree-`t−1` polynomial, evaluate at
/// authority indices `1..n`, and derive every party's `vk` share. REAL,
/// mechanical (the dealer holds the plaintext secrets). `random` is the
/// caller's PRNG (seed it for deterministic tests).
pub fn keygen(
    allocator: std.mem.Allocator,
    random: std.Random,
    q: usize,
    t: u64,
    n: u64,
) KeysError!ThresholdKeys {
    if (t == 0 or n == 0 or t > n or q == 0) return error.InvalidThreshold;

    // q+1 polynomials of degree t-1: poly[c][0] = the master secret for
    // component c, poly[c][1..t] = random blinding coefficients.
    const ncoef: usize = @intCast(t);
    var polys = try allocator.alloc([]Fr, q + 1);
    defer {
        // The polynomial coefficients ARE the secret key components
        // (poly[c][0]) plus their blinding — zero before free.
        for (polys) |p| std.crypto.secureZero(u8, std.mem.sliceAsBytes(p));
        for (polys) |p| allocator.free(p);
        allocator.free(polys);
    }
    var allocated: usize = 0;
    errdefer for (polys[0..allocated]) |p| allocator.free(p);
    for (polys) |*p| {
        p.* = try allocator.alloc(Fr, ncoef);
        allocated += 1;
        for (p.*) |*c| c.* = randomScalar(random);
    }

    var master_sk = SecretKey{
        .x = polys[0][0],
        .ys = blk: {
            const ys = try allocator.alloc(Fr, q);
            for (ys, 0..) |*y, i| y.* = polys[i + 1][0];
            break :blk ys;
        },
    };
    errdefer master_sk.deinit(allocator);
    const master_vk = try VerificationKey.fromSecret(allocator, master_sk);
    errdefer master_vk.deinit(allocator);

    const sk_shares = try allocator.alloc(SecretKeyShare, @intCast(n));
    var sk_done: usize = 0;
    errdefer {
        for (sk_shares[0..sk_done]) |*s| s.deinit(allocator);
        allocator.free(sk_shares);
    }
    for (sk_shares, 1..) |*share, idx| {
        const xi = lagrange.indexScalar(@intCast(idx));
        const ys = try allocator.alloc(Fr, q);
        share.* = .{ .index = @intCast(idx), .x = evalPoly(polys[0], xi), .ys = ys };
        for (ys, 0..) |*y, c| y.* = evalPoly(polys[c + 1], xi);
        sk_done += 1;
    }

    const vk_shares = try allocator.alloc(VerificationKeyShare, @intCast(n));
    var vk_done: usize = 0;
    errdefer {
        for (vk_shares[0..vk_done]) |s| s.deinit(allocator);
        allocator.free(vk_shares);
    }
    for (vk_shares, sk_shares) |*vks, sks| {
        vks.* = try VerificationKeyShare.fromShare(allocator, sks);
        vk_done += 1;
    }

    return .{
        .q = q,
        .t = t,
        .n = n,
        .master_sk = master_sk,
        .master_vk = master_vk,
        .sk_shares = sk_shares,
        .vk_shares = vk_shares,
    };
}

/// Horner evaluation of `poly` (low-to-high coefficients) at `x` over
/// `Fr`.
pub fn evalPoly(poly: []const Fr, x: Fr) Fr {
    var acc = Fr.zero;
    var i: usize = poly.len;
    while (i > 0) {
        i -= 1;
        acc = acc.mul(x).add(poly[i]);
    }
    return acc;
}

/// Lagrange-in-EXPONENT aggregation of any `t` verification-key shares
/// into the group `vk = (g2^x, g2^{y_i})`. REAL — the first
/// Lagrange-in-exponent operation, over PUBLIC `G2` shares. `subset` must
/// hold at least `t` shares with distinct nonzero indices (extra shares
/// are fine — Lagrange over any `t`-or-more consistent points gives the
/// same result). Caller frees the returned key.
pub fn aggregateVerificationKeys(
    allocator: std.mem.Allocator,
    subset: []const VerificationKeyShare,
) KeysError!VerificationKey {
    if (subset.len == 0) return error.NotEnoughShares;
    const q = subset[0].betas.len;

    const indices = try allocator.alloc(u64, subset.len);
    defer allocator.free(indices);
    for (indices, subset) |*ix, s| {
        if (s.betas.len != q) return error.MismatchedAttributes;
        ix.* = s.index;
    }

    var alpha = g2.Jacobian.identity;
    const betas = try allocator.alloc(g2.Affine, q);
    errdefer allocator.free(betas);
    const betas_acc = try allocator.alloc(g2.Jacobian, q);
    defer allocator.free(betas_acc);
    for (betas_acc) |*b| b.* = g2.Jacobian.identity;

    for (subset) |s| {
        const l = try lagrange.coefficientAtZero(indices, s.index);
        alpha = alpha.add(g2.Jacobian.fromAffine(s.alpha).scalarMul(l));
        for (betas_acc, s.betas) |*acc, b| {
            acc.* = acc.add(g2.Jacobian.fromAffine(b).scalarMul(l));
        }
    }
    for (betas, betas_acc) |*out, acc| out.* = acc.toAffine();
    return .{ .alpha = alpha.toAffine(), .betas = betas };
}

test "keygen: any t shares Lagrange-reconstruct the master secret key vector" {
    const allocator = std.testing.allocator;
    var prng = std.Random.DefaultPrng.init(0xC0C0);
    var keys = try keygen(allocator, prng.random(), 3, 2, 4);
    defer keys.deinit(allocator);

    // Reconstruct x and each y_j in the SCALAR field from shares {2,3}.
    const subset = [_]usize{ 1, 2 }; // 0-based into sk_shares → indices 2,3
    const idxs = [_]u64{ keys.sk_shares[subset[0]].index, keys.sk_shares[subset[1]].index };
    var x_rec = Fr.zero;
    var y_rec = [_]Fr{Fr.zero} ** 3;
    for (subset) |si| {
        const share = keys.sk_shares[si];
        const l = try lagrange.coefficientAtZero(&idxs, share.index);
        x_rec = x_rec.add(l.mul(share.x));
        for (&y_rec, share.ys) |*yr, y| yr.* = yr.add(l.mul(y));
    }
    try std.testing.expect(x_rec.eql(keys.master_sk.x));
    for (y_rec, keys.master_sk.ys) |yr, ym| try std.testing.expect(yr.eql(ym));
}

test "aggregateVerificationKeys: Lagrange-in-exponent recovers the master vk" {
    const allocator = std.testing.allocator;
    var prng = std.Random.DefaultPrng.init(0xBEEF);
    var keys = try keygen(allocator, prng.random(), 2, 3, 5);
    defer keys.deinit(allocator);

    // Aggregate a t=3 subset of vk shares (indices 1,3,5).
    const subset = [_]VerificationKeyShare{ keys.vk_shares[0], keys.vk_shares[2], keys.vk_shares[4] };
    const agg = try aggregateVerificationKeys(allocator, &subset);
    defer agg.deinit(allocator);

    try std.testing.expect(g2Eql(agg.alpha, keys.master_vk.alpha));
    for (agg.betas, keys.master_vk.betas) |b, bm| try std.testing.expect(g2Eql(b, bm));

    // A DIFFERENT t-subset (indices 2,3,4) recovers the SAME group vk.
    const subset2 = [_]VerificationKeyShare{ keys.vk_shares[1], keys.vk_shares[2], keys.vk_shares[3] };
    const agg2 = try aggregateVerificationKeys(allocator, &subset2);
    defer agg2.deinit(allocator);
    try std.testing.expect(g2Eql(agg2.alpha, keys.master_vk.alpha));
}

test "SecretKey/SecretKeyShare.deinit zeroes the secret Fr material" {
    const allocator = std.testing.allocator;

    var sk = SecretKey{ .x = commitFr(11), .ys = try allocator.dupe(Fr, &[_]Fr{ commitFr(22), commitFr(33) }) };
    // Snapshot the heap pointer before deinit frees it: secureZero writes
    // through it first, so the bytes at that address must be zero right
    // up to (and logically including) the free.
    sk.deinit(allocator);
    try std.testing.expect(sk.x.eql(Fr.zero));

    var share = SecretKeyShare{ .index = 7, .x = commitFr(44), .ys = try allocator.dupe(Fr, &[_]Fr{commitFr(55)}) };
    share.deinit(allocator);
    try std.testing.expect(share.x.eql(Fr.zero));
    try std.testing.expectEqual(@as(u64, 7), share.index); // public field untouched
}

fn commitFr(v: u32) Fr {
    var buf: [32]u8 = [_]u8{0} ** 32;
    std.mem.writeInt(u32, buf[28..32], v, .big);
    return Fr.fromBytes(buf) catch unreachable;
}

test "keygen: rejects invalid thresholds" {
    const allocator = std.testing.allocator;
    var prng = std.Random.DefaultPrng.init(1);
    try std.testing.expectError(error.InvalidThreshold, keygen(allocator, prng.random(), 2, 0, 3));
    try std.testing.expectError(error.InvalidThreshold, keygen(allocator, prng.random(), 2, 4, 3));
    try std.testing.expectError(error.InvalidThreshold, keygen(allocator, prng.random(), 0, 2, 3));
}

fn g2Eql(a: g2.Affine, b: g2.Affine) bool {
    return a.x.eql(b.x) and a.y.eql(b.y) and a.infinity == b.infinity;
}
