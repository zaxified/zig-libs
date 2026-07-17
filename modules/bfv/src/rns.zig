// SPDX-License-Identifier: MIT

//! rns — Residue Number System (CRT) representation of the large ciphertext
//! modulus `q = q_0 · q_1 · … · q_{L-1}` as a product of distinct NTT-friendly
//! word-size primes. Each big coefficient mod `q` is stored as its residues
//! `(x mod q_i)_i`; add/mul become independent per-limb operations, and each
//! limb is small enough for a single-prime NTT. This is how SEAL/OpenFHE avoid
//! multi-precision arithmetic in the hot path.
//!
//! Part-1 scope (REAL, ungated): the RNS basis container, **exact** CRT
//! reconstruction (residues → integer, via `u128` for KAT-sized moduli),
//! integer → residues decomposition, and **exact** base conversion
//! (reconstruct-then-reduce). The *fast/approximate* base conversion used to
//! implement the BFV multiply's `⌊t/q·…⌉` rescale is noise-sensitive and lives
//! with the gated Fable core (see `bfv.zig` / SPEC.md), NOT here.

const std = @import("std");
const ma = @import("modarith.zig");

/// An RNS basis: a set of distinct primes whose product is the working
/// modulus. `primes` is borrowed (caller-owned, must outlive the basis).
pub const Basis = struct {
    primes: []const u64,

    pub fn init(primes: []const u64) !Basis {
        if (primes.len == 0) return error.EmptyBasis;
        for (primes, 0..) |p, i| {
            if (!ma.isPrime(p)) return error.NotPrime;
            for (primes[0..i]) |q| if (p == q) return error.DuplicatePrime;
        }
        return .{ .primes = primes };
    }

    pub fn len(self: Basis) usize {
        return self.primes.len;
    }

    /// Decompose an integer `x < 2^128` into its residues, written into
    /// `out` (length == number of primes).
    pub fn decompose(self: Basis, x: u128, out: []u64) void {
        std.debug.assert(out.len == self.primes.len);
        for (self.primes, out) |p, *r| r.* = @intCast(x % p);
    }

    /// Exact CRT reconstruction of `residues` into the integer in
    /// `[0, ∏ primes)`. Uses `u128` accumulation, so the product of primes
    /// must fit in `u128` (true for all Part-1 KAT/test parameter sets;
    /// production RNS never materialises this integer — it stays in residues).
    pub fn reconstruct(self: Basis, residues: []const u64) u128 {
        std.debug.assert(residues.len == self.primes.len);
        var m: u128 = 1;
        for (self.primes) |p| m *= p;
        var acc: u128 = 0;
        for (self.primes, residues) |p, r| {
            const mi: u128 = m / p; // ∏_{j≠i} p_j
            const mi_mod_p: u64 = @intCast(mi % p);
            const inv = ma.invMod(mi_mod_p, p) catch unreachable; // gcd(mi,p)=1
            // term = r * mi * inv  (mod m); reduce mi*inv mod p first to bound size
            const coeff: u64 = ma.mulMod(r, inv, p); // < p
            acc = (acc + mi * @as(u128, coeff)) % m;
        }
        return acc;
    }

    /// Modulus `∏ primes` (must fit in `u128`).
    pub fn modulus(self: Basis) u128 {
        var m: u128 = 1;
        for (self.primes) |p| m *= p;
        return m;
    }

    /// Exact base conversion: given `residues` in THIS basis, produce the
    /// residues of the same integer in `dst` basis. Correct but O(reconstruct)
    /// — the fast RNS base conversion (Bajard/Halevi-Polyakov) is a gated /
    /// deferred increment. Requires this basis's product to fit in `u128`.
    pub fn convertExact(self: Basis, residues: []const u64, dst: Basis, out: []u64) void {
        const x = self.reconstruct(residues);
        dst.decompose(x, out);
    }
};

// ── tests (REAL, ungated) ────────────────────────────────────────────────────

const testing = std.testing;

test "decompose → reconstruct round-trip" {
    const primes = [_]u64{ 17, 97 };
    const basis = try Basis.init(&primes);
    try testing.expectEqual(@as(u128, 1649), basis.modulus());
    var res: [2]u64 = undefined;
    var v: u128 = 0;
    while (v < 1649) : (v += 1) {
        basis.decompose(v, &res);
        try testing.expectEqual(v, basis.reconstruct(&res));
    }
}

test "reconstruct on 3 word-size primes" {
    const primes = [_]u64{ 1073750017, 1073753089, 1073754113 }; // all ≡1 mod 2048, prime
    for (primes) |p| try testing.expect(ma.isPrime(p));
    const basis = try Basis.init(&primes);
    var res: [3]u64 = undefined;
    const x: u128 = 123456789012345;
    basis.decompose(x, &res);
    try testing.expectEqual(x, basis.reconstruct(&res));
}

test "base conversion between two bases agrees with reconstruct" {
    const a = [_]u64{ 17, 97 };
    const b = [_]u64{ 193, 257 }; // distinct primes, product > 1649
    const ba = try Basis.init(&a);
    const bb = try Basis.init(&b);
    var ra: [2]u64 = undefined;
    var rb: [2]u64 = undefined;
    ba.decompose(500, &ra);
    ba.convertExact(&ra, bb, &rb);
    try testing.expectEqual(@as(u64, 500 % 193), rb[0]);
    try testing.expectEqual(@as(u64, 500 % 257), rb[1]);
}

test "init rejects non-prime and duplicate bases" {
    try testing.expectError(error.NotPrime, Basis.init(&[_]u64{ 17, 100 }));
    try testing.expectError(error.DuplicatePrime, Basis.init(&[_]u64{ 17, 17 }));
    try testing.expectError(error.EmptyBasis, Basis.init(&[_]u64{}));
}
