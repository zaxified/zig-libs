// SPDX-License-Identifier: MIT

//! ring — polynomials of `R_q = Z_q[X]/(X^N+1)` in RNS form, `q = ∏ q_i`.
//!
//! An `RnsPoly` holds one length-`N` residue vector per RNS prime. It carries
//! a `domain` tag (`.coeff` or `.ntt`) so add/mul can assert they operate in
//! the right representation: add is legal in either domain (limb-wise), but
//! multiply must be pointwise in the `.ntt` domain (that IS the negacyclic
//! convolution). This is the RLWE ring the BFV scheme is built from — REAL,
//! ungated arithmetic.

const std = @import("std");
const ma = @import("modarith.zig");
const nttmod = @import("ntt.zig");

pub const Domain = enum { coeff, ntt };

/// `RnsPoly(N, L)` — an element of `R_q` with `L` RNS limbs of degree `N`.
pub fn RnsPoly(comptime N: usize, comptime L: usize) type {
    return struct {
        const Self = @This();
        pub const degree = N;
        pub const num_primes = L;
        pub const Engine = nttmod.Ntt(N);

        /// `limbs[i]` = residues mod prime `i`, either coefficient or NTT
        /// domain per `domain`.
        limbs: [L][N]u64,
        domain: Domain,

        pub fn zero(domain: Domain) Self {
            return .{ .limbs = [_][N]u64{[_]u64{0} ** N} ** L, .domain = domain };
        }

        /// Reduce arbitrary per-limb inputs into `[0, q_i)` and tag as coeff.
        pub fn fromCoeffs(primes: *const [L]u64, raw: [L][N]u64) Self {
            var out = Self{ .limbs = raw, .domain = .coeff };
            for (0..L) |i| for (&out.limbs[i]) |*x| {
                x.* %= primes[i];
            };
            return out;
        }

        /// `self += other`, limb-wise. Legal in either domain (must match).
        pub fn addAssign(self: *Self, other: *const Self, primes: *const [L]u64) void {
            std.debug.assert(self.domain == other.domain);
            for (0..L) |i| {
                for (&self.limbs[i], other.limbs[i]) |*x, y| x.* = ma.addMod(x.*, y, primes[i]);
            }
        }

        /// `self -= other`, limb-wise.
        pub fn subAssign(self: *Self, other: *const Self, primes: *const [L]u64) void {
            std.debug.assert(self.domain == other.domain);
            for (0..L) |i| {
                for (&self.limbs[i], other.limbs[i]) |*x, y| x.* = ma.subMod(x.*, y, primes[i]);
            }
        }

        pub fn negate(self: *Self, primes: *const [L]u64) void {
            for (0..L) |i| {
                for (&self.limbs[i]) |*x| x.* = ma.subMod(0, x.*, primes[i]);
            }
        }

        /// Forward NTT every limb (coeff → ntt). `engines[i]` is the NTT for
        /// prime `i`.
        pub fn toNtt(self: *Self, engines: *const [L]Engine) void {
            std.debug.assert(self.domain == .coeff);
            for (0..L) |i| engines[i].forward(&self.limbs[i]);
            self.domain = .ntt;
        }

        /// Inverse NTT every limb (ntt → coeff).
        pub fn fromNtt(self: *Self, engines: *const [L]Engine) void {
            std.debug.assert(self.domain == .ntt);
            for (0..L) |i| engines[i].inverse(&self.limbs[i]);
            self.domain = .coeff;
        }

        /// Pointwise `self *= other` — only valid in the NTT domain, where it
        /// realises negacyclic multiplication in `R_q`. Takes the engines
        /// rather than the bare primes because both factors vary, so this uses
        /// each engine's precomputed Barrett constant instead of a division.
        pub fn mulPointwise(self: *Self, other: *const Self, engines: *const [L]Engine) void {
            std.debug.assert(self.domain == .ntt and other.domain == .ntt);
            for (0..L) |i| engines[i].pointwiseMul(&self.limbs[i], &other.limbs[i]);
        }

        /// Coefficient-domain negacyclic multiply via NTT: `out = self·other`
        /// in `R_q` (both inputs coeff domain, output coeff domain). The RNS
        /// primes no longer need to be passed separately: each engine carries
        /// its own prime plus the precomputed Barrett/Shoup constants.
        pub fn mul(self: *const Self, other: *const Self, engines: *const [L]Engine) Self {
            std.debug.assert(self.domain == .coeff and other.domain == .coeff);
            var a = self.*;
            var b = other.*;
            a.toNtt(engines);
            b.toNtt(engines);
            a.mulPointwise(&b, engines);
            a.fromNtt(engines);
            return a;
        }

        pub fn eql(self: *const Self, other: *const Self) bool {
            if (self.domain != other.domain) return false;
            for (0..L) |i| if (!std.mem.eql(u64, &self.limbs[i], &other.limbs[i])) return false;
            return true;
        }
    };
}

/// Build the `L` NTT engines for a prime chain (one per limb).
pub fn makeEngines(comptime N: usize, comptime L: usize, primes: *const [L]u64) ![L]nttmod.Ntt(N) {
    var engines: [L]nttmod.Ntt(N) = undefined;
    for (0..L) |i| engines[i] = try nttmod.Ntt(N).init(primes[i]);
    return engines;
}

// ── tests (REAL, ungated) ────────────────────────────────────────────────────

const testing = std.testing;

test "ring add is limb-wise and matches per-prime reduction" {
    const primes = [_]u64{ 17, 97 };
    const P = RnsPoly(8, 2);
    var a = P.fromCoeffs(&primes, .{ [_]u64{ 1, 2, 3, 4, 5, 6, 7, 8 }, [_]u64{ 90, 91, 92, 93, 94, 95, 96, 0 } });
    const b = P.fromCoeffs(&primes, .{ [_]u64{ 16, 16, 16, 16, 16, 16, 16, 16 }, [_]u64{ 10, 10, 10, 10, 10, 10, 10, 10 } });
    a.addAssign(&b, &primes);
    try testing.expectEqual(@as(u64, 0), a.limbs[0][0]); // (1+16) mod 17
    try testing.expectEqual(@as(u64, 3), a.limbs[1][0]); // (90+10) mod 97
}

test "ring multiply via NTT == schoolbook per limb" {
    const primes = [_]u64{ 17, 97 };
    const P = RnsPoly(8, 2);
    const engines = try makeEngines(8, 2, &primes);
    var prng = std.Random.DefaultPrng.init(7);
    const rnd = prng.random();
    for (0..10) |_| {
        var raw_a: [2][8]u64 = undefined;
        var raw_b: [2][8]u64 = undefined;
        for (0..2) |i| for (0..8) |j| {
            raw_a[i][j] = rnd.uintLessThan(u64, primes[i]);
            raw_b[i][j] = rnd.uintLessThan(u64, primes[i]);
        };
        const a = P.fromCoeffs(&primes, raw_a);
        const b = P.fromCoeffs(&primes, raw_b);
        const prod = a.mul(&b, &engines);
        // cross-check each limb against the independent schoolbook oracle
        for (0..2) |i| {
            const want = nttmod.Ntt(8).mulSchoolbook(primes[i], &a.limbs[i], &b.limbs[i]);
            try testing.expectEqualSlices(u64, &want, &prod.limbs[i]);
        }
    }
}
