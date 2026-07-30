// SPDX-License-Identifier: MIT
//! `small_field` — a **test-only** prime field, so that the MDS security
//! checks can be exercised on inputs that actually fail them.
//!
//! ## Why this exists
//!
//! Over BN254 and BLS12-381 the subspace-trail checks essentially never
//! reject. `algorithm_3` fails only when some ratio `λ_i/λ_j` of eigenvalues
//! is a root of unity of order at most `4t`; there are fewer than `(4t)^2`
//! such roots and `t(t-1)` ratios, so for a 254-bit `p` the probability is
//! about `2^-236`. A sweep of 816 BN254 parameter sets (`t = 2..17`,
//! `R_P = 40..90`) produced **zero** rejections — see `SPEC.md`.
//!
//! That is a fine thing for Poseidon and a terrible thing for a test suite: a
//! check that never fires is indistinguishable from `return true`. Over a
//! *small* prime the same probability is O(1). Measured over `p = 101`:
//! **13 of 104** random matrices (`t = 3..6`) are rejected, and **5 of 48**
//! `(t, R_P)` parameter sets need more than one MDS candidate — so
//! `algorithm_1`'s eigenvalue path, its sub-codes and `derive`'s rejection
//! loop with its Grain-stream advance all get real coverage.
//!
//! It is deliberately **not** exported from `root.zig`: it is a fixture, not a
//! field anyone should compute with. It is not constant time and makes no
//! attempt to be.

const std = @import("std");

/// A prime field `GF(p)` for a `p` that fits in 32 bits, in the shape the rest
/// of this module expects of `bn254.Fr` / `bls12_381.Fr`.
///
/// `p` must be prime and **greater than 64**: `linalg.fromU64` is called with
/// small integers up to the Cantor-Zassenhaus shift bound of 64, and it
/// requires them to be canonical.
pub fn SmallField(comptime p: u32) type {
    std.debug.assert(p > 64);
    return struct {
        v: u32,

        const Self = @This();

        pub const encoded_bytes = 32;
        pub const modulus: u32 = p;

        /// The modulus big-endian in `encoded_bytes` bytes — what `Config` and
        /// `Linalg` take.
        pub const modulus_be: [encoded_bytes]u8 = blk: {
            var be: [encoded_bytes]u8 = @splat(0);
            std.mem.writeInt(u32, be[encoded_bytes - 4 ..][0..4], p, .big);
            break :blk be;
        };

        pub const zero: Self = .{ .v = 0 };
        pub const one: Self = .{ .v = 1 };

        pub fn fromBytes(b: [encoded_bytes]u8) error{NonCanonical}!Self {
            const x = std.mem.readInt(u256, &b, .big);
            if (x >= p) return error.NonCanonical;
            return .{ .v = @intCast(x) };
        }

        pub fn toBytes(self: Self) [encoded_bytes]u8 {
            var be: [encoded_bytes]u8 = @splat(0);
            std.mem.writeInt(u32, be[encoded_bytes - 4 ..][0..4], self.v, .big);
            return be;
        }

        /// `int(bytes) mod p` — the reducing conversion `create_mds_p` needs.
        pub fn reduceWide(b: []const u8) Self {
            var acc: u64 = 0;
            for (b) |byte| acc = (acc * 256 + byte) % p;
            return .{ .v = @intCast(acc) };
        }

        pub fn isZero(self: Self) bool {
            return self.v == 0;
        }

        pub fn eql(a: Self, b: Self) bool {
            return a.v == b.v;
        }

        pub fn add(a: Self, b: Self) Self {
            return .{ .v = @intCast((@as(u64, a.v) + b.v) % p) };
        }

        pub fn sub(a: Self, b: Self) Self {
            return .{ .v = @intCast((@as(u64, a.v) + p - b.v) % p) };
        }

        pub fn neg(a: Self) Self {
            return .{ .v = if (a.v == 0) 0 else p - a.v };
        }

        pub fn mul(a: Self, b: Self) Self {
            return .{ .v = @intCast((@as(u64, a.v) * b.v) % p) };
        }

        pub fn square(a: Self) Self {
            return a.mul(a);
        }

        pub fn inv(a: Self) error{NotInvertible}!Self {
            if (a.v == 0) return error.NotInvertible;
            // Fermat: a^(p-2). p is prime by the caller's contract.
            var result: Self = .one;
            var base = a;
            var e: u32 = p - 2;
            while (e > 0) {
                if (e & 1 == 1) result = result.mul(base);
                base = base.square();
                e >>= 1;
            }
            return result;
        }
    };
}

test "SmallField is a field" {
    const F = SmallField(1013);
    const a = F{ .v = 7 };
    const b = F{ .v = 999 };
    try std.testing.expect(a.add(b).sub(b).eql(a));
    try std.testing.expect(a.mul(b).mul(try b.inv()).eql(a));
    try std.testing.expect(F.one.eql(try F.one.inv()));
    try std.testing.expectError(error.NotInvertible, F.zero.inv());
    try std.testing.expect(a.neg().add(a).isZero());
    try std.testing.expect(F.reduceWide(&F.modulus_be).isZero());
}
