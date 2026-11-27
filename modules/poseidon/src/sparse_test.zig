// SPDX-License-Identifier: MIT
//! The optimised partial-round schedule (`Permutation.permute`) against the
//! textbook one (`permutePlain`): same function, bit for bit, on every width
//! the module ships and on shapes the shipped sets do not reach.

const std = @import("std");
const testing = std.testing;
const bn = @import("bn254_poseidon.zig");
const bls = @import("bls12_381_poseidon.zig");
const neptune = @import("neptune.zig");
const small_field = @import("small_field.zig");
const perm = @import("perm.zig");
const grain_mod = @import("grain.zig");

fn randomState(comptime P: type, rng: std.Random) [P.t]P.Fr {
    var st: [P.t]P.Fr = undefined;
    for (&st) |*x| {
        var be: [32]u8 = undefined;
        rng.bytes(&be);
        be[0] &= 0x0f; // below both 254-bit and 255-bit moduli
        x.* = P.Fr.fromBytes(be) catch unreachable;
    }
    return st;
}

fn agree(comptime P: type, p: *const P, seed: u64, n: usize) !void {
    var prng = std.Random.DefaultPrng.init(seed);
    const rng = prng.random();
    for (0..n) |_| {
        const st = randomState(P, rng);
        const a = p.permute(st);
        const b = p.permutePlain(st);
        for (a, b) |x, y| try testing.expect(x.eql(y));
    }
    // The all-zero state too (constants only).
    const z: [P.t]P.Fr = @splat(P.Fr.zero);
    const a = p.permute(z);
    const b = p.permutePlain(z);
    for (a, b) |x, y| try testing.expect(x.eql(y));
}

test "optimised == plain: bn254 t = 2..17" {
    inline for (2..18) |t| {
        const P = bn.Perm(t);
        const p = P.init();
        try agree(P, &p, t, 4);
    }
}

test "optimised == plain: bls12-381 t = 3, 5" {
    inline for (.{ 3, 5 }) |t| {
        const P = bls.Perm(t);
        const p = P.init();
        try agree(P, &p, t, 4);
    }
}

test "optimised == plain: neptune arities, both strengths" {
    inline for (.{ 1, 2, 3, 4, 7, 8, 11, 15, 24, 36 }) |a| {
        inline for (.{ neptune.Strength.standard, neptune.Strength.strengthened }) |s| {
            const H = neptune.Hasher(a, s);
            const h = H.init();
            try agree(H.Permutation, &h.permutation, a, 2);
        }
    }
}

// Round shapes the shipped sets never produce: no partial rounds, one, an odd
// full-round count (unequal halves) and no full rounds at all.
const F = small_field.SmallField(101);

fn smallCfg(comptime t: u12, comptime r_f: u10, comptime r_p: u10) perm.Config {
    return .{ .Fr = F, .modulus_be = F.modulus_be, .n = 7, .t = t, .r_f = r_f, .r_p = r_p, .mds = .cauchy_consecutive };
}

test "optimised == plain: unusual round shapes over a small field" {
    inline for (.{
        .{ 3, 8, 0 },
        .{ 3, 8, 1 },
        .{ 3, 7, 5 },
        .{ 4, 1, 6 },
        .{ 3, 0, 4 },
        .{ 2, 2, 9 },
        .{ 5, 0, 1 },
    }) |c| {
        const P = perm.Permutation(smallCfg(c[0], c[1], c[2]));
        const p = P.init();
        var prng = std.Random.DefaultPrng.init(c[0] * 100 + c[2]);
        const rng = prng.random();
        for (0..20) |_| {
            var st: [P.t]F = undefined;
            for (&st) |*x| {
                var be: [32]u8 = @splat(0);
                be[31] = rng.uintLessThan(u8, 101);
                x.* = F.fromBytes(be) catch unreachable;
            }
            const a = p.permute(st);
            const b = p.permutePlain(st);
            for (a, b) |x, y| try testing.expect(x.eql(y));
        }
    }
}

test "mutation 2026-11-25: a consecutive-Cauchy MDS draws no Grain candidates" {
    const tables = try grain_mod.derive(smallCfg(3, 8, 2));
    try testing.expectEqual(@as(usize, 0), tables.mds_candidates);
}
