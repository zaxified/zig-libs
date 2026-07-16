// SPDX-License-Identifier: MIT

//! splitmix64 — the property harness's sole source of randomness (public-domain
//! algorithm by Sebastiano Vigna). Deterministic, seeded, no clock/OS-rng, so
//! any failure reproduces exactly by re-running its seed. Mirrors `kv`'s own
//! `prng.zig` (that module keeps its copy private, so we carry our own rather
//! than reach across a module boundary for two dozen lines).

const std = @import("std");

pub const Prng = struct {
    state: u64,

    pub fn init(seed: u64) Prng {
        var p = Prng{ .state = seed };
        _ = p.next(); // decorrelate low-entropy seeds (0, 1, 2, …)
        return p;
    }

    pub fn next(p: *Prng) u64 {
        p.state +%= 0x9e3779b97f4a7c15;
        var z = p.state;
        z = (z ^ (z >> 30)) *% 0xbf58476d1ce4e5b9;
        z = (z ^ (z >> 27)) *% 0x94d049bb133111eb;
        return z ^ (z >> 31);
    }

    /// Uniform-ish integer in [0, n). Modulo bias is irrelevant here.
    pub fn below(p: *Prng, n: usize) usize {
        std.debug.assert(n > 0);
        return @intCast(p.next() % @as(u64, n));
    }

    /// True with probability num/den.
    pub fn chance(p: *Prng, num: usize, den: usize) bool {
        return p.below(den) < num;
    }

    pub fn fill(p: *Prng, buf: []u8) void {
        var i: usize = 0;
        while (i < buf.len) : (i += 8) {
            var tmp: [8]u8 = undefined;
            std.mem.writeInt(u64, &tmp, p.next(), .little);
            const n = @min(@as(usize, 8), buf.len - i);
            @memcpy(buf[i..][0..n], tmp[0..n]);
        }
    }
};

const testing = std.testing;

test "Prng: identical seed reproduces the identical stream" {
    var a = Prng.init(42);
    var b = Prng.init(42);
    var i: usize = 0;
    while (i < 100) : (i += 1) try testing.expectEqual(a.next(), b.next());
}
