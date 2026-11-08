// SPDX-License-Identifier: MIT

//! splitmix64 — the VOPR's sole source of randomness (public-domain
//! algorithm by Sebastiano Vigna). Deterministic, seeded, no clock/OS-rng.
//! Shared by `vopr.zig` (the randomized fault-schedule driver), `scheduler.zig`
//! (the pluggable fault-scheduling policy seam) and `shrink.zig` (the
//! failing-seed search/shrink entry point) so all three draw from the exact
//! same generator.

const std = @import("std");

pub const Prng = struct {
    state: u64,

    pub fn init(seed: u64) Prng {
        var p = Prng{ .state = seed };
        _ = p.next(); // decorrelate low-entropy seeds (0, 1, 2, …)
        return p;
    }

    pub fn next(p: *Prng) u64 {
        var sm = std.Random.SplitMix64.init(p.state);
        defer p.state = sm.s;
        return sm.next();
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
    while (i < 100) : (i += 1) {
        try testing.expectEqual(a.next(), b.next());
    }
}

test "Prng: different seeds diverge" {
    var a = Prng.init(1);
    var b = Prng.init(2);
    try testing.expect(a.next() != b.next());
}

test "Prng.next is splitmix64 (known answers for state 0)" {
    var p: Prng = .{ .state = 0 };
    try std.testing.expectEqual(@as(u64, 0xe220a8397b1dcdaf), p.next());
    try std.testing.expectEqual(@as(u64, 0x6e789e6aa1b965f4), p.next());
}
