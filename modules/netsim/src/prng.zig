// SPDX-License-Identifier: MIT

//! splitmix64 — netsim's sole source of randomness (public-domain algorithm by
//! Sebastiano Vigna). Deterministic, seeded, no clock / OS-rng / thread
//! nondeterminism, so any run reproduces byte-for-byte from its seed. Shared by
//! `sim.zig` (message mechanics: jitter, loss, dup, reorder) and `fault.zig`
//! (the failure-schedule fuzzer), each seeding an independent stream so a
//! concrete fault trace can be replayed without perturbing the message stream.
//!
//! This is the same generator `kv/src/prng.zig` uses — netsim borrows kv's
//! proven VOPR methodology, not its code.

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

    /// Uniform-ish integer in `[0, n)`. Modulo bias is irrelevant here.
    ///
    /// `n == 0` is an EMPTY range and yields 0. It used to `assert(n > 0)`,
    /// which is a no-op in ReleaseFast and therefore left `next() % 0` — a
    /// division by zero, illegal behaviour — as the actual release-build
    /// outcome of a config that set a bound to 0. A guard that only exists in
    /// safe builds is not a guard for the build that ships. The loud rejection
    /// belongs where such a bound ENTERS: `fault.generate` returns
    /// `error.ZeroHorizon` rather than silently drawing every disruption at
    /// t=0. Note `chance(num, 0)` is `0 < num` by the same rule.
    pub fn below(p: *Prng, n: usize) usize {
        if (n == 0) return 0;
        return @intCast(p.next() % @as(u64, n));
    }

    /// True with probability num/den.
    pub fn chance(p: *Prng, num: usize, den: usize) bool {
        return p.below(den) < num;
    }

    /// True with probability rate/1000 (parts per mille) — the unit link
    /// loss/dup/reorder rates are expressed in.
    pub fn permille(p: *Prng, rate: u16) bool {
        if (rate == 0) return false;
        return p.below(1000) < rate;
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

test "Prng: permille(0) never fires, permille(1000) always fires" {
    var p = Prng.init(7);
    var i: usize = 0;
    while (i < 50) : (i += 1) {
        try testing.expect(!p.permille(0));
        try testing.expect(p.permille(1000));
    }
}

test "below is total: an empty range yields 0 in every build, never a modulo by zero" {
    var p = Prng.init(0xC0FFEE);
    // The case that used to be `assert` in safe builds and `% 0` in ReleaseFast.
    try std.testing.expectEqual(@as(usize, 0), p.below(0));
    try std.testing.expectEqual(@as(usize, 0), p.below(0));
    // A one-element range is the other degenerate end, and is genuinely uniform.
    for (0..8) |_| try std.testing.expectEqual(@as(usize, 0), p.below(1));
    // …and a real range still spans it: with 2 outcomes over 64 draws, seeing
    // only one would mean `below` had stopped depending on `next()`.
    var seen: [2]usize = .{ 0, 0 };
    for (0..64) |_| seen[p.below(2)] += 1;
    try std.testing.expect(seen[0] > 0 and seen[1] > 0);
    // `chance` inherits the rule: an empty denominator is never "true".
    try std.testing.expect(!p.chance(0, 0));
}
