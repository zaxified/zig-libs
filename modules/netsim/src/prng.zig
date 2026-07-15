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

    /// Uniform-ish integer in [0, n). Modulo bias is irrelevant here.
    pub fn below(p: *Prng, n: usize) usize {
        std.debug.assert(n > 0);
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
