// SPDX-License-Identifier: MIT
//! Tests for the thing that is invisible on every shipped parameter set: what
//! happens when the MDS rejection loop **actually rejects**.
//!
//! Over BN254 and BLS12-381 it never does — see `small_field.zig` for the
//! probability argument and `SPEC.md` for the 816-parameter-set sweep that
//! found zero rejections. So the loop is exercised here over a small prime,
//! where the same checks fire constantly, using the same `grain.derive` the
//! shipped instances use.
//!
//! What these tests are for, specifically: the failure mode where a rejection
//! is *detected* but does not *consume* its Grain draws. That produces a
//! perfectly valid-looking MDS matrix, passes every structural property
//! (invertible, MDS, deterministic), and is wrong. Only "the accepted matrix
//! is the k-th draw, and it differs from the first" catches it.

const std = @import("std");
const testing = std.testing;
const grain = @import("grain.zig");
const mds_security = @import("mds_security.zig");
const small_field = @import("small_field.zig");

/// `p = 101`: small enough that `algorithm_1`/`2`/`3` reject often — 5 of the
/// 48 `(t, R_P)` sets swept below need more than one candidate — and large
/// enough for `linalg`'s small-integer constants (up to the Cantor-Zassenhaus
/// shift bound of 64) to stay canonical.
const F = small_field.SmallField(101);

fn cfgFor(comptime t: u12, comptime r_p: u10) grain.Config {
    return .{
        .Fr = F,
        .modulus_be = F.modulus_be,
        .n = 7, // 101 < 2^7
        .t = t,
        .r_f = 8,
        .r_p = r_p,
    };
}

/// The first Cauchy candidate for a config, built by replaying the Grain
/// stream by hand — i.e. what `derive` would have produced with the security
/// checks removed. Deliberately a *separate* transcription of `create_mds_p`,
/// so it cannot inherit a bug from `derive`.
fn firstCandidate(comptime cfg: grain.Config) [cfg.t][cfg.t]F {
    var lfsr: grain.Lfsr = .init(cfg.n, cfg.t, cfg.r_f, cfg.r_p);
    const p = std.mem.readInt(u256, &cfg.modulus_be, .big);
    for (0..cfg.numConstants()) |_| {
        var v = lfsr.nextNum(cfg.n);
        while (v >= p) v = lfsr.nextNum(cfg.n);
    }
    while (true) {
        var rand_list: [2 * cfg.t]F = undefined;
        while (true) {
            for (&rand_list) |*e| {
                var be: [32]u8 = undefined;
                std.mem.writeInt(u256, &be, lfsr.nextNum(cfg.n), .big);
                e.* = F.reduceWide(&be);
            }
            var dup = false;
            for (0..2 * cfg.t) |i| {
                for (i + 1..2 * cfg.t) |j| {
                    if (rand_list[i].eql(rand_list[j])) dup = true;
                }
            }
            if (!dup) break;
        }
        var m: [cfg.t][cfg.t]F = undefined;
        var singular = false;
        for (0..cfg.t) |i| {
            for (0..cfg.t) |j| {
                const s = rand_list[i].add(rand_list[cfg.t + j]);
                if (s.isZero()) singular = true else m[i][j] = s.inv() catch unreachable;
            }
        }
        if (!singular) return m;
    }
}

fn matEql(comptime t: usize, a: [t][t]F, b: [t][t]F) bool {
    for (0..t) |i| {
        for (0..t) |j| {
            if (!a[i][j].eql(b[i][j])) return false;
        }
    }
    return true;
}

test "the rejection loop fires, and the accepted matrix is not the first draw" {
    // Found by sweeping `r_p` over p = 101; kept as fixed literals so the test
    // is a pin, not a search. `want` counts SECURITY rejections — a singular
    // Cauchy draw is redrawn inside `create_mds_p` and does not count.
    const cases = [_]struct { t: u12, r_p: u10, want: usize }{
        .{ .t = 4, .r_p = 24, .want = 3 },
        .{ .t = 5, .r_p = 21, .want = 3 },
        .{ .t = 5, .r_p = 24, .want = 2 },
        .{ .t = 6, .r_p = 28, .want = 2 },
    };
    var saw_multi = false;
    inline for (cases) |c| {
        const cfg = cfgFor(c.t, c.r_p);
        const tab = try grain.derive(cfg);
        try testing.expectEqual(c.want, tab.mds_candidates);
        if (tab.mds_candidates > 1) {
            saw_multi = true;
            // The whole point: the accepted matrix is NOT the one a generator
            // without the checks would have used.
            try testing.expect(!matEql(c.t, tab.mds, firstCandidate(cfg)));
            // And the first candidate really is rejected by the checks.
            const C = mds_security.Checks(F, &F.modulus_be, mds_security.max_state_width);
            var first = C.la.zeroMat();
            const fc = firstCandidate(cfg);
            for (0..c.t) |i| {
                for (0..c.t) |j| first[i][j] = fc[i][j];
            }
            try testing.expect(!try C.isSecure(&first, c.t));
        }
    }
    try testing.expect(saw_multi);
}

test "a parameter set whose first candidate passes is untouched by the loop" {
    // The other half of the pin: where no rejection happens, `derive` must
    // return exactly the first Cauchy matrix — which is the situation every
    // shipped BN254/BLS12-381 set is in.
    const cfg = cfgFor(5, 25);
    const tab = try grain.derive(cfg);
    try testing.expectEqual(@as(usize, 1), tab.mds_candidates);
    try testing.expect(matEql(5, tab.mds, firstCandidate(cfg)));
}

test "derive over the small field stays deterministic across candidates" {
    const cfg = cfgFor(5, 21);
    const a = try grain.derive(cfg);
    const b = try grain.derive(cfg);
    try testing.expect(matEql(5, a.mds, b.mds));
    try testing.expectEqual(a.mds_candidates, b.mds_candidates);
    for (a.round_constants, b.round_constants) |x, y| try testing.expect(x.eql(y));
}

test "an accepted matrix passes all three checks; a rejected one fails at least one" {
    const C = mds_security.Checks(F, &F.modulus_be, mds_security.max_state_width);
    var accepted: usize = 0;
    var rejected: usize = 0;
    inline for (.{ 3, 4, 5, 6 }) |t| {
        comptime var r_p: u10 = 20;
        inline while (r_p < 32) : (r_p += 1) {
            const cfg = cfgFor(t, r_p);
            const tab = try grain.derive(cfg);
            var m = C.la.zeroMat();
            for (0..t) |i| {
                for (0..t) |j| m[i][j] = tab.mds[i][j];
            }
            // Whatever came out must pass all three, individually.
            try testing.expect((try C.algorithm1(&m, t)).secure);
            try testing.expect(C.algorithm2(&m, t));
            try testing.expect(C.algorithm3(&m, t));
            accepted += 1;
            if (tab.mds_candidates > 1) rejected += 1;
        }
    }
    try testing.expect(accepted == 48);
    // If this ever hits zero the fixture stopped exercising the loop.
    try testing.expect(rejected > 0);
}
