// SPDX-License-Identifier: MIT

//! Deterministic fuzz driver for fss (added 2026-10-10, the jwt pattern).
//!
//! Driver: `FSS_FUZZ=<runs>[,<first seed>]` (testkit's fuzz driver; `_ONLY`
//! selects a harness by name, `_MS`, `_SEEDFILE`, `_INPUT` as documented
//! there). Harness names: `fss-dpf`, `fss-mpf`.
//!
//! Keys carry no authentication, so a damaged key is not "refused": it decodes
//! to some other key. What is required of it is that nothing panics, that
//! decoding is total and re-encoding reaches a fixed point, and that the
//! tree-reuse walk (`evalFull`) agrees with the per-point `eval` on it. What
//! is required of a key pair `Gen` produced is that the shares add up to the
//! point function everywhere, through the byte codec; and a tagged key with
//! the wrong tag is refused.

const std = @import("std");
const testing = std.testing;
const testkit = @import("testkit");
const fss = @import("root.zig");
pub const fuzz_driver = testkit.fuzz.driver;

pub fn Marker(comptime Label: type) type {
    return struct {
        var counts: [@typeInfo(Label).@"enum".fields.len]usize = @splat(0);

        pub fn mark(comptime l: Label) void {
            counts[@intFromEnum(l)] += 1;
            fuzz_driver.hit(@tagName(l));
        }

        pub fn reach(comptime harness: anytype, comptime name: []const u8, seeds: usize) !void {
            counts = @splat(0);
            for (0..seeds) |seed| {
                var prng = std.Random.DefaultPrng.init(seed);
                var rng: fuzz_driver.Rng = .{ .r = prng.random() };
                harness(fuzz_driver.Rng, &rng, testing.allocator) catch |err| {
                    std.debug.print(name ++ " seed {d}: {t}\n", .{ seed, err });
                    return err;
                };
            }
            for (counts, 0..) |n, i| if (n == 0) {
                std.debug.print("reach: " ++ name ++ " label {t} never hit in {d} seeds\n", .{ @as(Label, @enumFromInt(i)), seeds });
                return error.HarnessDoesNotReach;
            };
        }
    };
}

fn damage(comptime S: type, src: *S, buf: []u8) bool {
    var any = false;
    for (0..src.valueRangeAtMost(u8, 0, 3)) |_| {
        buf[src.index(buf.len)] ^= src.valueRangeAtMost(u8, 1, 255);
        any = true;
    }
    return any;
}

const DpfMark = Marker(enum { genuine_reconstructs, tag_ok, tag_refused, damaged_key, raw_key, walk_agrees, fixed_point });

pub fn fuzzDpf(comptime S: type, src: *S, _: std.mem.Allocator) anyerror!void {
    const D = fss.Dpf(8, 4);
    const kind = src.valueRangeAtMost(u8, 0, 3);
    var keys: [2]D.Key = undefined;
    var genuine = false;
    if (kind != 0) {
        var s0: fss.prg.Seed = undefined;
        var s1: fss.prg.Seed = undefined;
        src.bytes(&s0);
        src.bytes(&s1);
        if (std.mem.eql(u8, &s0, &s1)) s1[0] ^= 1;
        const alpha: D.Index = src.value(u8);
        const beta: D.Elem = src.value(u32);
        D.genWithSeeds(alpha, beta, &s0, &s1, &keys);
        // Through the codec, both parties.
        var wire: [2][D.Key.serialized_len]u8 = undefined;
        keys[0].toBytes(&wire[0]);
        keys[1].toBytes(&wire[1]);
        var damaged = false;
        if (kind == 3) damaged = damage(S, src, &wire[0]);
        D.Key.fromBytes(&keys[0], &wire[0]);
        D.Key.fromBytes(&keys[1], &wire[1]);
        genuine = !damaged;
        if (genuine) {
            var e0: [D.domain_size]D.Elem = undefined;
            var e1: [D.domain_size]D.Elem = undefined;
            D.evalAll(0, &keys[0], &e0);
            D.evalAll(1, &keys[1], &e1);
            if (D.firstMismatch(&e0, &e1, alpha, beta) != null) return error.SharesDoNotReconstruct;
            DpfMark.mark(.genuine_reconstructs);
            // tagged codec
            var tagged: [D.Key.tagged_len]u8 = undefined;
            keys[0].toBytesTagged(&tagged);
            var back: D.Key = undefined;
            try D.Key.fromBytesTagged(&back, &tagged);
            DpfMark.mark(.tag_ok);
            tagged[0] ^= src.valueRangeAtMost(u8, 1, 255);
            if (D.Key.fromBytesTagged(&back, &tagged)) |_| return error.WrongTagAccepted else |e| {
                if (e != error.UnsupportedKeyFormat) return error.UnexpectedError;
            }
            DpfMark.mark(.tag_refused);
        } else DpfMark.mark(.damaged_key);
    } else {
        var raw: [D.Key.serialized_len]u8 = undefined;
        src.bytes(&raw);
        D.Key.fromBytes(&keys[0], &raw);
        DpfMark.mark(.raw_key);
    }
    // Any key: the walk agrees with the point evaluation, re-encoding is a fixed point.
    for ([_]u1{ 0, 1 }) |b| {
        const count: usize = src.valueRangeAtMost(u16, 0, D.domain_size);
        var walk: [D.domain_size]D.Elem = undefined;
        D.evalFull(b, &keys[0], walk[0..count]);
        for (walk[0..count], 0..) |v, x| {
            if (D.eval(b, &keys[0], @intCast(x)) != v) return error.WalkDiffersFromEval;
        }
    }
    DpfMark.mark(.walk_agrees);
    var once: [D.Key.serialized_len]u8 = undefined;
    keys[0].toBytes(&once);
    var again: D.Key = undefined;
    D.Key.fromBytes(&again, &once);
    var twice: [D.Key.serialized_len]u8 = undefined;
    again.toBytes(&twice);
    if (!std.mem.eql(u8, &once, &twice)) return error.EncodingNotFixedPoint;
    DpfMark.mark(.fixed_point);
}

const MpfMark = Marker(enum { genuine_reconstructs, seed_reuse_refused, raw_key, walk_agrees, fixed_point, each_sums });

pub fn fuzzMpf(comptime S: type, src: *S, _: std.mem.Allocator) anyerror!void {
    const M = fss.Mpf(8, 4, 3);
    var key: M.Key = undefined;
    if (src.valueRangeAtMost(u8, 0, 2) != 0) {
        var s0: [3]fss.prg.Seed = undefined;
        var s1: [3]fss.prg.Seed = undefined;
        for (&s0) |*s| src.bytes(s);
        for (&s1) |*s| src.bytes(s);
        // now and then a repeated seed: Gen must refuse it, not degrade
        if (src.valueRangeAtMost(u8, 0, 3) == 0) s1[src.index(3)] = s0[src.index(3)];
        var alphas: [3]M.Index = undefined;
        var betas: [3]M.Elem = undefined;
        for (&alphas) |*a| a.* = src.value(u8);
        for (&betas) |*b| b.* = src.value(u32);
        if (src.valueRangeAtMost(u8, 0, 3) == 0) alphas[1] = alphas[0]; // repeated point: sums
        var keys: [2]M.Key = undefined;
        M.genWithSeeds(alphas, betas, &s0, &s1, &keys) catch |e| {
            if (e != error.SeedReuse) return error.UnexpectedError;
            MpfMark.mark(.seed_reuse_refused);
            return;
        };
        var wire: [2][M.Key.serialized_len]u8 = undefined;
        keys[0].toBytes(&wire[0]);
        keys[1].toBytes(&wire[1]);
        M.Key.fromBytes(&keys[0], &wire[0]);
        M.Key.fromBytes(&keys[1], &wire[1]);
        var e0: [M.domain_size]M.Elem = undefined;
        var e1: [M.domain_size]M.Elem = undefined;
        M.evalAll(0, &keys[0], &e0);
        M.evalAll(1, &keys[1], &e1);
        if (M.firstMismatch(&e0, &e1, alphas, betas) != null) return error.SharesDoNotReconstruct;
        MpfMark.mark(.genuine_reconstructs);
        key = keys[0];
        var wrong = wire[0];
        if (src.value(bool)) _ = damage(S, src, &wrong);
        M.Key.fromBytes(&key, &wrong);
    } else {
        var raw: [M.Key.serialized_len]u8 = undefined;
        src.bytes(&raw);
        M.Key.fromBytes(&key, &raw);
        MpfMark.mark(.raw_key);
    }
    for ([_]u1{ 0, 1 }) |b| {
        const count: usize = src.valueRangeAtMost(u16, 0, M.domain_size);
        var walk: [M.domain_size]M.Elem = undefined;
        M.evalFull(b, &key, walk[0..count]);
        for (walk[0..count], 0..) |v, x| {
            if (M.eval(b, &key, @intCast(x)) != v) return error.WalkDiffersFromEval;
        }
        const x: M.Index = src.value(u8);
        var each: [3]M.Elem = undefined;
        M.evalEach(b, &key, x, &each);
        var sum: M.Elem = 0;
        for (each) |e| sum +%= e;
        if (sum != M.eval(b, &key, x)) return error.EachDoesNotSum;
        MpfMark.mark(.each_sums);
    }
    MpfMark.mark(.walk_agrees);
    var once: [M.Key.serialized_len]u8 = undefined;
    key.toBytes(&once);
    var again: M.Key = undefined;
    M.Key.fromBytes(&again, &once);
    var twice: [M.Key.serialized_len]u8 = undefined;
    again.toBytes(&twice);
    if (!std.mem.eql(u8, &once, &twice)) return error.EncodingNotFixedPoint;
    MpfMark.mark(.fixed_point);
}

test "fuzz driver: FSS_FUZZ (dpf)" {
    try fuzz_driver.run(fuzzDpf, .{ .prefix = "FSS_FUZZ", .name = "fss-dpf" });
}
test "fuzz driver: FSS_FUZZ (mpf)" {
    try fuzz_driver.run(fuzzMpf, .{ .prefix = "FSS_FUZZ", .name = "fss-mpf" });
}
test "fuzz harness: dpf, 300 seeds, reaches every outcome" {
    try DpfMark.reach(fuzzDpf, "fss-dpf", 300);
}
test "fuzz harness: mpf, 300 seeds, reaches every outcome" {
    try MpfMark.reach(fuzzMpf, "fss-mpf", 300);
}
