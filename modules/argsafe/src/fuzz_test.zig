// SPDX-License-Identifier: MIT
//! Fuzz harness (deterministic driver `ARGSAFE_FUZZ`) for the shape predicates: each input is
//! built from structure (a valid-looking hostname, interface name, port or unsigned number of an
//! edge length, then a few substitutions, insertions and truncations drawn from the byte
//! classes that matter) and every predicate is compared with the independent reference models
//! of `model_test.zig`. The models decide; the harness only chooses strings.

const std = @import("std");
const testing = std.testing;
const testkit = @import("testkit");
const fuzz_driver = testkit.fuzz.driver;
const argsafe = @import("root.zig");
const model = @import("model_test.zig");

const max_len = 300;
const pool = "aZ09-._:/+ \x00\xff\"'$`;\n\x7f\x1b";

const Label = enum { host_ok, host_bad, if_ok, if_bad, port_ok, port_bad, uint_ok, uint_bad };
var reach: [@typeInfo(Label).@"enum".field_names.len]usize = @splat(0);
fn mark(comptime l: Label) void {
    reach[@backingInt(l)] += 1;
    fuzz_driver.hit(@tagName(l));
}

fn harness(comptime S: type, src: *S, _: std.mem.Allocator) anyerror!void {
    var buf: [max_len + 8]u8 = undefined;
    var len: usize = 0;
    switch (src.index(4)) {
        0 => { // hostname-shaped, edges at 63 / 253 and label boundaries
            const lens = [_]usize{ 1, 2, 62, 63, 64, 100, 252, 253, 254, 300 };
            len = lens[src.index(lens.len)];
            for (buf[0..len], 0..) |*c, i| {
                c.* = if (i % 64 == 63 and src.index(2) == 0) '.' else "abcXYZ019-"[src.index(10)];
            }
        },
        1 => { // interface-name-shaped, edges at 15
            const lens = [_]usize{ 1, 2, 14, 15, 16, 17 };
            len = lens[src.index(lens.len)];
            for (buf[0..len]) |*c| c.* = "abcXYZ019._-"[src.index(12)];
        },
        2 => { // decimal number, edges at the u64 maximum and the port range
            const digits = std.fmt.bufPrint(&buf, "{d}", .{switch (src.index(5)) {
                0 => src.valueRangeAtMost(u64, 0, 70000),
                1 => std.math.maxInt(u64) - src.valueRangeAtMost(u64, 0, 3),
                2 => @as(u64, 65535) + src.valueRangeAtMost(u64, 0, 2) - 1,
                3 => src.valueRangeAtMost(u64, 0, 130),
                else => src.value(u64),
            }}) catch unreachable;
            len = digits.len;
            if (src.index(8) == 0) { // leading zeros
                std.mem.copyBackwards(u8, buf[1 .. len + 1], buf[0..len]);
                buf[0] = '0';
                len += 1;
            }
        },
        else => { // anything from the pool
            len = src.index(40);
            for (buf[0..len]) |*c| c.* = pool[src.index(pool.len)];
        },
    }
    for (0..src.index(4)) |_| {
        if (len == 0) break;
        const p = src.index(len);
        const c = pool[src.index(pool.len)];
        switch (src.index(3)) {
            0 => buf[p] = c,
            1 => if (len < max_len) {
                std.mem.copyBackwards(u8, buf[p + 1 .. len + 1], buf[p..len]);
                buf[p] = c;
                len += 1;
            },
            else => len = p,
        }
    }
    const s = buf[0..len];

    const host = model.modelHostname(s);
    try testing.expectEqual(host, argsafe.isSafeHostname(s));
    if (host) mark(.host_ok) else mark(.host_bad);
    const ifn = model.modelIfname(s);
    try testing.expectEqual(ifn, argsafe.isSafeIfname(s));
    if (ifn) mark(.if_ok) else mark(.if_bad);
    const port = model.modelUint(s, 1, 65535);
    try testing.expectEqual(port, argsafe.isSafePort(s));
    if (port) mark(.port_ok) else mark(.port_bad);
    const lo = src.valueRangeAtMost(u64, 0, 130);
    const hi = src.valueRangeAtMost(u64, 0, 200);
    const u = model.modelUint(s, lo, hi);
    try testing.expectEqual(u, argsafe.isSafeUint(s, lo, hi));
    try testing.expectEqual(model.modelUint(s, 0, std.math.maxInt(u64)), argsafe.isSafeUint(s, 0, std.math.maxInt(u64)));
    if (u) mark(.uint_ok) else mark(.uint_bad);
}

test "fuzz driver: ARGSAFE_FUZZ (shape predicates against the reference models)" {
    try fuzz_driver.run(harness, .{ .prefix = "ARGSAFE_FUZZ", .name = "argsafe-shapes" });
}

test "fuzz: shape harness, arbitrary bytes under testing.fuzz" {
    try std.testing.fuzz({}, fuzzOne, .{});
}

fn fuzzOne(_: void, smith: *std.testing.Smith) !void {
    try harness(std.testing.Smith, smith, testing.allocator);
}

test "fuzz harness (shapes): 4000 seeds in every test run, and they reach every verdict of every predicate" {
    reach = @splat(0);
    const seeds = 4000;
    for (0..seeds) |seed| {
        var prng = std.Random.DefaultPrng.init(seed);
        var rng: fuzz_driver.Rng = .{ .r = prng.random() };
        harness(fuzz_driver.Rng, &rng, testing.allocator) catch |err| {
            std.debug.print("argsafe shapes seed {d}: {t}\n", .{ seed, err });
            return err;
        };
    }
    for (reach, 0..) |n, i| if (n == 0) {
        std.debug.print("reach: label {t} never hit in {d} seeds\n", .{ @as(Label, @fromBackingInt(@intCast(i))), seeds });
        return error.HarnessDoesNotReach;
    };
}
