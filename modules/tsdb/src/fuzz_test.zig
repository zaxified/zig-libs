// SPDX-License-Identifier: MIT

//! Deterministic fuzz driver over tsdb's two `testing.fuzz` harnesses,
//! `parseCanonical` and `decodePointKey` (added 2026-10-09). Both bodies are
//! generic over their source of choices (`fn(comptime S, *S, gpa)`). The first
//! draw is one `slice` of bytes (the input, as `std.testing.fuzz` seeds it);
//! a second, ranged draw picks a SHAPE: 0 = the bytes as they are, 1-3 = a
//! structurally valid input built from them (a canonical descriptor from
//! `canonicalize`, then cut short / with a lying label count; a point key with
//! the right tag and length), because random octets essentially never spell
//! either. Past the end of a corpus seed the ranged draw answers 0, so a seed
//! stays a raw input.
//!
//! Driver: `TSDB_FUZZ=<runs>[,<first seed>]` (testkit's fuzz driver; `_MS`,
//! `_SEEDFILE`, `_INPUT`, `_ONLY` as documented there).

const std = @import("std");
const testing = std.testing;
const testkit = @import("testkit");
const fuzz_driver = testkit.fuzz.driver;
const codec = @import("codec.zig");

pub const Label = enum { rejected, accepted, round_tripped, key_decoded, key_refused };
var reach: [@typeInfo(Label).@"enum".fields.len]usize = @splat(0);

fn mark(comptime l: Label) void {
    reach[@intFromEnum(l)] += 1;
    fuzz_driver.hit(@tagName(l));
}

/// `testing.fuzz`'s source: the bytes come FIRST, in one `slice` draw, and the
/// harness reads every choice from them. Past the end a ranged draw answers its
/// minimum (shape 0 = the raw input).
pub const ScriptSource = struct {
    cur: testkit.fuzz.Cursor,

    pub fn valueRangeAtMost(self: *ScriptSource, comptime T: type, at_least: T, at_most: T) T {
        if (self.cur.at >= self.cur.bytes.len) return at_least;
        return @intCast(self.cur.ranged(at_least, at_most));
    }
    pub fn slice(self: *ScriptSource, buf: []u8) u32 {
        const left = self.cur.bytes.len -| self.cur.at;
        const n = @min(buf.len, left);
        @memcpy(buf[0..n], self.cur.bytes[self.cur.at..][0..n]);
        self.cur.at += n;
        return @intCast(n);
    }
};

pub fn parseCanonicalHarness(comptime S: type, src: *S, gpa: std.mem.Allocator) anyerror!void {
    var buf: [256]u8 = @splat(0);
    const len: usize = src.slice(&buf);
    const shape = src.valueRangeAtMost(u8, 0, 3);

    var arena = std.heap.ArenaAllocator.init(gpa);
    defer arena.deinit();
    const ar = arena.allocator();

    var image: []const u8 = buf[0..len];
    var name: []const u8 = "";
    var labels: []codec.Label = &.{};
    if (shape != 0) {
        var c: testkit.fuzz.Cursor = .{ .bytes = buf[0..len] };
        const nm = try ar.alloc(u8, c.ranged(0, 6));
        for (nm) |*b| b.* = 'a' + @as(u8, @intCast(c.ranged(0, 25)));
        name = nm;
        labels = try ar.alloc(codec.Label, c.ranged(0, 3));
        for (labels, 0..) |*l, i| {
            const v = try ar.alloc(u8, c.ranged(0, 6));
            for (v) |*b| b.* = c.byte();
            l.* = .{ .name = try std.fmt.allocPrint(ar, "l{d}", .{i}), .value = v };
        }
        var out: std.ArrayList(u8) = .empty;
        try codec.canonicalize(ar, &out, name, labels);
        const full = out.items;
        switch (shape) {
            1 => image = full,
            2 => image = full[0 .. full.len - 1 - c.ranged(0, @intCast(full.len - 1))],
            else => {
                std.mem.writeInt(u16, full[2 + name.len ..][0..2], 0xffff, .big);
                image = full;
            },
        }
    }

    var d = codec.parseCanonical(gpa, image) catch {
        mark(.rejected);
        return;
    };
    defer d.deinit(gpa);
    mark(.accepted);
    if (shape == 1) {
        // Well-formed in, so the same descriptor must come back out.
        try testing.expectEqualStrings(name, d.name);
        try testing.expectEqual(labels.len, d.labels.len);
        for (labels, d.labels) |want, got| {
            try testing.expectEqualStrings(want.name, got.name);
            try testing.expectEqualStrings(want.value, got.value);
        }
        mark(.round_tripped);
    }
}

pub fn decodePointKeyHarness(comptime S: type, src: *S, gpa: std.mem.Allocator) anyerror!void {
    _ = gpa;
    var buf: [64]u8 = @splat(0);
    var len: usize = src.slice(&buf);
    const shape = src.valueRangeAtMost(u8, 0, 2);
    if (shape != 0) {
        len = codec.point_key_len;
        buf[0] = codec.tag_point;
        if (shape == 2) len -= 1 + buf[1] % 2; // one or two octets short
    }
    if (codec.decodePointKey(buf[0..len])) |ref| {
        mark(.key_decoded);
        if (len == codec.point_key_len)
            try testing.expectEqualSlices(u8, buf[0..len], &codec.pointKey(ref.series, ref.ts));
    } else mark(.key_refused);
}

test "fuzz driver: TSDB_FUZZ (parseCanonical)" {
    try fuzz_driver.run(parseCanonicalHarness, .{ .prefix = "TSDB_FUZZ", .name = "tsdb-parseCanonical" });
}

test "fuzz driver: TSDB_FUZZ (decodePointKey)" {
    try fuzz_driver.run(decodePointKeyHarness, .{ .prefix = "TSDB_FUZZ", .name = "tsdb-decodePointKey" });
}

test "fuzz harnesses: 400 seeds each in every test run, and they get everywhere" {
    reach = @splat(0);
    inline for (.{ parseCanonicalHarness, decodePointKeyHarness }, 0..) |h, which| {
        for (0..400) |seed| {
            var prng = std.Random.DefaultPrng.init(seed);
            var rng: fuzz_driver.Rng = .{ .r = prng.random() };
            h(fuzz_driver.Rng, &rng, testing.allocator) catch |err| {
                std.debug.print("tsdb harness {d} seed {d}: {t}\n", .{ which, seed, err });
                return err;
            };
        }
    }
    for (reach, 0..) |n, i| if (n == 0) {
        std.debug.print("reach: label {t} never hit in 400 seeds\n", .{@as(Label, @enumFromInt(i))});
        return error.HarnessDoesNotReach;
    };
}
