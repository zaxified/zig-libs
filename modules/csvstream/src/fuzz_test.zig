// SPDX-License-Identifier: MIT

//! Deterministic fuzz driver over csvstream's two existing `testing.fuzz`
//! harnesses (`LineIterator`, `splitFields`; added 2026-10-09). The bodies
//! live here, generic over their source of choices (`fn(comptime S, *S,
//! gpa)`); `line.zig`'s `testing.fuzz` tests feed them through the cursor
//! adapter below, the driver feeds them a PRNG.
//!
//! Driver: `CSVSTREAM_FUZZ=<runs>[,<first seed>]` (testkit's fuzz driver;
//! `_MS`, `_SEEDFILE`, `_INPUT`, `_ONLY` as documented there).

const std = @import("std");
const testing = std.testing;
const testkit = @import("testkit");
const fuzz_driver = testkit.fuzz.driver;
const line = @import("line.zig");

pub const Label = enum { records, unbalanced, fields };
var reach: [@typeInfo(Label).@"enum".fields.len]usize = @splat(0);

fn mark(comptime l: Label) void {
    reach[@intFromEnum(l)] += 1;
    fuzz_driver.hit(@tagName(l));
}

/// `testing.fuzz`'s source: the bytes come FIRST, in one `slice` draw, and
/// every choice is read from them by a cursor -- so each seed is its own input.
pub const ScriptSource = struct {
    cur: testkit.fuzz.Cursor,

    /// What `Smith.slice` would have returned for this script: up to
    /// `buf.len` of the remaining script bytes, and their count.
    pub fn slice(self: *ScriptSource, buf: []u8) u32 {
        const left = self.cur.bytes.len -| self.cur.at;
        const n = @min(buf.len, left);
        @memcpy(buf[0..n], self.cur.bytes[self.cur.at..][0..n]);
        self.cur.at += n;
        return @intCast(n);
    }
};

const quotes = [_]u8{ '"', 0 };
const delims = [_]u8{ ',', ';', '\t' };

/// `LineIterator` never panics or loops: the record count is bounded by the
/// input length, with and without quoting.
pub fn lineHarness(comptime S: type, src: *S, gpa: std.mem.Allocator) anyerror!void {
    _ = gpa;
    var buf: [512]u8 = undefined;
    const len: usize = src.slice(&buf);
    for (quotes) |quote| {
        var it = line.LineIterator.init(buf[0..len], quote, 0);
        var steps: usize = 0;
        while (it.next()) |rec| {
            steps += 1;
            if (steps >= 2) mark(.records);
            if (rec.unbalanced_quote) mark(.unbalanced);
            try testing.expect(steps <= len + 1);
        }
    }
}

/// `splitFields` never panics on one arbitrary record, for every delimiter
/// and quote setting. (Its one error, more fields than the 64-slot buffer,
/// is not reachable from random bytes, so it is not a reach label.)
pub fn splitHarness(comptime S: type, src: *S, gpa: std.mem.Allocator) anyerror!void {
    var arena = std.heap.ArenaAllocator.init(gpa);
    defer arena.deinit();
    var line_buf: [256]u8 = undefined;
    const len: usize = src.slice(&line_buf);
    var fields_buf: [64][]const u8 = undefined;
    for (delims) |delimiter| {
        for (quotes) |quote| {
            const out = line.splitFields(line_buf[0..len], &fields_buf, delimiter, quote, arena.allocator()) catch continue;
            if (out.len >= 2) mark(.fields);
        }
    }
}

test "fuzz driver: CSVSTREAM_FUZZ" {
    try fuzz_driver.run(lineHarness, .{ .prefix = "CSVSTREAM_FUZZ", .name = "csvstream-line" });
    try fuzz_driver.run(splitHarness, .{ .prefix = "CSVSTREAM_FUZZ", .name = "csvstream-split" });
}

test "fuzz harness: 500 seeds in every test run, and they get everywhere" {
    reach = @splat(0);
    for (0..500) |seed| {
        var prng = std.Random.DefaultPrng.init(seed);
        var rng: fuzz_driver.Rng = .{ .r = prng.random() };
        lineHarness(fuzz_driver.Rng, &rng, testing.allocator) catch |err| {
            std.debug.print("csvstream line seed {d}: {t}\n", .{ seed, err });
            return err;
        };
        splitHarness(fuzz_driver.Rng, &rng, testing.allocator) catch |err| {
            std.debug.print("csvstream split seed {d}: {t}\n", .{ seed, err });
            return err;
        };
    }
    for (reach, 0..) |n, i| if (n == 0) {
        std.debug.print("reach: label {t} never hit in 500 seeds\n", .{@as(Label, @enumFromInt(i))});
        return error.HarnessDoesNotReach;
    };
}
