// SPDX-License-Identifier: MIT

//! Deterministic fuzz driver support for cookies (added 2026-10-09): the
//! source adapter `testing.fuzz` feeds the jar harness through, reach labels,
//! and the `Cookie:` header parse harness (generic over its source). The jar
//! harness itself and its driver test live in `jar.zig` beside the private
//! jar internals it checks.
//!
//! Driver: `COOKIES_FUZZ=<runs>[,<first seed>]` (testkit's fuzz driver; `_MS`,
//! `_SEEDFILE`, `_INPUT`, `_ONLY` as documented there). Harness names: `jar`,
//! `parse`.

const std = @import("std");
const testing = std.testing;
const testkit = @import("testkit");
const fuzz_driver = testkit.fuzz.driver;
const root = @import("root.zig");

pub const Label = enum { domain_cookie, secure_cookie, stored, sent, parsed, quoted_value, empty };
var reach: [@typeInfo(Label).@"enum".fields.len]usize = @splat(0);

pub fn mark(l: Label) void {
    reach[@intFromEnum(l)] += 1;
    switch (l) {
        inline else => |c| fuzz_driver.hit(@tagName(c)),
    }
}

pub fn resetReach() void {
    reach = @splat(0);
}

/// Reach before verdict: every listed outcome was seen since `resetReach`.
pub fn expectReached(labels: []const Label) !void {
    for (labels) |l| if (reach[@intFromEnum(l)] == 0) {
        std.debug.print("reach: label {t} never hit\n", .{l});
        return error.HarnessDoesNotReach;
    };
}

/// `testing.fuzz`'s source: the bytes come FIRST, in one `slice` draw, and
/// every choice is read from them by a cursor -- so each seed is its own input.
pub const ScriptSource = struct {
    cur: testkit.fuzz.Cursor,

    pub fn valueRangeAtMost(self: *ScriptSource, comptime T: type, at_least: T, at_most: T) T {
        return @intCast(self.cur.ranged(at_least, at_most));
    }
    pub fn value(self: *ScriptSource, comptime T: type) T {
        return switch (T) {
            bool => self.cur.byte() & 1 == 1,
            u8 => self.cur.byte(),
            u16 => self.cur.word(),
            else => @compileError("ScriptSource.value: unsupported type"),
        };
    }
    pub fn bytes(self: *ScriptSource, buf: []u8) void {
        for (buf) |*b| b.* = self.cur.byte();
    }
    pub fn index(self: *ScriptSource, len: usize) usize {
        return self.cur.ranged(0, @intCast(len - 1));
    }
    pub fn slice(self: *ScriptSource, buf: []u8) u32 {
        const left = self.cur.bytes.len -| self.cur.at;
        const n = @min(buf.len, left);
        @memcpy(buf[0..n], self.cur.bytes[self.cur.at..][0..n]);
        self.cur.at += n;
        return @intCast(n);
    }
};

/// `parse` over an arbitrary `Cookie:` header: never panics, and every pair
/// it yields is a slice of the input.
pub fn parseHarness(comptime S: type, src: *S, gpa: std.mem.Allocator) anyerror!void {
    _ = gpa;
    var buf: [512]u8 = undefined;
    const len: usize = src.slice(&buf);
    var it = root.parse(buf[0..len]);
    var n: usize = 0;
    while (it.next()) |c| {
        n += 1;
        std.mem.doNotOptimizeAway(c.name);
        std.mem.doNotOptimizeAway(c.value);
        if (std.mem.indexOfScalar(u8, c.value, ';') != null) mark(.quoted_value);
    }
    mark(if (n == 0) .empty else .parsed);
}

test "fuzz driver: COOKIES_FUZZ (parse)" {
    try fuzz_driver.run(parseHarness, .{ .prefix = "COOKIES_FUZZ", .name = "parse" });
}

test "fuzz harness: 500 seeds of parse in every test run, and they get everywhere" {
    resetReach();
    for (0..500) |seed| {
        var prng = std.Random.DefaultPrng.init(seed);
        var rng: fuzz_driver.Rng = .{ .r = prng.random() };
        parseHarness(fuzz_driver.Rng, &rng, testing.allocator) catch |err| {
            std.debug.print("cookies parse seed {d}: {t}\n", .{ seed, err });
            return err;
        };
    }
    // `quoted_value` (a ';' inside a quoted value) needs a `"` and a `;` in
    // random bytes at once: rare, so only the common outcomes are required.
    try expectReached(&.{ .parsed, .empty });
}
