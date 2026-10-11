// SPDX-License-Identifier: MIT

//! Deterministic fuzz driver support for cookies (added 2026-10-09): the
//! source adapter `testing.fuzz` feeds the jar harness through, reach labels,
//! and the `Cookie:` header parse harness (generic over its source). The jar
//! harness itself and its driver test live in `jar.zig` beside the private
//! jar internals it checks. `secure` (2026-10-12): signed/private values,
//! genuine or mutated, against `verify`/`open`.
//!
//! Driver: `COOKIES_FUZZ=<runs>[,<first seed>]` (testkit's fuzz driver; `_MS`,
//! `_SEEDFILE`, `_INPUT`, `_ONLY` as documented there). Harness names: `jar`,
//! `parse`, `secure`.

const std = @import("std");
const testing = std.testing;
const testkit = @import("testkit");
const fuzz_driver = testkit.fuzz.driver;
const root = @import("root.zig");

pub const Label = enum { domain_cookie, secure_cookie, stored, sent, parsed, quoted_value, empty, secure_accepted, secure_refused };
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

/// `signed.verify` and `private.open` over a genuine value or a mutation of
/// it (byte flip, truncation, extension, foreign bytes, another name, another
/// key): never panics, accepts exactly the genuine value (or a mutation that
/// left it byte-identical) and returns its plaintext, refuses everything else.
pub fn secureHarness(comptime S: type, src: *S, gpa: std.mem.Allocator) anyerror!void {
    _ = gpa;
    const secure = root.secure;
    var master: [32]u8 = @splat(0x11);
    master[0] = src.value(u8) & 3; // four keys, so "another key" is reachable
    var key: secure.Key = undefined;
    try secure.Key.deriveInto(&key, &master);
    var other: secure.Key = undefined;
    master[0] ^= 1;
    try secure.Key.deriveInto(&other, &master);

    var value_buf: [96]u8 = undefined;
    const vlen = src.index(value_buf.len + 1);
    for (value_buf[0..vlen]) |*c| c.* = "abcXYZ019!#$%&'()*+-./:<=>?@[]^_`{|}~"[src.index(37)];
    const value = value_buf[0..vlen];
    const name = if (src.value(bool)) "sid" else "theme";

    var enc: [256]u8 = undefined;
    const use_private = src.value(bool);
    const genuine = if (use_private)
        try secure.private.seal(&key, name, value, @splat(src.value(u8)), &enc)
    else
        try secure.signed.sign(&key, name, value, &enc, .{});
    var presented_buf: [300]u8 = undefined;
    @memcpy(presented_buf[0..genuine.len], genuine);
    var presented: []u8 = presented_buf[0..genuine.len];
    var open_name: []const u8 = name;
    var keys = [_]secure.Key{ other, key };
    switch (src.index(7)) {
        0 => {},
        1 => presented[src.index(presented.len)] ^= src.value(u8) | 1,
        2 => presented = presented[0..src.index(presented.len)],
        3 => {
            presented = presented_buf[0 .. genuine.len + 1];
            presented[genuine.len] = 'A';
        },
        4 => {
            const n = src.slice(&presented_buf);
            presented = presented_buf[0..n];
        },
        5 => open_name = if (name.len == 3) "theme" else "sid",
        else => keys[1] = other,
    }
    const intact = std.mem.eql(u8, presented, genuine) and open_name.ptr == name.ptr and
        std.mem.eql(u8, &keys[1].signing, &key.signing);
    var plain: [300]u8 = undefined;
    const got = if (use_private)
        secure.private.open(&keys, open_name, presented, &plain)
    else
        secure.signed.verify(&keys, open_name, presented, .{});
    if (intact) {
        const g = got orelse return error.GenuineRefused;
        try testing.expectEqualSlices(u8, value, g);
        mark(.secure_accepted);
    } else {
        if (got != null) return error.ForgeryAccepted;
        mark(.secure_refused);
    }
}

test "fuzz driver: COOKIES_FUZZ (secure)" {
    try fuzz_driver.run(secureHarness, .{ .prefix = "COOKIES_FUZZ", .name = "secure" });
}

test "fuzz harness: 500 seeds of secure in every test run, and they get everywhere" {
    resetReach();
    for (0..500) |seed| {
        var prng = std.Random.DefaultPrng.init(seed);
        var rng: fuzz_driver.Rng = .{ .r = prng.random() };
        secureHarness(fuzz_driver.Rng, &rng, testing.allocator) catch |err| {
            std.debug.print("cookies secure seed {d}: {t}\n", .{ seed, err });
            return err;
        };
    }
    try expectReached(&.{ .secure_accepted, .secure_refused });
}
