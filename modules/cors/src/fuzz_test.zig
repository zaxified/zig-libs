// SPDX-License-Identifier: MIT

//! Deterministic fuzz driver over cors's existing `testing.fuzz` harness
//! (added 2026-10-09): the three pure gates against hostile header bytes. The
//! body is generic over its source (`fn(comptime S, *S, gpa)`); `root.zig`'s
//! `testing.fuzz` test calls it with a `Smith` (its first and only draw is one
//! `slice`, so the corpus is honoured), the driver with a PRNG.
//!
//! Driver: `CORS_FUZZ=<runs>[,<first seed>]` (testkit's fuzz driver; `_MS`,
//! `_SEEDFILE`, `_INPUT`, `_ONLY` as documented there).
//!
//! Not reachable from random bytes, hence no label: a granted origin or an
//! allowed non-OPTIONS method token (both need an exact listed string; the
//! corpus in root.zig carries those).

const std = @import("std");
const testing = std.testing;
const testkit = @import("testkit");
const fuzz_driver = testkit.fuzz.driver;
const Cors = @import("root.zig").Cors;

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

pub const Label = enum { origin_refused, any_granted, headers_allowed, headers_refused, method_refused, pattern_granted, pattern_refused };
var reach: [@typeInfo(Label).@"enum".fields.len]usize = @splat(0);

fn mark(l: Label) void {
    reach[@intFromEnum(l)] += 1;
    switch (l) {
        inline else => |c| fuzz_driver.hit(@tagName(c)),
    }
}

/// 96 octets against the longest value any of the three gates is handed in
/// this module's own wire tests, with room for a comma list naming both
/// allowed headers several times over.
const gate_buf_len = 96;

pub fn gatesHarness(comptime S: type, src: *S, gpa: std.mem.Allocator) anyerror!void {
    _ = gpa;
    var buf: [gate_buf_len]u8 = undefined;
    // ⚠ One `slice`, never `bytes` then a ranged draw (see root.zig's corpus).
    const len: usize = src.slice(&buf);
    const bytes = buf[0..len];

    // Policies live on the stack — the gates allocate nothing.
    const listed: Cors = .{
        .gpa = testing.failing_allocator,
        .options = .{
            .allowed_origins = .{ .list = &.{ "https://app.example", "null" } },
            .allowed_headers = .{ .list = &.{ "Content-Type", "Authorization" } },
        },
        .allow_methods_value = "",
        .allow_headers_value = "",
        .expose_headers_value = "",
    };
    if (listed.allowOriginValue(bytes) == null) mark(.origin_refused);
    if (!listed.methodTokenAllowed(bytes)) mark(.method_refused);
    mark(if (listed.requestedHeadersAllowed(bytes)) .headers_allowed else .headers_refused);

    // The other side of every union the gates read: a `.reflect` policy is
    // the default and was once the input that broke "never panic".
    const reflecting: Cors = .{
        .gpa = testing.failing_allocator,
        .options = .{
            .allowed_origins = .any,
            .allowed_headers = .reflect,
        },
        .allow_methods_value = "",
        .allow_headers_value = "",
        .expose_headers_value = "",
    };
    if (reflecting.allowOriginValue(bytes) != null) mark(.any_granted);
    _ = reflecting.methodTokenAllowed(bytes);
    _ = reflecting.requestedHeadersAllowed(bytes);

    const none_policy: Cors = .{
        .gpa = testing.failing_allocator,
        .options = .{ .allowed_origins = .none, .allowed_headers = .reflect },
        .allow_methods_value = "",
        .allow_headers_value = "",
        .expose_headers_value = "",
    };
    _ = none_policy.allowOriginValue(bytes);

    // The subdomain-pattern matcher. Raw bytes almost never carry the
    // `https://` prefix and the `.example.com` suffix, so the second feed
    // builds an origin around a few drawn bytes (mapped onto label bytes plus
    // the separators that must NOT widen a match) -- that is what reaches the
    // granting side. The oracle is independent of the matcher: whatever is
    // granted must be an https origin of `*.example.com` whose `*` part is
    // plain labels.
    const patterned: Cors = .{
        .gpa = testing.failing_allocator,
        .options = .{ .allowed_origins = .{ .patterns = .{
            .exact = &.{"https://exact.example"},
            .subdomains = &.{ "https://*.example.com", "http://*.dev.example:8080" },
        } } },
        .allow_methods_value = "",
        .allow_headers_value = "",
        .expose_headers_value = "",
    };
    _ = patterned.allowOriginValue(bytes); // raw hostile bytes: must not panic
    if (len > 1) {
        const alphabet = "abcdefghijklmnopqrstuvwxyz0123456789-_..@/:";
        const mid_len: usize = bytes[0] % 9;
        var cand: [8 + 8 + 12]u8 = undefined;
        @memcpy(cand[0..8], "https://");
        var n: usize = 8;
        for (0..@min(mid_len, len - 1)) |i| {
            cand[n] = alphabet[bytes[1 + i] % alphabet.len];
            n += 1;
        }
        @memcpy(cand[n..][0..12], ".example.com");
        n += 12;
        const origin = cand[0..n];
        if (patterned.allowOriginValue(origin)) |granted| {
            mark(.pattern_granted);
            const mid = origin[8 .. n - 12];
            try testing.expectEqualStrings(origin, granted);
            try testing.expect(mid.len != 0);
            for (mid) |ch| try testing.expect(std.mem.indexOfScalar(u8, "@/:", ch) == null);
            try testing.expect(mid[0] != '.' and mid[mid.len - 1] != '.');
            try testing.expect(std.mem.indexOf(u8, mid, "..") == null);
        } else mark(.pattern_refused);
    }
}

test "fuzz driver: CORS_FUZZ (gates)" {
    try fuzz_driver.run(gatesHarness, .{ .prefix = "CORS_FUZZ", .name = "gates" });
}

test "fuzz harness: 500 seeds in every test run, and they get everywhere" {
    reach = @splat(0);
    for (0..500) |seed| {
        var prng = std.Random.DefaultPrng.init(seed);
        var rng: fuzz_driver.Rng = .{ .r = prng.random() };
        gatesHarness(fuzz_driver.Rng, &rng, testing.allocator) catch |err| {
            std.debug.print("cors seed {d}: {t}\n", .{ seed, err });
            return err;
        };
    }
    for (reach, 0..) |n, i| if (n == 0) {
        std.debug.print("reach: label {t} never hit in 500 seeds\n", .{@as(Label, @enumFromInt(i))});
        return error.HarnessDoesNotReach;
    };
}
