// SPDX-License-Identifier: MIT

//! Deterministic fuzz driver over ini's existing `testing.fuzz` harness
//! (added 2026-10-09). The harness body lives here, generic over its source of
//! choices (`fn(comptime S, *S, gpa)`); `root.zig`'s `testing.fuzz` test feeds
//! it through the cursor adapter below, the driver feeds it a PRNG.
//!
//! Driver: `INI_FUZZ=<runs>[,<first seed>]` (testkit's fuzz driver; `_MS`,
//! `_SEEDFILE`, `_INPUT`, `_ONLY` as documented there).

const std = @import("std");
const testing = std.testing;
const testkit = @import("testkit");
const fuzz_driver = testkit.fuzz.driver;
const ini = @import("root.zig");

pub const Label = enum { strict_rejected, strict_parsed, lenient_skipped };
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

pub fn parseHarness(comptime S: type, src: *S, gpa: std.mem.Allocator) anyerror!void {
    var buf: [1024]u8 = undefined;
    const len: usize = src.slice(&buf);
    _ = try checkAllPresets(gpa, buf[0..len]);
}

/// Parse `text` with every preset, strict and lenient, and check what must
/// hold whatever the input: lenient never fails (short of memory); when
/// strict succeeds, lenient produced the same document and skipped nothing;
/// every line number is inside the text. Returns how many strict parses
/// succeeded.
pub fn checkAllPresets(gpa: std.mem.Allocator, text: []const u8) !usize {
    const line_count = std.mem.count(u8, text, "\n") + 1;
    var ok: usize = 0;
    for ([_]ini.Options{ .{}, .python, .desktop, .{ .inline_comments = true } }) |base| {
        var lax_opts = base;
        lax_opts.strict = false;
        var lax = try ini.parse(gpa, text, lax_opts);
        defer lax.deinit();
        if (lax.skipped.len != 0) mark(.lenient_skipped);
        for (lax.skipped) |l| try testing.expect(l >= 1 and l <= line_count);
        for (lax.sections) |s| {
            try testing.expect(s.line <= line_count);
            for (s.entries) |e| {
                try testing.expect(e.line >= 1 and e.line <= line_count);
                try testing.expect(e.key.len > 0);
            }
        }
        var strict = ini.parse(gpa, text, base) catch |e| switch (e) {
            error.OutOfMemory => return e,
            else => {
                mark(.strict_rejected);
                continue;
            },
        };
        defer strict.deinit();
        mark(.strict_parsed);
        ok += 1;
        try testing.expectEqual(@as(usize, 0), lax.skipped.len);
        try testing.expectEqual(lax.sections.len, strict.sections.len);
        for (lax.sections, strict.sections) |x, y| {
            try testing.expectEqualStrings(x.name, y.name);
            try testing.expectEqual(x.entries.len, y.entries.len);
            for (x.entries, y.entries) |ex, ey| {
                try testing.expectEqualStrings(ex.key, ey.key);
                try testing.expectEqualStrings(ex.value, ey.value);
            }
        }
    }
    return ok;
}

test "fuzz driver: INI_FUZZ" {
    try fuzz_driver.run(parseHarness, .{ .prefix = "INI_FUZZ", .name = "ini" });
}

test "fuzz harness: 400 seeds in every test run, and they get everywhere" {
    reach = @splat(0);
    for (0..400) |seed| {
        var prng = std.Random.DefaultPrng.init(seed);
        var rng: fuzz_driver.Rng = .{ .r = prng.random() };
        parseHarness(fuzz_driver.Rng, &rng, testing.allocator) catch |err| {
            std.debug.print("ini seed {d}: {t}\n", .{ seed, err });
            return err;
        };
    }
    for (reach, 0..) |n, i| if (n == 0) {
        std.debug.print("reach: label {t} never hit in 400 seeds\n", .{@as(Label, @enumFromInt(i))});
        return error.HarnessDoesNotReach;
    };
}
