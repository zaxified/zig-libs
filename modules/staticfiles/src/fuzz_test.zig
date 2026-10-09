// SPDX-License-Identifier: MIT

//! Deterministic fuzz driver over staticfiles' `sanitizePath` traversal-safety
//! harness (added 2026-10-09). The body is generic over its source of choices
//! (`fn(comptime S, *S, gpa)`). The first draw is one `slice` of bytes (the
//! request path, as `std.testing.fuzz` seeds it), then `allow_dotfiles`; a
//! ranged draw picks a SHAPE: 0 = the bytes as the path (random octets nearly
//! always hit a NUL or a backslash and are refused), 1 = a path assembled from
//! the bytes out of segment atoms (names, `..`, `.`, encoded dots/slashes/NUL/
//! backslash, dotfiles, empty), so the accepted side of the contract and the
//! attack shapes that CAN be accepted are reachable. Past the end of a corpus
//! seed the ranged draw answers 0, so a seed stays a raw path.
//!
//! Driver: `STATICFILES_FUZZ=<runs>[,<first seed>]` (testkit's fuzz driver;
//! `_MS`, `_SEEDFILE`, `_INPUT`, `_ONLY` as documented there).

const std = @import("std");
const testing = std.testing;
const testkit = @import("testkit");
const fuzz_driver = testkit.fuzz.driver;
const sf = @import("root.zig");

pub const Label = enum { refused, accepted_root, accepted_path, dotfiles_allowed };
var reach: [@typeInfo(Label).@"enum".fields.len]usize = @splat(0);

fn mark(comptime l: Label) void {
    reach[@intFromEnum(l)] += 1;
    fuzz_driver.hit(@tagName(l));
}

/// `testing.fuzz`'s source: the path bytes come FIRST, in one `slice` draw; the
/// `allow_dotfiles` word and the shape are drawn by the wrapper right after and
/// stored here.
pub const ScriptSource = struct {
    cur: testkit.fuzz.Cursor,
    dotfiles: bool,
    shape: u8,

    pub fn valueRangeAtMost(self: *ScriptSource, comptime T: type, at_least: T, at_most: T) T {
        return @intCast(@min(@max(self.shape, at_least), at_most));
    }
    pub fn value(self: *ScriptSource, comptime T: type) T {
        comptime std.debug.assert(T == bool);
        return self.dotfiles;
    }
    pub fn slice(self: *ScriptSource, buf: []u8) u32 {
        const left = self.cur.bytes.len -| self.cur.at;
        const n = @min(buf.len, left);
        @memcpy(buf[0..n], self.cur.bytes[self.cur.at..][0..n]);
        self.cur.at += n;
        return @intCast(n);
    }
};

const atoms = [_][]const u8{
    "a",     "b.txt",  "..",   ".",    "%2e%2e", "%2E", "%2f", "%5c",
    "x%00",  "\\",     ".env", "....", "dir",    "%ZZ", "",    "%2",
    "é",
    "a%20b", "%c0%af", "~",    "..;",  "file.",  " ",   "CON",
};

pub fn sanitizePathHarness(comptime S: type, src: *S, gpa: std.mem.Allocator) anyerror!void {
    _ = gpa;
    var raw_buf: [4096]u8 = undefined;
    var raw_len: usize = src.slice(&raw_buf);
    const allow_dotfiles = src.value(bool);
    const shape = src.valueRangeAtMost(u8, 0, 1);
    if (shape == 1) {
        // The bytes are a script over `atoms`.
        var script: [4096]u8 = undefined;
        @memcpy(script[0..raw_len], raw_buf[0..raw_len]);
        var c: testkit.fuzz.Cursor = .{ .bytes = script[0..raw_len] };
        var w: std.Io.Writer = .fixed(&raw_buf);
        if (c.byte() & 1 == 0) w.writeByte('/') catch unreachable;
        const nseg = c.ranged(0, 6);
        for (0..nseg) |i| {
            if (i > 0) w.writeByte('/') catch unreachable;
            w.writeAll(atoms[c.ranged(0, atoms.len - 1)]) catch unreachable;
        }
        raw_len = w.buffered().len;
    }
    const raw = raw_buf[0..raw_len];

    var out: [sf.max_path_bytes]u8 = undefined;
    const clean = sf.sanitizePath(raw, &out, .{ .allow_dotfiles = allow_dotfiles }) catch {
        mark(.refused);
        return;
    };
    if (allow_dotfiles) mark(.dotfiles_allowed);

    // An empty result is a valid outcome (the request targets the root itself).
    if (clean.len == 0) {
        mark(.accepted_root);
        return;
    }
    mark(.accepted_path);
    try testing.expect(clean[0] != '/');
    try testing.expect(clean[clean.len - 1] != '/');
    var it = std.mem.splitScalar(u8, clean, '/');
    while (it.next()) |seg| {
        try testing.expect(seg.len != 0);
        try testing.expect(!std.mem.eql(u8, seg, "."));
        try testing.expect(!std.mem.eql(u8, seg, ".."));
        if (!allow_dotfiles) try testing.expect(seg[0] != '.');
        for (seg) |c| try testing.expect(c != 0 and c != '\\');
    }
}

test "fuzz driver: STATICFILES_FUZZ (sanitizePath)" {
    try fuzz_driver.run(sanitizePathHarness, .{ .prefix = "STATICFILES_FUZZ", .name = "staticfiles-sanitizePath" });
}

test "fuzz harness: 400 seeds in every test run, and they get everywhere" {
    reach = @splat(0);
    for (0..400) |seed| {
        var prng = std.Random.DefaultPrng.init(seed);
        var rng: fuzz_driver.Rng = .{ .r = prng.random() };
        sanitizePathHarness(fuzz_driver.Rng, &rng, testing.allocator) catch |err| {
            std.debug.print("staticfiles seed {d}: {t}\n", .{ seed, err });
            return err;
        };
    }
    for (reach, 0..) |n, i| if (n == 0) {
        std.debug.print("reach: label {t} never hit in 400 seeds\n", .{@as(Label, @enumFromInt(i))});
        return error.HarnessDoesNotReach;
    };
}
