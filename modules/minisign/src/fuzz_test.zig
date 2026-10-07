// SPDX-License-Identifier: MIT

//! Deterministic fuzz driver over minisign's existing `testing.fuzz` harnesses
//! (added 2026-10-07). The harness bodies stay where they were, now generic
//! over their source of choices (`fn(comptime S, *S, gpa)`); this file adds the
//! cursor adapter `testing.fuzz` feeds them through, the driver tests, and a
//! 500-seed in-suite run with a reach check.
//!
//! Driver: `MINISIGN_FUZZ=<runs>[,<first seed>]` (testkit's fuzz driver; `_MS`,
//! `_SEEDFILE`, `_INPUT`, `_ONLY` as documented there).

const std = @import("std");
const testing = std.testing;
const testkit = @import("testkit");
const fuzz_driver = testkit.fuzz.driver;
const ms = @import("root.zig");

pub const Label = enum { sig_file_parsed, sig_file_rejected, key_file_parsed, key_file_rejected, comment_printable, comment_rejected };
var reach: [@typeInfo(Label).@"enum".fields.len]usize = @splat(0);

pub fn mark(comptime l: Label) void {
    reach[@intFromEnum(l)] += 1;
    fuzz_driver.hit(@tagName(l));
}

/// `testing.fuzz`'s source: the bytes come FIRST, in one `slice` draw, and
/// every choice is read from them by a cursor -- so each seed is its own input
/// (a ranged `Smith` draw first collapses every seed to one, `check-fuzz-reach`).
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

test "fuzz driver: MINISIGN_FUZZ (minisign_sigfile)" {
    fuzz_driver.run(ms.sigFileHarness, .{ .prefix = "MINISIGN_FUZZ", .name = "minisign_sigfile" }) catch |e| switch (e) {
        error.SkipZigTest => return error.SkipZigTest,
        else => return e,
    };
}

test "fuzz driver: MINISIGN_FUZZ (minisign_keyfile)" {
    fuzz_driver.run(ms.secretKeyFileHarness, .{ .prefix = "MINISIGN_FUZZ", .name = "minisign_keyfile" }) catch |e| switch (e) {
        error.SkipZigTest => return error.SkipZigTest,
        else => return e,
    };
}

test "fuzz driver: MINISIGN_FUZZ (minisign_comment)" {
    fuzz_driver.run(ms.commentHarness, .{ .prefix = "MINISIGN_FUZZ", .name = "minisign_comment" }) catch |e| switch (e) {
        error.SkipZigTest => return error.SkipZigTest,
        else => return e,
    };
}

test "fuzz harness: 500 seeds in every test run, and they get everywhere" {
    reach = @splat(0);
    for (0..500) |seed| {
        var prng = std.Random.DefaultPrng.init(seed);
        var rng: fuzz_driver.Rng = .{ .r = prng.random() };
        ms.sigFileHarness(fuzz_driver.Rng, &rng, testing.allocator) catch |err| {
            std.debug.print("minisign_sigfile seed {d}: {t}\n", .{ seed, err });
            return err;
        };
    }
    for (0..500) |seed| {
        var prng = std.Random.DefaultPrng.init(seed);
        var rng: fuzz_driver.Rng = .{ .r = prng.random() };
        ms.secretKeyFileHarness(fuzz_driver.Rng, &rng, testing.allocator) catch |err| {
            std.debug.print("minisign_keyfile seed {d}: {t}\n", .{ seed, err });
            return err;
        };
    }
    for (0..500) |seed| {
        var prng = std.Random.DefaultPrng.init(seed);
        var rng: fuzz_driver.Rng = .{ .r = prng.random() };
        ms.commentHarness(fuzz_driver.Rng, &rng, testing.allocator) catch |err| {
            std.debug.print("minisign_comment seed {d}: {t}\n", .{ seed, err });
            return err;
        };
    }
    // Reach before verdict: every outcome the harness judges was seen.
    for (reach, 0..) |n, i| if (n == 0) {
        std.debug.print("reach: label {t} never hit in 500 seeds\n", .{@as(Label, @enumFromInt(i))});
        return error.HarnessDoesNotReach;
    };
}
