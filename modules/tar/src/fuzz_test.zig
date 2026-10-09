// SPDX-License-Identifier: MIT

//! Support for tar's deterministic fuzz driver (added 2026-10-09): the source
//! adapter `testing.fuzz` feeds the harness through, and reach labels. The
//! harness bodies and the driver tests live in `root.zig` beside the private
//! corpus builder and checksum helper they share.
//!
//! Driver: `TAR_FUZZ=<runs>[,<first seed>]` (testkit's fuzz driver; `_MS`,
//! `_SEEDFILE`, `_INPUT`, `_ONLY` as documented there). Harness names:
//! `reader` (arbitrary bytes), `mutated` (a valid archive from the module's
//! own `Writer`, a few octets flipped, maybe re-stamped, maybe cut short).

const std = @import("std");
const testkit = @import("testkit");
const fuzz_driver = testkit.fuzz.driver;

pub const Label = enum { entry_walked, content_read, refused, ended_clean };
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

/// Reach before verdict: every label was seen since `resetReach`.
pub fn expectAllReached() !void {
    for (reach, 0..) |n, i| if (n == 0) {
        std.debug.print("reach: label {t} never hit\n", .{@as(Label, @enumFromInt(i))});
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
