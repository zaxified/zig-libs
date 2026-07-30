// SPDX-License-Identifier: MIT
//! One diagnostic type shared by the lexer, the parser and the renderer.
//!
//! It owns a fixed buffer rather than an allocation so that a caller can keep
//! the message after the render arena is gone — the single most common way an
//! engine's error reporting turns into a use-after-free.

const std = @import("std");

pub const Diagnostic = struct {
    /// 1-based line in the template source; 0 when unknown.
    line: usize = 0,
    buf: [512]u8 = undefined,
    len: usize = 0,

    pub fn message(self: *const Diagnostic) []const u8 {
        return self.buf[0..self.len];
    }

    pub fn set(self: *Diagnostic, line: usize, comptime fmt: []const u8, args: anytype) void {
        self.line = line;
        const s = std.fmt.bufPrint(&self.buf, fmt, args) catch blk: {
            // Truncation is fine; losing the diagnostic entirely is not.
            break :blk self.buf[0..self.buf.len];
        };
        self.len = s.len;
    }

    pub fn format(self: *const Diagnostic, writer: *std.Io.Writer) std.Io.Writer.Error!void {
        try writer.print("line {d}: {s}", .{ self.line, self.message() });
    }
};
