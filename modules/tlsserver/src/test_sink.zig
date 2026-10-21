// SPDX-License-Identifier: MIT

//! A stream-shaped `std.Io.Writer` for tests: a fixed buffer whose `drain`
//! moves everything to a growing list, so `flush` empties the buffer in
//! place — what `Connection` needs from its transport writer (whose buffer
//! it seals records into). `Writer.fixed` and `Writer.Allocating` keep
//! their bytes in the buffer instead.

const std = @import("std");

pub const Sink = struct {
    gpa: std.mem.Allocator,
    got: std.ArrayList(u8) = .empty,
    writer: std.Io.Writer,

    pub fn init(gpa: std.mem.Allocator, buf: []u8) Sink {
        return .{ .gpa = gpa, .writer = .{ .vtable = &.{ .drain = drain }, .buffer = buf } };
    }

    pub fn deinit(self: *Sink) void {
        self.got.deinit(self.gpa);
    }

    /// Everything flushed so far.
    pub fn written(self: *const Sink) []const u8 {
        return self.got.items;
    }

    fn drain(w: *std.Io.Writer, data: []const []const u8, splat: usize) std.Io.Writer.Error!usize {
        const self: *Sink = @fieldParentPtr("writer", w);
        self.got.appendSlice(self.gpa, w.buffer[0..w.end]) catch return error.WriteFailed;
        w.end = 0;
        var n: usize = 0;
        for (data[0 .. data.len - 1]) |d| {
            self.got.appendSlice(self.gpa, d) catch return error.WriteFailed;
            n += d.len;
        }
        const pattern = data[data.len - 1];
        for (0..splat) |_| self.got.appendSlice(self.gpa, pattern) catch return error.WriteFailed;
        return n + pattern.len * splat;
    }
};
