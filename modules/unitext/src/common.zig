// SPDX-License-Identifier: MIT

//! Options, error sets and the two output sinks (a caller's `std.Io.Writer`, a
//! size-capped growing buffer) every algorithm in this module is written against.

const std = @import("std");
const utf8 = @import("utf8.zig");

pub const InvalidUtf8 = utf8.InvalidUtf8;

/// Options shared by every string function.
pub const Options = struct {
    /// What to do with bytes that are not well-formed UTF-8; see `InvalidUtf8`.
    /// CPython and Rust take a `str`, which cannot hold them: decode first with
    /// `errors="replace"` / `from_utf8_lossy` to get `.replace`.
    invalid_utf8: InvalidUtf8 = .reject,
    /// Cap on the result of an allocating form, in bytes (`error.TooLarge` beyond it).
    /// Case mapping grows a string by at most 3x, compatibility normalization by up to
    /// 11x in bytes (U+FDFA expands to 18 code points), so the cap is the only thing
    /// between a hostile input and the allocator. Writer forms stream and ignore it.
    max_output: usize = 1 << 30,
    /// Cap on one normalization segment (a starter and the marks after it), in code
    /// points after decomposition, which is what the working buffer holds
    /// (`error.TooLarge` beyond it). CPython and Rust have no such cap; a real text
    /// has segments of a few code points, so only an attack reaches 16M.
    max_segment: usize = 1 << 24,
};

/// Errors of the allocating forms.
pub const Error = error{ InvalidUtf8, OutOfMemory, TooLarge };

/// Errors of the writer forms that need no allocation.
pub const WriteError = std.Io.Writer.Error || error{InvalidUtf8};

/// Errors of the writer forms that need a working buffer (normalization).
pub const WriteAllocError = std.Io.Writer.Error || error{ InvalidUtf8, OutOfMemory, TooLarge };

pub const WriterOut = struct {
    w: *std.Io.Writer,
    pub const Error = std.Io.Writer.Error;
    pub fn put(self: *WriterOut, bytes: []const u8) WriterOut.Error!void {
        try self.w.writeAll(bytes);
    }
};

pub const ListOut = struct {
    list: std.ArrayList(u8) = .empty,
    a: std.mem.Allocator,
    cap: usize,
    pub const Error = error{ OutOfMemory, TooLarge };
    pub fn put(self: *ListOut, bytes: []const u8) ListOut.Error!void {
        if (bytes.len > self.cap - self.list.items.len) return error.TooLarge;
        try self.list.appendSlice(self.a, bytes);
    }
    pub fn deinit(self: *ListOut) void {
        self.list.deinit(self.a);
    }
    pub fn toOwned(self: *ListOut) std.mem.Allocator.Error![]u8 {
        return self.list.toOwnedSlice(self.a);
    }
};

/// Batches code points into a 256-byte block before they reach the sink.
pub fn Emitter(comptime Out: type) type {
    return struct {
        out: *Out,
        n: usize = 0,
        buf: [256]u8 = undefined,

        const Self = @This();

        pub fn flush(self: *Self) Out.Error!void {
            if (self.n != 0) {
                const n = self.n;
                self.n = 0;
                try self.out.put(self.buf[0..n]);
            }
        }

        pub fn cp(self: *Self, c: u21) Out.Error!void {
            if (self.n + 4 > self.buf.len) try self.flush();
            self.n += utf8.encode(c, self.buf[self.n..][0..4]);
        }

        pub fn bytes(self: *Self, b: []const u8) Out.Error!void {
            if (b.len > 64) {
                try self.flush();
                return self.out.put(b);
            }
            if (self.n + b.len > self.buf.len) try self.flush();
            @memcpy(self.buf[self.n..][0..b.len], b);
            self.n += b.len;
        }
    };
}
