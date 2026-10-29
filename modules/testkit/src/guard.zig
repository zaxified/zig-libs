// SPDX-License-Identifier: MIT
//! Memory between two unreadable pages, for a harness's input and output.
//!
//! A differential fuzz verdict cannot see a read past the end of the input
//! when every implementation compared shares the code that reads it — and a
//! many-pointer (`[*]u8`) read has no bounds check even under ReleaseSafe.
//! brotli 2026-10-15: four decoders over one `HotBits` reader agreed on every
//! input while it read up to eight bytes past the end. Put the input at
//! `tail(len)` and such a read faults on the spot, under the seed that made
//! it; `head(len)` does the same for a read before the start.
//!
//!     const In = testkit.guard.Guarded(32 << 10);
//!     const input = In.tail(n);           // the last n bytes before the guard
//!     src.bytes(input);
//!     try decode(input);
//!
//! One region per `Guarded(cap)` type, mapped on first use and never unmapped
//! (a harness runs it for every seed), so two buffers in the same harness are
//! two types. Not thread-safe on first use. Off Linux (`supported`) it is a
//! plain static buffer: the same API, without the fault.

const std = @import("std");
const builtin = @import("builtin");

pub const supported = builtin.os.tag == .linux;

pub fn Guarded(comptime cap: usize) type {
    return struct {
        var region: ?[]u8 = null;
        var plain: [cap]u8 = undefined;

        /// `cap` writable bytes, a guard page directly before and directly
        /// after the page-rounded body.
        fn room() []u8 {
            if (!supported) return plain[0..];
            if (region) |r| return r;
            const linux = std.os.linux;
            const page = std.heap.pageSize();
            const body = std.mem.alignForward(usize, @max(cap, 1), page);
            const m = std.posix.mmap(null, page + body + page, .{ .READ = true, .WRITE = true }, .{ .TYPE = .PRIVATE, .ANONYMOUS = true }, -1, 0) catch
                @panic("testkit.guard: mmap");
            if (linux.errno(linux.mprotect(m.ptr, page, .{})) != .SUCCESS or
                linux.errno(linux.mprotect(m.ptr + page + body, page, .{})) != .SUCCESS)
                @panic("testkit.guard: mprotect");
            region = m[page..][0..body];
            return region.?;
        }

        /// The last `len` bytes before the guard page: a read or write at
        /// `[len]` faults.
        pub fn tail(len: usize) []u8 {
            if (len > cap) @panic("testkit.guard: tail(len) with len > cap");
            const r = room();
            return r[r.len - len ..];
        }

        /// The first `len` bytes after the guard page: a read or write at
        /// `[-1]` faults.
        pub fn head(len: usize) []u8 {
            if (len > cap) @panic("testkit.guard: head(len) with len > cap");
            return room()[0..len];
        }
    };
}

// ── tests ────────────────────────────────────────────────────────────────────

const testing = std.testing;
const child = @import("child.zig");

const T = Guarded(100);

fn touch(p: [*]volatile u8, off: isize) u8 {
    const q: [*]volatile u8 = @ptrFromInt(@as(usize, @bitCast(@as(isize, @bitCast(@intFromPtr(p))) + off)));
    return q[0];
}

fn readPastTail(len: usize) u8 {
    const s = T.tail(len);
    return touch(@ptrCast(s.ptr), @intCast(len));
}

fn readBeforeHead(len: usize) u8 {
    const s = T.head(len);
    return touch(@ptrCast(s.ptr), -1);
}

fn readLastAndFirst(len: usize) u8 {
    const t = T.tail(len);
    const h = T.head(len);
    @memset(t, 0xaa);
    @memset(h, 0x55);
    if (len == 0) return 0;
    // Exit code 0 only when both ends read back what was written.
    const last = touch(@ptrCast(t.ptr), @intCast(len - 1));
    const first = touch(@ptrCast(h.ptr), 0);
    return if (last == 0xaa and first == 0x55) 0 else 1;
}

test "Guarded: a read one past tail(len), or one before head(len), faults" {
    if (!child.supported) return error.SkipZigTest;
    // The negative control first: reading inside the slice is fine.
    for ([_]usize{ 0, 1, 7, 100 }) |len| {
        try testing.expect((try child.run(readLastAndFirst, .{len}, .{ .limit_ms = 5000 })).eql(.{ .exited = 0 }));
    }
    for ([_]usize{ 0, 1, 7, 100 }) |len| {
        const past = try child.run(readPastTail, .{len}, .{ .limit_ms = 5000 });
        try testing.expect(past == .signaled);
        const before = try child.run(readBeforeHead, .{len}, .{ .limit_ms = 5000 });
        try testing.expect(before == .signaled);
    }
}

test "Guarded: the slices have the asked length and the region is reused" {
    const a = T.tail(10);
    const b = T.tail(10);
    try testing.expectEqual(@as(usize, 10), a.len);
    try testing.expectEqual(a.ptr, b.ptr);
    try testing.expectEqual(@as(usize, 100), T.head(100).len);
    // head(0) is the body's start, tail(0) its page-rounded end.
    if (supported) try testing.expectEqual(@intFromPtr(T.head(0).ptr) + std.mem.alignForward(usize, 100, std.heap.pageSize()), @intFromPtr(T.tail(0).ptr));
}

fn tailOver() u8 {
    std.mem.doNotOptimizeAway(T.tail(101).len);
    return 0;
}
fn headOver() u8 {
    std.mem.doNotOptimizeAway(T.head(101).len);
    return 0;
}

test "tail past cap is a checked panic (sweep TK-6)" {
    if (!child.supported) return error.SkipZigTest;
    const out = try child.run(tailOver, .{}, .{ .limit_ms = 5000 });
    try testing.expect(out.eql(.{ .signaled = @backingInt(std.os.linux.SIG.ABRT) }));
    // The boundary itself is fine.
    try testing.expectEqual(@as(usize, 100), T.tail(100).len);
}

test "head past cap is a checked panic (sweep TK-6)" {
    if (!child.supported) return error.SkipZigTest;
    const out = try child.run(headOver, .{}, .{ .limit_ms = 5000 });
    try testing.expect(out.eql(.{ .signaled = @backingInt(std.os.linux.SIG.ABRT) }));
    try testing.expectEqual(@as(usize, 0), T.head(0).len);
}
