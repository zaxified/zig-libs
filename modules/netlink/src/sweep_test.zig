// SPDX-License-Identifier: MIT
//! No-panic sweep tests (wave GV) for netlink's public API.
//! Findings NL-1 .. NL-4, see ~/CML/20261029-panic-sweep/netlink-sweep.report.md.
//! Tests that need the private engines (`collectDumpPass`, `recvDatagramLimit`)
//! sit at the end of root.zig.
const std = @import("std");
const builtin = @import("builtin");
const linux = std.os.linux;
const testing = std.testing;
const codec = @import("codec.zig");
const bridge = @import("bridge.zig");

/// Run `body` in a forked child with its stderr captured into `buf`; returns
/// the captured length and whether the child died from a signal.
const Child = struct { died: bool, len: usize };

fn runChild(comptime body: fn () void, buf: []u8) !Child {
    if (builtin.os.tag != .linux) return error.SkipZigTest;
    var fds: [2]i32 = undefined;
    if (linux.errno(linux.pipe2(&fds, .{})) != .SUCCESS) return error.SkipZigTest;
    const rc = linux.fork();
    if (linux.errno(rc) != .SUCCESS) return error.SkipZigTest;
    if (rc == 0) {
        _ = linux.dup2(fds[1], 2);
        _ = linux.close(fds[0]);
        _ = linux.close(fds[1]);
        body();
        linux.exit_group(0);
    }
    _ = linux.close(fds[1]);
    defer _ = linux.close(fds[0]);
    const pid: linux.pid_t = @intCast(rc);
    var status: u32 = 0;
    var waited_ms: usize = 0;
    while (true) {
        const r = linux.waitpid(pid, @ptrCast(&status), linux.W.NOHANG);
        if (linux.errno(r) != .SUCCESS) return error.WaitFailed;
        if (r == @as(usize, @intCast(pid))) break;
        if (waited_ms >= 5000) {
            _ = linux.kill(pid, .KILL);
            _ = linux.waitpid(pid, @ptrCast(&status), 0);
            return error.ChildHung;
        }
        const ts: linux.timespec = .{ .sec = 0, .nsec = 10 * std.time.ns_per_ms };
        _ = linux.nanosleep(&ts, null);
        waited_ms += 10;
    }
    const n = linux.read(fds[0], buf.ptr, buf.len);
    return .{ .died = linux.W.IFSIGNALED(status), .len = if (linux.errno(n) == .SUCCESS) n else 0 };
}

// Needles live in consts, never inline in the expectPanicMessage call (the child's stack trace prints
// the caller's source line, so an inline needle matches ANY panic).
const needle_len = "netlink: message exceeds 4 GiB";

fn expectPanicMessage(comptime body: fn () void, needle: []const u8) !void {
    var buf: [8192]u8 = undefined;
    const c = try runChild(body, &buf);
    try testing.expect(c.died);
    try testing.expect(std.mem.find(u8, buf[0..c.len], needle) != null);
}

fn lenOver4Gib() void {
    _ = codec.checkedMessageLen(@as(usize, std.math.maxInt(u32)) + 1);
}

test "message length: u32 range is exact, past it is a checked netlink panic (sweep NL-3)" {
    try testing.expectEqual(@as(u32, 16), codec.checkedMessageLen(16));
    try testing.expectEqual(std.math.maxInt(u32), codec.checkedMessageLen(std.math.maxInt(u32)));
    try expectPanicMessage(lenOver4Gib, needle_len);
}

test "VlanEntry.count is total for a hand-built inverted entry (sweep NL-4)" {
    const e: bridge.VlanEntry = .{ .ifindex = 1, .vid = 100, .vid_end = 10, .flags = 0 };
    try testing.expectEqual(@as(u32, 0), e.count());
    const ok: bridge.VlanEntry = .{ .ifindex = 1, .vid = 10, .vid_end = 12, .flags = 0 };
    try testing.expectEqual(@as(u32, 3), ok.count());
}

// ── fix round (review GV-b) ─────────────────────────────────────────────────

fn doneMsg(payload: ?[]const u8) [24]u8 {
    var m: [24]u8 = @splat(0);
    const native = @import("builtin").cpu.arch.endian();
    const len: u32 = 16 + if (payload) |p| @as(u32, @intCast(p.len)) else 0;
    std.mem.writeInt(u32, m[0..4], len, native);
    std.mem.writeInt(u16, m[4..6], codec.NLMSG_DONE, native);
    std.mem.writeInt(u32, m[8..12], 5, native); // seq
    std.mem.writeInt(u32, m[12..16], 9, native); // pid
    if (payload) |p| @memcpy(m[16..][0..p.len], p);
    return m;
}

fn classifyDone(bytes: []const u8) codec.DumpStep {
    var it: codec.MessageIterator = .{ .buf = bytes };
    const m = (it.next() catch unreachable).?;
    return codec.classifyDumpMessage(m, 9, 5);
}

test "NLMSG_DONE carrying a negative errno is a failed dump, not a complete one (sweep REV-1)" {
    const native = @import("builtin").cpu.arch.endian();
    var neg: [4]u8 = undefined;
    std.mem.writeInt(i32, &neg, -12, native);
    const with_err = doneMsg(&neg);
    switch (classifyDone(with_err[0..20])) {
        .failed => |c| try testing.expectEqual(@as(i32, -12), c),
        else => return error.TestExpectedFailed,
    }
    // No payload (old kernels), a zero payload, a short payload: complete.
    const bare = doneMsg(null);
    try testing.expect(classifyDone(bare[0..16]) == .done);
    var zero: [4]u8 = @splat(0);
    const z = doneMsg(&zero);
    try testing.expect(classifyDone(z[0..20]) == .done);
    const short = doneMsg(&.{ 0xff, 0xff });
    try testing.expect(classifyDone(short[0..18]) == .done);
    // A positive payload is not an error either.
    std.mem.writeInt(i32, &neg, 7, native);
    const pos = doneMsg(&neg);
    try testing.expect(classifyDone(pos[0..20]) == .done);
}
