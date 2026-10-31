// SPDX-License-Identifier: MIT
//! No-panic sweep tests (wave GZ). Each test names the finding it kills. The
//! reply-walk hostile inputs (ctrlGetFamilyOver is private) are pinned in
//! root.zig's own test section, "(sweep clean)".

const std = @import("std");
const builtin = @import("builtin");
const linux = std.os.linux;
const testing = std.testing;
const genetlink = @import("root.zig");

/// Run `body` in a forked child with its stderr captured into `buf`; returns
/// the captured length and whether the child died from a signal (a panic
/// aborts). A child past five seconds counts as hung.
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

fn expectPanicMessage(comptime body: fn () void, needle: []const u8) !void {
    var buf: [8192]u8 = undefined;
    const c = try runChild(body, &buf);
    try testing.expect(c.died);
    try testing.expect(std.mem.find(u8, buf[0..c.len], needle) != null);
}

// Needles live in consts, never inline in the expectPanicMessage call: the
// child's stack trace prints the caller's source line (GS trap).
const needle_batch = "panic: genetlink: resolveMcastGroups: names.len != out.len";

/// A Socket that was never opened: fd -1, so a request that reaches `send`
/// fails with `SendFailed` and one that is rejected earlier never does.
fn closedSocket(buf: []u8) genetlink.Socket {
    return .{ .gpa = testing.allocator, .fd = -1, .portid = 1, .seq = 0, .buf = buf };
}

fn childBatchShortOut() void {
    var empty: [0]u8 = .{};
    var s = closedSocket(&empty);
    var out: [1]?u32 = undefined;
    const names: []const []const u8 = &.{ "a", "b" };
    _ = s.resolveMcastGroups("nl80211", names, &out) catch {};
}

fn childBatchLongOut() void {
    var empty: [0]u8 = .{};
    var s = closedSocket(&empty);
    var out: [3]?u32 = undefined;
    const names: []const []const u8 = &.{"a"};
    _ = s.resolveMcastGroups("nl80211", names, &out) catch {};
}

test "resolveMcastGroups with names.len != out.len is a checked panic (sweep GN-1)" {
    try expectPanicMessage(childBatchShortOut, needle_batch);
    try expectPanicMessage(childBatchLongOut, needle_batch);

    // Positive control through the same entry point: equal lengths pass the
    // check (the closed socket then fails at send, a typed error).
    var empty: [0]u8 = .{};
    var s = closedSocket(&empty);
    var out: [2]?u32 = undefined;
    const names: []const []const u8 = &.{ "a", "b" };
    try testing.expectError(error.SendFailed, s.resolveMcastGroups("nl80211", names, &out));
    try testing.expectEqual(@as(?u32, null), out[0]);
    try testing.expectEqual(@as(?u32, null), out[1]);
    // Zero names: nothing to look up, equal (zero) lengths.
    try testing.expectError(error.SendFailed, s.resolveMcastGroups("nl80211", &.{}, out[0..0]));
}
