// SPDX-License-Identifier: MIT

//! No-panic sweep tests (wave GQ). Names end with "(sweep <ID>)".

const std = @import("std");
const builtin = @import("builtin");
const fastmem = @import("root.zig");

const linux = std.os.linux;

/// Run `body` in a forked child and require that it dies of a signal (a
/// panic aborts). A child that returns, or runs past five seconds, fails.
fn expectChildDies(comptime body: fn () void) !void {
    if (builtin.os.tag != .linux) return error.SkipZigTest;
    const rc = linux.fork();
    if (linux.errno(rc) != .SUCCESS) return error.SkipZigTest;
    if (rc == 0) {
        body();
        linux.exit_group(0);
    }
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
    if (!linux.W.IFSIGNALED(status)) return error.ChildDidNotDie;
}

fn memsetNullBody() void {
    var n: usize = 1;
    _ = &n;
    _ = fastmem.memset(null, 0, n);
}

fn memcpyNullDestBody() void {
    var n: usize = 1;
    _ = &n;
    var src: [1]u8 = .{0};
    _ = fastmem.memcpy(null, &src, n);
}

fn memcpyNullSrcBody() void {
    var n: usize = 1;
    _ = &n;
    var dst: [1]u8 = .{0};
    _ = fastmem.memcpy(&dst, null, n);
}

test "memset/memcpy: a null pointer with a non-zero length traps, not a null access (sweep FM-1)" {
    try expectChildDies(memsetNullBody);
    try expectChildDies(memcpyNullDestBody);
    try expectChildDies(memcpyNullSrcBody);
}

test "memset/memcpy: a null pointer with len 0 stays a no-op (sweep FM-1)" {
    try std.testing.expectEqual(@as(?[*]u8, null), fastmem.memset(null, 1, 0));
    var b: [1]u8 = .{7};
    try std.testing.expectEqual(@as(?[*]u8, null), fastmem.memcpy(null, &b, 0));
    try std.testing.expectEqual(@as(?[*]u8, &b), fastmem.memcpy(&b, null, 0));
    try std.testing.expectEqual(@as(u8, 7), b[0]);
}
