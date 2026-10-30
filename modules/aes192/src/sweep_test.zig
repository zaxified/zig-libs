// SPDX-License-Identifier: MIT

//! No-panic sweep tests (wave GU, gu-a). Every test name ends with its finding
//! ID; report: ~/CML/20261029-panic-sweep/aes192-sweep.report.md.

const std = @import("std");
const builtin = @import("builtin");
const linux = std.os.linux;
const testing = std.testing;
const root = @import("root.zig");

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

// Needles live in consts, never inline in the call: the forked child's stack
// trace prints the caller's source line, so an inline needle matches ANY panic.
const needle_ctr = "aes192: ctr dst shorter than src";
const needle_wrong = "aes192: this text is not in any panic";

fn expectPanicMessage(comptime body: fn () void, needle: []const u8) !void {
    var buf: [8192]u8 = undefined;
    const c = try runChild(body, &buf);
    try testing.expect(c.died);
    try testing.expect(std.mem.find(u8, buf[0..c.len], needle) != null);
}

const key: [24]u8 = @splat(9);
const iv: [16]u8 = @splat(1);

fn ctrShortDst() void {
    const ctx = root.Aes192.initEnc(key);
    var dst: [31]u8 = undefined;
    const src: [32]u8 = @splat(0);
    ctx.ctr(&dst, &src, iv);
}

fn ctrEmptyDst() void {
    const ctx = root.Aes192.initEnc(key);
    var dst: [0]u8 = undefined;
    ctx.ctr(&dst, "x", iv);
}

test "ctr: a dst shorter than src is a checked aes192 panic (sweep A9-1)" {
    const ctx = root.Aes192.initEnc(key);
    // dst longer than src is fine and touches only src.len bytes.
    var dst: [40]u8 = @splat(0xee);
    const src: [32]u8 = @splat(0);
    ctx.ctr(&dst, &src, iv);
    for (dst[32..]) |b| try testing.expectEqual(@as(u8, 0xee), b);
    // The needle can fail: a wrong one does not match the real panic.
    try testing.expectError(error.TestUnexpectedResult, expectPanicMessage(ctrShortDst, needle_wrong));
    try expectPanicMessage(ctrShortDst, needle_ctr);
    try expectPanicMessage(ctrEmptyDst, needle_ctr);
}
