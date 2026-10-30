// SPDX-License-Identifier: MIT
//! No-panic sweep tests (wave GV) for nftables' public API.
//! Findings NF-1 .. NF-6, see ~/CML/20261029-panic-sweep/nftables-sweep.report.md.
//! Tests that need the private reply engines sit at the end of socket.zig.
const std = @import("std");
const builtin = @import("builtin");
const linux = std.os.linux;
const testing = std.testing;
const wire = @import("wire.zig");

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

// Needle in a const, never inline in the call (the child's stack trace prints the caller's source line).
const needle_batch = "nftables: Batch command after finish()";

fn expectPanicMessage(comptime body: fn () void, needle: []const u8) !void {
    var buf: [8192]u8 = undefined;
    const c = try runChild(body, &buf);
    try testing.expect(c.died);
    try testing.expect(std.mem.find(u8, buf[0..c.len], needle) != null);
}

fn commandAfterFinish() void {
    var b = wire.Batch.init(std.heap.page_allocator, 1, .{}) catch return;
    _ = b.finish() catch return;
    b.addTable(.{ .family = .inet, .name = "t" }) catch return;
}

test "a Batch command after finish() is a checked nftables panic (sweep NF-6)" {
    // The same calls in the right order are fine.
    var ok = try wire.Batch.init(testing.allocator, 1, .{});
    defer ok.deinit();
    try ok.addTable(.{ .family = .inet, .name = "t" });
    _ = try ok.finish();
    try expectPanicMessage(commandAfterFinish, needle_batch);
}

test "addSetElems: more than 65535 elements is AttrTooLong, not an unchecked index cast (sweep NF-5)" {
    var b = try wire.Batch.init(testing.allocator, 1, .{});
    defer b.deinit();
    const n = 65536;
    const elems = try testing.allocator.alloc(wire.SetElem, n);
    defer testing.allocator.free(elems);
    @memset(elems, .{ .key = "" });
    try testing.expectError(error.AttrTooLong, b.addSetElems(.inet, "t", "s", null, elems));
}
