// SPDX-License-Identifier: MIT
//! No-panic sweep tests (wave GS), findings AS-1, REV-AS-1, REV-AS-2, round 2.
const std = @import("std");
const builtin = @import("builtin");
const linux = std.os.linux;
const testing = std.testing;
const argsafe = @import("root.zig");

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

// The needle lives in a constant, not in the `expectPanicMessage(...)` call line:
// the child's stack trace prints that source line, and a needle written there
// would match any panic at all.
const not_parsed = "argsafe: Template.fill on a Template that Template.parse did not accept";

// ── AS-1: Template.fill on a Template that never went through parse ────────

fn fillUnclosedBrace() void {
    const holes = [_]argsafe.Hole{.{ .name = "x", .class = .{} }};
    const t: argsafe.Template = .{ .tokens = &.{ "prog", "--a={x" }, .holes = &holes };
    const out = t.fill(std.heap.page_allocator, &.{"v"}) catch return;
    _ = out;
}

fn fillUnknownHole() void {
    const t: argsafe.Template = .{ .tokens = &.{ "prog", "{nope}" }, .holes = &.{} };
    const out = t.fill(std.heap.page_allocator, &.{}) catch return;
    _ = out;
}

test "Template.fill: a never-parsed template with an unclosed brace is a checked panic (sweep AS-1)" {
    try expectPanicMessage(fillUnclosedBrace, not_parsed);
}

test "Template.fill: a never-parsed template naming an undeclared hole is a checked panic (sweep AS-1)" {
    try expectPanicMessage(fillUnknownHole, not_parsed);
}

// ── REV-AS-1: a failed append poisons the builder ──────────────────────────

test "Argv: a swallowed OutOfMemory poisons the builder (sweep REV-AS-1)" {
    var fa = testing.FailingAllocator.init(testing.allocator, .{ .fail_index = 0 });
    var argv: argsafe.Argv = .empty;
    defer argv.deinit(fa.allocator());
    argv.push(fa.allocator(), "--") catch {};
    try testing.expectError(error.Rejected, argv.slice());

    var fb = testing.FailingAllocator.init(testing.allocator, .{ .fail_index = 0 });
    var a2: argsafe.Argv = .empty;
    defer a2.deinit(fb.allocator());
    a2.pushChecked(fb.allocator(), "ok", .{}) catch {};
    try testing.expectError(error.Rejected, a2.slice());

    var fc = testing.FailingAllocator.init(testing.allocator, .{ .fail_index = 0 });
    var a3: argsafe.Argv = .empty;
    defer a3.deinit(fc.allocator());
    a3.pushIf(fc.allocator(), "ok", argsafe.isSafeIdentifier) catch {};
    try testing.expectError(error.Rejected, a3.slice());
}

// ── REV-AS-2: separators and empty base64 ──────────────────────────────────

test "isSafeCidrList: a NUL, control, space or non-ASCII separator is refused (sweep REV-AS-2)" {
    const seps = [_]u8{ 0, 1, '\n', ' ', 0x7f, 0x80, 0xff };
    for (seps) |sep| try testing.expect(!argsafe.isSafeCidrList("10.0.0.0/8", sep));
    try testing.expect(argsafe.isSafeCidrList("10.0.0.0/8,fe80::/10", ','));
    try testing.expect(argsafe.isSafeCidrList("10.0.0.0/8;1.0.0.0/8", ';'));
}

test "isSafeBase64: the empty string is refused in both branches (sweep REV-AS-2)" {
    try testing.expect(!argsafe.isSafeBase64("", 0));
    try testing.expect(!argsafe.isSafeBase64("", null));
    try testing.expect(argsafe.isSafeBase64("QQ==", null));
}
