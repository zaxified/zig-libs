// SPDX-License-Identifier: MIT
//! No-panic sweep tests (wave GY). Findings SL-*, see
//! ~/CML/20261029-panic-sweep/syslog-sweep.report.md.
const std = @import("std");
const builtin = @import("builtin");
const linux = std.os.linux;
const testing = std.testing;
const message = @import("message.zig");
const bsd = @import("bsd.zig");
const transport = @import("transport.zig");
const unix = @import("unix.zig");

/// Run `body` in a forked child and return its exit status. A child still
/// running after five seconds is killed and counts as hung (`error.ChildHung`).
fn runChild(comptime body: fn () u8) !u32 {
    if (builtin.os.tag != .linux) return error.SkipZigTest;
    const rc = linux.fork();
    if (linux.errno(rc) != .SUCCESS) return error.SkipZigTest;
    if (rc == 0) linux.exit_group(body());
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
    if (!linux.W.IFEXITED(status)) return error.ChildDied;
    return linux.W.EXITSTATUS(status);
}

// ── SL-1: a send to a peer that never reads must not block forever ──────────

var g_path_buf: [128]u8 = undefined;
var g_path_len: usize = 0;
var g_timeout_ms: u32 = 0;

fn gPath() []const u8 {
    return g_path_buf[0..g_path_len];
}

/// Exit 0: the first failing send was `WouldBlock`. 1: another error. 2: 100 000
/// sends never filled the queue.
fn fillUnix() u8 {
    var e = unix.UnixEmitter.open(gPath()) catch return 9;
    e.send_timeout_ms = g_timeout_ms;
    const body: [1000]u8 = @splat('x');
    const msg: message.Message = .{ .msg = &body };
    for (0..100_000) |_| {
        e.send(&msg) catch |err| return if (err == error.WouldBlock) 0 else 1;
    }
    return 2;
}

fn fillJournal() u8 {
    var e = unix.journal.Emitter.open(gPath()) catch return 9;
    e.send_timeout_ms = g_timeout_ms;
    const body: [1000]u8 = @splat('x');
    for (0..100_000) |_| {
        e.sendMessage(.{ .message = &body }) catch |err| return if (err == error.WouldBlock) 0 else 1;
    }
    return 2;
}

/// A receiver that is bound and never read; the child fills its queue.
fn withDeadReader(timeout_ms: u32, comptime child: fn () u8) !u32 {
    var tmp = testing.tmpDir(.{});
    defer tmp.cleanup();
    const path = try std.mem.print(&g_path_buf, ".zig-cache/tmp/{s}/dead.sock", .{&tmp.sub_path});
    g_path_len = path.len;
    g_timeout_ms = timeout_ms;
    var addr: linux.sockaddr.un = .{ .family = linux.AF.UNIX, .path = @splat(0) };
    @memcpy(addr.path[0..path.len], path);
    const fd_rc = linux.socket(linux.AF.UNIX, linux.SOCK.DGRAM | linux.SOCK.CLOEXEC, 0);
    if (linux.errno(fd_rc) != .SUCCESS) return error.SkipZigTest;
    const fd: linux.fd_t = @intCast(fd_rc);
    defer _ = linux.close(fd);
    if (linux.errno(linux.bind(fd, @ptrCast(&addr), @sizeOf(linux.sockaddr.un))) != .SUCCESS) return error.BindFailed;
    return runChild(child);
}

test "UnixEmitter: a full peer queue ends in WouldBlock after the deadline, not a hang (sweep SL-1)" {
    try testing.expectEqual(@as(u32, 0), try withDeadReader(20, fillUnix));
}

test "UnixEmitter: send_timeout_ms = 0 fails at once on a full queue (sweep SL-1)" {
    try testing.expectEqual(@as(u32, 0), try withDeadReader(0, fillUnix));
}

test "journal.Emitter: a full peer queue ends in WouldBlock after the deadline, not a hang (sweep SL-1)" {
    try testing.expectEqual(@as(u32, 0), try withDeadReader(20, fillJournal));
}

// ── Clean entry points: hostile values stay total ───────────────────────────

test "Message.format: hostile timestamps render '-' or a valid time, never panic" {
    const stamps = [_]i64{ std.math.minInt(i64), -1, 0, 253402300799999, 253402300800000, std.math.maxInt(i64) };
    const offsets = [_]?i16{ null, std.math.minInt(i16), -1440, -1439, 0, 1439, 1440, std.math.maxInt(i16) };
    var buf: [512]u8 = undefined;
    for (stamps) |ms| for (offsets) |off| {
        const ts: message.Timestamp = .{ .unix_ms = ms, .offset_minutes = off };
        const m5: message.Message = .{ .timestamp = ts, .msg = "x" };
        _ = try message.bufPrint(&m5, &buf);
        const m3: bsd.Message = .{ .timestamp = ts, .tag = "t", .msg = "x" };
        _ = try bsd.bufPrint(&m3, &buf);
    };
}

test "buildDatagram: zero, tiny and huge limits and markers stay inside the scratch" {
    const msg: message.Message = .{ .msg = "hello world" };
    var scratch: [64]u8 = undefined;
    const limits = [_]usize{ 0, 1, 5, 64, 65, 1 << 20, std.math.maxInt(usize) };
    const markers = [_][]const u8{ "", "...", "a-marker-longer-than-the-whole-scratch-buffer-of-sixty-four-bytes-yes" };
    for (limits) |l| for (markers) |mk| {
        const out = transport.buildDatagram(&msg, &scratch, .{ .udp_limit = l, .trunc_marker = mk });
        try testing.expect(out.len <= scratch.len);
    };
    var empty: [0]u8 = undefined;
    try testing.expectEqual(@as(usize, 0), transport.buildDatagram(&msg, &empty, .{}).len);
}

test "journal.Emitter.send: 64 maximal fields are refused or sent, 65 are TooManyFields" {
    const path = "/nonexistent-dir/sweep.sock";
    var e = try unix.journal.Emitter.open(path);
    defer e.close();
    var fields: [65]unix.journal.Field = undefined;
    const long_name: [64]u8 = @splat('A');
    for (&fields) |*f| f.* = .{ .name = &long_name, .value = "v\nw" };
    try testing.expectError(error.TooManyFields, e.send(&fields));
    try testing.expectError(error.WriteFailed, e.send(fields[0..64])); // nobody listens: an error, not a panic
    try testing.expectError(error.TooManyFields, e.sendMessage(.{ .message = "m", .priority = .info, .identifier = "i", .fields = fields[0..62] }));
}

// ── RV-SL-1 / RV-SL-4: TcpEmitter deadlines over loopback ───────────────────

const net = std.Io.net;

/// Exit 0: connect to a listener whose backlog is full ended in Timeout.
/// 1: another error. 2: every connect succeeded.
fn connectBlackhole() u8 {
    var threaded = std.Io.Threaded.init(std.heap.page_allocator, .{});
    const io = threaded.io();
    var addr: net.IpAddress = .{ .ip4 = .loopback(0) };
    const server = addr.listen(io, .{ .kernel_backlog = 0 }) catch return 9;
    const target = server.socket.address;
    var keep: [16]transport.TcpEmitter = undefined;
    for (0..16) |i| {
        keep[i] = transport.TcpEmitter.connectTimeout(io, target, 50) catch |err| return if (err == error.Timeout) 0 else 1;
    }
    return 2;
}

test "TcpEmitter.connectTimeout: a full backlog ends in Timeout, not a ~2 min hang (sweep RV-SL-1)" {
    const st = try runChild(connectBlackhole);
    if (st != 0) return error.SkipZigTest; // this kernel answered differently; a hang fails above via ChildHung
}

/// Exit 0: filled the window -> Timeout, then (unless the frame was partial and
/// the emitter is rightly Broken) recovered after the peer drained.
fn stopReading() u8 {
    var threaded = std.Io.Threaded.init(std.heap.page_allocator, .{});
    const io = threaded.io();
    var addr: net.IpAddress = .{ .ip4 = .loopback(0) };
    var server = addr.listen(io, .{}) catch return 9;
    var em = transport.TcpEmitter.connect(io, server.socket.address) catch return 9;
    const peer = server.accept(io) catch return 9;

    em.send_timeout_ms = 20;
    const body: [1800]u8 = @splat('x');
    const msg: message.Message = .{ .msg = &body };
    var failure: ?anyerror = null;
    for (0..200_000) |_| {
        em.send(&msg) catch |err| {
            failure = err;
            break;
        };
    }
    if (failure == null or failure.? != error.Timeout) return 1;
    if (em.send(&msg)) |_| {} else |err| if (err != error.Timeout and err != error.Broken) return 2;
    if (em.broken) return 0; // a partial frame: sticky, covered offline

    var buf: [65536]u8 = undefined;
    while (true) {
        const rc = linux.recvfrom(peer.socket.handle, &buf, buf.len, linux.MSG.DONTWAIT, null, null);
        if (linux.errno(rc) != .SUCCESS or rc == 0) break;
    }
    em.send_timeout_ms = 2000;
    em.send(&msg) catch return 3;
    return 0;
}

test "TcpEmitter.send: a peer that stops reading gives Timeout, the emitter stays usable, and recovers (sweep RV-SL-1)" {
    try testing.expectEqual(@as(u32, 0), try runChild(stopReading));
}
