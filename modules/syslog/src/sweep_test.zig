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
    g_rfd = fd;
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
    // Hard assertion (sweep audit GY-SL10): a Linux listener with a full accept
    // queue drops the SYN, so connects 2..16 must time out. A poll that reports
    // "ready" on a timeout would make every connect succeed (status 2).
    try testing.expectEqual(@as(u32, 0), try runChild(connectBlackhole));
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

// ── GY audit: recovery within the deadline, frame bytes, IPv6, refusal ──────

var g_rfd: linux.fd_t = -1;
const big_body: [1000]u8 = @splat('x');
const big_msg: message.Message = .{ .msg = &big_body };
const a_bytes: [3000]u8 = @splat('a');

fn sleepMs(ms: u32) void {
    const ts: linux.timespec = .{ .sec = 0, .nsec = @as(isize, @intCast(ms)) * 1_000_000 };
    _ = linux.nanosleep(&ts, null);
}

/// After `delay_ms`, read everything that arrives on `fd` until `stop`.
fn drainThread(fd: linux.fd_t, delay_ms: u32, stop: *std.atomic.Value(bool)) void {
    sleepMs(delay_ms);
    var buf: [65536]u8 = undefined;
    while (!stop.load(.acquire)) {
        const rc = linux.recvfrom(fd, &buf, buf.len, linux.MSG.DONTWAIT, null, null);
        if (linux.errno(rc) != .SUCCESS) sleepMs(1);
    }
}

fn openEmitter(comptime journal: bool) !(if (journal) unix.journal.Emitter else unix.UnixEmitter) {
    return if (journal) unix.journal.Emitter.open(gPath()) else unix.UnixEmitter.open(gPath());
}

fn sendOnce(comptime journal: bool, em: anytype) !void {
    if (journal) try em.sendMessage(.{ .message = &big_body }) else try em.send(&big_msg);
}

/// Exit 0: with a zero timeout the queue fills (WouldBlock); with a long one
/// and a reader that wakes up 40 ms later, the very next send gets through.
fn recoverImpl(comptime journal: bool) u8 {
    var em = openEmitter(journal) catch return 9;
    em.send_timeout_ms = 0;
    var full = false;
    for (0..100_000) |_| {
        sendOnce(journal, &em) catch |err| {
            if (err != error.WouldBlock) return 1;
            full = true;
            break;
        };
    }
    if (!full) return 2;
    em.send_timeout_ms = 20_000;
    var stop = std.atomic.Value(bool).init(false);
    const th = std.Thread.spawn(.{}, drainThread, .{ g_rfd, 40, &stop }) catch return 9;
    const r = sendOnce(journal, &em);
    stop.store(true, .release);
    th.join();
    r catch return 3;
    return 0;
}

fn recoverUnix() u8 {
    return recoverImpl(false);
}

fn recoverJournal() u8 {
    return recoverImpl(true);
}

test "UnixEmitter: a full queue that drains within the deadline lets the send through (sweep audit GY-SL2)" {
    try testing.expectEqual(@as(u32, 0), try withDeadReader(0, recoverUnix));
}

test "journal.Emitter: a full queue that drains within the deadline lets the send through (sweep audit GY-SL3)" {
    try testing.expectEqual(@as(u32, 0), try withDeadReader(0, recoverJournal));
}

/// Read exactly `out.len` bytes from `fd`, waiting at most ~3 s.
fn readExactly(fd: linux.fd_t, out: []u8) bool {
    var got: usize = 0;
    var waited: u32 = 0;
    while (got < out.len) {
        const rc = linux.recvfrom(fd, out[got..].ptr, out.len - got, linux.MSG.DONTWAIT, null, null);
        if (linux.errno(rc) == .SUCCESS and rc > 0) {
            got += rc;
            continue;
        }
        if (waited >= 3000) return false;
        sleepMs(1);
        waited += 1;
    }
    return true;
}

/// Exit 0: every frame arrives as `<len> <payload>` byte for byte (incl. the
/// 2048-byte maximum); an over-long message is NoSpaceLeft, writes nothing and
/// leaves the emitter usable.
fn frameContent() u8 {
    var threaded = std.Io.Threaded.init(std.heap.page_allocator, .{});
    const io = threaded.io();
    var addr: net.IpAddress = .{ .ip4 = .loopback(0) };
    var server = addr.listen(io, .{}) catch return 9;
    var em = transport.TcpEmitter.connect(io, server.socket.address) catch return 8;
    const peer = server.accept(io) catch return 9;
    // connectTimeout hands std a BLOCKING socket (std treats EAGAIN as a bug).
    const fl = linux.fcntl(em.stream.socket.handle, linux.F.GETFL, 0);
    if (linux.errno(fl) != .SUCCESS) return 9;
    if (fl & (1 << @bitOffsetOf(linux.O, "NONBLOCK")) != 0) return 12;
    var hb: [4096]u8 = undefined;
    // The longest body whose whole line still fits the emitter's 2048-byte scratch.
    var max_n: usize = 2048;
    while (max_n > 0) : (max_n -= 1) {
        const probe: message.Message = .{ .msg = a_bytes[0..max_n] };
        if (message.bufPrint(&probe, hb[0..2048])) |_| break else |_| {}
    }
    if (max_n == 0 or max_n == 2048) return 9;
    const sizes = [_]usize{ 0, 7, 120, max_n };
    for (sizes) |n| {
        const msg: message.Message = .{ .msg = a_bytes[0..n] };
        const payload = message.bufPrint(&msg, &hb) catch return 9;
        var eb: [4200]u8 = undefined;
        const exp = std.fmt.bufPrint(&eb, "{d} {s}", .{ payload.len, payload }) catch return 9;
        em.send(&msg) catch return 1;
        var got: [4200]u8 = undefined;
        if (!readExactly(peer.socket.handle, got[0..exp.len])) return 2;
        if (!std.mem.eql(u8, exp, got[0..exp.len])) return 3;
    }
    const over: message.Message = .{ .msg = a_bytes[0 .. max_n + 1] };
    if (em.send(&over)) |_| return 4 else |err| if (err != error.NoSpaceLeft) return 5;
    if (em.broken) return 6;
    const small: message.Message = .{ .msg = a_bytes[0..7] };
    const payload = message.bufPrint(&small, &hb) catch return 9;
    var eb: [64]u8 = undefined;
    const exp = std.fmt.bufPrint(&eb, "{d} {s}", .{ payload.len, payload }) catch return 9;
    em.send(&small) catch return 7;
    var got: [64]u8 = undefined;
    if (!readExactly(peer.socket.handle, got[0..exp.len])) return 10;
    if (!std.mem.eql(u8, exp, got[0..exp.len])) return 11;
    return 0;
}

test "TcpEmitter.send: frames arrive byte for byte, NoSpaceLeft writes nothing and keeps it usable (sweep audit GY-SL4)" {
    try testing.expectEqual(@as(u32, 0), try runChild(frameContent));
}

/// Exit 0: the send window is full; a long deadline plus a reader that wakes
/// up 40 ms later lets a whole 1800-byte frame through, emitter not broken.
fn windowRecovery() u8 {
    var threaded = std.Io.Threaded.init(std.heap.page_allocator, .{});
    const io = threaded.io();
    var addr: net.IpAddress = .{ .ip4 = .loopback(0) };
    var server = addr.listen(io, .{}) catch return 9;
    var em = transport.TcpEmitter.connect(io, server.socket.address) catch return 8;
    const peer = server.accept(io) catch return 9;
    const chunk: [4096]u8 = @splat(0);
    var sent: usize = 0;
    while (true) {
        const rc = linux.sendto(em.stream.socket.handle, &chunk, chunk.len, linux.MSG.DONTWAIT | linux.MSG.NOSIGNAL, null, 0);
        switch (linux.errno(rc)) {
            .SUCCESS => sent += rc,
            .AGAIN => break,
            else => return 9,
        }
        if (sent > (1 << 30)) return 9;
    }
    em.send_timeout_ms = 20_000;
    var stop = std.atomic.Value(bool).init(false);
    const th = std.Thread.spawn(.{}, drainThread, .{ peer.socket.handle, 40, &stop }) catch return 9;
    const body: [1800]u8 = @splat('y');
    const msg: message.Message = .{ .msg = &body };
    const r = em.send(&msg);
    stop.store(true, .release);
    th.join();
    r catch return 1;
    if (em.broken) return 2;
    return 0;
}

test "TcpEmitter.send: a full window that drains within the deadline lets a whole frame through (sweep audit GY-SL5)" {
    try testing.expectEqual(@as(u32, 0), try runChild(windowRecovery));
}

/// Exit 0: connect to a loopback port nobody listens on is ConnectionRefused.
fn refused() u8 {
    var threaded = std.Io.Threaded.init(std.heap.page_allocator, .{});
    const io = threaded.io();
    var addr: net.IpAddress = .{ .ip4 = .loopback(0) };
    var server = addr.listen(io, .{}) catch return 9;
    const target = server.socket.address;
    server.deinit(io);
    _ = transport.TcpEmitter.connectTimeout(io, target, 2000) catch |err| return if (err == error.ConnectionRefused) 0 else 1;
    return 2;
}

test "TcpEmitter.connectTimeout: a closed loopback port is ConnectionRefused (sweep audit GY-SL6)" {
    try testing.expectEqual(@as(u32, 0), try runChild(refused));
}

/// Exit 0: an IPv6 loopback connect works and a frame arrives; 77: no IPv6 here.
fn ipv6Frame() u8 {
    var threaded = std.Io.Threaded.init(std.heap.page_allocator, .{});
    const io = threaded.io();
    var addr: net.IpAddress = .{ .ip6 = .loopback(0) };
    var server = addr.listen(io, .{}) catch return 77;
    var em = transport.TcpEmitter.connect(io, server.socket.address) catch return 1;
    const peer = server.accept(io) catch return 9;
    const msg: message.Message = .{ .msg = "six" };
    var hb: [256]u8 = undefined;
    const payload = message.bufPrint(&msg, &hb) catch return 9;
    var eb: [300]u8 = undefined;
    const exp = std.fmt.bufPrint(&eb, "{d} {s}", .{ payload.len, payload }) catch return 9;
    em.send(&msg) catch return 2;
    var got: [300]u8 = undefined;
    if (!readExactly(peer.socket.handle, got[0..exp.len])) return 3;
    return if (std.mem.eql(u8, exp, got[0..exp.len])) 0 else 4;
}

test "TcpEmitter.connect: an IPv6 loopback address connects and carries a frame (sweep audit GY-SL7)" {
    const st = try runChild(ipv6Frame);
    if (st == 77) return error.SkipZigTest;
    try testing.expectEqual(@as(u32, 0), st);
}
