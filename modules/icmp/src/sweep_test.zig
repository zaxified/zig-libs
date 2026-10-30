// SPDX-License-Identifier: MIT

//! No-panic sweep (wave GO) regression tests. Every test name ends with the
//! finding id. The engine is driven through its public `prepare`/`step` with
//! hand-placed state: a socket with fd -1 (sends fail at once, no network),
//! or a loopback UDP socket pair where a reply has to be injected.

const std = @import("std");
const linux = std.os.linux;
const icmp = @import("root.zig");
const echo = icmp.echo;
const Socket = icmp.Socket;
const IoSocket = icmp.IoSocket;
const Pinger = icmp.Pinger;
const seqmap = @import("seqmap");

const max_u32 = std.math.maxInt(u32);

fn deadSocket() Socket {
    return .{ .fd = -1, .family = .v4, .kind = .dgram, .ident = 0x1234 };
}

fn v4(port_be: u16, last: u8) icmp.Addr {
    return .{ .v4 = .{ .port = port_be, .addr = std.mem.bytesToValue(u32, &[4]u8{ 127, 0, 0, last }) } };
}

/// Two loopback UDP sockets: `fd` is the "ICMP socket" the pinger reads and
/// sends on, `inj` injects crafted packets into it.
const Rig = struct {
    fd: i32,
    inj: i32,
    fd_port: u16, // network order
    inj_port: u16,

    fn bound() !struct { fd: i32, port: u16 } {
        const rc = linux.socket(linux.AF.INET, linux.SOCK.DGRAM | linux.SOCK.NONBLOCK | linux.SOCK.CLOEXEC, 0);
        if (linux.errno(rc) != .SUCCESS) return error.SkipZigTest;
        const fd: i32 = @intCast(rc);
        errdefer _ = linux.close(fd);
        const sa = v4(0, 1).v4;
        if (linux.errno(linux.bind(fd, @ptrCast(&sa), @sizeOf(linux.sockaddr.in))) != .SUCCESS) return error.SkipZigTest;
        var out: linux.sockaddr.in = undefined;
        var len: linux.socklen_t = @sizeOf(linux.sockaddr.in);
        if (linux.errno(linux.getsockname(fd, @ptrCast(&out), &len)) != .SUCCESS) return error.SkipZigTest;
        return .{ .fd = fd, .port = out.port };
    }

    fn open() !Rig {
        const a = try bound();
        errdefer _ = linux.close(a.fd);
        const b = try bound();
        return .{ .fd = a.fd, .inj = b.fd, .fd_port = a.port, .inj_port = b.port };
    }

    fn close(r: *Rig) void {
        _ = linux.close(r.fd);
        _ = linux.close(r.inj);
    }

    fn socket(r: Rig) Socket {
        return .{ .fd = r.fd, .family = .v4, .kind = .dgram, .ident = 0x1234 };
    }

    fn inject(r: Rig, bytes: []const u8) !void {
        const to = v4(r.fd_port, 1).v4;
        const rc = linux.sendto(r.inj, bytes.ptr, bytes.len, 0, @ptrCast(&to), @sizeOf(linux.sockaddr.in));
        if (linux.errno(rc) != .SUCCESS) return error.SkipZigTest;
    }
};

fn replyPacket(seq: u16) [echo.echo_header_len]u8 {
    var pkt: [echo.echo_header_len]u8 = @splat(0);
    pkt[0] = echo.v4.echo_reply;
    std.mem.writeInt(u16, pkt[4..6], 0x1234, .big);
    std.mem.writeInt(u16, pkt[6..8], seq, .big);
    std.mem.writeInt(u16, pkt[2..4], echo.checksum(&pkt), .big);
    return pkt;
}

fn errorPacket(seq: u16) [echo.echo_header_len + 20 + echo.echo_header_len]u8 {
    var pkt: [echo.echo_header_len + 20 + echo.echo_header_len]u8 = @splat(0);
    pkt[0] = echo.v4.time_exceeded;
    pkt[8] = 0x45;
    const orig = pkt[28..];
    orig[0] = echo.v4.echo_request;
    std.mem.writeInt(u16, orig[4..6], 0x1234, .big);
    std.mem.writeInt(u16, orig[6..8], seq, .big);
    std.mem.writeInt(u16, pkt[2..4], echo.checksum(&pkt), .big);
    return pkt;
}

test "max_inflight = 0 still sends instead of spinning (sweep IC-1)" {
    var p = try Pinger.init(std.testing.allocator, .{ .max_inflight = 0, .interval_ns = 0, .retries = 0 });
    defer p.deinit();
    _ = try p.addTarget("192.0.2.1");
    p.sock4 = .{ .os = deadSocket() };
    try p.prepare();
    _ = try p.step();
    // Unfixed: nothing is ever sent and step() keeps returning a zero wait.
    try std.testing.expectEqual(@as(u32, 1), p.stats(0).sent);
}

test "jitter_ns above maxInt(i64) does not overflow (sweep IC-2)" {
    var p = try Pinger.init(std.testing.allocator, .{ .jitter_ns = std.math.maxInt(u64) });
    defer p.deinit();
    _ = try p.addTarget("192.0.2.1");
    p.sock4 = .{ .os = deadSocket() };
    // Half of the u64 draws exceed maxInt(i64); 64 prepares make a miss 2^-64.
    for (0..64) |_| try p.prepare();
}

test "Config durations above maxInt(i64) do not overflow (sweep IC-2)" {
    // Global interval.
    {
        var p = try Pinger.init(std.testing.allocator, .{ .interval_ns = std.math.maxInt(u64) });
        defer p.deinit();
        _ = try p.addTarget("192.0.2.1");
        p.sock4 = .{ .os = deadSocket() };
        try p.prepare();
        const deadline = try p.step();
        try std.testing.expect(deadline != null);
        try std.testing.expectEqual(@as(u32, 0), p.stats(0).sent);
    }
    // perhost, timeout and subnet gap, through a send that succeeds.
    var rig = try Rig.open();
    defer rig.close();
    var p = try Pinger.init(std.testing.allocator, .{
        .mode = .count,
        .count = 2,
        .interval_ns = 0,
        .perhost_interval_ns = std.math.maxInt(u64),
        .timeout_ns = std.math.maxInt(u64),
        .subnet_gap_ns = std.math.maxInt(u64),
    });
    defer p.deinit();
    _ = try p.addTargetAddr(v4(rig.inj_port, 1));
    _ = try p.addTargetAddr(v4(rig.inj_port, 1)); // same /24: sees the first one's send
    p.sock4 = .{ .os = rig.socket() };
    try p.prepare();
    _ = try p.step();
    try std.testing.expectEqual(@as(u32, 1), p.stats(0).sent);
    // Global pacing with a huge interval after a send: `last_send_ns + interval`.
    p.cfg.interval_ns = std.math.maxInt(u64);
    try p.ping_q.push(p.gpa, .{ .time = icmp.monoNow(), .target = 0, .probe = 1 });
    _ = try p.step();
}

test "retries = 65535 does not overflow the probe index (sweep IC-7)" {
    var p = try Pinger.init(std.testing.allocator, .{ .retries = 65535, .interval_ns = 0 });
    defer p.deinit();
    _ = try p.addTarget("192.0.2.1");
    p.sock4 = .{ .os = deadSocket() };
    const now = icmp.monoNow();
    const seq = try p.seqmap.add(0, 65535, now);
    p.targets.items[0].pending = 1;
    p.inflight = 1;
    try p.timeout_q.push(p.gpa, .{ .time = now - 1, .target = 0, .probe = 65535, .seq = seq });
    _ = try p.step(); // unfixed: `ev.probe + 1` overflows in handleTimeout
    try std.testing.expectEqual(@as(u32, 1), p.stats(0).sent);
}

const Adder = struct {
    p: *Pinger,
    calls: usize = 0,

    fn cb(ctx: ?*anyopaque, id: icmp.TargetId, probe: u16, outcome: icmp.Outcome) void {
        _ = outcome;
        _ = id;
        _ = probe;
        const self: *Adder = @ptrCast(@alignCast(ctx.?));
        if (self.calls != 0) return;
        self.calls += 1;
        // Enough to move the `targets` buffer to a different allocation.
        for (0..300) |_| _ = self.p.addTarget("192.0.2.9") catch {};
    }
};

test "a result callback that adds targets does not corrupt the engine (sweep IC-4)" {
    var p = try Pinger.init(std.testing.allocator, .{ .retries = 3, .interval_ns = 0 });
    defer p.deinit();
    _ = try p.addTarget("192.0.2.1");
    p.sock4 = .{ .os = deadSocket() };
    var adder: Adder = .{ .p = &p };
    p.setResultCallback(&adder, Adder.cb);
    const now = icmp.monoNow();
    const seq = try p.seqmap.add(0, 0, now);
    p.targets.items[0].pending = 1;
    p.inflight = 1;
    try p.timeout_q.push(p.gpa, .{ .time = now - 1, .target = 0, .probe = 0, .seq = seq });
    _ = try p.step();
    try std.testing.expectEqual(@as(usize, 1), adder.calls);
    // The retry was scheduled (and sent, interval 0) from the re-fetched
    // target: unfixed, the stale pointer reads freed memory.
    try std.testing.expectEqual(@as(u32, 1), p.stats(0).sent);
}

test "a callback that adds targets on a send error leaves the target's state intact (sweep IC-4)" {
    var p = try Pinger.init(std.testing.allocator, .{ .retries = 0, .interval_ns = 0 });
    defer p.deinit();
    _ = try p.addTarget("192.0.2.1");
    p.sock4 = .{ .os = deadSocket() };
    var adder: Adder = .{ .p = &p };
    p.setResultCallback(&adder, Adder.cb);
    try p.prepare();
    _ = try p.step();
    try std.testing.expectEqual(@as(usize, 1), adder.calls);
    try std.testing.expect(p.targets.items[0].done); // unfixed: written to the freed buffer
}

test "a callback that adds targets on a reply leaves the target's state intact (sweep IC-4)" {
    var rig = try Rig.open();
    defer rig.close();
    var p = try Pinger.init(std.testing.allocator, .{ .check_source = false, .interval_ns = 0 });
    defer p.deinit();
    _ = try p.addTargetAddr(v4(rig.inj_port, 1));
    p.sock4 = .{ .os = rig.socket() };
    var adder: Adder = .{ .p = &p };
    p.setResultCallback(&adder, Adder.cb);
    const seq = try p.seqmap.add(0, 0, icmp.monoNow());
    p.targets.items[0].pending = 1;
    p.inflight = 1;
    try rig.inject(&replyPacket(seq));
    _ = try p.step();
    try std.testing.expectEqual(@as(usize, 1), adder.calls);
    try std.testing.expect(p.targets.items[0].done);
}

test "Stats counters saturate instead of overflowing (sweep IC-5)" {
    var rig = try Rig.open();
    defer rig.close();
    var p = try Pinger.init(std.testing.allocator, .{ .check_source = false, .interval_ns = 0 });
    defer p.deinit();
    _ = try p.addTargetAddr(v4(rig.inj_port, 1));
    p.sock4 = .{ .os = rig.socket() };
    const t = &p.targets.items[0];

    // recv, then duplicates (the slot stays answered), then icmp_errors.
    const seq = try p.seqmap.add(0, 0, icmp.monoNow());
    t.pending = 1;
    p.inflight = 1;
    t.stats.recv = max_u32;
    t.stats.duplicates = max_u32;
    t.stats.icmp_errors = max_u32;
    try rig.inject(&replyPacket(seq));
    _ = try p.step();
    try rig.inject(&replyPacket(seq));
    _ = try p.step();
    try rig.inject(&errorPacket(seq));
    _ = try p.step();
    try std.testing.expectEqual(max_u32, p.stats(0).recv);
    try std.testing.expectEqual(max_u32, p.stats(0).duplicates);
    try std.testing.expectEqual(max_u32, p.stats(0).icmp_errors);

    // sent: one more probe.
    t.stats.sent = max_u32;
    try p.ping_q.push(p.gpa, .{ .time = icmp.monoNow(), .target = 0, .probe = 1 });
    _ = try p.step();
    try std.testing.expectEqual(max_u32, p.stats(0).sent);
}

test "source_mismatches and send_errors saturate (sweep IC-5)" {
    var rig = try Rig.open();
    defer rig.close();
    var p = try Pinger.init(std.testing.allocator, .{ .check_source = true, .interval_ns = 0 });
    defer p.deinit();
    _ = try p.addTargetAddr(v4(rig.inj_port, 2)); // replies come from 127.0.0.1
    p.sock4 = .{ .os = rig.socket() };
    const seq = try p.seqmap.add(0, 0, icmp.monoNow());
    p.targets.items[0].pending = 1;
    p.inflight = 1;
    p.targets.items[0].stats.source_mismatches = max_u32;
    try rig.inject(&replyPacket(seq));
    _ = try p.step();
    try std.testing.expectEqual(max_u32, p.stats(0).source_mismatches);

    p.sock4 = .{ .os = deadSocket() };
    p.targets.items[0].stats.send_errors = max_u32;
    try p.ping_q.push(p.gpa, .{ .time = icmp.monoNow(), .target = 0, .probe = 1 });
    _ = try p.step();
    try std.testing.expectEqual(max_u32, p.stats(0).send_errors);
}

test "Stats.lost with recv > sent does not underflow (sweep IC-6)" {
    const s: icmp.Stats = .{ .sent = 1, .recv = 5 };
    try std.testing.expectEqual(@as(u32, 0), s.lost());
    try std.testing.expectEqual(@as(u32, 0), s.lossPermille());
}

test "oiface_index >= 2^31 is an error from the kernel, not a cast panic (sweep IC-8)" {
    var s = deadSocket();
    s.oiface_index = 0x8000_0000;
    const sa = v4(0, 1).v4;
    const addr: *const linux.sockaddr = @ptrCast(&sa);
    try std.testing.expectError(error.Unexpected, s.sendTo(addr, @sizeOf(linux.sockaddr.in), "x"));
    const addrs = [_]*const linux.sockaddr{addr};
    const pkts = [_][]const u8{"x"};
    try std.testing.expectEqual(@as(usize, 0), try s.sendMany(&addrs, @sizeOf(linux.sockaddr.in), &pkts));
}

test "recvBatch slot_size that wraps batch_max * slot_size is rejected (sweep IC-10)" {
    var slab: [16]u8 = undefined;
    var b: Socket.RecvBatch = .{ .slab = &slab, .slot_size = @as(usize, 1) << (@bitSizeOf(usize) - 4) };
    const s = deadSocket();
    try std.testing.expectError(error.SlabTooSmall, s.recvBatch(&b));
    var io_sock: IoSocket = undefined; // the size check runs before any use
    try std.testing.expectError(error.SlabTooSmall, io_sock.recvBatch(&b));
}

// ── IC-3: subnet pacing ─────────────────────────────────────────────────────

fn sleepUntil(deadline_ns: i64) void {
    const d = deadline_ns - icmp.monoNow();
    if (d <= 0) return;
    var req: linux.timespec = .{ .sec = @intCast(@divTrunc(d, std.time.ns_per_s)), .nsec = @intCast(@mod(d, std.time.ns_per_s)) };
    _ = linux.nanosleep(&req, null);
}

fn threadCpuNs() u64 {
    var ts: linux.timespec = undefined;
    _ = linux.clock_gettime(.THREAD_CPUTIME_ID, &ts);
    return @as(u64, @intCast(ts.sec)) * std.time.ns_per_s + @as(u64, @intCast(ts.nsec));
}

/// `n` targets in one /24, sends failing at once. Returns the CPU time spent
/// and appends the send instants (`last_send_ns` after each step that sent).
fn runBucket(n: usize, gap_ns: u64, sends: ?*std.ArrayList(i64)) !u64 {
    var p = try Pinger.init(std.testing.allocator, .{ .interval_ns = 0, .subnet_gap_ns = gap_ns, .retries = 0 });
    defer p.deinit();
    for (0..n) |_| _ = try p.addTarget("192.0.2.1");
    p.sock4 = .{ .os = deadSocket() };
    const cpu0 = threadCpuNs();
    try p.prepare();
    var prev = p.last_send_ns;
    while (try p.step()) |deadline| {
        if (p.last_send_ns != prev) {
            prev = p.last_send_ns;
            if (sends) |l| try l.append(std.testing.allocator, prev);
        }
        sleepUntil(deadline);
    }
    if (p.last_send_ns != prev) if (sends) |l| try l.append(std.testing.allocator, p.last_send_ns);
    const used = threadCpuNs() - cpu0;
    var total: u64 = 0;
    for (p.targets.items) |t| total += t.stats.sent;
    try std.testing.expectEqual(@as(u64, n), total);
    return used;
}

test "subnet pacing work is linear in the targets of one bucket (sweep IC-3)" {
    // N vs 4N: linear ~4x, the old per-send re-deferral of every other event
    // ~16x. CPU time of the thread (the waits are sleeps, not work).
    const gap = 400 * std.time.ns_per_us;
    var best_small: u64 = std.math.maxInt(u64);
    var best_big: u64 = std.math.maxInt(u64);
    for (0..2) |_| {
        best_small = @min(best_small, try runBucket(250, gap, null));
        best_big = @min(best_big, try runBucket(1000, gap, null));
    }
    try std.testing.expect(best_big < 9 * best_small);
}

test "subnet pacing still spaces sends of one bucket by the gap (sweep IC-3)" {
    const gap: i64 = 2 * std.time.ns_per_ms;
    var sends: std.ArrayList(i64) = .empty;
    defer sends.deinit(std.testing.allocator);
    _ = try runBucket(8, @intCast(gap), &sends);
    try std.testing.expectEqual(@as(usize, 8), sends.items.len);
    for (sends.items[1..], 0..) |t, i| {
        try std.testing.expect(t - sends.items[i] >= gap);
    }
}

// ── review fixes D1-D6 ──────────────────────────────────────────────────────

test "a saturated subnet bucket does not keep its consumed waiters (sweep D1)" {
    // 32 targets in one /24, a gap far longer than the per-host interval:
    // the bucket never drains, every send promotes one waiter and queues the
    // sender's next probe behind it. Unfixed, the list grew by one dead
    // event per send (about 17 * N after 16 * N sends).
    const n = 32;
    var p = try Pinger.init(std.testing.allocator, .{
        .mode = .loop,
        .interval_ns = 0,
        .perhost_interval_ns = 0,
        .subnet_gap_ns = 100 * std.time.ns_per_us,
    });
    defer p.deinit();
    for (0..n) |_| _ = try p.addTarget("192.0.2.1");
    p.sock4 = .{ .os = deadSocket() };
    try p.prepare();
    var total: u64 = 0;
    while (total < 16 * n) {
        const deadline = (try p.step()).?;
        sleepUntil(deadline);
        total = 0;
        for (p.targets.items) |t| total += t.stats.sent;
    }
    var it = p.subnet_wait.valueIterator();
    const w = it.next().?;
    try std.testing.expect(w.items.capacity <= 8 * n);
    try std.testing.expect(w.items.items.len - w.head <= n);
}

test "at the in-flight cap the wait is the timeout, not zero (sweep D2)" {
    var rig = try Rig.open();
    defer rig.close();
    const timeout = 10 * std.time.ns_per_s;
    var p = try Pinger.init(std.testing.allocator, .{
        .mode = .count,
        .count = 1,
        .max_inflight = 1,
        .interval_ns = 0,
        .timeout_ns = timeout,
    });
    defer p.deinit();
    _ = try p.addTargetAddr(v4(rig.inj_port, 1));
    _ = try p.addTargetAddr(v4(rig.inj_port, 1));
    p.sock4 = .{ .os = rig.socket() };
    try p.prepare();
    const before = icmp.monoNow();
    const deadline = (try p.step()).?;
    try std.testing.expectEqual(@as(u32, 1), p.inflight);
    // Unfixed: the second target's due event made this `now`, and run()
    // spun at 100 % CPU for the whole timeout.
    try std.testing.expect(deadline - before > timeout / 2);
}

const Counter = struct {
    p: *Pinger,
    calls: usize = 0,

    fn cb(ctx: ?*anyopaque, id: icmp.TargetId, probe: u16, outcome: icmp.Outcome) void {
        _ = id;
        _ = probe;
        _ = outcome;
        const self: *Counter = @ptrCast(@alignCast(ctx.?));
        self.calls += 1;
        // Not a stop request: the unfixed loop has no exit, this only keeps
        // the failing case from hanging the test run.
        if (self.calls == 20_000) self.p.cfg.perhost_interval_ns = 3600 * std.time.ns_per_s;
    }
};

test "step returns although every send fails at once (sweep D3)" {
    var p = try Pinger.init(std.testing.allocator, .{
        .mode = .loop,
        .interval_ns = 0,
        .perhost_interval_ns = 0,
        .max_inflight = 8,
    });
    defer p.deinit();
    _ = try p.addTarget("192.0.2.1");
    p.sock4 = .{ .os = deadSocket() };
    var c: Counter = .{ .p = &p };
    p.setResultCallback(&c, Counter.cb);
    try p.prepare();
    const deadline = try p.step();
    try std.testing.expect(deadline != null);
    try std.testing.expect(c.calls <= 8);
    // The next due probe goes out in the next call.
    _ = try p.step();
    try std.testing.expect(c.calls <= 16);
}

test "a prepareProbe error mid-batch releases the batch's sequence numbers (sweep D4)" {
    var rig = try Rig.open();
    defer rig.close();
    var p = try Pinger.init(std.testing.allocator, .{ .mode = .count, .count = 1, .interval_ns = 0 });
    defer p.deinit();
    _ = try p.addTargetAddr(v4(rig.inj_port, 1));
    _ = try p.addTargetAddr(v4(rig.inj_port, 1));
    p.sock4 = .{ .os = rig.socket() };
    try p.prepare();
    // Seq 0 goes to the first event, seq 1 is taken: the second fails.
    p.seqmap.cursor = 0;
    p.seqmap.slots[1] = .{ .target = 9, .probe = 0, .sent_ns = 0 };
    try std.testing.expectError(error.SequenceSpaceExhausted, p.step());
    try std.testing.expectEqual(@as(?seqmap.Entry, null), p.seqmap.fetch(0));
}

test "a reply for an entry nothing is in flight for is ignored (sweep D4)" {
    var rig = try Rig.open();
    defer rig.close();
    var p = try Pinger.init(std.testing.allocator, .{ .check_source = false, .interval_ns = 0 });
    defer p.deinit();
    _ = try p.addTargetAddr(v4(rig.inj_port, 1));
    p.sock4 = .{ .os = rig.socket() };
    // An uncommitted entry: pending and inflight are 0.
    const seq = try p.seqmap.add(0, 0, icmp.monoNow());
    try rig.inject(&replyPacket(seq));
    _ = try p.step(); // unfixed: `pending -= 1` on 0
    try std.testing.expectEqual(@as(u16, 0), p.targets.items[0].pending);
    try std.testing.expectEqual(@as(u32, 0), p.inflight);
    try std.testing.expectEqual(@as(u32, 0), p.stats(0).recv);
}

test "an allocation failure while deferring to a subnet keeps every target (sweep D5)" {
    var any_failed = false;
    for (0..8) |k| {
        var fa = std.testing.FailingAllocator.init(std.testing.allocator, .{});
        const gpa = fa.allocator();
        var p = try Pinger.init(gpa, .{
            .mode = .count,
            .count = 1,
            .interval_ns = 0,
            .subnet_gap_ns = 200 * std.time.ns_per_us,
        });
        defer p.deinit();
        for (0..4) |_| _ = try p.addTarget("192.0.2.1");
        p.sock4 = .{ .os = deadSocket() };
        try p.prepare();
        // Room for the table the sends fill, so that only the bucket
        // bookkeeping allocates from here on.
        try p.subnet_last.ensureTotalCapacity(gpa, 8);
        fa.fail_index = fa.alloc_index + k;
        var failed = false;
        while (true) {
            const r = p.step() catch |err| {
                try std.testing.expectEqual(error.OutOfMemory, err);
                failed = true;
                fa.fail_index = std.math.maxInt(usize); // the failing index stays failing
                continue;
            };
            sleepUntil(r orelse break);
        }
        any_failed = any_failed or failed;
        for (p.targets.items) |t| try std.testing.expectEqual(@as(u32, 1), t.stats.sent);
    }
    try std.testing.expect(any_failed);
}

test "prepareProbe that fails after taking a sequence number gives it back (sweep D4)" {
    var fa = std.testing.FailingAllocator.init(std.testing.allocator, .{});
    const gpa = fa.allocator();
    var p = try Pinger.init(gpa, .{ .mode = .count, .count = 1, .interval_ns = 0, .subnet_gap_ns = std.time.ns_per_ms });
    defer p.deinit();
    _ = try p.addTarget("192.0.2.1");
    p.sock4 = .{ .os = deadSocket() };
    try p.prepare();
    // The first send records its subnet: that table allocates.
    fa.fail_index = fa.alloc_index;
    const cursor = p.seqmap.cursor;
    try std.testing.expectError(error.OutOfMemory, p.step());
    try std.testing.expectEqual(@as(?seqmap.Entry, null), p.seqmap.fetch(cursor));
}

test "prepare reserves the event queue first: an allocation failure changes nothing (sweep D5)" {
    var fa = std.testing.FailingAllocator.init(std.testing.allocator, .{});
    const gpa = fa.allocator();
    var p = try Pinger.init(gpa, .{ .mode = .count, .count = 1, .interval_ns = 0 });
    defer p.deinit();
    for (0..4) |_| _ = try p.addTarget("192.0.2.1");
    p.sock4 = .{ .os = deadSocket() };
    p.targets.items[0].stats.sent = 7;
    p.inflight = 3;
    fa.fail_index = fa.alloc_index;
    try std.testing.expectError(error.OutOfMemory, p.prepare());
    try std.testing.expectEqual(@as(u32, 7), p.stats(0).sent);
    try std.testing.expectEqual(@as(u32, 3), p.inflight);
    try std.testing.expectEqual(@as(usize, 0), p.ping_q.items.len);
    // Retrying works and sends every target exactly once.
    fa.fail_index = std.math.maxInt(usize);
    try p.prepare();
    while (try p.step()) |d| sleepUntil(d);
    for (p.targets.items) |t| try std.testing.expectEqual(@as(u32, 1), t.stats.sent);
}

// ── delta mutation audit GO-IC ──────────────────────────────────────────────

test "v6 oiface_index >= 2^31 is an error from the kernel, not a cast panic (sweep audit GO-IC)" {
    var s: Socket = .{ .fd = -1, .family = .v6, .kind = .dgram, .ident = 0x1234 };
    s.oiface_index = 0x8000_0000;
    const sa: linux.sockaddr.in6 = .{ .port = 0, .flowinfo = 0, .addr = @splat(0), .scope_id = 0 };
    const addr: *const linux.sockaddr = @ptrCast(&sa);
    try std.testing.expectError(error.Unexpected, s.sendTo(addr, @sizeOf(linux.sockaddr.in6), "x"));
}

test "prepare's seeding never allocates beyond its reservation (sweep audit GO-IC)" {
    var fa = std.testing.FailingAllocator.init(std.testing.allocator, .{});
    const gpa = fa.allocator();
    var p = try Pinger.init(gpa, .{ .mode = .count, .count = 1, .interval_ns = 0 });
    defer p.deinit();
    // 9 = one more than the first capacity step of the queue (8), so a
    // reservation one short would have to grow during the seeding.
    for (0..9) |_| _ = try p.addTarget("192.0.2.1");
    p.sock4 = .{ .os = deadSocket() };
    // The reservation is allocation 0; every later push of the seeding loop
    // must fit in it (`pushPing` is `catch unreachable`).
    // No in-place growth either: a growth must be a fresh (failing) allocation.
    fa.fail_index = fa.alloc_index + 1;
    fa.resize_fail_index = fa.resize_index;
    try p.prepare();
    try std.testing.expectEqual(@as(usize, 9), p.ping_q.items.len);
}

test "prepare drops the subnet waiters of the previous round (sweep audit GO-IC)" {
    var p = try Pinger.init(std.testing.allocator, .{
        .mode = .count,
        .count = 1,
        .interval_ns = 0,
        .subnet_gap_ns = 3 * std.time.ns_per_ms,
    });
    defer p.deinit();
    for (0..3) |_| _ = try p.addTarget("192.0.2.1");
    p.sock4 = .{ .os = deadSocket() };
    try p.prepare();
    _ = try p.step(); // target 0 sent, 1 is the bucket head, 2 waits
    try std.testing.expectEqual(@as(u32, 1), p.subnet_wait.count());
    try p.prepare(); // a new round with the old bucket still open
    try std.testing.expectEqual(@as(u32, 0), p.subnet_wait.count());
    while (try p.step()) |d| sleepUntil(d);
    for (p.targets.items) |t| try std.testing.expectEqual(@as(u32, 1), t.stats.sent);
    // Unfinished at deinit: the waiter lists are freed too (leak check).
    try p.prepare();
    _ = try p.step();
}

const Order = struct {
    counts: [3]u32 = @splat(0),
    worst_gap: u32 = 0,
    total: u32 = 0,

    fn cb(ctx: ?*anyopaque, id: icmp.TargetId, probe: u16, outcome: icmp.Outcome) void {
        _ = probe;
        _ = outcome;
        const self: *Order = @ptrCast(@alignCast(ctx.?));
        self.counts[id] += 1;
        self.total += 1;
        const mx = std.mem.max(u32, &self.counts);
        const mn = std.mem.min(u32, &self.counts);
        self.worst_gap = @max(self.worst_gap, mx - mn);
    }
};

test "a bucket's waiters go before a target that is due again (sweep audit GO-IC)" {
    var p = try Pinger.init(std.testing.allocator, .{
        .mode = .loop,
        .interval_ns = 0,
        .perhost_interval_ns = 0,
        .subnet_gap_ns = 300 * std.time.ns_per_us,
    });
    defer p.deinit();
    for (0..3) |_| _ = try p.addTarget("192.0.2.1");
    p.sock4 = .{ .os = deadSocket() };
    var o: Order = .{};
    p.setResultCallback(&o, Order.cb);
    try p.prepare();
    while (o.total < 30) sleepUntil((try p.step()).?);
    // Round robin: no target is ever more than one send ahead.
    try std.testing.expect(o.worst_gap <= 1);
}

test "an early bucket head waits for its time again instead of being lost (sweep audit GO-IC)" {
    var p = try Pinger.init(std.testing.allocator, .{
        .mode = .count,
        .count = 1,
        .interval_ns = 0,
        .subnet_gap_ns = 4 * std.time.ns_per_ms,
    });
    defer p.deinit();
    _ = try p.addTarget("192.0.2.1");
    _ = try p.addTarget("192.0.2.1");
    p.sock4 = .{ .os = deadSocket() };
    try p.prepare();
    _ = try p.step(); // target 0 sent, target 1 is the head (reserved)
    try std.testing.expectEqual(@as(usize, 1), p.ping_q.items.len);
    try std.testing.expect(p.ping_q.items[0].reserved);
    p.ping_q.items[0].time = icmp.monoNow() - 1; // due before the gap is over
    const d = (try p.step()).?; // must be re-queued, not dropped
    try std.testing.expectEqual(@as(usize, 1), p.ping_q.items.len);
    sleepUntil(d);
    while (try p.step()) |dd| sleepUntil(dd);
    try std.testing.expectEqual(@as(u32, 1), p.stats(1).sent);
}

test "a promoted waiter becomes due one gap after the send that promoted it (sweep audit GO-IC)" {
    const gap = 30 * std.time.ns_per_ms;
    var p = try Pinger.init(std.testing.allocator, .{
        .mode = .count,
        .count = 1,
        .max_inflight = 1,
        .interval_ns = 0,
        .subnet_gap_ns = gap,
    });
    defer p.deinit();
    for (0..3) |_| _ = try p.addTarget("192.0.2.1");
    p.sock4 = .{ .os = deadSocket() };
    try p.prepare();
    _ = try p.step(); // target 0 sent (one send per step at max_inflight 1)
    const d = (try p.step()).?; // 1 becomes the head, 2 waits
    sleepUntil(d);
    _ = try p.step(); // the head sends and promotes target 2
    try std.testing.expectEqual(@as(u32, 1), p.stats(1).sent);
    const head = p.ping_q.peek().?;
    try std.testing.expect(head.reserved);
    try std.testing.expect(head.time >= p.last_send_ns + gap);
}

test "max_inflight = 0 keeps the loop going while sends fail at once (sweep audit GO-IC)" {
    var p = try Pinger.init(std.testing.allocator, .{
        .mode = .loop,
        .max_inflight = 0,
        .interval_ns = 0,
        .perhost_interval_ns = 0,
    });
    defer p.deinit();
    _ = try p.addTarget("192.0.2.1");
    p.sock4 = .{ .os = deadSocket() };
    try p.prepare();
    // Nothing in flight, the next probe is due: the answer is "now", not
    // "nothing left to do" (null) or a timeout.
    const d1 = try p.step();
    try std.testing.expect(d1 != null);
    try std.testing.expect(d1.? <= icmp.monoNow());
    try std.testing.expectEqual(@as(u32, 1), p.stats(0).sent);
    _ = try p.step();
    try std.testing.expectEqual(@as(u32, 2), p.stats(0).sent);
}

test "Target.attempts saturates (sweep audit GO-IC)" {
    var p = try Pinger.init(std.testing.allocator, .{ .mode = .alive, .retries = 3, .interval_ns = 0 });
    defer p.deinit();
    _ = try p.addTarget("192.0.2.1");
    p.sock4 = .{ .os = deadSocket() };
    try p.prepare();
    p.targets.items[0].attempts = max_u32;
    _ = try p.step();
    try std.testing.expectEqual(@as(u32, 1), p.stats(0).sent);
    try std.testing.expectEqual(max_u32, p.targets.items[0].attempts);
}

test "a timeout for an entry with nothing in flight keeps the counters at 0 (sweep audit GO-IC)" {
    var p = try Pinger.init(std.testing.allocator, .{ .mode = .count, .count = 1, .retries = 0, .interval_ns = 0 });
    defer p.deinit();
    _ = try p.addTarget("192.0.2.1");
    p.sock4 = .{ .os = deadSocket() };
    // pending 0, inflight 1 (another target's).
    var now = icmp.monoNow();
    var seq = try p.seqmap.add(0, 0, now);
    p.inflight = 1;
    try p.timeout_q.push(p.gpa, .{ .time = now - 1, .target = 0, .probe = 0, .seq = seq });
    _ = try p.step();
    try std.testing.expectEqual(@as(u16, 0), p.targets.items[0].pending);
    try std.testing.expectEqual(@as(u32, 0), p.inflight);
    // pending 1, inflight 0.
    now = icmp.monoNow();
    seq = try p.seqmap.add(0, 0, now);
    p.targets.items[0].pending = 1;
    p.inflight = 0;
    try p.timeout_q.push(p.gpa, .{ .time = now - 1, .target = 0, .probe = 0, .seq = seq });
    _ = try p.step();
    try std.testing.expectEqual(@as(u16, 0), p.targets.items[0].pending);
    try std.testing.expectEqual(@as(u32, 0), p.inflight);
}

test "a reply is ignored unless both the target and the engine have a probe in flight (sweep audit GO-IC)" {
    var rig = try Rig.open();
    defer rig.close();
    var p = try Pinger.init(std.testing.allocator, .{ .check_source = false, .interval_ns = 0 });
    defer p.deinit();
    _ = try p.addTargetAddr(v4(rig.inj_port, 1));
    p.sock4 = .{ .os = rig.socket() };
    // The target has nothing pending, the engine has another target's probe.
    var seq = try p.seqmap.add(0, 0, icmp.monoNow());
    p.inflight = 1;
    try rig.inject(&replyPacket(seq));
    _ = try p.step();
    try std.testing.expectEqual(@as(u16, 0), p.targets.items[0].pending);
    try std.testing.expectEqual(@as(u32, 1), p.inflight);
    try std.testing.expectEqual(@as(u32, 0), p.stats(0).recv);
    // The target has a probe pending, the engine counts none.
    p.seqmap.release(seq);
    seq = try p.seqmap.add(0, 1, icmp.monoNow());
    p.targets.items[0].pending = 1;
    p.inflight = 0;
    try rig.inject(&replyPacket(seq));
    _ = try p.step();
    try std.testing.expectEqual(@as(u16, 1), p.targets.items[0].pending);
    try std.testing.expectEqual(@as(u32, 0), p.inflight);
    try std.testing.expectEqual(@as(u32, 0), p.stats(0).recv);
}

test "icmp_errors from the socket error queue saturate (sweep audit GO-IC)" {
    var rig = try Rig.open();
    defer rig.close();
    const on: u32 = 1;
    if (linux.errno(linux.setsockopt(rig.fd, linux.SOL.IP, linux.IP.RECVERR, @ptrCast(&on), @sizeOf(u32))) != .SUCCESS)
        return error.SkipZigTest;
    var p = try Pinger.init(std.testing.allocator, .{ .check_source = false, .interval_ns = 0 });
    defer p.deinit();
    _ = try p.addTargetAddr(v4(rig.inj_port, 1));
    p.sock4 = .{ .os = rig.socket() };
    const seq = try p.seqmap.add(0, 0, icmp.monoNow());
    // A datagram to a port nobody listens on: loopback answers with a port
    // unreachable, queued on `fd` together with the datagram as its payload.
    const closed = try Rig.bound();
    const closed_port = closed.port;
    _ = linux.close(closed.fd);
    const to = v4(closed_port, 1).v4;
    const pkt = replyPacket(seq);
    for ([_]u32{ 0, max_u32 }) |start| {
        p.targets.items[0].stats.icmp_errors = start;
        const rc = linux.sendto(rig.fd, &pkt, pkt.len, 0, @ptrCast(&to), @sizeOf(linux.sockaddr.in));
        if (linux.errno(rc) != .SUCCESS) return error.SkipZigTest;
        _ = try p.step();
        // 0 -> 1 proves the error reached the queue; then the cap holds.
        try std.testing.expectEqual(start +| 1, p.stats(0).icmp_errors);
    }
}

test "a target that is due again does not jump ahead of its bucket's head (sweep audit GO-IC)" {
    const gap = 5 * std.time.ns_per_ms;
    var p = try Pinger.init(std.testing.allocator, .{
        .mode = .count,
        .count = 1,
        .interval_ns = 0,
        .subnet_gap_ns = gap,
    });
    defer p.deinit();
    for (0..3) |_| _ = try p.addTarget("192.0.2.1");
    p.sock4 = .{ .os = deadSocket() };
    try p.prepare();
    _ = try p.step(); // target 0 sent, 1 is the head (reserved), 2 waits
    try std.testing.expectEqual(@as(u32, 1), p.subnet_wait.count());
    // The gap is over and everything is due; target 0 has an earlier event
    // than the head. The bucket has waiters, so it queues behind them.
    const now = icmp.monoNow();
    var it = p.subnet_last.valueIterator();
    it.next().?.* = now - 10 * gap;
    try std.testing.expectEqual(@as(usize, 1), p.ping_q.items.len);
    p.ping_q.items[0].time = now - 1;
    try p.ping_q.push(p.gpa, .{ .time = now - 2, .target = 0, .probe = 1 });
    _ = try p.step();
    try std.testing.expectEqual(@as(u32, 1), p.stats(1).sent); // the head went first
    try std.testing.expectEqual(@as(u32, 1), p.stats(0).sent); // not again
    try std.testing.expectEqual(@as(u32, 0), p.stats(2).sent);
}
