// SPDX-License-Identifier: MIT

//! Engine tests added by the whole-module mutation audit (2026-11-17): what a
//! `Pinger` puts on the wire, how it books replies, timeouts, retries and
//! duplicates, and which options reach its sockets. They run on the loopback
//! rig of `sweep_test.zig` (a UDP socket pair standing in for the ICMP socket:
//! the pinger's sends reach the injector, whose datagrams are the "replies")
//! and, for the option plumbing, on real ping sockets (skipped where the
//! kernel refuses them).

const std = @import("std");
const linux = std.os.linux;
const icmp = @import("root.zig");
const echo = icmp.echo;
const Socket = icmp.Socket;
const Pinger = icmp.Pinger;
const seqmap = @import("seqmap");
const sw = @import("sweep_test.zig");
const Rig = sw.Rig;
const v4 = sw.v4;
const replyPacket = sw.replyPacket;

const ms = std.time.ns_per_ms;

/// Records every result the callback sees.
const Log = struct {
    pinger: ?*Pinger = null,
    stop_after_timeouts: usize = 0,
    n: usize = 0,
    kind: [64]enum { reply, duplicate, timeout, send_error } = undefined,
    probe: [64]u16 = undefined,
    at: [64]i64 = undefined,
    info: [64]icmp.ReplyInfo = undefined,
    timeouts: usize = 0,

    fn cb(ctx: ?*anyopaque, id: icmp.TargetId, probe: u16, outcome: icmp.Outcome) void {
        _ = id;
        const self: *Log = @ptrCast(@alignCast(ctx.?));
        if (self.n >= self.kind.len) return;
        self.probe[self.n] = probe;
        self.at[self.n] = icmp.monoNow();
        self.info[self.n] = switch (outcome) {
            .reply, .duplicate => |r| r,
            else => .{ .rtt_ns = 0 },
        };
        self.kind[self.n] = switch (outcome) {
            .reply => .reply,
            .duplicate => .duplicate,
            .timeout => .timeout,
            .send_error => .send_error,
        };
        if (outcome == .timeout) {
            self.timeouts += 1;
            if (self.stop_after_timeouts != 0 and self.timeouts >= self.stop_after_timeouts) self.pinger.?.stop();
        }
        self.n += 1;
    }
};

fn setOn(fd: i32, level: i32, opt: u32) void {
    const on: u32 = 1;
    _ = linux.setsockopt(fd, level, opt, @ptrCast(&on), @sizeOf(u32));
}

/// One datagram off the injector socket (what the pinger sent), or null.
fn sent(rig: Rig, buf: []u8) ?[]u8 {
    const rc = linux.recvfrom(rig.inj, buf.ptr, buf.len, 0, null, null);
    if (linux.errno(rc) != .SUCCESS) return null;
    return buf[0..rc];
}

fn seqOf(pkt: []const u8) u16 {
    return std.mem.readInt(u16, pkt[6..8], .big);
}

fn newPinger(cfg: icmp.Config) !Pinger {
    return Pinger.init(std.testing.allocator, cfg);
}

test "audit: probes on the wire, replies booked, duplicates counted, statistics exact" {
    var rig = try Rig.open();
    defer rig.close();
    setOn(rig.fd, linux.SOL.IP, linux.IP.RECVTTL);
    setOn(rig.fd, linux.SOL.IP, linux.IP.RECVTOS);
    setOn(rig.fd, linux.SOL.SOCKET, linux.SO.TIMESTAMPNS_OLD);
    const tos: u32 = 0x28;
    _ = linux.setsockopt(rig.inj, linux.SOL.IP, linux.IP.TOS, @ptrCast(&tos), @sizeOf(u32));

    var p = try newPinger(.{ .mode = .count, .count = 2, .interval_ns = 0, .perhost_interval_ns = 0, .timeout_ns = 5_000 * ms });
    defer p.deinit();
    var log: Log = .{};
    p.setResultCallback(&log, Log.cb);
    _ = try p.addTargetAddr(v4(rig.inj_port, 1));
    p.sock4 = .{ .os = rig.socket() };
    try p.prepare();
    _ = try p.step(); // interval 0, perhost 0: both probes of the target go out together

    var b0: [256]u8 = undefined;
    var b1: [256]u8 = undefined;
    const w0 = sent(rig, &b0) orelse return error.TestUnexpectedResult;
    const w1 = sent(rig, &b1) orelse return error.TestUnexpectedResult;
    try std.testing.expect(sent(rig, &b1) == null); // exactly two datagrams, no resend of the batch
    for ([_][]u8{ w0, w1 }) |w| {
        try std.testing.expectEqual(@as(usize, 64), w.len); // 8 header + 56 payload
        try std.testing.expectEqual(echo.v4.echo_request, w[0]);
        try std.testing.expectEqual(@as(u16, 0x1234), std.mem.readInt(u16, w[4..6], .big)); // the socket's ident
        try std.testing.expectEqual(@as(u16, 0), echo.checksum(w)); // the checksum verifies
        for (w[8..]) |c| try std.testing.expectEqual(@as(u8, 0), c); // payload not random
    }
    const s0 = seqOf(w0);
    const s1 = seqOf(w1);
    try std.testing.expect(s0 != s1); // batch members do not share a send slot
    try std.testing.expectEqual(@as(u32, 2), p.stats(0).sent);
    try std.testing.expectEqual(@as(u16, 2), p.targets.items[0].pending);
    try std.testing.expectEqual(@as(u32, 2), p.inflight);
    try std.testing.expectEqual(@as(usize, 2), p.timeout_q.items.len);
    // Both timeout events name their own probe and slot.
    var saw: [2]bool = .{ false, false };
    for (p.timeout_q.items) |ev| {
        try std.testing.expect(ev.seq == s0 or ev.seq == s1);
        const probe_of_seq: u16 = if (ev.seq == s0) seqProbe(&p, s0) else seqProbe(&p, s1);
        try std.testing.expectEqual(probe_of_seq, ev.probe);
        saw[ev.probe] = true;
    }
    try std.testing.expect(saw[0] and saw[1]);

    // Probe 0 answered 50 ms "ago"; the same reply arrives twice in one go.
    p.seqmap.fetchPtr(s0).?.sent_ns = icmp.monoNow() - 50 * ms;
    try rig.inject(&replyPacket(s0));
    try rig.inject(&replyPacket(s0));
    _ = try p.step();
    try std.testing.expectEqual(@as(usize, 2), log.n);
    try std.testing.expect(log.kind[0] == .reply);
    const r0 = log.info[0];
    try std.testing.expect(r0.rtt_ns >= 50 * ms and r0.rtt_ns < 2_000 * ms);
    try std.testing.expectEqual(@as(u16, 8), r0.size); // an 8-byte message on a DGRAM socket: nothing stripped
    try std.testing.expectEqual(@as(?u8, 64), r0.ttl);
    try std.testing.expectEqual(@as(?u8, 0x28), r0.tos);
    try std.testing.expectEqual(@as(?echo.TsData, null), r0.ts);
    // The second one is a duplicate: told apart, counted, not a second reply.
    try std.testing.expect(log.kind[1] == .duplicate);
    try std.testing.expectEqual(@as(u32, 1), p.stats(0).duplicates);
    try std.testing.expectEqual(@as(u32, 1), p.stats(0).recv);
    try std.testing.expect(!p.targets.items[0].done); // probe 1 is still out
    try std.testing.expectEqual(@as(u16, 1), p.targets.items[0].pending);
    try std.testing.expectEqual(@as(u32, 1), p.inflight);

    p.seqmap.fetchPtr(s1).?.sent_ns = icmp.monoNow() - 1 * ms;
    try rig.inject(&replyPacket(s1));
    _ = try p.step();
    try std.testing.expectEqual(@as(usize, 3), log.n);
    try std.testing.expect(log.kind[2] == .reply);
    const r1 = log.info[2];
    try std.testing.expect(r1.rtt_ns >= 1 * ms and r1.rtt_ns < r0.rtt_ns);
    try std.testing.expect(p.targets.items[0].done);
    try std.testing.expectEqual(@as(u32, 0), p.inflight);
    const st = p.stats(0);
    try std.testing.expectEqual(@as(u32, 2), st.recv);
    try std.testing.expectEqual(r0.rtt_ns + r1.rtt_ns, st.total_ns);
    try std.testing.expectEqual(r1.rtt_ns, st.min_ns);
    try std.testing.expectEqual(r0.rtt_ns, st.max_ns);
    try std.testing.expectEqual(r1.rtt_ns, st.last_ns);
    try std.testing.expectEqual(@as(?u64, (r0.rtt_ns + r1.rtt_ns) / 2), st.avgNs());
    try std.testing.expectEqual(r0.rtt_ns - r1.rtt_ns, st.jitter_sum_ns);
}

fn seqProbe(p: *Pinger, seq: u16) u16 {
    return p.seqmap.fetch(seq).?.probe;
}

test "audit: a DGRAM socket accepts any ident (the kernel filtered it), a RAW one does not" {
    var rig = try Rig.open();
    defer rig.close();
    var p = try newPinger(.{ .interval_ns = 0, .check_source = true });
    defer p.deinit();
    _ = try p.addTargetAddr(v4(rig.inj_port, 1));
    p.sock4 = .{ .os = rig.socket() };
    try p.prepare();
    _ = try p.step();
    var buf: [256]u8 = undefined;
    const seq = seqOf(sent(rig, &buf).?);
    var pkt = replyPacket(seq);
    std.mem.writeInt(u16, pkt[4..6], 0x9999, .big); // not the socket's ident
    std.mem.writeInt(u16, pkt[2..4], 0, .big);
    std.mem.writeInt(u16, pkt[2..4], echo.checksum(&pkt), .big);
    try rig.inject(&pkt);
    _ = try p.step();
    try std.testing.expectEqual(@as(u32, 1), p.stats(0).recv);
}

test "audit: a RAW v4 socket strips the IP header from the reported size, whatever its version nibble" {
    var rig = try Rig.open();
    defer rig.close();
    var p = try newPinger(.{ .interval_ns = 0, .mode = .count, .count = 2, .check_source = true, .perhost_interval_ns = 0 });
    defer p.deinit();
    var log: Log = .{};
    p.setResultCallback(&log, Log.cb);
    _ = try p.addTargetAddr(v4(rig.inj_port, 1));
    var sk = rig.socket();
    sk.kind = .raw;
    p.sock4 = .{ .os = sk };
    try p.prepare();
    _ = try p.step();
    var buf: [256]u8 = undefined;
    const s0 = seqOf(sent(rig, &buf).?);
    const s1 = seqOf(sent(rig, &buf).?);
    for ([_]struct { seq: u16, b0: u8 }{ .{ .seq = s0, .b0 = 0x45 }, .{ .seq = s1, .b0 = 0x55 } }) |c| {
        var dgram: [20 + echo.echo_header_len]u8 = @splat(0);
        dgram[0] = c.b0; // IHL 5 (0x55: a wrong version, the same IHL)
        dgram[9] = 1;
        dgram[20..].* = replyPacket(c.seq);
        try rig.inject(&dgram);
        _ = try p.step();
    }
    try std.testing.expectEqual(@as(usize, 2), log.n);
    try std.testing.expectEqual(@as(u16, 8), log.info[0].size);
    try std.testing.expectEqual(@as(u16, 8), log.info[1].size);
    try std.testing.expectEqual(@as(u32, 2), p.stats(0).recv);
}

fn tsReply(seq: u16, o: u32, r: u32, t: u32) [echo.timestamp_msg_len]u8 {
    var m: [echo.timestamp_msg_len]u8 = @splat(0);
    m[0] = echo.v4.timestamp_reply;
    std.mem.writeInt(u16, m[4..6], 0x1234, .big);
    std.mem.writeInt(u16, m[6..8], seq, .big);
    std.mem.writeInt(u32, m[8..12], o, .big);
    std.mem.writeInt(u32, m[12..16], r, .big);
    std.mem.writeInt(u32, m[16..20], t, .big);
    std.mem.writeInt(u16, m[2..4], echo.checksum(&m), .big);
    return m;
}

test "audit: an ICMP timestamp probe is a 20-byte timestamp request; its reply carries all three times" {
    var rig = try Rig.open();
    defer rig.close();
    var p = try newPinger(.{ .interval_ns = 0, .icmp_timestamp = true, .check_source = true });
    defer p.deinit();
    var log: Log = .{};
    p.setResultCallback(&log, Log.cb);
    _ = try p.addTargetAddr(v4(rig.inj_port, 1));
    p.sock4 = .{ .os = rig.socket() };
    try p.prepare();
    _ = try p.step();
    var buf: [256]u8 = undefined;
    const w = sent(rig, &buf) orelse return error.TestUnexpectedResult;
    try std.testing.expectEqual(echo.timestamp_msg_len, w.len);
    try std.testing.expectEqual(echo.v4.timestamp_request, w[0]);
    try std.testing.expectEqual(@as(u16, 0), echo.checksum(w));
    const originate = std.mem.readInt(u32, w[8..12], .big);
    try std.testing.expect(originate < 86_400_000); // milliseconds since midnight UT
    try rig.inject(&tsReply(seqOf(w), 1111, 2222, 3333));
    _ = try p.step();
    try std.testing.expectEqual(@as(usize, 1), log.n);
    try std.testing.expectEqual(@as(u16, 20), log.info[0].size);
    const ts = log.info[0].ts orelse return error.TestUnexpectedResult;
    try std.testing.expectEqual(@as(u32, 1111), ts.originate_ms);
    try std.testing.expectEqual(@as(u32, 2222), ts.receive_ms);
    try std.testing.expectEqual(@as(u32, 3333), ts.transmit_ms);
}

test "audit: random payloads are random, keep a valid header, and are off by default" {
    var rig = try Rig.open();
    defer rig.close();
    var p = try newPinger(.{ .interval_ns = 0, .mode = .count, .count = 2, .perhost_interval_ns = 0, .payload_size = 32, .random_payload = true });
    defer p.deinit();
    _ = try p.addTargetAddr(v4(rig.inj_port, 1));
    p.sock4 = .{ .os = rig.socket() };
    try p.prepare();
    _ = try p.step();
    var b0: [256]u8 = undefined;
    var b1: [256]u8 = undefined;
    const w0 = sent(rig, &b0).?;
    const w1 = sent(rig, &b1).?;
    for ([_][]u8{ w0, w1 }) |w| {
        try std.testing.expectEqual(@as(usize, 40), w.len);
        try std.testing.expectEqual(echo.v4.echo_request, w[0]);
        try std.testing.expectEqual(@as(u8, 0), w[1]);
        try std.testing.expectEqual(@as(u16, 0), echo.checksum(w)); // computed over the random bytes
        var any = false;
        for (w[8..]) |c| any = any or c != 0;
        try std.testing.expect(any);
    }
    try std.testing.expect(!std.mem.eql(u8, w0[8..], w1[8..]));
}

test "audit: a batch is one probe per target, spaced by the global gap when there is one" {
    // Gap 0: three targets go out together, each with its own sequence number.
    {
        var rig = try Rig.open();
        defer rig.close();
        var p = try newPinger(.{ .interval_ns = 0, .check_source = false });
        defer p.deinit();
        for (0..3) |_| _ = try p.addTargetAddr(v4(rig.inj_port, 1));
        p.sock4 = .{ .os = rig.socket() };
        try p.prepare();
        _ = try p.step();
        var bufs: [4][256]u8 = undefined;
        var seqs: [3]u16 = undefined;
        for (&seqs, 0..) |*s, i| s.* = seqOf(sent(rig, &bufs[i]) orelse return error.TestUnexpectedResult);
        try std.testing.expect(sent(rig, &bufs[3]) == null); // not sent twice
        try std.testing.expect(seqs[0] != seqs[1] and seqs[1] != seqs[2] and seqs[0] != seqs[2]);
        for (0..3) |i| try std.testing.expectEqual(@as(u32, 1), p.stats(@intCast(i)).sent);
    }
    // A 50 ms gap: only one of the three is due per step.
    {
        var rig = try Rig.open();
        defer rig.close();
        var p = try newPinger(.{ .interval_ns = 50 * ms, .check_source = false });
        defer p.deinit();
        for (0..3) |_| _ = try p.addTargetAddr(v4(rig.inj_port, 1));
        p.sock4 = .{ .os = rig.socket() };
        try p.prepare();
        _ = try p.step();
        var total: u32 = 0;
        for (0..3) |i| total += p.stats(@intCast(i)).sent;
        try std.testing.expectEqual(@as(u32, 1), total);
        var buf: [256]u8 = undefined;
        try std.testing.expect(sent(rig, &buf) != null);
        try std.testing.expect(sent(rig, &buf) == null);
    }
}

test "audit: probes of different families are never batched together" {
    var rig = try Rig.open();
    defer rig.close();
    var rig6 = try Rig6.open();
    defer rig6.close();
    var p = try newPinger(.{ .interval_ns = 0, .check_source = false });
    defer p.deinit();
    _ = try p.addTargetAddr(v4(rig.inj_port, 1));
    _ = try p.addTargetAddr(rig6.target());
    _ = try p.addTargetAddr(v4(rig.inj_port, 1));
    p.sock4 = .{ .os = rig.socket() };
    p.sock6 = .{ .os = rig6.socket() };
    try p.prepare();
    var rounds: usize = 0;
    while (rounds < 4) : (rounds += 1) _ = try p.step();
    for (0..3) |i| try std.testing.expectEqual(@as(u32, 0), p.stats(@intCast(i)).send_errors);
    var b: [256]u8 = undefined;
    // IPv6: exactly one datagram, an ICMPv6 echo request.
    const n6 = linux.recvfrom(rig6.inj, &b, b.len, 0, null, null);
    try std.testing.expect(linux.errno(n6) == .SUCCESS);
    try std.testing.expectEqual(echo.v6.echo_request, b[0]);
    try std.testing.expect(linux.errno(linux.recvfrom(rig6.inj, &b, b.len, 0, null, null)) != .SUCCESS);
    // IPv4: exactly two, ICMP echo requests.
    for (0..2) |_| {
        const n4 = sent(rig, &b) orelse return error.TestUnexpectedResult;
        try std.testing.expectEqual(echo.v4.echo_request, n4[0]);
    }
    try std.testing.expect(sent(rig, &b) == null);
}

/// A UDP/IPv6 loopback pair standing in for an ICMPv6 socket.
const Rig6 = struct {
    fd: i32,
    inj: i32,
    fd_port: u16,
    inj_port: u16,

    fn bound() !struct { fd: i32, port: u16 } {
        const rc = linux.socket(linux.AF.INET6, linux.SOCK.DGRAM | linux.SOCK.NONBLOCK | linux.SOCK.CLOEXEC, 0);
        if (linux.errno(rc) != .SUCCESS) return error.SkipZigTest;
        const fd: i32 = @intCast(rc);
        errdefer _ = linux.close(fd);
        var sa: linux.sockaddr.in6 = .{ .port = 0, .flowinfo = 0, .addr = loop6(), .scope_id = 0 };
        if (linux.errno(linux.bind(fd, @ptrCast(&sa), @sizeOf(linux.sockaddr.in6))) != .SUCCESS) return error.SkipZigTest;
        var len: linux.socklen_t = @sizeOf(linux.sockaddr.in6);
        if (linux.errno(linux.getsockname(fd, @ptrCast(&sa), &len)) != .SUCCESS) return error.SkipZigTest;
        return .{ .fd = fd, .port = sa.port };
    }

    fn open() !Rig6 {
        const a = try bound();
        errdefer _ = linux.close(a.fd);
        const b = try bound();
        return .{ .fd = a.fd, .inj = b.fd, .fd_port = a.port, .inj_port = b.port };
    }

    fn close(r: *Rig6) void {
        _ = linux.close(r.fd);
        _ = linux.close(r.inj);
    }

    fn loop6() [16]u8 {
        var a: [16]u8 = @splat(0);
        a[15] = 1;
        return a;
    }

    fn socket(r: Rig6) Socket {
        return .{ .fd = r.fd, .family = .v6, .kind = .dgram, .ident = 0x1234 };
    }

    fn target(r: Rig6) icmp.Addr {
        return .{ .v6 = .{ .port = r.inj_port, .flowinfo = 0, .addr = loop6(), .scope_id = 0 } };
    }

    fn inject(r: Rig6, bytes: []const u8) !void {
        const to: linux.sockaddr.in6 = .{ .port = r.fd_port, .flowinfo = 0, .addr = loop6(), .scope_id = 0 };
        const rc = linux.sendto(r.inj, bytes.ptr, bytes.len, 0, @ptrCast(&to), @sizeOf(linux.sockaddr.in6));
        if (linux.errno(rc) != .SUCCESS) return error.SkipZigTest;
    }
};

fn v6Reply(seq: u16) [echo.echo_header_len]u8 {
    var m: [echo.echo_header_len]u8 = @splat(0);
    m[0] = echo.v6.echo_reply;
    std.mem.writeInt(u16, m[4..6], 0x1234, .big);
    std.mem.writeInt(u16, m[6..8], seq, .big);
    return m;
}

test "audit: a RAW v6 socket reports the whole message, no IP header to strip" {
    var rig6 = try Rig6.open();
    defer rig6.close();
    var p = try newPinger(.{ .interval_ns = 0, .check_source = true });
    defer p.deinit();
    var log: Log = .{};
    p.setResultCallback(&log, Log.cb);
    _ = try p.addTargetAddr(rig6.target());
    var sk = rig6.socket();
    sk.kind = .raw;
    p.sock6 = .{ .os = sk };
    try p.prepare();
    _ = try p.step();
    var buf: [256]u8 = undefined;
    const n = linux.recvfrom(rig6.inj, &buf, buf.len, 0, null, null);
    try std.testing.expect(linux.errno(n) == .SUCCESS);
    var reply: [24]u8 = @splat(0); // a reply with 16 payload bytes
    reply[0..8].* = v6Reply(seqOf(buf[0..n]));
    try rig6.inject(&reply);
    _ = try p.step();
    try std.testing.expectEqual(@as(usize, 1), log.n);
    try std.testing.expectEqual(@as(u16, 24), log.info[0].size); // 0x81 & 0x0f would have taken 4 off
}

test "audit: a v6 error counts only when the quoted DESTINATION is the target" {
    var rig6 = try Rig6.open();
    defer rig6.close();
    var p = try newPinger(.{ .interval_ns = 0, .check_source = true });
    defer p.deinit();
    _ = try p.addTargetAddr(rig6.target());
    p.sock6 = .{ .os = rig6.socket() };
    try p.prepare();
    _ = try p.step();
    var buf: [256]u8 = undefined;
    const n = linux.recvfrom(rig6.inj, &buf, buf.len, 0, null, null);
    try std.testing.expect(linux.errno(n) == .SUCCESS);
    const seq = seqOf(buf[0..n]);

    // ICMPv6 Time Exceeded quoting our request: src 2001:db8::5 -> dst ::1 (the target).
    var err: [8 + 40 + 8]u8 = @splat(0);
    err[0] = echo.v6.time_exceeded;
    const q = err[8..];
    q[6] = 58;
    q[8..24].* = .{ 0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 5 };
    q[24..40].* = Rig6.loop6();
    q[40] = echo.v6.echo_request;
    std.mem.writeInt(u16, q[44..46], 0x1234, .big);
    std.mem.writeInt(u16, q[46..48], seq, .big);
    try rig6.inject(&err);
    _ = try p.step();
    try std.testing.expectEqual(@as(u32, 1), p.stats(0).icmp_errors);
    // The same error quoting a different destination is someone else's.
    q[24..40].* = .{ 0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 9 };
    try rig6.inject(&err);
    _ = try p.step();
    try std.testing.expectEqual(@as(u32, 1), p.stats(0).icmp_errors);
}

test "audit: an unanswered target is retried with a growing timeout, then given up" {
    var rig = try Rig.open();
    defer rig.close();
    var p = try newPinger(.{ .mode = .alive, .retries = 2, .interval_ns = 0, .timeout_ns = 3 * ms, .backoff_factor = 2.0 });
    defer p.deinit();
    var log: Log = .{};
    p.setResultCallback(&log, Log.cb);
    _ = try p.addTargetAddr(v4(rig.inj_port, 1));
    p.sock4 = .{ .os = rig.socket() };
    try p.run();
    try std.testing.expectEqual(@as(usize, 3), log.n);
    for (0..3) |i| {
        try std.testing.expect(log.kind[i] == .timeout);
        try std.testing.expectEqual(@as(u16, @intCast(i)), log.probe[i]);
    }
    try std.testing.expect(log.at[1] - log.at[0] >= 6 * ms); // 3 ms x 2
    try std.testing.expect(log.at[2] - log.at[1] >= 12 * ms); // x 2 again
    try std.testing.expectEqual(@as(u32, 3), p.stats(0).sent);
    try std.testing.expectEqual(@as(u32, 0), p.stats(0).recv);
    try std.testing.expect(p.targets.items[0].done);
    try std.testing.expectEqual(@as(u32, 0), p.inflight);
    // The three probes carry distinct, consecutive-slot sequence numbers.
    var buf: [256]u8 = undefined;
    var seqs: [3]u16 = undefined;
    for (&seqs) |*s| s.* = seqOf(sent(rig, &buf) orelse return error.TestUnexpectedResult);
    try std.testing.expect(seqs[0] != seqs[1] and seqs[1] != seqs[2] and seqs[0] != seqs[2]);
}

test "audit: count mode sends exactly `count` probes, spaced by the per-host interval" {
    var rig = try Rig.open();
    defer rig.close();
    var p = try newPinger(.{ .mode = .count, .count = 3, .interval_ns = 0, .perhost_interval_ns = 30 * ms, .timeout_ns = 5 * ms });
    defer p.deinit();
    var log: Log = .{};
    p.setResultCallback(&log, Log.cb);
    _ = try p.addTargetAddr(v4(rig.inj_port, 1));
    p.sock4 = .{ .os = rig.socket() };
    try p.run();
    try std.testing.expectEqual(@as(usize, 3), log.n);
    for (0..3) |i| try std.testing.expectEqual(@as(u16, @intCast(i)), log.probe[i]);
    // Each probe's timeout is 5 ms after its send; the sends are 30 ms apart.
    try std.testing.expect(log.at[1] - log.at[0] >= 20 * ms);
    try std.testing.expect(log.at[2] - log.at[1] >= 20 * ms);
    try std.testing.expectEqual(@as(u32, 3), p.stats(0).sent);
    try std.testing.expect(p.targets.items[0].done);
}

test "audit: loop mode keeps probing until stop(), and its target is never done" {
    var rig = try Rig.open();
    defer rig.close();
    var p = try newPinger(.{ .mode = .loop, .interval_ns = 0, .perhost_interval_ns = 1 * ms, .timeout_ns = 1 * ms });
    defer p.deinit();
    var log: Log = .{ .pinger = &p, .stop_after_timeouts = 5 };
    p.setResultCallback(&log, Log.cb);
    _ = try p.addTargetAddr(v4(rig.inj_port, 1));
    p.sock4 = .{ .os = rig.socket() };
    try p.run();
    try std.testing.expect(log.timeouts >= 5);
    try std.testing.expect(p.stats(0).sent >= 5);
    try std.testing.expect(!p.targets.items[0].done);
    try std.testing.expect(p.stop_requested.load(.monotonic));
    // A reply in loop mode does not finish the target either.
    var rig2 = try Rig.open();
    defer rig2.close();
    var q = try newPinger(.{ .mode = .loop, .interval_ns = 0, .perhost_interval_ns = 10_000 * ms, .check_source = false });
    defer q.deinit();
    _ = try q.addTargetAddr(v4(rig2.inj_port, 1));
    q.sock4 = .{ .os = rig2.socket() };
    try q.prepare();
    _ = try q.step();
    var buf: [256]u8 = undefined;
    try rig2.inject(&replyPacket(seqOf(sent(rig2, &buf).?)));
    _ = try q.step();
    try std.testing.expectEqual(@as(u32, 1), q.stats(0).recv);
    try std.testing.expect(!q.targets.items[0].done);
}

test "audit: a rejected send is counted, told, its slot freed and the target finished" {
    var p = try newPinger(.{ .mode = .alive, .retries = 0, .interval_ns = 0 });
    defer p.deinit();
    var log: Log = .{};
    p.setResultCallback(&log, Log.cb);
    _ = try p.addTargetAddr(v4(0, 1));
    p.sock4 = .{ .os = sw.deadSocket() };
    try p.run();
    try std.testing.expectEqual(@as(usize, 1), log.n);
    try std.testing.expect(log.kind[0] == .send_error);
    try std.testing.expectEqual(@as(u32, 1), p.stats(0).send_errors);
    try std.testing.expectEqual(@as(u32, 1), p.stats(0).sent);
    try std.testing.expectEqual(@as(u32, 0), p.inflight);
    try std.testing.expectEqual(@as(u16, 0), p.targets.items[0].pending);
    for (0..seqmap.capacity) |i| try std.testing.expectEqual(@as(?seqmap.Entry, null), p.seqmap.fetch(@intCast(i))); // the slot went back
    try std.testing.expect(p.targets.items[0].done);
}

test "audit: step's deadline is the earlier of the next send and the next timeout, never in the past" {
    var rig = try Rig.open();
    defer rig.close();
    var p = try newPinger(.{ .mode = .count, .count = 2, .interval_ns = 0, .perhost_interval_ns = 20 * ms, .timeout_ns = 5_000 * ms });
    defer p.deinit();
    _ = try p.addTargetAddr(v4(rig.inj_port, 1));
    p.sock4 = .{ .os = rig.socket() };
    const t_prep = icmp.monoNow();
    try p.prepare();
    const before = icmp.monoNow();
    const dl = (try p.step()).?;
    try std.testing.expect(dl > before);
    try std.testing.expect(dl - before < 1_000 * ms); // the next send (20 ms), not the 5 s timeout
    // The next send waits one per-host interval after the first one's nominal time.
    const next = p.ping_q.peek().?;
    try std.testing.expectEqual(@as(u16, 1), next.probe);
    try std.testing.expect(next.time >= t_prep + 20 * ms and next.time <= before + 20 * ms);

    // An overdue event that could not be sent leaves a wait of 0, not a negative one.
    var q = try newPinger(.{ .interval_ns = 0, .max_inflight = 1, .retries = 0 });
    defer q.deinit();
    _ = try q.addTargetAddr(v4(0, 1));
    _ = try q.addTargetAddr(v4(0, 2));
    q.sock4 = .{ .os = sw.deadSocket() };
    try q.prepare();
    const d2 = (try q.step()).?;
    try std.testing.expect(d2 > q.last_send_ns);
}

test "audit: the next probe is due one per-host interval after the NOMINAL time of this one" {
    var rig = try Rig.open();
    defer rig.close();
    var p = try newPinger(.{ .mode = .count, .count = 2, .interval_ns = 0, .perhost_interval_ns = 10_000 * ms });
    defer p.deinit();
    _ = try p.addTargetAddr(v4(rig.inj_port, 1));
    p.sock4 = .{ .os = rig.socket() };
    try p.prepare();
    const nominal = icmp.monoNow() - 1_000 * ms; // the event is a second late
    p.ping_q.items[0].time = nominal;
    _ = try p.step();
    try std.testing.expectEqual(@as(usize, 1), p.ping_q.items.len);
    try std.testing.expectEqual(nominal + 10_000 * ms, p.ping_q.peek().?.time);
    try std.testing.expectEqual(@as(u16, 1), p.ping_q.peek().?.probe);
}

test "audit: prepare gives every target a fresh round and schedules each one" {
    var p = try newPinger(.{ .interval_ns = 0, .timeout_ns = 500 * ms });
    defer p.deinit();
    _ = try p.addTarget("192.0.2.1");
    _ = try p.addTarget("192.0.2.2");
    p.sock4 = .{ .os = sw.deadSocket() };
    // A round left dirty.
    const now = icmp.monoNow();
    const seq = try p.seqmap.add(0, 0, now);
    try p.timeout_q.push(p.gpa, .{ .time = now, .target = 0, .probe = 0, .seq = seq });
    try p.ping_q.push(p.gpa, .{ .time = now, .target = 1, .probe = 7 });
    p.inflight = 5;
    try p.subnet_last.put(p.gpa, 42, now);
    p.targets.items[0].stats = .{ .sent = 9, .recv = 9 };
    p.targets.items[0].attempts = 9;
    p.targets.items[0].pending = 3;
    p.targets.items[0].timeout_ns = 77;
    p.targets.items[0].done = true;
    p.stop();
    try p.prepare();
    try std.testing.expectEqual(@as(?seqmap.Entry, null), p.seqmap.fetch(seq));
    try std.testing.expectEqual(@as(u32, 0), p.inflight);
    try std.testing.expectEqual(@as(usize, 0), p.timeout_q.items.len);
    try std.testing.expectEqual(@as(u32, 0), p.subnet_last.count());
    try std.testing.expect(!p.stop_requested.load(.monotonic));
    const t = p.targets.items[0];
    try std.testing.expectEqual(@as(u32, 0), t.stats.sent);
    try std.testing.expectEqual(@as(u32, 0), t.attempts);
    try std.testing.expectEqual(@as(u16, 0), t.pending);
    try std.testing.expectEqual(@as(u64, 500 * ms), t.timeout_ns);
    try std.testing.expect(!t.done);
    // One first probe per target, each for its own target and probe 0.
    try std.testing.expectEqual(@as(usize, 2), p.ping_q.items.len);
    var seen: [2]bool = .{ false, false };
    while (p.ping_q.pop()) |ev| {
        try std.testing.expectEqual(@as(u16, 0), ev.probe);
        seen[ev.target] = true;
    }
    try std.testing.expect(seen[0] and seen[1]);
    // stop() after prepare ends the round before anything is sent.
    try p.prepare();
    p.stop();
    try std.testing.expectEqual(@as(?i64, null), try p.step());
    try std.testing.expectEqual(@as(u32, 0), p.stats(0).sent);
}

test "audit: jitter spreads the first probes inside [start, start + jitter)" {
    var p = try newPinger(.{ .jitter_ns = 1_000 * ms });
    defer p.deinit();
    _ = try p.addTarget("192.0.2.1");
    p.sock4 = .{ .os = sw.deadSocket() };
    var spread = false;
    for (0..16) |_| {
        const before = icmp.monoNow();
        try p.prepare();
        const after = icmp.monoNow();
        const t = p.ping_q.peek().?.time;
        try std.testing.expect(t >= before and t < after + 1_000 * ms);
        spread = spread or t > after + 1 * ms;
    }
    try std.testing.expect(spread);
}

test "audit: pollFds lists the sockets that have a descriptor, POLLIN, in family order" {
    var rig = try Rig.open();
    defer rig.close();
    var rig6 = try Rig6.open();
    defer rig6.close();
    var p = try newPinger(.{});
    defer p.deinit();
    var buf: [2]linux.pollfd = undefined;
    try std.testing.expectEqual(@as(usize, 0), p.pollFds(&buf).len);
    p.sock4 = .{ .os = rig.socket() };
    var fds = p.pollFds(&buf);
    try std.testing.expectEqual(@as(usize, 1), fds.len);
    try std.testing.expectEqual(rig.fd, fds[0].fd);
    try std.testing.expectEqual(@as(i16, linux.POLL.IN), fds[0].events);
    p.sock6 = .{ .os = rig6.socket() };
    fds = p.pollFds(&buf);
    try std.testing.expectEqual(@as(usize, 2), fds.len);
    try std.testing.expectEqual(rig.fd, fds[0].fd);
    try std.testing.expectEqual(rig6.fd, fds[1].fd);
    try std.testing.expectEqual(@as(i16, linux.POLL.IN), fds[1].events);
    p.sock4 = null;
    fds = p.pollFds(&buf);
    try std.testing.expectEqual(@as(usize, 1), fds.len);
    try std.testing.expectEqual(rig6.fd, fds[0].fd);
    p.sock6 = null;
}

/// Provoke an ICMP port-unreachable for a datagram `payload` that `rig.fd`
/// sends to a closed loopback port: it comes back on `rig.fd`'s error queue
/// with the datagram as payload and the closed address as msg_name.
fn provoke(rig: Rig, payload: []const u8, to_last: u8) !void {
    setOn(rig.fd, linux.SOL.IP, linux.IP.RECVERR);
    const rc = linux.socket(linux.AF.INET, linux.SOCK.DGRAM | linux.SOCK.CLOEXEC, 0);
    if (linux.errno(rc) != .SUCCESS) return error.SkipZigTest;
    const cfd: i32 = @intCast(rc);
    var dst = v4(0, to_last).v4;
    if (linux.errno(linux.bind(cfd, @ptrCast(&dst), @sizeOf(linux.sockaddr.in))) != .SUCCESS) {
        _ = linux.close(cfd);
        return error.SkipZigTest;
    }
    var len: linux.socklen_t = @sizeOf(linux.sockaddr.in);
    _ = linux.getsockname(cfd, @ptrCast(&dst), &len);
    _ = linux.close(cfd);
    if (linux.errno(linux.sendto(rig.fd, payload.ptr, payload.len, 0, @ptrCast(&dst), @sizeOf(linux.sockaddr.in))) != .SUCCESS) return error.SkipZigTest;
    const nap: linux.timespec = .{ .sec = 0, .nsec = 20 * ms };
    _ = linux.nanosleep(&nap, null);
}

fn errorCount(payload_ident: u16, payload_seq_delta: u16, quote_len: usize, check_source: bool, target_last: u8, to_last: u8, target_v6: bool) !u32 {
    var rig = try Rig.open();
    defer rig.close();
    var p = try newPinger(.{ .interval_ns = 0, .check_source = check_source });
    defer p.deinit();
    const target: icmp.Addr = if (target_v6) .{ .v6 = .{ .port = 0, .flowinfo = 0, .addr = Rig6.loop6(), .scope_id = 0 } } else v4(0, target_last);
    _ = try p.addTargetAddr(target);
    p.sock4 = .{ .os = rig.socket() };
    const seq = try p.seqmap.add(0, 0, icmp.monoNow());
    var q: [8]u8 = @splat(0);
    q[0] = echo.v4.echo_request;
    std.mem.writeInt(u16, q[4..6], payload_ident, .big);
    std.mem.writeInt(u16, q[6..8], seq +% payload_seq_delta, .big);
    try provoke(rig, q[0..quote_len], to_last);
    _ = try p.step();
    return p.stats(0).icmp_errors;
}

test "audit: the socket error queue counts an error only for our ident, a live slot, the right family and source" {
    try std.testing.expectEqual(@as(u32, 1), try errorCount(0x1234, 0, 8, true, 1, 1, false));
    try std.testing.expectEqual(@as(u32, 0), try errorCount(0x4321, 0, 8, true, 1, 1, false)); // not our ident
    try std.testing.expectEqual(@as(u32, 0), try errorCount(0x1234, 1, 8, true, 1, 1, false)); // a slot nobody holds
    try std.testing.expectEqual(@as(u32, 0), try errorCount(0x1234, 0, 4, true, 1, 1, false)); // a quote too short to name a probe
    try std.testing.expectEqual(@as(u32, 0), try errorCount(0x1234, 0, 8, false, 1, 1, true)); // a v6 target on the v4 socket
    // The error is about 127.0.0.1; the target is 127.0.0.2: refused with check_source, counted without.
    try std.testing.expectEqual(@as(u32, 0), try errorCount(0x1234, 0, 8, true, 2, 1, false));
    try std.testing.expectEqual(@as(u32, 1), try errorCount(0x1234, 0, 8, false, 2, 1, false));
}

/// Can this process set SO_MARK (CAP_NET_ADMIN)?
fn markSettable() bool {
    const rc = linux.socket(linux.AF.INET, linux.SOCK.DGRAM | linux.SOCK.CLOEXEC, 0);
    if (linux.errno(rc) != .SUCCESS) return false;
    const fd: i32 = @intCast(rc);
    defer _ = linux.close(fd);
    const mark: u32 = 0x1234;
    return linux.errno(linux.setsockopt(fd, linux.SOL.SOCKET, linux.SO.MARK, @ptrCast(&mark), @sizeOf(u32))) == .SUCCESS;
}

/// How many descriptors this process has open (a leak shows as a difference).
fn openFds() usize {
    var n: usize = 0;
    for (0..1024) |fd| {
        if (linux.errno(linux.fcntl(@intCast(fd), linux.F.GETFD, 0)) == .SUCCESS) n += 1;
    }
    return n;
}

fn getOpt(fd: i32, level: i32, opt: u32) !u32 {
    var v: u32 = 0;
    var len: linux.socklen_t = @sizeOf(u32);
    if (linux.errno(linux.getsockopt(fd, level, opt, @ptrCast(&v), &len)) != .SUCCESS) return error.TestUnexpectedResult;
    return v;
}

test "audit: prepare opens each family's socket once and hands the options on" {
    const lo4 = icmp.Addr.parse("127.0.0.1") catch unreachable;
    const lo6 = icmp.Addr.parse("::1") catch unreachable;
    var p = try newPinger(.{
        .socket_mode = .dgram,
        .recv_buf_size = 8192,
        .ttl = 77,
        .tos = 0x28,
        .dont_fragment = true,
        .source4 = lo4,
        .source6 = lo6,
        .oiface = "lo",
    });
    defer p.deinit();
    _ = try p.addTargetAddr(lo4);
    _ = try p.addTargetAddr(lo6);
    const base = openFds();
    p.prepare() catch |err| switch (err) {
        error.PermissionDenied, error.AddressFamilyUnsupported, error.SourceAddressBind => return error.SkipZigTest,
        else => return err,
    };
    try std.testing.expectEqual(base + 2, openFds());
    const s4 = p.sock4.?.os;
    const s6 = p.sock6.?.os;
    try std.testing.expectEqual(Socket.Kind.dgram, s4.kind);
    try std.testing.expectEqual(Socket.Kind.dgram, s6.kind);
    try std.testing.expectEqual(@as(u32, 1), s4.oiface_index); // "lo"
    try std.testing.expectEqual(@as(u32, 77), try getOpt(s4.fd, linux.SOL.IP, linux.IP.TTL));
    try std.testing.expectEqual(@as(u32, 0x28), try getOpt(s4.fd, linux.SOL.IP, linux.IP.TOS));
    try std.testing.expectEqual(@as(u32, linux.IP.PMTUDISC_DO), try getOpt(s4.fd, linux.SOL.IP, linux.IP.MTU_DISCOVER));
    try std.testing.expectEqual(@as(u32, 16384), try getOpt(s4.fd, linux.SOL.SOCKET, linux.SO.RCVBUF));
    try std.testing.expectEqual(@as(u32, 77), try getOpt(s6.fd, linux.SOL.IPV6, linux.IPV6.UNICAST_HOPS));
    try std.testing.expectEqual(@as(u32, 0x28), try getOpt(s6.fd, linux.SOL.IPV6, linux.IPV6.TCLASS));
    try std.testing.expectEqual(@as(u32, linux.IPV6.PMTUDISC_DO), try getOpt(s6.fd, linux.SOL.IPV6, linux.IPV6.MTU_DISCOVER));
    // The sources were bound: the sockets sit on loopback, not the wildcard.
    var sa: linux.sockaddr.in = undefined;
    var len: linux.socklen_t = @sizeOf(linux.sockaddr.in);
    try std.testing.expectEqual(linux.E.SUCCESS, linux.errno(linux.getsockname(s4.fd, @ptrCast(&sa), &len)));
    try std.testing.expectEqual(lo4.v4.addr, sa.addr);
    var sa6: linux.sockaddr.in6 = undefined;
    var len6: linux.socklen_t = @sizeOf(linux.sockaddr.in6);
    try std.testing.expectEqual(linux.E.SUCCESS, linux.errno(linux.getsockname(s6.fd, @ptrCast(&sa6), &len6)));
    try std.testing.expectEqual(lo6.v6.addr, sa6.addr);
    // A second prepare reuses both sockets.
    try p.prepare();
    try std.testing.expectEqual(base + 2, openFds());
    try std.testing.expectEqual(s4.fd, p.sock4.?.os.fd);
    try std.testing.expectEqual(s6.fd, p.sock6.?.os.fd);
}

test "audit: socket_mode, interface name, mark and forwarded options each reach Socket.open" {
    // socket_mode: raw is a raw socket or a refusal, never a quiet ping socket;
    // each family on its own, so one family's refusal cannot hide the other.
    for ([_][]const u8{ "127.0.0.1", "::1" }) |t| {
        var p = try newPinger(.{ .socket_mode = .raw });
        defer p.deinit();
        _ = try p.addTarget(t);
        if (p.prepare()) {
            const s = p.sock4 orelse p.sock6.?;
            try std.testing.expectEqual(Socket.Kind.raw, s.os.kind);
        } else |err| try std.testing.expect(err == error.PermissionDenied or err == error.AddressFamilyUnsupported);
    }
    // iface: a name that is no interface is refused, for each family.
    for ([_][]const u8{ "127.0.0.1", "::1" }) |t| {
        var p = try newPinger(.{ .socket_mode = .dgram, .iface = "nonexist0" });
        defer p.deinit();
        _ = try p.addTarget(t);
        if (p.prepare()) {
            return error.TestUnexpectedResult;
        } else |err| try std.testing.expect(err == error.InterfaceBind or err == error.AddressFamilyUnsupported or err == error.PermissionDenied);
    }
    // fwmark needs CAP_NET_ADMIN: where it is allowed, it is set.
    var p = try newPinger(.{ .socket_mode = .dgram, .fwmark = 0x1234 });
    defer p.deinit();
    _ = try p.addTarget("127.0.0.1");
    p.prepare() catch return error.SkipZigTest;
    const got = try getOpt(p.sock4.?.os.fd, linux.SOL.SOCKET, linux.SO.MARK);
    if (markSettable()) try std.testing.expectEqual(@as(u32, 0x1234), got);
}

test "audit: Config.io refuses every option only raw sockets implement, and opens one socket per family" {
    var threaded = std.Io.Threaded.init(std.testing.allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();
    const cases = [_]icmp.Config{
        .{ .io = io, .ttl = 1 },
        .{ .io = io, .tos = 1 },
        .{ .io = io, .dont_fragment = true },
        .{ .io = io, .fwmark = 1 },
        .{ .io = io, .iface = "lo" },
        .{ .io = io, .oiface = "lo" },
        .{ .io = io, .socket_mode = .raw },
    };
    for (cases) |c| {
        var p = try newPinger(c);
        defer p.deinit();
        try std.testing.expectError(error.NeedsRawSockets, p.prepare());
    }
    // One socket per family however many targets: three v4 targets cost what one does
    // (the first pinger warms up whatever the `Io` opens for itself).
    var warm = try newPinger(.{ .io = io });
    defer warm.deinit();
    _ = try warm.addTarget("127.0.0.1");
    warm.prepare() catch |err| switch (err) {
        error.PermissionDenied, error.AddressFamilyUnsupported => return error.SkipZigTest,
        else => return err,
    };
    var one = try newPinger(.{ .io = io });
    defer one.deinit();
    _ = try one.addTarget("127.0.0.1");
    const base1 = openFds();
    try one.prepare();
    const cost1 = openFds() - base1;
    var three = try newPinger(.{ .io = io });
    defer three.deinit();
    _ = try three.addTarget("127.0.0.1");
    _ = try three.addTarget("127.0.0.2");
    _ = try three.addTarget("127.0.0.3");
    const base3 = openFds();
    try three.prepare();
    try std.testing.expectEqual(cost1, openFds() - base3);
    try std.testing.expect(cost1 >= 1);
}

test "audit: replies are timed from the kernel's receive timestamp, not from when they were read" {
    var rig = try Rig.open();
    defer rig.close();
    setOn(rig.fd, linux.SOL.SOCKET, linux.SO.TIMESTAMPNS_OLD);
    var p = try newPinger(.{ .interval_ns = 0, .check_source = false });
    defer p.deinit();
    var log: Log = .{};
    p.setResultCallback(&log, Log.cb);
    _ = try p.addTargetAddr(v4(rig.inj_port, 1));
    p.sock4 = .{ .os = rig.socket() };
    try p.prepare();
    _ = try p.step();
    var buf: [256]u8 = undefined;
    const seq = seqOf(sent(rig, &buf).?);
    p.seqmap.fetchPtr(seq).?.sent_ns = icmp.monoNow();
    try rig.inject(&replyPacket(seq));
    const nap: linux.timespec = .{ .sec = 0, .nsec = 80 * ms };
    _ = linux.nanosleep(&nap, null);
    _ = try p.step(); // reads the reply 80 ms after it arrived
    try std.testing.expectEqual(@as(usize, 1), log.n);
    try std.testing.expect(log.info[0].rtt_ns < 40 * ms);
}

test "audit: a reply sent in the future of the read clock has an RTT of 0, not a panic" {
    var rig = try Rig.open();
    defer rig.close();
    var p = try newPinger(.{ .interval_ns = 0, .check_source = false });
    defer p.deinit();
    var log: Log = .{};
    p.setResultCallback(&log, Log.cb);
    _ = try p.addTargetAddr(v4(rig.inj_port, 1));
    p.sock4 = .{ .os = rig.socket() };
    try p.prepare();
    _ = try p.step();
    var buf: [256]u8 = undefined;
    const seq = seqOf(sent(rig, &buf).?);
    p.seqmap.fetchPtr(seq).?.sent_ns = icmp.monoNow() + 60_000 * ms;
    try rig.inject(&replyPacket(seq));
    _ = try p.step();
    try std.testing.expectEqual(@as(usize, 1), log.n);
    try std.testing.expectEqual(@as(u64, 0), log.info[0].rtt_ns);
}
