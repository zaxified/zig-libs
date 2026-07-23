// SPDX-License-Identifier: MIT

//! The **only** part of this module that knows what a socket is.
//!
//! The fleet core is pure: a harness feeds it bytes and reads bytes back. That
//! is what makes it deterministic and what makes 1000 nodes affordable. But a
//! simulator nobody can point a real master at is a toy, so this file binds a
//! node to a real listener: bytes off the socket go in through
//! `Fleet.submitStream`, simulated time advances from the monotonic clock, and
//! whatever the fleet puts in `outbound()` for that node goes back out.
//!
//! Deliberately small and deliberately blocking: one thread, one connection at
//! a time, `poll(2)` for the idle timeout so the fleet's timers still fire on a
//! quiet link. Anything more ambitious belongs in the consumer, not here — the
//! moment this file grows an event loop, the "no I/O in the core" property
//! stops being visible.

const std = @import("std");
const fleet_mod = @import("fleet.zig");
const node_mod = @import("node.zig");

const Fleet = fleet_mod.Fleet;
const NodeId = node_mod.NodeId;
const Time = node_mod.Time;

pub const Options = struct {
    /// How long a read may block before the fleet is advanced anyway, so
    /// unsolicited traffic and protocol timers still happen on an idle link.
    idle_ms: u32 = 200,
    /// Stop after this much real time. Zero means "until the peer closes".
    run_ms: u64 = 0,
    /// Stop once this many inbound frames have been served. Zero means "no
    /// limit". Useful in tests, which want to end deterministically.
    max_frames: usize = 0,
    read_buf: usize = 8192,
    /// How many peers to serve one after another. A master that reconnects per
    /// operation (and a port scanner that connects and hangs up) both need more
    /// than one.
    max_sessions: usize = 1,
};

pub const Report = struct {
    connected: bool = false,
    bytes_in: usize = 0,
    bytes_out: usize = 0,
    frames_in: usize = 0,
    frames_out: usize = 0,
    /// Peers served (always 1 for `serveTcpOn`).
    sessions: usize = 0,
    /// Real milliseconds the session lasted.
    duration_ms: u64 = 0,
};

pub const Error = error{
    BindFailed,
    NoPeer,
} || fleet_mod.Error;

/// Monotonic milliseconds. The one place real time enters this module.
pub fn nowMs() u64 {
    var ts: std.posix.timespec = undefined;
    if (std.posix.errno(std.posix.system.clock_gettime(.MONOTONIC, &ts)) != .SUCCESS) return 0;
    return @as(u64, @intCast(ts.sec)) * 1000 + @as(u64, @intCast(ts.nsec)) / 1_000_000;
}

fn readable(handle: std.posix.fd_t, ms: u32) bool {
    var fds = [_]std.posix.pollfd{.{ .fd = handle, .events = std.posix.POLL.IN, .revents = 0 }};
    const n = std.posix.poll(&fds, @intCast(ms)) catch return true;
    return n != 0;
}

/// Bind `address`, accept one TCP peer, and drive `node` from it until the peer
/// closes or a limit in `opts` is reached.
///
/// The caller owns `gpa` (used only for the read buffer) and the fleet. Nothing
/// else in this module allocates while a session is running.
pub fn serveTcp(
    gpa: std.mem.Allocator,
    io: std.Io,
    fleet: *Fleet,
    node: NodeId,
    address: std.Io.net.IpAddress,
    opts: Options,
) !Report {
    var listener = address.listen(io, .{ .reuse_address = true }) catch return error.BindFailed;
    defer listener.socket.close(io);

    var total = Report{};
    const start = nowMs();
    var session: usize = 0;
    while (session < @max(opts.max_sessions, 1)) : (session += 1) {
        const elapsed = nowMs() - start;
        if (opts.run_ms != 0 and elapsed >= opts.run_ms) break;
        // Bound the accept too, or a `run_ms` budget means nothing: `accept(2)`
        // blocks forever on a quiet listener.
        if (opts.run_ms != 0) {
            const budget: u32 = @intCast(@min(opts.run_ms - elapsed, @as(u64, std.math.maxInt(u32))));
            if (!readable(listener.socket.handle, budget)) {
                if (total.connected) break;
                return error.NoPeer;
            }
        }
        const one = serveTcpOn(gpa, io, fleet, node, &listener, opts) catch |e| switch (e) {
            error.NoPeer => if (total.connected) break else return e,
            else => return e,
        };
        total.connected = total.connected or one.connected;
        total.bytes_in += one.bytes_in;
        total.bytes_out += one.bytes_out;
        total.frames_in += one.frames_in;
        total.frames_out += one.frames_out;
        total.sessions += 1;
    }
    total.duration_ms = nowMs() - start;
    return total;
}

/// Same, on a listener the caller already owns (so a test can print the port it
/// actually got before a peer connects).
pub fn serveTcpOn(
    gpa: std.mem.Allocator,
    io: std.Io,
    fleet: *Fleet,
    node: NodeId,
    listener: anytype,
    opts: Options,
) !Report {
    var report = Report{};
    const stream = listener.accept(io) catch return error.NoPeer;
    defer stream.close(io);
    report.connected = true;
    report.sessions = 1;

    const buf = try gpa.alloc(u8, opts.read_buf);
    defer gpa.free(buf);
    const rbuf = try gpa.alloc(u8, opts.read_buf);
    defer gpa.free(rbuf);
    const wbuf = try gpa.alloc(u8, opts.read_buf);
    defer gpa.free(wbuf);

    var reader = stream.reader(io, rbuf);
    var writer = stream.writer(io, wbuf);
    const r = &reader.interface;
    const w = &writer.interface;

    const start = nowMs();
    // A carry buffer for a frame split across two reads.
    var carry: usize = 0;

    while (true) {
        const real = nowMs();
        const t: Time = real - start;
        if (opts.run_ms != 0 and t >= opts.run_ms) break;
        if (opts.max_frames != 0 and report.frames_in >= opts.max_frames) break;

        if (r.bufferedLen() == 0 and !readable(stream.socket.handle, opts.idle_ms)) {
            // Idle: still advance so timers and unsolicited traffic fire.
            _ = try fleet.advance(t);
            if (try flush(fleet, node, w, &report)) continue else continue;
        }

        // `readVec`, not `readSliceShort`: the latter keeps reading until the
        // destination is FULL, which on a request/response protocol means
        // waiting for 8 KiB that the master will never send. One underlying
        // read is exactly what a framed stream wants.
        var vec: [1][]u8 = .{buf[carry..]};
        const n = r.readVec(&vec) catch break; // EndOfStream / ReadFailed
        if (n == 0) break; // peer closed
        report.bytes_in += n;
        const have = carry + n;

        const consumed = try fleet.submitStream(node, buf[0..have], t);
        report.frames_in += 1;
        carry = have - consumed;
        if (carry != 0) {
            if (carry >= buf.len) {
                carry = 0; // a frame bigger than the read buffer: resynchronise
            } else {
                std.mem.copyForwards(u8, buf[0..carry], buf[consumed..have]);
            }
        }

        _ = try fleet.advance(t);
        _ = try flush(fleet, node, w, &report);
    }

    // One last drain so a reply produced on the way out is not lost.
    _ = try fleet.advance(nowMs() - start);
    _ = try flush(fleet, node, w, &report);
    report.duration_ms = nowMs() - start;
    return report;
}

fn flush(fleet: *Fleet, node: NodeId, w: *std.Io.Writer, report: *Report) !bool {
    var any = false;
    for (fleet.outbound()) |f| {
        if (f.node != node) continue;
        const bytes = fleet.frameBytes(f);
        w.writeAll(bytes) catch return any;
        report.bytes_out += bytes.len;
        report.frames_out += 1;
        any = true;
    }
    if (any) w.flush() catch return any;
    return any;
}

/// Bind a UDP socket and drive a datagram node (BACnet/IP) from it. Each
/// datagram is one frame; replies go back to whoever sent the last one, which
/// is what a device does when it cannot broadcast onto the requester's subnet.
pub fn serveUdp(
    gpa: std.mem.Allocator,
    io: std.Io,
    fleet: *Fleet,
    node: NodeId,
    address: std.Io.net.IpAddress,
    opts: Options,
) !Report {
    var report = Report{};
    var socket = address.bind(io, .{ .mode = .dgram, .allow_broadcast = true }) catch
        return error.BindFailed;
    defer socket.close(io);
    report.connected = true;

    const buf = try gpa.alloc(u8, opts.read_buf);
    defer gpa.free(buf);

    const start = nowMs();
    var last_peer: ?std.Io.net.IpAddress = null;
    while (true) {
        const t: Time = nowMs() - start;
        if (opts.run_ms != 0 and t >= opts.run_ms) break;
        if (opts.max_frames != 0 and report.frames_in >= opts.max_frames) break;

        const msg = socket.receiveTimeout(io, buf, .{ .duration = .{
            .raw = .fromNanoseconds(@as(i96, opts.idle_ms) * 1_000_000),
            .clock = .awake,
        } }) catch |e| switch (e) {
            // An idle link is the normal state of a BACnet device between
            // transactions; advance anyway so its timers fire.
            error.Timeout => {
                _ = try fleet.advance(t);
                _ = try flushUdp(fleet, node, io, &socket, last_peer, &report);
                continue;
            },
            else => break,
        };
        if (msg.data.len == 0) continue;
        last_peer = msg.from;
        report.bytes_in += msg.data.len;
        report.frames_in += 1;
        try fleet.submit(node, msg.data, t);
        _ = try fleet.advance(t);
        _ = try flushUdp(fleet, node, io, &socket, last_peer, &report);
    }
    report.duration_ms = nowMs() - start;
    return report;
}

fn flushUdp(
    fleet: *Fleet,
    node: NodeId,
    io: std.Io,
    socket: *std.Io.net.Socket,
    to: ?std.Io.net.IpAddress,
    report: *Report,
) !bool {
    const dest = to orelse return false;
    var any = false;
    for (fleet.outbound()) |f| {
        if (f.node != node) continue;
        const bytes = fleet.frameBytes(f);
        socket.send(io, &dest, bytes) catch return any;
        report.bytes_out += bytes.len;
        report.frames_out += 1;
        any = true;
    }
    return any;
}
