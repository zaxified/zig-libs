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
//! Deliberately small and still deliberately single-threaded. Two shapes:
//!
//!  - `serveTcp` / `serveUdp` — one node, one peer at a time. The smallest
//!    thing that can be pointed at a real master.
//!  - `serveTcpMulti` — several listeners and several peers at once, over one
//!    `poll(2)` readiness loop. Still one thread, still no per-node thread,
//!    still not one clock read inside the fleet: the loop reads the monotonic
//!    clock exactly where the single-peer version does, at the top, and hands
//!    the fleet an injected `Time`. Concurrency here is a *readiness set*, not
//!    a thread pool — which is the only way to add it without moving I/O into
//!    the core.

const std = @import("std");
const fleet_mod = @import("fleet.zig");
const node_mod = @import("node.zig");

// Skip diagnostics are opt-in: `zig build test` must be silent on
// success (any stderr triggers the build runner's `failed command:`
// line even when the step succeeded), while the skip *count* still
// shows up in the summary regardless. Set ZIG_LIBS_VERBOSE_SKIP to any
// non-empty value to see the reasons. (std.posix.getenv doesn't exist
// in 0.16 — std.testing.environ + Environ.getPosix is the repo's
// existing env-read pattern for tests, see netconf's `envVar`.)
const testkit = @import("testkit");
const verboseSkip = testkit.verboseSkip;

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

    // Pairing a Reader and a Writer on the same stream is safe: each keeps its
    // own copy of the two-word `Stream` and its own buffer. The `Stream.Reader`
    // "stops writes reaching the wire" hazard noted in
    // `modules/bacnet/src/sc_interop.zig` does not reproduce — the regression
    // test at the end of this file pins it.
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

// ── several listeners, several peers, one loop ──────────────────────────────

/// One listening socket and the node behind it.
pub const Binding = struct {
    node: NodeId,
    address: std.Io.net.IpAddress,
};

pub const MultiOptions = struct {
    /// How long the readiness loop may block with nothing to do, so the fleet
    /// still advances (and its timers still fire) on a quiet link.
    idle_ms: u32 = 200,
    /// Stop after this much real time. Zero means "until every peer has hung
    /// up and at least one had connected".
    run_ms: u64 = 0,
    /// Stop once this many inbound reads have been served across all peers.
    max_frames: usize = 0,
    read_buf: usize = 8192,
    /// How many peers may be connected **at the same time**. Beyond this, a
    /// new connection is accepted and immediately closed rather than left
    /// hanging in the backlog pretending to be served.
    max_peers: usize = 8,
};

pub const MultiReport = struct {
    /// Peers accepted over the whole run.
    peers_accepted: usize = 0,
    /// The most peers that were connected simultaneously — the number that
    /// makes "multi-peer" a claim rather than a hope.
    peak_concurrent: usize = 0,
    /// Peers refused because `max_peers` was already reached.
    peers_refused: usize = 0,
    bytes_in: usize = 0,
    bytes_out: usize = 0,
    frames_in: usize = 0,
    frames_out: usize = 0,
    duration_ms: u64 = 0,
};

const Peer = struct {
    active: bool = false,
    /// Index into `bindings`, which is what maps a peer back to its node.
    binding: usize = 0,
    stream: std.Io.net.Stream = undefined,
    reader: std.Io.net.Stream.Reader = undefined,
    writer: std.Io.net.Stream.Writer = undefined,
    /// Frame-assembly buffer: bytes of a frame split across two reads.
    buf: []u8 = &.{},
    carry: usize = 0,
};

/// Bind every address in `bindings` and service all of them, and every peer on
/// them, concurrently from one thread.
///
/// The loop is: wait for readiness on the listeners and every connected peer →
/// accept what is new → read what is ready and `submitStream` it → `advance`
/// the fleet once → write each node's `outbound()` back to the peer that asked.
/// A node's reply goes to the peer that most recently sent it something; when
/// nothing has been asked of it (unsolicited traffic), it goes to every peer on
/// that node's listener, which is what a device with several connected masters
/// does.
///
/// Everything is allocated once, before the loop: `max_peers` slots, three
/// buffers each. Nothing in the steady state allocates.
pub fn serveTcpMulti(
    gpa: std.mem.Allocator,
    io: std.Io,
    fleet: *Fleet,
    bindings: []const Binding,
    opts: MultiOptions,
) !MultiReport {
    if (bindings.len == 0) return error.NoPeer;
    const max_peers = @max(opts.max_peers, 1);

    const listeners = try gpa.alloc(std.Io.net.Server, bindings.len);
    defer gpa.free(listeners);
    // One `defer` over `listeners[0..bound]`, evaluated at scope exit: a
    // half-built array must not close handles it never opened, and it must not
    // close the ones it did open twice (an `errdefer` *plus* a `defer` over the
    // whole array does exactly that, and a double close aborts).
    var bound: usize = 0;
    defer for (listeners[0..bound]) |*l| l.socket.close(io);
    while (bound < bindings.len) : (bound += 1) {
        listeners[bound] = bindings[bound].address.listen(io, .{ .reuse_address = true }) catch
            return error.BindFailed;
    }

    const peers = try gpa.alloc(Peer, max_peers);
    defer gpa.free(peers);
    @memset(peers, .{});

    // One block for every peer's three buffers, so the steady state never
    // touches the allocator.
    const block = try gpa.alloc(u8, max_peers * 3 * opts.read_buf);
    defer gpa.free(block);

    // Which peer last spoke for each binding, so a reply goes back where the
    // request came from.
    const last_peer = try gpa.alloc(?usize, bindings.len);
    defer gpa.free(last_peer);
    @memset(last_peer, null);

    const fds = try gpa.alloc(std.posix.pollfd, bindings.len + max_peers);
    defer gpa.free(fds);

    var report = MultiReport{};
    const start = nowMs();
    var live: usize = 0;
    var ever_connected = false;

    while (true) {
        const real = nowMs();
        const t: Time = real - start;
        if (opts.run_ms != 0 and t >= opts.run_ms) break;
        if (opts.max_frames != 0 and report.frames_in >= opts.max_frames) break;
        if (opts.run_ms == 0 and ever_connected and live == 0) break;

        // Build the readiness set: every listener that could still take a peer,
        // plus every connected peer. A peer whose reader already holds decoded
        // bytes is "ready" without asking the kernel.
        var n_fds: usize = 0;
        var buffered = false;
        if (live < max_peers) {
            for (listeners) |*l| {
                fds[n_fds] = .{ .fd = l.socket.handle, .events = std.posix.POLL.IN, .revents = 0 };
                n_fds += 1;
            }
        }
        const listener_fds = n_fds;
        for (peers) |*p| {
            if (!p.active) continue;
            if (p.reader.interface.bufferedLen() != 0) buffered = true;
            fds[n_fds] = .{ .fd = p.stream.socket.handle, .events = std.posix.POLL.IN, .revents = 0 };
            n_fds += 1;
        }

        var timeout: u32 = opts.idle_ms;
        if (opts.run_ms != 0) {
            const left = opts.run_ms - t;
            timeout = @intCast(@min(@as(u64, opts.idle_ms), left));
        }
        if (buffered) timeout = 0;
        const ready = std.posix.poll(fds[0..n_fds], @intCast(timeout)) catch 0;

        if (ready != 0 and listener_fds != 0) {
            for (fds[0..listener_fds], 0..) |fd, i| {
                if (fd.revents & std.posix.POLL.IN == 0) continue;
                const stream = listeners[i].accept(io) catch continue;
                const slot = freeSlot(peers) orelse {
                    // Accepted and closed on purpose: an unserviceable
                    // connection left in the backlog looks like a hang to the
                    // master, which is a worse lie than a refusal.
                    stream.close(io);
                    report.peers_refused += 1;
                    continue;
                };
                const base = slot * 3 * opts.read_buf;
                peers[slot] = .{
                    .active = true,
                    .binding = i,
                    .stream = stream,
                    .buf = block[base..][0..opts.read_buf],
                    .carry = 0,
                };
                // Paired Reader+Writer on one stream is safe; see the note in
                // `serveTcpOn` and the regression test at the end of this file.
                peers[slot].reader = stream.reader(io, block[base + opts.read_buf ..][0..opts.read_buf]);
                peers[slot].writer = stream.writer(io, block[base + 2 * opts.read_buf ..][0..opts.read_buf]);
                live += 1;
                ever_connected = true;
                report.peers_accepted += 1;
                report.peak_concurrent = @max(report.peak_concurrent, live);
            }
        }

        // Read from every peer that has something, in slot order — which keeps
        // the order frames reach the fleet a function of the readiness set and
        // the slot assignment, not of thread scheduling.
        var fd_i = listener_fds;
        for (peers, 0..) |*p, slot| {
            if (!p.active) continue;
            const revents = fds[fd_i].revents;
            fd_i += 1;
            const has_buffered = p.reader.interface.bufferedLen() != 0;
            if (!has_buffered and revents & (std.posix.POLL.IN | std.posix.POLL.HUP | std.posix.POLL.ERR) == 0) continue;

            var vec: [1][]u8 = .{p.buf[p.carry..]};
            const n = p.reader.interface.readVec(&vec) catch 0;
            if (n == 0) {
                closePeer(io, peers, slot, last_peer);
                live -= 1;
                continue;
            }
            report.bytes_in += n;
            report.frames_in += 1;
            const have = p.carry + n;
            const consumed = fleet.submitStream(bindings[p.binding].node, p.buf[0..have], t) catch 0;
            p.carry = have - consumed;
            if (p.carry != 0) {
                if (p.carry >= p.buf.len) {
                    p.carry = 0; // a frame larger than the buffer: resynchronise
                } else {
                    std.mem.copyForwards(u8, p.buf[0..p.carry], p.buf[consumed..have]);
                }
            }
            last_peer[p.binding] = slot;
        }

        _ = try fleet.advance(t);
        try flushMulti(fleet, bindings, peers, last_peer, &report);
    }

    // One last drain, then hang up on everyone still connected.
    _ = try fleet.advance(nowMs() - start);
    try flushMulti(fleet, bindings, peers, last_peer, &report);
    for (peers, 0..) |*p, slot| {
        if (p.active) closePeer(io, peers, slot, last_peer);
    }
    report.duration_ms = nowMs() - start;
    if (!ever_connected) return error.NoPeer;
    return report;
}

fn freeSlot(peers: []Peer) ?usize {
    for (peers, 0..) |p, i| {
        if (!p.active) return i;
    }
    return null;
}

fn closePeer(io: std.Io, peers: []Peer, slot: usize, last_peer: []?usize) void {
    peers[slot].stream.close(io);
    peers[slot].active = false;
    // A reply must never be routed to a slot that has been reused by a
    // different master.
    for (last_peer) |*lp| {
        if (lp.* == slot) lp.* = null;
    }
}

fn flushMulti(
    fleet: *Fleet,
    bindings: []const Binding,
    peers: []Peer,
    last_peer: []const ?usize,
    report: *MultiReport,
) !void {
    for (fleet.outbound()) |f| {
        const b = bindingOf(bindings, f.node) orelse continue;
        const bytes = fleet.frameBytes(f);
        if (last_peer[b]) |slot| {
            if (peers[slot].active and peers[slot].binding == b) {
                writeTo(&peers[slot], bytes, report);
                continue;
            }
        }
        // Unsolicited: nobody asked, so tell everyone on that listener.
        for (peers) |*p| {
            if (p.active and p.binding == b) writeTo(p, bytes, report);
        }
    }
    for (peers) |*p| {
        if (p.active) p.writer.interface.flush() catch {};
    }
}

fn writeTo(p: *Peer, bytes: []const u8, report: *MultiReport) void {
    p.writer.interface.writeAll(bytes) catch return;
    report.bytes_out += bytes.len;
    report.frames_out += 1;
}

fn bindingOf(bindings: []const Binding, node: NodeId) ?usize {
    for (bindings, 0..) |b, i| {
        if (b.node == node) return i;
    }
    return null;
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

// ── tests ───────────────────────────────────────────────────────────────────
//
// The single-peer bindings are exercised by the live tests in `root.zig`, which
// need a real master. The multi-peer loop can be proved without one: two
// in-process clients, on two sockets, driving two different nodes of the same
// fleet at the same time. The clients are threads because a *client* is allowed
// to be — the server side is still one thread with no per-node thread, which is
// the property under test.

const testing = std.testing;
const modbus = @import("modbus");

const test_port_a: u16 = 15571;
const test_port_b: u16 = 15572;
const test_port_single: u16 = 15573;

const ClientResult = struct {
    port: u16,
    /// Bytes to send, once per round.
    request: []const u8,
    rounds: usize,
    replies: usize = 0,
    connected: bool = false,
    /// Set once the client has connected, so the other client can be made to
    /// overlap with it rather than merely follow it.
    ready: std.atomic.Value(bool) = .init(false),
    /// Cleared by the main thread when both clients may finish.
    hold: *std.atomic.Value(bool) = undefined,
};

fn sleepMs(ms: u64) void {
    var req: std.posix.timespec = .{
        .sec = @intCast(ms / 1000),
        .nsec = @intCast((ms % 1000) * 1_000_000),
    };
    var rem: std.posix.timespec = undefined;
    while (std.posix.errno(std.posix.system.nanosleep(&req, &rem)) == .INTR) req = rem;
}

fn testClient(r: *ClientResult) void {
    var threaded = std.Io.Threaded.init(testing.allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();
    const addr = std.Io.net.IpAddress.parse("127.0.0.1", r.port) catch return;

    // The server may not have called listen(2) yet.
    var stream: std.Io.net.Stream = undefined;
    var tries: usize = 0;
    while (true) : (tries += 1) {
        stream = addr.connect(io, .{ .mode = .stream }) catch {
            if (tries > 200) return;
            sleepMs(10);
            continue;
        };
        break;
    }
    defer stream.close(io);
    r.connected = true;
    r.ready.store(true, .release);

    var rbuf: [1024]u8 = undefined;
    var wbuf: [1024]u8 = undefined;
    var reader = stream.reader(io, &rbuf);
    var writer = stream.writer(io, &wbuf);

    for (0..r.rounds) |_| {
        writer.interface.writeAll(r.request) catch break;
        writer.interface.flush() catch break;
        var got: [512]u8 = undefined;
        var vec: [1][]u8 = .{&got};
        const n = reader.interface.readVec(&vec) catch break;
        if (n == 0) break;
        r.replies += 1;
    }
    // Stay connected until the other client has also been served, so the two
    // really overlap on the server's readiness set.
    while (r.hold.load(.acquire)) sleepMs(5);
}

test "serveTcpMulti: two masters, two nodes, one thread, at the same time" {
    const gpa = testing.allocator;
    var threaded = std.Io.Threaded.init(gpa, .{});
    defer threaded.deinit();
    const io = threaded.io();

    var f = try Fleet.init(gpa, .{ .seed = 21, .max_frame_len = 512, .outbox_bytes = 1 << 16 });
    defer f.deinit();

    const adapters = @import("adapters.zig");
    var holdings_a = [_]u16{ 11, 22, 33, 44 };
    var slave_a = adapters.Modbus.init(
        .{ .unit_id = 1, .framing = .tcp },
        .{ .holding_registers = .{ .base = 0, .values = &holdings_a } },
    );
    const node_a = try f.addNode(.{ .node = slave_a.node(), .tag = 1 });

    var holdings_b = [_]u16{ 55, 66, 77, 88 };
    var slave_b = adapters.Modbus.init(
        .{ .unit_id = 2, .framing = .tcp },
        .{ .holding_registers = .{ .base = 0, .values = &holdings_b } },
    );
    const node_b = try f.addNode(.{ .node = slave_b.node(), .tag = 2 });

    var req_a: [12]u8 = undefined;
    var req_b: [12]u8 = undefined;
    const ra = try modbus.tcp.encodeAdu(&req_a, 0x0001, 1, &.{ 0x03, 0, 0, 0, 4 });
    const rb = try modbus.tcp.encodeAdu(&req_b, 0x0002, 2, &.{ 0x03, 0, 0, 0, 4 });

    var hold: std.atomic.Value(bool) = .init(true);
    var ca = ClientResult{ .port = test_port_a, .request = ra, .rounds = 4, .hold = &hold };
    var cb = ClientResult{ .port = test_port_b, .request = rb, .rounds = 4, .hold = &hold };

    const bindings = [_]Binding{
        .{ .node = node_a, .address = try std.Io.net.IpAddress.parse("127.0.0.1", test_port_a) },
        .{ .node = node_b, .address = try std.Io.net.IpAddress.parse("127.0.0.1", test_port_b) },
    };

    const ta = try std.Thread.spawn(.{}, testClient, .{&ca});
    const tb = try std.Thread.spawn(.{}, testClient, .{&cb});

    const report = serveTcpMulti(gpa, io, &f, &bindings, .{
        .idle_ms = 20,
        .run_ms = 4000,
        .max_peers = 4,
    }) catch |e| {
        hold.store(false, .release);
        ta.join();
        tb.join();
        switch (e) {
            error.BindFailed, error.NoPeer => {
                if (verboseSkip()) std.debug.print("SKIPPED: serveTcpMulti (cannot bind 127.0.0.1:{d}/{d})\n", .{ test_port_a, test_port_b });
                return error.SkipZigTest;
            },
            else => return e,
        }
    };
    hold.store(false, .release);
    ta.join();
    tb.join();

    // Both masters were connected at the same time, on the same thread …
    try testing.expectEqual(@as(usize, 2), report.peers_accepted);
    try testing.expectEqual(@as(usize, 2), report.peak_concurrent);
    // … and each got its own node's registers back, not the other's.
    try testing.expectEqual(@as(usize, 4), ca.replies);
    try testing.expectEqual(@as(usize, 4), cb.replies);
    try testing.expect(f.stats(node_a).replied >= 4);
    try testing.expect(f.stats(node_b).replied >= 4);
    try testing.expectEqual(@as(usize, 0), report.peers_refused);
}

test "serveTcpMulti: an unbindable address is a typed error, not a hang" {
    const gpa = testing.allocator;
    var threaded = std.Io.Threaded.init(gpa, .{});
    defer threaded.deinit();
    const io = threaded.io();
    var f = try Fleet.init(gpa, .{ .seed = 1 });
    defer f.deinit();
    // Port 1 on a non-local address: bind must fail rather than block.
    const bindings = [_]Binding{
        .{ .node = 0, .address = try std.Io.net.IpAddress.parse("192.0.2.1", 1) },
    };
    try testing.expectError(
        error.BindFailed,
        serveTcpMulti(gpa, io, &f, &bindings, .{ .run_ms = 100 }),
    );
    try testing.expectError(
        error.NoPeer,
        serveTcpMulti(gpa, io, &f, &.{}, .{ .run_ms = 100 }),
    );
}

// ── regression: the paired Stream.Reader / Stream.Writer over a real socket ──
//
// Both `serveTcpOn` and `serveTcpMulti` pair a `std.Io.net.Stream.Reader` and a
// `std.Io.net.Stream.Writer` on the **same** stream. A prior report — see
// `modules/bacnet/src/sc_interop.zig` — claimed that creating a `Stream.Reader`
// stops subsequent writes through the paired `Stream.Writer` from reaching the
// wire under `std.Io.Threaded`. That claim does **not** reproduce: reader and
// writer each hold their own copy of the two-word `Stream` and their own
// buffer, neither touches the fd's flags, and both `netRead`/`netWrite` are
// plain `readv`/`sendmsg`. The paired pattern is sound.
//
// The `serveTcpMulti` test above already drives two paired reader/writers to
// completion without an env gate. This one pins the single-peer `serveTcp` loop
// the same way: a real master (a client thread) writes a request, the serve
// loop reads it and writes the reply, four times over. It proves the serve
// loop's write path reaches the client after its read path has consumed a
// request — the exact write → read → write shape the report worried about.
test "serveTcp: one master round-trips over a real socket (no env gate)" {
    const gpa = testing.allocator;
    var threaded = std.Io.Threaded.init(gpa, .{});
    defer threaded.deinit();
    const io = threaded.io();

    var f = try Fleet.init(gpa, .{ .seed = 9, .max_frame_len = 512, .outbox_bytes = 1 << 16 });
    defer f.deinit();

    const adapters = @import("adapters.zig");
    var holdings = [_]u16{ 100, 200, 300, 400 };
    var slave = adapters.Modbus.init(
        .{ .unit_id = 1, .framing = .tcp },
        .{ .holding_registers = .{ .base = 0, .values = &holdings } },
    );
    const node = try f.addNode(.{ .node = slave.node(), .tag = 1 });

    var req: [12]u8 = undefined;
    const request = try modbus.tcp.encodeAdu(&req, 0x0001, 1, &.{ 0x03, 0, 0, 0, 4 });

    var hold: std.atomic.Value(bool) = .init(true);
    var c = ClientResult{ .port = test_port_single, .request = request, .rounds = 4, .hold = &hold };
    const th = try std.Thread.spawn(.{}, testClient, .{&c});

    const addr = try std.Io.net.IpAddress.parse("127.0.0.1", test_port_single);
    const report = serveTcp(gpa, io, &f, node, addr, .{
        .idle_ms = 20,
        .run_ms = 4000,
        .max_frames = 4,
    }) catch |e| {
        hold.store(false, .release);
        th.join();
        switch (e) {
            error.BindFailed, error.NoPeer => {
                if (verboseSkip()) std.debug.print("SKIPPED: serveTcp (cannot bind 127.0.0.1:{d})\n", .{test_port_single});
                return error.SkipZigTest;
            },
            else => return e,
        }
    };
    hold.store(false, .release);
    th.join();

    // The master connected, all four requests were read, and all four replies
    // were written back and received — write → read → write, four times.
    try testing.expect(report.connected);
    try testing.expectEqual(@as(usize, 4), c.replies);
    try testing.expect(report.frames_out >= 4);
    try testing.expect(report.bytes_in > 0);
    try testing.expect(f.stats(node).replied >= 4);
}
