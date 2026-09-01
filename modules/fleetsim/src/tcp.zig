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
    /// A blocking wait was canceled through the `std.Io` cancellation
    /// protocol (`Future.cancel`) — an accept/read-readiness poll, or a UDP
    /// `receiveTimeout`/`send`. Surfaced instead of an ordinary idle round
    /// (or a silently truncated flush) so a caller shutting a session down
    /// can tell its own cancellation from "nothing arrived yet".
    Canceled,
} || fleet_mod.Error;

/// Monotonic milliseconds. The one place real time enters this module.
pub fn nowMs() u64 {
    var ts: std.posix.timespec = undefined;
    if (std.posix.errno(std.posix.system.clock_gettime(.MONOTONIC, &ts)) != .SUCCESS) return 0;
    return @as(u64, @intCast(ts.sec)) * 1000 + @as(u64, @intCast(ts.nsec)) / 1_000_000;
}

/// `Io.checkCancel` acknowledges the request and reports it exactly once;
/// the answer has to be converted into an error right here, not asked for
/// again.
fn checkCanceled(io: std.Io) error{Canceled}!void {
    io.checkCancel() catch return error.Canceled;
}

/// Distinguish a canceled wait from a genuine read/write failure using the
/// concrete `Stream.Reader`/`Stream.Writer`'s out-of-band `err` field —
/// `Io.Reader.Error`/`Io.Writer.Error` are exactly `{ReadFailed, EndOfStream}`
/// / `{WriteFailed}` and cannot carry `Canceled` themselves.
fn readCanceled(reader: *const std.Io.net.Stream.Reader) bool {
    return if (reader.err) |e| e == error.Canceled else false;
}

fn writeCanceled(writer: *const std.Io.net.Stream.Writer) bool {
    return if (writer.err) |e| e == error.Canceled else false;
}

/// The TCP data-transfer read, shared by `serveTcpOn` and `serveTcpMulti`.
/// Unlike `readable`'s raw `poll`, this is a genuine blocking `std.Io` call
/// (`Io.Reader.readVec` reaches the network only once its own buffer is
/// exhausted, at `net.zig`'s `readVec` → `io.vtable.netRead`), so it *is* a
/// real cancellation point and needs the `err`-field recovery, not a
/// `checkCancel` call. `0` means "stop the session" either way — end of
/// stream or an ordinary failure — matching this file's existing convention;
/// only a cancel gets a different exit, so the caller can tell it apart from
/// the peer just going away.
fn readData(reader: *std.Io.net.Stream.Reader, vec: [][]u8) error{Canceled}!usize {
    return reader.interface.readVec(vec) catch |e| switch (e) {
        error.EndOfStream => 0,
        error.ReadFailed => if (readCanceled(reader)) return error.Canceled else 0,
    };
}

/// The TCP data-transfer write, shared by `flush` and `writeTo`. `true` on
/// success; `false` on an ordinary failure, preserving each caller's existing
/// "stop and keep what was already sent" behavior; `error.Canceled` when the
/// wait was canceled, which must not be mistaken for either.
fn writeAllChecked(writer: *std.Io.net.Stream.Writer, bytes: []const u8) error{Canceled}!bool {
    writer.interface.writeAll(bytes) catch {
        if (writeCanceled(writer)) return error.Canceled;
        return false;
    };
    return true;
}

/// True when the fd has something to read, false when the wait elapsed with
/// nothing there.
///
/// `std.posix.poll` is not a `std.Io` cancellation point: it retries on
/// `EINTR`, and a thread parked in it is never signalled by `Threaded` at
/// all, so the wait runs to its full `ms` regardless of a pending
/// `Future.cancel` — which would otherwise come back as an ordinary "nothing
/// yet" round, leaving a caller that canceled a session polling a peer it has
/// already abandoned. `checkCanceled` recovers it on both exit paths: a poll
/// that fails outright still defers to the real read for the failure itself
/// (unchanged from before), but not before a cancel gets its turn.
/// `poll(2)` takes a SIGNED millisecond timeout, and a negative one means
/// "block forever". A bare `@intCast` from the `u32` these options carry
/// therefore panics above 2^31 ms (~24.8 days) in Debug and ReleaseSafe, and
/// in ReleaseFast silently becomes an infinite wait -- from an option value a
/// caller may set to "run for a month" without doing anything wrong. Measured
/// 2026-09-01: `readable(io, fd, 3_000_000_000)` -> `panic: integer does not
/// fit in destination type`. Saturating is the honest answer; a 24-day poll
/// round is already indistinguishable from forever.
fn pollTimeout(ms: u32) i32 {
    return @intCast(@min(ms, @as(u32, std.math.maxInt(i32))));
}

fn readable(io: std.Io, handle: std.posix.fd_t, ms: u32) error{Canceled}!bool {
    var fds = [_]std.posix.pollfd{.{ .fd = handle, .events = std.posix.POLL.IN, .revents = 0 }};
    const n = std.posix.poll(&fds, pollTimeout(ms)) catch {
        try checkCanceled(io);
        return true;
    };
    if (n != 0) return true;
    try checkCanceled(io);
    return false;
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
            if (!try readable(io, listener.socket.handle, budget)) {
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
    // `AcceptError` ends in `Io.Cancelable`, so folding it into `NoPeer` throws
    // a cancelation away -- and `serveTcp` turns `NoPeer` into a normal
    // `Report` once a session has connected, so a caller that cancelled a
    // shutdown was handed success. `Threaded.checkCancel` reports `.canceling`
    // only once, so nothing recovers it on a later round either.
    const stream = listener.accept(io) catch |e| switch (e) {
        error.Canceled => return error.Canceled,
        else => return error.NoPeer,
    };
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

    const start = nowMs();
    // A carry buffer for a frame split across two reads.
    var carry: usize = 0;

    while (true) {
        const real = nowMs();
        const t: Time = real - start;
        if (opts.run_ms != 0 and t >= opts.run_ms) break;
        if (opts.max_frames != 0 and report.frames_in >= opts.max_frames) break;

        if (r.bufferedLen() == 0 and !try readable(io, stream.socket.handle, opts.idle_ms)) {
            // Idle: still advance so timers and unsolicited traffic fire.
            _ = try fleet.advance(t);
            if (try flush(fleet, node, &writer, &report)) continue else continue;
        }

        // `readVec`, not `readSliceShort`: the latter keeps reading until the
        // destination is FULL, which on a request/response protocol means
        // waiting for 8 KiB that the master will never send. One underlying
        // read is exactly what a framed stream wants.
        var vec: [1][]u8 = .{buf[carry..]};
        const n = try readData(&reader, &vec);
        if (n == 0) break; // peer closed, or a genuine failure
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
        _ = try flush(fleet, node, &writer, &report);
    }

    // One last drain so a reply produced on the way out is not lost.
    _ = try fleet.advance(nowMs() - start);
    _ = try flush(fleet, node, &writer, &report);
    report.duration_ms = nowMs() - start;
    return report;
}

/// Takes the concrete `Stream.Writer`, not the abstract `Io.Writer` interface
/// it embeds, so a failed `writeAll`/`flush` can be checked against its
/// out-of-band `err` field — `Io.Writer.Error` cannot carry `Canceled`.
fn flush(fleet: *Fleet, node: NodeId, writer: *std.Io.net.Stream.Writer, report: *Report) !bool {
    var any = false;
    for (fleet.outbound()) |f| {
        if (f.node != node) continue;
        const bytes = fleet.frameBytes(f);
        if (!try writeAllChecked(writer, bytes)) return any;
        report.bytes_out += bytes.len;
        report.frames_out += 1;
        any = true;
    }
    if (any) writer.interface.flush() catch {
        if (writeCanceled(writer)) return error.Canceled;
        return any;
    };
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
    /// This peer's index in `fds` for the round in progress, or `null` when it
    /// is not in the readiness set.
    ///
    /// ⚠ Load-bearing, and the reason it exists is a defect. `fds` is built
    /// from the peers active BEFORE the accept pass; a peer accepted during
    /// that pass is active by the time the read loop runs but has no entry.
    /// The read loop used to walk the peers with a running cursor into `fds`,
    /// so from the first newly-accepted peer onward every peer read someone
    /// else's `revents` -- or, for the last one, an entry never written this
    /// round, which on the first round is the allocator's fill pattern
    /// (`0xaaaa`, whose bit 3 is `POLL.ERR`). The gate then opened and the
    /// loop entered a BLOCKING read on a peer that had sent nothing.
    /// Measured before the fix: one peer that connects, stays silent and does
    /// not hang up held a `run_ms = 700` loop for 3120 ms -- it was released
    /// by the peer's disconnect, not by its own deadline, so a peer that never
    /// disconnects wedges the single thread every other master shares.
    poll_i: ?usize = null,
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
    // Peers are closed on the normal exit path below, but the cancellation
    // campaign added early returns (`try readData`, `try flushMulti`) that
    // never reach it, and there was no `defer`. Measured: cancelling a loop
    // with one connected master leaked exactly one descriptor, so a supervisor
    // that cancels and restarts on a schedule walks into EMFILE. Registered
    // AFTER `gpa.free(peers)` so it runs BEFORE it; the normal path
    // deactivates every peer first, so nothing is closed twice.
    defer for (peers) |*p| {
        if (p.active) p.stream.close(io);
    };

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
            p.poll_i = null;
            if (!p.active) continue;
            if (p.reader.interface.bufferedLen() != 0) buffered = true;
            p.poll_i = n_fds;
            fds[n_fds] = .{ .fd = p.stream.socket.handle, .events = std.posix.POLL.IN, .revents = 0 };
            n_fds += 1;
        }

        var timeout: u32 = opts.idle_ms;
        if (opts.run_ms != 0) {
            const left = opts.run_ms - t;
            timeout = @intCast(@min(@as(u64, opts.idle_ms), left));
        }
        if (buffered) timeout = 0;
        // Same hazard as `readable` above, for a set of descriptors instead
        // of one: `poll` is not a cancellation point, so a canceled wait
        // would otherwise run to its full `timeout` and come back
        // indistinguishable from an ordinary empty round — on the timed-out
        // path (`ready == 0`) as much as on the "poll itself failed" path
        // (folded into `ready == 0` here too, since neither carries a peer to
        // blame). `checkCanceled` recovers it before the loop treats either
        // as "nothing to do this round".
        const ready = std.posix.poll(fds[0..n_fds], pollTimeout(timeout)) catch 0;
        if (ready == 0) try checkCanceled(io);

        if (ready != 0 and listener_fds != 0) {
            for (fds[0..listener_fds], 0..) |fd, i| {
                if (fd.revents & std.posix.POLL.IN == 0) continue;
                const stream = listeners[i].accept(io) catch |e| switch (e) {
                    // `catch continue` on an `AcceptError` discards a
                    // cancelation permanently -- see `serveTcpOn` above.
                    error.Canceled => return error.Canceled,
                    else => continue,
                };
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
        for (peers, 0..) |*p, slot| {
            if (!p.active) continue;
            // A peer with no entry this round was accepted after the set was
            // built: it has not been polled, so it is not ready. Waiting one
            // round costs nothing; guessing costs a blocking read.
            const revents: i16 = if (p.poll_i) |i| fds[i].revents else 0;
            const has_buffered = p.reader.interface.bufferedLen() != 0;
            if (!has_buffered and revents & (std.posix.POLL.IN | std.posix.POLL.HUP | std.posix.POLL.ERR) == 0) continue;

            var vec: [1][]u8 = .{p.buf[p.carry..]};
            const n = try readData(&p.reader, &vec);
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
                try writeTo(&peers[slot], bytes, report);
                continue;
            }
        }
        // Unsolicited: nobody asked, so tell everyone on that listener.
        for (peers) |*p| {
            if (p.active and p.binding == b) try writeTo(p, bytes, report);
        }
    }
    for (peers) |*p| {
        if (p.active) p.writer.interface.flush() catch {
            if (writeCanceled(&p.writer)) return error.Canceled;
        };
    }
}

/// A failed write is otherwise silently dropped here — an unsolicited-traffic
/// fan-out to several peers must not let one dead peer stop the others — but
/// a cancel is not "this peer is dead", so it still has to reach the caller.
fn writeTo(p: *Peer, bytes: []const u8, report: *MultiReport) error{Canceled}!void {
    if (!try writeAllChecked(&p.writer, bytes)) return;
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
            // Unlike the stream transports, `Socket.ReceiveTimeoutError`
            // already carries `Io.Cancelable` intact — there is no
            // out-of-band field to consult, so the only defect possible here
            // is throwing the variant away. Propagate it instead of letting
            // it fall into the catch-all below, where a canceled wait would
            // otherwise come back as an ordinary (if premature) end of
            // session.
            error.Canceled => return error.Canceled,
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
        // `Socket.SendError` carries `Io.Cancelable` intact too; the same
        // reasoning as the receive side above applies — a canceled send must
        // not come back looking like an ordinary truncated flush.
        socket.send(io, &dest, bytes) catch |e| switch (e) {
            error.Canceled => return error.Canceled,
            else => return any,
        };
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

/// Is the caller asserting that this host CAN open a loopback socket?
///
/// Every test in this file gives up with `error.SkipZigTest` when a
/// bind/connect/accept on 127.0.0.1 fails, and a skip reports PASS. That is
/// the right default -- a sandbox with no usable loopback should not fail a
/// build -- but it means this module's entire real-socket surface, the four
/// cancellation guards included, can vanish into a green run whose summary
/// line looks identical. `root.zig` already carries exactly this mechanism
/// for the third-party live tests (`FLEETSIM_EXPECT_LIVE`), and it stops at
/// that file. `FLEETSIM_EXPECT_TCP=1` is the sibling for this one: set it
/// where loopback is expected to work, and a skip becomes a failure that
/// names itself.
fn expectTcp() bool {
    const v = testkit.getEnv("FLEETSIM_EXPECT_TCP") orelse return false;
    return v.len > 0 and !std.mem.eql(u8, v, "0");
}

/// The gate every loopback-dependent test in this file gives up through.
fn socketSkip(what: []const u8) anyerror {
    if (expectTcp()) {
        std.debug.print("FLEETSIM_EXPECT_TCP is set but {s}\n", .{what});
        return error.TcpTestDidNotRun;
    }
    if (verboseSkip()) std.debug.print("SKIPPED: {s}\n", .{what});
    return error.SkipZigTest;
}

// ⚠ Derived from the pid, not fixed. With three constants here, two
// `test-fleetsim` runs at once stole each other's connections: the winner of
// the bind accepted the loser's clients too, so `peers_accepted` came back 1,
// 3 or 4 instead of 2 and the run failed on an assertion that looks entirely
// real. Measured during the 2026-09-01 audit -- two concurrent runs gave
// `expected 2, found 1` and `expected 2, found 3`, and a LONE run failed too
// while another lane was building. `scripts/test.sh` runs modules in parallel,
// so this was a false RED waiting for a busy machine. The newer cancellation
// tests in this file already bind port 0 for exactly this reason; these three
// predate that. A pid-derived base keeps the ports stable within one run (the
// client threads need to know them before the server binds) while making a
// collision between two runs require the same pid.
/// Runtime, not comptime: `getpid` is a syscall, and these three must differ
/// between two processes rather than between two builds.
fn testPortBase() u16 {
    // Strided by 4, not 1. Two processes spawned together get CONSECUTIVE
    // pids, so a stride of 1 makes run N's ports {b, b+1, b+2} overlap run
    // N+1's {b+1, b+2, b+3} -- measured: the first version of this fix still
    // failed two concurrent runs with `expected 2, found 3`. Four leaves a
    // gap wider than the three ports each run takes.
    return 15000 + @as(u16, @truncate(@as(u32, @bitCast(std.posix.system.getpid())) % 10000)) * 4;
}
fn testPortA() u16 {
    return testPortBase();
}
fn testPortB() u16 {
    return testPortBase() +% 1;
}
fn testPortSingle() u16 {
    return testPortBase() +% 2;
}

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
    var ca = ClientResult{ .port = testPortA(), .request = ra, .rounds = 4, .hold = &hold };
    var cb = ClientResult{ .port = testPortB(), .request = rb, .rounds = 4, .hold = &hold };

    const bindings = [_]Binding{
        .{ .node = node_a, .address = try std.Io.net.IpAddress.parse("127.0.0.1", testPortA()) },
        .{ .node = node_b, .address = try std.Io.net.IpAddress.parse("127.0.0.1", testPortB()) },
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
            // ⚠ `BindFailed` only. `NoPeer` used to skip here too, and that
            // is a SERVER verdict, not an environment one: the client threads
            // above did connect. Measured -- inverting `readable`'s readiness
            // predicate (`n != 0` -> `n == 0`), i.e. breaking the central
            // readiness decision, made this test print "cannot bind" and count
            // GREEN. A broken server reported as an unavailable port is the
            // skip-as-pass shape with a plausible cover story.
            error.BindFailed => return socketSkip("serveTcpMulti cannot bind 127.0.0.1"),
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
    var c = ClientResult{ .port = testPortSingle(), .request = request, .rounds = 4, .hold = &hold };
    const th = try std.Thread.spawn(.{}, testClient, .{&c});

    const addr = try std.Io.net.IpAddress.parse("127.0.0.1", testPortSingle());
    const report = serveTcp(gpa, io, &f, node, addr, .{
        .idle_ms = 20,
        .run_ms = 4000,
        .max_frames = 4,
    }) catch |e| {
        hold.store(false, .release);
        th.join();
        switch (e) {
            // `BindFailed` only -- see the note on the sibling test above.
            error.BindFailed => return socketSkip("serveTcp cannot bind 127.0.0.1"),
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

// ── cancellation ───────────────────────────────────────────────────────────
//
// `Future.cancel` unblocks a thread parked in a real `std.Io` call, but
// `readable`'s (and `serveTcpMulti`'s) wait is a raw `std.posix.poll`, which
// is outside `std.Io` entirely: it retries on `EINTR`, and a thread inside it
// is never signalled by `Threaded` at all, so the wait ran to its full
// timeout regardless — and used to come back as an ordinary idle round rather
// than `error.Canceled`. Both tests below use a small `idle_ms` because the
// canceled wait still costs its full timeout before `checkCanceled` gets a
// turn (`fut.cancel` waits for the task to actually return).

/// `io.concurrent` builds an `ArgsTuple` from the callee's signature at
/// comptime, which cannot be done for `serveTcpOn`'s `listener: anytype` —
/// this gives it a concrete one.
fn serveTcpOnConcrete(
    gpa: std.mem.Allocator,
    io: std.Io,
    fleet: *Fleet,
    node: NodeId,
    listener: *std.Io.net.Server,
    opts: Options,
) !Report {
    return serveTcpOn(gpa, io, fleet, node, listener, opts);
}

test "serveTcpOn: a canceled idle-read wait surfaces Canceled, not an idle round" {
    const gpa = testing.allocator;
    var threaded = std.Io.Threaded.init(gpa, .{});
    defer threaded.deinit();
    const io = threaded.io();

    var f = try Fleet.init(gpa, .{ .seed = 77 });
    defer f.deinit();

    const adapters = @import("adapters.zig");
    var holdings = [_]u16{0} ** 4;
    var slave = adapters.Modbus.init(
        .{ .unit_id = 1, .framing = .tcp },
        .{ .holding_registers = .{ .base = 0, .values = &holdings } },
    );
    const node = try f.addNode(.{ .node = slave.node(), .tag = 1 });

    // Port 0: an ephemeral port cannot collide with a parallel test run.
    const addr: std.Io.net.IpAddress = .{ .ip4 = .loopback(0) };
    var listener = addr.listen(io, .{ .reuse_address = true }) catch return socketSkip("loopback listen failed");
    defer listener.socket.close(io);

    // A peer that connects and then says nothing. TCP `connect` succeeds as
    // soon as the SYN is queued in the kernel backlog, before `accept` is
    // ever called, so `serveTcpOn`'s own accept (a real `std.Io` call)
    // returns immediately and the loop parks in the idle-read wait under
    // test.
    var client = listener.socket.address.connect(io, .{ .mode = .stream }) catch return socketSkip("loopback connect failed");
    defer client.close(io);

    // `run_ms` is a safety net only: the cancel below always arrives well
    // inside it. It exists so that if cancellation recovery were ever broken
    // again, this test would fail fast instead of hanging the suite — the
    // loop is otherwise unbounded (`Options.run_ms` defaults to 0, "forever").
    var fut = try io.concurrent(serveTcpOnConcrete, .{ gpa, io, &f, node, &listener, Options{ .idle_ms = 600, .run_ms = 3000 } });
    try io.sleep(.fromMilliseconds(100), .awake);
    try testing.expectError(error.Canceled, fut.cancel(io));
}

test "serveTcpMulti: a canceled readiness wait surfaces Canceled, not an idle round" {
    const gpa = testing.allocator;
    var threaded = std.Io.Threaded.init(gpa, .{});
    defer threaded.deinit();
    const io = threaded.io();

    var f = try Fleet.init(gpa, .{ .seed = 88 });
    defer f.deinit();

    // No peer ever connects, so the loop sits polling the listener fd alone
    // — the many-descriptor path `serveTcpOn` doesn't exercise.
    const bindings = [_]Binding{
        .{ .node = 0, .address = .{ .ip4 = .loopback(0) } },
    };

    // See the `run_ms` note in the `serveTcpOn` test above: a safety net, not
    // part of the path under test.
    var fut = try io.concurrent(serveTcpMulti, .{ gpa, io, &f, &bindings, MultiOptions{ .idle_ms = 600, .run_ms = 3000 } });
    try io.sleep(.fromMilliseconds(100), .awake);
    _ = fut.cancel(io) catch |e| switch (e) {
        error.Canceled => return,
        error.BindFailed => return socketSkip("loopback bind failed"),
        else => return e,
    };
    return error.TestUnexpectedResult;
}

test "serveUdp: a canceled receive wait surfaces Canceled, not an idle round" {
    const gpa = testing.allocator;
    var threaded = std.Io.Threaded.init(gpa, .{});
    defer threaded.deinit();
    const io = threaded.io();

    var f = try Fleet.init(gpa, .{ .seed = 99 });
    defer f.deinit();

    // Nothing ever sends to this port, and no node needs to be registered:
    // `flushUdp` returns before touching `fleet`/`node` at all while
    // `last_peer` is still null, so a plain `0` stands in for the node id.
    // Port 0: an ephemeral port cannot collide with a parallel test run.
    const addr: std.Io.net.IpAddress = .{ .ip4 = .loopback(0) };

    // `run_ms` is a safety net only, same reasoning as the TCP cancellation
    // tests above: the loop is otherwise unbounded, and a broken cancel path
    // must fail fast rather than hang the suite.
    var fut = try io.concurrent(serveUdp, .{ gpa, io, &f, @as(NodeId, 0), addr, Options{ .idle_ms = 600, .run_ms = 3000 } });
    try io.sleep(.fromMilliseconds(100), .awake);
    try testing.expectError(error.Canceled, fut.cancel(io));
}

// ── the TCP data-transfer read/write fold ───────────────────────────────────
//
// `readable`'s raw `poll` is not the only place a cancel could be lost.
// `serveTcpOn`/`serveTcpMulti` only ever call into `Io.Reader.readVec` once
// `readable` (or a peer already known to be readable) says there is
// something there, but `readVec` itself reaches the network — a genuine
// `std.Io` call, and a real cancellation point distinct from the poll gate in
// front of it — whenever more is asked for than is already buffered, which is
// always true here (`buf[carry..]` spans the whole remaining read buffer).
// `readData`, the helper both loops now share, is what recovers the reason
// from `reader.err`; this drives it directly against a silent peer, the same
// probe shape as the poll-based tests above but parked in the read itself.

fn readOnce(reader: *std.Io.net.Stream.Reader, buf: []u8) error{Canceled}!usize {
    var vec: [1][]u8 = .{buf};
    return readData(reader, &vec);
}

test "readData: a canceled blocking read surfaces Canceled, not 0" {
    const gpa = testing.allocator;
    var threaded = std.Io.Threaded.init(gpa, .{});
    defer threaded.deinit();
    const io = threaded.io();

    // Port 0: an ephemeral port cannot collide with a parallel test run.
    const addr: std.Io.net.IpAddress = .{ .ip4 = .loopback(0) };
    var listener = addr.listen(io, .{ .reuse_address = true }) catch return socketSkip("loopback listen failed");
    defer listener.socket.close(io);

    // Loopback `connect` succeeds as soon as the SYN is queued in the kernel
    // backlog, so a plain sequential connect-then-accept is enough here —
    // unlike the `serveTcpOn` cancellation test above, nothing under test
    // runs between the two.
    var client = listener.socket.address.connect(io, .{ .mode = .stream }) catch return socketSkip("loopback connect failed");
    defer client.close(io);
    var accepted = listener.accept(io) catch return socketSkip("loopback accept failed");
    defer accepted.close(io);

    var rbuf: [64]u8 = undefined;
    var reader = accepted.reader(io, &rbuf);
    var buf: [64]u8 = undefined;

    // Nothing is ever written to `accepted`, and the reader's own buffer
    // starts empty, so the read genuinely parks in `io.vtable.netRead`.
    var fut = try io.concurrent(readOnce, .{ &reader, &buf });
    try io.sleep(.fromMilliseconds(100), .awake);
    try testing.expectError(error.Canceled, fut.cancel(io));
}

// ── audit 2026-09-01: the real-socket surface, held by nothing ─────────────

/// A peer that connects, stays silent, and does not hang up. Two of the tests
/// below need one; both used to pass with the loop wedged.
const SilentPeer = struct {
    port: u16,
    hold_ms: u64,
    connected: std.atomic.Value(bool) = .init(false),

    fn run(self: *SilentPeer) void {
        // `testing.allocator`, not `page_allocator`: the repo's
        // check-global-alloc gate forbids reaching for a process-global
        // allocator outside a test block, and the sibling `testClient`
        // above already does it this way.
        var t: std.Io.Threaded = .init(testing.allocator, .{});
        defer t.deinit();
        const io = t.io();
        const a = std.Io.net.IpAddress.parse("127.0.0.1", self.port) catch return;
        var c = a.connect(io, .{ .mode = .stream }) catch return;
        self.connected.store(true, .release);
        sleepMs(self.hold_ms);
        c.close(io);
    }
};

// `nowMs` and `sleepMs` already exist above; reused here.

test "serveTcpMulti: one silent peer must not hold the loop past its own deadline" {
    // The readiness set `fds` is built from the peers active BEFORE the accept
    // pass. A peer accepted DURING that pass is active by the time the read
    // loop runs but has no entry, and the loop used to index `fds` with a
    // running cursor -- so it read a stale entry (on the first round, the
    // allocator's 0xaaaa fill, whose bit 3 is POLL.ERR), opened the gate, and
    // entered a BLOCKING read on a peer that had sent nothing.
    //
    // Measured before the fix: run_ms = 700, actual 3120 ms -- the loop was
    // released by the peer's disconnect, not by its own deadline. A peer that
    // never disconnects wedges the single thread every other master shares.
    const gpa = testing.allocator;
    var threaded = std.Io.Threaded.init(gpa, .{});
    defer threaded.deinit();
    const io = threaded.io();

    const adapters = @import("adapters.zig");
    var holdings = [_]u16{ 1, 2, 3, 4 };
    var slave = adapters.Modbus.init(
        .{ .unit_id = 1, .framing = .tcp },
        .{ .holding_registers = .{ .base = 0, .values = &holdings } },
    );
    var f = try Fleet.init(gpa, .{});
    defer f.deinit();
    const node = try f.addNode(.{ .node = slave.node(), .tag = 1 });

    const port = testPortA();
    const bindings = [_]Binding{
        .{ .node = node, .address = try std.Io.net.IpAddress.parse("127.0.0.1", port) },
    };

    var peer: SilentPeer = .{ .port = port, .hold_ms = 2500 };
    const th = try std.Thread.spawn(.{}, SilentPeer.run, .{&peer});
    defer th.join();

    const t0 = nowMs();
    const report = serveTcpMulti(gpa, io, &f, &bindings, .{
        .run_ms = 600,
        .idle_ms = 50,
    }) catch |e| switch (e) {
        error.BindFailed => return socketSkip("cannot bind 127.0.0.1"),
        else => return e,
    };
    const wall = nowMs() - t0;

    // Generous: the point is 600 vs 2500+, not a tight timing assertion.
    if (wall > 1500) {
        std.debug.print(
            "serveTcpMulti ran {d}ms against run_ms=600 -- a silent peer is holding the loop\n",
            .{wall},
        );
        return error.DeadlineIgnored;
    }
    _ = report;
}

test "serveTcpOn: a canceled accept surfaces Canceled, not NoPeer" {
    // `AcceptError` ends in `Io.Cancelable`, and `catch return error.NoPeer`
    // threw that away. `serveTcp` then turns `NoPeer` into a normal `Report`
    // once a session has connected, so a caller that canceled a shutdown was
    // handed success -- and `Threaded.checkCancel` reports `.canceling` only
    // once, so no later round recovers it either.
    const gpa = testing.allocator;
    var threaded = std.Io.Threaded.init(gpa, .{});
    defer threaded.deinit();
    const io = threaded.io();

    var f = try Fleet.init(gpa, .{});
    defer f.deinit();

    // Port 0: an ephemeral port cannot collide with a parallel test run.
    const addr: std.Io.net.IpAddress = .{ .ip4 = .loopback(0) };
    var listener = addr.listen(io, .{ .reuse_address = true }) catch return socketSkip("loopback listen failed");
    defer listener.socket.close(io);

    const Run = struct {
        fn go(io2: std.Io, gpa2: std.mem.Allocator, f2: *Fleet, l: *std.Io.net.Server) !Report {
            return serveTcpOn(gpa2, io2, f2, 0, l, .{ .run_ms = 5000, .idle_ms = 50 });
        }
    };
    // Nobody ever connects, so the accept below is parked when the cancel lands.
    var fut = try io.concurrent(Run.go, .{ io, gpa, &f, &listener });
    try io.sleep(.fromMilliseconds(100), .awake);
    const res = fut.cancel(io);
    try testing.expectError(error.Canceled, res);
}

/// How many descriptors this process holds. Used to catch a leak that no
/// allocator can see: `std.testing.allocator` is clean across a canceled
/// `serveTcpMulti` because every `gpa.free` is a `defer` -- it was only the
/// accepted sockets that were left open.
fn openFdCount() usize {
    var n: usize = 0;
    var fd: i32 = 0;
    while (fd < 4096) : (fd += 1) {
        if (std.posix.errno(std.posix.system.fcntl(fd, std.posix.F.GETFD, @as(usize, 0))) == .SUCCESS) n += 1;
    }
    return n;
}

test "serveTcpMulti: a canceled loop closes the peers it accepted" {
    // Peers were closed only on the normal exit path. The cancellation
    // campaign added early returns (`try readData`, `try flushMulti`) that
    // skip it, and there was no `defer` -- measured: cancelling with one
    // connected master leaked exactly one descriptor, so a supervisor that
    // cancels and restarts on a schedule walks into EMFILE.
    const gpa = testing.allocator;
    var threaded = std.Io.Threaded.init(gpa, .{});
    defer threaded.deinit();
    const io = threaded.io();

    const adapters = @import("adapters.zig");
    var holdings = [_]u16{ 1, 2, 3, 4 };
    var slave = adapters.Modbus.init(
        .{ .unit_id = 1, .framing = .tcp },
        .{ .holding_registers = .{ .base = 0, .values = &holdings } },
    );
    var f = try Fleet.init(gpa, .{});
    defer f.deinit();
    const node = try f.addNode(.{ .node = slave.node(), .tag = 1 });

    const port = testPortB();
    const bindings = [_]Binding{
        .{ .node = node, .address = try std.Io.net.IpAddress.parse("127.0.0.1", port) },
    };

    const Run = struct {
        fn go(
            io2: std.Io,
            gpa2: std.mem.Allocator,
            f2: *Fleet,
            b: []const Binding,
        ) !MultiReport {
            return serveTcpMulti(gpa2, io2, f2, b, .{ .run_ms = 5000, .idle_ms = 30 });
        }
    };

    const before = openFdCount();
    var fut = try io.concurrent(Run.go, .{ io, gpa, &f, bindings[0..] });

    var peer: SilentPeer = .{ .port = port, .hold_ms = 4000 };
    const th = try std.Thread.spawn(.{}, SilentPeer.run, .{&peer});

    // Wait for the peer to be connected AND accepted, so there is a descriptor
    // to leak when the cancel lands.
    var waited: u64 = 0;
    while (waited < 2000 and !peer.connected.load(.acquire)) : (waited += 20) sleepMs(20);
    sleepMs(150);

    const res = fut.cancel(io);
    th.join();

    if (res) |_| {
        // The loop finished on its own (bind failed, or the peer never
        // arrived): nothing to assert about a cancel that did not happen.
        return socketSkip("the cancel raced the loop's own exit");
    } else |e| switch (e) {
        error.Canceled => {},
        error.BindFailed => return socketSkip("cannot bind 127.0.0.1"),
        else => return e,
    }

    const after = openFdCount();
    if (after > before) {
        std.debug.print(
            "canceled serveTcpMulti leaked {d} descriptor(s) ({d} -> {d})\n",
            .{ after - before, before, after },
        );
        return error.DescriptorLeak;
    }
}

test "a run_ms past 2^31 ms saturates the poll timeout instead of panicking" {
    // `poll(2)`'s timeout is signed and negative means "forever", so the bare
    // `@intCast` these two call sites used panicked in Debug/ReleaseSafe and
    // became an infinite wait in ReleaseFast — reachable from an ordinary
    // "run for a month" option value, with no misuse on the caller's part.
    try testing.expectEqual(@as(i32, 0), pollTimeout(0));
    try testing.expectEqual(@as(i32, 200), pollTimeout(200));
    try testing.expectEqual(@as(i32, std.math.maxInt(i32)), pollTimeout(std.math.maxInt(i32)));
    try testing.expectEqual(@as(i32, std.math.maxInt(i32)), pollTimeout(std.math.maxInt(i32) + 1));
    try testing.expectEqual(@as(i32, std.math.maxInt(i32)), pollTimeout(3_000_000_000));
    try testing.expectEqual(@as(i32, std.math.maxInt(i32)), pollTimeout(std.math.maxInt(u32)));
}
