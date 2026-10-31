// SPDX-License-Identifier: MIT
//! Blocking network emitters for RFC 5424 messages over `std.Io.net`, plus the
//! transport-only codec pieces (UDP datagram assembly with a truncation marker,
//! RFC 6587 octet-counting TCP framing). The framing helpers are pure and
//! tested offline; the `UdpEmitter`/`TcpEmitter` structs are convenience
//! adapters that only touch the network when a caller constructs one — no test
//! opens a socket.

const std = @import("std");
const message = @import("message.zig");
const linux = std.os.linux;

const Message = message.Message;

/// Practical UDP datagram budget. RFC 5424 §6.1 requires receivers to accept
/// ≥ 480 bytes and recommends ≥ 2048; 1024 is a safe default that avoids IP
/// fragmentation on typical MTUs.
pub const default_udp_limit: usize = 1024;

/// Appended (replacing the tail) when a datagram would exceed the UDP budget.
pub const default_trunc_marker = "...[TRUNCATED]";

/// Internal scratch size — must hold a full, un-truncated message before the
/// UDP budget is applied. RFC 5424 SHOULD-support ceiling.
const scratch_len = 2048;

pub const Options = struct {
    udp_limit: usize = default_udp_limit,
    trunc_marker: []const u8 = default_trunc_marker,
};

/// Format `msg` into `scratch` and return the datagram payload, truncated to
/// `opts.udp_limit` with `opts.trunc_marker` substituted for the overflowing
/// tail. `scratch` should be ≥ `default_udp_limit`.
pub fn buildDatagram(msg: *const Message, scratch: []u8, opts: Options) []const u8 {
    var w: std.Io.Writer = .fixed(scratch);
    // On overflow the fixed writer stops at capacity; the partial content in
    // `scratch` is what we then truncate — either way we clamp below.
    //
    // The overflow itself must be remembered: when `udp_limit >= scratch.len`
    // a message longer than `scratch` comes back exactly `limit` bytes long,
    // so `bytes.len > limit` alone missed it and the datagram went out cut
    // short WITHOUT the marker -- a silent truncation, the one thing the
    // marker exists to rule out (audit 2026-10-04).
    const overflowed = if (msg.format(&w)) |_| false else |_| true;
    var bytes = w.buffered();

    const limit = @min(opts.udp_limit, scratch.len);
    if (bytes.len > limit or overflowed) {
        const mlen = @min(opts.trunc_marker.len, limit);
        const keep = limit - mlen;
        @memcpy(scratch[keep .. keep + mlen], opts.trunc_marker[0..mlen]);
        bytes = scratch[0 .. keep + mlen];
    }
    return bytes;
}

/// RFC 6587 §3.4.1 octet-counting frame: `MSG-LEN SP SYSLOG-MSG`, where
/// `MSG-LEN` is the decimal byte length of `payload`.
pub fn writeOctetCounted(w: *std.Io.Writer, payload: []const u8) std.Io.Writer.Error!void {
    try w.print("{d} ", .{payload.len});
    try w.writeAll(payload);
}

// ── UDP emitter ─────────────────────────────────────────────────────────────

/// One-datagram-per-message UDP sender (syslog/udp is port 514). Construct with
/// `open`; nothing here runs until you call `send`.
pub const UdpEmitter = struct {
    io: std.Io,
    socket: std.Io.net.Socket,
    peer: std.Io.net.IpAddress,
    options: Options = .{},
    scratch: [scratch_len]u8 = undefined,

    pub fn open(io: std.Io, peer: std.Io.net.IpAddress, options: Options) !UdpEmitter {
        const local: std.Io.net.IpAddress = switch (peer) {
            .ip4 => .{ .ip4 = .unspecified(0) },
            .ip6 => .{ .ip6 = .unspecified(0) },
        };
        const socket = try local.bind(io, .{ .mode = .dgram });
        return .{ .io = io, .socket = socket, .peer = peer, .options = options };
    }

    pub fn close(e: *UdpEmitter) void {
        e.socket.close(e.io);
    }

    /// Assemble and send one datagram. Over-budget messages are truncated with
    /// the marker rather than fragmented.
    pub fn send(e: *UdpEmitter, msg: *const Message) !void {
        const bytes = buildDatagram(msg, &e.scratch, e.options);
        try e.socket.send(e.io, &e.peer, bytes);
    }
};

// ── TCP emitter ─────────────────────────────────────────────────────────────

/// Default `connect` deadline (ms): a blackhole address otherwise hangs for
/// about two minutes in the kernel's SYN retries.
pub const default_connect_timeout_ms: u32 = 5000;

/// Default `TcpEmitter.send_timeout_ms`: one deadline for a whole frame.
pub const default_send_timeout_ms: u32 = 1000;

/// Room reserved in front of the payload for the `MSG-LEN SP` prefix
/// (`scratch_len` = 2048 needs 5 bytes; 8 is generous).
const prefix_room = 8;

fn msTimeout(ms: u32) std.Io.Timeout {
    return .{ .duration = .{ .raw = .fromMilliseconds(ms), .clock = .awake } };
}

/// RFC 6587 octet-counted TCP sender (syslog/tcp is port 514). Construct with
/// `connect`; each `send` writes one `MSG-LEN SP MSG` frame.
///
/// Bounded waits (sweep RV-SL-1): `connect` gives up after
/// `default_connect_timeout_ms` (`connectTimeout` picks another) with
/// `error.Timeout`; `send` has ONE absolute deadline of `send_timeout_ms` for the
/// whole frame (0: fail if the first write would block) and returns
/// `error.Timeout` -- a collector that stopped reading (zero window) can no
/// longer block the caller forever.
///
/// Sticky failure (sweep RV-SL-4): a failure that happens after at least one
/// byte of a frame went out (timeout, write error, cancellation) leaves the
/// octet-counted stream desynchronised, so the emitter is marked broken and
/// every later `send` returns `error.Broken` without touching the socket; close
/// it and connect again. A failure with NOTHING written (a timeout on the first
/// write, `NoSpaceLeft` while formatting) leaves it usable.
pub const TcpEmitter = struct {
    io: std.Io,
    stream: std.Io.net.Stream,
    scratch: [prefix_room + scratch_len]u8 = undefined,
    /// Deadline of one `send`, ms. See the type's doc comment.
    send_timeout_ms: u32 = default_send_timeout_ms,
    /// Set by a failure mid-frame; see the type's doc comment.
    broken: bool = false,

    /// `connectTimeout` with `default_connect_timeout_ms`.
    pub fn connect(io: std.Io, address: std.Io.net.IpAddress) !TcpEmitter {
        return connectTimeout(io, address, default_connect_timeout_ms);
    }

    pub const ConnectError = error{
        Timeout,
        ConnectionRefused,
        NetworkUnreachable,
        HostUnreachable,
        SocketFailed,
        ConnectFailed,
    };

    /// Connect, failing with `error.Timeout` after `connect_timeout_ms`.
    ///
    /// Raw non-blocking connect + poll, not `IpAddress.connect(.., .timeout)`:
    /// std 0.17's `Io.Threaded` panics on any connect timeout ("TODO implement
    /// netConnectIpPosix with timeout", Io/Threaded.zig:12410), and without one a
    /// blackhole address hangs for about two minutes. Linux only; the socket is
    /// switched back to blocking before it is handed to std's stream code (std
    /// treats EAGAIN as a bug). An IPv6 address is connected with scope id 0
    /// (a link-local address needing an interface scope is not supported here).
    pub fn connectTimeout(io: std.Io, address: std.Io.net.IpAddress, connect_timeout_ms: u32) ConnectError!TcpEmitter {
        const fd = try connectNonBlocking(address, connect_timeout_ms);
        return .{ .io = io, .stream = .{ .socket = .{ .handle = fd, .address = address } } };
    }

    pub fn close(e: *TcpEmitter) void {
        e.stream.close(e.io);
    }

    /// Failures reported by `send`. `Canceled`: the write was canceled through
    /// the `std.Io` cancellation protocol (`Future.cancel`). `Timeout`: the
    /// deadline passed. `Broken`: an earlier send failed mid-frame (see the
    /// type's doc comment).
    pub const SendError = error{ Canceled, NoSpaceLeft, Timeout, Broken } || std.Io.Writer.Error;

    pub fn send(e: *TcpEmitter, msg: *const Message) SendError!void {
        if (e.broken) return error.Broken;
        const payload = try message.bufPrint(msg, e.scratch[prefix_room..][0..scratch_len]);
        var pbuf: [prefix_room]u8 = undefined;
        const prefix = std.fmt.bufPrint(&pbuf, "{d} ", .{payload.len}) catch unreachable; // payload.len <= 2048: 5 bytes <= prefix_room
        const start = prefix_room - prefix.len;
        @memcpy(e.scratch[start..prefix_room], prefix);
        const frame = e.scratch[start .. prefix_room + payload.len];

        var step: NetStep = .{ .e = e, .deadline = msTimeout(e.send_timeout_ms).toDeadline(e.io) };
        return e.finish(writeFrame(&step, frame));
    }

    /// Apply the sticky-failure rule to the outcome of one frame.
    fn finish(e: *TcpEmitter, r: FrameResult) SendError!void {
        if (r.err) |err| {
            if (r.written != 0) e.broken = true;
            return err;
        }
    }

    const NetStep = struct {
        e: *TcpEmitter,
        deadline: std.Io.Timeout,

        /// One bounded write of (a prefix of) `chunk`; returns bytes written.
        /// The batch is ALWAYS cancelled before returning, so no pending
        /// operation can still reference `chunk` afterwards; an operation that
        /// completed despite a timeout still counts (its bytes are on the wire).
        fn write(self: *NetStep, chunk: []const u8) SendError!usize {
            const io = self.e.io;
            const data = [_][]const u8{chunk};
            const op: std.Io.Operation = .{ .net_write = .{ .socket_handle = self.e.stream.socket.handle, .data = &data } };
            var storage: [1]std.Io.Operation.Storage = undefined;
            var batch: std.Io.Batch = .init(&storage);
            batch.addAt(0, op);
            const waited = batch.awaitConcurrent(io, self.deadline);
            batch.cancel(io);
            if (batch.next()) |done| {
                const n = done.result.net_write catch return error.WriteFailed;
                return n;
            }
            waited catch |err| switch (err) {
                error.Timeout => return error.Timeout,
                error.Canceled => return error.Canceled,
                // The Io cannot run the wait concurrently (not the case for
                // std.Io.Threaded on Linux, which polls): write untimed
                // rather than fail every send. Documented gap: this write
                // has no deadline.
                error.ConcurrencyUnavailable => {
                    const res = io.operate(op) catch return error.Canceled;
                    return res.net_write catch error.WriteFailed;
                },
            };
            return error.WriteFailed;
        }
    };
};

fn monotonicMs() ?u64 {
    var ts: linux.timespec = undefined;
    if (linux.errno(linux.clock_gettime(.MONOTONIC, &ts)) != .SUCCESS) return null;
    return @as(u64, @intCast(ts.sec)) *| 1000 +| @as(u64, @intCast(ts.nsec)) / std.time.ns_per_ms;
}

fn connectNonBlocking(address: std.Io.net.IpAddress, timeout_ms: u32) TcpEmitter.ConnectError!linux.fd_t {
    var storage: extern union { in4: linux.sockaddr.in, in6: linux.sockaddr.in6 } = undefined;
    var len: linux.socklen_t = undefined;
    const family: u32 = switch (address) {
        .ip4 => |a| blk: {
            storage.in4 = .{ .port = std.mem.nativeToBig(u16, a.port), .addr = @bitCast(a.bytes) };
            len = @sizeOf(linux.sockaddr.in);
            break :blk linux.AF.INET;
        },
        .ip6 => |a| blk: {
            storage.in6 = .{ .port = std.mem.nativeToBig(u16, a.port), .flowinfo = a.flow, .addr = a.bytes, .scope_id = 0 };
            len = @sizeOf(linux.sockaddr.in6);
            break :blk linux.AF.INET6;
        },
    };
    const rc = linux.socket(family, linux.SOCK.STREAM | linux.SOCK.NONBLOCK | linux.SOCK.CLOEXEC, 0);
    if (linux.errno(rc) != .SUCCESS) return error.SocketFailed;
    const fd: linux.fd_t = @intCast(rc);
    errdefer _ = linux.close(fd);

    const start = monotonicMs();
    const crc = linux.connect(fd, @ptrCast(&storage), len);
    switch (linux.errno(crc)) {
        .SUCCESS => {},
        .INPROGRESS, .INTR => {
            // Absolute deadline; an unreadable clock means no waiting at all.
            const begin = start orelse return error.Timeout;
            while (true) {
                const now = monotonicMs() orelse return error.Timeout;
                const spent = now -| begin;
                if (spent >= timeout_ms) return error.Timeout;
                var pfd = [1]linux.pollfd{.{ .fd = fd, .events = linux.POLL.OUT, .revents = 0 }};
                const left: i32 = @intCast(@min(timeout_ms - spent, std.math.maxInt(i32)));
                const prc = linux.poll(&pfd, 1, left);
                switch (linux.errno(prc)) {
                    .SUCCESS => if (prc != 0) break,
                    .INTR => {},
                    else => return error.ConnectFailed,
                }
            }
            var soerr: i32 = 0;
            var olen: linux.socklen_t = @sizeOf(i32);
            if (linux.errno(linux.getsockopt(fd, linux.SOL.SOCKET, linux.SO.ERROR, @ptrCast(&soerr), &olen)) != .SUCCESS)
                return error.ConnectFailed;
            if (soerr != 0) return mapConnectErrno(@fromBackingInt(@intCast(soerr)));
        },
        else => |e| return mapConnectErrno(e),
    }
    // Back to blocking: std's stream code treats EAGAIN as a bug.
    const fl = linux.fcntl(fd, linux.F.GETFL, 0);
    if (linux.errno(fl) != .SUCCESS) return error.ConnectFailed;
    const nonblock: usize = 1 << @bitOffsetOf(linux.O, "NONBLOCK");
    if (linux.errno(linux.fcntl(fd, linux.F.SETFL, fl & ~nonblock)) != .SUCCESS) return error.ConnectFailed;
    return fd;
}

fn mapConnectErrno(e: linux.E) TcpEmitter.ConnectError {
    return switch (e) {
        .CONNREFUSED => error.ConnectionRefused,
        .NETUNREACH => error.NetworkUnreachable,
        .HOSTUNREACH => error.HostUnreachable,
        .TIMEDOUT => error.Timeout,
        else => error.ConnectFailed,
    };
}

const FrameResult = struct { written: usize, err: ?TcpEmitter.SendError };

/// Write all of `frame` through `step.write(chunk)`; report how many bytes got
/// out and why it stopped.
fn writeFrame(step: anytype, frame: []const u8) FrameResult {
    var off: usize = 0;
    while (off < frame.len) {
        const n = step.write(frame[off..]) catch |err| return .{ .written = off, .err = err };
        if (n == 0) return .{ .written = off, .err = error.WriteFailed };
        off += @min(n, frame.len - off);
    }
    return .{ .written = off, .err = null };
}

// ── tests (offline: framing bytes only, never a socket) ─────────────────────

const t = std.testing;

test "octet-counting frame carries the exact MSG-LEN prefix" {
    const msg = Message{ .facility = .user, .severity = .notice };
    var mbuf: [64]u8 = undefined;
    const payload = try message.bufPrint(&msg, &mbuf); // "<13>1 - - - - - -"

    var out: [128]u8 = undefined;
    var w: std.Io.Writer = .fixed(&out);
    try writeOctetCounted(&w, payload);

    // "<MSG-LEN> " prefix (17-byte payload) then the message verbatim.
    try t.expectEqualStrings("17 <13>1 - - - - - -", w.buffered());
    try t.expectEqual(@as(usize, 17), payload.len);
}

test "buildDatagram passes a small message through unchanged" {
    const msg = Message{ .facility = .user, .severity = .notice };
    var scratch: [scratch_len]u8 = undefined;
    const dg = buildDatagram(&msg, &scratch, .{});
    try t.expectEqualStrings("<13>1 - - - - - -", dg);
}

test "buildDatagram: a budget shorter than the marker keeps only the marker's head" {
    // The datagram is "truncated to `opts.udp_limit`" (doc) -- even when the
    // marker itself does not fit; it is then cut, never written past the
    // budget. Mutation 2026-10-04: an unclamped marker survived (it
    // underflows `limit - mlen`).
    var scratch: [scratch_len]u8 = undefined;
    const msg = Message{ .msg = strRepeat("A", 100) };
    const dg = buildDatagram(&msg, &scratch, .{ .udp_limit = 4 });
    try std.testing.expectEqualStrings("...[", dg);
}

test "buildDatagram marks a message that overflows the scratch buffer itself" {
    // `buildDatagram` doc: the payload is "truncated ... with
    // `opts.trunc_marker` substituted for the overflowing tail". With a
    // budget at or above the scratch size, a message longer than the scratch
    // used to come back exactly `scratch.len` bytes and unmarked, because
    // only `bytes.len > limit` was checked (audit 2026-10-04).
    var scratch: [64]u8 = undefined;
    const msg = Message{ .msg = strRepeat("x", 200) };
    const dg = buildDatagram(&msg, &scratch, .{ .udp_limit = 2048 });
    try std.testing.expectEqual(@as(usize, 64), dg.len);
    try std.testing.expect(std.mem.endsWith(u8, dg, default_trunc_marker));
    // A message that fits the scratch exactly is still passed through whole.
    var fits: [256]u8 = undefined;
    const whole = buildDatagram(&msg, &fits, .{ .udp_limit = 2048 });
    try std.testing.expect(std.mem.endsWith(u8, whole, strRepeat("x", 200)));
}

test "buildDatagram truncates and appends the marker over budget" {
    const msg = Message{ .facility = .user, .severity = .notice, .msg = strRepeat("A", 400) };
    var scratch: [scratch_len]u8 = undefined;
    const opts = Options{ .udp_limit = 64, .trunc_marker = "...[TRUNCATED]" };
    const dg = buildDatagram(&msg, &scratch, opts);
    try t.expectEqual(@as(usize, 64), dg.len);
    try t.expect(std.mem.endsWith(u8, dg, "...[TRUNCATED]"));
    try t.expect(std.mem.startsWith(u8, dg, "<13>1 - - - - - - A"));
}

const MockStep = struct {
    script: []const ?usize, // null: fail with Timeout; n: write n bytes
    i: usize = 0,
    fn write(m: *MockStep, chunk: []const u8) TcpEmitter.SendError!usize {
        defer m.i += 1;
        const x = m.script[m.i] orelse return error.Timeout;
        return @min(x, chunk.len);
    }
};

test "writeFrame/finish: a failure after some bytes is sticky Broken, one before any byte is not (sweep RV-SL-4)" {
    const frame = "5 hello";
    var e: TcpEmitter = .{ .io = undefined, .stream = undefined };

    // 0 bytes out, then Timeout: reported, emitter still usable
    var m0: MockStep = .{ .script = &.{null} };
    try t.expectError(error.Timeout, e.finish(writeFrame(&m0, frame)));
    try t.expect(!e.broken);

    // 3 bytes out, then Timeout: reported, and the emitter is broken
    var m1: MockStep = .{ .script = &.{ 3, null } };
    const r = writeFrame(&m1, frame);
    try t.expectEqual(@as(usize, 3), r.written);
    try t.expectError(error.Timeout, e.finish(r));
    try t.expect(e.broken);

    // a broken emitter refuses before touching the (undefined) socket
    const msg = Message{};
    try t.expectError(error.Broken, e.send(&msg));

    // a complete frame over several partial writes succeeds
    var m2: MockStep = .{ .script = &.{ 2, 2, 100 } };
    const ok = writeFrame(&m2, frame);
    try t.expectEqual(frame.len, ok.written);
    try t.expect(ok.err == null);
    // a zero-byte write is an error, not an endless loop
    var m3: MockStep = .{ .script = &.{ 0, 0 } };
    try t.expect(writeFrame(&m3, frame).err != null);
}

test "emitters compile (no socket is opened in tests)" {
    t.refAllDecls(UdpEmitter);
    t.refAllDecls(TcpEmitter);
}

test "real UDP send is not exercised in unit tests" {
    // The live path (bind + sendto) is gated behind runtime construction; a
    // networked integration test would build a UdpEmitter here.
    return error.SkipZigTest;
}

/// Comptime string repetition; replaces the `**` operator removed in Zig 0.17.
inline fn strRepeat(comptime s: []const u8, comptime n: usize) *const [s.len * n:0]u8 {
    // One @splat + @bitCast, not a loop: a comptime loop writing into an
    // array var costs O(n^2) in Sema (40 000 bytes: 8.7 s; http's test
    // binary spent ~5 min in Sema on these, 2026-10-24).
    const rep_result = comptime blk: {
        const unit: [s.len]u8 = s[0..s.len].*;
        const grid: [n][s.len]u8 = @splat(unit);
        const flat: [s.len * n]u8 = @bitCast(grid);
        break :blk (flat ++ [_:0]u8{})[0 .. s.len * n :0].*;
    };
    return &rep_result;
}
