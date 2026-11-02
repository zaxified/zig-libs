// SPDX-License-Identifier: MIT
//! Blocking network emitters for RFC 5424 messages over `std.Io.net`, plus the
//! transport-only codec pieces (UDP datagram assembly with a truncation marker,
//! RFC 6587 octet-counting TCP framing). The framing helpers are pure and
//! tested offline; the `UdpEmitter`/`TcpEmitter` structs are convenience
//! adapters that only touch the network when a caller constructs one.
//!
//! `TcpEmitter` holds one connection and goes sticky-`Broken` when it dies;
//! `ReconnectingEmitter` is the same over TCP or a unix stream socket with the
//! reconnect-and-retry a long-lived sender wants; `WriterEmitter` frames onto
//! any `std.Io.Writer`, which is the seam RFC 5425 (TLS) goes through.

const std = @import("std");
const message = @import("message.zig");
const bsd = @import("bsd.zig");
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
/// tail. `scratch` should be ≥ `default_udp_limit`. The cut never splits a UTF-8
/// sequence: a receiver checking MSG would otherwise refuse or mangle the line.
pub fn buildDatagram(msg: *const Message, scratch: []u8, opts: Options) []const u8 {
    return buildDatagramOf(msg, scratch, opts);
}

/// `buildDatagram` for an RFC 3164 message.
pub fn buildDatagramBsd(msg: *const bsd.Message, scratch: []u8, opts: Options) []const u8 {
    return buildDatagramOf(msg, scratch, opts);
}

fn buildDatagramOf(msg: anytype, scratch: []u8, opts: Options) []const u8 {
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
    const bytes = w.buffered();

    const limit = @min(opts.udp_limit, scratch.len);
    if (bytes.len > limit or overflowed) return markTruncated(scratch, bytes, limit, opts.trunc_marker);
    return bytes;
}

/// Replace what lies past `limit` in `bytes` (a slice at the start of `scratch`,
/// `limit` ≤ `scratch.len`) by `marker`, cutting at a UTF-8 boundary when the cut
/// lands inside a sequence.
pub fn markTruncated(scratch: []u8, bytes: []const u8, limit: usize, marker: []const u8) []const u8 {
    const mlen = @min(marker.len, limit);
    // `@min`: the marker never lands past what was written, whatever `bytes` is.
    const keep = utf8Boundary(bytes, @min(limit - mlen, bytes.len));
    @memcpy(scratch[keep .. keep + mlen], marker[0..mlen]);
    return scratch[0 .. keep + mlen];
}

/// The largest cut ≤ `at` that does not split a UTF-8 sequence of `bytes`:
/// back over at most three continuation bytes to a lead byte. Bytes that are not
/// UTF-8 at that spot keep `at`: there is nothing to preserve.
fn utf8Boundary(bytes: []const u8, at: usize) usize {
    if (at >= bytes.len) return at;
    var k = at;
    var back: usize = 0;
    while (k > 0 and back < 3 and bytes[k] & 0xC0 == 0x80) {
        k -= 1;
        back += 1;
    }
    if (back == 0) return at;
    return if (bytes[k] >= 0xC0) k else at;
}

/// RFC 6587 §3.4.1 octet-counting frame: `MSG-LEN SP SYSLOG-MSG`, where
/// `MSG-LEN` is the decimal byte length of `payload`.
pub fn writeOctetCounted(w: *std.Io.Writer, payload: []const u8) std.Io.Writer.Error!void {
    try w.print("{d} ", .{payload.len});
    try w.writeAll(payload);
}

/// How a message is delimited on a stream.
pub const Framing = enum {
    /// RFC 6587 §3.4.1 `MSG-LEN SP MSG`, RFC 5425's only framing. Any byte can
    /// be in MSG. The default, and what `TcpEmitter` always did.
    octet_counting,
    /// RFC 6587 §3.4.2 non-transparent framing: the trailer `LF`, which every
    /// old collector reads and Go's `log/syslog` sends.
    lf,
    /// The same with a `NUL` trailer: what glibc and Rust's `syslog` crate send
    /// on a local stream socket.
    nul,

    /// The byte that ends a frame; null for octet counting.
    pub fn trailer(f: Framing) ?u8 {
        return switch (f) {
            .octet_counting => null,
            .lf => '\n',
            .nul => 0,
        };
    }
};

/// Keep a trailer out of a formatted message: it would end the record there and
/// let the rest forge another. Replaced by a space, as a header field's control
/// byte is mapped rather than sent.
fn neutralizeTrailer(f: Framing, bytes: []u8) void {
    const tr = f.trailer() orelse return;
    for (bytes) |*b| {
        if (b.* == tr) b.* = ' ';
    }
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

    /// `send` for an RFC 3164 message.
    pub fn sendBsd(e: *UdpEmitter, msg: *const bsd.Message) !void {
        const bytes = buildDatagramBsd(msg, &e.scratch, e.options);
        try e.socket.send(e.io, &e.peer, bytes);
    }

    /// Send `bytes` verbatim as one datagram: no format, no budget. Reentrant.
    pub fn sendRaw(e: *UdpEmitter, bytes: []const u8) !void {
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
/// (`scratch_len` = 2048 needs 5 bytes; 8 is generous), and behind it for a
/// trailer.
const prefix_room = 8;
const trailer_room = 1;

fn msTimeout(ms: u32) std.Io.Timeout {
    return .{ .duration = .{ .raw = .fromMilliseconds(ms), .clock = .awake } };
}

/// Stream sender: RFC 6587 over TCP (syslog/tcp is port 514) or over a local
/// unix stream socket. Construct with `connect` or `connectUnix`; each `send`
/// writes one frame, `MSG-LEN SP MSG` unless `framing` says otherwise.
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
    scratch: [prefix_room + scratch_len + trailer_room]u8 = undefined,
    /// How a frame is delimited. See `Framing`.
    framing: Framing = .octet_counting,
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
        /// `connectUnix`: the path (plus its NUL) does not fit `sockaddr_un`.
        PathTooLong,
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

    /// Connect to a unix STREAM socket, for a `/dev/log` a daemon serves that
    /// way: `UnixEmitter`'s datagrams get `EPROTOTYPE` there (Linux only; the
    /// same deadline rule). Framing `.nul`, what glibc and syslog-ng's
    /// `unix-stream()` expect; a caller may set another afterwards.
    pub fn connectUnix(io: std.Io, path: []const u8, connect_timeout_ms: u32) ConnectError!TcpEmitter {
        const fd = try connectUnixStream(path, connect_timeout_ms);
        const unspec: std.Io.net.IpAddress = .{ .ip4 = .unspecified(0) };
        return .{ .io = io, .stream = .{ .socket = .{ .handle = fd, .address = unspec } }, .framing = .nul };
    }

    pub fn close(e: *TcpEmitter) void {
        e.stream.close(e.io);
    }

    /// Failures reported by `send`. `Canceled`: the write was canceled through
    /// the `std.Io` cancellation protocol (`Future.cancel`). `Timeout`: the
    /// deadline passed. `Broken`: an earlier send failed mid-frame (see the
    /// type's doc comment). `DelimiterInMessage`: `sendRaw` was handed bytes
    /// holding the trailer of a non-transparent `framing`.
    pub const SendError = error{ Canceled, NoSpaceLeft, Timeout, Broken, DelimiterInMessage } || std.Io.Writer.Error;

    pub fn send(e: *TcpEmitter, msg: *const Message) SendError!void {
        if (e.broken) return error.Broken;
        const payload = try message.bufPrint(msg, e.payloadRoom());
        return e.sendScratch(payload.len);
    }

    /// `send` for an RFC 3164 message.
    pub fn sendBsd(e: *TcpEmitter, msg: *const bsd.Message) SendError!void {
        if (e.broken) return error.Broken;
        const payload = try bsd.bufPrint(msg, e.payloadRoom());
        return e.sendScratch(payload.len);
    }

    /// Frame and send `bytes` as they are: no format, and no 2048-byte cap (a
    /// longer one takes two writes). The trailer of a non-transparent `framing`
    /// in `bytes` is `error.DelimiterInMessage`: nothing is sent.
    pub fn sendRaw(e: *TcpEmitter, bytes: []const u8) SendError!void {
        if (e.broken) return error.Broken;
        if (e.framing.trailer()) |tr| {
            if (std.mem.findScalar(u8, bytes, tr) != null) return error.DelimiterInMessage;
        }
        if (bytes.len <= scratch_len) {
            @memcpy(e.payloadRoom()[0..bytes.len], bytes);
            return e.sendScratch(bytes.len);
        }
        var step: NetStep = .{ .e = e, .deadline = msTimeout(e.send_timeout_ms).toDeadline(e.io) };
        var pbuf: [24]u8 = undefined;
        const head: []const u8 = switch (e.framing) {
            .octet_counting => std.fmt.bufPrint(&pbuf, "{d} ", .{bytes.len}) catch "",
            .lf, .nul => "",
        };
        const trailer_byte: [1]u8 = .{e.framing.trailer() orelse 0};
        const tail: []const u8 = if (e.framing.trailer() != null) &trailer_byte else "";
        var written: usize = 0;
        for ([_][]const u8{ head, bytes, tail }) |chunk| {
            const r = writeFrame(&step, chunk);
            written += r.written;
            if (r.err != null) return e.finish(.{ .written = written, .err = r.err });
        }
    }

    fn payloadRoom(e: *TcpEmitter) []u8 {
        return e.scratch[prefix_room..][0..scratch_len];
    }

    /// Frame the `len` bytes `payloadRoom` holds and write them in one go.
    fn sendScratch(e: *TcpEmitter, len: usize) SendError!void {
        var start: usize = prefix_room;
        var end: usize = prefix_room + len;
        neutralizeTrailer(e.framing, e.scratch[prefix_room..end]);
        if (e.framing.trailer()) |tr| {
            e.scratch[end] = tr;
            end += 1;
        } else {
            var pbuf: [prefix_room]u8 = undefined;
            const prefix = std.fmt.bufPrint(&pbuf, "{d} ", .{len}) catch unreachable; // len <= 2048: 5 bytes <= prefix_room
            start = prefix_room - prefix.len;
            @memcpy(e.scratch[start..prefix_room], prefix);
        }
        var step: NetStep = .{ .e = e, .deadline = msTimeout(e.send_timeout_ms).toDeadline(e.io) };
        return e.finish(writeFrame(&step, e.scratch[start..end]));
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
    return connectFd(family, @ptrCast(&storage), len, timeout_ms);
}

fn connectUnixStream(path: []const u8, timeout_ms: u32) TcpEmitter.ConnectError!linux.fd_t {
    var addr: linux.sockaddr.un = .{ .family = linux.AF.UNIX, .path = @splat(0) };
    if (path.len >= addr.path.len) return error.PathTooLong;
    @memcpy(addr.path[0..path.len], path);
    return connectFd(linux.AF.UNIX, @ptrCast(&addr), @sizeOf(linux.sockaddr.un), timeout_ms);
}

fn connectFd(family: u32, addr: *const linux.sockaddr, len: linux.socklen_t, timeout_ms: u32) TcpEmitter.ConnectError!linux.fd_t {
    const rc = linux.socket(family, linux.SOCK.STREAM | linux.SOCK.NONBLOCK | linux.SOCK.CLOEXEC, 0);
    if (linux.errno(rc) != .SUCCESS) return error.SocketFailed;
    const fd: linux.fd_t = @intCast(rc);
    errdefer _ = linux.close(fd);

    const start = monotonicMs();
    const crc = linux.connect(fd, addr, len);
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
        // A unix stream socket whose backlog is full: no way to wait for it.
        .AGAIN => return error.Timeout,
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
        // ENOENT: nothing bound at a unix path, its "connection refused".
        .CONNREFUSED, .NOENT => error.ConnectionRefused,
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

// ── reconnecting emitter ────────────────────────────────────────────────────

/// A stream sender that survives its peer: what a long-lived daemon wants when
/// the collector restarts. `init` does no I/O; the first `send` connects.
///
/// Delivery is at-least-once, not exactly-once and not guaranteed. A write that
/// fails is retried on a new connection (`Config.retries`), so a frame the old
/// connection cut can arrive whole a second time; a frame the peer's kernel took
/// and the peer never read is gone, as with every syslog over TCP. One thing
/// plain senders lose and this does not: before each send it checks whether the
/// peer has already closed (Go's `log/syslog` and Rust's `syslog` write into the
/// half-closed socket, the kernel accepts it, and the record vanishes).
///
/// `Timeout` is NOT retried: a collector that stopped reading would otherwise
/// cost the caller `retries + 1` deadlines per record. While the peer stays
/// down, `send` answers `error.Backoff` at once for `Config.backoff_ms` after a
/// failed connect, so a logging call does not sit in `connect` every time.
pub const ReconnectingEmitter = struct {
    pub const Target = union(enum) {
        tcp: std.Io.net.IpAddress,
        /// A unix stream socket path; it must outlive the emitter.
        unix: []const u8,
    };

    pub const Config = struct {
        connect_timeout_ms: u32 = default_connect_timeout_ms,
        send_timeout_ms: u32 = default_send_timeout_ms,
        /// `null`: `.octet_counting` for TCP, `.nul` for a unix socket.
        framing: ?Framing = null,
        /// New connections one `send` may try after the first attempt failed.
        retries: u8 = 1,
        /// How long a failed connect is not tried again.
        backoff_ms: u32 = 1000,
    };

    pub const SendError = TcpEmitter.SendError || TcpEmitter.ConnectError || error{
        /// A connect failed less than `Config.backoff_ms` ago: nothing was tried.
        Backoff,
    };

    io: std.Io,
    target: Target,
    config: Config = .{},
    conn: ?TcpEmitter = null,
    /// Monotonic ms before which no connect is tried.
    next_connect_ms: u64 = 0,
    /// Connections opened after the first, for a caller's metrics.
    reconnects: u64 = 0,
    connected_once: bool = false,
    scratch: [scratch_len]u8 = undefined,

    pub fn init(io: std.Io, target: Target, config: Config) ReconnectingEmitter {
        return .{ .io = io, .target = target, .config = config };
    }

    pub fn close(e: *ReconnectingEmitter) void {
        if (e.conn) |*c| c.close();
        e.conn = null;
    }

    pub fn send(e: *ReconnectingEmitter, msg: *const Message) SendError!void {
        const bytes = message.bufPrint(msg, &e.scratch) catch return error.NoSpaceLeft;
        neutralizeTrailer(e.framing(), e.scratch[0..bytes.len]);
        return e.sendRaw(bytes);
    }

    /// `send` for an RFC 3164 message.
    pub fn sendBsd(e: *ReconnectingEmitter, msg: *const bsd.Message) SendError!void {
        const bytes = bsd.bufPrint(msg, &e.scratch) catch return error.NoSpaceLeft;
        neutralizeTrailer(e.framing(), e.scratch[0..bytes.len]);
        return e.sendRaw(bytes);
    }

    /// `TcpEmitter.sendRaw` with the reconnect above.
    pub fn sendRaw(e: *ReconnectingEmitter, bytes: []const u8) SendError!void {
        var attempts_left: u32 = @as(u32, e.config.retries) + 1;
        while (true) {
            attempts_left -= 1;
            const c = try e.connection();
            if (c.sendRaw(bytes)) |_| return else |err| switch (err) {
                error.DelimiterInMessage, error.NoSpaceLeft => return err,
                error.Canceled, error.Timeout => {
                    if (c.broken) e.close();
                    return err;
                },
                error.Broken, error.WriteFailed => {
                    e.close();
                    if (attempts_left == 0) return err;
                },
            }
        }
    }

    /// The framing in use: `Config.framing` or the target's default.
    pub fn framing(e: *const ReconnectingEmitter) Framing {
        return e.config.framing orelse switch (e.target) {
            .tcp => .octet_counting,
            .unix => .nul,
        };
    }

    /// The live connection, after dropping one the peer already closed; a new
    /// one if there is none and the backoff allows.
    fn connection(e: *ReconnectingEmitter) SendError!*TcpEmitter {
        if (e.conn) |*c| {
            if (!peerClosed(c.stream.socket.handle)) return c;
            e.close();
        }
        // An unreadable clock: no backoff, rather than a backoff that never ends.
        if (monotonicMs()) |now| {
            if (now < e.next_connect_ms) return error.Backoff;
        }
        const conn = switch (e.target) {
            .tcp => |a| TcpEmitter.connectTimeout(e.io, a, e.config.connect_timeout_ms),
            .unix => |p| TcpEmitter.connectUnix(e.io, p, e.config.connect_timeout_ms),
        } catch |err| {
            // From the failure, not the attempt: a connect that took its whole
            // deadline must still leave `backoff_ms` of quiet after it (review).
            if (monotonicMs()) |failed_at| e.next_connect_ms = failed_at +| e.config.backoff_ms;
            return err;
        };
        e.conn = conn;
        const c = &e.conn.?;
        c.framing = e.framing();
        c.send_timeout_ms = e.config.send_timeout_ms;
        if (e.connected_once) e.reconnects +|= 1;
        e.connected_once = true;
        return c;
    }
};

/// Did the peer close (or reset) this stream? `recv(MSG_PEEK)` answers without a
/// byte taken: 0 is an orderly close, an error other than "nothing to read" a
/// dead socket. Bytes waiting (a syslog collector sends none) mean it is alive.
fn peerClosed(fd: linux.fd_t) bool {
    var b: [1]u8 = undefined;
    const rc = linux.recvfrom(fd, &b, 1, linux.MSG.PEEK | linux.MSG.DONTWAIT | linux.MSG.NOSIGNAL, null, null);
    return switch (linux.errno(rc)) {
        .SUCCESS => rc == 0,
        .AGAIN, .INTR => false,
        else => true,
    };
}

// ── any writer: the RFC 5425 seam ───────────────────────────────────────────

/// Frames onto a caller's `std.Io.Writer` and flushes after every message. This
/// is how syslog over TLS (RFC 5425) is sent: its wire is exactly RFC 6587 octet
/// counting inside the TLS records, so `writer` is the TLS client's plaintext
/// writer and `downstream` the socket writer under it, which a TLS writer's own
/// flush only fills. See the README for it with `tlsclient`.
///
/// The session belongs to the caller: handshake, certificate and server name
/// checks (RFC 5425 §4.2), and the reconnect. A failed send leaves the stream in
/// an unknown state: close the session and open a new one.
pub const WriterEmitter = struct {
    writer: *std.Io.Writer,
    downstream: ?*std.Io.Writer = null,
    framing: Framing = .octet_counting,
    scratch: [scratch_len]u8 = undefined,

    pub const SendError = error{ NoSpaceLeft, DelimiterInMessage } || std.Io.Writer.Error;

    pub fn send(e: *WriterEmitter, msg: *const Message) SendError!void {
        const bytes = message.bufPrint(msg, &e.scratch) catch return error.NoSpaceLeft;
        neutralizeTrailer(e.framing, e.scratch[0..bytes.len]);
        return e.sendRaw(bytes);
    }

    /// `send` for an RFC 3164 message.
    pub fn sendBsd(e: *WriterEmitter, msg: *const bsd.Message) SendError!void {
        const bytes = bsd.bufPrint(msg, &e.scratch) catch return error.NoSpaceLeft;
        neutralizeTrailer(e.framing, e.scratch[0..bytes.len]);
        return e.sendRaw(bytes);
    }

    /// Frame `bytes` as they are, any length; then flush.
    pub fn sendRaw(e: *WriterEmitter, bytes: []const u8) SendError!void {
        if (e.framing.trailer()) |tr| {
            if (std.mem.findScalar(u8, bytes, tr) != null) return error.DelimiterInMessage;
            try e.writer.writeAll(bytes);
            try e.writer.writeByte(tr);
        } else {
            try writeOctetCounted(e.writer, bytes);
        }
        try e.writer.flush();
        if (e.downstream) |d| try d.flush();
    }
};

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

test "markTruncated never splits a UTF-8 sequence, and leaves other bytes alone" {
    // "é" = C3 A9, "€" = E2 82 AC, "😀" = F0 9F 98 80, with the cut on each byte.
    const cases = [_]struct { []const u8, usize, []const u8 }{
        .{ "ab\xC3\xA9cd", 3, "ab" },
        .{ "ab\xC3\xA9cd", 2, "ab" },
        .{ "ab\xC3\xA9cd", 4, "ab\xC3\xA9" },
        .{ "a\xE2\x82\xACb", 2, "a" },
        .{ "a\xE2\x82\xACb", 3, "a" },
        .{ "a\xF0\x9F\x98\x80b", 4, "a" },
        .{ "a\xF0\x9F\x98\x80b", 5, "a\xF0\x9F\x98\x80" },
        // Not UTF-8: continuation bytes with no lead byte in reach stay cut as asked.
        .{ "ab\x80\x80\x80\x80\x80", 5, "ab\x80\x80\x80" },
        // An ASCII byte under the walk back: a stray continuation, no sequence.
        .{ "a\x80\x80", 2, "a\x80" },
    };
    for (cases) |c| {
        var scratch: [16]u8 = undefined;
        @memcpy(scratch[0..c[0].len], c[0]);
        try t.expectEqualStrings(c[2], markTruncated(&scratch, scratch[0..c[0].len], c[1], ""));
    }
    var scratch: [16]u8 = undefined;
    @memcpy(scratch[0..6], "ab\xC3\xA9cd");
    try t.expectEqualStrings("ab.", markTruncated(&scratch, scratch[0..6], 4, "."));
}

test "buildDatagramBsd truncates over budget like buildDatagram" {
    var scratch: [128]u8 = undefined;
    const msg = bsd.Message{ .tag = "t", .msg = &@as([100]u8, @splat('x')) };
    const d = buildDatagramBsd(&msg, &scratch, .{ .udp_limit = 40, .trunc_marker = "!" });
    try t.expectEqual(@as(usize, 40), d.len);
    try t.expect(d[39] == '!');
    try t.expect(std.mem.startsWith(u8, d, "<13>t: x"));
}

test "WriterEmitter: octet counting, LF and NUL frames, a trailer in a message" {
    var out: [256]u8 = undefined;
    var w: std.Io.Writer = .fixed(&out);
    var e: WriterEmitter = .{ .writer = &w };
    const msg = Message{ .msg = "a\nb" };
    try e.send(&msg);
    try t.expectEqualStrings("21 <13>1 - - - - - - a\nb", w.buffered());

    w = .fixed(&out);
    e.framing = .lf;
    try e.send(&msg);
    try t.expectEqualStrings("<13>1 - - - - - - a b\n", w.buffered());
    try t.expectError(error.DelimiterInMessage, e.sendRaw("x\ny"));

    w = .fixed(&out);
    e.framing = .nul;
    try e.sendBsd(&.{ .tag = "t", .msg = "a\x00b" });
    try t.expectEqualStrings("<13>t: a b\x00", w.buffered());
    try t.expectError(error.DelimiterInMessage, e.sendRaw("x\x00y"));

    // A writer that fills up is an error, not a panic; a message that cannot
    // fit the scratch likewise.
    var tiny: [4]u8 = undefined;
    w = .fixed(&tiny);
    e.framing = .octet_counting;
    try t.expectError(error.WriteFailed, e.send(&msg));
    const huge = Message{ .msg = &@as([3000]u8, @splat('x')) };
    w = .fixed(&out);
    try t.expectError(error.NoSpaceLeft, e.send(&huge));
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

test "finish: a failure after exactly one byte is already sticky Broken (sweep audit GY-SL8)" {
    var e: TcpEmitter = .{ .io = undefined, .stream = undefined };
    var m: MockStep = .{ .script = &.{ 1, null } };
    const r = writeFrame(&m, "5 hello");
    try t.expectEqual(@as(usize, 1), r.written);
    try t.expectError(error.Timeout, e.finish(r));
    try t.expect(e.broken);
}

test "mapConnectErrno: every named errno maps to its own error (sweep audit GY-SL9)" {
    try t.expectEqual(error.ConnectionRefused, mapConnectErrno(.CONNREFUSED));
    try t.expectEqual(error.NetworkUnreachable, mapConnectErrno(.NETUNREACH));
    try t.expectEqual(error.HostUnreachable, mapConnectErrno(.HOSTUNREACH));
    try t.expectEqual(error.Timeout, mapConnectErrno(.TIMEDOUT));
    try t.expectEqual(error.ConnectFailed, mapConnectErrno(.PERM));
}
