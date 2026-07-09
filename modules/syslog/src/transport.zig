// SPDX-License-Identifier: MIT
//! Blocking network emitters for RFC 5424 messages over `std.Io.net`, plus the
//! transport-only codec pieces (UDP datagram assembly with a truncation marker,
//! RFC 6587 octet-counting TCP framing). The framing helpers are pure and
//! tested offline; the `UdpEmitter`/`TcpEmitter` structs are convenience
//! adapters that only touch the network when a caller constructs one — no test
//! opens a socket.

const std = @import("std");
const message = @import("message.zig");

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
    msg.format(&w) catch {};
    var bytes = w.buffered();

    const limit = @min(opts.udp_limit, scratch.len);
    if (bytes.len > limit) {
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

/// RFC 6587 octet-counted TCP sender (syslog/tcp is port 514). Construct with
/// `connect`; each `send` writes one `MSG-LEN SP MSG` frame.
pub const TcpEmitter = struct {
    io: std.Io,
    stream: std.Io.net.Stream,
    scratch: [scratch_len]u8 = undefined,

    pub fn connect(io: std.Io, address: std.Io.net.IpAddress) !TcpEmitter {
        const stream = try address.connect(io, .{ .mode = .stream });
        return .{ .io = io, .stream = stream };
    }

    pub fn close(e: *TcpEmitter) void {
        e.stream.close(e.io);
    }

    pub fn send(e: *TcpEmitter, msg: *const Message) !void {
        const payload = try message.bufPrint(msg, &e.scratch);
        var wbuf: [32]u8 = undefined; // holds the "MSG-LEN SP" prefix
        var sw = e.stream.writer(e.io, &wbuf);
        try writeOctetCounted(&sw.interface, payload);
        try sw.interface.flush();
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

test "buildDatagram truncates and appends the marker over budget" {
    const msg = Message{ .facility = .user, .severity = .notice, .msg = "A" ** 400 };
    var scratch: [scratch_len]u8 = undefined;
    const opts = Options{ .udp_limit = 64, .trunc_marker = "...[TRUNCATED]" };
    const dg = buildDatagram(&msg, &scratch, opts);
    try t.expectEqual(@as(usize, 64), dg.len);
    try t.expect(std.mem.endsWith(u8, dg, "...[TRUNCATED]"));
    try t.expect(std.mem.startsWith(u8, dg, "<13>1 - - - - - - A"));
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
