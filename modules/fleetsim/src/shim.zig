// SPDX-License-Identifier: MIT

//! One-chunk-in / one-buffer-out transport shims.
//!
//! Two of the seven responders this module composes are *transport-driven*:
//! `iec104.outstation.Server.poll` and `bacnet.device.Device.poll` pull their
//! input from a `Transport` vtable and push their output back through it,
//! rather than taking a packet and returning a packet. To hold one of those
//! behind the fleet's packet-shaped `Node.deliver`, something has to stand in
//! for the socket: hand over exactly the bytes the fleet injected, collect
//! everything the responder writes into exactly one caller-owned buffer, and
//! then get out of the way.
//!
//! ## Why this lives here
//!
//! Both `iec104` and `bacnet` already ship a `LoopTransport`. Those are
//! peer-to-peer rigs for their own offline tests — two endpoints, a 16-slot ×
//! 1.5 kB mailbox each — which is the right shape for "a client and a server
//! talk to each other in one process" and the wrong shape here twice over:
//! ~24 kB per simulated node is unaffordable at fleet scale, and a mailbox
//! implies a *peer*, while a fleet node's peer is the outside world.
//!
//! The shim could not live in either module without that module depending on
//! the other's `Transport` type (they are structurally alike but nominally
//! different: `iec104`'s is read/write over a byte stream, `bacnet`'s is
//! send/broadcast/recv over datagrams). A separate module for ~60 lines would
//! be a dependency both ways for no gain. `fleetsim` is the only place the two
//! shapes meet and already depends on both, so it is where the shim belongs —
//! and `Window` below, the part with all the logic in it, is protocol-agnostic:
//! an eighth `Transport`-driven responder costs one ~15-line vtable binding,
//! not another buffer discipline.
//!
//! Nothing here allocates, reads a clock or keeps state between calls beyond
//! the current `reset` window, which is what keeps the fleet deterministic.

const std = @import("std");

const iec104 = @import("iec104");
const bacnet = @import("bacnet");

/// The protocol-agnostic half: one input chunk to hand out, one output buffer
/// to fill. Every shim below is this plus a vtable.
///
/// `overflow` latches instead of truncating: a responder whose answer does not
/// fit must be reported as such, never silently cut in half — half a frame on
/// the wire is a bug that looks like a peer bug.
pub const Window = struct {
    input: []const u8 = &.{},
    in_pos: usize = 0,
    out: []u8 = &.{},
    out_used: usize = 0,
    overflow: bool = false,

    /// Point the window at one input chunk (possibly empty) and one output
    /// buffer. Every field is replaced, so a shim can be reused across calls
    /// and across `Fleet.advance` boundaries without carrying state.
    pub fn reset(self: *Window, input: []const u8, out: []u8) void {
        self.* = .{ .input = input, .out = out };
    }

    /// Stream read: up to `buf.len` bytes, 0 once the chunk is drained.
    pub fn take(self: *Window, buf: []u8) usize {
        const n = @min(buf.len, self.input.len - self.in_pos);
        if (n == 0) return 0;
        @memcpy(buf[0..n], self.input[self.in_pos..][0..n]);
        self.in_pos += n;
        return n;
    }

    /// Datagram read: the whole chunk exactly once, then nothing. `null` means
    /// "no datagram waiting"; `error.TooLarge` means the caller's receive
    /// buffer is smaller than the datagram, which is a real transport
    /// condition and not something to paper over.
    pub fn takeDatagram(self: *Window, buf: []u8) error{TooLarge}!?[]u8 {
        if (self.pending() == 0) return null;
        const dgram = self.input[self.in_pos..];
        if (dgram.len > buf.len) return error.TooLarge;
        self.in_pos = self.input.len;
        @memcpy(buf[0..dgram.len], dgram);
        return buf[0..dgram.len];
    }

    /// Append to the output buffer. Latches `overflow` and fails rather than
    /// writing a partial frame.
    pub fn put(self: *Window, bytes: []const u8) error{Overflow}!void {
        if (self.out_used + bytes.len > self.out.len) {
            self.overflow = true;
            return error.Overflow;
        }
        @memcpy(self.out[self.out_used..][0..bytes.len], bytes);
        self.out_used += bytes.len;
    }

    /// What the responder has written so far.
    pub fn written(self: *const Window) []const u8 {
        return self.out[0..self.out_used];
    }

    /// Input bytes not yet handed over.
    pub fn pending(self: *const Window) usize {
        return self.input.len - self.in_pos;
    }

    /// True once the responder has consumed the whole chunk.
    pub fn drained(self: *const Window) bool {
        return self.pending() == 0;
    }
};

// ── IEC 60870-5-104: a byte-stream Transport ────────────────────────────────

/// Binds a `Window` to `iec104.Transport`. The APCI layer is self-delimiting,
/// so several APDUs written in one poll round concatenate cleanly and the
/// fleet's `Framing.iec104_apci` splits them back apart.
pub const StreamShim = struct {
    window: Window = .{},

    pub fn transport(self: *StreamShim) iec104.Transport {
        return .{ .ctx = self, .vtable = &vtable };
    }

    pub fn reset(self: *StreamShim, input: []const u8, out: []u8) void {
        self.window.reset(input, out);
    }

    pub fn written(self: *const StreamShim) []const u8 {
        return self.window.written();
    }

    const vtable = iec104.Transport.VTable{ .read = readFn, .write = writeFn };

    fn readFn(ctx: *anyopaque, buf: []u8) iec104.TransportError!usize {
        const self: *StreamShim = @ptrCast(@alignCast(ctx));
        return self.window.take(buf);
    }

    fn writeFn(ctx: *anyopaque, bytes: []const u8) iec104.TransportError!void {
        const self: *StreamShim = @ptrCast(@alignCast(ctx));
        self.window.put(bytes) catch return error.WriteFailed;
    }
};

// ── BACnet/IP: a datagram Transport ─────────────────────────────────────────

/// Binds a `Window` to `bacnet.Transport`. `send` and `broadcast` land in the
/// same buffer: BVLC carries its own length, so the fleet splits the output
/// back into individual datagrams with `Framing.bacnet_bvll`, and a simulated
/// device on a point-to-point link has nowhere else to put a broadcast anyway.
pub const DatagramShim = struct {
    window: Window = .{},
    /// The address this device answers as, and the address every reply is
    /// attributed to. A shim has exactly one peer by construction — the fleet
    /// binding decides where the bytes really go.
    address: bacnet.BipAddress = .{ .ip = @splat(0) },
    peer: bacnet.BipAddress = .{ .ip = @splat(0) },

    pub fn transport(self: *DatagramShim) bacnet.Transport {
        return .{ .ctx = self, .vtable = &vtable };
    }

    pub fn reset(self: *DatagramShim, input: []const u8, out: []u8) void {
        self.window.reset(input, out);
    }

    pub fn written(self: *const DatagramShim) []const u8 {
        return self.window.written();
    }

    const vtable = bacnet.Transport.VTable{
        .send = sendFn,
        .broadcast = broadcastFn,
        .recv = recvFn,
    };

    fn sendFn(ctx: *anyopaque, to: bacnet.BipAddress, bytes: []const u8) bacnet.TransportError!void {
        _ = to;
        const self: *DatagramShim = @ptrCast(@alignCast(ctx));
        self.window.put(bytes) catch return error.SendFailed;
    }

    fn broadcastFn(ctx: *anyopaque, bytes: []const u8) bacnet.TransportError!void {
        const self: *DatagramShim = @ptrCast(@alignCast(ctx));
        self.window.put(bytes) catch return error.SendFailed;
    }

    fn recvFn(ctx: *anyopaque, buf: []u8) bacnet.TransportError!?bacnet.transport.Received {
        const self: *DatagramShim = @ptrCast(@alignCast(ctx));
        const dgram = self.window.takeDatagram(buf) catch return error.DatagramTooLarge;
        return .{ .from = self.peer, .bytes = dgram orelse return null };
    }
};

// ── tests ───────────────────────────────────────────────────────────────────

const testing = std.testing;

test "Window: a stream chunk is handed over once, in pieces, then runs dry" {
    var w = Window{};
    var out: [8]u8 = undefined;
    w.reset("abcdef", &out);
    try testing.expectEqual(@as(usize, 6), w.pending());

    var buf: [4]u8 = undefined;
    try testing.expectEqual(@as(usize, 4), w.take(&buf));
    try testing.expectEqualSlices(u8, "abcd", buf[0..4]);
    try testing.expectEqual(@as(usize, 2), w.take(&buf));
    try testing.expectEqualSlices(u8, "ef", buf[0..2]);
    try testing.expectEqual(@as(usize, 0), w.take(&buf));
    try testing.expect(w.drained());
}

test "Window: a datagram is all-or-nothing, and too-large is an error not a truncation" {
    var w = Window{};
    var out: [8]u8 = undefined;
    w.reset("hello", &out);

    var small: [2]u8 = undefined;
    try testing.expectError(error.TooLarge, w.takeDatagram(&small));
    try testing.expectEqual(@as(usize, 5), w.pending()); // not consumed

    var big: [16]u8 = undefined;
    try testing.expectEqualSlices(u8, "hello", (try w.takeDatagram(&big)).?);
    try testing.expectEqual(@as(?[]u8, null), try w.takeDatagram(&big));
}

test "Window: overflow latches and never writes a partial frame" {
    var w = Window{};
    var out: [4]u8 = undefined;
    w.reset(&.{}, &out);
    try w.put("ab");
    try testing.expectError(error.Overflow, w.put("xyz"));
    try testing.expect(w.overflow);
    try testing.expectEqualSlices(u8, "ab", w.written()); // "xy" was NOT written
    // reset clears the latch, so a shim is reusable across calls.
    w.reset(&.{}, &out);
    try testing.expect(!w.overflow);
    try testing.expectEqual(@as(usize, 0), w.written().len);
}

test "StreamShim: an IEC 104 outstation answers STARTDT through it" {
    var points = [_]iec104.Point{
        .{ .ioa = 101, .type_id = .m_sp_na_1, .element = .{ .siq = .{ .on = true } } },
    };
    var frame_buf: [512]u8 = undefined;
    var queue_buf: [2048]u8 = undefined;
    var shim = StreamShim{};
    var server = try iec104.OutstationServer.init(
        .{ .common_address = 47 },
        &points,
        shim.transport(),
        &frame_buf,
        &queue_buf,
        .{},
    );
    server.onConnected(0);

    var out: [256]u8 = undefined;
    shim.reset(&.{ 0x68, 0x04, 0x07, 0x00, 0x00, 0x00 }, &out); // STARTDT act
    server.transport = shim.transport();
    // `poll` is one step of a state machine: read, then act. Drain it the way
    // the adapter does.
    for (0..8) |_| {
        const ev = try server.poll(0);
        if (ev == .none and shim.window.drained()) break;
    }
    try testing.expectEqualSlices(u8, &.{ 0x68, 0x04, 0x0B, 0x00, 0x00, 0x00 }, shim.written());
    try testing.expect(server.isStarted());
}

test "DatagramShim: a BACnet device answers a Who-Is through it" {
    var props = [_]bacnet.Property{
        .{ .id = .object_name, .value = .{ .string = "AI-1" } },
    };
    var objects = [_]bacnet.Object{.{
        .id = .{ .type = .analog_input, .instance = 1 },
        .properties = &props,
    }};
    var shim = DatagramShim{
        .address = .{ .ip = .{ 10, 0, 0, 2 }, .port = 47808 },
        .peer = .{ .ip = .{ 10, 0, 0, 1 }, .port = 47808 },
    };
    var dev = bacnet.DeviceWith(2).init(shim.transport(), .{ .instance = 2001, .vendor_id = 9 }, &objects);

    var out: [512]u8 = undefined;
    const who_is = [_]u8{ 0x81, 0x0B, 0x00, 0x0C, 0x01, 0x20, 0xFF, 0xFF, 0x00, 0xFF, 0x10, 0x08 };
    shim.reset(&who_is, &out);
    dev.tp = shim.transport();
    _ = try dev.poll(0);
    const reply = shim.written();
    try testing.expect(reply.len > 4);
    try testing.expectEqual(@as(u8, 0x81), reply[0]); // BVLC
}
