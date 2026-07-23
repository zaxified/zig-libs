// SPDX-License-Identifier: MIT

//! The node seam: the one interface every simulated device satisfies, plus the
//! framing rules the scheduler needs in order to cut a responder's output back
//! into individual wire frames.
//!
//! The seven responders this module composes (`modbus.server.Server`,
//! `dnp3.outstation.Session`, `iec104.outstation.Outstation`,
//! `s7comm.server.Responder`, `bacnet.device.Device`, `enip.adapter.Adapter`,
//! `opcua.server.Connection`) were all written to the same shape — bytes in,
//! bytes out, injected clock, caller-owned storage — but their *signatures*
//! differ (`handleAdu` / `handle` / `feedFrame` / `poll` / `feed`). `Node` is
//! the smallest vtable that covers all of them without touching any of them:
//!
//!   - `deliver(bytes, out, now) -> ?reply` — one inbound frame in, zero or
//!     more concatenated reply frames out. `null` means "say nothing", which
//!     every one of these protocols has a legitimate reason to do.
//!   - `tick(out, now) -> ?frames` — unsolicited traffic (DNP3 unsolicited
//!     responses, IEC 104 spontaneous ASDUs, BACnet COV notifications, OPC UA
//!     publish responses). Optional: a Modbus slave never speaks first.
//!   - `nextDeadline(now) -> ?Time` — when the node next *wants* a tick, so a
//!     1000-node fleet does not have to poll every node every millisecond.
//!   - `control(op, now) -> bool` — restart / device-trouble injection. Returns
//!     false when the protocol has no such concept, which the fleet logs rather
//!     than papering over.

const std = @import("std");

/// Simulated milliseconds. Always injected — nothing in this module reads a
/// clock.
pub const Time = u64;

/// A node's handle inside one `Fleet`. Dense, assigned in creation order.
pub const NodeId = u32;

pub const NodeError = error{
    /// The responder refused the frame outright (a modelled device fault, not
    /// a bug): the fleet counts it and stays silent.
    ResponderFailed,
    /// The reply did not fit the buffer the fleet handed over.
    OutputTooSmall,
};

/// What `control` can be asked to do.
pub const Control = enum {
    /// Power-cycle: responder state returns to its as-constructed value, so a
    /// master sees the restart indication its protocol defines (DNP3 IIN1.7,
    /// an OPC UA channel that must be re-opened, a re-negotiated S7 PDU size).
    restart,
    /// Report an internal device problem (Modbus exception 0x04, DNP3 IIN1.6,
    /// S7 CPU in STOP, IEC 104 quality `iv`).
    trouble_on,
    trouble_off,
};

/// Which protocol a node speaks. Carried for logging, for the TCP binding's
/// default port, and for framing.
pub const Protocol = enum {
    modbus,
    dnp3,
    iec104,
    s7comm,
    bacnet,
    enip,
    opcua,
    custom,

    /// The IANA-registered listen port, for the optional transport binding.
    pub fn defaultPort(self: Protocol) u16 {
        return switch (self) {
            .modbus => 502,
            .dnp3 => 20000,
            .iec104 => 2404,
            .s7comm => 102,
            .bacnet => 47808,
            .enip => 44818,
            .opcua => 4840,
            .custom => 0,
        };
    }

    /// True when the protocol is datagram-oriented, so the TCP binding must
    /// open a UDP socket instead.
    pub fn isDatagram(self: Protocol) bool {
        return self == .bacnet;
    }
};

// ── framing ─────────────────────────────────────────────────────────────────

/// How to find frame boundaries in a byte stream. Every one of these formats
/// carries an explicit length, which is what lets the fleet apply per-frame
/// link faults to a responder that answered with three ASDUs in one buffer.
pub const Framing = enum {
    /// MBAP: 6-byte header, big-endian length at [4..6] counting the unit id.
    modbus_tcp,
    /// 0x05 0x64 LEN …, LEN = user data + 5, one CRC per 16-byte block.
    dnp3_link,
    /// 0x68 LEN …, LEN counts everything after itself.
    iec104_apci,
    /// RFC 1006 TPKT: 0x03 0x00 then a big-endian total length.
    tpkt,
    /// EtherNet/IP encapsulation: 24-byte header, little-endian body length.
    enip_encap,
    /// OPC UA UA-TCP: 3-byte type, chunk byte, little-endian total length.
    opcua_uatcp,
    /// BACnet BVLC: 0x81, function, big-endian total length.
    bacnet_bvll,
    /// No length field (Modbus RTU) or not worth splitting — the whole buffer
    /// is one frame.
    opaque_whole,

    /// Length of the complete frame at the head of `buf`, `null` when more
    /// bytes are needed, `error.BadFrame` when the head cannot be a frame at
    /// all. Never reads past `buf`.
    pub fn frameLen(self: Framing, buf: []const u8) error{BadFrame}!?usize {
        switch (self) {
            .modbus_tcp => {
                if (buf.len < 6) return null;
                const body = std.mem.readInt(u16, buf[4..6], .big);
                if (body == 0 or body > 254) return error.BadFrame;
                return 6 + @as(usize, body);
            },
            .dnp3_link => {
                if (buf.len < 3) return null;
                if (buf[0] != 0x05 or buf[1] != 0x64) return error.BadFrame;
                const length: usize = buf[2];
                if (length < 5) return error.BadFrame;
                const user = length - 5;
                if (user > 250) return error.BadFrame;
                const blocks = if (user == 0) 0 else (user + 15) / 16;
                return 10 + user + blocks * 2;
            },
            .iec104_apci => {
                if (buf.len < 2) return null;
                if (buf[0] != 0x68) return error.BadFrame;
                if (buf[1] < 4) return error.BadFrame;
                return 2 + @as(usize, buf[1]);
            },
            .tpkt => {
                if (buf.len < 4) return null;
                if (buf[0] != 0x03) return error.BadFrame;
                const total = std.mem.readInt(u16, buf[2..4], .big);
                if (total < 4) return error.BadFrame;
                return total;
            },
            .enip_encap => {
                if (buf.len < 24) return null;
                const body = std.mem.readInt(u16, buf[2..4], .little);
                return 24 + @as(usize, body);
            },
            .opcua_uatcp => {
                if (buf.len < 8) return null;
                const total = std.mem.readInt(u32, buf[4..8], .little);
                if (total < 8) return error.BadFrame;
                return total;
            },
            .bacnet_bvll => {
                if (buf.len < 4) return null;
                if (buf[0] != 0x81) return error.BadFrame;
                const total = std.mem.readInt(u16, buf[2..4], .big);
                if (total < 4) return error.BadFrame;
                return total;
            },
            .opaque_whole => return if (buf.len == 0) null else buf.len,
        }
    }
};

/// Walks a buffer of concatenated frames. A frame that does not parse ends the
/// walk — the remainder is reported through `rest` so a caller can decide
/// whether that is a truncated read (stream) or garbage (a responder bug).
pub const FrameIterator = struct {
    framing: Framing,
    buf: []const u8,
    pos: usize = 0,
    /// Set once a malformed head byte was seen.
    bad: bool = false,

    pub fn init(framing: Framing, buf: []const u8) FrameIterator {
        return .{ .framing = framing, .buf = buf };
    }

    pub fn next(self: *FrameIterator) ?[]const u8 {
        if (self.bad or self.pos >= self.buf.len) return null;
        const tail = self.buf[self.pos..];
        const n = self.framing.frameLen(tail) catch {
            self.bad = true;
            return null;
        } orelse return null;
        if (n > tail.len) return null; // truncated tail
        self.pos += n;
        return tail[0..n];
    }

    /// Bytes not consumed: a partial frame, or the garbage that stopped the
    /// walk.
    pub fn rest(self: *const FrameIterator) []const u8 {
        return self.buf[self.pos..];
    }
};

// ── the node interface ──────────────────────────────────────────────────────

pub const Node = struct {
    ctx: *anyopaque,
    vtable: *const VTable,
    protocol: Protocol = .custom,
    framing: Framing = .opaque_whole,

    pub const VTable = struct {
        deliver: *const fn (ctx: *anyopaque, bytes: []const u8, out: []u8, now_ms: Time) NodeError!?[]const u8,
        tick: ?*const fn (ctx: *anyopaque, out: []u8, now_ms: Time) NodeError!?[]const u8 = null,
        nextDeadline: ?*const fn (ctx: *anyopaque, now_ms: Time) ?Time = null,
        /// Returns false when the protocol cannot express `op`; the fleet logs
        /// that rather than pretending the fault landed.
        control: ?*const fn (ctx: *anyopaque, op: Control, now_ms: Time) bool = null,
    };

    pub fn deliver(self: Node, bytes: []const u8, out: []u8, now_ms: Time) NodeError!?[]const u8 {
        return self.vtable.deliver(self.ctx, bytes, out, now_ms);
    }

    pub fn tick(self: Node, out: []u8, now_ms: Time) NodeError!?[]const u8 {
        const f = self.vtable.tick orelse return null;
        return f(self.ctx, out, now_ms);
    }

    pub fn hasTick(self: Node) bool {
        return self.vtable.tick != null;
    }

    pub fn nextDeadline(self: Node, now_ms: Time) ?Time {
        const f = self.vtable.nextDeadline orelse return null;
        return f(self.ctx, now_ms);
    }

    pub fn control(self: Node, op: Control, now_ms: Time) bool {
        const f = self.vtable.control orelse return false;
        return f(self.ctx, op, now_ms);
    }
};

// ── tests ───────────────────────────────────────────────────────────────────

const testing = std.testing;

test "framing: every length rule agrees with a real frame from its protocol" {
    // MBAP: txid 0x0001, proto 0, len 6, unit 5, FC3 read.
    const mb = [_]u8{ 0x00, 0x01, 0x00, 0x00, 0x00, 0x06, 0x05, 0x03, 0x00, 0x64, 0x00, 0x01 };
    try testing.expectEqual(@as(?usize, 12), try Framing.modbus_tcp.frameLen(&mb));
    try testing.expectEqual(@as(?usize, null), try Framing.modbus_tcp.frameLen(mb[0..4]));

    // DNP3: LEN 5 means an empty user-data frame -> 10 bytes on the wire.
    const link = [_]u8{ 0x05, 0x64, 0x05, 0xC0, 0x01, 0x00, 0x00, 0x04, 0xE9, 0x21 };
    try testing.expectEqual(@as(?usize, 10), try Framing.dnp3_link.frameLen(&link));
    // LEN 5 + 10 user bytes -> 10 + 10 + 2 (one block CRC).
    const link2 = [_]u8{ 0x05, 0x64, 15, 0xC4, 0x01, 0x00, 0x00, 0x04 } ++ [_]u8{0} ** 14;
    try testing.expectEqual(@as(?usize, 22), try Framing.dnp3_link.frameLen(&link2));

    // IEC 104 STARTDT act.
    const apci = [_]u8{ 0x68, 0x04, 0x07, 0x00, 0x00, 0x00 };
    try testing.expectEqual(@as(?usize, 6), try Framing.iec104_apci.frameLen(&apci));

    // TPKT header claims the total length.
    const tpkt = [_]u8{ 0x03, 0x00, 0x00, 0x16 } ++ [_]u8{0} ** 18;
    try testing.expectEqual(@as(?usize, 22), try Framing.tpkt.frameLen(&tpkt));

    // ENIP RegisterSession: 24-byte header + 4-byte body.
    const enip = [_]u8{ 0x65, 0x00, 0x04, 0x00 } ++ [_]u8{0} ** 24;
    try testing.expectEqual(@as(?usize, 28), try Framing.enip_encap.frameLen(&enip));

    // OPC UA HEL chunk, total length little-endian at [4..8].
    const ua = [_]u8{ 'H', 'E', 'L', 'F', 0x20, 0x00, 0x00, 0x00 } ++ [_]u8{0} ** 24;
    try testing.expectEqual(@as(?usize, 32), try Framing.opcua_uatcp.frameLen(&ua));

    // BACnet BVLC Original-Unicast-NPDU.
    const bvlc = [_]u8{ 0x81, 0x0A, 0x00, 0x0C } ++ [_]u8{0} ** 8;
    try testing.expectEqual(@as(?usize, 12), try Framing.bacnet_bvll.frameLen(&bvlc));
}

test "framing: hostile heads are BadFrame, short heads are 'need more'" {
    try testing.expectError(error.BadFrame, Framing.dnp3_link.frameLen(&.{ 0x06, 0x64, 0x05 }));
    try testing.expectError(error.BadFrame, Framing.iec104_apci.frameLen(&.{ 0x69, 0x04 }));
    try testing.expectError(error.BadFrame, Framing.iec104_apci.frameLen(&.{ 0x68, 0x01 }));
    try testing.expectError(error.BadFrame, Framing.tpkt.frameLen(&.{ 0x04, 0x00, 0x00, 0x16 }));
    try testing.expectError(error.BadFrame, Framing.bacnet_bvll.frameLen(&.{ 0x80, 0x0A, 0x00, 0x0C }));
    try testing.expectError(error.BadFrame, Framing.modbus_tcp.frameLen(&.{ 0, 1, 0, 0, 0, 0 }));
    for ([_]Framing{ .modbus_tcp, .dnp3_link, .iec104_apci, .tpkt, .enip_encap, .opcua_uatcp, .bacnet_bvll }) |f| {
        try testing.expectEqual(@as(?usize, null), try f.frameLen(&.{}));
    }
}

test "FrameIterator: splits a concatenated burst and reports the partial tail" {
    const a = [_]u8{ 0x68, 0x04, 0x07, 0x00, 0x00, 0x00 };
    const b = [_]u8{ 0x68, 0x04, 0x0B, 0x00, 0x00, 0x00 };
    var buf: [16]u8 = undefined;
    @memcpy(buf[0..6], &a);
    @memcpy(buf[6..12], &b);
    @memcpy(buf[12..15], b[0..3]); // a truncated third frame

    var it = FrameIterator.init(.iec104_apci, buf[0..15]);
    try testing.expectEqualSlices(u8, &a, it.next().?);
    try testing.expectEqualSlices(u8, &b, it.next().?);
    try testing.expectEqual(@as(?[]const u8, null), it.next());
    try testing.expectEqual(@as(usize, 3), it.rest().len);
    try testing.expect(!it.bad);
}

test "FrameIterator: a malformed head stops the walk without consuming it" {
    var it = FrameIterator.init(.iec104_apci, &.{ 0x69, 0x04, 0x07, 0x00 });
    try testing.expectEqual(@as(?[]const u8, null), it.next());
    try testing.expect(it.bad);
    try testing.expectEqual(@as(usize, 4), it.rest().len);
}

test "Protocol: ports and datagram-ness" {
    try testing.expectEqual(@as(u16, 502), Protocol.modbus.defaultPort());
    try testing.expectEqual(@as(u16, 47808), Protocol.bacnet.defaultPort());
    try testing.expect(Protocol.bacnet.isDatagram());
    try testing.expect(!Protocol.modbus.isDatagram());
}
