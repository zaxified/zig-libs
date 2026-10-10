// SPDX-License-Identifier: MIT
//! CTAPHID message framing (CTAP 2.1 §11.2): a message is split into 64-byte
//! reports, one initialization packet followed by continuation packets.
//!
//!   init packet:  CID(4) | CMD(1, bit 7 set) | BCNTH | BCNTL | DATA(57)
//!   cont packet:  CID(4) | SEQ(1, 0..127)    | DATA(59)
//!
//! This file is a pure codec: `Encoder` turns a message into reports, `Assembler`
//! turns reports back into a message, and `Channel` drives one CTAPHID_CBOR
//! transaction (keep-alives skipped) over a caller-supplied `ReportDevice` —
//! the actual `/dev/hidraw` or libusb read/write stays with the caller.

const std = @import("std");
const framing = @import("framing.zig");

pub const packet_size = 64;
pub const init_data_size = packet_size - 7; // 57
pub const cont_data_size = packet_size - 5; // 59
/// 57 + 128 * 59 = 7609: the largest message that fits 128 sequence numbers.
pub const max_payload = init_data_size + 128 * cont_data_size;
pub const broadcast_cid: u32 = 0xFFFF_FFFF;

pub const Packet = [packet_size]u8;

/// CTAPHID command numbers, without the bit-7 marker the wire adds (§11.2.9).
pub const Command = enum(u8) {
    ping = 0x01,
    msg = 0x03,
    lock = 0x04,
    init = 0x06,
    wink = 0x08,
    cbor = 0x10,
    cancel = 0x11,
    keepalive = 0x3B,
    @"error" = 0x3F,
    _,
};

/// CTAPHID_ERROR codes (§11.2.9.1.6).
pub const HidError = enum(u8) {
    invalid_cmd = 0x01,
    invalid_par = 0x02,
    invalid_len = 0x03,
    invalid_seq = 0x04,
    msg_timeout = 0x05,
    channel_busy = 0x06,
    lock_required = 0x0A,
    invalid_channel = 0x0B,
    other = 0x7F,
    _,
};

pub const EncodeError = error{PayloadTooLong};

/// Iterates the reports of one message. Unused bytes are zero.
pub const Encoder = struct {
    cid: u32,
    cmd: u8,
    payload: []const u8,
    sent: usize = 0,
    seq: u8 = 0,
    started: bool = false,

    pub fn init(cid: u32, cmd: Command, payload: []const u8) EncodeError!Encoder {
        if (payload.len > max_payload) return error.PayloadTooLong;
        return .{ .cid = cid, .cmd = @intFromEnum(cmd), .payload = payload };
    }

    /// Number of reports `payload_len` bytes need (at least one).
    pub fn packetCount(payload_len: usize) usize {
        if (payload_len <= init_data_size) return 1;
        return 1 + (payload_len - init_data_size + cont_data_size - 1) / cont_data_size;
    }

    /// Fill `out` with the next report; `false` when the message is done.
    pub fn next(self: *Encoder, out: *Packet) bool {
        if (self.started and self.sent >= self.payload.len) return false;
        @memset(out, 0);
        std.mem.writeInt(u32, out[0..4], self.cid, .big);
        if (!self.started) {
            self.started = true;
            out[4] = 0x80 | self.cmd;
            std.mem.writeInt(u16, out[5..7], @intCast(self.payload.len), .big);
            const n = @min(init_data_size, self.payload.len);
            @memcpy(out[7..][0..n], self.payload[0..n]);
            self.sent = n;
        } else {
            out[4] = self.seq;
            self.seq += 1;
            const n = @min(cont_data_size, self.payload.len - self.sent);
            @memcpy(out[5..][0..n], self.payload[self.sent..][0..n]);
            self.sent += n;
        }
        return true;
    }
};

pub const AssembleError = error{
    /// A continuation packet arrived with no message in progress.
    UnexpectedContinuation,
    /// An initialization packet arrived while a message was in progress.
    UnexpectedInit,
    /// The continuation sequence number is not the expected one.
    BadSequence,
    /// The declared length exceeds the protocol maximum or the caller's buffer.
    PayloadTooLarge,
};

pub const Message = struct {
    cid: u32,
    /// The command with bit 7 stripped.
    cmd: Command,
    payload: []const u8,
};

pub const Feed = union(enum) {
    /// More packets are needed.
    incomplete,
    /// The packet belongs to another channel; ignore it.
    other_channel,
    complete: Message,
};

/// Reassembles one message on channel `cid` from reports, into caller storage.
pub const Assembler = struct {
    cid: u32,
    buf: []u8,
    cmd: u8 = 0,
    want: usize = 0,
    have: usize = 0,
    next_seq: u8 = 0,
    active: bool = false,

    pub fn init(cid: u32, buf: []u8) Assembler {
        return .{ .cid = cid, .buf = buf };
    }

    fn reset(self: *Assembler) void {
        self.active = false;
        self.have = 0;
        self.want = 0;
        self.next_seq = 0;
    }

    /// Consume one report. On an error the assembler is reset (the caller
    /// decides whether to abort or resynchronize with CTAPHID_INIT).
    pub fn feed(self: *Assembler, packet: *const Packet) AssembleError!Feed {
        const cid = std.mem.readInt(u32, packet[0..4], .big);
        if (cid != self.cid) return .other_channel;
        if (packet[4] & 0x80 != 0) {
            if (self.active) {
                self.reset();
                return error.UnexpectedInit;
            }
            const len: usize = std.mem.readInt(u16, packet[5..7], .big);
            if (len > max_payload or len > self.buf.len) return error.PayloadTooLarge;
            self.cmd = packet[4] & 0x7f;
            self.want = len;
            const n = @min(init_data_size, len);
            @memcpy(self.buf[0..n], packet[7..][0..n]);
            self.have = n;
            self.next_seq = 0;
            self.active = true;
        } else {
            if (!self.active) return error.UnexpectedContinuation;
            if (packet[4] != self.next_seq) {
                self.reset();
                return error.BadSequence;
            }
            self.next_seq += 1;
            const n = @min(cont_data_size, self.want - self.have);
            @memcpy(self.buf[self.have..][0..n], packet[5..][0..n]);
            self.have += n;
        }
        if (self.have < self.want) return .incomplete;
        const msg: Message = .{ .cid = self.cid, .cmd = @enumFromInt(self.cmd), .payload = self.buf[0..self.want] };
        self.active = false;
        return .{ .complete = msg };
    }
};

// ── CTAPHID_INIT ────────────────────────────────────────────────────────────

pub const InitResponse = struct {
    nonce: [8]u8,
    cid: u32,
    protocol_version: u8,
    device_major: u8,
    device_minor: u8,
    device_build: u8,
    capabilities: u8,

    pub const cap_wink: u8 = 0x01;
    pub const cap_cbor: u8 = 0x04;
    pub const cap_nmsg: u8 = 0x08;

    pub fn supportsCbor(self: InitResponse) bool {
        return self.capabilities & cap_cbor != 0;
    }
};

pub const InitError = error{ ShortResponse, NonceMismatch };

/// Parse a CTAPHID_INIT response payload. Longer payloads are accepted (the
/// spec reserves room for later fields); the nonce must match the request's.
pub fn parseInitResponse(payload: []const u8, nonce: [8]u8) InitError!InitResponse {
    if (payload.len < 17) return error.ShortResponse;
    if (!std.mem.eql(u8, payload[0..8], &nonce)) return error.NonceMismatch;
    return .{
        .nonce = nonce,
        .cid = std.mem.readInt(u32, payload[8..12], .big),
        .protocol_version = payload[12],
        .device_major = payload[13],
        .device_minor = payload[14],
        .device_build = payload[15],
        .capabilities = payload[16],
    };
}

// ── one CTAPHID_CBOR transaction over a report device ───────────────────────

/// Sends and receives single 64-byte reports. Blocking, one report per call.
pub const ReportDevice = struct {
    ctx: *anyopaque,
    writeFn: *const fn (ctx: *anyopaque, report: *const Packet) framing.TransportError!void,
    readFn: *const fn (ctx: *anyopaque, report: *Packet) framing.TransportError!void,
};

/// Give up after this many consecutive keep-alive messages (a stuck device).
pub const max_keepalives = 100_000;

/// One CTAPHID channel: `transact` runs a CTAPHID_CBOR exchange and can be
/// wrapped as a `framing.Transport`.
pub const Channel = struct {
    dev: ReportDevice,
    cid: u32,
    /// Set when the last transaction ended with a CTAPHID_ERROR response.
    last_hid_error: ?HidError = null,

    /// Allocate a channel: CTAPHID_INIT on the broadcast CID with a caller-chosen
    /// nonce (use fresh randomness).
    pub fn open(dev: ReportDevice, nonce: [8]u8) framing.TransportError!Channel {
        var ch: Channel = .{ .dev = dev, .cid = broadcast_cid };
        var buf: [64]u8 = undefined;
        const msg = try ch.exchangeFiltered(.init, &nonce, &buf, &nonce);
        const info = parseInitResponse(msg, nonce) catch return error.TransportFailed;
        if (!info.supportsCbor()) return error.TransportFailed;
        // CID 0 is reserved and the broadcast CID is for INIT only (§11.2.3): a
        // device that hands either out as the new channel is not speaking CTAPHID.
        if (info.cid == 0 or info.cid == broadcast_cid) return error.TransportFailed;
        ch.cid = info.cid;
        return ch;
    }

    fn exchange(self: *Channel, cmd: Command, payload: []const u8, out: []u8) framing.TransportError![]const u8 {
        return self.exchangeFiltered(cmd, payload, out, null);
    }

    /// `init_nonce`: an INIT response on the broadcast channel whose nonce is
    /// not this one answers another client's INIT and is skipped (§11.2.3:
    /// "the client ignores it and keeps reading"), instead of failing `open`.
    fn exchangeFiltered(self: *Channel, cmd: Command, payload: []const u8, out: []u8, init_nonce: ?*const [8]u8) framing.TransportError![]const u8 {
        self.last_hid_error = null;
        var enc = Encoder.init(self.cid, cmd, payload) catch return error.TransportFailed;
        var pkt: Packet = undefined;
        while (enc.next(&pkt)) try self.dev.writeFn(self.dev.ctx, &pkt);

        var asm_ = Assembler.init(self.cid, out);
        var keepalives: usize = 0;
        while (true) {
            try self.dev.readFn(self.dev.ctx, &pkt);
            const fed = asm_.feed(&pkt) catch |e| switch (e) {
                error.PayloadTooLarge => return error.ResponseBufferTooSmall,
                else => return error.TransportFailed,
            };
            switch (fed) {
                .incomplete, .other_channel => {},
                .complete => |m| switch (m.cmd) {
                    .keepalive => {
                        keepalives += 1;
                        if (keepalives > max_keepalives) return error.TransportFailed;
                    },
                    .@"error" => {
                        self.last_hid_error = if (m.payload.len >= 1) @enumFromInt(m.payload[0]) else .other;
                        return error.TransportFailed;
                    },
                    else => {
                        if (m.cmd != cmd) return error.TransportFailed;
                        if (init_nonce) |n| if (m.payload.len >= 8 and !std.mem.eql(u8, m.payload[0..8], n)) {
                            asm_ = Assembler.init(self.cid, out);
                            continue;
                        };
                        return m.payload;
                    },
                },
            }
        }
    }

    /// `request` = CTAP command byte || CBOR; the response (status byte ||
    /// CBOR) lands in `response`. Returns its length.
    pub fn transact(self: *Channel, request: []const u8, response: []u8) framing.TransportError!usize {
        const payload = try self.exchange(.cbor, request, response);
        return payload.len;
    }

    fn transactFn(ctx: *anyopaque, request: []const u8, response: []u8) framing.TransportError!usize {
        const self: *Channel = @ptrCast(@alignCast(ctx));
        return self.transact(request, response);
    }

    pub fn transport(self: *Channel) framing.Transport {
        return .{ .ctx = self, .transactFn = transactFn };
    }
};

// ── tests ───────────────────────────────────────────────────────────────────

const testing = std.testing;

test "constants match the spec" {
    try testing.expectEqual(@as(usize, 57), init_data_size);
    try testing.expectEqual(@as(usize, 59), cont_data_size);
    try testing.expectEqual(@as(usize, 7609), max_payload); // CTAP 2.1 §11.2.4
    try testing.expectEqual(@as(u8, 0x10), @intFromEnum(Command.cbor));
    try testing.expectEqual(@as(u8, 0x06), @intFromEnum(Command.init));
    try testing.expectEqual(@as(u8, 0x3F), @intFromEnum(Command.@"error"));
}

test "init packet layout: CID | 0x80|CMD | BCNT | data, zero padded" {
    var enc = try Encoder.init(0x01020304, .cbor, &.{0x04});
    var p: Packet = undefined;
    try testing.expect(enc.next(&p));
    try testing.expectEqualSlices(u8, &.{ 1, 2, 3, 4, 0x90, 0x00, 0x01, 0x04 }, p[0..8]);
    for (p[8..]) |b| try testing.expectEqual(@as(u8, 0), b);
    try testing.expect(!enc.next(&p));
}

test "INIT request on the broadcast channel" {
    const nonce = [_]u8{ 1, 2, 3, 4, 5, 6, 7, 8 };
    var enc = try Encoder.init(broadcast_cid, .init, &nonce);
    var p: Packet = undefined;
    try testing.expect(enc.next(&p));
    try testing.expectEqualSlices(u8, &.{ 0xff, 0xff, 0xff, 0xff, 0x86, 0x00, 0x08, 1, 2, 3, 4, 5, 6, 7, 8 }, p[0..15]);
}

test "continuation packets: sequence numbers and boundaries" {
    var payload: [57 + 59 + 1]u8 = undefined;
    for (&payload, 0..) |*b, i| b.* = @intCast(i);
    var enc = try Encoder.init(7, .cbor, &payload);
    var p: Packet = undefined;
    try testing.expect(enc.next(&p));
    try testing.expectEqual(@as(u8, 0x90), p[4]);
    try testing.expectEqual(@as(u8, 56), p[63]);
    try testing.expect(enc.next(&p));
    try testing.expectEqual(@as(u8, 0), p[4]); // SEQ 0
    try testing.expectEqual(@as(u8, 57), p[5]);
    try testing.expectEqual(@as(u8, 115), p[63]);
    try testing.expect(enc.next(&p));
    try testing.expectEqual(@as(u8, 1), p[4]); // SEQ 1
    try testing.expectEqual(@as(u8, 116), p[5]);
    try testing.expectEqual(@as(u8, 0), p[6]); // padding
    try testing.expect(!enc.next(&p));
    try testing.expectEqual(@as(usize, 3), Encoder.packetCount(payload.len));
}

test "packetCount boundaries" {
    try testing.expectEqual(@as(usize, 1), Encoder.packetCount(0));
    try testing.expectEqual(@as(usize, 1), Encoder.packetCount(57));
    try testing.expectEqual(@as(usize, 2), Encoder.packetCount(58));
    try testing.expectEqual(@as(usize, 2), Encoder.packetCount(57 + 59));
    try testing.expectEqual(@as(usize, 3), Encoder.packetCount(57 + 59 + 1));
    try testing.expectEqual(@as(usize, 129), Encoder.packetCount(max_payload));
}

test "encoder/assembler round trip at every boundary length" {
    const a = testing.allocator;
    const lens = [_]usize{ 0, 1, 56, 57, 58, 115, 116, 117, 175, 176, 1000, max_payload - 1, max_payload };
    for (lens) |len| {
        const payload = try a.alloc(u8, len);
        defer a.free(payload);
        for (payload, 0..) |*b, i| b.* = @truncate(i *% 31 +% 7);
        const buf = try a.alloc(u8, max_payload);
        defer a.free(buf);
        var enc = try Encoder.init(0xdeadbeef, .cbor, payload);
        var asm_ = Assembler.init(0xdeadbeef, buf);
        var p: Packet = undefined;
        var count: usize = 0;
        var done: ?Message = null;
        while (enc.next(&p)) {
            count += 1;
            switch (try asm_.feed(&p)) {
                .complete => |m| done = m,
                else => {},
            }
        }
        try testing.expectEqual(Encoder.packetCount(len), count);
        try testing.expectEqualSlices(u8, payload, done.?.payload);
        try testing.expectEqual(Command.cbor, done.?.cmd);
    }
}

test "encoder: over-long payload is refused" {
    const big = [_]u8{0} ** (max_payload + 1);
    try testing.expectError(error.PayloadTooLong, Encoder.init(1, .cbor, &big));
}

test "assembler: errors and other channels" {
    var buf: [200]u8 = undefined;
    var asm_ = Assembler.init(5, &buf);
    var p: Packet = @splat(0);
    // A packet for another channel is ignored.
    std.mem.writeInt(u32, p[0..4], 6, .big);
    p[4] = 0x90;
    try testing.expectEqual(Feed.other_channel, try asm_.feed(&p));
    // Continuation with nothing in progress.
    std.mem.writeInt(u32, p[0..4], 5, .big);
    p[4] = 0x00;
    try testing.expectError(error.UnexpectedContinuation, asm_.feed(&p));
    // Declared length larger than the buffer / the protocol maximum.
    p[4] = 0x90;
    std.mem.writeInt(u16, p[5..7], 201, .big);
    try testing.expectError(error.PayloadTooLarge, asm_.feed(&p));
    std.mem.writeInt(u16, p[5..7], 0xffff, .big);
    try testing.expectError(error.PayloadTooLarge, asm_.feed(&p));
    // A second init while one is in progress.
    std.mem.writeInt(u16, p[5..7], 100, .big);
    try testing.expectEqual(Feed.incomplete, try asm_.feed(&p));
    try testing.expectError(error.UnexpectedInit, asm_.feed(&p));
    // Wrong sequence number.
    try testing.expectEqual(Feed.incomplete, try asm_.feed(&p));
    p[4] = 1;
    try testing.expectError(error.BadSequence, asm_.feed(&p));
    // After an error the assembler accepts a fresh message.
    p[4] = 0x90;
    std.mem.writeInt(u16, p[5..7], 3, .big);
    try testing.expect((try asm_.feed(&p)) == .complete);
}

test "parseInitResponse: fields, longer payloads, and the failures" {
    const nonce = [_]u8{ 1, 2, 3, 4, 5, 6, 7, 8 };
    var payload: [17]u8 = undefined;
    @memcpy(payload[0..8], &nonce);
    std.mem.writeInt(u32, payload[8..12], 0x11223344, .big);
    payload[12] = 2;
    payload[13] = 5;
    payload[14] = 6;
    payload[15] = 7;
    payload[16] = 0x0d; // wink + cbor + nmsg
    const r = try parseInitResponse(&payload, nonce);
    try testing.expectEqual(@as(u32, 0x11223344), r.cid);
    try testing.expectEqual(@as(u8, 2), r.protocol_version);
    try testing.expect(r.supportsCbor());
    var longer: [20]u8 = @splat(0);
    @memcpy(longer[0..17], &payload);
    _ = try parseInitResponse(&longer, nonce);
    try testing.expectError(error.ShortResponse, parseInitResponse(payload[0..16], nonce));
    try testing.expectError(error.NonceMismatch, parseInitResponse(&payload, .{ 9, 9, 9, 9, 9, 9, 9, 9 }));
}

/// A loopback authenticator: reassembles requests, answers INIT, and answers
/// CBOR with two keep-alives then `status 0 || request[1..]`.
const FakeHid = struct {
    a: std.mem.Allocator,
    cid: u32 = 0x0a0b0c0d,
    inbox: [max_payload]u8 = undefined,
    asm_: ?Assembler = null,
    queue: std.ArrayList(Packet) = .empty,
    inject_error: ?u8 = null,
    caps: u8 = 0x04,

    fn dev(self: *FakeHid) ReportDevice {
        return .{ .ctx = self, .writeFn = write, .readFn = read };
    }

    fn push(self: *FakeHid, cid: u32, cmd: Command, payload: []const u8) !void {
        var enc = try Encoder.init(cid, cmd, payload);
        var p: Packet = undefined;
        while (enc.next(&p)) try self.queue.append(self.a, p);
    }

    fn write(ctx: *anyopaque, report: *const Packet) framing.TransportError!void {
        const self: *FakeHid = @ptrCast(@alignCast(ctx));
        const cid = std.mem.readInt(u32, report[0..4], .big);
        if (self.asm_ == null) self.asm_ = Assembler.init(cid, &self.inbox);
        const fed = self.asm_.?.feed(report) catch return error.TransportFailed;
        const m = switch (fed) {
            .complete => |m| m,
            else => return,
        };
        self.asm_ = null;
        self.respond(m) catch return error.TransportFailed;
    }

    fn respond(self: *FakeHid, m: Message) !void {
        switch (m.cmd) {
            .init => {
                var resp: [17]u8 = undefined;
                @memcpy(resp[0..8], m.payload[0..8]);
                std.mem.writeInt(u32, resp[8..12], self.cid, .big);
                resp[12] = 2;
                resp[13] = 1;
                resp[14] = 0;
                resp[15] = 0;
                resp[16] = self.caps;
                try self.push(m.cid, .init, &resp);
            },
            .cbor => {
                if (self.inject_error) |code| return self.push(m.cid, .@"error", &.{code});
                try self.push(m.cid, .keepalive, &.{1});
                try self.push(0x99999999, .cbor, &.{ 0xEE, 0xEE }); // another channel's traffic
                try self.push(m.cid, .keepalive, &.{2});
                const out = try self.a.alloc(u8, m.payload.len);
                defer self.a.free(out);
                out[0] = 0x00;
                @memcpy(out[1..], m.payload[1..]);
                try self.push(m.cid, .cbor, out);
            },
            else => try self.push(m.cid, .@"error", &.{0x01}),
        }
    }

    fn read(ctx: *anyopaque, report: *Packet) framing.TransportError!void {
        const self: *FakeHid = @ptrCast(@alignCast(ctx));
        if (self.queue.items.len == 0) return error.TransportFailed;
        report.* = self.queue.orderedRemove(0);
    }
};

test "Channel: open, then a multi-packet CBOR transaction with keep-alives and foreign traffic" {
    const a = testing.allocator;
    var hid: FakeHid = .{ .a = a };
    defer hid.queue.deinit(a);
    var ch = try Channel.open(hid.dev(), .{ 1, 2, 3, 4, 5, 6, 7, 8 });
    try testing.expectEqual(@as(u32, 0x0a0b0c0d), ch.cid);

    var request: [300]u8 = undefined;
    for (&request, 0..) |*b, i| b.* = @truncate(i);
    request[0] = 0x06;
    var resp: [400]u8 = undefined;
    const t = ch.transport();
    var raw: [400]u8 = undefined;
    const got = try t.transact(&request, &raw);
    try testing.expectEqual(@as(usize, 300), got.len);
    try testing.expectEqual(@as(u8, 0), got[0]);
    try testing.expectEqualSlices(u8, request[1..], got[1..]);
    _ = &resp;
    try testing.expectEqual(@as(usize, 0), hid.queue.items.len);
}

test "Channel: CTAPHID_ERROR, a too-small buffer, and a device without CBOR" {
    const a = testing.allocator;
    var hid: FakeHid = .{ .a = a };
    defer hid.queue.deinit(a);
    var ch = try Channel.open(hid.dev(), .{ 8, 7, 6, 5, 4, 3, 2, 1 });
    hid.inject_error = 0x06;
    var out: [64]u8 = undefined;
    try testing.expectError(error.TransportFailed, ch.transact(&.{0x04}, &out));
    try testing.expectEqual(HidError.channel_busy, ch.last_hid_error.?);
    hid.inject_error = null;
    hid.queue.clearRetainingCapacity();
    var small: [3]u8 = undefined;
    try testing.expectError(error.ResponseBufferTooSmall, ch.transact(&.{ 0x06, 1, 2, 3, 4, 5 }, &small));

    var hid2: FakeHid = .{ .a = a, .caps = 0x08 };
    defer hid2.queue.deinit(a);
    try testing.expectError(error.TransportFailed, Channel.open(hid2.dev(), .{ 0, 0, 0, 0, 0, 0, 0, 0 }));
}

test "parseInitResponse: every field is read from its own offset" {
    const nonce = [_]u8{ 1, 2, 3, 4, 5, 6, 7, 8 };
    var payload: [17]u8 = undefined;
    @memcpy(payload[0..8], &nonce);
    std.mem.writeInt(u32, payload[8..12], 0xa1b2c3d4, .big);
    payload[12] = 2;
    payload[13] = 5;
    payload[14] = 6;
    payload[15] = 7;
    payload[16] = 0x05;
    const r = try parseInitResponse(&payload, nonce);
    try testing.expectEqual(@as(u8, 2), r.protocol_version);
    try testing.expectEqual(@as(u8, 5), r.device_major);
    try testing.expectEqual(@as(u8, 6), r.device_minor);
    try testing.expectEqual(@as(u8, 7), r.device_build);
    try testing.expectEqual(@as(u8, 0x05), r.capabilities);
}

test "assembler: the length bound is the protocol's, not only the buffer's" {
    const a = testing.allocator;
    const buf = try a.alloc(u8, max_payload + 100);
    defer a.free(buf);
    var asm_ = Assembler.init(5, buf);
    var p: Packet = @splat(0);
    std.mem.writeInt(u32, p[0..4], 5, .big);
    p[4] = 0x90;
    // 7610 bytes would need 129 continuation packets; sequence number 128 has bit 7 set.
    std.mem.writeInt(u16, p[5..7], max_payload + 1, .big);
    try testing.expectError(error.PayloadTooLarge, asm_.feed(&p));
    std.mem.writeInt(u16, p[5..7], max_payload, .big);
    try testing.expectEqual(Feed.incomplete, try asm_.feed(&p));
}

test "assembler: back-to-back messages on one assembler, and a buffer of exactly the message size" {
    const a = testing.allocator;
    var asm_ = Assembler.init(9, try a.alloc(u8, 130));
    defer a.free(asm_.buf);
    // First message: 130 bytes = 57 + 59 + 14, so the last packet is partial and
    // fills the buffer to its last byte.
    var first: [130]u8 = undefined;
    for (&first, 0..) |*b, i| b.* = @intCast(i);
    var enc = try Encoder.init(9, .cbor, &first);
    var p: Packet = undefined;
    var done: ?Message = null;
    while (enc.next(&p)) {
        switch (try asm_.feed(&p)) {
            .complete => |m| done = m,
            else => {},
        }
    }
    try testing.expectEqualSlices(u8, &first, done.?.payload);
    // Second message on the same assembler: sequence numbers restart at 0 and a
    // finished message leaves nothing in progress.
    var second: [100]u8 = undefined;
    for (&second, 0..) |*b, i| b.* = @intCast(255 - i);
    var enc2 = try Encoder.init(9, .ping, &second);
    done = null;
    while (enc2.next(&p)) {
        switch (try asm_.feed(&p)) {
            .complete => |m| done = m,
            else => {},
        }
    }
    try testing.expectEqualSlices(u8, &second, done.?.payload);
    try testing.expectEqual(Command.ping, done.?.cmd);
    // Nothing is in progress now: a continuation packet is a stray.
    p[4] = 0;
    try testing.expectError(error.UnexpectedContinuation, asm_.feed(&p));
    // ... and a fresh init is not "an init during a message".
    p[4] = 0x90;
    std.mem.writeInt(u16, p[5..7], 1, .big);
    try testing.expect((try asm_.feed(&p)) == .complete);
}

/// A scripted device for hostile-device cases: writes are swallowed, reads pop
/// `queue`, or (with `flood_cid` set) are an endless stream of keep-alives.
const ScriptDev = struct {
    a: std.mem.Allocator,
    queue: std.ArrayList(Packet) = .empty,
    flood_cid: ?u32 = null,
    reads: usize = 0,

    fn dev(self: *ScriptDev) ReportDevice {
        return .{ .ctx = self, .writeFn = write, .readFn = read };
    }

    fn push(self: *ScriptDev, cid: u32, cmd: Command, payload: []const u8) !void {
        var enc = try Encoder.init(cid, cmd, payload);
        var p: Packet = undefined;
        while (enc.next(&p)) try self.queue.append(self.a, p);
    }

    fn write(_: *anyopaque, _: *const Packet) framing.TransportError!void {}

    fn read(ctx: *anyopaque, report: *Packet) framing.TransportError!void {
        const self: *ScriptDev = @ptrCast(@alignCast(ctx));
        self.reads += 1;
        if (self.flood_cid) |cid| {
            var enc = Encoder.init(cid, .keepalive, &.{1}) catch unreachable;
            _ = enc.next(report);
            return;
        }
        if (self.queue.items.len == 0) return error.TransportFailed;
        report.* = self.queue.orderedRemove(0);
    }
};

test "Channel: a device that only ever sends keep-alives is given up on" {
    var sd: ScriptDev = .{ .a = testing.allocator, .flood_cid = 7 };
    var ch: Channel = .{ .dev = sd.dev(), .cid = 7 };
    var out: [64]u8 = undefined;
    try testing.expectError(error.TransportFailed, ch.transact(&.{0x04}, &out));
    try testing.expectEqual(@as(usize, max_keepalives + 1), sd.reads);
}

test "Channel: a response to another command, an empty error, and a stale error" {
    const a = testing.allocator;
    var sd: ScriptDev = .{ .a = a };
    defer sd.queue.deinit(a);
    var ch: Channel = .{ .dev = sd.dev(), .cid = 7 };
    var out: [64]u8 = undefined;

    // A PING answer to a CBOR request is not the answer.
    try sd.push(7, .ping, &.{ 0, 1, 2 });
    try testing.expectError(error.TransportFailed, ch.transact(&.{0x04}, &out));

    // CTAPHID_ERROR without its code byte: reported as `other`, no out-of-range read.
    sd.queue.clearRetainingCapacity();
    try sd.push(7, .@"error", &.{});
    try testing.expectError(error.TransportFailed, ch.transact(&.{0x04}, &out));
    try testing.expectEqual(HidError.other, ch.last_hid_error.?);

    // The next successful transaction clears the recorded error.
    sd.queue.clearRetainingCapacity();
    try sd.push(7, .cbor, &.{0x00});
    try testing.expectEqual(@as(usize, 1), try ch.transact(&.{0x04}, &out));
    try testing.expectEqual(@as(?HidError, null), ch.last_hid_error);
}

test "Channel.open: a device that allocates CID 0 or the broadcast CID is refused" {
    const a = testing.allocator;
    for ([_]u32{ 0, broadcast_cid }) |bad| {
        var hid: FakeHid = .{ .a = a, .cid = bad };
        defer hid.queue.deinit(a);
        try testing.expectError(error.TransportFailed, Channel.open(hid.dev(), .{ 1, 2, 3, 4, 5, 6, 7, 8 }));
    }
}

test "Channel.open: another client's INIT response on the broadcast channel is skipped" {
    const a = testing.allocator;
    var hid: FakeHid = .{ .a = a };
    defer hid.queue.deinit(a);
    // Queued before ours: the answer to someone else's INIT (other nonce, other CID).
    var foreign: [17]u8 = @splat(0);
    @memcpy(foreign[0..8], &[_]u8{ 9, 9, 9, 9, 9, 9, 9, 9 });
    std.mem.writeInt(u32, foreign[8..12], 0x11223344, .big);
    foreign[16] = 0x04;
    try hid.push(broadcast_cid, .init, &foreign);
    const ch = try Channel.open(hid.dev(), .{ 1, 2, 3, 4, 5, 6, 7, 8 });
    try testing.expectEqual(hid.cid, ch.cid);
}

// ── fuzz: a hostile authenticator on the HID side ───────────────────────────

const fz = @import("fuzz_test.zig");
const testkit = @import("testkit");
const HidMark = fz.Marker(enum {
    roundtrip,
    roundtrip_noise,
    damaged_error,
    damaged_complete,
    damaged_incomplete,
    unknown_command,
    init_ok,
    init_refused,
    channel_ok,
    channel_keepalive,
    channel_hid_error,
    channel_refused,
});

test "fuzz driver: CTAP2_FUZZ (ctaphid)" {
    try fz.fuzz_driver.run(fuzzHid, .{ .prefix = "CTAP2_FUZZ", .name = "ctap2-ctaphid" });
}

test "fuzz harness: ctaphid, 300 seeds, reaches every outcome" {
    try HidMark.reach(fuzzHid, "ctap2-ctaphid", 300);
}

test "fuzz: ctaphid assembler and channel survive a damaged report stream" {
    try testing.fuzz({}, fuzzHidSmith, .{});
}

fn fuzzHidSmith(_: void, smith: *std.testing.Smith) !void {
    var script: [1024]u8 = undefined;
    var src: testkit.fuzz.ScriptSource = .init(script[0..smith.slice(&script)]);
    try fuzzHid(testkit.fuzz.ScriptSource, &src, testing.allocator);
}

/// A scripted report device: serves `reads` in order (then a transport
/// failure), records what the channel wrote.
const FakeDevice = struct {
    reads: []const Packet,
    ri: usize = 0,
    written: [16]Packet = undefined,
    nw: usize = 0,

    fn dev(self: *FakeDevice) ReportDevice {
        return .{ .ctx = self, .writeFn = write, .readFn = read };
    }
    fn write(ctx: *anyopaque, report: *const Packet) framing.TransportError!void {
        const self: *FakeDevice = @ptrCast(@alignCast(ctx));
        if (self.nw == self.written.len) return error.TransportFailed;
        self.written[self.nw] = report.*;
        self.nw += 1;
    }
    fn read(ctx: *anyopaque, report: *Packet) framing.TransportError!void {
        const self: *FakeDevice = @ptrCast(@alignCast(ctx));
        if (self.ri >= self.reads.len) return error.TransportFailed;
        report.* = self.reads[self.ri];
        self.ri += 1;
    }
};

/// Encode `payload` as `cmd` on `cid` and append the reports.
fn pushMessage(list: *std.ArrayList(Packet), gpa: std.mem.Allocator, cid: u32, cmd: Command, payload: []const u8) !void {
    var enc = try Encoder.init(cid, cmd, payload);
    var pkt: Packet = undefined;
    while (enc.next(&pkt)) try list.append(gpa, pkt);
}

fn fuzzHid(comptime S: type, src: *S, gpa: std.mem.Allocator) anyerror!void {
    const our_cid: u32 = src.value(u32) | 1;
    var payload: [400]u8 = undefined;
    const plen = src.valueRangeAtMost(u16, 0, payload.len);
    src.bytes(&payload);
    const body = payload[0..plen];
    const raw_cmd = src.valueRangeAtMost(u8, 0, 0x7f);
    const cmd: Command = @enumFromInt(raw_cmd);
    switch (cmd) {
        .ping, .msg, .lock, .init, .wink, .cbor, .cancel, .keepalive, .@"error" => {},
        _ => HidMark.mark(.unknown_command),
    }

    // (1) Assembler: the genuine report stream comes back as the message, with
    // reports of other channels interleaved; then one damaged copy.
    var pkts: std.ArrayList(Packet) = .empty;
    defer pkts.deinit(gpa);
    try pushMessage(&pkts, gpa, our_cid, cmd, body);
    var buf: [max_payload]u8 = undefined;
    {
        var a = Assembler.init(our_cid, &buf);
        var got: ?Message = null;
        var noise = false;
        for (pkts.items) |*pk| {
            if (src.valueRangeAtMost(u8, 0, 3) == 0) {
                var other: Packet = pk.*;
                std.mem.writeInt(u32, other[0..4], our_cid ^ 0x8000_0000, .big);
                if ((try a.feed(&other)) != .other_channel) return error.OtherChannelNotIgnored;
                noise = true;
            }
            switch (try a.feed(pk)) {
                .complete => |m| got = m,
                .incomplete => {},
                .other_channel => return error.OwnChannelIgnored,
            }
        }
        const m = got orelse return error.GenuineMessageNotAssembled;
        if (m.cmd != cmd or m.cid != our_cid or !std.mem.eql(u8, m.payload, body)) return error.GenuineMessageChanged;
        if (noise) HidMark.mark(.roundtrip_noise) else HidMark.mark(.roundtrip);
    }
    {
        var a = Assembler.init(our_cid, &buf);
        const victim = src.index(pkts.items.len);
        for (pkts.items, 0..) |*pk, i| {
            var use: Packet = pk.*;
            if (i == victim) {
                var dmg: Packet = undefined;
                const n = fz.damage(src, &dmg, pk);
                @memcpy(use[0..n], dmg[0..n]);
                if (n < use.len and src.value(bool)) @memset(use[n..], 0);
            }
            if (a.feed(&use)) |f| switch (f) {
                .complete => HidMark.mark(.damaged_complete),
                .incomplete => HidMark.mark(.damaged_incomplete),
                .other_channel => {},
            } else |_| {
                HidMark.mark(.damaged_error);
                // `active` is what gates the next report; the counters of a
                // finished message stay behind until the next init report
                // overwrites them (an error with nothing in progress resets nothing).
                if (a.active) return error.AssemblerStillActiveAfterError;
                break;
            }
            if (a.have > a.want or a.want > buf.len) return error.AssemblerCountsOutOfRange;
        }
    }

    // (2) CTAPHID_INIT response parse: genuine accepted, wrong nonce / short refused.
    var nonce: [8]u8 = undefined;
    src.bytes(&nonce);
    var init_payload: [17]u8 = undefined;
    @memcpy(init_payload[0..8], &nonce);
    src.bytes(init_payload[8..]);
    if (parseInitResponse(&init_payload, nonce)) |_| HidMark.mark(.init_ok) else |_| return error.GenuineInitRefused;
    var bad = init_payload;
    bad[src.index(8)] ^= 1;
    if (parseInitResponse(&bad, nonce)) |_| return error.WrongNonceAccepted else |_| {}
    if (parseInitResponse(init_payload[0..src.index(17)], nonce)) |_| return error.ShortInitAccepted else |_| HidMark.mark(.init_refused);

    // (3) Channel: INIT on the broadcast channel then one CBOR exchange, the
    // device's reports woven from keepalives, other-channel noise and the
    // answer; optionally one report damaged.
    var reads: std.ArrayList(Packet) = .empty;
    defer reads.deinit(gpa);
    var init_resp: [17]u8 = undefined;
    @memcpy(init_resp[0..8], &nonce);
    std.mem.writeInt(u32, init_resp[8..12], our_cid, .big);
    init_resp[12] = 2;
    init_resp[13] = 1;
    init_resp[14] = 0;
    init_resp[15] = 0;
    init_resp[16] = InitResponse.cap_cbor;
    try pushMessage(&reads, gpa, broadcast_cid, .init, &init_resp);
    const keepalives = src.valueRangeAtMost(u8, 0, 3);
    for (0..keepalives) |_| try pushMessage(&reads, gpa, our_cid, .keepalive, &.{1});
    if (src.value(bool)) try pushMessage(&reads, gpa, our_cid ^ 0x100, .cbor, "someone else");
    const hid_err = src.valueRangeAtMost(u8, 0, 9) == 0;
    if (hid_err) try pushMessage(&reads, gpa, our_cid, .@"error", &.{0x06}) else try pushMessage(&reads, gpa, our_cid, .cbor, body);
    const damage_at: ?usize = if (src.valueRangeAtMost(u8, 0, 2) == 0) src.index(reads.items.len) else null;
    if (damage_at) |at| {
        var dmg: Packet = undefined;
        const n = fz.damage(src, &dmg, &reads.items[at]);
        @memcpy(reads.items[at][0..n], dmg[0..n]);
    }
    var fd: FakeDevice = .{ .reads = reads.items };
    var ch = Channel.open(fd.dev(), nonce) catch {
        HidMark.mark(.channel_refused);
        if (damage_at == null) return error.GenuineChannelOpenRefused;
        return;
    };
    var resp: [max_payload]u8 = undefined;
    if (ch.transact(&.{ 0x06, 0xa0 }, &resp)) |n| {
        if (damage_at == null) {
            if (hid_err) return error.HidErrorNotReported;
            if (!std.mem.eql(u8, resp[0..n], body)) return error.GenuineResponseChanged;
            HidMark.mark(.channel_ok);
            if (keepalives != 0) HidMark.mark(.channel_keepalive);
        }
    } else |_| {
        if (ch.last_hid_error != null) HidMark.mark(.channel_hid_error) else if (damage_at != null) HidMark.mark(.channel_refused);
        if (damage_at == null and !hid_err) return error.GenuineExchangeFailed;
    }
}
