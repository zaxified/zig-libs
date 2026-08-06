// SPDX-License-Identifier: MIT

//! A minimal S7 **responder**: the PLC side of the conversation, as a pure
//! function from one request packet to one reply packet.
//!
//! Its reason to exist is fleet simulation. A responder that speaks the real
//! wire format lets a whole S7 client stack — including this module's own
//! client — be exercised against hundreds of simulated CPUs with no hardware,
//! and it is what makes the round-trip tests in `root.zig` possible.
//!
//! It is deliberately **not** a PLC emulator: there is no program execution,
//! no cycle, no retentive-memory semantics. Registered areas are plain byte
//! slices the caller owns, and reads and writes hit them directly.
//!
//! `handle` takes one whole TPKT and writes one whole TPKT, so a caller can
//! drive it from any transport — or from none, which is what the tests do.

const std = @import("std");
const tpkt = @import("tpkt.zig");
const cotp = @import("cotp.zig");
const s7 = @import("s7.zig");
const items = @import("items.zig");
const vars = @import("vars.zig");
const userdata = @import("userdata.zig");

pub const Error = error{
    /// The request is not something this responder implements.
    Unsupported,
    /// The caller's output buffer is too small for the reply.
    BufferTooSmall,
} || tpkt.Error || cotp.Error || s7.Error || items.Error || vars.Error || userdata.Error;

/// One addressable memory area backed by caller-owned storage.
pub const AreaBinding = struct {
    area: items.Area,
    /// Only meaningful for `.db` / `.instance_db`.
    db_number: u16 = 0,
    bytes: []u8,
};

pub const Config = struct {
    /// PDU length this responder will agree to. The lower of this and what the
    /// client asks for wins.
    max_pdu_length: u16 = 480,
    /// Records returned for `Read SZL 0x0011` (module identification). Empty
    /// means "list not available", answered with a return code rather than a
    /// dropped connection.
    szl_0011: []const u8 = &.{},
    /// Operating mode reported through SZL `0x0424`.
    cpu_status: userdata.CpuStatus = .run,
    /// When false, PLC stop/restart requests are answered with an error class
    /// instead of being obeyed. Off by default: a simulator that silently
    /// accepts a stop teaches its operator the wrong lesson.
    allow_plc_control: bool = false,
};

/// The length field a failed data item carries. It is meaningless — there is
/// no payload behind it — but the reference CPU emits exactly `0x0004` for
/// every failed item regardless of what was asked for, and the responder
/// reproduces that so its replies are byte-identical to a real one's.
pub const error_item_length: u16 = 4;

pub const Responder = struct {
    config: Config,
    areas: []const AreaBinding,
    /// Negotiated after `Setup communication`; zero until then.
    pdu_length: u16 = 0,
    connected: bool = false,
    /// Set by a PLC control request when `allow_plc_control` is on.
    stopped: bool = false,

    pub fn init(config: Config, areas: []const AreaBinding) Responder {
        return .{ .config = config, .areas = areas };
    }

    fn find(self: *Responder, area: items.Area, db_number: u16) ?[]u8 {
        for (self.areas) |b| {
            if (b.area != area) continue;
            if ((area == .db or area == .instance_db) and b.db_number != db_number) continue;
            return b.bytes;
        }
        return null;
    }

    /// Handles one whole TPKT and writes one whole TPKT into `out`.
    /// Returns null when the request needs no reply (a disconnect).
    pub fn handle(self: *Responder, packet: []const u8, out: []u8) Error!?[]u8 {
        const pkt = try tpkt.decode(packet);
        switch (try cotp.decode(pkt.payload)) {
            .cr => |cr| {
                self.connected = true;
                var body: [64]u8 = undefined;
                // Echo the client's parameters back, which is what a real CPU
                // does and what makes the rack/slot round trip visible.
                const cc = try cotp.encodeConnect(.{
                    .code = .cc,
                    .credit = cr.credit,
                    .dst_ref = cr.src_ref,
                    .src_ref = 1,
                    .src_tsap = cr.src_tsap,
                    .dst_tsap = cr.dst_tsap,
                    .tpdu_size = cr.tpdu_size,
                }, &body);
                return try tpkt.encode(cc, out);
            },
            .dr, .dc => {
                self.connected = false;
                return null;
            },
            .dt => |dt| return try self.handleS7(dt.payload, out),
            else => return error.Unsupported,
        }
    }

    fn handleS7(self: *Responder, bytes: []const u8, out: []u8) Error!?[]u8 {
        const pdu = try s7.decode(bytes);
        return switch (pdu.header.rosctr) {
            .job => try self.handleJob(pdu, out),
            .userdata => try self.handleUserdata(pdu, out),
            else => error.Unsupported,
        };
    }

    fn handleJob(self: *Responder, pdu: s7.Pdu, out: []u8) Error!?[]u8 {
        if (pdu.parameters.len == 0) return error.Unsupported;
        const function: s7.Function = @enumFromInt(pdu.parameters[0]);
        return switch (function) {
            .setup_communication => try self.doSetup(pdu, out),
            .read_var => try self.doRead(pdu, out),
            .write_var => try self.doWrite(pdu, out),
            .plc_stop => try self.doControl(pdu, out, true),
            .pi_service => try self.doControl(pdu, out, false),
            else => try errorReply(pdu, .error_on_service_processing, 0x04, out),
        };
    }

    fn doSetup(self: *Responder, pdu: s7.Pdu, out: []u8) Error![]u8 {
        const asked = try s7.Setup.decode(pdu.parameters);
        self.pdu_length = @min(asked.pdu_length, self.config.max_pdu_length);
        var params: [s7.Setup.wire_len]u8 = undefined;
        const p = try (s7.Setup{
            .max_amq_calling = 1,
            .max_amq_called = 1,
            .pdu_length = self.pdu_length,
        }).encode(&params);
        return self.reply(pdu.header.pdu_reference, p, &.{}, out);
    }

    fn doRead(self: *Responder, pdu: s7.Pdu, out: []u8) Error![]u8 {
        const req = try vars.decodeRequest(pdu.parameters);
        var it = req.iterator();
        // Build the data block into the tail of `out` and the parameters in
        // front of it once the length is known.
        var data: [2048]u8 = undefined;
        var w = items.DataBlockWriter{ .out = &data };
        var count: u8 = 0;
        while (try it.next()) |item| {
            count += 1;
            const want = item.payloadBytes() orelse {
                try w.addError(.data_type_unsupported, error_item_length);
                continue;
            };
            // A zero element count makes the bounds guard below vacuous: `want`
            // is 0, so `start + want > store.len` is false even at
            // `start == store.len`, and the `.bit` arm then indexes
            // `store[item.byteOffset()]` one octet past the area. Refuse it up
            // front -- there is nothing to transfer either way, and with
            // `count >= 1` the guard implies `byteOffset() < store.len` for
            // every area kind (for a bit-addressed area `start == byteOffset()`;
            // for an element-addressed one `byteOffset() <= start`).
            if (item.count == 0) {
                try w.addError(.invalid_address, error_item_length);
                continue;
            }
            const store = self.find(item.area, item.db_number) orelse {
                try w.addError(.object_does_not_exist, error_item_length);
                continue;
            };
            const start: usize = if (item.area.addressesElements())
                @as(usize, item.address) * 2
            else
                item.byteOffset();
            if (start + want > store.len) {
                try w.addError(.invalid_address, error_item_length);
                continue;
            }
            const ts = if (item.transport_size == .bit)
                items.DataTransportSize.bit
            else if (item.transport_size == .real)
                items.DataTransportSize.real
            else if (item.area.addressesElements())
                items.DataTransportSize.octet_string
            else
                items.DataTransportSize.byte_word_dword;
            if (ts == .bit) {
                // One bit, reported the way a real CPU does: length 1.
                const byte = store[item.byteOffset()];
                const v: u8 = @intFromBool((byte >> item.bitOffset()) & 1 != 0);
                if (w.pos + 5 > data.len) return error.BufferTooSmall;
                data[w.pos] = @intFromEnum(items.ReturnCode.success);
                data[w.pos + 1] = @intFromEnum(items.DataTransportSize.bit);
                data[w.pos + 2] = 0;
                data[w.pos + 3] = 1;
                data[w.pos + 4] = v;
                w.pos += 5;
                w.pending_pad = true;
            } else {
                try w.add(ts, store[start..][0..want]);
            }
        }
        var params: [2]u8 = undefined;
        const p = try vars.encodeReply(.read_var, count, &params);
        return self.reply(pdu.header.pdu_reference, p, w.written(), out);
    }

    fn doWrite(self: *Responder, pdu: s7.Pdu, out: []u8) Error![]u8 {
        const req = try vars.decodeRequest(pdu.parameters);
        var it = req.iterator();
        var di = items.DataItemIterator.initRequest(pdu.data, req.count);
        var codes: [vars.max_items]u8 = undefined;
        var count: u8 = 0;
        while (try it.next()) |item| {
            const value = (try di.next()) orelse return error.ShortItem;
            const rc = self.applyWrite(item, value);
            codes[count] = @intFromEnum(rc);
            count += 1;
        }
        var params: [2]u8 = undefined;
        const p = try vars.encodeReply(.write_var, count, &params);
        return self.reply(pdu.header.pdu_reference, p, codes[0..count], out);
    }

    fn applyWrite(self: *Responder, item: items.Item, value: items.DataItem) items.ReturnCode {
        const store = self.find(item.area, item.db_number) orelse return .object_does_not_exist;
        if (item.transport_size == .bit) {
            const off = item.byteOffset();
            if (off >= store.len or value.payload.len < 1) return .invalid_address;
            const mask: u8 = @as(u8, 1) << item.bitOffset();
            if (value.payload[0] & 1 != 0) store[off] |= mask else store[off] &= ~mask;
            return .success;
        }
        const want = item.payloadBytes() orelse return .data_type_unsupported;
        const start: usize = if (item.area.addressesElements())
            @as(usize, item.address) * 2
        else
            item.byteOffset();
        if (start + want > store.len) return .invalid_address;
        if (value.payload.len < want) return .data_type_inconsistent;
        @memcpy(store[start..][0..want], value.payload[0..want]);
        return .success;
    }

    fn doControl(self: *Responder, pdu: s7.Pdu, out: []u8, is_stop: bool) Error![]u8 {
        if (!self.config.allow_plc_control) {
            return errorReply(pdu, .error_on_service_processing, 0x04, out);
        }
        self.stopped = is_stop;
        return self.reply(pdu.header.pdu_reference, pdu.parameters[0..1], &.{}, out);
    }

    fn handleUserdata(self: *Responder, pdu: s7.Pdu, out: []u8) Error![]u8 {
        const p = try userdata.Param.decode(pdu.parameters);
        if (p.function_group != .cpu_functions or
            p.subfunction != @intFromEnum(userdata.CpuSubfunction.read_szl))
        {
            return error.Unsupported;
        }
        const block = try userdata.DataBlock.decode(pdu.data);
        const req = try userdata.SzlRequest.decode(block.payload);

        var payload: [1024]u8 = undefined;
        const szl = switch (req.id) {
            userdata.SzlId.module_identification => blk: {
                if (self.config.szl_0011.len == 0) break :blk null;
                const rl: u16 = 28;
                const n: u16 = @intCast(self.config.szl_0011.len / rl);
                break :blk try userdata.SzlResponse.encode(
                    .{ .id = req.id, .index = req.index, .record_length = rl, .record_count = n },
                    self.config.szl_0011,
                    &payload,
                );
            },
            userdata.SzlId.cpu_status => blk: {
                var rec: [20]u8 = @splat(0);
                rec[0] = 0x51;
                rec[1] = 0x44;
                rec[2] = 0xFF;
                rec[userdata.cpu_status_offset] =
                    @intFromEnum(if (self.stopped) userdata.CpuStatus.stop else self.config.cpu_status);
                break :blk try userdata.SzlResponse.encode(
                    .{ .id = req.id, .index = req.index, .record_length = 20, .record_count = 1 },
                    &rec,
                    &payload,
                );
            },
            else => null,
        };

        var params: [userdata.Param.response_len]u8 = undefined;
        const rp = try (userdata.Param{
            .message_type = .response,
            .function_group = .cpu_functions,
            .subfunction = p.subfunction,
            .sequence = p.sequence,
            .last_data_unit = .no_more,
            .error_code = if (szl == null) 0xD401 else 0,
        }).encodeResponse(&params);

        var data: [1040]u8 = undefined;
        const db = if (szl) |s|
            try userdata.DataBlock.encode(.success, .octet_string, s, &data)
        else
            try userdata.DataBlock.encode(.object_does_not_exist, .null_size, &.{}, &data);

        return self.frame(.userdata, pdu.header.pdu_reference, rp, db, out, false);
    }

    fn reply(self: *Responder, pdu_ref: u16, params: []const u8, data: []const u8, out: []u8) Error![]u8 {
        return self.frame(.ack_data, pdu_ref, params, data, out, true);
    }

    fn errorReply(pdu: s7.Pdu, class: s7.ErrorClass, code: u8, out: []u8) Error![]u8 {
        var body: [512]u8 = undefined;
        const enc = try s7.encode(.{
            .rosctr = .ack_data,
            .pdu_reference = pdu.header.pdu_reference,
            .error_class = class,
            .error_code = code,
        }, &.{}, &.{}, &body);
        return try wrap(enc, out);
    }

    fn frame(
        self: *Responder,
        rosctr: s7.Rosctr,
        pdu_ref: u16,
        params: []const u8,
        data: []const u8,
        out: []u8,
        check_pdu: bool,
    ) Error![]u8 {
        var body: [2048]u8 = undefined;
        const enc = try s7.encode(
            .{ .rosctr = rosctr, .pdu_reference = pdu_ref },
            params,
            data,
            &body,
        );
        if (check_pdu and self.pdu_length != 0 and enc.len > self.pdu_length) {
            return error.BufferTooSmall;
        }
        return try wrap(enc, out);
    }

    fn wrap(pdu: []const u8, out: []u8) Error![]u8 {
        if (out.len < tpkt.header_len + 3 + pdu.len) return error.BufferTooSmall;
        const dh = cotp.dataHeader(0, true);
        @memcpy(out[tpkt.header_len..][0..3], &dh);
        @memcpy(out[tpkt.header_len + 3 ..][0..pdu.len], pdu);
        const total = tpkt.header_len + 3 + pdu.len;
        const th = try tpkt.header(total - tpkt.header_len);
        @memcpy(out[0..tpkt.header_len], &th);
        return out[0..total];
    }
};

// ── tests ───────────────────────────────────────────────────────────────────

const testing = std.testing;

fn hex(comptime s: []const u8, out: []u8) []const u8 {
    return std.fmt.hexToBytes(out, s) catch unreachable;
}

test "the responder answers the reference client's CR with a CC echoing the TSAPs" {
    var db: [64]u8 = @splat(0);
    var areas = [_]AreaBinding{.{ .area = .db, .db_number = 1, .bytes = &db }};
    var r = Responder.init(.{}, &areas);
    var in: [64]u8 = undefined;
    var out: [64]u8 = undefined;
    const cr = hex("0300001611e00000000100c0010ac1020100c2020122", &in);
    const cc = (try r.handle(cr, &out)).?;
    // Rack 1 slot 2 comes back untouched: 0x0122.
    try testing.expectEqualSlices(u8, &[_]u8{ 0xC2, 0x02, 0x01, 0x22 }, cc[18..22]);
    try testing.expectEqual(@as(u8, 0xD0), cc[5]);
}

test "setup negotiates down to the responder's ceiling" {
    var db: [64]u8 = @splat(0);
    var areas = [_]AreaBinding{.{ .area = .db, .db_number = 1, .bytes = &db }};
    var r = Responder.init(.{ .max_pdu_length = 240 }, &areas);
    var in: [64]u8 = undefined;
    var out: [64]u8 = undefined;
    const req = hex("0300001902f08032010000000100080000f0000001000101e0", &in);
    const rep = (try r.handle(req, &out)).?;
    try testing.expectEqual(@as(u16, 240), r.pdu_length);
    // f0 00 0001 0001 00f0
    try testing.expectEqualSlices(u8, &[_]u8{ 0xF0, 0x00, 0x00, 0x01, 0x00, 0x01, 0x00, 0xF0 }, rep[19..27]);
}

test "read and write hit the registered area" {
    var db: [64]u8 = @splat(0);
    var areas = [_]AreaBinding{.{ .area = .db, .db_number = 1, .bytes = &db }};
    var r = Responder.init(.{}, &areas);
    var in: [128]u8 = undefined;
    var out: [128]u8 = undefined;
    _ = try r.handle(hex("0300001902f08032010000000100080000f0000001000101e0", &in), &out);

    // Write 12345678 to DB1.DBB20 — the reference client's exact request.
    const wreq = hex("0300002702f080320100000200000e00080501120a100200040001840000a0" ++
        "0004002012345678", &in);
    const wrep = (try r.handle(wreq, &out)).?;
    try testing.expectEqual(@as(u8, 0xFF), wrep[wrep.len - 1]);
    try testing.expectEqualSlices(u8, &[_]u8{ 0x12, 0x34, 0x56, 0x78 }, db[20..24]);

    // Read it back.
    const rreq = hex("0300001f02f080320100000300000e00000401120a100200040001840000a0", &in);
    const rrep = (try r.handle(rreq, &out)).?;
    try testing.expectEqualSlices(u8, &[_]u8{ 0xFF, 0x04, 0x00, 0x20, 0x12, 0x34, 0x56, 0x78 }, rrep[21..]);
}

test "a read of a DB that is not registered gets the object-does-not-exist code" {
    var db: [64]u8 = @splat(0);
    var areas = [_]AreaBinding{.{ .area = .db, .db_number = 1, .bytes = &db }};
    var r = Responder.init(.{}, &areas);
    var in: [128]u8 = undefined;
    var out: [128]u8 = undefined;
    _ = try r.handle(hex("0300001902f08032010000000100080000f0000001000101e0", &in), &out);
    // DB 77.
    const req = hex("0300001f02f080320100000200000e00000401120a10020004004d84000000", &in);
    const rep = (try r.handle(req, &out)).?;
    try testing.expectEqual(@as(u8, 0x0A), rep[21]);
    // An address past the end of a registered DB.
    const oob = hex("0300001f02f080320100000300000e00000401120a100200200001840007d0", &in);
    const rep2 = (try r.handle(oob, &out)).?;
    try testing.expectEqual(@as(u8, 0x05), rep2[21]);
}

test "bit read and write" {
    var flags: [16]u8 = @splat(0);
    var areas = [_]AreaBinding{.{ .area = .flags, .bytes = &flags }};
    var r = Responder.init(.{}, &areas);
    var in: [128]u8 = undefined;
    var out: [128]u8 = undefined;
    _ = try r.handle(hex("0300001902f08032010000000100080000f0000001000101e0", &in), &out);
    // Set M10.2.
    const w = hex("0300002402f080320100000200000e00050501120a100100010000830000520003000101", &in);
    _ = try r.handle(w, &out);
    try testing.expectEqual(@as(u8, 0x04), flags[10]);
    // Read it back: the reply must be `ff 03 0001 01`.
    const rd = hex("0300001f02f080320100000300000e00000401120a10010001000083000052", &in);
    const rep = (try r.handle(rd, &out)).?;
    try testing.expectEqualSlices(u8, &[_]u8{ 0xFF, 0x03, 0x00, 0x01, 0x01 }, rep[21..]);
}

test "PLC control is refused unless explicitly enabled" {
    var db: [16]u8 = @splat(0);
    var areas = [_]AreaBinding{.{ .area = .db, .db_number = 1, .bytes = &db }};
    var r = Responder.init(.{}, &areas);
    var setup_buf: [64]u8 = undefined;
    var stop_buf: [64]u8 = undefined;
    var out: [128]u8 = undefined;
    const setup_req = hex("0300001902f08032010000000100080000f0000001000101e0", &setup_buf);
    const stop = hex("0300002102f0803201000002000010000029000000000009505f50524f4752414d", &stop_buf);
    _ = try r.handle(setup_req, &out);
    const rep = (try r.handle(stop, &out)).?;
    // Ack-Data with an error class, and the CPU is still running.
    try testing.expectEqual(@as(u8, 0x84), rep[17]);
    try testing.expect(!r.stopped);

    var r2 = Responder.init(.{ .allow_plc_control = true }, &areas);
    _ = try r2.handle(setup_req, &out);
    const rep2 = (try r2.handle(stop, &out)).?;
    try testing.expectEqual(@as(u8, 0x29), rep2[19]);
    try testing.expect(r2.stopped);
}

test "an unrecognized job function code gets a typed error reply, not silence" {
    // handleJob's `else` arm (unrecognized/unimplemented function code) had
    // no test at all -- only the *specific* function codes' own error paths
    // (e.g. PLC control refused) were covered. Built from the "PLC stop"
    // frame above with its function-code octet (0x29) replaced by 0xAA,
    // which is not one of `s7.Function`'s named values.
    var db: [16]u8 = @splat(0);
    var areas = [_]AreaBinding{.{ .area = .db, .db_number = 1, .bytes = &db }};
    var r = Responder.init(.{}, &areas);
    var setup_buf: [64]u8 = undefined;
    var bad_buf: [64]u8 = undefined;
    var out: [128]u8 = undefined;
    const setup_req = hex("0300001902f08032010000000100080000f0000001000101e0", &setup_buf);
    const bad = hex("0300002102f08032010000020000100000aa000000000009505f50524f4752414d", &bad_buf);
    _ = try r.handle(setup_req, &out);
    const rep = (try r.handle(bad, &out)).?;
    // Ack-Data (rosctr) with error_class = error_on_service_processing (0x84)
    // and error_code = 0x04, same shape as the refused-PLC-control reply.
    try testing.expectEqual(@as(u8, 0x84), rep[17]);
    try testing.expectEqual(@as(u8, 0x04), rep[18]);
}

test "read SZL 0x0424 reflects the configured and the stopped state" {
    var db: [16]u8 = @splat(0);
    var areas = [_]AreaBinding{.{ .area = .db, .db_number = 1, .bytes = &db }};
    var r = Responder.init(.{ .allow_plc_control = true }, &areas);
    var setup_buf: [64]u8 = undefined;
    var szl_buf: [64]u8 = undefined;
    var out: [256]u8 = undefined;
    _ = try r.handle(hex("0300001902f08032010000000100080000f0000001000101e0", &setup_buf), &out);
    const szl = hex("0300002102f080320700000200000800080001120411440100ff09000404240000", &szl_buf);
    const rep = (try r.handle(szl, &out)).?;
    const pdu = try s7.decode((try cotp.decode((try tpkt.decode(rep)).payload)).dt.payload);
    const block = try userdata.DataBlock.decode(pdu.data);
    const resp = try userdata.SzlResponse.decode(block.payload);
    try testing.expectEqual(userdata.CpuStatus.run, userdata.cpuStatusFrom(resp).?);

    r.stopped = true;
    const rep2 = (try r.handle(szl, &out)).?;
    const pdu2 = try s7.decode((try cotp.decode((try tpkt.decode(rep2)).payload)).dt.payload);
    const resp2 = try userdata.SzlResponse.decode((try userdata.DataBlock.decode(pdu2.data)).payload);
    try testing.expectEqual(userdata.CpuStatus.stop, userdata.cpuStatusFrom(resp2).?);
}

test "a Read Var item with count 0 on the bit path does not index past the area" {
    // Regression, wave-2 W2-02. `payloadBytes()` returns `(count + 7) / 8`, so a
    // `.bit` item with `count == 0` wants ZERO octets and the guard
    // `start + want > store.len` is satisfied at `start == store.len` -- after
    // which the `.bit` arm unconditionally read `store[item.byteOffset()]`, one
    // past the end. Wire-controlled and unauthenticated: S7 has no
    // authentication at all, and `doRead` does not require `Setup
    // communication` to have run first, so this frame is the whole attack.
    //
    // The item is `12 0a 10 01 0000 0001 84 000200`: S7ANY, transport size
    // `bit` (0x01), count 0, DB 1, area DB, bit address 0x200 = byte 64 -- one
    // past a 64-octet DB.
    //
    // (The audit's evidence line quotes this frame with a TPKT length octet of
    // `0x2b` and calls it "43 octets". That is wrong on both counts and the
    // frame as printed would have been refused by `tpkt.decode`, whose
    // `total > buf.len` check bites: the frame is 31 octets and its length
    // field is `0x1f`. The item bytes -- the part that carries the defect --
    // are exactly as the audit recorded them.)
    var db: [64]u8 = @splat(0);
    var areas = [_]AreaBinding{.{ .area = .db, .db_number = 1, .bytes = &db }};
    var r = Responder.init(.{}, &areas);
    var in: [64]u8 = undefined;
    var out: [128]u8 = undefined;
    const req = hex("0300001f" ++ "02f080" ++ "320100000001000e0000" ++ "0401" ++
        "120a1001" ++ "0000" ++ "0001" ++ "84" ++ "000200", &in);
    const rep = (try r.handle(req, &out)).?;
    // A refusal, not a payload: the item must come back as a four-octet error
    // entry (`rc, null_size, 00 04`) rather than a success item carrying a byte
    // that was never inside the area.
    try testing.expectEqualSlices(
        u8,
        &[_]u8{ @intFromEnum(items.ReturnCode.invalid_address), 0x00, 0x00, 0x04 },
        rep[21..],
    );
}

test "fuzz: the responder never panics on hostile requests inside a well-formed envelope" {
    try std.testing.fuzz({}, fuzzHandle, .{});
}

// ── the structure-aware responder harness ───────────────────────────────────
//
// The previous version of this harness fed `smith.bytes()` straight into
// `handle`. That looked like coverage of the responder and was coverage of the
// framing layer only: before control can reach `doRead`, an input has to
// satisfy TPKT (`03 00`, a self-consistent length), COTP (LI, code, class 0),
// the S7 header (`0x32`, a known ROSCTR, and `parameter_length + data_length`
// matching the frame **exactly**), a Read/Write Var function octet and a
// `12 0a 10` S7ANY descriptor whose item count matches the octets present.
// Uniform random bytes clear that with probability ~0 — a 400 s
// coverage-guided run never got past `cotp` — so `doRead`, `doWrite`,
// `applyWrite` and `handleUserdata` had no fuzz coverage at all, and the
// out-of-bounds read in `doRead` (regression test above) sat one well-formed
// packet away from a harness that could never build one.
//
// So the envelope is **built** here rather than guessed, and the fuzzer's
// entropy is spent where the responder makes decisions: the item descriptors
// (transport size, element count, DB number, area, address) and the write
// data block (declared length vs. payload actually present). The framing
// layer keeps its own raw-byte harnesses in `tpkt.zig`, `cotp.zig`, `s7.zig`,
// `vars.zig` and `items.zig`, so nothing is given up by specialising this one.

/// Areas the responder can be asked about: two of them are registered below,
/// the rest must come back as a return code rather than a crash. `counter` and
/// `timer` are in the list because they are the two areas whose address counts
/// elements rather than bits, which is a second address-arithmetic path.
const fuzz_areas = [_]u8{ 0x1C, 0x1D, 0x80, 0x81, 0x82, 0x83, 0x84, 0x85, 0x86, 0x87 };

/// The two areas the harness actually registers. Drawn from more often than
/// the full list: an item naming an unregistered area is answered from
/// `find`'s `orelse` arm and never reaches the address arithmetic at all, so
/// spreading the draw uniformly over ten areas spends 80% of the budget on one
/// early return.
const fuzz_bound_areas = [_]u8{ 0x83, 0x84 };

/// Every named request transport size, `bit` (0x01) included — it is the one
/// whose payload length is counted in bits and therefore rounds, which is what
/// made a zero element count degenerate.
const fuzz_sizes = [_]u8{ 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0F, 0x1C, 0x1D, 0x1E, 0x1F, 0x20 };

/// The sizes a real client actually asks for, weighted up for the same reason.
const fuzz_common_sizes = [_]u8{ 0x01, 0x02, 0x04, 0x05, 0x06, 0x07, 0x08 };

/// Data-block transport sizes, including `null_size` and unknown-to-us values.
const fuzz_data_sizes = [_]u8{ 0x00, 0x03, 0x04, 0x05, 0x06, 0x07, 0x09 };

/// Writes one 12-octet S7ANY item descriptor. The three-octet prefix is fixed
/// because a wrong one is rejected by `items.Item.decode` before the responder
/// ever sees the item — that refusal is `items.zig`'s harness's job, not this
/// one's.
fn fuzzItemBytes(smith: *std.testing.Smith, out: *[12]u8) void {
    out[0] = 0x12;
    out[1] = 0x0A;
    out[2] = 0x10;
    out[3] = switch (smith.valueRangeAtMost(u8, 0, 9)) {
        0...5 => fuzz_common_sizes[smith.index(fuzz_common_sizes.len)],
        6...8 => fuzz_sizes[smith.index(fuzz_sizes.len)],
        else => smith.value(u8),
    };
    // Biased small: that is the region where an item is *accepted* and the
    // bounds arithmetic is what decides the outcome. Zero is deliberately in
    // range — a zero count makes `payloadBytes()` zero for every size.
    const count: u16 = switch (smith.valueRangeAtMost(u8, 0, 9)) {
        0...5 => smith.valueRangeAtMost(u16, 0, 8),
        6...8 => smith.valueRangeAtMost(u16, 0, 64),
        else => smith.value(u16),
    };
    out[4] = @intCast(count >> 8);
    out[5] = @truncate(count);
    // DB 1 is registered; 0 and 2 are not.
    const db: u16 = smith.valueRangeAtMost(u16, 0, 2);
    out[6] = @intCast(db >> 8);
    out[7] = @truncate(db);
    out[8] = if (smith.boolWeighted(2, 3))
        fuzz_bound_areas[smith.index(fuzz_bound_areas.len)]
    else
        fuzz_areas[smith.index(fuzz_areas.len)];
    // The address is generated the way a client writes one -- a byte offset
    // plus a bit index -- rather than as a raw 24-bit number, and the byte
    // offset is drawn from a range that straddles the end of both 64-octet
    // areas. Uniform over 2^24 the boundary is never hit; uniform over the
    // wire encoding it is hit only by accident.
    const addr: u24 = switch (smith.valueRangeAtMost(u8, 0, 9)) {
        0...6 => @as(u24, smith.valueRangeAtMost(u8, 0, 80)) * 8 + smith.valueRangeAtMost(u8, 0, 7),
        7...8 => smith.valueRangeAtMost(u24, 0, 4096),
        else => smith.value(u24),
    };
    out[9] = @intCast((addr >> 16) & 0xFF);
    out[10] = @intCast((addr >> 8) & 0xFF);
    out[11] = @truncate(addr);
}

/// Appends one Write Var request data item at `pos`, returning the new
/// position. The declared length is usually the honest one — otherwise the
/// data-block iterator rejects the frame before `applyWrite` runs and the
/// whole request is wasted — but sometimes a lie, which is the case
/// `applyWrite`'s own `value.payload.len < want` guard exists for.
fn fuzzWriteValue(smith: *std.testing.Smith, data: []u8, pos: usize, last: bool) ?usize {
    const ts: items.DataTransportSize = @enumFromInt(fuzz_data_sizes[smith.index(fuzz_data_sizes.len)]);
    const n: usize = smith.valueRangeAtMost(u8, 0, 32);
    const honest = items.encodeLength(ts, n) catch return null;
    const raw: u16 = if (smith.boolWeighted(7, 1)) honest else smith.value(u16);
    if (pos + 4 + n > data.len) return null;
    data[pos] = 0x00; // a request item's return-code octet is `reserved`
    data[pos + 1] = @intFromEnum(ts);
    data[pos + 2] = @intCast(raw >> 8);
    data[pos + 3] = @truncate(raw);
    smith.bytes(data[pos + 4 ..][0..n]);
    var p = pos + 4 + n;
    if (n % 2 == 1 and !last) {
        if (p >= data.len) return null;
        data[p] = 0x00;
        p += 1;
    }
    return p;
}

/// Wraps `params` / `data` in a correct COTP-DT + TPKT envelope and an S7
/// header whose two length fields agree with what follows, which is what
/// `s7.decode` insists on.
fn fuzzEnvelope(rosctr: u8, params: []const u8, data: []const u8, out: []u8) ?[]const u8 {
    const total = tpkt.header_len + 3 + 10 + params.len + data.len;
    if (total > out.len or total > 0xFFFF) return null;
    out[0] = 0x03;
    out[1] = 0x00;
    out[2] = @intCast(total >> 8);
    out[3] = @truncate(total);
    out[4] = 0x02; // COTP LI
    out[5] = 0xF0; // DT
    out[6] = 0x80; // TPDU number 0, EOT
    out[7] = 0x32; // S7 protocol id
    out[8] = rosctr;
    out[9] = 0x00; // redundancy identification
    out[10] = 0x00;
    out[11] = 0x00; // PDU reference
    out[12] = 0x01;
    out[13] = @intCast(params.len >> 8);
    out[14] = @truncate(params.len);
    out[15] = @intCast(data.len >> 8);
    out[16] = @truncate(data.len);
    @memcpy(out[17..][0..params.len], params);
    @memcpy(out[17 + params.len ..][0..data.len], data);
    return out[0..total];
}

/// Builds one request. Returns null when this draw could not be assembled, in
/// which case the caller simply moves on.
fn fuzzRequest(smith: *std.testing.Smith, out: []u8) ?[]const u8 {
    var params: [320]u8 = undefined;
    var data: [640]u8 = undefined;
    var plen: usize = 0;
    var dlen: usize = 0;
    var rosctr: u8 = 0x01; // job

    // Read Var is drawn most often: it is the request with the most
    // wire-controlled arithmetic behind it, and the only one that can be sent
    // with no prior exchange at all.
    switch (smith.valueRangeAtMost(u8, 0, 9)) {
        // Setup communication: the negotiated PDU length gates every reply.
        0 => {
            const asked = if (smith.boolWeighted(3, 1))
                smith.valueRangeAtMost(u16, 0, 960)
            else
                smith.value(u16);
            params[0] = 0xF0;
            params[1] = 0x00;
            params[2] = 0x00;
            params[3] = 0x01;
            params[4] = 0x00;
            params[5] = 0x01;
            params[6] = @intCast(asked >> 8);
            params[7] = @truncate(asked);
            plen = 8;
        },
        // Read Var / Write Var.
        1...6 => |k| {
            const func: u8 = if (k >= 5) 0x05 else 0x04;
            const n: u8 = smith.valueRangeAtMost(u8, 1, 12);
            params[0] = func;
            params[1] = n;
            plen = 2;
            var i: u8 = 0;
            while (i < n) : (i += 1) {
                fuzzItemBytes(smith, params[plen..][0..12]);
                plen += 12;
            }
            if (func == 0x05) {
                i = 0;
                while (i < n) : (i += 1) {
                    dlen = fuzzWriteValue(smith, &data, dlen, i + 1 == n) orelse break;
                }
            }
        },
        // PLC control, and — via an arbitrary function octet — `handleJob`'s
        // unrecognised-function arm.
        7 => {
            params[0] = if (smith.boolWeighted(2, 1))
                (if (smith.value(bool)) @as(u8, 0x29) else 0x28)
            else
                smith.value(u8);
            const tail: usize = smith.valueRangeAtMost(u8, 0, 24);
            smith.bytes(params[1..][0..tail]);
            plen = 1 + tail;
        },
        // Userdata / Read SZL.
        else => {
            rosctr = 0x07;
            const p = (userdata.Param{
                .message_type = @enumFromInt(@as(u4, @truncate(if (smith.boolWeighted(7, 1)) @as(u8, 0) else smith.value(u8)))),
                .function_group = @enumFromInt(@as(u4, @truncate(if (smith.boolWeighted(7, 1)) @as(u8, 4) else smith.value(u8)))),
                .subfunction = if (smith.boolWeighted(7, 1)) 0x01 else smith.value(u8),
            }).encodeRequest(&params) catch return null;
            plen = p.len;
            var payload: [32]u8 = undefined;
            const n: usize = smith.valueRangeAtMost(u8, 0, 8);
            smith.bytes(payload[0..n]);
            if (n >= 2 and smith.boolWeighted(3, 1)) {
                // Steer the list id onto one the responder implements.
                const known = [_]u16{ 0x0011, 0x0424 };
                const id = known[smith.index(known.len)];
                payload[0] = @intCast(id >> 8);
                payload[1] = @truncate(id);
            }
            const db = userdata.DataBlock.encode(
                @enumFromInt(0xFF),
                @enumFromInt(0x09),
                payload[0..n],
                &data,
            ) catch return null;
            dlen = db.len;
        },
    }
    return fuzzEnvelope(rosctr, params[0..plen], data[0..dlen], out);
}

fn fuzzHandle(_: void, smith: *std.testing.Smith) !void {
    var storage: [128]u8 = @splat(0);
    var areas = [_]AreaBinding{
        .{ .area = .db, .db_number = 1, .bytes = storage[0..64] },
        .{ .area = .flags, .bytes = storage[64..] },
    };
    var szl: [56]u8 = @splat(0x5A);
    var r = Responder.init(
        .{ .allow_plc_control = true, .szl_0011 = &szl },
        &areas,
    );
    var frame_buf: [1024]u8 = undefined;
    var out: [2048]u8 = undefined;
    // Several requests down one connection: `pdu_length` and `stopped` carry
    // across, so a state a single packet cannot reach is still reachable.
    var n: usize = 0;
    while (n < 4) : (n += 1) {
        const frame = fuzzRequest(smith, &frame_buf) orelse continue;
        _ = r.handle(frame, &out) catch continue;
    }
}
