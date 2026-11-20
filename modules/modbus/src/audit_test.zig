// SPDX-License-Identifier: MIT

//! Tests added by the whole-module mutation audit: each pins down
//! a boundary, a length check, a counter or a side effect that no earlier test
//! observed (see SPEC.md "Audit (whole-module mutation)").

const std = @import("std");
const mb = @import("root.zig");
const srv = @import("server.zig");

const testing = std.testing;
const Server = srv.Server;

fn call(s: *Server, request: []const u8, out: *[mb.max_pdu_len]u8) ![]u8 {
    @memset(out, 0xEE); // a reply byte the handler forgot to write stays visible
    return s.handlePdu(request, out);
}

fn expectExc(reply: []const u8, fc: u8, code: u8) !void {
    try testing.expectEqualSlices(u8, &.{ fc | 0x80, code }, reply);
}

// ── encoders: buffer exactly one byte short ────────────────────────────────

test "audit: every encoder rejects a buffer one byte short and fills an exact one" {
    var big: [300]u8 = undefined;
    try testing.expectError(error.BufferTooSmall, mb.pdu.encodeReadRequest(big[0..4], .read_coils, 0, 1));
    try testing.expectEqual(@as(usize, 5), (try mb.pdu.encodeReadRequest(big[0..5], .read_coils, 0, 1)).len);
    try testing.expectError(error.BufferTooSmall, mb.pdu.encodeWriteSingleCoil(big[0..4], 0, true));
    try testing.expectEqual(@as(usize, 5), (try mb.pdu.encodeWriteSingleCoil(big[0..5], 0, true)).len);
    try testing.expectError(error.BufferTooSmall, mb.pdu.encodeWriteSingleRegister(big[0..4], 0, 1));
    try testing.expectEqual(@as(usize, 5), (try mb.pdu.encodeWriteSingleRegister(big[0..5], 0, 1)).len);
    const bits = @as([9]bool, @splat(true)); // 2 data bytes: 8 bytes in all
    try testing.expectError(error.BufferTooSmall, mb.pdu.encodeWriteMultipleCoils(big[0..7], 0, &bits));
    try testing.expectEqual(@as(usize, 8), (try mb.pdu.encodeWriteMultipleCoils(big[0..8], 0, &bits)).len);
    const regs = [_]u16{ 1, 2, 3 }; // 12 bytes
    try testing.expectError(error.BufferTooSmall, mb.pdu.encodeWriteMultipleRegisters(big[0..11], 0, &regs));
    try testing.expectEqual(@as(usize, 12), (try mb.pdu.encodeWriteMultipleRegisters(big[0..12], 0, &regs)).len);
    const w2 = [_]u16{ 1, 2 }; // 14 bytes
    try testing.expectError(error.BufferTooSmall, mb.pdu.encodeReadWriteMultipleRegisters(big[0..13], 0, 1, 0, &w2));
    try testing.expectEqual(@as(usize, 14), (try mb.pdu.encodeReadWriteMultipleRegisters(big[0..14], 0, 1, 0, &w2)).len);
    try testing.expectError(error.BufferTooSmall, mb.pdu.encodeMaskWriteRegister(big[0..6], 0, 0, 0));
    try testing.expectEqual(@as(usize, 7), (try mb.pdu.encodeMaskWriteRegister(big[0..7], 0, 0, 0)).len);
    try testing.expectError(error.BufferTooSmall, mb.device_id.encodeRequest(big[0..3], .basic, 0));
    try testing.expectEqual(@as(usize, 4), (try mb.device_id.encodeRequest(big[0..4], .basic, 0)).len);
}

test "audit: ADU encoders and decoders at their size edges" {
    var buf: [300]u8 = undefined;
    const pdu253 = @as([253]u8, @splat(0x03));
    // tcp
    try testing.expectError(error.PduTooLong, mb.tcp.encodeAdu(&buf, 1, 1, &.{}));
    try testing.expectError(error.PduTooLong, mb.tcp.encodeAdu(&buf, 1, 1, buf[0..254]));
    try testing.expectError(error.BufferTooSmall, mb.tcp.encodeAdu(buf[0..259], 1, 1, &pdu253));
    const t = try mb.tcp.encodeAdu(buf[0..260], 1, 1, &pdu253);
    try testing.expectEqual(@as(usize, 260), t.len);
    var copy: [260]u8 = undefined;
    @memcpy(&copy, t);
    const f = try mb.tcp.decodeAdu(&copy);
    try testing.expectEqual(@as(usize, 253), f.pdu.len);
    // rtu
    try testing.expectError(error.PduTooLong, mb.rtu.encodeAdu(&buf, 1, &.{}));
    try testing.expectError(error.PduTooLong, mb.rtu.encodeAdu(&buf, 1, buf[0..254]));
    try testing.expectError(error.BufferTooSmall, mb.rtu.encodeAdu(buf[0..255], 1, &pdu253));
    const r = try mb.rtu.encodeAdu(buf[0..256], 1, &pdu253);
    try testing.expectEqual(@as(usize, 256), r.len);
    const rf = try mb.rtu.decodeAdu(r);
    try testing.expectEqual(@as(usize, 253), rf.pdu.len);
    // a one-byte PDU is the smallest frame of both kinds
    try testing.expectEqual(@as(usize, 8), (try mb.tcp.encodeAdu(&buf, 1, 1, &.{0x07})).len);
    try testing.expectEqual(@as(usize, 4), (try mb.rtu.encodeAdu(&buf, 1, &.{0x07})).len);
}

// ── response parsers: trailing bytes and echoes ────────────────────────────

test "audit: response parsers reject a longer payload and a wrong echo" {
    try testing.expectError(error.MalformedResponse, mb.pdu.parseMaskWriteResponse(&.{ 0x16, 0, 4, 0, 0xF2, 0, 0x25, 0 }, 4, 0xF2, 0x25));
    var bits: [3]bool = undefined;
    // correct length, wrong byte count
    try testing.expectError(error.MalformedResponse, mb.pdu.parseReadBitsResponse(&.{ 0x01, 2, 0x05 }, .read_coils, &bits));
    // correct byte count, wrong length (one byte missing / one extra)
    try testing.expectError(error.MalformedResponse, mb.pdu.parseReadBitsResponse(&.{ 0x01, 1 }, .read_coils, &bits));
    try testing.expectError(error.MalformedResponse, mb.pdu.parseReadBitsResponse(&.{ 0x01, 1, 0x05, 0 }, .read_coils, &bits));
    try mb.pdu.parseReadBitsResponse(&.{ 0x01, 1, 0x05 }, .read_coils, &bits);
    var regs: [2]u16 = undefined;
    try testing.expectError(error.MalformedResponse, mb.pdu.parseReadRegistersResponse(&.{ 0x03, 2, 0, 1, 0, 2 }, .read_holding_registers, &regs));
    try testing.expectError(error.MalformedResponse, mb.pdu.parseReadRegistersResponse(&.{ 0x03, 4, 0, 1, 0, 2, 0 }, .read_holding_registers, &regs));
    try testing.expectError(error.MalformedResponse, mb.pdu.parseWriteSingleResponse(&.{ 0x06, 0, 1, 0, 2, 0 }, .write_single_register, 1, 2));
    try testing.expectError(error.MalformedResponse, mb.pdu.parseWriteSingleResponse(&.{ 0x06, 0, 1, 0, 3 }, .write_single_register, 1, 2));
    try testing.expectError(error.MalformedResponse, mb.pdu.parseWriteMultipleResponse(&.{ 0x10, 0, 1, 0, 2, 0 }, .write_multiple_registers, 1, 2));
    try testing.expectError(error.MalformedResponse, mb.pdu.parseWriteMultipleResponse(&.{ 0x10, 0, 9, 0, 2 }, .write_multiple_registers, 1, 2));
}

test "audit: the object iterator stops at an object that overruns the data" {
    const It = mb.device_id.Response.Iterator;
    var it: It = .{ .data = &.{ 0x00, 0x05, 'a', 'b' } }; // claims 5 value bytes, holds 2
    try testing.expect(it.next() == null);
    var ok: It = .{ .data = &.{ 0x00, 0x02, 'a', 'b' } }; // ends exactly at the data
    const o = ok.next().?;
    try testing.expectEqual(@as(u8, 0), o.id);
    try testing.expectEqualSlices(u8, "ab", o.value);
    try testing.expect(ok.next() == null);
}

// ── Transport seam ─────────────────────────────────────────────────────────

const FixedTransport = struct {
    n: usize,
    fn ex(ctx: *anyopaque, request: []const u8, reply_buf: []u8) mb.TransportError!usize {
        _ = request;
        const self: *FixedTransport = @ptrCast(@alignCast(ctx));
        @memset(reply_buf, 0x11);
        return self.n;
    }
};

test "audit: Transport.exchange rejects a length beyond the buffer and accepts the whole buffer" {
    var ft: FixedTransport = .{ .n = 11 };
    const t: mb.Transport = .{ .ctx = &ft, .exchangeFn = FixedTransport.ex };
    var buf: [10]u8 = undefined;
    try testing.expectError(error.TransportFailed, t.exchange(&.{1}, &buf));
    ft.n = 10;
    try testing.expectEqual(@as(usize, 10), (try t.exchange(&.{1}, &buf)).len);
    ft.n = 0;
    try testing.expectEqual(@as(usize, 0), (try t.exchange(&.{1}, &buf)).len);
}

// ── RtuStream ──────────────────────────────────────────────────────────────

test "audit: RtuStream.feed reuses the room of frames already handed out" {
    var st = mb.RtuStream.init(.request);
    var adu: [8]u8 = undefined;
    const frame = try mb.rtu.encodeAdu(&adu, 7, &.{ 0x06, 0, 1, 0, 2 });
    var fill: [256]u8 = undefined;
    @memcpy(fill[0..8], frame);
    @memset(fill[8..], 0xFF); // 0xFF as a function code: garbage
    try testing.expectEqual(@as(usize, 256), st.feed(&fill));
    const f = st.next().?;
    try testing.expectEqual(@as(u8, 7), f.unit);
    // the 8 handed-out bytes are free again, and feed must say so
    try testing.expectEqual(@as(usize, 8), st.feed(&adu));
}

test "audit: RtuStream drops a bad function code as soon as two bytes are seen" {
    var st = mb.RtuStream.init(.request);
    try testing.expectEqual(@as(usize, 2), st.feed(&.{ 0x01, 0x99 }));
    try testing.expect(st.next() == null);
    try testing.expectEqual(@as(u64, 1), st.discarded);
}

test "audit: RtuStream drops an impossible length instead of waiting for it" {
    var adu: [8]u8 = undefined;
    // unit 0x99: read as a function code by the byte before it, that is an exception frame
    // whose CRC fails, never a long frame that would make the scan wait
    const good = try mb.rtu.encodeAdu(&adu, 0x99, &.{ 0x06, 0, 1, 0, 2 });
    // FC 0x18 response claiming 0xFFF0 bytes: no frame can be that long
    {
        var st = mb.RtuStream.init(.response);
        try testing.expectEqual(@as(usize, 4), st.feed(&.{ 0x01, 0x18, 0xFF, 0xF0 }));
        try testing.expectEqual(@as(usize, 8), st.feed(good));
        const f = st.next().?;
        try testing.expectEqual(@as(u8, 0x99), f.unit);
        try testing.expect(st.next() == null);
    }
    // FC 0x2B response whose second object would end beyond 256 bytes
    {
        var st = mb.RtuStream.init(.response);
        var head: [8 + 242 + 2]u8 = undefined;
        head[0] = 0x01;
        head[1] = 0x2B;
        head[2] = 0x0E;
        head[3] = 0x01;
        head[4] = 0x83;
        head[5] = 0x00;
        head[6] = 0x00;
        head[7] = 0x05; // five objects
        head[8] = 0x00; // object 0: 240 value bytes
        head[9] = 0xF0;
        @memset(head[10..250], 0xA5);
        head[250] = 0xC1; // object 1 header: another 240 bytes announced
        head[251] = 0xF0;
        try testing.expectEqual(@as(usize, 252), st.feed(head[0..252]));
        // decided at once: the second object cannot end inside a frame, so the
        // scan moves on instead of waiting for bytes that cannot complete it
        try testing.expect(st.next() == null);
        try testing.expect(st.discarded > 200);
        try testing.expectEqual(@as(usize, 8), st.feed(good));
        const f = st.next().?;
        try testing.expectEqual(@as(u8, 0x99), f.unit);
    }
}

// ── Server: window edges ───────────────────────────────────────────────────

test "audit: window edges on a window that does not start at 0" {
    var coils: [16]bool = @splat(false);
    var regs: [16]u16 = @splat(0);
    var s = Server.init(.{ .unit_id = 1, .framing = .tcp }, .{
        .coils = .{ .base = 10, .values = &coils },
        .discrete_inputs = .{ .base = 10, .values = &coils },
        .holding_registers = .{ .base = 100, .values = &regs },
        .input_registers = .{ .base = 100, .values = &regs },
    });
    var out: [mb.max_pdu_len]u8 = undefined;
    // single writes: one below, first, last, one past the end
    try expectExc(try call(&s, &.{ 0x05, 0, 9, 0xFF, 0 }, &out), 0x05, 2);
    try testing.expectEqualSlices(u8, &.{ 0x05, 0, 10, 0xFF, 0 }, try call(&s, &.{ 0x05, 0, 10, 0xFF, 0 }, &out));
    try testing.expectEqualSlices(u8, &.{ 0x05, 0, 25, 0xFF, 0 }, try call(&s, &.{ 0x05, 0, 25, 0xFF, 0 }, &out));
    try expectExc(try call(&s, &.{ 0x05, 0, 26, 0xFF, 0 }, &out), 0x05, 2);
    try expectExc(try call(&s, &.{ 0x06, 0, 99, 0, 1 }, &out), 0x06, 2);
    try testing.expectEqualSlices(u8, &.{ 0x06, 0, 115, 0, 1 }, try call(&s, &.{ 0x06, 0, 115, 0, 1 }, &out));
    try expectExc(try call(&s, &.{ 0x06, 0, 116, 0, 1 }, &out), 0x06, 2);
    try testing.expect(coils[15] and coils[0]);
    // reads: a span that starts below, or ends one past, the window
    try expectExc(try call(&s, &.{ 0x01, 0, 9, 0, 1 }, &out), 0x01, 2);
    try expectExc(try call(&s, &.{ 0x01, 0, 11, 0, 16 }, &out), 0x01, 2);
    try testing.expectEqual(@as(usize, 4), (try call(&s, &.{ 0x01, 0, 10, 0, 16 }, &out)).len);
    try expectExc(try call(&s, &.{ 0x02, 0, 9, 0, 1 }, &out), 0x02, 2);
    // the windows themselves
    const B = srv.BitArea{ .base = 10, .values = &coils };
    try testing.expect(!B.contains(10, 0));
    try testing.expect(!B.contains(9, 1));
    try testing.expect(B.contains(10, 16) and !B.contains(10, 17) and !B.contains(11, 16));
    try testing.expectEqual(@as(?usize, null), B.index(9));
    try testing.expectEqual(@as(?usize, 15), B.index(25));
    try testing.expectEqual(@as(?usize, null), B.index(26));
    const R = srv.RegisterArea{ .base = 100, .values = &regs };
    try testing.expect(!R.contains(100, 0));
    try testing.expect(!R.contains(99, 1));
    try testing.expect(R.contains(100, 16) and !R.contains(100, 17));
    try testing.expectEqual(@as(?usize, null), R.index(99));
    try testing.expectEqual(@as(?usize, 15), R.index(115));
    try testing.expectEqual(@as(?usize, null), R.index(116));
}

// ── Server: quantity limits, body lengths, hooks ───────────────────────────

const Rec = struct {
    events: [8]srv.WriteEvent = undefined,
    n: usize = 0,
    fn on(ctx: *anyopaque, e: srv.WriteEvent) void {
        const r: *Rec = @ptrCast(@alignCast(ctx));
        r.events[r.n] = e;
        r.n += 1;
    }
};

const Big = struct {
    coils: [2000]bool = @splat(false),
    regs: [300]u16 = @splat(0),

    fn server(b: *Big, config: srv.Config) Server {
        return Server.init(config, .{
            .coils = .{ .values = &b.coils },
            .holding_registers = .{ .values = &b.regs },
        });
    }
};

fn expectHook(rec: *const Rec, area: srv.Area, addr: u16, count: u16) !void {
    try testing.expectEqual(@as(usize, 1), rec.n);
    try testing.expectEqual(area, rec.events[0].area);
    try testing.expectEqual(addr, rec.events[0].addr);
    try testing.expectEqual(count, rec.events[0].count);
}

test "audit: the write hook sees the exact area, address and count of every write function" {
    var big: Big = .{};
    var s = big.server(.{ .unit_id = 1, .framing = .tcp });
    var rec: Rec = .{};
    s.setWriteHook(.{ .ctx = &rec, .onWriteFn = Rec.on });
    var out: [mb.max_pdu_len]u8 = undefined;
    _ = try call(&s, &.{ 0x05, 0, 3, 0xFF, 0 }, &out);
    try expectHook(&rec, .coils, 3, 1);
    rec.n = 0;
    _ = try call(&s, &.{ 0x06, 0, 4, 0, 9 }, &out);
    try expectHook(&rec, .holding_registers, 4, 1);
    rec.n = 0;
    _ = try call(&s, &.{ 0x0F, 0, 5, 0, 9, 2, 0xFF, 0x01 }, &out);
    try expectHook(&rec, .coils, 5, 9);
    rec.n = 0;
    _ = try call(&s, &.{ 0x10, 0, 6, 0, 2, 4, 0, 1, 0, 2 }, &out);
    try expectHook(&rec, .holding_registers, 6, 2);
    rec.n = 0;
    _ = try call(&s, &.{ 0x17, 0, 1, 0, 3, 0, 20, 0, 2, 4, 0, 7, 0, 8 }, &out);
    try expectHook(&rec, .holding_registers, 20, 2);
    rec.n = 0;
    _ = try call(&s, &.{ 0x16, 0, 8, 0, 0xFF, 0, 1 }, &out);
    try expectHook(&rec, .holding_registers, 8, 1);
}

test "audit: quantity limits are inclusive, a zero quantity is IllegalDataValue, a surplus byte too" {
    var big: Big = .{};
    var s = big.server(.{ .unit_id = 1, .framing = .tcp });
    var out: [mb.max_pdu_len]u8 = undefined;
    var req: [mb.max_pdu_len]u8 = undefined;
    // FC 0x0F: 1968 coils (246 data bytes) pass, 0 is a value error
    req[0] = 0x0F;
    std.mem.writeInt(u16, req[1..3], 0, .big);
    std.mem.writeInt(u16, req[3..5], 1968, .big);
    req[5] = 246;
    @memset(req[6..252], 0xFF);
    try testing.expectEqual(@as(usize, 5), (try call(&s, req[0..252], &out)).len);
    try testing.expect(big.coils[1967] and !big.coils[1968]);
    try expectExc(try call(&s, &.{ 0x0F, 0, 0, 0, 0, 0 }, &out), 0x0F, 3);
    // FC 0x10: 123 registers pass, 0 is a value error, one surplus byte is a value error
    req[0] = 0x10;
    std.mem.writeInt(u16, req[3..5], 123, .big);
    req[5] = 246;
    @memset(req[6..252], 0x01);
    try testing.expectEqual(@as(usize, 5), (try call(&s, req[0..252], &out)).len);
    try expectExc(try call(&s, &.{ 0x10, 0, 0, 0, 0, 0 }, &out), 0x10, 3);
    try expectExc(try call(&s, &.{ 0x10, 0, 0, 0, 1, 2, 0, 5, 0 }, &out), 0x10, 3);
    try testing.expectEqual(@as(u16, 0x0101), big.regs[122]);
    // FC 0x17: 125 read / 121 write pass; zero read / zero write / a surplus byte are value errors
    req[0] = 0x17;
    std.mem.writeInt(u16, req[1..3], 0, .big);
    std.mem.writeInt(u16, req[3..5], 125, .big);
    std.mem.writeInt(u16, req[5..7], 0, .big);
    std.mem.writeInt(u16, req[7..9], 121, .big);
    req[9] = 242;
    @memset(req[10..252], 0x02);
    try testing.expectEqual(@as(usize, 2 + 250), (try call(&s, req[0..252], &out)).len);
    try expectExc(try call(&s, &.{ 0x17, 0, 0, 0, 0, 0, 0, 0, 1, 2, 0, 5 }, &out), 0x17, 3);
    try expectExc(try call(&s, &.{ 0x17, 0, 0, 0, 1, 0, 0, 0, 0, 0 }, &out), 0x17, 3);
    try expectExc(try call(&s, &.{ 0x17, 0, 0, 0, 1, 0, 0, 0, 1, 2, 0, 5, 0 }, &out), 0x17, 3);
    // FC 0x05 with a surplus byte
    try expectExc(try call(&s, &.{ 0x05, 0, 0, 0xFF, 0, 0 }, &out), 0x05, 3);
    // FC 0x16: 7 bytes is not 6
    try expectExc(try call(&s, &.{ 0x16, 0, 0, 0, 0xFF, 0, 1, 0 }, &out), 0x16, 3);
}

test "audit: FC 0x17 can be switched off, FC 0x0F reads every data byte" {
    var big: Big = .{};
    var off = big.server(.{ .unit_id = 1, .framing = .tcp, .read_write_registers = false });
    var out: [mb.max_pdu_len]u8 = undefined;
    try expectExc(try call(&off, &.{ 0x17, 0, 0, 0, 1, 0, 0, 0, 1, 2, 0, 5 }, &out), 0x17, 1);
    var s = big.server(.{ .unit_id = 1, .framing = .tcp });
    // 20 coils: 0xA5, 0x3C, 0x0A
    _ = try call(&s, &.{ 0x0F, 0, 0, 0, 20, 3, 0xA5, 0x3C, 0x0A }, &out);
    const want = [_]u8{ 0xA5, 0x3C, 0x0A };
    for (0..20) |i| try testing.expectEqual((want[i / 8] >> @intCast(i % 8)) & 1 != 0, big.coils[i]);
}

// ── Server: diagnostics ────────────────────────────────────────────────────

test "audit: diagnostics restart, listen-only, clear and counter requests validate their data" {
    var big: Big = .{};
    var s = big.server(.{ .unit_id = 1, .framing = .rtu });
    var out: [mb.max_pdu_len]u8 = undefined;
    s.counters.bus_message = 5;
    // restart: 0x0000 keeps the counters, 0xFF00 clears them, anything else is a value error
    try testing.expectEqualSlices(u8, &.{ 0x08, 0, 1, 0, 0 }, try call(&s, &.{ 0x08, 0, 1, 0, 0 }, &out));
    try testing.expectEqual(@as(u16, 5), s.counters.bus_message);
    try testing.expectEqualSlices(u8, &.{ 0x08, 0, 1, 0xFF, 0 }, try call(&s, &.{ 0x08, 0, 1, 0xFF, 0 }, &out));
    try testing.expectEqual(@as(u16, 0), s.counters.bus_message);
    try expectExc(try call(&s, &.{ 0x08, 0, 1, 0x12, 0x34 }, &out), 0x08, 3);
    try expectExc(try call(&s, &.{ 0x08, 0, 1, 0, 0, 0 }, &out), 0x08, 3);
    try expectExc(try call(&s, &.{ 0x08, 0, 1, 0 }, &out), 0x08, 3);
    // listen-only: data must be 0x0000, exactly two bytes; the reply is the echo
    try expectExc(try call(&s, &.{ 0x08, 0, 4, 0, 0, 0 }, &out), 0x08, 3);
    try expectExc(try call(&s, &.{ 0x08, 0, 4, 0, 1 }, &out), 0x08, 3);
    try testing.expect(!s.listen_only);
    try testing.expectEqualSlices(u8, &.{ 0x08, 0, 4, 0, 0 }, try call(&s, &.{ 0x08, 0, 4, 0, 0 }, &out));
    try testing.expect(s.listen_only);
    s.listen_only = false;
    // clear counters: same validation, echo reply, counters cleared
    s.counters.bus_message = 9;
    try expectExc(try call(&s, &.{ 0x08, 0, 0x0A, 0, 0, 0 }, &out), 0x08, 3);
    try expectExc(try call(&s, &.{ 0x08, 0, 0x0A, 0, 1 }, &out), 0x08, 3);
    try testing.expectEqual(@as(u16, 9), s.counters.bus_message);
    try testing.expectEqualSlices(u8, &.{ 0x08, 0, 0x0A, 0, 0 }, try call(&s, &.{ 0x08, 0, 0x0A, 0, 0 }, &out));
    try testing.expectEqual(@as(u16, 0), s.counters.bus_message);
    // counter reads: two zero data bytes, and nothing else
    try expectExc(try call(&s, &.{ 0x08, 0, 0x0B, 0, 0, 0 }, &out), 0x08, 3);
    try expectExc(try call(&s, &.{ 0x08, 0, 0x0B, 0, 1 }, &out), 0x08, 3);
}

test "audit: diagnostics echo is bounded by the PDU size" {
    var big: Big = .{};
    var s = big.server(.{ .unit_id = 1, .framing = .rtu });
    var out: [mb.max_pdu_len]u8 = undefined;
    var req: [300]u8 = @splat(0x5A);
    req[0] = 0x08;
    req[1] = 0;
    req[2] = 0;
    const exact = try call(&s, req[0..253], &out); // 3 + 250 = 253
    try testing.expectEqual(@as(usize, 253), exact.len);
    try testing.expectEqualSlices(u8, req[0..253], exact);
    try expectExc(try call(&s, req[0..254], &out), 0x08, 3);
    try expectExc(try call(&s, req[0..300], &out), 0x08, 3);
}

test "audit: Report Slave ID size limits" {
    var big: Big = .{};
    var out: [mb.max_pdu_len]u8 = undefined;
    const id251 = @as([251]u8, @splat(0x41)); // + run indicator = 252 bytes: reply is 254, too long
    var s = big.server(.{ .unit_id = 1, .framing = .tcp, .slave_id = &id251 });
    try expectExc(try call(&s, &.{0x11}, &out), 0x11, 4);
    const id250 = @as([250]u8, @splat(0x41)); // 251 bytes: reply is 253
    var s2 = big.server(.{ .unit_id = 1, .framing = .tcp, .slave_id = &id250 });
    const r = try call(&s2, &.{0x11}, &out);
    try testing.expectEqual(@as(usize, 253), r.len);
    try testing.expectEqual(@as(u8, 251), r[1]);
}

// ── Server: counters, listen-only, unit handling ───────────────────────────

test "audit: RTU counters, foreign units and the 0xFF unit" {
    var big: Big = .{};
    var s = big.server(.{ .unit_id = 5, .framing = .rtu });
    var out: [mb.tcp.max_adu_len]u8 = undefined;
    var adu: [mb.rtu.max_adu_len]u8 = undefined;
    const read = [_]u8{ 0x03, 0, 0, 0, 1 };
    // bad CRC
    var bad = (try mb.rtu.encodeAdu(&adu, 5, &read)).len;
    adu[bad - 1] ^= 0xFF;
    try testing.expect((try s.handleAdu(adu[0..bad], &out)) == null);
    try testing.expectEqual(@as(u16, 1), s.counters.bus_message);
    try testing.expectEqual(@as(u16, 1), s.counters.bus_comm_error);
    // a frame too short to be one: counted on the bus, not a CRC error
    try testing.expect((try s.handleAdu(&.{ 1, 2, 3 }, &out)) == null);
    try testing.expectEqual(@as(u16, 2), s.counters.bus_message);
    try testing.expectEqual(@as(u16, 1), s.counters.bus_comm_error);
    // another slave, and unit 255 (which RTU does not treat as "directly connected")
    bad = (try mb.rtu.encodeAdu(&adu, 9, &read)).len;
    try testing.expect((try s.handleAdu(adu[0..bad], &out)) == null);
    bad = (try mb.rtu.encodeAdu(&adu, 255, &read)).len;
    try testing.expect((try s.handleAdu(adu[0..bad], &out)) == null);
    try testing.expectEqual(@as(u16, 4), s.counters.bus_message);
    try testing.expectEqual(@as(u16, 0), s.counters.slave_message);
    // addressed to us
    bad = (try mb.rtu.encodeAdu(&adu, 5, &read)).len;
    try testing.expect((try s.handleAdu(adu[0..bad], &out)) != null);
    try testing.expectEqual(@as(u16, 5), s.counters.bus_message);
    try testing.expectEqual(@as(u16, 1), s.counters.slave_message);
    // a broadcast write: applied, counted as ours and as unanswered
    bad = (try mb.rtu.encodeAdu(&adu, 0, &.{ 0x06, 0, 3, 0, 7 })).len;
    try testing.expect((try s.handleAdu(adu[0..bad], &out)) == null);
    try testing.expectEqual(@as(u16, 7), big.regs[3]);
    try testing.expectEqual(@as(u16, 6), s.counters.bus_message);
    try testing.expectEqual(@as(u16, 2), s.counters.slave_message);
    try testing.expectEqual(@as(u16, 1), s.counters.slave_no_response);
    try testing.expectEqual(@as(u16, 0), s.counters.slave_exception_error);
}

fn tcpAdu(buf: []u8, unit: u8, pdu: []const u8) []u8 {
    return mb.tcp.encodeAdu(buf, 0x1234, unit, pdu) catch unreachable;
}

fn rtuAdu(buf: []u8, unit: u8, pdu: []const u8) []u8 {
    return mb.rtu.encodeAdu(buf, unit, pdu) catch unreachable;
}

test "audit: a listen-only device processes nothing but a restart, and answers nothing (TCP)" {
    var big: Big = .{};
    var s = big.server(.{ .unit_id = 1, .framing = .tcp });
    var out: [mb.tcp.max_adu_len]u8 = undefined;
    var adu: [mb.tcp.max_adu_len]u8 = undefined;
    s.listen_only = true; // TCP cannot enter the mode on the wire, a caller can
    // a write to register 1 has the same bytes 1..3 as a restart (08 00 01): it is still a write
    try testing.expect((try s.handleAdu(tcpAdu(&adu, 1, &.{ 0x06, 0, 1, 0, 0x42 }), &out)) == null);
    try testing.expectEqual(@as(u16, 0), big.regs[1]);
    try testing.expectEqual(@as(u16, 1), s.counters.slave_no_response);
    // another diagnostic is muted and not executed
    s.counters.bus_comm_error = 3;
    try testing.expect((try s.handleAdu(tcpAdu(&adu, 1, &.{ 0x08, 0, 0x0A, 0, 0 }), &out)) == null);
    try testing.expectEqual(@as(u16, 3), s.counters.bus_comm_error);
    // a one- and a two-byte PDU are muted too, without reading past them
    try testing.expect((try s.handleAdu(tcpAdu(&adu, 1, &.{0x08}), &out)) == null);
    try testing.expect((try s.handleAdu(tcpAdu(&adu, 1, &.{ 0x08, 0x00 }), &out)) == null);
    // a restart of 3 bytes is recognised as a restart: executed (here: rejected, not muted early)
    const before = s.counters.slave_exception_error;
    try testing.expect((try s.handleAdu(tcpAdu(&adu, 1, &.{ 0x08, 0x00, 0x01 }), &out)) == null);
    try testing.expectEqual(before + 1, s.counters.slave_exception_error);
    try testing.expect(s.listen_only);
    // a valid restart leaves the mode, is not answered, and is counted as unanswered
    const nr = s.counters.slave_no_response;
    try testing.expect((try s.handleAdu(tcpAdu(&adu, 1, &.{ 0x08, 0x00, 0x01, 0x00, 0x00 }), &out)) == null);
    try testing.expect(!s.listen_only);
    try testing.expectEqual(nr + 1, s.counters.slave_no_response);
    // ... and the device answers again
    try testing.expect((try s.handleAdu(tcpAdu(&adu, 1, &.{ 0x03, 0, 0, 0, 1 }), &out)) != null);
    // a restart while NOT muted is answered
    try testing.expect((try s.handleAdu(tcpAdu(&adu, 1, &.{ 0x08, 0x00, 0x01, 0x00, 0x00 }), &out)) != null);
    // muted again: a malformed restart is not answered either
    s.listen_only = true;
    try testing.expect((try s.handleAdu(tcpAdu(&adu, 1, &.{ 0x08, 0x00, 0x01, 0x12, 0x34 }), &out)) == null);
    try testing.expect(s.listen_only);
}

test "audit: a listen-only device processes nothing but a restart, and answers nothing (RTU)" {
    var big: Big = .{};
    var s = big.server(.{ .unit_id = 1, .framing = .rtu });
    var out: [mb.tcp.max_adu_len]u8 = undefined;
    var adu: [mb.rtu.max_adu_len]u8 = undefined;
    // the request that mutes the device is not answered, and counts as unanswered
    try testing.expect((try s.handleAdu(rtuAdu(&adu, 1, &.{ 0x08, 0, 4, 0, 0 }), &out)) == null);
    try testing.expect(s.listen_only);
    try testing.expectEqual(@as(u16, 1), s.counters.slave_no_response);
    // muted: a write is neither executed nor answered; unanswered is counted
    try testing.expect((try s.handleAdu(rtuAdu(&adu, 1, &.{ 0x06, 0, 1, 0, 0x42 }), &out)) == null);
    try testing.expectEqual(@as(u16, 0), big.regs[1]);
    try testing.expectEqual(@as(u16, 2), s.counters.slave_no_response);
    // muted: a diagnostic with another sub-function is not executed
    s.counters.bus_comm_error = 3;
    try testing.expect((try s.handleAdu(rtuAdu(&adu, 1, &.{ 0x08, 0, 0x0A, 0, 0 }), &out)) == null);
    try testing.expectEqual(@as(u16, 3), s.counters.bus_comm_error);
    try testing.expect((try s.handleAdu(rtuAdu(&adu, 1, &.{0x08}), &out)) == null);
    try testing.expect((try s.handleAdu(rtuAdu(&adu, 1, &.{ 0x08, 0x00 }), &out)) == null);
    // a restart, even a malformed one, is processed but never answered
    const before = s.counters.slave_exception_error;
    try testing.expect((try s.handleAdu(rtuAdu(&adu, 1, &.{ 0x08, 0x00, 0x01, 0x12, 0x34 }), &out)) == null);
    try testing.expectEqual(before + 1, s.counters.slave_exception_error);
    try testing.expect(s.listen_only);
    const nr = s.counters.slave_no_response;
    try testing.expect((try s.handleAdu(rtuAdu(&adu, 1, &.{ 0x08, 0x00, 0x01, 0x00, 0x00 }), &out)) == null);
    try testing.expect(!s.listen_only);
    try testing.expectEqual(nr + 1, s.counters.slave_no_response);
    try testing.expect((try s.handleAdu(rtuAdu(&adu, 1, &.{ 0x03, 0, 0, 0, 1 }), &out)) != null);
}
