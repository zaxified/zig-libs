// SPDX-License-Identifier: MIT

//! Tests added by the whole-module mutation audit: each one pins a
//! boundary or a side effect that the original suite could not see. Public API
//! only; the file is part of the test binary through root.zig.

const std = @import("std");
const apci = @import("apci.zig");
const info = @import("info.zig");
const asdu = @import("asdu.zig");
const state = @import("state.zig");
const outstation = @import("outstation.zig");
const client = @import("client.zig");
const transport = @import("transport.zig");
const testkit = @import("testkit");

const testing = std.testing;
const hex = testkit.hex.literal;

// ── apci ────────────────────────────────────────────────────────────────────

test "apci: header edges of decode, encode and the framer" {
    try testing.expectError(error.TruncatedApdu, apci.decode(&[_]u8{ 0x68, 0x04 }));
    try testing.expectError(error.LengthTooSmall, apci.decode(&[_]u8{ 0x68, 0x02 }));
    // S-format: ctl3 bit 0 and ctl2 are reserved.
    try testing.expectError(error.ReservedBitsSet, apci.decode(&hex("680401000100")));
    // U-format: each of ctl2/ctl3/ctl4 alone is refused.
    try testing.expectError(error.ReservedBitsSet, apci.decode(&hex("680407010000")));
    try testing.expectError(error.ReservedBitsSet, apci.decode(&hex("680407000100")));
    try testing.expectError(error.ReservedBitsSet, apci.decode(&hex("680407000001")));
    // S and U frames cannot carry an ASDU on the encode side either.
    var buf: [apci.max_apdu_len]u8 = undefined;
    try testing.expectError(error.AsduTooLong, apci.encode(.{ .s = .{ .recv_seq = 0 } }, &[_]u8{1}, &buf));
    try testing.expectError(error.AsduTooLong, apci.encode(.{ .u = .startdt_act }, &[_]u8{1}, &buf));

    // The framer judges a header as soon as two octets are in.
    var fb: [apci.max_apdu_len]u8 = undefined;
    var f = apci.Framer.init(&fb);
    try f.feed(&[_]u8{ 0x68, 0xFE });
    try testing.expectError(error.LengthTooLarge, f.next());
    f = apci.Framer.init(&fb);
    try f.feed(&[_]u8{ 0x68, 0x02 });
    try testing.expectError(error.LengthTooSmall, f.next());
    f = apci.Framer.init(&fb);
    try f.feed(&[_]u8{ 0x00, 0x04 });
    try testing.expectError(error.BadStartByte, f.next());
    f = apci.Framer.init(&fb);
    try f.feed(&[_]u8{0x68});
    try testing.expectEqual(@as(?apci.Apdu, null), try f.next());
}

// ── state ───────────────────────────────────────────────────────────────────

const fast = state.Config{ .k = 3, .w = 2, .t0_ms = 100, .t1_ms = 50, .t2_ms = 20, .t3_ms = 30 };
const no_t3 = state.Config{ .k = 3, .w = 2, .t0_ms = 100, .t1_ms = 50, .t2_ms = 20, .t3_ms = 100_000 };

fn uframe(f: apci.UFunction) apci.Apdu {
    return .{ .control = .{ .u = f }, .asdu = &.{}, .len = 6 };
}

fn sframeNr(nr: apci.Seq) apci.Apdu {
    return .{ .control = .{ .s = .{ .recv_seq = nr } }, .asdu = &.{}, .len = 6 };
}

fn iframeNs(ns: apci.Seq, nr: apci.Seq) apci.Apdu {
    return .{ .control = .{ .i = .{ .send_seq = ns, .recv_seq = nr } }, .asdu = &[_]u8{0}, .len = 7 };
}

fn startedConn(role: state.Role, cfg: state.Config) !state.Connection {
    var c = try state.Connection.init(cfg, role);
    c.beginConnect(0);
    c.onTcpConnected(0);
    switch (role) {
        .controlling => {
            _ = try c.startDataTransfer(0);
            _ = try c.onFrame(uframe(.startdt_con), 0);
        },
        .controlled => {
            _ = try c.onFrame(uframe(.startdt_act), 0);
            _ = c.tick(0);
        },
    }
    try testing.expectEqual(state.State.started, c.state);
    return c;
}

test "state: config validation boundaries" {
    const C = state.Config;
    try (C{ .k = 32767, .w = 32767 }).validate();
    try testing.expectError(error.WindowOutOfRange, (C{ .k = 32768, .w = 1 }).validate());
    try testing.expectError(error.WindowOutOfRange, (C{ .k = 32767, .w = 32768 }).validate());
    try (C{ .k = 3, .w = 3 }).validate();
    try testing.expectError(error.ReceiveWindowTooLarge, (C{ .k = 3, .w = 4 }).validate());
    try testing.expectError(error.ZeroTimeout, (C{ .t0_ms = 0 }).validate());
    try testing.expectError(error.ZeroTimeout, (C{ .t1_ms = 0 }).validate());
    try testing.expectError(error.ZeroTimeout, (C{ .t2_ms = 0 }).validate());
    try testing.expectError(error.ZeroTimeout, (C{ .t3_ms = 0 }).validate());
    try testing.expectError(error.T2NotLessThanT1, (C{ .t1_ms = 10, .t2_ms = 10 }).validate());
    try (C{ .t1_ms = 11, .t2_ms = 10 }).validate();
}

test "state: beginConnect and onTcpClosed reset every field" {
    var c = try startedConn(.controlling, fast);
    _ = try c.prepareI(5);
    try testing.expect(c.send_seq != 0);
    c.beginConnect(1000);
    try testing.expectEqual(state.State.connecting, c.state);
    try testing.expectEqual(@as(?u64, 1100), c.t0_deadline);
    try testing.expectEqual(@as(?u64, null), c.t1_i_deadline);
    try testing.expectEqual(@as(u16, 0), c.outstanding());
    try testing.expectEqual(@as(apci.Seq, 0), c.send_seq);

    c.send_seq = 4;
    c.ack_seq = 3;
    c.recv_seq = 2;
    c.last_sent_ack = 1;
    c.unacked_rx = 7;
    c.t0_deadline = 1;
    c.t1_i_deadline = 2;
    c.t1_u_deadline = 3;
    c.t2_deadline = 4;
    c.t3_deadline = 5;
    c.pending_act = .testfr_act;
    c.owed_confirmation = .testfr_con;
    c.onTcpClosed();
    try testing.expectEqual(state.State.closed, c.state);
    try testing.expectEqual(@as(apci.Seq, 0), c.send_seq);
    try testing.expectEqual(@as(apci.Seq, 0), c.ack_seq);
    try testing.expectEqual(@as(apci.Seq, 0), c.recv_seq);
    try testing.expectEqual(@as(apci.Seq, 0), c.last_sent_ack);
    try testing.expectEqual(@as(u16, 0), c.unacked_rx);
    try testing.expectEqual(@as(?u64, null), c.t0_deadline);
    try testing.expectEqual(@as(?u64, null), c.t1_i_deadline);
    try testing.expectEqual(@as(?u64, null), c.t1_u_deadline);
    try testing.expectEqual(@as(?u64, null), c.t2_deadline);
    try testing.expectEqual(@as(?u64, null), c.t3_deadline);
    try testing.expectEqual(@as(?apci.UFunction, null), c.pending_act);
    try testing.expectEqual(@as(?apci.UFunction, null), c.owed_confirmation);
}

test "state: t3 runs from the moment TCP is up" {
    var c = try state.Connection.init(fast, .controlling);
    c.beginConnect(0);
    c.onTcpConnected(1000);
    try testing.expectEqual(@as(?u64, 1030), c.nextDeadline());
    try testing.expectEqual(state.Action.none, c.tick(1000));
    try testing.expectEqual(state.Action.none, c.tick(1029));
    try testing.expectEqual(state.Action{ .send_u = .testfr_act }, c.tick(1030));
    // The rearmed t3 and the new t1 are both ahead; nothing is due at once.
    try testing.expectEqual(@as(?u64, 1060), c.nextDeadline());
    try testing.expectEqual(state.Action.none, c.tick(1030));
}

test "state: not-connected and not-started refusals" {
    var c = try state.Connection.init(no_t3, .controlling);
    // closed
    try testing.expectError(error.NotConnected, c.prepareI(0));
    try testing.expectError(error.NotConnected, c.startDataTransfer(0));
    try testing.expectError(error.NotConnected, c.stopDataTransfer(0));
    try testing.expectError(error.NotConnected, c.sendTestFrame(0));
    try testing.expectError(error.NotConnected, c.onFrame(uframe(.testfr_act), 0));
    // connecting
    c.beginConnect(0);
    try testing.expectError(error.NotConnected, c.prepareI(0));
    try testing.expectError(error.NotConnected, c.startDataTransfer(0));
    try testing.expectError(error.NotConnected, c.stopDataTransfer(0));
    try testing.expectError(error.NotConnected, c.sendTestFrame(0));
    try testing.expectError(error.NotConnected, c.onFrame(uframe(.testfr_act), 0));
    // stopped: connected, but no I-frames
    c.onTcpConnected(0);
    try testing.expectError(error.NotStarted, c.prepareI(0));
    try testing.expectError(error.NotStarted, c.onFrame(iframeNs(0, 0), 0));
}

test "state: a second act while one is pending is refused, test act is the right one" {
    var c = try state.Connection.init(no_t3, .controlling);
    c.beginConnect(0);
    c.onTcpConnected(0);
    try testing.expectEqual(apci.UFunction.startdt_act, try c.startDataTransfer(0));
    try testing.expectError(error.ConfirmationPending, c.startDataTransfer(0));
    try testing.expectError(error.ConfirmationPending, c.stopDataTransfer(0));
    try testing.expectError(error.ConfirmationPending, c.sendTestFrame(0));

    var d = try state.Connection.init(no_t3, .controlling);
    d.beginConnect(0);
    d.onTcpConnected(0);
    try testing.expectEqual(apci.UFunction.testfr_act, try d.sendTestFrame(0));
    try testing.expectEqual(@as(?apci.UFunction, .testfr_act), d.pending_act);
    try testing.expectEqual(state.State.stopped, d.state);

    var e = try state.Connection.init(no_t3, .controlling);
    e.beginConnect(0);
    e.onTcpConnected(0);
    try testing.expectEqual(apci.UFunction.stopdt_act, try e.stopDataTransfer(0));
    try testing.expectError(error.ConfirmationPending, e.startDataTransfer(0));
    try testing.expectError(error.ConfirmationPending, e.stopDataTransfer(0));
}

test "state: t2 is not restarted by later I-frames" {
    const cfg = state.Config{ .k = 5, .w = 4, .t0_ms = 100, .t1_ms = 50, .t2_ms = 20, .t3_ms = 100_000 };
    var c = try startedConn(.controlled, cfg);
    _ = try c.onFrame(iframeNs(0, 0), 0);
    _ = try c.onFrame(iframeNs(1, 0), 15);
    try testing.expectEqual(state.Action.none, c.tick(19));
    try testing.expectEqual(state.Action{ .send_s_frame = 2 }, c.tick(20));
}

test "state: a controlling station refuses STOPDT act and STARTDT act" {
    var c = try startedConn(.controlling, no_t3);
    try testing.expectError(error.UnexpectedFrame, c.onFrame(uframe(.stopdt_act), 1));
    try testing.expectError(error.UnexpectedFrame, c.onFrame(uframe(.startdt_act), 1));
}

test "state: a repeated acknowledgement does not restart t1" {
    var c = try startedConn(.controlling, no_t3);
    _ = try c.prepareI(0); // t1 expires at 50
    _ = try c.onFrame(sframeNr(0), 40); // acknowledges nothing new
    try testing.expectEqual(state.Action{ .close = .ack_timeout }, c.tick(50));
}

test "state: a fired timer is consumed" {
    var c = try state.Connection.init(no_t3, .controlling);
    c.beginConnect(0);
    try testing.expectEqual(state.Action{ .close = .connect_timeout }, c.tick(100));
    try testing.expectEqual(@as(?u64, null), c.t0_deadline);
    try testing.expectEqual(state.Action.none, c.tick(100));

    var d = try startedConn(.controlling, no_t3);
    _ = try d.prepareI(0);
    try testing.expectEqual(state.Action{ .close = .ack_timeout }, d.tick(50));
    try testing.expectEqual(@as(?u64, null), d.t1_i_deadline);
    try testing.expectEqual(state.Action.none, d.tick(50));

    var e = try state.Connection.init(no_t3, .controlling);
    e.beginConnect(0);
    e.onTcpConnected(0);
    _ = try e.startDataTransfer(0);
    try testing.expectEqual(state.Action{ .close = .confirm_timeout }, e.tick(50));
    try testing.expectEqual(@as(?u64, null), e.t1_u_deadline);
    try testing.expectEqual(@as(?apci.UFunction, null), e.pending_act);
    try testing.expectEqual(state.Action.none, e.tick(50));
}

test "state: nextDeadline sees every timer" {
    var c = try state.Connection.init(no_t3, .controlling);
    c.beginConnect(10);
    try testing.expectEqual(@as(?u64, 110), c.nextDeadline()); // t0

    var d = try startedConn(.controlling, no_t3);
    _ = try d.prepareI(5);
    try testing.expectEqual(@as(?u64, 55), d.nextDeadline()); // t1 of the I-frame

    var e = try state.Connection.init(no_t3, .controlling);
    e.beginConnect(0);
    e.onTcpConnected(0);
    _ = try e.startDataTransfer(7);
    try testing.expectEqual(@as(?u64, 57), e.nextDeadline()); // t1 of the U act

    var f = try startedConn(.controlled, no_t3);
    _ = try f.onFrame(uframe(.testfr_act), 3);
    try testing.expectEqual(@as(?u64, 0), f.nextDeadline()); // an owed confirmation is due now
}

// ── asdu / info ─────────────────────────────────────────────────────────────

test "asdu: Params validation, derived sizes and ceilings" {
    const P = asdu.Params;
    try (P{}).validate();
    inline for (.{ 1, 2, 3 }) |v| try (P{ .ioa_size = v }).validate();
    inline for (.{ 1, 2 }) |v| try (P{ .ca_size = v }).validate();
    inline for (.{ 1, 2 }) |v| try (P{ .cot_size = v }).validate();
    try testing.expectError(error.InvalidParams, (P{ .ioa_size = 0 }).validate());
    try testing.expectError(error.InvalidParams, (P{ .ioa_size = 4 }).validate());
    try testing.expectError(error.InvalidParams, (P{ .ca_size = 0 }).validate());
    try testing.expectError(error.InvalidParams, (P{ .ca_size = 3 }).validate());
    try testing.expectError(error.InvalidParams, (P{ .cot_size = 0 }).validate());
    try testing.expectError(error.InvalidParams, (P{ .cot_size = 3 }).validate());

    try testing.expectEqual(@as(usize, 6), (P{}).headerLen());
    try testing.expectEqual(@as(usize, 4), (P{ .ca_size = 1, .cot_size = 1 }).headerLen());
    try testing.expect((P{}).hasOriginator());
    try testing.expect(!(P{ .cot_size = 1 }).hasOriginator());
    try testing.expectEqual(@as(u32, 0xFF), (P{ .ioa_size = 1 }).maxIoa());
    try testing.expectEqual(@as(u32, 0xFFFF), (P{ .ioa_size = 2 }).maxIoa());
    try testing.expectEqual(@as(u32, 0xFF_FFFF), (P{ .ioa_size = 3 }).maxIoa());
    try testing.expectEqual(@as(u16, 0xFF), (P{ .ca_size = 1 }).maxCa());
    try testing.expectEqual(@as(u16, 0xFFFF), (P{ .ca_size = 2 }).maxCa());
    try testing.expectEqual(@as(u16, 0xFF), (P{ .ca_size = 1 }).broadcastCa());
    try testing.expectEqual(@as(u16, 0xFFFF), (P{ .ca_size = 2 }).broadcastCa());
}

test "asdu: type id direction ranges at their edges" {
    const T = asdu.TypeId;
    const mon = [_]struct { id: u8, yes: bool }{
        .{ .id = 0, .yes = false }, .{ .id = 1, .yes = true }, .{ .id = 40, .yes = true }, .{ .id = 41, .yes = false },
    };
    for (mon) |c| try testing.expectEqual(c.yes, @as(T, @fromBackingInt(c.id)).isMonitoring());
    const cmd = [_]struct { id: u8, yes: bool }{
        .{ .id = 44, .yes = false }, .{ .id = 45, .yes = true }, .{ .id = 69, .yes = true }, .{ .id = 70, .yes = false },
    };
    for (cmd) |c| try testing.expectEqual(c.yes, @as(T, @fromBackingInt(c.id)).isCommand());
}

test "asdu: the shape table matches the standard, type by type" {
    const K = asdu.ElementKind;
    const Tm = asdu.TimeKind;
    const rows = [_]struct { id: u8, base: K, time: Tm, size: usize }{
        .{ .id = 1, .base = .siq, .time = .none, .size = 1 },
        .{ .id = 2, .base = .siq, .time = .cp24, .size = 4 },
        .{ .id = 3, .base = .diq, .time = .none, .size = 1 },
        .{ .id = 4, .base = .diq, .time = .cp24, .size = 4 },
        .{ .id = 5, .base = .step, .time = .none, .size = 2 },
        .{ .id = 6, .base = .step, .time = .cp24, .size = 5 },
        .{ .id = 7, .base = .bitstring, .time = .none, .size = 5 },
        .{ .id = 8, .base = .bitstring, .time = .cp24, .size = 8 },
        .{ .id = 9, .base = .normalized, .time = .none, .size = 3 },
        .{ .id = 10, .base = .normalized, .time = .cp24, .size = 6 },
        .{ .id = 11, .base = .scaled, .time = .none, .size = 3 },
        .{ .id = 12, .base = .scaled, .time = .cp24, .size = 6 },
        .{ .id = 13, .base = .short_float, .time = .none, .size = 5 },
        .{ .id = 14, .base = .short_float, .time = .cp24, .size = 8 },
        .{ .id = 15, .base = .counter, .time = .none, .size = 5 },
        .{ .id = 16, .base = .counter, .time = .cp24, .size = 8 },
        .{ .id = 17, .base = .protection_event, .time = .cp24, .size = 6 },
        .{ .id = 18, .base = .protection_start, .time = .cp24, .size = 7 },
        .{ .id = 19, .base = .protection_output, .time = .cp24, .size = 7 },
        .{ .id = 20, .base = .packed_single, .time = .none, .size = 5 },
        .{ .id = 21, .base = .normalized_no_quality, .time = .none, .size = 2 },
        .{ .id = 30, .base = .siq, .time = .cp56, .size = 8 },
        .{ .id = 31, .base = .diq, .time = .cp56, .size = 8 },
        .{ .id = 32, .base = .step, .time = .cp56, .size = 9 },
        .{ .id = 33, .base = .bitstring, .time = .cp56, .size = 12 },
        .{ .id = 34, .base = .normalized, .time = .cp56, .size = 10 },
        .{ .id = 35, .base = .scaled, .time = .cp56, .size = 10 },
        .{ .id = 36, .base = .short_float, .time = .cp56, .size = 12 },
        .{ .id = 37, .base = .counter, .time = .cp56, .size = 12 },
        .{ .id = 38, .base = .protection_event, .time = .cp56, .size = 10 },
        .{ .id = 39, .base = .protection_start, .time = .cp56, .size = 11 },
        .{ .id = 40, .base = .protection_output, .time = .cp56, .size = 11 },
        .{ .id = 45, .base = .sco, .time = .none, .size = 1 },
        .{ .id = 46, .base = .dco, .time = .none, .size = 1 },
        .{ .id = 47, .base = .rco, .time = .none, .size = 1 },
        .{ .id = 48, .base = .setpoint_normalized, .time = .none, .size = 3 },
        .{ .id = 49, .base = .setpoint_scaled, .time = .none, .size = 3 },
        .{ .id = 50, .base = .setpoint_float, .time = .none, .size = 5 },
        .{ .id = 51, .base = .bitstring_command, .time = .none, .size = 4 },
        .{ .id = 58, .base = .sco, .time = .cp56, .size = 8 },
        .{ .id = 59, .base = .dco, .time = .cp56, .size = 8 },
        .{ .id = 60, .base = .rco, .time = .cp56, .size = 8 },
        .{ .id = 61, .base = .setpoint_normalized, .time = .cp56, .size = 10 },
        .{ .id = 62, .base = .setpoint_scaled, .time = .cp56, .size = 10 },
        .{ .id = 63, .base = .setpoint_float, .time = .cp56, .size = 12 },
        .{ .id = 64, .base = .bitstring_command, .time = .cp56, .size = 11 },
        .{ .id = 70, .base = .coi, .time = .none, .size = 1 },
        .{ .id = 100, .base = .qoi, .time = .none, .size = 1 },
        .{ .id = 101, .base = .qcc, .time = .none, .size = 1 },
        .{ .id = 102, .base = .empty, .time = .none, .size = 0 },
        .{ .id = 103, .base = .empty, .time = .cp56, .size = 7 },
        .{ .id = 104, .base = .fbp, .time = .none, .size = 2 },
        .{ .id = 105, .base = .qrp, .time = .none, .size = 1 },
        .{ .id = 106, .base = .empty, .time = .cp16, .size = 2 },
        .{ .id = 107, .base = .fbp, .time = .cp56, .size = 9 },
        .{ .id = 110, .base = .parameter, .time = .none, .size = 3 },
        .{ .id = 111, .base = .parameter, .time = .none, .size = 3 },
        .{ .id = 112, .base = .parameter_float, .time = .none, .size = 5 },
        .{ .id = 113, .base = .qrp, .time = .none, .size = 1 },
    };
    for (rows) |r| {
        const t: asdu.TypeId = @fromBackingInt(r.id);
        const sh = asdu.shapeOf(t).?;
        try testing.expectEqual(r.base, sh.base);
        try testing.expectEqual(r.time, sh.time);
        try testing.expectEqual(r.size, sh.size());
        try testing.expectEqual(@as(?usize, r.size), asdu.elementSize(t));
    }
    // Not modelled: file transfer, the unused ids.
    for ([_]u8{ 0, 22, 29, 41, 120, 127, 200 }) |id| {
        try testing.expectEqual(@as(?asdu.Shape, null), asdu.shapeOf(@fromBackingInt(id)));
    }
}

test "asdu: P_ME_NC_1 is a short float plus QPM, five octets" {
    // IEC 60870-5-101 §7.3.5.3: R32 (1.5 = 0x3FC00000, little endian) + QPM.
    const std_asdu = hex("70010600" ++ "2f00" ++ "010000" ++ "0000c03f" ++ "01");
    const a = try asdu.decode(&std_asdu, asdu.default_params);
    var it = a.objects();
    const o = (try it.next()).?;
    try testing.expectEqual(@as(u32, 1), o.ioa);
    try testing.expectEqual(@as(f32, 1.5), o.element.parameter_float.value);
    try testing.expectEqual(@as(u8, 1), o.element.parameter_float.qpm);

    var buf: [32]u8 = undefined;
    const built = try asdu.buildSingle(&buf, asdu.default_params, .p_me_nc_1, .{ .cot = .activation }, 47, 1, .{ .parameter_float = .{ .value = 1.5, .qpm = 1 } }, .none);
    try testing.expectEqualSlices(u8, &std_asdu, built);

    // The 3-octet element the module used to assume is now refused.
    const old = hex("70010600" ++ "2f00" ++ "010000" ++ "0000c0");
    try testing.expectError(error.ObjectCountMismatch, asdu.decode(&old, asdu.default_params));
    // The two integer parameter types keep their 3-octet element.
    const na = hex("6e010600" ++ "2f00" ++ "010000" ++ "0040" ++ "02");
    const n = try asdu.decode(&na, asdu.default_params);
    var it2 = n.objects();
    const o2 = (try it2.next()).?;
    try testing.expectEqual([2]u8{ 0x00, 0x40 }, o2.element.parameter.raw);
    try testing.expectEqual(@as(u8, 2), o2.element.parameter.qpm);
}

test "asdu: select/execute is reported by the six command elements only" {
    const E = asdu.Element;
    const sel = info.SelectExecute.select;
    try testing.expectEqual(@as(?info.SelectExecute, sel), (E{ .sco = .{ .select = .select } }).selectExecute());
    try testing.expectEqual(@as(?info.SelectExecute, sel), (E{ .dco = .{ .select = .select } }).selectExecute());
    try testing.expectEqual(@as(?info.SelectExecute, sel), (E{ .rco = .{ .select = .select } }).selectExecute());
    try testing.expectEqual(@as(?info.SelectExecute, sel), (E{ .setpoint_normalized = .{ .value = .{}, .qos = .{ .select = .select } } }).selectExecute());
    try testing.expectEqual(@as(?info.SelectExecute, sel), (E{ .setpoint_scaled = .{ .value = 0, .qos = .{ .select = .select } } }).selectExecute());
    try testing.expectEqual(@as(?info.SelectExecute, sel), (E{ .setpoint_float = .{ .value = 0, .qos = .{ .select = .select } } }).selectExecute());
    try testing.expectEqual(@as(?info.SelectExecute, null), (E{ .bitstring_command = 1 }).selectExecute());
    try testing.expectEqual(@as(?info.SelectExecute, null), (E{ .siq = .{} }).selectExecute());
}

test "asdu: header encode accepts an exact buffer and the broadcast address" {
    var exact: [6]u8 = undefined;
    const h = try asdu.encodeHeader(.{ .type_id = .m_sp_na_1, .common_address = 0xFFFF }, asdu.default_params, &exact);
    try testing.expectEqual(@as(usize, 6), h.len);
    try testing.expectEqual(@as(u16, 0xFFFF), (try asdu.decodeHeader(h, asdu.default_params)).common_address);
    const p1 = asdu.Params{ .ca_size = 1, .cot_size = 1 };
    var small: [4]u8 = undefined;
    _ = try asdu.encodeHeader(.{ .type_id = .m_sp_na_1, .common_address = 0xFF }, p1, &small);
    try testing.expectError(error.AddressOutOfRange, asdu.encodeHeader(.{ .type_id = .m_sp_na_1, .common_address = 0x100 }, p1, &small));
}

test "asdu: single-octet elements read the leading octet of a longer slice" {
    const b = [_]u8{ 0x25, 0xEE };
    try testing.expectEqual(@as(u8, 0x25), @backingInt((try asdu.decodeElement(.qoi, &b)).qoi));
    try testing.expectEqual(@as(u8, 0x25), @backingInt((try asdu.decodeElement(.qrp, &b)).qrp));
    try testing.expectEqual(@as(u8, 0x25), (try asdu.decodeElement(.qcc, &b)).qcc.toByte());
    try testing.expectEqual(@as(u8, 0x25), (try asdu.decodeElement(.coi, &b)).coi.toByte());
    try testing.expectEqual(@as(u8, 0x25), (try asdu.decodeElement(.sco, &b)).sco.toByte());
    try testing.expectEqual(@as(u8, 0x25), (try asdu.decodeElement(.rco, &b)).rco.toByte());
    try testing.expectEqual(@as(u8, 0x25), (try asdu.decodeElement(.dco, &b)).dco.toByte());
    const q = [_]u8{ 0x31, 0xEE };
    try testing.expectEqual(@as(u8, 0x31), (try asdu.decodeElement(.siq, &q)).siq.toByte());
    try testing.expectEqual(@as(u8, 0x31), (try asdu.decodeElement(.diq, &q)).diq.toByte());
}

test "asdu: encodeElement fills an exactly sized buffer, scaled carries its quality" {
    var out: [3]u8 = undefined;
    const n = try asdu.encodeElement(.{ .scaled = .{ .value = -2, .quality = .{ .iv = true, .nt = true } } }, &out);
    try testing.expectEqual(@as(usize, 3), n);
    try testing.expectEqualSlices(u8, &[_]u8{ 0xFE, 0xFF, 0xC0 }, &out);
    var two: [2]u8 = undefined;
    try testing.expectError(error.BufferTooSmall, asdu.encodeElement(.{ .scaled = .{ .value = 0, .quality = .{} } }, &two));
}

test "asdu: Builder takes the top address and an exactly sized buffer" {
    const el = asdu.Element{ .siq = .{ .on = true } };
    var exact: [10]u8 = undefined; // 6 header + 3 address + 1 element
    var b = try asdu.Builder.init(&exact, asdu.default_params, .m_sp_na_1, .{ .cot = .spontaneous }, 47, false);
    try b.add(0xFF_FFFF, el, .none);
    try testing.expectEqual(@as(usize, 10), (try b.finish()).len);
    var b2 = try asdu.Builder.init(&exact, asdu.default_params, .m_sp_na_1, .{ .cot = .spontaneous }, 47, false);
    try testing.expectError(error.AddressOutOfRange, b2.add(0x100_0000, el, .none));
    var one: [10]u8 = undefined;
    var b3 = try asdu.Builder.init(&one, asdu.default_params, .m_sp_na_1, .{ .cot = .spontaneous }, 47, true);
    try b3.add(7, el, .none);
    try testing.expectEqual(@as(usize, 10), (try b3.finish()).len);
}

test "asdu: Builder holds 127 elements and refuses the 128th" {
    var buf: [6 + 3 + 128]u8 = undefined;
    var b = try asdu.Builder.init(&buf, asdu.default_params, .m_sp_na_1, .{ .cot = .spontaneous }, 47, true);
    var i: u32 = 0;
    while (i < 127) : (i += 1) try b.add(1000 + i, .{ .siq = .{} }, .none);
    try testing.expectError(error.TooManyObjects, b.add(1127, .{ .siq = .{} }, .none));
    const out = try b.finish();
    const a = try asdu.decode(out, asdu.default_params);
    try testing.expectEqual(@as(u7, 127), a.count());
}

test "info: Quality.isGood sees every flag" {
    try testing.expect((info.Quality{}).isGood());
    try testing.expect(!(info.Quality{ .ov = true }).isGood());
    try testing.expect(!(info.Quality{ .bl = true }).isGood());
    try testing.expect(!(info.Quality{ .sb = true }).isGood());
    try testing.expect(!(info.Quality{ .nt = true }).isGood());
    try testing.expect(!(info.Quality{ .iv = true }).isGood());
}

test "info: CP24Time2a ranges and flags" {
    var out: [3]u8 = undefined;
    const T = info.CP24Time2a;
    try testing.expectError(error.ImpossibleTime, (T{ .millisecond = 1000 }).encode(&out));
    _ = try (T{ .millisecond = 999 }).encode(&out);
    try testing.expectError(error.ImpossibleTime, (T{ .second = 60 }).encode(&out));
    _ = try (T{ .second = 59 }).encode(&out);
    try testing.expectError(error.ImpossibleTime, (T{ .minute = 60 }).encode(&out));
    _ = try (T{ .minute = 59 }).encode(&out);
    _ = try (T{ .minute = 5, .substituted = true }).encode(&out);
    try testing.expectEqual(@as(u8, 0x45), out[2]);
    _ = try (T{ .minute = 5, .invalid = true }).encode(&out);
    try testing.expectEqual(@as(u8, 0x85), out[2]);
    try testing.expectError(error.ImpossibleTime, T.decode(&[_]u8{ 0, 0, 0x3C }));
    try testing.expectEqual(@as(u8, 59), (try T.decode(&[_]u8{ 0, 0, 0x3B })).minute);
    const d = try T.decode(&[_]u8{ 0, 0, 0x45 });
    try testing.expectEqual(@as(u8, 5), d.minute);
    try testing.expect(d.substituted and !d.invalid);
}

test "info: CP56Time2a validation and flag bits" {
    const T = info.CP56Time2a;
    var out: [7]u8 = undefined;
    try testing.expectError(error.ImpossibleTime, (T{ .millisecond = 1000 }).encode(&out));
    try testing.expectError(error.ImpossibleTime, (T{ .millisecond = 1000 }).validate());
    try (T{ .millisecond = 999 }).validate();
    try testing.expectError(error.ImpossibleTime, (T{ .second = 60 }).encode(&out));
    try (T{ .second = 59 }).validate();
    // 60000 ms is the first impossible value of the combined field.
    try testing.expectError(error.ImpossibleTime, T.decode(&hex("60ea00000101" ++ "00")));
    // IV (0x80) and GEN (0x40) of the minute octet are told apart.
    const iv = try T.decode(&hex("00008000010100"));
    try testing.expect(iv.invalid and !iv.substituted);
    const gen = try T.decode(&hex("00004000010100"));
    try testing.expect(!gen.invalid and gen.substituted);
}

test "info: Diq keeps OV out of the state bits, Nva rounds and scales by 32768" {
    try testing.expectEqual(@as(u8, 0), (info.Diq{ .state = .intermediate, .quality = .{ .ov = true } }).toByte());
    try testing.expectEqual(@as(i16, 2), info.Nva.fromFloat(1.5 / 32768.0).raw);
    try testing.expectEqual(@as(i16, 24576), info.Nva.fromFloat(0.75).raw);
    try testing.expectEqual(@as(i16, -32768), info.Nva.fromFloat(-1.0).raw);
    try testing.expectEqual(@as(i16, 32767), info.Nva.fromFloat(1.0).raw);
    try testing.expectEqual(@as(f32, 0.75), (info.Nva{ .raw = 24576 }).toFloat());
}

test "info: Bcr flag bits and command qualifier bit positions" {
    const inv = info.Bcr.decode(&hex("0100000080"));
    try testing.expect(inv.invalid and !inv.adjusted and !inv.carry);
    const adj = info.Bcr.decode(&hex("0100000040"));
    try testing.expect(!adj.invalid and adj.adjusted and !adj.carry);
    const cy = info.Bcr.decode(&hex("0100000020"));
    try testing.expect(!cy.invalid and !cy.adjusted and cy.carry);

    const dco = info.Dco{ .state = .on, .qualifier = .short_pulse, .select = .select };
    try testing.expectEqual(@as(u8, 0x86), dco.toByte());
    const dback = info.Dco.fromByte(0x86);
    try testing.expectEqual(info.DoublePoint.on, dback.state);
    try testing.expectEqual(info.CommandQualifier.short_pulse, dback.qualifier);
    try testing.expectEqual(info.SelectExecute.select, dback.select);

    const rco = info.Rco{ .step = .higher, .qualifier = .long_pulse, .select = .select };
    try testing.expectEqual(@as(u8, 0x8A), rco.toByte());
    const rback = info.Rco.fromByte(0x8A);
    try testing.expectEqual(info.StepCommand.higher, rback.step);
    try testing.expectEqual(info.CommandQualifier.long_pulse, rback.qualifier);
    try testing.expectEqual(info.SelectExecute.select, rback.select);

    const sco = info.Sco{ .on = true, .qualifier = .persistent, .select = .select };
    try testing.expectEqual(@as(u8, 0x8D), sco.toByte());
    try testing.expectEqual(info.SelectExecute.select, info.Sco.fromByte(0x8D).select);
    try testing.expectEqual(info.CommandQualifier.persistent, info.Sco.fromByte(0x8D).qualifier);
    try testing.expectEqual(@as(u8, 0x85), (info.Qos{ .ql = 5, .select = .select }).toByte());
    try testing.expectEqual(info.SelectExecute.select, info.Qos.fromByte(0x85).select);
    try testing.expectEqual(@as(u7, 5), info.Qos.fromByte(0x85).ql);
}

// ── outstation ──────────────────────────────────────────────────────────────

const Point = outstation.Point;
const CollectSink = outstation.CollectSink;

fn mkPoints() [9]Point {
    return .{
        .{ .ioa = 1, .type_id = .m_sp_na_1, .element = .{ .siq = .{ .on = true } }, .group = 1 },
        .{ .ioa = 2, .type_id = .m_sp_na_1, .element = .{ .siq = .{} }, .group = 16 },
        .{ .ioa = 3, .type_id = .m_sp_na_1, .element = .{ .siq = .{ .on = true } } },
        .{ .ioa = 4, .type_id = .m_it_ta_1, .element = .{ .counter = .{} }, .time = .{ .cp24 = .{} } },
        .{ .ioa = 5, .type_id = .m_it_tb_1, .element = .{ .counter = .{} }, .time = .{ .cp56 = .{} } },
        .{ .ioa = 6, .type_id = .m_it_na_1, .element = .{ .counter = .{} } },
        .{ .ioa = 700, .type_id = .c_bo_na_1, .element = .{ .bitstring_command = 0 } },
        .{ .ioa = 800, .type_id = .c_sc_ta_1, .element = .{ .sco = .{} }, .time = .{ .cp56 = .{} } },
        .{ .ioa = 301, .type_id = .c_sc_na_1, .element = .{ .sco = .{} } },
    };
}

fn hdrOf(b: []const u8) !asdu.Header {
    return asdu.decodeHeader(b, asdu.default_params);
}

test "outstation: station interrogation and the QOI group boundaries" {
    var pts = mkPoints();
    var o = try outstation.Outstation.init(.{ .common_address = 47 }, &pts);
    const Case = struct { qoi: u8, cause: asdu.Cot, ioas: []const u32 };
    const cases = [_]Case{
        .{ .qoi = 20, .cause = .interrogated_by_station, .ioas = &.{ 1, 2, 3 } },
        .{ .qoi = 0, .cause = .interrogated_by_station, .ioas = &.{ 1, 2, 3 } },
        .{ .qoi = 19, .cause = .interrogated_by_station, .ioas = &.{ 1, 2, 3 } },
        .{ .qoi = 37, .cause = .interrogated_by_station, .ioas = &.{ 1, 2, 3 } },
        .{ .qoi = 21, .cause = .interrogated_by_group_1, .ioas = &.{1} },
        .{ .qoi = 36, .cause = .interrogated_by_group_16, .ioas = &.{2} },
    };
    for (cases) |c| {
        var s = CollectSink{};
        var req = hex("640106002f0000000014");
        req[9] = c.qoi;
        try o.handle(&req, s.sink());
        try testing.expectEqual(c.ioas.len + 2, s.count);
        for (c.ioas, 0..) |ioa, i| {
            const a = try asdu.decode(s.get(i + 1), asdu.default_params);
            try testing.expectEqual(c.cause, a.header.cause.cot);
            var it = a.objects();
            try testing.expectEqual(ioa, (try it.next()).?.ioa);
        }
        try testing.expectEqual(asdu.Cot.activation_termination, (try hdrOf(s.get(s.count - 1))).cause.cot);
    }
}

test "outstation: counter interrogation reports every counter type" {
    var pts = mkPoints();
    var o = try outstation.Outstation.init(.{ .common_address = 47 }, &pts);
    var s = CollectSink{};
    try o.handle(&hex("650106002f0000000005"), s.sink());
    try testing.expectEqual(@as(usize, 5), s.count);
    const want = [_]asdu.TypeId{ .m_it_ta_1, .m_it_tb_1, .m_it_na_1 };
    for (want, 0..) |t, i| {
        const h = try hdrOf(s.get(i + 1));
        try testing.expectEqual(t, h.type_id);
        try testing.expectEqual(asdu.Cot.requested_by_general_counter, h.cause.cot);
    }
    try testing.expectEqual(asdu.Cot.activation_termination, (try hdrOf(s.get(4))).cause.cot);
}

test "outstation: causes other than the expected one are refused with cause 45" {
    var pts = mkPoints();
    var o = try outstation.Outstation.init(.{ .common_address = 47 }, &pts);
    const reqs = [_][]const u8{
        &hex("670103002f00" ++ "000000" ++ "00000000010100"), // clock sync, spontaneous
        &hex("650103002f0000000005"), // counter interrogation
        &hex("660106002f00650000"), // read with activation instead of request
        &hex("2d0103002f002d010001"), // command, spontaneous
        &hex("2d0105002f002d010001"), // command, request
    };
    for (reqs) |r| {
        var s = CollectSink{};
        try o.handle(r, s.sink());
        try testing.expectEqual(@as(usize, 1), s.count);
        const h = try hdrOf(s.get(0));
        try testing.expectEqual(asdu.Cot.unknown_cause, h.cause.cot);
        try testing.expect(h.cause.negative);
    }
}

test "outstation: unknown address and type-mismatched commands are negatively confirmed" {
    var pts = mkPoints();
    var o = try outstation.Outstation.init(.{ .common_address = 47 }, &pts);
    // Read of an address nobody has: negative con, then cause 47.
    var s = CollectSink{};
    try o.handle(&hex("660105002f00ff0000"), s.sink());
    try testing.expectEqual(@as(usize, 2), s.count);
    try testing.expect((try hdrOf(s.get(0))).cause.negative);
    try testing.expectEqual(asdu.Cot.activation_con, (try hdrOf(s.get(0))).cause.cot);
    try testing.expect(!(try hdrOf(s.get(1))).cause.negative);
    try testing.expectEqual(asdu.Cot.unknown_ioa, (try hdrOf(s.get(1))).cause.cot);
    // A double command to the address of a single-command point.
    s.reset();
    try o.handle(&hex("2e0106002f002d010002"), s.sink());
    try testing.expectEqual(@as(usize, 2), s.count);
    try testing.expect((try hdrOf(s.get(0))).cause.negative);
    try testing.expectEqual(asdu.Cot.unknown_ioa, (try hdrOf(s.get(1))).cause.cot);
    try testing.expect(!(try hdrOf(s.get(1))).cause.negative);
    // A deactivation naming an unknown address is answered with cause 9.
    s.reset();
    try o.handle(&hex("2d0108002f00ff010001"), s.sink());
    try testing.expectEqual(asdu.Cot.deactivation_con, (try hdrOf(s.get(0))).cause.cot);
    try testing.expect((try hdrOf(s.get(0))).cause.negative);
}

test "outstation: a bitstring command (no S/E bit) executes on a direct point and a timed command stores its time" {
    var pts = mkPoints();
    var o = try outstation.Outstation.init(.{ .common_address = 47 }, &pts);
    var s = CollectSink{};
    try o.handle(&hex("330106002f00bc020078563412"), s.sink());
    try testing.expectEqual(@as(usize, 2), s.count);
    try testing.expect(!(try hdrOf(s.get(0))).cause.negative);
    try testing.expectEqual(@as(u32, 0x12345678), o.find(700, null).?.element.bitstring_command);

    s.reset();
    try o.handle(&hex("3a0106002f00200300" ++ "01" ++ "10270506070819"), s.sink());
    try testing.expectEqual(@as(usize, 2), s.count);
    const t = o.find(800, null).?.time.cp56;
    try testing.expectEqual(@as(u8, 5), t.minute);
    try testing.expectEqual(@as(u8, 6), t.hour);
    try testing.expectEqual(@as(u8, 25), t.year);
    try testing.expectEqual(@as(u16, 0), t.millisecond);
    try testing.expectEqual(@as(u8, 10), t.second);
}

test "outstation: init validates its parameters, find honours the type" {
    var pts = mkPoints();
    try testing.expectError(error.InvalidParams, outstation.Outstation.init(.{ .common_address = 1, .params = .{ .ioa_size = 0 } }, &pts));
    try testing.expectError(error.AddressOutOfRange, outstation.Outstation.init(.{ .common_address = 0x100, .params = .{ .ca_size = 1 } }, &pts));
    try testing.expectError(error.AddressOutOfRange, outstation.Outstation.init(.{ .common_address = 0xFFFF }, &pts));
    var o = try outstation.Outstation.init(.{ .common_address = 47 }, &pts);
    try testing.expect(o.find(3, .m_sp_na_1) != null);
    try testing.expect(o.find(3, null) != null);
    try testing.expect(o.find(3, .m_dp_na_1) == null);
}

test "outstation: the VSQ, the T bit and the originator of a request survive into the reply" {
    var pts = mkPoints();
    var o = try outstation.Outstation.init(.{ .common_address = 47 }, &pts);
    var s = CollectSink{};
    try o.handle(&hex("648106002f0000000014"), s.sink());
    try testing.expectEqual(@as(u8, 0x81), s.get(0)[1]);
    // Unknown type id, test bit and originator: echoed byte for byte but the cause.
    s.reset();
    try o.handle(&hex("fe018605" ++ "2f00"), s.sink());
    try testing.expectEqualSlices(u8, &hex("fe01ec05" ++ "2f00"), s.get(0));
    // Header-only request: an empty body is fine.
    s.reset();
    try o.handle(&hex("fe0106002f00"), s.sink());
    try testing.expectEqualSlices(u8, &hex("fe016c002f00"), s.get(0));
    // The scratch buffer is exactly one ASDU long.
    var big: [250]u8 = @splat(0);
    @memcpy(big[0..6], &hex("fe0106002f00"));
    s.reset();
    try o.handle(big[0..249], s.sink());
    try testing.expectEqual(@as(usize, 249), s.get(0).len);
    try testing.expectError(error.BufferTooSmall, o.handle(big[0..250], s.sink()));
}

// ── Server and Client over the in-memory pipe ───────────────────────────────

const Server = outstation.Server;
const LoopTransport = transport.LoopTransport;

fn deliverI(loop: *LoopTransport, ns: apci.Seq, nr: apci.Seq, body: []const u8) !void {
    var f: [apci.max_apdu_len]u8 = undefined;
    loop.deliver(try apci.encode(.{ .i = .{ .send_seq = ns, .recv_seq = nr } }, body, &f));
}

fn startServer(srv: *Server, loop: *LoopTransport) !void {
    srv.onConnected(0);
    loop.deliver(&apci.encodeU(.startdt_act));
    try testing.expectEqual(Server.Event.started, try srv.poll(0));
    _ = try srv.poll(0); // sends STARTDT con
    loop.clearSent();
}

/// ASDUs of every I-frame in `sent`, in order, as (offset, len) into `sent`.
fn iFrameBodies(sent: []const u8, out: [][]const u8) !usize {
    var off: usize = 0;
    var n: usize = 0;
    while (off < sent.len) {
        const a = try apci.decode(sent[off..]);
        if (a.control == .i) {
            out[n] = a.asdu;
            n += 1;
        }
        off += a.len;
    }
    return n;
}

const srv_cfg = state.Config{ .k = 12, .w = 8, .t0_ms = 100, .t1_ms = 5000, .t2_ms = 2000, .t3_ms = 100_000 };

test "server: onDisconnected clears the framer and the queue" {
    var loop = LoopTransport{};
    var pts = mkPoints();
    var fb: [apci.max_apdu_len]u8 = undefined;
    var qb: [64]u8 = undefined;
    var srv = try Server.init(.{ .common_address = 47 }, &pts, loop.transport(), &fb, &qb, srv_cfg);
    srv.onConnected(0);
    srv.framer.len = 5;
    srv.framer.pos = 2;
    srv.queue_used = 7;
    srv.queue_read = 3;
    srv.onDisconnected();
    try testing.expectEqual(state.State.closed, srv.conn.state);
    try testing.expectEqual(@as(usize, 0), srv.framer.len);
    try testing.expectEqual(@as(usize, 0), srv.framer.pos);
    try testing.expectEqual(@as(usize, 0), srv.queue_used);
    try testing.expectEqual(@as(usize, 0), srv.queue_read);
}

test "server: unanswered I-frames are acknowledged by an S-frame" {
    var loop = LoopTransport{};
    var pts = mkPoints();
    var fb: [apci.max_apdu_len]u8 = undefined;
    var qb: [256]u8 = undefined;
    const cfg = state.Config{ .k = 12, .w = 2, .t0_ms = 100, .t1_ms = 5000, .t2_ms = 2000, .t3_ms = 100_000 };
    var srv = try Server.init(.{ .common_address = 47 }, &pts, loop.transport(), &fb, &qb, cfg);
    try startServer(&srv, &loop);
    // A broadcast command is dropped silently: counted, never answered.
    const bc = hex("2d010600ffff2d010001");
    try deliverI(&loop, 0, 0, &bc);
    _ = try srv.poll(0);
    try deliverI(&loop, 1, 0, &bc);
    _ = try srv.poll(0);
    _ = try srv.poll(0);
    try testing.expectEqualSlices(u8, &apci.encodeS(2), loop.sent());
}

test "server: replies leave in the poll that handled the request; a stopped link keeps the queue" {
    var loop = LoopTransport{};
    var pts = mkPoints();
    var fb: [apci.max_apdu_len]u8 = undefined;
    var qb: [512]u8 = undefined;
    const cfg = state.Config{ .k = 2, .w = 1, .t0_ms = 100, .t1_ms = 5000, .t2_ms = 2000, .t3_ms = 100_000 };
    var srv = try Server.init(.{ .common_address = 47 }, &pts, loop.transport(), &fb, &qb, cfg);
    try startServer(&srv, &loop);
    try deliverI(&loop, 0, 0, &hex("640106002f0000000014"));
    _ = try srv.poll(0);
    // The window of two I-frames is already on the wire after that one poll.
    var bodies: [16][]const u8 = undefined;
    try testing.expectEqual(@as(usize, 2), try iFrameBodies(loop.sent(), &bodies));
    try testing.expect(srv.queue_used > srv.queue_read);
    loop.deliver(&apci.encodeU(.stopdt_act));
    try testing.expectEqual(Server.Event.stopped, try srv.poll(1));
    _ = try srv.poll(1); // sends STOPDT con
    const before = loop.sent().len;
    // The master now acknowledges both I-frames: the send window is free, but the link is stopped.
    loop.deliver(&apci.encodeS(2));
    _ = try srv.poll(1);
    _ = try srv.poll(1); // must not try to drain into a stopped link
    _ = try srv.poll(1);
    try testing.expectEqual(before, loop.sent().len);
    try testing.expect(srv.queue_used > srv.queue_read);
}

fn interrogate10(loop: *LoopTransport, srv: *Server, ns: apci.Seq) !void {
    try deliverI(loop, ns, 0, &hex("640106002f0000000014"));
    _ = try srv.poll(0);
}

test "server: a reply queue sized exactly fits, one octet less does not" {
    var pts = mkPoints();
    {
        var loop = LoopTransport{};
        var fb: [apci.max_apdu_len]u8 = undefined;
        var qb: [60]u8 = undefined; // 5 ASDUs of 10 octets + 2 octets of prefix each
        var srv = try Server.init(.{ .common_address = 47 }, &pts, loop.transport(), &fb, &qb, srv_cfg);
        try startServer(&srv, &loop);
        try interrogate10(&loop, &srv, 0);
        var bodies: [16][]const u8 = undefined;
        try testing.expectEqual(@as(usize, 5), try iFrameBodies(loop.sent(), &bodies));
    }
    {
        var loop = LoopTransport{};
        var fb: [apci.max_apdu_len]u8 = undefined;
        var qb: [59]u8 = undefined;
        var srv = try Server.init(.{ .common_address = 47 }, &pts, loop.transport(), &fb, &qb, srv_cfg);
        try startServer(&srv, &loop);
        try deliverI(&loop, 0, 0, &hex("640106002f0000000014"));
        try testing.expectError(error.SinkFull, srv.poll(0));
    }
}

test "server: the reply queue is compacted when the send window held part of it back" {
    var pts = mkPoints();
    var loop = LoopTransport{};
    var fb: [apci.max_apdu_len]u8 = undefined;
    var qb: [96]u8 = undefined; // 36 left over + 60 for the second request = exactly full
    const cfg = state.Config{ .k = 2, .w = 1, .t0_ms = 100, .t1_ms = 5000, .t2_ms = 2000, .t3_ms = 100_000 };
    var srv = try Server.init(.{ .common_address = 47 }, &pts, loop.transport(), &fb, &qb, cfg);
    try startServer(&srv, &loop);
    try interrogate10(&loop, &srv, 0);
    try interrogate10(&loop, &srv, 1);

    // The master acknowledges what it has seen until all ten replies are out.
    var bodies: [32][]const u8 = undefined;
    var acked: apci.Seq = 0;
    var round: usize = 0;
    while (round < 40) : (round += 1) {
        const n = try iFrameBodies(loop.sent(), &bodies);
        if (n == 10) break;
        if (n > acked) {
            loop.deliver(&apci.encodeS(@intCast(n)));
            acked = @intCast(n);
        }
        _ = try srv.poll(0);
    }
    const n = try iFrameBodies(loop.sent(), &bodies);
    try testing.expectEqual(@as(usize, 10), n);
    const con = hex("640107002f0000000014");
    const term = hex("64010a002f0000000014");
    const p1 = hex("018114002f00" ++ "010000" ++ "01");
    const p2 = hex("018114002f00" ++ "020000" ++ "00");
    const p3 = hex("018114002f00" ++ "030000" ++ "01");
    const want = [_][]const u8{ &con, &p1, &p2, &p3, &term, &con, &p1, &p2, &p3, &term };
    for (want, 0..) |w, i| try testing.expectEqualSlices(u8, w, bodies[i]);
}

test "server: an ASDU longer than 127 octets goes through the reply queue intact" {
    var pts = mkPoints();
    var loop = LoopTransport{};
    var fb: [apci.max_apdu_len]u8 = undefined;
    var qb: [1024]u8 = undefined;
    var srv = try Server.init(.{ .common_address = 47 }, &pts, loop.transport(), &fb, &qb, srv_cfg);
    try startServer(&srv, &loop);
    // C_IC_NA_1, SQ = 1, 127 elements: a 136-octet ASDU that the confirmation echoes whole.
    var req: [136]u8 = @splat(0);
    @memcpy(req[0..6], &hex("64ff06002f00"));
    req[9] = 0x14;
    try deliverI(&loop, 0, 0, &req);
    _ = try srv.poll(0);
    var bodies: [16][]const u8 = undefined;
    const n = try iFrameBodies(loop.sent(), &bodies);
    try testing.expectEqual(@as(usize, 5), n);
    try testing.expectEqual(@as(usize, 136), bodies[0].len);
    try testing.expectEqual(asdu.Cot.activation_con, (try hdrOf(bodies[0])).cause.cot);
    try testing.expectEqual(@as(usize, 136), bodies[4].len);
}

/// An I-frame with a 249-octet ASDU of an unknown type id, 255 octets on the wire.
fn fullFrame(buf: *[apci.max_apdu_len]u8) ![]u8 {
    var body: [apci.max_asdu_len]u8 = @splat(0);
    @memcpy(body[0..6], &hex("fe0106002f00"));
    return apci.encode(.{ .i = .{ .send_seq = 0, .recv_seq = 0 } }, &body, buf);
}

test "server: a read with exactly four octets of room completes a frame and takes nothing more" {
    var loop = LoopTransport{};
    var pts = mkPoints();
    var fb: [apci.max_apdu_len]u8 = undefined;
    var qb: [1024]u8 = undefined;
    var srv = try Server.init(.{ .common_address = 47 }, &pts, loop.transport(), &fb, &qb, srv_cfg);
    try startServer(&srv, &loop);
    var ff: [apci.max_apdu_len]u8 = undefined;
    const full = try fullFrame(&ff);
    try srv.framer.feed(full[0..251]); // four octets of room left
    loop.deliver(full[251..]);
    loop.deliver(&apci.encodeU(.testfr_act)); // coalesced behind the tail
    const ev = try srv.poll(0);
    try testing.expectEqual(@as(asdu.TypeId, @fromBackingInt(0xfe)), ev.request.type_id);
    _ = try srv.poll(0); // the TESTFR act that followed is read next, then confirmed
    _ = try srv.poll(0);
    const sent = loop.sent();
    try testing.expectEqualSlices(u8, &apci.encodeU(.testfr_con), sent[sent.len - 6 ..]);
}

fn startClient(c: *client.Client, loop: *LoopTransport) !void {
    c.beginConnect(0);
    c.onConnected(0);
    try c.startDataTransfer(0);
    loop.deliver(&hex("68040b000000"));
    try testing.expectEqual(client.Incoming.started, try c.poll(0));
    loop.clearSent();
}

test "client: a read with exactly four octets of room completes a frame" {
    var loop = LoopTransport{};
    var fb: [apci.max_apdu_len]u8 = undefined;
    var c = try client.Client.init(loop.transport(), &fb, .{});
    try startClient(&c, &loop);
    var ff: [apci.max_apdu_len]u8 = undefined;
    const full = try fullFrame(&ff);
    try c.framer.feed(full[0..251]);
    loop.deliver(full[251..]);
    loop.deliver(&apci.encodeU(.testfr_act));
    const ev = try c.poll(0);
    try testing.expectEqual(@as(asdu.TypeId, @fromBackingInt(0xfe)), ev.unsupported_asdu.type_id);
}

test "client: lifecycle calls reach the state machine" {
    var loop = LoopTransport{};
    var fb: [apci.max_apdu_len]u8 = undefined;
    try testing.expectError(error.InvalidParams, client.Client.init(loop.transport(), &fb, .{ .params = .{ .ca_size = 0 } }));
    var c = try client.Client.init(loop.transport(), &fb, .{ .config = .{ .t0_ms = 100 } });
    c.beginConnect(0);
    try testing.expectEqual(state.State.connecting, c.conn.state);
    try testing.expectEqual(client.Incoming{ .closed = .connect_timeout }, try c.poll(100));
    c.onConnected(0);
    try testing.expectEqual(state.State.stopped, c.conn.state);
    try c.framer.feed(&[_]u8{ 0x68, 0x04, 0x07 });
    c.framer.pos = 1;
    c.onDisconnected();
    try testing.expectEqual(state.State.closed, c.conn.state);
    try testing.expectEqual(@as(usize, 0), c.framer.len);
    try testing.expectEqual(@as(usize, 0), c.framer.pos);
}

test "client: TESTFR act and the system commands put the documented frames on the wire" {
    var loop = LoopTransport{};
    var fb: [apci.max_apdu_len]u8 = undefined;
    var c = try client.Client.init(loop.transport(), &fb, .{});
    c.beginConnect(0);
    c.onConnected(0);
    try c.testLink(0);
    try testing.expectEqualSlices(u8, &hex("680443000000"), loop.sent());
    loop.deliver(&hex("68048300" ++ "0000")); // TESTFR con
    try testing.expectEqual(client.Incoming.test_confirmed, try c.poll(0));
    c.conn.state = .started;
    loop.clearSent();

    const T = struct {
        fn check(l: *LoopTransport, want: []const u8) !void {
            try testing.expectEqualSlices(u8, want, l.sent()[6..]);
            l.clearSent();
        }
    };
    try c.interrogateCounters(47, .{}, 0);
    try T.check(&loop, &hex("650106002f0000000005"));
    try c.syncClock(47, .{ .minute = 5, .hour = 6, .day = 7, .month = 8, .year = 25 }, 0);
    try T.check(&loop, &hex("670106002f00" ++ "000000" ++ "00000506070819"));
    try c.testCommand(47, 0xAA55, 0);
    try T.check(&loop, &hex("680106002f00" ++ "000000" ++ "55aa"));
    try c.resetProcess(47, .general_reset, 0);
    try T.check(&loop, &hex("690106002f00" ++ "000000" ++ "01"));
    try c.readPoint(47, 0x65, 0);
    try T.check(&loop, &hex("660105002f00" ++ "650000"));
    try c.interrogate(47, .station, 0);
    try T.check(&loop, &hex("640106002f00" ++ "000000" ++ "14"));
    try c.command(.c_sc_na_1, 47, 301, .{ .sco = .{ .on = true } }, .none, 0);
    try T.check(&loop, &hex("2d0106002f00" ++ "2d0100" ++ "01"));
}

test "transport: the in-memory pipe takes exactly its capacity" {
    var loop = LoopTransport{};
    const t = loop.transport();
    var blob: [4096]u8 = @splat(0xAB);
    try t.write(&blob);
    try testing.expectEqual(@as(usize, 4096), loop.sent().len);
    try testing.expectError(error.WriteFailed, t.write(&[_]u8{1}));
}

// ── protection equipment events (types 17-19, 38-40) ───────────────────────
//
// Octet layouts from IEC 60870-5-101 §7.3.1 (cross-checked against the field
// order and bit values of lib60870-C's headers): one
// object is the base element with its CP16Time2a, then the CP24Time2a (17-19)
// or CP56Time2a (38-40) tag.

const ProtectionCase = struct {
    type_id: asdu.TypeId,
    /// the whole ASDU with one object at IOA 1, hand-built from the standard
    wire: []const u8,
};

fn expectProtectionRoundTrip(c: ProtectionCase, want: asdu.Object) !void {
    const a = try asdu.decode(c.wire, asdu.default_params);
    try testing.expectEqual(c.type_id, a.header.type_id);
    var it = a.objects();
    const o = (try it.next()).?;
    try testing.expectEqual(@as(?asdu.Object, null), try it.next());
    try testing.expectEqual(want.ioa, o.ioa);
    try testing.expectEqualDeep(want.element, o.element);
    try testing.expectEqualDeep(want.time, o.time);
    // and back to the very same octets
    var buf: [64]u8 = undefined;
    const built = try asdu.buildSingle(&buf, asdu.default_params, c.type_id, .{ .cot = .spontaneous }, 47, want.ioa, want.element, want.time);
    try testing.expectEqualSlices(u8, c.wire, built);
    // one octet short or long is a count mismatch, never a partial element
    try testing.expectError(error.ObjectCountMismatch, asdu.decode(c.wire[0 .. c.wire.len - 1], asdu.default_params));
    var longer: [64]u8 = undefined;
    @memcpy(longer[0..c.wire.len], c.wire);
    longer[c.wire.len] = 0;
    try testing.expectError(error.ObjectCountMismatch, asdu.decode(longer[0 .. c.wire.len + 1], asdu.default_params));
}

test "protection events: M_EP_TA_1 (17) SEP + elapsed time + CP24" {
    // SEP 0x9A = ES 2 (on) | EI | BL | IV; elapsed 0x1234 ms; CP24 5.000 s, minute 5, IV.
    try expectProtectionRoundTrip(.{
        .type_id = .m_ep_ta_1,
        .wire = &hex("11010300" ++ "2f00" ++ "010000" ++ "9a" ++ "3412" ++ "8813" ++ "85"),
    }, .{
        .ioa = 1,
        .element = .{ .protection_event = .{
            .event = .{ .state = .on, .elapsed_invalid = true, .quality = .{ .bl = true, .iv = true } },
            .elapsed = .{ .milliseconds = 0x1234 },
        } },
        .time = .{ .cp24 = .{ .second = 5, .minute = 5, .invalid = true } },
    });
}

test "protection events: M_EP_TB_1 (18) SPE + QDP + duration + CP24" {
    // SPE 0x25 = GS | SL2 | SRD; QDP 0x58 = EI | BL | NT; duration 0x0102 ms; CP24 0.001 s, minute 59.
    try expectProtectionRoundTrip(.{
        .type_id = .m_ep_tb_1,
        .wire = &hex("12010300" ++ "2f00" ++ "010000" ++ "25" ++ "58" ++ "0201" ++ "0100" ++ "3b"),
    }, .{
        .ioa = 1,
        .element = .{ .protection_start = .{
            .start = .{ .gs = true, .sl2 = true, .srd = true },
            .qdp = .{ .elapsed_invalid = true, .quality = .{ .bl = true, .nt = true } },
            .duration = .{ .milliseconds = 0x0102 },
        } },
        .time = .{ .cp24 = .{ .millisecond = 1, .minute = 59 } },
    });
}

test "protection events: M_EP_TC_1 (19) OCI + QDP + operating time + CP24" {
    // OCI 0x0A = CL1 | CL3; QDP 0xA0 = SB | IV; operating time 0xFFFF ms; CP24 59.999 s, minute 0, substituted.
    try expectProtectionRoundTrip(.{
        .type_id = .m_ep_tc_1,
        .wire = &hex("13010300" ++ "2f00" ++ "010000" ++ "0a" ++ "a0" ++ "ffff" ++ "5fea" ++ "40"),
    }, .{
        .ioa = 1,
        .element = .{ .protection_output = .{
            .output = .{ .cl1 = true, .cl3 = true },
            .qdp = .{ .quality = .{ .sb = true, .iv = true } },
            .operating = .{ .milliseconds = 0xFFFF },
        } },
        .time = .{ .cp24 = .{ .millisecond = 999, .second = 59, .substituted = true } },
    });
}

test "protection events: M_EP_TD_1 (38) SEP + elapsed time + CP56" {
    // SEP 0x41 = ES 1 (off) | NT; CP56 2025-12-31 23:59:59.999, minute 59, hour 23 + SU, Sunday.
    try expectProtectionRoundTrip(.{
        .type_id = .m_ep_td_1,
        .wire = &hex("26010300" ++ "2f00" ++ "010000" ++ "41" ++ "0100" ++ "5fea" ++ "3b" ++ "97" ++ "ff" ++ "0c" ++ "63"),
    }, .{
        .ioa = 1,
        .element = .{ .protection_event = .{
            .event = .{ .state = .off, .quality = .{ .nt = true } },
            .elapsed = .{ .milliseconds = 1 },
        } },
        .time = .{ .cp56 = .{ .millisecond = 999, .second = 59, .minute = 59, .hour = 23, .day = 31, .day_of_week = 7, .month = 12, .year = 99, .summer_time = true } },
    });
}

test "protection events: M_EP_TE_1 (39) SPE + QDP + duration + CP56" {
    // SPE 0x3F = every start bit; QDP 0x08 = EI only.
    try expectProtectionRoundTrip(.{
        .type_id = .m_ep_te_1,
        .wire = &hex("27010300" ++ "2f00" ++ "010000" ++ "3f" ++ "08" ++ "e803" ++ "0000" ++ "00" ++ "00" ++ "01" ++ "01" ++ "00"),
    }, .{
        .ioa = 1,
        .element = .{ .protection_start = .{
            .start = .{ .gs = true, .sl1 = true, .sl2 = true, .sl3 = true, .sie = true, .srd = true },
            .qdp = .{ .elapsed_invalid = true },
            .duration = .{ .milliseconds = 1000 },
        } },
        .time = .{ .cp56 = .{} },
    });
}

test "protection events: M_EP_TF_1 (40) OCI + QDP + operating time + CP56" {
    // OCI 0x0F = every output bit; QDP 0xF8 = EI | BL | SB | NT | IV.
    try expectProtectionRoundTrip(.{
        .type_id = .m_ep_tf_1,
        .wire = &hex("28010300" ++ "2f00" ++ "010000" ++ "0f" ++ "f8" ++ "0a00" ++ "1027" ++ "3b" ++ "17" ++ "11" ++ "06" ++ "19"),
    }, .{
        .ioa = 1,
        .element = .{ .protection_output = .{
            .output = .{ .gc = true, .cl1 = true, .cl2 = true, .cl3 = true },
            .qdp = .{ .elapsed_invalid = true, .quality = .{ .bl = true, .sb = true, .nt = true, .iv = true } },
            .operating = .{ .milliseconds = 10 },
        } },
        .time = .{ .cp56 = .{ .second = 10, .minute = 59, .hour = 23, .day = 17, .day_of_week = 0, .month = 6, .year = 25 } },
    });
}

test "protection events: sequence of two objects and a bad time tag" {
    // SQ = 1, IOA 7 and 8, M_EP_TA_1: the elements are 6 octets each.
    const sq = hex("11820300" ++ "2f00" ++ "070000" ++ "01" ++ "0100" ++ "0000" ++ "00" ++ "02" ++ "0200" ++ "0000" ++ "00");
    const a = try asdu.decode(&sq, asdu.default_params);
    var it = a.objects();
    const o1 = (try it.next()).?;
    const o2 = (try it.next()).?;
    try testing.expectEqual(@as(u32, 7), o1.ioa);
    try testing.expectEqual(@as(u32, 8), o2.ioa);
    try testing.expectEqual(info.DoublePoint.off, o1.element.protection_event.event.state);
    try testing.expectEqual(info.DoublePoint.on, o2.element.protection_event.event.state);
    try testing.expectEqual(@as(u16, 2), o2.element.protection_event.elapsed.milliseconds);
    // minute 60 in the CP24 tag is an impossible time, reported per object
    const bad = hex("11010300" ++ "2f00" ++ "010000" ++ "01" ++ "0000" ++ "0000" ++ "3c");
    const b = try asdu.decode(&bad, asdu.default_params);
    var bit = b.objects();
    try testing.expectError(error.ImpossibleTime, bit.next());
}

test "protection events: element bits outside the standard are masked, not echoed" {
    // SEP bit 2 (reserved) and the bit shared with OV never come back.
    try testing.expectEqual(@as(u8, 0x0A), (info.Sep{ .state = .on, .elapsed_invalid = true, .quality = .{ .ov = true } }).toByte());
    // OV is not a field of SEP/QDP: the low bits never turn into `quality.ov`.
    try testing.expect(!info.Sep.fromByte(0x01).quality.ov);
    try testing.expect(!info.Qdp.fromByte(0x07).quality.ov);
    try testing.expectEqual(info.DoublePoint.off, info.Sep.fromByte(0x01).state);
    try testing.expectEqual(@as(u8, 0x01), info.Sep.fromByte(0x05).toByte());
    // SPE bits 6..7, OCI bits 4..7 and QDP bits 0..2 are reserved.
    try testing.expectEqual(@as(u8, 0x3F), info.Spe.fromByte(0xFF).toByte());
    try testing.expectEqual(@as(u8, 0x0F), info.Oci.fromByte(0xFF).toByte());
    try testing.expectEqual(@as(u8, 0xF8), info.Qdp.fromByte(0xFF).toByte());
    try testing.expectEqual(@as(u8, 0xF0), (info.Qdp{ .quality = .{ .ov = true, .bl = true, .sb = true, .nt = true, .iv = true } }).toByte());
    // every single bit lands in its own field
    for (0..8) |bit| {
        const b: u8 = @as(u8, 1) << @intCast(bit);
        const sep = info.Sep.fromByte(b);
        try testing.expectEqual(b & 0xF9 | (b & 0x02), sep.toByte());
        try testing.expectEqual(b & 0x3F, info.Spe.fromByte(b).toByte());
        try testing.expectEqual(b & 0x0F, info.Oci.fromByte(b).toByte());
        try testing.expectEqual(b & 0xF8, info.Qdp.fromByte(b).toByte());
    }
    // a short element is refused by the element codec as well
    try testing.expectError(error.ObjectCountMismatch, asdu.decodeElement(.protection_event, &hex("0000")));
    try testing.expectError(error.ObjectCountMismatch, asdu.decodeElement(.protection_start, &hex("000000")));
    try testing.expectError(error.ObjectCountMismatch, asdu.decodeElement(.protection_output, &hex("000000")));
    var small: [3]u8 = undefined;
    try testing.expectError(error.BufferTooSmall, asdu.encodeElement(.{ .protection_start = .{ .start = .{}, .qdp = .{}, .duration = .{} } }, &small));
}

test "outstation: protection events are spontaneous only, never interrogated" {
    var points = [_]outstation.Point{
        .{ .ioa = 1, .type_id = .m_sp_na_1, .element = .{ .siq = .{ .on = true } }, .group = 1 },
        .{ .ioa = 2, .type_id = .m_ep_ta_1, .element = .{ .protection_event = .{ .event = .{ .state = .on }, .elapsed = .{ .milliseconds = 5 } } }, .time = .{ .cp24 = .{} }, .group = 1 },
        .{ .ioa = 3, .type_id = .m_ep_te_1, .element = .{ .protection_start = .{ .start = .{ .gs = true }, .qdp = .{}, .duration = .{} } }, .time = .{ .cp56 = .{} }, .group = 1 },
    };
    var o = try outstation.Outstation.init(.{ .common_address = 47 }, &points);
    var s = outstation.CollectSink{};
    // station interrogation: con, the single-point, termination - nothing else
    try o.handle(&hex("640106002f0000000014"), s.sink());
    try testing.expectEqual(@as(usize, 3), s.count);
    // group 1 interrogation (QOI 21)
    s.reset();
    try o.handle(&hex("640106002f0000000015"), s.sink());
    try testing.expectEqual(@as(usize, 3), s.count);
    for (0..s.count) |i| {
        const a = try asdu.decode(s.get(i), asdu.default_params);
        try testing.expect(!a.header.type_id.isSpontaneousOnly());
    }
    // spontaneously they are sent, with cause 3
    s.reset();
    try o.reportSpontaneous(2, s.sink());
    try o.reportSpontaneous(3, s.sink());
    try testing.expectEqual(@as(usize, 2), s.count);
    const a = try asdu.decode(s.get(1), asdu.default_params);
    try testing.expectEqual(asdu.TypeId.m_ep_te_1, a.header.type_id);
    try testing.expectEqual(asdu.Cot.spontaneous, a.header.cause.cot);
    // the predicate covers exactly the six ids
    for (0..256) |id| {
        const t: asdu.TypeId = @fromBackingInt(@intCast(id));
        const want = (id >= 17 and id <= 19) or (id >= 38 and id <= 40);
        try testing.expectEqual(want, t.isSpontaneousOnly());
    }
}
