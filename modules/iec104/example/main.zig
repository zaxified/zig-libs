// SPDX-License-Identifier: MIT

//! What a control-centre integration does with `iec104`: bring up a
//! controlling-station `Client` against a controlled-station `Server`, run
//! `STARTDT`, general-interrogate the outstation's point database, and read
//! back the monitoring data that comes in reply.
//!
//! No socket is needed to exercise the whole protocol stack: `LoopTransport`
//! is the module's own in-memory pipe, and both peers are driven by hand-fed
//! `now_ms` values — the entry points this module exposes take the clock as a
//! parameter rather than reading one themselves. Two `LoopTransport`s form the
//! full-duplex link: each one's `sent()` bytes are handed to the other's
//! `deliver()` after every round.

const std = @import("std");
const iec104 = @import("iec104");

fn pump(from: *iec104.LoopTransport, to: *iec104.LoopTransport) void {
    to.deliver(from.sent());
    from.clearSent();
}

/// Runs both peers until neither makes further progress for a few rounds —
/// enough for one request/reply exchange to fully settle.
fn settle(
    now: *u64,
    master: *iec104.Client,
    rtu: *iec104.OutstationServer,
    m_lt: *iec104.LoopTransport,
    r_lt: *iec104.LoopTransport,
) !void {
    var idle: usize = 0;
    while (idle < 4) {
        now.* += 1;
        var progress = false;

        switch (try rtu.poll(now.*)) {
            .none => {},
            else => progress = true,
        }
        pump(r_lt, m_lt);

        switch (try master.poll(now.*)) {
            .none => {},
            .asdu => |a| {
                progress = true;
                var it = a.objects();
                while (try it.next()) |obj| {
                    // The active field of `obj.element` is determined by
                    // this ASDU's `type_id`, not by what the *previous*
                    // ASDU carried: a general interrogation reply is a
                    // stream of `M_SP_NA_1` data objects (`.siq`) bracketed
                    // by `C_IC_NA_1` activation-confirmation and
                    // activation-termination ASDUs (`.qoi`). Reading
                    // `.siq` unconditionally panics on the bracketing
                    // ASDUs with "access of union field 'siq' while field
                    // 'qoi' is active".
                    switch (a.header.type_id) {
                        .m_sp_na_1 => std.debug.print(
                            "  ioa={d} cot={s}: on={}\n",
                            .{ obj.ioa, @tagName(a.header.cause.cot), obj.element.siq.on },
                        ),
                        .c_ic_na_1 => std.debug.print(
                            "  ioa={d} cot={s}: interrogation qoi={s}\n",
                            .{ obj.ioa, @tagName(a.header.cause.cot), @tagName(obj.element.qoi) },
                        ),
                        else => std.debug.print(
                            "  ioa={d} cot={s}: type={s}\n",
                            .{ obj.ioa, @tagName(a.header.cause.cot), @tagName(a.header.type_id) },
                        ),
                    }
                }
            },
            else => progress = true,
        }
        pump(m_lt, r_lt);

        idle = if (progress) 0 else idle + 1;
    }
}

pub fn main() !void {
    // The outstation's point database: two single-point status points.
    var points = [_]iec104.Point{
        .{ .ioa = 101, .type_id = .m_sp_na_1, .element = .{ .siq = .{ .on = true } } },
        .{ .ioa = 102, .type_id = .m_sp_na_1, .element = .{ .siq = .{ .on = false } } },
    };

    var m_lt: iec104.LoopTransport = .{};
    var r_lt: iec104.LoopTransport = .{};

    var m_frames: [iec104.apci.max_apdu_len * 2]u8 = undefined;
    var r_frames: [iec104.apci.max_apdu_len * 2]u8 = undefined;
    var r_queue: [4096]u8 = undefined;

    var master = try iec104.Client.init(m_lt.transport(), &m_frames, .{});
    var rtu = try iec104.OutstationServer.init(
        .{ .common_address = 47 },
        &points,
        r_lt.transport(),
        &r_frames,
        &r_queue,
        .{},
    );

    var now: u64 = 0;
    master.beginConnect(now);
    master.onConnected(now);
    rtu.onConnected(now);

    // A general interrogation before STARTDT has been confirmed is refused
    // by the flow-control state machine — the error has to be nameable from
    // outside the module for a caller to tell "not up yet" from "wire error".
    if (master.interrogate(47, .station, now)) |_| {
        @panic("unexpected: interrogation accepted before STARTDT");
    } else |err| switch (err) {
        error.NotStarted => std.debug.print("interrogate before STARTDT: NotStarted (expected)\n", .{}),
        else => return err,
    }

    try master.startDataTransfer(now);
    try settle(&now, &master, &rtu, &m_lt, &r_lt);
    std.debug.print("data transfer started: master={} rtu={}\n", .{ master.isStarted(), rtu.isStarted() });

    std.debug.print("general interrogation:\n", .{});
    try master.interrogate(47, .station, now);
    try settle(&now, &master, &rtu, &m_lt, &r_lt);

    try master.stopDataTransfer(now);
    try settle(&now, &master, &rtu, &m_lt, &r_lt);
    std.debug.print("data transfer stopped: master={} rtu={}\n", .{ master.isStarted(), rtu.isStarted() });
}
