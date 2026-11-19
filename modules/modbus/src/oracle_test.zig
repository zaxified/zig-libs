// SPDX-License-Identifier: MIT

//! Replay of the pymodbus oracle (`tools/oracle.py`): FC 0x16, FC 0x2B/0x0E
//! and RTU-over-TCP framing against bytes pymodbus 3.16.2 produced. No Python
//! runs here; `oracle_vectors.zig` is the frozen answer.

const std = @import("std");
const mb = @import("root.zig");
const srv = @import("server.zig");
const v = @import("oracle_vectors.zig");

const testing = std.testing;

test "oracle FC 0x16: the server and the codec give pymodbus's bytes" {
    for (v.mask_cases, 0..) |c, i| {
        var cur = [1]u16{c.cur};
        var s = srv.Server.init(.{ .unit_id = 1, .framing = .tcp }, .{
            .holding_registers = .{ .base = c.addr, .values = &cur },
        });
        var out: [mb.max_pdu_len]u8 = undefined;
        const reply = try s.handlePdu(c.request, &out);
        testing.expectEqualSlices(u8, c.response, reply) catch |e| {
            std.debug.print("mask case {d}: reply differs\n", .{i});
            return e;
        };
        try testing.expectEqual(c.after, cur[0]);
        try testing.expectEqual(c.after, mb.pdu.applyMask(c.cur, c.and_mask, c.or_mask));

        var buf: [8]u8 = undefined;
        const enc = try mb.pdu.encodeMaskWriteRegister(&buf, c.addr, c.and_mask, c.or_mask);
        try testing.expectEqualSlices(u8, c.request, enc);
        try mb.pdu.parseMaskWriteResponse(c.response, c.addr, c.and_mask, c.or_mask);
    }
    // a register outside the window: pymodbus relays the datastore's IllegalDataAddress
    var one = [1]u16{0};
    var s = srv.Server.init(.{ .unit_id = 1, .framing = .tcp }, .{
        .holding_registers = .{ .base = 100, .values = &one },
    });
    var out: [mb.max_pdu_len]u8 = undefined;
    const reply = try s.handlePdu(v.mask_exception_request, &out);
    try testing.expectEqualSlices(u8, v.mask_exception_response, reply);
}

fn toObjects(tab: []const v.Obj, buf: []mb.device_id.Object) []const mb.device_id.Object {
    for (tab, 0..) |o, i| buf[i] = .{ .id = o.id, .value = o.value };
    return buf[0..tab.len];
}

/// The conformity byte the spec asks for: the device's own level (highest
/// category with a served object) | 0x80 for individual access. pymodbus
/// 3.16.2 always sends 0x83, so this byte is checked here, not against it.
fn specConformity(tab: []const v.Obj) u8 {
    var level: u8 = 0x01;
    for (tab) |o| {
        if (o.value.len == 0 or mb.device_id.isReserved(o.id)) continue;
        if (o.id >= 0x80) level = 0x03 else if (o.id >= 0x03) level = @max(level, 0x02);
    }
    return level | 0x80;
}

/// pymodbus's answer to the same table and read code at object 0.
fn pyAtZero(table: u8, code: u8) ?[]const u8 {
    for (v.mei_cases) |c| {
        if (c.table == table and c.request[2] == code and c.request[3] == 0) return c.response;
    }
    return null;
}

/// Equal except the conformity byte (index 3), which `specConformity` checks.
fn eqButConformity(a: []const u8, b: []const u8) bool {
    if (a.len != b.len or a.len < 4) return std.mem.eql(u8, a, b);
    return std.mem.eql(u8, a[0..3], b[0..3]) and std.mem.eql(u8, a[4..], b[4..]);
}

test "oracle FC 0x2B/0x0E: every byte matches pymodbus except where it departs from spec 6.21" {
    // Where pymodbus 3.16.2 departs from the spec text (V1.1b3 6.21, checked
    // 2026-11-19), the spec wins (owner rule: spec-mandatory first). Each
    // departure is a named class with an exact count, so a new difference
    // fails this test instead of joining a pile.
    //   restart:  a stream request whose object id is not a known object of
    //             that walk. Spec: "the server responds as if object 0 were
    //             pointed out (restart at the beginning)". pymodbus answers
    //             an empty list (range(i, 3) for basic; for regular/extended
    //             it walks range(i, 7) from an extended id).
    //   too_big:  an object longer than any response (spec: "An object is
    //             indivisible, therefore any object must have a size
    //             consistent with the size of transaction response"). pymodbus
    //             answers more-follows with next id = the same object and no
    //             objects, so a client loops forever; we answer
    //             ServerDeviceFailure.
    var restart: usize = 0;
    var too_big: usize = 0;
    var other: usize = 0;
    for (v.mei_cases, 0..) |c, i| {
        var objs: [16]mb.device_id.Object = undefined;
        var s = srv.Server.init(.{
            .unit_id = 1,
            .framing = .tcp,
            .device_objects = toObjects(v.tables[c.table], &objs),
        }, .{});
        var out: [mb.max_pdu_len]u8 = undefined;
        const reply = try s.handlePdu(c.request, &out);
        const is_exc = reply[0] & 0x80 != 0;
        if (!is_exc) try testing.expectEqual(specConformity(v.tables[c.table]), reply[3]);
        if (eqButConformity(reply, c.response)) continue;

        const py_exc = c.response[0] & 0x80 != 0;
        const py_empty = !py_exc and c.response.len == 7 and c.response[6] == 0;
        if (py_empty and c.response[4] == 0x00 and c.request[2] != 0x04) {
            if (pyAtZero(c.table, c.request[2])) |z| if (eqButConformity(reply, z)) {
                restart += 1;
                continue;
            };
        }
        if (py_empty and c.response[4] == 0xFF and c.response[5] == c.request[3] and
            is_exc and reply[1] == @backingInt(mb.ExceptionCode.server_device_failure))
        {
            too_big += 1;
            continue;
        }
        other += 1;
        std.debug.print("mei case {d} table {d} req {x}: ours {x} pymodbus {x}\n", .{ i, c.table, c.request, reply, c.response });
    }
    try testing.expectEqual(@as(usize, 0), other);
    try testing.expectEqual(@as(usize, 168), restart);
    try testing.expectEqual(@as(usize, 3), too_big);
}

test "oracle RtuStream: pymodbus's RTU frames, with garbage and a broken CRC between" {
    for (v.rtu_cases, 0..) |c, i| {
        var st = mb.RtuStream.init(if (c.response_role) .response else .request);
        var data: []const u8 = c.stream;
        var got: usize = 0;
        while (data.len > 0) {
            const n = st.feed(data);
            data = data[n..];
            while (st.next()) |f| {
                if (got >= c.frames.len or f.unit != c.frames[got].unit or !std.mem.eql(u8, f.pdu, c.frames[got].pdu)) {
                    std.debug.print("rtu stream {d}: frame {d} differs (unit {d} pdu {x})\n", .{ i, got, f.unit, f.pdu });
                    return error.TestUnexpectedResult;
                }
                got += 1;
            }
        }
        if (got != c.frames.len) {
            std.debug.print("rtu stream {d}: {d} of {d} frames\n", .{ i, got, c.frames.len });
            return error.TestUnexpectedResult;
        }
    }
}
