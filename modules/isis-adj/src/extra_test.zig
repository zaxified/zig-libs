// SPDX-License-Identifier: MIT
//! Tests for the options added around the P2P machine: adjacency usage (split
//! L1/L2), Protocols Supported, hello padding, counters, the RFC 5306 helper
//! and the Adj-SID. Hellos go through the real encoder and `rxHelloBytes`.

const std = @import("std");
const isis = @import("isis");
const fsm = @import("fsm.zig");

const testing = std.testing;
const Adjacency = fsm.Adjacency;
const Config = fsm.Config;
const State = fsm.State;
const Time = fsm.Time;

const sys_a: fsm.SystemId = .{ 0, 0, 0, 0, 0, 0xA };
const sys_b: fsm.SystemId = .{ 0, 0, 0, 0, 0, 0xB };
const our_area = [_]u8{ 3, 0x49, 0x00, 0x01 };
const other_area = [_]u8{ 3, 0x49, 0x99, 0x99 };

/// An echoing hello of B towards A, as RxHello (no wire).
fn echo(ct: isis.pdu.CircuitType, areas: []const u8) fsm.RxHello {
    return .{
        .source_id = sys_b,
        .holding_time = 30,
        .circuit_type = ct,
        .local_circuit_id = 1,
        .neighbor_area_addresses = areas,
        .three_way = .{ .state = .initializing, .extended_local_circuit_id = 0xB1, .neighbor = .{ .system_id = sys_a, .extended_local_circuit_id = 0xA1 } },
    };
}

fn cfgA() Config {
    return .{ .system_id = sys_a, .extended_local_circuit_id = 0xA1, .local_areas = &.{our_area[1..]} };
}

test "usage: a Level 1/2 circuit with a disjoint-area Level 1/2 neighbour is a Level 2 adjacency, with a shared area Level 1/2" {
    var adj = Adjacency.init(cfgA());
    _ = adj.start(0);
    var e = adj.rxHello(echo(.level1_2, &other_area), 1);
    try testing.expect(e.adjacency_up and e.usage_changed);
    try testing.expectEqual(fsm.Usage.level2, adj.usage.?);

    // The neighbour adds our area: the usage widens while Up.
    e = adj.rxHello(echo(.level1_2, &our_area), 2);
    try testing.expect(e.transition == null and e.usage_changed);
    try testing.expectEqual(fsm.Usage.level1_2, adj.usage.?);
    e = adj.rxHello(echo(.level1_2, &our_area), 3);
    try testing.expect(!e.usage_changed);
    _ = adj.stop();
    try testing.expect(adj.usage == null);
}

test "usage: a Level-1-only neighbour needs a shared area, whatever our circuit type" {
    for ([_]isis.pdu.CircuitType{ .level1, .level1_2 }) |ours| {
        var c = cfgA();
        c.circuit_type = ours;
        var adj = Adjacency.init(c);
        _ = adj.start(0);
        const e = adj.rxHello(echo(.level1, &other_area), 1);
        try testing.expectEqual(@as(?fsm.RejectReason, .area_mismatch), e.rejected);
        const g = adj.rxHello(echo(.level1, &our_area), 2);
        try testing.expect(g.adjacency_up);
        try testing.expectEqual(fsm.Usage.level1, adj.usage.?);
    }
    // Level 2 only on our side: the area never matters.
    var c = cfgA();
    c.circuit_type = .level2;
    var adj = Adjacency.init(c);
    _ = adj.start(0);
    try testing.expect(adj.rxHello(echo(.level1_2, &other_area), 1).adjacency_up);
    try testing.expectEqual(fsm.Usage.level2, adj.usage.?);
}

test "Protocols Supported: no common NLPID is refused, a missing TLV means CLNP only" {
    const v4 = [_]u8{0xCC};
    var c = cfgA();
    c.protocols = &v4;
    var adj = Adjacency.init(c);
    _ = adj.start(0);
    var rx = echo(.level1_2, &our_area);
    rx.neighbor_protocols = &[_]u8{0x8E};
    try testing.expectEqual(@as(?fsm.RejectReason, .no_common_protocol), adj.rxHello(rx, 1).rejected);
    rx.neighbor_protocols = null;
    try testing.expectEqual(@as(?fsm.RejectReason, .no_common_protocol), adj.rxHello(rx, 2).rejected);
    rx.neighbor_protocols = &[_]u8{ 0x8E, 0xCC };
    try testing.expect(adj.rxHello(rx, 3).adjacency_up);

    // Our own CLNP-only side accepts a neighbour that sends no #129.
    var c2 = cfgA();
    c2.protocols = &[_]u8{ 0x81, 0xCC };
    var adj2 = Adjacency.init(c2);
    _ = adj2.start(0);
    rx.neighbor_protocols = null;
    try testing.expect(adj2.rxHello(rx, 1).adjacency_up);
    // Not configured: nothing is enforced, and no #129 is built.
    var adj3 = Adjacency.init(cfgA());
    _ = adj3.start(0);
    rx.neighbor_protocols = &[_]u8{0x8E};
    try testing.expect(adj3.rxHello(rx, 1).adjacency_up);
}

test "Protocols Supported on the wire: built into the hello, found by rxHelloBytes" {
    var c = cfgA();
    c.protocols = &[_]u8{ 0xCC, 0x8E };
    var a = Adjacency.init(c);
    var b = Adjacency.init(.{ .system_id = sys_b, .extended_local_circuit_id = 0xB1, .protocols = &[_]u8{0x8E} });
    var buf: [200]u8 = undefined;
    const hb = try fsm.buildHello(&buf, b.start(0).send_hello.?);
    const p = try isis.P2pHello.decode(hb);
    const tlv = (try isis.tlv.findFirst(p.tlv_bytes, isis.tlvs.code.protocols_supported)).?;
    try testing.expectEqualSlices(u8, &.{0x8E}, tlv);
    _ = a.start(0);
    const e = try a.rxHelloBytes(hb, 1);
    try testing.expect(e.rejected == null);
    // A neighbour with only IPv4 against our IPv6-only configuration.
    var c6 = cfgA();
    c6.protocols = &[_]u8{0x8E};
    var a6 = Adjacency.init(c6);
    var b4 = Adjacency.init(.{ .system_id = sys_b, .extended_local_circuit_id = 0xB1, .protocols = &[_]u8{0xCC} });
    const h4 = try fsm.buildHello(&buf, b4.start(0).send_hello.?);
    _ = a6.start(0);
    try testing.expectEqual(@as(?fsm.RejectReason, .no_common_protocol), (try a6.rxHelloBytes(h4, 1)).rejected);
    try testing.expectEqual(@as(u32, 1), a6.counters.rejected.get(.no_common_protocol));
}

test "hello padding: exact length in every mode, never one octet short, nothing when already longer" {
    var buf: [1600]u8 = undefined;
    var a = Adjacency.init(.{ .system_id = sys_a, .extended_local_circuit_id = 1, .hello_padding = .always, .mtu = 700 });
    const hf = a.start(0).send_hello.?;
    try testing.expectEqual(@as(u16, 700), hf.pad_to);
    var b = try fsm.buildHello(&buf, hf);
    try testing.expectEqual(@as(usize, 700), b.len);
    // The padded hello still decodes and walks cleanly.
    const p = try isis.P2pHello.decode(b);
    _ = try isis.tlv.count(p.tlv_bytes);
    // Every target length from the natural size to 600 octets is met exactly,
    // except a single missing octet which no TLV can fill.
    const natural = (try fsm.buildHello(&buf, .{
        .source_id = sys_a,
        .holding_time = 30,
        .local_circuit_id = 1,
        .circuit_type = .level1_2,
        .three_way = hf.three_way,
    })).len;
    var want: usize = natural;
    while (want < 600) : (want += 1) {
        if (want == natural + 1) continue;
        var h = hf;
        h.pad_to = @intCast(want);
        b = try fsm.buildHello(&buf, h);
        try testing.expectEqual(want, b.len);
    }
    var h = hf;
    h.pad_to = @intCast(natural + 1);
    try testing.expectEqual(natural, (try fsm.buildHello(&buf, h)).len);
    h.pad_to = 10;
    try testing.expectEqual(natural, (try fsm.buildHello(&buf, h)).len);

    // during_formation: padded until Up, plain afterwards.
    var c = Adjacency.init(.{ .system_id = sys_a, .extended_local_circuit_id = 0xA1, .hello_padding = .during_formation, .mtu = 300 });
    try testing.expectEqual(@as(u16, 300), c.start(0).send_hello.?.pad_to);
    _ = c.rxHello(echo(.level1_2, &our_area), 1);
    try testing.expectEqual(State.up, c.currentState());
    try testing.expectEqual(@as(u16, 0), c.helloFields().pad_to);
    // never: the default.
    var d = Adjacency.init(.{ .system_id = sys_a, .extended_local_circuit_id = 1 });
    try testing.expectEqual(@as(u16, 0), d.start(0).send_hello.?.pad_to);
}

test "hello padding is signed with the keys: a padded authenticated hello verifies" {
    var buf: [400]u8 = undefined;
    const key = isis.auth.Key{ .algorithm = .cleartext, .secret = "pw" };
    var a = Adjacency.init(.{ .system_id = sys_a, .extended_local_circuit_id = 1, .auth_keys = &.{key}, .hello_padding = .always, .mtu = 300 });
    var b = Adjacency.init(.{ .system_id = sys_b, .extended_local_circuit_id = 2, .auth_keys = &.{key} });
    const hb = try fsm.buildHello(&buf, a.start(0).send_hello.?);
    try testing.expectEqual(@as(usize, 300), hb.len);
    _ = b.start(0);
    try testing.expect((try b.rxHelloBytes(hb, 1)).rejected == null);
}

test "counters: changes, init failures, rejects by reason, hellos and hold expiries" {
    var adj = Adjacency.init(cfgA());
    _ = adj.start(0);
    _ = adj.rxHello(.{ .source_id = sys_a, .holding_time = 30, .circuit_type = .level1_2, .local_circuit_id = 1 }, 1);
    try testing.expectEqual(@as(u32, 1), adj.counters.rejected.get(.looped_back));
    // Heard but not echoed, then silence: an init failure.
    var rx = echo(.level1_2, &our_area);
    rx.three_way = .{ .state = .down, .extended_local_circuit_id = 0xB1 };
    _ = adj.rxHello(rx, 2);
    try testing.expectEqual(State.initializing, adj.currentState());
    _ = adj.tick(40);
    try testing.expectEqual(@as(u32, 1), adj.counters.init_fails);
    try testing.expectEqual(@as(u32, 1), adj.counters.hold_expirations);
    // Up, then the hold expires: two adjacency changes.
    _ = adj.rxHello(echo(.level1_2, &our_area), 50);
    try testing.expectEqual(State.up, adj.currentState());
    _ = adj.tick(100);
    try testing.expectEqual(@as(u32, 2), adj.counters.adjacency_changes);
    try testing.expectEqual(@as(u32, 2), adj.counters.hold_expirations);
    try testing.expectEqual(@as(u32, 2), adj.counters.hellos_accepted);
    try testing.expectEqual(@as(u32, 1), adj.counters.rejected_total);
}

fn helperCfg() Config {
    var c = cfgA();
    c.graceful_restart_helper = true;
    c.adj_sid_label = 24001;
    return c;
}

fn bringUp(adj: *Adjacency) void {
    _ = adj.start(0);
    _ = adj.rxHello(echo(.level1_2, &our_area), 1);
    std.debug.assert(adj.currentState() == .up);
}

fn restarting(rr: bool, sa: bool) fsm.RxHello {
    var rx = echo(.level1_2, &our_area);
    // The restarted neighbour lost its state: Down, no neighbour block.
    rx.three_way = .{ .state = .down, .extended_local_circuit_id = 0xB2 };
    rx.restart = .{ .rr = rr, .sa = sa };
    return rx;
}

test "RFC 5306 helper: an RR from the Up neighbour keeps the adjacency, acks with the remaining time, asks for CSNPs" {
    var adj = Adjacency.init(helperCfg());
    bringUp(&adj);
    try testing.expectEqual(@as(Time, 31), adj.hold_deadline);
    const e = adj.rxHello(restarting(true, false), 10);
    try testing.expect(e.transition == null and e.adjacency_down == null and e.rejected == null);
    try testing.expectEqual(State.up, adj.currentState());
    try testing.expectEqual(@as(?bool, true), e.restart_mode);
    try testing.expect(e.send_csnp);
    const ack = e.send_hello.?.restart.?;
    try testing.expect(ack.ra and !ack.rr);
    // The first RR refreshed the hold: 10 + 30.
    try testing.expectEqual(@as(Time, 40), adj.hold_deadline);
    try testing.expectEqual(@as(?u16, 30), ack.remaining_time);
    // The recorded extended circuit id follows the restarted neighbour.
    try testing.expectEqual(@as(?u32, 0xB2), adj.neighbor_ext_circuit_id);

    // A second RR does not refresh the hold and does not re-announce.
    const e2 = adj.rxHello(restarting(true, false), 20);
    try testing.expectEqual(@as(?bool, null), e2.restart_mode);
    try testing.expectEqual(@as(Time, 40), adj.hold_deadline);
    try testing.expectEqual(@as(?u16, 20), e2.send_hello.?.restart.?.remaining_time);

    // The hold still ends the help (no refresh after the first RR).
    const e3 = adj.tick(41);
    try testing.expectEqual(@as(?fsm.DownReason, .hold_expired), e3.adjacency_down);
    try testing.expect(!adj.helper.restart_mode);
}

test "RFC 5306 helper: a hello without RR ends the restart mode and runs the normal machine" {
    var adj = Adjacency.init(helperCfg());
    bringUp(&adj);
    _ = adj.rxHello(restarting(true, false), 10);
    // Back to normal: the neighbour now echoes us again.
    const e = adj.rxHello(echo(.level1_2, &our_area), 12);
    try testing.expectEqual(@as(?bool, false), e.restart_mode);
    try testing.expectEqual(State.up, adj.currentState());
    try testing.expect(!adj.helper.restart_mode);
}

test "RFC 5306 helper off: an RR hello is just a Down-state hello (silent Initialize), and no Restart TLV is sent" {
    var adj = Adjacency.init(cfgA());
    bringUp(&adj);
    const e = adj.rxHello(restarting(true, false), 10);
    try testing.expectEqual(State.initializing, adj.currentState());
    try testing.expect(!e.send_csnp and e.restart_mode == null);
    try testing.expect(adj.helloFields().restart == null);
}

test "RFC 5306 SA: the adjacency is suppressed until the neighbour clears the flag, and its Adj-SID is withdrawn" {
    var adj = Adjacency.init(helperCfg());
    bringUp(&adj);
    const sid = adj.adjSid().?;
    try testing.expectEqual(@as(u20, 24001), sid.sid.label);
    try testing.expect(sid.persistent);
    var e = adj.rxHello(restarting(true, true), 10);
    try testing.expectEqual(@as(?bool, true), e.suppress_adjacency);
    try testing.expect(adj.adjSid() == null);
    e = adj.rxHello(restarting(true, true), 11);
    try testing.expectEqual(@as(?bool, null), e.suppress_adjacency);
    e = adj.rxHello(echo(.level1_2, &our_area), 12);
    try testing.expectEqual(@as(?bool, false), e.suppress_adjacency);
    try testing.expect(adj.adjSid() != null);
    // Down: no SID.
    _ = adj.stop();
    try testing.expect(adj.adjSid() == null);
}

test "RFC 5306 helper: an RR with no Up adjacency is processed normally and still gets an RA" {
    var adj = Adjacency.init(helperCfg());
    _ = adj.start(0);
    const e = adj.rxHello(restarting(true, false), 1);
    try testing.expectEqual(State.initializing, adj.currentState());
    const ack = e.send_hello.?.restart.?;
    try testing.expect(ack.ra);
    try testing.expectEqual(@as(?u16, 30), ack.remaining_time);
    // The Up stranger's RR is not helped.
    var up = Adjacency.init(helperCfg());
    bringUp(&up);
    var rx = restarting(true, false);
    rx.source_id = .{ 9, 9, 9, 9, 9, 9 };
    try testing.expectEqual(@as(?fsm.RejectReason, .other_neighbor), up.rxHello(rx, 5).rejected);
}

test "RFC 5306 on the wire: the Restart TLV is built into every hello and read back by rxHelloBytes" {
    var a = Adjacency.init(helperCfg());
    var restarter = Adjacency.init(.{ .system_id = sys_b, .extended_local_circuit_id = 0xB1, .local_areas = &.{our_area[1..]}, .graceful_restart_helper = true });
    var buf: [200]u8 = undefined;
    // B alone: a hello with an empty Restart TLV.
    var hf = restarter.start(0).send_hello.?;
    var hb = try fsm.buildHello(&buf, hf);
    var p = try isis.P2pHello.decode(hb);
    const v = (try isis.tlv.findFirst(p.tlv_bytes, 211)).?;
    try testing.expectEqualSlices(u8, &.{0}, v);
    // Bring A up with B's own hellos, then B restarts.
    _ = a.start(0);
    _ = try a.rxHelloBytes(hb, 1);
    _ = restarter.rxHello(.{ .source_id = sys_a, .holding_time = 30, .circuit_type = .level1_2, .local_circuit_id = 1, .three_way = a.helloFields().three_way }, 1);
    _ = try a.rxHelloBytes(try fsm.buildHello(&buf, restarter.helloFields()), 2);
    try testing.expectEqual(State.up, a.currentState());
    var fresh = Adjacency.init(.{ .system_id = sys_b, .extended_local_circuit_id = 0xB9, .graceful_restart_helper = true });
    hf = fresh.start(5).send_hello.?;
    hf.restart = .{ .rr = true };
    hb = try fsm.buildHello(&buf, hf);
    const e = try a.rxHelloBytes(hb, 6);
    try testing.expectEqual(State.up, a.currentState());
    try testing.expectEqual(@as(?bool, true), e.restart_mode);
    // A malformed Restart TLV is a typed error, nothing mutated.
    var tb: [100]u8 = undefined;
    var b2 = try isis.pdu.P2pHelloBuilder.init(&tb, .{ .source_id = sys_b, .holding_time = 30 });
    try b2.tlvs.addTlv(211, &.{ 1, 2 });
    try testing.expectError(error.BadLength, a.rxHelloBytes(b2.finish(), 7));
    p = try isis.P2pHello.decode(hb);
}
