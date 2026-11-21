// SPDX-License-Identifier: MIT
//! LAN adjacency tests: circuits exchange real encoded LAN IIHs.

const std = @import("std");
const isis = @import("isis");
const lan = @import("lan.zig");
const fsm = @import("fsm.zig");

const testing = std.testing;
const LanCircuit = lan.LanCircuit;
const Config = lan.Config;
const Time = lan.Time;

fn sid(n: u8) lan.SystemId {
    return .{ 0, 0, 0, 0, 0, n };
}
fn mac(n: u8) lan.Snpa {
    return .{ 0xaa, 0, 0, 0, 0, n };
}
const area1 = [_]u8{ 0x49, 0, 1 };
const area2 = [_]u8{ 0x49, 0, 2 };

fn cfg(n: u8, level: lan.Level) Config {
    return .{ .system_id = sid(n), .snpa = mac(n), .level = level, .local_areas = &.{&area1} };
}

/// Deliver `from`'s hello to `to`.
fn send(from: *const LanCircuit, to: *LanCircuit, now: Time) !lan.Effect {
    var buf: [1600]u8 = undefined;
    const hb = try from.buildHello(&buf, .{});
    return to.rxHelloBytes(hb, from.cfg.snpa, now);
}

fn converge(cs: []*LanCircuit, now: Time) !void {
    for (0..4) |_| {
        for (cs) |a| for (cs) |b| {
            if (a != b) _ = try send(a, b, now);
        };
    }
}

test "three circuits on one LAN reach Up with each other through real hellos" {
    var sa: [4]lan.Neighbor = undefined;
    var sb: [4]lan.Neighbor = undefined;
    var sc: [4]lan.Neighbor = undefined;
    var a = LanCircuit.init(cfg(1, .l1), &sa);
    var b = LanCircuit.init(cfg(2, .l1), &sb);
    var c = LanCircuit.init(cfg(3, .l1), &sc);
    a.start(0);
    b.start(0);
    c.start(0);
    var cs = [_]*LanCircuit{ &a, &b, &c };
    try converge(&cs, 1);
    for (cs) |x| {
        try testing.expectEqual(@as(usize, 2), x.upCount());
        try testing.expectEqual(@as(usize, 2), x.neighbors().len);
        for (x.neighbors()) |n| try testing.expectEqual(fsm.Usage.level1, n.usage);
    }
    try testing.expectEqual(lan.NeighborState.up, a.find(mac(2)).?.state);
    try testing.expectEqual(@as(u32, 2), a.counters.adjacency_changes);
}

test "the two-way check: a neighbour that does not list us stays Initializing, and falls back when it stops" {
    var sa: [4]lan.Neighbor = undefined;
    var sb: [4]lan.Neighbor = undefined;
    var a = LanCircuit.init(cfg(1, .l1), &sa);
    var b = LanCircuit.init(cfg(2, .l1), &sb);
    a.start(0);
    b.start(0);
    // B has not heard A: its hello lists nobody.
    var e = try send(&b, &a, 1);
    try testing.expectEqual(lan.EventKind.new_neighbor, e.event.?.kind);
    try testing.expect(e.send_hello);
    try testing.expectEqual(lan.NeighborState.initializing, a.find(mac(2)).?.state);
    // B hears A, lists it: A takes it Up.
    _ = try send(&a, &b, 2);
    e = try send(&b, &a, 3);
    try testing.expectEqual(lan.EventKind.up, e.event.?.kind);
    try testing.expectEqual(lan.NeighborState.up, a.find(mac(2)).?.state);
    // B resets and no longer lists A (a fresh circuit state).
    var sb2: [4]lan.Neighbor = undefined;
    var b2 = LanCircuit.init(cfg(2, .l1), &sb2);
    b2.start(10);
    e = try send(&b2, &a, 11);
    try testing.expectEqual(lan.EventKind.down, e.event.?.kind);
    try testing.expectEqual(@as(?fsm.DownReason, .neighbor_restarted), e.event.?.reason);
    try testing.expectEqual(lan.NeighborState.initializing, a.find(mac(2)).?.state);
    try testing.expectEqual(@as(usize, 0), a.upCount());
}

test "per-neighbour hold timers: each expires on its own advertised holding time" {
    var sa: [4]lan.Neighbor = undefined;
    var a = LanCircuit.init(cfg(1, .l1), &sa);
    a.start(0);
    var hello = lan.RxHello{ .snpa = mac(2), .level = .l1, .source_id = sid(2), .holding_time = 20, .circuit_type = .level1_2, .priority = 64, .lan_id = @splat(0), .area_tlvs = &.{&[_]u8{ 3, 0x49, 0, 1 }} };
    _ = a.rxHello(hello, 0);
    hello.snpa = mac(3);
    hello.source_id = sid(3);
    hello.holding_time = 50;
    _ = a.rxHello(hello, 0);
    try testing.expectEqual(@as(usize, 2), a.neighbors().len);
    var ev: [4]lan.Event = undefined;
    var t = a.tick(19, &ev);
    try testing.expectEqual(@as(usize, 0), t.events.len);
    t = a.tick(20, &ev);
    try testing.expectEqual(@as(usize, 1), t.events.len);
    try testing.expectEqual(lan.EventKind.deleted, t.events[0].kind);
    try testing.expectEqual(sid(2), t.events[0].system_id);
    try testing.expectEqual(@as(usize, 1), a.neighbors().len);
    try testing.expectEqual(@as(u32, 1), a.counters.init_fails);
    t = a.tick(50, &ev);
    try testing.expectEqual(@as(usize, 1), t.events.len);
    try testing.expectEqual(@as(usize, 0), a.neighbors().len);
}

test "an Up neighbour that expires reports down then deleted; the hello cadence is a third faster for the DIS" {
    var sa: [4]lan.Neighbor = undefined;
    var sb: [4]lan.Neighbor = undefined;
    var a = LanCircuit.init(cfg(1, .l1), &sa);
    var b = LanCircuit.init(cfg(2, .l1), &sb);
    a.start(0);
    b.start(0);
    _ = try send(&a, &b, 1);
    _ = try send(&b, &a, 1);
    _ = try send(&a, &b, 1);
    _ = try send(&b, &a, 2);
    try testing.expectEqual(@as(usize, 1), a.upCount());
    var ev: [4]lan.Event = undefined;
    const t = a.tick(100, &ev);
    try testing.expectEqual(@as(usize, 2), t.events.len);
    try testing.expectEqual(lan.EventKind.down, t.events[0].kind);
    try testing.expectEqual(@as(?fsm.DownReason, .hold_expired), t.events[0].reason);
    try testing.expectEqual(lan.EventKind.deleted, t.events[1].kind);
    try testing.expect(t.send_hello);

    // DIS: interval 10 / 3 = 3, from the next hello on.
    a.setDis(true);
    try testing.expectEqual(@as(Time, 110), a.next_hello_due);
    var t2 = a.tick(110, &ev);
    try testing.expect(t2.send_hello);
    try testing.expectEqual(@as(Time, 113), a.next_hello_due);
    t2 = a.tick(112, &ev);
    try testing.expect(!t2.send_hello);
    t2 = a.tick(113, &ev);
    try testing.expect(t2.send_hello);
}

test "priority and LAN ID changes are reported as DIS election inputs" {
    var sa: [4]lan.Neighbor = undefined;
    var a = LanCircuit.init(cfg(1, .l1), &sa);
    a.start(0);
    var rx = lan.RxHello{ .snpa = mac(2), .level = .l1, .source_id = sid(2), .holding_time = 30, .circuit_type = .level1_2, .priority = 10, .lan_id = sid(2) ++ [_]u8{1}, .area_tlvs = &.{&[_]u8{ 3, 0x49, 0, 1 }} };
    _ = a.rxHello(rx, 0);
    try testing.expectEqual(@as(u7, 10), a.find(mac(2)).?.priority);
    var e = a.rxHello(rx, 1);
    try testing.expect(e.event == null);
    rx.priority = 100;
    e = a.rxHello(rx, 2);
    try testing.expectEqual(lan.EventKind.dis_input_changed, e.event.?.kind);
    try testing.expectEqual(@as(u7, 100), a.find(mac(2)).?.priority);
    rx.lan_id = sid(9) ++ [_]u8{2};
    e = a.rxHello(rx, 3);
    try testing.expectEqual(lan.EventKind.dis_input_changed, e.event.?.kind);
    try testing.expectEqual(sid(9) ++ [_]u8{2}, a.find(mac(2)).?.lan_id);
}

test "another system answering from a known SNPA replaces the entry; a full table refuses" {
    var sa: [2]lan.Neighbor = undefined;
    var a = LanCircuit.init(cfg(1, .l1), &sa);
    a.start(0);
    var rx = lan.RxHello{ .snpa = mac(2), .level = .l1, .source_id = sid(2), .holding_time = 30, .circuit_type = .level1_2, .priority = 10, .lan_id = @splat(0), .area_tlvs = &.{&[_]u8{ 3, 0x49, 0, 1 }} };
    _ = a.rxHello(rx, 0);
    rx.source_id = sid(7);
    const e = a.rxHello(rx, 1);
    try testing.expectEqual(lan.EventKind.deleted, e.event.?.kind);
    try testing.expectEqual(sid(7), a.find(mac(2)).?.system_id);
    try testing.expectEqual(@as(usize, 1), a.neighbors().len);
    rx.snpa = mac(3);
    rx.source_id = sid(3);
    _ = a.rxHello(rx, 2);
    rx.snpa = mac(4);
    rx.source_id = sid(4);
    try testing.expectEqual(@as(?fsm.RejectReason, .neighbor_table_full), a.rxHello(rx, 3).rejected);
    try testing.expectEqual(@as(usize, 2), a.neighbors().len);
}

test "acceptance checks: level, area (Level 1 only), max areas, loopback, hold floor, not started" {
    var sa: [4]lan.Neighbor = undefined;
    var a = LanCircuit.init(cfg(1, .l1), &sa);
    const base = lan.RxHello{ .snpa = mac(2), .level = .l1, .source_id = sid(2), .holding_time = 30, .circuit_type = .level1_2, .priority = 10, .lan_id = @splat(0), .area_tlvs = &.{&[_]u8{ 3, 0x49, 0, 1 }} };
    try testing.expectEqual(@as(?fsm.RejectReason, .not_started), a.rxHello(base, 0).rejected);
    a.start(0);
    var rx = base;
    rx.level = .l2;
    try testing.expectEqual(@as(?fsm.RejectReason, .level_mismatch), a.rxHello(rx, 0).rejected);
    rx = base;
    rx.circuit_type = .level2;
    try testing.expectEqual(@as(?fsm.RejectReason, .level_mismatch), a.rxHello(rx, 0).rejected);
    rx = base;
    rx.area_tlvs = &.{&[_]u8{ 3, 0x49, 0, 2 }};
    try testing.expectEqual(@as(?fsm.RejectReason, .area_mismatch), a.rxHello(rx, 0).rejected);
    // A shared area in the second #1 TLV is found.
    rx.area_tlvs = &.{ &[_]u8{ 3, 0x49, 0, 2 }, &[_]u8{ 3, 0x49, 0, 1 } };
    try testing.expect(a.rxHello(rx, 0).rejected == null);
    rx = base;
    rx.snpa = mac(5);
    rx.max_area_addresses = 5;
    try testing.expectEqual(@as(?fsm.RejectReason, .max_area_mismatch), a.rxHello(rx, 0).rejected);
    rx = base;
    rx.source_id = sid(1);
    try testing.expectEqual(@as(?fsm.RejectReason, .looped_back), a.rxHello(rx, 0).rejected);
    rx = base;
    rx.snpa = mac(1);
    try testing.expectEqual(@as(?fsm.RejectReason, .looped_back), a.rxHello(rx, 0).rejected);
    rx = base;
    rx.snpa = mac(6);
    rx.holding_time = 0;
    try testing.expectEqual(@as(?fsm.RejectReason, .holding_time_too_short), a.rxHello(rx, 0).rejected);
    try testing.expectEqual(@as(u32, 8), a.counters.rejected_total);

    // Level 2: the area never matters.
    var sb: [4]lan.Neighbor = undefined;
    var b = LanCircuit.init(cfg(1, .l2), &sb);
    b.start(0);
    rx = base;
    rx.level = .l2;
    rx.area_tlvs = &.{&[_]u8{ 3, 0x49, 0, 2 }};
    const e = b.rxHello(rx, 0);
    try testing.expect(e.rejected == null);
    try testing.expectEqual(fsm.Usage.level2, b.find(mac(2)).?.usage);
}

test "a Level 2 hello is the type-16 PDU and a Level 1 machine refuses it on the wire" {
    var sa: [4]lan.Neighbor = undefined;
    var sb: [4]lan.Neighbor = undefined;
    var a1 = LanCircuit.init(cfg(1, .l1), &sa);
    var b2 = LanCircuit.init(cfg(2, .l2), &sb);
    a1.start(0);
    b2.start(0);
    var buf: [400]u8 = undefined;
    const hb = try b2.buildHello(&buf, .{});
    const p = try isis.LanHello.decode(hb);
    try testing.expectEqual(isis.header.PduType.l2_lan_iih, p.header.pdu_type);
    try testing.expectEqual(@as(?fsm.RejectReason, .level_mismatch), (try a1.rxHelloBytes(hb, mac(2), 1)).rejected);
}

test "protocols and IPv4 subnets: no common NLPID or no common subnet is refused" {
    const nets_a = [_]lan.Subnet{.{ .addr = .{ 10, 1, 2, 1 }, .prefix_len = 24 }};
    const nets_b = [_]lan.Subnet{.{ .addr = .{ 10, 1, 2, 7 }, .prefix_len = 24 }};
    const nets_c = [_]lan.Subnet{.{ .addr = .{ 10, 9, 9, 7 }, .prefix_len = 24 }};
    var ca = cfg(1, .l1);
    ca.protocols = &[_]u8{0xCC};
    ca.ipv4_subnets = &nets_a;
    var cb = cfg(2, .l1);
    cb.protocols = &[_]u8{ 0xCC, 0x8E };
    cb.ipv4_subnets = &nets_b;
    var cc = cfg(3, .l1);
    cc.protocols = &[_]u8{0xCC};
    cc.ipv4_subnets = &nets_c;
    var cd = cfg(4, .l1);
    cd.protocols = &[_]u8{0x8E};
    cd.ipv4_subnets = &nets_b;
    var sa: [4]lan.Neighbor = undefined;
    var sb: [4]lan.Neighbor = undefined;
    var sc: [4]lan.Neighbor = undefined;
    var sd: [4]lan.Neighbor = undefined;
    var a = LanCircuit.init(ca, &sa);
    var b = LanCircuit.init(cb, &sb);
    var c = LanCircuit.init(cc, &sc);
    var d = LanCircuit.init(cd, &sd);
    a.start(0);
    b.start(0);
    c.start(0);
    d.start(0);
    try testing.expect((try send(&b, &a, 1)).rejected == null);
    try testing.expectEqual(@as(?fsm.RejectReason, .ip_subnet_mismatch), (try send(&c, &a, 1)).rejected);
    try testing.expectEqual(@as(?fsm.RejectReason, .no_common_protocol), (try send(&d, &a, 1)).rejected);
    try testing.expect(!(lan.Subnet{ .addr = .{ 10, 0, 0, 0 }, .prefix_len = 8 }).contains(.{ 11, 0, 0, 1 }));
    try testing.expect((lan.Subnet{ .addr = .{ 0, 0, 0, 0 }, .prefix_len = 0 }).contains(.{ 11, 0, 0, 1 }));
    try testing.expect((lan.Subnet{ .addr = .{ 1, 2, 3, 4 }, .prefix_len = 32 }).contains(.{ 1, 2, 3, 4 }));
    try testing.expect(!(lan.Subnet{ .addr = .{ 1, 2, 3, 4 }, .prefix_len = 32 }).contains(.{ 1, 2, 3, 5 }));
}

test "authentication: a keyed circuit refuses unsigned and wrongly signed hellos and accepts its own key" {
    const key = isis.auth.Key{ .algorithm = .hmac_sha256, .id = 7, .secret = "lan-secret" };
    const bad = isis.auth.Key{ .algorithm = .hmac_sha256, .id = 7, .secret = "wrong" };
    var ca = cfg(1, .l1);
    ca.auth_keys = &.{key};
    var cb = cfg(2, .l1);
    cb.auth_keys = &.{key};
    const cu = cfg(3, .l1);
    var cw = cfg(4, .l1);
    cw.auth_keys = &.{bad};
    var sa: [4]lan.Neighbor = undefined;
    var sb: [4]lan.Neighbor = undefined;
    var su: [4]lan.Neighbor = undefined;
    var sw: [4]lan.Neighbor = undefined;
    var a = LanCircuit.init(ca, &sa);
    var b = LanCircuit.init(cb, &sb);
    var u = LanCircuit.init(cu, &su);
    var w = LanCircuit.init(cw, &sw);
    a.start(0);
    b.start(0);
    u.start(0);
    w.start(0);
    try testing.expect((try send(&b, &a, 1)).rejected == null);
    try testing.expectEqual(@as(?fsm.RejectReason, .auth_missing), (try send(&u, &a, 1)).rejected);
    try testing.expectEqual(@as(?fsm.RejectReason, .auth_failed), (try send(&w, &a, 1)).rejected);
    try testing.expectEqual(@as(usize, 1), a.neighbors().len);
}

fn restartRx(snpa: lan.Snpa, system: lan.SystemId, priority: u7, rr: bool) lan.RxHello {
    return .{
        .snpa = snpa,
        .level = .l1,
        .source_id = system,
        .holding_time = 30,
        .circuit_type = .level1_2,
        .priority = priority,
        .lan_id = @splat(0),
        .area_tlvs = &.{&[_]u8{ 3, 0x49, 0, 1 }},
        // The restarted neighbour lost its table: it lists nobody.
        .restart = .{ .rr = rr },
    };
}

test "RFC 5306 on a LAN: an RR from an Up neighbour keeps it Up, is acknowledged with its id, and only the top-priority router sends the CSNPs" {
    var sa: [4]lan.Neighbor = undefined;
    var c1 = cfg(1, .l1);
    c1.graceful_restart_helper = true;
    c1.priority = 80;
    var a = LanCircuit.init(c1, &sa);
    a.start(0);
    // Two neighbours brought Up (they list us).
    var listing: [6]u8 = mac(1);
    var up2 = restartRx(mac(2), sid(2), 50, false);
    up2.restart = null;
    up2.neighbor_tlvs = &.{&listing};
    _ = a.rxHello(up2, 0);
    var up3 = restartRx(mac(3), sid(3), 90, false);
    up3.restart = null;
    up3.neighbor_tlvs = &.{&listing};
    _ = a.rxHello(up3, 0);
    try testing.expectEqual(@as(usize, 2), a.upCount());

    // Neighbour 2 restarts: we (80) beat it (50) but neighbour 3 (90) beats us.
    var e = a.rxHello(restartRx(mac(2), sid(2), 50, true), 10);
    try testing.expect(e.event == null);
    try testing.expectEqual(lan.NeighborState.up, a.find(mac(2)).?.state);
    try testing.expectEqual(@as(?lan.SystemId, sid(2)), e.ack);
    try testing.expect(!e.send_csnp);
    try testing.expect(a.find(mac(2)).?.helper.restart_mode);
    try testing.expectEqual(@as(Time, 40), a.find(mac(2)).?.hold_deadline);
    // A second RR does not refresh the hold.
    _ = a.rxHello(restartRx(mac(2), sid(2), 50, true), 20);
    try testing.expectEqual(@as(Time, 40), a.find(mac(2)).?.hold_deadline);

    // Neighbour 3 (the top priority) restarts: now we are the highest among the
    // Up neighbours not in restart mode (neighbour 2 is in restart mode).
    e = a.rxHello(restartRx(mac(3), sid(3), 90, true), 21);
    try testing.expect(e.send_csnp);

    // The ack hello carries the Restart TLV with RA, the id and the remaining time.
    var buf: [400]u8 = undefined;
    const ack = try a.buildAck(&buf, sid(3), 21);
    const p = try isis.LanHello.decode(ack);
    const v = (try isis.tlv.findFirst(p.tlv_bytes, 211)).?;
    const r = try lan.Restart.decode(v);
    try testing.expect(r.ra and !r.rr);
    try testing.expectEqual(@as(?lan.SystemId, sid(3)), r.neighbor_id);
    try testing.expectEqual(@as(?u16, 30), r.remaining_time);

    // RR clear ends the restart mode (the neighbour now lists us again).
    var back = restartRx(mac(2), sid(2), 50, false);
    back.restart = .{};
    back.neighbor_tlvs = &.{&listing};
    _ = a.rxHello(back, 22);
    try testing.expect(!a.find(mac(2)).?.helper.restart_mode);

    // RR from an unknown SNPA: processed normally, still answered.
    e = a.rxHello(restartRx(mac(9), sid(9), 10, true), 23);
    try testing.expectEqual(@as(?lan.SystemId, sid(9)), e.ack);
    try testing.expectEqual(lan.EventKind.new_neighbor, e.event.?.kind);
}

test "SA on a LAN suppresses the neighbour until the flag clears" {
    var sa: [4]lan.Neighbor = undefined;
    var c1 = cfg(1, .l1);
    c1.graceful_restart_helper = true;
    var a = LanCircuit.init(c1, &sa);
    a.start(0);
    var rx = restartRx(mac(2), sid(2), 50, false);
    rx.restart = .{ .sa = true };
    var e = a.rxHello(rx, 0);
    try testing.expect(e.suppress.?.on);
    e = a.rxHello(rx, 1);
    try testing.expect(e.suppress == null);
    rx.restart = .{};
    e = a.rxHello(rx, 2);
    try testing.expect(!e.suppress.?.on);
}

test "hello building: IS Neighbours splits at 42 SNPAs, padding is exact, ours are listed" {
    var storage: [60]lan.Neighbor = undefined;
    var c1 = cfg(1, .l1);
    c1.hello_padding = .always;
    c1.mtu = 800;
    var a = LanCircuit.init(c1, &storage);
    a.start(0);
    for (0..50) |i| {
        const rx = lan.RxHello{ .snpa = .{ 0xbb, 0, 0, 0, 0, @intCast(i) }, .level = .l1, .source_id = sid(@intCast(100 + i)), .holding_time = 30, .circuit_type = .level1_2, .priority = 1, .lan_id = @splat(0), .area_tlvs = &.{&[_]u8{ 3, 0x49, 0, 1 }} };
        try testing.expect(a.rxHello(rx, 0).rejected == null);
    }
    var buf: [1500]u8 = undefined;
    const hb = try a.buildHello(&buf, .{});
    try testing.expectEqual(@as(usize, 800), hb.len);
    const p = try isis.LanHello.decode(hb);
    var it = p.tlvIterator();
    var tlvs: usize = 0;
    var snpas: usize = 0;
    var areas: usize = 0;
    while (try it.next()) |raw| {
        if (raw.code == isis.tlvs.code.is_neighbours_iih) {
            tlvs += 1;
            snpas += raw.value.len / 6;
        }
        if (raw.code == isis.tlvs.code.area_addresses) areas += 1;
    }
    try testing.expectEqual(@as(usize, 2), tlvs);
    try testing.expectEqual(@as(usize, 50), snpas);
    try testing.expectEqual(@as(usize, 1), areas);
    try testing.expectEqual(@as(u7, 64), p.priority);
    try testing.expectEqual(sid(1) ++ [_]u8{1}, p.lan_id);
}
