// SPDX-License-Identifier: MIT
//! isis-adj — the IS-IS point-to-point adjacency state machine (ISO/IEC 10589
//! §8.2 + RFC 5303 three-way handshake): a pure, time-injected FSM that drives
//! one P2P neighbour Down → Initializing → Up from received IIH PDUs (decoded
//! by the sibling `isis` codec) and hold-timer expiry. No threads, no owned
//! timers, no sockets — the caller supplies `now` and the received PDUs and
//! acts on the emitted transitions/effects. LAN adjacency + DIS election are a
//! later increment (E-Line/P2P is the current fabric phase).
//!
//! ## Layers
//! - `three_way` — the RFC 5303 Point-to-Point Three-Way Adjacency TLV (type
//!   240) codec. `isis` does not model 240 typed; it reaches us as a raw TLV and
//!   this file parses/emits its value with the same bounds-checked discipline.
//! - `fsm` — the `Adjacency` state machine itself: `start`/`stop`, `rxHello` /
//!   `rxHelloBytes`, `tick`, the hold/hello timing, and the `Effect` the caller
//!   acts on.
//!
//! ## Time-injection contract
//! The FSM never reads a clock. Every entry point that cares about time takes a
//! caller-supplied monotonic `now: Time` (abstract ticks in the caller's own
//! unit); `holding_time` and `hello_interval` are in that same unit. Given the
//! same `(event, now)` stream the FSM is fully deterministic — the same
//! transitions and effects, every run (a permanent test pins this).
//!
//! Provenance: clean-room from ISO/IEC 10589 §8.2 and RFC 5303; no third-party
//! implementation consulted. See /NOTICE (no entry required — public specs).

const std = @import("std");
const isis = @import("isis");

pub const meta = .{
    .targets = .{.linux64},
    .platform = .any,
    .role = .util,
    .concurrency = .single_owner,
    .model_after = "ISO/IEC 10589 §8.2 P2P adjacency + RFC 5303 three-way handshake",
    .deps = .{"isis"},
};

pub const three_way = @import("three_way.zig");
pub const fsm = @import("fsm.zig");

// ── the most-used surface, re-exported ───────────────────────────────────────
pub const Adjacency = fsm.Adjacency;
pub const Config = fsm.Config;
pub const State = fsm.State;
pub const Effect = fsm.Effect;
pub const Transition = fsm.Transition;
pub const DownReason = fsm.DownReason;
pub const RejectReason = fsm.RejectReason;
pub const HelloFields = fsm.HelloFields;
pub const RxHello = fsm.RxHello;
pub const Time = fsm.Time;
pub const SystemId = fsm.SystemId;
pub const buildHello = fsm.buildHello;

pub const ThreeWayState = three_way.ThreeWayState;
pub const ThreeWayTlv = three_way.ThreeWayTlv;

// ── integration tests: the whole pipeline against itself ─────────────────────

const testing = std.testing;
const sys_a: SystemId = .{ 0, 0, 0, 0, 0, 0xA };
const sys_b: SystemId = .{ 0, 0, 0, 0, 0, 0xB };

fn cfg(sid: SystemId, ext: u32) Config {
    return .{ .system_id = sid, .extended_local_circuit_id = ext, .hello_interval = 10 };
}

fn wire(buf: []u8, hf: HelloFields) []const u8 {
    return buildHello(buf, hf) catch unreachable;
}

// The core proof: two independent FSMs, each fed ONLY the other's serialized
// IIH bytes (full `isis` encode → `rxHelloBytes` decode round-trip), converge
// to Up on both with the exact transition sequence Down → Initializing → Up,
// and the three-way state on the wire progresses in lockstep.
test "mutual drive: A and B handshake Down->Init->Up on both" {
    var a = Adjacency.init(cfg(sys_a, 0xA1));
    var b = Adjacency.init(cfg(sys_b, 0xB1));

    var a_seq: [8]State = undefined;
    var an: usize = 0;
    var b_seq: [8]State = undefined;
    var bn: usize = 0;

    var abuf: [128]u8 = undefined;
    var bbuf: [128]u8 = undefined;

    // t = 0: both circuits come up and emit their first IIH (state Down, no
    // neighbour block — neither has heard the other yet).
    var wa = wire(&abuf, a.start(0).send_hello.?);
    var wb = wire(&bbuf, b.start(0).send_hello.?);
    a_seq[an] = a.currentState();
    an += 1;
    b_seq[bn] = b.currentState();
    bn += 1;

    var t: Time = 1;
    var round: usize = 0;
    while (round < 6 and !(a.currentState() == .up and b.currentState() == .up)) : (round += 1) {
        const ea = try a.rxHelloBytes(wb, t);
        const eb = try b.rxHelloBytes(wa, t);
        if (ea.transition) |tr| {
            a_seq[an] = tr.to;
            an += 1;
        }
        if (eb.transition) |tr| {
            b_seq[bn] = tr.to;
            bn += 1;
        }
        // Each side re-emits an IIH reflecting its new state (now carrying the
        // neighbour echo once it has heard the far end).
        wa = wire(&abuf, a.helloFields());
        wb = wire(&bbuf, b.helloFields());
        t += 1;
    }

    try testing.expectEqual(State.up, a.currentState());
    try testing.expectEqual(State.up, b.currentState());
    try testing.expectEqualSlices(State, &.{ .down, .initializing, .up }, a_seq[0..an]);
    try testing.expectEqualSlices(State, &.{ .down, .initializing, .up }, b_seq[0..bn]);

    // The last IIH each emitted advertises the Up wire-state and a full neighbour
    // echo — the completed handshake on the wire.
    try testing.expectEqual(ThreeWayState.up, a.helloFields().three_way.state);
    try testing.expect(a.helloFields().three_way.neighbor != null);
    try testing.expectEqual(sys_a, b.helloFields().three_way.neighbor.?.system_id);
}

test "determinism: the same (event, now) stream yields identical transitions" {
    const Run = struct {
        fn drive() [3]State {
            var a = Adjacency.init(cfg(sys_a, 0xA1));
            var b = Adjacency.init(cfg(sys_b, 0xB1));
            var abuf: [128]u8 = undefined;
            var bbuf: [128]u8 = undefined;
            var seq: [3]State = .{ .down, .down, .down };
            var wa = wire(&abuf, a.start(0).send_hello.?);
            var wb = wire(&bbuf, b.start(0).send_hello.?);
            seq[0] = a.currentState();
            var i: usize = 1;
            var t: Time = 1;
            while (i < 3) : (i += 1) {
                _ = a.rxHelloBytes(wb, t) catch unreachable;
                _ = b.rxHelloBytes(wa, t) catch unreachable;
                seq[i] = a.currentState();
                wa = wire(&abuf, a.helloFields());
                wb = wire(&bbuf, b.helloFields());
                t += 1;
            }
            return seq;
        }
    };
    try testing.expectEqual(Run.drive(), Run.drive());
    try testing.expectEqual([3]State{ .down, .initializing, .up }, Run.drive());
}

// Permanent positive control (CONVENTIONS/brief): deliberately break the
// three-way check by dropping `three_way_required`, feed the SAME half-open
// hello that the guard test proves keeps a correct FSM at Initializing, and
// show it wrongly reaches Up. If the guard in `rxHello` were removed, the
// three-way-guard unit test (`fsm.zig`) would see this Up and go RED — this
// test is what proves that guard has teeth.
test "positive control: without the three-way guard a half-open hello reaches Up" {
    // half-open hello: neighbour advertises a state + its ext id but NO neighbour
    // block — it has not confirmed hearing us.
    const half_open: RxHello = .{
        .source_id = sys_b,
        .holding_time = 30,
        .circuit_type = .level1_2,
        .local_circuit_id = 1,
        .three_way = .{ .state = .initializing, .extended_local_circuit_id = 0xB1 },
    };

    // Correct FSM (guard on): stays Initializing.
    var guarded = Adjacency.init(.{ .system_id = sys_a, .extended_local_circuit_id = 0xA1 });
    _ = guarded.start(0);
    _ = guarded.rxHello(half_open, 1);
    try testing.expectEqual(State.initializing, guarded.currentState());

    // Broken FSM (guard off): same input wrongly reaches Up.
    var broken = Adjacency.init(.{ .system_id = sys_a, .extended_local_circuit_id = 0xA1, .three_way_required = false });
    _ = broken.start(0);
    const e = broken.rxHello(half_open, 1);
    try testing.expectEqual(State.up, broken.currentState());
    try testing.expect(e.adjacency_up);
}

// ── External anchor: Wireshark 4.6.4 (sharkd, via scripts/dissect.py) ────────
//
// Every vector below was produced by THIS module's own `buildHello`/`helloFields`
// (or, for the 11-octet case, hand-built to the RFC-legal shape Wireshark
// decodes) and fed through Wireshark's real IS-IS dissector — not hand-derived
// expected values. See `three_way.zig`'s file docs for the full reasoning on
// the 11-octet shape (a real bug this task found: the codec used to reject it
// as `BadLength`).

// Command:
//   scripts/dissect.py --frame llc --fields '83 14 01 06 11 01 00 03 03 00 00
//   00 00 00 0a 00 1b 00 1b 03 f0 05 02 00 00 00 a1'
//
// Wireshark printed (trimmed to the load-bearing lines):
//   isis.type == 17 = ...1 0001 = PDU Type: P2P HELLO (17)
//   isis.hello.circuit_type == 0x03 = Circuit type: Level 1 and 2 (0x3)
//   isis.hello.source_id == 0000.0000.000a
//   isis.hello.holding_timer == 27 = Holding timer: 27
//   isis.hello.pdu_length == 27 = PDU length: 27
//   isis.hello.local_circuit_id == 3 = Local circuit ID: 3
//   frame[37:7] == f0:05:02:00:00:00:a1 = Point-to-point Adjacency State (t=240, l=5)
//   isis.hello.adjacency_state == 2 = Adjacency State: Down (2)
//   isis.hello.extended_local_circuit_id == 0x000000a1
const golden_p2p_hello_down_5 = [_]u8{
    0x83, 0x14, 0x01, 0x06, 0x11, 0x01, 0x00, 0x03,
    0x03, 0x00, 0x00, 0x00, 0x00, 0x00, 0x0a, 0x00,
    0x1b, 0x00, 0x1b, 0x03, 0xf0, 0x05, 0x02, 0x00,
    0x00, 0x00, 0xa1,
};

test "golden P2P Hello (Wireshark-anchored): our own start() reproduces the exact bytes" {
    var buf: [128]u8 = undefined;
    var a = Adjacency.init(.{
        .system_id = sys_a,
        .extended_local_circuit_id = 0xA1,
        .circuit_type = .level1_2,
        .holding_time = 27,
        .local_circuit_id = 3,
    });
    const e = a.start(0);
    const w = try buildHello(&buf, e.send_hello.?);
    try testing.expectEqualSlices(u8, &golden_p2p_hello_down_5, w);
}

// Command:
//   scripts/dissect.py --frame llc --fields '83 14 01 06 11 01 00 03 03 00 00
//   00 00 00 0a 00 1b 00 25 03 f0 0f 01 00 00 00 a1 00 00 00 00 00 0b 00 00
//   00 b1'
//
// Wireshark printed:
//   isis.hello.pdu_length == 37
//   frame[37:17] == f0:0f:... = Point-to-point Adjacency State (t=240, l=15)
//   isis.hello.adjacency_state == 1 = Adjacency State: Initializing (1)
//   isis.hello.extended_local_circuit_id == 0x000000a1
//   isis.hello.neighbor_systemid == 0000.0000.000b
//   isis.hello.neighbor_extended_local_circuit_id == 0x000000b1
const golden_p2p_hello_init_15 = [_]u8{
    0x83, 0x14, 0x01, 0x06, 0x11, 0x01, 0x00, 0x03,
    0x03, 0x00, 0x00, 0x00, 0x00, 0x00, 0x0a, 0x00,
    0x1b, 0x00, 0x25, 0x03, 0xf0, 0x0f, 0x01, 0x00,
    0x00, 0x00, 0xa1, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x0b, 0x00, 0x00, 0x00, 0xb1,
};

test "golden P2P Hello (Wireshark-anchored): rxHelloBytes+helloFields reproduce the exact bytes after hearing B" {
    var abuf: [128]u8 = undefined;
    var bbuf: [128]u8 = undefined;
    var a = Adjacency.init(.{ .system_id = sys_a, .extended_local_circuit_id = 0xA1, .circuit_type = .level1_2, .holding_time = 27, .local_circuit_id = 3 });
    _ = a.start(0);
    // B heard A but has not echoed A yet (no neighbour block on B's side).
    const b_wire = try buildHello(&bbuf, .{
        .source_id = sys_b,
        .holding_time = 30,
        .local_circuit_id = 1,
        .circuit_type = .level1_2,
        .three_way = .{ .state = .initializing, .extended_local_circuit_id = 0xB1 },
    });
    const e = try a.rxHelloBytes(b_wire, 1);
    try testing.expectEqual(State.initializing, a.currentState());
    try testing.expect(e.adjacency_up == false);
    const w = try buildHello(&abuf, a.helloFields());
    try testing.expectEqualSlices(u8, &golden_p2p_hello_init_15, w);
}

// Command:
//   scripts/dissect.py --frame llc --fields '83 14 01 06 11 01 00 03 03 00 00
//   00 00 00 0b 00 1b 00 21 01 f0 0b 01 00 00 00 b1 00 00 00 00 00 0a'
//
// Wireshark printed:
//   isis.hello.source_id == 0000.0000.000b = SystemID {Sender of PDU}
//   isis.hello.pdu_length == 33 = PDU length: 33
//   frame[37:13] == f0:0b:... = Point-to-point Adjacency State (t=240, l=11)
//   isis.hello.clv.length == 11 = Length: 11
//   isis.hello.adjacency_state == 1 = Adjacency State: Initializing (1)
//   isis.hello.extended_local_circuit_id == 0x000000b1
//   isis.hello.neighbor_systemid == 0000.0000.000a
//   (no neighbor_extended_local_circuit_id line — absent at length 11)
//
// This is the real bug this task found: B's TLV 240 names OUR (A's) system-id
// as its neighbour WITHOUT knowing our extended-local-circuit-id — a legal
// wire shape per RFC 5303 §3.1 and Wireshark's independent dissector — but our
// codec used to reject the *whole PDU* as `error.BadLength`. It now decodes
// cleanly, and (see fsm.zig) the FSM correctly still refuses to call this an
// echo — a bare system-id cannot disambiguate parallel circuits to the same
// neighbour — so A's adjacency stays at Initializing rather than either
// erroring out or wrongly reaching Up.
const golden_p2p_hello_240_11 = [_]u8{
    0x83, 0x14, 0x01, 0x06, 0x11, 0x01, 0x00, 0x03,
    0x03, 0x00, 0x00, 0x00, 0x00, 0x00, 0x0b, 0x00,
    0x1b, 0x00, 0x21, 0x01, 0xf0, 0x0b, 0x01, 0x00,
    0x00, 0x00, 0xb1, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x0a,
};

test "golden P2P Hello with 11-octet TLV240 (Wireshark-anchored): rxHelloBytes decodes it and does NOT treat it as echoed" {
    var a = Adjacency.init(.{ .system_id = sys_a, .extended_local_circuit_id = 0xA1 });
    _ = a.start(0);
    const e = try a.rxHelloBytes(&golden_p2p_hello_240_11, 1);
    try testing.expectEqual(State.initializing, a.currentState());
    try testing.expect(e.adjacency_up == false);
}

// ── fuzz: hostile IIH bytes must never panic and never corrupt the FSM ───────

test "fuzz: rxHelloBytes on hostile bytes never panics; a rejected PDU is inert" {
    try std.testing.fuzz({}, fuzzRx, .{});
}

fn fuzzRx(_: void, smith: *std.testing.Smith) !void {
    var buf: [128]u8 = undefined;
    smith.bytes(&buf);
    const len: usize = smith.valueRangeAtMost(u8, 0, @intCast(buf.len));
    const input = buf[0..len];

    // Bias toward a valid-looking P2P IIH header so deeper paths are reached.
    if (len >= 20 and smith.value(bool)) {
        buf[0] = 0x83; // discriminator
        buf[1] = 20; // length indicator (P2P IIH fixed header)
        buf[2] = 1; // version
        buf[3] = 0; // id length 0 => 6
        buf[4] = 17; // p2p_iih
        buf[5] = 1; // version
    }

    var adj = Adjacency.init(.{ .system_id = sys_a, .extended_local_circuit_id = 0xA1 });
    _ = adj.start(0);
    const before = adj.currentState();
    if (adj.rxHelloBytes(input, 1)) |_| {
        // Accepted or rejected — either way the state is one of the three legal
        // values (guaranteed by the enum) and the FSM did not panic.
    } else |_| {
        // A decode error must be inert: it mutates nothing.
        try std.testing.expectEqual(before, adj.currentState());
    }
}

test {
    std.testing.refAllDecls(@This());
    _ = @import("three_way.zig");
    _ = @import("fsm.zig");
}
