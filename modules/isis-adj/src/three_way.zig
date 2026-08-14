// SPDX-License-Identifier: MIT

//! The RFC 5303 Point-to-Point Three-Way Adjacency TLV (type 240) codec.
//!
//! `isis` (the sibling PDU codec) does not model TLV 240 typed — its `tlvs.code`
//! set stops at the SPB TLVs — so a P2P IIH carrying a 240 exposes it only as a
//! `tlv.RawTlv` via the raw escape hatch. This file is the small, bounds-checked
//! parser/emitter for that one value, kept out of `isis` proper because 240 is an
//! adjacency-FSM concern, not a generic wire concern.
//!
//! ## Wire format (RFC 5303 §3, the "Adjacency Three-Way State" option)
//! The TLV value is, in order:
//!
//! | Field                              | Octets | Presence            |
//! |------------------------------------|--------|---------------------|
//! | Adjacency Three-Way State          | 1      | always              |
//! | Extended Local Circuit ID          | 4      | when value ≥ 5      |
//! | Neighbour System ID                | 6      | when value ≥ 11     |
//! | Neighbour Extended Local Circuit ID| 4      | when value == 15    |
//!
//! So four value lengths are well-formed for the modeled 6-octet system id:
//! **1**, **5**, **11**, and **15**. Any other length is `error.BadLength`.
//!
//! CORRECTION (Wireshark-anchored, see below): an earlier revision of this file
//! claimed exactly three lengths (1/5/15), reading the neighbour block as
//! all-or-nothing. RFC 5303 §3.1's own syntax gives `Length` as "1 to 17 octets"
//! and defines the four fields with independent presence ("if known" for each of
//! the two neighbour fields separately) — consistent with 1, 5, 5+idlen, and
//! 5+idlen+4, not just 1/5/15. Wireshark 4.6.4's IS-IS dissector
//! (`packet-isis-hello.c`, `dissect_hello_ptp_adj_clv`) hardcodes exactly these
//! four cases (1/5/11/15 for the default 6-octet system id) and decodes the
//! 11-octet form as Neighbour System ID present WITHOUT a Neighbour Extended
//! Local Circuit ID — proof, from an independent implementation, that the
//! all-or-nothing reading of the neighbour block was wrong. Verified via:
//!
//!     scripts/dissect.py --frame llc --fields '83 14 01 06 11 01 00 03 03 00
//!     00 00 00 00 0a 00 1b 00 21 03 f0 0b 00 00 00 00 a1 00 00 00 00 00 0b'
//!
//! Wireshark printed (trimmed to the load-bearing lines):
//!     frame[37:13] == f0:0b:... = Point-to-point Adjacency State (t=240, l=11)
//!     isis.hello.clv.length == 11 = Length: 11
//!     isis.hello.adjacency_state == 0 = Adjacency State: Up (0)
//!     isis.hello.extended_local_circuit_id == 0x000000a1
//!     isis.hello.neighbor_systemid == 0000.0000.000b = Neighbor SystemID: ...
//! (no `neighbor_extended_local_circuit_id` line — absent at length 11, exactly
//! as `packet-isis-hello.c` decodes it). See `fsm.zig` for why the FSM still
//! treats a neighbour block with no extended-circuit-id as an unconfirmed echo
//! (it cannot disambiguate parallel circuits to the same neighbour system).
//!
//! ## Three-way state encoding — NOTE the values
//! RFC 5303 numbers the state field **Up = 0, Initializing = 1, Down = 2** — the
//! *reverse* of the intuitive "Down-first" ordering. This is a common source of
//! off-by-one bugs; `ThreeWayState` pins the exact wire values.

const std = @import("std");

/// The IANA/RFC 5303 code point for the Point-to-Point Three-Way Adjacency TLV.
pub const tlv_code: u8 = 240;

/// The system-id length this codec models (matches `isis`'s modeled 6 octets).
pub const system_id_len: usize = 6;

/// The "Adjacency Three-Way State" field (RFC 5303 §3). The numeric values are
/// the on-the-wire encoding and are NOT in intuitive order: `up == 0`.
pub const ThreeWayState = enum(u8) {
    up = 0,
    initializing = 1,
    down = 2,

    /// Decode the 1-octet state field; an unassigned value is a typed error
    /// rather than an illegal `@enumFromInt`.
    pub fn fromByte(b: u8) error{BadState}!ThreeWayState {
        return switch (b) {
            0 => .up,
            1 => .initializing,
            2 => .down,
            else => error.BadState,
        };
    }
};

pub const DecodeError = error{
    /// The value length is not one of the four well-formed sizes (1, 5, 11, 15).
    BadLength,
    /// The 1-octet state field holds an unassigned value.
    BadState,
};

/// A neighbour reference: the system-id a router echoes back to prove it has
/// heard the far end, plus — when the sender also knows it — the far end's
/// extended-local-circuit-id, which disambiguates which of possibly several
/// parallel circuits to that system this echo refers to.
/// `extended_local_circuit_id == null` is the 11-octet wire shape (Wireshark-
/// anchored, see the file docs); the FSM (`fsm.zig`) treats it as an
/// unconfirmed echo, since a bare system-id cannot disambiguate parallel
/// circuits to the same neighbour.
pub const Neighbor = struct {
    system_id: [system_id_len]u8,
    extended_local_circuit_id: ?u32 = null,
};

/// A decoded / to-be-encoded TLV 240 value. `extended_local_circuit_id` is
/// present for the 5-, 11- and 15-octet forms; `neighbor` for the 11- and
/// 15-octet forms (with its own `extended_local_circuit_id` present only in the
/// 15-octet form).
pub const ThreeWayTlv = struct {
    state: ThreeWayState,
    extended_local_circuit_id: ?u32 = null,
    neighbor: ?Neighbor = null,

    /// Parse a raw TLV 240 value (the bytes after code+length). Zero-copy in the
    /// sense that it reads fixed offsets only; never over-reads (the length is
    /// checked against the four legal sizes first).
    pub fn decode(value: []const u8) DecodeError!ThreeWayTlv {
        switch (value.len) {
            1 => return .{ .state = try ThreeWayState.fromByte(value[0]) },
            5 => return .{
                .state = try ThreeWayState.fromByte(value[0]),
                .extended_local_circuit_id = std.mem.readInt(u32, value[1..5], .big),
            },
            11 => return .{
                .state = try ThreeWayState.fromByte(value[0]),
                .extended_local_circuit_id = std.mem.readInt(u32, value[1..5], .big),
                .neighbor = .{ .system_id = value[5..11].* },
            },
            15 => return .{
                .state = try ThreeWayState.fromByte(value[0]),
                .extended_local_circuit_id = std.mem.readInt(u32, value[1..5], .big),
                .neighbor = .{
                    .system_id = value[5..11].*,
                    .extended_local_circuit_id = std.mem.readInt(u32, value[11..15], .big),
                },
            },
            else => return error.BadLength,
        }
    }

    /// The number of value octets `encode` will write (1, 5, 11, or 15).
    pub fn encodedLen(self: ThreeWayTlv) usize {
        if (self.neighbor) |nb| return if (nb.extended_local_circuit_id != null) 15 else 11;
        if (self.extended_local_circuit_id != null) return 5;
        return 1;
    }

    /// Serialize the value into `out` (which must be ≥ `encodedLen()`), returning
    /// the written slice. A `neighbor` without an outer `extended_local_circuit_id`
    /// is a programming error (the wire format has no such shape, the neighbour
    /// block always sits after it) and is rejected.
    pub fn encode(self: ThreeWayTlv, out: []u8) error{ BufferTooSmall, MalformedTlv }![]const u8 {
        const n = self.encodedLen();
        if (out.len < n) return error.BufferTooSmall;
        if (self.neighbor != null and self.extended_local_circuit_id == null) return error.MalformedTlv;
        out[0] = @intFromEnum(self.state);
        if (self.extended_local_circuit_id) |ext| {
            std.mem.writeInt(u32, out[1..5], ext, .big);
        }
        if (self.neighbor) |nb| {
            @memcpy(out[5..11], &nb.system_id);
            if (nb.extended_local_circuit_id) |nb_ext| {
                std.mem.writeInt(u32, out[11..15], nb_ext, .big);
            }
        }
        return out[0..n];
    }
};

// ── tests ───────────────────────────────────────────────────────────────────

const testing = std.testing;

test "three-way state wire values are RFC 5303 (up==0, down==2)" {
    try testing.expectEqual(@as(u8, 0), @intFromEnum(ThreeWayState.up));
    try testing.expectEqual(@as(u8, 1), @intFromEnum(ThreeWayState.initializing));
    try testing.expectEqual(@as(u8, 2), @intFromEnum(ThreeWayState.down));
    try testing.expectEqual(ThreeWayState.up, try ThreeWayState.fromByte(0));
    try testing.expectEqual(ThreeWayState.down, try ThreeWayState.fromByte(2));
    try testing.expectError(error.BadState, ThreeWayState.fromByte(3));
}

test "TLV 240 round-trips the 1, 5, 11 and 15 octet forms" {
    var buf: [16]u8 = undefined;

    // state-only (1 octet)
    const t1: ThreeWayTlv = .{ .state = .down };
    const w1 = try t1.encode(&buf);
    try testing.expectEqual(@as(usize, 1), w1.len);
    try testing.expectEqual(t1, try ThreeWayTlv.decode(w1));

    // state + extended local circuit id (5 octets)
    const t5: ThreeWayTlv = .{ .state = .initializing, .extended_local_circuit_id = 0xAABBCCDD };
    const w5 = try t5.encode(&buf);
    try testing.expectEqual(@as(usize, 5), w5.len);
    try testing.expectEqual(t5, try ThreeWayTlv.decode(w5));

    // neighbour system-id WITHOUT its extended-local-circuit-id (11 octets) —
    // Wireshark-anchored shape, see the file docs.
    const t11: ThreeWayTlv = .{
        .state = .up,
        .extended_local_circuit_id = 0xA1,
        .neighbor = .{ .system_id = .{ 0, 0, 0, 0, 0, 0xB } },
    };
    const w11 = try t11.encode(&buf);
    try testing.expectEqual(@as(usize, 11), w11.len);
    const d11 = try ThreeWayTlv.decode(w11);
    try testing.expectEqual(t11.state, d11.state);
    try testing.expectEqual(t11.extended_local_circuit_id, d11.extended_local_circuit_id);
    try testing.expectEqual(@as(u8, 0xB), d11.neighbor.?.system_id[5]);
    try testing.expectEqual(@as(?u32, null), d11.neighbor.?.extended_local_circuit_id);

    // full (15 octets) with neighbour echo
    const t15: ThreeWayTlv = .{
        .state = .up,
        .extended_local_circuit_id = 7,
        .neighbor = .{ .system_id = .{ 0, 0, 0, 0, 0, 9 }, .extended_local_circuit_id = 42 },
    };
    const w15 = try t15.encode(&buf);
    try testing.expectEqual(@as(usize, 15), w15.len);
    const d15 = try ThreeWayTlv.decode(w15);
    try testing.expectEqual(t15.state, d15.state);
    try testing.expectEqual(t15.extended_local_circuit_id, d15.extended_local_circuit_id);
    try testing.expectEqual(@as(u32, 42), d15.neighbor.?.extended_local_circuit_id.?);
    try testing.expectEqual(@as(u8, 9), d15.neighbor.?.system_id[5]);
}

// External anchor: Wireshark 4.6.4 (sharkd, via scripts/dissect.py) — the
// 11-octet shape above was not a hypothesis, it is what an independent
// dissector's hardcoded length switch (`packet-isis-hello.c`,
// `dissect_hello_ptp_adj_clv`: `case 1/5/11/15`) actually decodes.
//
// Command:
//   scripts/dissect.py --frame llc --fields '83 14 01 06 11 01 00 03 03 00
//   00 00 00 00 0a 00 1b 00 21 03 f0 0b 00 00 00 00 a1 00 00 00 00 00 0b'
//
// Wireshark printed (trimmed to the load-bearing lines):
//   frame[37:13] == f0:0b:00:00:00:00:a1:00:00:00:00:00:0b = Point-to-point
//     Adjacency State (t=240, l=11)
//   isis.hello.clv.length == 11 = Length: 11
//   isis.hello.adjacency_state == 0 = Adjacency State: Up (0)
//   isis.hello.extended_local_circuit_id == 0x000000a1
//   isis.hello.neighbor_systemid == 0000.0000.000b = Neighbor SystemID: ...
// (no `neighbor_extended_local_circuit_id` field printed for length 11 — it is
// genuinely absent at this length, per Wireshark, not merely zero.)
test "golden TLV240 11-octet form (Wireshark-anchored): decode matches what Wireshark printed" {
    // The 240-value bytes Wireshark parsed above (offset 37, length 13 incl.
    // type+length octets -> value is the trailing 11).
    const golden_240_11 = [_]u8{ 0x00, 0x00, 0x00, 0x00, 0xa1, 0x00, 0x00, 0x00, 0x00, 0x00, 0x0b };
    const d = try ThreeWayTlv.decode(&golden_240_11);
    try testing.expectEqual(ThreeWayState.up, d.state);
    try testing.expectEqual(@as(u32, 0xA1), d.extended_local_circuit_id.?);
    try testing.expectEqual([6]u8{ 0, 0, 0, 0, 0, 0xB }, d.neighbor.?.system_id);
    try testing.expectEqual(@as(?u32, null), d.neighbor.?.extended_local_circuit_id);
}

// ── External anchor: the 1-octet (state-only) form, the OTHER direction ─────
//
// the anchor record's remnant for this module (`SPEC.md` § Anchoring): every golden above was produced by
// THIS module's own `buildHello`/`helloFields` and then checked against
// Wireshark. The 1-octet (state-only) TLV 240 shape is never emitted by that
// API — `fsm.zig`'s `helloFields` always sets `extended_local_circuit_id` from
// `cfg`, so the encoder only ever writes the 5/11/15-octet forms — so there is
// nothing of *our own construction* to hand to `dissect.py` for that shape.
//
// The honest anchor runs the other direction instead: hand a bare 1-octet
// TLV 240 value to Wireshark's dissector AND to this module's own `decode`,
// and check the two independent readings agree. This is NOT a case of "the
// shape isn't anchorable" — Wireshark's `packet-isis-hello.c` DOES model
// length 1 explicitly (its length switch is exactly 1/5/11/15, matching this
// codec's `DecodeError.BadLength` boundary), so the comparison is real.
//
// Command (a full P2P Hello carrying a length-1 TLV 240 with state = Down):
//   scripts/dissect.py --frame llc --fields '83 14 01 06 11 01 00 03 03 00 00
//   00 00 00 0a 00 1b 00 17 03 f0 01 02'
//
// Wireshark printed (verbatim, trimmed to the load-bearing lines):
//   frame.protocols == "eth:llc:osi:isis:isis.hello" (full Hello dissection,
//     not a generic/"data" fallback)
//   isis.hello.pdu_length == 23 = PDU length: 23
//   frame[37:3] == f0:01:02 = Point-to-point Adjacency State (t=240, l=1)
//   isis.hello.clv.type == 240 = Type: 240
//   isis.hello.clv.length == 1 = Length: 1
//   isis.hello.adjacency_state == 2 = Adjacency State: Down (2)
// (no extended_local_circuit_id / neighbor_systemid lines — correctly absent
// at length 1, matching this codec's `ThreeWayTlv.decode` 1-octet case which
// sets only `state` and leaves `extended_local_circuit_id`/`neighbor` null.)
test "golden TLV240 1-octet (state-only) form (Wireshark-anchored, reverse direction): our decode agrees with Wireshark, though our own encoder never emits this shape" {
    const golden_240_1 = [_]u8{0x02}; // Down
    const d = try ThreeWayTlv.decode(&golden_240_1);
    try testing.expectEqual(ThreeWayState.down, d.state);
    try testing.expectEqual(@as(?u32, null), d.extended_local_circuit_id);
    try testing.expectEqual(@as(?Neighbor, null), d.neighbor);
}

test "TLV 240 rejects bad length and bad state, never over-reads" {
    try testing.expectError(error.BadLength, ThreeWayTlv.decode(&.{})); // empty
    try testing.expectError(error.BadLength, ThreeWayTlv.decode(&[_]u8{ 0, 1 })); // 2 octets
    try testing.expectError(error.BadLength, ThreeWayTlv.decode(&[_]u8{0} ** 12)); // 12 octets
    // 5-octet form with an illegal state value.
    try testing.expectError(error.BadState, ThreeWayTlv.decode(&[_]u8{ 9, 0, 0, 0, 0 }));
}

test "encode rejects a neighbour block without an extended circuit id" {
    var buf: [16]u8 = undefined;
    const bad: ThreeWayTlv = .{
        .state = .up,
        .extended_local_circuit_id = null,
        .neighbor = .{ .system_id = @splat(0), .extended_local_circuit_id = 1 },
    };
    try testing.expectError(error.MalformedTlv, bad.encode(&buf));
}
