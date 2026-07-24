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
//! | Neighbour System ID                | 6      | when value == 15    |
//! | Neighbour Extended Local Circuit ID| 4      | when value == 15    |
//!
//! So exactly three value lengths are well-formed for the modeled 6-octet system
//! id: **1**, **5**, and **15**. Any other length is `error.BadLength`. The
//! neighbour block is all-or-nothing (both fields, or neither).
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
    /// The value length is not one of the three well-formed sizes (1, 5, 15).
    BadLength,
    /// The 1-octet state field holds an unassigned value.
    BadState,
};

/// A neighbour reference: the (system-id, extended-local-circuit-id) pair a
/// router echoes back to prove it has heard the far end — the heart of the
/// three-way handshake's loop guard.
pub const Neighbor = struct {
    system_id: [system_id_len]u8,
    extended_local_circuit_id: u32,
};

/// A decoded / to-be-encoded TLV 240 value. `extended_local_circuit_id` is
/// present for the 5- and 15-octet forms; `neighbor` only for the 15-octet form.
/// A well-formed 15-octet TLV always carries the extended id as well, so
/// `neighbor != null` implies `extended_local_circuit_id != null`.
pub const ThreeWayTlv = struct {
    state: ThreeWayState,
    extended_local_circuit_id: ?u32 = null,
    neighbor: ?Neighbor = null,

    /// Parse a raw TLV 240 value (the bytes after code+length). Zero-copy in the
    /// sense that it reads fixed offsets only; never over-reads (the length is
    /// checked against the three legal sizes first).
    pub fn decode(value: []const u8) DecodeError!ThreeWayTlv {
        switch (value.len) {
            1 => return .{ .state = try ThreeWayState.fromByte(value[0]) },
            5 => return .{
                .state = try ThreeWayState.fromByte(value[0]),
                .extended_local_circuit_id = std.mem.readInt(u32, value[1..5], .big),
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

    /// The number of value octets `encode` will write (1, 5, or 15).
    pub fn encodedLen(self: ThreeWayTlv) usize {
        if (self.neighbor != null) return 15;
        if (self.extended_local_circuit_id != null) return 5;
        return 1;
    }

    /// Serialize the value into `out` (which must be ≥ `encodedLen()`), returning
    /// the written slice. A `neighbor` without an `extended_local_circuit_id` is a
    /// programming error (the wire format has no such shape) and is rejected.
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
            std.mem.writeInt(u32, out[11..15], nb.extended_local_circuit_id, .big);
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

test "TLV 240 round-trips the 1, 5 and 15 octet forms" {
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
    try testing.expectEqual(@as(u32, 42), d15.neighbor.?.extended_local_circuit_id);
    try testing.expectEqual(@as(u8, 9), d15.neighbor.?.system_id[5]);
}

test "TLV 240 rejects bad length and bad state, never over-reads" {
    try testing.expectError(error.BadLength, ThreeWayTlv.decode(&.{})); // empty
    try testing.expectError(error.BadLength, ThreeWayTlv.decode(&[_]u8{ 0, 1 })); // 2 octets
    try testing.expectError(error.BadLength, ThreeWayTlv.decode(&[_]u8{0} ** 11)); // 11 octets
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
