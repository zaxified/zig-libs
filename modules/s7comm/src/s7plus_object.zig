// SPDX-License-Identifier: MIT

//! The S7CommPlus **object / session / function** layer: what sits inside a
//! `Frame`'s `data` part (see `s7plus.zig`).
//!
//! A Data PDU begins with a small header — an **opcode** (request / response /
//! notification), a **function** (CreateObject, SetVariable, …), and a **per-PDU
//! sequence number** — and then carries an **object graph**: typed attributes
//! (`s7plus_value.zig`) grouped into objects that can nest. Establishing a
//! connection is itself a `CreateObject` on the session object; reading and
//! writing a tag are `GetVariable` / `SetVariable` against a relative object id.
//!
//! ## Session, sequence, integrity
//!
//! Three running values move a session forward, and getting any of them wrong
//! desynchronises the peer:
//!
//! * **Session id** — assigned by the controller in the connect response and
//!   echoed on every later PDU.
//! * **Sequence number** — incremented by the client per request; the response
//!   echoes it, which is how a reply is matched to its request.
//! * **Integrity id** — a *running* value that S7-1500 firmware (V2+) checks on
//!   every PDU as an anti-replay measure. It must **strictly progress**; a PDU
//!   whose id repeats or goes backwards is a replay and is refused.
//!
//! **Firmware coverage, stated plainly.** This module models the integrity
//! id's *sequence semantics* — a monotonic running value the peer verifies —
//! which is the part a responder can enforce and a client can drive. It does
//! **not** implement the keyed cryptographic derivation of the id and its
//! digest that the newest S7-1500 firmware uses (that is bound up with the
//! session-key exchange and the optional encryption layer, both **out of
//! scope** — see SPEC.md). Concretely: the *progression and verification* are
//! real; the *digest bytes* are treated as an opaque caller-supplied blob, not
//! computed. This covers S7-1200 and S7-1500 up to the point where a signed
//! integrity digest becomes mandatory.

const std = @import("std");
const value = @import("s7plus_value.zig");

pub const Error = error{
    /// The data part ended before the 9-octet inner header.
    ShortHeader,
    /// The opcode octet is not request / response / notification.
    BadOpcode,
    /// A reserved field that must be zero was not.
    ReservedNotZero,
    /// An object stream was malformed (bad element marker, missing terminator).
    BadObject,
    /// An object graph nested past the depth bound.
    DepthExceeded,
    /// A VLQ id or length ran past the buffer.
    Truncated,
    /// The integrity id did not strictly progress (a replay or a stale PDU).
    IntegrityReplay,
    /// The caller's output buffer is too small.
    BufferTooSmall,
} || value.Error;

/// Depth bound for a nested object graph — independent of, and stricter than,
/// the value codec's own bound, because objects nest more shallowly than the
/// typed values inside them.
pub const max_object_depth: u8 = 16;

// ── opcode + function ───────────────────────────────────────────────────────

/// The role of a Data PDU.
pub const Opcode = enum(u8) {
    request = 0x31,
    response = 0x32,
    /// A cyclic/subscription push. Modelled in the header; the subscription
    /// machinery itself is deferred (see SPEC.md).
    notification = 0x33,
    _,
};

/// The S7CommPlus function set. The codes are the ones the `s7comm-plus`
/// dissector documents; the subset here is what a read/write client drives.
/// Self-derived byte values (no live peer) — see SPEC.md.
pub const Function = enum(u16) {
    explore = 0x04bb,
    create_object = 0x04ca,
    delete_object = 0x04d4,
    get_variable = 0x04e2,
    set_variable = 0x04f2,
    get_link = 0x0524,
    set_multi_variables = 0x0542,
    get_multi_variables = 0x0586,
    begin_sequence = 0x0604,
    end_sequence = 0x0621,
    invoke = 0x0632,
    _,
};

/// Octets in the Data-PDU inner header.
pub const data_header_len: usize = 9;

/// The inner header of a Data PDU: `opcode(1) reserved(2) function(2)
/// reserved(2) seqnum(2)`.
pub const DataHeader = struct {
    opcode: Opcode,
    function: Function,
    seqnum: u16,

    pub fn encode(self: DataHeader, out: []u8) Error![]u8 {
        if (out.len < data_header_len) return error.BufferTooSmall;
        out[0] = @intFromEnum(self.opcode);
        out[1] = 0;
        out[2] = 0;
        std.mem.writeInt(u16, out[3..5], @intFromEnum(self.function), .big);
        out[5] = 0;
        out[6] = 0;
        std.mem.writeInt(u16, out[7..9], self.seqnum, .big);
        return out[0..data_header_len];
    }

    pub fn decode(bytes: []const u8) Error!DataHeader {
        if (bytes.len < data_header_len) return error.ShortHeader;
        const op: Opcode = @enumFromInt(bytes[0]);
        switch (op) {
            .request, .response, .notification => {},
            _ => return error.BadOpcode,
        }
        if (bytes[1] != 0 or bytes[2] != 0 or bytes[5] != 0 or bytes[6] != 0)
            return error.ReservedNotZero;
        return .{
            .opcode = op,
            .function = @enumFromInt(std.mem.readInt(u16, bytes[3..5], .big)),
            .seqnum = std.mem.readInt(u16, bytes[7..9], .big),
        };
    }
};

// ── object graph ────────────────────────────────────────────────────────────

/// Object-stream element markers.
pub const elem_start_object: u8 = 0xa1;
pub const elem_terminating_object: u8 = 0xa2;
pub const elem_attribute: u8 = 0xa3;

/// Walks an object stream, validating structure and bounding recursion. Returns
/// how many octets one complete top-level object occupied. Used by the fuzz and
/// hostile-input tests, and by the responder to bound a request it decodes.
///
/// Grammar (self-derived from the documented layout):
/// ```text
/// object  := 0xa1 <relation-id u32> <class-id u32> body 0xa2
/// body    := ( attribute | object )*
/// attribute := 0xa3 <attr-id VLQ> <value>          (value per s7plus_value)
/// ```
pub fn objectLen(bytes: []const u8) Error!usize {
    var cur = value.Cursor{ .bytes = bytes };
    try walkObject(&cur, max_object_depth);
    return cur.pos;
}

fn walkObject(cur: *value.Cursor, depth: u8) Error!void {
    if (depth == 0) return error.DepthExceeded;
    if (try cur.byte() != elem_start_object) return error.BadObject;
    _ = try cur.take(8); // relation id (u32) + class id (u32), fixed
    while (true) {
        const marker = try cur.byte();
        switch (marker) {
            elem_terminating_object => return,
            elem_attribute => {
                _ = try cur.varUint(u32, 5); // attribute id
                try value.skipValue(cur, value.max_depth);
            },
            elem_start_object => {
                cur.pos -= 1; // put the marker back for the nested walk
                try walkObject(cur, depth - 1);
            },
            else => return error.BadObject,
        }
    }
}

/// Appends a `start-object` marker with its relation and class ids.
pub fn beginObject(relation_id: u32, class_id: u32, out: []u8) Error![]u8 {
    if (out.len < 9) return error.BufferTooSmall;
    out[0] = elem_start_object;
    std.mem.writeInt(u32, out[1..5], relation_id, .big);
    std.mem.writeInt(u32, out[5..9], class_id, .big);
    return out[0..9];
}

/// Appends an `attribute` marker and its id; the caller writes the value after.
pub fn beginAttribute(attr_id: u32, out: []u8) Error![]u8 {
    if (out.len < 1) return error.BufferTooSmall;
    out[0] = elem_attribute;
    const id = try value.putVarUint(attr_id, out[1..]);
    return out[0 .. 1 + id.len];
}

/// Appends a `terminating-object` marker.
pub fn endObject(out: []u8) Error![]u8 {
    if (out.len < 1) return error.BufferTooSmall;
    out[0] = elem_terminating_object;
    return out[0..1];
}

// ── session / sequence / integrity ──────────────────────────────────────────

/// The trailing integrity part of a V3 frame: a running id and an opaque
/// digest. The digest is **not** computed here (see the file header); only the
/// id's progression is modelled and verified.
pub const Integrity = struct {
    id: u32,
    digest: []const u8 = &.{},

    /// Encodes the integrity part: `id` as a VLQ, then the digest verbatim.
    pub fn encode(self: Integrity, out: []u8) Error![]u8 {
        const id = try value.putVarUint(self.id, out);
        if (out.len < id.len + self.digest.len) return error.BufferTooSmall;
        @memcpy(out[id.len..][0..self.digest.len], self.digest);
        return out[0 .. id.len + self.digest.len];
    }

    pub fn decode(bytes: []const u8) Error!Integrity {
        const r = try value.getVarUint(u32, bytes, 5);
        return .{ .id = r.value, .digest = bytes[r.len..] };
    }
};

/// Per-connection state the client and responder both keep. `single_owner`,
/// like the classic `Client`: one session owns one connection's counters.
pub const Session = struct {
    /// Assigned by the controller in the connect response; 0 before connect.
    session_id: u32 = 0,
    /// Next request sequence number to emit.
    seqnum: u16 = 1,
    /// The running integrity value. The peer requires each PDU's id to be
    /// exactly this before advancing.
    integrity_id: u32 = 0,
    /// Whether this session enforces the integrity id (V3 firmware). A V1/V2
    /// connection leaves it false and omits the integrity part entirely.
    integrity_enabled: bool = false,

    /// Returns the current sequence number and advances it (wrapping, since it
    /// is a 16-bit field — 0 is skipped so it never collides with "unset").
    pub fn nextSeq(self: *Session) u16 {
        const s = self.seqnum;
        self.seqnum +%= 1;
        if (self.seqnum == 0) self.seqnum = 1;
        return s;
    }

    /// The integrity id to stamp on the next outgoing PDU, then advances the
    /// running value. The progression is `+1` — a deliberately simple, strictly
    /// monotonic rule; the cryptographic derivation the newest firmware uses is
    /// out of scope (see the file header).
    pub fn nextIntegrity(self: *Session) u32 {
        const v = self.integrity_id;
        self.integrity_id +%= 1;
        return v;
    }

    /// Verifies a received PDU's integrity id against what this session expects,
    /// then advances. A stale or repeated id is `error.IntegrityReplay`; this is
    /// the anti-replay check a responder runs on every V3 request.
    pub fn verifyIntegrity(self: *Session, received: u32) Error!void {
        if (!self.integrity_enabled) return;
        if (received != self.integrity_id) return error.IntegrityReplay;
        self.integrity_id +%= 1;
    }
};

// ── tests ───────────────────────────────────────────────────────────────────

const testing = std.testing;

test "data header round trips" {
    var buf: [16]u8 = undefined;
    const h = DataHeader{ .opcode = .request, .function = .set_variable, .seqnum = 0x1234 };
    const enc = try h.encode(&buf);
    try testing.expectEqualSlices(u8, &[_]u8{ 0x31, 0x00, 0x00, 0x04, 0xf2, 0x00, 0x00, 0x12, 0x34 }, enc);
    const dec = try DataHeader.decode(enc);
    try testing.expectEqual(Opcode.request, dec.opcode);
    try testing.expectEqual(Function.set_variable, dec.function);
    try testing.expectEqual(@as(u16, 0x1234), dec.seqnum);
}

test "data header rejects a bad opcode and non-zero reserved" {
    try testing.expectError(error.ShortHeader, DataHeader.decode(&[_]u8{ 0x31, 0, 0 }));
    try testing.expectError(error.BadOpcode, DataHeader.decode(&[_]u8{ 0x99, 0, 0, 0, 0, 0, 0, 0, 0 }));
    try testing.expectError(error.ReservedNotZero, DataHeader.decode(&[_]u8{ 0x31, 0x01, 0, 0, 0, 0, 0, 0, 0 }));
}

test "an object with attributes round trips through objectLen" {
    var buf: [128]u8 = undefined;
    var w: usize = 0;
    w += (try beginObject(0x0102, 0x03000000, buf[w..])).len;
    // attribute 1 = usint 42
    w += (try beginAttribute(1, buf[w..])).len;
    w += (try value.encodeScalar(.usint, i64, 42, buf[w..])).len;
    // attribute 2 = real 1.5
    w += (try beginAttribute(2, buf[w..])).len;
    w += (try value.encodeReal(1.5, buf[w..])).len;
    w += (try endObject(buf[w..])).len;
    buf[w] = 0xEE; // trailing junk
    try testing.expectEqual(w, try objectLen(buf[0 .. w + 1]));
}

test "a nested object round trips and a bad marker is BadObject" {
    var buf: [128]u8 = undefined;
    var w: usize = 0;
    w += (try beginObject(1, 1, buf[w..])).len;
    w += (try beginObject(2, 2, buf[w..])).len; // nested
    w += (try beginAttribute(1, buf[w..])).len;
    w += (try value.encodeScalar(.uint, i64, 7, buf[w..])).len;
    w += (try endObject(buf[w..])).len; // end nested
    w += (try endObject(buf[w..])).len; // end outer
    try testing.expectEqual(w, try objectLen(buf[0..w]));

    // Corrupt the inner marker.
    var bad: [16]u8 = undefined;
    const n = (try beginObject(1, 1, &bad)).len;
    bad[n] = 0x55; // not a valid element marker
    bad[n + 1] = elem_terminating_object;
    try testing.expectError(error.BadObject, objectLen(bad[0 .. n + 2]));
}

test "a pathologically nested object is DepthExceeded" {
    var buf: [512]u8 = undefined;
    var w: usize = 0;
    var i: usize = 0;
    while (i < max_object_depth + 3) : (i += 1) w += (try beginObject(1, 1, buf[w..])).len;
    try testing.expectError(error.DepthExceeded, objectLen(buf[0..w]));
}

test "integrity part round trips" {
    var buf: [16]u8 = undefined;
    const it = Integrity{ .id = 300, .digest = &[_]u8{ 0xDE, 0xAD } };
    const enc = try it.encode(&buf);
    const dec = try Integrity.decode(enc);
    try testing.expectEqual(@as(u32, 300), dec.id);
    try testing.expectEqualSlices(u8, &[_]u8{ 0xDE, 0xAD }, dec.digest);
}

test "sequence number advances and skips 0 on wrap" {
    var s = Session{ .seqnum = 0xFFFF };
    try testing.expectEqual(@as(u16, 0xFFFF), s.nextSeq());
    try testing.expectEqual(@as(u16, 1), s.seqnum); // wrapped past 0
}

test "integrity id must strictly progress or it is a replay" {
    var s = Session{ .integrity_enabled = true, .integrity_id = 10 };
    try s.verifyIntegrity(10); // ok, advances to 11
    try testing.expectError(error.IntegrityReplay, s.verifyIntegrity(10)); // stale
    try testing.expectError(error.IntegrityReplay, s.verifyIntegrity(99)); // ahead
    try s.verifyIntegrity(11); // the expected next value
    // A V1/V2 session does not enforce it.
    var v2 = Session{ .integrity_enabled = false };
    try v2.verifyIntegrity(12345);
}

test "fuzz: object walker never panics or hangs" {
    try std.testing.fuzz({}, fuzzObject, .{});
}

fn fuzzObject(_: void, smith: *std.testing.Smith) !void {
    var buf: [512]u8 = undefined;
    smith.bytes(&buf);
    const len: usize = smith.valueRangeAtMost(u16, 0, buf.len);
    var cur = value.Cursor{ .bytes = buf[0..len] };
    walkObject(&cur, max_object_depth) catch return;
    try testing.expect(cur.pos <= len);
}
