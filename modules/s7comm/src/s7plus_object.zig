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

/// Depth bound for a nested object graph. **Not independent of the value
/// codec's own bound**: an attribute's value walk is handed the *remaining*
/// object-walk budget (see `walkObject`), not a fresh `value.max_depth`, so
/// the real worst-case recursion at any point is bounded by this single
/// constant, not by the two constants composing on the call stack.
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
    // One element-visit budget shared by every attribute value in the whole
    // object graph, however deeply nested -- see `value.WalkBudgetExceeded`
    // (F6). Without this, each attribute's value walk got its own fresh
    // `value.max_walk_budget`, so a peer could multiply a handful of input
    // octets into tens of millions of loop iterations just by declaring many
    // zero-width-element arrays across many attributes/objects.
    var elem_budget: u32 = value.max_walk_budget;
    try walkObject(&cur, max_object_depth, &elem_budget);
    return cur.pos;
}

fn walkObject(cur: *value.Cursor, depth: u8, elem_budget: *u32) Error!void {
    if (depth == 0) return error.DepthExceeded;
    if (try cur.byte() != elem_start_object) return error.BadObject;
    _ = try cur.take(8); // relation id (u32) + class id (u32), fixed
    while (true) {
        const marker = try cur.byte();
        switch (marker) {
            elem_terminating_object => return,
            elem_attribute => {
                _ = try cur.varUint(u32, 5); // attribute id
                // Hand the value walk the *remaining* object-walk depth
                // budget, not a fresh `value.max_depth`. A fresh depth budget
                // here let the two "independent" bounds compose on the real
                // call stack: an attribute at object-depth 15 could still
                // open a value nested 32 deep, for combined recursion
                // nowhere close to what either constant alone suggests.
                // `elem_budget` is a second, separate resource (total
                // element visits, not depth) and is shared unconditionally.
                try value.skipValue(cur, depth, elem_budget);
            },
            elem_start_object => {
                cur.pos -= 1; // put the marker back for the nested walk
                try walkObject(cur, depth - 1, elem_budget);
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

test "an attribute value inherits the object walk's remaining depth budget, not a fresh one" {
    // Nest objects to within 3 of `max_object_depth`, then give the innermost
    // object one attribute whose value needs 5 nested `skipValue` calls (4
    // `s7struct` layers wrapping one scalar) — well inside `value.max_depth`
    // (32) on its own, but more than the 3 levels of object-walk budget left
    // at that point. If the value walk gets a *fresh* budget here (the old
    // behaviour), this decodes cleanly; if it inherits the remaining object
    // budget (the fix), it must fail with `DepthExceeded`.
    var buf: [512]u8 = undefined;
    var w: usize = 0;

    // `nest_count` objects: walkObject's own call uses depth = max_object_depth
    // for the 1st, and each further nested object recurses with depth - 1, so
    // the `nest_count`-th (innermost) frame runs with depth = max_object_depth
    // + 1 - nest_count. Pick nest_count so that remainder is 3.
    const nest_count = max_object_depth - 2;
    var i: usize = 0;
    while (i < nest_count) : (i += 1) w += (try beginObject(1, 1, buf[w..])).len;

    w += (try beginAttribute(1, buf[w..])).len;
    // 4 nested s7struct layers, each opening element id 1, then a scalar leaf.
    var d: usize = 0;
    while (d < 4) : (d += 1) {
        buf[w] = 0; // flags
        w += 1;
        buf[w] = @intFromEnum(value.Datatype.s7struct);
        w += 1;
        w += (try value.putVarUint(1, buf[w..])).len; // element id 1
    }
    w += (try value.encodeScalar(.usint, i64, 42, buf[w..])).len;
    // Terminate each of the 4 struct layers (element id 0).
    d = 0;
    while (d < 4) : (d += 1) w += (try value.putVarUint(0, buf[w..])).len;

    i = 0;
    while (i < nest_count) : (i += 1) w += (try endObject(buf[w..])).len;

    try testing.expectError(error.DepthExceeded, objectLen(buf[0..w]));
}

/// Two attributes, each an array of `.null` (0 octets/element, so the wire
/// cost of naming N elements is the same VLQ regardless of N) of `count1`
/// and `count2` elements respectively.
fn buildTwoNullArrayAttrs(out: []u8, count1: u32, count2: u32) ![]u8 {
    var w: usize = 0;
    w += (try beginObject(0, 1, out[w..])).len;
    for ([_]u32{ count1, count2 }, 1..) |count, attr_id| {
        w += (try beginAttribute(@intCast(attr_id), out[w..])).len;
        out[w] = value.flag_array;
        w += 1;
        out[w] = @intFromEnum(value.Datatype.null);
        w += 1;
        w += (try value.putVarUint(count, out[w..])).len;
    }
    w += (try endObject(out[w..])).len;
    return out[0..w];
}

test "F6: many small requests cannot each buy a fresh max_elements of CPU" {
    // Each attribute's array count is legal on its own (<= max_elements,
    // which per-array checks already enforced before this fix) -- the wire
    // for BOTH attributes together is under 20 octets. Before the fix, each
    // attribute's `skipValue` got its own fresh `max_walk_budget`
    // (== max_elements), so two such attributes bought ~2x the iterations of
    // one; a peer could keep adding more zero-width-element attributes,
    // each nearly free on the wire, and multiply the CPU cost linearly with
    // no shared ceiling (F6, measured in the audit: 231 wire octets -> 39.8M
    // iterations / 142 ms).
    var buf: [64]u8 = undefined;

    // Positive control: split exactly at the shared budget -- must still
    // succeed, proving the fix didn't just lower the per-array cap.
    const half = value.max_walk_budget / 2;
    const ok = try buildTwoNullArrayAttrs(&buf, half, half);
    _ = try objectLen(ok);

    // One element over the shared budget, split across two attributes that
    // are each individually far under `max_elements`.
    var buf2: [64]u8 = undefined;
    const over = try buildTwoNullArrayAttrs(&buf2, half, half + 1);
    try testing.expectError(error.WalkBudgetExceeded, objectLen(over));
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

/// The corpus-entry format `Smith.slice` reads: a little-endian u32 length,
/// then the frame. Was a local copy in every file that needed it -- 33 across 12
/// modules in three shapes -- each with its own note about the same trap (the
/// array has to be container-level or the returned slice dangles with the RIGHT
/// length and garbage behind it). It lives in `testkit.fuzz` now, with tests
/// that drive the real `std.testing.Smith` over what it produces.
const fuzzSeedInto = @import("testkit").fuzz.seedInto;

test "fuzz: object walker never panics or hangs" {
    var raw: [5][256]u8 = undefined;
    var pre: [5][264]u8 = undefined;
    var seeds: [5][]const u8 = undefined;
    var w: usize = 0;

    // An object with two attributes, one scalar and one real.
    w = 0;
    w += (try beginObject(0x0102, 0x03000000, raw[0][w..])).len;
    w += (try beginAttribute(1, raw[0][w..])).len;
    w += (try value.encodeScalar(.usint, i64, 42, raw[0][w..])).len;
    w += (try beginAttribute(2, raw[0][w..])).len;
    w += (try value.encodeReal(1.5, raw[0][w..])).len;
    w += (try endObject(raw[0][w..])).len;
    seeds[0] = fuzzSeedInto(&pre[0], raw[0][0..w]);

    // A nested object.
    w = 0;
    w += (try beginObject(1, 1, raw[1][w..])).len;
    w += (try beginObject(2, 2, raw[1][w..])).len;
    w += (try beginAttribute(1, raw[1][w..])).len;
    w += (try value.encodeScalar(.uint, i64, 7, raw[1][w..])).len;
    w += (try endObject(raw[1][w..])).len;
    w += (try endObject(raw[1][w..])).len;
    seeds[1] = fuzzSeedInto(&pre[1], raw[1][0..w]);

    // An element marker that is not one of the three.
    w = (try beginObject(1, 1, &raw[2])).len;
    raw[2][w] = 0x55;
    raw[2][w + 1] = elem_terminating_object;
    seeds[2] = fuzzSeedInto(&pre[2], raw[2][0 .. w + 2]);

    // Nested past `max_object_depth`.
    w = 0;
    var i: usize = 0;
    while (i < max_object_depth + 3) : (i += 1) w += (try beginObject(1, 1, raw[3][w..])).len;
    seeds[3] = fuzzSeedInto(&pre[3], raw[3][0..w]);

    // An object opened and never closed.
    w = (try beginObject(9, 9, &raw[4])).len;
    seeds[4] = fuzzSeedInto(&pre[4], raw[4][0..w]);

    try std.testing.fuzz({}, fuzzObject, .{ .corpus = &seeds });
}

fn fuzzObject(_: void, smith: *std.testing.Smith) !void {
    var buf: [512]u8 = undefined;
    // ⚠ One `smith.slice` call, never `bytes` followed by a ranged length.
    // `Smith.bytes` consumes the whole remaining seed, and the ranged draw then
    // finds fewer than eight octets left and returns the range MINIMUM — so
    // `len` was 0 for every seed and `walkObject` was handed an empty cursor.
    // Measured on 2026-09-06 over the five seeds built above: **0 of 5 non-empty
    // and 0 that `walkObject` accepted before, 5 of 5 non-empty and 2 accepted
    // after** — the other three are the malformed marker, the over-deep nest and
    // the unterminated object, which must be refused rather than walked.
    const len: usize = smith.slice(&buf);
    var cur = value.Cursor{ .bytes = buf[0..len] };
    var elem_budget: u32 = value.max_walk_budget;
    walkObject(&cur, max_object_depth, &elem_budget) catch return;
    try testing.expect(cur.pos <= len);
}
