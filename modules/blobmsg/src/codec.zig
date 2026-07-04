// SPDX-License-Identifier: MIT
//! blob/blobmsg wire codec — the pure-wire, security-critical core of the
//! `blobmsg` module (OpenWRT's typed message format, used by ubus). No I/O,
//! no syscalls, no platform dependency: everything here operates on byte
//! slices and is fully unit- and fuzz-testable on any OS.
//!
//! Wire format (big-endian, 4-byte alignment), clean-room from the OpenWRT
//! sources (libubox `blob.h`/`blobmsg.h`, ubus `ubusmsg.h`) and byte-parity
//! verified against `ubus -S` on real hardware (see the module README):
//!
//! ```text
//! ubus_msghdr:  u8 version | u8 type | u16 seq (BE) | u32 peer (BE)   (8 bytes)
//! blob_attr:    u32 id_len (BE) | data | pad-to-4
//!               id_len = (EXTENDED << 31) | (id << 24) | len
//!               len counts the 4-byte header; the pad does NOT count
//! blobmsg:      a blob_attr with EXTENDED set and id = blobmsg type;
//!               data = blobmsg_hdr (u16 namelen BE + name + NUL + pad-to-4)
//!               followed by the value
//! ```
//!
//! A ubus message is the msghdr followed by one top-level blob_attr (id 0)
//! that wraps the child attrs. Top-level ubus attrs are raw blob attrs
//! (OBJID/STATUS = BE u32, METHOD/OBJPATH = NUL-terminated string, DATA =
//! nested blobmsg children); DATA payloads and reply values are blobmsg.
//! blobmsg value types: INT8 = bool, INT16/32/64 = signed BE, DOUBLE = BE
//! u64 holding the f64 bits, STRING = NUL-terminated, TABLE/ARRAY = nested.
//!
//! Every length field is validated against the enclosing buffer before any
//! slice is formed: a truncated, hostile, or bit-flipped buffer yields
//! `error.Truncated` / `error.BadLength`, never a panic or an out-of-bounds
//! read. Iteration always advances by at least 4 bytes, so a walk over N
//! bytes is capped at N/4 steps, and JSON decoding caps container nesting at
//! `max_depth` (`error.TooDeep`) so hostile input cannot blow the stack.

const std = @import("std");

pub const Error = error{
    /// A header or a declared length runs past the end of the buffer.
    Truncated,
    /// A declared length is impossibly small, or a fixed-size scalar value
    /// has the wrong size.
    BadLength,
    /// Container nesting exceeded `max_depth` (hostile input guard).
    TooDeep,
};

pub const EncodeError = error{
    OutOfMemory,
    /// A name/value exceeds its wire field (name > 64 KiB, attr > 16 MiB).
    TooLarge,
    /// Container nesting exceeded `max_depth`.
    TooDeep,
    /// The JSON value has no blobmsg mapping (null / number_string).
    Unsupported,
};

/// Errors of the streaming blobmsg→JSON decoder (`error.WriteFailed` comes
/// from the destination writer).
pub const JsonError = Error || std.Io.Writer.Error;

// ── wire constants ──────────────────────────────────────────────────────────

/// blob attrs and blobmsg headers align to 4 bytes (blob.h BLOB_ATTR_ALIGN).
pub const align_to: usize = 4;
/// sizeof the blob_attr id_len header.
pub const attr_header_len: usize = 4;
/// sizeof struct ubus_msghdr (ubusmsg.h).
pub const msghdr_len: usize = 8;
/// ubus_msghdr.version is always 0 (ubusmsg.h UBUS_MSGHDR_VERSION).
pub const version: u8 = 0;

/// blob_attr id_len bit layout (blob.h).
pub const EXTENDED: u32 = 0x8000_0000;
pub const ID_MASK: u32 = 0x7f00_0000;
pub const ID_SHIFT: u5 = 24;
pub const LEN_MASK: u32 = 0x00ff_ffff;

/// Container nesting cap for the JSON encoder/decoder — a defense against
/// hostile deeply-nested input, far above anything ubus produces.
pub const max_depth: usize = 64;

/// ubus_msghdr message types (clean-room from ubusmsg.h enum ubus_msg_type;
/// only the daemon-verified subset the client uses is declared).
pub const MSG = struct {
    pub const HELLO: u8 = 0;
    pub const STATUS: u8 = 1;
    pub const DATA: u8 = 2;
    pub const LOOKUP: u8 = 4;
    pub const INVOKE: u8 = 5;
    pub const ADD_OBJECT: u8 = 6;
};

/// ubus attribute ids (ubusmsg.h enum ubus_msg_attr) — raw blob attrs at the
/// top level of a message.
pub const ATTR = struct {
    pub const STATUS: u32 = 1;
    pub const OBJPATH: u32 = 2;
    pub const OBJID: u32 = 3;
    pub const METHOD: u32 = 4;
    pub const OBJTYPE: u32 = 5;
    pub const SIGNATURE: u32 = 6;
    pub const DATA: u32 = 7;
    pub const NO_REPLY: u32 = 10;
};

/// blobmsg value types (blobmsg.h enum blobmsg_type). INT8 doubles as BOOL —
/// ubus stores booleans as INT8 and `ubus -S` prints them as true/false.
pub const BM = struct {
    pub const ARRAY: u32 = 1;
    pub const TABLE: u32 = 2;
    pub const STRING: u32 = 3;
    pub const INT64: u32 = 4;
    pub const INT32: u32 = 5;
    pub const INT16: u32 = 6;
    pub const INT8: u32 = 7;
    pub const DOUBLE: u32 = 8;
};

/// Well-known system object id of the ubusd event registry (ubusmsg.h).
pub const SYS_OBJECT_EVENT: u32 = 1;

/// Round `n` up to the blob 4-byte boundary.
pub fn alignUp(n: usize) usize {
    return (n + (align_to - 1)) & ~(align_to - 1);
}

/// Pack a blob_attr id_len word: `(EXTENDED<<31) | (id<<24) | len`, where
/// `len` counts the 4-byte header itself. Callers validate `len` first.
pub fn idLen(id: u32, extended: bool, len: usize) u32 {
    std.debug.assert(id <= ID_MASK >> ID_SHIFT);
    std.debug.assert(len <= LEN_MASK);
    var v: u32 = @intCast(len & LEN_MASK);
    v |= (id << ID_SHIFT) & ID_MASK;
    if (extended) v |= EXTENDED;
    return v;
}

// ── message framing ─────────────────────────────────────────────────────────

/// Decoded ubus_msghdr fields.
pub const MsgHeader = struct {
    version: u8,
    type: u8,
    seq: u16,
    peer: u32,
};

/// Decode the fixed 8-byte ubus_msghdr (seq/peer big-endian).
pub fn parseMsgHeader(bytes: *const [msghdr_len]u8) MsgHeader {
    return .{
        .version = bytes[0],
        .type = bytes[1],
        .seq = std.mem.readInt(u16, bytes[2..4], .big),
        .peer = std.mem.readInt(u32, bytes[4..8], .big),
    };
}

/// Build one framed ubus message: the 8-byte msghdr followed by the top
/// blob_attr (id 0) wrapping `children`. Caller owns the returned bytes.
pub fn encodeMessage(
    gpa: std.mem.Allocator,
    mtype: u8,
    seq: u16,
    peer: u32,
    children: []const u8,
) EncodeError![]u8 {
    const top_len = attr_header_len + children.len;
    if (top_len > LEN_MASK) return error.TooLarge;
    const buf = try gpa.alloc(u8, msghdr_len + top_len);
    buf[0] = version;
    buf[1] = mtype;
    std.mem.writeInt(u16, buf[2..4], seq, .big);
    std.mem.writeInt(u32, buf[4..8], peer, .big);
    std.mem.writeInt(u32, buf[8..12], idLen(0, false, top_len), .big);
    @memcpy(buf[12..], children);
    return buf;
}

// ── raw blob_attr parsing ───────────────────────────────────────────────────

/// One raw blob attr. `data` borrows from the input buffer (excludes the
/// 4-byte header and the trailing pad).
pub const Attr = struct {
    id: u32,
    /// The EXTENDED bit — set on blobmsg attrs (which carry a blobmsg_hdr).
    extended: bool,
    data: []const u8,
};

/// Bounds-checked walker over concatenated raw blob attrs (the children of a
/// message's top attr, or of a nested attr). Validation per attr: 4 header
/// bytes remain, `len >= 4`, and `len` fits the remaining buffer — otherwise
/// `error.Truncated`/`error.BadLength`, never an OOB read. Since `len >= 4`,
/// every step advances >= 4 bytes: iteration over N bytes is capped at N/4
/// steps by construction. The final attr may omit its trailing pad.
pub const AttrIterator = struct {
    buf: []const u8,
    off: usize = 0,

    pub fn next(it: *AttrIterator) Error!?Attr {
        if (it.off >= it.buf.len) return null;
        const rest = it.buf[it.off..];
        if (rest.len < attr_header_len) return error.Truncated;
        const id_len = std.mem.readInt(u32, rest[0..4], .big);
        const len: usize = id_len & LEN_MASK;
        if (len < attr_header_len) return error.BadLength;
        if (len > rest.len) return error.Truncated;
        it.off += @min(alignUp(len), rest.len);
        return .{
            .id = (id_len & ID_MASK) >> ID_SHIFT,
            .extended = (id_len & EXTENDED) != 0,
            .data = rest[attr_header_len..len],
        };
    }
};

// ── blobmsg (named, typed) parsing ──────────────────────────────────────────

/// One decoded blobmsg value. Slices borrow from the input buffer.
pub const Value = union(enum) {
    string: []const u8,
    /// INT8 on the wire — ubus's boolean.
    boolean: bool,
    int16: i16,
    int32: i32,
    int64: i64,
    /// BE u64 on the wire holding the raw f64 bits.
    double: f64,
    /// Nested blobmsg children — walk with another `FieldIterator`.
    table: []const u8,
    /// Nested blobmsg children (elements carry empty names).
    array: []const u8,
    /// Unrecognized blobmsg type id (decoded to JSON null).
    unknown: u32,
};

/// One named blobmsg field: the blobmsg type id, the name from the
/// blobmsg_hdr (empty for array elements) and the typed value.
pub const Field = struct {
    type: u32,
    name: []const u8,
    value: Value,
};

/// Bounds-checked walker over blobmsg children (a TABLE/ARRAY payload, or a
/// ubus DATA body). Each field's blobmsg_hdr and scalar size are validated;
/// malformed input errors out instead of over-reading.
pub const FieldIterator = struct {
    it: AttrIterator,

    pub fn init(children: []const u8) FieldIterator {
        return .{ .it = .{ .buf = children } };
    }

    pub fn next(self: *FieldIterator) Error!?Field {
        const a = (try self.it.next()) orelse return null;
        return try parseField(a);
    }
};

/// Split a blob attr into its blobmsg_hdr (namelen BE16 + name + NUL, padded
/// to 4) and typed value. Scalar sizes are exact (per libubox's
/// blobmsg_check_attr); a STRING's single trailing NUL is stripped.
pub fn parseField(a: Attr) Error!Field {
    if (a.data.len < 2) return error.Truncated;
    const namelen: usize = std.mem.readInt(u16, a.data[0..2], .big);
    const hdrlen = alignUp(2 + namelen + 1);
    if (hdrlen > a.data.len) return error.Truncated;
    const name = a.data[2 .. 2 + namelen];
    const payload = a.data[hdrlen..];

    const value: Value = switch (a.id) {
        BM.STRING => .{
            .string = if (payload.len > 0 and payload[payload.len - 1] == 0)
                payload[0 .. payload.len - 1]
            else
                payload,
        },
        BM.INT8 => blk: {
            if (payload.len != 1) return error.BadLength;
            break :blk .{ .boolean = payload[0] != 0 };
        },
        BM.INT16 => blk: {
            if (payload.len != 2) return error.BadLength;
            break :blk .{ .int16 = std.mem.readInt(i16, payload[0..2], .big) };
        },
        BM.INT32 => blk: {
            if (payload.len != 4) return error.BadLength;
            break :blk .{ .int32 = std.mem.readInt(i32, payload[0..4], .big) };
        },
        BM.INT64 => blk: {
            if (payload.len != 8) return error.BadLength;
            break :blk .{ .int64 = std.mem.readInt(i64, payload[0..8], .big) };
        },
        BM.DOUBLE => blk: {
            if (payload.len != 8) return error.BadLength;
            break :blk .{ .double = @bitCast(std.mem.readInt(u64, payload[0..8], .big)) };
        },
        BM.TABLE => .{ .table = payload },
        BM.ARRAY => .{ .array = payload },
        else => .{ .unknown = a.id },
    };
    return .{ .type = a.id, .name = name, .value = value };
}

// ── blobmsg → JSON ──────────────────────────────────────────────────────────

/// Decode a sequence of blobmsg children (a ubus DATA body / TABLE payload)
/// as a compact JSON object onto `out` — the shape `ubus -S` prints. Field
/// order is the wire order. Malformed input → `Error`; nesting past
/// `max_depth` → `error.TooDeep`.
pub fn decodeToJson(children: []const u8, out: *std.Io.Writer) JsonError!void {
    var s: std.json.Stringify = .{ .writer = out };
    try streamChildren(&s, children, false, 0);
}

/// Allocating convenience wrapper around `decodeToJson`.
pub fn decodeToJsonAlloc(
    gpa: std.mem.Allocator,
    children: []const u8,
) (Error || std.mem.Allocator.Error)![]u8 {
    var aw = std.Io.Writer.Allocating.init(gpa);
    defer aw.deinit();
    decodeToJson(children, &aw.writer) catch |err| switch (err) {
        error.WriteFailed => return error.OutOfMemory, // Allocating writer: alloc failure
        error.Truncated => return error.Truncated,
        error.BadLength => return error.BadLength,
        error.TooDeep => return error.TooDeep,
    };
    return aw.toOwnedSlice();
}

/// Stream blobmsg children into an already-open `std.json.Stringify` — for
/// callers composing a larger JSON document (e.g. `{"<event>": <data>}`).
/// `is_array` picks the container shape.
pub fn streamInto(s: *std.json.Stringify, children: []const u8, is_array: bool) JsonError!void {
    return streamChildren(s, children, is_array, 0);
}

fn streamChildren(
    s: *std.json.Stringify,
    children: []const u8,
    is_array: bool,
    depth: usize,
) JsonError!void {
    if (depth > max_depth) return error.TooDeep;
    if (is_array) try s.beginArray() else try s.beginObject();
    var it = FieldIterator.init(children);
    while (try it.next()) |f| {
        if (!is_array) try s.objectField(f.name);
        switch (f.value) {
            .table => |b| try streamChildren(s, b, false, depth + 1),
            .array => |b| try streamChildren(s, b, true, depth + 1),
            .string => |v| try s.write(v),
            .boolean => |v| try s.write(v),
            .int16 => |v| try s.write(v),
            .int32 => |v| try s.write(v),
            .int64 => |v| try s.write(v),
            .double => |v| try s.write(v),
            .unknown => try s.write(null),
        }
    }
    if (is_array) try s.endArray() else try s.endObject();
}

// ── blobmsg encoding ────────────────────────────────────────────────────────

/// Write the blob_attr header + blobmsg_hdr for a field whose value will be
/// `value_len` bytes; returns the attr's total (unpadded) length so the
/// caller can pad after appending the value.
fn fieldHeader(
    gpa: std.mem.Allocator,
    out: *std.ArrayList(u8),
    bm_type: u32,
    name: []const u8,
    value_len: usize,
) EncodeError!usize {
    if (name.len > std.math.maxInt(u16)) return error.TooLarge;
    const hdrlen = alignUp(2 + name.len + 1);
    const total = attr_header_len + hdrlen + value_len;
    if (total > LEN_MASK) return error.TooLarge;
    var h: [4]u8 = undefined;
    std.mem.writeInt(u32, &h, idLen(bm_type, true, total), .big);
    try out.appendSlice(gpa, &h);
    var nl: [2]u8 = undefined;
    std.mem.writeInt(u16, &nl, @intCast(name.len), .big);
    try out.appendSlice(gpa, &nl);
    try out.appendSlice(gpa, name);
    // One zero run covers the name's NUL and the header pad.
    try out.appendNTimes(gpa, 0, hdrlen - (2 + name.len));
    return total;
}

/// Append one blobmsg attr with a raw pre-encoded value: blob header
/// (EXTENDED | type | len), blobmsg_hdr (namelen BE16 + name + NUL + pad),
/// the value, then pad the whole attr to 4.
pub fn appendField(
    gpa: std.mem.Allocator,
    out: *std.ArrayList(u8),
    bm_type: u32,
    name: []const u8,
    value: []const u8,
) EncodeError!void {
    const total = try fieldHeader(gpa, out, bm_type, name, value.len);
    try out.appendSlice(gpa, value);
    try out.appendNTimes(gpa, 0, alignUp(total) - total);
}

/// Append a named STRING field (the value is NUL-terminated on the wire).
pub fn appendString(
    gpa: std.mem.Allocator,
    out: *std.ArrayList(u8),
    name: []const u8,
    s: []const u8,
) EncodeError!void {
    const total = try fieldHeader(gpa, out, BM.STRING, name, s.len + 1);
    try out.appendSlice(gpa, s);
    // One zero run covers the value's NUL and the attr pad.
    try out.appendNTimes(gpa, 0, 1 + alignUp(total) - total);
}

/// Append a named INT8 (boolean) field.
pub fn appendBool(gpa: std.mem.Allocator, out: *std.ArrayList(u8), name: []const u8, v: bool) EncodeError!void {
    try appendField(gpa, out, BM.INT8, name, &[_]u8{@intFromBool(v)});
}

/// Append a named INT16 field (BE).
pub fn appendInt16(gpa: std.mem.Allocator, out: *std.ArrayList(u8), name: []const u8, v: i16) EncodeError!void {
    var b: [2]u8 = undefined;
    std.mem.writeInt(i16, &b, v, .big);
    try appendField(gpa, out, BM.INT16, name, &b);
}

/// Append a named INT32 field (BE).
pub fn appendInt32(gpa: std.mem.Allocator, out: *std.ArrayList(u8), name: []const u8, v: i32) EncodeError!void {
    var b: [4]u8 = undefined;
    std.mem.writeInt(i32, &b, v, .big);
    try appendField(gpa, out, BM.INT32, name, &b);
}

/// Append a named INT32 field carrying an unsigned 32-bit value (BE) — e.g.
/// an object id, which the ubusd event registry requires as INT32 even when
/// it exceeds maxInt(i32).
pub fn appendU32(gpa: std.mem.Allocator, out: *std.ArrayList(u8), name: []const u8, v: u32) EncodeError!void {
    var b: [4]u8 = undefined;
    std.mem.writeInt(u32, &b, v, .big);
    try appendField(gpa, out, BM.INT32, name, &b);
}

/// Append a named INT64 field (BE).
pub fn appendInt64(gpa: std.mem.Allocator, out: *std.ArrayList(u8), name: []const u8, v: i64) EncodeError!void {
    var b: [8]u8 = undefined;
    std.mem.writeInt(i64, &b, v, .big);
    try appendField(gpa, out, BM.INT64, name, &b);
}

/// Append a named DOUBLE field (BE u64 of the f64 bits).
pub fn appendDouble(gpa: std.mem.Allocator, out: *std.ArrayList(u8), name: []const u8, v: f64) EncodeError!void {
    var b: [8]u8 = undefined;
    std.mem.writeInt(u64, &b, @bitCast(v), .big);
    try appendField(gpa, out, BM.DOUBLE, name, &b);
}

/// Append a named TABLE field wrapping pre-encoded blobmsg children.
pub fn appendTable(gpa: std.mem.Allocator, out: *std.ArrayList(u8), name: []const u8, children: []const u8) EncodeError!void {
    try appendField(gpa, out, BM.TABLE, name, children);
}

/// Append a named ARRAY field wrapping pre-encoded blobmsg children
/// (elements must carry empty names).
pub fn appendArray(gpa: std.mem.Allocator, out: *std.ArrayList(u8), name: []const u8, children: []const u8) EncodeError!void {
    try appendField(gpa, out, BM.ARRAY, name, children);
}

// ── JSON → blobmsg ──────────────────────────────────────────────────────────

/// Encode one JSON value as a named blobmsg field appended to `out`
/// (recursive for object/array). The type mapping mirrors ubus's own JSON
/// parser: object→TABLE, array→ARRAY, string→STRING, bool→INT8,
/// integer→INT32 (INT64 when it overflows i32), float→DOUBLE. JSON null has
/// no blobmsg mapping → `error.Unsupported`.
pub fn encodeJson(
    gpa: std.mem.Allocator,
    out: *std.ArrayList(u8),
    name: []const u8,
    v: std.json.Value,
) EncodeError!void {
    return encodeJsonDepth(gpa, out, name, v, 0);
}

/// Encode a JSON object's members as blobmsg children — the body of a ubus
/// `UBUS_ATTR_DATA` args attr. Non-object → `error.Unsupported` (ubus args
/// are always a table). Caller owns the returned bytes.
pub fn encodeArgs(gpa: std.mem.Allocator, args: std.json.Value) EncodeError![]u8 {
    if (args != .object) return error.Unsupported;
    var out: std.ArrayList(u8) = .empty;
    errdefer out.deinit(gpa);
    var it = args.object.iterator();
    while (it.next()) |e| try encodeJsonDepth(gpa, &out, e.key_ptr.*, e.value_ptr.*, 0);
    return out.toOwnedSlice(gpa);
}

fn encodeJsonDepth(
    gpa: std.mem.Allocator,
    out: *std.ArrayList(u8),
    name: []const u8,
    v: std.json.Value,
    depth: usize,
) EncodeError!void {
    if (depth > max_depth) return error.TooDeep;
    switch (v) {
        .object => |o| {
            var val: std.ArrayList(u8) = .empty;
            defer val.deinit(gpa);
            var it = o.iterator();
            while (it.next()) |e| try encodeJsonDepth(gpa, &val, e.key_ptr.*, e.value_ptr.*, depth + 1);
            try appendTable(gpa, out, name, val.items);
        },
        .array => |a| {
            var val: std.ArrayList(u8) = .empty;
            defer val.deinit(gpa);
            for (a.items) |item| try encodeJsonDepth(gpa, &val, "", item, depth + 1);
            try appendArray(gpa, out, name, val.items);
        },
        .string => |s| try appendString(gpa, out, name, s),
        .bool => |b| try appendBool(gpa, out, name, b),
        .integer => |i| {
            if (i >= std.math.minInt(i32) and i <= std.math.maxInt(i32)) {
                try appendInt32(gpa, out, name, @intCast(i));
            } else {
                try appendInt64(gpa, out, name, i);
            }
        },
        .float => |f| try appendDouble(gpa, out, name, f),
        else => return error.Unsupported, // null / number_string: no blobmsg mapping
    }
}

// ── raw blob_attr encoding (top-level ubus attrs) ───────────────────────────

/// Append a raw (non-extended) blob attr with `data` as payload, padded to 4
/// — nested ubus attrs like DATA/SIGNATURE (empty `data` = the empty attr,
/// len 4). The length field does not include the padding.
pub fn appendAttr(
    gpa: std.mem.Allocator,
    out: *std.ArrayList(u8),
    id: u32,
    data: []const u8,
) EncodeError!void {
    const total = attr_header_len + data.len;
    if (total > LEN_MASK) return error.TooLarge;
    var h: [4]u8 = undefined;
    std.mem.writeInt(u32, &h, idLen(id, false, total), .big);
    try out.appendSlice(gpa, &h);
    try out.appendSlice(gpa, data);
    try out.appendNTimes(gpa, 0, alignUp(total) - total);
}

/// Append a BE u32 blob attr (OBJID/STATUS style; 8 bytes, no pad needed).
pub fn appendAttrU32(gpa: std.mem.Allocator, out: *std.ArrayList(u8), id: u32, v: u32) EncodeError!void {
    var b: [4]u8 = undefined;
    std.mem.writeInt(u32, &b, v, .big);
    try appendAttr(gpa, out, id, &b);
}

/// Append a NUL-terminated string blob attr (METHOD/OBJPATH style), padded
/// to 4.
pub fn appendAttrString(
    gpa: std.mem.Allocator,
    out: *std.ArrayList(u8),
    id: u32,
    s: []const u8,
) EncodeError!void {
    const total = attr_header_len + s.len + 1;
    if (total > LEN_MASK) return error.TooLarge;
    var h: [4]u8 = undefined;
    std.mem.writeInt(u32, &h, idLen(id, false, total), .big);
    try out.appendSlice(gpa, &h);
    try out.appendSlice(gpa, s);
    // One zero run covers the terminating NUL and the alignment pad.
    try out.appendNTimes(gpa, 0, 1 + alignUp(total) - total);
}

// ── tests ───────────────────────────────────────────────────────────────────

const testing = std.testing;

test "alignUp + idLen pack" {
    try testing.expectEqual(@as(usize, 0), alignUp(0));
    try testing.expectEqual(@as(usize, 4), alignUp(1));
    try testing.expectEqual(@as(usize, 8), alignUp(5));
    try testing.expectEqual(@as(usize, 8), alignUp(8));
    try testing.expectEqual(@as(usize, 12), alignUp(9));
    // id 3, len 8, no extended → 0x03000008 big-endian semantics.
    try testing.expectEqual(@as(u32, 0x03000008), idLen(ATTR.OBJID, false, 8));
    try testing.expectEqual(@as(u32, 0x80000000 | (BM.STRING << 24) | 12), idLen(BM.STRING, true, 12));
}

test "golden: blobmsg field encode — string, bool, int32" {
    const gpa = testing.allocator;
    var buf: std.ArrayList(u8) = .empty;
    defer buf.deinit(gpa);

    // "name":"eth0" → total 17, hdr pad 1, value NUL, attr pad 3.
    try appendString(gpa, &buf, "name", "eth0");
    try testing.expectEqualSlices(u8, &.{
        0x83, 0x00, 0x00, 0x11, // EXTENDED | STRING<<24 | 17
        0x00, 0x04, 'n', 'a', 'm', 'e', 0x00, 0x00, // blobmsg_hdr, padded to 8
        'e', 't', 'h', '0', 0x00, // value + NUL
        0x00, 0x00, 0x00, // pad 17 → 20
    }, buf.items);

    // "up":true → INT8, total 13, pad 3.
    buf.clearRetainingCapacity();
    try appendBool(gpa, &buf, "up", true);
    try testing.expectEqualSlices(u8, &.{
        0x87, 0x00, 0x00, 0x0d,
        0x00, 0x02, 'u',  'p',
        0x00, 0x00, 0x00, 0x00,
        0x01, 0x00, 0x00, 0x00,
    }, buf.items);

    // "mtu":1500 → INT32, total 16, no pad.
    buf.clearRetainingCapacity();
    try appendInt32(gpa, &buf, "mtu", 1500);
    try testing.expectEqualSlices(u8, &.{
        0x85, 0x00, 0x00, 0x10,
        0x00, 0x03, 'm',  't',
        'u',  0x00, 0x00, 0x00,
        0x00, 0x00, 0x05, 0xdc,
    }, buf.items);
}

test "golden: ubus LOOKUP message frame" {
    const gpa = testing.allocator;
    var children: std.ArrayList(u8) = .empty;
    defer children.deinit(gpa);
    try appendAttrString(gpa, &children, ATTR.OBJPATH, "system");

    const msg = try encodeMessage(gpa, MSG.LOOKUP, 1, 0, children.items);
    defer gpa.free(msg);
    try testing.expectEqualSlices(u8, &.{
        0x00, 0x04, 0x00, 0x01, // version 0, type LOOKUP, seq 1
        0x00, 0x00, 0x00, 0x00, // peer 0
        0x00, 0x00, 0x00, 0x10, // top blob_attr, id 0, len 16
        0x02, 0x00, 0x00, 0x0b, // OBJPATH attr, len 11
        's', 'y', 's', 't', 'e', 'm', 0x00, // "system" + NUL
        0x00, // pad 11 → 12
    }, msg);

    const hdr = parseMsgHeader(msg[0..msghdr_len]);
    try testing.expectEqual(@as(u8, 0), hdr.version);
    try testing.expectEqual(MSG.LOOKUP, hdr.type);
    try testing.expectEqual(@as(u16, 1), hdr.seq);
    try testing.expectEqual(@as(u32, 0), hdr.peer);
}

test "golden: INVOKE children carry an empty UBUS_ATTR_DATA (daemon gotcha)" {
    const gpa = testing.allocator;
    var children: std.ArrayList(u8) = .empty;
    defer children.deinit(gpa);
    try appendAttrU32(gpa, &children, ATTR.OBJID, 0x1234);
    try appendAttrString(gpa, &children, ATTR.METHOD, "board");
    try appendAttr(gpa, &children, ATTR.DATA, &.{}); // required even when empty
    try testing.expectEqualSlices(u8, &.{
        0x03, 0x00, 0x00, 0x08, 0x00, 0x00, 0x12, 0x34, // OBJID
        0x04, 0x00, 0x00, 0x0a, 'b', 'o', 'a', 'r', 'd', 0x00, 0x00, 0x00, // METHOD
        0x07, 0x00, 0x00, 0x04, // empty DATA — header only, len 4
    }, children.items);
}

test "raw AttrIterator: id/extended/data round-trip" {
    const gpa = testing.allocator;
    var buf: std.ArrayList(u8) = .empty;
    defer buf.deinit(gpa);
    try appendAttrU32(gpa, &buf, ATTR.OBJID, 0xdeadbeef);
    try appendAttrString(gpa, &buf, ATTR.METHOD, "get");
    try appendField(gpa, &buf, BM.TABLE, "t", &.{}); // extended blobmsg attr

    var it: AttrIterator = .{ .buf = buf.items };
    const a1 = (try it.next()).?;
    try testing.expectEqual(ATTR.OBJID, a1.id);
    try testing.expect(!a1.extended);
    try testing.expectEqual(@as(u32, 0xdeadbeef), std.mem.readInt(u32, a1.data[0..4], .big));
    const a2 = (try it.next()).?;
    try testing.expectEqual(ATTR.METHOD, a2.id);
    try testing.expectEqualStrings("get", std.mem.trimEnd(u8, a2.data, "\x00"));
    const a3 = (try it.next()).?;
    try testing.expectEqual(BM.TABLE, a3.id);
    try testing.expect(a3.extended);
    try testing.expectEqual(@as(?Attr, null), try it.next());
}

test "decode blobmsg table -> json (string, bool, int16, int32, int64)" {
    const gpa = testing.allocator;
    var buf: std.ArrayList(u8) = .empty;
    defer buf.deinit(gpa);

    try appendString(gpa, &buf, "model", "TestRouter");
    try appendBool(gpa, &buf, "up", true);
    try appendInt16(gpa, &buf, "small", -7);
    try appendInt32(gpa, &buf, "n", 42);
    try appendInt64(gpa, &buf, "big", 123456789012);

    const json = try decodeToJsonAlloc(gpa, buf.items);
    defer gpa.free(json);
    // Field order is preserved (the wire order of the attrs) — this is the
    // compact shape `ubus -S` prints.
    try testing.expectEqualStrings(
        \\{"model":"TestRouter","up":true,"small":-7,"n":42,"big":123456789012}
    , json);
}

test "decode nested table + array" {
    const gpa = testing.allocator;
    var inner: std.ArrayList(u8) = .empty;
    defer inner.deinit(gpa);
    try appendString(gpa, &inner, "k", "v");

    var arr: std.ArrayList(u8) = .empty;
    defer arr.deinit(gpa);
    try appendInt32(gpa, &arr, "", 7); // array element: empty name

    var top: std.ArrayList(u8) = .empty;
    defer top.deinit(gpa);
    try appendTable(gpa, &top, "obj", inner.items);
    try appendArray(gpa, &top, "list", arr.items);

    const json = try decodeToJsonAlloc(gpa, top.items);
    defer gpa.free(json);
    try testing.expectEqualStrings(
        \\{"obj":{"k":"v"},"list":[7]}
    , json);
}

test "typed FieldIterator decode incl. nested containers" {
    const gpa = testing.allocator;
    var inner: std.ArrayList(u8) = .empty;
    defer inner.deinit(gpa);
    try appendBool(gpa, &inner, "flag", false);

    var buf: std.ArrayList(u8) = .empty;
    defer buf.deinit(gpa);
    try appendString(gpa, &buf, "s", "x");
    try appendInt64(gpa, &buf, "i", -5);
    try appendTable(gpa, &buf, "t", inner.items);

    var it = FieldIterator.init(buf.items);
    const f1 = (try it.next()).?;
    try testing.expectEqualStrings("s", f1.name);
    try testing.expectEqualStrings("x", f1.value.string);
    const f2 = (try it.next()).?;
    try testing.expectEqual(@as(i64, -5), f2.value.int64);
    const f3 = (try it.next()).?;
    try testing.expectEqualStrings("t", f3.name);
    var sub = FieldIterator.init(f3.value.table);
    const n1 = (try sub.next()).?;
    try testing.expectEqualStrings("flag", n1.name);
    try testing.expectEqual(false, n1.value.boolean);
    try testing.expectEqual(@as(?Field, null), try sub.next());
    try testing.expectEqual(@as(?Field, null), try it.next());
}

test "encode args -> blobmsg -> decode round-trips (string/bool/int/nested/array)" {
    const gpa = testing.allocator;
    const src =
        \\{"path":"/etc/os-release","enable":true,"count":42,"opts":{"deep":false},"ids":[1,2,3]}
    ;
    var parsed = try std.json.parseFromSlice(std.json.Value, gpa, src, .{});
    defer parsed.deinit();

    const buf = try encodeArgs(gpa, parsed.value);
    defer gpa.free(buf);

    const json = try decodeToJsonAlloc(gpa, buf);
    defer gpa.free(json);
    // The decoder reproduces the same field order + types we encoded.
    try testing.expectEqualStrings(src, json);
}

test "DOUBLE: golden BE bits + value round-trip" {
    const gpa = testing.allocator;
    var buf: std.ArrayList(u8) = .empty;
    defer buf.deinit(gpa);
    try appendDouble(gpa, &buf, "pi", 3.5);
    // 3.5 = 0x400C000000000000, stored as a BE u64.
    try testing.expectEqualSlices(u8, &.{
        0x88, 0x00, 0x00, 0x14,
        0x00, 0x02, 'p',  'i',
        0x00, 0x00, 0x00, 0x00,
        0x40, 0x0c, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00,
    }, buf.items);

    const json = try decodeToJsonAlloc(gpa, buf.items);
    defer gpa.free(json);
    var parsed = try std.json.parseFromSlice(std.json.Value, gpa, json, .{});
    defer parsed.deinit();
    try testing.expectEqual(@as(f64, 3.5), parsed.value.object.get("pi").?.float);
}

test "int32/int64 JSON split at the i32 boundary" {
    const gpa = testing.allocator;
    const src =
        \\{"lo":-2147483648,"hi":2147483647,"over":2147483648,"under":-2147483649}
    ;
    var parsed = try std.json.parseFromSlice(std.json.Value, gpa, src, .{});
    defer parsed.deinit();
    const buf = try encodeArgs(gpa, parsed.value);
    defer gpa.free(buf);

    var it = FieldIterator.init(buf);
    try testing.expectEqual(@as(i32, std.math.minInt(i32)), (try it.next()).?.value.int32);
    try testing.expectEqual(@as(i32, std.math.maxInt(i32)), (try it.next()).?.value.int32);
    try testing.expectEqual(@as(i64, 2147483648), (try it.next()).?.value.int64);
    try testing.expectEqual(@as(i64, -2147483649), (try it.next()).?.value.int64);
}

test "JSON null and non-object args are Unsupported" {
    const gpa = testing.allocator;
    var parsed = try std.json.parseFromSlice(std.json.Value, gpa, "{\"x\":null}", .{});
    defer parsed.deinit();
    try testing.expectError(error.Unsupported, encodeArgs(gpa, parsed.value));

    var arr = try std.json.parseFromSlice(std.json.Value, gpa, "[1,2]", .{});
    defer arr.deinit();
    try testing.expectError(error.Unsupported, encodeArgs(gpa, arr.value));
}

test "empty containers and string edge cases" {
    const gpa = testing.allocator;
    var buf: std.ArrayList(u8) = .empty;
    defer buf.deinit(gpa);
    try appendTable(gpa, &buf, "t", &.{});
    try appendArray(gpa, &buf, "a", &.{});
    try appendString(gpa, &buf, "e", "");
    const json = try decodeToJsonAlloc(gpa, buf.items);
    defer gpa.free(json);
    try testing.expectEqualStrings(
        \\{"t":{},"a":[],"e":""}
    , json);

    // A STRING value without a trailing NUL is tolerated (kept verbatim).
    var raw: std.ArrayList(u8) = .empty;
    defer raw.deinit(gpa);
    try appendField(gpa, &raw, BM.STRING, "s", "ab");
    var it = FieldIterator.init(raw.items);
    try testing.expectEqualStrings("ab", (try it.next()).?.value.string);
}

test "walker rejects truncated, bad-length and OOB attrs" {
    // Header cut short.
    var it: AttrIterator = .{ .buf = &.{ 0x83, 0x00, 0x00 } };
    try testing.expectError(error.Truncated, it.next());
    // Declared length runs past the buffer.
    it = .{ .buf = &.{ 0x83, 0x00, 0x00, 0x20, 0xaa, 0xbb } };
    try testing.expectError(error.Truncated, it.next());
    // Impossibly small length (< 4).
    it = .{ .buf = &.{ 0x83, 0x00, 0x00, 0x03, 0xaa, 0xbb, 0xcc, 0xdd } };
    try testing.expectError(error.BadLength, it.next());
    // Zero length must not loop forever either.
    it = .{ .buf = &.{ 0x00, 0x00, 0x00, 0x00 } };
    try testing.expectError(error.BadLength, it.next());
    // A valid attr followed by garbage still reports the garbage.
    it = .{ .buf = &.{ 0x03, 0x00, 0x00, 0x04, 0x02, 0x00 } };
    _ = (try it.next()).?;
    try testing.expectError(error.Truncated, it.next());
}

test "blobmsg header + scalar validation" {
    // blobmsg data shorter than the namelen field.
    var f = FieldIterator.init(&.{ 0x83, 0x00, 0x00, 0x05, 0x00 });
    try testing.expectError(error.Truncated, f.next());
    // namelen pointing past the attr's data.
    f = FieldIterator.init(&.{ 0x83, 0x00, 0x00, 0x08, 0x00, 0xff, 'a', 0x00 });
    try testing.expectError(error.Truncated, f.next());
    // INT32 whose payload is 2 bytes instead of 4.
    var buf: std.ArrayList(u8) = .empty;
    defer buf.deinit(testing.allocator);
    try appendField(testing.allocator, &buf, BM.INT32, "n", &.{ 0x00, 0x01 });
    f = FieldIterator.init(buf.items);
    try testing.expectError(error.BadLength, f.next());
    // Unknown blobmsg type id decodes to JSON null.
    buf.clearRetainingCapacity();
    try appendField(testing.allocator, &buf, 0x33, "u", &.{0xaa});
    const json = try decodeToJsonAlloc(testing.allocator, buf.items);
    defer testing.allocator.free(json);
    try testing.expectEqualStrings(
        \\{"u":null}
    , json);
}

test "walker accepts a final unpadded attr" {
    // STRING attr of len 9 ("hi\0" value + 4B header + 2B namelen... built by
    // hand) sitting at the very end of the buffer with its pad omitted.
    const gpa = testing.allocator;
    var buf: std.ArrayList(u8) = .empty;
    defer buf.deinit(gpa);
    try appendString(gpa, &buf, "k", "hi");
    // Strip the trailing pad: total = 4 + 4 + 3 = 11, padded to 12.
    const unpadded = buf.items[0..11];
    var it = FieldIterator.init(unpadded);
    const fld = (try it.next()).?;
    try testing.expectEqualStrings("k", fld.name);
    try testing.expectEqualStrings("hi", fld.value.string);
    try testing.expectEqual(@as(?Field, null), try it.next());
}

test "hostile nesting depth errors out instead of blowing the stack" {
    const gpa = testing.allocator;
    // Decode side: 70 nested TABLEs.
    var cur: std.ArrayList(u8) = .empty;
    defer cur.deinit(gpa);
    try appendInt32(gpa, &cur, "v", 1);
    for (0..70) |_| {
        var outer: std.ArrayList(u8) = .empty;
        errdefer outer.deinit(gpa);
        try appendTable(gpa, &outer, "t", cur.items);
        cur.deinit(gpa);
        cur = outer;
    }
    try testing.expectError(error.TooDeep, decodeToJsonAlloc(gpa, cur.items));

    // Encode side: 70 nested JSON objects.
    var src: std.ArrayList(u8) = .empty;
    defer src.deinit(gpa);
    for (0..70) |_| try src.appendSlice(gpa, "{\"a\":");
    try src.append(gpa, '1');
    for (0..70) |_| try src.append(gpa, '}');
    var parsed = try std.json.parseFromSlice(std.json.Value, gpa, src.items, .{});
    defer parsed.deinit();
    try testing.expectError(error.TooDeep, encodeArgs(gpa, parsed.value));
}

test "encode limits: oversized name and attr are rejected" {
    const gpa = testing.allocator;
    var out: std.ArrayList(u8) = .empty;
    defer out.deinit(gpa);

    const long_name = try gpa.alloc(u8, std.math.maxInt(u16) + 1);
    defer gpa.free(long_name);
    @memset(long_name, 'x');
    try testing.expectError(error.TooLarge, appendString(gpa, &out, long_name, "v"));

    const huge = try std.heap.page_allocator.alloc(u8, LEN_MASK);
    defer std.heap.page_allocator.free(huge);
    try testing.expectError(error.TooLarge, appendAttr(gpa, &out, ATTR.DATA, huge));
    try testing.expectError(error.TooLarge, appendField(gpa, &out, BM.TABLE, "t", huge));
    try testing.expectError(error.TooLarge, encodeMessage(gpa, MSG.DATA, 0, 0, huge));
    try testing.expect(out.items.len == 0); // nothing partial appended
}

test "fuzz: walkers + JSON decoder never crash, loop, or read OOB" {
    try testing.fuzz({}, fuzzCodec, .{});
}

fn fuzzCodec(_: void, smith: *std.testing.Smith) !void {
    var raw: [512]u8 = undefined;
    smith.bytes(&raw);
    const len = smith.valueRangeAtMost(u16, 0, raw.len);
    const buf = raw[0..len];

    // Raw walk: each step consumes >= 4 bytes, so bound the step count.
    var steps: usize = 0;
    var it: AttrIterator = .{ .buf = buf };
    while (it.next() catch null) |_| {
        steps += 1;
        try testing.expect(steps <= buf.len / 4 + 1);
    }

    // Typed blobmsg walk, one nesting level deep.
    var fsteps: usize = 0;
    var fit = FieldIterator.init(buf);
    while (fit.next() catch null) |f| {
        fsteps += 1;
        try testing.expect(fsteps <= buf.len / 4 + 1);
        switch (f.value) {
            .table, .array => |b| {
                var sub = FieldIterator.init(b);
                while (sub.next() catch null) |_| {}
            },
            else => {},
        }
    }

    // Full recursive JSON decode (exercises the depth cap too).
    var aw = std.Io.Writer.Allocating.init(testing.allocator);
    defer aw.deinit();
    decodeToJson(buf, &aw.writer) catch {};
}
