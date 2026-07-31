// SPDX-License-Identifier: MIT

//! S7CommPlus **value / datatype TLV codec** — the heart of the protocol.
//!
//! Where classic S7comm (protocol id 0x32) addresses raw memory by area and
//! byte offset, S7CommPlus (protocol id 0x72, the S7-1200/1500 dialect) carries
//! *typed values*: every attribute, every variable, every object field is a
//! `<datatype-flags><datatype><value>` triple, and structures and arrays nest
//! those triples recursively. This file owns that encoding once, so the object
//! model, the client and the responder above it never re-derive it.
//!
//! ## The variable-length integer
//!
//! S7CommPlus does not send fixed-width integers for the "big" scalar types.
//! `UDInt`, `ULInt`, `AID`, `DInt`, `LInt` and `Timespan` are a **base-128
//! big-endian VLQ**: seven value bits per octet, most-significant group first,
//! and the high bit (`0x80`) set on every octet except the last.
//!
//! * **Unsigned** (`UDInt`/`ULInt`/`AID`): the groups are the magnitude.
//! * **Signed** (`DInt`/`LInt`/`Timespan`): identical framing, but the value is
//!   two's-complement in `7 * N` bits, so the sign is the top bit of the whole
//!   number — which, because the first group is the most significant, is exactly
//!   bit `0x40` of the **first** octet. This is the convention the Wireshark
//!   `s7comm-plus` dissector documents.
//!
//! Both directions round-trip exactly; see the tests. The *unsigned* form is
//! byte-for-byte the classic protobuf-style VLQ only in reverse group order —
//! the signed sign-extension rule is the S7CommPlus-specific part and is
//! self-derived from the documented layout (no live peer was available).
//!
//! ## Bounded recursion
//!
//! A `Struct` is a list of `<element-id VLQ><value>` pairs terminated by
//! element-id `0`; an array is a count followed by that many bare bodies; a
//! sparse array is `<key VLQ><value>` pairs terminated by key `0`; a `Variant`
//! wraps one nested value. All of these can nest, so every walk carries a depth
//! counter and refuses to descend past `max_depth` — a hostile deeply-nested
//! blob is a typed error, never a stack overflow.

const std = @import("std");

pub const Error = error{
    /// The buffer ended in the middle of a value.
    Truncated,
    /// A VLQ ran longer than its type can hold (5 octets for 32-bit, 10 for
    /// 64-bit) — a peer trying to smuggle an over-wide integer.
    VarIntTooLong,
    /// The datatype-flags octet has a bit set outside the defined mask.
    ReservedFlagBit,
    /// An array/struct/variant nested past `max_depth`.
    DepthExceeded,
    /// An array count or a blob/string length exceeds the sane ceiling.
    TooLong,
    /// The output buffer handed to an encoder is too small.
    BufferTooSmall,
    /// A datatype code this codec does not model was encountered.
    UnsupportedDatatype,
};

/// How deep structs/arrays/variants may nest before a walk refuses to descend.
/// A real controller nests only a handful of levels; this is pure hostile-input
/// containment.
pub const max_depth: u8 = 32;

/// Sane ceiling on an array count or a blob/string length. Nothing in a PLC
/// object graph approaches this; it exists so a decoder cannot be steered into
/// a multi-gigabyte loop by a lying length field.
pub const max_elements: u32 = 1 << 20;

// ── datatype flags ──────────────────────────────────────────────────────────

/// The value is an array: a VLQ count then that many bare bodies of `datatype`.
pub const flag_array: u8 = 0x10;
/// An "address array" — same wire shape as a plain array here.
pub const flag_address_array: u8 = 0x20;
/// A sparse array: `<key VLQ><body>` pairs terminated by key 0.
pub const flag_sparsearray: u8 = 0x40;
/// Every bit a valid flags octet may set. Anything else is `ReservedFlagBit`.
pub const flag_valid_mask: u8 = flag_array | flag_address_array | flag_sparsearray;

/// The typed-value datatype codes, as the `s7comm-plus` dissector names them.
/// The comment on each says how its body is encoded.
pub const Datatype = enum(u8) {
    null = 0x00, // 0 octets
    bool = 0x01, // 1 octet (0/1)
    usint = 0x02, // 1 octet
    uint = 0x03, // 2 octets
    udint = 0x04, // VLQ u32
    ulint = 0x05, // VLQ u64
    sint = 0x06, // 1 octet
    int = 0x07, // 2 octets
    dint = 0x08, // VLQ i32
    lint = 0x09, // VLQ i64
    byte = 0x0a, // 1 octet
    word = 0x0b, // 2 octets
    dword = 0x0c, // 4 octets
    lword = 0x0d, // 8 octets
    real = 0x0e, // 4 octets (f32)
    lreal = 0x0f, // 8 octets (f64)
    timestamp = 0x10, // 8 octets (fixed)
    timespan = 0x11, // VLQ i64
    rid = 0x12, // 4 octets (fixed u32)
    aid = 0x13, // VLQ u32
    blob = 0x14, // VLQ len + bytes
    wstring = 0x15, // VLQ len + UTF-8 bytes
    variant = 0x16, // one nested value
    s7struct = 0x17, // element list, id-0 terminated
    s7string = 0x19, // VLQ len + bytes
    _,
};

// ── VLQ primitives ──────────────────────────────────────────────────────────

/// Octets an unsigned VLQ of `v` occupies (minimum 1).
pub fn varUintLen(v: u64) usize {
    var n: usize = 1;
    var x = v >> 7;
    while (x != 0) : (x >>= 7) n += 1;
    return n;
}

/// Writes `v` as a base-128 big-endian VLQ into `out`; returns the written
/// slice. `max_octets` caps the width (5 for u32, 9 for u64).
pub fn putVarUint(v: u64, out: []u8) Error![]u8 {
    const n = varUintLen(v);
    if (out.len < n) return error.BufferTooSmall;
    var i: usize = 0;
    while (i < n) : (i += 1) {
        const shift: u6 = @intCast(7 * (n - 1 - i));
        var octet: u8 = @intCast((v >> shift) & 0x7f);
        if (i != n - 1) octet |= 0x80;
        out[i] = octet;
    }
    return out[0..n];
}

/// A decoded VLQ: its value and how many octets it consumed.
pub fn VarResult(comptime T: type) type {
    return struct { value: T, len: usize };
}

/// Reads a base-128 big-endian VLQ from the front of `bytes`. `max_octets`
/// bounds the width so an over-wide encoding is `VarIntTooLong` rather than an
/// integer overflow. Accumulates in `u128` so a full 64-bit value (which needs
/// ten groups) cannot overflow mid-decode.
pub fn getVarUint(comptime T: type, bytes: []const u8, max_octets: usize) Error!VarResult(T) {
    var value: u128 = 0;
    var i: usize = 0;
    while (true) : (i += 1) {
        if (i >= bytes.len) return error.Truncated;
        if (i >= max_octets) return error.VarIntTooLong;
        const octet = bytes[i];
        value = (value << 7) | (octet & 0x7f);
        if (octet & 0x80 == 0) break;
    }
    // Reject an encoding that overflowed the target width.
    if (value > std.math.maxInt(T)) return error.VarIntTooLong;
    return .{ .value = @intCast(value), .len = i + 1 };
}

/// Writes a signed VLQ: the same framing as `putVarUint`, but the width is
/// chosen so the value's two's-complement sign bit lands in bit `0x40` of the
/// first octet.
pub fn putVarInt(v: i64, out: []u8) Error![]u8 {
    // Smallest group count N such that v fits in a signed 7*N-bit field. A full
    // i64 needs ten groups (10 * 7 = 70 >= 64).
    var n: usize = 1;
    while (n < 10) : (n += 1) {
        const bits: u8 = @intCast(7 * n);
        const lo = -(@as(i128, 1) << @intCast(bits - 1));
        const hi = (@as(i128, 1) << @intCast(bits - 1)) - 1;
        if (v >= lo and v <= hi) break;
    }
    if (out.len < n) return error.BufferTooSmall;
    const bits: u8 = @intCast(7 * n);
    const mask: u128 = (@as(u128, 1) << @intCast(bits)) - 1;
    // Sign-extend v to 128 bits first, then mask to the field width, so a
    // negative value's high groups carry the correct two's-complement bits.
    const u: u128 = @as(u128, @bitCast(@as(i128, v))) & mask;
    var i: usize = 0;
    while (i < n) : (i += 1) {
        const shift: u7 = @intCast(7 * (n - 1 - i));
        var octet: u8 = @intCast((u >> shift) & 0x7f);
        if (i != n - 1) octet |= 0x80;
        out[i] = octet;
    }
    return out[0..n];
}

/// Reads a signed VLQ, sign-extending from the `7*N`-bit field it occupies.
pub fn getVarInt(comptime T: type, bytes: []const u8, max_octets: usize) Error!VarResult(T) {
    var u: u128 = 0;
    var i: usize = 0;
    while (true) : (i += 1) {
        if (i >= bytes.len) return error.Truncated;
        if (i >= max_octets) return error.VarIntTooLong;
        u = (u << 7) | (bytes[i] & 0x7f);
        if (bytes[i] & 0x80 == 0) break;
    }
    const bits: u8 = @intCast(7 * (i + 1));
    // Two's-complement over the field width: if the top bit is set, subtract
    // 2^bits to recover the negative value.
    var value: i128 = @intCast(u);
    if (bits < 128 and (u & (@as(u128, 1) << @intCast(bits - 1))) != 0) {
        value -= @as(i128, 1) << @intCast(bits);
    }
    if (value < std.math.minInt(T) or value > std.math.maxInt(T)) return error.VarIntTooLong;
    return .{ .value = @intCast(value), .len = i + 1 };
}

// ── flags ───────────────────────────────────────────────────────────────────

/// The parsed datatype-flags octet.
pub const Flags = struct {
    raw: u8,

    pub fn decode(octet: u8) Error!Flags {
        if (octet & ~flag_valid_mask != 0) return error.ReservedFlagBit;
        return .{ .raw = octet };
    }
    pub fn isArray(self: Flags) bool {
        return self.raw & (flag_array | flag_address_array) != 0;
    }
    pub fn isSparse(self: Flags) bool {
        return self.raw & flag_sparsearray != 0;
    }
    pub fn scalar() Flags {
        return .{ .raw = 0 };
    }
};

// ── walking a value ─────────────────────────────────────────────────────────

/// A cursor over an encoded value stream. `pos` is the consumed prefix.
pub const Cursor = struct {
    bytes: []const u8,
    pos: usize = 0,

    pub fn take(self: *Cursor, n: usize) Error![]const u8 {
        if (self.pos + n > self.bytes.len) return error.Truncated;
        const s = self.bytes[self.pos..][0..n];
        self.pos += n;
        return s;
    }
    pub fn byte(self: *Cursor) Error!u8 {
        return (try self.take(1))[0];
    }
    pub fn varUint(self: *Cursor, comptime T: type, max_octets: usize) Error!T {
        const r = try getVarUint(T, self.bytes[self.pos..], max_octets);
        self.pos += r.len;
        return r.value;
    }
    pub fn varInt(self: *Cursor, comptime T: type, max_octets: usize) Error!T {
        const r = try getVarInt(T, self.bytes[self.pos..], max_octets);
        self.pos += r.len;
        return r.value;
    }
};

/// Number of fixed octets a scalar datatype's body occupies, or null if the
/// datatype is variable-length (VLQ / length-prefixed / composite).
fn fixedBodyLen(dt: Datatype) ?usize {
    return switch (dt) {
        .null => 0,
        .bool, .usint, .sint, .byte => 1,
        .uint, .int, .word => 2,
        .dword, .real, .rid => 4,
        .lword, .lreal, .timestamp => 8,
        else => null,
    };
}

/// Consumes exactly one value **body** (the bytes after the flags+datatype
/// octets) of datatype `dt`, honouring `flags`, and bounded by `depth`.
/// Advances the cursor. This is the single recursion point the whole codec
/// funnels through, so the depth bound and the array/length guards live here
/// and nowhere else.
pub fn skipBody(cur: *Cursor, flags: Flags, dt: Datatype, depth: u8) Error!void {
    if (depth == 0) return error.DepthExceeded;

    if (flags.isArray()) {
        const count = try cur.varUint(u32, 5);
        if (count > max_elements) return error.TooLong;
        var k: u32 = 0;
        while (k < count) : (k += 1) try skipOneBody(cur, dt, depth);
        return;
    }
    if (flags.isSparse()) {
        while (true) {
            const key = try cur.varUint(u32, 5);
            if (key == 0) break;
            try skipOneBody(cur, dt, depth);
        }
        return;
    }
    try skipOneBody(cur, dt, depth);
}

/// One scalar-or-composite body, without the array/sparse wrapper.
fn skipOneBody(cur: *Cursor, dt: Datatype, depth: u8) Error!void {
    if (fixedBodyLen(dt)) |n| {
        _ = try cur.take(n);
        return;
    }
    switch (dt) {
        .udint, .aid => _ = try cur.varUint(u32, 5),
        .ulint => _ = try cur.varUint(u64, 10),
        .dint => _ = try cur.varInt(i32, 5),
        .lint, .timespan => _ = try cur.varInt(i64, 10),
        .blob, .wstring, .s7string => {
            const len = try cur.varUint(u32, 5);
            if (len > max_elements) return error.TooLong;
            _ = try cur.take(len);
        },
        .variant => try skipValue(cur, depth - 1),
        .s7struct => {
            while (true) {
                const id = try cur.varUint(u32, 5);
                if (id == 0) break;
                try skipValue(cur, depth - 1);
            }
        },
        else => return error.UnsupportedDatatype,
    }
}

/// Consumes one full value: the flags octet, the datatype octet, and the body.
/// Advances the cursor to the octet after the value.
pub fn skipValue(cur: *Cursor, depth: u8) Error!void {
    if (depth == 0) return error.DepthExceeded;
    const flags = try Flags.decode(try cur.byte());
    const dt: Datatype = @enumFromInt(try cur.byte());
    try skipBody(cur, flags, dt, depth);
}

/// Validates that `bytes` is exactly one well-formed value and returns how many
/// octets it occupied. `error.Truncated` if it runs short; trailing octets are
/// left for the caller (they are the next field).
pub fn valueLen(bytes: []const u8) Error!usize {
    var cur = Cursor{ .bytes = bytes };
    try skipValue(&cur, max_depth);
    return cur.pos;
}

// ── scalar encode / decode (the leaf values a caller actually reads) ─────────

/// Writes a full scalar value (`flags=0`, datatype, body) into `out`.
pub fn encodeScalar(dt: Datatype, comptime T: type, v: T, out: []u8) Error![]u8 {
    if (out.len < 2) return error.BufferTooSmall;
    out[0] = 0; // scalar flags
    out[1] = @intFromEnum(dt);
    const body = try encodeScalarBody(dt, T, v, out[2..]);
    return out[0 .. 2 + body.len];
}

fn encodeScalarBody(dt: Datatype, comptime T: type, v: T, out: []u8) Error![]u8 {
    switch (dt) {
        .bool, .usint, .sint, .byte => {
            if (out.len < 1) return error.BufferTooSmall;
            out[0] = @intCast(@as(u64, @bitCast(@as(i64, v))) & 0xff);
            return out[0..1];
        },
        .uint, .int, .word => {
            if (out.len < 2) return error.BufferTooSmall;
            const u: u16 = @truncate(@as(u64, @bitCast(@as(i64, v))));
            out[0] = @intCast(u >> 8);
            out[1] = @intCast(u & 0xff);
            return out[0..2];
        },
        .dword, .rid => {
            if (out.len < 4) return error.BufferTooSmall;
            std.mem.writeInt(u32, out[0..4], @truncate(@as(u64, @bitCast(@as(i64, v)))), .big);
            return out[0..4];
        },
        .lword, .timestamp => {
            if (out.len < 8) return error.BufferTooSmall;
            std.mem.writeInt(u64, out[0..8], @bitCast(@as(i64, v)), .big);
            return out[0..8];
        },
        .udint, .aid => return putVarUint(@intCast(v), out),
        .ulint => return putVarUint(@intCast(v), out),
        .dint => return putVarInt(@intCast(v), out),
        .lint, .timespan => return putVarInt(@intCast(v), out),
        else => return error.UnsupportedDatatype,
    }
}

/// Writes a `Real` (f32) value.
pub fn encodeReal(v: f32, out: []u8) Error![]u8 {
    if (out.len < 6) return error.BufferTooSmall;
    out[0] = 0;
    out[1] = @intFromEnum(Datatype.real);
    std.mem.writeInt(u32, out[2..6], @bitCast(v), .big);
    return out[0..6];
}

/// Writes an `LReal` (f64) value.
pub fn encodeLReal(v: f64, out: []u8) Error![]u8 {
    if (out.len < 10) return error.BufferTooSmall;
    out[0] = 0;
    out[1] = @intFromEnum(Datatype.lreal);
    std.mem.writeInt(u64, out[2..10], @bitCast(v), .big);
    return out[0..10];
}

/// Writes a length-prefixed value (`blob`/`wstring`/`s7string`).
pub fn encodeBytes(dt: Datatype, data: []const u8, out: []u8) Error![]u8 {
    if (out.len < 2) return error.BufferTooSmall;
    out[0] = 0;
    out[1] = @intFromEnum(dt);
    const lenbytes = try putVarUint(data.len, out[2..]);
    const start = 2 + lenbytes.len;
    if (out.len < start + data.len) return error.BufferTooSmall;
    @memcpy(out[start..][0..data.len], data);
    return out[0 .. start + data.len];
}

/// A decoded scalar, wide enough to hold any of the fixed/VLQ integer types.
pub const Scalar = union(enum) {
    boolean: bool,
    unsigned: u64,
    signed: i64,
    real: f32,
    lreal: f64,
    bytes: []const u8,
};

/// Reads one full value and, for the leaf scalar types, returns its Zig value.
/// Composite values (struct/array/variant) return `error.UnsupportedDatatype`
/// from here — walk those with `skipValue`/`Cursor` instead.
pub fn decodeScalar(bytes: []const u8) Error!struct { value: Scalar, dt: Datatype, len: usize } {
    var cur = Cursor{ .bytes = bytes };
    const flags = try Flags.decode(try cur.byte());
    if (flags.raw != 0) return error.UnsupportedDatatype;
    const dt: Datatype = @enumFromInt(try cur.byte());
    const val: Scalar = switch (dt) {
        .bool => .{ .boolean = (try cur.byte()) != 0 },
        .usint, .byte => .{ .unsigned = try cur.byte() },
        .sint => .{ .signed = @as(i8, @bitCast(try cur.byte())) },
        .uint, .word => .{ .unsigned = std.mem.readInt(u16, (try cur.take(2))[0..2], .big) },
        .int => .{ .signed = std.mem.readInt(i16, (try cur.take(2))[0..2], .big) },
        .dword, .rid => .{ .unsigned = std.mem.readInt(u32, (try cur.take(4))[0..4], .big) },
        .lword, .timestamp => .{ .unsigned = std.mem.readInt(u64, (try cur.take(8))[0..8], .big) },
        .udint, .aid => .{ .unsigned = try cur.varUint(u32, 5) },
        .ulint => .{ .unsigned = try cur.varUint(u64, 10) },
        .dint => .{ .signed = try cur.varInt(i32, 5) },
        .lint, .timespan => .{ .signed = try cur.varInt(i64, 10) },
        .real => .{ .real = @bitCast(std.mem.readInt(u32, (try cur.take(4))[0..4], .big)) },
        .lreal => .{ .lreal = @bitCast(std.mem.readInt(u64, (try cur.take(8))[0..8], .big)) },
        .blob, .wstring, .s7string => blk: {
            const len = try cur.varUint(u32, 5);
            break :blk .{ .bytes = try cur.take(len) };
        },
        else => return error.UnsupportedDatatype,
    };
    return .{ .value = val, .dt = dt, .len = cur.pos };
}

// ── tests ───────────────────────────────────────────────────────────────────

const testing = std.testing;

test "varuint round trips and is big-endian, MSB-continuation" {
    // 300 = 0b1_0010_1100 -> groups [0000010][0101100] -> 0x82 0x2C
    var buf: [10]u8 = undefined;
    const enc = try putVarUint(300, &buf);
    try testing.expectEqualSlices(u8, &[_]u8{ 0x82, 0x2C }, enc);
    const dec = try getVarUint(u32, enc, 5);
    try testing.expectEqual(@as(u32, 300), dec.value);
    try testing.expectEqual(@as(usize, 2), dec.len);

    for ([_]u64{ 0, 1, 127, 128, 16383, 16384, 0xFFFF, 0xDEADBEEF, std.math.maxInt(u64) }) |v| {
        const e = try putVarUint(v, &buf);
        const d = try getVarUint(u64, e, 10);
        try testing.expectEqual(v, d.value);
        try testing.expectEqual(e.len, d.len);
    }
}

test "varint sign lives in bit 0x40 of the first octet and round trips" {
    var buf: [10]u8 = undefined;
    // -1 in 7 bits is 0x7f (no continuation), sign bit 0x40 set.
    const m1 = try putVarInt(-1, &buf);
    try testing.expectEqualSlices(u8, &[_]u8{0x7F}, m1);
    try testing.expectEqual(@as(i64, -1), (try getVarInt(i64, m1, 10)).value);

    for ([_]i64{ 0, 1, -1, 63, -64, 64, -65, 8191, -8192, 0x7FFFFFFF, -0x80000000, std.math.minInt(i64), std.math.maxInt(i64) }) |v| {
        const e = try putVarInt(v, &buf);
        const d = try getVarInt(i64, e, 10);
        try testing.expectEqual(v, d.value);
        try testing.expectEqual(e.len, d.len);
        // The sign is bit 0x40 of the first octet.
        try testing.expectEqual(v < 0, (e[0] & 0x40) != 0);
    }
}

test "an over-wide VLQ is VarIntTooLong, not an overflow" {
    // Six continuation octets for a u32 target.
    const wide = [_]u8{ 0x81, 0x80, 0x80, 0x80, 0x80, 0x00 };
    try testing.expectError(error.VarIntTooLong, getVarUint(u32, &wide, 5));
    // A value that fits in 5 octets of framing but exceeds u32.
    const big = [_]u8{ 0x9F, 0xFF, 0xFF, 0xFF, 0x7F };
    try testing.expectError(error.VarIntTooLong, getVarUint(u32, &big, 5));
}

test "reserved flag bit is refused" {
    try testing.expectError(error.ReservedFlagBit, Flags.decode(0x08));
    try testing.expectError(error.ReservedFlagBit, Flags.decode(0x80));
    _ = try Flags.decode(flag_array);
    _ = try Flags.decode(0);
}

test "scalar round trips through decode for every fixed and VLQ type" {
    var buf: [16]u8 = undefined;

    const b = try encodeScalar(.bool, i64, 1, &buf);
    try testing.expectEqual(true, (try decodeScalar(b)).value.boolean);

    const u = try encodeScalar(.uint, i64, 0x1234, &buf);
    try testing.expectEqual(@as(u64, 0x1234), (try decodeScalar(u)).value.unsigned);

    const s = try encodeScalar(.int, i64, -1000, &buf);
    try testing.expectEqual(@as(i64, -1000), (try decodeScalar(s)).value.signed);

    const ud = try encodeScalar(.udint, i64, 1_000_000, &buf);
    try testing.expectEqual(@as(u64, 1_000_000), (try decodeScalar(ud)).value.unsigned);

    const di = try encodeScalar(.dint, i64, -1_000_000, &buf);
    try testing.expectEqual(@as(i64, -1_000_000), (try decodeScalar(di)).value.signed);

    const r = try encodeReal(3.5, &buf);
    try testing.expectEqual(@as(f32, 3.5), (try decodeScalar(r)).value.real);

    const lr = try encodeLReal(-2.25, &buf);
    try testing.expectEqual(@as(f64, -2.25), (try decodeScalar(lr)).value.lreal);

    const bl = try encodeBytes(.blob, "abc", &buf);
    try testing.expectEqualSlices(u8, "abc", (try decodeScalar(bl)).value.bytes);
}

test "scalar round trips for every fixed-width type, one per decode-switch group" {
    // The test above only touches one member of each *shared* switch arm
    // (uint covers uint/word, udint covers udint/aid, ...). The other
    // member of each shared arm, plus the arms nothing above touches at
    // all (usint/byte, sint, dword/rid, lword/timestamp, ulint,
    // lint/timespan), were never round-tripped -- `rid` in particular is
    // documented as "4 octets (fixed)" while its sibling `aid` is a VLQ,
    // and only encode/decode agreeing on that split keeps them from silently
    // desyncing a struct/array walk that mixes the two.
    var buf: [16]u8 = undefined;

    const us = try encodeScalar(.usint, i64, 200, &buf);
    try testing.expectEqual(@as(u64, 200), (try decodeScalar(us)).value.unsigned);
    const by = try encodeScalar(.byte, i64, 201, &buf);
    try testing.expectEqual(@as(u64, 201), (try decodeScalar(by)).value.unsigned);

    const si = try encodeScalar(.sint, i64, -100, &buf);
    try testing.expectEqual(@as(i64, -100), (try decodeScalar(si)).value.signed);

    const wo = try encodeScalar(.word, i64, 0x5678, &buf);
    try testing.expectEqual(@as(u64, 0x5678), (try decodeScalar(wo)).value.unsigned);

    const dw = try encodeScalar(.dword, i64, 0x12345678, &buf);
    try testing.expectEqual(@as(u64, 0x12345678), (try decodeScalar(dw)).value.unsigned);
    const rid = try encodeScalar(.rid, i64, 0x0A0B0C0D, &buf);
    const dec_rid = try decodeScalar(rid);
    try testing.expectEqual(@as(u64, 0x0A0B0C0D), dec_rid.value.unsigned);
    try testing.expectEqual(@as(usize, 6), dec_rid.len); // flags + tag + 4 fixed octets

    const lw = try encodeScalar(.lword, i64, 0x1122334455667788, &buf);
    try testing.expectEqual(@as(u64, 0x1122334455667788), (try decodeScalar(lw)).value.unsigned);
    const ts = try encodeScalar(.timestamp, i64, 0x1122334455667788, &buf);
    try testing.expectEqual(@as(u64, 0x1122334455667788), (try decodeScalar(ts)).value.unsigned);

    const ul = try encodeScalar(.ulint, i64, 5_000_000_000, &buf);
    try testing.expectEqual(@as(u64, 5_000_000_000), (try decodeScalar(ul)).value.unsigned);

    const li = try encodeScalar(.lint, i64, -5_000_000_000, &buf);
    try testing.expectEqual(@as(i64, -5_000_000_000), (try decodeScalar(li)).value.signed);
    const tsp = try encodeScalar(.timespan, i64, -5_000_000_000, &buf);
    try testing.expectEqual(@as(i64, -5_000_000_000), (try decodeScalar(tsp)).value.signed);
}

test "valueLen walks a nested struct exactly" {
    // struct { id1: usint=7, id2: struct { id1: uint=0x0102 } }
    var buf: [64]u8 = undefined;
    var w: usize = 0;
    buf[w] = 0;
    w += 1; // outer flags
    buf[w] = @intFromEnum(Datatype.s7struct);
    w += 1;
    // element 1
    w += (try putVarUint(1, buf[w..])).len;
    w += (try encodeScalar(.usint, i64, 7, buf[w..])).len;
    // element 2 = nested struct
    w += (try putVarUint(2, buf[w..])).len;
    buf[w] = 0;
    w += 1;
    buf[w] = @intFromEnum(Datatype.s7struct);
    w += 1;
    w += (try putVarUint(1, buf[w..])).len;
    w += (try encodeScalar(.uint, i64, 0x0102, buf[w..])).len;
    w += (try putVarUint(0, buf[w..])).len; // terminate inner
    w += (try putVarUint(0, buf[w..])).len; // terminate outer

    // Trailing junk must be left untouched.
    buf[w] = 0xAB;
    try testing.expectEqual(w, try valueLen(buf[0 .. w + 1]));
}

test "a deeply nested struct is DepthExceeded, never a stack overflow" {
    var buf: [512]u8 = undefined;
    var w: usize = 0;
    // Open max_depth + 5 nested structs.
    var i: usize = 0;
    while (i < max_depth + 5) : (i += 1) {
        buf[w] = 0;
        w += 1;
        buf[w] = @intFromEnum(Datatype.s7struct);
        w += 1;
        w += (try putVarUint(1, buf[w..])).len; // element id 1 opens the next
    }
    try testing.expectError(error.DepthExceeded, valueLen(buf[0..w]));
}

test "an array count that overruns the buffer is Truncated" {
    // flags=array, datatype=uint(2 bytes), count=100, but only 4 bytes follow.
    var buf: [8]u8 = undefined;
    buf[0] = flag_array;
    buf[1] = @intFromEnum(Datatype.uint);
    const c = try putVarUint(100, buf[2..]);
    // Provide only two elements' worth.
    try testing.expectError(error.Truncated, valueLen(buf[0 .. 2 + c.len + 4]));
}

test "an absurd array count is TooLong, not a long loop" {
    var buf: [16]u8 = undefined;
    buf[0] = flag_array;
    buf[1] = @intFromEnum(Datatype.byte);
    const c = try putVarUint(max_elements + 1, buf[2..]);
    try testing.expectError(error.TooLong, valueLen(buf[0 .. 2 + c.len]));
}

test "a valid small array round trips through skipValue" {
    var buf: [16]u8 = undefined;
    buf[0] = flag_array;
    buf[1] = @intFromEnum(Datatype.byte);
    var w: usize = 2;
    w += (try putVarUint(3, buf[w..])).len;
    buf[w] = 0xAA;
    buf[w + 1] = 0xBB;
    buf[w + 2] = 0xCC;
    w += 3;
    try testing.expectEqual(w, try valueLen(buf[0..w]));
}

test "fuzz: value walker never panics or hangs" {
    try std.testing.fuzz({}, fuzzValue, .{});
}

fn fuzzValue(_: void, smith: *std.testing.Smith) !void {
    var buf: [512]u8 = undefined;
    smith.bytes(&buf);
    const len: usize = smith.valueRangeAtMost(u16, 0, buf.len);
    var cur = Cursor{ .bytes = buf[0..len] };
    // Either it validates a prefix as a value (consuming no more than present)
    // or it returns a typed error. Never a panic, never past the buffer.
    skipValue(&cur, max_depth) catch return;
    try testing.expect(cur.pos <= len);
}

test "fuzz: varint decoders never panic" {
    try std.testing.fuzz({}, fuzzVar, .{});
}

fn fuzzVar(_: void, smith: *std.testing.Smith) !void {
    var buf: [16]u8 = undefined;
    smith.bytes(&buf);
    const len: usize = smith.valueRangeAtMost(u8, 0, buf.len);
    if (getVarUint(u64, buf[0..len], 10)) |r| {
        try testing.expect(r.len <= len);
        // Re-encoding a decoded value and decoding again is a fixed point
        // (the encoder is canonical even if the input was not).
        var round: [16]u8 = undefined;
        const again = try putVarUint(r.value, &round);
        try testing.expectEqual(r.value, (try getVarUint(u64, again, 10)).value);
    } else |_| {}
    if (getVarInt(i64, buf[0..len], 10)) |r| {
        try testing.expect(r.len <= len);
        var round: [16]u8 = undefined;
        const again = try putVarInt(r.value, &round);
        try testing.expectEqual(r.value, (try getVarInt(i64, again, 10)).value);
    } else |_| {}
}
