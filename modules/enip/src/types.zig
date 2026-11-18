// SPDX-License-Identifier: MIT

//! **CIP data types** (Volume 1, Appendix C) and the Logix tag services that
//! carry them (`Read Tag` 0x4C, `Write Tag` 0x4D, and their fragmented forms
//! 0x52 / 0x53).
//!
//! The type code is a **16-bit little-endian value**, even though every
//! elementary type fits in one octet — `C3 00`, not `C3`. A structure reply
//! sends `A0 02` (that is, the 16-bit value `0x02A0`) followed by a two-octet
//! **structure handle** naming the UDT, and only then the member octets. A
//! decoder that treats the handle as data is off by two for the whole tag.
//!
//! Element count semantics, which the fragmented services make load-bearing:
//!
//! * `Read Tag` asks for *N elements* and gets back the type code and N
//!   elements' worth of octets — unless the reply would not fit, in which case
//!   the general status is `partial_transfer` (0x06) and *fewer* come back.
//! * `Read Tag Fragmented` adds a **byte offset**, not an element offset. The
//!   offset is into the tag's octets, so a caller resuming after a partial
//!   read advances by the octets it received and not by the elements.
//! * `Write Tag` sends the type code, then the count, then the values;
//!   `Write Tag Fragmented` inserts the byte offset between count and values.
//!   The orders differ, and swapping them writes plausible garbage.

const std = @import("std");

pub const DecodeError = error{
    /// The payload is shorter than the type code (and handle) require.
    Truncated,
    /// The data length is not a whole number of elements of the stated type.
    LengthNotAMultiple,
    /// A variable-width type (STRING, SHORT_STRING) whose length prefix runs
    /// past the data.
    StringOverruns,
    /// An element index past what the payload holds.
    OutOfRange,
    /// A type code this module cannot size, asked for as a fixed-width value.
    UnknownType,
    /// A structure reply missing its handle.
    MissingStructureHandle,
};

pub const EncodeError = error{
    BufferTooSmall,
    /// More elements than the 16-bit count field can express.
    TooManyElements,
    /// A string longer than its length prefix can express.
    StringTooLong,
};

/// CIP elementary and constructed type codes.
pub const DataType = enum(u16) {
    /// One octet on the wire; any non-zero value is true, and Logix writes
    /// `0xFF`.
    bool = 0x00C1,
    sint = 0x00C2,
    int = 0x00C3,
    dint = 0x00C4,
    lint = 0x00C5,
    usint = 0x00C6,
    uint = 0x00C7,
    udint = 0x00C8,
    ulint = 0x00C9,
    real = 0x00CA,
    lreal = 0x00CB,
    stime = 0x00CC,
    date = 0x00CD,
    time_of_day = 0x00CE,
    date_and_time = 0x00CF,
    /// 16-bit length prefix, then that many octets.
    string = 0x00D0,
    byte = 0x00D1,
    word = 0x00D2,
    dword = 0x00D3,
    lword = 0x00D4,
    string2 = 0x00D5,
    ftime = 0x00D6,
    ltime = 0x00D7,
    itime = 0x00D8,
    stringn = 0x00D9,
    /// 8-bit length prefix, then that many octets.
    short_string = 0x00DA,
    time = 0x00DB,
    epath = 0x00DC,
    engunit = 0x00DD,
    stringi = 0x00DE,
    /// The code a Logix structure (UDT) read answers with. Followed by a
    /// two-octet structure handle.
    structure = 0x02A0,
    /// An abbreviated structure — same handle rule.
    abbreviated_structure = 0x02A2,
    _,

    /// Octets one element occupies, or null for a variable-width or
    /// structured type whose size only the device knows.
    ///
    /// `date_and_time` (0xCF) is deliberately **not** sized: the published
    /// tables disagree about its width, and guessing wrong silently
    /// mis-slices an array. It is handed back as `.raw`.
    pub fn elementSize(t: DataType) ?usize {
        return switch (t) {
            .bool, .sint, .usint, .byte => 1,
            .int, .uint, .word, .itime, .date => 2,
            .dint, .udint, .dword, .real, .stime, .time_of_day, .ftime, .time => 4,
            .lint, .ulint, .lword, .lreal, .ltime => 8,
            else => null,
        };
    }

    /// True for the two codes that carry a structure handle after them.
    pub fn hasStructureHandle(t: DataType) bool {
        return t == .structure or t == .abbreviated_structure;
    }

    pub fn isString(t: DataType) bool {
        return t == .string or t == .short_string or t == .string2 or t == .stringn or t == .stringi;
    }
};

/// A decoded CIP value.
pub const Value = union(enum) {
    boolean: bool,
    sint: i8,
    int: i16,
    dint: i32,
    lint: i64,
    usint: u8,
    uint: u16,
    udint: u32,
    ulint: u64,
    real: f32,
    lreal: f64,
    byte: u8,
    word: u16,
    dword: u32,
    lword: u64,
    /// STRING / SHORT_STRING contents, without the length prefix.
    string: []const u8,
    /// Anything this module does not model as a scalar — a structure's
    /// members, an EPATH, a STRINGI — handed back verbatim.
    raw: []const u8,

    /// The value as an `i64` where that is meaningful, for the common case of
    /// "just give me the number".
    pub fn asInt(self: Value) ?i64 {
        return switch (self) {
            .boolean => |b| @intFromBool(b),
            .sint => |v| v,
            .int => |v| v,
            .dint => |v| v,
            .lint => |v| v,
            .usint => |v| v,
            .uint => |v| v,
            .udint => |v| v,
            .ulint => |v| if (v <= std.math.maxInt(i64)) @intCast(v) else null,
            .byte => |v| v,
            .word => |v| v,
            .dword => |v| v,
            .lword => |v| if (v <= std.math.maxInt(i64)) @intCast(v) else null,
            else => null,
        };
    }

    pub fn asFloat(self: Value) ?f64 {
        return switch (self) {
            .real => |v| v,
            .lreal => |v| v,
            else => if (self.asInt()) |i| @floatFromInt(i) else null,
        };
    }
};

/// Decodes one element of `t` from the front of `bytes`.
pub fn decodeValue(t: DataType, bytes: []const u8) DecodeError!Value {
    if (t.elementSize()) |n| {
        if (bytes.len < n) return error.Truncated;
        return switch (t) {
            .bool => .{ .boolean = bytes[0] != 0 },
            .sint => .{ .sint = @bitCast(bytes[0]) },
            .usint => .{ .usint = bytes[0] },
            .byte => .{ .byte = bytes[0] },
            .int, .itime => .{ .int = std.mem.readInt(i16, bytes[0..2], .little) },
            .uint, .date => .{ .uint = std.mem.readInt(u16, bytes[0..2], .little) },
            .word => .{ .word = std.mem.readInt(u16, bytes[0..2], .little) },
            .dint, .stime, .ftime, .time => .{ .dint = std.mem.readInt(i32, bytes[0..4], .little) },
            .udint, .time_of_day => .{ .udint = std.mem.readInt(u32, bytes[0..4], .little) },
            .dword => .{ .dword = std.mem.readInt(u32, bytes[0..4], .little) },
            .real => .{ .real = @bitCast(std.mem.readInt(u32, bytes[0..4], .little)) },
            .lint, .ltime => .{ .lint = std.mem.readInt(i64, bytes[0..8], .little) },
            .ulint => .{ .ulint = std.mem.readInt(u64, bytes[0..8], .little) },
            .lword => .{ .lword = std.mem.readInt(u64, bytes[0..8], .little) },
            .lreal => .{ .lreal = @bitCast(std.mem.readInt(u64, bytes[0..8], .little)) },
            else => unreachable,
        };
    }
    switch (t) {
        .short_string => {
            if (bytes.len < 1) return error.Truncated;
            const n: usize = bytes[0];
            if (1 + n > bytes.len) return error.StringOverruns;
            return .{ .string = bytes[1 .. 1 + n] };
        },
        .string => {
            if (bytes.len < 2) return error.Truncated;
            const n: usize = std.mem.readInt(u16, bytes[0..2], .little);
            if (2 + n > bytes.len) return error.StringOverruns;
            return .{ .string = bytes[2 .. 2 + n] };
        },
        else => return .{ .raw = bytes },
    }
}

/// Octets one encoded element of `v` occupies.
pub fn encodedValueLen(v: Value) usize {
    return switch (v) {
        .boolean, .sint, .usint, .byte => 1,
        .int, .uint, .word => 2,
        .dint, .udint, .dword, .real => 4,
        .lint, .ulint, .lword, .lreal => 8,
        .string => |s| 1 + s.len,
        .raw => |r| r.len,
    };
}

/// Encodes one value. `.string` is written as a SHORT_STRING; use
/// `encodeString` for the 16-bit-prefixed form.
pub fn encodeValue(v: Value, out: []u8) EncodeError![]u8 {
    const n = encodedValueLen(v);
    if (out.len < n) return error.BufferTooSmall;
    switch (v) {
        .boolean => |b| out[0] = if (b) 0xFF else 0x00,
        .sint => |x| out[0] = @bitCast(x),
        .usint, .byte => |x| out[0] = x,
        .int => |x| std.mem.writeInt(i16, out[0..2], x, .little),
        .uint, .word => |x| std.mem.writeInt(u16, out[0..2], x, .little),
        .dint => |x| std.mem.writeInt(i32, out[0..4], x, .little),
        .udint, .dword => |x| std.mem.writeInt(u32, out[0..4], x, .little),
        .real => |x| std.mem.writeInt(u32, out[0..4], @bitCast(x), .little),
        .lint => |x| std.mem.writeInt(i64, out[0..8], x, .little),
        .ulint, .lword => |x| std.mem.writeInt(u64, out[0..8], x, .little),
        .lreal => |x| std.mem.writeInt(u64, out[0..8], @bitCast(x), .little),
        .string => |s| {
            if (s.len > 255) return error.StringTooLong;
            out[0] = @intCast(s.len);
            @memcpy(out[1..][0..s.len], s);
        },
        .raw => |r| @memcpy(out[0..r.len], r),
    }
    return out[0..n];
}

// ── a decoded tag payload ──────────────────────────────────────────────────

/// The payload of a `Read Tag` reply: a type code, an optional structure
/// handle, and the element octets.
pub const TagData = struct {
    type: DataType,
    /// Present exactly when the type is a structure.
    structure_handle: ?u16 = null,
    /// The element octets, with the type code and handle stripped.
    data: []const u8,

    /// Decodes the reply payload of `Read Tag` / `Read Tag Fragmented`.
    pub fn decode(payload: []const u8) DecodeError!TagData {
        if (payload.len < 2) return error.Truncated;
        const t: DataType = @fromBackingInt(@intCast(std.mem.readInt(u16, payload[0..2], .little)));
        if (t.hasStructureHandle()) {
            if (payload.len < 4) return error.MissingStructureHandle;
            return .{
                .type = t,
                .structure_handle = std.mem.readInt(u16, payload[2..4], .little),
                .data = payload[4..],
            };
        }
        return .{ .type = t, .data = payload[2..] };
    }

    pub fn encodedLen(self: TagData) usize {
        return 2 + @as(usize, if (self.structure_handle != null) 2 else 0) + self.data.len;
    }

    pub fn encode(self: TagData, out: []u8) EncodeError![]u8 {
        const total = self.encodedLen();
        if (out.len < total) return error.BufferTooSmall;
        std.mem.writeInt(u16, out[0..2], @backingInt(self.type), .little);
        var off: usize = 2;
        if (self.structure_handle) |h| {
            std.mem.writeInt(u16, out[2..4], h, .little);
            off = 4;
        }
        @memcpy(out[off..][0..self.data.len], self.data);
        return out[0..total];
    }

    /// How many whole elements the payload holds. Null for a variable-width
    /// or structured type, where only the device knows.
    pub fn elementCount(self: TagData) ?usize {
        const n = self.type.elementSize() orelse return null;
        if (n == 0) return null;
        return self.data.len / n;
    }

    /// The `i`-th element. Fixed-width types are indexed directly; a
    /// SHORT_STRING array is walked from the front, because its elements are
    /// not the same width.
    pub fn at(self: TagData, i: usize) DecodeError!Value {
        if (self.type.elementSize()) |n| {
            // `i` is caller-supplied and `n` is wire-derived, so `i * n` and
            // `start + n` are both attacker-influenced products: compute the
            // bound by subtraction on the (known-small) buffer length instead,
            // so a huge `i` reports `OutOfRange` rather than wrapping into an
            // in-bounds `start` under ReleaseFast.
            const start = std.math.mul(usize, i, n) catch return error.OutOfRange;
            if (n > self.data.len or start > self.data.len - n) return error.OutOfRange;
            return decodeValue(self.type, self.data[start..]);
        }
        if (self.type == .short_string or self.type == .string) {
            var off: usize = 0;
            var k: usize = 0;
            while (k < i) : (k += 1) {
                const v = try decodeValue(self.type, self.data[off..]);
                off += switch (self.type) {
                    .short_string => 1 + v.string.len,
                    else => 2 + v.string.len,
                };
                if (off > self.data.len) return error.OutOfRange;
            }
            if (off >= self.data.len) return error.OutOfRange;
            return decodeValue(self.type, self.data[off..]);
        }
        if (i != 0) return error.OutOfRange;
        return .{ .raw = self.data };
    }

    /// Refuses a payload whose octet count is not a whole number of elements
    /// of the stated type — the "type code contradicts the data length" case.
    pub fn validate(self: TagData) DecodeError!void {
        const n = self.type.elementSize() orelse return;
        if (n == 0) return error.UnknownType;
        if (self.data.len % n != 0) return error.LengthNotAMultiple;
    }
};

// ── Logix tag service payloads ─────────────────────────────────────────────

/// `Read Tag` (0x4C) request data: an element count.
pub const ReadTagRequest = struct {
    count: u16 = 1,

    pub const encoded_len: usize = 2;

    pub fn decode(bytes: []const u8) DecodeError!ReadTagRequest {
        if (bytes.len < 2) return error.Truncated;
        return .{ .count = std.mem.readInt(u16, bytes[0..2], .little) };
    }

    pub fn encode(self: ReadTagRequest, out: []u8) EncodeError![]u8 {
        if (out.len < 2) return error.BufferTooSmall;
        std.mem.writeInt(u16, out[0..2], self.count, .little);
        return out[0..2];
    }
};

/// `Read Tag Fragmented` (0x52) request data: an element count and a **byte**
/// offset into the tag.
pub const ReadTagFragmentedRequest = struct {
    count: u16 = 1,
    byte_offset: u32 = 0,

    pub const encoded_len: usize = 6;

    pub fn decode(bytes: []const u8) DecodeError!ReadTagFragmentedRequest {
        if (bytes.len < 6) return error.Truncated;
        return .{
            .count = std.mem.readInt(u16, bytes[0..2], .little),
            .byte_offset = std.mem.readInt(u32, bytes[2..6], .little),
        };
    }

    pub fn encode(self: ReadTagFragmentedRequest, out: []u8) EncodeError![]u8 {
        if (out.len < 6) return error.BufferTooSmall;
        std.mem.writeInt(u16, out[0..2], self.count, .little);
        std.mem.writeInt(u32, out[2..6], self.byte_offset, .little);
        return out[0..6];
    }
};

/// `Write Tag` (0x4D) request data: type code, optional structure handle,
/// element count, then the values.
pub const WriteTagRequest = struct {
    type: DataType,
    structure_handle: ?u16 = null,
    count: u16 = 1,
    values: []const u8,

    pub fn encodedLen(self: WriteTagRequest) usize {
        return 2 + @as(usize, if (self.structure_handle != null) 2 else 0) + 2 + self.values.len;
    }

    pub fn decode(bytes: []const u8) DecodeError!WriteTagRequest {
        if (bytes.len < 4) return error.Truncated;
        const t: DataType = @fromBackingInt(@intCast(std.mem.readInt(u16, bytes[0..2], .little)));
        var off: usize = 2;
        var handle: ?u16 = null;
        if (t.hasStructureHandle()) {
            if (bytes.len < 6) return error.MissingStructureHandle;
            handle = std.mem.readInt(u16, bytes[2..4], .little);
            off = 4;
        }
        if (off + 2 > bytes.len) return error.Truncated;
        const count = std.mem.readInt(u16, bytes[off..][0..2], .little);
        return .{
            .type = t,
            .structure_handle = handle,
            .count = count,
            .values = bytes[off + 2 ..],
        };
    }

    pub fn encode(self: WriteTagRequest, out: []u8) EncodeError![]u8 {
        const total = self.encodedLen();
        if (out.len < total) return error.BufferTooSmall;
        std.mem.writeInt(u16, out[0..2], @backingInt(self.type), .little);
        var off: usize = 2;
        if (self.structure_handle) |h| {
            std.mem.writeInt(u16, out[2..4], h, .little);
            off = 4;
        }
        std.mem.writeInt(u16, out[off..][0..2], self.count, .little);
        off += 2;
        @memcpy(out[off..][0..self.values.len], self.values);
        return out[0..total];
    }
};

/// `Write Tag Fragmented` (0x53) request data: the same as `Write Tag`, with
/// a **byte** offset inserted between the count and the values.
pub const WriteTagFragmentedRequest = struct {
    type: DataType,
    structure_handle: ?u16 = null,
    /// The **total** element count of the tag, repeated in every fragment.
    count: u16 = 1,
    byte_offset: u32 = 0,
    values: []const u8,

    pub fn encodedLen(self: WriteTagFragmentedRequest) usize {
        return 2 + @as(usize, if (self.structure_handle != null) 2 else 0) + 2 + 4 + self.values.len;
    }

    pub fn decode(bytes: []const u8) DecodeError!WriteTagFragmentedRequest {
        if (bytes.len < 8) return error.Truncated;
        const t: DataType = @fromBackingInt(@intCast(std.mem.readInt(u16, bytes[0..2], .little)));
        var off: usize = 2;
        var handle: ?u16 = null;
        if (t.hasStructureHandle()) {
            if (bytes.len < 10) return error.MissingStructureHandle;
            handle = std.mem.readInt(u16, bytes[2..4], .little);
            off = 4;
        }
        if (off + 6 > bytes.len) return error.Truncated;
        const count = std.mem.readInt(u16, bytes[off..][0..2], .little);
        const byte_offset = std.mem.readInt(u32, bytes[off + 2 ..][0..4], .little);
        return .{
            .type = t,
            .structure_handle = handle,
            .count = count,
            .byte_offset = byte_offset,
            .values = bytes[off + 6 ..],
        };
    }

    pub fn encode(self: WriteTagFragmentedRequest, out: []u8) EncodeError![]u8 {
        const total = self.encodedLen();
        if (out.len < total) return error.BufferTooSmall;
        std.mem.writeInt(u16, out[0..2], @backingInt(self.type), .little);
        var off: usize = 2;
        if (self.structure_handle) |h| {
            std.mem.writeInt(u16, out[2..4], h, .little);
            off = 4;
        }
        std.mem.writeInt(u16, out[off..][0..2], self.count, .little);
        std.mem.writeInt(u32, out[off + 2 ..][0..4], self.byte_offset, .little);
        off += 6;
        @memcpy(out[off..][0..self.values.len], self.values);
        return out[0..total];
    }
};

// ── tests ───────────────────────────────────────────────────────────────────

const testing = std.testing;

test "elementary types size and decode" {
    try testing.expectEqual(@as(?usize, 2), DataType.int.elementSize());
    try testing.expectEqual(@as(?usize, 4), DataType.real.elementSize());
    try testing.expectEqual(@as(?usize, 8), DataType.lreal.elementSize());
    try testing.expectEqual(@as(?usize, null), DataType.short_string.elementSize());

    try testing.expectEqual(@as(i64, -7), (try decodeValue(.int, &[_]u8{ 0xF9, 0xFF })).asInt().?);
    try testing.expectEqual(@as(i64, 11), (try decodeValue(.dint, &[_]u8{ 11, 0, 0, 0 })).asInt().?);
    try testing.expectEqual(@as(f64, 3.5), (try decodeValue(.real, &[_]u8{ 0x00, 0x00, 0x60, 0x40 })).asFloat().?);
    try testing.expect((try decodeValue(.bool, &[_]u8{0xFF})).boolean);
    try testing.expect(!(try decodeValue(.bool, &[_]u8{0x00})).boolean);
    try testing.expectError(error.Truncated, decodeValue(.dint, &[_]u8{ 1, 2 }));
}

test "strings carry their own length prefix" {
    const short = [_]u8{ 0x05, 'h', 'e', 'l', 'l', 'o' };
    try testing.expectEqualStrings("hello", (try decodeValue(.short_string, &short)).string);
    const long = [_]u8{ 0x03, 0x00, 'a', 'b', 'c' };
    try testing.expectEqualStrings("abc", (try decodeValue(.string, &long)).string);
    // A length prefix that runs past the data.
    try testing.expectError(error.StringOverruns, decodeValue(.short_string, &[_]u8{ 0x20, 'x' }));
    try testing.expectError(error.StringOverruns, decodeValue(.string, &[_]u8{ 0x20, 0x00, 'x' }));
    try testing.expectError(error.Truncated, decodeValue(.string, &[_]u8{0x01}));
}

test "values round trip through encode" {
    var buf: [16]u8 = undefined;
    try testing.expectEqualSlices(u8, &[_]u8{ 0xF9, 0xFF }, try encodeValue(.{ .int = -7 }, &buf));
    try testing.expectEqualSlices(u8, &[_]u8{ 0x00, 0x00, 0x60, 0x40 }, try encodeValue(.{ .real = 3.5 }, &buf));
    try testing.expectEqualSlices(u8, &[_]u8{0xFF}, try encodeValue(.{ .boolean = true }, &buf));
    try testing.expectEqualSlices(u8, &[_]u8{ 0x02, 'h', 'i' }, try encodeValue(.{ .string = "hi" }, &buf));
    try testing.expectError(error.BufferTooSmall, encodeValue(.{ .lreal = 1.0 }, buf[0..4]));
}

test "a tag read payload splits type code from elements" {
    // Exactly what a real INT[4] read answers: c3 00 then four INTs.
    const payload = [_]u8{ 0xC3, 0x00, 0x01, 0x00, 0x02, 0x00, 0x03, 0x00, 0x04, 0x00 };
    const td = try TagData.decode(&payload);
    try testing.expectEqual(DataType.int, td.type);
    try testing.expectEqual(@as(?u16, null), td.structure_handle);
    try testing.expectEqual(@as(?usize, 4), td.elementCount());
    try td.validate();
    try testing.expectEqual(@as(i64, 3), (try td.at(2)).asInt().?);
    try testing.expectError(error.OutOfRange, td.at(4));
    var out: [16]u8 = undefined;
    try testing.expectEqualSlices(u8, &payload, try td.encode(&out));
}

test "TagData.at reports OutOfRange instead of wrapping on a huge index" {
    // `at` is public API over a wire-decoded struct. Before the guard, `i * n`
    // and `start + n` were unchecked: in Debug they trap, and in ReleaseFast a
    // large `i` wraps into an in-bounds `start` and silently returns the WRONG
    // element instead of `error.OutOfRange`.
    const payload = [_]u8{ 0xC3, 0x00, 0x01, 0x00, 0x02, 0x00, 0x03, 0x00, 0x04, 0x00 };
    const td = try TagData.decode(&payload);
    try testing.expectEqual(@as(?usize, 2), td.type.elementSize());
    // i * 2 wraps to 0 -> element 0 ("1") would come back as if in range.
    // Target-relative, not a hardcoded 64-bit literal: "half of usize's
    // range, rounded up" is what makes `* 2` wrap regardless of pointer
    // width (on 64-bit this equals the original `1 << 63` exactly).
    const wrapping_index: usize = (std.math.maxInt(usize) / 2) + 1;
    try testing.expectError(error.OutOfRange, td.at(wrapping_index));
    // i * 2 wraps to `start = data.len - n`, i.e. the LAST element.
    try testing.expectError(error.OutOfRange, td.at(wrapping_index + 3));
    // start + n overflows while start itself does not.
    try testing.expectError(error.OutOfRange, td.at(std.math.maxInt(usize) / 2));
    // A one-byte element type: `start + n` is the only overflow route left.
    const sint = TagData{ .type = .sint, .data = payload[2..], .structure_handle = null };
    try testing.expectError(error.OutOfRange, sint.at(std.math.maxInt(usize)));
}

test "a structure read carries a handle the data does not include" {
    const payload = [_]u8{ 0xA0, 0x02, 0x34, 0x12, 0xAA, 0xBB, 0xCC };
    const td = try TagData.decode(&payload);
    try testing.expectEqual(DataType.structure, td.type);
    try testing.expectEqual(@as(?u16, 0x1234), td.structure_handle);
    try testing.expectEqualSlices(u8, &[_]u8{ 0xAA, 0xBB, 0xCC }, td.data);
    try testing.expectEqual(@as(?usize, null), td.elementCount());
    try testing.expectEqualSlices(u8, &[_]u8{ 0xAA, 0xBB, 0xCC }, (try td.at(0)).raw);
    var out: [16]u8 = undefined;
    try testing.expectEqualSlices(u8, &payload, try td.encode(&out));
    // A structure code with no room for its handle.
    try testing.expectError(error.MissingStructureHandle, TagData.decode(&[_]u8{ 0xA0, 0x02, 0x34 }));
}

test "a type code that contradicts the data length is refused" {
    // DINT (4 octets) with 6 octets of data.
    const payload = [_]u8{ 0xC4, 0x00, 1, 2, 3, 4, 5, 6 };
    const td = try TagData.decode(&payload);
    try testing.expectError(error.LengthNotAMultiple, td.validate());
    // …and indexing past the whole elements still fails cleanly.
    _ = try td.at(0);
    try testing.expectError(error.OutOfRange, td.at(1));
}

test "a short-string array is walked, not indexed" {
    // Two SHORT_STRINGs of different lengths.
    const payload = [_]u8{ 0xDA, 0x00, 0x05, 'h', 'e', 'l', 'l', 'o', 0x02, 'h', 'i' };
    const td = try TagData.decode(&payload);
    try testing.expectEqualStrings("hello", (try td.at(0)).string);
    try testing.expectEqualStrings("hi", (try td.at(1)).string);
    try testing.expectError(error.OutOfRange, td.at(2));
}

test "read tag request payloads round trip" {
    var buf: [8]u8 = undefined;
    try testing.expectEqualSlices(u8, &[_]u8{ 0x04, 0x00 }, try (ReadTagRequest{ .count = 4 }).encode(&buf));
    try testing.expectEqual(@as(u16, 4), (try ReadTagRequest.decode(&[_]u8{ 0x04, 0x00 })).count);
    const frag = ReadTagFragmentedRequest{ .count = 10, .byte_offset = 20 };
    const wire = try frag.encode(&buf);
    try testing.expectEqualSlices(u8, &[_]u8{ 0x0A, 0x00, 0x14, 0x00, 0x00, 0x00 }, wire);
    const back = try ReadTagFragmentedRequest.decode(wire);
    try testing.expectEqual(@as(u32, 20), back.byte_offset);
    try testing.expectError(error.Truncated, ReadTagFragmentedRequest.decode(wire[0..5]));
}

test "write tag and its fragmented form order their fields differently" {
    var buf: [32]u8 = undefined;
    const w = WriteTagRequest{ .type = .int, .count = 1, .values = &[_]u8{ 0xF9, 0xFF } };
    // type, count, values — no offset.
    try testing.expectEqualSlices(
        u8,
        &[_]u8{ 0xC3, 0x00, 0x01, 0x00, 0xF9, 0xFF },
        try w.encode(&buf),
    );
    const wf = WriteTagFragmentedRequest{
        .type = .int,
        .count = 4,
        .byte_offset = 0,
        .values = &[_]u8{ 1, 0, 2, 0, 3, 0, 4, 0 },
    };
    // type, count, offset, values.
    try testing.expectEqualSlices(
        u8,
        &[_]u8{ 0xC3, 0x00, 0x04, 0x00, 0x00, 0x00, 0x00, 0x00, 1, 0, 2, 0, 3, 0, 4, 0 },
        try wf.encode(&buf),
    );
    const back = try WriteTagFragmentedRequest.decode(try wf.encode(&buf));
    try testing.expectEqual(@as(u16, 4), back.count);
    try testing.expectEqual(@as(u32, 0), back.byte_offset);
    try testing.expectEqual(@as(usize, 8), back.values.len);
}

test "a write of a structure carries its handle" {
    var buf: [32]u8 = undefined;
    const w = WriteTagRequest{
        .type = .structure,
        .structure_handle = 0x1234,
        .count = 1,
        .values = &[_]u8{ 0xAA, 0xBB },
    };
    const wire = try w.encode(&buf);
    try testing.expectEqualSlices(u8, &[_]u8{ 0xA0, 0x02, 0x34, 0x12, 0x01, 0x00, 0xAA, 0xBB }, wire);
    const back = try WriteTagRequest.decode(wire);
    try testing.expectEqual(@as(?u16, 0x1234), back.structure_handle);
    try testing.expectEqualSlices(u8, &[_]u8{ 0xAA, 0xBB }, back.values);
    try testing.expectError(error.MissingStructureHandle, WriteTagRequest.decode(&[_]u8{ 0xA0, 0x02, 0x34, 0x12, 0x01 }));
}

/// The corpus-entry format `Smith.slice` reads: a little-endian u32 length,
/// then the frame. Was a local copy in every file that needed it — 33 across 12
/// modules — each with its own note about the same trap (the array has to be
/// container-level or the returned slice dangles with the RIGHT length and
/// garbage behind it). It lives in `testkit.fuzz` now, with tests that drive the
/// real `std.testing.Smith` over what it produces.
const fuzzSeed = @import("testkit").fuzz.seedHex;
const fz = @import("fuzz_test.zig");

/// Tag payloads: a two-octet type code and its value, which is what `TagData`
/// and `WriteTagRequest` both read, plus the bare values `decodeValue` takes.
const type_seeds = [_][]const u8{
    fuzzSeed("c2002a"), // SINT 42
    fuzzSeed("c3002a00"), // INT 42
    fuzzSeed("c4002a000000"), // DINT 42
    fuzzSeed("ca0000006040"), // REAL 3.5
    fuzzSeed("c10001"), // BOOL true
    fuzzSeed("c4000100020003000400"), // a DINT array, four elements
    fuzzSeed("a002341201"), // a structure with a template handle
    fuzzSeed("a0023412010000aabb"), // a structure with a body
    fuzzSeed("a0023412aabbcc"), // a structure whose body is not a whole number of elements
    fuzzSeed("c4002a00"), // a DINT with only two octets of value
    fuzzSeed("050068656c6c6f"), // a SHORT_STRING
    fuzzSeed("030000616263"), // a STRING
    fuzzSeed("ffffaabb"), // a type code nobody defines
    fuzzSeed("c400"), // a type code and no value
};

test "fuzz: value and tag payload decoding never panics" {
    try std.testing.fuzz({}, fuzzTypesSmith, .{ .corpus = &type_seeds });
}

const fuzzTypesMark = fz.Marker(enum { ran, nonempty });

fn fuzzTypesSmith(_: void, smith: *std.testing.Smith) !void {
    try fuzzTypes(std.testing.Smith, smith, std.testing.allocator);
}

fn fuzzTypes(comptime S: type, src: *S, gpa: std.mem.Allocator) anyerror!void {
    _ = gpa;
    var buf: [256]u8 = undefined;
    // ⚠ One `smith.slice` call, never `bytes` followed by a ranged length.
    // `Smith.bytes` consumes the whole remaining seed, and the ranged draw then
    // finds fewer than eight octets left and returns the range MINIMUM — so the
    // length was 0 for every seed and this harness only ever saw the empty
    // input. Measured on 2026-09-06 over the corpus above: **0 of 14
    // non-empty, one single (payload, type code) pair, and 0 that `TagData`
    // accepted before; 14 of 14 non-empty, 14 distinct pairs and 14 accepted
    // after.**
    const len: usize = fz.drawInput(S, src, &buf, &type_seeds);
    fuzzTypesMark.mark(.ran);
    if (len != 0) fuzzTypesMark.mark(.nonempty);
    // The type code follows the payload and is drawn with `value(u64)`. A
    // ranged draw over the WHOLE `u16` range does contain the word it reads
    // whenever that word happens to be below 65536, so this one was not
    // hopeless — but `bytes` had already emptied the seed, so it was 0 anyway.
    const code: u16 = @truncate(src.value(u64));
    const t: DataType = @fromBackingInt(@intCast(code));
    _ = decodeValue(t, buf[0..len]) catch {};

    if (TagData.decode(buf[0..len])) |td| {
        var round: [256]u8 = undefined;
        try testing.expectEqualSlices(u8, buf[0..len], try td.encode(&round));
        _ = td.validate() catch {};
        var i: usize = 0;
        while (i < 32) : (i += 1) _ = td.at(i) catch break;
    } else |_| {}

    if (WriteTagRequest.decode(buf[0..len])) |w| {
        var round: [256]u8 = undefined;
        try testing.expectEqualSlices(u8, buf[0..len], try w.encode(&round));
    } else |_| {}
    if (WriteTagFragmentedRequest.decode(buf[0..len])) |w| {
        var round: [256]u8 = undefined;
        try testing.expectEqualSlices(u8, buf[0..len], try w.encode(&round));
    } else |_| {}
    _ = ReadTagRequest.decode(buf[0..len]) catch {};
    _ = ReadTagFragmentedRequest.decode(buf[0..len]) catch {};
}

test "fuzz driver: ENIP_FUZZ (fuzzTypes)" {
    try fz.fuzz_driver.run(fuzzTypes, .{ .prefix = "ENIP_FUZZ", .name = "enip-types-types" });
}

test "fuzz harness: fuzzTypes, 400 seeds, reaches every outcome" {
    try fuzzTypesMark.reach(fuzzTypes, "enip-types-types", 400);
}

// ── whole-module mutation audit 2026-11-17: boundary tests ────────────────

test "element sizes: every sized type, and the types that have none" {
    const Case = struct { t: DataType, n: ?usize };
    const cases = [_]Case{
        .{ .t = .bool, .n = 1 },            .{ .t = .sint, .n = 1 },                     .{ .t = .usint, .n = 1 },
        .{ .t = .byte, .n = 1 },            .{ .t = .int, .n = 2 },                      .{ .t = .uint, .n = 2 },
        .{ .t = .word, .n = 2 },            .{ .t = .itime, .n = 2 },                    .{ .t = .date, .n = 2 },
        .{ .t = .dint, .n = 4 },            .{ .t = .udint, .n = 4 },                    .{ .t = .dword, .n = 4 },
        .{ .t = .real, .n = 4 },            .{ .t = .stime, .n = 4 },                    .{ .t = .time_of_day, .n = 4 },
        .{ .t = .ftime, .n = 4 },           .{ .t = .time, .n = 4 },                     .{ .t = .lint, .n = 8 },
        .{ .t = .ulint, .n = 8 },           .{ .t = .lword, .n = 8 },                    .{ .t = .lreal, .n = 8 },
        .{ .t = .ltime, .n = 8 },           .{ .t = .date_and_time, .n = null },         .{ .t = .string, .n = null },
        .{ .t = .short_string, .n = null }, .{ .t = .string2, .n = null },               .{ .t = .stringn, .n = null },
        .{ .t = .stringi, .n = null },      .{ .t = .epath, .n = null },                 .{ .t = .engunit, .n = null },
        .{ .t = .structure, .n = null },    .{ .t = .abbreviated_structure, .n = null },
    };
    for (cases) |c| try testing.expectEqual(c.n, c.t.elementSize());
    for ([_]DataType{ .string, .short_string, .string2, .stringn, .stringi }) |t| try testing.expect(t.isString());
    for ([_]DataType{ .bool, .structure, .epath, .date_and_time }) |t| try testing.expect(!t.isString());
    try testing.expect(DataType.structure.hasStructureHandle());
    try testing.expect(DataType.abbreviated_structure.hasStructureHandle());
    try testing.expect(!DataType.dint.hasStructureHandle());
}

test "Value.asInt and asFloat cover every integer variant and refuse what does not fit" {
    const mx: u64 = std.math.maxInt(i64);
    try testing.expectEqual(@as(?i64, 1), (Value{ .boolean = true }).asInt());
    try testing.expectEqual(@as(?i64, 0), (Value{ .boolean = false }).asInt());
    try testing.expectEqual(@as(?i64, -5), (Value{ .sint = -5 }).asInt());
    try testing.expectEqual(@as(?i64, -300), (Value{ .int = -300 }).asInt());
    try testing.expectEqual(@as(?i64, -70000), (Value{ .dint = -70000 }).asInt());
    try testing.expectEqual(@as(?i64, -5_000_000_000), (Value{ .lint = -5_000_000_000 }).asInt());
    try testing.expectEqual(@as(?i64, 200), (Value{ .usint = 200 }).asInt());
    try testing.expectEqual(@as(?i64, 60000), (Value{ .uint = 60000 }).asInt());
    try testing.expectEqual(@as(?i64, 4_000_000_000), (Value{ .udint = 4_000_000_000 }).asInt());
    try testing.expectEqual(@as(?i64, @intCast(mx)), (Value{ .ulint = mx }).asInt());
    try testing.expectEqual(@as(?i64, null), (Value{ .ulint = mx + 1 }).asInt());
    try testing.expectEqual(@as(?i64, 7), (Value{ .byte = 7 }).asInt());
    try testing.expectEqual(@as(?i64, 9), (Value{ .word = 9 }).asInt());
    try testing.expectEqual(@as(?i64, 11), (Value{ .dword = 11 }).asInt());
    try testing.expectEqual(@as(?i64, @intCast(mx)), (Value{ .lword = mx }).asInt());
    try testing.expectEqual(@as(?i64, null), (Value{ .lword = mx + 1 }).asInt());
    try testing.expectEqual(@as(?i64, null), (Value{ .string = "x" }).asInt());
    try testing.expectEqual(@as(?f64, 2.5), (Value{ .lreal = 2.5 }).asFloat());
    try testing.expectEqual(@as(?f64, 1.5), (Value{ .real = 1.5 }).asFloat());
    try testing.expectEqual(@as(?f64, 3.0), (Value{ .int = 3 }).asFloat());
    try testing.expectEqual(@as(?f64, null), (Value{ .raw = "x" }).asFloat());
}

test "multi-octet values decode little-endian, one type at a time" {
    try testing.expectEqual(true, (try decodeValue(.bool, &.{1})).boolean);
    try testing.expectEqual(false, (try decodeValue(.bool, &.{0})).boolean);
    try testing.expectEqual(@as(u16, 0x1234), (try decodeValue(.uint, &.{ 0x34, 0x12 })).uint);
    try testing.expectEqual(@as(u16, 0x1234), (try decodeValue(.date, &.{ 0x34, 0x12 })).uint);
    try testing.expectEqual(@as(u16, 0x1234), (try decodeValue(.word, &.{ 0x34, 0x12 })).word);
    try testing.expectEqual(@as(i16, 0x1234), (try decodeValue(.itime, &.{ 0x34, 0x12 })).int);
    try testing.expectEqual(@as(u32, 0x01020304), (try decodeValue(.udint, &.{ 4, 3, 2, 1 })).udint);
    try testing.expectEqual(@as(u32, 0x01020304), (try decodeValue(.time_of_day, &.{ 4, 3, 2, 1 })).udint);
    try testing.expectEqual(@as(u32, 0x01020304), (try decodeValue(.dword, &.{ 4, 3, 2, 1 })).dword);
    try testing.expectEqual(@as(i32, 0x01020304), (try decodeValue(.stime, &.{ 4, 3, 2, 1 })).dint);
    const e8 = [_]u8{ 8, 7, 6, 5, 4, 3, 2, 1 };
    try testing.expectEqual(@as(i64, 0x0102030405060708), (try decodeValue(.lint, &e8)).lint);
    try testing.expectEqual(@as(i64, 0x0102030405060708), (try decodeValue(.ltime, &e8)).lint);
    try testing.expectEqual(@as(u64, 0x0102030405060708), (try decodeValue(.ulint, &e8)).ulint);
    try testing.expectEqual(@as(u64, 0x0102030405060708), (try decodeValue(.lword, &e8)).lword);
    var f: [8]u8 = undefined;
    std.mem.writeInt(u64, &f, @bitCast(@as(f64, 2.5)), .little);
    try testing.expectEqual(@as(f64, 2.5), (try decodeValue(.lreal, &f)).lreal);
    // An empty SHORT_STRING has no length octet; an empty STRING is a zero 16-bit length.
    try testing.expectError(error.Truncated, decodeValue(.short_string, &.{}));
    try testing.expectEqual(@as(usize, 0), (try decodeValue(.string, &.{ 0, 0 })).string.len);
    try testing.expectEqualStrings("x", (try decodeValue(.string, &.{ 1, 0, 'x' })).string);
}

fn expectEncoded(v: Value, want: []const u8) !void {
    var buf: [16]u8 = undefined;
    const w = try encodeValue(v, &buf);
    try testing.expectEqualSlices(u8, want, w);
    try testing.expectEqual(want.len, encodedValueLen(v));
    // The exact-size buffer works.
    _ = try encodeValue(v, buf[0..want.len]);
}

test "encoded value lengths and bytes: one variant at a time, little-endian" {
    try expectEncoded(.{ .boolean = true }, &.{0xFF});
    try expectEncoded(.{ .boolean = false }, &.{0x00});
    try expectEncoded(.{ .sint = -1 }, &.{0xFF});
    try expectEncoded(.{ .usint = 7 }, &.{7});
    try expectEncoded(.{ .byte = 8 }, &.{8});
    try expectEncoded(.{ .int = 0x0102 }, &.{ 2, 1 });
    try expectEncoded(.{ .uint = 0x0102 }, &.{ 2, 1 });
    try expectEncoded(.{ .word = 0x0102 }, &.{ 2, 1 });
    try expectEncoded(.{ .dint = 0x01020304 }, &.{ 4, 3, 2, 1 });
    try expectEncoded(.{ .udint = 0x01020304 }, &.{ 4, 3, 2, 1 });
    try expectEncoded(.{ .dword = 0x01020304 }, &.{ 4, 3, 2, 1 });
    try expectEncoded(.{ .real = 1.0 }, &.{ 0, 0, 0x80, 0x3F });
    try expectEncoded(.{ .lint = 0x0102030405060708 }, &.{ 8, 7, 6, 5, 4, 3, 2, 1 });
    try expectEncoded(.{ .ulint = 0x0102030405060708 }, &.{ 8, 7, 6, 5, 4, 3, 2, 1 });
    try expectEncoded(.{ .lword = 0x0102030405060708 }, &.{ 8, 7, 6, 5, 4, 3, 2, 1 });
    try expectEncoded(.{ .lreal = 1.0 }, &.{ 0, 0, 0, 0, 0, 0, 0xF0, 0x3F });
    try expectEncoded(.{ .string = "ab" }, &.{ 2, 'a', 'b' });
    try expectEncoded(.{ .raw = &.{ 9, 8, 7 } }, &.{ 9, 8, 7 });
    var out: [300]u8 = undefined;
    const s255: [255]u8 = @splat('s');
    const s256: [256]u8 = @splat('s');
    try testing.expectEqual(@as(usize, 256), (try encodeValue(.{ .string = &s255 }, &out)).len);
    try testing.expectError(error.StringTooLong, encodeValue(.{ .string = &s256 }, &out));
}

test "TagData: a bare structure handle, a short buffer, string arrays and raw payloads" {
    const st = try TagData.decode(&.{ 0xA0, 0x02, 0x34, 0x12 });
    try testing.expectEqual(@as(?u16, 0x1234), st.structure_handle);
    try testing.expectEqual(@as(usize, 0), st.data.len);
    var out: [8]u8 = undefined;
    const td = TagData{ .type = .dint, .data = &.{ 1, 2, 3, 4 } };
    try testing.expectError(error.BufferTooSmall, td.encode(out[0..5]));
    _ = try td.encode(out[0..6]);

    // STRING elements are not equally wide: they are walked from the front.
    const strs = TagData{ .type = .string, .data = &.{ 2, 0, 'a', 'b', 1, 0, 'c' } };
    try testing.expectEqualStrings("ab", (try strs.at(0)).string);
    try testing.expectEqualStrings("c", (try strs.at(1)).string);
    try testing.expectError(error.OutOfRange, strs.at(2));
    // Walking past the last element reports the decoder's own truncation, not a range error.
    const one = TagData{ .type = .short_string, .data = &.{ 1, 'A' } };
    try testing.expectError(error.Truncated, one.at(2));
    try testing.expectError(error.OutOfRange, one.at(1));

    const raw = TagData{ .type = .structure, .structure_handle = 1, .data = &.{ 1, 2 } };
    try testing.expectEqualSlices(u8, &.{ 1, 2 }, (try raw.at(0)).raw);
    try testing.expectError(error.OutOfRange, raw.at(1));

    try (TagData{ .type = .dint, .data = &.{ 1, 2, 3, 4 } }).validate();
    try testing.expectError(error.LengthNotAMultiple, (TagData{ .type = .dint, .data = &.{ 1, 2, 3, 4, 5 } }).validate());
    try (TagData{ .type = .string, .data = &.{ 1, 2, 3 } }).validate();
}

test "tag request bodies: minimal lengths, structure handles and short buffers" {
    const w = try WriteTagRequest.decode(&.{ 0xC3, 0, 1, 0 });
    try testing.expectEqual(@as(usize, 0), w.values.len);
    const ws = try WriteTagRequest.decode(&.{ 0xA0, 2, 0x34, 0x12, 3, 0 });
    try testing.expectEqual(@as(?u16, 0x1234), ws.structure_handle);
    try testing.expectEqual(@as(u16, 3), ws.count);
    var out: [32]u8 = undefined;
    const r = WriteTagRequest{ .type = .int, .count = 1, .values = &.{ 1, 2 } };
    try testing.expectError(error.BufferTooSmall, r.encode(out[0..5]));
    _ = try r.encode(out[0..6]);

    const f = WriteTagFragmentedRequest{ .type = .structure, .structure_handle = 0x1234, .count = 3, .byte_offset = 0x01020304, .values = &.{9} };
    try testing.expectEqual(@as(usize, 11), f.encodedLen());
    const fw = try f.encode(&out);
    try testing.expectEqualSlices(u8, &.{ 0xA0, 2, 0x34, 0x12, 3, 0, 4, 3, 2, 1, 9 }, fw);
    const back = try WriteTagFragmentedRequest.decode(fw);
    try testing.expectEqual(@as(?u16, 0x1234), back.structure_handle);
    try testing.expectEqual(@as(u16, 3), back.count);
    try testing.expectEqual(@as(u32, 0x01020304), back.byte_offset);
    try testing.expectEqualSlices(u8, &.{9}, back.values);
    try testing.expectError(error.BufferTooSmall, f.encode(out[0..10]));
    _ = try f.encode(out[0..11]);
    // The smallest bodies: eight octets plain, ten with a handle, no values.
    const plain = try WriteTagFragmentedRequest.decode(&.{ 0xC3, 0, 1, 0, 0, 0, 0, 0 });
    try testing.expectEqual(@as(usize, 0), plain.values.len);
    const hd = try WriteTagFragmentedRequest.decode(&.{ 0xA0, 2, 1, 0, 1, 0, 0, 0, 0, 0 });
    try testing.expectEqual(@as(?u16, 1), hd.structure_handle);
    const p = WriteTagFragmentedRequest{ .type = .int, .values = &.{ 1, 2 } };
    try testing.expectError(error.BufferTooSmall, p.encode(out[0..9]));
}

test "a structure body shorter than its handle is MissingStructureHandle, not a generic truncation" {
    try testing.expectError(error.MissingStructureHandle, WriteTagFragmentedRequest.decode(&.{ 0xA0, 2, 1, 0, 1, 0, 0, 0 }));
    try testing.expectError(error.MissingStructureHandle, WriteTagRequest.decode(&.{ 0xA0, 2, 1, 0 }));
}
