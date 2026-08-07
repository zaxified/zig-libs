// SPDX-License-Identifier: MIT

//! **Clause 20.2 — the tag encoding.** This is the heart of BACnet and the
//! place most implementations are subtly wrong, so it is its own file with its
//! own exhaustive boundary tests.
//!
//! Every datum on a BACnet wire is `tag header || data`. The header's first
//! octet is four fields packed into one byte:
//!
//! ```text
//!  7 6 5 4   3   2 1 0
//! +-------+-----+-----+
//! |  num  |class| LVT |
//! +-------+-----+-----+
//! ```
//!
//! * **num** — the tag number. `0b1111` (15) is an *escape*: the real number
//!   is in the octet that follows, so numbers 15..254 need two header octets.
//! * **class** — 0 = *application* (the number names a primitive datatype from
//!   the table below), 1 = *context* (the number names a parameter position in
//!   whatever service is being encoded, and the datatype is implied by the
//!   service definition, not by the wire).
//! * **LVT** — length/value/type, three bits with four different meanings:
//!   - 0..4 — the data is exactly that many octets;
//!   - 5 — *extended length*: one more octet L follows. `L <= 253` is the
//!     length; `L == 254` means a `u16` length follows; `L == 255` means a
//!     `u32` length follows. (Note the asymmetry: 253 is representable in one
//!     octet, 254 and 255 are the escapes, so a length of exactly 254 costs
//!     three octets.)
//!   - 6 — *opening* tag, 7 — *closing* tag. These bracket constructed data
//!     and carry no data of their own. They are only legal on **context**
//!     tags; an application tag whose LVT reads 6 or 7 is malformed.
//!   - Special case: an **application Boolean** (tag number 1) puts its *value*
//!     in the LVT field and has no data octets at all. A **context** tag with
//!     number 1 is an ordinary context tag and has nothing to do with Boolean.
//!
//! Nothing here allocates. Decoded strings and octet strings are slices that
//! borrow from the caller's input buffer.

const std = @import("std");
const types = @import("types.zig");

pub const Error = error{
    /// The buffer ended in the middle of a tag header or its data.
    Truncated,
    /// A tag header that cannot exist: LVT 6/7 on an application tag, an
    /// application Boolean whose LVT is neither 0 nor 1, or a reserved
    /// application tag number.
    InvalidTag,
    /// The tag is well formed but is not the tag the caller required (wrong
    /// class, wrong number, or a primitive where a constructed one was due).
    UnexpectedTag,
    /// A primitive's data length is impossible for its type: a Real that is
    /// not 4 octets, a Date that is not 4, an Unsigned wider than 8, ...
    InvalidLength,
    /// A value is well formed but out of range for the type it must become —
    /// a BitString claiming more unused bits than a trailing octet has, an
    /// ObjectIdentifier whose 32-bit packing does not fit, a Date field that
    /// is neither a legal value nor the "unspecified" marker.
    InvalidValue,
    /// The output buffer is too small.
    NoSpace,
};

/// Application-tag numbers (clause 20.2.1.4). Numbers 13..15 are reserved and
/// 16.. are "application-specific" — neither may appear on a BACnet/IP wire,
/// so the decoder refuses them rather than guessing a length.
pub const ApplicationTag = enum(u8) {
    null = 0,
    boolean = 1,
    unsigned = 2,
    signed = 3,
    real = 4,
    double = 5,
    octet_string = 6,
    character_string = 7,
    bit_string = 8,
    enumerated = 9,
    date = 10,
    time = 11,
    object_identifier = 12,
    _,
};

pub const Class = enum(u1) { application = 0, context = 1 };

/// What the LVT field turned out to mean.
pub const Form = enum {
    /// A datum: `len` octets of data follow the header.
    primitive,
    /// `[` — the start of constructed data. No data of its own.
    opening,
    /// `]` — the end of constructed data. No data of its own.
    closing,
};

/// A decoded tag header. `header_len` is how many octets the header itself
/// occupied, so `header_len + len` is the whole tagged datum.
pub const Tag = struct {
    class: Class,
    number: u32,
    form: Form,
    /// Data octets following the header. Always 0 for opening/closing tags and
    /// for an application Boolean (whose value lives in `bool_value`).
    len: u32 = 0,
    /// Only meaningful for an application Boolean: the value carried in LVT.
    bool_value: bool = false,
    header_len: u8 = 1,

    pub fn isApplication(self: Tag, n: ApplicationTag) bool {
        return self.class == .application and self.form == .primitive and
            self.number == @intFromEnum(n);
    }

    pub fn isContext(self: Tag, n: u32) bool {
        return self.class == .context and self.form == .primitive and self.number == n;
    }

    pub fn isOpening(self: Tag, n: u32) bool {
        return self.form == .opening and self.number == n;
    }

    pub fn isClosing(self: Tag, n: u32) bool {
        return self.form == .closing and self.number == n;
    }
};

/// Maximum octets a tag header can occupy: 1 (base) + 1 (extended number) +
/// 1 (0xFF marker) + 4 (u32 length).
pub const max_header_len = 7;

// ── header codec ────────────────────────────────────────────────────────────

/// Decodes one tag header from the front of `buf`.
pub fn decodeHeader(buf: []const u8) Error!Tag {
    if (buf.len < 1) return error.Truncated;
    const b0 = buf[0];
    const class: Class = if (b0 & 0x08 != 0) .context else .application;
    const lvt: u3 = @truncate(b0 & 0x07);

    var pos: usize = 1;
    var number: u32 = b0 >> 4;
    if (number == 0x0F) {
        // Extended tag number: the real number is the next octet. The standard
        // reserves 0..254 for this form; 255 is not assignable.
        if (buf.len < 2) return error.Truncated;
        number = buf[1];
        pos = 2;
        // An extended header that encodes a number below 15 is a
        // non-canonical encoding of something that fits in the nibble. Accept
        // it on decode (a peer may emit it) but never produce it. The *length*
        // escape below has exactly the same property and the same answer; see
        // `headerIsCanonical`, which is the one place both are written down.
    }

    switch (lvt) {
        6, 7 => {
            // Opening/closing brackets are context-only. The class bit is part
            // of the same octet, so an application tag reading LVT 6 or 7 is a
            // genuinely malformed header, not an alternate spelling.
            if (class != .context) return error.InvalidTag;
            return .{
                .class = .context,
                .number = number,
                .form = if (lvt == 6) .opening else .closing,
                .len = 0,
                .header_len = @intCast(pos),
            };
        },
        else => {},
    }

    // Application Boolean: the LVT field *is* the value; no data follows.
    if (class == .application and number == @intFromEnum(ApplicationTag.boolean)) {
        if (lvt > 1) return error.InvalidTag;
        return .{
            .class = .application,
            .number = number,
            .form = .primitive,
            .len = 0,
            .bool_value = lvt == 1,
            .header_len = @intCast(pos),
        };
    }

    if (lvt < 5) {
        return .{
            .class = class,
            .number = number,
            .form = .primitive,
            .len = lvt,
            .header_len = @intCast(pos),
        };
    }

    // Extended length.
    if (buf.len < pos + 1) return error.Truncated;
    const l0 = buf[pos];
    pos += 1;
    var len: u32 = l0;
    if (l0 == 254) {
        if (buf.len < pos + 2) return error.Truncated;
        len = std.mem.readInt(u16, buf[pos..][0..2], .big);
        pos += 2;
    } else if (l0 == 255) {
        if (buf.len < pos + 4) return error.Truncated;
        len = std.mem.readInt(u32, buf[pos..][0..4], .big);
        pos += 4;
    }
    return .{
        .class = class,
        .number = number,
        .form = .primitive,
        .len = len,
        .header_len = @intCast(pos),
    };
}

/// Encodes a tag header into `out`, returning the octets written. The
/// canonical form is always produced: the nibble is used whenever the number
/// fits, and the shortest length escape is chosen.
pub fn encodeHeader(tag: Tag, out: []u8) Error!usize {
    if (tag.number > 254) return error.InvalidValue;
    var pos: usize = 0;
    var b0: u8 = if (tag.class == .context) 0x08 else 0x00;
    if (tag.number < 15) {
        b0 |= @as(u8, @intCast(tag.number)) << 4;
    } else {
        b0 |= 0xF0;
    }

    const lvt: u8 = switch (tag.form) {
        .opening => blk: {
            if (tag.class != .context) return error.InvalidTag;
            break :blk 6;
        },
        .closing => blk: {
            if (tag.class != .context) return error.InvalidTag;
            break :blk 7;
        },
        .primitive => blk: {
            if (tag.class == .application and tag.number == @intFromEnum(ApplicationTag.boolean)) {
                if (tag.len != 0) return error.InvalidLength;
                break :blk @as(u8, if (tag.bool_value) 1 else 0);
            }
            break :blk if (tag.len < 5) @as(u8, @intCast(tag.len)) else 5;
        },
    };
    b0 |= lvt;

    if (out.len < 1) return error.NoSpace;
    out[0] = b0;
    pos = 1;
    if (tag.number >= 15) {
        if (out.len < pos + 1) return error.NoSpace;
        out[pos] = @intCast(tag.number);
        pos += 1;
    }
    if (tag.form == .primitive and lvt == 5) {
        if (tag.len <= 253) {
            if (out.len < pos + 1) return error.NoSpace;
            out[pos] = @intCast(tag.len);
            pos += 1;
        } else if (tag.len <= 65535) {
            if (out.len < pos + 3) return error.NoSpace;
            out[pos] = 254;
            std.mem.writeInt(u16, out[pos + 1 ..][0..2], @intCast(tag.len), .big);
            pos += 3;
        } else {
            if (out.len < pos + 5) return error.NoSpace;
            out[pos] = 255;
            std.mem.writeInt(u32, out[pos + 1 ..][0..4], tag.len, .big);
            pos += 5;
        }
    }
    return pos;
}

/// True when `buf` spells its tag header the way `encodeHeader` would.
///
/// Clause 20.2 gives **both** the tag number and the length an escape, and a
/// peer may take an escape where the short form would have fitted: `f0 01` is
/// tag number 1 spelled the long way, and `7d 00` is length 0 spelled through
/// the extended-length escape (as are `7d fe 00 00` and `7d ff 00 00 00 00`).
/// All of them decode to the same tag as the short spelling.
///
/// **They are accepted, not refused.** `bacpypes3` 0.0.106 — the implementation
/// this module's goldens come from — decodes every one of those four and
/// re-emits the *short* form, which is exactly what `encodeHeader` does. So a
/// non-canonical spelling is legal input that cannot survive a byte-identical
/// round trip, and refusing it would drop traffic the reference stack accepts.
/// This predicate names that set once, so a caller (or a round-trip check) does
/// not have to re-derive half of it from the shape of the first octet.
///
/// Returns false for a header that does not decode at all.
pub fn headerIsCanonical(buf: []const u8) bool {
    const t = decodeHeader(buf) catch return false;
    var pos: usize = 1;
    if (buf[0] >> 4 == 0x0F) {
        // The number escape, used for a number the nibble could have held.
        if (t.number < 15) return false;
        pos = 2;
    }
    // Opening/closing brackets carry no length, and an application Boolean's
    // LVT is its value: in both cases there is only one spelling.
    if (t.form != .primitive) return true;
    if (buf[0] & 0x07 != 5) return true;
    // Extended length: the shortest escape that fits is the canonical one.
    return switch (buf[pos]) {
        0...4 => false, // would have fitted in the LVT nibble
        254 => t.len > 253,
        255 => t.len > 65535,
        else => true, // 5..253, spelled in the single octet, as it must be
    };
}

// ── primitive value types ───────────────────────────────────────────────────

/// The `character_string` encoding octet (clause 20.2.9). Only `utf8` is
/// mandatory; the rest are legacy code pages that a decoder must *report*
/// rather than silently reinterpret, because the bytes mean different things.
pub const StringEncoding = enum(u8) {
    /// ANSI X3.4 / UTF-8. The only encoding a modern device should emit.
    utf8 = 0,
    /// IBM/Microsoft DBCS (the octets are followed by a code page).
    dbcs = 1,
    jis_x_0208 = 2,
    ucs4 = 3,
    ucs2 = 4,
    iso_8859_1 = 5,
    _,
};

/// A character string as it sits on the wire: an encoding octet plus raw
/// octets. Deliberately *not* decoded to UTF-8 — a `ucs2` string's octets are
/// not text in the caller's sense, and pretending otherwise loses data.
pub const CharacterString = struct {
    encoding: StringEncoding,
    /// The octets after the encoding octet. Borrowed from the input buffer.
    bytes: []const u8,

    /// The string as UTF-8, or null if it is in some other encoding (or is not
    /// valid UTF-8). Callers that only ever talk to modern devices can treat
    /// null as "unsupported encoding".
    pub fn asUtf8(self: CharacterString) ?[]const u8 {
        if (self.encoding != .utf8) return null;
        if (!std.unicode.utf8ValidateSlice(self.bytes)) return null;
        return self.bytes;
    }
};

/// A bit string: `unused_bits` low-order bits of the final octet are padding.
/// An empty bit string has no octets and `unused_bits == 0`.
pub const BitString = struct {
    unused_bits: u3 = 0,
    /// Borrowed from the input buffer.
    bytes: []const u8 = &.{},

    /// Number of meaningful bits.
    pub fn bitCount(self: BitString) usize {
        if (self.bytes.len == 0) return 0;
        return self.bytes.len * 8 - self.unused_bits;
    }

    /// Bit `i` counting from the most significant bit of the first octet,
    /// which is the order BACnet numbers bit strings in.
    pub fn bit(self: BitString, i: usize) bool {
        if (i >= self.bitCount()) return false;
        return (self.bytes[i / 8] & (@as(u8, 0x80) >> @intCast(i % 8))) != 0;
    }
};

/// `BACnetDate` (clause 20.2.12). Every field has a wildcard value of 255
/// ("unspecified"), which is what makes date *patterns* expressible. `year` is
/// an offset from 1900, so 2026 is 126.
pub const Date = struct {
    /// Year minus 1900, or 255 for unspecified.
    year: u8 = 255,
    /// 1..12, 13 = odd months, 14 = even months, 255 = unspecified.
    month: u8 = 255,
    /// 1..31, 32 = last day of month, 33 = odd days, 34 = even days,
    /// 255 = unspecified.
    day: u8 = 255,
    /// 1 = Monday .. 7 = Sunday, 255 = unspecified.
    weekday: u8 = 255,

    pub const unspecified: Date = .{};

    /// Rejects field values that are neither legal nor the wildcard. This runs
    /// on both encode and decode, so an impossible date is a typed error and
    /// never a struct a caller might act on.
    pub fn validate(self: Date) Error!void {
        if (self.month != 255 and (self.month < 1 or self.month > 14)) return error.InvalidValue;
        if (self.day != 255 and (self.day < 1 or self.day > 34)) return error.InvalidValue;
        if (self.weekday != 255 and (self.weekday < 1 or self.weekday > 7)) return error.InvalidValue;
    }

    /// The calendar year, or null when unspecified.
    pub fn fullYear(self: Date) ?u16 {
        if (self.year == 255) return null;
        return @as(u16, self.year) + 1900;
    }
};

/// `BACnetTime` (clause 20.2.13). 255 in any field means unspecified.
pub const Time = struct {
    hour: u8 = 255,
    minute: u8 = 255,
    second: u8 = 255,
    /// Hundredths of a second, 0..99.
    hundredths: u8 = 255,

    pub const unspecified: Time = .{};

    pub fn validate(self: Time) Error!void {
        if (self.hour != 255 and self.hour > 23) return error.InvalidValue;
        if (self.minute != 255 and self.minute > 59) return error.InvalidValue;
        if (self.second != 255 and self.second > 59) return error.InvalidValue;
        if (self.hundredths != 255 and self.hundredths > 99) return error.InvalidValue;
    }
};

/// `BACnetObjectIdentifier` (clause 20.2.14): a **32-bit** word with the
/// object type in the top 10 bits and the instance number in the low 22. The
/// 22-bit instance is why `4194303` (all ones) is the "unconfigured device"
/// instance every uncommissioned device ships with.
pub const ObjectId = struct {
    type: types.ObjectType,
    instance: u22,

    /// The wildcard instance number (2^22 - 1), reserved by the standard.
    pub const unconfigured_instance: u22 = 0x3FFFFF;

    pub fn pack(self: ObjectId) u32 {
        return (@as(u32, @intFromEnum(self.type)) << 22) | @as(u32, self.instance);
    }

    pub fn unpack(word: u32) ObjectId {
        return .{
            .type = @enumFromInt(@as(u10, @truncate(word >> 22))),
            .instance = @truncate(word & 0x3FFFFF),
        };
    }

    pub fn device(instance: u22) ObjectId {
        return .{ .type = .device, .instance = instance };
    }

    pub fn eql(a: ObjectId, b: ObjectId) bool {
        return a.type == b.type and a.instance == b.instance;
    }
};

/// A decoded application-tagged datum. Slice-carrying variants borrow from the
/// input buffer, so nothing here allocates and nothing outlives the input.
pub const Value = union(ApplicationTag) {
    null,
    boolean: bool,
    unsigned: u64,
    signed: i64,
    real: f32,
    double: f64,
    octet_string: []const u8,
    character_string: CharacterString,
    bit_string: BitString,
    enumerated: u32,
    date: Date,
    time: Time,
    object_identifier: ObjectId,
};

// ── Writer: build a tagged byte stream into a caller-supplied buffer ────────

/// Appends tagged data to a fixed buffer. Every method returns
/// `error.NoSpace` rather than truncating, so a half-written APDU can never
/// reach a socket.
pub const Writer = struct {
    buf: []u8,
    pos: usize = 0,

    pub fn init(buf: []u8) Writer {
        return .{ .buf = buf };
    }

    pub fn written(self: *const Writer) []const u8 {
        return self.buf[0..self.pos];
    }

    pub fn reset(self: *Writer) void {
        self.pos = 0;
    }

    pub fn byte(self: *Writer, b: u8) Error!void {
        if (self.pos + 1 > self.buf.len) return error.NoSpace;
        self.buf[self.pos] = b;
        self.pos += 1;
    }

    pub fn raw(self: *Writer, bytes: []const u8) Error!void {
        if (self.pos + bytes.len > self.buf.len) return error.NoSpace;
        @memcpy(self.buf[self.pos..][0..bytes.len], bytes);
        self.pos += bytes.len;
    }

    pub fn header(self: *Writer, tag: Tag) Error!void {
        const n = try encodeHeader(tag, self.buf[self.pos..]);
        self.pos += n;
    }

    /// `[` — opens constructed data for context tag `n`.
    pub fn open(self: *Writer, n: u32) Error!void {
        try self.header(.{ .class = .context, .number = n, .form = .opening });
    }

    /// `]` — closes constructed data for context tag `n`.
    pub fn close(self: *Writer, n: u32) Error!void {
        try self.header(.{ .class = .context, .number = n, .form = .closing });
    }

    /// A tagged datum with an explicit class/number and raw data.
    pub fn tagged(self: *Writer, class: Class, number: u32, data: []const u8) Error!void {
        try self.header(.{
            .class = class,
            .number = number,
            .form = .primitive,
            .len = @intCast(data.len),
        });
        try self.raw(data);
    }

    // ── application-tagged primitives ──────────────────────────────────────

    pub fn appNull(self: *Writer) Error!void {
        try self.header(.{ .class = .application, .number = 0, .form = .primitive, .len = 0 });
    }

    pub fn appBool(self: *Writer, v: bool) Error!void {
        try self.header(.{
            .class = .application,
            .number = @intFromEnum(ApplicationTag.boolean),
            .form = .primitive,
            .len = 0,
            .bool_value = v,
        });
    }

    pub fn appUnsigned(self: *Writer, v: u64) Error!void {
        var tmp: [8]u8 = undefined;
        const n = packUnsigned(v, &tmp);
        try self.tagged(.application, @intFromEnum(ApplicationTag.unsigned), tmp[0..n]);
    }

    pub fn appSigned(self: *Writer, v: i64) Error!void {
        var tmp: [8]u8 = undefined;
        const n = packSigned(v, &tmp);
        try self.tagged(.application, @intFromEnum(ApplicationTag.signed), tmp[0..n]);
    }

    pub fn appReal(self: *Writer, v: f32) Error!void {
        var tmp: [4]u8 = undefined;
        std.mem.writeInt(u32, &tmp, @bitCast(v), .big);
        try self.tagged(.application, @intFromEnum(ApplicationTag.real), &tmp);
    }

    pub fn appDouble(self: *Writer, v: f64) Error!void {
        var tmp: [8]u8 = undefined;
        std.mem.writeInt(u64, &tmp, @bitCast(v), .big);
        try self.tagged(.application, @intFromEnum(ApplicationTag.double), &tmp);
    }

    pub fn appOctetString(self: *Writer, v: []const u8) Error!void {
        try self.tagged(.application, @intFromEnum(ApplicationTag.octet_string), v);
    }

    pub fn appCharacterString(self: *Writer, s: CharacterString) Error!void {
        try self.header(.{
            .class = .application,
            .number = @intFromEnum(ApplicationTag.character_string),
            .form = .primitive,
            .len = @intCast(s.bytes.len + 1),
        });
        try self.byte(@intFromEnum(s.encoding));
        try self.raw(s.bytes);
    }

    /// Convenience: a UTF-8 string (encoding octet 0).
    pub fn appString(self: *Writer, s: []const u8) Error!void {
        try self.appCharacterString(.{ .encoding = .utf8, .bytes = s });
    }

    pub fn appBitString(self: *Writer, bs: BitString) Error!void {
        if (bs.bytes.len == 0 and bs.unused_bits != 0) return error.InvalidValue;
        try self.header(.{
            .class = .application,
            .number = @intFromEnum(ApplicationTag.bit_string),
            .form = .primitive,
            .len = @intCast(bs.bytes.len + 1),
        });
        try self.byte(bs.unused_bits);
        try self.raw(bs.bytes);
    }

    pub fn appEnumerated(self: *Writer, v: u32) Error!void {
        var tmp: [8]u8 = undefined;
        const n = packUnsigned(v, &tmp);
        try self.tagged(.application, @intFromEnum(ApplicationTag.enumerated), tmp[0..n]);
    }

    pub fn appDate(self: *Writer, d: Date) Error!void {
        try d.validate();
        try self.tagged(.application, @intFromEnum(ApplicationTag.date), &.{
            d.year, d.month, d.day, d.weekday,
        });
    }

    pub fn appTime(self: *Writer, t: Time) Error!void {
        try t.validate();
        try self.tagged(.application, @intFromEnum(ApplicationTag.time), &.{
            t.hour, t.minute, t.second, t.hundredths,
        });
    }

    pub fn appObjectId(self: *Writer, oid: ObjectId) Error!void {
        var tmp: [4]u8 = undefined;
        std.mem.writeInt(u32, &tmp, oid.pack(), .big);
        try self.tagged(.application, @intFromEnum(ApplicationTag.object_identifier), &tmp);
    }

    /// Writes any `Value` with its application tag.
    pub fn appValue(self: *Writer, v: Value) Error!void {
        switch (v) {
            .null => try self.appNull(),
            .boolean => |b| try self.appBool(b),
            .unsigned => |u| try self.appUnsigned(u),
            .signed => |i| try self.appSigned(i),
            .real => |r| try self.appReal(r),
            .double => |d| try self.appDouble(d),
            .octet_string => |o| try self.appOctetString(o),
            .character_string => |c| try self.appCharacterString(c),
            .bit_string => |b| try self.appBitString(b),
            .enumerated => |e| try self.appEnumerated(e),
            .date => |d| try self.appDate(d),
            .time => |t| try self.appTime(t),
            .object_identifier => |o| try self.appObjectId(o),
        }
    }

    // ── context-tagged primitives ──────────────────────────────────────────
    //
    // A context tag names a *parameter position*; the datatype comes from the
    // service definition. So the same byte layout as the application form, but
    // with no application tag number on the wire — which is exactly why a
    // decoder cannot infer types from context-tagged data alone.

    pub fn ctxUnsigned(self: *Writer, n: u32, v: u64) Error!void {
        var tmp: [8]u8 = undefined;
        const len = packUnsigned(v, &tmp);
        try self.tagged(.context, n, tmp[0..len]);
    }

    pub fn ctxSigned(self: *Writer, n: u32, v: i64) Error!void {
        var tmp: [8]u8 = undefined;
        const len = packSigned(v, &tmp);
        try self.tagged(.context, n, tmp[0..len]);
    }

    pub fn ctxEnumerated(self: *Writer, n: u32, v: u32) Error!void {
        var tmp: [8]u8 = undefined;
        const len = packUnsigned(v, &tmp);
        try self.tagged(.context, n, tmp[0..len]);
    }

    /// A context-tagged Boolean is **one data octet**, not an LVT-carried
    /// value — the Boolean-in-LVT rule is an application-tag rule only.
    pub fn ctxBool(self: *Writer, n: u32, v: bool) Error!void {
        try self.tagged(.context, n, &.{@intFromBool(v)});
    }

    pub fn ctxNull(self: *Writer, n: u32) Error!void {
        try self.tagged(.context, n, &.{});
    }

    pub fn ctxReal(self: *Writer, n: u32, v: f32) Error!void {
        var tmp: [4]u8 = undefined;
        std.mem.writeInt(u32, &tmp, @bitCast(v), .big);
        try self.tagged(.context, n, &tmp);
    }

    pub fn ctxObjectId(self: *Writer, n: u32, oid: ObjectId) Error!void {
        var tmp: [4]u8 = undefined;
        std.mem.writeInt(u32, &tmp, oid.pack(), .big);
        try self.tagged(.context, n, &tmp);
    }

    pub fn ctxOctetString(self: *Writer, n: u32, v: []const u8) Error!void {
        try self.tagged(.context, n, v);
    }

    pub fn ctxString(self: *Writer, n: u32, s: []const u8) Error!void {
        try self.header(.{
            .class = .context,
            .number = n,
            .form = .primitive,
            .len = @intCast(s.len + 1),
        });
        try self.byte(@intFromEnum(StringEncoding.utf8));
        try self.raw(s);
    }

    pub fn ctxTime(self: *Writer, n: u32, t: Time) Error!void {
        try t.validate();
        try self.tagged(.context, n, &.{ t.hour, t.minute, t.second, t.hundredths });
    }

    pub fn ctxDate(self: *Writer, n: u32, d: Date) Error!void {
        try d.validate();
        try self.tagged(.context, n, &.{ d.year, d.month, d.day, d.weekday });
    }
};

/// Big-endian minimal-width encoding of an unsigned value: at least one octet,
/// no leading zero octets. `0` encodes as a single `0x00`.
pub fn packUnsigned(v: u64, out: *[8]u8) usize {
    std.mem.writeInt(u64, out, v, .big);
    var start: usize = 0;
    while (start < 7 and out[start] == 0) start += 1;
    const n = 8 - start;
    std.mem.copyForwards(u8, out[0..n], out[start..8]);
    return n;
}

/// Big-endian minimal-width two's-complement encoding. The sign must survive:
/// a leading octet may only be dropped if the next octet's top bit already
/// carries the same sign.
pub fn packSigned(v: i64, out: *[8]u8) usize {
    std.mem.writeInt(i64, out, v, .big);
    var start: usize = 0;
    while (start < 7) : (start += 1) {
        const pad: u8 = if (v < 0) 0xFF else 0x00;
        if (out[start] != pad) break;
        const next_sign = out[start + 1] & 0x80;
        if ((v < 0) != (next_sign != 0)) break;
    }
    const n = 8 - start;
    std.mem.copyForwards(u8, out[0..n], out[start..8]);
    return n;
}

// ── Reader: walk a tagged byte stream ──────────────────────────────────────

/// Cursor over a tagged byte stream. Nothing is copied: every slice returned
/// borrows from `buf`.
pub const Reader = struct {
    buf: []const u8,
    pos: usize = 0,

    pub fn init(buf: []const u8) Reader {
        return .{ .buf = buf };
    }

    pub fn rest(self: *const Reader) []const u8 {
        return self.buf[self.pos..];
    }

    pub fn atEnd(self: *const Reader) bool {
        return self.pos >= self.buf.len;
    }

    /// Reads the next tag header **without** advancing.
    pub fn peek(self: *const Reader) Error!Tag {
        return decodeHeader(self.buf[self.pos..]);
    }

    /// Reads the next tag header and advances past it (not past its data).
    pub fn next(self: *Reader) Error!Tag {
        const t = try decodeHeader(self.buf[self.pos..]);
        self.pos += t.header_len;
        return t;
    }

    /// Consumes `n` data octets.
    pub fn take(self: *Reader, n: usize) Error![]const u8 {
        if (self.pos + n > self.buf.len) return error.Truncated;
        const s = self.buf[self.pos..][0..n];
        self.pos += n;
        return s;
    }

    /// Skips a whole tagged datum, including constructed data with nested
    /// brackets. Used to step over parameters a caller does not care about,
    /// and to bound-check a peer's framing without interpreting it.
    pub fn skip(self: *Reader) Error!void {
        const t = try self.next();
        switch (t.form) {
            .primitive => _ = try self.take(t.len),
            .closing => return error.UnexpectedTag,
            .opening => {
                var depth: usize = 1;
                while (depth > 0) {
                    const inner = try self.next();
                    switch (inner.form) {
                        .opening => depth += 1,
                        .closing => {
                            if (inner.number != t.number and depth == 1) return error.UnexpectedTag;
                            depth -= 1;
                        },
                        .primitive => _ = try self.take(inner.len),
                    }
                }
            },
        }
    }

    /// The raw octets of one constructed block, brackets excluded, with the
    /// cursor left after the closing bracket. This is how a service decoder
    /// hands an opaque "abstract syntax" value (`ReadProperty`'s propertyValue,
    /// a COV notification's value) to its caller without interpreting it.
    pub fn openedBlock(self: *Reader, n: u32) Error![]const u8 {
        const t = try self.next();
        if (!t.isOpening(n)) return error.UnexpectedTag;
        const start = self.pos;
        var depth: usize = 1;
        var end = start;
        while (depth > 0) {
            // Remember where this header began: the body of the block ends
            // where its *own* closing bracket starts. Backing off from the end
            // by the width the OPENING number would have been spelled at
            // assumes the peer spelled both brackets alike, which nothing on
            // the wire guarantees — `[3 ... ]99` then leaks an octet of the
            // closing header into the body, and `[99 ... ]3` underflows
            // `self.pos` into a slice of length ~2^64.
            const header_at = self.pos;
            const inner = try self.next();
            switch (inner.form) {
                .opening => depth += 1,
                .closing => {
                    depth -= 1;
                    if (depth == 0) {
                        // The bracket that closes *this* block must carry this
                        // block's number, exactly as `skip` requires at depth 1.
                        if (inner.number != n) return error.UnexpectedTag;
                        end = header_at;
                    }
                },
                .primitive => _ = try self.take(inner.len),
            }
        }
        return self.buf[start..end];
    }

    /// Requires and consumes an opening bracket.
    pub fn expectOpen(self: *Reader, n: u32) Error!void {
        const t = try self.next();
        if (!t.isOpening(n)) return error.UnexpectedTag;
    }

    /// Requires and consumes a closing bracket.
    pub fn expectClose(self: *Reader, n: u32) Error!void {
        const t = try self.next();
        if (!t.isClosing(n)) return error.UnexpectedTag;
    }

    // ── typed reads ────────────────────────────────────────────────────────

    /// Reads a context-tagged unsigned integer with number `n`.
    pub fn ctxUnsigned(self: *Reader, n: u32) Error!u64 {
        const t = try self.next();
        if (!t.isContext(n)) return error.UnexpectedTag;
        return unpackUnsigned(try self.take(t.len));
    }

    pub fn ctxSigned(self: *Reader, n: u32) Error!i64 {
        const t = try self.next();
        if (!t.isContext(n)) return error.UnexpectedTag;
        return unpackSigned(try self.take(t.len));
    }

    pub fn ctxEnumerated(self: *Reader, n: u32) Error!u32 {
        const v = try self.ctxUnsigned(n);
        if (v > std.math.maxInt(u32)) return error.InvalidValue;
        return @intCast(v);
    }

    pub fn ctxBool(self: *Reader, n: u32) Error!bool {
        const t = try self.next();
        if (!t.isContext(n)) return error.UnexpectedTag;
        if (t.len != 1) return error.InvalidLength;
        const d = try self.take(1);
        return d[0] != 0;
    }

    pub fn ctxObjectId(self: *Reader, n: u32) Error!ObjectId {
        const t = try self.next();
        if (!t.isContext(n)) return error.UnexpectedTag;
        if (t.len != 4) return error.InvalidLength;
        const d = try self.take(4);
        return ObjectId.unpack(std.mem.readInt(u32, d[0..4], .big));
    }

    pub fn ctxOctetString(self: *Reader, n: u32) Error![]const u8 {
        const t = try self.next();
        if (!t.isContext(n)) return error.UnexpectedTag;
        return self.take(t.len);
    }

    pub fn ctxString(self: *Reader, n: u32) Error!CharacterString {
        const t = try self.next();
        if (!t.isContext(n)) return error.UnexpectedTag;
        if (t.len < 1) return error.InvalidLength;
        const d = try self.take(t.len);
        return .{ .encoding = @enumFromInt(d[0]), .bytes = d[1..] };
    }

    /// Reads whatever application-tagged datum comes next.
    pub fn appValue(self: *Reader) Error!Value {
        const t = try self.next();
        if (t.class != .application or t.form != .primitive) return error.UnexpectedTag;
        return self.decodeAppData(t);
    }

    /// Reads an application-tagged datum and requires a specific type.
    pub fn expectApp(self: *Reader, want: ApplicationTag) Error!Value {
        const t = try self.next();
        if (!t.isApplication(want)) return error.UnexpectedTag;
        return self.decodeAppData(t);
    }

    fn decodeAppData(self: *Reader, t: Tag) Error!Value {
        const app: ApplicationTag = @enumFromInt(@as(u8, @intCast(@min(t.number, 255))));
        switch (app) {
            .null => {
                if (t.len != 0) return error.InvalidLength;
                return .null;
            },
            .boolean => return .{ .boolean = t.bool_value },
            .unsigned => return .{ .unsigned = try unpackUnsigned(try self.take(t.len)) },
            .signed => return .{ .signed = try unpackSigned(try self.take(t.len)) },
            .real => {
                if (t.len != 4) return error.InvalidLength;
                const d = try self.take(4);
                return .{ .real = @bitCast(std.mem.readInt(u32, d[0..4], .big)) };
            },
            .double => {
                if (t.len != 8) return error.InvalidLength;
                const d = try self.take(8);
                return .{ .double = @bitCast(std.mem.readInt(u64, d[0..8], .big)) };
            },
            .octet_string => return .{ .octet_string = try self.take(t.len) },
            .character_string => {
                // The encoding octet is mandatory, so even the empty string is
                // one octet long. A zero-length character string is malformed.
                if (t.len < 1) return error.InvalidLength;
                const d = try self.take(t.len);
                return .{ .character_string = .{
                    .encoding = @enumFromInt(d[0]),
                    .bytes = d[1..],
                } };
            },
            .bit_string => {
                if (t.len < 1) return error.InvalidLength;
                const d = try self.take(t.len);
                if (d[0] > 7) return error.InvalidValue;
                // "7 unused bits" of a zero-octet payload is nonsense: there is
                // no octet for those bits to be unused in.
                if (d.len == 1 and d[0] != 0) return error.InvalidValue;
                return .{ .bit_string = .{ .unused_bits = @intCast(d[0]), .bytes = d[1..] } };
            },
            .enumerated => {
                const v = try unpackUnsigned(try self.take(t.len));
                if (v > std.math.maxInt(u32)) return error.InvalidValue;
                return .{ .enumerated = @intCast(v) };
            },
            .date => {
                if (t.len != 4) return error.InvalidLength;
                const d = try self.take(4);
                const date: Date = .{ .year = d[0], .month = d[1], .day = d[2], .weekday = d[3] };
                try date.validate();
                return .{ .date = date };
            },
            .time => {
                if (t.len != 4) return error.InvalidLength;
                const d = try self.take(4);
                const tm: Time = .{
                    .hour = d[0],
                    .minute = d[1],
                    .second = d[2],
                    .hundredths = d[3],
                };
                try tm.validate();
                return .{ .time = tm };
            },
            .object_identifier => {
                if (t.len != 4) return error.InvalidLength;
                const d = try self.take(4);
                return .{ .object_identifier = ObjectId.unpack(std.mem.readInt(u32, d[0..4], .big)) };
            },
            _ => return error.InvalidTag,
        }
    }
};

/// Big-endian unsigned of 1..8 octets. Zero octets is *not* zero — BACnet
/// always writes at least one octet — so it is an error.
pub fn unpackUnsigned(d: []const u8) Error!u64 {
    if (d.len == 0 or d.len > 8) return error.InvalidLength;
    var v: u64 = 0;
    for (d) |b| v = (v << 8) | b;
    return v;
}

/// Big-endian two's complement of 1..8 octets.
pub fn unpackSigned(d: []const u8) Error!i64 {
    if (d.len == 0 or d.len > 8) return error.InvalidLength;
    var v: u64 = if (d[0] & 0x80 != 0) std.math.maxInt(u64) else 0;
    for (d) |b| v = (v << 8) | b;
    return @bitCast(v);
}

// ── tests ───────────────────────────────────────────────────────────────────

const testing = std.testing;

test "header: every LVT meaning and both classes" {
    // application, tag 2 (unsigned), length 1
    {
        const t = try decodeHeader(&.{ 0x21, 0x00 });
        try testing.expectEqual(Class.application, t.class);
        try testing.expectEqual(@as(u32, 2), t.number);
        try testing.expectEqual(Form.primitive, t.form);
        try testing.expectEqual(@as(u32, 1), t.len);
        try testing.expectEqual(@as(u8, 1), t.header_len);
    }
    // context, tag 0, length 1
    {
        const t = try decodeHeader(&.{ 0x09, 0x01 });
        try testing.expectEqual(Class.context, t.class);
        try testing.expectEqual(@as(u32, 0), t.number);
        try testing.expectEqual(@as(u32, 1), t.len);
    }
    // opening tag 3 == 0x3E, closing tag 3 == 0x3F
    {
        const o = try decodeHeader(&.{0x3E});
        try testing.expect(o.isOpening(3));
        const c = try decodeHeader(&.{0x3F});
        try testing.expect(c.isClosing(3));
    }
    // extended tag number: context 15 == f9 0f, context 254 == f9 fe
    {
        const t = try decodeHeader(&.{ 0xF9, 0x0F, 0x01 });
        try testing.expectEqual(@as(u32, 15), t.number);
        try testing.expectEqual(@as(u32, 1), t.len);
        try testing.expectEqual(@as(u8, 2), t.header_len);
    }
    {
        const t = try decodeHeader(&.{ 0xF9, 0xFE, 0x01 });
        try testing.expectEqual(@as(u32, 254), t.number);
    }
    // extended opening/closing: fe 0f, ff 63
    {
        const o = try decodeHeader(&.{ 0xFE, 0x0F });
        try testing.expect(o.isOpening(15));
        try testing.expectEqual(@as(u8, 2), o.header_len);
        const c = try decodeHeader(&.{ 0xFF, 0x63 });
        try testing.expect(c.isClosing(99));
    }
}

test "header: an application tag can never carry LVT 6 or 7" {
    // 0x06 = tag 0, application class, LVT 6. There is no such thing.
    try testing.expectError(error.InvalidTag, decodeHeader(&.{0x06}));
    try testing.expectError(error.InvalidTag, decodeHeader(&.{0x07}));
    try testing.expectError(error.InvalidTag, decodeHeader(&.{0x46}));
}

test "header: application Boolean carries its value in LVT" {
    const f = try decodeHeader(&.{0x10});
    try testing.expect(f.isApplication(.boolean));
    try testing.expectEqual(false, f.bool_value);
    try testing.expectEqual(@as(u32, 0), f.len);

    const t = try decodeHeader(&.{0x11});
    try testing.expectEqual(true, t.bool_value);

    // LVT 2 on an application Boolean is not a length — it is an impossible
    // value.
    try testing.expectError(error.InvalidTag, decodeHeader(&.{0x12}));
    try testing.expectError(error.InvalidTag, decodeHeader(&.{0x14}));

    // A *context* tag numbered 1 is not a Boolean at all: LVT is a length.
    const c = try decodeHeader(&.{ 0x19, 0x64 });
    try testing.expect(c.isContext(1));
    try testing.expectEqual(@as(u32, 1), c.len);
}

test "header: every extended-length escape boundary" {
    // 0..4 inline
    for (0..5) |n| {
        const t = try decodeHeader(&[_]u8{@intCast(0x60 | n)});
        try testing.expectEqual(@as(u32, @intCast(n)), t.len);
        try testing.expectEqual(@as(u8, 1), t.header_len);
    }
    // 5 -> escape, one octet
    {
        const t = try decodeHeader(&.{ 0x65, 0x05 });
        try testing.expectEqual(@as(u32, 5), t.len);
        try testing.expectEqual(@as(u8, 2), t.header_len);
    }
    // 253 -> still one octet
    {
        const t = try decodeHeader(&.{ 0x65, 0xFD });
        try testing.expectEqual(@as(u32, 253), t.len);
        try testing.expectEqual(@as(u8, 2), t.header_len);
    }
    // 254 -> 0xFE marker plus u16
    {
        const t = try decodeHeader(&.{ 0x65, 0xFE, 0x00, 0xFE });
        try testing.expectEqual(@as(u32, 254), t.len);
        try testing.expectEqual(@as(u8, 4), t.header_len);
    }
    // 65535 -> still the u16 form
    {
        const t = try decodeHeader(&.{ 0x65, 0xFE, 0xFF, 0xFF });
        try testing.expectEqual(@as(u32, 65535), t.len);
    }
    // 65536 -> 0xFF marker plus u32
    {
        const t = try decodeHeader(&.{ 0x65, 0xFF, 0x00, 0x01, 0x00, 0x00 });
        try testing.expectEqual(@as(u32, 65536), t.len);
        try testing.expectEqual(@as(u8, 6), t.header_len);
    }
}

test "header: truncation at every point is a typed error, never a crash" {
    try testing.expectError(error.Truncated, decodeHeader(&.{}));
    try testing.expectError(error.Truncated, decodeHeader(&.{0xF9})); // extended num
    try testing.expectError(error.Truncated, decodeHeader(&.{0x65})); // extended len
    try testing.expectError(error.Truncated, decodeHeader(&.{ 0x65, 0xFE })); // u16 len
    try testing.expectError(error.Truncated, decodeHeader(&.{ 0x65, 0xFE, 0x00 }));
    try testing.expectError(error.Truncated, decodeHeader(&.{ 0x65, 0xFF, 0x00, 0x00 }));
    try testing.expectError(error.Truncated, decodeHeader(&.{ 0xFD, 0x20 })); // ext num + ext len

    // ... but an extended tag number with an *inline* length is complete in
    // two octets and must NOT be reported as truncated.
    const ok = try decodeHeader(&.{ 0xF9, 0x20 });
    try testing.expectEqual(@as(u32, 32), ok.number);
    try testing.expectEqual(@as(u32, 1), ok.len);
}

test "header: encode is canonical and round-trips every form" {
    var buf: [16]u8 = undefined;
    const cases = [_]Tag{
        .{ .class = .application, .number = 2, .form = .primitive, .len = 1 },
        .{ .class = .context, .number = 0, .form = .primitive, .len = 1 },
        .{ .class = .context, .number = 3, .form = .opening },
        .{ .class = .context, .number = 3, .form = .closing },
        .{ .class = .context, .number = 15, .form = .primitive, .len = 1 },
        .{ .class = .context, .number = 254, .form = .primitive, .len = 1 },
        .{ .class = .context, .number = 15, .form = .opening },
        .{ .class = .context, .number = 99, .form = .closing },
        .{ .class = .application, .number = 6, .form = .primitive, .len = 253 },
        .{ .class = .application, .number = 6, .form = .primitive, .len = 254 },
        .{ .class = .application, .number = 6, .form = .primitive, .len = 65535 },
        .{ .class = .application, .number = 6, .form = .primitive, .len = 65536 },
        .{ .class = .application, .number = 1, .form = .primitive, .bool_value = true },
        .{ .class = .application, .number = 1, .form = .primitive, .bool_value = false },
    };
    for (cases) |t| {
        const n = try encodeHeader(t, &buf);
        const back = try decodeHeader(buf[0..n]);
        try testing.expectEqual(t.class, back.class);
        try testing.expectEqual(t.number, back.number);
        try testing.expectEqual(t.form, back.form);
        try testing.expectEqual(t.len, back.len);
        try testing.expectEqual(t.bool_value, back.bool_value);
        try testing.expectEqual(@as(u8, @intCast(n)), back.header_len);
    }
}

test "header: a length spelled through an escape it did not need is legal, and not canonical" {
    // Anchored on `bacpypes3` 0.0.106 (the stack that produced this module's
    // goldens): each `spelling` below decodes there to the very same tag as its
    // `canonical` neighbour, and re-encodes to `canonical`. So this module must
    // accept them too — and must report them as non-canonical, because they can
    // never come back out byte-identically.
    const cases = [_]struct { spelling: []const u8, canonical: []const u8 }{
        // The two reproducers, at a context tag and at an application tag.
        .{ .spelling = &.{ 0x7d, 0x00 }, .canonical = &.{0x78} },
        .{ .spelling = &.{ 0xc5, 0x00 }, .canonical = &.{0xc0} },
        // The same length 0, reached through the two wider escapes.
        .{ .spelling = &.{ 0x7d, 0xfe, 0x00, 0x00 }, .canonical = &.{0x78} },
        .{ .spelling = &.{ 0x7d, 0xff, 0x00, 0x00, 0x00, 0x00 }, .canonical = &.{0x78} },
        // A length of 4 still fits in the LVT nibble; 253 still fits in one octet.
        .{ .spelling = &.{ 0x7d, 0x04 }, .canonical = &.{0x7c} },
        .{ .spelling = &.{ 0x7d, 0xfe, 0x00, 0xfd }, .canonical = &.{ 0x7d, 0xfd } },
        // 65535 fits in the u16 escape, so the u32 escape is one octet too many.
        .{ .spelling = &.{ 0x7d, 0xff, 0x00, 0x00, 0xff, 0xff }, .canonical = &.{ 0x7d, 0xfe, 0xff, 0xff } },
        // The sibling escape, on the tag *number*, which was already excused.
        .{ .spelling = &.{ 0xf0, 0x01 }, .canonical = &.{0x10} },
    };
    var buf: [max_header_len]u8 = undefined;
    for (cases) |c| {
        const a = try decodeHeader(c.spelling);
        const b = try decodeHeader(c.canonical);
        try testing.expectEqual(b.class, a.class);
        try testing.expectEqual(b.number, a.number);
        try testing.expectEqual(b.form, a.form);
        try testing.expectEqual(b.len, a.len);
        try testing.expectEqual(@as(u8, @intCast(c.spelling.len)), a.header_len);

        // The escape is what makes it non-canonical; the short form is not.
        try testing.expect(!headerIsCanonical(c.spelling));
        try testing.expect(headerIsCanonical(c.canonical));

        // And re-encoding really does shorten it — which is precisely why the
        // round-trip fuzzer has to skip this input rather than assert on it.
        const n = try encodeHeader(a, &buf);
        try testing.expectEqualSlices(u8, c.canonical, buf[0..n]);
        try testing.expect(n < a.header_len);
    }
}

test "header: every canonical spelling is reported as canonical" {
    // The negative control. If `headerIsCanonical` ever answers false here, the
    // round-trip fuzzer stops asserting on real traffic and quietly goes green.
    const canonical = [_][]const u8{
        &.{0x78}, // context 7, length 0 in the LVT
        &.{0x7c}, // context 7, length 4 in the LVT
        &.{ 0x7d, 0x05 }, // length 5: the escape is now obligatory
        &.{ 0x7d, 0xfd }, // 253, still one octet
        &.{ 0x7d, 0xfe, 0x00, 0xfe }, // 254: the u16 escape becomes obligatory
        &.{ 0x7d, 0xff, 0x00, 0x01, 0x00, 0x00 }, // 65536: and then the u32 one
        &.{ 0xf9, 0x20 }, // extended number 32, inline length
        &.{ 0xf5, 0x20, 0x05 }, // extended number 32, extended length
        &.{0x3e}, // opening bracket 3
        &.{0x3f}, // closing bracket 3
        &.{0x11}, // application Boolean: LVT is the value, not a length
        &.{0x10},
    };
    for (canonical) |c| try testing.expect(headerIsCanonical(c));

    // A header that does not decode is not canonical either.
    try testing.expect(!headerIsCanonical(&.{}));
    try testing.expect(!headerIsCanonical(&.{0xf0}));
    try testing.expect(!headerIsCanonical(&.{0x06})); // LVT 6 on an application tag
}

test "header: opening/closing on the application class is rejected on encode" {
    var buf: [16]u8 = undefined;
    try testing.expectError(error.InvalidTag, encodeHeader(
        .{ .class = .application, .number = 3, .form = .opening },
        &buf,
    ));
    try testing.expectError(error.NoSpace, encodeHeader(
        .{ .class = .context, .number = 0, .form = .primitive, .len = 1 },
        buf[0..0],
    ));
    try testing.expectError(error.InvalidValue, encodeHeader(
        .{ .class = .context, .number = 255, .form = .primitive, .len = 1 },
        &buf,
    ));
}

test "minimal-width integer packing" {
    var tmp: [8]u8 = undefined;
    // Unsigned: 0 is one octet, not zero octets.
    try testing.expectEqual(@as(usize, 1), packUnsigned(0, &tmp));
    try testing.expectEqual(@as(u8, 0), tmp[0]);
    try testing.expectEqual(@as(usize, 1), packUnsigned(255, &tmp));
    try testing.expectEqual(@as(usize, 2), packUnsigned(256, &tmp));
    try testing.expectEqual(@as(usize, 2), packUnsigned(65535, &tmp));
    try testing.expectEqual(@as(usize, 3), packUnsigned(65536, &tmp));
    try testing.expectEqual(@as(usize, 4), packUnsigned(4294967295, &tmp));
    try testing.expectEqual(@as(usize, 5), packUnsigned(4294967296, &tmp));
    try testing.expectEqual(@as(usize, 8), packUnsigned(std.math.maxInt(u64), &tmp));

    // Signed: the sign bit must survive the trim.
    try testing.expectEqual(@as(usize, 1), packSigned(0, &tmp));
    try testing.expectEqual(@as(usize, 1), packSigned(127, &tmp));
    try testing.expectEqual(@as(usize, 2), packSigned(128, &tmp)); // 0x0080, not 0x80
    try testing.expectEqual(@as(usize, 1), packSigned(-1, &tmp));
    try testing.expectEqual(@as(u8, 0xFF), tmp[0]);
    try testing.expectEqual(@as(usize, 1), packSigned(-128, &tmp));
    try testing.expectEqual(@as(usize, 2), packSigned(-129, &tmp));
    try testing.expectEqual(@as(usize, 2), packSigned(-32768, &tmp));
    try testing.expectEqual(@as(usize, 3), packSigned(-32769, &tmp));
    try testing.expectEqual(@as(usize, 4), packSigned(2147483647, &tmp));
    try testing.expectEqual(@as(usize, 4), packSigned(-2147483648, &tmp));

    // Round trip through the unpackers.
    const vals = [_]i64{ 0, 1, -1, 127, 128, -128, -129, 32767, -32768, 2147483647, -2147483648, std.math.minInt(i64), std.math.maxInt(i64) };
    for (vals) |v| {
        const n = packSigned(v, &tmp);
        try testing.expectEqual(v, try unpackSigned(tmp[0..n]));
    }
    const uvals = [_]u64{ 0, 1, 255, 256, 65535, 65536, 4294967295, std.math.maxInt(u64) };
    for (uvals) |v| {
        const n = packUnsigned(v, &tmp);
        try testing.expectEqual(v, try unpackUnsigned(tmp[0..n]));
    }
}

test "unpack rejects impossible widths" {
    try testing.expectError(error.InvalidLength, unpackUnsigned(&.{}));
    try testing.expectError(error.InvalidLength, unpackUnsigned(&.{ 1, 2, 3, 4, 5, 6, 7, 8, 9 }));
    try testing.expectError(error.InvalidLength, unpackSigned(&.{}));
}

test "object identifier packs type and instance into 22 bits" {
    const oid: ObjectId = .{ .type = .analog_value, .instance = 12 };
    try testing.expectEqual(@as(u32, 0x0080000C), oid.pack());
    const back = ObjectId.unpack(0x0080000C);
    try testing.expect(back.eql(oid));

    // The all-ones instance: an uncommissioned device.
    const dev: ObjectId = .{ .type = .device, .instance = ObjectId.unconfigured_instance };
    try testing.expectEqual(@as(u32, 0x023FFFFF), dev.pack());

    // A reserved/vendor object type still round-trips numerically.
    const weird = ObjectId.unpack(0xFFC00001);
    try testing.expectEqual(@as(u10, 1023), @intFromEnum(weird.type));
    try testing.expectEqual(@as(u22, 1), weird.instance);
    try testing.expectEqual(@as(u32, 0xFFC00001), weird.pack());
}

test "bit string: unused-bit accounting" {
    const bs: BitString = .{ .unused_bits = 5, .bytes = &.{0xA0} };
    try testing.expectEqual(@as(usize, 3), bs.bitCount());
    try testing.expect(bs.bit(0));
    try testing.expect(!bs.bit(1));
    try testing.expect(bs.bit(2));
    try testing.expect(!bs.bit(3)); // past the end reads false, never panics

    const empty: BitString = .{};
    try testing.expectEqual(@as(usize, 0), empty.bitCount());
    try testing.expect(!empty.bit(0));
}

test "date and time validation refuses impossible values" {
    try (Date{ .year = 126, .month = 7, .day = 23, .weekday = 4 }).validate();
    try (Date{}).validate(); // fully unspecified is legal
    try testing.expectError(error.InvalidValue, (Date{ .month = 0 }).validate());
    try testing.expectError(error.InvalidValue, (Date{ .month = 15 }).validate());
    try testing.expectError(error.InvalidValue, (Date{ .day = 35 }).validate());
    try testing.expectError(error.InvalidValue, (Date{ .weekday = 8 }).validate());
    try testing.expectError(error.InvalidValue, (Date{ .weekday = 0 }).validate());

    try (Time{ .hour = 13, .minute = 45, .second = 30, .hundredths = 50 }).validate();
    try (Time{}).validate();
    try testing.expectError(error.InvalidValue, (Time{ .hour = 24 }).validate());
    try testing.expectError(error.InvalidValue, (Time{ .minute = 60 }).validate());
    try testing.expectError(error.InvalidValue, (Time{ .hundredths = 100 }).validate());

    try testing.expectEqual(@as(?u16, 2026), (Date{ .year = 126 }).fullYear());
    try testing.expectEqual(@as(?u16, null), (Date{}).fullYear());
}

test "reader: skip steps over nested constructed data" {
    // [3] [3] 21 05 ]3 21 06 ]3  then a trailing 21 07
    const bytes = [_]u8{ 0x3E, 0x3E, 0x21, 0x05, 0x3F, 0x21, 0x06, 0x3F, 0x21, 0x07 };
    var r = Reader.init(&bytes);
    try r.skip();
    try testing.expectEqual(@as(usize, 8), r.pos);
    const v = try r.appValue();
    try testing.expectEqual(@as(u64, 7), v.unsigned);
    try testing.expect(r.atEnd());
}

test "reader: an unclosed context tag is Truncated, not a hang" {
    const bytes = [_]u8{ 0x3E, 0x21, 0x05 }; // opens [3], never closes
    var r = Reader.init(&bytes);
    try testing.expectError(error.Truncated, r.skip());

    // Deeply nested and unclosed: still bounded by the buffer.
    var deep: [64]u8 = undefined;
    @memset(&deep, 0x3E);
    var r2 = Reader.init(&deep);
    try testing.expectError(error.Truncated, r2.skip());
}

test "reader: openedBlock hands back the body without the brackets" {
    const bytes = [_]u8{ 0x3E, 0x21, 0x05, 0x3F, 0x21, 0x09 };
    var r = Reader.init(&bytes);
    const body = try r.openedBlock(3);
    try testing.expectEqualSlices(u8, &.{ 0x21, 0x05 }, body);
    const v = try r.appValue();
    try testing.expectEqual(@as(u64, 9), v.unsigned);

    // Extended-number brackets: the closing header is two octets wide, so the
    // body end has to account for that.
    const ext = [_]u8{ 0xFE, 0x63, 0x21, 0x05, 0xFF, 0x63 };
    var r2 = Reader.init(&ext);
    const body2 = try r2.openedBlock(99);
    try testing.expectEqualSlices(u8, &.{ 0x21, 0x05 }, body2);
    try testing.expect(r2.atEnd());
}

test "reader: openedBlock refuses a closing bracket that is not its own" {
    // W2-05. A block's body ends where the block's OWN closing bracket starts.
    // Deriving that end from the *opening* number's width instead lets a peer
    // spell the closing bracket at a different width and move the end of the
    // body: one octet late in one direction, and below `start` in the other,
    // where the `usize` subtraction wraps.
    const cases = [_]struct { n: u32, bytes: []const u8, what: []const u8 }{
        // `[3 21 05 ]99` — the closing header is two octets where one was
        // assumed, so `FF`, half of that header, was handed back as value.
        .{ .n = 3, .bytes = &.{ 0x3E, 0x21, 0x05, 0xFF, 0x63 }, .what = "[3 ... ]99 (leaks a closing-header octet)" },
        // `[99 ]3` — one octet where two were assumed. `pos - 2` underflows
        // below `start`: a Debug panic, and under ReleaseFast a returned slice
        // of length 2^64-1 that the caller can read from.
        .{ .n = 99, .bytes = &.{ 0xFE, 0x63, 0x3F }, .what = "[99 ]3 (underflows, empty body)" },
        // The same inversion with a body, so the identity check is what is
        // under test and not merely the underflow.
        .{ .n = 99, .bytes = &.{ 0xFE, 0x63, 0x21, 0x05, 0x3F }, .what = "[99 ... ]3 (underflows, non-empty body)" },
        // A mismatch at the *same* width. No arithmetic on the opening
        // number could ever have caught this one: both brackets are one octet.
        .{ .n = 3, .bytes = &.{ 0x3E, 0x21, 0x05, 0x4F }, .what = "[3 ... ]4 (same width, wrong number)" },
    };

    // Counted rather than short-circuited: under ReleaseFast one run says how
    // many of the four shapes are accepted, not just that the first one is.
    var accepted: usize = 0;
    for (cases) |c| {
        var r = Reader.init(c.bytes);
        if (r.openedBlock(c.n)) |body| {
            accepted += 1;
            std.debug.print("accepted {s}: body len {d}\n", .{ c.what, body.len });
        } else |e| if (e != error.UnexpectedTag) {
            std.debug.print("{s}: got {s}, want UnexpectedTag\n", .{ c.what, @errorName(e) });
            return e;
        }
    }
    try testing.expectEqual(@as(usize, 0), accepted);

    // A *nested* block still closes normally: only the outermost bracket has
    // to carry this block's number, exactly as `skip` requires at depth 1.
    const nested = [_]u8{ 0x3E, 0x4E, 0x21, 0x05, 0x4F, 0x3F };
    var rn = Reader.init(&nested);
    try testing.expectEqualSlices(u8, &.{ 0x4E, 0x21, 0x05, 0x4F }, try rn.openedBlock(3));
    try testing.expect(rn.atEnd());
}

test "reader: wrong tag is UnexpectedTag" {
    const bytes = [_]u8{ 0x21, 0x05 };
    var r = Reader.init(&bytes);
    try testing.expectError(error.UnexpectedTag, r.ctxUnsigned(0));

    var r2 = Reader.init(&bytes);
    try testing.expectError(error.UnexpectedTag, r2.expectApp(.real));

    var r3 = Reader.init(&.{0x3F}); // a bare closing tag
    try testing.expectError(error.UnexpectedTag, r3.skip());
}

test "writer: application primitives match the standard's encodings" {
    var buf: [512]u8 = undefined;

    const Case = struct { hex: []const u8, fill: *const fn (*Writer) Error!void };
    const cases = [_]Case{
        .{ .hex = "00", .fill = struct {
            fn f(w: *Writer) Error!void {
                try w.appNull();
            }
        }.f },
        .{ .hex = "11", .fill = struct {
            fn f(w: *Writer) Error!void {
                try w.appBool(true);
            }
        }.f },
        .{ .hex = "10", .fill = struct {
            fn f(w: *Writer) Error!void {
                try w.appBool(false);
            }
        }.f },
        .{ .hex = "2100", .fill = struct {
            fn f(w: *Writer) Error!void {
                try w.appUnsigned(0);
            }
        }.f },
        .{ .hex = "21ff", .fill = struct {
            fn f(w: *Writer) Error!void {
                try w.appUnsigned(255);
            }
        }.f },
        .{ .hex = "220100", .fill = struct {
            fn f(w: *Writer) Error!void {
                try w.appUnsigned(256);
            }
        }.f },
        .{ .hex = "24ffffffff", .fill = struct {
            fn f(w: *Writer) Error!void {
                try w.appUnsigned(4294967295);
            }
        }.f },
        .{ .hex = "31ff", .fill = struct {
            fn f(w: *Writer) Error!void {
                try w.appSigned(-1);
            }
        }.f },
        .{ .hex = "3180", .fill = struct {
            fn f(w: *Writer) Error!void {
                try w.appSigned(-128);
            }
        }.f },
        .{ .hex = "32ff7f", .fill = struct {
            fn f(w: *Writer) Error!void {
                try w.appSigned(-129);
            }
        }.f },
        .{ .hex = "320080", .fill = struct {
            fn f(w: *Writer) Error!void {
                try w.appSigned(128);
            }
        }.f },
        .{ .hex = "444048f5c3", .fill = struct {
            fn f(w: *Writer) Error!void {
                try w.appReal(3.14);
            }
        }.f },
        .{ .hex = "550840091eb851eb851f", .fill = struct {
            fn f(w: *Writer) Error!void {
                try w.appDouble(3.14);
            }
        }.f },
        .{ .hex = "75060068656c6c6f", .fill = struct {
            fn f(w: *Writer) Error!void {
                try w.appString("hello");
            }
        }.f },
        .{ .hex = "7100", .fill = struct {
            fn f(w: *Writer) Error!void {
                try w.appString("");
            }
        }.f },
        .{ .hex = "8205a0", .fill = struct {
            fn f(w: *Writer) Error!void {
                try w.appBitString(.{ .unused_bits = 5, .bytes = &.{0xA0} });
            }
        }.f },
        .{ .hex = "8100", .fill = struct {
            fn f(w: *Writer) Error!void {
                try w.appBitString(.{});
            }
        }.f },
        .{ .hex = "9103", .fill = struct {
            fn f(w: *Writer) Error!void {
                try w.appEnumerated(3);
            }
        }.f },
        .{ .hex = "a47c071702", .fill = struct {
            fn f(w: *Writer) Error!void {
                try w.appDate(.{ .year = 124, .month = 7, .day = 23, .weekday = 2 });
            }
        }.f },
        .{ .hex = "b40d2d1e32", .fill = struct {
            fn f(w: *Writer) Error!void {
                try w.appTime(.{ .hour = 13, .minute = 45, .second = 30, .hundredths = 50 });
            }
        }.f },
        .{ .hex = "c4023fffff", .fill = struct {
            fn f(w: *Writer) Error!void {
                try w.appObjectId(.{ .type = @enumFromInt(8), .instance = 4194303 });
            }
        }.f },
        .{ .hex = "c40080000c", .fill = struct {
            fn f(w: *Writer) Error!void {
                try w.appObjectId(.{ .type = .analog_value, .instance = 12 });
            }
        }.f },
    };

    var expect: [64]u8 = undefined;
    for (cases) |c| {
        var w = Writer.init(&buf);
        try c.fill(&w);
        const e = try std.fmt.hexToBytes(&expect, c.hex);
        try testing.expectEqualSlices(u8, e, w.written());

        // and it decodes back to something equivalent
        var r = Reader.init(w.written());
        _ = try r.appValue();
        try testing.expect(r.atEnd());
    }
}

test "writer: octet-string length escapes at every boundary" {
    var big: [70000]u8 = undefined;
    @memset(&big, 0xAB);
    var out: [70016]u8 = undefined;

    const Expect = struct { n: usize, prefix: []const u8 };
    const cases = [_]Expect{
        .{ .n = 0, .prefix = "60" },
        .{ .n = 1, .prefix = "61" },
        .{ .n = 4, .prefix = "64" },
        .{ .n = 5, .prefix = "6505" },
        .{ .n = 253, .prefix = "65fd" },
        .{ .n = 254, .prefix = "65fe00fe" },
        .{ .n = 255, .prefix = "65fe00ff" },
        .{ .n = 300, .prefix = "65fe012c" },
        .{ .n = 65535, .prefix = "65feffff" },
        .{ .n = 65536, .prefix = "65ff00010000" },
    };
    var pbuf: [8]u8 = undefined;
    for (cases) |c| {
        var w = Writer.init(&out);
        try w.appOctetString(big[0..c.n]);
        const p = try std.fmt.hexToBytes(&pbuf, c.prefix);
        try testing.expectEqualSlices(u8, p, w.written()[0..p.len]);
        try testing.expectEqual(p.len + c.n, w.written().len);

        var r = Reader.init(w.written());
        const v = try r.appValue();
        try testing.expectEqual(c.n, v.octet_string.len);
        try testing.expect(r.atEnd());
    }
}

test "writer: context primitives" {
    var buf: [64]u8 = undefined;
    {
        var w = Writer.init(&buf);
        try w.ctxUnsigned(0, 1);
        try w.ctxUnsigned(1, 100);
        try testing.expectEqualSlices(u8, &.{ 0x09, 0x01, 0x19, 0x64 }, w.written());
    }
    {
        // A context Boolean is a data octet, not an LVT value.
        var w = Writer.init(&buf);
        try w.ctxBool(2, true);
        try testing.expectEqualSlices(u8, &.{ 0x29, 0x01 }, w.written());
        var r = Reader.init(w.written());
        try testing.expectEqual(true, try r.ctxBool(2));
    }
    {
        var w = Writer.init(&buf);
        try w.ctxObjectId(0, .{ .type = .analog_input, .instance = 5 });
        try testing.expectEqualSlices(u8, &.{ 0x0C, 0x00, 0x00, 0x00, 0x05 }, w.written());
        var r = Reader.init(w.written());
        const o = try r.ctxObjectId(0);
        try testing.expect(o.eql(.{ .type = .analog_input, .instance = 5 }));
    }
    {
        var w = Writer.init(&buf);
        try w.ctxNull(9);
        try testing.expectEqualSlices(u8, &.{0x98}, w.written());
    }
}

test "writer: NoSpace instead of a truncated datum" {
    var tiny: [3]u8 = undefined;
    var w = Writer.init(&tiny);
    try testing.expectError(error.NoSpace, w.appString("hello"));
    // Nothing partial may have been committed past the header attempt: the
    // caller must treat the writer as dead, but the buffer must not overflow.
    try testing.expect(w.pos <= tiny.len);
}

test "decoder: hostile primitive payloads" {
    // Real that is not 4 octets.
    {
        var r = Reader.init(&.{ 0x42, 0x00, 0x00 });
        try testing.expectError(error.InvalidLength, r.appValue());
    }
    // Double that is not 8.
    {
        var r = Reader.init(&.{ 0x54, 0x00, 0x00, 0x00, 0x00 });
        try testing.expectError(error.InvalidLength, r.appValue());
    }
    // Character string with no encoding octet at all.
    {
        var r = Reader.init(&.{0x70});
        try testing.expectError(error.InvalidLength, r.appValue());
    }
    // Character string with an unknown encoding octet: decodes, but reports
    // the encoding rather than pretending the bytes are UTF-8.
    {
        var r = Reader.init(&.{ 0x74, 0x63, 0x61, 0x62, 0x63 });
        const v = try r.appValue();
        try testing.expectEqual(@as(u8, 0x63), @intFromEnum(v.character_string.encoding));
        try testing.expectEqual(@as(?[]const u8, null), v.character_string.asUtf8());
    }
    // Character string claiming UTF-8 but carrying invalid UTF-8.
    {
        var r = Reader.init(&.{ 0x72, 0x00, 0xFF });
        const v = try r.appValue();
        try testing.expectEqual(@as(?[]const u8, null), v.character_string.asUtf8());
    }
    // BitString claiming 8 unused bits (only 0..7 exist).
    {
        var r = Reader.init(&.{ 0x82, 0x08, 0xFF });
        try testing.expectError(error.InvalidValue, r.appValue());
    }
    // BitString claiming unused bits with no data octet to be unused in.
    {
        var r = Reader.init(&.{ 0x81, 0x03 });
        try testing.expectError(error.InvalidValue, r.appValue());
    }
    // Date with an impossible month.
    {
        var r = Reader.init(&.{ 0xA4, 0x7C, 0x0F, 0x17, 0x02 });
        try testing.expectError(error.InvalidValue, r.appValue());
    }
    // Time with 60 minutes.
    {
        var r = Reader.init(&.{ 0xB4, 0x0D, 0x3C, 0x1E, 0x32 });
        try testing.expectError(error.InvalidValue, r.appValue());
    }
    // Reserved application tag 13.
    {
        var r = Reader.init(&.{ 0xD1, 0x00 });
        try testing.expectError(error.InvalidTag, r.appValue());
    }
    // A tag whose extended length runs past the end of the buffer.
    {
        var r = Reader.init(&.{ 0x65, 0xFF, 0x7F, 0xFF, 0xFF, 0xFF, 0x01 });
        try testing.expectError(error.Truncated, r.appValue());
    }
    // Unsigned wider than 8 octets.
    {
        var r = Reader.init(&.{ 0x25, 0x09, 1, 2, 3, 4, 5, 6, 7, 8, 9 });
        try testing.expectError(error.InvalidLength, r.appValue());
    }
}

test "fuzz: tag skipping never crashes, hangs or stalls" {
    try std.testing.fuzz({}, fuzzSkip, .{});
}

fn fuzzSkip(_: void, smith: *std.testing.Smith) !void {
    var buf: [256]u8 = undefined;
    smith.bytes(&buf);
    const len: usize = smith.valueRangeAtMost(u16, 0, buf.len);
    var r = Reader.init(buf[0..len]);
    var guard: usize = 0;
    while (!r.atEnd() and guard < 4096) : (guard += 1) {
        const before = r.pos;
        r.skip() catch break;
        // `skip` must always make progress; a zero-width step would be an
        // unbounded loop on a hostile buffer.
        if (r.pos <= before) return error.NoProgress;
    }
}

test "fuzz: application values never crash the decoder" {
    try std.testing.fuzz({}, fuzzAppValue, .{});
}

fn fuzzAppValue(_: void, smith: *std.testing.Smith) !void {
    var buf: [256]u8 = undefined;
    smith.bytes(&buf);
    const len: usize = smith.valueRangeAtMost(u16, 0, buf.len);
    var r = Reader.init(buf[0..len]);
    var guard: usize = 0;
    while (!r.atEnd() and guard < 4096) : (guard += 1) {
        const before = r.pos;
        _ = r.appValue() catch break;
        if (r.pos <= before) break;
    }
}

test "fuzz: openedBlock returns a sub-slice of its input or nothing" {
    try std.testing.fuzz({}, fuzzOpenedBlock, .{});
}

/// W2-05 lived through a clean coverage-guided sweep because `openedBlock` was
/// not fuzzed at all: `fuzzSkip`, `fuzzAppValue` and `fuzzHeaderRoundTrip`
/// between them cover `skip`, `appValue` and `decodeHeader` and nothing else.
/// The property that would have caught it is the one `sc.zig`'s harness
/// already asserts for its own decode — a borrowed slice must lie inside the
/// buffer it was borrowed from.
fn fuzzOpenedBlock(_: void, smith: *std.testing.Smith) !void {
    var buf: [256]u8 = undefined;
    smith.bytes(&buf);
    const len: usize = smith.valueRangeAtMost(u16, 0, buf.len);
    const input = buf[0..len];
    // Every bracket number a service decoder in this module actually opens,
    // plus one extended-form number, so a closing bracket of a *different*
    // width than the opening one is reachable in both directions.
    for ([_]u32{ 0, 1, 2, 3, 4, 5, 6, 7, 99 }) |n| {
        var r = Reader.init(input);
        const body = r.openedBlock(n) catch continue;
        // Checked as a length and an offset, never as a pointer comparison: a
        // wrapped length is exactly the failure mode here, and `ptr + len`
        // would wrap with it.
        if (body.len > input.len) return error.BodyLongerThanInput;
        const offset = @intFromPtr(body.ptr) - @intFromPtr(input.ptr);
        if (offset > input.len or offset + body.len > input.len) return error.BodyOutsideInput;
        if (r.pos > input.len) return error.CursorPastEnd;
        // The body must end before the closing bracket the cursor just passed.
        if (offset + body.len > r.pos) return error.BodyOverrunsCursor;
    }
}

test "fuzz: every canonically decoded header re-encodes to the same octets" {
    try std.testing.fuzz({}, fuzzHeaderRoundTrip, .{});
}

fn fuzzHeaderRoundTrip(_: void, smith: *std.testing.Smith) !void {
    var buf: [max_header_len]u8 = undefined;
    smith.bytes(&buf);
    const len: usize = smith.valueRangeAtMost(u8, 0, buf.len);
    const input = buf[0..len];
    const t = decodeHeader(input) catch return;
    // A peer may take an escape where the short form would have fitted — for
    // the tag *number* (`f0 01`) or for the *length* (`7d 00`). Both decode,
    // both are legal (`bacpypes3` accepts them), and neither is ever re-emitted
    // here, so neither can round-trip byte-identically. Skip exactly that set —
    // which `headerIsCanonical` defines and its own tests pin — and no more.
    if (!headerIsCanonical(input)) return;
    var out: [max_header_len]u8 = undefined;
    const n = encodeHeader(t, &out) catch return;
    if (n != t.header_len) return error.HeaderLenMismatch;
    if (!std.mem.eql(u8, input[0..n], out[0..n])) return error.NotCanonical;
}
