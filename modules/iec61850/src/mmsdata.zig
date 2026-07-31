// SPDX-License-Identifier: MIT

//! The MMS **`Data`** type (ISO 9506-2) — the recursive `CHOICE` every value in
//! an IEC 61850 system travels as, whether it is read over MMS, pushed in an
//! `InformationReport` or published in a GOOSE `allData` list.
//!
//! ```text
//! Data ::= CHOICE {
//!   array            [1] IMPLICIT SEQUENCE OF Data,
//!   structure        [2] IMPLICIT SEQUENCE OF Data,
//!   boolean          [3] IMPLICIT BOOLEAN,
//!   bit-string       [4] IMPLICIT BIT STRING,
//!   integer          [5] IMPLICIT INTEGER,
//!   unsigned         [6] IMPLICIT INTEGER,
//!   floating-point   [7] IMPLICIT FloatingPoint,
//!   real             [8] IMPLICIT REAL,            -- withdrawn, decoded not emitted
//!   octet-string     [9] IMPLICIT OCTET STRING,
//!   visible-string  [10] IMPLICIT VisibleString,
//!   generalized-time[11] IMPLICIT GeneralizedTime,
//!   binary-time     [12] IMPLICIT TimeOfDay,
//!   bcd             [13] IMPLICIT INTEGER,
//!   booleanArray    [14] IMPLICIT BIT STRING,
//!   objId           [15] IMPLICIT OBJECT IDENTIFIER,
//!   mMSString       [16] IMPLICIT MMSString,
//!   utc-time        [17] IMPLICIT UtcTime }
//! ```
//!
//! Two design decisions carry the file:
//!
//! * **`Data` is a view, never a tree.** It holds the tag plus slices into the
//!   caller's buffer; `members()` hands out an iterator over a structure's or
//!   array's children. Nothing allocates, and a 6 kB `GetNameList` reply costs
//!   no more than the bytes it arrived in.
//! * **Recursion is budgeted at every entry point.** `array` and `structure`
//!   nest arbitrarily, so a hostile `a2 03 a2 01 a2 …` is a stack overflow in
//!   any decoder that recurses without a counter. `validate` walks the whole
//!   tree once against `max_depth` and is the only thing that recurses; every
//!   accessor after that is flat.
//!
//! `utc-time` and `binary-time` are the two encodings that hide impossible
//! values behind a fixed width, so both are range-checked rather than passed
//! through as octets a caller might act on.

const std = @import("std");
const ber = @import("ber.zig");

pub const Error = ber.Error || error{
    /// A context tag that is not one of the `Data` alternatives.
    UnknownDataType,
    /// The value is not of the type the accessor requires.
    WrongDataType,
    /// A `UtcTime`, `TimeOfDay` or `GeneralizedTime` whose fields cannot
    /// describe a real instant.
    BadTime,
};

/// The depth budget for a `Data` tree. IEC 61850's own data model never nests
/// past about six (`LD/LN.DO.SDO.DA.subDA` plus an array), and libiec61850
/// proposes a nesting level of 10 in `Initiate`; 16 is a ceiling no legitimate
/// value approaches and a hostile one hits immediately.
pub const max_depth: u8 = 16;

pub const Kind = enum(u32) {
    array = 1,
    structure = 2,
    boolean = 3,
    bit_string = 4,
    integer = 5,
    unsigned = 6,
    floating_point = 7,
    /// Withdrawn from the standard; decoded so a legacy peer does not wedge
    /// the parser, never emitted.
    real = 8,
    octet_string = 9,
    visible_string = 10,
    generalized_time = 11,
    binary_time = 12,
    bcd = 13,
    boolean_array = 14,
    obj_id = 15,
    mms_string = 16,
    utc_time = 17,

    pub fn fromTag(t: ber.Tag) Error!Kind {
        if (t.class != .context) return error.UnknownDataType;
        return switch (t.number) {
            1...17 => @enumFromInt(t.number),
            else => error.UnknownDataType,
        };
    }

    pub fn isConstructed(self: Kind) bool {
        return self == .array or self == .structure;
    }

    pub fn tag(self: Kind) ber.Tag {
        return if (self.isConstructed())
            ber.Tag.ctxc(@intFromEnum(self))
        else
            ber.Tag.ctx(@intFromEnum(self));
    }
};

/// A view onto one `Data` value. `raw` is the complete TLV, which is what makes
/// a byte-exact re-encode of a captured frame possible.
pub const Data = struct {
    kind: Kind,
    content: []const u8,
    raw: []const u8,

    /// Reads one `Data` from the front of `bytes` **without** walking into it.
    /// Call `validate` (or `members`) to descend.
    pub fn decode(bytes: []const u8) Error!Data {
        const e = try ber.decode(bytes);
        const kind = try Kind.fromTag(e.tag);
        // The constructed bit must agree with the alternative: a primitive
        // `structure` is not a structure, and a constructed `integer` is not an
        // integer.
        if (kind.isConstructed() != e.tag.constructed) return error.WrongDataType;
        return .{ .kind = kind, .content = e.content, .raw = bytes[0..e.total_len] };
    }

    /// Walks the whole tree, checking every node's tag and the depth bound.
    /// This is the only recursive function here.
    pub fn validate(self: Data) Error!void {
        try self.validateDepth(max_depth);
    }

    fn validateDepth(self: Data, budget: u8) Error!void {
        if (budget == 0) return error.TooDeep;
        if (!self.kind.isConstructed()) {
            // Range-check the encodings that can hide an impossible value.
            switch (self.kind) {
                .utc_time => _ = try self.utcTime(),
                .binary_time => _ = try self.binaryTime(),
                .bit_string, .boolean_array => _ = try ber.BitString.parse(self.content),
                .floating_point => _ = try ber.Float.parse(self.content),
                .boolean => _ = try self.boolean(),
                else => {},
            }
            return;
        }
        var it = ber.Iterator.initDepth(self.content, budget);
        while (try it.next()) |e| {
            const child = Data{
                .kind = try Kind.fromTag(e.tag),
                .content = e.content,
                .raw = e.raw,
            };
            if (child.kind.isConstructed() != e.tag.constructed) return error.WrongDataType;
            try child.validateDepth(budget - 1);
        }
    }

    /// Members of an `array` or `structure`.
    pub fn members(self: Data) Error!Members {
        if (!self.kind.isConstructed()) return error.WrongDataType;
        return .{ .inner = ber.Iterator.initDepth(self.content, max_depth) };
    }

    /// Number of members, counted by walking. Bounded by the content length.
    pub fn memberCount(self: Data) Error!usize {
        var it = try self.members();
        var n: usize = 0;
        while (try it.next()) |_| n += 1;
        return n;
    }

    pub fn boolean(self: Data) Error!bool {
        if (self.kind != .boolean) return error.WrongDataType;
        if (self.content.len != 1) return error.BadForm;
        return self.content[0] != 0;
    }

    pub fn integer(self: Data, comptime T: type) Error!T {
        if (self.kind != .integer and self.kind != .bcd) return error.WrongDataType;
        return ber.decodeInt(T, self.content);
    }

    pub fn unsigned(self: Data, comptime T: type) Error!T {
        if (self.kind != .unsigned) return error.WrongDataType;
        return ber.decodeUint(T, self.content);
    }

    /// Either alternative, as an `i64` — most IEC 61850 attributes are declared
    /// `INT32` or `INT32U` and a caller usually does not care which arrived.
    pub fn asInt(self: Data) Error!i64 {
        return switch (self.kind) {
            .integer, .bcd => ber.decodeInt(i64, self.content),
            .unsigned => @intCast(try ber.decodeUint(u63, self.content)),
            else => error.WrongDataType,
        };
    }

    pub fn float(self: Data) Error!ber.Float {
        if (self.kind != .floating_point) return error.WrongDataType;
        return ber.Float.parse(self.content);
    }

    /// A numeric value however it was encoded.
    pub fn asFloat(self: Data) Error!f64 {
        return switch (self.kind) {
            .floating_point => (try ber.Float.parse(self.content)).value(),
            .integer, .unsigned, .bcd => @floatFromInt(try self.asInt()),
            else => error.WrongDataType,
        };
    }

    pub fn bitString(self: Data) Error!ber.BitString {
        if (self.kind != .bit_string and self.kind != .boolean_array) return error.WrongDataType;
        return ber.BitString.parse(self.content);
    }

    pub fn octetString(self: Data) Error![]const u8 {
        if (self.kind != .octet_string) return error.WrongDataType;
        return self.content;
    }

    pub fn visibleString(self: Data) Error![]const u8 {
        if (self.kind != .visible_string and self.kind != .mms_string) return error.WrongDataType;
        return self.content;
    }

    pub fn objId(self: Data) Error!ber.Oid {
        if (self.kind != .obj_id) return error.WrongDataType;
        return .{ .bytes = self.content };
    }

    pub fn utcTime(self: Data) Error!UtcTime {
        if (self.kind != .utc_time) return error.WrongDataType;
        return UtcTime.parse(self.content);
    }

    pub fn binaryTime(self: Data) Error!BinaryTime {
        if (self.kind != .binary_time) return error.WrongDataType;
        return BinaryTime.parse(self.content);
    }

    pub fn generalizedTime(self: Data) Error![]const u8 {
        if (self.kind != .generalized_time) return error.WrongDataType;
        if (self.content.len < 10) return error.BadTime;
        for (self.content) |c| {
            const ok = (c >= '0' and c <= '9') or c == '.' or c == 'Z' or c == '+' or c == '-';
            if (!ok) return error.BadTime;
        }
        return self.content;
    }
};

pub const Members = struct {
    inner: ber.Iterator,

    pub fn next(self: *Members) Error!?Data {
        const e = (try self.inner.next()) orelse return null;
        const kind = try Kind.fromTag(e.tag);
        if (kind.isConstructed() != e.tag.constructed) return error.WrongDataType;
        return .{ .kind = kind, .content = e.content, .raw = e.raw };
    }

    /// The member at `index`, or null. O(index); MMS structures are small.
    pub fn at(self: *Members, index: usize) Error!?Data {
        var i: usize = 0;
        while (try self.next()) |d| : (i += 1) {
            if (i == index) return d;
        }
        return null;
    }
};

// ── UtcTime ─────────────────────────────────────────────────────────────────

/// IEC 61850's `UtcTime`: four octets of seconds since the UNIX epoch, three
/// octets of binary fraction of a second, and one octet of `TimeQuality`.
///
/// The quality octet is where implementations go wrong: bits 0..4 are the
/// **time accuracy** as a count of significant fraction bits, and values 25..31
/// other than 31 ("unspecified") are not defined. A GOOSE subscriber that
/// treats an undefined accuracy as "accurate" will trust a timestamp it should
/// not, so it is a decode error here.
pub const UtcTime = struct {
    seconds: u32,
    /// Binary fraction of a second, 24 bits: value / 2^24 seconds.
    fraction: u24,
    leap_seconds_known: bool,
    clock_failure: bool,
    clock_not_synchronized: bool,
    /// Significant bits of `fraction`, 0..24, or null for "unspecified" (31).
    accuracy: ?u5,

    pub fn parse(content: []const u8) Error!UtcTime {
        if (content.len != 8) return error.BadTime;
        const q = content[7];
        const acc: u5 = @truncate(q & 0x1F);
        const accuracy: ?u5 = if (acc == 31) null else if (acc <= 24) acc else return error.BadTime;
        return .{
            .seconds = std.mem.readInt(u32, content[0..4], .big),
            .fraction = (@as(u24, content[4]) << 16) | (@as(u24, content[5]) << 8) | content[6],
            .leap_seconds_known = q & 0x80 != 0,
            .clock_failure = q & 0x40 != 0,
            .clock_not_synchronized = q & 0x20 != 0,
            .accuracy = accuracy,
        };
    }

    pub fn encode(self: UtcTime, out: *[8]u8) void {
        std.mem.writeInt(u32, out[0..4], self.seconds, .big);
        out[4] = @truncate(self.fraction >> 16);
        out[5] = @truncate(self.fraction >> 8);
        out[6] = @truncate(self.fraction);
        var q: u8 = if (self.accuracy) |a| a else 31;
        if (self.leap_seconds_known) q |= 0x80;
        if (self.clock_failure) q |= 0x40;
        if (self.clock_not_synchronized) q |= 0x20;
        out[7] = q;
    }

    /// Milliseconds since the epoch, which is what a caller almost always
    /// wants. The fraction is a binary fraction, not milliseconds.
    pub fn millis(self: UtcTime) u64 {
        return @as(u64, self.seconds) * 1000 + (@as(u64, self.fraction) * 1000) / (1 << 24);
    }

    pub fn fromMillis(ms: u64, accuracy: ?u5) UtcTime {
        return .{
            .seconds = @intCast(ms / 1000),
            .fraction = @intCast(((ms % 1000) * (1 << 24)) / 1000),
            .leap_seconds_known = false,
            .clock_failure = false,
            .clock_not_synchronized = false,
            .accuracy = accuracy,
        };
    }

    /// A timestamp a subscriber must not trust.
    pub fn suspect(self: UtcTime) bool {
        return self.clock_failure or self.clock_not_synchronized;
    }
};

// ── BinaryTime (TimeOfDay) ──────────────────────────────────────────────────

/// MMS `TimeOfDay`: four octets of milliseconds since midnight, optionally
/// followed by two octets of days since 1984-01-01. IEC 61850 reports carry the
/// six-octet form as `TimeOfEntry`.
pub const BinaryTime = struct {
    ms_since_midnight: u32,
    /// Null for the four-octet form.
    days_since_1984: ?u16,

    pub const ms_per_day: u32 = 86_400_000;

    pub fn parse(content: []const u8) Error!BinaryTime {
        if (content.len != 4 and content.len != 6) return error.BadTime;
        const ms = std.mem.readInt(u32, content[0..4], .big);
        if (ms >= ms_per_day) return error.BadTime;
        return .{
            .ms_since_midnight = ms,
            .days_since_1984 = if (content.len == 6) std.mem.readInt(u16, content[4..6], .big) else null,
        };
    }

    pub fn encode(self: BinaryTime, out: []u8) Error![]u8 {
        const n: usize = if (self.days_since_1984 == null) 4 else 6;
        if (out.len < n) return error.BufferTooSmall;
        if (self.ms_since_midnight >= ms_per_day) return error.BadTime;
        std.mem.writeInt(u32, out[0..4], self.ms_since_midnight, .big);
        if (self.days_since_1984) |d| std.mem.writeInt(u16, out[4..6], d, .big);
        return out[0..n];
    }
};

// ── writing ─────────────────────────────────────────────────────────────────

/// Emits `Data` values through a `ber.Writer`. Because the writer builds
/// backwards, a structure is written **members last to first**, then closed —
/// which is what `structure` does for a caller that has a slice of already
/// encoded members.
pub const Emit = struct {
    pub fn boolean(w: *ber.Writer, v: bool) Error!void {
        // MMS booleans on the wire are 0x00 / 0xFF from most stacks, but the
        // captured IED emits 0x00 / 0x01; either decodes.
        try w.primitive(Kind.boolean.tag(), &[_]u8{if (v) 0x01 else 0x00});
    }
    pub fn integer(w: *ber.Writer, v: i64) Error!void {
        try w.integer(Kind.integer.tag(), v);
    }
    pub fn unsigned(w: *ber.Writer, v: u64) Error!void {
        try w.unsigned(Kind.unsigned.tag(), v);
    }
    pub fn float(w: *ber.Writer, v: f32) Error!void {
        try w.float(Kind.floating_point.tag(), .{ .single = v });
    }
    pub fn double(w: *ber.Writer, v: f64) Error!void {
        try w.float(Kind.floating_point.tag(), .{ .double = v });
    }
    pub fn visibleString(w: *ber.Writer, s: []const u8) Error!void {
        try w.primitive(Kind.visible_string.tag(), s);
    }
    pub fn octetString(w: *ber.Writer, s: []const u8) Error!void {
        try w.primitive(Kind.octet_string.tag(), s);
    }
    pub fn bitString(w: *ber.Writer, value: u64, count: u8) Error!void {
        try w.bitString(Kind.bit_string.tag(), value, count);
    }
    pub fn utcTime(w: *ber.Writer, t: UtcTime) Error!void {
        var tmp: [8]u8 = undefined;
        t.encode(&tmp);
        try w.primitive(Kind.utc_time.tag(), &tmp);
    }
    pub fn binaryTime(w: *ber.Writer, t: BinaryTime) Error!void {
        var tmp: [6]u8 = undefined;
        try w.primitive(Kind.binary_time.tag(), try t.encode(&tmp));
    }
    /// Closes a `structure` around everything written since `mark`.
    pub fn structure(w: *ber.Writer, mark: usize) Error!void {
        try w.header(Kind.structure.tag(), mark);
    }
    /// Closes an `array` around everything written since `mark`.
    pub fn array(w: *ber.Writer, mark: usize) Error!void {
        try w.header(Kind.array.tag(), mark);
    }
};

// ── tests ───────────────────────────────────────────────────────────────────

const testing = std.testing;

test "the captured measurement value decodes" {
    // `87 05 08 3d 2a 51 55` — a floating-point AnIn1.mag.f read from a real IED.
    const bytes = [_]u8{ 0x87, 0x05, 0x08, 0x3D, 0x2A, 0x51, 0x55 };
    const d = try Data.decode(&bytes);
    try testing.expectEqual(Kind.floating_point, d.kind);
    try d.validate();
    try testing.expectApproxEqAbs(@as(f64, 0.0415809), try d.asFloat(), 1e-6);
    try testing.expectEqualSlices(u8, &bytes, d.raw);
}

test "the captured report structure decodes member by member" {
    // The URCB a real IED returned for `LLN0$RP$EventsRCB01`, verbatim.
    const bytes = [_]u8{
        0xA2, 0x47,
        0x8A, 0x07, 'E', 'v', 'e', 'n', 't', 's', '1', // RptID
        0x83, 0x01, 0x00, // RptEna
        0x83, 0x01, 0x00, // Resv
        0x8A, 0x1D, 's',
        'i',  'm',  'p',
        'l',  'e',  'I',
        'O',  'G',  'e',
        'n',  'e',  'r',
        'i',  'c',  'I',
        'O',  '/',  'L',
        'L',  'N',  '0',
        '$',  'E',  'v',
        'e',  'n',  't',
        's',
        0x86, 0x01, 0x01, // ConfRev
        0x84, 0x03, 0x06, 0x7A, 0x80, // OptFlds
        0x86, 0x01, 0x32, // BufTm = 50
        0x86, 0x01, 0x00, // SqNum
        0x84, 0x02, 0x02, 0x0C, // TrgOps
        0x86, 0x02, 0x03, 0xE8, // IntgPd = 1000
        0x83, 0x01, 0x00, // GI
    };
    const d = try Data.decode(&bytes);
    try testing.expectEqual(Kind.structure, d.kind);
    try d.validate();
    try testing.expectEqual(@as(usize, 11), try d.memberCount());

    var it = try d.members();
    try testing.expectEqualStrings("Events1", try (try it.next()).?.visibleString());
    try testing.expectEqual(false, try (try it.next()).?.boolean());
    _ = try it.next(); // Resv
    try testing.expectEqualStrings("simpleIOGenericIO/LLN0$Events", try (try it.next()).?.visibleString());
    try testing.expectEqual(@as(u32, 1), try (try it.next()).?.unsigned(u32));
    const opt_flds = try (try it.next()).?.bitString();
    try testing.expectEqual(@as(usize, 10), opt_flds.bitCount());
    try testing.expectEqual(@as(u32, 50), try (try it.next()).?.unsigned(u32));
    try testing.expectEqual(@as(u32, 0), try (try it.next()).?.unsigned(u32));
    const trg_ops = try (try it.next()).?.bitString();
    try testing.expectEqual(@as(usize, 6), trg_ops.bitCount());
    try testing.expectEqual(@as(u32, 1000), try (try it.next()).?.unsigned(u32));
    try testing.expectEqual(false, try (try it.next()).?.boolean());
    try testing.expect((try it.next()) == null);
}

test "every alternative round trips through the writer" {
    var buf: [256]u8 = undefined;
    var w = ber.Writer.init(&buf);
    const outer = w.mark();
    try Emit.utcTime(&w, UtcTime.fromMillis(1_700_000_123_456, 10));
    try Emit.bitString(&w, 0b000011, 6);
    try Emit.visibleString(&w, "hello");
    try Emit.float(&w, 1.5);
    try Emit.unsigned(&w, 4294967295);
    try Emit.integer(&w, -1234);
    try Emit.boolean(&w, true);
    try Emit.structure(&w, outer);

    const d = try Data.decode(w.done());
    try d.validate();
    try testing.expectEqual(Kind.structure, d.kind);
    var it = try d.members();
    try testing.expectEqual(true, try (try it.next()).?.boolean());
    try testing.expectEqual(@as(i32, -1234), try (try it.next()).?.integer(i32));
    try testing.expectEqual(@as(u32, 4294967295), try (try it.next()).?.unsigned(u32));
    try testing.expectEqual(@as(f32, 1.5), (try (try it.next()).?.float()).single);
    try testing.expectEqualStrings("hello", try (try it.next()).?.visibleString());
    try testing.expectEqual(@as(u64, 0b000011), (try (try it.next()).?.bitString()).asInt());
    const t = try (try it.next()).?.utcTime();
    // The fraction is a binary 2^-24 fraction, so a millisecond round trip is
    // exact to within one unit in the last place, not bit-for-bit.
    try testing.expectApproxEqAbs(@as(f64, 1_700_000_123_456), @as(f64, @floatFromInt(t.millis())), 1.0);
    try testing.expectEqual(@as(u5, 10), t.accuracy.?);
}

test "nested arrays and structures walk to the leaves" {
    var buf: [256]u8 = undefined;
    var w = ber.Writer.init(&buf);
    // array { structure { integer 1, integer 2 }, structure { integer 3 } }
    const arr = w.mark();
    const s2 = w.mark();
    try Emit.integer(&w, 3);
    try Emit.structure(&w, s2);
    const s1 = w.mark();
    try Emit.integer(&w, 2);
    try Emit.integer(&w, 1);
    try Emit.structure(&w, s1);
    try Emit.array(&w, arr);

    const d = try Data.decode(w.done());
    try d.validate();
    try testing.expectEqual(Kind.array, d.kind);
    try testing.expectEqual(@as(usize, 2), try d.memberCount());
    var it = try d.members();
    const first = (try it.next()).?;
    try testing.expectEqual(@as(usize, 2), try first.memberCount());
    var inner = try first.members();
    try testing.expectEqual(@as(i32, 1), try (try inner.next()).?.integer(i32));
    try testing.expectEqual(@as(i32, 2), try (try inner.next()).?.integer(i32));
}

test "a Data nested past the depth bound is refused, not recursed into" {
    // 64 nested `structure`s: a2 <len> a2 <len> … a2 00
    var buf: [512]u8 = undefined;
    const depth: usize = 64;
    var i: usize = depth;
    var len: usize = 0;
    while (i > 0) : (i -= 1) {
        buf[depth * 2 - len - 1] = @intCast(len);
        buf[depth * 2 - len - 2] = 0xA2;
        len += 2;
    }
    const bytes = buf[0 .. depth * 2];
    const d = try Data.decode(bytes);
    try testing.expectError(error.TooDeep, d.validate());

    // Just inside the bound still validates.
    var ok: [64]u8 = undefined;
    const shallow: usize = max_depth - 1;
    var j: usize = shallow;
    var l2: usize = 0;
    while (j > 0) : (j -= 1) {
        ok[shallow * 2 - l2 - 1] = @intCast(l2);
        ok[shallow * 2 - l2 - 2] = 0xA2;
        l2 += 2;
    }
    try (try Data.decode(ok[0 .. shallow * 2])).validate();
}

test "a tag that is not a Data alternative is refused" {
    try testing.expectError(error.UnknownDataType, Data.decode(&[_]u8{ 0x80, 0x00 })); // [0]
    try testing.expectError(error.UnknownDataType, Data.decode(&[_]u8{ 0x92, 0x00 })); // [18]
    try testing.expectError(error.UnknownDataType, Data.decode(&[_]u8{ 0x02, 0x01, 0x05 })); // universal
    // A primitive `structure` and a constructed `integer` are both refused.
    try testing.expectError(error.WrongDataType, Data.decode(&[_]u8{ 0x82, 0x00 }));
    try testing.expectError(error.WrongDataType, Data.decode(&[_]u8{ 0xA5, 0x00 }));
}

test "the withdrawn REAL alternative still decodes, per its doc comment" {
    // Kind.real (tag [8]) has no writer, no accessor and, until this test,
    // no coverage at all: nothing exercised `Kind.fromTag`'s `1...17` range
    // at the one member that isn't reachable through any other alternative's
    // test. "decoded so a legacy peer does not wedge the parser" was an
    // unverified claim.
    const d = try Data.decode(&[_]u8{ 0x88, 0x04, 0x3F, 0x80, 0x00, 0x00 });
    try testing.expectEqual(Kind.real, d.kind);
    try testing.expectEqual(@as(usize, 4), d.content.len);
    try testing.expectEqualSlices(u8, &[_]u8{ 0x88, 0x04, 0x3F, 0x80, 0x00, 0x00 }, d.raw);
    // A constructed [8] is refused just like every other primitive-only kind.
    try testing.expectError(error.WrongDataType, Data.decode(&[_]u8{ 0xA8, 0x00 }));
}

test "accessors refuse the wrong alternative" {
    const b = try Data.decode(&[_]u8{ 0x83, 0x01, 0x01 });
    try testing.expectError(error.WrongDataType, b.integer(i32));
    try testing.expectError(error.WrongDataType, b.visibleString());
    try testing.expectError(error.WrongDataType, b.members());
    const s = try Data.decode(&[_]u8{ 0xA2, 0x00 });
    try testing.expectError(error.WrongDataType, s.boolean());
}

test "UtcTime round trips and refuses impossible quality" {
    // The `t` field of a captured GOOSE frame.
    const captured = [_]u8{ 0x6A, 0x61, 0xD9, 0x8F, 0xC4, 0x18, 0x93, 0x0A };
    const t = try UtcTime.parse(&captured);
    try testing.expectEqual(@as(u32, 0x6A61D98F), t.seconds);
    try testing.expectEqual(@as(u5, 10), t.accuracy.?);
    try testing.expect(!t.clock_failure);
    try testing.expect(!t.clock_not_synchronized);
    var out: [8]u8 = undefined;
    t.encode(&out);
    try testing.expectEqualSlices(u8, &captured, &out);

    // Accuracy 31 is "unspecified" and legal.
    var unspec = captured;
    unspec[7] = 0x1F;
    try testing.expect((try UtcTime.parse(&unspec)).accuracy == null);
    // 25..30 are not defined values.
    var bad = captured;
    bad[7] = 25;
    try testing.expectError(error.BadTime, UtcTime.parse(&bad));
    bad[7] = 30;
    try testing.expectError(error.BadTime, UtcTime.parse(&bad));
    // Wrong width.
    try testing.expectError(error.BadTime, UtcTime.parse(&[_]u8{0} ** 7));
    try testing.expectError(error.BadTime, UtcTime.parse(&[_]u8{0} ** 9));

    // The failure flags survive.
    var suspicious = captured;
    suspicious[7] = 0x60 | 10;
    const s = try UtcTime.parse(&suspicious);
    try testing.expect(s.clock_failure and s.clock_not_synchronized and s.suspect());
}

test "BinaryTime refuses a millisecond count past midnight" {
    // The `TimeOfEntry` of a captured report: 6 octets.
    const captured = [_]u8{ 0x01, 0xE9, 0xC1, 0x11, 0x3C, 0xB8 };
    const t = try BinaryTime.parse(&captured);
    try testing.expectEqual(@as(u32, 0x01E9C111), t.ms_since_midnight);
    try testing.expectEqual(@as(u16, 0x3CB8), t.days_since_1984.?);
    var out: [6]u8 = undefined;
    try testing.expectEqualSlices(u8, &captured, try t.encode(&out));

    try testing.expectError(error.BadTime, BinaryTime.parse(&[_]u8{ 0xFF, 0xFF, 0xFF, 0xFF }));
    try testing.expectError(error.BadTime, BinaryTime.parse(&[_]u8{ 0x00, 0x00, 0x00 }));
    try testing.expectError(error.BadTime, BinaryTime.parse(&[_]u8{ 0x00, 0x00, 0x00, 0x00, 0x00 }));
}

test "validate reaches an impossible time buried in a structure" {
    var buf: [64]u8 = undefined;
    var w = ber.Writer.init(&buf);
    const outer = w.mark();
    // A utc-time whose accuracy field is a reserved value.
    try w.primitive(Kind.utc_time.tag(), &[_]u8{ 0, 0, 0, 0, 0, 0, 0, 26 });
    try Emit.integer(&w, 1);
    try Emit.structure(&w, outer);
    try testing.expectError(error.BadTime, (try Data.decode(w.done())).validate());
}

test "generalized time is checked for shape" {
    const good = [_]u8{ 0x8B, 0x0F } ++ "20260722120000Z".*;
    _ = try (try Data.decode(&good)).generalizedTime();
    const bad = [_]u8{ 0x8B, 0x04 } ++ "20xx".*;
    try testing.expectError(error.BadTime, (try Data.decode(&bad)).generalizedTime());
}

test "fuzz: Data decode and validate never panic" {
    try std.testing.fuzz({}, fuzzData, .{});
}

fn fuzzData(_: void, smith: *std.testing.Smith) !void {
    var buf: [512]u8 = undefined;
    smith.bytes(&buf);
    const len: usize = smith.valueRangeAtMost(u16, 0, buf.len);
    const d = Data.decode(buf[0..len]) catch return;
    d.validate() catch return;
    // Everything that validated must be walkable without error.
    if (d.kind.isConstructed()) {
        var it = try d.members();
        var guard: usize = 0;
        while (try it.next()) |_| {
            guard += 1;
            try testing.expect(guard <= buf.len);
        }
    } else {
        _ = d.asInt() catch {};
        _ = d.asFloat() catch {};
        _ = d.bitString() catch {};
        _ = d.utcTime() catch {};
        _ = d.binaryTime() catch {};
    }
}
