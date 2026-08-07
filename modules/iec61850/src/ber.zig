// SPDX-License-Identifier: MIT

//! BER (ITU-T X.690) — the encoding every layer above TPKT in an IEC 61850 MMS
//! association uses, and the one GOOSE and SV use for their PDUs too.
//!
//! The whole OSI sandwich (presentation, ACSE, MMS) and both fast-path
//! protocols are decoded by this one file, so every escape it gets wrong is a
//! bug in five places at once. The three that matter:
//!
//! * **The long-form tag escape.** A tag number of 31 in the identifier octet
//!   means "the real number follows in base-128 continuation octets". MMS uses
//!   it for real: `FileOpen` is `[72]`, i.e. `bf 48`, and a decoder that stops
//!   at `bf` reads the `48` as the length.
//! * **The long-form length escape.** `0x81..0x84` say "the length is in the
//!   next 1..4 octets"; `0x80` means **indefinite** — the content runs until a
//!   two-octet end-of-contents marker that can only be found by parsing the
//!   nested elements. Both appear in captured traffic.
//! * **Indefinite length is unbounded recursion in disguise.** Finding the EOC
//!   means descending into every nested TLV, so a hostile `a0 80 a0 80 a0 80 …`
//!   is a stack overflow unless the descent is explicitly bounded. Every entry
//!   point here therefore carries a depth budget and returns `error.TooDeep`.
//!
//! Encoding is done **backwards** — content first, header prepended once its
//! length is known. That is the only way to emit definite lengths for a deeply
//! nested structure without either a second pass or a scratch allocation, and
//! it is why nothing in this module allocates.

const std = @import("std");

pub const Error = error{
    /// Ran out of octets mid-element.
    Truncated,
    /// A tag number that does not fit `u32`, or a non-minimal long-form tag.
    BadTag,
    /// A length octet form that is not legal here (e.g. the reserved `0xFF`).
    BadLength,
    /// A definite length larger than the octets actually present.
    Overrun,
    /// An indefinite-length element whose end-of-contents marker never arrives.
    MissingEoc,
    /// Nesting past the depth budget.
    TooDeep,
    /// A primitive element used where a constructed one is required, or vice
    /// versa.
    BadForm,
    /// An integer wider than the requested Zig type, or a negative value in an
    /// unsigned field.
    IntegerRange,
    /// A BIT STRING whose unused-bit count is not 0..7, or which is empty, or
    /// (on the writing side) one asked for more bits than the `u64` value
    /// carrying them can hold.
    BadBitString,
    /// A FloatingPoint whose width octet does not match its payload.
    BadFloat,
    /// The output buffer cannot hold what is being written.
    BufferTooSmall,
    /// The element found is not the one the caller required.
    UnexpectedTag,
};

/// The default descent budget. IEC 61850-8-1 negotiates a data-structure
/// nesting level (libiec61850 proposes 10); this is the hard ceiling the codec
/// enforces regardless of what a peer proposes, so a peer cannot raise it.
pub const default_max_depth: u8 = 24;

// ── tags ────────────────────────────────────────────────────────────────────

pub const Class = enum(u2) {
    universal = 0,
    application = 1,
    context = 2,
    private = 3,
};

/// Universal tag numbers this module cares about.
pub const Universal = struct {
    pub const end_of_contents: u32 = 0;
    pub const boolean: u32 = 1;
    pub const integer: u32 = 2;
    pub const bit_string: u32 = 3;
    pub const octet_string: u32 = 4;
    pub const null_: u32 = 5;
    pub const object_identifier: u32 = 6;
    pub const external: u32 = 8;
    pub const utf8_string: u32 = 12;
    pub const sequence: u32 = 16;
    pub const set: u32 = 17;
    pub const visible_string: u32 = 26;
    pub const graphic_string: u32 = 25;
    pub const generalized_time: u32 = 24;
};

pub const Tag = struct {
    class: Class,
    constructed: bool,
    number: u32,

    pub fn ctx(number: u32) Tag {
        return .{ .class = .context, .constructed = false, .number = number };
    }
    pub fn ctxc(number: u32) Tag {
        return .{ .class = .context, .constructed = true, .number = number };
    }
    pub fn app(number: u32) Tag {
        return .{ .class = .application, .constructed = false, .number = number };
    }
    pub fn appc(number: u32) Tag {
        return .{ .class = .application, .constructed = true, .number = number };
    }
    pub fn uni(number: u32) Tag {
        return .{ .class = .universal, .constructed = false, .number = number };
    }
    pub fn unic(number: u32) Tag {
        return .{ .class = .universal, .constructed = true, .number = number };
    }
    /// SEQUENCE and SET are always constructed.
    pub const sequence = Tag{ .class = .universal, .constructed = true, .number = Universal.sequence };
    pub const set = Tag{ .class = .universal, .constructed = true, .number = Universal.set };

    pub fn eql(a: Tag, b: Tag) bool {
        return a.class == b.class and a.constructed == b.constructed and a.number == b.number;
    }

    /// Same tag ignoring the constructed bit — useful where a peer may send a
    /// constructed OCTET STRING for something this module emits primitive.
    pub fn eqlLoose(a: Tag, b: Tag) bool {
        return a.class == b.class and a.number == b.number;
    }

    /// Octets the identifier occupies on the wire.
    pub fn encodedLen(self: Tag) usize {
        if (self.number < 31) return 1;
        var n: usize = 1;
        var v = self.number;
        while (v != 0) : (v >>= 7) n += 1;
        return n;
    }
};

/// Decodes an identifier field. Returns the tag and how many octets it took.
pub fn decodeTag(bytes: []const u8) Error!struct { tag: Tag, len: usize } {
    if (bytes.len < 1) return error.Truncated;
    const first = bytes[0];
    const class: Class = @enumFromInt(@as(u2, @truncate(first >> 6)));
    const constructed = (first & 0x20) != 0;
    const low: u32 = first & 0x1F;
    if (low != 0x1F) {
        return .{ .tag = .{ .class = class, .constructed = constructed, .number = low }, .len = 1 };
    }
    // Long form: base-128, high bit = continuation.
    var number: u32 = 0;
    var i: usize = 1;
    while (true) : (i += 1) {
        if (i >= bytes.len) return error.Truncated;
        // More than five continuation octets cannot fit a u32; and a leading
        // 0x80 is the non-minimal form X.690 §8.1.2.4.2 forbids.
        if (i == 1 and bytes[i] == 0x80) return error.BadTag;
        if (i > 5) return error.BadTag;
        const b = bytes[i];
        const shifted = @mulWithOverflow(number, 128);
        if (shifted[1] != 0) return error.BadTag;
        const added = @addWithOverflow(shifted[0], @as(u32, b & 0x7F));
        if (added[1] != 0) return error.BadTag;
        number = added[0];
        if (b & 0x80 == 0) break;
    }
    // A long-form tag must not encode a number the short form could carry.
    if (number < 31) return error.BadTag;
    return .{ .tag = .{ .class = class, .constructed = constructed, .number = number }, .len = i + 1 };
}

pub fn encodeTag(tag: Tag, out: []u8) Error!usize {
    const first: u8 = (@as(u8, @intFromEnum(tag.class)) << 6) | (if (tag.constructed) @as(u8, 0x20) else 0);
    if (tag.number < 31) {
        if (out.len < 1) return error.BufferTooSmall;
        out[0] = first | @as(u8, @intCast(tag.number));
        return 1;
    }
    var tmp: [5]u8 = undefined;
    var n: usize = 0;
    var v = tag.number;
    while (true) {
        tmp[n] = @intCast(v & 0x7F);
        n += 1;
        v >>= 7;
        if (v == 0) break;
    }
    if (out.len < n + 1) return error.BufferTooSmall;
    out[0] = first | 0x1F;
    // tmp holds least-significant group first; the wire wants the opposite.
    var i: usize = 0;
    while (i < n) : (i += 1) {
        const g = tmp[n - 1 - i];
        out[1 + i] = if (i + 1 == n) g else g | 0x80;
    }
    return n + 1;
}

// ── lengths ─────────────────────────────────────────────────────────────────

pub const Length = union(enum) {
    definite: usize,
    indefinite,
};

pub fn decodeLength(bytes: []const u8) Error!struct { length: Length, len: usize } {
    if (bytes.len < 1) return error.Truncated;
    const first = bytes[0];
    if (first < 0x80) return .{ .length = .{ .definite = first }, .len = 1 };
    if (first == 0x80) return .{ .length = .indefinite, .len = 1 };
    if (first == 0xFF) return error.BadLength; // reserved by X.690 §8.1.3.5(c)
    const count: usize = first & 0x7F;
    if (count > @sizeOf(usize)) return error.BadLength;
    if (bytes.len < 1 + count) return error.Truncated;
    var v: usize = 0;
    for (bytes[1 .. 1 + count]) |b| v = (v << 8) | b;
    return .{ .length = .{ .definite = v }, .len = 1 + count };
}

/// Octets a definite length occupies.
pub fn lengthLen(v: usize) usize {
    if (v < 0x80) return 1;
    var n: usize = 0;
    var x = v;
    while (x != 0) : (x >>= 8) n += 1;
    return n + 1;
}

pub fn encodeLength(v: usize, out: []u8) Error!usize {
    const n = lengthLen(v);
    if (out.len < n) return error.BufferTooSmall;
    if (n == 1) {
        out[0] = @intCast(v);
        return 1;
    }
    out[0] = 0x80 | @as(u8, @intCast(n - 1));
    var i: usize = 1;
    while (i < n) : (i += 1) {
        const shift: u6 = @intCast((n - 1 - i) * 8);
        out[i] = @truncate(v >> shift);
    }
    return n;
}

// ── elements ────────────────────────────────────────────────────────────────

/// One decoded TLV. `content` excludes the header and, for an indefinite-length
/// element, excludes the two end-of-contents octets; `total_len` includes both.
pub const Element = struct {
    tag: Tag,
    content: []const u8,
    /// The complete TLV, header included — what a byte-exact re-encode needs.
    raw: []const u8,
    total_len: usize,
    /// True when the element arrived in indefinite-length form. It re-encodes
    /// as a definite length, which is legal BER but **not** byte-identical —
    /// callers that must round-trip verbatim keep the original slice.
    indefinite: bool = false,

    pub fn is(self: Element, tag: Tag) bool {
        return self.tag.eql(tag);
    }
};

/// Reads one element from the front of `bytes`.
pub fn decode(bytes: []const u8) Error!Element {
    return decodeDepth(bytes, default_max_depth);
}

pub fn decodeDepth(bytes: []const u8, budget: u8) Error!Element {
    if (budget == 0) return error.TooDeep;
    const t = try decodeTag(bytes);
    const l = try decodeLength(bytes[t.len..]);
    const head = t.len + l.len;
    switch (l.length) {
        .definite => |n| {
            if (bytes.len - head < n) return error.Overrun;
            return .{
                .tag = t.tag,
                .content = bytes[head..][0..n],
                .raw = bytes[0 .. head + n],
                .total_len = head + n,
            };
        },
        .indefinite => {
            // X.690 §8.1.3.6: only a constructed element may be indefinite.
            if (!t.tag.constructed) return error.BadLength;
            const span = try scanToEoc(bytes[head..], budget - 1);
            return .{
                .tag = t.tag,
                .content = bytes[head..][0..span],
                .raw = bytes[0 .. head + span + 2],
                .total_len = head + span + 2,
                .indefinite = true,
            };
        },
    }
}

/// Walks nested elements until the end-of-contents marker, returning how many
/// octets of content preceded it. This is where a hostile stream tries to
/// recurse forever, so the budget is checked before every descent.
fn scanToEoc(bytes: []const u8, budget: u8) Error!usize {
    if (budget == 0) return error.TooDeep;
    var off: usize = 0;
    while (true) {
        if (bytes.len - off < 2) return error.MissingEoc;
        if (bytes[off] == 0x00 and bytes[off + 1] == 0x00) return off;
        const e = try decodeDepth(bytes[off..], budget);
        // A zero-length step would spin forever; decodeDepth cannot produce
        // one (a header is at least two octets), but assert the invariant.
        if (e.total_len == 0) return error.BadLength;
        off += e.total_len;
    }
}

/// Iterates the elements inside a constructed element's content.
pub const Iterator = struct {
    rest: []const u8,
    budget: u8 = default_max_depth,

    pub fn init(content: []const u8) Iterator {
        return .{ .rest = content };
    }
    pub fn initDepth(content: []const u8, budget: u8) Iterator {
        return .{ .rest = content, .budget = budget };
    }

    pub fn next(self: *Iterator) Error!?Element {
        if (self.rest.len == 0) return null;
        // A stray end-of-contents inside a definite-length body is malformed,
        // but treating it as "done" is what a lenient decoder would do; refuse
        // it instead so the framing error surfaces.
        const e = try decodeDepth(self.rest, self.budget);
        self.rest = self.rest[e.total_len..];
        return e;
    }

    /// The next element, required to carry `tag`.
    pub fn expect(self: *Iterator, tag: Tag) Error!Element {
        const e = (try self.next()) orelse return error.Truncated;
        if (!e.tag.eql(tag)) return error.UnexpectedTag;
        return e;
    }

    pub fn done(self: *const Iterator) bool {
        return self.rest.len == 0;
    }
};

/// Reads one element and requires it to carry `tag`.
pub fn expect(bytes: []const u8, tag: Tag) Error!Element {
    const e = try decode(bytes);
    if (!e.tag.eql(tag)) return error.UnexpectedTag;
    return e;
}

// ── primitive content ───────────────────────────────────────────────────────

/// Signed INTEGER content, two's complement, big-endian.
pub fn decodeInt(comptime T: type, content: []const u8) Error!T {
    if (content.len == 0) return error.IntegerRange;
    // Reject the non-minimal forms X.690 §8.3.2 forbids: 9 leading identical
    // sign bits. A permissive decoder here is a signature-malleability hazard
    // in every protocol that hashes a re-encoding.
    if (content.len > 1) {
        if (content[0] == 0x00 and content[1] & 0x80 == 0) return error.IntegerRange;
        if (content[0] == 0xFF and content[1] & 0x80 != 0) return error.IntegerRange;
    }
    // Nine octets is the widest thing MMS names (`Unsigned64` carried as a
    // signed INTEGER with a leading zero); wider is refused rather than
    // silently truncated.
    if (content.len > 9) return error.IntegerRange;
    const negative = content[0] & 0x80 != 0;
    var acc: i128 = if (negative) -1 else 0;
    for (content) |b| acc = (acc << 8) | b;
    if (acc > std.math.maxInt(T) or acc < std.math.minInt(T)) return error.IntegerRange;
    return @intCast(acc);
}

/// Unsigned INTEGER content. MMS `Unsigned32` is still a signed-ASN.1 INTEGER
/// on the wire, so a leading zero octet is normal and a negative value is an
/// error rather than a huge positive number.
pub fn decodeUint(comptime T: type, content: []const u8) Error!T {
    const v = try decodeInt(i128, content);
    if (v < 0) return error.IntegerRange;
    if (v > std.math.maxInt(T)) return error.IntegerRange;
    return @intCast(v);
}

pub fn decodeBool(content: []const u8) Error!bool {
    if (content.len != 1) return error.BadForm;
    return content[0] != 0;
}

/// Octets a minimal signed INTEGER encoding of `v` needs.
pub fn intLen(v: i64) usize {
    var n: usize = 1;
    var x = v;
    while (x > 127 or x < -128) : (n += 1) x >>= 8;
    return n;
}

pub fn encodeIntContent(v: i64, out: []u8) Error!usize {
    const n = intLen(v);
    if (out.len < n) return error.BufferTooSmall;
    var i: usize = 0;
    while (i < n) : (i += 1) {
        const shift: u6 = @intCast((n - 1 - i) * 8);
        out[i] = @truncate(@as(u64, @bitCast(v)) >> shift);
    }
    return n;
}

// ── BIT STRING ──────────────────────────────────────────────────────────────

/// A BIT STRING: a count of unused trailing bits plus the octets. IEC 61850
/// leans on these hard — `OptFlds`, `TrgOps`, the report inclusion bitstring
/// and the reason-for-inclusion codes are all BIT STRINGs, and getting the
/// unused-bit count wrong shifts every flag.
pub const BitString = struct {
    unused: u3,
    bytes: []const u8,

    pub fn parse(content: []const u8) Error!BitString {
        if (content.len == 0) return error.BadBitString;
        if (content[0] > 7) return error.BadBitString;
        if (content.len == 1 and content[0] != 0) return error.BadBitString;
        return .{ .unused = @intCast(content[0]), .bytes = content[1..] };
    }

    /// Number of significant bits.
    pub fn bitCount(self: BitString) usize {
        if (self.bytes.len == 0) return 0;
        return self.bytes.len * 8 - self.unused;
    }

    /// Bit `i` counting from the **first** bit of the first octet, which is
    /// bit 7 of that octet. IEC 61850 numbers every bitstring this way.
    pub fn bit(self: BitString, i: usize) bool {
        if (i >= self.bitCount()) return false;
        return (self.bytes[i / 8] >> @intCast(7 - (i % 8))) & 1 != 0;
    }

    /// The bits as a right-aligned integer, first wire bit in the most
    /// significant position of the result's `bitCount()` window.
    pub fn asInt(self: BitString) u64 {
        var v: u64 = 0;
        const n = @min(self.bitCount(), 64);
        var i: usize = 0;
        while (i < n) : (i += 1) {
            v = (v << 1) | @intFromBool(self.bit(i));
        }
        return v;
    }
};

/// Builds a BIT STRING body from `count` bits held most-significant-first in
/// `value`.
pub fn bitStringContent(value: u64, count: u8, out: []u8) Error![]u8 {
    // The bits live in a `u64`, so `count` above 64 has no source to read from
    // and the shift amount below would not fit the `u6` it is cast to. Reject
    // it here: the `out.len` guard alone admits counts up to 8 * out.len - 8
    // (88 for the 12-byte scratch `Writer.bitString` passes), which used to
    // reach `@intCast` on a 64..87 shift — a trap in Debug, UB in ReleaseFast.
    if (count > 64) return error.BadBitString;
    const octets = (@as(usize, count) + 7) / 8;
    if (out.len < octets + 1) return error.BufferTooSmall;
    const unused: u8 = @intCast(octets * 8 - count);
    out[0] = unused;
    @memset(out[1 .. octets + 1], 0);
    var i: usize = 0;
    while (i < count) : (i += 1) {
        const b = (value >> @intCast(count - 1 - i)) & 1;
        if (b != 0) out[1 + i / 8] |= @as(u8, 0x80) >> @intCast(i % 8);
    }
    return out[0 .. octets + 1];
}

// ── MMS FloatingPoint ───────────────────────────────────────────────────────

/// MMS encodes a float as an OCTET STRING whose first octet is the **exponent
/// width in bits** (8 for IEEE single, 11 for double), followed by the IEEE
/// bits big-endian. Captured IEC 61850 traffic uses `08` + four octets for
/// every `f32` measurement.
pub const Float = union(enum) {
    single: f32,
    double: f64,

    pub fn value(self: Float) f64 {
        return switch (self) {
            .single => |v| @floatCast(v),
            .double => |v| v,
        };
    }

    pub fn parse(content: []const u8) Error!Float {
        if (content.len < 2) return error.BadFloat;
        const exponent_width = content[0];
        const body = content[1..];
        if (body.len == 4) {
            if (exponent_width != 8) return error.BadFloat;
            return .{ .single = @bitCast(std.mem.readInt(u32, body[0..4], .big)) };
        }
        if (body.len == 8) {
            if (exponent_width != 11) return error.BadFloat;
            return .{ .double = @bitCast(std.mem.readInt(u64, body[0..8], .big)) };
        }
        return error.BadFloat;
    }

    pub fn encode(self: Float, out: []u8) Error![]u8 {
        switch (self) {
            .single => |v| {
                if (out.len < 5) return error.BufferTooSmall;
                out[0] = 8;
                std.mem.writeInt(u32, out[1..5], @bitCast(v), .big);
                return out[0..5];
            },
            .double => |v| {
                if (out.len < 9) return error.BufferTooSmall;
                out[0] = 11;
                std.mem.writeInt(u64, out[1..9], @bitCast(v), .big);
                return out[0..9];
            },
        }
    }
};

// ── OBJECT IDENTIFIER ───────────────────────────────────────────────────────

/// An OID kept in its wire form. Comparing encoded octets is exact and needs no
/// decoding, which is all the presentation and ACSE layers require.
pub const Oid = struct {
    bytes: []const u8,

    pub fn eql(a: Oid, b: Oid) bool {
        return std.mem.eql(u8, a.bytes, b.bytes);
    }

    /// Formats as dotted decimal into `out`.
    pub fn format(self: Oid, out: []u8) Error![]u8 {
        if (self.bytes.len == 0) return error.Truncated;
        var w: usize = 0;
        var first = true;
        var acc: u64 = 0;
        var started = false;
        for (self.bytes) |b| {
            acc = (acc << 7) | (b & 0x7F);
            if (b & 0x80 != 0) {
                started = true;
                continue;
            }
            started = false;
            if (first) {
                const a: u64 = @min(acc / 40, 2);
                const c: u64 = acc - a * 40;
                w += (std.fmt.bufPrint(out[w..], "{d}.{d}", .{ a, c }) catch return error.BufferTooSmall).len;
                first = false;
            } else {
                w += (std.fmt.bufPrint(out[w..], ".{d}", .{acc}) catch return error.BufferTooSmall).len;
            }
            acc = 0;
        }
        if (started) return error.Truncated;
        return out[0..w];
    }
};

/// The OIDs an MMS association names, in wire form.
pub const oids = struct {
    /// 2.2.1.0.1 — the ACSE abstract syntax.
    pub const acse_abstract_syntax = [_]u8{ 0x52, 0x01, 0x00, 0x01 };
    /// 1.0.9506.2.1 — the MMS abstract syntax.
    pub const mms_abstract_syntax = [_]u8{ 0x28, 0xCA, 0x22, 0x02, 0x01 };
    /// 1.0.9506.2.3 — the MMS application context name.
    pub const mms_application_context = [_]u8{ 0x28, 0xCA, 0x22, 0x02, 0x03 };
    /// 2.1.1 — BER, the only transfer syntax IEC 61850 uses.
    pub const ber_transfer_syntax = [_]u8{ 0x51, 0x01 };
};

// ── backwards writer ────────────────────────────────────────────────────────

/// Builds BER **from the end of the buffer towards the front**: write the
/// content, then prepend the header once the content length is known. Nested
/// structures fall out naturally and no length is ever patched afterwards.
///
/// Usage is always the same three lines:
///
/// ```zig
/// const m = w.mark();
/// try w.bytes(payload);
/// try w.header(ber.Tag.ctxc(0), m);
/// ```
pub const Writer = struct {
    buf: []u8,
    /// Index of the first written octet; content occupies `buf[start..]`.
    start: usize,

    pub fn init(buf: []u8) Writer {
        return .{ .buf = buf, .start = buf.len };
    }

    /// Everything written so far, in wire order.
    pub fn done(self: *const Writer) []const u8 {
        return self.buf[self.start..];
    }

    pub fn len(self: *const Writer) usize {
        return self.buf.len - self.start;
    }

    /// A position to measure a later `header` call against.
    pub fn mark(self: *const Writer) usize {
        return self.start;
    }

    pub fn bytes(self: *Writer, b: []const u8) Error!void {
        if (self.start < b.len) return error.BufferTooSmall;
        self.start -= b.len;
        @memcpy(self.buf[self.start..][0..b.len], b);
    }

    pub fn byte(self: *Writer, b: u8) Error!void {
        if (self.start < 1) return error.BufferTooSmall;
        self.start -= 1;
        self.buf[self.start] = b;
    }

    /// Prepends tag + definite length covering everything written since
    /// `mark_pos`.
    pub fn header(self: *Writer, tag: Tag, mark_pos: usize) Error!void {
        const content_len = mark_pos - self.start;
        // Order matters: the length lands immediately before the content, then
        // the tag lands immediately before the length.
        var lbuf: [16]u8 = undefined;
        const ll = try encodeLength(content_len, &lbuf);
        var tbuf: [8]u8 = undefined;
        const tl = try encodeTag(tag, &tbuf);
        if (self.start < ll + tl) return error.BufferTooSmall;
        try self.bytes(lbuf[0..ll]);
        try self.bytes(tbuf[0..tl]);
    }

    /// Writes a complete primitive TLV.
    pub fn primitive(self: *Writer, tag: Tag, content: []const u8) Error!void {
        const m = self.mark();
        try self.bytes(content);
        try self.header(tag, m);
    }

    /// X.690 §11.1 (DER) fixes TRUE at `0xFF`, but BER allows any non-zero
    /// octet and **every IEC 61850 stack observed here emits `0x01`**. This
    /// writer matches the wire it has to interoperate with; the decoder accepts
    /// both.
    pub fn boolean(self: *Writer, tag: Tag, v: bool) Error!void {
        try self.primitive(tag, &[_]u8{if (v) 0x01 else 0x00});
    }

    pub fn integer(self: *Writer, tag: Tag, v: i64) Error!void {
        var tmp: [8]u8 = undefined;
        const n = try encodeIntContent(v, &tmp);
        try self.primitive(tag, tmp[0..n]);
    }

    pub fn unsigned(self: *Writer, tag: Tag, v: u64) Error!void {
        if (v <= std.math.maxInt(i64)) {
            try self.integer(tag, @intCast(v));
            return;
        }
        var tmp: [9]u8 = undefined;
        tmp[0] = 0;
        std.mem.writeInt(u64, tmp[1..9], v, .big);
        try self.primitive(tag, &tmp);
    }

    pub fn bitString(self: *Writer, tag: Tag, value: u64, count: u8) Error!void {
        var tmp: [12]u8 = undefined;
        const body = try bitStringContent(value, count, &tmp);
        try self.primitive(tag, body);
    }

    /// A BIT STRING already in wire form (leading unused-bit octet included).
    pub fn bitStringRaw(self: *Writer, tag: Tag, unused: u3, body: []const u8) Error!void {
        const m = self.mark();
        try self.bytes(body);
        try self.byte(unused);
        try self.header(tag, m);
    }

    pub fn float(self: *Writer, tag: Tag, v: Float) Error!void {
        var tmp: [9]u8 = undefined;
        const body = try v.encode(&tmp);
        try self.primitive(tag, body);
    }

    pub fn null_(self: *Writer, tag: Tag) Error!void {
        try self.primitive(tag, &[_]u8{});
    }

    pub fn oid(self: *Writer, tag: Tag, o: Oid) Error!void {
        try self.primitive(tag, o.bytes);
    }
};

// ── tests ───────────────────────────────────────────────────────────────────

const testing = std.testing;

test "short-form tags round trip" {
    var out: [8]u8 = undefined;
    for ([_]Tag{
        Tag.ctx(0),
        Tag.ctxc(4),
        Tag.app(1),
        Tag.appc(1),
        Tag.sequence,
        Tag.uni(Universal.visible_string),
        .{ .class = .private, .constructed = true, .number = 30 },
    }) |t| {
        const n = try encodeTag(t, &out);
        const back = try decodeTag(out[0..n]);
        try testing.expectEqual(n, back.len);
        try testing.expect(t.eql(back.tag));
    }
}

test "the long-form tag escape: MMS FileOpen is bf 48" {
    var out: [8]u8 = undefined;
    const n = try encodeTag(Tag.ctxc(72), &out);
    try testing.expectEqualSlices(u8, &[_]u8{ 0xBF, 0x48 }, out[0..n]);
    const back = try decodeTag(out[0..n]);
    try testing.expectEqual(@as(u32, 72), back.tag.number);
    try testing.expect(back.tag.constructed);
    try testing.expectEqual(Class.context, back.tag.class);
}

test "long-form tags round trip across every continuation boundary" {
    var out: [8]u8 = undefined;
    for ([_]u32{ 31, 32, 126, 127, 128, 129, 16383, 16384, 2097151, 2097152, 268435455, std.math.maxInt(u32) }) |num| {
        const t = Tag.ctxc(num);
        const n = try encodeTag(t, &out);
        const back = try decodeTag(out[0..n]);
        try testing.expectEqual(num, back.tag.number);
        try testing.expectEqual(n, back.len);
        try testing.expectEqual(t.encodedLen(), n);
    }
}

test "malformed tags are typed errors" {
    try testing.expectError(error.Truncated, decodeTag(&[_]u8{}));
    try testing.expectError(error.Truncated, decodeTag(&[_]u8{0xBF}));
    try testing.expectError(error.Truncated, decodeTag(&[_]u8{ 0xBF, 0x80 + 1 }));
    // Non-minimal long form: a leading 0x80 continuation octet.
    try testing.expectError(error.BadTag, decodeTag(&[_]u8{ 0xBF, 0x80, 0x01 }));
    // A long form encoding a number the short form covers.
    try testing.expectError(error.BadTag, decodeTag(&[_]u8{ 0xBF, 0x1E }));
    // Six continuation octets cannot fit a u32.
    try testing.expectError(error.BadTag, decodeTag(&[_]u8{ 0xBF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0x7F }));
}

test "length forms round trip at every boundary" {
    var out: [16]u8 = undefined;
    for ([_]usize{ 0, 1, 127, 128, 255, 256, 65535, 65536, 16777215, 16777216 }) |v| {
        const n = try encodeLength(v, &out);
        try testing.expectEqual(lengthLen(v), n);
        const back = try decodeLength(out[0..n]);
        try testing.expectEqual(n, back.len);
        try testing.expectEqual(v, back.length.definite);
    }
    // The captured shapes.
    try testing.expectEqual(@as(usize, 0x99), (try decodeLength(&[_]u8{ 0x81, 0x99 })).length.definite);
    try testing.expectEqual(@as(usize, 0x1a00), (try decodeLength(&[_]u8{ 0x82, 0x1a, 0x00 })).length.definite);
}

test "malformed lengths are typed errors" {
    try testing.expectError(error.Truncated, decodeLength(&[_]u8{}));
    try testing.expectError(error.BadLength, decodeLength(&[_]u8{0xFF}));
    try testing.expectError(error.Truncated, decodeLength(&[_]u8{0x82}));
    try testing.expectError(error.Truncated, decodeLength(&[_]u8{ 0x84, 1, 2 }));
    // More length octets than a usize can hold.
    try testing.expectError(error.BadLength, decodeLength(&[_]u8{ 0x89, 1, 2, 3, 4, 5, 6, 7, 8, 9 }));
    try testing.expect((try decodeLength(&[_]u8{0x80})).length == .indefinite);
}

test "a definite length that overruns the buffer is refused" {
    try testing.expectError(error.Overrun, decode(&[_]u8{ 0x30, 0x10, 0x01, 0x02 }));
    try testing.expectError(error.Overrun, decode(&[_]u8{ 0x04, 0x82, 0xFF, 0xFF, 0x00 }));
}

test "indefinite length finds its end-of-contents" {
    // a0 80 { 02 01 05 } 00 00
    const bytes = [_]u8{ 0xA0, 0x80, 0x02, 0x01, 0x05, 0x00, 0x00 };
    const e = try decode(&bytes);
    try testing.expect(e.indefinite);
    try testing.expectEqualSlices(u8, &[_]u8{ 0x02, 0x01, 0x05 }, e.content);
    try testing.expectEqual(@as(usize, 7), e.total_len);
    var it = Iterator.init(e.content);
    const inner = (try it.next()).?;
    try testing.expectEqual(@as(i32, 5), try decodeInt(i32, inner.content));
}

test "nested indefinite lengths nest correctly" {
    // a0 80 { a1 80 { 02 01 07 } 00 00 } 00 00
    const bytes = [_]u8{ 0xA0, 0x80, 0xA1, 0x80, 0x02, 0x01, 0x07, 0x00, 0x00, 0x00, 0x00 };
    const outer = try decode(&bytes);
    try testing.expectEqual(@as(usize, 11), outer.total_len);
    const inner = try decode(outer.content);
    try testing.expect(inner.indefinite);
    try testing.expectEqual(@as(i32, 7), try decodeInt(i32, (try decode(inner.content)).content));
}

test "indefinite length without a terminator is refused, not looped on" {
    try testing.expectError(error.MissingEoc, decode(&[_]u8{ 0xA0, 0x80, 0x02, 0x01, 0x05 }));
    try testing.expectError(error.MissingEoc, decode(&[_]u8{ 0xA0, 0x80 }));
    // A primitive element may not use the indefinite form.
    try testing.expectError(error.BadLength, decode(&[_]u8{ 0x04, 0x80, 0x00, 0x00 }));
}

test "indefinite nesting past the depth bound is refused rather than overflowing the stack" {
    var bytes: [4096]u8 = undefined;
    // 512 nested `a0 80` openers, then 512 EOCs — well past default_max_depth.
    const depth = 512;
    var i: usize = 0;
    while (i < depth) : (i += 1) {
        bytes[i * 2] = 0xA0;
        bytes[i * 2 + 1] = 0x80;
    }
    @memset(bytes[depth * 2 ..][0 .. depth * 2], 0x00);
    try testing.expectError(error.TooDeep, decode(bytes[0 .. depth * 4]));
}

test "integers reject the non-minimal forms" {
    try testing.expectEqual(@as(i32, 0), try decodeInt(i32, &[_]u8{0x00}));
    try testing.expectEqual(@as(i32, -1), try decodeInt(i32, &[_]u8{0xFF}));
    try testing.expectEqual(@as(i32, 127), try decodeInt(i32, &[_]u8{0x7F}));
    try testing.expectEqual(@as(i32, 128), try decodeInt(i32, &[_]u8{ 0x00, 0x80 }));
    try testing.expectEqual(@as(i32, -128), try decodeInt(i32, &[_]u8{0x80}));
    try testing.expectEqual(@as(u32, 65000), try decodeUint(u32, &[_]u8{ 0x00, 0xFD, 0xE8 }));
    // 9 redundant leading sign bits, both polarities.
    try testing.expectError(error.IntegerRange, decodeInt(i32, &[_]u8{ 0x00, 0x01 }));
    try testing.expectError(error.IntegerRange, decodeInt(i32, &[_]u8{ 0xFF, 0xFF }));
    try testing.expectError(error.IntegerRange, decodeInt(i32, &[_]u8{}));
    // Too wide for the requested type.
    try testing.expectError(error.IntegerRange, decodeInt(i8, &[_]u8{ 0x01, 0x00 }));
    // Negative into an unsigned field.
    try testing.expectError(error.IntegerRange, decodeUint(u32, &[_]u8{0xFF}));
}

test "integer content round trips" {
    var out: [8]u8 = undefined;
    for ([_]i64{ 0, 1, -1, 127, 128, -128, -129, 255, 256, 65535, -65536, 1 << 40, -(1 << 40), std.math.maxInt(i64), std.math.minInt(i64) }) |v| {
        const n = try encodeIntContent(v, &out);
        try testing.expectEqual(intLen(v), n);
        try testing.expectEqual(v, try decodeInt(i64, out[0..n]));
    }
}

test "bit strings honour the unused-bit count" {
    // The captured TrgOps: 2 unused bits, 0x0c -> bits 4 and 5 set of 6.
    const bs = try BitString.parse(&[_]u8{ 0x02, 0x0C });
    try testing.expectEqual(@as(usize, 6), bs.bitCount());
    try testing.expect(!bs.bit(0));
    try testing.expect(bs.bit(4));
    try testing.expect(bs.bit(5));
    // Past the end reads false rather than panicking.
    try testing.expect(!bs.bit(99));

    try testing.expectError(error.BadBitString, BitString.parse(&[_]u8{}));
    try testing.expectError(error.BadBitString, BitString.parse(&[_]u8{0x08}));
    try testing.expectError(error.BadBitString, BitString.parse(&[_]u8{0x03}));
}

test "bit string content round trips through the writer" {
    var tmp: [12]u8 = undefined;
    // 4 bits, value 0b1111 -> 4 unused, 0xF0.
    try testing.expectEqualSlices(u8, &[_]u8{ 0x04, 0xF0 }, try bitStringContent(0b1111, 4, &tmp));
    // 6 bits, 0b000011 -> 2 unused, 0x0C (the captured TrgOps).
    try testing.expectEqualSlices(u8, &[_]u8{ 0x02, 0x0C }, try bitStringContent(0b000011, 6, &tmp));
    // 13 bits (the captured OptFlds width) -> 3 unused.
    const of = try bitStringContent(0b0111101000000, 13, &tmp);
    try testing.expectEqual(@as(u8, 3), of[0]);
    const back = try BitString.parse(of);
    try testing.expectEqual(@as(usize, 13), back.bitCount());
    try testing.expectEqual(@as(u64, 0b0111101000000), back.asInt());
}

test "a bit string wider than its u64 source is refused, not miscast" {
    // `bitStringContent`/`Writer.bitString` are public API. The only bound was
    // `out.len`, and `Writer.bitString`'s own 12-byte scratch admits counts up
    // to 88 — so counts 65..88 reached `@intCast(count - 1 - i)` with a shift
    // amount of 64..87 for the `u6` shift of a `u64`. Debug trapped; under
    // ReleaseFast the shift is UB and the emitted BIT STRING is garbage.
    var tmp: [12]u8 = undefined;
    try testing.expectEqualSlices(u8, &[_]u8{ 0x00, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF }, try bitStringContent(std.math.maxInt(u64), 64, &tmp));
    try testing.expectError(error.BadBitString, bitStringContent(1, 65, &tmp));
    try testing.expectError(error.BadBitString, bitStringContent(1, 88, &tmp));
    try testing.expectError(error.BadBitString, bitStringContent(1, 255, &tmp));

    // Same guard reached through the writer, which is the surface a caller
    // outside this module actually holds.
    var buf: [64]u8 = undefined;
    var w = Writer.init(&buf);
    try testing.expectError(error.BadBitString, w.bitString(Tag.uni(Universal.bit_string), 1, 65));
}

test "MMS floats carry their exponent width" {
    var tmp: [16]u8 = undefined;
    const single = Float{ .single = 1.5 };
    const enc = try single.encode(&tmp);
    try testing.expectEqualSlices(u8, &[_]u8{ 0x08, 0x3F, 0xC0, 0x00, 0x00 }, enc);
    try testing.expectEqual(@as(f32, 1.5), (try Float.parse(enc)).single);
    const double = Float{ .double = -2.25 };
    const enc2 = try double.encode(&tmp);
    try testing.expectEqual(@as(u8, 11), enc2[0]);
    try testing.expectEqual(@as(f64, -2.25), (try Float.parse(enc2)).double);
    // The captured measurement from a real IED.
    const captured = [_]u8{ 0x08, 0x3D, 0x2A, 0x51, 0x55 };
    try testing.expectApproxEqAbs(@as(f64, 0.0415809), (try Float.parse(&captured)).value(), 1e-6);
    // A width that disagrees with the payload.
    try testing.expectError(error.BadFloat, Float.parse(&[_]u8{ 0x0B, 0x3F, 0xC0, 0x00, 0x00 }));
    try testing.expectError(error.BadFloat, Float.parse(&[_]u8{ 0x08, 0x00, 0x00 }));
    try testing.expectError(error.BadFloat, Float.parse(&[_]u8{0x08}));
}

test "OIDs format as dotted decimal" {
    var out: [64]u8 = undefined;
    try testing.expectEqualStrings("1.0.9506.2.1", try (Oid{ .bytes = &oids.mms_abstract_syntax }).format(&out));
    try testing.expectEqualStrings("2.2.1.0.1", try (Oid{ .bytes = &oids.acse_abstract_syntax }).format(&out));
    try testing.expectEqualStrings("2.1.1", try (Oid{ .bytes = &oids.ber_transfer_syntax }).format(&out));
    try testing.expectEqualStrings("1.0.9506.2.3", try (Oid{ .bytes = &oids.mms_application_context }).format(&out));
    // A dangling continuation octet.
    try testing.expectError(error.Truncated, (Oid{ .bytes = &[_]u8{ 0x28, 0x80 } }).format(&out));
}

test "the backwards writer builds nested definite lengths" {
    var buf: [256]u8 = undefined;
    var w = Writer.init(&buf);
    // Build: a0 { 02 01 05, 04 03 'a''b''c' }
    const outer = w.mark();
    try w.primitive(Tag.uni(Universal.octet_string), "abc");
    try w.integer(Tag.uni(Universal.integer), 5);
    try w.header(Tag.ctxc(0), outer);
    try testing.expectEqualSlices(
        u8,
        &[_]u8{ 0xA0, 0x08, 0x02, 0x01, 0x05, 0x04, 0x03, 'a', 'b', 'c' },
        w.done(),
    );
}

test "the writer emits the long-form length when it must" {
    var buf: [512]u8 = undefined;
    var w = Writer.init(&buf);
    const m = w.mark();
    try w.bytes(&[_]u8{0xAA} ** 200);
    try w.header(Tag.ctxc(2), m);
    const out = w.done();
    try testing.expectEqualSlices(u8, &[_]u8{ 0xA2, 0x81, 0xC8 }, out[0..3]);
    const e = try decode(out);
    try testing.expectEqual(@as(usize, 200), e.content.len);
}

test "the writer emits the long-form tag when it must" {
    var buf: [64]u8 = undefined;
    var w = Writer.init(&buf);
    try w.primitive(Tag.ctxc(72), &[_]u8{});
    try testing.expectEqualSlices(u8, &[_]u8{ 0xBF, 0x48, 0x00 }, w.done());
}

test "the writer refuses to overflow its buffer" {
    var buf: [4]u8 = undefined;
    var w = Writer.init(&buf);
    try testing.expectError(error.BufferTooSmall, w.bytes(&[_]u8{0} ** 5));
    var w2 = Writer.init(&buf);
    try w2.bytes(&[_]u8{ 1, 2, 3, 4 });
    try testing.expectError(error.BufferTooSmall, w2.byte(5));
}

test "iterator walks a constructed body and refuses a malformed member" {
    const bytes = [_]u8{ 0x30, 0x08, 0x02, 0x01, 0x01, 0x02, 0x01, 0x02, 0x05, 0x00 };
    const e = try decode(&bytes);
    var it = Iterator.init(e.content);
    try testing.expectEqual(@as(i32, 1), try decodeInt(i32, (try it.next()).?.content));
    try testing.expectEqual(@as(i32, 2), try decodeInt(i32, (try it.next()).?.content));
    try testing.expectEqual(@as(usize, 0), (try it.next()).?.content.len);
    try testing.expect((try it.next()) == null);
    try testing.expect(it.done());

    var bad = Iterator.init(&[_]u8{ 0x30, 0x08, 0x02 });
    try testing.expectError(error.Overrun, bad.next());
}

test "expect surfaces the wrong tag rather than mis-parsing" {
    const bytes = [_]u8{ 0xA1, 0x03, 0x02, 0x01, 0x07 };
    try testing.expectError(error.UnexpectedTag, expect(&bytes, Tag.ctxc(0)));
    _ = try expect(&bytes, Tag.ctxc(1));
}

test "fuzz: ber decode never panics and re-encodes consistently" {
    try std.testing.fuzz({}, fuzzDecode, .{});
}

fn fuzzDecode(_: void, smith: *std.testing.Smith) !void {
    var buf: [512]u8 = undefined;
    smith.bytes(&buf);
    const n: usize = smith.valueRangeAtMost(u16, 0, buf.len);
    const e = decode(buf[0..n]) catch return;
    try testing.expect(e.total_len <= n);
    try testing.expect(e.content.len <= e.total_len);
    // A definite-length element must re-encode to exactly the octets it came
    // from; an indefinite one legitimately re-encodes shorter.
    if (!e.indefinite) {
        var out: [1024]u8 = undefined;
        var w = Writer.init(&out);
        const m = w.mark();
        w.bytes(e.content) catch return;
        w.header(e.tag, m) catch return;
        try testing.expectEqualSlices(u8, buf[0..e.total_len], w.done());
    }
}

test "fuzz: iterating arbitrary constructed bodies terminates" {
    try std.testing.fuzz({}, fuzzIterate, .{});
}

fn fuzzIterate(_: void, smith: *std.testing.Smith) !void {
    var buf: [512]u8 = undefined;
    smith.bytes(&buf);
    const n: usize = smith.valueRangeAtMost(u16, 0, buf.len);
    var it = Iterator.init(buf[0..n]);
    var guard: usize = 0;
    while (true) {
        guard += 1;
        try testing.expect(guard <= buf.len + 1);
        const e = it.next() catch return;
        if (e == null) break;
        _ = decodeInt(i64, e.?.content) catch {};
        _ = BitString.parse(e.?.content) catch {};
        _ = Float.parse(e.?.content) catch {};
    }
}

test "fuzz: tag and length codecs round trip" {
    try std.testing.fuzz({}, fuzzTagLength, .{});
}

fn fuzzTagLength(_: void, smith: *std.testing.Smith) !void {
    var out: [16]u8 = undefined;
    const number: u32 = smith.value(u32);
    const t = Tag{
        .class = @enumFromInt(smith.value(u2)),
        .constructed = smith.value(bool),
        .number = number,
    };
    const n = try encodeTag(t, &out);
    const back = try decodeTag(out[0..n]);
    try testing.expect(t.eql(back.tag));

    const v: usize = smith.value(u32);
    const ln = try encodeLength(v, &out);
    try testing.expectEqual(v, (try decodeLength(out[0..ln])).length.definite);
}
