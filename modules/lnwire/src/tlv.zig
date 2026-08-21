// SPDX-License-Identifier: MIT
//! BigSize (Lightning's varint) and the generic BOLT#1 TLV stream format.
//!
//! BigSize is CompactSize (Bitcoin's varint) with the multi-byte forms
//! flipped to big-endian (BOLT#1 "Appendix A: BigSize Test Vectors"). A
//! `tlv_stream` is a sequence of `(bigsize type, bigsize length, length
//! bytes of value)` records; BOLT#1's "Type-Length-Value Format"
//! Requirements govern strictly-increasing types, minimal `bigsize`
//! encoding, and the "it's ok to be odd" unknown-type rule (odd unknown
//! types are silently discarded, even unknown types fail the stream).
//!
//! `parseStream` implements exactly those generic, message-agnostic
//! rules over untrusted bytes. It does NOT know any message's per-type
//! value encoding (e.g. that `n1`'s `tlv1` is a truncated `u64`, or that
//! BOLT#2's `channel_type` is an opaque byte string) — that's the
//! caller's layer (see `message.zig`'s `Extension`, and each
//! `bolt2.zig`/`bolt7.zig` message's `known_tlv_types`). A caller tells
//! `parseStream` which top-level types are "known" for its stream (so it
//! can decide even-unknown-rejection vs odd-unknown-discard); everything
//! else — ordering, minimality, truncation — is enforced unconditionally.
//!
//! `decodeTruncated`/`encodeTruncated` implement the `tu16`/`tu32`/`tu64`
//! "truncated integer" convention (0 to N bytes, no leading zero byte —
//! BOLT#1 "Fundamental Types"), reusable by any TLV value that uses it.

const std = @import("std");
const Allocator = std.mem.Allocator;

// ── BigSize ──────────────────────────────────────────────────────────────

pub const BigSizeError = error{
    /// Fewer bytes remain than the encoding requires.
    Truncated,
    /// A value was encoded wider than necessary (e.g. `0xfd 0x00 0xfc` for
    /// the value 252, which fits the 1-byte form) — BOLT#1 requires
    /// minimal encoding; this decoder rejects non-minimal forms.
    NonMinimal,
};

pub const BigSizeDecoded = struct { value: u64, consumed: usize };

/// The minimal BigSize encoding length for `value`.
pub fn bigSizeLen(value: u64) usize {
    if (value < 0xfd) return 1;
    if (value <= 0xffff) return 3;
    if (value <= 0xffffffff) return 5;
    return 9;
}

/// Writes the minimal BigSize encoding of `value` into `out` (big-endian
/// multi-byte forms, per BOLT#1). `out` must be at least
/// `bigSizeLen(value)` bytes (9 always suffices for any `u64`).
pub fn encodeBigSize(value: u64, out: []u8) error{BufferTooSmall}![]u8 {
    const n = bigSizeLen(value);
    if (out.len < n) return error.BufferTooSmall;
    if (value < 0xfd) {
        out[0] = @intCast(value);
    } else if (value <= 0xffff) {
        out[0] = 0xfd;
        std.mem.writeInt(u16, out[1..3], @intCast(value), .big);
    } else if (value <= 0xffffffff) {
        out[0] = 0xfe;
        std.mem.writeInt(u32, out[1..5], @intCast(value), .big);
    } else {
        out[0] = 0xff;
        std.mem.writeInt(u64, out[1..9], value, .big);
    }
    return out[0..n];
}

/// Decodes one BigSize from the front of `bytes`. Fail-closed on
/// truncation and on non-minimal encodings.
pub fn decodeBigSize(bytes: []const u8) BigSizeError!BigSizeDecoded {
    if (bytes.len == 0) return error.Truncated;
    const first = bytes[0];
    if (first < 0xfd) return .{ .value = first, .consumed = 1 };
    if (first == 0xfd) {
        if (bytes.len < 3) return error.Truncated;
        const v = std.mem.readInt(u16, bytes[1..3], .big);
        if (v < 0xfd) return error.NonMinimal;
        return .{ .value = v, .consumed = 3 };
    }
    if (first == 0xfe) {
        if (bytes.len < 5) return error.Truncated;
        const v = std.mem.readInt(u32, bytes[1..5], .big);
        if (v <= 0xffff) return error.NonMinimal;
        return .{ .value = v, .consumed = 5 };
    }
    // first == 0xff
    if (bytes.len < 9) return error.Truncated;
    const v = std.mem.readInt(u64, bytes[1..9], .big);
    if (v <= 0xffffffff) return error.NonMinimal;
    return .{ .value = v, .consumed = 9 };
}

// ── truncated integers (tu16/tu32/tu64) ─────────────────────────────────

pub const TruncatedIntError = error{
    /// More bytes than `@sizeOf(T)` were given — wider than the field
    /// could ever legitimately need.
    TooLong,
    /// A leading zero byte was present; the minimal encoding of a
    /// truncated integer never has one (zero itself is zero bytes).
    NonMinimal,
};

/// Decodes a BOLT#1 "truncated integer" (`tu16`/`tu32`/`tu64`): 0 to
/// `@sizeOf(T)` big-endian bytes, no leading zero byte.
pub fn decodeTruncated(comptime T: type, value: []const u8) TruncatedIntError!T {
    if (value.len > @sizeOf(T)) return error.TooLong;
    if (value.len > 0 and value[0] == 0) return error.NonMinimal;
    var v: T = 0;
    for (value) |b| v = (v << 8) | b;
    return v;
}

/// The minimal truncated-integer encoding length for `value` (0 for
/// `value == 0`).
pub fn truncatedLen(comptime T: type, value: T) usize {
    var v = value;
    var n: usize = 0;
    while (v != 0) : (v >>= 8) n += 1;
    return n;
}

/// Writes the minimal truncated-integer encoding of `value` into `out`.
/// `out` must be at least `truncatedLen(T, value)` bytes.
pub fn encodeTruncated(comptime T: type, value: T, out: []u8) error{BufferTooSmall}![]u8 {
    const n = truncatedLen(T, value);
    if (out.len < n) return error.BufferTooSmall;
    var v = value;
    var i = n;
    while (i > 0) {
        i -= 1;
        out[i] = @truncate(v);
        v >>= 8;
    }
    return out[0..n];
}

// ── TLV stream ───────────────────────────────────────────────────────────

/// One decoded `tlv_record`: `value` is a borrowed slice into the buffer
/// `parseStream` was called with (never copied — see module doc comment
/// and `message.zig`'s `Extension`).
pub const RawRecord = struct { type: u64, value: []const u8 };

pub const StreamError = BigSizeError || error{
    /// Decoded types were not strictly increasing — includes the
    /// duplicate-type case (BOLT#1 folds both under one requirement).
    NotStrictlyIncreasing,
    /// An unrecognized *even* type was encountered — BOLT#1: "it's ok to
    /// be odd", so only even unknown types must fail the stream.
    UnknownEvenType,
};

pub const ParsedStream = struct {
    /// Only the records whose `type` was in the caller's `known_types` —
    /// unknown-odd records were parsed (to stay stream-aligned) then
    /// discarded, never stored, per BOLT#1.
    records: []RawRecord,

    pub fn deinit(self: *ParsedStream, allocator: Allocator) void {
        allocator.free(self.records);
        self.* = undefined;
    }

    /// The value bytes of the first record of type `t`, if present.
    pub fn find(self: ParsedStream, t: u64) ?[]const u8 {
        for (self.records) |r| {
            if (r.type == t) return r.value;
        }
        return null;
    }
};

fn isKnown(known_types: []const u64, t: u64) bool {
    for (known_types) |k| {
        if (k == t) return true;
    }
    return false;
}

/// Parses a `tlv_stream` from the whole of `bytes` (BOLT#1's "if zero
/// bytes remain before parsing a type: MUST stop parsing" — so an empty
/// `bytes` decodes to zero records, not an error). Enforces strictly-
/// increasing types, minimal `bigsize` type/length encoding, and that
/// each record's `length` doesn't exceed the bytes remaining. A type in
/// `known_types` is kept (its raw value bytes returned, uninterpreted —
/// per-type value semantics are the caller's, see module doc comment); a
/// type NOT in `known_types` is rejected if even, silently discarded (its
/// value bytes skipped, not stored) if odd.
pub fn parseStream(allocator: Allocator, bytes: []const u8, known_types: []const u64) (StreamError || Allocator.Error)!ParsedStream {
    var list: std.ArrayList(RawRecord) = .empty;
    errdefer list.deinit(allocator);

    var offset: usize = 0;
    var last_type: ?u64 = null;
    while (offset < bytes.len) {
        const t = try decodeBigSize(bytes[offset..]);
        offset += t.consumed;
        // BOLT#1: unlike the type position, zero bytes remaining here is
        // NOT a valid stream end -- a type with no following length/value
        // is a truncated record. decodeBigSize on an empty slice already
        // returns error.Truncated, which is exactly right.
        const l = try decodeBigSize(bytes[offset..]);
        offset += l.consumed;

        const remaining: u64 = bytes.len - offset;
        if (l.value > remaining) return error.Truncated;
        const len: usize = @intCast(l.value);
        const value = bytes[offset .. offset + len];
        offset += len;

        if (last_type) |lt| {
            if (t.value <= lt) return error.NotStrictlyIncreasing;
        }
        last_type = t.value;

        if (isKnown(known_types, t.value)) {
            try list.append(allocator, .{ .type = t.value, .value = value });
        } else if (t.value % 2 == 0) {
            return error.UnknownEvenType;
        }
        // unknown odd: already consumed past `value` above -- discard.
    }
    return .{ .records = try list.toOwnedSlice(allocator) };
}

fn appendRecord(list: *std.ArrayList(u8), allocator: Allocator, rec: RawRecord) Allocator.Error!void {
    var tmp: [9]u8 = undefined;
    const t_enc = encodeBigSize(rec.type, &tmp) catch unreachable; // tmp always big enough
    try list.appendSlice(allocator, t_enc);
    const l_enc = encodeBigSize(rec.value.len, &tmp) catch unreachable;
    try list.appendSlice(allocator, l_enc);
    try list.appendSlice(allocator, rec.value);
}

/// Serializes `records` (assumed already in valid strictly-increasing
/// order, e.g. as returned by `parseStream` or built that way by hand) as
/// a `tlv_stream`, appending to `list`.
pub fn appendStream(list: *std.ArrayList(u8), allocator: Allocator, records: []const RawRecord) Allocator.Error!void {
    for (records) |r| try appendRecord(list, allocator, r);
}

// ── tests ────────────────────────────────────────────────────────────────

const testing = std.testing;

/// Decodes a hex string (no `0x`, no separators, even length -- possibly
/// empty) into freshly allocated bytes. Test-only: lets the BOLT#1
/// appendix vectors below be pasted verbatim from the spec's own hex
/// strings rather than hand-transcribed into `0x..` Zig array literals
/// (eliminates an entire class of transcription slip).
fn hexBytes(allocator: Allocator, hex: []const u8) ![]u8 {
    std.debug.assert(hex.len % 2 == 0);
    const out = try allocator.alloc(u8, hex.len / 2);
    errdefer allocator.free(out);
    var i: usize = 0;
    while (i < hex.len) : (i += 2) {
        out[i / 2] = try std.fmt.parseInt(u8, hex[i .. i + 2], 16);
    }
    return out;
}

test "truncated integers: minimal length, minimal encoding, round-trip" {
    const t = std.testing;
    // BOLT#1 truncated integers drop leading zero bytes; zero encodes empty.
    try t.expectEqual(@as(usize, 0), truncatedLen(u64, 0));
    try t.expectEqual(@as(usize, 1), truncatedLen(u64, 0xff));
    try t.expectEqual(@as(usize, 2), truncatedLen(u64, 0x0100));
    try t.expectEqual(@as(usize, 8), truncatedLen(u64, std.math.maxInt(u64)));

    var buf: [8]u8 = undefined;
    try t.expectEqualSlices(u8, &.{}, try encodeTruncated(u64, 0, &buf));
    try t.expectEqualSlices(u8, &.{0xff}, try encodeTruncated(u64, 0xff, &buf));
    try t.expectEqualSlices(u8, &.{ 0x01, 0x00 }, try encodeTruncated(u64, 0x0100, &buf));

    // The encoding is exactly what the decoder accepts, at every width.
    for ([_]u64{ 0, 1, 0xff, 0x0100, 0x123456, std.math.maxInt(u64) }) |v| {
        const enc = try encodeTruncated(u64, v, &buf);
        try t.expectEqual(v, try decodeTruncated(u64, enc));
    }

    // `out` shorter than the minimal encoding is refused, not truncated.
    try t.expectError(error.BufferTooSmall, encodeTruncated(u64, 0x0100, buf[0..1]));
}

test "hexBytes self-check" {
    const allocator = testing.allocator;
    const b = try hexBytes(allocator, "fd00fd");
    defer allocator.free(b);
    try testing.expectEqualSlices(u8, &.{ 0xfd, 0x00, 0xfd }, b);
}

// -- BOLT#1 Appendix A: BigSize decoding vectors (byte-exact) --

test "BigSize decode vectors: valid" {
    const Case = struct { hex: []const u8, value: u64 };
    const cases = [_]Case{
        .{ .hex = "00", .value = 0 }, // zero
        .{ .hex = "fc", .value = 252 }, // one byte high
        .{ .hex = "fd00fd", .value = 253 }, // two byte low
        .{ .hex = "fdffff", .value = 65535 }, // two byte high
        .{ .hex = "fe00010000", .value = 65536 }, // four byte low
        .{ .hex = "feffffffff", .value = 4294967295 }, // four byte high
        .{ .hex = "ff0000000100000000", .value = 4294967296 }, // eight byte low
        .{ .hex = "ffffffffffffffffff", .value = 18446744073709551615 }, // eight byte high
    };
    const allocator = testing.allocator;
    for (cases) |c| {
        const b = try hexBytes(allocator, c.hex);
        defer allocator.free(b);
        const d = try decodeBigSize(b);
        try testing.expectEqual(c.value, d.value);
        try testing.expectEqual(b.len, d.consumed);
        // Round-trip: minimal re-encode matches the vector bytes exactly.
        var tmp: [9]u8 = undefined;
        const enc = try encodeBigSize(c.value, &tmp);
        try testing.expectEqualSlices(u8, b, enc);
    }
}

test "BigSize decode vectors: non-canonical (NonMinimal)" {
    const allocator = testing.allocator;
    const hexes = [_][]const u8{
        "fd00fc", // two byte not canonical
        "fe0000ffff", // four byte not canonical
        "ff00000000ffffffff", // eight byte not canonical
    };
    for (hexes) |h| {
        const b = try hexBytes(allocator, h);
        defer allocator.free(b);
        try testing.expectError(error.NonMinimal, decodeBigSize(b));
    }
}

test "BigSize decode vectors: short/no read (Truncated)" {
    const allocator = testing.allocator;
    const hexes = [_][]const u8{
        "fd00", // two byte short read
        "feffff", // four byte short read
        "ffffffffff", // eight byte short read
        "", // one byte no read
        "fd", // two byte no read
        "fe", // four byte no read
        "ff", // eight byte no read
    };
    for (hexes) |h| {
        const b = try hexBytes(allocator, h);
        defer allocator.free(b);
        try testing.expectError(error.Truncated, decodeBigSize(b));
    }
}

// -- BOLT#1 Appendix A: BigSize encoding vectors (byte-exact) --

test "BigSize encode vectors" {
    const Case = struct { value: u64, hex: []const u8 };
    const cases = [_]Case{
        .{ .value = 0, .hex = "00" },
        .{ .value = 252, .hex = "fc" },
        .{ .value = 253, .hex = "fd00fd" },
        .{ .value = 65535, .hex = "fdffff" },
        .{ .value = 65536, .hex = "fe00010000" },
        .{ .value = 4294967295, .hex = "feffffffff" },
        .{ .value = 4294967296, .hex = "ff0000000100000000" },
        .{ .value = 18446744073709551615, .hex = "ffffffffffffffffff" },
    };
    const allocator = testing.allocator;
    for (cases) |c| {
        var tmp: [9]u8 = undefined;
        const enc = try encodeBigSize(c.value, &tmp);
        const want = try hexBytes(allocator, c.hex);
        defer allocator.free(want);
        try testing.expectEqualSlices(u8, want, enc);
    }
}

// -- BOLT#1 Appendix B: TLV test vectors --
//
// The `n1`/`n2` namespaces are the spec's own teaching example (not real
// Lightning message types); `n1KnownTypes`/`n1Decode` below is a small
// typed layer over `parseStream`, built ONLY to exercise these vectors --
// it mirrors exactly what a real per-message typed-extension decoder
// (BOLT#2/BOLT#7's `known_tlv_types`, see `message.zig`) would do, one
// level up from the generic stream parser this file ships as public API.

const n1_known_types = [_]u64{ 1, 2, 3, 254 };
const n2_known_types = [_]u64{ 0, 11 };

/// Type-specific validation for `n1`'s 4 defined TLV types, applied to
/// `parseStream`'s (already ordering/minimality/truncation-checked) raw
/// records. Mirrors BOLT#1 Appendix B's per-type "encoding length" and
/// "valid point" requirements.
fn n1Validate(records: []const RawRecord) !void {
    for (records) |r| {
        switch (r.type) {
            1 => _ = try decodeTruncated(u64, r.value), // tlv1.amount_msat: tu64
            2 => if (r.value.len != 8) return error.BadLength, // tlv2.scid: short_channel_id
            3 => { // tlv3: point(33) + u64 + u64 = 49
                if (r.value.len != 49) return error.BadLength;
                if (r.value[0] != 0x02 and r.value[0] != 0x03) return error.InvalidPoint;
            },
            254 => if (r.value.len != 2) return error.BadLength, // tlv4.cltv_delta: u16
            else => {},
        }
    }
}

fn n1Decode(allocator: Allocator, bytes: []const u8) !void {
    var parsed = try parseStream(allocator, bytes, &n1_known_types);
    defer parsed.deinit(allocator);
    try n1Validate(parsed.records);
}

fn n2Decode(allocator: Allocator, bytes: []const u8) !void {
    var parsed = try parseStream(allocator, bytes, &n2_known_types);
    defer parsed.deinit(allocator);
}

test "TLV Appendix B: decoding failures (either namespace)" {
    const allocator = testing.allocator;
    const hexes = [_][]const u8{
        "fd", // type truncated
        "fd01", // type truncated
        "fd0101", // missing length
        "0ffd", // length truncated
        "0ffd26", // length truncated
        "0ffd2602", // missing value
    };
    for (hexes) |h| {
        const b = try hexBytes(allocator, h);
        defer allocator.free(b);
        try testing.expectError(error.Truncated, n1Decode(allocator, b));
    }
    // not minimally encoded type / length
    {
        const b = try hexBytes(allocator, "fd000100");
        defer allocator.free(b);
        try testing.expectError(error.NonMinimal, n1Decode(allocator, b));
    }
    {
        const b = try hexBytes(allocator, "0ffd000100");
        defer allocator.free(b);
        try testing.expectError(error.NonMinimal, n1Decode(allocator, b));
    }
    // value truncated: length=0x0201=513 but far fewer value bytes follow.
    {
        const b = try hexBytes(allocator, "0ffd0201" ++ "00" ** 258);
        defer allocator.free(b);
        try testing.expectError(error.Truncated, n1Decode(allocator, b));
    }
    // unknown even type, in both namespaces
    const even_hexes = [_][]const u8{ "1200", "fd010200", "fe0100000200", "ff010000000000000200" };
    for (even_hexes) |h| {
        const b = try hexBytes(allocator, h);
        defer allocator.free(b);
        try testing.expectError(error.UnknownEvenType, n1Decode(allocator, b));
        try testing.expectError(error.UnknownEvenType, n2Decode(allocator, b));
    }
}

test "TLV Appendix B: decoding failures (n1 namespace)" {
    const allocator = testing.allocator;
    const Case = struct { hex: []const u8, err: anyerror };
    const cases = [_]Case{
        .{ .hex = "0109ffffffffffffffffff", .err = error.TooLong }, // tlv1: greater than encoding length
        .{ .hex = "010100", .err = error.NonMinimal },
        .{ .hex = "01020001", .err = error.NonMinimal },
        .{ .hex = "0103000100", .err = error.NonMinimal },
        .{ .hex = "010400010000", .err = error.NonMinimal },
        .{ .hex = "01050001000000", .err = error.NonMinimal },
        .{ .hex = "0106000100000000", .err = error.NonMinimal },
        .{ .hex = "010700010000000000", .err = error.NonMinimal },
        .{ .hex = "01080001000000000000", .err = error.NonMinimal },
        .{ .hex = "020701010101010101", .err = error.BadLength }, // tlv2: less than
        .{ .hex = "0209010101010101010101", .err = error.BadLength }, // tlv2: greater than
        .{ .hex = "0321023da092f6980e58d2c037173180e9a465476026ee50f96695963e8efe436f54eb", .err = error.BadLength },
        .{ .hex = "0329023da092f6980e58d2c037173180e9a465476026ee50f96695963e8efe436f54eb0000000000000001", .err = error.BadLength },
        .{ .hex = "0330023da092f6980e58d2c037173180e9a465476026ee50f96695963e8efe436f54eb000000000000000100000000000001", .err = error.BadLength },
        .{ .hex = "0331043da092f6980e58d2c037173180e9a465476026ee50f96695963e8efe436f54eb00000000000000010000000000000002", .err = error.InvalidPoint },
        .{ .hex = "0332023da092f6980e58d2c037173180e9a465476026ee50f96695963e8efe436f54eb0000000000000001000000000000000001", .err = error.BadLength },
        .{ .hex = "fd00fe00", .err = error.BadLength }, // tlv4: less than
        .{ .hex = "fd00fe0101", .err = error.BadLength },
        .{ .hex = "fd00fe03010101", .err = error.BadLength }, // tlv4: greater than
        .{ .hex = "0000", .err = error.UnknownEvenType }, // unknown even field for n1
    };
    for (cases) |c| {
        const b = try hexBytes(allocator, c.hex);
        defer allocator.free(b);
        try testing.expectError(c.err, n1Decode(allocator, b));
    }
}

test "TLV Appendix B: decoding successes, ignored (either namespace)" {
    const allocator = testing.allocator;
    const hexes = [_][]const u8{
        "", // empty message
        "2100", // unknown odd type
        "fd020100",
        "fd00fd00",
        "fd00ff00",
        "fe0200000100",
        "ff020000000000000100",
    };
    for (hexes) |h| {
        const b = try hexBytes(allocator, h);
        defer allocator.free(b);
        try n1Decode(allocator, b);
        try n2Decode(allocator, b);
    }
}

test "TLV Appendix B: decoding successes with values (n1 namespace)" {
    const allocator = testing.allocator;

    const U64Case = struct { hex: []const u8, value: u64 };
    const tlv1_cases = [_]U64Case{
        .{ .hex = "0100", .value = 0 },
        .{ .hex = "010101", .value = 1 },
        .{ .hex = "01020100", .value = 256 },
        .{ .hex = "0103010000", .value = 65536 },
        .{ .hex = "010401000000", .value = 16777216 },
        .{ .hex = "01050100000000", .value = 4294967296 },
        .{ .hex = "0106010000000000", .value = 1099511627776 },
        .{ .hex = "010701000000000000", .value = 281474976710656 },
        .{ .hex = "01080100000000000000", .value = 72057594037927936 },
    };
    for (tlv1_cases) |c| {
        const b = try hexBytes(allocator, c.hex);
        defer allocator.free(b);
        var parsed = try parseStream(allocator, b, &n1_known_types);
        defer parsed.deinit(allocator);
        try testing.expectEqual(@as(usize, 1), parsed.records.len);
        try testing.expectEqual(@as(u64, 1), parsed.records[0].type);
        try testing.expectEqual(c.value, try decodeTruncated(u64, parsed.records[0].value));
    }

    // tlv2: scid = 0x0550
    {
        const b = try hexBytes(allocator, "02080000000000000226");
        defer allocator.free(b);
        var parsed = try parseStream(allocator, b, &n1_known_types);
        defer parsed.deinit(allocator);
        try testing.expectEqual(@as(usize, 1), parsed.records.len);
        try testing.expectEqual(@as(u64, 0x226), std.mem.readInt(u64, parsed.records[0].value[0..8], .big));
    }

    // tlv3: node_id + amount_msat_1=1 + amount_msat_2=2
    {
        const b = try hexBytes(allocator, "0331023da092f6980e58d2c037173180e9a465476026ee50f96695963e8efe436f54eb00000000000000010000000000000002");
        defer allocator.free(b);
        var parsed = try parseStream(allocator, b, &n1_known_types);
        defer parsed.deinit(allocator);
        try testing.expectEqual(@as(usize, 1), parsed.records.len);
        const v = parsed.records[0].value;
        try testing.expectEqual(@as(usize, 49), v.len);
        try testing.expectEqual(@as(u64, 1), std.mem.readInt(u64, v[33..41], .big));
        try testing.expectEqual(@as(u64, 2), std.mem.readInt(u64, v[41..49], .big));
    }

    // tlv4: cltv_delta = 550
    {
        const b = try hexBytes(allocator, "fd00fe020226");
        defer allocator.free(b);
        var parsed = try parseStream(allocator, b, &n1_known_types);
        defer parsed.deinit(allocator);
        try testing.expectEqual(@as(usize, 1), parsed.records.len);
        try testing.expectEqual(@as(u64, 254), parsed.records[0].type);
        try testing.expectEqual(@as(u16, 550), std.mem.readInt(u16, parsed.records[0].value[0..2], .big));
    }
}

test "TLV Appendix B: stream-level ordering/duplicate failures" {
    const allocator = testing.allocator;
    const Case = struct { hex: []const u8, err: anyerror, ns: enum { n1, n2 } };
    const cases = [_]Case{
        .{ .hex = "0208000000000000022601012a", .err = error.NotStrictlyIncreasing, .ns = .n1 },
        .{ .hex = "0208000000000000023102080000000000000451", .err = error.NotStrictlyIncreasing, .ns = .n1 },
        .{ .hex = "1f000f012a", .err = error.NotStrictlyIncreasing, .ns = .n1 },
        .{ .hex = "1f001f012a", .err = error.NotStrictlyIncreasing, .ns = .n1 },
        .{ .hex = "ffffffffffffffffff000000", .err = error.NotStrictlyIncreasing, .ns = .n2 },
    };
    for (cases) |c| {
        const b = try hexBytes(allocator, c.hex);
        defer allocator.free(b);
        switch (c.ns) {
            .n1 => try testing.expectError(c.err, n1Decode(allocator, b)),
            .n2 => try testing.expectError(c.err, n2Decode(allocator, b)),
        }
    }
}

test "TLV stream: round-trip encode matches decode" {
    const allocator = testing.allocator;
    const records = [_]RawRecord{
        .{ .type = 1, .value = &.{0x2a} },
        .{ .type = 3, .value = &.{ 0x01, 0x02, 0x03 } },
        .{ .type = 254, .value = &.{} },
    };
    var buf: std.ArrayList(u8) = .empty;
    defer buf.deinit(allocator);
    try appendStream(&buf, allocator, &records);

    var parsed = try parseStream(allocator, buf.items, &.{ 1, 3, 254 });
    defer parsed.deinit(allocator);
    try testing.expectEqual(@as(usize, 3), parsed.records.len);
    for (records, parsed.records) |want, got| {
        try testing.expectEqual(want.type, got.type);
        try testing.expectEqualSlices(u8, want.value, got.value);
    }
}

test "hostile: TLV length claiming more bytes than remain fails closed (no OOM)" {
    const allocator = testing.allocator;
    // type=1, length=0xff (bigsize single-byte can't reach 0xff directly;
    // use 0xfd0100 = 256) but only 3 bytes of value follow.
    const b = try hexBytes(allocator, "01fd0100" ++ "aabbcc");
    defer allocator.free(b);
    try testing.expectError(error.Truncated, parseStream(allocator, b, &.{1}));
}

test "hostile: truncated integer wider than the target type is rejected" {
    try testing.expectError(error.TooLong, decodeTruncated(u16, &.{ 1, 2, 3 }));
    try testing.expectError(error.TooLong, decodeTruncated(u32, &.{ 1, 2, 3, 4, 5 }));
}

// ── fuzz: parseStream never panics on arbitrary attacker-supplied bytes ────
//
// `parseStream` is the generic decoder underneath EVERY BOLT#1/#2/#7
// message's trailing `tlv_stream` (see `message.zig`'s `decodeExtension`)
// -- an adversarial peer controls these bytes end to end. It is also the
// richest state machine in this module: nested BigSize type/length reads,
// a strictly-increasing-type check, and an even/odd-unknown-type branch,
// all before the generic ordering/truncation checks even apply. Plain
// uniform bytes would almost always die on the very first BigSize's
// multi-byte-prefix truncation check, so the `Smith` is biased to spend
// most of its budget constructing a run of syntactically well-formed
// `(type, length, value)` records (small single-byte BigSize forms,
// mostly-in-bounds lengths) with only occasional fully-random bytes
// spliced in -- this is what actually drives the parser past the first
// record and into the ordering/known-type logic the hostile-input tests
// above target by hand.
test "fuzz: parseStream never panics on arbitrary bytes" {
    try testing.fuzz({}, fuzzParseStream, .{});
}

fn fuzzParseStream(_: void, smith: *std.testing.Smith) !void {
    const allocator = testing.allocator;
    var buf: std.ArrayList(u8) = .empty;
    defer buf.deinit(allocator);

    const n_records = smith.valueRangeAtMost(u8, 0, 12);
    var i: u8 = 0;
    while (i < n_records) : (i += 1) {
        // Bias the type/length BigSize prefixes toward small single-byte
        // forms (0..0xfc) most of the time -- the multi-byte 0xfd/0xfe/0xff
        // forms are already exhaustively covered by `decodeBigSize`'s own
        // vector tests; occasionally emit a raw random byte instead so the
        // 0xfd/0xfe/0xff truncation/non-minimal paths still get exercised.
        const t: u8 = if (smith.value(bool)) smith.valueRangeAtMost(u8, 0, 0xfc) else smith.value(u8);
        buf.append(allocator, t) catch return;
        const len: u8 = if (smith.value(bool)) smith.valueRangeAtMost(u8, 0, 16) else smith.value(u8);
        buf.append(allocator, len) catch return;
        var vbuf: [16]u8 = undefined;
        smith.bytes(&vbuf);
        buf.appendSlice(allocator, vbuf[0..@min(len, vbuf.len)]) catch return;
    }
    // Splice in a tail of fully-random bytes too, unconstrained by the
    // record-shaped loop above -- catches anything the biased construction
    // above structurally can't produce.
    var tail: [32]u8 = undefined;
    smith.bytes(&tail);
    const tail_len: usize = smith.valueRangeAtMost(u8, 0, tail.len);
    buf.appendSlice(allocator, tail[0..tail_len]) catch return;

    const known_types = [_]u64{ 0, 1, 2, 3, 254 };
    var parsed = parseStream(allocator, buf.items, &known_types) catch return;
    defer parsed.deinit(allocator);
}
