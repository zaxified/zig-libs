// SPDX-License-Identifier: MIT

//! Call metadata — the arbitrary key/value pairs a gRPC call carries in its
//! HTTP/2 header and trailer sections.
//!
//! Two kinds, distinguished purely by the key:
//!
//!   - an ordinary key carries a **printable-ASCII** value and goes on the
//!     wire as written;
//!   - a key ending in **`-bin`** carries arbitrary binary, base64-encoded on
//!     the wire. Callers here always hand over and receive the *raw* bytes;
//!     the base64 never leaks into the API, because a caller who has to
//!     remember to encode is a caller who will one day forget.
//!
//! On receive, unpadded base64 must be accepted — the spec tells implementations
//! to emit values without padding, so that is what most peers send, and a
//! decoder that demands `=` padding fails against the majority of the network.
//! (We emit unpadded too, and accept both.)

const std = @import("std");
const Allocator = std.mem.Allocator;

/// One metadata pair. `value` is the *decoded* form in both directions:
/// literal text for an ASCII key, raw bytes for a `-bin` key.
pub const Entry = struct {
    name: []const u8,
    value: []const u8,
};

/// Whether `name` designates a binary-valued key (`-bin` suffix,
/// case-insensitive — HTTP/2 field names are lowercase on the wire, but a
/// caller may well write `X-Trace-Bin`).
pub fn isBinary(name: []const u8) bool {
    return name.len > 4 and std.ascii.endsWithIgnoreCase(name, "-bin");
}

const encoder = std.base64.standard_no_pad.Encoder;
const decoder = std.base64.standard_no_pad.Decoder;

/// Length of the wire value `encodeValue` will produce for `entry`.
pub fn encodedValueLen(entry: Entry) usize {
    return if (isBinary(entry.name)) encoder.calcSize(entry.value.len) else entry.value.len;
}

/// Render `entry`'s wire value into `out` (`out.len >= encodedValueLen`).
pub fn encodeValue(entry: Entry, out: []u8) []const u8 {
    if (!isBinary(entry.name)) {
        @memcpy(out[0..entry.value.len], entry.value);
        return out[0..entry.value.len];
    }
    return encoder.encode(out[0..encoder.calcSize(entry.value.len)], entry.value);
}

pub const DecodeError = error{ InvalidBinaryValue, OutOfMemory };

/// Decode a received wire value for `name`: identity for an ASCII key, base64
/// for a `-bin` one. Padding is tolerated in either presence or absence.
/// The result is allocated only for a binary key; for an ASCII key it aliases
/// `wire_value` — `owned` says which, so the caller knows what to free.
pub const Decoded = struct {
    bytes: []const u8,
    owned: bool,

    pub fn deinit(d: Decoded, gpa: Allocator) void {
        if (d.owned) gpa.free(@constCast(d.bytes));
    }
};

pub fn decodeValue(gpa: Allocator, name: []const u8, wire_value: []const u8) DecodeError!Decoded {
    if (!isBinary(name)) return .{ .bytes = wire_value, .owned = false };
    // Tolerate padding on receive by trimming it — the no-pad decoder is
    // strict, and both spellings are legal input per the spec.
    var trimmed = wire_value;
    while (trimmed.len != 0 and trimmed[trimmed.len - 1] == '=') trimmed.len -= 1;
    const n = decoder.calcSizeForSlice(trimmed) catch return error.InvalidBinaryValue;
    const out = try gpa.alloc(u8, n);
    errdefer gpa.free(out);
    decoder.decode(out, trimmed) catch return error.InvalidBinaryValue;
    return .{ .bytes = out, .owned = true };
}

// ── reserved names ──────────────────────────────────────────────────────────

/// Header names the call layer owns. A caller-supplied entry with one of
/// these names is rejected rather than duplicated onto the wire: a second
/// `grpc-timeout` or a forged `grpc-status` in the request section is a way
/// to confuse an intermediary, and silently letting the last one win is how
/// request smuggling happens elsewhere.
pub fn isReserved(name: []const u8) bool {
    const reserved = [_][]const u8{
        ":method",              ":scheme",     ":path",        ":authority",
        "content-type",         "te",          "grpc-timeout", "grpc-encoding",
        "grpc-accept-encoding", "grpc-status", "grpc-message", "grpc-status-details-bin",
        "user-agent",
    };
    for (reserved) |r| {
        if (std.ascii.eqlIgnoreCase(name, r)) return true;
    }
    return false;
}

// ── tests ───────────────────────────────────────────────────────────────────

const testing = std.testing;

test "metadata: -bin detection is by suffix, case-insensitively" {
    try testing.expect(isBinary("x-trace-bin"));
    try testing.expect(isBinary("X-Trace-Bin"));
    try testing.expect(!isBinary("x-trace"));
    try testing.expect(!isBinary("-bin")); // a name that is only the suffix
    try testing.expect(!isBinary("binary"));
    try testing.expect(!isBinary(""));
}

test "metadata: an ASCII value goes on the wire untouched" {
    var buf: [32]u8 = undefined;
    const e: Entry = .{ .name = "x-probe", .value = "hello" };
    try testing.expectEqual(@as(usize, 5), encodedValueLen(e));
    try testing.expectEqualStrings("hello", encodeValue(e, &buf));

    const d = try decodeValue(testing.allocator, "x-probe", "hello");
    defer d.deinit(testing.allocator);
    try testing.expect(!d.owned);
    try testing.expectEqualStrings("hello", d.bytes);
}

test "metadata: a -bin value round trips through unpadded base64" {
    const gpa = testing.allocator;
    const raw = [_]u8{ 0x00, 0xff, 0x10, 0x80, 0x7f };
    const e: Entry = .{ .name = "x-probe-bin", .value = &raw };

    var buf: [32]u8 = undefined;
    const wire = encodeValue(e, buf[0..encodedValueLen(e)]);
    try testing.expectEqualStrings("AP8QgH8", wire); // 5 bytes → 7 chars, no '='

    const d = try decodeValue(gpa, "x-probe-bin", wire);
    defer d.deinit(gpa);
    try testing.expect(d.owned);
    try testing.expectEqualSlices(u8, &raw, d.bytes);
}

test "metadata: padded base64 is accepted on receive (spec requires it)" {
    const gpa = testing.allocator;
    // Same five bytes, this time with the padding a padding-emitting peer
    // would add.
    const d = try decodeValue(gpa, "x-probe-bin", "AP8QgH8=");
    defer d.deinit(gpa);
    try testing.expectEqualSlices(u8, &.{ 0x00, 0xff, 0x10, 0x80, 0x7f }, d.bytes);

    const d2 = try decodeValue(gpa, "x-probe-bin", "AA==");
    defer d2.deinit(gpa);
    try testing.expectEqualSlices(u8, &.{0x00}, d2.bytes);
}

test "metadata: an undecodable -bin value is an error, not silent garbage" {
    const gpa = testing.allocator;
    try testing.expectError(error.InvalidBinaryValue, decodeValue(gpa, "x-bin", "!!!!"));
    try testing.expectError(error.InvalidBinaryValue, decodeValue(gpa, "x-bin", "A"));
}

test "metadata: an empty -bin value decodes to zero bytes" {
    const gpa = testing.allocator;
    const d = try decodeValue(gpa, "x-probe-bin", "");
    defer d.deinit(gpa);
    try testing.expectEqual(@as(usize, 0), d.bytes.len);
}

test "metadata: reserved names are recognised however they are spelled" {
    try testing.expect(isReserved("grpc-timeout"));
    try testing.expect(isReserved("GRPC-Status"));
    try testing.expect(isReserved("Content-Type"));
    try testing.expect(!isReserved("x-grpc-timeout"));
    try testing.expect(!isReserved("authorization"));
}
