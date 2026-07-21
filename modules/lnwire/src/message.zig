// SPDX-License-Identifier: MIT
//! Shared wire-level plumbing for BOLT#1/#2/#7 messages: a bounds-checked
//! big-endian byte reader/writer, the BOLT#1 "Fundamental Types" aliases,
//! the 2-byte message-type frame, and `Extension` — the per-message
//! trailing `tlv_stream`, decoded via `tlv.parseStream`.
//!
//! ## Ownership model
//!
//! Every `decode` function in `bolt1.zig`/`bolt2.zig`/`bolt7.zig` borrows
//! variable-length fields (`scriptpubkey`, `reason`, `features`, TLV
//! record values, ...) directly from the caller's input buffer — never
//! copied. The input buffer must outlive the decoded message. The only
//! heap allocation a decode performs is `Extension.records` (the parsed
//! TLV-record array itself, not the value bytes each record borrows);
//! `deinit` frees exactly that.
//!
//! ## Hostile-input handling
//!
//! Every decode path returns a typed error, never panics, on truncated or
//! adversarial bytes: a fixed-length field or a `u16`-length-prefixed
//! field whose declared length exceeds the bytes remaining fails closed
//! with `error.Truncated` before any read past the buffer, and the
//! trailing extension is `tlv.parseStream`, whose own hostile-input
//! handling is documented in `tlv.zig`.

const std = @import("std");
const Allocator = std.mem.Allocator;
pub const tlv = @import("tlv.zig");

// ── BOLT#1 "Fundamental Types" ──────────────────────────────────────────

pub const ChainHash = [32]u8;
pub const ChannelId = [32]u8;
pub const Sha256 = [32]u8;
/// A 64-byte bitcoin ECDSA signature (raw r||s, not DER -- BOLT#1's
/// `signature` type). Opaque bytes: no signature-validity check anywhere
/// in this module (caller's secp256k1, see module doc comment / SPEC.md).
pub const Signature = [64]u8;
/// A 33-byte SEC1-compressed elliptic-curve point (BOLT#1's `point`
/// type). Opaque bytes: no curve-membership check (that needs
/// secp256k1, out of scope here -- see SPEC.md).
pub const Point = [33]u8;
/// BOLT#7 "Definition of `short_channel_id`": `blockheight (3 bytes) ||
/// tx_index (3 bytes) || output_index (2 bytes)`, carried as a single
/// 8-byte big-endian wire value. Decomposition into its 3 sub-fields is
/// left to the caller (opaque `u64` here, matching how every other
/// message field in this module treats domain-specific bit-packing).
pub const ShortChannelId = u64;

// ── byte reader/writer ──────────────────────────────────────────────────

pub const ReadError = error{Truncated};

pub const Reader = struct {
    bytes: []const u8,
    pos: usize = 0,

    pub fn remaining(self: Reader) usize {
        return self.bytes.len - self.pos;
    }

    /// Every remaining byte -- the caller's cue that "the rest is the
    /// trailing extension" (see `decodeExtension`).
    pub fn rest(self: Reader) []const u8 {
        return self.bytes[self.pos..];
    }

    /// A borrowed slice of the next `n` bytes (see module doc comment).
    pub fn takeBytes(self: *Reader, n: u64) ReadError![]const u8 {
        const rem: u64 = self.bytes.len - self.pos;
        if (n > rem) return error.Truncated;
        const nu: usize = @intCast(n);
        const s = self.bytes[self.pos..][0..nu];
        self.pos += nu;
        return s;
    }

    pub fn takeArray(self: *Reader, comptime n: usize) ReadError![n]u8 {
        const s = try self.takeBytes(n);
        var out: [n]u8 = undefined;
        @memcpy(&out, s);
        return out;
    }

    pub fn byte(self: *Reader) ReadError!u8 {
        return (try self.takeBytes(1))[0];
    }

    pub fn u16be(self: *Reader) ReadError!u16 {
        const s = try self.takeBytes(2);
        return std.mem.readInt(u16, s[0..2], .big);
    }

    pub fn u32be(self: *Reader) ReadError!u32 {
        const s = try self.takeBytes(4);
        return std.mem.readInt(u32, s[0..4], .big);
    }

    pub fn u64be(self: *Reader) ReadError!u64 {
        const s = try self.takeBytes(8);
        return std.mem.readInt(u64, s[0..8], .big);
    }

    /// A `u16`-length-prefixed borrowed byte slice (BOLT#2's `len` +
    /// `len*byte` idiom, e.g. `shutdown`'s `scriptpubkey`).
    pub fn bytesU16(self: *Reader) ReadError![]const u8 {
        const len = try self.u16be();
        return self.takeBytes(len);
    }
};

pub const Writer = struct {
    list: std.ArrayList(u8) = .empty,

    pub fn deinit(self: *Writer, allocator: Allocator) void {
        self.list.deinit(allocator);
    }

    pub fn toOwned(self: *Writer, allocator: Allocator) Allocator.Error![]u8 {
        return self.list.toOwnedSlice(allocator);
    }

    pub fn putU8(self: *Writer, allocator: Allocator, v: u8) Allocator.Error!void {
        try self.list.append(allocator, v);
    }

    pub fn putU16be(self: *Writer, allocator: Allocator, v: u16) Allocator.Error!void {
        var tmp: [2]u8 = undefined;
        std.mem.writeInt(u16, &tmp, v, .big);
        try self.list.appendSlice(allocator, &tmp);
    }

    pub fn putU32be(self: *Writer, allocator: Allocator, v: u32) Allocator.Error!void {
        var tmp: [4]u8 = undefined;
        std.mem.writeInt(u32, &tmp, v, .big);
        try self.list.appendSlice(allocator, &tmp);
    }

    pub fn putU64be(self: *Writer, allocator: Allocator, v: u64) Allocator.Error!void {
        var tmp: [8]u8 = undefined;
        std.mem.writeInt(u64, &tmp, v, .big);
        try self.list.appendSlice(allocator, &tmp);
    }

    pub fn putBytes(self: *Writer, allocator: Allocator, b: []const u8) Allocator.Error!void {
        try self.list.appendSlice(allocator, b);
    }

    pub fn putBytesU16(self: *Writer, allocator: Allocator, b: []const u8) Allocator.Error!void {
        std.debug.assert(b.len <= std.math.maxInt(u16));
        try self.putU16be(allocator, @intCast(b.len));
        try self.putBytes(allocator, b);
    }
};

// ── 2-byte message-type frame ───────────────────────────────────────────

pub const FrameError = ReadError || error{WrongType};

/// Reads the leading 2-byte big-endian `type` field, asserts it equals
/// `want` (`error.WrongType` otherwise -- e.g. an `open_channel` decoder
/// handed an `accept_channel` message), and returns a `Reader` positioned
/// at the start of the payload.
pub fn openFrame(bytes: []const u8, want: u16) FrameError!Reader {
    var r: Reader = .{ .bytes = bytes };
    const t = try r.u16be();
    if (t != want) return error.WrongType;
    return r;
}

pub fn putFrameType(w: *Writer, allocator: Allocator, msg_type: u16) Allocator.Error!void {
    try w.putU16be(allocator, msg_type);
}

// ── trailing TLV extension ──────────────────────────────────────────────

/// A message's trailing `tlv_stream` (BOLT#1's `extension` field),
/// decoded via `tlv.parseStream`. Only the *known* record types for this
/// particular message (its `known_tlv_types`, see each `bolt2.zig`/
/// `bolt7.zig` message) are returned; each record's per-type internal
/// value encoding (e.g. `channel_type`'s feature-bitmap bytes, or
/// `fee_range`'s two `u64`s) is left to the caller to interpret --
/// `Extension` hands back raw `(type, value)` pairs, already validated
/// for ordering/minimal-encoding/truncation/unknown-even-rejection.
pub const Extension = struct {
    records: []tlv.RawRecord = &.{},

    pub fn deinit(self: *Extension, allocator: Allocator) void {
        allocator.free(self.records);
        self.* = .{};
    }

    pub fn find(self: Extension, t: u64) ?[]const u8 {
        for (self.records) |r| {
            if (r.type == t) return r.value;
        }
        return null;
    }
};

pub fn decodeExtension(allocator: Allocator, bytes: []const u8, known_types: []const u64) (tlv.StreamError || Allocator.Error)!Extension {
    // Ownership of `.records` moves straight into `Extension` -- no
    // separate `ParsedStream.deinit` call (would double-free).
    const parsed = try tlv.parseStream(allocator, bytes, known_types);
    return .{ .records = parsed.records };
}

pub fn encodeExtension(w: *Writer, allocator: Allocator, ext: Extension) Allocator.Error!void {
    try tlv.appendStream(&w.list, allocator, ext.records);
}

// ── tests ────────────────────────────────────────────────────────────────

const testing = std.testing;

test "Reader: fixed-width big-endian reads" {
    const bytes = [_]u8{ 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09 };
    var r: Reader = .{ .bytes = &bytes };
    try testing.expectEqual(@as(u8, 0x01), try r.byte());
    try testing.expectEqual(@as(u16, 0x0203), try r.u16be());
    try testing.expectEqual(@as(u32, 0x04050607), try r.u32be());
    try testing.expectEqual(@as(usize, 2), r.remaining());
    try testing.expectEqualSlices(u8, &.{ 0x08, 0x09 }, r.rest());
}

test "Reader: u64be" {
    const bytes = [_]u8{ 0, 0, 0, 0, 0, 0, 0x12, 0x34 };
    var r: Reader = .{ .bytes = &bytes };
    try testing.expectEqual(@as(u64, 0x1234), try r.u64be());
}

test "hostile: Reader.takeBytes rejects truncated reads (no panic/OOB)" {
    const bytes = [_]u8{ 0x01, 0x02 };
    var r: Reader = .{ .bytes = &bytes };
    try testing.expectError(error.Truncated, r.takeBytes(3));
}

test "hostile: Reader.bytesU16 rejects a length prefix exceeding remaining bytes" {
    // len=100 but only 2 bytes actually follow.
    const bytes = [_]u8{ 0x00, 0x64, 0xaa, 0xbb };
    var r: Reader = .{ .bytes = &bytes };
    try testing.expectError(error.Truncated, r.bytesU16());
}

test "Writer/Reader round-trip: u16/u32/u64/bytesU16" {
    const allocator = testing.allocator;
    var w: Writer = .{};
    defer w.deinit(allocator);
    try w.putU16be(allocator, 0xabcd);
    try w.putU32be(allocator, 0x11223344);
    try w.putU64be(allocator, 0x1122334455667788);
    try w.putBytesU16(allocator, "hello");

    var r: Reader = .{ .bytes = w.list.items };
    try testing.expectEqual(@as(u16, 0xabcd), try r.u16be());
    try testing.expectEqual(@as(u32, 0x11223344), try r.u32be());
    try testing.expectEqual(@as(u64, 0x1122334455667788), try r.u64be());
    try testing.expectEqualSlices(u8, "hello", try r.bytesU16());
    try testing.expectEqual(@as(usize, 0), r.remaining());
}

test "openFrame: type mismatch is a typed error" {
    const bytes = [_]u8{ 0x00, 0x20 }; // type 32
    try testing.expectError(error.WrongType, openFrame(&bytes, 33));
    var r = try openFrame(&bytes, 32);
    try testing.expectEqual(@as(usize, 0), r.remaining());
}

test "hostile: openFrame on a 1-byte (sub-type-field) message fails closed" {
    const bytes = [_]u8{0x00};
    try testing.expectError(error.Truncated, openFrame(&bytes, 32));
}

test "Extension: decode/encode round-trip, unknown-odd discarded, unknown-even rejected" {
    const allocator = testing.allocator;
    const records = [_]tlv.RawRecord{
        .{ .type = 0, .value = &.{0xaa} },
        .{ .type = 1, .value = &.{ 0xbb, 0xcc } },
    };
    var buf: std.ArrayList(u8) = .empty;
    defer buf.deinit(allocator);
    try tlv.appendStream(&buf, allocator, &records);
    // append an unknown-odd record too -- must round-trip-decode to
    // exactly the 2 known records (discarded, not stored).
    try tlv.appendStream(&buf, allocator, &.{.{ .type = 101, .value = "ignored" }});

    var ext = try decodeExtension(allocator, buf.items, &.{ 0, 1 });
    defer ext.deinit(allocator);
    try testing.expectEqual(@as(usize, 2), ext.records.len);
    try testing.expectEqualSlices(u8, &.{0xaa}, ext.find(0).?);
    try testing.expectEqualSlices(u8, &.{ 0xbb, 0xcc }, ext.find(1).?);
    try testing.expect(ext.find(2) == null);

    var w: Writer = .{};
    defer w.deinit(allocator);
    try encodeExtension(&w, allocator, ext);
    // Re-encoding the *decoded* (known-only) extension drops the
    // unknown-odd record -- that's correct BOLT#1 behavior, not lossy
    // round-trip breakage: an unknown-odd record is defined to be
    // discardable.
    var reparsed = try tlv.parseStream(allocator, w.list.items, &.{ 0, 1 });
    defer reparsed.deinit(allocator);
    try testing.expectEqual(@as(usize, 2), reparsed.records.len);
}

test "hostile: an unknown even TLV type in the extension fails closed" {
    const allocator = testing.allocator;
    var buf: std.ArrayList(u8) = .empty;
    defer buf.deinit(allocator);
    try tlv.appendStream(&buf, allocator, &.{.{ .type = 2, .value = &.{} }}); // even, unknown
    try testing.expectError(error.UnknownEvenType, decodeExtension(allocator, buf.items, &.{0}));
}
