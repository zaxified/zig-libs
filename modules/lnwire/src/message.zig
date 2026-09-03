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

    /// Write `b` prefixed by its `u16` big-endian length.
    ///
    /// ⚠ The bound was a `std.debug.assert` followed by an unchecked
    /// `@intCast`, which in ReleaseFast is no bound at all: the prefix became
    /// `b.len mod 65536` while the whole of `b` was still appended, so the
    /// bytes past the field landed where the peer parses whatever comes next
    /// (for `reply_channel_range`, the trailing `tlv_stream`). And the length
    /// that overflows is not ours to choose — `encoded_short_ids` is 8 bytes
    /// per channel over a **block range the remote peer asked for**, so 8,192
    /// channels is already one byte past the field. Measured, same source and
    /// input: Debug and ReleaseSafe abort (rc=134); ReleaseFast is undefined
    /// and did NOT present the same way twice (an `OutOfMemory` here, a frame
    /// with `declared len=1` and 65,536 bytes past the field elsewhere).
    pub fn putBytesU16(self: *Writer, allocator: Allocator, b: []const u8) WriteError!void {
        if (b.len > std.math.maxInt(u16)) return error.FieldTooLong;
        try self.putU16be(allocator, @intCast(b.len));
        try self.putBytes(allocator, b);
    }
};

// ── 2-byte message-type frame ───────────────────────────────────────────

/// A value handed to the encoder does not fit the wire field that must carry
/// it. Separate from `Allocator.Error` because it is a caller/peer-input
/// problem, not a host one — and it is an ERROR rather than an assert because
/// asserts are compiled out of the ReleaseFast lane this collection ships.
pub const WriteError = Allocator.Error || error{FieldTooLong};

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

// ── fuzz: the shared reader chain every message decode runs through ───────
//
// `openFrame` (the 2-byte type frame) and `decodeExtension` (the trailing
// `tlv_stream`, `tlv.zig`'s own fuzz harness covers `parseStream` itself in
// depth) are the two pieces of machinery EVERY `bolt1`/`bolt2`/`bolt7`
// message decoder runs through before/after its own fixed fields -- an
// adversarial peer's raw message bytes reach both directly. `Reader`'s
// individual `takeBytes`/`bytesU16` truncation behavior is already
// covered by the hostile tests above; this harness instead drives the two
// public entry points end to end over arbitrary bytes.
test "fuzz: openFrame + decodeExtension never panic on arbitrary bytes" {
    try testing.fuzz({}, fuzzFrameAndExtension, .{});
}

fn fuzzFrameAndExtension(_: void, smith: *std.testing.Smith) !void {
    const allocator = testing.allocator;
    var buf: [512]u8 = undefined;
    smith.bytes(&buf);
    // ⚠ Written as `valueRangeAtMost(u16, 0, buf.len)` this drew ZERO on the
    // one input an ordinary `zig build test-*` run gets: outside `--fuzz` an
    // empty corpus is exactly one input, and `Smith.valueRangeAtMost` falls
    // back to the range's LOWER bound once the input is exhausted. So the
    // harness's single smoke run fed an EMPTY buffer to the decoder, which
    // bails at the first length check — while `check-fuzz` counted the module
    // covered. Subtracting instead makes the exhausted-input fallback the FULL
    // buffer, which is the interesting end of the range.
    const len: usize = buf.len - smith.valueRangeAtMost(u16, 0, @intCast(buf.len));
    const bytes = buf[0..len];

    // Bias `want` toward the type actually encoded at the front of `bytes`
    // half the time (reaches the payload-Reader path instead of always
    // bailing out on `error.WrongType`), fully random the other half.
    const want: u16 = if (bytes.len >= 2 and smith.value(bool))
        std.mem.readInt(u16, bytes[0..2], .big)
    else
        smith.value(u16);

    var r = openFrame(bytes, want) catch return;
    var ext = decodeExtension(allocator, r.rest(), &.{ 0, 1, 3, 254 }) catch return;
    defer ext.deinit(allocator);
}

test "TEETH: a field too long for its u16 prefix is REFUSED, not truncated" {
    // The bound here was a `std.debug.assert` plus an unchecked `@intCast`.
    // In ReleaseFast that is no bound: the prefix became `len mod 65536` while
    // the whole payload was still appended, so the excess landed where the peer
    // parses the next field. And the overflowing length is chosen by the REMOTE
    // PEER — `reply_channel_range` carries 8 bytes per channel over a block
    // range the peer asked for, so 8,192 channels is already one past the field.
    //
    // Measured before the fix, same source and input, three modes: Debug and
    // ReleaseSafe abort (rc=134); ReleaseFast is undefined and did not present
    // the same way twice.
    const a = std.testing.allocator;
    const too_long = try a.alloc(u8, std.math.maxInt(u16) + 1);
    defer a.free(too_long);
    @memset(too_long, 0xAB);

    var w: Writer = .{};
    defer w.deinit(a);
    try std.testing.expectError(error.FieldTooLong, w.putBytesU16(a, too_long));
    // Nothing was written, so a refused field cannot leave a half-frame behind.
    try std.testing.expectEqual(@as(usize, 0), w.list.items.len);

    // The largest length that DOES fit still writes, so the bound is not off by
    // one in the other direction.
    var w2: Writer = .{};
    defer w2.deinit(a);
    try w2.putBytesU16(a, too_long[0..std.math.maxInt(u16)]);
    try std.testing.expectEqual(@as(usize, 2 + std.math.maxInt(u16)), w2.list.items.len);
    try std.testing.expectEqual(@as(u16, std.math.maxInt(u16)), std.mem.readInt(u16, w2.list.items[0..2], .big));
}

test "TEETH: the fuzz harness's smoke run feeds a FULL buffer, not an empty one" {
    // Outside `--fuzz`, `std.testing.fuzz` with an empty corpus runs exactly
    // one input, and `Smith.valueRangeAtMost` falls back to the range's LOWER
    // bound on exhausted input. Written `valueRangeAtMost(u16, 0, buf.len)`
    // that made the one input an EMPTY buffer, which every decoder rejects at
    // its first length check — so an ordinary `zig build test-lnwire` exercised
    // nothing, while `check-fuzz` reported the module covered.
    //
    // This reads the same expression the harness uses, through a `Smith` in
    // exactly that exhausted state.
    var empty: [0]u8 = .{};
    var smith: std.testing.Smith = .{ .in = &empty };
    const buf_len: usize = 512;
    const len: usize = buf_len - smith.valueRangeAtMost(u16, 0, @intCast(buf_len));
    try std.testing.expectEqual(buf_len, len);
}
