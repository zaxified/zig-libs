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
const testkit = @import("testkit");

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
/// Framed messages paired with the type the caller asks for, in the format
/// `Smith` reads: `slice` framing for the octets, then an eight-octet word
/// that carries the `want` choice.
///
/// The tail word's low bit says "ask for the type the message actually
/// carries"; otherwise the type comes from the word itself. ⚠ It has to travel
/// in the seed: `want` used to hang on a `smith.value(bool)` drawn AFTER the
/// bytes, i.e. after the input was exhausted, so it was `false` on every
/// replay and the payload-`Reader` path the comment claims to reach half the
/// time was reached only by the coincidence that an all-zero buffer frames as
/// type 0 and `value(u16)` of an exhausted input is also 0.
const FrameCorpus = struct {
    scratch: [512]u8 = undefined,
    store: [12 * (4 + 512 + 8)]u8 = undefined,
    used: usize = 0,
    entries: [12][]const u8 = undefined,
    matches: [12]bool = undefined,
    n: usize = 0,

    fn push(self: *FrameCorpus, bytes: []const u8, match_type: bool) void {
        const head = testkit.fuzz.seedInto(self.store[self.used..], bytes);
        const word: u64 = if (match_type) 1 else 0xDEAD_0000;
        std.mem.writeInt(u64, self.store[self.used + head.len ..][0..8], word, .little);
        self.entries[self.n] = self.store[self.used..][0 .. head.len + 8];
        self.matches[self.n] = match_type;
        self.used += head.len + 8;
        self.n += 1;
    }

    /// A 2-octet type frame followed by a tlv_stream built from `records`.
    fn framed(self: *FrameCorpus, allocator: Allocator, msg_type: u16, records: []const tlv.RawRecord) ![]const u8 {
        var w: Writer = .{};
        defer w.deinit(allocator);
        try w.putU16be(allocator, msg_type);
        try encodeExtension(&w, allocator, .{ .records = @constCast(records) });
        @memcpy(self.scratch[0..w.list.items.len], w.list.items);
        return self.scratch[0..w.list.items.len];
    }

    fn build(self: *FrameCorpus, allocator: Allocator) ![]const []const u8 {
        // Every known type, in the strictly-increasing order BOLT#1 requires.
        self.push(try self.framed(allocator, 33, &.{
            .{ .type = 0, .value = &.{} },
            .{ .type = 1, .value = &.{0x08} },
            .{ .type = 3, .value = &[_]u8{0xAA} ** 32 },
            .{ .type = 254, .value = &.{ 1, 2, 3 } },
        }), true);
        // A frame with no extension at all: the whole message is its type.
        self.push(try self.framed(allocator, 16, &.{}), true);
        // One record, asked for under the WRONG type: the `WrongType` path.
        self.push(try self.framed(allocator, 16, &.{.{ .type = 1, .value = &.{0x01} }}), false);
        // An unknown ODD type in the stream, which must be tolerated and
        // discarded, and an unknown EVEN one, which must be refused.
        self.push(try self.framed(allocator, 33, &.{.{ .type = 255, .value = &.{0x01} }}), true);
        self.push(try self.framed(allocator, 33, &.{.{ .type = 100, .value = &.{0x01} }}), true);

        // ── hand-built streams no encoder will produce ──────────────────────
        // Records out of order: `NotStrictlyIncreasing`.
        self.push(&[_]u8{ 0x00, 0x21, 0x03, 0x00, 0x01, 0x00 }, true);
        // The same type twice, which is the same refusal.
        self.push(&[_]u8{ 0x00, 0x21, 0x01, 0x00, 0x01, 0x00 }, true);
        // A record length that runs past the end.
        self.push(&[_]u8{ 0x00, 0x21, 0x00, 0x7F }, true);
        // A type BigSize with no length behind it.
        self.push(&[_]u8{ 0x00, 0x21, 0x01 }, true);
        // A multi-byte BigSize truncated inside its own prefix.
        self.push(&[_]u8{ 0x00, 0x21, 0xFF, 0x01, 0x02 }, true);
        // One octet: not even a type frame.
        self.push(&[_]u8{0x00}, true);
        self.push(&.{}, true); // the empty message
        return self.entries[0..self.n];
    }
};

test "fuzz: openFrame + decodeExtension never panic on arbitrary bytes" {
    var corpus: FrameCorpus = .{};
    try testing.fuzz({}, fuzzFrameAndExtension, .{ .corpus = try corpus.build(testing.allocator) });
}

fn fuzzFrameAndExtension(_: void, smith: *std.testing.Smith) !void {
    const allocator = testing.allocator;
    var buf: [512]u8 = undefined;
    // ⚠ One `smith.slice` call. What was here before was a partial fix, and it
    // is worth naming because it looked complete: the length was written as
    // `buf.len - valueRangeAtMost(...)` precisely so the exhausted-input
    // fallback would be the FULL buffer rather than an empty one. That was
    // right, and it bought less than it appears to — `bytes` fills the tail
    // with the weight minimum, so with no corpus the ONE input this harness
    // ever ran was 512 zero octets. Measured 2026-09-07 over the corpus
    // above: **1 of 12 seeds non-empty (that all-zero buffer), 1 framed and 0
    // TLV records read before; 11 of 12 non-empty (the empty message is a
    // deliberate seed), 9 framed and 4 records after.**
    const len: usize = smith.slice(&buf);
    const bytes = buf[0..len];

    // ⚠ `value(u64)` and a bit test, not `value(bool)`: a bool drawn after the
    // bytes is `false` on every replay, so `want` was always the second
    // branch. The choice travels in the seed now — see `FrameCorpus`.
    const w = smith.value(u64);
    const want: u16 = if (bytes.len >= 2 and w & 1 != 0)
        std.mem.readInt(u16, bytes[0..2], .big)
    else
        @truncate(w >> 16);

    var r = openFrame(bytes, want) catch return;
    var ext = decodeExtension(allocator, r.rest(), &.{ 0, 1, 3, 254 }) catch return;
    defer ext.deinit(allocator);
}

test "corpus: every frame seed reaches openFrame, and the records read are pinned" {
    // ⭐ The measurement, executable rather than written in a comment, over the
    // SAME corpus the harness gets. Three numbers, because `nonempty` cannot
    // see either of the two ways this harness was blind: `matched` pins that
    // the `want` word arrived as written (without it every seed goes back to
    // one branch), and `records` is what an empty message cannot produce —
    // `framed` alone is satisfied by a message whose extension is empty, which
    // half a real corpus is.
    var corpus: FrameCorpus = .{};
    const allocator = testing.allocator;
    const entries = try corpus.build(allocator);
    var nonempty: usize = 0;
    var matched: usize = 0;
    var framed_ok: usize = 0;
    var records: usize = 0;
    for (entries, corpus.matches[0..corpus.n]) |sd, want_match| {
        var smith: std.testing.Smith = .{ .in = sd };
        var buf: [512]u8 = undefined;
        const len: usize = smith.slice(&buf);
        if (len != 0) nonempty += 1;
        const bytes = buf[0..len];
        const w = smith.value(u64);
        if ((w & 1 != 0) == want_match) matched += 1;
        const want: u16 = if (bytes.len >= 2 and w & 1 != 0)
            std.mem.readInt(u16, bytes[0..2], .big)
        else
            @truncate(w >> 16);
        var r = openFrame(bytes, want) catch continue;
        framed_ok += 1;
        var ext = decodeExtension(allocator, r.rest(), &.{ 0, 1, 3, 254 }) catch continue;
        defer ext.deinit(allocator);
        records += ext.records.len;
    }
    // One short of the corpus length: the empty message is a seed on purpose.
    try testing.expectEqual(entries.len - 1, nonempty);
    try testing.expectEqual(entries.len, matched);
    try testing.expectEqual(@as(usize, 9), framed_ok);
    // 4, all from the first seed: types 0, 1, 3 and 254. The unknown-odd seed
    // decodes and contributes none, because tolerating an odd type means
    // DISCARDING it.
    try testing.expectEqual(@as(usize, 4), records);
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
