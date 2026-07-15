// SPDX-License-Identifier: MIT
//! mls.codec — the TLS presentation-language (de)serializer MLS (RFC 9420
//! §2.1) is written in, with the ONE deviation RFC 9420 makes from plain
//! RFC 8446 §3: every `opaque foo<V>` / `Type foo<V>` VECTOR is prefixed
//! with a variable-length integer (RFC 9420 §2.1.2, borrowed from QUIC's
//! varint, RFC 9000 §16 — NOT a fixed `uint8`/`uint16`/`uint32` length
//! header the way plain TLS 1.3 vectors are). Every later MLS part
//! (KeyPackage, LeafNode, Proposal, Commit, framing, …) is built on this
//! file — `Writer`/`Reader` are the only place vector-length-encoding
//! policy lives, so getting §2.1.2 byte-exact here is load-bearing for the
//! whole arc, not just this part's own `crypto.zig`.
//!
//! Design: bounded, caller-owned buffers throughout (`Writer` wraps a
//! `[]u8` it never grows; `Reader` wraps a `[]const u8` it only slices
//! into, no copies) — every write/read is capacity-checked and returns a
//! typed error, NEVER a panic/OOB read on a short buffer or hostile
//! (attacker-controlled) input. This is the module's fuzz-safety
//! boundary: nothing downstream should need `@memcpy`/manual indexing
//! into wire bytes once a message has gone through `Reader`.
//!
//! Model: RFC 9420 §2.1 (Presentation Language) — §2.1.1 (`optional<T>`)
//! and §2.1.2 (variable-size vector length headers) specifically; RFC 9000
//! §16 for the underlying varint encoding RFC 9420 borrows (with RFC
//! 9420's own added minimum-encoding requirement, which RFC 9000 also
//! requires — both specs reject non-minimal encodings).

const std = @import("std");

pub const Error = error{
    /// A write didn't fit in the caller-supplied buffer, or a read ran
    /// past the end of the caller-supplied buffer — the ONLY failure mode
    /// for malformed/truncated/hostile input; this module never panics on
    /// out-of-range access.
    BufferTooShort,
    /// A varint's two-MSB prefix was `11` (RFC 9420 §2.1.2: "Vectors that
    /// start with the prefix '11' are invalid and MUST be rejected").
    InvalidVarint,
    /// A varint used more bytes than the minimal encoding for its value
    /// (RFC 9420 §2.1.2: "the encoded value MUST use the smallest number
    /// of bits required... values using more bits than necessary MUST be
    /// treated as malformed").
    NonMinimalVarint,
    /// A length exceeds the varint format's 30-bit ceiling
    /// (`varint.max_value`, 2^30 - 1) — RFC 9420 §2.1.2: "vectors to grow
    /// very large, up to 2^30 bytes".
    VarintTooLarge,
    /// `Writer.writeVector`/`writeVectorConcat`: the byte length to encode
    /// exceeds `varint.max_value` — same ceiling as `VarintTooLarge`, named
    /// separately because it's an ENCODE-side caller error (an oversized
    /// `[]const u8` the caller handed in), not a malformed-input DECODE
    /// finding.
    VectorTooLong,
    /// A structurally-invalid but bounds-safe decode: an `optional<T>`
    /// presence octet that isn't 0 or 1 (RFC 9420 §2.1.1: "a presence
    /// octet with a value other than 0 or 1 MUST be rejected as
    /// malformed").
    Malformed,
};

// ── §2.1.2: variable-length integer (QUIC-style, RFC 9000 §16) ──────────

pub const varint = struct {
    /// The largest value the 4-byte (30-usable-bit) encoding can carry —
    /// RFC 9420 §2.1.2's Table 1 "Max" column for the `10` prefix.
    pub const max_value: u64 = (1 << 30) - 1;

    /// The number of bytes `encode` will use for `value`, or
    /// `error.VarintTooLarge` if `value` doesn't fit the format at all.
    pub fn encodedLen(value: u64) Error!usize {
        if (value <= 63) return 1;
        if (value <= 16383) return 2;
        if (value <= max_value) return 4;
        return error.VarintTooLarge;
    }

    /// Encodes `value` into `out` using the SMALLEST of the three
    /// prefixes (`00`/1-byte, `01`/2-byte, `10`/4-byte) that can hold it —
    /// RFC 9420 §2.1.2's own minimal-encoding requirement applies to the
    /// ENCODER too: this function can never itself produce a
    /// non-minimally-encoded varint. Returns the prefix of `out` written.
    pub fn encode(value: u64, out: []u8) Error![]u8 {
        if (value <= 63) {
            if (out.len < 1) return error.BufferTooShort;
            out[0] = @intCast(value);
            return out[0..1];
        } else if (value <= 16383) {
            if (out.len < 2) return error.BufferTooShort;
            const v: u16 = @intCast(value);
            out[0] = 0x40 | @as(u8, @intCast(v >> 8));
            out[1] = @as(u8, @intCast(v & 0xff));
            return out[0..2];
        } else if (value <= max_value) {
            if (out.len < 4) return error.BufferTooShort;
            const v: u32 = @intCast(value);
            out[0] = 0x80 | @as(u8, @intCast((v >> 24) & 0x3f));
            out[1] = @as(u8, @intCast((v >> 16) & 0xff));
            out[2] = @as(u8, @intCast((v >> 8) & 0xff));
            out[3] = @as(u8, @intCast(v & 0xff));
            return out[0..4];
        }
        return error.VarintTooLarge;
    }

    pub const Decoded = struct { value: u64, len: usize };

    /// Decodes ONE varint from the front of `buf`. Rejects the `11`
    /// prefix (`error.InvalidVarint`), a truncated encoding
    /// (`error.BufferTooShort`), and a non-minimal encoding
    /// (`error.NonMinimalVarint`) — the exact three failure modes RFC
    /// 9420 §2.1.2's `ReadVarint` pseudocode names. Never reads past
    /// `buf.len`.
    pub fn decode(buf: []const u8) Error!Decoded {
        if (buf.len < 1) return error.BufferTooShort;
        const prefix = buf[0] >> 6;
        if (prefix == 3) return error.InvalidVarint;
        const length: usize = @as(usize, 1) << @intCast(prefix);
        if (buf.len < length) return error.BufferTooShort;
        var v: u64 = buf[0] & 0x3f;
        var i: usize = 1;
        while (i < length) : (i += 1) v = (v << 8) | buf[i];
        if (prefix >= 1) {
            const half_bits: u6 = @intCast(8 * (length / 2) - 2);
            const threshold: u64 = @as(u64, 1) << half_bits;
            if (v < threshold) return error.NonMinimalVarint;
        }
        return .{ .value = v, .len = length };
    }
};

// ── Writer: bounded, caller-owned output buffer ──────────────────────────

pub const Writer = struct {
    buf: []u8,
    pos: usize = 0,

    pub fn init(buf: []u8) Writer {
        return .{ .buf = buf, .pos = 0 };
    }

    fn ensure(self: *const Writer, n: usize) Error!void {
        if (self.pos + n > self.buf.len) return error.BufferTooShort;
    }

    /// Fixed-width big-endian integers (RFC 8446 §3's `uintN`, unchanged
    /// by RFC 9420 — only VECTOR lengths get the varint treatment, plain
    /// scalar fields like `KDFLabel.length` stay fixed-width).
    pub fn writeU8(self: *Writer, v: u8) Error!void {
        try self.ensure(1);
        self.buf[self.pos] = v;
        self.pos += 1;
    }

    pub fn writeU16(self: *Writer, v: u16) Error!void {
        try self.ensure(2);
        std.mem.writeInt(u16, self.buf[self.pos..][0..2], v, .big);
        self.pos += 2;
    }

    pub fn writeU32(self: *Writer, v: u32) Error!void {
        try self.ensure(4);
        std.mem.writeInt(u32, self.buf[self.pos..][0..4], v, .big);
        self.pos += 4;
    }

    pub fn writeU64(self: *Writer, v: u64) Error!void {
        try self.ensure(8);
        std.mem.writeInt(u64, self.buf[self.pos..][0..8], v, .big);
        self.pos += 8;
    }

    /// Raw bytes, no length prefix — for a FIXED-size field (a hash
    /// digest, an already-length-known key) where the length lives in the
    /// schema, not the wire.
    pub fn writeBytes(self: *Writer, bytes: []const u8) Error!void {
        try self.ensure(bytes.len);
        @memcpy(self.buf[self.pos..][0..bytes.len], bytes);
        self.pos += bytes.len;
    }

    /// The bare varint itself (§2.1.2) — used both as a vector's length
    /// prefix (`writeVector`/`writeVectorConcat`) and directly for the
    /// (rare) case a later part needs a standalone variable-length
    /// integer field.
    pub fn writeVarint(self: *Writer, value: u64) Error!void {
        var tmp: [4]u8 = undefined;
        const enc = try varint.encode(value, &tmp);
        try self.writeBytes(enc);
    }

    /// `opaque foo<V>` / `T foo<V>` — a varint length prefix followed by
    /// the raw bytes.
    pub fn writeVector(self: *Writer, bytes: []const u8) Error!void {
        if (bytes.len > varint.max_value) return error.VectorTooLong;
        try self.writeVarint(bytes.len);
        try self.writeBytes(bytes);
    }

    /// A `<V>` vector assembled from several already-split slices without
    /// requiring the caller to concatenate them first — e.g. `crypto.zig`'s
    /// `"MLS 1.0 " ++ Label` (RFC 9420 §5.1.2/§8's `KDFLabel.label`/
    /// `SignContent.label`/`EncryptContext.label` are all ONE vector whose
    /// length is `len("MLS 1.0 ") + len(Label)`, not two nested vectors).
    pub fn writeVectorConcat(self: *Writer, parts: []const []const u8) Error!void {
        var total: usize = 0;
        for (parts) |p| total += p.len;
        if (total > varint.max_value) return error.VectorTooLong;
        try self.writeVarint(total);
        for (parts) |p| try self.writeBytes(p);
    }

    /// `optional<T>`'s presence octet (§2.1.1) alone — `writeOptional`
    /// below composes this with a value-writer for the common case.
    pub fn writePresence(self: *Writer, present: bool) Error!void {
        try self.writeU8(if (present) 1 else 0);
    }

    /// `optional<T>` (§2.1.1): presence octet, then `writeFn(self, v)` iff
    /// present.
    pub fn writeOptional(self: *Writer, comptime T: type, value: ?T, comptime writeFn: fn (*Writer, T) Error!void) Error!void {
        try self.writePresence(value != null);
        if (value) |v| try writeFn(self, v);
    }

    /// An enum field, encoded as its underlying integer tag at the tag's
    /// own bit width (MLS enums are always `uint8`/`uint16`/`uint32`-typed
    /// per their RFC 9420 definitions — never varint-encoded; only VECTOR
    /// lengths use §2.1.2).
    pub fn writeEnum(self: *Writer, comptime E: type, value: E) Error!void {
        const tag_bits = @bitSizeOf(@typeInfo(E).@"enum".tag_type);
        switch (tag_bits) {
            8 => try self.writeU8(@intFromEnum(value)),
            16 => try self.writeU16(@intFromEnum(value)),
            32 => try self.writeU32(@intFromEnum(value)),
            else => @compileError("mls.codec.writeEnum: unsupported enum tag width (need u8/u16/u32)"),
        }
    }

    /// The written prefix of `buf` so far.
    pub fn finish(self: *const Writer) []u8 {
        return self.buf[0..self.pos];
    }
};

// ── Reader: bounded, non-copying input cursor ────────────────────────────

pub const Reader = struct {
    buf: []const u8,
    pos: usize = 0,

    pub fn init(buf: []const u8) Reader {
        return .{ .buf = buf, .pos = 0 };
    }

    fn take(self: *Reader, n: usize) Error![]const u8 {
        if (self.pos + n > self.buf.len) return error.BufferTooShort;
        const s = self.buf[self.pos..][0..n];
        self.pos += n;
        return s;
    }

    pub fn readU8(self: *Reader) Error!u8 {
        return (try self.take(1))[0];
    }

    pub fn readU16(self: *Reader) Error!u16 {
        const s = try self.take(2);
        return std.mem.readInt(u16, s[0..2], .big);
    }

    pub fn readU32(self: *Reader) Error!u32 {
        const s = try self.take(4);
        return std.mem.readInt(u32, s[0..4], .big);
    }

    pub fn readU64(self: *Reader) Error!u64 {
        const s = try self.take(8);
        return std.mem.readInt(u64, s[0..8], .big);
    }

    /// A fixed-size field of known length `n` — a slice ALIASING `buf`
    /// (no copy), same convention as `dtls.messages`' `Extension.data`.
    pub fn readBytes(self: *Reader, n: usize) Error![]const u8 {
        return self.take(n);
    }

    pub fn readVarint(self: *Reader) Error!u64 {
        if (self.pos > self.buf.len) return error.BufferTooShort;
        const r = try varint.decode(self.buf[self.pos..]);
        self.pos += r.len;
        return r.value;
    }

    /// `opaque foo<V>` / `T foo<V>` — reads the varint length prefix, then
    /// returns that many bytes ALIASING `buf` (no copy). Bounds-checked
    /// against `buf.len` regardless of what the length prefix claims — a
    /// hostile length larger than the remaining buffer is
    /// `error.BufferTooShort`, never an OOB read.
    pub fn readVector(self: *Reader) Error![]const u8 {
        const len = try self.readVarint();
        const n = std.math.cast(usize, len) orelse return error.Malformed;
        return self.take(n);
    }

    pub fn readPresence(self: *Reader) Error!bool {
        return switch (try self.readU8()) {
            0 => false,
            1 => true,
            else => error.Malformed,
        };
    }

    /// `optional<T>` (§2.1.1): presence octet, then `readFn(self)` iff
    /// present.
    pub fn readOptional(self: *Reader, comptime T: type, comptime readFn: fn (*Reader) Error!T) Error!?T {
        if (try self.readPresence()) return try readFn(self);
        return null;
    }

    /// The enum counterpart of `Writer.writeEnum` — reads the tag at its
    /// declared bit width and reinterprets it as `E`. `E` should be a
    /// NON-EXHAUSTIVE enum (a trailing `_,` variant, the convention this
    /// whole repo's wire-format enums already follow — `dtls.messages
    /// .HandshakeType`, `hpke.suite.KemId`, …) so an unrecognized tag
    /// value from hostile input decodes to the catch-all variant instead
    /// of making `@enumFromInt` reachable-UB on an exhaustive enum.
    pub fn readEnum(self: *Reader, comptime E: type) Error!E {
        const tag_bits = @bitSizeOf(@typeInfo(E).@"enum".tag_type);
        const raw: @typeInfo(E).@"enum".tag_type = switch (tag_bits) {
            8 => try self.readU8(),
            16 => try self.readU16(),
            32 => try self.readU32(),
            else => @compileError("mls.codec.readEnum: unsupported enum tag width (need u8/u16/u32)"),
        };
        return @enumFromInt(raw);
    }

    pub fn remaining(self: *const Reader) []const u8 {
        return self.buf[self.pos..];
    }

    pub fn atEnd(self: *const Reader) bool {
        return self.pos == self.buf.len;
    }
};

// ── tests ─────────────────────────────────────────────────────────────

const testing = std.testing;

test "varint.decode: RFC 9420 §2.1.2's own three worked examples" {
    // "The four-byte length value 0x9d7f3e7d decodes to 494878333."
    try testing.expectEqual(@as(u64, 494878333), (try varint.decode(&[_]u8{ 0x9d, 0x7f, 0x3e, 0x7d })).value);
    // "The two-byte length value 0x7bbd decodes to 15293."
    try testing.expectEqual(@as(u64, 15293), (try varint.decode(&[_]u8{ 0x7b, 0xbd })).value);
    // "The single-byte length value 0x25 decodes to 37."
    try testing.expectEqual(@as(u64, 37), (try varint.decode(&[_]u8{0x25})).value);
}

test "varint.encode/decode round trip at every prefix-length boundary" {
    const cases = [_]u64{ 0, 1, 63, 64, 65, 16383, 16384, 16385, varint.max_value };
    for (cases) |v| {
        var buf: [4]u8 = undefined;
        const enc = try varint.encode(v, &buf);
        const dec = try varint.decode(enc);
        try testing.expectEqual(v, dec.value);
        try testing.expectEqual(enc.len, dec.len);
    }
    var scratch: [4]u8 = undefined;
    try testing.expectError(error.VarintTooLarge, varint.encode(varint.max_value + 1, &scratch));
}

test "varint.decode: prefix 11 is rejected (InvalidVarint)" {
    try testing.expectError(error.InvalidVarint, varint.decode(&[_]u8{0xff}));
}

test "varint.decode: non-minimal encodings are rejected at every boundary" {
    // 63 fits in 1 byte (prefix 00); encoding it with the 2-byte prefix
    // (01) instead is non-minimal.
    try testing.expectError(error.NonMinimalVarint, varint.decode(&[_]u8{ 0x40, 63 }));
    // 16383 fits in 2 bytes; encoding it with the 4-byte prefix is
    // non-minimal.
    var buf4: [4]u8 = .{ 0x80, 0x00, 0x3f, 0xff };
    try testing.expectError(error.NonMinimalVarint, varint.decode(&buf4));
    // Zero itself must use the 1-byte form.
    try testing.expectError(error.NonMinimalVarint, varint.decode(&[_]u8{ 0x40, 0x00 }));
}

test "varint.decode: truncated input is BufferTooShort, never an OOB read" {
    try testing.expectError(error.BufferTooShort, varint.decode(&[_]u8{}));
    try testing.expectError(error.BufferTooShort, varint.decode(&[_]u8{0x40})); // claims 2 bytes, has 1
    try testing.expectError(error.BufferTooShort, varint.decode(&[_]u8{0x80})); // claims 4 bytes, has 1
}

test "Writer/Reader: fixed-width ints round trip big-endian" {
    var buf: [15]u8 = undefined;
    var w = Writer.init(&buf);
    try w.writeU8(0xab);
    try w.writeU16(0x1234);
    try w.writeU32(0xdeadbeef);
    try w.writeU64(0x0102030405060708);
    const out = w.finish();
    try testing.expectEqualSlices(u8, &[_]u8{ 0xab, 0x12, 0x34, 0xde, 0xad, 0xbe, 0xef, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08 }, out);

    var r = Reader.init(out);
    try testing.expectEqual(@as(u8, 0xab), try r.readU8());
    try testing.expectEqual(@as(u16, 0x1234), try r.readU16());
    try testing.expectEqual(@as(u32, 0xdeadbeef), try r.readU32());
    try testing.expectEqual(@as(u64, 0x0102030405060708), try r.readU64());
    try testing.expect(r.atEnd());
}

test "Writer/Reader: writeVector/readVector round trip, aliases the buffer (no copy)" {
    var buf: [64]u8 = undefined;
    var w = Writer.init(&buf);
    try w.writeVector("hello, mls");
    try w.writeVector(""); // empty vector must round-trip too
    const out = w.finish();

    var r = Reader.init(out);
    const v1 = try r.readVector();
    try testing.expectEqualStrings("hello, mls", v1);
    // aliasing check: v1 must point INTO out, not a copy.
    try testing.expectEqual(@intFromPtr(out.ptr) + 1, @intFromPtr(v1.ptr));
    const v2 = try r.readVector();
    try testing.expectEqual(@as(usize, 0), v2.len);
    try testing.expect(r.atEnd());
}

test "Writer.writeVectorConcat: length covers ALL parts, one vector not several" {
    var buf: [32]u8 = undefined;
    var w = Writer.init(&buf);
    try w.writeVectorConcat(&.{ "MLS 1.0 ", "secret" });
    const out = w.finish();
    var r = Reader.init(out);
    const got = try r.readVector();
    try testing.expectEqualStrings("MLS 1.0 secret", got);
}

test "Writer/Reader: readVector on a hostile too-large length prefix fails closed, never OOB" {
    // A 4-byte varint claiming the full 2^30-1 ceiling, but the buffer has
    // only 2 bytes of payload after it.
    var buf: [6]u8 = .{ 0xbf, 0xff, 0xff, 0xff, 0xaa, 0xbb };
    var r = Reader.init(&buf);
    try testing.expectError(error.BufferTooShort, r.readVector());
}

test "Writer: BufferTooShort on overflow, never OOB write" {
    var buf: [2]u8 = undefined;
    var w = Writer.init(&buf);
    try w.writeU8(1);
    try testing.expectError(error.BufferTooShort, w.writeU16(2));
    // The failed write must not have partially mutated pos.
    try testing.expectEqual(@as(usize, 1), w.pos);
}

test "Writer/Reader: optional<T> both branches round trip" {
    const writeU16Val = struct {
        fn f(w: *Writer, v: u16) Error!void {
            try w.writeU16(v);
        }
    }.f;
    const readU16Val = struct {
        fn f(r: *Reader) Error!u16 {
            return r.readU16();
        }
    }.f;

    var buf: [8]u8 = undefined;
    var w = Writer.init(&buf);
    try w.writeOptional(u16, @as(?u16, 0xbeef), writeU16Val);
    try w.writeOptional(u16, @as(?u16, null), writeU16Val);
    const out = w.finish();
    try testing.expectEqualSlices(u8, &[_]u8{ 1, 0xbe, 0xef, 0 }, out);

    var r = Reader.init(out);
    try testing.expectEqual(@as(?u16, 0xbeef), try r.readOptional(u16, readU16Val));
    try testing.expectEqual(@as(?u16, null), try r.readOptional(u16, readU16Val));
}

test "Reader.readPresence: any octet other than 0/1 is Malformed" {
    var buf: [1]u8 = .{2};
    var r = Reader.init(&buf);
    try testing.expectError(error.Malformed, r.readPresence());
}

const TestEnum = enum(u8) { a = 1, b = 2, _ };

test "Writer/Reader: enum round trip, unknown tag decodes to the non-exhaustive catch-all" {
    var buf: [3]u8 = undefined;
    var w = Writer.init(&buf);
    try w.writeEnum(TestEnum, .b);
    try w.writeU8(0xff); // an unrecognized tag value
    const out = w.finish();

    var r = Reader.init(out);
    try testing.expectEqual(TestEnum.b, try r.readEnum(TestEnum));
    const unknown = try r.readEnum(TestEnum);
    try testing.expectEqual(@as(u8, 0xff), @intFromEnum(unknown));
}
