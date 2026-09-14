// SPDX-License-Identifier: MIT

//! Protocol Buffers **wire primitives** — varints, zigzag, tags, and the
//! bounds-checked cursor every length-delimited read goes through.
//!
//! This file owns the single most security-relevant rule in the module:
//! a length-delimited field carries a byte count taken **from the input**,
//! and that count is validated against the bytes actually remaining
//! *before* anything is allocated, sliced or looped over. `Cursor.take` is
//! the only way to consume a declared length, so the check cannot be
//! forgotten at a call site — there is no unchecked alternative to reach
//! for. A hostile 5-byte message claiming a 4 GiB submessage therefore
//! fails in `take` with `error.Truncated`, having allocated nothing.
//!
//! Reference: the Protocol Buffers encoding specification
//! (protobuf.dev/programming-guides/encoding), mirrored from the behaviour
//! of the upstream C++/Python implementations.

const std = @import("std");

/// Wire types. 3/4 (start/end group) are recognised so they can be
/// *rejected* by name; proto3 removed groups and this codec does not
/// implement them (see SPEC.md).
pub const WireType = enum(u3) {
    varint = 0,
    i64 = 1,
    len = 2,
    sgroup = 3,
    egroup = 4,
    i32 = 5,
    _,
};

pub const Error = error{
    /// The input ended in the middle of a value, or a declared length
    /// exceeded the bytes actually remaining. This is the check that keeps
    /// an attacker-supplied length from sizing an allocation.
    Truncated,
    /// A varint ran past 10 bytes, or its 10th byte carried bits above 2^64.
    VarintOverflow,
    /// Field number 0, which the wire format reserves and no encoder emits.
    FieldNumberZero,
    /// Field number above `2^29-1`, the wire format's ceiling (field
    /// numbers are packed into 29 bits alongside the 3-bit wire type). A
    /// deliberately stricter choice than the reference implementation,
    /// which accepts an out-of-range field number and treats it as unknown
    /// (verified: `protoc`-generated Python accepted a tag naming field
    /// `2^29` and produced an empty message) -- this codec refuses instead.
    /// Previously conflated with `FieldNumberZero` under that name, which
    /// named the wrong cause for this half of the check (wave-2 audit
    /// finding `protobuf` F4).
    FieldNumberOutOfRange,
    /// Wire type 3 or 4 (groups), or one of the two unassigned wire types
    /// (6, 7) that no conforming encoder produces.
    UnsupportedWireType,
    /// A tag varint encoded with extra continuation bytes beyond the
    /// minimal length for its value — e.g. `80 00` instead of `00` for tag
    /// 0. No conforming encoder emits this; see `Cursor.tag`'s doc for why
    /// it is rejected rather than decoded (wave-3 audit finding `protobuf`
    /// F3).
    NonMinimalTag,
};

/// The number of bytes `value` occupies as a base-128 varint (1..10).
pub fn varintLen(value: u64) usize {
    // 7 bits per byte; 0 still takes one byte.
    return (@as(usize, 63 - @clz(value | 1)) / 7) + 1;
}

/// Two's-complement widening used for the signed *non*-zigzag types.
///
/// This is the trap the brief calls out: protobuf encodes `int32`/`int64`
/// negatives by sign-extending to 64 bits first, so `-1` is always the
/// 10-byte varint `ff ff ff ff ff ff ff ff ff 01` — never a short one. An
/// implementation that casts `i32` straight to `u32` produces 5 bytes,
/// round-trips against itself perfectly, and is rejected by every other
/// implementation on the planet.
pub fn signExtend(value: i64) u64 {
    return @bitCast(value);
}

/// zigzag: map signed to unsigned so small magnitudes stay small.
pub fn zigzagEncode(value: i64) u64 {
    return @bitCast((value << 1) ^ (value >> 63));
}

pub fn zigzagDecode(value: u64) i64 {
    return @bitCast((value >> 1) ^ (~(value & 1) +% 1));
}

/// zigzag decode on 32 bits, for `sint32`. **Not** `zigzagDecode` truncated
/// afterwards: the reference implementation truncates the wire varint to 32
/// bits *first* and zigzags on that (`ZigZagDecode32(static_cast<uint32>(v))`
/// upstream). The two orders agree for varints below 2^32 and disagree above
/// it — `sint32` accepts arbitrarily large varints on the wire like every
/// other integer kind, so a peer can legally send one (wave-3 audit finding
/// `protobuf` F2).
pub fn zigzagDecode32(value: u32) i32 {
    return @bitCast((value >> 1) ^ (~(value & 1) +% 1));
}

/// A decoded tag: field number plus wire type.
pub const Tag = struct {
    number: u32,
    wire: WireType,
};

/// Bounds-checked read cursor over a byte slice.
///
/// Invariant: `pos <= buf.len` at all times, so `buf.len - pos` never
/// underflows and `remaining()` is always the true byte count left.
pub const Cursor = struct {
    buf: []const u8,
    pos: usize = 0,

    pub fn init(buf: []const u8) Cursor {
        return .{ .buf = buf };
    }

    pub fn remaining(self: Cursor) usize {
        return self.buf.len - self.pos;
    }

    pub fn atEnd(self: Cursor) bool {
        return self.pos >= self.buf.len;
    }

    /// Consume `n` bytes. **The bounds check.** `n` is caller-supplied and,
    /// for every length-delimited field, comes straight off the wire; it is
    /// compared against the bytes really present before any slice is formed.
    /// Widened to u64 first so a 2^63 length on a 32-bit host cannot wrap
    /// during the comparison.
    pub fn take(self: *Cursor, n: u64) Error![]const u8 {
        if (n > @as(u64, self.remaining())) return error.Truncated;
        const start = self.pos;
        self.pos = start + @as(usize, @intCast(n));
        return self.buf[start..self.pos];
    }

    pub fn takeByte(self: *Cursor) Error!u8 {
        if (self.pos >= self.buf.len) return error.Truncated;
        defer self.pos += 1;
        return self.buf[self.pos];
    }

    /// Base-128 varint, little-endian groups of 7 bits, high bit = continue.
    ///
    /// Capped at 10 bytes (the most a u64 can need). The 10th byte may only
    /// contribute the single bit that fits below 2^64: anything larger is a
    /// value no u64 can hold, and is rejected rather than silently truncated
    /// the way the C++ implementation does — a truncating decoder lets one
    /// stream mean two different things to two readers.
    ///
    /// The 9-then-1 split below is deliberate, not decorative: an earlier
    /// version read all 10 bytes through one loop with an `i == 9` special
    /// case that unconditionally returned, which made the loop's own upper
    /// bound (`10`) unable to affect behaviour and left a `return
    /// error.VarintOverflow` after the loop that could never execute —
    /// mutating the loop bound (`10` -> `11`) was a silent no-op and two
    /// mutations targeting the dead line both survived 69/69 green (wave-3
    /// audit finding `protobuf` F9). Reading the first 9 bytes in the loop
    /// and the 10th explicitly after it removes both: the loop bound is now
    /// load-bearing, and there is no unreachable line left to point at.
    pub fn varint(self: *Cursor) Error!u64 {
        var result: u64 = 0;
        var shift: u6 = 0;
        for (0..9) |_| {
            const b = try self.takeByte();
            result |= @as(u64, b & 0x7f) << shift;
            if (b & 0x80 == 0) return result;
            shift += 7;
        }
        // The 10th and final permissible byte: only bit 63 is addressable.
        const b = try self.takeByte();
        if (b > 1) return error.VarintOverflow;
        result |= @as(u64, b) << 63;
        return result;
    }

    pub fn fixed32(self: *Cursor) Error!u32 {
        const b = try self.take(4);
        return std.mem.readInt(u32, b[0..4], .little);
    }

    pub fn fixed64(self: *Cursor) Error!u64 {
        const b = try self.take(8);
        return std.mem.readInt(u64, b[0..8], .little);
    }

    /// Read a tag. Rejects field number 0, a non-minimally encoded tag
    /// varint, and the wire types this codec does not implement, so callers
    /// never have to consider them.
    ///
    /// The non-minimal check is scoped to the tag *only* — a **value**
    /// varint stays accepted non-minimally (see `wire.varint`'s doc and
    /// SPEC.md's "Smaller hardening": that is verified parity with the
    /// reference, not a gap). The tag is different: the reference's pure-
    /// Python decoder dispatches on the tag's *raw bytes*
    /// (`_decoders_by_tag[tag_bytes]`), not on the field number `tag()`
    /// decodes to, so a non-minimally encoded tag never matches a known
    /// field there and falls through as unknown — while a field-number
    /// dispatch (this decoder, and reportedly upstream C++) reads it as the
    /// field the number names. Two readers, two different fields (and for
    /// `proto3 optional`, a different *presence* verdict) from one byte
    /// string is exactly the smuggling primitive `Truncated`/`DepthExceeded`
    /// exist to close elsewhere; rejecting it here closes it for the tag too
    /// (wave-3 audit finding `protobuf` F3 — no legitimate encoder, this one
    /// included, ever emits a non-minimal tag, so nothing real is lost).
    pub fn tag(self: *Cursor) Error!Tag {
        const start = self.pos;
        const raw = try self.varint();
        if (self.pos - start != varintLen(raw)) return error.NonMinimalTag;
        const number: u64 = raw >> 3;
        if (number == 0) return error.FieldNumberZero;
        if (number > std.math.maxInt(u29)) return error.FieldNumberOutOfRange;
        const wire: WireType = @enumFromInt(@as(u3, @truncate(raw)));
        switch (wire) {
            .varint, .i64, .len, .i32 => {},
            .sgroup, .egroup => return error.UnsupportedWireType,
            _ => return error.UnsupportedWireType,
        }
        return .{ .number = @intCast(number), .wire = wire };
    }

    /// Skip one value of `wire`, returning the raw bytes consumed *including*
    /// nothing of the tag (the caller already read that). Used both to drop
    /// unwanted fields and to capture unknown ones verbatim.
    pub fn skipValue(self: *Cursor, wire: WireType) Error![]const u8 {
        const start = self.pos;
        switch (wire) {
            .varint => _ = try self.varint(),
            .i64 => _ = try self.take(8),
            .i32 => _ = try self.take(4),
            .len => {
                const n = try self.varint();
                _ = try self.take(n); // bounds-checked before any use of n
            },
            else => return error.UnsupportedWireType,
        }
        return self.buf[start..self.pos];
    }
};

/// The message every size/emit disagreement aborts with. It is a real
/// `@panic`, not `std.debug.assert` (audit F8): an assert does not exist in
/// ReleaseFast or ReleaseSmall, where the same disagreement wrote past the
/// buffer and died with SIGSEGV.
pub const size_mismatch_message =
    "protobuf: the encoder's sizing pass and emit pass disagree — this is a bug " ++
    "in the encoder, not in the message; nothing was written past the buffer.";

/// Append-only write cursor over a caller-sized buffer.
///
/// The buffer is sized by `encodedSize` in a first pass; every `put` checks
/// it fits, and the encoder checks the buffer was filled exactly. A
/// size/emit disagreement is therefore a loud failure in every build mode,
/// not silent corruption.
pub const Emitter = struct {
    out: []u8,
    pos: usize = 0,

    pub fn init(out: []u8) Emitter {
        return .{ .out = out };
    }

    pub fn byte(self: *Emitter, b: u8) void {
        if (self.pos >= self.out.len) @panic(size_mismatch_message);
        self.out[self.pos] = b;
        self.pos += 1;
    }

    pub fn bytes(self: *Emitter, b: []const u8) void {
        if (self.out.len - self.pos < b.len) @panic(size_mismatch_message);
        @memcpy(self.out[self.pos..][0..b.len], b);
        self.pos += b.len;
    }

    pub fn varint(self: *Emitter, value: u64) void {
        var v = value;
        while (v >= 0x80) {
            self.byte(@as(u8, @truncate(v)) | 0x80);
            v >>= 7;
        }
        self.byte(@truncate(v));
    }

    pub fn tag(self: *Emitter, number: u32, wire: WireType) void {
        self.varint((@as(u64, number) << 3) | @intFromEnum(wire));
    }

    pub fn fixed32(self: *Emitter, value: u32) void {
        var b: [4]u8 = undefined;
        std.mem.writeInt(u32, &b, value, .little);
        self.bytes(&b);
    }

    pub fn fixed64(self: *Emitter, value: u64) void {
        var b: [8]u8 = undefined;
        std.mem.writeInt(u64, &b, value, .little);
        self.bytes(&b);
    }
};

pub fn tagLen(number: u32, wire: WireType) usize {
    return varintLen((@as(u64, number) << 3) | @intFromEnum(wire));
}

// ── tests ───────────────────────────────────────────────────────────────────

const testing = std.testing;

fn encodeVarint(value: u64, buf: []u8) []u8 {
    var e = Emitter.init(buf);
    e.varint(value);
    return buf[0..e.pos];
}

test "varint: the boundary vectors" {
    var buf: [16]u8 = undefined;
    // 0, 1, 127 (one byte), 128 (two bytes) — the 7-bit boundary.
    try testing.expectEqualSlices(u8, &.{0x00}, encodeVarint(0, &buf));
    try testing.expectEqualSlices(u8, &.{0x01}, encodeVarint(1, &buf));
    try testing.expectEqualSlices(u8, &.{0x7f}, encodeVarint(127, &buf));
    try testing.expectEqualSlices(u8, &.{ 0x80, 0x01 }, encodeVarint(128, &buf));
    try testing.expectEqualSlices(u8, &.{ 0x96, 0x01 }, encodeVarint(150, &buf));
    // maxInt(u64) is the 10-byte case.
    try testing.expectEqualSlices(
        u8,
        &.{ 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0x01 },
        encodeVarint(std.math.maxInt(u64), &buf),
    );
    for ([_]u64{ 0, 1, 127, 128, 300, 16383, 16384, std.math.maxInt(u32), std.math.maxInt(u64) }) |v| {
        const enc = encodeVarint(v, &buf);
        try testing.expectEqual(enc.len, varintLen(v));
        var c = Cursor.init(enc);
        try testing.expectEqual(v, try c.varint());
        try testing.expect(c.atEnd());
    }
}

test "varint: negative int64 is a 10-byte sign-extended varint" {
    var buf: [16]u8 = undefined;
    // -1 sign-extends to 0xffff_ffff_ffff_ffff.
    try testing.expectEqualSlices(
        u8,
        &.{ 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0x01 },
        encodeVarint(signExtend(-1), &buf),
    );
    try testing.expectEqualSlices(
        u8,
        &.{ 0xfe, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0x01 },
        encodeVarint(signExtend(-2), &buf),
    );
    try testing.expectEqual(@as(usize, 10), varintLen(signExtend(-1)));
}

test "varint: over-long and over-large are rejected, not truncated" {
    // 11 continuation bytes: no u64 needs more than 10.
    var c = Cursor.init(&.{ 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0x01 });
    try testing.expectError(error.VarintOverflow, c.varint());
    // 10th byte = 2 would set bit 64.
    var c2 = Cursor.init(&.{ 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0x02 });
    try testing.expectError(error.VarintOverflow, c2.varint());
    // Runs off the end mid-varint.
    var c3 = Cursor.init(&.{ 0x80, 0x80 });
    try testing.expectError(error.Truncated, c3.varint());
}

test "zigzag: spec vectors and round trip" {
    try testing.expectEqual(@as(u64, 0), zigzagEncode(0));
    try testing.expectEqual(@as(u64, 1), zigzagEncode(-1));
    try testing.expectEqual(@as(u64, 2), zigzagEncode(1));
    try testing.expectEqual(@as(u64, 3), zigzagEncode(-2));
    try testing.expectEqual(@as(u64, 4294967294), zigzagEncode(2147483647));
    try testing.expectEqual(@as(u64, 4294967295), zigzagEncode(-2147483648));
    for ([_]i64{ 0, 1, -1, 2, -2, 63, -64, 1 << 40, -(1 << 40), std.math.maxInt(i64), std.math.minInt(i64) }) |v|
        try testing.expectEqual(v, zigzagDecode(zigzagEncode(v)));
}

test "cursor: a declared length longer than the buffer is refused before use" {
    // Five bytes total, of which the payload claims 0xffff_ffff.
    var c = Cursor.init(&.{ 0xff, 0xff, 0xff, 0xff, 0x0f });
    const n = try c.varint();
    try testing.expectEqual(@as(u64, 0xffff_ffff), n);
    try testing.expectError(error.Truncated, c.take(n));
    // And the cursor did not move past the end.
    try testing.expect(c.pos <= c.buf.len);
}

test "cursor: tag rejects field 0 and group wire types" {
    var c = Cursor.init(&.{0x00}); // field 0, wire 0
    try testing.expectError(error.FieldNumberZero, c.tag());
    var c2 = Cursor.init(&.{0x0b}); // field 1, wire 3 (sgroup)
    try testing.expectError(error.UnsupportedWireType, c2.tag());
    var c3 = Cursor.init(&.{0x0c}); // field 1, wire 4 (egroup)
    try testing.expectError(error.UnsupportedWireType, c3.tag());
    var c4 = Cursor.init(&.{0x0e}); // field 1, wire 6 (unassigned)
    try testing.expectError(error.UnsupportedWireType, c4.tag());
}

test "F4 regression: a field number above 2^29-1 is FieldNumberOutOfRange, not FieldNumberZero" {
    // Before the fix, both field 0 AND field > 2^29-1 returned the same
    // `error.FieldNumberZero`, which named the wrong cause for the second
    // half of the check (wave-2 audit finding `protobuf` F4). The reference
    // implementation actually ACCEPTS an out-of-range field number and
    // treats it as unknown; this module deliberately stays stricter, but
    // the error it raises must say so.
    var buf: [10]u8 = undefined;
    // tag = (2^29 << 3) | wire_type(0), varint-encoded.
    const raw_tag: u64 = (@as(u64, 1) << 29) << 3;
    var c = Cursor.init(encodeVarint(raw_tag, &buf));
    try testing.expectError(error.FieldNumberOutOfRange, c.tag());

    // Positive control/boundary: the maximum IN-range field number (2^29-1)
    // must still be accepted, not swept up by an off-by-one in the bound.
    var buf2: [10]u8 = undefined;
    const max_tag: u64 = (@as(u64, std.math.maxInt(u29)) << 3);
    var c2 = Cursor.init(encodeVarint(max_tag, &buf2));
    const t = try c2.tag();
    try testing.expectEqual(@as(u32, std.math.maxInt(u29)), t.number);
}

test "cursor: skipValue returns exactly the bytes of the value" {
    var c = Cursor.init(&.{ 0x96, 0x01, 0xff });
    const got = try c.skipValue(.varint);
    try testing.expectEqualSlices(u8, &.{ 0x96, 0x01 }, got);
    try testing.expectEqual(@as(usize, 1), c.remaining());

    var c2 = Cursor.init(&.{ 0x03, 'a', 'b', 'c', 'z' });
    const got2 = try c2.skipValue(.len);
    try testing.expectEqualSlices(u8, &.{ 0x03, 'a', 'b', 'c' }, got2);

    // Length-delimited whose length overruns: refused.
    var c3 = Cursor.init(&.{ 0x7f, 'a' });
    try testing.expectError(error.Truncated, c3.skipValue(.len));
}

// F8: `Emitter.byte`/`bytes` used `std.debug.assert`, which does not exist in
// ReleaseFast or ReleaseSmall — measured there, a size/emit disagreement wrote
// past the buffer and died with SIGSEGV. The child below overflows a one-byte
// emitter with guard bytes behind it; without the check it exits normally
// having overwritten the guard.
test "Emitter aborts with its own message on overflow, in every build mode (F8)" {
    const builtin = @import("builtin");
    if (builtin.os.tag != .linux) return error.SkipZigTest;

    for ([_]bool{ false, true }) |use_bytes| {
        var fds: [2]i32 = undefined;
        if (std.os.linux.pipe2(&fds, .{}) != 0) return error.SkipZigTest;
        const rc = std.os.linux.fork();
        const pid: isize = @bitCast(rc);
        if (pid < 0) return error.SkipZigTest;
        if (pid == 0) {
            _ = std.os.linux.close(fds[0]);
            _ = std.os.linux.dup3(fds[1], 2, 0);
            var guarded: [4]u8 = @splat(0xaa);
            var e = Emitter.init(guarded[0..1]);
            if (use_bytes) {
                e.bytes("xy");
            } else {
                e.byte(1);
                e.byte(2);
            }
            // 71: returned with the guard intact; 72: returned having overwritten it.
            std.os.linux.exit(if (guarded[1] == 0xaa) 71 else 72);
        }
        _ = std.os.linux.close(fds[1]);

        var msg: [4096]u8 = undefined;
        var msg_len: usize = 0;
        while (msg_len < msg.len) {
            const n = std.os.linux.read(fds[0], msg[msg_len..].ptr, msg.len - msg_len);
            const got: isize = @bitCast(n);
            if (got <= 0) break;
            msg_len += @intCast(got);
        }
        _ = std.os.linux.close(fds[0]);

        var status: u32 = 0;
        _ = std.os.linux.wait4(@intCast(pid), &status, 0, null);
        const sig = status & 0x7f;
        const exit_code = (status >> 8) & 0xff;
        if (sig != 6) {
            std.debug.print("\nEmitter overflow ({s}): signal {d}, exit {d}, not SIGABRT\n", .{
                if (use_bytes) "bytes" else "byte", sig, exit_code,
            });
            return error.TestUnexpectedResult;
        }
        const needle = size_mismatch_message[0..40];
        try testing.expect(std.mem.indexOf(u8, msg[0..msg_len], needle) != null);
    }
}
