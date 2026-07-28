// SPDX-License-Identifier: MIT
//! Shared wire-level plumbing for the Bitcoin P2P message payloads:
//! a bounds-checked little-endian byte reader/writer (Bitcoin's wire
//! format is little-endian throughout, unlike Lightning's BOLT#1 frames —
//! see `lnwire`'s big-endian `message.zig`, the closest sibling in this
//! repo, for the analogous shape) plus CompactSize/var_str helpers built
//! directly on `bitcointx`'s existing CompactSize codec (Bitcoin's varint
//! is one wire format shared by transactions, inventory lists, address
//! lists and more — `bitcointx` already implements it byte-exact and
//! fuzzed, so this module never redefines it).
//!
//! ## Ownership model
//!
//! Every `decode*` function across this module borrows variable-length
//! fields (`user_agent`, `reject`'s `message`/`reason`, a `var_str`'s
//! bytes, ...) directly from the caller's input buffer — never copied.
//! The input buffer must outlive the decoded value. Fixed-size fields are
//! copied by value (they're small: hashes, addresses, nonces).
//!
//! ## Hostile-input handling
//!
//! Every decode path returns a typed error, never panics, on truncated or
//! adversarial bytes: a fixed-length field or a CompactSize-length-
//! prefixed field whose declared length exceeds the bytes remaining fails
//! closed with `error.Truncated` before any read past the buffer.

const std = @import("std");
const Allocator = std.mem.Allocator;
const bitcointx = @import("bitcointx");

pub const ReadError = error{Truncated};
pub const CompactSizeError = bitcointx.tx.CompactSizeError;

pub const Reader = struct {
    bytes: []const u8,
    pos: usize = 0,

    pub fn remaining(self: Reader) usize {
        return self.bytes.len - self.pos;
    }

    /// Every remaining byte -- used where a field is "the rest of the
    /// message" (e.g. `reject`'s trailing `data`).
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

    pub fn boolByte(self: *Reader) ReadError!bool {
        return (try self.byte()) != 0;
    }

    pub fn u16le(self: *Reader) ReadError!u16 {
        const s = try self.takeBytes(2);
        return std.mem.readInt(u16, s[0..2], .little);
    }

    /// Big-endian 16-bit read -- only `net_addr`'s `port` field uses
    /// network (big-endian) byte order; everything else in this wire
    /// format is little-endian (see module doc comment).
    pub fn u16be(self: *Reader) ReadError!u16 {
        const s = try self.takeBytes(2);
        return std.mem.readInt(u16, s[0..2], .big);
    }

    pub fn u32le(self: *Reader) ReadError!u32 {
        const s = try self.takeBytes(4);
        return std.mem.readInt(u32, s[0..4], .little);
    }

    pub fn i32le(self: *Reader) ReadError!i32 {
        const s = try self.takeBytes(4);
        return std.mem.readInt(i32, s[0..4], .little);
    }

    pub fn u64le(self: *Reader) ReadError!u64 {
        const s = try self.takeBytes(8);
        return std.mem.readInt(u64, s[0..8], .little);
    }

    pub fn i64le(self: *Reader) ReadError!i64 {
        const s = try self.takeBytes(8);
        return std.mem.readInt(i64, s[0..8], .little);
    }

    /// Decodes one CompactSize (Bitcoin's varint, via `bitcointx`) from
    /// the current position and advances past it.
    pub fn compactSize(self: *Reader) CompactSizeError!u64 {
        const r = try bitcointx.decodeCompactSize(self.bytes[self.pos..]);
        self.pos += r.consumed;
        return r.value;
    }

    /// A CompactSize-length-prefixed borrowed byte slice (Bitcoin's
    /// `var_str`: a `version` message's `user_agent`, a `reject`
    /// message's `message`/`reason`).
    pub fn varBytes(self: *Reader) (CompactSizeError || ReadError)![]const u8 {
        const len = try self.compactSize();
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

    pub fn putBool(self: *Writer, allocator: Allocator, v: bool) Allocator.Error!void {
        try self.putU8(allocator, if (v) 1 else 0);
    }

    pub fn putU16le(self: *Writer, allocator: Allocator, v: u16) Allocator.Error!void {
        var tmp: [2]u8 = undefined;
        std.mem.writeInt(u16, &tmp, v, .little);
        try self.list.appendSlice(allocator, &tmp);
    }

    pub fn putU16be(self: *Writer, allocator: Allocator, v: u16) Allocator.Error!void {
        var tmp: [2]u8 = undefined;
        std.mem.writeInt(u16, &tmp, v, .big);
        try self.list.appendSlice(allocator, &tmp);
    }

    pub fn putU32le(self: *Writer, allocator: Allocator, v: u32) Allocator.Error!void {
        var tmp: [4]u8 = undefined;
        std.mem.writeInt(u32, &tmp, v, .little);
        try self.list.appendSlice(allocator, &tmp);
    }

    pub fn putI32le(self: *Writer, allocator: Allocator, v: i32) Allocator.Error!void {
        var tmp: [4]u8 = undefined;
        std.mem.writeInt(i32, &tmp, v, .little);
        try self.list.appendSlice(allocator, &tmp);
    }

    pub fn putU64le(self: *Writer, allocator: Allocator, v: u64) Allocator.Error!void {
        var tmp: [8]u8 = undefined;
        std.mem.writeInt(u64, &tmp, v, .little);
        try self.list.appendSlice(allocator, &tmp);
    }

    pub fn putI64le(self: *Writer, allocator: Allocator, v: i64) Allocator.Error!void {
        var tmp: [8]u8 = undefined;
        std.mem.writeInt(i64, &tmp, v, .little);
        try self.list.appendSlice(allocator, &tmp);
    }

    pub fn putBytes(self: *Writer, allocator: Allocator, b: []const u8) Allocator.Error!void {
        try self.list.appendSlice(allocator, b);
    }

    pub fn putCompactSize(self: *Writer, allocator: Allocator, v: u64) Allocator.Error!void {
        var tmp: [9]u8 = undefined;
        const w = bitcointx.encodeCompactSize(v, &tmp) catch unreachable; // tmp is always big enough
        try self.list.appendSlice(allocator, w);
    }

    pub fn putVarBytes(self: *Writer, allocator: Allocator, b: []const u8) Allocator.Error!void {
        try self.putCompactSize(allocator, b.len);
        try self.putBytes(allocator, b);
    }
};

// ── tests ────────────────────────────────────────────────────────────────

const testing = std.testing;

test "Reader: fixed-width little-endian reads" {
    const bytes = [_]u8{ 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09 };
    var r: Reader = .{ .bytes = &bytes };
    try testing.expectEqual(@as(u8, 0x01), try r.byte());
    try testing.expectEqual(@as(u16, 0x0302), try r.u16le());
    try testing.expectEqual(@as(u32, 0x07060504), try r.u32le());
    try testing.expectEqual(@as(usize, 2), r.remaining());
}

test "Reader: u16be is network byte order (net_addr's port field)" {
    const bytes = [_]u8{ 0x20, 0x8d }; // port 8333
    var r: Reader = .{ .bytes = &bytes };
    try testing.expectEqual(@as(u16, 8333), try r.u16be());
}

test "Reader: i32le / u64le / i64le" {
    const bytes = [_]u8{ 0xff, 0xff, 0xff, 0xff, 0, 0, 0, 0, 0, 0, 0, 0x80, 0, 0, 0, 0, 0, 0, 0, 0x80 };
    var r: Reader = .{ .bytes = &bytes };
    try testing.expectEqual(@as(i32, -1), try r.i32le());
    try testing.expectEqual(@as(u64, 0x8000000000000000), try r.u64le());
    try testing.expectEqual(@as(i64, std.math.minInt(i64)), try r.i64le());
}

test "hostile: Reader.takeBytes rejects truncated reads (no panic/OOB)" {
    const bytes = [_]u8{ 0x01, 0x02 };
    var r: Reader = .{ .bytes = &bytes };
    try testing.expectError(error.Truncated, r.takeBytes(3));
}

test "hostile: Reader.varBytes rejects a CompactSize length exceeding remaining bytes" {
    const bytes = [_]u8{ 0xfd, 0x00, 0x01 }; // CompactSize(256), 0 bytes follow
    var r: Reader = .{ .bytes = &bytes };
    try testing.expectError(error.Truncated, r.varBytes());
}

test "Writer/Reader round-trip: le ints, compactSize, varBytes" {
    const allocator = testing.allocator;
    var w: Writer = .{};
    defer w.deinit(allocator);
    try w.putU32le(allocator, 0x11223344);
    try w.putU64le(allocator, 0x1122334455667788);
    try w.putCompactSize(allocator, 300);
    try w.putVarBytes(allocator, "hello");

    var r: Reader = .{ .bytes = w.list.items };
    try testing.expectEqual(@as(u32, 0x11223344), try r.u32le());
    try testing.expectEqual(@as(u64, 0x1122334455667788), try r.u64le());
    try testing.expectEqual(@as(u64, 300), try r.compactSize());
    try testing.expectEqualSlices(u8, "hello", try r.varBytes());
    try testing.expectEqual(@as(usize, 0), r.remaining());
}

// ── fuzz: the shared reader chain every message decode runs through ───────
//
// Every message decoder in this module runs its variable-length fields
// through `compactSize`/`varBytes`; this harness drives them directly
// over arbitrary bytes (per-message fuzz harnesses cover the fixed-field
// framing around them).
test "fuzz: compactSize + varBytes never panic on arbitrary bytes" {
    try testing.fuzz({}, fuzzCompactSizeAndVarBytes, .{});
}

fn fuzzCompactSizeAndVarBytes(_: void, smith: *std.testing.Smith) !void {
    var buf: [256]u8 = undefined;
    smith.bytes(&buf);
    const len: usize = smith.valueRangeAtMost(u16, 0, buf.len);

    var r: Reader = .{ .bytes = buf[0..len] };
    _ = r.varBytes() catch return;
}
