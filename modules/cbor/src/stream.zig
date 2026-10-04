// SPDX-License-Identifier: MIT
//! Streaming CBOR without a `Value` tree.
//!
//! **`Reader`** pulls one `Token` (one head, plus a definite string's content)
//! at a time out of a byte slice. It allocates nothing: string tokens are
//! slices of the input. A token that does not fit in what is left of the
//! input fails `error.Truncated` and leaves `pos` where it was, so a caller
//! receiving data piece by piece can append more bytes (a longer slice over
//! the same buffer) and call `next()` again — incremental decoding at token
//! granularity. `next()` checks each token on its own (reserved
//! additional-info values, a misplaced indefinite marker, UTF-8 of a definite
//! text string); `skipValue`/`rawValue` walk one whole item and check its
//! structure too (break placement, indefinite-string chunks, the depth cap),
//! with exactly `decode`'s rules — the fuzz driver holds the two to the same
//! verdict on every input.
//!
//! **`Writer`** emits heads and items onto any `*std.Io.Writer`: into a
//! caller-owned buffer with `std.Io.Writer.fixed(&buf)` (no allocation), into
//! a file, a socket. Integers and lengths are always shortest-form; floats
//! through `float` are written in the shortest exact width. Indefinite-length
//! items are the caller's to open (`beginArray(null)`, …) and close
//! (`end()`); the writer does not track nesting.

const std = @import("std");
const root = @import("root.zig");
const Value = root.Value;
const DecodeError = root.DecodeError;

/// One CBOR head, or one definite string.
pub const Token = union(enum) {
    uint: u64,
    /// The real value is `-1 - negint`, as in `Value.negint`.
    negint: u64,
    /// A definite byte string — whole, or one chunk of an indefinite one.
    bytes: []const u8,
    /// A definite text string (UTF-8 checked), or one chunk.
    text: []const u8,
    /// `0x5f`: chunks (`.bytes` tokens) follow, then `.break_code`.
    bytes_start,
    /// `0x7f`: chunks (`.text` tokens) follow, then `.break_code`.
    text_start,
    /// An array of `n` items, or indefinite (`null`, closed by `.break_code`).
    array: ?u64,
    /// A map of `n` pairs, or indefinite (`null`).
    map: ?u64,
    /// A tag; the tagged item follows.
    tag: u64,
    simple: u8,
    bool: bool,
    null_value,
    undefined_value,
    f16: f16,
    f32: f32,
    f64: f64,
    /// `0xff`, which closes an indefinite-length item.
    break_code,
};

pub const Reader = struct {
    bytes: []const u8,
    pos: usize = 0,

    pub fn init(bytes: []const u8) Reader {
        return .{ .bytes = bytes };
    }

    /// The next token, or `null` once every byte has been read. On any error
    /// `pos` is left unchanged.
    pub fn next(self: *Reader) DecodeError!?Token {
        if (self.pos == self.bytes.len) return null;
        var p = self.pos;
        const tok = try self.readToken(&p);
        self.pos = p;
        return tok;
    }

    /// The next token without consuming it.
    pub fn peek(self: *const Reader) DecodeError!?Token {
        if (self.pos == self.bytes.len) return null;
        var p = self.pos;
        return try self.readToken(&p);
    }

    fn readArg(self: *const Reader, p: *usize, info: u5) DecodeError!?u64 {
        const n: usize = switch (info) {
            0...23 => return info,
            24 => 1,
            25 => 2,
            26 => 4,
            27 => 8,
            28, 29, 30 => return error.Malformed,
            31 => return null,
        };
        if (n > self.bytes.len - p.*) return error.Truncated;
        var v: u64 = 0;
        for (self.bytes[p.*..][0..n]) |b| v = (v << 8) | b;
        p.* += n;
        return v;
    }

    fn readToken(self: *const Reader, p: *usize) DecodeError!Token {
        if (p.* >= self.bytes.len) return error.Truncated;
        const ib = self.bytes[p.*];
        p.* += 1;
        const major: u3 = @intCast(ib >> 5);
        const info: u5 = @intCast(ib & 0x1f);
        if (major == 7) return self.readSimple(p, info);
        const arg = try self.readArg(p, info);
        switch (major) {
            0 => return .{ .uint = arg orelse return error.Malformed },
            1 => return .{ .negint = arg orelse return error.Malformed },
            6 => return .{ .tag = arg orelse return error.Malformed },
            4 => return .{ .array = arg },
            5 => return .{ .map = arg },
            2, 3 => {
                const len = arg orelse return if (major == 2) .bytes_start else .text_start;
                if (len > self.bytes.len - p.*) return error.Truncated;
                const s = self.bytes[p.*..][0..@intCast(len)];
                if (major == 3 and !std.unicode.utf8ValidateSlice(s)) return error.Malformed;
                p.* += @intCast(len);
                return if (major == 2) .{ .bytes = s } else .{ .text = s };
            },
            7 => unreachable,
        }
    }

    fn readSimple(self: *const Reader, p: *usize, info: u5) DecodeError!Token {
        const n: usize = switch (info) {
            0...19 => return .{ .simple = info },
            20 => return .{ .bool = false },
            21 => return .{ .bool = true },
            22 => return .null_value,
            23 => return .undefined_value,
            24 => 1,
            25 => 2,
            26 => 4,
            27 => 8,
            28, 29, 30 => return error.Malformed,
            31 => return .break_code,
        };
        if (n > self.bytes.len - p.*) return error.Truncated;
        const s = self.bytes[p.*..][0..n];
        p.* += n;
        return switch (info) {
            // RFC 8949 §3.3: a two-byte simple value below 32 is not well-formed.
            24 => if (s[0] < 32) error.Malformed else .{ .simple = s[0] },
            25 => .{ .f16 = @bitCast(std.mem.readInt(u16, s[0..2], .big)) },
            26 => .{ .f32 = @bitCast(std.mem.readInt(u32, s[0..4], .big)) },
            else => .{ .f64 = @bitCast(std.mem.readInt(u64, s[0..8], .big)) },
        };
    }

    /// Consume one complete item (an array with everything in it, a tag with
    /// its item), checking its structure as `decode` would — the same errors
    /// for the same input. `max_depth` is `DecodeOptions.max_depth`'s
    /// meaning. On an error `pos` is left unchanged.
    pub fn skipValue(self: *Reader, max_depth: u32) DecodeError!void {
        var p = self.pos;
        try self.skipAt(&p, 0, max_depth);
        self.pos = p;
    }

    /// `skipValue`, returning the bytes the item occupied (a slice of the
    /// input) — to hash, forward or decode later.
    pub fn rawValue(self: *Reader, max_depth: u32) DecodeError![]const u8 {
        const start = self.pos;
        try self.skipValue(max_depth);
        return self.bytes[start..self.pos];
    }

    fn skipAt(self: *const Reader, p: *usize, depth: u32, max_depth: u32) DecodeError!void {
        if (depth > max_depth) return error.DepthLimitExceeded;
        switch (try self.readToken(p)) {
            .uint, .negint, .bytes, .text, .simple, .bool, .null_value, .undefined_value, .f16, .f32, .f64 => {},
            .break_code => return error.Malformed,
            .bytes_start, .text_start => {
                const want: u3 = @intCast(self.bytes[p.* - 1] >> 5);
                while (true) {
                    if (p.* >= self.bytes.len) return error.Truncated;
                    const b = self.bytes[p.*];
                    if (b == 0xff) {
                        p.* += 1;
                        break;
                    }
                    // A chunk is a definite string of the same major type
                    // (RFC 8949 §3.2.3); the major type is judged before the
                    // argument is read, as `decode` does.
                    if (b >> 5 != want or b & 0x1f == 31) return error.Malformed;
                    _ = try self.readToken(p);
                }
            },
            .array => |n| if (n) |count| {
                var i: u64 = 0;
                while (i < count) : (i += 1) try self.skipAt(p, depth + 1, max_depth);
            } else try self.skipUntilBreak(p, depth, max_depth, 1),
            .map => |n| if (n) |count| {
                var i: u64 = 0;
                while (i < count) : (i += 1) {
                    try self.skipAt(p, depth + 1, max_depth);
                    try self.skipAt(p, depth + 1, max_depth);
                }
            } else try self.skipUntilBreak(p, depth, max_depth, 2),
            .tag => try self.skipAt(p, depth + 1, max_depth),
        }
    }

    fn skipUntilBreak(self: *const Reader, p: *usize, depth: u32, max_depth: u32, per: u2) DecodeError!void {
        while (true) {
            if (p.* >= self.bytes.len) return error.Truncated;
            if (self.bytes[p.*] == 0xff) {
                p.* += 1;
                return;
            }
            for (0..per) |_| try self.skipAt(p, depth + 1, max_depth);
        }
    }
};

/// Push encoder onto a `*std.Io.Writer`. Never allocates; never buffers
/// beyond what the underlying writer does.
pub const Writer = struct {
    w: *std.Io.Writer,

    pub const Error = std.Io.Writer.Error;

    pub fn init(w: *std.Io.Writer) Writer {
        return .{ .w = w };
    }

    fn headOut(self: Writer, major: u3, arg: u64) Error!void {
        const h = root.head(major, arg);
        try self.w.writeAll(h.slice());
    }

    pub fn uint(self: Writer, v: u64) Error!void {
        try self.headOut(0, v);
    }

    /// A signed integer: major type 0 for `v >= 0`, major type 1 otherwise.
    pub fn int(self: Writer, v: i64) Error!void {
        if (v >= 0) try self.headOut(0, @intCast(v)) else try self.headOut(1, @intCast(-1 - v));
    }

    /// Major type 1 with magnitude `n`: the value `-1 - n`.
    pub fn negint(self: Writer, n: u64) Error!void {
        try self.headOut(1, n);
    }

    pub fn bytes(self: Writer, b: []const u8) Error!void {
        try self.headOut(2, b.len);
        try self.w.writeAll(b);
    }

    /// A text string. The caller vouches for UTF-8 (as with `Value.text`).
    pub fn text(self: Writer, t: []const u8) Error!void {
        try self.headOut(3, t.len);
        try self.w.writeAll(t);
    }

    /// An array of `n` items, or an indefinite one (`null`; close with `end`).
    pub fn beginArray(self: Writer, n: ?u64) Error!void {
        if (n) |c| try self.headOut(4, c) else try self.w.writeByte(0x9f);
    }

    /// A map of `n` pairs, or an indefinite one (`null`; close with `end`).
    pub fn beginMap(self: Writer, n: ?u64) Error!void {
        if (n) |c| try self.headOut(5, c) else try self.w.writeByte(0xbf);
    }

    /// An indefinite byte string: `bytes` chunks, then `end`.
    pub fn beginBytes(self: Writer) Error!void {
        try self.w.writeByte(0x5f);
    }

    /// An indefinite text string: `text` chunks, then `end`.
    pub fn beginText(self: Writer) Error!void {
        try self.w.writeByte(0x7f);
    }

    /// The break code closing an indefinite-length item.
    pub fn end(self: Writer) Error!void {
        try self.w.writeByte(0xff);
    }

    pub fn tag(self: Writer, n: u64) Error!void {
        try self.headOut(6, n);
    }

    pub fn boolean(self: Writer, b: bool) Error!void {
        try self.w.writeByte(if (b) 0xf5 else 0xf4);
    }

    pub fn null_(self: Writer) Error!void {
        try self.w.writeByte(0xf6);
    }

    pub fn undefined_(self: Writer) Error!void {
        try self.w.writeByte(0xf7);
    }

    /// A simple value (0..19 or 32..255; 20..31 are not simple values and
    /// are a programmer error, as with `Value.simple`).
    pub fn simple(self: Writer, s: u8) Error!void {
        if (s < 20) try self.w.writeByte(0xe0 | s) else try self.w.writeAll(&.{ 0xf8, s });
    }

    /// A float in the shortest width that keeps its value (NaN as `f97e00`).
    pub fn float(self: Writer, x: f64) Error!void {
        const h = root.floatBytes(x);
        try self.w.writeAll(h.slice());
    }

    pub fn float16(self: Writer, x: f16) Error!void {
        var b: [3]u8 = .{ 0xf9, 0, 0 };
        std.mem.writeInt(u16, b[1..3], @bitCast(x), .big);
        try self.w.writeAll(&b);
    }

    pub fn float32(self: Writer, x: f32) Error!void {
        var b: [5]u8 = .{ 0xfa, 0, 0, 0, 0 };
        std.mem.writeInt(u32, b[1..5], @bitCast(x), .big);
        try self.w.writeAll(&b);
    }

    pub fn float64(self: Writer, x: f64) Error!void {
        var b: [9]u8 = .{ 0xfb, 0, 0, 0, 0, 0, 0, 0, 0 };
        std.mem.writeInt(u64, b[1..9], @bitCast(x), .big);
        try self.w.writeAll(&b);
    }

    /// A whole `Value`, byte for byte what `encode(.., .{})` returns (map
    /// order as given, float widths as given). For the canonical form, which
    /// needs scratch to sort keys, use `encode(.., .{ .canonical = true })`.
    pub fn value(self: Writer, v: Value) Error!void {
        switch (v) {
            .uint => |u| try self.uint(u),
            .negint => |n| try self.negint(n),
            .bytes => |b| try self.bytes(b),
            .text => |t| try self.text(t),
            .array => |items| {
                try self.beginArray(items.len);
                for (items) |it| try self.value(it);
            },
            .map => |entries| {
                try self.beginMap(entries.len);
                for (entries) |e| {
                    try self.value(e.key);
                    try self.value(e.value);
                }
            },
            .tag => |t| {
                try self.tag(t.number);
                try self.value(t.value.*);
            },
            .simple => |s| try self.simple(s),
            .bool => |b| try self.boolean(b),
            .null_value => try self.null_(),
            .undefined_value => try self.undefined_(),
            .f16 => |f| try self.float16(f),
            .f32 => |f| try self.float32(f),
            .f64 => |f| try self.float64(f),
        }
    }
};
