// SPDX-License-Identifier: MIT
//! framing — length-prefixed stream framing (`writeFrame`/`readFrame`) plus a
//! generic JSON tagged-union envelope codec (`EnvelopeCodec(T)`) on top.
//!
//! Wire shape: a 4-byte little-endian `u32` byte length, then that many raw
//! bytes of payload (JSON, produced by `EnvelopeCodec` or anything else). This
//! is **length-prefixed** framing, not newline-delimited — a payload may
//! freely contain `\n`, `\r`, `NUL`, or any other byte. If you need
//! newline-delimited JSON (the MCP stdio convention: one JSON object + `\n`
//! per message), that is a different framing and belongs to the `mcp` module
//! — this module does not attempt to serve MCP transports.

const std = @import("std");

pub const meta = .{
    // The module catalog's one-line entry. This IS the source of truth:
    // README.md's table is rendered from it by `zig build gen-catalog`.
    .doc = "Length-prefixed stream framing (`writeFrame`/`readFrame`) plus a generic JSON tagged-union envelope codec.",
    // The catalog's Platform cell. Prose, because it carries nuance the
    // `platform` enum below cannot -- "any (packer: linux)", "amd64 asm +
    // portable fallback". Rendered by `gen-catalog` alongside `doc`.
    .platform_note = "any",
    .targets = .{ .linux64, .linux32 },
    .platform = .any,
    .role = .codec,
    .concurrency = .reentrant,
    .model_after = "length-prefixed framing + tagged-union JSON envelope",
    .deps = .{},
};

// ── length-prefixed framing ─────────────────────────────────────────────────

/// Default hard cap on a single frame's payload. Generous vs heartbeats/
/// configs, bounds memory. Override per call via `Limits.max_frame`.
pub const default_max_frame: u32 = 1 << 20; // 1 MiB

/// The length field's width. `varint` is unsigned LEB128 (protobuf's
/// varint: 7 bits per byte, low group first, high bit = "more follows"). The
/// fixed widths cover tokio's whole 1-8 byte range, odd sizes included.
pub const Width = enum { u8, u16, u24, u32, u40, u48, u56, u64, varint };

/// The length prefix's wire format. The default — 4 bytes, little-endian,
/// payload length only — is this module's original format. tokio-util's
/// `LengthDelimitedCodec` default is `.{ .endian = .big }`; Netty's
/// `LengthFieldPrepender(2)` is `.{ .width = .u16, .endian = .big }`.
///
/// The general form is tokio's / Netty's parameter set. A frame on the wire is
/// `offset` header bytes, the length field, then the rest. With `n` the
/// number of frame bytes after the first `skip` bytes of the head:
///
///     field = n - adjustment (+ the field's own width if `includes_prefix`)
///
/// `skip` defaults to the whole head (`offset` + field), so `n` is just the
/// payload and the frame handed out starts after the field. A smaller `skip`
/// keeps the tail of the head as the start of the frame (Netty's
/// `initialBytesToStrip`); `n` then counts from there.
pub const Prefix = struct {
    width: Width = .u32,
    /// Byte order of a fixed-width field; ignored by `varint`.
    endian: std.builtin.Endian = .little,
    /// The field counts the prefix's own bytes too (field = prefix length +
    /// payload length) — tokio's `length_adjustment(-width)` case. With
    /// `varint` the prefix length is the encoding's own length, found as the
    /// fixpoint (a 127-byte payload is announced as 129 in two bytes).
    includes_prefix: bool = false,
    /// Header bytes in front of the length field (tokio `length_field_offset`).
    /// The decoder ignores their value; `writeFrame` refuses a nonzero offset,
    /// `writeFrameWithHeader` supplies them.
    offset: u8 = 0,
    /// tokio `length_adjustment` / Netty `lengthAdjustment` (same sign as
    /// tokio: the wire field is `n - adjustment`). Added to `includes_prefix`.
    adjustment: i32 = 0,
    /// Head bytes DROPPED from the front of the frame (tokio `num_skip`); null =
    /// the whole head. The head bytes kept at the front of the frame are the
    /// head minus `skip`. More than the head is `BadLength` on decode. Readers
    /// only: `writeFrame`/`writeFrameWithHeader` refuse any other value than
    /// null or the whole head with `error.SkipNotWritable`.
    skip: ?u8 = null,
};

/// Options for `writeFrame`/`readFrame`/`Decoder`. `max_frame` is a parameter
/// (not a compile-time constant) so callers can tighten or loosen the cap per
/// protocol; `.{}` uses `default_max_frame` and the original u32-LE prefix.
/// `max_frame` bounds `n`, the frame length after `adjustment` (tokio bounds
/// the raw field instead; the two agree when `adjustment` is 0).
pub const Limits = struct {
    max_frame: u32 = default_max_frame,
    prefix: Prefix = .{},
};

/// Longest length field: a 10-byte varint (64 bits in 7-bit groups).
pub const max_prefix_len = 10;
/// Longest head: `Prefix.offset` (a u8) plus the longest field.
pub const max_head_len = 255 + max_prefix_len;

fn fixedLen(w: Width) usize {
    return switch (w) {
        .u8 => 1,
        .u16 => 2,
        .u24 => 3,
        .u32 => 4,
        .u40 => 5,
        .u48 => 6,
        .u56 => 7,
        .u64 => 8,
        .varint => unreachable,
    };
}

fn writeUint(buf: []u8, value: u64, endian: std.builtin.Endian) void {
    switch (buf.len) {
        1 => buf[0] = @intCast(value),
        2 => std.mem.writeInt(u16, buf[0..2], @intCast(value), endian),
        4 => std.mem.writeInt(u32, buf[0..4], @intCast(value), endian),
        8 => std.mem.writeInt(u64, buf[0..8], value, endian),
        else => for (buf, 0..) |*b, i| {
            const k = if (endian == .little) i else buf.len - 1 - i;
            b.* = @truncate(value >> @intCast(8 * k));
        },
    }
}

fn readUint(bytes: []const u8, endian: std.builtin.Endian) u64 {
    switch (bytes.len) {
        1 => return bytes[0],
        2 => return std.mem.readInt(u16, bytes[0..2], endian),
        4 => return std.mem.readInt(u32, bytes[0..4], endian),
        8 => return std.mem.readInt(u64, bytes[0..8], endian),
        else => {
            var v: u64 = 0;
            for (bytes, 0..) |b, i| {
                const k = if (endian == .little) i else bytes.len - 1 - i;
                v |= @as(u64, b) << @intCast(8 * k);
            }
            return v;
        },
    }
}

/// `x` as a u64 when it is in range. Explicit range test, then a bit
/// reinterpretation: never `@intCast`/`std.math.cast` from a signed type to a
/// narrower unsigned one (Zig 0.17 miscompile #37131 poisons the upper half in
/// optimized builds, and these values come from a hostile length field).
fn toU64(x: i128) ?u64 {
    if (x < 0 or x > std.math.maxInt(u64)) return null;
    return @truncate(@as(u128, @bitCast(x)));
}

fn varintLen(v: u64) usize {
    var n: usize = 1;
    var x = v >> 7;
    while (x != 0) : (x >>= 7) n += 1;
    return n;
}

/// Encode the length field for a `payload_len`-byte frame into `buf`.
fn encodePrefix(buf: *[max_prefix_len]u8, payload_len: usize, p: Prefix) error{ FrameTooLarge, BadLength }![]const u8 {
    // field = n - adjustment (+ own width if includes_prefix); it may not go below zero.
    const base: i128 = @as(i128, payload_len) - p.adjustment;
    if (p.width == .varint) {
        var value: u64 = undefined;
        if (p.includes_prefix) {
            // The smallest n with varintLen(base + n) == n and base + n >= 0; it
            // exists for every base below 2^64 − 10 (the encoded length grows by
            // at most one byte per step of n).
            if (base < -max_prefix_len) return error.BadLength; // no field of that size exists
            var n: usize = if (base < 0) @intCast(@as(u8, @truncate(@as(u128, @bitCast(-base))))) else 1;
            if (n == 0) n = 1;
            while (true) : (n += 1) {
                if (n > max_prefix_len) return error.BadLength; // no field of that size exists
                const v = toU64(base + @as(i128, n)) orelse return error.FrameTooLarge;
                if (varintLen(v) == n) {
                    value = v;
                    break;
                }
            }
        } else {
            if (base < 0) return error.BadLength;
            value = toU64(base) orelse return error.FrameTooLarge;
        }
        var i: usize = 0;
        while (true) : (i += 1) {
            const low: u8 = @truncate(value & 0x7f);
            value >>= 7;
            if (value == 0) {
                buf[i] = low;
                return buf[0 .. i + 1];
            }
            buf[i] = low | 0x80;
        }
    }
    const n = fixedLen(p.width);
    const value: i128 = base + if (p.includes_prefix) @as(i128, n) else 0;
    if (value < 0) return error.BadLength;
    const limit: i128 = (@as(i128, 1) << @intCast(8 * n)) - 1;
    if (value > limit) return error.FrameTooLarge;
    writeUint(buf[0..n], toU64(value).?, p.endian); // 0 <= value <= limit checked above
    return buf[0..n];
}

const PrefixError = error{
    /// A length field the format cannot produce: a varint longer than 10
    /// bytes, past 64 bits or not minimally encoded (a trailing `0x00`
    /// group — `serialize` never writes one, and accepting it would give one
    /// frame two encodings); with `includes_prefix`, a value smaller than
    /// the prefix itself; an `adjustment` that takes the length below zero; a
    /// `skip` past the head, or a frame shorter than the head bytes it keeps.
    BadLength,
};

/// What a complete head says.
const Head = struct {
    /// `n`: the frame bytes after the first `skip` head bytes. Saturates at maxInt(u64).
    n: u64,
    /// Head bytes dropped (`skip`, resolved).
    skip: usize,
    /// Total head length: `offset` + field.
    len: usize,
};

/// Decode a complete head from `bytes`, or null if `bytes` holds only part of it.
fn decodeHead(bytes: []const u8, p: Prefix) PrefixError!?Head {
    const off: usize = p.offset;
    if (bytes.len < off) return null;
    var value: u64 = 0;
    var flen: usize = 0;
    if (p.width == .varint) {
        while (true) {
            // The cap before the "need more bytes" answer: an 11th byte is
            // never needed, so a caller must not be told to fetch one.
            if (flen == max_prefix_len) return error.BadLength;
            if (off + flen == bytes.len) return null;
            const b = bytes[off + flen];
            const group: u64 = b & 0x7f;
            // The 10th byte may carry only the top bit of a u64.
            if (flen == 9 and group > 1) return error.BadLength;
            value |= group << @intCast(7 * flen);
            flen += 1;
            if (b & 0x80 == 0) {
                if (b == 0 and flen > 1) return error.BadLength; // overlong
                break;
            }
        }
    } else {
        flen = fixedLen(p.width);
        if (bytes.len < off + flen) return null;
        value = readUint(bytes[off..][0..flen], p.endian);
    }
    var n: i128 = @as(i128, value) + p.adjustment;
    if (p.includes_prefix) n -= @as(i128, flen);
    if (n < 0) return error.BadLength;
    const head_len = off + flen;
    const skip: usize = p.skip orelse head_len;
    if (skip > head_len) return error.BadLength;
    // The head bytes kept at the front of the frame must fit inside it.
    if (n < head_len - skip) return error.BadLength;
    return .{ .n = toU64(n) orelse std.math.maxInt(u64), .skip = skip, .len = head_len };
}

/// Read the head from a stream into `hdr` (the field byte by byte for a varint).
fn readHead(r: *std.Io.Reader, p: Prefix, hdr: *[max_head_len]u8) !Head {
    const off: usize = p.offset;
    var have: usize = off + if (p.width == .varint) 1 else fixedLen(p.width);
    try r.readSliceAll(hdr[0..have]);
    while (true) {
        if (try decodeHead(hdr[0..have], p)) |h| return h;
        // Only a varint can be incomplete here, and `decodeHead` refuses one
        // that reaches `max_prefix_len`, so `have` stays in bounds.
        hdr[have] = try r.takeByte();
        have += 1;
    }
}

/// Write one length-prefixed frame to `w`. If a write fails after the prefix
/// went out, a partial frame stays on the writer, which is then out of step and
/// must be dropped; and a writer shared between threads must be locked around
/// the call, because the prefix and the payload are two separate writes.
///
/// Errors, all returned before anything is written except the writer's own
/// (`WriteFailed`, which may leave a partial frame): `FrameTooLarge` (payload
/// above `limits.max_frame` -- the same bound `readFrame` applies, to the same
/// number, because `n` equals the payload length for every prefix a writer
/// accepts -- or above what the width can announce: 255 for `.u8`, ...),
/// `BadLength` (an `adjustment` that takes the field below zero),
/// `HeaderRequired` (`offset > 0`: use `writeFrameWithHeader`) and
/// `SkipNotWritable` (`Prefix.skip` other than null or the whole head: such a
/// frame includes head bytes the writer does not produce, so the same `Limits`
/// would not read back what was written). tokio, by contrast, bounds the raw
/// length FIELD by its `max_frame_length`; here the bound is on `n`.
pub fn writeFrame(w: *std.Io.Writer, payload: []const u8, limits: Limits) !void {
    if (limits.prefix.offset != 0) return error.HeaderRequired;
    return writeFrameWithHeader(w, "", payload, limits);
}

/// `writeFrame` for a prefix with `offset` header bytes: `header` is written
/// in front of the length field and must be exactly `limits.prefix.offset`
/// long (`error.HeaderRequired` otherwise). The same errors as `writeFrame`;
/// as there, a failing write after the first one leaves a partial frame
/// (header, or header and field) on `w`, which must then be dropped.
pub fn writeFrameWithHeader(w: *std.Io.Writer, header: []const u8, payload: []const u8, limits: Limits) !void {
    if (header.len != limits.prefix.offset) return error.HeaderRequired;
    if (payload.len > limits.max_frame) return error.FrameTooLarge;
    var hdr: [max_prefix_len]u8 = undefined;
    const field = try encodePrefix(&hdr, payload.len, limits.prefix);
    if (limits.prefix.skip) |sk| if (sk != header.len + field.len) return error.SkipNotWritable;
    try w.writeAll(header);
    try w.writeAll(field);
    try w.writeAll(payload);
}

/// `error.EndOfStream` means both a clean close between frames and a stream
/// truncated inside a frame (prefix or payload); this function cannot tell them
/// apart, so a caller that must distinguish them tracks whether any byte of the
/// current frame was seen.
///
/// Read one frame from `r` into `buf`; returns the payload sub-slice of
/// `buf`. Fails with `error.FrameTooLarge` if the announced length exceeds
/// either `limits.max_frame` or `buf.len`, and `error.BadLength` on a length
/// field the format cannot produce.
pub fn readFrame(r: *std.Io.Reader, buf: []u8, limits: Limits) ![]u8 {
    var hdr: [max_head_len]u8 = undefined;
    const h = try readHead(r, limits.prefix, &hdr);
    if (h.n > limits.max_frame or h.n > buf.len) return error.FrameTooLarge;
    const n: usize = @intCast(h.n);
    const kept = h.len - h.skip; // <= n: decodeHead checked
    @memcpy(buf[0..kept], hdr[h.skip..h.len]);
    const dst = buf[0..n];
    try r.readSliceAll(dst[kept..]);
    return dst;
}

/// Read one frame, allocating exactly the announced payload length.
///
/// The reason this exists rather than callers sizing a buffer themselves: the
/// obvious way to write a server loop is to allocate `limits.max_frame` per
/// connection and hand it to `readFrame`, which makes every connection cost
/// the CAP — 1 MiB by default — no matter how small the actual request is, and
/// lets anyone who can open connections choose that cost. Reading the 4-byte
/// header first and allocating against it keeps the cap as a rejection
/// threshold instead of a per-connection price.
///
/// The length is still checked against `limits.max_frame` BEFORE allocating,
/// so an announced 4 GiB is refused rather than attempted. Caller owns the
/// returned slice.
///
/// A frame larger than 16 KiB is not allocated at its announced size: the
/// buffer grows as the bytes actually arrive, so a peer that announces
/// `max_frame` and then stalls costs memory in proportion to what it sent.
/// How long to wait for the rest is the `Reader`'s business (a socket
/// reader's timeout), not this function's.
pub fn readFrameAlloc(r: *std.Io.Reader, gpa: std.mem.Allocator, limits: Limits) ![]u8 {
    var hdr: [max_head_len]u8 = undefined;
    const h = try readHead(r, limits.prefix, &hdr);
    if (h.n > limits.max_frame) return error.FrameTooLarge;
    const len: usize = @intCast(h.n); // <= max_frame, a u32: fits usize on every target
    const kept = h.len - h.skip; // <= len: decodeHead checked
    if (len <= alloc_chunk) {
        const dst = try gpa.alloc(u8, len);
        errdefer gpa.free(dst);
        @memcpy(dst[0..kept], hdr[h.skip..h.len]);
        try r.readSliceAll(dst[kept..]);
        return dst;
    }
    // A big announced length is believed only as the bytes arrive: the buffer
    // grows by what was actually read (doubling, so the copying stays linear),
    // never to the announced size up front. A peer that announces `max_frame`
    // and then stalls or hangs up costs one chunk, not `max_frame` per
    // connection.
    var list: std.ArrayList(u8) = .empty;
    errdefer list.deinit(gpa);
    try list.appendSlice(gpa, hdr[h.skip..h.len]);
    while (list.items.len < len) {
        const want = @min(len - list.items.len, @max(alloc_chunk, list.items.len));
        const dst = try list.addManyAsSlice(gpa, want);
        try r.readSliceAll(dst);
    }
    return list.toOwnedSlice(gpa); // exactly `len` bytes: `gpa.free` of the result is valid
}

/// First allocation step of `readFrameAlloc` for a frame whose announced
/// length is larger than this.
const alloc_chunk = 16 * 1024;

// ── incremental decoder ─────────────────────────────────────────────────────

/// Frames out of bytes that arrive in arbitrary pieces — for an event loop
/// that cannot block in `readFrame`. `feed` what was received, then call
/// `next` until it returns null:
///
///     var d: Decoder = .init(.{ .max_frame = 64 * 1024 });
///     defer d.deinit(gpa);
///     try d.feed(gpa, received);
///     while (try d.next()) |frame| handle(frame);
///
/// A frame slice is valid until the next `feed`. The announced length is
/// checked as soon as the prefix is complete — an oversize frame is refused
/// before its body arrives, not after it was buffered. After an error the
/// stream is out of step and every later `next` returns the same error.
/// Memory: at most one incomplete frame (prefix + `max_frame`) plus what one
/// `feed` brings; `feed` refuses to grow past that when the caller has not
/// drained the frames already complete (`error.NotDrained`).
pub const Decoder = struct {
    limits: Limits,
    pending: std.ArrayList(u8) = .empty,
    start: usize = 0,
    failed: ?DecodeError = null,

    pub const DecodeError = error{ FrameTooLarge, BadLength };

    pub fn init(limits: Limits) Decoder {
        return .{ .limits = limits };
    }

    pub fn deinit(d: *Decoder, gpa: std.mem.Allocator) void {
        d.pending.deinit(gpa);
        d.* = undefined;
    }

    /// Bytes buffered and not yet returned as a frame.
    pub fn buffered(d: *const Decoder) usize {
        return d.pending.items.len - d.start;
    }

    pub fn feed(d: *Decoder, gpa: std.mem.Allocator, bytes: []const u8) (std.mem.Allocator.Error || error{NotDrained})!void {
        // Saturating: on a 32-bit target `max_frame = maxInt(u32)` plus the prefix
        // would overflow `usize` (a panic in safe builds, a wrapped, tiny limit in ReleaseFast).
        if (d.buffered() > @as(usize, d.limits.max_frame) +| max_prefix_len +| d.limits.prefix.offset) return error.NotDrained;
        if (d.start > 0) {
            // Drop what was consumed; the slices handed out are now invalid.
            const rest = d.pending.items[d.start..];
            std.mem.copyForwards(u8, d.pending.items[0..rest.len], rest);
            d.pending.shrinkRetainingCapacity(rest.len);
            d.start = 0;
        }
        try d.pending.appendSlice(gpa, bytes);
    }

    /// The next complete frame's payload, or null when more bytes are needed.
    pub fn next(d: *Decoder) DecodeError!?[]const u8 {
        if (d.failed) |e| return e;
        const avail = d.pending.items[d.start..];
        const h = (decodeHead(avail, d.limits.prefix) catch |e| return d.fail(e)) orelse return null;
        if (h.n > d.limits.max_frame) return d.fail(error.FrameTooLarge);
        const len: usize = @intCast(h.n);
        if (avail.len - h.skip < len) return null;
        d.start += h.skip + len;
        return avail[h.skip..][0..len];
    }

    fn fail(d: *Decoder, e: DecodeError) DecodeError {
        d.failed = e;
        return e;
    }
};

// ── generic JSON tagged-union envelope codec ────────────────────────────────

/// Default cap on JSON nesting depth accepted by `EnvelopeCodec(T).parse`.
/// Deep enough that no hand-written envelope will ever reach it (JSON-RPC-
/// shaped messages sit at 3-5), shallow enough that the per-level cost of a
/// dynamic `std.json.Value` cannot be amplified by a full frame of `[`.
pub const default_max_json_depth: u16 = 64;

/// Parse-side limits for `EnvelopeCodec(T).parseLimited`. Separate from
/// `Limits` (which is about frame bytes) because this one only bites when `T`
/// embeds a dynamic `std.json.Value`.
pub const JsonLimits = struct {
    max_depth: u16 = default_max_json_depth,
};

/// True when no `[`/`{` in `bytes` nests deeper than `max_depth`. One pass, no
/// allocation, and string-aware: brackets inside a JSON string (including
/// after a `\\` escape) are text, not structure, so a payload that merely
/// CONTAINS `"[[[[…"` is not penalised. Runs before `std.json` sees the input,
/// which is the point — rejecting afterwards would already have paid for the
/// allocations.
pub fn jsonDepthWithin(bytes: []const u8, max_depth: u16) bool {
    var depth: usize = 0;
    var in_string = false;
    var escaped = false;
    for (bytes) |c| {
        if (in_string) {
            if (escaped) {
                escaped = false;
            } else switch (c) {
                '\\' => escaped = true,
                '"' => in_string = false,
                else => {},
            }
            continue;
        }
        switch (c) {
            '"' => in_string = true,
            '[', '{' => {
                depth += 1;
                if (depth > max_depth) return false;
            },
            ']', '}' => depth -|= 1,
            else => {},
        }
    }
    return true;
}

/// A JSON envelope codec over any `T` that is a `union(enum)` whose payload
/// types are `std.json`-serializable. Zig's `std.json.Stringify` serializes a
/// plain tagged union as a tag-keyed object `{"<tag>": {...}}` by default —
/// the union tag *is* the message type on the wire, no separate discriminator
/// field is needed (this holds even when a payload struct itself contains an
/// inner `enum` field: that field serializes as its tag name, a plain JSON
/// string).
///
/// ## `T` should be fixed-shape — and what happens when it is not
///
/// With a fixed-shape `T` (structs, enums, ints, fixed arrays, slices of
/// those) the parse cost is bounded by the frame: `std.json`'s
/// `max_value_len` defaults to the input length, so every string/array
/// allocation is already self-bounded by `limits.max_frame`, and the type's
/// own nesting depth is a compile-time constant.
///
/// A `T` that embeds a **dynamic `std.json.Value`** field is different: that
/// sub-value's shape comes from the wire, so its nesting depth is bounded only
/// by the frame length. It will not smash the stack on the way IN
/// (`std.json.Value.jsonParse` is iterative — an explicit heap stack, not
/// call-frame recursion), but a 1 MiB frame of `[[[[…` still becomes ~1M live
/// container objects, an allocation amplification of one input byte into tens
/// of bytes; and `Value`'s *stringify* IS recursive, so echoing such a value
/// back out through `encodeAlloc` would then overflow the native stack.
///
/// ## Memory is not bounded by `max_frame` alone
///
/// Allocation follows the number of JSON elements, not only the byte count:
/// `[{},{},{}…]` costs 3 bytes per element on the wire but `@sizeOf(element)`
/// in memory (a `std.json.Value` is roughly ten times its text). So a frame of
/// `max_frame` bytes can allocate `max_frame` times the element-size ratio.
/// Tighten `max_frame` to what the protocol needs and cap how many parses run
/// concurrently.
///
/// `parse` therefore refuses more than `default_max_json_depth` levels of
/// nesting before `std.json` ever sees the bytes (`parseLimited` to choose
/// your own cap). The check costs one allocation-free pass and is a no-op for
/// the fixed-shape case, whose depth is a constant well under the cap.
pub fn EnvelopeCodec(comptime T: type) type {
    if (@typeInfo(T) != .@"union") @compileError("EnvelopeCodec(T): T must be a union(enum)");

    return struct {
        /// Encode `msg` to freshly-allocated JSON bytes (caller frees).
        pub fn encodeAlloc(msg: T, gpa: std.mem.Allocator) ![]u8 {
            return std.json.Stringify.valueAlloc(gpa, msg, .{});
        }

        /// Parse JSON bytes into a `T`. Caller calls `.deinit()` on the
        /// result. Nesting deeper than `default_max_json_depth` is rejected
        /// with `error.JsonNestingTooDeep` — see the type doc for why that
        /// matters only when `T` embeds a dynamic `std.json.Value`.
        pub fn parse(gpa: std.mem.Allocator, bytes: []const u8) !std.json.Parsed(T) {
            return parseLimited(gpa, bytes, .{});
        }

        /// `parse` with a caller-chosen nesting cap. Use it when `T` embeds a
        /// `std.json.Value` whose legitimate depth is known — tighter than the
        /// default is the useful direction; raising it re-opens exactly the
        /// amplification the default exists to bound.
        pub fn parseLimited(
            gpa: std.mem.Allocator,
            bytes: []const u8,
            limits: JsonLimits,
        ) !std.json.Parsed(T) {
            if (!jsonDepthWithin(bytes, limits.max_depth)) return error.JsonNestingTooDeep;
            // `.alloc_always`: the result never aliases `bytes`, so the frame buffer can be
            // reused or freed while the parsed value lives.
            return std.json.parseFromSlice(T, gpa, bytes, .{ .allocate = .alloc_always });
        }

        /// Encode + frame onto `w` in one step, using `gpa` for the scratch
        /// JSON buffer (freed before returning).
        pub fn writeFramed(msg: T, gpa: std.mem.Allocator, w: *std.Io.Writer, limits: Limits) !void {
            const json = try encodeAlloc(msg, gpa);
            defer gpa.free(json);
            try writeFrame(w, json, limits);
        }
    };
}

// ── tests: writeFrame/readFrame ─────────────────────────────────────────────

test {
    _ = @import("sweep_test.zig");
}

test "frame round-trip" {
    const t = std.testing;
    var out: [256]u8 = undefined;
    var w: std.Io.Writer = .fixed(&out);
    try writeFrame(&w, "hello", .{});
    try writeFrame(&w, "world!!", .{});
    try writeFrame(&w, "", .{}); // empty payload is valid

    var r: std.Io.Reader = .fixed(w.buffered());
    var rb: [256]u8 = undefined;
    try t.expectEqualStrings("hello", try readFrame(&r, &rb, .{}));
    try t.expectEqualStrings("world!!", try readFrame(&r, &rb, .{}));
    try t.expectEqualStrings("", try readFrame(&r, &rb, .{}));
}

test "payload larger than read buffer is rejected" {
    const t = std.testing;
    var out: [64]u8 = undefined;
    var w: std.Io.Writer = .fixed(&out);
    try writeFrame(&w, "0123456789", .{}); // 10-byte payload

    var r: std.Io.Reader = .fixed(w.buffered());
    var tiny: [4]u8 = undefined;
    try t.expectError(error.FrameTooLarge, readFrame(&r, &tiny, .{}));
}

test "writeFrame rejects oversize payload" {
    const t = std.testing;
    var sink: [8]u8 = undefined;
    var w: std.Io.Writer = .fixed(&sink);
    const limits = Limits{ .max_frame = 16 };
    const huge = limits.max_frame + 1;
    // a slice with len > max_frame (no backing needed; len check happens first)
    const fake: []const u8 = @as([*]const u8, @ptrFromInt(0x1000))[0..huge];
    try t.expectError(error.FrameTooLarge, writeFrame(&w, fake, limits));
}

test "writeFrame accepts a payload exactly at max_frame (audit F1)" {
    // Boundary: payload.len == max_frame must succeed, not be rejected — only
    // payload.len > max_frame is oversize. Only the +1-over case was tested.
    var out: [32]u8 = undefined;
    var w: std.Io.Writer = .fixed(&out);
    const limits = Limits{ .max_frame = 8 };
    try writeFrame(&w, "01234567", limits); // exactly 8 bytes == max_frame
}

test "readFrame accepts a payload exactly filling buf (audit F2)" {
    // Boundary: len == buf.len must succeed — only the strictly-larger case
    // (10-byte payload into a 4-byte buf) was tested.
    const t = std.testing;
    var out: [16]u8 = undefined;
    var w: std.Io.Writer = .fixed(&out);
    try writeFrame(&w, "abcd", .{}); // 4-byte payload

    var r: std.Io.Reader = .fixed(w.buffered());
    var exact: [4]u8 = undefined; // buf.len == payload len exactly
    try t.expectEqualStrings("abcd", try readFrame(&r, &exact, .{}));
}

test "readFrame enforces max_frame even when the buffer is larger" {
    const t = std.testing;
    var out: [64]u8 = undefined;
    var w: std.Io.Writer = .fixed(&out);
    // default limits: announce a 20-byte frame, no cap violation at write time
    try writeFrame(&w, "01234567890123456789", .{});

    var r: std.Io.Reader = .fixed(w.buffered());
    var roomy: [4096]u8 = undefined; // buffer is plenty big
    // but a tighter protocol cap on the read side should still reject it
    try t.expectError(error.FrameTooLarge, readFrame(&r, &roomy, .{ .max_frame = 8 }));
}

// ── fuzz: length-prefixed frame read off an untrusted stream, never panics ──
//
// `readFrame` is what any consumer of this framing (`ipcbus`, an
// `EnvelopeCodec`-based protocol) runs directly on bytes from a socket or
// pipe — the 4-byte length prefix is exactly attacker-controlled before any
// bound has been checked.

// ⛔ This harness used to fetch the stream and then throw it away:
// `smith.bytes(&buf)` copies `min(buf.len, in.len)` octets, and the
// `valueRangeAtMost(u16, 0, buf.len)` right after it reads EIGHT more as a
// little-endian u64 and returns the range MINIMUM when fewer remain — so `len`
// was 0 for every input a corpus can carry, and `readFrame` was handed an
// EMPTY reader on every iteration, failing at `takeArray(4)` before it had
// looked at a length prefix at all. It carried no corpus either, so that empty
// stream was the only input it ever ran: the 4-byte header this module exists
// to bound-check had never been decoded once inside the harness.
const testkit = @import("testkit");
const seed = testkit.fuzz.seed;

/// Whole streams, in the format the length draw reads. The interesting
/// variable is the announced `u32` against `buf.len` and `max_frame`, so the
/// corpus is a ladder over the header with the payload deliberately short,
/// truthful and lying.
const frame_seeds = [_][]const u8{
    seed("\x04\x00\x00\x00abcd"), // a truthful 4-octet frame
    seed("\x00\x00\x00\x00"), // the zero-length frame: legal, empty payload
    seed("\x80\x00\x00\x00" ++ strRepeat("x", 128)), // exactly `out.len`: the boundary that must pass
    seed("\x81\x00\x00\x00" ++ strRepeat("x", 129)), // ⭐ one past `out.len`: FrameTooLarge
    seed("\xff\xff\xff\xff" ++ "abcd"), // 4 GiB announced, 4 octets present: refused before allocating
    seed("\x00\x00\x10\x00"), // exactly `default_max_frame`, no payload: too large for `out`, allocatable
    seed("\x01\x00\x10\x00"), // one past `default_max_frame`: refused by the cap itself
    seed("\x08\x00\x00\x00" ++ "abc"), // a truthful header with the payload cut short: ReadFailed
    seed("\x04\x00\x00\x00abcd" ++ "\x03\x00\x00\x00xyz"), // two frames back to back; only the first is read
    seed("\x02\x00\x00\x00\x0a\x00"), // a payload that is NUL and newline: not a delimiter here
    seed("\xff\x00"), // a header cut in half
    seed(""), // the empty stream: what the collapsed harness ran, every time
};

test "fuzz: readFrame never panics on an arbitrary stream" {
    try std.testing.fuzz({}, fuzzReadFrame, .{ .corpus = &frame_seeds });
}

fn fuzzReadFrame(_: void, smith: *std.testing.Smith) !void {
    var buf: [512]u8 = undefined;
    const len: usize = smith.slice(&buf);

    var r: std.Io.Reader = .fixed(buf[0..len]);
    var out: [128]u8 = undefined;
    _ = readFrame(&r, &out, .{}) catch {};

    // The allocating twin bounds the SAME attacker-chosen `u32` without a
    // caller buffer to clamp it, so it takes a different branch on exactly the
    // frames that matter (an announced 4 GiB is refused, not attempted).
    var r2: std.Io.Reader = .fixed(buf[0..len]);
    const owned = readFrameAlloc(&r2, std.testing.allocator, .{}) catch return;
    std.testing.allocator.free(owned);
}

test "corpus: every stream seed reaches the header decode, and the payload octets are pinned" {
    // ⭐ Not `accepted > 0`: the zero-length frame is a LEGAL frame here, so a
    // guard counting successes would read healthy on a corpus that never moved
    // a payload octet. The number the empty stream cannot produce is the
    // payload actually delivered, and the count refused for being too large.
    var nonempty: usize = 0;
    var frames: usize = 0;
    var payload_octets: usize = 0;
    var too_large: usize = 0;
    for (frame_seeds) |sd| {
        var smith: std.testing.Smith = .{ .in = sd };
        var buf: [512]u8 = undefined;
        const len: usize = smith.slice(&buf);
        if (len != 0) nonempty += 1;
        var r: std.Io.Reader = .fixed(buf[0..len]);
        var out: [128]u8 = undefined;
        if (readFrame(&r, &out, .{})) |p| {
            frames += 1;
            payload_octets += p.len;
        } else |e| {
            if (e == error.FrameTooLarge) too_large += 1;
        }
    }
    // One seed is deliberately the empty stream.
    try std.testing.expectEqual(frame_seeds.len - 1, nonempty);
    // Measured 2026-09-07: 0 frames, 0 payload octets and 0 refusals before the
    // draw was fixed — every iteration ran out of input inside `takeArray(4)`.
    try std.testing.expectEqual(@as(usize, 5), frames);
    try std.testing.expectEqual(@as(usize, 138), payload_octets);
    try std.testing.expectEqual(@as(usize, 4), too_large);
}

// ── tests: EnvelopeCodec(T), on a domain-free test-only union ───────────────

const TestStatus = enum { idle, running, done };

const TestEmpty = struct {
    id: u64 = 0,
};

const TestBlob = struct {
    id: u64 = 0,
    data: []const u8 = "",
};

const TestPing = struct {
    id: u64 = 0,
    state: TestStatus,
};

/// Domain-free stand-in for a real protocol union (e.g. a message enum) —
/// exercises the same shapes without importing any project-specific types.
const TestEnvelope = union(enum) {
    empty: TestEmpty,
    blob: TestBlob,
    ping: TestPing,
};

const TestCodec = EnvelopeCodec(TestEnvelope);

test "envelope round-trip (normal payload)" {
    const t = std.testing;
    const gpa = t.allocator;
    const msg: TestEnvelope = .{ .blob = .{ .id = 7, .data = "hello envelope" } };

    const bytes = try TestCodec.encodeAlloc(msg, gpa);
    defer gpa.free(bytes);

    const parsed = try TestCodec.parse(gpa, bytes);
    defer parsed.deinit();

    try t.expect(parsed.value == .blob);
    try t.expectEqual(@as(u64, 7), parsed.value.blob.id);
    try t.expectEqualStrings("hello envelope", parsed.value.blob.data);
}

test "envelope round-trip (empty payload)" {
    const t = std.testing;
    const gpa = t.allocator;
    const msg: TestEnvelope = .{ .empty = .{ .id = 3 } };

    const bytes = try TestCodec.encodeAlloc(msg, gpa);
    defer gpa.free(bytes);

    const parsed = try TestCodec.parse(gpa, bytes);
    defer parsed.deinit();

    try t.expect(parsed.value == .empty);
    try t.expectEqual(@as(u64, 3), parsed.value.empty.id);

    // and a struct payload with a default-empty string field
    const blank: TestEnvelope = .{ .blob = .{ .id = 4 } };
    const bb = try TestCodec.encodeAlloc(blank, gpa);
    defer gpa.free(bb);
    const bp = try TestCodec.parse(gpa, bb);
    defer bp.deinit();
    try t.expectEqualStrings("", bp.value.blob.data);
}

test "envelope round-trip (enum-payload variant)" {
    const t = std.testing;
    const gpa = t.allocator;
    // proves a union containing an inner `enum` field still serializes as a
    // tag-keyed object with the inner enum as a plain JSON string.
    const msg: TestEnvelope = .{ .ping = .{ .id = 1, .state = .running } };

    const bytes = try TestCodec.encodeAlloc(msg, gpa);
    defer gpa.free(bytes);
    try t.expect(std.mem.find(u8, bytes, "\"ping\"") != null);
    try t.expect(std.mem.find(u8, bytes, "\"running\"") != null);

    const parsed = try TestCodec.parse(gpa, bytes);
    defer parsed.deinit();
    try t.expect(parsed.value == .ping);
    try t.expectEqual(TestStatus.running, parsed.value.ping.state);
}

test "envelope round-trip (embedded newline + binary bytes, proves not newline-delimited)" {
    const t = std.testing;
    const gpa = t.allocator;
    const raw = "line one\nline two\r\n\x00tail"; // \n, \r\n and a NUL byte
    const msg: TestEnvelope = .{ .blob = .{ .id = 9, .data = raw } };

    const bytes = try TestCodec.encodeAlloc(msg, gpa);
    defer gpa.free(bytes);

    const parsed = try TestCodec.parse(gpa, bytes);
    defer parsed.deinit();
    try t.expect(parsed.value == .blob);
    try t.expectEqualStrings(raw, parsed.value.blob.data);
}

test "envelope encodes through the wire frame" {
    const t = std.testing;
    const gpa = t.allocator;
    var out: [512]u8 = undefined;
    var w: std.Io.Writer = .fixed(&out);

    const msg: TestEnvelope = .{ .ping = .{ .id = 5, .state = .done } };
    try TestCodec.writeFramed(msg, gpa, &w, .{});

    var r: std.Io.Reader = .fixed(w.buffered());
    var rb: [512]u8 = undefined;
    const payload = try readFrame(&r, &rb, .{});
    const parsed = try TestCodec.parse(gpa, payload);
    defer parsed.deinit();
    try t.expectEqual(TestStatus.done, parsed.value.ping.state);
}

test "envelope writeFramed rejects oversize payload" {
    const t = std.testing;
    const gpa = t.allocator;
    var out: [64]u8 = undefined;
    var w: std.Io.Writer = .fixed(&out);

    // a data field long enough that the encoded JSON exceeds a tiny cap
    const msg: TestEnvelope = .{ .blob = .{ .id = 1, .data = strRepeat("0123456789", 4) } };
    try t.expectError(error.FrameTooLarge, TestCodec.writeFramed(msg, gpa, &w, .{ .max_frame = 8 }));
}

test "readFrameAlloc: allocation follows the frame, not the cap" {
    // A fixed buffer far smaller than `max_frame`: if the implementation ever
    // goes back to allocating the cap, this runs out of memory instead of
    // quietly costing a megabyte per connection where nobody would notice.
    var scratch: [64]u8 = undefined;
    var fba = std.heap.FixedBufferAllocator.init(&scratch);

    var wire = [_]u8{ 5, 0, 0, 0 } ++ "hello".*;
    var r: std.Io.Reader = .fixed(&wire);
    const got = try readFrameAlloc(&r, fba.allocator(), .{}); // .{} = 1 MiB cap
    defer fba.allocator().free(got);
    try std.testing.expectEqualStrings("hello", got);
    try std.testing.expect(fba.end_index <= 8);
}

test "readFrameAlloc: an oversize announced length is refused before allocating" {
    // The header claims 4 GiB and the body never arrives. Checking the cap
    // first means this is a clean error, not an allocation attempt or a wait.
    var wire = [_]u8{ 0xff, 0xff, 0xff, 0xff };
    var r: std.Io.Reader = .fixed(&wire);
    try std.testing.expectError(
        error.FrameTooLarge,
        readFrameAlloc(&r, std.testing.failing_allocator, .{}),
    );
}

// ── dynamic-payload depth guard ─────────────────────────────────────────────
//
// The case the guard exists for: an envelope whose payload is a raw
// `std.json.Value`, i.e. a shape chosen by the sender rather than by `T`.

const DynEnvelope = union(enum) {
    /// Deliberately dynamic — the shape F1 warns about.
    passthrough: std.json.Value,
    ping: struct { seq: u32 },
};

/// `"[" * n ++ "]" * n` wrapped in the `passthrough` variant.
fn nestedDyn(gpa: std.mem.Allocator, n: usize) ![]u8 {
    var out: std.ArrayList(u8) = .empty;
    errdefer out.deinit(gpa);
    try out.appendSlice(gpa, "{\"passthrough\":");
    try out.appendNTimes(gpa, '[', n);
    try out.appendNTimes(gpa, ']', n);
    try out.appendSlice(gpa, "}");
    return out.toOwnedSlice(gpa);
}

test "envelope: a dynamic payload nested past the cap is refused before std.json sees it" {
    const t = std.testing;
    const gpa = t.allocator;
    const Codec = EnvelopeCodec(DynEnvelope);

    // Just inside the cap parses…
    {
        const bytes = try nestedDyn(gpa, default_max_json_depth - 1);
        defer gpa.free(bytes);
        var parsed = try Codec.parse(gpa, bytes);
        defer parsed.deinit();
        try t.expect(parsed.value == .passthrough);
    }
    // …one level past it does not. Literal arithmetic on the constant, so
    // moving `default_max_json_depth` moves both sides of this test together
    // while the two assertions below pin the VALUE itself.
    {
        const bytes = try nestedDyn(gpa, default_max_json_depth + 1);
        defer gpa.free(bytes);
        try t.expectError(error.JsonNestingTooDeep, Codec.parse(gpa, bytes));
    }
    // A frame-sized wall of brackets — the actual amplification input — is
    // refused at a fixed, tiny cost rather than turned into ~1M live objects.
    {
        const bytes = try nestedDyn(gpa, 100_000);
        defer gpa.free(bytes);
        try t.expectError(error.JsonNestingTooDeep, Codec.parse(gpa, bytes));
    }
    // The cap is a parameter: a caller who knows its payloads are flat can
    // tighten it, and the tightened value is the one that decides.
    {
        // 5 nested arrays inside the envelope object = depth 6, the object
        // itself being level 1 — the cap counts the whole document, which is
        // what bounds the work.
        const bytes = try nestedDyn(gpa, 5);
        defer gpa.free(bytes);
        try t.expectError(
            error.JsonNestingTooDeep,
            Codec.parseLimited(gpa, bytes, .{ .max_depth = 5 }),
        );
        var parsed = try Codec.parseLimited(gpa, bytes, .{ .max_depth = 6 });
        parsed.deinit();
    }
}

test "depth scan counts structure, not text: brackets inside strings are payload" {
    const t = std.testing;
    // The pinned default, so a change to it is a deliberate edit here.
    try t.expectEqual(@as(u16, 64), default_max_json_depth);

    // 500 brackets, all inside one JSON string → depth 2, accepted.
    const gpa = t.allocator;
    var buf: std.ArrayList(u8) = .empty;
    defer buf.deinit(gpa);
    try buf.appendSlice(gpa, "{\"passthrough\":\"");
    try buf.appendNTimes(gpa, '[', 500);
    try buf.appendSlice(gpa, "\"}");
    var parsed = try EnvelopeCodec(DynEnvelope).parse(gpa, buf.items);
    defer parsed.deinit();
    try t.expectEqualStrings(
        buf.items[16 .. buf.items.len - 2],
        parsed.value.passthrough.string,
    );

    // …and an escaped quote does not end the string early, so the brackets
    // after it are still text. `\"` then 200 '[' then the real closing quote.
    try t.expect(jsonDepthWithin("{\"a\":\"\\\"" ++ (strRepeat("[", 200)) ++ "\"}", 8));
    // The same brackets OUTSIDE a string are structure, and are counted.
    try t.expect(!jsonDepthWithin("{\"a\":" ++ (strRepeat("[", 200)), 8));
    // A closing bracket pops, so a long flat sequence never accumulates.
    try t.expect(jsonDepthWithin(strRepeat("[]", 1000), 2));
    // Unbalanced closers saturate at zero instead of wrapping around.
    try t.expect(jsonDepthWithin(strRepeat("]", 100) ++ "[", 1));
}

// ── tests: prefix formats and the incremental decoder (2026-10-04) ──────────

fn framed(buf: []u8, payload: []const u8, limits: Limits) ![]const u8 {
    var w: std.Io.Writer = .fixed(buf);
    try writeFrame(&w, payload, limits);
    return w.buffered();
}

test "prefix formats: exact wire bytes, derived by hand" {
    const t = std.testing;
    var b: [64]u8 = undefined;
    // Default: u32 little-endian — unchanged.
    try t.expectEqualSlices(u8, "\x03\x00\x00\x00abc", try framed(&b, "abc", .{}));
    try t.expectEqualSlices(u8, "\x00\x00\x00\x03abc", try framed(&b, "abc", .{ .prefix = .{ .endian = .big } }));
    try t.expectEqualSlices(u8, "\x00\x03abc", try framed(&b, "abc", .{ .prefix = .{ .width = .u16, .endian = .big } }));
    try t.expectEqualSlices(u8, "\x03\x00abc", try framed(&b, "abc", .{ .prefix = .{ .width = .u16 } }));
    try t.expectEqualSlices(u8, "\x03abc", try framed(&b, "abc", .{ .prefix = .{ .width = .u8 } }));
    try t.expectEqualSlices(u8, "\x00\x00\x00\x00\x00\x00\x00\x01x", try framed(&b, "x", .{ .prefix = .{ .width = .u64, .endian = .big } }));
    // The length counts the prefix: 4 + 5 = 9.
    try t.expectEqualSlices(u8, "\x00\x00\x00\x09hello", try framed(&b, "hello", .{ .prefix = .{ .endian = .big, .includes_prefix = true } }));
    try t.expectEqualSlices(u8, "\x03ab", try framed(&b, "ab", .{ .prefix = .{ .width = .u8, .includes_prefix = true } })); // 1 + 2
    try t.expectEqualSlices(u8, "\x00", try framed(&b, "", .{ .prefix = .{ .width = .varint } }));
}

test "varint prefix: protobuf's 300 = ac 02, and the includes_prefix fixpoint" {
    const t = std.testing;
    var b: [400]u8 = undefined;
    const p300 = @as([300]u8, @splat('z'));
    const f = try framed(&b, &p300, .{ .prefix = .{ .width = .varint } });
    // protobuf encoding guide: 300 → 0xAC 0x02.
    try t.expectEqualSlices(u8, &.{ 0xac, 0x02 }, f[0..2]);
    try t.expectEqual(@as(usize, 302), f.len);
    // 127 is the largest one-byte varint, 128 the smallest two-byte one.
    const p127 = @as([127]u8, @splat('a'));
    try t.expectEqualSlices(u8, &.{0x7f}, (try framed(&b, &p127, .{ .prefix = .{ .width = .varint } }))[0..1]);
    const p128 = @as([128]u8, @splat('a'));
    try t.expectEqualSlices(u8, &.{ 0x80, 0x01 }, (try framed(&b, &p128, .{ .prefix = .{ .width = .varint } }))[0..2]);
    // includes_prefix: 126 + 1 = 127 fits one byte; 127 + 1 = 128 does not,
    // so it takes two: 127 + 2 = 129 = 0x81 0x01.
    const ip = Prefix{ .width = .varint, .includes_prefix = true };
    const p126 = @as([126]u8, @splat('a'));
    try t.expectEqualSlices(u8, &.{0x7f}, (try framed(&b, &p126, .{ .prefix = ip }))[0..1]);
    try t.expectEqualSlices(u8, &.{ 0x81, 0x01 }, (try framed(&b, &p127, .{ .prefix = ip }))[0..2]);
}

test "every format round-trips through readFrame, readFrameAlloc and the Decoder" {
    const t = std.testing;
    const widths = [_]Width{ .u8, .u16, .u32, .u64, .varint };
    const payloads = [_][]const u8{ "", "a", "hello world", &(@as([200]u8, @splat(0xff))) };
    for (widths) |wd| for ([_]std.builtin.Endian{ .little, .big }) |en| for ([_]bool{ false, true }) |inc| {
        const limits: Limits = .{ .prefix = .{ .width = wd, .endian = en, .includes_prefix = inc } };
        var out: [2048]u8 = undefined;
        var w: std.Io.Writer = .fixed(&out);
        for (payloads) |pl| try writeFrame(&w, pl, limits);
        var r: std.Io.Reader = .fixed(w.buffered());
        var rb: [256]u8 = undefined;
        for (payloads) |pl| try t.expectEqualSlices(u8, pl, try readFrame(&r, &rb, limits));
        var r2: std.Io.Reader = .fixed(w.buffered());
        for (payloads) |pl| {
            const got = try readFrameAlloc(&r2, t.allocator, limits);
            defer t.allocator.free(got);
            try t.expectEqualSlices(u8, pl, got);
        }
        // Byte by byte through the decoder.
        var d: Decoder = .init(limits);
        defer d.deinit(t.allocator);
        var seen: usize = 0;
        for (w.buffered()) |byte| {
            try d.feed(t.allocator, &.{byte});
            while (try d.next()) |frame| : (seen += 1) try t.expectEqualSlices(u8, payloads[seen], frame);
        }
        try t.expectEqual(payloads.len, seen);
        try t.expectEqual(@as(usize, 0), d.buffered());
    };
}

test "prefix limits: width capacity, malformed lengths" {
    const t = std.testing;
    var b: [600]u8 = undefined;
    const p256 = @as([256]u8, @splat(0));
    try t.expectError(error.FrameTooLarge, framed(&b, &p256, .{ .prefix = .{ .width = .u8 } }));
    const p254 = @as([254]u8, @splat(0));
    // 254 + 1 prefix byte = 255 still fits; 255 + 1 does not.
    _ = try framed(&b, &p254, .{ .prefix = .{ .width = .u8, .includes_prefix = true } });
    try t.expectError(error.FrameTooLarge, framed(&b, p256[0..255], .{ .prefix = .{ .width = .u8, .includes_prefix = true } }));
    _ = try framed(&b, p256[0..255], .{ .prefix = .{ .width = .u8 } });

    const Bad = struct { []const u8, Prefix };
    const bad = [_]Bad{
        .{ "\x80\x00", .{ .width = .varint } }, // overlong zero
        .{ "\xff\x80\x00", .{ .width = .varint } }, // overlong
        .{ strRepeat("\xff", 10) ++ "\x01", .{ .width = .varint } }, // 11 bytes
        .{ strRepeat("\xff", 9) ++ "\x02", .{ .width = .varint } }, // past 64 bits
        .{ "\x00", .{ .width = .u8, .includes_prefix = true } }, // smaller than its own prefix (1)
        .{ "\x00", .{ .width = .varint, .includes_prefix = true } },
    };
    for (bad) |bd| {
        // The malformed prefix followed by a few payload bytes.
        var src: [32]u8 = @splat(0);
        @memcpy(src[0..bd[0].len], bd[0]);
        var r: std.Io.Reader = .fixed(src[0 .. bd[0].len + 4]);
        var rb: [16]u8 = undefined;
        try t.expectError(error.BadLength, readFrame(&r, &rb, .{ .prefix = bd[1] }));
        var d: Decoder = .init(.{ .prefix = bd[1] });
        defer d.deinit(t.allocator);
        try d.feed(t.allocator, bd[0]);
        try t.expectError(error.BadLength, d.next());
        try t.expectError(error.BadLength, d.next()); // sticky
    }
    // Controls: value 3 with a 2-byte self-counting prefix is a 1-byte
    // payload; value 1 with a 1-byte one is the empty payload.
    var r: std.Io.Reader = .fixed("\x00\x03z");
    var rb: [4]u8 = undefined;
    try t.expectEqualStrings("z", try readFrame(&r, &rb, .{ .prefix = .{ .width = .u16, .endian = .big, .includes_prefix = true } }));
    var r1: std.Io.Reader = .fixed("\x01");
    try t.expectEqualStrings("", try readFrame(&r1, &rb, .{ .prefix = .{ .width = .u8, .includes_prefix = true } }));
    // The largest legal varint: 2^64 − 1 in ten bytes — legal encoding, too big a frame.
    var r9: std.Io.Reader = .fixed(strRepeat("\xff", 9) ++ "\x01");
    try t.expectError(error.FrameTooLarge, readFrame(&r9, &rb, .{ .prefix = .{ .width = .varint } }));
    // A u64 prefix announcing more than max_frame.
    var r8: std.Io.Reader = .fixed("\x00\x00\x00\x01\x00\x00\x00\x00");
    try t.expectError(error.FrameTooLarge, readFrame(&r8, &rb, .{ .prefix = .{ .width = .u64, .endian = .big } }));
}

test "Decoder: oversize refused at the prefix, not after buffering the body; NotDrained" {
    const t = std.testing;
    var d: Decoder = .init(.{ .max_frame = 8 });
    defer d.deinit(t.allocator);
    // 9-byte announcement, no body yet: refused now.
    try d.feed(t.allocator, "\x09\x00\x00\x00");
    try t.expectError(error.FrameTooLarge, d.next());
    try t.expectError(error.FrameTooLarge, d.next());

    var e: Decoder = .init(.{ .max_frame = 8 });
    defer e.deinit(t.allocator);
    // A partial prefix and a partial body both answer "need more".
    try e.feed(t.allocator, "\x02\x00");
    try t.expectEqual(@as(?[]const u8, null), try e.next());
    try e.feed(t.allocator, "\x00\x00a");
    try t.expectEqual(@as(?[]const u8, null), try e.next());
    try e.feed(t.allocator, "b\x01\x00\x00\x00c");
    try t.expectEqualStrings("ab", (try e.next()).?);
    try t.expectEqualStrings("c", (try e.next()).?);
    try t.expectEqual(@as(?[]const u8, null), try e.next());
    // Feeding without draining: allowed up to one frame's worth (8 + 10)
    // already buffered, refused past it.
    var f: Decoder = .init(.{ .max_frame = 8 });
    defer f.deinit(t.allocator);
    try f.feed(t.allocator, strRepeat("\x01\x00\x00\x00x", 3)); // 15 buffered
    try f.feed(t.allocator, "\x01\x00\x00\x00x"); // 15 ≤ 18 before this feed: ok → 20
    try t.expectError(error.NotDrained, f.feed(t.allocator, "y"));
    var n: usize = 0;
    while (try f.next()) |_| n += 1;
    try t.expectEqual(@as(usize, 4), n);
    try f.feed(t.allocator, "\x01\x00\x00\x00y");
    try t.expectEqualStrings("y", (try f.next()).?);
}

test "driver: 2000 PRNG streams — Decoder agrees with readFrame, garbage never panics" {
    // Deterministic verdict run (~/.claude/fuzzing.md): every format, random
    // payloads written then fed back in random-sized pieces must come out
    // identical; random bytes must end in a frame, "need more", or one of
    // the two declared errors — never a crash.
    const t = std.testing;
    var prng = std.Random.DefaultPrng.init(0xf4a3_1e2d);
    const r = prng.random();
    const widths = [_]Width{ .u8, .u16, .u32, .u64, .varint };
    var frames_seen: usize = 0;
    for (0..2000) |iter| {
        const limits: Limits = .{
            .max_frame = r.intRangeAtMost(u32, 0, 300),
            .prefix = .{ .width = widths[r.uintLessThan(usize, widths.len)], .endian = if (r.boolean()) .big else .little, .includes_prefix = r.boolean() },
        };
        var wire: [4096]u8 = undefined;
        var w: std.Io.Writer = .fixed(&wire);
        var payloads: [8][]const u8 = undefined;
        var store: [8][300]u8 = undefined;
        var np: usize = 0;
        if (iter % 2 == 0) {
            // Well-formed stream.
            while (np < 8) : (np += 1) {
                const len = r.uintAtMost(usize, @min(limits.max_frame, 250));
                r.bytes(store[np][0..len]);
                payloads[np] = store[np][0..len];
                try writeFrame(&w, payloads[np], limits);
            }
        } else {
            const len = r.uintAtMost(usize, 200);
            r.bytes(wire[0..len]);
            w.end = len;
        }
        const bytes = w.buffered();
        var d: Decoder = .init(limits);
        defer d.deinit(t.allocator);
        var pos: usize = 0;
        var got: usize = 0;
        stream: while (pos < bytes.len) {
            const n = @min(bytes.len - pos, r.uintAtMost(usize, 16));
            try d.feed(t.allocator, bytes[pos .. pos + n]);
            pos += n;
            while (true) {
                const f = d.next() catch |e| {
                    try t.expect(iter % 2 == 1); // only garbage may fail
                    try t.expect(e == error.FrameTooLarge or e == error.BadLength);
                    break :stream;
                } orelse break;
                if (iter % 2 == 0) try t.expectEqualSlices(u8, payloads[got], f);
                got += 1;
            }
        }
        if (iter % 2 == 0) {
            try t.expectEqual(np, got);
            frames_seen += got;
            // And the blocking reader agrees.
            var rd: std.Io.Reader = .fixed(bytes);
            var rb: [300]u8 = undefined;
            for (payloads[0..np]) |pl| try t.expectEqualSlices(u8, pl, try readFrame(&rd, &rb, limits));
        } else {
            var rd: std.Io.Reader = .fixed(bytes);
            var rb: [300]u8 = undefined;
            while (readFrame(&rd, &rb, limits)) |_| {} else |_| {}
        }
    }
    try t.expect(frames_seen == 8000);
}

test "edges the mutation run asked for (framing)" {
    const t = std.testing;
    // A 10th varint byte that still says "more follows" is refused at ten
    // bytes — an 11th is never read (it would be shifted past bit 63).
    const eleven = strRepeat("\xff", 9) ++ "\x81" ++ "\x01";
    var r: std.Io.Reader = .fixed(eleven ++ strRepeat("\x00", 4));
    var rb: [8]u8 = undefined;
    try t.expectError(error.BadLength, readFrame(&r, &rb, .{ .prefix = .{ .width = .varint } }));
    var d: Decoder = .init(.{ .prefix = .{ .width = .varint } });
    defer d.deinit(t.allocator);
    try d.feed(t.allocator, eleven);
    try t.expectError(error.BadLength, d.next());
    // NotDrained boundary: exactly max_frame + max_prefix_len (8 + 10 = 18)
    // buffered may still be fed; one byte more may not.
    var e: Decoder = .init(.{ .max_frame = 8 });
    defer e.deinit(t.allocator);
    try e.feed(t.allocator, strRepeat("\x00\x00\x00\x00", 4) ++ "\x00\x00"); // 18 bytes buffered
    try e.feed(t.allocator, "\x00"); // allowed: 18 ≤ 18 before this feed
    try t.expectError(error.NotDrained, e.feed(t.allocator, "\x00")); // 19 > 18
}

// ── tests: the general prefix (offset, adjustment, skip, widths 1-8) ────────
//
// Golden values below were produced by tokio-util 0.7.19's
// `LengthDelimitedCodec` through tools/oracle (see tools/diff.zig for the
// 20 000-case differential run); the parameters are mapped as the header of
// tools/diff.zig says (tokio's length_adjustment = ours - width if
// includes_prefix).

test "general prefix: golden frames from tokio-util" {
    const t = std.testing;
    var b: [64]u8 = undefined;
    // 3-byte big-endian field.
    try t.expectEqualSlices(u8, "\x00\x00\x03abc", try framed(&b, "abc", .{ .prefix = .{ .width = .u24, .endian = .big } }));
    // 5-byte little-endian field counting its own width: 3 + 5 = 8.
    try t.expectEqualSlices(u8, "\x08\x00\x00\x00\x00abc", try framed(&b, "abc", .{ .prefix = .{ .width = .u40, .includes_prefix = true } }));
    // Decode: 2 header bytes, 2-byte BE field, adjustment 0, skip 2 -> the
    // field itself starts the frame; n = field = 3 counts from there.
    var d: Decoder = .init(.{ .prefix = .{ .width = .u16, .endian = .big, .offset = 2, .skip = 2 } });
    defer d.deinit(t.allocator);
    try d.feed(t.allocator, "ab\x00\x03xyz");
    try t.expectEqualSlices(u8, "\x00\x03x", (try d.next()).?);
    try t.expectEqual(@as(?[]const u8, null), try d.next());
    // skip 0, adjustment 4: the whole 7 bytes are the frame.
    var e: Decoder = .init(.{ .prefix = .{ .width = .u16, .endian = .big, .offset = 2, .skip = 0, .adjustment = 4 } });
    defer e.deinit(t.allocator);
    try e.feed(t.allocator, "ab\x00\x03xyz");
    try t.expectEqualSlices(u8, "ab\x00\x03xyz", (try e.next()).?);
    // The default skip: the payload only, header bytes ignored.
    var f: Decoder = .init(.{ .prefix = .{ .width = .u16, .endian = .big, .offset = 2 } });
    defer f.deinit(t.allocator);
    try f.feed(t.allocator, "ab\x00\x03xyz" ++ "cd\x00\x01q");
    try t.expectEqualSlices(u8, "xyz", (try f.next()).?);
    try t.expectEqualSlices(u8, "q", (try f.next()).?);
}

test "general prefix: header writer, adjustment signs, refusals" {
    const t = std.testing;
    var b: [64]u8 = undefined;
    const lim: Limits = .{ .prefix = .{ .width = .u16, .endian = .big, .offset = 2, .adjustment = -1 } };
    var w: std.Io.Writer = .fixed(&b);
    try t.expectError(error.HeaderRequired, writeFrame(&w, "xy", lim));
    try t.expectError(error.HeaderRequired, writeFrameWithHeader(&w, "a", "xy", lim));
    try writeFrameWithHeader(&w, "ab", "xy", lim);
    // field = n - adjustment = 2 + 1
    try t.expectEqualSlices(u8, "ab\x00\x03xy", w.buffered());
    var r: std.Io.Reader = .fixed(w.buffered());
    var rb: [8]u8 = undefined;
    try t.expectEqualStrings("xy", try readFrame(&r, &rb, lim));
    // An adjustment that takes the field below zero is BadLength, not a wrap.
    var w2: std.Io.Writer = .fixed(&b);
    try t.expectError(error.BadLength, writeFrame(&w2, "x", .{ .prefix = .{ .adjustment = 2 } }));
    // ... also for a self-counting varint with a huge adjustment (no endless search).
    try t.expectError(error.BadLength, writeFrame(&w2, "x", .{ .prefix = .{ .width = .varint, .includes_prefix = true, .adjustment = 1 << 30 } }));
    // A skip past the head is BadLength on decode.
    var r2: std.Io.Reader = .fixed("\x00\x01x");
    try t.expectError(error.BadLength, readFrame(&r2, &rb, .{ .prefix = .{ .width = .u16, .skip = 3 } }));
    // A frame shorter than the head bytes it keeps is BadLength.
    var r3: std.Io.Reader = .fixed("\x00\x01x");
    try t.expectError(error.BadLength, readFrame(&r3, &rb, .{ .prefix = .{ .width = .u16, .endian = .big, .skip = 0 } }));
    // max_frame bounds n after the adjustment.
    var r4: std.Io.Reader = .fixed("\x05abcde");
    try t.expectError(error.FrameTooLarge, readFrame(&r4, &rb, .{ .max_frame = 4, .prefix = .{ .width = .u8 } }));
    var r5: std.Io.Reader = .fixed("\x05abcde");
    try t.expectEqualStrings("abcd", try readFrame(&r5, &rb, .{ .max_frame = 4, .prefix = .{ .width = .u8, .adjustment = -1 } }));
}

test "general prefix: every width, offset and adjustment round-trips through all three readers (skip is null)" {
    const t = std.testing;
    const widths = [_]Width{ .u8, .u16, .u24, .u32, .u40, .u48, .u56, .u64, .varint };
    for (widths) |wd| for ([_]std.builtin.Endian{ .little, .big }) |en| for ([_]bool{ false, true }) |inc| for ([_]u8{ 0, 3 }) |off| for ([_]i32{ -2, 0, 5 }) |adj| {
        const limits: Limits = .{ .prefix = .{ .width = wd, .endian = en, .includes_prefix = inc, .offset = off, .adjustment = adj } };
        var out: [1024]u8 = undefined;
        var w: std.Io.Writer = .fixed(&out);
        const payloads = [_][]const u8{ "", "a", "hello world", &(@as([40]u8, @splat(0xee))) };
        var wrote: [payloads.len][]const u8 = undefined;
        var written: usize = 0;
        for (payloads) |pl| {
            // A tiny payload with a positive adjustment (and no self-count) has no field.
            writeFrameWithHeader(&w, "xyz"[0..off], pl, limits) catch |e| {
                try t.expect(e == error.BadLength);
                continue;
            };
            wrote[written] = pl;
            written += 1;
        }
        var r: std.Io.Reader = .fixed(w.buffered());
        var rb: [64]u8 = undefined;
        var d: Decoder = .init(limits);
        defer d.deinit(t.allocator);
        try d.feed(t.allocator, w.buffered());
        var seen: usize = 0;
        for (wrote[0..written]) |pl| {
            try t.expectEqualSlices(u8, pl, try readFrame(&r, &rb, limits));
            try t.expectEqualSlices(u8, pl, (try d.next()).?);
            seen += 1;
        }
        try t.expectEqual(written, seen);
        try t.expectEqual(@as(?[]const u8, null), try d.next());
    };
}

// ── fuzz: a literal model of the format as oracle ───────────────────────────

/// The spec, written the dumb way, as an independent reading of the wire:
/// frames out of `bytes`, and how the walk ended (`'N'` need more, `'E'` refused).
fn modelDecode(gpa: std.mem.Allocator, bytes: []const u8, lim: Limits, frames: *std.ArrayList([]const u8)) !u8 {
    const p = lim.prefix;
    var pos: usize = 0;
    while (true) {
        const rest = bytes[pos..];
        const off: usize = p.offset;
        var value: u64 = 0;
        var flen: usize = 0;
        if (p.width == .varint) {
            var i: usize = 0;
            while (true) : (i += 1) {
                if (i == 10) return 'E';
                if (off + i >= rest.len) return 'N';
                const g = rest[off + i];
                if (i == 9 and (g & 0x7f) > 1) return 'E';
                value |= @as(u64, g & 0x7f) << @intCast(7 * i);
                if (g & 0x80 == 0) {
                    if (g == 0 and i > 0) return 'E';
                    flen = i + 1;
                    break;
                }
            }
        } else {
            flen = switch (p.width) {
                .u8 => 1,
                .u16 => 2,
                .u24 => 3,
                .u32 => 4,
                .u40 => 5,
                .u48 => 6,
                .u56 => 7,
                .u64 => 8,
                .varint => unreachable,
            };
            if (rest.len < off + flen) return 'N';
            for (0..flen) |i| {
                const byte = rest[off + (if (p.endian == .big) i else flen - 1 - i)];
                value = (value << 8) | byte;
            }
        }
        var n: i128 = @as(i128, value) + p.adjustment;
        if (p.includes_prefix) n -= @as(i128, flen);
        if (n < 0) return 'E';
        const head = off + flen;
        const skip: usize = p.skip orelse head;
        if (skip > head or n < head - skip) return 'E';
        if (n > lim.max_frame) return 'E';
        const len: usize = @intCast(n);
        if (rest.len < skip + len) return 'N';
        try frames.append(gpa, rest[skip..][0..len]);
        pos += skip + len;
    }
}

var reach: struct { frames: usize = 0, refused: usize = 0, need_more: usize = 0, kept: usize = 0, varint: usize = 0 } = .{};

fn fuzzPrefix(comptime S: type, src: *S, gpa: std.mem.Allocator) anyerror!void {
    const widths = [_]Width{ .u8, .u16, .u24, .u32, .u40, .u48, .u56, .u64, .varint };
    var lim: Limits = .{ .max_frame = src.valueRangeAtMost(u32, 0, 400), .prefix = .{
        .width = widths[src.index(widths.len)],
        .endian = if (src.valueRangeAtMost(u8, 0, 1) == 0) .little else .big,
        .includes_prefix = src.valueRangeAtMost(u8, 0, 1) == 1,
        .offset = src.valueRangeAtMost(u8, 0, 20),
        .adjustment = switch (src.valueRangeAtMost(u8, 0, 5)) {
            0 => std.math.minInt(i32),
            1 => std.math.maxInt(i32),
            else => src.valueRangeAtMost(i32, -300, 300),
        },
    } };
    const head_max: u8 = lim.prefix.offset + @as(u8, if (lim.prefix.width == .varint) 2 else 8);
    if (src.valueRangeAtMost(u8, 0, 3) == 0) lim.prefix.skip = src.valueRangeAtMost(u8, 0, head_max);

    // A stream of frames we wrote, then possibly damaged.
    var wire: [1024]u8 = undefined;
    var w: std.Io.Writer = .fixed(&wire);
    const nframes = src.valueRangeAtMost(u8, 0, 3);
    var store: [3][24]u8 = undefined;
    var stored: [3][]const u8 = undefined;
    var nstored: usize = 0;
    for (0..nframes) |_| {
        var hdr: [20]u8 = undefined;
        src.bytes(&hdr);
        const len: usize = src.valueRangeAtMost(u8, 0, 24);
        src.bytes(store[nstored][0..len]);
        var wl = lim;
        wl.prefix.skip = null;
        writeFrameWithHeader(&w, hdr[0..lim.prefix.offset], store[nstored][0..len], wl) catch continue;
        stored[nstored] = store[nstored][0..len];
        nstored += 1;
    }
    // The encoder oracle: whatever the writer emitted, read back by the model
    // (skip null, the one form a writer produces) is exactly the payloads
    // written, and ends needing more.
    {
        var wl = lim;
        wl.prefix.skip = null;
        var exp: std.ArrayList([]const u8) = .empty;
        defer exp.deinit(gpa);
        const e = try modelDecode(gpa, w.buffered(), wl, &exp);
        try std.testing.expectEqual(@as(u8, 'N'), e);
        try std.testing.expectEqual(nstored, exp.items.len);
        for (exp.items, stored[0..nstored]) |a, b| try std.testing.expectEqualSlices(u8, b, a);
    }
    var bytes: []u8 = w.buffered();
    switch (src.valueRangeAtMost(u8, 0, 4)) {
        0 => bytes = bytes[0..src.valueRangeAtMost(u16, 0, @intCast(bytes.len))],
        1 => if (bytes.len > 0) {
            bytes[src.index(bytes.len)] ^= src.value(u8);
        },
        2 => {
            const n: usize = src.valueRangeAtMost(u8, 0, 24);
            src.bytes(wire[0..n]);
            bytes = wire[0..n];
        },
        else => {},
    }

    var want: std.ArrayList([]const u8) = .empty;
    defer want.deinit(gpa);
    const end = try modelDecode(gpa, bytes, lim, &want);

    // The Decoder, fed in pieces.
    var d: Decoder = .init(lim);
    defer d.deinit(gpa);
    var got: usize = 0;
    var dend: u8 = 'N';
    var pos: usize = 0;
    const step: usize = src.valueRangeAtMost(u8, 1, 9);
    feed: while (true) {
        const n = @min(bytes.len - pos, step);
        try d.feed(gpa, bytes[pos..][0..n]);
        pos += n;
        while (true) {
            const f = d.next() catch {
                dend = 'E';
                break :feed;
            } orelse break;
            try std.testing.expect(got < want.items.len);
            try std.testing.expectEqualSlices(u8, want.items[got], f);
            got += 1;
        }
        if (pos == bytes.len) break;
    }
    try std.testing.expectEqual(want.items.len, got);
    try std.testing.expectEqual(end, dend);

    // The blocking readers.
    var r: std.Io.Reader = .fixed(bytes);
    var r2: std.Io.Reader = .fixed(bytes);
    var buf: [512]u8 = undefined;
    for (want.items) |wf| {
        try std.testing.expectEqualSlices(u8, wf, try readFrame(&r, &buf, lim));
        const a = try readFrameAlloc(&r2, gpa, lim);
        defer gpa.free(a);
        try std.testing.expectEqualSlices(u8, wf, a);
    }
    if (readFrame(&r, &buf, lim)) |_| return error.TestUnexpectedResult else |e| {
        try std.testing.expect(if (end == 'N') e == error.EndOfStream else (e == error.FrameTooLarge or e == error.BadLength));
    }
    reach.frames += want.items.len;
    if (end == 'E') reach.refused += 1 else reach.need_more += 1;
    if (lim.prefix.skip != null and want.items.len > 0 and lim.prefix.skip.? < lim.prefix.offset + 1) reach.kept += 1;
    if (lim.prefix.width == .varint and want.items.len > 0) reach.varint += 1;
}

test "fuzz driver: FRAMING_FUZZ (general prefix against a literal model)" {
    try testkit.fuzz.driver.runAll(.{
        .{ fuzzPrefix, .{ .prefix = "FRAMING_FUZZ", .name = "framing-prefix" } },
    });
}

test "fuzz harness: 4000 seeds in every test run, and they reach frames, refusals, kept heads, varints" {
    reach = .{};
    var prng = std.Random.DefaultPrng.init(0x7a11_f4a3);
    for (0..4000) |_| {
        var rng: testkit.fuzz.driver.Rng = .{ .r = prng.random() };
        try fuzzPrefix(testkit.fuzz.driver.Rng, &rng, std.testing.allocator);
    }
    try std.testing.expect(reach.frames > 1000);
    try std.testing.expect(reach.refused > 100);
    try std.testing.expect(reach.need_more > 100);
    try std.testing.expect(reach.kept > 10);
    try std.testing.expect(reach.varint > 100);
}

/// Comptime string repetition; replaces the `**` operator removed in Zig 0.17.
inline fn strRepeat(comptime s: []const u8, comptime n: usize) *const [s.len * n:0]u8 {
    // One @splat + @bitCast, not a loop: a comptime loop writing into an
    // array var costs O(n^2) in Sema (40 000 bytes: 8.7 s; http's test
    // binary spent ~5 min in Sema on these, 2026-10-24).
    const rep_result = comptime blk: {
        const unit: [s.len]u8 = s[0..s.len].*;
        const grid: [n][s.len]u8 = @splat(unit);
        const flat: [s.len * n]u8 = @bitCast(grid);
        break :blk (flat ++ [_:0]u8{})[0 .. s.len * n :0].*;
    };
    return &rep_result;
}
