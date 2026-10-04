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
/// varint: 7 bits per byte, low group first, high bit = "more follows").
pub const Width = enum { u8, u16, u32, u64, varint };

/// The length prefix's wire format. The default — 4 bytes, little-endian,
/// payload length only — is this module's original format. tokio-util's
/// `LengthDelimitedCodec` default is `.{ .endian = .big }`; Netty's
/// `LengthFieldPrepender(2)` is `.{ .width = .u16, .endian = .big }`.
pub const Prefix = struct {
    width: Width = .u32,
    /// Byte order of a fixed-width field; ignored by `varint`.
    endian: std.builtin.Endian = .little,
    /// The field counts the prefix's own bytes too (field = prefix length +
    /// payload length) — tokio's `length_adjustment(-width)` case. With
    /// `varint` the prefix length is the encoding's own length, found as the
    /// fixpoint (a 127-byte payload is announced as 129 in two bytes).
    includes_prefix: bool = false,
};

/// Options for `writeFrame`/`readFrame`/`Decoder`. `max_frame` is a parameter
/// (not a compile-time constant) so callers can tighten or loosen the cap per
/// protocol; `.{}` uses `default_max_frame` and the original u32-LE prefix.
pub const Limits = struct {
    max_frame: u32 = default_max_frame,
    prefix: Prefix = .{},
};

/// Longest length prefix: a 10-byte varint (64 bits in 7-bit groups).
pub const max_prefix_len = 10;

fn fixedLen(w: Width) usize {
    return switch (w) {
        .u8 => 1,
        .u16 => 2,
        .u32 => 4,
        .u64 => 8,
        .varint => unreachable,
    };
}

fn varintLen(v: u64) usize {
    var n: usize = 1;
    var x = v >> 7;
    while (x != 0) : (x >>= 7) n += 1;
    return n;
}

/// Encode the prefix for a `payload_len`-byte payload into `buf`.
fn encodePrefix(buf: *[max_prefix_len]u8, payload_len: usize, p: Prefix) error{FrameTooLarge}![]const u8 {
    if (p.width == .varint) {
        var value: u64 = payload_len;
        if (p.includes_prefix) {
            // The smallest n with varintLen(len + n) == n; it exists for every
            // len below 2^64 − 10 (the encoded length grows by at most one byte
            // per step of n).
            var n: usize = 1;
            while (varintLen(payload_len + n) != n) n += 1;
            value = payload_len + n;
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
    const value: u64 = payload_len + if (p.includes_prefix) n else 0;
    switch (p.width) {
        .u8 => buf[0] = std.math.cast(u8, value) orelse return error.FrameTooLarge,
        .u16 => std.mem.writeInt(u16, buf[0..2], std.math.cast(u16, value) orelse return error.FrameTooLarge, p.endian),
        .u32 => std.mem.writeInt(u32, buf[0..4], std.math.cast(u32, value) orelse return error.FrameTooLarge, p.endian),
        .u64 => std.mem.writeInt(u64, buf[0..8], value, p.endian),
        .varint => unreachable,
    }
    return buf[0..n];
}

const PrefixError = error{
    /// A length field the format cannot produce: a varint longer than 10
    /// bytes, past 64 bits, or not minimally encoded (a trailing `0x00`
    /// group — `serialize` never writes one, and accepting it would give one
    /// frame two encodings); or, with `includes_prefix`, a value smaller than
    /// the prefix itself.
    BadLength,
};

/// Decode a complete prefix from `bytes`: the payload length and how many
/// bytes the prefix took, or null if `bytes` holds only part of it.
fn decodePrefix(bytes: []const u8, p: Prefix) PrefixError!?struct { payload: u64, len: usize } {
    var value: u64 = 0;
    var n: usize = 0;
    if (p.width == .varint) {
        while (true) {
            // The cap before the "need more bytes" answer: an 11th byte is
            // never needed, so a caller must not be told to fetch one.
            if (n == max_prefix_len) return error.BadLength;
            if (n == bytes.len) return null;
            const b = bytes[n];
            const group: u64 = b & 0x7f;
            // The 10th byte may carry only the top bit of a u64.
            if (n == 9 and group > 1) return error.BadLength;
            value |= group << @intCast(7 * n);
            n += 1;
            if (b & 0x80 == 0) {
                if (b == 0 and n > 1) return error.BadLength; // overlong
                break;
            }
        }
    } else {
        n = fixedLen(p.width);
        if (bytes.len < n) return null;
        value = switch (p.width) {
            .u8 => bytes[0],
            .u16 => std.mem.readInt(u16, bytes[0..2], p.endian),
            .u32 => std.mem.readInt(u32, bytes[0..4], p.endian),
            .u64 => std.mem.readInt(u64, bytes[0..8], p.endian),
            .varint => unreachable,
        };
    }
    if (p.includes_prefix) {
        if (value < n) return error.BadLength;
        value -= n;
    }
    return .{ .payload = value, .len = n };
}

/// Read the prefix from a stream, one byte at a time for a varint.
fn readPrefix(r: *std.Io.Reader, p: Prefix) !u64 {
    var buf: [max_prefix_len]u8 = undefined;
    var have: usize = if (p.width == .varint) 1 else fixedLen(p.width);
    try r.readSliceAll(buf[0..have]);
    while (true) {
        if (try decodePrefix(buf[0..have], p)) |d| return d.payload;
        // Only a varint can be incomplete here, and `decodePrefix` refuses one
        // that reaches `max_prefix_len`, so `have` stays in bounds.
        buf[have] = try r.takeByte();
        have += 1;
    }
}

/// Write one length-prefixed frame to `w`. Rejects `payload` larger than
/// `limits.max_frame` — or than the prefix width can announce (255 for
/// `.u8`, …) — before touching `w` or dereferencing `payload`.
pub fn writeFrame(w: *std.Io.Writer, payload: []const u8, limits: Limits) !void {
    if (payload.len > limits.max_frame) return error.FrameTooLarge;
    var hdr: [max_prefix_len]u8 = undefined;
    try w.writeAll(try encodePrefix(&hdr, payload.len, limits.prefix));
    try w.writeAll(payload);
}

/// Read one frame from `r` into `buf`; returns the payload sub-slice of
/// `buf`. Fails with `error.FrameTooLarge` if the announced length exceeds
/// either `limits.max_frame` or `buf.len`, and `error.BadLength` on a length
/// field the format cannot produce.
pub fn readFrame(r: *std.Io.Reader, buf: []u8, limits: Limits) ![]u8 {
    const len = try readPrefix(r, limits.prefix);
    if (len > limits.max_frame or len > buf.len) return error.FrameTooLarge;
    const dst = buf[0..@intCast(len)];
    try r.readSliceAll(dst);
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
pub fn readFrameAlloc(r: *std.Io.Reader, gpa: std.mem.Allocator, limits: Limits) ![]u8 {
    const len = try readPrefix(r, limits.prefix);
    if (len > limits.max_frame) return error.FrameTooLarge;
    const dst = try gpa.alloc(u8, @intCast(len));
    errdefer gpa.free(dst);
    try r.readSliceAll(dst);
    return dst;
}

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
        if (d.buffered() > @as(usize, d.limits.max_frame) + max_prefix_len) return error.NotDrained;
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
        const pre = (decodePrefix(avail, d.limits.prefix) catch |e| return d.fail(e)) orelse return null;
        if (pre.payload > d.limits.max_frame) return d.fail(error.FrameTooLarge);
        const len: usize = @intCast(pre.payload);
        if (avail.len - pre.len < len) return null;
        d.start += pre.len + len;
        return avail[pre.len..][0..len];
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
            return std.json.parseFromSlice(T, gpa, bytes, .{});
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
    seed("\x80\x00\x00\x00" ++ "x" ** 128), // exactly `out.len`: the boundary that must pass
    seed("\x81\x00\x00\x00" ++ "x" ** 129), // ⭐ one past `out.len`: FrameTooLarge
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
    try t.expect(std.mem.indexOf(u8, bytes, "\"ping\"") != null);
    try t.expect(std.mem.indexOf(u8, bytes, "\"running\"") != null);

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
    const msg: TestEnvelope = .{ .blob = .{ .id = 1, .data = "0123456789" ** 4 } };
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
    try t.expect(jsonDepthWithin("{\"a\":\"\\\"" ++ ("[" ** 200) ++ "\"}", 8));
    // The same brackets OUTSIDE a string are structure, and are counted.
    try t.expect(!jsonDepthWithin("{\"a\":" ++ ("[" ** 200), 8));
    // A closing bracket pops, so a long flat sequence never accumulates.
    try t.expect(jsonDepthWithin("[]" ** 1000, 2));
    // Unbalanced closers saturate at zero instead of wrapping around.
    try t.expect(jsonDepthWithin("]" ** 100 ++ "[", 1));
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
    const p300 = [_]u8{'z'} ** 300;
    const f = try framed(&b, &p300, .{ .prefix = .{ .width = .varint } });
    // protobuf encoding guide: 300 → 0xAC 0x02.
    try t.expectEqualSlices(u8, &.{ 0xac, 0x02 }, f[0..2]);
    try t.expectEqual(@as(usize, 302), f.len);
    // 127 is the largest one-byte varint, 128 the smallest two-byte one.
    const p127 = [_]u8{'a'} ** 127;
    try t.expectEqualSlices(u8, &.{0x7f}, (try framed(&b, &p127, .{ .prefix = .{ .width = .varint } }))[0..1]);
    const p128 = [_]u8{'a'} ** 128;
    try t.expectEqualSlices(u8, &.{ 0x80, 0x01 }, (try framed(&b, &p128, .{ .prefix = .{ .width = .varint } }))[0..2]);
    // includes_prefix: 126 + 1 = 127 fits one byte; 127 + 1 = 128 does not,
    // so it takes two: 127 + 2 = 129 = 0x81 0x01.
    const ip = Prefix{ .width = .varint, .includes_prefix = true };
    const p126 = [_]u8{'a'} ** 126;
    try t.expectEqualSlices(u8, &.{0x7f}, (try framed(&b, &p126, .{ .prefix = ip }))[0..1]);
    try t.expectEqualSlices(u8, &.{ 0x81, 0x01 }, (try framed(&b, &p127, .{ .prefix = ip }))[0..2]);
}

test "every format round-trips through readFrame, readFrameAlloc and the Decoder" {
    const t = std.testing;
    const widths = [_]Width{ .u8, .u16, .u32, .u64, .varint };
    const payloads = [_][]const u8{ "", "a", "hello world", &([_]u8{0xff} ** 200) };
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
    const p256 = [_]u8{0} ** 256;
    try t.expectError(error.FrameTooLarge, framed(&b, &p256, .{ .prefix = .{ .width = .u8 } }));
    const p254 = [_]u8{0} ** 254;
    // 254 + 1 prefix byte = 255 still fits; 255 + 1 does not.
    _ = try framed(&b, &p254, .{ .prefix = .{ .width = .u8, .includes_prefix = true } });
    try t.expectError(error.FrameTooLarge, framed(&b, p256[0..255], .{ .prefix = .{ .width = .u8, .includes_prefix = true } }));
    _ = try framed(&b, p256[0..255], .{ .prefix = .{ .width = .u8 } });

    const Bad = struct { []const u8, Prefix };
    const bad = [_]Bad{
        .{ "\x80\x00", .{ .width = .varint } }, // overlong zero
        .{ "\xff\x80\x00", .{ .width = .varint } }, // overlong
        .{ "\xff" ** 10 ++ "\x01", .{ .width = .varint } }, // 11 bytes
        .{ "\xff" ** 9 ++ "\x02", .{ .width = .varint } }, // past 64 bits
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
    var r9: std.Io.Reader = .fixed("\xff" ** 9 ++ "\x01");
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
    try f.feed(t.allocator, "\x01\x00\x00\x00x" ** 3); // 15 buffered
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
    const eleven = "\xff" ** 9 ++ "\x81" ++ "\x01";
    var r: std.Io.Reader = .fixed(eleven ++ "\x00" ** 4);
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
    try e.feed(t.allocator, "\x00\x00\x00\x00" ** 4 ++ "\x00\x00"); // 18 bytes buffered
    try e.feed(t.allocator, "\x00"); // allowed: 18 ≤ 18 before this feed
    try t.expectError(error.NotDrained, e.feed(t.allocator, "\x00")); // 19 > 18
}
