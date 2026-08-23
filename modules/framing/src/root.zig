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

/// Options for `writeFrame`/`readFrame`. `max_frame` is a parameter (not a
/// compile-time constant) so callers can tighten or loosen the cap per
/// protocol; `.{}` uses `default_max_frame`.
pub const Limits = struct {
    max_frame: u32 = default_max_frame,
};

/// Write one length-prefixed frame to `w`. Rejects `payload` larger than
/// `limits.max_frame` before touching `w` or dereferencing `payload`.
pub fn writeFrame(w: *std.Io.Writer, payload: []const u8, limits: Limits) !void {
    if (payload.len > limits.max_frame) return error.FrameTooLarge;
    var hdr: [4]u8 = undefined;
    std.mem.writeInt(u32, &hdr, @intCast(payload.len), .little);
    try w.writeAll(&hdr);
    try w.writeAll(payload);
}

/// Read one frame from `r` into `buf`; returns the payload sub-slice of
/// `buf`. Fails with `error.FrameTooLarge` if the announced length exceeds
/// either `limits.max_frame` or `buf.len`.
pub fn readFrame(r: *std.Io.Reader, buf: []u8, limits: Limits) ![]u8 {
    const hdr = try r.takeArray(4);
    const len = std.mem.readInt(u32, hdr, .little);
    if (len > limits.max_frame or len > buf.len) return error.FrameTooLarge;
    const dst = buf[0..len];
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
    const hdr = try r.takeArray(4);
    const len = std.mem.readInt(u32, hdr, .little);
    if (len > limits.max_frame) return error.FrameTooLarge;
    const dst = try gpa.alloc(u8, len);
    errdefer gpa.free(dst);
    try r.readSliceAll(dst);
    return dst;
}

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

test "fuzz: readFrame never panics on an arbitrary stream" {
    try std.testing.fuzz({}, fuzzReadFrame, .{});
}

fn fuzzReadFrame(_: void, smith: *std.testing.Smith) !void {
    var buf: [256]u8 = undefined;
    smith.bytes(&buf);
    const len: usize = smith.valueRangeAtMost(u16, 0, buf.len);

    var r: std.Io.Reader = .fixed(buf[0..len]);
    var out: [128]u8 = undefined;
    _ = readFrame(&r, &out, .{}) catch return;
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
