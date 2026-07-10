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

// ── generic JSON tagged-union envelope codec ────────────────────────────────

/// A JSON envelope codec over any `T` that is a `union(enum)` whose payload
/// types are `std.json`-serializable. Zig's `std.json.Stringify` serializes a
/// plain tagged union as a tag-keyed object `{"<tag>": {...}}` by default —
/// the union tag *is* the message type on the wire, no separate discriminator
/// field is needed (this holds even when a payload struct itself contains an
/// inner `enum` field: that field serializes as its tag name, a plain JSON
/// string).
pub fn EnvelopeCodec(comptime T: type) type {
    if (@typeInfo(T) != .@"union") @compileError("EnvelopeCodec(T): T must be a union(enum)");

    return struct {
        /// Encode `msg` to freshly-allocated JSON bytes (caller frees).
        pub fn encodeAlloc(msg: T, gpa: std.mem.Allocator) ![]u8 {
            return std.json.Stringify.valueAlloc(gpa, msg, .{});
        }

        /// Parse JSON bytes into a `T`. Caller calls `.deinit()` on the result.
        pub fn parse(gpa: std.mem.Allocator, bytes: []const u8) !std.json.Parsed(T) {
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
