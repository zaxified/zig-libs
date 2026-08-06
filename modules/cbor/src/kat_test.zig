// SPDX-License-Identifier: MIT
//! Verification for `root.zig` / `cose.zig`: RFC 8949 Appendix A byte-exact
//! KATs (`kat_vectors.zig`), hostile-input hardening (typed errors, never a
//! panic/OOB), and a canonical-encoding positive control.

const std = @import("std");
const testing = std.testing;
const cbor = @import("root.zig");
const Value = cbor.Value;
const MapEntry = cbor.MapEntry;
const kat = @import("kat_vectors.zig");

fn hexDecode(a: std.mem.Allocator, hex: []const u8) ![]u8 {
    const out = try a.alloc(u8, hex.len / 2);
    return try std.fmt.hexToBytes(out, hex);
}

/// Structural equality, bit-exact for floats (so NaN/-0.0 rows compare
/// correctly instead of following IEEE `==` semantics).
fn valueEql(x: Value, y: Value) bool {
    if (std.meta.activeTag(x) != std.meta.activeTag(y)) return false;
    return switch (x) {
        .uint => |v| v == y.uint,
        .negint => |v| v == y.negint,
        .bytes => |v| std.mem.eql(u8, v, y.bytes),
        .text => |v| std.mem.eql(u8, v, y.text),
        .array => |v| blk: {
            if (v.len != y.array.len) break :blk false;
            for (v, y.array) |xi, yi| {
                if (!valueEql(xi, yi)) break :blk false;
            }
            break :blk true;
        },
        .map => |v| blk: {
            if (v.len != y.map.len) break :blk false;
            for (v, y.map) |xe, ye| {
                if (!valueEql(xe.key, ye.key) or !valueEql(xe.value, ye.value)) break :blk false;
            }
            break :blk true;
        },
        .tag => |v| v.number == y.tag.number and valueEql(v.value.*, y.tag.value.*),
        .simple => |v| v == y.simple,
        .bool => |v| v == y.bool,
        .null_value, .undefined_value => true,
        .f16 => |v| @as(u16, @bitCast(v)) == @as(u16, @bitCast(y.f16)),
        .f32 => |v| @as(u32, @bitCast(v)) == @as(u32, @bitCast(y.f32)),
        .f64 => |v| @as(u64, @bitCast(v)) == @as(u64, @bitCast(y.f64)),
    };
}

test "RFC 8949 Appendix A: decode(hex) == expected value, for every vector" {
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();

    for (kat.vectors) |v| {
        const bytes = try hexDecode(a, v.hex);
        const got = cbor.decode(a, bytes, .{}) catch |err| {
            std.debug.print("decode failed for hex {s}: {}\n", .{ v.hex, err });
            return err;
        };
        if (!valueEql(got, v.value)) {
            std.debug.print("value mismatch for hex {s}\n", .{v.hex});
            return error.TestUnexpectedResult;
        }
    }
}

test "RFC 8949 Appendix A: encode(value) == hex, for every roundtrip vector" {
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();

    for (kat.vectors) |v| {
        if (!v.roundtrip) continue;
        const expected = try hexDecode(a, v.hex);
        const got = try cbor.encode(a, v.value, .{});
        if (!std.mem.eql(u8, expected, got)) {
            std.debug.print("encode mismatch for hex {s}: got {x}\n", .{ v.hex, got });
            return error.TestUnexpectedResult;
        }
    }
}

test "RFC 8949 Appendix A: indefinite-length vectors decode, encode via this module, and re-decode to the same value (value-level round-trip)" {
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();

    for (kat.vectors) |v| {
        if (v.roundtrip) continue;
        const bytes = try hexDecode(a, v.hex);
        const decoded = try cbor.decode(a, bytes, .{});
        const re_encoded = try cbor.encode(a, decoded, .{});
        const re_decoded = try cbor.decode(a, re_encoded, .{});
        try testing.expect(valueEql(decoded, re_decoded));
        try testing.expect(valueEql(decoded, v.value));
    }
}

// ── canonical (RFC 8949 §4.2.1) map-key ordering — positive control ───────

test "canonical: map keys sorted bytewise by encoded key (positive control)" {
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();

    // Given order: key=10 (0x0a), key=1 (0x01) — deliberately NOT ascending.
    const entries = [_]MapEntry{
        .{ .key = .{ .uint = 10 }, .value = .{ .uint = 100 } },
        .{ .key = .{ .uint = 1 }, .value = .{ .uint = 200 } },
    };
    const v: Value = .{ .map = &entries };

    // Default (canonical=false): given order preserved verbatim.
    // a2 (map,2 pairs) 0a (key10) 18 64 (val100) 01 (key1) 18 c8 (val200)
    const default_bytes = try cbor.encode(a, v, .{});
    try testing.expectEqualSlices(u8, &[_]u8{ 0xa2, 0x0a, 0x18, 0x64, 0x01, 0x18, 0xc8 }, default_bytes);

    // canonical=true: RFC 8949 §4.2.1 sorts entries by the bytewise order of
    // their *encoded* key: encoded key1 = [0x01], encoded key10 = [0x0a];
    // 0x01 < 0x0a, so key1's pair moves first. If the sort were missing,
    // reversed, or numeric-instead-of-bytewise, this exact byte sequence
    // would not come out and the assertion below fails.
    const canon_bytes = try cbor.encode(a, v, .{ .canonical = true });
    try testing.expectEqualSlices(u8, &[_]u8{ 0xa2, 0x01, 0x18, 0xc8, 0x0a, 0x18, 0x64 }, canon_bytes);

    // The two must actually differ — proves canonical mode did something,
    // not a no-op that happened to pass the exact-bytes checks above by luck
    // of a trivial map.
    try testing.expect(!std.mem.eql(u8, default_bytes, canon_bytes));
}

test "canonical: string-keyed map, bytewise order independent of key text length" {
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();

    // Given order: "aa" (encodes 62 61 61, 3 bytes), "b" (encodes 61 62, 2
    // bytes). Bytewise: first byte 0x61 ("b") < 0x62 ("aa") -> "b" sorts
    // first, even though its encoding happens to also be shorter here.
    const entries = [_]MapEntry{
        .{ .key = .{ .text = "aa" }, .value = .{ .uint = 2 } },
        .{ .key = .{ .text = "b" }, .value = .{ .uint = 1 } },
    };
    const v: Value = .{ .map = &entries };

    const canon_bytes = try cbor.encode(a, v, .{ .canonical = true });
    // a2 (map,2) 61 62 (key "b") 01 (val1) 62 61 61 (key "aa") 02 (val2)
    try testing.expectEqualSlices(u8, &[_]u8{ 0xa2, 0x61, 0x62, 0x01, 0x62, 0x61, 0x61, 0x02 }, canon_bytes);

    // Sanity: canonical output still decodes to the same logical map.
    const decoded = try cbor.decode(a, canon_bytes, .{});
    try testing.expect(decoded == .map);
    try testing.expectEqual(@as(usize, 2), decoded.map.len);
}

// ── hostile input — typed errors, never a panic/OOB ────────────────────────

test "hostile: truncated multi-byte length header" {
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();
    // 0x1a introduces a 4-byte argument (uint, major 0) but only 2 follow.
    const bytes = [_]u8{ 0x1a, 0x00, 0x0f };
    try testing.expectError(error.Truncated, cbor.decode(a, &bytes, .{}));
}

test "hostile: declared array length far exceeds available input" {
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();
    // 0x9b = array, 8-byte length argument = u64 max, then nothing follows.
    // Must fail Truncated on the first element read, never attempt to
    // pre-allocate ~2^64 elements.
    var bytes = [_]u8{ 0x9b, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff };
    try testing.expectError(error.Truncated, cbor.decode(a, &bytes, .{}));
}

test "hostile: declared byte-string length exceeds available input" {
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();
    // 0x5b = byte string, 8-byte length = u64 max, zero content bytes
    // follow. No allocation of that size should ever be attempted.
    const bytes = [_]u8{ 0x5b, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff };
    try testing.expectError(error.Truncated, cbor.decode(a, &bytes, .{}));
}

test "hostile: depth bomb - deeply nested single-element arrays exceed max_depth" {
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();

    // Build [[[...[0]...]]] nested 200 levels deep: 200 * 0x81 (array of 1)
    // followed by one 0x00 (uint 0) innermost item. Default max_depth is 64.
    const depth = 200;
    var bytes = try a.alloc(u8, depth + 1);
    for (bytes[0..depth]) |*b| b.* = 0x81;
    bytes[depth] = 0x00;

    try testing.expectError(error.DepthLimitExceeded, cbor.decode(a, bytes, .{}));

    // A depth within the cap succeeds (sanity: the cap doesn't misfire on
    // ordinary input).
    const shallow = 10;
    var shallow_bytes = try a.alloc(u8, shallow + 1);
    for (shallow_bytes[0..shallow]) |*b| b.* = 0x81;
    shallow_bytes[shallow] = 0x00;
    _ = try cbor.decode(a, shallow_bytes, .{});
}

test "hostile: trailing garbage after a complete item is rejected" {
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();
    const bytes = [_]u8{ 0x01, 0xff }; // uint(1), then a stray byte
    try testing.expectError(error.TrailingGarbage, cbor.decode(a, &bytes, .{}));
}

test "hostile: reserved additional-info value (28) is Malformed" {
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();
    const bytes = [_]u8{0x1c}; // major 0, additional info 28 (reserved)
    try testing.expectError(error.Malformed, cbor.decode(a, &bytes, .{}));
}

test "hostile: bare 'break' (0xff) outside an indefinite context is Malformed" {
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();
    const bytes = [_]u8{0xff};
    try testing.expectError(error.Malformed, cbor.decode(a, &bytes, .{}));
}

test "hostile: indefinite byte-string chunk of the wrong major type is Malformed" {
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();
    // 0x5f starts an indefinite byte string; a text-string chunk (0x61 'a')
    // is not a valid chunk type inside it.
    const bytes = [_]u8{ 0x5f, 0x61, 0x61, 0xff };
    try testing.expectError(error.Malformed, cbor.decode(a, &bytes, .{}));
}

test "hostile: indefinite-length uint (major 0, info 31) is Malformed" {
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();
    const bytes = [_]u8{0x1f}; // major 0 doesn't support indefinite length
    try testing.expectError(error.Malformed, cbor.decode(a, &bytes, .{}));
}

test "hostile: non-canonical 1-byte simple-value form (0xf818, RFC 8949 §3.3) is Malformed" {
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();
    // 0xf8 0x18: simple value 24 via the one-byte-argument form. RFC 8949
    // §3.3 requires values < 32 use the direct form (0xf0..0xf7 area) only —
    // this exact two-byte encoding is explicitly "not well-formed". Found
    // while cross-checking Appendix A against a third-party test-vectors
    // repo that (incorrectly) included this as a vector; the RFC's own
    // table does not.
    const bytes = [_]u8{ 0xf8, 0x18 };
    try testing.expectError(error.Malformed, cbor.decode(a, &bytes, .{}));
}

test "hostile: invalid UTF-8 in a text string is Malformed" {
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();
    const bytes = [_]u8{ 0x61, 0xff }; // text, len 1, content byte 0xff (not valid UTF-8)
    try testing.expectError(error.Malformed, cbor.decode(a, &bytes, .{}));
}

test "hostile: empty input is Truncated, not a panic" {
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();
    try testing.expectError(error.Truncated, cbor.decode(a, &.{}, .{}));
}

// ── boundary teeth for `Decoder.readBytes` ─────────────────────────────────
//
// Every string read in the decoder passes through one bounds check:
//   `if (len > remaining) return error.Truncated;`  (`root.zig`)
// The hostile tests above only ever declare `len = 2^64-1`, i.e. astronomically
// past the bound. That is the "tested far past the limit, never at it" shape:
// widening the check to `len > remaining + 1` keeps every one of those tests
// green while the decoder walks one byte off the end of the input for real.
// These tests pin BOTH sides of the boundary — `len == remaining` must be
// accepted and `len == remaining + 1` must be `Truncated` — on every path that
// reaches `readBytes`: definite byte string, definite text string, a multi-byte
// length argument, and both flavours of indefinite-length chunk.
//
// Under the off-by-one the `remaining + 1` cases stop returning `Truncated`
// and slice past `bytes.len`, so they fail either as a wrong error or as a
// bounds-check panic; either way the suite exits non-zero.

test "boundary: definite byte string with len == remaining is accepted" {
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();
    const bytes = [_]u8{ 0x41, 0xaa }; // bstr, len 1, exactly 1 content byte
    const v = try cbor.decode(a, &bytes, .{});
    try testing.expectEqualSlices(u8, &[_]u8{0xaa}, v.bytes);
}

test "boundary: definite byte string with len == remaining + 1 is Truncated" {
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();
    const bytes = [_]u8{0x41}; // bstr, len 1, zero content bytes follow
    try testing.expectError(error.Truncated, cbor.decode(a, &bytes, .{}));
}

test "boundary: definite text string with len == remaining / remaining + 1" {
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();
    const exact = [_]u8{ 0x61, 'a' }; // tstr, len 1, one content byte
    const v = try cbor.decode(a, &exact, .{});
    try testing.expectEqualStrings("a", v.text);

    const over = [_]u8{0x61}; // tstr, len 1, nothing follows
    try testing.expectError(error.Truncated, cbor.decode(a, &over, .{}));
}

test "boundary: multi-byte length argument, len == remaining / remaining + 1" {
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();
    // 0x59 = bstr with a 2-byte length argument. Exercises the boundary through
    // `readUintN(2)` rather than the inline 0..23 form.
    const exact = [_]u8{ 0x59, 0x00, 0x03, 1, 2, 3 };
    const v = try cbor.decode(a, &exact, .{});
    try testing.expectEqualSlices(u8, &[_]u8{ 1, 2, 3 }, v.bytes);

    const over = [_]u8{ 0x59, 0x00, 0x03, 1, 2 }; // declares 3, supplies 2
    try testing.expectError(error.Truncated, cbor.decode(a, &over, .{}));
}

test "boundary: indefinite byte-string chunk, len == remaining / remaining + 1" {
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();
    // 0x5f … 0xff — the chunk length is bounds-checked by the same `readBytes`.
    const exact = [_]u8{ 0x5f, 0x42, 0xaa, 0xbb, 0xff };
    const v = try cbor.decode(a, &exact, .{});
    try testing.expectEqualSlices(u8, &[_]u8{ 0xaa, 0xbb }, v.bytes);

    // Chunk declares 1 byte with 0 bytes left in the whole input (`0xff` was
    // already consumed as the chunk head's neighbour): len == remaining + 1.
    const over = [_]u8{ 0x5f, 0x41 };
    try testing.expectError(error.Truncated, cbor.decode(a, &over, .{}));
}

test "boundary: indefinite text-string chunk, len == remaining / remaining + 1" {
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();
    const exact = [_]u8{ 0x7f, 0x62, 'h', 'i', 0xff };
    const v = try cbor.decode(a, &exact, .{});
    try testing.expectEqualStrings("hi", v.text);

    const over = [_]u8{ 0x7f, 0x61 }; // chunk declares 1, nothing remains
    try testing.expectError(error.Truncated, cbor.decode(a, &over, .{}));
}

// ── fuzz: decode on arbitrary bytes never panics/OOB ────────────────────────

fn fuzzDecodeNeverPanics(_: void, smith: *std.testing.Smith) !void {
    var buf: [512]u8 = undefined;
    smith.bytes(&buf);
    const len = smith.valueRangeAtMost(u16, 0, buf.len);
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    _ = cbor.decode(arena.allocator(), buf[0..len], .{}) catch return;
}
test "fuzz: decode never panics on arbitrary bytes" {
    try std.testing.fuzz({}, fuzzDecodeNeverPanics, .{});
}
