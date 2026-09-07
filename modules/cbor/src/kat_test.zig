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
/// Test-only (`build.zig`'s `test_deps`, never `deps`): fuzz corpus framing.
const testkit = @import("testkit");

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

test "hostile: depth bomb - exact boundary at max_depth and max_depth+1" {
    // Only depths 200 (fails) and 10 (succeeds) were exercised elsewhere,
    // leaving root.zig's `if (depth > self.max_depth) …` off-by-one
    // (`>` vs `>=`) untested at the boundary itself. Default max_depth is
    // 64; the decode call chain for N nested single-element arrays reaches
    // depth == N at the innermost item, so N == max_depth must succeed and
    // N == max_depth + 1 must fail.
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();
    const max_depth = 64; // DecodeOptions.max_depth default

    {
        const depth = max_depth;
        var bytes = try a.alloc(u8, depth + 1);
        for (bytes[0..depth]) |*b| b.* = 0x81;
        bytes[depth] = 0x00;
        _ = try cbor.decode(a, bytes, .{});
    }
    {
        const depth = max_depth + 1;
        var bytes = try a.alloc(u8, depth + 1);
        for (bytes[0..depth]) |*b| b.* = 0x81;
        bytes[depth] = 0x00;
        try testing.expectError(error.DepthLimitExceeded, cbor.decode(a, bytes, .{}));
    }
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

/// W2 A3 (F5): this used to cap the driven input at 512 octets, which is
/// shorter than plenty of real COSE structures and far too short to build a
/// deeply nested one. The companion harness in `root.zig` covers the other
/// half of that finding — the arena here cannot see a leak, so the leak oracle
/// had to live where `freeValue` is in scope.
fn fuzzDecodeNeverPanics(_: void, smith: *std.testing.Smith) !void {
    var buf: [4096]u8 = undefined;
    // ⚠ One `smith.slice` call, never `bytes` followed by a ranged length: the
    // latter drew `len == 0` on every input this target ever ran outside
    // `--fuzz` (a ranged draw reads eight octets as a little-endian u64 and
    // returns the range MINIMUM when fewer than eight remain, and `bytes` had
    // already eaten them). With no corpus either, the one input for ever was
    // the zero-length slice.
    const len: usize = smith.slice(&buf);
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    _ = cbor.decode(arena.allocator(), buf[0..len], .{}) catch return;
}

/// The corpus is RFC 8949 Appendix A itself — every vector this module already
/// checks byte-exactly — plus the malformed frames the tests above name.
///
/// ⛔ It is built at run time from `kat.vectors`, and the guard below builds it
/// from the same call, because a guard measuring a different corpus is not a
/// guard.
const DecodeCorpus = struct {
    /// Every Appendix A vector, plus the refusals, plus the empty input.
    const cap = kat.vectors.len + 16;
    store: [cap * (4 + 64)]u8 = undefined,
    used: usize = 0,
    entries: [cap][]const u8 = undefined,
    n: usize = 0,

    fn push(self: *DecodeCorpus, frame: []const u8) void {
        const sd = testkit.fuzz.seedInto(self.store[self.used..], frame);
        self.entries[self.n] = self.store[self.used..][0..sd.len];
        self.used += sd.len;
        self.n += 1;
    }

    fn pushHex(self: *DecodeCorpus, h: []const u8) void {
        var raw: [64]u8 = undefined;
        const frame = std.fmt.hexToBytes(raw[0 .. h.len / 2], h) catch unreachable;
        self.push(frame);
    }

    fn build(self: *DecodeCorpus) []const []const u8 {
        // The 81 Appendix A vectors: every major type, every argument width,
        // both indefinite-length forms, tags, floats and the simple values.
        for (kat.vectors) |v| self.pushHex(v.hex);
        // The refusals the value tests above are about, so the corpus is not
        // "accepted frames only".
        self.pushHex("9BFFFFFFFFFFFFFFFF"); // array claiming 2^64-1 elements
        self.pushHex("5BFFFFFFFFFFFFFFFF"); // byte string claiming 2^64-1 octets
        self.pushHex("01FF"); // trailing `break` after a complete item
        self.pushHex("1C"); // reserved additional-information value
        self.pushHex("FF"); // a bare `break`
        self.pushHex("5F6161FF"); // text chunk inside an indefinite BYTE string
        self.pushHex("5900030102"); // declared 3 octets, 2 present
        self.pushHex("5F41"); // indefinite byte string cut inside a chunk head
        self.pushHex("7F61"); // ditto, text
        self.pushHex("5F5FFFFF"); // an indefinite string nested in an indefinite string
        self.pushHex("41AA02"); // a complete item with trailing garbage after it
        self.pushHex("824161AA81"); // array whose second element is a truncated array
        self.push("");
        return self.entries[0..self.n];
    }
};

test "fuzz: decode never panics on arbitrary bytes" {
    var corpus: DecodeCorpus = .{};
    try std.testing.fuzz({}, fuzzDecodeNeverPanics, .{ .corpus = corpus.build() });
}

test "corpus: every decode seed reaches the decoder, and the counts are pinned" {
    var corpus: DecodeCorpus = .{};
    var nonempty: usize = 0;
    var accepted: usize = 0;
    // ⛔ `accepted` alone is not reach here: `decode` of the one-octet vector
    // `00` succeeds, and so would a corpus that had collapsed to it. `nodes`
    // is the number the collapse cannot hold up — every item in every decoded
    // tree, which only moves when a seed's own octets are walked.
    var nodes: usize = 0;
    for (corpus.build()) |sd| {
        var smith: std.testing.Smith = .{ .in = sd };
        var buf: [4096]u8 = undefined;
        const len: usize = smith.slice(&buf);
        if (len != 0) nonempty += 1;
        var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
        defer arena.deinit();
        const v = cbor.decode(arena.allocator(), buf[0..len], .{}) catch continue;
        accepted += 1;
        nodes += countNodes(v);
    }
    try testing.expectEqual(corpus.n - 1, nonempty); // all but the empty seed
    try testing.expectEqual(@as(usize, 81), accepted);
    try testing.expectEqual(@as(usize, 215), nodes);
}

fn countNodes(v: Value) usize {
    return switch (v) {
        .array => |items| blk: {
            var n: usize = 1;
            for (items) |it| n += countNodes(it);
            break :blk n;
        },
        .map => |entries| blk: {
            var n: usize = 1;
            for (entries) |e| n += countNodes(e.key) + countNodes(e.value);
            break :blk n;
        },
        .tag => |t| 1 + countNodes(t.value.*),
        else => 1,
    };
}

// ── the free path is part of the public API ────────────────────────────────
//
// The module's stated posture is "arena-friendly, not arena-required", but
// `freeValue` was private and the only documented cleanup contract was "free
// the arena" — so for a caller on a plain allocator the posture was not
// deliverable: there was no supported way to release a decoded tree at all.
// This test lives in a *separate file* on purpose. Zig only exposes `pub`
// declarations across a file boundary, so it exercises exactly the property
// the finding is about, and it is the leak-detecting `testing.allocator`
// rather than an arena, so the free path also has to be correct, not just
// reachable.

test "a decoded tree can be freed through the public API, with no arena" {
    // map{ "a": [1, h'0102'], 2: 24("txt") } — one value of every owning
    // shape: text, array + its backing slice, byte string, and a tag with a
    // heap-allocated inner value.
    const bytes = [_]u8{
        0xa2, // map, 2 pairs
        0x61, 'a', // key: text "a"
        0x82, 0x01, 0x42, 0x01, 0x02, // value: [1, h'0102']
        0x02, // key: 2
        0xd8, 0x18, 0x63, 't', 'x', 't', // value: tag(24, "txt")
    };
    const v = try cbor.decode(testing.allocator, &bytes, .{});
    try testing.expectEqual(@as(usize, 2), v.map.len);
    try testing.expectEqualStrings("txt", v.map[1].value.tag.value.text);
    cbor.freeValue(testing.allocator, v);
}

// ── audit 2026-09-01: guards that were correct but held by nothing ─────────

test "boundary: peekByte at end of input is Truncated, never a one-past-end read" {
    // `readBytes`' bound got its boundary test when F1 was closed in 2026-08;
    // `peekByte`'s did not. Relaxing `pos >= len` to `pos > len` survived the
    // whole suite in Debug AND ReleaseFast, and in ReleaseFast that relaxation
    // is a SILENT one-past-end read whose value then steers decoding — the
    // major type of whatever byte follows the buffer decides what gets parsed.
    //
    // Every input below leaves the cursor exactly at the end with `peekByte`
    // as the next operation: the four indefinite-length openers with nothing
    // after them, and three with one complete chunk/element and no `0xff`.
    const at_end = [_][]const u8{
        &[_]u8{0x5f}, // indefinite byte string, then EOF
        &[_]u8{0x7f}, // indefinite text string, then EOF
        &[_]u8{0x9f}, // indefinite array, then EOF
        &[_]u8{0xbf}, // indefinite map, then EOF
        &[_]u8{ 0x9f, 0x01 }, // one element, no break
        &[_]u8{ 0xbf, 0x01, 0x02 }, // one pair, no break
        &[_]u8{ 0x5f, 0x41, 0xaa }, // one chunk, no break
    };
    for (at_end) |input| {
        try testing.expectError(error.Truncated, cbor.decode(testing.allocator, input, .{}));
    }
}

test "reserved additional-info 28/29/30 in major type 7 is Malformed" {
    for ([_]u8{ 0xfc, 0xfd, 0xfe }) |b| {
        try testing.expectError(error.Malformed, cbor.decode(testing.allocator, &[_]u8{b}, .{}));
    }
}

test "an indefinite string chunk may not itself be indefinite (RFC 8949 §3.2.3)" {
    const nested = [_][]const u8{
        &[_]u8{ 0x5f, 0x5f, 0xff, 0xff },
        &[_]u8{ 0x7f, 0x7f, 0xff, 0xff },
        &[_]u8{ 0x5f, 0x41, 0xaa, 0x5f, 0xff, 0xff },
    };
    for (nested) |input| {
        try testing.expectError(error.Malformed, cbor.decode(testing.allocator, input, .{}));
    }
}

test "toI64 rejects exactly at the signed boundary, in both directions" {
    // `toI64` is the accessor the COSE layer resolves every label and
    // algorithm identifier through, so its range check is load-bearing well
    // outside this module. Both loosening mutations survived the suite.
    const max: u64 = std.math.maxInt(i64);
    try testing.expectEqual(@as(?i64, std.math.maxInt(i64)), (Value{ .uint = max }).toI64());
    try testing.expectEqual(@as(?i64, null), (Value{ .uint = max + 1 }).toI64());

    // negint stores the magnitude n for the value -1-n, so the most negative
    // representable value has magnitude maxInt(i64).
    try testing.expectEqual(@as(?i64, std.math.minInt(i64)), (Value{ .negint = max }).toI64());
    try testing.expectEqual(@as(?i64, null), (Value{ .negint = max + 1 }).toI64());
}

test "writeHead emits the shortest form at every width boundary" {
    // No Appendix A vector carries a value of exactly 255 or 65535, so the
    // 1-byte/2-byte and 2-byte/4-byte boundaries were unpinned — and a
    // regression there silently produces non-preferred serialisation, which
    // matters precisely because deterministic output is what this module is
    // used for when something is about to be signed.
    const cases = [_]struct { v: u64, want: []const u8 }{
        .{ .v = 23, .want = &[_]u8{0x17} },
        .{ .v = 24, .want = &[_]u8{ 0x18, 0x18 } },
        .{ .v = 255, .want = &[_]u8{ 0x18, 0xff } },
        .{ .v = 256, .want = &[_]u8{ 0x19, 0x01, 0x00 } },
        .{ .v = 65535, .want = &[_]u8{ 0x19, 0xff, 0xff } },
        .{ .v = 65536, .want = &[_]u8{ 0x1a, 0x00, 0x01, 0x00, 0x00 } },
        .{ .v = 4294967295, .want = &[_]u8{ 0x1a, 0xff, 0xff, 0xff, 0xff } },
        .{ .v = 4294967296, .want = &[_]u8{ 0x1b, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00 } },
        .{ .v = std.math.maxInt(u64), .want = &[_]u8{ 0x1b, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff } },
    };
    for (cases) |c| {
        const out = try cbor.encode(testing.allocator, .{ .uint = c.v }, .{});
        defer testing.allocator.free(out);
        try testing.expectEqualSlices(u8, c.want, out);
    }
}

// ── the leak class, driven by ALLOCATOR failure rather than wire failure ───
//
// The decode leak (audit 2026-08-06) was closed with `errdefer`s, and the
// hostile-input tests exercise them — but only along paths where a MALFORMED
// INPUT triggers the error. An allocation that fails partway through a
// well-formed input takes different paths, and three of them were held by
// nothing: `readArray`'s per-item `errdefer freeValue`, `readMap`'s per-key
// one, and `readMap`'s outer errdefer. `readArray`'s outer equivalent IS
// killed by the shipped suite; `readMap`'s is not, because no test had a map
// whose earlier entry owns an allocation and whose later entry fails.

fn decodeOne(a: std.mem.Allocator, input: []const u8) !void {
    const v = cbor.decode(a, input, .{}) catch |e| switch (e) {
        error.OutOfMemory => return e,
        else => return, // a wire error is the expected outcome for some inputs
    };
    cbor.freeValue(a, v);
}

test "decode frees everything it built when an ALLOCATION fails, not just when the input is bad" {
    const inputs = [_][]const u8{
        // well-formed and owning: the interesting shapes for OOM injection
        &[_]u8{ 0x82, 0x63, 0x61, 0x62, 0x63, 0x63, 0x64, 0x65, 0x66 }, // ["abc","def"]
        &[_]u8{ 0xa2, 0x63, 0x61, 0x62, 0x63, 0x01, 0x63, 0x64, 0x65, 0x66, 0x02 }, // {"abc":1,"def":2}
        &[_]u8{ 0xa1, 0x63, 0x61, 0x62, 0x63, 0x82, 0x63, 0x64, 0x65, 0x66, 0x01 }, // {"abc":["def",1]}
        &[_]u8{ 0x82, 0x81, 0x63, 0x61, 0x62, 0x63, 0x63, 0x64, 0x65, 0x66 }, // [["abc"],"def"]
        &[_]u8{ 0xc1, 0x63, 0x61, 0x62, 0x63 }, // tag(1, "abc")
        &[_]u8{ 0x5f, 0x41, 0xaa, 0x41, 0xbb, 0xff }, // indefinite bstr, 2 chunks
        &[_]u8{ 0x9f, 0x63, 0x61, 0x62, 0x63, 0xff }, // indefinite array
        // truncated after an entry that already owns memory
        &[_]u8{ 0xa2, 0x63, 0x61, 0x62, 0x63, 0x01, 0x63, 0x64, 0x65 },
        &[_]u8{ 0x82, 0x63, 0x61, 0x62, 0x63 },
    };
    for (inputs) |input| {
        try testing.checkAllAllocationFailures(testing.allocator, decodeOne, .{input});
    }
}

fn encodeRoundTrip(a: std.mem.Allocator, canonical: bool) !void {
    const inner = [_]Value{ .{ .uint = 1 }, .{ .uint = 2 }, .{ .uint = 3 } };
    const entries = [_]MapEntry{
        .{ .key = .{ .text = "alpha" }, .value = .{ .bytes = "0123456789" } },
        .{ .key = .{ .text = "beta" }, .value = .{ .array = &inner } },
        .{ .key = .{ .text = "gamma" }, .value = .{ .f64 = 1.5 } },
    };
    const out = try cbor.encode(a, .{ .map = &entries }, .{ .canonical = canonical });
    a.free(out);
}

test "encode frees its partial output when an allocation fails" {
    // Found by this audit: `encode` had no `errdefer` on its output buffer, so
    // any failure inside `encodeInto` -- or in `toOwnedSlice`'s own final
    // resize -- abandoned every byte already produced. 129 bytes allocated, 0
    // freed. This also pins `14ef4331`'s canonical-scratch fix, which until
    // now was caught only by the example's leak-checking allocator, so a
    // reintroduced leak looked green under a plain `zig build test-cbor`.
    try testing.checkAllAllocationFailures(testing.allocator, encodeRoundTrip, .{false});
    try testing.checkAllAllocationFailures(testing.allocator, encodeRoundTrip, .{true});
}
