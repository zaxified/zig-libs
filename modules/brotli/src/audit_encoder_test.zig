// SPDX-License-Identifier: MIT

//! Tests asked for by the 2026-10-27 mutation run (A1): each names the
//! mutant it kills.

const std = @import("std");
const testing = std.testing;
const encoder = @import("encoder.zig");
const decoder = @import("decoder.zig");
const parallel = @import("parallel.zig");
const shared_dictionary = @import("shared_dictionary.zig");

// ---------------------------------------------------------------------------
// shared_dictionary.parse: negative tests (m81..m93)
// ---------------------------------------------------------------------------

fn expectInvalid(bytes: []const u8) !void {
    try testing.expectError(error.InvalidSharedDictionary, shared_dictionary.parse(testing.allocator, bytes));
}

fn expectValid(bytes: []const u8) !void {
    var d = try shared_dictionary.parse(testing.allocator, bytes);
    d.deinit();
}

/// A dictionary with no LZ77 bytes, no word list and one transform list:
/// stringlet data `ps`, `triplets` (3 bytes each), `params` (after the
/// triplets, only when a shift is present) and `tail` (NUM_DICTIONARIES,
/// the pairs, the context flag and map).
fn oneTransformList(gpa: std.mem.Allocator, ps: []const u8, triplets: []const u8, params: []const u8, tail: []const u8) ![]u8 {
    var b: std.ArrayList(u8) = .empty;
    errdefer b.deinit(gpa);
    try b.appendSlice(gpa, &.{ 0x91, 0x00, 0, 0, 1 });
    try b.appendSlice(gpa, &.{ @truncate(ps.len), @truncate(ps.len >> 8) });
    try b.appendSlice(gpa, ps);
    try b.append(gpa, @intCast(triplets.len / 3));
    try b.appendSlice(gpa, triplets);
    try b.appendSlice(gpa, params);
    try b.appendSlice(gpa, tail);
    return b.toOwnedSlice(gpa);
}

fn expectTransformList(ps: []const u8, triplets: []const u8, params: []const u8, tail: []const u8, valid: bool) !void {
    const gpa = testing.allocator;
    const bytes = try oneTransformList(gpa, ps, triplets, params, tail);
    defer gpa.free(bytes);
    if (valid) try expectValid(bytes) else try expectInvalid(bytes);
}

const plain_tail = [_]u8{ 1, 0, 0, 0 };

test "A1 m81: a varint of nine continuation bytes is refused (63-bit limit)" {
    // LZ77 length: eight 0x80 bytes and a ninth that still has its high bit
    // set; a tenth byte ends it. The mutant (`k == 9`) lets the ninth pass
    // and reads 0, so the rest (no word lists, no transform lists) parses.
    var bad: [2 + 10 + 2]u8 = undefined;
    bad[0] = 0x91;
    bad[1] = 0x00;
    @memset(bad[2..11], 0x80);
    bad[11] = 0x00;
    bad[12] = 0; // n_words
    bad[13] = 0; // n_transforms
    try expectInvalid(&bad);
    // Control: the ninth byte without its high bit is the longest legal form.
    var good: [2 + 9 + 2]u8 = undefined;
    good[0] = 0x91;
    good[1] = 0x00;
    @memset(good[2..10], 0x80);
    good[10] = 0x00;
    good[11] = 0;
    good[12] = 0;
    try expectValid(&good);
}

test "A1 m82: 65 word lists are refused, 64 are not" {
    const gpa = testing.allocator;
    for ([_]usize{ 64, 65 }) |n| {
        var b: std.ArrayList(u8) = .empty;
        defer b.deinit(gpa);
        try b.appendSlice(gpa, &.{ 0x91, 0x00, 0, @intCast(n) });
        try b.appendNTimes(gpa, 0, 28 * n); // every list empty
        try b.append(gpa, 0); // n_transforms
        // One dictionary: (no custom words, no custom transforms), no context map.
        try b.appendSlice(gpa, &.{ 1, @intCast(n), 0, 0 });
        if (n == 64) try expectValid(b.items) else try expectInvalid(b.items);
    }
}

test "A1 m85: 257 stringlets are refused, 256 are not" {
    const gpa = testing.allocator;
    for ([_]usize{ 256, 257 }) |count| {
        // count - 1 one-byte stringlets, then the empty one.
        var ps: std.ArrayList(u8) = .empty;
        defer ps.deinit(gpa);
        for (0..count - 1) |_| try ps.appendSlice(gpa, &.{ 1, 'a' });
        try ps.append(gpa, 0);
        try expectTransformList(ps.items, &.{}, &.{}, &plain_tail, count == 256);
    }
}

test "A1 m86: bytes after the empty stringlet are refused" {
    try expectTransformList(&.{ 1, 'x', 0 }, &.{}, &.{}, &plain_tail, true);
    try expectTransformList(&.{ 1, 'x', 0, 'y' }, &.{}, &.{}, &plain_tail, false);
}

test "A1 m88: a prefix id equal to the stringlet count is refused" {
    // Two stringlets ("x" and the empty one): ids 0 and 1.
    const ps = [_]u8{ 1, 'x', 0 };
    try expectTransformList(&ps, &.{ 1, 0, 1 }, &.{}, &plain_tail, true);
    try expectTransformList(&ps, &.{ 2, 0, 0 }, &.{}, &plain_tail, false);
}

test "A1 m90: a non-shift operation with a nonzero parameter is refused" {
    const ps = [_]u8{ 1, 'x', 0 };
    // Transform 0 is Identity, transform 1 ShiftFirst (21): params follow.
    const tri = [_]u8{ 0, 0, 0, 0, 21, 0 };
    try expectTransformList(&ps, &tri, &.{ 0, 0, 2, 0 }, &plain_tail, true);
    try expectTransformList(&ps, &tri, &.{ 1, 0, 2, 0 }, &plain_tail, false);
}

test "A1 m92: a context flag of 2 is refused" {
    const ps = [_]u8{ 1, 'x', 0 };
    try expectTransformList(&ps, &.{}, &.{}, &.{ 1, 0, 0, 0 }, true);
    try expectTransformList(&ps, &.{}, &.{}, &.{ 1, 0, 0, 2 }, false);
}

test "A1 m93: a context map entry equal to the dictionary count is refused" {
    const ps = [_]u8{ 1, 'x', 0 };
    var map_ok: [4 + 64]u8 = @splat(0);
    map_ok[0] = 1;
    map_ok[3] = 1;
    try expectTransformList(&ps, &.{}, &.{}, &map_ok, true);
    // One dictionary, so the only legal entry is 0; the last one is 1.
    map_ok[4 + 63] = 1;
    try expectTransformList(&ps, &.{}, &.{}, &map_ok, false);
}

// ---------------------------------------------------------------------------
// .q0 (m9, m10, m21, m4, m29)
// ---------------------------------------------------------------------------

/// `n` bytes below `alphabet` in which no 5 bytes repeat (`.q0` finds no
/// match in them: its matches are 5 bytes), from the first seed that gives
/// such a sequence.
fn distinctFives(gpa: std.mem.Allocator, n: usize, alphabet: u8) ![]u8 {
    const buf = try gpa.alloc(u8, n);
    errdefer gpa.free(buf);
    var seen: std.AutoHashMapUnmanaged(u64, void) = .empty;
    defer seen.deinit(gpa);
    var seed: u64 = 1;
    while (seed < 10_000) : (seed += 1) {
        var prng = std.Random.DefaultPrng.init(seed);
        const rnd = prng.random();
        for (buf) |*b| b.* = rnd.uintLessThan(u8, alphabet);
        seen.clearRetainingCapacity();
        var distinct = true;
        for (0..n - 4) |i| {
            var k: u64 = 0;
            for (buf[i..][0..5]) |c| k = k << 8 | c;
            if ((try seen.getOrPut(gpa, k)).found_existing) {
                distinct = false;
                break;
            }
        }
        if (distinct) return buf;
    }
    return error.TestUnexpectedResult;
}

fn q0Stream(gpa: std.mem.Allocator, input: []const u8) ![]u8 {
    const s = try encoder.compressWith(gpa, input, .{ .effort = .q0 });
    errdefer gpa.free(s);
    const back = try decoder.decompress(gpa, s, .{ .max_output = input.len + 1 });
    defer gpa.free(back);
    try testing.expectEqualSlices(u8, input, back);
    return s;
}

test "A1 m9: an insert of exactly 2114 literals writes its 12 extra bits" {
    // No match anywhere, so the whole input is one tail insert of 2114
    // (`q0InsertLen`: code 61 with 12 extra bits from 2114 on). The
    // mutant (`<=`) writes 11 and the decoder reads the literals one bit off.
    const gpa = testing.allocator;
    const input = try distinctFives(gpa, 2114, 32);
    defer gpa.free(input);
    const s = try q0Stream(gpa, input);
    defer gpa.free(s);
    // Compressed (5 bits a literal), not stored.
    try testing.expect(s.len < 2114 * 3 / 4);
}

test "A1 m10: an insert of exactly 22594 literals uses code 63 with 24 extra bits" {
    // 22594 literals of a 64-symbol alphabet (6 bits each: compressible, so
    // neither stored here nor by `compressBlock`). Mutant `<=` writes code 62
    // with a 14-bit field that holds 16384 — which needs 15 bits.
    const gpa = testing.allocator;
    const input = try distinctFives(gpa, 22594, 64);
    defer gpa.free(input);
    const s = try q0Stream(gpa, input);
    defer gpa.free(s);
    try testing.expect(s.len < 22594 * 9 / 10);
}

test "A1 m21: a long compressible tail insert is not stored" {
    // 7000 literals (>= 6210) of 6 bits each at the end of the meta-block:
    // `literal_ratio` (about 750 thousandths) is below 980, so they are
    // coded. The mutant (`> 0`) stores them: the stream is then larger than
    // the input.
    const gpa = testing.allocator;
    const input = try distinctFives(gpa, 7000, 64);
    defer gpa.free(input);
    const s = try q0Stream(gpa, input);
    defer gpa.free(s);
    try testing.expect(s.len < 7000 * 9 / 10);
}

// m19 (`total_block_size + block_size <= 1 << 20` -> `1 << 21`) is equivalent:
// `writeQ0` is given one block, at most `compressed_block_size` = 1 MiB
// (`CompressOptions.sanitized` and `StreamOptions` clamp `block_size`), and
// `total_block_size + block_size` never exceeds the bytes it was given.
// m33 (`< store_bits` -> `<=` in `compressBlock`'s tight-buffer path) is
// equivalent: on a tie the mutant copies the compressed block into `w`, but
// the check at the end of `compressBlock` (`w.bitPos() < store_bits`, equal
// then) rolls it back and stores the block — the same bytes.

fn hex(digest: [32]u8) [64]u8 {
    return std.fmt.bytesToHex(digest, .lower);
}

fn expectPin(what: []const u8, got: [64]u8, want: []const u8) !void {
    if (!std.mem.eql(u8, &got, want)) {
        std.debug.print("PIN {s} = {s}\n", .{ what, &got });
        return error.TestExpectedEqual;
    }
}

test "A1 m4b: a copy ending at ip_limit takes no further copy there" {
    // '#', "VWXYZ" (probed at position 1, so in the table), 120 distinct
    // bytes U five times, "VWXYZ", 11 more bytes: n = 622, ip_limit = n - 16
    // = 606. The copy of U (distance 120) ends at 606 exactly; there the real
    // loop stops and writes the last 16 bytes as literals. `ip > ip_limit`
    // goes on, finds "VWXYZ" at position 1 and writes one more copy: other
    // bytes. (U repeats so the block is compressed -- a stored block would
    // hide the difference.)
    const gpa = testing.allocator;
    const l = 120;
    const reps = 5;
    var in: [1 + 5 + reps * l + 5 + 11]u8 = undefined;
    in[0] = '#';
    @memcpy(in[1..6], "VWXYZ");
    for (0..reps * l) |i| in[6 + i] = @intCast(0x80 + i % l);
    @memcpy(in[6 + reps * l ..][0..5], "VWXYZ");
    for (0..11) |i| in[11 + reps * l + i] = @intCast(0x30 + i);
    const out = try encoder.compressWith(gpa, &in, .{ .effort = .q0 });
    defer gpa.free(out);
    try testing.expect(out.len * 2 < in.len); // compressed, not stored
    const back = try decoder.decompress(gpa, out, .{});
    defer gpa.free(back);
    try testing.expectEqualSlices(u8, &in, back);
    var sum: [32]u8 = undefined;
    std.crypto.hash.sha2.Sha256.hash(out, &sum, .{});
    // Today's bytes (2026-10-27).
    try expectPin("m4b", hex(sum), "c02e8f71f8d0d2a412085e5362fa79014351e55c08a51adee53c06be6287cfc9");
}

test "A1 q0 byte pin: periodic inputs ending near ip_limit" {
    // Pins today's `.q0` bytes of eight inputs of 394 bytes (compared as one
    // SHA-256 of the eight streams, each also round-tripped); google/brotli's
    // decoder blessing covers `.q0` through the interop shapes. The input
    // ends a copy exactly at `ip_limit` (n - 16): a periodic text with one
    // substituted byte there, which starts a 5-byte window planted early
    // ("Xbcde" at 2). The reference stops (the last 16 bytes are literals);
    // the mutant (`ip > ip_limit`) goes on and writes one more 5-byte copy.
    const gpa = testing.allocator;
    const n = 394;
    var h: std.crypto.hash.sha2.Sha256 = .init(.{});
    for (0..8) |seed| {
        var prng = std.Random.DefaultPrng.init(seed);
        const rnd = prng.random();
        var in: [n]u8 = undefined;
        for (&in) |*b| b.* = 128 + rnd.uintLessThan(u8, 128);
        @memcpy(in[2..7], "Xbcde");
        for (in[28..], 28..) |*b, p| b.* = "abcdefg"[(p - 28) % 7];
        in[n - 16] = 'X';
        const s = try q0Stream(gpa, &in);
        defer gpa.free(s);
        try testing.expect(s.len < 150);
        h.update(s);
    }
    try expectPin("m4", hex(h.finalResult()), "ec5d9ae62c4a7d8ae5fe7ebb07a6a28e39c11706102f8764549d98c2d7411dff");
}

test "A1 m29: the literal histogram counts a symbol's first 11 occurrences three times (byte pin)" {
    // Pins today's `.q0` bytes (one SHA-256 over four streams, each also
    // round-tripped; google/brotli's decoder blessing covers `.q0` through
    // the interop shapes). Five symbols, so a complex code, with weights
    // 3v up to 11 and v + 22 above: three of 11 (33 each), one of 43 (65;
    // the mutant's `min(v, 12)` gives it 67) and one of 1000. Huffman merges
    // 33 + 33 = 66, then 33 + 65 (lengths 3, 3, 3, 3, 1) — but 33 + 66 against
    // 67 under the mutant (lengths 4, 4, 3, 2, 1): another code header.
    const gpa = testing.allocator;
    var h: std.crypto.hash.sha2.Sha256 = .init(.{});
    for (0..4) |seed| {
        var in: [3 * 11 + 43 + 1000]u8 = undefined;
        var at: usize = 0;
        for ([_]struct { u8, usize }{ .{ 1, 11 }, .{ 2, 11 }, .{ 3, 11 }, .{ 4, 43 }, .{ 5, 1000 } }) |sc| {
            @memset(in[at..][0..sc[1]], sc[0]);
            at += sc[1];
        }
        var prng = std.Random.DefaultPrng.init(seed);
        const rnd = prng.random();
        var i: usize = in.len;
        while (i > 1) {
            i -= 1;
            std.mem.swap(u8, &in[i], &in[rnd.uintLessThan(usize, i + 1)]);
        }
        const s = try q0Stream(gpa, &in);
        defer gpa.free(s);
        h.update(s);
    }
    try expectPin("m29", hex(h.finalResult()), "347b2b923ccb67426f658d35a3c5dea2c7506f14ad12206ed15da7910ae13aa8");
}

// ---------------------------------------------------------------------------
// parallel (m101)
// ---------------------------------------------------------------------------

test "A1 m101: a job size below min_job_size counts as min_job_size" {
    // Without the floor, `job_size = 1` cuts the input into one job a byte
    // (and different bytes); with it, 1 and 0 and `min_job_size` itself are
    // the same two jobs.
    const gpa = testing.allocator;
    const n = parallel.min_job_size + 1000;
    const input = try gpa.alloc(u8, n);
    defer gpa.free(input);
    var prng = std.Random.DefaultPrng.init(7);
    const rnd = prng.random();
    for (input) |*b| b.* = "etaoin shrdlu\n"[rnd.uintLessThan(usize, 14)];
    const opts: encoder.CompressOptions = .{ .effort = .q0 };
    const want = try parallel.compress(gpa, testing.io, input, opts, .{ .job_size = parallel.min_job_size, .threads = 1 });
    defer gpa.free(want);
    for ([_]usize{ 0, 1 }) |job| {
        const got = try parallel.compress(gpa, testing.io, input, opts, .{ .job_size = job, .threads = 1 });
        defer gpa.free(got);
        try testing.expectEqualSlices(u8, want, got);
    }
    const back = try decoder.decompress(gpa, want, .{ .max_output = n + 1 });
    defer gpa.free(back);
    try testing.expectEqualSlices(u8, input, back);
}
