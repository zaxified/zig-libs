// SPDX-License-Identifier: MIT
//! Dictionary loading tests found by open-mutant batch 2: what
//! `cdict.loadDictionaryContent` keeps of a dictionary too large for the
//! tables or the index range. Each dictionary is random bytes `P` followed
//! by a long run of zeros: every position of the run hashes to one slot, so
//! the entries made for `P` survive any later insertion, and an input equal
//! to `P` is compressed only if `P` itself was loaded. Expectations follow
//! `ZSTD_loadDictionaryContent` (only the end of a dictionary that does not
//! fit is loaded).

const std = @import("std");
const zstd = @import("root.zig");

const gpa = std.testing.allocator;

/// `P` of `p_len` random bytes then `zeros` zero bytes.
fn pThenZeros(p_len: usize, zeros: usize) ![]u8 {
    const d = try gpa.alloc(u8, p_len + zeros);
    var prng: std.Random.DefaultPrng = .init(0x5eed_0b2);
    prng.random().bytes(d[0..p_len]);
    @memset(d[p_len..], 0);
    return d;
}

fn framed(c: *zstd.Compressor, src: []const u8, opts: zstd.Options) !usize {
    const dst = try gpa.alloc(u8, zstd.compressBound(src.len) + 64);
    defer gpa.free(dst);
    return c.compress(dst, src, opts);
}

fn framedCDict(c: *zstd.Compressor, src: []const u8, cd: *const zstd.CDict) !usize {
    const dst = try gpa.alloc(u8, zstd.compressBound(src.len) + 64);
    defer gpa.free(dst);
    return c.compressUsingCDict(dst, src, cd, .{});
}

test "w10zb2 a dictionary past the table's reach loads only its end (context)" {
    const p_len = 600;
    const dict = try pThenZeros(p_len, 9000);
    defer gpa.free(dict);
    const pc = try gpa.dupe(u8, dict[0..p_len]); // not inside the dictionary's memory: an overlap shortens it
    defer gpa.free(pc);
    var c: zstd.Compressor = .init(gpa);
    defer c.deinit();
    // fast, hash log 10, chain log 6: 2^13 bytes are indexed
    const n = try framed(&c, pc, .{
        .level = 1,
        .advanced = .{ .strategy = .fast, .window_log = 14, .hash_log = 10, .chain_log = 6 },
        .dictionary = .{ .prefix = .{ .bytes = dict } },
    });
    try std.testing.expect(n >= p_len);
}

test "w10zb2 a dictionary past the table's reach loads only its end (CDict)" {
    const p_len = 600;
    const dict = try pThenZeros(p_len, 9000);
    defer gpa.free(dict);
    const pc = try gpa.dupe(u8, dict[0..p_len]); // not inside the dictionary's memory: an overlap shortens it
    defer gpa.free(pc);
    var cd = try zstd.CDict.initAdvanced(gpa, dict, .{
        .level = 1,
        .advanced = .{ .strategy = .fast, .window_log = 14, .hash_log = 10, .chain_log = 6 },
    });
    defer cd.deinit();
    var c: zstd.Compressor = .init(gpa);
    defer c.deinit();
    const n = try framedCDict(&c, pc, &cd);
    try std.testing.expect(n >= p_len);
}

test "w10zb2 a dictionary within the table's reach is loaded whole" {
    const p_len = 600;
    const dict = try pThenZeros(p_len, 3000);
    defer gpa.free(dict);
    const pc = try gpa.dupe(u8, dict[0..p_len]); // not inside the dictionary's memory: an overlap shortens it
    defer gpa.free(pc);
    var c: zstd.Compressor = .init(gpa);
    defer c.deinit();
    const n = try framed(&c, pc, .{
        .level = 1,
        .advanced = .{ .strategy = .fast, .window_log = 14, .hash_log = 10, .chain_log = 6 },
        .dictionary = .{ .prefix = .{ .bytes = dict } },
    });
    try std.testing.expect(n < p_len / 2);
}

test "w10zb2 a context loads a dictionary of over 16 MiB whole" {
    const p_len = 2048;
    const dict = try pThenZeros(p_len, (16 << 20) + 4096);
    defer gpa.free(dict);
    const pc = try gpa.dupe(u8, dict[0..p_len]); // not inside the dictionary's memory: an overlap shortens it
    defer gpa.free(pc);
    var c: zstd.Compressor = .init(gpa);
    defer c.deinit();
    // the short-cache index limit is for a CDict only
    const n = try framed(&c, pc, .{
        .level = 1,
        .advanced = .{ .strategy = .fast, .window_log = 25, .hash_log = 22, .chain_log = 12 },
        .dictionary = .{ .prefix = .{ .bytes = dict } },
    });
    try std.testing.expect(n < p_len / 2);
}

test "w10zb2 a fast CDict keeps the last 2^24 bytes of a larger dictionary" {
    const p_len = 2048;
    const dict = try pThenZeros(p_len, (16 << 20) + 4096);
    defer gpa.free(dict);
    const pc = try gpa.dupe(u8, dict[0..p_len]); // not inside the dictionary's memory: an overlap shortens it
    defer gpa.free(pc);
    var cd = try zstd.CDict.initAdvanced(gpa, dict, .{
        .level = 1,
        .advanced = .{ .strategy = .fast, .window_log = 25, .hash_log = 22, .chain_log = 12 },
    });
    defer cd.deinit();
    var c: zstd.Compressor = .init(gpa);
    defer c.deinit();
    const n = try framedCDict(&c, pc, &cd);
    try std.testing.expect(n >= p_len);
}

test "w10zb2 a fast CDict of under 2^24 bytes is loaded whole" {
    const p_len = 2048;
    const dict = try pThenZeros(p_len, 8 << 20);
    defer gpa.free(dict);
    const pc = try gpa.dupe(u8, dict[0..p_len]);
    defer gpa.free(pc);
    var cd = try zstd.CDict.initAdvanced(gpa, dict, .{
        .level = 1,
        .advanced = .{ .strategy = .fast, .window_log = 25, .hash_log = 22, .chain_log = 12 },
    });
    defer cd.deinit();
    var c: zstd.Compressor = .init(gpa);
    defer c.deinit();
    const n = try framedCDict(&c, pc, &cd);
    try std.testing.expect(n < p_len / 2);
}

fn greedyCDictLen(zeros: usize) !usize {
    const p_len = 2048;
    const dict = try pThenZeros(p_len, zeros);
    defer gpa.free(dict);
    const pc = try gpa.dupe(u8, dict[0..p_len]);
    defer gpa.free(pc);
    var cd = try zstd.CDict.initAdvanced(gpa, dict, .{
        .level = 5,
        .advanced = .{ .strategy = .greedy, .window_log = 25, .hash_log = 22, .chain_log = 12, .row_match_finder = .disable },
    });
    defer cd.deinit();
    var c: zstd.Compressor = .init(gpa);
    defer c.deinit();
    return framedCDict(&c, pc, &cd);
}

test "w10zb2 a greedy CDict loads a dictionary of over 16 MiB whole (the short-cache limit is for fast and dfast)" {
    if (!@import("params.zig").all_strategies) return error.SkipZigTest;
    try std.testing.expect(try greedyCDictLen(8 << 20) < 1024);
    try std.testing.expect(try greedyCDictLen((16 << 20) + 4096) < 1024);
}

/// The input is `a` random bytes then the first 300 bytes of an 8000-byte
/// random dictionary, at a distance over the 2^10 window.
fn farDictionaryLen(force_max_window: bool) !struct { n: usize, len: usize } {
    const dict = try gpa.alloc(u8, 8000);
    defer gpa.free(dict);
    var prng: std.Random.DefaultPrng = .init(0xd1c7);
    prng.random().bytes(dict);
    const src = try gpa.alloc(u8, 800);
    defer gpa.free(src);
    prng.random().bytes(src[0..500]);
    @memcpy(src[500..], dict[0..300]);
    var c: zstd.Compressor = .init(gpa);
    defer c.deinit();
    const n = try framed(&c, src, .{
        .level = 1,
        .advanced = .{
            .window_log = 10,
            .force_max_window = force_max_window,
            .long_distance_matching = .enable,
            .ldm_hash_log = 16,
            .ldm_min_match = 32,
            .ldm_hash_rate_log = 1,
            .ldm_bucket_size_log = 1,
        },
        .dictionary = .{ .prefix = .{ .bytes = dict } },
    });
    return .{ .n = n, .len = src.len };
}

test "w10zb2 with force_max_window a dictionary beyond the window is never matched, long-distance or not" {
    // without it the dictionary counts until the input is a window past it
    const free = try farDictionaryLen(false);
    try std.testing.expect(free.n + 200 < free.len);
    const forced = try farDictionaryLen(true);
    try std.testing.expect(forced.n >= forced.len);
}
