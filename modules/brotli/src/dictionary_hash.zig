// SPDX-License-Identifier: MIT
//! The static dictionary's hash table for `.q9` (RFC 7932 §8 words found
//! the way google/brotli's qualities 5–9 find them, `Matcher.findWord`).
//!
//! Port of google/brotli 1.2.0 `c/enc/dictionary_hash.c`
//! (`BrotliEncoderInitDictionaryHash`, MIT, see `NOTICE`): 2^15 buckets, two
//! per 14-bit hash of a word's first four bytes — the even one for words of
//! eight bytes or more, the odd one for shorter words. Each bucket names one
//! word; where several words share a bucket, `frozen` (google's
//! `frozen_idx`, one bit per word in the order the loop below visits them)
//! marks the one google chose by measurement, and otherwise the last one
//! visited stays. Changes: built at comptime from `dictionary.data` instead of
//! the compiled-in `dictionary_hash_inc.h`; a test pins the result to that
//! table's SHA-256.

const std = @import("std");
const dictionary = @import("dictionary.zig");

pub const num_buckets = 1 << 15;

/// The 14-bit hash of the four bytes at `p` (google `Hash14`).
pub inline fn hash14(p: *const [4]u8) u32 {
    return (std.mem.readInt(u32, p, .little) *% 0x1e35a7bd) >> (32 - 14);
}

pub const Table = struct {
    /// Index of the bucket's word among the words of its length.
    words: [num_buckets]u16,
    /// The word's length; 0 for an empty bucket.
    lengths: [num_buckets]u8,
};

pub const table: Table = blk: {
    @setEvalBranchQuota(2_000_000);
    var t: Table = .{ .words = @splat(0), .lengths = @splat(0) };
    var final: [num_buckets]bool = @splat(false);
    var global: usize = 0;
    var len: usize = dictionary.max_word_length;
    while (len >= dictionary.min_word_length) : (len -= 1) {
        const n: usize = @as(usize, 1) << dictionary.size_bits_by_length[len];
        const words = dictionary.data[dictionary.offsets_by_length[len]..];
        for (0..n) |i| {
            const j = n - 1 - i;
            const idx = (hash14(words[len * j ..][0..4]) << 1) + @intFromBool(len < 8);
            if (!final[idx]) {
                t.words[idx] = j;
                t.lengths[idx] = len;
                final[idx] = frozen[global / 8] & (1 << (global % 8)) != 0;
            }
            global += 1;
        }
    }
    break :blk t;
};

/// google/brotli `frozen_idx`: one bit per dictionary word, LSB first, in
/// the order `table` visits them (lengths 24 down to 4, each length's words
/// last to first).
const frozen = [1688]u8{
    0,   0,   8,   164, 32,  56,  31,  191, 36,  4,   128, 81,  68,  132, 145, 129, 0,   0,   0,   28,  0,   8,   1,   1,
    64,  3,   1,   0,   0,   0,   0,   0,   4,   64,  1,   2,   128, 0,   132, 49,  0,   0,   0,   0,   0,   0,   0,   0,
    17,  0,   0,   0,   1,   0,   36,  152, 0,   0,   0,   0,   128, 8,   0,   0,   128, 0,   0,   8,   0,   0,   64,  0,
    0,   0,   0,   0,   0,   0,   0,   0,   8,   0,   0,   0,   1,   0,   64,  133, 0,   32,  0,   0,   128, 1,   0,   0,
    0,   0,   4,   4,   4,   32,  16,  130, 0,   128, 8,   0,   0,   0,   0,   0,   64,  0,   64,  0,   160, 0,   148, 53,
    0,   0,   0,   0,   0,   128, 0,   130, 0,   0,   0,   8,   0,   0,   0,   0,   0,   48,  0,   0,   0,   0,   0,   0,
    32,  1,   32,  129, 0,   12,  0,   1,   0,   0,   0,   0,   0,   0,   0,   16,  0,   0,   0,   16,  32,  0,   0,   0,
    0,   0,   0,   0,   0,   1,   0,   0,   8,   0,   0,   2,   0,   0,   0,   0,   0,   32,  0,   0,   0,   2,   66,  128,
    0,   0,   16,  0,   0,   0,   0,   64,  1,   6,   128, 8,   0,   192, 24,  32,  0,   0,   8,   4,   128, 128, 2,   160,
    0,   160, 0,   64,  0,   0,   2,   0,   0,   0,   0,   0,   0,   0,   0,   0,   32,  1,   0,   0,   64,  0,   0,   0,
    0,   0,   0,   32,  0,   66,  0,   2,   0,   4,   0,   8,   0,   2,   0,   0,   33,  8,   0,   0,   0,   8,   0,   128,
    162, 4,   128, 0,   2,   33,  0,   160, 0,   8,   0,   64,  0,   160, 0,   129, 4,   0,   0,   32,  0,   0,   32,  0,
    2,   0,   0,   0,   0,   0,   0,   128, 0,   0,   0,   0,   0,   64,  10,  0,   0,   0,   0,   32,  64,  0,   0,   0,
    0,   0,   16,  0,   16,  16,  0,   0,   80,  2,   0,   0,   0,   0,   8,   0,   0,   16,  0,   8,   0,   0,   0,   8,
    64,  128, 0,   0,   0,   8,   208, 0,   0,   0,   0,   0,   0,   0,   32,  0,   0,   0,   0,   0,   0,   32,  0,   8,
    0,   128, 0,   0,   0,   1,   0,   0,   0,   16,  8,   1,   136, 0,   0,   36,  0,   64,  9,   0,   1,   32,  8,   0,
    64,  64,  131, 16,  224, 32,  4,   0,   4,   5,   160, 0,   131, 0,   4,   96,  0,   0,   184, 192, 0,   177, 205, 96,
    0,   0,   0,   0,   2,   0,   32,  0,   0,   0,   0,   0,   0,   0,   0,   64,  0,   0,   128, 0,   0,   8,   0,   0,
    0,   0,   1,   4,   0,   1,   0,   0,   0,   4,   0,   0,   0,   0,   0,   0,   4,   0,   0,   64,  69,  0,   0,   8,
    2,   66,  32,  64,  0,   0,   0,   0,   0,   1,   0,   128, 17,  0,   0,   0,   0,   0,   0,   0,   0,   0,   0,   12,
    0,   16,  0,   0,   4,   128, 64,  0,   0,   0,   0,   0,   0,   0,   0,   224, 0,   8,   0,   0,   130, 16,  64,  128,
    2,   64,  0,   0,   0,   128, 2,   192, 64,  0,   65,  0,   0,   0,   16,  0,   0,   0,   32,  4,   2,   2,   76,  0,
    0,   0,   4,   72,  52,  131, 44,  76,  0,   0,   0,   0,   64,  1,   16,  148, 4,   0,   16,  10,  64,  0,   2,   0,
    1,   0,   128, 64,  68,  0,   0,   0,   0,   0,   64,  144, 0,   8,   0,   2,   0,   0,   0,   0,   0,   0,   3,   64,
    0,   0,   0,   0,   1,   128, 0,   0,   32,  66,  0,   0,   0,   40,  0,   18,  0,   0,   0,   0,   0,   33,  0,   0,
    32,  0,   0,   32,  0,   128, 4,   64,  145, 140, 0,   0,   0,   128, 0,   2,   0,   0,   20,  0,   80,  38,  0,   0,
    32,  0,   32,  64,  4,   4,   0,   4,   0,   0,   0,   129, 4,   0,   0,   144, 17,  32,  130, 16,  132, 24,  134, 0,
    0,   64,  2,   5,   50,  8,   194, 33,  1,   68,  117, 1,   8,   32,  161, 54,  0,   130, 34,  0,   0,   0,   64,  128,
    0,   0,   2,   0,   0,   0,   0,   32,  1,   0,   0,   0,   3,   14,  0,   0,   0,   0,   0,   16,  4,   0,   0,   0,
    0,   0,   0,   0,   0,   96,  1,   24,  18,  0,   1,   128, 24,  0,   64,  0,   4,   0,   16,  128, 0,   64,  0,   0,
    0,   64,  0,   8,   0,   0,   0,   0,   0,   66,  128, 0,   0,   0,   0,   0,   0,   0,   0,   0,   0,   0,   0,   0,
    0,   0,   16,  0,   64,  2,   0,   0,   0,   0,   6,   0,   8,   8,   2,   0,   64,  0,   0,   0,   0,   128, 2,   2,
    12,  64,  0,   64,  0,   8,   0,   128, 32,  0,   0,   10,  0,   0,   32,  0,   128, 32,  33,  8,   136, 0,   96,  64,
    0,   0,   0,   0,   0,   64,  4,   16,  4,   8,   0,   0,   0,   16,  0,   2,   0,   0,   1,   128, 0,   64,  16,  0,
    0,   0,   0,   0,   0,   0,   0,   8,   0,   0,   2,   0,   16,  0,   4,   0,   8,   0,   0,   0,   0,   0,   20,  0,
    0,   0,   0,   1,   0,   0,   0,   0,   0,   0,   0,   0,   0,   0,   0,   8,   136, 0,   0,   0,   0,   0,   8,   0,
    0,   0,   0,   0,   2,   0,   0,   0,   64,  0,   0,   1,   0,   2,   0,   0,   0,   0,   0,   0,   0,   0,   0,   128,
    0,   0,   0,   0,   4,   0,   0,   0,   0,   65,  0,   0,   0,   0,   0,   0,   0,   0,   0,   0,   4,   0,   0,   0,
    0,   0,   0,   0,   0,   0,   0,   0,   2,   128, 0,   0,   0,   8,   2,   0,   0,   128, 0,   16,  2,   0,   0,   4,
    0,   32,  0,   0,   1,   4,   64,  64,  0,   4,   0,   1,   0,   16,  0,   32,  68,  4,   4,   65,  10,  0,   20,  37,
    18,  1,   148, 0,   32,  128, 3,   8,   0,   64,  0,   0,   0,   0,   0,   0,   4,   0,   16,  1,   128, 0,   0,   0,
    128, 16,  0,   0,   0,   0,   1,   128, 0,   0,   128, 64,  128, 64,  0,   130, 0,   164, 8,   0,   0,   1,   64,  128,
    0,   18,  0,   2,   150, 0,   8,   0,   0,   64,  0,   81,  0,   0,   16,  128, 2,   8,   36,  32,  129, 4,   144, 13,
    0,   0,   3,   8,   1,   0,   2,   0,   0,   64,  0,   5,   0,   1,   34,  1,   32,  2,   16,  128, 128, 128, 0,   0,
    0,   2,   0,   4,   18,  8,   12,  34,  32,  192, 6,   64,  224, 33,  0,   0,   137, 72,  64,  0,   24,  8,   128, 128,
    0,   16,  0,   32,  128, 128, 132, 8,   0,   0,   16,  0,   64,  0,   0,   4,   0,   0,   16,  0,   4,   128, 64,  0,
    0,   1,   0,   4,   64,  32,  144, 130, 2,   128, 0,   192, 0,   64,  82,  64,  1,   32,  128, 128, 2,   0,   84,  0,
    32,  0,   44,  24,  72,  80,  32,  16,  0,   0,   44,  16,  96,  64,  1,   72,  131, 0,   0,   0,   16,  0,   0,   165,
    0,   129, 2,   49,  48,  64,  64,  12,  64,  176, 64,  84,  8,   128, 20,  64,  213, 136, 104, 1,   41,  15,  83,  170,
    0,   0,   41,  1,   64,  64,  0,   193, 64,  64,  8,   0,   128, 0,   0,   64,  8,   64,  8,   1,   16,  0,   8,   0,
    0,   2,   1,   128, 28,  84,  141, 97,  0,   0,   68,  0,   0,   129, 8,   0,   16,  8,   32,  0,   64,  0,   0,   0,
    24,  0,   0,   0,   192, 0,   8,   128, 0,   0,   0,   0,   0,   64,  0,   1,   0,   0,   0,   0,   40,  1,   128, 64,
    0,   4,   2,   32,  0,   0,   0,   0,   0,   0,   0,   0,   0,   0,   0,   0,   128, 32,  8,   0,   32,  0,   0,   0,
    16,  17,  0,   2,   4,   0,   0,   33,  128, 2,   0,   0,   0,   0,   129, 0,   2,   0,   0,   0,   36,  0,   32,  2,
    0,   0,   0,   0,   0,   0,   32,  0,   0,   0,   0,   4,   0,   0,   0,   0,   0,   0,   0,   4,   32,  64,  0,   0,
    0,   0,   0,   0,   32,  0,   0,   32,  128, 0,   0,   0,   0,   0,   0,   0,   0,   0,   0,   128, 16,  0,   0,   0,
    0,   0,   0,   0,   1,   0,   136, 0,   0,   24,  192, 128, 3,   0,   17,  18,  2,   0,   66,  0,   4,   24,  0,   9,
    208, 167, 0,   144, 20,  64,  0,   130, 64,  0,   2,   16,  136, 8,   74,  32,  0,   168, 0,   65,  32,  8,   12,  1,
    3,   1,   64,  180, 3,   0,   64,  0,   8,   0,   0,   32,  65,  0,   4,   16,  4,   16,  68,  32,  64,  36,  32,  24,
    33,  1,   128, 0,   0,   8,   0,   32,  64,  81,  0,   1,   10,  19,  8,   0,   0,   4,   5,   144, 0,   0,   8,   128,
    0,   0,   4,   0,   0,   0,   0,   0,   0,   1,   0,   0,   0,   8,   0,   0,   0,   0,   0,   80,  1,   0,   0,   33,
    0,   32,  66,  4,   2,   0,   1,   43,  2,   0,   0,   4,   32,  16,  0,   64,  0,   3,   32,  0,   2,   64,  64,  116,
    0,   65,  52,  64,  0,   17,  64,  192, 96,  8,   10,  8,   2,   4,   0,   17,  64,  0,   4,   0,   0,   4,   128, 0,
    0,   9,   0,   0,   130, 2,   0,   192, 0,   48,  128, 64,  0,   96,  0,   64,  0,   1,   16,  32,  0,   1,   32,  6,
    128, 2,   32,  0,   12,  0,   0,   48,  32,  8,   0,   0,   128, 0,   18,  0,   0,   28,  24,  41,  16,  5,   32,  0,
    0,   0,   0,   0,   0,   0,   16,  0,   0,   0,   0,   0,   0,   0,   0,   0,   0,   0,   0,   0,   0,   1,   0,   0,
    0,   16,  0,   0,   0,   0,   64,  0,   0,   0,   0,   8,   0,   0,   0,   0,   16,  128, 0,   0,   0,   16,  0,   0,
    0,   0,   0,   0,   8,   0,   0,   0,   0,   0,   0,   0,   0,   0,   0,   0,   0,   0,   33,  0,   0,   0,   0,   0,
    0,   0,   0,   0,   0,   0,   0,   0,   0,   16,  0,   0,   0,   0,   0,   0,   0,   0,   0,   0,   0,   0,   0,   0,
    0,   0,   0,   0,   0,   0,   0,   0,   0,   0,   0,   0,   0,   0,   0,   0,   0,   0,   0,   0,   0,   0,   0,   0,
    0,   0,   0,   0,   0,   0,   0,   0,
};

test "dictionary hash: equals google/brotli's compiled-in table" {
    // SHA-256 of `kStaticDictionaryHashWords` (little-endian u16) followed
    // by `kStaticDictionaryHashLengths`, google/brotli 1.2.0
    // `c/enc/dictionary_hash_inc.h`.
    var h = std.crypto.hash.sha2.Sha256.init(.{});
    for (table.words) |w| h.update(&std.mem.toBytes(std.mem.nativeToLittle(u16, w)));
    h.update(&table.lengths);
    var got: [32]u8 = undefined;
    h.final(&got);
    var want: [32]u8 = undefined;
    _ = try std.fmt.hexToBytes(&want, "8dff92b020e954f9dc429c8b2aa011c221224fba6ac72de35693e00ebdb87417");
    try std.testing.expectEqualSlices(u8, &want, &got);
}

test "dictionary hash: every bucket names a word of its own bucket" {
    var used: usize = 0;
    for (table.lengths, table.words, 0..) |len, j, idx| {
        if (len == 0) continue;
        used += 1;
        const w = dictionary.data[dictionary.offsets_by_length[len] + @as(usize, len) * j ..][0..4];
        try std.testing.expectEqual(idx, (hash14(w) << 1) + @intFromBool(len < 8));
    }
    try std.testing.expectEqual(6031, used);
}
