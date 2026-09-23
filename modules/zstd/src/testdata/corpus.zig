// SPDX-License-Identifier: MIT
//! Deterministic inputs for the golden test.
//!
//! Each case is generated here rather than stored, so the repository carries
//! only the reference digests (`goldens.zig`). The generator uses its own
//! splitmix64 so the bytes cannot move with a std PRNG change; the recipe in
//! `../../tools/` writes the same inputs to disk for libzstd to compress.
//!
//! The cases are chosen for the code paths they reach, not for realism:
//! every size tier of the level table, the 7-byte "too small to compress"
//! edge, RLE blocks after the first block, literal and match lengths past
//! 0xFFFF (the seqStore "long length" slot), both pre-splitters (they need
//! two full blocks and prior savings), inputs larger than the level-1 window,
//! and data Huffman or the whole block cannot shrink.

const std = @import("std");

pub const Case = struct {
    name: []const u8,
    len: usize,
    kind: Kind,
    /// Extra generator seed; 0 for every hand-designed case.
    seed: u64 = 0,
    /// When set, the case is in the golden set at these levels only, without
    /// the checksum variant: a large input kept for one optimal-parser path.
    only_levels: []const i32 = &.{},
    /// Compressed with long-distance matching switched on by hand
    /// (`frame.Options.ldm`, libzstd's `ZSTD_c_enableLongDistanceMatching`),
    /// which reaches LDM far below the 64 MB where level 22 switches it on.
    /// Needs `only_levels` (btopt and up).
    ldm: bool = false,
    /// `ZSTD_c_windowLog` set by hand (`frame.Options.window_log`): a window
    /// far smaller than the input, so overflow correction (below) has room
    /// to run many times. Needs `only_levels`.
    window_log: ?u32 = null,
    /// Compressed with overflow correction as libzstd's fuzzing build does it
    /// (`ZSTD_WINDOW_OVERFLOW_CORRECT_FREQUENTLY`, `frame.Options.
    /// overflow_correct_frequently`): whenever it is safe rather than past
    /// 3500 MiB. The reference is a libzstd compiled with that switch.
    /// Needs `only_levels`.
    ocf: bool = false,
};

pub const Kind = enum {
    words, // text-like: words from a small vocabulary
    csv, // number-heavy lines
    random, // incompressible
    zeros,
    two_symbols,
    skewed, // geometric byte distribution: deep Huffman trees
    rle_text_rle, // runs around text: RLE blocks after the first block
    long_literals, // 100 KB of noise then repeats: litLength > 0xFFFF
    long_match, // text, 150 KB run, text: matchLength > 0xFFFF
    alternating, // 48 KB text / 48 KB noise: pre-splitter decisions
    far_repeat, // 700 KB text repeated: offsets beyond the level-1 window
    debruijn, // B(9,4): nine equally frequent literals, no 4-byte repeat
    sparse_matches, // ~300-byte noise runs between phrases: fast's step reaches 4
    drift, // word mix shifting with position: marginal pre-split decisions
    sparse_far, // ~1 KB noise runs between 48-byte phrases: dfast's step reaches 4
    split_margin, // a byChunks deviation between the penalty-2 and -3 thresholds
    mix, // random pieces (text, csv, noise, runs, small alphabets, copies): found by search
    rle_tail, // 128 KB of text, then a 6-byte run as the last block
    repeat_1024, // 128 KB of text, then a 1024-byte block of literals only
    far_mix, // 1.1 MB of `mix`, then a copy of it with sparse edits: offsets past 2^20
};

pub const cases = [_]Case{
    .{ .name = "empty", .len = 0, .kind = .words },
    .{ .name = "one", .len = 1, .kind = .words },
    .{ .name = "six", .len = 6, .kind = .words },
    .{ .name = "seven", .len = 7, .kind = .words },
    .{ .name = "words-100", .len = 100, .kind = .words },
    .{ .name = "words-1000", .len = 1000, .kind = .words },
    .{ .name = "words-16384", .len = 16384, .kind = .words },
    .{ .name = "words-16385", .len = 16385, .kind = .words },
    .{ .name = "csv-131072", .len = 131072, .kind = .csv },
    .{ .name = "csv-131073", .len = 131073, .kind = .csv },
    .{ .name = "words-262144", .len = 262144, .kind = .words },
    .{ .name = "words-262145", .len = 262145, .kind = .words },
    .{ .name = "csv-600000", .len = 600000, .kind = .csv },
    .{ .name = "random-5000", .len = 5000, .kind = .random },
    .{ .name = "random-300000", .len = 300000, .kind = .random },
    .{ .name = "zeros-300000", .len = 300000, .kind = .zeros },
    .{ .name = "two-symbols-200000", .len = 200000, .kind = .two_symbols },
    .{ .name = "skewed-300000", .len = 300000, .kind = .skewed },
    .{ .name = "rle-text-rle", .len = 550000, .kind = .rle_text_rle },
    .{ .name = "long-literals", .len = 140000, .kind = .long_literals },
    .{ .name = "long-match", .len = 152000, .kind = .long_match },
    .{ .name = "alternating", .len = 1_000_000, .kind = .alternating },
    .{ .name = "far-repeat", .len = 1_400_000, .kind = .far_repeat },
    .{ .name = "debruijn-9-4", .len = 6561, .kind = .debruijn },
    .{ .name = "sparse-matches", .len = 300000, .kind = .sparse_matches },
    .{ .name = "drift", .len = 1_000_000, .kind = .drift },
    .{ .name = "sparse-far", .len = 400000, .kind = .sparse_far },
    .{ .name = "split-margin", .len = 400000, .kind = .split_margin },
    .{ .name = "rle-tail-6", .len = 131072 + 6, .kind = .rle_tail },
    .{ .name = "repeat-1024", .len = 131072 + 1024, .kind = .repeat_1024 },
    // Found by searching generator seeds for an input on which one specific
    // boundary decision (a `>=` that could have been `>`, a threshold off by
    // one) changes the output; each kills the mutation noted beside it.
    .{ .name = "mix-772", .len = 300, .kind = .mix, .seed = 772 }, // block kept only if cSize < blockSize - minGain
    .{ .name = "mix-455", .len = 1500, .kind = .mix, .seed = 455 }, // normalizeM2: total / toDistribute > lowOne
    .{ .name = "mix-106", .len = 20000, .kind = .mix, .seed = 106 }, // normalizeCount: M2 fallback when -stillToDistribute >= largest/2
    .{ .name = "mix-1186", .len = 140000, .kind = .mix, .seed = 1186 }, // literals kept only if cLitSize < srcSize - minGain
    .{ .name = "mix-2031", .len = 20000, .kind = .mix, .seed = 2031 }, // useLowProbCount from nbSeq >= 2048
    .{ .name = "mix-43", .len = 300000, .kind = .mix, .seed = 43 }, // last code dropped from counts when its count > 1
    .{ .name = "mix-6643", .len = 300000, .kind = .mix, .seed = 6643 }, // suspectUncompressible at litSize / nbSeq >= 20
    .{ .name = "mix-39", .len = 9000, .kind = .mix, .seed = 39 }, // predefined table for nbSeq <= 2 of one code
    .{ .name = "mix-10086", .len = 300000, .kind = .mix, .seed = 10086 }, // old Huffman table kept when oldSize <= hSize + newSize
    .{ .name = "skewed-180", .len = 180, .kind = .skewed, .seed = 22903 }, // FSE-coded weights only when hSize < maxSymbol / 2
    // Found the same way for the lazy strategies (levels 4-8):
    .{ .name = "two-symbols-300000-1", .len = 300000, .kind = .two_symbols, .seed = 1 }, // immediate repcode check at ip == ilimit
    .{ .name = "mix-140000-2", .len = 140000, .kind = .mix, .seed = 2 }, // row update keeps 96 positions from a long match's start
    .{ .name = "mix-300000-9", .len = 300000, .kind = .mix, .seed = 9 }, // ... and 32 from its end
    .{ .name = "mix-140000-1148", .len = 140000, .kind = .mix, .seed = 1148 }, // ... and skips only past a 384-position gap
    .{ .name = "mix-140000-1", .len = 140000, .kind = .mix, .seed = 1 }, // lazy2's second lookahead only while ip < ilimit
    .{ .name = "mix-9000-5", .len = 9000, .kind = .mix, .seed = 5 }, // hash chain inserts one position while lazily skipping
    .{ .name = "mix-300000-28", .len = 300000, .kind = .mix, .seed = 28 }, // a block start resumes at most 192 positions back
    .{ .name = "mix-300000-2675", .len = 300000, .kind = .mix, .seed = 2675 }, // ... and only past a 384-position gap
    .{ .name = "mix-300000-34", .len = 300000, .kind = .mix, .seed = 34 }, // predefined table wins a tie with the repeated one
    .{ .name = "mix-16000-1", .len = 16000, .kind = .mix, .seed = 1 }, // predefined table wins a tie with a new one
    .{ .name = "drift-300000-8", .len = 300000, .kind = .drift, .seed = 8 }, // repeated table wins a tie with a new one
    .{ .name = "mix-300000-30", .len = 300000, .kind = .mix, .seed = 30 }, // cross-entropy prices a -1 probability as 1
    // ... and for btlazy2 (levels 9-10, inputs up to 16 KB):
    .{ .name = "two-symbols-16384-0", .len = 16384, .kind = .two_symbols, .seed = 0 }, // DUBT drops the last still-unsorted candidate; 1 << searchLog compares
    .{ .name = "two-symbols-16384-1", .len = 16384, .kind = .two_symbols, .seed = 1 }, // DUBT stacks unsorted candidates only while more than one is left
    .{ .name = "two-symbols-16000-1", .len = 16000, .kind = .two_symbols, .seed = 1 }, // DUBT skips a repetitive match to its end - 8; sorting stops at the input end
    .{ .name = "skewed-16384-2", .len = 16384, .kind = .skewed, .seed = 2 }, // DUBT prices an offset as highbit(distance + 1)
    // ... and for the optimal parsers (levels 11-21):
    .{ .name = "far-mix-5", .len = 1_400_000, .kind = .far_mix, .seed = 5, .only_levels = &.{16} }, // btopt's surcharge on offsets of 2^20 and up
    .{ .name = "csv-200000-18", .len = 200000, .kind = .csv, .seed = 18, .only_levels = &.{16} }, // two repcodes of one length: the later is listed too, and the longest entry's offset is what an immediate encoding takes
    .{ .name = "two-symbols-100000-0", .len = 100000, .kind = .two_symbols, .seed = 0, .only_levels = &.{13} }, // a repcode exactly `targetLength` long does not end the search
    .{ .name = "mix-200000-33", .len = 200000, .kind = .mix, .seed = 33, .only_levels = &.{19} }, // btultra's "match + 1 literal" wins only when strictly cheaper than more literals
    .{ .name = "csv-200000-0", .len = 200000, .kind = .csv, .seed = 0, .only_levels = &.{16} }, // ... and than what the next position already holds
    .{ .name = "mix-200000-2", .len = 200000, .kind = .mix, .seed = 2, .only_levels = &.{16} }, // split estimate: literals of 63 bytes or fewer are priced raw
    .{ .name = "mix-200000-0", .len = 200000, .kind = .mix, .seed = 0, .only_levels = &.{13} }, // a split part's repcode is rewritten only where the two offset histories disagree
    .{ .name = "mix-70000-0", .len = 70000, .kind = .mix, .seed = 0, .only_levels = &.{15} }, // the post-splitter starts at a 128 KB window (windowLog 17)
    .{ .name = "mix-200000-93", .len = 200000, .kind = .mix, .seed = 93, .only_levels = &.{16} }, // a split part stored raw leaves the decoder's offset history where it was
    .{ .name = "drift-200000-0", .len = 200000, .kind = .drift, .seed = 0, .only_levels = &.{19} }, // split estimate: four Huffman streams add a 6-byte jump table
    .{ .name = "drift-200000-20", .len = 200000, .kind = .drift, .seed = 20, .only_levels = &.{19} }, // split estimate: one stream below 256 literals
    .{ .name = "words-100000-6", .len = 100000, .kind = .words, .seed = 6, .only_levels = &.{16} }, // optimal Huffman depth stops once a size exceeds the best by more than one
    .{ .name = "skewed-262144-75", .len = 262144, .kind = .skewed, .seed = 75, .only_levels = &.{11} }, // DUBT search stops at the tree's low end (smaller side, `<=`)
    .{ .name = "skewed-200000-43", .len = 200000, .kind = .skewed, .seed = 43, .only_levels = &.{11} }, // ... and on the larger side
    // Long-distance matching by hand: inputs where its candidates change what
    // the optimal parser picks (found by comparing with and without).
    .{ .name = "ldm-mix-100000-3", .len = 100000, .kind = .mix, .seed = 3, .only_levels = &.{ 16, 19 }, .ldm = true }, // btultra, btultra2
    .{ .name = "ldm-mix-600000-0", .len = 600000, .kind = .mix, .seed = 0, .only_levels = &.{16}, .ldm = true }, // btopt: minMatch 64, bucket 2^7
    .{ .name = "ldm-far-mix-300000-3", .len = 300000, .kind = .far_mix, .seed = 3, .only_levels = &.{ 17, 19 }, .ldm = true },
    .{ .name = "ldm-far-mix-300000-2", .len = 300000, .kind = .far_mix, .seed = 2, .only_levels = &.{19}, .ldm = true },
    .{ .name = "ldm-drift-600000-0", .len = 600000, .kind = .drift, .seed = 0, .only_levels = &.{22}, .ldm = true },
    // ... and cases the mutation sweep's seed search found (SPEC.md, *Anchoring*)
    .{ .name = "ldm-words-40", .len = 40, .kind = .words, .only_levels = &.{16}, .ldm = true }, // a 1 KB window: hash log 6 bounds the bucket log
    .{ .name = "ldm-mix-140000-13", .len = 140000, .kind = .mix, .seed = 13, .only_levels = &.{17}, .ldm = true }, // btultra halves the minimum match
    .{ .name = "ldm-far-mix-200000-20", .len = 200000, .kind = .far_mix, .seed = 20, .only_levels = &.{17}, .ldm = true }, // gear reset leaves the hash as it was
    .{ .name = "ldm-far-mix-200000-23", .len = 200000, .kind = .far_mix, .seed = 23, .only_levels = &.{20}, .ldm = true }, // equal totals keep the earlier bucket entry
    .{ .name = "ldm-far-mix-200000-3", .len = 200000, .kind = .far_mix, .seed = 3, .only_levels = &.{21}, .ldm = true }, // a matched split is inserted too; the next candidate is fetched at its end
    .{ .name = "ldm-far-mix-600000-6", .len = 600000, .kind = .far_mix, .seed = 6, .only_levels = &.{19}, .ldm = true }, // a forward match of exactly minMatchLength counts
    .{ .name = "ldm-far-mix-600000-13", .len = 600000, .kind = .far_mix, .seed = 13, .only_levels = &.{19}, .ldm = true }, // a split sits just past the byte that triggered it
    .{ .name = "ldm-drift-300000-2", .len = 300000, .kind = .drift, .seed = 2, .only_levels = &.{20}, .ldm = true }, // the parser's overshoot past a candidate is skipped
    .{ .name = "ldm-mix-600000-7", .len = 600000, .kind = .mix, .seed = 7, .only_levels = &.{17}, .ldm = true }, // the first candidate is fetched before the first position
    .{ .name = "ldm-mix-600000-25", .len = 600000, .kind = .mix, .seed = 25, .only_levels = &.{21}, .ldm = true }, // a candidate resumed inside its match
    // Index overflow correction (Z3), run often: a window of 1..128 KB over
    // inputs of 200..600 KB, one case per match finder and its tables.
    .{ .name = "ocf-mix-200000-1-w10", .len = 200000, .kind = .mix, .seed = 1, .only_levels = &.{-5}, .window_log = 10, .ocf = true }, // fast, the smallest window
    .{ .name = "ocf-mix-200000-2-w12", .len = 200000, .kind = .mix, .seed = 2, .only_levels = &.{1}, .window_log = 12, .ocf = true }, // fast
    .{ .name = "ocf-mix-200000-3-w12", .len = 200000, .kind = .mix, .seed = 3, .only_levels = &.{3}, .window_log = 12, .ocf = true }, // dfast: both tables
    .{ .name = "ocf-mix-200000-4-w12", .len = 200000, .kind = .mix, .seed = 4, .only_levels = &.{ 5, 7 }, .window_log = 12, .ocf = true }, // greedy, lazy on hash chains
    .{ .name = "ocf-mix-600000-5-w15", .len = 600000, .kind = .mix, .seed = 5, .only_levels = &.{ 5, 8 }, .window_log = 15, .ocf = true }, // greedy, lazy2 on the row match finder (window > 16 KB)
    .{ .name = "ocf-mix-200000-6-w12", .len = 200000, .kind = .mix, .seed = 6, .only_levels = &.{ 11, 12 }, .window_log = 12, .ocf = true }, // btlazy2: the unsorted mark survives the reduction
    .{ .name = "ocf-mix-200000-7-w12", .len = 200000, .kind = .mix, .seed = 7, .only_levels = &.{ 13, 16, 19 }, .window_log = 12, .ocf = true }, // btopt, btultra and btultra2 with the 3-byte hash
    .{ .name = "ocf-mix-600000-8-w17", .len = 600000, .kind = .mix, .seed = 8, .only_levels = &.{19}, .window_log = 17, .ocf = true }, // btultra2 with the post-splitter (window >= 128 KB)
    .{ .name = "ocf-ldm-mix-600000-9-w15", .len = 600000, .kind = .mix, .seed = 9, .only_levels = &.{16}, .ldm = true, .window_log = 15, .ocf = true }, // the LDM window corrects on its own (cycle log 0)
    .{ .name = "ocf-far-repeat-1400000", .len = 1_400_000, .kind = .far_repeat, .only_levels = &.{1}, .ocf = true }, // the level's own window, no override
    // found by seed search against surviving mutations
    .{ .name = "ocf-mix-20000-128-w12", .len = 20000, .kind = .mix, .seed = 128, .only_levels = &.{11}, .window_log = 12, .ocf = true }, // btlazy2's unsorted mark must survive the reduction
    .{ .name = "ocf-ldm-mix-600000-244-w13", .len = 600000, .kind = .mix, .seed = 244, .only_levels = &.{18}, .ldm = true, .window_log = 13, .ocf = true }, // the LDM table is reduced with the window
    .{ .name = "ocf-ldm-mix-600000-67-w11", .len = 600000, .kind = .mix, .seed = 67, .only_levels = &.{19}, .ldm = true, .window_log = 11, .ocf = true }, // ... and its offsets below the correction become 0
};

pub const levels = [_]i32{ -5, -1, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22 };

/// First level of the optimal parsers (btopt in the 16 KB tier).
pub const opt_level_min = 11;
/// Largest input the golden set compresses at the optimal-parser levels.
pub const opt_len_max = 600_000;

/// Whether the golden set holds `(case, level, checksum)`. The optimal
/// parsers cost 10-40x a lazy level, so from `opt_level_min` up the set
/// leaves out the checksum variant (the trailer does not depend on the level)
/// and inputs above `opt_len_max` (their long-window paths are the earlier
/// levels' concern). A case with `only_levels` is covered there alone.
/// `tools/dump_corpus.zig` writes the covered set for the recipe.
pub fn covered(case: Case, level: i32, checksum: bool) bool {
    if (case.only_levels.len != 0) return !checksum and std.mem.indexOfScalar(i32, case.only_levels, level) != null;
    if (level < opt_level_min) return true;
    return !checksum and case.len <= opt_len_max;
}

/// The dfast pre-splitter's chunk size (`CHUNKSIZE` in zstd_preSplit.c).
const chunk_len = 8 << 10;

const Rng = struct {
    s: u64,
    fn next(r: *Rng) u64 {
        r.s +%= 0x9E3779B97F4A7C15;
        var z = r.s;
        z = (z ^ (z >> 30)) *% 0xBF58476D1CE4E5B9;
        z = (z ^ (z >> 27)) *% 0x94D049BB133111EB;
        return z ^ (z >> 31);
    }
    fn below(r: *Rng, n: u64) u64 {
        return r.next() % n;
    }
};

const vocabulary = [_][]const u8{
    "the ",     "of ",    "and ",  "compress ", "block ",   "frame ", "window ",
    "offset ",  "match ", "zstd ", "literal ",  "table ",   "state ", "huffman ",
    "sequence", ", ",     ". ",    "\n",        "entropy ", "rle ",   "level ",
};

fn words(r: *Rng, out: []u8) void {
    var i: usize = 0;
    while (i < out.len) {
        const w = vocabulary[r.below(vocabulary.len)];
        const n = @min(w.len, out.len - i);
        @memcpy(out[i..][0..n], w[0..n]);
        i += n;
    }
}

fn csv(r: *Rng, out: []u8) void {
    var i: usize = 0;
    var t: u64 = 1_700_000_000;
    var line: [64]u8 = undefined;
    while (i < out.len) {
        t += 1 + r.below(10);
        const s = std.fmt.bufPrint(&line, "{d},{d},{d}.{d}\n", .{ r.below(28), t, r.below(5000), r.below(1000) }) catch unreachable;
        const n = @min(s.len, out.len - i);
        @memcpy(out[i..][0..n], s[0..n]);
        i += n;
    }
}

fn random(r: *Rng, out: []u8) void {
    for (out) |*b| b.* = @truncate(r.next());
}

/// De Bruijn sequence B(k, n) over the bytes 'a'.., linearised (length k^n):
/// every n-byte window of the cyclic sequence occurs once.
fn deBruijn(k: u8, comptime n: usize, out: []u8) void {
    var a = [_]u8{0} ** (n + 1);
    var len: usize = 0;
    // Recursive "db(t, p)" of Ruskey/Savage/Wang, unrolled with an explicit stack.
    const Frame = struct { t: usize, p: usize, j: u8 };
    var stack: [n + 2]Frame = undefined;
    var sp: usize = 0;
    stack[0] = .{ .t = 1, .p = 1, .j = 0 };
    sp = 1;
    while (sp > 0) {
        const f = &stack[sp - 1];
        if (f.t > n) {
            if (n % f.p == 0) {
                for (a[1 .. f.p + 1]) |v| {
                    out[len] = 'a' + v;
                    len += 1;
                }
            }
            sp -= 1;
            continue;
        }
        if (f.j == 0) {
            f.j = 1;
            a[f.t] = a[f.t - f.p];
            stack[sp] = .{ .t = f.t + 1, .p = f.p, .j = 0 };
            sp += 1;
            continue;
        }
        const next = a[f.t - f.p] + f.j;
        if (next >= k) {
            sp -= 1;
            continue;
        }
        f.j += 1;
        a[f.t] = next;
        stack[sp] = .{ .t = f.t + 1, .p = f.t, .j = 0 };
        sp += 1;
    }
    std.debug.assert(len == out.len);
}

/// Concatenated random pieces. Used for cases found by searching seeds for an
/// input that reaches one specific boundary (see SPEC.md, *Anchoring*).
fn mix(r: *Rng, out: []u8) void {
    var i: usize = 0;
    while (i < out.len) {
        const want: usize = @intCast(@as(u64, 1) << @intCast(r.below(17)));
        const n = @min(want + r.below(want), out.len - i);
        const piece = out[i..][0..n];
        switch (r.below(7)) {
            0 => words(r, piece),
            1 => csv(r, piece),
            2 => random(r, piece),
            3 => @memset(piece, @truncate(r.next())),
            4 => {
                const k = 2 + r.below(7);
                var alphabet: [8]u8 = undefined;
                random(r, &alphabet);
                for (piece) |*b| b.* = alphabet[r.below(k)];
            },
            5 => if (i > 0) {
                // copy from earlier output: a match at some offset
                const dist = 1 + r.below(i);
                for (piece, 0..) |*b, j| b.* = out[i + j - dist];
            } else @memset(piece, 0),
            else => @memset(piece, 0),
        }
        i += n;
    }
}

/// Fill `out` with the input of `case`.
pub fn generate(case: Case, out: []u8) void {
    std.debug.assert(out.len == case.len);
    var r: Rng = .{ .s = case.len *% 31 +% @intFromEnum(case.kind) +% case.seed *% 0xD1B54A32D192ED03 };
    switch (case.kind) {
        .words => words(&r, out),
        .csv => csv(&r, out),
        .random => random(&r, out),
        .zeros => @memset(out, 0),
        .two_symbols => for (out) |*b| {
            b.* = if (r.next() & 1 == 0) 'a' else 'b';
        },
        .skewed => for (out) |*b| {
            // geometric: each step halves the probability
            var v: u8 = 0;
            while (v < 40 and r.next() & 1 == 0) v += 1;
            b.* = v;
        },
        .rle_text_rle => {
            @memset(out[0..200000], 'x');
            words(&r, out[200000..400000]);
            @memset(out[400000..], 'y');
        },
        .long_literals => {
            random(&r, out[0..100000]);
            var i: usize = 100000;
            while (i < out.len) : (i += 1) out[i] = "abcd"[i % 4];
        },
        .long_match => {
            words(&r, out[0..1000]);
            @memset(out[1000..151000], 'Q');
            @memcpy(out[151000..], out[0..1000]);
        },
        .alternating => {
            var i: usize = 0;
            var k: usize = 0;
            while (i < out.len) : (k += 1) {
                const n = @min(48 * 1024, out.len - i);
                if (k % 2 == 0) words(&r, out[i..][0..n]) else random(&r, out[i..][0..n]);
                i += n;
            }
        },
        .far_repeat => {
            words(&r, out[0..700000]);
            @memcpy(out[700000..], out[0..700000]);
        },
        .debruijn => deBruijn(9, 4, out),
        .far_mix => {
            const p = @min(out.len, 1_100_000);
            mix(&r, out[0..p]);
            for (out[p..], p..) |*b, i| b.* = if (r.below(1500) == 0) @truncate(r.next()) else out[i - p];
        },
        .sparse_matches => {
            const phrases = [_][]const u8{ "<record id=\"", "\" type=\"sample\">", "</record>\n", "timestamp=" };
            var i: usize = 0;
            while (i < out.len) {
                const noise = @min(250 + r.below(200), out.len - i);
                random(&r, out[i..][0..noise]);
                i += noise;
                const p = phrases[r.below(phrases.len)];
                const n = @min(p.len, out.len - i);
                @memcpy(out[i..][0..n], p[0..n]);
                i += n;
            }
        },
        .sparse_far => {
            // Phrases long enough that the 8-byte hash at "match + 4" stays
            // inside the phrase, so dfast's step==4 table write is observable.
            var phrases: [4][48]u8 = undefined;
            for (&phrases) |*p| for (p) |*b| {
                b.* = @intCast(33 + r.below(94));
            };
            var i: usize = 0;
            while (i < out.len) {
                const noise = @min(800 + r.below(300), out.len - i);
                random(&r, out[i..][0..noise]);
                i += noise;
                const p = &phrases[r.below(phrases.len)];
                const n = @min(p.len, out.len - i);
                @memcpy(out[i..][0..n], p[0..n]);
                i += n;
            }
        },
        .mix => mix(&r, out),
        .rle_tail => {
            // The 6-byte last block is below libzstd's "attempt compression"
            // size (7), so it is stored raw although it is a run.
            words(&r, out[0..131072]);
            @memset(out[131072..], 'z');
        },
        .repeat_1024 => {
            // Block 2 is exactly 1024 literals (no 4-byte string in it occurs
            // in the text or twice in itself), over letters block 1's Huffman
            // table covers. At <= 1024 bytes libzstd reuses that table without
            // pricing a new one; one byte more and it would build its own.
            words(&r, out[0..131072]);
            var db: [4096]u8 = undefined;
            deBruijn(8, 4, &db);
            const letters = "abcdefhi";
            for (out[131072..], db[0..1024]) |*o, d| o.* = letters[d - 'a'];
        },
        .split_margin => {
            // Block 1 (never split) is text. Block 2 starts at 128 KB: its first
            // 8 KB chunk is all 'A'; every later chunk has 'B' on 97 of the 191
            // positions the dfast splitter samples (every 43rd byte). Deviation
            // 380 * 97 = 36860 against thresholds 38356 (penalty 3, libzstd)
            // and 36100 (penalty 2): libzstd keeps chunk 1, a penalty of 2
            // would split there.
            const b2 = 128 * 1024;
            words(&r, out[0..b2]);
            @memset(out[b2 .. 2 * b2], 'A');
            var chunk: usize = 1;
            while (chunk < 16) : (chunk += 1) {
                const start = b2 + chunk * chunk_len;
                var m: usize = 0;
                while (m < 97) : (m += 1) out[start + m * 43] = 'B';
            }
            words(&r, out[2 * b2 ..]);
        },
        .drift => {
            var i: usize = 0;
            while (i < out.len) {
                // the favoured half of the vocabulary slides with position
                const shift = (i * vocabulary.len) / out.len;
                const pick = if (r.below(4) != 0) (shift + r.below(vocabulary.len / 2)) % vocabulary.len else r.below(vocabulary.len);
                const w = vocabulary[pick];
                const n = @min(w.len, out.len - i);
                @memcpy(out[i..][0..n], w[0..n]);
                i += n;
            }
        },
    }
}
