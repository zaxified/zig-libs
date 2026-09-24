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
    /// (`Advanced.long_distance_matching`, libzstd's `ZSTD_c_enableLongDistanceMatching`),
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

/// Goldens with libzstd's advanced parameters (`zstd.Advanced`): corpus case
/// `case` compressed one-shot at each of `levels` with `params` set --
/// libzstd's parameter names, `name=value`, comma-separated (the grammar of
/// `tools/zref.c`'s last argument; switches are 0 auto, 1 enable, 2
/// disable) -- once per entry of `checksums`.
pub const ParamCase = struct {
    case: []const u8,
    params: []const u8,
    levels: []const i32,
    checksums: []const bool = &.{false},
};

pub const param_cases = [_]ParamCase{
    // explicit compression parameters, over and against the level's own
    .{ .case = "words-262145", .params = "minMatch=3", .levels = &.{ 1, 3 } }, // fast and dfast search 3 as 4
    .{ .case = "words-262145", .params = "minMatch=4", .levels = &.{ 1, 3 } },
    .{ .case = "csv-600000", .params = "minMatch=7", .levels = &.{ 1, 3, 5 } }, // greedy clamps it to 6
    .{ .case = "mix-300000-9", .params = "minMatch=3", .levels = &.{ 5, 7 } }, // ... and 3 to 4
    .{ .case = "csv-600000", .params = "hashLog=12,chainLog=10,searchLog=6", .levels = &.{ 5, 8, 13 } }, // small tables: rows, chain, tree
    .{ .case = "sparse-matches", .params = "targetLength=4", .levels = &.{1} }, // fast's step
    .{ .case = "csv-131073", .params = "targetLength=0", .levels = &.{-5} }, // 0 does not override the acceleration
    .{ .case = "mix-200000-2", .params = "targetLength=8", .levels = &.{ 16, 19 } }, // the optimal parsers' "long enough"
    .{ .case = "csv-600000", .params = "strategy=9", .levels = &.{1} }, // btultra2 on level 1's tables
    .{ .case = "words-262145", .params = "strategy=1", .levels = &.{19} }, // fast on level 19's: minMatch 3, a 256 step
    .{ .case = "far-repeat", .params = "windowLog=21", .levels = &.{1} }, // a wider window than the level's
    .{ .case = "csv-600000", .params = "strategy=6,windowLog=20", .levels = &.{3} }, // btlazy2 over a 1 MB window
    // the row match finder
    .{ .case = "words-16384", .params = "useRowMatchFinder=1", .levels = &.{ 4, 5, 6, 7, 8 } }, // rows in a 16 KB window
    .{ .case = "csv-600000", .params = "useRowMatchFinder=2", .levels = &.{ 5, 7, 8 } }, // the hash chain in a 2 MB one
    .{ .case = "mix-140000-2", .params = "useRowMatchFinder=1,searchLog=7", .levels = &.{6} }, // 64-entry rows
    .{ .case = "words-262145", .params = "useRowMatchFinder=1", .levels = &.{13} }, // btlazy2 has no rows
    // literal compression
    .{ .case = "csv-131073", .params = "literalCompressionMode=1", .levels = &.{ -5, -1 } }, // Huffman at the negative levels
    .{ .case = "csv-131073", .params = "literalCompressionMode=2", .levels = &.{ 1, 3, 5, 9 } }, // raw literals
    .{ .case = "mix-200000-33", .params = "literalCompressionMode=2", .levels = &.{ 16, 18, 19 } }, // priced at 8 bits, and in the split estimate
    // the post-splitter
    .{ .case = "mix-200000-2", .params = "splitAfterSequences=1", .levels = &.{ -10, 1, 3, 5 } }, // below btopt; at -10 over raw literals
    .{ .case = "mix-200000-0", .params = "splitAfterSequences=2", .levels = &.{ 13, 19 } },
    // the pre-splitter
    .{ .case = "alternating", .params = "blockSplitterLevel=1", .levels = &.{ 1, 3 } }, // never splits
    .{ .case = "alternating", .params = "blockSplitterLevel=2", .levels = &.{5} }, // from the borders
    .{ .case = "alternating", .params = "blockSplitterLevel=3", .levels = &.{1} }, // by chunks, levels 0..3
    .{ .case = "drift", .params = "blockSplitterLevel=4", .levels = &.{1} },
    .{ .case = "drift", .params = "blockSplitterLevel=5", .levels = &.{3} },
    .{ .case = "split-margin", .params = "blockSplitterLevel=6", .levels = &.{1} },
    // block size
    .{ .case = "words-262145", .params = "maxBlockSize=1024", .levels = &.{ 1, 5, 19 } },
    .{ .case = "csv-600000", .params = "maxBlockSize=65536", .levels = &.{3} }, // no pre-split below 128 KB blocks
    .{ .case = "mix-300000-9", .params = "maxBlockSize=100000", .levels = &.{13} },
    .{ .case = "random-5000", .params = "maxBlockSize=1024", .levels = &.{3} }, // raw blocks
    // frame header
    .{ .case = "empty", .params = "contentSizeFlag=0", .levels = &.{3}, .checksums = &.{ false, true } }, // the empty frame
    .{ .case = "words-1000", .params = "contentSizeFlag=0", .levels = &.{3} }, // a window byte instead of the size
    .{ .case = "csv-600000", .params = "contentSizeFlag=0", .levels = &.{1} },
    .{ .case = "empty", .params = "format=1", .levels = &.{3}, .checksums = &.{ false, true } },
    .{ .case = "words-1000", .params = "format=1", .levels = &.{3}, .checksums = &.{ false, true } },
    .{ .case = "csv-131073", .params = "format=1,contentSizeFlag=0", .levels = &.{1} },
    // long-distance matching below the optimal parsers: its matches taken
    // as they come, the level's match finder over the literals between
    .{ .case = "ldm-mix-600000-0", .params = "enableLongDistanceMatching=1", .levels = &.{ -5, 1, 3, 5, 7, 9, 12 } },
    .{ .case = "far-repeat", .params = "enableLongDistanceMatching=1", .levels = &.{ 1, 4 } }, // repeats 700 KB back, past level 1's window
    .{ .case = "zeros-300000", .params = "enableLongDistanceMatching=1", .levels = &.{ 1, 3 } }, // one overlapping match: the hash skips over it
    .{ .case = "mix-300000-9", .params = "enableLongDistanceMatching=1,ldmMinMatch=4,ldmHashRateLog=1", .levels = &.{ 1, 3, 5, 8 } }, // many short matches, cut at block ends
    .{ .case = "csv-600000", .params = "enableLongDistanceMatching=1,ldmHashLog=10,ldmBucketSizeLog=1", .levels = &.{ 3, 6 } }, // a tiny table
    .{ .case = "words-262145", .params = "enableLongDistanceMatching=1,ldmHashLog=12", .levels = &.{2} }, // the hash rate from the hash log
    .{ .case = "ldm-far-mix-300000-3", .params = "enableLongDistanceMatching=1,useRowMatchFinder=2", .levels = &.{ 5, 7 } }, // hash chains
    .{ .case = "far-repeat", .params = "enableLongDistanceMatching=1,ldmMinMatch=4096", .levels = &.{3} }, // the longest minimum
    .{ .case = "words-100", .params = "enableLongDistanceMatching=1,ldmHashLog=12,ldmMinMatch=4", .levels = &.{ 1, 3, 5 } }, // a split at every byte: a few literals at the window's first indices
    // ... found by a seed search over corpus inputs and parameters (original against mutant):
    .{ .case = "mix-10086", .params = "enableLongDistanceMatching=1,ldmHashLog=15,ldmMinMatch=6,ldmBucketSizeLog=4", .levels = &.{3} }, // the LDM offset pushes the repcodes down; dfast's table fill ends exactly 10 bytes before the stretch; the table update is limited from exactly 1024 positions on
    .{ .case = "ldm-far-mix-600000-6", .params = "enableLongDistanceMatching=1,ldmHashLog=21,ldmMinMatch=16", .levels = &.{1} }, // fast's table fill ends exactly 9 bytes before the stretch
    .{ .case = "zeros-300000", .params = "enableLongDistanceMatching=1,ldmHashLog=19", .levels = &.{2} }, // fast on the first 1 byte of the window (iend - 8 below index 0)
    .{ .case = "mix-70000-0", .params = "enableLongDistanceMatching=1,ldmHashLog=15,windowLog=12", .levels = &.{3} }, // ... and dfast
    // targetCBlockSize: each block cut into compressed blocks of about that size
    .{ .case = "csv-600000", .params = "targetCBlockSize=1340", .levels = &.{ -5, 1, 3, 7, 16 }, .checksums = &.{ false, true } }, // the smallest target: the entropy tables go with the first sub-block
    .{ .case = "words-262145", .params = "targetCBlockSize=1", .levels = &.{ 3, 19 } }, // below the minimum counts as it
    .{ .case = "mix-300000-9", .params = "targetCBlockSize=16384", .levels = &.{ 1, 5, 12 } },
    .{ .case = "random-300000", .params = "targetCBlockSize=5000", .levels = &.{3} }, // no gain: raw blocks
    .{ .case = "zeros-300000", .params = "targetCBlockSize=2000", .levels = &.{ 1, 3 } }, // RLE blocks after the first
    .{ .case = "long-literals", .params = "targetCBlockSize=4096", .levels = &.{ 1, 7 } }, // literal runs past a sub-block's budget
    .{ .case = "csv-131073", .params = "targetCBlockSize=131072", .levels = &.{3} }, // the largest target: one sub-block
    .{ .case = "mix-200000-2", .params = "targetCBlockSize=3000,literalCompressionMode=2", .levels = &.{ 3, 16 } }, // raw literals
    .{ .case = "two-symbols-200000", .params = "targetCBlockSize=1500", .levels = &.{ 1, 9 } },
    // ... found by a seed search over corpus inputs and parameters (original against mutant):
    .{ .case = "ldm-drift-300000-2", .params = "targetCBlockSize=2000,strategy=8,minMatch=5,literalCompressionMode=1", .levels = &.{3} }, // a later sub-block's literals that do not shrink are stored raw
    .{ .case = "mix-6643", .params = "targetCBlockSize=1400,minMatch=4", .levels = &.{5} }, // ... but the first one's may grow within their header size
    .{ .case = "mix-300000-28", .params = "targetCBlockSize=1400", .levels = &.{8} }, // a sub-block exactly as long as it decodes to is folded into the next
    .{ .case = "mix-772", .params = "targetCBlockSize=5000,windowLog=18,maxBlockSize=2000", .levels = &.{-5} }, // a superblock exactly a raw block's size minus minGain is stored raw
    .{ .case = "ocf-mix-600000-5-w15", .params = "targetCBlockSize=7634", .levels = &.{12} }, // ... the bound counts minGain
};

/// Streaming goldens: corpus case `case` compressed through `zstd.Stream`
/// following `schedule` (the grammar of `tools/zstream.c`: `pN` pledge,
/// `wN` window log, `oN` output buffer size, `cN`/`fN`/`eN` continue /
/// flush / end with the next N input bytes, `*` for the rest; a leading
/// `x` for libzstd's frequent index-overflow correction) at every
/// level of `stream_levels`, with and without the checksum.
pub const StreamCase = struct {
    case: []const u8,
    schedule: []const u8,
    /// Levels at which the input buffer wraps, so blocks are compressed
    /// with the window in two segments (the extDict match finders); the
    /// test checks that some were.
    ext_dict: []const i32 = &.{},
    /// With `x`: whether a correction must have run (a case found by
    /// search may carry an `x` that corrects nothing).
    corrects: bool = true,
    /// The levels it is golden at.
    levels: []const i32 = &stream_levels,
};

const all_stream_levels: []const i32 = &stream_levels;

pub const stream_levels = [_]i32{ -5, -1, 1, 2, 3 };
/// greedy, lazy, lazy2 (hash chain up to a 16 KB window, rows above) and,
/// for inputs of 16 KB or less, btlazy2.
pub const lazy_stream_levels = [_]i32{ 4, 5, 6, 7, 8, 9, 10 };
const lazy_levels: []const i32 = &lazy_stream_levels;
/// Without a pledged size level 4 is dfast (the table for inputs over 256 KB).
const lazy_only_levels: []const i32 = lazy_stream_levels[1..];
/// btopt, btultra, btultra2 without a pledged size, 22 with LDM.
const opt_levels: []const i32 = &.{ 16, 18, 19, 22 };

pub const stream_cases = [_]StreamCase{
    .{ .case = "empty", .schedule = "e*" }, // pledged 0: the one-shot shortcut
    .{ .case = "empty", .schedule = "c*,e0" }, // unknown size: no size in the header
    .{ .case = "seven", .schedule = "p7,c*,f0,e0" }, // pledged, a flush of a block too small to compress
    .{ .case = "words-262145", .schedule = "e*" }, // the shortcut: the one-shot frame
    .{ .case = "words-262145", .schedule = "o100,e*" }, // output too small for the shortcut: buffered, size from the first call
    .{ .case = "csv-600000", .schedule = "c*,e0" }, // unknown size: the >256 KB parameters, a chunk per block
    .{ .case = "csv-600000", .schedule = "p600000,c*,e0" }, // pledged
    .{ .case = "alternating", .schedule = "c100000,f0,c*,e0" }, // a flush mid-block; the pre-splitter per chunk
    .{ .case = "far-repeat", .schedule = "c*,e0", .ext_dict = &.{ -5, -1, 1, 2 } }, // a 512 KB or 1 MB window wraps its buffer; level 3's 2 MB does not
    .{ .case = "mix-300000-9", .schedule = "w10,c*,e0", .ext_dict = all_stream_levels }, // the smallest window: a wrap every 2 KB
    .{ .case = "mix-300000-9", .schedule = "w12,o50,c3000,f0,c*,e0" }, // flushes through a 50-byte output
    .{ .case = "rle-text-rle", .schedule = "w14,c65536,c65536,f0,c*,e0" },
    .{ .case = "sparse-far", .schedule = "w11,c100000,f0,c50000,e*", .ext_dict = all_stream_levels }, // the end straight from the caller's buffer
    .{ .case = "random-300000", .schedule = "w17,c*,e0", .ext_dict = all_stream_levels }, // raw blocks
    .{ .case = "mix-9000-5", .schedule = "w10,c1,c1,c1,f0,c10,f0,c*,e0" }, // flushes of 1 and 10 bytes
    .{ .case = "csv-131072", .schedule = "p131072,c*,e0" }, // pledged exactly one block: buffered one byte past it, no empty last block
    .{ .case = "mix-300000-9", .schedule = "o301171,e*" }, // output of exactly compressBound(input): still the shortcut (buffered, this input's pre-split differs)
    // Found by a seed search over schedules (original against mutant):
    .{ .case = "mix-140000-1148", .schedule = "w14,c526,c4191,c278,c130005,c1,c1,f3,c3518,c500,c5,c64,c1,c204,c230,c366,c87,e20", .ext_dict = &.{1} }, // a match from the extDict's end goes on at the prefix's first byte
    .{ .case = "csv-600000", .schedule = "x,w12,c10,c3971,f458744,c128202,e9073", .ext_dict = &.{-1} }, // ... at all
    .{ .case = "two-symbols-200000", .schedule = "w13,o1048576,c15239,c152195,f2318,c4470,f2,f3389,f8,c3206,c4524,c209,f10,c12302,c167,f5,f599,c132,c205,c228,f245,c356,c106,c45,f1,c0,c35,c4,e0", .ext_dict = &.{3} }, // dfast: a long candidate exactly at the extDict's low end is refused
    .{ .case = "csv-200000-0", .schedule = "w10,c24539,c4450,c144065,f23131,c1891,c8,c352,c246,c776,c3,f243,c90,f132,f26,c41,c6,c1,e0", .ext_dict = &.{3} }, // dfast: the search stops 9 bytes before the end (ip < ilimit)
    .{ .case = "mix-300000-28", .schedule = "x,w13,c84908,c24801,c3798,f1829,c5,c46473,c243,c6,c8448,f0,c7,f9,f43303,f39361,f9,c300,f0,f28049,c3725,c6,c5,c4308,c8,c8,f8034,c1962,f261,c83,c35,e16", .ext_dict = &.{3} }, // dfast: a long match in the extDict extends backwards only to the extDict's low end
    .{ .case = "words-100000-6", .schedule = "w10,c2,c29324,c9,f37,f1387,c20400,e48841", .ext_dict = &.{3} }, // ... a short one likewise
    .{ .case = "mix-300000-34", .schedule = "w16,o1,c2,c1658,e298340", .ext_dict = &.{3} }, // dfast: the step after a miss grows with the distance from the anchor
    .{ .case = "csv-200000-0", .schedule = "x,w11,c3,c169,c4,c156974,c108,f53,c35795,c3692,c430,c58,c7,f10,c337,c18,c501,c696,c13,c253,c653,c206,c4,c13,f2,f0,c1,e0", .ext_dict = &.{-5} }, // fast: a candidate exactly at the extDict's low end is taken (first lookup)
    .{ .case = "skewed-200000-43", .schedule = "x,w12,o1048576,c36590,c78,c6365,f86076,f4685,c0,c3,c75,c1497,c5,f18190,c38785,f5,c2237,c3881,c1177,f4,c243,f48,c53,c2,c0,c1,e0", .ext_dict = &.{2} }, // ... (second lookup)
    .{ .case = "far-mix-5", .schedule = "x,w10,o64,c1167020,c3409,c68773,c7,c2226,c28665,c4874,c12263,f128,c12858,f2327,c20695,c9,f3,c49880,f62,c2372,c5505,c9407,c6,c8754,f60,c144,f540,c5,f6,c2,e0", .ext_dict = &.{-5} }, // fast: a match extends backwards down to just above its segment's low end
    .{ .case = "two-symbols-200000", .schedule = "w10,c7,c4,c2865,f107,c7,c5,c70919,f1678,f70857,f33002,c9655,f2078,c2213,c449,c5556,f481,c15,c95,c7,e0", .ext_dict = &.{1} }, // a repcode 4 bytes before the extDict's end does not straddle it
    .{ .case = "mix-140000-1148", .schedule = "w17,f1,f71,c2,c93058,c10526,c227,c31763,f1296,c286,f5,f1715,c0,c594,c5,c370,f16,e65" }, // the pre-splitter's savings count the frame header
    // The lazy levels over a two-segment window:
    .{ .case = "csv-600000", .schedule = "w18,c*,e0", .levels = lazy_levels, .ext_dict = lazy_levels }, // rows; a 256 KB window wraps a 384 KB buffer
    .{ .case = "far-repeat", .schedule = "w19,c300000,f0,c*,e0", .levels = lazy_levels, .ext_dict = lazy_levels }, // repeats 700 KB back reach into the extDict
    .{ .case = "mix-300000-9", .schedule = "w12,o50,c3000,f0,c*,e0", .levels = lazy_levels, .ext_dict = lazy_only_levels }, // hash chain (window 4 KB), flushes
    .{ .case = "two-symbols-200000", .schedule = "w13,c1000,f0,c7777,f0,c*,e0", .levels = lazy_levels, .ext_dict = lazy_only_levels },
    .{ .case = "two-symbols-16384-0", .schedule = "p16384,w10,c*,e0", .levels = lazy_levels, .ext_dict = lazy_levels }, // pledged <= 16 KB: btlazy2 at 9-10, the tree across both segments
    .{ .case = "skewed-16384-2", .schedule = "p16384,w11,c3000,f0,c*,e0", .levels = lazy_levels, .ext_dict = lazy_levels },
    .{ .case = "mix-300000-9", .schedule = "x,p300000,w12,c*,e0", .levels = lazy_levels, .ext_dict = lazy_only_levels }, // overflow correction, both segments (pledged: the chain log shrinks to the window, so corrections come early)
    // ... found by a seed search over schedules (original against mutant):
    .{ .case = "drift-200000-0", .schedule = "w10,o1,e200000", .levels = &.{5}, .ext_dict = &.{5} }, // the immediate repcode is tried at ip == ilimit too
    .{ .case = "far-repeat", .schedule = "p1400000,w10,o1000,c1055633,f196936,c252,f116014,c74,c7,c13336,f8367,c2,c4688,c3,c3619,c948,c64,c2,c50,c1,c2,c1,c1,e0", .levels = &.{10}, .ext_dict = &.{10} }, // a repcode exactly a window back is taken
    .{ .case = "long-literals", .schedule = "w13,o1000,c158,f70733,f26279,e42830", .levels = &.{8}, .ext_dict = &.{8} }, // catching up stops at the extDict's low limit (not the window's)
    .{ .case = "split-margin", .schedule = "x,p400000,w14,c2230,c7,c4,c44823,c1546,f43664,c115585,f1125,c31499,c6933,c65582,c3986,c9187,c475,c23209,c7,c3,c14831,c10841,c12647,f3477,c6978,c575,c326,f159,c171,c102,c14,f2,c5,c0,c6,c0,c0,f1,e0", .levels = &.{8}, .ext_dict = &.{8} }, // ... down to just above it
    .{ .case = "mix-140000-1", .schedule = "x,w13,c3797,c36559,f33578,c5,f24157,c19101,e22803", .levels = &.{6}, .ext_dict = &.{6}, .corrects = false }, // lazy skipping from a step of 9, not 8
    .{ .case = "mix-43", .schedule = "x,w17,c123076,f4272,c48374,f288,c67,f4530,c376,f43560,c60468,f115,e14874", .levels = &.{9}, .ext_dict = &.{9}, .corrects = false }, // rows: the hash cache is refilled after lazy skipping
    // The optimal parsers (levels 11-22) and long-distance matching over a
    // two-segment window:
    .{ .case = "mix-300000-9", .schedule = "w14,c*,e0", .levels = opt_levels, .ext_dict = opt_levels }, // unknown size: btopt from level 16
    .{ .case = "skewed-16384-2", .schedule = "p16384,w10,c3000,f0,c*,e0", .levels = &.{ 11, 13, 16, 19, 22 }, .ext_dict = &.{ 11, 13, 16, 19, 22 } }, // pledged <= 16 KB: btopt from level 11
    .{ .case = "two-symbols-200000", .schedule = "w13,c1000,f0,c7777,f0,c*,e0", .levels = opt_levels, .ext_dict = opt_levels }, // minMatch 3: the 3-byte hash across both segments
    .{ .case = "csv-200000-0", .schedule = "l,w15,c*,e0", .levels = opt_levels, .ext_dict = opt_levels }, // LDM by hand: its window wraps too
    .{ .case = "far-mix-5", .schedule = "l,w18,c300000,f0,c*,e0", .levels = &.{ 16, 19 }, .ext_dict = &.{ 16, 19 } }, // offsets past 2^20, LDM matches into the extDict
    .{ .case = "mix-300000-9", .schedule = "x,p300000,l,w12,c*,e0", .levels = &.{ 16, 19 }, .ext_dict = &.{ 16, 19 } }, // both windows corrected for overflow
    // ... found by a seed search over schedules (original against mutant):
    .{ .case = "mix-300000-28", .schedule = "l,w18,o1000,f52800,c7,c24476,c8,c10,f68511,c2247,c49127,c49898,c8741,c58,c168,e43949", .levels = &.{21}, .ext_dict = &.{21} }, // LDM: a candidate in the extDict extends backwards to the window's low limit
    .{ .case = "split-margin", .schedule = "l,w17,f35551,c10,f105190,c25472,c1,c1,f138968,f2984,c2378,c28907,c212,c23,c50027,e10276", .levels = &.{18}, .ext_dict = &.{18} }, // LDM: candidates are valid down to the low limit, not the prefix
    .{ .case = "csv-131072", .schedule = "p131072,w10,c74508,c24956,e31608", .levels = &.{21}, .ext_dict = &.{21} }, // a 3-byte-hash match from the extDict goes on at the prefix's first byte
    .{ .case = "mix-70000-0", .schedule = "x,l,w13,c16208,f34666,c9,f4384,c3296,c4130,f4398,e2909", .levels = &.{16}, .ext_dict = &.{16} }, // the LDM window's correction moves its extDict too
    // x: libzstd's frequent overflow correction, here of a two-segment window
    .{ .case = "mix-300000-9", .schedule = "x,w10,c*,e0", .ext_dict = all_stream_levels },
    .{ .case = "far-repeat", .schedule = "x,w14,c200000,f0,c*,e0", .ext_dict = all_stream_levels },
    // advanced parameters (`name=value`, as in `param_cases`)
    .{ .case = "csv-600000", .schedule = "srcSizeHint=5000,c*,e0" }, // unknown size chosen as 5000 bytes: an 8 KB window (as long as a block, so no extDict)
    .{ .case = "words-262145", .schedule = "srcSizeHint=200000,c100000,f0,c*,e0", .levels = lazy_only_levels }, // the 256 KB tier
    .{ .case = "csv-600000", .schedule = "maxBlockSize=4096,c*,e0", .levels = &.{ 1, 3, 5, 16 } },
    .{ .case = "words-16385", .schedule = "format=1,contentSizeFlag=0,p16385,c*,e0", .levels = &.{ 1, 5 } }, // pledged, yet no size in the header
    .{ .case = "words-16385", .schedule = "format=1,c1000,f0,c*,e0", .levels = &.{3} },
    .{ .case = "mix-300000-9", .schedule = "useRowMatchFinder=2,w15,c*,e0", .levels = lazy_only_levels, .ext_dict = &.{ 5, 6, 7, 8, 9, 10 } }, // hash chains over two segments where rows would run
    .{ .case = "mix-300000-9", .schedule = "useRowMatchFinder=1,w13,c*,e0", .levels = &.{ 5, 6, 7, 8 }, .ext_dict = &.{ 5, 6, 7, 8 } }, // rows in an 8 KB window
    .{ .case = "mix-200000-33", .schedule = "literalCompressionMode=2,w15,c*,e0", .levels = opt_levels, .ext_dict = opt_levels },
    // long-distance matching below the optimal parsers, over a two-segment
    // window: the match finders' extDict variants between its matches
    .{ .case = "far-repeat", .schedule = "l,w17,c300000,f0,c*,e0", .levels = &.{ -5, 1, 3 }, .ext_dict = &.{ -5, 1, 3 } },
    .{ .case = "csv-200000-0", .schedule = "l,w15,c*,e0", .levels = lazy_levels, .ext_dict = lazy_only_levels },
    .{ .case = "mix-300000-9", .schedule = "l,ldmMinMatch=4,ldmHashRateLog=1,w14,c*,e0", .levels = &.{ 1, 3, 5, 7 }, .ext_dict = &.{ 1, 3, 5, 7 } },
    // targetCBlockSize while streaming: flushes cut blocks short, then sub-blocks
    .{ .case = "csv-600000", .schedule = "targetCBlockSize=1340,w15,c100000,f0,c3000,f0,c*,e0", .levels = &.{ -5, 1, 3, 5, 7 }, .ext_dict = &.{ -5, 1, 3, 5, 7 } },
    .{ .case = "far-repeat", .schedule = "targetCBlockSize=8192,o700,c*,e0", .levels = &.{ 1, 3 } }, // a small output buffer
    // ... found by a seed search over corpus inputs and schedules (original against mutant):
    .{ .case = "mix-2031", .schedule = "targetCBlockSize=5000,o2755,c69,c15,c17979,c1225,f82,c65,c527,c32,c3,c3,e*", .levels = &.{9} }, // the literal header allows 200 bytes for the tables
    .{ .case = "sparse-far", .schedule = "targetCBlockSize=1340,f42293,c138441,c42,c207007,f5778,c1568,c1244,f2404,c337,c596,c0,c128,c149,c5,c3,f5,e*", .levels = &.{3} }, // a sub-block stops at its budget only while it still shrinks what it covers
    .{ .case = "drift-300000-8", .schedule = "targetCBlockSize=1340,literalCompressionMode=2,w12,o4072,f179089,c62647,c143,c21137,c17859,f76,f371,c4148,c95,f13305,c414,c31,f585,c15,f63,c3,c18,f0,f0,c1,e*", .levels = &.{-8} }, // the last sub-block exactly as long as it decodes to: the rest goes raw
    .{ .case = "ocf-ldm-mix-600000-9-w15", .schedule = "targetCBlockSize=1340,windowLog=13,c43458,c1546,f222273,c34063,c4968,c4479,c3902,c67154,c1427,c49105,c80,c1244,c31285,c131867,c55,c613,f1653,c54,c590,c160,c5,c13,c0,c4,c0,c2,e*", .levels = &.{-9} }, // ... and the repeat offsets go back to those of the sub-blocks emitted
    .{ .case = "long-match", .schedule = "targetCBlockSize=2000,maxBlockSize=65536,w11,c55789,c70384,c2304,c1276,c20498,f678,f24,c74,c29,c851,c48,c43,c1,c0,c1,e*", .levels = &.{-10} }, // an RLE block needs fewer than 10 literals
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

// ---------------------------------------------------------------------------
// Dictionaries (`dict_test.zig`, `testdata/cdict_goldens.zig`)

/// A dictionary the recipe trains with libzstd's `ZDICT_trainFromBuffer`
/// (`tools/zdtrain.c`) on generated samples; the result is committed as
/// `testdata/<name>.zdict`, which `dict_test.zig` embeds and pins.
pub const TrainSet = struct {
    name: []const u8,
    /// `dictBufferCapacity`.
    capacity: usize,
    kind: Kind,
    count: usize,
    seed: u64,
};

pub const train_sets = [_]TrainSet{
    .{ .name = "zd-words", .capacity = 4096, .kind = .words, .count = 200, .seed = 101 },
    .{ .name = "zd-csv", .capacity = 16384, .kind = .csv, .count = 200, .seed = 202 },
};

/// Training sample `i` of `ts`: 200..3000 bytes of its generator.
pub fn trainSample(ts: TrainSet, i: usize, out_len: *usize) Case {
    var r: Rng = .{ .s = ts.seed *% 0x9E3779B97F4A7C15 +% i };
    const len: usize = 200 + @as(usize, @intCast(r.below(2800)));
    out_len.* = len;
    return .{ .name = "", .len = len, .kind = ts.kind, .seed = ts.seed * 1000 + i };
}

/// A dictionary of the dictionary goldens.
pub const DictDef = struct {
    name: []const u8,
    source: Source,

    pub const Source = union(enum) {
        /// Raw content: this generated input.
        generated: Case,
        /// A trained full dictionary (`train_sets`).
        trained: []const u8,
        /// The trained dictionary `of` with its ID replaced: 1- and 2-byte
        /// ID fields (libzstd's trainer picks IDs of 32768 and up).
        reid: struct { of: []const u8, id: u32 },
        /// A hand-built full dictionary whose tables all start as `check`:
        /// a Huffman table over ASCII with zero weights (control bytes but
        /// the newline), FSE tables with zero probabilities, repcodes 1 4 8,
        /// then `content`.
        crafted: struct { content: Case, id: u32 },
        /// Raw content: `len` bytes of the generated input `of` from
        /// `from` -- a dictionary that is a piece of the input it serves.
        slice: struct { of: Case, from: usize, len: usize },
    };
};

pub const dict_defs = [_]DictDef{
    .{ .name = "raw-words-8000", .source = .{ .generated = .{ .name = "", .len = 8000, .kind = .words, .seed = 21 } } },
    .{ .name = "raw-csv-30000", .source = .{ .generated = .{ .name = "", .len = 30000, .kind = .csv, .seed = 22 } } },
    .{ .name = "raw-csv-150000", .source = .{ .generated = .{ .name = "", .len = 150000, .kind = .csv, .seed = 25 } } },
    .{ .name = "raw-csv-28672", .source = .{ .generated = .{ .name = "", .len = 28672, .kind = .csv, .seed = 26 } } },
    .{ .name = "raw-words-3584", .source = .{ .generated = .{ .name = "", .len = 3584, .kind = .words, .seed = 27 } } },
    .{ .name = "raw-words-15900", .source = .{ .generated = .{ .name = "", .len = 15900, .kind = .words, .seed = 28 } } },
    .{ .name = "raw-one", .source = .{ .generated = .{ .name = "", .len = 1, .kind = .words, .seed = 29 } } },
    .{ .name = "raw-mix-100000-self", .source = .{ .generated = .{ .name = "", .len = 100000, .kind = .mix, .seed = 14 } } },
    .{ .name = "raw-mix-3000", .source = .{ .generated = .{ .name = "", .len = 3000, .kind = .mix, .seed = 24 } } },
    .{ .name = "raw-words-9000-self", .source = .{ .generated = .{ .name = "", .len = 9000, .kind = .words, .seed = 30 } } },
    .{ .name = "slice-words-6000-at-1000", .source = .{ .slice = .{ .of = .{ .name = "", .len = 9000, .kind = .words, .seed = 35 }, .from = 1000, .len = 6000 } } },
    .{ .name = "slice-far-repeat-tail", .source = .{ .slice = .{ .of = .{ .name = "", .len = 1400000, .kind = .far_repeat, .seed = 34 }, .from = 692000, .len = 8000 } } },
    .{ .name = "zd-words", .source = .{ .trained = "zd-words" } },
    .{ .name = "zd-csv", .source = .{ .trained = "zd-csv" } },
    .{ .name = "zd-words-id200", .source = .{ .reid = .{ .of = "zd-words", .id = 200 } } },
    .{ .name = "zd-words-id1000", .source = .{ .reid = .{ .of = "zd-words", .id = 1000 } } },
    .{ .name = "zd-words-id256", .source = .{ .reid = .{ .of = "zd-words", .id = 256 } } },
    .{ .name = "zd-words-id65536", .source = .{ .reid = .{ .of = "zd-words", .id = 65536 } } },
    .{ .name = "crafted-words", .source = .{ .crafted = .{ .content = .{ .name = "", .len = 3000, .kind = .words, .seed = 23 }, .id = 70000 } } },
};

pub fn findDict(name: []const u8) DictDef {
    for (dict_defs) |d| if (std.mem.eql(u8, d.name, name)) return d;
    unreachable;
}

/// The bytes of `d` into `out` (at least `dictLen(d)` long); `trained`
/// gives a trained dictionary's bytes by name. Returns the length.
pub fn buildDict(d: DictDef, trained: *const fn ([]const u8) []const u8, out: []u8) usize {
    switch (d.source) {
        .generated => |c| {
            generate(c, out[0..c.len]);
            return c.len;
        },
        .trained => |name| {
            const t = trained(name);
            @memcpy(out[0..t.len], t);
            return t.len;
        },
        .reid => |x| {
            const t = trained(x.of);
            @memcpy(out[0..t.len], t);
            std.mem.writeInt(u32, out[4..8], x.id, .little);
            return t.len;
        },
        .crafted => |x| return crafted(x.content, x.id, out),
        .slice => |x| {
            generate(x.of, out[0..x.of.len]);
            std.mem.copyForwards(u8, out[0..x.len], out[x.from..][0..x.len]);
            return x.len;
        },
    }
}

/// An upper bound of `buildDict`'s length.
pub fn dictLen(d: DictDef, trained: *const fn ([]const u8) []const u8) usize {
    return switch (d.source) {
        .generated => |c| c.len,
        .trained => |name| trained(name).len,
        .reid => |x| trained(x.of).len,
        .crafted => |x| x.content.len + 512,
        .slice => |x| x.of.len,
    };
}

/// `FSE_writeNCount` (the safe variant), for the crafted dictionary.
fn writeNCount(out: []u8, norm: []const i16, max_symbol: u32, table_log: u32) usize {
    var op: usize = 0;
    const table_size: i32 = @as(i32, 1) << @intCast(table_log);
    var bit_stream: u32 = table_log - 5;
    var bit_count: u32 = 4;
    var remaining: i32 = table_size + 1;
    var threshold: i32 = table_size;
    var nb_bits: u32 = table_log + 1;
    var symbol: u32 = 0;
    var previous_is0 = false;
    while (symbol <= max_symbol and remaining > 1) {
        if (previous_is0) {
            var start = symbol;
            while (symbol <= max_symbol and norm[symbol] == 0) symbol += 1;
            std.debug.assert(symbol <= max_symbol);
            while (symbol >= start + 24) {
                start += 24;
                bit_stream +%= @as(u32, 0xFFFF) << @intCast(bit_count);
                std.mem.writeInt(u16, out[op..][0..2], @truncate(bit_stream), .little);
                op += 2;
                bit_stream >>= 16;
            }
            while (symbol >= start + 3) {
                start += 3;
                bit_stream +%= @as(u32, 3) << @intCast(bit_count);
                bit_count += 2;
            }
            bit_stream +%= (symbol - start) << @intCast(bit_count);
            bit_count += 2;
            if (bit_count > 16) {
                std.mem.writeInt(u16, out[op..][0..2], @truncate(bit_stream), .little);
                op += 2;
                bit_stream >>= 16;
                bit_count -= 16;
            }
        }
        var count: i32 = norm[symbol];
        symbol += 1;
        const max: i32 = (2 * threshold - 1) - remaining;
        remaining -= if (count < 0) -count else count;
        count += 1; // +1 for extra accuracy
        if (count >= threshold) count += max;
        bit_stream +%= @as(u32, @bitCast(count)) << @intCast(bit_count);
        bit_count += nb_bits;
        bit_count -= @intFromBool(count < max);
        previous_is0 = count == 1;
        std.debug.assert(remaining >= 1);
        while (remaining < threshold) {
            nb_bits -= 1;
            threshold >>= 1;
        }
        if (bit_count > 16) {
            std.mem.writeInt(u16, out[op..][0..2], @truncate(bit_stream), .little);
            op += 2;
            bit_stream >>= 16;
            bit_count -= 16;
        }
    }
    std.debug.assert(remaining == 1);
    std.mem.writeInt(u16, out[op..][0..2], @truncate(bit_stream), .little);
    op += (bit_count + 7) / 8;
    return op;
}

/// The crafted full dictionary (`DictDef.Source.crafted`).
fn crafted(content: Case, id: u32, out: []u8) usize {
    std.mem.writeInt(u32, out[0..4], 0xEC30A437, .little);
    std.mem.writeInt(u32, out[4..8], id, .little);
    var p: usize = 8;
    // Huffman weights, direct representation: symbols 0..126 (the last,
    // 127, implied). Zero for the control bytes but '\n'; 2 for the 31
    // most common text bytes, 1 for the other 65: 31 * 2 + 65 = 127, so the
    // implied weight is 1 and the table log 7.
    var w = [_]u8{0} ** 128;
    for (32..127) |s| w[s] = 1;
    w['\n'] = 1;
    for ("abcdefghijklmnopqrstuvwxyz ,.\n0") |s| w[s] = 2;
    out[p] = 127 + 127;
    p += 1;
    var n: usize = 0;
    while (n < 127) : (n += 2) {
        out[p] = (w[n] << 4) | w[n + 1];
        p += 1;
    }
    // offset codes (log 6): 0..20 but 5, so the table has a zero within
    // what the content's offsets need
    var of_norm = [_]i16{0} ** 32;
    for (0..21) |s| of_norm[s] = 3;
    of_norm[5] = 0;
    of_norm[0] += 4;
    p += writeNCount(out[p..], &of_norm, 20, 6);
    // match lengths (log 6): codes 0..31 only
    var ml_norm = [_]i16{0} ** 53;
    for (0..32) |s| ml_norm[s] = 2;
    p += writeNCount(out[p..], &ml_norm, 31, 6);
    // literal lengths (log 6): codes 0..15 only
    var ll_norm = [_]i16{0} ** 36;
    for (0..16) |s| ll_norm[s] = 4;
    p += writeNCount(out[p..], &ll_norm, 15, 6);
    for ([_]u32{ 1, 4, 8 }) |rep| {
        std.mem.writeInt(u32, out[p..][0..4], rep, .little);
        p += 4;
    }
    generate(content, out[p..][0..content.len]);
    return p + content.len;
}

/// How a dictionary golden uses its dictionary: libzstd's call on one side
/// (`tools/zref.c`, `tools/zstream.c` with a schedule), this module's on the
/// other.
pub const DictPath = enum {
    /// `ZSTD_CCtx_loadDictionary_advanced` + `ZSTD_compress2` (`Options.dictionary = .raw`).
    load,
    /// `ZSTD_createCDict(level)` + `ZSTD_CCtx_refCDict` (`CDict.init`, `.cdict`).
    cdict,
    /// `ZSTD_createCDict_advanced2` with the level and the parameters (`CDict.initAdvanced`).
    cdictadv,
    /// `ZSTD_CCtx_refPrefix_advanced` (`.prefix`).
    prefix,
    /// The same, the input right after the prefix in memory.
    prefixadj,
    /// `ZSTD_compress_usingDict` (`Compressor.compressUsingDict`).
    usingdict,
    /// `ZSTD_compress_usingCDict_advanced` (`Compressor.compressUsingCDict`).
    usingcdict,
};

/// A dictionary golden: `input` compressed with dictionary `dict` used as
/// `path` says, content type `content_type` (0 auto, 1 raw, 2 full),
/// advanced parameters `params` (`param_cases`' grammar), one-shot -- or,
/// with a `schedule`, streaming (`stream_cases`' grammar) -- at each of
/// `levels`, once per `checksums` entry.
pub const DictCase = struct {
    name: []const u8,
    input: Case,
    dict: []const u8,
    path: DictPath,
    content_type: u2 = 0,
    params: []const u8 = "-",
    schedule: ?[]const u8 = null,
    levels: []const i32,
    checksums: []const bool = &.{false},
    /// Against libzstd built to correct index overflow frequently
    /// (`Case.ocf`); one-shot `.load`, `.cdict` or `.prefix` only.
    ocf: bool = false,
};

const all_levels: []const i32 = &levels;
const in_words_40000: Case = .{ .name = "", .len = 40000, .kind = .words, .seed = 11 };
const in_csv_200000: Case = .{ .name = "", .len = 200000, .kind = .csv, .seed = 12 };
const in_words_3000: Case = .{ .name = "", .len = 3000, .kind = .words, .seed = 13 };
const in_mix_100000: Case = .{ .name = "", .len = 100000, .kind = .mix, .seed = 14 };
const in_empty: Case = .{ .name = "", .len = 0, .kind = .words };
const some_levels: []const i32 = &.{ -5, 1, 3, 5, 9, 13, 19 };

pub const dict_cases = [_]DictCase{
    // every level, one path each
    .{ .name = "cdict-copy", .input = in_words_40000, .dict = "zd-words", .path = .cdict, .levels = all_levels, .checksums = &.{ false, true } }, // above every attach cutoff: tables copied
    .{ .name = "load-copy", .input = in_words_40000, .dict = "raw-words-8000", .path = .load, .levels = all_levels }, // the context's own CDict (no level): copied
    .{ .name = "prefix", .input = in_csv_200000, .dict = "raw-csv-30000", .path = .prefix, .levels = all_levels }, // loaded into the context
    .{ .name = "usingdict", .input = in_csv_200000, .dict = "zd-csv", .path = .usingdict, .levels = all_levels },
    .{ .name = "cdict-reload", .input = in_csv_200000, .dict = "zd-csv", .path = .cdict, .levels = all_levels }, // 200 KB >= 128 KB and 6x the dictionary: loaded anew with the input's parameters
    .{ .name = "usingcdict", .input = in_words_40000, .dict = "zd-words", .path = .usingcdict, .levels = some_levels, .checksums = &.{ false, true } },
    .{ .name = "usingcdict-reload", .input = in_csv_200000, .dict = "raw-csv-30000", .path = .usingcdict, .levels = &.{ 1, 3, 7 } },
    // content types
    .{ .name = "cdictadv-full-as-raw", .input = in_words_40000, .dict = "zd-words", .path = .cdictadv, .content_type = 1, .params = "forceAttachDict=2", .levels = &.{ 1, 3, 6, 12, 16 } },
    .{ .name = "load-full", .input = in_mix_100000, .dict = "zd-csv", .path = .load, .content_type = 2, .levels = &.{ -1, 2, 4, 7, 10, 15, 18 } },
    .{ .name = "prefix-raw", .input = in_words_40000, .dict = "raw-mix-3000", .path = .prefix, .content_type = 1, .levels = &.{ 1, 3, 5, 8, 11, 17 } },
    // dictionary IDs: none, 1, 2 and 4 bytes
    .{ .name = "cdict-no-id", .input = in_words_40000, .dict = "zd-words", .path = .cdict, .params = "dictIDFlag=0", .levels = &.{ 3, 19 } },
    .{ .name = "load-id200", .input = in_words_40000, .dict = "zd-words-id200", .path = .load, .levels = &.{3} },
    .{ .name = "load-id1000", .input = in_words_40000, .dict = "zd-words-id1000", .path = .load, .levels = &.{3} },
    .{ .name = "load-id256", .input = in_words_40000, .dict = "zd-words-id256", .path = .load, .levels = &.{3} }, // the 2-byte field from 256
    .{ .name = "load-id65536", .input = in_words_40000, .dict = "zd-words-id65536", .path = .load, .levels = &.{3} }, // the 4-byte field from 65536
    .{ .name = "cdictadv-no-id", .input = in_words_40000, .dict = "zd-words-id1000", .path = .cdictadv, .params = "dictIDFlag=0,forceAttachDict=2", .levels = &.{5} },
    // tables that must be checked (the crafted dictionary)
    .{ .name = "usingdict-crafted", .input = in_words_40000, .dict = "crafted-words", .path = .usingdict, .levels = &.{ -1, 1, 3, 5, 8, 12, 16, 19 } },
    .{ .name = "load-crafted", .input = in_words_3000, .dict = "crafted-words", .path = .load, .params = "forceAttachDict=2", .levels = &.{ 1, 3, 5, 13 } },
    // 128 KB exactly: a CDict with a level is loaded anew
    .{ .name = "cdict-reload-at-128k", .input = .{ .name = "", .len = 131072, .kind = .csv, .seed = 15 }, .dict = "zd-words", .path = .cdict, .levels = &.{ 3, 12 } },
    .{ .name = "usingcdict-reload-at-128k", .input = .{ .name = "", .len = 131072, .kind = .csv, .seed = 15 }, .dict = "zd-words", .path = .usingcdict, .levels = &.{5} },
    // ... and six times the dictionary exactly (below it, the CDict's own
    // parameters)
    .{ .name = "cdict-reload-at-6x", .input = .{ .name = "", .len = 180000, .kind = .csv, .seed = 16 }, .dict = "raw-csv-30000", .path = .cdict, .levels = &.{ 2, 9 } },
    // the match length a dictionary is hashed with: 7 as 7 (the search
    // clamps it to 6), 3 as 4
    .{ .name = "prefix-minmatch-7", .input = in_words_40000, .dict = "raw-words-8000", .path = .prefix, .params = "minMatch=7", .levels = &.{ 1, 3, 5, 7, 13 } },
    .{ .name = "prefix-minmatch-3-chain", .input = in_words_40000, .dict = "raw-words-8000", .path = .prefix, .params = "minMatch=3,useRowMatchFinder=2", .levels = &.{ 5, 8, 11 } },
    .{ .name = "cdict-minmatch-7-row", .input = in_words_40000, .dict = "raw-words-8000", .path = .cdictadv, .params = "minMatch=7,useRowMatchFinder=1,forceAttachDict=2", .levels = &.{ 5, 7 } },
    // Found by the mutation sweep (SPEC.md, *Anchoring*):
    // a dictionary longer than the tables reach loads its end only
    .{ .name = "prefix-long-dict", .input = in_csv_200000, .dict = "raw-csv-150000", .path = .prefix, .levels = &.{ 1, 3 } }, // 2^(hashLog + 3)
    .{ .name = "prefix-long-dict-chain", .input = in_csv_200000, .dict = "raw-csv-150000", .path = .prefix, .params = "hashLog=10,chainLog=16,useRowMatchFinder=2", .levels = &.{5} }, // 2^(chainLog + 1)
    // a dictionary valid across a window: as far back as the dictionary, not further
    .{ .name = "prefix-force-max-window", .input = in_words_40000, .dict = "raw-words-8000", .path = .prefix, .params = "forceMaxWindow=1,windowLog=12", .levels = &.{ 1, 5, 16 } },
    .{ .name = "prefix-adjacent-window", .input = in_words_40000, .dict = "raw-words-8000", .path = .prefixadj, .params = "windowLog=12", .levels = &.{ 1, 3, 5, 12 } },
    .{ .name = "prefix-window-rows", .input = in_csv_200000, .dict = "raw-csv-30000", .path = .prefix, .params = "windowLog=15", .levels = &.{ 5, 7 } },
    .{ .name = "prefix-ldm-window", .input = in_csv_200000, .dict = "raw-csv-30000", .path = .prefix, .params = "enableLongDistanceMatching=1,windowLog=15", .levels = &.{ 3, 16 } },
    // levels: a CDict made at level 0 has level 3; one without a level
    // gives the frame the default level, and is never reloaded
    .{ .name = "cdict-reload-level0", .input = in_csv_200000, .dict = "zd-csv", .path = .cdict, .levels = &.{0} },
    .{ .name = "cdictadv-large", .input = in_csv_200000, .dict = "zd-csv", .path = .cdictadv, .levels = &.{ 1, 19 } },
    .{ .name = "cdictadv-force-load", .input = in_csv_200000, .dict = "zd-csv", .path = .cdictadv, .params = "forceAttachDict=3", .levels = &.{ 1, 19 } },
    // compressUsingCDict: at six times the dictionary, reloaded; a window
    // grown to the input past 256 KB; switches resolved before it grows
    .{ .name = "usingcdict-reload-at-6x", .input = .{ .name = "", .len = 180000, .kind = .csv, .seed = 16 }, .dict = "raw-csv-30000", .path = .usingcdict, .levels = &.{2} },
    .{ .name = "usingcdict-wide", .input = .{ .name = "", .len = 300000, .kind = .csv, .seed = 17 }, .dict = "raw-csv-150000", .path = .usingcdict, .levels = &.{ 1, 5 } },
    .{ .name = "usingcdict-grown-window", .input = in_mix_100000, .dict = "raw-mix-3000", .path = .usingcdict, .levels = &.{ 16, 19 } },
    // a copy keeps the switches resolved on the frame's parameters
    .{ .name = "cdict-copy-splitter", .input = in_mix_100000, .dict = "zd-words", .path = .cdict, .levels = &.{ 16, 19 } },
    // minMatch 7 into hash chains
    .{ .name = "prefix-minmatch-7-chain", .input = in_words_40000, .dict = "raw-words-8000", .path = .prefix, .params = "minMatch=7,useRowMatchFinder=2", .levels = &.{ 5, 7 } },
    // an input of 8 bytes: the optimal parser seeded from the dictionary
    .{ .name = "cdict-eight-bytes", .input = .{ .name = "", .len = 8, .kind = .words, .seed = 18 }, .dict = "zd-words", .path = .cdict, .params = "forceAttachDict=2", .levels = &.{ 16, 19 } },
    // the window covering the dictionary and the input exactly, and a
    // dictionary plus window of exactly 2^15 (ZSTD_dictAndWindowLog)
    .{ .name = "prefix-window-fits", .input = .{ .name = "", .len = 2768, .kind = .csv, .seed = 19 }, .dict = "raw-csv-30000", .path = .prefix, .levels = &.{ 4, 7, 12 } },
    .{ .name = "prefix-dict-and-window-pow2", .input = in_csv_200000, .dict = "raw-csv-28672", .path = .prefix, .params = "windowLog=12", .levels = &.{ 4, 7 } },
    .{ .name = "prefix-one-byte", .input = in_csv_200000, .dict = "raw-one", .path = .prefix, .params = "windowLog=17", .levels = &.{10} },
    // a CDict for 513 + 3584 = 4097 bytes; a tagged table capped at 2^24
    .{ .name = "cdict-513", .input = in_words_40000, .dict = "raw-words-3584", .path = .cdict, .params = "forceAttachDict=2", .levels = &.{ 3, 6 } },
    .{ .name = "cdictadv-tag-cap", .input = in_words_40000, .dict = "raw-words-8000", .path = .cdictadv, .params = "hashLog=25,forceAttachDict=2", .levels = &.{1} },
    // an unknown size: the table row for the dictionary + 500 bytes
    .{ .name = "stream-prefix-500", .input = in_words_40000, .dict = "raw-words-15900", .path = .prefix, .schedule = "c*,e0", .levels = &.{ 5, 12 } },
    // ... and by searching generator seeds (original against mutant):
    .{ .name = "usingdict-6-literals", .input = .{ .name = "", .len = 272, .kind = .words, .seed = 660316 }, .dict = "zd-words", .path = .usingdict, .levels = &.{3} }, // a dictionary's Huffman table compresses 6 literals
    .{ .name = "cdict-1000-sequences", .input = .{ .name = "", .len = 101386, .kind = .mix, .seed = 812926 }, .dict = "zd-words", .path = .cdict, .params = "forceAttachDict=2", .levels = &.{3} }, // a valid table is repeated below 1000 sequences only
    // long-distance matching into a raw dictionary (here the input itself)
    .{ .name = "prefix-ldm-self", .input = in_mix_100000, .dict = "raw-mix-100000-self", .path = .prefix, .params = "enableLongDistanceMatching=1,windowLog=15", .levels = &.{ 1, 3, 16 } },
    // a tagged CDict table capped at 2^24 (the window lets the hash log stay)
    .{ .name = "cdictadv-tag-cap-24", .input = in_words_40000, .dict = "raw-words-8000", .path = .cdictadv, .params = "hashLog=25,windowLog=27,forceAttachDict=2", .levels = &.{1} },
    // loaded anew where it would be attached: the parameters ignore the dictionary's size
    .{ .name = "cdict-force-load-csv", .input = in_words_3000, .dict = "zd-csv", .path = .cdict, .params = "forceAttachDict=3", .levels = &.{ 1, 5 } },
    // attach preference: small inputs copied, or loaded anew
    .{ .name = "cdict-force-copy", .input = in_words_3000, .dict = "zd-words", .path = .cdict, .params = "forceAttachDict=2", .levels = &.{ 1, 3, 5, 9, 13, 19 } },
    .{ .name = "cdict-force-load", .input = in_words_3000, .dict = "zd-words", .path = .cdict, .params = "forceAttachDict=3", .levels = &.{ 1, 4, 16 } },
    .{ .name = "load-force-max-window", .input = in_words_3000, .dict = "raw-words-8000", .path = .load, .params = "forceMaxWindow=1", .levels = &.{ 1, 3, 7, 16 } }, // never attached; the dictionary only within the window
    // a prefix right before the input in memory: one segment
    .{ .name = "prefix-adjacent", .input = in_words_40000, .dict = "raw-words-8000", .path = .prefixadj, .levels = &.{ 1, 3, 5, 9, 13, 19 } },
    .{ .name = "prefix-adjacent-deterministic", .input = in_words_40000, .dict = "raw-words-8000", .path = .prefixadj, .params = "deterministicRefPrefix=1", .levels = &.{ 3, 9 } },
    // a window shorter than the dictionary and the input
    .{ .name = "prefix-window", .input = in_csv_200000, .dict = "raw-csv-30000", .path = .prefix, .params = "windowLog=12", .levels = &.{ 1, 3, 5, 13 } },
    // ... with index overflow corrected as often as it may: not while the
    // dictionary is still valid, and a correction invalidates it
    .{ .name = "prefix-window-ocf", .input = in_csv_200000, .dict = "raw-csv-30000", .path = .prefix, .params = "windowLog=12", .levels = &.{ 1, 3, 5, 13 }, .ocf = true },
    .{ .name = "cdict-window-ocf", .input = in_csv_200000, .dict = "zd-csv", .path = .cdict, .params = "windowLog=11,forceAttachDict=2", .levels = &.{ -1, 4, 16 }, .ocf = true },
    // long-distance matching with a raw dictionary (it enters the LDM table too)
    .{ .name = "prefix-ldm", .input = in_csv_200000, .dict = "raw-csv-30000", .path = .prefix, .params = "enableLongDistanceMatching=1", .levels = &.{ 3, 16 } },
    // frame flags
    .{ .name = "cdict-magicless", .input = in_words_40000, .dict = "zd-words", .path = .cdict, .params = "format=1", .levels = &.{3} },
    .{ .name = "usingcdict-no-size", .input = in_words_40000, .dict = "zd-words", .path = .usingcdict, .params = "contentSizeFlag=0,dictIDFlag=0", .levels = &.{3} },
    // an empty input: the header still carries the dictionary ID
    .{ .name = "empty-cdict", .input = in_empty, .dict = "zd-words", .path = .cdict, .params = "forceAttachDict=2", .levels = &.{3} },
    .{ .name = "empty-usingdict", .input = in_empty, .dict = "zd-words", .path = .usingdict, .levels = &.{3} },
    // streaming (`schedule`): the dictionary is the first frame's
    .{ .name = "stream-load", .input = in_words_40000, .dict = "raw-words-8000", .path = .load, .schedule = "forceAttachDict=2,c*,e0", .levels = &.{ -5, -1, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 16, 19 } },
    .{ .name = "stream-cdict-reload", .input = in_csv_200000, .dict = "zd-csv", .path = .cdict, .schedule = "p200000,c*,e0", .levels = &.{ 1, 3, 5, 9, 16 } },
    .{ .name = "stream-prefix", .input = in_csv_200000, .dict = "raw-csv-30000", .path = .prefix, .schedule = "c50000,f0,c*,e0", .levels = &.{ 1, 3, 6, 12 } },
    .{ .name = "stream-cdictadv-wrap", .input = in_words_40000, .dict = "zd-words", .path = .cdictadv, .schedule = "w12,forceAttachDict=2,c10000,f0,c*,e0", .levels = &.{ 3, 7, 16 } }, // the buffer wraps: the dictionary leaves the window
} ++ dict_cases_attach_opt;

const attach_opt_levels: []const i32 = &.{ 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22 };
const in_words_8192: Case = .{ .name = "", .len = 8192, .kind = .words, .seed = 31 };
const in_words_8193: Case = .{ .name = "", .len = 8193, .kind = .words, .seed = 31 };
const in_words_32768: Case = .{ .name = "", .len = 32768, .kind = .words, .seed = 32 };
const in_words_32769: Case = .{ .name = "", .len = 32769, .kind = .words, .seed = 32 };

/// D3: the optimal parsers with an attached CDict (`dictMatchState`, the
/// attach cutoffs of btopt 32 KB and btultra / btultra2 8 KB), and
/// long-distance matching with a dictionary. zd-words' CDict (a 4 KB
/// dictionary: the 16 KB table) runs btopt at 11-12, btultra at 13-15 and
/// btultra2 from 16; zd-csv's (16 KB: the 128 KB table) btopt at 13-15,
/// btultra at 16-18, btultra2 from 19.
pub const dict_cases_attach_opt = [_]DictCase{
    // small inputs attach, every optimal level
    .{ .name = "attach-opt-cdict", .input = in_words_3000, .dict = "zd-words", .path = .cdict, .levels = attach_opt_levels, .checksums = &.{ false, true } },
    .{ .name = "attach-opt-load", .input = in_words_3000, .dict = "raw-words-8000", .path = .load, .levels = attach_opt_levels },
    .{ .name = "attach-opt-usingcdict", .input = in_words_3000, .dict = "zd-words", .path = .usingcdict, .levels = &.{ 11, 13, 16, 19, 22 } },
    .{ .name = "attach-opt-full-as-raw", .input = in_words_3000, .dict = "zd-csv", .path = .cdictadv, .content_type = 1, .levels = &.{ 13, 16, 19, 22 } },
    // the cutoffs: 8 KB attaches btultra / btultra2, one byte more copies;
    // btopt attaches up to 32 KB
    .{ .name = "attach-opt-8192", .input = in_words_8192, .dict = "zd-words", .path = .cdict, .levels = &.{ 11, 13, 15, 16, 19, 22 } },
    .{ .name = "attach-opt-8193", .input = in_words_8193, .dict = "zd-words", .path = .cdict, .levels = &.{ 11, 13, 15, 16, 19, 22 } },
    .{ .name = "attach-opt-32768", .input = in_words_32768, .dict = "zd-csv", .path = .cdict, .levels = &.{ 13, 14, 15 } },
    .{ .name = "attach-opt-32769", .input = in_words_32769, .dict = "zd-csv", .path = .cdict, .levels = &.{ 13, 14, 15 } },
    // forced: a larger input, several blocks (the dictionary stays valid)
    .{ .name = "attach-opt-force", .input = in_mix_100000, .dict = "zd-csv", .path = .cdict, .params = "forceAttachDict=1", .levels = &.{ 13, 16, 19, 22 } },
    .{ .name = "attach-opt-force-blocks", .input = in_csv_200000, .dict = "raw-csv-30000", .path = .load, .params = "forceAttachDict=1", .levels = &.{ 13, 16, 19, 22 } },
    // strategies and match lengths no level gives with this CDict
    .{ .name = "attach-opt-strategy-btopt", .input = in_words_3000, .dict = "zd-words", .path = .cdictadv, .params = "strategy=7", .levels = &.{ 1, 5 } },
    .{ .name = "attach-opt-strategy-btultra", .input = in_words_3000, .dict = "zd-words", .path = .cdictadv, .params = "strategy=8", .levels = &.{ 3, 19 } },
    .{ .name = "attach-opt-strategy-btultra2", .input = in_words_3000, .dict = "zd-words", .path = .cdictadv, .params = "strategy=9", .levels = &.{ 1, 12 } },
    .{ .name = "attach-opt-minmatch", .input = in_words_3000, .dict = "raw-words-8000", .path = .cdictadv, .params = "minMatch=5", .levels = &.{ 11, 16, 19 } },
    .{ .name = "attach-opt-minmatch-3", .input = in_words_3000, .dict = "raw-words-8000", .path = .cdictadv, .params = "minMatch=3,targetLength=999", .levels = &.{ 11, 13 } },
    // the input is the dictionary: matches longer than ZSTD_OPT_NUM and up
    // to the end of the input
    .{ .name = "attach-opt-self", .input = .{ .name = "", .len = 9000, .kind = .words, .seed = 30 }, .dict = "raw-words-9000-self", .path = .cdict, .levels = &.{ 11, 12 } },
    .{ .name = "attach-opt-self-force", .input = .{ .name = "", .len = 9000, .kind = .words, .seed = 30 }, .dict = "raw-words-9000-self", .path = .cdict, .params = "forceAttachDict=1", .levels = &.{ 13, 19 } },
    // attached with long-distance matching
    .{ .name = "attach-opt-ldm", .input = in_csv_200000, .dict = "raw-csv-30000", .path = .load, .params = "forceAttachDict=1,enableLongDistanceMatching=1", .levels = &.{ 16, 19 } },
    // unknown sizes attach: streams
    .{ .name = "attach-opt-stream", .input = in_words_40000, .dict = "zd-words", .path = .cdict, .schedule = "c*,e0", .levels = attach_opt_levels },
    .{ .name = "attach-opt-stream-load", .input = in_csv_200000, .dict = "raw-csv-30000", .path = .load, .schedule = "c50000,f0,c*,e0", .levels = &.{ 13, 16, 19, 22 } },
    .{ .name = "attach-opt-stream-wrap", .input = in_words_40000, .dict = "zd-words", .path = .cdictadv, .schedule = "w12,c10000,f0,c*,e0", .levels = &.{ 13, 19 } }, // the dictionary leaves the window, then the buffer wraps
    // Found by the mutation sweep:
    // a CDict longer than its binary tree reaches (`dmsBtLow`)
    .{ .name = "attach-opt-bt-low", .input = .{ .name = "", .len = 6000, .kind = .csv, .seed = 33 }, .dict = "raw-csv-30000", .path = .cdictadv, .params = "chainLog=12,searchLog=8", .levels = &.{ 13, 16, 19 } },
    // ... and a candidate right at that edge
    .{ .name = "attach-opt-bt-low-edge", .input = in_words_40000, .dict = "raw-words-15900", .path = .cdictadv, .params = "chainLog=9,forceAttachDict=1", .levels = &.{ 13, 16 } },
    // a dictionary taken from the input at 1000: the best match there
    // starts at the dictionary's first byte (`> dmsLowLimit`)
    .{ .name = "attach-opt-dict-start", .input = .{ .name = "", .len = 9000, .kind = .words, .seed = 35 }, .dict = "slice-words-6000-at-1000", .path = .cdict, .levels = &.{ 11, 12 } },
    // the dictionary is the text right before the input's second copy of
    // itself: its matches run past its end into the prefix
    // (`ZSTD_count_2segments`)
    .{ .name = "attach-opt-cross-end", .input = .{ .name = "", .len = 1400000, .kind = .far_repeat, .seed = 34 }, .dict = "slice-far-repeat-tail", .path = .load, .params = "forceAttachDict=1", .levels = &.{ 13, 16 } },
    // long-distance matching into a raw dictionary the tables reach only
    // the end of: the LDM table holds all of it
    .{ .name = "prefix-ldm-beyond-tables", .input = in_mix_100000, .dict = "raw-mix-100000-self", .path = .prefix, .params = "enableLongDistanceMatching=1,hashLog=10,chainLog=10,windowLog=17", .levels = &.{ 1, 5, 16 } },
};
