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
    dict_boundary_echo, // hunted (D1): a dictMatchState match reaches exactly the CDict's end and continues into the prefix
    survivor_literal, // hunted (D1): a mutation-sweep survivor's killing case; `seed` indexes `survivor_inputs`
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
        .dict_boundary_echo => @memcpy(out, &dict_boundary_echo_input),
        .survivor_literal => @memcpy(out, survivor_inputs[case.seed]),
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
        /// Fixed bytes, verbatim (a hunted case that needs an exact byte
        /// coincidence a generator is unlikely to reproduce).
        literal: []const u8,
    };
};

const dict_boundary_echo_dict = [_]u8{
    126, 194, 52,  127, 6,   110, 208, 143, 93,  199, 81,  36,  71,  227, 64,  67,  0,   2,   107, 110,
    84,  85,  148, 160, 101, 104, 93,  100, 196, 152, 11,  184, 212, 84,  74,  135, 33,  169, 154, 1,
    173, 33,  158, 181, 156, 246, 161, 94,  246, 241, 90,  29,  131, 11,  183, 206, 9,   214, 187, 192,
    4,   231, 23,  92,  100, 60,  125, 236, 176, 181, 128, 236, 55,  188, 151, 18,  221, 46,  106, 174,
    185, 75,  174, 141, 47,  159, 162, 156, 90,  40,  76,  158, 247, 82,  24,  41,  207, 16,  121, 176,
    128, 233, 215, 74,  28,  16,  252, 171, 106, 66,  67,  211, 54,  86,  222, 190, 76,  30,  215, 150,
    72,  232, 86,  232, 249, 162, 245, 140, 149, 240, 206, 75,  57,  193, 91,  255, 173, 92,  45,  251,
    139, 184, 32,  182, 17,  156, 186, 143, 248, 135, 150, 174, 91,  5,   242, 128, 166, 140, 237, 147,
    182, 178, 140, 176, 209, 179, 88,  230, 186, 171, 72,  85,  101, 185, 244, 144, 40,  213, 87,  215,
    154, 138, 14,  100, 81,  225, 92,  112, 92,  21,  241, 115, 84,  27,  68,  56,  162, 92,  247, 99,
    18,  212, 238, 179, 194, 36,  104, 121, 191, 0,   179, 207, 142, 209, 58,  191, 18,  154, 48,  151,
    173, 150, 180, 66,  214, 209, 189, 239, 72,  80,  195, 244, 101, 68,  46,  179, 0,   195, 55,  166,
    72,  166, 192, 219, 221, 115, 252, 149, 245, 194, 196, 81,  133, 154, 254, 128, 212, 10,  163, 157,
    251, 146, 73,  244, 12,  62,  227, 125, 150, 20,  69,  200, 6,   245, 140, 124, 242, 18,  125, 250,
    137, 79,  146, 150, 252, 243, 60,  8,   64,  153, 144, 172, 151, 13,  237, 179, 184, 67,  18,  1,
    129, 233, 55,  97,  7,   219, 218, 246, 197, 243, 200, 100, 151, 238, 33,  155, 1,   221, 146, 241,
    159, 73,  84,  244, 254, 169, 78,  217, 24,  35,  117, 136, 43,  32,  13,  170, 219, 35,  207, 249,
    25,  63,  62,  112, 56,  68,  149, 224, 76,  93,  94,  211, 82,  34,  109, 22,  55,  194, 36,  143,
    29,  60,  204, 68,  5,   221, 46,  161, 250, 250, 180, 191, 28,  70,  150, 77,  148, 112, 134, 32,
    120, 130, 145, 68,  120, 190, 232, 199, 91,  67,  9,   174, 43,  18,  46,  63,  232, 122, 199, 236,
    245, 165, 55,  15,  196, 27,  77,  219, 114, 59,  42,  251, 108, 71,  192, 181, 120, 148, 170, 178,
    197, 193, 69,  183, 151, 221, 185, 18,  110, 92,  202, 32,  49,  18,  16,  95,  103, 100, 20,  250,
    246, 178, 0,   218, 240, 153, 219, 165, 238, 236, 51,  98,  79,  81,  36,  191, 197, 240, 77,  130,
    56,  142, 82,  146, 120, 16,  246, 16,  176, 188, 161, 30,  11,  233, 241, 79,  60,  166, 149, 232,
    122, 83,  17,  102, 12,  118, 40,  205, 186, 159, 94,  239, 185, 144, 34,  239, 83,  123, 89,  106,
    22,  220, 138, 3,   236, 31,  231, 210, 86,  23,  17,  179, 48,  36,  121, 251, 47,  241, 27,  124,
    25,  254, 203, 30,  24,  130, 208, 228, 156, 26,  19,  99,  91,  206, 96,  119, 43,  160, 55,  44,
    82,  38,  109, 8,   225, 183, 249, 216, 192, 67,  6,   157, 229, 114, 59,  71,  159, 247, 44,  134,
    206, 160, 67,  66,  41,  241, 125, 43,  219, 125, 141, 31,  252, 127, 24,  102, 146, 191, 50,  36,
    215, 160, 194, 0,   146, 67,  14,  226, 73,  9,   24,  218, 137, 54,  195, 66,  164, 33,  156, 86,
    70,  134, 254, 165, 146, 17,  32,  14,  14,  62,  25,  66,  182, 223, 132, 8,   118, 219, 64,  185,
    103, 169, 183, 6,   83,  83,  48,  137, 87,  73,  228, 222, 219, 60,  170, 162, 228, 116, 236, 222,
    87,  226, 24,  82,  242, 251, 0,   53,  64,  214, 26,  106, 0,   16,  120, 246, 181, 201, 237, 110,
    103, 141, 102, 155, 182, 123, 187, 180, 127, 31,  253, 205, 178, 73,  73,  122, 250, 195, 19,  48,
    86,  203, 50,  144, 102, 165, 244, 240, 46,  101, 192, 5,   53,  94,  199, 11,  162, 13,  159, 196,
    243, 204, 230, 31,  75,  213, 185, 10,  105, 145, 146, 39,  13,  44,  182, 211, 157, 7,   140, 120,
    36,  19,  45,  153, 179, 106, 247, 47,  61,  122, 175, 216, 201, 1,   199, 193, 91,  106, 164, 197,
    165, 55,  191, 127, 51,  108, 150, 156, 137, 39,  85,  39,  211, 94,  115, 32,  208, 213, 118, 217,
    247, 125, 154, 214, 143, 43,  169, 95,  215, 15,  76,  59,  151, 94,  222, 97,  166, 52,  169, 39,
    31,  248, 70,  37,  163, 96,  239, 196, 117, 244, 51,  0,   99,  80,  57,  47,  171, 77,  188, 53,
    225, 165, 93,  52,  187, 52,  33,  100, 105, 165, 191, 88,  234, 42,  125, 206, 238, 192, 2,   60,
    191, 67,  1,   253, 195, 175, 36,  251, 151, 8,   59,  245, 181, 100, 175, 195, 72,  148, 255, 45,
    56,  151, 208, 172, 32,  221, 25,  112, 215, 121, 138, 37,  74,  138, 49,  244, 221, 92,  197, 125,
    47,  231, 182, 66,  42,  2,   72,  184, 8,   10,  128, 234, 196, 40,  27,  111, 99,  226, 6,   241,
    43,  142, 240, 11,  27,  81,  201, 222, 18,  110, 12,  215, 211, 221, 193, 7,   85,  173, 75,  155,
    97,  216, 39,  189, 110, 201, 215, 97,  138, 71,  240, 186, 146, 1,   63,  86,  234, 39,  37,  195,
    18,  209, 76,  100, 9,   252, 162, 234, 69,  239, 121, 39,  186, 15,  7,   94,  219, 43,  136, 67,
    190, 171, 109, 77,  150, 46,  145, 56,  54,  204, 191, 155, 188, 244, 227, 123, 71,  134, 8,   6,
    197, 68,  121, 246, 28,  4,   7,   108, 214, 119, 120, 157, 28,  122, 19,  197, 177, 10,  152, 225,
    183, 14,  238, 127, 26,  80,  57,  190,
};

const dict_boundary_echo_input = [_]u8{
    52,  63,  189, 141, 199, 193, 154, 85,  39,  229, 28,  108, 199, 50,  153, 191, 209, 70,  233, 179,
    32,  253, 1,   106, 232, 21,  30,  45,  59,  175, 73,  191, 174, 134, 141, 247, 73,  63,  134, 128,
    12,  129, 198, 85,  125, 134, 224, 90,  70,  26,  181, 63,  4,   233, 22,  253, 20,  13,  210, 60,
    211, 226, 113, 56,  32,  47,  21,  34,  235, 155, 35,  139, 61,  207, 156, 132, 232, 152, 153, 0,
    165, 254, 238, 194, 79,  110, 134, 161, 105, 234, 45,  76,  180, 40,  217, 224, 202, 89,  100, 71,
    251, 86,  228, 176, 8,   74,  222, 137, 252, 110, 122, 86,  214, 128, 160, 150, 55,  100, 132, 217,
    183, 135, 249, 44,  59,  56,  172, 49,  52,  145, 91,  25,  196, 88,  171, 133, 51,  209, 168, 49,
    159, 32,  149, 172, 210, 209, 32,  33,  154, 35,  92,  20,  48,  208, 53,  236, 213, 36,  115, 215,
    13,  148, 55,  165, 185, 38,  238, 194, 52,  87,  125, 58,  48,  42,  194, 223, 58,  139, 156, 232,
    219, 20,  107, 68,  195, 92,  98,  166, 36,  71,  156, 27,  238, 156, 226, 130, 145, 85,  131, 233,
    240, 206, 50,  68,  103, 234, 52,  227, 119, 68,  127, 85,  45,  228, 131, 237, 83,  246, 53,  152,
    128, 182, 26,  62,  105, 12,  172, 246, 250, 144, 170, 29,  147, 68,  215, 150, 212, 189, 65,  148,
    99,  16,  0,   249, 81,  159, 213, 144, 215, 236, 167, 7,   81,  253, 0,   247, 238, 191, 22,  116,
    1,   245, 61,  103, 86,  87,  121, 204, 52,  197, 213, 117, 140, 5,   104, 120, 34,  191, 222, 156,
    114, 48,  190, 227, 31,  133, 1,   75,  217, 29,  237, 7,   97,  97,  54,  88,  234, 224, 240, 244,
    148, 38,  12,  238, 104, 10,  227, 103, 33,  174, 102, 51,  189, 45,  88,  112, 202, 1,   17,  219,
    29,  153, 96,  199, 200, 85,  58,  196, 96,  111, 67,  206, 230, 75,  209, 13,  140, 233, 103, 136,
    47,  119, 216, 213, 227, 97,  103, 167, 128, 23,  98,  82,  187, 48,  221, 185, 73,  147, 93,  3,
    76,  217, 53,  3,   238, 166, 40,  249, 77,  188, 3,   29,  189, 244, 135, 231, 168, 211, 87,  201,
    218, 225, 8,   117, 245, 150, 55,  36,  247, 112, 42,  160, 48,  41,  166, 208, 89,  164, 179, 21,
    158, 63,  42,  43,  20,  249, 240, 110, 226, 155, 77,  217, 142, 230, 36,  124, 148, 46,  154, 37,
    192, 149, 211, 49,  183, 14,  238, 127, 26,  80,  57,  190, 52,  63,  189, 141, 199, 193, 154, 85,
    39,  229, 28,  108, 199, 50,  153, 191, 209, 70,  233, 179, 32,  253, 1,   106, 232, 21,  30,  45,
    59,  175, 73,  191, 174, 134, 141, 247, 73,  63,  134, 128, 12,  129, 198, 85,  125, 134, 224, 90,
    70,  26,  181, 63,  4,   233, 22,  253, 20,  13,  210, 60,  211, 226, 113, 56,  32,  47,  21,  34,
    235, 155, 35,  139, 61,  207, 156, 132, 232, 152, 153, 0,   165, 254, 238, 194, 79,  110, 134, 161,
    105, 234, 45,  76,  180, 40,  217, 224, 202, 89,  100, 71,  251, 86,  228, 176, 8,   74,  222, 137,
    252, 110, 122, 86,  214, 128, 160, 150, 55,  100, 132, 217, 183, 135, 249, 44,  59,  56,  172, 49,
    52,  145, 91,  25,  196, 88,  171, 133, 51,  209, 168, 49,  159, 32,  149, 172, 210, 209, 32,  33,
    154, 35,  92,  20,  48,  208, 53,  236, 213, 36,  115, 215, 13,  148, 55,  165, 185, 38,  238, 194,
    52,  87,  125, 58,  48,  42,  194, 223, 58,  139, 156, 232, 219, 20,  107, 68,  195, 92,  98,  166,
    36,  71,  156, 27,  238, 156, 226, 130, 145, 85,  131, 233, 240, 206, 50,  68,  103, 234, 52,  227,
    119, 68,  127, 85,  45,  228, 131, 237, 83,  246, 53,  152, 128, 182, 26,  62,  105, 12,  172, 246,
    250, 144, 170, 29,  147, 68,  215, 150, 212, 189, 65,  148, 99,  16,  0,   249, 81,  159, 213, 144,
    215, 236, 177, 217, 45,  175, 107, 182, 53,  236, 166, 50,
};
const surv_m12_dict = [_]u8{
    25,  25,  25,  104, 104, 104, 104, 104, 104, 104, 104, 104, 104, 104, 104, 104, 104, 104, 104, 104,
    104, 254, 254, 254, 254, 254, 254, 254, 254, 254, 254, 27,  27,  27,  27,  27,  27,  7,   7,   7,
    7,   7,   7,   7,   7,   7,   7,   7,   7,   7,   7,   7,   7,   7,   7,   7,   7,   7,   7,   7,
    7,   7,   7,   7,   7,   7,   164, 164, 164, 164, 164, 164, 164, 164, 164, 164, 164, 164, 164, 164,
    164, 164, 164, 2,   127, 127, 127, 127, 127, 127, 127, 127, 127, 127, 127, 127, 127, 127, 127, 127,
    127, 127, 210, 210, 210, 210, 210, 210, 210, 210, 210, 210, 210, 210, 210, 210, 210, 210, 210, 210,
    210, 210, 210, 210, 210, 210, 210, 210, 54,  54,  54,  54,  54,  54,  54,  54,  54,  54,  54,  54,
    54,  65,  65,  65,  65,  65,  65,  65,  65,  65,  65,  65,  65,  65,  65,  65,  34,  34,  34,  34,
    34,  34,  34,  78,  78,  78,  78,  78,  78,  78,  78,  78,  78,  31,  31,  31,  31,  31,  31,  31,
    31,  31,  253, 253, 253, 253, 135, 135, 135, 135, 135, 135, 135, 135, 135, 135, 135, 135, 135, 135,
    16,  16,  16,  16,  16,  16,  16,  16,  16,  16,  16,  16,  18,  18,  18,  18,  18,  18,  18,  18,
    18,  18,  18,  18,  18,  18,  18,  18,  18,  18,  18,  18,  18,  18,  18,  18,  18,  18,  18,  18,
    146, 146, 234, 234, 234, 234, 234, 234, 234, 234, 234, 234, 234, 234, 234, 234, 234, 234, 234, 234,
    234, 234, 234, 234, 234, 234, 234, 234, 234, 234, 234, 222, 222, 222, 222, 222, 222, 222, 222, 222,
    222, 222, 222, 222, 222, 222, 222, 222, 222, 222, 222, 222, 222, 222, 222, 222, 222, 222, 108, 108,
    108, 108, 108, 108, 108, 108, 108, 108, 108, 108, 108, 108, 108, 108, 108, 108, 108, 192, 192, 192,
    192, 192, 192, 192, 192, 192, 192, 192, 192, 192, 192, 192, 192, 192, 192, 192, 192, 192, 192, 192,
    192, 192, 192, 192, 198, 198, 198, 198, 198, 198, 242, 242, 242, 242, 242, 242, 242, 242, 242, 242,
    242, 242, 242, 242, 242, 242, 242, 242, 242, 242, 242, 242, 62,  62,  62,  62,  62,  62,  62,  62,
    62,  62,  62,  62,  62,  62,  62,  62,  62,  62,  62,  62,  74,  74,  74,  74,  74,  74,  74,  74,
    247, 247, 247, 247, 247, 247, 247, 247, 247, 247, 247, 247, 247, 247, 237, 237, 237, 237, 237, 101,
    101, 101, 101, 101, 101, 101, 101, 101, 101, 101, 101, 101, 101, 101, 101, 101, 101, 101, 101, 101,
    101, 101, 101, 101, 101, 101, 101, 223, 223, 223, 223, 223, 223, 223, 223, 223, 223, 223, 149, 149,
    149, 149, 149, 149, 149, 149, 149, 149, 149, 149, 149, 149, 149, 149, 149, 149, 149, 149, 149, 106,
    106, 106, 106, 106, 106, 106, 106, 106, 106, 106, 106, 106, 106, 106, 106, 106, 106, 76,  76,  76,
    70,  70,  70,  70,  70,  70,  70,  70,  70,  70,  70,  70,  70,  70,  70,  70,  70,  70,  70,  70,
    70,  70,  70,  70,  70,  5,   5,   5,   5,   5,   5,   5,   5,   5,   125, 125, 125, 85,  85,  85,
    85,  85,  85,  85,  85,  85,  85,  85,  85,  85,  85,  85,  85,  85,  59,  59,  59,  59,  59,  59,
    59,  59,  59,  59,  59,  59,  59,  59,  59,  59,  59,  59,  59,  59,  59,  59,  59,  59,  59,  59,
    194, 194, 194, 194, 194, 194, 194, 194, 194, 137, 137, 137, 137, 137, 137, 137, 137, 137, 137, 137,
    137, 137, 137, 137, 137, 137, 137, 137, 137, 137, 137, 137, 137, 137, 137, 137, 137, 10,  10,  10,
    10,  10,  10,  10,  10,  10,  10,  10,  10,  10,  10,  10,  10,  10,  10,  10,  10,  10,  51,  51,
    51,  51,  51,  51,  51,  51,  51,  13,  13,  13,  13,  13,  13,  13,  13,  13,  13,  13,  13,  13,
    230, 230, 230, 230, 230, 230, 230, 230, 230, 230, 230, 230, 230, 230, 230, 230, 230, 230, 230, 230,
    230, 230, 230, 230, 230, 230, 230, 92,  92,  92,  92,  92,  92,  92,  92,  92,  92,  92,  92,  92,
    92,  92,  92,  92,  92,  92,  242, 242, 242, 242, 242, 242, 242, 242, 242, 242, 242, 242, 242, 242,
    242, 105, 105, 105, 105, 105, 105, 105, 105, 105, 105, 105, 105, 105, 105, 105, 105, 105, 105, 105,
    186, 186, 186, 186, 186, 186, 186, 186, 186, 186, 186, 186, 186, 186, 186, 186, 201, 201, 201, 201,
    201, 201, 190, 190, 190, 190, 190, 190, 190, 190, 190, 190, 190, 190, 190, 190, 190, 190, 190, 190,
    190, 190, 190, 190, 121, 121, 121, 121, 121, 121, 121, 121, 121, 121, 23,  165, 165, 165, 165, 165,
    165, 165, 165, 165, 165, 165, 165, 165, 165, 165, 165, 165, 165, 165, 165, 165, 165, 165, 165, 165,
    165, 165, 165, 165, 252, 252, 252, 252, 252, 252, 252, 252, 252, 252, 252, 252, 252, 252, 252, 252,
    252, 252, 252, 252, 252, 252, 252, 252, 86,  86,  86,  86,  86,  86,  86,  86,  86,  86,  86,  86,
    86,  86,  86,  86,  86,  86,  86,  86,  86,  86,  86,  41,  41,  41,  41,  41,  41,  41,  41,  41,
    47,  47,  47,  47,  47,  47,  47,  47,  47,  47,  47,  47,  47,  47,  47,  47,  47,  47,  47,  47,
    47,  47,  47,  47,  47,  47,  47,  47,  47,  153, 153, 153, 153, 153, 153, 153, 153, 153, 153, 153,
    113, 113, 113, 113, 113, 4,   4,   4,   4,   4,   4,   4,   4,   4,   4,   4,   4,   4,   4,   4,
    4,   4,   187, 187, 187, 187, 187, 187, 187, 187, 187, 187, 187, 187, 187, 187, 187, 187, 187, 187,
    187, 187, 187, 187, 187, 187, 67,  67,  67,  67,  67,  67,  67,  67,  67,  67,  67,  67,  67,  67,
    67,  67,  67,  67,  67,  67,  67,  67,  67,  98,  98,  98,  98,  98,  98,  98,  98,  98,  98,  98,
    98,  98,  98,  98,  98,  98,  144, 144, 144, 144, 144, 144, 144, 144, 144, 144, 144, 144, 144, 144,
    144, 144, 138, 138, 138, 138, 138, 138, 138, 138, 138, 138, 138, 138, 138, 138, 138, 138, 138, 138,
    91,  91,  91,  91,  91,  91,  91,  91,  91,  91,  91,  91,  91,  91,  91,  91,  91,  91,  91,  91,
    91,  91,  91,  9,   9,   9,   9,   9,   9,   9,   9,   191, 191, 191, 191, 191, 191, 191, 191, 191,
    191, 191, 191, 191, 54,  54,  54,  54,  54,  54,  54,  54,  57,  57,  57,  57,  57,  57,  57,  57,
    57,  57,  57,  57,  57,  57,  57,  57,  57,  57,  57,  57,  57,  57,  57,  57,  57,  57,  57,  57,
    65,  65,  65,  65,  65,  65,  65,  65,  65,  65,  65,  65,  65,  65,  39,  39,  39,  39,  39,  39,
    39,  39,  39,  39,  39,  39,  39,  39,  39,  39,  39,  39,  39,  39,  39,  142, 142, 142, 142, 142,
    142, 142, 249, 245, 245, 245, 245, 245, 245, 245, 245, 245, 245, 245, 245, 245, 245, 245, 245, 245,
    245, 245, 245, 245, 245, 245, 223, 223, 223, 223, 223, 223, 223, 223, 223, 223, 223, 223, 102, 102,
    102, 102, 102, 102, 102, 102, 102, 102, 102, 102, 102, 102, 102, 102, 102, 102, 102, 102, 102, 102,
    102, 102, 102, 102, 102, 102, 2,   2,   2,   2,   2,   2,   2,   2,   2,   2,   2,   2,   2,   2,
    2,   2,   2,   2,   2,   2,   2,   2,   2,   2,   2,   188, 188, 188, 188, 188, 188, 188, 188, 188,
    188, 188, 188, 188, 188, 188, 188, 188, 188, 188, 188, 188, 188, 188, 188, 188, 188, 188, 71,  71,
    71,  71,  71,  71,  71,  71,  71,  71,  71,  71,  71,  71,  71,  60,  60,  60,  60,  60,  60,  60,
    60,  60,  1,   1,   1,   1,   1,   1,   1,   1,   1,   1,   1,   108, 108, 108, 108, 108, 108, 108,
    108, 108, 108, 108, 108, 47,  47,  47,  47,  88,  88,  88,  88,  88,  88,  88,  88,  88,  88,  88,
    88,  88,  88,  88,  88,  88,  88,  88,  88,  88,  81,  81,  81,  81,  81,  81,  81,  81,  81,  81,
    81,  81,  81,  81,  81,  81,  81,  81,  81,  81,  81,  81,  81,  81,  173, 173, 173, 173, 173, 173,
    173, 173, 173, 173, 173, 173, 173, 173, 173, 173, 173, 173, 173, 173, 173, 173, 173, 173, 173, 89,
    89,  89,  89,  89,  89,  89,  89,  89,  89,  89,  89,  89,  89,  89,  89,  89,  89,  89,  89,  89,
    89,  172, 172, 172, 172, 172, 172, 172, 172, 172, 172, 58,  58,  58,  58,  58,  58,  58,  58,  58,
    58,  58,  58,  58,  58,  58,  58,  58,  58,  58,  58,  58,  100, 254, 254, 254, 237, 237, 237, 237,
    237, 237, 237, 237, 237, 237, 237, 237, 237, 237, 237, 237, 237, 237, 237, 237, 237, 237, 237, 237,
    237, 237, 217, 217, 217, 200, 200, 200, 200, 200, 200, 200, 200, 3,   3,   3,   3,   3,   3,   3,
    3,   3,   3,   3,   3,   3,   3,   3,   3,   3,   3,   3,   3,   3,   3,   3,   3,   235, 235, 235,
    235, 235, 235, 235, 235, 235, 235, 235, 235, 235, 235, 235, 235, 235, 235, 235, 235, 235, 235, 235,
    235, 65,  65,  65,  65,  150, 150, 150, 150, 150, 150, 150, 150, 150, 150, 150, 150, 150, 150, 150,
    150, 150, 150, 150, 150, 150, 150, 150, 150, 150, 150, 90,  90,  90,  90,  90,  90,  90,  90,  90,
    90,  90,  90,  90,  90,  90,  90,  90,  90,  90,  90,  90,  90,  90,  90,  90,  90,  90,  90,  90,
    97,  97,  97,  97,  97,  86,  86,  86,  86,  86,  86,  86,  86,  86,  15,  15,  15,  15,  15,  15,
    15,  15,  15,  15,  15,  15,  15,  15,  15,  15,  95,  95,  95,  95,  95,  95,  95,  95,  95,  95,
    95,  95,  95,  95,  95,  95,  95,  95,  95,  95,  95,  95,  95,  95,  95,  131, 131, 131, 131, 131,
    131, 131, 131, 131, 131, 131, 131, 131, 131, 131, 184, 184, 184, 184, 184, 184, 184, 184, 184, 184,
    184, 184, 184, 184, 244, 244, 244, 244, 244, 244, 244, 244, 244, 244, 244, 244, 244, 244, 244, 244,
    244, 244, 84,  84,  84,  84,  84,  84,  84,  84,  84,  84,  84,  84,  84,  84,  84,  84,  84,  84,
    84,  84,  84,  156, 156, 156, 95,  95,  95,  95,  95,  95,  95,  95,  95,  95,  102, 102, 102, 21,
    21,  21,  21,  21,  21,  21,  21,  21,  21,  21,  97,  97,  97,  97,  97,  97,  97,  97,  97,  97,
    97,  97,  97,  97,  97,  97,  97,  97,  97,  97,  97,  97,  97,  97,  97,  97,  97,  34,  174, 174,
    174, 174, 174, 174, 174, 174, 174, 167, 167, 167, 167, 167, 167, 167, 167, 167, 167, 167, 167, 167,
    167, 167, 167, 167, 167, 167, 167, 167, 167, 215, 215, 215, 215, 215, 215, 215, 215, 215, 215, 215,
    215, 215, 215, 215, 215, 215, 84,  84,  84,  84,  84,  84,  84,  84,  84,  84,  84,  84,  84,  84,
    229, 229, 229, 229, 229, 229, 229, 229, 229, 229, 229, 229, 229, 229, 229, 81,  81,  81,  81,  81,
    81,  81,  81,  81,  81,  81,  81,  81,  81,  81,  81,  81,  45,  45,  49,  49,  49,  49,  49,  49,
    49,  49,  49,  148, 148, 148, 148, 148, 148, 148, 148, 148, 148, 148, 148, 148, 148, 131, 131, 203,
    203, 203, 203, 203, 203, 203, 203, 203, 203, 236, 236, 236, 236, 236, 236, 236, 236, 236, 236, 211,
    211, 211, 211, 211, 211, 211, 211, 211, 211, 211, 211, 211, 211, 35,  35,  35,  35,  35,  35,  35,
    35,  35,  35,  35,  35,  35,  35,  30,  30,  30,  30,  30,  30,  30,  30,  30,  30,  30,  30,  30,
    30,  30,  30,  30,  2,   2,   66,  66,  66,  66,  66,  66,  66,  66,  66,  66,  66,  66,  66,  66,
    66,  66,  66,  66,  66,  66,  66,  66,  66,  66,  66,  66,  66,  141, 141, 141, 141, 141, 141, 141,
    141, 141, 141, 141, 141, 141, 141, 141, 141, 214, 214, 214, 214, 214, 214, 214, 214, 214, 214, 214,
    214, 214, 214, 214, 214, 214, 214, 214, 214, 214, 214, 214, 214, 214, 214, 214, 221, 221, 221, 221,
    148, 148, 148, 148, 148, 148, 148, 148, 148, 194, 194, 194, 194, 194, 194, 194, 194, 194, 194, 194,
    194, 194, 194, 194, 194, 194, 194, 194, 194, 194, 194, 194, 14,  14,  14,  14,  14,  14,  14,  14,
    14,  14,  14,  14,  14,  14,  211, 211, 211, 211, 211, 211, 211, 211, 211, 211, 177, 177, 177, 177,
    177, 177, 177, 177, 177, 177, 177, 177, 177, 177, 177, 177, 177, 177, 177, 177, 177, 177, 177, 61,
    61,  61,  61,  61,  61,  61,  61,  61,  27,  27,  27,  27,  27,  27,  27,  27,  27,  27,  27,  27,
    27,  27,  27,  27,  27,  27,  27,  27,  27,  221, 221, 221, 221, 221, 221, 221, 221, 221, 221, 221,
    221, 221, 221, 221, 221, 221, 221, 221, 221, 221, 21,  21,  21,  21,  21,  21,  21,  21,  21,  21,
    21,  21,  165, 165, 165, 165, 165, 165, 165, 165, 165, 165, 165, 165, 165, 165, 165, 160, 160, 160,
    160, 160, 160, 160, 160, 160, 160, 160, 160, 160, 160, 160, 160, 160, 0,   0,   0,   0,   0,   65,
    65,  65,  65,  65,  65,  65,  65,  65,  65,  65,  65,  171, 171, 171, 171, 171, 171, 171, 171, 171,
    171, 171, 171, 171, 171, 171, 171, 171, 171, 116, 116, 116, 116, 116, 116, 116, 116, 116, 116, 116,
    25,  25,  25,  25,  25,  25,  25,  25,  25,  25,  25,  25,  25,  25,  25,  25,  25,  25,  25,  25,
    25,  25,  25,  25,  25,  25,  25,  25,  25,  198, 198, 198, 198, 198, 198, 198, 198, 198, 198, 198,
    198, 198, 198, 198, 198, 198, 198, 198, 198, 210, 210, 210, 210, 210, 210, 210, 210, 210, 210, 210,
    210, 210, 210, 210, 210, 210, 210, 210, 210, 170, 170, 170, 170, 170, 170, 170, 236, 236, 56,  56,
    56,  56,  56,  149, 149, 149, 149, 149, 149, 149, 149, 149, 149, 149, 149, 149, 128, 128, 128, 16,
    16,  16,  16,  16,  16,  16,  16,  16,  16,  16,  16,  16,  16,  16,  16,  16,  16,  16,  16,  16,
    16,  16,  9,   9,   9,   9,   9,   9,   9,   9,   9,   9,   9,   9,   9,   9,   9,   9,   9,   237,
    237, 237, 237, 237, 237, 237, 237, 237, 237, 237, 237, 237, 237, 237, 237, 237, 237, 237, 237, 237,
    237, 237, 237, 237, 237, 237, 177, 177, 177, 177, 177, 177, 177, 177, 177, 177, 177, 177, 177, 177,
    177, 177, 177, 177, 177, 177, 177, 177, 177, 177, 177, 82,  82,  82,  104, 104, 104, 104, 104, 104,
    104, 104, 104, 104, 104, 104, 104, 104, 104, 104, 104, 104, 104, 104, 104, 104, 104, 104, 104, 38,
    38,  38,  38,  38,  38,  38,  38,  38,  38,  38,  38,  38,  38,  38,  38,  38,  38,  38,  38,  38,
    38,  38,  38,  38,  38,  248, 248, 248, 248, 248, 248, 248, 227, 227, 227, 227, 227, 227, 227, 227,
    227, 227, 227, 227, 227, 227, 227, 227, 227, 227, 227, 227, 227, 227, 227, 227, 227, 157, 157, 157,
    157, 157, 157, 157, 157, 157, 157, 157, 56,  56,  56,  56,  56,  56,  56,  56,  56,  56,  56,  56,
    56,  56,  56,  56,  56,  56,  56,  56,  56,  56,  56,  56,  70,  234, 234, 234, 234, 234, 234, 234,
    234, 234, 234, 234, 234, 234, 234, 234, 234, 234, 234, 234, 234, 234, 234, 234, 234, 234, 234, 234,
    191, 191, 191, 191, 191, 191, 191, 191, 191, 191, 191, 191, 191, 191, 227, 227, 227, 227, 227, 67,
    67,  67,  67,  67,  67,  67,  67,  67,  67,  67,  67,  67,  67,  67,  67,  67,  67,  67,  67,  67,
    67,  67,  146, 249, 249, 249, 249, 249, 249, 249, 80,  80,  80,  80,  80,  80,  80,  80,  80,  80,
    80,  80,  80,  80,  80,  80,  80,  80,  80,  80,  218, 218, 218, 218, 218, 218, 218, 218, 218, 218,
    218, 201, 201, 201, 201, 201, 201, 233, 233, 233, 233, 233, 233, 233, 233, 233, 233, 233, 233, 233,
    233, 233, 233, 233, 233, 233, 233, 74,  74,  74,  74,  74,  74,  74,  74,  74,  74,  74,  74,  74,
    74,  74,  74,  74,  74,  74,  74,  74,  21,  21,  21,  21,  21,  21,  50,  50,  50,  50,  50,  50,
    50,  50,  50,  50,  50,  50,  50,  50,  50,  50,  50,  50,  50,  50,  50,  50,  50,  50,  50,  50,
    50,  126, 126, 126, 126, 126, 126, 126, 126, 126, 126, 126, 126, 65,  65,  65,  65,  65,  65,  65,
    65,  65,  65,  65,  65,  65,  65,  65,  65,  65,  152, 152, 152, 152, 152, 152, 152, 152, 152, 152,
    152, 152, 152, 152, 152, 152, 152, 152, 152, 152, 152, 94,  94,  94,  94,  94,  94,  94,  94,  94,
    94,  94,  94,  94,  94,  94,  63,  106, 106, 106, 106, 106, 106, 106, 193, 193, 193, 193, 193, 193,
    193, 193, 193, 133, 133, 133, 133, 133, 133, 133, 133, 133, 133, 133, 242, 242, 242, 242, 242, 242,
    242, 242, 242, 242, 242, 242, 242, 242, 242, 242, 166, 166, 166, 166, 166, 166, 166, 166, 239, 239,
    239, 239, 239, 239, 239, 239, 239, 239, 239, 239, 239, 239, 239, 239, 239, 239, 239, 239, 239, 239,
    239, 77,  77,  77,  77,  77,  77,  77,  77,  77,  77,  77,  77,  77,  77,  77,  248, 248, 248, 248,
    248, 248, 248, 248, 248, 248, 248, 248, 248, 248, 248, 248, 248, 248, 248, 248, 248, 248, 248, 248,
    248, 248, 248, 248, 248, 177, 177, 177, 177, 177, 177, 177, 177, 177, 177, 177, 177, 177, 177, 177,
    177, 177, 177, 177, 177, 177, 177, 177, 177, 177, 177, 177, 94,  180, 180, 180, 180, 180, 180, 180,
    141, 141, 141, 141, 141, 141, 141, 141, 141, 141, 141, 141, 141, 141, 84,  84,  84,  84,  84,  84,
    84,  84,  84,  84,  84,  84,  84,  84,  84,  84,  30,  30,  30,  30,  30,  30,  30,  30,  30,  30,
    30,  234, 234, 234, 234, 234, 205, 205, 205, 205, 205, 205, 205, 205, 205, 205, 205,
};

const surv_m12_input = [_]u8{
    82,  82,  82,  82,  82,  34,  34,  34,  34,  34,  34,  34,  34,  34,  34,  34,  34,  34,  34,  34,
    34,  34,  87,  87,  87,  87,  87,  87,  87,  87,  87,  87,  87,  87,  87,  87,  87,  87,  87,  87,
    87,  87,  87,  87,  87,  87,  87,  56,  56,  56,  56,  56,  56,  56,  56,  56,  56,  56,  56,  56,
    56,  56,  56,  56,  56,  56,  56,  56,  56,  56,  56,  56,  217, 217, 217, 217, 217, 217, 21,  21,
    21,  21,  21,  21,  21,  21,  21,  21,  21,  21,  1,   1,   1,   227, 227, 227, 227, 227, 227, 227,
    227, 227, 227, 227, 227, 227, 227, 227, 227, 227, 227, 227, 227, 227, 182, 182, 182, 182, 182, 182,
    182, 182, 182, 182, 182, 182, 182, 182, 182, 182, 182, 182, 182, 182, 182, 182, 182, 182, 182, 182,
    250, 250, 250, 250, 250, 250, 250, 250, 250, 250, 250, 250, 250, 250, 250, 250, 250, 250, 250, 250,
    250, 105, 105, 105, 105, 105, 105, 105, 105, 105, 105, 105, 105, 105, 105, 105, 105, 105, 105, 105,
    105, 105, 228, 228, 228, 228, 228, 228, 228, 228, 228, 228, 228, 228, 228, 228, 228, 228, 228, 228,
    228, 171, 171, 171, 171, 171, 171, 171, 171, 171, 171, 171, 171, 171, 171, 171, 62,  62,  166, 166,
    166, 166, 166, 166, 166, 166, 166, 166, 166, 166, 166, 166, 166, 166, 166, 166, 166, 166, 166, 131,
    131, 131, 131, 131, 131, 131, 131, 131, 131, 131, 131, 131, 131, 131, 131, 131, 131, 131, 243, 243,
    243, 243, 243, 243, 243, 243, 243, 243, 243, 243, 243, 243, 243, 243, 243, 243, 243, 233, 233, 233,
    233, 233, 233, 233, 233, 14,  14,  14,  14,  14,  14,  14,  14,  14,  14,  14,  14,  14,  14,  14,
    14,  14,  14,  14,  140, 140, 140, 140, 140, 140, 140, 140, 140, 140, 76,  76,  76,  76,  76,  76,
    76,  76,  76,  76,  76,  76,  76,  144, 144, 144, 144, 144, 144, 144, 144, 144, 144, 144, 144, 144,
    144, 144, 144, 144, 144, 144, 144, 144, 219, 219, 219, 219, 219, 219, 219, 219, 219, 219, 219, 219,
    219, 219, 121, 121, 121, 121, 121, 121, 121, 121, 121, 121, 121, 121, 121, 121, 121, 121, 121, 121,
    121, 121, 121, 27,  27,  27,  27,  27,  27,  9,   9,   9,   9,   9,   9,   9,   9,   9,   9,   9,
    9,   9,   9,   9,   9,   9,   213, 213, 213, 213, 213, 213, 213, 213, 213, 213, 213, 213, 213, 213,
    213, 213, 213, 213, 213, 213, 213, 213, 213, 208, 208, 208, 208, 208, 208, 208, 208, 208, 208, 208,
    208, 127, 127, 127, 127, 127, 127, 127, 127, 127, 127, 127, 127, 127, 127, 127, 127, 127, 127, 127,
    127, 127, 127, 127, 127, 127, 127, 127, 127, 127, 21,  21,  21,  21,  21,  21,  21,  21,  21,  21,
    21,  24,  24,  24,  24,  24,  24,  24,  135, 135, 135, 135, 135, 135, 135, 135, 135, 135, 135, 135,
    135, 135, 225, 225, 225, 225, 225, 225, 225, 225, 225, 225, 225, 225, 225, 225, 225, 225, 225, 225,
    225, 225, 225, 225, 225, 225, 225, 225, 58,  58,  58,  58,  58,  58,  58,  58,  236, 236, 236, 236,
    236, 236, 236, 236, 236, 236, 236, 236, 236, 236, 236, 236, 236, 236, 236, 87,  87,  87,  87,  87,
    87,  87,  87,  87,  87,  87,  87,  87,  87,  87,  87,  87,  87,  87,  87,  87,  87,  87,  87,  87,
    87,  87,  87,  74,  74,  74,  74,  74,  74,  74,  74,  74,  74,  74,  208, 208, 208, 79,  79,  79,
    79,  79,  79,  79,  79,  79,  79,  134, 134, 134, 134, 134, 134, 235, 235, 235, 235, 235, 235, 235,
    235, 235, 235, 235, 235, 235, 235, 225, 225, 225, 133, 133, 133, 133, 133, 133, 133, 133, 133, 133,
    133, 133, 133, 133, 133, 133, 133, 133, 133, 133, 133, 155, 155, 155, 155, 155, 155, 155, 155, 155,
    155, 155, 155, 155, 155, 155, 155, 155, 155, 155, 201, 201, 201, 201, 201, 201, 201, 201, 201, 118,
    118, 118, 118, 118, 118, 232, 232, 232, 232, 232, 232, 232, 232, 232, 232, 232, 232, 232, 232, 232,
    232, 232, 232, 232, 232, 232, 232, 232, 182, 182, 182, 182, 182, 182, 182, 182, 182, 182, 182, 182,
    182, 182, 182, 182, 182, 182, 182, 182, 182, 182, 182, 182, 182, 182, 182, 224, 224, 224, 102, 102,
    102, 102, 102, 102, 102, 102, 102, 102, 102, 67,  67,  67,  67,  67,  67,  67,  67,  67,  67,  67,
    110, 110, 110, 110, 94,  94,  94,  94,  94,  94,  94,  94,  94,  94,  94,  94,  94,  94,  94,  94,
    94,  94,  94,  94,  94,  94,  34,  34,  34,  34,  34,  34,  34,  34,  34,  34,  99,  99,  99,  99,
    99,  99,  99,  99,  99,  99,  99,  99,  99,  99,  99,  99,  99,  202, 202, 197, 197, 197, 197, 197,
    197, 197, 197, 197, 197, 197, 197, 197, 197, 197, 197, 197, 251, 251, 251, 251, 251, 251, 251, 251,
    251, 251, 251, 251, 251, 251, 251, 251, 251, 251, 251, 251, 251, 251, 251, 251, 254, 254, 254, 254,
    254, 254, 254, 254, 254, 254, 254, 254, 254, 254, 254, 254, 254, 97,  97,  97,  97,  97,  97,  97,
    97,  97,  76,  76,  76,  76,  76,  76,  76,  76,  76,  76,  76,  76,  76,  76,  76,  76,  76,  76,
    76,  76,  76,  76,  76,  76,  76,  76,  76,  76,  76,  162, 162, 162, 162, 19,  19,  19,  19,  19,
    19,  19,  19,  19,  19,  19,  19,  19,  19,  19,  19,  19,  19,  19,  19,  19,  143, 143, 143, 186,
    186, 186, 186, 186, 186, 186, 186, 186, 186, 186, 186, 186, 186, 186, 186, 186, 136, 136, 136, 136,
    136, 136, 55,  55,  55,  55,  55,  55,  55,  55,  55,  55,  55,  55,  55,  55,  55,  55,  55,  63,
    63,  63,  63,  63,  63,  63,  63,  63,  63,  63,  63,  213, 213, 213, 213, 213, 213, 213, 213, 213,
    213, 213, 213, 235, 235, 235, 235, 235, 235, 235, 235, 235, 235, 235, 235, 235, 189, 189, 189, 189,
    189, 189, 189, 189, 189, 189, 189, 189, 189, 189, 189, 107, 107, 107, 107, 107, 107, 107, 107, 107,
    107, 107, 59,  59,  75,  75,  75,  75,  75,  75,  75,  75,  75,  75,  75,  75,  75,  75,  75,  75,
    75,  75,  75,  75,  123, 123, 123, 123, 123, 123, 123, 123, 123, 123, 123, 123, 123, 123, 123, 203,
    203, 131, 131, 131, 131, 131, 131, 131, 131, 131, 99,  99,  99,  99,  99,  99,  99,  99,  99,  99,
    99,  99,  99,  99,  99,  99,  99,  99,  99,  183, 183, 183, 183, 183, 183, 183, 183, 183, 183, 183,
    183, 183, 183, 183, 183, 183, 24,  24,  24,  24,  24,  24,  24,  24,  24,  24,  24,  24,  24,  24,
    24,  24,  24,  57,  57,  57,  57,  57,  57,  57,  57,  57,  57,  57,  57,  57,  57,  57,  57,  57,
    57,  57,  57,  57,  57,  57,  42,  42,  42,  42,  229, 229, 229, 229, 229, 229, 229, 229, 229, 229,
    229, 229, 229, 241, 241, 241, 241, 241, 241, 241, 241, 241, 241, 241, 241, 241, 241, 241, 241, 241,
    241, 241, 241, 241, 241, 173, 173, 173, 173, 173, 173, 173, 173, 173, 173, 173, 173, 173, 173, 173,
    174, 174, 174, 174, 174, 174, 174, 174, 174, 174, 221, 221, 221, 221, 221, 221, 221, 221, 221, 221,
    221, 221, 221, 221, 221, 221, 221, 218, 218, 218, 218, 218, 218, 218, 218, 218, 218, 218, 218, 218,
    218, 218, 218, 218, 218, 218, 218, 218, 218, 218, 218, 218, 247, 247, 247, 247, 247, 247, 247, 247,
    247, 247, 247, 247, 247, 247, 123, 123, 123, 123, 123, 123, 123, 123, 123, 123, 123, 123, 123, 123,
    123, 123, 123, 123, 123, 123, 123, 123, 123, 123, 123, 123, 245, 245, 245, 245, 245, 245, 245, 245,
    245, 245, 237, 237, 237, 167, 167, 167, 167, 167, 167, 167, 167, 167, 153, 153, 153, 153, 153, 153,
    153, 153, 153, 153, 153, 153, 153, 153, 153, 153, 153, 153, 153, 153, 153, 153, 246, 246, 246, 246,
    246, 246, 246, 29,  29,  29,  29,  29,  29,  29,  29,  29,  29,  29,  29,  29,  29,  29,  29,  29,
    29,  29,  29,  29,  29,  29,  29,  29,  29,  29,  29,  101, 101, 101, 101, 101, 101, 101, 77,  77,
    77,  77,  77,  77,  77,  77,  77,  77,  77,  77,  77,  77,  77,  77,  77,  77,  77,  77,  77,  77,
    77,  77,  77,  77,  77,  77,  1,   1,   1,   1,   1,   1,   1,   1,   1,   1,   1,   1,   1,   1,
    1,   1,   1,   1,   1,   1,   1,   1,   1,   1,   1,   200, 200, 200, 200, 200, 200, 200, 200, 200,
    200, 200, 200, 200, 200, 200, 200, 200, 104, 104, 104, 104, 104, 104, 104, 104, 104, 104, 104, 104,
    104, 104, 145, 145, 145, 145, 145, 145, 145, 145, 145, 145, 145, 145, 145, 145, 145, 145, 145, 145,
    145, 145, 145, 145, 145, 145, 145, 145, 145, 145, 76,  76,  144, 144, 144, 144, 144, 144, 58,  58,
    58,  58,  58,  58,  58,  58,  58,  58,  58,  58,  58,  100, 100, 100, 100, 100, 100, 100, 100, 100,
    100, 100, 100, 100, 100, 100, 100, 100, 100, 100, 100, 100, 100, 100, 100, 100, 100, 100, 100, 142,
    142, 181, 181, 181, 181, 181, 181, 181, 181, 181, 181, 181, 181, 181, 181, 181, 181, 181, 181, 181,
    181, 181, 181, 181, 181, 181, 181, 181, 181, 224, 224, 224, 224, 224, 224, 224, 224, 224, 224, 224,
    224, 224, 224, 224, 224, 224, 224, 224, 224, 224, 224, 224, 224, 224, 224, 224, 224, 156, 156, 156,
    156, 82,  82,  82,  82,  82,  82,  82,  82,  82,  82,  82,  82,  82,  82,  82,  82,  82,  82,  82,
    82,  82,  82,  82,  82,  82,  82,  13,  13,  13,  13,  13,  13,  13,  13,  13,  13,  13,  13,  13,
    13,  13,  13,  13,  13,  13,  13,  13,  13,  13,  13,  13,  13,  13,  13,  13,  117, 117, 117, 117,
    117, 117, 117, 117, 117, 117, 117, 177,
};

const surv_m17_dict = [_]u8{
    154, 154, 154, 154, 154, 154, 154, 187, 187, 187, 112, 112, 112, 112, 112, 112, 112, 112, 112, 112,
    112, 112, 112, 112, 112, 112, 112, 112, 112, 112, 112, 112, 112, 112, 112, 82,  82,  82,  82,  82,
    82,  82,  82,  82,  82,  82,  82,  82,  82,  82,  155, 155, 155, 155, 123, 123, 123, 123, 123, 123,
    123, 123, 123, 123, 123, 123, 123, 123, 123, 203, 203, 203, 203, 203, 203, 203, 203, 203, 203, 203,
    203, 203, 203, 203, 203, 203, 203, 72,  72,  72,  72,  72,  72,  72,  72,  72,  72,  72,  72,  72,
    168, 168, 168, 168, 168, 168, 168, 168, 168, 168, 168, 168, 168, 168, 168, 168, 168, 168, 168, 168,
    168, 168, 168, 168, 168, 241, 241, 241, 241, 241, 241, 241, 241, 241, 198, 198, 198, 61,  61,  61,
    61,  61,  61,  61,  61,  61,  61,  61,  61,  61,  61,  61,  61,  61,  61,  61,  61,  61,  61,  61,
    61,  61,  61,  231, 231, 231, 231, 231, 231, 231, 231, 231, 231, 231, 231, 231, 231, 231, 231, 231,
    41,  41,  41,  41,  41,  41,  41,  41,  41,  41,  41,  41,  41,  41,  41,  41,  41,  41,  41,  41,
    252, 252, 252, 252, 252, 252, 252, 252, 252, 252, 252, 252, 252, 252, 252, 252, 252, 144, 144, 144,
    144, 144, 144, 144, 144, 144, 144, 144, 144, 144, 144, 144, 144, 144, 144, 144, 144, 144, 144, 144,
    144, 144, 144, 144, 144, 144, 20,  20,  20,  20,  20,  20,  20,  20,  20,  20,  20,  20,  161, 161,
    161, 161, 161, 161, 161, 161, 161, 161, 161, 161, 161, 161, 161, 161, 161, 161, 223, 223, 223, 223,
    223, 223, 223, 223, 223, 223, 223, 223, 223, 188, 188, 188, 188, 188, 36,  36,  36,  36,  36,  36,
    36,  36,  36,  36,  36,  36,  36,  42,  42,  42,  42,  42,  42,  42,  42,  42,  42,  42,  42,  42,
    42,  42,  11,  11,  11,  11,  11,  11,  11,  11,  11,  11,  11,  11,  11,  11,  11,  11,  11,  11,
    11,  11,  100, 243, 243, 243, 243, 243, 243, 243, 243, 243, 243, 243, 243, 243, 243, 243, 243, 243,
    243, 243, 243, 243, 243, 243, 243, 243, 243, 243, 243, 153, 153, 153, 153, 153, 153, 153, 153, 153,
    153, 153, 153, 153, 153, 248, 248, 248, 248, 248, 248, 248, 248, 248, 248, 248, 248, 104, 104, 104,
    104, 104, 104, 104, 104, 104, 104, 104, 104, 104, 104, 104, 104, 104, 104, 104, 104, 115, 184, 184,
    184, 184, 184, 184, 184, 184, 184, 184, 184, 184, 184, 184, 184, 184, 184, 184, 184, 184, 52,  52,
    52,  52,  52,  52,  52,  52,  52,  52,  52,  52,  52,  52,  52,  170, 170, 170, 170, 170, 170, 170,
    170, 170, 170, 170, 170, 170, 170, 170, 170, 51,  51,  51,  51,  51,  51,  51,  51,  51,  51,  51,
    51,  51,  51,  51,  51,  51,  51,  51,  51,  126, 126, 126, 126, 126, 126, 126, 126, 126, 126, 126,
    126, 126, 126, 126, 126, 126, 126, 126, 126, 126, 126, 126, 126, 126, 126, 126, 227, 227, 54,  54,
    54,  54,  54,  54,  54,  54,  54,  54,  54,  54,  54,  54,  54,  54,  54,  54,  54,  54,  54,  188,
    188, 188, 188, 188, 188, 188, 188, 188, 188, 188, 188, 188, 188, 188, 188, 188, 188, 188, 188, 188,
    188, 188, 188, 188, 47,  47,  47,  47,  47,  47,  47,  47,  47,  47,  47,  47,  47,  47,  47,  47,
    47,  47,  47,  47,  47,  47,  47,  47,  47,  47,  149, 149, 149, 149, 149, 149, 149, 149, 149, 149,
    149, 149, 149, 149, 149, 149, 149, 149, 149, 149, 149, 149, 149, 149, 122, 122, 122, 122, 122, 122,
    122, 122, 122, 205, 205, 205, 205, 205, 205, 205, 205, 205, 205, 205, 205, 205, 205, 205, 205, 205,
    205, 205, 205, 205, 205, 205, 205, 205, 205, 205, 205, 124, 124, 124, 124, 124, 124, 124, 124, 124,
    124, 124, 124, 124, 124, 124, 124, 124, 124, 124, 124, 124, 124, 124, 124, 124, 124, 86,  86,  86,
    86,  86,  86,  86,  94,  94,  94,  94,  94,  94,  94,  94,  94,  94,  94,  94,  94,  94,  94,  94,
    94,  94,  94,  94,  94,  94,  94,  194, 194, 194, 194, 194, 194, 194, 194, 194, 194, 194, 194, 194,
    194, 194, 194, 194, 194, 194, 194, 194, 194, 194, 174, 174, 174, 174, 174, 174, 174, 174, 174, 174,
    174, 174, 89,  89,  89,  89,  89,  89,  89,  89,  89,  89,  89,  89,  89,  89,  89,  89,  166, 166,
    166, 166, 166, 166, 166, 166, 166, 166, 166, 166, 166, 203, 203, 55,  55,  55,  55,  55,  55,  55,
    55,  55,  55,  55,  55,  55,  55,  55,  55,  55,  55,  55,  55,  55,  55,  55,  55,  55,  55,  55,
    55,  55,  212, 212, 212, 212, 212, 212, 212, 212, 212, 212, 212, 212, 212, 212, 212, 212, 212, 87,
    87,  87,  87,  87,  87,  87,  87,  87,  87,  87,  87,  87,  87,  87,  87,  87,  87,  87,  87,  87,
    26,  26,  26,  26,  26,  26,  26,  26,  26,  26,  26,  26,  26,  26,  26,  26,  26,  26,  26,  26,
    26,  26,  26,  26,  26,  26,  26,  26,  92,  92,  92,  92,  92,  92,  92,  92,  92,  92,  92,  92,
    92,  92,  92,  92,  94,  94,  94,  94,  94,  94,  94,  94,  94,  94,  94,  94,  94,  94,  74,  74,
    74,  74,  74,  74,  74,  74,  74,  74,  74,  74,  74,  74,  74,  74,  74,  45,  45,  45,  45,  51,
    51,  51,  51,  51,  51,  51,  51,  51,  51,  51,  51,  22,  22,  22,  22,  22,  22,  229, 229, 229,
    229, 229, 229, 229, 229, 229, 229, 229, 229, 229, 229, 229, 229, 229, 229, 229, 229, 229, 229, 207,
    207, 207, 207, 207, 207, 207, 207, 207, 207, 207, 207, 207, 207, 207, 207, 207, 207, 207, 207, 207,
    207, 177, 177, 177, 177, 177, 177, 177, 177, 177, 177, 177, 177, 177, 177, 177, 177, 177, 177, 177,
    177, 177, 177, 177, 177, 177, 177, 177, 36,  36,  36,  36,  36,  36,  36,  36,  36,  36,  36,  36,
    36,  36,  36,  36,  36,  36,  36,  36,  36,  36,  36,  36,  36,  36,  36,  36,  45,  45,  45,  45,
    45,  45,  45,  45,  45,  45,  47,  47,  47,  47,  47,  47,  47,  47,  47,  47,  47,  47,  47,  47,
    47,  47,  47,  47,  47,  47,  47,  47,  147, 147, 147, 147, 147, 147, 147, 147, 147, 147, 147, 147,
    147, 147, 147, 115, 115, 115, 115, 115, 115, 115, 115, 8,   8,   8,   8,   8,   8,   8,   8,   8,
    8,   8,   8,   8,   8,   8,   8,   8,   8,   8,   179, 179, 4,   4,   144, 144, 144, 144, 144, 144,
    189, 189, 189, 189, 189, 189, 189, 189, 189, 189, 189, 189, 189, 189, 189, 189, 189, 189, 189, 189,
    189, 189, 189, 189, 61,  61,  61,  61,  61,  61,  61,  61,  61,  61,  61,  61,  61,  61,  61,  61,
    61,  61,  61,  61,  61,  61,  61,  61,  61,  61,  61,  250, 250, 250, 250, 250, 250, 250, 250, 250,
    250, 250, 250, 250, 250, 250, 250, 250, 250, 250, 250, 149, 149, 149, 149, 149, 149, 149, 149, 149,
    149, 149, 149, 149, 149, 149, 174, 174, 240, 240, 240, 240, 240, 240, 19,  19,  19,  19,  19,  19,
    19,  19,  19,  19,  19,  19,  19,  19,  19,  19,  19,  19,  19,  19,  19,  19,  19,  51,  51,  51,
    51,  51,  51,  51,  24,  24,  24,  24,  24,  24,  24,  24,  24,  24,  24,  24,  24,  24,  24,  24,
    24,  24,  24,  24,  24,  44,  44,  44,  44,  44,  44,  44,  44,  44,  44,  44,  44,  44,  44,  44,
    11,  11,  11,  11,  100, 100, 100, 100, 100, 100, 100, 100, 100, 100, 100, 204, 204, 204, 204, 204,
    204, 204, 204, 204, 204, 204, 137, 137, 137, 137, 137, 137, 137, 137, 137, 1,   1,   1,   1,   1,
    1,   1,   1,   1,   1,   54,  54,  54,  54,  54,  54,  54,  54,  54,  54,  179, 179, 179, 179, 179,
    179, 179, 179, 179, 179, 179, 179, 179, 179, 179, 179, 179, 179, 179, 179, 179, 179, 185, 185, 185,
    185, 185, 185, 185, 185, 185, 185, 185, 185, 185, 211, 211, 211, 211, 211, 211, 211, 211, 211, 211,
    211, 211, 211, 211, 211, 211, 211, 211, 211, 211, 211, 211, 211, 99,  99,  99,  99,  99,  99,  99,
    99,  99,  99,  99,  99,  99,  99,  99,  99,  99,  99,  99,  99,  99,  99,  164, 164, 164, 164, 164,
    164, 164, 164, 164, 164, 164, 240, 240, 240, 240, 240, 117, 117, 117, 117, 117, 117, 117, 117, 117,
    117, 181, 181, 181, 181, 181, 181, 181, 181, 181, 181, 84,  39,  39,  39,  39,  39,  39,  39,  39,
    39,  39,  39,  134, 134, 134, 134, 134, 134, 134, 134, 134, 134, 134, 134, 134, 134, 134, 134, 134,
    134, 134, 134, 134, 134, 134, 134, 134, 134, 69,  69,  69,  69,  69,  69,  69,  69,  190, 190, 190,
    190, 190, 190, 190, 190, 190, 190, 190, 190, 13,  13,  13,  13,  13,  13,  13,  13,  13,  13,  13,
    13,  13,  13,  13,  13,  13,  13,  13,  13,  13,  13,  13,  65,  65,  65,  65,  65,  65,  65,  228,
    228, 228, 228, 228, 228, 228, 228, 228, 228, 178, 178, 178, 178, 178, 178, 178, 178, 178, 178, 178,
    178, 178, 178, 178, 178, 178, 178, 178, 178, 178, 122, 122, 122, 122, 122, 122, 122, 122, 122, 122,
    122, 122, 122, 122, 122, 49,  49,  49,  49,  207, 207, 207, 207, 207, 207, 207, 207, 27,  27,  27,
    27,  27,  27,  27,  27,  27,  27,  27,  27,  27,  27,  27,  27,  27,  27,  27,  27,  27,  27,  27,
    27,  3,   3,   3,   3,   3,   3,   3,   3,   3,   3,   3,   3,   3,   3,   3,   3,   3,   3,   3,
    3,   199, 199, 199, 199, 89,  89,  89,  89,  89,  89,  89,  89,  89,  89,  89,  89,  89,  89,  220,
    220, 220, 220, 220, 220, 220, 220, 220, 220, 220, 220, 220, 220, 220, 220, 220, 220, 220, 220, 220,
    220, 220, 220, 4,   4,   4,   4,   4,   4,   4,   4,   4,   203, 203, 203, 203, 203, 203, 203, 203,
    126, 126, 126, 126, 126, 126, 126, 126, 126, 126, 126, 126, 126, 126, 126, 126, 126, 126, 126, 145,
    145, 145, 145, 145, 145, 145, 145, 145, 145, 36,  36,  36,  36,  36,  36,  36,  36,  36,  36,  36,
    36,  36,  36,  36,  36,  36,  36,  36,  36,  36,  36,  36,  36,  36,  36,  107, 107, 107, 107, 107,
    107, 107, 107, 107, 107, 107, 107, 107, 107, 107, 107, 107, 85,  85,  85,  85,  85,  85,  85,  85,
    85,  85,  85,  85,  85,  85,  85,  85,  85,  85,  85,  85,  234, 234, 234, 234, 234, 234, 234, 234,
    234, 234, 234, 234, 234, 234, 234, 234, 234, 234, 46,  46,  46,  46,  46,  159, 159, 159, 159, 159,
    159, 159, 159, 159, 159, 159, 48,  48,  48,  48,  48,  48,  248, 248, 248, 248, 248, 248, 248, 248,
    248, 248, 248, 248, 248, 248, 248, 248, 248, 109, 109, 150, 150, 150, 150, 150, 150, 150, 150, 150,
    150, 150, 150, 150, 150, 150, 150, 150, 150, 150, 150, 150, 150, 150, 150, 150, 240, 240, 240, 240,
    240, 240, 240, 240, 240, 240, 240, 240, 240, 41,  41,  41,  41,  41,  41,  23,  23,  23,  23,  23,
    23,  23,  23,  23,  23,  23,  23,  23,  23,  23,  23,  23,  23,  23,  23,  23,  23,  23,  23,  23,
    152, 86,  86,  86,  86,  86,  86,  86,  86,  86,  86,  86,  86,  86,  86,  86,  86,  86,  86,  86,
    86,  86,  86,  86,  86,  86,  86,  86,  86,  157, 157, 50,  50,  50,  50,  50,  50,  50,  50,  50,
    50,  50,  50,  50,  50,  50,  50,  50,  50,  50,  50,  50,  50,  50,  50,  50,  50,  50,  252, 252,
    252, 252, 252, 252, 252, 252, 252, 252, 252, 252, 252, 252, 252, 252, 252, 252, 252, 252, 252, 252,
    252, 167, 167, 167, 167, 167, 167, 167, 167, 217, 217, 217, 217, 217, 217, 217, 217, 217, 217, 217,
    224, 224, 224, 224, 224, 224, 224, 224, 224, 224, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255,
    255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 30,  30,
    30,  30,  30,  30,  30,  30,  30,  30,  30,  30,  30,  30,  30,  30,  30,  243, 243, 243, 87,  87,
    87,  87,  227, 227, 227, 227, 227, 227, 227, 227, 227, 227, 227, 227, 227, 227, 227, 227, 227,
};

const surv_m17_input = [_]u8{
    154, 154, 154, 88,  88,  88,  88,  88,  88,  88,  88,  88,  88,  88,  88,  88,  88,  88,  88,  88,
    88,  88,  88,  88,  88,  159, 159, 159, 159, 159, 159, 159, 159, 159, 159, 159, 159, 69,  156, 156,
    156, 156, 156, 156, 156, 156, 156, 156, 156, 156, 156, 180, 180, 180, 180, 180, 180, 180, 180, 180,
    180, 180, 180, 180, 180, 180, 180, 180, 180, 180, 180, 180, 180, 149, 149, 149, 149, 149, 149, 149,
    149, 149, 149, 149, 149, 149, 149, 218, 218, 218, 218, 218, 218, 218, 218, 218, 218, 218, 218, 218,
    218, 218, 218, 218, 218, 218, 218, 218, 15,  15,  15,  15,  15,  15,  15,  15,  15,  15,  15,  15,
    15,  15,  15,  59,  59,  59,  59,  59,  59,  140, 140, 140, 140, 140, 140, 140, 140, 140, 140, 140,
    140, 140, 140, 140, 140, 140, 140, 140, 140, 140, 140, 140, 140, 133, 133, 133, 133, 133, 133, 133,
    133, 133, 234, 234, 234, 234, 234, 234, 234, 234, 234, 129, 129, 129, 129, 129, 129, 129, 129, 129,
    129, 129, 129, 129, 129, 129, 129, 129, 129, 129, 129, 129, 129, 129, 109, 109, 109, 109, 109, 109,
    109, 109, 109, 109, 109, 109, 109, 109, 109, 109, 109, 109, 109, 109, 109, 109, 109, 109, 109, 109,
    109, 142, 142, 142, 142, 142, 142, 142, 142, 142, 142, 142, 142, 142, 142, 142, 142, 142, 142, 142,
    142, 142, 142, 142, 142, 216, 216, 216, 216, 216, 216, 216, 216, 216, 216, 216, 216, 216, 216, 216,
    216, 216, 216, 216, 216, 216, 216, 216, 216, 216, 110, 110, 110, 110, 110, 110, 110, 110, 110, 110,
    110, 110, 110, 110, 110, 110, 110, 110, 110, 110, 68,  68,  68,  68,  68,  68,  68,  68,  108, 108,
    108, 108, 108, 108, 185, 185, 185, 185, 185, 185, 185, 185, 185, 185, 185, 185, 185, 185, 185, 185,
    185, 185, 185, 185, 185, 185, 185, 185, 146, 146, 146, 146, 146, 146, 146, 146, 146, 146, 146, 146,
    146, 146, 75,  75,  75,  75,  75,  75,  75,  75,  75,  75,  60,  60,  60,  60,  60,  60,  60,  60,
    60,  60,  48,  48,  48,  48,  48,  48,  48,  48,  48,  48,  48,  48,  48,  24,  24,  24,  24,  24,
    24,  24,  24,  24,  24,  24,  24,  24,  24,  24,  24,  24,  24,  24,  24,  24,  24,  24,  35,  35,
    35,  35,  35,  126, 126, 126, 126, 126, 126, 126, 126, 126, 126, 126, 24,  24,  24,  138, 138, 138,
    138, 138, 38,  38,  38,  38,  245, 245, 245, 245, 245, 245, 245, 245, 245,
};

const surv_m22_dict = [_]u8{
    186, 186, 186, 186, 186, 186, 186, 186, 186, 186, 186, 186, 186, 186, 186, 186, 186, 186, 186, 186,
    186, 186, 186, 114, 114, 114, 114, 114, 114, 114, 114, 114, 114, 114, 114, 114, 114, 114, 34,  34,
    34,  34,  34,  34,  34,  34,  34,  34,  34,  34,  34,  34,  34,  34,  34,  34,  34,  34,  34,  34,
    34,  34,  118, 118, 118, 118, 118, 118, 111, 111, 111, 111, 111, 111, 111, 111, 111, 111, 111, 111,
    111, 111, 111, 111, 111, 111, 111, 111, 111, 179, 179, 179, 179, 179, 179, 179, 179, 179, 179, 179,
    179, 179, 179, 179, 179, 179, 179, 179, 179, 179, 179, 179, 179, 179, 179, 179, 18,  18,  18,  18,
    18,  18,  18,  18,  18,  18,  18,  18,  18,  18,  18,  18,  18,  18,  18,  18,  18,  18,  138, 138,
    138, 138, 138, 138, 138, 138, 138, 138, 138, 138, 138, 138, 138, 138, 138, 138, 138, 138, 138, 7,
    7,   7,   7,   7,   7,   7,   65,  65,  65,  65,  65,  65,  65,  65,  65,  65,  65,  65,  65,  65,
    65,  65,  65,  65,  65,  134, 134, 134, 134, 134, 134, 131, 131, 131, 131, 131, 131, 131, 131, 131,
    131, 131, 131, 131, 131, 131, 131, 131, 131, 131, 131, 131, 131, 131, 131, 128, 128, 128, 128, 128,
    128, 128, 128, 128, 128, 128, 128, 128, 128, 128, 128, 128, 128, 128, 128, 128, 128, 128, 128, 70,
    70,  70,  70,  70,  70,  253, 253, 253, 253, 253, 253, 253, 253, 253, 253, 253, 253, 253, 253, 253,
    253, 253, 253, 253, 207, 207, 207, 207, 207, 207, 207, 207, 207, 207, 207, 207, 207, 207, 207, 207,
    207, 207, 207, 42,  42,  42,  42,  42,  42,  42,  42,  42,  42,  42,  42,  42,  42,  42,  42,  42,
    42,  42,  42,  42,  42,  42,  42,  42,  212, 101, 101, 101, 101, 101, 101, 101, 101, 101, 101, 101,
    101, 101, 101, 101, 101, 101, 101, 101, 101, 101, 101, 101, 101, 101, 17,  17,  17,  17,  17,  17,
    17,  17,  17,  17,  17,  17,  17,  17,  17,  17,  17,  17,  17,  17,  17,  17,  126, 126, 126, 126,
    126, 126, 126, 126, 126, 126, 126, 126, 126, 126, 126, 234, 234, 234, 234, 234, 234, 234, 234, 234,
    234, 234, 62,  62,  62,  62,  62,  235, 235, 235, 40,  40,  40,  40,  40,  40,  40,  40,  40,  40,
    40,  40,  40,  40,  40,  110, 110, 110, 110, 110, 110, 110, 110, 110, 110, 110, 110, 110, 110, 110,
    110, 110, 110, 110, 110, 110, 110, 110, 12,  12,  12,  12,  12,  12,  12,  12,  12,  12,  12,  12,
    12,  12,  12,  12,  12,  12,  12,  12,  12,  12,  12,  12,  12,  12,  12,  250, 250, 250, 250, 250,
    250, 250, 250, 250, 250, 250, 250, 250, 250, 250, 250, 250, 250, 250, 250, 250, 250, 250, 95,  95,
    95,  95,  95,  95,  95,  95,  95,  95,  95,  95,  95,  95,  95,  95,  95,  95,  95,  95,  95,  46,
    46,  46,  46,  46,  46,  46,  46,  46,  46,  46,  46,  46,  46,  46,  46,  46,  46,  46,  46,  46,
    46,  46,  46,  46,  46,  46,  46,  46,  193, 193, 193, 193, 193, 193, 193, 193, 193, 193, 193, 76,
    76,  76,  76,  131, 131, 131, 131, 131, 131, 131, 131, 131, 131, 131, 131, 131, 131, 131, 131, 131,
    131, 106, 106, 106, 106, 106, 106, 106, 106, 106, 106, 106, 106, 156, 156, 156, 156, 156, 156, 156,
    156, 156, 156, 156, 156, 156, 156, 156, 156, 156, 156, 156, 156, 208, 208, 208, 208, 208, 208, 208,
    208, 208, 208, 208, 208, 208, 208, 208, 208, 208, 208, 208, 208, 208, 208, 208, 208, 208, 208, 48,
    48,  48,  48,  48,  48,  48,  48,  48,  48,  48,  48,  48,  48,  48,  48,  48,  48,  48,  48,  48,
    48,  25,  25,  25,  152, 152, 152, 152, 152, 152, 152, 152, 152, 151, 151, 151, 151, 151, 151, 151,
    151, 151, 151, 151, 151, 151, 151, 151, 151, 151, 151, 151, 73,  73,  73,  73,  73,  73,  73,  73,
    73,  73,  73,  73,  73,  73,  73,  73,  73,  73,  73,  73,  73,  73,  73,  141, 141, 141, 141, 141,
    141, 141, 141, 141, 141, 141, 141, 141, 141, 141, 141, 141, 141, 141, 141, 141, 141, 141, 141, 141,
    141, 141, 141, 141, 141, 141, 141, 141, 141, 141, 141, 141, 141, 141, 141, 141, 141, 174, 174, 174,
    174, 174, 174, 174, 174, 174, 174, 174, 174, 174, 174, 174, 174, 174, 65,  65,  65,  65,  65,  65,
    65,  65,  65,  65,  65,  65,  65,  65,  65,  65,  65,  65,  65,  65,  65,  65,  201, 201, 201, 201,
    201, 201, 201, 201, 201, 201, 201, 201, 201, 201, 201, 201, 201, 201, 201, 201, 201, 201, 201, 86,
    86,  116, 116, 116, 116, 116, 116, 116, 116, 116, 116, 116, 116, 116, 116, 116, 116, 116, 116, 116,
    116, 116, 116, 116, 116, 116, 29,  29,  29,  213, 213, 213, 213, 213, 213, 213, 213, 188, 188, 188,
    135, 135, 135, 135, 135, 135, 135, 135, 135, 135, 135, 135, 135, 135, 135, 135, 135, 135, 135, 135,
    135, 135, 135, 135, 135, 135, 135, 135, 235, 235, 235, 235, 235, 235, 235, 235, 235, 235, 235, 235,
    235, 235, 235, 235, 235, 235, 235, 235, 235, 235, 235, 235, 235, 235, 235, 253, 253, 253, 253, 253,
    253, 253, 253, 253, 253, 253, 253, 253, 253, 253, 253, 253, 253, 213, 213, 143, 111, 111, 111, 111,
    111, 111, 111, 111, 111, 111, 111, 111, 111, 111, 111, 111, 111, 111, 111, 111, 111, 111, 111, 111,
    111, 111, 111, 111, 49,  49,  49,  49,  49,  49,  49,  49,  49,  49,  49,  49,  49,  49,  49,  49,
    49,  49,  49,  49,  49,  49,  49,  49,  49,  49,  49,  9,   9,   9,   9,   9,   9,   9,   9,   86,
    86,  86,  86,  86,  86,  86,  86,  86,  86,  86,  86,  86,  86,  86,  86,  86,  86,  86,  86,  86,
    86,  86,  86,  217, 18,  18,  18,  18,  18,  18,  94,  94,  94,  94,  94,  94,  94,  94,  94,  94,
    94,  94,  118, 118, 118, 118, 118, 118, 118, 118, 118, 118, 118, 118, 118, 118, 118, 118, 118, 118,
    118, 118, 118, 118, 12,  12,  12,  12,  12,  12,  12,  12,  12,  12,  12,  111, 111, 111, 111, 111,
    111, 111, 191, 191, 191, 191, 191, 191, 191, 191, 191, 191, 191, 191, 191, 57,  57,  57,  57,  57,
    57,  57,  57,  57,  57,  57,  57,  57,  57,  57,  57,  139, 139, 139, 139, 139, 139, 139, 139, 128,
    128, 128, 128, 128, 128, 128, 128, 128, 128, 128, 128, 128, 128, 128, 128, 128, 128, 128, 128, 128,
    128, 128, 128, 128, 128, 47,  47,  47,  47,  47,  47,  47,  47,  180, 180, 180, 180, 180, 180, 180,
    180, 180, 180, 180, 180, 180, 180, 34,  34,  34,  34,  34,  34,  34,  159, 159, 159, 159, 159, 159,
    159, 159, 159, 159, 159, 159, 159, 159, 159, 159, 159, 159, 46,  46,  46,  46,  46,  46,  46,  46,
    46,  46,  46,  184, 184, 184, 184, 184, 184, 184, 184, 184, 184, 184, 184, 184, 184, 184, 184, 184,
    184, 184, 184, 184, 184, 184, 184, 184, 184, 184, 184, 112, 112, 112, 112, 112, 112, 112, 112, 112,
    112, 112, 23,  23,  23,  23,  23,  23,  23,  23,  23,  23,  23,  23,  169, 169, 169, 169, 169, 169,
    169, 169, 169, 169, 169, 169, 169, 169, 169, 169, 169, 169, 169, 169, 169, 169, 129, 129, 129, 76,
    21,  21,  21,  21,  21,  21,  21,  21,  21,  21,  21,  21,  21,  21,  211, 211, 211, 211, 211, 211,
    211, 211, 64,  64,  64,  64,  64,  64,  64,  64,  64,  204, 204, 204, 204, 204, 204, 204, 204, 204,
    204, 204, 204, 204, 204, 204, 204, 204, 204, 204, 143, 143, 143, 143, 143, 143, 143, 143, 143, 143,
    143, 143, 143, 143, 143, 143, 143, 143, 143, 143, 78,  78,  78,  78,  78,  78,  78,  78,  78,  78,
    78,  78,  78,  78,  78,  78,  78,  78,  78,  78,  78,  78,  78,  78,  130, 191, 191, 191, 191, 191,
    191, 191, 191, 191, 191, 191, 191, 191, 191, 191, 78,  78,  78,  78,  78,  78,  78,  78,  78,  78,
    78,  78,  78,  78,  78,  78,  78,  78,  10,  10,  10,  10,  10,  10,  10,  10,  10,  10,  10,  10,
    10,  10,  10,  10,  10,  10,  10,  73,  73,  73,  73,  73,  73,  73,  73,  101, 101, 101, 101, 101,
    101, 101, 101, 101, 101, 101, 38,  38,  38,  38,  38,  38,  38,  38,  38,  38,  38,  38,  38,  38,
    38,  165, 165, 165, 165, 165, 165, 165, 165, 165, 165, 165, 165, 165, 28,  172, 172, 172, 172, 172,
    172, 172, 172, 172, 172, 207, 207, 207, 207, 207, 207, 207, 207, 207, 207, 207, 207, 207, 207, 207,
    207, 207, 207, 207, 207, 207, 207, 207, 207, 207, 202, 202, 202, 106, 106, 106, 106, 106, 106, 106,
    177, 177, 177, 177, 177, 177, 177, 177, 177, 177, 177, 177, 177, 177, 177, 177, 177, 177, 177, 177,
    177, 177, 182, 182, 182, 182, 182, 182, 182, 182, 182, 182, 182, 182, 182, 182, 182, 182, 182, 182,
    182, 74,  74,  74,  74,  74,  74,  74,  74,  74,  125, 125, 125, 125, 125, 125, 125, 125, 125, 125,
    125, 125, 125, 125, 125, 125, 125, 125, 125, 125, 125, 125, 125, 125, 125, 145, 145, 38,  38,  38,
    38,  38,  38,  38,  38,  38,  38,  38,  38,  38,  38,  38,  38,  38,  38,  38,  38,  38,  38,  64,
    64,  64,  64,  64,  64,  64,  64,  64,  64,  64,  64,  64,  72,  72,  72,  72,  175, 175, 175, 175,
    175, 175, 175, 175, 175, 175, 175, 175, 175, 175, 175, 175, 175, 175, 175, 175, 175, 191, 191, 191,
    191, 191, 191, 191, 191, 191, 191, 191, 191, 191, 191, 191, 191, 191, 191, 164, 164, 164, 164, 164,
    164, 164, 164, 164, 164, 27,  27,  27,  27,  27,  27,  27,  27,  27,  27,  27,  27,  27,  27,  27,
    27,  27,  27,  30,  30,  30,  30,  30,  30,  30,  30,  30,  30,  30,  30,  30,  30,  30,  30,  30,
    30,  30,  30,  30,  30,  30,  30,  30,  30,  30,  30,  30,  88,  88,  88,  88,  88,  88,  88,  88,
    88,  88,  88,  88,  88,  88,  88,  88,  88,  88,  88,  88,  88,  88,  88,  245, 245, 245, 245, 245,
    245, 245, 245, 238, 238, 238, 238, 238, 238, 238, 238, 238, 238, 238, 238, 238, 238, 238, 238, 238,
    238, 238, 238, 238, 161, 161, 161, 161, 161, 161, 161, 161, 161, 161, 161, 161, 161, 161, 161, 194,
    194, 194, 194, 194, 194, 194, 194, 194, 194, 194, 194, 252, 252, 252, 252, 252, 252, 252, 252, 252,
    252, 252, 252, 252, 252, 252, 252, 252, 252, 252, 252, 252, 252, 252, 252, 252, 252, 252, 166, 166,
    166, 166, 166, 166, 166, 166, 166, 166, 166, 166, 166, 166, 166, 166, 166, 166, 166, 166, 165, 165,
    165, 165, 165, 165, 165, 165, 165, 165, 165, 165, 165, 165, 165, 165, 165, 165, 165, 165, 173, 173,
    173, 173, 173, 173, 173, 173, 173, 229, 229, 229, 229, 229, 229, 229, 229, 229, 229, 229, 229, 229,
    229, 229, 229, 229, 229, 229, 229, 229, 229, 229, 229, 229, 229, 125, 125, 125, 125, 125, 125, 125,
    125, 125, 125, 125, 125, 125, 125, 125, 125, 125, 125, 125, 226, 226, 226, 226, 226, 226, 226, 226,
    226, 226, 226, 226, 226, 226, 226, 226, 140, 140, 140, 140, 140, 140, 140, 140, 140, 140, 140, 140,
    140, 140, 140, 140, 140, 140, 140, 67,  67,  67,  67,  67,  108, 108, 108, 108, 108, 108, 108, 252,
    252, 252, 252, 252, 252, 252, 252, 252, 252, 146, 146, 146, 146, 146, 146, 146, 146, 146, 146, 146,
    146, 146, 146, 146, 146, 146, 146, 146, 146, 146, 63,  63,  63,  63,  63,  247, 247, 247, 247, 247,
    247, 247, 247, 177, 177, 177, 177, 177, 177, 177, 177, 177, 177, 177, 177, 177, 177, 204, 204, 204,
    204, 204, 204, 204, 204, 204, 204, 204, 204, 204, 204, 204, 204, 204, 204, 204, 204, 204, 242, 242,
    242, 242, 242, 242, 242, 242, 242, 242, 242, 242, 242, 242, 187, 187, 187, 187, 187, 187, 187, 187,
    187, 187, 187, 187, 187, 187, 187, 187, 187, 187, 187, 187, 187, 187, 187, 105, 105, 105, 105, 105,
    105, 105, 105, 105, 105, 105, 105, 105, 105, 105, 105, 105, 105, 105, 105, 105, 105, 105, 105, 105,
    105, 105, 115, 115, 115, 115, 115, 115, 115, 115, 115, 115, 115, 115, 115, 115, 115, 115, 115, 115,
    61,  61,  61,  61,  61,  61,  61,  61,  61,  61,  61,  61,  61,  61,  61,  61,  61,  61,  61,  61,
    61,  61,  134, 134, 134, 134, 134, 134, 134, 134, 134, 134, 134, 134, 106, 106, 106, 106, 106, 106,
    106, 106, 106, 106, 66,  66,  66,  66,  66,  66,  66,  66,  66,  66,  66,  66,  66,  66,  66,  66,
    66,  66,  66,  66,  66,  50,  148, 148, 148, 148, 148, 148, 148, 148, 148, 148, 148, 148, 148, 148,
    148, 187, 187, 187, 187, 187, 187, 220, 220, 220, 220, 220, 220, 220, 220, 136, 136, 136, 136, 136,
    136, 136, 136, 136, 136, 136, 136, 136, 136, 136, 94,  94,  94,  94,  94,  94,  94,  94,  94,  94,
    94,  94,  94,  94,  94,  134, 134, 134, 134, 134, 134, 134, 134, 134, 134, 43,  43,  43,
};

const surv_m22_input = [_]u8{
    186, 186, 186, 186, 186, 186, 186, 186, 186, 101, 101, 101, 101, 101, 101, 101, 101, 101, 101, 101,
    101, 101, 101, 101, 101, 101, 101, 255, 255, 23,  23,  23,  23,  23,  23,  23,  208, 208, 65,  65,
    65,  65,  65,  65,  210, 210, 210, 210, 210, 210, 210, 210, 210, 210, 210, 210, 210, 210, 255, 255,
    255, 255, 255, 255, 255, 40,  40,  40,  40,  40,  40,  40,  40,  76,  76,  76,  76,  76,  76,  76,
    76,  76,  76,  76,  132, 132, 132, 132, 132, 132, 132, 132, 132, 132, 132, 132, 132, 132, 132, 132,
    132, 132, 132, 132, 132, 132, 132, 132, 132, 132, 107, 107, 107, 107, 107, 107, 107, 107, 107, 107,
    107, 107, 107, 107, 107, 107, 107, 107, 36,  36,  36,  36,  36,  36,  36,  36,  36,  36,  36,  36,
    36,  36,  36,  36,  36,  36,  36,  36,  36,  36,  36,  247, 247, 247, 247, 247, 247, 247, 247, 247,
    247, 247, 247, 247, 247, 247, 247, 60,  60,  60,  60,  60,  60,  60,  60,  60,  60,  60,  60,  60,
    60,  60,  60,  60,  60,  60,  60,  60,  60,  60,  60,  60,  60,  60,  60,  103, 103, 103, 103, 103,
    103, 103, 103, 103, 103, 103, 103, 103, 103, 103, 103, 103, 103, 17,  17,  17,  17,  17,  17,  17,
    17,  17,  17,  17,  17,  17,  17,  17,  17,  17,  17,  17,  17,  17,  17,  17,  17,  17,  17,  17,
    17,  17,  8,   8,   8,   8,   8,   8,   8,   8,   8,   8,   8,   8,   8,   8,   8,   8,   8,   8,
    8,   8,   8,   18,  18,  18,  18,  18,  18,  18,  18,  18,  18,  18,  18,  18,  18,  18,  18,  18,
    18,  18,  7,   7,   7,   7,   7,   7,   7,   7,   7,   7,   7,   7,   7,   7,   7,   7,   7,   7,
    7,   7,   7,   168, 168, 168, 168, 168, 168, 168, 168, 168, 168, 168, 168, 168, 168, 168, 168, 168,
    168, 168, 168, 168, 168, 168, 168, 168, 168, 255, 255, 255, 255, 255, 255, 16,  16,  16,  16,  16,
    16,  16,  16,  16,  16,  16,  16,  16,  16,  16,  16,  16,  16,  16,  46,  46,  213, 213, 213, 213,
    213, 213, 213, 213, 213, 213, 213, 213, 213, 213, 213, 213, 213, 213, 213, 213, 213, 213, 213, 213,
    213, 213, 213, 253, 253, 253, 253, 253, 253, 253, 253, 253, 253, 253, 253, 253, 253, 253, 253, 253,
    253, 253, 253, 253, 253, 253, 253, 61,  61,  61,  61,  186, 186, 186, 186, 186, 186, 186, 186, 186,
    186, 186, 186, 186, 186, 186, 186, 186, 186, 186, 186, 186, 186, 186, 186, 186, 186, 186, 186, 186,
    28,  28,  28,  28,  25,  25,  25,  25,  25,  25,  25,  25,  25,  25,  25,  25,  25,  25,  25,  25,
    25,  25,  25,  25,  25,  25,  25,  25,  25,  25,  25,  25,  25,  233, 233, 233, 233, 233, 233, 233,
    233, 233, 26,  26,  26,  26,  26,  26,  26,  26,  26,  26,  26,  26,  26,  26,  26,  26,  26,  26,
    26,  26,  26,  26,  26,  26,  200, 200, 200, 250, 250, 250, 250, 250, 250, 250, 250, 250, 250, 250,
    250, 250, 250, 250, 250, 250, 250, 250, 250, 250, 250, 130, 130, 130, 130, 130, 130, 130, 130, 130,
    130, 130, 130, 130, 130, 130, 130, 130, 130, 130, 130, 130, 115, 115, 115, 115, 115, 115, 115, 115,
    115, 199, 199, 199, 199, 199, 199, 199, 199, 199, 199, 199, 199, 199, 199, 199, 199, 199, 89,  89,
    89,  89,  89,  89,  89,  89,  89,  89,  89,  89,  89,  89,  89,  89,  89,  89,  89,  89,  89,  89,
    89,  233, 233, 233, 233, 233, 233, 233, 233, 233, 233, 233, 233, 233, 233, 79,  79,  79,  79,  79,
    79,  79,  79,  79,  79,  79,  79,  79,  79,  79,  79,  79,  79,  79,  217, 217, 217, 217, 217, 217,
    217, 217, 217, 217, 217, 217, 217, 217, 217, 217, 217, 217, 217, 217, 217, 217, 217, 217, 217, 217,
    217, 177, 177, 177, 177, 177, 177, 177, 177, 177, 177, 177, 177, 177, 177, 177, 177, 177, 177, 177,
    177, 177, 177, 177, 177, 235, 235, 235, 235, 23,  23,  23,  23,  23,  23,  23,  23,  23,  23,  23,
    23,  195, 195, 195, 195, 195, 195, 195, 195, 195, 195, 195, 195, 195, 195, 127, 127, 238, 238, 238,
    238, 238, 238, 238, 238, 238, 238, 238, 238, 238, 238, 238, 238, 238, 238, 53,  53,  53,  53,  53,
    53,  53,  53,  53,  53,  53,  53,  53,  155, 155, 155, 155, 155, 155, 155, 155, 155, 155, 155, 155,
    155, 155, 155, 155, 155, 155, 155, 155, 155, 155, 155, 155, 155, 218, 218, 218, 121, 121, 121, 121,
    121, 121, 89,  89,  89,  89,  89,  89,  89,  89,  89,  89,  89,  89,  89,  89,  89,  89,  242, 242,
    242, 242, 242, 242, 242, 242, 242, 242, 141, 141, 141, 141, 141, 141, 141, 141, 141, 141, 141, 141,
    141, 141, 141, 141, 141, 141, 141, 141, 141, 141, 141, 141, 41,  63,  63,  63,  63,  63,  63,  63,
    63,  63,  63,  63,  63,  63,  63,  63,  63,  63,  63,  63,  63,  63,  63,  63,  63,  56,  56,  56,
    56,  56,  56,  56,  56,  56,  56,  56,  56,  97,  97,  97,  97,  97,  97,  97,  97,  97,  169, 169,
    169, 169, 169, 169, 169, 169, 169, 169, 169, 169, 169, 169, 169, 169, 169, 169, 90,  90,  90,  90,
    90,  90,  90,  90,  90,  90,  90,  90,  90,  90,  90,  90,  90,  90,  119, 119, 119, 226, 226, 226,
    226, 226, 226, 226, 226, 226, 226, 226, 226, 226, 202, 94,  94,  94,  94,  94,  94,  94,  94,  94,
    94,  94,  94,  94,  94,  94,  94,  94,  94,  94,  94,  94,  94,  94,  94,  94,  94,  94,  94,  165,
    165, 165, 165, 165, 165, 165, 165, 165, 165, 165, 165, 165, 165, 165, 165, 165, 165, 165, 165, 165,
    165, 165, 165, 165, 165, 165, 223, 223, 223, 223, 223, 223, 119, 119, 17,  17,  17,  17,  17,  17,
    17,  17,  17,  17,  17,  17,  17,  17,  17,  17,  17,  17,  17,  17,  17,  159, 159, 159, 159, 159,
    159, 159, 159, 159, 159, 159, 159, 159, 159, 159, 159, 159, 159, 159, 159, 159, 159, 159, 151, 151,
    151, 151, 151, 151, 151, 151, 151, 151, 151, 151, 151, 151, 151, 151, 151, 151, 151, 151, 151, 151,
    151, 151, 151, 151, 218, 218, 218, 161, 161, 191, 191, 191, 191, 92,  92,  92,  92,  92,  92,  92,
    92,  92,  92,  92,  92,  92,  92,  157, 157, 157, 157, 157, 157, 157, 157, 157, 157, 157, 157, 46,
    46,  46,  22,  22,  22,  22,  22,  22,  22,  22,  22,  22,  22,  22,  22,  22,  22,  22,  22,  22,
    22,  22,  22,  22,  22,  22,  22,  22,  165, 165, 165, 165, 165, 134, 134, 134, 134, 134, 134, 134,
    134, 134, 134, 134, 71,  71,  71,  232, 232, 232, 232, 232, 232, 232, 232, 232, 232, 232, 232, 232,
    232, 232, 232, 232, 232, 232, 232, 232, 232, 232, 232, 232, 232, 232, 232, 72,  72,  72,  72,  72,
    72,  72,  72,  72,  72,  72,  72,  72,  72,  72,  72,  72,  72,  72,  0,   0,   0,   0,   0,   0,
    0,   0,   0,   0,   0,   0,   0,   0,   0,   0,   0,   18,  18,  18,  18,  254, 254, 254, 254, 254,
    254, 254, 254, 254, 254, 254, 254, 254, 254, 254, 254, 254, 254, 68,  68,  68,  68,  68,  68,  68,
    68,  68,  68,  68,  68,  68,  33,  33,  33,  33,  33,  33,  33,  33,  33,  33,  33,  33,  33,  33,
    33,  33,  174, 174, 174, 174, 174, 174, 174, 174, 174, 174, 174, 174, 174, 174, 174, 191, 191, 191,
    191, 191, 191, 191, 191, 191, 191, 191, 191, 191, 191, 191, 191, 191, 101, 101, 101, 101, 101, 101,
    101, 119, 119, 119, 119, 119, 119, 119, 119, 119, 119, 119, 119, 119, 119, 119, 119, 119, 119, 119,
    119, 119, 119, 119, 119, 217, 217, 217, 217, 217, 217, 217, 217, 217, 54,  54,  54,  54,  54,  54,
    54,  54,  54,  54,  54,  54,  54,  54,  197, 197, 197, 197, 197, 197, 197, 197, 197, 197, 197, 197,
    197, 197, 25,  25,  25,  25,  25,  25,  25,  25,  25,  157, 157, 157, 157, 157, 157, 157, 157, 157,
    157, 157, 157, 157, 157, 157, 157, 157, 157, 157, 157, 157, 157, 2,   2,   2,   2,   2,   2,   2,
    2,   2,   2,   2,   2,   2,   2,   2,   2,   2,   2,   2,   2,   2,   2,   2,   2,   2,   2,   2,
    2,   2,   208, 208, 208, 208, 208, 119, 119, 119, 119, 119, 150, 150, 150, 150, 150, 150, 150, 150,
    150, 150, 150, 150, 150, 150, 150, 150, 150, 150, 150, 150, 136, 136, 136, 34,  34,  34,  34,  34,
    34,  34,  34,  34,  34,  34,  34,  34,  34,  34,  34,  238, 238, 238, 238, 238, 238, 238, 238, 238,
    238, 238, 238, 238, 238, 233, 233, 233, 233, 233, 233, 233, 233, 233, 233, 233, 233, 233, 233, 233,
    233, 233, 233, 233, 233, 233, 0,   0,   0,   0,   0,   0,   0,   0,   0,   0,   0,   0,   0,   143,
    143, 143, 143, 143, 143, 143, 143, 143, 143, 140, 140, 140, 140, 140, 140, 140, 140, 140, 140, 140,
    140, 140, 140, 140, 140, 140, 140, 140, 100, 100, 100, 100, 100, 100, 100, 100, 100, 100, 100, 100,
    165, 165, 165, 165, 165, 165, 165, 165, 165, 165, 165, 165, 165, 165, 165, 165, 165, 165, 165, 165,
    165, 165, 165, 165, 165, 227, 227, 227, 227, 227, 227, 227, 227, 227, 227, 227, 227, 152, 152, 152,
    152, 217, 217, 217, 217, 217, 217, 217, 217, 217, 217, 217, 217, 217, 217, 217, 217, 217, 217, 217,
    119, 119, 119, 119, 119, 119, 119, 119, 119, 119, 119, 119, 119, 119, 119, 119, 119, 119, 119, 119,
    119, 119, 119, 119, 119, 245, 245, 245, 245, 245, 245, 245, 245, 245, 245, 136, 136, 136, 136, 14,
    14,  14,  14,  14,  14,  14,  14,  14,  14,  14,  14,  14,  254, 254, 254, 254, 192, 192, 192, 192,
    192, 192, 192, 192, 192, 87,  87,  87,  87,  87,  87,  87,  87,  87,  10,  10,  10,  10,  10,  10,
    10,  10,  10,  10,  10,  10,  10,  10,  10,  10,  10,  10,  10,  10,  10,  10,  10,  10,  10,  10,
    10,  10,  10,  96,  179, 179, 179, 179, 179, 179, 179, 179, 179, 179, 179, 179, 179, 179, 179, 179,
    223, 223, 223, 223, 223, 223, 223, 223, 223, 223, 223, 223, 223, 223, 223, 223, 223, 223, 223, 223,
    223, 223, 223, 223, 223, 223, 223, 83,  83,  83,  83,  83,  83,  83,  83,  83,  83,  83,  83,  224,
    224, 224, 224, 224, 224, 224, 224, 224, 224, 224, 224, 100, 100, 100, 100, 100, 100, 100, 100, 100,
    100, 100, 100, 100, 100, 100, 100, 219, 219, 219, 219, 219, 219, 219, 219, 219, 219, 242, 242, 242,
    242, 172, 172, 172, 172, 172, 172, 172, 172, 172, 172, 172, 172, 172, 172, 172, 172, 172, 172, 172,
    172, 172, 172, 172, 172, 172, 172, 172, 172, 125, 125, 125, 125, 125, 125, 125, 125, 125, 125, 125,
    125, 125, 125, 125, 125, 125, 125, 125, 81,  81,  81,  81,  81,  81,  81,  81,  81,  81,  81,  81,
    81,  81,  81,  81,  81,  81,  81,  81,  81,  81,  81,  97,  97,  97,  97,  97,  97,  97,  97,  97,
    97,  97,  97,  97,  97,  97,  97,  97,  97,  97,  97,  97,  97,  97,  97,  97,  149, 149, 149, 149,
    149, 149, 149, 149, 149, 149, 68,  68,  68,  68,  68,  68,  68,  68,  68,  68,  68,  68,  68,  68,
    68,  68,  68,  68,  113, 113, 113, 113, 113, 113, 113, 113, 113, 113, 113, 113, 113, 113, 113, 113,
    113, 113, 113, 113, 113, 144, 144, 144, 144, 144, 144, 144, 144, 144, 144, 144, 144, 144, 144, 144,
    144, 144, 144, 144, 144, 144, 144, 144, 144, 144, 144, 144, 144, 124, 124, 124, 124, 124, 124, 124,
    124, 124, 124, 124, 124, 124, 124, 124, 139, 139, 139, 139, 139, 139, 180, 180, 180, 180, 180, 180,
    180, 180, 180, 180, 180, 180, 180, 180, 180, 180, 180, 180, 180, 180, 180, 180, 180, 180, 27,  27,
    27,  27,  27,  27,  27,  27,  27,  27,  27,  27,  27,  27,  27,  231, 231, 231, 231, 231, 231, 231,
    231, 231, 231, 231, 231, 231, 231, 231, 231, 106, 106, 106, 106, 106, 106, 106, 106, 106, 133, 133,
    133, 133, 76,  76,  76,  76,  76,  76,  76,  76,  76,  76,  76,  76,  128, 128, 128, 128, 128, 128,
    128, 128, 128, 128, 128, 128, 128, 128, 128, 128, 128, 128, 128, 128, 128, 128, 128, 128, 128, 128,
    128, 128, 128, 37,  37,  37,  37,  37,  37,  37,  37,  37,  37,  37,  37,  37,  37,  37,  37,  37,
    37,  37,  37,  37,  37,  37,  37,  37,  37,  231, 231, 231, 231, 231, 231, 231, 231, 231, 231, 231,
    231, 192, 192, 192, 192, 192, 119, 119, 119, 119, 119, 119, 119, 119, 119, 119, 119, 119, 119, 119,
    119, 222, 222, 181, 181, 181, 181, 181, 181, 181, 181, 181, 181, 181, 181, 181, 139, 139, 139, 139,
    139, 139, 139, 139, 139, 139, 139, 139, 139, 139, 139, 139, 139, 139, 139, 139, 139, 139, 126, 126,
    126, 126, 126, 126, 126, 126, 126, 126, 126, 221, 221, 221, 221, 221, 221, 221, 221, 221, 221, 221,
    221, 221, 221, 221, 221, 237, 237, 237, 237, 237, 237, 237, 185, 185, 185, 185, 185, 185, 185, 185,
    185, 185, 185, 185, 232, 232, 232, 232, 232, 232, 232, 232, 232, 59,  59,  59,  59,  59,  59,  59,
    49,  49,  49,  49,  49,  49,  49,  49,  49,  49,  49,  49,  216, 216, 216, 216, 216, 216, 216, 216,
    216, 216, 216, 216, 216, 216, 216, 216, 216, 216, 216, 216, 216, 216, 216, 216, 216, 216, 216, 216,
    216, 194, 194, 194, 194, 194, 194, 194, 194, 194, 194, 194, 194, 194, 194, 194, 194, 194, 194, 194,
    194, 198, 198, 198, 198, 198, 198, 198, 198, 198, 198, 198, 198, 34,  34,  34,  34,  34,  34,  34,
    34,  34,  34,  34,  34,  34,  34,  34,  222, 222, 222, 222, 222, 222, 222, 222, 222, 222, 222, 222,
    222, 222, 222, 222, 222, 222, 222, 222, 222, 222, 222, 222, 222, 141, 141, 141, 141, 141, 141, 141,
    141, 141, 141, 141, 208, 208, 208, 208, 208, 208, 208, 208, 208, 208, 208, 208, 208, 4,   4,   4,
    4,   4,   4,   4,   4,   4,   4,   4,   4,   4,   4,   4,   4,   4,   4,   4,   4,   4,   4,   4,
    4,   4,   4,   4,   4,   4,   28,  28,  28,  28,  28,  28,  28,  28,  28,  28,  28,  28,  28,  28,
    28,  28,  28,  28,  28,  28,  28,  28,  28,  28,  28,  28,  9,   9,   9,   9,   9,   9,   9,   9,
    9,   9,   9,   9,   9,   9,   9,   9,   9,   9,   9,   229, 206, 206, 206, 206, 206, 206, 206, 206,
    206, 206, 206, 206, 206, 206, 206, 206, 206, 107, 107, 107, 107, 107, 107, 107, 107, 107, 107, 107,
    107, 107, 107, 107, 107, 107, 107, 107, 36,  36,  36,  36,  36,  36,  36,  36,  36,  36,  36,  36,
    36,  36,  36,  36,  36,  36,  36,  36,  36,  36,  36,  36,  36,  78,  78,  78,  78,  78,  78,  78,
    78,  78,  78,  78,  78,  78,  78,  78,  78,  78,  78,  78,  78,  214, 214, 214, 214, 214, 214, 214,
    214, 214, 214, 214, 214, 214, 214, 214, 214, 214, 214, 214, 214, 214, 226, 226, 226, 226, 226, 226,
    226, 50,  78,  78,  78,  78,  78,  78,  78,  154, 154, 154, 154, 154, 154, 154, 154, 154, 154, 154,
    154, 158, 158, 158, 158, 158, 158, 158, 158, 158, 158, 158, 158, 158, 158, 158, 158, 158, 158, 158,
    158, 158, 158, 158, 158, 158, 158, 158, 158, 88,  88,  88,  88,  156, 156, 156, 156, 100, 100, 100,
    100, 100, 100, 100, 100, 100, 100, 100, 100, 100, 86,  86,  86,  86,  86,  86,  86,  86,  86,  86,
    86,  86,  86,  86,  86,  86,  86,  86,  86,  86,  86,  249, 249, 249, 249, 249, 249, 249, 249, 249,
    249, 249, 249, 249, 249, 249, 249, 249, 249, 249, 19,  19,  19,  19,  19,  19,  19,  19,  19,  19,
    19,  19,  19,  19,  19,  19,  19,  19,  19,  19,  116, 116, 116, 116, 116, 116, 116, 116, 116, 116,
    217, 217, 217, 217, 217, 217, 217, 217, 122, 122, 122, 122, 122, 122, 122, 122, 122, 122, 122, 122,
    253, 253, 253, 253, 253, 253, 253, 253, 253, 253, 6,   6,   6,   6,   6,   110, 110, 110, 110, 110,
    110, 110, 110, 110, 110, 110, 110, 110, 110, 110, 110, 110, 110, 110, 110, 110, 110, 110, 137, 137,
    137, 137, 137, 137, 137, 137, 137, 137, 137, 137, 137, 137, 137, 172, 172, 172, 172, 172, 172, 172,
    172, 172, 172, 215, 215, 215, 215, 181, 181, 181, 181, 181, 181, 181, 181, 181, 181, 181, 181, 181,
    181, 181, 181, 181, 181, 181, 181, 181, 253, 253, 253, 253, 251, 251, 251, 251, 251, 251, 251, 251,
    251, 70,  70,  70,  70,  70,  70,  70,  70,  70,  70,  70,  70,  223, 223, 223, 223, 223, 223, 223,
    223, 223, 223, 25,  25,  25,  25,  25,  25,  25,  25,  25,  25,  25,  25,  25,  25,  25,  25,  25,
    25,  25,  25,  25,  25,  25,  25,  25,  25,  25,  190, 190, 190, 190, 190, 190, 190, 190, 190, 190,
    190, 190, 190, 190, 190, 190, 190, 190, 190, 190, 190, 190, 190, 190, 190, 190, 190, 190, 190, 35,
    35,  35,  35,  35,  35,  35,  35,  35,  35,  35,  35,  35,  35,  35,  35,  35,  35,  35,  190, 190,
    190, 190, 190, 190, 190, 190, 190, 190, 190, 190, 190, 190, 190, 190, 190, 190, 190, 190, 190, 190,
};

const surv_m23_dict = [_]u8{
    109, 109, 109, 109, 109, 109, 109, 109, 109, 38,  38,  38,  38,  38,  38,  38,  38,  38,  38,  38,
    234, 234, 234, 234, 234, 234, 234, 234, 234, 234, 58,  58,  58,  58,  58,  58,  58,  58,  58,  58,
    58,  58,  58,  58,  58,  58,  58,  58,  58,  58,  58,  58,  58,  58,  58,  58,  222, 222, 222, 222,
    222, 222, 222, 222, 222, 151, 151, 91,  91,  91,  91,  91,  91,  91,  91,  91,  91,  91,  91,  91,
    91,  124, 124, 124, 124, 124, 124, 117, 117, 117, 117, 117, 117, 117, 117, 117, 117, 117, 117, 117,
    117, 117, 117, 117, 117, 117, 117, 117, 155, 155, 155, 155, 155, 155, 155, 155, 155, 155, 155, 155,
    155, 155, 155, 155, 155, 155, 155, 155, 155, 155, 155, 155, 155, 155, 155, 155, 196, 196, 196, 196,
    196, 196, 196, 196, 196, 196, 196, 196, 196, 196, 196, 196, 196, 13,  13,  13,  13,  13,  13,  13,
    13,  13,  13,  13,  13,  13,  13,  13,  13,  13,  13,  13,  13,  13,  13,  13,  13,  249, 249, 249,
    249, 249, 249, 249, 249, 249, 249, 249, 249, 249, 249, 188, 21,  21,  21,  21,  21,  21,  21,  21,
    21,  21,  21,  21,  21,  21,  21,  21,  21,  21,  21,  21,  18,  18,  18,  18,  18,  18,  18,  18,
    18,  18,  18,  18,  18,  18,  18,  18,  18,  18,  18,  18,  18,  18,  208, 208, 208, 208, 208, 208,
    208, 208, 208, 208, 208, 208, 208, 206, 206, 206, 206, 206, 206, 206, 206, 206, 206, 206, 206, 206,
    206, 88,  88,  88,  88,  88,  88,  143, 143, 143, 143, 143, 143, 143, 153, 153, 153, 153, 153, 153,
    153, 153, 153, 153, 153, 153, 153, 153, 153, 153, 49,  49,  49,  49,  49,  49,  49,  49,  49,  49,
    49,  49,  49,  49,  49,  49,  49,  54,  54,  54,  7,   215, 215, 215, 215, 215, 215, 215, 215, 215,
    215, 215, 215, 215, 215, 215, 215, 215, 215, 215, 215, 215, 215, 215, 215, 215, 215, 215, 215, 215,
    215, 215, 215, 215, 215, 215, 222, 222, 222, 222, 222, 222, 222, 222, 222, 100, 100, 100, 100, 100,
    100, 100, 100, 100, 100, 100, 100, 100, 100, 100, 100, 100, 72,  72,  72,  72,  72,  72,  72,  72,
    72,  72,  72,  67,  67,  67,  67,  67,  67,  67,  67,  67,  67,  67,  67,  67,  67,  84,  84,  84,
    84,  84,  84,  84,  84,  84,  84,  84,  84,  84,  84,  84,  84,  84,  84,  84,  84,  84,  84,  84,
    84,  37,  37,  37,  37,  37,  37,  37,  37,  37,  37,  37,  37,  37,  37,  52,  52,  93,  93,  93,
    93,  93,  93,  93,  93,  93,  93,  121, 121, 121, 121, 121, 121, 121, 36,  36,  36,  36,  36,  36,
    36,  36,  36,  36,  36,  36,  36,  36,  36,  36,  45,  45,  45,  146, 146, 146, 146, 216, 216, 216,
    216, 216, 216, 216, 216, 216, 216, 216, 216, 216, 216, 216, 216, 216, 216, 216, 216, 216, 216, 216,
    216, 216, 216, 216, 216, 235, 235, 235, 235, 235, 139, 139, 139, 139, 139, 139, 139, 139, 139, 139,
    139, 86,  86,  86,  86,  86,  86,  86,  171, 171, 171, 171, 171, 171, 171, 171, 171, 171, 171, 127,
    127, 127, 221, 221, 221, 221, 221, 221, 221, 221, 221, 221, 221, 221, 255, 255, 167, 167, 167, 167,
    167, 167, 167, 167, 167, 167, 167, 167, 167, 167, 167, 167, 167, 167, 167, 167, 167, 167, 167, 167,
    167, 167, 167, 203, 203, 203, 203, 203, 203, 203, 203, 203, 203, 203, 203, 203, 203, 203, 221, 221,
    221, 221, 221, 221, 221, 221, 221, 221, 221, 221, 221, 221, 221, 221, 221, 221, 221, 221, 221, 221,
    221, 221, 242, 33,  33,  33,  33,  33,  33,  33,  33,  33,  33,  33,  33,  33,  78,  78,  78,  78,
    202, 202, 202, 202, 202, 202, 202, 202, 202, 202, 202, 202, 202, 202, 202, 202, 202, 202, 202, 202,
    202, 202, 202, 202, 202, 95,  95,  95,  95,  95,  95,  160, 160, 160, 160, 160, 160, 160, 160, 160,
    160, 189, 189, 189, 189, 189, 189, 189, 189, 189, 189, 189, 189, 189, 140, 140, 140, 140, 140, 140,
    140, 140, 52,  52,  52,  18,  18,  18,  18,  18,  18,  18,  18,  18,  18,  18,  18,  64,  64,  64,
    64,  64,  64,  64,  64,  64,  64,  64,  64,  64,  64,  64,  64,  64,  64,  64,  64,  64,  64,  64,
    64,  64,  64,  21,  21,  21,  21,  44,  44,  44,  44,  44,  44,  44,  149, 149, 149, 149, 149, 149,
    149, 149, 149, 149, 149, 32,  32,  32,  32,  32,  32,  32,  32,  32,  32,  32,  32,  32,  32,  32,
    32,  32,  32,  32,  73,  73,  73,  73,  73,  73,  41,  41,  41,  41,  41,  41,  41,  194, 194, 194,
    194, 194, 194, 194, 194, 194, 194, 194, 194, 194, 194, 194, 241, 241, 241, 241, 241, 241, 241, 241,
    241, 241, 241, 241, 241, 241, 241, 241, 241, 241, 241, 241, 241, 241, 219, 219, 219, 219, 219, 219,
    219, 70,  192, 192, 192, 192, 192, 192, 227, 227, 223, 223, 223, 223, 223, 223, 223, 223, 223, 223,
    223, 223, 223, 149, 149, 149, 149, 149, 149, 149, 149, 149, 149, 149, 149, 149, 149, 149, 149, 149,
    149, 149, 149, 149, 28,  28,  28,  28,  28,  28,  28,  28,  28,  28,  28,  28,  28,  28,  28,  28,
    28,  28,  28,  28,  28,  28,  28,  28,  109, 109, 109, 109, 177, 177, 177, 177, 177, 177, 177, 177,
    177, 177, 177, 177, 177, 177, 177, 177, 177, 177, 177, 177, 177, 177, 58,  58,  58,  58,  58,  58,
    58,  58,  58,  58,  58,  58,  58,  58,  72,  72,  72,  72,  72,  72,  72,  72,  72,  72,  72,  72,
    72,  72,  72,  72,  72,  72,  72,  72,  72,  72,  72,  72,  72,  67,  67,  88,  88,  88,  88,  27,
    27,  27,  27,  27,  27,  27,  27,  27,  27,  117, 117, 117, 117, 117, 117, 117, 117, 117, 117, 117,
    117, 117, 117, 117, 117, 117, 117, 117, 117, 117, 117, 50,  50,  50,  50,  50,  50,  155, 155, 155,
    155, 4,   4,   4,   4,   4,   4,   4,   4,   4,   4,   4,   4,   4,   4,   4,   4,   4,   4,   4,
    4,   4,   4,   4,   4,   4,   214, 214, 214, 214, 214, 214, 214, 214, 214, 214, 214, 214, 214, 214,
    214, 214, 214, 214, 214, 214, 214, 214, 214, 214, 214, 214, 214, 214, 93,  93,  93,  93,  93,  93,
    93,  93,  93,  93,  93,  93,  93,  93,  93,  93,  93,  228, 228, 228, 228, 228, 228, 228, 228, 228,
    228, 228, 228, 59,  59,  59,  59,  59,  59,  59,  59,  59,  59,  59,  59,  59,  59,  59,  59,  59,
    59,  59,  59,  59,  59,  67,  67,  67,  67,  67,  67,  67,  67,  67,  67,  67,  67,  67,  67,  67,
    67,  67,  67,  67,  67,  67,  67,  254, 254, 254, 254, 254, 254, 254, 254, 254, 254, 254, 254, 254,
    254, 254, 254, 254, 254, 254, 254, 254, 254, 254, 254, 113, 113, 113, 113, 113, 12,  12,  12,  12,
    12,  12,  12,  12,  12,  12,  12,  12,  12,  12,  12,  12,  12,  12,  12,  12,  12,  12,  12,  12,
    12,  12,  33,  33,  33,  33,  33,  33,  33,  33,  33,  33,  33,  33,  33,  33,  33,  7,   7,   7,
    7,   7,   7,   7,   7,   7,   238, 238, 238, 238, 226, 226, 226, 226, 226, 226, 226, 226, 226, 226,
    226, 229, 229, 229, 229, 194, 194, 194, 194, 194, 194, 194, 194, 194, 194, 194, 194, 194, 194, 194,
    194, 194, 194, 194, 194, 194, 194, 194, 194, 194, 194, 194, 194, 194, 120, 120, 120, 120, 120, 120,
    120, 120, 120, 120, 120, 120, 120, 120, 120, 120, 120, 120, 120, 120, 120, 120, 120, 120, 120, 120,
    120, 120, 76,  76,  76,  76,  76,  76,  76,  76,  76,  76,  76,  76,  76,  18,  18,  18,  18,  18,
    18,  18,  18,  18,  18,  18,  18,  18,  18,  18,  18,  18,  18,  18,  18,  18,  18,  18,  18,  18,
    18,  18,  18,  126, 126, 126, 126, 126, 126, 126, 126, 126, 126, 126, 126, 126, 126, 126, 126, 126,
    126, 126, 126, 126, 126, 126, 126, 126, 126, 126, 126, 117, 117, 117, 117, 117, 117, 117, 117, 117,
    117, 117, 117, 117, 117, 117, 191, 191, 191, 191, 191, 191, 114, 114, 114, 114, 114, 114, 114, 114,
    114, 114, 114, 114, 114, 114, 114, 114, 114, 114, 114, 114, 114, 114, 114, 114, 114, 114, 114, 114,
    98,  98,  98,  98,  98,  98,  98,  98,  98,  98,  98,  98,  98,  98,  98,  98,  98,  249, 249, 249,
    249, 249, 249, 249, 249, 249, 249, 249, 249, 249, 249, 249, 249, 249, 249, 88,  88,  88,  88,  88,
    88,  88,  88,  27,  27,  27,  27,  120, 120, 120, 120, 120, 120, 120, 120, 120, 120, 120, 120, 120,
    120, 120, 129, 129, 129, 129, 129, 129, 129, 129, 129, 129, 129, 129, 129, 129, 129, 129, 129, 152,
    152, 152, 152, 152, 152, 152, 182, 182, 233, 233, 233, 233, 233, 233, 233, 176, 176, 176, 176, 176,
    189, 189, 189, 189, 189, 189, 189, 189, 189, 189, 189, 189, 189, 189, 189, 189, 189, 189, 189, 189,
    189, 189, 189, 189, 189, 117, 117, 117, 117, 117, 117, 117, 117, 117, 117, 117, 90,  90,  90,  90,
    90,  90,  90,  90,  90,  90,  90,  90,  90,  90,  90,  90,  90,  90,  90,  90,  90,  123, 123, 123,
    123, 123, 148, 148, 148, 148, 148, 148, 148, 148, 148, 148, 148, 148, 148, 148, 148, 148, 148, 148,
    148, 148, 148, 148, 148, 148, 148, 148, 148, 148, 3,   3,   3,   3,   3,   3,   3,   3,   3,   3,
    3,   3,   3,   3,   3,   3,   3,   3,   3,   3,   118, 118, 118, 118, 118, 118, 118, 118, 118, 118,
    118, 118, 118, 168, 168, 168, 168, 168, 168, 27,  27,  27,  27,  27,  27,  27,  27,  27,  27,  27,
    27,  27,  27,  27,  27,  27,  27,  27,  27,  27,  13,  13,  13,  13,  13,  233, 219, 219, 219, 219,
    219, 219, 219, 219, 219, 219, 219, 219, 219, 219, 250, 250, 250, 250, 250, 250, 113, 113, 113, 113,
    113, 113, 120, 120, 120, 120, 120, 120, 120, 120, 120, 120, 120, 120, 120, 83,  83,  83,  83,  83,
    83,  83,  239, 239, 239, 239, 239, 239, 239, 239, 239, 239, 239, 239, 239, 239, 239, 239, 239, 239,
    239, 239, 239, 239, 239, 239, 239, 239, 239, 239, 239, 22,  22,  114, 114, 114, 114, 114, 154, 154,
    154, 154, 154, 154, 154, 154, 154, 154, 154, 154, 0,   0,   0,   0,   0,   0,   0,   0,   0,   0,
    0,   0,   0,   0,   0,   0,   0,   120, 120, 120, 120, 120, 120, 120, 120, 120, 120, 120, 120, 120,
    120, 120, 120, 120, 120, 120, 120, 120, 120, 120, 120, 120, 120, 120, 120, 238, 238, 238, 238, 238,
    238, 238, 238, 238, 238, 238, 238, 238, 238, 238, 238, 238, 238, 17,  17,  17,  17,  17,  17,  17,
    17,  17,  17,  17,  17,  17,  17,  17,  17,  17,  17,  17,  17,  17,  17,  17,  136, 136, 136, 136,
    136, 136, 136, 136, 136, 136, 136, 136, 136, 136, 136, 136, 136, 132, 132, 132, 132, 132, 132, 132,
    132, 132, 132, 132, 132, 132, 132, 132, 132, 132, 132, 132, 132, 132, 132, 132, 132, 132, 132, 132,
    132, 60,  60,  60,  60,  60,  60,  60,  60,  60,  60,  60,  60,  60,  60,  60,  60,  60,  60,  60,
    60,  60,  60,  60,  202, 202, 202, 202, 202, 202, 202, 202, 202, 202, 202, 202, 202, 202, 202, 202,
    202, 202, 202, 227, 227, 227, 227, 227, 227, 227, 227, 227, 227, 8,   8,   8,   8,   8,   8,   8,
    8,   8,   8,   8,   8,   8,   8,   8,   221, 221, 221, 221, 221, 221, 221, 221, 221, 221, 221, 221,
    110, 110, 110, 110, 110, 110, 110, 110, 203, 203, 203, 203, 203, 203, 203, 203, 203, 203, 203, 203,
    203, 203, 203, 203, 203, 68,  68,  68,  68,  68,  68,  68,  68,  68,  68,  68,  68,  68,  68,  54,
    54,  54,  54,  54,  215, 215, 215, 215, 215, 215, 215, 215, 215, 215, 215, 215, 215, 215, 215, 215,
    215, 215, 215, 215, 215, 215, 215, 215, 191, 191, 191, 191, 191, 191, 191, 191, 191, 191, 191, 191,
    191, 191, 191, 191, 191, 191, 191, 191, 191, 200, 200, 200, 200, 200, 200, 200, 200, 200, 200, 200,
    200, 200, 200, 200, 200, 200, 200, 200, 200, 200, 200, 200, 200, 200, 200, 200, 47,  47,  47,  47,
    47,  47,  47,  47,  47,  47,  47,  47,  47,  47,  47,  251, 251, 251, 251, 251, 156, 156, 156, 156,
    156, 156, 156, 156, 156, 156, 156, 156, 156, 156, 156, 156, 156, 156, 156, 156, 156, 156, 156, 156,
    156, 156, 156, 156, 48,  48,  48,  48,  48,  48,  48,  48,  118, 118, 118, 118, 118, 118, 118, 118,
    118, 118, 118, 118, 118, 118, 118, 118, 118, 118, 118, 118, 118, 118, 118, 118, 118, 118, 59,  59,
    59,  59,  59,  59,  59,  59,  185, 185, 185, 185, 185, 143, 79,  79,  79,  79,  79,  79,  79,  79,
    79,  37,  37,  37,  37,  37,  37,  37,  37,  37,  37,  37,  37,  37,  37,  37,  37,  37,  37,  37,
    37,  37,  37,  37,  37,  37,  17,  17,  189, 189, 189, 189, 189, 189, 189, 189, 189, 189, 189, 189,
    189, 189, 189, 189, 189, 189, 108, 108, 108, 108, 108, 108, 108, 108, 108, 108, 108, 108, 108, 45,
    45,  20,  20,  20,  20,  20,  20,  20,  20,  20,  20,  20,  20,  20,  20,  20,  20,  20,  20,  20,
    20,  21,  214, 214, 214, 214, 214, 214, 214, 214, 252, 252, 252, 252, 252, 252, 252, 252, 252, 252,
    252, 252, 252, 252, 252, 252, 252, 252, 252, 252, 252, 252, 252, 252, 252, 252, 252, 252, 252, 78,
    67,  67,  67,  67,  67,  67,  67,  67,  67,  67,  67,  67,  67,  67,  67,  67,  67,  67,  67,  67,
    67,  56,  56,  56,  56,  56,  56,  56,  56,  56,  56,  56,  56,  56,  56,  56,  56,  56,  56,  56,
    56,  56,  56,  56,  56,  56,  56,  86,  86,  86,  86,  86,  86,  86,  86,  86,  86,  86,  86,  86,
    86,  86,  86,  86,  86,  86,  86,  86,  86,  86,  86,  86,  86,  86,  86,  24,  24,  24,  24,  24,
    24,  24,  24,  74,  74,  74,  74,  74,  74,  74,  74,  74,  74,  74,  74,  74,  74,  74,  74,  74,
    74,  74,  74,  74,  74,  74,  74,  74,  74,  74,  74,  74,  86,  86,  86,  86,  86,  86,  86,  86,
    86,  86,  86,  86,  86,  86,  86,  86,  86,  86,  78,  78,  78,  78,  78,  158, 158, 158, 158, 158,
    97,  97,  97,  97,  97,  97,  97,  97,  97,  97,  97,  97,  97,  97,  97,  97,  97,  97,  97,  97,
    97,  97,  97,  97,  97,  97,  211, 211, 211, 211, 211, 211, 211, 211, 211, 211, 211, 211, 211, 211,
    211, 211, 158, 158, 158, 158, 158, 158, 158, 158, 158, 158, 158, 158, 158, 158, 158, 158, 158, 158,
    158, 158, 158, 158, 158, 158, 158, 158, 158, 172, 172, 172, 172, 172, 172, 156, 156, 156, 156, 156,
    156, 156, 156, 156, 156, 156, 156, 156, 85,  85,  85,  85,  85,  85,  85,  85,  85,  85,  85,  85,
    85,  85,  85,  85,  85,  85,  85,  85,  85,  85,  85,  85,  85,  4,   4,   4,   4,   4,   4,   80,
    80,  80,  80,  80,  80,  80,  80,  80,  80,  80,  80,  80,  80,  80,  80,  80,  80,  52,  52,  52,
    52,  52,  96,  248, 248, 248, 49,  49,  49,  49,  49,  49,  49,  49,  49,  49,  49,  49,  49,  49,
    49,  203, 203, 203, 140, 140, 140, 140, 140, 140, 140, 140, 140, 140, 140, 140, 140, 140, 140, 140,
    140, 140, 140, 140, 140, 140, 140, 140, 140, 88,  88,  88,  88,  88,  88,  102, 102, 102, 102, 102,
    33,  33,  33,  33,  33,  33,  33,  33,  33,  33,  33,  33,  226, 226, 226, 226, 226, 226, 226, 226,
    226, 226, 226, 226, 105, 105, 105, 105, 105, 105, 105, 105, 105, 105, 200, 200, 142, 142, 142, 142,
    142, 142, 142, 142, 142, 142, 142, 142, 62,  62,  62,  62,  62,  62,  62,  62,  62,  62,  187, 187,
    187, 187, 187, 187, 187, 187, 187, 187, 187, 187, 187, 187, 187, 187, 187, 187, 187, 187, 187, 187,
    187, 187, 116, 116, 116, 116, 116, 116, 116, 116, 116, 116, 116, 116, 116, 116, 116, 96,  96,  96,
    96,  96,  96,  96,  96,  96,  96,  96,  96,  96,  96,  96,  96,  96,  96,  96,  96,  96,  96,  96,
    96,  96,  80,  80,  80,  80,  86,  86,  86,  86,  86,  86,  86,  6,   6,   6,   6,   6,   6,   6,
    6,   6,   6,   6,   6,   6,   6,   6,   6,   6,   58,  58,  58,  58,  58,  58,  58,  58,  58,  58,
    58,  58,  58,  58,  58,  58,  67,  67,  67,  67,  67,  67,  67,  123, 123, 123, 123, 123, 123, 123,
    123, 123, 123, 123, 123, 53,  244, 244, 244, 244, 244, 244, 244, 244, 244, 244, 238, 238, 238, 238,
    238, 238, 238, 238, 238, 114, 114, 139, 139, 139, 139, 139, 139, 139, 139, 139, 139, 139, 139, 139,
    139, 139, 139, 139, 139, 139, 96,  96,  96,  96,  96,  96,  96,  96,  96,  96,  96,  96,  96,  96,
    96,  96,  96,  96,  96,  225, 225, 225, 225, 225, 225, 225, 225, 225, 225, 225, 225, 225, 225, 225,
    225, 225, 225, 225, 225, 225, 225, 225, 225, 225, 225, 225, 225, 225, 49,  49,  49,  49,  49,  49,
    49,  49,  49,  49,  49,  49,  49,  49,  49,  49,  49,  49,  49,  49,  49,  49,  49,  49,  49,  184,
    184, 184, 184, 184, 184, 184, 184, 184, 184, 184, 184, 184, 184, 184, 184, 184, 184, 184, 184, 184,
    184, 184, 184, 184, 184, 184, 184, 2,   2,   2,   2,   2,   2,   2,   2,   2,   2,   2,   2,   2,
    32,  32,  32,  32,  32,  152, 152, 152, 152, 152, 152, 152, 152, 152, 152, 152, 152, 152, 152, 152,
    152, 152, 98,  98,  98,  98,  98,  98,  98,  98,  98,  98,  98,  98,  190, 190, 190, 190, 190, 190,
    190, 190, 194, 194, 194, 194, 194, 194, 194, 194, 194, 194, 194, 194, 194, 146, 146, 146, 146, 146,
    146, 146, 146, 146, 146, 146, 146, 146, 146, 146, 146, 146, 110, 110, 110, 110, 110, 110, 110, 110,
    110, 110, 110, 110, 110, 110, 110, 110, 110, 110, 207, 227, 227, 227, 227, 227, 227, 227, 227, 227,
    227, 227, 227, 227, 227, 227, 227, 227, 227, 227, 227, 227, 227, 227, 227, 227, 227, 227, 227, 227,
    6,   6,   6,   6,   6,   6,   6,   6,   6,   6,   6,   6,   6,   6,   6,   6,   6,   6,   6,   6,
    6,   6,   6,   6,   107, 107, 107, 107, 107, 107, 107, 107, 107, 41,  41,  41,  41,  41,  41,  41,
    41,  41,  41,  40,  40,  40,  40,  40,  40,  40,  40,  40,  40,  40,  40,  40,  40,  40,  40,  40,
    40,  40,  40,
};

const surv_m23_input = [_]u8{
    40,  145, 145, 145, 145, 145, 145, 145, 39,  39,  39,  39,  39,  39,  39,  39,  39,  39,  39,  39,
    39,  39,  39,  39,  39,  39,  39,  96,  96,  96,  96,  96,  96,  96,  97,  97,  97,  97,  97,  97,
    97,  97,  97,  97,  97,  97,  97,  97,  97,  97,  97,  97,  97,  97,  97,  97,  97,  97,  97,  97,
    97,  157, 157, 157, 157, 157, 157, 157, 157, 157, 157, 157, 157, 157, 157, 157, 157, 157, 157, 157,
    157, 157, 203, 203, 203, 203, 203, 203, 203, 203, 203, 203, 203, 203, 203, 203, 203, 203, 203, 203,
    203, 203, 203, 203, 223, 223, 223, 223, 223, 223, 223, 223, 223, 223, 223, 223, 223, 223, 223, 223,
    223, 223, 223, 223, 127, 127, 127, 127, 127, 127, 127, 127, 171, 171, 171, 171, 171, 171, 171, 171,
    171, 171, 120, 120, 120, 120, 120, 120, 120, 120, 120, 120, 120, 120, 120, 120, 120, 120, 120, 120,
    120, 120, 120, 120, 120, 120, 120, 249, 249, 249, 249, 249, 249, 249, 249, 249, 249, 249, 249, 249,
    249, 249, 211, 211, 211, 211, 211, 211, 211, 211, 211, 211, 211, 211, 211, 100, 100, 100, 100, 100,
    100, 100, 100, 100, 100, 100, 100, 100, 100, 100, 100, 100, 147, 147, 147, 147, 147, 147, 147, 147,
    147, 147, 240, 240, 240, 240, 240, 240, 240, 240, 240, 84,  84,  84,  84,  84,  84,  84,  84,  84,
    84,  84,  84,  84,  84,  84,  84,  84,  84,  84,  84,  84,  84,  84,  84,  84,  84,  234, 234, 234,
    234, 234, 234, 234, 234, 234, 234, 234, 234, 234, 234, 234, 234, 234, 234, 147, 147, 147, 147, 147,
    147, 147, 147, 147, 147, 147, 147, 147, 147, 147, 147, 147, 132, 132, 132, 132, 132, 132, 132, 132,
    223, 223, 111, 111, 111, 111, 111, 111, 111, 111, 111, 111, 111, 111, 111, 111, 111, 111, 111, 111,
    111, 111, 111, 111, 111, 111, 111, 111, 111, 246, 246, 246, 246, 246, 246, 246, 246, 246, 246, 246,
    246, 246, 246, 246, 246, 246, 246, 246, 246, 246, 246, 246, 246, 246, 11,  11,  11,  11,  11,  11,
    11,  11,  11,  11,  11,  11,  11,  11,  11,  11,  11,  11,  11,  11,  11,  11,  11,  11,  11,  11,
    12,  12,  12,  12,  19,  19,  19,  19,  19,  19,  19,  19,  19,  50,  50,  50,  50,  50,  50,  50,
    50,  50,  50,  50,  50,  50,  50,  50,  188, 188, 188, 188, 188, 188, 188, 188, 188, 188, 188, 188,
    188, 188, 188, 188, 188, 188, 188, 188, 188, 188, 188, 188, 188, 188, 127, 127, 127, 127, 127, 127,
    127, 127, 127, 127, 127, 127, 127, 127, 127, 127, 127, 127, 127, 127, 127, 127, 45,  45,  45,  45,
    45,  45,  45,  45,  45,  11,  11,  11,  11,  11,  11,  11,  11,  11,  11,  202, 202, 202, 9,   9,
    9,   105, 105, 105, 105, 36,  36,  36,  36,  36,  36,  36,  36,  36,  36,  36,  36,  36,  36,  36,
    36,  36,  36,  36,  36,  36,  36,  36,  36,  168, 168, 168, 168, 168, 168, 168, 168, 168, 168, 168,
    168, 168, 168, 168, 168, 168, 168, 168, 168, 168, 168, 11,  11,  11,  11,  219, 219, 219, 219, 219,
    219, 219, 219, 219, 219, 219, 219, 219, 219, 219, 219, 219, 219, 219, 219, 219, 219, 219, 219, 219,
    219, 219, 219, 90,  90,  90,  90,  90,  90,  109, 109, 109, 109, 109, 109, 109, 109, 109, 109, 109,
    109, 109, 109, 109, 109, 109, 109, 109, 182, 182, 182, 182, 182, 182, 182, 182, 182, 182, 182, 182,
    182, 182, 182, 182, 182, 182, 182, 182, 182, 182, 182, 182, 182, 182, 142, 142, 142, 142, 142, 142,
    142, 142, 232, 232, 232, 232, 232, 232, 232, 209, 209, 209, 209, 45,  45,  45,  45,  45,  45,  45,
    45,  45,  45,  45,  45,  45,  140, 140, 140, 140, 140, 140, 140, 140, 140, 140, 140, 140, 140, 214,
    214, 214, 214, 214, 214, 214, 214, 214, 214, 214, 214, 214, 214, 214, 214, 214, 214, 214, 214, 5,
    5,   5,   5,   252, 252, 252, 252, 252, 252, 252, 252, 205, 205, 205, 205, 205, 205, 205, 205, 205,
    205, 205, 205, 205, 205, 205, 205, 205, 245, 245, 245, 245, 245, 245, 245, 245, 245, 245, 245, 245,
    245, 245, 245, 245, 245, 245, 245, 245, 245, 245, 245, 245, 245, 245, 245, 245, 52,  52,  52,  52,
    52,  52,  52,  52,  52,  52,  52,  52,  52,  52,  52,  52,  52,  52,  52,  52,  252, 252, 252, 252,
    252, 252, 252, 252, 252, 252, 252, 252, 252, 252, 252, 252, 252, 252, 252, 252, 252, 252, 252, 177,
    177, 177, 177, 177, 177, 177, 177, 177, 177, 177, 177, 177, 177, 177, 177, 177, 177, 177, 177, 177,
    177, 177, 177, 177, 177, 177, 177, 159, 159, 159, 159, 159, 159, 159, 159, 159, 159, 159, 159, 159,
    159, 159, 159, 159, 159, 93,  93,  93,  93,  93,  93,  93,  93,  93,  93,  93,  93,  93,  93,  93,
    93,  93,  93,  93,  93,  93,  93,  93,  93,  93,  93,  57,  57,  57,  57,  57,  57,  57,  57,  57,
    57,  57,  57,  116, 116, 116, 116, 116, 116, 116, 116, 116, 116, 116, 116, 116, 116, 116, 116, 116,
    116, 116, 116, 116, 116, 116, 171, 171, 171, 171, 171, 171, 171, 171, 171, 171, 171, 171, 171, 171,
    171, 171, 171, 171, 171, 101, 101, 101, 101, 101, 101, 101, 101, 101, 101, 101, 101, 101, 101, 101,
    101, 101, 101, 134, 134, 134, 134, 134, 134, 134, 134, 134, 134, 134, 134, 134, 134, 134, 134, 134,
    134, 134, 134, 134, 134, 134, 134, 134, 134, 77,  77,  77,  77,  87,  87,  87,  87,  87,  87,  87,
    87,  87,  87,  87,  87,  87,  87,  87,  87,  87,  87,  87,  87,  87,  87,  87,  87,  87,  159, 220,
    220, 220, 220, 220, 220, 220, 220, 220, 220, 220, 247, 247, 247, 247, 247, 247, 247, 247, 247, 247,
    247, 247, 247, 247, 247, 247, 247, 247, 247, 247, 247, 247, 247, 247, 109, 109, 109, 109, 109, 109,
    109, 109, 109, 109, 109, 109, 109, 109, 109, 109, 109, 109, 109, 109, 109, 109, 109, 109, 109, 180,
    180, 180, 180, 180, 180, 180, 180, 180, 180, 180, 180, 180, 180, 180, 180, 180, 180, 180, 180, 180,
    180, 180, 180, 180, 180, 180, 180, 180, 194, 194, 194, 194, 194, 194, 194, 194, 194, 194, 194, 194,
    194, 59,  59,  59,  59,  59,  59,  59,  59,  59,  59,  59,  59,  59,  59,  59,  59,  59,  59,  59,
    59,  97,  97,  97,  97,  97,  97,  97,  97,  97,  97,  97,  97,  97,  252, 252, 252, 136, 136, 136,
    219, 219, 219, 219, 219, 219, 219, 219, 219, 219, 219, 219, 219, 18,  18,  18,  18,  18,  18,  18,
    18,  18,  18,  18,  66,  66,  66,  66,  66,  66,  66,  66,  66,  66,  66,  66,  66,  66,  66,  66,
    66,  66,  66,  66,  66,  66,  66,  66,  56,  56,  56,  56,  56,  56,  56,  56,  56,  56,  56,  56,
    56,  56,  56,  56,  56,  56,  56,  56,  56,  56,  56,  56,  56,  56,  56,  14,  14,  14,  14,  14,
    14,  14,  14,  14,  14,  14,  14,  14,  14,  14,  14,  14,  14,  209, 209, 209, 209, 209, 209, 209,
    209, 209, 209, 209, 209, 209, 209, 209, 209, 209, 209, 209, 209, 209, 209, 209, 209, 209, 201, 201,
    201, 201, 201, 201, 2,   2,   2,   2,   2,   2,   2,   144, 144, 144, 144, 144, 144, 144, 144, 144,
    144, 144, 144, 144, 144, 144, 144, 144, 132, 49,  49,  49,  49,  49,  49,  49,  49,  49,  49,  49,
    49,  49,  49,  49,  49,  49,  49,  49,  49,  49,  49,  49,  49,  49,  49,  49,  49,  150, 150, 150,
    150, 150, 150, 150, 150, 150, 150, 150, 150, 150, 150, 150, 150, 150, 150, 150, 150, 150, 150, 150,
    150, 150, 200, 200, 200, 200, 200, 200, 200, 200, 200, 200, 200, 200, 200, 200, 200, 200, 249, 249,
    249, 249, 249, 249, 249, 249, 249, 249, 249, 249, 249, 249, 249, 22,  22,  22,  22,  22,  22,  22,
    22,  22,  22,  22,  22,  22,  22,  22,  22,  22,  22,  22,  22,  22,  22,  22,  22,  22,  22,  92,
    92,  92,  92,  68,  68,  68,  68,  68,  68,  68,  68,  68,  68,  68,  68,  68,  68,  165, 165, 165,
    165, 165, 165, 165, 165, 165, 165, 165, 165, 165, 165, 165, 165, 165, 165, 220, 220, 220, 220, 220,
    220, 220, 220, 220, 220, 220, 220, 220, 220, 220, 220, 220, 220, 220, 220, 255, 255, 255, 255, 255,
    255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 200, 200, 200, 200,
    200, 200, 200, 200, 200, 200, 200, 200, 200, 59,  59,  59,  59,  59,  59,  59,  59,  59,  59,  59,
    1,   1,   1,   1,   1,   1,   1,   1,   1,   1,   1,   1,   1,   1,   1,   1,   1,   1,   239, 239,
    239, 239, 239, 239, 239, 239, 239, 239, 239, 239, 239, 239, 239, 239, 239, 237, 237, 237, 237, 237,
    237, 237, 237, 237, 237, 237, 237, 237, 237, 237, 237, 237, 237, 237, 237, 237, 237, 214, 214, 214,
    214, 214, 214, 214, 214, 214, 214, 214, 214, 214, 214, 214, 214, 214, 214, 214, 214, 103, 103, 103,
    103, 103, 103, 103, 103, 103, 103, 103, 103, 103, 103, 103, 103, 103, 157, 157, 157, 157, 157, 157,
    157, 157, 170, 170, 170, 170, 170, 170, 170, 156, 156, 156, 156, 156, 156, 156, 156, 156, 156, 156,
    156, 156, 146, 146, 146, 146, 146, 146, 146, 146, 146, 146, 146, 146, 146, 146, 146, 146, 146, 146,
    146, 146, 146, 146, 126, 126, 126, 126, 126, 126, 126, 126, 34,  34,  34,  34,  34,  34,  34,  34,
    34,  34,  34,  34,  34,  34,  34,  34,  34,  34,  34,  210, 210, 210, 210, 210, 210, 210, 210, 210,
    210, 210, 11,  11,  11,  11,  11,  11,  11,  11,  11,  11,  11,  11,  11,  11,  11,  11,  11,  11,
    11,  11,  11,  11,  11,  11,  11,  11,  11,  142, 142, 142, 142, 142, 142, 142, 142, 142, 142, 142,
    142, 142, 142, 142, 142, 142, 142, 62,  62,  62,  62,  62,  62,  62,  62,  62,  62,  62,  62,  182,
    182, 182, 182, 182, 182, 182, 182, 182, 182, 182, 182, 182, 182, 182, 182, 182, 182, 59,  59,  59,
    59,  59,  59,  59,  59,  59,  59,  59,  59,  189, 189, 189, 189, 189, 189, 189, 189, 189, 23,  23,
    23,  23,  23,  23,  23,  23,  23,  23,  176, 176, 176, 176, 176, 10,  10,  10,  10,  10,  10,  10,
    10,  10,  10,  10,  10,  10,  10,  10,  10,  10,  10,  10,  10,  10,  10,  10,  10,  27,  27,  27,
    27,  27,  27,  27,  163, 206, 206, 206, 206, 206, 206, 206, 206, 206, 206, 206, 206, 206, 206, 206,
    206, 206, 206, 206, 206, 122, 122, 122, 122, 122, 122, 122, 122, 122, 122, 122, 122, 122, 122, 122,
    122, 122, 122, 122, 122, 122, 122, 122, 244, 244, 244, 244, 244, 244, 244, 244, 244, 244, 244, 244,
    244, 244, 202, 202, 202, 202, 202, 202, 202, 202, 202, 202, 202, 202, 202, 202, 202, 202, 202, 202,
    202, 202, 202, 202, 202, 202, 183, 183, 183, 183, 183, 183, 183, 183, 183, 183, 183, 183, 183, 183,
    183, 183, 183, 183, 183, 183, 183, 183, 183, 183, 183, 183, 183, 183, 183, 34,  34,  34,  34,  34,
    34,  34,  34,  34,  34,  34,  34,  34,  34,  34,  34,  34,  34,  34,  34,  34,  34,  34,  34,  219,
    219, 219, 219, 219, 219, 219, 219, 187, 187, 187, 187, 187, 187, 187, 187, 187, 187, 187, 187, 187,
    187, 187, 187, 187, 187, 187, 0,   0,   0,   0,   0,   0,   0,   0,   0,   0,   0,   0,   0,   0,
    0,   0,   8,   8,   8,   8,   72,  72,  72,  72,  72,  72,  72,  72,  72,  72,  72,  72,  72,  72,
    72,  72,  72,  72,  72,  72,  72,  72,  72,  72,  72,  72,  72,  72,  180, 180, 180, 180, 180, 180,
    180, 180, 180, 180, 180, 180, 180, 180, 180, 180, 180, 180, 81,  81,  157, 157, 157, 157, 157, 157,
    157, 157, 157, 157, 157, 157, 157, 173, 173,
};

const surv_m24_dict = [_]u8{
    176, 176, 176, 176, 176, 176, 176, 176, 176, 176, 176, 176, 176, 176, 176, 176, 233, 233, 233, 233,
    233, 233, 233, 33,  33,  33,  33,  33,  33,  33,  33,  33,  33,  33,  33,  33,  33,  33,  33,  33,
    33,  33,  33,  33,  33,  33,  33,  12,  12,  12,  12,  12,  12,  12,  12,  12,  12,  12,  12,  12,
    12,  12,  12,  12,  12,  12,  12,  12,  12,  12,  233, 233, 233, 233, 233, 233, 233, 233, 233, 233,
    233, 233, 233, 233, 233, 233, 30,  30,  30,  30,  30,  30,  30,  30,  30,  30,  30,  30,  30,  30,
    30,  30,  30,  30,  43,  43,  43,  43,  43,  43,  43,  43,  43,  43,  43,  43,  43,  43,  43,  43,
    43,  43,  43,  43,  43,  43,  43,  96,  96,  96,  96,  96,  96,  96,  100, 100, 100, 100, 100, 100,
    100, 100, 100, 100, 100, 100, 100, 100, 100, 100, 100, 100, 100, 100, 100, 162, 162, 162, 162, 162,
    162, 162, 162, 162, 162, 162, 162, 162, 162, 162, 162, 162, 162, 162, 162, 144, 144, 144, 144, 144,
    144, 144, 144, 144, 144, 144, 144, 144, 144, 144, 144, 226, 226, 226, 226, 226, 226, 226, 226, 226,
    226, 226, 226, 226, 226, 226, 226, 226, 226, 226, 226, 226, 226, 226, 226, 226, 180, 180, 180, 180,
    180, 180, 180, 180, 180, 180, 180, 180, 180, 180, 180, 180, 180, 180, 180, 180, 180, 180, 57,  36,
    36,  36,  36,  36,  36,  36,  36,  36,  36,  36,  36,  36,  36,  36,  36,  36,  36,  99,
};

const surv_m24_input = [_]u8{
    176, 176, 176, 176, 176, 221, 221, 221, 221, 221, 221, 221, 221, 221, 221, 221, 221, 221, 234, 234,
    234, 234, 234, 234, 234, 234, 191, 191, 191, 191, 191, 191, 191, 191, 191, 191, 191, 191, 191, 182,
    182, 182, 182, 169, 169, 169, 169, 169, 169, 169, 169, 169, 169, 169, 169, 169, 169, 169, 169, 169,
    169, 160, 160, 160, 160, 160, 160, 160, 218, 218, 218, 218, 218, 218, 218, 218, 218, 218, 218, 218,
    218, 218, 218, 218, 218, 218, 218, 218, 218, 218, 218, 218, 218, 242, 242, 242, 242, 242, 242, 242,
    242, 242, 242, 242, 242, 242, 242, 242, 158, 158, 158, 158, 158, 158, 158, 158, 158, 158, 158, 158,
    158, 159, 159, 159, 159, 159, 159, 159, 159, 159, 159, 155, 155, 155, 155, 155, 155, 155, 155, 155,
    155, 155, 155, 155, 155, 82,  82,  82,  82,  82,  82,  82,  82,  82,  82,  82,  82,  82,  82,  82,
    82,  82,  82,  228, 228, 228, 228, 228, 228, 41,  41,  41,  41,  41,  41,  41,  41,  41,  41,  41,
    41,  41,  41,  41,  41,  41,  41,  41,  41,  41,  41,  41,  41,  41,  41,  41,  20,  20,  20,  20,
    20,  20,  20,  20,  20,  20,  20,  20,  20,  20,  20,  20,  20,  20,  20,  20,  20,  27,  27,  27,
    27,  27,  27,  27,  27,  27,  27,  27,  27,  27,  27,  27,  27,  27,  73,  73,  73,  73,  73,  73,
    73,  73,  73,  73,  73,  43,  247, 247, 247, 247, 247, 247, 247, 247, 226, 226, 226, 226, 226, 226,
    226, 45,  45,  45,  45,  45,  45,  45,  45,  45,  210, 16,  16,  16,  16,  16,  16,  16,  16,  16,
    16,  16,  16,  16,  16,  16,  16,  16,  16,  16,  16,  16,  16,  16,  16,  174, 174, 174, 174, 174,
    174, 174, 174, 174, 174, 174, 174, 22,  22,  22,  22,  22,  22,  22,  22,  22,  22,  22,  22,  165,
    165, 165, 165, 165, 165, 165, 165, 165, 165, 165, 165, 165, 165, 165, 165, 165, 165, 165, 56,  56,
    56,  56,  56,  56,  56,  56,  56,  56,  56,  56,  56,  56,  56,  56,  56,  56,  56,  56,  56,  56,
    56,  56,  56,  56,  56,  56,  56,  98,  98,  98,  98,  98,  98,  98,  98,  98,  98,  98,  98,  98,
    98,  98,  98,  98,  98,  98,  98,  98,  242, 242, 242, 242, 242, 242, 242, 242, 242, 242, 242, 242,
    242, 242, 242, 242, 242, 242, 242, 235, 235, 235, 235, 235, 235, 235, 235, 235, 235, 235, 235, 235,
    235, 235, 235, 235, 235, 235, 235, 235, 235, 235, 235, 235, 235, 235, 246, 65,  65,  65,  65,  65,
    65,  65,  65,  65,  65,  65,  65,  65,  65,  65,  65,  65,  65,  65,  65,  65,  65,  65,  65,  65,
    65,  65,  65,  65,  0,   0,   0,   0,   0,   0,   0,   20,  20,  20,  20,  20,  20,  20,  20,  20,
    20,  20,  20,  20,  20,  20,  20,  20,  20,  20,  20,  20,  20,  20,  20,  153, 153, 153, 153, 153,
    153, 153, 153, 153, 153, 153, 153, 153, 153, 228, 228, 228, 228, 228, 228, 228, 228, 228, 228, 228,
    248, 248, 248, 248, 248, 248, 248, 248, 248, 248, 248, 248, 248, 248, 248, 130, 130, 130, 130, 130,
    130, 130, 130, 130, 130, 130, 130, 130, 130, 130, 130, 130, 130, 130, 130, 130, 130, 130, 196, 196,
    196, 196, 196, 196, 196, 196, 196, 196, 196, 196, 196, 196, 196, 196, 196, 196, 196, 196, 196, 126,
    126, 126, 126, 126, 126, 126, 126, 126, 126, 126, 126, 126, 126, 126, 126, 126, 126, 126, 126, 126,
    198, 198, 198, 198, 198, 198, 198, 198, 198, 198, 198, 198, 198, 198, 198, 198, 198, 198, 198, 198,
    198, 198, 198, 198, 189, 189, 189, 189, 189, 189, 189, 189, 189, 189, 189, 189, 189, 189, 189, 189,
    189, 189, 189, 189, 99,  99,  118, 118, 118, 118, 118, 118, 118, 118, 118, 118, 118, 118, 118, 118,
    118, 118, 118, 118, 118, 81,  81,  249, 249, 249, 249, 249, 249, 249, 249, 222, 222, 222, 222, 222,
    222, 222, 222, 222, 222, 222, 222, 222, 222, 222, 222, 222, 246, 246, 246, 246, 246, 246, 176, 176,
    176, 176, 33,  33,  33,  33,  33,  33,  33,  33,  33,  33,  33,  33,  33,  33,  33,  33,  33,  33,
    33,  33,  42,  42,  42,  42,  42,  42,  42,  42,  42,  42,  42,  42,  42,  42,  42,  42,  42,  42,
    42,  42,  42,  42,  42,  42,  42,  42,  42,  42,  29,  29,  29,  29,  29,  29,  29,  29,  29,  29,
    29,  193, 193, 61,  61,  61,  61,  61,  61,  61,  61,  61,  61,  61,  61,  61,  61,  61,  61,  61,
    61,  61,  61,  61,  61,  61,  61,  61,  28,  28,  28,  28,  28,  28,  28,  28,  28,  28,  28,  28,
    28,  28,  28,  28,  28,  28,  28,  28,  28,  28,  28,  28,  28,  102, 102, 102, 102, 102, 102, 102,
    102, 102, 102, 102, 102, 102, 102, 102, 102, 102, 102, 102, 102, 102, 102, 102, 188, 188, 188, 188,
    131, 131, 131, 131, 131, 131, 131, 131, 131, 131, 131, 131, 131, 131, 131, 112, 112, 112, 112, 112,
    112, 112, 18,  18,  18,  18,  18,  18,  18,  18,  18,  18,  18,  18,  18,  18,  18,  18,  18,  18,
    18,  18,  18,  18,  18,  18,  18,  18,  18,  18,  36,  36,  36,  36,  36,  36,  36,  36,  36,  36,
    36,  36,  36,  36,  36,  36,  36,  36,  36,  36,  36,  36,  36,  36,  36,  36,  36,  169, 169, 169,
    169, 169, 169, 114, 114, 114, 114, 114, 114, 114, 114, 114, 114, 114, 114, 114, 114, 114, 114, 114,
    114, 114, 114, 114, 114, 193, 62,  62,  62,  62,  62,  62,  165, 165, 165, 165, 165, 165, 165, 165,
    165, 165, 165, 165, 165, 165, 165, 165, 165, 165, 165, 165, 165, 165, 165, 165, 6,   6,   6,   6,
    6,   6,   6,   6,   6,   6,   6,   6,   6,   6,   6,   6,   6,   218, 218, 218, 218, 218, 218, 218,
    218, 218, 218, 218, 218, 218, 218, 218, 218, 218, 218, 218, 218, 218, 36,  36,  36,  36,  36,  36,
    36,  36,  36,  36,  36,  179, 179, 85,  85,  85,  85,  85,  85,  85,  85,  85,  85,  85,  85,  85,
    85,  85,  85,  85,  85,  85,  85,  177, 177, 177, 177, 50,  50,  50,  50,  50,  50,  50,  50,  50,
    50,  50,  50,  50,  50,  50,  50,  50,  50,  12,  12,  12,  12,  12,  12,  12,  12,  12,  12,  12,
    12,  12,  12,  12,  12,  12,  12,  12,  12,  12,  12,  12,  12,  12,  12,  12,  12,  12,  108, 108,
    108, 108, 108, 108, 108, 108, 108, 108, 108, 108, 108, 212, 212, 212, 212, 247, 51,  51,  51,  51,
    166, 232, 145, 145, 145, 145, 145, 145, 145, 145, 145, 145, 145, 145, 145, 145, 145, 145, 145, 221,
    221, 221, 221, 221, 221, 221, 221, 221, 221, 221, 221, 221, 221, 221, 221, 29,  29,  29,  29,  29,
    29,  29,  29,  29,  29,  29,  29,  29,  29,  29,  29,  29,  29,  29,  29,  29,  29,  29,  29,  29,
    29,  29,  185, 185, 185, 185, 185, 185, 185, 185, 185, 185, 185, 185, 185, 112, 112, 112, 112, 112,
    112, 112, 112, 112, 112, 112, 112, 112, 112, 112, 112, 112, 112, 112, 112, 112, 112, 112, 112, 113,
    113, 113, 113, 113, 113, 113, 113, 113, 113, 113, 113, 113, 113, 113, 113, 113, 113, 113, 113, 113,
    113, 113, 113, 113, 113, 113, 113, 113, 164, 164, 164, 164, 164, 164, 164, 164, 164, 164, 164, 164,
    164, 164, 164, 164, 164, 164, 164, 164, 164, 164, 164, 164, 164, 164, 219, 219, 219, 219, 219, 219,
    219, 219, 219, 219, 219, 219, 219, 219, 219, 219, 219, 219, 219, 219, 219, 219, 219, 219, 219, 219,
    169, 169, 169, 169, 169, 169, 169, 169, 169, 169, 169, 169, 69,  69,  174, 174, 174, 174, 174, 174,
    174, 174, 174, 174, 174, 90,  90,  90,  254, 254, 254, 254, 254, 254, 254, 254, 254, 254, 254, 254,
    254, 254, 254, 254, 254, 254, 254, 254, 254, 254, 254, 254, 181, 181, 181, 181, 181, 58,  58,  58,
    58,  58,  58,  58,  58,  58,  58,  58,  58,  58,  58,  58,  58,  58,  58,  58,  91,  91,  91,  91,
    91,  91,  91,  91,  91,  91,  91,  91,  91,  91,  91,  91,  91,  91,  91,  91,  91,  91,  7,   7,
    7,   7,   7,   121, 121, 121, 121, 121, 121, 121, 121, 121, 121, 121, 121, 121, 88,  88,  88,  88,
    88,  88,  88,  88,  88,  88,  88,  88,  88,  88,  88,  88,  88,  88,  88,  88,  88,  88,  88,  81,
    81,  81,  81,  81,  81,  81,  81,  81,  81,  81,  81,  81,  81,  81,  35,  35,  35,  35,  35,  35,
    35,  35,  35,  35,  35,  35,  35,  32,  32,  32,  32,  32,  32,  32,  32,  32,  32,  32,  32,  32,
    32,  32,  32,  32,  32,  32,  32,  32,  46,  46,  46,  46,  46,  46,  46,  46,  46,  46,  46,  46,
    46,  46,  46,  46,  46,  46,  46,  46,  46,  46,  46,  46,  46,  149, 54,  54,  54,  54,  54,  54,
    54,  54,  54,  54,  54,  54,  54,  54,  54,  54,  54,  54,  54,  54,  54,  54,  64,  64,  64,  64,
    64,  64,  64,  64,  64,  64,  64,  64,  64,  64,  64,  64,  64,  64,  64,  64,  64,  138, 138, 138,
    138, 138, 138, 138, 138, 138, 138, 138, 138, 138, 138, 138, 138, 138, 138, 138, 138, 138, 138, 112,
    112, 112, 112, 112, 112, 112, 112, 112, 112, 112, 112, 112, 112, 112, 112, 112, 112, 112, 112, 112,
    112, 112, 112, 112, 112, 112, 112, 112, 127, 127, 127, 127, 127, 127, 127, 127, 127, 127, 127, 127,
    127, 127, 211, 211, 211, 211, 211, 211, 211, 211, 211, 211, 211, 211, 211, 211, 211, 211, 211, 211,
    211, 211, 211, 211, 211, 211, 211, 211, 211, 211, 106, 106, 106, 106, 106, 106, 106, 106, 106, 106,
    106, 106, 106, 106, 106, 106, 106, 106, 112, 112, 112, 112, 112, 112, 112, 112, 190, 190, 190, 190,
    190, 190, 190, 190, 190, 190, 190, 190, 190, 190, 190, 190, 190, 190, 190, 190, 190, 190, 190, 190,
    190, 190, 190, 190, 190, 92,  92,  92,  92,  194, 194, 194, 194, 194, 194, 194, 194, 194, 194, 194,
    194, 194, 194, 194, 194, 194, 194, 194, 194, 194, 194, 194, 194, 194, 194, 185, 185, 185, 185, 25,
    25,  25,  117, 117, 117, 117, 117, 117, 117, 117, 117, 117, 117, 117, 117, 117, 117, 117, 117, 117,
    117, 117, 117, 109, 109, 109, 109, 109, 109, 109, 109, 109, 109, 109, 109, 109, 109, 109, 109, 109,
    109, 109, 109, 109, 109, 109, 109, 109, 109, 109, 109, 174, 174, 174, 174, 174, 174, 174, 174, 174,
    174, 174, 174, 174, 174, 174, 174, 174, 174, 174, 211, 211, 211, 211, 211, 211, 211, 211, 211, 211,
    211, 211, 211, 211, 211, 211, 211, 211, 211, 211, 211, 211, 211, 211, 211, 59,  59,  59,  59,  59,
    59,  200, 200, 200, 200, 200, 200, 200, 200, 200, 200, 200, 200, 200, 200, 200, 200, 200, 200, 200,
    200, 200, 200, 200, 200, 80,  80,  15,  15,  15,  15,  15,  15,  15,  15,  15,  15,  15,  15,  15,
    15,  15,  15,  15,  15,  15,  15,  15,  15,  15,  77,  77,  77,  77,  77,  77,  77,  77,  27,  27,
    27,  27,  242, 242, 242, 242, 242, 242, 242, 242, 242, 242, 242, 242, 242, 242, 242, 242, 242, 242,
    85,  85,  85,  85,  85,  85,  85,  85,  217, 217, 217, 217, 69,  69,  69,  69,  69,  69,  69,  69,
    69,  69,  69,  69,  69,  163, 163, 163, 163, 163, 163, 163, 163, 163, 163, 163, 163, 163, 163, 163,
    163, 163, 163, 163, 163, 163, 163, 163, 163, 163, 163, 245, 245, 245, 245, 245, 245, 245, 245, 245,
    245, 245, 245, 245, 139, 139, 139, 139, 139, 139, 139, 139, 139, 139, 139, 139, 139, 139, 139, 139,
    139, 159, 159, 159, 159, 159, 159, 159, 159, 159, 159, 159, 159, 159, 159, 159, 159, 159, 159, 159,
    159, 159, 159, 159, 159, 220, 220, 220, 220, 220, 220, 220, 220, 220, 220, 19,  19,  19,  19,  19,
    19,  19,  19,  19,  19,  19,  19,  19,  19,  19,  19,  19,  19,  19,  19,  19,  19,  19,  19,  19,
    193, 193, 193, 193, 193, 193, 193, 193, 193, 193, 193, 193, 193, 193, 193, 9,   9,   9,   9,   9,
    9,   9,   231, 231, 231, 231, 14,  14,  14,  14,  0,   0,   0,   0,   0,   0,   0,   0,   0,   0,
    0,   0,   0,   0,   170, 170, 170, 170, 197, 197, 197, 197, 197, 197, 197, 197, 197, 197, 197, 197,
    197, 197, 197, 197, 197, 197, 197, 197, 197, 197, 197, 197, 197, 197, 197, 197, 197, 171, 171, 171,
    171, 171, 171, 171, 171, 171, 171, 171, 171, 171, 171, 171, 171, 233, 233, 233, 233, 233, 233, 233,
    233, 233, 233, 233, 233, 233, 233, 233, 233, 233, 233, 233, 233, 233, 233, 233, 233, 233, 96,  96,
    96,  96,  96,  96,  96,  96,  96,  96,  96,  96,  96,  96,  203, 203, 203, 203, 203, 203, 203, 203,
    203, 203, 203, 203, 203, 203, 203, 203, 203, 203, 203, 203, 203, 203, 203, 50,  50,  50,  50,  50,
    50,  50,  50,  50,  50,  50,  50,  50,  50,  50,  50,  50,  50,  50,  244, 244, 244, 244, 244, 244,
    244, 244, 244, 244, 244, 244, 244, 244, 244, 244, 244, 244, 244, 244, 244, 244, 244, 244, 244, 244,
    244, 244, 244, 24,  24,  24,  24,  24,  24,  24,  24,  24,  24,  24,  24,  24,  132, 132, 120, 120,
    141, 141, 141, 141, 141, 141, 141, 141, 141, 141, 141, 141, 141, 141, 141, 141, 141, 141, 141, 141,
    141, 141, 141, 71,  71,  71,  52,  52,  52,  52,  52,  52,  52,  87,  87,  87,  87,  87,  87,  87,
    87,  253, 253, 253, 253, 253, 253, 253, 253, 253, 253, 253, 253, 253, 253, 253, 253, 55,  55,  55,
    55,  55,  55,  55,  55,  55,  55,  128, 128, 128, 128, 128, 128, 128, 128, 128, 128, 128, 128, 128,
    128, 128, 128, 128, 128, 107, 107, 107, 107, 107, 107, 107, 107, 107, 107, 107, 107, 107, 107, 107,
    107, 107, 107, 107, 107, 107, 107, 107, 107, 107, 107, 114, 114, 114, 114, 114, 114, 114, 114, 114,
    114, 114, 114, 114, 114, 114, 114, 114, 114, 114, 114, 114, 114, 114, 114, 114, 114, 114, 203, 203,
    203, 203, 203, 203, 203, 203, 203, 203, 203, 203, 203, 203, 203, 203, 203, 203, 203, 203, 203, 203,
    203, 203, 203, 203, 203, 203, 203, 0,   0,   0,   0,   0,   0,   0,   0,   0,   0,   0,   0,   0,
    0,   0,   0,   0,   175, 175, 175, 175, 175, 175, 175, 175, 175, 175, 175, 175, 175, 175, 175, 175,
    175, 175, 175, 175, 175, 175, 175, 175, 175, 175, 175, 175, 134, 134, 134, 134, 134, 234, 234, 234,
    234, 234, 234, 234, 234, 234, 234, 234, 234, 234, 234, 234, 234, 234, 234, 234, 234, 234, 234, 109,
    109, 109, 109, 109, 109, 109, 109, 109, 109, 109, 109, 109, 109, 109, 109, 99,  99,  99,  99,  99,
    99,  99,  99,  99,  99,  99,  99,  99,  99,  99,  99,  99,  99,  99,  99,  99,  99,  99,  99,  99,
    99,  99,  99,  253, 253, 253, 253, 253, 253, 253, 253, 253, 253, 253, 253, 253, 253, 253, 86,  86,
    86,  86,  86,  86,  86,  86,  86,  86,  86,  86,  86,  86,  86,  86,  86,  21,  52,  52,  52,  52,
    52,  52,  52,  52,  52,  52,  52,  52,  52,  52,  52,  52,  52,  52,  52,  52,  52,  52,  52,  52,
    52,  52,  52,  52,  161, 161, 161, 161, 161, 161, 161, 161, 161, 161, 218, 218, 218, 218, 218, 218,
    218, 218, 218, 218, 218, 218, 218, 218, 218, 218, 14,  14,  14,  14,  14,  14,  14,  159, 159, 159,
    159, 159, 159, 159, 159, 159, 159, 159, 159, 159, 141, 141, 141, 141, 141, 141, 141, 141, 141, 141,
    141, 141, 141, 141, 141, 141, 141, 141, 141, 141, 141, 141, 141, 141, 126, 126, 126, 126, 126, 126,
    126, 126, 126, 126, 126, 126, 126, 126, 126, 126, 126, 126, 126, 126, 126, 126, 115, 115, 115, 115,
    115, 115, 115, 115, 115, 115, 115, 115, 115, 115, 115, 115, 115, 115, 115, 115, 115, 115, 115, 115,
    115, 115, 115, 110, 110, 110, 110, 110, 110, 110, 110, 110, 110, 110, 110, 110, 110, 110, 110, 110,
    110, 110, 110, 110, 110, 110, 110, 110, 110, 110, 70,  70,  70,  70,  70,  70,  70,  70,  70,  70,
    70,  70,  70,  70,  70,  70,  70,  70,  70,  70,  70,  70,  70,  70,  70,  70,  80,  80,  80,  80,
    80,  80,  80,  80,  80,  80,  85,  85,  85,  85,  85,  85,  85,  85,  85,  85,  85,  85,  85,  85,
    85,  85,  85,  85,  85,  85,  85,  85,  85,  85,  85,  85,  85,  85,  127, 127, 127, 127, 127, 105,
    105, 105, 105, 105, 105, 48,  48,  48,  48,  48,  48,  48,  48,  48,  48,  48,  48,  48,  48,  48,
    48,  48,  48,  48,  48,  110, 110, 110, 110, 110, 110, 110, 110, 110, 110, 110, 110, 110, 110, 110,
    110, 110, 110, 110, 110, 110, 110, 110, 110, 110, 110, 110, 110, 106, 106, 106, 106, 106, 106, 106,
    106, 106, 106, 106, 106, 106, 106, 106, 106, 106, 106, 106, 106, 106, 106, 106, 106, 106, 106, 106,
    106, 106, 46,  46,  46,  46,  46,  46,  46,  46,  46,  46,  46,  46,  46,  46,  46,  46,  46,  46,
    46,  46,  46,  46,  46,  46,  46,  46,  143, 143, 143, 143, 143, 143, 143, 92,  92,  92,  92,  92,
    92,  92,  92,  92,  92,  92,  92,  92,  92,  92,  92,  92,  92,  92,  92,  92,  248, 248, 248, 248,
    248, 248, 248, 248, 248, 248, 248, 248, 248, 248, 248, 248, 248, 248, 248, 248, 248, 248, 248, 242,
    242, 242, 242, 242, 242, 242, 242, 242, 242, 242, 242, 242, 242, 242, 242, 242, 242, 242, 86,  86,
    86,  40,  40,  40,  40,  40,  40,  40,  40,  40,  40,  40,  40,  40,  40,  40,  40,  40,  40,  40,
    40,  40,  40,  40,  40,  16,  16,  16,  16,  16,  16,  16,  16,  16,  16,  16,  16,  16,  16,  16,
    16,  16,  16,  16,  16,  16,  211, 211, 211, 211, 211, 211, 211, 211, 119, 119, 95,  95,  95,  95,
    95,  95,  95,  95,  95,  95,  95,  95,  87,  87,  87,  87,  87,  87,  87,  87,  87,  87,  87,  87,
    87,  165, 165, 165, 165, 165, 165, 165, 165, 165, 161, 161, 161, 161, 161, 161, 161, 161, 161, 161,
    161, 71,  71,  71,  111, 111, 111, 111, 111, 111, 111, 111, 111, 111, 111, 17,  17,  17,  17,  17,
    17,  123, 123, 123, 123, 123, 189, 189, 189, 189, 189, 189, 189, 189, 189, 189, 189, 189, 189, 189,
    189, 189, 189, 189, 189, 189, 189, 189, 189, 63,  63,  63,  63,  63,  63,  63,  63,  63,  63,  63,
    63,  63,  63,  63,  63,  63,  63,  63,  63,  63,  63,  63,  63,  63,  63,  63,  242, 242, 242, 242,
    242, 242, 242, 242, 242, 242, 242, 242, 242, 242, 242, 242, 242, 242, 242, 242, 242, 236, 236, 236,
    236, 236, 236, 236, 236, 236, 236, 236, 236, 236, 236, 236, 236, 134, 134, 134, 134, 134, 134, 134,
    134, 134, 134, 134, 134, 134, 134, 134, 134, 134, 134, 134, 134, 134, 134, 134, 134, 15,  15,  15,
    15,  15,  15,  15,  15,  15,  15,  15,  15,  15,  15,  15,  15,  15,  15,  15,  15,  15,  15,  15,
    15,  15,  15,  15,  15,  84,  84,  84,  84,  84,  84,  84,  84,  84,  84,  84,  57,  57,  57,  57,
    57,  57,  57,  57,  57,  57,  57,  57,  57,  57,  57,  57,  57,  57,  57,  57,  57,  57,  57,  57,
    57,  173, 173, 173, 5,   5,   5,   5,   5,   5,   5,   5,   5,   5,   5,   5,   5,   5,   5,   5,
    5,   5,   5,   5,   5,   5,   5,   5,   5,   5,   5,   5,   5,   85,  85,  85,  85,  85,  85,  85,
    85,  85,  85,  85,  85,  85,  85,  85,  85,  85,  85,  85,  85,  85,  85,  48,  48,  48,  48,  48,
    48,  48,  48,  48,  48,  48,  48,  48,  48,  48,  48,  48,  48,  49,  49,  49,  49,  49,  49,  49,
    49,  229, 229, 229, 229, 229, 229, 229, 229, 229, 229, 229, 229, 229, 229, 229, 229, 229, 229, 229,
    229, 86,  86,  86,  86,  86,  86,  86,  86,  86,  86,  86,  86,  86,  86,  86,  86,  86,  46,  46,
    46,  46,  46,  46,  46,  46,  179, 179, 179, 179, 179, 179, 179, 179, 179, 179, 179, 179, 179, 179,
    179, 179, 179, 77,  77,  77,  77,  77,  77,  77,  77,  77,  77,  77,  77,  77,  77,  77,  225, 225,
    225, 225, 225, 225, 225, 225, 225, 225, 232, 232, 232, 232, 232, 232, 194, 194, 194, 194, 194, 194,
    194, 194, 194, 194, 94,  94,  94,  94,  94,  94,  94,  94,  94,  94,  94,  94,  94,  94,  94,  94,
    94,  94,  94,  94,  94,  94,  94,  94,  94,  94,  94,  94,  94,  221, 221, 221, 221, 215, 215, 215,
    215, 215, 12,  12,  12,  12,  12,  12,  12,  12,  12,  12,  12,  12,  12,  12,  12,  12,  12,  12,
    12,  12,  12,  12,  12,  12,  12,  12,  65,  65,  65,  65,  65,  65,  65,  65,  65,  65,  65,  65,
    65,  65,  65,  65,  65,  65,  226, 226, 226, 18,  18,  18,  18,  18,  18,  18,  18,  18,  18,  18,
    30,  30,  30,  30,  175, 175, 175, 175, 24,  41,  41,  41,  41,  41,  41,  41,  41,  41,  244, 244,
    244, 244, 244, 244, 244, 244, 244, 244, 244, 244, 244, 244, 244, 244, 244, 244, 244, 244, 244, 244,
    244, 244, 112, 112, 112, 112, 112, 112, 112, 112, 112, 112, 112, 112, 112, 112, 112, 112, 193, 193,
    193, 193, 193, 193, 193, 193, 193, 193, 193, 193, 193, 193, 193, 193, 193, 193, 193, 193, 193, 193,
    193, 193, 193, 73,  73,  73,  73,  73,  73,  73,  73,  73,  73,  73,  73,  73,  73,  73,  73,  73,
    73,  205, 205, 205, 205, 205, 205, 205, 205, 205, 59,  59,  59,  59,  59,  59,  59,  59,  59,  59,
    59,  59,  218, 218, 218, 218, 218, 218, 218, 218, 218, 218, 227, 227, 227, 227, 227, 227, 227, 227,
    227, 227, 227, 227, 227, 227, 227, 227, 227, 227, 227, 227, 227, 145, 145, 145, 113, 113, 113, 113,
    113, 113, 113, 113, 113, 113, 113, 113, 113, 113, 113, 113, 113, 113, 113, 113, 113, 113, 113, 113,
    113, 113, 113, 113, 72,  72,  72,  72,  72,  72,  72,  72,  72,  72,  72,  72,  72,  72,  72,  72,
    72,  72,  72,  72,  72,  72,  72,  72,  164, 164, 164, 164, 164, 164, 164, 164, 164, 164, 164, 164,
    164, 164, 164, 164, 164, 164, 164, 164, 164, 164, 164,
};

const surv_m25_dict = [_]u8{
    188, 188, 59,  59,  59,  59,  59,  59,  59,  59,  59,  59,  59,  59,  59,  59,  59,  59,  59,  59,
    59,  208, 208, 208, 208, 208, 208, 208, 208, 208, 208, 208, 208, 242, 242, 242, 242, 242, 198, 198,
    198, 198, 198, 198, 198, 198, 198, 198, 198, 198, 198, 211, 211, 211, 162, 162, 162, 162, 162, 162,
    162, 162, 162, 162, 162, 162, 162, 162, 162, 162, 162, 162, 162, 162, 162, 162, 162, 162, 162, 162,
    162, 162, 78,  78,  78,  78,  78,  78,  78,  78,  78,  78,  78,  78,  78,  78,  78,  78,  78,  78,
    78,  78,  78,  78,  78,  214, 214, 214, 214, 214, 214, 214, 214, 214, 214, 214, 214, 214, 214, 214,
    214, 214, 214, 214, 214, 146, 146, 146, 146, 146, 146, 146, 146, 146, 146, 146, 146, 146, 146, 146,
    146, 146, 146, 2,   2,   2,   2,   2,   2,   2,   2,   2,   2,   2,   2,   115, 115, 115, 115, 115,
    71,  71,  71,  71,  71,  71,  71,  71,  71,  71,  71,  71,  71,  71,  71,  71,  71,  71,  71,  71,
    71,  71,  71,  71,  71,  71,  71,  35,  35,  35,  35,  35,  35,  35,  35,  35,  35,  35,  35,  35,
    35,  35,  35,  35,  35,  35,  35,  35,  35,  35,  35,  35,  35,  190, 190, 226, 226, 226, 226, 226,
    226, 226, 226, 226, 226, 226, 226, 226, 226, 226, 226, 226, 226, 226, 226, 226, 226, 226, 226, 226,
    226, 226, 226, 182, 182, 182, 182, 182, 182, 182, 182, 182, 204, 204, 204, 204, 204, 204, 204, 204,
    204, 204, 204, 204, 204, 204, 204, 204, 204, 204, 204, 204, 204, 204, 204, 204, 204, 204, 204, 204,
    204, 227, 227, 227, 227, 227, 227, 227, 227, 227, 227, 227, 227, 227, 227, 227, 227, 227, 227, 227,
    227, 227, 227, 227, 239, 239, 239, 239, 239, 239, 239, 239, 239, 239, 239, 239, 239, 239, 239, 239,
    239, 239, 239, 239, 239, 239, 239, 239, 239, 239, 239, 239, 239, 137, 137, 137, 137, 137, 137, 137,
    137, 137, 137, 137, 137, 137, 137, 137, 137, 137, 137, 137, 137, 137, 137, 137, 137, 137, 45,  45,
    45,  45,  45,  45,  45,  241, 241, 241, 241, 241, 241, 241, 241, 241, 197, 197, 197, 197, 197, 18,
    18,  18,  18,  18,  18,  18,  18,  18,  18,  18,  18,  18,  18,  18,  18,  18,  18,  18,  18,  18,
    33,  33,  33,  33,  33,  33,  33,  33,  33,  33,  33,  33,  33,  33,  33,  33,  33,  33,  103, 103,
    103, 103, 103, 103, 103, 103, 103, 103, 103, 103, 103, 103, 213, 170, 170, 170, 170, 170, 170, 170,
    170, 170, 170, 170, 170, 170, 170, 170, 170, 116, 116, 116, 116, 116, 116, 116, 116, 116, 116, 116,
    116, 116, 116, 116, 116, 116, 116, 116, 116, 116, 116, 116, 116, 116, 116, 116, 165, 165, 165, 165,
    165, 165, 165, 165, 165, 165, 165, 165, 165, 165, 165, 165, 165, 165, 165, 165, 165, 165, 165, 165,
    165, 165, 165, 106, 106, 106, 106, 106, 106, 106, 106, 106, 106, 106, 106, 106, 106, 106, 106, 106,
    106, 106, 106, 106, 106, 106, 106, 106, 106, 106, 106, 53,  53,  53,  53,  53,  53,  53,  53,  53,
    53,  217, 217, 65,  65,  65,  65,  65,  65,  65,  65,  65,  65,  227, 227, 227, 227, 227, 227, 227,
    227, 227, 227, 227, 227, 227, 227, 227, 227, 227, 227, 227, 227, 227, 227, 227, 227, 227, 227, 227,
    43,  43,  43,  43,  43,  43,  43,  43,  43,  43,  43,  43,  43,  43,  43,  43,  43,  43,  43,  43,
    100, 100, 100, 100, 232, 232, 232, 232, 232, 232, 232, 232, 232, 232, 232, 232, 232, 232, 232, 232,
    232, 232, 232, 232, 232, 232, 232, 232, 232, 38,  38,  38,  38,  38,  38,  38,  38,  38,  38,  38,
    38,  38,  38,  38,  38,  38,  38,  38,  38,  38,  38,  190, 190, 190, 190, 190, 190, 190, 190, 190,
    190, 190, 190, 190, 190, 190, 190, 190, 190, 190, 190, 190, 190, 190, 190, 190, 190, 190, 150, 150,
    150, 150, 150, 150, 150, 150, 150, 150, 150, 150, 150, 150, 150, 150, 150, 150, 150, 150, 150, 150,
    150, 150, 56,  56,  56,  56,  56,  56,  56,  56,  56,  56,  150, 150, 150, 150, 150, 150, 150, 150,
    150, 150, 150, 150, 150, 150, 150, 150, 150, 150, 150, 54,  54,  54,  54,  54,  54,  54,  54,  54,
    54,  54,  54,  54,  54,  54,  54,  54,  54,  169, 169, 169, 179, 179, 179, 179, 179, 179, 179, 179,
    179, 179, 179, 242, 242, 242, 242, 242, 242, 242, 242, 242, 242, 242, 242, 242, 242, 242, 242, 242,
    242, 253, 253, 253, 253, 253, 253, 253, 253, 253, 253, 253, 253, 253, 253, 253, 253, 253, 253, 253,
    253, 253, 253, 253, 33,  33,  33,  33,  33,  33,  33,  33,  33,  33,  33,  33,  251, 251, 251, 251,
    251, 251, 251, 251, 251, 251, 251, 251, 251, 251, 251, 251, 251, 251, 251, 251, 251, 251, 251, 251,
    251, 251, 226, 226, 226, 226, 226, 226, 226, 226, 226, 226, 226, 226, 226, 226, 226, 226, 226, 226,
    226, 226, 226, 226, 226, 226, 226, 226, 226, 226, 226, 79,  79,  79,  79,  79,  79,  79,  79,  79,
    79,  79,  43,  43,  43,  43,  136, 136, 136, 136, 136, 159, 159, 159, 159, 159, 159, 159, 159, 159,
    159, 159, 159, 159, 159, 159, 159, 159, 159, 159, 48,  48,  48,  41,  41,  41,  41,  106, 203, 203,
    203, 203, 203, 231, 231, 231, 231, 231, 231, 231, 231, 231, 231, 231, 231, 231, 231, 231, 231, 231,
    231, 231, 231, 231, 231, 79,  79,  79,  79,  79,  79,  79,  79,  79,  79,  79,  79,  79,  79,  79,
    79,  79,  79,  79,  79,  79,  79,  6,   6,   6,   6,   83,  83,  83,  83,  83,  83,  83,  83,  83,
    83,  83,  83,  83,  83,  83,  81,  81,  81,  81,  81,  81,  81,  81,  81,  81,  81,  81,  81,  81,
    81,  81,  81,  81,  81,  81,  81,  81,  81,  81,  81,  81,  81,  54,  54,  54,  54,  54,  54,  54,
    54,  54,  54,  54,  54,  54,  54,  54,  54,  54,  54,  54,  54,  54,  50,  50,  50,  50,  50,  50,
    50,  50,  50,  50,  50,  50,  50,  50,  50,  50,  50,  50,  50,  50,  50,  50,  50,  78,  78,  78,
    78,  78,  78,  78,  210, 210, 210, 210, 210, 210, 210, 210, 210, 210, 44,  44,  44,  44,  44,  44,
    44,  44,  44,  44,  44,  44,  44,  44,  44,  44,  44,  161, 161, 161, 161, 161, 161, 161, 161, 161,
    161, 161, 161, 161, 161, 161, 225, 225, 225, 225, 225, 225, 225, 225, 225, 225, 225, 225, 225, 225,
    225, 225, 225, 225, 225, 225, 225, 225, 225, 225, 225, 225, 225, 225, 228, 228, 228, 228, 228, 228,
    228, 228, 247, 247, 247, 247, 247, 247, 247, 247, 247, 247, 210, 210, 210, 210, 210, 210, 210, 210,
    210, 210, 210, 210, 210, 210, 210, 238, 238, 238, 238, 238, 238, 238, 238, 238, 238, 238, 238, 238,
    238, 238, 238, 238, 238, 238, 238, 69,  69,  69,  69,  69,  150, 150, 150, 150, 150, 150, 150, 150,
    150, 150, 150, 150, 150, 150, 150, 150, 150, 150, 150, 150, 150, 150, 231, 231, 231, 231, 231, 231,
    231, 231, 231, 231, 231, 231, 207, 207, 207, 207, 207, 207, 207, 207, 106, 106, 106, 106, 106, 106,
    106, 106, 106, 106, 106, 106, 106, 106, 106, 106, 106, 106, 106, 106, 106, 106, 106, 106, 106, 78,
    78,  78,  78,  78,  78,  186, 186, 186, 186, 30,  30,  30,  30,  30,  30,  30,  30,  30,  30,  30,
    30,  30,  30,  30,  30,  30,  30,  30,  30,  30,  30,  30,  30,  30,  30,  30,  30,  30,  113, 113,
    113, 113, 109, 109, 109, 109, 109, 109, 109, 109, 109, 109, 109, 109, 109, 109, 109, 109, 109, 109,
    109, 109, 109, 109, 109, 109, 252, 252, 252, 252, 252, 252, 252, 252, 252, 252, 252, 252, 252, 252,
    252, 252, 252, 252, 252, 152, 152, 152, 152, 152, 152, 7,   7,   7,   7,   7,   7,   7,   7,   7,
    7,   7,   7,   7,   7,   7,   7,   7,   7,   7,   7,   7,   7,   7,   7,   7,   7,   7,   7,   7,
    89,  89,  89,  89,  89,  89,  89,  89,  89,  89,  89,  89,  89,  89,  89,  89,  89,  89,  89,  89,
    89,  89,  89,  89,  89,  89,  89,  89,  9,   9,   9,   9,   9,   9,   9,   9,   9,   9,   9,   9,
    9,   9,   9,   9,   9,   9,   9,   9,   9,   9,   9,   9,   9,   9,   19,  19,  19,  19,  19,  19,
    19,  19,  19,  19,  19,  19,  19,  19,  19,  19,  19,  19,  19,  19,  19,  19,  19,  19,  91,  91,
    91,  225, 225, 225, 225, 225, 225, 225, 225, 225, 225, 225, 225, 225, 225, 225, 225, 225, 225, 225,
    225, 225, 225, 225, 225, 225, 225, 225, 225, 225, 135, 135, 135, 135, 135, 135, 135, 135, 135, 135,
    135, 135, 135, 135, 135, 135, 135, 135, 135, 135, 90,  90,  90,  90,  90,  90,  90,  90,  90,  90,
    90,  90,  90,  90,  90,  90,  90,  90,  90,  90,  90,  90,  90,  208, 208, 208, 208, 208, 208, 208,
    208, 208, 208, 208, 208, 208, 208, 208, 11,  11,  11,  11,  11,  11,  11,  11,  11,  11,  11,  11,
    11,  11,  11,  11,  11,  11,  11,  11,  11,  11,  11,  11,  210, 210, 210, 210, 210, 210, 210, 210,
    210, 210, 210, 210, 210, 210, 210, 210, 210, 210, 210, 210, 210, 210, 210, 210, 210, 210, 210, 210,
    210, 61,  61,  61,  61,  61,  61,  61,  61,  61,  61,  203, 203, 203, 203, 203, 203, 203, 203, 203,
    203, 203, 203, 203, 203, 203, 203, 203, 203, 203, 203, 203, 203, 203, 203, 203, 203, 203, 203, 203,
    146, 146, 146, 146, 146, 146, 146, 146, 146, 146, 146, 146, 146, 146, 146, 146, 146, 146, 146, 146,
    146, 146, 146, 146, 146, 139, 139, 139, 139, 139, 139, 139, 139, 139, 139, 139, 139, 139, 139, 139,
    139, 139, 139, 139, 139, 139, 139, 139, 139, 139, 139, 139, 139, 68,  68,  68,  68,  68,  68,  68,
    68,  68,  68,  68,  215, 215, 215, 215, 215, 215, 215, 215, 215, 215, 215, 215, 215, 215, 215, 215,
    215, 215, 215, 215, 215, 99,  99,  99,  99,  99,  99,  99,  99,  99,  99,  99,  99,  99,  99,  99,
    99,  99,  99,  99,  99,  99,  99,  99,  99,  99,  99,  99,  99,  99,  226, 226, 226, 226, 226, 226,
    226, 226, 226, 226, 226, 226, 226, 226, 226, 226, 226, 226, 226, 226, 226, 33,  33,  33,  33,  33,
    33,  33,  33,  33,  33,  33,  190, 190, 190, 190, 190, 190, 190, 190, 190, 190, 190, 190, 190, 190,
    190, 63,  63,  63,  63,  63,  63,  63,  63,  63,  52,  16,  16,  16,  16,  16,  16,  16,  16,  16,
    16,  16,  161, 161, 216, 216, 216, 216, 216, 216, 216, 216, 216, 216, 216, 216, 216, 216, 216, 216,
    216, 216, 216, 216, 216, 216, 216, 216, 216, 65,  65,  65,  65,  65,  65,  65,  65,  65,  65,  65,
    65,  65,  65,  65,  65,  65,  65,  65,  65,  65,  79,  79,  79,  79,  79,  79,  79,  79,  79,  79,
    79,  79,  79,  79,  79,  79,  79,  79,  79,  79,  79,  79,  79,  79,  104, 104, 104, 104, 104, 84,
    84,  84,  33,  33,  33,  33,  29,  29,  29,  29,  29,  29,  29,  29,  29,  29,  29,  29,  29,  29,
    29,  29,  29,  29,  29,  29,  29,  29,  29,  29,  29,  2,   2,   2,   2,   2,   2,   201, 201, 201,
    201, 201, 241, 241, 241, 152, 152, 249, 249, 249, 249, 249, 249, 249, 249, 249, 249, 249, 249, 249,
    249, 249, 249, 169, 169, 169, 169, 169, 169, 198, 198, 198, 198, 198, 198, 198, 198, 198, 198, 198,
    198, 198, 198, 198, 198, 198, 198, 198, 198, 198, 198, 198, 198, 71,  71,  71,  71,  71,  71,  71,
    71,  71,  71,  71,  71,  71,  71,  71,  232, 232, 232, 232, 232, 232, 232, 232, 232, 232, 232, 232,
    232, 232, 232, 232, 129, 129, 129, 129, 129, 129, 129, 129, 61,  61,  61,  61,  61,  61,  61,  61,
    61,  61,  61,  61,  61,  61,  61,  61,  61,  61,  61,  61,  61,  61,  61,  61,  61,  61,  61,  61,
    61,  61,  61,  61,  61,  61,  61,  61,  61,  61,  61,  29,  29,  29,  29,  29,  29,  29,  29,  29,
    29,  29,  29,  29,  29,  29,  29,  29,  29,  29,  29,  29,  29,  29,  29,  207, 207, 207, 207, 207,
    207, 207, 207, 207, 207, 207, 207, 207, 207, 207, 207, 207, 207, 207, 207, 207, 207, 207, 207, 207,
    216, 216, 216, 216, 216, 216, 216, 216, 216, 216, 216, 216, 216, 47,  47,  47,  47,  47,  47,  47,
    47,  121, 64,  64,  64,  64,  64,  64,  64,  64,  64,  64,  137, 137, 137, 137, 137, 137, 137, 137,
    137, 137, 137, 137, 137, 137, 137, 137, 139, 139, 139, 139, 139, 139, 130, 130, 184, 184, 184, 184,
    184, 184, 184, 184, 184, 184, 184, 184, 184, 184, 184, 184, 184, 184, 184, 184, 184, 184, 184, 184,
    18,  18,  18,  18,  18,  18,  18,  18,  18,  18,  125, 125, 125, 125, 125, 125, 125, 125, 125, 125,
    125, 125, 125, 125, 125, 125, 125, 125, 125, 125, 125, 166, 166, 166, 166, 166, 166, 166, 166, 166,
    166, 166, 166, 166, 166, 166, 166, 121, 121, 121, 121, 121, 121, 121, 121, 121, 121, 121, 65,  65,
    65,  65,  65,  65,  65,  65,  65,  65,  65,  65,  65,  65,  65,  65,  65,  65,  211, 211, 211, 211,
    211, 211, 211, 211, 211, 112, 112, 112, 112, 112, 112, 112, 112, 127, 127, 127, 127, 127, 127, 127,
    127, 127, 127, 127, 127, 127, 235, 235, 235, 235, 235, 235, 235, 234, 234, 234, 234, 234, 234, 234,
    234, 234, 234, 234, 234, 234, 234, 234, 234, 234, 234, 234, 234, 234, 234, 234, 234, 234, 234, 234,
    123, 123, 123, 123, 123, 123, 123, 123, 85,  85,  85,  85,  85,  85,  199, 199, 199, 199, 199, 199,
    199, 199, 199, 199, 199, 199, 199, 199, 199, 199, 199, 199, 199, 199, 199, 199, 199, 199, 199, 199,
    199, 199, 206, 206, 206, 206, 206, 206, 206, 206, 206, 39,  39,  39,  39,  39,  39,  39,  39,  39,
    39,  39,  39,  39,  39,  39,  39,  39,  39,  39,  194, 194, 194, 194, 194, 194, 194, 194, 194, 194,
    0,   0,   0,   0,   0,   0,   0,   0,   0,   0,   0,   0,   0,   0,   0,   0,   0,   0,   225, 225,
    225, 225, 72,  72,  72,  72,  72,  72,  72,  15,  15,  15,  15,  15,  15,  15,  15,  15,  15,  206,
    206, 206, 206, 206, 206, 208, 208, 208, 208, 208, 208, 208, 195, 195, 195, 195, 195, 195, 195, 195,
    195, 195, 195, 195, 68,  250, 250, 250, 250, 250, 250, 250, 250, 250, 250, 95,  95,  95,  95,  95,
    95,  181, 181, 181, 181, 181, 181, 181, 181, 181, 181, 181, 181, 181, 181, 181, 181, 181, 181, 181,
    181, 181, 181, 181, 181, 181, 181, 146, 146, 146, 146, 146, 146, 146, 146, 146, 146, 146, 146, 146,
    146, 146, 146, 146, 146, 146, 146, 146, 146, 146, 146, 146, 146, 146, 146, 146, 147, 147, 147, 147,
    147, 147, 147, 147, 147, 147, 147, 147, 147, 147, 147, 147, 147, 147, 147, 219, 219, 219, 219, 219,
    219, 219, 219, 219, 219, 219, 219, 61,  61,  61,  61,  61,  61,  61,  61,  61,  61,  61,  61,  61,
    61,  150, 150, 150, 150, 150, 150, 150, 150, 150, 150, 150, 150, 150, 150, 150, 150, 222, 222, 222,
    222, 222, 222, 222, 222, 222, 222, 222, 222, 222, 222, 222, 222, 222, 222, 222, 222, 222, 222, 222,
    222, 222, 222, 222, 189, 189, 189, 189, 189, 189, 189, 189, 189, 189, 189, 189, 189, 189, 189, 189,
    189, 189, 189, 189, 189, 189, 189, 189, 189, 189, 189, 189, 189, 209, 209, 209, 209, 209, 209, 209,
    209, 209, 209, 209, 73,  73,  73,  73,  73,  73,  73,  73,  73,  73,  73,  73,  73,  73,  73,  73,
    73,  73,  73,  73,  73,  73,  73,  73,  73,  73,  73,  73,  73,  235, 235, 235, 235, 235, 235, 235,
    235, 235, 235, 235, 235, 214, 214, 214, 214, 214, 214, 214, 214, 214, 214, 214, 214, 214, 214, 214,
    214, 214, 214, 214, 214, 214, 214, 79,  79,  79,  79,  79,  79,  79,  79,  79,  79,  79,  79,  208,
    208, 208, 208, 208, 208, 208, 208, 208, 208, 208, 208, 208, 208, 204, 12,  12,  12,  12,  12,  12,
    12,  12,  12,  12,  12,  12,  12,  12,  12,  12,  12,  12,  12,  12,  12,  12,  12,  12,  12,  12,
    54,  54,  54,  54,  54,  139, 139, 139, 139, 139, 139, 139, 139, 139, 139, 139, 139, 139, 139, 139,
    139, 114, 114, 114, 114, 114, 114, 114, 114, 114, 114, 114, 114, 114, 114, 114, 114, 114, 114, 114,
    114, 114, 114, 114, 114, 114, 114, 114, 114, 170, 170, 170, 170, 170, 181, 181, 181, 181, 181, 165,
    165, 165, 165, 165, 165, 165, 165, 165, 165, 165, 165, 165, 165, 165, 165, 165, 165, 165, 175, 175,
    175, 175, 175, 175, 175, 175, 171, 171, 171, 171, 171, 171, 171, 171, 171, 171, 171, 171, 171, 171,
    171, 171, 171, 171, 171, 171, 171, 171, 171, 171, 249, 249, 249, 249, 249, 249, 249, 249, 3,   3,
    3,   3,   3,   3,   3,   226, 226, 226, 226, 226, 226, 226, 226, 226, 226, 226, 226, 226, 226, 226,
    226, 226, 226, 226, 226, 226, 226, 226, 226, 226, 226, 226, 226, 226, 43,  43,  43,  43,  43,  43,
    43,  43,  43,  43,  193, 193, 193, 193, 193, 193, 193, 193, 193, 193, 193, 193, 193, 193, 193, 193,
    193, 193, 193, 193, 193, 193, 193, 193, 222, 222, 222, 222, 222, 222, 222, 196, 196, 196, 196, 196,
    196, 196, 196, 196, 196, 196, 196, 196, 196, 196, 196, 196, 196, 196, 196, 253, 253, 253, 253, 253,
    253, 253, 253, 253, 253, 253, 253, 253, 253, 253, 253, 253, 253, 240, 240, 240, 240, 240, 240, 240,
    240, 118, 118, 118, 118, 118, 118, 118, 118, 118, 118, 118, 118, 118, 118, 118, 118, 118, 118, 118,
    118, 118, 118, 118, 118, 118, 118, 118, 118, 176, 66,  66,  66,  66,  66,  66,  66,  66,  66,  66,
    66,  66,  66,  66,  66,  66,  66,  66,  19,  19,  19,  19,  19,  19,  19,  192, 192, 192, 192, 192,
    192, 192, 192, 192, 192, 192, 192, 2,   2,   2,   2,   2,   2,   2,   2,   2,   2,   2,   2,   2,
    2,   2,   2,   2,   248, 248, 248, 248, 248, 248, 248, 248, 248, 248, 248, 248, 248, 248, 248, 231,
    231, 231, 231, 231, 231, 231, 231, 231, 231, 231, 231, 231, 231, 231, 231, 231, 231, 231, 231, 231,
    231, 231, 231, 239, 239, 239, 239, 239, 239, 239, 239, 239, 239, 239, 239, 239, 239, 239, 239, 239,
    239, 239, 239, 239, 239, 239, 239, 147, 147, 11,  11,  11,  11,  11,  28,  28,  28,  28,  28,  28,
    28,  28,  28,  28,  28,  28,  28,  28,  26,  26,  26,  26,  26,  26,  26,  26,  26,  26,  26,  26,
    26,  26,  26,  26,  26,  26,  26,  26,  26,  26,  26,  26,  26,  26,  26,  26,  26,  54,  54,  54,
    54,  54,  54,  54,  54,  54,  54,  54,  54,  54,  54,  54,  54,  54,  54,  54,  54,  237, 237, 237,
    237, 237, 237, 237, 237, 0,   69,  69,  69,  69,  69,  69,  69,  69,  69,  69,  69,  69,  69,  69,
    69,  69,  69,  69,  69,  69,  69,  69,  69,  69,  69,  69,  69,  69,  69,  146, 146, 146, 126, 126,
    126, 126, 219, 219, 219, 219, 219, 219, 219, 219, 219, 219, 161, 161, 161, 161, 161, 161, 161, 161,
    161, 161, 161, 161, 161, 161, 161, 161, 161, 161, 161, 161, 161, 161, 161, 161, 161, 161, 72,  72,
    72,  72,  72,  72,  72,  72,  72,  72,  72,  72,  72,  72,  92,  92,  92,  92,  92,  92,  92,  92,
    92,  92,  92,  92,  92,  92,  92,  92,  92,  92,  223, 223, 223, 223, 223, 223, 223, 223, 223, 223,
    223, 223, 223, 223, 223, 223, 247, 247, 247, 247, 247, 247, 247, 247, 247, 247, 247, 247, 247, 247,
    247, 247, 89,  89,  89,  89,  89,  89,  89,  89,  89,  89,  89,  89,  89,  89,  114, 114, 114, 114,
    114, 114, 114, 114, 114, 114, 114, 5,   5,   5,   5,   5,   5,   5,   5,   5,   5,   5,   5,   5,
    62,  62,  62,  62,  62,  62,  62,  62,  62,  62,  62,  62,  62,  62,  62,  62,  62,  62,  62,  62,
    62,  236, 236, 236, 236, 236, 236, 236, 236, 236, 236, 236, 236, 236, 236, 236, 236, 17,  17,  17,
    17,  17,  17,  17,  17,  17,  17,  17,  17,  17,  17,  17,  17,  17,  17,  17,  17,  17,  17,  17,
    17,  17,  17,  17,  17,  17,  252, 252, 252, 252, 252, 252, 252, 252, 252, 252, 252, 252, 252, 252,
    252, 252, 252, 252, 252, 252, 252, 252, 252, 252, 252, 163, 163, 163, 163, 163, 163, 163, 163, 163,
    163, 67,  67,  67,  67,  67,  67,  67,  67,  67,  67,  67,  139, 139, 139, 139, 139, 139, 139, 139,
    139, 139, 139, 139, 139, 139, 139, 139, 139, 139, 139, 67,  67,  104, 104, 104, 104, 104, 104, 104,
    104, 104, 104, 104, 104, 104, 104, 104, 104, 104, 104, 242, 242, 242, 242, 242, 242, 242, 242, 242,
    242, 242, 242, 242, 242, 242, 242, 23,  23,  23,  23,  23,  23,  23,  23,  23,  23,  23,  23,  23,
    23,  23,  71,  71,  207, 207, 207, 207, 207, 207, 207, 207, 207, 207, 207, 207, 207, 207, 207, 207,
    73,  240,
};

const surv_m25_input = [_]u8{
    188, 188, 59,  59,  6,   6,   6,   6,   6,   6,   6,   6,   6,   6,   6,   6,   6,   6,   6,   6,
    6,   6,   6,   6,   6,   6,   6,   6,   179, 179, 179, 179, 179, 179, 179, 179, 179, 179, 179, 179,
    179, 179, 179, 179, 179, 179, 179, 179, 10,  10,  10,  10,  10,  10,  10,  10,  10,  10,  10,  10,
    10,  10,  10,  10,  10,  10,  10,  10,  10,  10,  10,  10,  10,  10,  80,  80,  80,  80,  80,  80,
    80,  80,  80,  80,  80,  80,  80,  237, 237, 237, 237, 237, 237, 237, 237, 237, 237, 237, 237, 237,
    237, 237, 237, 237, 237, 189, 189, 189, 189, 189, 189, 189, 199, 199, 199, 199, 199, 199, 199, 199,
    199, 199, 199, 199, 199, 199, 199, 62,  62,  62,  62,  62,  62,  62,  62,  62,  62,  62,  62,  62,
    62,  62,  62,  62,  62,  62,  62,  62,  62,  62,  62,  62,  62,  62,  62,  187, 91,  91,  91,  91,
    91,  91,  91,  91,  91,  91,  91,  91,  91,  91,  91,  91,  91,  91,  91,  91,  91,  91,  105, 105,
    105, 105, 105, 105, 105, 105, 105, 105, 105, 105, 131, 131, 131, 162, 162, 12,  12,  12,  12,  12,
    12,  12,  12,  12,  12,  12,  12,  12,  12,  77,  77,  77,  173, 173, 173, 173, 173, 173, 173, 173,
    173, 173, 173, 173, 173, 173, 173, 173, 173, 173, 173, 173, 173, 173, 173, 223, 223, 223, 223, 223,
    223, 223, 223, 223, 223, 223, 223, 223, 223, 223, 223, 223, 223, 223, 223, 223, 223, 223, 223, 104,
    104, 104, 104, 104, 104, 104, 104, 104, 104, 104, 104, 104, 104, 104, 104, 104, 104, 104, 104, 104,
    227, 227, 227, 227, 227, 227, 227, 227, 227, 227, 227, 227, 227, 227, 227, 227, 227, 227, 227, 227,
    227, 227, 227, 227, 227, 227, 227, 227, 44,  44,  44,  44,  44,  44,  44,  44,  44,  44,  44,  44,
    44,  44,  44,  81,  81,  81,  81,  81,  81,  81,  81,  0,   0,   0,   0,   0,   0,   0,   0,   0,
    0,   0,   0,   0,   0,   0,   0,   0,   151, 151, 151, 151, 151, 151, 151, 151, 151, 151, 151, 151,
    151, 151, 151, 151, 151, 151, 151, 151, 151, 151, 118, 118, 118, 118, 118, 118, 118, 118, 118, 118,
    120, 120, 120, 120, 120, 120, 120, 120, 120, 120, 120, 120, 120, 120, 120, 120, 244, 244, 244, 244,
    244, 244, 244, 244, 244, 38,  38,  38,  172, 172, 172, 172, 172, 172, 172, 172, 172, 172, 172, 172,
    172, 172, 172, 172, 243, 243, 243, 243, 243, 243, 243, 243, 243, 243, 243, 243, 243, 243, 243, 243,
    243, 243, 243, 243, 243, 243, 243, 243, 243, 119, 119, 119, 119, 119, 119, 119, 119, 119, 119, 119,
    119, 119, 119, 119, 119, 119, 119, 119, 119, 119, 119, 119, 119, 119, 119, 119, 38,  38,  38,  38,
    38,  38,  38,  38,  38,  38,  38,  38,  38,  38,  38,  38,  38,  190, 190, 52,  52,  52,  52,  52,
    52,  52,  52,  52,  52,  52,  52,  52,  52,  52,  52,  52,  52,  52,  52,  52,  52,  52,  52,  52,
    52,  52,  52,  52,  236, 172, 41,  41,  41,  41,  41,  41,  41,  41,  41,  41,  41,  41,  41,  41,
    41,  41,  41,  41,  41,  18,  18,  18,  18,  18,  18,  18,  18,  18,  18,  18,  18,  18,  18,  18,
    18,  18,  18,  18,  18,  18,  18,  18,  18,  18,  18,  18,  18,  18,  143, 143, 143, 143, 143, 143,
    143, 143, 143, 206, 206, 206, 206, 206, 206, 206, 206, 206, 206, 206, 206, 206, 206, 206, 206, 206,
    206, 206, 206, 206, 206, 109, 109, 109, 109, 109, 109, 109, 83,  83,  83,  83,  83,  83,  83,  83,
    83,  83,  83,  148, 148, 148, 148, 148, 148, 148, 148, 148, 148, 148, 148, 148, 148, 148, 148, 148,
    148, 148, 148, 148, 148, 148, 148, 148, 148, 141, 141, 141, 141, 141, 141, 141, 141, 141, 141, 141,
    141, 141, 141, 141, 141, 141, 141, 141, 141, 141, 141, 47,  91,  91,  91,  91,  91,  91,  91,  91,
    91,  91,  91,  91,  91,  91,  91,  91,  91,  91,  91,  91,  91,  91,  91,  242, 242, 242, 242, 242,
    242, 242, 242, 242, 242, 242, 76,  76,  76,  76,  76,  76,  76,  76,  76,  76,  76,  76,  76,  76,
    76,  76,  76,  76,  76,  76,  153, 153, 153, 153, 153, 153, 108, 108, 108, 108, 108, 165, 165, 165,
    165, 165, 165, 165, 165, 165, 165, 165, 165, 165, 165, 165, 165, 165, 165, 165, 165, 165, 165, 165,
    165, 165, 165, 165, 8,   8,   8,   8,   8,   8,   8,   8,   8,   8,   8,   8,   8,   8,   8,   5,
    5,   5,   5,   5,   5,   5,   5,   5,   5,   5,   5,   5,   5,   5,   5,   5,   5,   5,   5,   5,
    5,   5,   77,  77,  77,  77,  77,  77,  77,  77,  77,  77,  77,  77,  77,  77,  77,  77,  77,  77,
    77,  77,  77,  77,  77,  77,  77,  77,  77,  77,  77,  89,  89,  89,  89,  140, 140, 140, 140, 140,
    140, 140, 140, 140, 130, 130, 130, 130, 130, 130, 130, 130, 130, 130, 130, 130, 130, 130, 130, 130,
    130, 130, 130, 130, 130, 130, 40,  40,  208, 208, 208, 208, 208, 208, 208, 208, 208, 208, 208, 208,
    26,  26,  26,  26,  26,  26,  26,  26,  26,  26,  26,  26,  26,  26,  26,  26,  26,  26,  26,  26,
    26,  26,  26,  26,  26,  90,  90,  90,  90,  90,  90,  90,  90,  90,  90,  90,  90,  90,  90,  90,
    90,  90,  90,  90,  90,  90,  90,  90,  90,  90,  204, 204, 204, 204, 204, 204, 204, 204, 204, 204,
    204, 204, 204, 94,  94,  94,  94,  94,  94,  94,  94,  94,  94,  94,  94,  94,  94,  94,  94,  94,
    94,  94,  94,  94,  94,  94,  94,  94,  94,  94,  94,  37,  37,  37,  37,  37,  37,  37,  37,  37,
    37,  37,  37,  37,  37,  37,  84,  84,  84,  84,  84,  84,  84,  13,  13,  13,  13,  13,  13,  13,
    13,  13,  210, 210, 51,  51,  51,  51,  51,  51,  51,  51,  188, 188, 188, 188, 188, 188, 188, 188,
    188, 188, 188, 188, 188, 188, 188, 188, 188, 188, 188, 188, 188, 188, 188, 188, 188, 188, 188, 35,
    35,  35,  35,  35,  35,  35,  35,  35,  0,   0,   0,   0,   0,   0,   0,   0,   0,   0,   0,   0,
    0,   0,   137, 137, 137, 137, 25,  25,  25,  25,  25,  25,  25,  25,  25,  25,  25,  25,  25,  25,
    25,  25,  94,  94,  94,  94,  94,  94,  58,  58,  58,  58,  58,  58,  58,  58,  58,  58,  58,  58,
    58,  58,  58,  58,  58,  58,  248, 248, 248, 248, 248, 248, 248, 248, 248, 248, 98,  98,  98,  98,
    98,  98,  98,  98,  98,  98,  250, 250, 250, 250, 250, 250, 250, 250, 250, 250, 250, 250, 250, 250,
    250, 250, 250, 250, 250, 250, 250, 250, 250, 250, 250, 250, 86,  86,  86,  86,  86,  86,  86,  86,
    86,  86,  86,  86,  86,  86,  86,  86,  86,  86,  86,  86,  86,  86,  86,  86,  86,  207, 207, 207,
    207, 207, 207, 207, 207, 207, 207, 207, 207, 132, 132, 132, 132, 132, 132, 132, 132, 132, 132, 127,
    127, 127, 127, 127, 127, 127, 127, 127, 127, 127, 127, 127, 127, 127, 127, 127, 127, 127, 127, 127,
    127, 127, 127, 127, 127, 127, 127, 177, 177, 177, 177, 177, 177, 177, 177, 177, 177, 177, 177, 177,
    177, 177, 177, 177, 177, 177, 120, 120, 120, 120, 120, 120, 120, 120, 120, 120, 120, 120, 120, 120,
    120, 120, 120, 120, 120, 120, 28,  28,  28,  28,  28,  247, 247, 247, 247, 247, 247, 247, 247, 247,
    247, 247, 247, 247, 247, 247, 247, 247, 247, 247, 247, 230, 230, 230, 230, 230, 230, 230, 230, 167,
    167, 167, 167, 167, 167, 167, 167, 167, 167, 167, 167, 167, 167, 167, 167, 167, 167, 167, 167, 167,
    167, 167, 167, 167, 167, 167, 167, 167, 247, 247, 247, 247, 247, 247, 247, 247, 247, 247, 247, 247,
    18,  18,  18,  18,  18,  18,  18,  18,  18,  18,  18,  18,  18,  18,  18,  18,  18,  18,  18,  18,
    18,  18,  18,  18,  18,  18,  18,  18,  18,  37,  37,  37,  37,  37,  37,  37,  37,  37,  37,  37,
    37,  37,  37,  37,  37,  37,  37,  11,  11,  11,  11,  11,  11,  67,  39,  39,  39,  39,  39,  39,
    39,  39,  39,  39,  39,  39,  39,  183, 25,  25,  25,  25,  25,  25,  25,  25,  25,  25,  25,  25,
    25,  25,  25,  25,  25,  25,  25,  25,  25,  25,  25,  25,  17,  17,  17,  17,  17,  17,  17,  17,
    17,  17,  17,  17,  17,  17,  17,  17,  17,  17,  17,  17,  225, 225, 225, 225, 225, 225, 225, 225,
    225, 225, 225, 225, 225, 225, 225, 225, 225, 225, 225, 225, 225, 179, 179, 179, 179, 179, 179, 179,
    179, 179, 178, 178, 178, 178, 178, 178, 123, 123, 123, 123, 123, 123, 123, 123, 123, 123, 123, 123,
    123, 123, 123, 123, 123, 123, 123, 123, 123, 123, 123, 123, 123, 123, 123, 150, 150, 150, 150, 150,
    150, 150, 150, 150, 150, 150, 150, 150, 150, 150, 150, 150, 150, 150, 150, 150, 150, 89,  89,  89,
    89,  89,  89,  89,  89,  89,  89,  89,  89,  89,  89,  89,  89,  89,  89,  89,  89,  89,  89,  89,
    104, 104, 104, 104, 104, 104, 104, 104, 104, 104, 104, 104, 104, 104, 104, 104, 104, 104, 104, 104,
    104, 104, 104, 104, 104, 104, 104, 6,   6,   6,   6,   6,   6,   6,   6,   6,   6,   6,   6,   6,
    6,   6,   6,   6,   6,   6,   6,   6,   6,   6,   228, 228, 228, 228, 228, 228, 228, 228, 228, 228,
    228, 228, 228, 228, 228, 228, 228, 228, 228, 228, 228, 228, 228, 228, 228, 228, 113, 113, 113, 113,
    113, 113, 113, 113, 114, 114, 114, 114, 114, 114, 114, 96,  96,  96,  96,  96,  96,  96,  96,  96,
    174, 174, 174, 174, 174, 174, 18,  18,  18,  18,  18,  18,  154, 154, 154, 154, 154, 154, 154, 52,
    52,  52,  52,  52,  52,  52,  52,  52,  52,  52,  52,  52,  52,  52,  52,  52,  52,  52,  52,  52,
    52,  52,  52,  52,  41,  41,  41,  41,  41,  12,  12,  12,  12,  12,  12,  12,  12,  12,  12,  12,
    12,  12,  12,  12,  12,  12,  12,  12,  102, 102, 102, 102, 122, 122, 122, 122, 122, 122, 122, 122,
    122, 122, 122, 122, 122, 122, 122, 122, 122, 122, 122, 56,  56,  56,  56,  56,  56,  56,  56,  56,
    56,  56,  56,  56,  56,  56,  56,  56,  56,  133, 133, 133, 133, 133, 133, 133, 133, 133, 133, 133,
    133, 133, 133, 133, 133, 133, 133, 133, 133, 133, 133, 133, 133, 133, 133, 133, 133, 133, 101, 101,
    101, 101, 101, 101, 101, 101, 101, 101, 101, 101, 101, 101, 101, 101, 101, 101, 68,  68,  2,   2,
    2,   2,   2,   2,   2,   2,   2,   2,   2,   2,   2,   2,   45,  45,  45,  45,  45,  45,  45,  45,
    45,  45,  45,  218, 218, 218, 218, 218, 218, 218, 218, 218, 218, 218, 218, 218, 218, 218, 152, 152,
    152, 152, 152, 152, 152, 152, 152, 152, 152, 152, 152, 152, 152, 152, 152, 152, 152, 152, 152, 152,
    189, 189, 189, 189, 189, 189, 189, 189, 189, 189, 189, 189, 182, 182, 182, 182, 182, 182, 182, 182,
    182, 182, 22,  22,  22,  22,  22,  154, 154, 154, 154, 154, 154, 154, 154, 46,  46,  46,  46,  3,
    3,   3,   3,   3,   3,   3,   3,   3,   3,   3,   3,   3,   3,   18,  18,  18,  238, 238, 238, 238,
    238, 161, 161, 98,  98,  98,  98,  98,  98,  98,  98,  98,  98,  98,  98,  98,  98,  98,  98,  98,
    98,  98,  98,  167, 167, 167, 167, 45,  45,  45,  45,  45,  45,  45,  45,  45,  45,  45,  45,  45,
    45,  45,  45,  45,  45,  45,  45,  45,  45,  45,  45,  124, 124, 124, 124, 124, 124, 124, 124, 124,
    124, 124, 124, 96,  96,  96,  96,  96,  96,  96,  96,  96,  96,  96,  96,  96,  96,  96,  96,  96,
    96,  96,  96,  96,  96,  96,  96,  96,  96,  96,  96,  116, 116, 116, 116, 116, 116, 116, 116, 116,
    116, 116, 116, 116, 116, 116, 116, 116, 116, 116, 116, 116, 116, 116, 116, 116, 226, 226, 226, 226,
    226, 226, 226, 226, 226, 226, 226, 226, 226, 226, 226, 226, 226, 226, 147, 147, 147, 147, 147, 147,
    186, 186, 186, 186, 186, 186, 186, 186, 65,  65,  65,  65,  65,  65,  65,  65,  65,  65,  65,  65,
    118, 118, 118, 118, 118, 118, 118, 118, 118, 118, 205, 205, 205, 205, 205, 205, 205, 205, 205, 205,
    205, 205, 205, 205, 205, 205, 205, 205, 205, 205, 205, 205, 205, 205, 79,  79,  79,  79,  79,  79,
    79,  79,  79,  79,  79,  79,  79,  79,  79,  79,  79,  79,  79,  79,  79,  79,  79,  79,  87,  87,
    87,  87,  87,  87,  87,  87,  87,  87,  87,  87,  87,  87,  87,  87,  87,  87,  87,  87,  87,  43,
    43,  43,  43,  43,  43,  43,  43,  43,  43,  43,  43,  43,  43,  43,  43,  43,  43,  43,  43,  43,
    43,  43,  43,  142, 142, 142, 142, 142, 142, 142, 142, 142, 142, 142, 142, 142, 142, 142, 142, 142,
    142, 142, 142, 3,   3,   3,   3,   3,   3,   3,   3,   3,   3,   3,   3,   64,  64,  64,  64,  64,
    64,  64,  64,  64,  64,  64,  64,  64,  118, 118, 32,  32,  32,  32,  32,  32,  32,  32,  32,  32,
    32,  32,  32,  32,  32,  32,  32,  32,  32,  32,  32,  32,  136, 136, 136, 136, 136, 136, 136, 136,
    26,  26,  26,  26,  26,  26,  26,  26,  26,  26,  99,  99,  99,  99,  99,  99,  99,  99,  65,  65,
    65,  65,  65,  65,  205, 205, 205, 205, 205, 205, 205, 205, 205, 205, 205, 205, 205, 205, 205, 205,
    205, 205, 205, 205, 205, 205, 205, 205, 205, 205, 205, 205, 84,  84,  84,  84,  84,  84,  84,  84,
    84,  84,  84,  84,  84,  84,  84,  84,  84,  84,  84,  84,  16,  16,  16,  16,  16,  16,  206, 206,
    206, 206, 206, 206, 206, 206, 206, 206, 206, 206, 206, 206, 244, 244, 244, 244, 244, 244, 44,  44,
    44,  44,  44,  44,  44,  44,  44,  44,  44,  44,  44,  44,  44,  44,  44,  44,  44,  44,  44,  44,
    44,  44,  44,  44,  102, 102, 102, 102, 102, 102, 102, 102, 102, 102, 102, 102, 102, 102, 102, 102,
    102, 102, 102, 102, 102, 102, 102, 102, 97,  97,  97,  97,  97,  97,  97,  97,  97,  97,  97,  97,
    97,  97,  97,  97,  97,  97,  97,  97,  97,  97,  97,  97,  97,  97,  97,  97,  97,  92,  92,  92,
    92,  92,  92,  92,  200, 200, 200, 200, 200, 200, 200, 200, 200, 200, 200, 200, 200, 200, 200, 200,
    200, 200, 200, 200, 200, 200, 129, 129, 129, 129, 129, 129, 129, 129, 129, 129, 129, 129, 129, 129,
    129, 129, 136, 15,  15,  15,  15,  15,  15,  15,  15,  15,  15,  15,  15,  15,  15,  15,  15,  169,
    169, 169, 169, 169, 169, 169, 169, 169, 169, 169, 121, 121, 121, 121, 121, 121, 121, 121, 121, 121,
    121, 121, 121, 121, 121, 121, 121, 121, 121, 121, 121, 121, 121, 121, 121, 121, 88,  88,  88,  88,
    88,  88,  88,  88,  88,  88,  88,  88,  88,  88,  88,  88,  90,  90,  90,  90,  90,  90,  90,  232,
    232, 232, 232, 232, 232, 22,  22,  22,  22,  22,  22,  22,  22,  22,  22,  22,  22,  22,  22,  22,
    22,  22,  22,  22,  151, 151, 151, 151, 151, 151, 151, 151, 151, 151, 151, 151, 151, 151, 151, 151,
    151, 151, 151, 151, 151, 151, 15,  15,  15,  15,  15,  15,  15,  15,  15,  81,  81,  81,  81,  81,
    81,  81,  81,  81,  81,  81,  81,  81,  233, 233, 233, 233, 233, 233, 233, 233, 233, 233, 233, 233,
    233, 233, 233, 233, 233, 233, 233, 233, 233, 233, 233, 233, 233, 233, 228, 228, 228, 228, 228, 228,
    228, 228, 228, 228, 228, 228, 228, 228, 228, 228, 228, 242, 242, 242, 242, 242, 242, 242, 242, 242,
    242, 242, 161, 161, 161, 161, 161, 161, 161, 161, 161, 161, 161, 161, 161, 161, 150, 150, 150, 150,
    150, 150, 150, 150, 150, 150, 150, 150, 150, 150, 150, 150, 150, 150, 150, 150, 150, 150, 150, 150,
    150, 150, 150, 150, 176, 176, 254, 254, 254, 254, 254, 254, 254, 254, 254, 254, 254, 254, 254, 254,
    254, 254, 254, 254, 254, 254, 227, 227, 227, 227, 227, 227, 227, 227, 227, 227, 227, 227, 227, 227,
    59,  193, 193, 193, 193, 193, 193, 193, 193, 193, 120, 120, 120, 120, 120, 120, 120, 120, 120, 157,
    157, 157, 157, 157, 157, 157, 157, 157, 157, 157, 157, 157, 157, 157, 157, 157, 157, 157, 108, 108,
    108, 108, 108, 108, 108, 108, 108, 108, 151, 151, 151, 151, 151, 151, 151, 151, 151, 82,  82,  82,
    82,  82,  82,  82,  82,  82,  82,  82,  82,  82,  82,  82,  82,  82,  82,  82,  82,  82,  82,  82,
    82,  82,  82,  82,  82,  96,  96,  96,  96,  96,  151, 151, 211, 211, 211, 211, 211, 211, 211, 211,
    211, 211, 211, 211, 211, 211, 211, 211, 211, 211, 211, 211, 211, 173, 173, 173, 173, 173, 173, 173,
    173, 173, 173, 173, 173, 173, 173, 173, 173, 173, 173, 31,  31,  31,  31,  31,  31,  182, 182, 182,
    238, 238, 238, 238, 238, 238, 238, 238, 238, 238, 238, 238, 238, 238, 16,  16,  16,  16,  16,  16,
    31,  31,  31,  31,  31,  31,  31,  31,  212, 212, 212, 212, 212, 212, 212, 212, 212, 212, 212, 212,
    212, 212, 212, 212, 212, 212, 212, 161, 161, 195, 195, 195, 195, 195, 195, 195, 195, 195, 195, 195,
    180, 180, 180, 180, 180, 180, 180, 180, 180, 180, 85,  85,  85,  85,  85,  85,  85,  85,  85,  85,
    85,  85,  85,  85,  85,  85,  85,  85,  85,  85,  6,   6,   6,   6,   6,   6,   6,   6,   6,   6,
    6,   6,   6,   6,   6,   6,   6,   6,   6,   6,   6,   237, 237, 237, 237, 237, 237, 237, 237, 237,
    237, 237, 237, 237, 237, 223, 223, 223, 223, 223, 223, 223, 223, 223, 223, 223, 223, 223, 223, 223,
    223, 223, 223, 223, 223, 223, 223, 223, 134, 134, 134, 249, 249, 249, 249, 249, 249, 249, 249, 249,
    249, 249, 249, 249, 249, 249, 249, 162, 162, 162, 162, 162, 162, 162, 162, 162, 162, 162, 162, 162,
    162, 162, 162, 162, 162, 162, 43,  43,  43,  43,  43,  43,  43,  43,  43,  43,  43,  43,  43,  43,
    43,  43,  26,  26,  26,  26,  26,  26,  26,  26,  26,  26,  26,  26,  26,  26,  26,  26,  26,  26,
    26,  26,  26,  26,  26,  26,  26,  26,  26,  26,  26,  233, 233, 233, 233, 233, 233, 233, 233, 233,
    233, 233, 233, 233, 233, 233, 233, 233, 233, 233, 233, 233, 233, 233, 31,  31,  31,  31,  31,  31,
    31,  31,  31,  177, 177, 177, 177, 177, 177, 177, 177, 177, 177, 177, 177, 177, 177, 177, 177, 177,
    177, 177, 177, 177, 177, 177, 177, 177, 177, 177, 177, 69,  69,  69,  69,  69,  69,  69,  69,  69,
    69,  69,  69,  69,  69,  69,  69,  69,  69,  69,  69,  69,  69,  69,  69,  69,  220, 220, 220, 220,
    220, 220, 220, 220, 220, 220, 220, 220, 220, 220, 220, 220, 220, 220, 220, 220, 220, 220, 66,  66,
    66,  66,  66,  66,  66,  66,  66,  66,  76,  76,  54,  54,  121, 121, 121, 121, 121, 121, 121, 121,
    121, 121, 121, 121, 121, 121, 121, 121, 121, 121, 121, 121, 121, 121, 121, 121, 121, 121, 249, 249,
    249, 249, 249, 249, 249, 249, 249, 249, 249, 249, 249, 249, 249, 249, 249, 249, 249, 249, 249, 222,
    222, 222, 222, 222, 222, 222, 222, 222, 222, 222, 222, 222, 222, 222, 222, 222, 222, 222, 222, 68,
    68,  227, 227, 227, 227, 227, 227, 227, 227, 227, 227, 227, 227, 227, 227, 227, 227, 227, 227, 227,
    227, 227, 227, 227, 227, 227, 227, 227, 227, 227, 143, 143, 143, 143, 143, 143, 143, 143, 143, 143,
    143, 143, 143, 143, 143, 143, 143, 143, 143, 143, 187, 187, 187, 187, 187, 187, 187, 187, 187, 187,
    187, 187, 187, 187, 187, 187, 187, 187, 187, 187, 187, 187, 187, 187, 187, 18,  18,  18,  18,  18,
    18,  18,  18,  18,  18,  18,  18,  18,  18,  18,  241, 241, 241, 241, 23,  23,  23,  23,  23,  23,
    23,  23,  23,  23,  23,  23,  23,  23,  23,  23,  23,  23,  23,  23,  23,  23,  23,  23,  23,  23,
    23,  23,  145, 145, 145, 145, 145, 145, 145, 145, 145, 145, 145, 145, 145, 145, 145, 113, 113, 113,
    113, 113, 113, 113, 148, 148, 148, 148, 148, 148, 148, 148, 148, 148, 148, 148, 148, 148, 148, 148,
    148, 148, 148, 148, 148, 148, 148, 148, 148, 148, 148, 148, 148, 94,  94,  94,  94,  94,  94,  88,
    88,  88,  88,  88,  88,  88,  88,  88,  88,  88,  88,  88,  88,  88,  88,  33,  33,  33,  33,  33,
    33,  33,  156, 156, 156, 156, 156, 156, 156, 156, 156, 156, 156, 156, 156, 160, 160, 160, 160, 42,
    42,  42,  42,  42,  42,  42,  42,  42,  124, 124, 124, 124, 124, 124, 124, 124, 124, 124, 124, 124,
    124, 124, 124, 124, 124, 124, 124, 124, 124, 124, 124, 124, 213, 213, 213, 213, 213, 213, 213, 213,
    213, 213, 213, 213, 213, 213, 213, 213, 213, 213, 213, 213, 213, 213, 56,  56,  56,  56,  56,  56,
    56,  56,  56,  56,  56,  56,  56,  56,  56,  56,  56,  56,  56,  56,  56,  56,  56,  56,  56,  56,
    108, 108, 108, 108, 108, 108, 108, 108, 108, 108, 108, 108, 108, 108, 108, 108, 108, 108, 108, 108,
    108, 108, 108, 108, 108, 108, 108, 90,  90,  90,  90,  90,  90,  90,  90,  90,  90,  90,  90,  90,
    90,  90,  90,  90,  90,  90,  90,  204, 204, 204, 204, 204, 204, 204, 204, 204, 204, 204, 204, 204,
    204, 204, 134, 134, 134, 134, 134, 134, 223, 223, 223, 223, 223, 223, 223, 223, 223, 223, 223, 255,
    255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 240, 240, 240, 240, 240, 240,
    240, 240, 240, 240, 240, 240, 240, 240, 240, 224, 224, 224, 224, 224, 224, 224, 224, 224, 224, 224,
    224, 224, 224, 224, 224, 224, 224, 224, 224, 224, 224, 65,  65,  179, 179, 179, 179, 179, 179, 244,
    244, 244, 244, 244, 244, 244, 244, 244, 244, 244, 244, 244, 244, 244, 244, 244, 244, 244, 244, 244,
    244, 244, 244, 244, 19,  19,  19,  19,  19,  19,  19,  19,  19,  19,  19,  19,  19,  19,  19,  19,
    19,  19,  19,  19,  168, 168, 168, 168, 168, 168, 168, 168, 168, 168, 168, 168, 168, 168, 168, 168,
    168, 168, 168, 168, 168, 168, 168, 168, 168, 168, 168, 77,  69,  69,  69,  69,  69,  69,  186, 186,
    186, 186, 186, 186, 186, 186, 186, 186, 186, 186, 186, 186, 186, 186, 186, 186, 186, 186, 186, 186,
    186, 186, 186, 186, 186, 10,  10,  10,  10,  10,  10,  10,  10,  10,  10,  10,  10,  10,  10,  10,
    10,  10,  10,  10,  10,  10,  10,  10,  236, 236, 236, 236, 236, 236, 236, 236, 236, 236, 236, 236,
    236, 236, 236, 236, 236, 236, 236, 236, 236, 236, 236, 236, 100, 100, 100, 100, 100, 100, 100, 100,
    100, 100, 100, 100, 100, 100, 100, 100, 100, 100, 100, 100, 34,  34,  34,  34,  34,  34,  34,  34,
};

const surv_m27_dict = [_]u8{
    112, 112, 112, 112, 112, 18,  18,  18,  18,  18,  18,  18,  18,  18,  18,  18,  18,  18,  18,  97,
    97,  97,  97,  97,  97,  97,  97,  97,  97,  97,  97,  97,  232, 232, 232, 232, 232, 232, 232, 232,
    232, 232, 82,  82,  82,  221, 221, 221, 221, 221, 221, 221, 221, 221, 221, 221, 221, 221, 221, 221,
    221, 221, 221, 221, 221, 137, 137, 137, 137, 137, 137, 137, 137, 137, 137, 137, 137, 137, 137, 137,
    137, 137, 137, 137, 137, 137, 137, 137, 19,  19,  19,  19,  19,  19,  19,  19,  19,  19,  19,  19,
    19,  19,  19,  19,  19,  19,  19,  19,  28,  28,  28,  28,  28,  28,  28,  28,  28,  28,  28,  28,
    28,  28,  28,  28,  28,  28,  28,  28,  28,  28,  28,  28,  28,  28,  44,  44,  44,  44,  44,  44,
    44,  44,  44,  44,  44,  44,  186, 186, 186, 186, 186, 186, 186, 186, 186, 186, 186, 186, 186, 186,
    186, 186, 186, 186, 186, 68,  199, 199, 199, 199, 199, 199, 199, 199, 199, 199, 199, 199, 199, 199,
    250, 250, 250, 250, 250, 250, 250, 250, 250, 250, 250, 250, 250, 250, 250, 250, 250, 250, 250, 250,
    250, 250, 250, 120, 120, 120, 120, 120, 120, 120, 120, 120, 120, 120, 120, 120, 120, 120, 120, 120,
    120, 235, 235, 235, 235, 235, 235, 235, 235, 235, 235, 235, 106, 106, 106, 106, 106, 106, 106, 106,
    106, 19,  19,  19,  19,  19,  19,  19,  19,  19,  19,  19,  19,  19,  19,  19,  19,  19,  19,  19,
    19,  19,  117, 117, 117, 74,  74,  74,  74,  74,  74,  74,  74,  74,  74,  74,  74,  74,  74,  74,
    74,  74,  74,  74,  74,  74,  74,  229, 229, 229, 229, 229, 229, 229, 229, 229, 229, 229, 229, 229,
    229, 229, 229, 229, 229, 229, 27,  27,  27,  27,  27,  27,  27,  146, 146, 146, 146, 146, 146, 146,
    146, 146, 146, 175, 175, 175, 175, 175, 175, 23,  23,  23,  23,  23,  23,  66,  66,  66,  66,  66,
    66,  66,  66,  157, 157, 157, 157, 157, 157, 157, 157, 157, 157, 157, 157, 157, 157, 157, 157, 157,
    157, 157, 157, 157, 157, 157, 241, 241, 241, 241, 241, 241, 241, 241, 241, 241, 241, 241, 241, 241,
    241, 241, 241, 241, 241, 241, 241, 241, 241, 241, 241, 241, 241, 211, 211, 211, 211, 211, 211, 211,
    211, 211, 211, 211, 211, 211, 211, 211, 211, 211, 211, 211, 211, 211, 211, 211, 211, 211, 211, 77,
    77,  77,  77,  77,  77,  77,  77,  77,  77,  77,  77,  77,  77,  77,  77,  77,  77,  77,  77,  77,
    77,  77,  77,  77,  77,  77,  77,  9,   9,   9,   9,   9,   9,   9,   9,   9,   9,   9,   9,
};

const surv_m27_input = [_]u8{
    216, 216, 216, 216, 216, 216, 216, 216, 216, 216, 216, 216, 216, 216, 216, 216, 216, 216, 216, 216,
    216, 216, 110, 110, 110, 110, 110, 110, 110, 110, 110, 110, 18,  18,  18,  18,  18,  18,  18,  18,
    18,  18,  18,  18,  18,  18,  50,  50,  50,  50,  50,  50,  50,  50,  50,  50,  104, 104, 104, 104,
    157, 157, 244, 244, 244, 244, 244, 244, 244, 244, 244, 244, 244, 244, 244, 244, 244, 244, 244, 244,
    244, 244, 244, 244, 244, 244, 134, 134, 134, 134, 134, 134, 134, 134, 134, 134, 134, 134, 134, 134,
    134, 134, 134, 134, 134, 134, 23,  23,  23,  192, 192, 192, 192, 192, 192, 192, 192, 192, 192, 192,
    192, 192, 192, 72,  72,  72,  72,  72,  72,  72,  72,  197, 197, 197, 197, 197, 197, 197, 197, 197,
    197, 197, 197, 197, 197, 197, 197, 197, 197, 197, 197, 244, 244, 244, 244, 244, 244, 244, 244, 244,
    244, 244, 244, 244, 244, 244, 244, 244, 44,  44,  44,  44,  229, 229, 229, 229, 229, 229, 229, 229,
    229, 229, 150, 127, 112, 112, 112, 112, 112, 112, 112, 18,  18,  18,  18,  18,  18,  18,  18,  18,
    18,  18,  18,  18,  18,  18,  18,  18,  18,  18,  18,  18,  18,  18,  18,  18,  18,  18,  18,  90,
    90,  90,  90,  90,  90,  90,  90,  109, 109, 109, 109, 109, 109, 109, 109, 109, 109, 109, 109, 109,
    109, 109, 109, 109, 109, 109, 109, 109, 33,  33,  33,  33,  33,  33,  33,  33,  33,  33,  33,  33,
    33,  33,  33,  33,  33,  33,  33,  33,  33,  33,  33,  33,  33,  33,  33,  255, 255, 255, 255, 255,
    255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 131, 131, 131, 131, 131, 131, 131,
    131, 131, 131, 131, 131, 131, 131, 131, 131, 131, 131, 131, 131, 131, 131, 131, 131, 131, 131, 160,
    160, 160, 160, 160, 160, 160, 160, 160, 160, 160, 160, 160, 160, 160, 160, 160, 87,  87,  87,  87,
    87,  87,  87,  87,  87,  87,  87,  87,  87,  87,  87,  87,  87,  87,  87,  87,  87,  142, 142, 142,
    142, 142, 142, 142, 142, 142, 142, 142, 89,  89,  89,  89,  89,  89,  89,  89,  89,  89,  89,  89,
    89,  89,  89,  89,  89,  89,  89,  89,  89,  89,  89,  89,  231, 231, 231, 231, 231, 231, 231, 231,
    231, 34,  34,  34,  34,  34,  34,  34,  34,  34,  161, 161, 161, 161, 161, 161, 161, 161, 161, 161,
    161, 161, 161, 161, 65,  65,  65,  65,  65,  65,  65,  65,  65,  65,  65,  65,  65,  65,  65,  65,
    65,  65,  65,  65,  65,  65,  65,  65,  65,  65,  65,  65,  65,  119, 119, 119, 119, 119, 119, 119,
    119, 119, 119, 119, 119, 119, 119, 119, 119, 119, 119, 119, 119, 171, 171, 171, 171, 171, 171, 171,
    171, 171, 171, 128, 128, 128, 128, 128, 128, 128, 128, 128, 128, 128, 128, 128, 128, 128, 128, 191,
    191, 191, 191, 191, 191, 191, 191, 191, 191, 191, 191, 191, 191, 191, 173, 173, 173, 173, 173, 173,
    173, 173, 173, 173, 173, 173, 173, 173, 163, 163, 163, 163, 163, 163, 163, 163, 163, 163, 163, 163,
    163, 163, 163, 163, 163, 163, 163, 163, 163, 163, 163, 163, 163, 171, 171, 171, 171, 171, 171, 171,
    171, 171, 171, 171, 171, 171, 171, 111, 111, 111, 111, 111, 111, 111, 111, 111, 111, 111, 111, 111,
    3,   3,   3,   3,   3,   3,   3,   3,   3,   142, 142, 142, 142, 142, 142, 142, 142, 142, 142, 142,
    142, 142, 142, 142, 142, 142, 142, 142, 142, 142, 142, 142, 142, 142, 142, 114, 114, 114, 114, 114,
    114, 114, 114, 114, 114, 114, 114, 114, 114, 114, 114, 114, 114, 114, 114, 114, 114, 114, 114, 114,
    114, 114, 114, 187, 187, 187, 187, 187, 187, 187, 187, 187, 187, 187, 187, 187, 187, 187, 187, 187,
    187, 187, 187, 187, 187, 187, 68,  68,  68,  68,  68,  68,  24,  24,  24,  24,  24,  24,  24,  24,
    24,  24,  24,  24,  24,  24,  24,  24,  235, 235, 235, 235, 235, 235, 235, 235, 235, 235, 235, 19,
    19,  19,  19,  19,  19,  19,  19,  19,  19,  19,  19,  175, 175, 175, 175, 175, 175, 175, 175, 175,
    175, 175, 175, 175, 175, 175, 198, 198, 198, 198, 198, 198, 198, 198, 198, 198, 198, 198, 198, 198,
    198, 198, 198, 198, 67,  67,  67,  67,  67,  67,  67,  67,  67,  67,  67,  67,  67,  67,  67,  67,
    67,  67,  205, 205, 205, 205, 205, 205, 205, 205, 205, 205, 205, 205, 205, 205, 205, 205, 205, 205,
    205, 205, 205, 205, 130, 130, 140, 140, 140, 140, 140, 140, 140, 140, 140, 140, 140, 140, 197, 197,
    197, 197, 197, 197, 197, 197, 197, 197, 197, 10,  10,  10,  10,  10,  10,  10,  10,  10,  10,  62,
    62,  62,  62,  62,  62,  62,  62,  62,  62,  62,  62,  62,  62,  62,  62,  62,  62,  62,  62,  62,
    62,  62,  62,  62,  62,  35,  35,  35,  35,  35,  35,  35,  35,  35,  35,  35,  35,  35,  35,  35,
    35,  35,  35,  35,  35,  35,  35,  35,  126, 126, 126, 126, 126, 126, 126, 126, 126, 126, 126, 126,
    126, 126, 126, 126, 126, 226, 226, 226, 226, 20,  20,  20,  20,  20,  20,  20,  20,  20,  20,  20,
    20,  20,  20,  20,  20,  20,  20,  20,  20,  20,  20,  20,  20,  20,  20,  217, 217, 217, 217, 217,
    217, 217, 217, 217, 217, 217, 217, 217, 217, 217, 217, 217, 217, 217, 217, 217, 217, 217, 217, 217,
    217, 217, 217, 216, 216, 216, 216, 216, 216, 216, 216, 216, 216, 216, 68,  20,  20,  20,  20,  20,
    20,  20,  20,  20,  20,  20,  20,  20,  20,  20,  20,  20,  20,  20,  20,  20,  20,  20,  20,  20,
    130, 130, 130, 130, 130, 130, 130, 130, 130, 130, 130, 130, 130, 130, 130, 130, 130, 130, 130, 74,
    74,  74,  74,  74,  74,  74,  74,  74,  74,  74,  74,  74,  74,  74,  74,  74,  74,  74,  74,  178,
    178, 178, 178, 178, 178, 251, 251, 251, 251, 251, 251, 251, 251, 251, 251, 251, 251, 251, 251, 251,
    251, 251, 251, 251, 251, 251, 251, 71,  71,  71,  71,  71,  71,  71,  71,  71,  71,  87,  87,  87,
    87,  87,  87,  87,  87,  87,  87,  87,  87,  87,  87,  87,  221, 11,  11,  11,  11,  11,  49,  49,
    49,  49,  49,  49,  49,  49,  49,  49,  49,  49,  49,  49,  49,  49,  49,  49,  49,  49,  49,  49,
    49,  49,  160, 160, 160, 160, 160, 160, 160, 160, 160, 160, 160, 160, 160, 227, 227, 227, 227, 227,
    227, 227, 227, 227, 227, 227, 227, 227, 227, 227, 227, 227, 227, 227, 227, 227, 227, 101, 101, 101,
    101, 101, 101, 101, 101, 101, 101, 101, 101, 101, 101, 101, 101, 101, 67,  67,  67,  67,  67,  67,
    67,  67,  67,  67,  67,  67,  67,  67,  67,  67,  67,  67,  67,  67,  67,  67,  67,  67,  128, 128,
    128, 128, 128, 128, 128, 128, 128, 128, 128, 128, 128, 128, 128, 128, 128, 128, 128, 128, 128, 128,
    128, 128, 128, 128, 128, 46,  46,  46,  84,  84,  84,  84,  84,  84,  84,  84,  84,  84,  84,  84,
    84,  84,  84,  84,  84,  22,  22,  22,  22,  22,  22,  22,  22,  22,  22,  22,  22,  22,  22,  22,
    22,  22,  22,  22,  22,  22,  22,  213, 213, 213, 213, 213, 243, 243, 243, 243, 243, 243, 243, 243,
    243, 243, 243, 243, 243, 243, 243, 243, 243, 243, 243, 243, 243, 243, 243, 243, 243, 243, 84,  84,
    84,  84,  84,  84,  84,  84,  84,  84,  84,  84,  84,  84,  84,  84,  84,  84,  84,  84,  138, 138,
    138, 138, 138, 138, 138, 138, 138, 138, 138, 138, 138, 138, 138, 138, 138, 138, 138, 138, 138, 138,
    138, 138, 138, 138, 138, 138, 160, 160, 160, 160, 160, 160, 160, 160, 160, 160, 160, 160, 160, 160,
    29,  29,  29,  29,  29,  29,  29,  29,  29,  29,  29,  29,  29,  29,  29,  29,  29,  29,  29,  29,
    29,  29,  29,  29,  129, 129, 129, 129, 129, 129, 129, 129, 129, 129, 129, 129, 129, 129, 129, 129,
    129, 129, 129, 129, 129, 129, 129, 129, 129, 207, 207, 207, 207, 207, 207, 207, 207, 207, 207, 207,
    207, 207, 207, 207, 207, 207, 37,  37,  37,  18,  18,  18,  18,  18,  224, 224, 224, 224, 224, 224,
    224, 224, 224, 224, 224, 224, 224, 224, 224, 224, 224, 224, 224, 224, 224, 197, 197, 197, 197, 197,
    197, 197, 197, 197, 197, 197, 197, 197, 197, 197, 197, 197, 197, 197, 197, 197, 197, 171, 171, 171,
    171, 171, 171, 171, 171, 171, 171, 171, 171, 171, 171, 171, 171, 171, 171, 171, 171, 171, 171, 60,
    60,  60,  60,  60,  60,  60,  60,  60,  60,  60,  60,  60,  60,  60,  60,  60,  60,  60,  60,  60,
    60,  60,  60,  60,  60,  60,  60,  118, 118, 118, 118, 118, 118, 118, 118, 118, 118, 118, 118, 118,
    118, 118, 46,  46,  46,  46,  46,  46,  46,  58,  58,  58,  58,  58,  58,  58,  58,  58,  58,  58,
    58,  58,  58,  58,  58,  58,  58,  58,  71,  71,  71,  71,  71,  71,  71,  71,  71,  71,  71,  71,
    71,  71,  71,  71,  71,  71,  71,  71,  71,  71,  71,  71,  41,  41,  41,  41,  41,  41,  41,  41,
    41,  41,  41,  41,  96,  96,  96,  96,  96,  96,  96,  96,  243, 243, 243, 243, 243, 243, 243, 243,
    243, 151, 151, 151, 151, 151, 151, 151, 151, 151, 151, 151, 151, 151, 151, 181, 181, 181, 181, 181,
    181, 181, 181, 181, 181, 181, 181, 181, 181, 181, 181, 181, 181, 181, 181, 181, 181, 181, 181, 181,
    181, 181, 128, 128, 128, 125, 125, 125, 125, 125, 125, 125, 125, 125, 125, 125, 125, 125, 125, 125,
    125, 125, 125, 125, 125, 125, 125, 125, 125, 88,  88,  88,  88,  88,  88,  88,  88,  88,  88,  88,
    88,  88,  88,  88,  88,  88,  88,  88,  88,  88,  88,  88,  88,  88,  88,  240, 240, 240, 240, 240,
    240, 240, 240, 240, 240, 240, 240, 240, 240, 240, 240, 240, 240, 240, 240, 240, 240, 240, 240, 240,
    165, 165, 165, 165, 165, 165, 165, 165, 165, 148, 140, 140, 140, 140, 140, 140, 140, 140, 140, 140,
    140, 140, 140, 140, 140, 140, 140, 140, 140, 140, 140, 140, 86,  86,  86,  86,  86,  86,  86,  86,
    86,  86,  86,  86,  86,  86,  86,  86,  86,  86,  86,  86,  86,  86,  86,  86,  86,  86,  91,  91,
    91,  91,  91,  91,  91,  91,  91,  91,  91,  91,  91,  91,  91,  91,  91,  91,  91,  104, 104, 104,
    104, 104, 104, 104, 104, 104, 104, 104, 104, 104, 104, 104, 104, 104, 104, 104, 240, 240, 240, 240,
    240, 240, 240, 240, 240, 240, 240, 240, 240, 240, 240, 212, 212, 212, 212, 212, 212, 212, 212, 212,
    212, 212, 212, 212, 244, 244, 244, 244, 244, 244, 244, 244, 244, 244, 244, 244, 244, 244, 244, 244,
    244, 244, 73,  73,  73,  73,  73,  73,  73,  73,  73,  73,  62,  62,  62,  62,  62,  62,  62,  62,
    62,  62,  62,  62,  62,  62,  62,  62,  62,  62,  62,  62,  62,  62,  62,  135, 135, 135, 135, 135,
    135, 135, 135, 135, 135, 135, 135, 135, 135, 135, 135, 135, 135, 135, 135, 135, 135, 166, 166, 166,
    166, 166, 166, 166, 166, 166, 166, 166, 166, 166, 143, 143, 143, 143, 143, 143, 143, 143, 143, 143,
    54,  54,  54,  54,  54,  54,  54,  54,  54,  54,  189, 189, 189, 189, 189, 189, 189, 189, 189, 189,
    189, 189, 189, 189, 189, 189, 189, 195, 195, 195, 195, 195, 195, 195, 195, 195, 195, 195, 195, 195,
    195, 195, 195, 195, 195, 195, 195, 195, 195, 195, 195, 195, 195, 195, 195, 74,  74,  74,  74,  74,
    74,  74,  74,  220, 220, 220, 220, 220, 220, 220, 220, 220, 220, 220, 220, 220, 220, 220, 220, 220,
    125, 125, 125, 174, 174, 174, 174, 174, 174, 174, 174, 174, 174, 174, 174, 174, 174, 174, 174, 174,
    174, 174, 174, 96,  96,  96,  96,  96,  96,  96,  96,  96,  96,  107, 107, 107, 107, 107, 107, 107,
    107, 107, 107, 107, 107, 107, 107, 107, 107, 107, 107, 107, 107, 107, 107, 107, 107, 107, 107, 107,
    107, 115, 115, 115, 115, 115, 115, 115, 115, 115, 115, 115, 115, 115, 115, 115, 115, 115, 115, 115,
    115, 115, 115, 115, 115, 115, 115, 115, 115, 115, 76,  76,  76,  76,  76,  76,  76,  76,  76,  76,
    76,  76,  76,  76,  214, 154, 154, 154, 154, 154, 154,
};

const survivor_inputs = [_][]const u8{
    &surv_m12_input, &surv_m17_input, &surv_m22_input, &surv_m23_input,
    &surv_m24_input, &surv_m25_input, &surv_m27_input,
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
    .{ .name = "raw-words-10264", .source = .{ .generated = .{ .name = "", .len = 10264, .kind = .words, .seed = 141981 } } },
    .{ .name = "raw-two-symbols-17900", .source = .{ .generated = .{ .name = "", .len = 17900, .kind = .two_symbols, .seed = 791639 } } },
    .{ .name = "raw-words-9000-self", .source = .{ .generated = .{ .name = "", .len = 9000, .kind = .words, .seed = 30 } } },
    .{ .name = "slice-words-6000-at-1000", .source = .{ .slice = .{ .of = .{ .name = "", .len = 9000, .kind = .words, .seed = 35 }, .from = 1000, .len = 6000 } } },
    .{ .name = "slice-far-repeat-tail", .source = .{ .slice = .{ .of = .{ .name = "", .len = 1400000, .kind = .far_repeat, .seed = 34 }, .from = 692000, .len = 8000 } } },
    .{ .name = "zd-words", .source = .{ .trained = "zd-words" } },
    .{ .name = "zd-csv", .source = .{ .trained = "zd-csv" } },
    .{ .name = "zd-words-id200", .source = .{ .reid = .{ .of = "zd-words", .id = 200 } } },
    .{ .name = "zd-words-id1000", .source = .{ .reid = .{ .of = "zd-words", .id = 1000 } } },
    .{ .name = "zd-words-id256", .source = .{ .reid = .{ .of = "zd-words", .id = 256 } } },
    .{ .name = "zd-words-id65536", .source = .{ .reid = .{ .of = "zd-words", .id = 65536 } } },
    .{ .name = "raw-two-symbols-12528", .source = .{ .generated = .{ .name = "", .len = 12528, .kind = .two_symbols, .seed = 17340 } } },
    .{ .name = "raw-skewed-18461", .source = .{ .generated = .{ .name = "", .len = 18461, .kind = .skewed, .seed = 666518 } } },
    .{ .name = "crafted-words", .source = .{ .crafted = .{ .content = .{ .name = "", .len = 3000, .kind = .words, .seed = 23 }, .id = 70000 } } },
    // hunted (D1): a dfast dictMatchState match that reaches exactly the
    // CDict's end and continues into the prefix (countAcrossDict) -- see
    // dict_cases_attach_fast's "attach-dfast-cross-end"
    .{ .name = "boundary-echo-dict", .source = .{ .literal = &dict_boundary_echo_dict } },
    // hunted (D1): mutation-sweep survivors' killing cases
    .{ .name = "surv-m12-dict", .source = .{ .literal = &surv_m12_dict } },
    .{ .name = "surv-m17-dict", .source = .{ .literal = &surv_m17_dict } },
    .{ .name = "surv-m22-dict", .source = .{ .literal = &surv_m22_dict } },
    .{ .name = "surv-m23-dict", .source = .{ .literal = &surv_m23_dict } },
    .{ .name = "surv-m24-dict", .source = .{ .literal = &surv_m24_dict } },
    .{ .name = "surv-m25-dict", .source = .{ .literal = &surv_m25_dict } },
    .{ .name = "surv-m27-dict", .source = .{ .literal = &surv_m27_dict } },
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
        .literal => |bytes| {
            @memcpy(out[0..bytes.len], bytes);
            return bytes.len;
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
        .literal => |bytes| bytes.len,
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
    /// The same, the input right after the dictionary in memory: libzstd
    /// keeps a copy, so the input never continues it.
    loadadj,
    /// `ZSTD_createCDict(level)` + `ZSTD_CCtx_refCDict` (`CDict.init`, `.cdict`).
    cdict,
    /// `ZSTD_createCDict_advanced2` with the level and the parameters (`CDict.initAdvanced`).
    cdictadv,
    /// `ZSTD_createCDict_advanced2` by reference (`CDict.initReference`),
    /// the input right after the dictionary in memory: the CDict's window
    /// continues into it.
    cdictrefadj,
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

/// Every dictionary golden: D0's (the dictionary in the window) and those
/// of the attach variants (the CDict searched in place).
pub const dict_cases = dict_cases_d0 ++ dict_cases_attach_lazy ++ dict_cases_load_adjacent ++ dict_cases_dds;

/// `.raw` is loaded by copy (`ZSTD_dlm_byCopy`): an input right after the
/// caller's dictionary in memory must not continue the context's own
/// CDict's window. Copied (the default above the attach cutoffs, and
/// forced), and loaded into the context anew.
const dict_cases_load_adjacent = [_]DictCase{
    .{ .name = "load-adjacent-copy", .input = in_words_40000, .dict = "raw-words-8000", .path = .loadadj, .levels = some_levels },
    .{ .name = "load-adjacent-force-copy", .input = in_words_3000, .dict = "raw-words-8000", .path = .loadadj, .params = "forceAttachDict=2", .levels = &.{ -5, 1, 3, 5, 13 } },
    .{ .name = "load-adjacent-force-load", .input = in_words_40000, .dict = "raw-words-8000", .path = .loadadj, .params = "forceAttachDict=3", .levels = &.{ -5, 1, 3, 5, 13 } },
    // ... whereas a CDict by reference is continued, in libzstd too
    .{ .name = "cdictref-adjacent-copy", .input = in_words_40000, .dict = "raw-words-8000", .path = .cdictrefadj, .levels = &.{ -5, 3, 13 } },
};

const dict_cases_d0 = [_]DictCase{
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

const in_csv_32768: Case = .{ .name = "", .len = 32768, .kind = .csv, .seed = 31 };
const in_csv_32769: Case = .{ .name = "", .len = 32769, .kind = .csv, .seed = 31 };
const in_mix_20000: Case = .{ .name = "", .len = 20000, .kind = .mix, .seed = 32 };
/// A CDict of zd-words (4 KB) is made for 4.6 KB: levels 4 greedy, 5 lazy,
/// 6..8 lazy2, 9 and 10 btlazy2, all with a 16 KB window (hash chains).
const levels_attach_small: []const i32 = &.{ 4, 5, 6, 7, 8, 9, 10 };
/// A CDict of 30 KB is made for the 128 KB row: 5 greedy, 6 lazy, 7..10
/// lazy2 (row match finder), 11 and 12 btlazy2.
const levels_attach_30k: []const i32 = &.{ 5, 6, 7, 8, 10, 11, 12 };

/// The dictMatchState variants of `greedy`, `lazy`, `lazy2` and `btlazy2`
/// (hash chain, rows, binary tree): an attached CDict searched in place.
const dict_cases_attach_lazy = [_]DictCase{
    // at the cutoff (32 KB, attached) and a byte above it (copied)
    .{ .name = "attach-lazy-cdict", .input = in_words_3000, .dict = "zd-words", .path = .cdict, .levels = levels_attach_small, .checksums = &.{ false, true } },
    .{ .name = "attach-lazy-cdict-32k", .input = in_csv_32768, .dict = "raw-csv-30000", .path = .cdict, .levels = levels_attach_30k },
    .{ .name = "attach-lazy-cdict-32k-plus-1", .input = in_csv_32769, .dict = "raw-csv-30000", .path = .cdict, .levels = levels_attach_30k },
    .{ .name = "attach-lazy-load", .input = in_words_3000, .dict = "raw-words-8000", .path = .load, .levels = &.{ 4, 5, 6, 8, 9, 10 } },
    .{ .name = "attach-lazy-usingcdict", .input = in_words_3000, .dict = "zd-words", .path = .usingcdict, .levels = &.{ 4, 5, 7, 9 } },
    // content types: a full dictionary as raw content, tables to check
    .{ .name = "attach-lazy-full-as-raw", .input = in_words_3000, .dict = "zd-words", .path = .cdictadv, .content_type = 1, .levels = &.{ 4, 6, 9 } },
    .{ .name = "attach-lazy-crafted", .input = in_words_3000, .dict = "crafted-words", .path = .load, .levels = &.{ 4, 5, 7, 10 } },
    // a dictionary larger than the window (the frame's is the input's), and
    // one of 150 KB made for the 256 KB row
    .{ .name = "attach-lazy-dict-over-window", .input = in_mix_20000, .dict = "raw-csv-150000", .path = .cdict, .levels = &.{ 4, 6, 8, 11 } },
    // forced on inputs past the cutoff, over many blocks (a CDict without a
    // level, or 200 KB would load it anew); with a small window the
    // dictionary leaves it within the frame, and then indices are corrected
    .{ .name = "attach-lazy-force", .input = in_words_40000, .dict = "zd-words", .path = .cdict, .params = "forceAttachDict=1", .levels = levels_attach_small },
    .{ .name = "attach-lazy-force-200k", .input = in_csv_200000, .dict = "raw-csv-30000", .path = .cdictadv, .params = "forceAttachDict=1", .levels = levels_attach_30k },
    .{ .name = "attach-lazy-force-window", .input = in_csv_200000, .dict = "zd-csv", .path = .cdictadv, .params = "windowLog=12,forceAttachDict=1", .levels = &.{ 5, 6, 8, 10, 12 } },
    .{ .name = "attach-lazy-force-ocf", .input = in_csv_200000, .dict = "zd-csv", .path = .load, .params = "windowLog=11,forceAttachDict=1", .levels = &.{ 5, 6, 7, 11 }, .ocf = true },
    // the row match finder on and off, for the CDict and the context alike
    .{ .name = "attach-lazy-rows-on", .input = in_words_3000, .dict = "zd-words", .path = .cdictadv, .params = "useRowMatchFinder=1", .levels = &.{ 4, 5, 6, 8 } },
    .{ .name = "attach-lazy-rows-off", .input = in_csv_32768, .dict = "raw-csv-30000", .path = .cdictadv, .params = "useRowMatchFinder=2", .levels = &.{ 5, 6, 7, 10 } },
    .{ .name = "attach-lazy-rows-search", .input = in_words_40000, .dict = "raw-words-15900", .path = .cdictadv, .params = "useRowMatchFinder=1,searchLog=6,forceAttachDict=1", .levels = &.{ 5, 7 } },
    // minimum match lengths 3 (hashed as 4), 5, 6 and 7 (searched as 6)
    .{ .name = "attach-lazy-minmatch-3", .input = in_words_3000, .dict = "raw-words-8000", .path = .cdictadv, .params = "minMatch=3", .levels = &.{ 4, 6, 9 } },
    .{ .name = "attach-lazy-minmatch-5-row", .input = in_words_3000, .dict = "raw-words-8000", .path = .cdictadv, .params = "minMatch=5,useRowMatchFinder=1", .levels = &.{ 5, 7 } },
    .{ .name = "attach-lazy-minmatch-6", .input = in_words_3000, .dict = "raw-words-8000", .path = .cdictadv, .params = "minMatch=6", .levels = &.{ 4, 8, 10 } },
    .{ .name = "attach-lazy-minmatch-7", .input = in_words_3000, .dict = "raw-words-8000", .path = .cdictadv, .params = "minMatch=7,useRowMatchFinder=1", .levels = &.{ 5, 8 } },
    // strategies forced where no level puts them for this size
    .{ .name = "attach-lazy-strategy-greedy", .input = in_words_3000, .dict = "raw-words-8000", .path = .load, .params = "strategy=3", .levels = &.{ 1, 19 } },
    .{ .name = "attach-lazy-strategy-btlazy2", .input = in_words_3000, .dict = "raw-csv-30000", .path = .cdictadv, .params = "strategy=6", .levels = &.{ 3, 16 } },
    .{ .name = "attach-lazy-strategy-lazy-row", .input = in_words_3000, .dict = "raw-csv-30000", .path = .cdictadv, .params = "strategy=4,useRowMatchFinder=1,searchLog=4", .levels = &.{ 1, 22 } },
    // an empty input: nothing searched, the header carries the ID
    .{ .name = "attach-lazy-empty", .input = in_empty, .dict = "zd-words", .path = .cdict, .levels = &.{ 5, 9 } },
    // Found by the mutation sweep (generator seeds searched, original
    // against mutant; SPEC.md, *Anchoring*):
    // the CDict's tree smaller than it: its low end, larger side
    .{ .name = "attach-lazy-bt-tree-low-larger", .input = .{ .name = "", .len = 80927, .kind = .mix, .seed = 323089 }, .dict = "zd-words", .path = .cdictadv, .params = "forceAttachDict=1,strategy=6,chainLog=9,searchLog=3,hashLog=16", .levels = &.{7} },
    // ... smaller side
    .{ .name = "attach-lazy-bt-tree-low-smaller", .input = .{ .name = "", .len = 73245, .kind = .mix, .seed = 620601 }, .dict = "raw-words-3584", .path = .cdictadv, .params = "forceAttachDict=1,strategy=6,chainLog=8,searchLog=5", .levels = &.{10} },
    // one compare left for the CDict's tree
    .{ .name = "attach-lazy-bt-one-compare-left", .input = .{ .name = "", .len = 9918, .kind = .csv, .seed = 748492 }, .dict = "raw-csv-30000", .path = .cdictadv, .params = "forceAttachDict=1,strategy=6,chainLog=13,searchLog=2,hashLog=10,windowLog=16", .levels = &.{5} },
    // a window match to the input's end skips the CDict
    .{ .name = "attach-lazy-bt-input-end", .input = .{ .name = "", .len = 242, .kind = .words, .seed = 384050 }, .dict = "zd-words", .path = .cdict, .params = "-", .levels = &.{9} },
    // a dictionary offset of 2^k - 1
    .{ .name = "attach-lazy-bt-offset-price", .input = .{ .name = "", .len = 49917, .kind = .words, .seed = 609613 }, .dict = "crafted-words", .path = .cdictadv, .params = "forceAttachDict=1,strategy=6,chainLog=14,searchLog=6", .levels = &.{13} },
    // the tree's low end when it spans less than the CDict
    .{ .name = "attach-lazy-bt-tree-low-span", .input = .{ .name = "", .len = 14565, .kind = .mix, .seed = 63123 }, .dict = "crafted-words", .path = .cdictadv, .params = "forceAttachDict=1,strategy=6,chainLog=10,searchLog=6,minMatch=4", .levels = &.{11} },
    // ... with the compares left zeroed
    .{ .name = "attach-lazy-bt-input-end-zero", .input = .{ .name = "", .len = 86911, .kind = .csv, .seed = 80382 }, .dict = "zd-csv", .path = .cdict, .params = "forceAttachDict=1", .levels = &.{11} },
    // a CDict chain candidate needs its first 4 bytes
    .{ .name = "attach-lazy-hc-first-four", .input = .{ .name = "", .len = 3016, .kind = .csv, .seed = 733954 }, .dict = "raw-csv-150000", .path = .cdictadv, .params = "forceAttachDict=1,useRowMatchFinder=2,chainLog=13,searchLog=6,strategy=3,minMatch=6,hashLog=9", .levels = &.{12} },
    // a CDict chain match running on into the input
    .{ .name = "attach-lazy-hc-into-prefix", .input = .{ .name = "", .len = 27487, .kind = .drift, .seed = 208226 }, .dict = "zd-words", .path = .cdictadv, .params = "forceAttachDict=1,minMatch=4", .levels = &.{6} },
    // the CDict's chain shorter than it: where it ends
    .{ .name = "attach-lazy-hc-chain-end", .input = .{ .name = "", .len = 58554, .kind = .words, .seed = 361537 }, .dict = "raw-words-3584", .path = .cdictadv, .params = "forceAttachDict=1,useRowMatchFinder=2,chainLog=10,searchLog=8,strategy=4,minMatch=4", .levels = &.{10} },
    .{ .name = "attach-lazy-hc-chain-end-2", .input = .{ .name = "", .len = 32389, .kind = .words, .seed = 471759 }, .dict = "raw-words-8000", .path = .cdictadv, .params = "forceAttachDict=1,useRowMatchFinder=2,chainLog=7,searchLog=7,strategy=5", .levels = &.{4} },
    // catching a match up to the CDict's first byte
    .{ .name = "attach-lazy-catch-up-dict-start", .input = .{ .name = "", .len = 75888, .kind = .words, .seed = 849755 }, .dict = "raw-words-3584", .path = .cdict, .params = "forceAttachDict=1", .levels = &.{10} },
    // ... and to the input's first byte
    .{ .name = "attach-lazy-catch-up-prefix-start", .input = .{ .name = "", .len = 27934, .kind = .two_symbols, .seed = 709728 }, .dict = "raw-words-8000", .path = .cdict, .params = "-", .levels = &.{5} },
    // an immediate repcode right at the parser's limit
    .{ .name = "attach-lazy-imm-rep-at-limit", .input = .{ .name = "", .len = 40616, .kind = .drift, .seed = 146458 }, .dict = "raw-mix-3000", .path = .cdictadv, .params = "forceAttachDict=1,strategy=6,chainLog=8,searchLog=1,minMatch=7", .levels = &.{22} },
    // a CDict row match running on into the input
    .{ .name = "attach-lazy-row-into-prefix", .input = .{ .name = "", .len = 1002, .kind = .drift, .seed = 689080 }, .dict = "zd-words", .path = .cdictadv, .params = "forceAttachDict=1,useRowMatchFinder=1,searchLog=6,strategy=5", .levels = &.{9} },
    // a CDict row entry at its first index
    .{ .name = "attach-lazy-row-dict-start", .input = .{ .name = "", .len = 47993, .kind = .drift, .seed = 517561 }, .dict = "crafted-words", .path = .cdictadv, .params = "forceAttachDict=1,useRowMatchFinder=1,searchLog=3,strategy=3,hashLog=14", .levels = &.{9} },
    // a repcode match from the CDict on into the input
    .{ .name = "attach-lazy-rep-into-prefix", .input = .{ .name = "", .len = 6247, .kind = .two_symbols, .seed = 17340 }, .dict = "raw-two-symbols-12528", .path = .load, .params = "forceAttachDict=1,strategy=6,chainLog=6,searchLog=4,minMatch=4", .levels = &.{7} },
    // a match at the input's first byte is not caught up into the CDict
    .{ .name = "attach-lazy-catch-up-at-prefix", .input = .{ .name = "", .len = 2935, .kind = .skewed, .seed = 110998 }, .dict = "raw-skewed-18461", .path = .usingcdict, .levels = &.{9} },
    // unknown sizes: a stream attaches
    .{ .name = "attach-lazy-stream-load", .input = in_words_40000, .dict = "raw-words-8000", .path = .load, .schedule = "c*,e0", .levels = &.{ 4, 5, 6, 7, 8, 9, 10 } },
    .{ .name = "attach-lazy-stream-cdict", .input = in_csv_200000, .dict = "zd-csv", .path = .cdict, .schedule = "c50000,f0,c*,e0", .levels = &.{ 5, 6, 7, 11 } },
    .{ .name = "attach-lazy-stream-cdictadv", .input = in_words_40000, .dict = "zd-words", .path = .cdictadv, .schedule = "useRowMatchFinder=1,o3000,c1000,f0,c*,e0", .levels = &.{ 4, 5, 6 } },
    // a size hint makes the context's own CDict for over 256 KB: 5 greedy,
    // 6 and 7 lazy, 8..12 lazy2, 13..15 btlazy2
    .{ .name = "attach-lazy-stream-hint", .input = in_words_40000, .dict = "raw-csv-30000", .path = .load, .schedule = "srcSizeHint=300000,c*,e0", .levels = &.{ 5, 6, 8, 12, 13, 15 } },
    .{ .name = "attach-lazy-stream-wrap", .input = in_words_40000, .dict = "zd-words", .path = .cdictadv, .schedule = "w12,c10000,f0,c*,e0", .levels = &.{ 5, 8, 10 } },
};

/// D4: the dedicated dictionary search (`enableDedicatedDictSearch=1`):
/// a CDict for `greedy`..`lazy2` laid out in buckets and always attached
/// (`lazy.ddsLoadDictionary`, `lazy.ddsSearch`), and where libzstd falls
/// back to a plain CDict (other strategies, a hash log not above the chain
/// log). zd-words (4 KB) is made for its own size: 4 greedy, 5 lazy, 6..8
/// lazy2, 9 btlazy2; raw-csv-30000 on the 128 KB row: 5 greedy, 6 lazy,
/// 7..10 lazy2 (rows), 11 btlazy2.
pub const dict_cases_dds = [_]DictCase{
    .{ .name = "dds-cdictadv", .input = in_words_3000, .dict = "zd-words", .path = .cdictadv, .params = "enableDedicatedDictSearch=1", .levels = &.{ 1, 3, 4, 5, 6, 7, 8, 9, 13, 19 }, .checksums = &.{ false, true } },
    .{ .name = "dds-cdictadv-30k", .input = in_csv_32768, .dict = "raw-csv-30000", .path = .cdictadv, .params = "enableDedicatedDictSearch=1", .levels = &.{ 5, 6, 7, 8, 10, 11 } },
    // attached past the cutoffs too, over many blocks
    .{ .name = "dds-cdictadv-200k", .input = in_csv_200000, .dict = "raw-csv-30000", .path = .cdictadv, .params = "enableDedicatedDictSearch=1", .levels = &.{ 5, 6, 8, 12 } },
    // the context's own CDict (`.raw`) takes the parameter from the context
    .{ .name = "dds-load", .input = in_words_3000, .dict = "raw-words-8000", .path = .load, .params = "enableDedicatedDictSearch=1", .levels = &.{ 3, 4, 5, 6, 8, 9 } },
    .{ .name = "dds-load-40k", .input = in_words_40000, .dict = "raw-words-8000", .path = .load, .params = "enableDedicatedDictSearch=1", .levels = &.{ 4, 5, 7 } },
    .{ .name = "dds-full-as-raw", .input = in_words_3000, .dict = "zd-words", .path = .cdictadv, .content_type = 1, .params = "enableDedicatedDictSearch=1", .levels = &.{ 4, 6 } },
    .{ .name = "dds-crafted", .input = in_words_3000, .dict = "crafted-words", .path = .load, .params = "enableDedicatedDictSearch=1", .levels = &.{ 4, 5, 7 } },
    // forced copy and `forceMaxWindow` still attach; a forced load loads
    // the content into the context
    .{ .name = "dds-force-copy", .input = in_words_40000, .dict = "zd-words", .path = .cdictadv, .params = "enableDedicatedDictSearch=1,forceAttachDict=2", .levels = &.{ 4, 6, 8 } },
    .{ .name = "dds-force-load", .input = in_words_40000, .dict = "zd-words", .path = .cdictadv, .params = "enableDedicatedDictSearch=1,forceAttachDict=3", .levels = &.{ 4, 6 } },
    .{ .name = "dds-force-max-window", .input = in_words_40000, .dict = "zd-words", .path = .cdictadv, .params = "enableDedicatedDictSearch=1,forceMaxWindow=1", .levels = &.{ 4, 6, 8 } },
    // rows on and off; a 15.9 KB dictionary gets a 16 KB window (hash
    // chains) where a plain CDict's 32 KB one gets rows
    .{ .name = "dds-rows-on", .input = in_words_3000, .dict = "zd-words", .path = .cdictadv, .params = "enableDedicatedDictSearch=1,useRowMatchFinder=1", .levels = &.{ 4, 5, 6 } },
    .{ .name = "dds-rows-off", .input = in_csv_32768, .dict = "raw-csv-30000", .path = .cdictadv, .params = "enableDedicatedDictSearch=1,useRowMatchFinder=2", .levels = &.{ 5, 7, 10 } },
    .{ .name = "dds-window-16k", .input = in_words_3000, .dict = "raw-words-15900", .path = .cdictadv, .params = "enableDedicatedDictSearch=1", .levels = &.{ 5, 7 } },
    // search logs: 1 (the chain limit wraps to 255), 7 with rows (the
    // CDict gets the attempts the rows are capped at)
    .{ .name = "dds-search-1", .input = in_words_40000, .dict = "raw-words-8000", .path = .cdictadv, .params = "enableDedicatedDictSearch=1,searchLog=1", .levels = &.{ 4, 6 } },
    .{ .name = "dds-search-7-row", .input = in_words_40000, .dict = "raw-csv-30000", .path = .cdictadv, .params = "enableDedicatedDictSearch=1,searchLog=7,useRowMatchFinder=1", .levels = &.{ 5, 8 } },
    // minimum matches 3 (hashed as 4), 5, and 7 (loaded as 7, searched as 6)
    .{ .name = "dds-minmatch-3", .input = in_words_3000, .dict = "raw-words-8000", .path = .cdictadv, .params = "enableDedicatedDictSearch=1,minMatch=3", .levels = &.{ 4, 6 } },
    .{ .name = "dds-minmatch-5-row", .input = in_words_3000, .dict = "raw-words-8000", .path = .cdictadv, .params = "enableDedicatedDictSearch=1,minMatch=5,useRowMatchFinder=1", .levels = &.{ 5, 7 } },
    .{ .name = "dds-minmatch-7", .input = in_words_3000, .dict = "raw-words-8000", .path = .cdictadv, .params = "enableDedicatedDictSearch=1,minMatch=7", .levels = &.{ 4, 8 } },
    // an explicit hash log replaces the dedicated one; one not above the
    // chain log falls back to a plain CDict
    .{ .name = "dds-hashlog", .input = in_words_40000, .dict = "raw-csv-30000", .path = .cdictadv, .params = "enableDedicatedDictSearch=1,hashLog=18", .levels = &.{ 5, 7 } },
    .{ .name = "dds-hashlog-fallback", .input = in_words_40000, .dict = "raw-csv-30000", .path = .cdictadv, .params = "enableDedicatedDictSearch=1,hashLog=14,chainLog=16", .levels = &.{ 5, 7 } },
    .{ .name = "dds-strategy-lazy2", .input = in_words_3000, .dict = "raw-csv-30000", .path = .cdictadv, .params = "enableDedicatedDictSearch=1,strategy=5", .levels = &.{ 1, 19 } },
    .{ .name = "dds-dict-150k", .input = in_words_40000, .dict = "raw-csv-150000", .path = .cdictadv, .params = "enableDedicatedDictSearch=1", .levels = &.{ 4, 6, 8, 11 } },
    .{ .name = "dds-empty", .input = in_empty, .dict = "zd-words", .path = .cdictadv, .params = "enableDedicatedDictSearch=1", .levels = &.{ 5, 8 } },
    // index overflow corrected while the CDict stays attached
    .{ .name = "dds-ocf", .input = in_csv_200000, .dict = "zd-csv", .path = .load, .params = "enableDedicatedDictSearch=1,windowLog=11", .levels = &.{ 5, 6, 7 }, .ocf = true },
    // streams
    .{ .name = "dds-stream-load", .input = in_words_40000, .dict = "raw-words-8000", .path = .load, .schedule = "enableDedicatedDictSearch=1,c*,e0", .levels = &.{ 4, 5, 6, 8 } },
    .{ .name = "dds-stream-cdictadv", .input = in_csv_200000, .dict = "zd-csv", .path = .cdictadv, .schedule = "enableDedicatedDictSearch=1,c50000,f0,c*,e0", .levels = &.{ 5, 6, 7, 11 } },
    .{ .name = "dds-stream-pledged", .input = in_words_40000, .dict = "zd-words", .path = .cdictadv, .schedule = "enableDedicatedDictSearch=1,p40000,c*,e0", .levels = &.{ 4, 6 } },
    // Found by the mutation sweep (hunted, original against mutant):
    // a position exactly at the temporary chain's low end starts a chain
    .{ .name = "dds-tmp-chain-low-end", .input = .{ .name = "", .len = 1874, .kind = .words, .seed = 667508 }, .dict = "raw-words-10264", .path = .load, .params = "enableDedicatedDictSearch=1,hashLog=9,chainLog=7", .levels = &.{5} },
    // a search log of 10: the laid-out chains stop at 255 entries
    .{ .name = "dds-chain-limit-255", .input = .{ .name = "", .len = 1893, .kind = .two_symbols, .seed = 830422 }, .dict = "raw-two-symbols-17900", .path = .cdictadv, .params = "enableDedicatedDictSearch=1,searchLog=10,useRowMatchFinder=2", .levels = &.{6} },
    .{ .name = "dds-stream-wrap", .input = in_words_40000, .dict = "zd-words", .path = .cdictadv, .schedule = "enableDedicatedDictSearch=1,w12,c10000,f0,c*,e0", .levels = &.{ 5, 8 } },
};

const in_words_8192_fast: Case = .{ .name = "", .len = 8192, .kind = .words, .seed = 101 };
const in_words_8193_fast: Case = .{ .name = "", .len = 8193, .kind = .words, .seed = 102 };
const in_csv_16384: Case = .{ .name = "", .len = 16384, .kind = .csv, .seed = 103 };
const in_csv_16385: Case = .{ .name = "", .len = 16385, .kind = .csv, .seed = 104 };
const in_words_2000: Case = .{ .name = "", .len = 2000, .kind = .words, .seed = 105 };

/// Wave 2 (D1): attach (`ms.dict_match_state`) cases for the `fast` and
/// `dfast` strategies, where `match.hasDictMatchStateVariant` now admits
/// them (SPEC.md, *Dictionaries*). Kept separate from `dict_cases` so
/// sibling agents' own attach cases (other strategy families) merge
/// cleanly; wired into the same golden test and manifest as `dict_cases`.
/// Levels: -3/-7 and 1 are `fast` (negative levels are always the base
/// `fast` row); 2 and 3 are `dfast` on the small-input table `dict_cases`'
/// own "the attach cutoffs are libzstd's" test already pins.
pub const dict_cases_attach_fast = [_]DictCase{
    // at the 8 KB (fast) / 16 KB (dfast) cutoff -- attaches -- and just
    // above -- copies; the boundary itself must give the same bytes either way
    .{ .name = "attach-fast-at-cutoff", .input = in_words_8192_fast, .dict = "raw-words-8000", .path = .cdict, .levels = &.{1} },
    .{ .name = "attach-fast-just-over", .input = in_words_8193_fast, .dict = "raw-words-8000", .path = .cdict, .levels = &.{1} },
    .{ .name = "attach-dfast-at-cutoff", .input = in_csv_16384, .dict = "raw-csv-30000", .path = .cdict, .levels = &.{3} },
    .{ .name = "attach-dfast-just-over", .input = in_csv_16385, .dict = "raw-csv-30000", .path = .cdict, .levels = &.{3} },
    // unknown-size streams: shouldAttachDict treats them like the smallest input
    .{ .name = "attach-fast-stream-unknown", .input = in_words_3000, .dict = "raw-words-8000", .path = .cdict, .schedule = "c*,e0", .levels = &.{1} },
    .{ .name = "attach-dfast-stream-unknown", .input = in_csv_200000, .dict = "raw-csv-30000", .path = .cdict, .schedule = "c20000,f0,c*,e0", .levels = &.{3} },
    // forceAttachDict=1 (attach) past the cutoff, where libzstd would
    // otherwise copy
    .{ .name = "attach-fast-forced-big", .input = in_words_40000, .dict = "raw-words-8000", .path = .cdictadv, .params = "forceAttachDict=1", .levels = &.{1} },
    .{ .name = "attach-dfast-forced-big", .input = in_csv_200000, .dict = "raw-csv-30000", .path = .cdictadv, .params = "forceAttachDict=1", .levels = &.{3} },
    // a full (trained) dictionary, attached, vs. raw content
    .{ .name = "attach-fast-full-dict", .input = in_words_2000, .dict = "zd-words", .path = .cdict, .levels = &.{1} },
    .{ .name = "attach-dfast-full-dict", .input = in_words_2000, .dict = "zd-csv", .path = .cdict, .levels = &.{3} },
    // a dictionary bigger than a forced-small window (truncated to it) vs.
    // comfortably inside a wide one
    .{ .name = "attach-fast-dict-over-window", .input = in_words_2000, .dict = "raw-csv-30000", .path = .cdictadv, .params = "windowLog=12,forceAttachDict=1", .levels = &.{1} },
    .{ .name = "attach-dfast-dict-under-window", .input = in_words_2000, .dict = "raw-words-3584", .path = .cdictadv, .params = "windowLog=20,forceAttachDict=1", .levels = &.{3} },
    // negative levels: always the fast strategy's base row
    .{ .name = "attach-fast-negative-level", .input = in_words_3000, .dict = "raw-words-8000", .path = .cdict, .levels = &.{ -1, -3, -7 } },
    // level 2 (dfast on the small-input table), raw and full
    .{ .name = "attach-level2-raw", .input = in_words_3000, .dict = "raw-words-8000", .path = .cdict, .levels = &.{2} },
    .{ .name = "attach-level2-full", .input = in_words_3000, .dict = "zd-words", .path = .cdict, .levels = &.{2} },
    // hunted: a dfast dictMatchState match confirmed at the CDict's very
    // last bytes, which continues counting from the prefix's start
    // (`countAcrossDict`'s fallthrough, not an early "return 0"); without
    // the fix this mismatches libzstd (456 bytes instead of 454, byte 8
    // onward) -- found by comparing the fixed helper against the pre-fix
    // one over ~20 random constructions, confirmed against libzstd 1.5.7.
    .{ .name = "attach-dfast-cross-end", .input = .{ .name = "", .len = dict_boundary_echo_input.len, .kind = .dict_boundary_echo }, .dict = "boundary-echo-dict", .path = .cdict, .params = "forceAttachDict=1", .levels = &.{3} },
    // hunted (D1): mutation-sweep survivors' killing cases (orig vs mutant
    // over random (dict, input) constructions, confirmed against libzstd
    // 1.5.7). Each `survivor_literal` case's `seed` indexes `survivor_inputs`.
    .{ .name = "surv-m12-fast", .input = .{ .name = "", .len = surv_m12_input.len, .kind = .survivor_literal, .seed = 0 }, .dict = "surv-m12-dict", .path = .cdict, .params = "forceAttachDict=1", .levels = &.{1} },
    .{ .name = "surv-m17-fast", .input = .{ .name = "", .len = surv_m17_input.len, .kind = .survivor_literal, .seed = 1 }, .dict = "surv-m17-dict", .path = .cdict, .params = "forceAttachDict=1", .levels = &.{1} },
    .{ .name = "surv-m22-dfast", .input = .{ .name = "", .len = surv_m22_input.len, .kind = .survivor_literal, .seed = 2 }, .dict = "surv-m22-dict", .path = .cdict, .params = "forceAttachDict=1", .levels = &.{3} },
    .{ .name = "surv-m23-dfast", .input = .{ .name = "", .len = surv_m23_input.len, .kind = .survivor_literal, .seed = 3 }, .dict = "surv-m23-dict", .path = .cdict, .params = "forceAttachDict=1", .levels = &.{3} },
    .{ .name = "surv-m24-dfast", .input = .{ .name = "", .len = surv_m24_input.len, .kind = .survivor_literal, .seed = 4 }, .dict = "surv-m24-dict", .path = .cdict, .params = "forceAttachDict=1", .levels = &.{3} },
    .{ .name = "surv-m25-dfast", .input = .{ .name = "", .len = surv_m25_input.len, .kind = .survivor_literal, .seed = 5 }, .dict = "surv-m25-dict", .path = .cdict, .params = "forceAttachDict=1", .levels = &.{3} },
    .{ .name = "surv-m27-dfast", .input = .{ .name = "", .len = surv_m27_input.len, .kind = .survivor_literal, .seed = 6 }, .dict = "surv-m27-dict", .path = .cdict, .params = "forceAttachDict=1", .levels = &.{3} },
};
