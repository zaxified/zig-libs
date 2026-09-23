# `zstd` — specification

Consumer view, API and purpose: [README.md](README.md).

## What this module is, and what it is not

A one-shot Zstandard **compressor** that reproduces libzstd 1.5.7's output
byte for byte for every level, 1–22 and negative. Every strategy is
translated from libzstd — `fast`, `dfast`, `greedy`/`lazy`/`lazy2` over both
the hash chain and the row-based search, `btlazy2`'s binary tree, and the
optimal parsers `btopt`/`btultra`/`btultra2` — together with the frame/block
driver, the block pre-splitter and post-splitter, long-distance matching as
libzstd switches it on by itself (level 22 above 64 MB), and the entropy stage
(literals via Huffman, sequences via FSE); see [NOTICE](NOTICE) for the
file-by-file map.

**Goal (2026-09-22): production quality — as close to libzstd's feature set
and behaviour as possible, so that a Zig program never needs to link libzstd.**
Today it is the one-shot compressor only; everything else libzstd offers is
in *Backlog / deferred* below, with its cost.

Not here yet, and a reader might expect it (each is a backlog item):

- **A decoder.** `std.compress.zstd.Decompress` decodes what this module
  writes and is the tests' round-trip oracle, but it refuses dictionary
  frames, leaves checksum verification as a TODO panic, and defaults to an
  8 MB window (frames of levels 20–22 on large inputs need
  `window_len` raised). Z2.
- **Streaming, as libzstd streams.** libzstd's streaming API blocks the
  input on its own buffer boundaries and so produces *different* (equally
  valid) frames; matching those is its own contract. Z1. What exists is
  `FrameWriter` (Z1a, see *Algorithm*): a `std.Io.Writer` that emits one
  independent one-shot frame per buffer fill and per flush.
- **Dictionaries (Z4, Z5), multithreading (Z9), `targetCBlockSize` (Z8),
  and long-distance matching as an option (Z7).** libzstd's `ZSTD_c_enableLongDistanceMatching`
  (the CLI's `--long`) is not in `Options`: LDM happens exactly where libzstd
  switches it on by itself. Under the optimal parsers the by-hand switch is
  a test seam (`frame.Options.ldm`); below `btopt` LDM runs a different path
  (its sequences spliced between runs of the block compressor,
  `ZSTD_ldm_blockCompress`'s loop with `maybeSplitSequence` and
  `ZSTD_ldm_fillFastTables`), which is not ported.

## Algorithm

libzstd's one-shot path (`ZSTD_compress2` with the whole input and a
`compressBound`-sized destination goes through `ZSTD_compressEnd_public`):

1. **Parameters** (`params.zig`): row `level` (0 → 3, negative → row 0 with
   `targetLength = -level`) of the table chosen by source size (≤16 KB,
   ≤128 KB, ≤256 KB, larger), then `ZSTD_adjustCParams_internal` shrinks the
   window to the input and caps hash/chain logs by it. The window log goes into
   the frame header.
2. **Frame header** (`frame.zig`): content size always present; single-segment
   when the window covers the input.
3. **Blocks**: at most `min(128 KB, window, input)` each. From the second full
   block on — once the frame has saved at least 3 bytes — a 128 KB block may be
   cut by the pre-splitter (`presplit.zig`): `fast` compares the byte histograms
   of the first and last 512 bytes (and the middle, to pick 32/64/96 KB);
   `dfast` fingerprints 8 KB chunks sampled every 43rd byte and cuts at the
   first chunk that deviates; `greedy`/`lazy` sample every 11th byte of 2-byte
   hashes, `lazy2` and up every 5th.
4. **Match finding** (`match.zig`, `lazy.zig`, `opt.zig`): indices start at 2, as in libzstd, so a zero
   hash slot means "empty". Repeat offsets carry across blocks; a block emitted
   raw or RLE does not commit its repeat offsets or entropy tables (the next
   block starts again from the last compressed block's state).
   `greedy`/`lazy`/`lazy2` share one parser (lookahead depth 0/1/2) over a hash
   chain when the window is 16 KB or less, and over libzstd's row-based finder
   (16/32/64-entry rows of 8-bit tags) above that — libzstd's own automatic
   choice. `btlazy2` runs the same parser at depth 2 over libzstd's "delayed
   update" binary tree: new positions are only chained and marked unsorted,
   and a search first sorts the unsorted candidates it meets into the tree
   (two chain-table entries per position, hence `ZSTD_cycleLog` = chain log − 1
   in the parameter adjustment). Insertion state (`nextToUpdate`) carries
   across blocks, with libzstd's caps after long matches.
   `btopt`/`btultra`/`btultra2` use a binary tree that is sorted on insertion
   and returns *every* match length at a position (plus the three repeat
   offsets and, with `minMatch` 3, a 3-byte hash table), and price each path
   through the next up-to-4096 positions with adaptive statistics of literals,
   literal lengths, match lengths and offset codes (scaled down per block, in
   1/256 bits; `btopt` in whole bits with early exits, `btultra` in
   fractional bits with a "match + 1 literal" probe). The cheapest path is
   traced back and stored. `btultra2` first runs its parser over the first
   block only to seed the statistics, then forgets that block's matches
   (libzstd moves its window base; here the tables are emptied, the same thing
   for every comparison the finders make) and parses it again.
   **Long-distance matching** (`ldm.zig`), on when the strategy is `btopt` or
   up and the window log is at least 27 — level 22 on inputs over 64 MB
   (`ZSTD_resolveEnableLdm`): before each block is parsed, a gear rolling hash
   marks split points about every 2^4 bytes (2^5 for `btopt`/`btultra`); the
   32 (`btopt`: 64) bytes before each are hashed with XXH64 into a table of
   2^23 entries in buckets of 256 (`btopt`: 128), keyed by the low bits and
   checked by the high 32. A checksum hit that extends forwards to at least
   that length (and then backwards) becomes a raw sequence; the table keeps
   its own window, cut back by the END of each block. The block's sequences
   are then offered to the optimal parser as one extra candidate per position
   (`ZSTD_optLdm_*`), appended when longer than every match the tree found.
   Two libzstd quirks are kept because the output depends on them:
   `ZSTD_ldm_gear_reset` rolls a local copy and never stores it (so it
   resets nothing), and the candidate taken from a block's last LDM sequence
   is never offered (consuming it leaves the store exhausted, which returns
   before the candidate is added).
5. **Post-split** (`blocksplit.zig`), `btopt` and up with a window of at least
   128 KB: the block's sequences are halved recursively (ranges of ≥ 300
   sequences, ≤ 196 splits) while the estimated sizes of the two halves, each
   with its own tables, beat the whole; each part becomes a block. A part
   emitted raw or RLE leaves the decoder with older repeat offsets, so the next
   part's repcodes are rewritten as full offsets where the two histories
   disagree (`ZSTD_seqStore_resolveOffCodes`).
6. **Entropy** (`literals.zig`, `huf.zig`, `sequences.zig`, `fse.zig`):
   literals are Huffman-coded (1 or 4 streams) when that beats `minGain`,
   reusing the previous block's table when libzstd would; from `btultra` on
   the Huffman table log is chosen by trial (`HUF_flags_optimalDepth`). Each
   sequence code stream uses the predefined table, RLE, or a new table — below
   `lazy` by libzstd's count heuristics, from `lazy` on by pricing the
   predefined, the previous block's and a new table and taking the cheapest.
7. **Block type**: compressed if it beats `blockSize - minGain`, RLE when the
   whole block is one byte (never for the first block — zstd ≤ 1.4.3 decoders
   mishandle that), raw otherwise. Optional XXH64 checksum at the end.

**Everything that can reach the output is kept verbatim**, including three
things that look like incidental implementation detail and are not:

- the Huffman symbol sort's *unstable* quicksort on its log buckets (it decides
  which of equally frequent symbols gets the longer code);
- `HUF_setMaxHeight`'s repayment order when capping code lengths at 11 bits;
- the FSE normaliser's `rtbTable` rounding and its fallback `normalizeM2`.

What is *not* kept is how libzstd gets there fast: the unrolled Huffman loops,
the cmov/branch match-found variants, 4-way histograms and 8-byte table
spreading are replaced by plain loops that make the same decisions. Where the
reference chooses between two code paths on *capacity* (`HUF_compress1X`'s
fast flush when the destination is large), both paths produce the same bits
and one path is carried.

Endianness: every multi-byte read that feeds a decision is little-endian,
matching libzstd on x86/arm64 (libzstd reads native order in one place, the
pre-splitter's 16-bit hash, which `greedy` and up use).

**Index overflow correction** (`match.zig`, `ldm.zig`; libzstd's
`ZSTD_overflowCorrectIfNeeded`, `ZSTD_window_correctOverflow`,
`ZSTD_reduceIndex`, `ZSTD_ldm_reduceTable`). Indices are 32-bit. Before each
block, once the block's end index would pass `ZSTD_CURRENT_MAX` (3500 MiB),
every index drops by a correction that brings the block start to just above
the window while keeping its low `cycleLog` bits (`chainLog`, one less from
`btlazy2` up — the chains and trees are indexed by them). The hash, chain /
tree and 3-byte hash tables are reduced (an index below the correction plus 2
becomes 0, empty; `btlazy2`'s unsorted mark 1 is kept), and so are the window
limits and `nextToUpdate`. libzstd moves `window.base` forward by the
correction; here `ms.src` loses that many bytes at the front, so every
`idx - window_start` access stays as it was, and the frame driver keeps the
sum to turn input positions into indices. The LDM window corrects on its
own, per 1 MB chunk, with cycle log 0, and reduces its table. Nothing inside
the window is lost, so the output is the same with or without a correction —
which is also why the tests have to ask whether one ran (*Anchoring*).

**`FrameWriter`** (`frame_writer.zig`, not a port) is a `std.Io.Writer` over
that one-shot path. Every byte passes through the caller's buffer; the
buffer's contents become one frame — exactly `compress` of those bytes — when
the buffer fills, at each `flush` that finds something buffered, and at
`finish`. So frame boundaries follow the buffer length and the flush points,
never how the writes were cut (a `rebase` asking for more room than is left
also cuts one, as a flush would). `finish` on a stream that never produced a
frame writes the 9-byte empty frame, so an empty body is still a valid zstd
stream. A decoder reads concatenated frames as one stream (RFC 8878 §3.1).
Each frame starts with no history and allocates its match tables anew, so
small flushes cost ratio and time; Z1 is the real stream. `Writer.Error` has
one member, so a failure of our own (out of memory) is kept in
`FrameWriter.err`; null there means `output` failed.

## Limits and refusals

| limit | value | source |
|---|---|---|
| level | `min_level` (-131072) … 22; lower is clamped, higher is `error.LevelUnsupported` | `ZSTD_minCLevel()` / `ZSTD_maxCLevel()`; libzstd clamps above 22 too, which would hand a caller a level it did not ask for |
| memory | level 22 above 64 MB: 512 MiB binary tree + 128 MiB hash + 64 MiB LDM table + 32 KiB bucket offsets (≈ 820 MB peak on a 70 MB input, as libzstd) | the level's own table sizes; nothing is capped, as libzstd caps nothing |
| input | none (the input and `compressBound` of it in memory) | past `ZSTD_CURRENT_MAX` (3500 MiB on 64-bit) the indices are rescaled, as libzstd does (see *Algorithm*) |
| destination | ≥ `compressBound(src.len)` or `error.NoSpaceLeft` | the reference's decisions assume the one-shot bound; accepting less would let capacity change the output |
| block | 128 KB | format |

`golden_test.zig` pins all of the above through the output; `root.zig` tests
pin the level refusal and the destination bound. `FrameWriter` takes a
nonempty buffer and holds `compressBound(buffer.len)` of scratch for its life.

## Anchoring

**External anchor.** `src/testdata/goldens.zig` holds, for each of 56 corpus
inputs × levels {-5, -1, 1…10} × checksum {off, on}, and for the 53 inputs up
to 600 KB × levels 11…22 without checksum, plus 14 cases golden at one level
each, 15 compressed with long-distance matching switched on by hand and 13
with index overflow correction run often (a small window set by hand, and
libzstd built with `ZSTD_WINDOW_OVERFLOW_CORRECT_FREQUENTLY`), also at one to
three levels each (2029 frames), the length and
SHA-256 of the frame libzstd v1.5.7 (`f8745da6`) emits via `ZSTD_compress2`.
The optimal-parser levels cost 10–40× a lazy one, and the checksum trailer
does not depend on the level, hence the narrower set there
(`corpus.covered`; the three inputs above 600 KB are there for window and
pre-split paths the lower levels already reach). It is written by
`tools/gen-goldens.sh`, which builds that exact tag and runs
`tools/zref.c`; the inputs come from `src/testdata/corpus.zig`, whose own
output is pinned by a digest test so a generator drift cannot pass as an
encoder regression.

The corpus is built to reach decisions. On 2026-09-22 the port was mutated
(32 single-edit mutations: thresholds off by one, `>=` for `>`, a changed
constant) and every mutation the corpus did not notice got a case that does:

| case | what it pins |
|---|---|
| `debruijn-9-4` | 9 equally frequent literals, no 4-byte repeat: the Huffman quicksort order |
| `sparse-matches` | `fast`'s `step <= 4` hash-table write |
| `sparse-far` | `dfast`'s `step < 4` write (needs 48-byte phrases so the 8-byte hash at match+4 stays inside the phrase) |
| `split-margin` | a `dfast` pre-split deviation of 36 860, between the penalty-2 (36 100) and penalty-3 (38 356) thresholds |
| `rle-tail-6` | a 6-byte run as last block: below the 7-byte "attempt compression" size, so raw, not RLE |
| `repeat-1024` | exactly 1024 literals: the Huffman table is reused unpriced at `<= 1024` |
| `mix-*`, `skewed-180`, `two-symbols-300000-1`, `drift-300000-8` | found by searching generator seeds for an input where one boundary flips the output; `corpus.zig` names the boundary beside each |

Nine mutations still pass, and are left so on purpose:

| mutation | why no case exists |
|---|---|
| `lastCountSize + bitstreamSize < 4` → `< 3` | unreachable below `lazy`: a `set_compressed` sequence table needs ≥ 36 sequences, which cannot fit a 1-byte bitstream |
| pre-split `savings < 3` → `< 2` | frame savings of exactly 2 need hundreds of raw blocks (> 80 MB of input) |
| `dfast` `idxl1 > prefixLowest` → `>=` | index 2 is never inserted, and the prefix only moves once the input passes the 2 MB window |
| RLE block when `cSize < 25` → `< 24` | a block of one repeated byte compresses to far fewer than 24 bytes |
| Huffman `largest <= n/128 + 4`, `total >= n - 1`, `hSize + 12 >= n`, sampled `largestTotal <= 68` | masked: at equality the literals are near-uniform and the section is stored raw by the `minGain` check that follows anyway |
| `mostFrequent < nbSeq >> (log - 1)` → `<=` | reachable in principle; 50 000 generated inputs did not hit equality. **Uncovered.** |

The lazy strategies (levels 4–8) got the same treatment on 2026-09-22: 43
mutations of `lazy.zig`, the lazy half of `sequences.zig` and the new
`frame.zig`/`params.zig` lines. 21 were caught by the existing corpus (two
of them as a safety-checked overflow rather than a mismatch), 13 are caught by
12 cases found by the seed search (the lazy entries of `corpus.zig`: repcode
and lookahead limits, the row finder's long-match skip, `nextToUpdate`'s
resume cap, every tie in the table pricing, the `-1` probability in
cross-entropy), and 9 survive — listed below with one mutation from outside
the sweep, the hash salt:

| mutation | why no case exists |
|---|---|
| hash chain `matchIndex <= minChain` → `<`, `minChain + 1` | the hash chain runs only for windows ≤ 16 KB, where the chain table covers the whole input: `minChain` never rises above the first index |
| `currentMl > ml` → `>=` (hash chain and row) | equivalent: a candidate is measured only when the 4 bytes ending at offset `ml` match, so it is at least `ml + 1` long; a tie cannot occur |
| row: `break` → `continue` at `matchIndex < lowLimit` | equivalent: a row lists entries newest first, so every entry after the first out-of-window one is out of the window too |
| `fillHashCache` limit `>` → `>=` | the entry it drops is for a position no search reaches before the block ends |
| `nextToUpdate` raised to `lowLimit` before a block | unreachable one-shot: insertion trails the parser by at most a block, the window's low end only moves once the input passes the window |
| row `hashLog` cap `24 + rowLog` → `23 + rowLog` | unreachable at levels ≤ 10 (hash logs ≤ 23, cap ≥ 28); binds from level 22 |
| hash salt → 0 | equivalent on a fresh context: the salt XORs every hash before the shift, a bijection on (row, tag) that leaves every collision in place; it matters only for reused tag tables |
| `nbSeq >= 2048` → `>` in `ZSTD_NCountCost` | reachable in principle: a block of exactly 2048 sequences whose cost comparison flips on the low-probability rule; 4 000 generated seeds × 7 kinds × 6 sizes did not hit it. **Uncovered.** |

`btlazy2` (levels 9–10) followed on the same day: 35 mutations of the
binary-tree code in `lazy.zig` and of `max_level`. 11 were caught by the
existing corpus, 9 by the 4 `btlazy2` cases found by the seed search
(`two_symbols` inputs reach the unsorted-candidate limits, the skip over
repetitive matches and the end-of-input stop; a `skewed` one the offset
price), and 15 survive:

| mutation | why no case exists |
|---|---|
| window and tree-size limits: `matchIndex > windowLow` → `>=` (insertion), `matchIndex <= btLow` → `<` (insertion and search, both sides), the `dummy32` redirect dropped (both sides), `btMask >= curr` → `>`, `unsortLimit` → `windowLow` or → `btLow` alone, `maxDistance` − 1 | unreachable below level 11: at levels 9–10 `btlazy2` runs only on inputs ≤ 16 KB, whose window covers the whole input, so `windowLow` stays at the first index and `btLow` at 0 (the parser stops 8 bytes before the end, below `btMask`). `btlazy2` on larger inputs comes with levels 11–15, and their goldens will reach these lines; until then they were checked against libzstd with the strategy forced (below) |
| byte order `match[ml] < ip[ml]` → `<=` (insertion and search) | equivalent: `ml` is where `ZSTD_count` stopped, so the two bytes differ, unless the match reached the input end, which breaks out first |
| `matchEndIdx` update `>` → `>=` | equivalent: at equality it stores the value it already holds |
| `commonLengthSmaller` reset to 0 | equivalent: the common-prefix floor only saves re-comparing bytes known to be equal |

The optimal parsers, the post-splitter and optimal Huffman depth (levels
11–21) got the same sweep on 2026-09-22: 101 mutations of `opt.zig`,
`blocksplit.zig`, the new lines of `frame.zig`/`huf.zig`/`literals.zig`, and
the 11 `btlazy2` survivors above, which levels 11–15 now reach on larger
inputs. 52 were caught by the corpus as it stood, 16 by 14 cases the seed
search found (the `only_levels` entries of `corpus.zig`, each golden at the
one level that tells; `far-mix-5` is 1.4 MB, the only input past the 2^20
offsets btopt surcharges), and 33 survive:

| mutation | why no case exists |
|---|---|
| literal price cap `>` → `>=`; `insertBt1` `bestLength > 384` → `>=` and its initial 8 → 7; post-split `nbSeq <= 4` → `< 4`; `writeLitEntropy` always; a long length at exactly a chunk's end (`> endIdx` → `>=`); optimal depth breaking at `guess >= minTableLog`; DUBT `btMask >= curr` → `>` | equivalent: equality stores the same value (cap; `bestLength` 384 gives 0 skipped positions, and the initial value feeds nothing else); 4 sequences are under the 300 a split needs anyway; the header size is 0 unless the table is new; a long length at the end index is never read by that chunk and its stray code is recomputed by the next; at the minimum log a shallower natural tree is the same tree at any larger log; `btMask == curr` gives `btLow` 0 either way |
| predefined prices (literal 6 bits, offset `16 +`), the `srcSize <= 8` switch to them, `btultra2`'s `srcSize > 8` seeding pass; `ZSTD_BLOCKSIZE_MAX` literal length | unreachable: prices are predefined only for a first block of 8 bytes or less, where the parser (which stops 8 bytes before the end) never runs; a literal run of a whole 128 KB block likewise never reaches the parser |
| `sufficient_len` cap 4095 → 4094; split estimate error `nbSeq * 10`; 196 → 195 splits; sequence buffer sized `/4` for `minMatch` 3 | unreachable: `targetLength` is at most 999; a table the estimate just built from the same counts represents every symbol; 196 profitable splits need ~30 000 sequences in one block; more than `blockSize / 4` sequences need matches under 4 bytes on average — the last only sizes a buffer (an overrun is a bounds panic, not a different frame) |
| `insertBt1`'s window low at `curr` instead of `target`; DUBT insertion `matchIndex > windowLow` → `>=`; DUBT `maxDistance` − 1 | reached only when the input outgrows the window, which at the optimal levels takes > 4 MB (the golden set stops at 600 KB there, bar `far-mix-5`, whose window is 4 MB); checked instead against `zref` on 8–13 MB inputs at levels 13, 16 and 19 |
| tree low end `matchIndex <= btLow` → `<` (insertion, both sides — `insertBt1` and DUBT); DUBT `unsortLimit` → `btLow` (differs only for a candidate at index 2); a 3-byte-hash match of exactly `targetLength`; a tree match of exactly 4096 bytes (`> ZSTD_OPT_NUM` → `>=`); split literal estimate thresholds (`largest <= n/128 + 4`, repeat when `old < n`, `hSize + 12 >= n`, `old <= hSize + new`); estimate header sizes at 1024 literals and 128 sequences | reachable in principle, each at an equality; ten minutes of seed search per mutation (tens of thousands of inputs of 70 KB–600 KB at the levels concerned) did not hit one. **Uncovered.** |

Long-distance matching (level 22) got its own sweep on 2026-09-22: 47
mutations of `ldm.zig`, the LDM candidate code in `opt.zig`, the LDM switch
and the by-hand window in `params.zig`. The golden set can only reach LDM
through the by-hand seam (`frame.Options.ldm`, libzstd's
`ZSTD_c_enableLongDistanceMatching`), because it switches itself on only
above 64 MB; so the 5 cases that first carried it were inputs where LDM
changes the output at all. 16 mutations were caught by those, 1 by a unit
test added for it (LDM on from exactly 64 MB + 1 byte), 12 by 10 cases the
seed search found (the later `ldm-*` entries of `corpus.zig`; among them the
two libzstd quirks the port keeps — a "fixed" `ZSTD_ldm_gear_reset` and
offering the block's last LDM candidate both change the output), 2 only by
the 140 MB comparison below, and 16 survive:

| mutation | why no case exists |
|---|---|
| LDM window raising neither `lowLimit` nor `dictLimit` | reached only past 128 MB of input (window log 27); caught by `zref` on a 140 MB input whose last 10 MB repeat its first at a distance of 130 MB — the module's output matches libzstd's, both mutants do not |
| hash log floor 6 → 7; `srcSize < minMatchLength` → `<=`; `literalsBytesRemaining >= blockBytesRemaining` → `>`; a candidate cut at the block end `>` → `>=`, or skipping its full length; the candidate's initial end position | equivalent: at a 1 KB window (the only place the floor binds) the table is one bucket that fewer than 64 splits never fill; a chunk of exactly the minimum length has no byte left to hash; at the equality the candidate starts and ends at the block end, where no position lies, and the store is discarded with the block; the first fetch overwrites the initial value |
| backward extension stopping one byte above the prefix start; the last hashable byte (`ilimit`) one further; a split exactly at the previous match's end searched (`split < anchor` → `<=`); a table entry exactly at the lowest valid index; an overlapping match that ends exactly where hashing stopped (`>` → `>=`); continuing the batch after skipping an overlap; a batch of 32; another XXH64 seed; the checksum from bits 31..62; a candidate of exactly `minMatch` | reachable in principle; four minutes of seed search each (about 2 000 inputs of 3–600 KB at levels 16–22, 300 000 of 40 B–2.5 KB for the two small-window ones) did not hit one. The index equality needs the window past 128 MB. **Uncovered.** |

Index overflow correction (2026-09-23) is invisible in the output by design,
so the golden test also demands, for every `ocf` case, a nonzero correction
count from the match state and (for LDM) the LDM window
(`frame.Options.overflow_corrections`). 13 mutations of the correction and
the table reductions: 9 were caught by the first 10 `ocf` cases (mostly as
a crash — a stale index reads outside the input), one only by the
`reduceTable` unit test (the threshold without the `+ 2`), and 3 by cases a
seed search found (original against mutant over corpus-generated inputs,
windows of 1–128 KB): dropping `btlazy2`'s unsorted mark hit in 28 % of
inputs, and the two LDM table mutations crash within a minute. None
survives; a mutation of the correction's back-off only changes how often it
runs, which no output can show.

Beyond the committed goldens, the port was compared against `zref` on 49
boundary-size and edge-case files, 11 system files (ELF binaries, gzip, PNG,
JSON, text) and 800 random mixed inputs across levels -7…3, all identical;
for levels 4–8, on the golden corpus, 54 boundary-size and system files and
600 random mixed inputs (7 bytes to 900 KB) at every level — 3 470 frames,
all identical; for levels 9–10, on the golden corpus plus 25 boundary-size and
system files (308 frames) and 600 random inputs (1 byte to 400 KB), all
identical. Because those levels reach `btlazy2` only up to 16 KB, the
binary tree was also run on large inputs with the strategy forced — libzstd
via `ZSTD_c_strategy`, the port via a throwaway copy of `params.zig` that
repeats libzstd's two parameter adjustments (one for the level's own
strategy, one for the forced one) — on the same 77 files, a 9 MB input
(window slides) and about 200 of the random inputs: identical.
For levels 11–21 (2026-09-22): the golden corpus, 62 boundary-size and
system files at every level (682 frames), 6 inputs of 0.3–13 MB (window
slides, multi-block post-splits) at 8 levels, 600 random mixed inputs up to
700 KB, and every file with the strategy forced to `btopt`, `btultra` and
`btultra2` at levels 1–19 (about 1 000 frames): all identical, the first
time each ran. The strategy is now forced through `frame.Options.strategy`
and `params.getOverridden`, which repeat libzstd's two parameter
derivations, and `zref` takes the strategy as a fifth argument.
For level 22 and long-distance matching (2026-09-22): level 22 itself on
64 MB (window log 26, no LDM), 64 MB + 1 byte, 70 MB and 140 MB inputs of
system binaries with repeats 10–130 MB back (LDM on, the 140 MB one sliding
both windows past 128 MB); and with LDM switched on by hand, 50 system
files and concatenations up to 6 MB at levels 16–22 and with the strategy
forced to `btopt`/`btultra`/`btultra2` at levels 3, 9 and 12 (885 frames),
62 boundary sizes from 1 byte to 300 KB (around the minimum match, the hash
read limit and the block size) and 300 random mixed inputs up to 700 KB
(848 frames with level 22 without LDM): all identical, the first time each
ran.
For index overflow correction at its real threshold (2026-09-23): a 4.4 GB
generated input (words, noise and copies from anywhere earlier, so indices
pass 3500 MiB and positions pass 4 GiB) at levels 1, 3, 7 (row match
finder) and 13 (`btlazy2`), identical to plain `zref` — the port 1.0–1.15×
libzstd's time — and at level 1 in ReleaseSafe, where an index overflow
would have trapped.
Those runs are not stored; the oracle is, and re-runs them on any input.

**Anchor grade:** class A · oracle EXTERNAL

## What is deliberately not done

- **A faster port.** This is 1.3–1.5× slower than libzstd (process time,
  ReleaseFast, level 1 and 3 on a 13.7 MB CSV, a 3 MB text and an 11 MB ELF);
  1.2–1.4× at levels 5–8 (12 MB of Zig source, a 4.5 MB ELF); 0.9–1.4× at
  levels 13–19 (a 12.9 MB JSON and a 7.5 MB ELF, single runs on a loaded
  machine).
  The reference's speed comes from unrolling, prefetch and branchless selects
  that do not change decisions; adding them is possible later without touching
  the goldens. *Not now.*
- **Matching the `zstd` CLI as such.** The CLI drives the streaming API with
  its own buffer sizes; once Z1 matches `ZSTD_compressStream2`, the same
  chunking reproduces the CLI's frames, but the CLI (argv, file handling) is
  not this module's contract. *Never.*

## Backlog / deferred

Toward the goal above. "Session" ≈ one working session of the size of the
level-22/LDM port (≈ 500 lines of Zig with its goldens, diff runs and
mutation sweep). Every item that changes output is anchored the same way as
today: byte-identical to libzstd 1.5.7 through `tools/zref.c`, extended for
the API in question, plus goldens and a mutation sweep. Consumers as of
2026-09-22: **egw-hub** compresses CSV backups (one-shot suffices today);
**qap** wants HTTP `Content-Encoding: zstd` (Z1a now, Z1 later);
dictionaries are undecided.

- **Z1 — Streaming compression, byte-identical to `ZSTD_compressStream2`.**
  A compression context (`ZSTD_CCtx`) with `compressStream2`
  (`continue`/`flush`/`end`), reset and parameter setting; libzstd's input
  buffer of window + block size that wraps around; unknown pledged size (no
  parameter shrinking, header without content size — or with it when
  pledged); the stable-input mode. The wrap makes the window two segments,
  so **every match finder needs its extDict variant** (fast, dfast, lazy
  over hash chain / row / DUBT, the binary tree and optimal parser —
  roughly 1 500–2 000 lines of C across `zstd_fast.c`, `zstd_double_fast.c`,
  `zstd_lazy.c`, `zstd_opt.c`), and `ZSTD_count_2segments` plus LDM's
  two-segment counters. Long streams need Z3. Oracle: a `zref` mode that
  feeds the input in a given chunk schedule. **3–4 sessions.**
- ~~**Z1a — Frame-per-flush writer (interim).**~~ Done 2026-09-23:
  `FrameWriter`, see *Algorithm*.
- **Z2 — Decoder.** Frames with dictionaries (raw content and zstd-format:
  entropy tables + repcodes + content as history), checksum verification,
  configurable window limit (`ZSTD_d_windowLogMax`), streaming
  (`ZSTD_decompressStream`), and the frame utilities
  (`ZSTD_getFrameContentSize`, `ZSTD_findFrameCompressedSize`,
  `ZSTD_getDictID_fromFrame`, skippable frames). Correctness, not byte
  equality, is the contract: differential against libzstd's decoder plus
  its fuzz corpus. Can start from std's decoder (MIT) — it is a superset,
  which is why it is not a duplicate of std (CONVENTIONS.md §1.3). Legacy
  (pre-v0.8) formats: no. **1–2 sessions.**
- ~~**Z3 — Index overflow correction.**~~ Done 2026-09-23, see
  *Algorithm*. (The row tag table needs no reduction: it holds tags and
  in-row heads, not indices.)
- **Z4 — Compression with a dictionary.** Raw-content and zstd-format
  dictionaries (`ZSTD_loadCEntropy`, `ZSTD_loadDictionaryContent`), a
  reusable `CDict`, libzstd's attach / copy / reload choice
  (`ZSTD_shouldAttachDict` by size and strategy), which needs the
  **dictMatchState variant of every match finder** (on top of Z1's
  extDict), and the dictionary ID in the header. Dedicated dictionary
  search (`enableDedicatedDictSearch`) optional. Needs Z2 to decode.
  **2–3 sessions** after Z1.
- **Z5 — Dictionary training.** `ZDICT_trainFromBuffer` (fastCover, the
  CLI's default), `ZDICT_optimizeTrainFromBuffer_*`, `cover`, and
  `ZDICT_finalizeDictionary` (entropy tables for a given content); the
  legacy divsufsort trainer: no. Until then `zstd --train` offline works.
  **1–2 sessions.**
- **Z6 — Advanced parameters.** Explicit compression parameters (window,
  chain, hash, search log, min match, target length, strategy) with
  libzstd's bounds and adjustment; content-size and dictID flags;
  magicless frames; writing skippable frames; `literalCompressionMode`,
  `useRowMatchFinder`, `useBlockSplitter`/`postBlockSplitter`,
  `maxBlockSize`, `searchForExternalRepcodes`. Each goldened through
  `zref` with the parameter set. **~1 session.**
- **Z7 — Long-distance matching as an option** (`--long`, window log 27 by
  default): the path below `btopt` (`ZSTD_ldm_blockCompress`'s splicing
  loop, `maybeSplitSequence`, `ZSTD_ldm_skipSequences`,
  `ZSTD_ldm_fillFastTables` with `ZSTD_fillHashTable` /
  `ZSTD_fillDoubleHashTable`), and the LDM parameters. The optimal-parser
  path exists (level 22). **~0.5 session.**
- **Z8 — `targetCBlockSize`** (superblocks, `zstd_compress_superblock.c`,
  ~700 lines): blocks cut to a target compressed size for low-latency
  streaming. **~1 session.** After Z1.
- **Z9 — Multithreaded compression** (`zstdmt_compress.c`, ~1 900 lines):
  jobs, overlap between them, LDM across jobs, `rsyncable`. libzstd's
  output does not depend on the worker count once there is more than
  none, so it stays goldenable. **~2 sessions.** After Z1.
- **Z10 — Sequence-level API.** `ZSTD_compressSequences`,
  `ZSTD_generateSequences`, the external sequence producer. **~1
  session.** Niche.
- **Z11 — Speed parity** (target ≤ 1.1× libzstd): unrolled Huffman and
  histogram loops, prefetch, SIMD row-tag compare, the fast/dfast inner
  loops' cmov variants — none changes a decision, so the goldens stay.
  Today 1.2–1.5× at levels 1–8. **~2 sessions**, open-ended.
- **Z12 — Portability.** Run `portable-zstd-*`; big-endian (the
  pre-splitter's 16-bit hash reads *native* order in libzstd — decide which
  to match); 32-bit (`ZSTD_CURRENT_MAX` 2 000 MB). **~0.5 session.**
- **Z13 — Context reuse and sizing.** A reused `CCtx` gives different
  output than a fresh one (hash salt, tables kept between frames); match
  that, plus `ZSTD_estimateCCtxSize*` for memory planning and a
  caller-provided workspace (`ZSTD_initStaticCCtx`). **~1 session.** With Z1.

Suggested order: (Z1a, Z3 done) Z1 → Z2 → Z6 + Z13 → Z11 → Z7 → Z8 → Z4 + Z5
(once dictionaries are decided) → Z9 → Z10 → Z12. Z1 through Z13 together:
roughly 17–22 sessions.

## Open

- Reachable boundaries without a case: the sequence encoding-type
  heuristic's `mostFrequent < nbSeq >> (log - 1)` at equality, the table
  pricing's low-probability switch at exactly 2048 sequences, and 13
  equalities in the optimal parsers and the post-splitter's estimates, and
  10 in long-distance matching (see *Anchoring*).
- `targets` declares only `.linux64`; the code has no OS or endianness
  dependency, but `portable-zstd-*` has not been run.
