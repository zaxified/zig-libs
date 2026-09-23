# `zstd` — specification

Consumer view, API and purpose: [README.md](README.md).

## What this module is, and what it is not

A Zstandard **compressor** that reproduces libzstd 1.5.7's output byte for
byte: one-shot for every level, 1–22 and negative, and streaming
(`ZSTD_compressStream2`, for the same sequence of calls) for the same levels;
and a **decoder** ported from libzstd's, one-shot and streaming (see
*Decoder*). Every strategy is
translated from libzstd — `fast`, `dfast`, `greedy`/`lazy`/`lazy2` over both
the hash chain and the row-based search, `btlazy2`'s binary tree, and the
optimal parsers `btopt`/`btultra`/`btultra2` — together with the frame/block
driver, the block pre-splitter and post-splitter, long-distance matching as
libzstd switches it on by itself (level 22 above 64 MB), and the entropy stage
(literals via Huffman, sequences via FSE); see [NOTICE](NOTICE) for the
file-by-file map.

**Goal (2026-09-22): production quality — as close to libzstd's feature set
and behaviour as possible, so that a Zig program never needs to link libzstd.**
Today it is the compressor and the decoder, each one-shot and streaming;
everything else libzstd offers is in *Backlog / deferred* below,
with its cost.

Not here yet, and a reader might expect it (each is a backlog item):

- **Dictionaries (Z2c, Z4, Z5).** A frame naming a dictionary is
  `error.DictionaryWrong`.
- **The rest of the streaming API.** `Stream` (see *Algorithm*) does
  libzstd's default buffered modes for one frame; not the stable-buffer
  modes, a second frame on the same context (Z1, Z13), or a `std.Io.Writer`
  over it. `FrameWriter` (Z1a) — a `std.Io.Writer` of
  independent one-shot frames — takes every level.
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

**Streaming** (`stream.zig`, `ZSTD_compressStream2` /
`ZSTD_compressStream_generic` with libzstd's default buffered input and
output). A `Stream` sets its parameters at the first call: from the pledged
size, or — when that first call already ends the frame — from that call's
input, as libzstd does; with neither, from the table for inputs over 256 KB,
without shrinking anything, and the header then carries no content size.
Input is copied into a buffer of one window plus one block (the window
shrunk to a pledged size). Each time a block's worth (`blockSizeMax`) is
buffered — at the first block, one byte more when the pledged size is
exactly one block, so the frame does not need an empty last block — and at
each `flush` and `end`, the buffered chunk is compressed
(`ZSTD_compressContinue`, `ZSTD_compressEnd`: `frame.Compressor`, which the
one-shot path runs over the whole input as one chunk). So the pre-splitter
sees one chunk at a time, and its savings count the frame header. When the
next block would not fit before the buffer's end, buffering restarts at its
start. An `end` that finds the buffer empty and the caller's output large
enough (`compressBound` of the rest) compresses the rest straight from the
caller's input. The output goes straight into the caller's buffer when it
has room for `compressBound` of the chunk, else through a buffer of one
compressed block that later calls drain; the bytes are the same either way.

A chunk that does not follow the previous one in memory (the buffer
wrapped, or the end came from the caller's input) makes the window two
segments (`ZSTD_window_update`): the old prefix becomes the *extDict*, the
chunk starts a new prefix at the next index, and new input copied over the
extDict's memory raises its low limit. From then on `fast` and `dfast` run
their extDict variants (`ZSTD_compressBlock_fast_extDict_generic`,
`..._doubleFast_extDict_generic`): a candidate's bytes come from whichever
segment holds its index, a match may run from the extDict's end on into
the prefix (`ZSTD_count_2segments`), repcodes straddling the boundary are
refused, and once the window has left the extDict behind they fall back to
the plain variants. `greedy` … `btlazy2` run libzstd's extDict parser
(`ZSTD_compressBlock_lazy_extDict_generic`), which has no such fall-back and
no saved repcodes: each repcode test checks the offset against the window at
that position instead. Its three searches take a candidate below the
extDict's end by its first 4 bytes and count on into the prefix (hash chain,
row); the binary tree compares across the boundary too, and sorting a
still-unsorted candidate that is itself in the extDict compares it against
older extDict positions up to the extDict's end. Tables are only ever filled
from the prefix (`nextToUpdate` moves to the new segment's start).

An overflow correction moves both segments (of both windows). libzstd's
`dfast` extDict search reads 8 bytes at a table index that can lie 7 bytes
before the extDict's end, so one byte past it: the port reads the same
buffer byte (the extDict stays readable up to the buffer's end, which starts
zeroed like a fresh allocation). The byte only matters on an 8-byte hash
hit whose first 7 bytes match; libzstd's own buffer there holds whatever the
allocator gave it.

The optimal parsers keep their parser as it is; their binary tree
(insertion and the all-matches search) compares candidates across the
boundary as DUBT does, a repcode below the prefix is tested against the
window and the boundary, and the 3-byte hash's candidate may lie in the
extDict. `btultra2` seeds its statistics only on a frame's first block with
no extDict, as libzstd checks. Long-distance matching keeps its own window
of the same chunks (`ZSTD_window_update` on its window too): over two
segments a candidate is valid down to the window's low limit, counts
forwards into the prefix and backwards from the prefix into the extDict —
except, as libzstd compares the two segments' starts as pointers, when
those are one address.

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

## Decoder

A port of libzstd's decoder (`lib/decompress/*`, `lib/common/entropy_common.c`,
`fse_decompress.c` and the reader half of `bitstream.h`): frame header, raw,
RLE and compressed blocks, Huffman literals (single- and double-symbol
tables, one and four streams, the choice between them by
`HUF_selectDecoder`), FSE sequence tables (predefined, RLE, compressed,
repeat), repeat offsets, content checksum, concatenated and skippable
frames, and the frame queries (`getFrameHeader`, `getFrameContentSize`,
`findFrameCompressedSize`, `findDecompressedSize`, `decompressBound`,
`decompressionMargin`, `readSkippableFrame`, `getDictIdFromFrame`). Errors
are named after `ZSTD_error_*`, so a differential run compares the error
class too.

The contract is correctness: every valid frame decodes to its content, and
a malformed one is refused where libzstd refuses it. Corrupt input is where
ports drift, so the code keeps libzstd's behaviour past the end of a
corrupt bitstream (the reader keeps handing out bits from its stale
container, and only the final "fully consumed" check rejects the block)
and uses libzstd's fast four-stream Huffman loop wherever libzstd does on a
64-bit little-endian CPU with BMI2 — that loop does not check a stream's
end mark, so which damaged literal sections are accepted depends on it.
Two simplifications, neither of which changes a decoded byte or which
frames are accepted: literals are decoded into the context's own buffer
(libzstd parks them at the far end of `dst` when there is room, saving a
copy — the limit that puts on a block's output is kept; its "split"
placement, for more than 64 KB of literals with little room left, is not);
and only the "short" sequence decoder is ported (libzstd switches to a
prefetching one for cold dictionaries and long distances, which checks the
bitstream's end before its last eight sequences run). On corrupt input
either can change only the reported error. Like libzstd, the one-shot
decoder does not hold raw and RLE blocks to the frame's
`Block_Maximum_Size`, while the piecewise decoder under the stream refuses
any block over it (RFC 8878 §3.1.1.2.4) — so a malformed frame can be
accepted one way and refused the other, in both libraries alike.

**Streaming** (`DecompressStream`, `ZSTD_decompressStream`) is built on the
piecewise decoder (`Decompressor.decompressContinue`, public as
`ZSTD_decompressContinue` is): a frame header or block that arrives split
is gathered in an input buffer of one block; output goes through a ring of
one window plus two blocks (`ZSTD_decodingBufferSize`), or with
`stable_output` straight into the caller's buffer, which must then stay put
(`error.DstBufferWrong` otherwise). History across the ring's wrap is
libzstd's pointer model (`ZSTD_checkContinuity`): output not written right
after the previous output starts a new prefix, and the old prefix becomes
the second segment matches may reach. A frame whose whole compressed form
is in the input and whose content fits the output goes through the
one-shot decoder (libzstd's single-pass shortcut). Kept from libzstd too:
the hostage byte (a frame decoded but not yet flushed holds its last input
byte back, so "all input consumed" means "done"), the returned hint, the
error after 16 calls without progress, and shrinking buffers that stayed
3× too large for 128 frames. `DecompressReader` is a `std.Io.Reader` over
it.

Speed: 1.04–1.05× libzstd's decode time on 200 MB of system binaries
compressed at levels 3 and 19 (decode only, best of 5, ReleaseFast). std's
decoder takes 30× libzstd's time on the same frames, which is why this is a
port and not an extension of it.

`Decompressor` holds the tables and a 128 KB literal buffer (≈ 190 KB) on
the heap; `decompress` allocates one per call.

## Limits and refusals

| limit | value | source |
|---|---|---|
| level | `min_level` (-131072) … 22; lower is clamped, higher is `error.LevelUnsupported` | `ZSTD_minCLevel()` / `ZSTD_maxCLevel()`; libzstd clamps above 22 too, which would hand a caller a level it did not ask for |
| memory | level 22 above 64 MB: 512 MiB binary tree + 128 MiB hash + 64 MiB LDM table + 32 KiB bucket offsets (≈ 820 MB peak on a 70 MB input, as libzstd) | the level's own table sizes; nothing is capped, as libzstd caps nothing |
| input | none (the input and `compressBound` of it in memory) | past `ZSTD_CURRENT_MAX` (3500 MiB on 64-bit) the indices are rescaled, as libzstd does (see *Algorithm*) |
| destination | ≥ `compressBound(src.len)` or `error.NoSpaceLeft` | the reference's decisions assume the one-shot bound; accepting less would let capacity change the output |
| block | 128 KB | format |
| stream level | as one-shot (`stream_max_level` = `max_level`) | level 22 without a pledged size uses a 128 MB window and long-distance matching (window log 27, as libzstd), ≈ 1 GB |
| stream size | a pledged size must be met exactly, else `error.SrcSizeWrong` (more input at the chunk that passes it, less at the end) | `srcSize_wrong` |
| stream memory | one window plus one block of input buffer, `compressBound(block) + 1` of output buffer, and the level's tables | `ZSTD_resetCCtx_internal` |
| decode window | one-shot: none, the whole output is history (window log ≤ 31 in the header, else `error.FrameParameterWindowTooLarge`); streaming: `window_log_max`, default 2^27 + 1 bytes, else `error.FrameParameterWindowTooLarge` | `ZSTD_WINDOWLOG_MAX` (64-bit); `ZSTD_d_windowLogMax` and its default `ZSTD_WINDOWLOG_LIMIT_DEFAULT` |
| decode stream memory | input buffer of one block, output ring of one window + two blocks + 64 bytes (none with `stable_output`), plus the ≈ 190 KB context | `ZSTD_decodingBufferSize_min` |
| decode destination | the whole output; too small is `error.DstSizeTooSmall`. `decompressAlloc` sizes from the headers, else `decompressBound`, never above its `max_size` | `ZSTD_decompress` |
| decode block | streaming: decoded size ≤ `Block_Maximum_Size`; one-shot: as libzstd, only a compressed block's output is bounded (see *Decoder*) | RFC 8878; `ZSTD_decompressContinue` / `ZSTD_decompressFrame` |

`golden_test.zig` pins all of the above through the output; `root.zig` tests
pin the level refusal and the destination bound, `stream_test.zig` the
stream's level refusal, the pledged size both ways and the call after the
end. `FrameWriter` takes a
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

**Streaming** (2026-09-23) has its own goldens: `src/testdata/
stream_goldens.zig` holds, for each of 54 `corpus.stream_cases` (a corpus
input and a call schedule) × its levels (-5, -1 and 1–3 for 31 cases, 4–10
for 7, 11–22 for 6, one level each for the 10 found by search) × checksum,
the length and SHA-256 of everything `ZSTD_compressStream2` emits (470
streams),
written by the same recipe through `tools/zstream.c`; schedules starting
with `x` run against libzstd built with frequent overflow correction. The
extDict search leaves no mark in the output, so the test also demands, where
a case says so, that the extDict variant of a match finder actually searched
some block (`MatchState.n_ext_dict_blocks`, counted after the fall-back to
the plain variant — a first version counted windows that merely had an
extDict and was blind: with a window of 128 KB or less a full block reaches
back exactly one window, the extDict is out of reach and the plain variant
runs), and for `x` cases a nonzero correction count.

59 mutations of the new code (`windowUpdate`, `count2Segments`, the `fast`
and `dfast` extDict variants, overflow correction of two segments,
`stream.zig`, `frame.Compressor`, the unknown-size parameters): 26 were
caught by the first 17 cases, 3 more once rewritten to compile, and 14 by
cases a seed search found — the mutant against `zstream` over corpus inputs
× random schedules (window logs 10–20, chunks of 0 bytes to the whole
input, flushes, small outputs, `x`) — or built for the purpose (a pledged
size of exactly one block; an output of exactly `compressBound`, on an input
whose buffered pre-split differs from one-shot). 16 survive:

| mutation | why no case exists |
|---|---|
| `ZSTD_window_update`: the overlap rule (off, `>` → `>=`, `<` → `<=`), `lowLimit` not moved up to the old `dictLimit` | equivalent in the buffered mode: the input buffer is one window plus one block, so input written over the extDict's memory only ever overwrites bytes more than a window back, which `maxDist` already excludes; at the overlap's equalities the new limit equals the old one |
| "too small extDict" (< 8 bytes) → < 7 | unreachable: a segment is a whole pass through the buffer (at least one window, 1 KB) |
| extDict readable to the buffer's end dropped | not reached by any case (it would be a bounds panic, not a different frame); see *Algorithm* |
| `ZSTD_getLowestMatchIndex` `>` → `>=`; overflow correction of a segment at exactly the threshold (`>=` → `>`) | equivalent: both branches give the same value at the equality |
| `fast` extDict: `offset >= maxRep` → `>` (both repcodes), the saved-offset rotation dropped; `dfast` extDict: repcode `offset <= curr + 1 - dictStart` → `<` (both), short and 3-byte-hash candidates at exactly the extDict's low end | reachable in principle, each at an equality; 1 200 random schedules per mutation over the corpus did not hit one. **Uncovered.** |
| more input than pledged caught when a chunk passes the size | equivalent in outcome: the end catches the same stream with the same error, only later |

The lazy extDict code (Z1b, 2026-09-23) got 22 mutations (the parser's
repcode tests, catch-up limits, gains, lazy skipping and hash-cache refill,
the extDict candidate test of the hash chain and rows, DUBT's comparisons
across the boundary and within the extDict). 14 were caught by the 7 lazy
cases, 6 by cases the schedule search found (the last 6 lazy entries of
`corpus.stream_cases`), and 2 survive as equivalent: DUBT's segment choice
at `matchIndex + matchLength == dictLimit` (`>=` → `>`, in insertion and
search) — a match starting exactly at the extDict's end counts nothing
there and goes on from the prefix's first byte, which is where it is.

The optimal parsers and long-distance matching over two segments (Z1c,
2026-09-23) got 21 mutations. 9 were caught by the 6 cases at levels
11–22, 4 by cases the schedule search found (with LDM switched on by hand,
schedule token `l`), and 8 survive:

| mutation | why no case exists |
|---|---|
| tree and 3-byte-hash segment choice at `matchIndex (+ matchLength) == dictLimit` (`>=` → `>`) | equivalent, as for DUBT above |
| LDM's extDict readable to the buffer's end dropped | not reached (it would be a bounds panic, not a different frame) |
| optimal parser: a repcode into the extDict exactly at the window's low end (`<` → `<=`); LDM: a forward match from the extDict's end going on into the prefix, a backward match from the prefix's start going on into the extDict (dropped; its low end one higher; the pointer comparison of the segment starts replaced by the segment test) | reachable in principle; 1 500 random schedules per mutation at levels 16–22 (95 % with LDM by hand) and 36 constructed ones (long repeats and runs across the wrap point) did not hit one. **Uncovered.** |

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
finder), 13 (`btlazy2`) and 16 (`btopt`, 36 min), identical to plain `zref`
— the port 1.0–1.15× libzstd's time where both were timed — and at level 1
in ReleaseSafe, where an index overflow would have trapped.
Those runs are not stored; the oracle is, and re-runs them on any input.

**Decoder (2026-09-23).** The contract is correctness (see *Decoder*), so
the anchor is libzstd's own decoder rather than digests: every golden and
streaming frame above is decoded back to its input in the test suite, and
off-line, through `tools/zdec.c`, 13 600 random valid frames from libzstd's
`tests/decodecorpus` (block sizes down to 1 KB, forced raw/RLE/compressed
blocks, content sizes on and off) and the CLI's `--long=30`,
`--rsyncable` and concatenated/skippable frames decoded identically, and of
5 000 damaged frames (bit flips, byte changes, cuts, insertions, zeroed
runs) none crashed a ReleaseSafe build, none decoded differently, and every
one libzstd refused was refused. After the streaming decoder landed
(Z2b), the same 35 662 files (the damaged ones included) went through both
libraries again, with `tools/zdec.c` gaining a streaming mode that feeds
one input byte per call into a 997-byte output buffer, which `sdec`-style
drivers repeat call for call: one-shot and streaming each agree with
libzstd's on every frame — output, acceptance and, but for the split
literal placement and the prefetching decoder above, the error — and on
valid frames every call plan (random chunks, single bytes, stable output,
the `Reader`) gives the same bytes.

A mutation sweep of the new decoder files (64 single-edit mutations) then
drove the tests: 26 were caught by the corpus round trips and
`decoder_test.zig`, 3 had to be rewritten to compile (one of them,
`more_than_1_frame` ignored, is caught by `decoder_test`), and for the
survivors a hunt ran each mutant against the unmutated decoder over 45 000
valid and damaged `decodecorpus` frames. It found a frame for 11 of them;
those frames are `src/testdata/decode_kats.zig` (13–210 bytes each, random
content, each with libzstd's verdict and the mutation it pins): the fast
Huffman loop's conditions and table log (it decides which damaged literals
are accepted), X1/X2 choice, the bitstream's exact end, a literal length
past the literals, a content size larger than the output and
`decompressBound` for frames without a size. (The eleventh, the window
mantissa, lost its frame when Z2b made the one-shot decoder bound blocks
as libzstd does; a header test pins it now.) The rest survive:

| mutation | why no case exists |
|---|---|
| bit reader `ptr >= start + 8` → `>`, `bitsConsumed < 64` → `<=`, `ptr - start < nbBytes` → `<=` | equivalent: the two reload paths read the same bytes at the boundary, and callers do not tell `endOfBuffer` from `completed` |
| `FSE_readNCount` `remaining != 1` → `> 1`; Huffman `rankStats[1] < 2` → `< 1`; FSE weight table `tableLog > maxLog` → `> maxLog + 1` | equivalent: `remaining` never drops below 1; a single weight-1 symbol is odd and caught by `& 1`; this port's weight table holds log 6 and refuses more itself |
| FSE `fastMode` at `count >= tableSize/2` → `>` | equivalent: at exactly half the table no state consumes 0 bits |
| `FSE_readNCount` `count >= threshold` → `>`, `bitCount > 32` → `>=` | reachable only in damaged headers (no encoder writes the value `threshold`); 45 000 frames did not produce one |
| Huffman fast-loop and X2 tail limits (`p_end - p > 3`, `op[3] >= oend`, `dtLog <= 11`, X2 level-2 fill rounding), `HUF_selectDecoder`'s weighting, raw literals read in place vs copied, `total_bits >= 31` reload, last-literals bound, the checksum computed when ignored, the frame-size precheck | equivalent: each changes only which of two equal paths runs |
| 4 streams with exactly 6 literals refused; an RLE table of the largest code refused | **uncovered**: valid by the format, but no encoder emits either (libzstd uses one stream below 256 literals, and RLE tables only for three or more sequences, which the largest codes cannot fit in a block) |
| `nbSeq` ≥ 0x7F00 (3-byte count) off by one | **uncovered**: needs a block of more than 32 512 sequences; generated token streams reached 31 106 |

**Streaming decoder (Z2b, 2026-09-23).** `dstream_test.zig` replays
libzstd's `ZSTD_decompressStream` call by call on the same frames — return
hints (header in pieces, the next block header counted, the checksum read
only after the output is flushed), how much input each call consumes, the
hostage byte with and without an empty input after it, a raw block passed
through in pieces, the single-pass shortcut at exactly the content size,
the window limit (a single-segment frame's content size counts; the
default is 2^27 + 1), a 4-byte checksum through the input buffer of a
2-byte frame, and the buffers shrinking after 128 frames 3× too large —
all recorded from libzstd first, then asserted. Output under every call
plan is checked against the input and the one-shot decoder. A 26-mutation
sweep of the streaming code and `decompressContinue` ended with 19 caught
by those tests or by one more damaged frame in `decode_kats.zig` (raw
literals read in place do not bound the block the way literals in `dst`
do), 2 of them after a rewrite to compile, and 7 survivors: the skippable
frame's detour through the flush stage, a ring one block smaller (the
refill starts only past a window plus 64 bytes of flushed output, so the
second block is headroom), decoding a piece straight from the input rather
than through the input buffer at the exact size, the "should never
happen" input-buffer guard, the ring restart at exactly one block from its
end, and continuity on an empty destination (never passed while a frame is
decoded) — all equivalent; and the literal-placement limit off by one
(`+ 32` → `+ 33`), reachable only on damaged input, not found in 18 680
damaged frames.

**Anchor grade:** class A · oracle EXTERNAL

## What is deliberately not done

- **A faster port.** Z1 made the match state's prefix start at a variable
  index (a segment can begin anywhere): +4.5 % instructions on one-shot
  compression at levels 1–16 of a 6 MB text (`perf stat`, ReleaseFast),
  output unchanged. Z11 is where it comes back.
  This is 1.3–1.5× slower than libzstd (process time,
  ReleaseFast, level 1 and 3 on a 13.7 MB CSV, a 3 MB text and an 11 MB ELF);
  1.2–1.4× at levels 5–8 (12 MB of Zig source, a 4.5 MB ELF); 0.9–1.4× at
  levels 13–19 (a 12.9 MB JSON and a 7.5 MB ELF, single runs on a loaded
  machine).
  The reference's speed comes from unrolling, prefetch and branchless selects
  that do not change decisions; adding them is possible later without touching
  the goldens. *Not now.*
- **Matching the `zstd` CLI as such.** The CLI drives the streaming API with
  its own buffer sizes; `Stream` matches `ZSTD_compressStream2`, so the same
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
  ~~**Z1a**~~ `FrameWriter`, done 2026-09-23. ~~**Z1-1**~~ done 2026-09-23:
  `Stream` with `continue`/`flush`/`end` over buffered input and output,
  pledged or unknown size, the window in two segments, and the extDict
  variants of `fast` and `dfast` — so levels ≤ 3. Oracle `tools/zstream.c`
  (a call schedule), goldens in `stream_goldens.zig`. Left:
  - ~~**Z1b — lazy family.**~~ done 2026-09-23: the extDict parser and the
    hash chain, row and DUBT searches in extDict mode; streams up to
    level 10.
  - ~~**Z1c — optimal parsers and LDM.**~~ done 2026-09-23: the binary
    tree of the optimal parsers and the 3-byte hash across both segments,
    and long-distance matching over its own two-segment window; streams at
    every level.
  - **Later:** the stable-input / stable-output buffer modes
    (`ZSTD_c_stableInBuffer`, which compresses straight from the caller's
    buffer and waits for a full block), `ZSTD_CCtx_reset` and a second frame
    on the same context (with Z13), a `std.Io.Writer` over `Stream`
    (replacing `FrameWriter` for callers that want libzstd's bytes).
- **Z2 — Decoder.** ~~**Z2a**~~ done 2026-09-23: the one-shot decoder,
  checksum verification, concatenated and skippable frames and the frame
  utilities, ported from libzstd (std's decoder takes 30× libzstd's time,
  so it was not the base); see *Decoder*. Left:
  - ~~**Z2b — streaming**~~ done 2026-09-23: `DecompressStream`
    (`ZSTD_decompressStream`), `decompressContinue`, `DecompressReader`.
  - **Z2c — dictionaries**: raw-content and zstd-format (`ZSTD_loadDEntropy`:
    entropy tables, repcodes, content as history), a reusable `DDict`, and
    the multiple-dictionary table. **~1 session**; together with Z4.
  Legacy (pre-v0.8) formats: no. Magicless frames: with Z6.
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

Suggested order: (Z1a, Z1-1, Z1b, Z1c, Z3, Z2a, Z2b done) Z6 + Z13 → Z11 → Z7 → Z8 → Z4 + Z5
(once dictionaries are decided) → Z9 → Z10 → Z12. Z1 through Z13 together:
roughly 17–22 sessions.

## Open

- Decoder: three reachable decisions without a case (see *Anchoring*):
  a block of ≥ 0x7F00 sequences, four-stream literals of exactly 6 bytes, an
  RLE sequence table of the largest code.
- Reachable boundaries without a case: the sequence encoding-type
  heuristic's `mostFrequent < nbSeq >> (log - 1)` at equality, the table
  pricing's low-probability switch at exactly 2048 sequences, and 13
  equalities in the optimal parsers and the post-splitter's estimates, and
  10 in long-distance matching (see *Anchoring*).
- `targets` declares only `.linux64`; the code has no OS or endianness
  dependency, but `portable-zstd-*` has not been run.
