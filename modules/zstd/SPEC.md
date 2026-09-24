# `zstd` — specification

Consumer view, API and purpose: [README.md](README.md).

## What this module is, and what it is not

A Zstandard **compressor** that reproduces libzstd 1.5.7's output byte for
byte: one-shot for every level, 1–22 and negative, and streaming
(`ZSTD_compressStream2`, for the same sequence of calls) for the same levels,
with libzstd's advanced parameters (see *Advanced parameters*); and a
**decoder** ported from libzstd's, one-shot and streaming (see *Decoder*). Every strategy is
translated from libzstd — `fast`, `dfast`, `greedy`/`lazy`/`lazy2` over both
the hash chain and the row-based search, `btlazy2`'s binary tree, and the
optimal parsers `btopt`/`btultra`/`btultra2` — together with the frame/block
driver, the block pre-splitter and post-splitter, long-distance matching
(where libzstd switches it on by itself, level 22 above 64 MB, and as the
option `--long` is, at any level), and the entropy stage
(literals via Huffman, sequences via FSE); see [NOTICE](NOTICE) for the
file-by-file map.

**Goal (2026-09-22): production quality — as close to libzstd's feature set
and behaviour as possible, so that a Zig program never needs to link libzstd.**
Today it is the compressor and the decoder, each one-shot and streaming;
everything else libzstd offers is in *Backlog / deferred* below,
with its cost.

Not here yet, and a reader might expect it (each is a backlog item):

- **Part of dictionaries (Z2c, Z4, Z5b).** Compressing with a dictionary is
  here (see *Dictionaries*), attaching included for every strategy now
  (`fast`/`dfast`: D1; `greedy`…`btlazy2`: D2; the optimal parsers: D3).
  **Decompression with a dictionary is done too** (Z2c, see *Decoder*):
  raw-content and zstd-format dictionaries, a digested `DDict`,
  `ZSTD_d_refMultipleDDicts`, one-shot and streaming; a frame that names a
  dictionary this module was not given is `error.DictionaryWrong`. Of
  training, the content selection is here (*Dictionary training*);
  finalization is not.
- **The rest of the streaming API.** `Stream` (see *Algorithm*) does
  libzstd's default buffered modes, frame after frame on one context; not
  the stable-buffer modes (Z1) or a `std.Io.Writer` over it. `FrameWriter` (Z1a) — a `std.Io.Writer` of
  independent one-shot frames — takes every level.
- **Multithreading (Z9).**

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
   Switched on as an option (`Advanced.long_distance_matching = .enable`,
   the CLI's `--long`), LDM runs at any level, and the window log starts
   from 27 before the input shrinks it. Below `btopt` its sequences are not
   candidates but taken as they come (`ZSTD_ldm_blockCompress`): the level's
   own match finder runs over the literals before each (with its repeat
   offsets, then the LDM offset pushed onto them), and before each run `fast` and `dfast`
   insert every third position from `nextToUpdate` into their tables
   (`ZSTD_ldm_fillFastTables` — with no lower bound but
   `ZSTD_ldm_limitTableUpdate`, which after a long match keeps only the
   last 512 positions before it). The match finders run on stretches a few
   bytes long there, so their `iend - 8` limits saturate at 0 rather than
   point below the stretch. libzstd's loop also cuts a sequence that runs
   past the block's end (`maybeSplitSequence`, `ZSTD_ldm_skipSequences`);
   that is ported but not reachable from LDM, whose sequences are generated
   per block and end inside it — it is there for external sequences (Z10).
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
Each frame starts with no history, so small flushes cost ratio; the
compression context (its workspace, see *Contexts*) is reused from frame
to frame. `Stream` is the real stream. `Writer.Error` has
one member, so a failure of our own (out of memory) is kept in
`FrameWriter.err`; null there means `output` failed.

## Advanced parameters

`Options.advanced` (and the same field of `StreamOptions` and
`FrameWriterOptions`) is libzstd's `ZSTD_CCtx_setParameter` set, each field
one parameter, null or `.auto` for "not set":

| field | libzstd | bounds |
|---|---|---|
| `window_log`, `hash_log`, `chain_log`, `search_log`, `min_match`, `target_length`, `strategy` | `ZSTD_c_windowLog` … `ZSTD_c_strategy` | 10–31, 6–30, 6–30, 1–30, 3–7, 0–131072 |
| `content_size` | `ZSTD_c_contentSizeFlag` | |
| `format` | `ZSTD_c_format` (`.magicless`: no magic number) | |
| `literal_compression`, `row_match_finder`, `split_after_sequences` | `ZSTD_c_literalCompressionMode`, `ZSTD_c_useRowMatchFinder`, `ZSTD_c_splitAfterSequences` | auto / enable / disable |
| `block_splitter_level` | `ZSTD_c_blockSplitterLevel` | 0–6 |
| `max_block_size` | `ZSTD_c_maxBlockSize` | 1024–131072 |
| `long_distance_matching` | `ZSTD_c_enableLongDistanceMatching` | auto / enable / disable |
| `ldm_hash_log`, `ldm_min_match`, `ldm_bucket_size_log`, `ldm_hash_rate_log` | `ZSTD_c_ldmHashLog` … `ZSTD_c_ldmHashRateLog` (0 = not set) | 6–30, 4–4096, 1–8, 0–25 |
| `target_c_block_size` | `ZSTD_c_targetCBlockSize` (0 = off; 1–1339 count as 1340) | 0–131072 |
| `StreamOptions.src_size_hint` | `ZSTD_c_srcSizeHint` | 1–2^31-1 |
| `dict_id_flag` | `ZSTD_c_dictIDFlag` | |
| `force_attach_dict` | `ZSTD_c_forceAttachDict` | default / attach / copy / load |
| `deterministic_ref_prefix` | `ZSTD_c_deterministicRefPrefix` | |
| `force_max_window` | `ZSTD_c_forceMaxWindow` | |

The bounds are `ZSTD_cParam_getBounds` on 64-bit; outside them is
`error.ParameterOutOfBound`, where `ZSTD_CCtx_setParameter` refuses. The
parameters are derived as `ZSTD_getCParamsFromCCtxParams` does: the
level's row (by the source size, or for an unknown size by
`src_size_hint`), already adjusted once for the level's own strategy; the
explicit parameters put over it (`ZSTD_overrideCParams`, where a
`target_length` of 0 counts as "not set"); and the adjustment run again —
which caps the hash log for the row match finder unless that is switched
off. Then libzstd's resolvers: the row match finder only for `greedy` …
`lazy2` (enable on another strategy does nothing), the post-splitter and
literal compression (`.auto`: off for `fast` with an acceleration, that is
the negative levels) as described in *Algorithm*. The block size is
`min(max_block_size, window)`; with blocks under 128 KB the pre-splitter
never cuts. `block_splitter_level` 1 never pre-splits, 2–6 are the
splitter's levels 0–4 (from the borders, then by chunks), 0 picks by
strategy. Long-distance matching `.enable` sets the window log to 27
before the explicit parameters go over it (`ZSTD_LDM_DEFAULT_WINDOW_LOG`);
`.auto` decides from the final parameters (`btopt` and up with a window log
of 27 or more, `ZSTD_resolveEnableLdm`), so an explicit `window_log` of 27
turns it on under the optimal parsers, and so does a stream of unknown size
there. The LDM parameters left unset are derived by
`ZSTD_ldm_adjustParameters`: the hash rate from the hash log when that is
set (window log − hash log, or 0 when the table is not smaller than the
window: then every position is a split point), else 7 − strategy/3; the
hash log from the rate, window log − rate bounded to 6–30 — in libzstd's
unsigned arithmetic, so a rate above the window log (which the input can
have shrunk) wraps to a hash log of 30, a table of 8 GB, exactly as libzstd
allocates it; the minimum match 64, 32 from `btultra`; the bucket log the
strategy bounded to 4–8, and never above the hash log. Two places consult literal compression besides the literals
section itself: the optimal parsers price a literal at 8 bits and keep no
literal statistics when it is disabled (`ZSTD_compressedLiterals`), and the
post-splitter's size estimate stores the literals raw.

`content_size = false` leaves the size out of the header (and so the
header is never single-segment); libzstd clears the flag for an unknown
size anyway. A magicless frame is the same frame without its first four
bytes; only a decoder told `format = .magicless` reads it, and such a
decoder knows no skippable frames. `writeSkippableFrame` writes one
(`ZSTD_writeSkippableFrame`, magic variants 0–15).

`target_c_block_size` cuts each block into compressed blocks of about that
many bytes (*superblocks*, `superblock.zig`, `ZSTD_compressBlock_targetCBlockSize`),
so that a decoder fed over a network can emit output sooner. It takes
precedence over the post-splitter. The block's entropy tables are built
once for all its sequences (`ZSTD_buildBlockEntropyStats`); from their
estimated cost per literal and per sequence, the sequences are dealt into
`round(estimate / target)` sub-blocks of equal budget, the first charged
120 bytes more for the tables it will carry. The first sub-block that
writes literals (or sequences) carries their tables; the later ones say
`set_repeat`, so a sub-block's literal header may be 3 bytes where a block
of its own would need 4 (the header size is chosen with 200 bytes of slack
for the tables, and a sub-block whose compressed literals would outgrow it
stores them raw). A sub-block that does not come out smaller than what it
decodes to is folded into the next one; if the last one fails too, the
rest of the block goes out raw and the repeat offsets are set back to what
the emitted sub-blocks leave. A block whose estimate exceeds its own size,
or whose sub-blocks together would, is one raw block; a block of fewer than
4 sequences and 10 literals that repeats one byte is an RLE block (never
the first). The frame is not bound by `compressBound` sub-block by
sub-block: a superblock of a raw block's size or more is replaced by the
raw block, as libzstd does.

The four dictionary parameters are described in *Dictionaries*. Not here,
each with its backlog item: `enableDedicatedDictSearch`,
`prefetchCDictTables` (Z4; the second changes speed only); `nbWorkers`, `jobSize`, `overlapLog`, `rsyncable` (Z9);
`repcodeResolution` (formerly `searchForExternalRepcodes`),
`blockDelimiters`, `validateSequences`, `enableSeqProducerFallback` (they
act on external sequences: Z10); `stableInBuffer` / `stableOutBuffer` (Z1).

## Contexts: reuse and sizing

`Compressor` (one-shot, `ZSTD_compress2` on a `ZSTD_CCtx`), `Stream` and
`FrameWriter` hold a compression context (`frame.Compressor`) that is set
up anew for each frame by `begin`, the port of `ZSTD_resetCCtx_internal`.
Everything the context needs — match tables, tag table, block states, the
pre-splitter's and the optimal parser's scratch, the LDM table and
sequences, sequence and literal buffers, a stream's input and output
buffers — lives in one workspace (libzstd's `ZSTD_cwksp`), tables first.
The port keeps libzstd's policy for it:

- The workspace is kept for the next frame when it is big enough, and
  replaced when it is too small or when three times what a frame needs has
  been free for more than 128 frames in a row
  (`ZSTD_WORKSPACETOOLARGE_FACTOR` / `_MAXDURATION`; "free" counts from the
  previous frame's layout, so the first smaller frame after a bigger one
  does not count).
- Indexing goes on where the last frame ended (`ZSTD_window_clear`: the new
  window starts at the old end, nothing below it is valid) unless the
  context is new, its workspace was replaced, or the index is within 16 MB
  of `ZSTD_CURRENT_MAX` (`ZSTD_indexTooCloseToMax`) — then it restarts at 2
  (`ZSTD_window_init`). The match tables are not cleared when indexing goes
  on: whatever they hold is an index of an older frame, below the window.
  Only table space the last frame's tables did not cover is zeroed
  (libzstd's `tableValidEnd`), and all of it when indexing restarts. The
  row match finder's tag table keeps its contents when it lands where it
  was (libzstd's init-once space), and is zeroed otherwise.
- The row match finder's hash salt advances at every frame that uses it
  (`ZSTD_advanceHashSalt`; the entropy mixed in is never set in libzstd
  1.5.7, so the sequence is fixed). Block states, repeat offsets, the
  optimal parser's statistics and LDM's table and window start fresh.

**The output of a reused context is the output of a fresh one.** This was
measured before building on it (2026-09-24): libzstd 1.5.7 compressing with
one reused `ZSTD_CCtx` and with a fresh one per frame, 1 960 frames —
`ZSTD_compress2` and `ZSTD_compressStream2` (random chunking and flushes),
levels −7…22, sizes 0 to 1.1 MB from a 12 MB mix, half of them with random
explicit window/strategy/search/minimum-match/row/LDM settings, and 600 on
a build that corrects index overflow frequently — gave no difference. A
debug build confirmed the reused frames continued their indexing (37 of 40
in a sample; the rest restarted on a resized workspace). The reasons: the
salt XORs the hash before the shift, a bijection on (row, tag), so it moves
entries without changing which collide; a stale table entry is below the
window and is rejected like an empty one; a row lists its entries newest
first, so stale entries come after every live one. Hence the golden tests
run every frame through one reused context (`golden_test.zig`,
`param_test.zig`, `stream_test.zig`), across levels, sizes and seams, so
they exercise keeping, replacing and relaying out the workspace and both
ways of starting the index — and still must equal libzstd's fresh-context
frames. One byte is left to chance on both sides: the `dfast` extDict read
one byte past the old segment (see *Algorithm*) finds whatever the input
buffer held there, in a reused stream the last frame's input, as in
libzstd while its buffer stays in place.

What reuse saves (instructions under callgrind, ReleaseFast, `smp_allocator`,
the same frames fresh and on one context): 16 % on 1 KB frames and 24 % on
16 KB frames at level 3 — mostly the table clearing a fresh context does
per frame — and under 1 % where compression dominates (16 KB at level 19,
128 KB at level 1). The allocator's system calls are not in those counts.

`Stream` after its end: libzstd resets the session
(`ZSTD_CCtx_reset(ZSTD_reset_session_only)`), so the next call starts a new
frame with the same options and an unknown size; `Stream.reset(opts)`
(`ZSTD_reset_session_and_parameters` plus the new options, pledged size
included) abandons a frame or changes the options.

**Sizes.** `estimateCompressorSize(src_size, opts)` and
`estimateStreamSize(opts)` return exactly the workspace the context
allocates — this port's layout, computed by the same function `begin`
lays the workspace out with, not libzstd's number (which counts its C
structures and packing); `workspaceSize()` reports what a context holds.
A null size, and a stream with neither a pledged size nor a size hint,
give the most any input can need: within each of the level table's size
classes (≤ 16 KB, ≤ 128 KB, ≤ 256 KB) the parameters grow with the size,
so the maximum is at a class bound or at the largest size (an unknown size
for a stream, whose hash log is not capped by the window). A stream with a
pledged size is exact for its first frame (later frames have an unknown
size); with a size hint, for every frame. `initStatic` takes a caller's
workspace (`ZSTD_initStaticCCtx`), aligned to 64 bytes (`Workspace`); it is
never freed or replaced, and a frame that needs more is
`error.OutOfMemory`. For scale (`estimate*`): level 1 one-shot on 64 KB,
0.3 MB; level 3 on 1 MB, 1.3 MB one-shot, 2.6 MB as a stream with that
size pledged, 3.7 MB for an unknown size; level 19 on 1 MB, 18 MB; the
most any input needs at level 22, 740 MB one-shot and 874 MB streaming.

## Dictionaries

Compression with a dictionary is libzstd's (`zstd_compress.c`): a
**raw-content** dictionary is bytes the input is likely to repeat; a
**full** one (RFC 8878, *Dictionary Format*) starts with the magic number
0xEC30A437 and an ID, then a Huffman table, the offset, match-length and
literal-length FSE tables, three repcodes, and its content.
`DictContentType` (`ZSTD_dictContentType_e`) says which: `.auto` goes by
the first four bytes, `.raw_content` takes even a full dictionary as raw
bytes, `.full` refuses anything else (`error.DictionaryWrong`). A
dictionary under 8 bytes is ignored (unless it must be full); an empty
`.raw` or `.prefix` is no dictionary at all, as in libzstd.

**Loading** (`cdict.zig`: `ZSTD_compress_insertDictionary`,
`ZSTD_loadZstdDictionary`, `ZSTD_loadCEntropy`, `ZSTD_loadDictionaryContent`).
The entropy tables become the first block's previous tables, the repcodes
its repcodes. The Huffman table is `valid` (reused without checking, and
for inputs of 6 literals up) only when it gives all 256 bytes a code;
otherwise `check`. An FSE table is `valid` when every symbol up to the
largest code the frame can need has a nonzero probability — for offsets,
the code of the dictionary's content size + 128 KB — else `check`; the
offset table's `valid` is demoted to `check` after the first block (the
content no longer bounds the offsets), the length tables' is kept. A
`valid` table is reused by the `fast`/`dfast` heuristic for fewer than 1000
sequences; `valid` Huffman makes a 3-byte-header literal section single
stream. The optimal parsers seed their first block's statistics from a
`valid` Huffman table and the three FSE tables (`ZSTD_rescaleFreqs`).
A table must satisfy libzstd's checks (table logs 8/9/9, repcodes nonzero
and within the content), else `error.DictionaryCorrupted`.

The content goes into the window as its prefix, and the strategy's tables
are filled from it: `fast`/`dfast` every third position (a `CDict`: all of
them where free, `ZSTD_dtlm_full`), the hash chains every position (hashed
with `minMatch` as it is: 7 as 7, although the search clamps it to 6), the
rows every position (without the hash cache and its skipping), the binary tree (also for `btlazy2`) every position up to its last 8
bytes; for raw content with long-distance matching, the LDM table too
(a full dictionary's content never enters it). A dictionary longer than
the tables can reach, `2^max(hashLog + 3, chainLog + 1)`, loads only its
end into them (the LDM table takes up to `ZSTD_CURRENT_MAX`). The frame's
input then starts a new segment, so the dictionary becomes the window's
extDict and every strategy's extDict match finder searches it — unless
the input follows the dictionary in memory (a `.prefix` right before it),
when the two are one prefix. `loaded_dict_end` (`loadedDictEnd`) marks the
dictionary valid: the whole window may be referenced while any byte of the
dictionary is in it; once the input is a window past its end, or the window
went on in another segment, or indices were corrected for overflow, it is
dropped (`ZSTD_checkDictValidity`, `ZSTD_window_enforceMaxDist`), and index
overflow correction waits until then. `force_max_window` keeps it 0 from
the start (the dictionary counts only within the window);
`deterministic_ref_prefix` makes the input a new segment even when it
follows a prefix in memory, so the output does not depend on where the
buffers lie.

**The dictionary ID** goes into the header in 1, 2 or 4 bytes (up to 255,
65 535, above), unless `dict_id_flag` is false or the dictionary is raw
content. An empty frame's header written by the epilogue carries none,
as libzstd's does.

**`CDict`** (`ZSTD_CDict`) digests a dictionary once: its content (copied),
entropy tables, and its own match tables filled with its own parameters —
`ZSTD_getCParams_internal(level, unknown, dictSize, ZSTD_cpm_createCDict)`,
which takes the input as 513 bytes and the table for 513 + dictSize,
caps a tagged table's logs at 24, and resolves the row match finder. For
`fast` and `dfast` its entries are tagged: the index in the upper 24 bits,
8 more bits of hash below (`ZSTD_SHORT_CACHE_TAG_BITS`), so a dictionary
loads only its last 16 MB. `CDict.init(gpa, dict, level)` is
`ZSTD_createCDict` (remembers its level); `initAdvanced` is
`ZSTD_createCDict_advanced2` with a level and `Advanced` (no level: libzstd's
`ZSTD_NO_CLEVEL`), and takes a size hint.

**Into a context** (`frame.Compressor.beginInternal`,
`ZSTD_compressBegin_internal`). The frame's parameters come from
`ZSTD_getCParamsFromCCtxParams` with the dictionary's size: in
`ZSTD_cpm_noAttachDict` mode the table row is chosen for input +
dictionary (+ 500 bytes when the input size is unknown), the window for
their sum, and the hash and chain logs for a window covering both
(`ZSTD_dictAndWindowLog`); in `ZSTD_cpm_attachDict` mode (below) for the
input alone. A `CDict`'s level, if it has one, replaces the context's. Then:

- **Loaded into the context** (`dtlm_fast`): a `.prefix` (for one frame
  only, raw by default: `ZSTD_CCtx_refPrefix`), `compressUsingDict`
  (`ZSTD_compress_usingDict`: the level, every other parameter default),
  and a `CDict` *with a level* when the input is at least 128 KB and six
  times the dictionary (its content, reloaded with the input's parameters),
  or any `CDict` with `force_attach_dict = .load`. A dictionary over
  `ZSTD_CHUNKSIZE_MAX` restarts indexing.
- **Copied** (`ZSTD_resetCCtx_byCopyingCDict`): the context takes the
  CDict's parameters but for the window log, its tables (untagged: `>> 8`),
  its tag table and hash salt (row), its window, entropy tables and
  repcodes; a hash3 table is zeroed. The switches resolved on the frame's
  own parameters (post-splitter, LDM) stay, as libzstd resolves them before.
- **Attached** (`ZSTD_resetCCtx_byAttachingCDict`) where
  `ZSTD_shouldAttachDict` says: an input of at most 8 KB (`fast`,
  `btultra`, `btultra2`), 16 KB (`dfast`) or 32 KB (the others) by the
  CDict's strategy, or of unknown size, or `force_attach_dict = .attach` —
  never with `.copy`, never with `force_max_window`. Ported for every
  strategy now: `fast`/`dfast` (D1), `greedy`…`btlazy2` (D2, *Attach for
  the lazy family*, below) and `btopt`/`btultra`/`btultra2` (D3, below) --
  the gate, `match.hasDictMatchStateVariant`, is exhaustively `true`, so
  `error.DictAttachUnsupported` (refusing before anything is written,
  rather than copying, which would change the bytes) no longer has a
  strategy left to name.

`Options.dictionary` / `StreamOptions.dictionary` mirror libzstd's calls on
a context before `ZSTD_compress2` / `ZSTD_compressStream2`: `.raw` is
`ZSTD_CCtx_loadDictionary_advanced` — a `CDict` made by the context with
the frame's parameters (by reference; no level of its own, so copied or
attached, never reloaded), for one call (`Compressor.compress`) or for
every frame until `reset` (`Stream`); `.cdict` is `ZSTD_CCtx_refCDict`;
`.prefix` is `ZSTD_CCtx_refPrefix_advanced`. `compressUsingCDict` is
`ZSTD_compress_usingCDict_advanced`: the CDict's parameters (for inputs up
to 128 KB or six times the dictionary, or a CDict without a level) with
the window widened to the input up to 512 KB — the switches resolved
before that — else the level's for the input and the dictionary, loaded
anew. Error classes: a corrupt dictionary is `DictionaryCorrupted` /
`DictionaryWrong` on every path, where libzstd's `ZSTD_compress2` with
`ZSTD_CCtx_loadDictionary` reports `memory_allocation` (its internal CDict
creation fails and it cannot tell why).

**Reuse.** libzstd 1.5.7 gives a reused context the bytes of a fresh one
with dictionaries too (1 500 frames, every way of using a dictionary,
attach included, levels −3…22, measured 2026-09-24 with a probe like
`tools/zreuse.c`): the dictionary is loaded above the last frame's
indices, and the copy replaces the window and tables outright. The
dictionary goldens run through one context and one stream.

**Not expressible here:** `ZSTD_c_srcSizeHint` set on a context for
`ZSTD_compress2` with `ZSTD_CCtx_loadDictionary` sizes that call's internal
CDict; `Options` has no size hint (`StreamOptions` does, and `CDict.
initAdvanced` takes one). `estimateCompressorSize` / `estimateStreamSize`
leave dictionaries out (a copied CDict brings its own table sizes; a
`.raw` dictionary allocates a CDict per call or per stream; a static
context cannot make one: `error.OutOfMemory`). libzstd reads the FSE
entries past a dictionary table's last symbol when seeding the optimal
parser — memory it never initialised; this port zeroes them (a
difference only for a dictionary with a valid Huffman table but length
tables that stop short of the largest code, which no trainer makes).

**Adding an attach (`dictMatchState`) variant** (D1–D3). The seam is
`MatchState.dict_match_state`: the attached CDict's `ms` (its window —
content from index 2 up to its end, `dict_limit`, `low_limit` — its
`cp`, its tables, tagged for `fast`/`dfast`, and `hash_salt` 0). The
context's window starts at the CDict's end (`src_base` = its end index),
so a dictionary index maps into the context's space by libzstd's
`dictIndexDelta` (the context's low limit less the CDict's end), and `loaded_dict_end` = the context's
`dict_limit`. To port one: write the variant in the strategy's file
(`zstd_fast.c` → `match.zig`, `zstd_double_fast.c` → `match.zig`,
`zstd_lazy.c` → `lazy.zig`, `zstd_opt.c` → `opt.zig`) from libzstd's
`*_dictMatchState*` functions; dispatch to it where `ms.dict_match_state
!= null` and `!ms.hasExtDict()` (`match.compressBlock` dispatches
`fast`/`dfast` there since D1; `lazy.compressBlock` and `opt.compressBlock`
choose their own variants); flip the strategy in
`match.hasDictMatchStateVariant`, which lifts the refusal in
`frame.Compressor.resetByAttachingCDict`; then the goldens: small inputs
(≤ 8/16/32 KB) and unknown-size streams with `.cdict` and `.raw`
dictionaries, which `dict_test.zig`'s "refused" test lists today, into
`corpus.dict_cases` (D1: a separate `corpus.dict_cases_attach_fast`, so
siblings' own cases merge without conflict), and `tools/gen-goldens.sh`
(`dump_corpus.zig` reads both arrays). Checked against libzstd the same
way (`zref.c` / `zstream.c` take every dictionary path already). The
attach reset (`resetByAttachingCDict`) is ported and exercised by D1's
and D2's goldens (window move-up via `ZSTD_window_clear`'s semantics,
`loadedDictEnd`, `ZSTD_adjustCParams_internal(cdict cParams, …,
ZSTD_cpm_attachDict)`) — D1 read it line by line against
`ZSTD_resetCCtx_byAttachingCDict` and found no bug there by *reading*
(not mutation-backed: D1's sweep targeted the new match finders, not
this function specifically); D2 exercised it as it stands.

**Attach for the lazy family** (D2, 2026-09-24; `lazy.zig`). Every
function of the lazy finders takes libzstd's dictionary mode at compile
time (`DictMode`: `no_dict`, `ext_dict`, `dict_match_state`), as libzstd's
templates do, so the no-dictionary path compiles to what it was (same
`instructions:u`). `lazy.compressBlock` picks the mode as
`ZSTD_matchState_dictMode` does: extDict first, then an attached CDict.
With one, the parser (`ZSTD_compressBlock_lazy_generic`, dictMatchState)
never drops a repcode at the block start; it tests repcodes at every
depth against the CDict below the prefix (not straddling its end, the
count running on into the prefix), catches a match up within the CDict
or the prefix, never across, and its immediate-repcode loop tests
`offset_2` without the zero check. Each finder, having spent its attempts
in the window, spends what is left in the CDict: the hash chain on the
CDict's own chain (its hash and chain logs, the search's clamped
`minMatch`), the row finder on the CDict's row (hashed with the CDict's
row hash log and no salt — a CDict never salts — but the context's row
log, prefetched before the window's update), `btlazy2` on the CDict's
binary tree (sorted in full when the CDict was made, read only:
`ZSTD_DUBT_findBetterDictMatch`, whose offset price reads `offBase + 1`
where the window's reads `offBase`), unless a window match reached the
input's end. A dictionary match's index moves into the context's space by
`dictIndexDelta` (the context's `dictLimit` — `lowLimit` in the tree —
less the CDict's end).

Row or hash chain: the context takes the CDict's choice
(`params.useRowMatchFinder = cdict->useRowMatchFinder`), resolved when the
CDict was made on its own parameters (`ZSTD_createCDict_advanced2`: for
`auto`, rows when its window is over 16 KB — a CDict for a 4 KB
dictionary gets hash chains, one for 30 KB rows — whatever the frame's
own parameters would choose). The frame's own resolution only caps the
context's hash log in `ZSTD_adjustCParams_internal`. Both tables then
have the same kind, so the dictMatchState search reads the CDict's tables
of the kind the context searches its own.
D1's `fast`/`dfast` variants (`fastDictMatchStateBlock`,
`dfastDictMatchStateBlock` in `match.zig`) port libzstd's
`ZSTD_compressBlock_fast_dictMatchState_generic` /
`..._doubleFast_dictMatchState_generic` literally, including a quirk
worth flagging for D2/D3: unlike the noDict/extDict variants, libzstd's
own dictMatchState repcode checks do **not** guard against a zero
(invalidated) `rep_offset1`/`rep_offset2` -- the comment in
`zstd_fast.c` notes this is intentional (dictMatchState inputs are
assumed to start with valid reps). The two new match finders share a
`countAcrossDict` helper (`match.zig`) -- `ZSTD_count_2segments` where
the match side is a different `MatchState` (the attached CDict's own,
not `ms.dict`) rather than a second segment of the same one.

**D1 mutation sweep** (33 mutants over `countAcrossDict`,
`comparePackedTags`, `fastDictMatchStateBlock`, `dfastDictMatchStateBlock`;
`-Dtest-filter=dict`, `dict_test.zig`'s 33 dictionary tests only -- a
narrower binary than the full suite, valid for finding whether a mutation
is caught at all, not as evidence about the rest of the module):
**19 killed, 14 survived**, all early-return/early-exit boundary checks
that only misfire when a match starts or ends at *exactly* an index
(`dict_start_index`, `prefix_start_index`/`prefix_lowest_index`, or the
CDict's own end) -- the same shape as the equality-boundary survivors
already open elsewhere in this file (`opt`/splitter, LDM, decoder); no
golden here happens to land a match on the boundary byte. Listed for a
future hunt (SPEC backlog, not blocking): `countAcrossDict`'s `p_match >
m_end` / `v_end > p_in` / the `orelse len` fallback / the `i_start,i_end`
argument order in its continuation call; the `>` vs `>=` reads against
`prefix_start_index`/`dict_start_index` in both new match finders'
prefix-vs-dict preference and backward catch-up bounds (11 sites, see
`match.zig`'s `fastDictMatchStateBlock`/`dfastDictMatchStateBlock`).
One mutation (removing `countAcrossDict`'s fallthrough for a dict match
that ends exactly at the CDict's edge) exposed a **real bug** the sweep
caught before it shipped: the first port of `countAcrossDict` returned 0
early whenever the dict-side runway was exactly exhausted
(`p_match == m_end` / `v_end == p_in`), instead of falling through to
`ZSTD_count_2segments`'s continuation into the prefix, as the existing
`Base.count2Segments` already does correctly for the extDict case. Fixed
to mirror `Base.count2Segments`'s shape exactly. No committed golden
currently exercises this exact boundary (fixing it left all 33 dict
tests unchanged), which is why the boundary mutants above still survive
after the fix -- flagged, not hidden, in the list above.

**The optimal parsers attached (D3).** `btopt`, `btultra` and `btultra2`
search an attached CDict (`zstd_opt.c` with `dictMode ==
ZSTD_dictMatchState`: `opt.DictMode.dict_match_state`, a compile-time
mode, so the no-dictionary and extDict loops are unchanged). A repcode may
point into the CDict's content, not across the prefix start
(`ZSTD_index_overlap_check`). Once the context's own tree has been walked,
what is left of the `searchLog` budget walks the CDict's binary tree —
read only, hashed with the CDict's hash log and the context's `minMatch`,
masked by the CDict's chain log, stopped at its `btLow` — and a match may
run past the CDict's end into the prefix (`ZSTD_count_2segments`). A
match that ends the context's walk (longer than `ZSTD_OPT_NUM`, or up to
the block's end) skips the CDict's. The 3-byte hash of `minMatch` 3 is
searched in the context only (a CDict has none). Attached, `btultra2` runs
`btultra`, as libzstd has no btultra2 variant for dictMatchState: no first
statistics pass (`ZSTD_initStats_ultra`), whose "no dictionary" test would
otherwise pass — an attached window is one segment. The first block's
statistics come from the CDict's entropy tables as with a copied one
(`ZSTD_rescaleFreqs`). Long-distance matching runs over the input as
without a dictionary: a CDict has no LDM table (libzstd gives its
`ZSTD_loadDictionaryContent` no LDM state), so an attached dictionary
never enters it, while a loaded one does (above).

## Decoder

A port of libzstd's decoder (`lib/decompress/*`, `lib/common/entropy_common.c`,
`fse_decompress.c` and the reader half of `bitstream.h`): frame header, raw,
RLE and compressed blocks, Huffman literals (single- and double-symbol
tables, one and four streams, the choice between them by
`HUF_selectDecoder`), FSE sequence tables (predefined, RLE, compressed,
repeat), repeat offsets, content checksum, concatenated and skippable
frames, and the frame queries (`getFrameHeader`, `getFrameContentSize`,
`findFrameCompressedSize`, `findDecompressedSize`, `decompressBound`,
`decompressionMargin`, `readSkippableFrame`, `getDictIdFromFrame`), and
magicless frames (`DecompressOptions.format`, `ZSTD_d_format`: the header
starts at the descriptor byte, and no frame is taken for a skippable one;
`getFrameHeaderAdvanced` reads such a header). Errors
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

**Dictionaries** (`ddict.zig`, port of `zstd_ddict.c` and
`ZSTD_loadDEntropy`/`ZSTD_getDictID_from*` from `zstd_decompress.c`).
`DDict.init`/`initByReference` load a dictionary by copy or by reference
(`ZSTD_createDDict_advanced`'s two `ZSTD_dictLoadMethod_e`); `DictContentType`
is `ZSTD_dictContentType_e` (`.auto`/`.raw_content`/`.full`). For a
zstd-format dictionary (starts with the magic number `0xEC30A437`,
`ZSTD_MAGIC_DICTIONARY`) `loadDEntropy` reads the Huffman table (X2, as
libzstd's default non-`HUF_FORCE_DECOMPRESS_X1` build), the three FSE tables
and three repeat offsets once, validating each repeat offset against the
content size that follows (`rep == 0 or rep > content_size` is
`error.DictionaryCorrupted`); `.raw_content` skips all of that, `.full`
requires it (`error.DictionaryCorrupted` otherwise), `.auto` falls back to
raw content when the magic number is absent or the buffer is under 8 bytes.

**A dictionary's content becomes history the same way this port's history
already works: as an address range `checkContinuity` can compare against a
real write.** libzstd does this too (`ZSTD_copyDDictParameters` sets
`prefixStart`/`previousDstEnd` from `ddict->dictContent`/`dictSize`), which
this port mirrors exactly (`Decompressor.setHistoryFrom`) rather than
threading a separate "external content" value through the history model.
One genuine libzstd asymmetry, kept: a digested `DDict`
(`Options.ddict`/`.ddicts`, `ZSTD_decompress_usingDDict`) makes its **whole**
buffer reachable as history, header and entropy tables included, even
though those bytes are never themselves valid output; the undigested
one-shot path (`Options.dictionary`, the legacy `ZSTD_decompress_usingDict`)
**strips** the entropy header first (`ZSTD_decompress_insertDictionary`) —
only the content after it is history. Both are anchored independently
(`tools/zdec.c`'s `legacy:` vs `auto:`/`raw:`/`full:` dict-specs). A
streaming `DecompressStream`/`Reader`'s `Options.dictionary` always goes
through the digested (unstripped) path, since that is what
`ZSTD_DCtx_loadDictionary` itself does internally — only the one-shot
`Decompressor`'s raw-bytes option is stripped. `Options.prefix`
(`ZSTD_DCtx_refPrefix`) is forced raw content (a zstd-format dictionary's
magic number is never looked for) and applies to exactly one frame,
including when that frame turns out to be skippable: libzstd evaluates
`ZSTD_getDDict` — which flips `dictUses` from "once" to "don't use" —
*before* checking whether the frame is skippable, so a skippable frame
between the prefix and the next real frame consumes it too, without the
prefix ever reaching a decode; this port matches (the skippable-frame
branch in `dstream.zig`'s header-consume step clears `prefix_once` too).

`Options.ddicts` (`ZSTD_d_refMultipleDDicts`) picks a dictionary by the
frame's dictionary ID from a caller-given list, falling back to
`Options.ddict`; the selection itself is a linear scan (last match wins on
a duplicate ID) rather than a port of libzstd's open-addressing hash set,
since only which `DDict` is picked is observable, not how. **Streaming**
selects fresh for every frame, matching libzstd's own early
`ZSTD_DCtx_selectFrameDDict` call inside `ZSTD_decompressStream`.
**One-shot is different, and was verified empirically, not just read from
the source**: `ZSTD_decompress_usingDDict`/`ZSTD_decompressDCtx` resolve
ONE dictionary — `ZSTD_getDDict(dctx)`, "whichever `ZSTD_DCtx_refDDict`
call was last" — *before* the frame loop starts, and apply its content and
entropy to *every* frame in that one call; `ZSTD_d_refMultipleDDicts` only
re-validates each frame's dictID against the right `DDict`
(`ZSTD_DCtx_selectFrameDDict`, called from inside `ZSTD_decodeFrameHeader`,
*after* that frame's content/entropy were already applied from the fixed
one) — it does not re-apply. Five adversarial cases were built by hand
(two same-size, differently-trained dictionaries; frames whose matches
depend on their own dictionary's vocabulary; both `refDDict` orders; both
frame orders) and run through `tools/zdec.c`: every combination that
*would* need the "wrong" fixed dictionary's content refused cleanly with
`error.CorruptionDetected` — never silently wrong output — and every
combination that happened not to need it decoded correctly. Since libzstd
never produced demonstrably wrong output (only a clean refusal, which is a
false negative on valid input, not corruption), this port matches
exactly (`Decompressor.decompress`'s doc comment) rather than keeping the
"more correct" fresh-per-frame selection an earlier version of this work
had: `Options.ddict` if set, else `Options.ddicts`'s *last* entry (mirrors
"last ref'd"), fixed for the whole one-shot call; the KATs this produced
(`frame2b_full_l3` etc.) are in `testdata/dict_kats.zig`.

**One divergence this work makes reachable for the first time, not new:**
already documented above, libzstd switches between a "short" and a
"prefetching" sequence decoder per block (`usePrefetchDecoder`), defaulting
to the prefetching one whenever `dctx->ddictIsCold` — true essentially every
time a dictionary decode begins, since it means "this dctx has not already
been decoding with this exact dictionary". Only the short decoder is
ported. On a corrupted sequences section the two can disagree on which
check trips first — confirmed empirically here (`ERR 20`
`corruption_detected` from libzstd vs `error.DstSizeTooSmall` from this
port, both refusing the frame) — exactly the already-declared "on corrupt
input either can change only the reported error" simplification above,
observed in practice once decoding actually exercises a "cold" dictionary
path (13/4000 random single-byte-flip corruptions of dictionary-compressed
frames in a throwaway differential run hit this; every other corrupted
input and every valid one, output and error class alike, matched).

Speed: 1.04–1.05× libzstd's decode time on 200 MB of system binaries
compressed at levels 3 and 19 (decode only, best of 5, ReleaseFast). std's
decoder takes 30× libzstd's time on the same frames, which is why this is a
port and not an extension of it. Dictionary decoding was not separately
measured (no compressor support yet to produce a realistic corpus, Z4).

`Decompressor` holds the tables and a 128 KB literal buffer (≈ 190 KB) on
the heap; `decompress` allocates one per call. A `DDict` adds its content
buffer (by copy or by reference) and, when a zstd-format dictionary's
entropy is present, the same three FSE tables and one Huffman table
`Decompressor` itself holds (a few KB).

## Dictionary training (content selection)

`dict_builder.zig` ports libzstd's `cover.c` and `fastcover.c` up to, not
including, `ZDICT_finalizeDictionary`: the dictionary content -- sample
segments -- the trainers place at the end of the dictionary buffer, byte for
byte (`trainCoverInto` / `trainFastCoverInto` leave it at the same place,
`dict[len - n ..]`; `trainCover` / `trainFastCover` return a copy).

- **cover** (`COVER_ctx_init`): every training position with `max(d, 8)`
  bytes left (`suffixSize`) is sorted by its first d bytes -- for d ≤ 8 as
  a masked little-endian `u64` (`COVER_cmp8`), not lexicographically;
  above 8 with `memcmp` -- ties by position. libzstd sorts with `qsort_r`
  and a comparator that breaks ties by the element's *address*; glibc's
  `qsort_r` is a merge sort, which keeps the initial ascending positions,
  so the order is the total order (d-mer, position) and any sort gives it
  (here `std.sort.pdq`, in place). Each group of equal d-mers
  (`COVER_group`) records its id (its first index in the sorted array) for
  every position and counts the samples it occurs in -- once per sample,
  found by `COVER_lower_bound` over the sample offsets. The quirk is ported:
  a d-mer at the exact start of a sample and again later in it counts twice
  (the bound finds that sample's start, not its end). The count overwrites
  the group's first slot, so the suffix array becomes the frequency table.
  `COVER_selectSegment` slides a window of k - d + 1 d-mers through each
  epoch, scoring distinct d-mers with an open-addressing map of
  2^(highbit(k-d+1)+2) pairs (`COVER_map_t`, backward-shift deletion),
  keeps the first best (`>`), trims zero-frequency d-mers from both ends and
  zeroes the chosen d-mers' frequencies.
- **fastCover**: d-mers are hashed to f bits (`ZSTD_hash6Ptr` for d = 6,
  else `ZSTD_hash8Ptr`, both reading 8 bytes); frequencies count every
  (skip+1)-th d-mer lying wholly inside a training sample (`accel` table);
  the segment's distinct hashes are tracked in 2^f 16-bit counters (wrapping
  as libzstd's `U16`), no trimming.
- **Epochs** (`COVER_computeEpochs`): capacity / k / passes epochs (cover 4
  passes, fastCover 1), at least 10·k d-mers each; one segment per epoch
  in turn, filled from the back, until the buffer is full, a segment is
  shorter than d, or 10 (cover: 10..100 by epoch count) epochs in a row
  score nothing. Segments run across sample boundaries, as in libzstd.
- **Checks, in libzstd's order**: parameters (`COVER_checkParameters` /
  `FASTCOVER_checkParameters`), no samples, capacity below 256, then the
  context's (total below `max(d, 8)` or at 2^32 − 1 and up, fewer than 5 training
  samples, no testing sample). f and accel of 0 take 20 and 1; k and d have
  no defaults (`ZDICT_trainFromBuffer_*` has none).
- **Optimizer** (`optimizeCover` / `optimizeFastCover`): the defaults and
  checks of `ZDICT_optimizeTrainFromBuffer_*`, the (d, k) grid (d 6..8 by 2,
  k 50..2000 in `steps` steps), one context per d on the training share
  (split point: cover 1.0, fastCover 0.75), each k built on a copy of the
  frequencies, candidates whose parameters fail the check skipped. The score
  -- `COVER_selectDict`: finalize, compress the testing samples with the
  dictionary, optionally shrink -- is the caller's `scorer.select`, which
  gets the content and what `COVER_selectDict` takes (`nb_finalize_samples`
  from the accel table, the offsets). The first strictly smallest total
  wins (`COVER_best_finish` in submission order: single-threaded; libzstd's
  pool would break ties by completion order).
- **For finalization (Z5b)**: `ZDICT_finalizeDictionary` keeps the content's
  *head* when header + content exceed the capacity (`memmove` of the first
  `capacity - hSize` bytes), dropping the best segments at the tail -- a
  libzstd quirk the port must reproduce, and why `tools/ztrain.c` reads the
  content before finalization rather than out of a finished dictionary.

**Memory.** Besides the dictionary buffer, cover allocates the offsets
((n + 1) · 8), the suffix array and the d-mer map (2 · 4 · `suffixSize`,
i.e. 8 bytes per sample byte) and the active-d-mer map (8 · 2^(highbit(k -
d + 1) + 2)); fastCover the offsets, 2^f `u32` frequencies and 2^f `u16`
counters (6 MiB at f = 20, 12 GiB at f = 31). `estimateCoverMemory` /
`estimateFastCoverMemory` are exactly those bytes (a test counts the
allocations), and every trainer compares them with `memory_limit` (default
256 MiB: cover over ~30 MB of samples, fastCover up to f = 25) before its
first allocation. libzstd has no ceiling; its CLI loads samples up to its
own memory estimate.

**Anchoring.** `dict_golden_test.zig`: 54 runs over 13 generated sample
sets (`testdata/dict_samples.zig`; four built so that text first reaches
the epoch the empty-epoch stop lets run, or the first it does not, or sits
between runs of empty epochs), each content's length and SHA-256 equal to
what libzstd's trainer left in the buffer before finalization, or the same
refusal (`tools/ztrain.c` calls the trainers' internal steps; its content
was checked against the public trainers' finalized output, whose kept head
it matches). A one-off diff over 2 450 random sample sets and parameters
(up to ~10 MB of samples; either trainer, d 0–40, f 1–24 and out of range,
accel 0–12, split points 0.3–1, capacities 200–131 072) gave the same
content or refusal on all but two, both refusals where libzstd fails
`malloc` on its underflowed `suffixSize` (deliberate difference 1 below).
Mutation sweep of `dict_builder.zig`: 92 mutants, 84 killed (after adding
the island sets and unit tests for 12), 8 equivalent: `e.size >=` vs `>`
in `computeEpochs` (at equality both branches give the same epochs); the
total's `max(d, 8)` vs `max(d, 7)` (the training-share check refuses the
same inputs); `split_point < 1.0` vs `<=` for the training count (n · 1.0 =
n); removing an absent key from the map (a backward shift into an empty
slot keeps every chain; the trainers never remove an absent key); the
`d ≤ 8` compare taken as `memcmp` for d = 8, and each frequency counted
twice (d-mer ids are relabelled and scores scaled; neither changes a
choice); the lower-bound search skipped for a group's last position (it
only sets state no later position reads).

**Deliberate differences.** (1) A training share shorter than one d-mer
(only with a split point below 1) is `SrcSizeWrong`; libzstd computes
`suffixSize` negative there and fails the huge `malloc`
(`memory_allocation`) -- or, when the multiplication wraps, writes past a
small buffer. (2) Sizes summing past the buffer are `SrcSizeWrong` (libzstd
cannot see the buffer's length). (3) The context API checks its split point
(libzstd's callers do). (4) An active-d-mer map past 2^31 slots (k - d + 1 ≥
2^30) is `ParameterOutOfBound`; libzstd's `(U32)1 << 32` is undefined there.
(5) The optimizer's loops count in 64 bits (libzstd's wrap at d or k near
2^32 and never end). (6) Warnings are not printed: `smallCorpus` gives
`COVER_warnOnSmallCorpus`'s verdict.

## Limits and refusals

| limit | value | source |
|---|---|---|
| level | `min_level` (-131072) … 22; lower is clamped, higher is `error.LevelUnsupported` | `ZSTD_minCLevel()` / `ZSTD_maxCLevel()`; libzstd clamps above 22 too, which would hand a caller a level it did not ask for |
| memory | level 22 above 64 MB: 512 MiB binary tree + 128 MiB hash + 64 MiB LDM table + 32 KiB bucket offsets (≈ 820 MB peak on a 70 MB input, as libzstd) | the level's own table sizes; nothing is capped, as libzstd caps nothing |
| input | none (the input and `compressBound` of it in memory) | past `ZSTD_CURRENT_MAX` (3500 MiB on 64-bit) the indices are rescaled, as libzstd does (see *Algorithm*) |
| destination | ≥ `compressBound(src.len)` or `error.NoSpaceLeft` | the reference's decisions assume the one-shot bound; accepting less would let capacity change the output |
| block | 128 KB | format |
| stream level | as one-shot (`stream_max_level` = `max_level`) | level 22 without a pledged size uses a 128 MB window and long-distance matching (window log 27, as libzstd), ≈ 1 GB |
| advanced parameters | libzstd's bounds (see *Advanced parameters*), else `error.ParameterOutOfBound` | `ZSTD_cParam_getBounds`, 64-bit |
| stream size | a pledged size must be met exactly, else `error.SrcSizeWrong` (more input at the chunk that passes it, less at the end) | `srcSize_wrong` |
| stream memory | one window plus one block of input buffer, `compressBound(block) + 1` of output buffer, and the level's tables | `ZSTD_resetCCtx_internal` |
| context memory | one workspace, exactly `estimateCompressorSize` / `estimateStreamSize`; a static one is never exceeded (`error.OutOfMemory`) | `ZSTD_estimateCCtxSize*`, `ZSTD_initStaticCCtx` |
| decode window | one-shot: none, the whole output is history (window log ≤ 31 in the header, else `error.FrameParameterWindowTooLarge`); streaming: `window_log_max`, default 2^27 + 1 bytes, else `error.FrameParameterWindowTooLarge` | `ZSTD_WINDOWLOG_MAX` (64-bit); `ZSTD_d_windowLogMax` and its default `ZSTD_WINDOWLOG_LIMIT_DEFAULT` |
| decode stream memory | input buffer of one block, output ring of one window + two blocks + 64 bytes (none with `stable_output`), plus the ≈ 190 KB context | `ZSTD_decodingBufferSize_min` |
| decode destination | the whole output; too small is `error.DstSizeTooSmall`. `decompressAlloc` sizes from the headers, else `decompressBound`, never above its `max_size` | `ZSTD_decompress` |
| training memory | `estimateCoverMemory` / `estimateFastCoverMemory` ≤ `memory_limit` (default 256 MiB), else `error.MemoryLimitExceeded` before any allocation | libzstd has none (cover ≈ 8 B per sample byte, fastCover 6 · 2^f B) |
| training samples | total below 4 GiB and at least `max(d, 8)` bytes, ≥ 5 training samples, sizes within the buffer, else `error.SrcSizeWrong` | `COVER_MAX_SAMPLES_SIZE`, `COVER_ctx_init` |
| decode block | streaming: decoded size ≤ `Block_Maximum_Size`; one-shot: as libzstd, only a compressed block's output is bounded (see *Decoder*) | RFC 8878; `ZSTD_decompressContinue` / `ZSTD_decompressFrame` |

`golden_test.zig` pins all of the above through the output; `root.zig` tests
pin the level refusal and the destination bound, `stream_test.zig` the
stream's level refusal, the pledged size both ways and the frame after the
end, `context_test.zig` the estimates and a static workspace's bound.
`FrameWriter` takes a nonempty buffer and holds `compressBound(buffer.len)`
of scratch and its context's workspace for its life.

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
| hash salt → 0 | equivalent: the salt XORs every hash before the shift, a bijection on (row, tag) that leaves every collision in place — on a reused context too (see *Contexts*) |
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
switched on by hand (then a test seam, since Z7 `Advanced.long_distance_matching`;
libzstd's `ZSTD_c_enableLongDistanceMatching`), because it switches itself on only
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

Long-distance matching as an option (Z7, 2026-09-24) got 38 mutations of
the LDM path below `btopt` (`ldm.blockCompress` and its helpers, the table
fills in `match.zig`, the saturated limits), the parameter derivation, the
bounds and the switch. 19 were caught by the cases first written for it, 6
by 2 cases a search over corpus inputs, LDM parameters and schedules found
(original against mutant), and 2 — `fast`/`dfast` on a stretch ending below
index 8, where libzstd's `iend - 8` goes below zero — by a test on a fresh
context (the golden tests reuse one, so their frames never start at index
2). 11 survive:

| mutation | why no case exists |
|---|---|
| `maybeSplitSequence` and `ZSTD_ldm_skipSequences`: every comparison at its equality, the cut match's `minMatch` test, the carry of a too-short match into the next sequence's literals, the skip dropped (8) | unreachable from LDM: its sequences are generated per block, counted only up to the block's end, and the store is discarded with the block, so no sequence runs past the end and the loop leaves when the store is empty. A panic on that path did not fire in 4 128 hunted inputs and schedules. They wait for external sequences (Z10) |
| the loop's `ip < iend` dropped; `rep[2]` not pushed down after an LDM sequence; the hash rate derived from the hash log also at equality (`>` → `>=`) | equivalent: the store empties exactly at the block's end; below `btopt` no match finder reads the third repcode (the optimal parsers and the post-splitter, which do, take LDM matches as candidates instead); at equality the rate is 0 either way |

Superblocks (Z8, 2026-09-24): 5 200 random one-shot and streamed inputs
(corpus and generated, levels −20…22, random `targetCBlockSize` and other
parameters) identical to libzstd the first time. 43 mutations of
`superblock.zig` and the frame's `targetCBlockSize` path: 14 caught by the
first 9 parameter and 2 stream cases, 10 by 10 cases the seed search found
(corpus inputs × parameters × schedules, original against mutant; the later
`targetCBlockSize` entries of `corpus.zig`), and 19 survive:

| mutation | why no case exists |
|---|---|
| the target raised to 1340 in `compressMulti` or in the frame (either dropped) | equivalent: libzstd raises it twice, at `ZSTD_CCtx_setParameter` and in `ZSTD_compressSubBlock_multi`; either one suffices |
| "sequence tables never written" returning 0 (dropped, or `set_rle` left out) | equivalent: the tables stay unwritten only when no sub-block with sequences came out smaller, so nothing was emitted but a raw block of the whole input, which the frame's size check replaces with the same raw block |
| the predefined offset table's `max <= 28` at equality | unreachable: offset code 28 needs an offset of 2^28, a window past 256 MB |
| literal header sizes at exactly 16 KB − 200 literals and at compressed sizes of exactly 1 KB / 16 KB; the sequence section under 4 bytes (dropped, or at 3) and the zstd ≤ 1.3.4 table workaround at 3; the sub-block budget at equality (`>` → `>=`, `<` → `<=`); no literals at all (average cost 0); the estimate exactly the block's size; the Huffman table not restored when no sub-block wrote it; the repeat-offset fix's "no literals" flag; the empty-block statistics not resetting the literal-length table; an RLE block of exactly 4 sequences | reachable in principle; two rounds of seed search (2 900 corpus and generated inputs × random targets from 1340, block sizes down to 1 KB, windows down to 1 KB, every level) did not hit one. **Uncovered.** |

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
stream_goldens.zig` holds, for each of 62 `corpus.stream_cases` (a corpus
input and a call schedule) × its levels (-5, -1 and 1–3 for 31 cases, 4–10
for 7, 11–22 for 6, one level each for the 10 found by search, and the 8
with advanced parameters, 2026-09-24) × checksum,
the length and SHA-256 of everything `ZSTD_compressStream2` emits (534
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
time each ran. The strategy is now forced through `Advanced.strategy`
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

**Advanced parameters** (2026-09-24) have their own goldens:
`src/testdata/param_goldens.zig` holds, for each of 37 `corpus.param_cases`
(a corpus input, a `name=value` list of libzstd parameters, levels), the
length and SHA-256 of the frame `ZSTD_compress2` emits with the same
parameters set (67 frames, through `tools/zref.c`'s last argument); 8
stream cases carry parameters as schedule tokens (64 streams). Before the
cases were chosen, random parameter sets — every field of `Advanced` with
probability 0.15–0.4, over the whole corpus at levels -10…22 — were run
against `zref`: of the first 300 one-shot frames 2 differed (the
post-splitter's estimate priced literals as compressed when literal
compression was off; fixed), then 3 300 one-shot frames and 1 550 streams
(the same sets plus a size hint, pledges, window logs 10–18, chunks,
flushes and small outputs, against `zstream`) were all identical. 47
mutations of the new code (bounds, the override, the three resolvers, the
row cap, the header, the block size, both splitters, the optimal parsers'
raw literal price, the size hint, the decoder's format checks, the API
plumbing): 43 caught, 4 of them once rewritten to compile, 4 only after a
hand-built magicless frame whose first four bytes read like a skippable
magic number was added. 4 survive, all equivalent: the optimal parsers'
literal statistics gathered or scaled while literal compression is off
(3 — nothing reads them then, the price is a flat 8 bits), and the
streaming decoder's single-pass shortcut sizing a magicless frame as a
zstd1 one (it then finds no frame and decodes through the stream path, to
the same bytes).

**Context reuse** (2026-09-24) has no goldens of its own: libzstd gives a
reused context the bytes of a fresh one (measured, see *Contexts*), so the
golden, parameter and stream goldens all run through one reused context
each, and `context_test.zig` checks the policy and the sizes. 12 mutations
of the new code: 7 caught — the table space a larger layout newly covers
left uncleared, or kept as clean across an index restart (both crash on
garbage indices), indexing never restarting near its limit, the oversized
workspace never replaced or replaced one frame early, a stream keeping its
pledged size into the next frame, and the estimate for an unknown size
ignoring the size classes (caught only once level 11 with tiny explicit
tables was added: its 16 KB class runs `btopt`, whose parser scratch
outweighs everything a larger input needs). 5 survive, all equivalent:
the cleared window's `lowLimit` and `nextToUpdate` (the continuing window
has an empty prefix, so its first update takes the non-contiguous path,
which sets both again), the tag table never cleared and the hash salt not
advanced (see *Contexts*: stale tags come after every live entry, and the
salt permutes rows and tags), and the stream's output buffer one byte
short of libzstd's `compressBound(block) + 1` (the bound leaves 512 bytes
over a block and its header, so the room never decides).

**Dictionaries** (D0, 2026-09-24) have their own goldens:
`src/testdata/cdict_goldens.zig`, 326 frames and streams over 74
`corpus.dict_cases` (every level −5…22 on the copy, load, prefix,
`compressUsingDict` and reload paths; content types; IDs of 0–4 bytes;
the attach preferences; windows across a dictionary; frequent overflow
correction; long dictionaries; streams), through `tools/zref.c` /
`zstream.c`, which decode each frame back with the dictionary. Before the
cases: 2 700 random one-shot and 1 900 random streamed frames (inputs up
to 700 KB, raw and trained dictionaries of 0 bytes to 64 KB and a 17.5 MB
one, every path, random advanced parameters) identical to libzstd, 600
more against the frequent-correction build; edge dictionaries (empty,
under 8 bytes, truncated, flipped bytes) fail on both sides. A 112-mutation
sweep of the new code: 89 caught (37 only after the cases and unit tests
it asked for, 2 of them inputs found by seed search), 11 equivalent (the
no-magic branch's `auto` test after `raw_content` was handled; a full
dictionary with no content, whose repcodes fail anyway; an 8-byte content,
which fills no position; clearing the tag table, whose stale entries sort
after live ones; `loadedDictEnd` resets that `ZSTD_checkDictValidity`
already makes; the optimal parser's price type for inputs of 8 bytes, which
search nothing; a zero `valPerRank` slot already zero; the copy's row
switch, `nextToUpdate` and `lowLimit`, all set again by the first window
update), 5 unreachable today (the CDict tags, read only by the attach
variants; a Huffman or FSE cost of 0 bits under a table the trainer
makes; the epilogue's empty-frame header, which no API path reaches; a
dictionary over 596 MB), and 7 uncovered: the table-reach trim by the
chain log, LDM entries from a raw dictionary (the one case's dictionary
equals its input, so the normal finder finds the same matches — D3, LDM
with a dictionary, owns it), `ZSTD_getLowestPrefixIndex` with an adjacent
prefix larger than the window within one small block, the post-splitter's
6-literal threshold under a dictionary table, `ZSTD_dictAndWindowLog` at an
exact power of two (the parameters differ, the frames do not on the one
case), and the tagged-table cap at 2^24 (needs a 16 MB dictionary).

**Attached, the optimal parsers** (D3, 2026-09-24): 118 more rows in
`cdict_goldens.zig`, 26 cases in `corpus.dict_cases_attach_opt` (every
optimal level on small inputs, `.cdict`, `.load`, `compressUsingCDict`
and a full dictionary as raw; both sides of the 8 KB and 32 KB cutoffs;
forced attach over several blocks and with LDM; forced strategies and
`minMatch` 3 / 5; unknown-size streams, one whose window leaves the
dictionary and wraps). Before them: 5 085 random frames and streams
(inputs up to 400 KB, raw dictionaries of 1 byte to 400 KB near the input
and trained ones on the same data, every dictionary path, levels −3…22
with forced optimal strategies, random advanced parameters incl. LDM)
identical to libzstd, 1 985 of them through an attached CDict. A
50-mutation sweep of the new code: 34 caught (9 only after the cases it
asked for: a CDict longer than its tree and a candidate at its edge, a
dictionary cut from the input so the best match starts at its first byte,
and one that ends right before the input's repeat so its matches run on
into the prefix — the `slice` dictionary source), 5 equivalent (`vEnd` at
`p_match == m_end`, which counts nothing either way; `dmsBtLow` at
`dmsBtMask == dmsHighLimit - dmsLowLimit` and its fallback, the same index;
the `nbCompares != 0` guard, which the loop repeats; the tree update's
extDict flag, as every candidate is in the prefix), and 10 uncovered: a
repcode at the CDict's first byte or one before it; a repcode match into
the CDict that runs on into the prefix (the random frames catch it, no
generated input does); a CDict match of exactly `ZSTD_OPT_NUM` + 1; a
CDict match longer than its distance (`matchEndIdx`; the prefix then
offers the same run nearer); and the guaranteed common length and byte
order of the CDict's tree walk (they matter only when that length reaches
past the CDict's end). **LDM entries from a raw dictionary**, D0's
uncovered mutant, are now caught by `prefix-ldm-beyond-tables` (a
dictionary its tables reach only the end of).

**Attach for the lazy family** (D2, 2026-09-24): 141 more rows over 46
`corpus.dict_cases_attach_lazy` cases (one-shot at the 32 KB cutoff and a
byte above it, `.load` / `.cdict` / `compressUsingCDict`, unknown-size
streams with flushes, a wrapping buffer and a size hint that sizes the
CDict for over 256 KB, forced attach over many blocks and past the
window, with frequent overflow correction; raw, full and crafted
dictionaries, dictionaries larger than the window; rows on and off,
`minMatch` 3–7, strategies forced where no level reaches them). Before
them: 6 660 random frames and streams (inputs 0–140 KB around the
cutoffs, raw dictionaries of 8 bytes to 300 KB and five trained ones,
every one-shot and streaming path, random advanced parameters incl. LDM),
all identical to libzstd where it ran, 3 400 of them still attached at
their end, over every strategy × row/chain. A 69-mutation sweep of the
new code: 57 caught (19 only after cases it asked for — generator seeds
and two new generated dictionaries searched, original against mutant),
8 equivalent (a `dmsMinChain` bound whose `>` and `>=` meet at 0; the
window-end breaks of the chain and row searches, which only save reads;
two prefetches; `dictIndexDelta` from `dictLimit` rather than `lowLimit`,
equal whenever a CDict is attached; the tree's `btLow` choice where both
sides coincide; `countDms` at a match exactly at the CDict's end, which
both branches count on into the prefix), 4 uncovered, all in
`ZSTD_DUBT_findBetterDictMatch`: the byte comparison `<` against `<=` and
dropping either common-length update (both differ only when the
guaranteed common length already runs past the CDict's end), and `>=`
for `>` on the best length (a zero-length candidate re-pricing the
offset; one random real-text input caught it, no generator input in
29 000 tried).

**Anchor grade:** class A · oracle EXTERNAL

## Speed

Speed changes no decision, so the goldens pin them like everything else.
Measured against libzstd 1.5.7 (built `-O3` by its Makefile) on an
i7-7920HQ, both compressing the same input in-process on a reused context,
min of 3 runs on a pinned core, user-mode cycles and instructions
(`perf stat`), ReleaseFast; inputs a 3.4 MB CSV, 12 MB of Zig source and
12 MB of ELF binaries:

| | one-shot, levels −5…19 | streaming (128 KB chunks, unknown size), −5…12 |
|---|---|---|
| cycles | 0.87–1.15× (1.03–1.07× at 1–7 on a quieter run) | 0.99–1.10× |
| instructions | 0.95–1.15× | 0.97–1.12× |

Before Z11 (2026-09-24) the same measurement gave 1.2–1.4× at levels
−5…3 and 1.3–2.0× at 5–12. What closed it:

- **Row match finder prefetch** (`ZSTD_row_prefetch`): the hash cache
  computes a hash 8 positions ahead, and now also prefetches that hash's
  hash-table and tag-table rows; each candidate's bytes are prefetched as
  it is collected. The row search is specialised on the row log at
  compile time. Levels 5–12 went from 1.3–2.0× to about 1.05×, with *more*
  instructions — it was memory latency.
- **The window's base in a register** (`match.Base`, libzstd's
  `window.base`): the match finders read the input as `base + index`
  through a local copy instead of `MatchState.src` / `src_base`, which the
  compiler had to reload after every table store (a store through a `u32`
  slice may alias them). The safe build modes still bounds-check every
  read. −15–20 % instructions at the fast levels.
- **Repcode swaps without `std.mem.swap`**: swapping two hot `u32` locals
  through pointers made LLVM keep them in memory and reassemble them byte
  by byte — 16 % of all instructions at level 1. A plain temporary fixes
  it. (`a, b = .{ b, a }` is not a swap in Zig 0.16: the tuple is built in
  place, so `b` receives the new `a`; the goldens caught it.)
- `fast`/`dfast` prefetch 64 and 128 bytes ahead when their step grows, as
  libzstd does.

What is left above 1.0×: a few percent of instructions in `fast`'s search
loop and `btopt`'s (levels 13–16, 1.13–1.15× instructions at equal
cycles). The entropy stage (literals, sequences) already costs what
libzstd's does.

## What is deliberately not done

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
    buffer and waits for a full block), a `std.Io.Writer` over `Stream`
    (replacing `FrameWriter` for callers that want libzstd's bytes).
    (`ZSTD_CCtx_reset` and frames after the first: done with Z13.)
- **Z2 — Decoder.** ~~**Z2a**~~ done 2026-09-23: the one-shot decoder,
  checksum verification, concatenated and skippable frames and the frame
  utilities, ported from libzstd (std's decoder takes 30× libzstd's time,
  so it was not the base); see *Decoder*. Left:
  - ~~**Z2b — streaming**~~ done 2026-09-23: `DecompressStream`
    (`ZSTD_decompressStream`), `decompressContinue`, `DecompressReader`.
  - **Z2c — dictionaries**: raw-content and zstd-format (`ZSTD_loadDEntropy`:
    entropy tables, repcodes, content as history), a reusable `DDict`, and
    the multiple-dictionary table. **~1 session**; together with Z4.
  Legacy (pre-v0.8) formats: no. Magicless frames: done with Z6.
- ~~**Z3 — Index overflow correction.**~~ Done 2026-09-23, see
  *Algorithm*. (The row tag table needs no reduction: it holds tags and
  in-row heads, not indices.)
- **Z4 — Compression with a dictionary.** ~~**D0**~~ done 2026-09-24
  (see *Dictionaries*): raw-content and full dictionaries, `CDict`, the
  load / copy / reload paths and the attach decision, prefixes,
  `compressUsingDict` / `compressUsingCDict`, the dictionary ID and its
  flag, `forceAttachDict`, `deterministicRefPrefix`, `forceMaxWindow`;
  attaching is refused for strategies without a `dictMatchState` variant
  yet. Left:
  - **D1–D3 — attach**: the `dictMatchState` variant of every match
    finder — ~~D1 `fast`/`dfast`~~ (tagged CDict tables), ~~D2 hash chain /
    row / DUBT~~ (*Attach for the lazy family*), ~~D3 the optimal parsers
    (and LDM with a dictionary)~~ — all done 2026-09-24-2026-09-25, each
    lifting the refusal for its strategies (*Dictionaries*, "Adding an
    attach variant"); `hasDictMatchStateVariant` is exhaustively `true`.
  - Dedicated dictionary search (`enableDedicatedDictSearch`) optional;
    `prefetchCDictTables` (speed only).
- **Z5 — Dictionary training.** ~~**Z5a**~~ done 2026-09-24: the content
  cover and fastCover pick, the optimizers' grid, memory estimates and a
  ceiling (see *Dictionary training*). Left, **Z5b**:
  `ZDICT_finalizeDictionary` (`ZDICT_analyzeEntropy` compresses the samples
  through an attached CDict, so it needs Z4's dictMatchState path at the
  finalization level, L3 = dfast by default; it keeps the content's head
  when short of room), `ZDICT_trainFromBuffer*` on top of it, and
  `COVER_selectDict` (incl. `shrinkDict`) as the optimizers' `scorer`. The
  legacy divsufsort trainer: no. **~1 session** after Z4.
- ~~**Z6 — Advanced parameters.**~~ Done 2026-09-24, see *Advanced
  parameters*: the explicit compression parameters with libzstd's bounds
  and derivation, the content-size flag, magicless frames (both ways),
  skippable frames, literal compression, the row match finder, both
  splitters, the block size, the size hint. Moved out: the dictID flag
  (Z4, it has no effect without a dictionary) and
  `searchForExternalRepcodes` (Z10, it acts on external sequences only).
- ~~**Z7 — Long-distance matching as an option.**~~ Done 2026-09-24, see
  *Algorithm* and *Advanced parameters*: the switch and the four LDM
  parameters, and the path below `btopt`.
- ~~**Z8 — `targetCBlockSize`.**~~ Done 2026-09-24, see *Advanced
  parameters*.
- **Z9 — Multithreaded compression** (`zstdmt_compress.c`, ~1 900 lines):
  jobs, overlap between them, LDM across jobs, `rsyncable`. libzstd's
  output does not depend on the worker count once there is more than
  none, so it stays goldenable. **~2 sessions.** After Z1.
- **Z10 — Sequence-level API.** `ZSTD_compressSequences`,
  `ZSTD_generateSequences`, the external sequence producer, and their
  parameters (`repcodeResolution`, `blockDelimiters`, `validateSequences`,
  `enableSeqProducerFallback`). **~1 session.** Niche.
- ~~**Z11 — Speed parity.**~~ Done 2026-09-24, see *Speed*: within about
  10 % of libzstd at every level (was 1.2–2.0×).
- **Z12 — Portability.** Run `portable-zstd-*`; big-endian (the
  pre-splitter's 16-bit hash reads *native* order in libzstd — decide which
  to match); 32-bit (`ZSTD_CURRENT_MAX` 2 000 MB). **~0.5 session.**
- ~~**Z13 — Context reuse and sizing.**~~ Done 2026-09-24, see *Contexts*.
  Its premise was wrong: without a dictionary a reused libzstd context gives
  the same bytes as a fresh one (measured), so reuse is for speed and
  memory; libzstd's reuse policy is ported anyway. Also
  `ZSTD_estimateCCtxSize*` (as this port's exact sizes), a caller's
  workspace (`ZSTD_initStaticCCtx`), and a stream's later frames and
  `ZSTD_CCtx_reset`. With dictionaries (Z4) reuse matters again: a
  `CDict` attached or copied into a reused context.

Suggested order: (Z1a, Z1-1, Z1b, Z1c, Z3, Z2a, Z2b, Z6, Z13, Z7, Z11, Z8 done) Z4 + Z5
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
- Dictionaries (Z2c mutation sweep, widened per the coordinator's request:
  48 mutations across every bounds/length check and error branch of
  `loadDEntropy` and its header parsing, the content-type dispatch, dictID
  checks and selection, history/entropy setup in one-shot and streaming,
  and `refPrefix`'s lifetime — 43 killed, 4 equivalent, 1 hunted and not
  found). All three originally-uncovered cases the coordinator asked to be
  hand-crafted byte by byte were, checked against libzstd through
  `tools/zdec.c`, and turned into KATs (`testdata/dict_kats.zig`):
  - A dictionary truncated to exactly its entropy header (content size 0,
    `full_dict_zero_content`) — libzstd rejects it too
    (`dictionary_corrupted`), and turned out to prove the repcode-room
    check (`pos + 12 > dict.len`) **equivalent** to its `>=` mutant, not
    merely uncovered: with content size 0, `rep == 0 or rep > 0` is a
    tautology, so every valid repeat offset (always ≥ 1) fails the
    *other* half of the same check regardless of the room check's
    boundary — confirmed by running the mutant against this exact
    dictionary, which still rejects it, same class.
  - A dictionary with its first repeat offset patched to 0
    (`full_dict_rep0_zero`, otherwise identical to `full_dict` so its
    content size stays > 0) — kills the `rep == 0` half of that check
    directly; libzstd rejects it too.
  - Two small raw-content dictionaries (dictionary ID 0 by construction,
    like every raw-content dictionary — `small_raw_a`/`small_raw_b`) in a
    `ddicts` set, decoding a dictID-0 frame (`small_frame`): confirmed
    against libzstd (`tools/zdec.c`, `refMultipleDDicts`) that a dictID-0
    frame is *not* exempt from selection — libzstd's hash set uses
    `currDictID == 0` as both its empty-slot sentinel and a real
    raw-content dictionary's ID, so it genuinely matches whichever one
    last landed at that bucket. This reversed the original guard
    (`selectDDict` no longer special-cases `frame_dict_id == 0`) rather
    than confirming it — the guard was a wrong, undisclosed simplification
    from before this round, not a deliberate one.
  Also hand-crafted, found by the widened sweep itself, each checked
  against libzstd and turned into a KAT: a dictionary of exactly 8 bytes
  (magic + dictID, no entropy header at all, `eight_byte_dict` — also
  proved `dict.len <= 8` vs `< 8` **equivalent**: at exactly 8 bytes both
  reach the same downstream Huffman-header failure); `raw_dict` requested
  as `.full` (has no magic number, so `.full` must still refuse it);
  `frame_raw_l5` (dictID 0) decoded with an unrelated nonzero-dictID
  dictionary active, confirming libzstd's dictID check really does
  short-circuit entirely at `fParams.dictID == 0` regardless of what
  dictionary is configured; a frame whose literals reuse the dictionary's
  Huffman table (`lit_repeat_frame`, found by hunting ~50 (input, level)
  combinations — most frames here don't exercise this at all); and three
  `refPrefix`-lifetime KATs (single-pass shortcut, the regular
  block-by-block path, and an intervening skippable frame all correctly
  drop the prefix after one frame, matching libzstd exactly per the
  deviation-4 resolution above).

  Two more equivalent, by the same kind of proof as the repcode-room
  check: `readEntropyFse` building its table with the *declared* maximum
  symbol value instead of the one `FSE_readNCount` actually read is
  unobservable, because that value can only be smaller (the read loop is
  bounded by the declared one), and every symbol between the two has
  probability 0 in the returned table by construction, contributing no
  cells to it either way. `setHistoryFrom`'s `content.len == 0` guard is
  equivalent too: the address arithmetic it skips computes the same
  `checkContinuity` outcome (an empty `ext`) either way, since
  `prefix_addr == prev_end_addr` whenever `content.len == 0` regardless of
  which address they hold.

  One mutation was hunted and not found: dropping `applyEntropy`'s
  `st.rep = e.rep` (the dictionary's repeat offsets never actually reach
  the decoder) survived every attempt — a hand-built dictionary with
  distinctive repeat offsets (50/60/70, in place of the default 1/4/8
  every `ZDICT_trainFromBuffer` dictionary here has) decoded through
  `tools/zdec.c` identically regardless of which repeat offsets were
  active, across 5 corpus inputs × 5 levels × content styled to match the
  dictionary's own training vocabulary, and again through this port's own
  differential tool across a further 150 (input, level) combinations.
  Contrast with `lit_entropy` above (a structurally similar mutation,
  found within roughly 50 attempts by the same kind of hunt): a dictionary
  match landing at one of the dictionary's own specific repeat-offset
  values, as the very first sequence of a freshly attached dictionary
  compression, appears not to happen for `ZSTD_compress_usingDict` at any
  level on content of the sizes tried here — plausibly because it needs
  the encoder's very first match to coincide exactly with one of three
  fixed distances into unrelated dictionary bytes, unlike Huffman-table
  reuse, which the cost model can choose deliberately. Confirming this
  would need a hand-encoded sequence bitstream (bypassing the compressor
  entirely) rather than a compression-based hunt; not attempted this
  round.
