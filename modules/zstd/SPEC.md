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
- **The whole streaming API.** `Stream` (see *Algorithm*) does libzstd's
  buffered modes and the stable-buffer ones (`ZSTD_c_stableInBuffer`,
  `ZSTD_c_stableOutBuffer`), frame after frame on one context;
  `StreamWriter` is a `std.Io.Writer` over it (libzstd's bytes), and
  `FrameWriter` (Z1a) a `std.Io.Writer` of independent one-shot frames.

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
   single-threaded LDM never needs it (its sequences are generated per
   block and end inside it), multithreaded LDM does: a job's sequences
   are generated for the whole job and handed to it as external raw
   sequences (see *Multithreading*). (The sequence-level API's sequences
   are another kind, `ZSTD_Sequence`, copied straight into the block's
   store: *Sequences*.)
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

**Stable buffers** (`Advanced.stable_in_buffer`, `stable_out_buffer`;
`ZSTD_c_stableInBuffer`, `ZSTD_c_stableOutBuffer`). With a stable input
the caller keeps one buffer for the frame -- the same address, only ever
longer, `pos` where the last call left it (checked at every call, as
libzstd checks it: `error.StabilityConditionNotRespected`) -- and there is
no input buffer: `continue` compresses whole blocks straight from the
caller's bytes (`min(rest, blockSizeMax)` each) and reports the rest
consumed while it is still needed; `flush` and `end` compress what is left.
The window is then the caller's buffer, in one piece (no second segment),
so the bytes differ from the buffered mode's for the same calls, as
libzstd's do. Before the frame starts, calls with less than one block in
all (`ZSTD_BLOCKSIZE_MAX`) only record it -- pretending to consume it, and
returning the smallest frame header as the hint -- so that the parameters
are chosen once more input, a flush or the end has come; the held-back
bytes go to the workers too with `nb_workers`. With a stable output there
is no output buffer: every block goes straight into the caller's buffer
(`end`'s one-pass shortcut is taken whatever the room), and the caller may
not change the room left between calls (it may move the buffer). Blocks
are then compressed into whatever room there is, as libzstd does (Z1d):
the frame header needs 18 bytes, a block 6 before it is tried, a block
whose compressed form does not fit is stored raw when that fits
(`ZSTD_entropyCompressSeqStore`'s fallback) and is `error.DstSizeTooSmall`
when it does not, and the epilogue needs its 3 and 4 bytes -- each check
where libzstd makes it, so a frame needs a few bytes more than it ends up
as, the same few. Where libzstd writes without checking (a sub-block's
header, literal header and Huffman table description, its FSE tables, an
RLE literal section, with `targetCBlockSize`) and runs past the end of a
smaller buffer, this port stops with `error.DstSizeTooSmall` instead. The
workspace leaves out the buffers the caller's stand in for, and
`estimateStreamSize` with it.
`ZSTD_CCtx_reset` leaves the input a waiting frame held back on the
context (the next frame would take it off its own input); `reset` drops it.

**`StreamWriter`** (`stream_writer.zig`) is a `std.Io.Writer` over a
`Stream` in the buffered modes: each drain of the writer's buffer (and what
did not fit in it) is `continue`, `flush` is `flush`, `finish` sends what
is buffered as `end` -- the bytes libzstd gives for those calls. The
compressed bytes go to the output writer through a scratch of
`compressBound` of one block, so libzstd's one-pass `end` takes at most one
block, which is also what its ordinary path makes of it: the frame depends
on where the flushes fall, not on how the writes were cut or on the
buffer's length. When nothing reached the stream before `finish`, that one
`end` records the size in the header. Stable buffers are refused
(`error.ParameterCombinationUnsupported`): the writer's buffer is reused.

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
| `enable_dedicated_dict_search` | `ZSTD_c_enableDedicatedDictSearch` | |
| `nb_workers`, `job_size`, `overlap_log` | `ZSTD_c_nbWorkers`, `ZSTD_c_jobSize`, `ZSTD_c_overlapLog` (see *Multithreading*) | 0–256, 0–1 GiB (under 512 KB counts as 512 KB), 0–9 |
| `block_delimiters`, `validate_sequences`, `repcode_resolution`, `enable_seq_producer_fallback` | `ZSTD_c_blockDelimiters`, `ZSTD_c_validateSequences`, `ZSTD_c_repcodeResolution` (formerly `searchForExternalRepcodes`), `ZSTD_c_enableSeqProducerFallback` (see *Sequences*) | none / explicit, —, auto / enable / disable, — |

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

The five dictionary parameters are described in *Dictionaries*, the four
sequence parameters in *Sequences*. Not here, each with its backlog item:
`prefetchCDictTables` (Z4; it changes speed only). `stableInBuffer` and
`stableOutBuffer` (`stable_in_buffer`, `stable_out_buffer`) apply to
`Stream` only, see *Algorithm*.

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
the frame's parameters (no level of its own, so copied or attached, never
reloaded), for one call (`Compressor.compress`) or for every frame until
`reset` (`Stream`); `.cdict` is `ZSTD_CCtx_refCDict`;
`.prefix` is `ZSTD_CCtx_refPrefix_advanced`. `compressUsingCDict` is
`ZSTD_compress_usingCDict_advanced`: the CDict's parameters (for inputs up
to 128 KB or six times the dictionary, or a CDict without a level) with
the window widened to the input up to 512 KB — the switches resolved
before that — else the level's for the input and the dictionary, loaded
anew. Error classes: a corrupt dictionary is `DictionaryCorrupted` /
`DictionaryWrong` on every path, where libzstd's `ZSTD_compress2` with
`ZSTD_CCtx_loadDictionary` reports `memory_allocation` (its internal CDict
creation fails and it cannot tell why).

**Where the dictionary lies.** libzstd's window is pointers: an input
that starts where the window's content ends in memory continues it (one
segment) instead of starting a new one below an extDict, and the match
finders may then choose differently. So the bytes depend on placement
exactly where libzstd's do: a `.prefix`, `compressUsingDict` and a
`CDict.initReference` (`ZSTD_dlm_byRef`) are continued by an input right
after them, in libzstd too (goldens `prefix-adjacent*`,
`cdictref-adjacent-copy`). `.raw` is not: `ZSTD_CCtx_loadDictionary`
copies the dictionary (`ZSTD_dlm_byCopy`) and digests the copy, so this
port's context CDict is made with `CDict.initAdvanced` (a copy), never
`initReference` — until 2026-09-25 it referenced the caller's bytes, and
an input placed right after them gave other bytes than libzstd whenever
the CDict was copied or loaded anew (goldens `load-adjacent-*`; a
5 000-case random diff over every entry path, adjacent and not, 0
mismatches). A CDict that owns its copy (`init`, `initAdvanced`) is
placement-independent.

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
`comparePackedTags`, `fastDictMatchStateBlock`, `dfastDictMatchStateBlock`).
First pass against `-Dtest-filter=dict` (`dict_test.zig`'s dictionary
tests only, a narrower binary -- fast enough to iterate, but only
evidence that a mutation is caught at all, not about the rest of the
module): 19 killed, 14 survived, 0 invalid. One mutation (removing
`countAcrossDict`'s fallthrough for a dict match that ends exactly at
the CDict's edge) exposed a **real bug**: the first port of
`countAcrossDict` returned 0 early whenever the dict-side runway was
exactly exhausted (`p_match == m_end` / `v_end == p_in`), instead of
falling through to `ZSTD_count_2segments`'s continuation into the
prefix, as the existing `Base.count2Segments` already does for the
extDict case. Fixed to mirror `Base.count2Segments`'s shape exactly, and
anchored with a hunted golden, `attach-dfast-cross-end` (dfast, a match
confirmed at the CDict's last bytes that continues counting from the
prefix's start; found by generating random `dict = filler ++ P`,
`input = Z ++ mid ++ P ++ Z ++ tail` constructions and comparing the
fixed helper's output against the pre-fix one until one diverged, then
confirmed against libzstd 1.5.7 byte-for-byte: 454 bytes either way,
while the pre-fix code gives 456 and does not match).

The 14 survivors were then re-run against the **full** `test-zstd` suite
(not just the dict filter, since a filtered binary is a different
binary and a survivor there could still be caught elsewhere): 2 flipped
to KILLED outright (`m04`, an argument-order bug in the continuation
call -- some *other* test in the full suite already covered it) or were
found by hunting. Orig-vs-mutant search (plan §5.4: random `(dict,
input)` triples, `forceAttachDict=1`, ~15–100 k tries per batch,
capped) killed **7 more** with a real divergence confirmed against
libzstd, each now a golden (`surv-m12-fast`, `surv-m17-fast`,
`surv-m22-dfast`, `surv-m23-dfast`, `surv-m24-dfast`, `surv-m25-dfast`,
`surv-m27-dfast`) exercising: the `>` vs `>=` read against
`prefix_start_index`/`prefix_lowest_index` in the prefix-match
acceptance (`fastDictMatchStateBlock`'s `m12`, `dfastDictMatchStateBlock`'s
`m22`, `m24`); the outer loop's off-by-one exit bound (`m17`); and the
`>` vs `>=` read against `dict_start_index` in the dict-match acceptance
and the long-match-plus-one dict branch (`m23`, `m27`).

**Final tally: 28/33 killed, 2 confirmed equivalent, 3 open.**
- **Equivalent** (justified, not hunted further): `m01`/`m02`
  (`countAcrossDict`'s `p_match > m_end` vs `>=`, and `v_end > p_in` vs
  `>=`) -- at the exact boundary these mutate (`p_match == m_end`), the
  `@min` formula and the direct `p_in` branch both evaluate to
  `v_end == p_in`, so `n` comes out 0 either way: no input can tell them
  apart, confirmed by re-running the new `attach-dfast-cross-end` golden
  (which hits exactly this boundary) against both -- still survives,
  as expected of a genuinely equivalent mutant.
- **Open** (30–100 k random tries each did not land the exact index
  coincidence; a future session may hunt further, is not blocking):
  `m03` (`countAcrossDict`'s `orelse len` vs `orelse 0`, needs a full
  matching span up to but short of `m_end`, not the cross-end case
  `attach-dfast-cross-end` covers); `m14` (`fastDictMatchStateBlock`'s
  backward catch-up bound `dm > dict_start_index` vs `>=`); `m19`
  (`fastDictMatchStateBlock`'s `ip1`/`ip0` init-order swap, likely a rare
  or equivalent reordering since it only matters when
  `dict_and_prefix_length == 0` interacts with the very first step);
  `m26` (`dfastDictMatchStateBlock`'s long-match-plus-one prefix
  acceptance `match_idx_l3 >= prefix_lowest_index` vs `>`, the sibling of
  the now-killed `m22`/`m24`, just on the "+1" lookahead specifically).

**The dedicated dictionary search (D4, 2026-09-25).**
`Advanced.enable_dedicated_dict_search` (`ZSTD_c_enableDedicatedDictSearch`)
acts on the `CDict`s made with those parameters (`CDict.initAdvanced`, and
the context's own for `Dictionary.raw`, which libzstd makes from the
context's requested parameters); a `CDict.init` never has it
(`ZSTD_createCDict`). `ZSTD_createCDict_advanced2`: the parameters are
`ZSTD_dedicatedDictSearch_getCParams` -- the level's row for an input of 0
bytes (not 513) plus the dictionary, so the window is sized for the
dictionary alone, the hash log 2 larger for `greedy`..`lazy2` -- with the
explicit parameters put over them and no further adjustment (no size hint,
no LDM window). If they are not supported (`ZSTD_dedicatedDictSearch_isSupported`:
`greedy`..`lazy2`, hash log above the chain log, chain log at most 24), the
CDict is a plain one with the plain parameters. The row match finder is
resolved on the dedicated parameters too (a 15.9 KB dictionary: 16 KB
window, hash chains; its plain CDict would have rows). The chain table is
always allocated (`ZSTD_allocateChainTable` with `forDDSDict`).

Loading (`lazy.ddsLoadDictionary`, `ZSTD_dedicatedDictSearch_lazy_loadDictionary`)
hashes every position with the hash log less 2 (and `minMatch` as it is: 3
as 4, 7 as 7) into a temporary hash chain built inside the oversized hash
table, then lays each hash's chain out as a bucket of 4 entries -- the
three newest positions, newest first, and `(start << 8) | length` of the
rest of the chain, copied contiguously into the chain table: at most
`min(2^searchLog - 3, 255)` entries (unsigned, so a search log of 1 wraps
to 255), and at most 3 of them older than the chain table's reach. A
context always attaches such a CDict (`ZSTD_shouldAttachDict`: even with
`force_attach_dict = .copy` or `force_max_window`, at any input size; only
`.load` loads its content into the context, whose own tables are plain),
sizing its own tables from the CDict's parameters with the hash log taken
back down (`ZSTD_dedicatedDictSearch_revertCParams`, not below 6). The
parser is the dictMatchState one (`DictMode.dedicated_dict_search`,
compile-time); the hash-chain and row finders, after the window, spend
their attempts left on the bucket (stopping at an empty entry) and then on
the chain's contiguous entries (`lazy.ddsSearch`,
`ZSTD_dedicatedDictSearch_lazy_search`); the row finder adds
`2^(searchLog - rowLog)` attempts the rows are capped at. libzstd also
prefetches every candidate's bytes; that decides nothing and is left out
(the pointer arithmetic on an empty entry would trip a safe build).

Verified: 99 goldens (`corpus.dict_cases_dds`: supported and fallen-back
levels, `.raw` and `.cdictadv`, raw and trained dictionaries, forced
copy/load, `force_max_window`, rows on and off, search logs 1 and 7,
minimum matches 3/5/7, explicit hash logs, 150 KB dictionary, index
overflow correction, four stream schedules, and two hunted by the
mutation sweep) and a random diff against libzstd 1.5.7 linked in: 7 700
cases over random raw and trained dictionaries (tiny vocabularies for long
chains), input sizes 0-400 KB, levels -1..22, one-shot and streamed, `.raw`
and `.cdictadv`, random row/search/min-match/hash/chain/strategy/window/
attach settings -- 0 mismatches. Mutation sweep (46 mutants over the new
code in `lazy.zig`, `cdict.zig`, `frame.zig`): 41 killed (38 by the random
diff, 1 by a unit test, 2 by hunted goldens `dds-tmp-chain-low-end` and
`dds-chain-limit-255`), 5 equivalent: `min_chain`'s `<` as `<=` (equal
sides give the same value); the chain attempts `2^s - 3` as `2^s - 2`
(the one more entry laid out is never read: a search has at most `2^s`
attempts, 3 of them spent on the bucket); zeroing only 2 of a bucket's 3
slots (every insert shifts slot 1 into slot 2, and a bucket without
inserts stops at slot 0); and the two "match reached the input's end"
early exits of `ddsSearch` (no later candidate can be longer). Without a
dictionary the port runs the same instructions (`instructions:u` of
greedy..lazy2 on 6 MB, rows and chains: 12 336 220 k before and after,
within 4 k); with an attached CDict (dictMatchState), within 0.002 %.

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

## Multithreading

`Advanced.nb_workers` (libzstd's `ZSTD_c_nbWorkers`) of 1 or more hands a
frame to `zstdmt.zig`, the port of `zstdmt_compress.c`, as libzstd's
`ZSTD_compressStream2` does: for a `Stream` whose frame is of unknown size
or pledged above 512 KB (`ZSTDMT_JOBSIZE_MIN`; a first call that ends the
frame pledges its input), and for one-shot `compress` of more than 512 KB
(`ZSTD_compress2` goes through the same path). Smaller frames stay on the
calling thread and give nbWorkers 0's bytes. From one worker up the frame
differs from nbWorkers 0's, and **does not depend on the worker count**:
the goldens are made with 3 workers, checked equal with 1 by the recipe,
and the test compares 1, 2, 4 and 8.

**Jobs.** The input is copied into a round buffer and cut into jobs of
`targetSectionSize` bytes: `Advanced.job_size` (`ZSTD_c_jobSize`, a value
under 512 KB counts as 512 KB), else 4 windows and at least 1 MB
(`ZSTDMT_computeTargetJobLog`; with long-distance matching, whose window is
typically oversized, 2^(cycle log + 3), at least 2 MB); a flush, or the
end, cuts a shorter one. Where jobs end depends only on the calls — the
caller must go on calling `flush`/`end` until they return 0, as for
libzstd — so the bytes do too. Each job is compressed on a context of its
own as a frame of its own: the first writes the frame header (with the
content size and checksum flag of the whole frame) and carries the
dictionary; every later one reloads the last `targetPrefixSize` bytes of
the previous job's input as a raw-content prefix
(`ZSTD_compressBegin_advanced_internal`, with `forceMaxWindow` and without
`deterministicRefPrefix`), writes a header that is then dropped, and
starts with its repeat offsets set to 0 (`ZSTD_invalidateRepCodes`); the
last one ends the frame (a job of no input writes just the last empty
block). A job compresses its input 512 KB at a time
(`ZSTD_compressContinue`), which the pre-splitter sees as chunks. The
overlap is `Advanced.overlap_log` (`ZSTD_c_overlapLog`): 9 reloads a whole
window, each step below half as much, 1 nothing; 0 picks 6 up to `lazy`, 7
for `lazy2`/`btlazy2`, 8 for `btopt`/`btultra`, 9 for `btultra2`
(`ZSTDMT_computeOverlapSize`; with LDM a fraction of a quarter job). When
the round buffer has no room for another job, the prefix is moved to its
start, so a job's window is always one segment.

**Serial state.** Two things run across jobs in job order
(`ZSTDMT_serialState`): the content checksum, appended after the last job,
and long-distance matching, whose table and window span the round buffer
from job to job (a raw prefix is loaded into it first); the sequences it
finds for a job are handed to that job's context as external sequences
(`ZSTD_referenceExternalSequences`), which `ZSTD_buildSeqStore` consumes
block by block ahead of the match finder, through `ZSTD_ldm_blockCompress`
as when LDM runs in the context. libzstd runs this step in the workers,
each waiting for its turn; the port runs it on the calling thread when it
prepares the job, which is the same order and needs no lock. libzstd waits
there, too, before it reuses round-buffer space the LDM window still
covers; once every prepared job's step has run the window never does
(else libzstd would wait forever), which a safety-checked assertion pins.

**Dictionaries.** Only the first job has one. `.raw` and `.cdict` are
used by the first job's context as by a single-threaded frame (attached,
copied or reloaded by its size — the frame's, unknown included); a raw
`.prefix` (content type raw) is the first job's prefix and is loaded into
the LDM table; a `.prefix` of another content type becomes a `CDict` made
by reference with the frame's parameters and no level (libzstd's
`ZSTD_createCDict_advanced` in `ZSTDMT_initCStream_internal`). The later
jobs see only their predecessor's tail.

**Threads.** `Stream` and `Compressor` make a `zstdmt.MtCtx` at their
first multithreaded frame and keep it: `nb_workers` `std.Thread`s, each
with its own compression context (reused frame after frame, as libzstd's
CCtx pool), a job table of a power of two above `nb_workers + 2`, the round
buffer, each job slot's output and sequence buffers, and the LDM table. A
job is posted only while a thread is free (`POOL_tryAdd` on a pool without
a queue); otherwise it waits prepared (`jobReady`) and the input is not
read further. `flush` and `end` wait for the oldest job's next output when
no input could be taken. Synchronisation is atomics plus the futex of
`std.Io` through the process-global `std.Io.Threaded` instance, whose
futex calls touch no state of the instance, so the module needs neither
libc (zig-libs policy) nor an `Io` from its caller. Not `workerpool`: it
needs the caller's `Io`, boxes every job on the heap and queues without
bound, where this needs a fixed set of threads each owning a context and
at most one job each. With `builtin.single_threaded`, or the test seam
`run_inline`, the jobs run on the calling thread when posted — the same
bytes. The large buffers (the round buffer, up to `max(window,
nb_workers × job) + 3 jobs`; each job's output, `compressBound(job)`) come
from the allocator's `rawAlloc`, so a safe build does not fill them with
`undefined` and they stay unresident until used, as libzstd's `malloc`
does; at level 22 with an unknown size a job is 512 MB.

Deviations: the pledged size is checked against the whole frame (more
input than pledged, or less at the end, is `error.SrcSizeWrong`), where
libzstd's jobs check only their own; `continue` while a frame is being
ended is `error.StageWrong` (libzstd's `stage_wrong`); `nb_workers` above
256, `job_size` above 1 GiB and `overlap_log` above 9 are
`error.ParameterOutOfBound` where libzstd clamps; a frame abandoned with a
job prepared but not posted does not leave it for the next frame (libzstd
keeps `jobReady`). `estimateCompressorSize` / `estimateStreamSize` size the
single-threaded context only (libzstd refuses to estimate with workers);
`MtCtx.memorySize` reports what a multithreaded context holds.

**`rsyncable`** (Z9b, `ZSTD_c_rsyncable`, `Advanced.rsyncable`): while
input is copied into the round buffer, `findSynchronizationPoint` rolls a
hash over the last 32 bytes (`ZSTD_rollingHash_*`: a polynomial in
`prime8bytes` over the bytes plus 10, modulo 2^64) and ends the job
right after the first byte, at least 128 KB (`RSYNC_MIN_BLOCK_SIZE`) into
it, where the hash's low log2(section size in KB) + 10 bits are all set
-- the mask is taken from the job size before it is raised to the overlap
size, as libzstd does -- turning the call's `continue` into a `flush`; so
jobs, and the output, resynchronize after a local change of the input.
The hash is started from the input when the 128 KB point lies 32 bytes or
more into it, else from the buffered tail; with 128 KB already buffered,
from the buffer's last 32 bytes, and a hit there (a job cut but not yet
taken, the job table being full) loads nothing until it is. Like libzstd,
a frame kept on the calling thread ignores it. The one branch never
taken: "fewer than 32 bytes to hash" (it needs a buffer under 32 bytes
with 128 KB in view, which the section size of 512 KB and up rules out).

## Sequences

The sequence-level API (`seqapi.zig`, with its drivers at the end of
`frame.zig`), ported from `zstd_compress.c`: the caller's parse compressed
without a match finder, the parse a compression makes returned, and a
block-level match finder of the caller's own. A sequence is libzstd's
`ZSTD_Sequence` (`zstd.Sequence`: offset, literal length, match length,
rep — the same four `u32`s, so a C array passes as it is); one with offset
and match length 0 is a *block delimiter* whose literals end a block.

**`Compressor.compressSequences`** (`ZSTD_compressSequences`) sets the
context up exactly as `compress` does for the input's size — parameters,
dictionary, frame flags — writes the frame header and then, block by
block (`ZSTD_compressSequences_internal`): the block's size — with
`block_delimiters = .explicit` the sum up to the next delimiter, refused
over the block size or the input left; with `.none`, the block size — and
its sequences copied into the block's store. The explicit copier
(`ZSTD_transferSequences_wBlockDelim`) takes them as they are, encoding an
offset as a repcode only with `repcode_resolution` (`.auto`: from level
10, `ZSTD_resolveExternalRepcodeSearch`; without it the history the next
block starts from is the block's last three raw offsets). The
no-delimiter copier (`ZSTD_transferSequences_noDelim`) always resolves
repcodes and cuts the sequence that crosses the block's end: inside its
literals the block ends there; inside its match, the match is split only
when it is longer than the block and both halves keep `minMatch` (the
first half shortened for the second to reach it), else the block ends
before the match — so a block may come out shorter than the block size,
and a sequence may span several blocks. A block under 7 bytes is stored
raw; otherwise it is entropy-coded as any block
(`ZSTD_entropyCompressSeqStore`, where running out of room is "store raw"
only when the raw block fits, else `error.DstSizeTooSmall`), made RLE when
it is not the first block, has fewer than 4 sequences and 10 literals and
repeats one byte (`ZSTD_maybeRLE`), and stored raw when it does not
compress. Unlike the frame path, a raw or RLE block leaves the offset
table's `valid` mark as it was, and a raw block under 7 bytes does not end
the "first block" (libzstd clears it only after a block that went through
the entropy stage). No pre-splitter, post-splitter, superblocks, match
finder or window update run; the checksum is over the input. The
destination may have any size: its room decides as in libzstd.

With `validate_sequences` every stored sequence is checked
(`ZSTD_validateSequence`): its offset against the bytes decoded so far
plus the dictionary's content (while those are within the window; then
the window), its match length against 3 (`minMatch` 3, or a producer
registered) or 4. The dictionary counted is a `CDict`'s, loaded or
referenced; a prefix counts 0 — libzstd clears the prefix from the
context before the sequences are read. A block of more sequences than the
store holds (`ZSTD_maxNbSeq`: the block size / 3 with `minMatch` 3 or a
producer, else / 4) is `error.ExternalSequencesInvalid` either way.
Without validation the sequences are trusted, as in libzstd: the port
keeps libzstd's unsigned wrapping arithmetic on them (a match shorter
than 3 stored with its wrapped length and flagged long, a second long
length replacing the first, offsets that wrap into repcodes), so invalid
sequences give libzstd's (undecodable) frame, byte for byte.

**`compressSequencesAndLiterals`** (`ZSTD_compressSequencesAndLiterals`)
takes the literals gathered instead of the input, and the content size:
explicit delimiters only (`error.FrameParameterUnsupported`), no
validation (`error.ParameterUnsupported`) and no checksum
(`error.FrameParameterUnsupported`). A block ends at the first match
length of 0 (`ZSTD_get1BlockSummary`); its sequences are converted
without their literals (`ZSTD_convertBlockSequences`) and the literals
entropy-coded from the caller's buffer. There is no raw fallback: a block
that does not come out under the block size, or does not compress at all,
is `error.CannotProduceUncompressedBlock`; literals or sizes that do not
add up exactly are `error.ExternalSequencesInvalid`. An empty frame (one
delimiter) fails too, as in libzstd: its store holds 0 sequences for a
block size of 1.

**`generateSequences`** (`ZSTD_generateSequences`, deprecated in libzstd)
runs `compress` into a scratch buffer from the context's allocator (a
static context has none: `error.OutOfMemory`) with a collector
(`SeqCollector`) that takes each block's sequences with raw offsets
(repcodes resolved against the history before the block) and a delimiter
holding its last literals (`ZSTD_copyBlockSequences`; the delimiter's
`rep` is left as the caller's buffer had it), after which the block is
stored raw, so the pre-splitter's savings see raw blocks. With the
post-splitter each part is collected with the history before it, its
repcodes already rewritten where an earlier part's raw storage would have
broken them. A block under 7 bytes is `error.SequenceProducerFailed`
("uncompressible block"): an input whose last block is that short cannot
be collected. `target_c_block_size` and workers are
`error.ParameterUnsupported`; room for fewer sequences than the blocks
give, `error.DstSizeTooSmall`. `sequenceBound` and `mergeBlockDelimiters`
(which folds each delimiter's literals into the next sequence and drops
the last one's) are libzstd's.

**A sequence producer** (`zstd.SequenceProducer` in
`Options.sequence_producer` / `StreamOptions.sequence_producer`;
`ZSTD_registerSequenceProducer`) replaces the match finder in
`ZSTD_buildSeqStore`: for each block of 7 bytes or more it is given the
block alone (no dictionary; the frame's level and window size) and room for
`sequenceBound(block size)` sequences, a buffer in the context's workspace
(which `estimateCompressorSize` counts, with the store's room for a
sequence per 3 bytes). Its count is checked
(`ZSTD_postProcessSequenceProducerResult`: more than the room, or none for
a nonempty block, is a failure; a missing final delimiter is appended),
the lengths must not add up past the block
(`error.ExternalSequencesInvalid`, fallback or not), and the sequences go
through the explicit copier, validated against the block's own positions.
When it fails, `enable_seq_producer_fallback` runs the level's match
finder for that block; otherwise the frame fails with
`error.SequenceProducerFailed`. The post-splitter, superblocks and every
later stage run over its sequences as over the match finder's. With
long-distance matching each block of 7 bytes or more fails with
`error.ParameterCombinationUnsupported` (libzstd's check, in the same
place); with workers the frame does, before anything else. The producer is
a struct of a context pointer and a function pointer, as libzstd's
(state, function) pair: chosen at run time, so neither `Compressor` nor
`Stream` becomes generic over it; failing is an error
(`error.SequenceProducerFailed`) rather than libzstd's magic count, and a
count above the room counts as a failure too.

**Deviations** — where libzstd's behaviour is undefined, the call fails
instead:

- a destination under 18 bytes (`ZSTD_FRAMEHEADERSIZE_MAX`):
  `error.DstSizeTooSmall` (libzstd does not check the error its frame
  header writer returns and goes on at a wild position; on the random runs
  it returned unrelated errors);
- an offset code of 0 (a raw offset of 0xFFFFFFFD stored without
  resolution): `error.ExternalSequencesInvalid` (libzstd takes
  `highbit32(0)`);
- a sequence whose literal and match lengths wrap 32 bits, or run past the
  block (only through such a wrap, or the no-delimiter copier's cut of
  one): `error.ExternalSequencesInvalid` (libzstd copies literals from
  outside the input; it crashed on the random runs that got there);
- `compressSequences*` with workers over a frame of more than 512 KB:
  `error.ParameterUnsupported` (libzstd hands the frame to its
  multithreaded context, which the sequence API then bypasses, reading a
  block state never set up). Smaller frames run single-threaded, as in
  libzstd;
- `compressSequencesAndLiterals` takes the literals as a slice, so
  libzstd's literal-buffer capacity argument (checked only against the
  literal count) has no counterpart.

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

## Dictionary training

`dict_builder.zig` ports libzstd's `cover.c` and `fastcover.c`, and
`zdict.zig` the finalization of `zdict.c` (not its legacy divsufsort
trainer). First the content selection (Z5a): the sample segments the
trainers place at the end of the dictionary buffer, byte for byte
(`coverContentInto` / `fastCoverContentInto` leave it at the same place,
`dict[len - n ..]`; `coverContent` / `fastCoverContent` return a copy).
Then finalization and the complete trainers (Z5b, *Finalization* below).

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
- `ZDICT_finalizeDictionary` keeps the content's *head* when header +
  content exceed the capacity (`memmove` of the first `capacity - hSize`
  bytes), dropping the best segments at the tail -- reproduced (every
  trainer run that fills its buffer does it), and why `tools/ztrain.c`
  reads the content before finalization rather than out of a finished
  dictionary.

**Finalization** (`zdict.zig`, Z5b). `ZDICT_finalizeDictionary`: magic
number, ID (the caller's, else XXH64 of the content taken into 32 768 ..
2^31 − 1), entropy tables, then the content, zero-padded in front to the 8
bytes the largest start repcode needs; checks and order as libzstd's
(capacity below the content or 256; no room for the padding). The tables
(`ZDICT_analyzeEntropy`) come from the compressor itself: a `CDict` of the
content made with `ZSTD_getParams(level, average sample size, content size)`
put over the default level's (`ZSTD_createCDict_advanced`, raw content, by
reference, no level), each sample (cut to `min(128 KB, window)` of those
parameters) compressed as one block on one reused context through the
**attached** CDict -- `frame.Compressor.beginUsingCDict` +
`compressBlockOnly`, ports of `ZSTD_compressBegin_usingCDict_deprecated`
and `ZSTD_compressBlock_deprecated` (block mode: no frame, no RLE block,
unknown size so always attached). A sample above the context's block --
the CDict's window, which `ZSTD_cpm_createCDict` sizes for 513 bytes plus
the content, so a small content makes a small window -- is refused by
`compressBlock` and not counted, as in libzstd; a block that does not
compress is not counted either. Counted: every literal (starting from 1
each, so all 256 bytes get a code), and the offset, match-length and
literal-length codes (`ZSTD_seqToCodes`), from 1 up to the offset code of
content + 128 KB (above code 30: `DictionaryCreationFailed`). Then the
Huffman table (max 11 bits; a flat distribution that gives 8 bits is
replaced by `ZDICT_flatLit`'s), the three normalized FSE tables
(`useLowProbCount`), and the repcodes 1, 4, 8 -- libzstd computes the most
common first offsets and does not use them ("impact not properly
evaluated"); that ranking is not ported. The header must fit in 256 bytes.
`ZDICT_addEntropyTablesFromBuffer` writes the tables straight into the
buffer (over the content's head if they reach it), hashes the content for
the ID after that, and moves the content down only when there is room to
spare -- reproduced.

**Scoring and the optimizers.** `selectDict` is `COVER_selectDict`:
finalize the candidate on the finalization share (cover: the training
samples; fastCover: `accel`'s percentage of them), then
`COVER_checkTotalCompressedSize`: the dictionary's size plus each testing
sample (all samples at split 1) compressed with `ZSTD_createCDict(dict,
level)` and `ZSTD_compress_usingCDict` on one context. With `shrink`, it
finalizes the last 256 bytes of the candidate's buffer and goes on with
*twice the finished size* (libzstd reassigns the size to finalization's
result) until one is within `shrink_max_regression` percent -- reading
before the content once the size passes it, from the candidate's whole
buffer, as libzstd does. libzstd 1.5.7's optimizers pass `shrinkDict = 0`
whatever the caller sets, so no public trainer shrinks; `selectDict` offers
it, anchored through `tools/zfinal.c` calling `COVER_selectDict` directly.
`optimizeCover` / `optimizeFastCover` plug `selectDict` into Z5a's grid:
the first strictly smallest total wins, as `COVER_best_finish` decides in
submission order when single-threaded -- with threads too (see
*Multithreaded optimizers* below; libzstd's thread pool breaks ties by
completion order instead). `train` is `ZDICT_trainFromBuffer`
(fastCover, d = 8, steps = 4, level 3). A failed candidate (finalization
or compression error) is skipped, as libzstd's error selections never beat
the best; none left is `error.NoCandidate` (libzstd `GENERIC`).

**API choices (the user's, 2026-09-25).** `d` defaults to 8 (the CLI's);
k stays required for `trainCover` / `trainFastCover`; the optimizers keep
libzstd's defaults. `memory_limit` stays 256 MiB and now bounds *all*
working memory, the dictionary buffer excluded: the complete trainers run
on a `LimitedAllocator` that refuses any allocation past it
(`error.MemoryLimitExceeded`), so finalization's compressor and `CDict`,
the optimizer's candidates and scoring count too (the content selection
is still checked up front, before allocating).

**Multithreaded optimizers** (Z9b, `OptimizeParams.nb_threads`, libzstd's
`nbThreads`). libzstd posts each (k, d) candidate to a pool
(`POOL_create(nbThreads, 1)`), and `COVER_best_finish` keeps, under a
mutex, any candidate strictly better than the best *so far*: of two
candidates with the same total, whichever finishes first wins, so its
result with threads depends on the timing -- which a byte-identical port
cannot follow. The port runs the candidates of one d on `nb_threads`
worker threads (a slot and a thread each, fed through a futex like
`zstdmt.zig`'s; no libc) but compares them on the calling thread in grid
order, so the first strictly smallest total wins -- libzstd's
single-threaded result, which the goldens pin, for every thread count.
Measured on the random diff below: libzstd with 4 threads returned
another dictionary than its own single-threaded run on 7 of 300 runs; the
port never did. Memory: each candidate in flight holds its own
frequencies copy (cover: 4 bytes per training d-mer; fastCover: 6 · 2^f
bytes), buffer and scorer (finalization, a `CDict` and a compressor), so
threads multiply the working memory. `memory_limit` bounds the sum rather
than each candidate, and the thread count must not change the answer:
fewer candidates run at once when the ceiling does not hold `nb_threads`
content selections next to the context (a static count), and a candidate
refused by the ceiling while others held memory -- the scorers' memory is
not known up front -- is run again after the others are dropped, with half
as many at once; refused alone, the refusal is final
(`MemoryLimitExceeded`), exactly where one thread is refused. Each
candidate charges its own `LimitedAllocator.View` of the one ceiling to
tell its own refusals apart; the slots and threads (a few hundred bytes)
are not counted. Refusing `nb_threads` beyond what the ceiling holds was
the alternative: it would make a call that succeeds with one thread fail
with more, for the same memory. The allocator must be thread-safe with
`nb_threads` > 1, and so must a scorer given to `optimize*With`. `trainFromSlices` takes the
samples as `[]const []const u8` and copies them into one buffer (the
trainers need them contiguous: segments cross sample boundaries); the copy
counts against the limit. Levels above 22 are `LevelUnsupported` (libzstd
clamps). Nothing is printed (`notificationLevel`).

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
`COVER_warnOnSmallCorpus`'s verdict. (7) Finalization levels above 22 are
`LevelUnsupported` (libzstd clamps them to 22). (8)
`addEntropyTablesFromBuffer` refuses a content longer than the buffer or a
buffer under 8 bytes (`DstSizeTooSmall`; libzstd reads or writes outside
it). (9) Running out of memory (or past `memory_limit`) while scoring a
candidate is an error, not a skipped candidate (libzstd skips a candidate
whose `malloc` fails, and so can return another dictionary under memory
pressure). (10) A sample-buffer check: sizes summing past it are
`SrcSizeWrong` in finalization too.

**Anchoring (Z5b).** `dict_golden_test.zig`: 66 finished-dictionary runs
(`dict_samples.final_runs`: finalization at levels −5..22 of every
strategy, IDs, finalization shares incl. none, flat literals, a content
whose CDict window refuses most samples, samples above a block, the header
not fitting, padding, refusals; `addEntropyTablesFromBuffer` incl. tables
over the content; both trainers; both optimizers on coarse grids;
`ZDICT_trainFromBuffer`; `COVER_selectDict` with and without shrinking),
each dictionary's length and SHA-256, `ZDICT_getDictHeaderSize` of it, and
the optimizers' k and d or the selection's total equal to libzstd's through
`tools/zfinal.c` -- identical on the first run -- and each loads as a
`DDict` (unless its tables overwrote the content). A one-off diff over
2 060 random runs (every operation; sample
sets of 1–700 samples, some up to 250 KB each, up to ~4 MB; capacities
200–110 000; levels −7..22; random IDs, splits, f, accel, finalization
shares, shrink tolerances) gave the same dictionary, header size, chosen
parameters and totals, or the same refusal, on all of them.
Mutation sweep of the new code (`zdict.zig`, the block-mode additions to
`frame.zig`, the scoring, trainers and ceiling in `dict_builder.zig`): 63
mutants, 48 killed (six only after hunting: goldens for an average sample
+ content of exactly 16 KiB, 12 bytes left for the repcodes, 1025-byte
samples against a 1 KiB window, and unit tests for `addEntropyTables`'
own ID and tiny buffers and `trainFromSlices(.default)` on a set where the
grid matters), 12 equivalent, 3 unreached. Equivalent: an 8-byte
dictionary in `getDictHeaderSize` (`<= 8` vs `< 8`: the tables then fail
to parse anyway); the content cut at `hSize + content == capacity` (`>`
vs `>=` cut to the same size); padding at exactly 8 bytes of content (none
either way); `addEntropyTables`' move at `hSize + content == capacity`
(onto itself); an average sample size of 0 treated as a known 0 (then no
sample has a byte to compress); the analysis `CDict` made at the level
instead of the default (every field is overridden but a zero target
length, and the only level whose target length differs between the size
classes, 4, uses it only with strategies that ignore it); `ZDICT_flatLit`'s
weight of byte 0 as 3 (same code lengths; the path is reached: m30/m32
kill); the offset table written with `offcode_max` rather than 30 symbols
(the writer stops at the last one); RLE allowed in block mode (a context
never leaves its first block there); the row match finder switch not
resolved (`resetByAttachingCDict` overwrites it from the CDict); the
optimizers' own level check (finalization refuses the level anyway); the
candidate's buffer re-sliced. Unreached: the padding check at `hSize + 8
== capacity` (a capacity of 256 and up needs a 248-byte header), the offset
code limit at 30 vs 29 (a content of 1 GiB), the shrink tolerance at
equality (a smaller dictionary with exactly the full one's total).

## Limits and refusals

| limit | value | source |
|---|---|---|
| level | `min_level` (-131072) … 22; lower is clamped, higher is `error.LevelUnsupported` | `ZSTD_minCLevel()` / `ZSTD_maxCLevel()`; libzstd clamps above 22 too, which would hand a caller a level it did not ask for |
| memory | level 22 above 64 MB: 512 MiB binary tree + 128 MiB hash + 64 MiB LDM table + 32 KiB bucket offsets (≈ 820 MB peak on a 70 MB input, as libzstd) | the level's own table sizes; nothing is capped, as libzstd caps nothing |
| input | none (the input and `compressBound` of it in memory) | past `ZSTD_CURRENT_MAX` (3500 MiB on 64-bit, 2000 MiB on 32-bit -- *Portability*) the indices are rescaled, as libzstd does (see *Algorithm*) |
| destination | ≥ `compressBound(src.len)` or `error.NoSpaceLeft` | the reference's decisions assume the one-shot bound; accepting less would let capacity change the output |
| block | 128 KB | format |
| stream level | as one-shot (`stream_max_level` = `max_level`) | level 22 without a pledged size uses a 128 MB window and long-distance matching (window log 27, as libzstd), ≈ 1 GB |
| advanced parameters | libzstd's bounds (see *Advanced parameters*), else `error.ParameterOutOfBound` | `ZSTD_cParam_getBounds`, 64-bit |
| stream size | a pledged size must be met exactly, else `error.SrcSizeWrong` (more input at the chunk that passes it, less at the end) | `srcSize_wrong` |
| stream memory | one window plus one block of input buffer (none with `stable_in_buffer`), `compressBound(block) + 1` of output buffer (none with `stable_out_buffer`), and the level's tables | `ZSTD_resetCCtx_internal` |
| stable output room | any: blocks go into what is left, raw when the compressed form does not fit, else `error.DstSizeTooSmall`; where libzstd would write past the end (sub-blocks), `error.DstSizeTooSmall` | `ZSTD_c_stableOutBuffer`: libzstd's own capacity checks (Z1d) |
| context memory | one workspace, exactly `estimateCompressorSize` / `estimateStreamSize`; a static one is never exceeded (`error.OutOfMemory`) | `ZSTD_estimateCCtxSize*`, `ZSTD_initStaticCCtx` |
| decode window | one-shot: none, the whole output is history (window log ≤ 31 in the header on 64-bit, ≤ 30 on 32-bit -- *Portability* -- else `error.FrameParameterWindowTooLarge`); streaming: `window_log_max`, default 2^27 + 1 bytes, else `error.FrameParameterWindowTooLarge` | `ZSTD_WINDOWLOG_MAX` (`_64`/`_32` by `sizeof(size_t)`); `ZSTD_d_windowLogMax` and its default `ZSTD_WINDOWLOG_LIMIT_DEFAULT` |
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
| `maybeSplitSequence` and `ZSTD_ldm_skipSequences`: every comparison at its equality, the cut match's `minMatch` test, the carry of a too-short match into the next sequence's literals, the skip dropped (8) | unreachable from single-threaded LDM: its sequences are generated per block, counted only up to the block's end, and the store is discarded with the block. Multithreaded LDM reaches them (a job's sequences span its blocks); Z10 swept them there (*Sequences* below): killed, or equivalent |
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

**Stable buffers and `StreamWriter`** (Z1, 2026-09-26): 13 more
`corpus.stream_cases` (78 rows) with `stableInBuffer`/`stableOutBuffer`
through `tools/zstream.c`, which keeps libzstd's contract (one input buffer
grown by each token, `pos` kept; one output buffer never drained, exit 9
when full): the wait under one block, exactly one block, a wait then an
end, pledged, a small window (one segment), LDM, a flush between, a
block's rest compressed where it lies before an empty end, the block path
of an end through a small output buffer, the held-back input handed to
workers, a stable output alone and both together. Before them 1 260 random
runs against `zstream` (both modes and each alone, 0–2.5 MB of source,
binaries, text, noise and generated mixes; levels −5…19, window, pledged
size, size hint, block size, workers, flushes and chunkings up to
600 KB): 1 155 identical, 98 refused alike (a stable output that fills),
7 where a stable output below `compressBound` was refused and libzstd went
on (the refusal Z1d then removed, below), none different. Unit tests pin the contract
checks one condition at a time (address, `pos`, room left), the wait's
hint and pretended consumption, exactly one block starting the frame, a
reset dropping a waiting frame's input, both refusals short of
`compressBound`, and the workspace without the caller's buffers matching
`estimateStreamSize`. `StreamWriter` against `Stream` driven with the
schedule the test spells out, over 4 buffer lengths × 4 write sizes (and
splats), the one-call frame and the empty one. Mutation sweep, 33 mutants
of `stream.zig`, `stream_writer.zig` and the workspace layout: 31 caught
(11 after the tests and cases above), 1 equivalent -- `or stable_out` in
the block path's direct test, always true behind the `compressBound`
refusal -- and 1 whose code went (`StreamWriter` sent `finish` as
`continue` plus an empty `end` once anything had been written; the
one-block scratch makes one `end` the same bytes).

**Any room** (Z1d, 2026-09-26): libzstd's capacity checks in the frame
path, anchored at their edges. For 13 cases (plain, flushed,
`targetCBlockSize`, `maxBlockSize`, the block splitter at 16 and 19, a
stable input, an incompressible and an all-zero input, a 7-byte and an
empty one, a flush before an empty end) the least room libzstd succeeds in
was bisected with `zstream` and is a golden row (`o<room>`, 26 rows with
the checksum and without): the same bytes as with room to spare, a few
bytes more than the frame (libzstd checks for a block's worst case before
it knows the size). One byte less is refused, as by libzstd, with the
checksum and, where libzstd's least room is the same, without; 32 rooms
below the least for a level-19 frame all refused; each check shown to be
the deciding one by a `zstream` built with `DEBUGLEVEL=3`: the raw block
exactly the room after its header, six bytes asked before a 1-byte block
that needs four, the epilogue's 3 and 4 bytes after a raw block. 1 260
random runs against `zstream` built with AddressSanitizer (a stable output
of 0 bytes to a little over `compressBound`, with a stable input, sub-blocks,
block sizes, windows, flushes and chunkings): 561 identical, 691 refused
alike, none different, and 8 where libzstd wrote past the end of the
output buffer (a sub-block's Huffman description or FSE tables copied
unchecked) and this port refuses; two such inputs from the corpus are unit
tests. Mutation sweep, 17 mutants of the capacity checks: 12 caught (8
after the cases above), 2 equivalent -- the epilogue's own frame-header
check (the epilogue always follows the header's writer), the RLE block's
4 bytes in the frame path (6 are asked before every block; in
`compressSequences` a destination ending 3 bytes into an RLE block would
reach it, and no case does) -- and 3 guards with no case found: a
block-splitter partition, and a sub-block or its RLE literals, starting
within 2 or 3 bytes of the end.

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

**Multithreading** (Z9a, 2026-09-25): `testdata/mt_goldens.zig`, 57 rows
over 29 `corpus.mt_cases` (one-shot and streamed, 512 KB jobs over 1–3 MB
inputs, every strategy family, every overlap from none to a window, the
round buffer wrapping, LDM across jobs and its reach into a raw prefix,
checksums, a job of no input, empty frames, the 512 KB routing edge,
dictionaries loaded / as a raw or full prefix / a CDict attached or
copied), from libzstd built with `ZSTD_MULTITHREAD` at 3 workers; the
recipe checks that 1 worker gives the same bytes, and `mt_test.zig` runs
every row with 1, 2, 4 and 8 threads and once with the jobs inline. The
oracles for everything else are now the multithreaded build too: all
other goldens came out unchanged. Before the goldens, 2 040 random runs
against libzstd (`ZSTD_compress2` and `ZSTD_compressStream2` plans with
flushes, pledges and small output buffers; levels −7…22, inputs 0–4.5 MB,
1–8 workers, random job size and overlap, LDM with small windows, random
advanced parameters, raw and trained dictionaries by every path), 400 of
them with the jobs inline: all identical. A mutation sweep of the new
code, 56 mutations: 45 caught (4 of them as a hang: a job that never
completes), 12 of those only after the cases they asked for (a copy just
past the window, a raw prefix with a small window, `deterministicRefPrefix`,
LDM with a large cycle log, a prefix that only LDM reaches from the second
job and whose validity ends exactly at the input's end, exactly 512 KB
pledged, a prefix across two frames). 8 equivalent: `forceMaxWindow` for
the later jobs (their prefix is contiguous with the input, so
`ZSTD_checkDictValidity` clears `loadedDictEnd` at the first block either
way); the later jobs' pledged size (it only sizes buffers and the dropped
header); clearing the checksum flag of a one-job frame (nothing reads it
again in that frame); the level of a full prefix's CDict (a CDict made
this way has no level, and level 0's row is the default level's, under the
frame's explicit parameters); the external sequences skipped by a block
under 7 bytes, both ways (only a job's last block can be that small); an
assertion; `end`'s "frame not ended" answer (unreachable: an `end` that
consumed its input has created the last job, or holds it ready). 3
uncovered: a later job's prefix read as `auto` instead of raw content (it
matters only when the overlap starts with the dictionary magic), and two
concurrency invariants a deterministic test cannot provoke (one job more
in flight than threads, which could overwrite a queued job; the
round-buffer in-use check skipped for one job too many, which could
overwrite a running job's input).

**`rsyncable`** (Z9b, 2026-09-25): 14 more `mt_cases` (32 rows) with
`rsyncable=1`, most on `rsync_marks` inputs -- words with a 32-byte
trigger whose rolling hash has 30 low bits set placed at chosen offsets,
and every other window that would hit a 19-bit mask edited away -- so the
jobs are cut where the case says (checked with a probe when they were
made): one byte before a cut may happen and exactly at the first byte it
may; a full job's last byte and just past it; jobs of one 512 KB chunk and
of a chunk and a byte; one 16 MB default job cut by the marks alone;
overlap 9 raising the section size over the mask's; LDM; a dictionary;
natural data; a frame too small for workers; streams whose hash starts
from the buffered tail, at exactly 128 KB buffered, and at a buffered hit
while the job table is full (a 50-byte output buffer). The recipe checks
1 worker against 3; the test runs 1, 2, 4, 8 and inline. 1 600 random
runs against libzstd (one-shot and stream plans, 0.1–2.6 MB with up to 25
triggers at random places, levels −5..19, random job size, overlap, LDM,
window, 1–4 workers): all identical. Mutation sweep, 38 mutants: 33 caught
(3 after the cases they asked for: overlap 9 on natural data, the call
ending at 128 KB, `rsyncable` left on a reused context -- a unit test), 5
equivalent: the "too little to hash" return (unreachable, see
*Multithreading*) dropped or at `<=`; the "too little input" return at
`<=` (at equality the scan is empty); the input-start test at `pos > 32`
(at 32 the tail branch hashes the same 32 input bytes, and `prev` is not
read); the missing `break` after a hit (the loop bound is the new
`to_load`, so it ends anyway).

**Multithreaded optimizers** (Z9b, 2026-09-25): `dict_golden_test.zig`
runs every optimizer row of the finished-dictionary goldens with 2, 3 and
8 threads: libzstd's single-threaded dictionary, k and d each time; a
unit test compares 0/2/3/4/8/64 threads against one with a scorer that
ties a lot (a hash mod 5); another bisects the smallest `memory_limit`
one thread succeeds with, and checks that 4 threads succeed with the same
dictionary under it, stay under it, and are refused one byte lower. The
rerun after a refusal does not wait for contention to happen: a scorer
gates the first round so that the ceiling refuses at grid position 1, 2
or 3 whatever the scheduling (exactly one rerun, grid order, nothing
live after), and a scorer's own OutOfMemory on a slot refused before is
final. Test seams record the slot count (at most one d's 41 candidates;
0 and 1 thread run on the caller) and the static count (4 with no
ceiling, 1 at the lowest ceiling the up-front check lets through). 300 random
optimizer runs (both trainers, 5–700 samples, random k, d, steps, split,
f, accel, level, ID; 2–8 threads) against `tools/zfinal.c`: the same
dictionary, k and d or the same refusal as libzstd single-threaded, and
N threads = 1 thread, on all; libzstd itself with 4 threads gave another
dictionary than single-threaded on 7 of them (on 2 in a rerun of the same
300 on 2026-09-26: its ties go by completion order). Mutation sweep, 33 mutants of the
driver and `LimitedAllocator`: 32 caught (8 only after the seams above,
2 after unit tests of a failing child allocator and an in-place shrink),
1 equivalent: the rerun keeping the old in-flight count (the drained
slots are idle with no result, so they compare as nothing until the
count is back under the new one, and the reposted candidates follow them
in grid order).

**Sequences** (Z10, 2026-09-25): `testdata/seq_goldens.zig`, 172 rows
over 118 `corpus.seq_cases` through `tools/zseq.c` — `generateSequences`
over every strategy family, the post-splitter, LDM, a dictionary and its
refusals; `mergeBlockDelimiters`; `compressSequences` with and without
delimiters, repcode resolution by level and by hand, validation, small,
raw and RLE blocks, the no-delimiter copier's cuts at each equality, ten
kinds of damaged sequences (`testdata/seqgen.zig`) and hand-made lists,
raw and full dictionaries by every path, small destinations;
`compressSequencesAndLiterals`; the example producer (`seq_test.zig`,
the same function as zseq's) failing, falling back, misbehaving, cutting
matches to 3 bytes, streamed — 37 of the rows are libzstd's error, which
must match by class. Before them, 4 300 random runs (inputs 0–700 KB of
source, binaries and generated mixes; levels −7…22; libzstd's own
generated parses, re-blocked, merged and damaged at random; random
parameters, capacities and dictionaries; producer modes and stream
chunkings) against `zseq`: all identical, bytes or error class, the first
time — except where libzstd's behaviour is undefined (it crashed on 7, and
returned unrelated errors on 19 with a destination under 18 bytes; the
port refuses those, see *Sequences*, *Deviations*). A full dictionary
loaded into the context briefly looked like a divergence; it was a
stale recipe copy that passed the dictionary as raw content.

A mutation sweep of `seqapi.zig` and the new `frame.zig` lines, 67
mutations: 59 killed (21 only after the cases they asked for: hand-made
lists at the long-length, validation-bound, store-room and RLE edges; a
full dictionary over 1 KB blocks, where the offset table's `valid` mark
must end after the first compressed block; three producer inputs found
by search, original against mutant, where a block of 3, 2 or 1 sequences
without repcode resolution leaves the history the next block's fallback
match finder reads), 6 equivalent, 2 uncovered:

| mutation | why no case exists |
|---|---|
| no-delimiter copier: `start_pos >= lit_length` → `>`; `second_half < minMatch` → `<=`; `end_pos > lit_length` → `>=` in the split branch | equivalent: at each equality both branches leave the same lengths (a literal length of 0, an adjustment of 0, a first half of 0 that falls to the same "end before the match") |
| `ZSTD_convertBlockSequences`' history without resolution for 3 sequences (`>= 4` → `> 4`, the 2-sequence branch's `rep[2]`) | equivalent: `compressSequencesAndLiterals` has no match finder and no later reader of the history unless repcode resolution is on, and then this branch does not run |
| the empty-frame special case of `compressSequencesAndLiterals` dropped | equivalent: every path through it fails anyway (a 1-byte block size leaves room for no sequence) |
| a producer's trailing delimiter not recognised (appended again) | reachable only when the producer fills its whole buffer, `sequenceBound(block)` sequences, which needs zero-length sequences; the example producer makes none. **Uncovered.** |
| the collector's history updated with the long literal length (`+ 0x10000`) instead of the stored 16 bits | differs only for a literal length of exactly 65 536 before a match in `generateSequences`. **Uncovered.** |

The LDM raw-sequence mutations Z7 left (`maybeSplitSequence`,
`ZSTD_ldm_skipSequences`; 9 as swept here) were run against multithreaded
LDM, which reaches them: 5 killed — the skip dropped by the existing
multithreaded goldens, 4 by `mt-ldm-cut-4k` and `mt-ldm-cut-1500` in
`corpus.mt_cases` (found by search against libzstd-checked originals: a cut
match of exactly `minMatch`, a too-short one carried into the next
literals, the skip at exactly a sequence's literals), 4
equivalent (the whole-sequence test `>=` → `>`, where the cut path returns
the same sequence and skips it whole; the cut's `remaining < ll + ml`
equality, excluded by the test before it; `remaining <= ll` → `<`, where
the match cut to 0 bytes is below `minMatch` and dropped the same way;
the skip's `src_size < ml` → `<=`, where a 0-byte match carries 0
literals). (A first hunt driver rejected `jobSize` on both sides and
compared stale files; the finds above were each checked by hand against
`zref`.)

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

**Multithreaded** (Z9a; wall-clock and CPU seconds, 33.5 MB of Zig
source and a mixed corpus, one-shot, ReleaseFast, 8 cores, not pinned):
level 3, 1 worker 0.17–0.21 s wall (libzstd 0.15–0.21), 4 workers 0.09 s
(libzstd 0.09–0.10); level 9, 0.57–0.63 (0.56–0.59) and 0.36–0.39
(0.37–0.38); level 19 with 4 MB jobs, 1 worker 14.2 s (14.4), 4 workers
5.1 s wall, 16.7 s CPU (4.8, 15.4). At level 19's default job size (32 MB)
that input is one job and 4 workers gain nothing, as in libzstd.

What is left above 1.0×: a few percent of instructions in `fast`'s search
loop and `btopt`'s (levels 13–16, 1.13–1.15× instructions at equal
cycles). The entropy stage (literals, sequences) already costs what
libzstd's does.

## Portability

`meta.targets` (`root.zig`): `.linux64` (mandatory), `.linux32`, `.windows`
(`check-portable`'s vocabulary, `build.zig`'s `PortableTarget` -- see its
doc comments before adding a target here). Not `.wasm32`: `zstdmt.zig`'s
worker pool uses `std.Thread.spawn`, unavailable in `wasm32-wasi`'s
single-threaded build (`std/Thread.zig`'s `@compileError`) -- an open
question, not decided here (below).

`.linux32` is `mips-linux-musl`, `mips32,soft_float` -- 32-bit **and**
big-endian at once, libzstd's actual combination on real hardware (an
ath79 24Kc; `build.zig`'s doc comment on `PortableTarget.linux32`), so this
section covers both axes through the targets `check-portable` actually
declares, not the wider i386/arm/s390x sweep a first read of libzstd's
`MEM_32bits()`/`MEM_isLittleEndian()` might suggest.

**What changed, by libzstd site** (`rg 'MEM_32bits|MEM_64bits'` over
`lib/`, every hit read):

- `zstd_compress_internal.h`'s `ZSTD_CURRENT_MAX` (3500 MiB / 2000 MiB) and
  `zstd.h`'s `ZSTD_WINDOWLOG_MAX_64`/`_32` (31 / 30) are real behaviour,
  not perf: the first decides when indices rescale (`match.zig`'s
  `current_max`, past which `ZSTD_window_correctOverflow`'s C also runs on
  a 32-bit build), the second is the advanced-parameter bound and the
  decoder's hard frame-header cap (`params.window_log_max`,
  `decompress.window_log_max`). Both were a bare `31` / `3500 << 20`
  (the 64-bit value only) and are now `if (@sizeOf(usize) == 4) ... else
  ...` -- libzstd's own `sizeof(size_t) == 4` check, with a Zig
  cross-compile's `usize` standing in for the C `size_t`. A dedicated test
  next to each pins the selected constant against the literal libzstd
  picks (`match.zig`, `params.zig`, `decompress.zig`), so it runs for real
  under every declared target, not just read as consistent with itself.
- Every other `MEM_32bits()`/`MEM_64bits()` site (`huf_compress.c`,
  `zstd_compress_sequences.c`, `huf_decompress.c`, `zstd_decompress_block.c`
  -- about twenty, all in the bitstream and sequence-decode paths) only
  decides how often libzstd's C flushes or reloads a `size_t`-sized bit
  accumulator to avoid overflowing a 32-bit register; the serialized
  bitstream is invariant to that timing (a later flush moves already-
  decided bits to the output earlier, never changes them). This port's
  accumulators are `u64` unconditionally (`bitstream.zig`'s `CStream`,
  `dbits.zig`'s `DStream`), so it always has 64-bit headroom and never
  needs the narrower path -- confirmed by the existing goldens (built
  against libzstd's 64-bit output) staying byte-identical under both
  32-bit targets in the sweep below, including `zstd_decompress_block.c`'s
  `isLongOffset`, which exists only to compensate a 32-bit accumulator
  that this port does not have.
- `huf_decompress.c:203`, `!MEM_isLittleEndian() || MEM_32bits()`: gates
  libzstd's 64-bit-little-endian fast Huffman decode loop, falling back to
  the reference decoder elsewhere -- a speed selection between two
  implementations proven to agree, not a value difference. `huf_dec.zig`
  already had the equivalent gate (`@sizeOf(usize) != 8 or
  builtin.cpu.arch.endian() != .little`, `initFastDStream` and its
  callers) before Z12; nothing to change.

**Big-endian: the pre-splitter's hash** (`zstd_preSplit.c`'s `hash2`,
`MEM_read16` -- native order on the build host). `presplit.zig`'s `hash2`
already read the two bytes as **explicitly little-endian**
(`std.mem.readInt(u16, p[0..2], .little)`), not native order, before Z12
-- a deliberate choice (its existing comment) rather than an oversight.
**Decision, made explicit here: keep it.** This module's byte-identical
claim is against libzstd's ordinary little-endian builds (amd64/arm64,
the mandatory `.linux64`, and every real-world zstd installation a
consumer's frames need to interoperate with) -- matching *this* build's
native order instead would make a big-endian build of this module produce
frames a little-endian libzstd decodes fine (the format is endianness-
agnostic) but whose *bytes* differ from what every other zstd
implementation in existence writes for the same input and level, which is
a worse portability property than a deliberately fixed byte order. Checked
against a genuinely big-endian libzstd build (below): the two disagree
exactly where the pre-splitter's cut points move because of it, nowhere
else. Everywhere else in this port already reads and writes explicitly
`.little` or `.big` (`rg` over `src/*.zig` for `readInt`/`writeInt` with
no explicit endianness: zero hits) -- `ZSTD_count`'s trailing-zero byte
count (`match.zig`'s `count`/`hashSalted`, `huf_dec.zig`'s CTZ-driven
Huffman fast loop) reads its words with an explicit `.little`
`std.mem.readInt`, so `@ctz`/byte-count arithmetic is correct on any host
regardless of native order, unlike libzstd's C (`ZSTD_NbCommonBytes`,
`bits.h`), which branches on `MEM_isLittleEndian()` to get the same
answer from a native-order read.

**The real bug: the row match finder's tag-match mask** (`lazy.zig`'s
`matchMask`, `ZSTD_row_getMatchMask`). Its vector compare
(`tag_row[0..entries] == splat(tag)`) is bitcast straight to an integer
mask, bit `i` meaning "slot `i` matched" -- the convention `rotr` and
every caller (`headGrouped + ZSTD_VecMask_next(matches)`) depend on, and
the one libzstd's own SIMD paths *and* its portable SWAR fallback both
preserve on purpose: the fallback's comment literally says "big endian:
reverse bits during extraction", doing extra work so a big-endian host's
`MEM_readST`-native-order read still lands bit `i` on slot `i`. This
port's `@bitCast(@Vector(entries, bool))` does not carry that guarantee.
Measured directly (a standalone comparison of the identical vector
compare + bitcast on `x86_64-linux` vs. `mips-linux-musl`, 16-, 32- and
64-lane, matching the three row widths this function is ever
instantiated at): the big-endian result is the little-endian one with
**every bit reversed end to end**, not a byte swap. This is not a compile
failure `check-portable` (compile-only, see *Anchoring* below) could ever
catch -- it produces a *valid*, decodable frame, just not libzstd's bytes
-- and it was found by actually running the test suite under `qemu-mips`
(below), where `context_test.zig`'s "indexing restarts near the index
limit, with the same bytes" (level 7, `lazy`, which crosses the 16 KB row
threshold) failed reproducibly while every other test passed. Fixed with
`@bitReverse` on a big-endian target only, a no-op branch removed at
comptime elsewhere, so `.linux64`/`.windows` emit the exact same code as
before.

**Four more bugs `check-portable -Dportable-measure-all` actually
found**, all now fixed:

- `literals.zig`'s `minLiteralsToCompress`/`minGain` shifted a `usize`
  value by a bare `u6` -- correct only when `usize` is 64-bit
  (`Log2Int(usize)` is `u5` on 32-bit) -- the exact bug class
  `build.zig`'s `check-portable` comment names (`qr`'s `BitWriter`). Now
  `std.math.Log2Int(usize)`.
- `zstdmt.zig`'s `Pool.posted`/`taken`/`finished` were
  `std.atomic.Value(u64)`: `mips-linux-musl` has no native 64-bit atomic
  ops, and `@atomicLoad`/`Store`/`Rmw` refuse to compile there for a
  64-bit operand. Narrowed to `u32` -- which turns out to match libzstd's
  own `nextJobID`/`doneJobID` (`zstdmt_compress.c`, plain `unsigned`) more
  closely than the `u64` this port had; a `u32` job-sequence wrap needs
  over four billion jobs in one compression, unreachable at any realistic
  job size. `Pool.slot` centralises the `u32`/`usize` cast at the one
  place indices meet the queue length.
- `frame_writer.zig`'s `drain`/`flush` recover `*FrameWriter` from
  `*Writer` with `@fieldParentPtr`; on `mips-linux-musl` alone the
  compiler reports the result as only 2-aligned and refuses to widen it,
  even though the field's actual offset is a multiple of 8 there
  (`@offsetOf`, checked by hand) -- a conservative bound this target's
  ABI makes `@fieldParentPtr` compute, not a real alignment hazard (`w`
  only ever points at the `writer` field of an actual `FrameWriter`
  value). `@alignCast` at both call sites, as the compiler's own error
  suggests.
- `testdata/corpus.zig` and `testdata/dict_samples.zig` (test-only, not
  shipped): several `Rng.below(n: u64) u64` results indexed a slice
  directly, which needs `usize` -- fine by implicit widening on a 64-bit
  `usize` and a compile error on a 32-bit one. `@intCast` at each site.

**Five more test-only bugs, found only by actually running the suite**
(`check-portable` is compile-only and could not have caught any of
these -- see *Anchoring*): `dict_builder.zig`'s "the memory ceiling
refuses before allocating anything" hardcoded `(s.sizes.len + 1) * 8`
where the code under test (`FastCoverContext.memory`) correctly uses
`* @sizeOf(usize)` (libzstd's own `sizeof(size_t)`-sized per-sample
entries) -- the estimate itself was already right for both widths, only
the test's expectation assumed 64-bit; now `* @sizeOf(usize)`. And
`param_test.zig`'s advanced-parameter bounds table hardcoded four
64-bit-only edges as bare literals instead of the constants they check:
`window_log` (`params.window_log_max`, 30 not 31), `search_log`
(`params.search_log_max` = `ZSTD_SEARCHLOG_MAX` = `ZSTD_WINDOWLOG_MAX -
1`, 29 not 30) and `ldm_hash_rate_log` (`params.ldm_hash_rate_log_max` =
`ZSTD_LDM_HASHRATELOG_MAX` = `ZSTD_WINDOWLOG_MAX - ZSTD_HASHLOG_MIN`, 24
not 25) -- all three confirmed against libzstd's own `zstd.h`.
`hash_log`/`chain_log`'s edges (30/31) needed no change: their bound is a
fixed `ZSTD_HASHLOG_MAX`/`ZSTD_CHAINLOG_MAX` = 30, not derived from
`ZSTD_WINDOWLOG_MAX`.

**Anchoring.** `check-portable`'s own claim is compile-only
(`build.zig`'s comment on why: `addTest`, never run, on every
cross-compiled target) -- it caught the four compile-time bugs above but,
by construction, never could have caught the row-match-finder bug, which
compiles cleanly and only produces wrong bytes at runtime. The evidence
below is this module's own, beyond that gate:

- `zig build test-zstd -Dtarget=mips-linux-musl
  -Dcpu=baseline+mips32+soft_float -Doptimize=ReleaseSafe`, actually
  *executed* under `qemu-mips` (Zig's test runner picks it up from `PATH`
  automatically for a foreign target): first run (before any Z12 fix)
  179/193 passed, 11 failed, 3 crashed -- nearly all traced to the
  row-match-finder mask (`context_test`'s reuse-equals-fresh checks and
  `param_test`'s byte-identical-with-advanced-parameters check, every one
  exercising `greedy`..`lazy2` above a 16 KB window) or the test-only
  memory-ceiling literal above. One more pre-existing failure was fixed
  alongside the others: `param_test.zig`'s bounds table hardcoded three
  more 64-bit-only edges besides `window_log` -- `search_log`
  (`ZSTD_SEARCHLOG_MAX = ZSTD_WINDOWLOG_MAX - 1`, 29 not 30 on 32-bit) and
  `ldm_hash_rate_log` (`ZSTD_LDM_HASHRATELOG_MAX = ZSTD_WINDOWLOG_MAX -
  ZSTD_HASHLOG_MIN`, 24 not 25) -- now `params.search_log_max` /
  `params.ldm_hash_rate_log_max`, both real libzstd constants confirmed
  in `zstd.h`.

  **Full runs after every fix (2026-09-26, with Z9b and Z10 merged in),
  ReleaseSafe under qemu:** `x86-linux-musl` (i386) 212/212 and
  `arm-linux-musleabihf` 212/212, both with every sweep in full;
  `s390x-linux-musl` (64-bit big-endian, used to separate the two axes)
  211/212, the failing `seq_test` fixed and rerun alone, 6/6;
  `mips-linux-musl` soft-float 211/212 with `mt_test` skipped (below).
  Two bugs of the Z10 sequence API showed up only here:
  `blockSizeExplicitDelimiter` and `fastSequenceLengthSum` summed `u32`
  lengths into `usize`, and the validation's running position grew before
  the block-bound check, so lengths near 2^32 -- refused on 64-bit --
  overflowed a 32-bit `usize` (a panic in ReleaseSafe on i386); the sums
  are `u64` and the bound is checked first (the same error class either
  way). And `seq_test` read the little-endian sequence records it writes
  for the goldens back as native `Sequence`s -- garbage on big-endian (a
  test-only bug).

  **qemu-mips crashes:** `qemu-mips: accel/tcg/user-exec.c:581:
  page_find_range_empty: Assertion 'min <= max' failed` -- QEMU's own
  page-tracking invariant, in tests that allocate and free many
  differently-sized regions or thread pools in quick succession
  (`stream_test`, `context_test`, `mt_test`). i386 and ARM (32-bit) and
  s390x (big-endian) run all three in full, so both axes are covered;
  on 32-bit MIPS only, `context_test` and `stream_test` run a trimmed
  sweep and `mt_test` (whose load grew with Z9b's rsyncable cases until
  even a trimmed run tripped qemu) is skipped.

  **The damaged-frame KATs are libzstd's verdict per platform, not a
  bug:** `decoder_test.zig`'s `c00743`, `c01822` and `d04112` (mutation-
  sweep fixtures for fast Huffman loop decisions) give
  `error.ChecksumWrong` on x86_64 and `error.CorruptionDetected` on every
  target without the fast loop (not 64-bit little-endian). libzstd 1.5.7
  itself does the same: `tools/zdec.c` built with `zig cc` for i386 and
  s390x and run under qemu gives `corruption_detected` on all three,
  x86_64 `checksum_wrong` -- libzstd's fast loop, like this port's, runs
  on 64-bit little-endian only, and these frames decode differently
  without it. The fixtures carry both verdicts
  (`Kat.expect_no_fast_loop`).
- A differential sweep of **libzstd itself** (not this port): `.linux32`'s
  `mips-linux-musl` soft-float and, for comparison, plain 32-bit
  little-endian (`x86-linux-musl`, `qemu-i386`) -- `zref.c` (this module's
  own reference oracle, `tools/README.md`) built three ways with `zig cc`
  straight from libzstd 1.5.7's sources (`-target x86_64-linux-musl` /
  `x86-linux-musl` / `mips-linux-musleabi -mcpu=baseline+mips32+soft_float`,
  no prebuilt static lib needed) -- native x86_64, `qemu-i386`, `qemu-mips`.
  Every `(case, level, checksum, ldm, window_log)` combination the golden
  tests themselves use (`tools/dump_corpus.zig`'s manifest, 2 011
  non-`ocf` entries over 98 inputs) compressed natively; one in six also
  compressed under both emulators and diffed by SHA-256 against the
  native frame: **0 mismatches** (335 checked per emulator) -- real
  libzstd's own output is unaffected by 32-bitness or big-endianness for
  every case this corpus reaches (unsurprising: `ZSTD_CURRENT_MAX`/
  `ZSTD_WINDOWLOG_MAX` need multi-gigabyte inputs to matter, and this
  corpus is small by design).
- **This port itself**, compiled for `x86-linux-musl` (a throwaway batch
  driver over this module's `compressAlloc`, not committed) under
  `qemu-i386`, against `zref-i386`, real libzstd built the same way: 249
  `(case, level, checksum)` combinations (every eighth manifest entry,
  spanning every strategy and level) -- **0 mismatches**. Independent of
  the golden tests (which pin this port's output against goldens
  generated on the native x86_64 host, not against a live i386 libzstd
  run) and of the `qemu-mips` test-suite execution above (which pins
  this port's 32-bit-big-endian output against those same goldens); this
  is the one piece of evidence that compares this port's own 32-bit
  *little-endian* bytes directly against a real 32-bit libzstd build's
  bytes for the same input.
- `s390x-linux-musl` (64-bit, big-endian -- not a declared `meta.targets`
  member, since `PortableTarget` has no 64-bit-big-endian entry;
  used here only to separate the two axes `.linux32` conflates): full
  suite green except what the runs above record, *none* of `.linux32`'s
  qemu crashes (confirming those are about a 32-bit
  address space specifically, per their entry above) -- and, importantly,
  every row-match-finder test that `.linux32` needed the `matchMask` fix
  for also passes here, on a completely different big-endian QEMU
  backend from `mips`, which is the strongest evidence available that
  the fix is correct in general and not a MIPS-shaped coincidence.
- The presplitter's endianness decision (above) checked directly, since
  the manifest sweep above is all small inputs unlikely to reach a
  presplit-changing threshold: a 1.96 MB mixed Zig-source file, `zref`
  (real libzstd) natively vs. under `qemu-mips`, at levels 5/9/12/17/19
  with checksums both off and on. Levels 5, 17 and 19 (`greedy` and
  `btopt`/`btultra2`, presplitting active) **differ** between the two
  builds, by tens of bytes out of ~350-410 KB each -- confirming the
  documented decision above is a real, deliberate divergence from a
  genuine big-endian libzstd build, not a hypothetical one. Levels 9 and
  12 (`lazy2`/`btlazy2`) happened to agree for this input -- the
  pre-splitter's cut decision is a threshold, not guaranteed to move for
  every input just because presplitting runs.

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
  - ~~**Stable buffers and a writer.**~~ done 2026-09-26: the stable-input
    and stable-output modes (`ZSTD_c_stableInBuffer`,
    `ZSTD_c_stableOutBuffer`) and `StreamWriter`, a `std.Io.Writer` over
    `Stream` with libzstd's bytes; see *Algorithm*. (`ZSTD_CCtx_reset` and
    frames after the first: done with Z13.)
  - ~~**Z1d — compression into less room than `compressBound`.**~~ done
    2026-09-26: libzstd's capacity checks in the frame path (header, each
    block, the raw and RLE fallbacks, the epilogue); a stable output takes
    any room, as libzstd's. The one-shot API still asks for
    `compressBound` (`error.NoSpaceLeft`): its callers get the whole frame
    or nothing, and libzstd's `ZSTD_compress2` below the bound is left for
    a caller that asks.
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
  - ~~**D4** dedicated dictionary search (`enableDedicatedDictSearch`)~~
    done 2026-09-25 (*Dictionaries*, "The dedicated dictionary search").
  - `prefetchCDictTables` (speed only).
- ~~**Z5 — Dictionary training.**~~ ~~**Z5a**~~ done 2026-09-24 (content
  selection, the optimizers' grid, memory estimates and a ceiling);
  ~~**Z5b**~~ done 2026-09-25: finalization, `COVER_selectDict` (with
  shrinking) as the optimizers' score, the complete trainers and
  `ZDICT_trainFromBuffer` (see *Dictionary training*). The legacy
  divsufsort trainer: no. The multithreaded optimizers: Z9b.
- ~~**Z6 — Advanced parameters.**~~ Done 2026-09-24, see *Advanced
  parameters*: the explicit compression parameters with libzstd's bounds
  and derivation, the content-size flag, magicless frames (both ways),
  skippable frames, literal compression, the row match finder, both
  splitters, the block size, the size hint. Moved out: the dictID flag
  (Z4, it has no effect without a dictionary) and
  `searchForExternalRepcodes` (Z10, it acts on external sequences only;
  done there).
- ~~**Z7 — Long-distance matching as an option.**~~ Done 2026-09-24, see
  *Algorithm* and *Advanced parameters*: the switch and the four LDM
  parameters, and the path below `btopt`.
- ~~**Z8 — `targetCBlockSize`.**~~ Done 2026-09-24, see *Advanced
  parameters*.
- **Z9 — Multithreaded compression** (`zstdmt_compress.c`, ~1 900 lines).
  ~~**Z9a**~~ done 2026-09-25 (see *Multithreading*): jobs, overlap, the
  round buffer, LDM and the checksum across jobs, flushing, dictionaries,
  `ZSTD_compress2` and `ZSTD_compressStream2` with workers. ~~**Z9b**~~
  done 2026-09-25: `rsyncable` (*Multithreading*) and the dictionary
  trainers' multithreaded optimizers, deterministic: libzstd's
  single-threaded winner for any thread count (*Dictionary training*).
- ~~**Z10 — Sequence-level API.**~~ Done 2026-09-25, see *Sequences*:
  `ZSTD_compressSequences` (both delimiter modes, validation, repcode
  resolution), `ZSTD_compressSequencesAndLiterals`,
  `ZSTD_generateSequences`, `ZSTD_sequenceBound`,
  `ZSTD_mergeBlockDelimiters`, the block-level sequence producer with its
  fallback.
- ~~**Z11 — Speed parity.**~~ Done 2026-09-24, see *Speed*: within about
  10 % of libzstd at every level (was 1.2–2.0×).
- ~~**Z12 — Portability.**~~ Done 2026-09-25, see *Portability*: 32-bit
  (`window_log_max`, `ZSTD_CURRENT_MAX`) and big-endian (`.linux32` is
  libzstd's actual combination of both, `mips-linux-musl` soft-float); the
  headline finding was a real correctness bug (the row match finder's
  tag-match mask, big-endian-only, found by actually running the tests
  under `qemu-mips` rather than by `check-portable`, which is compile-only
  and did catch four smaller ones). Run in full under qemu on i386, ARM,
  s390x and mips (2026-09-26); the 3 KAT differences off 64-bit
  little-endian are libzstd's own (see *Portability*'s *Anchoring*).
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
- Sequences (Z10): a producer that fills its whole buffer with a
  trailing delimiter, and a literal length of exactly 65 536 in
  `generateSequences`, have no case (see *Anchoring*).
- Reachable boundaries without a case: the sequence encoding-type
  heuristic's `mostFrequent < nbSeq >> (log - 1)` at equality, the table
  pricing's low-probability switch at exactly 2048 sequences, and 13
  equalities in the optimal parsers and the post-splitter's estimates, and
  10 in long-distance matching (see *Anchoring*).
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
