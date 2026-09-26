# zstd

**Zstandard (RFC 8878) compressor** for every level — 1–22 and the negative
("fast") levels — emitting **exactly the bytes libzstd 1.5.7 emits** for the same input
and level, and a **decoder** ported from libzstd's, one-shot and streaming (also as a
`std.Io.Reader`): as fast (1.05× its time), checksums verified,
concatenated and skippable frames, the frame size queries. std's `std.compress.zstd.Decompress` takes 30× libzstd's time,
leaves checksum verification as a TODO panic and defaults to an 8 MB window.

Not yet a full libzstd replacement — that is the goal: one-shot
compression is complete, streaming (`Stream`, `ZSTD_compressStream2`'s bytes
for the same calls) covers every level too, and `FrameWriter` is a
`std.Io.Writer` that emits one frame per flush, and libzstd's advanced
parameters (`zstd.Advanced`: explicit window/hash/chain/search/strategy,
frame flags, magicless frames, the splitters, the row match finder, literal
compression, block size) give libzstd's bytes for the same settings, and so
does **compressing** with a dictionary (raw or trained, `CDict`, prefixes),
including every strategy's way of **attaching** a `CDict` in place instead
of copying it (`fast`, `dfast`; `greedy`…`btlazy2`; the optimal parsers) —
inputs under 8/16/32 KB by strategy, or unknown sizes.
**Decoding** with a dictionary (raw-content or zstd-format, a digested
`DDict`, `ZSTD_d_refMultipleDDicts`) is done too, and so is dictionary
**training** (`zstd.dict_builder`: cover, fastCover, the optimizers,
`ZDICT_trainFromBuffer`, finalization — the same finished dictionaries as
libzstd), and so is **multithreaded** compression
(`Advanced.nb_workers`, `job_size`, `overlap_log`, `rsyncable`: libzstd's
jobs, overlap, long-distance matching across jobs, rsync-friendly job cuts
— the same bytes as libzstd's for any worker count, on a small pool of
`std.Thread`s without libc), and the optimizers train on several threads
(`OptimizeParams.nb_threads`, the single-threaded result for any count).
The stable-buffer part of the streaming API is queued in
[SPEC.md](SPEC.md) (*Backlog / deferred*, with costs).

It is a port of every libzstd strategy: `fast`, `dfast`, `greedy`, `lazy`,
`lazy2` (with both the hash-chain and the row-based search), `btlazy2` (its
lazily sorted binary tree), and the optimal parsers `btopt`, `btultra` and
`btultra2`; plus the one-shot frame and block driver, the block pre-splitter
and post-splitter, long-distance matching (which libzstd switches on by
itself at level 22 for inputs over 64 MB, and at any level as the option
`--long` does), and the Huffman/FSE entropy
encoders. Pure Zig, no C, no
libc.

- **Levels:** 1–22 (0 means the default, 3), and negative levels down to
  -131072 (lower values are clamped, as libzstd does). Above 22 is
  `error.LevelUnsupported` where libzstd would quietly clamp to 22.
- **Output:** one frame, content size in the header, optional content checksum
  (`checksum = true`). Byte-identical to `ZSTD_compress2()` with the same
  level and checksum setting — pinned by the golden test on a 56-case corpus
  (2029 frames: every case at levels -5…10 with and without checksum, cases up
  to 600 KB at levels 11–22, 14 cases found by mutation testing at the one
  level each pins, 15 compressed with long-distance matching switched
  on by hand, and 13 with index overflow correction run often), and against
  libzstd at level 22 on 64–140 MB inputs and on a 4.4 GB input past the
  3500 MiB index limit.
- **Speed:** within about 10 % of libzstd at every level, one-shot and
  streaming: 0.87–1.15× its CPU cycles (min of 3 runs on a pinned core,
  ReleaseFast, 3–12 MB text/CSV/ELF inputs, levels −5…19; the upper end on
  a loaded machine, 1.03–1.07× on a quieter one) and 0.95–1.15× its
  instructions (see SPEC.md, *Speed*). Level 19 compresses about
  2 MB/s; level 22 about 2.4 MB/s on a 70 MB input (libzstd: 2.5). Memory:
  the match tables for the chosen level, allocated per call and freed before
  it returns — 64 + 16 MiB at level 19 on inputs over 256 KB, up to 256 +
  64 MiB at level 21 on inputs over 64 MB, and 512 + 128 MiB plus a 64 MiB
  long-distance table at level 22 on inputs over 64 MB (about 820 MB peak on
  a 70 MB input, as libzstd) — plus about 0.8 MiB of block buffers and parser
  state.
- **Platform:** any (no OS calls). **Role:** codec. **Concurrency:** reentrant.

Provenance: a translation of libzstd v1.5.7 C source (BSD licence), so this
module carries the required attribution in [`NOTICE`](NOTICE). The byte-exactness
claim rests on libzstd itself, run by the recipe in [`tools/`](tools/README.md).

## API

```zig
const zstd = @import("zstd");

// Allocate the frame (caller owns it).
const frame = try zstd.compressAlloc(gpa, data, .{ .level = 3 });
defer gpa.free(frame);

// Or into your own buffer, which must hold compressBound(data.len) bytes.
var buf = try gpa.alloc(u8, zstd.compressBound(data.len));
const n = try zstd.compress(gpa, buf, data, .{ .level = 1, .checksum = true });
// buf[0..n] is the frame.

// Decode: into a new buffer sized from the header (at most max_size) ...
const back = try zstd.decompressAlloc(gpa, frame, 1 << 30);
defer gpa.free(back);
// ... or into your own; reuse a Decompressor to keep its ~190 KB of tables.
var dec = try zstd.Decompressor.init(gpa, .{});
defer dec.deinit();
const out = try gpa.alloc(u8, data.len);
const len = try dec.decompress(out, frame); // error.DstSizeTooSmall if out is short
```

One-shot decoding takes the whole input and a destination for the whole
output (`ZSTD_decompress`); a frame's size is in `getFrameContentSize`
(null when the header omits it — `decompressBound` then gives an upper
bound). Errors carry libzstd's names (`error.CorruptionDetected`,
`error.ChecksumWrong`, `error.SrcSizeWrong`, ...).

A frame compressed with a dictionary decodes via `Decompressor`'s
`DecompressOptions` (the free `zstd.decompress` takes none) or
`DecompressStreamOptions`, either raw bytes (`.dictionary`) or a digested
`zstd.DDict` (`.ddict`, load once and reuse — `zstd.DDict.init`/
`initByReference`, `.raw_content`/`.full`/`.auto` content types), plus
`.ddicts` for `ZSTD_d_refMultipleDDicts` (pick by the frame's dictionary
ID) and, for streaming, `.prefix` for a one-frame `ZSTD_DCtx_refPrefix`:

```zig
var dd = try zstd.DDict.init(gpa, dict_bytes, .auto);
defer dd.deinit(gpa);
var dec = try zstd.Decompressor.init(gpa, .{ .ddict = &dd });
defer dec.deinit();
const len = try dec.decompress(out, frame); // error.DictionaryWrong if frame/dict mismatch
```

`zstd.getDictId(dict_bytes)` and `zstd.getFrameDictId(frame)` read a
dictionary's or a frame's dictionary ID without decoding (see SPEC.md, §
Decoder, for exactly what a dictionary's content covers as history — a
digested `DDict`'s whole buffer, an undigested `.dictionary`'s only the
part past its entropy header). This module's own **compressor** does not
support dictionaries yet (Z4); the frames these decode were produced by
libzstd itself.

Streaming decompression, from any `std.Io.Reader` (a file, a socket):

```zig
var dr = try zstd.DecompressReader.init(gpa, &file_reader.interface, &.{}, .{});
defer dr.deinit();
_ = try dr.interface.streamRemaining(&out.writer); // every frame, in order
// error.ReadFailed with dr.err set: a decoding error, or the input ended mid-frame
```

or call by call (`ZSTD_decompressStream`): `DecompressStream.decompressStream(&out_buf, &in_buf)`
returns 0 when a frame is fully decoded and flushed. It keeps one window
plus two blocks of output ring and refuses frames asking for more than a
128 MB window unless `window_log_max` says otherwise (libzstd's default);
`stable_output` decodes straight into a caller's buffer that stays put.

`gpa` backs only the per-call match tables and block buffers; everything is
freed before `compress` returns. For many frames, keep a context — its one
workspace is reused (and its tables are not cleared, as in libzstd), and
each frame is still exactly the one a fresh context gives:

```zig
var c: zstd.Compressor = .init(gpa); // ZSTD_CCtx + ZSTD_compress2
defer c.deinit();
for (messages) |m| {
    const n = try c.compress(buf, m, .{ .level = 3 });
    try sink.writeAll(buf[0..n]);
}
```

The workspace size is known in advance, exactly (`ZSTD_estimateCCtxSize`),
and it can be the caller's memory (`ZSTD_initStaticCCtx`) — then nothing is
allocated and a frame needing more is `error.OutOfMemory`:

```zig
const size = try zstd.estimateCompressorSize(max_input, .{ .level = 3 }); // null: any input
const ws = try gpa.alignedAlloc(u8, .fromByteUnits(zstd.workspace_alignment), size);
var c: zstd.Compressor = .initStatic(ws);
```

`estimateStreamSize(opts)` and `Stream.initStatic(ws, opts)` do the same
for a stream (exact for a pledged size or a size hint; without either, the
most any frame can need).

Streaming into any `std.Io.Writer` (an HTTP body, a file), one independent
frame per buffer fill and per flush:

```zig
var buf: [64 * 1024]u8 = undefined; // frame size when nobody flushes
var fw: zstd.FrameWriter = try .init(gpa, out, &buf, .{ .level = 3 });
defer fw.deinit();
try fw.writer.writeAll(chunk);
try fw.writer.flush(); // what is buffered becomes a frame on `out`
try fw.finish(); // the last frame; `out` itself is not flushed
```

Frames share no history, so frequent small flushes cost ratio (the
compression context is reused, so they cost no allocation). On
`error.WriteFailed`, `fw.err` names our own cause (`OutOfMemory`); null
means `out` failed.

Streaming as libzstd streams — history kept across flushes, the same bytes
`ZSTD_compressStream2` produces for the same sequence of calls (every
level):

```zig
var s = try zstd.Stream.init(gpa, .{ .level = 3 }); // .pledged_size = n puts the size in the header
defer s.deinit();
var out_buf: [64 * 1024]u8 = undefined;
var in: zstd.InBuffer = .{ .src = chunk };
while (in.pos < in.src.len) { // .continue: buffer input, emit whole blocks
    var o: zstd.OutBuffer = .{ .dst = &out_buf };
    _ = try s.compressStream2(&o, &in, .@"continue");
    try sink.writeAll(out_buf[0..o.pos]);
}
// .flush / .end: repeat until the return value (bytes still held back) is 0
var end: zstd.InBuffer = .{ .src = "" };
while (true) {
    var o: zstd.OutBuffer = .{ .dst = &out_buf };
    const left = try s.compressStream2(&o, &end, .end);
    try sink.writeAll(out_buf[0..o.pos]);
    if (left == 0) break;
}
```

Once a frame has ended, the next call starts another on the same context
with the same options and an unknown size, as libzstd does;
`s.reset(opts)` abandons a frame or changes the options (pledged size
included). Its memory is the level's tables plus an input buffer of one
window and one block (3.7 MB at level 3 with an unknown size; at level 22
without a pledged size the window is 128 MB and long-distance matching is
on, about 1 GB in all, as libzstd). Errors: `LevelUnsupported`,
`SrcSizeWrong` (a pledged size not met), `InvalidBuffer`, `OutOfMemory`.

libzstd's advanced parameters (`ZSTD_CCtx_setParameter`), by field of
`advanced`; each defaults to the level's choice, and the output is what
libzstd emits with the same parameters set:

```zig
const frame = try zstd.compressAlloc(gpa, data, .{ .level = 19, .advanced = .{
    .window_log = 24, // ZSTD_c_windowLog; also hash_log, chain_log, search_log,
    .strategy = .btultra2, // min_match, target_length, strategy
    .content_size = false, // ZSTD_c_contentSizeFlag
    .format = .magicless, // ZSTD_c_format: decode with DecompressOptions.format
    .row_match_finder = .disable, // .auto / .enable / .disable
    .max_block_size = 16 * 1024, // ZSTD_c_maxBlockSize
    .long_distance_matching = .enable, // ZSTD_c_enableLongDistanceMatching (--long)
} });
```

Also `literal_compression`, `split_after_sequences` (the post-splitter),
`block_splitter_level` (the pre-splitter, 0–6), and the long-distance
matcher's `ldm_hash_log`, `ldm_min_match`, `ldm_bucket_size_log`,
`ldm_hash_rate_log` (0 or null: derived, as libzstd does), and
`target_c_block_size` (`ZSTD_c_targetCBlockSize`: blocks cut into
compressed blocks of about that many bytes, at least 1340, for decoders
fed over a network). Long-distance
matching on sets the window log to 27 (128 MB) unless `window_log` says
otherwise, so a stream of unknown size buffers that much; the input's size
shrinks it in one-shot and pledged frames; `Stream` takes the same
`advanced` plus `src_size_hint` (`ZSTD_c_srcSizeHint`: parameters for an
unknown size chosen as for about that many bytes), and so does
`FrameWriter`. A value outside libzstd's bounds is
`error.ParameterOutOfBound`. `writeSkippableFrame` writes a skippable frame
(`ZSTD_writeSkippableFrame`).

Compressing with a dictionary — the same bytes as libzstd with the
dictionary set the same way:

```zig
// Digest it once (ZSTD_createCDict): for many frames and contexts.
var cd = try zstd.CDict.init(gpa, dict_bytes, 3); // raw content, or a `zstd --train` dictionary
defer cd.deinit();
const n = try c.compress(buf, data, .{ .level = 3, .dictionary = .{ .cdict = &cd } });
// Or: .{ .raw = .{ .bytes = dict_bytes } }      (ZSTD_CCtx_loadDictionary: copied, digested per call)
//     .{ .prefix = .{ .bytes = previous_version } } (ZSTD_CCtx_refPrefix: this frame only)
// and c.compressUsingDict(buf, data, dict_bytes, level) / c.compressUsingCDict(buf, data, &cd, .{}).
```

The frame carries the dictionary's ID (`advanced.dict_id_flag = false`
leaves it out); a decoder needs the same dictionary. `StreamOptions` takes
the same `dictionary` (a `.prefix` for its first frame only). For small
inputs — up to 8, 16 or 32 KB by strategy — and streams of unknown size,
libzstd attaches a `CDict` instead of copying it and searches it in
place, for every strategy now (`fast`, `dfast`; `greedy`, `lazy`, `lazy2`,
`btlazy2`; the optimal parsers `btopt`, `btultra`, `btultra2`) --
`advanced.force_attach_dict = .copy` still gets libzstd's bytes for the
copy instead, on any strategy. `CDict.initAdvanced` takes a content type
(`.auto`, `.raw_content`, `.full`) and advanced parameters, among them
`enable_dedicated_dict_search` (libzstd's dedicated dictionary search:
for `greedy`..`lazy2`, a CDict with a bucketed table 4x the size, always
attached; also on a context for its own `.raw` CDict); see SPEC.md,
*Dictionaries*.

Errors: `LevelUnsupported` (level > 22), `ParameterOutOfBound`, `NoSpaceLeft`
(`dst` below `compressBound`), `OutOfMemory`, and with a dictionary
`DictionaryCorrupted`, `DictionaryWrong`, `DictAttachUnsupported`. There is no input size limit: past 3500 MiB
the indices are rescaled as libzstd does (the whole input still has to be in
memory, and so does its `compressBound`).

### Dictionary training (`zstd.dict_builder`)

libzstd's trainers (`zdict.h`), single-threaded, giving the same finished
zstd dictionaries byte for byte: `train` is `ZDICT_trainFromBuffer` (what
`zstd --train` does: fastCover, d = 8, k tried in 4 steps from 50 to 2000,
level 3).

```zig
const db = zstd.dict_builder;
// samples back to back, and their sizes -- libzstd's representation
const s: db.Samples = .{ .buffer = all_samples, .sizes = sample_sizes };
var dict: [16 * 1024]u8 = undefined;
const n = try db.train(gpa, &dict, s); // the dictionary is dict[0..n]
// fixed parameters: k required, d = 8 by default (fastCover: 6 or 8)
const n2 = try db.trainFastCover(gpa, &dict, s, .{ .k = 200, .level = 19 });
const n3 = try db.trainCover(gpa, &dict, s, .{ .k = 200, .d = 6 });
// the optimizers (libzstd's defaults for k, d, steps; the chosen k, d back)
const o = try db.optimizeCover(gpa, &dict, s, .{ .steps = 8 });
// ... on 8 threads: the same dictionary (gpa must be thread-safe)
const o8 = try db.optimizeCover(gpa, &dict, s, .{ .steps = 8, .nb_threads = 8 });
// samples in separate slices: copied into one buffer first (counted)
const n4 = try db.trainFromSlices(gpa, &dict, slices, .{ .fast_cover = .{ .k = 200 } });
// your own content: header, entropy tables and ID in front of it
const n5 = try db.finalizeDictionary(gpa, &dict, content, s, .{ .level = 3 });
```

`level` is the level the dictionary is meant for (finalization measures its
entropy tables by compressing the samples with it); `dict_id` 0 derives the
ID from the content. As in libzstd, a dictionary that fills the buffer keeps
the *head* of the content when the header needs room. Content only (a
raw-content dictionary): `coverContent` / `fastCoverContent` (and `*Into`).
`getDictId`, `getDictHeaderSize` read a finished one.

Memory: `memory_limit` (default 256 MiB) bounds all the working memory —
content selection (cover: 8 bytes per sample byte, `estimateCoverMemory`;
fastCover: 6 · 2^f bytes, `estimateFastCoverMemory`), finalization and the
optimizers' scoring — but not the dictionary buffer; past it,
`error.MemoryLimitExceeded`. With `nb_threads` it bounds the sum over the
candidates in flight: fewer run at once rather than the answer changing. Other errors are libzstd's:
`ParameterOutOfBound`, `SrcSizeWrong` (fewer than 5 samples, under 8 bytes,
4 GiB and up, sizes past the buffer), `DstSizeTooSmall`,
`DictionaryCreationFailed`, `Generic`, `NoCandidate` (no optimizer candidate
finalized), `LevelUnsupported` (above 22: libzstd clamps). Nothing is
printed (libzstd's `notificationLevel`).

## Tests

`zig build test-zstd` (all three release lanes). The load-bearing one is
`src/golden_test.zig`: every corpus input (`src/testdata/corpus.zig`,
generated, so the repository stores none) is compressed at levels -5, -1 and
1–10 with and without checksum, and — up to 600 KB, without checksum — at
11–22; each frame's length and SHA-256 must equal what libzstd 1.5.7 produced
(`src/testdata/goldens.zig`, written by `tools/gen-goldens.sh`). The corpus
is built for coverage: each size tier of the level table, RLE blocks, literal
and match lengths past 0xFFFF, both pre-splitters, the post-splitter, offsets
beyond the window, long-distance matching (switched on through
`Advanced.long_distance_matching`, as it only switches itself on above 64 MB), and cases constructed
so that specific decisions are marginal (see SPEC.md, *Anchoring*). All
the frames come from one reused context, so every golden also checks
context reuse (libzstd gives a reused context's frames the same bytes as a
fresh one's). The module is `heavy` in `build.zig`:
its tests run at ReleaseSafe when Debug is asked for (Debug takes ~2 min 15 s,
ReleaseSafe ~1 min with the build); `-Dstrict-debug` forces Debug.

`src/stream_test.zig` does the same for streaming: 72 cases, each a schedule of calls
(pledged and unknown sizes, flushes, 50-byte outputs, windows down to 1 KB
so libzstd's input buffer wraps, index overflow correction run often, long-distance
matching switched on by hand; 24 of them found by mutation testing) over
corpus inputs at levels -10 … 22, with and without checksum — 586 streams,
each equal in length and SHA-256 to what `ZSTD_compressStream2` produced
(`src/testdata/stream_goldens.zig`, `tools/zstream.c` driving libzstd).

`src/param_test.zig` does it for the advanced parameters: 64 cases (an
input, a `name=value` list of libzstd parameters, levels) — 125 frames equal
to what `ZSTD_compress2` produced with the same parameters set
(`src/testdata/param_goldens.zig`); 15 more stream cases carry parameters
too. It also pins the bounds of every parameter, magicless frames both ways
and the content-size flag.

The decoder is checked by decoding every golden and streaming frame back to
its input, by `src/decoder_test.zig` (frame structure, the size queries and
every error a malformed frame produces, each checked against libzstd) and
`src/dstream_test.zig` (streaming under 1-byte and random call patterns,
the window limit, stable output, the `Reader`), and
off-line against libzstd's decoder through `tools/zdec.c` (see SPEC.md,
*Anchoring*).

`src/dict_golden_test.zig` does it for dictionary training: 54 runs (13
generated sample sets, `src/testdata/dict_samples.zig`, × cover and
fastCover parameters, capacities, split points; refusals included), each
content equal in length and SHA-256 to what libzstd's trainer placed in the
buffer before finalization (`src/testdata/dict_goldens.zig`,
`tools/ztrain.c` calling the trainers' internal steps).

`src/dict_test.zig` does it with dictionaries: 74 cases (an input, a
dictionary — raw content from the corpus generators, two trained by
libzstd's `ZDICT_trainFromBuffer` and committed as `src/testdata/*.zdict`,
those with 1-, 2- and 4-byte IDs, and a hand-built one whose tables all
need checking — the way it is used, content type, parameters, levels
−5…22) — 326 frames and streams equal to libzstd's
(`src/testdata/cdict_goldens.zig`), which the recipe also decodes back
with the dictionary.

`src/context_test.zig` pins the estimates (exact, and the largest for an
unknown size), a static workspace's bound, the workspace being replaced
when too small or long too big, and indexing restarting near its limit.

`src/fuzz_test.zig` round-trips arbitrary input through std's decoder and
this one, and feeds the decoder arbitrary bytes; unit
tests cover the FSE normalisation, Huffman depth limiting, bit writer and
parameter selection.
