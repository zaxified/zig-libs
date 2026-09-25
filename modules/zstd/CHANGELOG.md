# `zstd` — changelog

Newest first. See the root [`CHANGELOG.md`](../../CHANGELOG.md) for which
release tag each entry shipped in, and `CONVENTIONS.md` §8 for the policy.

## Unreleased

- **2026-09-25** — **BREAKING:** dictionary training now gives finished
  zstd dictionaries (SPEC backlog Z5b). `zstd.dict_builder` gains
  `finalizeDictionary` (`ZDICT_finalizeDictionary`, its entropy tables
  measured by compressing the samples through the attached content),
  `addEntropyTablesFromBuffer`, `getDictId`, `getDictHeaderSize`,
  `selectDict` (`COVER_selectDict`, with shrinking), and the complete
  trainers `trainCover` / `trainFastCover` (`ZDICT_trainFromBuffer_cover`
  / `_fastCover`), `optimizeCover` / `optimizeFastCover` (the optimizers,
  single-threaded) and `train` (`ZDICT_trainFromBuffer`), plus
  `trainFromSlices` for samples in separate slices (copied, counted
  against the ceiling). Renamed: Z5a's content-only `trainCover*` /
  `trainFastCover*` are now `coverContent*` / `fastCoverContent*`, the
  scorer-taking `optimizeCover` / `optimizeFastCover` are
  `optimizeCoverWith` / `optimizeFastCoverWith`. `d` defaults to 8; the
  params structs gain `level` and `dict_id`; `memory_limit` (still 256
  MiB) now bounds all working memory, finalization and scoring included
  (not the dictionary buffer). 63 finished dictionaries byte-identical to
  libzstd 1.5.7 through the new oracle `tools/zfinal.c`.
  `frame.Compressor` gains `beginUsingCDict` / `compressBlockOnly` /
  `seqStore` (block mode, internal).

- **2026-09-25** — **BEHAVIOURAL, not breaking (bug fix):** `Options.
  dictionary = .raw` (one-shot and `Stream`) now copies the dictionary
  into the context's own `CDict`, as `ZSTD_CCtx_loadDictionary` does
  (`ZSTD_dlm_byCopy`); it referenced the caller's bytes. With the input
  placed right after the dictionary in memory, the window continued into
  the input and the frame differed from libzstd 1.5.7's whenever the
  CDict was copied or loaded anew (not attached). Output for any other
  placement is unchanged. Goldens `load-adjacent-copy`,
  `load-adjacent-force-copy`, `load-adjacent-force-load` and
  `cdictref-adjacent-copy` (a by-reference CDict is continued, in libzstd
  too); `tools/zref.c` gained the `loadadj`, `cdictref` and `cdictrefadj`
  modes. The context's CDict costs one copy of the dictionary more.

- **2026-09-25** — **NO CONSUMER-VISIBLE CHANGE:** `cdict_goldens.zig`
  regenerated after rebasing D1 onto D2 and Z2c's merges; +141 rows
  (D2's own cases), the rest byte-identical.

- **2026-09-25** — **NO CONSUMER-VISIBLE CHANGE:** D1's random diff loop
  (≥3000 cases vs libzstd, fast/dfast attach) and mutation-sweep hunt
  added 8 golden cases (`attach-dfast-cross-end`, `surv-m12-fast`,
  `surv-m17-fast`, `surv-m22-dfast`, `surv-m23-dfast`, `surv-m24-dfast`,
  `surv-m25-dfast`, `surv-m27-dfast`) and a `DictDef.Source.literal`
  variant (test-only, `pub` so `dump_corpus.zig` can read it) for exact
  hunted byte sequences a generator would not reproduce; no behaviour
  change outside the test corpus.

- **2026-09-25** — **BEHAVIOURAL, not breaking:** two Z2c corners now match
  libzstd exactly instead of an earlier, unverified reading of it (both
  confirmed empirically against libzstd 1.5.7 through `tools/zdec.c`, not
  just read from its source — see SPEC.md, *Decoder*). One-shot
  `Decompressor.decompress` with `Options.ddicts` set now fixes ONE
  dictionary (`.ddict` if set, else `ddicts`' last entry) for content and
  entropy across the whole call, re-selecting only each frame's dictID for
  validation, matching libzstd's own `ZSTD_decompress_usingDDict`/
  `ZSTD_decompressDCtx` (confirmed with five adversarial concatenated-
  frame cases: libzstd never produced silently wrong output, only a clean
  refusal or the correct result, so this port matches exactly rather than
  keeping the more useful fresh-per-frame selection an earlier version
  had). `selectDDict` no longer exempts a dictID-0 frame from `ddicts`
  selection: libzstd's hash set uses dictID 0 as both its empty-slot
  sentinel and a real raw-content dictionary's ID, so a dictID-0 frame
  genuinely can match one. A `refPrefix`-lifetime KAT closes the third:
  an intervening skippable frame consumes a one-shot `Options.prefix`,
  same as libzstd, confirmed with a test (this one was already matched in
  the prior entry's implementation, just not anchored by a test until
  now). Mutation sweep of `ddict.zig` and the decoder's dictionary
  plumbing widened from 14 to 48 mutations (every bounds/length check and
  error branch of `loadDEntropy` and its header parsing, the content-type
  dispatch, dictID checks and selection, history/entropy setup in
  one-shot and streaming, `refPrefix`'s lifetime): 43 killed, 4 equivalent
  (proven, not just asserted — see SPEC.md, *Open*), 1 hunted extensively
  and not found (dictionary repeat-offsets never reaching the decoder;
  SPEC.md explains why a compression-based hunt could not reach it). 8 new
  KATs in `testdata/dict_kats.zig`, three of them the ones originally left
  as "needs a hand-built dictionary" in the prior entry.

- **2026-09-24** — **BEHAVIOURAL, not breaking:** a `CDict` of strategy
  `greedy`, `lazy`, `lazy2` or `btlazy2` is now attached where libzstd
  attaches it (inputs up to 32 KB, unknown sizes, `force_attach_dict =
  .attach`) and searched in place, byte-identical to libzstd 1.5.7 (SPEC
  backlog Z4, part D2: the `dictMatchState` variants of the hash chain, the
  row match finder and the DUBT); those calls no longer fail with
  `error.DictAttachUnsupported`, which remains for the other strategies.
  141 attached frames and streams in the goldens, 6 660 random ones
  identical.

- **2026-09-24** — Compression with a dictionary attached to the optimal
  parsers (SPEC backlog Z4, part D3): where libzstd attaches a `CDict`
  (inputs up to 32 KB for `btopt`, 8 KB for `btultra` / `btultra2`,
  unknown sizes, `force_attach_dict = .attach`), `btopt`, `btultra` and
  `btultra2` now search it in place (`zstd_opt.c`'s `dictMatchState`
  mode: repcodes into the dictionary, the CDict's binary tree) instead of
  failing with `error.DictAttachUnsupported`; attached `btultra2` runs
  `btultra`, as in libzstd. Long-distance matching with a loaded raw
  dictionary gets a golden case that needs its LDM entries. 118 new
  dictionary frames and streams (26 cases, `corpus.dict_cases_attach_opt`)
  byte-identical to libzstd 1.5.7; 5 085 random frames and streams
  identical (1 985 of them through an attached CDict); a 50-mutation
  sweep: 34 caught, 5 equivalent, 10 uncovered (SPEC.md). The
  dictionary goldens gain a `slice` dictionary source (a piece of an
  input).

- **2026-09-24** — **NO CONSUMER-VISIBLE CHANGE:** `corpus.dict_cases_attach_fast`,
  a test-only corpus array (`pub` only so `tools/dump_corpus.zig` can read
  it) for the previous entry's attach goldens; nothing a consumer of the
  module observes.

- **2026-09-24** — Compression with a dictionary, attach for `fast` and
  `dfast` (SPEC backlog Z4, part D1): where libzstd would attach a `CDict`
  in place (inputs under 8/16 KB, unknown sizes) rather than copy it,
  this now happens for the `fast` and `dfast` strategies (levels 1–4ish,
  and every negative level), matching libzstd byte-for-byte; every other
  strategy still refuses with `error.DictAttachUnsupported` until its own
  `dictMatchState` variant lands (D2, the hash-chain/row/DUBT family).

- **2026-09-24** — Compression with a dictionary (SPEC backlog Z4, part
  D0): `CDict` (`init` = `ZSTD_createCDict`, `initAdvanced` =
  `ZSTD_createCDict_advanced2`), `Options.dictionary` /
  `StreamOptions.dictionary` (`.raw` = `ZSTD_CCtx_loadDictionary_advanced`,
  `.cdict` = `ZSTD_CCtx_refCDict`, `.prefix` = `ZSTD_CCtx_refPrefix_advanced`),
  `Compressor.compressUsingDict` / `compressUsingCDict`, raw-content and
  full zstd dictionaries (`DictContentType`), the dictionary ID in the
  header, and `Advanced.dict_id_flag`, `force_attach_dict`,
  `deterministic_ref_prefix`, `force_max_window`. A CDict is copied into
  the context or its content loaded anew, as libzstd chooses; where
  libzstd would **attach** it (inputs up to 8–32 KB by strategy, unknown
  sizes) the call fails with `error.DictAttachUnsupported` for now. 326
  dictionary frames and streams byte-identical to libzstd 1.5.7 (all
  levels), 2 700 random ones identical on the first run. `zref.c` /
  `zstream.c` take a dictionary; `zdtrain.c` trains the committed ones.

- **2026-09-24** — Dictionary training, content selection (SPEC backlog
  Z5a): `zstd.dict_builder` ports libzstd's cover and fastCover trainers
  (`cover.c`, `fastcover.c`) up to, not including, finalization.
  `trainCover` / `trainFastCover` (and `*Into`, which leaves the content at
  the tail of the caller's buffer where libzstd places it) return the
  dictionary content `ZDICT_trainFromBuffer_cover` / `_fastCover` pick,
  byte for byte -- usable as a raw-content dictionary. Exact memory
  estimates (`estimateCoverMemory`, `estimateFastCoverMemory`) and a
  `memory_limit` ceiling (default 256 MiB) refused with
  `error.MemoryLimitExceeded` before any allocation. The optimizer's
  (d, k) grid (`optimizeCover`, `optimizeFastCover`) runs with the
  compression-based score supplied by the caller. 54 golden runs
  (content digests and refusals) byte-identical to libzstd 1.5.7 through
  the new oracle `tools/ztrain.c`; 2 450 random runs identical (two
  deliberate refusals apart); a 92-mutation sweep: 84 caught, 8
  equivalent (SPEC.md).

- **2026-09-24** — **NO CONSUMER-VISIBLE CHANGE:** dictionary decoder test
  fixtures (`src/testdata/dict_kats.zig`, generated by
  `tools/gen-dict-testdata.sh`) and `tools/zdec.c` dict-spec arguments,
  landed as their own commit alongside the Z2c entry below; `pub` on the
  fixture file's byte-array constants is an artifact of it living under
  `src/`, not a public API.

- **2026-09-24** — Decoding with a dictionary (SPEC backlog Z2c): raw-content
  and zstd-format dictionaries, a digested `DDict` (`zstd.DDict.init` /
  `initByReference`, `.auto`/`.raw_content`/`.full` content types,
  `loadDEntropy`'s Huffman and three FSE tables and repeat offsets, a port
  of `zstd_ddict.c`, `src/ddict.zig`), `Decompressor`'s and
  `DecompressStream`'s `Options.dictionary`/`.ddict`/`.ddicts`/`.prefix`
  (`ZSTD_decompress_usingDict`/`_usingDDict`, `ZSTD_DCtx_loadDictionary` /
  `refDDict`/`refPrefix`, `ZSTD_d_refMultipleDDicts`), and
  `zstd.getDictId`/`getFrameDictId`. A dictionary's content becomes history
  through the same address-based model `checkContinuity` already used
  (`Decompressor.setHistoryFrom`), which needed the continuity check in
  one-shot `decompressFrame` moved to *after* the dictionary is applied
  (was before) — a real ordering bug the mutation sweep confirms: reverting
  it fails 92 of the module's existing tests, dictionaries aside. One
  deliberate divergence, not decided silently: `ddicts`
  (`ZSTD_d_refMultipleDDicts`) picks a dictionary fresh for every frame in
  this port; libzstd's own one-shot `ZSTD_decompress_usingDDict` (by this
  reading of its source) applies whichever dictionary was resolved once
  before the frame loop to every frame's content, only re-validating (not
  re-applying) per frame — see SPEC.md, *Decoder*. Anchored against libzstd
  1.5.7 through an extended `tools/zdec.c` (new `dict-spec` arguments, e.g.
  `full:path.bin`, `auto:`/`raw:`/`prefix:`/`legacy:`) and a new recipe
  `tools/gen-dict-testdata.sh`: 3681 valid (input × level × dictionary kind
  × content type × one-shot/streaming) combinations, a dictID-mismatch case
  and a multi-dictionary-selection case all byte- and error-class-identical;
  a 4000-case random single-byte-corruption run over dictionary-compressed
  frames and dictionaries, 3984 identical, 13 an already-documented
  equivalence (the un-ported prefetching sequence decoder, first actually
  exercised here since a fresh `ZSTD_DCtx` always starts "cold" with a
  dictionary), 3 a throwaway-oracle formatting gap, not a module difference
  (SPEC.md, *Decoder*, *Open*). 14-mutation sweep of the new code: 10
  killed, 1 equivalent, 3 uncovered (justified in SPEC.md, *Open*).
  Compression with a dictionary (Z4) and training one (Z5) are still not
  here; this work's test frames come from libzstd itself.

- **2026-09-24** — `targetCBlockSize` (SPEC backlog Z8):
  `Advanced.target_c_block_size` (`ZSTD_c_targetCBlockSize`, 0 = off,
  values below 1340 count as 1340, above 131072 `ParameterOutOfBound`)
  cuts each block into compressed blocks of about that size — superblocks,
  a port of `zstd_compress_superblock.c` (`src/superblock.zig`) with the
  frame's `ZSTD_compressBlock_targetCBlockSize` path, one-shot, streaming
  and `FrameWriter`. 14 parameter and 7 stream cases (30 frames, 24
  streams) byte-identical to libzstd 1.5.7; 5 200 random inputs identical
  on the first run; a 43-mutation sweep: 24 caught, 4 equivalent, 1
  unreachable, 14 uncovered (SPEC.md). `zref.c` / `zstream.c` take
  `targetCBlockSize`.

- **2026-09-24** — Speed parity with libzstd (SPEC backlog Z11): within
  about 10 % of its CPU cycles at every level, one-shot and streaming (was
  1.2–1.4× at levels −5…3 and 1.3–2.0× at 5–12). The row match finder
  prefetches the rows of the hash 8 positions ahead and each candidate
  (`ZSTD_row_prefetch`), and is specialised on the row log; the match
  finders read the input through `match.Base` (libzstd's `window.base` in a
  register, still bounds-checked in the safe modes) instead of reloading
  `MatchState.src` after every table store; repcode swaps no longer go
  through `std.mem.swap`, which made LLVM spill two hot locals byte by byte
  (16 % of level 1's instructions); `fast`/`dfast` prefetch ahead when
  their step grows. Output unchanged (goldens; 57 frames of 3–12 MB real
  files at levels −7…19 identical to libzstd).

- **2026-09-24** — Long-distance matching as an option (SPEC backlog Z7):
  `Advanced.long_distance_matching` (`ZSTD_c_enableLongDistanceMatching`,
  the CLI's `--long`; `.enable` starts the window log from 27) and
  `ldm_hash_log`, `ldm_min_match`, `ldm_bucket_size_log`,
  `ldm_hash_rate_log` with libzstd's bounds and derivation. Below `btopt`
  the LDM sequences are taken as they come and the level's match finder
  runs between them (`ZSTD_ldm_blockCompress`, `maybeSplitSequence`,
  `ZSTD_ldm_skipSequences`, `ZSTD_ldm_fillFastTables` with
  `ZSTD_fillHashTable` / `ZSTD_fillDoubleHashTable`), one-shot and
  streaming over a two-segment window. The test seams `frame.Options.ldm`
  and `Stream.ldm` are gone (the option replaces them). 13 parameter and 3
  stream cases (28 frames, 28 streams) byte-identical to libzstd 1.5.7;
  3 800 random one-shot and streamed inputs (levels −30…22, random LDM
  and match parameters, windows down to 1 KB) identical on the first run.
  `zref.c` / `zstream.c` take the LDM parameters by name. A 38-mutation
  sweep: 27 caught, 8 unreachable (the sequence cut at a block's end, which
  LDM's per-block sequences never need), 3 equivalent.

- **2026-09-24** — Context reuse and sizing (SPEC backlog Z13):
  `zstd.Compressor` (a reusable `ZSTD_CCtx` for one-shot frames), and
  `Stream` goes on after the end of a frame with the next one (unknown
  size, same options) as libzstd does; `Stream.reset(opts)`
  (`ZSTD_CCtx_reset`) abandons a frame or changes the options.
  `error.FrameEnded` is gone. A context now lives in one workspace, kept
  from frame to frame under libzstd's policy (replaced when too small or
  three times too big for 128 frames; indexing goes on past the last frame,
  tables not cleared, restarting near the index limit); `FrameWriter`
  reuses its context too. `estimateCompressorSize` / `estimateStreamSize`
  give the exact workspace (null / no size: the most any input needs);
  `Compressor.initStatic` / `Stream.initStatic` run in a caller's
  64-byte-aligned workspace (`ZSTD_initStaticCCtx`), `error.OutOfMemory`
  when a frame needs more. The backlog's premise that a reused context
  changes the output was measured false (1 960 frames of libzstd 1.5.7,
  reused vs fresh, no difference), so every golden test now runs through
  one reused context. Reuse saves 16–24 % of instructions on 1–16 KB
  frames at level 3.
- **2026-09-24** — Advanced parameters (SPEC backlog Z6): `Options`,
  `StreamOptions` and `FrameWriterOptions` take `advanced: zstd.Advanced`,
  libzstd's `ZSTD_CCtx_setParameter` set — explicit window, hash, chain and
  search logs, minimum match, target length and strategy (over the level's
  row, derived as `ZSTD_getCParamsFromCCtxParams` does), the content-size
  flag, magicless frames, literal compression, the row match finder, the
  post-splitter, the pre-splitter level and the maximum block size — with
  libzstd's bounds (`error.ParameterOutOfBound`); `StreamOptions.
  src_size_hint` (`ZSTD_c_srcSizeHint`); `writeSkippableFrame`. The decoder
  reads magicless frames (`DecompressOptions.format`,
  `DecompressStreamOptions.format`, `getFrameHeaderAdvanced`). The
  `frame.Options.strategy` / `window_log` and `Stream.window_log` test seams
  are gone (now `advanced`). `param_goldens.zig`: 67 frames of 37 cases
  from libzstd with the same parameters, plus 64 streams; `zref` and
  `zstream` take `name=value` parameters. With literal compression off the
  optimal parsers price literals raw (`ZSTD_compressedLiterals`), and the
  post-splitter's estimate stores them raw — the latter found by the
  differential run, the only mismatch in 4 850 random parameter sets
  (3 300 one-shot, 1 550 streams). 47 mutations: 43 caught, 4 equivalent.
- **2026-09-23** — Streaming decompression (SPEC backlog Z2b):
  `DecompressStream` (`ZSTD_decompressStream`: input and output in any
  pieces, output ring of one window plus two blocks or `stable_output`,
  `window_log_max` defaulting to libzstd's 2^27 + 1, hostage byte, the
  single-pass shortcut, the no-progress error), `DecompressReader` (a
  `std.Io.Reader` over another reader) and `Decompressor.decompressContinue`
  (`ZSTD_decompressContinue`). History across output buffers follows
  libzstd's `ZSTD_checkContinuity`. The one-shot decoder now bounds a
  block's output exactly where libzstd's does (by where it would have put
  the literals), no longer by the block maximum for raw and RLE blocks —
  the difference Z2a documented is gone. `tools/zdec.c` mode 2 streams one
  byte per call; one-shot and streaming each agree with libzstd on
  35 662 valid and damaged frames. `decode_kats.zig`: the window-mantissa
  frame no longer pins anything under the new bound (a header test does),
  and one frame joins for literals read in place; 11 frames. A 26-mutation
  sweep of the streaming code: 19 caught, 7 survivors in SPEC.md.

- **2026-09-23** — Decoder (SPEC backlog Z2a): a port of libzstd's one-shot
  decoder — `Decompressor`, `decompress`, `decompressAlloc`, content
  checksum verification (`DecompressOptions.ignore_checksum` to skip it),
  concatenated and skippable frames, and the frame queries
  (`getFrameHeader`, `frameHeaderSize`, `getFrameContentSize`,
  `findFrameCompressedSize`, `findDecompressedSize`, `decompressBound`,
  `decompressionMargin`, `readSkippableFrame`, `getDictIdFromFrame`,
  `isFrame`, `isSkippableFrame`). Errors are named after `ZSTD_error_*`.
  1.04–1.05× libzstd's decode time (std's decoder: 30×). Checked against
  libzstd through the new oracle `tools/zdec.c`: 13 600 random valid frames
  from libzstd's `decodecorpus` and the CLI's `--long`/multithreaded frames
  decode identically; of 5 000 damaged frames none crashed or decoded
  differently, and every one libzstd refused was refused. One deliberate
  difference on malformed frames: a raw or RLE block larger than the
  block maximum is refused (as RFC 8878 and libzstd's streaming decoder
  do; libzstd's one-shot decoder lets it through). Golden and streaming
  tests now decode every frame back; `decoder_test.zig` covers frame
  structure and the errors; a new fuzz target feeds the decoder arbitrary
  bytes. A 64-mutation sweep of the decoder plus a hunt over 45 000
  frames added `testdata/decode_kats.zig` (11 damaged frames, each pinning
  a decision nothing else reached); the equivalent survivors and three
  reachable-but-unemitted cases are listed in SPEC.md.

- **2026-09-23** — Streaming at every level (SPEC backlog Z1c): the binary
  tree of `btopt`/`btultra`/`btultra2` and the 3-byte hash across a
  two-segment window, and long-distance matching over its own two-segment
  window (`ZSTD_window_update` on the LDM window, forward and backward
  counts across the boundary). `stream_max_level` equals `max_level`. New
  test seam `Stream.ldm` / schedule token `l` (LDM by hand, as
  `ZSTD_c_enableLongDistanceMatching`); level 22 on an unknown-size 150 MB
  stream (window 128 MB wrapped, LDM on by itself) matched libzstd.

- **2026-09-23** — Streaming up to level 10 (SPEC backlog Z1b): the extDict
  parser of `greedy` … `btlazy2` (`ZSTD_compressBlock_lazy_extDict_generic`)
  and the hash-chain, row and binary-tree searches across two segments.
  `stream_max_level` is 10. Streaming goldens gain 13 cases at levels 4–10
  (per-case level lists in `corpus.stream_cases`; 6 found by a schedule
  search against a 22-mutation sweep, 2 survivors equivalent), and 1 600
  random schedules at levels -5…10 matched libzstd.

- **2026-09-23** — Streaming (SPEC backlog Z1, first part): `zstd.Stream`,
  a port of `ZSTD_compressStream2` / `ZSTD_compressStream_generic` with
  buffered input and output — `continue`/`flush`/`end`, pledged or unknown
  size (no content size in the header then), the input buffer of one window
  plus one block and its wrap, the end compressed straight from the
  caller's buffer — byte-identical to libzstd for the same calls, at levels
  ≤ 3 (`stream_max_level`). The wrap makes the window two segments:
  `ZSTD_window_update`, `ZSTD_count_2segments` and the extDict variants of
  `fast` and `dfast` are ported; overflow correction moves both segments.
  The one-shot path now runs through the same context (`frame.Compressor`,
  one chunk), its goldens unchanged. Anchored by 310 streaming goldens (new
  `tools/zstream.c`, driven by a call schedule both sides parse; the recipe
  also builds it with frequent overflow correction), checks that the extDict
  search and the correction ran, a 59-mutation sweep (16 survivors, reasons
  in SPEC.md), a streaming fuzz harness, and 1 150 schedules compared with
  libzstd (files up to 6 MB and random schedules). One-shot compression costs +4.5 %
  instructions (the prefix's first index is now a variable).

- **2026-09-23** — Index overflow correction (SPEC backlog Z3):
  `ZSTD_window_correctOverflow` with the table reductions of the match state
  (hash, chain / binary tree keeping `btlazy2`'s unsorted mark, 3-byte hash)
  and of the LDM window, so inputs past 3500 MiB compress as libzstd does.
  `max_input_size` and `error.InputTooLarge` are gone. Anchored by 13 golden
  cases compressed with a small window (new `frame.Options.window_log` seam,
  `ZSTD_c_windowLog`) and correction run often (`frame.Options.
  overflow_correct_frequently`, against libzstd built with
  `ZSTD_WINDOW_OVERFLOW_CORRECT_FREQUENTLY`), a check that the corrections
  ran, 13 mutations all caught, and a 4.4 GB input identical to libzstd.
  `tools/zref.c` takes the window log as a seventh argument.

- **2026-09-23** — `FrameWriter`: a `std.Io.Writer` that compresses into
  concatenated one-shot frames, one per buffer fill and per flush (SPEC
  backlog Z1a, the interim before libzstd-identical streaming). Each frame is
  exactly `compress` of its bytes, which is what its tests pin; an empty
  stream is the empty frame.

- **2026-09-22** — Level 22: long-distance matching (`zstd_ldm.c`: gear
  rolling hash, bucketed XXH64 table, sequence generation over its own
  trailing window) and its candidates in the optimal parser
  (`ZSTD_optLdm_*`), which libzstd switches on at level 22 for inputs over
  64 MB (window log 27). `max_level` is 22; `error.LevelUnsupported` now
  means a level above 22. Byte-identical to `ZSTD_compress2()`: the goldens
  grow to 2011 frames (level 22 on the corpus, and 15 cases compressed with
  LDM switched on by hand through the new `frame.Options.ldm` test seam, 10
  of them found by a 47-mutation sweep that leaves 10 reachable equalities
  uncovered, see SPEC.md);
  level 22 was compared with libzstd on 64 MB, 64 MB + 1, 70 MB and 140 MB
  inputs. `tools/zref.c` takes LDM-by-hand as a sixth argument, and
  `params.getWithStrategy` became `params.getOverridden`.
- **2026-09-22** — Levels 11–21: the optimal parsers `btopt`, `btultra`
  and `btultra2` (`zstd_opt.c`: all-matches binary tree, 3-byte hash for
  `minMatch` 3, adaptive price model, forward pricing and backward trace,
  btultra2's statistics-seeding first pass), the post-block splitter
  (`ZSTD_compressBlock_splitBlock` with its size estimates and repcode
  resolution) and optimal Huffman depth from `btultra` on. Byte-identical to
  `ZSTD_compress2()`: the goldens grow to 1941 frames (levels 11–21 without
  the checksum variant on inputs up to 600 KB, plus 14 single-level cases).
  Level 22 is `error.LevelUnsupported` (long-distance matching above 64 MB is
  not ported; `max_level` was 10). A 101-mutation sweep added 14 corpus
  cases; 33 mutations survive with reasons in SPEC.md, 13 of them reachable
  equalities no seed search hit. The golden recipe now reads the covered set
  from `dump_corpus.zig`'s manifest, and `tools/zref.c` can force a strategy.
- **2026-09-22** — Levels 9–10: the `btlazy2` strategy (`zstd_lazy.c`'s
  lazily sorted binary tree, "DUBT", under the existing lazy parser).
  Byte-identical to `ZSTD_compress2()`: the goldens grow to 1344 frames
  (56 inputs × 12 levels × checksum on/off). Levels 11+ remain
  `error.LevelUnsupported` (level 11 is `btopt` for inputs up to 16 KB).
  A 35-mutation sweep added 4 corpus cases; 15 mutations survive with
  reasons in SPEC.md (11 unreachable until levels 11–15 run `btlazy2` on
  larger inputs, 4 equivalent).
- **2026-09-22** — Levels 4–8: the `greedy`, `lazy` and `lazy2` strategies
  (`zstd_lazy.c`: hash-chain and row-based match finders, one lazy parser),
  the priced choice between predefined, repeated and new sequence tables, and
  libzstd's full level tables. Still byte-identical to `ZSTD_compress2()`:
  the goldens grow to 1040 frames (52 inputs × 10 levels × checksum on/off).
  Levels 9+ remain `error.LevelUnsupported` (level 9 is `btlazy2` for inputs
  up to 16 KB). A 43-mutation sweep of the new code added 12 corpus cases; 9
  mutations survive with reasons in SPEC.md, one of them (the 2048-sequence
  pricing switch) a real gap.
- **2026-09-22** — New module: a Zstandard compressor for levels 1–3 and the
  negative levels, translated from libzstd 1.5.7 (`fast`/`dfast`, frame and
  block driver, pre-splitter, Huffman and FSE encoders), whose frames are
  byte-identical to `ZSTD_compress2()`. Anchored externally: 400 golden frames
  (40 generated inputs × 5 levels × checksum on/off) must match libzstd's
  length and SHA-256, regenerated by `tools/gen-goldens.sh` from the pinned
  tag. A 32-mutation sweep drove the corpus: 16 cases exist because a
  deliberate mutation survived without them; 9 mutations still survive, each
  with its reason in SPEC.md (one, a sequence-table threshold at equality, is
  a real gap).
