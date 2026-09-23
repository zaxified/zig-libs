# `zstd` — changelog

Newest first. See the root [`CHANGELOG.md`](../../CHANGELOG.md) for which
release tag each entry shipped in, and `CONVENTIONS.md` §8 for the policy.

## Unreleased

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
