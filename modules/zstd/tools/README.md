# `zstd` verification instruments

Two instruments that check this module against **libzstd itself**. They live
here and not in `src/` because they need a C compiler and a libzstd checkout,
which a module must never require (`CONVENTIONS.md` §9). Neither is wired into
`zig build`; run them by hand.

| file | kind (§9) | what it answers |
|---|---|---|
| `gen-goldens.sh` + `dump_corpus.zig` | **recipe** for committed goldens | Writes `src/testdata/goldens.zig`: for every case in `src/testdata/corpus.zig`, level and checksum setting, the length and SHA-256 of the frame libzstd emits. |
| `zref.c` | **differential oracle** | Compresses any file the way this module does (one-shot `ZSTD_compress2`, content size on, optional checksum), so any input can be compared, not only the corpus. Optional arguments: the strategy (`ZSTD_c_strategy`), LDM by hand, the window log (`ZSTD_c_windowLog`). Built a second time with `-DZSTD_WINDOW_OVERFLOW_CORRECT_FREQUENTLY=1` (`zref-ocf`), it is the reference for frequent index-overflow correction. |

## The reference they need

    R=.zig-cache/zstd-ref            # disposable: the recipe re-clones it
    git clone --depth 1 --branch v1.5.7 https://github.com/facebook/zstd.git "$R"
    make -C "$R/lib" libzstd.a
    cc -O2 -I "$R/lib" -o "$R/zref" modules/zstd/tools/zref.c "$R/lib/libzstd.a"

Tag `v1.5.7` is commit `f8745da6ff1ad1e7bab384bd1f9d742439278e99`;
`gen-goldens.sh` refuses any other checkout. Nothing is copied out of the tree
into the goldens except lengths and digests of libzstd's *output*.

⚠ **Compare against `ZSTD_compress2`, not the `zstd` CLI.** The CLI feeds the
library through its streaming API, which blocks the input differently (a
pre-split decision is taken on each 128 KB input buffer, not on the whole
input), so its frames legitimately differ from one-shot output. Measured on a
13.7 MB CSV at level 1: CLI 803 211 bytes, `ZSTD_compress2` 803 403.

## Regenerating the goldens

    ZSTD_REF=<dir> modules/zstd/tools/gen-goldens.sh   # default dir as above

Needed when `src/testdata/corpus.zig` changes (a new case, or a generator
change — `golden_test.zig` pins a digest of all corpus inputs, so the latter
cannot happen silently). The recipe prints the row count; it must equal what
`corpus.covered` admits: cases × 12 levels (-5…10) × 2, plus the cases up to
600 KB × 11 levels (11–21) without checksum.

## Comparing an arbitrary file

    "$R/zref" <level> <checksum 0|1> in.bin ref.zst
    # and the same input through this module (e.g. a three-line main around
    # zstd.compressAlloc), then: cmp ref.zst ours.zst

The level table keeps some strategy/parameter pairs out of every level's
reach (`fast` never gets a window above 1 MB, `btopt` never the 8 MB window
of level 19). To reach one, force the strategy on both sides:

    "$R/zref" <level> 0 in.bin ref.zst 7          # 7 = btopt
    # module side: frame.compress(..., .{ .level = L, .checksum = false,
    #     .strategy = .btopt }) from a main that imports src/frame.zig

libzstd then derives the parameters twice — once for the level's own
strategy, once for the forced one — and `params.getOverridden` does the
same; comparing against a single derivation gives false mismatches.

Long-distance matching switches itself on only at level 22 above 64 MB. To
reach it on a small input, switch it on by hand on both sides (strategy 0
keeps the level's own):

    "$R/zref" <level> 0 in.bin ref.zst 0 1        # ZSTD_c_enableLongDistanceMatching
    # module side: frame.compress(..., .{ .level = L, .checksum = false,
    #     .ldm = true }); btopt and up only (levels 16+, or a forced strategy)

By hand, libzstd first resets the window log to 27 and only then shrinks it to
the input; `params.getOverridden` does the same.

Index overflow correction happens by itself only once an index passes
`ZSTD_CURRENT_MAX` (3500 MiB). libzstd's fuzzing build corrects whenever it
safely can instead; `gen-goldens.sh` builds that variant from the sources as
`$R/zref-ocf`. With a small window set by hand it corrects many times on an
input of kilobytes:

    "$R/zref-ocf" <level> 0 in.bin ref.zst 0 0 12   # window log 12
    # module side: frame.compress(..., .{ .level = L, .checksum = false,
    #     .window_log = 12, .overflow_correct_frequently = true })

A correction only drops indices that have left the window, so the frame is
the same as without it: the test also reads `frame.Options.
overflow_corrections` to know the correction ran. The real threshold is
checked by comparing a > 3500 MiB input with plain `zref`.
