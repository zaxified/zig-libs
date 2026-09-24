# `zstd` verification instruments

Five instruments that check this module against **libzstd itself**. They live
here and not in `src/` because they need a C compiler and a libzstd checkout,
which a module must never require (`CONVENTIONS.md` §9). Neither is wired into
`zig build`; run them by hand.

| file | kind (§9) | what it answers |
|---|---|---|
| `gen-goldens.sh` + `dump_corpus.zig` | **recipe** for committed goldens | Writes `src/testdata/goldens.zig`: for every case in `src/testdata/corpus.zig`, level and checksum setting, the length and SHA-256 of the frame libzstd emits; `src/testdata/stream_goldens.zig`, the same for every `corpus.stream_cases` schedule through `zstream`; and `src/testdata/param_goldens.zig`, for every `corpus.param_cases` entry with its advanced parameters through `zref`. |
| `zstream.c` | **differential oracle** (streaming) | Compresses any file with `ZSTD_compressStream2` following a call schedule (`p` pledge, `w` window log, `o` output buffer size, `c`/`f`/`e` continue/flush/end with the next N bytes, `x` frequent overflow correction, `name=value` an advanced parameter by libzstd's name); `stream_test.zig` parses the same schedules. The recipe uses it for `src/testdata/stream_goldens.zig` and builds it a second time as `zstream-ocf`. |
| `zdec.c` | **differential oracle** (decoder) | Decompresses any file with libzstd — mode 0 one-shot `ZSTD_decompressDCtx` into `ZSTD_decompressBound` bytes (the capacity `Decompressor` gets from the same query), mode 1 streaming with window log max 31, whole input at once (libzstd then takes its single-pass shortcut), mode 2 streaming one input byte per call into a 997-byte output buffer (no shortcut: the plan `DecompressStream` is compared under) — and prints `OK <size> <fnv1a64>` or `ERR <ZSTD_ErrorCode>`, so a run of both decoders over valid and damaged frames compares output, acceptance and error class. With a repetition count it times the decode alone. Pair it with libzstd's own `tests/decodecorpus` (`make -C "$R/tests" decodecorpus`), which writes random valid frames that reach every decoder path, and their contents. |
| `zreuse.c` | **differential oracle** (context reuse) | Compresses random slices of a file at random levels and parameters, one-shot and streaming, on a reused `ZSTD_CCtx` and on a fresh one, and reports any frame that differs. The golden tests run every frame through one reused context against fresh-context goldens, which is sound only while libzstd answers "no difference" (SPEC.md, *Contexts*: 1 960 frames, none, on v1.5.7); re-run it when the pinned version changes. |
| `zref.c` | **differential oracle** | Compresses any file the way this module does (one-shot `ZSTD_compress2`, content size on, optional checksum), so any input can be compared, not only the corpus. Optional arguments: the strategy (`ZSTD_c_strategy`), LDM by hand, the window log (`ZSTD_c_windowLog`), and a `name=value` list of any advanced parameter (`zstd.Advanced`). Built a second time with `-DZSTD_WINDOW_OVERFLOW_CORRECT_FREQUENTLY=1` (`zref-ocf`), it is the reference for frequent index-overflow correction. |

## The reference they need

    R=.zig-cache/zstd-ref            # disposable: the recipe re-clones it
    git clone --depth 1 --branch v1.5.7 https://github.com/facebook/zstd.git "$R"
    make -C "$R/lib" libzstd.a
    cc -O2 -I "$R/lib" -o "$R/zref" modules/zstd/tools/zref.c "$R/lib/libzstd.a"
    cc -O2 -I "$R/lib" -o "$R/zdec" modules/zstd/tools/zdec.c "$R/lib/libzstd.a"
    cc -O2 -I "$R/lib" -o "$R/zreuse" modules/zstd/tools/zreuse.c "$R/lib/libzstd.a"
    "$R/zreuse" some-file 1 300 2 -7 22   # frames 300 diffs 0

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
    # module side: zstd.compress(..., .{ .level = L,
    #     .advanced = .{ .strategy = .btopt } })

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
    #     .advanced = .{ .window_log = 12 }, .overflow_correct_frequently = true })

Any of libzstd's advanced parameters goes in as the last argument, by
libzstd's names, `name=value`, comma-separated (switches 0 auto, 1 enable,
2 disable; `-` for none) — the grammar of `corpus.param_cases`, which
`param_test.zig` reads into `zstd.Advanced`:

    "$R/zref" 5 0 in.bin ref.zst 0 0 0 "useRowMatchFinder=2,hashLog=12,maxBlockSize=4096"
    # module side: zstd.compress(..., .{ .level = 5, .advanced = .{
    #     .row_match_finder = .disable, .hash_log = 12, .max_block_size = 4096 } })

A correction only drops indices that have left the window, so the frame is
the same as without it: the test also reads `frame.Options.
overflow_corrections` to know the correction ran. The real threshold is
checked by comparing a > 3500 MiB input with plain `zref`.

## Comparing a stream

    cc -O2 -I "$R/lib" -o "$R/zstream" modules/zstd/tools/zstream.c "$R/lib/libzstd.a"
    "$R/zstream" 3 0 in.bin ref.zst "w12,o100,c50000,f0,c*,e0"
    # module side: the same schedule through zstd.Stream (`run` in
    # src/stream_test.zig does exactly this), then: cmp ref.zst ours.zst

The bytes depend on the schedule, not only the input: where chunks end
(every block's worth of buffered input, every flush and the end), when the
input buffer (one window plus one block) wraps — the window log `w` makes
that happen within kilobytes — and whether the end finds the buffer empty
and room for `compressBound` of the rest in the output, in which case it is
compressed straight from the caller's input. The output buffer size `o`
matters only for that last condition.
