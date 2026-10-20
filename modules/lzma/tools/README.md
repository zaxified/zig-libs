# lzma — tools

Recipes for the instruments that check this module against liblzma 5.8.1, the `xz` program and
Python's `lzma` (CONVENTIONS.md §9). The reference is **driven, not vendored**: its source is
cloned into the gitignored `.zig-cache/survey/lzma/xz` and never built with its own build system.

| File | What |
|---|---|
| `build-oracle.sh` | `git clone --depth 1 --branch v5.8.1 https://github.com/tukaani-project/xz.git .zig-cache/survey/lzma/xz` (pinned commit `a522a226545730551f7e7c2685fab27cf567746c`) if absent, then `cc -O2` of the library sources it needs (the macros its CMake would define are passed on the command line) with `c_oracle/lzref.c` and `c_oracle/lzbench.c` into `.zig-cache/lzma-oracle/`. Needs `git` (first run) and `cc`. |
| `c_oracle/lzref.c` | The black-box driver: `lzref enc FORMAT SPEC CHECK in out` (liblzma's `lzma_stream_encoder` / `lzma_alone_encoder` / `lzma_raw_encoder`, fed the whole input then `LZMA_FINISH`, the way `xz` and Python do), `lzref dec FORMAT in out` (verdict line and output), `lzref raw1 PROPS SIZE EOPM in out`. |
| `interop.zig` | `zig build interop-lzma [-- --capture] [-- --quick] [-- --decoder] [-- --encoder]`: our decoder on liblzma's, the `xz` program's and Python's streams (every check type, `.lzma`, raw LZMA1 with and without the end marker, raw LZMA2, multi-block, threaded), stream boundaries and 6000 mutated streams (verdicts and outputs must equal liblzma's); our encoder's bytes against liblzma's for 32 input shapes, the presets 0..9 and `-e`, custom lc/lp/pb/dictionary/mode/finder/nice/depth, in all four formats. `--capture` freezes liblzma's digests and small reference streams into `src/testdata/` (`src/golden_test.zig` replays them offline). Needs `python3` and `xz`. |
| `bench.zig`, `c_oracle/lzbench.c` | `zig build bench-lzma`: wall-time ratios against liblzma on seeded text and binary payloads (`LZMA_BENCH_MIB`, default 2; `BENCH_ROUNDS`). Needs `zig cc` and the clone. |

The clone's licence (0BSD, `COPYING`) was read before any source was; the sources are read for the
port recorded in `../NOTICE`.
