# bzip2 — tools

Recipes for the instruments that check this module against libbzip2 1.0.8 and Python's `bz2`
(CONVENTIONS.md §9). The reference is **driven, not vendored**: its source is cloned into the
gitignored `.zig-cache/survey/bzip2` and never built with its own Makefile.

| File | What |
|---|---|
| `build-oracle.sh` | `git clone --depth 1 https://sourceware.org/git/bzip2.git .zig-cache/survey/bzip2` (pinned commit `f5dfc96063fef2d9c5446d0733867d899ef9b942`, the 1.0.8 sources) if absent, then `cc -O2` of its seven library sources with `c_oracle/bzref.c` into `.zig-cache/bzip2-oracle/bzref`. Needs `git` (first run) and `cc`. |
| `c_oracle/bzref.c` | The black-box driver: `bzref c LEVEL WF CHUNK in out` (compress the way the bzip2 CLI feeds it: `BZ_RUN` calls, then `BZ_FINISH`), `bzref d in out`, `bzref t in` (verdict line). |
| `interop.zig` | `zig build interop-bzip2 [-- --capture] [-- --quick]`: our bytes against libbzip2's for every shape in `src/shapes.zig` (levels 1..9, work factors, CLI-style chunking), Python's `bz2.decompress` on our streams, our decoder on Python's and libbzip2's streams, stream boundaries, a randomised block, and 1500 mutated streams (verdicts must agree). `--capture` freezes libbzip2's digests and small streams into `src/testdata/` (`src/golden_test.zig` replays them offline). Needs `python3`. |
| `bench.zig`, `c_bench/foreign_bench.c` | `zig build bench-bzip2`: wall-time ratios against libbzip2 on seeded text and binary payloads (`BZIP2_BENCH_MIB`, default 8; `BENCH_ROUNDS`). Needs `zig cc` and the clone. |

The clone's licence (BSD-style) was read from its `LICENSE` before any source was; the sources
are read for the port recorded in `../NOTICE`.
