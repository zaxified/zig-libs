# fastmem — changelog

Newest first. See the root [`CHANGELOG.md`](../../CHANGELOG.md) for which
release tag each entry shipped in, and `CONVENTIONS.md` §8 for the policy.

## Unreleased

- **2026-10-26** — New: `copy` and the C `memcpy`, and `exportSymbols` now
  exports `memcpy` too (a consumer that already calls it gets the faster copy on
  its next build). Against Zig 0.17.0's compiler_rt `memcpy` 1.1–2.0× faster,
  against glibc 0.74–1.04×: up to 256 B by overlapping vectors with no loop,
  then a four-store aligned loop, from 16 KiB `rep movsb` to a 64-aligned
  destination on x86-64. `set` takes the same no-loop arm for 32–256 B and the
  four-store loop (256 B 1.58× → 1.10× glibc, 4 KiB 1.05× → 0.81× musl).
  `bench-fastmem` measures both (`tools/c_bench/memset_bench.c` → `mem_bench.c`).

- **2026-10-18** — **NO CONSUMER-VISIBLE CHANGE:** Docs: README/SPEC: 0.17.0's compiler_rt `memset` is vectorised; the gap and speed table are labelled as 0.16 measurements; the delete-the-module trigger is recorded as fired.
- **2026-10-10** — `set` stores the middle of a clear of 192 KiB or more with
  `rep stosq` on x86-64 (head and tail vectors unchanged): 1 MiB went from
  1.23–1.32× musl's and glibc's `memset` to 0.90–1.02×; shorter lengths run the
  same code as before. `bench-fastmem` now alternates the sides per round
  (`BENCH_ROUNDS`) and prints each side's spread. No API change.

- **2026-10-03** — Audit (review + 28-mutant schemata run): no defect; one test
  added for `memset(null, c, 0)` (the length guard had no test). No API or
  behaviour change.
- **2026-09-28** — The test binary exports `memset` from inside the test that
  checks the export instead of a file-level `comptime` block, which also fired
  when `check-pubfn-reach` imported the file and analysed `exportSymbols`: two
  strong `memset`s, "exported symbol collision" (CI run 36443590540). No API or
  behaviour change.
- **2026-09-28** — New module: a vectorised `memset` (`set`, C `memset`) and
  `exportSymbols`, which an executable without libc calls to replace
  compiler_rt's byte-at-a-time `memset` for every caller, std included:
  `@memset` 4 KiB 1 190 → 52 ns, `secureZero` 16 KiB 27× faster, std deflate
  level 6 on 16 KiB −27 % time. Opt-in; a compile error with libc linked.
  Found by qap's std perf audit.
