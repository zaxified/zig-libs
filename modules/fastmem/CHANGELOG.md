# fastmem — changelog

Newest first. See the root [`CHANGELOG.md`](../../CHANGELOG.md) for which
release tag each entry shipped in, and `CONVENTIONS.md` §8 for the policy.

## Unreleased

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
