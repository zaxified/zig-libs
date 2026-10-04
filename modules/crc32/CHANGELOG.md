# crc32 — changelog

Newest first. See the root [`CHANGELOG.md`](../../CHANGELOG.md) for which
release tag each entry shipped in, and `CONVENTIONS.md` §8 for the policy.

## Unreleased

- **2026-10-04** — Tests: `combine` is now held to Go's `hash/crc32` (IEEE) at lengths
  around 2^28 … 2^33 and past 5·10^9 bytes, for three prefixes (`tools/gen_kat.go` →
  `src/kat_vectors.zig`). Anchor grade MIXED → EXTERNAL.
- **2026-10-03** — Audit (review + 65-mutant schemata run, x86-64 and ARMv8 under
  qemu): no defect in the code; two tests added where mutants survived (`.table`
  availability; run-time CPU detection against `/proc/cpuinfo`). No API or
  behaviour change.
- **2026-09-29** — Fix: a Debug build for a baseline x86_64 target (`-Dtarget=x86_64-linux`,
  or any CPU model without the instruction) failed to compile — Zig 0.16's self-hosted x86_64
  backend cannot encode the run-time-dispatched PCLMULQDQ path for such a CPU. That build now uses
  the table; LLVM builds and targets that have the instruction are unchanged. Found by qap's
  portability check.
- **2026-09-28** — New module: CRC-32 (IEEE 802.3 / gzip / zlib / PNG) with x86-64
  PCLMULQDQ folding and the ARMv8 `crc32x` instructions chosen at run time, and a
  slicing-by-8 fallback, against std's bytewise ~0.4 GB/s; `hash`, `extend`, `combine`,
  streaming `Crc32` (the shape of `std.hash.Crc32`), `backend`/`hashWith`. Anchored to the
  CRC catalogue check value and zlib-computed vectors, and differentially to
  `std.hash.Crc32`. Requested by qap's audit: `http`'s gzip and `kvtree`'s page checksums
  now use it.
