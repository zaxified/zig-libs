# crc32c — changelog

Newest first. See the root [`CHANGELOG.md`](../../CHANGELOG.md) for which
release tag each entry shipped in, and `CONVENTIONS.md` §8 for the policy.

## Unreleased

- **2026-10-08** — **NO CONSUMER-VISIBLE CHANGE:** `tools/count.tsv` rewritten, 2139 → 1631
  instructions per 4 KiB round (−24 %): the 2026-10-07 `crc32q` chain change below, which the
  baseline had not recorded — found by the new `count amd64` lane on its first local run.
- **2026-10-07** — **NO CONSUMER-VISIBLE CHANGE:** the test-only `ScriptSource` (the fuzz harness's cursor source) drops `pub` from its two methods; it was never reachable from outside, and the textual consumer-example trigger (CONVENTIONS.md §7.2) counted them as state methods.
- **2026-10-07** — Performance, not breaking: the x86-64 `crc32q` chains stay
  64-bit (no narrowing and widening around every instruction): against Go
  `hash/crc32` Castagnoli (new `tools/bench.zig`, `zig build bench-crc32c`)
  1 KiB 1.34 → 0.91×, 1 MiB 1.25 → 1.01×. New deterministic fuzz driver
  `CRC32C_FUZZ`.

- **2026-10-07** — Tests only (pilot): instruction-count cases in `src/count.zig`, skipped unless
  `ZIGLIBS_COUNT` names one, held by `scripts/count-insns crc32c` to `tools/count.tsv` (instructions per
  round under cachegrind, ReleaseFast, `-mcpu=x86_64_v3`): `crc32c-4KiB` 2 139.

- **2026-10-04** — Tests: `combine` is now held to Go's `hash/crc32` (Castagnoli) at lengths
  around 2^28 … 2^33 and past 5·10^9 bytes, for three prefixes (`tools/gen_kat.go` →
  `src/kat_vectors.zig`); the test fails with the `len_b ≥ 2^29` defect put back. Anchor
  grade MIXED → EXTERNAL.
- **2026-10-04** — Fix: `combine(a, b, len_b)` returned a wrong checksum whenever
  `len_b ≥ 2^29` bytes (512 MiB). Its table of x^(2^k) mod P was folded to 32 entries as
  zlib does for the IEEE polynomial, but CRC-32C's powers repeat every 31. Shorter lengths
  were right and are unchanged; `hash`, `extend` and `Crc32c` were never affected. Found by
  an independent review; test added (fails without the fix).
- **2026-09-29** — Fix: a Debug build for a baseline x86_64 target (`-Dtarget=x86_64-linux`,
  or any CPU model without the instruction) failed to compile — Zig 0.16's self-hosted x86_64
  backend cannot encode the run-time-dispatched SSE4.2 path for such a CPU. That build now uses
  the table; LLVM builds and targets that have the instruction are unchanged. Found by qap's
  portability check.
- **2026-09-27** — New module: CRC-32C with the SSE4.2 and ARMv8 CRC
  instructions chosen at run time (three interleaved streams, 7–20 GB/s) and a
  slicing-by-8 fallback (~1.9 GB/s), against std's bytewise ~0.45 GB/s; `hash`,
  `extend`, `combine`, streaming `Crc32c`, `backend`/`hashWith`. Anchored to
  RFC 3720 B.4 and the CRC catalogue check value, and differentially to
  `std.hash.crc.Crc32Iscsi`. Requested by `seglog` (egw-hub), whose reads it
  bounded.
