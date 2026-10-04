# crc32c — changelog

Newest first. See the root [`CHANGELOG.md`](../../CHANGELOG.md) for which
release tag each entry shipped in, and `CONVENTIONS.md` §8 for the policy.

## Unreleased

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
