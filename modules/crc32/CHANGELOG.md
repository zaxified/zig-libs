# crc32 — changelog

Newest first. See the root [`CHANGELOG.md`](../../CHANGELOG.md) for which
release tag each entry shipped in, and `CONVENTIONS.md` §8 for the policy.

## Unreleased

- **2026-09-28** — New module: CRC-32 (IEEE 802.3 / gzip / zlib / PNG) with x86-64
  PCLMULQDQ folding and the ARMv8 `crc32x` instructions chosen at run time, and a
  slicing-by-8 fallback, against std's bytewise ~0.4 GB/s; `hash`, `extend`, `combine`,
  streaming `Crc32` (the shape of `std.hash.Crc32`), `backend`/`hashWith`. Anchored to the
  CRC catalogue check value and zlib-computed vectors, and differentially to
  `std.hash.Crc32`. Requested by qap's audit: `http`'s gzip and `kvtree`'s page checksums
  now use it.
