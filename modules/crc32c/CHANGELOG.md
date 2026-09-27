# crc32c — changelog

Newest first. See the root [`CHANGELOG.md`](../../CHANGELOG.md) for which
release tag each entry shipped in, and `CONVENTIONS.md` §8 for the policy.

## Unreleased

- **2026-09-27** — New module: CRC-32C with the SSE4.2 and ARMv8 CRC
  instructions chosen at run time (three interleaved streams, 7–20 GB/s) and a
  slicing-by-8 fallback (~1.9 GB/s), against std's bytewise ~0.45 GB/s; `hash`,
  `extend`, `combine`, streaming `Crc32c`, `backend`/`hashWith`. Anchored to
  RFC 3720 B.4 and the CRC catalogue check value, and differentially to
  `std.hash.crc.Crc32Iscsi`. Requested by `seglog` (egw-hub), whose reads it
  bounded.
