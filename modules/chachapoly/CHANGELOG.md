# chachapoly — changelog

Newest first. See the root [`CHANGELOG.md`](../../CHANGELOG.md) for which
release tag each entry shipped in, and `CONVENTIONS.md` §8 for the policy.

## Unreleased

- **2026-07-19** — Performance: a SIMD implementation now beats OpenSSL's AVX2 keystream
  throughput on the reference host (part of a collection-wide
  performance campaign; the root changelog records no further detail
  than this).
