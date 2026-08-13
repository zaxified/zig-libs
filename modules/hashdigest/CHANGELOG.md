# hashdigest — changelog

Newest first. See the root [`CHANGELOG.md`](../../CHANGELOG.md) for which
release tag each entry shipped in, and `CONVENTIONS.md` §8 for the policy.

## Unreleased

- **2026-07-18** — Security audit: no findings. Modeled on OpenSSL / BLAKE3-C (design
  reference, not a test anchor).
- **2026-07-07** — New module: Streaming digests — one-shot / incremental / file
  (EOF-read, size-0 `/proc` safe); SHA-256 convenience + a multi-algorithm layer
  (SHA-2/SHA-3/BLAKE2b/BLAKE3).
