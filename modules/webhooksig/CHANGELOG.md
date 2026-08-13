# webhooksig — changelog

Newest first. See the root [`CHANGELOG.md`](../../CHANGELOG.md) for which
release tag each entry shipped in, and `CONVENTIONS.md` §8 for the policy.

## Unreleased

- **2026-07-18** — Security audit: one finding fixed (part of the collection-wide audit;
  the root changelog records no further detail than this). Verified: Byte-exact
  HMAC-SHA256 KAT (key="key", "The quick brown fox…" → `f7bc83f4…a3cd8`),
  `src/root.zig:360-368`.
- **2026-07-08** — New module: HMAC webhook signatures (GitHub style: `sha256=<hex>`).
