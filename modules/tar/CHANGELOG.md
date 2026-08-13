# tar — changelog

Newest first. See the root [`CHANGELOG.md`](../../CHANGELOG.md) for which
release tag each entry shipped in, and `CONVENTIONS.md` §8 for the policy.

## Unreleased

- **2026-07-19** — Security audit: a crafted GNU/star base-256 archive size field could
  overflow `padding()`'s internal arithmetic and crash the reader before any content was
  read; fixed the same day. A second finding (path-traversal in caller-supplied
  extraction) turned out to already be documented as the caller's responsibility; a
  third was accepted as informative-only.
- **2026-07-05** — New module: ustar/GNU tar reader+writer (preserves uid/gid/mtime) +
  gzip.
