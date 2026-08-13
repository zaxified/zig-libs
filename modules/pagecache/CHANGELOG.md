# pagecache — changelog

Newest first. See the root [`CHANGELOG.md`](../../CHANGELOG.md) for which
release tag each entry shipped in, and `CONVENTIONS.md` §8 for the policy.

## Unreleased

- **2026-08-06** — Security audit: six findings fixed (part of the collection-wide
  audit; the root changelog records no further detail than this). Modeled on LMDB mmap'd
  pages / Postgres `shared_buffers` (design reference, not a test anchor).
- **2026-07-22** — New module: bounded write-through page cache between `kvtree`'s pager
  and its `Storage`.
