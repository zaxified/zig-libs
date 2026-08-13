# idempotency — changelog

Newest first. See the root [`CHANGELOG.md`](../../CHANGELOG.md) for which
release tag each entry shipped in, and `CONVENTIONS.md` §8 for the policy.

## Unreleased

- **2026-07-18** — Security audit: two findings fixed (part of the collection-wide
  audit; the root changelog records no further detail than this).
- **2026-07-08** — New module: Idempotency-Key dedup of unsafe retries — a middleware +
  ramcache-backed `Store` replaying a key's cached response without re-running the
  handler.
