# stun — changelog

Newest first. See the root [`CHANGELOG.md`](../../CHANGELOG.md) for which
release tag each entry shipped in, and `CONVENTIONS.md` §8 for the policy.

## Unreleased

- **2026-08-18** — **BREAKING:** `query` gained a required `options: QueryOptions` parameter with a
  `timeout_ms` field (mirrors `sntp.QueryOptions`) so a caller can bound the wait for a reply instead
  of blocking indefinitely against a dark/unresponsive server; on expiry it returns `error.Timeout`.
  The default (`timeout_ms = 0`) preserves `query`'s original unbounded-wait behavior — this is a
  source-compatibility break (a fifth argument), not a behavioral one, for any existing caller.
- **2026-07-19** — Security audit: fixed a memory-safety finding rated CRIT/HIGH (part of
  the collection-wide audit; the root changelog records no further detail
  than this).
