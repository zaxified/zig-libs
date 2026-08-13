# kv — changelog

Newest first. See the root [`CHANGELOG.md`](../../CHANGELOG.md) for which
release tag each entry shipped in, and `CONVENTIONS.md` §8 for the policy.

## Unreleased

- **2026-08-11** — Security audit: four findings fixed (part of the collection-wide
  audit; the root changelog records no further detail than this). Modeled on Bitcask
  (Go) (design reference, not a test anchor).
- **2026-07-04** — New module: Crash-consistent embedded KV store (Bitcask-style log +
  randomized seeded VOPR: model-checked crash recovery across fuzzed fault schedules).
