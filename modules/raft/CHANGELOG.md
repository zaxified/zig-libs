# raft — changelog

Newest first. See the root [`CHANGELOG.md`](../../CHANGELOG.md) for which
release tag each entry shipped in, and `CONVENTIONS.md` §8 for the policy.

## Unreleased

- **2026-08-24** — `root.zig` now re-exports `tagOf` and `max_entries_per_msg`.
  Found by the module's first outside caller (`example-apps/raft-kv`): every
  RPC type was public but the dispatch helper and the decode-buffer bound were
  not, so an external consumer could not decode the wire the module itself
  defines without reaching into `types.zig`, which the package does not expose.
- **2026-08-11** — Security audit: three findings fixed, one documented as accepted (not
  defects) — part of the collection-wide audit.
- **2026-07-17** — New module: Raft consensus (Ongaro & Ousterhout) — leader election +
  log replication, model-checked in netsim against all five formal safety properties.
