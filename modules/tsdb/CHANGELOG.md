# tsdb — changelog

Newest first. See the root [`CHANGELOG.md`](../../CHANGELOG.md) for which
release tag each entry shipped in, and `CONVENTIONS.md` §8 for the policy.

## Unreleased

- **2026-08-18** — Portability fix (`check-portable`): same defect and fix as
  `kvtree`'s 2026-08-18 entry — two crash-injection tests mixed a `usize` `crash_at`
  directly with the splitmix64-style `0x9e3779b97f4a7c15` constant feeding
  `SimStorage.reorder_seed` (`u64`), which doesn't fit `usize` on a 32-bit target.
  Widened `crash_at` to `u64` for the mixing expression rather than truncating the
  constant. Compile-only, identical produced seed on every target that already built.
  Verified: `zig build portable-tsdb` and `zig build test-tsdb --summary all` (32/32)
  both green.
- **2026-08-06** — Security audit: five findings fixed, one documented as accepted (not
  defects) — part of the collection-wide audit. Modeled on Prometheus TSDB / OpenTSDB /
  InfluxDB TSM (design ref), over `kvtree` (design reference, not a test anchor).
- **2026-07-30** — New module: time-series persistence over `kvtree` — series identity,
  append, streaming range scans, retention by age. Filed as a layer over
  `kv`; that premise was wrong and was not followed. `kv` is a Bitcask log
  with an unordered keydir and no cursor, and a time series is nothing but
  ordered range scans, so `kvtree`'s COW B-tree (ordered `seek`/`next`,
  MVCC snapshots, multi-key ACID) is the substrate instead. The module's
  foundation is one identity — byte-lexicographic order over an encoded
  key equals logical `(series, timestamp)` order — which forces
  fixed-width big-endian fields and a flipped sign bit so pre-epoch
  timestamps sort below the epoch; it is asserted as a property over
  random + boundary pairs rather than round-tripped, because the strongest
  codec bug (little-endian on *both* sides) round-trips perfectly and only
  an ordering assertion sees it. Series ids come from an
  order-independent, length-prefixed (hence injective) canonicalisation of
  `(name, labels)`, allocated with their forward index, reverse index and
  counter in one transaction. Ranges are half-open `[from, to)` and
  stream. Retention runs as bounded chunks, each ONE transaction that both
  deletes ≤ N points and advances the durable resume position — so an
  interrupted sweep is consistent, re-runnable to the same end state, and
  never leaves the position ahead of the deletions it implies; a changed
  cutoff restarts rather than resumes. v1 deliberately excludes sample
  compression, rollups, a query language and aggregation (`SPEC.md` §9).
