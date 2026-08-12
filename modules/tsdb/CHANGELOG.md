# tsdb — changelog

Newest first. See the root [`CHANGELOG.md`](../../CHANGELOG.md) for which
release tag each entry shipped in, and `CONVENTIONS.md` §8 for the policy.

## Unreleased

- New module: time-series persistence over `kvtree` — series identity,
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
