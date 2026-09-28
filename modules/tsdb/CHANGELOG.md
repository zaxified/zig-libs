# tsdb — changelog

Newest first. See the root [`CHANGELOG.md`](../../CHANGELOG.md) for which
release tag each entry shipped in, and `CONVENTIONS.md` §8 for the policy.

## Unreleased

- **2026-09-28** — Retention now bounds the file: with kvtree dropping emptied leaves (same day),
  appending and sweeping at the same rate reaches a steady file size instead of growing ~60 KiB
  per 1000 points. No tsdb code change; README/SPEC corrected and a test pins the steady size.
- **2026-09-28** — Series listing, multi-series batches, a size budget — requested by ttydesk
  (2026-09-27), which worked around all three in `src/diskhist.zig` (each marked `zig-libs
  request: tsdb — …`; the new API lets that workaround be deleted). New: `Db.seriesIterator()`
  (every registered series, id order, id + parsed `Descriptor`, replacing a walk of ids `1, 2,
  3, …` that only worked because ids happen to be dense today) and `Db.findSeries(name, filter)`
  (a bounded name-prefix range scan over the forward index, filtered by a label SUPERSET check —
  covers "I know the metric but not every label value" without decoding every series in the
  store); both return the new `SeriesIterator`/`SeriesEntry` (MVCC-snapshotted like `Range`, each
  entry fully owned so it survives past the next `next()` call). `Db.appendBatch([]const
  SeriesBatch{ series, points })`: every series in one kvtree transaction — a CONSTANT number of
  commits (and therefore fsyncs) regardless of how many series are batched, not one per series;
  a crash or an error partway through leaves every series in the batch untouched, verified both
  by a `FailingAllocator` failure and a `kv.SimStorage` crash sweep. `Db.liveSize()` (exact
  point-data byte count — every point is fixed-width, so this needs no estimate) and
  `Db.sweepToBudget(max_bytes, opts)` (deletes the globally OLDEST points, by timestamp across
  every series — not by key order, which sorts series-major — via a k-way merge over per-series
  candidates, not a full-store rescan). kvtree exposes no compaction/vacuum and never shrinks its
  file, so `sweepToBudget` is explicitly a budget on LIVE data, never on file size — see SPEC.md
  §5a for the full design, including `sweepToBudget`'s narrower (non-resumable) crash-safety
  compared to `sweep`'s. Purely additive — no existing type, field, or behavior changed.

- **2026-09-07** — Test-only, no production change: both fuzz targets ran one input.
  `fuzzParseCanonical` and `fuzzDecodePointKey` each opened `smith.bytes(&buf)` and then
  drew a length with `smith.valueRangeAtMost`; a ranged `Smith` draw reads eight octets as
  a little-endian `u64` and returns the range MINIMUM when fewer than eight remain, and
  `bytes` had already eaten them - so `len` was **0** every round, `parseCanonical` failed
  at its first `takeLenPrefixed`, and `decodePointKey` never saw a key of the one length it
  accepts. Neither had a corpus either. Both now draw with one `smith.slice(&buf)`. The
  descriptor corpus is built from `canonicalize`, the module's own encoder (a canonical
  descriptor is a nest of length prefixes that all have to agree with the bytes behind
  them, which arbitrary octets essentially never spell), and includes the frame this
  decoder's shape invites: a `count` claiming 65535 labels over a two-label frame, which
  must not be committed to by `gpa.alloc(Label, count)`. Measured by the two new `corpus:`
  guards: descriptors 8 non-empty seeds, 3 accepted, **3 labels decoded**; point keys 6
  non-empty, 3 decoded, **3 round-tripping** back to their own series and timestamp. The
  label count is pinned rather than `accepted > 0` because a `count = 0` descriptor is
  accepted while walking no label at all.

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
