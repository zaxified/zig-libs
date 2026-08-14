# tsdb — design & verification

What it is: see `README.md`.

This document is the auditor's view: the invariants, why the substrate was
chosen, what the retention guarantee actually says (and what it does not), and
the evidence.

## 1. Substrate: `kvtree`, not `kv`

This module's task was originally filed as "TSDB / retention layer over `kv`".
That premise is wrong and was not followed. `kv` is a Bitcask-style
append-only log with an in-memory keydir: `put` / `get` / `delete` / `compact`,
no cursor, no ordering, no range query — its own README lists "ordered/ranged
scans" under *noted phases, deliberately not in v0*. A time-series layer is
ordered range scans and nothing else, so it cannot be built there at all.

`kvtree` is the copy-on-write B-tree sibling and supplies every primitive this
module needs:

| Need | kvtree gives |
|---|---|
| `[from, to)` in time order | `Cursor.seek` / `Cursor.next` over a key-ordered tree |
| a scan that streams | the cursor's root-to-leaf page stack — depth, not window size |
| one retention chunk = all-or-nothing | `begin` / `commit` multi-key ACID transactions |
| a reader unaffected by a concurrent sweep | `snapshot()` MVCC views |
| crash-safety underneath all of it | the COW meta-swap commit, VOPR-checked |

## 2. The load-bearing invariant

```
std.mem.order(u8, encode(a), encode(b)) == logicalOrder(a, b)
```

Byte-lexicographic order over an encoded point key must equal logical
`(series, timestamp)` order. Everything else in the module is a consequence:
`seek(series, from)` finds the window's first sample only because the encoding
is monotone, and `next()` stays inside the window only because later keys sort
later.

This invariant fails **silently**. A broken codec does not error — it returns
the wrong samples, in a plausible-looking order. Two consequences shape the
layout:

- **Fixed-width big-endian fields.** Little-endian or variable-width fields
  break lexicographic order immediately.
- **Sign-flipped timestamps.** Negative timestamps are admitted (historical
  backfill is a normal operation), and two's-complement bytes sort wrongly:
  `-1` is `0xFFFF…`, which lexicographically exceeds `+1`'s `0x00…01`. XOR-ing
  the sign bit maps `i64` monotonically onto `u64` (`minInt → 0`,
  `maxInt → maxInt`).

**Why the test is an ordering assertion and not a round-trip.** The strongest
mutation of a codec stays *consistent* between the writing and the reading
side: encode AND decode little-endian, and every round trip still passes while
every range scan is silently wrong. `codec.zig`'s property test therefore
asserts `std.mem.order` against the logical comparison for every pair drawn
from a set of boundary values (`minInt`, `-1`, `0`, `1`, `maxInt`, byte-carry
neighbours 255/256/257) plus a deterministic random cloud — ~2100 points,
pairwise. A second test sorts encoded keys by bytes and checks the decoded
sequence is logically ascending, which is the scan's premise stated directly.

## 3. Keyspace

One `kvtree` holds everything; a leading tag byte partitions it, and the
partition order is itself load-bearing — nothing may sort *between* two point
keys, or a forward scan would terminate early.

| Key | Value |
|---|---|
| `0x00 's'` | next series id (BE u64) |
| `0x00 'r'` | retention resume record |
| `0x01 \| series(BE u64) \| orderedTs(BE u64)` | sample, f64 bits (BE) |
| `0x02 \| canonical(name, labels)` | series id (BE u64) |
| `0x03 \| series(BE u64)` | canonical(name, labels) |

Keys outside these four tags are untouched, so the tree can be shared.

## 4. Series identity

`(name, labels)` is canonicalised to bytes that are

- **order-independent** — labels are sorted by name first, so `{a=1,b=2}` and
  `{b=2,a=1}` are the same series; and
- **injective** — every component is length-prefixed
  (`u16 len | bytes`), so no separator can be forged from inside a name or a
  value. A `name{k=v,…}` string-join would map `{"a=b": "c"}` and
  `{"a": "b=c"}` to the same string; length prefixes cannot.

Duplicate label names are rejected rather than deduplicated: `{a=1,a=2}` has no
defensible meaning and its resolution would otherwise depend on sort stability.

Allocation is one transaction writing the forward index, the reverse index and
the incremented counter together, so no crash can expose an id whose reverse
entry is missing, or hand out an id the counter has not moved past.

Bounds: components ≤ 1024 bytes, canonical form ≤ 3072 bytes. kvtree stores a
whole entry inside one 4 KiB page; these caps surface as a clean
`ComponentTooLong` / `SeriesTooLong` instead of `EntryTooLarge` from deep inside
a commit.

## 5. Retention — the guarantee, stated exactly

`sweep(cutoff, opts)` deletes every point with `ts < cutoff`. It runs as a
sequence of chunks; **each chunk is one transaction that deletes at most
`chunk_deletes` points and, in the same transaction, advances (or clears) the
durable resume position.**

Two bounds, not one. `chunk_deletes` bounds the transaction and the memory the
sweep holds. `chunk_examines` bounds a chunk that finds nothing to delete —
without it, a store full of live data turns one "chunk" into a full-keyspace
scan. Within a series, points at or above the cutoff are a suffix, so the scan
skips straight to the next series' first key rather than walking a live tail.

What the atomic pairing buys, precisely:

- **Consistent under interruption.** kvtree commits atomically, so after a crash
  or an early return the deletions and the resume position are both present or
  both absent. No chunk is ever half-applied.
- **The position is never ahead of the deletions it implies.** This is the
  ordering property that matters, and it is what atomicity gives for free.
  Committing the position *first* in a separate transaction would violate it: a
  crash in between leaves expired data behind an already-advanced position,
  stranded for good once the sweep completes and clears the record. (That exact
  inversion is mutation 10 below, and the crash sweep catches it.)
- **Idempotent.** Re-running converges on exactly the end state an
  uninterrupted sweep produces. Honestly stated: this comes from the *data*, not
  from the position — the operation is "delete keys below a bound", deletes of
  absent keys are no-ops. Re-running is always safe.
- **Resumable, and that is the position's real job.** With the position, a
  sweep is linear: `examined ≤ deleted + series_count + chunks`. Without it a
  sweep still *terminates* and still reaches the same end state — it just
  re-probes every retired series on every chunk. So a stale-but-present position
  is invisible to any end-state assertion; only the linearity bound sees it.
  That is why the chunked-sweep test asserts the bound (measured 130 correct vs.
  175 mutated on the same workload).
- **A different cutoff restarts from the beginning.** A stored position is only
  valid for the cutoff it was written for. A *larger* cutoff newly expires data
  that lies behind the position — resuming would strand it. The cutoff is
  therefore stored in the resume record and compared.

Retention never removes series-index entries: a series that loses every point
keeps its id, so re-appearing data lands in the same series.

`SweepStalled` is a defensive error, not a reachable state: a chunk that neither
deletes anything nor advances its position while claiming more work would spin
forever, so it stops instead.

## 6. Threat model / what can go wrong

- **Untrusted key bytes.** Point keys come from this module, but the tree can be
  shared, so `decodePointKey` validates length and tag and the scan treats
  anything else as "past the point partition". `parseCanonical` validates every
  length prefix and rejects trailing bytes (`Malformed`).
- **Corrupt index values.** An index entry that is not 8 bytes, or a resume
  record with a bad version/length, surfaces as `CorruptIndex` rather than
  being read as garbage.
- **Sample values are opaque.** NaN/±Inf round-trip bit-exactly; this layer
  never compares or aggregates them.
- **Not concurrency-safe by itself.** `single_owner`, inherited: one writer at a
  time. A `Range` holds an MVCC snapshot, so a leaked `Range` pins kvtree's page
  reclaim — hence `defer r.deinit()`.
- **Inherited caveats from kvtree**, unchanged and not re-argued here:
  merge-less deletes (emptied leaves persist until overwritten — space, never
  correctness), a single bounded freelist page, no overflow pages.

## 7. Verification

`zig build test-tsdb` — 27 tests, **no skips**, green in Debug, ReleaseSafe and
ReleaseFast.

- **Codec property tests** (§2): pairwise order identity over boundary +
  random pairs; sort-by-bytes equals sort-by-logic; partition-order checks;
  canonicalisation order-independence, injectivity-vs-delimiter, and rejection
  cases.
- **Range semantics**: half-open `[from, to)`, no bleed into the neighbouring
  series, empty windows, pre-epoch timestamps straddling the epoch.
- **Streaming**: 3000 points iterated with this layer's allocator swapped for a
  256-byte fixed buffer. Buffering the window would need ~48 KB. (The claim is
  scoped: it proves *this* layer buffers nothing; the cursor's own bounded page
  stack is kvtree's property, proven there.)
- **Retention**: strict `<` cutoff, idempotence, chunked-vs-one-shot end-state
  equality, the linearity bound, resume across a full close/reopen,
  larger-cutoff restart, `chunk_examines` bounding a no-op sweep, empty store,
  and non-interference with a foreign key in the same tree.
- **Crash sweeps** over `kv.SimStorage`: the crash point is swept across every
  storage side effect of (a) a chunked retention sweep and (b) a series-id
  allocation, in all four crash modes (`lose_unsynced`, `torn_tail`,
  `reorder_unsynced`, `keep_unsynced`). After each reboot the store must reopen,
  a re-run must finish, and the result must equal an uninterrupted reference run
  byte for byte. Instrumented once to confirm the sweeps have teeth: **200 real
  crashes** fired in the retention sweep, not zero.
- **Filesystem round trip**: `FsStorage` over a tmp dir, samples + a chunked
  sweep, reopened and re-read.

### 7.1 Mutation results

Every central invariant was mutated in the implementation and the suite
re-run. All twelve go red; the mutations that "come out the same either way"
were the point of the exercise.

| # | Mutation | Caught by |
|---|---|---|
| 1 | timestamp encoded **and decoded** little-endian (round-trips perfectly) | codec order property; pre-epoch range; persistence |
| 2 | sign flip removed on both sides (round-trips perfectly) | codec order property; smoke ordering; retention |
| 3 | series id encoded and decoded little-endian | codec order property |
| 4 | labels sorted only when there are >2 of them | series-identity test |
| 5 | scan's upper bound made inclusive | half-open range test |
| 6 | chunk commits deletions, never persists the resume position | chunked-sweep; reopen-resume; larger-cutoff |
| 7 | resume position persisted every chunk but always at the start | **linearity bound**; larger-cutoff |
| 8 | stored cutoff ignored when resuming | larger-cutoff restart test |
| 9 | retention deletes `<= cutoff` instead of `< cutoff` | strict-cutoff; chunked-sweep; reopen-resume |
| 10 | resume position committed **before** the deletions, separately | retention crash sweep |
| 11 | series id written as three separate autocommits | series-id crash sweep |
| 12 | series-skip forgets to re-seek the cursor | `chunk_examines` bound test |

Mutation 7 is the one worth noting: it leaves a resume record present and
well-formed, so every end-state assertion still passes. Only the linearity
bound distinguishes it — which is why that bound is asserted rather than
assumed. Two earlier test versions were strengthened *because* mutations 8 and
11 initially survived them; the fixed tests are in the suite.

## 8. Provenance

Clean-room. The composite `(series id, big-endian timestamp)` row key is the
publicly documented shape shared by Prometheus's TSDB, OpenTSDB's HBase rowkeys
and InfluxDB's TSM; the read path is LMDB-style ordered range scans, which is
`kvtree`'s own lineage (and carries `kvtree`'s NOTICE entry, not a new one). No
third-party implementation was studied and no source was consulted for this
module, so per `CONVENTIONS.md` §5 it takes **no root `NOTICE` entry** — this
section is its citation.

## 9. Backlog — deliberate v1 non-goals

Named as scope decisions, not omissions.

- **Sample compression.** Gorilla-style delta-of-delta timestamps + XOR'd
  floats (Facebook's Gorilla paper, VLDB 2015) is the standard ~10× win. It
  needs a chunked block format — samples packed per (series, time-window) into
  one value — which changes the point keyspace from one-key-per-sample to
  one-key-per-block and makes a single-sample overwrite a read-modify-write.
  v1's one-key-per-sample layout keeps the ordering invariant trivially true
  and retention a plain key-range delete; compression is a format change to be
  made deliberately, with its own migration.
- **Downsampling / rollups.** Precomputed `(min, max, sum, count)` per coarse
  bucket, written by a background pass, with reads picking a resolution. Needs
  a resolution-aware key tag and a rollup watermark; independent of everything
  above.
- **Query language and aggregation functions.** `rate()`, `sum by (…)`, label
  matchers. This is a query engine, a much larger deliverable than a storage
  layer, and it belongs above this module rather than inside it.
- **Series deletion / label-matcher lookup.** v1 resolves an exact label set to
  an id; there is no inverted index for "every series with `host=web-1`", and
  no way to drop a series. Both want a `0x04` inverted-index partition.
- **A retention policy per series.** v1 sweeps one global cutoff. Per-series
  retention wants the policy stored beside the reverse index and the sweep
  reading it per series — mechanical, but it changes the sweep's skip rule.

## Anchoring

**Anchor grade:** class C · oracle n/a

- **Class C** — internal algorithm or data structure — no outside exists, so correctness is defined by invariants or a brute-force reference. Not anchor debt.
- **Oracle n/a** — class C/D carries no anchor debt, so there is no oracle grade to give.

**What the tests actually contain.** embedded time-series store; row-key shape Prometheus-like but no wire interop
