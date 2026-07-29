# tsdb

Time-series **persistence** over `kvtree`: turn `(metric name, labels)` into a
stable series id, append `(timestamp, f64)` samples, stream an ordered
half-open `[from, to)` window back out, and expire old data with a retention
sweep that runs in bounded, resumable, idempotent chunks. It is the durable
layer the repo's in-memory statistics modules do not have — `metrics` keeps a
live registry and renders Prometheus exposition, `latency-stats` keeps HDR-style
latency summaries, `finstats` computes portfolio statistics over a `dataset`;
none of them stores a point beyond process lifetime.

- **Model after:** the composite `(series id, big-endian timestamp)` row key
  shared by Prometheus's TSDB, OpenTSDB and InfluxDB TSM; LMDB-style ordered
  range scans for the read path.
- **Platform:** any — all I/O goes through `kvtree` → `kv`'s `Storage` seam.
  **Role:** util. **Concurrency:** `single_owner` (inherits kvtree's model: one
  writer, MVCC snapshot readers; this module adds no shared state of its own).
- **Deps:** `kvtree`.

Provenance: clean-room from a publicly documented design; no third-party
implementation was studied and no source was consulted, so there is no root
`NOTICE` entry — see `SPEC.md` §Provenance.

## Why `kvtree` and not `kv`

A time-series read *is* an ordered range scan. `kv` is a Bitcask-style
append-only log with an unordered in-memory keydir — `put`/`get`/`delete`/
`compact`, no cursor, no ordering, no range query — so no amount of layering
turns it into a TSDB. `kvtree` is the copy-on-write B-tree sibling that has
exactly what is needed: `seek`/`next` cursors in key order, MVCC snapshots, and
multi-key ACID transactions (which is what makes one retention chunk atomic).

## API

```zig
const kvtree = @import("kvtree");
const tsdb = @import("tsdb");

// The kvtree is the CALLER's: it must outlive the tsdb view and must not move
// (kvtree cursors hold a pointer into it).
var tree = try kvtree.Db.open(gpa, store, "series.kvt", .{});
defer tree.close();
var db = tsdb.Db.init(gpa, &tree);

// Series identity. Label ORDER is irrelevant — {a=1,b=2} and {b=2,a=1} are the
// same series. The id is durable: it is the same after a restart.
const cpu = try db.seriesId("cpu_seconds", &.{
    .{ .name = "host", .value = "web-1" },
    .{ .name = "mode", .value = "user" },
});
_ = try db.lookupSeries("cpu_seconds", &.{...});  // ?SeriesId, never creates

// Append. Same (series, ts) twice = last write wins; the key is the identity.
try db.append(cpu, 1_754_000_000_000, 12.5);
try db.appendMany(cpu, &.{                        // one atomic transaction
    .{ .ts = 1_754_000_060_000, .value = 12.9 },
    .{ .ts = 1_754_000_120_000, .value = 13.1 },
});

// Read [from, to) — LOWER bound inclusive, UPPER bound exclusive, so
// consecutive windows tile without double-counting the boundary sample.
var r = try db.range(cpu, from, to);
defer r.deinit();                                  // releases the MVCC snapshot
while (try r.next()) |s| use(s.ts, s.value);       // streams; buffers nothing
```

Timestamps are `i64` in whatever unit the caller picks (Unix milliseconds is
the conventional choice) — the module only requires that ordering is numeric
and that retention cutoffs use the same unit. **Negative (pre-epoch) timestamps
are legal** and sort correctly below the epoch.

The tree may be shared with other data: this module only ever touches keys
whose first byte is one of its four tags.

## Retention

```zig
// Run to completion: delete everything with ts < cutoff.
const res = try db.sweep(cutoff, .{});
// res.deleted / res.examined / res.chunks / res.done

// Or bound the work — e.g. from a maintenance tick — and continue later.
var r = try db.sweep(cutoff, .{ .chunk_deletes = 4096, .max_chunks = 4 });
while (!r.done) r = try db.sweep(cutoff, .{ .max_chunks = 4 });

_ = try db.retentionState();  // ?RetentionState — non-null while mid-sweep
```

Each chunk is **one transaction** that deletes at most `chunk_deletes` points
*and* advances the durable resume position. What that buys, precisely:

- **Bounded.** No sweep ever builds one enormous transaction over an unbounded
  key range. `chunk_examines` bounds a chunk even when nothing expires.
- **Consistent under interruption.** A crash or an early return leaves the tree
  on a chunk boundary — never a half-applied chunk.
- **Resumable.** A later call with the *same* cutoff continues where it stopped,
  across process restarts. A call with a *different* cutoff restarts from the
  beginning, on purpose: a larger cutoff expires data the stored position has
  already scanned past.
- **Idempotent.** Re-running after an interruption converges on exactly the
  state an uninterrupted sweep produces.

Series index entries are **not** removed by retention — a series that loses
every point keeps its id, so re-appearing data lands in the same series.

## Not in v1 (deliberate, see `SPEC.md`)

Sample compression (Gorilla-style delta-of-delta timestamps + XOR floats),
downsampling/rollups, any query language, and aggregation functions. These are
scope decisions, not oversights; each is listed in `SPEC.md` with what it would
take.

## Verify

```
zig build test-tsdb                          # Debug
zig build test-tsdb -Doptimize=ReleaseFast   # ReleaseFast
```

All tests run for real (no skips). The key codec's ordering identity is a
property test over random and boundary `(series, timestamp)` pairs; retention is
checked against a crash sweep over every storage side effect in all four
`kv.SimStorage` crash modes. See `SPEC.md` for the verification argument and the
mutation results.
