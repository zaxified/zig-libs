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

## Listing series, batched writes, a size budget

```zig
// Every registered series, id order, id + parsed (name, labels) descriptor.
var it = try db.seriesIterator();
defer it.deinit();
while (try it.next(gpa)) |*entry| {
    defer entry.deinit(gpa);
    use(entry.id, entry.descriptor.name, entry.descriptor.labels);
}

// A known metric name, labels not all known up front: filter by a SUBSET —
// every listed label must match; the series may carry further labels too.
var m = try db.findSeries("cpu_seconds", &.{.{ .name = "host", .value = "web-1" }});
defer m.deinit();
while (try m.next(gpa)) |*entry| { defer entry.deinit(gpa); use(entry.id); }

// N series in ONE transaction — a constant number of fsyncs, not one per
// series — and a crash or an error partway through leaves EVERY series in
// the batch untouched, never some committed and others not.
try db.appendBatch(&.{
    .{ .series = cpu, .points = &.{.{ .ts = 1, .value = 1 }} },
    .{ .series = mem, .points = &.{.{ .ts = 1, .value = 2 }} },
});

// A byte BUDGET on live data (kvtree never shrinks the file — see below):
// drops the globally oldest points, by timestamp across every series, until
// live data fits (or opts.max_deletes is spent — call again to continue).
const size = try db.liveSize();               // exact: every point is 25 bytes
const r = try db.sweepToBudget(64 << 20, .{});
// r.before / r.after / r.deleted / r.done
```

`seriesIterator`/`findSeries` return a `SeriesIterator` — MVCC-snapshotted like `Range`, so
`defer it.deinit()` — whose `next()` hands back a fully OWNED `SeriesEntry` (`defer
entry.deinit(gpa)`): its descriptor's name/label slices point into their own copy, not into any
buffer the next `next()` call would invalidate.

`sweepToBudget` solves a different problem than `sweep`: a point key sorts `(series, timestamp)`
— series-major — so "the earliest keys in the tree" is not "the oldest points in the store" (one
series can hold decade-old data while another is five minutes old). It merges every series'
current-oldest candidate in a min-heap ordered by timestamp rather than rescanning the whole store
per decision. Its crash-safety is narrower than `sweep`'s: each chunk of deletions commits
atomically, but there is no persisted resume record, so an interrupted call's progress is not
resumed — the next call just recomputes and reseeds (still correct, just not linear). **kvtree
never shrinks its file** and exposes no compaction/vacuum — so `liveSize`/`sweepToBudget` are a
budget on the point data, never on `stat().size` (which a caller reads for itself, e.g. via its
own `Io.Dir.statFile`).

**Retention does bound the file**, though: kvtree recycles the pages of leaves a sweep empties, so
a store that appends and sweeps at the same rate reaches a steady size (since 2026-09-28; before,
the emptied leaves stayed in the tree and the file grew ~60 KiB per 1000 points in and out). The
steady size is above `liveSize`: pages are not repacked, and pages freed while a reader holds a
snapshot wait for it.

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
