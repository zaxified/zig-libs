# seglog

A segmented, crash-consistent, append-only log. Records go into the newest
segment; old segments are deleted whole. Nothing is rewritten in place, so a
record keeps its `Position` until its segment is dropped, and a consumer can
persist a position and resume from it after a restart. Every record also has
an **LSN** — 1, 2, 3 … across the whole log, never reused — and a timestamp.

**Status:** a zig-libs module since 2026-11-15, moved from energomonitor's
`egw-hub/seglog/` (its first consumer, which has not switched to this copy
yet). Depends on `kv` (the `Storage` seam and `SimStorage` crash simulator),
`crc32c` and `zstd`.

**Model after:** the LevelDB log format and the Prometheus TSDB WAL for the
record format and for repairing only the last segment; Kafka log segments for
retention by whole segment. Reliability is `kv`'s `SimStorage` crash sweep,
reused as is.

## Use

```zig
const seglog = @import("seglog");

var fs = seglog.FsStorage.init(io, dir);          // or SimStorage in tests
var log = try seglog.Log.open(gpa, fs.storage(), .{ .create = true });
defer log.close();

try log.rotate(today);                            // no-op if already today's
const a = try log.append(payload);                // after fsync: a.pos, a.lsn
_ = try log.appendAt(ts, payload);                // the caller's timestamp

var it = log.iterator(saved_position);            // null = from the start
defer it.deinit();
while (try it.next()) |rec| {
    deliver(rec.lsn, rec.ts, rec.payload);
    saved_position = rec.next;                    // persist this
}

_ = try log.dropBefore(today - 30);               // never drops the newest
```

- `append` returns only after `fsync` — by default. `appendMany` writes a batch
  with one write and one `fsync`; each record is atomic, the batch is a prefix.
  `Options.sync = .{ .every_bytes = n }` or `.manual` (then `log.sync()`) let
  appends share an `fsync`; `durableLsn()` says how far is safe, and the
  writer's own iterators read no further.
- `rotate(id)` seals the current segment and starts `id`. Ids only grow.
- Or let it rotate itself: `Options.auto_rotate = .{ .max_bytes, .max_age }`
  starts segment `newest + 1` before an append that would overflow, or once
  the segment is old by `Options.now` (Kafka's `segment.bytes` / `segment.ms`).
- The iterator follows the writer: at the live end it returns null, and a
  later call sees what was appended or rotated to since. It never reads past
  what `fsync` confirmed.
- After any write error the log is poisoned and refuses mutations; reopen.
- `bytesCutOnOpen()` says how much torn tail `open` removed — worth logging.
- **Damage** is reported, never repaired: after `error.Corrupt`,
  `it.damage()` says where and what; `it.resync()` steps to the next intact
  record in the segment (LevelDB's salvage) and `it.skipSegment()` to the next
  segment, each returning the LSNs stepped over — exact, because every record
  carries its LSN. `log.verify(gpa)` reads the whole log that way and lists
  every damage.
- **Retention**: `dropBefore(id)`, or `enforceRetention(.{ .max_bytes, .max_age },
  now)` — oldest first, by the files' size and by each closed segment's newest
  timestamp (from its seal); never the newest segment.

**Seek.** `log.seek(lsn)` and `log.seekTime(t)` return the `Position` to start
an iterator from: the segment from the manifest, then a sparse index per
segment (an entry every 4 KiB, `seg-<id>.idx`, rebuilt if lost or damaged) —
a seek reads a few blocks, not the segment.

**Compaction.** `log.compact(id, ctx, keep)` rewrites a closed segment with
only the records `keep` accepts, at their LSNs (gaps where the others were);
`log.compactByKey(ids, ctx, keyOf)` keeps the newest record per key, as Kafka
does. Crash-safe by temp file + rename. Positions from before still work:
each carries its LSN, and an iterator started there re-finds its record.

**Preallocation.** `Options.preallocate = n` reserves the active segment's
space `n` bytes at a time (`fallocate`) and syncs data with `fdatasync`: a
full disk refuses an append before a byte of it lands, and small appends sync
about 3× faster (no size to record). The reservation is cut at the seal; zeros
past the data read as its end.

**Compression.** `log.compress(id)` turns a closed segment into the zstd
seekable format (`seg-<id>.zst`): the same bytes, so positions, LSNs and the
index do not change, reads decode only the frames they touch, and
`zstd -d` gives the segment back. On a real day of egw-hub records: 9.4× at
level 3 in 0.06 s, 11× at level 9 in 0.22 s.

**Stats.** `log.stats()` counts appends, records, bytes, fsyncs, rotations,
drops and compactions, and — given `Options.monotonic_ns` — keeps a histogram
of fsync latency.

**Many threads.** `seglog.Concurrent.open(gpa, store, io, opts)` is a `Log`
behind a `std.Io.Mutex`, with the same calls. Under `.always` appends from
different threads share their fsync — group commit: 8 threads ~1 250 durable
appends/s, 32 threads ~4 560, against ~280 for one (NVMe) — and each still
returns only once durable.

**Readers in other processes.** `Log.openReadOnly` opens the log beside a
live writer: no lock, and nothing is ever written, created, repaired or
deleted (files are opened `kv.Storage.OpenMode.read_only`). Its iterator
follows the writer across appends, rotations and drops, and an unfinished
tail of the newest segment — no file yet, a short header, a record whose bytes
have not all arrived — reads as "nothing more yet", not as corruption.
⚠ It cannot know what is durable: it may return a record whose `append` has
not returned, which a power failure before that `fsync` would take back. A
consumer that must never see such a record reads through the writer's own
`Log` instead. Mutations on a read-only log return `error.ReadOnly`;
`refresh()` re-reads the manifest for `segments()`.

A backup needs neither: a segment file is append-only, so a plain copy of it
is always a valid prefix. ⚠ A backup that copies segment files but misses
`MANIFEST` (or restores it separately, out of order) leaves the log looking
empty — `open` with `Options.create` then treats that as "nothing here yet",
and the next same-day `rotate` truncates a real segment: back both up, or
neither, in one step.

**Recovering a lost `MANIFEST`.** Every other kind of damage already has a
path back (a torn tail is repaired on `open`, `resync`/`skipSegment` step
over mid-segment damage, a missing `.idx` is rebuilt by a walk) — a torn or
corrupt `MANIFEST` did not, until `Log.rebuildManifest(gpa, store, ids)`:
given the segments' ids in order (an operator's `ls seg-*.log seg-*.zst`, or
a small wrapper that lists the directory — `kv.Storage` has none), it reads
each one's own header and seal and writes a fresh manifest, refusing if they
disagree with each other or a manifest is already there. Run `Log.verify`
afterwards: this checks headers and seals, not every data record.
`egw-hub-tools manifest-rebuild --dir LOG` is the wrapper: it does the
directory listing (`std.Io.Dir`, since this is an offline recovery tool, not
the online path the "no listing" reasoning above is about) and calls
`rebuildManifest`.

**Upgrades.** A log in the previous format is migrated by the writer's `open`
itself: checked whole first (damage refuses it, nothing written), converted
segment by segment in place, each read back before it replaces the old file,
crash-safe and resumed by the next `open`; `log.migration()` reports what was
done. Readers are told to wait meanwhile. Back the directory up before an
upgrade: the old files are not kept. Save whole `Position`s (they carry the
LSN) and a future format change moves nothing for you.

## How it compares

Same machine, same scenarios (`example/bench.zig`; the Go side in
`tools/bench-go`: tidwall/wal v1.2, Prometheus `wlog` v0.315, each with its own
sync), 2026-09-27, NVMe ext4, best of three rounds:

| scenario | seglog | tidwall/wal | Prometheus wlog |
|---|---|---|---|
| append 155 B, fsync each | 295/s — **887/s preallocated** | 305/s | 293/s |
| append 4 KiB, fsync each | 283/s | 292/s | 182/s |
| 8 threads, each append durable | **2 827/s** (group commit, preallocated) | — | — |
| batch 1000 × 155 B | 246 k/s | 244 k/s | 116 k/s |
| read 1 M × 155 B | **2.4 GB/s** | 1.2 GB/s | 1.5 GB/s |
| read 100 k × 4 KiB | 5–6 GB/s | 2.7 GB/s | 5.7 GB/s |
| open after 155 MB | 0.07 s (walks and checks the tail) | 3.5 ms (no tail check) | 0.1 ms (no check at all) |
| seek to a random record | ~17 k/s (LSN index) | ~150/s | — |
| overhead per record | 25 B (CRC, type, length, LSN, time) | 2 B (no CRC) | 7 B |

What the others leave out, and seglog does: a CRC on every record and a
check of the tail on `open` (tidwall has neither; wlog checks only when a
reader reaches the damage), an LSN and a timestamp in every record, seals on
closed segments, preallocation, compression of closed segments, compaction,
and a reader in another process. Writing is disk-bound for all three.

## Verification

`kv`'s `SimStorage` crashes the log at every side effect of scripted
workloads (appends, rotations, drops, compaction, compression,
preallocation, `Concurrent`) under four crash models, and again inside the
recovering `open`. A fuzz harness damages every kind of file; its
deterministic driver (`SEGLOG_FUZZ=<runs>`) runs 160 000 cases in about two
minutes with a watchdog per case. On a real ext4 filesystem,
`tools/crash-dm/run.sh` (root) records the workload through dm-log-writes and
checks the log at every flush and FUA write: all 301 states of a 300-record
run, with and without preallocation, clean. Guards are mutation-checked (see
`SPEC.md`, *Anchoring*).

Provenance: clean-room from the publicly documented designs named above; no
third-party implementation was studied and no source was consulted, so no
`NOTICE` entry is required (root [`NOTICE`](../../NOTICE) §0).
The only committed data, `tools/bench-go/go.mod` and `go.sum`, is the Go
module manifest and checksum list of the Go comparison benchmark's two
dependencies (tidwall/wal, Prometheus `wlog`), generated by our own tooling
(`go mod tidy`); no third-party source or test data is vendored.
