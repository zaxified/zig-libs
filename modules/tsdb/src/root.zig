// SPDX-License-Identifier: MIT

//! tsdb — a time-series persistence layer over `kvtree`: append a sample,
//! stream an ordered `[from, to)` range back, and expire old data with a
//! chunked, resumable retention sweep.
//!
//! **Why `kvtree` and not `kv`.** A time series is nothing but ordered range
//! scans over time. `kv` is a Bitcask-style append-only log with an unordered
//! in-memory keydir — `put`/`get`/`delete`/`compact`, no cursor, no ordering,
//! no range query — so a time-series layer cannot be built on it at all.
//! `kvtree` is the copy-on-write B-tree sibling: ordered `seek`/`next` cursors,
//! MVCC snapshots, multi-key ACID transactions. Every capability this module
//! needs (a range scan that streams, a retention sweep that is one atomic
//! bounded transaction per chunk) is one of those.
//!
//! **The one invariant everything rests on** lives in `codec.zig`:
//! byte-lexicographic order over an encoded key equals logical
//! `(series, timestamp)` order. Fixed-width big-endian fields, and the
//! timestamp's sign bit flipped so pre-epoch samples sort below the epoch. If
//! that identity breaks, `seek(series, from)` + `next()` silently returns the
//! wrong window rather than failing — which is why it is asserted as a property
//! over random pairs, not spot-checked with examples.
//!
//! **Deliberate non-goals in v1** (see SPEC.md): sample compression
//! (Gorilla-style delta-of-delta + XOR), downsampling/rollups, a query
//! language, aggregation functions. `metrics` (registry + Prometheus
//! exposition), `latency-stats` and `finstats` cover live counters, latency
//! summaries and portfolio statistics respectively; none of them persists
//! anything, and this is the persistence layer they lack.

const std = @import("std");
const kvtree = @import("kvtree");

pub const meta = .{
    // The module catalog's one-line entry. This IS the source of truth:
    // README.md's table is rendered from it by `zig build gen-catalog`.
    .doc = "Time-series persistence over `kvtree` — ordered (series, timestamp) key codec, streaming range scans, crash-safe retention-by-age.",
    // The catalog's Platform cell. Prose, because it carries nuance the
    // `platform` enum below cannot -- "any (packer: linux)", "amd64 asm +
    // portable fallback". Rendered by `gen-catalog` alongside `doc`.
    .platform_note = "any",
    .targets = .{.linux64},
    .platform = .any, // all I/O via kvtree → kv's Storage seam
    .role = .util, // a layer over a store the caller owns
    // Inherits kvtree's model: one writer at a time; readers take MVCC
    // snapshots. This module adds no shared mutable state of its own.
    .concurrency = .single_owner,
    // The composite `(series id, big-endian timestamp)` row key is the
    // documented, publicly described shape shared by Prometheus's TSDB,
    // OpenTSDB's HBase rowkeys and InfluxDB's TSM; the read path is LMDB-style
    // ordered range scans (kvtree's own lineage). No third-party
    // implementation was studied — see SPEC.md §Provenance.
    .model_after = "Prometheus TSDB / OpenTSDB composite (series, timestamp) row keys; LMDB-style ordered scans",
    .deps = .{"kvtree"},
};

pub const codec = @import("codec.zig");

pub const Timestamp = codec.Timestamp;
pub const SeriesId = codec.SeriesId;
pub const Label = codec.Label;
pub const Descriptor = codec.Descriptor;

/// Re-export the storage seam so a consumer wires a backend without importing
/// `kvtree`/`kv` directly.
pub const Storage = kvtree.Storage;
pub const FsStorage = kvtree.FsStorage;
pub const SimStorage = kvtree.SimStorage;

const Allocator = std.mem.Allocator;

pub const Error = codec.CanonError ||
    kvtree.GetError ||
    kvtree.CommitError ||
    Allocator.Error ||
    error{
        /// A series-index entry exists but is not an 8-byte id — the tree was
        /// written by something else, or corrupted below kvtree's checks.
        CorruptIndex,
        /// A point entry's value is not an 8-byte sample.
        CorruptPoint,
        /// A retention chunk neither deleted anything nor advanced its resume
        /// position while claiming more work remains. Unreachable by
        /// construction; surfaced as an error so a regression stops instead of
        /// spinning forever.
        SweepStalled,
    };

/// One sample of one series.
pub const Sample = struct { ts: Timestamp, value: f64 };

/// One series' points for `Db.appendBatch` — same shape as `appendMany`'s
/// `(series, points)` pair, batched across several series into one call.
pub const SeriesBatch = struct { series: SeriesId, points: []const Sample };

// ── Db ───────────────────────────────────────────────────────────────────────

/// A time-series view over a `kvtree.Db` the CALLER owns and keeps alive.
///
/// The tree is borrowed, not owned: `kvtree.Cursor` holds a `*Pager` into it,
/// so the `kvtree.Db` must not move for as long as any `Db`/`Range` refers to
/// it. Open it, take its address, and keep it pinned:
///
/// ```zig
/// var tree = try kvtree.Db.open(gpa, store, "series.kvt", .{});
/// defer tree.close();
/// var db = tsdb.Db.init(gpa, &tree);
/// ```
///
/// Sharing the tree with other data is fine — this module confines itself to
/// keys whose first byte is one of `codec.tag_*`.
pub const Db = struct {
    gpa: Allocator,
    tree: *kvtree.Db,
    /// In-memory `(name, labels) -> SeriesId` cache, keyed by the same
    /// canonical `idx_key` bytes `seriesId`/`lookupSeries` build anyway
    /// (owned copies). A consumer that resolves per sample — the natural
    /// naive usage, and the only one the API suggests for a metric name held
    /// as a string — hits this before paying a tree descent, though the
    /// canonicalization itself (needed to make label order irrelevant) still
    /// runs on every call. Call `deinit` to free it.
    series_cache: std.StringHashMapUnmanaged(SeriesId) = .empty,
    /// Retained scratch buffer for `sweepChunk`'s per-chunk delete list —
    /// `clearRetainingCapacity`'d and reused across chunks of one `sweep`
    /// call (and across calls) instead of a fresh `alloc`/`free` every
    /// chunk of a long retention sweep.
    sweep_scratch: std.ArrayList([codec.point_key_len]u8) = .empty,

    pub fn init(gpa: Allocator, tree: *kvtree.Db) Db {
        return .{ .gpa = gpa, .tree = tree };
    }

    /// Frees the in-memory series-id cache and sweep scratch. Does not touch
    /// `tree` (borrowed).
    pub fn deinit(self: *Db) void {
        var it = self.series_cache.keyIterator();
        while (it.next()) |k| self.gpa.free(k.*);
        self.series_cache.deinit(self.gpa);
        self.sweep_scratch.deinit(self.gpa);
        self.* = undefined;
    }

    /// Cache `id` under `idx_key`'s canonical bytes. Best-effort: a failed
    /// dupe/insert just means the next call re-resolves through the tree —
    /// this is a performance cache, not a durability path, so OOM here is
    /// silently absorbed by design (unlike a durable-write path, where the
    /// campaign's writebehind F3 finding is why that distinction matters).
    fn cacheSeriesId(self: *Db, idx_key: []const u8, id: SeriesId) void {
        if (self.series_cache.contains(idx_key)) return;
        const key_copy = self.gpa.dupe(u8, idx_key) catch return;
        self.series_cache.put(self.gpa, key_copy, id) catch self.gpa.free(key_copy);
    }

    // ── series identity ──────────────────────────────────────────────────────

    /// Resolve (metric name, labels) to its stable id, creating it if new.
    ///
    /// The id survives restart because both directions of the mapping and the
    /// allocation counter live in the same tree, written in ONE transaction —
    /// so a crash can never leave an id handed out but unrecorded, or a
    /// forward index without its reverse.
    ///
    /// Label ORDER is irrelevant: `{a=1,b=2}` and `{b=2,a=1}` canonicalize
    /// identically and therefore resolve to the same id.
    pub fn seriesId(self: *Db, name: []const u8, labels: []const Label) Error!SeriesId {
        var idx_key: std.ArrayList(u8) = .empty;
        defer idx_key.deinit(self.gpa);
        try self.indexKey(&idx_key, name, labels);

        if (self.series_cache.get(idx_key.items)) |cached| return cached;

        if (try self.tree.get(self.gpa, idx_key.items)) |v| {
            defer self.gpa.free(v);
            if (v.len != 8) return error.CorruptIndex;
            const id = std.mem.readInt(u64, v[0..8], .big);
            self.cacheSeriesId(idx_key.items, id);
            return id;
        }

        const id = try self.nextSeriesId();
        var id_bytes: [8]u8 = undefined;
        std.mem.writeInt(u64, &id_bytes, id, .big);
        var counter: [8]u8 = undefined;
        std.mem.writeInt(u64, &counter, id + 1, .big);

        const rev_key = reverseKey(id);
        var txn = try self.tree.begin();
        {
            errdefer txn.rollback();
            try txn.put(idx_key.items, &id_bytes);
            try txn.put(&rev_key, idx_key.items[1..]); // canonical form, tag stripped
            try txn.put(&codec.meta_key_next_series, &counter);
        }
        try txn.commit(); // consumes the txn on both outcomes
        self.cacheSeriesId(idx_key.items, id);
        return id;
    }

    /// Resolve without creating. Null when the series has never been written.
    pub fn lookupSeries(self: *Db, name: []const u8, labels: []const Label) Error!?SeriesId {
        var idx_key: std.ArrayList(u8) = .empty;
        defer idx_key.deinit(self.gpa);
        try self.indexKey(&idx_key, name, labels);

        if (self.series_cache.get(idx_key.items)) |cached| return cached;

        const v = (try self.tree.get(self.gpa, idx_key.items)) orelse return null;
        defer self.gpa.free(v);
        if (v.len != 8) return error.CorruptIndex;
        const id = std.mem.readInt(u64, v[0..8], .big);
        self.cacheSeriesId(idx_key.items, id);
        return id;
    }

    /// The canonical bytes registered for `id` (caller frees), or null. Decode
    /// with `codec.parseCanonical` for the name + sorted labels.
    pub fn seriesCanonical(self: *Db, gpa: Allocator, id: SeriesId) Error!?[]u8 {
        const rev_key = reverseKey(id);
        return self.tree.get(gpa, &rev_key);
    }

    /// Every registered series, id + parsed descriptor, in ascending id
    /// order. Replaces walking ids `1, 2, 3, …` until one is missing (which
    /// only ever worked because ids happen to be dense today — this reads
    /// the reverse index directly, so it stays correct if that ever
    /// changes). Holds an MVCC snapshot like `range` — `defer it.deinit()`.
    pub fn seriesIterator(self: *Db) Error!SeriesIterator {
        var snap = try self.tree.snapshot();
        errdefer snap.release();
        var cur = try snap.cursor();
        errdefer cur.deinit();
        try cur.seek(&[_]u8{codec.tag_series_rev});
        return .{ .snap = snap, .cur = cur, .mode = .all };
    }

    /// Every series registered under exactly `name`, filtered to those whose
    /// labels are a SUPERSET of `filter` — every `(name, value)` pair in
    /// `filter` must be present with an equal value; the series may carry
    /// further labels `filter` says nothing about. For a reader that knows
    /// the metric name but not every label value up front (ttydesk's own
    /// `key`/`field` disambiguation: today it walks and decodes every series
    /// in the store to find the ones for one source, `src/diskhist.zig`,
    /// marked `zig-libs request: tsdb — list series`).
    ///
    /// `filter` is borrowed — it must outlive the returned iterator, same
    /// convention as `labels` in `seriesId`. Scans only the series registered
    /// under `name` (a name-prefix range over the forward index), never the
    /// whole series catalog, so a store with many metric names costs this
    /// call nothing proportional to the ones that don't match.
    pub fn findSeries(self: *Db, name: []const u8, filter: []const Label) Error!SeriesIterator {
        if (name.len > codec.max_component_len) return error.ComponentTooLong;
        var snap = try self.tree.snapshot();
        errdefer snap.release();
        var cur = try snap.cursor();
        errdefer cur.deinit();
        var prefix: [1 + 2 + codec.max_component_len]u8 = undefined;
        prefix[0] = codec.tag_series_index;
        std.mem.writeInt(u16, prefix[1..3], @intCast(name.len), .big);
        @memcpy(prefix[3..][0..name.len], name);
        const prefix_len = 3 + name.len;
        try cur.seek(prefix[0..prefix_len]);
        return .{ .snap = snap, .cur = cur, .mode = .{ .by_name = .{
            .prefix = prefix,
            .prefix_len = prefix_len,
            .filter = filter,
        } } };
    }

    fn indexKey(
        self: *Db,
        out: *std.ArrayList(u8),
        name: []const u8,
        labels: []const Label,
    ) Error!void {
        try out.append(self.gpa, codec.tag_series_index);
        var canon: std.ArrayList(u8) = .empty;
        defer canon.deinit(self.gpa);
        try codec.canonicalize(self.gpa, &canon, name, labels);
        try out.appendSlice(self.gpa, canon.items);
    }

    fn reverseKey(id: SeriesId) [9]u8 {
        var k: [9]u8 = undefined;
        k[0] = codec.tag_series_rev;
        std.mem.writeInt(u64, k[1..9], id, .big);
        return k;
    }

    fn nextSeriesId(self: *Db) Error!SeriesId {
        const v = (try self.tree.get(self.gpa, &codec.meta_key_next_series)) orelse return 1;
        defer self.gpa.free(v);
        if (v.len != 8) return error.CorruptIndex;
        return std.mem.readInt(u64, v[0..8], .big);
    }

    // ── writes ───────────────────────────────────────────────────────────────

    /// Append (or overwrite) one sample. Same `(series, ts)` twice = last write
    /// wins; the key IS the identity, so there is no duplicate-point state.
    pub fn append(self: *Db, series: SeriesId, ts: Timestamp, value: f64) Error!void {
        const key = codec.pointKey(series, ts);
        const val = codec.encodeValue(value);
        try self.tree.put(&key, &val);
    }

    /// Append a batch atomically — one transaction, so a crash leaves either
    /// all of `points` or none of it.
    pub fn appendMany(self: *Db, series: SeriesId, points: []const Sample) Error!void {
        if (points.len == 0) return;
        var txn = try self.tree.begin();
        {
            errdefer txn.rollback();
            for (points) |p| {
                const key = codec.pointKey(series, p.ts);
                const val = codec.encodeValue(p.value);
                try txn.put(&key, &val);
            }
        }
        try txn.commit();
    }

    /// Append points for MULTIPLE series in ONE transaction — a crash or an
    /// error partway through leaves every series untouched, never some
    /// committed and others not. A flush across N series via `appendMany`
    /// (one call per series) is N transactions and therefore N commits of
    /// kvtree's own COW protocol (two `fsync`s each: one for the written
    /// pages, one for the meta swap that makes the commit durable — see
    /// `kvtree/src/core.zig`'s `commit`) — `appendBatch` is a CONSTANT number
    /// of commits (one) regardless of how many series are in `batches`, not
    /// one per series. Replaces ttydesk's own per-series-transaction flush
    /// loop (`src/diskhist.zig`, marked `zig-libs request: tsdb — append
    /// points of many series in one transaction`).
    pub fn appendBatch(self: *Db, batches: []const SeriesBatch) Error!void {
        var any = false;
        for (batches) |b| {
            if (b.points.len != 0) {
                any = true;
                break;
            }
        }
        if (!any) return;

        var txn = try self.tree.begin();
        {
            errdefer txn.rollback();
            for (batches) |b| {
                for (b.points) |p| {
                    const key = codec.pointKey(b.series, p.ts);
                    const val = codec.encodeValue(p.value);
                    try txn.put(&key, &val);
                }
            }
        }
        try txn.commit();
    }

    // ── reads ────────────────────────────────────────────────────────────────

    /// Stream `[from, to)` of one series in ascending time order.
    ///
    /// The upper bound is EXCLUSIVE — half-open windows are what makes
    /// consecutive queries tile without double-counting the boundary sample.
    ///
    /// The scan streams: it holds an MVCC snapshot and a `kvtree.Cursor` (a
    /// root-to-leaf page stack), so iterating a month of points costs tree
    /// depth, not the size of the window. This layer buffers nothing.
    pub fn range(self: *Db, series: SeriesId, from: Timestamp, to: Timestamp) Error!Range {
        var snap = try self.tree.snapshot();
        errdefer snap.release();
        var cur = try snap.cursor();
        errdefer cur.deinit();
        const start = codec.pointKey(series, from);
        try cur.seek(&start);
        return .{ .snap = snap, .cur = cur, .series = series, .to = to, .done = false };
    }

    // ── retention ────────────────────────────────────────────────────────────

    pub const SweepOptions = struct {
        /// Upper bound on deletions batched into ONE transaction. Caps both the
        /// transaction's size and the memory the sweep holds (one 17-byte key
        /// each).
        chunk_deletes: usize = 4096,
        /// Upper bound on point keys EXAMINED in one chunk. Needed
        /// independently of `chunk_deletes`: a chunk that finds nothing to
        /// delete must still be bounded, or a store full of live data turns one
        /// "chunk" into a full-keyspace scan.
        chunk_examines: usize = 16384,
        /// Chunks this call may run before returning with `done = false`.
        /// 0 = run to completion.
        max_chunks: usize = 0,
    };

    pub const SweepResult = struct {
        /// Points deleted by this call.
        deleted: usize = 0,
        /// Point keys read by this call. Exposed because it is the *linearity*
        /// witness: a sweep that fails to persist its resume position re-reads
        /// keys it already handled, and only this counter shows it.
        examined: usize = 0,
        /// Chunks (= transactions) this call committed.
        chunks: usize = 0,
        /// True when the whole keyspace has been swept for `cutoff` and the
        /// resume record has been cleared.
        done: bool = false,
    };

    /// Delete every point with `ts < cutoff`, in bounded chunks.
    ///
    /// Each chunk is ONE transaction that deletes at most `chunk_deletes`
    /// points AND advances (or clears) the persisted resume position. That
    /// pairing is the whole guarantee — see SPEC.md §Retention:
    ///
    /// - **Consistent under interruption.** A crash or an early return leaves
    ///   the tree on a chunk boundary: kvtree commits atomically, so the
    ///   deletions and the resume position are both there or both absent. No
    ///   chunk is ever half-applied.
    /// - **Resumable.** A later call with the SAME cutoff continues from the
    ///   persisted position instead of rescanning. A call with a DIFFERENT
    ///   cutoff restarts from the beginning — a larger cutoff expires data the
    ///   old position has already scanned past, and resuming would strand it
    ///   forever.
    /// - **Idempotent.** Re-running after an interruption converges on exactly
    ///   the end state an uninterrupted sweep produces: the operation is
    ///   "delete the keys below a bound", deletes of absent keys are no-ops,
    ///   and the position is only ever an optimization on top.
    pub fn sweep(self: *Db, cutoff: Timestamp, opts: SweepOptions) Error!SweepResult {
        var pos = try self.resumePosition(cutoff);
        var res: SweepResult = .{};
        while (true) {
            const before = pos;
            const chunk = try self.sweepChunk(cutoff, opts, &pos);
            res.deleted += chunk.deleted;
            res.examined += chunk.examined;
            res.chunks += 1;
            if (chunk.done) {
                res.done = true;
                break;
            }
            if (chunk.deleted == 0 and std.mem.order(u8, pos.slice(), before.slice()) != .gt)
                return error.SweepStalled;
            if (opts.max_chunks != 0 and res.chunks >= opts.max_chunks) break;
        }
        return res;
    }

    const ChunkResult = struct { deleted: usize, examined: usize, done: bool };

    /// One bounded chunk: scan forward from `pos`, then commit the deletions
    /// together with the new `pos` in a single transaction.
    fn sweepChunk(self: *Db, cutoff: Timestamp, opts: SweepOptions, pos: *ScanPos) Error!ChunkResult {
        // Retained across chunks/calls (F5) — was a fresh `alloc`/`free` of
        // up to `chunk_deletes * point_key_len` bytes (68 KiB at the
        // defaults) every single chunk of a long retention sweep.
        self.sweep_scratch.clearRetainingCapacity();
        const deletes = &self.sweep_scratch;

        var examined: usize = 0;
        var done = false;

        {
            var cur = try self.tree.cursor();
            defer cur.deinit();
            try cur.seek(pos.slice());
            while (true) {
                const e = (try cur.next()) orelse {
                    done = true;
                    break;
                };
                const p = codec.decodePointKey(e.key) orelse {
                    // Left the point partition (or a malformed key): every
                    // later key sorts above every point key, so we are done.
                    done = true;
                    break;
                };
                examined += 1;

                var reseek = false;
                if (p.ts < cutoff) {
                    const key = e.key[0..codec.point_key_len].*;
                    try deletes.append(self.gpa, key);
                    const succ = codec.pointKeySuccessor(key);
                    pos.set(&succ);
                } else {
                    // Within a series, points at or above the cutoff are a
                    // suffix — nothing further in THIS series can expire, so
                    // jump straight to the next one.
                    if (p.series == std.math.maxInt(SeriesId)) {
                        done = true;
                        break;
                    }
                    const next_series = codec.seriesStartKey(p.series + 1);
                    pos.set(&next_series);
                    reseek = true;
                }

                if (deletes.items.len >= opts.chunk_deletes) break;
                if (examined >= opts.chunk_examines) break;
                if (reseek) try cur.seek(pos.slice());
            }
        }

        // The atomic pairing: deletions + resume advance, one transaction.
        var txn = try self.tree.begin();
        {
            errdefer txn.rollback();
            for (deletes.items) |*k| try txn.del(k);
            if (done) {
                try txn.del(&codec.meta_key_retention);
            } else {
                var rec: [1 + 8 + codec.max_scan_key_len]u8 = undefined;
                const n = encodeResume(&rec, cutoff, pos.slice());
                try txn.put(&codec.meta_key_retention, rec[0..n]);
            }
        }
        try txn.commit();

        return .{ .deleted = deletes.items.len, .examined = examined, .done = done };
    }

    /// Where the next chunk starts: the persisted position when it belongs to
    /// this same cutoff, otherwise the very beginning of the point partition.
    fn resumePosition(self: *Db, cutoff: Timestamp) Error!ScanPos {
        var pos: ScanPos = .{};
        pos.set(&[_]u8{codec.tag_point}); // sorts below every point key
        const st = (try self.retentionState()) orelse return pos;
        if (st.cutoff != cutoff) return pos;
        pos.set(st.pos());
        return pos;
    }

    /// The persisted retention resume record, if a sweep is mid-flight.
    /// Exposed for operators and for the tests that assert resumability.
    pub fn retentionState(self: *Db) Error!?RetentionState {
        const v = (try self.tree.get(self.gpa, &codec.meta_key_retention)) orelse return null;
        defer self.gpa.free(v);
        if (v.len < 1 + 8 or v[0] != 1) return error.CorruptIndex;
        const key = v[9..];
        if (key.len == 0 or key.len > codec.max_scan_key_len) return error.CorruptIndex;
        var st = RetentionState{
            .cutoff = @bitCast(std.mem.readInt(u64, v[1..9], .big)),
            .buf = undefined,
            .len = @intCast(key.len),
        };
        @memcpy(st.buf[0..key.len], key);
        return st;
    }

    // ── size budget ──────────────────────────────────────────────────────────
    //
    // `sweep`/`sweepChunk` above retire data by AGE: a caller picks a cutoff
    // and everything older goes. That is a policy decision this module cannot
    // make on the caller's behalf — but a caller that instead wants "keep the
    // disk usage under N bytes" needs the module to answer "how big is the
    // LIVE data" and "delete the globally oldest points until it fits", which
    // `sweep` alone does not give: a per-series cutoff sweep does not know
    // what counts as "oldest" ACROSS series.
    //
    // kvtree never shrinks the underlying file — freed pages are recycled
    // (COW page reuse) but the file's high-water mark only ever grows, and
    // kvtree exposes no compaction/vacuum operation that would repack it
    // smaller (checked: no such method exists on `kvtree.Db`; SPEC.md §6
    // already documents "merge-less deletes" and a non-shrinking file as
    // inherited kvtree caveats). So `liveSize`/`sweepToBudget` are
    // deliberately about LIVE data — the point entries retention can still
    // reclaim — not `stat().size`, which a caller reads for itself (ttydesk's
    // own `fileSize()`, `src/diskhist.zig`) and which these two functions
    // cannot promise to shrink.

    /// Live point-data size, in bytes: `(number of samples) *
    /// codec.point_entry_bytes`. EXACT, not an estimate — every point key and
    /// value is fixed-width (see `codec.point_entry_bytes`), so a point count
    /// converts to a byte count with no rounding or sampling. Excludes the
    /// series index/reverse-index entries (small — one per series, never
    /// touched by retention) and kvtree's own on-disk page/freelist overhead
    /// (the file itself never shrinks — see this section's doc comment
    /// above). Costs one forward scan of the point partition: O(live points).
    pub fn liveSize(self: *Db) Error!u64 {
        var cur = try self.tree.cursor();
        defer cur.deinit();
        try cur.seek(&[_]u8{codec.tag_point});
        var count: u64 = 0;
        while (try cur.next()) |e| {
            _ = codec.decodePointKey(e.key) orelse break; // left the point partition
            count += 1;
        }
        return count * codec.point_entry_bytes;
    }

    pub const SweepToBudgetOptions = struct {
        /// Deletions per committed transaction. Bounds one transaction's
        /// size, same role as `SweepOptions.chunk_deletes` — but see the
        /// doc comment on `sweepToBudget` for why chunking here does NOT
        /// give the same resumability `sweep` has.
        chunk_deletes: usize = 4096,
        /// Upper bound on deletions this call will make. `sweepToBudget`
        /// seeds one probe per series up front (see its doc comment); this
        /// additionally bounds the deletions themselves, the same way
        /// `SweepOptions.chunk_examines` bounds one retention chunk's work.
        max_deletes: usize = 65536,
    };

    pub const SweepToBudgetResult = struct {
        /// `liveSize()` before this call.
        before: u64,
        /// `liveSize()` after. Exact: `before - after == deleted *
        /// codec.point_entry_bytes` (see `liveSize`'s doc comment on why
        /// this needs no re-scan to compute).
        after: u64,
        /// Points deleted by this call.
        deleted: usize = 0,
        /// True iff `after <= max_bytes`. False means `max_deletes` was hit
        /// before the budget was met — call again to continue.
        done: bool = false,
    };

    /// Delete the globally OLDEST points — across every series, by
    /// timestamp, not by key order — until live data is at most `max_bytes`,
    /// or until `opts.max_deletes` is spent (call again to continue). A
    /// no-op, `.done = true`, if the budget is already met.
    ///
    /// **Why not `sweep` with a computed cutoff.** A point key sorts
    /// `(series, timestamp)` — series-MAJOR — so "the earliest keys in the
    /// tree" is NOT "the oldest points in the store": series 9 can hold data
    /// from a decade ago while series 0 was created five minutes ago. Age
    /// retention (`sweep`) is fine with this because it applies ONE cutoff
    /// independently to every series; a size BUDGET has no such per-series
    /// answer — "which points are `oldest`" is a comparison across series,
    /// and only their timestamps answer it.
    ///
    /// **The algorithm**: a k-way merge over per-series "current oldest
    /// surviving point" candidates, seeded once via `seriesIterator` (one
    /// tree probe per series) and kept in a min-heap ordered by timestamp
    /// (ties broken by series id, for determinism). Popping the heap's
    /// minimum and re-probing that one series for its next point costs
    /// O(log(series count)) per deletion — NOT a rescan of the whole store,
    /// and NOT a bisection over candidate cutoffs (which would need many
    /// full-store passes to evaluate each candidate). Because every point is
    /// fixed-width (`codec.point_entry_bytes`), the number of points to
    /// delete is computed exactly from `liveSize()` up front — no repeated
    /// re-measurement is needed as deletions are collected.
    ///
    /// **Crash-safety — narrower than `sweep`'s.** Each chunk of
    /// `opts.chunk_deletes` deletions commits atomically (kvtree's COW
    /// commit), so a crash mid-call leaves a CONSISTENT tree — never a
    /// torn chunk. But unlike `sweep`, there is no persisted resume record:
    /// a crash (or hitting `max_deletes`) leaves the merge's in-memory
    /// progress on the floor. This is still CORRECT, just not linear the way
    /// resumed retention is — the next call recomputes `liveSize` and
    /// reseeds the heap from scratch, which costs one more series-count
    /// probe pass but reaches the same end state (deleting the globally
    /// oldest points is idempotent in the same sense `sweep`'s cutoff delete
    /// is: re-running never un-deletes anything or deletes the wrong ones).
    /// A future version could persist a resume record shaped like `sweep`'s,
    /// keyed by `max_bytes` instead of a cutoff; not built for v1 — this is
    /// a scope decision, matching how `sweep` itself once lacked resumability
    /// (SPEC.md §5) until that specific gap was closed deliberately.
    pub fn sweepToBudget(self: *Db, max_bytes: u64, opts: SweepToBudgetOptions) Error!SweepToBudgetResult {
        const before = try self.liveSize();
        if (before <= max_bytes) return .{ .before = before, .after = before, .done = true };

        const excess = before - max_bytes;
        const needed: u64 = (excess + codec.point_entry_bytes - 1) / codec.point_entry_bytes;
        const want: usize = @intCast(@min(@as(u64, opts.max_deletes), needed));

        const Candidate = struct { key: [codec.point_key_len]u8, series: SeriesId };
        const less = struct {
            fn f(_: void, a: Candidate, b: Candidate) std.math.Order {
                const pa = codec.decodePointKey(&a.key).?;
                const pb = codec.decodePointKey(&b.key).?;
                if (pa.ts != pb.ts) return std.math.order(pa.ts, pb.ts);
                return std.math.order(pa.series, pb.series); // deterministic tie-break
            }
        }.f;

        var heap: std.PriorityQueue(Candidate, void, less) = .empty;
        defer heap.deinit(self.gpa);
        {
            var it = try self.seriesIterator();
            defer it.deinit();
            while (try it.next(self.gpa)) |entry_val| {
                var entry_mut = entry_val;
                const entry = &entry_mut;
                defer entry.deinit(self.gpa);
                if (try self.firstPointOf(entry.id)) |k| try heap.push(self.gpa, .{ .key = k, .series = entry.id });
            }
        }

        var deletes: std.ArrayList([codec.point_key_len]u8) = .empty;
        defer deletes.deinit(self.gpa);
        while (deletes.items.len < want) {
            const cand = heap.pop() orelse break; // no live points anywhere
            try deletes.append(self.gpa, cand.key);
            if (try self.nextPointAfter(cand.key)) |k| try heap.push(self.gpa, .{ .key = k, .series = cand.series });
        }

        var deleted: usize = 0;
        var i: usize = 0;
        while (i < deletes.items.len) {
            const end = @min(i + opts.chunk_deletes, deletes.items.len);
            var txn = try self.tree.begin();
            {
                errdefer txn.rollback();
                for (deletes.items[i..end]) |*k| try txn.del(k);
            }
            try txn.commit();
            deleted += end - i;
            i = end;
        }

        const after = before - @as(u64, deleted) * codec.point_entry_bytes;
        return .{ .before = before, .after = after, .deleted = deleted, .done = after <= max_bytes };
    }

    /// `series`'s current oldest surviving point, or null if it has none.
    fn firstPointOf(self: *Db, series: SeriesId) Error!?[codec.point_key_len]u8 {
        var cur = try self.tree.cursor();
        defer cur.deinit();
        const start = codec.seriesStartKey(series);
        try cur.seek(&start);
        const e = (try cur.next()) orelse return null;
        const p = codec.decodePointKey(e.key) orelse return null;
        if (p.series != series) return null; // this series has no points
        return e.key[0..codec.point_key_len].*;
    }

    /// The next surviving point strictly after `key`, WITHIN THE SAME
    /// SERIES `key` belongs to — never the next series' first point, which
    /// would silently merge two series' timelines.
    fn nextPointAfter(self: *Db, key: [codec.point_key_len]u8) Error!?[codec.point_key_len]u8 {
        const want_series = codec.decodePointKey(&key).?.series;
        var cur = try self.tree.cursor();
        defer cur.deinit();
        const succ = codec.pointKeySuccessor(key);
        try cur.seek(&succ);
        const e = (try cur.next()) orelse return null;
        const p = codec.decodePointKey(e.key) orelse return null;
        if (p.series != want_series) return null; // exhausted this series
        return e.key[0..codec.point_key_len].*;
    }
};

/// `version(1) | cutoff (raw i64 BE, equality only) | resume key bytes`.
fn encodeResume(out: *[1 + 8 + codec.max_scan_key_len]u8, cutoff: Timestamp, pos: []const u8) usize {
    out[0] = 1;
    std.mem.writeInt(u64, out[1..9], @bitCast(cutoff), .big);
    @memcpy(out[9..][0..pos.len], pos);
    return 9 + pos.len;
}

pub const RetentionState = struct {
    cutoff: Timestamp,
    buf: [codec.max_scan_key_len]u8,
    len: u8,

    pub fn pos(self: *const RetentionState) []const u8 {
        return self.buf[0..self.len];
    }
};

/// A scan position: a point key, a point key + 0x00 (resume strictly after it),
/// or the bare tag byte (the start of the point partition).
const ScanPos = struct {
    buf: [codec.max_scan_key_len]u8 = [_]u8{0} ** codec.max_scan_key_len,
    len: u8 = 0,

    fn set(self: *ScanPos, bytes: []const u8) void {
        @memcpy(self.buf[0..bytes.len], bytes);
        self.len = @intCast(bytes.len);
    }

    fn slice(self: *const ScanPos) []const u8 {
        return self.buf[0..self.len];
    }
};

// ── series listing ──────────────────────────────────────────────────────────

/// One series from `Db.seriesIterator`/`Db.findSeries`: its id and its
/// parsed (name, labels) descriptor. Fully owned — `descriptor`'s slices
/// point into `canon`, not into any iterator-internal buffer, so an entry
/// stays valid past the iterator's next `next()` call or even its `deinit`.
/// `deinit` frees both.
pub const SeriesEntry = struct {
    id: SeriesId,
    /// Owned canonical bytes; `descriptor.name`/`.labels[].name`/`.value`
    /// are subslices of this, per `codec.parseCanonical`.
    canon: []u8,
    descriptor: Descriptor,

    pub fn deinit(self: *SeriesEntry, gpa: Allocator) void {
        self.descriptor.deinit(gpa);
        gpa.free(self.canon);
        self.* = undefined;
    }
};

/// A streaming series-listing iterator (`Db.seriesIterator` / `Db.findSeries`).
/// Holds an MVCC snapshot, same contract as `Range`: concurrent commits do
/// not disturb it, and a leaked one pins kvtree's page reclaim — always
/// `defer it.deinit()`.
pub const SeriesIterator = struct {
    snap: kvtree.Snapshot,
    cur: kvtree.Cursor,
    mode: Mode,

    const Mode = union(enum) {
        /// `Db.seriesIterator`: the whole reverse index, in id order.
        all,
        /// `Db.findSeries`: the forward index, bounded to one name's
        /// contiguous key range (see `Db.findSeries`), filtered by labels.
        by_name: struct {
            prefix: [1 + 2 + codec.max_component_len]u8,
            prefix_len: usize,
            filter: []const Label,
        },
    };

    /// The next matching series, or null once the scan is exhausted (the
    /// reverse index ends / the name-prefix range ends). Allocates the
    /// returned entry's `canon` buffer and `descriptor.labels` on `gpa` —
    /// the caller's to free via `SeriesEntry.deinit`.
    pub fn next(self: *SeriesIterator, gpa: Allocator) Error!?SeriesEntry {
        while (true) {
            const e = (try self.cur.next()) orelse return null;
            switch (self.mode) {
                .all => {
                    if (e.key.len != 9 or e.key[0] != codec.tag_series_rev) return null;
                    const id = std.mem.readInt(u64, e.key[1..9], .big);
                    return try self.decodeEntry(gpa, id, e.val);
                },
                .by_name => |m| {
                    const prefix = m.prefix[0..m.prefix_len];
                    if (e.key.len < prefix.len or !std.mem.eql(u8, e.key[0..prefix.len], prefix))
                        return null; // left this name's contiguous key range
                    if (e.val.len != 8) return error.CorruptIndex;
                    const id = std.mem.readInt(u64, e.val[0..8], .big);
                    const entry = try self.decodeEntry(gpa, id, e.key[1..]);
                    if (!labelsMatch(entry.descriptor.labels, m.filter)) {
                        var mut = entry;
                        mut.deinit(gpa);
                        continue; // keep scanning within this name's range
                    }
                    return entry;
                },
            }
        }
    }

    /// Dupe `canon_bytes` onto `gpa` and parse it — see `SeriesEntry`'s doc
    /// comment for why this is a fresh copy rather than a slice borrowed
    /// from the cursor's own (next-call-invalidated) leaf buffer.
    fn decodeEntry(self: *SeriesIterator, gpa: Allocator, id: SeriesId, canon_bytes: []const u8) Error!SeriesEntry {
        _ = self;
        const canon = try gpa.dupe(u8, canon_bytes);
        errdefer gpa.free(canon);
        const descriptor = codec.parseCanonical(gpa, canon) catch |err| switch (err) {
            error.Malformed => return error.CorruptIndex,
            error.OutOfMemory => return error.OutOfMemory,
        };
        return .{ .id = id, .canon = canon, .descriptor = descriptor };
    }

    pub fn deinit(self: *SeriesIterator) void {
        self.cur.deinit();
        self.snap.release();
        self.* = undefined;
    }
};

/// True iff every `(name, value)` pair in `filter` is present in `have`
/// (label-name equality, case-sensitive, exact value match). `have` may
/// carry further labels `filter` says nothing about.
fn labelsMatch(have: []const Label, filter: []const Label) bool {
    for (filter) |f| {
        var found = false;
        for (have) |h| {
            if (std.mem.eql(u8, h.name, f.name) and std.mem.eql(u8, h.value, f.value)) {
                found = true;
                break;
            }
        }
        if (!found) return false;
    }
    return true;
}

// ── Range ────────────────────────────────────────────────────────────────────

/// A streaming `[from, to)` iterator. Holds an MVCC snapshot, so concurrent
/// commits do not disturb it; `deinit` releases both the cursor and the
/// snapshot (leaking a snapshot pins kvtree's page reclaim, so always `defer`).
pub const Range = struct {
    snap: kvtree.Snapshot,
    cur: kvtree.Cursor,
    series: SeriesId,
    to: Timestamp,
    done: bool,

    pub fn next(self: *Range) Error!?Sample {
        if (self.done) return null;
        const e = (try self.cur.next()) orelse {
            self.done = true;
            return null;
        };
        const p = codec.decodePointKey(e.key) orelse {
            self.done = true;
            return null;
        };
        // Ordering is the whole contract: once the key leaves this series or
        // reaches the exclusive upper bound, nothing later can qualify.
        if (p.series != self.series or p.ts >= self.to) {
            self.done = true;
            return null;
        }
        const v = codec.decodeValue(e.val) orelse return error.CorruptPoint;
        return .{ .ts = p.ts, .value = v };
    }

    pub fn deinit(self: *Range) void {
        self.cur.deinit();
        self.snap.release();
        self.* = undefined;
    }
};

// ── dark-tests aggregator (CONVENTIONS.md §6 step 3) ─────────────────────────

test {
    std.testing.refAllDecls(@This());
    _ = @import("codec.zig");
}

// ── tests ────────────────────────────────────────────────────────────────────

const testing = std.testing;

/// A `SimStorage`-backed store plus its tsdb view, for tests.
const Fixture = struct {
    sim: *kvtree.SimStorage,
    tree: *kvtree.Db,
    db: Db,
    gpa: Allocator,

    fn init(gpa: Allocator) !Fixture {
        const sim = try gpa.create(kvtree.SimStorage);
        sim.* = kvtree.SimStorage.init(gpa);
        sim.allow_overwrite = true; // COW page store: meta slots + page reuse
        const tree = try gpa.create(kvtree.Db);
        tree.* = try kvtree.Db.open(gpa, sim.storage(), "series.kvt", .{});
        return .{ .sim = sim, .tree = tree, .db = Db.init(gpa, tree), .gpa = gpa };
    }

    /// Close and reopen the tree from the same simulated media — the
    /// restart-survival check.
    fn reopen(self: *Fixture) !void {
        self.db.deinit(); // free the old Db's series-id cache before replacing it
        self.tree.close();
        self.tree.* = try kvtree.Db.open(self.gpa, self.sim.storage(), "series.kvt", .{});
        self.db = Db.init(self.gpa, self.tree);
    }

    fn deinit(self: *Fixture) void {
        self.db.deinit();
        self.tree.close();
        self.gpa.destroy(self.tree);
        self.sim.deinit();
        self.gpa.destroy(self.sim);
    }
};

fn collect(gpa: Allocator, db: *Db, series: SeriesId, from: Timestamp, to: Timestamp) ![]Sample {
    var out: std.ArrayList(Sample) = .empty;
    errdefer out.deinit(gpa);
    var r = try db.range(series, from, to);
    defer r.deinit();
    while (try r.next()) |s| try out.append(gpa, s);
    return out.toOwnedSlice(gpa);
}

test "smoke: append and read back one series in time order" {
    var fx = try Fixture.init(testing.allocator);
    defer fx.deinit();

    const s = try fx.db.seriesId("cpu", &.{.{ .name = "host", .value = "a" }});
    try fx.db.appendMany(s, &.{
        .{ .ts = 30, .value = 3 },
        .{ .ts = 10, .value = 1 }, // out of order on the way in…
        .{ .ts = 20, .value = 2 },
    });

    const got = try collect(testing.allocator, &fx.db, s, std.math.minInt(i64), std.math.maxInt(i64));
    defer testing.allocator.free(got);
    // …ordered on the way out, because the key IS the order.
    try testing.expectEqual(@as(usize, 3), got.len);
    try testing.expectEqual(@as(Timestamp, 10), got[0].ts);
    try testing.expectEqual(@as(Timestamp, 20), got[1].ts);
    try testing.expectEqual(@as(Timestamp, 30), got[2].ts);
    try testing.expectEqual(@as(f64, 2), got[1].value);
}

test "series identity: label order irrelevant, ids stable across reopen" {
    var fx = try Fixture.init(testing.allocator);
    defer fx.deinit();

    const a = try fx.db.seriesId("http", &.{
        .{ .name = "code", .value = "200" },
        .{ .name = "path", .value = "/" },
    });
    const b = try fx.db.seriesId("http", &.{
        .{ .name = "path", .value = "/" },
        .{ .name = "code", .value = "200" },
    });
    try testing.expectEqual(a, b);

    const c = try fx.db.seriesId("http", &.{
        .{ .name = "code", .value = "500" },
        .{ .name = "path", .value = "/" },
    });
    try testing.expect(a != c);

    const no_labels = try fx.db.seriesId("http", &.{});
    try testing.expect(no_labels != a and no_labels != c);

    try fx.reopen();
    const a2 = try fx.db.seriesId("http", &.{
        .{ .name = "path", .value = "/" },
        .{ .name = "code", .value = "200" },
    });
    try testing.expectEqual(a, a2);
    // …and a brand-new series still gets a fresh id (the counter is durable).
    const d = try fx.db.seriesId("http", &.{.{ .name = "code", .value = "404" }});
    try testing.expect(d != a and d != c and d != no_labels);

    // Reverse index round-trips.
    const canon = (try fx.db.seriesCanonical(testing.allocator, a)).?;
    defer testing.allocator.free(canon);
    var desc = try codec.parseCanonical(testing.allocator, canon);
    defer desc.deinit(testing.allocator);
    try testing.expectEqualStrings("http", desc.name);
    try testing.expectEqualStrings("code", desc.labels[0].name);
    try testing.expectEqualStrings("200", desc.labels[0].value);
}

test "lookupSeries does not create; unknown series reads empty" {
    var fx = try Fixture.init(testing.allocator);
    defer fx.deinit();

    try testing.expect((try fx.db.lookupSeries("nope", &.{})) == null);
    const got = try collect(testing.allocator, &fx.db, 12345, 0, 100);
    defer testing.allocator.free(got);
    try testing.expectEqual(@as(usize, 0), got.len);

    const s = try fx.db.seriesId("nope", &.{});
    try testing.expectEqual(s, (try fx.db.lookupSeries("nope", &.{})).?);
}

// ── series listing ──────────────────────────────────────────────────────────

test "seriesIterator: empty store yields nothing" {
    var fx = try Fixture.init(testing.allocator);
    defer fx.deinit();
    var it = try fx.db.seriesIterator();
    defer it.deinit();
    try testing.expect((try it.next(testing.allocator)) == null);
}

test "seriesIterator: every created series comes back, in id order, with its descriptor" {
    const gpa = testing.allocator;
    var fx = try Fixture.init(gpa);
    defer fx.deinit();

    const a = try fx.db.seriesId("cpu", &.{.{ .name = "host", .value = "a" }});
    const b = try fx.db.seriesId("mem", &.{});
    const c = try fx.db.seriesId("cpu", &.{ .{ .name = "host", .value = "b" }, .{ .name = "core", .value = "0" } });

    var it = try fx.db.seriesIterator();
    defer it.deinit();

    var seen: std.ArrayList(SeriesId) = .empty;
    defer seen.deinit(gpa);
    var last_id: SeriesId = 0;
    while (try it.next(gpa)) |entry_val| {
        var entry_mut = entry_val;
        const entry = &entry_mut;
        defer entry.deinit(gpa);
        try testing.expect(entry.id > last_id); // ascending id order
        last_id = entry.id;
        try seen.append(gpa, entry.id);
        if (entry.id == a) {
            try testing.expectEqualStrings("cpu", entry.descriptor.name);
            try testing.expectEqual(@as(usize, 1), entry.descriptor.labels.len);
        } else if (entry.id == c) {
            try testing.expectEqualStrings("cpu", entry.descriptor.name);
            try testing.expectEqual(@as(usize, 2), entry.descriptor.labels.len);
        } else if (entry.id == b) {
            try testing.expectEqualStrings("mem", entry.descriptor.name);
            try testing.expectEqual(@as(usize, 0), entry.descriptor.labels.len);
        } else {
            return error.TestUnexpectedResult;
        }
    }
    try testing.expectEqual(@as(usize, 3), seen.items.len);
}

test "findSeries: filters by name and by a label subset, leaving unrelated series out" {
    const gpa = testing.allocator;
    var fx = try Fixture.init(gpa);
    defer fx.deinit();

    const cpu_a = try fx.db.seriesId("cpu", &.{ .{ .name = "host", .value = "a" }, .{ .name = "core", .value = "0" } });
    const cpu_a1 = try fx.db.seriesId("cpu", &.{ .{ .name = "host", .value = "a" }, .{ .name = "core", .value = "1" } });
    const cpu_b = try fx.db.seriesId("cpu", &.{ .{ .name = "host", .value = "b" }, .{ .name = "core", .value = "0" } });
    _ = try fx.db.seriesId("mem", &.{.{ .name = "host", .value = "a" }}); // different name: must never match

    // Name only: every "cpu" series, regardless of labels.
    {
        var it = try fx.db.findSeries("cpu", &.{});
        defer it.deinit();
        var count: usize = 0;
        while (try it.next(gpa)) |e_val| {
            var e_mut = e_val;
            const e = &e_mut;
            defer e.deinit(gpa);
            try testing.expectEqualStrings("cpu", e.descriptor.name);
            count += 1;
        }
        try testing.expectEqual(@as(usize, 3), count);
    }

    // Name + a label subset: only host=a, both cores.
    {
        var it = try fx.db.findSeries("cpu", &.{.{ .name = "host", .value = "a" }});
        defer it.deinit();
        var got: std.ArrayList(SeriesId) = .empty;
        defer got.deinit(gpa);
        while (try it.next(gpa)) |e_val| {
            var e_mut = e_val;
            const e = &e_mut;
            defer e.deinit(gpa);
            try got.append(gpa, e.id);
        }
        try testing.expectEqual(@as(usize, 2), got.items.len);
        try testing.expect(std.mem.indexOfScalar(SeriesId, got.items, cpu_a) != null);
        try testing.expect(std.mem.indexOfScalar(SeriesId, got.items, cpu_a1) != null);
        try testing.expect(std.mem.indexOfScalar(SeriesId, got.items, cpu_b) == null);
    }

    // Name + a fully specific label set: exactly one match.
    {
        var it = try fx.db.findSeries("cpu", &.{ .{ .name = "host", .value = "b" }, .{ .name = "core", .value = "0" } });
        defer it.deinit();
        var only = (try it.next(gpa)).?;
        defer only.deinit(gpa);
        try testing.expectEqual(cpu_b, only.id);
        try testing.expect((try it.next(gpa)) == null);
    }

    // A name that was never registered: no matches, not an error.
    {
        var it = try fx.db.findSeries("disk", &.{});
        defer it.deinit();
        try testing.expect((try it.next(gpa)) == null);
    }
}

test "range: half-open [from, to) and never bleeds into a neighbouring series" {
    var fx = try Fixture.init(testing.allocator);
    defer fx.deinit();

    const a = try fx.db.seriesId("m", &.{.{ .name = "i", .value = "a" }});
    const b = try fx.db.seriesId("m", &.{.{ .name = "i", .value = "b" }});
    for (0..10) |i| {
        try fx.db.append(a, @intCast(i), @floatFromInt(i));
        try fx.db.append(b, @intCast(i), @floatFromInt(100 + i));
    }

    const got = try collect(testing.allocator, &fx.db, a, 3, 7);
    defer testing.allocator.free(got);
    // Lower bound INCLUSIVE, upper bound EXCLUSIVE: 3,4,5,6 — not 7.
    try testing.expectEqual(@as(usize, 4), got.len);
    try testing.expectEqual(@as(Timestamp, 3), got[0].ts);
    try testing.expectEqual(@as(Timestamp, 6), got[got.len - 1].ts);
    for (got) |s| try testing.expect(s.value < 100); // series b never appears

    // The last series in the tree must still terminate at its own end.
    const tail = try collect(testing.allocator, &fx.db, b, 8, std.math.maxInt(i64));
    defer testing.allocator.free(tail);
    try testing.expectEqual(@as(usize, 2), tail.len);

    // Empty windows.
    const empty = try collect(testing.allocator, &fx.db, a, 7, 7);
    defer testing.allocator.free(empty);
    try testing.expectEqual(@as(usize, 0), empty.len);
}

test "range: negative (pre-epoch) timestamps sort below the epoch" {
    var fx = try Fixture.init(testing.allocator);
    defer fx.deinit();

    const s = try fx.db.seriesId("hist", &.{});
    const ts = [_]Timestamp{ std.math.minInt(i64), -1_000_000, -1, 0, 1, 1_000_000, std.math.maxInt(i64) };
    for (ts, 0..) |t, i| try fx.db.append(s, t, @floatFromInt(i));

    const all = try collect(testing.allocator, &fx.db, s, std.math.minInt(i64), std.math.maxInt(i64));
    defer testing.allocator.free(all);
    // maxInt is excluded by the half-open bound; everything else, in order.
    try testing.expectEqual(ts.len - 1, all.len);
    for (all, 0..) |sample, i| try testing.expectEqual(ts[i], sample.ts);

    // A window that straddles the epoch.
    const straddle = try collect(testing.allocator, &fx.db, s, -1, 2);
    defer testing.allocator.free(straddle);
    try testing.expectEqual(@as(usize, 3), straddle.len);
    try testing.expectEqual(@as(Timestamp, -1), straddle[0].ts);
}

test "range streams: iterating thousands of points allocates nothing at this layer" {
    var fx = try Fixture.init(testing.allocator);
    defer fx.deinit();

    const n = 3000;
    const s = try fx.db.seriesId("stream", &.{});
    var batch: std.ArrayList(Sample) = .empty;
    defer batch.deinit(testing.allocator);
    for (0..n) |i| try batch.append(testing.allocator, .{ .ts = @intCast(i), .value = @floatFromInt(i) });
    // Several transactions so the tree is genuinely multi-level.
    var off: usize = 0;
    while (off < n) : (off += 500) try fx.db.appendMany(s, batch.items[off..@min(off + 500, n)]);

    // Swap this layer's allocator for a tiny fixed buffer. Buffering the whole
    // range would need n * 16 bytes = ~48 KB; streaming needs zero.
    var tiny: [256]u8 = undefined;
    var fba = std.heap.FixedBufferAllocator.init(&tiny);
    fx.db.gpa = fba.allocator();

    var r = try fx.db.range(s, 0, n);
    defer r.deinit();
    var count: usize = 0;
    var last: Timestamp = -1;
    while (try r.next()) |sample| {
        try testing.expect(sample.ts > last);
        last = sample.ts;
        count += 1;
    }
    try testing.expectEqual(@as(usize, n), count);

    fx.db.gpa = testing.allocator;
}

// ── appendBatch ──────────────────────────────────────────────────────────────

test "appendBatch: commits points for multiple series at once" {
    const gpa = testing.allocator;
    var fx = try Fixture.init(gpa);
    defer fx.deinit();

    const a = try fx.db.seriesId("a", &.{});
    const b = try fx.db.seriesId("b", &.{});
    try fx.db.appendBatch(&.{
        .{ .series = a, .points = &.{ .{ .ts = 1, .value = 10 }, .{ .ts = 2, .value = 20 } } },
        .{ .series = b, .points = &.{.{ .ts = 5, .value = 50 }} },
    });

    const ga = try collect(gpa, &fx.db, a, std.math.minInt(i64), std.math.maxInt(i64));
    defer gpa.free(ga);
    try testing.expectEqual(@as(usize, 2), ga.len);
    const gb = try collect(gpa, &fx.db, b, std.math.minInt(i64), std.math.maxInt(i64));
    defer gpa.free(gb);
    try testing.expectEqual(@as(usize, 1), gb.len);
    try testing.expectEqual(@as(f64, 50), gb[0].value);
}

test "appendBatch: an empty call and a call whose series all have zero points are no-ops" {
    const gpa = testing.allocator;
    var fx = try Fixture.init(gpa);
    defer fx.deinit();
    const a = try fx.db.seriesId("a", &.{});

    try fx.db.appendBatch(&.{});
    try fx.db.appendBatch(&.{.{ .series = a, .points = &.{} }});
    try testing.expectEqual(@as(usize, 0), try totalPoints(gpa, &fx.db, &.{a}));
}

test "appendBatch: an allocation failure partway through leaves NOTHING committed — all series or none" {
    // Same guarantee `appendMany` already gives for one series, extended
    // across a whole batch: `appendBatch` wraps every series' puts in ONE
    // kvtree transaction, so a failure partway through (here: the
    // underlying tree's allocator running out) must roll back everything,
    // not just the series it happened to fail inside.
    const gpa = testing.allocator;
    var fx = try Fixture.init(gpa);
    defer fx.deinit();

    const a = try fx.db.seriesId("a", &.{});
    const b = try fx.db.seriesId("b", &.{});

    // Swap the underlying kvtree's allocator (what `Txn.put`'s key/val
    // dupes come from — see `kvtree.Txn.put`) for one that fails a few
    // allocations in, well before either series' points are fully buffered.
    var fa = std.testing.FailingAllocator.init(gpa, .{ .fail_index = 2 });
    fx.tree.gpa = fa.allocator();
    const batches = [_]SeriesBatch{
        .{ .series = a, .points = &.{ .{ .ts = 1, .value = 1 }, .{ .ts = 2, .value = 2 } } },
        .{ .series = b, .points = &.{ .{ .ts = 1, .value = 1 }, .{ .ts = 2, .value = 2 } } },
    };
    try testing.expectError(error.OutOfMemory, fx.db.appendBatch(&batches));
    fx.tree.gpa = gpa; // restore before any further use of the tree

    try testing.expectEqual(@as(usize, 0), try totalPoints(gpa, &fx.db, &.{ a, b }));
}

test "appendBatch: a crash mid-batch loses everything or nothing, never a partial series set" {
    const gpa = testing.allocator;
    const CrashMode = @FieldType(kvtree.SimStorage, "crash_mode");
    const modes = [_]CrashMode{ .lose_unsynced, .torn_tail, .reorder_unsynced, .keep_unsynced };
    for (modes) |mode| {
        var crash_at: usize = 0;
        var survived_without_crashing = false;
        while (!survived_without_crashing) : (crash_at += 1) {
            try testing.expect(crash_at < 200);

            var fx = try Fixture.init(gpa);
            defer fx.deinit();
            const a = try fx.db.seriesId("a", &.{});
            const b = try fx.db.seriesId("b", &.{});
            const c = try fx.db.seriesId("c", &.{});

            fx.sim.crash_mode = mode;
            fx.sim.reorder_seed = 0xba7 +% @as(u64, crash_at) *% 0x9e3779b97f4a7c15;
            fx.sim.ops_until_crash = crash_at;
            const batches = [_]SeriesBatch{
                .{ .series = a, .points = &.{ .{ .ts = 1, .value = 1 }, .{ .ts = 2, .value = 2 } } },
                .{ .series = b, .points = &.{ .{ .ts = 1, .value = 1 }, .{ .ts = 2, .value = 2 } } },
                .{ .series = c, .points = &.{ .{ .ts = 1, .value = 1 }, .{ .ts = 2, .value = 2 } } },
            };
            if (fx.db.appendBatch(&batches)) |_| {
                survived_without_crashing = true;
            } else |_| {}
            fx.sim.reboot();
            try fx.reopen();

            const na = try totalPoints(gpa, &fx.db, &.{a});
            const nb = try totalPoints(gpa, &fx.db, &.{b});
            const nc = try totalPoints(gpa, &fx.db, &.{c});
            // Every series has the SAME count (0 or 2) -- the batch is one
            // transaction, so a crash can never leave one series filled and
            // another empty.
            try testing.expectEqual(na, nb);
            try testing.expectEqual(nb, nc);
            try testing.expect(na == 0 or na == 2);
        }
    }
}

test "appendBatch commits ALL series in one transaction: sync count is constant, not per series" {
    const gpa = testing.allocator;
    var sim = kvtree.SimStorage.init(gpa);
    defer sim.deinit();
    sim.allow_overwrite = true;
    var counting = CountingStorage{ .inner = sim.storage() };
    var tree = try kvtree.Db.open(gpa, counting.storage(), "series.kvt", .{});
    defer tree.close();
    var db = Db.init(gpa, &tree);
    defer db.deinit();

    const a = try db.seriesId("a", &.{});
    const b = try db.seriesId("b", &.{});
    const c = try db.seriesId("c", &.{});

    // One series' worth of points, for the single-transaction baseline.
    const before_single = counting.sync_count;
    try db.appendMany(a, &.{ .{ .ts = 1, .value = 1 }, .{ .ts = 2, .value = 2 } });
    const per_single_txn = counting.sync_count - before_single;
    try testing.expect(per_single_txn > 0); // a real commit must sync at least once

    // Three series' worth of points in ONE appendBatch call.
    const before_batch = counting.sync_count;
    try db.appendBatch(&.{
        .{ .series = a, .points = &.{ .{ .ts = 3, .value = 3 }, .{ .ts = 4, .value = 4 } } },
        .{ .series = b, .points = &.{ .{ .ts = 1, .value = 1 }, .{ .ts = 2, .value = 2 } } },
        .{ .series = c, .points = &.{ .{ .ts = 1, .value = 1 }, .{ .ts = 2, .value = 2 } } },
    });
    const per_batch_txn = counting.sync_count - before_batch;

    // Same sync cost as ONE `appendMany` call, whatever it is (kvtree's own
    // commit protocol) -- NOT three times as much, which is what three
    // separate `appendMany` calls (one per series) would have cost.
    try testing.expectEqual(per_single_txn, per_batch_txn);
}

// ── retention ────────────────────────────────────────────────────────────────

/// Seed `series_count` series with `per_series` points each at ts 0..per_series.
fn seedGrid(fx: *Fixture, series_count: usize, per_series: usize) ![]SeriesId {
    const ids = try fx.gpa.alloc(SeriesId, series_count);
    errdefer fx.gpa.free(ids);
    var name_buf: [16]u8 = undefined;
    var batch: std.ArrayList(Sample) = .empty;
    defer batch.deinit(fx.gpa);
    for (ids, 0..) |*id, i| {
        const nm = try std.fmt.bufPrint(&name_buf, "s{d}", .{i});
        id.* = try fx.db.seriesId(nm, &.{});
        batch.clearRetainingCapacity();
        for (0..per_series) |t|
            try batch.append(fx.gpa, .{ .ts = @intCast(t), .value = @floatFromInt(t) });
        try fx.db.appendMany(id.*, batch.items);
    }
    return ids;
}

fn totalPoints(gpa: Allocator, db: *Db, ids: []const SeriesId) !usize {
    var n: usize = 0;
    for (ids) |id| {
        const got = try collect(gpa, db, id, std.math.minInt(i64), std.math.maxInt(i64));
        defer gpa.free(got);
        n += got.len;
    }
    return n;
}

fn oldestPoint(gpa: Allocator, db: *Db, ids: []const SeriesId) !?Timestamp {
    var oldest: ?Timestamp = null;
    for (ids) |id| {
        const got = try collect(gpa, db, id, std.math.minInt(i64), std.math.maxInt(i64));
        defer gpa.free(got);
        if (got.len == 0) continue;
        if (oldest == null or got[0].ts < oldest.?) oldest = got[0].ts;
    }
    return oldest;
}

test "retention: deletes strictly below the cutoff, keeps the rest, is idempotent" {
    const gpa = testing.allocator;
    var fx = try Fixture.init(gpa);
    defer fx.deinit();

    const ids = try seedGrid(&fx, 4, 50);
    defer gpa.free(ids);

    const res = try fx.db.sweep(20, .{});
    try testing.expect(res.done);
    try testing.expectEqual(@as(usize, 4 * 20), res.deleted);
    try testing.expectEqual(@as(usize, 4 * 30), try totalPoints(gpa, &fx.db, ids));
    try testing.expectEqual(@as(?Timestamp, 20), try oldestPoint(gpa, &fx.db, ids));

    // Re-running is a no-op, and clears no live data.
    const again = try fx.db.sweep(20, .{});
    try testing.expect(again.done);
    try testing.expectEqual(@as(usize, 0), again.deleted);
    try testing.expectEqual(@as(usize, 4 * 30), try totalPoints(gpa, &fx.db, ids));

    // The resume record is gone once a sweep completes.
    try testing.expect((try fx.db.retentionState()) == null);

    // The series index survives retention even when a series loses every point.
    const wiped = try fx.db.sweep(std.math.maxInt(i64), .{});
    try testing.expect(wiped.done);
    try testing.expectEqual(@as(usize, 0), try totalPoints(gpa, &fx.db, ids));
    try testing.expectEqual(ids[0], (try fx.db.lookupSeries("s0", &.{})).?);
}

test "retention: chunked sweep converges on the same end state as one shot" {
    const gpa = testing.allocator;

    var one_shot: Fixture = try .init(gpa);
    defer one_shot.deinit();
    const ids_a = try seedGrid(&one_shot, 5, 40);
    defer gpa.free(ids_a);
    _ = try one_shot.db.sweep(25, .{});

    var chunked: Fixture = try .init(gpa);
    defer chunked.deinit();
    const ids_b = try seedGrid(&chunked, 5, 40);
    defer gpa.free(ids_b);

    var calls: usize = 0;
    var deleted: usize = 0;
    var examined: usize = 0;
    while (true) {
        calls += 1;
        try testing.expect(calls < 200); // termination is part of the contract
        const r = try chunked.db.sweep(25, .{ .chunk_deletes = 7, .chunk_examines = 9, .max_chunks = 1 });
        deleted += r.deleted;
        examined += r.examined;
        if (r.done) break;
        // Mid-sweep the resume record exists and belongs to this cutoff.
        const st = try chunked.db.retentionState();
        try testing.expect(st != null);
        try testing.expectEqual(@as(Timestamp, 25), st.?.cutoff);
    }

    try testing.expectEqual(@as(usize, 5 * 25), deleted);
    try testing.expectEqual(
        try totalPoints(gpa, &one_shot.db, ids_a),
        try totalPoints(gpa, &chunked.db, ids_b),
    );
    for (ids_a, ids_b) |a, b| {
        const ga = try collect(gpa, &one_shot.db, a, std.math.minInt(i64), std.math.maxInt(i64));
        defer gpa.free(ga);
        const gb = try collect(gpa, &chunked.db, b, std.math.minInt(i64), std.math.maxInt(i64));
        defer gpa.free(gb);
        try testing.expectEqualSlices(Sample, ga, gb);
    }

    // LINEARITY — the resume position's reason to exist, and the only thing
    // that can see a position which is persisted but stale. Every key a correct
    // sweep examines is either (a) deleted, (b) the one live probe that retires
    // a series — at most `series_count` over the WHOLE sweep, because a correct
    // sweep never returns to a retired series — or (c) the key a chunk stopped
    // on, at most one per chunk. So `examined <= deleted + series + chunks`.
    // A sweep that restarts from the beginning every chunk re-probes every
    // retired series and blows the bound (measured: 175 vs. 130 here).
    try testing.expect(examined <= deleted + 5 + calls);
}

test "retention: resumes across a full close/reopen of the store" {
    const gpa = testing.allocator;
    var fx = try Fixture.init(gpa);
    defer fx.deinit();

    const ids = try seedGrid(&fx, 3, 30);
    defer gpa.free(ids);

    const first = try fx.db.sweep(15, .{ .chunk_deletes = 5, .max_chunks = 1 });
    try testing.expect(!first.done);
    const st = (try fx.db.retentionState()).?;

    try fx.reopen(); // the resume record must be durable, not in-memory state

    const after = (try fx.db.retentionState()).?;
    try testing.expectEqual(st.cutoff, after.cutoff);
    try testing.expectEqualSlices(u8, st.pos(), after.pos());

    const rest = try fx.db.sweep(15, .{ .chunk_deletes = 5 });
    try testing.expect(rest.done);
    try testing.expectEqual(@as(usize, 3 * 15), first.deleted + rest.deleted);
    try testing.expectEqual(@as(?Timestamp, 15), try oldestPoint(gpa, &fx.db, ids));
}

test "retention: a larger cutoff restarts instead of resuming past unexpired data" {
    const gpa = testing.allocator;
    var fx = try Fixture.init(gpa);
    defer fx.deinit();

    const ids = try seedGrid(&fx, 4, 40);
    defer gpa.free(ids);

    // Stop the sweep after it has FINISHED the first series and jumped past
    // that series' still-live tail — 5 deletions (ts 0..4) plus the one probe
    // that says "the rest of series 1 is live", i.e. 6 examines. The resume
    // position now sits at series 2, with series 1's ts 5..39 behind it.
    const partial = try fx.db.sweep(5, .{ .chunk_examines = 6, .max_chunks = 1 });
    try testing.expect(!partial.done);
    try testing.expectEqual(@as(usize, 5), partial.deleted);
    const st = try fx.db.retentionState();
    try testing.expect(st != null);
    const series2_start = codec.seriesStartKey(ids[1]);
    try testing.expectEqualSlices(u8, &series2_start, st.?.pos());

    // Now sweep with a LATER cutoff. Series 1's ts 5..29 lie BEHIND the stored
    // position and are newly expired; honouring that position would strand them
    // for good, because a completed sweep clears the record.
    const wider = try fx.db.sweep(30, .{});
    try testing.expect(wider.done);
    try testing.expectEqual(@as(?Timestamp, 30), try oldestPoint(gpa, &fx.db, ids));
    try testing.expectEqual(@as(usize, 4 * 10), try totalPoints(gpa, &fx.db, ids));
}

test "series ids are allocated atomically — a crash never strands a half-registered series" {
    const gpa = testing.allocator;

    // The claim: the forward index, the reverse index and the id counter are
    // written in ONE transaction, so no crash can expose an id whose reverse
    // entry is missing, or hand out an id the counter has not moved past.
    const CrashMode = @FieldType(kvtree.SimStorage, "crash_mode");
    const modes = [_]CrashMode{ .lose_unsynced, .torn_tail, .reorder_unsynced, .keep_unsynced };
    for (modes) |mode| {
        var crash_at: usize = 0;
        var survived_without_crashing = false;
        while (!survived_without_crashing) : (crash_at += 1) {
            try testing.expect(crash_at < 200);

            var fx = try Fixture.init(gpa);
            defer fx.deinit();
            fx.sim.crash_mode = mode;
            // `reorder_seed` is `u64` and its splitmix64-style mixing constant
            // is genuinely a 64-bit magic number — mix in `u64`, not in
            // `crash_at`'s native `usize` (which the constant doesn't fit on
            // a 32-bit target).
            fx.sim.reorder_seed = 0x51d +% @as(u64, crash_at) *% 0x9e3779b97f4a7c15;

            const first = try fx.db.seriesId("base", &.{});
            fx.sim.ops_until_crash = crash_at;
            if (fx.db.seriesId("victim", &.{.{ .name = "k", .value = "v" }})) |_| {
                survived_without_crashing = true;
            } else |_| {}
            fx.sim.reboot();
            try fx.reopen();

            // The pre-existing series is untouched, whatever happened.
            try testing.expectEqual(first, (try fx.db.lookupSeries("base", &.{})).?);

            // The new one is either absent, or COMPLETE in all three places.
            if (try fx.db.lookupSeries("victim", &.{.{ .name = "k", .value = "v" }})) |id| {
                const canon = try fx.db.seriesCanonical(gpa, id);
                try testing.expect(canon != null);
                defer gpa.free(canon.?);
                var d = try codec.parseCanonical(gpa, canon.?);
                defer d.deinit(gpa);
                try testing.expectEqualStrings("victim", d.name);
                // The counter moved past it, so no later series can reuse the id.
                try testing.expect((try fx.db.nextSeriesId()) > id);
            }

            // Either way the store keeps working: a fresh series gets a fresh id.
            const fresh = try fx.db.seriesId("after", &.{});
            try testing.expect(fresh != first);
            const victim_now = try fx.db.lookupSeries("victim", &.{.{ .name = "k", .value = "v" }});
            if (victim_now) |id| try testing.expect(fresh != id);
        }
    }
}

test "retention: a crash mid-sweep leaves a consistent tree; re-running finishes it" {
    const gpa = testing.allocator;

    // Reference: the same workload swept without interruption.
    var ref: Fixture = try .init(gpa);
    defer ref.deinit();
    const ref_ids = try seedGrid(&ref, 3, 24);
    defer gpa.free(ref_ids);
    _ = try ref.db.sweep(12, .{ .chunk_deletes = 4 });

    // Sweep the crash point across the storage side effects a chunked sweep
    // performs, in every crash mode kv's simulator offers.
    const CrashMode = @FieldType(kvtree.SimStorage, "crash_mode");
    const modes = [_]CrashMode{ .lose_unsynced, .torn_tail, .reorder_unsynced, .keep_unsynced };
    for (modes) |mode| {
        var crash_at: usize = 0;
        var survived_without_crashing = false;
        while (!survived_without_crashing) : (crash_at += 1) {
            try testing.expect(crash_at < 400); // the sweep must outrun the sweep

            var fx = try Fixture.init(gpa);
            defer fx.deinit();
            fx.sim.crash_mode = mode;
            // Same target-relative mixing fix as the sibling test above.
            fx.sim.reorder_seed = 0x7d5b +% @as(u64, crash_at) *% 0x9e3779b97f4a7c15;

            const ids = try seedGrid(&fx, 3, 24);
            defer gpa.free(ids);

            fx.sim.ops_until_crash = crash_at;
            if (fx.db.sweep(12, .{ .chunk_deletes = 4 })) |_| {
                survived_without_crashing = true;
            } else |_| {}
            fx.sim.reboot();

            // Reopen: kvtree's recovery must yield a committed version, and the
            // tsdb layer on top of it must be readable — never a half-chunk.
            try fx.reopen();

            // Whatever survived, no point below the cutoff may coexist with a
            // *later* chunk's deletions in a way that breaks re-running: a
            // second sweep must finish and land exactly on the reference state.
            const finish = try fx.db.sweep(12, .{ .chunk_deletes = 4 });
            try testing.expect(finish.done);
            try testing.expect((try fx.db.retentionState()) == null);

            for (ref_ids, ids) |a, b| {
                const ga = try collect(gpa, &ref.db, a, std.math.minInt(i64), std.math.maxInt(i64));
                defer gpa.free(ga);
                const gb = try collect(gpa, &fx.db, b, std.math.minInt(i64), std.math.maxInt(i64));
                defer gpa.free(gb);
                try testing.expectEqualSlices(Sample, ga, gb);
            }
        }
    }
}

test "retention: chunk_examines bounds work even when nothing expires" {
    const gpa = testing.allocator;
    var fx = try Fixture.init(gpa);
    defer fx.deinit();

    const ids = try seedGrid(&fx, 2, 100);
    defer gpa.free(ids);

    // Cutoff below everything: no deletions at all, and the sweep still
    // terminates in one pass because each live series is skipped wholesale.
    const r = try fx.db.sweep(-1, .{ .chunk_examines = 4 });
    try testing.expect(r.done);
    try testing.expectEqual(@as(usize, 0), r.deleted);
    try testing.expectEqual(@as(usize, 2 * 100), try totalPoints(gpa, &fx.db, ids));
    // Two series → two probes, not 200.
    try testing.expectEqual(@as(usize, 2), r.examined);
}

test "retention on an empty store completes immediately" {
    var fx = try Fixture.init(testing.allocator);
    defer fx.deinit();
    const r = try fx.db.sweep(1000, .{});
    try testing.expect(r.done);
    try testing.expectEqual(@as(usize, 0), r.deleted);
    try testing.expectEqual(@as(usize, 0), r.examined);
}

test "retention leaves other tenants of the tree untouched" {
    var fx = try Fixture.init(testing.allocator);
    defer fx.deinit();

    // A key outside every tsdb tag — this module must confine itself.
    try fx.tree.put("\xf0user-data", "keep me");
    const ids = try seedGrid(&fx, 2, 10);
    defer testing.allocator.free(ids);

    _ = try fx.db.sweep(std.math.maxInt(i64), .{});
    const v = (try fx.tree.get(testing.allocator, "\xf0user-data")).?;
    defer testing.allocator.free(v);
    try testing.expectEqualStrings("keep me", v);
}

// ── size budget ──────────────────────────────────────────────────────────────

test "liveSize: empty store is zero; grows and shrinks exactly with point count" {
    const gpa = testing.allocator;
    var fx = try Fixture.init(gpa);
    defer fx.deinit();
    try testing.expectEqual(@as(u64, 0), try fx.db.liveSize());

    const s = try fx.db.seriesId("m", &.{});
    try fx.db.appendMany(s, &.{ .{ .ts = 1, .value = 1 }, .{ .ts = 2, .value = 2 }, .{ .ts = 3, .value = 3 } });
    try testing.expectEqual(@as(u64, 3 * codec.point_entry_bytes), try fx.db.liveSize());

    _ = try fx.db.sweep(2, .{}); // deletes ts 1 only (strict <)
    try testing.expectEqual(@as(u64, 2 * codec.point_entry_bytes), try fx.db.liveSize());
}

test "sweepToBudget: a no-op when the budget is already met" {
    const gpa = testing.allocator;
    var fx = try Fixture.init(gpa);
    defer fx.deinit();
    const s = try fx.db.seriesId("m", &.{});
    try fx.db.appendMany(s, &.{ .{ .ts = 1, .value = 1 }, .{ .ts = 2, .value = 2 } });
    const size = try fx.db.liveSize();

    const r = try fx.db.sweepToBudget(size, .{}); // exactly at budget
    try testing.expect(r.done);
    try testing.expectEqual(@as(usize, 0), r.deleted);
    try testing.expectEqual(size, r.before);
    try testing.expectEqual(size, r.after);
    try testing.expectEqual(@as(usize, 2), try totalPoints(gpa, &fx.db, &.{s}));

    const r2 = try fx.db.sweepToBudget(size + 1000, .{}); // budget well above size
    try testing.expect(r2.done);
    try testing.expectEqual(@as(usize, 0), r2.deleted);
}

test "sweepToBudget: drops the globally OLDEST points across series first, not key order" {
    // series A gets the LOWER id (sorts first in key order) but the NEWER
    // timestamps; series B gets the HIGHER id but the OLDER timestamps. A
    // budget sweep that (wrongly) walked key order would delete from A
    // first; the correct, timestamp-driven merge must delete from B.
    const gpa = testing.allocator;
    var fx = try Fixture.init(gpa);
    defer fx.deinit();

    const a = try fx.db.seriesId("a", &.{}); // id 1 — created first
    const b = try fx.db.seriesId("b", &.{}); // id 2 — created second
    var pts_a: std.ArrayList(Sample) = .empty;
    defer pts_a.deinit(gpa);
    for (0..10) |i| try pts_a.append(gpa, .{ .ts = @intCast(1000 + i), .value = @floatFromInt(i) }); // NEWER
    var pts_b: std.ArrayList(Sample) = .empty;
    defer pts_b.deinit(gpa);
    for (0..10) |i| try pts_b.append(gpa, .{ .ts = @intCast(i), .value = @floatFromInt(i) }); // OLDER
    try fx.db.appendMany(a, pts_a.items);
    try fx.db.appendMany(b, pts_b.items);

    const before = try fx.db.liveSize(); // 20 points
    try testing.expectEqual(@as(u64, 20 * codec.point_entry_bytes), before);

    // Ask to drop exactly 5 points' worth.
    const budget = before - 5 * codec.point_entry_bytes;
    const r = try fx.db.sweepToBudget(budget, .{});
    try testing.expect(r.done);
    try testing.expectEqual(@as(usize, 5), r.deleted);
    try testing.expectEqual(before, r.before);
    try testing.expectEqual(budget, r.after);

    // Series A (the NEWER data) is untouched...
    try testing.expectEqual(@as(usize, 10), try totalPoints(gpa, &fx.db, &.{a}));
    // ...series B lost exactly its 5 oldest points (ts 0..4), keeping 5..9.
    const gb = try collect(gpa, &fx.db, b, std.math.minInt(i64), std.math.maxInt(i64));
    defer gpa.free(gb);
    try testing.expectEqual(@as(usize, 5), gb.len);
    try testing.expectEqual(@as(Timestamp, 5), gb[0].ts);
    try testing.expectEqual(@as(Timestamp, 9), gb[gb.len - 1].ts);
}

test "sweepToBudget: max_deletes bounds one call; a second call finishes the job" {
    const gpa = testing.allocator;
    var fx = try Fixture.init(gpa);
    defer fx.deinit();
    const s = try fx.db.seriesId("m", &.{});
    var pts: std.ArrayList(Sample) = .empty;
    defer pts.deinit(gpa);
    for (0..10) |i| try pts.append(gpa, .{ .ts = @intCast(i), .value = @floatFromInt(i) });
    try fx.db.appendMany(s, pts.items);

    const before = try fx.db.liveSize();
    const budget = before - 8 * codec.point_entry_bytes; // needs 8 deletions

    const r1 = try fx.db.sweepToBudget(budget, .{ .max_deletes = 3 });
    try testing.expect(!r1.done);
    try testing.expectEqual(@as(usize, 3), r1.deleted);

    const r2 = try fx.db.sweepToBudget(budget, .{ .max_deletes = 3 });
    try testing.expect(!r2.done);
    try testing.expectEqual(@as(usize, 3), r2.deleted);

    const r3 = try fx.db.sweepToBudget(budget, .{ .max_deletes = 3 });
    try testing.expect(r3.done);
    try testing.expectEqual(@as(usize, 2), r3.deleted); // 8 - 3 - 3 = 2 left

    try testing.expectEqual(budget, try fx.db.liveSize());
    const got = try collect(gpa, &fx.db, s, std.math.minInt(i64), std.math.maxInt(i64));
    defer gpa.free(got);
    try testing.expectEqual(@as(usize, 2), got.len);
    try testing.expectEqual(@as(Timestamp, 8), got[0].ts); // the two newest survive
    try testing.expectEqual(@as(Timestamp, 9), got[1].ts);
}

test "persistence: samples survive a real filesystem round trip" {
    const gpa = testing.allocator;
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();

    var fs = kvtree.FsStorage.init(testing.io, tmp.dir);
    {
        var tree = try kvtree.Db.open(gpa, fs.storage(), "ts.kvt", .{});
        defer tree.close();
        var db = Db.init(gpa, &tree);
        defer db.deinit();
        const s = try db.seriesId("disk", &.{.{ .name = "dev", .value = "sda" }});
        for (0..64) |i| try db.append(s, @intCast(i * 10), @floatFromInt(i));
        _ = try db.sweep(200, .{ .chunk_deletes = 3 });
    }

    var tree2 = try kvtree.Db.open(gpa, fs.storage(), "ts.kvt", .{});
    defer tree2.close();
    var db2 = Db.init(gpa, &tree2);
    defer db2.deinit();
    const s2 = (try db2.lookupSeries("disk", &.{.{ .name = "dev", .value = "sda" }})).?;
    const got = try collect(gpa, &db2, s2, std.math.minInt(i64), std.math.maxInt(i64));
    defer gpa.free(got);
    try testing.expectEqual(@as(usize, 44), got.len); // 64 points, ts 0..630, cutoff 200
    try testing.expectEqual(@as(Timestamp, 200), got[0].ts);
}

/// A `Storage` wrapper that counts `pread` calls reaching the inner backend
/// — used to prove F4's cache actually skips the tree descent, independent
/// of any allocator-count subtlety.
const CountingStorage = struct {
    inner: kvtree.Storage,
    pread_count: usize = 0,
    /// Counts `sync` calls reaching the inner backend — used to prove
    /// `appendBatch` commits every series in ONE transaction (a constant
    /// number of syncs per call, kvtree's own COW commit protocol,
    /// independent of how many series/points are in the batch) rather than
    /// one transaction per series.
    sync_count: usize = 0,

    fn cast(ctx: *anyopaque) *CountingStorage {
        return @ptrCast(@alignCast(ctx));
    }
    fn vOpen(ctx: *anyopaque, path: []const u8, mode: kvtree.Storage.OpenMode) kvtree.Storage.Error!kvtree.Storage.Handle {
        return cast(ctx).inner.open(path, mode);
    }
    fn vSize(ctx: *anyopaque, h: kvtree.Storage.Handle) kvtree.Storage.Error!u64 {
        return cast(ctx).inner.size(h);
    }
    fn vPread(ctx: *anyopaque, h: kvtree.Storage.Handle, buf: []u8, off: u64) kvtree.Storage.Error!usize {
        const self = cast(ctx);
        self.pread_count += 1;
        return self.inner.pread(h, buf, off);
    }
    fn vWriteAll(ctx: *anyopaque, h: kvtree.Storage.Handle, bytes: []const u8, off: u64) kvtree.Storage.Error!void {
        return cast(ctx).inner.writeAll(h, bytes, off);
    }
    fn vSync(ctx: *anyopaque, h: kvtree.Storage.Handle) kvtree.Storage.Error!void {
        const self = cast(ctx);
        self.sync_count += 1;
        return self.inner.sync(h);
    }
    fn vTruncate(ctx: *anyopaque, h: kvtree.Storage.Handle, len: u64) kvtree.Storage.Error!void {
        return cast(ctx).inner.truncate(h, len);
    }
    fn vClose(ctx: *anyopaque, h: kvtree.Storage.Handle) void {
        cast(ctx).inner.close(h);
    }
    fn vRename(ctx: *anyopaque, old_path: []const u8, new_path: []const u8) kvtree.Storage.Error!void {
        return cast(ctx).inner.rename(old_path, new_path);
    }
    fn vDelete(ctx: *anyopaque, path: []const u8) kvtree.Storage.Error!void {
        return cast(ctx).inner.delete(path);
    }
    fn vSyncDir(ctx: *anyopaque) kvtree.Storage.Error!void {
        return cast(ctx).inner.syncDir();
    }
    fn vTryLockExclusive(ctx: *anyopaque, h: kvtree.Storage.Handle) kvtree.Storage.Error!bool {
        return cast(ctx).inner.tryLockExclusive(h);
    }

    const vtable = kvtree.Storage.VTable{
        .open = vOpen,
        .size = vSize,
        .pread = vPread,
        .writeAll = vWriteAll,
        .sync = vSync,
        .truncate = vTruncate,
        .close = vClose,
        .rename = vRename,
        .delete = vDelete,
        .syncDir = vSyncDir,
        .tryLockExclusive = vTryLockExclusive,
    };

    fn storage(self: *CountingStorage) kvtree.Storage {
        return .{ .ctx = self, .vtable = &vtable };
    }
};

test "F4: a resolved series id is served from the in-memory cache, not a repeat tree descent" {
    const gpa = testing.allocator;
    var sim = kvtree.SimStorage.init(gpa);
    defer sim.deinit();
    sim.allow_overwrite = true;
    var counting = CountingStorage{ .inner = sim.storage() };
    var tree = try kvtree.Db.open(gpa, counting.storage(), "series.kvt", .{});
    defer tree.close();
    var db = Db.init(gpa, &tree);
    defer db.deinit();

    const labels = [_]Label{ .{ .name = "region", .value = "eu" }, .{ .name = "host", .value = "a1" } };
    const id1 = try db.seriesId("cpu", &labels);

    const before = counting.pread_count;
    const id2 = (try db.lookupSeries("cpu", &labels)).?;
    try testing.expectEqual(id1, id2);

    // The cache answered without a single further `pread` reaching the
    // backend — no tree descent happened at all for the repeat lookup.
    try testing.expectEqual(before, counting.pread_count);
}

test "F5: sweepChunk's delete scratch is retained across chunks, not alloc/free per chunk" {
    const gpa = testing.allocator;
    var sim = kvtree.SimStorage.init(gpa);
    defer sim.deinit();
    sim.allow_overwrite = true;
    var tree = try kvtree.Db.open(gpa, sim.storage(), "series.kvt", .{});
    defer tree.close();

    // A separate FailingAllocator (never fails; just counts) as the tsdb
    // layer's OWN allocator, isolated from `tree`'s internal allocator
    // (`kvtree.Db.cursor`/`begin` use the gpa `tree` was opened with, not
    // `Db.gpa`) — so every counted allocation is attributable to this
    // layer: `sweepChunk`'s scratch and the handful of fixed per-sweep
    // calls (`resumePosition`'s one `tree.get`), not tree internals.
    var fa = std.testing.FailingAllocator.init(gpa, .{});
    var db = Db.init(fa.allocator(), &tree);
    defer db.deinit();

    // Seed enough points that a small `chunk_deletes` forces several
    // chunks per series, all pure-delete chunks (well below any cutoff).
    var name_buf: [16]u8 = undefined;
    var batch: std.ArrayList(Sample) = .empty;
    defer batch.deinit(gpa);
    for (0..3) |i| {
        const nm = try std.fmt.bufPrint(&name_buf, "s{d}", .{i});
        const id = try db.seriesId(nm, &.{});
        batch.clearRetainingCapacity();
        for (0..30) |t| try batch.append(gpa, .{ .ts = @intCast(t), .value = @floatFromInt(t) });
        try db.appendMany(id, batch.items);
    }

    var pos = try db.resumePosition(1000);
    const opts = Db.SweepOptions{ .chunk_deletes = 10, .chunk_examines = 10 };

    // First chunk: the scratch buffer grows from empty to `chunk_deletes`
    // capacity — the one place an allocation is expected.
    const before1 = fa.allocations;
    const c1 = try db.sweepChunk(1000, opts, &pos);
    const delta1 = fa.allocations - before1;
    try testing.expectEqual(@as(usize, 10), c1.deleted);

    // Second chunk: same shape of work (10 deletes), but the scratch
    // buffer already has the capacity from chunk 1 — `clearRetainingCapacity`
    // reuses it, so this chunk must allocate strictly less than chunk 1.
    const before2 = fa.allocations;
    const c2 = try db.sweepChunk(1000, opts, &pos);
    const delta2 = fa.allocations - before2;
    try testing.expectEqual(@as(usize, 10), c2.deleted);

    try testing.expect(delta2 < delta1);
}

test "F1: CorruptIndex/CorruptPoint reject paths actually fire on a malformed value written directly through the tree" {
    // Every corruption reject path (CorruptIndex, CorruptPoint) is
    // declared and documented in SPEC.md as the module's fail-closed
    // story, but nothing ever constructed the malformed bytes that would
    // exercise them — the reject branches were dead code as far as the
    // suite could tell. Write directly through the underlying kvtree at
    // the module's own known key shapes (bypassing tsdb's own API, which
    // never itself produces malformed values) and confirm each guard
    // actually returns its documented typed error.
    var fx = try Fixture.init(testing.allocator);
    defer fx.deinit();
    const gpa = testing.allocator;

    // ── CorruptIndex via lookupSeries: index value must be exactly 8 bytes ──
    {
        var idx_key: std.ArrayList(u8) = .empty;
        defer idx_key.deinit(gpa);
        try fx.db.indexKey(&idx_key, "bad-index", &.{});
        try fx.tree.put(idx_key.items, "\x01\x02\x03"); // 3 bytes, not 8
        try testing.expectError(error.CorruptIndex, fx.db.lookupSeries("bad-index", &.{}));
    }

    // ── CorruptIndex via retentionState: header too short ──────────────────
    {
        try fx.tree.put(&codec.meta_key_retention, "\x01\x00\x00\x00"); // < 1+8 bytes
        try testing.expectError(error.CorruptIndex, fx.db.retentionState());
    }

    // ── CorruptIndex via retentionState: wrong version byte ────────────────
    {
        var v: [1 + 8 + 3]u8 = undefined;
        v[0] = 0x99; // not version 1
        @memset(v[1..9], 0);
        @memset(v[9..12], 0xAA); // any nonempty resume-key filler
        try fx.tree.put(&codec.meta_key_retention, &v);
        try testing.expectError(error.CorruptIndex, fx.db.retentionState());
    }

    // ── CorruptIndex via retentionState: empty resume key ──────────────────
    {
        var v: [1 + 8]u8 = undefined;
        v[0] = 1;
        @memset(v[1..9], 0);
        try fx.tree.put(&codec.meta_key_retention, &v);
        try testing.expectError(error.CorruptIndex, fx.db.retentionState());
    }
    try fx.tree.del(&codec.meta_key_retention); // clean up for the next section

    // ── CorruptPoint via Range.next: point value must be exactly 8 bytes ───
    {
        const s = try fx.db.seriesId("bad-point", &.{});
        const key = codec.pointKey(s, 42);
        try fx.tree.put(&key, "\x01\x02\x03\x04"); // 4 bytes, not 8
        var r = try fx.db.range(s, 0, 1000);
        defer r.deinit();
        try testing.expectError(error.CorruptPoint, r.next());
    }
}
