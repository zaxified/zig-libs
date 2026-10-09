// SPDX-License-Identifier: MIT

//! tsdb — a time-series persistence layer over `kvtree`: append a sample,
//! stream an ordered `[from, to)` range back, pack older samples into
//! compressed blocks (`compact`), and expire old data with a chunked,
//! resumable retention sweep.
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
//! **Compression** (SPEC.md §5b): writes stay one key per sample; `compact`
//! packs samples below a horizon into Gorilla blocks (`chunk.zig`), and reads
//! merge the two. **Deliberate non-goals** (see SPEC.md): downsampling/rollups,
//! a query language, aggregation functions. `metrics` (registry + Prometheus
//! exposition), `latency-stats` and `finstats` cover live counters, latency
//! summaries and portfolio statistics respectively; none of them persists
//! anything, and this is the persistence layer they lack.

const std = @import("std");
const kvtree = @import("kvtree");

pub const meta = .{
    // The module catalog's one-line entry. This IS the source of truth:
    // README.md's table is rendered from it by `zig build gen-catalog`.
    .doc = "Time-series persistence over `kvtree` — ordered (series, timestamp) key codec, streaming range scans, Gorilla-compressed blocks, crash-safe retention by age or size budget.",
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
/// The compressed block codec (Gorilla delta-of-delta timestamps + XOR'd
/// values) that `Db.compact` packs samples into.
pub const chunk = @import("chunk.zig");

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
        /// A point entry's value is not an 8-byte sample, or a block entry's
        /// value does not decode (`chunk.Reader` refused it, or its samples
        /// disagree with the block key).
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

    // ── series deletion ──────────────────────────────────────────────────────

    pub const DeleteSeriesOptions = struct {
        /// Entries (raw points or blocks) deleted per transaction.
        chunk_deletes: usize = 4096,
    };

    pub const DeleteSeriesResult = struct {
        /// Samples deleted (a block counts its samples).
        deleted: usize = 0,
        /// Transactions committed.
        chunks: usize = 0,
        /// False when `id` was not registered (nothing to delete).
        existed: bool = false,
    };

    /// Drop series `id`: every sample (raw and compacted) and its index
    /// entries. The data goes in bounded chunks; the LAST transaction removes
    /// the forward and reverse index together, so the series disappears from
    /// `lookupSeries`/`seriesIterator` only once its data is gone. A crash
    /// part-way leaves a registered series with fewer samples — call again;
    /// the operation is idempotent. The id is never handed out again (the
    /// counter only grows), so a name registered afterwards gets a fresh id
    /// and no stale sample can resurface under it.
    ///
    /// The id is dead afterwards: do not `append` through a `SeriesId` held
    /// from before the delete — those samples would have no index entry (no
    /// listing or budget sweep reaches them, though `liveSize` counts them).
    /// Re-resolve with `seriesId`.
    pub fn deleteSeries(self: *Db, id: SeriesId, opts: DeleteSeriesOptions) Error!DeleteSeriesResult {
        std.debug.assert(opts.chunk_deletes >= 1);
        const rev_key = reverseKey(id);
        const canon = (try self.tree.get(self.gpa, &rev_key)) orelse return .{};
        defer self.gpa.free(canon);
        var res: DeleteSeriesResult = .{ .existed = true };
        var keys: std.ArrayList([codec.point_key_len]u8) = .empty;
        defer keys.deinit(self.gpa);
        while (true) {
            keys.clearRetainingCapacity();
            var more = false;
            {
                var cur = try self.tree.cursor();
                defer cur.deinit();
                for ([_]bool{ false, true }) |block| {
                    try cur.seek(if (block) &codec.seriesBlockStartKey(id) else &codec.seriesStartKey(id));
                    while (try cur.next()) |e| {
                        const ref = (if (block) codec.decodeBlockKey(e.key) else codec.decodePointKey(e.key)) orelse break;
                        if (ref.series != id) break;
                        if (keys.items.len >= opts.chunk_deletes) {
                            more = true;
                            break;
                        }
                        try keys.append(self.gpa, e.key[0..codec.point_key_len].*);
                        res.deleted += if (block) try blockCount(e.val) else 1;
                    }
                    if (more) break;
                }
            }
            var txn = try self.tree.begin();
            {
                errdefer txn.rollback();
                for (keys.items) |*k| try txn.del(k);
                if (!more) {
                    var idx_key: std.ArrayList(u8) = .empty;
                    defer idx_key.deinit(self.gpa);
                    try idx_key.append(self.gpa, codec.tag_series_index);
                    try idx_key.appendSlice(self.gpa, canon);
                    try txn.del(idx_key.items);
                    try txn.del(&rev_key);
                    if (self.series_cache.fetchRemove(idx_key.items)) |kv| self.gpa.free(kv.key);
                }
            }
            try txn.commit();
            res.chunks += 1;
            if (!more) return res;
        }
    }

    // ── compaction ───────────────────────────────────────────────────────────
    //
    // Writes land as one key per sample (`tag_point`) — cheap to append, to
    // overwrite and to write out of order. `compact` later packs the samples
    // below a horizon into Gorilla blocks (`tag_block`, `chunk.zig`), one key
    // per block. Reads merge the two partitions; a raw sample shadows a block
    // sample with the same timestamp, because a raw key inside a block's span
    // can only come from a write AFTER that block was made (compaction deletes
    // every raw key it absorbs, in the same transaction). See SPEC.md §5b.

    pub const CompactOptions = struct {
        /// A run of raw samples AFTER a series' last block (the ordinary
        /// "new data" case) is left raw until at least this many of them are
        /// below `before` — so a caller compacting every minute does not cut
        /// one tiny block per minute. Samples that fall inside or between
        /// existing blocks (late writes, overwrites) are always merged.
        min_run: usize = 64,
        /// Raw samples absorbed per transaction (bounds the transaction and
        /// the chunk's memory, ~16 bytes each plus the blocks it rewrites).
        chunk_points: usize = 4096,
        /// Raw keys read per chunk — bounds a chunk that finds nothing to
        /// pack (every series' raw tail shorter than `min_run`).
        chunk_examines: usize = 16384,
        /// Chunks this call may run before returning `done = false`. 0 = all.
        max_chunks: usize = 0,
    };

    pub const CompactResult = struct {
        /// Raw samples packed into blocks (their raw keys deleted).
        compacted: usize = 0,
        /// Block entries written (new or rewritten).
        blocks_written: usize = 0,
        /// Raw keys read.
        examined: usize = 0,
        /// Chunks (= transactions) run.
        chunks: usize = 0,
        /// True when the whole raw partition was scanned.
        done: bool = false,
    };

    /// Pack every raw sample with `ts < before` into compressed blocks.
    ///
    /// Each chunk is ONE transaction that writes the blocks and deletes the
    /// raw keys they absorbed, so a crash or an error leaves every sample
    /// exactly once — raw or in a block, never both lost, never torn. There is
    /// no resume record: compaction is idempotent ("pack what is still raw"),
    /// and a re-run reads only what is still raw, which after a completed run
    /// is the short tail per series plus everything at or above `before`.
    /// Choose `before` so recent data — still being written, perhaps out of
    /// order — stays raw (e.g. `now - 1h`).
    pub fn compact(self: *Db, before: Timestamp, opts: CompactOptions) Error!CompactResult {
        std.debug.assert(opts.chunk_points >= 1 and opts.chunk_examines >= 1);
        var pos: ScanPos = .{};
        pos.set(&[_]u8{codec.tag_point});
        var res: CompactResult = .{};
        while (true) {
            const c = try self.compactChunk(before, opts, &pos);
            res.compacted += c.compacted;
            res.blocks_written += c.blocks;
            res.examined += c.examined;
            res.chunks += 1;
            if (c.done) {
                res.done = true;
                break;
            }
            if (opts.max_chunks != 0 and res.chunks >= opts.max_chunks) break;
        }
        return res;
    }

    const CompactChunk = struct { compacted: usize, blocks: usize, examined: usize, done: bool };

    fn compactChunk(self: *Db, before: Timestamp, opts: CompactOptions, pos: *ScanPos) Error!CompactChunk {
        var arena = std.heap.ArenaAllocator.init(self.gpa);
        defer arena.deinit();
        const a = arena.allocator();

        // 1. Collect raw runs below `before`, in key order: (series, samples).
        const Run = struct { series: SeriesId, start: usize, end: usize };
        var samples: std.ArrayList(Sample) = .empty;
        var runs: std.ArrayList(Run) = .empty;
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
                    done = true;
                    break;
                };
                examined += 1;
                var reseek = false;
                if (p.ts < before) {
                    const v = codec.decodeValue(e.val) orelse return error.CorruptPoint;
                    if (runs.items.len == 0 or runs.items[runs.items.len - 1].series != p.series)
                        try runs.append(a, .{ .series = p.series, .start = samples.items.len, .end = samples.items.len });
                    try samples.append(a, .{ .ts = p.ts, .value = v });
                    runs.items[runs.items.len - 1].end = samples.items.len;
                    pos.set(&codec.pointKeySuccessor(e.key[0..codec.point_key_len].*));
                } else {
                    // At or above the horizon: the rest of this series is too.
                    if (p.series == std.math.maxInt(SeriesId)) {
                        done = true;
                        break;
                    }
                    pos.set(&codec.seriesStartKey(p.series + 1));
                    reseek = true;
                }
                if (samples.items.len >= opts.chunk_points) break;
                if (examined >= opts.chunk_examines) break;
                if (reseek) try cur.seek(pos.slice());
            }
        }
        if (runs.items.len == 0) return .{ .compacted = 0, .blocks = 0, .examined = examined, .done = done };

        // 2. Place each run against the series' blocks and write, in ONE txn.
        var compacted: usize = 0;
        var blocks: usize = 0;
        // Per-placement scratch (a block copy, a merge): reset every
        // iteration, so a chunk that rewrites many blocks holds one at a
        // time — `txn.put` has already copied what it keeps.
        var scratch = std.heap.ArenaAllocator.init(self.gpa);
        defer scratch.deinit();
        const sa = scratch.allocator();
        var txn = try self.tree.begin();
        {
            errdefer txn.rollback();
            var bcur = try self.tree.cursor();
            defer bcur.deinit();
            for (runs.items) |run| {
                const r = samples.items[run.start..run.end];
                var i: usize = 0;
                while (i < r.len) {
                    _ = scratch.reset(.retain_capacity);
                    // The first block that can hold r[i]: the lowest whose last
                    // timestamp is >= r[i].ts (blocks never overlap).
                    try bcur.seek(&codec.blockKey(run.series, r[i].ts));
                    var blk: ?BlockRef = null;
                    if (try bcur.next()) |e| if (codec.decodeBlockKey(e.key)) |bk| if (bk.series == run.series) {
                        blk = .{
                            .key = e.key[0..codec.block_key_len].*,
                            .last = bk.ts,
                            .first = chunk.firstTs(e.val) catch return error.CorruptPoint,
                            .val = try sa.dupe(u8, e.val),
                        };
                    };
                    var j = i;
                    if (blk) |b| if (b.first <= r[i].ts) {
                        // Inside a block's span: merge every raw sample up to
                        // its last timestamp into it (raw wins on a tie).
                        while (j < r.len and r[j].ts <= b.last) j += 1;
                        const merged = try mergeIntoBlock(sa, b, r[i..j]);
                        try txn.del(&b.key); // the last piece re-puts this key
                        blocks += try putBlocks(&txn, run.series, merged);
                        for (r[i..j]) |sm| try txn.del(&codec.pointKey(run.series, sm.ts));
                        compacted += j - i;
                        i = j;
                        continue;
                    };
                    // In the gap before `blk`, or past the last block.
                    const limit: ?Timestamp = if (blk) |b| b.first else null;
                    while (j < r.len and (limit == null or r[j].ts < limit.?)) j += 1;
                    if (limit == null and j - i < opts.min_run) break; // short tail: stays raw
                    blocks += try putBlocks(&txn, run.series, r[i..j]);
                    for (r[i..j]) |sm| try txn.del(&codec.pointKey(run.series, sm.ts));
                    compacted += j - i;
                    i = j;
                }
            }
        }
        try txn.commit();
        return .{ .compacted = compacted, .blocks = blocks, .examined = examined, .done = done };
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
        try cur.seek(&codec.pointKey(series, from));
        // Blocks are keyed by their LAST timestamp, so this lands on the
        // first block that can hold a sample at or after `from`.
        var bcur = try snap.cursor();
        errdefer bcur.deinit();
        try bcur.seek(&codec.blockKey(series, from));
        return .{ .snap = snap, .cur = cur, .bcur = bcur, .series = series, .from = from, .to = to };
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
            const ch = try self.sweepChunk(cutoff, opts, &pos);
            res.deleted += ch.deleted;
            res.examined += ch.examined;
            res.chunks += 1;
            if (ch.done) {
                res.done = true;
                break;
            }
            if (ch.deleted == 0 and std.mem.order(u8, pos.slice(), before.slice()) != .gt)
                return error.SweepStalled;
            if (opts.max_chunks != 0 and res.chunks >= opts.max_chunks) break;
        }
        return res;
    }

    const ChunkResult = struct { deleted: usize, examined: usize, done: bool };

    /// One bounded chunk: scan forward from `pos`, then commit the deletions
    /// together with the new `pos` in a single transaction. The scan covers
    /// the raw partition, then the block partition: a block wholly below the
    /// cutoff is deleted, a block straddling it is rewritten with its suffix.
    fn sweepChunk(self: *Db, cutoff: Timestamp, opts: SweepOptions, pos: *ScanPos) Error!ChunkResult {
        // Retained across chunks/calls (F5) — was a fresh `alloc`/`free` of
        // up to `chunk_deletes * point_key_len` bytes (68 KiB at the
        // defaults) every single chunk of a long retention sweep.
        self.sweep_scratch.clearRetainingCapacity();
        const deletes = &self.sweep_scratch;
        // Straddling blocks' surviving suffixes (rare: at most one per series).
        var arena = std.heap.ArenaAllocator.init(self.gpa);
        defer arena.deinit();
        const a = arena.allocator();
        const Rewrite = struct { series: SeriesId, samples: []const Sample };
        var rewrites: std.ArrayList(Rewrite) = .empty;

        var examined: usize = 0;
        var deleted: usize = 0; // samples
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
                var reseek = false;
                if (codec.decodePointKey(e.key)) |p| {
                    examined += 1;
                    if (p.ts < cutoff) {
                        const key = e.key[0..codec.point_key_len].*;
                        try deletes.append(self.gpa, key);
                        deleted += 1;
                        const succ = codec.pointKeySuccessor(key);
                        pos.set(&succ);
                    } else {
                        // Within a series, points at or above the cutoff are a
                        // suffix — nothing further in THIS series can expire, so
                        // jump straight to the next one.
                        if (p.series == std.math.maxInt(SeriesId)) {
                            pos.set(&[_]u8{codec.tag_block}); // on to the blocks
                        } else {
                            const next_series = codec.seriesStartKey(p.series + 1);
                            pos.set(&next_series);
                        }
                        reseek = true;
                    }
                } else if (codec.decodeBlockKey(e.key)) |bk| {
                    examined += 1;
                    const key = e.key[0..codec.block_key_len].*;
                    if (bk.ts < cutoff) {
                        // The block's LAST sample is expired: all of it is.
                        try deletes.append(self.gpa, key);
                        deleted += try blockCount(e.val);
                        pos.set(&codec.pointKeySuccessor(key));
                    } else {
                        const first = chunk.firstTs(e.val) catch return error.CorruptPoint;
                        if (first < cutoff) {
                            // Straddles the cutoff: keep the suffix. Later
                            // blocks of this series start after this one ends.
                            var keep: std.ArrayList(Sample) = .empty;
                            var rd = chunk.Reader.init(e.val) catch return error.CorruptPoint;
                            while (rd.next() catch return error.CorruptPoint) |bs| {
                                if (bs.ts < cutoff) {
                                    deleted += 1;
                                } else {
                                    try keep.append(a, .{ .ts = bs.ts, .value = bs.value });
                                }
                            }
                            try deletes.append(self.gpa, key);
                            try rewrites.append(a, .{ .series = bk.series, .samples = keep.items });
                        }
                        // Either way nothing later in this series can expire.
                        if (bk.series == std.math.maxInt(SeriesId)) {
                            done = true;
                            break;
                        }
                        pos.set(&codec.seriesBlockStartKey(bk.series + 1));
                        reseek = true;
                    }
                } else if (e.key.len != 0 and e.key[0] < codec.tag_block) {
                    // Left the raw partition (the series indexes sort between
                    // it and the blocks): continue at the first block key.
                    pos.set(&[_]u8{codec.tag_block});
                    reseek = true;
                } else {
                    // Past the block partition (or a malformed key there):
                    // every later key sorts above every key this sweeps.
                    done = true;
                    break;
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
            // A rewritten suffix keeps the block's last timestamp, so its last
            // piece re-puts the key deleted just above.
            for (rewrites.items) |rw| _ = try putBlocks(&txn, rw.series, rw.samples);
            if (done) {
                try txn.del(&codec.meta_key_retention);
            } else {
                var rec: [1 + 8 + codec.max_scan_key_len]u8 = undefined;
                const n = encodeResume(&rec, cutoff, pos.slice());
                try txn.put(&codec.meta_key_retention, rec[0..n]);
            }
        }
        try txn.commit();

        return .{ .deleted = deleted, .examined = examined, .done = done };
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

    /// Live sample-data size, in bytes: every raw point entry
    /// (`codec.point_entry_bytes` each) plus every block entry's key and
    /// value bytes as stored. EXACT, not an estimate — it sums the entries'
    /// own lengths. Excludes the series index/reverse-index entries (small —
    /// one per series, never touched by retention) and kvtree's own on-disk
    /// page/freelist overhead (the file itself never shrinks — see this
    /// section's doc comment above). Costs one forward scan of both
    /// partitions: O(raw points + blocks).
    pub fn liveSize(self: *Db) Error!u64 {
        var cur = try self.tree.cursor();
        defer cur.deinit();
        try cur.seek(&[_]u8{codec.tag_point});
        var count: u64 = 0;
        while (try cur.next()) |e| {
            _ = codec.decodePointKey(e.key) orelse break; // left the point partition
            count += 1;
        }
        var bytes = count * codec.point_entry_bytes;
        try cur.seek(&[_]u8{codec.tag_block});
        while (try cur.next()) |e| {
            _ = codec.decodeBlockKey(e.key) orelse break;
            bytes += e.key.len + e.val.len;
        }
        return bytes;
    }

    pub const SweepToBudgetOptions = struct {
        /// Entries deleted per committed transaction. Bounds one transaction's
        /// size, same role as `SweepOptions.chunk_deletes` — but see the
        /// doc comment on `sweepToBudget` for why chunking here does NOT
        /// give the same resumability `sweep` has.
        chunk_deletes: usize = 4096,
        /// Upper bound on SAMPLES this call deletes, checked before each
        /// entry — so a block (up to `chunk.max_block_samples` samples) can
        /// carry the total past it by less than one block.
        max_deletes: usize = 65536,
    };

    pub const SweepToBudgetResult = struct {
        /// `liveSize()` before this call.
        before: u64,
        /// `liveSize()` after: exactly `before` minus the bytes of the entries
        /// deleted (each entry's size is known when it is picked).
        after: u64,
        /// Samples deleted by this call.
        deleted: usize = 0,
        /// True iff `after <= max_bytes`. False means `max_deletes` was hit
        /// before the budget was met — call again to continue.
        done: bool = false,
    };

    /// Delete the globally OLDEST data — across every series, by timestamp,
    /// not by key order — until live data is at most `max_bytes`, or until
    /// `opts.max_deletes` is spent (call again to continue). A no-op,
    /// `.done = true`, if the budget is already met.
    ///
    /// **Unit of deletion.** A raw point, or a WHOLE compacted block, ordered
    /// by its oldest timestamp (a block's first sample). Splitting a block to
    /// free a few bytes would cost a rewrite and gain little; a block holds a
    /// bounded window, so the newest sample dropped this way is at most one
    /// block span younger than a per-sample policy would have dropped.
    ///
    /// **Why not `sweep` with a computed cutoff.** A key sorts `(series,
    /// timestamp)` — series-MAJOR — so "the earliest keys in the tree" is NOT
    /// "the oldest data in the store": series 9 can hold data from a decade
    /// ago while series 0 was created five minutes ago. Age retention
    /// (`sweep`) applies ONE cutoff independently to every series; a size
    /// BUDGET is a comparison across series, and only timestamps answer it.
    ///
    /// **The algorithm**: a k-way merge over per-series, per-partition "oldest
    /// surviving entry" candidates, seeded once via `seriesIterator` (two tree
    /// probes per series) and kept in a min-heap ordered by timestamp (ties
    /// broken by series id, then BLOCK before raw — see `less`). Popping
    /// the minimum and re-probing that one stream costs O(log(series count))
    /// per entry — no rescan of the store, no bisection over candidate
    /// cutoffs.
    ///
    /// **Crash-safety — narrower than `sweep`'s.** Each chunk of
    /// `opts.chunk_deletes` deletions commits atomically (kvtree's COW
    /// commit), so a crash mid-call leaves a CONSISTENT tree — never a torn
    /// chunk. But there is no persisted resume record: a crash (or hitting
    /// `max_deletes`) leaves the merge's in-memory progress on the floor; the
    /// next call recomputes `liveSize` and reseeds from scratch, reaching the
    /// same end state (deleting the globally oldest entries is idempotent).
    pub fn sweepToBudget(self: *Db, max_bytes: u64, opts: SweepToBudgetOptions) Error!SweepToBudgetResult {
        const before = try self.liveSize();
        if (before <= max_bytes) return .{ .before = before, .after = before, .done = true };
        const excess = before - max_bytes;

        const less = struct {
            fn f(_: void, x: Unit, y: Unit) std.math.Order {
                if (x.oldest != y.oldest) return std.math.order(x.oldest, y.oldest);
                if (x.series != y.series) return std.math.order(x.series, y.series);
                // Block before raw: a raw point can shadow a block sample with
                // its own timestamp (B3), and if the raw one went first the
                // older value it replaced would read again. Any raw point that
                // shadows a block sample has `ts >= block.first`, so with this
                // order the block is always deleted no later than its shadow.
                return std.math.order(@intFromBool(y.block), @intFromBool(x.block));
            }
        }.f;

        var heap: std.PriorityQueue(Unit, void, less) = .empty;
        defer heap.deinit(self.gpa);
        {
            var it = try self.seriesIterator();
            defer it.deinit();
            while (try it.next(self.gpa)) |entry_val| {
                var entry_mut = entry_val;
                const entry = &entry_mut;
                defer entry.deinit(self.gpa);
                if (try self.unitAt(&codec.seriesStartKey(entry.id), entry.id, false)) |u| try heap.push(self.gpa, u);
                if (try self.unitAt(&codec.seriesBlockStartKey(entry.id), entry.id, true)) |u| try heap.push(self.gpa, u);
            }
        }

        var deletes: std.ArrayList([codec.point_key_len]u8) = .empty;
        defer deletes.deinit(self.gpa);
        var freed: u64 = 0;
        var deleted: usize = 0;
        while (freed < excess and deleted < opts.max_deletes) {
            const u = heap.pop() orelse break; // no live data anywhere
            try deletes.append(self.gpa, u.key);
            freed += u.bytes;
            deleted += u.samples;
            if (try self.unitAt(&codec.pointKeySuccessor(u.key), u.series, u.block)) |n| try heap.push(self.gpa, n);
        }

        var i: usize = 0;
        while (i < deletes.items.len) {
            const end = @min(i + opts.chunk_deletes, deletes.items.len);
            var txn = try self.tree.begin();
            {
                errdefer txn.rollback();
                for (deletes.items[i..end]) |*k| try txn.del(k);
            }
            try txn.commit();
            i = end;
        }

        const after = before - freed;
        return .{ .before = before, .after = after, .deleted = deleted, .done = after <= max_bytes };
    }

    /// One deletable entry for `sweepToBudget`: a raw point or a whole block.
    const Unit = struct {
        key: [codec.point_key_len]u8,
        series: SeriesId,
        /// Its oldest timestamp (a block's first sample).
        oldest: Timestamp,
        /// Its bytes as `liveSize` counts them.
        bytes: u64,
        samples: u32,
        block: bool,
    };

    /// The first entry at or after `seek_key` in `series`' raw (or block)
    /// partition, or null when that partition of the series is exhausted.
    fn unitAt(self: *Db, seek_key: []const u8, series: SeriesId, block: bool) Error!?Unit {
        var cur = try self.tree.cursor();
        defer cur.deinit();
        try cur.seek(seek_key);
        const e = (try cur.next()) orelse return null;
        if (block) {
            const bk = codec.decodeBlockKey(e.key) orelse return null;
            if (bk.series != series) return null;
            return .{
                .key = e.key[0..codec.block_key_len].*,
                .series = series,
                .oldest = chunk.firstTs(e.val) catch return error.CorruptPoint,
                .bytes = e.key.len + e.val.len,
                .samples = try blockCount(e.val),
                .block = true,
            };
        }
        const p = codec.decodePointKey(e.key) orelse return null;
        if (p.series != series) return null; // this series has no (more) points
        return .{
            .key = e.key[0..codec.point_key_len].*,
            .series = series,
            .oldest = p.ts,
            .bytes = codec.point_entry_bytes,
            .samples = 1,
            .block = false,
        };
    }
};

// ── blocks ───────────────────────────────────────────────────────────────────

/// One block entry read for a rewrite: its key, its span, and a copy of its
/// bytes (the cursor's value is invalidated by the next cursor call).
const BlockRef = struct {
    key: [codec.block_key_len]u8,
    first: Timestamp,
    last: Timestamp,
    val: []const u8,
};

/// Decode `b`, check it against its own key (a block's span IS its key),
/// and merge `raw` into it: ascending, and a raw sample replaces a block
/// sample with the same timestamp. Allocates the result on `a`.
fn mergeIntoBlock(a: Allocator, b: BlockRef, raw: []const Sample) Error![]Sample {
    var rd = chunk.Reader.init(b.val) catch return error.CorruptPoint;
    var out: std.ArrayList(Sample) = .empty;
    try out.ensureTotalCapacity(a, raw.len + rd.count());
    var i: usize = 0;
    var prev: ?Timestamp = null;
    while (rd.next() catch return error.CorruptPoint) |bs| {
        if (prev == null and bs.ts != b.first) return error.CorruptPoint;
        prev = bs.ts;
        while (i < raw.len and raw[i].ts < bs.ts) : (i += 1) out.appendAssumeCapacity(raw[i]);
        if (i < raw.len and raw[i].ts == bs.ts) {
            out.appendAssumeCapacity(raw[i]); // the later write wins
            i += 1;
        } else {
            out.appendAssumeCapacity(.{ .ts = bs.ts, .value = bs.value });
        }
    }
    if (prev == null or prev.? != b.last) return error.CorruptPoint;
    while (i < raw.len) : (i += 1) out.appendAssumeCapacity(raw[i]);
    return out.items;
}

/// Encode strictly ascending `samples` into as many blocks as the caps need,
/// each keyed by its own last timestamp, into `txn`. Returns the block count.
fn putBlocks(txn: *kvtree.Txn, series: SeriesId, samples: []const Sample) Error!usize {
    var w = chunk.Writer.init();
    var n: usize = 0;
    for (samples) |sm| {
        const cs: chunk.Sample = .{ .ts = sm.ts, .value = sm.value };
        w.append(cs) catch |err| switch (err) {
            error.BlockFull => {
                try txn.put(&codec.blockKey(series, w.lastTs()), w.bytes());
                n += 1;
                w = chunk.Writer.init();
                // One sample always fits an empty block.
                w.append(cs) catch return error.CorruptPoint;
            },
            // Callers pass raw keys (unique, ascending) or a merge of them.
            error.OutOfOrder => return error.CorruptPoint,
        };
    }
    if (w.count() != 0) {
        try txn.put(&codec.blockKey(series, w.lastTs()), w.bytes());
        n += 1;
    }
    return n;
}

/// The sample count stored in a block's header, or `CorruptPoint`.
fn blockCount(val: []const u8) Error!u32 {
    const rd = chunk.Reader.init(val) catch return error.CorruptPoint;
    return rd.count();
}

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
/// commits do not disturb it; `deinit` releases both cursors and the
/// snapshot (leaking a snapshot pins kvtree's page reclaim, so always `defer`).
///
/// It merges two ordered streams — raw samples and the samples of compacted
/// blocks — and on a timestamp present in both returns the raw one (the
/// later write; see `Db.compact`). The one block being decoded is copied into
/// a fixed buffer inside the `Range`, so memory stays bounded by one block,
/// never by the window.
pub const Range = struct {
    snap: kvtree.Snapshot,
    cur: kvtree.Cursor,
    bcur: kvtree.Cursor,
    series: SeriesId,
    from: Timestamp,
    to: Timestamp,
    raw_done: bool = false,
    raw_peek: ?Sample = null,
    blk_done: bool = false,
    blk_peek: ?Sample = null,
    /// The current block's bytes; `reader` decodes from here. Re-pointed on
    /// every use, so a `Range` stays valid if it is moved between calls.
    blk_buf: [chunk.max_block_bytes]u8 = undefined,
    blk_len: usize = 0,
    reader: ?chunk.Reader = null,

    pub fn next(self: *Range) Error!?Sample {
        try self.fillRaw();
        try self.fillBlock();
        const r = self.raw_peek;
        const b = self.blk_peek;
        if (r) |rs| {
            if (b) |bs| {
                if (bs.ts < rs.ts) {
                    self.blk_peek = null;
                    return bs;
                }
                if (bs.ts == rs.ts) self.blk_peek = null; // shadowed by the raw write
            }
            self.raw_peek = null;
            return rs;
        }
        if (b) |bs| {
            self.blk_peek = null;
            return bs;
        }
        return null;
    }

    fn fillRaw(self: *Range) Error!void {
        if (self.raw_peek != null or self.raw_done) return;
        const e = (try self.cur.next()) orelse {
            self.raw_done = true;
            return;
        };
        const p = codec.decodePointKey(e.key) orelse {
            self.raw_done = true;
            return;
        };
        // Ordering is the whole contract: once the key leaves this series or
        // reaches the exclusive upper bound, nothing later can qualify.
        if (p.series != self.series or p.ts >= self.to) {
            self.raw_done = true;
            return;
        }
        const v = codec.decodeValue(e.val) orelse return error.CorruptPoint;
        self.raw_peek = .{ .ts = p.ts, .value = v };
    }

    fn fillBlock(self: *Range) Error!void {
        while (self.blk_peek == null and !self.blk_done) {
            if (self.reader) |*rd| {
                rd.rebind(self.blk_buf[0..self.blk_len]);
                const s = (rd.next() catch return error.CorruptPoint) orelse {
                    self.reader = null;
                    continue;
                };
                if (s.ts < self.from) continue;
                if (s.ts >= self.to) {
                    self.blk_done = true; // blocks are ordered: nothing later qualifies
                    return;
                }
                self.blk_peek = .{ .ts = s.ts, .value = s.value };
                return;
            }
            const e = (try self.bcur.next()) orelse {
                self.blk_done = true;
                return;
            };
            const bk = codec.decodeBlockKey(e.key) orelse {
                self.blk_done = true;
                return;
            };
            if (bk.series != self.series) {
                self.blk_done = true;
                return;
            }
            if (e.val.len > self.blk_buf.len) return error.CorruptPoint;
            @memcpy(self.blk_buf[0..e.val.len], e.val);
            self.blk_len = e.val.len;
            self.reader = chunk.Reader.init(self.blk_buf[0..self.blk_len]) catch return error.CorruptPoint;
        }
    }

    pub fn deinit(self: *Range) void {
        self.bcur.deinit();
        self.cur.deinit();
        self.snap.release();
        self.* = undefined;
    }
};

// ── dark-tests aggregator (CONVENTIONS.md §6 step 3) ─────────────────────────

test {
    std.testing.refAllDecls(@This());
    _ = @import("codec.zig");
    _ = @import("fuzz_test.zig");
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

test "retention bounds the file: appending and sweeping at the same rate reaches a steady size" {
    // The 2026-09-28 measurement, as a test: 1000 points in and 1000 swept
    // per round grew the file ~60 KiB a round, linearly, because kvtree kept
    // the leaves the sweep emptied and a series never writes below its
    // cutoff again. kvtree now drops emptied leaves, so their pages recycle.
    var fx = try Fixture.init(testing.allocator);
    defer fx.deinit();
    const s = try fx.db.seriesId("cpu", &.{});

    const per_round = 1000;
    const live_rounds = 4;
    var points: [per_round]Sample = undefined;
    var hw: [2]u64 = undefined;
    var round: i64 = 0;
    while (round < 80) : (round += 1) {
        for (&points, 0..) |*p, i| p.* = .{ .ts = round * per_round + @as(i64, @intCast(i)), .value = @floatFromInt(i) };
        try fx.db.appendBatch(&.{.{ .series = s, .points = &points }});
        _ = try fx.db.sweep((round - live_rounds + 1) * per_round, .{});
        if (round == 39) hw[0] = fx.tree.meta_rec.high_water;
        if (round == 79) hw[1] = fx.tree.meta_rec.high_water;
    }
    try testing.expectEqual(hw[0], hw[1]);
    const got = try collect(testing.allocator, &fx.db, s, std.math.minInt(i64), std.math.maxInt(i64));
    defer testing.allocator.free(got);
    try testing.expectEqual(@as(usize, live_rounds * per_round), got.len);
    try testing.expectEqual(@as(i64, (80 - live_rounds) * per_round), got[0].ts);
}

// ── compaction (§5b) ─────────────────────────────────────────────────────────

/// Every block of every series, checked: key = its last sample, header first
/// = its first sample, strictly ascending inside, and blocks of one series
/// never overlap (each starts after the previous one ends). Returns the count.
fn checkBlockInvariants(db: *Db) !usize {
    var cur = try db.tree.cursor();
    defer cur.deinit();
    try cur.seek(&[_]u8{codec.tag_block});
    var n: usize = 0;
    var prev_series: ?SeriesId = null;
    var prev_last: Timestamp = 0;
    while (try cur.next()) |e| {
        const bk = codec.decodeBlockKey(e.key) orelse break;
        var rd = try chunk.Reader.init(e.val);
        var first: ?Timestamp = null;
        var last: Timestamp = 0;
        var count: u32 = 0;
        while (try rd.next()) |s| {
            if (first == null) first = s.ts else try testing.expect(s.ts > last);
            last = s.ts;
            count += 1;
        }
        try testing.expectEqual(@as(u32, rd.count()), count);
        try testing.expectEqual(bk.ts, last);
        try testing.expectEqual(first.?, try chunk.firstTs(e.val));
        if (prev_series != null and prev_series.? == bk.series) try testing.expect(first.? > prev_last);
        prev_series = bk.series;
        prev_last = last;
        n += 1;
    }
    return n;
}

fn rawCount(db: *Db) !usize {
    var cur = try db.tree.cursor();
    defer cur.deinit();
    try cur.seek(&[_]u8{codec.tag_point});
    var n: usize = 0;
    while (try cur.next()) |e| {
        _ = codec.decodePointKey(e.key) orelse break;
        n += 1;
    }
    return n;
}

test "compact: a regular series packs into blocks, reads back bit-exact, and live size drops below a tenth" {
    const gpa = testing.allocator;
    var fx = try Fixture.init(gpa);
    defer fx.deinit();
    const s = try fx.db.seriesId("cpu", &.{.{ .name = "host", .value = "a" }});
    var pts: std.ArrayList(Sample) = .empty;
    defer pts.deinit(gpa);
    // A 15 s scrape of a slowly moving gauge, plus one NaN and a -0.0.
    for (0..3000) |i| try pts.append(gpa, .{
        .ts = 1_700_000_000_000 + @as(i64, @intCast(i)) * 15_000,
        .value = if (i == 7) std.math.nan(f64) else if (i == 8) -0.0 else 40.0 + @as(f64, @floatFromInt(i % 17)) * 0.25,
    });
    try fx.db.appendMany(s, pts.items);
    const raw_size = try fx.db.liveSize();
    try testing.expectEqual(@as(u64, 3000) * codec.point_entry_bytes, raw_size);

    const res = try fx.db.compact(std.math.maxInt(i64), .{});
    try testing.expect(res.done);
    try testing.expectEqual(@as(usize, 3000), res.compacted);
    try testing.expectEqual(@as(usize, 0), try rawCount(&fx.db));
    try testing.expect(try checkBlockInvariants(&fx.db) >= 3); // ≤ 1024 samples per block

    const got = try collect(gpa, &fx.db, s, std.math.minInt(i64), std.math.maxInt(i64));
    defer gpa.free(got);
    try testing.expectEqual(pts.items.len, got.len);
    for (pts.items, got) |want, have| {
        try testing.expectEqual(want.ts, have.ts);
        try testing.expectEqual(@as(u64, @bitCast(want.value)), @as(u64, @bitCast(have.value)));
    }
    const packed_size = try fx.db.liveSize();
    try testing.expect(packed_size * 10 < raw_size);

    // A window in the middle, cut inside a block, is still exact and half-open.
    const mid = try collect(gpa, &fx.db, s, pts.items[1500].ts, pts.items[1510].ts);
    defer gpa.free(mid);
    try testing.expectEqual(@as(usize, 10), mid.len);
    try testing.expectEqual(pts.items[1500].ts, mid[0].ts);

    // Persisted: a reopen reads the same.
    try fx.reopen();
    const again = try collect(gpa, &fx.db, s, std.math.minInt(i64), std.math.maxInt(i64));
    defer gpa.free(again);
    try testing.expectEqual(got.len, again.len);
}

test "compact: a short tail after the last block stays raw until min_run samples are below the horizon" {
    const gpa = testing.allocator;
    var fx = try Fixture.init(gpa);
    defer fx.deinit();
    const s = try fx.db.seriesId("m", &.{});
    for (0..30) |i| try fx.db.append(s, @intCast(i), 1);
    var res = try fx.db.compact(1000, .{ .min_run = 64 });
    try testing.expectEqual(@as(usize, 0), res.compacted);
    try testing.expectEqual(@as(usize, 30), try rawCount(&fx.db));
    for (30..100) |i| try fx.db.append(s, @intCast(i), 1);
    // The horizon still splits it: only samples below 64 count.
    res = try fx.db.compact(63, .{ .min_run = 64 });
    try testing.expectEqual(@as(usize, 0), res.compacted);
    res = try fx.db.compact(64, .{ .min_run = 64 });
    try testing.expectEqual(@as(usize, 64), res.compacted);
    try testing.expectEqual(@as(usize, 36), try rawCount(&fx.db)); // 64..99 stay raw
    try testing.expectEqual(@as(usize, 1), try checkBlockInvariants(&fx.db));
}

test "compact: an overwrite after compaction wins on read, and the next compaction merges it into the block" {
    const gpa = testing.allocator;
    var fx = try Fixture.init(gpa);
    defer fx.deinit();
    const s = try fx.db.seriesId("m", &.{});
    for (0..200) |i| try fx.db.append(s, @as(i64, @intCast(i)) * 10, @floatFromInt(i));
    _ = try fx.db.compact(std.math.maxInt(i64), .{ .min_run = 1 });
    try testing.expectEqual(@as(usize, 0), try rawCount(&fx.db));

    try fx.db.append(s, 500, -1); // overwrite a compacted sample
    try fx.db.append(s, 505, -2); // a late sample inside the block's span
    var got = try collect(gpa, &fx.db, s, 490, 520);
    try testing.expectEqualSlices(Sample, &.{
        .{ .ts = 490, .value = 49 }, .{ .ts = 500, .value = -1 }, .{ .ts = 505, .value = -2 }, .{ .ts = 510, .value = 51 },
    }, got);
    gpa.free(got);

    const res = try fx.db.compact(std.math.maxInt(i64), .{ .min_run = 1 });
    try testing.expectEqual(@as(usize, 2), res.compacted);
    try testing.expectEqual(@as(usize, 0), try rawCount(&fx.db));
    _ = try checkBlockInvariants(&fx.db);
    got = try collect(gpa, &fx.db, s, 490, 520);
    defer gpa.free(got);
    try testing.expectEqualSlices(Sample, &.{
        .{ .ts = 490, .value = 49 }, .{ .ts = 500, .value = -1 }, .{ .ts = 505, .value = -2 }, .{ .ts = 510, .value = 51 },
    }, got);
}

test "compact: samples between two blocks become their own block without overlapping either" {
    const gpa = testing.allocator;
    var fx = try Fixture.init(gpa);
    defer fx.deinit();
    const s = try fx.db.seriesId("m", &.{});
    for (0..100) |i| try fx.db.append(s, @intCast(i), 1);
    _ = try fx.db.compact(std.math.maxInt(i64), .{ .min_run = 1 });
    for (1000..1100) |i| try fx.db.append(s, @intCast(i), 2);
    _ = try fx.db.compact(std.math.maxInt(i64), .{ .min_run = 1 });
    // Late data in the gap, and one sample older than every block.
    for (500..510) |i| try fx.db.append(s, @intCast(i), 3);
    try fx.db.append(s, -5, 4);
    // The gap run is placed even though it is shorter than min_run.
    const res = try fx.db.compact(std.math.maxInt(i64), .{ .min_run = 64 });
    try testing.expectEqual(@as(usize, 11), res.compacted);
    try testing.expectEqual(@as(usize, 4), try checkBlockInvariants(&fx.db));
    const got = try collect(gpa, &fx.db, s, std.math.minInt(i64), std.math.maxInt(i64));
    defer gpa.free(got);
    try testing.expectEqual(@as(usize, 211), got.len);
    try testing.expectEqual(@as(i64, -5), got[0].ts);
}

test "compact + retention: whole expired blocks go, a straddling block keeps its suffix, chunked equals one-shot" {
    const gpa = testing.allocator;
    var one: Fixture = try .init(gpa);
    defer one.deinit();
    var chunked: Fixture = try .init(gpa);
    defer chunked.deinit();
    for ([_]*Fixture{ &one, &chunked }) |fx| {
        for (0..3) |k| {
            const s = try fx.db.seriesId("m", &.{.{ .name = "k", .value = &.{@as(u8, '0') + @as(u8, @intCast(k))} }});
            for (0..2500) |i| try fx.db.append(s, @intCast(i), @floatFromInt(i * (k + 1)));
            _ = try fx.db.compact(2400, .{ .min_run = 1 }); // 2400..2499 stay raw
        }
    }
    const r1 = try one.db.sweep(1500, .{});
    try testing.expect(r1.done);
    try testing.expectEqual(@as(usize, 3 * 1500), r1.deleted);
    var rc: Db.SweepResult = .{};
    while (!rc.done) rc = try chunked.db.sweep(1500, .{ .chunk_deletes = 1, .max_chunks = 1 });
    for (1..4) |id| {
        const a = try collect(gpa, &one.db, id, std.math.minInt(i64), std.math.maxInt(i64));
        defer gpa.free(a);
        const b = try collect(gpa, &chunked.db, id, std.math.minInt(i64), std.math.maxInt(i64));
        defer gpa.free(b);
        try testing.expectEqual(@as(usize, 1000), a.len);
        try testing.expectEqual(@as(i64, 1500), a[0].ts);
        try testing.expectEqualSlices(Sample, a, b);
    }
    _ = try checkBlockInvariants(&one.db);
    _ = try checkBlockInvariants(&chunked.db);
    try testing.expectEqual(try one.db.liveSize(), try chunked.db.liveSize());
}

test "compact + sweepToBudget: whole blocks go oldest-first across series, and the accounting is exact" {
    const gpa = testing.allocator;
    var fx = try Fixture.init(gpa);
    defer fx.deinit();
    const old = try fx.db.seriesId("old", &.{});
    const new = try fx.db.seriesId("new", &.{});
    for (0..2000) |i| try fx.db.append(old, @intCast(i), 1); // older data, lower id
    for (0..2000) |i| try fx.db.append(new, @as(i64, @intCast(i)) + 10_000, 2);
    _ = try fx.db.compact(std.math.maxInt(i64), .{ .min_run = 1 });
    const before = try fx.db.liveSize();
    const r = try fx.db.sweepToBudget(before / 2, .{});
    try testing.expect(r.done);
    try testing.expectEqual(try fx.db.liveSize(), r.after);
    // Everything of `old` goes before anything of `new`.
    const left_old = try collect(gpa, &fx.db, old, std.math.minInt(i64), std.math.maxInt(i64));
    defer gpa.free(left_old);
    const left_new = try collect(gpa, &fx.db, new, std.math.minInt(i64), std.math.maxInt(i64));
    defer gpa.free(left_new);
    try testing.expect(left_old.len == 0 or left_new.len == 2000);
    try testing.expectEqual(@as(usize, 4000) - r.deleted, left_old.len + left_new.len);
}

test "compact: model check — random appends, overwrites, compactions, sweeps and windows agree with a map" {
    const gpa = testing.allocator;
    var prng = std.Random.DefaultPrng.init(0x75db_c0de);
    const rnd = prng.random();
    var round: usize = 0;
    while (round < 12) : (round += 1) {
        var fx = try Fixture.init(gpa);
        defer fx.deinit();
        var ids: [3]SeriesId = undefined;
        var model: [3]std.AutoArrayHashMapUnmanaged(Timestamp, u64) = @splat(.empty);
        defer for (&model) |*m| m.deinit(gpa);
        for (&ids, 0..) |*id, k| id.* = try fx.db.seriesId("m", &.{.{ .name = "k", .value = &.{@as(u8, '0') + @as(u8, @intCast(k))} }});
        var horizon: Timestamp = 0;
        var step: usize = 0;
        while (step < 120) : (step += 1) {
            const k = rnd.uintLessThan(usize, 3);
            switch (rnd.uintLessThan(u8, 10)) {
                0...4 => { // a batch of appends around a moving front, some late, some overwrites
                    var batch: [40]Sample = undefined;
                    const n = rnd.uintLessThan(usize, batch.len) + 1;
                    for (batch[0..n]) |*b| {
                        const late = rnd.uintLessThan(u8, 5) == 0;
                        // An overwrite of a timestamp the series already has —
                        // often a block's first sample, the tie review H1 is about.
                        const over = model[k].count() != 0 and rnd.uintLessThan(u8, 4) == 0;
                        const ts: Timestamp = if (over)
                            model[k].keys()[rnd.uintLessThan(usize, model[k].count())]
                        else if (late) rnd.intRangeLessThan(i64, -50, horizon + 1) else horizon + rnd.intRangeLessThan(i64, 0, 30);
                        b.* = .{ .ts = ts, .value = @bitCast(rnd.int(u64) & 0xfff0_0000_0000_ffff) };
                    }
                    // appendMany keeps the LAST write of a duplicated ts in a batch.
                    try fx.db.appendMany(ids[k], batch[0..n]);
                    for (batch[0..n]) |b| try model[k].put(gpa, b.ts, @bitCast(b.value));
                    horizon += rnd.intRangeLessThan(i64, 0, 25);
                },
                5, 6 => _ = try fx.db.compact(horizon - rnd.intRangeLessThan(i64, 0, 40), .{
                    .min_run = rnd.uintLessThan(usize, 80) + 1,
                    .chunk_points = rnd.uintLessThan(usize, 300) + 1,
                }),
                7 => {
                    const cutoff = horizon - rnd.intRangeLessThan(i64, 50, 400);
                    var rr: Db.SweepResult = .{};
                    while (!rr.done) rr = try fx.db.sweep(cutoff, .{ .chunk_deletes = rnd.uintLessThan(usize, 50) + 1, .max_chunks = 1 });
                    for (&model) |*m| {
                        var i: usize = 0;
                        while (i < m.count()) {
                            if (m.keys()[i] < cutoff) m.swapRemoveAt(i) else i += 1;
                        }
                    }
                },
                8 => {
                    // A budget drops whole entries oldest-first; which ones is
                    // the store's choice, so the check is one-sided: nothing
                    // it still returns may differ from the model (no
                    // overwritten value may come back — review H1); then the
                    // model adopts what is left.
                    const live = try fx.db.liveSize();
                    _ = try fx.db.sweepToBudget(live * rnd.uintLessThan(u64, 100) / 100, .{
                        .chunk_deletes = rnd.uintLessThan(usize, 5) + 1,
                    });
                    for (ids, 0..) |id, m| {
                        const all = try collect(gpa, &fx.db, id, std.math.minInt(i64), std.math.maxInt(i64));
                        defer gpa.free(all);
                        for (all) |g| {
                            const want = model[m].get(g.ts) orelse return error.TestUnexpectedResult;
                            try testing.expectEqual(want, @as(u64, @bitCast(g.value)));
                        }
                        model[m].clearRetainingCapacity();
                        for (all) |g| try model[m].put(gpa, g.ts, @bitCast(g.value));
                    }
                },
                else => {}, // a read-only step
            }
            // Every series, any window: the store equals the model.
            _ = try checkBlockInvariants(&fx.db);
            for (ids, 0..) |id, m| {
                const lo = rnd.intRangeLessThan(i64, -60, horizon + 10);
                const hi = lo + rnd.intRangeLessThan(i64, 0, 400);
                var want: std.ArrayList(Sample) = .empty;
                defer want.deinit(gpa);
                for (model[m].keys(), model[m].values()) |ts, v| if (ts >= lo and ts < hi) try want.append(gpa, .{ .ts = ts, .value = @bitCast(v) });
                std.mem.sort(Sample, want.items, {}, struct {
                    fn lt(_: void, x: Sample, y: Sample) bool {
                        return x.ts < y.ts;
                    }
                }.lt);
                const got = try collect(gpa, &fx.db, id, lo, hi);
                defer gpa.free(got);
                try testing.expectEqual(want.items.len, got.len);
                for (want.items, got) |w, g| {
                    try testing.expectEqual(w.ts, g.ts);
                    try testing.expectEqual(@as(u64, @bitCast(w.value)), @as(u64, @bitCast(g.value)));
                }
            }
        }
    }
}

test "compact: a crash at any storage effect leaves every sample exactly once; re-running finishes it" {
    const gpa = testing.allocator;
    var ref: Fixture = try .init(gpa);
    defer ref.deinit();
    const ref_ids = try seedGrid(&ref, 3, 300);
    defer gpa.free(ref_ids);
    const ref_before = try collectAll(gpa, &ref.db, ref_ids);
    defer freeAll(gpa, ref_before);
    _ = try ref.db.compact(std.math.maxInt(i64), .{ .min_run = 1, .chunk_points = 200 });

    const CrashMode = @FieldType(kvtree.SimStorage, "crash_mode");
    const modes = [_]CrashMode{ .lose_unsynced, .torn_tail, .reorder_unsynced, .keep_unsynced };
    for (modes) |mode| {
        var crash_at: usize = 0;
        var survived_without_crashing = false;
        while (!survived_without_crashing) : (crash_at += 1) {
            try testing.expect(crash_at < 400);
            var fx = try Fixture.init(gpa);
            defer fx.deinit();
            fx.sim.crash_mode = mode;
            fx.sim.reorder_seed = 0x6c1f +% @as(u64, crash_at) *% 0x9e3779b97f4a7c15;
            const ids = try seedGrid(&fx, 3, 300);
            defer gpa.free(ids);

            fx.sim.ops_until_crash = crash_at;
            if (fx.db.compact(std.math.maxInt(i64), .{ .min_run = 1, .chunk_points = 200 })) |_| {
                survived_without_crashing = true;
            } else |_| {}
            fx.sim.reboot();
            try fx.reopen();

            // Whatever committed, every sample is there exactly once.
            const mid = try collectAll(gpa, &fx.db, ids);
            defer freeAll(gpa, mid);
            for (ref_before, mid) |a, b| try testing.expectEqualSlices(Sample, a, b);
            _ = try checkBlockInvariants(&fx.db);

            const fin = try fx.db.compact(std.math.maxInt(i64), .{ .min_run = 1, .chunk_points = 200 });
            try testing.expect(fin.done);
            try testing.expectEqual(@as(usize, 0), try rawCount(&fx.db));
            const after = try collectAll(gpa, &fx.db, ids);
            defer freeAll(gpa, after);
            for (ref_before, after) |a, b| try testing.expectEqualSlices(Sample, a, b);
        }
    }
}

fn collectAll(gpa: Allocator, db: *Db, ids: []const SeriesId) ![][]Sample {
    const out = try gpa.alloc([]Sample, ids.len);
    for (ids, out) |id, *o| o.* = try collect(gpa, db, id, std.math.minInt(i64), std.math.maxInt(i64));
    return out;
}

fn freeAll(gpa: Allocator, all: [][]Sample) void {
    for (all) |a| gpa.free(a);
    gpa.free(all);
}

test "deleteSeries: raw and compacted samples and both index entries go; the id is not reused; other series untouched" {
    const gpa = testing.allocator;
    var fx = try Fixture.init(gpa);
    defer fx.deinit();
    const keep = try fx.db.seriesId("keep", &.{});
    const gone = try fx.db.seriesId("gone", &.{.{ .name = "a", .value = "1" }});
    for (0..3000) |i| {
        try fx.db.append(keep, @intCast(i), 1);
        try fx.db.append(gone, @intCast(i), 2);
    }
    _ = try fx.db.compact(2000, .{ .min_run = 1 }); // both partitions populated
    const before_keep = try fx.db.liveSize();

    // Small chunks: several transactions, the index removed only by the last.
    const r = try fx.db.deleteSeries(gone, .{ .chunk_deletes = 3 });
    try testing.expect(r.existed);
    try testing.expectEqual(@as(usize, 3000), r.deleted);
    try testing.expect(r.chunks > 1);
    try testing.expect((try fx.db.lookupSeries("gone", &.{.{ .name = "a", .value = "1" }})) == null);
    try testing.expect((try fx.db.seriesCanonical(gpa, gone)) == null);
    const none = try collect(gpa, &fx.db, gone, std.math.minInt(i64), std.math.maxInt(i64));
    defer gpa.free(none);
    try testing.expectEqual(@as(usize, 0), none.len);
    const kept = try collect(gpa, &fx.db, keep, std.math.minInt(i64), std.math.maxInt(i64));
    defer gpa.free(kept);
    try testing.expectEqual(@as(usize, 3000), kept.len);
    try testing.expect(try fx.db.liveSize() < before_keep);

    var it = try fx.db.seriesIterator();
    defer it.deinit();
    var n: usize = 0;
    while (try it.next(gpa)) |e_val| {
        var e = e_val;
        defer e.deinit(gpa);
        try testing.expectEqual(keep, e.id);
        n += 1;
    }
    try testing.expectEqual(@as(usize, 1), n);

    // Re-registering the name gets a fresh id with no stale samples, also
    // through the in-memory cache that had the old id.
    const again = try fx.db.seriesId("gone", &.{.{ .name = "a", .value = "1" }});
    try testing.expect(again != gone);
    const fresh = try collect(gpa, &fx.db, again, std.math.minInt(i64), std.math.maxInt(i64));
    defer gpa.free(fresh);
    try testing.expectEqual(@as(usize, 0), fresh.len);
    // Deleting an unknown or already deleted id is a no-op.
    try testing.expect(!(try fx.db.deleteSeries(gone, .{})).existed);
}

// ── mutation-audit additions (2026-10-04) ────────────────────────────────────

fn blockBytesInTree(db: *Db) !u64 {
    var cur = try db.tree.cursor();
    defer cur.deinit();
    try cur.seek(&[_]u8{codec.tag_block});
    var bytes: u64 = 0;
    while (try cur.next()) |e| {
        _ = codec.decodeBlockKey(e.key) orelse break;
        bytes += e.val.len + e.key.len;
    }
    return bytes;
}

test "compact: chunk_points, chunk_examines and max_chunks bound a call exactly; the raw tail above the horizon is skipped by one seek" {
    // Kills: `>=` -> `>` on the two chunk caps and on max_chunks, and a
    // dropped reseek after the horizon (the tail would be read and counted).
    const gpa = testing.allocator;
    {
        var fx = try Fixture.init(gpa);
        defer fx.deinit();
        const s = try fx.db.seriesId("m", &.{});
        for (0..10) |i| try fx.db.append(s, @intCast(i), 1);
        for (100..105) |i| try fx.db.append(s, @intCast(i), 1);
        const res = try fx.db.compact(50, .{ .min_run = 1, .chunk_points = 3 });
        try testing.expect(res.done);
        try testing.expectEqual(@as(usize, 10), res.compacted);
        try testing.expectEqual(@as(usize, 4), res.chunks); // 3 + 3 + 3 + 1
        try testing.expectEqual(@as(usize, 4), res.blocks_written);
        // 10 below the horizon, then ONE tail key read before the skip.
        try testing.expectEqual(@as(usize, 11), res.examined);
        try testing.expectEqual(@as(usize, 5), try rawCount(&fx.db));
    }
    {
        var fx = try Fixture.init(gpa);
        defer fx.deinit();
        const s = try fx.db.seriesId("m", &.{});
        for (0..10) |i| try fx.db.append(s, @intCast(i), 1);
        for (100..105) |i| try fx.db.append(s, @intCast(i), 1);
        const res = try fx.db.compact(50, .{ .min_run = 1, .chunk_examines = 4 });
        try testing.expect(res.done);
        try testing.expectEqual(@as(usize, 10), res.compacted);
        try testing.expectEqual(@as(usize, 3), res.blocks_written); // 4 + 4 + 2
    }
    {
        var fx = try Fixture.init(gpa);
        defer fx.deinit();
        const s = try fx.db.seriesId("m", &.{});
        for (0..10) |i| try fx.db.append(s, @intCast(i), 1);
        var res = try fx.db.compact(50, .{ .min_run = 1, .chunk_points = 3, .max_chunks = 2 });
        try testing.expect(!res.done);
        try testing.expectEqual(@as(usize, 2), res.chunks);
        try testing.expectEqual(@as(usize, 6), res.compacted);
        res = try fx.db.compact(50, .{ .min_run = 1, .chunk_points = 3 });
        try testing.expect(res.done);
        try testing.expectEqual(@as(usize, 4), res.compacted);
    }
}

test "compact: merging late samples into a full block splits it, counts every piece, and sizes the merge buffer by the raw count" {
    // Kills: merge `blocks_written` drift, an uncounted BlockFull split, and a
    // merge buffer that ignores raw.len (2024 samples > any growth slack).
    const gpa = testing.allocator;
    var fx = try Fixture.init(gpa);
    defer fx.deinit();
    const s = try fx.db.seriesId("m", &.{});
    for (0..1024) |i| try fx.db.append(s, @as(i64, @intCast(i)) * 10, 1);
    var res = try fx.db.compact(std.math.maxInt(i64), .{ .min_run = 1 });
    try testing.expectEqual(@as(usize, 1), res.blocks_written); // exactly max_block_samples
    for (0..1000) |k| try fx.db.append(s, @as(i64, @intCast(k)) * 10 + 5, 1); // inside the span
    res = try fx.db.compact(std.math.maxInt(i64), .{ .min_run = 1 });
    try testing.expectEqual(@as(usize, 1000), res.compacted);
    try testing.expectEqual(@as(usize, 2), res.blocks_written); // 1024 + 1000
    try testing.expectEqual(@as(usize, 2), try checkBlockInvariants(&fx.db));
    try testing.expectEqual(@as(usize, 0), try rawCount(&fx.db));
    const got = try collect(gpa, &fx.db, s, std.math.minInt(i64), std.math.maxInt(i64));
    defer gpa.free(got);
    try testing.expectEqual(@as(usize, 2024), got.len);
}

test "compact: a block whose last sample disagrees with its key is CorruptPoint, not silently merged" {
    // Kills: the last-vs-key check in mergeIntoBlock dropped.
    const gpa = testing.allocator;
    var fx = try Fixture.init(gpa);
    defer fx.deinit();
    const s = try fx.db.seriesId("m", &.{});
    var w = chunk.Writer.init();
    for ([_]Timestamp{ 10, 20, 30 }) |t| try w.append(.{ .ts = t, .value = 1 });
    try fx.tree.put(&codec.blockKey(s, 35), w.bytes()); // key says 35, last sample is 30
    try fx.db.append(s, 15, 2);
    try testing.expectError(error.CorruptPoint, fx.db.compact(std.math.maxInt(i64), .{ .min_run = 1 }));
    try testing.expectEqual(@as(usize, 1), try rawCount(&fx.db)); // rolled back
}

test "Range: a Range moved to new memory mid-block keeps decoding (the reader is rebound every use)" {
    // Kills: `rd.rebind` removed from fillBlock.
    const gpa = testing.allocator;
    var fx = try Fixture.init(gpa);
    defer fx.deinit();
    const s = try fx.db.seriesId("m", &.{});
    for (0..100) |i| try fx.db.append(s, @intCast(i), @floatFromInt(i));
    _ = try fx.db.compact(std.math.maxInt(i64), .{ .min_run = 1 });
    var rng = try fx.db.range(s, std.math.minInt(i64), std.math.maxInt(i64));
    for (0..5) |i| try testing.expectEqual(@as(Timestamp, @intCast(i)), (try rng.next()).?.ts);
    const moved = try gpa.create(Range);
    defer gpa.destroy(moved);
    moved.* = rng;
    @memset(std.mem.asBytes(&rng), 0xAA); // the old copy's block buffer is garbage now
    defer moved.deinit();
    var i: usize = 5;
    while (try moved.next()) |smp| : (i += 1) {
        try testing.expectEqual(@as(Timestamp, @intCast(i)), smp.ts);
        try testing.expectEqual(@as(f64, @floatFromInt(i)), smp.value);
    }
    try testing.expectEqual(@as(usize, 100), i);
}

test "series id maxInt: compact, sweep and reads survive the next-series overflow edge in both partitions" {
    // Kills: the maxInt-series guards in sweepChunk (raw and block branch)
    // dropped -- `series + 1` would overflow and panic.
    const gpa = testing.allocator;
    var fx = try Fixture.init(gpa);
    defer fx.deinit();
    const top: SeriesId = std.math.maxInt(SeriesId);
    for (0..10) |i| try fx.db.append(top, @intCast(i), @floatFromInt(i));
    const c = try fx.db.compact(5, .{ .min_run = 1 });
    try testing.expect(c.done);
    try testing.expectEqual(@as(usize, 5), c.compacted);
    const r = try fx.db.sweep(3, .{});
    try testing.expect(r.done);
    try testing.expectEqual(@as(usize, 3), r.deleted); // 0, 1, 2 of the block
    const got = try collect(gpa, &fx.db, top, std.math.minInt(i64), std.math.maxInt(i64));
    defer gpa.free(got);
    try testing.expectEqual(@as(usize, 7), got.len);
    try testing.expectEqual(@as(Timestamp, 3), got[0].ts);
    try testing.expectEqual(@as(Timestamp, 9), got[6].ts);
}

test "sweep: a malformed key in the block tag range ends the scan instead of looping" {
    // Kills: `<` -> `<=` on the leave-the-raw-partition test (it would re-seek
    // to the first block forever).
    const gpa = testing.allocator;
    var fx = try Fixture.init(gpa);
    defer fx.deinit();
    const s = try fx.db.seriesId("m", &.{});
    for (0..10) |i| try fx.db.append(s, @intCast(i), 1);
    _ = try fx.db.compact(std.math.maxInt(i64), .{ .min_run = 1 });
    try fx.tree.put(&[_]u8{ codec.tag_block, 0xff }, "x");
    const r = try fx.db.sweep(5, .{});
    try testing.expect(r.done);
    try testing.expectEqual(@as(usize, 5), r.deleted);
    const got = try collect(gpa, &fx.db, s, std.math.minInt(i64), std.math.maxInt(i64));
    defer gpa.free(got);
    try testing.expectEqual(@as(usize, 5), got.len);
}

test "sweep: chunk_deletes bounds the deletes of one chunk exactly" {
    // Kills: `>=` -> `>` on the sweepChunk delete cap.
    const gpa = testing.allocator;
    var fx = try Fixture.init(gpa);
    defer fx.deinit();
    const s = try fx.db.seriesId("m", &.{});
    for (0..10) |i| try fx.db.append(s, @intCast(i), 1);
    const r = try fx.db.sweep(5, .{ .chunk_deletes = 2 });
    try testing.expect(r.done);
    try testing.expectEqual(@as(usize, 5), r.deleted);
    try testing.expectEqual(@as(usize, 3), r.chunks); // 2 + 2 + 1
}

test "liveSize: a block entry counts its key and value bytes exactly, next to the raw points" {
    // Kills: the block scan seeking the wrong tag, and a dropped key length.
    const gpa = testing.allocator;
    var fx = try Fixture.init(gpa);
    defer fx.deinit();
    const s = try fx.db.seriesId("m", &.{});
    for (0..300) |i| try fx.db.append(s, @intCast(i), @floatFromInt(i % 7));
    _ = try fx.db.compact(200, .{ .min_run = 1 });
    const packed_bytes = try blockBytesInTree(&fx.db);
    try testing.expect(packed_bytes > 0);
    try testing.expectEqual(@as(usize, 100), try rawCount(&fx.db));
    try testing.expectEqual(100 * codec.point_entry_bytes + packed_bytes, try fx.db.liveSize());
}

test "sweepToBudget: equal timestamps go lowest series id first" {
    // Kills: the series tie-break reversed.
    const gpa = testing.allocator;
    var fx = try Fixture.init(gpa);
    defer fx.deinit();
    const a = try fx.db.seriesId("a", &.{});
    const b = try fx.db.seriesId("b", &.{});
    for ([_]SeriesId{ a, b }) |id| {
        try fx.db.append(id, 100, 1);
        try fx.db.append(id, 200, 2);
    }
    const before = try fx.db.liveSize();
    const r = try fx.db.sweepToBudget(before - codec.point_entry_bytes, .{});
    try testing.expect(r.done);
    try testing.expectEqual(@as(usize, 1), r.deleted);
    const got_a = try collect(gpa, &fx.db, a, std.math.minInt(i64), std.math.maxInt(i64));
    defer gpa.free(got_a);
    try testing.expectEqual(@as(usize, 1), got_a.len);
    try testing.expectEqual(@as(Timestamp, 200), got_a[0].ts);
    const got_b = try collect(gpa, &fx.db, b, std.math.minInt(i64), std.math.maxInt(i64));
    defer gpa.free(got_b);
    try testing.expectEqual(@as(usize, 2), got_b.len);
}

test "sweepToBudget: on a timestamp tie the block goes before the raw point that shadows it (review H1)" {
    // Kills: the tie-break reversed to raw-first — which deleted the newer
    // raw value and let the overwritten block sample read again.
    const gpa = testing.allocator;
    var fx = try Fixture.init(gpa);
    defer fx.deinit();
    const s = try fx.db.seriesId("m", &.{});
    for (100..150) |i| try fx.db.append(s, @intCast(i), @floatFromInt(i));
    _ = try fx.db.compact(std.math.maxInt(i64), .{ .min_run = 1 });
    try fx.db.append(s, 100, -1); // overwrite of the block's first sample
    try fx.db.append(s, 1000, 5);
    const before = try fx.db.liveSize();
    const r = try fx.db.sweepToBudget(before - codec.point_entry_bytes, .{});
    try testing.expectEqual(@as(usize, 50), r.deleted); // the whole block
    const got = try collect(gpa, &fx.db, s, std.math.minInt(i64), std.math.maxInt(i64));
    defer gpa.free(got);
    // Never the stale 100: the newer -1 survives, or nothing at ts 100 does.
    for (got) |g| if (g.ts == 100) try testing.expectEqual(@as(f64, -1), g.value);
    try testing.expectEqual(@as(usize, 2), got.len);
}

test "sweepToBudget: a block is ordered by its FIRST sample, not its key (last sample)" {
    // Kills: unitAt's block `oldest` taken from the key.
    const gpa = testing.allocator;
    var fx = try Fixture.init(gpa);
    defer fx.deinit();
    const a = try fx.db.seriesId("a", &.{});
    const b = try fx.db.seriesId("b", &.{});
    for (0..101) |i| try fx.db.append(a, @intCast(i), 1);
    _ = try fx.db.compact(std.math.maxInt(i64), .{ .min_run = 1 });
    try fx.db.append(b, 50, 2); // between the block's first (0) and last (100)
    const before = try fx.db.liveSize();
    const r = try fx.db.sweepToBudget(before - codec.point_entry_bytes, .{});
    try testing.expect(r.done);
    const got_a = try collect(gpa, &fx.db, a, std.math.minInt(i64), std.math.maxInt(i64));
    defer gpa.free(got_a);
    try testing.expectEqual(@as(usize, 0), got_a.len);
    const got_b = try collect(gpa, &fx.db, b, std.math.minInt(i64), std.math.maxInt(i64));
    defer gpa.free(got_b);
    try testing.expectEqual(@as(usize, 1), got_b.len);
}

test "sweepToBudget: a series without raw points or without blocks is never credited with its neighbour's entries" {
    // Kills: the series checks in unitAt dropped (a probe would land on the
    // next series' entry and the accounting would count it twice).
    const gpa = testing.allocator;
    var fx = try Fixture.init(gpa);
    defer fx.deinit();
    const s1 = try fx.db.seriesId("s1", &.{});
    const s2 = try fx.db.seriesId("s2", &.{});
    const s3 = try fx.db.seriesId("s3", &.{});
    for (0..100) |i| {
        try fx.db.append(s1, @intCast(i), 1);
        try fx.db.append(s3, @intCast(i), 1);
    }
    _ = try fx.db.compact(std.math.maxInt(i64), .{ .min_run = 1 }); // s1, s3: blocks only
    for (0..10) |i| try fx.db.append(s2, @intCast(i), 1); // s2: raw only
    const r = try fx.db.sweepToBudget(0, .{});
    try testing.expect(r.done);
    try testing.expectEqual(@as(usize, 210), r.deleted);
    try testing.expectEqual(@as(u64, 0), r.after);
    try testing.expectEqual(@as(u64, 0), try fx.db.liveSize());
}

test "sweepToBudget: chunk_deletes bounds the entries per commit" {
    // Kills: the delete chunk widened by one (half the commits at chunk 1).
    const gpa = testing.allocator;
    var sim = kvtree.SimStorage.init(gpa);
    defer sim.deinit();
    sim.allow_overwrite = true;
    var counting = CountingStorage{ .inner = sim.storage() };
    var tree = try kvtree.Db.open(gpa, counting.storage(), "series.kvt", .{});
    defer tree.close();
    var db = Db.init(gpa, &tree);
    defer db.deinit();
    const s = try db.seriesId("m", &.{});
    for (0..12) |i| try db.append(s, @intCast(i), 1);

    var t0 = counting.sync_count;
    var before = try db.liveSize();
    var r = try db.sweepToBudget(before - 4 * codec.point_entry_bytes, .{ .chunk_deletes = 100 });
    try testing.expectEqual(@as(usize, 4), r.deleted);
    const per_commit = counting.sync_count - t0;
    try testing.expect(per_commit > 0);

    t0 = counting.sync_count;
    before = try db.liveSize();
    r = try db.sweepToBudget(before - 4 * codec.point_entry_bytes, .{ .chunk_deletes = 1 });
    try testing.expectEqual(@as(usize, 4), r.deleted);
    try testing.expectEqual(4 * per_commit, counting.sync_count - t0);
}

test "deleteSeries: deleting a LOWER id never touches a higher series, and chunking is exact" {
    // Kills: the series-boundary break dropped in either pass, and
    // `>=` -> `>` on chunk_deletes.
    const gpa = testing.allocator;
    var fx = try Fixture.init(gpa);
    defer fx.deinit();
    const a = try fx.db.seriesId("a", &.{});
    const b = try fx.db.seriesId("b", &.{});
    for (0..100) |i| {
        try fx.db.append(a, @intCast(i), 1);
        try fx.db.append(b, @intCast(i), 2);
    }
    _ = try fx.db.compact(50, .{ .min_run = 1 }); // 50 raw + 1 block each
    const r = try fx.db.deleteSeries(a, .{ .chunk_deletes = 10 });
    try testing.expect(r.existed);
    try testing.expectEqual(@as(usize, 100), r.deleted);
    try testing.expectEqual(@as(usize, 6), r.chunks); // 5 x 10 raw keys, then the block
    const kept = try collect(gpa, &fx.db, b, std.math.minInt(i64), std.math.maxInt(i64));
    defer gpa.free(kept);
    try testing.expectEqual(@as(usize, 100), kept.len);
    try testing.expectEqual(@as(usize, 50), try rawCount(&fx.db));
    try testing.expectEqual(@as(usize, 1), try checkBlockInvariants(&fx.db));
}
