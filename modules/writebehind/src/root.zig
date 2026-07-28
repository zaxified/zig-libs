// SPDX-License-Identifier: MIT

//! writebehind — a crash-safe write-behind (write-back) cache coordinator.
//!
//! Application writes hit a fast in-memory cache and return immediately; dirty
//! entries are flushed asynchronously to a durable sink by a worker pool. A
//! durable write-ahead log (WAL) makes it crash-safe: an acknowledged `put` is
//! never lost, even if the process dies before the async flush lands.
//!
//! This is the P2 data-layer "write-behind coordinator" (DL5) — the product
//! feature that lets the server ack writes at cache speed while guaranteeing
//! durability. It is a *composition* of four existing modules, each used for
//! exactly its strength:
//!
//!   * **`ramcache`** — the write buffer + read cache. Every `put` lands here
//!     (marked dirty) and returns; `get` serves from it. Its write-behind seam
//!     (`on_evict` / dirty-bit / `drainDirty` / `markClean`) tells the
//!     coordinator *which* keys still need flushing and catches a dirty entry
//!     that is evicted before the flusher reaches it.
//!   * **`jobqueue`** — the **durable WAL** and crash-safety anchor. Every
//!     `put`/`del` appends a durable record (fsync'd) *before* the caller sees
//!     an ack; the flusher later leases → writes-to-sink → acks (a durable
//!     delete). A crash leaves every un-acked record on disk; `recover` replays
//!     them. Partition = the cache key, so a key's records dequeue oldest-first
//!     (FIFO) — the ordering that makes last-writer-wins hold.
//!   * **`workerpool`** — flush concurrency. Each "write this record to the
//!     sink" job runs off the request path on a pool worker.
//!   * **`kvtree`** — the reference durable **sink** (`KvtreeSink`). Any sink
//!     that implements the `Sink` vtable works; a later SQL adapter (DL6) slots
//!     in without touching this module. `MapSink` is an in-memory sink for
//!     tests.
//!
//! ## Durability & consistency guarantee
//!
//!   * **Durability.** When `put(k, v)` returns, `v` is durable: its WAL record
//!     was fsync'd by `jobqueue` before the ack. A crash at any later point
//!     loses nothing — `recover()` (or the next flush) re-applies it to the
//!     sink. This holds even though the sink write itself is asynchronous.
//!   * **Consistency = eventual, last-writer-wins per key.** After a quiescent
//!     `flushAll()` (or a `recover()`), the sink reflects, for every key, the
//!     value of the *last* acknowledged `put` (or absence, after the last
//!     `del`). Flushes for *different* keys may be reordered and run
//!     concurrently; flushes for the *same* key are serialized in enqueue order
//!     (single-flight per key + FIFO WAL partition), so a key never regresses to
//!     an older value.
//!   * **At-least-once to the sink.** A recovered/retried record may be written
//!     to the sink more than once; because the sink is a keyed store, a
//!     duplicate write of the same (k, v) is idempotent. `recover()` is itself
//!     idempotent (a second call is a no-op — the WAL is already drained).
//!
//! ## Threading contract
//!
//!   * **The write side is single-owner.** One thread ("the coordinator
//!     thread") calls `put` / `get` / `del` / `drain` / `flushAll` / `recover` /
//!     `deinit`. These are NOT internally synchronized against each other —
//!     exactly like the `ramcache`, `jobqueue`, and `kvtree` they wrap (all
//!     `single_owner`). Do not call them from two threads at once.
//!   * **Flush concurrency is internal.** The worker pool runs sink writes on
//!     its own threads. A flush job touches ONLY the `Sink` (and an internal
//!     completion channel); it never touches the cache or the WAL — those stay
//!     single-owner on the coordinator thread, which harvests completions and
//!     does all cache/WAL bookkeeping.
//!   * **The `Sink` must tolerate concurrent calls** from multiple worker
//!     threads (and the coordinator thread during `get` read-through /
//!     `recover`). The reference `KvtreeSink` / `MapSink` serialize internally
//!     with a spinlock, since `kvtree` is single-writer.
//!   * **The allocator must be thread-safe** (the worker pool allocates queue
//!     nodes and job boxes from worker threads — `workerpool`'s documented
//!     requirement). Use a thread-safe allocator not near exhaustion.
//!
//! ## The workerpool producer-quiescence contract, honored
//!
//! `workerpool`'s lifecycle (`drain`/`deinit`) must not run concurrently with
//! `submit`. The coordinator is the *only* submitter, and it submits only from
//! the coordinator thread. `deinit` first runs `flushAll` (which blocks until
//! every submitted flush has completed and been harvested — no jobs are in
//! flight and none are about to be submitted), and only *then* calls
//! `pool.drain()`. So producers are provably quiesced before the lifecycle
//! call. `max_submitters = 0`: only the shared, spinlock-serialized `submit`
//! path is used, never a `Submitter` handle.

const std = @import("std");
const Allocator = std.mem.Allocator;

const ramcache = @import("ramcache");
const workerpool = @import("workerpool");
const jobqueue = @import("jobqueue");
const kvtree = @import("kvtree");

pub const meta = .{
    // `jobqueue`'s default wall/monotonic clocks use posix `clock_gettime`
    // (both injectable); everything else is portable.
    .platform = .posix,
    .role = .both,
    // The public write-side API is single-owner (one coordinator thread);
    // flush concurrency is an internal detail provided by the worker pool.
    .concurrency = .single_owner,
    .model_after = "write-back cache (Caffeine writeBehind / a DB buffer pool) over a durable WAL",
    .deps = .{ "ramcache", "workerpool", "jobqueue", "kvtree" },
};

// ── re-exported storage seam ────────────────────────────────────────────────
//
// The WAL runs on `jobqueue`, which is backed by the `kv` `Storage` interface.
// Re-export it (via `kvtree`, which already re-exports the identical types) so
// a consumer wires a WAL backend without importing `kv` directly: production
// `FsStorage`, deterministic `SimStorage`.
pub const Storage = kvtree.Storage;
pub const FsStorage = kvtree.FsStorage;
pub const SimStorage = kvtree.SimStorage;

// ── the sink abstraction (vtable) ───────────────────────────────────────────

/// A sink-agnostic durable destination. The coordinator flushes cache writes
/// through this vtable; a concrete adapter (kvtree today, a SQL table under
/// DL6) implements it. **Thread-safety:** `write`/`delete`/`read` may be called
/// concurrently from multiple worker threads and the coordinator thread — an
/// implementation that is not internally thread-safe must synchronize (the
/// reference adapters use a spinlock).
pub const Sink = struct {
    ptr: *anyopaque,
    vtable: *const VTable,

    pub const VTable = struct {
        /// Durably upsert `key` → `value`. Both slices are borrowed for the
        /// call only; copy anything you retain.
        write: *const fn (ptr: *anyopaque, key: []const u8, value: []const u8) anyerror!void,
        /// Durably remove `key` (a no-op if absent).
        delete: *const fn (ptr: *anyopaque, key: []const u8) anyerror!void,
        /// Optional read-through: fetch `key` from the sink, allocating the
        /// result with `gpa` (caller frees). `null` field ⇒ no read-through (a
        /// cache miss with no readable sink returns `null`).
        read: ?*const fn (ptr: *anyopaque, gpa: Allocator, key: []const u8) anyerror!?[]u8 = null,
    };

    pub fn write(self: Sink, key: []const u8, value: []const u8) anyerror!void {
        return self.vtable.write(self.ptr, key, value);
    }
    pub fn delete(self: Sink, key: []const u8) anyerror!void {
        return self.vtable.delete(self.ptr, key);
    }
    /// Returns `error.NoReadThrough` if the sink provides no `read`.
    pub fn read(self: Sink, gpa: Allocator, key: []const u8) anyerror!?[]u8 {
        const f = self.vtable.read orelse return error.NoReadThrough;
        return f(self.ptr, gpa, key);
    }
    pub fn canRead(self: Sink) bool {
        return self.vtable.read != null;
    }
};

/// A tiny test/utility spinlock (pure `std.atomic`) used to make the
/// single-writer reference sinks safe under concurrent flush.
const SpinLock = struct {
    state: std.atomic.Value(u32) = .init(0),
    fn lock(self: *SpinLock) void {
        while (self.state.cmpxchgWeak(0, 1, .acquire, .monotonic) != null)
            std.atomic.spinLoopHint();
    }
    fn unlock(self: *SpinLock) void {
        self.state.store(0, .release);
    }
};

// ── reference sink: kvtree ──────────────────────────────────────────────────

/// The reference durable sink over a `kvtree.Db` (the caller owns the `Db` and
/// its storage). Serializes all sink ops with a spinlock, since `kvtree` is
/// single-writer and the coordinator flushes concurrently.
pub const KvtreeSink = struct {
    db: *kvtree.Db,
    gpa: Allocator,
    lock: SpinLock = .{},

    pub fn init(gpa: Allocator, db: *kvtree.Db) KvtreeSink {
        return .{ .db = db, .gpa = gpa };
    }

    pub fn sink(self: *KvtreeSink) Sink {
        return .{ .ptr = self, .vtable = &vtable };
    }

    const vtable = Sink.VTable{ .write = vWrite, .delete = vDelete, .read = vRead };

    fn cast(ptr: *anyopaque) *KvtreeSink {
        return @ptrCast(@alignCast(ptr));
    }
    fn vWrite(ptr: *anyopaque, key: []const u8, value: []const u8) anyerror!void {
        const self = cast(ptr);
        self.lock.lock();
        defer self.lock.unlock();
        try self.db.put(key, value);
    }
    fn vDelete(ptr: *anyopaque, key: []const u8) anyerror!void {
        const self = cast(ptr);
        self.lock.lock();
        defer self.lock.unlock();
        try self.db.del(key);
    }
    fn vRead(ptr: *anyopaque, gpa: Allocator, key: []const u8) anyerror!?[]u8 {
        const self = cast(ptr);
        self.lock.lock();
        defer self.lock.unlock();
        return self.db.get(gpa, key);
    }
};

// ── reference sink: in-memory map (tests / a volatile tier) ─────────────────

/// A simple thread-safe in-memory sink — a durable-store stand-in for tests and
/// a legitimate volatile lower tier. Owns copies of every key/value.
pub const MapSink = struct {
    gpa: Allocator,
    map: std.StringHashMapUnmanaged([]u8) = .empty,
    lock: SpinLock = .{},

    pub fn init(gpa: Allocator) MapSink {
        return .{ .gpa = gpa };
    }
    pub fn deinit(self: *MapSink) void {
        var it = self.map.iterator();
        while (it.next()) |e| {
            self.gpa.free(e.key_ptr.*);
            self.gpa.free(e.value_ptr.*);
        }
        self.map.deinit(self.gpa);
        self.* = undefined;
    }

    pub fn sink(self: *MapSink) Sink {
        return .{ .ptr = self, .vtable = &vtable };
    }
    /// Count of live keys (test helper).
    pub fn count(self: *MapSink) usize {
        self.lock.lock();
        defer self.lock.unlock();
        return self.map.count();
    }
    /// Borrowed value for `key` (test helper; valid until the next sink write
    /// to that key).
    pub fn peek(self: *MapSink, key: []const u8) ?[]const u8 {
        self.lock.lock();
        defer self.lock.unlock();
        return self.map.get(key);
    }

    const vtable = Sink.VTable{ .write = vWrite, .delete = vDelete, .read = vRead };

    fn cast(ptr: *anyopaque) *MapSink {
        return @ptrCast(@alignCast(ptr));
    }
    fn vWrite(ptr: *anyopaque, key: []const u8, value: []const u8) anyerror!void {
        const self = cast(ptr);
        self.lock.lock();
        defer self.lock.unlock();
        const vdup = try self.gpa.dupe(u8, value);
        errdefer self.gpa.free(vdup);
        if (self.map.getPtr(key)) |slot| {
            self.gpa.free(slot.*);
            slot.* = vdup;
            return;
        }
        const kdup = try self.gpa.dupe(u8, key);
        errdefer self.gpa.free(kdup);
        try self.map.put(self.gpa, kdup, vdup);
    }
    fn vDelete(ptr: *anyopaque, key: []const u8) anyerror!void {
        const self = cast(ptr);
        self.lock.lock();
        defer self.lock.unlock();
        if (self.map.fetchRemove(key)) |kv| {
            self.gpa.free(kv.key);
            self.gpa.free(kv.value);
        }
    }
    fn vRead(ptr: *anyopaque, gpa: Allocator, key: []const u8) anyerror!?[]u8 {
        const self = cast(ptr);
        self.lock.lock();
        defer self.lock.unlock();
        const v = self.map.get(key) orelse return null;
        return try gpa.dupe(u8, v);
    }
};

// ── coordinator ─────────────────────────────────────────────────────────────

pub const Options = struct {
    /// The `Io` backing the worker pool (futex wait/wake) and `flushAll`'s
    /// blocking wait. Must outlive the coordinator.
    io: std.Io,
    /// The durable destination (see `Sink`).
    sink: Sink,
    /// Storage backend for the durable WAL (`FsStorage` in production,
    /// `SimStorage` in tests).
    wal_store: Storage,
    /// WAL file path, resolved by `wal_store`.
    wal_path: []const u8,
    /// Read cache byte budget (see `ramcache`).
    max_cache_bytes: usize,
    /// Read cache entry budget (see `ramcache`).
    max_cache_entries: usize,
    /// Flush worker count. `null` ⇒ a cpu-derived default (min 1).
    n_workers: ?usize = null,
    /// Requeue backoff after a *failed* sink write (wall ns). Default 0 = retry
    /// on the next drain with no delay.
    retry_backoff_ns: u64 = 0,
    /// WAL clocks (injectable for deterministic tests). Defaults use the OS
    /// clocks. Delivery visibility uses only `delay = 0`, so the wall clock
    /// merely needs to be non-decreasing.
    wal_wall_clock: jobqueue.WallClock = .system,
    wal_mono_clock: jobqueue.MonoClock = .monotonic,
};

pub const InitError = error{WalOpenFailed} || workerpool.InitError || Allocator.Error;

pub const PutError = error{
    /// `key` exceeds the WAL field cap (`jobqueue.max_field_len`, 4096).
    KeyTooLarge,
    /// `value` exceeds the WAL payload cap.
    ValueTooLarge,
    /// The durable WAL append failed (storage error) — the write was NOT
    /// acknowledged and nothing changed.
    WalWriteFailed,
} || Allocator.Error;

pub const GetError = error{SinkReadFailed} || Allocator.Error;

pub const RecoverError = error{SinkWriteFailed};

const Op = enum { put, del };

/// One queued flush: an owned snapshot of a single WAL record plus the lease to
/// ack once the sink write lands. Heap-allocated; the worker thread fills `ok`
/// and links it onto the completion list; the coordinator thread acks + frees.
const FlushTask = struct {
    coord: *Coordinator,
    op: Op,
    key: []u8,
    value: []u8,
    lease: jobqueue.Lease,
    ok: bool = false,
    next: ?*FlushTask = null,
};

pub const Coordinator = struct {
    gpa: Allocator,
    io: std.Io,
    sink: Sink,
    pool: *workerpool.WorkerPool,
    wal: jobqueue.Queue,
    cache: ramcache.Cache,
    retry_backoff_ns: u64,

    /// Un-acked WAL records (== writes not yet known-durable in the sink).
    /// Coordinator-thread-only. `flushAll`/`deinit` block until this is 0.
    unflushed: usize = 0,

    /// Keys with a flush currently in flight (single-flight per key → per-key
    /// ordering → LWW). Owns its key strings.
    in_flight: std.StringHashMapUnmanaged(void) = .empty,
    /// Dirty keys evicted from the cache before being flushed (the `on_evict`
    /// safety net): their WAL records are still durable, so the flusher must
    /// revisit them even though the cache no longer lists them dirty. Owns keys.
    orphans: std.StringHashMapUnmanaged(void) = .empty,
    /// Keys deleted but possibly still cached — `get` returns `null` for these
    /// so a `del` is visible immediately. Cleared by a later `put`. Owns keys.
    tombstones: std.StringHashMapUnmanaged(void) = .empty,
    /// Scratch list of duped keys collected from `drainDirty`/`orphans`.
    scratch: std.ArrayList([]u8) = .empty,

    // completion channel (worker → coordinator)
    completion_lock: SpinLock = .{},
    completion_head: ?*FlushTask = null,
    /// Bumped on every completion; the futex word `flushAll` parks on.
    completion_gen: std.atomic.Value(u32) = .init(0),

    const vis_timeout_ns: u64 = 60 * std.time.ns_per_s;

    /// Build the coordinator. Returns a heap-owned `*Coordinator` so worker
    /// flush tasks can hold a stable back-pointer. `deinit` frees it.
    ///
    /// If `wal_path` names a non-empty existing WAL, call `recover()` right
    /// after `init` (before serving) to replay any writes that a prior process
    /// acked but had not yet flushed.
    pub fn init(gpa: Allocator, options: Options) InitError!*Coordinator {
        const self = try gpa.create(Coordinator);
        errdefer gpa.destroy(self);

        self.* = .{
            .gpa = gpa,
            .io = options.io,
            .sink = options.sink,
            .pool = undefined,
            .wal = undefined,
            .cache = undefined,
            .retry_backoff_ns = options.retry_backoff_ns,
        };

        self.pool = try workerpool.WorkerPool.init(gpa, .{
            .io = options.io,
            .n_workers = options.n_workers,
            .max_submitters = 0, // only the shared, serialized submit path
        });
        errdefer self.pool.deinit();

        self.wal = jobqueue.Queue.open(gpa, options.wal_store, options.wal_path, .{
            .wall_clock = options.wal_wall_clock,
            .mono_clock = options.wal_mono_clock,
        }) catch return error.WalOpenFailed;
        errdefer self.wal.close();

        self.cache = ramcache.Cache.init(gpa, .{
            .max_bytes = options.max_cache_bytes,
            .max_entries = options.max_cache_entries,
            .on_evict = onEvict,
            .on_evict_ctx = self,
        });

        // A reopened WAL carries the prior process's un-flushed writes.
        self.unflushed = self.wal.readyCount();
        return self;
    }

    /// Graceful teardown: flush everything durably to the sink, quiesce the
    /// pool, and release all resources. Honors the pool producer-quiescence
    /// contract (see the module doc). Blocks until the cache is clean.
    pub fn deinit(self: *Coordinator) void {
        self.flushAll(); // no jobs in flight and none about to be submitted after this
        self.pool.drain(); // producers quiesced → safe lifecycle call
        self.pump(); // harvest any final completions (none expected after flushAll)
        self.pool.deinit();
        self.wal.close();
        self.cache.deinit();
        self.freeKeySet(&self.in_flight);
        self.freeKeySet(&self.orphans);
        self.freeKeySet(&self.tombstones);
        for (self.scratch.items) |k| self.gpa.free(k);
        self.scratch.deinit(self.gpa);
        const gpa = self.gpa;
        gpa.destroy(self);
    }

    /// Abrupt teardown WITHOUT flushing — a crash simulation, or a fast exit
    /// that delegates durability to the next process's `recover()`. Un-acked
    /// WAL records stay durable; in-memory cache state is dropped. Queued flush
    /// jobs are discarded (their sink writes may or may not have run). The
    /// caller still owns (and must close) the sink's storage.
    pub fn deinitNoFlush(self: *Coordinator) void {
        self.pool.shutdownNow();
        self.pool.deinit();
        // Free any un-harvested completion tasks (their sink writes ran but were
        // never acked — the durable WAL still covers them for recovery).
        self.pump(); // acks whatever completed; the rest are simply dropped
        self.drainCompletionTasks();
        self.wal.close();
        self.cache.deinit();
        self.freeKeySet(&self.in_flight);
        self.freeKeySet(&self.orphans);
        self.freeKeySet(&self.tombstones);
        for (self.scratch.items) |k| self.gpa.free(k);
        self.scratch.deinit(self.gpa);
        const gpa = self.gpa;
        gpa.destroy(self);
    }

    // ── write path ──────────────────────────────────────────────────────────

    /// Buffer a write: durably append it to the WAL (crash-safety anchor),
    /// stage it in the cache (dirty), and return — the caller sees a fast ack.
    /// The value is durable when this returns.
    pub fn put(self: *Coordinator, key: []const u8, value: []const u8) PutError!void {
        // Durable WAL append FIRST — after this the write survives a crash.
        _ = self.wal.enqueue("put", value, .{ .partition = key }) catch |e| return mapWalErr(e);
        self.unflushed += 1;
        // Stage in the cache (marks the entry dirty). OOM here is non-fatal to
        // durability: the WAL record still drives the flush/recovery.
        self.cache.put(key, value, 0, 0, 0);
        // A prior tombstone (delete) for this key is now superseded.
        self.dropTombstone(key);
    }

    /// Durably delete `key`: append a WAL delete record, and shadow the key so
    /// a `get` misses immediately. Eventually removed from the sink by the
    /// flusher / `recover`.
    pub fn del(self: *Coordinator, key: []const u8) PutError!void {
        _ = self.wal.enqueue("del", "", .{ .partition = key }) catch |e| return mapWalErr(e);
        self.unflushed += 1;
        self.addTombstone(key) catch {};
        // The key's WAL delete record is not tied to a cached dirty entry, so
        // register it as an orphan for the flusher to pick up.
        self.addKeySet(&self.orphans, key) catch {};
    }

    /// Read `key`: cache hit (fast), else — if the sink supports read-through —
    /// fetch from the sink and populate the cache (as clean, no WAL write).
    /// `null` = absent. The returned slice borrows cache storage and is valid
    /// only until the next mutating call on this coordinator (copy if needed).
    pub fn get(self: *Coordinator, key: []const u8) GetError!?[]const u8 {
        if (self.tombstones.contains(key)) return null;
        if (self.cache.get(key, 0, 0)) |v| return v;
        if (!self.sink.canRead()) return null;
        const owned = self.sink.read(self.gpa, key) catch return error.SinkReadFailed;
        const buf = owned orelse return null;
        defer self.gpa.free(buf);
        self.cache.put(key, buf, 0, 0, 0);
        _ = self.cache.markClean(key); // read-through fill is not a pending write
        return self.cache.get(key, 0, 0);
    }

    // ── flush machinery ───────────────────────────────────────────────────────

    /// One non-blocking flush pass: harvest completed flushes (ack + advance),
    /// then submit new flush jobs for every dirty/orphan key not already in
    /// flight. Call periodically (a tick) or on a dirty-count threshold.
    pub fn drain(self: *Coordinator) void {
        self.pump();
        self.kick();
    }

    /// Block until the cache is fully clean: every acknowledged write is durable
    /// in the sink and nothing is in flight. Use for graceful shutdown / a
    /// consistency barrier. Assumes the sink eventually accepts writes.
    pub fn flushAll(self: *Coordinator) void {
        self.drain();
        while (self.unflushed > 0 or self.in_flight.count() > 0) {
            if (self.in_flight.count() == 0) {
                // Records remain but nothing is in flight (e.g. WAL entries from
                // a reopened log whose keys are not cache-dirty). Flush one
                // synchronously to guarantee forward progress, then re-drain.
                if (!self.flushOneSync()) break;
                self.drain();
                continue;
            }
            // Park until a worker signals a completion (bounded), then re-drain.
            const gen = self.completion_gen.load(.acquire);
            self.io.futexWaitTimeout(u32, &self.completion_gen.raw, gen, .{ .duration = .{
                .raw = .fromMilliseconds(50),
                .clock = .awake,
            } }) catch {};
            self.drain();
        }
    }
    /// Alias — a graceful-shutdown / barrier `sync`.
    pub fn sync(self: *Coordinator) void {
        self.flushAll();
    }

    /// Replay every durable, un-acked WAL record to the sink in global enqueue
    /// (FIFO) order, then ack it. Makes the sink eventually consistent with
    /// every acknowledged `put`/`del`. Idempotent: a second call finds an empty
    /// WAL and does nothing; replaying a (k, v) that is already in the sink is a
    /// harmless idempotent overwrite. Call once after `init` over a non-empty
    /// WAL, before serving. Synchronous (does not use the pool).
    pub fn recover(self: *Coordinator) RecoverError!void {
        while (self.wal.dequeue(.{ .visibility_timeout_ns = vis_timeout_ns }) catch null) |lease| {
            const op: Op = if (std.mem.eql(u8, lease.job_type, "del")) .del else .put;
            const res = switch (op) {
                .put => self.sink.write(lease.partition, lease.payload),
                .del => self.sink.delete(lease.partition),
            };
            if (res) |_| {
                self.wal.ack(lease) catch {};
                if (self.unflushed > 0) self.unflushed -= 1;
            } else |_| {
                self.wal.nack(lease, .{ .backoff_ns = 0 }) catch {};
                return error.SinkWriteFailed;
            }
        }
    }

    // ── observability ─────────────────────────────────────────────────────────

    /// Count of writes not yet known durable in the sink (un-acked WAL records).
    pub fn pendingCount(self: *const Coordinator) usize {
        return self.unflushed;
    }
    /// Flushes currently executing on the pool.
    pub fn inFlightCount(self: *const Coordinator) usize {
        return self.in_flight.count();
    }
    pub fn cacheStats(self: *const Coordinator) ramcache.Stats {
        return self.cache.stats;
    }

    // ── internals ─────────────────────────────────────────────────────────────

    /// Harvest all completed flushes and resolve each (ack + advance the key, or
    /// requeue on failure). Coordinator-thread-only.
    fn pump(self: *Coordinator) void {
        self.completion_lock.lock();
        var chain = self.completion_head;
        self.completion_head = null;
        self.completion_lock.unlock();
        while (chain) |t| {
            const nxt = t.next;
            self.finishTask(t);
            chain = nxt;
        }
    }

    fn finishTask(self: *Coordinator, t: *FlushTask) void {
        self.removeKeySet(&self.in_flight, t.key);
        if (t.ok) {
            self.wal.ack(t.lease) catch {};
            if (self.unflushed > 0) self.unflushed -= 1;
            // Advance this key: flush its next queued record, if any (keeps
            // per-key ordering). Otherwise the key is fully persisted.
            if (self.dequeueFor(t.key)) |lease2| {
                self.startFlush(t.key, lease2);
            } else {
                _ = self.cache.markClean(t.key);
                self.removeKeySet(&self.orphans, t.key);
            }
        } else {
            // Sink write failed: return the record to the WAL for retry. The key
            // stays dirty/orphan and a later `drain` re-selects it.
            self.wal.nack(t.lease, .{ .backoff_ns = self.retry_backoff_ns }) catch {};
        }
        self.freeTask(t);
    }

    /// Select every dirty/orphan key not in flight and submit a flush for its
    /// oldest queued WAL record.
    fn kick(self: *Coordinator) void {
        for (self.scratch.items) |k| self.gpa.free(k);
        self.scratch.clearRetainingCapacity();

        // Collect dirty keys (duped — the callback's slices are iteration-scoped
        // and we submit after the sweep).
        self.cache.drainDirty(collectDirty, self);
        // Collect orphan keys.
        var it = self.orphans.keyIterator();
        while (it.next()) |k| {
            if (self.in_flight.contains(k.*)) continue;
            const dup = self.gpa.dupe(u8, k.*) catch continue;
            self.scratch.append(self.gpa, dup) catch {
                self.gpa.free(dup);
            };
        }

        for (self.scratch.items) |k| self.startKey(k);
        for (self.scratch.items) |k| self.gpa.free(k);
        self.scratch.clearRetainingCapacity();
    }

    fn collectDirty(ctx: ?*anyopaque, key: []const u8, value: []const u8) void {
        _ = value;
        const self: *Coordinator = @ptrCast(@alignCast(ctx.?));
        if (self.in_flight.contains(key)) return;
        const dup = self.gpa.dupe(u8, key) catch return;
        self.scratch.append(self.gpa, dup) catch self.gpa.free(dup);
    }

    /// Begin flushing `key` (idempotent w.r.t. in-flight): lease its oldest WAL
    /// record and submit it.
    fn startKey(self: *Coordinator, key: []const u8) void {
        if (self.in_flight.contains(key)) return;
        const lease = self.dequeueFor(key) orelse {
            // No WAL record for this key: reconcile stale bookkeeping.
            _ = self.cache.markClean(key);
            self.removeKeySet(&self.orphans, key);
            return;
        };
        self.startFlush(key, lease);
    }

    /// Snapshot `lease` into an owned `FlushTask`, mark the key in flight, and
    /// submit it to the pool. On any failure the lease is returned to the WAL.
    fn startFlush(self: *Coordinator, key: []const u8, lease: jobqueue.Lease) void {
        const task = self.gpa.create(FlushTask) catch {
            self.wal.nack(lease, .{ .backoff_ns = 0 }) catch {};
            return;
        };
        task.* = .{
            .coord = self,
            .op = if (std.mem.eql(u8, lease.job_type, "del")) .del else .put,
            .key = self.gpa.dupe(u8, key) catch {
                self.gpa.destroy(task);
                self.wal.nack(lease, .{ .backoff_ns = 0 }) catch {};
                return;
            },
            .value = self.gpa.dupe(u8, lease.payload) catch {
                self.gpa.free(task.key);
                self.gpa.destroy(task);
                self.wal.nack(lease, .{ .backoff_ns = 0 }) catch {};
                return;
            },
            .lease = lease,
        };
        self.addKeySet(&self.in_flight, key) catch {
            self.freeTask(task);
            self.wal.nack(lease, .{ .backoff_ns = 0 }) catch {};
            return;
        };
        self.pool.submit(.{ .func = flushEntry, .ctx = task }) catch {
            self.removeKeySet(&self.in_flight, key);
            self.freeTask(task);
            self.wal.nack(lease, .{ .backoff_ns = 0 }) catch {};
        };
    }

    /// Synchronously flush the single oldest queued WAL record (any key) on the
    /// coordinator thread. A `flushAll` backstop for records not reachable via
    /// the cache. Returns true if a record was flushed.
    fn flushOneSync(self: *Coordinator) bool {
        const lease = (self.wal.dequeue(.{ .visibility_timeout_ns = vis_timeout_ns }) catch null) orelse
            return false;
        const op: Op = if (std.mem.eql(u8, lease.job_type, "del")) .del else .put;
        const res = switch (op) {
            .put => self.sink.write(lease.partition, lease.payload),
            .del => self.sink.delete(lease.partition),
        };
        if (res) |_| {
            self.wal.ack(lease) catch {};
            if (self.unflushed > 0) self.unflushed -= 1;
            if (self.dequeueFor(lease.partition) == null) {
                _ = self.cache.markClean(lease.partition);
                self.removeKeySet(&self.orphans, lease.partition);
            }
            return true;
        } else |_| {
            self.wal.nack(lease, .{ .backoff_ns = 0 }) catch {};
            return false;
        }
    }

    fn dequeueFor(self: *Coordinator, key: []const u8) ?jobqueue.Lease {
        return self.wal.dequeue(.{
            .partition = key,
            .visibility_timeout_ns = vis_timeout_ns,
        }) catch null;
    }

    /// The `ramcache` eviction hook: a dirty entry leaving the cache still has a
    /// durable WAL record, so register it as an orphan for the flusher. This is
    /// the synchronous safety net — a write is never dropped by an eviction that
    /// races the flusher. Runs on the coordinator thread (from `cache.put`/`get`).
    fn onEvict(
        ctx: ?*anyopaque,
        key: []const u8,
        value: []const u8,
        dirty: bool,
        reason: ramcache.EvictReason,
    ) void {
        _ = value;
        _ = reason;
        if (!dirty) return;
        const self: *Coordinator = @ptrCast(@alignCast(ctx.?));
        self.addKeySet(&self.orphans, key) catch {};
    }

    fn freeTask(self: *Coordinator, t: *FlushTask) void {
        self.gpa.free(t.key);
        self.gpa.free(t.value);
        self.gpa.destroy(t);
    }

    /// Drop (free) any completion tasks still queued (crash-teardown path).
    fn drainCompletionTasks(self: *Coordinator) void {
        self.completion_lock.lock();
        var chain = self.completion_head;
        self.completion_head = null;
        self.completion_lock.unlock();
        while (chain) |t| {
            const nxt = t.next;
            self.freeTask(t);
            chain = nxt;
        }
    }

    // owned-key-set helpers
    fn addKeySet(self: *Coordinator, m: *std.StringHashMapUnmanaged(void), key: []const u8) !void {
        if (m.contains(key)) return;
        const dup = try self.gpa.dupe(u8, key);
        errdefer self.gpa.free(dup);
        try m.put(self.gpa, dup, {});
    }
    fn removeKeySet(self: *Coordinator, m: *std.StringHashMapUnmanaged(void), key: []const u8) void {
        if (m.fetchRemove(key)) |kv| self.gpa.free(kv.key);
    }
    fn freeKeySet(self: *Coordinator, m: *std.StringHashMapUnmanaged(void)) void {
        var it = m.keyIterator();
        while (it.next()) |k| self.gpa.free(k.*);
        m.deinit(self.gpa);
    }
    fn addTombstone(self: *Coordinator, key: []const u8) !void {
        return self.addKeySet(&self.tombstones, key);
    }
    fn dropTombstone(self: *Coordinator, key: []const u8) void {
        self.removeKeySet(&self.tombstones, key);
    }
};

/// The worker-thread flush body: write the snapshot to the sink, record the
/// outcome, and hand the task back to the coordinator via the completion list.
/// Touches ONLY the sink and the completion channel — never the cache or WAL.
fn flushEntry(ctx: *anyopaque) void {
    const task: *FlushTask = @ptrCast(@alignCast(ctx));
    const c = task.coord;
    const res = switch (task.op) {
        .put => c.sink.write(task.key, task.value),
        .del => c.sink.delete(task.key),
    };
    task.ok = if (res) |_| true else |_| false;

    c.completion_lock.lock();
    task.next = c.completion_head;
    c.completion_head = task;
    c.completion_lock.unlock();

    _ = c.completion_gen.fetchAdd(1, .release);
    c.io.futexWake(u32, &c.completion_gen.raw, std.math.maxInt(u32));
}

fn mapWalErr(e: anyerror) PutError {
    return switch (e) {
        error.FieldTooLarge => error.KeyTooLarge,
        error.PayloadTooLarge => error.ValueTooLarge,
        error.OutOfMemory => error.OutOfMemory,
        else => error.WalWriteFailed,
    };
}

// ── tests ────────────────────────────────────────────────────────────────────
//
// Real threads (via the worker pool) throughout. Deterministic where it matters:
// the WAL clocks are the OS defaults but only `delay = 0` visibility is used, so
// timing never affects an assertion. `testing.allocator` is a DebugAllocator, so
// every test also proves no leak / double-free across the full lifecycle. Run
// under both Debug and ReleaseFast (`zig build test-writebehind [-Doptimize=ReleaseFast]`).

const testing = std.testing;

/// A test rig: an `Io`, an in-memory `MapSink`, and a `SimStorage` for the WAL,
/// all torn down together. `wal_sim` outlives a reopen so crash-recovery over a
/// simulated durable log can be exercised.
const Rig = struct {
    threaded: std.Io.Threaded,
    sink: MapSink,
    wal_sim: SimStorage,

    fn init(rig: *Rig) void {
        rig.* = .{
            .threaded = std.Io.Threaded.init(testing.allocator, .{}),
            .sink = MapSink.init(testing.allocator),
            .wal_sim = SimStorage.init(testing.allocator),
        };
    }
    fn deinit(rig: *Rig) void {
        rig.wal_sim.deinit();
        rig.sink.deinit();
        rig.threaded.deinit();
    }
    fn open(rig: *Rig, n_workers: usize) !*Coordinator {
        return Coordinator.init(testing.allocator, .{
            .io = rig.threaded.io(),
            .sink = rig.sink.sink(),
            .wal_store = rig.wal_sim.storage(),
            .wal_path = "wal.jq",
            .max_cache_bytes = 1 << 20,
            .max_cache_entries = 1024,
            .n_workers = n_workers,
        });
    }
};

test "basic: put is readable from cache immediately; after flush the sink is consistent" {
    var rig: Rig = undefined;
    rig.init();
    defer rig.deinit();
    var c = try rig.open(4);
    defer c.deinit();

    const n = 200;
    var buf: [24]u8 = undefined;
    var i: usize = 0;
    while (i < n) : (i += 1) {
        const k = try std.fmt.bufPrint(&buf, "k{d}", .{i});
        try c.put(k, "v");
    }
    // Immediately readable from the cache (before any flush).
    i = 0;
    while (i < n) : (i += 1) {
        const k = try std.fmt.bufPrint(&buf, "k{d}", .{i});
        try testing.expectEqualStrings("v", (try c.get(k)).?);
    }
    try testing.expectEqual(@as(usize, n), c.pendingCount());

    c.flushAll();
    try testing.expectEqual(@as(usize, 0), c.pendingCount());
    try testing.expectEqual(@as(usize, 0), c.inFlightCount());

    // Sink now holds every write; the cache is clean.
    try testing.expectEqual(@as(usize, n), rig.sink.count());
    i = 0;
    while (i < n) : (i += 1) {
        const k = try std.fmt.bufPrint(&buf, "k{d}", .{i});
        try testing.expectEqualStrings("v", rig.sink.peek(k).?);
        try testing.expect(!c.cache.isDirty(k));
    }
}

test "last-writer-wins per key: overwrites coalesce to the latest value in the sink" {
    var rig: Rig = undefined;
    rig.init();
    defer rig.deinit();
    var c = try rig.open(4);
    defer c.deinit();

    try c.put("k", "v1");
    try c.put("k", "v2");
    try c.put("k", "v3");
    try testing.expectEqualStrings("v3", (try c.get("k")).?);

    c.flushAll();
    try testing.expectEqualStrings("v3", rig.sink.peek("k").?);
    try testing.expectEqual(@as(usize, 1), rig.sink.count());
}

test "delete: get misses immediately; sink drops the key after flush" {
    var rig: Rig = undefined;
    rig.init();
    defer rig.deinit();
    var c = try rig.open(2);
    defer c.deinit();

    try c.put("a", "1");
    try c.put("b", "2");
    c.flushAll();
    try testing.expectEqual(@as(usize, 2), rig.sink.count());

    try c.del("a");
    try testing.expect((try c.get("a")) == null); // tombstone shadows the cache
    c.flushAll();
    try testing.expect(rig.sink.peek("a") == null); // gone from the sink
    try testing.expectEqualStrings("2", rig.sink.peek("b").?);

    // A later put clears the tombstone.
    try c.put("a", "3");
    try testing.expectEqualStrings("3", (try c.get("a")).?);
}

test "read-through: a cache miss populates from the sink (as a clean entry)" {
    var rig: Rig = undefined;
    rig.init();
    defer rig.deinit();

    // Seed the sink directly (as if written by a prior run), no coordinator yet.
    try rig.sink.sink().write("seeded", "fromsink");

    var c = try rig.open(2);
    defer c.deinit();

    // Not in the cache → read-through fetches it and returns it.
    try testing.expectEqualStrings("fromsink", (try c.get("seeded")).?);
    // Populated as clean: it is not a pending write, so nothing to flush.
    try testing.expect(!c.cache.isDirty("seeded"));
    try testing.expectEqual(@as(usize, 0), c.pendingCount());
}

test "crash recovery: drop the coordinator+cache without flushing; recover replays every acked write" {
    var rig: Rig = undefined;
    rig.init();
    defer rig.deinit();

    const n = 64;
    var buf: [24]u8 = undefined;

    // Phase 1: put N keys, then SIMULATE A CRASH — tear down without flushing.
    // Only the durable WAL (rig.wal_sim) survives; the sink got nothing.
    {
        var c = try rig.open(4);
        var i: usize = 0;
        while (i < n) : (i += 1) {
            const k = try std.fmt.bufPrint(&buf, "key{d}", .{i});
            try c.put(k, "payload");
        }
        c.deinitNoFlush(); // crash: no flush, WAL records remain durable
    }
    try testing.expectEqual(@as(usize, 0), rig.sink.count()); // nothing reached the sink

    // Phase 2: a fresh coordinator over the SAME durable WAL replays it.
    var c2 = try rig.open(4);
    defer c2.deinit();
    try testing.expectEqual(@as(usize, n), c2.pendingCount()); // reopened WAL carries them
    try c2.recover();

    // Every acknowledged write is now in the sink — nothing lost.
    try testing.expectEqual(@as(usize, n), rig.sink.count());
    var i: usize = 0;
    while (i < n) : (i += 1) {
        const k = try std.fmt.bufPrint(&buf, "key{d}", .{i});
        try testing.expectEqualStrings("payload", rig.sink.peek(k).?);
    }

    // Idempotent under double recovery: the WAL is already drained.
    try c2.recover();
    try testing.expectEqual(@as(usize, n), rig.sink.count());
    try testing.expectEqual(@as(usize, 0), c2.pendingCount());
}

test "crash recovery preserves last-writer-wins across overwrites" {
    var rig: Rig = undefined;
    rig.init();
    defer rig.deinit();
    {
        var c = try rig.open(2);
        try c.put("k", "old");
        try c.put("k", "new"); // two WAL records for k
        try c.del("gone"); // a delete of a never-flushed key
        try c.put("gone", "back"); // ...then recreated
        c.deinitNoFlush();
    }
    var c2 = try rig.open(2);
    defer c2.deinit();
    try c2.recover();
    try testing.expectEqualStrings("new", rig.sink.peek("k").?);
    try testing.expectEqualStrings("back", rig.sink.peek("gone").?);
}

test "on_evict safety net: a dirty entry evicted before flush is still persisted" {
    var rig: Rig = undefined;
    rig.init();
    defer rig.deinit();

    // Tiny cache (2 entries) so a third dirty put evicts an earlier dirty one
    // before it can be flushed — the on_evict path must not lose it.
    var c = try Coordinator.init(testing.allocator, .{
        .io = rig.threaded.io(),
        .sink = rig.sink.sink(),
        .wal_store = rig.wal_sim.storage(),
        .wal_path = "wal.jq",
        .max_cache_bytes = 1 << 20,
        .max_cache_entries = 2,
        .n_workers = 2,
    });
    defer c.deinit();

    try c.put("a", "1");
    try c.put("b", "2");
    try c.put("cc", "3"); // over capacity → an earlier dirty entry is evicted here

    // CONTROL: the hook actually fired and registered the evicted key. Without
    // this the test cannot fail when `on_evict` is a no-op — `flushAll`'s
    // `flushOneSync` backstop drains any leftover WAL record regardless of the
    // orphan bookkeeping, so the sink ends up correct either way.
    try testing.expect(c.orphans.count() >= 1);
    // The orphan is a key that is no longer resident in the cache: it can only
    // be reached by the flusher via the on_evict safety net.
    {
        var it = c.orphans.keyIterator();
        const orphan = it.next().?.*;
        try testing.expect(!c.cache.isDirty(orphan)); // gone from the cache entirely
    }

    // Whichever entry was evicted fired on_evict(dirty) → orphan; its WAL record
    // is still durable. flushAll must persist all three, none silently dropped.
    c.flushAll();
    try testing.expectEqual(@as(usize, 0), c.pendingCount());
    try testing.expectEqual(@as(usize, 3), rig.sink.count());
    try testing.expectEqualStrings("1", rig.sink.peek("a").?);
    try testing.expectEqualStrings("2", rig.sink.peek("b").?);
    try testing.expectEqualStrings("3", rig.sink.peek("cc").?);
}

test "on_evict safety net: the evicted entry reaches the sink via drain() ALONE (no flushAll backstop)" {
    var rig: Rig = undefined;
    rig.init();
    defer rig.deinit();

    var c = try Coordinator.init(testing.allocator, .{
        .io = rig.threaded.io(),
        .sink = rig.sink.sink(),
        .wal_store = rig.wal_sim.storage(),
        .wal_path = "wal.jq",
        .max_cache_bytes = 1 << 20,
        .max_cache_entries = 2,
        .n_workers = 2,
    });
    defer c.deinit();

    try c.put("a", "1");
    try c.put("b", "2");
    try c.put("cc", "3"); // over capacity → one dirty entry is evicted here

    // `flushAll` would mask a broken safety net: its `flushOneSync` backstop
    // drains ANY leftover WAL record, including one no bookkeeping selected.
    // `drain()` has no such backstop — `kick` can only reach a key that is no
    // longer resident in the cache through the orphan set `on_evict` fills, so
    // this loop persists all three ONLY if the safety net works.
    var spins: usize = 0;
    while (c.pendingCount() > 0 and spins < 100_000) : (spins += 1) c.drain();

    try testing.expectEqual(@as(usize, 0), c.pendingCount());
    try testing.expectEqual(@as(usize, 3), rig.sink.count());
    try testing.expectEqualStrings("1", rig.sink.peek("a").?);
    try testing.expectEqualStrings("2", rig.sink.peek("b").?);
    try testing.expectEqualStrings("3", rig.sink.peek("cc").?);
}

test "concurrency: many keys flush via the pool; drain-loop reaches a clean state, no leak" {
    var rig: Rig = undefined;
    rig.init();
    defer rig.deinit();
    var c = try rig.open(6);
    defer c.deinit();

    const n = 1000;
    var buf: [24]u8 = undefined;
    var i: usize = 0;
    while (i < n) : (i += 1) {
        const k = try std.fmt.bufPrint(&buf, "item-{d}", .{i});
        try c.put(k, "x");
        if (i % 64 == 0) c.drain(); // interleave flush passes with writes
    }
    c.flushAll();

    try testing.expectEqual(@as(usize, 0), c.pendingCount());
    try testing.expectEqual(@as(usize, 0), c.inFlightCount());
    try testing.expectEqual(@as(usize, n), rig.sink.count());
    try testing.expect(c.pool.completedCount() > 0); // the pool actually did the work
}

test "kvtree reference sink: put → flush lands in a real durable kvtree, survives across recover" {
    var tmp = testing.tmpDir(.{});
    defer tmp.cleanup();

    var threaded = std.Io.Threaded.init(testing.allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();

    // The sink is a real on-disk kvtree; the WAL is a real on-disk jobqueue —
    // both in the tmp dir, each on its own FsStorage.
    var wal_fs = FsStorage.init(io, tmp.dir);

    const n = 40;
    var buf: [24]u8 = undefined;

    // Phase 1: write, then crash (no flush). The kvtree sink stays empty.
    {
        var sink_fs = FsStorage.init(io, tmp.dir);
        var sink_db = try kvtree.Db.open(testing.allocator, sink_fs.storage(), "sink.kvt", .{});
        var ksink = KvtreeSink.init(testing.allocator, &sink_db);

        var c = try Coordinator.init(testing.allocator, .{
            .io = io,
            .sink = ksink.sink(),
            .wal_store = wal_fs.storage(),
            .wal_path = "wal.jq",
            .max_cache_bytes = 1 << 20,
            .max_cache_entries = 1024,
            .n_workers = 3,
        });
        var i: usize = 0;
        while (i < n) : (i += 1) {
            const k = try std.fmt.bufPrint(&buf, "row{d}", .{i});
            try c.put(k, "durable");
        }
        c.deinitNoFlush();
        sink_db.close();
    }

    // Phase 2: reopen the durable WAL + the (empty) durable sink; recover.
    var wal_fs2 = FsStorage.init(io, tmp.dir);
    var sink_fs2 = FsStorage.init(io, tmp.dir);
    var sink_db2 = try kvtree.Db.open(testing.allocator, sink_fs2.storage(), "sink.kvt", .{});
    defer sink_db2.close();
    var ksink2 = KvtreeSink.init(testing.allocator, &sink_db2);

    var c2 = try Coordinator.init(testing.allocator, .{
        .io = io,
        .sink = ksink2.sink(),
        .wal_store = wal_fs2.storage(),
        .wal_path = "wal.jq",
        .max_cache_bytes = 1 << 20,
        .max_cache_entries = 1024,
        .n_workers = 3,
    });
    defer c2.deinit();

    try c2.recover();

    // Every acked write is now in the durable kvtree sink.
    var i: usize = 0;
    while (i < n) : (i += 1) {
        const k = try std.fmt.bufPrint(&buf, "row{d}", .{i});
        const got = try sink_db2.get(testing.allocator, k);
        defer if (got) |g| testing.allocator.free(g);
        try testing.expect(got != null);
        try testing.expectEqualStrings("durable", got.?);
    }
}

test "flushAll on a fresh reopened WAL drains pending records even without recover()" {
    var rig: Rig = undefined;
    rig.init();
    defer rig.deinit();
    {
        var c = try rig.open(2);
        try c.put("p", "1");
        try c.put("q", "2");
        c.deinitNoFlush(); // WAL keeps both
    }
    // A new coordinator; the operator forgot recover() and just flushes — the
    // flushOneSync backstop still drains the reopened WAL, losing nothing.
    var c2 = try rig.open(2);
    defer c2.deinit();
    try testing.expectEqual(@as(usize, 2), c2.pendingCount());
    c2.flushAll();
    try testing.expectEqual(@as(usize, 0), c2.pendingCount());
    try testing.expectEqualStrings("1", rig.sink.peek("p").?);
    try testing.expectEqualStrings("2", rig.sink.peek("q").?);
}

test "oversized key / value are rejected before any durable write" {
    var rig: Rig = undefined;
    rig.init();
    defer rig.deinit();
    var c = try rig.open(1);
    defer c.deinit();

    const big_key = "x" ** (jobqueue.max_field_len + 1);
    try testing.expectError(error.KeyTooLarge, c.put(big_key, "v"));
    try testing.expectEqual(@as(usize, 0), c.pendingCount()); // nothing enqueued
}

test "meta is well-formed" {
    try testing.expect(meta.platform == .posix);
    try testing.expect(meta.concurrency == .single_owner);
    try testing.expectEqual(@as(usize, 4), meta.deps.len);
}
