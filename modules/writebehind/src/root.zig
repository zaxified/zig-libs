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
//!   * **A rejecting sink costs liveness, not data.** A failed sink write is
//!     returned to the WAL and retried forever by default, so the durability
//!     guarantee above holds against a sink that is down, full, or refusing:
//!     `flushAll` keeps retrying until `Options.flush_timeout_ns` and then
//!     reports `error.FlushIncomplete`, and the record survives a crash either
//!     way. Only an explicit `max_flush_attempts` cap trades
//!     that for dropping poison records, and a dropped record is counted
//!     (`poisonedCount`) and inspectable (`poisoned`).
//!
//!     This is the one guarantee the module shipped without: the WAL was
//!     enqueued at `jobqueue`'s default `max_attempts` of 5, so the sixth
//!     rejection dead-lettered an acknowledged write, no caller was told, and
//!     `flushAll` then waited on a record that could never be dispatched. The
//!     reference sinks never fail, so nothing noticed.
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
//! the coordinator thread. `deinit` first runs `flushAll` and only *then*
//! calls `pool.drain()`, both on the coordinator thread, so nothing can submit
//! while the pool drains: producers are quiesced before the lifecycle call
//! (when `flushAll` gave up at its deadline, `pool.drain()` waits for the
//! flushes still running). `max_submitters = 0`: only the shared, spinlock-serialized `submit`
//! path is used, never a `Submitter` handle.

const std = @import("std");
const Allocator = std.mem.Allocator;

const ramcache = @import("ramcache");
const workerpool = @import("workerpool");
const jobqueue = @import("jobqueue");
const kvtree = @import("kvtree");

pub const meta = .{
    // The module catalog's one-line entry. This IS the source of truth:
    // README.md's table is rendered from it by `zig build gen-catalog`.
    .doc = "Crash-safe write-behind cache coordinator — fast in-memory acks, async flush to a durable `Sink` via `workerpool`; WAL written before ack so a crash-recovered write survives",
    // The catalog's Platform cell. Prose, because it carries nuance the
    // `platform` enum below cannot -- "any (packer: linux)", "amd64 asm +
    // portable fallback". Rendered by `gen-catalog` alongside `doc`.
    .platform_note = "any",
    // `jobqueue`'s default wall/monotonic clocks use posix `clock_gettime`
    // (both injectable); everything else is portable.
    .targets = .{.linux64},
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
/// its storage). Serializes all sink ops with `kvtree.Lock`, since `kvtree` is
/// single-writer and the coordinator flushes concurrently.
pub const KvtreeSink = struct {
    db: *kvtree.Db,
    gpa: Allocator,
    /// Held across `kvtree` writes (page writes and an fsync): an
    /// `std.Io.Mutex` when the `Db`'s storage has an `Io`, so a flush task
    /// waiting for it yields instead of spinning.
    lock: kvtree.Lock,

    pub fn init(gpa: Allocator, db: *kvtree.Db) KvtreeSink {
        return .{ .db = db, .gpa = gpa, .lock = .{ .io = db.io() } };
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
        self.lock.acquire();
        defer self.lock.release();
        try self.db.put(key, value);
    }
    fn vDelete(ptr: *anyopaque, key: []const u8) anyerror!void {
        const self = cast(ptr);
        self.lock.acquire();
        defer self.lock.release();
        try self.db.del(key);
    }
    fn vRead(ptr: *anyopaque, gpa: Allocator, key: []const u8) anyerror!?[]u8 {
        const self = cast(ptr);
        self.lock.acquire();
        defer self.lock.release();
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
    /// How long a key waits after a *failed* sink write before its record is
    /// retried (ns on `wal_mono_clock`). Default 0 = retry on the next drain
    /// with no delay. The wait is kept in memory per key, not in the WAL: the
    /// record goes back to the WAL visible at once, so it stays the oldest of
    /// its key and a newer write to that key cannot overtake it (a WAL-side
    /// backoff hid it, the newer record flushed first and the retried older
    /// one then overwrote it). The key's later records wait behind it. After a
    /// restart the record is retried without delay (Kafka's `retry.backoff.ms`
    /// is in-memory too).
    retry_backoff_ns: u64 = 0,
    /// How long `flushAll` (and so `sync` and `deinit`) keeps waiting for
    /// pending records -- in-flight flushes, retries after a rejection, a key's
    /// `retry_backoff_ns` -- before it gives up with `error.FlushIncomplete`.
    /// Default 120 s, Kafka's `delivery.timeout.ms` (the bound on how long
    /// `producer.flush()` can wait for a record to be delivered or fail).
    /// 0 = never wait: flush what can be flushed synchronously, then report.
    /// `std.math.maxInt(u64)` = no limit. Records still pending when it gives
    /// up stay durable in the WAL.
    flush_timeout_ns: u64 = 120 * std.time.ns_per_s,
    /// Sink-write attempts before the WAL gives up on a record and dead-letters
    /// it. **0 (the default) = never give up**, which is what the durability
    /// guarantee above requires: an acknowledged `put` stays retryable until the
    /// sink accepts it, so a permanently-failing sink is a liveness problem
    /// (`flushAll` keeps retrying until `flush_timeout_ns`, then returns
    /// `error.FlushIncomplete`) and never a data-loss one.
    ///
    /// Set a finite cap only if you would rather drop a record the sink keeps
    /// rejecting — a "poison" record, e.g. a value that violates a sink-side
    /// constraint — than block that key's queue behind it. A dropped record is
    /// **counted and inspectable** (`poisonedCount` / `poisoned`), never silent;
    /// treat a non-zero count as data loss that has already happened.
    ///
    /// This defaulted to `jobqueue`'s own `max_attempts` of 5 until 2026-07-31,
    /// which silently dropped an acked write after five rejections while the
    /// SPEC promised the opposite.
    ///
    /// Note the shutdown consequence: `deinit` runs `flushAll`, so tearing down
    /// while the sink is refusing blocks for up to `flush_timeout_ns`.
    /// `deinitNoFlush` is the immediate exit — it leaves the WAL durable for
    /// the next process's `recover()`.
    max_flush_attempts: u32 = 0,
    /// High-water mark for back-pressure: the most acknowledged writes that may
    /// wait un-flushed (`pendingCount`) before `put`/`del` stop admitting more.
    /// **0 (the default) = unbounded**, the behaviour before this option
    /// existed. At the mark `put`/`del` drive the flush themselves and wait up
    /// to `put_block_ns` for room, then fail with `error.Backpressure` having
    /// written nothing (Ehcache write-behind `queueSize`: "pending write
    /// operations before applying back pressure"; Kafka producer
    /// `buffer.memory` + `max.block.ms`: block up to a deadline, then a typed
    /// error). Counted in entries; the bytes behind a mark are bounded by
    /// `max_unflushed` x the WAL payload cap.
    max_unflushed: usize = 0,
    /// How long `put`/`del` wait at the high-water mark before returning
    /// `error.Backpressure`. 0 = never wait (one flush pass, then fail).
    /// Default 60 s, Kafka's `max.block.ms`. Ignored while `max_unflushed` is 0.
    put_block_ns: u64 = 60 * std.time.ns_per_s,
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
    /// `Options.max_unflushed` writes are pending and none was flushed within
    /// `Options.put_block_ns`: nothing was written, retry once the sink drains.
    Backpressure,
} || Allocator.Error;

pub const GetError = error{SinkReadFailed} || Allocator.Error;

pub const RecoverError = error{SinkWriteFailed};

pub const FlushError = error{
    /// `Options.flush_timeout_ns` passed with writes still pending
    /// (`pendingCount() > 0`) or flushes still in flight. Nothing is lost:
    /// every pending record is still in the WAL, retried by the next
    /// `drain`/`flushAll` or replayed by `recover()` after a restart.
    FlushIncomplete,
};

const Op = enum { put, del };

/// See `Coordinator.held`.
const Held = struct {
    lease: jobqueue.Lease,
    kind: enum {
        /// A synchronous rejection, returned at the end of the `flushAll` pass.
        rejected,
        /// The `nack` that should have returned it failed: retried by every
        /// `drain`.
        nack_failed,
        /// Written (or superseded by a newer record of the key that was), but
        /// its ack failed or must wait for an older one of the key: the ack is
        /// retried by every `drain`; it is never written again. A key's acks
        /// go strictly oldest first, so a restart can never replay an older
        /// record over a newer one that was already acked.
        ack_failed,
        /// Passed over by the synchronous path because its key waits out a
        /// retry backoff, and `jobqueue`'s `release` (which counts no
        /// attempt) failed: the release is retried by every `drain`.
        release_failed,
    },
};

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
    /// `Options.flush_timeout_ns`.
    flush_timeout_ns: u64,
    /// `Options.wal_mono_clock`: the clock of the per-key retry wait.
    mono: jobqueue.MonoClock,
    /// `jobqueue`'s `max_attempts` for every WAL record we enqueue; `maxInt`
    /// when `Options.max_flush_attempts` is 0 (the default), i.e. never
    /// dead-letter.
    wal_max_attempts: u32,
    /// `Options.max_unflushed` / `Options.put_block_ns`.
    max_unflushed: usize,
    put_block_ns: u64,

    /// Records the WAL gave up on (dead-lettered) because the sink kept
    /// rejecting them. Only ever non-zero when a finite `max_flush_attempts`
    /// was configured. Each one is an acknowledged write that will never reach
    /// the sink.
    n_poisoned: usize = 0,

    /// Orphan registrations `onEvict` could not record because `addKeySet`
    /// hit OOM (F3). The record stays fully durable in the WAL either way —
    /// `unflushed`/`flushAll`'s WAL-rescan backstop (`flushOneSync`, driven
    /// off `self.unflushed`, not the orphan set) does not depend on this
    /// bookkeeping — but the key drops out of the periodic `drain()`/`kick()`
    /// polling path (the exact F1 non-admission shape) until something else
    /// touches it. Non-zero means: call `flushAll`/`sync` to force the
    /// WAL-rescan reconciliation rather than relying on periodic `drain()`.
    n_dropped_orphans: usize = 0,

    /// Un-acked WAL records (== writes not yet known-durable in the sink).
    /// Coordinator-thread-only. `flushAll`/`deinit` block until this is 0.
    unflushed: usize = 0,

    /// Keys with a flush currently in flight (single-flight per key → per-key
    /// ordering → LWW), each with the task submitted for it (so a teardown
    /// that drops queued jobs can free their tasks). Owns its key strings.
    in_flight: std.StringHashMapUnmanaged(*FlushTask) = .empty,
    /// Dirty keys evicted from the cache before being flushed (the `on_evict`
    /// safety net): their WAL records are still durable, so the flusher must
    /// revisit them even though the cache no longer lists them dirty. Owns keys.
    orphans: std.StringHashMapUnmanaged(void) = .empty,
    /// Keys deleted but possibly still cached — `get` returns `null` for these
    /// so a `del` is visible immediately. Cleared by a later `put`. Owns keys.
    tombstones: std.StringHashMapUnmanaged(void) = .empty,
    /// Keys whose last flush failed, each with the `mono` time before which it
    /// is not retried (`retry_backoff_ns`). Their record is back in the WAL and
    /// visible; this is what holds them (and every later record of the key)
    /// back. An entry past its time is dropped when the key is next selected.
    /// Owns keys.
    retry_at: std.StringHashMapUnmanaged(u64) = .empty,
    /// Leases this coordinator still holds (the records are leased, so
    /// invisible to every dequeue): synchronous rejections kept for the rest
    /// of a `flushAll` pass, records whose `nack` failed, and records whose
    /// `ack` failed or waits for an older one. While a key has an entry here,
    /// `startKey` leaves it alone; a newer record of it that the synchronous
    /// path writes supersedes the held ones (they are acked, never retried
    /// over it). Oldest first per key. Every entry is still counted in
    /// `unflushed`.
    held: std.ArrayList(Held) = .empty,
    /// Leases the synchronous path took for keys waiting out their retry
    /// backoff, to reach the next record of another key. Only non-empty
    /// inside `syncFlush`, which hands each back with `jobqueue`'s `release`
    /// (no attempt counted) before it returns.
    skipped: std.ArrayList(jobqueue.Lease) = .empty,
    /// Set by `deinit`/`deinitNoFlush` before their last harvest: a key that
    /// the harvest advances is not dispatched any more. Its lease is simply
    /// left (in-memory only), so the record stays in the WAL with no attempt
    /// counted -- a `nack` on the stopped pool's refusal would burn one and,
    /// with a finite `max_flush_attempts`, dead-letter records the sink
    /// never saw.
    no_dispatch: bool = false,
    /// Scratch list of duped keys collected from `drainDirty`/`orphans`.
    /// The strings themselves are arena-allocated (`scratch_arena`) — every
    /// consumer of `scratch.items` (`startKey`/`addKeySet`/`startFlush`)
    /// dupes what it needs to keep, so a whole-arena `reset` after each
    /// `kick()` is exactly as safe as freeing each string individually was,
    /// and avoids a general-purpose alloc+free pair per key on every tick.
    scratch: std.ArrayList([]u8) = .empty,
    scratch_arena: std.heap.ArenaAllocator = undefined,

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
            .flush_timeout_ns = options.flush_timeout_ns,
            .mono = options.wal_mono_clock,
            .wal_max_attempts = if (options.max_flush_attempts == 0)
                std.math.maxInt(u32)
            else
                options.max_flush_attempts,
            .max_unflushed = options.max_unflushed,
            .put_block_ns = options.put_block_ns,
            .scratch_arena = std.heap.ArenaAllocator.init(gpa),
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
    /// contract (see the module doc). Blocks until the cache is clean or
    /// `Options.flush_timeout_ns` passes (a sink that is down holds it that
    /// long; `deinitNoFlush` exits at once). What is still pending then stays
    /// durable in the WAL for the next process's `recover()`.
    pub fn deinit(self: *Coordinator) void {
        // Gave up at the deadline: the rest stays in the WAL (see above).
        self.flushAll() catch {};
        self.pool.drain(); // producers quiesced → safe lifecycle call; waits for running flushes
        self.no_dispatch = true;
        self.pump(); // harvest the flushes that were still running (none after a complete flushAll)
        self.pool.deinit();
        self.wal.close();
        self.cache.deinit();
        self.freeInFlight();
        self.freeKeySet(&self.orphans);
        self.freeKeySet(&self.tombstones);
        self.freeRetry();
        // Leases still held stay in the WAL (a lease is in-memory only).
        self.held.deinit(self.gpa);
        self.skipped.deinit(self.gpa);
        self.scratch.deinit(self.gpa);
        self.scratch_arena.deinit();
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
        // Harvest the flushes that completed: ack them. This runs BEFORE
        // `pool.deinit`, because acking a key can advance it to its next record
        // and `startFlush` then calls `pool.submit` -- which a stopped pool
        // refuses (the record goes back to the WAL), but a freed one would be a
        // use-after-free.
        self.no_dispatch = true;
        self.pump();
        self.drainCompletionTasks();
        self.pool.deinit();
        self.wal.close();
        self.cache.deinit();
        // What is still in flight now is a job `shutdownNow` dropped unrun: its
        // task was never handed back, so free it here (its WAL record stays
        // durable for the next process's `recover()`).
        self.freeInFlight();
        self.freeKeySet(&self.orphans);
        self.freeKeySet(&self.tombstones);
        self.freeRetry();
        // Leases still held stay in the WAL (a lease is in-memory only).
        self.held.deinit(self.gpa);
        self.skipped.deinit(self.gpa);
        self.scratch.deinit(self.gpa);
        self.scratch_arena.deinit();
        const gpa = self.gpa;
        gpa.destroy(self);
    }

    // ── write path ──────────────────────────────────────────────────────────

    /// Buffer a write: durably append it to the WAL (crash-safety anchor),
    /// stage it in the cache (dirty), and return — the caller sees a fast ack.
    /// The value is durable when this returns.
    pub fn put(self: *Coordinator, key: []const u8, value: []const u8) PutError!void {
        if (key.len > jobqueue.max_field_len) return error.KeyTooLarge; // before any wait
        try self.awaitCapacity();
        // Durable WAL append FIRST — after this the write survives a crash.
        _ = self.wal.enqueue("put", value, .{
            .partition = key,
            .max_attempts = self.wal_max_attempts,
        }) catch |e| return mapWalErr(e);
        self.unflushed += 1;
        // Stage in the cache (marks the entry dirty). OOM here is non-fatal to
        // durability: the WAL record still drives the flush/recovery.
        self.cache.put(key, value, 0, 0, 0);
        // NON-ADMISSION, not eviction: `ramcache.put` silently refuses any value
        // larger than the whole cache budget (`value.len > max_bytes`) and fires
        // NO `on_evict`, so the key would end up neither cache-dirty nor an
        // orphan — and `kick()`'s only two sources are `drainDirty` and
        // `orphans`. The acked, durable record would then never be selected by
        // the documented periodic `drain()` tick, leaving it pending forever
        // while the WAL grows. Registering the key as an orphan puts it back
        // under the flush loop's ownership; `startKey` reads the value from the
        // WAL lease, not from the cache, so an over-budget value still flushes.
        // (Cheap: `isDirty` is one hash lookup, and the branch is taken only in
        // the non-admission / immediately-evicted cases.)
        if (!self.cache.isDirty(key)) try self.addKeySet(&self.orphans, key);
        // A prior tombstone (delete) for this key is now superseded.
        self.dropTombstone(key);
    }

    /// Durably delete `key`: append a WAL delete record, and shadow the key so
    /// a `get` misses immediately. Eventually removed from the sink by the
    /// flusher / `recover`.
    pub fn del(self: *Coordinator, key: []const u8) PutError!void {
        if (key.len > jobqueue.max_field_len) return error.KeyTooLarge; // before any wait
        try self.awaitCapacity();
        _ = self.wal.enqueue("del", "", .{
            .partition = key,
            .max_attempts = self.wal_max_attempts,
        }) catch |e| return mapWalErr(e);
        self.unflushed += 1;
        // The durable WAL delete record is already written; an OOM below
        // must not be swallowed (F3) — a dropped tombstone would silently
        // un-shadow the deleted key's stale cached value on `get`, the same
        // class of consequence `put`'s own orphan registration below already
        // propagates rather than swallows.
        try self.addTombstone(key);
        // The key's WAL delete record is not tied to a cached dirty entry, so
        // register it as an orphan for the flusher to pick up.
        try self.addKeySet(&self.orphans, key);
    }

    /// Back-pressure: at `max_unflushed` pending writes, drive the flush on this
    /// (the coordinator) thread until one lands or `put_block_ns` passes.
    fn awaitCapacity(self: *Coordinator) PutError!void {
        if (self.max_unflushed == 0 or self.unflushed < self.max_unflushed) return;
        const start = std.Io.Timestamp.now(self.io, .awake).nanoseconds;
        const deadline = start +| @as(i96, self.put_block_ns);
        while (true) {
            self.drain();
            if (self.unflushed < self.max_unflushed) return;
            // Records not reachable through the cache: flush one synchronously,
            // as `flushAll` does, so waiting is never stuck on them.
            if (self.in_flight.count() == 0 and self.flushOneSync()) continue;
            const now = std.Io.Timestamp.now(self.io, .awake).nanoseconds;
            if (now >= deadline) return error.Backpressure;
            const wait_ms: i64 = @intCast(@min(@divTrunc(deadline - now + 999_999, 1_000_000), 20));
            const gen = self.completion_gen.load(.acquire);
            self.io.futexWaitTimeout(u32, &self.completion_gen.raw, gen, .{ .duration = .{
                .raw = .fromMilliseconds(wait_ms),
                .clock = .awake,
            } }) catch {};
        }
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
        // Retry the nacks/acks of held leases first: those that fail in this
        // drain's own harvest wait for the next one.
        if (self.held.items.len > 0) self.releaseHeld(false);
        self.pump();
        self.kick();
    }

    /// Block until the cache is fully clean: every acknowledged write is durable
    /// in the sink and nothing is in flight. Use for graceful shutdown / a
    /// consistency barrier. A rejected write does not end the wait: it is
    /// retried (after `retry_backoff_ns`) like any other, and records whose
    /// write was rejected on the synchronous path do not hold up the others.
    /// The wait is bounded by `Options.flush_timeout_ns`; past it this returns
    /// `error.FlushIncomplete` with the rest still pending in the WAL. Records
    /// the WAL gives up on (a finite `max_flush_attempts`) are done, not
    /// pending: they are counted by `poisonedCount` (Kafka's `flush()` likewise
    /// waits until each record is delivered or has definitively failed).
    pub fn flushAll(self: *Coordinator) FlushError!void {
        const start = std.Io.Timestamp.now(self.io, .awake).nanoseconds;
        const deadline = start +| @as(i96, self.flush_timeout_ns);
        // Synchronous writes the sink rejects in this pass are held (so the
        // next synchronous flush moves on to the next record) and returned to
        // the WAL once nothing else is visible (`releaseHeld`).
        self.drain();
        while (self.unflushed > 0 or self.in_flight.count() > 0) {
            if (self.in_flight.count() == 0) {
                // Records remain but nothing is in flight (e.g. WAL entries from
                // a reopened log whose keys are not cache-dirty). Flush one
                // synchronously to guarantee forward progress, then re-drain.
                // A key waiting out its retry backoff is passed over (its
                // records are released, no attempt counted), so it delays
                // only itself.
                switch (self.syncFlush(true)) {
                    .landed => {
                        self.drain();
                        continue;
                    },
                    .held => continue,
                    .rejected, .none => {},
                }
            }
            // Nothing more to do now: give the rejected records back for a
            // retry, and wait before trying them again.
            self.releaseHeld(true);
            const now = std.Io.Timestamp.now(self.io, .awake).nanoseconds;
            if (now >= deadline) return error.FlushIncomplete;
            // Park until a worker signals a completion (bounded), then re-drain.
            const wait_ms: i64 = @intCast(@min(@divTrunc(deadline - now + 999_999, 1_000_000), 50));
            const gen = self.completion_gen.load(.acquire);
            self.io.futexWaitTimeout(u32, &self.completion_gen.raw, gen, .{ .duration = .{
                .raw = .fromMilliseconds(wait_ms),
                .clock = .awake,
            } }) catch {};
            self.drain();
        }
    }
    /// Alias — a graceful-shutdown / barrier `sync`.
    pub fn sync(self: *Coordinator) FlushError!void {
        return self.flushAll();
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
            var key_buf: [jobqueue.max_field_len]u8 = undefined;
            const key = key_buf[0..lease.partition.len];
            @memcpy(key, lease.partition);
            if (res) |_| {
                _ = self.ackLanded(key, lease);
            } else |_| {
                // Back to the WAL as any failed write is (a dead-lettered one
                // is counted, a retried one waits `retry_backoff_ns`).
                self.flushFailed(key, lease);
                return error.SinkWriteFailed;
            }
        }
    }

    // ── observability ─────────────────────────────────────────────────────────

    /// Count of writes not yet known durable in the sink (un-acked WAL records).
    pub fn pendingCount(self: *const Coordinator) usize {
        return self.unflushed;
    }
    /// Acknowledged writes the WAL gave up on after `max_flush_attempts` sink
    /// rejections. **Always 0 under the default config** (attempts unlimited).
    /// Non-zero means data loss has already happened: those writes were acked
    /// to callers and will never reach the sink. Inspect them with `poisoned`.
    pub fn poisonedCount(self: *const Coordinator) usize {
        return self.n_poisoned;
    }
    /// Count behind `n_dropped_orphans` (F3) — see its doc comment. Durability
    /// is never at risk (the WAL still has the record), but non-zero means a
    /// caller relying solely on periodic `drain()` should call `flushAll`
    /// instead to guarantee those records are reached.
    pub fn droppedOrphanCount(self: *const Coordinator) usize {
        return self.n_dropped_orphans;
    }
    /// The dead-lettered WAL records behind `poisonedCount` — the cache key is
    /// `partition`, the written value `payload`. Every entry is deep-copied
    /// into `gpa`; release the whole snapshot with `freePoisoned` (freeing just
    /// the outer slice leaks three strings per entry).
    pub fn poisoned(self: *Coordinator, gpa: Allocator) ![]jobqueue.DeadLetter {
        return self.wal.deadLetterList(gpa);
    }
    /// Release a `poisoned` snapshot.
    pub fn freePoisoned(gpa: Allocator, list: []jobqueue.DeadLetter) void {
        jobqueue.Queue.freeDeadLetterList(gpa, list);
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
        self.clearInFlight(t.key);
        if (t.ok) {
            if (!self.ackLanded(t.key, t.lease)) {
                // The ack is held for a later drain; the key moves on after it.
                self.addKeySet(&self.orphans, t.key) catch {
                    self.n_dropped_orphans += 1;
                };
                self.freeTask(t);
                return;
            }
            self.clearRetry(t.key);
            // Advance this key: flush its next queued record, if any (keeps
            // per-key ordering). Otherwise the key is fully persisted.
            if (self.dequeueFor(t.key)) |lease2| {
                self.startFlush(t.key, lease2);
            } else {
                _ = self.cache.markClean(t.key);
                self.removeKeySet(&self.orphans, t.key);
                // F2: a durably-applied delete is exactly the point it is safe
                // to garbage-collect its tombstone — the sink no longer has the
                // key, so a future `get` miss (cache-miss + sink read-through)
                // will correctly return null even without the tombstone
                // shadowing it. `cache.remove` MUST run in the same breath as
                // `dropTombstone`: they are the two halves of one atomic-on-
                // this-thread step (Coordinator is `.single_owner` — no other
                // call can interleave here), because a stale cached value from
                // an earlier `put` to this key (its own flush already
                // completed and `markClean`'d it, but nothing ever evicted it)
                // would otherwise be served by `get`'s cache-hit path the
                // instant the tombstone stops shadowing it.
                if (t.op == .del) {
                    _ = self.cache.remove(t.key);
                    self.dropTombstone(t.key);
                }
            }
        } else {
            self.flushFailed(t.key, t.lease);
        }
        self.freeTask(t);
    }

    /// Select every dirty/orphan key not in flight and submit a flush for its
    /// oldest queued WAL record.
    fn kick(self: *Coordinator) void {
        self.scratch.clearRetainingCapacity();
        _ = self.scratch_arena.reset(.retain_capacity);

        // Collect dirty keys (duped — the callback's slices are iteration-scoped
        // and we submit after the sweep). Duped from `scratch_arena`, not `gpa`:
        // a fresh general-purpose alloc+free pair per key, every tick, is real
        // churn a bump-allocated scratch region with one bulk reset avoids.
        self.cache.drainDirty(collectDirty, self);
        // Collect orphan keys.
        var it = self.orphans.keyIterator();
        while (it.next()) |k| {
            if (self.in_flight.contains(k.*)) continue;
            const dup = self.scratch_arena.allocator().dupe(u8, k.*) catch continue;
            self.scratch.append(self.gpa, dup) catch {};
        }

        for (self.scratch.items) |k| self.startKey(k);
        self.scratch.clearRetainingCapacity();
        _ = self.scratch_arena.reset(.retain_capacity);
    }

    fn collectDirty(ctx: ?*anyopaque, key: []const u8, value: []const u8) void {
        _ = value;
        const self: *Coordinator = @ptrCast(@alignCast(ctx.?));
        if (self.in_flight.contains(key)) return;
        const dup = self.scratch_arena.allocator().dupe(u8, key) catch return;
        self.scratch.append(self.gpa, dup) catch {};
    }

    /// Begin flushing `key` (idempotent w.r.t. in-flight): lease its oldest WAL
    /// record and submit it.
    fn startKey(self: *Coordinator, key: []const u8) void {
        if (self.in_flight.contains(key)) return;
        // Waiting out a retry backoff: neither the failed record nor a newer
        // one of this key may go yet. The key stays registered.
        if (self.retryWaiting(key)) return;
        // A failed record of this key is held: it must go back before any
        // newer one of the key can be dequeued.
        if (self.heldFor(key)) return;
        const lease = self.dequeueFor(key) orelse {
            // No WAL record for this key: reconcile stale bookkeeping.
            _ = self.cache.markClean(key);
            self.removeKeySet(&self.orphans, key);
            return;
        };
        self.startFlush(key, lease);
    }

    /// A sink write of `lease` (a record of `key`) failed: return the record to
    /// the WAL for a retry. The key is registered as an orphan, so a later
    /// `drain` re-selects it however it was reached, and it waits
    /// `retry_backoff_ns` first (`retry_at`).
    ///
    /// The record goes back with NO WAL-side backoff. `jobqueue` would move a
    /// backed-off record to its schedule heap, out of its partition's FIFO, and
    /// a newer record of the same key would then be dequeued first -- the
    /// retried older value overwrote it (last-writer-wins broken, also across
    /// a restart, because the WAL persists the backoff). Visible at once, the
    /// record stays its key's oldest; the wait lives in `retry_at`.
    ///
    /// Unless the WAL gave up on it. `nack` dead-letters a record once it has
    /// burned `max_attempts`, and then nothing will ever redeliver it: leaving
    /// `unflushed` incremented would strand `flushAll` (it waits for a record
    /// that can no longer be dispatched) and leave the key dirty forever.
    /// Default config never reaches this — attempts are unlimited — so this
    /// runs only for a caller who asked for a finite cap, and it is counted so
    /// that choice is not silent.
    fn flushFailed(self: *Coordinator, key: []const u8, lease: jobqueue.Lease) void {
        if (self.giveBack(key, lease)) |next| self.startFlush(key, next);
    }

    /// `flushFailed`'s body. Returns the key's next record when this one was
    /// dead-lettered and the key may advance; the caller dispatches it (a loop
    /// in `startFlush`, so a backlog of records that keep failing to dispatch
    /// does not recurse once per record).
    fn giveBack(self: *Coordinator, key: []const u8, lease: jobqueue.Lease) ?jobqueue.Lease {
        const dead_before = self.wal.deadLetterCount();
        self.wal.nack(lease, .{ .backoff_ns = 0 }) catch {
            // The record is still leased to us (a WAL storage or allocation
            // failure). Hold it, so no newer record of the key is dequeued
            // ahead of it, and nack it again on the next `drain`. Should even
            // that list refuse to grow, the record is stranded until a restart
            // (its lease is in-memory only). The nack that succeeds later
            // registers the key again.
            self.held.append(self.gpa, .{ .lease = lease, .kind = .nack_failed }) catch {};
            return null;
        };
        if (self.wal.deadLetterCount() > dead_before) {
            self.n_poisoned += 1;
            if (self.unflushed > 0) self.unflushed -= 1;
            self.clearRetry(key);
            // A held record of this key is older than anything `dequeueFor`
            // would return: the key advances when that one is released.
            if (self.heldFor(key)) return null;
            // Same key-advance as the success path: a later record for this
            // key is still good and must not be stranded behind the dropped
            // one (it is also newer, so LWW is unaffected).
            if (self.dequeueFor(key)) |lease2| {
                return lease2;
            } else {
                _ = self.cache.markClean(key);
                self.removeKeySet(&self.orphans, key);
                // Deliberately NOT the F2 tombstone-GC step of `finishTask`: a
                // dead-lettered delete never actually reached the sink (that is
                // what `poisonedCount`/`n_poisoned` mean), so the sink still
                // holds the pre-delete value. Dropping the tombstone here would
                // let a later `get` read-through straight to that stale value —
                // the tombstone must outlive a poisoned delete forever, which
                // is the conservative side of the data loss `poisonedCount`
                // already documents.
            }
            return null;
        }
        // Can't fail the caller here: count a lost registration as `onEvict`
        // does (the record is in the WAL; `flushAll` still reaches it).
        self.addKeySet(&self.orphans, key) catch {
            self.n_dropped_orphans += 1;
        };
        if (self.retry_backoff_ns > 0) {
            // On OOM the key is simply retried without the wait.
            self.setRetry(key, self.mono.now() +| self.retry_backoff_ns) catch {};
        }
        return null;
    }

    /// Snapshot `lease` into an owned `FlushTask`, mark the key in flight, and
    /// submit it to the pool. On any failure the lease is returned to the WAL.
    fn startFlush(self: *Coordinator, key: []const u8, first: jobqueue.Lease) void {
        if (self.no_dispatch) return;
        // A failed dispatch returns the lease like a failed write: the `nack`
        // counts as an attempt, so with a finite `max_flush_attempts` it can
        // dead-letter the record, which must be counted and the key advanced
        // (a bare `nack` left `unflushed` waiting for it forever). The advance
        // is dispatched by this loop, not by recursion.
        var lease = first;
        while (!self.submitFlush(key, lease)) {
            lease = self.giveBack(key, lease) orelse return;
        }
    }

    /// Snapshot `lease` into an owned `FlushTask`, mark the key in flight and
    /// submit it. False (with the lease untouched and nothing left behind)
    /// when an allocation fails or the pool refuses the job.
    fn submitFlush(self: *Coordinator, key: []const u8, lease: jobqueue.Lease) bool {
        const task = self.gpa.create(FlushTask) catch return false;
        task.* = .{
            .coord = self,
            .op = if (std.mem.eql(u8, lease.job_type, "del")) .del else .put,
            .key = self.gpa.dupe(u8, key) catch {
                self.gpa.destroy(task);
                return false;
            },
            .value = self.gpa.dupe(u8, lease.payload) catch {
                self.gpa.free(task.key);
                self.gpa.destroy(task);
                return false;
            },
            .lease = lease,
        };
        self.markInFlight(key, task) catch {
            self.freeTask(task);
            return false;
        };
        self.pool.submit(.{ .func = flushEntry, .ctx = task }) catch {
            self.clearInFlight(key);
            self.freeTask(task);
            return false;
        };
        return true;
    }

    /// Synchronously flush the single oldest queued WAL record (any key) on the
    /// coordinator thread. A `flushAll` backstop for records not reachable via
    /// the cache. Returns true if a record was flushed; a rejected record goes
    /// back to the WAL for a retry (`flushFailed`).
    fn flushOneSync(self: *Coordinator) bool {
        return self.syncFlush(false) == .landed;
    }

    const SyncResult = enum {
        /// A record was written and acked.
        landed,
        /// The sink rejected a record; its lease is in `held` (not visible to
        /// the next dequeue until `releaseHeld`).
        held,
        /// The sink rejected a record; it went back to the WAL.
        rejected,
        /// No record is visible.
        none,
    };

    /// `flushOneSync`'s body. With `hold`, a rejected record's lease is kept in
    /// `held`, so the caller's next call moves on to the next record instead
    /// of retrying this one at once.
    ///
    /// The oldest record of a key that waits out its retry backoff
    /// (`retry_at`) is not written early: its lease is kept in `skipped`
    /// while the global dequeue moves on to the next record, and every such
    /// lease is handed back (`jobqueue.release`, no attempt counted, its
    /// place in the key's FIFO kept) before this returns. So one waiting key
    /// no longer stalls the backstop for all keys (F5b). Skipped records are
    /// neither written nor acked, so the per-key ack order is untouched: the
    /// record that is written belongs to a key that is not waiting, it is the
    /// oldest of its key still in the WAL (the dequeue is FIFO per key), and
    /// any older one of its key is held, where `ackLanded` orders the acks.
    fn syncFlush(self: *Coordinator, hold: bool) SyncResult {
        defer self.releaseSkipped();
        const lease = while (true) {
            const l = (self.wal.dequeue(.{ .visibility_timeout_ns = vis_timeout_ns }) catch null) orelse
                return .none;
            if (!self.retryWaiting(l.partition)) break l;
            self.skipped.append(self.gpa, l) catch {
                // No room to pass it over: give it back and stop this pass.
                self.releaseOne(l);
                return .none;
            };
        };
        const op: Op = if (std.mem.eql(u8, lease.job_type, "del")) .del else .put;
        const res = switch (op) {
            .put => self.sink.write(lease.partition, lease.payload),
            .del => self.sink.delete(lease.partition),
        };
        // `ack`/`nack` may free the lease's borrowed fields: copy the key out first.
        var key_buf: [jobqueue.max_field_len]u8 = undefined;
        const key = key_buf[0..lease.partition.len];
        @memcpy(key, lease.partition);
        if (res) |_| {
            if (!self.ackLanded(key, lease)) {
                self.addKeySet(&self.orphans, key) catch {
                    self.n_dropped_orphans += 1;
                };
                return .landed;
            }
            self.clearRetry(key);
            // Advance the key as `finishTask` does: its next record goes to the
            // pool. (Leasing it and dropping the lease hid it for the whole
            // visibility timeout, and `flushAll` stopped with it pending.)
            if (self.dequeueFor(key)) |lease2| {
                self.startFlush(key, lease2);
            } else {
                _ = self.cache.markClean(key);
                self.removeKeySet(&self.orphans, key);
            }
            return .landed;
        } else |_| {
            if (hold) {
                if (self.held.append(self.gpa, .{ .lease = lease, .kind = .rejected })) |_| return .held else |_| {}
            }
            self.flushFailed(key, lease);
            return .rejected;
        }
    }

    /// Hand back every lease `syncFlush` passed over.
    fn releaseSkipped(self: *Coordinator) void {
        for (self.skipped.items) |l| self.releaseOne(l);
        self.skipped.clearRetainingCapacity();
    }

    /// Return a passed-over lease to the WAL with no attempt counted. When
    /// `release` fails (an allocation failure inside `jobqueue`), hold it, so
    /// no newer record of its key is dequeued ahead of it, and retry on the
    /// next `drain`. Should even the held list refuse to grow, the record
    /// stays leased until a restart (as for `nack_failed`).
    fn releaseOne(self: *Coordinator, l: jobqueue.Lease) void {
        self.wal.release(l, .{}) catch {
            self.held.append(self.gpa, .{ .lease = l, .kind = .release_failed }) catch {};
        };
    }

    /// True while a lease of `key` is held.
    fn heldFor(self: *const Coordinator, key: []const u8) bool {
        for (self.held.items) |h| {
            if (std.mem.eql(u8, h.lease.partition, key)) return true;
        }
        return false;
    }

    /// The write of `lease` (a record of `key`) reached the sink: ack it, in
    /// key order (WAL id). The key's held leases with a smaller id are
    /// superseded: they are acked first, never written again. When an ack
    /// fails, it and every later one of those, and `lease`, are held as
    /// `ack_failed` and retried by `drain`, so the WAL never keeps an older
    /// record of a key whose newer one it no longer has. Held leases with a
    /// larger id are left alone. Returns whether `lease` was acked (otherwise
    /// the key must not advance yet).
    fn ackLanded(self: *Coordinator, key: []const u8, lease: jobqueue.Lease) bool {
        const id = leaseId(lease);
        var blocked = false;
        // The key's held leases OLDER than this one (a smaller WAL id), oldest
        // first. A newer one is not superseded: it was never written (the
        // older record became visible again while it stayed held) and is
        // released and written after this one.
        var floor: u64 = 0;
        while (self.oldestHeld(key, floor, id)) |j| {
            const h = self.held.items[j];
            if (!blocked) {
                if (self.wal.ack(h.lease)) |_| {
                    _ = self.held.orderedRemove(j);
                    if (self.unflushed > 0) self.unflushed -= 1;
                    continue;
                } else |_| blocked = true;
            }
            self.held.items[j].kind = .ack_failed;
            floor = leaseId(h.lease) + 1;
        }
        if (!blocked) {
            if (self.wal.ack(lease)) |_| {
                if (self.unflushed > 0) self.unflushed -= 1;
                return true;
            } else |_| {}
        }
        // Should even the held list refuse to grow, the record stays leased
        // until a restart replays it, together with any older one of the key.
        self.held.append(self.gpa, .{ .lease = lease, .kind = .ack_failed }) catch {};
        return false;
    }

    fn leaseId(lease: jobqueue.Lease) u64 {
        return @backingInt(lease.id);
    }

    /// Index of the held lease of `key` with the smallest WAL id in
    /// `[floor, below)`, or null.
    fn oldestHeld(self: *const Coordinator, key: []const u8, floor: u64, below: u64) ?usize {
        var best: ?usize = null;
        var best_id: u64 = 0;
        for (self.held.items, 0..) |h, j| {
            if (!std.mem.eql(u8, h.lease.partition, key)) continue;
            const hid = leaseId(h.lease);
            if (hid < floor or hid >= below) continue;
            if (best == null or hid < best_id) {
                best = j;
                best_id = hid;
            }
        }
        return best;
    }

    /// Resolve held leases: retry the failed nacks and acks, and with
    /// `sync_too` return the synchronous rejections of a `flushAll` pass to the
    /// WAL as failed writes. A key's held leases go back oldest first, and a
    /// key still holding one is not advanced (`flushFailed`).
    fn releaseHeld(self: *Coordinator, sync_too: bool) void {
        // Visit only the entries present now: a `nack` that fails again
        // appends its lease at the end, for the next call.
        var remaining = self.held.items.len;
        var i: usize = 0;
        while (remaining > 0) : (remaining -= 1) {
            const h = self.held.items[i];
            switch (h.kind) {
                .rejected => if (!sync_too) {
                    i += 1;
                    continue;
                },
                .nack_failed => {},
                .release_failed => {
                    // Still passed over, not failed: no attempt, no new wait.
                    self.wal.release(h.lease, .{}) catch {
                        i += 1;
                        continue;
                    };
                    _ = self.held.orderedRemove(i);
                    continue;
                },
                .ack_failed => {
                    // Oldest first per key (by WAL id, not list order): wait
                    // for an older held one.
                    if (self.oldestHeld(h.lease.partition, 0, leaseId(h.lease)) != null) {
                        i += 1;
                        continue;
                    }
                    self.wal.ack(h.lease) catch {
                        i += 1;
                        continue;
                    };
                    _ = self.held.orderedRemove(i);
                    if (self.unflushed > 0) self.unflushed -= 1;
                    continue;
                },
            }
            _ = self.held.orderedRemove(i);
            var key_buf: [jobqueue.max_field_len]u8 = undefined;
            const key = key_buf[0..h.lease.partition.len];
            @memcpy(key, h.lease.partition);
            self.flushFailed(key, h.lease);
        }
    }

    /// True while `key` waits out its retry backoff; drops a lapsed entry.
    fn retryWaiting(self: *Coordinator, key: []const u8) bool {
        const at = self.retry_at.get(key) orelse return false;
        if (self.mono.now() < at) return true;
        self.clearRetry(key);
        return false;
    }

    fn setRetry(self: *Coordinator, key: []const u8, at: u64) !void {
        if (self.retry_at.getPtr(key)) |slot| {
            slot.* = at;
            return;
        }
        const dup = try self.gpa.dupe(u8, key);
        errdefer self.gpa.free(dup);
        try self.retry_at.put(self.gpa, dup, at);
    }

    fn clearRetry(self: *Coordinator, key: []const u8) void {
        if (self.retry_at.fetchRemove(key)) |kv| self.gpa.free(kv.key);
    }

    fn freeRetry(self: *Coordinator) void {
        var it = self.retry_at.keyIterator();
        while (it.next()) |k| self.gpa.free(k.*);
        self.retry_at.deinit(self.gpa);
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
        // Can't return an error from a `ramcache` eviction hook — count it
        // instead (F3) rather than swallowing it silently. See
        // `n_dropped_orphans`'s doc comment for why this does not risk
        // durability.
        self.addKeySet(&self.orphans, key) catch {
            self.n_dropped_orphans += 1;
        };
    }

    /// Free the in-flight set: its keys and the task of every entry (a task
    /// still listed here never reached the completion list).
    fn freeInFlight(self: *Coordinator) void {
        var it = self.in_flight.iterator();
        while (it.next()) |e| {
            self.freeTask(e.value_ptr.*);
            self.gpa.free(e.key_ptr.*);
        }
        self.in_flight.deinit(self.gpa);
    }

    fn markInFlight(self: *Coordinator, key: []const u8, task: *FlushTask) !void {
        std.debug.assert(!self.in_flight.contains(key));
        const dup = try self.gpa.dupe(u8, key);
        errdefer self.gpa.free(dup);
        try self.in_flight.put(self.gpa, dup, task);
    }

    fn clearInFlight(self: *Coordinator, key: []const u8) void {
        if (self.in_flight.fetchRemove(key)) |kv| self.gpa.free(kv.key);
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
        const k = try std.mem.print(&buf, "k{d}", .{i});
        try c.put(k, "v");
    }
    // Immediately readable from the cache (before any flush).
    i = 0;
    while (i < n) : (i += 1) {
        const k = try std.mem.print(&buf, "k{d}", .{i});
        try testing.expectEqualStrings("v", (try c.get(k)).?);
    }
    try testing.expectEqual(@as(usize, n), c.pendingCount());

    try c.flushAll();
    try testing.expectEqual(@as(usize, 0), c.pendingCount());
    try testing.expectEqual(@as(usize, 0), c.inFlightCount());

    // Sink now holds every write; the cache is clean.
    try testing.expectEqual(@as(usize, n), rig.sink.count());
    i = 0;
    while (i < n) : (i += 1) {
        const k = try std.mem.print(&buf, "k{d}", .{i});
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

    try c.flushAll();
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
    try c.flushAll();
    try testing.expectEqual(@as(usize, 2), rig.sink.count());

    try c.del("a");
    try testing.expect((try c.get("a")) == null); // tombstone shadows the cache
    try c.flushAll();
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
            const k = try std.mem.print(&buf, "key{d}", .{i});
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
        const k = try std.mem.print(&buf, "key{d}", .{i});
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

test "F3: del() propagates OOM in tombstone/orphan registration instead of swallowing it" {
    var rig: Rig = undefined;
    rig.init();
    defer rig.deinit();
    var c = try rig.open(4);
    defer c.deinit();

    try c.put("k", "v");

    // The WAL delete write itself uses `wal`'s own allocator (captured at
    // init), unaffected by swapping `c.gpa` — so `del`'s durable append still
    // succeeds; only the tombstone/orphan bookkeeping after it can fail.
    var fa = std.testing.FailingAllocator.init(testing.allocator, .{ .fail_index = 0 });
    c.gpa = fa.allocator();
    const result = c.del("k");
    c.gpa = testing.allocator; // restore before anything else touches gpa

    try testing.expectError(error.OutOfMemory, result);
}

test "F2: a durably-flushed delete's tombstone is reclaimed, and the stale cache entry with it" {
    var rig: Rig = undefined;
    rig.init();
    defer rig.deinit();
    var c = try rig.open(4);
    defer c.deinit();

    // A prior put, durably flushed — this is the stale cache entry that must
    // not resurface once the tombstone stops shadowing it.
    try c.put("k", "v1");
    try c.flushAll();
    try testing.expectEqualStrings("v1", rig.sink.peek("k").?);

    try c.del("k");
    // Before the delete flushes: shadowed by the tombstone, and the
    // bookkeeping this finding is about is present.
    try testing.expect(c.tombstones.contains("k"));
    try testing.expectEqual(@as(?[]const u8, null), try c.get("k"));

    try c.flushAll();
    try testing.expectEqual(@as(usize, 0), c.pendingCount());
    try testing.expectEqual(@as(usize, 0), rig.sink.count()); // sink applied the delete

    // F2: the tombstone is gone — reclaimed on durable delete-flush
    // completion, not left to grow until some future `put` to this exact
    // key. Without the fix this assertion is what goes RED (the tombstone
    // set still contains "k" here).
    try testing.expect(!c.tombstones.contains("k"));

    // And the miss is still correct with the tombstone gone: `get` now falls
    // through to a cache-miss + sink-read-through-miss, NOT a stale cache
    // hit. This is the safety half of F2 — GC-ing the tombstone without also
    // evicting the stale "v1" cache entry would resurrect deleted data here.
    try testing.expectEqual(@as(?[]const u8, null), try c.get("k"));
}

test "F2: a poisoned (dead-lettered) delete keeps its tombstone forever, on purpose" {
    // A sink whose delete always fails, so the WAL record dead-letters once
    // it burns its (finite, here) attempt budget — the delete never actually
    // reaches the sink.
    var failing_rig: FailRig = undefined;
    failing_rig.init(.{ .gpa = testing.allocator, .fail_delete = true });
    defer failing_rig.deinit();
    var c = try failing_rig.open(1); // max_flush_attempts = 1: dead-letters fast
    defer c.deinit();

    try c.del("k");
    try testing.expect(c.tombstones.contains("k"));
    try c.flushAll();
    try testing.expectEqual(@as(usize, 1), c.poisonedCount());
    // The delete never landed in the sink — GC-ing the tombstone here would
    // let a later `get` read-through resurrect whatever the sink still has
    // for "k". It must still be shadowed.
    try testing.expect(c.tombstones.contains("k"));
}

test "F3: onEvict's dropped orphan registration is counted, not silently lost" {
    var rig: Rig = undefined;
    rig.init();
    defer rig.deinit();

    // Tiny cache (2 entries), same shape as the on_evict safety-net test
    // below, so a third dirty put evicts an earlier dirty one.
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
    try testing.expectEqual(@as(usize, 0), c.droppedOrphanCount());

    var fa = std.testing.FailingAllocator.init(testing.allocator, .{ .fail_index = 0 });
    c.gpa = fa.allocator();
    try c.put("cc", "3"); // over capacity → on_evict fires, its addKeySet OOMs
    c.gpa = testing.allocator; // restore before anything else touches gpa

    try testing.expectEqual(@as(usize, 1), c.droppedOrphanCount());

    // Durability is unaffected: flushAll's WAL-rescan backstop (driven off
    // `unflushed`, not the orphan set) still reaches every record.
    try c.flushAll();
    try testing.expectEqual(@as(usize, 0), c.pendingCount());
    try testing.expectEqual(@as(usize, 3), rig.sink.count());
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
    try c.flushAll();
    try testing.expectEqual(@as(usize, 0), c.pendingCount());
    try testing.expectEqual(@as(usize, 3), rig.sink.count());
    try testing.expectEqualStrings("1", rig.sink.peek("a").?);
    try testing.expectEqualStrings("2", rig.sink.peek("b").?);
    try testing.expectEqualStrings("3", rig.sink.peek("cc").?);
}

/// Poll `drain()` (never `flushAll` — its `flushOneSync` backstop would mask a
/// broken safety net) until quiescent, bounded by WALL-CLOCK time, never an
/// iteration count. `drain()` itself is a cheap non-blocking pass, but the
/// pool workers that actually do the flushing are real OS threads
/// (`workerpool` spawns them via `std.Thread.spawn`); an iteration-bounded
/// spin races the scheduler, not the workers. In `ReleaseFast` a no-op pass
/// through `drain()` costs tens of nanoseconds, so a 100_000-iteration bound
/// can burn its whole budget in well under a millisecond of wall time — nowhere
/// near enough for two starved OS threads to be scheduled, run an in-memory
/// sink write, and post the completion back, on a host where every core is
/// already oversubscribed (the ~215-module full test lane, or a single core
/// under `taskset -c 0` deliberately, either one starves the workers the same
/// way). A correct implementation always converges given enough real time —
/// there is no path where the safety net can spin forever without the workers
/// making progress — so the fix is a deadline, not a longer iteration count.
/// 10s is generous for a handful of in-memory sink writes; between `drain()`
/// passes it parks on the same `completion_gen` futex `flushAll` waits on,
/// rather than busy-spinning the CPU the workers need.
fn drainUntilQuiescent(c: *Coordinator) void {
    const deadline_ns = std.Io.Timestamp.now(c.io, .awake).nanoseconds + 10 * std.time.ns_per_s;
    while (c.pendingCount() > 0) {
        c.drain();
        if (c.pendingCount() == 0) return;
        if (std.Io.Timestamp.now(c.io, .awake).nanoseconds >= deadline_ns) return;
        const gen = c.completion_gen.load(.acquire);
        c.io.futexWaitTimeout(u32, &c.completion_gen.raw, gen, .{ .duration = .{
            .raw = .fromMilliseconds(20),
            .clock = .awake,
        } }) catch {};
    }
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
    drainUntilQuiescent(c);

    try testing.expectEqual(@as(usize, 0), c.pendingCount());
    try testing.expectEqual(@as(usize, 3), rig.sink.count());
    try testing.expectEqualStrings("1", rig.sink.peek("a").?);
    try testing.expectEqualStrings("2", rig.sink.peek("b").?);
    try testing.expectEqualStrings("3", rig.sink.peek("cc").?);
}

// Regression: wave-2 F1. A value larger than the WHOLE cache budget is refused
// admission by `ramcache.put` (`value.len > max_bytes`) WITHOUT firing
// `on_evict`, so before the fix the key was neither cache-dirty nor an orphan
// and `kick()` — whose only sources are `drainDirty` and `orphans` — could never
// select it. The write was acked and durable, yet the documented periodic
// `drain()` tick left it pending forever. `flushAll` is deliberately NOT used:
// its `flushOneSync` backstop drains any leftover WAL record and would mask the
// hole (that is exactly why the audit's own reproducer needed 2000 drain passes).
test "over-budget value: acked write is reachable by drain() ALONE (non-admission, not eviction)" {
    var rig: Rig = undefined;
    rig.init();
    defer rig.deinit();

    var c = try Coordinator.init(testing.allocator, .{
        .io = rig.threaded.io(),
        .sink = rig.sink.sink(),
        .wal_store = rig.wal_sim.storage(),
        .wal_path = "wal.jq",
        .max_cache_bytes = 1024, // deliberately smaller than the value below
        .max_cache_entries = 64,
        .n_workers = 2,
    });
    defer c.deinit();

    const big: [4096]u8 = @splat('z');
    try c.put("small", "s"); // a normally-admitted neighbour, must be unaffected
    try c.put("big", &big); // 4096 > max_bytes=1024 → refused admission
    try testing.expectEqual(@as(usize, 2), c.pendingCount());

    // CONTROL 1: the value really was refused admission — this test is only
    // meaningful while `ramcache` keeps rejecting over-budget values. If a future
    // `ramcache` change admits it, this assertion fails loudly rather than
    // letting the test silently stop covering the defect.
    try testing.expect(!c.cache.isDirty("big"));
    try testing.expect(c.cache.get("big", 0, 0) == null);
    // CONTROL 2: and `on_evict` did NOT fire for it (non-admission is not
    // eviction), so the orphan entry can only have come from `put`'s own
    // non-admission check.
    try testing.expect(c.orphans.contains("big"));

    // drain() ALONE — no flushAll backstop.
    drainUntilQuiescent(c);

    try testing.expectEqual(@as(usize, 0), c.pendingCount());
    try testing.expectEqual(@as(usize, 2), rig.sink.count());
    try testing.expectEqualStrings("s", rig.sink.peek("small").?);
    try testing.expectEqualStrings(&big, rig.sink.peek("big").?);
    // Bookkeeping is reconciled once the record is acked — no permanent orphan.
    try testing.expect(!c.orphans.contains("big"));
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
        const k = try std.mem.print(&buf, "item-{d}", .{i});
        try c.put(k, "x");
        if (i % 64 == 0) c.drain(); // interleave flush passes with writes
    }
    try c.flushAll();

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
        // Over `FsStorage` the sink waits on its lock through the `Io`.
        try testing.expect(ksink.lock.io != null);

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
            const k = try std.mem.print(&buf, "row{d}", .{i});
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
        const k = try std.mem.print(&buf, "row{d}", .{i});
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
    try c2.flushAll();
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

    const big_key = strRepeat("x", jobqueue.max_field_len + 1);
    try testing.expectError(error.KeyTooLarge, c.put(big_key, "v"));
    try testing.expectEqual(@as(usize, 0), c.pendingCount()); // nothing enqueued
}

/// A sink that fails on purpose: the first `fail_n` writes (any key) and every
/// write to `reject_key`. Nothing like it exists among the reference sinks —
/// `MapSink` and `KvtreeSink` both accept essentially every write, which is why
/// the failure contract below went unexercised.
const FailingSink = struct {
    lock: SpinLock = .{},
    map: std.StringHashMapUnmanaged([]u8) = .empty,
    gpa: Allocator,
    /// The first `fail_n` write attempts are rejected, then writes succeed.
    fail_n: usize = 0,
    /// Every write to this key is rejected, forever.
    reject_key: ?[]const u8 = null,
    /// Total write attempts seen (accepted or not).
    seen: usize = 0,
    /// Every delete attempt is rejected, forever (F2's poisoned-delete test:
    /// unlike `fail_n`/`reject_key`, which only ever gate `write`, this is
    /// the only way to make a delete never durably land).
    fail_delete: bool = false,

    fn deinit(self: *FailingSink) void {
        var it = self.map.iterator();
        while (it.next()) |e| {
            self.gpa.free(e.key_ptr.*);
            self.gpa.free(e.value_ptr.*);
        }
        self.map.deinit(self.gpa);
    }
    fn sink(self: *FailingSink) Sink {
        return .{ .ptr = self, .vtable = &vt };
    }
    fn get(self: *FailingSink, key: []const u8) ?[]const u8 {
        self.lock.lock();
        defer self.lock.unlock();
        return self.map.get(key);
    }

    const vt = Sink.VTable{ .write = vWrite, .delete = vDelete };

    fn vWrite(ptr: *anyopaque, key: []const u8, value: []const u8) anyerror!void {
        const self: *FailingSink = @ptrCast(@alignCast(ptr));
        self.lock.lock();
        defer self.lock.unlock();
        self.seen += 1;
        if (self.seen <= self.fail_n) return error.SinkRejected;
        if (self.reject_key) |rk| {
            if (std.mem.eql(u8, rk, key)) return error.SinkRejected;
        }
        // An existing key keeps its own storage (`fetchPut` would leave the
        // map pointing at a key this function had just freed).
        if (self.map.getPtr(key)) |slot| {
            const nv = try self.gpa.dupe(u8, value);
            self.gpa.free(slot.*);
            slot.* = nv;
            return;
        }
        const k = try self.gpa.dupe(u8, key);
        errdefer self.gpa.free(k);
        const v = try self.gpa.dupe(u8, value);
        errdefer self.gpa.free(v);
        try self.map.put(self.gpa, k, v);
    }
    fn vDelete(ptr: *anyopaque, key: []const u8) anyerror!void {
        const self: *FailingSink = @ptrCast(@alignCast(ptr));
        self.lock.lock();
        defer self.lock.unlock();
        if (self.fail_delete) return error.SinkRejected;
        if (self.map.fetchRemove(key)) |old| {
            self.gpa.free(old.key);
            self.gpa.free(old.value);
        }
    }
};

const FailRig = struct {
    threaded: std.Io.Threaded,
    sink: FailingSink,
    wal_sim: SimStorage,

    fn init(rig: *FailRig, sink: FailingSink) void {
        rig.* = .{
            .threaded = std.Io.Threaded.init(testing.allocator, .{}),
            .sink = sink,
            .wal_sim = SimStorage.init(testing.allocator),
        };
    }
    fn deinit(rig: *FailRig) void {
        rig.wal_sim.deinit();
        rig.sink.deinit();
        rig.threaded.deinit();
    }
    fn open(rig: *FailRig, max_flush_attempts: u32) !*Coordinator {
        return Coordinator.init(testing.allocator, .{
            .io = rig.threaded.io(),
            .sink = rig.sink.sink(),
            .wal_store = rig.wal_sim.storage(),
            .wal_path = "wal.jq",
            .max_cache_bytes = 1 << 20,
            .max_cache_entries = 1024,
            .n_workers = 2,
            .max_flush_attempts = max_flush_attempts,
        });
    }
};

test "a sink that rejects more often than jobqueue's default cap still lands the write" {
    // The regression test for the defect this module shipped with: the WAL was
    // enqueued at `jobqueue`'s default `max_attempts = 5`, so the SIXTH
    // rejection dead-lettered an already-acknowledged write and nothing ever
    // told the caller. 12 rejections is comfortably past that cliff.
    var rig: FailRig = undefined;
    rig.init(.{ .gpa = testing.allocator, .fail_n = 12 });
    defer rig.deinit();

    const c = try rig.open(0); // default: never give up
    defer c.deinit();

    try c.put("k", "v");
    try c.flushAll();

    const landed = rig.sink.get("k");
    try testing.expect(landed != null); // the acked write reached the sink at all
    try testing.expectEqualStrings("v", landed.?);
    try testing.expectEqual(@as(usize, 0), c.poisonedCount());
    try testing.expectEqual(@as(usize, 0), c.pendingCount());
    try testing.expectEqual(@as(usize, 13), rig.sink.seen); // 12 failures + 1 success
}

test "an explicit attempt cap drops the record — counted, listed, and not stranded" {
    var rig: FailRig = undefined;
    rig.init(.{ .gpa = testing.allocator, .reject_key = "bad" });
    defer rig.deinit();

    const c = try rig.open(3); // opt in to giving up after 3 attempts
    defer c.deinit();

    try c.put("bad", "x");
    try c.put("good", "y");
    try c.flushAll();

    // The poisoned key is dropped, and saying so is the whole point: an
    // acknowledged write did not reach the sink.
    try testing.expectEqual(@as(usize, 1), c.poisonedCount());
    try testing.expect(rig.sink.get("bad") == null);

    const dead = try c.poisoned(testing.allocator);
    defer Coordinator.freePoisoned(testing.allocator, dead);
    try testing.expectEqual(@as(usize, 1), dead.len);
    try testing.expectEqualStrings("bad", dead[0].partition);
    try testing.expectEqualStrings("x", dead[0].payload);
    try testing.expectEqual(@as(u32, 3), dead[0].attempts);

    // An unrelated key is unaffected, and the accounting is clean — before the
    // fix `unflushed` kept counting the dropped record forever, so `flushAll`
    // could never reach a quiescent state again.
    try testing.expectEqualStrings("y", rig.sink.get("good").?);
    try testing.expectEqual(@as(usize, 0), c.pendingCount());
}

test "a second record for a poisoned key is not stranded behind it" {
    var rig: FailRig = undefined;
    rig.init(.{ .gpa = testing.allocator, .reject_key = "bad" });
    defer rig.deinit();

    const c = try rig.open(2);
    defer c.deinit();

    try c.put("bad", "x1");
    try c.put("bad", "x2");
    try c.flushAll();

    // Both records for the key are dropped (the sink rejects the key itself),
    // and crucially the SECOND one was actually attempted rather than left
    // queued behind the first — the key-advance the success path performs.
    try testing.expectEqual(@as(usize, 2), c.poisonedCount());
    try testing.expectEqual(@as(usize, 0), c.pendingCount());
    try testing.expectEqual(@as(usize, 4), rig.sink.seen); // 2 records x 2 attempts
}

test "F4: recover() stops at the first sink failure, keeps prior progress, and resumes cleanly on retry" {
    // FailingSink existed but was only ever driven through flushAll -- no
    // test put a failing sink through recover() at all. recover() aborts
    // on the FIRST failure after nacking that one lease, with no count of
    // how much it did replay. Decide (and pin) the contract: earlier
    // records already acked to the sink before the failure stay acked
    // (never replayed twice, never lost), the failing record and
    // everything still queued behind it stay pending/durable, and a later
    // recover() call (once the obstacle is gone) finishes the job.
    var rig: FailRig = undefined;
    rig.init(.{ .gpa = testing.allocator, .reject_key = "k1" });
    defer rig.deinit();

    {
        const c = try rig.open(0);
        try c.put("k0", "v0");
        try c.put("k1", "v1");
        try c.put("k2", "v2");
        c.deinitNoFlush(); // crash: nothing reached the sink yet
    }
    try testing.expect(rig.sink.get("k0") == null);

    const c2 = try rig.open(0);
    defer c2.deinit();
    try testing.expectEqual(@as(usize, 3), c2.pendingCount());

    try testing.expectError(error.SinkWriteFailed, c2.recover());

    // k0 (enqueued before the failing key) made it through and is durably
    // acked -- recover() does not lose or replay-skip prior progress.
    try testing.expectEqualStrings("v0", rig.sink.get("k0").?);
    // k1 (the failure) and k2 (never reached) are still outstanding.
    try testing.expect(rig.sink.get("k1") == null);
    try testing.expect(rig.sink.get("k2") == null);
    try testing.expectEqual(@as(usize, 2), c2.pendingCount());

    // Clear the obstacle and resume: a later recover() call finishes
    // replaying what the first call left behind.
    rig.sink.reject_key = null;
    try c2.recover();
    try testing.expectEqualStrings("v0", rig.sink.get("k0").?);
    try testing.expectEqualStrings("v1", rig.sink.get("k1").?);
    try testing.expectEqualStrings("v2", rig.sink.get("k2").?);
    try testing.expectEqual(@as(usize, 0), c2.pendingCount());
}

test "a put after a del supersedes the tombstone at once" {
    var rig: Rig = undefined;
    rig.init();
    defer rig.deinit();
    var c = try rig.open(2);
    defer c.deinit();
    try c.del("k");
    try c.put("k", "back");
    try testing.expectEqualStrings("back", (try c.get("k")).?);
}

test "a failing sink read-through is reported, not turned into a miss" {
    const BrokenRead = struct {
        fn vWrite(_: *anyopaque, _: []const u8, _: []const u8) anyerror!void {}
        fn vDelete(_: *anyopaque, _: []const u8) anyerror!void {}
        fn vRead(_: *anyopaque, _: Allocator, _: []const u8) anyerror!?[]u8 {
            return error.Unreachable;
        }
        const vt = Sink.VTable{ .write = vWrite, .delete = vDelete, .read = vRead };
    };
    var dummy: u8 = 0;
    var threaded = std.Io.Threaded.init(testing.allocator, .{});
    defer threaded.deinit();
    var wal_sim = SimStorage.init(testing.allocator);
    defer wal_sim.deinit();
    const c = try Coordinator.init(testing.allocator, .{
        .io = threaded.io(),
        .sink = .{ .ptr = &dummy, .vtable = &BrokenRead.vt },
        .wal_store = wal_sim.storage(),
        .wal_path = "wal.jq",
        .max_cache_bytes = 1 << 20,
        .max_cache_entries = 1024,
        .n_workers = 1,
    });
    defer c.deinit();
    try testing.expectError(error.SinkReadFailed, c.get("absent-from-cache"));
}

test "recover() applies a WAL delete as a delete" {
    var rig: Rig = undefined;
    rig.init();
    defer rig.deinit();
    {
        var c = try rig.open(2);
        try c.put("k", "v");
        try c.flushAll();
        try testing.expectEqualStrings("v", rig.sink.peek("k").?);
        try c.del("k");
        c.deinitNoFlush(); // the delete is only in the WAL
    }
    var c2 = try rig.open(2);
    defer c2.deinit();
    try c2.recover();
    try testing.expect(rig.sink.peek("k") == null);
}

test "drain() alone carries one key through every queued record" {
    var rig: Rig = undefined;
    rig.init();
    defer rig.deinit();
    var c = try rig.open(2);
    defer c.deinit();
    try c.put("k", "a");
    try c.put("k", "b"); // two WAL records for one key
    drainUntilQuiescent(c);
    try testing.expectEqual(@as(usize, 0), c.pendingCount());
    try testing.expectEqualStrings("b", rig.sink.peek("k").?);
}

test "one key never has two sink calls in flight (dirty AND orphan selects it twice)" {
    const OverlapSink = struct {
        io: std.Io,
        inner: MapSink,
        active: std.atomic.Value(u32) = .init(0),
        max_active: std.atomic.Value(u32) = .init(0),

        fn enter(self: *@This()) void {
            const n = self.active.fetchAdd(1, .acq_rel) + 1;
            _ = self.max_active.fetchMax(n, .acq_rel);
            // Hold the call open long enough for a second one to overlap it.
            self.io.sleep(.fromMilliseconds(30), .awake) catch {};
        }
        fn vWrite(ptr: *anyopaque, key: []const u8, value: []const u8) anyerror!void {
            const self: *@This() = @ptrCast(@alignCast(ptr));
            self.enter();
            defer _ = self.active.fetchSub(1, .acq_rel);
            return MapSink.vWrite(&self.inner, key, value);
        }
        fn vDelete(ptr: *anyopaque, key: []const u8) anyerror!void {
            const self: *@This() = @ptrCast(@alignCast(ptr));
            self.enter();
            defer _ = self.active.fetchSub(1, .acq_rel);
            return MapSink.vDelete(&self.inner, key);
        }
        const vt = Sink.VTable{ .write = vWrite, .delete = vDelete };
    };
    var threaded = std.Io.Threaded.init(testing.allocator, .{});
    defer threaded.deinit();
    var wal_sim = SimStorage.init(testing.allocator);
    defer wal_sim.deinit();
    var os: OverlapSink = .{ .io = threaded.io(), .inner = MapSink.init(testing.allocator) };
    defer os.inner.deinit();
    const c = try Coordinator.init(testing.allocator, .{
        .io = threaded.io(),
        .sink = .{ .ptr = &os, .vtable = &OverlapSink.vt },
        .wal_store = wal_sim.storage(),
        .wal_path = "wal.jq",
        .max_cache_bytes = 1 << 20,
        .max_cache_entries = 1024,
        .n_workers = 2,
    });
    defer c.deinit();
    try c.put("k", "v"); // dirty in the cache
    try c.del("k"); // and an orphan: kick() collects "k" from both sources
    try c.flushAll();
    try testing.expectEqual(@as(u32, 1), os.max_active.load(.acquire));
    try testing.expect(os.inner.peek("k") == null); // the delete landed last
}

// Regression (mutation run 2026-10-05). `flushOneSync` read `lease.partition`
// AFTER `ack` had freed it, then leased that key's next record and dropped the
// lease: the record stayed invisible for the 60 s visibility timeout and
// `flushAll` gave up with it pending. In safe modes `free` fills the key with
// 0xAA, so the lookup missed and an ordinary key passed by accident; a key that
// IS 0xAA reproduces in every mode what a ReleaseFast build does with any key.
test "flushOneSync: a key's next record is flushed, not leased and dropped" {
    var rig: Rig = undefined;
    rig.init();
    defer rig.deinit();
    const key = "\xaa";
    {
        var c = try rig.open(2);
        try c.put(key, "old");
        try c.put(key, "new");
        c.deinitNoFlush();
    }
    var c2 = try rig.open(2);
    defer c2.deinit();
    try c2.flushAll();
    try testing.expectEqual(@as(usize, 0), c2.pendingCount());
    try testing.expectEqualStrings("new", rig.sink.peek(key).?);
}

test "meta is well-formed" {
    try testing.expect(meta.platform == .posix);
    try testing.expect(meta.concurrency == .single_owner);
    try testing.expectEqual(@as(usize, 4), meta.deps.len);
}

/// Comptime string repetition; replaces the `**` operator removed in Zig 0.17.
inline fn strRepeat(comptime s: []const u8, comptime n: usize) *const [s.len * n:0]u8 {
    // One @splat + @bitCast, not a loop: a comptime loop writing into an
    // array var costs O(n^2) in Sema (40 000 bytes: 8.7 s; http's test
    // binary spent ~5 min in Sema on these, 2026-10-24).
    const rep_result = comptime blk: {
        const unit: [s.len]u8 = s[0..s.len].*;
        const grid: [n][s.len]u8 = @splat(unit);
        const flat: [s.len * n]u8 = @bitCast(grid);
        break :blk (flat ++ [_:0]u8{})[0 .. s.len * n :0].*;
    };
    return &rep_result;
}

// ── back-pressure (high-water mark) ──────────────────────────────────────────

const BpRig = struct {
    fn open(rig: *FailRig, mark: usize, block_ns: u64) !*Coordinator {
        return Coordinator.init(testing.allocator, .{
            .io = rig.threaded.io(),
            .sink = rig.sink.sink(),
            .wal_store = rig.wal_sim.storage(),
            .wal_path = "wal.jq",
            .max_cache_bytes = 1 << 20,
            .max_cache_entries = 1024,
            .n_workers = 2,
            .max_unflushed = mark,
            .put_block_ns = block_ns,
        });
    }
    /// Let the sink accept writes again (`fail_n` is read under its lock).
    fn unstall(rig: *FailRig) void {
        rig.sink.lock.lock();
        defer rig.sink.lock.unlock();
        rig.sink.fail_n = 0;
    }
};

test "back-pressure: mark entries are admitted, mark+1 fails typed with nothing written, recovery after the sink drains" {
    var rig: FailRig = undefined;
    rig.init(.{ .gpa = testing.allocator, .fail_n = std.math.maxInt(usize) }); // stalled sink
    defer rig.deinit();
    const c = try BpRig.open(&rig, 3, 0);
    defer c.deinit();

    try c.put("a", "1");
    try c.put("b", "2");
    try c.put("c", "3"); // exactly the mark: admitted
    try testing.expectEqual(@as(usize, 3), c.pendingCount());
    try testing.expectError(error.Backpressure, c.put("d", "4")); // mark + 1
    try testing.expectError(error.Backpressure, c.del("a")); // del is a WAL write too
    try testing.expectEqual(@as(usize, 3), c.pendingCount()); // nothing was written
    try testing.expect((try c.get("d")) == null);
    // A key too large is the caller's error even at the mark, and is not made to wait.
    try testing.expectError(error.KeyTooLarge, c.put(strRepeat("x", jobqueue.max_field_len + 1), "v"));
    try testing.expectError(error.KeyTooLarge, c.del(strRepeat("x", jobqueue.max_field_len + 1)));
    // At the cap itself the key is admitted by the size check (then the mark speaks).
    try testing.expectError(error.Backpressure, c.put(strRepeat("x", jobqueue.max_field_len), "v"));

    // The sink drains: a put that may wait gets in once a record lands. The
    // earlier flush attempts are in flight (failed, not yet harvested), so
    // only the wait loop's own `drain` can move on.
    c.drain();
    try testing.expect(c.in_flight.count() > 0);
    BpRig.unstall(&rig);
    c.put_block_ns = 30 * std.time.ns_per_s;
    try c.put("d", "4");
    try testing.expect(c.pendingCount() <= 3);
    try c.flushAll();
    try testing.expectEqual(@as(usize, 0), c.pendingCount());
    try testing.expectEqualStrings("4", rig.sink.get("d").?);
    try testing.expectEqualStrings("1", rig.sink.get("a").?);
    try testing.expectEqual(@as(usize, 4), rig.sink.map.count());
}

test "back-pressure: a put waits at least put_block_ns at the mark, then fails" {
    var rig: FailRig = undefined;
    rig.init(.{ .gpa = testing.allocator, .fail_n = std.math.maxInt(usize) });
    defer rig.deinit();
    const c = try BpRig.open(&rig, 1, 60 * std.time.ns_per_ms);
    defer c.deinit();
    try c.put("a", "1");
    const t0 = std.Io.Timestamp.now(c.io, .awake).nanoseconds;
    try testing.expectError(error.Backpressure, c.put("b", "2"));
    const waited = std.Io.Timestamp.now(c.io, .awake).nanoseconds - t0;
    try testing.expect(waited >= 60 * std.time.ns_per_ms);
    BpRig.unstall(&rig);
}

test "back-pressure: the default (mark 0) never blocks" {
    var rig: FailRig = undefined;
    rig.init(.{ .gpa = testing.allocator, .fail_n = std.math.maxInt(usize) });
    defer rig.deinit();
    const c = try BpRig.open(&rig, 0, 0);
    defer c.deinit();
    var buf: [16]u8 = undefined;
    for (0..50) |i| try c.put(try std.mem.print(&buf, "k{d}", .{i}), "v");
    try testing.expectEqual(@as(usize, 50), c.pendingCount());
    BpRig.unstall(&rig);
}

test "back-pressure: records of a reopened WAL (not in the cache) are flushed synchronously to make room" {
    var rig: FailRig = undefined;
    rig.init(.{ .gpa = testing.allocator });
    defer rig.deinit();
    {
        const c1 = try BpRig.open(&rig, 0, 0);
        try c1.put("p", "1");
        try c1.put("q", "2");
        c1.deinitNoFlush(); // the WAL keeps both
    }
    // Two pending records, mark 2, nothing dirty in the new cache: only the
    // synchronous backstop can free a slot.
    const c2 = try BpRig.open(&rig, 2, 0); // never waits: the room must come from the sync flush
    defer c2.deinit();
    try testing.expectEqual(@as(usize, 2), c2.pendingCount());
    try c2.put("r", "3");
    try testing.expect(c2.pendingCount() <= 2);
    try c2.flushAll();
    try testing.expectEqualStrings("1", rig.sink.get("p").?);
    try testing.expectEqualStrings("3", rig.sink.get("r").?);
}

// ── whole-module mutation audit (2026-11-18): killing tests ──────────────────

/// Poll until a worker has published a completion (bounded by wall time). The
/// task stays on the completion list until the coordinator thread pumps it, so
/// a test can observe the exact state between "sink call done" and "acked".
fn waitCompletion(c: *Coordinator) !void {
    const deadline_ns = std.Io.Timestamp.now(c.io, .awake).nanoseconds + 10 * std.time.ns_per_s;
    while (true) {
        c.completion_lock.lock();
        const has = c.completion_head != null;
        c.completion_lock.unlock();
        if (has) return;
        if (std.Io.Timestamp.now(c.io, .awake).nanoseconds >= deadline_ns) return error.Timeout;
        const gen = c.completion_gen.load(.acquire);
        c.io.futexWaitTimeout(u32, &c.completion_gen.raw, gen, .{ .duration = .{
            .raw = .fromMilliseconds(5),
            .clock = .awake,
        } }) catch {};
    }
}

/// One injectable clock serving as both the WAL wall clock and monotonic clock.
const FakeClock = struct {
    // Far ahead of the real clock: records enqueued under the system clock stay visible.
    ns: std.atomic.Value(u64) = .init(4_000_000_000_000_000_000),
    fn wall(ctx: ?*anyopaque) i64 {
        const s: *FakeClock = @ptrCast(@alignCast(ctx.?));
        return @intCast(s.ns.load(.monotonic));
    }
    fn mono(ctx: ?*anyopaque) u64 {
        const s: *FakeClock = @ptrCast(@alignCast(ctx.?));
        return s.ns.load(.monotonic);
    }
};

test "MapSink: write, replace, delete, read, count and peek behave as a keyed store" {
    var m = MapSink.init(testing.allocator);
    defer m.deinit();
    const s = m.sink();
    try s.write("a", "1");
    try s.write("b", "22");
    try testing.expectEqual(@as(usize, 2), m.count());
    try s.write("a", "333"); // replace in place
    try testing.expectEqual(@as(usize, 2), m.count());
    try testing.expectEqualStrings("333", m.peek("a").?);
    try testing.expectEqualStrings("22", m.peek("b").?);
    try testing.expect(m.peek("zz") == null);
    const got = (try s.read(testing.allocator, "b")).?;
    defer testing.allocator.free(got);
    try testing.expectEqualStrings("22", got);
    try testing.expect((try s.read(testing.allocator, "zz")) == null);
    try s.delete("a");
    try s.delete("a"); // absent: a no-op
    try testing.expectEqual(@as(usize, 1), m.count());
    try testing.expect(m.peek("a") == null);
    try testing.expect(s.canRead());
}

test "MapSink: a failed allocation in write leaves no leak and no half-stored entry" {
    var i: usize = 0;
    while (i < 4) : (i += 1) {
        var fa = std.testing.FailingAllocator.init(testing.allocator, .{ .fail_index = i });
        var m = MapSink.init(fa.allocator());
        defer m.deinit();
        m.sink().write("key", "value") catch {};
        m.sink().write("key", "again") catch {};
        if (m.peek("key")) |v| try testing.expect(v.len > 0);
    }
}

test "Sink: a vtable without read reports NoReadThrough; write and delete pass key and value through" {
    var fs: FailingSink = .{ .gpa = testing.allocator };
    defer fs.deinit();
    const s = fs.sink();
    try testing.expect(!s.canRead());
    try testing.expectError(error.NoReadThrough, s.read(testing.allocator, "k"));
    try s.write("k", "v");
    try testing.expectEqualStrings("v", fs.get("k").?);
    try s.delete("k");
    try testing.expect(fs.get("k") == null);
}

test "KvtreeSink: write, read and delete round-trip through a real kvtree" {
    var tmp = testing.tmpDir(.{});
    defer tmp.cleanup();
    var threaded = std.Io.Threaded.init(testing.allocator, .{});
    defer threaded.deinit();
    var fs = FsStorage.init(threaded.io(), tmp.dir);
    var db = try kvtree.Db.open(testing.allocator, fs.storage(), "s.kvt", .{});
    defer db.close();
    var ks = KvtreeSink.init(testing.allocator, &db);
    const s = ks.sink();
    try testing.expect(s.canRead());
    try s.write("a", "1");
    try s.write("b", "2");
    {
        const got = (try s.read(testing.allocator, "a")).?;
        defer testing.allocator.free(got);
        try testing.expectEqualStrings("1", got);
    }
    try s.delete("a");
    try testing.expect((try s.read(testing.allocator, "a")) == null);
    const b = (try s.read(testing.allocator, "b")).?;
    defer testing.allocator.free(b);
    try testing.expectEqualStrings("2", b);
}

test "kvtree sink behind the pool: concurrent flushes and deletes land" {
    var tmp = testing.tmpDir(.{});
    defer tmp.cleanup();
    var threaded = std.Io.Threaded.init(testing.allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();
    var wal_fs = FsStorage.init(io, tmp.dir);
    var sink_fs = FsStorage.init(io, tmp.dir);
    var db = try kvtree.Db.open(testing.allocator, sink_fs.storage(), "sink.kvt", .{});
    defer db.close();
    var ks = KvtreeSink.init(testing.allocator, &db);
    const c = try Coordinator.init(testing.allocator, .{
        .io = io,
        .sink = ks.sink(),
        .wal_store = wal_fs.storage(),
        .wal_path = "wal.jq",
        .max_cache_bytes = 1 << 20,
        .max_cache_entries = 1024,
        .n_workers = 3,
    });
    defer c.deinit();
    const n = 60;
    var buf: [24]u8 = undefined;
    for (0..n) |i| {
        try c.put(try std.mem.print(&buf, "r{d}", .{i}), "val");
        if (i % 8 == 0) c.drain();
    }
    try c.flushAll();
    for (0..n) |i| {
        if (i % 3 == 0) try c.del(try std.mem.print(&buf, "r{d}", .{i}));
    }
    try c.flushAll();
    for (0..n) |i| {
        const k = try std.mem.print(&buf, "r{d}", .{i});
        const got = try db.get(testing.allocator, k);
        defer if (got) |g| testing.allocator.free(g);
        if (i % 3 == 0) {
            try testing.expect(got == null);
        } else {
            try testing.expectEqualStrings("val", got.?);
        }
    }
}

test "put/del report the WAL's refusal as ValueTooLarge or WalWriteFailed and change nothing" {
    var rig: Rig = undefined;
    rig.init();
    defer rig.deinit();
    const c = try rig.open(1);
    defer c.deinit();

    const big = try testing.allocator.alloc(u8, (jobqueue.Options{}).max_payload + 1);
    defer testing.allocator.free(big);
    @memset(big, 'v');
    try testing.expectError(error.ValueTooLarge, c.put("k", big));
    try testing.expectEqual(@as(usize, 0), c.pendingCount());
    try testing.expect((try c.get("k")) == null);

    // A storage failure on the WAL append: the write is not acknowledged and
    // nothing is staged (no cache entry, no tombstone, no counter).
    rig.wal_sim.ops_until_crash = 0;
    try testing.expectError(error.WalWriteFailed, c.put("k", "v"));
    try testing.expectError(error.WalWriteFailed, c.del("k"));
    rig.wal_sim.reboot();
    try testing.expectEqual(@as(usize, 0), c.pendingCount());
    try testing.expect(!c.tombstones.contains("k"));
    try testing.expect(!c.cache.isDirty("k"));
    try testing.expectEqual(@as(usize, 0), c.orphans.count());
}

test "put/del: an allocation failure inside the WAL append is OutOfMemory and changes nothing" {
    var threaded = std.Io.Threaded.init(testing.allocator, .{});
    defer threaded.deinit();
    var sink = MapSink.init(testing.allocator);
    defer sink.deinit();
    var wal_sim = SimStorage.init(testing.allocator);
    defer wal_sim.deinit();
    var fa = std.testing.FailingAllocator.init(testing.allocator, .{});
    const c = try Coordinator.init(fa.allocator(), .{
        .io = threaded.io(),
        .sink = sink.sink(),
        .wal_store = wal_sim.storage(),
        .wal_path = "wal.jq",
        .max_cache_bytes = 1 << 20,
        .max_cache_entries = 64,
        .n_workers = 1,
    });
    defer c.deinit();
    // The pool's workers are idle, so no other thread touches the allocator
    // while it is armed.
    fa.fail_index = fa.alloc_index;
    const r1 = c.put("k", "v");
    fa.fail_index = std.math.maxInt(usize);
    try testing.expectError(error.OutOfMemory, r1);
    fa.fail_index = fa.alloc_index;
    const r2 = c.del("k");
    fa.fail_index = std.math.maxInt(usize);
    try testing.expectError(error.OutOfMemory, r2);
    try testing.expectEqual(@as(usize, 0), c.pendingCount());
    try testing.expect((try c.get("k")) == null);
}

test "every flush path acks its WAL record: a reopened WAL has nothing pending" {
    var rig: Rig = undefined;
    rig.init();
    defer rig.deinit();
    // pool path (finishTask), including a delete record
    {
        const c = try rig.open(2);
        try c.put("a", "1");
        try c.put("b", "2");
        try c.del("b");
        try c.flushAll();
        c.deinitNoFlush();
    }
    {
        const c = try rig.open(2);
        try testing.expectEqual(@as(usize, 0), c.pendingCount());
        c.deinitNoFlush();
    }
    // synchronous path (flushOneSync + hand-over of the key's next record)
    {
        const c = try rig.open(2);
        try c.put("p", "1");
        try c.put("p", "2");
        c.deinitNoFlush();
    }
    {
        const c = try rig.open(2);
        try testing.expectEqual(@as(usize, 2), c.pendingCount());
        try c.flushAll();
        c.deinitNoFlush();
    }
    {
        const c = try rig.open(2);
        try testing.expectEqual(@as(usize, 0), c.pendingCount());
        c.deinitNoFlush();
    }
    // recover()
    {
        const c = try rig.open(2);
        try c.put("q", "1");
        try c.del("a");
        c.deinitNoFlush();
    }
    {
        const c = try rig.open(2);
        try c.recover();
        c.deinitNoFlush();
    }
    {
        const c = try rig.open(2);
        try testing.expectEqual(@as(usize, 0), c.pendingCount());
        c.deinitNoFlush();
    }
}

test "deinitNoFlush acks the flushes that already completed" {
    var rig: Rig = undefined;
    rig.init();
    defer rig.deinit();
    {
        const c = try rig.open(1);
        try c.put("k", "v");
        c.drain();
        try waitCompletion(c); // sink written, not yet acked
        c.deinitNoFlush();
    }
    try testing.expectEqualStrings("v", rig.sink.peek("k").?);
    const c2 = try rig.open(1);
    defer c2.deinit();
    try testing.expectEqual(@as(usize, 0), c2.pendingCount());
}

test "drain reconciles the bookkeeping of keys whose records recover() already applied" {
    var rig: Rig = undefined;
    rig.init();
    defer rig.deinit();
    const c = try rig.open(1);
    defer c.deinit();
    try c.put("k", "v"); // dirty in the cache
    try c.del("d"); // an orphan
    try c.recover();
    try testing.expectEqual(@as(usize, 0), c.pendingCount());
    try testing.expect(c.cache.isDirty("k"));
    try testing.expect(c.orphans.contains("d"));
    c.drain(); // startKey finds no WAL record for either key
    try testing.expect(!c.cache.isDirty("k"));
    try testing.expectEqual(@as(usize, 0), c.orphans.count());
    try testing.expectEqual(@as(usize, 0), c.inFlightCount());
}

test "flushOneSync: hands the key's next record to the pool and clears the key's bookkeeping" {
    var rig: FailRig = undefined;
    rig.init(.{ .gpa = testing.allocator });
    defer rig.deinit();
    {
        const c = try rig.open(0);
        try c.put("k", "old");
        try c.put("k", "new");
        c.deinitNoFlush();
    }
    const c = try rig.open(0);
    defer c.deinit();
    try testing.expect(c.flushOneSync());
    // The second record of "k" is on the pool: in flight until pumped.
    try testing.expectEqual(@as(usize, 1), c.inFlightCount());
    try c.flushAll();
    try testing.expectEqualStrings("new", rig.sink.get("k").?);
    try testing.expect(!c.flushOneSync()); // empty WAL: nothing flushed

    // A key with a single record: the key is cleaned and un-orphaned.
    try c.put("z", "1");
    try c.addKeySet(&c.orphans, "z");
    try testing.expect(c.cache.isDirty("z"));
    try testing.expect(c.flushOneSync());
    try testing.expect(!c.cache.isDirty("z"));
    try testing.expect(!c.orphans.contains("z"));
    try testing.expectEqualStrings("1", rig.sink.get("z").?);
    try testing.expectEqual(@as(usize, 0), c.pendingCount());
}

test "flushOneSync: a rejected write returns the record and reports no progress" {
    var rig: FailRig = undefined;
    rig.init(.{ .gpa = testing.allocator, .fail_n = 1 });
    defer rig.deinit();
    const c = try rig.open(0);
    defer c.deinit();
    try c.put("k", "v");
    try testing.expect(!c.flushOneSync());
    try testing.expectEqual(@as(usize, 1), rig.sink.seen);
    try testing.expectEqual(@as(usize, 1), c.pendingCount());
    try testing.expect(rig.sink.get("k") == null);
    try testing.expect(c.flushOneSync()); // the record was returned, visible at once
    try testing.expectEqualStrings("v", rig.sink.get("k").?);
    try testing.expectEqual(@as(usize, 0), c.pendingCount());
}

test "startFlush: an allocation failure at any step returns the lease; the write still lands" {
    var i: usize = 0;
    while (i < 6) : (i += 1) {
        var rig: Rig = undefined;
        rig.init();
        defer rig.deinit();
        const c = try rig.open(1);
        defer c.deinit();
        try c.put("k", "v");
        var fa = std.testing.FailingAllocator.init(testing.allocator, .{ .fail_index = i });
        c.gpa = fa.allocator();
        c.drain();
        c.gpa = testing.allocator;
        try c.flushAll();
        try testing.expectEqual(@as(usize, 0), c.pendingCount());
        try testing.expectEqual(@as(usize, 0), c.inFlightCount());
        try testing.expectEqualStrings("v", rig.sink.peek("k").?);
    }
}

test "startFlush: a refused pool submit returns the lease and clears the in-flight mark" {
    var rig: Rig = undefined;
    rig.init();
    defer rig.deinit();
    const c = try rig.open(1);
    defer c.deinitNoFlush();
    try c.put("k", "v");
    c.pool.shutdownNow(); // every later submit fails with error.Shutdown
    c.drain();
    try testing.expectEqual(@as(usize, 0), c.inFlightCount());
    try testing.expectEqual(@as(usize, 1), c.pendingCount());
    try c.flushAll(); // the synchronous backstop still lands it
    try testing.expectEqual(@as(usize, 0), c.pendingCount());
    try testing.expectEqualStrings("v", rig.sink.peek("k").?);
}

test "a key registered twice is stored once, and a failing registration leaks nothing" {
    {
        var rig: Rig = undefined;
        rig.init();
        defer rig.deinit();
        const c = try rig.open(1);
        defer c.deinit();
        try c.del("k");
        try c.del("k");
        try testing.expectEqual(@as(usize, 1), c.orphans.count());
        try testing.expectEqual(@as(usize, 1), c.tombstones.count());
    }
    var i: usize = 0;
    while (i < 4) : (i += 1) {
        var rig: Rig = undefined;
        rig.init();
        defer rig.deinit();
        const c = try rig.open(1);
        defer c.deinit();
        var fa = std.testing.FailingAllocator.init(testing.allocator, .{ .fail_index = i });
        c.gpa = fa.allocator();
        const r = c.del("k");
        c.gpa = testing.allocator;
        r catch |e| try testing.expectEqual(error.OutOfMemory, e);
    }
}

test "a clean eviction (read-through fill) is not registered as an orphan" {
    var rig: Rig = undefined;
    rig.init();
    defer rig.deinit();
    try rig.sink.sink().write("a", "1");
    try rig.sink.sink().write("b", "2");
    try rig.sink.sink().write("c", "3");
    const c = try Coordinator.init(testing.allocator, .{
        .io = rig.threaded.io(),
        .sink = rig.sink.sink(),
        .wal_store = rig.wal_sim.storage(),
        .wal_path = "wal.jq",
        .max_cache_bytes = 1 << 20,
        .max_cache_entries = 2,
        .n_workers = 1,
    });
    defer c.deinit();
    _ = try c.get("a");
    _ = try c.get("b");
    _ = try c.get("c"); // evicts a clean entry
    try testing.expect(c.cacheStats().evictions >= 1);
    try testing.expectEqual(@as(usize, 0), c.orphans.count());
    try testing.expectEqual(@as(usize, 0), c.droppedOrphanCount());
}

test "sync() is a flush barrier and cacheStats() reports the cache's counters" {
    var rig: Rig = undefined;
    rig.init();
    defer rig.deinit();
    const c = try rig.open(2);
    defer c.deinit();
    try c.put("k", "v");
    _ = try c.get("k");
    try testing.expect(c.cacheStats().hits >= 1);
    try c.sync();
    try testing.expectEqual(@as(usize, 0), c.pendingCount());
    try testing.expectEqualStrings("v", rig.sink.peek("k").?);
}

test "init: a WAL held by another process fails with WalOpenFailed and leaks nothing" {
    var rig: Rig = undefined;
    rig.init();
    defer rig.deinit();
    try rig.wal_sim.holdForeignLock("wal.jq.lock");
    try testing.expectError(error.WalOpenFailed, rig.open(1));
}

test "init: the injected monotonic clock governs lease expiry" {
    var rig: Rig = undefined;
    rig.init();
    defer rig.deinit();
    {
        const c = try rig.open(1);
        try c.put("k", "v");
        c.deinitNoFlush();
    }
    var clk: FakeClock = .{};
    const hour: u64 = 3600 * std.time.ns_per_s;
    const c = try Coordinator.init(testing.allocator, .{
        .io = rig.threaded.io(),
        .sink = rig.sink.sink(),
        .wal_store = rig.wal_sim.storage(),
        .wal_path = "wal.jq",
        .max_cache_bytes = 1 << 20,
        .max_cache_entries = 64,
        .n_workers = 1,
        .wal_wall_clock = .{ .ctx = &clk, .nowFn = FakeClock.wall },
        .wal_mono_clock = .{ .ctx = &clk, .nowFn = FakeClock.mono },
    });
    defer c.deinit();
    // A lease nobody acks (a lost worker): hidden until its deadline.
    _ = (try c.wal.dequeue(.{ .visibility_timeout_ns = hour })).?;
    try testing.expectEqual(@as(usize, 0), try c.wal.reapExpiredLeases());
    _ = clk.ns.fetchAdd(2 * hour, .monotonic);
    try testing.expectEqual(@as(usize, 1), try c.wal.reapExpiredLeases());
    try c.flushAll();
    try testing.expectEqual(@as(usize, 0), c.pendingCount());
    try testing.expectEqualStrings("v", rig.sink.peek("k").?);
}

/// Knobs for `openWith` (a `FailRig` coordinator with injected clocks).
const OpenWith = struct {
    cap: u32 = 0,
    backoff_ns: u64 = 0,
    flush_timeout_ns: u64 = 10 * std.time.ns_per_s,
    n_workers: usize = 1,
    max_unflushed: usize = 0,
    put_block_ns: u64 = 60 * std.time.ns_per_s,
};

fn openWith(rig: *FailRig, clk: *FakeClock, o: OpenWith) !*Coordinator {
    return Coordinator.init(testing.allocator, .{
        .io = rig.threaded.io(),
        .sink = rig.sink.sink(),
        .wal_store = rig.wal_sim.storage(),
        .wal_path = "wal.jq",
        .max_cache_bytes = 1 << 20,
        .max_cache_entries = 64,
        .n_workers = o.n_workers,
        .max_flush_attempts = o.cap,
        .retry_backoff_ns = o.backoff_ns,
        .flush_timeout_ns = o.flush_timeout_ns,
        .max_unflushed = o.max_unflushed,
        .put_block_ns = o.put_block_ns,
        .wal_wall_clock = .{ .ctx = clk, .nowFn = FakeClock.wall },
        .wal_mono_clock = .{ .ctx = clk, .nowFn = FakeClock.mono },
    });
}

/// Harvest and re-drain until nothing is in flight (bounded).
fn settle(c: *Coordinator) !void {
    var spins: usize = 0;
    while (true) : (spins += 1) {
        c.drain();
        if (c.inFlightCount() == 0) return;
        if (spins > 2000) return error.Timeout;
        c.io.sleep(.fromMilliseconds(5), .awake) catch {};
    }
}

/// Advance `clk` by `by_ns` after `after_ms` of real time (a helper thread).
fn advanceLater(clk: *FakeClock, io: std.Io, after_ms: i64, by_ns: u64) void {
    io.sleep(.fromMilliseconds(after_ms), .awake) catch {};
    _ = clk.ns.fetchAdd(by_ns, .monotonic);
}

test "retry_backoff_ns: a failed key waits out its backoff, then drain() alone retries it" {
    var rig: FailRig = undefined;
    rig.init(.{ .gpa = testing.allocator, .fail_n = 1 });
    defer rig.deinit();
    var clk: FakeClock = .{};
    const hour: u64 = 3600 * std.time.ns_per_s;
    const c = try openWith(&rig, &clk, .{ .backoff_ns = hour, .flush_timeout_ns = 100 * std.time.ns_per_ms });
    defer c.deinit();
    try c.put("k", "v");
    c.drain();
    try waitCompletion(c);
    c.drain(); // harvest the failure: the key now waits for an hour
    try testing.expectEqual(@as(usize, 1), rig.sink.seen);
    try testing.expectEqual(@as(usize, 0), c.inFlightCount());
    try testing.expectEqual(@as(usize, 1), c.pendingCount());
    // flushAll waits for it (and must not retry it early, not even through
    // the synchronous path), then gives up at its deadline, typed.
    try testing.expectError(error.FlushIncomplete, c.flushAll());
    try testing.expectEqual(@as(usize, 1), rig.sink.seen);
    try testing.expectEqual(@as(usize, 1), c.pendingCount());
    // The key is still registered, so the periodic drain() retries it once
    // the backoff has passed (it used to be reconciled clean and forgotten).
    try testing.expect(c.orphans.contains("k"));
    _ = clk.ns.fetchAdd(hour + 1, .monotonic);
    c.drain();
    try testing.expectEqual(@as(usize, 1), c.inFlightCount());
    try waitCompletion(c);
    c.drain();
    try testing.expectEqual(@as(usize, 0), c.pendingCount());
    try testing.expectEqualStrings("v", rig.sink.get("k").?);
    try testing.expect(!c.orphans.contains("k"));
    try testing.expectEqual(@as(usize, 0), c.retry_at.count());
}

test "flushAll waits out a retry backoff instead of returning with the record pending (wbmut-1)" {
    var rig: FailRig = undefined;
    rig.init(.{ .gpa = testing.allocator, .fail_n = 1 });
    defer rig.deinit();
    var clk: FakeClock = .{};
    const hour: u64 = 3600 * std.time.ns_per_s;
    const c = try openWith(&rig, &clk, .{ .backoff_ns = hour });
    defer c.deinit();
    try c.put("k", "v");
    c.drain();
    try waitCompletion(c);
    c.drain();
    try testing.expectEqual(@as(usize, 1), c.pendingCount());
    // The hour passes (on the injected clock) while flushAll is waiting.
    const t = try std.Thread.spawn(.{}, advanceLater, .{ &clk, rig.threaded.io(), 60, hour + 1 });
    defer t.join();
    try c.flushAll();
    try testing.expectEqual(@as(usize, 0), c.pendingCount());
    try testing.expectEqualStrings("v", rig.sink.get("k").?);
    try testing.expectEqual(@as(usize, 2), rig.sink.seen);
}

test "flushAll over a reopened WAL: a rejected synchronous write does not end it, the others land first (wbmut-1)" {
    var rig: FailRig = undefined;
    rig.init(.{ .gpa = testing.allocator, .fail_n = 1 });
    defer rig.deinit();
    var clk: FakeClock = .{};
    {
        const c = try openWith(&rig, &clk, .{});
        try c.put("a", "1");
        try c.put("b", "2");
        c.deinitNoFlush();
    }
    const c2 = try openWith(&rig, &clk, .{});
    defer c2.deinit();
    try testing.expectEqual(@as(usize, 2), c2.pendingCount());
    // "a" (the oldest) is rejected once: "b" still lands, and "a" is retried.
    try c2.flushAll();
    try testing.expectEqual(@as(usize, 0), c2.pendingCount());
    try testing.expectEqualStrings("1", rig.sink.get("a").?);
    try testing.expectEqualStrings("2", rig.sink.get("b").?);
    try testing.expectEqual(@as(usize, 3), rig.sink.seen);
}

test "flushAll against a key the sink always rejects: the rest lands, then FlushIncomplete with it still pending" {
    var rig: FailRig = undefined;
    rig.init(.{ .gpa = testing.allocator, .reject_key = "a" });
    defer rig.deinit();
    var clk: FakeClock = .{};
    {
        const c = try openWith(&rig, &clk, .{});
        try c.put("a", "1");
        try c.put("b", "2");
        try c.put("c", "3");
        c.deinitNoFlush();
    }
    {
        const c = try openWith(&rig, &clk, .{ .flush_timeout_ns = 150 * std.time.ns_per_ms });
        try testing.expectError(error.FlushIncomplete, c.flushAll());
        try testing.expectEqual(@as(usize, 1), c.pendingCount());
        try testing.expectEqualStrings("2", rig.sink.get("b").?);
        try testing.expectEqualStrings("3", rig.sink.get("c").?);
        // Teardown with the sink still refusing is bounded by the same
        // deadline, and the record stays in the WAL.
        c.deinit();
    }
    const c3 = try openWith(&rig, &clk, .{});
    defer c3.deinitNoFlush();
    try testing.expectEqual(@as(usize, 1), c3.pendingCount());
    try testing.expect(rig.sink.get("a") == null);
}

test "flushAll with a zero timeout flushes synchronously what it can and reports the rest" {
    var rig: FailRig = undefined;
    rig.init(.{ .gpa = testing.allocator, .reject_key = "a" });
    defer rig.deinit();
    var clk: FakeClock = .{};
    {
        const c = try openWith(&rig, &clk, .{});
        try c.put("a", "1");
        try c.put("b", "2");
        c.deinitNoFlush();
    }
    const c = try openWith(&rig, &clk, .{ .flush_timeout_ns = 0 });
    defer c.deinitNoFlush();
    try testing.expectError(error.FlushIncomplete, c.flushAll());
    try testing.expectEqualStrings("2", rig.sink.get("b").?);
    try testing.expectEqual(@as(usize, 1), c.pendingCount());
    try testing.expectEqual(@as(usize, 2), rig.sink.seen); // "a" tried once, not again
}

test "last-writer-wins survives a retry backoff: a newer write never lands before the failed older one" {
    var rig: FailRig = undefined;
    rig.init(.{ .gpa = testing.allocator, .fail_n = 1 });
    defer rig.deinit();
    var clk: FakeClock = .{};
    const hour: u64 = 3600 * std.time.ns_per_s;
    const c = try openWith(&rig, &clk, .{ .backoff_ns = hour });
    defer c.deinit();
    try c.put("k", "v1");
    c.drain();
    try waitCompletion(c);
    c.drain(); // v1 rejected: back in the WAL, the key waits an hour
    try c.put("k", "v2");
    try settle(c); // v2 must wait behind v1, not overtake it
    try testing.expect(rig.sink.get("k") == null);
    _ = clk.ns.fetchAdd(hour + 1, .monotonic);
    try c.flushAll();
    try testing.expectEqualStrings("v2", rig.sink.get("k").?);
    try testing.expectEqual(@as(usize, 0), c.pendingCount());
}

test "last-writer-wins survives a retry backoff across a restart (recover and flushAll)" {
    const hour: u64 = 3600 * std.time.ns_per_s;
    var mode: usize = 0;
    while (mode < 2) : (mode += 1) {
        var rig: FailRig = undefined;
        rig.init(.{ .gpa = testing.allocator, .fail_n = 1 });
        defer rig.deinit();
        var clk: FakeClock = .{};
        {
            const c = try openWith(&rig, &clk, .{ .backoff_ns = hour });
            try c.put("k", "v1");
            c.drain();
            try waitCompletion(c);
            c.drain(); // v1 rejected and waiting
            try c.put("k", "v2");
            c.deinitNoFlush(); // crash with v1 still in its backoff
        }
        const c2 = try openWith(&rig, &clk, .{ .backoff_ns = hour });
        defer c2.deinit();
        // Both records are pending after the restart (the backoff is not
        // persisted: v1 is retried at once, in its place before v2).
        try testing.expectEqual(@as(usize, 2), c2.pendingCount());
        if (mode == 0) try c2.recover() else try c2.flushAll();
        _ = clk.ns.fetchAdd(hour + 1, .monotonic);
        try c2.flushAll();
        try testing.expectEqualStrings("v2", rig.sink.get("k").?);
        try testing.expectEqual(@as(usize, 0), c2.pendingCount());
    }
}

test "the synchronous path counts a dead-lettered record and moves on" {
    var rig: FailRig = undefined;
    rig.init(.{ .gpa = testing.allocator, .reject_key = "a" });
    defer rig.deinit();
    var clk: FakeClock = .{};
    {
        const c = try openWith(&rig, &clk, .{ .cap = 1 });
        try c.put("a", "1");
        try c.put("b", "2");
        c.deinitNoFlush();
    }
    const c = try openWith(&rig, &clk, .{ .cap = 1 });
    defer c.deinit();
    try c.flushAll(); // "a" is dead-lettered by its single rejection: done, not pending
    try testing.expectEqual(@as(usize, 1), c.poisonedCount());
    try testing.expectEqual(@as(usize, 0), c.pendingCount());
    try testing.expectEqualStrings("2", rig.sink.get("b").?);
}

test "deinit after a timed-out flushAll waits for the running flush and acks it" {
    var threaded = std.Io.Threaded.init(testing.allocator, .{});
    defer threaded.deinit();
    var wal_sim = SimStorage.init(testing.allocator);
    defer wal_sim.deinit();
    var gs: GateSink = .{ .inner = MapSink.init(testing.allocator), .io = threaded.io() };
    defer gs.inner.deinit();
    {
        const c = try Coordinator.init(testing.allocator, .{
            .io = threaded.io(),
            .sink = .{ .ptr = &gs, .vtable = &GateSink.vt },
            .wal_store = wal_sim.storage(),
            .wal_path = "wal.jq",
            .max_cache_bytes = 1 << 20,
            .max_cache_entries = 64,
            .n_workers = 1,
            .flush_timeout_ns = 20 * std.time.ns_per_ms,
        });
        try c.put("a", "1");
        // The write blocks in the sink: flushAll gives up with it in flight.
        try testing.expectError(error.FlushIncomplete, c.flushAll());
        try testing.expectEqual(@as(usize, 1), c.inFlightCount());
        const t = try std.Thread.spawn(.{}, GateSink.openLater, .{&gs});
        defer t.join();
        c.deinit(); // its own flushAll times out too; pool.drain waits for the write
    }
    try testing.expectEqualStrings("1", gs.inner.peek("a").?);
    var sink = MapSink.init(testing.allocator);
    defer sink.deinit();
    const c2 = try Coordinator.init(testing.allocator, .{
        .io = threaded.io(),
        .sink = sink.sink(),
        .wal_store = wal_sim.storage(),
        .wal_path = "wal.jq",
        .max_cache_bytes = 1 << 20,
        .max_cache_entries = 64,
        .n_workers = 1,
    });
    defer c2.deinitNoFlush();
    try testing.expectEqual(@as(usize, 0), c2.pendingCount()); // the harvest acked it
}

/// A sink that asks the WAL to reap expired leases from inside every write: a
/// correct coordinator holds its lease for the visibility timeout, so nothing
/// is ever reaped. Only for the single-threaded paths (`recover`, `flushOneSync`).
const ProbeSink = struct {
    inner: MapSink,
    coord: ?*Coordinator = null,
    reaped: usize = 0,

    fn vWrite(ptr: *anyopaque, key: []const u8, value: []const u8) anyerror!void {
        const self: *ProbeSink = @ptrCast(@alignCast(ptr));
        if (self.coord) |c| self.reaped += try c.wal.reapExpiredLeases();
        return MapSink.vWrite(&self.inner, key, value);
    }
    fn vDelete(ptr: *anyopaque, key: []const u8) anyerror!void {
        const self: *ProbeSink = @ptrCast(@alignCast(ptr));
        return MapSink.vDelete(&self.inner, key);
    }
    const vt = Sink.VTable{ .write = vWrite, .delete = vDelete };

    fn open(probe: *ProbeSink, threaded: *std.Io.Threaded, wal_sim: *SimStorage) !*Coordinator {
        return Coordinator.init(testing.allocator, .{
            .io = threaded.io(),
            .sink = .{ .ptr = probe, .vtable = &vt },
            .wal_store = wal_sim.storage(),
            .wal_path = "wal.jq",
            .max_cache_bytes = 1 << 20,
            .max_cache_entries = 64,
            .n_workers = 1,
        });
    }
};

test "every path holds its WAL lease for the visibility timeout while the sink is written" {
    var threaded = std.Io.Threaded.init(testing.allocator, .{});
    defer threaded.deinit();
    var wal_sim = SimStorage.init(testing.allocator);
    defer wal_sim.deinit();
    var probe: ProbeSink = .{ .inner = MapSink.init(testing.allocator) };
    defer probe.inner.deinit();

    // recover()
    {
        const c = try probe.open(&threaded, &wal_sim);
        try c.put("a", "1");
        try c.put("b", "2");
        c.deinitNoFlush();
    }
    {
        const c = try probe.open(&threaded, &wal_sim);
        probe.coord = c;
        try c.recover();
        probe.coord = null;
        try testing.expectEqual(@as(usize, 0), probe.reaped);
        try testing.expectEqual(@as(usize, 2), probe.inner.count());
        c.deinitNoFlush();
    }
    // flushOneSync()
    {
        const c = try probe.open(&threaded, &wal_sim);
        try c.put("p", "1");
        try c.put("q", "2");
        c.deinitNoFlush();
    }
    {
        const c = try probe.open(&threaded, &wal_sim);
        probe.coord = c;
        try testing.expect(c.flushOneSync());
        probe.coord = null;
        try testing.expectEqual(@as(usize, 0), probe.reaped);
        try c.flushAll();
        c.deinitNoFlush();
    }
    // the pool path: a finished flush that has not been pumped still holds its lease
    {
        const c = try probe.open(&threaded, &wal_sim);
        defer c.deinit();
        try c.put("k", "v");
        c.drain();
        try waitCompletion(c);
        try testing.expectEqual(@as(usize, 0), try c.wal.reapExpiredLeases());
    }
}

test "flushOneSync applies a WAL delete as a delete" {
    var rig: Rig = undefined;
    rig.init();
    defer rig.deinit();
    {
        const c = try rig.open(1);
        try c.put("k", "v");
        try c.flushAll();
        try c.del("k");
        c.deinitNoFlush();
    }
    try testing.expectEqualStrings("v", rig.sink.peek("k").?);
    const c2 = try rig.open(1);
    defer c2.deinit();
    try c2.flushAll(); // the cache is empty: the delete goes through flushOneSync
    try testing.expect(rig.sink.peek("k") == null);
}

test "a key of exactly the WAL field cap is accepted by put and del; del counts as pending" {
    var rig: Rig = undefined;
    rig.init();
    defer rig.deinit();
    const c = try rig.open(1);
    defer c.deinit();
    try c.put(strRepeat("x", jobqueue.max_field_len), "v");
    try c.del(strRepeat("y", jobqueue.max_field_len));
    try testing.expectEqual(@as(usize, 2), c.pendingCount());
    try testing.expectError(error.KeyTooLarge, c.del(strRepeat("z", jobqueue.max_field_len + 1)));
    try testing.expectEqual(@as(usize, 2), c.pendingCount());
}

test "a delete honours max_flush_attempts: dead-lettered after exactly that many rejections" {
    var rig: FailRig = undefined;
    rig.init(.{ .gpa = testing.allocator, .fail_delete = true });
    defer rig.deinit();
    const c = try rig.open(2);
    defer c.deinit();
    try c.del("k");
    try c.flushAll();
    try testing.expectEqual(@as(usize, 1), c.poisonedCount());
    const dead = try c.poisoned(testing.allocator);
    defer Coordinator.freePoisoned(testing.allocator, dead);
    try testing.expectEqual(@as(usize, 1), dead.len);
    try testing.expectEqual(@as(u32, 2), dead[0].attempts);
}

test "finishTask: a landed flush cleans the key and clears its marks before the next kick" {
    var rig: Rig = undefined;
    rig.init();
    defer rig.deinit();
    const c = try rig.open(1);
    defer c.deinit();
    try c.put("k", "v");
    c.drain();
    try waitCompletion(c);
    c.pump();
    try testing.expect(!c.cache.isDirty("k"));
    try c.del("d");
    c.drain();
    try waitCompletion(c);
    try testing.expect(c.orphans.contains("d"));
    try testing.expect(c.tombstones.contains("d"));
    c.pump();
    try testing.expect(!c.orphans.contains("d"));
    try testing.expect(!c.tombstones.contains("d"));
}

test "finishTask: a dead-lettered record also cleans the key and clears its marks at once" {
    var rig: FailRig = undefined;
    rig.init(.{ .gpa = testing.allocator, .reject_key = "bad", .fail_delete = true });
    defer rig.deinit();
    const c = try rig.open(1);
    defer c.deinit();
    try c.put("bad", "x");
    c.drain();
    try waitCompletion(c);
    c.pump();
    try testing.expectEqual(@as(usize, 1), c.poisonedCount());
    try testing.expect(!c.cache.isDirty("bad"));
    try c.del("gone");
    c.drain();
    try waitCompletion(c);
    try testing.expect(c.orphans.contains("gone"));
    c.pump();
    try testing.expectEqual(@as(usize, 2), c.poisonedCount());
    try testing.expect(!c.orphans.contains("gone"));
}

test "init: n_workers and max_submitters reach the pool; deinit flushes everything" {
    var rig: Rig = undefined;
    rig.init();
    defer rig.deinit();
    {
        const c = try rig.open(1);
        try testing.expectEqual(@as(usize, 1), c.pool.workerCount());
        // The coordinator submits only through the shared path (contract).
        try testing.expectError(error.TooManySubmitters, c.pool.registerSubmitter());
        try c.put("a", "1");
        try c.put("b", "2");
        c.deinit(); // no explicit flush: deinit is the graceful barrier
    }
    try testing.expectEqualStrings("1", rig.sink.peek("a").?);
    try testing.expectEqualStrings("2", rig.sink.peek("b").?);
}

/// A sink whose writes block until released, to hold a pool worker busy while
/// more flush jobs queue up behind it.
const GateSink = struct {
    inner: MapSink,
    io: std.Io,
    open: std.atomic.Value(bool) = .init(false),
    entered: std.atomic.Value(u32) = .init(0),
    writes: std.atomic.Value(u32) = .init(0),

    fn vWrite(ptr: *anyopaque, key: []const u8, value: []const u8) anyerror!void {
        const self: *GateSink = @ptrCast(@alignCast(ptr));
        _ = self.entered.fetchAdd(1, .acq_rel);
        var spins: u32 = 0;
        while (!self.open.load(.acquire) and spins < 2000) : (spins += 1)
            self.io.sleep(.fromMilliseconds(5), .awake) catch {};
        _ = self.writes.fetchAdd(1, .acq_rel);
        return MapSink.vWrite(&self.inner, key, value);
    }
    fn vDelete(ptr: *anyopaque, key: []const u8) anyerror!void {
        const self: *GateSink = @ptrCast(@alignCast(ptr));
        return MapSink.vDelete(&self.inner, key);
    }
    const vt = Sink.VTable{ .write = vWrite, .delete = vDelete };

    fn openLater(self: *GateSink) void {
        self.io.sleep(.fromMilliseconds(100), .awake) catch {};
        self.open.store(true, .release);
    }
};

test "deinitNoFlush discards queued flush jobs: only the running write finishes" {
    var threaded = std.Io.Threaded.init(testing.allocator, .{});
    defer threaded.deinit();
    var wal_sim = SimStorage.init(testing.allocator);
    defer wal_sim.deinit();
    var gs: GateSink = .{ .inner = MapSink.init(testing.allocator), .io = threaded.io() };
    defer gs.inner.deinit();
    // wbmut-2 (fixed 2026-11-19): the tasks of the jobs the pool drops unrun
    // (task, key, value: three allocations each) used to leak; the leak-checked
    // allocator now proves `deinitNoFlush` frees them.
    const c = try Coordinator.init(testing.allocator, .{
        .io = threaded.io(),
        .sink = .{ .ptr = &gs, .vtable = &GateSink.vt },
        .wal_store = wal_sim.storage(),
        .wal_path = "wal.jq",
        .max_cache_bytes = 1 << 20,
        .max_cache_entries = 64,
        .n_workers = 1,
    });
    try c.put("a", "1");
    try c.put("b", "2");
    try c.put("c", "3");
    c.drain(); // three jobs for the single worker, which blocks in the first
    var spins: usize = 0;
    while (gs.entered.load(.acquire) == 0 and spins < 2000) : (spins += 1)
        threaded.io().sleep(.fromMilliseconds(5), .awake) catch {};
    try testing.expectEqual(@as(u32, 1), gs.entered.load(.acquire));
    const t = try std.Thread.spawn(.{}, GateSink.openLater, .{&gs});
    c.deinitNoFlush(); // shutdownNow: the running job finishes, the queued two are dropped
    t.join();
    try testing.expectEqual(@as(u32, 1), gs.writes.load(.acquire));
    try testing.expectEqual(@as(usize, 1), gs.inner.count());
}

test "deinitNoFlush: a harvested flush that advances its key meets a stopped pool, not a freed one" {
    var rig: Rig = undefined;
    rig.init();
    defer rig.deinit();
    {
        const c = try rig.open(1);
        try c.put("k", "old");
        try c.put("k", "new");
        c.drain(); // single flight per key: only "old" is submitted
        try waitCompletion(c);
        // The harvest inside deinitNoFlush acks "old" and hands "new" to
        // startFlush, whose submit must find the pool stopped (and give the
        // lease back), not already freed.
        c.deinitNoFlush();
    }
    try testing.expectEqualStrings("old", rig.sink.peek("k").?);
    const c2 = try rig.open(1);
    defer c2.deinit();
    try testing.expectEqual(@as(usize, 1), c2.pendingCount());
    try c2.recover();
    try testing.expectEqualStrings("new", rig.sink.peek("k").?);
}

test "a record in a persisted WAL backoff (a WAL from before 2026-11-19) is counted at reopen and flushed once visible" {
    // Older versions nacked with a WAL-side backoff, which the WAL persists.
    // Such a record is pending (`readyCount` includes records whose `run_at`
    // lies ahead), so `pendingCount` reports it, `flushAll` waits for it, and
    // it lands once its time has come -- through recover(), the synchronous
    // path, or a pool flush started for its key.
    const hour: u64 = 3600 * std.time.ns_per_s;
    var path: usize = 0;
    while (path < 3) : (path += 1) {
        var rig: FailRig = undefined;
        rig.init(.{ .gpa = testing.allocator });
        defer rig.deinit();
        var clk: FakeClock = .{};
        {
            const c = try openWith(&rig, &clk, .{});
            _ = try c.wal.enqueue("put", "v", .{ .partition = "k", .delay_ns = hour });
            c.deinitNoFlush();
        }
        const c = try openWith(&rig, &clk, .{ .flush_timeout_ns = 30 * std.time.ns_per_ms });
        defer c.deinit();
        try testing.expectEqual(@as(usize, 1), c.pendingCount());
        try testing.expectError(error.FlushIncomplete, c.flushAll()); // hidden: waited for, not dropped
        try testing.expectEqual(@as(usize, 1), c.pendingCount());
        _ = clk.ns.fetchAdd(hour + 1, .monotonic);
        switch (path) {
            0 => try c.recover(),
            1 => try testing.expect(c.flushOneSync()),
            else => {
                c.startKey("k");
                try testing.expectEqual(@as(usize, 1), c.inFlightCount());
                try c.flushAll();
            },
        }
        try testing.expectEqual(@as(usize, 0), c.pendingCount());
        try testing.expectEqual(@as(usize, 0), c.inFlightCount());
        try testing.expectEqualStrings("v", rig.sink.get("k").?);
    }
}

test "back-pressure does not retry a key early: its synchronous backstop waits for the retry backoff too" {
    var rig: FailRig = undefined;
    rig.init(.{ .gpa = testing.allocator, .fail_n = 1 });
    defer rig.deinit();
    var clk: FakeClock = .{};
    const hour: u64 = 3600 * std.time.ns_per_s;
    const c = try openWith(&rig, &clk, .{
        .backoff_ns = hour,
        .max_unflushed = 1,
        .put_block_ns = 30 * std.time.ns_per_ms,
    });
    defer c.deinit();
    try c.put("k", "v");
    c.drain();
    try waitCompletion(c);
    c.drain(); // rejected: "k" waits an hour
    try testing.expectError(error.Backpressure, c.put("x", "1"));
    try testing.expectEqual(@as(usize, 1), rig.sink.seen); // not retried early
    _ = clk.ns.fetchAdd(hour + 1, .monotonic);
    try c.put("x", "1"); // the retry lands and makes room
    try testing.expectEqualStrings("v", rig.sink.get("k").?);
}

/// A reopened WAL holding `puts` (key, value) in order: none of its keys is
/// cache-dirty, so only the synchronous backstop reaches them.
fn reopenWithPuts(rig: *FailRig, clk: *FakeClock, puts: []const [2][]const u8, o: OpenWith) !*Coordinator {
    {
        const c = try openWith(rig, clk, .{});
        for (puts) |kvp| try c.put(kvp[0], kvp[1]);
        c.deinitNoFlush();
    }
    return openWith(rig, clk, o);
}

test "F5b: a key waiting out its retry backoff no longer stalls the synchronous backstop for the other keys" {
    var rig: FailRig = undefined;
    rig.init(.{ .gpa = testing.allocator });
    defer rig.deinit();
    var clk: FakeClock = .{};
    const hour: u64 = 3600 * std.time.ns_per_s;
    // cap 2: a single attempt counted for a pass-over would dead-letter "a".
    const c = try reopenWithPuts(&rig, &clk, &.{ .{ "a", "1" }, .{ "b", "2" }, .{ "a", "3" } }, .{
        .backoff_ns = hour,
        .cap = 2,
        .flush_timeout_ns = 100 * std.time.ns_per_ms,
    });
    defer c.deinit();
    rig.sink.reject_key = "a";
    try testing.expect(!c.flushOneSync()); // a's oldest is rejected: "a" waits an hour
    try testing.expect(waitsNow(c, "a"));
    rig.sink.reject_key = null;
    // flushAll's backstop passes "a" over (both of its records) and lands "b";
    // before 2026-11-19 it did not run at all while "a" waited.
    try testing.expectError(error.FlushIncomplete, c.flushAll());
    try testing.expectEqualStrings("2", rig.sink.get("b").?);
    try testing.expect(rig.sink.get("a") == null); // not retried early
    try testing.expectEqual(@as(usize, 2), rig.sink.seen);
    try testing.expectEqual(@as(usize, 2), c.pendingCount());
    // Every passed-over lease went back: nothing leased, nothing counted.
    try testing.expectEqual(@as(usize, 0), c.wal.leasedCount());
    try testing.expectEqual(@as(usize, 0), c.skipped.items.len);
    try testing.expectEqual(@as(usize, 0), c.held.items.len);
    try testing.expectEqual(@as(usize, 0), c.poisonedCount());
    // Once the wait is over, "a" lands in WAL order: the newer value wins.
    _ = clk.ns.fetchAdd(hour + 1, .monotonic);
    try c.flushAll();
    try testing.expectEqualStrings("3", rig.sink.get("a").?);
    try testing.expectEqual(@as(usize, 0), c.pendingCount());
    try testing.expectEqual(@as(usize, 0), c.poisonedCount());
}

test "F5b: back-pressure makes room through another key while one key waits out its backoff" {
    var rig: FailRig = undefined;
    rig.init(.{ .gpa = testing.allocator });
    defer rig.deinit();
    var clk: FakeClock = .{};
    const hour: u64 = 3600 * std.time.ns_per_s;
    const c = try reopenWithPuts(&rig, &clk, &.{ .{ "a", "1" }, .{ "b", "2" } }, .{
        .backoff_ns = hour,
        .max_unflushed = 2,
        .put_block_ns = 30 * std.time.ns_per_ms,
    });
    defer c.deinit();
    rig.sink.reject_key = "a";
    try testing.expect(!c.flushOneSync()); // "a" waits an hour
    rig.sink.reject_key = null;
    try c.put("x", "9"); // at the mark: "b" lands synchronously and makes room
    try testing.expectEqualStrings("2", rig.sink.get("b").?);
    try testing.expect(rig.sink.get("a") == null);
    try testing.expectEqual(@as(usize, 2), rig.sink.seen);
    _ = clk.ns.fetchAdd(hour + 1, .monotonic);
}

test "F5b: a pass-over whose release fails is held, blocks its key and is released by the next drain, no attempt counted" {
    var rig: FailRig = undefined;
    rig.init(.{ .gpa = testing.allocator });
    defer rig.deinit();
    var clk: FakeClock = .{};
    // cap 1: one counted attempt would dead-letter the record.
    const c = try reopenWithPuts(&rig, &clk, &.{.{ "a", "1" }}, .{ .cap = 1 });
    defer c.deinit();
    const lease = (try c.wal.dequeue(.{ .visibility_timeout_ns = std.time.ns_per_s })).?;
    // `release` needs room in the WAL's schedule heap; take it away and fail
    // the allocation.
    c.wal.pending.items.clearAndFree(c.wal.gpa);
    var fa = std.testing.FailingAllocator.init(testing.allocator, .{ .fail_index = 0 });
    const wal_gpa = c.wal.gpa;
    c.wal.gpa = fa.allocator();
    c.releaseOne(lease);
    c.wal.gpa = wal_gpa;
    try testing.expect(fa.has_induced_failure);
    try testing.expectEqual(@as(usize, 1), c.held.items.len);
    try testing.expect(c.held.items[0].kind == .release_failed);
    try testing.expectEqual(@as(usize, 1), c.wal.leasedCount());
    c.startKey("a"); // held: the pool path leaves the key alone
    try testing.expectEqual(@as(usize, 0), c.inFlightCount());
    c.releaseHeld(false); // what every drain does first
    try testing.expectEqual(@as(usize, 0), c.held.items.len);
    try testing.expectEqual(@as(usize, 0), c.wal.leasedCount());
    try c.flushAll();
    try testing.expectEqualStrings("1", rig.sink.get("a").?);
    try testing.expectEqual(@as(usize, 0), c.poisonedCount());
}

test "F5b: no room to pass a waiting key over ends the synchronous pass with its lease returned" {
    var rig: FailRig = undefined;
    rig.init(.{ .gpa = testing.allocator });
    defer rig.deinit();
    var clk: FakeClock = .{};
    const hour: u64 = 3600 * std.time.ns_per_s;
    const c = try reopenWithPuts(&rig, &clk, &.{ .{ "a", "1" }, .{ "b", "2" } }, .{ .backoff_ns = hour, .cap = 2 });
    defer c.deinit();
    rig.sink.reject_key = "a";
    try testing.expect(!c.flushOneSync()); // "a" waits an hour
    rig.sink.reject_key = null;
    c.skipped.clearAndFree(c.gpa);
    var fa = std.testing.FailingAllocator.init(testing.allocator, .{ .fail_index = 0 });
    const gpa = c.gpa;
    c.gpa = fa.allocator();
    const res = c.syncFlush(false);
    c.gpa = gpa;
    try testing.expect(fa.has_induced_failure);
    try testing.expectEqual(Coordinator.SyncResult.none, res);
    try testing.expectEqual(@as(usize, 0), c.wal.leasedCount()); // given back
    try testing.expectEqual(@as(usize, 1), rig.sink.seen); // "b" waits for the next pass
    try testing.expect(c.flushOneSync()); // which lands it
    try testing.expectEqualStrings("2", rig.sink.get("b").?);
    _ = clk.ns.fetchAdd(hour + 1, .monotonic);
}

/// Whether `key` waits out a retry backoff now (read-only: unlike
/// `retryWaiting`, a lapsed entry is left in place).
fn waitsNow(c: *Coordinator, key: []const u8) bool {
    const at = c.retry_at.get(key) orelse return false;
    return c.mono.now() < at;
}

test "the synchronous path keeps the per-key retry deadlines exact: cleared on landing and on dead-lettering, moved on a new rejection" {
    var rig: FailRig = undefined;
    rig.init(.{ .gpa = testing.allocator, .fail_n = 3 });
    defer rig.deinit();
    var clk: FakeClock = .{};
    const hour: u64 = 3600 * std.time.ns_per_s;
    const c = try openWith(&rig, &clk, .{ .backoff_ns = hour, .cap = 3 });
    defer c.deinit();
    try c.put("k", "v");
    c.drain();
    try waitCompletion(c);
    c.drain(); // first rejection (pool path): "k" waits an hour
    try testing.expect(waitsNow(c, "k"));
    _ = clk.ns.fetchAdd(hour + 1, .monotonic);
    try testing.expect(!waitsNow(c, "k"));
    // Second rejection, on the synchronous path: the lapsed deadline moves on.
    try testing.expect(!c.flushOneSync());
    try testing.expect(waitsNow(c, "k"));
    _ = clk.ns.fetchAdd(hour + 1, .monotonic);
    // Third rejection dead-letters it (cap 3): nothing is left waiting.
    try testing.expect(!c.flushOneSync());
    try testing.expectEqual(@as(usize, 1), c.poisonedCount());
    try testing.expectEqual(@as(usize, 0), c.retry_at.count());
    // A landed record clears its key's lapsed deadline as well.
    try c.put("j", "w");
    c.drain();
    try waitCompletion(c);
    c.drain(); // fail_n is spent: "j" lands
    try testing.expectEqualStrings("w", rig.sink.get("j").?);
    try c.put("m", "1");
    rig.sink.reject_key = "m";
    c.drain();
    try waitCompletion(c);
    c.drain(); // "m" rejected: waits
    rig.sink.reject_key = null;
    _ = clk.ns.fetchAdd(hour + 1, .monotonic);
    try testing.expect(c.flushOneSync()); // lands through the synchronous path
    try testing.expectEqual(@as(usize, 0), c.retry_at.count());
    try testing.expectEqualStrings("1", rig.sink.get("m").?);
}

test "last-writer-wins: a rejected synchronous write is never retried over a newer record of its key (review F1)" {
    var rig: FailRig = undefined;
    rig.init(.{ .gpa = testing.allocator, .fail_n = 1 });
    defer rig.deinit();
    var clk: FakeClock = .{};
    {
        const c = try openWith(&rig, &clk, .{});
        try c.put("A", "v1");
        try c.put("A", "v2");
        try c.put("B", "b");
        c.deinitNoFlush();
    }
    const c = try openWith(&rig, &clk, .{});
    defer c.deinit();
    // Synchronous path: A's first record is rejected; the newer one must win.
    try c.flushAll();
    try testing.expectEqualStrings("v2", rig.sink.get("A").?);
    try testing.expectEqualStrings("b", rig.sink.get("B").?);
    try testing.expectEqual(@as(usize, 0), c.pendingCount());
}

test "a refused pool submit is counted when the WAL dead-letters it (review F4)" {
    var rig: FailRig = undefined;
    rig.init(.{ .gpa = testing.allocator });
    defer rig.deinit();
    var clk: FakeClock = .{};
    const c = try openWith(&rig, &clk, .{ .cap = 1 });
    defer c.deinitNoFlush();
    try c.put("k", "v");
    c.pool.shutdownNow(); // every submit fails
    c.drain();
    try testing.expectEqual(@as(usize, 1), c.poisonedCount());
    try testing.expectEqual(@as(usize, 0), c.pendingCount());
}

test "a dispatch that fails on allocation is counted when the WAL dead-letters it (review F4)" {
    var i: usize = 0;
    while (i < 6) : (i += 1) {
        var rig: FailRig = undefined;
        rig.init(.{ .gpa = testing.allocator });
        defer rig.deinit();
        var clk: FakeClock = .{};
        const c = try openWith(&rig, &clk, .{ .cap = 1, .flush_timeout_ns = 200 * std.time.ns_per_ms });
        defer c.deinit();
        try c.put("k", "v");
        var fa = std.testing.FailingAllocator.init(testing.allocator, .{ .fail_index = i });
        c.gpa = fa.allocator();
        c.drain();
        c.gpa = testing.allocator;
        // Either the flush went out, or its single attempt was burnt by the
        // failed dispatch and the record is dead-lettered: never left pending.
        try c.flushAll();
        try testing.expectEqual(@as(usize, 0), c.pendingCount());
        const landed: usize = if (rig.sink.get("k") != null) 1 else 0;
        try testing.expectEqual(@as(usize, 1), landed + c.poisonedCount());
    }
}

test "a failed nack keeps the record held: no newer record of its key overtakes it (review F3)" {
    var rig: FailRig = undefined;
    rig.init(.{ .gpa = testing.allocator, .fail_n = 1 });
    defer rig.deinit();
    var clk: FakeClock = .{};
    const c = try openWith(&rig, &clk, .{ .flush_timeout_ns = 2 * std.time.ns_per_s });
    defer c.deinit();
    try c.put("k", "v1");
    try c.put("k", "v2");
    c.drain(); // v1 to the pool; the sink rejects it
    try waitCompletion(c);
    // The harvest's nack fails (the WAL's next allocation): v1 stays leased.
    var fa = std.testing.FailingAllocator.init(testing.allocator, .{ .fail_index = 0 });
    const wal_gpa = c.wal.gpa;
    c.wal.gpa = fa.allocator();
    c.drain();
    c.wal.gpa = wal_gpa;
    try testing.expect(fa.has_induced_failure);
    try testing.expectEqual(@as(usize, 1), c.held.items.len);
    // The same drain's kick did not dequeue v2 past it.
    try testing.expectEqual(@as(usize, 0), c.inFlightCount());
    try testing.expect(rig.sink.get("k") == null);
    // The next drain nacks it again and starts it (v1, not v2).
    c.drain();
    try testing.expectEqual(@as(usize, 0), c.held.items.len);
    try testing.expectEqual(@as(usize, 1), c.inFlightCount());
    try c.flushAll();
    try testing.expectEqual(@as(usize, 0), c.held.items.len);
    try testing.expectEqualStrings("v2", rig.sink.get("k").?);
    try testing.expectEqual(@as(usize, 0), c.pendingCount());
}

test "a key with a held synchronous rejection is not started by the pool path, and a newer landed record supersedes it" {
    var rig: FailRig = undefined;
    rig.init(.{ .gpa = testing.allocator, .fail_n = 1 });
    defer rig.deinit();
    var clk: FakeClock = .{};
    {
        const c = try openWith(&rig, &clk, .{});
        try c.put("A", "v1");
        try c.put("A", "v2");
        c.deinitNoFlush();
    }
    const c = try openWith(&rig, &clk, .{});
    defer c.deinit();
    try testing.expectEqual(Coordinator.SyncResult.held, c.syncFlush(true)); // v1 rejected, held
    try c.addKeySet(&c.orphans, "A");
    c.drain();
    try testing.expectEqual(@as(usize, 0), c.inFlightCount()); // A is blocked
    try testing.expectEqual(Coordinator.SyncResult.landed, c.syncFlush(true)); // v2 lands
    try testing.expectEqual(@as(usize, 0), c.held.items.len); // v1 superseded (acked)
    try testing.expectEqual(@as(usize, 0), c.pendingCount());
    try c.flushAll();
    try testing.expectEqualStrings("v2", rig.sink.get("A").?);
    try testing.expectEqual(@as(usize, 2), rig.sink.seen);
}

test "a record dead-lettered while an older one of its key is held does not advance the key past it" {
    var rig: FailRig = undefined;
    rig.init(.{ .gpa = testing.allocator, .fail_n = 2 });
    defer rig.deinit();
    var clk: FakeClock = .{};
    const c = try openWith(&rig, &clk, .{ .cap = 1 });
    defer c.deinit();
    try c.put("k", "v1");
    try c.put("k", "v2");
    try c.put("k", "v3");
    c.drain(); // v1 to the pool, rejected
    try waitCompletion(c);
    var fa = std.testing.FailingAllocator.init(testing.allocator, .{ .fail_index = 0 });
    const wal_gpa = c.wal.gpa;
    c.wal.gpa = fa.allocator();
    c.drain(); // its nack fails: v1 held
    c.wal.gpa = wal_gpa;
    try testing.expectEqual(@as(usize, 1), c.held.items.len);
    // The synchronous path takes v2 (v1 is leased), the sink rejects it, and
    // the cap of 1 dead-letters it: v3 must still wait behind v1.
    try testing.expect(!c.flushOneSync());
    try testing.expectEqual(@as(usize, 1), c.poisonedCount());
    try testing.expectEqual(@as(usize, 0), c.inFlightCount());
    try c.flushAll();
    try testing.expectEqualStrings("v3", rig.sink.get("k").?);
    try testing.expectEqual(@as(usize, 0), c.pendingCount());
}

test "acks go oldest first per key: a crash after a failed ack of a superseded record replays it before the newer one (a)" {
    // The WAL must never keep an older record of a key whose newer one it no
    // longer has: a restart would replay the old value over the new one.
    var rig: FailRig = undefined;
    rig.init(.{ .gpa = testing.allocator, .fail_n = 1 });
    defer rig.deinit();
    var clk: FakeClock = .{};
    {
        const c = try openWith(&rig, &clk, .{});
        try c.put("A", "v1");
        try c.put("A", "v2");
        c.deinitNoFlush();
    }
    {
        const c = try openWith(&rig, &clk, .{});
        try testing.expectEqual(Coordinator.SyncResult.held, c.syncFlush(true)); // v1 rejected
        // v2 lands; the store's allocations fail from the second one on (the
        // allocator stays failed), so exactly one of the two acks succeeds.
        var fa = std.testing.FailingAllocator.init(testing.allocator, .{ .fail_index = 1 });
        const db_gpa = c.wal.db.gpa;
        c.wal.db.gpa = fa.allocator();
        try testing.expectEqual(Coordinator.SyncResult.landed, c.syncFlush(true));
        c.wal.db.gpa = db_gpa;
        try testing.expect(fa.has_induced_failure);
        try testing.expectEqualStrings("v2", rig.sink.get("A").?);
        c.deinitNoFlush(); // crash before any retry
    }
    rig.sink.fail_n = 0;
    const c = try openWith(&rig, &clk, .{});
    defer c.deinit();
    try c.recover();
    try testing.expectEqualStrings("v2", rig.sink.get("A").?);
    try testing.expectEqual(@as(usize, 0), c.pendingCount());
}

test "acks go oldest first per key: a failed ack on the pool path blocks the key until it is retried (b)" {
    var rig: FailRig = undefined;
    rig.init(.{ .gpa = testing.allocator });
    defer rig.deinit();
    var clk: FakeClock = .{};
    {
        const c = try openWith(&rig, &clk, .{});
        try c.put("k", "v1");
        try c.put("k", "v2");
        c.drain(); // v1 to the pool
        try waitCompletion(c);
        // The harvest's ack of v1 fails: v2 must not go (and be acked) first.
        var fa = std.testing.FailingAllocator.init(testing.allocator, .{ .fail_index = 0 });
        const db_gpa = c.wal.db.gpa;
        c.wal.db.gpa = fa.allocator();
        c.drain();
        c.wal.db.gpa = db_gpa;
        try testing.expect(fa.has_induced_failure);
        try testing.expectEqual(@as(usize, 0), c.inFlightCount());
        try testing.expectEqual(@as(usize, 2), c.pendingCount());
        try testing.expectEqualStrings("v1", rig.sink.get("k").?);
        c.deinitNoFlush(); // crash: both records are still in the WAL
    }
    const c = try openWith(&rig, &clk, .{});
    defer c.deinit();
    try testing.expectEqual(@as(usize, 2), c.pendingCount());
    try c.recover();
    try testing.expectEqualStrings("v2", rig.sink.get("k").?);
    // And without a crash the retried ack lets the key move on.
    try c.put("j", "w1");
    try c.put("j", "w2");
    c.drain();
    try waitCompletion(c);
    var fa = std.testing.FailingAllocator.init(testing.allocator, .{ .fail_index = 0 });
    const db_gpa = c.wal.db.gpa;
    c.wal.db.gpa = fa.allocator();
    c.drain();
    c.wal.db.gpa = db_gpa;
    try c.flushAll();
    try testing.expectEqualStrings("w2", rig.sink.get("j").?);
    try testing.expectEqual(@as(usize, 0), c.pendingCount());
}

test "an ack that keeps failing ends flushAll and deinit at the deadline, the record kept in the WAL" {
    var rig: FailRig = undefined;
    rig.init(.{ .gpa = testing.allocator });
    defer rig.deinit();
    var clk: FakeClock = .{};
    {
        const c = try openWith(&rig, &clk, .{ .flush_timeout_ns = 60 * std.time.ns_per_ms });
        try c.put("k", "v");
        c.drain();
        try waitCompletion(c);
        var fa = std.testing.FailingAllocator.init(testing.allocator, .{ .fail_index = 0 });
        const db_gpa = c.wal.db.gpa;
        c.wal.db.gpa = fa.allocator(); // the store's writes fail from here on
        try testing.expectError(error.FlushIncomplete, c.flushAll());
        try testing.expectEqual(@as(usize, 1), c.pendingCount());
        try testing.expectEqual(@as(usize, 1), c.held.items.len);
        c.deinit(); // bounded by the same deadline
        _ = db_gpa;
    }
    const c = try openWith(&rig, &clk, .{});
    defer c.deinit();
    try testing.expectEqual(@as(usize, 1), c.pendingCount());
    try c.recover();
    try testing.expectEqualStrings("v", rig.sink.get("k").?);
}

/// Fails exactly one allocation (the `skip`-th after arming, 0-based) and
/// forwards every other one. `std.testing.FailingAllocator` keeps failing
/// after its first failure; the ack-order tests need an older ack to fail
/// while a newer one succeeds.
const OneShotFail = struct {
    child: Allocator,
    skip: usize,
    fired: bool = false,

    fn allocator(self: *OneShotFail) Allocator {
        return .{ .ptr = self, .vtable = &vt };
    }
    const vt = Allocator.VTable{ .alloc = alloc, .resize = resize, .remap = remap, .free = free };
    fn alloc(ctx: *anyopaque, len: usize, alignment: std.mem.Alignment, ra: usize) ?[*]u8 {
        const self: *OneShotFail = @ptrCast(@alignCast(ctx));
        if (!self.fired) {
            if (self.skip == 0) {
                self.fired = true;
                return null;
            }
            self.skip -= 1;
        }
        return self.child.rawAlloc(len, alignment, ra);
    }
    fn resize(ctx: *anyopaque, memory: []u8, alignment: std.mem.Alignment, new_len: usize, ra: usize) bool {
        const self: *OneShotFail = @ptrCast(@alignCast(ctx));
        return self.child.rawResize(memory, alignment, new_len, ra);
    }
    fn remap(ctx: *anyopaque, memory: []u8, alignment: std.mem.Alignment, new_len: usize, ra: usize) ?[*]u8 {
        const self: *OneShotFail = @ptrCast(@alignCast(ctx));
        return self.child.rawRemap(memory, alignment, new_len, ra);
    }
    fn free(ctx: *anyopaque, memory: []u8, alignment: std.mem.Alignment, ra: usize) void {
        const self: *OneShotFail = @ptrCast(@alignCast(ctx));
        self.child.rawFree(memory, alignment, ra);
    }
};

/// A reopened WAL holding `vals` as the records of key "A", in order.
fn reopenWithRecords(rig: *FailRig, clk: *FakeClock, vals: []const []const u8) !*Coordinator {
    {
        const c = try openWith(rig, clk, .{});
        for (vals) |v| try c.put("A", v);
        c.deinitNoFlush();
    }
    return openWith(rig, clk, .{});
}

test "ack order: the newest landed record is acked only after every older one of its key" {
    // Older held records are superseded by v3 and must be acked; v1's ack
    // fails once. v3 must then stay in the WAL (held) and the key must not
    // advance, so a crash replays v1 .. v3 and ends at v3.
    var rig: FailRig = undefined;
    rig.init(.{ .gpa = testing.allocator, .fail_n = 2 });
    defer rig.deinit();
    var clk: FakeClock = .{};
    {
        const c = try reopenWithRecords(&rig, &clk, &.{ "v1", "v2", "v3", "v4" });
        try testing.expectEqual(Coordinator.SyncResult.held, c.syncFlush(true)); // v1
        try testing.expectEqual(Coordinator.SyncResult.held, c.syncFlush(true)); // v2
        var os: OneShotFail = .{ .child = c.wal.db.gpa, .skip = 0 };
        const db_gpa = c.wal.db.gpa;
        c.wal.db.gpa = os.allocator();
        try testing.expectEqual(Coordinator.SyncResult.landed, c.syncFlush(true)); // v3
        c.wal.db.gpa = db_gpa;
        try testing.expect(os.fired);
        try testing.expectEqualStrings("v3", rig.sink.get("A").?);
        // Nothing of A goes on (v4 waits), and every held entry is an ack now.
        try testing.expectEqual(@as(usize, 0), c.inFlightCount());
        for (c.held.items) |h| try testing.expect(h.kind == .ack_failed);
        // The retry: v1's ack fails once more, v2 and v3 must wait for it.
        var os2: OneShotFail = .{ .child = c.wal.db.gpa, .skip = 0 };
        c.wal.db.gpa = os2.allocator();
        c.releaseHeld(false);
        c.wal.db.gpa = db_gpa;
        try testing.expect(os2.fired);
        c.deinitNoFlush(); // crash
    }
    const c = try openWith(&rig, &clk, .{});
    defer c.deinit();
    // No ack went through out of order: all four records are still there.
    try testing.expectEqual(@as(usize, 4), c.pendingCount());
    try c.recover();
    try testing.expectEqualStrings("v4", rig.sink.get("A").?);
    try testing.expectEqual(@as(usize, 0), c.pendingCount());
}

test "ack order: a superseded record whose ack fails is never written again" {
    var rig: FailRig = undefined;
    rig.init(.{ .gpa = testing.allocator, .fail_n = 1 });
    defer rig.deinit();
    var clk: FakeClock = .{};
    const c = try reopenWithRecords(&rig, &clk, &.{ "v1", "v2" });
    defer c.deinit();
    try testing.expectEqual(Coordinator.SyncResult.held, c.syncFlush(true)); // v1 rejected
    var os: OneShotFail = .{ .child = c.wal.db.gpa, .skip = 0 };
    const db_gpa = c.wal.db.gpa;
    c.wal.db.gpa = os.allocator();
    try testing.expectEqual(Coordinator.SyncResult.landed, c.syncFlush(true)); // v2; v1's ack fails
    c.wal.db.gpa = db_gpa;
    try c.flushAll();
    try testing.expectEqualStrings("v2", rig.sink.get("A").?);
    try testing.expectEqual(@as(usize, 2), rig.sink.seen); // v1 never rewritten
    try testing.expectEqual(@as(usize, 0), c.pendingCount());
}

test "ack order: a pool flush handed on by the synchronous path continues after its held ack" {
    var rig: FailRig = undefined;
    rig.init(.{ .gpa = testing.allocator });
    defer rig.deinit();
    var clk: FakeClock = .{};
    const c = try reopenWithRecords(&rig, &clk, &.{ "v1", "v2", "v3" });
    defer c.deinit();
    try testing.expect(c.flushOneSync()); // v1; v2 goes to the pool
    try testing.expectEqual(@as(usize, 1), c.inFlightCount());
    try waitCompletion(c);
    var os: OneShotFail = .{ .child = c.wal.db.gpa, .skip = 0 };
    const db_gpa = c.wal.db.gpa;
    c.wal.db.gpa = os.allocator();
    c.drain(); // v2's ack fails: held, the key waits
    c.wal.db.gpa = db_gpa;
    try testing.expect(os.fired);
    try testing.expectEqual(@as(usize, 0), c.inFlightCount());
    c.drain(); // the ack is retried and the key (not in the cache) moves on to v3
    try testing.expectEqual(@as(usize, 1), c.inFlightCount());
    try c.flushAll();
    try testing.expectEqualStrings("v3", rig.sink.get("A").?);
}

test "ack order: a synchronous landing whose ack is held lets drain() continue the key" {
    var rig: FailRig = undefined;
    rig.init(.{ .gpa = testing.allocator });
    defer rig.deinit();
    var clk: FakeClock = .{};
    const c = try reopenWithRecords(&rig, &clk, &.{ "v1", "v2" });
    defer c.deinit();
    var os: OneShotFail = .{ .child = c.wal.db.gpa, .skip = 0 };
    const db_gpa = c.wal.db.gpa;
    c.wal.db.gpa = os.allocator();
    try testing.expectEqual(Coordinator.SyncResult.landed, c.syncFlush(false)); // v1, ack held
    c.wal.db.gpa = db_gpa;
    try testing.expectEqual(@as(usize, 0), c.inFlightCount());
    c.drain(); // ack retried; the key moves on to v2 through the pool
    try testing.expectEqual(@as(usize, 1), c.inFlightCount());
    try c.flushAll();
    try testing.expectEqualStrings("v2", rig.sink.get("A").?);
}

test "ack order: recover() holds a failed ack instead of acking the newer record past it" {
    var rig: FailRig = undefined;
    rig.init(.{ .gpa = testing.allocator });
    defer rig.deinit();
    var clk: FakeClock = .{};
    {
        const c = try reopenWithRecords(&rig, &clk, &.{ "v1", "v2" });
        var os: OneShotFail = .{ .child = c.wal.db.gpa, .skip = 0 };
        const db_gpa = c.wal.db.gpa;
        c.wal.db.gpa = os.allocator();
        try c.recover(); // v1's ack fails; v2 lands, its ack retries v1's first
        c.wal.db.gpa = db_gpa;
        try testing.expect(os.fired);
        c.deinitNoFlush();
    }
    const c = try openWith(&rig, &clk, .{});
    defer c.deinitNoFlush();
    try testing.expectEqual(@as(usize, 0), c.pendingCount());
    try testing.expectEqualStrings("v2", rig.sink.get("A").?);
}

test "a held ack is retried as an ack, never as a nack (no attempt burnt on a landed record)" {
    var rig: FailRig = undefined;
    rig.init(.{ .gpa = testing.allocator });
    defer rig.deinit();
    var clk: FakeClock = .{};
    const c = try openWith(&rig, &clk, .{ .cap = 1 });
    defer c.deinit();
    try c.put("k", "v");
    c.drain();
    try waitCompletion(c);
    var os: OneShotFail = .{ .child = c.wal.db.gpa, .skip = 0 };
    const db_gpa = c.wal.db.gpa;
    c.wal.db.gpa = os.allocator();
    c.drain(); // the ack fails: held
    c.wal.db.gpa = db_gpa;
    try testing.expect(os.fired);
    try c.flushAll();
    try testing.expectEqual(@as(usize, 0), c.wal.deadLetterCount());
    try testing.expectEqual(@as(usize, 0), c.pendingCount());
    try testing.expectEqual(@as(usize, 1), rig.sink.seen);
}

test "an older record landing never acks a NEWER held record of its key (review2 N1)" {
    // R1 and R2 of one key are both rejected and held; releasing them, R1's
    // nack succeeds (visible again) but R2's fails (still held). R1 then
    // lands: R2 is newer, so it must stay held, be released, and be written.
    var skip: usize = 0;
    var hits: usize = 0;
    while (skip < 8) : (skip += 1) {
        var rig: FailRig = undefined;
        rig.init(.{ .gpa = testing.allocator, .fail_n = 2 });
        defer rig.deinit();
        var clk: FakeClock = .{};
        const c = try reopenWithRecords(&rig, &clk, &.{ "v1", "v2" });
        defer c.deinit();
        try testing.expectEqual(Coordinator.SyncResult.held, c.syncFlush(true));
        try testing.expectEqual(Coordinator.SyncResult.held, c.syncFlush(true));
        var os: OneShotFail = .{ .child = c.wal.gpa, .skip = skip };
        const wal_gpa = c.wal.gpa;
        c.wal.gpa = os.allocator();
        c.releaseHeld(true);
        c.wal.gpa = wal_gpa;
        const r2_held = c.held.items.len == 1 and c.held.items[0].kind == .nack_failed and
            std.mem.eql(u8, c.held.items[0].lease.payload, "v2");
        if (r2_held) {
            hits += 1;
            // R1 is visible again and lands; R2 stays held and counted.
            try testing.expectEqual(Coordinator.SyncResult.landed, c.syncFlush(true));
            try testing.expectEqualStrings("v1", rig.sink.get("A").?);
            try testing.expectEqual(@as(usize, 1), c.held.items.len);
            try testing.expectEqual(@as(usize, 1), c.pendingCount());
            try testing.expectEqual(@as(usize, 0), c.inFlightCount());
        }
        try c.flushAll();
        try testing.expectEqualStrings("v2", rig.sink.get("A").?);
        try testing.expectEqual(@as(usize, 0), c.pendingCount());
    }
    try testing.expect(hits > 0);
}

test "deinitNoFlush burns no attempt on the records it cannot dispatch any more (review2 N3)" {
    var rig: FailRig = undefined;
    rig.init(.{ .gpa = testing.allocator });
    defer rig.deinit();
    var clk: FakeClock = .{};
    {
        const c = try openWith(&rig, &clk, .{ .cap = 1 });
        try c.put("k", "v1");
        try c.put("k", "v2");
        try c.put("k", "v3");
        c.drain(); // v1 to the pool
        try waitCompletion(c);
        // The harvest acks v1 and would hand v2 to the stopped pool.
        c.deinitNoFlush();
    }
    const c = try openWith(&rig, &clk, .{ .cap = 1 });
    defer c.deinit();
    try testing.expectEqual(@as(usize, 0), c.wal.deadLetterCount());
    try testing.expectEqual(@as(usize, 2), c.pendingCount());
    try c.flushAll();
    try testing.expectEqualStrings("v3", rig.sink.get("k").?);
}

test "a dispatch that keeps failing dead-letters a key's records one after the other, in a loop" {
    var rig: FailRig = undefined;
    rig.init(.{ .gpa = testing.allocator });
    defer rig.deinit();
    var clk: FakeClock = .{};
    const c = try openWith(&rig, &clk, .{ .cap = 1 });
    defer c.deinitNoFlush();
    var i: usize = 0;
    while (i < 50) : (i += 1) try c.put("k", "v");
    c.pool.shutdownNow(); // every submit is refused (a live coordinator, not a teardown)
    c.drain();
    try testing.expectEqual(@as(usize, 50), c.poisonedCount());
    try testing.expectEqual(@as(usize, 0), c.pendingCount());
    try testing.expectEqual(@as(usize, 0), c.held.items.len);
}

test "superseded held records are acked by WAL id, whatever their order in the held list" {
    // The held list is not in id order once a failed nack re-appends an
    // entry at its end (e.g. [R2 rejected, R1 nack_failed]). When R3 lands
    // and the oldest ack fails, every older entry must turn into a pending
    // ack; none may be left to be released and rewritten over R3.
    var rig: FailRig = undefined;
    rig.init(.{ .gpa = testing.allocator, .fail_n = 2 });
    defer rig.deinit();
    var clk: FakeClock = .{};
    const c = try reopenWithRecords(&rig, &clk, &.{ "v1", "v2", "v3" });
    defer c.deinit();
    try testing.expectEqual(Coordinator.SyncResult.held, c.syncFlush(true));
    try testing.expectEqual(Coordinator.SyncResult.held, c.syncFlush(true));
    std.mem.swap(Held, &c.held.items[0], &c.held.items[1]); // [R2, R1]
    var os: OneShotFail = .{ .child = c.wal.db.gpa, .skip = 0 };
    const db_gpa = c.wal.db.gpa;
    c.wal.db.gpa = os.allocator();
    try testing.expectEqual(Coordinator.SyncResult.landed, c.syncFlush(true)); // v3; R1's ack fails
    c.wal.db.gpa = db_gpa;
    try testing.expect(os.fired);
    for (c.held.items) |h| try testing.expect(h.kind == .ack_failed);
    try c.flushAll();
    try testing.expectEqualStrings("v3", rig.sink.get("A").?);
    try testing.expectEqual(@as(usize, 3), rig.sink.seen);
    try testing.expectEqual(@as(usize, 0), c.pendingCount());
}

test "deinit after a timed-out flushAll burns no attempt on a record it can no longer dispatch" {
    var threaded = std.Io.Threaded.init(testing.allocator, .{});
    defer threaded.deinit();
    var wal_sim = SimStorage.init(testing.allocator);
    defer wal_sim.deinit();
    var gs: GateSink = .{ .inner = MapSink.init(testing.allocator), .io = threaded.io() };
    defer gs.inner.deinit();
    {
        const c = try Coordinator.init(testing.allocator, .{
            .io = threaded.io(),
            .sink = .{ .ptr = &gs, .vtable = &GateSink.vt },
            .wal_store = wal_sim.storage(),
            .wal_path = "wal.jq",
            .max_cache_bytes = 1 << 20,
            .max_cache_entries = 64,
            .n_workers = 1,
            .max_flush_attempts = 1,
            .flush_timeout_ns = 20 * std.time.ns_per_ms,
        });
        try c.put("a", "1");
        try c.put("a", "2");
        try testing.expectError(error.FlushIncomplete, c.flushAll()); // "1" blocks in the sink
        const t = try std.Thread.spawn(.{}, GateSink.openLater, .{&gs});
        defer t.join();
        // The final harvest acks "1" and would hand "2" to the drained pool.
        c.deinit();
    }
    var sink = MapSink.init(testing.allocator);
    defer sink.deinit();
    const c2 = try Coordinator.init(testing.allocator, .{
        .io = threaded.io(),
        .sink = sink.sink(),
        .wal_store = wal_sim.storage(),
        .wal_path = "wal.jq",
        .max_cache_bytes = 1 << 20,
        .max_cache_entries = 64,
        .n_workers = 1,
        .max_flush_attempts = 1,
    });
    defer c2.deinit();
    try testing.expectEqual(@as(usize, 0), c2.wal.deadLetterCount());
    try testing.expectEqual(@as(usize, 1), c2.pendingCount());
}
