// SPDX-License-Identifier: MIT

//! shardstore — a key-sharding router over N independent `kvtree` stores, the
//! multi-core WRITE-parallelism answer for the data layer.
//!
//! A single `kvtree` is a copy-on-write B-tree with a **single-writer** commit
//! path: correct and crash-safe, but one durable writer at a time, so it cannot
//! absorb multi-core write throughput on its own. The classic scale-out is to
//! **shard by key** across N independent `kvtree` instances — each its own
//! single-writer domain backed by its own file — so writes to *different* shards
//! proceed fully in parallel with no lock between them. This module is that
//! router: a stable key hash picks the owning shard; `put`/`get`/`delete`
//! delegate to it. It is a *stateless* router — the shard array is immutable
//! after `init` — so it adds **no** cross-shard coordination of its own.
//!
//! ## Threading contract (exactly what this guarantees — and what it does not)
//!
//! Each shard inherits `kvtree`'s contract verbatim: **one writer at a time per
//! shard**, with lockless MVCC readers. This router does not widen that:
//!
//! - Operations on **distinct** shards are independent — two threads writing
//!   keys that hash to different shards never contend (separate `kvtree.Db`
//!   state, separate files, no shared mutable router state). This is the whole
//!   point of sharding, and the design naturally encourages partitioning work
//!   by shard.
//! - Operations on the **same** shard are bounded by `kvtree`'s single-writer
//!   rule: the caller MUST serialize concurrent writers to the same shard. This
//!   router adds no latch to do that for you — `shardFor` is exposed precisely
//!   so a caller can partition work and route a dedicated thread per shard.
//! - **…and all of that is conditional on the injected `Storage`.** The router
//!   and the `Db`s above it hold no shared mutable state, but every operation
//!   ultimately lands in the backend, and two shards' operations meet there.
//!   Cross-shard parallelism is real only over a backend that is itself safe
//!   for concurrent operations on **distinct handles**. `FsStorage` is
//!   (per-handle `pread`/`pwrite`; its `files` array is written only by
//!   `open`/`close`, which the caller does single-threaded); `SimStorage` is
//!   **not** (plain `StringHashMapUnmanaged`/`ArrayListUnmanaged` plus a
//!   non-atomic `ops_seen`). This precondition used to be unstated, and the
//!   module's own headline test violated it — see `Options.storage_concurrency`,
//!   which now makes it part of the API and enforces it.
//!
//! We do NOT claim more safety than `kvtree` provides. `kvtree` is
//! `single_owner` (one thread/loop owns a `Db`'s mutation state, lock-free); a
//! stateless key-router over N of them is therefore per-shard single-owner and
//! cross-shard parallel — no more, no less.
//!
//! ## `n_shards` is immutable for the life of the data
//!
//! Routing reduces the key hash modulo `n_shards`, so changing the shard count
//! re-routes essentially every key: the data is still on disk but the router
//! looks for it in the wrong file. That used to be silent — reopening four
//! shards' worth of data with `n_shards = 8` simply read empty for ~half the
//! keys. A tiny `"<name_prefix>.manifest"` file now records the shard count at
//! creation and a mismatched reopen fails with `error.ShardCountMismatch`.
//! Incremental resharding (Redis Cluster's 16 384 fixed hash slots, or a
//! consistent-hashing ring) is a design this module does **not** implement.

const std = @import("std");
const Allocator = std.mem.Allocator;
const kvtree = @import("kvtree");

pub const meta = .{
    // The module catalog's one-line entry. This IS the source of truth:
    // README.md's table is rendered from it by `zig build gen-catalog`.
    .doc = "Key-sharding router over N independent `kvtree` stores — multi-core write parallelism (per-shard single-writer, cross-shard parallel)",
    // The catalog's Platform cell. Prose, because it carries nuance the
    // `platform` enum below cannot -- "any (packer: linux)", "amd64 asm +
    // portable fallback". Rendered by `gen-catalog` alongside `doc`.
    .platform_note = "any",
    .targets = .{.linux64},
    .platform = .any, // all I/O via kvtree → kv's Storage seam (std.Io)
    .role = .both, // sharded read+write store router
    // Per-shard single-owner (kvtree's contract), cross-shard parallel. The
    // router itself holds only immutable-after-init state; it adds no locking.
    // The caller serializes same-shard writers (the sharded design encourages
    // partitioning work by shard so this falls out naturally).
    .concurrency = .single_owner,
    .model_after = "consistent key-sharding over N single-writer stores (Redis Cluster / Dynamo partitioning idea)",
    .deps = .{"kvtree"},
};

// ── re-exports: the storage seam, so consumers wire a backend without also
// importing `kvtree`/`kv` directly ───────────────────────────────────────────

pub const Storage = kvtree.Storage;
pub const FsStorage = kvtree.FsStorage;
pub const SimStorage = kvtree.SimStorage;
/// The per-shard store type, exposed for advanced per-shard use (transactions,
/// snapshots, ordered cursors) via `shardAt`/`shardFor`.
pub const Db = kvtree.Db;

// ── errors ───────────────────────────────────────────────────────────────────

pub const InitError = kvtree.OpenError || Allocator.Error || error{
    /// `options.n_shards` was 0 — a store needs at least one shard.
    InvalidShardCount,
    /// The generated shard file name did not fit the format buffer (prefix +
    /// suffix too long).
    ShardNameTooLong,
    /// The store's manifest records a different `n_shards` than this `init`
    /// asked for. Routing is `hash % n_shards`, so opening with the wrong count
    /// would look for existing keys in the wrong shard files and silently read
    /// empty for most of them. Reopen with the recorded count.
    ShardCountMismatch,
    /// The manifest file exists but is not a shardstore manifest (bad magic) or
    /// is shorter than one record — a torn creation, or a name collision with
    /// some other file. Refused rather than overwritten.
    CorruptManifest,
};

/// Raised by a routed operation on a `.single_thread` store called from a
/// thread other than its owner. See `Options.storage_concurrency`.
pub const OwnerError = error{NotOwningThread};

/// Errors from a routed write (`put`/`delete`) — `kvtree`'s, plus the
/// owning-thread check.
pub const WriteError = kvtree.CommitError || Allocator.Error || OwnerError;
/// Errors from a routed read (`get`) — `kvtree`'s, plus the owning-thread
/// check.
pub const GetError = kvtree.GetError || OwnerError;

// ── Options ──────────────────────────────────────────────────────────────────

pub const Options = struct {
    /// Number of independent shards. Each becomes its own `kvtree` file and its
    /// own single-writer domain. A power of two lets routing use a cheap mask
    /// instead of a modulo, but any `n_shards >= 1` is accepted.
    n_shards: usize,
    /// Shard files are named `"<name_prefix>-<index:0>5><name_suffix>"` and
    /// resolved by the injected `Storage` (for `FsStorage`, relative to its
    /// `dir`). E.g. defaults yield `shard-00000.kvt` … `shard-0000N.kvt`.
    name_prefix: []const u8 = "shard",
    name_suffix: []const u8 = ".kvt",
    /// What the injected `Storage` guarantees about **concurrent** use. This is
    /// the module's central precondition, not a tuning knob: cross-shard write
    /// parallelism is a property of the composition, and the composition is only
    /// as parallel as the backend underneath it.
    storage_concurrency: StorageConcurrency = .single_thread,
};

/// The concurrency contract of the injected `Storage`. Defaults to the
/// conservative value: declaring `.parallel_per_handle` for a backend that is
/// not is silent undefined behaviour, while declaring `.single_thread` for one
/// that is costs only a lost opportunity.
pub const StorageConcurrency = enum {
    /// The backend is **not** safe for concurrent use — e.g. `SimStorage`,
    /// whose `files`/`log` are plain unmanaged containers and whose `ops_seen`
    /// is a non-atomic counter. The whole `Store` is then a single-thread
    /// object, and that is **enforced**: `put`/`get`/`delete` from any thread
    /// other than the owner return `error.NotOwningThread` rather than
    /// corrupting the backend. (`init` records the calling thread as the owner;
    /// `adoptOwner` hands the store to another thread explicitly.)
    single_thread,
    /// The backend is safe for concurrent operations on **distinct handles**,
    /// each shard having its own — e.g. `FsStorage`, where every operation is a
    /// positional `pread`/`pwrite` on its own `std.Io.File` and the only shared
    /// field, the handle table, is mutated solely by `open`/`close`. Routed
    /// operations then take no latch and no owner check, and threads working on
    /// distinct shards genuinely run in parallel. **The caller still serializes
    /// writers to the same shard** (`kvtree`'s single-writer rule) — partition
    /// work with `shardFor`/`shardAt`.
    parallel_per_handle,
};

// ── manifest: the shard count is part of the on-disk identity ────────────────

const manifest_magic = "SHRDSTOR";
/// magic (8) + n_shards as u64 LE (8).
const manifest_len = manifest_magic.len + 8;

/// A per-thread token that is unique to the calling thread and costs a TLS
/// address computation rather than a `gettid` syscall: the address of a
/// `threadlocal` is distinct in every thread and stable within one.
threadlocal var thread_marker: u8 = 0;

fn currentThreadToken() usize {
    return @intFromPtr(&thread_marker);
}

// ── Store ────────────────────────────────────────────────────────────────────

pub const Store = struct {
    gpa: Allocator,
    /// One independent single-writer store per shard. Immutable slice after
    /// `init` (never resized), so concurrent access to *distinct* elements is
    /// data-race-free; each element's mutation is bounded by `kvtree`'s rule.
    shards: []Db,
    n_shards: usize,
    /// `n_shards - 1` when `n_shards` is a power of two (routing masks), else
    /// null (routing uses modulo).
    mask: ?u64,
    /// The declared concurrency of the injected backend (`Options`).
    storage_concurrency: StorageConcurrency,
    /// Owning-thread token, meaningful only for `.single_thread` stores.
    owner: usize,
    /// Kept only to close `lock_file` in `deinit` — the `Storage` value
    /// itself is just a `{ctx, vtable}` pair, cheap to hold onto.
    store: Storage,
    /// Handle of the held `"<name_prefix>.lock"` sidecar — see `acquireLock`.
    lock_file: Storage.Handle,

    /// Open (or create) `options.n_shards` independent `kvtree` shards over the
    /// injected `Storage`. On any per-shard open failure, already-opened shards
    /// are closed and nothing leaks.
    ///
    /// A fresh store writes a `"<name_prefix>.manifest"` record; an existing one
    /// is checked against it and `error.ShardCountMismatch` is returned if the
    /// counts differ (see the module doc comment).
    pub fn init(gpa: Allocator, store: Storage, options: Options) InitError!Store {
        if (options.n_shards == 0) return error.InvalidShardCount;

        // Validate the shard-name format fits *before* touching the backend at
        // all — checkManifest/acquireLock below have real side effects (a
        // manifest write, a lock file), and a `name_prefix` long enough to
        // blow the per-shard `"<prefix>-NNNNN<suffix>"` format (but short
        // enough to fit the shorter `.manifest`/`.lock` names) used to reach
        // both of those before failing on shard 0 of the open loop, leaving
        // an orphaned manifest/lock file for a store that will never exist.
        try validateShardNameFits(options);

        try checkManifest(store, options);

        // ONE exclusive lock for the whole store (not one per shard — see
        // `acquireLock`'s doc comment for why).
        const lock_file = try acquireLock(store, options);
        errdefer store.close(lock_file);

        const shards = try gpa.alloc(Db, options.n_shards);
        errdefer gpa.free(shards);

        var opened: usize = 0;
        // Close the shards opened so far if a later open fails.
        errdefer for (shards[0..opened]) |*d| d.close();

        while (opened < options.n_shards) : (opened += 1) {
            var buf: [512]u8 = undefined;
            const path = std.fmt.bufPrint(
                &buf,
                "{s}-{d:0>5}{s}",
                .{ options.name_prefix, opened, options.name_suffix },
            ) catch return error.ShardNameTooLong;
            // `.lock = .none`: exclusion is already held once, above, for the
            // whole store — see `acquireLock`.
            shards[opened] = try Db.open(gpa, store, path, .{ .lock = .none });
        }

        return .{
            .gpa = gpa,
            .shards = shards,
            .n_shards = options.n_shards,
            .mask = if (std.math.isPowerOfTwo(options.n_shards))
                @as(u64, options.n_shards - 1)
            else
                null,
            .storage_concurrency = options.storage_concurrency,
            .owner = currentThreadToken(),
            .store = store,
            .lock_file = lock_file,
        };
    }

    /// Cross-process/cross-instance exclusion for the WHOLE store — one lock
    /// covering every shard, rather than each shard taking its own via
    /// `kvtree.Db.open`'s default `Options.lock == .exclusive`. Per-shard
    /// locking would work too (it is `kvtree`'s default), but it doubles the
    /// handle count per shard (data file + lock sidecar). When this was
    /// written, `FsStorage`'s handle table was fixed at `max_handles == 4`
    /// (sized for one `kv`/`kvtree` store's own data+lock+compaction-temp
    /// needs), so four shards alone would have needed 8 concurrently open
    /// handles over one `FsStorage` and failed. One lock at the `Store` level
    /// gives the identical guarantee this module's F2 finding asked for — a
    /// second `Store` over the same paths gets `error.Locked` with nothing
    /// touched — at the cost of one handle instead of N.
    ///
    /// **That handle constraint is gone, and this is still not debt.**
    /// `a77c388` raised `kv.FsStorage`'s default table to 64 and added
    /// `FsStorageCapacity(n)`, so per-shard locking is no longer *blocked*.
    /// It is simply not better: one store-wide lock is fewer handles, fewer
    /// files, one acquire/release path to reason about, and it already
    /// delivers the exclusion guarantee in full. **Do not re-propose
    /// per-shard locking as a cleanup or a follow-up.** It would buy no
    /// capability this module lacks and would trade a mechanism that works
    /// for N of them that each have to.
    fn acquireLock(store: Storage, options: Options) InitError!Storage.Handle {
        var buf: [512]u8 = undefined;
        const path = std.fmt.bufPrint(&buf, "{s}.lock", .{options.name_prefix}) catch
            return error.ShardNameTooLong;

        const h = try store.open(path, .open_or_create);
        errdefer store.close(h);
        if (!try store.tryLockExclusive(h)) return error.Locked;
        return h;
    }

    /// Dry-run the widest per-shard path (`"<prefix>-NNNNN<suffix>"`, at the
    /// highest shard index this `init` will ever format) into a throwaway
    /// buffer, so a `name_prefix`/`name_suffix` combination that cannot
    /// possibly open any shard is rejected before `checkManifest`/
    /// `acquireLock` write or lock anything.
    fn validateShardNameFits(options: Options) InitError!void {
        var buf: [512]u8 = undefined;
        _ = std.fmt.bufPrint(
            &buf,
            "{s}-{d:0>5}{s}",
            .{ options.name_prefix, options.n_shards - 1, options.name_suffix },
        ) catch return error.ShardNameTooLong;
    }

    /// Create-or-verify the shard-count manifest. Runs **before** any shard is
    /// opened, so a mismatched reopen touches nothing, and the manifest handle
    /// is closed again before the shard loop — `FsStorage` has a small fixed
    /// handle table and the manifest must not spend one of its slots.
    fn checkManifest(store: Storage, options: Options) InitError!void {
        var buf: [512]u8 = undefined;
        const path = std.fmt.bufPrint(&buf, "{s}.manifest", .{options.name_prefix}) catch
            return error.ShardNameTooLong;

        const h = try store.open(path, .open_or_create);
        defer store.close(h);

        const size = try store.size(h);
        if (size == 0) {
            // Fresh store: stamp the count. (A pre-existing store created before
            // manifests were written has no manifest either, so it is adopted
            // with whatever count this call passes — documented in SPEC.md.)
            var rec: [manifest_len]u8 = undefined;
            @memcpy(rec[0..manifest_magic.len], manifest_magic);
            std.mem.writeInt(u64, rec[manifest_magic.len..][0..8], options.n_shards, .little);
            try store.writeAll(h, &rec, 0);
            try store.sync(h);
            try store.syncDir();
            return;
        }
        if (size < manifest_len) return error.CorruptManifest;

        var rec: [manifest_len]u8 = undefined;
        store.preadFull(h, &rec, 0) catch |e| switch (e) {
            error.Corrupt => return error.CorruptManifest,
            else => |other| return other,
        };
        if (!std.mem.eql(u8, rec[0..manifest_magic.len], manifest_magic)) return error.CorruptManifest;
        const recorded = std.mem.readInt(u64, rec[manifest_magic.len..][0..8], .little);
        if (recorded != options.n_shards) return error.ShardCountMismatch;
    }

    /// Transfer ownership of a `.single_thread` store to the calling thread.
    /// The previous owner must be done with it (this is a hand-off, not a lock);
    /// the point is that a store built on the main thread and then run by one
    /// worker thread is legitimate, while two threads at once is not. No-op for
    /// a `.parallel_per_handle` store, which has no single owner.
    pub fn adoptOwner(self: *Store) void {
        self.owner = currentThreadToken();
    }

    /// The owning-thread check for `.single_thread` stores. Two loads and a
    /// compare; no syscall, no atomics, and deterministic — a foreign thread is
    /// rejected whether or not it happens to overlap with the owner, which is
    /// what makes it testable at all.
    inline fn checkOwner(self: *const Store) OwnerError!void {
        if (self.storage_concurrency == .single_thread and currentThreadToken() != self.owner)
            return error.NotOwningThread;
    }

    /// Close every shard, release the store-wide lock, and free the shard
    /// array. No leaks.
    pub fn deinit(self: *Store) void {
        for (self.shards) |*d| d.close();
        self.store.close(self.lock_file);
        self.gpa.free(self.shards);
        self.* = undefined;
    }

    /// The shard index that owns `key`: a stable, dep-free `Wyhash` of the key
    /// reduced to `[0, n_shards)`. Deterministic — the same key always routes to
    /// the same shard, within a run and across `init`s with the same `n_shards`.
    pub fn shardFor(self: *const Store, key: []const u8) usize {
        const h = std.hash.Wyhash.hash(0, key);
        if (self.mask) |m| return @intCast(h & m);
        return @intCast(h % @as(u64, self.n_shards));
    }

    /// The owning shard for `key`, for advanced per-shard use — multi-key ACID
    /// transactions, MVCC snapshots and ordered cursors are all per-shard (a
    /// transaction spanning shards is NOT atomic; keep atomic groups on one
    /// shard by choosing keys that route together, or use one shard).
    pub fn shard(self: *Store, key: []const u8) *Db {
        return &self.shards[self.shardFor(key)];
    }

    /// The shard at `index` (`index < n_shards`), e.g. to drive one dedicated
    /// writer thread per shard.
    pub fn shardAt(self: *Store, index: usize) *Db {
        return &self.shards[index];
    }

    // ── routed operations ────────────────────────────────────────────────────

    /// Autocommit put, routed to the owning shard. Concurrency: safe alongside
    /// puts to *other* shards; same-shard writers must be serialized by the
    /// caller (kvtree's single-writer rule — this router adds no latch).
    pub fn put(self: *Store, key: []const u8, val: []const u8) WriteError!void {
        try self.checkOwner();
        return self.shards[self.shardFor(key)].put(key, val);
    }

    /// Look up `key` in its owning shard's newest committed version. Caller
    /// frees the returned slice with `gpa`.
    pub fn get(self: *Store, gpa: Allocator, key: []const u8) GetError!?[]u8 {
        try self.checkOwner();
        return self.shards[self.shardFor(key)].get(gpa, key);
    }

    /// Autocommit delete, routed to the owning shard. Same concurrency contract
    /// as `put`.
    pub fn delete(self: *Store, key: []const u8) WriteError!void {
        try self.checkOwner();
        return self.shards[self.shardFor(key)].del(key);
    }

    /// A merge-sorted scan over **all** shards: a k-way merge of one
    /// `kvtree.Cursor` per shard, yielding entries in global key order
    /// (bytewise, as `kvtree` orders them) within `options`' range, up to
    /// `options.limit` entries. Call `Scan.next` until it returns null, then
    /// `Scan.deinit` (always — the scan pins a version of every shard).
    ///
    /// **What it sees.** Each shard's cursor is opened here, inside this one
    /// call, and pins that shard's newest committed version (`Db.cursor`'s
    /// reclaim-gate pin). Writes committed after `scan` returns — by the
    /// owner between `next` calls, say — are not visible to this scan, on
    /// any shard; a fresh `scan` sees them. Under the single-owner contract
    /// nothing else can commit while this call runs, so the pinned versions
    /// together are one point-in-time view of the whole store. See
    /// `Scan`'s doc comment for the precise contract and what a
    /// `.parallel_per_handle` caller must do.
    ///
    /// **Agrees with `get`.** An entry is yielded only from the shard that
    /// `shardFor` routes its key to, so the scan yields exactly the
    /// `(key, value)` pairs `get` would return, each key once. A key written
    /// straight into a non-owning shard through `shardAt` is invisible to
    /// `get`, and so to the scan.
    pub fn scan(self: *Store, options: ScanOptions) ScanError!Scan {
        try self.checkOwner();
        return Scan.open(self, options);
    }
};

// ── merge-sorted scan across shards ──────────────────────────────────────────

/// A yielded entry. Both slices borrow the scan's internal buffers and are
/// valid only until the next `Scan.next` or `Scan.deinit` call — copy them to
/// keep them (`kvtree.KV`'s rule, which this is).
pub const KV = kvtree.KV;

/// One end of a scan range, the way `kvtree.Cursor` positions: `seek(key)`
/// starts at the first key `>= key` (inclusive), `seekAfter(key)` at the
/// first key `> key` (exclusive).
pub const Bound = union(enum) {
    /// No bound on this side: from the first key / to the last key.
    unbounded,
    /// The bound key itself is in range.
    inclusive: []const u8,
    /// The bound key itself is not in range.
    exclusive: []const u8,
};

pub const ScanDirection = enum {
    /// Ascending key order (`kvtree.Cursor.next`).
    forward,
    /// Descending key order (`kvtree.Cursor.prev`).
    reverse,
};

pub const ScanOptions = struct {
    /// Lower end of the range (the smaller keys), whatever the direction.
    start: Bound = .unbounded,
    /// Upper end of the range (the larger keys), whatever the direction. A
    /// range whose `start` lies above its `end` is empty, not an error.
    end: Bound = .unbounded,
    /// Yield at most this many entries; null for no limit. In `.reverse`
    /// order this keeps the LARGEST `limit` keys of the range.
    limit: ?usize = null,
    direction: ScanDirection = .forward,
};

/// Errors from `Store.scan` and `Scan.next`: `kvtree`'s read errors (the
/// backend's, `error.Corrupt`, `error.OutOfMemory`) plus the owning-thread
/// check.
pub const ScanError = kvtree.GetError || OwnerError;

/// The iterator `Store.scan` returns.
///
/// ## Consistency contract
///
/// - **Per shard: a snapshot.** Every shard is read at the version that was
///   newest when `Store.scan` ran. Commits made after that — puts, overwrites,
///   deletes — never appear in, disappear from, or change the value of what
///   this scan yields, and the pinned pages stay readable however much is
///   committed meanwhile (`kvtree`'s reclaim gate). The flip side, also
///   `kvtree`'s: an open scan holds back page reclamation in every shard, so
///   `deinit` it promptly.
/// - **Across shards: one cut, because there is one owner.** All N cursors are
///   opened inside the single `Store.scan` call. On a `.single_thread` store
///   (enforced, as for `put`/`get`) no commit can land between two of those
///   opens, so the scan is a consistent point-in-time view of the whole store.
///   This is a consequence of the single-owner model, not a cross-shard
///   snapshot mechanism — `shardstore` has none (no cross-shard atomicity).
/// - **`.parallel_per_handle` stores.** A `kvtree.Db` is single-owner: opening
///   and releasing a cursor mutates the shard's reader list, and reading pages
///   goes through the shard's pager. So `Store.scan`, every `next` and `deinit`
///   must be serialized with the writers of EVERY shard — the scan is an
///   operation on all of them. Do that (pause the per-shard writers, or run the
///   scan on a thread that owns them all) and the cut above holds. Commits
///   made *between* `next` calls are fine and invisible, as above. Running a
///   scan concurrently with a per-shard writer thread is a data race this
///   module cannot detect for `.parallel_per_handle` (it takes no latch).
/// - **Order and uniqueness.** Keys come out strictly ascending (`.forward`) or
///   strictly descending (`.reverse`), each at most once, each from its owning
///   shard (see `Store.scan`). Shards are disjoint by routing, so the merge
///   never has to break a tie.
/// - **Errors are sticky.** After `next` returns an error the scan stays
///   failed and returns the same error again — it never resumes with a gap.
pub const Scan = struct {
    gpa: Allocator,
    store: *const Store,
    /// One cursor per shard; `cursors[i]` reads `store.shards[i]`.
    cursors: []kvtree.Cursor,
    /// The entry each cursor is currently offering, or null once it is
    /// exhausted or past the far bound. Borrowed from `cursors[i]`.
    heads: []?KV,
    /// Indices of cursors with a non-null head, as a binary heap ordered by
    /// head key (min-heap forward, max-heap reverse).
    heap: []u32,
    heap_len: usize = 0,
    /// The cursor whose head the last `next` yielded. It is advanced at the
    /// start of the following `next`, so the yielded slices stay valid until
    /// then.
    pending: ?u32 = null,
    /// The bound where the scan stops (the far end in scan direction): an
    /// owned copy, so the caller's bound slice need not outlive `scan`.
    stop_key: ?[]u8,
    stop_inclusive: bool,
    direction: ScanDirection,
    remaining: usize,
    failed: ?ScanError = null,

    fn open(store: *Store, options: ScanOptions) ScanError!Scan {
        const gpa = store.gpa;
        const n = store.n_shards;

        const stop: Bound = switch (options.direction) {
            .forward => options.end,
            .reverse => options.start,
        };
        const stop_key: ?[]u8 = switch (stop) {
            .unbounded => null,
            .inclusive, .exclusive => |k| try gpa.dupe(u8, k),
        };
        errdefer if (stop_key) |k| gpa.free(k);

        const cursors = try gpa.alloc(kvtree.Cursor, n);
        errdefer gpa.free(cursors);
        const heads = try gpa.alloc(?KV, n);
        errdefer gpa.free(heads);
        const heap = try gpa.alloc(u32, n);
        errdefer gpa.free(heap);

        var self: Scan = .{
            .gpa = gpa,
            .store = store,
            .cursors = cursors,
            .heads = heads,
            .heap = heap,
            .stop_key = stop_key,
            .stop_inclusive = stop == .inclusive,
            .direction = options.direction,
            .remaining = options.limit orelse std.math.maxInt(usize),
        };

        // Open every shard's cursor first, back to back: this is the moment
        // the scan's view of the store is fixed (see the contract above).
        var opened: usize = 0;
        errdefer for (cursors[0..opened]) |*c| c.deinit();
        while (opened < n) : (opened += 1) {
            cursors[opened] = try store.shards[opened].cursor();
        }

        if (self.remaining == 0) {
            @memset(heads, null);
            return self;
        }

        for (cursors, 0..) |*c, i| {
            switch (options.direction) {
                .forward => switch (options.start) {
                    .unbounded => try c.first(),
                    .inclusive => |k| try c.seek(k),
                    .exclusive => |k| try c.seekAfter(k),
                },
                .reverse => switch (options.end) {
                    .unbounded => try c.last(),
                    .inclusive => |k| try c.seekAfter(k),
                    .exclusive => |k| try c.seek(k),
                },
            }
            try self.fill(@intCast(i));
            if (self.heads[i] != null) self.push(@intCast(i));
        }
        return self;
    }

    /// Release every shard's pinned version and free the scan's buffers.
    /// Invalidates any `KV` still held from `next`.
    pub fn deinit(self: *Scan) void {
        for (self.cursors) |*c| c.deinit();
        self.gpa.free(self.cursors);
        self.gpa.free(self.heads);
        self.gpa.free(self.heap);
        if (self.stop_key) |k| self.gpa.free(k);
        self.* = undefined;
    }

    /// The next entry in scan order, or null when the range or the limit is
    /// exhausted. The returned slices are valid until the next call to `next`
    /// or `deinit`.
    pub fn next(self: *Scan) ScanError!?KV {
        // Not sticky: a foreign thread's refused call leaves the owner's scan
        // intact.
        try self.store.checkOwner();
        if (self.failed) |e| return e;
        if (self.remaining == 0) return null;
        self.advance() catch |e| {
            self.failed = e;
            return e;
        };
        if (self.heap_len == 0) return null;
        const i = self.pop();
        self.remaining -= 1;
        self.pending = i;
        return self.heads[i].?;
    }

    fn advance(self: *Scan) ScanError!void {
        const i = self.pending orelse return;
        self.pending = null;
        try self.fill(i);
        if (self.heads[i] != null) self.push(i);
    }

    /// Set `heads[i]` to cursor `i`'s next entry that is owned by shard `i`
    /// and inside the far bound, or null.
    fn fill(self: *Scan, i: u32) ScanError!void {
        const c = &self.cursors[i];
        while (true) {
            const e = (switch (self.direction) {
                .forward => try c.next(),
                .reverse => try c.prev(),
            }) orelse break;
            if (self.pastStop(e.key)) break;
            // A key stored in a shard it does not route to is invisible to
            // `get`; skip it so the scan agrees with `get` and stays
            // duplicate-free.
            if (self.store.shardFor(e.key) != i) continue;
            self.heads[i] = e;
            return;
        }
        self.heads[i] = null;
    }

    fn pastStop(self: *const Scan, key: []const u8) bool {
        const b = self.stop_key orelse return false;
        const ord = std.mem.order(u8, key, b);
        return switch (self.direction) {
            .forward => if (self.stop_inclusive) ord == .gt else ord != .lt,
            .reverse => if (self.stop_inclusive) ord == .lt else ord != .gt,
        };
    }

    /// True when cursor `a`'s head comes before cursor `b`'s in scan order.
    fn before(self: *const Scan, a: u32, b: u32) bool {
        const ord = std.mem.order(u8, self.heads[a].?.key, self.heads[b].?.key);
        return switch (self.direction) {
            .forward => ord == .lt,
            .reverse => ord == .gt,
        };
    }

    fn push(self: *Scan, i: u32) void {
        var pos = self.heap_len;
        self.heap_len += 1;
        self.heap[pos] = i;
        while (pos > 0) {
            const parent = (pos - 1) / 2;
            if (!self.before(self.heap[pos], self.heap[parent])) break;
            std.mem.swap(u32, &self.heap[pos], &self.heap[parent]);
            pos = parent;
        }
    }

    fn pop(self: *Scan) u32 {
        const top = self.heap[0];
        self.heap_len -= 1;
        self.heap[0] = self.heap[self.heap_len];
        var pos: usize = 0;
        while (true) {
            const l = 2 * pos + 1;
            if (l >= self.heap_len) break;
            var best = l;
            const r = l + 1;
            if (r < self.heap_len and self.before(self.heap[r], self.heap[l])) best = r;
            if (!self.before(self.heap[best], self.heap[pos])) break;
            std.mem.swap(u32, &self.heap[pos], &self.heap[best]);
            pos = best;
        }
        return top;
    }
};

// ── tests ─────────────────────────────────────────────────────────────────────

test {
    std.testing.refAllDecls(@This());
}

test "F5: a name_prefix too long for the per-shard format is refused before any backend I/O" {
    var sim = SimStorage.init(testing.allocator);
    defer sim.deinit();
    sim.allow_overwrite = true; // kvtree is a COW page store: meta slots overwrite in place

    // Chosen so `"<prefix>.manifest"` (9-byte suffix) and `"<prefix>.lock"`
    // (5-byte suffix) both fit the 512-byte format buffer, but the per-shard
    // `"<prefix>-00000<suffix>"` (10-byte suffix, default `.kvt`) does not —
    // 503 + 9 = 512 (fits), 503 + 10 = 513 (does not). Before this fix,
    // `checkManifest`/`acquireLock` ran to completion on exactly this input
    // (writing a manifest and taking a lock) before the shard-open loop
    // discovered `ShardNameTooLong` on shard 0, leaving those files behind
    // for a store that was never actually created.
    var prefix_buf: [503]u8 = undefined;
    @memset(&prefix_buf, 'a');
    const prefix = prefix_buf[0..503];

    try testing.expectError(
        error.ShardNameTooLong,
        Store.init(testing.allocator, sim.storage(), .{ .n_shards = 1, .name_prefix = prefix }),
    );

    // Nothing was created — validation ran before any manifest write or lock
    // acquisition touched the backend.
    try testing.expectEqual(@as(usize, 0), sim.names.count());
}

const testing = std.testing;

test "smoke: init opens N shards, empty, closes cleanly (SimStorage)" {
    var sim = SimStorage.init(testing.allocator);
    defer sim.deinit();
    sim.allow_overwrite = true; // kvtree is a COW page store: meta slots overwrite in place
    var store = try Store.init(testing.allocator, sim.storage(), .{ .n_shards = 4 });
    defer store.deinit();

    try testing.expectEqual(@as(usize, 4), store.n_shards);
    try testing.expect(store.mask != null); // 4 is a power of two
    const got = try store.get(testing.allocator, "absent");
    try testing.expect(got == null);
}

test "init rejects zero shards" {
    var sim = SimStorage.init(testing.allocator);
    defer sim.deinit();
    sim.allow_overwrite = true; // kvtree is a COW page store: meta slots overwrite in place
    try testing.expectError(error.InvalidShardCount, Store.init(testing.allocator, sim.storage(), .{ .n_shards = 0 }));
}

test "routing is deterministic and stable across store instances" {
    var sim = SimStorage.init(testing.allocator);
    defer sim.deinit();
    sim.allow_overwrite = true; // kvtree is a COW page store: meta slots overwrite in place

    var s1 = try Store.init(testing.allocator, sim.storage(), .{ .n_shards = 8 });

    // Same key → same shard, repeatedly.
    const idx = s1.shardFor("stable-key");
    try testing.expectEqual(idx, s1.shardFor("stable-key"));
    try testing.expectEqual(idx, s1.shardFor("stable-key"));

    // shardFor is a pure function of the key (no I/O), so capture s1's
    // answers before closing it — a second Store now holds an exclusive
    // store-wide lock (see `Store.acquireLock`), so a second live Store over
    // the SAME paths while the first is still open is refused, not merely
    // untested; that used to be the F2 finding (kvtree.Db.open discarded its
    // locking Options entirely). Close s1 first, exactly like any real
    // sequential reopen would.
    var buf: [32]u8 = undefined;
    var want: [200]usize = undefined;
    for (&want, 0..) |*w, n| {
        const k = try std.fmt.bufPrint(&buf, "k-{d}", .{n});
        w.* = s1.shardFor(k);
    }
    s1.deinit();

    // A second store with the same n_shards routes identically (pure hash).
    var s2 = try Store.init(testing.allocator, sim.storage(), .{ .n_shards = 8 });
    defer s2.deinit();
    for (want, 0..) |w, n| {
        const k = try std.fmt.bufPrint(&buf, "k-{d}", .{n});
        try testing.expectEqual(w, s2.shardFor(k));
        try testing.expect(s2.shardFor(k) < 8);
    }
}

test "keys distribute across shards (histogram sanity — hits >1 shard, all shards)" {
    var sim = SimStorage.init(testing.allocator);
    defer sim.deinit();
    sim.allow_overwrite = true; // kvtree is a COW page store: meta slots overwrite in place
    const n_shards = 8;
    var store = try Store.init(testing.allocator, sim.storage(), .{ .n_shards = n_shards });
    defer store.deinit();

    var hist = [_]usize{0} ** n_shards;
    var buf: [32]u8 = undefined;
    for (0..2000) |n| {
        const k = try std.fmt.bufPrint(&buf, "user:{d}", .{n});
        hist[store.shardFor(k)] += 1;
    }
    // Every shard should get a healthy share (expected ~250 each); assert none
    // is empty (spread hits every shard, definitely >1).
    var nonempty: usize = 0;
    for (hist) |c| {
        if (c > 0) nonempty += 1;
        try testing.expect(c > 50); // far from the 250 mean; catches a stuck router
    }
    try testing.expectEqual(@as(usize, n_shards), nonempty);
}

test "round-trip: put→get across shards, delete, values survive reads on other shards" {
    var sim = SimStorage.init(testing.allocator);
    defer sim.deinit();
    sim.allow_overwrite = true; // kvtree is a COW page store: meta slots overwrite in place
    var store = try Store.init(testing.allocator, sim.storage(), .{ .n_shards = 4 });
    defer store.deinit();

    var kbuf: [32]u8 = undefined;
    var vbuf: [32]u8 = undefined;
    // Write a spread of keys (they fan out across all 4 shards).
    for (0..400) |n| {
        const k = try std.fmt.bufPrint(&kbuf, "key-{d}", .{n});
        const v = try std.fmt.bufPrint(&vbuf, "val-{d}", .{n});
        try store.put(k, v);
    }
    // Read every one back through the router.
    for (0..400) |n| {
        const k = try std.fmt.bufPrint(&kbuf, "key-{d}", .{n});
        const want = try std.fmt.bufPrint(&vbuf, "val-{d}", .{n});
        const got = try store.get(testing.allocator, k);
        defer if (got) |g| testing.allocator.free(g);
        try testing.expect(got != null);
        try testing.expectEqualStrings(want, got.?);
    }
    // Delete half; the surviving half (which spans other shards) is untouched.
    for (0..400) |n| {
        if (n % 2 == 0) {
            const k = try std.fmt.bufPrint(&kbuf, "key-{d}", .{n});
            try store.delete(k);
        }
    }
    for (0..400) |n| {
        const k = try std.fmt.bufPrint(&kbuf, "key-{d}", .{n});
        const got = try store.get(testing.allocator, k);
        defer if (got) |g| testing.allocator.free(g);
        if (n % 2 == 0) {
            try testing.expect(got == null);
        } else {
            const want = try std.fmt.bufPrint(&vbuf, "val-{d}", .{n});
            try testing.expectEqualStrings(want, got.?);
        }
    }
}

// ── the headline claim, on a backend that can actually carry it ──────────────
//
// WAVE-2 F1. This test used to drive four threads through ONE `SimStorage`,
// whose state is plain `StringHashMapUnmanaged`/`ArrayListUnmanaged` fields plus
// a NON-ATOMIC `ops_seen`. The audit measured a lost increment (serial 33006 vs
// parallel 33005): the test certifying "no contention" was itself a data race,
// free to pass or to corrupt at the scheduler's whim, and the claim had never
// been exercised on a backend that could support it.
//
// The replacement changes three things.
//  1. It runs over `FsStorage` in a tmpDir — positional per-handle `pread`/
//     `pwrite`, and the one shared field (the handle table) is written only by
//     `open`/`close`, which happen single-threaded in `init`/`deinit`. The
//     backend is declared `.parallel_per_handle`, which is what the module now
//     requires before it will let more than one thread near a `Store`.
//  2. It does not merely check that the data is correct afterwards. Correct
//     data is exactly what a fully SERIALIZED run would also produce, so that
//     assertion alone cannot tell parallelism from its absence — which is how
//     the original claim survived unexamined. A `Storage` shim instead
//     rendezvouses the first backend write of each thread: the barrier opens
//     only when all `n_shards` threads are inside the backend AT THE SAME
//     TIME, on `n_shards` distinct shards, and every arriving thread blocks
//     until then. Put a latch back in the routed path, or any shared mutable
//     state that forces ordering, and the barrier is never met: the shim
//     gives up, sets `timed_out`, and the test fails. That is a deterministic
//     consequence of serialization, not a race we hope to catch in the act.
//     `n_shards` is 3, not 4 — `FsStorage.max_handles == 4` (kv module) plus
//     the one store-wide lock handle `Store.init` now holds for cross-process
//     exclusion (the F2 fix) leaves room for exactly 3 concurrently open
//     shards; see the test itself.
//  3. Three rounds, each re-arming the barrier and rewriting every key, with a
//     full exact-value read-back of all the keys as the correctness oracle —
//     one lost or torn write is one wrong value — under the leak-checking
//     `testing.allocator`. The suite also runs in ReleaseFast, so the same
//     assertions are made against optimized code.

/// A pass-through `Storage` that can prove N threads are simultaneously inside
/// the backend. Only `writeAll` participates; everything else delegates.
const Rendezvous = struct {
    inner: Storage,
    want: u32,
    armed: std.atomic.Value(bool) = .init(false),
    arrived: std.atomic.Value(u32) = .init(0),
    met: std.atomic.Value(bool) = .init(false),
    /// Set when a thread waited out the whole budget without the barrier
    /// opening — i.e. the writes were serialized.
    timed_out: std.atomic.Value(bool) = .init(false),

    /// Yields, so waiting is scheduler-friendly rather than a busy spin; the
    /// budget only ever elapses in the failure case.
    const spin_budget = 400_000;

    fn storage(self: *Rendezvous) Storage {
        return .{ .ctx = self, .vtable = &vtable };
    }

    fn cast(ctx: *anyopaque) *Rendezvous {
        return @ptrCast(@alignCast(ctx));
    }

    fn arm(self: *Rendezvous) void {
        self.arrived.store(0, .release);
        self.met.store(false, .release);
        self.armed.store(true, .release);
    }

    fn disarm(self: *Rendezvous) void {
        self.armed.store(false, .release);
        self.met.store(true, .release);
    }

    fn meet(self: *Rendezvous) void {
        if (!self.armed.load(.acquire)) return;
        if (self.met.load(.acquire)) return;
        // Each caller increments exactly once and then blocks, so the barrier
        // can only open when `want` DISTINCT threads are inside this function.
        if (self.arrived.fetchAdd(1, .acq_rel) + 1 >= self.want) {
            self.met.store(true, .release);
            return;
        }
        var spins: usize = 0;
        while (!self.met.load(.acquire)) : (spins += 1) {
            if (spins >= spin_budget) {
                self.timed_out.store(true, .release);
                self.met.store(true, .release); // let any peers out; the test fails
                return;
            }
            std.Thread.yield() catch std.atomic.spinLoopHint();
        }
    }

    const vtable = Storage.VTable{
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

    fn vOpen(ctx: *anyopaque, path: []const u8, mode: Storage.OpenMode) Storage.Error!Storage.Handle {
        return cast(ctx).inner.open(path, mode);
    }
    fn vSize(ctx: *anyopaque, h: Storage.Handle) Storage.Error!u64 {
        return cast(ctx).inner.size(h);
    }
    fn vPread(ctx: *anyopaque, h: Storage.Handle, buf: []u8, off: u64) Storage.Error!usize {
        return cast(ctx).inner.pread(h, buf, off);
    }
    fn vWriteAll(ctx: *anyopaque, h: Storage.Handle, bytes: []const u8, off: u64) Storage.Error!void {
        const self = cast(ctx);
        self.meet();
        return self.inner.writeAll(h, bytes, off);
    }
    fn vSync(ctx: *anyopaque, h: Storage.Handle) Storage.Error!void {
        return cast(ctx).inner.sync(h);
    }
    fn vTruncate(ctx: *anyopaque, h: Storage.Handle, len: u64) Storage.Error!void {
        return cast(ctx).inner.truncate(h, len);
    }
    fn vClose(ctx: *anyopaque, h: Storage.Handle) void {
        cast(ctx).inner.close(h);
    }
    fn vRename(ctx: *anyopaque, old_path: []const u8, new_path: []const u8) Storage.Error!void {
        return cast(ctx).inner.rename(old_path, new_path);
    }
    fn vDelete(ctx: *anyopaque, path: []const u8) Storage.Error!void {
        return cast(ctx).inner.delete(path);
    }
    fn vSyncDir(ctx: *anyopaque) Storage.Error!void {
        return cast(ctx).inner.syncDir();
    }
    fn vTryLockExclusive(ctx: *anyopaque, h: Storage.Handle) Storage.Error!bool {
        return cast(ctx).inner.tryLockExclusive(h);
    }
};

test "multi-core write parallelism: three writers provably inside the backend at once (FsStorage)" {
    var tmp = testing.tmpDir(.{});
    defer tmp.cleanup();

    // 3, not 4: `FsStorage.max_handles == 4` (kv module) has zero headroom
    // beyond exactly `n_shards` data-file handles, and `Store.init` now also
    // holds one store-wide lock handle for the whole store's lifetime (the
    // F2 fix) — 3 shard handles + 1 lock handle == 4 fits exactly; 4 shards
    // would need 5 and fail with `error.Unexpected` from `FsStorage.vOpen`.
    const n_shards = 3;
    var fs = FsStorage.init(testing.io, tmp.dir);
    var rv = Rendezvous{ .inner = fs.storage(), .want = n_shards };

    var store = try Store.init(testing.allocator, rv.storage(), .{
        .n_shards = n_shards,
        .storage_concurrency = .parallel_per_handle,
    });
    defer store.deinit();

    var arena_state = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena_state.deinit();
    const a = arena_state.allocator();

    // Bucket a pool of keys by their owning shard, so each thread's key set
    // routes only to its own shard (distinct shards ⇒ no cross-thread contention).
    var buckets: [n_shards]std.ArrayList([]const u8) = undefined;
    for (&buckets) |*b| b.* = .empty;
    // Every `put` here is a real `kvtree` COW commit ending in an `fsync`, so
    // the key count is a wall-clock budget, not a coverage knob: the barrier
    // needs one write per thread and the oracle needs every key checked.
    const total_keys = 400;
    for (0..total_keys) |n| {
        const k = try std.fmt.allocPrint(a, "item-{d}", .{n});
        try buckets[store.shardFor(k)].append(a, k);
    }
    // A thread with no keys would never reach the barrier and would time it out
    // for a reason that has nothing to do with parallelism.
    for (buckets) |b| try testing.expect(b.items.len > 0);

    const Worker = struct {
        store: *Store,
        keys: []const []const u8,
        round: usize = 0,
        err: ?anyerror = null,

        fn run(w: *@This()) void {
            var vbuf: [48]u8 = undefined;
            for (w.keys) |k| {
                const v = std.fmt.bufPrint(&vbuf, "V{d}:{s}", .{ w.round, k }) catch {
                    w.err = error.Format;
                    return;
                };
                w.store.put(k, v) catch |e| {
                    w.err = e;
                    return;
                };
            }
        }
    };

    const rounds = 3;
    for (0..rounds) |round| {
        var workers: [n_shards]Worker = undefined;
        for (&workers, 0..) |*w, i| w.* = .{ .store = &store, .keys = buckets[i].items, .round = round };

        rv.arm();
        var threads: [n_shards]std.Thread = undefined;
        for (&threads, 0..) |*t, i| t.* = try std.Thread.spawn(.{}, Worker.run, .{&workers[i]});
        for (&threads) |t| t.join();

        // No worker hit an error.
        for (workers) |w| try testing.expect(w.err == null);
        // THE CLAIM ITSELF: all `n_shards` writers were inside the backend
        // together, on `n_shards` distinct shards. This is what goes red if
        // the routed path ever serializes again.
        try testing.expect(!rv.timed_out.load(.acquire));
        try testing.expect(rv.met.load(.acquire));
    }
    rv.disarm();

    // Every write landed and reads back correctly (single-threaded verify): the
    // last round's value, for all 4000 keys, byte for byte.
    var vbuf: [48]u8 = undefined;
    for (0..total_keys) |n| {
        var kbuf: [32]u8 = undefined;
        const k = try std.fmt.bufPrint(&kbuf, "item-{d}", .{n});
        const want = try std.fmt.bufPrint(&vbuf, "V{d}:{s}", .{ rounds - 1, k });
        const got = try store.get(testing.allocator, k);
        defer if (got) |g| testing.allocator.free(g);
        try testing.expect(got != null);
        try testing.expectEqualStrings(want, got.?);
    }
}

// The other half of F1: the shape that produced the finding — several threads
// through one `SimStorage` — is now REJECTED rather than silently undefined.
// This is the deterministic guard. A foreign thread is refused whether or not it
// happens to overlap with the owner, so unlike a concurrency test it cannot pass
// by luck; rewrite the parallelism test back onto `SimStorage` and it stops
// being UB and starts being a hard error.
test "single_thread backend: a routed call from a foreign thread is refused, not raced" {
    var sim = SimStorage.init(testing.allocator);
    defer sim.deinit();
    sim.allow_overwrite = true; // kvtree is a COW page store: meta slots overwrite in place
    // `.single_thread` is the DEFAULT — the unsafe combination is the one you
    // have to ask for, not the one you get by forgetting.
    var store = try Store.init(testing.allocator, sim.storage(), .{ .n_shards = 4 });
    defer store.deinit();

    try store.put("owned", "ok"); // the owning thread is fine

    const Probe = struct {
        store: *Store,
        put_res: WriteError!void = {},
        get_res: GetError!?[]u8 = null,
        del_res: WriteError!void = {},

        fn run(p: *@This()) void {
            p.put_res = p.store.put("foreign", "x");
            p.get_res = p.store.get(testing.allocator, "owned");
            p.del_res = p.store.delete("owned");
        }
    };
    var probe = Probe{ .store = &store };
    const t = try std.Thread.spawn(.{}, Probe.run, .{&probe});
    t.join();

    try testing.expectError(error.NotOwningThread, probe.put_res);
    try testing.expectError(error.NotOwningThread, probe.get_res);
    try testing.expectError(error.NotOwningThread, probe.del_res);

    // Nothing the foreign thread attempted reached the backend.
    const gone = try store.get(testing.allocator, "foreign");
    try testing.expect(gone == null);
    const survived = try store.get(testing.allocator, "owned");
    defer if (survived) |g| testing.allocator.free(g);
    try testing.expectEqualStrings("ok", survived.?);
}

test "single_thread backend: ownership can be handed over explicitly" {
    var sim = SimStorage.init(testing.allocator);
    defer sim.deinit();
    sim.allow_overwrite = true; // kvtree is a COW page store: meta slots overwrite in place
    var store = try Store.init(testing.allocator, sim.storage(), .{ .n_shards = 2 });
    defer store.deinit();

    const Runner = struct {
        store: *Store,
        err: ?anyerror = null,

        fn run(r: *@This()) void {
            r.store.adoptOwner(); // explicit hand-off: the old owner is done
            r.store.put("handed", "over") catch |e| {
                r.err = e;
            };
        }
    };
    var runner = Runner{ .store = &store };
    const t = try std.Thread.spawn(.{}, Runner.run, .{&runner});
    t.join();
    try testing.expect(runner.err == null);

    // The main thread is no longer the owner and is now the one refused.
    try testing.expectError(error.NotOwningThread, store.put("nope", "x"));
    store.adoptOwner();
    const got = try store.get(testing.allocator, "handed");
    defer if (got) |g| testing.allocator.free(g);
    try testing.expectEqualStrings("over", got.?);
}

test "persistence: data survives reopening the shards (FsStorage over a tmp dir)" {
    var tmp = testing.tmpDir(.{});
    defer tmp.cleanup();

    // 3, not 4: see the multi-core-parallelism test above — `Store.init` now
    // holds one store-wide lock handle for the whole store's lifetime (the
    // F2 fix), and `FsStorage.max_handles == 4` (kv module) has no headroom
    // beyond exactly `n_shards` data-file handles + that one lock handle.
    {
        var fs = FsStorage.init(testing.io, tmp.dir);
        var store = try Store.init(testing.allocator, fs.storage(), .{ .n_shards = 3 });
        defer store.deinit();
        var kbuf: [32]u8 = undefined;
        var vbuf: [32]u8 = undefined;
        for (0..300) |n| {
            const k = try std.fmt.bufPrint(&kbuf, "persist-{d}", .{n});
            const v = try std.fmt.bufPrint(&vbuf, "durable-{d}", .{n});
            try store.put(k, v);
        }
    }

    // Reopen a fresh Store over the SAME dir/paths — durability delegates to
    // kvtree; the same key routes to the same shard file it was written to.
    var fs2 = FsStorage.init(testing.io, tmp.dir);
    var store2 = try Store.init(testing.allocator, fs2.storage(), .{ .n_shards = 3 });
    defer store2.deinit();
    var kbuf: [32]u8 = undefined;
    var vbuf: [32]u8 = undefined;
    for (0..300) |n| {
        const k = try std.fmt.bufPrint(&kbuf, "persist-{d}", .{n});
        const want = try std.fmt.bufPrint(&vbuf, "durable-{d}", .{n});
        const got = try store2.get(testing.allocator, k);
        defer if (got) |g| testing.allocator.free(g);
        try testing.expect(got != null);
        try testing.expectEqualStrings(want, got.?);
    }
}

// WAVE-2 F3. Routing is `hash % n_shards`, so a reopen with a different shard
// count sends every key to the wrong file. Before the manifest this was SILENT:
// the data was still on disk, the router just looked elsewhere, and ~half the
// keys read back as absent — indistinguishable from "never written", after an
// ordinary operational mistake (an operator scaling shards in a config file).
// Fail closed instead: the count is part of the store's on-disk identity.
test "reopen with a different n_shards FAILS instead of silently reading empty" {
    // `SimStorage` deliberately, not `FsStorage`: the latter's handle table
    // holds only 4 files, so a mismatched reopen with MORE shards happens to die
    // on `error.Unexpected` — an accident of the backend that masks the real
    // defect. Growing AND shrinking the count must both be refused on their own
    // merits, and only an unbounded backend shows that.
    var sim = SimStorage.init(testing.allocator);
    defer sim.deinit();
    sim.allow_overwrite = true; // kvtree is a COW page store: meta slots overwrite in place

    {
        var store = try Store.init(testing.allocator, sim.storage(), .{ .n_shards = 4 });
        defer store.deinit();
        var kbuf: [32]u8 = undefined;
        for (0..200) |n| {
            const k = try std.fmt.bufPrint(&kbuf, "reshard-{d}", .{n});
            try store.put(k, "v");
        }
    }

    // Without the manifest check both of these SUCCEED and then read empty for
    // most of the 200 keys (measured: 8 shards → 98/200 found, 2 shards →
    // 88/200 found) — a silent partial data loss after an ordinary
    // config-file mistake. Fail closed instead.
    try testing.expectError(
        error.ShardCountMismatch,
        Store.init(testing.allocator, sim.storage(), .{ .n_shards = 8 }),
    );
    try testing.expectError(
        error.ShardCountMismatch,
        Store.init(testing.allocator, sim.storage(), .{ .n_shards = 2 }),
    );

    // The recorded count still opens, and every key is still there.
    var ok = try Store.init(testing.allocator, sim.storage(), .{ .n_shards = 4 });
    defer ok.deinit();
    var kbuf: [32]u8 = undefined;
    for (0..200) |n| {
        const k = try std.fmt.bufPrint(&kbuf, "reshard-{d}", .{n});
        const got = try ok.get(testing.allocator, k);
        defer if (got) |g| testing.allocator.free(g);
        try testing.expectEqualStrings("v", got.?);
    }
}

test "manifest: a foreign/corrupt file under the manifest name is refused, not overwritten" {
    var sim = SimStorage.init(testing.allocator);
    defer sim.deinit();
    sim.allow_overwrite = true; // kvtree is a COW page store: meta slots overwrite in place

    // Something else already owns "shard.manifest": neither our magic nor our
    // length. Stamping over it would destroy a stranger's file and invent an
    // identity for data we never wrote.
    const store = sim.storage();
    const h = try store.open("shard.manifest", .open_or_create);
    try store.writeAll(h, "not a shardstore manifest at all", 0);
    store.close(h);

    try testing.expectError(
        error.CorruptManifest,
        Store.init(testing.allocator, store, .{ .n_shards = 4 }),
    );

    // A torn/short record is refused too, rather than being treated as fresh.
    const h2 = try store.open("short.manifest", .open_or_create);
    try store.writeAll(h2, "SHRD", 0);
    store.close(h2);
    try testing.expectError(
        error.CorruptManifest,
        Store.init(testing.allocator, store, .{ .n_shards = 4, .name_prefix = "short" }),
    );
}

test "non-power-of-two shard count uses modulo routing and round-trips" {
    var sim = SimStorage.init(testing.allocator);
    defer sim.deinit();
    sim.allow_overwrite = true; // kvtree is a COW page store: meta slots overwrite in place
    var store = try Store.init(testing.allocator, sim.storage(), .{ .n_shards = 5 });
    defer store.deinit();
    try testing.expect(store.mask == null); // 5 is not a power of two → modulo

    var kbuf: [32]u8 = undefined;
    for (0..100) |n| {
        const k = try std.fmt.bufPrint(&kbuf, "m-{d}", .{n});
        try testing.expect(store.shardFor(k) < 5);
        try store.put(k, "x");
    }
    for (0..100) |n| {
        const k = try std.fmt.bufPrint(&kbuf, "m-{d}", .{n});
        const got = try store.get(testing.allocator, k);
        defer if (got) |g| testing.allocator.free(g);
        try testing.expectEqualStrings("x", got.?);
    }
}

// Nothing ran two Stores over one backend at once, so dropping the
// `tryLockExclusive` refusal in `acquireLock` passed every test.
test "a second live Store over the same paths is refused with error.Locked" {
    var sim = SimStorage.init(testing.allocator);
    defer sim.deinit();
    sim.allow_overwrite = true; // kvtree is a COW page store: meta slots overwrite in place
    var first = try Store.init(testing.allocator, sim.storage(), .{ .n_shards = 2 });
    try testing.expectError(error.Locked, Store.init(testing.allocator, sim.storage(), .{ .n_shards = 2 }));
    first.deinit();
    // Released on deinit: the next open succeeds.
    var again = try Store.init(testing.allocator, sim.storage(), .{ .n_shards = 2 });
    again.deinit();
}

// Routing is part of the on-disk format: a key must reach the shard file it was
// written to by any build of this module. Pins the hash, seed included — the
// round-trip tests pass with any hash at all.
test "routing is pinned: known keys route to known shards" {
    var sim = SimStorage.init(testing.allocator);
    defer sim.deinit();
    sim.allow_overwrite = true; // kvtree is a COW page store: meta slots overwrite in place
    var store = try Store.init(testing.allocator, sim.storage(), .{ .n_shards = 8 });
    defer store.deinit();
    const keys = [_][]const u8{ "", "a", "stable-key", "user:1", "user:2", "k-0", "k-1", "k-199" };
    var got: [keys.len]usize = undefined;
    for (keys, &got) |k, *g| g.* = store.shardFor(k);
    try testing.expectEqualSlices(usize, &.{ 1, 1, 1, 1, 1, 0, 1, 6 }, &got);
}

// A shard that fails to open after the store-wide lock is taken must release
// the lock and close the shards opened before it: a retry reports the same
// open error (not `error.Locked`), and `testing.allocator` sees no leak.
test "a failed shard open releases the lock and the shards already opened" {
    var sim = SimStorage.init(testing.allocator);
    defer sim.deinit();
    sim.allow_overwrite = true; // kvtree is a COW page store: meta slots overwrite in place
    const st = sim.storage();
    const h = try st.open("shard-00001.kvt", .open_or_create);
    var junk: [8192]u8 = undefined;
    @memset(&junk, 0xA5);
    try st.writeAll(h, &junk, 0);
    st.close(h);

    const err1 = if (Store.init(testing.allocator, st, .{ .n_shards = 2 })) |_|
        return error.TestUnexpectedResult
    else |e|
        e;
    try testing.expect(err1 != error.Locked);
    try testing.expectError(err1, Store.init(testing.allocator, st, .{ .n_shards = 2 }));
}

// `validateShardNameFits` must format the HIGHEST index, not shard 0: with
// 100 001 shards the last name has six digits, one more than the rest.
test "name validation uses the widest shard index" {
    var sim = SimStorage.init(testing.allocator);
    defer sim.deinit();
    sim.allow_overwrite = true; // kvtree is a COW page store: meta slots overwrite in place
    // Any backend side effect fails at once, so validating the wrong index
    // shows up as `error.Crashed` from the manifest write rather than as
    // 100 000 shard opens.
    sim.ops_until_crash = 0;
    // 502 + "-" + 5 digits + ".kvt" = 512 fits; with 6 digits it is 513.
    var prefix_buf: [502]u8 = undefined;
    @memset(&prefix_buf, 'b');
    try testing.expectError(
        error.ShardNameTooLong,
        Store.init(testing.allocator, sim.storage(), .{ .n_shards = 100_001, .name_prefix = &prefix_buf }),
    );
    try testing.expectEqual(@as(usize, 0), sim.names.count());
}

// ── merge-sorted scan tests ───────────────────────────────────────────────────
//
// Anchor: SELF-DERIVED. There is no outside oracle for "a k-way merge over
// these shards"; the reference is a brute-force one — every key/value written
// is kept in a plain sorted list, and each scan is compared entry for entry
// against the slice of that list its options select (filter by range, reverse,
// truncate to the limit).

/// An owned copy of everything a scan yielded.
const Collected = struct {
    keys: std.ArrayList([]u8) = .empty,
    vals: std.ArrayList([]u8) = .empty,

    fn deinit(c: *Collected, gpa: Allocator) void {
        for (c.keys.items) |k| gpa.free(k);
        for (c.vals.items) |v| gpa.free(v);
        c.keys.deinit(gpa);
        c.vals.deinit(gpa);
    }
};

fn collectScan(gpa: Allocator, store: *Store, options: ScanOptions) !Collected {
    var out: Collected = .{};
    errdefer out.deinit(gpa);
    var it = try store.scan(options);
    defer it.deinit();
    while (try it.next()) |e| {
        try out.keys.ensureUnusedCapacity(gpa, 1);
        try out.vals.ensureUnusedCapacity(gpa, 1);
        const k = try gpa.dupe(u8, e.key);
        errdefer gpa.free(k);
        const v = try gpa.dupe(u8, e.val);
        out.keys.appendAssumeCapacity(k);
        out.vals.appendAssumeCapacity(v);
    }
    // Once exhausted, a scan stays exhausted.
    try testing.expect((try it.next()) == null);
    return out;
}

/// The brute-force reference: a sorted, duplicate-free key → value list.
const RefModel = struct {
    keys: std.ArrayList([]u8) = .empty,
    vals: std.ArrayList([]u8) = .empty,

    fn deinit(m: *RefModel, gpa: Allocator) void {
        for (m.keys.items) |k| gpa.free(k);
        for (m.vals.items) |v| gpa.free(v);
        m.keys.deinit(gpa);
        m.vals.deinit(gpa);
    }

    const Found = struct { found: bool, index: usize };

    fn find(m: *const RefModel, key: []const u8) Found {
        var lo: usize = 0;
        var hi: usize = m.keys.items.len;
        while (lo < hi) {
            const mid = lo + (hi - lo) / 2;
            switch (std.mem.order(u8, m.keys.items[mid], key)) {
                .lt => lo = mid + 1,
                .gt => hi = mid,
                .eq => return .{ .found = true, .index = mid },
            }
        }
        return .{ .found = false, .index = lo };
    }

    fn put(m: *RefModel, gpa: Allocator, key: []const u8, val: []const u8) !void {
        const f = m.find(key);
        const v = try gpa.dupe(u8, val);
        if (f.found) {
            gpa.free(m.vals.items[f.index]);
            m.vals.items[f.index] = v;
            return;
        }
        errdefer gpa.free(v);
        const k = try gpa.dupe(u8, key);
        errdefer gpa.free(k);
        try m.keys.insert(gpa, f.index, k);
        errdefer _ = m.keys.orderedRemove(f.index);
        try m.vals.insert(gpa, f.index, v);
    }

    fn del(m: *RefModel, gpa: Allocator, key: []const u8) void {
        const f = m.find(key);
        if (!f.found) return;
        gpa.free(m.keys.orderedRemove(f.index));
        gpa.free(m.vals.orderedRemove(f.index));
    }

    fn inRange(key: []const u8, o: ScanOptions) bool {
        switch (o.start) {
            .unbounded => {},
            .inclusive => |b| if (std.mem.order(u8, key, b) == .lt) return false,
            .exclusive => |b| if (std.mem.order(u8, key, b) != .gt) return false,
        }
        switch (o.end) {
            .unbounded => {},
            .inclusive => |b| if (std.mem.order(u8, key, b) == .gt) return false,
            .exclusive => |b| if (std.mem.order(u8, key, b) != .lt) return false,
        }
        return true;
    }

    /// Indices into `keys` the scan with options `o` must yield, in order.
    fn expected(m: *const RefModel, gpa: Allocator, o: ScanOptions) !std.ArrayList(usize) {
        var out: std.ArrayList(usize) = .empty;
        errdefer out.deinit(gpa);
        const n = m.keys.items.len;
        const limit = o.limit orelse std.math.maxInt(usize);
        for (0..n) |j| {
            if (out.items.len >= limit) break;
            const i = if (o.direction == .forward) j else n - 1 - j;
            if (inRange(m.keys.items[i], o)) try out.append(gpa, i);
        }
        return out;
    }
};

/// Scan with `o` and require exactly the reference's answer — same keys, same
/// values, same order, nothing extra (which also proves duplicate-freedom).
fn expectScanMatches(store: *Store, model: *const RefModel, o: ScanOptions) !void {
    const gpa = testing.allocator;
    var got = try collectScan(gpa, store, o);
    defer got.deinit(gpa);
    var want = try model.expected(gpa, o);
    defer want.deinit(gpa);
    try testing.expectEqual(want.items.len, got.keys.items.len);
    for (want.items, 0..) |wi, j| {
        try testing.expectEqualStrings(model.keys.items[wi], got.keys.items[j]);
        try testing.expectEqualStrings(model.vals.items[wi], got.vals.items[j]);
    }
    // Strictly monotone in scan direction: no key twice, never out of order.
    if (got.keys.items.len > 1) for (1..got.keys.items.len) |j| {
        const ord = std.mem.order(u8, got.keys.items[j - 1], got.keys.items[j]);
        try testing.expectEqual(if (o.direction == .forward) std.math.Order.lt else .gt, ord);
    };
}

test "scan: random keys across N shards come out in global order, both directions" {
    const gpa = testing.allocator;
    for ([_]usize{ 1, 3, 8 }) |n_shards| {
        var sim = SimStorage.init(gpa);
        defer sim.deinit();
        sim.allow_overwrite = true;
        var store = try Store.init(gpa, sim.storage(), .{ .n_shards = n_shards });
        defer store.deinit();
        var model: RefModel = .{};
        defer model.deinit(gpa);

        var prng = std.Random.DefaultPrng.init(0x5ca9_0000 + n_shards);
        const r = prng.random();
        var kbuf: [24]u8 = undefined;
        var vbuf: [24]u8 = undefined;
        for (0..300) |n| {
            // Random binary keys of random length, so ordering is bytewise and
            // includes prefixes of one another.
            const klen = r.intRangeAtMost(usize, 1, kbuf.len);
            r.bytes(kbuf[0..klen]);
            const v = try std.fmt.bufPrint(&vbuf, "v{d}", .{n});
            try store.put(kbuf[0..klen], v);
            try model.put(gpa, kbuf[0..klen], v);
        }
        // Every shard really holds data, so the merge is exercised.
        for (store.shards) |*d| {
            var c = try d.cursor();
            defer c.deinit();
            try c.first();
            try testing.expect((try c.next()) != null);
        }

        try expectScanMatches(&store, &model, .{});
        try expectScanMatches(&store, &model, .{ .direction = .reverse });
    }
}

test "scan: range bound edges — inclusive, exclusive, unbounded, present and absent keys" {
    const gpa = testing.allocator;
    var sim = SimStorage.init(gpa);
    defer sim.deinit();
    sim.allow_overwrite = true;
    var store = try Store.init(gpa, sim.storage(), .{ .n_shards = 4 });
    defer store.deinit();
    var model: RefModel = .{};
    defer model.deinit(gpa);

    // Even numbers only, zero-padded so text order is numeric order: "k010",
    // "k012", … "k098". Odd keys are absent and fall between two present ones.
    var kbuf: [8]u8 = undefined;
    var n: usize = 10;
    while (n < 100) : (n += 2) {
        const k = try std.fmt.bufPrint(&kbuf, "k{d:0>3}", .{n});
        try store.put(k, k);
        try model.put(gpa, k, k);
    }

    // Bound keys: below everything, the first, an absent middle, a present
    // middle, the last, above everything, prefixes of every key, and "".
    const probes = [_][]const u8{ "a", "k010", "k051", "k050", "k098", "z", "k", "k0", "" };
    for (probes) |s| for (probes) |e| {
        const starts = [_]Bound{ .unbounded, .{ .inclusive = s }, .{ .exclusive = s } };
        const ends = [_]Bound{ .unbounded, .{ .inclusive = e }, .{ .exclusive = e } };
        for (starts) |sb| for (ends) |eb| for ([_]ScanDirection{ .forward, .reverse }) |dir| {
            try expectScanMatches(&store, &model, .{ .start = sb, .end = eb, .direction = dir });
        };
    };

    // The edges spelled out, so a reader need not trust the reference:
    var got = try collectScan(gpa, &store, .{ .start = .{ .inclusive = "k050" }, .end = .{ .inclusive = "k050" } });
    try testing.expectEqual(@as(usize, 1), got.keys.items.len); // [x, x] is one key
    got.deinit(gpa);
    got = try collectScan(gpa, &store, .{ .start = .{ .inclusive = "k050" }, .end = .{ .exclusive = "k050" } });
    try testing.expectEqual(@as(usize, 0), got.keys.items.len); // [x, x) is empty
    got.deinit(gpa);
    got = try collectScan(gpa, &store, .{ .start = .{ .exclusive = "k050" }, .end = .{ .inclusive = "k054" } });
    try testing.expectEqual(@as(usize, 2), got.keys.items.len); // (50, 54] = 52, 54
    try testing.expectEqualStrings("k052", got.keys.items[0]);
    got.deinit(gpa);
    got = try collectScan(gpa, &store, .{ .start = .{ .inclusive = "k060" }, .end = .{ .inclusive = "k040" } });
    try testing.expectEqual(@as(usize, 0), got.keys.items.len); // start above end: empty, no error
    got.deinit(gpa);
    got = try collectScan(gpa, &store, .{ .start = .{ .exclusive = "k051" }, .end = .{ .exclusive = "k055" }, .direction = .reverse });
    try testing.expectEqual(@as(usize, 2), got.keys.items.len); // 54, 52
    try testing.expectEqualStrings("k054", got.keys.items[0]);
    try testing.expectEqualStrings("k052", got.keys.items[1]);
    got.deinit(gpa);
}

test "scan: empty store, empty shards, and the bound slice need not outlive scan()" {
    const gpa = testing.allocator;
    var sim = SimStorage.init(gpa);
    defer sim.deinit();
    sim.allow_overwrite = true;
    var store = try Store.init(gpa, sim.storage(), .{ .n_shards = 16 });
    defer store.deinit();
    var model: RefModel = .{};
    defer model.deinit(gpa);

    // Entirely empty: nothing, in either direction, with any bounds.
    try expectScanMatches(&store, &model, .{});
    try expectScanMatches(&store, &model, .{ .direction = .reverse });
    try expectScanMatches(&store, &model, .{ .start = .{ .inclusive = "a" }, .end = .{ .inclusive = "z" } });

    // Three keys over sixteen shards: at least thirteen shards stay empty.
    for ([_][]const u8{ "alpha", "mid", "zulu" }) |k| {
        try store.put(k, k);
        try model.put(gpa, k, k);
    }
    var empty_shards: usize = 0;
    for (store.shards) |*d| {
        var c = try d.cursor();
        defer c.deinit();
        try c.first();
        if ((try c.next()) == null) empty_shards += 1;
    }
    try testing.expect(empty_shards >= 13);
    try expectScanMatches(&store, &model, .{});
    try expectScanMatches(&store, &model, .{ .direction = .reverse, .limit = 2 });

    // The stop bound is copied: overwriting the caller's buffer after `scan`
    // returns changes nothing.
    var bound = "mid".*;
    var it = try store.scan(.{ .end = .{ .inclusive = &bound } });
    defer it.deinit();
    bound = "aaa".*;
    try testing.expectEqualStrings("alpha", (try it.next()).?.key);
    try testing.expectEqualStrings("mid", (try it.next()).?.key);
    try testing.expect((try it.next()) == null);
}

test "scan: duplicate-free — a key misplaced into a non-owning shard is not yielded" {
    const gpa = testing.allocator;
    var sim = SimStorage.init(gpa);
    defer sim.deinit();
    sim.allow_overwrite = true;
    var store = try Store.init(gpa, sim.storage(), .{ .n_shards = 4 });
    defer store.deinit();

    try store.put("dup", "owned");
    try store.put("solo", "x");
    const owner = store.shardFor("dup");
    // Write the same key, with a different value, straight into every other
    // shard — the only way a key can exist in two shards.
    for (0..4) |i| if (i != owner) try store.shardAt(i).put("dup", "stray");
    // And a key that exists ONLY in a shard it does not route to.
    const orphan_home = store.shardFor("orphan");
    try store.shardAt((orphan_home + 1) % 4).put("orphan", "stray");

    // `get` sees the owned copy only, and no orphan.
    const g = (try store.get(gpa, "dup")).?;
    defer gpa.free(g);
    try testing.expectEqualStrings("owned", g);
    try testing.expect((try store.get(gpa, "orphan")) == null);

    // The scan agrees with `get`, in both directions.
    for ([_]ScanDirection{ .forward, .reverse }) |dir| {
        var got = try collectScan(gpa, &store, .{ .direction = dir });
        defer got.deinit(gpa);
        try testing.expectEqual(@as(usize, 2), got.keys.items.len);
        const di: usize = if (dir == .forward) 0 else 1;
        try testing.expectEqualStrings("dup", got.keys.items[di]);
        try testing.expectEqualStrings("owned", got.vals.items[di]);
        try testing.expectEqualStrings("solo", got.keys.items[1 - di]);
    }
}

test "scan: limit — zero, one, partial, exact, beyond, with bounds and reverse" {
    const gpa = testing.allocator;
    var sim = SimStorage.init(gpa);
    defer sim.deinit();
    sim.allow_overwrite = true;
    var store = try Store.init(gpa, sim.storage(), .{ .n_shards = 5 });
    defer store.deinit();
    var model: RefModel = .{};
    defer model.deinit(gpa);

    var kbuf: [8]u8 = undefined;
    for (0..60) |n| {
        const k = try std.fmt.bufPrint(&kbuf, "k{d:0>3}", .{n});
        try store.put(k, k);
        try model.put(gpa, k, k);
    }
    for ([_]usize{ 0, 1, 7, 20, 59, 60, 61, 1000 }) |limit| {
        for ([_]ScanDirection{ .forward, .reverse }) |dir| {
            try expectScanMatches(&store, &model, .{ .limit = limit, .direction = dir });
            try expectScanMatches(&store, &model, .{
                .start = .{ .exclusive = "k010" },
                .end = .{ .inclusive = "k030" },
                .limit = limit,
                .direction = dir,
            });
        }
    }
    // Reverse + limit keeps the largest keys of the range.
    var got = try collectScan(gpa, &store, .{ .end = .{ .exclusive = "k030" }, .limit = 3, .direction = .reverse });
    defer got.deinit(gpa);
    try testing.expectEqual(@as(usize, 3), got.keys.items.len);
    try testing.expectEqualStrings("k029", got.keys.items[0]);
    try testing.expectEqualStrings("k027", got.keys.items[2]);
}

test "scan: property — random puts, overwrites and deletes vs a sorted reference" {
    const gpa = testing.allocator;
    var sim = SimStorage.init(gpa);
    defer sim.deinit();
    sim.allow_overwrite = true;
    const n_shards = 7;
    var store = try Store.init(gpa, sim.storage(), .{ .n_shards = n_shards });
    defer store.deinit();
    var model: RefModel = .{};
    defer model.deinit(gpa);

    var prng = std.Random.DefaultPrng.init(0x0005_ca75_ca75);
    const r = prng.random();
    var kbuf: [16]u8 = undefined;
    var vbuf: [600]u8 = undefined;
    var bbuf: [2][16]u8 = undefined;

    const randKey = struct {
        fn f(rr: std.Random, buf: *[16]u8) []const u8 {
            // A small alphabet over short keys, so overwrites, deletes of
            // present keys and bounds that hit real keys are all common.
            const len = rr.intRangeAtMost(usize, 0, 6);
            for (buf[0..len]) |*c| c.* = "abcdefgh"[rr.uintLessThan(usize, 8)];
            return buf[0..len];
        }
    }.f;

    for (0..6) |round| {
        // A batch of mutations per shard, committed as one transaction per
        // shard (the routed autocommit path is covered by the other tests;
        // this keeps a few thousand operations quick).
        var txns: [n_shards]kvtree.Txn = undefined;
        for (&txns, 0..) |*t, i| t.* = try store.shardAt(i).begin();
        for (0..600) |_| {
            const k = randKey(r, &kbuf);
            const t = &txns[store.shardFor(k)];
            if (r.uintLessThan(u8, 4) == 0) {
                try t.del(k);
                model.del(gpa, k);
            } else {
                // Mostly short values, sometimes one long enough for kvtree's
                // overflow pages (the cursor then yields from its own buffer).
                const vlen = if (r.uintLessThan(u8, 20) == 0) vbuf.len else r.intRangeAtMost(usize, 0, 12);
                @memset(vbuf[0..vlen], 'a' + @as(u8, @intCast(round)));
                if (vlen > 0) vbuf[0] = r.int(u8);
                try t.put(k, vbuf[0..vlen]);
                try model.put(gpa, k, vbuf[0..vlen]);
            }
        }
        for (&txns) |*t| try t.commit();

        try expectScanMatches(&store, &model, .{});
        try expectScanMatches(&store, &model, .{ .direction = .reverse });
        for (0..60) |_| {
            var bounds: [2]Bound = undefined;
            for (&bounds, 0..) |*b, j| b.* = switch (r.uintLessThan(u8, 3)) {
                0 => .unbounded,
                1 => .{ .inclusive = randKey(r, &bbuf[j]) },
                else => .{ .exclusive = randKey(r, &bbuf[j]) },
            };
            const limit: ?usize = if (r.boolean()) null else r.uintLessThan(usize, 40);
            const dir: ScanDirection = if (r.boolean()) .forward else .reverse;
            try expectScanMatches(&store, &model, .{ .start = bounds[0], .end = bounds[1], .limit = limit, .direction = dir });
        }
    }
    try testing.expect(model.keys.items.len > 1000);
}

test "scan consistency: a scan sees the store as of scan(); later commits are invisible to it" {
    const gpa = testing.allocator;
    var sim = SimStorage.init(gpa);
    defer sim.deinit();
    sim.allow_overwrite = true;
    var store = try Store.init(gpa, sim.storage(), .{ .n_shards = 4 });
    defer store.deinit();
    var model: RefModel = .{};
    defer model.deinit(gpa);

    var kbuf: [8]u8 = undefined;
    for (0..200) |n| {
        const k = try std.fmt.bufPrint(&kbuf, "k{d:0>4}", .{n * 2});
        try store.put(k, "old");
        try model.put(gpa, k, "old");
    }

    var overwritten: usize = 0;
    var deleted: usize = 0;
    var inserted: usize = 0;
    var it = try store.scan(.{});
    defer it.deinit();
    var seen: usize = 0;
    while (try it.next()) |e| : (seen += 1) {
        // The scan yields exactly the store as it was when it opened…
        try testing.expectEqualStrings(model.keys.items[seen], e.key);
        try testing.expectEqualStrings("old", e.val);
        // …while the owner keeps committing between `next` calls, on every
        // shard: overwrite a key not yet reached, delete the one after it,
        // insert a new key into a gap still ahead. None of it may show up.
        // (kvtree's reclaim-gate pin keeps the pinned pages intact across
        // these commits; without it this read would walk recycled pages.)
        if (seen % 8 == 0 and seen + 7 < model.keys.items.len) {
            try store.put(model.keys.items[seen + 5], "new");
            overwritten += 1;
            try store.delete(model.keys.items[seen + 6]);
            deleted += 1;
            const fresh = try std.fmt.bufPrint(&kbuf, "k{d:0>4}", .{seen * 2 + 9});
            try store.put(fresh, "new");
            inserted += 1;
        }
    }
    try testing.expectEqual(model.keys.items.len, seen);
    try testing.expect(overwritten > 20);

    // A fresh scan sees the new state.
    var after = try collectScan(gpa, &store, .{});
    defer after.deinit(gpa);
    var news: usize = 0;
    for (after.vals.items) |v| {
        if (std.mem.eql(u8, v, "new")) news += 1;
    }
    try testing.expectEqual(overwritten + inserted, news);
    try testing.expectEqual(model.keys.items.len - deleted + inserted, after.keys.items.len);
}

test "scan on a single_thread store: refused from a foreign thread, owner's scan unharmed" {
    const gpa = testing.allocator;
    var sim = SimStorage.init(gpa);
    defer sim.deinit();
    sim.allow_overwrite = true;
    var store = try Store.init(gpa, sim.storage(), .{ .n_shards = 3 });
    defer store.deinit();
    for ([_][]const u8{ "a", "b", "c", "d" }) |k| try store.put(k, k);

    var it = try store.scan(.{});
    defer it.deinit();
    try testing.expectEqualStrings("a", (try it.next()).?.key);

    const Probe = struct {
        store: *Store,
        it: *Scan,
        open_res: ScanError!void = {},
        next_res: ScanError!?KV = null,

        fn run(p: *@This()) void {
            if (p.store.scan(.{})) |s| {
                var s2 = s;
                s2.deinit();
            } else |e| p.open_res = e;
            p.next_res = p.it.next();
        }
    };
    var probe = Probe{ .store = &store, .it = &it };
    const t = try std.Thread.spawn(.{}, Probe.run, .{&probe});
    t.join();
    try testing.expectError(error.NotOwningThread, probe.open_res);
    try testing.expectError(error.NotOwningThread, probe.next_res);

    // The refusal is not sticky and did not advance the owner's scan.
    try testing.expectEqualStrings("b", (try it.next()).?.key);
    try testing.expectEqualStrings("c", (try it.next()).?.key);
    try testing.expectEqualStrings("d", (try it.next()).?.key);
    try testing.expect((try it.next()) == null);
}

test "scan: every allocation failure is reported, sticky, and leak-free" {
    var failing = std.testing.FailingAllocator.init(testing.allocator, .{});
    const gpa = failing.allocator();
    var sim = SimStorage.init(testing.allocator);
    defer sim.deinit();
    sim.allow_overwrite = true;
    var store = try Store.init(gpa, sim.storage(), .{ .n_shards = 3 });
    defer store.deinit();

    // Enough keys for multi-level trees, plus overflow values (the cursor
    // allocates to assemble those, mid-scan).
    var kbuf: [8]u8 = undefined;
    const big = [_]u8{'v'} ** 5000;
    for (0..300) |n| {
        const k = try std.fmt.bufPrint(&kbuf, "k{d:0>4}", .{n});
        try store.put(k, if (n % 50 == 0) &big else k);
    }

    var fail_at: usize = 0;
    var completed = false;
    var mid_scan_failures: usize = 0;
    while (!completed) : (fail_at += 1) {
        failing.fail_index = failing.alloc_index + fail_at;
        failing.resize_fail_index = failing.resize_index + fail_at;
        var it = store.scan(.{}) catch |e| {
            try testing.expectEqual(error.OutOfMemory, e);
            continue;
        };
        defer it.deinit();
        var count: usize = 0;
        while (true) {
            const entry = it.next() catch |err| {
                try testing.expectEqual(error.OutOfMemory, err);
                // Sticky: the scan does not resume with a gap.
                try testing.expectError(error.OutOfMemory, it.next());
                mid_scan_failures += 1;
                break;
            };
            if (entry == null) {
                try testing.expectEqual(@as(usize, 300), count);
                completed = true;
                break;
            }
            count += 1;
        }
    }
    failing.fail_index = std.math.maxInt(usize);
    failing.resize_fail_index = std.math.maxInt(usize);
    try testing.expect(mid_scan_failures > 0);
}
