// SPDX-License-Identifier: MIT

//! readthrough — a backend-agnostic read-through cache *coordinator*.
//!
//! The read-path counterpart to `writebehind`. It is NOT a storage engine: it
//! composes `ramcache` (W-TinyLFU + TTL + generation invalidation) for storage
//! and adds the orchestration `ramcache` lacks:
//!
//!   1. **Read-through.** `get(key)` returns a fresh cached value, or on a miss
//!      calls the caller-supplied **loader** (fetch from Postgres / an upstream
//!      API / a compute), stores the result with a TTL, and returns it.
//!   2. **Single-flight / request coalescing.** Concurrent misses for the SAME
//!      key collapse into ONE loader call; every other caller waits for and
//!      shares that one result (the "thundering herd" / cache-stampede guard —
//!      Go's `singleflight`, Caffeine's loading cache).
//!   3. **TTL + explicit invalidation.** Per-entry TTL, `invalidate(key)`, and a
//!      generation-bump `invalidateAll()` (reusing `ramcache`'s generation axis).
//!   4. **Negative caching.** A loader "not found" (and, opt-in, a loader error)
//!      is cacheable for a separate, short TTL so a missing/erroring key does
//!      not hammer the backend on every request.
//!
//! ## Concurrency model — `.threadsafe`
//!
//! A read-through cache's value is largely in concurrent single-flight, so this
//! module is genuinely thread-safe: `get` / `invalidate` / `invalidateAll` may
//! be called from any number of OS threads at once. All shared state (the
//! `ramcache`, the in-flight map, the generation counter, stats) is guarded by a
//! single `std.atomic` **SpinLock** — `ramcache` itself is `single_owner`, so
//! serializing every access to it under our lock is what makes the composite
//! safe. The **loader runs OUTSIDE the lock**, so a slow backend fetch never
//! blocks `get`s for other keys, and coalesced followers block on an
//! `std.Io` **futex** (0.16 has no `std.Thread.Mutex`/`Condition`/`Futex` — they
//! moved onto the `std.Io` vtable; this is the same primitive `workerpool` uses)
//! rather than busy-spinning.
//!
//! ## Ownership / return contract
//!
//! Because this cache is thread-safe, `get` returns an **owned copy** of the
//! value (allocated from the cache's allocator; free it with `Cache.free`).
//! Returning a slice that borrows cache storage — the way the `single_owner`
//! `ramcache`/`writebehind` do — is unsafe here: another thread could evict or
//! replace that entry the instant the lock is released. Callers that want an
//! allocation-free hit fast-path use `ifCached`, which hands the borrowed value
//! to a callback *while the lock is held*.
//!
//! ## Memory profile (qualitative)
//!
//!   * A **hit** allocates exactly one owned copy of the value (the return),
//!     nothing else. Use `ifCached` for a truly zero-allocation hit path.
//!   * A **miss** allocates one small `Call` (the single-flight rendezvous) plus
//!     one owned key string in the in-flight map — both freed the moment the
//!     load completes. There is **no per-entry heap churn at scale**: the
//!     in-flight map's size is bounded by the number of *concurrently loading
//!     distinct keys*, not by the total key population, and drains to empty.
//!   * Stored values live in `ramcache`, bounded by its `max_bytes` /
//!     `max_entries` caps (W-TinyLFU eviction). One tag byte of overhead per
//!     stored value distinguishes positive from negative entries.
//!
//! Provenance: clean-room from the single-flight / loading-cache pattern
//! (Go `singleflight`, Caffeine `LoadingCache`); no third-party source ported.
//! See `SPEC.md` for the full design, staleness/invalidation contracts, and the
//! deliberately-deferred list.

const std = @import("std");
const Allocator = std.mem.Allocator;

const ramcache = @import("ramcache");

pub const meta = .{
    // The module catalog's one-line entry. This IS the source of truth:
    // README.md's table is rendered from it by `zig build gen-catalog`.
    .doc = "Backend-agnostic read-through cache coordinator — serve-from-cache or single-flight-coalesce a miss into one backend fetch, TTL + invalidation + negative caching",
    // The catalog's Platform cell. Prose, because it carries nuance the
    // `platform` enum below cannot -- "any (packer: linux)", "amd64 asm +
    // portable fallback". Rendered by `gen-catalog` alongside `doc`.
    .platform_note = "any",
    .targets = .{.linux64},
    .platform = .any, // std.Io futex + std.Thread + std.atomic are all cross-OS
    .role = .util,
    .concurrency = .threadsafe, // internally synchronized (SpinLock + std.Io futex)
    .model_after = "Go singleflight + Caffeine LoadingCache over a W-TinyLFU store",
    .deps = .{"ramcache"},
};

// ── loader abstraction ──────────────────────────────────────────────────────

/// What a loader produced for a key. `value` is borrowed for the duration of
/// the load call only — the coordinator copies it into the cache / the return,
/// so a loader may hand back a slice into a scratch buffer it reuses. `missing`
/// is the loader's "not found" (a well-defined negative, distinct from a
/// transient backend error, which the loader signals by *returning an error*).
pub const LoadOutcome = union(enum) {
    value: []const u8,
    missing,
};

/// The backend fetch. Generic on purpose (a `ctx` pointer + a plain function
/// pointer) so it works for Postgres, an HTTP upstream, or a pure compute
/// without this module knowing anything about the backend. Called on the
/// *caller's* thread, OUTSIDE the coordinator lock, exactly once per set of
/// coalesced misses. It MUST NOT call back into the same `Cache` for the same
/// `key` (that would deadlock as a self-follower) and MUST NOT panic (Zig does
/// not unwind — a panic aborts the process and strands the in-flight `Call`).
pub const Loader = struct {
    ctx: ?*anyopaque = null,
    load: *const fn (ctx: ?*anyopaque, key: []const u8) anyerror!LoadOutcome,
};

/// Injectable clock, for deterministic TTL tests (drive time by hand — never
/// sleep). Production callers leave `Options.clock` null and the cache reads the
/// monotonic `std.Io` "awake" clock instead.
pub const Clock = struct {
    ctx: *anyopaque,
    now_fn: *const fn (ctx: *anyopaque) i64,
    pub fn now(self: Clock) i64 {
        return self.now_fn(self.ctx);
    }
};

// ── result / stats ──────────────────────────────────────────────────────────

/// The outcome of a `get`. `value` is owned by the caller — free it with
/// `Cache.free`. `missing` means the key is absent at the backend (a loader
/// "not found", possibly served from the negative cache). A transient loader
/// error surfaces as a Zig error from `get`, not here.
pub const Loaded = union(enum) {
    value: []u8,
    missing,
};

pub const Stats = struct {
    /// Fresh cache hits (positive or negative), served without a loader call.
    hits: u64 = 0,
    /// Requests that found no fresh entry.
    misses: u64 = 0,
    /// Loader invocations (== distinct in-flight loads started). The
    /// single-flight guarantee is exactly `loads <= misses`.
    loads: u64 = 0,
    /// Misses that coalesced onto an already-in-flight load instead of starting
    /// their own (the stampede that single-flight prevented).
    coalesced: u64 = 0,
    /// Hits served from a negative (missing / cached-error) entry.
    negative_hits: u64 = 0,
    /// `invalidate` + `invalidateAll` calls.
    invalidations: u64 = 0,
};

/// Returned by `get` when a hit lands on a negatively-cached loader *error*
/// (only possible when `Options.cache_loader_errors` is on). The original error
/// value is not preserved across the cache boundary — only the fact that the
/// last load failed. In-flight followers of the *same* load still receive the
/// exact original error.
pub const CachedLoaderError = error{CachedLoaderError};

// ── internals: entry tagging ────────────────────────────────────────────────
//
// ramcache stores opaque bytes; we prefix one tag byte so a stored value's
// kind (positive / negative-missing / negative-error) survives a round trip.
const tag_value: u8 = 'V';
const tag_missing: u8 = 'N';
const tag_error: u8 = 'E';

// A generation reserved for "poisoned" (per-key invalidated) entries. It never
// equals the live generation (which starts at 1 and only increments), so such
// an entry is always seen stale by the next `get` and dropped by ramcache. A
// 64-bit counter incremented once per `invalidateAll` cannot reach this in any
// realistic lifetime.
const poison_gen: u64 = std.math.maxInt(u64);

/// A tiny `std.atomic` spinlock — 0.16 has no `std.Thread.Mutex`; this is the
/// same shape `writebehind`/`lockfree` use for short critical sections.
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

/// One single-flight rendezvous: the leader fills `result` and flips `done`;
/// followers park on `done` (a futex word) and then read `result`. Reference
/// counted — the last participant to leave frees it (and any owned buffer).
/// Every field except `done` is guarded by the `Cache` lock.
const Call = struct {
    done: std.atomic.Value(u32) = .init(0), // 0 = pending, 1 = published
    refs: usize = 1,
    /// Set if the key was invalidated while this load was in flight — the
    /// leader then still delivers the value to coalesced callers but does NOT
    /// write it to the cache (see the invalidate-during-load contract in SPEC).
    poisoned: bool = false,
    result: Result = undefined,

    const Result = union(enum) {
        value: []u8, // owned by the Call
        missing,
        err: anyerror,
    };
};

pub const Options = struct {
    /// The `Io` whose futex backs the coalesced-follower wait. Required (0.16
    /// futexes live on the `Io` vtable). Pass the same `std.Io.Threaded` the
    /// rest of the server uses; it must outlive the cache.
    io: std.Io,
    /// The backend fetch. See `Loader`.
    loader: Loader,
    /// TTL for a positively-loaded value, in ns. `<= 0` = never expire by time.
    ttl_ns: i64 = 0,
    /// TTL for a negative (missing / error) entry, in ns. `<= 0` disables
    /// negative caching entirely (every miss re-hits the loader).
    negative_ttl_ns: i64 = 0,
    /// When true (and `negative_ttl_ns > 0`), a *loader error* is negatively
    /// cached too, not just a "not found". Off by default: backend errors are
    /// often transient, and caching "the DB is down" is usually wrong.
    cache_loader_errors: bool = false,
    /// ramcache value-byte budget.
    max_bytes: usize,
    /// ramcache entry-count budget.
    max_entries: usize,
    /// Clock override for deterministic tests. Null = monotonic `std.Io` clock.
    clock: ?Clock = null,
};

pub const Cache = struct {
    gpa: Allocator,
    io: std.Io,
    loader: Loader,
    ttl_ns: i64,
    negative_ttl_ns: i64,
    cache_loader_errors: bool,
    clock: ?Clock,

    lock: SpinLock = .{},
    store: ramcache.Cache,
    in_flight: std.StringHashMapUnmanaged(*Call) = .empty,
    /// Live generation for `ramcache`'s generation axis. Starts at 1 (nonzero,
    /// so entries are generation-tied and `invalidateAll` can shadow them);
    /// bumped by `invalidateAll`.
    generation: u64 = 1,
    stats: Stats = .{},

    pub fn init(gpa: Allocator, options: Options) Cache {
        return .{
            .gpa = gpa,
            .io = options.io,
            .loader = options.loader,
            .ttl_ns = options.ttl_ns,
            .negative_ttl_ns = options.negative_ttl_ns,
            .cache_loader_errors = options.cache_loader_errors,
            .clock = options.clock,
            .store = ramcache.Cache.init(gpa, .{
                .max_bytes = options.max_bytes,
                .max_entries = options.max_entries,
            }),
        };
    }

    /// Release all resources. **Quiescence requirement:** every `get` must have
    /// returned before `deinit` (no load may be in flight). Leaders remove their
    /// own in-flight entry on completion, so a quiesced cache has an empty
    /// in-flight map here; any leftover means the caller violated quiescence.
    ///
    /// This used to free only the map's owned *keys* and silently leak every
    /// `*Call` still present — a half-cleanup that masked a quiescence
    /// violation as a plain memory leak instead of making it visibly a
    /// pair-freeing bug. Both halves of every remaining pair are now
    /// reclaimed: the owned key AND the `*Call` itself. A leftover entry here
    /// is still a caller contract violation (its `Call.result` may be
    /// `undefined` if a load never completed) — this does not make racing
    /// `deinit` against an in-flight `get` safe, it only stops the map from
    /// leaking memory on top of it.
    pub fn deinit(self: *Cache) void {
        var it = self.in_flight.iterator();
        while (it.next()) |entry| {
            self.gpa.free(entry.key_ptr.*);
            self.gpa.destroy(entry.value_ptr.*);
        }
        self.in_flight.deinit(self.gpa);
        self.store.deinit();
        self.* = undefined;
    }

    /// Free a value returned by `get`.
    pub fn free(self: *Cache, loaded: Loaded) void {
        switch (loaded) {
            .value => |v| self.gpa.free(v),
            .missing => {},
        }
    }

    // ── read path ─────────────────────────────────────────────────────────────

    /// Read `key`: return a fresh cached value; else run the loader (coalescing
    /// concurrent misses into one call), store the result, and return it. The
    /// returned `.value` is owned — free it with `free`. A loader "not found"
    /// yields `.missing`; a transient loader error propagates as a Zig error.
    pub fn get(self: *Cache, key: []const u8) anyerror!Loaded {
        self.lock.lock();

        // Fast path: a fresh hit. Decode + copy the value while we hold the lock
        // (another thread may evict it the instant we release).
        if (self.decodeFreshLocked(key)) |dec| {
            self.stats.hits += 1;
            switch (dec) {
                .value => |v| {
                    const dup = self.gpa.dupe(u8, v) catch {
                        self.lock.unlock();
                        return error.OutOfMemory;
                    };
                    self.lock.unlock();
                    return .{ .value = dup };
                },
                .missing => {
                    self.stats.negative_hits += 1;
                    self.lock.unlock();
                    return .missing;
                },
                .err => {
                    self.stats.negative_hits += 1;
                    self.lock.unlock();
                    return error.CachedLoaderError;
                },
                .corrupt => {
                    self.lock.unlock();
                    return error.CorruptEntry;
                },
            }
        }

        // Miss.
        self.stats.misses += 1;

        // Join an in-flight load for this key, if any (the coalescing path).
        if (self.in_flight.get(key)) |call| {
            call.refs += 1;
            self.stats.coalesced += 1;
            self.lock.unlock();
            return self.awaitCall(call);
        }

        // Become the leader: register an in-flight Call, then load unlocked.
        const call = self.gpa.create(Call) catch {
            self.lock.unlock();
            return error.OutOfMemory;
        };
        call.* = .{};
        const kdup = self.gpa.dupe(u8, key) catch {
            self.gpa.destroy(call);
            self.lock.unlock();
            return error.OutOfMemory;
        };
        self.in_flight.put(self.gpa, kdup, call) catch {
            self.gpa.free(kdup);
            self.gpa.destroy(call);
            self.lock.unlock();
            return error.OutOfMemory;
        };
        self.stats.loads += 1;
        self.lock.unlock();

        // The one backend fetch, off the lock.
        const outcome = self.loader.load(self.loader.ctx, key);

        self.lock.lock();
        // Unregister so late arrivals go to the cache (now populated) or start a
        // fresh load; free the owned in-flight key.
        if (self.in_flight.fetchRemove(key)) |kv| self.gpa.free(kv.key);
        const poisoned = call.poisoned;

        if (outcome) |oc| switch (oc) {
            .value => |bytes| {
                // Never substitute a value for a failure: an empty slice here
                // would be byte-identical, at every participant, to a backend
                // that legitimately returned "". Deliver the error instead —
                // SPEC §6 ("a failed return copy surfaces as error.OutOfMemory").
                if (self.gpa.dupe(u8, bytes)) |copy| {
                    call.result = .{ .value = copy };
                } else |e| {
                    call.result = .{ .err = e };
                }
                // The store is independent of the copy and still worth doing:
                // it is fail-soft, and a populated cache makes the next get
                // succeed. It does not paper over the error above.
                if (!poisoned) self.storeLocked(key, tag_value, bytes, self.ttl_ns);
            },
            .missing => {
                call.result = .missing;
                if (!poisoned and self.negative_ttl_ns > 0)
                    self.storeLocked(key, tag_missing, "", self.negative_ttl_ns);
            },
        } else |e| {
            call.result = .{ .err = e };
            if (!poisoned and self.cache_loader_errors and self.negative_ttl_ns > 0)
                self.storeLocked(key, tag_error, "", self.negative_ttl_ns);
        }

        // Publish to followers.
        call.done.store(1, .release);
        self.lock.unlock();
        self.io.futexWake(u32, &call.done.raw, std.math.maxInt(u32));

        return self.finish(call);
    }

    /// Zero-allocation hit fast-path. If `key` is a fresh POSITIVE hit, invoke
    /// `f(ctx, value)` with the value borrowed *under the lock* and return true;
    /// otherwise return false (the caller then does a full `get`). `f` must be
    /// cheap and MUST NOT re-enter this cache (it runs inside the lock). A
    /// negatively-cached entry returns false (there is no positive value to
    /// hand out).
    pub fn ifCached(
        self: *Cache,
        key: []const u8,
        ctx: ?*anyopaque,
        f: *const fn (ctx: ?*anyopaque, value: []const u8) void,
    ) bool {
        self.lock.lock();
        defer self.lock.unlock();
        // Mirror `get`'s accounting exactly, so `hits + misses == requests`
        // holds whether a caller uses `get` or `ifCached` (or both): no
        // fresh entry at all is a miss; a fresh entry — positive or not —
        // is a hit, matching `get`'s `self.stats.hits += 1` before its own
        // dispatch on `dec`. Previously `ifCached` counted hits on the
        // positive branch only and nothing on any other outcome.
        const dec = self.decodeFreshLocked(key) orelse {
            self.stats.misses += 1;
            return false;
        };
        self.stats.hits += 1;
        switch (dec) {
            .value => |v| {
                f(ctx, v);
                return true;
            },
            .missing, .err => {
                self.stats.negative_hits += 1;
                return false;
            },
            .corrupt => return false,
        }
    }

    // ── invalidation ──────────────────────────────────────────────────────────

    /// Force the next `get(key)` to reload. Any cached entry is dropped
    /// EAGERLY, right here, not left to be discovered by some later `get`
    /// or eviction; a load in flight for `key` is poisoned so its result is
    /// delivered to current waiters but NOT written to the cache.
    pub fn invalidate(self: *Cache, key: []const u8) void {
        self.lock.lock();
        defer self.lock.unlock();
        if (self.in_flight.get(key)) |call| call.poisoned = true;
        // All our stored entries are dirty (we never markClean), so `isDirty`
        // is a side-effect-free presence test — avoid inserting junk for an
        // absent key. Shadow a present entry with a poison generation...
        if (self.store.isDirty(key)) {
            self.store.put(key, "", self.now(), 1, poison_gen);
            // ...then immediately reclaim the slot: `ramcache` has no
            // `remove(key)`, but a `get` under the REAL current generation
            // sees the poison entry's generation mismatch and drops it right
            // there (the same lazy-drop path a future caller would have
            // triggered) — so the slot and its allocation are freed now,
            // not whenever something else next happens to touch this key. A
            // burst of invalidations across hot keys no longer transiently
            // displaces live entries or inflates `stats.entries`.
            _ = self.store.get(key, self.now(), self.generation);
        }
        self.stats.invalidations += 1;
    }

    /// Invalidate EVERY entry at once via a generation bump (ramcache's
    /// generation axis — O(1), no sweep; stale entries drop lazily). Also
    /// poisons every in-flight load so none of them repopulate a just-cleared
    /// cache.
    pub fn invalidateAll(self: *Cache) void {
        self.lock.lock();
        defer self.lock.unlock();
        self.generation += 1;
        var it = self.in_flight.valueIterator();
        while (it.next()) |cp| cp.*.poisoned = true;
        self.stats.invalidations += 1;
    }

    /// A consistent snapshot of the counters.
    pub fn getStats(self: *Cache) Stats {
        self.lock.lock();
        defer self.lock.unlock();
        return self.stats;
    }

    // ── internals ─────────────────────────────────────────────────────────────

    const Decoded = union(enum) { value: []const u8, missing, err, corrupt };

    /// Look up `key` and, if fresh, decode its tag. Caller holds the lock. The
    /// returned `value` slice borrows ramcache storage — valid only while the
    /// lock is held.
    ///
    /// A stored entry is supposed to always have at least its tag byte, and
    /// the tag byte is supposed to always be one of the three known values —
    /// but both of those are cross-module invariants this function trusted
    /// rather than checked (every entry is written by `storeLocked`, which
    /// upholds them; a zero-length payload is unreachable through `.missing`/
    /// `.err`, whose payloads are always non-empty). Indexing `raw[0]`
    /// unchecked and closing with `else => unreachable` turned "nothing in
    /// THIS module currently violates it" into UB the instant `ramcache`'s
    /// own contract ever shifted underneath — an OOB read on an empty `raw`,
    /// or `unreachable` firing in ReleaseFast on an unknown tag, neither of
    /// which this module's own tests could ever trigger by construction. A
    /// stored-entry invariant should not be load-bearing for memory safety
    /// across a module boundary, so both cases now decode to `.corrupt`
    /// instead.
    fn decodeFreshLocked(self: *Cache, key: []const u8) ?Decoded {
        const raw = self.store.get(key, self.now(), self.generation) orelse return null;
        if (raw.len == 0) return .corrupt;
        return switch (raw[0]) {
            tag_value => .{ .value = raw[1..] },
            tag_missing => .missing,
            tag_error => .err,
            else => .corrupt,
        };
    }

    /// Store a tagged entry (tag byte + payload) into ramcache. Caller holds the
    /// lock. Silently no-ops on OOM (a failed store just means the next get
    /// reloads — a cache miss is never fatal).
    fn storeLocked(self: *Cache, key: []const u8, tag: u8, payload: []const u8, ttl: i64) void {
        const buf = self.gpa.alloc(u8, payload.len + 1) catch return;
        defer self.gpa.free(buf);
        buf[0] = tag;
        @memcpy(buf[1..], payload);
        // ramcache dupes `buf` internally, so freeing our temp is correct.
        self.store.put(key, buf, self.now(), ttl, self.generation);
    }

    /// Wait for `call` to be published, then materialize this participant's
    /// result and drop its reference.
    fn awaitCall(self: *Cache, call: *Call) anyerror!Loaded {
        while (call.done.load(.acquire) == 0) {
            self.io.futexWaitTimeout(u32, &call.done.raw, 0, .{ .duration = .{
                .raw = .fromMilliseconds(100),
                .clock = .awake,
            } }) catch {};
        }
        return self.finish(call);
    }

    /// Read `call.result` into this participant's owned return value, then
    /// release its reference (freeing the Call when the last participant leaves).
    fn finish(self: *Cache, call: *Call) anyerror!Loaded {
        self.lock.lock();
        var out: Loaded = .missing;
        var err: ?anyerror = null;
        switch (call.result) {
            .value => |v| {
                if (self.gpa.dupe(u8, v)) |d| {
                    out = .{ .value = d };
                } else |e| {
                    err = e;
                }
            },
            .missing => out = .missing,
            .err => |e| err = e,
        }
        self.releaseLocked(call);
        self.lock.unlock();
        if (err) |e| return e;
        return out;
    }

    /// Drop one reference to `call`; free it (and its owned buffer) at zero.
    /// Caller holds the lock.
    fn releaseLocked(self: *Cache, call: *Call) void {
        call.refs -= 1;
        if (call.refs != 0) return;
        switch (call.result) {
            // Unconditional: a zero-length value is a real, owned allocation
            // like any other now that OOM no longer masquerades as one.
            .value => |v| self.gpa.free(v),
            else => {},
        }
        self.gpa.destroy(call);
    }

    fn now(self: *Cache) i64 {
        if (self.clock) |c| return c.now();
        return @intCast(std.Io.Timestamp.now(self.io, .awake).nanoseconds);
    }
};

// ── tests ────────────────────────────────────────────────────────────────────
// Deterministic where it matters (an injected manual clock drives TTL; a loader
// counts its own invocations). `testing.allocator` is a leak-checking
// DebugAllocator, so every test also proves no leaked Call / in-flight key /
// value across the full lifecycle. Concurrency tests live in `tests.zig`, pulled
// in by the aggregator below (the dark-tests rule, CONVENTIONS §6.3).

test {
    _ = @import("tests.zig");
}

const testing = std.testing;

/// A manual clock: tests set `t` directly to drive TTL without sleeping.
const ManualClock = struct {
    t: i64 = 0,
    fn nowFn(ctx: *anyopaque) i64 {
        return @as(*ManualClock, @ptrCast(@alignCast(ctx))).t;
    }
    fn clock(self: *ManualClock) Clock {
        return .{ .ctx = self, .now_fn = nowFn };
    }
};

/// A loader over a fixed in-memory table that counts its invocations. `absent`
/// keys return `.missing`; keys in `fail` return an error.
const CountingLoader = struct {
    calls: std.atomic.Value(u64) = .init(0),
    table: std.StringHashMapUnmanaged([]const u8) = .empty,
    fail: bool = false,

    fn deinit(self: *CountingLoader, gpa: Allocator) void {
        self.table.deinit(gpa);
    }
    fn put(self: *CountingLoader, gpa: Allocator, k: []const u8, v: []const u8) !void {
        try self.table.put(gpa, k, v);
    }
    fn loadFn(ctx: ?*anyopaque, key: []const u8) anyerror!LoadOutcome {
        const self: *CountingLoader = @ptrCast(@alignCast(ctx.?));
        _ = self.calls.fetchAdd(1, .monotonic);
        if (self.fail) return error.BackendDown;
        if (self.table.get(key)) |v| return .{ .value = v };
        return .missing;
    }
    fn loader(self: *CountingLoader) Loader {
        return .{ .ctx = self, .load = loadFn };
    }
};

/// A single-threaded test rig (a real `std.Io.Threaded` for the futex, a manual
/// clock, a counting loader). Single-threaded loads never actually park, so the
/// futex is inert here — the threaded coalescing proof lives in `tests.zig`.
const Rig = struct {
    threaded: std.Io.Threaded,
    clock: ManualClock,
    ldr: CountingLoader,

    fn init(rig: *Rig) void {
        rig.* = .{
            .threaded = std.Io.Threaded.init(testing.allocator, .{}),
            .clock = .{},
            .ldr = .{},
        };
    }
    fn deinit(rig: *Rig) void {
        rig.ldr.deinit(testing.allocator);
        rig.threaded.deinit();
    }
    fn open(rig: *Rig, opts: struct {
        ttl_ns: i64 = 0,
        negative_ttl_ns: i64 = 0,
        cache_loader_errors: bool = false,
        max_entries: usize = 64,
    }) Cache {
        return Cache.init(testing.allocator, .{
            .io = rig.threaded.io(),
            .loader = rig.ldr.loader(),
            .clock = rig.clock.clock(),
            .ttl_ns = opts.ttl_ns,
            .negative_ttl_ns = opts.negative_ttl_ns,
            .cache_loader_errors = opts.cache_loader_errors,
            .max_bytes = 1 << 20,
            .max_entries = opts.max_entries,
        });
    }
};

test "read-through: miss loads, second get is a hit (loader not called again)" {
    var rig: Rig = undefined;
    rig.init();
    defer rig.deinit();
    try rig.ldr.put(testing.allocator, "k", "v");
    var c = rig.open(.{});
    defer c.deinit();

    const a = try c.get("k");
    defer c.free(a);
    try testing.expectEqualStrings("v", a.value);
    try testing.expectEqual(@as(u64, 1), rig.ldr.calls.load(.monotonic));

    const b = try c.get("k");
    defer c.free(b);
    try testing.expectEqualStrings("v", b.value);
    try testing.expectEqual(@as(u64, 1), rig.ldr.calls.load(.monotonic)); // still 1: served from cache
    try testing.expectEqual(@as(u64, 1), c.getStats().hits);
}

test "deinit reclaims BOTH halves of a leftover in-flight pair (key AND Call), not just the key" {
    // Simulates a quiescence-contract violation the same shape `deinit`'s own
    // doc comment warns against (a load that never completed before deinit),
    // WITHOUT actually racing a real load -- inserted directly, the way a
    // leader's registration (`get`'s `self.in_flight.put(...)`) would have
    // left it. `testing.allocator` fails this test on any unfreed
    // allocation, so a regression (freeing only the key, leaking the `*Call`
    // again) shows up as a leak report pointing at the `create(Call)` below.
    var rig: Rig = undefined;
    rig.init();
    defer rig.deinit();
    var c = rig.open(.{});

    const call = try testing.allocator.create(Call);
    call.* = .{};
    const kdup = try testing.allocator.dupe(u8, "leftover");
    try c.in_flight.put(testing.allocator, kdup, call);

    c.deinit(); // must free both `kdup` and `call`, or testing.allocator flags a leak
}

test "corrupt entry (zero-length payload, no tag byte) surfaces as a typed error, not UB" {
    // `decodeFreshLocked` used to index `raw[0]` unchecked and close its tag
    // switch with `else => unreachable` -- safe today only via a cross-module
    // invariant (every entry `storeLocked` ever writes has a tag byte) that
    // this test deliberately violates by writing straight through the
    // underlying `ramcache.Cache`, bypassing `storeLocked` entirely, the way
    // a future `ramcache` behavior change could.
    var rig: Rig = undefined;
    rig.init();
    defer rig.deinit();
    var c = rig.open(.{});
    defer c.deinit();

    c.store.put("k", &.{}, c.now(), 1_000_000_000, c.generation);
    try testing.expectError(error.CorruptEntry, c.get("k"));
}

test "distinct keys load independently" {
    var rig: Rig = undefined;
    rig.init();
    defer rig.deinit();
    try rig.ldr.put(testing.allocator, "a", "1");
    try rig.ldr.put(testing.allocator, "b", "2");
    var c = rig.open(.{});
    defer c.deinit();

    const a = try c.get("a");
    defer c.free(a);
    const b = try c.get("b");
    defer c.free(b);
    try testing.expectEqualStrings("1", a.value);
    try testing.expectEqualStrings("2", b.value);
    try testing.expectEqual(@as(u64, 2), rig.ldr.calls.load(.monotonic));
}

test "TTL: an entry past its TTL reloads (deterministic clock, no sleep)" {
    var rig: Rig = undefined;
    rig.init();
    defer rig.deinit();
    try rig.ldr.put(testing.allocator, "k", "v");
    var c = rig.open(.{ .ttl_ns = 100 });
    defer c.deinit();

    rig.clock.t = 1000;
    const a = try c.get("k");
    c.free(a);
    try testing.expectEqual(@as(u64, 1), rig.ldr.calls.load(.monotonic));

    rig.clock.t = 1050; // 50ns old → still fresh
    const b = try c.get("k");
    c.free(b);
    try testing.expectEqual(@as(u64, 1), rig.ldr.calls.load(.monotonic));

    rig.clock.t = 1201; // 201ns old → expired, reload
    const d = try c.get("k");
    c.free(d);
    try testing.expectEqual(@as(u64, 2), rig.ldr.calls.load(.monotonic));
}

test "invalidate(key): next get reloads; other keys untouched" {
    var rig: Rig = undefined;
    rig.init();
    defer rig.deinit();
    try rig.ldr.put(testing.allocator, "k", "v");
    try rig.ldr.put(testing.allocator, "other", "x");
    var c = rig.open(.{});
    defer c.deinit();

    c.free(try c.get("k"));
    c.free(try c.get("other"));
    try testing.expectEqual(@as(u64, 2), rig.ldr.calls.load(.monotonic));

    c.invalidate("k");
    c.free(try c.get("k")); // reload
    try testing.expectEqual(@as(u64, 3), rig.ldr.calls.load(.monotonic));
    c.free(try c.get("other")); // still cached
    try testing.expectEqual(@as(u64, 3), rig.ldr.calls.load(.monotonic));
}

test "F5: invalidate() drops the entry's slot immediately, not on a later touch" {
    var rig: Rig = undefined;
    rig.init();
    defer rig.deinit();
    try rig.ldr.put(testing.allocator, "k", "v");
    var c = rig.open(.{});
    defer c.deinit();

    c.free(try c.get("k")); // populate
    try testing.expectEqual(@as(usize, 1), c.store.stats.entries);

    c.invalidate("k");
    // No further `get`/`ifCached`/eviction touched "k" — the slot must
    // already be gone, not merely shadowed and waiting to be discovered.
    try testing.expectEqual(@as(usize, 0), c.store.stats.entries);
}

test "invalidate on an absent key inserts no junk and just forces a load" {
    var rig: Rig = undefined;
    rig.init();
    defer rig.deinit();
    try rig.ldr.put(testing.allocator, "k", "v");
    var c = rig.open(.{});
    defer c.deinit();

    c.invalidate("k"); // never loaded yet
    try testing.expectEqual(@as(usize, 0), c.store.stats.entries); // no poison entry left behind
    c.free(try c.get("k"));
    try testing.expectEqual(@as(u64, 1), rig.ldr.calls.load(.monotonic));
}

test "invalidateAll: generation bump reloads everything" {
    var rig: Rig = undefined;
    rig.init();
    defer rig.deinit();
    try rig.ldr.put(testing.allocator, "a", "1");
    try rig.ldr.put(testing.allocator, "b", "2");
    var c = rig.open(.{});
    defer c.deinit();

    c.free(try c.get("a"));
    c.free(try c.get("b"));
    try testing.expectEqual(@as(u64, 2), rig.ldr.calls.load(.monotonic));

    c.invalidateAll();
    c.free(try c.get("a"));
    c.free(try c.get("b"));
    try testing.expectEqual(@as(u64, 4), rig.ldr.calls.load(.monotonic)); // both reloaded
}

test "negative caching: a 'not found' is cached for the negative TTL, then retried" {
    var rig: Rig = undefined;
    rig.init();
    defer rig.deinit();
    // "gone" is absent from the loader table → .missing.
    var c = rig.open(.{ .negative_ttl_ns = 50 });
    defer c.deinit();

    rig.clock.t = 0;
    try testing.expect((try c.get("gone")) == .missing);
    try testing.expectEqual(@as(u64, 1), rig.ldr.calls.load(.monotonic));

    // Within the negative TTL: served from the negative cache, no loader call.
    rig.clock.t = 40;
    try testing.expect((try c.get("gone")) == .missing);
    try testing.expectEqual(@as(u64, 1), rig.ldr.calls.load(.monotonic));
    try testing.expectEqual(@as(u64, 1), c.getStats().negative_hits);

    // Past the negative TTL: retried.
    rig.clock.t = 60;
    try testing.expect((try c.get("gone")) == .missing);
    try testing.expectEqual(@as(u64, 2), rig.ldr.calls.load(.monotonic));
}

test "negative caching disabled (negative_ttl_ns = 0): every miss re-hits the loader" {
    var rig: Rig = undefined;
    rig.init();
    defer rig.deinit();
    var c = rig.open(.{}); // negative_ttl_ns defaults to 0
    defer c.deinit();

    try testing.expect((try c.get("gone")) == .missing);
    try testing.expect((try c.get("gone")) == .missing);
    try testing.expectEqual(@as(u64, 2), rig.ldr.calls.load(.monotonic));
}

test "loader error propagates and is NOT cached by default" {
    var rig: Rig = undefined;
    rig.init();
    defer rig.deinit();
    rig.ldr.fail = true;
    var c = rig.open(.{ .negative_ttl_ns = 50 }); // errors still off (cache_loader_errors=false)
    defer c.deinit();

    try testing.expectError(error.BackendDown, c.get("k"));
    try testing.expectError(error.BackendDown, c.get("k"));
    try testing.expectEqual(@as(u64, 2), rig.ldr.calls.load(.monotonic)); // re-hit each time
}

test "loader error IS cached when cache_loader_errors is on, then retried after the TTL" {
    var rig: Rig = undefined;
    rig.init();
    defer rig.deinit();
    rig.ldr.fail = true;
    var c = rig.open(.{ .negative_ttl_ns = 50, .cache_loader_errors = true });
    defer c.deinit();

    rig.clock.t = 0;
    try testing.expectError(error.BackendDown, c.get("k")); // fresh load → original error
    try testing.expectEqual(@as(u64, 1), rig.ldr.calls.load(.monotonic));

    rig.clock.t = 40; // cached error → CachedLoaderError, no loader call
    try testing.expectError(error.CachedLoaderError, c.get("k"));
    try testing.expectEqual(@as(u64, 1), rig.ldr.calls.load(.monotonic));
    try testing.expectEqual(@as(u64, 1), c.getStats().negative_hits);

    rig.clock.t = 60; // past negative TTL → retried
    try testing.expectError(error.BackendDown, c.get("k"));
    try testing.expectEqual(@as(u64, 2), rig.ldr.calls.load(.monotonic));
}

test "ifCached: zero-alloc hit hands the borrowed value to a callback; miss returns false" {
    var rig: Rig = undefined;
    rig.init();
    defer rig.deinit();
    try rig.ldr.put(testing.allocator, "k", "hello");
    var c = rig.open(.{});
    defer c.deinit();

    const Sink = struct {
        buf: [16]u8 = undefined,
        len: usize = 0,
        fn cb(ctx: ?*anyopaque, value: []const u8) void {
            const s: *@This() = @ptrCast(@alignCast(ctx.?));
            @memcpy(s.buf[0..value.len], value);
            s.len = value.len;
        }
    };
    var sink: Sink = .{};

    try testing.expect(!c.ifCached("k", &sink, Sink.cb)); // not loaded yet → miss
    c.free(try c.get("k")); // populate
    try testing.expect(c.ifCached("k", &sink, Sink.cb)); // now a hit
    try testing.expectEqualStrings("hello", sink.buf[0..sink.len]);
}

test "F5: ifCached counts its own misses, so hits + misses == requests through ifCached alone" {
    var rig: Rig = undefined;
    rig.init();
    defer rig.deinit();
    try rig.ldr.put(testing.allocator, "k", "v");
    var c = rig.open(.{});
    defer c.deinit();

    const Sink = struct {
        fn cb(ctx: ?*anyopaque, value: []const u8) void {
            _ = ctx;
            _ = value;
        }
    };

    // Nothing cached yet: a bare ifCached miss must count, on its own,
    // without ever going through `get`.
    try testing.expect(!c.ifCached("k", null, Sink.cb));
    try testing.expectEqual(@as(u64, 1), c.getStats().misses);
    try testing.expectEqual(@as(u64, 0), c.getStats().hits);

    c.free(try c.get("k")); // populate (get's own miss/hit accounting)
    const after_get = c.getStats();

    try testing.expect(c.ifCached("k", null, Sink.cb)); // now a hit
    const after_hit = c.getStats();
    try testing.expectEqual(after_get.hits + 1, after_hit.hits);
    try testing.expectEqual(after_get.misses, after_hit.misses); // unchanged
}

test "ifCached: a negatively-cached (missing) entry is NOT surfaced as a hit" {
    var rig: Rig = undefined;
    rig.init();
    defer rig.deinit();
    // "gone" is absent from the loader table → negatively cached as .missing.
    var c = rig.open(.{ .negative_ttl_ns = 1000 });
    defer c.deinit();

    try testing.expect((try c.get("gone")) == .missing); // populates the negative entry
    try testing.expectEqual(@as(u64, 1), c.getStats().misses);

    const Sink = struct {
        called: bool = false,
        fn cb(ctx: ?*anyopaque, value: []const u8) void {
            _ = value;
            const s: *@This() = @ptrCast(@alignCast(ctx.?));
            s.called = true;
        }
    };
    var sink: Sink = .{};
    // A fresh negative entry exists, but ifCached only fast-paths POSITIVE
    // hits — it must return false and never invoke the callback.
    try testing.expect(!c.ifCached("gone", &sink, Sink.cb));
    try testing.expect(!sink.called);
}

test "value is copied out of the cache (caller owns it across an invalidation)" {
    var rig: Rig = undefined;
    rig.init();
    defer rig.deinit();
    try rig.ldr.put(testing.allocator, "k", "durable");
    var c = rig.open(.{});
    defer c.deinit();

    const a = try c.get("k");
    defer c.free(a);
    c.invalidateAll(); // would shadow the stored entry
    try testing.expectEqualStrings("durable", a.value); // the returned copy is unaffected
}

/// An allocator that refuses every allocation of exactly `fail_len` bytes and
/// forwards everything else. Targeting a *size* rather than an ordinal makes
/// the OOM land on a specific `dupe` without depending on how many allocations
/// ramcache happens to make first (which `std.testing.FailingAllocator` would).
pub const SizeFailAllocator = struct {
    child: Allocator,
    fail_len: usize,
    /// How many allocations were actually refused — asserted by the tests, so
    /// a rig that stops reaching the target path cannot silently pass.
    /// Atomic: the threaded follower test shares one of these across threads.
    denied: std.atomic.Value(usize) = .init(0),

    fn alloc(ctx: *anyopaque, len: usize, alignment: std.mem.Alignment, ra: usize) ?[*]u8 {
        const self: *SizeFailAllocator = @ptrCast(@alignCast(ctx));
        if (len == self.fail_len) {
            _ = self.denied.fetchAdd(1, .monotonic);
            return null;
        }
        return self.child.rawAlloc(len, alignment, ra);
    }
    fn resize(ctx: *anyopaque, m: []u8, alignment: std.mem.Alignment, new_len: usize, ra: usize) bool {
        const self: *SizeFailAllocator = @ptrCast(@alignCast(ctx));
        if (new_len == self.fail_len) return false;
        return self.child.rawResize(m, alignment, new_len, ra);
    }
    fn remap(ctx: *anyopaque, m: []u8, alignment: std.mem.Alignment, new_len: usize, ra: usize) ?[*]u8 {
        const self: *SizeFailAllocator = @ptrCast(@alignCast(ctx));
        if (new_len == self.fail_len) return null;
        return self.child.rawRemap(m, alignment, new_len, ra);
    }
    fn free(ctx: *anyopaque, m: []u8, alignment: std.mem.Alignment, ra: usize) void {
        const self: *SizeFailAllocator = @ptrCast(@alignCast(ctx));
        self.child.rawFree(m, alignment, ra);
    }

    pub fn allocator(self: *SizeFailAllocator) Allocator {
        return .{ .ptr = self, .vtable = &.{
            .alloc = alloc,
            .resize = resize,
            .remap = remap,
            .free = free,
        } };
    }
};

test "OOM on the leader's result copy surfaces as an error, not as an empty value" {
    // The two outcomes the caller must be able to tell apart:
    //   (a) the backend legitimately returned a zero-length value  ⇒ `.value`
    //       with `len == 0`;
    //   (b) the return copy could not be allocated                 ⇒ an error.
    // The leader used to substitute `&[_]u8{}` for (b), making it byte-identical
    // to (a) at the caller while the cache still held the correct bytes — so the
    // failure self-healed on the next get and was never reportable.
    // `SPEC.md` §6 promises `error.OutOfMemory`.
    const value_len = 4093; // a size ramcache/the key path never asks for
    const big = "x" ** value_len;

    // (a) a genuinely empty backend value is a value, and stays one.
    {
        var rig: Rig = undefined;
        rig.init();
        defer rig.deinit();
        try rig.ldr.put(testing.allocator, "empty", "");
        var c = rig.open(.{});
        defer c.deinit();

        const got = try c.get("empty");
        defer c.free(got);
        try testing.expect(got == .value);
        try testing.expectEqual(@as(usize, 0), got.value.len);
    }

    // (b) the same shape at the caller must NOT be reachable by failing the copy.
    {
        var fa: SizeFailAllocator = .{ .child = testing.allocator, .fail_len = value_len };
        var rig: Rig = undefined;
        rig.init();
        defer rig.deinit();
        try rig.ldr.put(testing.allocator, "k", big);
        var c = Cache.init(fa.allocator(), .{
            .io = rig.threaded.io(),
            .loader = rig.ldr.loader(),
            .clock = rig.clock.clock(),
            .max_bytes = 1 << 20,
            .max_entries = 64,
        });
        defer c.deinit();

        try testing.expectError(error.OutOfMemory, c.get("k"));
        // The rig really did exercise the intended path, not some other one.
        try testing.expect(fa.denied.load(.monotonic) > 0);
        // And no Call / in-flight key was leaked by the error path: the
        // leak-checking child allocator would report it at test teardown.
        try testing.expectEqual(@as(usize, 1), c.getStats().loads);
    }
}

test "meta is well-formed" {
    try testing.expect(meta.platform == .any);
    try testing.expect(meta.concurrency == .threadsafe);
    try testing.expect(meta.deps.len == 1);
}
