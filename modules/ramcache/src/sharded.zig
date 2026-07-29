// SPDX-License-Identifier: MIT

//! `ramcache.Sharded` — the internally-synchronized ("threadsafe") face of this
//! module, built *alongside* `Cache`, never inside it.
//!
//! ## Why a wrapper and not a lock on `Cache`
//!
//! `Cache` is `.single_owner` on purpose: no lock, no atomics, no memory
//! barriers on the hit path. Five modules in this repo (`idempotency`,
//! `writebehind`, `pagecache`, `readthrough`, `sessions`) own an instance from
//! one thread and would pay for a lock they never need. So the shared-access
//! story is a separate type: `Sharded` holds **N independent `Cache`
//! instances**, each behind its own spinlock, and picks one by hashing the key.
//! `Cache` itself is byte-for-byte unchanged.
//!
//! ## Safety argument (structural, not empirical)
//!
//!   1. Every field of a shard's `Cache` is touched only between
//!      `lockSpin(&shard.lock)` and `shard.lock.unlock()`. No method on this
//!      type hands out a `*Cache`, a `*Shard`, or anything reachable from one
//!      (Zig has no field privacy, so "reach into `.shards` yourself" remains
//!      physically possible and is simply outside the contract — as it is for
//!      every lock-protected struct in this repo).
//!   2. Nothing derived from a `Cache` outlives its critical section. In
//!      particular no method returns a slice into cache storage (see the value
//!      handoff section) — the only slices that leave are copies the caller
//!      owns or the caller's own buffer.
//!   3. A key maps to exactly one shard, by a pure function of the key bytes
//!      (`shardIndex`), and no entry is ever moved between shards. So two
//!      shards never share a byte of state.
//!   4. No operation ever holds two shard locks at once. The aggregate
//!      operations (`stats`, `clear`, `drainDirty`) walk the shards
//!      **sequentially**, taking and releasing one lock at a time.
//!
//! (1)+(2) give each shard a serialized single owner, which is exactly the
//! contract `Cache` was written against, so every `Cache` invariant carries
//! over per shard. (3) means correctness composes across shards. (4) means
//! there is no lock order to get wrong, hence no deadlock between shards.
//!
//! ## Value handoff — why `get` does NOT mirror `Cache.get`
//!
//! `Cache.get` returns a slice **borrowing** the cache's own storage, valid
//! until that key is next replaced, evicted or cleared. That contract cannot
//! be honoured concurrently: the instant this type released the shard lock,
//! another thread could evict or overwrite the entry and free the bytes under
//! the caller's slice. Mirroring the signature would produce an API that looks
//! identical and corrupts memory under load, so it is deliberately not
//! offered. The signatures here differ, so single-owner code copied across
//! fails to *compile* rather than failing at runtime.
//!
//! Two safe handoffs are offered, both of which finish copying before the lock
//! is released:
//!
//!   * `getBuf(key, …, buf)` — copies into a caller-supplied buffer and
//!     returns a `GetResult`. Zero allocation; the default.
//!   * `get(key, …)` — returns an allocator-owned copy, released with `free`.
//!     For callers who do not know a bound on the value size.
//!
//! Rejected alternatives:
//!
//!   * *Return the borrowed slice and document "copy it fast".* Unfixable —
//!     the window is not the caller's to control. This is the bug this section
//!     exists to prevent.
//!   * *A `withValue(key, cb)` callback invoked while the shard lock is held*
//!     (the zero-copy option; `readthrough.ifCached` does exactly this over
//!     its single global lock). Dropped because `getBuf` already delivers the
//!     zero-allocation hit path without running caller code under a
//!     non-reentrant spinlock, where a callback that touches this same cache
//!     hangs the process. Every under-lock callback is a deadlock surface;
//!     this type keeps exactly one (`drainDirty`), where it is unavoidable.
//!
//! ## Eviction is per-shard — this is NOT a sharded view of one cache
//!
//! Every piece of W-TinyLFU state is per shard: the admission gate, the
//! Count-Min Sketch, the doorkeeper, the aging counter and the recency
//! ordering. Consequences, stated plainly:
//!
//!   * **Admission quality drops.** Each sketch sees ~1/N of the traffic, so
//!     its frequency estimates are built from N× fewer samples and the aging
//!     window (~10× the *per-shard* capacity) turns over on a shorter history.
//!     A key that is globally hot but spread thin is judged only against its
//!     own shard's population.
//!   * **The caps are divided, not shared.** `max_entries` and `max_bytes`
//!     are floor-divided by the shard count; each shard enforces its slice
//!     independently. So a hot shard evicts while a cold one still has room,
//!     and the achievable occupancy is below the nominal cap whenever the key
//!     distribution is uneven. Because of the floor division the *effective*
//!     aggregate cap is `N × (cap / N)`, i.e. rounded down to a multiple of N,
//!     never above what the caller asked for.
//!   * **The single-item limit tightens.** `Cache` refuses a value larger than
//!     `max_bytes`; here the bar is `max_bytes / N`.
//!   * The shard count is rounded **up** to a power of two, then clamped down
//!     so no shard gets a zero cap (see `init`). Ask for more shards than
//!     `max_entries` and you get fewer shards, not empty ones.
//!
//! The shard hash uses a Wyhash seed distinct from the frequency sketch's. If
//! it did not, every key in a shard would share the low bits of the sketch's
//! hash, collapsing the doorkeeper's index space to 1/N of its range and
//! systematically inflating collisions inside each shard.
//!
//! ## Aggregate operations are not atomic across shards
//!
//! `stats`, `clear` and `drainDirty` take one lock at a time, so a concurrent
//! writer can change a shard that was already visited (or one not yet
//! reached). What each does guarantee:
//!
//!   * `stats` — a per-shard-consistent, globally **approximate** snapshot.
//!     Each shard's counters are read atomically with respect to that shard,
//!     the sum is not atomic with respect to the whole cache. The lifetime
//!     counters (`hits`/`misses`/`evictions`/`expired`/`admissions`/
//!     `rejections`) are monotonic, so the returned sum lies between the true
//!     aggregate at the moment the first shard was read and the true aggregate
//!     at the moment the last shard was read. `entries`/`bytes` are not
//!     monotonic and get no such bound — they are a mix of readings taken at
//!     different instants and may correspond to no state the cache was ever
//!     in. Fine for metrics, not a basis for an equality assertion in a live
//!     system.
//!   * `clear` — every entry that was present in shard *i* when shard *i*'s
//!     lock was taken is gone. It does **not** guarantee the cache was ever
//!     observably empty: a writer can repopulate shard 0 while shard 5 is
//!     still being cleared.
//!   * `drainDirty` — visits every entry that was dirty in shard *i* when
//!     shard *i*'s lock was taken, exactly once. Entries dirtied after their
//!     shard was visited are simply seen by the next sweep.
//!
//! ## `on_evict` becomes a concurrent callback — a contract change
//!
//! With `Cache`, `on_evict` fires on the one owning thread. Here it fires from
//! **whichever thread** triggered the removal (a `put` that evicted, a `get`
//! that lazily dropped a stale entry, a `clear`), while that shard's lock is
//! held. Therefore the hook:
//!
//!   * must be thread-safe and re-entrant across threads — several shards can
//!     fire it simultaneously;
//!   * **must not call any method on this `Sharded`.** Re-entering the same
//!     shard on a non-reentrant spinlock is a hard hang, not a detected error.
//!     (`Cache` documents the same restriction as "unsupported"; here the
//!     failure mode is a deadlock, which is why it is repeated in bold.)
//!   * must stay cheap: it runs inside a critical section shared by every key
//!     that hashes to that shard.
//!
//! Its `key`/`value` slices are valid only for the duration of the call —
//! unchanged from `Cache`, and for the same reason.
//!
//! ## Write-behind seam — preserved, with one addition
//!
//! `isDirty` / `markClean` / `drainDirty` / `on_evict` are all here and mean
//! what they mean on `Cache`, per shard. Two things are genuinely different
//! and cannot be papered over:
//!
//!   * `drainDirty`'s callback runs with the shard lock held and therefore
//!     **must not call back into this `Sharded`** — including `markClean`,
//!     which `Cache.drainDirty` explicitly permits. Copy what you need and act
//!     after the sweep returns.
//!   * Doing exactly that opens a race `Cache` does not have: between
//!     observing a dirty value and calling `markClean(key)`, another thread
//!     can `put` a *newer* value, and the late `markClean` would clear the
//!     dirty bit of a write that was never persisted — a silently lost write.
//!     `markCleanIf(key, flushed_value)` closes it: it clears the bit only if
//!     the stored value still equals the bytes that were persisted.
//!
//! ## Requirements on the caller
//!
//! The allocator is shared by all shards and is used from every calling
//! thread (including inside `get`, which allocates the returned copy while
//! holding a shard lock) — it **must be thread-safe**. `init`/`deinit` are
//! not synchronized against anything: like any constructor/destructor, they
//! run before the first and after the last concurrent access.

const std = @import("std");
const Allocator = std.mem.Allocator;

const root = @import("root.zig");
const Cache = root.Cache;
const Stats = root.Stats;
const OnEvictFn = root.OnEvictFn;
const DirtyFn = root.DirtyFn;

/// The repo's 0.16 spinlock idiom (there is no `std.Thread.Mutex` in this era)
/// — same as `idempotency`, `ratelimit`, `resilience`, `readthrough`.
/// Non-reentrant and non-yielding: critical sections here are a hash lookup
/// plus a bounded memcpy.
fn lockSpin(m: *std.atomic.Mutex) void {
    while (!m.tryLock()) std.atomic.spinLoopHint();
}

pub const Sharded = struct {
    /// Tunables, fixed at `init`. `max_bytes`/`max_entries` are **aggregate**
    /// budgets — see the per-shard division in the module doc.
    pub const Options = struct {
        /// Aggregate cap on stored value bytes; each shard enforces
        /// `max_bytes / shard_count` of it independently.
        max_bytes: usize,
        /// Aggregate cap on entry count; each shard enforces
        /// `max_entries / shard_count` of it independently.
        max_entries: usize,
        /// Requested shard count. Rounded **up** to a power of two, then
        /// clamped down so every shard keeps a non-zero byte and entry cap.
        /// The useful range is "a few times the number of writer threads";
        /// more shards buy less contention and cost admission quality.
        shards: usize = 16,
        /// TTL applied by `putDefault`. `<= 0` = never expire by time.
        default_ttl_ns: i64 = 0,
        /// Optional write-behind hook. **Fires from any thread, with a shard
        /// lock held** — see the module doc's contract-change section.
        on_evict: ?OnEvictFn = null,
        /// Opaque pointer handed to every `on_evict` call.
        on_evict_ctx: ?*anyopaque = null,
    };

    /// Outcome of `getBuf`. Deliberately not `?[]const u8`: "the value is
    /// there but does not fit" is a distinct case a caller must handle, and
    /// silently reporting it as a miss would hide a sizing bug behind a
    /// plausible-looking cache miss.
    pub const GetResult = union(enum) {
        /// Absent, TTL-expired or generation-stale (and dropped in passing,
        /// exactly as `Cache.get` does).
        miss,
        /// A hit. The slice is a **prefix of the caller's own buffer**, not
        /// cache storage — it is as valid as that buffer is.
        ok: []const u8,
        /// A hit whose value does not fit `buf`; payload is the value's
        /// length, so the caller can size a buffer and retry. Nothing was
        /// written to `buf`. NOTE: the underlying lookup already happened —
        /// it counted as a hit and refreshed the entry's recency.
        buffer_too_small: usize,
    };

    /// One independently-locked cache. Cache-line aligned so two shards'
    /// locks never share a line: false sharing between the lock words would
    /// give back exactly the contention sharding exists to remove.
    const Shard = struct {
        lock: std.atomic.Mutex align(std.atomic.cache_line) = .unlocked,
        cache: Cache,
    };

    /// Seed distinct from `FrequencySketch`'s (`0` and `0x2545F4914F6CDD1D`).
    /// See the module doc: sharing it would confine each shard's keys to 1/N
    /// of the doorkeeper index space.
    const shard_seed: u64 = 0x9AE16A3B2F90404F;

    alloc: Allocator,
    shards: []Shard,
    mask: u64,
    /// The per-shard caps actually handed to each `Cache` — exposed because
    /// they, not `Options`, are what eviction enforces.
    per_shard_max_bytes: usize,
    per_shard_max_entries: usize,

    /// Allocate and initialize the shards. The shard count is
    /// `ceilPowerOfTwo(options.shards)`, clamped down so that neither
    /// `max_bytes / n` nor `max_entries / n` is zero (asking for 32 shards of
    /// a 4-entry cache gives 4 shards, not 32 shards that can hold nothing).
    /// A power of two lets `shardIndex` mask instead of divide.
    pub fn init(alloc: Allocator, options: Options) Allocator.Error!Sharded {
        const requested = @max(@as(usize, 1), options.shards);
        var n: usize = std.math.ceilPowerOfTwo(usize, requested) catch
            std.math.floorPowerOfTwo(usize, requested); // absurd request: round down instead
        if (options.max_entries < n) n = std.math.floorPowerOfTwo(usize, @max(@as(usize, 1), options.max_entries));
        if (options.max_bytes < n) n = std.math.floorPowerOfTwo(usize, @max(@as(usize, 1), options.max_bytes));
        n = @max(@as(usize, 1), n);

        const per_bytes = options.max_bytes / n;
        const per_entries = options.max_entries / n;

        const shards = try alloc.alloc(Shard, n);
        for (shards) |*s| s.* = .{ .cache = Cache.init(alloc, .{
            .max_bytes = per_bytes,
            .max_entries = per_entries,
            .default_ttl_ns = options.default_ttl_ns,
            .on_evict = options.on_evict,
            .on_evict_ctx = options.on_evict_ctx,
        }) };
        return .{
            .alloc = alloc,
            .shards = shards,
            .mask = n - 1,
            .per_shard_max_bytes = per_bytes,
            .per_shard_max_entries = per_entries,
        };
    }

    /// Free every shard and the shard array. Not synchronized — the caller
    /// guarantees no concurrent access, as for any destructor.
    pub fn deinit(self: *Sharded) void {
        for (self.shards) |*s| s.cache.deinit();
        self.alloc.free(self.shards);
    }

    /// The shard `key` lives in. A pure function of the key bytes — this is
    /// what makes "no state is shared between shards" true by construction.
    /// Public because a skewed key distribution is a real operational
    /// question, and `shardStats` is how you answer it.
    pub fn shardIndex(self: *const Sharded, key: []const u8) usize {
        return @intCast(std.hash.Wyhash.hash(shard_seed, key) & self.mask);
    }

    /// Number of shards actually allocated (may be less than `Options.shards`
    /// asked for — see `init`).
    pub fn shardCount(self: *const Sharded) usize {
        return self.shards.len;
    }

    // ── reads ───────────────────────────────────────────────────────────────

    /// Copy the value for `key` into `buf` if it is present and fresh.
    /// Allocation-free; the whole lookup and copy happen under one shard lock,
    /// so the bytes in `buf` are a coherent snapshot of one stored value and
    /// stay valid however the cache changes afterwards.
    ///
    /// Semantics of `key`/`now_ns`/`cur_gen` are `Cache.get`'s, unchanged: a
    /// TTL-expired or generation-stale entry is dropped in passing, and every
    /// call records the key in that shard's frequency sketch.
    ///
    /// Deliberately NOT returning a borrowed slice — see the module doc.
    pub fn getBuf(self: *Sharded, key: []const u8, now_ns: i64, cur_gen: u64, buf: []u8) GetResult {
        const s = &self.shards[self.shardIndex(key)];
        lockSpin(&s.lock);
        defer s.lock.unlock();
        const borrowed = s.cache.get(key, now_ns, cur_gen) orelse return .miss;
        if (borrowed.len > buf.len) return .{ .buffer_too_small = borrowed.len };
        @memcpy(buf[0..borrowed.len], borrowed);
        return .{ .ok = buf[0..borrowed.len] };
    }

    /// Like `getBuf`, but returns a copy owned by the cache's allocator —
    /// release it with `free`. For callers with no bound on the value size.
    /// `null` = miss. The copy is made while the shard lock is held (the
    /// allocator must therefore be thread-safe); on allocator failure the
    /// lookup has already been counted as a hit and the error is returned
    /// rather than degraded to a miss, because losing a value that IS cached
    /// is worth telling the caller about.
    pub fn get(self: *Sharded, key: []const u8, now_ns: i64, cur_gen: u64) Allocator.Error!?[]u8 {
        const s = &self.shards[self.shardIndex(key)];
        lockSpin(&s.lock);
        defer s.lock.unlock();
        const borrowed = s.cache.get(key, now_ns, cur_gen) orelse return null;
        return try self.alloc.dupe(u8, borrowed);
    }

    /// Release a copy returned by `get`.
    pub fn free(self: *Sharded, value: []u8) void {
        self.alloc.free(value);
    }

    // ── writes ──────────────────────────────────────────────────────────────

    /// Insert or replace `key` in its shard. Same contract as `Cache.put`
    /// (key and value are duped, `ttl_ns <= 0` = no time expiry, `gen == 0` =
    /// TTL-only, silent no-op on OOM) — except that the size ceiling is the
    /// *per-shard* byte cap, and eviction pressure is that shard's alone.
    pub fn put(self: *Sharded, key: []const u8, value: []const u8, now_ns: i64, ttl_ns: i64, gen: u64) void {
        const s = &self.shards[self.shardIndex(key)];
        lockSpin(&s.lock);
        defer s.lock.unlock();
        s.cache.put(key, value, now_ns, ttl_ns, gen);
    }

    /// `put` with `Options.default_ttl_ns` as the TTL.
    pub fn putDefault(self: *Sharded, key: []const u8, value: []const u8, now_ns: i64, gen: u64) void {
        const s = &self.shards[self.shardIndex(key)];
        lockSpin(&s.lock);
        defer s.lock.unlock();
        s.cache.putDefault(key, value, now_ns, gen);
    }

    /// Drop every entry, shard by shard. **Not atomic across shards** — see
    /// the module doc: what is guaranteed is that each entry present in a
    /// shard when that shard's lock was taken is gone, not that the cache was
    /// ever observably empty.
    pub fn clear(self: *Sharded) void {
        for (self.shards) |*s| {
            lockSpin(&s.lock);
            defer s.lock.unlock();
            s.cache.clear();
        }
    }

    // ── observability ───────────────────────────────────────────────────────

    /// Sum of every shard's counters — an **approximate**, per-shard-consistent
    /// snapshot. See the module doc for exactly what that does and does not
    /// bound. Takes one lock at a time, never two.
    pub fn stats(self: *Sharded) Stats {
        var total: Stats = .{};
        for (self.shards) |*s| {
            lockSpin(&s.lock);
            const st = s.cache.stats;
            s.lock.unlock();
            total.hits += st.hits;
            total.misses += st.misses;
            total.evictions += st.evictions;
            total.expired += st.expired;
            total.admissions += st.admissions;
            total.rejections += st.rejections;
            total.entries += st.entries;
            total.bytes += st.bytes;
        }
        return total;
    }

    /// One shard's counters, read under that shard's lock — exact for that
    /// shard at the moment of the read. Use it to check key-distribution skew
    /// (`shardCount` + `shardIndex` are public for the same reason).
    pub fn shardStats(self: *Sharded, index: usize) Stats {
        const s = &self.shards[index];
        lockSpin(&s.lock);
        defer s.lock.unlock();
        return s.cache.stats;
    }

    // ── write-behind seam ───────────────────────────────────────────────────

    /// True if `key` is present with its dirty bit set (`Cache.isDirty`, under
    /// the shard lock). Advisory only under concurrency: another thread may
    /// dirty or remove the entry the moment this returns.
    pub fn isDirty(self: *Sharded, key: []const u8) bool {
        const s = &self.shards[self.shardIndex(key)];
        lockSpin(&s.lock);
        defer s.lock.unlock();
        return s.cache.isDirty(key);
    }

    /// Clear `key`'s dirty bit. Returns false if the key is absent.
    ///
    /// **Racy by nature under concurrency** — if another thread `put` a newer
    /// value between the flush and this call, this clears the dirty bit of a
    /// write that was never persisted. Prefer `markCleanIf` unless the caller
    /// can prove no concurrent write to that key.
    pub fn markClean(self: *Sharded, key: []const u8) bool {
        const s = &self.shards[self.shardIndex(key)];
        lockSpin(&s.lock);
        defer s.lock.unlock();
        return s.cache.markClean(key);
    }

    /// Compare-and-clear: clear `key`'s dirty bit **only if** its stored value
    /// still equals `flushed` — i.e. only if the bytes that were persisted are
    /// still the bytes in the cache. Returns true when the bit was cleared
    /// (or was already clear on a matching value), false when the key is
    /// absent or has since been overwritten, in which case the entry stays
    /// dirty and the next sweep or `on_evict` picks the newer value up.
    ///
    /// This is the race-free `markClean` for an asynchronous flusher; the cost
    /// is one value comparison under the shard lock.
    pub fn markCleanIf(self: *Sharded, key: []const u8, flushed: []const u8) bool {
        const s = &self.shards[self.shardIndex(key)];
        lockSpin(&s.lock);
        defer s.lock.unlock();
        // Reaches into the shard's map rather than going through `Cache.get`
        // on purpose: `get` would count a hit, refresh recency, feed the
        // frequency sketch and lazily drop a stale entry. A flush ack must be
        // side-effect-free, exactly like `Cache.isDirty`/`markClean` are.
        const e = s.cache.map.getPtr(key) orelse return false;
        if (!std.mem.eql(u8, e.value, flushed)) return false;
        e.dirty = false;
        return true;
    }

    /// Visit every dirty entry, shard by shard, via `cb(ctx, key, value)`.
    ///
    /// `cb` runs **with a shard lock held**, so — unlike `Cache.drainDirty`,
    /// which permits `markClean` from the callback — it must not call *any*
    /// method on this `Sharded` (a hard deadlock, not a detected error). The
    /// `key`/`value` slices are valid only for the duration of the call. Copy
    /// what you need, then ack with `markCleanIf` after the sweep returns.
    ///
    /// Not atomic across shards — see the module doc.
    pub fn drainDirty(self: *Sharded, cb: DirtyFn, ctx: ?*anyopaque) void {
        for (self.shards) |*s| {
            lockSpin(&s.lock);
            defer s.lock.unlock();
            s.cache.drainDirty(cb, ctx);
        }
    }
};

// ── tests ───────────────────────────────────────────────────────────────────
// Deterministic wherever it can be (injected `now_ns`/generation, fixed key
// sets, a fixed LCG in the stress test). There is no external anchor for this
// design, so the invariants are asserted directly: byte accounting, region
// bookkeeping, key→shard mapping, and value shape.

const testing = std.testing;

fn testSharded(max_bytes: usize, max_entries: usize, shards: usize) !Sharded {
    return Sharded.init(testing.allocator, .{
        .max_bytes = max_bytes,
        .max_entries = max_entries,
        .shards = shards,
    });
}

/// Re-derive, from each shard's raw map, everything the cache tracks
/// incrementally, and assert the bookkeeping agrees. A dropped lock in any
/// single mutating path shows up here as drifted `bytes` or region counters.
/// Also asserts (3) of the safety argument: every stored key really is in the
/// shard its hash names.
fn expectInvariants(sc: *Sharded) !void {
    for (sc.shards, 0..) |*s, i| {
        var bytes: usize = 0;
        var window: usize = 0;
        var probation: usize = 0;
        var protected: usize = 0;
        var it = s.cache.map.iterator();
        while (it.next()) |kv| {
            bytes += kv.value_ptr.value.len;
            switch (kv.value_ptr.region) {
                .window => window += 1,
                .probation => probation += 1,
                .protected => protected += 1,
            }
            // No entry may live in a shard other than the one its key hashes
            // to — otherwise `get` would look in the wrong shard's lock.
            try testing.expectEqual(i, sc.shardIndex(kv.key_ptr.*));
        }
        try testing.expectEqual(bytes, s.cache.bytes);
        try testing.expectEqual(bytes, s.cache.stats.bytes);
        try testing.expectEqual(s.cache.map.count(), s.cache.stats.entries);
        try testing.expectEqual(s.cache.map.count(), window + probation + protected);
        try testing.expectEqual(window, s.cache.window_count);
        try testing.expectEqual(probation, s.cache.probation_count);
        try testing.expectEqual(protected, s.cache.protected_count);
        // Cap conformance. Sound for these tests, but note it is NOT a
        // universal `Cache` invariant: `put`'s replace path adjusts `bytes`
        // without calling `maintain`, so overwriting an entry with a larger
        // value can sit above `max_bytes` until the next insert. No test here
        // replaces a value with a larger one.
        try testing.expect(s.cache.map.count() <= sc.per_shard_max_entries);
        try testing.expect(s.cache.bytes <= sc.per_shard_max_bytes);
    }
}

test "round trip: put then getBuf copies the value into the caller's buffer" {
    var sc = try testSharded(1 << 20, 256, 8);
    defer sc.deinit();
    sc.put("k", "value", 0, 0, 0);
    var buf: [16]u8 = undefined;
    switch (sc.getBuf("k", 1, 0, &buf)) {
        .ok => |v| {
            try testing.expectEqualStrings("value", v);
            // The result aliases the CALLER's buffer, never cache storage.
            try testing.expectEqual(@intFromPtr(&buf), @intFromPtr(v.ptr));
        },
        else => return error.TestUnexpectedResult,
    }
    try testing.expect(sc.getBuf("absent", 1, 0, &buf) == .miss);
}

test "getBuf reports a too-small buffer as its own case, with the needed length" {
    var sc = try testSharded(1 << 20, 256, 8);
    defer sc.deinit();
    sc.put("k", "0123456789", 0, 0, 0);
    var small: [4]u8 = undefined;
    // A miss and a doesn't-fit must not be confusable: a caller that treats
    // "not found" as "fetch from origin" would silently re-fetch forever.
    switch (sc.getBuf("k", 1, 0, &small)) {
        .buffer_too_small => |need| try testing.expectEqual(@as(usize, 10), need),
        else => return error.TestUnexpectedResult,
    }
    var big: [10]u8 = undefined;
    switch (sc.getBuf("k", 1, 0, &big)) {
        .ok => |v| try testing.expectEqualStrings("0123456789", v),
        else => return error.TestUnexpectedResult,
    }
}

test "get returns an owned copy that outlives eviction of the entry it came from" {
    // This is the whole point of not mirroring `Cache.get`: with a borrowed
    // slice the assertion below would read freed memory.
    var sc = try testSharded(1 << 20, 64, 8);
    defer sc.deinit();
    sc.put("k", "durable", 0, 0, 0);
    const owned = (try sc.get("k", 1, 0)).?;
    defer sc.free(owned);
    sc.clear(); // frees every entry's storage, including the one just read
    try testing.expectEqualStrings("durable", owned);
    try testing.expect((try sc.get("k", 2, 0)) == null); // gone from the cache
}

test "get on a miss returns null and allocates nothing" {
    var sc = try testSharded(1 << 20, 64, 8);
    defer sc.deinit();
    // testing.allocator would flag a leak if the miss path allocated.
    try testing.expect((try sc.get("nope", 0, 0)) == null);
}

test "keys land in every shard, not all in one" {
    // Guards the shard hash itself. A degenerate `shardIndex` (e.g. always 0)
    // stays perfectly CONSISTENT between put and get, so every round-trip
    // test still passes — only distribution and achievable capacity see it.
    var sc = try testSharded(1 << 20, 4096, 8);
    defer sc.deinit();
    try testing.expectEqual(@as(usize, 8), sc.shardCount());
    var kbuf: [16]u8 = undefined;
    var i: usize = 0;
    while (i < 512) : (i += 1) {
        const key = std.fmt.bufPrint(&kbuf, "key{d}", .{i}) catch unreachable;
        sc.put(key, "v", 0, 0, 0);
    }
    var idx: usize = 0;
    while (idx < sc.shardCount()) : (idx += 1) {
        // 512 keys over 8 shards: an empty shard means the hash is not
        // spreading (P(empty) < 1e-25 for a sane hash).
        try testing.expect(sc.shardStats(idx).entries > 0);
    }
    try testing.expectEqual(@as(usize, 512), sc.stats().entries);
    try expectInvariants(&sc);
}

test "aggregate occupancy reaches the requested cap when the keys spread evenly" {
    // The other half of the distribution guard: with all keys funnelled into
    // one shard, only 1/8 of the nominal capacity is reachable.
    var sc = try testSharded(1 << 20, 512, 8);
    defer sc.deinit();
    try testing.expectEqual(@as(usize, 64), sc.per_shard_max_entries);
    var kbuf: [16]u8 = undefined;
    var i: usize = 0;
    while (i < 2000) : (i += 1) {
        const key = std.fmt.bufPrint(&kbuf, "k{d}", .{i}) catch unreachable;
        sc.put(key, "v", 0, 0, 0);
    }
    const st = sc.stats();
    try testing.expect(st.entries <= 512); // never above the aggregate cap
    try testing.expect(st.entries >= 448); // ...and within one shard's worth of it
    try expectInvariants(&sc);
}

test "shard count rounds up to a power of two and is clamped so no shard is starved" {
    var a = try testSharded(1 << 20, 4096, 5);
    defer a.deinit();
    try testing.expectEqual(@as(usize, 8), a.shardCount()); // 5 → 8

    // 32 shards over a 4-entry cache would give every shard a zero cap.
    var b = try testSharded(1 << 20, 4, 32);
    defer b.deinit();
    try testing.expectEqual(@as(usize, 4), b.shardCount());
    try testing.expectEqual(@as(usize, 1), b.per_shard_max_entries);
    b.put("x", "y", 0, 0, 0);
    var buf: [8]u8 = undefined;
    try testing.expect(b.getBuf("x", 1, 0, &buf) == .ok);

    // Byte budget can clamp too: 3 bytes cannot feed 8 shards.
    var c = try testSharded(3, 4096, 8);
    defer c.deinit();
    try testing.expectEqual(@as(usize, 2), c.shardCount());
    try testing.expectEqual(@as(usize, 1), c.per_shard_max_bytes);

    // Floor division: the effective aggregate cap never exceeds the request.
    var d = try testSharded(1 << 20, 100, 8);
    defer d.deinit();
    try testing.expectEqual(@as(usize, 12), d.per_shard_max_entries); // 100/8
    try testing.expect(d.per_shard_max_entries * d.shardCount() <= 100);
}

test "clear empties every shard" {
    var sc = try testSharded(1 << 20, 4096, 8);
    defer sc.deinit();
    var kbuf: [16]u8 = undefined;
    var i: usize = 0;
    while (i < 512) : (i += 1) {
        const key = std.fmt.bufPrint(&kbuf, "key{d}", .{i}) catch unreachable;
        sc.put(key, "value", 0, 0, 0);
    }
    sc.clear();
    // Aggregate AND per-shard: an aggregate check alone would be satisfied by
    // a `clear` that skips a shard if `stats` skipped the same one.
    try testing.expectEqual(@as(usize, 0), sc.stats().entries);
    try testing.expectEqual(@as(usize, 0), sc.stats().bytes);
    var idx: usize = 0;
    while (idx < sc.shardCount()) : (idx += 1) {
        try testing.expectEqual(@as(usize, 0), sc.shardStats(idx).entries);
        try testing.expectEqual(@as(usize, 0), sc.shardStats(idx).bytes);
    }
    try expectInvariants(&sc);
}

test "stats sums every shard: aggregate equals the sum of the per-shard readings" {
    var sc = try testSharded(1 << 20, 4096, 8);
    defer sc.deinit();
    var kbuf: [16]u8 = undefined;
    var i: usize = 0;
    while (i < 300) : (i += 1) {
        const key = std.fmt.bufPrint(&kbuf, "key{d}", .{i}) catch unreachable;
        sc.put(key, "vv", 0, 0, 0);
        var buf: [8]u8 = undefined;
        _ = sc.getBuf(key, 1, 0, &buf); // 300 hits
    }
    _ = sc.getBuf("absent", 1, 0, &kbuf); // 1 miss

    var sum: Stats = .{};
    var idx: usize = 0;
    while (idx < sc.shardCount()) : (idx += 1) {
        const st = sc.shardStats(idx);
        sum.hits += st.hits;
        sum.misses += st.misses;
        sum.entries += st.entries;
        sum.bytes += st.bytes;
    }
    const agg = sc.stats();
    try testing.expectEqual(sum.hits, agg.hits);
    try testing.expectEqual(sum.misses, agg.misses);
    try testing.expectEqual(sum.entries, agg.entries);
    try testing.expectEqual(sum.bytes, agg.bytes);
    // Absolute values too, so a `stats` that skips a shard cannot agree with a
    // per-shard sum that skips the same shard.
    try testing.expectEqual(@as(u64, 300), agg.hits);
    try testing.expectEqual(@as(u64, 1), agg.misses);
    try testing.expectEqual(@as(usize, 300), agg.entries);
    try testing.expectEqual(@as(usize, 600), agg.bytes);
}

test "TTL and generation axes work per shard, unchanged" {
    var sc = try Sharded.init(testing.allocator, .{
        .max_bytes = 1 << 20,
        .max_entries = 256,
        .shards = 4,
        .default_ttl_ns = 100,
    });
    defer sc.deinit();
    var buf: [16]u8 = undefined;

    sc.put("ttl", "v", 1000, 100, 0);
    try testing.expect(sc.getBuf("ttl", 1050, 0, &buf) == .ok);
    try testing.expect(sc.getBuf("ttl", 1201, 0, &buf) == .miss); // expired, dropped

    sc.put("gen", "rows", 0, 0, 7);
    try testing.expect(sc.getBuf("gen", 1, 7, &buf) == .ok);
    try testing.expect(sc.getBuf("gen", 1, 8, &buf) == .miss); // generation bumped

    sc.putDefault("def", "v", 2000, 0);
    try testing.expect(sc.getBuf("def", 2050, 0, &buf) == .ok);
    try testing.expect(sc.getBuf("def", 2201, 0, &buf) == .miss); // default TTL applied
    try expectInvariants(&sc);
}

test "an item larger than the PER-SHARD byte cap is not stored" {
    // Documented tightening vs `Cache`: the ceiling is max_bytes / shards.
    var sc = try testSharded(1024, 256, 8); // 128 bytes per shard
    defer sc.deinit();
    const big = [_]u8{'x'} ** 200;
    sc.put("k", &big, 0, 0, 0);
    var buf: [256]u8 = undefined;
    try testing.expect(sc.getBuf("k", 1, 0, &buf) == .miss);
    const ok = [_]u8{'x'} ** 100;
    sc.put("k2", &ok, 0, 0, 0);
    try testing.expect(sc.getBuf("k2", 1, 0, &buf) == .ok);
}

// ── write-behind seam ───────────────────────────────────────────────────────

test "dirty bit and markClean work through the shard, across many keys" {
    var sc = try testSharded(1 << 20, 4096, 8);
    defer sc.deinit();
    var kbuf: [16]u8 = undefined;
    var i: usize = 0;
    while (i < 64) : (i += 1) {
        const key = std.fmt.bufPrint(&kbuf, "key{d}", .{i}) catch unreachable;
        sc.put(key, "v", 0, 0, 0);
        try testing.expect(sc.isDirty(key));
        try testing.expect(sc.markClean(key));
        try testing.expect(!sc.isDirty(key));
    }
    try testing.expect(!sc.markClean("absent"));
    try testing.expect(!sc.isDirty("absent"));
}

test "markCleanIf refuses to ack a value that has since been overwritten" {
    var sc = try testSharded(1 << 20, 256, 8);
    defer sc.deinit();
    sc.put("k", "v1", 0, 0, 0);
    // The flusher persisted "v1"; meanwhile a writer stored "v2".
    sc.put("k", "v2", 1, 0, 0);
    try testing.expect(!sc.markCleanIf("k", "v1")); // stale ack refused
    try testing.expect(sc.isDirty("k")); // ...and the newer write stays dirty
    try testing.expect(sc.markCleanIf("k", "v2")); // acking the current value works
    try testing.expect(!sc.isDirty("k"));
    try testing.expect(!sc.markCleanIf("gone", "v")); // absent key
    // Contrast: the racy variant would have cleared the bit on the stale ack,
    // losing "v2". This is the whole reason markCleanIf exists.
    sc.put("k", "v3", 2, 0, 0);
    try testing.expect(sc.markClean("k"));
    try testing.expect(!sc.isDirty("k"));
}

const DirtyCollector = struct {
    keys: [256][24]u8 = undefined,
    lens: [256]usize = undefined,
    len: usize = 0,

    fn hook(ctx: ?*anyopaque, key: []const u8, value: []const u8) void {
        _ = value;
        const self: *DirtyCollector = @ptrCast(@alignCast(ctx.?));
        // Copies out: the slices are only valid while the shard lock is held.
        @memcpy(self.keys[self.len][0..key.len], key);
        self.lens[self.len] = key.len;
        self.len += 1;
    }

    fn has(self: *const DirtyCollector, want: []const u8) bool {
        for (0..self.len) |i| {
            if (std.mem.eql(u8, self.keys[i][0..self.lens[i]], want)) return true;
        }
        return false;
    }
};

test "drainDirty sweeps dirty entries in every shard and skips clean ones" {
    var sc = try testSharded(1 << 20, 4096, 8);
    defer sc.deinit();
    var kbuf: [16]u8 = undefined;
    var i: usize = 0;
    while (i < 128) : (i += 1) {
        const key = std.fmt.bufPrint(&kbuf, "key{d}", .{i}) catch unreachable;
        sc.put(key, "v", 0, 0, 0);
        if (i % 2 == 0) try testing.expect(sc.markClean(key)); // half are clean
    }
    var col: DirtyCollector = .{};
    sc.drainDirty(DirtyCollector.hook, &col);
    try testing.expectEqual(@as(usize, 64), col.len);
    i = 0;
    while (i < 128) : (i += 1) {
        const key = std.fmt.bufPrint(&kbuf, "key{d}", .{i}) catch unreachable;
        try testing.expectEqual(i % 2 == 1, col.has(key));
    }
}

// ── on_evict from the sharded type ──────────────────────────────────────────

const ShardedEvictSink = struct {
    count: std.atomic.Value(u32) = .init(0),
    dirty_count: std.atomic.Value(u32) = .init(0),
    evicted: std.atomic.Value(u32) = .init(0),
    replaced: std.atomic.Value(u32) = .init(0),
    cleared: std.atomic.Value(u32) = .init(0),
    /// A value whose shape did not match its key — a coherence failure.
    bad: std.atomic.Value(u32) = .init(0),
    /// Set when the hook should verify stress-test value shapes.
    check_shape: bool = false,

    fn hook(ctx: ?*anyopaque, key: []const u8, value: []const u8, dirty: bool, reason: root.EvictReason) void {
        const self: *ShardedEvictSink = @ptrCast(@alignCast(ctx.?));
        _ = self.count.fetchAdd(1, .monotonic);
        if (dirty) _ = self.dirty_count.fetchAdd(1, .monotonic);
        switch (reason) {
            .evicted => _ = self.evicted.fetchAdd(1, .monotonic),
            .replaced => _ = self.replaced.fetchAdd(1, .monotonic),
            .cleared => _ = self.cleared.fetchAdd(1, .monotonic),
        }
        if (self.check_shape) {
            const id = std.fmt.parseInt(u16, key[stress_key_prefix.len..], 10) catch {
                _ = self.bad.fetchAdd(1, .monotonic);
                return;
            };
            if (!checkStressValue(value, id)) _ = self.bad.fetchAdd(1, .monotonic);
        }
    }
};

test "on_evict fires per shard for eviction, replacement and clear" {
    var sink: ShardedEvictSink = .{};
    var sc = try Sharded.init(testing.allocator, .{
        .max_bytes = 1 << 20,
        .max_entries = 16, // 2 entries per shard
        .shards = 8,
        .on_evict = ShardedEvictSink.hook,
        .on_evict_ctx = &sink,
    });
    defer sc.deinit();

    sc.put("k", "aaaa", 0, 0, 0);
    sc.put("k", "bb", 1, 0, 0); // replacement
    try testing.expectEqual(@as(u32, 1), sink.replaced.load(.monotonic));

    var kbuf: [16]u8 = undefined;
    var i: usize = 0;
    while (i < 400) : (i += 1) { // force capacity eviction in every shard
        const key = std.fmt.bufPrint(&kbuf, "key{d}", .{i}) catch unreachable;
        sc.put(key, "v", 0, 0, 0);
    }
    try testing.expect(sink.evicted.load(.monotonic) > 0);

    const before_clear = sink.cleared.load(.monotonic);
    const live = sc.stats().entries;
    sc.clear();
    // Exactly one `.cleared` per surviving entry, across all shards.
    try testing.expectEqual(@as(u32, @intCast(live)), sink.cleared.load(.monotonic) - before_clear);
    try testing.expect(sink.dirty_count.load(.monotonic) > 0); // nothing was ever acked
}

// ── concurrent stress ───────────────────────────────────────────────────────
// The invariant is NOT "it did not crash". Every stored value is a
// self-describing 64-byte record (key id + round + a pattern derived from
// both), so:
//   * a value copied out while another thread frees or overwrites it fails the
//     pattern check (torn or foreign bytes),
//   * a value delivered under the wrong key fails the id check,
//   * `on_evict` re-checks the shape from inside the critical section,
//   * and after the join, `expectInvariants` re-derives byte totals and region
//     counters from the raw maps, so a single unsynchronized mutation shows up
//     as drifted accounting even if no read happened to catch it.

const stress_key_prefix = "key";
const stress_val_len = 64;
const stress_key_space: u16 = 400;

fn encodeStressValue(out: *[stress_val_len]u8, id: u16, round: u8) void {
    out[0] = @truncate(id);
    out[1] = @truncate(id >> 8);
    out[2] = round;
    out[3] = 0xA5;
    var i: usize = 4;
    while (i < stress_val_len) : (i += 1) {
        out[i] = @truncate(id *% 31 +% @as(u16, round) *% 7 +% @as(u16, @intCast(i)) *% 13);
    }
}

fn checkStressValue(v: []const u8, id: u16) bool {
    if (v.len != stress_val_len) return false;
    const stored_id = @as(u16, v[0]) | (@as(u16, v[1]) << 8);
    if (stored_id != id) return false;
    if (v[3] != 0xA5) return false;
    var expect: [stress_val_len]u8 = undefined;
    encodeStressValue(&expect, stored_id, v[2]);
    return std.mem.eql(u8, &expect, v);
}

fn stressKey(buf: *[16]u8, id: u16) []const u8 {
    return std.fmt.bufPrint(buf, stress_key_prefix ++ "{d}", .{id}) catch unreachable;
}

const StressWorker = struct {
    sc: *Sharded,
    seed: u64,
    ops: usize,
    reads: u64 = 0,
    misses: u64 = 0,
    bad: u64 = 0,

    fn run(w: *StressWorker) void {
        var rng = w.seed;
        var vbuf: [stress_val_len]u8 = undefined;
        var rbuf: [stress_val_len]u8 = undefined;
        var kbuf: [16]u8 = undefined;
        var op: usize = 0;
        while (op < w.ops) : (op += 1) {
            rng = rng *% 6364136223846793005 +% 1442695040888963407;
            const id: u16 = @intCast((rng >> 33) % stress_key_space);
            const key = stressKey(&kbuf, id);
            switch ((rng >> 17) & 15) {
                0...6 => { // write
                    encodeStressValue(&vbuf, id, @truncate(rng >> 5));
                    w.sc.put(key, &vbuf, 0, 0, 0);
                },
                7...11 => switch (w.sc.getBuf(key, 0, 0, &rbuf)) { // zero-alloc read
                    .miss => w.misses += 1,
                    .buffer_too_small => w.bad += 1, // every value is exactly 64B
                    .ok => |v| {
                        if (checkStressValue(v, id)) w.reads += 1 else w.bad += 1;
                    },
                },
                12, 13 => { // owned-copy read; the copy must survive the lock release
                    if (w.sc.get(key, 0, 0) catch null) |owned| {
                        defer w.sc.free(owned);
                        std.atomic.spinLoopHint(); // give other threads a chance to evict it
                        if (checkStressValue(owned, id)) w.reads += 1 else w.bad += 1;
                    } else w.misses += 1;
                },
                14 => { // write-behind seam under contention
                    _ = w.sc.isDirty(key);
                    encodeStressValue(&vbuf, id, @truncate(rng >> 5));
                    _ = w.sc.markCleanIf(key, &vbuf);
                },
                else => { // aggregate operations, interleaved with everything else
                    const st = w.sc.stats();
                    if (st.entries > stress_key_space) w.bad += 1;
                    if (op % 4096 == 0) w.sc.clear();
                },
            }
        }
    }
};

test "concurrent stress: mixed get/put/evict/clear keeps every value and every counter coherent" {
    const cpus = std.Thread.getCpuCount() catch 2;
    const thread_count = @max(@as(usize, 2), @min(@as(usize, 6), cpus));
    const ops_per_thread: usize = 20_000;

    var sink: ShardedEvictSink = .{ .check_shape = true };
    var sc = try Sharded.init(testing.allocator, .{
        // 8 shards × 16 entries: far below the 400-key space, so eviction and
        // replacement run constantly and every read races a possible free.
        .max_bytes = 16 * 1024,
        .max_entries = 128,
        .shards = 8,
        .on_evict = ShardedEvictSink.hook,
        .on_evict_ctx = &sink,
    });
    defer sc.deinit();

    const workers = try testing.allocator.alloc(StressWorker, thread_count);
    defer testing.allocator.free(workers);
    const threads = try testing.allocator.alloc(std.Thread, thread_count);
    defer testing.allocator.free(threads);

    for (workers, 0..) |*w, i| {
        w.* = .{ .sc = &sc, .seed = 0x243F6A88_85A308D3 +% @as(u64, i) *% 0x9E3779B97F4A7C15, .ops = ops_per_thread };
    }
    for (threads, 0..) |*t, i| t.* = try std.Thread.spawn(.{}, StressWorker.run, .{&workers[i]});
    for (threads) |t| t.join();

    var reads: u64 = 0;
    var misses: u64 = 0;
    var bad: u64 = 0;
    for (workers) |*w| {
        reads += w.reads;
        misses += w.misses;
        bad += w.bad;
    }
    // No lost, torn, mis-keyed or foreign value — on any read path...
    try testing.expectEqual(@as(u64, 0), bad);
    // ...nor inside the eviction callback, which sees values from every thread.
    try testing.expectEqual(@as(u32, 0), sink.bad.load(.monotonic));
    // The run has to have actually exercised the paths it claims to.
    try testing.expect(reads > 1000);
    try testing.expect(misses > 0);
    try testing.expect(sink.evicted.load(.monotonic) > 0);
    try testing.expect(sink.replaced.load(.monotonic) > 0);
    try testing.expect(sink.cleared.load(.monotonic) > 0);
    // Quiescent again: every counter must re-derive exactly from the raw maps.
    try expectInvariants(&sc);
    try testing.expect(sc.stats().entries <= 128);
}

test "a value is never freed or overwritten while it is being copied out" {
    // The mixed stress test above does NOT catch a `getBuf`/`get` that
    // releases the shard lock before copying: the window is two instructions
    // wide, and 120k reads never landed in it (measured — the mutation
    // survived 5/5 runs). Probability is the wrong tool here, so this test
    // removes it: the values are big enough that the copy itself takes tens of
    // microseconds, and a single shard forces the writer onto the same lock.
    //
    // Holding the lock across the copy makes "the entry was freed mid-copy"
    // *impossible*, so the assertion below cannot fail by luck. Release it
    // early and the reader copies memory that has since been unmapped or
    // reused — a segfault or a torn value.
    //
    // What makes this a real prosecutor rather than a hopeful one is the
    // **clearer** thread. A replacing `put` duplicates the incoming value
    // *before* freeing the outgoing one, so it frees ~a copy-time after taking
    // the lock and the reader usually finishes first (measured: the mutation
    // survived every run when `put` was the only source of frees). `clear`
    // frees the instant it holds the lock, which is precisely when an
    // unsynchronized reader is mid-copy.
    const big_len = 128 * 1024;

    const Ctx = struct {
        sc: *Sharded,
        stop: std.atomic.Value(bool) = .init(false),
        verified: std.atomic.Value(u32) = .init(0),
        torn: std.atomic.Value(u32) = .init(0),

        /// Every byte of a stored value equals its round stamp, which is never
        /// 0 — so any mixture of two writes, and any zeroed page, is visible.
        fn verify(c: *@This(), v: []const u8) void {
            if (v.len != big_len or v[0] == 0) {
                _ = c.torn.fetchAdd(1, .monotonic);
                return;
            }
            for (v) |b| {
                if (b != v[0]) {
                    _ = c.torn.fetchAdd(1, .monotonic);
                    return;
                }
            }
            _ = c.verified.fetchAdd(1, .monotonic);
        }

        fn writer(c: *@This()) void {
            const buf = testing.allocator.alloc(u8, big_len) catch return;
            defer testing.allocator.free(buf);
            var round: u8 = 1;
            var i: usize = 0;
            while (i < 2000) : (i += 1) {
                @memset(buf, round);
                round = if (round == 255) 1 else round + 1;
                c.sc.put("hot", buf, 0, 0, 0); // frees the previous value
            }
            c.stop.store(true, .release);
        }

        /// Frees whatever is stored the moment it owns the lock.
        fn clearer(c: *@This()) void {
            while (!c.stop.load(.acquire)) c.sc.clear();
        }

        /// `getBuf` only, in the tightest loop possible. Deliberately no
        /// `get`: the owned-copy path allocates under the lock, and mixing the
        /// two lets one reader hold the lock across a whole writer cycle.
        fn reader(c: *@This()) void {
            const buf = testing.allocator.alloc(u8, big_len) catch return;
            defer testing.allocator.free(buf);
            while (!c.stop.load(.acquire)) {
                switch (c.sc.getBuf("hot", 0, 0, buf)) {
                    .ok => |v| c.verify(v),
                    .buffer_too_small => _ = c.torn.fetchAdd(1, .monotonic),
                    .miss => {},
                }
            }
        }

        /// The `get` counterpart, kept on its own thread so its allocation
        /// never sits inside a `getBuf` reader's critical section.
        fn owningReader(c: *@This()) void {
            while (!c.stop.load(.acquire)) {
                if (c.sc.get("hot", 0, 0) catch null) |owned| {
                    defer c.sc.free(owned);
                    c.verify(owned);
                }
            }
        }
    };

    var sc = try Sharded.init(testing.allocator, .{
        .max_bytes = 4 * big_len,
        .max_entries = 4,
        .shards = 1, // one lock: reader and writer always contend
    });
    defer sc.deinit();
    var ctx: Ctx = .{ .sc = &sc };

    const r1 = try std.Thread.spawn(.{}, Ctx.reader, .{&ctx});
    const r2 = try std.Thread.spawn(.{}, Ctx.reader, .{&ctx});
    const r3 = try std.Thread.spawn(.{}, Ctx.owningReader, .{&ctx});
    const cl = try std.Thread.spawn(.{}, Ctx.clearer, .{&ctx});
    const w = try std.Thread.spawn(.{}, Ctx.writer, .{&ctx});
    w.join();
    r1.join();
    r2.join();
    r3.join();
    cl.join();

    try testing.expectEqual(@as(u32, 0), ctx.torn.load(.monotonic));
    // The run must actually have read values, not just raced with an empty
    // cache — otherwise "no torn value" would be vacuously true.
    try testing.expect(ctx.verified.load(.monotonic) > 100);
    try expectInvariants(&sc);
}

test "concurrent stress: parallel clear never leaves a shard behind or double-frees" {
    // A narrower race than the mixed test: writers hammer one small key set
    // while a dedicated thread clears. testing.allocator turns any double free
    // into a hard failure; `expectInvariants` catches a half-cleared shard.
    const Ctx = struct {
        sc: *Sharded,
        stop: std.atomic.Value(bool) = .init(false),

        fn writer(c: *@This()) void {
            var vbuf: [stress_val_len]u8 = undefined;
            var kbuf: [16]u8 = undefined;
            var rng: u64 = 0x123456789ABCDEF;
            var i: usize = 0;
            while (i < 30_000) : (i += 1) {
                rng = rng *% 6364136223846793005 +% 1442695040888963407;
                const id: u16 = @intCast((rng >> 33) % 64);
                encodeStressValue(&vbuf, id, @truncate(rng >> 5));
                c.sc.put(stressKey(&kbuf, id), &vbuf, 0, 0, 0);
            }
        }

        fn clearer(c: *@This()) void {
            while (!c.stop.load(.acquire)) {
                c.sc.clear();
                std.atomic.spinLoopHint();
            }
        }
    };

    var sc = try testSharded(8 * 1024, 64, 8);
    defer sc.deinit();
    var ctx: Ctx = .{ .sc = &sc };

    const w1 = try std.Thread.spawn(.{}, Ctx.writer, .{&ctx});
    const w2 = try std.Thread.spawn(.{}, Ctx.writer, .{&ctx});
    const cl = try std.Thread.spawn(.{}, Ctx.clearer, .{&ctx});
    w1.join();
    w2.join();
    ctx.stop.store(true, .release);
    cl.join();

    sc.clear();
    try testing.expectEqual(@as(usize, 0), sc.stats().entries);
    try expectInvariants(&sc);
}
