// SPDX-License-Identifier: MIT

//! ramcache — bounded in-memory cache with two independent freshness axes.
//!
//! Serving a repeated lookup (same DB query, same fetched URL, same computed
//! blob) from RAM in ~ns instead of re-executing it in ~ms is the whole point.
//! Each entry carries two *independent* freshness axes:
//!
//!   * **TTL** (`ttl_ns`): wall-time expiry. `ttl_ns <= 0` = never expire by
//!     time. Typical for external/remote data with a tunable staleness budget.
//!   * **generation** (`gen`): logical invalidation. `gen == 0` = not tied to
//!     a generation (TTL-only). A non-zero `gen` entry is stale the moment the
//!     caller's current generation differs — bump one counter to invalidate
//!     every derived entry at once. Stale entries are dropped **lazily on the
//!     next `get`** — there is no sweep.
//!
//! Design notes:
//!   * Pure `std`, dependency-free. The caller supplies the clock (`now_ns`)
//!     and the generation counter on every call, so this module has NO
//!     time/global dependency and every test is deterministic.
//!   * Bounded by both entry count and total value bytes; eviction prefers an
//!     already-expired entry, else the least-recently-used one (approx LRU via
//!     a single linear scan — fine for the modest entry counts a hot cache of
//!     query/fetch results holds).
//!   * **Ownership:** keys and values are duped into the cache's own
//!     allocator on `put`; freed on evict, replace, and clear. A slice
//!     returned by `get` borrows the cache's storage — it is valid only until
//!     that key is next replaced, evicted, or cleared. Copy it if you need it
//!     longer. `bytes` tracks value payloads only (the cap the user tunes).
//!   * **Concurrency = single owner.** The cache is NOT internally
//!     synchronized — no lock, by design (`meta.concurrency = .single_owner`).
//!     One thread/event loop owns the instance; a caller who needs to share it
//!     across threads must wrap it in their own lock.
//!   * `put` silently no-ops on OOM — a cache miss is never fatal.

const std = @import("std");

pub const meta = .{
    .status = .extract, // extracted from poc-wf-analytic src/cache.zig (same authors)
    .platform = .any,
    .role = .util,
    .concurrency = .single_owner, // one thread/loop owns it, lock-free by design
    .model_after = "groupcache / ristretto; generation-tie novel",
    .deps = .{}, // std only
};

/// Cumulative counters + current occupancy. `hits`/`misses`/`evictions`/
/// `expired` are lifetime totals (survive `clear`); `entries`/`bytes` mirror
/// the current contents.
pub const Stats = struct {
    hits: u64 = 0,
    misses: u64 = 0,
    evictions: u64 = 0,
    expired: u64 = 0,
    entries: usize = 0,
    bytes: usize = 0,
};

/// Tunables, fixed at `init`.
pub const Options = struct {
    /// Cap on the sum of stored value bytes. An item larger than this is
    /// never stored at all.
    max_bytes: usize,
    /// Cap on the number of entries.
    max_entries: usize,
    /// TTL applied by `putDefault`. `<= 0` = never expire by time.
    default_ttl_ns: i64 = 0,
};

pub const Cache = struct {
    const Entry = struct {
        value: []u8,
        inserted_ns: i64,
        ttl_ns: i64, // <= 0 → never expire by time
        gen: u64, // 0 → not generation-tied (TTL only)
        last_hit_ns: i64,
        hits: u64,
    };

    alloc: std.mem.Allocator,
    map: std.StringHashMapUnmanaged(Entry) = .empty,
    bytes: usize = 0,
    options: Options,
    stats: Stats = .{},

    pub fn init(alloc: std.mem.Allocator, options: Options) Cache {
        return .{ .alloc = alloc, .options = options };
    }

    pub fn deinit(self: *Cache) void {
        self.clear();
        self.map.deinit(self.alloc);
    }

    /// Return the cached value for `key` if it is still fresh (TTL not expired
    /// AND — for generation-tied entries — `entry.gen == cur_gen`). A stale
    /// entry is dropped in passing so its memory is reclaimed (lazy drop — the
    /// only reclamation besides eviction; there is no sweep). `null` = miss
    /// (caller fetches). Pass `cur_gen = 0` for TTL-only lookups.
    /// The returned slice borrows the cache's storage: valid until this key is
    /// replaced, evicted, or the cache is cleared.
    pub fn get(self: *Cache, key: []const u8, now_ns: i64, cur_gen: u64) ?[]const u8 {
        const e = self.map.getPtr(key) orelse {
            self.stats.misses += 1;
            return null;
        };
        const ttl_expired = e.ttl_ns > 0 and (now_ns - e.inserted_ns) > e.ttl_ns;
        const gen_stale = e.gen != 0 and e.gen != cur_gen;
        if (ttl_expired or gen_stale) {
            self.stats.expired += 1;
            self.stats.misses += 1;
            self.dropKey(key);
            return null;
        }
        e.last_hit_ns = now_ns;
        e.hits += 1;
        self.stats.hits += 1;
        return e.value;
    }

    /// Insert or replace `key` (both key and value are duped into the cache's
    /// allocator). `ttl_ns <= 0` = no time expiry; `gen == 0` = TTL-only (not
    /// invalidated by a generation bump). Evicts (expired first, then LRU) to
    /// stay within the entry/byte caps. Silently no-ops on OOM (a cache miss
    /// is never fatal).
    pub fn put(self: *Cache, key: []const u8, value: []const u8, now_ns: i64, ttl_ns: i64, gen: u64) void {
        if (self.map.getPtr(key)) |e| { // replace value in place, keep the stored key
            const vdup = self.alloc.dupe(u8, value) catch return;
            self.bytes -= e.value.len;
            self.alloc.free(e.value);
            e.* = .{ .value = vdup, .inserted_ns = now_ns, .ttl_ns = ttl_ns, .gen = gen, .last_hit_ns = now_ns, .hits = e.hits };
            self.bytes += vdup.len;
            self.syncStats();
            return;
        }
        if (value.len > self.options.max_bytes) return; // never cache an item larger than the whole cache
        while (self.map.count() >= self.options.max_entries or self.bytes + value.len > self.options.max_bytes) {
            if (!self.evictOne(now_ns)) break;
        }
        const kdup = self.alloc.dupe(u8, key) catch return;
        const vdup = self.alloc.dupe(u8, value) catch {
            self.alloc.free(kdup);
            return;
        };
        self.map.put(self.alloc, kdup, .{
            .value = vdup,
            .inserted_ns = now_ns,
            .ttl_ns = ttl_ns,
            .gen = gen,
            .last_hit_ns = now_ns,
            .hits = 0,
        }) catch {
            self.alloc.free(kdup);
            self.alloc.free(vdup);
            return;
        };
        self.bytes += vdup.len;
        self.syncStats();
    }

    /// `put` with `Options.default_ttl_ns` as the TTL.
    pub fn putDefault(self: *Cache, key: []const u8, value: []const u8, now_ns: i64, gen: u64) void {
        self.put(key, value, now_ns, self.options.default_ttl_ns, gen);
    }

    /// Drop every entry (e.g. a manual cache flush). Keeps map capacity and
    /// the cumulative hit/miss/eviction counters.
    pub fn clear(self: *Cache) void {
        var it = self.map.iterator();
        while (it.next()) |kv| {
            self.alloc.free(kv.value_ptr.value);
            self.alloc.free(kv.key_ptr.*);
        }
        self.map.clearRetainingCapacity();
        self.bytes = 0;
        self.syncStats();
    }

    // ── internals ───────────────────────────────────────────────────────────
    fn syncStats(self: *Cache) void {
        self.stats.entries = self.map.count();
        self.stats.bytes = self.bytes;
    }

    fn dropKey(self: *Cache, key: []const u8) void {
        if (self.map.fetchRemove(key)) |kv| {
            self.bytes -= kv.value.value.len;
            self.alloc.free(kv.value.value);
            self.alloc.free(kv.key);
        }
        self.syncStats();
    }

    /// Evict one entry: an already-expired one if found, else the LRU. Returns
    /// false only when the map is empty (nothing left to give back).
    fn evictOne(self: *Cache, now_ns: i64) bool {
        if (self.map.count() == 0) return false;
        var lru_key: ?[]const u8 = null;
        var lru_ts: i64 = std.math.maxInt(i64);
        var it = self.map.iterator();
        while (it.next()) |kv| {
            const e = kv.value_ptr.*;
            if (e.ttl_ns > 0 and (now_ns - e.inserted_ns) > e.ttl_ns) {
                // an expired entry is the best victim — take it now
                const ek = kv.key_ptr.*;
                self.dropKey(ek);
                self.stats.evictions += 1;
                return true;
            }
            if (e.last_hit_ns < lru_ts) {
                lru_ts = e.last_hit_ns;
                lru_key = kv.key_ptr.*;
            }
        }
        const vk = lru_key orelse return false;
        self.dropKey(vk);
        self.stats.evictions += 1;
        return true;
    }
};

// ── tests (deterministic: injected now_ns + generation, no real clock) ──────
const testing = std.testing;

fn testCache(max_bytes: usize, max_entries: usize) Cache {
    return Cache.init(testing.allocator, .{ .max_bytes = max_bytes, .max_entries = max_entries });
}

test "hit then miss" {
    var c = testCache(1 << 20, 16);
    defer c.deinit();
    c.put("k", "v", 0, 0, 0);
    try testing.expectEqualStrings("v", c.get("k", 1, 0).?);
    try testing.expect(c.get("absent", 1, 0) == null);
    try testing.expectEqual(@as(u64, 1), c.stats.hits);
    try testing.expectEqual(@as(u64, 1), c.stats.misses);
}

test "ttl expiry" {
    var c = testCache(1 << 20, 16);
    defer c.deinit();
    c.put("k", "v", 1000, 100, 0); // ttl 100ns, inserted at t=1000
    try testing.expect(c.get("k", 1050, 0) != null); // 50ns old → fresh
    try testing.expect(c.get("k", 1201, 0) == null); // 201ns old → expired, dropped
    try testing.expectEqual(@as(usize, 0), c.stats.entries);
    try testing.expectEqual(@as(u64, 1), c.stats.expired);
}

test "generation invalidation is lazy (no sweep)" {
    var c = testCache(1 << 20, 16);
    defer c.deinit();
    c.put("q", "rows", 0, 0, 7); // gen 7, no TTL
    try testing.expect(c.get("q", 1, 7) != null); // same gen → fresh
    // Bump the caller's generation — nothing is swept; the entry still sits
    // in the map, holding its bytes, until the next get touches it.
    try testing.expectEqual(@as(usize, 1), c.stats.entries);
    try testing.expect(c.get("q", 1, 8) == null); // gen bumped → stale, dropped in passing
    try testing.expectEqual(@as(usize, 0), c.stats.entries); // now reclaimed
    try testing.expect(c.get("q", 1, 7) == null); // and it's gone for good
}

test "gen == 0 entries are immune to generation bumps" {
    var c = testCache(1 << 20, 16);
    defer c.deinit();
    c.put("ext", "payload", 0, 0, 0); // TTL-only entry (external source)
    try testing.expect(c.get("ext", 1, 5) != null); // any cur_gen → still fresh
    try testing.expect(c.get("ext", 2, 99) != null);
}

test "replace updates value and byte accounting" {
    var c = testCache(1 << 20, 16);
    defer c.deinit();
    c.put("k", "aaaa", 0, 0, 0);
    try testing.expectEqual(@as(usize, 4), c.bytes);
    c.put("k", "bb", 1, 0, 0);
    try testing.expectEqualStrings("bb", c.get("k", 2, 0).?);
    try testing.expectEqual(@as(usize, 2), c.bytes);
    try testing.expectEqual(@as(usize, 1), c.stats.entries);
}

test "entry-count eviction is LRU" {
    var c = testCache(1 << 20, 2);
    defer c.deinit();
    c.put("a", "1", 0, 0, 0);
    c.put("b", "2", 0, 0, 0);
    _ = c.get("a", 10, 0); // touch a → b is now LRU
    c.put("cc", "3", 20, 0, 0); // over cap → evict LRU (b)
    try testing.expect(c.get("a", 30, 0) != null);
    try testing.expect(c.get("cc", 30, 0) != null);
    try testing.expect(c.get("b", 30, 0) == null);
    try testing.expect(c.stats.evictions >= 1);
}

test "byte-cap eviction" {
    var c = testCache(8, 100); // 8-byte cap
    defer c.deinit();
    c.put("a", "aaaa", 0, 0, 0); // 4 bytes
    c.put("b", "bbbb", 1, 0, 0); // 8 bytes total
    c.put("cc", "cccc", 2, 0, 0); // would be 12 → evict to fit
    try testing.expect(c.bytes <= 8);
}

test "eviction takes an expired entry before the LRU one" {
    var c = testCache(8, 100); // 8-byte cap
    defer c.deinit();
    c.put("lru", "bbbb", 0, 0, 0); // never expires; last_hit 0 → LRU candidate
    c.put("exp", "aaaa", 50, 10, 0); // expires at t=60; last_hit 50 (more recent)
    // At t=100 both fill the cap; inserting 4 more bytes forces one eviction.
    // Pure LRU would take "lru" (older last_hit) — expired-first must take "exp".
    c.put("new", "cccc", 100, 0, 0);
    try testing.expect(c.get("exp", 100, 0) == null); // the expired one went
    try testing.expect(c.get("lru", 100, 0) != null); // the LRU survivor stays
    try testing.expect(c.get("new", 100, 0) != null);
    try testing.expectEqual(@as(u64, 1), c.stats.evictions);
    try testing.expect(c.bytes <= 8);
}

test "clear frees everything but keeps cumulative counters" {
    var c = testCache(1 << 20, 16);
    defer c.deinit();
    c.put("a", "1", 0, 0, 0);
    c.put("b", "22", 0, 0, 0);
    _ = c.get("a", 1, 0); // 1 hit
    c.clear();
    try testing.expectEqual(@as(usize, 0), c.stats.entries);
    try testing.expectEqual(@as(usize, 0), c.bytes);
    try testing.expect(c.get("a", 2, 0) == null);
    try testing.expectEqual(@as(u64, 1), c.stats.hits); // lifetime counters survive
    try testing.expectEqual(@as(u64, 1), c.stats.misses);
}

test "item larger than cache is not stored" {
    var c = testCache(4, 16);
    defer c.deinit();
    c.put("k", "toolongvalue", 0, 0, 0);
    try testing.expect(c.get("k", 1, 0) == null);
    try testing.expectEqual(@as(usize, 0), c.stats.entries);
}

test "values are copied on put (caller's buffer may be reused)" {
    var c = testCache(1 << 20, 16);
    defer c.deinit();
    var buf: [5]u8 = undefined;
    @memcpy(&buf, "hello");
    c.put("k", &buf, 0, 0, 0);
    @memcpy(&buf, "XXXXX"); // clobber the caller's buffer after put
    try testing.expectEqualStrings("hello", c.get("k", 1, 0).?); // cache kept its own copy
}

test "returned slice stays valid until the entry is replaced" {
    var c = testCache(1 << 20, 16);
    defer c.deinit();
    c.put("k", "first", 0, 0, 0);
    const borrowed = c.get("k", 1, 0).?;
    try testing.expectEqualStrings("first", borrowed); // valid while entry lives
    c.put("k", "second", 2, 0, 0); // replace frees the old value → old slice is dead
    try testing.expectEqualStrings("second", c.get("k", 3, 0).?);
}

test "stats counters (hits/misses/expired/evictions/entries/bytes)" {
    var c = testCache(1 << 20, 2);
    defer c.deinit();
    c.put("a", "aa", 0, 100, 0);
    c.put("b", "bbb", 0, 0, 0);
    _ = c.get("a", 10, 0); // hit (a.last_hit=10; b stays at 0 → LRU)
    _ = c.get("a", 10, 0); // hit
    _ = c.get("nope", 10, 0); // miss
    c.put("d", "dd", 20, 0, 0); // at the entry cap → evict LRU (b)
    _ = c.get("a", 500, 0); // TTL-expired → expired + miss, dropped
    try testing.expectEqual(@as(u64, 2), c.stats.hits);
    try testing.expectEqual(@as(u64, 2), c.stats.misses);
    try testing.expectEqual(@as(u64, 1), c.stats.expired);
    try testing.expectEqual(@as(u64, 1), c.stats.evictions);
    try testing.expectEqual(@as(usize, 1), c.stats.entries); // only "d" left
    try testing.expectEqual(@as(usize, c.bytes), c.stats.bytes);
}

test "putDefault applies the configured default TTL" {
    var c = Cache.init(testing.allocator, .{
        .max_bytes = 1 << 20,
        .max_entries = 16,
        .default_ttl_ns = 100,
    });
    defer c.deinit();
    c.putDefault("k", "v", 1000, 0);
    try testing.expect(c.get("k", 1050, 0) != null); // within default TTL
    try testing.expect(c.get("k", 1201, 0) == null); // past default TTL → dropped
}

test "ttl <= 0 never expires by time" {
    var c = testCache(1 << 20, 16);
    defer c.deinit();
    c.put("k", "v", 0, 0, 0);
    try testing.expect(c.get("k", std.math.maxInt(i64), 0) != null);
}
