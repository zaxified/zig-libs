// SPDX-License-Identifier: MIT

//! ramcache — bounded in-memory cache with two independent freshness axes
//! and W-TinyLFU admission/eviction.
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
//!   * Bounded by both entry count and total value bytes. Eviction is
//!     **W-TinyLFU**: new entries land in a small admission *window* (~1% of
//!     capacity, plain LRU) that feeds a segmented-LRU main region (probation
//!     + protected, hits promote probation → protected). Under pressure the
//!     window's LRU *candidate* contends with the main region's LRU *victim*
//!     and is admitted only if its recent access frequency is higher —
//!     otherwise the candidate is dropped and the proven-hot victim stays.
//!     One-hit wonders therefore cannot flush the hot set (scan resistance).
//!     Frequency lives in a fixed-size 4-bit Count-Min Sketch with a
//!     doorkeeper bit set and periodic halving ("aging", every ~10× capacity
//!     samples) so it tracks *recent* frequency, not all-time. TTL-expired
//!     entries are always evicted first (a free win before any frequency
//!     logic). Recency ordering uses a logical access tick; region scans are
//!     linear — fine for the modest entry counts a hot cache of query/fetch
//!     results holds.
//!   * **Provenance:** W-TinyLFU per Einziger & Friedman, "TinyLFU: A Highly
//!     Efficient Cache Admission Policy"; design refs Caffeine (Apache-2.0)
//!     and ristretto (MIT) — behavior only, clean-room, no source copied.
//!   * **Ownership:** keys and values are duped into the cache's own
//!     allocator on `put`; freed on evict, replace, and clear. A slice
//!     returned by `get` borrows the cache's storage — it is valid only until
//!     that key is next replaced, evicted, or cleared. Copy it if you need it
//!     longer. `bytes` tracks value payloads only (the cap the user tunes).
//!   * **Concurrency = single owner.** The cache is NOT internally
//!     synchronized — no lock, by design (`meta.concurrency = .single_owner`).
//!     One thread/event loop owns the instance; a caller who needs to share it
//!     across threads must wrap it in their own lock.
//!   * `put` silently no-ops on OOM — a cache miss is never fatal. If the
//!     frequency sketch itself cannot be allocated, the cache degrades to
//!     plain LRU eviction (admission gate always passes).

const std = @import("std");

pub const meta = .{
    .status = .extract, // extracted from poc-wf-analytic src/cache.zig (same authors)
    .platform = .any,
    .role = .util,
    .concurrency = .single_owner, // one thread/loop owns it, lock-free by design
    .model_after = "W-TinyLFU (TinyLFU paper, Einziger & Friedman; Caffeine/ristretto design, clean-room); generation-tie novel",
    .deps = .{}, // std only
};

/// Cumulative counters + current occupancy. `hits`/`misses`/`evictions`/
/// `expired`/`admissions`/`rejections` are lifetime totals (survive `clear`);
/// `entries`/`bytes` mirror the current contents.
pub const Stats = struct {
    hits: u64 = 0,
    misses: u64 = 0,
    evictions: u64 = 0,
    expired: u64 = 0,
    /// Candidates that won the W-TinyLFU frequency contest against the main
    /// region's LRU victim (the victim was evicted instead).
    admissions: u64 = 0,
    /// Candidates denied by the frequency gate (the candidate was dropped,
    /// the proven-hot victim stayed). Every admission/rejection also counts
    /// as one eviction — `evictions` keeps its original meaning (an entry
    /// removed to make room).
    rejections: u64 = 0,
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

/// 4-bit Count-Min Sketch + doorkeeper with periodic aging, per the TinyLFU
/// paper (Einziger & Friedman). Tracks the *recent* access frequency of keys
/// in a fixed allocation sized to the cache capacity:
///   * `depth` rows × `width` 4-bit counters (16 counters packed per u64),
///     indexed by double hashing; estimate = min over rows (CMS never
///     underestimates).
///   * A doorkeeper bit set absorbs the first occurrence of each key, so
///     one-hit wonders never touch the counters; its bit adds 1 to estimates.
///   * Aging: after ~10× capacity recorded samples, every counter is halved
///     and the doorkeeper cleared, so stale popularity decays away.
const FrequencySketch = struct {
    counters: []u64, // depth rows × (width/16) words, 4-bit counters
    doorkeeper: []u64, // bloom-style bit set, one bit per key hash
    width: usize, // counters per row, power of two, >= 16
    words_per_row: usize,
    dk_bits: usize, // doorkeeper size in bits, power of two
    samples: u64 = 0,
    sample_limit: u64,

    const depth = 4;
    const hash_seed: u64 = 0x2545F4914F6CDD1D;

    fn init(alloc: std.mem.Allocator, capacity: usize) !FrequencySketch {
        // Width = 8× capacity (power of two): with the sample window capped
        // at ~10× capacity, the expected per-counter collision noise stays
        // ~1, so a cold key cannot impersonate a hot one even in a tiny
        // cache. Memory is 4-bit × 4 rows × width = 2 bytes per counter
        // column — negligible.
        const base = try std.math.ceilPowerOfTwo(usize, @max(capacity, 16));
        const width = base * 8;
        const words_per_row = width / 16;
        const counters = try alloc.alloc(u64, depth * words_per_row);
        errdefer alloc.free(counters);
        @memset(counters, 0);
        const dk_bits = width * 8; // 8 doorkeeper bits per counter column
        const doorkeeper = try alloc.alloc(u64, dk_bits / 64);
        @memset(doorkeeper, 0);
        return .{
            .counters = counters,
            .doorkeeper = doorkeeper,
            .width = width,
            .words_per_row = words_per_row,
            .dk_bits = dk_bits,
            .sample_limit = @as(u64, base) * 10, // ~10× capacity, per the paper
        };
    }

    fn deinit(self: *FrequencySketch, alloc: std.mem.Allocator) void {
        alloc.free(self.counters);
        alloc.free(self.doorkeeper);
    }

    fn hashPair(key: []const u8) [2]u64 {
        return .{
            std.hash.Wyhash.hash(0, key),
            std.hash.Wyhash.hash(hash_seed, key),
        };
    }

    /// Record one access of `key`. O(1), allocation-free.
    fn record(self: *FrequencySketch, key: []const u8) void {
        const h = hashPair(key);
        self.samples += 1;
        const dk_idx: usize = @intCast(h[0] & (self.dk_bits - 1));
        const dk_mask = @as(u64, 1) << @intCast(dk_idx & 63);
        if (self.doorkeeper[dk_idx >> 6] & dk_mask == 0) {
            // first sighting since the last reset — the doorkeeper absorbs it
            self.doorkeeper[dk_idx >> 6] |= dk_mask;
        } else {
            var row: usize = 0;
            while (row < depth) : (row += 1) {
                const idx: usize = @intCast((h[0] +% h[1] *% @as(u64, row)) & (self.width - 1));
                const word = row * self.words_per_row + (idx >> 4);
                const shift: u6 = @intCast((idx & 15) * 4);
                const cur = (self.counters[word] >> shift) & 0xF;
                if (cur < 15) self.counters[word] += @as(u64, 1) << shift;
            }
        }
        if (self.samples >= self.sample_limit) self.reset();
    }

    /// Estimated recent frequency of `key` (never underestimates within the
    /// CMS error bounds; capped at 15 + 1 doorkeeper bit).
    fn estimate(self: *const FrequencySketch, key: []const u8) u64 {
        const h = hashPair(key);
        var min: u64 = 15;
        var row: usize = 0;
        while (row < depth) : (row += 1) {
            const idx: usize = @intCast((h[0] +% h[1] *% @as(u64, row)) & (self.width - 1));
            const word = row * self.words_per_row + (idx >> 4);
            const shift: u6 = @intCast((idx & 15) * 4);
            const cur = (self.counters[word] >> shift) & 0xF;
            if (cur < min) min = cur;
        }
        const dk_idx: usize = @intCast(h[0] & (self.dk_bits - 1));
        const dk_hit = (self.doorkeeper[dk_idx >> 6] >> @intCast(dk_idx & 63)) & 1;
        return min + dk_hit;
    }

    /// Aging: halve every counter and clear the doorkeeper so the sketch
    /// tracks recent frequency, not all-time counts.
    fn reset(self: *FrequencySketch) void {
        for (self.counters) |*w| w.* = (w.* >> 1) & 0x7777777777777777;
        @memset(self.doorkeeper, 0);
        self.samples >>= 1;
    }
};

pub const Cache = struct {
    /// W-TinyLFU segment an entry currently lives in.
    const Region = enum(u2) {
        window, // admission window (~1% of capacity, plain LRU)
        probation, // main SLRU: not yet re-referenced since admission
        protected, // main SLRU: re-referenced at least once (hot)
    };

    const Entry = struct {
        value: []u8,
        inserted_ns: i64,
        ttl_ns: i64, // <= 0 → never expire by time
        gen: u64, // 0 → not generation-tied (TTL only)
        last_tick: u64, // logical access clock, drives LRU ordering
        region: Region,
    };

    alloc: std.mem.Allocator,
    map: std.StringHashMapUnmanaged(Entry) = .empty,
    bytes: usize = 0,
    options: Options,
    stats: Stats = .{},
    tick: u64 = 0, // logical clock, bumped on every hit/insert
    window_count: usize = 0,
    probation_count: usize = 0,
    protected_count: usize = 0,
    sketch: ?FrequencySketch = null, // lazily allocated on first access
    sketch_failed: bool = false, // OOM on sketch alloc → degrade to plain LRU
    prng: u64 = 0x9E3779B97F4A7C15, // deterministic LCG for tie-break admission

    pub fn init(alloc: std.mem.Allocator, options: Options) Cache {
        return .{ .alloc = alloc, .options = options };
    }

    pub fn deinit(self: *Cache) void {
        self.clear();
        self.map.deinit(self.alloc);
        if (self.sketch) |*s| s.deinit(self.alloc);
    }

    /// Return the cached value for `key` if it is still fresh (TTL not expired
    /// AND — for generation-tied entries — `entry.gen == cur_gen`). A stale
    /// entry is dropped in passing so its memory is reclaimed (lazy drop — the
    /// only reclamation besides eviction; there is no sweep). `null` = miss
    /// (caller fetches). Pass `cur_gen = 0` for TTL-only lookups.
    /// Every `get` records the key in the frequency sketch (hit or miss), so
    /// repeatedly requested keys build up admission credit.
    /// The returned slice borrows the cache's storage: valid until this key is
    /// replaced, evicted, or the cache is cleared.
    pub fn get(self: *Cache, key: []const u8, now_ns: i64, cur_gen: u64) ?[]const u8 {
        self.noteAccess(key);
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
        self.tick += 1;
        e.last_tick = self.tick;
        if (e.region == .probation) {
            // SLRU promotion: a re-referenced main entry is proven hot
            e.region = .protected;
            self.probation_count -= 1;
            self.protected_count += 1;
            self.enforceProtectedCap();
        }
        self.stats.hits += 1;
        return e.value;
    }

    /// Insert or replace `key` (both key and value are duped into the cache's
    /// allocator). `ttl_ns <= 0` = no time expiry; `gen == 0` = TTL-only (not
    /// invalidated by a generation bump). New entries land in the W-TinyLFU
    /// admission window; under capacity pressure the window's LRU contends
    /// with the main region's LRU victim on recent frequency (expired entries
    /// are always evicted first). Silently no-ops on OOM (a cache miss is
    /// never fatal).
    pub fn put(self: *Cache, key: []const u8, value: []const u8, now_ns: i64, ttl_ns: i64, gen: u64) void {
        self.noteAccess(key);
        if (self.map.getPtr(key)) |e| { // replace value in place, keep the stored key
            const vdup = self.alloc.dupe(u8, value) catch return;
            self.bytes -= e.value.len;
            self.alloc.free(e.value);
            self.tick += 1;
            e.* = .{
                .value = vdup,
                .inserted_ns = now_ns,
                .ttl_ns = ttl_ns,
                .gen = gen,
                .last_tick = self.tick,
                .region = e.region,
            };
            self.bytes += vdup.len;
            self.syncStats();
            return;
        }
        if (value.len > self.options.max_bytes) return; // never cache an item larger than the whole cache
        const kdup = self.alloc.dupe(u8, key) catch return;
        const vdup = self.alloc.dupe(u8, value) catch {
            self.alloc.free(kdup);
            return;
        };
        self.tick += 1;
        self.map.put(self.alloc, kdup, .{
            .value = vdup,
            .inserted_ns = now_ns,
            .ttl_ns = ttl_ns,
            .gen = gen,
            .last_tick = self.tick,
            .region = .window,
        }) catch {
            self.alloc.free(kdup);
            self.alloc.free(vdup);
            return;
        };
        self.window_count += 1;
        self.bytes += vdup.len;
        self.maintain(now_ns);
        self.syncStats();
    }

    /// `put` with `Options.default_ttl_ns` as the TTL.
    pub fn putDefault(self: *Cache, key: []const u8, value: []const u8, now_ns: i64, gen: u64) void {
        self.put(key, value, now_ns, self.options.default_ttl_ns, gen);
    }

    /// Drop every entry (e.g. a manual cache flush). Keeps map capacity, the
    /// cumulative hit/miss/eviction counters, and the frequency sketch (the
    /// popularity history stays useful across a flush).
    pub fn clear(self: *Cache) void {
        var it = self.map.iterator();
        while (it.next()) |kv| {
            self.alloc.free(kv.value_ptr.value);
            self.alloc.free(kv.key_ptr.*);
        }
        self.map.clearRetainingCapacity();
        self.bytes = 0;
        self.window_count = 0;
        self.probation_count = 0;
        self.protected_count = 0;
        self.syncStats();
    }

    // ── internals ───────────────────────────────────────────────────────────
    fn syncStats(self: *Cache) void {
        self.stats.entries = self.map.count();
        self.stats.bytes = self.bytes;
    }

    /// ~1% of capacity (min 1) — the admission window size in entries.
    fn windowCap(self: *const Cache) usize {
        if (self.options.max_entries == 0) return 0;
        return @max(1, self.options.max_entries / 100);
    }

    /// 80% of the main (non-window) region — the protected SLRU segment.
    fn protectedCap(self: *const Cache) usize {
        const main = self.options.max_entries -| self.windowCap();
        return main * 4 / 5;
    }

    /// Lazily create the frequency sketch, then record one access of `key`.
    /// On sketch OOM the cache degrades to plain LRU (gate always admits).
    fn noteAccess(self: *Cache, key: []const u8) void {
        if (self.sketch == null and !self.sketch_failed) {
            if (FrequencySketch.init(self.alloc, self.options.max_entries)) |s| {
                self.sketch = s;
            } else |_| {
                self.sketch_failed = true;
            }
        }
        if (self.sketch) |*s| s.record(key);
    }

    fn dropKey(self: *Cache, key: []const u8) void {
        if (self.map.fetchRemove(key)) |kv| {
            switch (kv.value.region) {
                .window => self.window_count -= 1,
                .probation => self.probation_count -= 1,
                .protected => self.protected_count -= 1,
            }
            self.bytes -= kv.value.value.len;
            self.alloc.free(kv.value.value);
            self.alloc.free(kv.key);
        }
        self.syncStats();
    }

    /// Key of the least-recently-used entry within `region`, or null.
    fn regionLruKey(self: *Cache, region: Region) ?[]const u8 {
        var best: ?[]const u8 = null;
        var best_tick: u64 = std.math.maxInt(u64);
        var it = self.map.iterator();
        while (it.next()) |kv| {
            if (kv.value_ptr.region != region) continue;
            if (kv.value_ptr.last_tick < best_tick) {
                best_tick = kv.value_ptr.last_tick;
                best = kv.key_ptr.*;
            }
        }
        return best;
    }

    /// Key of any TTL-expired entry, or null (expired entries are free wins —
    /// evicted before any frequency logic runs).
    fn findExpiredKey(self: *Cache, now_ns: i64) ?[]const u8 {
        var it = self.map.iterator();
        while (it.next()) |kv| {
            const e = kv.value_ptr.*;
            if (e.ttl_ns > 0 and (now_ns - e.inserted_ns) > e.ttl_ns) return kv.key_ptr.*;
        }
        return null;
    }

    /// Restore all W-TinyLFU invariants after an insert: global entry/byte
    /// caps (via admission-gated eviction), window size, protected size.
    fn maintain(self: *Cache, now_ns: i64) void {
        while (self.map.count() > self.options.max_entries or self.bytes > self.options.max_bytes) {
            if (!self.evictStep(now_ns)) break;
        }
        // Window overflow without global pressure: the main region has room
        // (global cap holds), so the window's LRU moves to probation freely.
        while (self.window_count > self.windowCap()) {
            const k = self.regionLruKey(.window) orelse break;
            const e = self.map.getPtr(k).?;
            e.region = .probation;
            self.window_count -= 1;
            self.probation_count += 1;
        }
        self.enforceProtectedCap();
    }

    /// Demote protected LRU entries back to probation while over the cap.
    fn enforceProtectedCap(self: *Cache) void {
        const cap = self.protectedCap();
        while (self.protected_count > cap) {
            const k = self.regionLruKey(.protected) orelse break;
            const e = self.map.getPtr(k).?;
            e.region = .probation;
            self.protected_count -= 1;
            self.probation_count += 1;
        }
    }

    /// TinyLFU admission gate: does `cand` (window LRU) deserve the slot of
    /// `victim` (main-region LRU)? Higher recent frequency wins. A moderately
    /// warm candidate (estimate >= 6) occasionally wins a tie via a
    /// deterministic ~1/128 coin so a rotating population cannot stall
    /// forever; cold candidates (one-hit wonders) are always rejected, which
    /// is what makes the cache scan-resistant.
    fn admit(self: *Cache, cand: []const u8, victim: []const u8) bool {
        const s = if (self.sketch) |*sk| sk else return true; // no sketch → plain LRU
        const cf = s.estimate(cand);
        const vf = s.estimate(victim);
        if (cf > vf) return true;
        if (cf >= 6) {
            self.prng = self.prng *% 6364136223846793005 +% 1442695040888963407;
            if (self.prng >> 57 == 0) return true; // top 7 bits zero ≈ 1/128
        }
        return false;
    }

    /// Evict exactly one entry to relieve capacity pressure. Order:
    ///   1. any TTL-expired entry (free win),
    ///   2. W-TinyLFU contest: window LRU candidate vs main-region LRU victim
    ///      — the frequency loser is evicted (admission moves the winner from
    ///      the window into probation),
    ///   3. degenerate fallbacks (main-only or window-only occupancy → LRU).
    /// Returns false only when the map is empty.
    fn evictStep(self: *Cache, now_ns: i64) bool {
        if (self.map.count() == 0) return false;
        if (self.findExpiredKey(now_ns)) |k| {
            self.dropKey(k);
            self.stats.evictions += 1;
            return true;
        }
        const cand = self.regionLruKey(.window) orelse {
            // no window entries — evict straight from the main region
            const vk = self.regionLruKey(.probation) orelse
                self.regionLruKey(.protected) orelse return false;
            self.dropKey(vk);
            self.stats.evictions += 1;
            return true;
        };
        const victim = self.regionLruKey(.probation) orelse
            self.regionLruKey(.protected) orelse {
            // main region empty — plain LRU within the window
            self.dropKey(cand);
            self.stats.evictions += 1;
            return true;
        };
        if (self.admit(cand, victim)) {
            self.dropKey(victim);
            const e = self.map.getPtr(cand).?;
            e.region = .probation;
            self.window_count -= 1;
            self.probation_count += 1;
            self.stats.admissions += 1;
        } else {
            self.dropKey(cand);
            self.stats.rejections += 1;
        }
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
    c.put("lru", "bbbb", 0, 0, 0); // never expires; oldest → LRU candidate
    c.put("exp", "aaaa", 50, 10, 0); // expires at t=60; touched more recently
    // At t=100 both fill the cap; inserting 4 more bytes forces one eviction.
    // Pure LRU would take "lru" (older) — expired-first must take "exp".
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
    _ = c.get("a", 10, 0); // hit (a touched; b stays untouched → LRU)
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

// ── W-TinyLFU: frequency sketch ─────────────────────────────────────────────

test "sketch: estimate tracks repeated records exactly for a lone key" {
    var s = try FrequencySketch.init(testing.allocator, 64);
    defer s.deinit(testing.allocator);
    try testing.expectEqual(@as(u64, 0), s.estimate("x")); // never seen
    var i: usize = 0;
    while (i < 5) : (i += 1) s.record("x");
    // doorkeeper absorbs the 1st record, CMS holds the other 4 → exactly 5
    try testing.expectEqual(@as(u64, 5), s.estimate("x"));
    try testing.expectEqual(@as(u64, 0), s.estimate("y")); // untouched key stays 0
}

test "sketch: CMS never underestimates under collision load" {
    var s = try FrequencySketch.init(testing.allocator, 64);
    defer s.deinit(testing.allocator);
    var i: usize = 0;
    while (i < 7) : (i += 1) s.record("hot");
    // hammer many other keys — collisions may only inflate, never deflate
    var kbuf: [16]u8 = undefined;
    var k: usize = 0;
    while (k < 40) : (k += 1) {
        const key = std.fmt.bufPrint(&kbuf, "other{d}", .{k}) catch unreachable;
        s.record(key);
    }
    try testing.expect(s.estimate("hot") >= 7);
}

test "sketch: counters saturate at 15 (+1 doorkeeper)" {
    var s = try FrequencySketch.init(testing.allocator, 64);
    defer s.deinit(testing.allocator);
    var i: usize = 0;
    while (i < 100) : (i += 1) s.record("x");
    try testing.expectEqual(@as(u64, 16), s.estimate("x"));
}

test "sketch: aging halves counters and clears the doorkeeper" {
    var s = try FrequencySketch.init(testing.allocator, 64);
    defer s.deinit(testing.allocator);
    var i: usize = 0;
    while (i < 9) : (i += 1) s.record("x"); // doorkeeper 1 + CMS 8 → estimate 9
    try testing.expectEqual(@as(u64, 9), s.estimate("x"));
    s.samples = s.sample_limit; // force the next record to trigger a reset
    s.record("y");
    // CMS 8 halved → 4; doorkeeper cleared (its +1 is gone)
    try testing.expectEqual(@as(u64, 4), s.estimate("x"));
    try testing.expectEqual(@as(u64, 0), s.estimate("y")); // swept with the reset
    try testing.expect(s.samples < s.sample_limit); // sample window restarted
}

// ── W-TinyLFU: admission behavior ───────────────────────────────────────────

test "admission gate: frequent candidate evicts cold victim, cold candidate is rejected" {
    var c = testCache(1 << 20, 3); // window 1, main 2
    defer c.deinit();
    c.put("a", "1", 0, 0, 0);
    c.put("b", "2", 0, 0, 0); // a → probation
    c.put("c", "3", 0, 0, 0); // b → probation; window = {c}
    // Build admission credit for "d" before it is ever stored (misses count).
    var i: usize = 0;
    while (i < 5) : (i += 1) _ = c.get("d", 1, 0);
    c.put("d", "4", 2, 0, 0); // over cap: candidate c (freq 1) vs victim a (freq 1) → c rejected
    try testing.expectEqual(@as(u64, 1), c.stats.rejections);
    try testing.expect(c.get("c", 3, 0) == null); // the cold window entry lost
    try testing.expect(c.get("d", 3, 0) != null); // the frequent newcomer stayed
    // Now insert another cold key: candidate d (freq high) vs victim a (freq 1)
    // → d is admitted into the main region, a is evicted.
    c.put("e", "5", 4, 0, 0);
    try testing.expectEqual(@as(u64, 1), c.stats.admissions);
    try testing.expect(c.get("a", 5, 0) == null); // victim lost the frequency contest
    try testing.expect(c.get("d", 5, 0) != null);
    try testing.expect(c.get("e", 5, 0) != null); // newest window entry untouched
}

test "scan resistance: a burst of one-hit keys does not evict the hot set" {
    var c = testCache(1 << 20, 50); // window 1, main 49, protected 39
    defer c.deinit();
    var kbuf: [24]u8 = undefined;
    // Establish a hot set of 20 keys with 10 hits each.
    var i: usize = 0;
    while (i < 20) : (i += 1) {
        const key = std.fmt.bufPrint(&kbuf, "hot{d}", .{i}) catch unreachable;
        c.put(key, "hotval", 0, 0, 0);
    }
    var round: usize = 0;
    while (round < 10) : (round += 1) {
        i = 0;
        while (i < 20) : (i += 1) {
            const key = std.fmt.bufPrint(&kbuf, "hot{d}", .{i}) catch unreachable;
            try testing.expect(c.get(key, 1, 0) != null);
        }
    }
    // Scan burst: 150 distinct keys, each seen exactly once (get-miss + put).
    i = 0;
    while (i < 150) : (i += 1) {
        const key = std.fmt.bufPrint(&kbuf, "scan{d}", .{i}) catch unreachable;
        try testing.expect(c.get(key, 2, 0) == null);
        c.put(key, "scanval", 2, 0, 0);
    }
    // Every hot key must have survived the scan.
    i = 0;
    while (i < 20) : (i += 1) {
        const key = std.fmt.bufPrint(&kbuf, "hot{d}", .{i}) catch unreachable;
        try testing.expect(c.get(key, 3, 0) != null);
    }
    try testing.expect(c.stats.rejections > 0); // the gate actually did the work
}

test "hit-ratio benchmark: W-TinyLFU beats plain LRU on a skewed trace" {
    const universe: u64 = 5000; // key space far above capacity
    const capacity: usize = 100;
    const ops: usize = 60_000;

    var c = testCache(1 << 30, capacity);
    defer c.deinit();

    // Plain-LRU baseline simulated inline on the identical trace.
    var lru = std.AutoHashMapUnmanaged(u64, u64).empty; // key id → last-use tick
    defer lru.deinit(testing.allocator);
    var lru_hits: u64 = 0;
    var lru_tick: u64 = 0;

    // Deterministic LCG → Zipf-ish skew: id = floor(u^3 · universe) piles
    // accesses onto low ids (top 100 ids ≈ 27% of the trace) with a long
    // tail of one-hit wonders — the workload TinyLFU is built for.
    var seed: u64 = 0x243F6A8885A308D3;
    var kbuf: [24]u8 = undefined;
    var op: usize = 0;
    while (op < ops) : (op += 1) {
        seed = seed *% 6364136223846793005 +% 1442695040888963407;
        const u = @as(f64, @floatFromInt(seed >> 33)) / @as(f64, @floatFromInt(@as(u64, 1) << 31));
        const id: u64 = @intFromFloat(u * u * u * @as(f64, @floatFromInt(universe)));

        // W-TinyLFU cache under test
        const key = std.fmt.bufPrint(&kbuf, "k{d}", .{id}) catch unreachable;
        if (c.get(key, 0, 0) == null) c.put(key, "v", 0, 0, 0);

        // LRU baseline
        lru_tick += 1;
        if (lru.getPtr(id)) |t| {
            lru_hits += 1;
            t.* = lru_tick;
        } else {
            if (lru.count() >= capacity) {
                var victim: u64 = 0;
                var oldest: u64 = std.math.maxInt(u64);
                var it = lru.iterator();
                while (it.next()) |kv| {
                    if (kv.value_ptr.* < oldest) {
                        oldest = kv.value_ptr.*;
                        victim = kv.key_ptr.*;
                    }
                }
                _ = lru.remove(victim);
            }
            lru.put(testing.allocator, id, lru_tick) catch unreachable;
        }
    }

    // The admission policy must strictly beat recency-only eviction here.
    try testing.expect(c.stats.hits > lru_hits);
    // And by a real margin, not noise: at least 10% more hits.
    try testing.expect(c.stats.hits * 10 >= lru_hits * 11);
}
