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
//!     logic). Recency ordering uses a logical access tick, indexed by a
//!     **binary min-heap per region** (plus one over TTL deadlines), so
//!     picking a victim is O(1) to look at and O(log n) to maintain — never
//!     a scan. It used to be a full-map scan per region, run up to three
//!     times per insert, which made one insert O(max_entries): the audited
//!     `pagecache` cost 93.5 us per 4 KiB page fill at a 4096-page pool,
//!     more CPU than the NVMe read it was avoiding, against 0.8 us now.
//!     A buffer pool is exactly the "modest entry counts" assumption's
//!     counterexample, so the assumption is gone rather than restated.
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
//!     across threads either wraps it in their own lock or uses this module's
//!     **`Sharded`** (see `sharded.zig`) — N independent `Cache` instances,
//!     each behind its own lock, selected by a hash of the key. `Sharded` is a
//!     wrapper *alongside* `Cache`, never a lock inside it: the single-owner
//!     hit path stays lock-free for the five modules that own an instance from
//!     one thread. Its semantics differ where sharding forces them to
//!     (per-shard eviction, non-atomic aggregates, a value handoff that cannot
//!     return a borrowed slice) — all of that is documented on `Sharded`.
//!   * `put` silently no-ops on OOM — a cache miss is never fatal. If the
//!     frequency sketch itself cannot be allocated, the cache degrades to
//!     plain LRU eviction (admission gate always passes).
//!   * **Write-behind seam (opt-in, for a caller-driven persistence layer):**
//!     every entry carries a *dirty* bit (`put` sets it; `markClean` clears
//!     it) and `Options.on_evict` is an optional hook fired just before an
//!     entry's value is freed — on eviction (W-TinyLFU victim or lazy
//!     TTL/generation drop), replacement (`put` over an existing key), and
//!     clear (once per entry). A write-behind coordinator marks nothing
//!     itself (every `put` is already dirty-by-definition); it periodically
//!     `drainDirty`s to flush proactively and calls `markClean` once
//!     persisted, with `on_evict`'s `dirty` flag as the safety net so a
//!     write is never silently dropped by an eviction that races the
//!     flusher. Unused (no callback, dirty bit never inspected), this costs
//!     one extra `bool` per entry and changes nothing else.

const std = @import("std");

/// The internally-synchronized wrapper: N independent `Cache` instances, one
/// lock each, picked by a hash of the key. Its own doc comment carries the
/// full contract — the value handoff, the per-shard eviction semantics, and
/// what the aggregate operations do and do not guarantee.
pub const Sharded = @import("sharded.zig").Sharded;

pub const meta = .{
    .platform = .any,
    .role = .util,
    // Describes `Cache`, this module's primary type: one thread/loop owns it,
    // lock-free by design. The opt-in `Sharded` wrapper in the same module is
    // internally synchronized (it would tag `.threadsafe`); the vocabulary has
    // one tag per module, so it names the default type.
    .concurrency = .single_owner,
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
    /// Entries with at least one live borrow (`pin`/`reserve` not yet
    /// matched by `release`). Such an entry is never chosen as an eviction
    /// victim, so while this is non-zero the cache may legitimately sit
    /// **over** `max_entries`/`max_bytes`: a borrowed page is resident by
    /// definition. Includes doomed entries (overwritten or removed while
    /// still borrowed — no longer findable, memory still alive for the
    /// borrower), which is why this can exceed `entries`.
    pinned: usize = 0,
};

/// Why an entry left the cache — passed to `on_evict` alongside the outgoing
/// key/value so a write-behind coordinator can tell an ordinary
/// capacity/staleness-driven removal from an explicit overwrite from a bulk
/// flush.
pub const EvictReason = enum {
    /// W-TinyLFU capacity pressure (frequency-contest victim, or a
    /// degenerate LRU fallback) **or** a lazy TTL/generation-stale drop
    /// (both `get`'s lazy drop and `evictStep`'s expired-first check route
    /// through the same removal — a dirty-but-stale entry fires this too,
    /// not a different reason, since either way it left uninvited).
    evicted,
    /// `put` overwrote an existing key with a new value; `value`/`dirty`
    /// describe the value that was just replaced.
    replaced,
    /// `clear()` dropped every entry — fired once per entry, in map
    /// iteration order (not LRU order).
    cleared,
};

/// Caller hook fired just before an entry's backing memory is freed, for
/// every way an entry can leave the cache — see `EvictReason`. Never fired
/// on a plain `get` hit or miss. `dirty` is the entry's dirty bit at the
/// moment of removal (see the dirty-set / write-behind seam on `Cache`) so
/// the hook doubles as a last-chance flush point before the memory goes
/// away. `ctx` is `Options.on_evict_ctx` verbatim. Called synchronously from
/// inside `get`/`put`/`clear` — keep it cheap (or hand off) and do not call
/// back into this `Cache` from it (reentrant mutation mid-removal, e.g.
/// during `clear`'s iteration, is unsupported).
pub const OnEvictFn = *const fn (ctx: ?*anyopaque, key: []const u8, value: []const u8, dirty: bool, reason: EvictReason) void;

/// `drainDirty` sweep callback — see `Cache.drainDirty`.
pub const DirtyFn = *const fn (ctx: ?*anyopaque, key: []const u8, value: []const u8) void;

/// Tunables, fixed at `init`.
pub const Options = struct {
    /// Cap on the sum of stored value bytes. An item larger than this is
    /// never stored at all.
    max_bytes: usize,
    /// Cap on the number of entries.
    max_entries: usize,
    /// TTL applied by `putDefault`. `<= 0` = never expire by time.
    default_ttl_ns: i64 = 0,
    /// Optional write-behind hook; see `OnEvictFn`. Null (default) = no-op —
    /// behavior and performance are unchanged from before this existed.
    on_evict: ?OnEvictFn = null,
    /// Opaque pointer handed to every `on_evict` call.
    on_evict_ctx: ?*anyopaque = null,
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

    /// Per-entry index node — the piece that makes victim selection O(1)
    /// instead of a full-map scan.
    ///
    /// It exists as a separate heap allocation for one reason: a
    /// `StringHashMapUnmanaged` moves its values on rehash, so nothing may
    /// hold a `*Entry`. A `*Node` is stable, so the four binary heaps below
    /// can hold pointers into it and write back a heap position without ever
    /// consulting the map. `key` borrows the map's stored key (the `kdup`
    /// this cache owns) and is valid for exactly as long as the entry is.
    const Node = struct {
        key: []const u8,
        /// Mirror of `Entry.last_tick`; the ordering key of the region heaps.
        tick: u64,
        /// `inserted_ns + ttl_ns` — the ordering key of the expiry heap.
        /// Meaningful only while `exp_idx != not_queued`.
        deadline: i64 = 0,
        /// Position in `Cache.lru[@intFromEnum(entry.region)]`, or
        /// `not_queued` while the entry is deliberately out of the index
        /// (borrowed — see `pins` — or doomed).
        heap_idx: u32 = not_queued,
        /// Position in `Cache.exp`, or `not_queued` for an entry with no TTL.
        exp_idx: u32 = not_queued,
        /// Live borrow count: `pin`/`reserve` increment it, `release`
        /// decrements it. A node with `pins > 0` is taken out of its region
        /// and expiry heaps, and victim selection only ever reads a heap
        /// root — so a borrowed entry is normally never even *considered*,
        /// at zero cost per eviction. `release` puts it back.
        ///
        /// ⚠ That unlinking is the fast path, **not** the safety property.
        /// Safety is `dropKeyReason`'s `pins > 0` check, which dooms rather
        /// than frees. Measured, not argued: deleting the `expRemove` call in
        /// `pinEntry` leaves `ramcache`, `pagecache` and `kvtree` all green,
        /// because a pinned entry that stays in the expiry heap is still
        /// doomed correctly when selected. Do not read the unlinking as the
        /// thing that prevents the use-after-free — it is belt, and the flag
        /// check is braces.
        pins: u32 = 0,
        /// Position in `Cache.doomed`, or `not_queued` when the node is a
        /// live map entry. A *doomed* node is one whose entry was
        /// overwritten, removed, cleared or expired while a borrow was still
        /// outstanding: it is unlinked from the map (so it can never be
        /// served again, no stale hits) but keeps owning `owned` until the
        /// last `release`, so the borrower reads its snapshot rather than
        /// freed memory.
        doom_idx: u32 = not_queued,
        /// Value bytes this node owns while doomed (`doom_idx != not_queued`);
        /// otherwise the value belongs to the map `Entry` and this is empty.
        owned: []u8 = &.{},

        const not_queued: u32 = std.math.maxInt(u32);
    };

    const Entry = struct {
        value: []u8,
        inserted_ns: i64,
        ttl_ns: i64, // <= 0 → never expire by time
        gen: u64, // 0 → not generation-tied (TTL only)
        last_tick: u64, // logical access clock, drives LRU ordering
        region: Region,
        /// Write-behind dirty bit: `put` sets it (a write not yet known to
        /// be persisted); the coordinator clears it via `markClean` once it
        /// has durably persisted `value`. Unused by the cache itself —
        /// purely a passenger bit for the caller.
        dirty: bool = false,
        /// Index node for the region/expiry heaps. Owned by the cache; freed
        /// with the entry.
        node: *Node,
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
    /// One min-heap per region, ordered by `Node.tick`: `items[0]` is that
    /// region's least-recently-used entry. Since `tick` is a global counter
    /// bumped on every insert and every hit, no two live entries share one,
    /// so "the minimum tick in this region" names exactly the entry the old
    /// full-map scan named — this is a complexity change, not a policy change.
    lru: [3]std.ArrayListUnmanaged(*Node) = .{ .empty, .empty, .empty },
    /// Min-heap over `Node.deadline`, holding only entries with a TTL:
    /// `items[0]` is the soonest to expire, so "is any entry expired?" is one
    /// comparison instead of a scan. (The old scan returned whichever expired
    /// entry hash order reached first — "any", explicitly; this returns the
    /// earliest, which is a subset of the same answer.)
    exp: std.ArrayListUnmanaged(*Node) = .empty,
    /// Nodes whose entry died while borrowed (see `Node.doom_idx`). They own
    /// their value bytes and are freed by the last matching `release`. The
    /// list's capacity is reserved up-front by `pin`/`reserve` — one slot per
    /// borrowed entry — precisely so that parking a borrow can never fail
    /// midway and be forced to free memory somebody is still reading.
    doomed: std.ArrayListUnmanaged(*Node) = .empty,
    /// Entries with `node.pins > 0`, live-in-map plus doomed. Mirrored into
    /// `Stats.pinned`; also the reservation target for `doomed`'s capacity.
    pinned_entries: usize = 0,
    /// Instrumentation: entries examined by `regionLruKey` + `findExpiredKey`,
    /// the two functions that used to walk the whole map on every insert.
    /// After this fix each call examines exactly one, so the count per `put`
    /// is flat in `max_entries`; a regression to a linear scan makes it grow
    /// with capacity. That is the acceptance criterion the audit set, and the
    /// regression test reads this counter rather than a clock.
    maintenance_visits: u64 = 0,

    pub fn init(alloc: std.mem.Allocator, options: Options) Cache {
        return .{ .alloc = alloc, .options = options };
    }

    pub fn deinit(self: *Cache) void {
        self.clear();
        // Tearing the cache down with borrows still outstanding is a caller
        // bug, but leaking their bytes would only turn it into a second one.
        for (self.doomed.items) |n| {
            self.alloc.free(n.owned);
            self.alloc.destroy(n);
        }
        self.doomed.deinit(self.alloc);
        self.map.deinit(self.alloc);
        for (&self.lru) |*h| h.deinit(self.alloc);
        self.exp.deinit(self.alloc);
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
            _ = self.dropKey(key);
            return null;
        }
        self.tick += 1;
        e.last_tick = self.tick;
        e.node.tick = self.tick;
        // A borrowed node is out of the heaps entirely (Node.pins), so it has
        // no heap position to sift and no region membership to move; the
        // fresh tick above is what it re-enters the index with on `release`.
        if (e.node.pins == 0) {
            self.lruTouched(e.region, e.node);
            if (e.region == .probation) {
                // SLRU promotion: a re-referenced main entry is proven hot
                if (self.lruMove(e.node, .probation, .protected)) {
                    e.region = .protected;
                    self.probation_count -= 1;
                    self.protected_count += 1;
                    self.enforceProtectedCap();
                } // else: OOM indexing the promotion — stay in probation
            }
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
        if (self.map.getPtr(key)) |e| replace: {
            if (e.node.pins > 0) {
                // Somebody is reading the current bytes. Freeing them here is
                // the `ocspcache` use-after-free shape verbatim, and *refusing*
                // the write would leave the cache serving pre-write bytes —
                // the stale-hit class a write-through cache exists to prevent.
                // So do neither: park the old value with its borrower (it
                // leaves the map immediately, so it can never be served again)
                // and fall through to insert the new value as a fresh entry.
                self.doomEntry(key, .replaced);
                break :replace;
            }
            // replace value in place, keep the stored key
            const vdup = self.alloc.dupe(u8, value) catch return;
            self.fireOnEvict(key, e.value, e.dirty, .replaced);
            self.bytes -= e.value.len;
            self.alloc.free(e.value);
            self.tick += 1;
            const node = e.node; // survives the rewrite: same key, same slot
            e.* = .{
                .value = vdup,
                .inserted_ns = now_ns,
                .ttl_ns = ttl_ns,
                .gen = gen,
                .last_tick = self.tick,
                .region = e.region,
                .dirty = true, // a fresh write, not yet known to be persisted
                .node = node,
            };
            node.tick = self.tick;
            self.lruTouched(e.region, node);
            self.expUpdate(node, now_ns, ttl_ns);
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
        const node = self.alloc.create(Node) catch {
            self.alloc.free(kdup);
            self.alloc.free(vdup);
            return;
        };
        // Reserve the index slots BEFORE the map insert, so that once the
        // entry exists it is guaranteed to be reachable from the heaps. An
        // entry the heaps do not know about could never be chosen as a victim.
        const reserved = blk: {
            self.lru[@intFromEnum(Region.window)].ensureUnusedCapacity(self.alloc, 1) catch break :blk false;
            if (ttl_ns > 0) self.exp.ensureUnusedCapacity(self.alloc, 1) catch break :blk false;
            break :blk true;
        };
        if (!reserved) {
            self.alloc.destroy(node);
            self.alloc.free(kdup);
            self.alloc.free(vdup);
            return;
        }
        self.tick += 1;
        node.* = .{ .key = kdup, .tick = self.tick };
        self.map.put(self.alloc, kdup, .{
            .value = vdup,
            .inserted_ns = now_ns,
            .ttl_ns = ttl_ns,
            .gen = gen,
            .last_tick = self.tick,
            .region = .window,
            .dirty = true, // a fresh write, not yet known to be persisted
            .node = node,
        }) catch {
            self.alloc.destroy(node);
            self.alloc.free(kdup);
            self.alloc.free(vdup);
            return;
        };
        // Capacity was reserved above, so neither can fail. Called for effect
        // in every build mode; the assert only checks the reservation held.
        const indexed = self.lruPush(.window, node);
        std.debug.assert(indexed);
        if (ttl_ns > 0) {
            const queued = self.expPush(node, now_ns +| ttl_ns);
            std.debug.assert(queued);
        }
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
            self.fireOnEvict(kv.key_ptr.*, kv.value_ptr.value, kv.value_ptr.dirty, .cleared);
            if (kv.value_ptr.node.pins > 0) {
                // Borrowed: unlink it like every other entry (a `clear` must
                // really leave nothing findable — that is what pagecache's
                // six invalidation guards rest on) but hand the bytes to the
                // borrower rather than freeing them under it.
                self.parkNode(kv.value_ptr.node, kv.key_ptr.*, kv.value_ptr.value);
                continue;
            }
            self.alloc.destroy(kv.value_ptr.node);
            self.alloc.free(kv.value_ptr.value);
            self.alloc.free(kv.key_ptr.*);
        }
        self.map.clearRetainingCapacity();
        for (&self.lru) |*h| h.clearRetainingCapacity();
        self.exp.clearRetainingCapacity();
        self.bytes = 0;
        self.window_count = 0;
        self.probation_count = 0;
        self.protected_count = 0;
        self.syncStats();
    }

    /// Explicitly remove one entry if present — frees its key/value/index
    /// node, updates `stats`/`bytes`/region counts, and fires `on_evict` with
    /// reason `.evicted` (the same reason capacity-driven removal uses: from
    /// the caller's perspective the entry left uninvited either way). O(1)
    /// map lookup plus the same O(log n) heap removal capacity eviction
    /// already pays — never a scan. Returns `true` if `key` was resident and
    /// removed, `false` if it was already absent (harmless no-op, same shape
    /// as `markClean`).
    ///
    /// This is the targeted counterpart to `clear()`: a caller that owns a
    /// narrower invalidation scope than "everything" (e.g. `pagecache`
    /// forgetting one file's pages on close, without discarding every other
    /// open file's hot pages) does not have to pay for a full-cache wipe.
    ///
    /// Removing a key that is currently borrowed (see `pin`) still returns
    /// `true` and still makes it immediately unfindable; the value bytes are
    /// handed to the borrower and freed by the last `release` instead of here.
    pub fn remove(self: *Cache, key: []const u8) bool {
        return self.dropKey(key);
    }

    // ── borrow seam: zero-copy reads out of cache storage ───────────────────
    //
    // `get` returns a slice into cache storage that is only valid "until this
    // key is replaced, evicted, or the cache is cleared" — a rule a caller can
    // only obey by copying immediately, which is exactly the per-hit `memcpy`
    // `pagecache` pays. `pin` removes that rule instead of restating it: while
    // a borrow is outstanding the entry is not an eviction candidate at all
    // (it is out of the heaps victim selection reads), and any operation that
    // *would* have destroyed it parks the bytes with the borrower instead.
    //
    // The enforcement is structural rather than documentary: there is no
    // eviction path that has to remember to check a flag, because a pinned
    // node is not reachable from the structures eviction chooses from.

    /// A read-only borrow of one entry's value bytes, valid until `release`.
    /// Opaque: hold it, read `bytes`, hand it back.
    pub const Borrow = struct {
        /// Cache-owned bytes. Valid for exactly the borrow's lifetime — and
        /// unlike `get`'s result, that lifetime survives eviction pressure,
        /// an overwrite of the same key, `remove`, and `clear`.
        bytes: []const u8,
        node: *Node,
    };

    /// A borrow of *uninitialized* storage from `reserve`, to be filled in
    /// place and then `commit`ed (or `discard`ed if the fill fails).
    pub const Fill = struct {
        /// Uninitialized cache-owned bytes. Write all of them before
        /// `commit`; anything left unwritten becomes cached garbage.
        bytes: []u8,
        node: *Node,
    };

    /// Like `get`, but returns a *borrow* instead of a bare slice: no copy is
    /// needed, because the entry cannot be evicted, replaced or cleared out
    /// from under the returned bytes until `release`. `null` = miss, or the
    /// borrow bookkeeping could not be allocated (treat as a miss and use the
    /// copying path — never a silent stale hit).
    ///
    /// While borrowed the entry does not participate in eviction, so a cache
    /// whose whole capacity is borrowed simply admits nothing new (`put`
    /// no-ops, as it already does under memory pressure) and may sit over its
    /// nominal cap; `Stats.pinned` reports how many entries are in that state.
    ///
    /// Unlike `get` this does **not** promote a probation entry to protected:
    /// the entry is out of the region heaps for the borrow's duration, so it
    /// has no region membership to move. It does refresh the entry's tick, so
    /// `release` re-files it as recently used.
    pub fn pin(self: *Cache, key: []const u8, now_ns: i64, cur_gen: u64) ?Borrow {
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
            _ = self.dropKey(key);
            return null;
        }
        const value = e.value;
        if (!self.pinEntry(e)) {
            self.stats.misses += 1;
            return null;
        }
        self.tick += 1;
        e.last_tick = self.tick;
        e.node.tick = self.tick;
        self.stats.hits += 1;
        self.syncStats();
        return .{ .bytes = value, .node = e.node };
    }

    /// Insert `key` with `len` bytes of **uninitialized** cache storage and
    /// hand back a writable borrow of it, so a caller that would otherwise
    /// fill a scratch buffer and then `put` (two copies of the payload) can
    /// produce the value straight into its final home (one). The entry is
    /// pinned from birth: it is visible to `get`/`pin` immediately, so fill it
    /// before returning to code that could read it.
    ///
    /// Finish with `commit` (keep it, downgrade to a read borrow) or `discard`
    /// (the fill failed — remove it without ever exposing the garbage).
    /// `null` on OOM or when `len` exceeds the whole cache's byte budget.
    pub fn reserve(self: *Cache, key: []const u8, len: usize, now_ns: i64, ttl_ns: i64, gen: u64) ?Fill {
        self.noteAccess(key);
        if (len > self.options.max_bytes) return null;
        if (self.map.getPtr(key)) |e| {
            // Same reasoning as `put`: an existing entry is either freed or,
            // if borrowed, parked — never left findable with old bytes.
            if (e.node.pins > 0) self.doomEntry(key, .replaced) else _ = self.dropKeyReason(key, .replaced);
        }
        // Reserve the parking slot before the entry exists, so that once the
        // bytes are lent out every path that could destroy them is infallible.
        self.doomed.ensureTotalCapacity(self.alloc, self.pinned_entries + 1) catch return null;
        const kdup = self.alloc.dupe(u8, key) catch return null;
        const vbuf = self.alloc.alloc(u8, len) catch {
            self.alloc.free(kdup);
            return null;
        };
        const node = self.alloc.create(Node) catch {
            self.alloc.free(kdup);
            self.alloc.free(vbuf);
            return null;
        };
        self.tick += 1;
        node.* = .{ .key = kdup, .tick = self.tick, .pins = 1 };
        self.map.put(self.alloc, kdup, .{
            .value = vbuf,
            .inserted_ns = now_ns,
            .ttl_ns = ttl_ns,
            .gen = gen,
            .last_tick = self.tick,
            .region = .window,
            .dirty = true,
            .node = node,
        }) catch {
            self.alloc.destroy(node);
            self.alloc.free(kdup);
            self.alloc.free(vbuf);
            return null;
        };
        // Deliberately NOT pushed into the window heap or the expiry heap:
        // `pins == 1`, and a pinned node is out of the index (see `Node.pins`).
        // `release` files it in the moment the borrow ends.
        self.pinned_entries += 1;
        self.window_count += 1;
        self.bytes += len;
        self.maintain(now_ns); // makes room by evicting *other* entries
        self.syncStats();
        return .{ .bytes = vbuf, .node = node };
    }

    /// Downgrade a filled `Fill` to a read-only borrow of the same bytes,
    /// keeping the pin. Release it with `release` like any other borrow.
    pub fn commit(self: *Cache, f: Fill) Borrow {
        _ = self;
        return .{ .bytes = f.bytes, .node = f.node };
    }

    /// Throw away a reservation whose fill failed. The entry is removed
    /// without firing `on_evict` — the bytes were never written, and handing a
    /// caller's hook uninitialized memory would be a disclosure, not a hook.
    pub fn discard(self: *Cache, f: Fill) void {
        const n = f.node;
        std.debug.assert(n.pins > 0);
        if (n.doom_idx != Node.not_queued or n.pins != 1) {
            // Something already unlinked it (a concurrent-ish put/clear on the
            // same key between `reserve` and here). Ordinary release then.
            self.release(.{ .bytes = f.bytes, .node = n });
            return;
        }
        const kv = self.map.fetchRemove(n.key).?;
        switch (kv.value.region) {
            .window => self.window_count -= 1,
            .probation => self.probation_count -= 1,
            .protected => self.protected_count -= 1,
        }
        self.bytes -= kv.value.value.len;
        self.alloc.free(kv.value.value);
        self.alloc.free(kv.key);
        self.alloc.destroy(n);
        self.pinned_entries -= 1;
        self.syncStats();
    }

    /// End a borrow. The entry becomes an ordinary eviction candidate again
    /// (re-filed into its region's LRU heap with the tick of its last access);
    /// a *doomed* entry — one whose logical life ended while it was borrowed —
    /// has its memory freed here, by the last release.
    ///
    /// Note it does not run `maintain`: if pins held the cache over its cap,
    /// the next `put` restores it. Evicting from inside `release` would make
    /// releasing one borrow able to invalidate an unrelated `get` slice.
    pub fn release(self: *Cache, b: Borrow) void {
        const n = b.node;
        std.debug.assert(n.pins > 0);
        n.pins -= 1;
        if (n.pins != 0) return;
        self.pinned_entries -= 1;
        if (n.doom_idx != Node.not_queued) {
            self.freeDoomed(n);
            self.syncStats();
            return;
        }
        const e = self.map.getPtr(n.key).?;
        if (!self.lruPush(e.region, n)) {
            // A live entry that is not in the index could never be chosen as
            // a victim — un-evictable forever. Dropping it is always safe.
            _ = self.dropKey(n.key);
            self.syncStats();
            return;
        }
        if (e.ttl_ns > 0) _ = self.expPush(n, e.inserted_ns +| e.ttl_ns);
        self.syncStats();
    }

    /// True while `key` is resident and has at least one live borrow.
    pub fn isPinned(self: *Cache, key: []const u8) bool {
        const e = self.map.getPtr(key) orelse return false;
        return e.node.pins > 0;
    }

    // ── write-behind seam: dirty-set ────────────────────────────────────────

    /// True if `key` is present and its dirty bit is set. Side-effect-free:
    /// unlike `get`, does not touch stats, SLRU promotion, the frequency
    /// sketch, or TTL/generation freshness — a diagnostic for a write-behind
    /// coordinator, not a substitute for `get`. `false` for an absent key
    /// (indistinguishable here from "clean"; use `get` if that distinction
    /// matters).
    pub fn isDirty(self: *Cache, key: []const u8) bool {
        const e = self.map.getPtr(key) orelse return false;
        return e.dirty;
    }

    /// Clear the dirty bit for `key` — the write-behind coordinator's ack
    /// after it has durably persisted the current value. Returns `false`
    /// (no-op) if `key` is absent, e.g. it was evicted/replaced/cleared
    /// before the flush landed; `on_evict`'s `dirty` flag is what catches
    /// that race. Side-effect-free otherwise (no stats/promotion/sketch
    /// touch).
    pub fn markClean(self: *Cache, key: []const u8) bool {
        const e = self.map.getPtr(key) orelse return false;
        e.dirty = false;
        return true;
    }

    /// Visit every currently-dirty entry exactly once via `cb(ctx, key,
    /// value)` — for a periodic flusher that persists dirty entries
    /// proactively rather than waiting for `on_evict` to catch them on the
    /// way out. No removal, no ordering guarantee, allocation-free. `cb` may
    /// call `markClean` on the cache (that only flips a bit, it does not
    /// touch map structure) but must not call `put`/`clear`/`get` — those
    /// can insert, evict, or resize mid-iteration, which is unsupported.
    pub fn drainDirty(self: *Cache, cb: DirtyFn, ctx: ?*anyopaque) void {
        var it = self.map.iterator();
        while (it.next()) |kv| {
            if (kv.value_ptr.dirty) cb(ctx, kv.key_ptr.*, kv.value_ptr.value);
        }
    }

    // ── internals ───────────────────────────────────────────────────────────
    fn syncStats(self: *Cache) void {
        self.stats.entries = self.map.count();
        self.stats.bytes = self.bytes;
        self.stats.pinned = self.pinned_entries;
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

    /// Returns `true` if `key` was present and removed, `false` if it was
    /// already absent — so callers that need to know (`remove`) and callers
    /// that don't (lazy TTL/generation drop, `evictStep`) share one path.
    fn dropKey(self: *Cache, key: []const u8) bool {
        return self.dropKeyReason(key, .evicted);
    }

    fn dropKeyReason(self: *Cache, key: []const u8, reason: EvictReason) bool {
        if (self.map.getPtr(key)) |e| {
            if (e.node.pins > 0) {
                // Borrowed: unlink it (no stale hit can follow) but leave the
                // bytes alive for the borrower — see `doomEntry`.
                self.doomEntry(key, reason);
                return true;
            }
        }
        const found = if (self.map.fetchRemove(key)) |kv| blk: {
            self.lruRemove(kv.value.region, kv.value.node);
            self.expRemove(kv.value.node);
            self.alloc.destroy(kv.value.node);
            switch (kv.value.region) {
                .window => self.window_count -= 1,
                .probation => self.probation_count -= 1,
                .protected => self.protected_count -= 1,
            }
            self.fireOnEvict(kv.key, kv.value.value, kv.value.dirty, reason);
            self.bytes -= kv.value.value.len;
            self.alloc.free(kv.value.value);
            self.alloc.free(kv.key);
            break :blk true;
        } else false;
        self.syncStats();
        return found;
    }

    // ── borrow internals ────────────────────────────────────────────────────

    /// Take one borrow of `e`. On the 0→1 transition the node leaves both
    /// index heaps — that single removal is the whole "borrowed entries are
    /// unevictable" mechanism, because victim selection reads heap roots and
    /// nothing else. False on OOM reserving the parking slot, in which case
    /// nothing changed and the caller must fall back to copying: better a
    /// missed optimisation than a borrow whose destruction path can fail.
    fn pinEntry(self: *Cache, e: *Entry) bool {
        const n = e.node;
        if (n.pins == 0) {
            self.doomed.ensureTotalCapacity(self.alloc, self.pinned_entries + 1) catch return false;
            self.lruRemove(e.region, n);
            self.expRemove(n);
            self.pinned_entries += 1;
        }
        n.pins += 1;
        return true;
    }

    /// Unlink `key`'s borrowed entry from the map and hand its value bytes to
    /// the node, which now owns them until the last `release`. The entry is
    /// gone for lookup purposes the instant this returns — a doomed page can
    /// never be served again — while the outstanding borrow keeps reading the
    /// snapshot it was given.
    fn doomEntry(self: *Cache, key: []const u8, reason: EvictReason) void {
        const kv = self.map.fetchRemove(key).?;
        std.debug.assert(kv.value.node.pins > 0);
        self.fireOnEvict(kv.key, kv.value.value, kv.value.dirty, reason);
        switch (kv.value.region) {
            .window => self.window_count -= 1,
            .probation => self.probation_count -= 1,
            .protected => self.protected_count -= 1,
        }
        self.bytes -= kv.value.value.len;
        self.parkNode(kv.value.node, kv.key, kv.value.value);
        self.syncStats();
    }

    /// Shared tail of `doomEntry` and `clear`: free the map's key copy and
    /// move the value onto the node. `doomed`'s capacity was reserved when
    /// the first borrow was taken (`pinEntry`/`reserve`), one slot per
    /// borrowed entry, so this append cannot fail.
    fn parkNode(self: *Cache, n: *Node, owned_key: []const u8, value: []u8) void {
        std.debug.assert(n.pins > 0);
        std.debug.assert(n.doom_idx == Node.not_queued);
        self.alloc.free(owned_key);
        n.key = &.{}; // the map key it borrowed is gone
        n.owned = value;
        self.doomed.appendAssumeCapacity(n);
        n.doom_idx = @intCast(self.doomed.items.len - 1);
    }

    /// Last release of a doomed node: free its value and the node itself.
    fn freeDoomed(self: *Cache, n: *Node) void {
        const i: usize = n.doom_idx;
        const last = self.doomed.items[self.doomed.items.len - 1];
        self.doomed.items.len -= 1;
        if (i < self.doomed.items.len) {
            self.doomed.items[i] = last;
            last.doom_idx = @intCast(i);
        }
        self.alloc.free(n.owned);
        self.alloc.destroy(n);
    }

    /// Fire `Options.on_evict` if one is set. Called just before the
    /// caller-visible value memory for `key` is freed.
    fn fireOnEvict(self: *Cache, key: []const u8, value: []const u8, dirty: bool, reason: EvictReason) void {
        if (self.options.on_evict) |cb| cb(self.options.on_evict_ctx, key, value, dirty, reason);
    }

    // ── the index heaps ─────────────────────────────────────────────────────
    //
    // Four binary min-heaps of `*Node`: one per region ordered by `tick`, one
    // over `deadline`. Every operation is O(log n) with no hashing — a swap
    // writes the moved node's index straight back into the node, which is the
    // whole reason `Node` is a separate stable allocation.

    fn lruAt(h: []*Node, i: usize, n: *Node) void {
        h[i] = n;
        n.heap_idx = @intCast(i);
    }

    fn lruSiftUp(h: []*Node, start: usize) void {
        var i = start;
        const item = h[i];
        while (i > 0) {
            const parent = (i - 1) / 2;
            if (h[parent].tick <= item.tick) break;
            lruAt(h, i, h[parent]);
            i = parent;
        }
        lruAt(h, i, item);
    }

    fn lruSiftDown(h: []*Node, start: usize) void {
        var i = start;
        const item = h[i];
        while (true) {
            var child = i * 2 + 1;
            if (child >= h.len) break;
            if (child + 1 < h.len and h[child + 1].tick < h[child].tick) child += 1;
            if (item.tick <= h[child].tick) break;
            lruAt(h, i, h[child]);
            i = child;
        }
        lruAt(h, i, item);
    }

    /// Insert `n` into `region`'s heap. False on OOM — every caller has a
    /// defined fallback, because a failed insert must never leave a live entry
    /// out of the index (it would then be un-evictable).
    fn lruPush(self: *Cache, region: Region, n: *Node) bool {
        const h = &self.lru[@intFromEnum(region)];
        h.append(self.alloc, n) catch return false;
        lruAt(h.items, h.items.len - 1, n);
        lruSiftUp(h.items, h.items.len - 1);
        return true;
    }

    fn lruRemove(self: *Cache, region: Region, n: *Node) void {
        if (n.heap_idx == Node.not_queued) return; // borrowed/doomed: not indexed
        const h = &self.lru[@intFromEnum(region)];
        const i: usize = n.heap_idx;
        n.heap_idx = Node.not_queued;
        const last = h.items[h.items.len - 1];
        h.items.len -= 1;
        if (i >= h.items.len) return; // it was the last slot
        lruAt(h.items, i, last);
        if (i > 0 and last.tick < h.items[(i - 1) / 2].tick) {
            lruSiftUp(h.items, i);
        } else {
            lruSiftDown(h.items, i);
        }
    }

    /// `n.tick` has just been raised (a hit or a rewrite), so it can only sink.
    fn lruTouched(self: *Cache, region: Region, n: *Node) void {
        if (n.heap_idx == Node.not_queued) return; // borrowed/doomed: not indexed
        lruSiftDown(self.lru[@intFromEnum(region)].items, n.heap_idx);
    }

    /// Move `n` between region heaps. False on OOM, with `n` left in `from`.
    fn lruMove(self: *Cache, n: *Node, from: Region, to: Region) bool {
        self.lruRemove(from, n);
        if (self.lruPush(to, n)) return true;
        // The slot just vacated in `from` is still reserved, so this cannot
        // fail — the entry stays indexed and the caller declines the move.
        // Written out rather than wrapped in `assert`: the call must happen in
        // every build mode, and an assert reads like it might not.
        const back = self.lruPush(from, n);
        std.debug.assert(back);
        return false;
    }

    fn expAt(h: []*Node, i: usize, n: *Node) void {
        h[i] = n;
        n.exp_idx = @intCast(i);
    }

    fn expSiftUp(h: []*Node, start: usize) void {
        var i = start;
        const item = h[i];
        while (i > 0) {
            const parent = (i - 1) / 2;
            if (h[parent].deadline <= item.deadline) break;
            expAt(h, i, h[parent]);
            i = parent;
        }
        expAt(h, i, item);
    }

    fn expSiftDown(h: []*Node, start: usize) void {
        var i = start;
        const item = h[i];
        while (true) {
            var child = i * 2 + 1;
            if (child >= h.len) break;
            if (child + 1 < h.len and h[child + 1].deadline < h[child].deadline) child += 1;
            if (item.deadline <= h[child].deadline) break;
            expAt(h, i, h[child]);
            i = child;
        }
        expAt(h, i, item);
    }

    fn expPush(self: *Cache, n: *Node, deadline: i64) bool {
        n.deadline = deadline;
        self.exp.append(self.alloc, n) catch return false;
        expAt(self.exp.items, self.exp.items.len - 1, n);
        expSiftUp(self.exp.items, self.exp.items.len - 1);
        return true;
    }

    fn expRemove(self: *Cache, n: *Node) void {
        if (n.exp_idx == Node.not_queued) return;
        const i: usize = n.exp_idx;
        n.exp_idx = Node.not_queued;
        const last = self.exp.items[self.exp.items.len - 1];
        self.exp.items.len -= 1;
        if (i >= self.exp.items.len) return;
        expAt(self.exp.items, i, last);
        if (i > 0 and last.deadline < self.exp.items[(i - 1) / 2].deadline) {
            expSiftUp(self.exp.items, i);
        } else {
            expSiftDown(self.exp.items, i);
        }
    }

    /// Re-file `n` after a rewrite changed its TTL (in either direction, so
    /// this sifts both ways).
    fn expUpdate(self: *Cache, n: *Node, now_ns: i64, ttl_ns: i64) void {
        if (ttl_ns <= 0) return self.expRemove(n);
        const deadline = now_ns +| ttl_ns;
        if (n.exp_idx == Node.not_queued) {
            _ = self.expPush(n, deadline); // OOM: entry simply loses expired-first priority
            return;
        }
        const i: usize = n.exp_idx;
        n.deadline = deadline;
        if (i > 0 and deadline < self.exp.items[(i - 1) / 2].deadline) {
            expSiftUp(self.exp.items, i);
        } else {
            expSiftDown(self.exp.items, i);
        }
    }

    /// Key of the least-recently-used entry within `region`, or null.
    /// O(1): the heap root. Was a full-map scan.
    fn regionLruKey(self: *Cache, region: Region) ?[]const u8 {
        const h = self.lru[@intFromEnum(region)].items;
        if (h.len == 0) return null;
        self.maintenance_visits += 1;
        return h[0].key;
    }

    /// Key of a TTL-expired entry, or null (expired entries are free wins —
    /// evicted before any frequency logic runs). O(1): the expiry heap's root
    /// is the soonest deadline, so if it has not passed, none has. Was a
    /// full-map scan on every single insert, TTLs in use or not.
    fn findExpiredKey(self: *Cache, now_ns: i64) ?[]const u8 {
        if (self.exp.items.len == 0) return null;
        self.maintenance_visits += 1;
        const first = self.exp.items[0];
        // Same predicate as the scan it replaces: `(now - inserted) > ttl`.
        return if (now_ns > first.deadline) first.key else null;
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
            if (!self.lruMove(e.node, .window, .probation)) break;
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
            if (!self.lruMove(e.node, .protected, .probation)) break;
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
            _ = self.dropKey(k);
            self.stats.evictions += 1;
            return true;
        }
        const cand = self.regionLruKey(.window) orelse {
            // no window entries — evict straight from the main region
            const vk = self.regionLruKey(.probation) orelse
                self.regionLruKey(.protected) orelse return false;
            _ = self.dropKey(vk);
            self.stats.evictions += 1;
            return true;
        };
        const victim = self.regionLruKey(.probation) orelse
            self.regionLruKey(.protected) orelse {
            // main region empty — plain LRU within the window
            _ = self.dropKey(cand);
            self.stats.evictions += 1;
            return true;
        };
        if (self.admit(cand, victim)) {
            _ = self.dropKey(victim);
            const e = self.map.getPtr(cand).?;
            if (self.lruMove(e.node, .window, .probation)) {
                e.region = .probation;
                self.window_count -= 1;
                self.probation_count += 1;
                self.stats.admissions += 1;
            } else {
                // OOM re-indexing the winner; drop it rather than leave the
                // cache over its cap. Same outcome shape as a rejection.
                _ = self.dropKey(cand);
                self.stats.rejections += 1;
            }
        } else {
            _ = self.dropKey(cand);
            self.stats.rejections += 1;
        }
        self.stats.evictions += 1;
        return true;
    }
};

// ── tests (deterministic: injected now_ns + generation, no real clock) ──────

// Multi-file aggregator (CONVENTIONS §6.3, the dark-tests rule): a bare
// `pub const Sharded = @import("sharded.zig").Sharded` does NOT pull that
// file's tests into the test binary.
test {
    _ = @import("sharded.zig");
}

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
    // CONTROL: check residency directly, BEFORE any `get`. `get("exp", 100, …)`
    // returns null for an expired entry whether or not it was evicted (it drops
    // it lazily), so a `get`-based assertion alone cannot fail here.
    try testing.expect(!c.map.contains("exp")); // physically gone, not just stale
    try testing.expect(c.map.contains("lru"));
    try testing.expect(c.map.contains("new"));
    // CONTROL: it left via the expired-first branch, not the frequency contest.
    // Without this the test passes even with expired-first removed: "exp" is
    // also the window-LRU candidate and loses the admission gate anyway, so the
    // surviving/evicted set is identical — only these counters tell them apart.
    try testing.expectEqual(@as(u64, 0), c.stats.rejections);
    try testing.expectEqual(@as(u64, 0), c.stats.admissions);
    // ...and by eviction, not by a lazy TTL drop on read.
    try testing.expectEqual(@as(u64, 0), c.stats.expired);

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

// ── borrow seam ─────────────────────────────────────────────────────────────

test "borrow: a pinned entry is never chosen as an eviction victim" {
    // A one-entry cache makes the choice forced and frequency-free: the
    // pinned entry is simply not in the window heap victim selection reads,
    // so the *incoming* entry is dropped instead of the borrowed one.
    var c = testCache(1 << 20, 1);
    defer c.deinit();
    c.put("hot", "AAAA", 0, 0, 0);

    const b = c.pin("hot", 0, 0).?;
    try testing.expectEqualStrings("AAAA", b.bytes);
    try testing.expectEqual(@as(usize, 1), c.stats.pinned);

    for (0..64) |i| {
        var k: [8]u8 = undefined;
        c.put(std.fmt.bufPrint(&k, "cold{d}", .{i}) catch unreachable, "BBBB", 0, 0, 0);
    }
    // Still resident, still its own bytes.
    try testing.expectEqualStrings("AAAA", c.get("hot", 0, 0).?);
    try testing.expectEqualStrings("AAAA", b.bytes);

    c.release(b);
    try testing.expectEqual(@as(usize, 0), c.stats.pinned);
    // Released = an ordinary candidate again: the next insert can take it.
    c.put("evictor", "CCCC", 0, 0, 0);
    try testing.expect(c.get("hot", 0, 0) == null);
    try testing.expectEqual(@as(usize, 1), c.stats.entries);
}

test "borrow: overwrite, remove and clear park a borrowed value instead of freeing it" {
    var c = testCache(1 << 20, 16);
    defer c.deinit();

    // 1) put over a borrowed key: the borrow keeps its snapshot, and the
    //    cache is NOT left serving the old bytes.
    c.put("k", "old", 0, 0, 0);
    const b1 = c.pin("k", 0, 0).?;
    c.put("k", "new", 0, 0, 0);
    try testing.expectEqualStrings("old", b1.bytes);
    try testing.expectEqualStrings("new", c.get("k", 0, 0).?);
    c.release(b1);
    try testing.expectEqualStrings("new", c.get("k", 0, 0).?); // the live entry is untouched

    // 2) remove of a borrowed key really removes it (lookup fails at once)
    //    while the borrower keeps reading.
    const b2 = c.pin("k", 0, 0).?;
    try testing.expect(c.remove("k"));
    try testing.expect(c.get("k", 0, 0) == null);
    try testing.expectEqualStrings("new", b2.bytes);
    c.release(b2);

    // 3) clear() with a borrow outstanding still empties the cache.
    c.put("a", "one", 0, 0, 0);
    c.put("b", "two", 0, 0, 0);
    const b3 = c.pin("a", 0, 0).?;
    c.clear();
    try testing.expectEqual(@as(usize, 0), c.stats.entries);
    try testing.expect(c.get("a", 0, 0) == null);
    try testing.expectEqualStrings("one", b3.bytes);
    c.release(b3); // frees the parked value — a leak here fails the test
    try testing.expectEqual(@as(usize, 0), c.stats.pinned);
}

test "borrow: reserve fills cache storage in place, and nested borrows are counted" {
    var c = testCache(1 << 20, 16);
    defer c.deinit();

    const f = c.reserve("page", 8, 0, 0, 0).?;
    @memcpy(f.bytes, "12345678");
    const b = c.commit(f);
    try testing.expectEqualStrings("12345678", c.get("page", 0, 0).?);
    // The value the cache serves IS the storage we filled — no copy happened.
    try testing.expectEqual(c.get("page", 0, 0).?.ptr, b.bytes.ptr);

    // Two live borrows of one entry: only the last release un-pins it.
    const b2 = c.pin("page", 0, 0).?;
    try testing.expectEqual(@as(usize, 1), c.stats.pinned); // one *entry*, two borrows
    c.release(b);
    try testing.expectEqual(@as(usize, 1), c.stats.pinned);
    c.release(b2);
    try testing.expectEqual(@as(usize, 0), c.stats.pinned);
    try testing.expectEqualStrings("12345678", c.get("page", 0, 0).?);

    // A discarded reservation never becomes visible.
    const f2 = c.reserve("ghost", 8, 0, 0, 0).?;
    c.discard(f2);
    try testing.expect(c.get("ghost", 0, 0) == null);
    try testing.expectEqual(@as(usize, 0), c.stats.pinned);
}

test "borrow: a pinned entry with a TTL is not expired out from under the borrower" {
    var c = testCache(1 << 20, 16);
    defer c.deinit();
    c.put("k", "v", 0, 1000, 0);
    const b = c.pin("k", 0, 0).?;
    // Well past the deadline: the entry must leave the lookup path...
    try testing.expect(c.get("k", 5000, 0) == null);
    // ...but its bytes are still the borrower's.
    try testing.expectEqualStrings("v", b.bytes);
    c.release(b);
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

// ── write-behind seam: on-evict callback + dirty-set ────────────────────────
// The hook fires the instant before the value's memory is freed, so its
// key/value must be copied out (fixed buffers, same pattern as other
// modules' test sinks — see aaa-gate's `Sink`) rather than held as a slice.

const EvictSink = struct {
    const Rec = struct {
        key_buf: [24]u8 = undefined,
        key_len: usize = 0,
        val_buf: [24]u8 = undefined,
        val_len: usize = 0,
        dirty: bool = false,
        reason: EvictReason = .evicted,

        fn key(r: *const Rec) []const u8 {
            return r.key_buf[0..r.key_len];
        }
        fn val(r: *const Rec) []const u8 {
            return r.val_buf[0..r.val_len];
        }
    };
    recs: [16]Rec = undefined,
    len: usize = 0,

    fn hook(ctx: ?*anyopaque, key: []const u8, value: []const u8, dirty: bool, reason: EvictReason) void {
        const self: *EvictSink = @ptrCast(@alignCast(ctx.?));
        var r: Rec = .{ .dirty = dirty, .reason = reason };
        @memcpy(r.key_buf[0..key.len], key);
        r.key_len = key.len;
        @memcpy(r.val_buf[0..value.len], value);
        r.val_len = value.len;
        self.recs[self.len] = r;
        self.len += 1;
    }
};

test "on-evict fires on W-TinyLFU eviction with correct key/value/dirty, and NOT on a plain hit/miss" {
    var sink: EvictSink = .{};
    var c = Cache.init(testing.allocator, .{
        .max_bytes = 1 << 20,
        .max_entries = 2,
        .on_evict = EvictSink.hook,
        .on_evict_ctx = &sink,
    });
    defer c.deinit();
    c.put("a", "1", 0, 0, 0);
    c.put("b", "2", 0, 0, 0);
    _ = c.get("a", 10, 0); // touch a → b becomes LRU
    _ = c.get("missing", 10, 0); // positive control: a miss must not fire the hook
    try testing.expectEqual(@as(usize, 0), sink.len); // nothing fired yet — just hits/misses
    c.put("cc", "3", 20, 0, 0); // over cap → evicts b (see "entry-count eviction is LRU")
    try testing.expectEqual(@as(usize, 1), sink.len);
    const r = &sink.recs[0];
    try testing.expectEqualStrings("b", r.key());
    try testing.expectEqualStrings("2", r.val());
    try testing.expect(r.dirty); // put'd, never persisted
    try testing.expectEqual(EvictReason.evicted, r.reason);
}

test "on-evict fires on replacement with the outgoing (old) key/value/dirty" {
    var sink: EvictSink = .{};
    var c = Cache.init(testing.allocator, .{
        .max_bytes = 1 << 20,
        .max_entries = 16,
        .on_evict = EvictSink.hook,
        .on_evict_ctx = &sink,
    });
    defer c.deinit();
    c.put("k", "aaaa", 0, 0, 0);
    try testing.expect(c.markClean("k")); // simulate: already persisted
    c.put("k", "bb", 1, 0, 0); // overwrite
    try testing.expectEqual(@as(usize, 1), sink.len);
    const r = &sink.recs[0];
    try testing.expectEqualStrings("k", r.key());
    try testing.expectEqualStrings("aaaa", r.val()); // the value that just got overwritten
    try testing.expect(!r.dirty); // it had been marked clean before the overwrite
    try testing.expectEqual(EvictReason.replaced, r.reason);
    try testing.expectEqualStrings("bb", c.get("k", 2, 0).?); // new value unaffected
}

test "on-evict fires once per entry on clear, and not at all when unset" {
    var sink: EvictSink = .{};
    var c = Cache.init(testing.allocator, .{
        .max_bytes = 1 << 20,
        .max_entries = 16,
        .on_evict = EvictSink.hook,
        .on_evict_ctx = &sink,
    });
    defer c.deinit();
    c.put("a", "1", 0, 0, 0);
    c.put("b", "22", 0, 0, 0);
    c.clear();
    try testing.expectEqual(@as(usize, 2), sink.len);
    var saw_a = false;
    var saw_b = false;
    for (sink.recs[0..sink.len]) |*r| {
        try testing.expectEqual(EvictReason.cleared, r.reason);
        try testing.expect(r.dirty); // neither was ever marked clean
        if (std.mem.eql(u8, r.key(), "a")) {
            try testing.expectEqualStrings("1", r.val());
            saw_a = true;
        }
        if (std.mem.eql(u8, r.key(), "b")) {
            try testing.expectEqualStrings("22", r.val());
            saw_b = true;
        }
    }
    try testing.expect(saw_a and saw_b);
}

test "remove: drops exactly the named key, leaves siblings untouched, no-ops on absent" {
    var c = testCache(1 << 20, 16);
    defer c.deinit();
    c.put("a", "1", 0, 0, 0);
    c.put("b", "22", 0, 0, 0);
    try testing.expectEqual(@as(usize, 2), c.stats.entries);
    try testing.expectEqual(@as(usize, 3), c.bytes);

    try testing.expect(c.remove("a")); // present → true, removed
    try testing.expect(!c.map.contains("a")); // physically gone
    try testing.expect(c.map.contains("b")); // sibling untouched
    try testing.expectEqual(@as(usize, 1), c.stats.entries);
    try testing.expectEqual(@as(usize, 2), c.bytes); // only "b"'s 2 bytes remain
    try testing.expect(c.get("a", 1, 0) == null); // truly gone, not just stale
    try testing.expectEqualStrings("22", c.get("b", 1, 0).?);

    try testing.expect(!c.remove("a")); // already absent → false, harmless no-op
    try testing.expect(!c.remove("never-existed"));
    try testing.expectEqual(@as(usize, 1), c.stats.entries); // unchanged by the no-ops
}

test "remove: fires on_evict with reason .evicted and frees the entry's memory (no leak)" {
    var sink: EvictSink = .{};
    var c = Cache.init(testing.allocator, .{
        .max_bytes = 1 << 20,
        .max_entries = 16,
        .on_evict = EvictSink.hook,
        .on_evict_ctx = &sink,
    });
    defer c.deinit();
    c.put("k", "value", 0, 0, 0);
    try testing.expectEqual(@as(usize, 0), sink.len); // put alone must not fire it

    try testing.expect(c.remove("k"));
    try testing.expectEqual(@as(usize, 1), sink.len);
    try testing.expectEqualStrings("k", sink.recs[0].key());
    try testing.expectEqualStrings("value", sink.recs[0].val());
    try testing.expectEqual(EvictReason.evicted, sink.recs[0].reason);

    try testing.expect(!c.remove("k")); // second call: already gone → no double-fire
    try testing.expectEqual(@as(usize, 1), sink.len);
}

test "remove: a removed key's slot can be reused by a fresh put (heap index not left dangling)" {
    // Targets the index-node bookkeeping `remove` shares with capacity
    // eviction: after removing a key, inserting a new key must land cleanly
    // in the region heaps rather than tripping over a stale node reference.
    var c = testCache(1 << 20, 4);
    defer c.deinit();
    c.put("a", "1", 0, 0, 0);
    c.put("b", "2", 1, 0, 0);
    c.put("c", "3", 2, 0, 0);
    try testing.expect(c.remove("b"));
    c.put("d", "4", 3, 0, 0);
    c.put("e", "5", 4, 0, 0); // more churn to exercise the heaps post-removal
    try testing.expect(c.get("a", 5, 0) != null);
    try testing.expect(c.get("b", 5, 0) == null);
    try testing.expect(c.get("c", 5, 0) != null);
    try testing.expect(c.get("d", 5, 0) != null);
    try testing.expect(c.get("e", 5, 0) != null);
}

test "dirty bit: set on put, cleared by markClean; markClean on an absent key is a harmless no-op" {
    var c = testCache(1 << 20, 16);
    defer c.deinit();
    try testing.expect(!c.isDirty("k")); // absent → false, not a crash
    c.put("k", "v", 0, 0, 0);
    try testing.expect(c.isDirty("k")); // a fresh write is dirty
    try testing.expect(c.markClean("k")); // found → true
    try testing.expect(!c.isDirty("k")); // cleared
    try testing.expect(!c.markClean("nope")); // absent → false
    c.put("k", "v2", 1, 0, 0); // an update re-dirties the entry
    try testing.expect(c.isDirty("k"));
}

test "drainDirty visits exactly the dirty entries, skipping clean ones" {
    var c = testCache(1 << 20, 16);
    defer c.deinit();
    c.put("a", "1", 0, 0, 0);
    c.put("b", "2", 0, 0, 0);
    c.put("c", "3", 0, 0, 0);
    try testing.expect(c.markClean("b")); // only a and c stay dirty

    const Collector = struct {
        seen: [8][]const u8 = undefined,
        len: usize = 0,
        fn hook(ctx: ?*anyopaque, key: []const u8, value: []const u8) void {
            _ = value;
            const self: *@This() = @ptrCast(@alignCast(ctx.?));
            self.seen[self.len] = key;
            self.len += 1;
        }
    };
    var collector: Collector = .{};
    c.drainDirty(Collector.hook, &collector);
    try testing.expectEqual(@as(usize, 2), collector.len);
    var saw_a = false;
    var saw_c = false;
    for (collector.seen[0..collector.len]) |k| {
        try testing.expect(!std.mem.eql(u8, k, "b")); // the clean entry must not appear
        if (std.mem.eql(u8, k, "a")) saw_a = true;
        if (std.mem.eql(u8, k, "c")) saw_c = true;
    }
    try testing.expect(saw_a and saw_c);
}

test "an evicted dirty entry is reported dirty to on_evict — the write-behind safety net" {
    var sink: EvictSink = .{};
    var c = Cache.init(testing.allocator, .{
        .max_bytes = 1 << 20,
        .max_entries = 2,
        .on_evict = EvictSink.hook,
        .on_evict_ctx = &sink,
    });
    defer c.deinit();
    c.put("a", "1", 0, 0, 0);
    c.put("b", "2", 0, 0, 0); // never markClean'd — still dirty
    _ = c.get("a", 10, 0); // touch a → b becomes LRU
    c.put("cc", "3", 20, 0, 0); // over cap → evicts b
    try testing.expectEqual(@as(usize, 1), sink.len);
    try testing.expectEqualStrings("b", sink.recs[0].key());
    try testing.expect(sink.recs[0].dirty); // coordinator must still persist it
}

test "a clean (already-persisted) entry is reported non-dirty to on_evict on the same eviction path" {
    var sink: EvictSink = .{};
    var c = Cache.init(testing.allocator, .{
        .max_bytes = 1 << 20,
        .max_entries = 2,
        .on_evict = EvictSink.hook,
        .on_evict_ctx = &sink,
    });
    defer c.deinit();
    c.put("a", "1", 0, 0, 0);
    c.put("b", "2", 0, 0, 0);
    try testing.expect(c.markClean("b")); // already persisted before eviction
    _ = c.get("a", 10, 0); // touch a → b stays LRU
    c.put("cc", "3", 20, 0, 0); // over cap → evicts b
    try testing.expectEqual(@as(usize, 1), sink.len);
    try testing.expect(!sink.recs[0].dirty);
}

test "with on_evict unset, eviction/replace/clear behave exactly as before (no crash, no-op hook)" {
    var c = testCache(1 << 20, 2);
    defer c.deinit();
    c.put("a", "1", 0, 0, 0);
    c.put("b", "2", 0, 0, 0);
    c.put("cc", "3", 20, 0, 0); // triggers an eviction path with on_evict == null
    c.put("cc", "33", 21, 0, 0); // triggers the replace path with on_evict == null
    try testing.expect(c.isDirty("cc"));
    try testing.expect(c.markClean("cc"));
    c.clear(); // triggers the clear path with on_evict == null
    try testing.expectEqual(@as(usize, 0), c.stats.entries);
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

test "victim selection is O(1): eviction bookkeeping does not scan the map" {
    // The defect: `maintain` ran on every insert and `evictStep` did up to
    // three full-map linear scans (`findExpiredKey`, `regionLruKey` twice), so
    // one page fill cost O(max_entries). Measured on `pagecache`, 20 000 fills:
    // 7.3 us/fill at 64 pages rising to 94.3 us/fill at 4096 — at a 16 MiB pool
    // the bookkeeping for one miss cost more CPU than the NVMe read it avoided.
    //
    // Judged by a counter rather than a clock: `maintenance_visits` counts the
    // entries those two functions examine. Flat per insert = O(1) selection;
    // growing with capacity = the scan is back.
    const val = [_]u8{0xcd} ** 64;
    const rounds: usize = 8; // 8x capacity of distinct keys → steady-state eviction

    var per_put: [2]f64 = undefined;
    for ([_]usize{ 64, 4096 }, 0..) |cap, slot| {
        var c = testCache(cap * val.len, cap);
        defer c.deinit();
        const puts = cap * rounds;
        var i: usize = 0;
        while (i < puts) : (i += 1) {
            var key: [8]u8 = undefined;
            std.mem.writeInt(u64, &key, i, .little);
            c.put(&key, &val, 0, 0, 0);
        }
        // The workload really did evict, i.e. the eviction path was exercised.
        try testing.expect(c.stats.evictions >= puts - cap);
        per_put[slot] = @as(f64, @floatFromInt(c.maintenance_visits)) /
            @as(f64, @floatFromInt(puts));
    }

    // 64x the capacity must not cost meaningfully more per insert. A full-map
    // scan would make this ratio ~64; the slack is for the region heaps being
    // occasionally empty, which skips a visit entirely.
    try testing.expect(per_put[1] <= per_put[0] * 2.0);
    // ...and the bookkeeping actually happens (a zero counter would satisfy
    // the ratio above for the wrong reason).
    try testing.expect(per_put[0] >= 1.0);
}

test "expired-first eviction still finds the expired entry among many live ones" {
    // The expiry heap replaced a full-map scan, so pin the behaviour it has to
    // reproduce: one TTL entry buried among entries that never expire is still
    // the one taken, and it is taken by the expired-first branch (rejections
    // and admissions stay at zero) rather than by the frequency contest.
    var c = testCache(1 << 20, 8);
    defer c.deinit();
    var i: usize = 0;
    while (i < 7) : (i += 1) {
        var key: [8]u8 = undefined;
        std.mem.writeInt(u64, &key, i, .little);
        c.put(&key, "live", 0, 0, 0); // no TTL
    }
    c.put("doomed", "x", 10, 5, 0); // expires at t = 15
    // Over the entry cap at t = 100: the expired one must go, not an LRU one.
    c.put("newcomer", "y", 100, 0, 0);

    try testing.expect(!c.map.contains("doomed"));
    try testing.expect(c.map.contains("newcomer"));
    var zero_key: [8]u8 = undefined;
    std.mem.writeInt(u64, &zero_key, 0, .little);
    try testing.expect(c.map.contains(&zero_key)); // the true LRU survived
    try testing.expectEqual(@as(u64, 0), c.stats.rejections);
    try testing.expectEqual(@as(u64, 0), c.stats.admissions);
    try testing.expectEqual(@as(u64, 1), c.stats.evictions);
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
