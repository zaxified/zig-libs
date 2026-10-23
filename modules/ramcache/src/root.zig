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
//!     logic). Recency order is an **intrusive doubly linked queue per
//!     region** (Caffeine's access-order deque; a min-heap over TTL deadlines
//!     beside it), so picking a victim is O(1) to look at and O(1) to
//!     maintain (the expiry heap O(log n)) — never a scan. It used to be a
//!     full-map scan per region, run up to three times per insert, which made one insert O(max_entries): the audited
//!     `pagecache` cost 93.5 us per 4 KiB page fill at a 4096-page pool,
//!     more CPU than the NVMe read it was avoiding, against 0.8 us now.
//!     A buffer pool is exactly the "modest entry counts" assumption's
//!     counterexample, so the assumption is gone rather than restated.
//!   * **Time-to-idle, read-through, adaptive window (all opt-in, 2026-10-11):**
//!     `Options.idle_ttl_ns` expires an entry that has not been read for that
//!     long (effective deadline = earlier of write TTL and idle deadline, kept
//!     in the same expiry heap); `getOrLoad` is the read-through call
//!     (`Sharded.getOrLoad` is single-flight); `Options.adaptive_window` lets a
//!     hill climber resize the admission window. Defaults keep every earlier
//!     behaviour.
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
const builtin = @import("builtin");

/// The internally-synchronized wrapper: N independent `Cache` instances, one
/// lock each, picked by a hash of the key. Its own doc comment carries the
/// full contract — the value handoff, the per-shard eviction semantics, and
/// what the aggregate operations do and do not guarantee.
pub const Sharded = @import("sharded.zig").Sharded;

pub const meta = .{
    // The module catalog's one-line entry. This IS the source of truth:
    // README.md's table is rendered from it by `zig build gen-catalog`.
    .doc = "Bounded in-memory cache — W-TinyLFU admission/eviction, TTL, generation invalidation; sharded thread-safe wrapper.",
    // The catalog's Platform cell. Prose, because it carries nuance the
    // `platform` enum below cannot -- "any (packer: linux)", "amd64 asm +
    // portable fallback". Rendered by `gen-catalog` alongside `doc`.
    .platform_note = "any",
    .targets = .{.linux64},
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
    /// Times the index was rebuilt to shed tombstones (see `Cache.removals`).
    rehashes: u64 = 0,
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
    /// Time-to-idle (Caffeine `expireAfterAccess`, otter `ExpiryAccessing`):
    /// an entry not read for this long is expired, whatever its write-TTL says.
    /// A hit (`get`, `pin`, `Sharded.getBuf`) and a `put` both refresh the idle
    /// deadline; the effective deadline of an entry is
    /// `min(inserted + ttl, last access + idle_ttl_ns)`. Idle expiry counts in
    /// `Stats.expired`, like a write-TTL expiry. `<= 0` = off (the default),
    /// treated exactly like `default_ttl_ns <= 0`: no assert, no clamp, simply
    /// "never expires by idleness". A `release` does not count as an access
    /// (it has no clock); the `pin` that opened the borrow did.
    idle_ttl_ns: i64 = 0,
    /// Adaptive admission window (Caffeine/otter hill climber). Off by
    /// default, which keeps the fixed ~1 % window and every existing behaviour.
    /// On: the hit rate is sampled over `10 x max_entries` lookups, and the
    /// window share is stepped up or down by a decaying step toward the
    /// better hit rate, bounded to `[1 entry, 80 % of max_entries]`. See
    /// `Cache.climbIfDue`. The step is `int(0.0625 x max_entries)` entries
    /// first, so a cache under ~16 entries never moves its window.
    adaptive_window: bool = false,
};

/// Why `getOrLoad` produced no value. `OutOfMemory` is the allocator failing
/// (the caller's `gpa` for the returned copy, or the in-flight table);
/// `LoadFailed` is whatever the `Loader` reported -- the cache stays agnostic
/// about *why*, a caller that needs the reason keeps it in its `ctx`.
pub const LoadError = error{ LoadFailed, OutOfMemory };

/// The value producer handed to `getOrLoad`.
pub const Loader = struct {
    ctx: ?*anyopaque,
    /// Produce the value for `key` into a `gpa`-owned slice (the allocator
    /// `getOrLoad` was given; the cache or the caller frees it). `Sharded`
    /// calls it at most once per key at a time and WITHOUT holding the shard
    /// lock, but a loader must not re-enter `getOrLoad` for the same key from
    /// the same thread: it would wait for itself, forever. (Like `on_evict`'s
    /// "must not suspend": a documented contract, not a detected error.)
    load: *const fn (ctx: ?*anyopaque, gpa: std.mem.Allocator, key: []const u8) LoadError![]u8,
};

/// 4-bit Count-Min Sketch + doorkeeper with periodic aging, per the TinyLFU
/// paper (Einziger & Friedman). Tracks the *recent* access frequency of keys
/// in a fixed allocation sized to the cache capacity:
///   * `depth` 4-bit counters per key (16 packed per u64), all inside ONE
///     64-byte block picked by the key's hash — Caffeine's block layout, so a
///     record touches one cache line of counters, not `depth` scattered ones.
///     Within the block, counter `i` lives in word `2i` or `2i+1`, nibble
///     picked by a byte of the second hash. Estimate = min over the `depth`
///     counters (CMS never underestimates).
///   * A doorkeeper bit set absorbs the first occurrence of each key, so
///     one-hit wonders never touch the counters; its bit adds 1 to estimates.
///   * Aging: after ~10× capacity recorded samples, every counter is halved
///     and the doorkeeper cleared, so stale popularity decays away.
/// The layout was rows × width with one counter per row (5 cache lines per
/// record with the doorkeeper); on a 16-shard cache the sketches outgrow L1
/// and those loads were the largest part of a miss (bench 2026-10-11).
const FrequencySketch = struct {
    counters: []align(64) u64, // blocks of 8 words, 4-bit counters
    doorkeeper: []u64, // bloom-style bit set, one bit per key hash
    block_mask: usize, // number of 8-word blocks - 1 (power of two)
    dk_bits: usize, // doorkeeper size in bits, power of two
    samples: u64 = 0,
    sample_limit: u64,

    const depth = 4;
    const words_per_block = 8;
    const hash_seed: u64 = 0x2545F4914F6CDD1D;

    fn init(alloc: std.mem.Allocator, capacity: usize) !FrequencySketch {
        // 8 × capacity counter columns of `depth` counters each (power of
        // two): with the sample window capped at ~10× capacity, the expected
        // per-counter collision noise stays ~1, so a cold key cannot
        // impersonate a hot one even in a tiny cache. 2 bytes per column.
        const base = try std.math.ceilPowerOfTwo(usize, @max(capacity, 16));
        const width = base * 8;
        const words = depth * width / 16;
        const counters = try alloc.alignedAlloc(u64, .@"64", words);
        errdefer alloc.free(counters);
        @memset(counters, 0);
        const dk_bits = width * 8; // 8 doorkeeper bits per counter column
        const doorkeeper = try alloc.alloc(u64, dk_bits / 64);
        @memset(doorkeeper, 0);
        return .{
            .counters = counters,
            .doorkeeper = doorkeeper,
            .block_mask = words / words_per_block - 1,
            .dk_bits = dk_bits,
            .sample_limit = @as(u64, base) * 10, // ~10× capacity, per the paper
        };
    }

    fn deinit(self: *FrequencySketch, alloc: std.mem.Allocator) void {
        alloc.free(self.counters);
        alloc.free(self.doorkeeper);
    }

    /// One pass over the key, the second hash re-mixed from the first
    /// (splitmix64's finalizer), as Caffeine re-spreads one hash. Was two
    /// full Wyhash passes.
    fn hashPair(key: []const u8) [2]u64 {
        const h0 = std.hash.Wyhash.hash(hash_seed, key);
        var z = h0 +% 0x9E3779B97F4A7C15;
        z = (z ^ (z >> 30)) *% 0xBF58476D1CE4E5B9;
        z = (z ^ (z >> 27)) *% 0x94D049BB133111EB;
        return .{ h0, z ^ (z >> 31) };
    }

    /// Word index and nibble shift of the key's counter `i` (< depth).
    inline fn slot(self: *const FrequencySketch, h: [2]u64, i: usize) struct { usize, u6 } {
        const block: usize = @intCast((h[0] >> 32) & self.block_mask);
        const b: u64 = h[1] >> @intCast(i * 8);
        const word = block * words_per_block + 2 * i + @as(usize, @intCast(b & 1));
        return .{ word, @intCast(((b >> 1) & 15) * 4) };
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
            for (0..depth) |i| {
                const word, const shift = self.slot(h, i);
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
        for (0..depth) |i| {
            const word, const shift = self.slot(h, i);
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

    // Hill-climber constants, from otter v2.3.0 `policy.go:30-35` (the same
    // values Caffeine uses). Kept verbatim: restart threshold 0.05, initial and
    // restart step 6.25 % of the capacity, decay 0.98 per sample.
    const hill_restart_threshold: f64 = 0.05;
    const hill_step_percent: f64 = 0.0625;
    const hill_step_decay: f64 = 0.98;
    /// Sample length in lookups, as a multiple of `max_entries` (otter takes
    /// its sketch's `sampleSize`, `sketch.go:63-65`, which is `10 x maximum`).
    const hill_sample_factor = 10;

    /// Per-entry node: the entry itself (`entry`), its key bytes, and the
    /// links that make victim selection O(1) instead of a full-map scan.
    ///
    /// One heap allocation per entry, the key bytes trailing the struct
    /// (`createNode`), and the map holds only `*Node` (Caffeine's node-in-map
    /// shape). A `*Node` is stable across rehashes, so the region queues and
    /// the expiry heap link to it directly. A lookup is the map's metadata,
    /// its key slot, then this node -- three dependent loads on three memory
    /// pages. It used to be five (metadata, key slot, a separately allocated
    /// key copy, the map's value slot, then the node): on a resident
    /// `pagecache` scan each was a cache and TLB miss per leaf, the largest
    /// part of a borrow (kvtree scan vs bbolt, 2026-10-11).
    const Node = struct {
        /// The trailing key bytes while the entry is in the map; `&.{}` once
        /// it is doomed (`parkNode`), so a stale queue or heap reference can
        /// never name a key the map holds again.
        key: []const u8,
        /// Length of the trailing key bytes, for `destroyNode` (`key` is
        /// emptied when the node is doomed, the allocation is not).
        key_len: usize,
        /// The entry's fields. `entry.node` points back here, so code holding
        /// an `*Entry` reaches its links without another lookup.
        entry: Entry,
        /// Logical time of the node's last append to its region queue
        /// (`lruPush`); ticks rise strictly from a queue's head to its tail.
        /// The queue order itself is the recency order — `tick` is what the
        /// tests check it against.
        tick: u64,
        /// Effective expiry instant (`Cache.deadlineFor`: the earlier of the
        /// write-TTL deadline and the idle deadline) — the ordering key of the
        /// expiry heap. Meaningful only while `exp_idx != not_queued`.
        deadline: i64 = 0,
        /// Links in `Cache.lru[@backingInt(region)]`, meaningful
        /// only while `queued`. Not queued while the entry is deliberately out
        /// of the index (borrowed — see `pins` — or doomed).
        prev: ?*Node = null,
        next: ?*Node = null,
        queued: bool = false,
        /// W-TinyLFU segment the entry lives in. On the node, not the map
        /// `Entry`, so moving a queue head between regions never looks the
        /// key up again (it used to: one hash per SLRU demotion).
        region: Region = .window,
        /// Position in `Cache.exp`, or `not_queued` for an entry with no
        /// deadline (no TTL and no idle TTL) or while borrowed.
        exp_idx: u32 = not_queued,
        /// Live borrow count: `pin`/`reserve` increment it, `release`
        /// decrements it. A node with `pins > 0` is taken out of its region
        /// and expiry heaps, and victim selection only ever reads a heap
        /// root — so a borrowed entry is normally never even *considered*,
        /// at zero cost per eviction. `release` puts it back.
        ///
        /// ⚠ Two different properties rest on two different things, and an
        /// earlier version of this comment conflated them:
        ///
        ///   * *No use-after-free* is `dropKeyReason`'s `pins > 0` check,
        ///     which dooms rather than frees. The unlinking is not what
        ///     prevents it.
        ///   * *Eviction still terminates* is the unlinking itself. A node
        ///     that stays in a heap after it is doomed has `key = &.{}`
        ///     (`parkNode`), so `regionLruKey`/`findExpiredKey` hand
        ///     `evictStep` a key the map does not hold and nothing is
        ///     removed. Until `evictStep` grew its progress guard that was an
        ///     unbounded loop in `maintain`; with the guard it is a cache
        ///     stuck over its cap. Neither is a fast-path concern.
        ///
        /// So: do NOT delete the unlinking on the grounds that the suites stay
        /// green. Deleting `expRemove` alone *is* green across `ramcache`,
        /// `pagecache` and `kvtree` — measured — because no test used to reach
        /// the shape; `borrow: a doomed TTL node must not stall eviction`
        /// reaches it, and that test fails when the unlinking goes.
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
        /// False between `reserve` and `commit`: the entry is in the map, but
        /// its bytes are uninitialized, so `get`, `pin` and `drainDirty` treat
        /// it as absent (`lookupFilled`), and `on_evict` stays silent for it
        /// — an entry can die in that window (overwritten, removed,
        /// cleared, TTL-dropped) and its value must not be handed to a
        /// caller's hook, which is the rule `discard` already states for
        /// itself. Every other way of creating an entry writes its value
        /// before publishing it, hence the `true` default.
        filled: bool = true,
        /// The expiry deadline `release` files the node under when its last
        /// borrow ends (`deadlineFor` of the entry's times; `null` = none).
        /// Meaningful only while `pins > 0`. Kept current by everything that
        /// changes those times while the entry is borrowed -- `pin`, `reserve`
        /// and `touchIdle` (an overwrite of a borrowed entry dooms it instead)
        /// -- so `release` re-files the node without looking its key up again:
        /// that second hash lookup was a fifth of a resident `pagecache` borrow
        /// (kvtree scan profile, 2026-10-11).
        pin_deadline: ?i64 = null,

        const not_queued: u32 = std.math.maxInt(u32);
    };

    const Entry = struct {
        value: []u8,
        inserted_ns: i64,
        ttl_ns: i64, // <= 0 → never expire by time
        /// Last read or write, for `Options.idle_ttl_ns`. Written even when
        /// idle expiry is off (one store per hit), so no mode switch exists.
        last_access_ns: i64,
        gen: u64, // 0 → not generation-tied (TTL only)
        /// Write-behind dirty bit: `put` sets it (a write not yet known to
        /// be persisted); the coordinator clears it via `markClean` once it
        /// has durably persisted `value`. Unused by the cache itself —
        /// purely a passenger bit for the caller.
        dirty: bool = false,
        /// The node this entry lives in (`Node.entry`).
        node: *Node,
    };

    /// The map hashes and compares a node by its key bytes.
    const NodeContext = struct {
        pub fn hash(_: NodeContext, n: *Node) u64 {
            return std.hash_map.hashString(n.key);
        }
        pub fn eql(_: NodeContext, a: *Node, b: *Node) bool {
            return std.mem.eql(u8, a.key, b.key);
        }
    };

    /// Looks a node up by a caller's key bytes.
    const KeyAdapter = struct {
        pub fn hash(_: KeyAdapter, k: []const u8) u64 {
            return std.hash_map.hashString(k);
        }
        pub fn eql(_: KeyAdapter, k: []const u8, n: *Node) bool {
            return std.mem.eql(u8, k, n.key);
        }
    };

    alloc: std.mem.Allocator,
    map: std.HashMapUnmanaged(*Node, void, NodeContext, std.hash_map.default_max_load_percentage) = .empty,
    bytes: usize = 0,
    options: Options,
    stats: Stats = .{},
    tick: u64 = 0, // logical clock, bumped on every region-queue append
    window_count: usize = 0,
    probation_count: usize = 0,
    protected_count: usize = 0,
    sketch: ?FrequencySketch = null, // lazily allocated on first access
    sketch_failed: bool = false, // OOM on sketch alloc → degrade to plain LRU
    prng: u64 = 0x9E3779B97F4A7C15, // deterministic LCG for tie-break admission
    /// One intrusive doubly linked queue per region (Caffeine's access-order
    /// deque): `head` is that region's least-recently-used entry, `tail` its
    /// most recent. A hit, an insert, a move between regions and a `release`
    /// all append at the tail, so every operation is O(1) with no allocation.
    /// Was one binary min-heap per region ordered by tick: O(log n) per hit,
    /// one pointer dereference per level, the larger part of a hit's cost
    /// (bench vs otter, 2026-10-11).
    lru: [3]Queue = .{ .{}, .{}, .{} },
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
    /// Entries removed from `map` since its last rebuild. ⛔ std's open-addressing
    /// map leaves a TOMBSTONE per removal and hands the slot back to `available`
    /// (`removeByIndex`: `available += 1`), so a remove-then-insert workload --
    /// which is what a cache under miss pressure IS -- never triggers the grow
    /// that would clear them. The table fills with tombstones until it has no
    /// free slot left, and from then on every lookup of an ABSENT key (the `pin`
    /// before every `reserve`) walks the whole table. Measured on pagecache over
    /// a flat backend, 4 KiB pages, 93 % misses: 700 000 instructions per access
    /// at a 1 024-entry budget, 92 % of them in the map's probe loop; the same
    /// probe with the rebuild below: see the CHANGELOG. `maintain` rebuilds the
    /// index once this passes a quarter of the capacity.
    removals: u32 = 0,
    /// Current admission-window size in entries while `Options.adaptive_window`
    /// is on (otter `windowMaximum`); unused otherwise (`windowCap` then
    /// derives the fixed ~1 %).
    window_adapt: usize,
    /// Hill-climber sample: lookups that hit / missed since the last climb
    /// (otter `hitsInSample` / `missesInSample`).
    hc_hits: u64 = 0,
    hc_misses: u64 = 0,
    /// Hit rate of the previous sample (otter `previousSampleHitRate`).
    hc_prev_rate: f64 = 0,
    /// Signed step in entries (otter `stepSize`); negative = shrink the window.
    hc_step: f64,
    /// Instrumentation: completed climber samples. Tests read it to prove a
    /// run reached the climber at all.
    climbs: u64 = 0,

    /// ~1% of `max_entries` (min 1) — the fixed admission window.
    fn baseWindow(max_entries: usize) usize {
        if (max_entries == 0) return 0;
        return @max(1, max_entries / 100);
    }

    pub fn init(alloc: std.mem.Allocator, options: Options) Cache {
        return .{
            .alloc = alloc,
            .options = options,
            .window_adapt = baseWindow(options.max_entries),
            .hc_step = -hill_step_percent * @as(f64, @floatFromInt(options.max_entries)),
        };
    }

    pub fn deinit(self: *Cache) void {
        self.clear();
        // Tearing the cache down with borrows still outstanding is a caller
        // bug, but leaking their bytes would only turn it into a second one.
        for (self.doomed.items) |n| {
            self.alloc.free(n.owned);
            self.destroyNode(n);
        }
        self.doomed.deinit(self.alloc);
        self.map.deinit(self.alloc);
        self.exp.deinit(self.alloc);
        if (self.sketch) |*s| s.deinit(self.alloc);
    }

    /// Return the cached value for `key` if it is still fresh (TTL not expired
    /// AND — for generation-tied entries — `entry.gen == cur_gen`). A stale
    /// entry is dropped in passing so its memory is reclaimed (lazy drop — the
    /// only reclamation besides eviction; there is no sweep). `null` = miss
    /// (caller fetches). Pass `cur_gen = 0` for TTL-only lookups.
    /// A hit records the key in the frequency sketch, as every `put` does,
    /// so repeatedly used keys build up admission credit. A miss records
    /// nothing (Caffeine and otter do the same): in the read-through shape the
    /// `put` that follows the miss counts the request once, and a key that is
    /// never stored has no use for credit. Until 2026-10-11 a miss recorded
    /// too — a sketch write per miss, the larger part of a miss's cost.
    /// The returned slice borrows the cache's storage: valid until this key is
    /// replaced, evicted, or the cache is cleared.
    pub fn get(self: *Cache, key: []const u8, now_ns: i64, cur_gen: u64) ?[]const u8 {
        self.climbIfDue();
        const e = self.lookupFilled(key) orelse {
            self.stats.misses += 1;
            self.noteOutcome(false);
            return null;
        };
        const ttl_expired = self.timeExpired(e, now_ns);
        const gen_stale = e.gen != 0 and e.gen != cur_gen;
        if (ttl_expired or gen_stale) {
            self.stats.expired += 1;
            self.stats.misses += 1;
            self.noteOutcome(false);
            _ = self.dropKey(key);
            return null;
        }
        self.noteAccess(key);
        self.noteOutcome(true);
        self.touchIdle(e, now_ns);
        // A borrowed node is out of the queues entirely (Node.pins), so it
        // has no position to move and no region membership to change; it
        // re-enters its queue at the tail on `release`.
        if (e.node.pins == 0) {
            if (e.node.region == .probation) {
                // SLRU promotion: a re-referenced main entry is proven hot
                self.lruMove(e.node, .probation, .protected);
                e.node.region = .protected;
                self.probation_count -= 1;
                self.protected_count += 1;
                self.enforceProtectedCap();
            } else {
                self.lruTouched(e.node.region, e.node);
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
        if (self.entryOf(key)) |e| replace: {
            if (value.len > self.options.max_bytes) {
                // Same single-item ceiling a fresh insert enforces below. It
                // has to be checked HERE too: without it an update-only
                // workload (a fixed key set, written over and over — the
                // session-store / write-behind shape) never takes the insert
                // path again, so `max_bytes` stops being a bound at all.
                //
                // Dropping the entry rather than refusing the write is the
                // same call the pinned branch below makes: keeping the old
                // bytes would serve pre-write data indefinitely, which is the
                // stale-hit class a write-through cache exists to prevent. The
                // key simply becomes absent, so the next `get` misses and the
                // caller refetches. Reason is `.evicted`, not `.replaced` —
                // nothing took the entry's place.
                _ = self.dropKey(key);
                return;
            }
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
            // replace value in place, keep the stored key.
            //
            // A `catch return` here would leave the OLD value in the map and
            // report nothing -- exactly the stale-hit class the `max_bytes`
            // branch above refuses by name, arrived at through the allocator
            // instead. `pagecache`'s write-through refresh calls this after
            // the durable write has already landed, so the resident copy
            // would then be pre-write bytes served as a hit, forever. Absent
            // is a miss; stale is corruption. Drop the key instead.
            const vdup = self.alloc.dupe(u8, value) catch {
                _ = self.dropKey(key);
                return;
            };
            self.fireOnEvict(e.node, key, e.value, e.dirty, .replaced);
            self.bytes -= e.value.len;
            self.alloc.free(e.value);
            const node = e.node; // survives the rewrite: same key, same slot
            // An entry can only be replaced in place when nothing borrows it,
            // and an unfilled reservation is borrowed by definition (`pins`
            // is 1 from birth), so this path never inherits `filled == false`.
            std.debug.assert(node.filled);
            e.* = .{
                .value = vdup,
                .inserted_ns = now_ns,
                .ttl_ns = ttl_ns,
                .gen = gen,
                .dirty = true, // a fresh write, not yet known to be persisted
                .node = node,
                .last_access_ns = now_ns,
            };
            self.lruTouched(e.node.region, node);
            self.expUpdate(node, self.deadlineFor(now_ns, ttl_ns, now_ns));
            self.bytes += vdup.len;
            // A replace can push `bytes` over the cap just as an insert can
            // (a bigger value for the same key), so it owes the same eviction
            // pass. `e` may be dangling once this returns — `maintain` can
            // evict the entry just written — so nothing below may touch it.
            self.maintain(now_ns);
            self.syncStats();
            return;
        }
        if (value.len > self.options.max_bytes) return; // never cache an item larger than the whole cache
        const vdup = self.alloc.dupe(u8, value) catch return;
        const node = self.createNode(key) orelse {
            self.alloc.free(vdup);
            return;
        };
        // Reserve the expiry slot BEFORE the map insert, so that once the
        // entry exists it is guaranteed to be reachable from the index. An
        // entry the index does not know about could never be chosen as a
        // victim. (The region queue is intrusive and needs no reservation.)
        const reserved = blk: {
            if (self.deadlineFor(now_ns, ttl_ns, now_ns) != null)
                self.exp.ensureUnusedCapacity(self.alloc, 1) catch break :blk false;
            self.map.ensureUnusedCapacity(self.alloc, 1) catch break :blk false;
            break :blk true;
        };
        if (!reserved) {
            self.destroyNode(node);
            self.alloc.free(vdup);
            return;
        }
        node.entry = .{
            .value = vdup,
            .inserted_ns = now_ns,
            .ttl_ns = ttl_ns,
            .gen = gen,
            .dirty = true, // a fresh write, not yet known to be persisted
            .node = node,
            .last_access_ns = now_ns,
        };
        self.map.putAssumeCapacityNoClobber(node, {});
        // Capacity was reserved above, so this cannot fail. Called for effect
        // in every build mode; the assert only checks the reservation held.
        self.lruPush(.window, node);
        if (self.deadlineFor(now_ns, ttl_ns, now_ns)) |d| {
            const queued = self.expPush(node, d);
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

    /// Read-through: the cached value for `key` (a copy owned by `gpa`, free it
    /// with `gpa`), or on a miss the value `loader` produces, which is stored
    /// (`put` semantics: admission may decline it, the caller still gets it)
    /// and returned. `cur_gen` is the lookup's current generation, `ttl_ns` and
    /// `gen` describe the entry written on a miss (`Cache.get` / `Cache.put`).
    ///
    /// `Cache` is single-owner, so this is the trivial non-concurrent shape —
    /// no in-flight table, the loader simply runs on the owning thread. It
    /// exists so a caller can switch between `Cache` and `Sharded.getOrLoad`
    /// (which does single-flight) without touching call sites. The loader must
    /// not call back into this cache. A `LoadFailed` leaves the cache as the
    /// miss's `get` left it.
    pub fn getOrLoad(
        self: *Cache,
        gpa: std.mem.Allocator,
        key: []const u8,
        now_ns: i64,
        cur_gen: u64,
        ttl_ns: i64,
        gen: u64,
        loader: Loader,
    ) LoadError![]u8 {
        if (self.get(key, now_ns, cur_gen)) |v| return gpa.dupe(u8, v);
        const loaded = try loader.load(loader.ctx, gpa, key);
        self.put(key, loaded, now_ns, ttl_ns, gen);
        return loaded;
    }

    /// Drop every entry (e.g. a manual cache flush). Keeps map capacity, the
    /// cumulative hit/miss/eviction counters, and the frequency sketch (the
    /// popularity history stays useful across a flush).
    pub fn clear(self: *Cache) void {
        var it = self.map.keyIterator();
        while (it.next()) |np| {
            const n = np.*;
            self.fireOnEvict(n, n.key, n.entry.value, n.entry.dirty, .cleared);
            if (n.pins > 0) {
                // Borrowed: unlink it like every other entry (a `clear` must
                // really leave nothing findable — that is what pagecache's
                // six invalidation guards rest on) but hand the bytes to the
                // borrower rather than freeing them under it.
                self.parkNode(n, n.entry.value);
                continue;
            }
            self.alloc.free(n.entry.value);
            self.destroyNode(n);
        }
        self.map.clearRetainingCapacity();
        self.lru = .{ .{}, .{}, .{} };
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

    /// Remove every resident entry whose key starts with `prefix`; returns how
    /// many were removed. Each removal is exactly `remove`, so a borrowed
    /// entry still becomes unfindable immediately and its bytes still outlive
    /// the call with the borrower.
    ///
    /// This exists for callers whose invalidation scope is a *key prefix*
    /// rather than one key or the whole cache -- `pagecache` forgetting one
    /// file handle's pages on close, where the alternatives were a full
    /// `clear()` (discarding every other open file's hot pages) or a side
    /// table of every page index the handle ever touched. That side table grew
    /// with the STORE, which is the one quantity a bounded page cache exists
    /// to decouple RAM from; this walks the resident set instead, which is
    /// bounded by `max_pages` by construction.
    ///
    /// Allocation-free, and therefore infallible: removing invalidates the
    /// map iterator, so one scan collects up to `remove_batch` matches into a
    /// stack buffer, then removes them, and scans again only while a scan
    /// filled the buffer. Until 2026-10-23 it re-scanned after EVERY removal:
    /// quadratic in the matches, ~10^10 steps for one file close over a
    /// 1 GiB fully resident `pagecache`; now `ceil(matches / remove_batch)`
    /// scans.
    pub fn removeMatching(self: *Cache, prefix: []const u8) usize {
        var removed: usize = 0;
        var batch: [remove_batch][]const u8 = undefined;
        while (true) {
            var n: usize = 0;
            var it = self.map.keyIterator();
            while (it.next()) |np| {
                const k = np.*.key;
                if (k.len < prefix.len) continue;
                if (!std.mem.eql(u8, k[0..prefix.len], prefix)) continue;
                batch[n] = k;
                n += 1;
                if (n == batch.len) break;
            }
            // Each slice is its own node's key: dropping one frees only that
            // one, so the rest of the batch stays valid.
            for (batch[0..n]) |k| _ = self.dropKey(k);
            removed += n;
            if (n < batch.len) break;
        }
        return removed;
    }

    const remove_batch = 512;

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
    /// the entry is out of the region queues for the borrow's duration, so it
    /// has no region membership to move. It does refresh the entry's tick, so
    /// `release` re-files it as recently used.
    pub fn pin(self: *Cache, key: []const u8, now_ns: i64, cur_gen: u64) ?Borrow {
        self.climbIfDue();
        const e = self.lookupFilled(key) orelse {
            self.stats.misses += 1;
            self.noteOutcome(false);
            return null;
        };
        const ttl_expired = self.timeExpired(e, now_ns);
        const gen_stale = e.gen != 0 and e.gen != cur_gen;
        if (ttl_expired or gen_stale) {
            self.stats.expired += 1;
            self.stats.misses += 1;
            self.noteOutcome(false);
            _ = self.dropKey(key);
            return null;
        }
        const value = e.value;
        if (!self.pinEntry(e)) {
            self.stats.misses += 1;
            self.noteOutcome(false);
            return null;
        }
        self.noteAccess(key);
        self.noteOutcome(true);
        // The node just left the expiry heap (`pinEntry`), so only the stamp
        // moves; `release` files it again under the deadline this implies.
        e.last_access_ns = now_ns;
        e.node.pin_deadline = self.deadlineFor(e.inserted_ns, e.ttl_ns, now_ns);
        self.stats.hits += 1;
        self.syncStats();
        return .{ .bytes = value, .node = e.node };
    }

    /// Insert `key` with `len` bytes of **uninitialized** cache storage and
    /// hand back a writable borrow of it, so a caller that would otherwise
    /// fill a scratch buffer and then `put` (two copies of the payload) can
    /// produce the value straight into its final home (one). The entry is
    /// pinned from birth, and until `commit` it is a MISS for `get`, `pin`
    /// and `drainDirty`: its bytes are uninitialized, and the producer may
    /// have to wait for them -- a fiber reading a page from disk into the
    /// slot parks there, and another fiber on the same thread may look the
    /// key up meanwhile (found from qap's research register H4, 2026-09-29:
    /// `pagecache.preadRef` does exactly that). The reader then fetches for
    /// itself; whichever `put`/`reserve` lands later replaces the other, and
    /// a borrow of the replaced one keeps its bytes (the doomed-entry rule).
    /// The key still occupies its map slot and its bytes count against the
    /// budget from `reserve` on.
    ///
    /// Finish with `commit` (keep it, downgrade to a read borrow) or `discard`
    /// (the fill failed — remove it without ever exposing the garbage).
    /// `null` on OOM or when `len` exceeds the whole cache's byte budget —
    /// and a `null` return leaves the cache **exactly as it was**, including
    /// any entry `key` already had. A reservation that both fails and evicts
    /// would be an invisible loss: the caller is told to use the copying path
    /// and has no way to learn that its previous value went with the refusal.
    pub fn reserve(self: *Cache, key: []const u8, len: usize, now_ns: i64, ttl_ns: i64, gen: u64) ?Fill {
        self.noteAccess(key);
        if (len > self.options.max_bytes) return null;
        // Every fallible step runs FIRST, before anything is mutated: the
        // parking slot, the map slot, and the three allocations. That is what
        // makes the promise above true, and it is also what makes the
        // `.replaced` reason below honest — by the time the old entry is
        // dropped, the entry that replaces it is certain to exist. (`put`'s
        // ceiling path makes the same distinction the other way round: it
        // drops with `.evicted`, because nothing takes the entry's place.)
        self.doomed.ensureTotalCapacity(self.alloc, self.pinned_entries + 1) catch return null;
        self.map.ensureUnusedCapacity(self.alloc, 1) catch return null;
        const vbuf = self.alloc.alloc(u8, len) catch return null;
        const node = self.createNode(key) orelse {
            self.alloc.free(vbuf);
            return null;
        };
        // Nothing below this line can fail.
        if (self.entryOf(key)) |e| {
            // Same reasoning as `put`: an existing entry is either freed or,
            // if borrowed, parked — never left findable with old bytes.
            if (e.node.pins > 0) self.doomEntry(key, .replaced) else _ = self.dropKeyReason(key, .replaced);
        }
        // Born borrowed, so out of the queue until `release` appends it.
        node.pins = 1;
        node.filled = false;
        node.pin_deadline = self.deadlineFor(now_ns, ttl_ns, now_ns);
        node.entry = .{
            .value = vbuf,
            .inserted_ns = now_ns,
            .ttl_ns = ttl_ns,
            .gen = gen,
            .dirty = true,
            .node = node,
            .last_access_ns = now_ns,
        };
        self.map.putAssumeCapacityNoClobber(node, {});
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
    ///
    /// A `Fill` is **consumed** by whichever of `commit`/`discard` it reaches
    /// first, and a `Borrow` by `release`. They are plain copyable structs
    /// holding a `*Node`, so a stale copy used a second time is a
    /// use-after-free the cache cannot always see: once the node has been
    /// freed there is nothing left to ask. The `filled` flag catches the half
    /// that is still detectable — a second `commit`, or a `discard` after a
    /// `commit` whose borrow is still outstanding — as a Debug assert here.
    /// Using a `Fill` after the entry it named has been freed is undetectable
    /// by construction and is the caller's rule to keep.
    pub fn commit(self: *Cache, f: Fill) Borrow {
        _ = self;
        std.debug.assert(f.node.pins > 0);
        std.debug.assert(!f.node.filled); // consumed already, or never a reservation
        f.node.filled = true;
        return .{ .bytes = f.bytes, .node = f.node };
    }

    /// Throw away a reservation whose fill failed. The entry is removed —
    /// always, including when the caller holds a second borrow of it — without
    /// firing `on_evict`: the bytes were never written, and handing a caller's
    /// hook uninitialized memory would be a disclosure, not a hook.
    /// Consumes the `Fill`; see `commit` for what that does and does not
    /// catch.
    pub fn discard(self: *Cache, f: Fill) void {
        const n = f.node;
        std.debug.assert(n.pins > 0);
        std.debug.assert(!n.filled); // already committed, or already discarded
        if (n.doom_idx != Node.not_queued) {
            // Something already unlinked it (a put/remove/clear/TTL drop on
            // the same key between `reserve` and here). It is out of the map
            // already and its bytes are parked, so an ordinary release — which
            // frees them if ours is the last — is exactly right.
            self.release(.{ .bytes = f.bytes, .node = n });
            return;
        }
        if (n.pins != 1) {
            // Unreachable through the public API since an unfilled entry is a
            // miss for `pin` (2026-09-29); kept, because the price of being
            // wrong about that is garbage served, not a slower path.
            // The caller also `pin`ned the key it was filling, so ours is not
            // the last release and the entry cannot simply be destroyed here.
            // It must still leave the map: "removed without ever exposing the
            // garbage" is the contract above, and a plain release would leave
            // the entry resident with uninitialized bytes that `get` and `pin`
            // would happily hand out. So doom it — unlinked now, its storage
            // parked with the borrow that is still outstanding and freed by
            // that borrow's release — and fire no hook, for the same reason
            // the single-owner path below fires none. (`parkNode` empties
            // `n.key`, but the bytes live in the node, which outlives the
            // call, so the slice passed here stays readable throughout.)
            self.doomEntry(n.key, null);
            self.release(.{ .bytes = f.bytes, .node = n });
            return;
        }
        const removed = self.map.removeAdapted(n.key, KeyAdapter{});
        std.debug.assert(removed);
        self.removals +|= 1;
        switch (n.region) {
            .window => self.window_count -= 1,
            .probation => self.probation_count -= 1,
            .protected => self.protected_count -= 1,
        }
        self.bytes -= n.entry.value.len;
        self.alloc.free(n.entry.value);
        self.destroyNode(n);
        self.pinned_entries -= 1;
        self.syncStats();
    }

    /// End a borrow. The entry becomes an ordinary eviction candidate again
    /// (re-filed at its region queue's tail, as its most recent entry);
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
        if (builtin.mode == .debug) std.debug.assert(self.entryOf(n.key).?.node == n);
        // Back in at the tail: the borrow was a use, so the entry is the
        // region's most recent one (Caffeine has no borrows; this is the
        // order its read of the same entry would leave).
        self.lruPush(n.region, n);
        if (n.pin_deadline) |d| _ = self.expPush(n, d);
        self.syncStats();
    }

    /// True while `key` is resident and has at least one live borrow.
    ///
    /// Note the *resident* half: a **doomed** entry — one overwritten,
    /// removed, cleared or expired while borrowed — has already left the map,
    /// so this answers `false` for it even though the borrow is still live and
    /// its bytes are still allocated. `false` therefore means "not a pinned
    /// map entry", never "nobody is reading anything for this key";
    /// `Stats.pinned` is the count that still includes doomed entries.
    pub fn isPinned(self: *Cache, key: []const u8) bool {
        const e = self.entryOf(key) orelse return false;
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
        const e = self.entryOf(key) orelse return false;
        return e.dirty;
    }

    /// Clear the dirty bit for `key` — the write-behind coordinator's ack
    /// after it has durably persisted the current value. Returns `false`
    /// (no-op) if `key` is absent, e.g. it was evicted/replaced/cleared
    /// before the flush landed; `on_evict`'s `dirty` flag is what catches
    /// that race. Side-effect-free otherwise (no stats/promotion/sketch
    /// touch).
    pub fn markClean(self: *Cache, key: []const u8) bool {
        const e = self.entryOf(key) orelse return false;
        e.dirty = false;
        return true;
    }

    /// `markClean` only if the resident value still equals `flushed` -- the
    /// race-free ack for a flusher that persisted a value which may have been
    /// overwritten since (`Sharded.markCleanIf` is this under the shard lock).
    /// Side-effect-free like `markClean`: going through `get` would count a
    /// hit, refresh recency, feed the sketch and lazily drop a stale entry.
    /// `false` if `key` is absent or its value differs.
    pub fn markCleanIf(self: *Cache, key: []const u8, flushed: []const u8) bool {
        const e = self.entryOf(key) orelse return false;
        if (!std.mem.eql(u8, e.value, flushed)) return false;
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
        var it = self.map.keyIterator();
        while (it.next()) |np| {
            const n = np.*;
            // A reservation is dirty from birth and its bytes are garbage
            // until `commit`: there is nothing to write behind yet.
            if (n.entry.dirty and n.filled) cb(ctx, n.key, n.entry.value);
        }
    }

    // ── internals ───────────────────────────────────────────────────────────

    /// The entry for `key` if it holds a value -- a reservation that has not
    /// been `commit`ted yet does not (see `reserve`), and reads as a miss.
    fn lookupFilled(self: *Cache, key: []const u8) ?*Entry {
        const n = self.map.getKeyAdapted(key, KeyAdapter{}) orelse return null;
        return if (n.filled) &n.entry else null;
    }

    /// The map entry for `key`, filled or not.
    fn entryOf(self: *Cache, key: []const u8) ?*Entry {
        const n = self.map.getKeyAdapted(key, KeyAdapter{}) orelse return null;
        return &n.entry;
    }

    /// One allocation: the node, then `key`'s bytes. `entry` is left for the
    /// caller to fill before the node is published in the map.
    fn createNode(self: *Cache, key: []const u8) ?*Node {
        const mem = self.alloc.alignedAlloc(u8, .of(Node), @sizeOf(Node) + key.len) catch return null;
        const n: *Node = @ptrCast(mem.ptr);
        const kbytes = mem[@sizeOf(Node)..];
        @memcpy(kbytes, key);
        n.* = .{ .key = kbytes, .key_len = key.len, .entry = undefined, .tick = 0 };
        return n;
    }

    fn destroyNode(self: *Cache, n: *Node) void {
        const base: [*]align(@alignOf(Node)) u8 = @ptrCast(n);
        self.alloc.free(base[0 .. @sizeOf(Node) + n.key_len]);
    }

    fn syncStats(self: *Cache) void {
        self.stats.entries = self.map.count();
        self.stats.bytes = self.bytes;
        self.stats.pinned = self.pinned_entries;
    }

    /// The admission window size in entries: ~1% of capacity (min 1), or the
    /// climber's current size under `Options.adaptive_window`.
    fn windowCap(self: *const Cache) usize {
        if (self.options.adaptive_window) return self.window_adapt;
        return baseWindow(self.options.max_entries);
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
        if (self.entryOf(key)) |e| {
            if (e.node.pins > 0) {
                // Borrowed: unlink it (no stale hit can follow) but leave the
                // bytes alive for the borrower — see `doomEntry`.
                self.doomEntry(key, reason);
                return true;
            }
        }
        const found = if (self.map.fetchRemoveAdapted(key, KeyAdapter{})) |kv| blk: {
            const n = kv.key;
            self.removals +|= 1;
            self.lruRemove(n.region, n);
            self.expRemove(n);
            switch (n.region) {
                .window => self.window_count -= 1,
                .probation => self.probation_count -= 1,
                .protected => self.protected_count -= 1,
            }
            // The hook reads `node.filled` and the key bytes the node holds,
            // so the node outlives it. It is already out of the map and out of
            // both heaps by now, so nothing can reach it either way.
            self.fireOnEvict(n, n.key, n.entry.value, n.entry.dirty, reason);
            self.bytes -= n.entry.value.len;
            self.alloc.free(n.entry.value);
            self.destroyNode(n);
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
            self.lruRemove(e.node.region, n);
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
    fn doomEntry(self: *Cache, key: []const u8, reason: ?EvictReason) void {
        const n = self.map.fetchRemoveAdapted(key, KeyAdapter{}).?.key;
        self.removals +|= 1;
        std.debug.assert(n.pins > 0);
        // A `null` reason means "unlink it, but tell nobody" — `discard`'s
        // case, where the bytes were never written and handing a caller's
        // hook uninitialized memory would be a disclosure, not a hook.
        if (reason) |r| self.fireOnEvict(n, n.key, n.entry.value, n.entry.dirty, r);
        switch (n.region) {
            .window => self.window_count -= 1,
            .probation => self.probation_count -= 1,
            .protected => self.protected_count -= 1,
        }
        self.bytes -= n.entry.value.len;
        self.parkNode(n, n.entry.value);
        self.syncStats();
    }

    /// Shared tail of `doomEntry` and `clear`: empty the node's key (its
    /// bytes stay in the node's allocation until `freeDoomed`) and move the
    /// value onto the node. `doomed`'s capacity was reserved when the first
    /// borrow was taken (`pinEntry`/`reserve`), one slot per borrowed entry,
    /// so this append cannot fail.
    fn parkNode(self: *Cache, n: *Node, value: []u8) void {
        std.debug.assert(n.pins > 0);
        std.debug.assert(n.doom_idx == Node.not_queued);
        n.key = &.{}; // no longer a key the map can hold
        n.entry.value = &.{};
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
        self.destroyNode(n);
    }

    /// Fire `Options.on_evict` if one is set. Called just before the
    /// caller-visible value memory for `key` is freed.
    ///
    /// Silent for an entry that is still between `reserve` and `commit`
    /// (`!node.filled`). Its bytes are uninitialized heap, and every way such
    /// an entry can die — `put` over it, `remove`, `clear`, a lazy TTL drop —
    /// would otherwise pass that memory straight to a caller's callback.
    /// `discard` refuses to do exactly this ("a disclosure, not a hook"), and
    /// the rule cannot be discard's alone: the four paths that fire this are
    /// how such an entry usually dies. The hook is a write-behind signal, and
    /// there is nothing to write behind — the value never existed.
    fn fireOnEvict(self: *Cache, node: *const Node, key: []const u8, value: []const u8, dirty: bool, reason: EvictReason) void {
        if (!node.filled) return;
        if (self.options.on_evict) |cb| cb(self.options.on_evict_ctx, key, value, dirty, reason);
    }

    // ── the region queues ───────────────────────────────────────────────────
    //
    // One intrusive doubly linked queue per region (Caffeine's access-order
    // deque), head = least recently used. Every append stamps a fresh `tick`,
    // so ticks rise strictly from head to tail (`expectQueuesOrdered`). No
    // operation allocates, so none can fail.

    const Queue = struct {
        head: ?*Node = null,
        tail: ?*Node = null,
        len: usize = 0,
    };

    /// Append `n` at `region`'s tail as its most recent entry.
    fn lruPush(self: *Cache, region: Region, n: *Node) void {
        std.debug.assert(!n.queued);
        const q = &self.lru[@backingInt(region)];
        self.tick += 1;
        n.tick = self.tick;
        n.prev = q.tail;
        n.next = null;
        if (q.tail) |t| t.next = n else q.head = n;
        q.tail = n;
        q.len += 1;
        n.queued = true;
    }

    fn lruRemove(self: *Cache, region: Region, n: *Node) void {
        if (!n.queued) return; // borrowed/doomed: not indexed
        const q = &self.lru[@backingInt(region)];
        if (n.prev) |p| p.next = n.next else q.head = n.next;
        if (n.next) |x| x.prev = n.prev else q.tail = n.prev;
        n.prev = null;
        n.next = null;
        n.queued = false;
        q.len -= 1;
    }

    /// A hit or a rewrite: move `n` to its region's tail.
    fn lruTouched(self: *Cache, region: Region, n: *Node) void {
        if (!n.queued) return; // borrowed/doomed: not indexed
        self.lruRemove(region, n);
        self.lruPush(region, n);
    }

    /// Move `n` from `from` to the tail of `to`.
    fn lruMove(self: *Cache, n: *Node, from: Region, to: Region) void {
        self.lruRemove(from, n);
        self.lruPush(to, n);
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

    /// Effective expiry instant of an entry written at `inserted_ns` with
    /// `ttl_ns` and last accessed at `last_access_ns`: the earlier of the
    /// write-TTL deadline and the idle deadline, `null` when neither applies
    /// (no expiry by time). Saturating, so a huge TTL cannot wrap.
    fn deadlineFor(self: *const Cache, inserted_ns: i64, ttl_ns: i64, last_access_ns: i64) ?i64 {
        var d: ?i64 = null;
        if (ttl_ns > 0) d = inserted_ns +| ttl_ns;
        if (self.options.idle_ttl_ns > 0) {
            const idle = last_access_ns +| self.options.idle_ttl_ns;
            d = if (d) |w| @min(w, idle) else idle;
        }
        return d;
    }

    /// The time-based freshness predicate shared by `get` and `pin`: expired
    /// by write TTL (`now - inserted > ttl`) or by idleness
    /// (`now - last access > idle_ttl_ns`). Strict `>` on both, so an entry is
    /// still fresh at exactly its TTL, matching the heap's `now > deadline`.
    fn timeExpired(self: *const Cache, e: *const Entry, now_ns: i64) bool {
        if (e.ttl_ns > 0 and (now_ns - e.inserted_ns) > e.ttl_ns) return true;
        return self.options.idle_ttl_ns > 0 and (now_ns - e.last_access_ns) > self.options.idle_ttl_ns;
    }

    /// A hit at `now_ns`: refresh the idle stamp and, when idle expiry is on,
    /// re-file the entry under its new deadline. A borrowed node is not in the
    /// expiry heap (`Node.pins`); it only gets the stamp.
    fn touchIdle(self: *Cache, e: *Entry, now_ns: i64) void {
        e.last_access_ns = now_ns;
        if (e.node.pins > 0) {
            e.node.pin_deadline = self.deadlineFor(e.inserted_ns, e.ttl_ns, now_ns);
            return;
        }
        if (self.options.idle_ttl_ns <= 0) return;
        self.expUpdate(e.node, self.deadlineFor(e.inserted_ns, e.ttl_ns, now_ns));
    }

    /// Re-file `n` after a rewrite or a hit changed its deadline (in either
    /// direction, so this sifts both ways). `null` = no deadline any more.
    fn expUpdate(self: *Cache, n: *Node, new_deadline: ?i64) void {
        const deadline = new_deadline orelse return self.expRemove(n);
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
    /// O(1): the queue head. Was a full-map scan.
    fn regionLruKey(self: *Cache, region: Region) ?[]const u8 {
        return (self.regionLru(region) orelse return null).key;
    }

    /// The node behind `regionLruKey`, for moves that need no map entry.
    fn regionLru(self: *Cache, region: Region) ?*Node {
        const head = self.lru[@backingInt(region)].head orelse return null;
        self.maintenance_visits += 1;
        return head;
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
        self.shrinkWindow();
        self.enforceProtectedCap();
        self.shedTombstones();
    }

    /// Window overflow without global pressure: the main region has room
    /// (global cap holds), so the window's LRU moves to probation freely.
    fn shrinkWindow(self: *Cache) void {
        while (self.window_count > self.windowCap()) {
            const n = self.regionLru(.window) orelse break;
            self.lruMove(n, .window, .probation);
            n.region = .probation;
            self.window_count -= 1;
            self.probation_count += 1;
        }
    }

    // ── adaptive window: the hill climber ───────────────────────────────────
    //
    // Behaviour anchored on otter v2.3.0 (`policy.go`: `climb` 375,
    // `determineAdjustment` 389, `increaseWindow` 449, `decreaseWindow` 495),
    // clean-room. Kept: constants (see `hill_*`), the sample length
    // (10 x capacity), the sign convention (initial step negative, the step
    // flips when the hit rate fell, restarts at full size on a >= 5 point
    // change, decays 2 % per sample otherwise), growing the window from the
    // probation LRU first and then the protected LRU, and handing back the part
    // of a step that could not be realised. Changed: (1) the hit rate counts
    // lookup outcomes (`get`/`pin` hit vs miss) where otter counts reads that
    // hit vs inserts -- a caller that does not insert on a miss still adapts;
    // (2) the window is capped at 80 % of `max_entries` explicitly, otter
    // stops where its protected quota hits zero; (3) every entry weighs 1
    // (byte caps are separate); (4) a shrink with an under-filled window
    // lowers the limit without moving entries out of it, otter moves up to
    // the quota regardless; (5) the climber runs at the start of a `get`/`pin`
    // instead of in an asynchronous maintenance cycle.

    fn noteOutcome(self: *Cache, hit: bool) void {
        if (!self.options.adaptive_window) return;
        if (hit) self.hc_hits += 1 else self.hc_misses += 1;
    }

    /// Run one climber step if a full sample has been collected. Moves
    /// entries between regions but never frees or inserts one, so it is safe
    /// to run before the lookup it precedes.
    fn climbIfDue(self: *Cache) void {
        if (!self.options.adaptive_window) return;
        const period = self.options.max_entries *| hill_sample_factor;
        const requests = self.hc_hits + self.hc_misses;
        if (period == 0 or requests < period) return;

        const hit_rate = @as(f64, @floatFromInt(self.hc_hits)) / @as(f64, @floatFromInt(requests));
        const change = hit_rate - self.hc_prev_rate;
        const amount = if (change < 0) -self.hc_step else self.hc_step;
        if (@abs(change) >= hill_restart_threshold) {
            const k: f64 = if (amount >= 0) 1 else -1;
            self.hc_step = hill_step_percent * @as(f64, @floatFromInt(self.options.max_entries)) * k;
        } else {
            self.hc_step = hill_step_decay * amount;
        }
        self.hc_prev_rate = hit_rate;
        self.hc_hits = 0;
        self.hc_misses = 0;
        self.climbs += 1;

        const quota: i64 = @intFromFloat(amount); // truncates toward zero, like otter's int64()
        if (quota > 0) {
            self.growWindow(@intCast(quota));
        } else if (quota < 0) {
            self.shrinkWindowBy(@intCast(-quota));
        }
    }

    /// Largest window the climber may reach: 80 % of the capacity (min 1).
    fn windowBound(self: *const Cache) usize {
        return @max(1, self.options.max_entries / 5 * 4);
    }

    /// Grow the window by up to `quota` entries, pulling the probation LRU
    /// (then the protected LRU) in at the window's most-recent end. The limit
    /// rises only by what was actually moved.
    fn growWindow(self: *Cache, quota: usize) void {
        const bound = self.windowBound();
        if (self.window_adapt >= bound) return;
        const want = @min(quota, bound - self.window_adapt);
        var moved: usize = 0;
        while (moved < want) {
            const n = self.regionLru(.probation) orelse self.regionLru(.protected) orelse break;
            self.moveToWindow(n);
            moved += 1;
        }
        self.window_adapt += moved;
        self.enforceProtectedCap();
    }

    /// Shrink the window limit by up to `quota` entries (never below 1); the
    /// overflow leaves from the window's LRU end into probation.
    fn shrinkWindowBy(self: *Cache, quota: usize) void {
        if (self.window_adapt <= 1) return;
        self.window_adapt -= @min(quota, self.window_adapt - 1);
        self.shrinkWindow();
    }

    /// Re-file a main-region entry as the window's most recent one.
    fn moveToWindow(self: *Cache, n: *Node) void {
        const from = n.region;
        self.lruMove(n, from, .window);
        switch (from) {
            .window => unreachable,
            .probation => self.probation_count -= 1,
            .protected => self.protected_count -= 1,
        }
        n.region = .window;
        self.window_count += 1;
    }

    /// Rebuild the index once removals since the last rebuild pass a quarter
    /// of its capacity, so a lookup never probes more than that many
    /// tombstones. O(capacity) once per capacity/4 removals -- a few
    /// instructions per removal, against a whole-table walk per lookup
    /// without it. Only here, at the end of `maintain`: nothing in this
    /// module holds an `*Entry` across it (borrows hold `*Node`, which the
    /// rebuild does not move), and every insert passes through `maintain`.
    fn shedTombstones(self: *Cache) void {
        const cap = self.map.capacity();
        if (cap == 0) return;
        if (self.removals < @max(32, cap / 4)) return;
        self.map.rehash(NodeContext{});
        self.removals = 0;
        self.stats.rehashes += 1;
    }

    /// Demote protected LRU entries back to probation while over the cap.
    fn enforceProtectedCap(self: *Cache) void {
        const cap = self.protectedCap();
        while (self.protected_count > cap) {
            const n = self.regionLru(.protected) orelse break;
            self.lruMove(n, .protected, .probation);
            n.region = .probation;
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
    /// Returns false when the map did not shrink — an empty map, no reachable
    /// victim, or a heap root that named a key the map no longer holds.
    ///
    /// `maintain` loops on this answer, so "true" has to mean *an entry was
    /// actually removed*, never "a branch was taken". The two are not the same
    /// thing: a node left in a region or expiry heap after it was doomed
    /// carries `key = &.{}` (`parkNode`), so `regionLruKey`/`findExpiredKey`
    /// hand back a key `dropKey` cannot find and every branch below would
    /// still report an eviction. That is an unbounded loop in `maintain` — a
    /// hang, which surfaces as a CI timeout rather than a failing test, and is
    /// strictly worse to diagnose than either a red test or a cache that
    /// merely sits over its cap. The guard is deliberately the *only*
    /// termination mechanism here: it is stated once, in terms of the map, so
    /// that no branch added later can forget it and no second, redundant check
    /// can hide it going wrong.
    fn evictStep(self: *Cache, now_ns: i64) bool {
        const before = self.map.count();
        if (!self.evictOne(now_ns)) return false;
        if (self.map.count() == before) return false; // progress guard
        // Counted here rather than per branch for the same reason: one
        // eviction is one entry gone, not one branch entered.
        self.stats.evictions += 1;
        return true;
    }

    /// The choice itself. May report `true` without having removed anything —
    /// `evictStep` is what turns that into an honest answer.
    fn evictOne(self: *Cache, now_ns: i64) bool {
        if (self.map.count() == 0) return false;
        if (self.findExpiredKey(now_ns)) |k| {
            _ = self.dropKey(k);
            return true;
        }
        const cand = self.regionLruKey(.window) orelse {
            // no window entries — evict straight from the main region
            const vk = self.regionLruKey(.probation) orelse
                self.regionLruKey(.protected) orelse return false;
            _ = self.dropKey(vk);
            return true;
        };
        const victim = self.regionLruKey(.probation) orelse
            self.regionLruKey(.protected) orelse {
            // main region empty — plain LRU within the window
            _ = self.dropKey(cand);
            return true;
        };
        if (self.admit(cand, victim)) {
            _ = self.dropKey(victim);
            const e = self.entryOf(cand).?;
            self.lruMove(e.node, .window, .probation);
            e.node.region = .probation;
            self.window_count -= 1;
            self.probation_count += 1;
            self.stats.admissions += 1;
        } else {
            _ = self.dropKey(cand);
            self.stats.rejections += 1;
        }
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

test "replace refuses a value larger than the whole cache, and drops the entry rather than serving the old bytes" {
    // The replace path used to return before the single-item ceiling, so
    // overwriting a resident key stored a value of ANY size.
    var c = testCache(64, 16); // 64-byte cache
    defer c.deinit();
    c.put("a", "aaaaaaaaaa", 0, 0, 0); // 10 bytes
    c.put("b", "bbbbbbbbbb", 1, 0, 0); // 10 bytes
    c.put("k", "small", 2, 0, 0); // 5 bytes — 25 total, well under the cap
    const big = @as([200]u8, @splat('x')); // 200 > 64 — unstorable however it arrives
    c.put("k", &big, 3, 0, 0);
    // Not the new bytes (3x the whole cache) and not the old ones either: a
    // refused write that keeps the previous value serves pre-write data
    // forever. Absent is the honest outcome — the caller refetches.
    try testing.expect(c.get("k", 4, 0) == null);
    // The oracle that separates "rejected at the ceiling" from "stored, then
    // evicted by the maintenance pass": admitting 200 bytes into a 64-byte
    // cache costs the INNOCENT residents their slots, because the freshly
    // written entry is the most-recently-used one and the LRU victims are the
    // bystanders. Rejecting it costs nothing.
    try testing.expectEqualStrings("aaaaaaaaaa", c.get("a", 5, 0).?);
    try testing.expectEqualStrings("bbbbbbbbbb", c.get("b", 5, 0).?);
    try testing.expectEqual(@as(usize, 20), c.bytes);
    try testing.expectEqual(@as(usize, 2), c.stats.entries);
    // Nothing was ever admitted, so no capacity eviction ran at all.
    try testing.expectEqual(@as(u64, 0), c.stats.evictions);
}

test "an update-only workload never grows past max_bytes (replace runs maintenance too)" {
    // The shape this matters for: a fixed key set written over and over (a
    // session store, a write-behind cache). No fresh insert ever happens after
    // the first round, so before the fix `maintain` was never reached again and
    // occupancy climbed monotonically: 256 -> 512 -> 1024 -> 2048 on a
    // 512-byte cache.
    var c = testCache(512, 64); // entry cap never binds: 32 keys < 64
    defer c.deinit();
    var kbuf: [8]u8 = undefined;
    var val: [64]u8 = undefined;
    @memset(&val, 'v');
    const rounds = [_]usize{ 8, 16, 32, 64 };
    var now: i64 = 0;
    for (rounds) |vlen| {
        var i: usize = 0;
        while (i < 32) : (i += 1) {
            const key = std.mem.print(&kbuf, "k{d}", .{i}) catch unreachable;
            now += 1;
            c.put(key, val[0..vlen], now, 0, 0);
            // The bound, checked after every single write — not just at the end.
            try testing.expect(c.bytes <= 512);
        }
    }
    // ...and the run really did apply pressure rather than fitting all along:
    // 32 x 64B = 2048 bytes were offered against a 512-byte cap.
    try testing.expect(c.stats.evictions > 0);
    try testing.expect(c.map.count() > 0);
    try testing.expect(c.bytes <= 512);
    try testing.expectEqual(c.bytes, c.stats.bytes);
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
    try testing.expect(!c.map.containsAdapted("exp", Cache.KeyAdapter{})); // physically gone, not just stale
    try testing.expect(c.map.containsAdapted("lru", Cache.KeyAdapter{}));
    try testing.expect(c.map.containsAdapted("new", Cache.KeyAdapter{}));
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

test "miss churn sheds the index's tombstones: the map is rebuilt, every live key still answers" {
    // Every miss on a full cache is a remove plus an insert. std's map keeps
    // a tombstone per remove and never rebuilds on its own (a remove hands
    // the slot back to `available`), so without `shedTombstones` this loop
    // ends with a table that has no free slot and a probe that walks all of
    // it. RED without the rebuild: `rehashes` stays 0.
    var c = testCache(1 << 20, 64);
    defer c.deinit();
    var k: [16]u8 = undefined;
    for (0..4096) |i| {
        c.put(std.mem.print(&k, "key{d}", .{i}) catch unreachable, "v", 0, 0, 0);
    }
    try testing.expect(c.stats.rehashes >= 1);
    try testing.expect(c.stats.rehashes <= 4096 / 32);
    // The rebuild kept the live set intact: the newest keys are resident.
    var live: usize = 0;
    for (4096 - 8..4096) |i| {
        if (c.get(std.mem.print(&k, "key{d}", .{i}) catch unreachable, 0, 0)) |v| {
            try testing.expectEqualStrings("v", v);
            live += 1;
        }
    }
    try testing.expect(live >= 1);
    try testing.expectEqual(@as(usize, c.map.count()), c.stats.entries);
}

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
        c.put(std.mem.print(&k, "cold{d}", .{i}) catch unreachable, "BBBB", 0, 0, 0);
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

// The next two tests are the only ones in the repo that park more than one
// value at a time, which is what makes `freeDoomed`'s swap-remove run at all.
// Three is the smallest number that discriminates, and that is measured, not
// assumed: with two parked nodes a stale `doom_idx` is self-correcting — the
// survivor's index is then out of range of a one-element list, so the fixup
// branch is skipped and it frees itself correctly either way.
//
// Parking order is deliberate rather than incidental: `clear` would park in
// map-iteration order, so which node lands in slot 0 would be a hash detail.
// Overwriting each pinned key in turn appends in call order.
test "borrow: releasing parked values out of order re-indexes the doomed list" {
    var c = testCache(1 << 20, 16);
    defer c.deinit();
    c.put("a", "AAA", 0, 0, 0);
    c.put("b", "BBB", 0, 0, 0);
    c.put("c", "CCC", 0, 0, 0);
    const ba = c.pin("a", 0, 0).?;
    const bb = c.pin("b", 0, 0).?;
    const bc = c.pin("c", 0, 0).?;
    c.put("a", "aaa", 0, 0, 0);
    c.put("b", "bbb", 0, 0, 0);
    c.put("c", "ccc", 0, 0, 0);

    try testing.expectEqual(@as(usize, 3), c.doomed.items.len);
    try testing.expectEqual(@as(u32, 0), ba.node.doom_idx);
    try testing.expectEqual(@as(u32, 1), bb.node.doom_idx);
    try testing.expectEqual(@as(u32, 2), bc.node.doom_idx);

    // Release the FIRST parked node. The last one is swap-moved into slot 0
    // and has to learn where it now lives; a node whose `doom_idx` still
    // names its old slot indexes a stranger on its own release.
    c.release(ba);
    try testing.expectEqual(@as(usize, 2), c.doomed.items.len);
    try testing.expectEqual(bc.node, c.doomed.items[0]);
    try testing.expectEqual(@as(u32, 0), bc.node.doom_idx);
    try testing.expectEqual(bb.node, c.doomed.items[1]);
    try testing.expectEqual(@as(u32, 1), bb.node.doom_idx);

    // Both snapshots are intact — the swap moved a slot, not any bytes.
    try testing.expectEqualStrings("BBB", bb.bytes);
    try testing.expectEqualStrings("CCC", bc.bytes);
    c.release(bc);
    c.release(bb);
    try testing.expectEqual(@as(usize, 0), c.doomed.items.len);
    try testing.expectEqual(@as(usize, 0), c.stats.pinned);
}

test "borrow: a parked value outliving two out-of-order releases is freed exactly once" {
    // Same shape as above with no assertions on internals: the oracle is
    // `testing.allocator`. Releasing slot 0 and then the node that was swapped
    // into it, with a third borrow still outstanding at `deinit`, is the
    // ordering in which a missed re-index frees one node twice (once by
    // `release`, once by `deinit`'s sweep) and leaks the other.
    var c = testCache(1 << 20, 16);
    defer c.deinit();
    c.put("a", "AAA", 0, 0, 0);
    c.put("b", "BBB", 0, 0, 0);
    c.put("c", "CCC", 0, 0, 0);
    const ba = c.pin("a", 0, 0).?;
    const bb = c.pin("b", 0, 0).?;
    const bc = c.pin("c", 0, 0).?;
    c.put("a", "aaa", 0, 0, 0);
    c.put("b", "bbb", 0, 0, 0);
    c.put("c", "ccc", 0, 0, 0);

    c.release(ba); // slot 0 freed, "c" swapped into it
    c.release(bc); // the swapped node — reached only through its new index
    // "b" is still borrowed and still readable; `deinit` frees it below, and
    // it must be the only thing left to free.
    try testing.expectEqualStrings("BBB", bb.bytes);
    try testing.expectEqual(@as(usize, 1), c.doomed.items.len);
}

// ── borrow-seam operation sequences (scripted + fuzzed) ─────────────────────
//
// Every scenario above is hand-built, which means the seam is only ever tested
// in shapes somebody already thought of — and the two most expensive defects
// in it (a stale `doom_idx`, and byte/region accounting that never comes back
// down) were both invisible to every hand-built shape in the repo. This drives
// arbitrary op sequences over a four-key cache instead, and checks the
// structural invariants after *every* operation rather than at the end.
//
// The script is raw bytes with a small modulus, deliberately not a weighted
// draw: a weighted draw over a random corpus never leaves its first range, so
// the rare operations would simply not exist on a plain build. And because a
// random corpus needs luck to reach the interesting interleavings at all, the
// shapes that matter are also driven as fixed scripts below, so they run in
// the ordinary suite.
const testkit = @import("testkit");
const fuzz_driver = testkit.fuzz.driver;

const SeamLabel = enum { pinned, committed, released, parked, idled };
var seam_reach: [@typeInfo(SeamLabel).@"enum".field_names.len]usize = @splat(0);

fn mark(comptime l: SeamLabel) void {
    seam_reach[@backingInt(l)] += 1;
    fuzz_driver.hit(@tagName(l));
}

const SeamHarness = struct {
    const key_pool = [_][]const u8{ "k0", "k1", "k2", "k3" };
    const payload = "abcdefgh";

    const op_put = 0;
    const op_get = 1;
    const op_pin = 2;
    const op_reserve = 3;
    const op_commit = 4;
    const op_discard = 5;
    const op_release = 6;
    const op_remove = 7;
    const op_clear = 8;
    const op_count = 9;

    c: Cache,
    /// Outstanding read borrows. A script that pins more than this simply
    /// releases the extras at once — it never drops one on the floor.
    borrows: [8]?Cache.Borrow = @splat(null),
    fill: ?Cache.Fill = null,
    now: i64 = 0,
    /// `Options.idle_ttl_ns` of the cache under test. Non-zero also switches
    /// time to advance by 1..136 ns per step instead of a flat 10, so a key's
    /// silence lands both below and above the idle limit.
    idle_ns: i64 = 0,

    /// Deliberately tiny caps: three entries and 24 bytes mean real eviction
    /// pressure within a handful of operations, which is where the borrow
    /// seam and the eviction machinery actually meet.
    fn init(alloc: std.mem.Allocator, idle_ns: i64) SeamHarness {
        return .{
            .c = Cache.init(alloc, .{ .max_bytes = 24, .max_entries = 3, .idle_ttl_ns = idle_ns }),
            .idle_ns = idle_ns,
        };
    }

    fn deinit(self: *SeamHarness) void {
        if (self.fill) |f| {
            self.c.discard(f);
            self.fill = null;
        }
        for (&self.borrows) |*slot| {
            if (slot.*) |b| self.c.release(b);
            slot.* = null;
        }
        self.c.deinit();
    }

    fn store(self: *SeamHarness, b: Cache.Borrow) void {
        for (&self.borrows) |*slot| {
            if (slot.* == null) {
                slot.* = b;
                return;
            }
        }
        self.c.release(b);
    }

    fn takeBorrow(self: *SeamHarness, which: usize) ?Cache.Borrow {
        for (0..self.borrows.len) |i| {
            const idx = (which + i) % self.borrows.len;
            if (self.borrows[idx]) |b| {
                self.borrows[idx] = null;
                return b;
            }
        }
        return null;
    }

    /// `arg` is packed so that no single script byte is degenerate: the low
    /// two bits pick the key, bit 3 picks a TTL, and the high nibble picks the
    /// value length. A length of zero everywhere would make the byte-accounting
    /// invariant below true for the wrong reason.
    fn step(self: *SeamHarness, op: u8, arg: u8) !void {
        const k = key_pool[arg % key_pool.len];
        const len = (arg >> 4) % (payload.len + 1);
        const ttl: i64 = if (arg & 8 != 0) 50 else 0;
        self.now += if (self.idle_ns > 0) 1 + @as(i64, op >> 4) * 9 else 10;
        // Reach: a lookup about to find an entry that only IDLENESS has expired
        // (silent for > idle_ns, still inside its write TTL).
        if (self.idle_ns > 0 and (op % op_count == op_get or op % op_count == op_pin)) {
            if (self.c.entryOf(k)) |e| {
                const ttl_dead = e.ttl_ns > 0 and (self.now - e.inserted_ns) > e.ttl_ns;
                if (e.node.filled and !ttl_dead and (self.now - e.last_access_ns) > self.idle_ns) mark(.idled);
            }
        }
        switch (op % op_count) {
            op_put => self.c.put(k, payload[0..len], self.now, ttl, 0),
            op_get => _ = self.c.get(k, self.now, 0),
            op_pin => if (self.c.pin(k, self.now, 0)) |b| {
                mark(.pinned);
                self.store(b);
            },
            op_reserve => if (self.fill == null) {
                if (self.c.reserve(k, len, self.now, ttl, 0)) |f| self.fill = f;
            },
            op_commit => if (self.fill) |f| {
                @memset(f.bytes, 'z');
                mark(.committed);
                self.store(self.c.commit(f));
                self.fill = null;
            },
            op_discard => if (self.fill) |f| {
                self.c.discard(f);
                self.fill = null;
            },
            op_release => if (self.takeBorrow(arg)) |b| {
                mark(.released);
                self.c.release(b);
            },
            op_remove => _ = self.c.remove(k),
            op_clear => self.c.clear(),
            else => unreachable,
        }
        if (self.c.doomed.items.len > 0) mark(.parked);
        try self.check();
    }

    /// What must be true after every single operation, borrowed or not.
    fn check(self: *SeamHarness) !void {
        // `bytes` counts live map values and nothing else — not a value that
        // was parked with a borrower, not one a discarded reservation held.
        var total: usize = 0;
        var it = self.c.map.keyIterator();
        while (it.next()) |kv| total += kv.*.entry.value.len;
        try testing.expectEqual(total, self.c.bytes);
        // The region counters partition the live map.
        try testing.expectEqual(
            @as(usize, self.c.map.count()),
            self.c.window_count + self.c.probation_count + self.c.protected_count,
        );
        // ...and they count the same entries the region queues index. That is a
        // strictly stronger statement than the partition above, which stays
        // true while an entry is counted in one region and indexed in another.
        try expectRegionQueuesAgree(&self.c);
        // Every parked node knows where it is parked, and is still borrowed.
        for (self.c.doomed.items, 0..) |n, i| {
            try testing.expectEqual(@as(u32, @intCast(i)), n.doom_idx);
            try testing.expect(n.pins > 0);
        }
        // The parking list never outgrows the reservation `pinEntry`/`reserve`
        // made for it — the invariant that lets `parkNode` be infallible.
        try testing.expect(self.c.doomed.items.len <= self.c.pinned_entries);
        try expectExpiryAgrees(&self.c);
    }

    fn run(alloc: std.mem.Allocator, script: []const u8) !void {
        return runWith(alloc, 0, script);
    }

    fn runWith(alloc: std.mem.Allocator, idle_ns: i64, script: []const u8) !void {
        var h = SeamHarness.init(alloc, idle_ns);
        defer h.deinit();
        var i: usize = 0;
        while (i + 1 < script.len) : (i += 2) try h.step(script[i], script[i + 1]);
    }
};

test "seam scripts: parked values released out of order, and reservations that die mid-fill" {
    const H = SeamHarness;
    // Three values parked at once and released out of order — the shape that
    // makes `freeDoomed`'s swap-remove run, which no other test in the repo
    // reaches by accident. Args carry a non-zero length (high nibble).
    try H.run(testing.allocator, &.{
        H.op_put,     0x30, H.op_put,     0x31, H.op_put,    0x32,
        H.op_pin,     0x30, H.op_pin,     0x31, H.op_pin,    0x32,
        H.op_remove,  0x30, H.op_remove,  0x31, H.op_remove, 0x32,
        H.op_release, 0x00, H.op_release, 0x02, H.op_get,    0x30,
    });

    // A reservation that is borrowed a second time and then discarded, and a
    // reservation that is cleared out from under the fill before it commits.
    try H.run(testing.allocator, &.{
        H.op_reserve, 0x30, H.op_pin,     0x30, H.op_discard, 0x00,
        H.op_get,     0x30, H.op_release, 0x00, H.op_reserve, 0x41,
        H.op_clear,   0x00, H.op_commit,  0x00, H.op_release, 0x00,
    });

    // Eviction pressure with everything borrowed: puts that cannot evict a
    // pinned entry, TTLs expiring underneath live borrows, then a clear.
    try H.run(testing.allocator, &.{
        H.op_put,     0x38, H.op_pin,     0x38, H.op_put,   0x59,
        H.op_pin,     0x59, H.op_put,     0x6a, H.op_put,   0x7b,
        H.op_get,     0x38, H.op_put,     0x3c, H.op_clear, 0x00,
        H.op_release, 0x00, H.op_release, 0x01,
    });
}

test "seam scripts: a live release re-files window, probation AND protected borrows" {
    // Every borrow released above is released *doomed* — parked by an
    // intervening remove/put-over/clear, so `release` takes its `freeDoomed`
    // branch. The other branch, `self.lruPush(e.node.region, n)` (re-filing a
    // still-resident entry into its OWN region's heap), never runs above —
    // for any region, not just a non-window one. That branch is exactly
    // where `release: release re-files the entry into its OWN region queue,
    // from every region` (below) pins a real historical bug: a refactor that
    // re-files into a fixed region instead of `e.node.region`. This script drives
    // that branch through the harness's own op vocabulary — not a
    // hand-written assertion beside it — so `check()`'s generic
    // `expectRegionQueuesAgree` is what catches a regression, the same way it
    // would for a shape the fuzzer found on its own.
    const H = SeamHarness;
    try H.run(testing.allocator, &.{
        // Fill all three slots so the third put demotes the first two out of
        // the window (window cap 1 at max_entries=3): k0, k1 -> probation,
        // k2 stays in the window.
        H.op_put,     0x30, H.op_put,     0x31, H.op_put, 0x32,
        // .window — pin the still-resident k2 and release it live.
        H.op_pin,     0x32, H.op_release, 0x00,
        // .probation — pin the still-resident k0 and release it live.
        H.op_pin, 0x30,
        H.op_release, 0x00,
        // Promote k1 out of probation (`get` on an unpinned probation entry
        // promotes it), then pin and release it live: .protected.
        H.op_get,     0x31, H.op_pin, 0x31,
        H.op_release, 0x00,
    });
}

fn fuzzSeam(_: void, smith: *std.testing.Smith) !void {
    // One raw-byte draw of a fixed length, read as (op, arg) pairs. Lengths
    // before payloads is moot here because there is exactly one draw; what
    // matters is that no weighted draw decides which operation runs.
    var script: [65]u8 = undefined; // 1 config byte + 32 (op, arg) pairs
    smith.bytes(&script);
    var src: ScriptSource = .{ .cur = .{ .bytes = &script } };
    try seamHarness(ScriptSource, &src, testing.allocator);
}

/// `testing.fuzz`'s source: the script `smith.bytes` produced, read by a cursor.
const ScriptSource = struct {
    cur: testkit.fuzz.Cursor,

    pub fn bytes(self: *ScriptSource, buf: []u8) void {
        for (buf) |*b| b.* = self.cur.byte();
    }
};

/// The harness body, generic over its source of choices (`ScriptSource` for
/// `testing.fuzz`, `fuzz_driver.Rng` for the deterministic driver).
fn seamHarness(comptime S: type, src: *S, gpa: std.mem.Allocator) anyerror!void {
    // One config byte: bit 0 turns time-to-idle on (40 ns), so half the
    // scripts run with idle expiry in play and half without.
    var cfg: [1]u8 = undefined;
    src.bytes(&cfg);
    var script: [64]u8 = undefined;
    src.bytes(&script);
    try SeamHarness.runWith(gpa, if (cfg[0] & 1 != 0) 40 else 0, &script);
}

/// The expiry heap holds exactly the nodes that should be in it, under the
/// deadline they should have: an unborrowed entry with a deadline (write TTL
/// and/or idle TTL) is queued at `Cache.deadlineFor`, one without is not
/// queued, and a borrowed one never is (`Node.pins`).
fn expectExpiryAgrees(c: *Cache) !void {
    var it = c.map.keyIterator();
    while (it.next()) |kv| {
        const e = &kv.*.entry;
        if (e.node.pins > 0) {
            try testing.expectEqual(Cache.Node.not_queued, e.node.exp_idx);
            // `release` files the node under this without a lookup.
            try testing.expectEqual(c.deadlineFor(e.inserted_ns, e.ttl_ns, e.last_access_ns), e.node.pin_deadline);
            continue;
        }
        if (c.deadlineFor(e.inserted_ns, e.ttl_ns, e.last_access_ns)) |d| {
            try testing.expect(e.node.exp_idx != Cache.Node.not_queued);
            try testing.expectEqual(d, e.node.deadline);
        } else {
            try testing.expectEqual(Cache.Node.not_queued, e.node.exp_idx);
        }
    }
}

test "fuzz driver: RAMCACHE_FUZZ (seam)" {
    try fuzz_driver.run(seamHarness, .{ .prefix = "RAMCACHE_FUZZ", .name = "ramcache-seam" });
}

test "fuzz harness: 400 seeds in every test run, and they get everywhere" {
    seam_reach = @splat(0);
    for (0..400) |seed| {
        var prng = std.Random.DefaultPrng.init(seed);
        var rng: fuzz_driver.Rng = .{ .r = prng.random() };
        seamHarness(fuzz_driver.Rng, &rng, testing.allocator) catch |err| {
            std.debug.print("ramcache seed {d}: {t}\n", .{ seed, err });
            return err;
        };
    }
    for (seam_reach, 0..) |n, i| if (n == 0) {
        std.debug.print("reach: label {t} never hit in 400 seeds\n", .{@as(SeamLabel, @fromBackingInt(@intCast(i)))});
        return error.HarnessDoesNotReach;
    };
}

test "fuzz: arbitrary borrow-seam operation sequences keep every structural invariant" {
    try testing.fuzz({}, fuzzSeam, .{});
}

test "borrow: a reservation is a miss until it is committed, for get, pin and drainDirty" {
    // qap research register H4: the producer of a reservation may park
    // mid-fill (a fiber reading the page from disk into the slot), and a
    // second fiber on the same thread may look the key up meanwhile. Before
    // this, `get` answered a HIT on the uninitialized bytes and `pin` lent
    // them; `drainDirty` handed them to a write-behind flusher, since a
    // reservation is dirty from birth.
    var c = testCache(1 << 20, 16);
    defer c.deinit();
    c.put("bystander", "B", 0, 0, 0);

    const f = c.reserve("half", 8, 0, 0, 0).?;
    @memset(f.bytes, 0xAA); // stands in for "whatever the heap held"
    try testing.expect(c.get("half", 0, 0) == null);
    try testing.expect(c.pin("half", 0, 0) == null);
    const Seen = struct {
        var n: usize = 0;
        fn cb(_: ?*anyopaque, key: []const u8, _: []const u8) void {
            if (std.mem.eql(u8, key, "half")) n += 1;
        }
    };
    Seen.n = 0;
    c.drainDirty(Seen.cb, null);
    try testing.expectEqual(@as(usize, 0), Seen.n);

    // The waiting reader fetched for itself and `put` its copy first: that
    // copy is what the cache serves, and the late fill still lands in the
    // borrow its producer is handed -- then goes with it.
    c.put("half", "readers!", 0, 0, 0);
    @memcpy(f.bytes, "producer");
    const b = c.commit(f);
    try testing.expectEqualStrings("producer", b.bytes);
    try testing.expectEqualStrings("readers!", c.get("half", 0, 0).?);
    c.release(b);
    try testing.expectEqualStrings("readers!", c.get("half", 0, 0).?);

    // Committed: visible, and dirty for the flusher.
    const f2 = c.reserve("full", 4, 0, 0, 0).?;
    @memcpy(f2.bytes, "done");
    c.release(c.commit(f2));
    try testing.expectEqualStrings("done", c.get("full", 0, 0).?);
    try testing.expectEqualStrings("B", c.get("bystander", 0, 0).?);
    try testing.expectEqual(@as(usize, 0), c.stats.pinned);
}

test "a replace whose value dupe fails drops the key rather than serving pre-write bytes" {
    // `put` over a resident key is the write-through refresh `pagecache` does
    // AFTER the durable write has landed, and it cannot report failure. When
    // the value dupe failed, the old value stayed in the map: the next read
    // was a HIT on pre-write bytes, indefinitely -- a silently stale cache
    // over correct media. `max_bytes` refusal three branches up already
    // reasons this out and calls `dropKey`; the allocator path did not.
    var hits: usize = 0;
    var failures: usize = 0;
    for (0..4) |n| {
        var fa = std.testing.FailingAllocator.init(testing.allocator, .{});
        var c = Cache.init(fa.allocator(), .{ .max_bytes = 1 << 20, .max_entries = 16 });
        defer c.deinit();
        c.put("page", "OLDOLDOLD", 0, 0, 0);
        c.put("bystander", "B", 0, 0, 0);
        fa.fail_index = fa.alloc_index + n;

        c.put("page", "NEWNEWNEW", 0, 0, 0);
        if (c.get("page", 0, 0)) |v| {
            // Present: it must be the value we just wrote, never the old one.
            try testing.expectEqualStrings("NEWNEWNEW", v);
            hits += 1;
        } else {
            // Absent is the correct degradation: a miss re-reads media.
            failures += 1;
        }
    }
    // Both outcomes have to occur, or the sweep proves nothing: all-hits would
    // mean no rung ever failed, all-misses that the write never lands.
    try testing.expect(hits > 0);
    try testing.expect(failures > 0);
}

test "removeMatching removes exactly the prefix, and nothing else" {
    var c = Cache.init(testing.allocator, .{ .max_bytes = 1 << 20, .max_entries = 64 });
    defer c.deinit();
    // Two "handles" sharing the cache, plus a key that merely shares a byte.
    c.put("\x01\x00page0", "a", 0, 0, 0);
    c.put("\x01\x00page1", "b", 0, 0, 0);
    c.put("\x01\x00page2", "c", 0, 0, 0);
    c.put("\x02\x00page0", "d", 0, 0, 0);
    c.put("\x01", "short", 0, 0, 0); // shorter than the prefix: not a match

    try testing.expectEqual(@as(usize, 3), c.removeMatching("\x01\x00"));
    try testing.expect(c.get("\x01\x00page0", 0, 0) == null);
    try testing.expect(c.get("\x01\x00page1", 0, 0) == null);
    try testing.expect(c.get("\x01\x00page2", 0, 0) == null);
    try testing.expectEqualStrings("d", c.get("\x02\x00page0", 0, 0).?);
    try testing.expectEqualStrings("short", c.get("\x01", 0, 0).?);
    // Idempotent, and an empty prefix is the whole cache.
    try testing.expectEqual(@as(usize, 0), c.removeMatching("\x01\x00"));
    try testing.expectEqual(@as(usize, 2), c.removeMatching(""));
}

test "removeMatching: match counts on and past the batch size are all removed, the rest kept" {
    const rb = Cache.remove_batch;
    for ([_]usize{ rb - 1, rb, rb + 1, 2 * rb + 7 }) |m| {
        var c = Cache.init(testing.allocator, .{ .max_bytes = 1 << 22, .max_entries = 4096 });
        defer c.deinit();
        var key: [5]u8 = undefined;
        for (0..m + 100) |i| {
            key[0] = if (i < m) 'a' else 'b';
            std.mem.writeInt(u32, key[1..5], @intCast(i), .little);
            c.put(&key, "v", 0, 0, 0);
        }
        try testing.expectEqual(m + 100, c.map.count());
        try testing.expectEqual(m, c.removeMatching("a"));
        try testing.expectEqual(@as(usize, 100), c.map.count());
        try testing.expectEqual(@as(usize, 0), c.removeMatching("a"));
    }
}

test "borrow: a reserve that fails leaves the caller's existing entry alone" {
    // Every early return in `reserve` is allocator-failure-only, so a failing
    // allocator is the only way to walk that ladder at all. Sweeping the fail
    // index takes it one rung at a time; the invariant under test is the same
    // on every rung — a refused reservation must not also evict, because the
    // caller is told "use the copying path" and has no way to notice that its
    // previous value left with the refusal.
    var failures: usize = 0;
    for (0..6) |n| {
        var fa = std.testing.FailingAllocator.init(testing.allocator, .{});
        var c = Cache.init(fa.allocator(), .{ .max_bytes = 1 << 20, .max_entries = 16 });
        defer c.deinit();
        c.put("k", "value", 0, 0, 0);
        c.put("bystander", "B", 0, 0, 0);
        fa.fail_index = fa.alloc_index + n; // the n-th allocation from here on fails

        if (c.reserve("k", 8, 0, 0, 0)) |f| {
            // This rung's allocation was not one `reserve` had to make.
            @memset(f.bytes, 'x');
            c.release(c.commit(f));
            continue;
        }
        failures += 1;
        // Spelled out rather than `.?` so that a reservation which failed AND
        // evicted reports itself as this test failing, not as a null unwrap.
        const kept = c.get("k", 0, 0) orelse return error.FailedReserveAlsoEvicted;
        try testing.expectEqualStrings("value", kept);
        const bystander = c.get("bystander", 0, 0) orelse return error.FailedReserveAlsoEvicted;
        try testing.expectEqualStrings("B", bystander);
    }
    // Guard against the whole sweep quietly becoming a no-op: several rungs
    // must really have failed for the assertions above to have meant anything.
    // Three since 2026-10-11 (parking slot, value, node with its key): the key
    // copy no longer is an allocation of its own.
    try testing.expect(failures >= 3);
}

test "on-evict: reserve over an existing key replaces it, and says so" {
    var sink: EvictSink = .{};
    var c = Cache.init(testing.allocator, .{
        .max_bytes = 1 << 20,
        .max_entries = 16,
        .on_evict = EvictSink.hook,
        .on_evict_ctx = &sink,
    });
    defer c.deinit();
    c.put("k", "old", 0, 0, 0);
    const f = c.reserve("k", 3, 0, 0, 0).?;
    @memcpy(f.bytes, "new");
    c.release(c.commit(f));

    try testing.expectEqual(@as(usize, 1), sink.len);
    try testing.expectEqualStrings("k", sink.recs[0].key());
    try testing.expectEqualStrings("old", sink.recs[0].val());
    // `.replaced` is only truthful because the drop now happens after the
    // last fallible step: something really did take the entry's place.
    try testing.expectEqual(EvictReason.replaced, sink.recs[0].reason);
    try testing.expectEqualStrings("new", c.get("k", 0, 0).?);
}

test "on-evict: an uncommitted reservation's uninitialized bytes never reach the hook" {
    var sink: EvictSink = .{};
    var c = Cache.init(testing.allocator, .{
        .max_bytes = 1 << 20,
        .max_entries = 16,
        .on_evict = EvictSink.hook,
        .on_evict_ctx = &sink,
    });
    defer c.deinit();

    // 1) overwritten between reserve and commit (fires from `doomEntry`)
    const f1 = c.reserve("half", 8, 0, 0, 0).?;
    c.put("half", "written", 0, 0, 0);
    try testing.expectEqual(@as(usize, 0), sink.len);
    c.discard(f1);

    // Positive control on the same hook, same key: a *filled* value does fire.
    try testing.expect(c.remove("half"));
    try testing.expectEqual(@as(usize, 1), sink.len);
    try testing.expectEqualStrings("written", sink.recs[0].val());

    // 2) removed between reserve and commit (fires from `dropKeyReason`)
    const f2 = c.reserve("gone", 8, 0, 0, 0).?;
    try testing.expect(c.remove("gone"));
    try testing.expectEqual(@as(usize, 1), sink.len);
    c.discard(f2);

    // 3) cleared between reserve and commit (fires from `clear`)
    const f3 = c.reserve("swept", 8, 0, 0, 0).?;
    c.clear();
    try testing.expectEqual(@as(usize, 1), sink.len);
    c.discard(f3);

    // 4) and once committed, the same entry is an ordinary one again.
    const f4 = c.reserve("full", 4, 0, 0, 0).?;
    @memcpy(f4.bytes, "abcd");
    c.release(c.commit(f4));
    c.clear();
    try testing.expectEqual(@as(usize, 2), sink.len);
    try testing.expectEqualStrings("abcd", sink.recs[1].val());
    try testing.expectEqual(EvictReason.cleared, sink.recs[1].reason);
}

test "borrow: isPinned tracks live borrows, and says false for a doomed entry" {
    var c = testCache(1 << 20, 16);
    defer c.deinit();
    try testing.expect(!c.isPinned("absent"));
    c.put("k", "v", 0, 0, 0);
    try testing.expect(!c.isPinned("k")); // resident, nobody borrowing

    const b = c.pin("k", 0, 0).?;
    try testing.expect(c.isPinned("k"));
    c.release(b);
    try testing.expect(!c.isPinned("k"));

    // The answer that is least obvious and most likely to be misread: a
    // doomed entry is *still borrowed*, but it is no longer in the map, so
    // this is false. A caller must not read that as "safe to free".
    const b2 = c.pin("k", 0, 0).?;
    try testing.expect(c.remove("k"));
    try testing.expect(!c.isPinned("k"));
    try testing.expectEqual(@as(usize, 1), c.stats.pinned); // ...while the borrow is very much alive
    try testing.expectEqualStrings("v", b2.bytes);
    c.release(b2);
    try testing.expectEqual(@as(usize, 0), c.stats.pinned);
}

// ── borrow-path accounting ──────────────────────────────────────────────────
//
// Parking a value moves it out of the cache's books and into a node's private
// ownership, so every counter the entry contributed to has to be given back.
// Getting that wrong is not cosmetic: `bytes` never comes down again, so
// `maintain` believes the cache is over `max_bytes` for the rest of its life
// and evicts on every single insert. Each test below therefore checks the
// counter *and* keeps an innocent bystander entry that a phantom over-count
// would evict — the counter alone would also be satisfied by a cache that
// zeroed everything.

test "borrow: parking a doomed value returns its bytes to the accounting" {
    // 100-byte budget, 40-byte values: two fit, three do not. If the doomed
    // 40 bytes stay counted, the second live entry pushes the *phantom* total
    // to 120 and the cache evicts to get back under the cap.
    var c = testCache(100, 16);
    defer c.deinit();
    c.put("a", strRepeat("A", 40), 0, 0, 0);
    const b = c.pin("a", 0, 0).?;
    c.put("a", strRepeat("B", 40), 0, 0, 0); // dooms the borrowed 40 bytes
    try testing.expectEqual(@as(usize, 40), c.bytes);

    c.put("bystander", strRepeat("C", 40), 0, 0, 0);
    try testing.expectEqual(@as(usize, 80), c.bytes);
    try testing.expectEqualStrings(strRepeat("C", 40), c.get("bystander", 0, 0).?);
    try testing.expectEqualStrings(strRepeat("B", 40), c.get("a", 0, 0).?);
    try testing.expectEqualStrings(strRepeat("A", 40), b.bytes);
    c.release(b);
    try testing.expectEqual(@as(usize, 80), c.bytes); // release frees, it does not un-count
}

test "borrow: parking a doomed value returns its region slot to the accounting" {
    var c = testCache(1 << 20, 16);
    defer c.deinit();
    c.put("a", "AAA", 0, 0, 0);
    c.put("b", "BBB", 0, 0, 0);
    const borrow = c.pin("a", 0, 0).?;
    c.put("a", "aaa", 0, 0, 0); // dooms the borrowed node, inserts a fresh one

    // The region counters partition the live map, and a doomed node is no
    // longer in it. This sum is the invariant `maintain`'s window/protected
    // loops are driven by; an entry counted twice makes them demote entries
    // that are not there.
    const regions = c.window_count + c.probation_count + c.protected_count;
    try testing.expectEqual(@as(usize, c.map.count()), regions);
    try testing.expectEqual(@as(usize, 2), regions);
    try testing.expectEqualStrings("AAA", borrow.bytes);
    c.release(borrow);
    try testing.expectEqual(@as(usize, c.map.count()), c.window_count + c.probation_count + c.protected_count);
}

test "borrow: a discarded reservation returns its bytes to the accounting" {
    var c = testCache(100, 16);
    defer c.deinit();
    c.put("keep", strRepeat("K", 40), 0, 0, 0);
    const f = c.reserve("tmp", 40, 0, 0, 0).?;
    try testing.expectEqual(@as(usize, 80), c.bytes);
    c.discard(f);
    try testing.expectEqual(@as(usize, 40), c.bytes);
    try testing.expectEqual(@as(usize, c.map.count()), c.window_count + c.probation_count + c.protected_count);

    // Bystander: a phantom 40 would put this insert at 120 and evict "keep".
    c.put("other", strRepeat("O", 40), 0, 0, 0);
    try testing.expectEqualStrings(strRepeat("K", 40), c.get("keep", 0, 0).?);
    try testing.expectEqualStrings(strRepeat("O", 40), c.get("other", 0, 0).?);
}

test "borrow: deinit frees values still parked for an outstanding borrow" {
    // Tearing the cache down mid-borrow is a caller bug, and this is the only
    // test in the repo that commits it — without one, `deinit`'s doomed sweep
    // could be deleted and `testing.allocator` would never see the leak.
    var c = testCache(1 << 20, 16);
    c.put("a", "AAA", 0, 0, 0);
    const b = c.pin("a", 0, 0).?;
    c.clear(); // parks the borrowed value with its node
    try testing.expectEqualStrings("AAA", b.bytes);
    try testing.expectEqual(@as(usize, 1), c.doomed.items.len);
    c.deinit(); // the oracle is `testing.allocator`: parked bytes must be freed
}

test "borrow: a doomed TTL node must not stall eviction" {
    // The shape that used to hang. A borrowed TTL entry is overwritten, so
    // its node is doomed; `parkNode` sets that node's key to `&.{}`. If the
    // node is also left in the expiry heap — which is exactly what deleting
    // `pinEntry`'s `expRemove` does — then `findExpiredKey` hands `evictStep`
    // a key `dropKey` cannot find. `evictStep` must not call that an
    // eviction: `maintain` loops until the cache is back under its cap, so a
    // branch that reports progress it did not make never terminates.
    //
    // Only the doomed node carries a TTL here, so it is the expiry heap's
    // root deterministically rather than by heap-order luck.
    var c = testCache(1 << 20, 2);
    defer c.deinit();

    c.put("k", "v", 0, 1_000, 0);
    const b = c.pin("k", 0, 0).?;
    c.put("k", "new", 0, 0, 0); // dooms the borrowed node; no TTL on the new one

    // Two inserts, both well past the doomed node's deadline and one past
    // the entry cap, so this pass consults the expiry heap and then has to
    // evict for real.
    c.put("x", "1", 5_000, 0, 0);
    c.put("y", "2", 5_000, 0, 0);

    // Terminated *and* evicted something real. The cap alone would also hold
    // for a cache that emptied itself, so the newest insert is the bystander:
    // it must still be resident.
    try testing.expectEqual(@as(u32, 2), c.map.count());
    try testing.expectEqualStrings("2", c.get("y", 5_000, 0).?);
    // ...and the borrower kept its snapshot the whole way through.
    try testing.expectEqualStrings("v", b.bytes);
    c.release(b);
}

/// The region counters and the region queues are two different structures over
/// the same entries, and they are read by different code: the counters drive
/// `maintain`'s window loop and `enforceProtectedCap`, while the queues decide
/// *which* entry those loops — and eviction — actually take. An entry counted
/// in one region but indexed in another therefore has no symptom in either
/// structure read on its own: the counters still partition the map, and every
/// queue is still a valid queue ordered by tick. This asserts the two name the
/// same entries, which is the property `release`'s re-file has to preserve.
fn expectRegionQueuesAgree(c: *Cache) !void {
    var live = [_]usize{ 0, 0, 0 }; // live map entries, by `Entry.region`
    var indexed = [_]usize{ 0, 0, 0 }; // ...of those, the ones a heap must hold
    var it = c.map.keyIterator();
    while (it.next()) |kv| {
        const r = @backingInt(kv.*.entry.node.region);
        live[r] += 1;
        // A borrowed node is deliberately out of both heaps (see `Node.pins`).
        if (kv.*.entry.node.pins == 0) indexed[r] += 1;
    }
    try testing.expectEqual(live[0], c.window_count);
    try testing.expectEqual(live[1], c.probation_count);
    try testing.expectEqual(live[2], c.protected_count);
    for (&c.lru, 0..) |*q, r| {
        try testing.expectEqual(indexed[r], q.len);
        var walked: usize = 0;
        var it_n = q.head;
        while (it_n) |n| : (it_n = n.next) {
            try testing.expect(n.queued);
            const e = c.entryOf(n.key) orelse return error.QueueHoldsAnUnmappedNode;
            try testing.expectEqual(@as(usize, r), @backingInt(e.node.region));
            walked += 1;
        }
        try testing.expectEqual(q.len, walked);
    }
}

test "borrow: release re-files the entry into its OWN region queue, from every region" {
    // `release` re-files an ended borrow with `lruPush(e.node.region, n)`. Pushing
    // it into a fixed region instead is a plausible refactor and a real bug —
    // heap membership diverging from the region the entry is *counted* in —
    // and it used to be invisible here: only `pagecache` failed, i.e. the rule
    // lived at the consumer, so this module was free to break it the moment
    // that consumer changed.
    //
    // A cache whose entries all sit in `.window` cannot see it: correct and
    // wrong agree exactly. So every borrow below is taken from an entry that
    // has genuinely reached the region under test, through the module's own
    // promotion path, and that is asserted before the pin — otherwise a future
    // change to the promotion policy would silently turn this into a tautology.
    var c = testCache(1 << 20, 3); // window cap 1, protected cap 1
    defer c.deinit();
    c.put("a", "A", 0, 0, 0);
    c.put("b", "B", 0, 0, 0);
    c.put("c", "C", 0, 0, 0); // window overflow demotes a, then b, to probation
    try expectRegionQueuesAgree(&c);

    // .window — the newest insert, still in the admission window.
    try testing.expectEqual(Cache.Region.window, c.entryOf("c").?.node.region);
    c.release(c.pin("c", 0, 0).?);
    try expectRegionQueuesAgree(&c);

    // .probation — demoted out of the window by `maintain`.
    try testing.expectEqual(Cache.Region.probation, c.entryOf("a").?.node.region);
    c.release(c.pin("a", 0, 0).?);
    try expectRegionQueuesAgree(&c);

    // .protected — promoted by the SLRU re-reference rule in `get`.
    _ = c.get("b", 0, 0).?;
    try testing.expectEqual(Cache.Region.protected, c.entryOf("b").?.node.region);
    try testing.expectEqual(@as(usize, 1), c.protected_count);
    c.release(c.pin("b", 0, 0).?);
    try expectRegionQueuesAgree(&c);
}

test "borrow: a released protected entry keeps its SLRU standing, so demotion takes the right victim" {
    // The consequence of the divergence above, observed through a bystander:
    // `enforceProtectedCap` picks its demotion victim from the protected heap
    // and counts it in `protected_count`. If a released protected entry is
    // filed anywhere else, the heap it should head is empty, and the demotion
    // falls on whichever entry *is* in there — the one just promoted for being
    // hot — while the entry that was actually least-recently-used keeps a
    // protected slot it is not in.
    var c = testCache(1 << 20, 3); // window cap 1, protected cap 1
    defer c.deinit();
    c.put("old", "O", 0, 0, 0);
    c.put("new", "N", 0, 0, 0);
    c.put("win", "W", 0, 0, 0);

    _ = c.get("old", 0, 0).?; // probation → protected
    try testing.expectEqual(Cache.Region.protected, c.entryOf("old").?.node.region);
    try testing.expectEqual(@as(usize, 1), c.protected_count);

    c.release(c.pin("old", 0, 0).?); // the borrow under test

    // "new" is re-referenced and promoted, which puts the protected region one
    // over its cap and forces exactly one demotion.
    _ = c.get("new", 0, 0).?;
    try testing.expectEqual(@as(usize, 1), c.protected_count);

    // The victim must be "old" (protected the longest ago), not the bystander
    // that just earned its place. Note both entries are still resident either
    // way, and both counters still partition the map either way — only *which*
    // entry was demoted differs.
    try testing.expectEqual(Cache.Region.protected, c.entryOf("new").?.node.region);
    try testing.expectEqual(Cache.Region.probation, c.entryOf("old").?.node.region);
    try expectRegionQueuesAgree(&c);
}

test "borrow: a released probation entry is still the region's eviction candidate" {
    // Same divergence, seen at the other structure that reads a heap root:
    // victim selection. The bystander here is a neighbour in the same region —
    // it survives when the released entry is where it belongs, and is evicted
    // in its place when it is not.
    var c = testCache(1 << 20, 3); // window cap 1
    defer c.deinit();
    c.put("lru", "L", 0, 0, 0);
    c.put("mru", "M", 0, 0, 0);
    c.put("win", "W", 0, 0, 0);
    try testing.expectEqual(Cache.Region.probation, c.entryOf("lru").?.node.region);
    try testing.expectEqual(Cache.Region.probation, c.entryOf("mru").?.node.region);

    c.release(c.pin("lru", 0, 0).?); // the borrow under test

    // The pin refreshed "lru"'s tick, so re-write the neighbour to put the
    // ordering back: "lru" is the probation LRU again, hence the victim.
    c.put("mru", "M2", 0, 0, 0);
    try testing.expect(c.entryOf("lru").?.node.tick < c.entryOf("mru").?.node.tick);

    // Borrow the sole window entry so the window heap is empty. That takes the
    // admission gate out of the eviction path entirely: with no candidate,
    // `evictOne` goes straight to the main region's LRU root, so the victim is
    // decided by heap membership alone and nothing here depends on frequency.
    const wb = c.pin("win", 0, 0).?;
    try testing.expectEqual(@as(usize, 0), c.lru[@backingInt(Cache.Region.window)].len);

    // A reservation is pinned from birth, so it adds pressure without adding a
    // window candidate: one entry over the cap, one eviction.
    const f = c.reserve("r", 1, 0, 0, 0).?;
    try testing.expectEqualStrings("M2", c.get("mru", 0, 0).?); // bystander survives
    try testing.expect(c.get("lru", 0, 0) == null); // the LRU went, as it should

    c.discard(f);
    c.release(wb);
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
    try testing.expect(!c.map.containsAdapted("a", Cache.KeyAdapter{})); // physically gone
    try testing.expect(c.map.containsAdapted("b", Cache.KeyAdapter{})); // sibling untouched
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
    // in the region queues rather than tripping over a stale node reference.
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

test "markCleanIf acks only the value that was flushed" {
    var c = testCache(1 << 20, 16);
    defer c.deinit();
    c.put("k", "v1", 0, 0, 0);
    // The flusher persisted "v1", but "v2" landed before its ack.
    c.put("k", "v2", 1, 0, 0);
    try testing.expect(!c.markCleanIf("k", "v1"));
    try testing.expect(c.isDirty("k")); // "v2" still owes a write
    try testing.expect(c.markCleanIf("k", "v2"));
    try testing.expect(!c.isDirty("k"));
    try testing.expect(!c.markCleanIf("nope", "v2")); // absent → false
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
        const key = std.mem.print(&kbuf, "other{d}", .{k}) catch unreachable;
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
        const key = std.mem.print(&kbuf, "hot{d}", .{i}) catch unreachable;
        c.put(key, "hotval", 0, 0, 0);
    }
    var round: usize = 0;
    while (round < 10) : (round += 1) {
        i = 0;
        while (i < 20) : (i += 1) {
            const key = std.mem.print(&kbuf, "hot{d}", .{i}) catch unreachable;
            try testing.expect(c.get(key, 1, 0) != null);
        }
    }
    // Scan burst: 150 distinct keys, each seen exactly once (get-miss + put).
    i = 0;
    while (i < 150) : (i += 1) {
        const key = std.mem.print(&kbuf, "scan{d}", .{i}) catch unreachable;
        try testing.expect(c.get(key, 2, 0) == null);
        c.put(key, "scanval", 2, 0, 0);
    }
    // Every hot key must have survived the scan.
    i = 0;
    while (i < 20) : (i += 1) {
        const key = std.mem.print(&kbuf, "hot{d}", .{i}) catch unreachable;
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
    const val = @as([64]u8, @splat(0xcd));
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
    // scan would make this ratio ~64; the slack is for the region queues being
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

    try testing.expect(!c.map.containsAdapted("doomed", Cache.KeyAdapter{}));
    try testing.expect(c.map.containsAdapted("newcomer", Cache.KeyAdapter{}));
    var zero_key: [8]u8 = undefined;
    std.mem.writeInt(u64, &zero_key, 0, .little);
    try testing.expect(c.map.containsAdapted(&zero_key, Cache.KeyAdapter{})); // the true LRU survived
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
        const key = std.mem.print(&kbuf, "k{d}", .{id}) catch unreachable;
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

// ── mutation run 2026-10-04: boundary and heap-order pins ───────────────────
//
// Each test kills mutants the earlier suite let survive (SPEC.md "Mutation
// run 2026-10-04"). The WHY of every expected value is stated per test.

test "TTL boundary: fresh at exactly ttl, expired one ns later; get, pin and the eviction pass agree" {
    // The module's predicate is `(now - inserted) > ttl` everywhere (the
    // expiry-heap comment in `findExpiredKey` says it is the same as the scan
    // it replaced), so now - inserted == ttl is still fresh.
    var c = testCache(1 << 20, 16);
    defer c.deinit();
    c.put("k", "v", 0, 100, 0);
    try testing.expect(c.get("k", 100, 0) != null);
    try testing.expect(c.get("k", 101, 0) == null);

    c.put("p", "v", 0, 100, 0);
    const b = c.pin("p", 100, 0).?;
    c.release(b);
    try testing.expect(c.pin("p", 101, 0) == null);

    // The eviction pass must not call an entry expired that `get` still serves.
    // cap 2: B (no ttl) -> probation, A (ttl 100) stays in the window and gets hot.
    var d = testCache(1 << 20, 2);
    defer d.deinit();
    d.put("B", "b", 0, 0, 0);
    d.put("A", "a", 0, 100, 0);
    var i: usize = 0;
    while (i < 4) : (i += 1) _ = d.get("A", 50, 0);
    // Pressure at now == A's deadline: candidate A (freq 5) beats victim B
    // (freq 1), so B goes. If A were treated as expired it would go instead.
    d.put("C", "c", 100, 0, 0);
    try testing.expect(d.get("A", 100, 0) != null);
    try testing.expect(d.get("B", 100, 0) == null);
}

test "generation 0 is immune to generation bumps for pin as well as get" {
    // Documented on `put`: `gen == 0` = TTL-only, not invalidated by a bump.
    var c = testCache(1 << 20, 16);
    defer c.deinit();
    c.put("k", "v", 0, 0, 0);
    const b = c.pin("k", 1, 7).?;
    c.release(b);
    try testing.expectEqualStrings("v", c.get("k", 1, 7).?);
}

test "a value of exactly max_bytes is stored (only a LARGER one is refused): insert, replace, reserve" {
    // Doc on `Options.max_bytes`: "An item larger than this is never stored".
    var c = testCache(8, 16);
    defer c.deinit();
    c.put("k", "12345678", 0, 0, 0);
    try testing.expectEqualStrings("12345678", c.get("k", 1, 0).?);
    c.put("k", "abcdefgh", 0, 0, 0); // replace path
    try testing.expectEqualStrings("abcdefgh", c.get("k", 1, 0).?);
    c.put("k", "123456789", 0, 0, 0); // one byte over: dropped, not served stale
    try testing.expect(c.get("k", 1, 0) == null);

    var d = testCache(8, 16);
    defer d.deinit();
    const f = d.reserve("r", 8, 0, 0, 0).?;
    d.discard(f);
    try testing.expect(d.reserve("r", 9, 0, 0, 0) == null);
}

test "region sizes: the window is ~1% and the protected segment 80% of the main region" {
    // `windowCap` doc: "~1% of capacity (min 1)"; `protectedCap` doc: "80% of
    // the main (non-window) region".
    var c = testCache(1 << 20, 300);
    defer c.deinit();
    var kbuf: [16]u8 = undefined;
    var i: usize = 0;
    while (i < 10) : (i += 1) c.put(std.mem.print(&kbuf, "k{d}", .{i}) catch unreachable, "v", 0, 0, 0);
    try testing.expectEqual(@as(usize, 3), c.window_count); // 300 / 100
    try testing.expectEqual(@as(usize, 7), c.probation_count);

    var d = testCache(1 << 20, 100);
    defer d.deinit();
    i = 0;
    while (i < 100) : (i += 1) d.put(std.mem.print(&kbuf, "k{d}", .{i}) catch unreachable, "v", 0, 0, 0);
    i = 0;
    while (i < 100) : (i += 1) _ = d.get(std.mem.print(&kbuf, "k{d}", .{i}) catch unreachable, 1, 0);
    // window 1, main 99, protected cap 99 * 4 / 5 = 79; the rest demoted to probation.
    try testing.expectEqual(@as(usize, 1), d.window_count);
    try testing.expectEqual(@as(usize, 79), d.protected_count);
    try testing.expectEqual(@as(usize, 20), d.probation_count);
}

test "admit: a frequency tie is broken by a ~1/128 coin, and only for candidates with estimate >= 6" {
    // `admit` doc: "A moderately warm candidate (estimate >= 6) occasionally
    // wins a tie via a deterministic ~1/128 coin"; cold candidates never do.
    var c = testCache(1 << 20, 16);
    defer c.deinit();
    c.noteAccess("init"); // creates the sketch
    const s = &c.sketch.?;
    var i: usize = 0;
    while (i < 6) : (i += 1) {
        s.record("warm-cand");
        s.record("warm-vict");
    }
    i = 0;
    while (i < 5) : (i += 1) {
        s.record("cool-cand");
        s.record("cool-vict");
    }
    try testing.expectEqual(@as(u64, 6), s.estimate("warm-cand"));
    try testing.expectEqual(@as(u64, 6), s.estimate("warm-vict"));
    try testing.expectEqual(@as(u64, 5), s.estimate("cool-cand"));
    try testing.expectEqual(@as(u64, 5), s.estimate("cool-vict"));

    var warm_wins: usize = 0;
    var cool_wins: usize = 0;
    i = 0;
    while (i < 64_000) : (i += 1) {
        if (c.admit("warm-cand", "warm-vict")) warm_wins += 1;
        if (c.admit("cool-cand", "cool-vict")) cool_wins += 1;
    }
    try testing.expectEqual(@as(usize, 0), cool_wins);
    // Expected 64000 / 128 = 500, sd ~22: a 1/64 or 1/256 coin lands far outside.
    try testing.expect(warm_wins > 300 and warm_wins < 700);
}

test "sketch reset halves every 4-bit counter independently and clears the doorkeeper" {
    var s = try FrequencySketch.init(testing.allocator, 16);
    defer s.deinit(testing.allocator);
    // nibbles (low to high): 3, 1 | 0, 15. floor(3/2)=1, floor(1/2)=0, 0, floor(15/2)=7.
    s.counters[0] = 0x13;
    s.counters[1] = 0xF0;
    s.doorkeeper[0] = 0xFF;
    s.samples = 10;
    s.reset();
    try testing.expectEqual(@as(u64, 0x01), s.counters[0]); // a carry from the next nibble would give 0x09
    try testing.expectEqual(@as(u64, 0x70), s.counters[1]);
    try testing.expectEqual(@as(u64, 0), s.doorkeeper[0]);
    try testing.expectEqual(@as(u64, 5), s.samples);
}

test "a huge TTL saturates the deadline instead of overflowing (insert, replace, release)" {
    // `+|` is deliberate: a practically-infinite TTL must not trap in a safe build.
    const huge = std.math.maxInt(i64);
    var c = testCache(1 << 20, 16);
    defer c.deinit();
    c.put("k", "v", 1000, huge, 0);
    c.put("k", "w", 2000, huge, 0);
    try testing.expectEqualStrings("w", c.get("k", 3000, 0).?);
    const b = c.pin("k", 3000, 0).?;
    c.release(b);
    try testing.expectEqualStrings("w", c.get("k", 4000, 0).?);
}

test "replacing a TTL entry with ttl 0 removes it from the expiry heap (it never expires by time)" {
    // Doc on `put`: ttl_ns <= 0 = no time expiry. A stale heap node would make
    // the eviction pass drop the entry as "expired" under later pressure.
    var c = testCache(1 << 20, 2);
    defer c.deinit();
    c.put("k", "v", 0, 100, 0);
    c.put("k", "w", 10, 0, 0);
    c.put("X", "x", 10, 0, 0); // k -> probation, X in the window
    c.put("Y", "y", 1000, 0, 0); // pressure at now = 1000: window candidate X (freq 1) loses to k (freq 2)
    try testing.expectEqualStrings("w", c.get("k", 1000, 0).?);
    try testing.expect(c.get("X", 1000, 0) == null);
}

test "eviction terminates even when the chosen victim key is not in the map (progress guard)" {
    // `evictStep` doc: "true has to mean an entry was actually removed" -- a
    // node whose key the map does not hold must end the loop, not spin it.
    // Corrupt a window node's key on purpose; without the guard `maintain`
    // loops forever (the harness kills a hang at 20 s).
    var c = testCache(1 << 20, 4);
    defer c.deinit();
    c.put("a", "1", 0, 0, 0);
    c.put("b", "2", 0, 0, 0); // a -> probation, b stays in the window
    c.options.max_entries = 1;
    const node = c.entryOf("b").?.node;
    const real_key = node.key;
    node.key = &.{};
    c.maintain(0);
    node.key = real_key;
    try testing.expectEqual(@as(usize, 2), c.map.count()); // nothing was removable
}

test "removeMatching removes a key equal to the prefix too" {
    // "every resident entry whose key starts with `prefix`": a key equal to the prefix does.
    var c = testCache(1 << 20, 16);
    defer c.deinit();
    c.put("ab", "1", 0, 0, 0);
    c.put("abc", "2", 0, 0, 0);
    c.put("b", "3", 0, 0, 0);
    try testing.expectEqual(@as(usize, 2), c.removeMatching("ab"));
    try testing.expect(c.get("ab", 1, 0) == null);
    try testing.expect(c.get("abc", 1, 0) == null);
    try testing.expectEqualStrings("3", c.get("b", 1, 0).?);
}

fn expectQueuesOrdered(c: *Cache) !void {
    // Each region queue: links consistent both ways, ticks strictly rising
    // head to tail (the recency order the head is picked by).
    for (&c.lru) |*q| {
        var prev: ?*Cache.Node = null;
        var it_n = q.head;
        var walked: usize = 0;
        while (it_n) |n| : (it_n = n.next) {
            try testing.expect(n.queued);
            try testing.expectEqual(prev, n.prev);
            if (prev) |p| try testing.expect(p.tick < n.tick);
            prev = n;
            walked += 1;
        }
        try testing.expectEqual(prev, q.tail);
        try testing.expectEqual(q.len, walked);
    }
    for (c.exp.items, 0..) |n, i| {
        try testing.expectEqual(@as(u32, @intCast(i)), n.exp_idx);
        if (i > 0) try testing.expect(c.exp.items[(i - 1) / 2].deadline <= n.deadline);
    }
}

test "random put/get/remove/replace sequences keep every region queue and the expiry heap ordered" {
    // A heap whose root is not the minimum silently evicts the wrong entry, so
    // the min-heap property (parent <= child on tick / deadline) and the
    // back-pointers are checked after EVERY operation. Fixed LCG, 48 keys in a
    // 100-entry cache: no eviction, so all three regions fill and entries move
    // between them.
    var c = testCache(1 << 20, 100);
    defer c.deinit();
    var state: u64 = 0x1234_5678_9ABC_DEF0;
    var now: i64 = 0;
    var kbuf: [16]u8 = undefined;
    var step: usize = 0;
    while (step < 4000) : (step += 1) {
        state = state *% 6364136223846793005 +% 1442695040888963407;
        const r = state >> 33;
        const key = std.mem.print(&kbuf, "k{d}", .{r % 48}) catch unreachable;
        now += @intCast(r % 7);
        switch ((r >> 8) % 5) {
            0, 1 => c.put(key, "v", now, if ((r >> 12) % 3 == 0) 0 else @as(i64, @intCast(20 + (r >> 14) % 400)), 0),
            2, 3 => _ = c.get(key, now, 0),
            else => _ = c.remove(key),
        }
        try expectQueuesOrdered(&c);
    }
}

// ── time-to-idle (2026-10-11) ───────────────────────────────────────────────
//
// Anchor: Caffeine `expireAfterAccess` / otter `ExpiryAccessing`
// (otter `expiry_calculator.go:108-126`): expire a fixed time after creation,
// replacement of the value, or the last read.

fn idleCache(idle_ns: i64, max_entries: usize) Cache {
    return Cache.init(testing.allocator, .{ .max_bytes = 1 << 20, .max_entries = max_entries, .idle_ttl_ns = idle_ns });
}

test "idle ttl: a hit refreshes the deadline, silence expires the entry, and it counts as expired" {
    var c = idleCache(100, 16);
    defer c.deinit();
    c.put("k", "v", 0, 0, 0);
    try testing.expect(c.get("k", 100, 0) != null); // exactly at the limit: still fresh (strict >)
    // 200 ns after the write but only 100 after the last read. RED if a hit
    // does not refresh the idle deadline.
    try testing.expect(c.get("k", 200, 0) != null);
    try testing.expectEqual(@as(u64, 0), c.stats.expired);
    try testing.expect(c.get("k", 301, 0) == null); // 101 ns of silence
    try testing.expectEqual(@as(u64, 1), c.stats.expired);
    try testing.expectEqual(@as(usize, 0), c.stats.entries);
    try testing.expectEqual(@as(u64, 1), c.stats.misses);
}

test "idle ttl: a put over the key refreshes the deadline too" {
    var c = idleCache(100, 16);
    defer c.deinit();
    c.put("p", "v", 1000, 0, 0);
    c.put("p", "w", 1090, 0, 0);
    // 180 after the first write, 90 after the rewrite.
    try testing.expectEqualStrings("w", c.get("p", 1180, 0).?);
}

test "idle ttl: the effective deadline is the earlier of the write TTL and the idle deadline" {
    var c = idleCache(100, 16);
    defer c.deinit();
    // Write TTL 300 binds although the entry is read every 90 ns.
    c.put("t", "v", 0, 300, 0);
    try testing.expect(c.get("t", 90, 0) != null);
    try testing.expect(c.get("t", 180, 0) != null);
    try testing.expect(c.get("t", 270, 0) != null);
    try testing.expect(c.get("t", 301, 0) == null); // 31 ns idle, but 301 > ttl 300
    // Idle binds although the write TTL is far away.
    c.put("i", "v", 1000, 100_000, 0);
    try testing.expect(c.get("i", 1101, 0) == null);
    try testing.expectEqual(@as(u64, 2), c.stats.expired);
}

test "idle ttl: eviction takes an idle-expired entry before the frequency contest" {
    var c = idleCache(100, 2);
    defer c.deinit();
    c.put("a", "1", 0, 0, 0);
    c.put("b", "2", 50, 0, 0); // a -> probation, b is the window candidate
    // At 120, "a" has been silent for 120 > 100 and "b" for 70. Without
    // idle-aware expiry the contest is b (candidate) against a (victim): a tie,
    // so b is rejected and a survives.
    c.put("c", "3", 120, 0, 0);
    try testing.expect(!c.map.containsAdapted("a", Cache.KeyAdapter{}));
    try testing.expect(c.map.containsAdapted("b", Cache.KeyAdapter{}));
    try testing.expect(c.map.containsAdapted("c", Cache.KeyAdapter{}));
    try testing.expectEqual(@as(u64, 0), c.stats.rejections);
    try testing.expectEqual(@as(u64, 0), c.stats.admissions);
    try testing.expectEqual(@as(u64, 1), c.stats.evictions);
}

test "idle ttl: a hit moves the entry's place in the expiry heap, so the NEXT one expires first" {
    var c = idleCache(100, 2);
    defer c.deinit();
    c.put("a", "1", 0, 0, 0);
    c.put("b", "2", 10, 0, 0);
    _ = c.get("a", 90, 0); // a: deadline 190 (was 100); b stays at 110
    try expectQueuesOrdered(&c);
    try expectExpiryAgrees(&c);
    // At 150 only b is idle-expired. RED if the hit left a's old deadline in
    // the heap: a would be the root and would be evicted instead.
    c.put("c", "3", 150, 0, 0);
    try testing.expect(c.map.containsAdapted("a", Cache.KeyAdapter{}));
    try testing.expect(!c.map.containsAdapted("b", Cache.KeyAdapter{}));
}

test "idle ttl: pin counts as an access and release re-files the entry under the new deadline" {
    var c = idleCache(100, 16);
    defer c.deinit();
    c.put("k", "v", 0, 0, 0);
    const b = c.pin("k", 90, 0).?;
    try expectExpiryAgrees(&c); // borrowed: not in the heap
    c.release(b);
    try expectExpiryAgrees(&c); // back, at 90 + 100
    try testing.expectEqual(@as(i64, 190), c.entryOf("k").?.node.deadline);
    try testing.expect(c.get("k", 180, 0) != null); // 90 since the pin; 180 since the write
    // And a borrow held across the deadline does not make the entry immortal:
    const b2 = c.pin("k", 200, 0).?;
    c.release(b2);
    try testing.expect(c.get("k", 301, 0) == null);
}

test "idle ttl: off by default, and a non-positive value is off exactly like default_ttl_ns" {
    for ([_]i64{ 0, -5 }) |idle| {
        var c = idleCache(idle, 16);
        defer c.deinit();
        c.put("k", "v", 0, 0, 0);
        try testing.expect(c.get("k", 1 << 50, 0) != null);
        try testing.expectEqual(@as(u64, 0), c.stats.expired);
        try testing.expectEqual(Cache.Node.not_queued, c.entryOf("k").?.node.exp_idx);
    }
}

test "idle ttl: random put/get/remove sequences agree with a naive model of write TTL + idle TTL" {
    // The model is the definition, written out: an entry is fresh iff it is
    // within its write TTL and within `idle` of its last read or write. The
    // cache is big enough that nothing is ever evicted, so every difference
    // is an expiry difference. Time advances by 0..5 ns per step against an idle
    // limit of 37 and write TTLs of 20..79: a key is touched about every 15
    // steps (~37 ns), so both sides of both limits are crossed constantly.
    const idle: i64 = 37;
    const nkeys = 12;
    var c = idleCache(idle, 64);
    defer c.deinit();
    const M = struct { present: bool = false, inserted: i64 = 0, ttl: i64 = 0, last: i64 = 0, val: u8 = 0 };
    var model: [nkeys]M = @splat(.{});
    var state: u64 = 0xC0FFEE_1234_5678;
    var now: i64 = 0;
    var kbuf: [8]u8 = undefined;
    var hits: usize = 0;
    var idle_only: usize = 0;
    for (0..6000) |step| {
        state = state *% 6364136223846793005 +% 1442695040888963407;
        const r = state >> 33;
        now += @intCast(r % 6);
        const ki: usize = @intCast((r >> 5) % nkeys);
        const key = std.mem.print(&kbuf, "k{d}", .{ki}) catch unreachable;
        const m = &model[ki];
        switch ((r >> 12) % 5) {
            0, 1 => {
                const ttl: i64 = if ((r >> 16) & 1 == 0) 0 else @intCast(20 + (r >> 17) % 60);
                const val: u8 = @intCast(step % 251);
                c.put(key, &[_]u8{val}, now, ttl, 0);
                m.* = .{ .present = true, .inserted = now, .ttl = ttl, .last = now, .val = val };
            },
            2, 3 => {
                const got = c.get(key, now, 0);
                if (m.present) {
                    const ttl_dead = m.ttl > 0 and now - m.inserted > m.ttl;
                    const idle_dead = now - m.last > idle;
                    if (ttl_dead or idle_dead) {
                        if (!ttl_dead) idle_only += 1;
                        try testing.expect(got == null);
                        m.present = false;
                    } else {
                        try testing.expectEqual(m.val, got.?[0]);
                        m.last = now;
                        hits += 1;
                    }
                } else {
                    try testing.expect(got == null);
                }
            },
            else => {
                try testing.expectEqual(m.present, c.remove(key));
                m.present = false;
            },
        }
        try expectQueuesOrdered(&c);
        try expectExpiryAgrees(&c);
    }
    // The run has to have crossed the boundary it claims to: hits that were
    // saved by a refresh, and entries lost to idleness alone.
    try testing.expect(hits > 200);
    try testing.expect(idle_only > 50);
    try testing.expect(c.stats.expired > 50);
}

// ── getOrLoad on the single-owner Cache ─────────────────────────────────────

const CountingLoader = struct {
    calls: u32 = 0,
    fail: bool = false,

    fn load(ctx: ?*anyopaque, gpa: std.mem.Allocator, key: []const u8) LoadError![]u8 {
        const self: *CountingLoader = @ptrCast(@alignCast(ctx.?));
        self.calls += 1;
        if (self.fail) return error.LoadFailed;
        const out = try gpa.alloc(u8, key.len + 1);
        out[0] = '=';
        @memcpy(out[1..], key);
        return out;
    }

    fn loader(self: *CountingLoader) Loader {
        return .{ .ctx = self, .load = load };
    }
};

test "Cache.getOrLoad: a miss loads and stores, a hit copies, an error stores nothing" {
    var c = testCache(1 << 20, 16);
    defer c.deinit();
    var cl: CountingLoader = .{};

    const a = try c.getOrLoad(testing.allocator, "x", 0, 0, 0, 0, cl.loader());
    defer testing.allocator.free(a);
    try testing.expectEqualStrings("=x", a);
    try testing.expectEqual(@as(u32, 1), cl.calls);
    const b = try c.getOrLoad(testing.allocator, "x", 1, 0, 0, 0, cl.loader());
    defer testing.allocator.free(b);
    try testing.expectEqualStrings("=x", b);
    try testing.expectEqual(@as(u32, 1), cl.calls); // served from the cache
    try testing.expect(a.ptr != b.ptr); // the caller's own copy, not cache storage

    cl.fail = true;
    try testing.expectError(error.LoadFailed, c.getOrLoad(testing.allocator, "y", 2, 0, 0, 0, cl.loader()));
    try testing.expect(c.get("y", 3, 0) == null);
    try testing.expectEqual(@as(u32, 2), cl.calls);
}

test "Cache.getOrLoad: the stored entry carries the given ttl and generation" {
    var c = testCache(1 << 20, 16);
    defer c.deinit();
    var cl: CountingLoader = .{};
    testing.allocator.free(try c.getOrLoad(testing.allocator, "x", 1000, 0, 100, 5, cl.loader()));
    try testing.expect(c.get("x", 1100, 5) != null); // 100 old: fresh
    try testing.expect(c.get("x", 1101, 5) == null); // ttl 100 passed
    testing.allocator.free(try c.getOrLoad(testing.allocator, "x", 2000, 0, 100, 5, cl.loader()));
    try testing.expect(c.get("x", 2001, 6) == null); // generation bumped
}

// ── adaptive window (hill climber) ──────────────────────────────────────────
//
// Anchor: otter v2.3.0 `policy.go` (constants 30-35, `determineAdjustment`
// 389-423, `increaseWindow` 449, `decreaseWindow` 495), see the comment on
// `Cache.climbIfDue` for what was kept and changed.

test "adaptive_window off (the default): the window stays ~1 % and the climber never runs" {
    var c = Cache.init(testing.allocator, .{ .max_bytes = 1 << 30, .max_entries = 200 });
    defer c.deinit();
    var kbuf: [16]u8 = undefined;
    for (0..20_000) |i| {
        const key = std.mem.print(&kbuf, "k{d}", .{(i * 7919) % 900}) catch unreachable;
        if (c.get(key, 0, 0) == null) c.put(key, "v", 0, 0, 0);
    }
    try testing.expectEqual(@as(u64, 0), c.climbs);
    try testing.expectEqual(@as(usize, 2), c.windowCap());
    try testing.expect(c.window_count <= 2);
}

fn expectAdaptiveInvariants(c: *Cache) !void {
    try expectQueuesOrdered(c);
    try expectRegionQueuesAgree(c);
    try testing.expectEqual(
        @as(usize, c.map.count()),
        c.window_count + c.probation_count + c.protected_count,
    );
    // The limit stays inside its bounds, and the regions inside the limits.
    try testing.expect(c.window_adapt >= 1);
    try testing.expect(c.window_adapt <= c.windowBound());
    try testing.expect(c.window_count <= c.windowCap());
    try testing.expect(c.protected_count <= c.protectedCap());
}

test "adaptive window: random get/put/remove keep every structural invariant while the window moves" {
    var c = Cache.init(testing.allocator, .{
        .max_bytes = 1 << 30,
        .max_entries = 100,
        .adaptive_window = true,
        .idle_ttl_ns = 400,
    });
    defer c.deinit();
    var state: u64 = 0x5EED_CAFE_0011_2233;
    var now: i64 = 0;
    var kbuf: [16]u8 = undefined;
    var lo: usize = c.window_adapt;
    var hi: usize = c.window_adapt;
    for (0..120_000) |_| {
        state = state *% 6364136223846793005 +% 1442695040888963407;
        const r = state >> 33;
        now += @intCast(r % 3);
        const key = std.mem.print(&kbuf, "k{d}", .{(r >> 4) % 300}) catch unreachable;
        switch ((r >> 20) % 10) {
            0, 1 => c.put(key, "v", now, if ((r >> 24) % 4 == 0) 150 else 0, 0),
            2 => _ = c.remove(key),
            else => if (c.get(key, now, 0) == null) c.put(key, "v", now, 0, 0),
        }
        lo = @min(lo, c.window_adapt);
        hi = @max(hi, c.window_adapt);
        try expectAdaptiveInvariants(&c);
        try expectExpiryAgrees(&c);
    }
    // Reach: the climber ran, and it actually moved the window.
    try testing.expect(c.climbs > 10);
    try testing.expect(hi > lo);
}

const TraceKind = enum { recency, zipf };

const TraceResult = struct { overall: f64, late: f64, window: usize };

/// Replay one deterministic synthetic trace through a 200-entry cache
/// (lookup, `put` on a miss) and report the hit rate over the whole run and
/// over its second half (where the climber has had time to settle).
fn replayTrace(kind: TraceKind, adaptive: bool) !TraceResult {
    const cap = 200;
    const ops: usize = 80_000;
    var c = Cache.init(testing.allocator, .{ .max_bytes = 1 << 30, .max_entries = cap, .adaptive_window = adaptive });
    defer c.deinit();

    const universe = 5000;
    var cdf: [universe]f64 = undefined;
    var total: f64 = 0;
    for (&cdf, 0..) |*slot, i| {
        total += 1.0 / @as(f64, @floatFromInt(i + 1)); // zipf, s = 1.0
        slot.* = total;
    }

    var state: u64 = 0xA5A5_1234_DEAD_BEEF;
    var next_new: u64 = 0;
    var hits: usize = 0;
    var late_hits: usize = 0;
    var kbuf: [24]u8 = undefined;
    for (0..ops) |i| {
        state = state *% 6364136223846793005 +% 1442695040888963407;
        const r = state >> 33;
        const id: u64 = switch (kind) {
            // Pure recency: half the accesses bring a never-seen key, half
            // re-reference one of the last 100 new keys (half the cache),
            // uniformly. Plain LRU would hit on every re-reference. A
            // frequency gate with a 2-entry window rejects nearly every new
            // key at the window's exit -- each has been seen once or twice,
            // the main region's victims at least as often -- so a fixed
            // window re-hits almost nothing.
            .recency => blk: {
                if (r & 1 == 0 or next_new < 100) {
                    next_new += 1;
                    break :blk next_new - 1;
                }
                break :blk next_new - 1 - (r >> 1) % 100;
            },
            // Frequency-skewed: zipf over 5000 keys.
            .zipf => blk: {
                const u = @as(f64, @floatFromInt(r & 0xFFFFFF)) / @as(f64, 0x1000000) * total;
                var lo: usize = 0;
                var hi: usize = universe - 1;
                while (lo < hi) {
                    const mid = (lo + hi) / 2;
                    if (cdf[mid] < u) lo = mid + 1 else hi = mid;
                }
                break :blk lo;
            },
        };
        const key = std.mem.print(&kbuf, "k{d}", .{id}) catch unreachable;
        if (c.get(key, 0, 0) != null) {
            hits += 1;
            if (i >= ops / 2) late_hits += 1;
        } else {
            c.put(key, "v", 0, 0, 0);
        }
    }
    return .{
        .overall = @as(f64, @floatFromInt(hits)) / @as(f64, ops),
        .late = @as(f64, @floatFromInt(late_hits)) / @as(f64, ops / 2),
        .window = c.window_adapt,
    };
}

test "adaptive window: on a recency-skewed trace it beats the fixed window by a wide margin" {
    const fixed = try replayTrace(.recency, false);
    const adaptive = try replayTrace(.recency, true);
    std.testing.expect(adaptive.late > fixed.late + 0.10) catch |err| {
        std.debug.print(
            "recency trace, second half: fixed {d:.4} (overall {d:.4}), adaptive {d:.4} (overall {d:.4}), adaptive window {d}\n",
            .{ fixed.late, fixed.overall, adaptive.late, adaptive.overall, adaptive.window },
        );
        return err;
    };
    // ...because the climber really did grow the window.
    try testing.expect(adaptive.window > 20);
}

test "adaptive window: on a frequency-skewed (zipf) trace it is no worse than the fixed window by 1 point" {
    const fixed = try replayTrace(.zipf, false);
    const adaptive = try replayTrace(.zipf, true);
    std.testing.expect(adaptive.overall + 0.01 >= fixed.overall) catch |err| {
        std.debug.print(
            "zipf trace: fixed {d:.4}, adaptive {d:.4} (overall), adaptive window {d}\n",
            .{ fixed.overall, adaptive.overall, adaptive.window },
        );
        return err;
    };
}

/// Comptime string repetition; replaces the `**` operator removed in Zig 0.17.
inline fn strRepeat(comptime s: []const u8, comptime n: usize) *const [s.len * n:0]u8 {
    const rep_result = comptime blk: {
        @setEvalBranchQuota(n * (s.len + 4) + 1000);
        var buf: [s.len * n:0]u8 = undefined;
        for (0..n) |i| @memcpy(buf[i * s.len ..][0..s.len], s);
        const rep_final = buf;
        break :blk rep_final;
    };
    return &rep_result;
}
