// SPDX-License-Identifier: MIT

//! pool — a poisoning node pool. **Mechanical**, plus it carries the
//! in-tree *use-after-free teeth* for this module: because sanitizers are
//! not usable here (TSan/ASan link libc, violating the zero-libc invariant —
//! and a TSan smoke probe on this toolchain silently failed to flag a blatant
//! data race; see SPEC §"Verification"), a UAF in the reclamation core cannot
//! be caught by a sanitizer. So the pool compensates: every freed node is
//! overwritten with a `0xA5` poison pattern and pushed onto a free list that
//! `acquire` **reuses first**. A reclamation bug that hands a node back to the
//! allocator while a thread still dereferences it will therefore (a) read a
//! recognizable poison value — `0xA5A5…`, whose high tag bits are never a
//! valid producer id, so the harness's multiset checker flags it as
//! `Corrupted` — and/or (b) trip `verifyQuiescent`, which asserts every node
//! sitting on the free list still holds intact poison.
//!
//! Concurrency: the pool IS shared mutable state — producers `acquire`
//! concurrently with each other and with reclaim-path `release`s, all racing
//! on `free_head` and on the `all` list. EBR only guarantees that a given
//! *node*'s handoff is quiescent; it says nothing about the pool's own
//! bookkeeping. (The scaffold originally claimed the pool needed no internal
//! synchronization — that was a latent data race; the gated stress test
//! drives `acquire` from 8 producer threads at once.) A `SpinLock` therefore
//! guards every entry point. Its release/acquire pair also carries the
//! happens-before edge for node memory handoff between a freeing thread and
//! the next acquiring thread, so the poison write, the poison check and the
//! new owner's initialization never race.
//!
//! The lock makes `acquire`/`release` not lock-free; node allocation never
//! was (it can hit the general-purpose allocator). The lock-free guarantees
//! of the queue concern its head/tail/next CAS loops, not allocation.
//!
//! Per-thread caches (2026-10-14): `acquireCached`/`releaseCached` keep freed
//! nodes in a caller-owned `Cache` and take the lock once per `cache_batch`
//! nodes. One lock per node was the unbounded queue's bottleneck (58 % of a
//! 4×4 run in `acquire` + `release`, 10× crossbeam's `SegQueue`). The lock
//! still carries the cross-thread node handoff: a node only changes threads
//! through a spill and a refill, both under it.

const std = @import("std");
const atomic = @import("atomic.zig");

/// The byte the free list is poisoned with. Chosen so a `u64` view reads as
/// `0xA5A5A5A5A5A5A5A5`, whose top 16 bits (`0xA5A5`) exceed any realistic
/// producer id — the harness recognizes it as corruption, not a live value.
pub const poison_byte: u8 = 0xA5;

pub const Error = error{
    /// A node on the free list no longer holds intact poison — something
    /// wrote to it after it was freed (a use-after-free), or the pool is
    /// corrupt. This is the canary tripping.
    CanaryTripped,
};

/// A pool of `T` nodes with poison-on-free and free-list reuse. `T` must be a
/// struct (the node type); the pool never interprets its fields.
pub fn NodePool(comptime T: type) type {
    return struct {
        const Self = @This();

        /// One backing slot. `next_free` links it into the free stack while
        /// retired; `live` tracks whether the slot is currently handed out
        /// (bookkeeping for `verifyQuiescent`).
        const Slot = struct {
            node: T,
            next_free: ?*Slot,
            live: bool,
        };

        allocator: std.mem.Allocator,
        /// LIFO free list — reused before allocating fresh, so a UAF reliably
        /// lands on a poisoned, still-referenced slot.
        free_head: ?*Slot,
        /// Every slot ever allocated, for teardown + `verifyQuiescent` sweep.
        all: std.ArrayListUnmanaged(*Slot),
        /// Guards `free_head`/`all` and orders node-memory handoff across
        /// threads (see the file doc comment).
        lock: atomic.SpinLock,
        /// Per-participant caches, chunk by chunk (see `cacheAt`). A chunk
        /// pointer is written once, under `lock`, and read without it.
        caches: [max_cache_chunks]std.atomic.Value(?*CacheChunk),

        pub fn init(allocator: std.mem.Allocator) Self {
            return .{
                .allocator = allocator,
                .free_head = null,
                .all = .empty,
                .lock = .{},
                .caches = @splat(.init(null)),
            };
        }

        pub fn deinit(self: *Self) void {
            for (&self.caches) |*c| if (c.load(.monotonic)) |chunk| self.allocator.destroy(chunk);
            for (self.all.items) |slot| self.allocator.destroy(slot);
            self.all.deinit(self.allocator);
            self.* = undefined;
        }

        fn slotOf(node: *T) *Slot {
            return @fieldParentPtr("node", node);
        }

        /// Hand out a node — reusing a freed (poisoned) slot first. On reuse
        /// the slot's poison is verified intact BEFORE the node is returned,
        /// so a UAF that corrupted a free-listed slot is caught at the next
        /// `acquire` even if `verifyQuiescent` is never called. Mechanical.
        pub fn acquire(self: *Self) (Error || std.mem.Allocator.Error)!*T {
            self.lock.lock();
            defer self.lock.unlock();
            if (self.free_head) |slot| {
                try checkPoison(slot);
                self.free_head = slot.next_free;
                slot.next_free = null;
                slot.live = true;
                return &slot.node;
            }
            // `all` is the *only* record of a slot's existence — `deinit`'s
            // destroy sweep walks nothing else — so growing it must happen
            // BEFORE the slot exists. The obvious `create` + `append` order
            // leaks: `create` succeeds, the independent `append` fails, and the
            // fresh slot is then unreachable from `all` for the rest of the
            // pool's life. Reserving first leaves no fallible step between the
            // allocation and the record of it.
            try self.all.ensureUnusedCapacity(self.allocator, 1);
            const slot = try self.allocator.create(Slot);
            slot.* = .{ .node = undefined, .next_free = null, .live = true };
            self.all.appendAssumeCapacity(slot);
            return &slot.node;
        }

        /// Retire a node: poison its bytes and push it on the free list.
        /// Mechanical. (The *decision* that it is safe to do this — that no
        /// thread can still reach the node — is EBR's job, not the pool's.)
        pub fn release(self: *Self, node: *T) void {
            const slot = slotOf(node);
            std.debug.assert(slot.live);
            self.lock.lock();
            defer self.lock.unlock();
            @memset(std.mem.asBytes(&slot.node), poison_byte);
            slot.live = false;
            slot.next_free = self.free_head;
            self.free_head = slot;
        }

        /// A per-thread node cache (a "magazine"): freed nodes a thread can
        /// take back without the pool's lock. The pool owns them, one per
        /// participant index (`cacheAt`), so a cache lives exactly as long as
        /// the nodes it holds. Owned by one thread at a time — the thread
        /// holding that participant slot, which hands it over with the slot;
        /// the lock is taken once per `cache_batch` nodes, to refill from or
        /// spill into the shared free list. Cached slots are poisoned and not
        /// `live`, exactly like free-listed ones, and `verifyQuiescent` checks
        /// them too. On its own cache line: neighbouring caches belong to
        /// different threads.
        pub const Cache = struct {
            pool: *Self align(atomic.cache_line),
            head: ?*Slot = null,
            len: usize = 0,
        };

        /// Nodes moved per refill/spill; a cache spills at twice this.
        pub const cache_batch = 64;
        /// Caches are allocated in chunks of this many, on first use, and
        /// never move. `cache_chunk * max_cache_chunks` indices are served;
        /// `cacheAt` returns null past that, and the caller falls back to the
        /// locked `acquire`/`release`.
        const cache_chunk = 64;
        const max_cache_chunks = 64;
        const CacheChunk = [cache_chunk]Cache;

        /// The cache for participant index `index`, allocated on first use;
        /// null when `index` is past the served range or the chunk cannot be
        /// allocated (the caller then uses the locked path — slower, same
        /// semantics).
        pub fn cacheAt(self: *Self, index: usize) ?*Cache {
            const ci = index / cache_chunk;
            if (ci >= max_cache_chunks) return null;
            // Acquire: pairs with the publishing release store below, so the
            // chunk's initialization is visible.
            const chunk = self.caches[ci].load(.acquire) orelse self.allocChunk(ci) orelse return null;
            return &chunk[index % cache_chunk];
        }

        fn allocChunk(self: *Self, ci: usize) ?*CacheChunk {
            self.lock.lock();
            defer self.lock.unlock();
            if (self.caches[ci].load(.monotonic)) |c| return c;
            const chunk = self.allocator.create(CacheChunk) catch return null;
            for (chunk) |*c| c.* = .{ .pool = self };
            self.caches[ci].store(chunk, .release);
            return chunk;
        }

        /// `acquire` through `c`: a cached node without the lock, else one
        /// locked refill of up to `cache_batch` nodes, else a fresh slot.
        /// The reused slot's poison is verified as in `acquire`.
        pub fn acquireCached(self: *Self, c: *Cache) (Error || std.mem.Allocator.Error)!*T {
            if (c.head == null) self.refill(c);
            const slot = c.head orelse return self.acquire();
            try checkPoison(slot);
            c.head = slot.next_free;
            c.len -= 1;
            slot.next_free = null;
            slot.live = true;
            return &slot.node;
        }

        /// `release` into `c`: poison, then keep the slot for this thread's
        /// next `acquireCached`; spill `cache_batch` slots to the shared free
        /// list once `c` holds twice that.
        pub fn releaseCached(self: *Self, c: *Cache, node: *T) void {
            const slot = slotOf(node);
            std.debug.assert(slot.live);
            @memset(std.mem.asBytes(&slot.node), poison_byte);
            slot.live = false;
            slot.next_free = c.head;
            c.head = slot;
            c.len += 1;
            if (c.len >= 2 * cache_batch) self.spill(c, cache_batch);
        }

        /// Hand every slot in `c` back to the shared free list.
        pub fn flushCache(self: *Self, c: *Cache) void {
            self.spill(c, c.len);
        }

        fn refill(self: *Self, c: *Cache) void {
            self.lock.lock();
            defer self.lock.unlock();
            var n: usize = 0;
            while (n < cache_batch) : (n += 1) {
                const slot = self.free_head orelse break;
                self.free_head = slot.next_free;
                slot.next_free = c.head;
                c.head = slot;
            }
            c.len += n;
        }

        fn spill(self: *Self, c: *Cache, n: usize) void {
            if (n == 0) return;
            // Cut the first `n` slots off the cache outside the lock (they are
            // ours), then splice them in front of the free list under it.
            const first = c.head.?;
            var last = first;
            for (1..n) |_| last = last.next_free.?;
            c.head = last.next_free;
            c.len -= n;
            self.lock.lock();
            defer self.lock.unlock();
            last.next_free = self.free_head;
            self.free_head = first;
        }

        /// Assert every node not handed out — on the free list or in any
        /// `Cache` — still holds intact poison. A use-after-free WRITE to a
        /// retired node flips a poison byte and is caught here.
        /// Deterministic; the harness calls it after a stress run drains the
        /// queue. This is the pool's canary. Quiescent only: it reads every
        /// slot's `live` flag, which cache owners write without the lock.
        pub fn verifyQuiescent(self: *Self) Error!void {
            self.lock.lock();
            defer self.lock.unlock();
            for (self.all.items) |slot| {
                if (!slot.live) try checkPoison(slot);
            }
        }

        fn checkPoison(slot: *Slot) Error!void {
            const bytes = std.mem.asBytes(&slot.node);
            for (bytes) |b| {
                if (b != poison_byte) return Error.CanaryTripped;
            }
        }
    };
}

// ── tests (mechanical + the deterministic canary teeth; all run today) ───────

const testing = std.testing;

const TestNode = struct {
    value: u64,
    next: ?*TestNode,
};

test "acquire/release round-trips and reuses freed slots" {
    var pool = NodePool(TestNode).init(testing.allocator);
    defer pool.deinit();

    const a = try pool.acquire();
    a.* = .{ .value = 1, .next = null };
    pool.release(a);

    // Reuse: the freed slot comes back (free list is LIFO, single slot).
    const b = try pool.acquire();
    try testing.expectEqual(a, b); // same backing slot reused
    try pool.verifyQuiescent(); // nothing on the free list now
}

test "verifyQuiescent passes for a properly poisoned free list" {
    var pool = NodePool(TestNode).init(testing.allocator);
    defer pool.deinit();
    const a = try pool.acquire();
    const b = try pool.acquire();
    pool.release(a);
    pool.release(b);
    try pool.verifyQuiescent(); // both freed slots hold intact poison
}

test "CANARY TEETH: a use-after-free write to a freed node is caught" {
    var pool = NodePool(TestNode).init(testing.allocator);
    defer pool.deinit();

    const a = try pool.acquire();
    a.* = .{ .value = 42, .next = null };
    pool.release(a); // `a` is now poisoned and on the free list

    // Simulate a use-after-free: a stale thread writes through the dangling
    // pointer. A correct reclamation scheme guarantees this never happens;
    // the poison canary exists to catch it when it does.
    a.value = 0xDEADBEEF;

    // The canary must trip — deterministically, every run.
    try testing.expectError(error.CanaryTripped, pool.verifyQuiescent());
}

test "CANARY TEETH: a UAF is also caught at the next acquire, not just the sweep" {
    var pool = NodePool(TestNode).init(testing.allocator);
    defer pool.deinit();
    const a = try pool.acquire();
    pool.release(a);
    a.next = a; // stale write corrupts the poisoned slot
    try testing.expectError(error.CanaryTripped, pool.acquire());
}

test "acquire leaks no slot when the allocator fails part-way through" {
    // The defect: `acquire` used to `create(Slot)` and only then `append` the
    // pointer to `self.all`. Those are two independent allocations; when the
    // second failed, the freshly created slot was never recorded, and
    // `deinit`'s destroy sweep — which walks `self.all` and nothing else —
    // could never find it again. Exactly one leaked `Slot` per pool, on
    // exactly the sweep index where the *append's* growth is the failing
    // allocation.
    //
    // The sweep drives every fail index a growing pool can reach, so it does
    // not depend on knowing which one that is; the whole point is that one of
    // them used to end with `allocations - deallocations == 1`.
    var idx: usize = 0;
    while (idx < 24) : (idx += 1) {
        var failing = std.testing.FailingAllocator.init(testing.allocator, .{ .fail_index = idx });
        const gpa = failing.allocator();
        {
            var pool = NodePool(TestNode).init(gpa);
            defer pool.deinit();
            // Acquire until the induced failure hits (or the budget is spent);
            // `release` first so some rounds also exercise the free-list path.
            var n: usize = 0;
            while (n < 16) : (n += 1) {
                const node = pool.acquire() catch break;
                if (n % 3 == 2) pool.release(node);
            }
        }
        try testing.expectEqual(failing.allocations, failing.deallocations);
    }
}

// ── per-participant caches ───────────────────────────────────────────────────

test "cache: a released node comes back from the same cache without the free list" {
    var pool = NodePool(TestNode).init(testing.allocator);
    defer pool.deinit();
    const c = pool.cacheAt(3).?;
    try testing.expectEqual(&pool, c.pool);
    try testing.expectEqual(c, pool.cacheAt(3).?); // stable

    const a = try pool.acquireCached(c); // empty cache, empty free list: fresh
    pool.releaseCached(c, a);
    try testing.expectEqual(@as(usize, 1), c.len);
    try testing.expectEqual(@as(?*NodePool(TestNode).Slot, null), pool.free_head);
    try testing.expectEqual(a, try pool.acquireCached(c));
    try testing.expectEqual(@as(usize, 0), c.len);
}

test "cache: spills a batch to the free list at twice the batch, and another cache refills from it" {
    const P = NodePool(TestNode);
    var pool = P.init(testing.allocator);
    defer pool.deinit();
    const c0 = pool.cacheAt(0).?;
    const c1 = pool.cacheAt(1).?;

    var nodes: [2 * P.cache_batch]*TestNode = undefined;
    for (&nodes) |*n| n.* = try pool.acquireCached(c0);
    for (nodes[0 .. nodes.len - 1]) |n| pool.releaseCached(c0, n);
    try testing.expectEqual(nodes.len - 1, c0.len); // below the spill mark
    pool.releaseCached(c0, nodes[nodes.len - 1]);
    try testing.expectEqual(@as(usize, P.cache_batch), c0.len); // spilled one batch

    // c1 takes the spilled batch in one refill, then its own cache serves.
    _ = try pool.acquireCached(c1);
    try testing.expectEqual(@as(usize, P.cache_batch - 1), c1.len);
    try testing.expectEqual(@as(?*P.Slot, null), pool.free_head);
    try testing.expectEqual(nodes.len, pool.all.items.len); // nothing new allocated

    pool.flushCache(c0);
    try testing.expectEqual(@as(usize, 0), c0.len);
    try pool.verifyQuiescent();
}

test "CANARY TEETH: a use-after-free write to a node sitting in a cache is caught by the sweep and by the next acquire" {
    var pool = NodePool(TestNode).init(testing.allocator);
    defer pool.deinit();
    const c = pool.cacheAt(0).?;
    const a = try pool.acquireCached(c);
    pool.releaseCached(c, a);
    a.value = 0xDEADBEEF; // never reached the free list: only the cache holds it
    try testing.expectError(error.CanaryTripped, pool.verifyQuiescent());
    try testing.expectError(error.CanaryTripped, pool.acquireCached(c));
}

test "cacheAt past the served range is null, and the locked path still works" {
    const P = NodePool(TestNode);
    var pool = P.init(testing.allocator);
    defer pool.deinit();
    try testing.expect(pool.cacheAt(P.cache_chunk * P.max_cache_chunks) == null);
    try testing.expect(pool.cacheAt(P.cache_chunk * P.max_cache_chunks - 1) != null);
}

test "cacheAt: a chunk that cannot be allocated is null, not an error" {
    var failing = std.testing.FailingAllocator.init(testing.allocator, .{ .fail_index = 0 });
    var pool = NodePool(TestNode).init(failing.allocator());
    defer pool.deinit();
    try testing.expect(pool.cacheAt(0) == null);
}
