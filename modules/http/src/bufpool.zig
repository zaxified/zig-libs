// SPDX-License-Identifier: MIT

//! bufpool — a small, bounded, thread-safe pool of fixed-size byte slabs
//! shared by client connections.
//!
//! Motivation (P2 gateway path): a gateway that opens and tears down many
//! short-lived client connections — notably fresh HTTP/2 upstream dials
//! (`Client.connectH2c`, each of which otherwise `gpa.alloc`s a
//! read+write slab and frees it on close) — churns the allocator and, if
//! many connections are kept warm at once, pins one large slab per
//! connection permanently. A shared slab pool bounds that: a connection
//! checks a slab **out** for its lifetime and returns it **in** on close,
//! so the steady-state memory is `slab_size * (in-flight + retained_idle)`
//! rather than `slab_size * (every connection ever opened)`, and the
//! allocator sees `O(peak concurrency)` allocations instead of one per
//! dial.
//!
//! Sizing: every slab is exactly `slab_size` bytes — the pool serves ONE
//! size class (mixing sizes would defeat reuse). A consumer that wants two
//! shapes (e.g. plaintext vs. TLS-record buffers) uses two pools. For the
//! h2 client the natural size is `read_buffer_size + write_buffer_size`
//! (the layout `Client.connectH2c` splits its slab into); construct the
//! pool with that exact total and hand it to `Client.Options.buffer_pool`.
//! `max_idle_slabs` bounds retained idle memory: a slab returned when the
//! idle list is already full is freed instead of retained (a missed reuse,
//! never a leak). Checked-out slabs are never counted against the cap — the
//! cap governs only the *idle* reserve.
//!
//! Thread-safety: `acquire`/`release` are internally synchronized (a tight
//! `std.atomic.Mutex` spinlock — this repo's era of `std` has no
//! `std.Thread.Mutex`; the same idiom `Client`'s idle pool uses). No I/O or
//! allocation happens while the lock is held on the hot path: `acquire`
//! pops a pooled slab under the lock and only `gpa.alloc`s (on a miss)
//! after unlocking; `release` pushes under the lock or `gpa.free`s (when
//! full) after unlocking. `deinit` is not synchronized — call it only once
//! nothing else can touch the pool (mirrors `Client.deinit`).
//!
//! Contents are NOT zeroed on checkout: a byte-stream protocol overwrites
//! exactly the region it reads/writes and never reads back stale bytes, so
//! zeroing would only cost cycles. A consumer that needs a clean slab must
//! clear it itself.

const std = @import("std");
const Allocator = std.mem.Allocator;

pub const BufferPool = struct {
    gpa: Allocator,
    slab_size: usize,
    max_idle_slabs: usize,
    mutex: std.atomic.Mutex = .unlocked,
    idle: std.ArrayList([]u8) = .empty,

    /// Lifetime counters (monotonic, diagnostics + the reuse proof in
    /// tests). `checkouts` = total `acquire` calls; `reuses` = those served
    /// from the idle reserve; `allocs` = those that had to allocate
    /// (`checkouts - reuses`). A steady `allocs` across many dials is the
    /// pool doing its job.
    checkouts: std.atomic.Value(usize) = .init(0),
    reuses: std.atomic.Value(usize) = .init(0),
    allocs: std.atomic.Value(usize) = .init(0),

    /// `slab_size` is the exact length of every slab this pool serves;
    /// `max_idle_slabs` bounds how many freed slabs are retained for reuse
    /// (0 disables retention — every release frees, every acquire allocs).
    pub fn init(gpa: Allocator, slab_size: usize, max_idle_slabs: usize) BufferPool {
        std.debug.assert(slab_size != 0);
        return .{ .gpa = gpa, .slab_size = slab_size, .max_idle_slabs = max_idle_slabs };
    }

    /// Free every retained idle slab and the pool's own bookkeeping. Any
    /// slab still checked out is the caller's to release/free — `deinit`
    /// only owns the idle reserve. Not synchronized.
    pub fn deinit(p: *BufferPool) void {
        for (p.idle.items) |slab| p.gpa.free(slab);
        p.idle.deinit(p.gpa);
        p.* = undefined;
    }

    /// Check out a slab of exactly `slab_size` bytes: a retained idle one
    /// when available, otherwise a fresh allocation. The slab's contents are
    /// unspecified (see the module doc). Return it with `release` when done.
    pub fn acquire(p: *BufferPool) Allocator.Error![]u8 {
        _ = p.checkouts.fetchAdd(1, .monotonic);
        {
            lockSpin(&p.mutex);
            defer p.mutex.unlock();
            if (p.idle.pop()) |slab| {
                _ = p.reuses.fetchAdd(1, .monotonic);
                return slab;
            }
        }
        _ = p.allocs.fetchAdd(1, .monotonic);
        return p.gpa.alloc(u8, p.slab_size);
    }

    /// Return `slab` (must be one this pool handed out — exactly
    /// `slab_size`) to the idle reserve, or free it when the reserve is
    /// already at `max_idle_slabs` or its own bookkeeping cannot grow.
    /// Never fails, never leaks.
    pub fn release(p: *BufferPool, slab: []u8) void {
        std.debug.assert(slab.len == p.slab_size);
        var keep = false;
        {
            lockSpin(&p.mutex);
            defer p.mutex.unlock();
            if (p.idle.items.len < p.max_idle_slabs) {
                if (p.idle.append(p.gpa, slab)) |_| {
                    keep = true;
                } else |_| {
                    keep = false; // bookkeeping OOM: fall through to free
                }
            }
        }
        if (!keep) p.gpa.free(slab);
    }

    /// Retained idle slabs right now. Diagnostics/tests.
    pub fn idleCount(p: *BufferPool) usize {
        lockSpin(&p.mutex);
        defer p.mutex.unlock();
        return p.idle.items.len;
    }

    /// Total checkouts served from the idle reserve (reuse hits).
    pub fn reuseCount(p: *const BufferPool) usize {
        return p.reuses.load(.monotonic);
    }

    /// Total `acquire` calls over the pool's life.
    pub fn checkoutCount(p: *const BufferPool) usize {
        return p.checkouts.load(.monotonic);
    }

    /// Total checkouts that had to allocate (idle reserve was empty).
    pub fn allocCount(p: *const BufferPool) usize {
        return p.allocs.load(.monotonic);
    }
};

/// Spin until `m` is acquired (this repo's era of `std` has no
/// `std.Thread.Mutex`; same idiom as `Client`'s idle pool).
fn lockSpin(m: *std.atomic.Mutex) void {
    while (!m.tryLock()) std.atomic.spinLoopHint();
}

// ── tests ───────────────────────────────────────────────────────────────────

const testing = std.testing;

test "bufpool: acquire allocs on miss, release retains, acquire reuses" {
    var p = BufferPool.init(testing.allocator, 128, 4);
    defer p.deinit();

    const a = try p.acquire();
    try testing.expectEqual(@as(usize, 128), a.len);
    try testing.expectEqual(@as(usize, 1), p.checkoutCount());
    try testing.expectEqual(@as(usize, 0), p.reuseCount());
    try testing.expectEqual(@as(usize, 1), p.allocCount());
    try testing.expectEqual(@as(usize, 0), p.idleCount());

    p.release(a);
    try testing.expectEqual(@as(usize, 1), p.idleCount());

    const b = try p.acquire();
    // The retained slab came straight back (same backing memory).
    try testing.expectEqual(a.ptr, b.ptr);
    try testing.expectEqual(@as(usize, 1), p.reuseCount());
    try testing.expectEqual(@as(usize, 1), p.allocCount()); // still just the one alloc
    try testing.expectEqual(@as(usize, 0), p.idleCount());
    p.release(b);
}

test "bufpool: idle reserve is bounded by max_idle_slabs" {
    var p = BufferPool.init(testing.allocator, 64, 2);
    defer p.deinit();

    const s0 = try p.acquire();
    const s1 = try p.acquire();
    const s2 = try p.acquire();
    // All three checked out (idle empty), three allocs.
    try testing.expectEqual(@as(usize, 3), p.allocCount());

    p.release(s0);
    p.release(s1);
    p.release(s2); // over the cap of 2 → freed, not retained
    try testing.expectEqual(@as(usize, 2), p.idleCount());

    // Only two reuses are possible now; the third acquire allocs afresh.
    const r0 = try p.acquire();
    const r1 = try p.acquire();
    const r2 = try p.acquire();
    try testing.expectEqual(@as(usize, 2), p.reuseCount());
    try testing.expectEqual(@as(usize, 4), p.allocCount());
    p.release(r0);
    p.release(r1);
    p.release(r2);
}

test "bufpool: max_idle_slabs 0 disables retention" {
    var p = BufferPool.init(testing.allocator, 32, 0);
    defer p.deinit();
    const s = try p.acquire();
    p.release(s);
    try testing.expectEqual(@as(usize, 0), p.idleCount());
    const s2 = try p.acquire();
    try testing.expectEqual(@as(usize, 0), p.reuseCount());
    p.release(s2);
}

test "bufpool: reused slab is usable and carries no framing corruption" {
    var p = BufferPool.init(testing.allocator, 256, 2);
    defer p.deinit();

    // First "connection" scribbles all over its slab, then returns it.
    const first = try p.acquire();
    @memset(first, 0xAB);
    p.release(first);

    // Second checkout gets that same memory; a protocol overwrites exactly
    // the region it uses — prove a fresh, correct write is unaffected by the
    // stale bytes underneath.
    const second = try p.acquire();
    try testing.expectEqual(first.ptr, second.ptr);
    const msg = "clean framing after reuse";
    @memcpy(second[0..msg.len], msg);
    try testing.expectEqualStrings(msg, second[0..msg.len]);
    p.release(second);
}
