// SPDX-License-Identifier: MIT

//! harness — the teeth. Lock-free correctness is probabilistic under naive
//! stress, so this file engineers detection three independent ways, and
//! proves each layer bites BEFORE the real core exists:
//!
//!  1. **Deterministic checker teeth** (`verify` + the "CHECKER TEETH" test):
//!     the multiset invariant — every producer enqueues a disjoint tagged
//!     range `(pid,seq)`, and the dequeued multiset must equal the enqueued
//!     set — is validated against hand-built broken histories (a missing
//!     item, a duplicate, a corrupt tag). 100% deterministic; no threads.
//!
//!  2. **Driver teeth, high-probability** (`BrokenRing` + the "DRIVER TEETH"
//!     test): the concurrent stress driver is run against a deliberately
//!     racy queue (non-atomic head/tail indices) and must report corruption.
//!     Real threads in ReleaseFast; NOT deterministic — so the test runs
//!     several rounds and asserts detection in at least one, which is
//!     overwhelmingly certain at these thread/op counts (a single lossy round
//!     over hundreds of thousands of racing ops essentially never comes back
//!     clean). SPEC §Verification is explicit about this being probabilistic.
//!     `BrokenRing` corrupts via a bounded, masked index so it never derefs
//!     wild memory — it loses/duplicates data instead of crashing, which is
//!     what makes the teeth reliable rather than a segfault lottery.
//!
//!  3. **No-false-positive control** (`RefQueue` + the "ORACLE IS CLEAN"
//!     test): the same driver over a correct spinlock-guarded queue must come
//!     back `clean` — proving the harness does not cry wolf on correct code.
//!     `RefQueue` is also the linearizability oracle: a coarse-locked queue is
//!     trivially linearizable, so multiset-equality against it is a sound
//!     correctness check for the lock-free queue (full history/linearization
//!     checking is a documented next increment — SPEC).
//!
//! The use-after-free teeth live one layer down in `pool.zig` (poison +
//! canary), because sanitizers are unusable here (SPEC §Verification). The
//! gated tests at the bottom drive the REAL `MpmcQueue`+`Domain` once a Fable
//! agent fills the core in; today they SKIP.

const std = @import("std");
const gate = @import("gate.zig");
const atomic = @import("atomic.zig");
const pool = @import("pool.zig");
const ebr = @import("ebr.zig");
const mpmc = @import("mpmc.zig");

// ── tagged-value encoding: pid in the high 16 bits, seq in the low 48 ────────

const seq_bits: u6 = 48;
const seq_mask: u64 = (@as(u64, 1) << seq_bits) - 1;

fn encode(pid: usize, seq: u64) u64 {
    return (@as(u64, @intCast(pid)) << seq_bits) | (seq & seq_mask);
}
fn decodePid(v: u64) usize {
    return @intCast(v >> seq_bits);
}
fn decodeSeq(v: u64) u64 {
    return v & seq_mask;
}

pub const StressConfig = struct {
    producers: usize,
    consumers: usize,
    /// Items each producer enqueues (its disjoint tagged range `[0,n)`).
    per_producer: u64,
};

/// The outcome of a stress run's multiset check.
pub const Verdict = enum {
    /// Dequeued multiset == enqueued set. No lost/duplicated/corrupted items.
    clean,
    /// Fewer distinct items came out than went in (a node was dropped).
    lost,
    /// The same `(pid,seq)` came out more than once (double-free / ABA / a
    /// reclaimed-then-reused node aliasing a live one).
    duplicated,
    /// A value came out that was never enqueued (memory corruption / a read
    /// of a poisoned, reclaimed slot).
    corrupted,
};

pub const StressError = error{StressThreadFailed};

/// The multiset invariant checker. Adapter-independent and deterministic —
/// this is the piece the "CHECKER TEETH" test bites directly. Reports the
/// FIRST anomaly found (corrupted, then duplicated, then lost).
pub fn verify(
    cfg: StressConfig,
    lists: []const std.ArrayListUnmanaged(u64),
    allocator: std.mem.Allocator,
) std.mem.Allocator.Error!Verdict {
    const total = cfg.producers * cfg.per_producer;
    const seen = try allocator.alloc(bool, total);
    defer allocator.free(seen);
    @memset(seen, false);

    var count: u64 = 0;
    for (lists) |list| {
        for (list.items) |v| {
            const pid = decodePid(v);
            const seq = decodeSeq(v);
            if (pid >= cfg.producers or seq >= cfg.per_producer) return .corrupted;
            const idx = pid * cfg.per_producer + seq;
            if (seen[idx]) return .duplicated;
            seen[idx] = true;
            count += 1;
        }
    }
    if (count != total) return .lost;
    return .clean;
}

/// Generic concurrent stress driver over any queue `Adapter`. N producers
/// each push a disjoint tagged range; M consumers drain until every producer
/// has finished and the queue reads empty; the merged multiset is then
/// `verify`-checked. One driver serves the correct oracle, the broken control,
/// and (gated) the real queue.
///
/// An `Adapter` must provide: `const ThreadCtx`, `fn initThread(*Adapter)
/// !ThreadCtx`, `fn deinitThread(*Adapter, ThreadCtx) void`, `fn
/// enqueue(*Adapter, ThreadCtx, u64) !void`, `fn dequeue(*Adapter, ThreadCtx)
/// ?u64`.
pub fn runStress(
    comptime Adapter: type,
    adapter: *Adapter,
    cfg: StressConfig,
    allocator: std.mem.Allocator,
) !Verdict {
    return Runner(Adapter).run(adapter, cfg, allocator);
}

fn Runner(comptime Adapter: type) type {
    return struct {
        /// Consecutive empty dequeues (after all producers have finished)
        /// before a consumer concludes the queue is drained and exits. Large
        /// enough that a correct queue never exits with items still in flight,
        /// and that a racy queue's transient empties don't matter.
        const drain_threshold: u32 = 2048;

        const Shared = struct {
            adapter: *Adapter,
            producers_done: std.atomic.Value(usize),
            failed: std.atomic.Value(bool),
            per_producer: u64,
            producers: usize,
            allocator: std.mem.Allocator,
        };

        fn producerMain(sh: *Shared, pid: usize) void {
            const ctx = sh.adapter.initThread() catch {
                sh.failed.store(true, .release);
                _ = sh.producers_done.fetchAdd(1, .release);
                return;
            };
            defer sh.adapter.deinitThread(ctx);
            defer _ = sh.producers_done.fetchAdd(1, .release);

            var seq: u64 = 0;
            while (seq < sh.per_producer) : (seq += 1) {
                sh.adapter.enqueue(ctx, encode(pid, seq)) catch {
                    sh.failed.store(true, .release);
                    return;
                };
            }
        }

        fn consumerMain(sh: *Shared, list: *std.ArrayListUnmanaged(u64)) void {
            const ctx = sh.adapter.initThread() catch {
                sh.failed.store(true, .release);
                return;
            };
            defer sh.adapter.deinitThread(ctx);

            var backoff: atomic.Backoff = .{};
            var empty_run: u32 = 0;
            while (true) {
                if (sh.failed.load(.acquire)) return;
                if (sh.adapter.dequeue(ctx)) |v| {
                    list.append(sh.allocator, v) catch {
                        sh.failed.store(true, .release);
                        return;
                    };
                    empty_run = 0;
                    backoff.reset();
                } else {
                    // Only start counting toward "drained" once no producer can
                    // still add work; before that an empty read is transient.
                    if (sh.producers_done.load(.acquire) == sh.producers) {
                        empty_run += 1;
                        if (empty_run >= drain_threshold) return;
                    }
                    backoff.pause();
                }
            }
        }

        fn run(adapter: *Adapter, cfg: StressConfig, allocator: std.mem.Allocator) !Verdict {
            const total = cfg.producers * cfg.per_producer;

            var sh: Shared = .{
                .adapter = adapter,
                .producers_done = .init(0),
                .failed = .init(false),
                .per_producer = cfg.per_producer,
                .producers = cfg.producers,
                .allocator = allocator,
            };

            const lists = try allocator.alloc(std.ArrayListUnmanaged(u64), cfg.consumers);
            defer allocator.free(lists);
            for (lists) |*l| l.* = .empty;
            defer for (lists) |*l| l.deinit(allocator);
            // Pre-size to the whole run so a correct queue never reallocs in
            // the hot loop (a broken one may over-produce duplicates and grow).
            for (lists) |*l| try l.ensureTotalCapacity(allocator, total);

            const prods = try allocator.alloc(std.Thread, cfg.producers);
            defer allocator.free(prods);
            const cons = try allocator.alloc(std.Thread, cfg.consumers);
            defer allocator.free(cons);

            for (prods, 0..) |*t, pid| t.* = try std.Thread.spawn(.{}, producerMain, .{ &sh, pid });
            for (cons, 0..) |*t, cid| t.* = try std.Thread.spawn(.{}, consumerMain, .{ &sh, &lists[cid] });
            for (prods) |*t| t.join();
            for (cons) |*t| t.join();

            if (sh.failed.load(.acquire)) return StressError.StressThreadFailed;
            return verify(cfg, lists, allocator);
        }
    };
}

// ── the correct oracle: a coarse-spinlock queue (also the linearizability
//    reference) ────────────────────────────────────────────────────────────

pub const RefQueue = struct {
    const RNode = struct { value: u64, next: ?*RNode };

    lock: atomic.SpinLock = .{},
    head: ?*RNode = null,
    tail: ?*RNode = null,
    allocator: std.mem.Allocator,

    pub fn init(allocator: std.mem.Allocator) RefQueue {
        return .{ .allocator = allocator };
    }

    pub fn deinit(self: *RefQueue) void {
        var cur = self.head;
        while (cur) |n| {
            cur = n.next;
            self.allocator.destroy(n);
        }
        self.* = undefined;
    }

    pub fn enqueue(self: *RefQueue, v: u64) std.mem.Allocator.Error!void {
        const n = try self.allocator.create(RNode);
        n.* = .{ .value = v, .next = null };
        self.lock.lock();
        defer self.lock.unlock();
        if (self.tail) |t| {
            t.next = n;
            self.tail = n;
        } else {
            self.head = n;
            self.tail = n;
        }
    }

    pub fn dequeue(self: *RefQueue) ?u64 {
        self.lock.lock();
        const n = self.head orelse {
            self.lock.unlock();
            return null;
        };
        self.head = n.next;
        if (self.head == null) self.tail = null;
        self.lock.unlock();
        const v = n.value;
        self.allocator.destroy(n);
        return v;
    }
};

const RefAdapter = struct {
    q: *RefQueue,
    const ThreadCtx = void;
    fn initThread(self: *RefAdapter) !ThreadCtx {
        _ = self;
    }
    fn deinitThread(self: *RefAdapter, ctx: ThreadCtx) void {
        _ = self;
        _ = ctx;
    }
    fn enqueue(self: *RefAdapter, ctx: ThreadCtx, v: u64) !void {
        _ = ctx;
        try self.q.enqueue(v);
    }
    fn dequeue(self: *RefAdapter, ctx: ThreadCtx) ?u64 {
        _ = ctx;
        return self.q.dequeue();
    }
};

// ── the broken positive control: a racy ring with non-atomic indices ─────────

/// A deliberately-broken queue: plain (non-atomic) head/tail indices into a
/// fixed ring, no synchronization. Concurrent producers clobber the same slot
/// and lose increments; concurrent consumers re-read slots; overflow overwrites
/// live data — all manifesting as lost/duplicated/corrupted items the driver
/// catches. The masked index means it NEVER dereferences wild memory, so it
/// corrupts data instead of crashing (that is what makes the teeth reliable).
pub const BrokenRing = struct {
    const cap: usize = 1 << 14;
    const mask: usize = cap - 1;
    /// Poison so an unwritten/overwritten slot decodes as `corrupted`.
    const empty_poison: u64 = 0xA5A5_A5A5_A5A5_A5A5;

    buf: [cap]u64,
    head: usize,
    tail: usize,

    pub fn create(allocator: std.mem.Allocator) std.mem.Allocator.Error!*BrokenRing {
        const self = try allocator.create(BrokenRing);
        @memset(self.buf[0..], empty_poison);
        self.head = 0;
        self.tail = 0;
        return self;
    }

    pub fn destroy(self: *BrokenRing, allocator: std.mem.Allocator) void {
        allocator.destroy(self);
    }

    // Intentionally racy: no atomics, no lock.
    fn enqueue(self: *BrokenRing, v: u64) void {
        const t = self.tail;
        self.buf[t & mask] = v;
        self.tail = t + 1;
    }
    fn dequeue(self: *BrokenRing) ?u64 {
        const h = self.head;
        if (h == self.tail) return null;
        const v = self.buf[h & mask];
        self.head = h + 1;
        return v;
    }
};

const BrokenAdapter = struct {
    q: *BrokenRing,
    const ThreadCtx = void;
    fn initThread(self: *BrokenAdapter) !ThreadCtx {
        _ = self;
    }
    fn deinitThread(self: *BrokenAdapter, ctx: ThreadCtx) void {
        _ = self;
        _ = ctx;
    }
    fn enqueue(self: *BrokenAdapter, ctx: ThreadCtx, v: u64) !void {
        _ = ctx;
        self.q.enqueue(v);
    }
    fn dequeue(self: *BrokenAdapter, ctx: ThreadCtx) ?u64 {
        _ = ctx;
        return self.q.dequeue();
    }
};

// ── the real queue adapter (drives the gated Fable core) ─────────────────────

const MpmcAdapter = struct {
    q: *mpmc.MpmcQueue,
    domain: *ebr.Domain,
    const ThreadCtx = *ebr.Participant;
    fn initThread(self: *MpmcAdapter) !ThreadCtx {
        return self.domain.register();
    }
    fn deinitThread(self: *MpmcAdapter, ctx: ThreadCtx) void {
        self.domain.unregister(ctx);
    }
    fn enqueue(self: *MpmcAdapter, ctx: ThreadCtx, v: u64) !void {
        try self.q.enqueue(ctx, v);
    }
    fn dequeue(self: *MpmcAdapter, ctx: ThreadCtx) ?u64 {
        return self.q.dequeue(ctx);
    }
};

// ── tests ────────────────────────────────────────────────────────────────────

const testing = std.testing;

test "CHECKER TEETH: the multiset verifier rejects lost / duplicated / corrupt histories (deterministic)" {
    const cfg: StressConfig = .{ .producers = 2, .consumers = 1, .per_producer = 3 };
    const alloc = testing.allocator;

    // A complete, correct history: pids {0,1} × seq {0,1,2}.
    {
        var l: std.ArrayListUnmanaged(u64) = .empty;
        defer l.deinit(alloc);
        for ([_]usize{ 0, 1 }) |pid| {
            var s: u64 = 0;
            while (s < 3) : (s += 1) try l.append(alloc, encode(pid, s));
        }
        try testing.expectEqual(Verdict.clean, try verify(cfg, &.{l}, alloc));
    }
    // Missing (0,2) → lost.
    {
        var l: std.ArrayListUnmanaged(u64) = .empty;
        defer l.deinit(alloc);
        try l.appendSlice(alloc, &.{ encode(0, 0), encode(0, 1), encode(1, 0), encode(1, 1), encode(1, 2) });
        try testing.expectEqual(Verdict.lost, try verify(cfg, &.{l}, alloc));
    }
    // (1,0) twice → duplicated.
    {
        var l: std.ArrayListUnmanaged(u64) = .empty;
        defer l.deinit(alloc);
        try l.appendSlice(alloc, &.{ encode(0, 0), encode(0, 1), encode(0, 2), encode(1, 0), encode(1, 0), encode(1, 2) });
        try testing.expectEqual(Verdict.duplicated, try verify(cfg, &.{l}, alloc));
    }
    // A poison value that was never enqueued → corrupted.
    {
        var l: std.ArrayListUnmanaged(u64) = .empty;
        defer l.deinit(alloc);
        try l.appendSlice(alloc, &.{ encode(0, 0), 0xA5A5_A5A5_A5A5_A5A5, encode(0, 2), encode(1, 0), encode(1, 1), encode(1, 2) });
        try testing.expectEqual(Verdict.corrupted, try verify(cfg, &.{l}, alloc));
    }
}

test "ORACLE IS CLEAN: the driver reports `clean` over the correct spinlock queue (no false positive)" {
    const alloc = testing.allocator;
    var rq = RefQueue.init(alloc);
    defer rq.deinit();
    var adapter: RefAdapter = .{ .q = &rq };
    const v = try runStress(RefAdapter, &adapter, .{ .producers = 4, .consumers = 4, .per_producer = 8000 }, alloc);
    try testing.expectEqual(Verdict.clean, v);
}

test "DRIVER TEETH: the driver catches the racy BrokenRing (high probability)" {
    const alloc = testing.allocator;
    var detected = false;
    var round: usize = 0;
    // Overwhelmingly certain to trip on the first round; a few rounds make the
    // test robust rather than flaky (SPEC §Verification notes this is
    // probabilistic, unlike the deterministic CHECKER/ CANARY teeth).
    while (round < 6) : (round += 1) {
        const ring = try BrokenRing.create(alloc);
        defer ring.destroy(alloc);
        var adapter: BrokenAdapter = .{ .q = ring };
        const v = try runStress(BrokenAdapter, &adapter, .{ .producers = 6, .consumers = 6, .per_producer = 4000 }, alloc);
        if (v != .clean) {
            detected = true;
            break;
        }
    }
    try testing.expect(detected);
}

// ── gated: the real MPMC queue + EBR under stress (SKIP until Fable core) ────

test "REAL CORE: MPMC + EBR survive N×M stress with no lost/dup/corrupt and no UAF" {
    if (!gate.fable_core_implemented) return error.SkipZigTest;

    const alloc = testing.allocator;
    var domain = try ebr.Domain.init(alloc, .{ .max_participants = 32 });
    defer domain.deinit();
    var node_pool = mpmc.Pool.init(alloc);
    defer node_pool.deinit();
    var q = try mpmc.MpmcQueue.init(&node_pool, &domain);
    defer q.deinit();

    var adapter: MpmcAdapter = .{ .q = &q, .domain = &domain };
    const v = try runStress(MpmcAdapter, &adapter, .{ .producers = 8, .consumers = 8, .per_producer = 50_000 }, alloc);
    try testing.expectEqual(Verdict.clean, v);

    // Drain, quiesce, then the pool canary must show no use-after-free.
    try node_pool.verifyQuiescent();
}
