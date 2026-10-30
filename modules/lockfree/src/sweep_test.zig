// SPDX-License-Identifier: MIT

//! No-panic sweep tests (wave GU, findings LF-1 .. LF-5); see
//! ~/CML/20261029-panic-sweep/lockfree-sweep.report.md. Misuse is a checked
//! panic with a message: each one runs in a forked child whose stderr is
//! captured.

const std = @import("std");
const builtin = @import("builtin");
const linux = std.os.linux;
const testing = std.testing;
const ebr = @import("ebr.zig");
const pool = @import("pool.zig");
const atomic = @import("atomic.zig");
const bounded = @import("bounded.zig");
const deque = @import("deque.zig");
const mpmc = @import("mpmc.zig");
const harness = @import("harness.zig");

const gpa = std.heap.page_allocator;

const Child = struct { died: bool, len: usize };

var debug_info_warm = false;

/// Parse the executable's debug info once before the first fork: a child
/// that panics symbolizes its stack trace and would pay for it again.
fn warmDebugInfo() void {
    if (debug_info_warm) return;
    debug_info_warm = true;
    var buf: [256]u8 = undefined;
    var sink: std.Io.Writer.Discarding = .init(&buf);
    std.debug.writeCurrentStackTrace(.{}, .{ .writer = &sink.writer, .mode = .no_color }) catch {};
}

fn runChild(comptime body: fn () void, buf: []u8) !Child {
    if (builtin.os.tag != .linux) return error.SkipZigTest;
    warmDebugInfo();
    var fds: [2]i32 = undefined;
    if (linux.errno(linux.pipe2(&fds, .{})) != .SUCCESS) return error.SkipZigTest;
    const rc = linux.fork();
    if (linux.errno(rc) != .SUCCESS) return error.SkipZigTest;
    if (rc == 0) {
        _ = linux.dup2(fds[1], 2);
        _ = linux.close(fds[0]);
        _ = linux.close(fds[1]);
        const no_core: linux.rlimit = .{ .cur = 0, .max = 0 };
        _ = linux.setrlimit(.CORE, &no_core);
        body();
        linux.exit_group(0);
    }
    _ = linux.close(fds[1]);
    defer _ = linux.close(fds[0]);
    const pid: linux.pid_t = @intCast(rc);
    var status: u32 = 0;
    var waited_ms: usize = 0;
    while (true) {
        const r = linux.waitpid(pid, @ptrCast(&status), linux.W.NOHANG);
        if (linux.errno(r) != .SUCCESS) return error.WaitFailed;
        if (r == @as(usize, @intCast(pid))) break;
        if (waited_ms >= 5000) {
            _ = linux.kill(pid, .KILL);
            _ = linux.waitpid(pid, @ptrCast(&status), 0);
            return error.ChildHung;
        }
        const ts: linux.timespec = .{ .sec = 0, .nsec = 10 * std.time.ns_per_ms };
        _ = linux.nanosleep(&ts, null);
        waited_ms += 10;
    }
    const n = linux.read(fds[0], buf.ptr, buf.len);
    return .{ .died = linux.W.IFSIGNALED(status), .len = if (linux.errno(n) == .SUCCESS) n else 0 };
}

// Needles are the modules' own message constants, never string literals
// inline in the call: the child's stack trace prints the caller's source
// line, so an inline needle would match ANY panic.
fn expectPanicMessage(comptime body: fn () void, needle: []const u8) !void {
    var buf: [16384]u8 = undefined;
    const c = try runChild(body, &buf);
    try testing.expect(c.died);
    try testing.expect(std.mem.find(u8, buf[0..c.len], needle) != null);
}

// ── LF-1: EBR state misuse ──────────────────────────────────────────────────

fn freshDomain() struct { d: ebr.Domain, p: *ebr.Participant } {
    var d = ebr.Domain.init(gpa, .{ .max_participants = 1 }) catch @panic("init");
    const p = d.register() catch @panic("register");
    return .{ .d = d, .p = p };
}

fn enterTwice() void {
    var f = freshDomain();
    _ = f.d.enterCritical(f.p);
    _ = f.d.enterCritical(f.p);
}

fn exitUnpinned() void {
    var f = freshDomain();
    f.d.exitCritical(f.p);
}

fn exitTwice() void {
    var f = freshDomain();
    const g = f.d.enterCritical(f.p);
    g.release();
    g.release();
}

fn repinUnpinned() void {
    var f = freshDomain();
    f.d.repin(f.p);
}

fn noopReclaim(_: *anyopaque, _: *anyopaque) void {}

fn retireUnpinned() void {
    var f = freshDomain();
    var x: u8 = 0;
    f.d.retire(f.p, .{ .ptr = &x, .ctx = &x, .reclaim = noopReclaim });
}

fn unregisterPinned() void {
    var f = freshDomain();
    _ = f.d.enterCritical(f.p);
    f.d.unregister(f.p);
}

fn unregisterNested() void {
    var f = freshDomain();
    _ = f.d.enterCriticalNested(f.p);
    _ = f.d.enterCriticalNested(f.p);
    f.d.unregister(f.p);
}

test "enterCritical on a pinned participant panics (sweep LF-1a)" {
    try expectPanicMessage(enterTwice, ebr.msg_enter_pinned);
}

test "exitCritical on an unpinned participant panics (sweep LF-1b)" {
    try expectPanicMessage(exitUnpinned, ebr.msg_exit_unpinned);
}

test "a guard released twice panics (sweep LF-1c)" {
    try expectPanicMessage(exitTwice, ebr.msg_exit_unpinned);
}

test "repin on an unpinned participant panics (sweep LF-1d)" {
    try expectPanicMessage(repinUnpinned, ebr.msg_repin_unpinned);
}

test "retire on an unpinned participant panics (sweep LF-1e)" {
    try expectPanicMessage(retireUnpinned, ebr.msg_retire_unpinned);
}

test "unregister while pinned panics (sweep LF-1f)" {
    try expectPanicMessage(unregisterPinned, ebr.msg_unregister_pinned);
}

test "unregister while nested-pinned panics (sweep LF-1g)" {
    try expectPanicMessage(unregisterNested, ebr.msg_unregister_pinned);
}

test "EBR correct use still works: pin, nest, unpin, pin again, unregister (sweep LF-1)" {
    var d = try ebr.Domain.init(testing.allocator, .{ .max_participants = 1 });
    defer d.deinit();
    const p = try d.register();
    const g1 = d.enterCritical(p);
    const g2 = d.enterCriticalNested(p);
    g2.release();
    try testing.expect(p.isPinned());
    g1.release();
    try testing.expect(!p.isPinned());
    const g3 = d.enterCritical(p);
    g3.repin();
    g3.release();
    d.unregister(p);
    const q = try d.register();
    _ = d.enterCritical(q).release();
    d.unregister(q);
}

// ── LF-2: NodePool release of a node that is not live ───────────────────────

const PNode = struct { v: u64, next: ?*PNode };

fn releaseTwice() void {
    var np = pool.NodePool(PNode).init(gpa);
    const a = np.acquire() catch @panic("acquire");
    np.release(a);
    np.release(a);
}

fn releaseCachedTwice() void {
    var np = pool.NodePool(PNode).init(gpa);
    const c = np.cacheAt(0) orelse @panic("cache");
    const a = np.acquireCached(c) catch @panic("acquire");
    np.releaseCached(c, a);
    np.releaseCached(c, a);
}

test "NodePool.release twice panics (sweep LF-2a)" {
    try expectPanicMessage(releaseTwice, pool.msg_release_not_live);
}

test "NodePool.releaseCached twice panics (sweep LF-2b)" {
    try expectPanicMessage(releaseCachedTwice, pool.msg_release_not_live);
}

// ── LF-3: TaggedPtr tags that do not fit ────────────────────────────────────

const TP = atomic.TaggedPtr(u64);
const TA = atomic.TaggedAtomic(u64);

fn tagInit() void {
    _ = TP.init(null, TP.tag_mask + 1);
}
fn tagWith() void {
    _ = TP.null_ptr.withTag(TP.tag_mask + 1);
}
fn tagOr() void {
    var a: TA = .init(TP.null_ptr);
    _ = a.fetchOrTag(TP.tag_mask + 1, .monotonic);
}
fn tagAnd() void {
    var a: TA = .init(TP.null_ptr);
    _ = a.fetchAndTag(TP.tag_mask + 1, .monotonic);
}
fn tagXor() void {
    var a: TA = .init(TP.null_ptr);
    _ = a.fetchXorTag(TP.tag_mask + 1, .monotonic);
}

test "TaggedPtr.init oversized tag panics (sweep LF-3a)" {
    try expectPanicMessage(tagInit, TP.msg_tag_too_wide);
}

test "TaggedPtr.withTag oversized tag panics (sweep LF-3b)" {
    try expectPanicMessage(tagWith, TP.msg_tag_too_wide);
}

test "fetchOrTag oversized tag panics (sweep LF-3c)" {
    try expectPanicMessage(tagOr, TP.msg_tag_too_wide);
}

test "fetchAndTag oversized tag panics (sweep LF-3d)" {
    try expectPanicMessage(tagAnd, TP.msg_tag_too_wide);
}

test "fetchXorTag oversized tag panics (sweep LF-3e)" {
    try expectPanicMessage(tagXor, TP.msg_tag_too_wide);
}

// ── LF-4: BoundedQueue.advance with nothing published ───────────────────────

test "advance on an empty single-consumer ring is a no-op (sweep LF-4)" {
    var q: bounded.BoundedQueue(u64, 4, .{ .consumers = .single }) = undefined;
    q.init();
    q.advance();
    q.advance();
    try testing.expectEqual(@as(usize, 0), q.len());
    try testing.expectEqual(@as(?*u64, null), q.front());
    // Nothing was skipped or corrupted: the ring still fills and drains in order.
    for (0..4) |i| try testing.expect(q.push(i));
    try testing.expect(!q.push(9));
    for (0..4) |i| {
        try testing.expectEqual(@as(u64, i), q.front().?.*);
        q.advance();
    }
    q.advance();
    try testing.expectEqual(@as(?*u64, null), q.front());
    try testing.expect(q.push(7));
    try testing.expectEqual(@as(?u64, 7), q.pop());
}

// ── LF-5: stealBatch limit 0 / into itself ──────────────────────────────────

const D = deque.Deque(u64);

fn batchLimitZero() void {
    var a = D.init(gpa, 4) catch @panic("init");
    var b = D.init(gpa, 4) catch @panic("init");
    a.push(1) catch @panic("push");
    _ = a.stealBatchWithLimit(&b, 0) catch {};
}
fn batchLimitZeroPop() void {
    var a = D.init(gpa, 4) catch @panic("init");
    var b = D.init(gpa, 4) catch @panic("init");
    a.push(1) catch @panic("push");
    _ = a.stealBatchWithLimitAndPop(&b, 0) catch {};
}
fn batchIntoSelf() void {
    var a = D.init(gpa, 4) catch @panic("init");
    a.push(1) catch @panic("push");
    a.push(2) catch @panic("push");
    _ = a.stealBatch(&a) catch {};
}
fn injectorLimitZero() void {
    var inj = deque.Injector(u64).init(gpa) catch @panic("init");
    var b = D.init(gpa, 4) catch @panic("init");
    inj.push(1) catch @panic("push");
    _ = inj.stealBatchWithLimit(&b, 0) catch {};
}

test "deque stealBatchWithLimit limit 0 panics (sweep LF-5a)" {
    try expectPanicMessage(batchLimitZero, deque.msg_batch_limit_zero);
}
test "deque stealBatchWithLimitAndPop limit 0 panics (sweep LF-5b)" {
    try expectPanicMessage(batchLimitZeroPop, deque.msg_batch_limit_zero);
}
test "deque stealBatch into itself panics (sweep LF-5c)" {
    try expectPanicMessage(batchIntoSelf, deque.msg_batch_into_self);
}
test "injector stealBatchWithLimit limit 0 panics (sweep LF-5d)" {
    try expectPanicMessage(injectorLimitZero, deque.msg_batch_limit_zero);
}

test "stealBatch with a limit of 1 still works (sweep LF-5)" {
    var a = try D.init(testing.allocator, 4);
    defer a.deinit();
    var b = try D.init(testing.allocator, 4);
    defer b.deinit();
    try a.push(1);
    try a.push(2);
    try testing.expect((try a.stealBatchWithLimit(&b, 1)).isSuccess());
    try testing.expectEqual(@as(usize, 1), b.len());
}

test "injector stealBatchWithLimit with a limit of 1 still works (sweep audit GU-L1)" {
    var inj = try deque.Injector(u64).init(testing.allocator);
    defer inj.deinit();
    var b = try D.init(testing.allocator, 4);
    defer b.deinit();
    try inj.push(1);
    try inj.push(2);
    try testing.expect((try inj.stealBatchWithLimit(&b, 1)).isSuccess());
}

test "the wrong needle fails (the helper can fail)" {
    var buf: [16384]u8 = undefined;
    const c = try runChild(enterTwice, &buf);
    try testing.expect(c.died);
    try testing.expect(std.mem.find(u8, buf[0..c.len], deque.msg_batch_into_self) == null);
}

test "a tag that fits the alignment bits is kept (sweep LF-3)" {
    var x: u64 = 0;
    const ok = TP.init(&x, TP.tag_mask);
    try testing.expectEqual(TP.tag_mask, ok.tag());
    try testing.expectEqual(&x, ok.ptr().?);
}

// ── REV-lockfree-1/-2/-6 (blind-review fixes) ───────────────────────────────

test "mpmc enqueue/dequeue compose with a caller already pinned on the participant (sweep REV-lockfree-1)" {
    var d = try ebr.Domain.init(testing.allocator, .{ .max_participants = 1 });
    defer d.deinit();
    var np = mpmc.MpmcQueue.Pool.init(testing.allocator);
    defer np.deinit();
    var q = try mpmc.MpmcQueue.init(&np, &d);
    defer q.deinit();
    const p = try d.register();
    // Plain pin, then queue operations on the same participant.
    const outer = d.enterCritical(p);
    try q.enqueue(p, 7);
    try q.enqueue(p, 8);
    try testing.expectEqual(@as(?u64, 7), q.dequeue(p));
    // The inner operations must not have released the outer pin.
    try testing.expect(p.pinned);
    try testing.expect(p.isPinned());
    try testing.expectEqual(@as(u32, 0), p.nested_pins);
    try testing.expectEqual(@as(?u64, 8), q.dequeue(p));
    try testing.expectEqual(@as(?u64, null), q.dequeue(p));
    try testing.expect(p.pinned);
    outer.release();
    try testing.expect(!p.pinned);
    try testing.expect(!p.isPinned());
    // And unpinned use still works.
    try q.enqueue(p, 9);
    try testing.expectEqual(@as(?u64, 9), q.dequeue(p));
    d.unregister(p);
}

fn unregisterTwice() void {
    var f = freshDomain();
    f.d.unregister(f.p);
    f.d.unregister(f.p);
}

fn unregisterOrphaned() void {
    var f = freshDomain();
    // The state a hand-off leaves: still `in_use`, flagged orphaned.
    f.p.orphaned.store(true, .release);
    f.d.unregister(f.p);
}

test "a second unregister of a freed slot panics (sweep REV-lockfree-2a)" {
    try expectPanicMessage(unregisterTwice, ebr.msg_unregister_unowned);
}

test "unregister of an orphaned slot panics (sweep REV-lockfree-2b)" {
    try expectPanicMessage(unregisterOrphaned, ebr.msg_unregister_unowned);
}

const NullAdapter = struct {
    pub const ThreadCtx = void;
    pub fn initThread(_: *NullAdapter) !void {}
    pub fn deinitThread(_: *NullAdapter, _: void) void {}
    pub fn enqueue(_: *NullAdapter, _: void, _: u64) !void {}
    pub fn dequeue(_: *NullAdapter, _: void) ?u64 {
        return null;
    }
};

test "the stress harness refuses producers * per_producer that overflows (sweep REV-lockfree-6)" {
    const cfg: harness.StressConfig = .{ .producers = (std.math.maxInt(usize) >> 1) + 1, .consumers = 1, .per_producer = 2 };
    try testing.expectError(error.StressTooLarge, harness.verify(cfg, &.{}, testing.allocator));
    var a: NullAdapter = .{};
    try testing.expectError(error.StressTooLarge, harness.runStress(NullAdapter, &a, cfg, testing.allocator));
}
