// SPDX-License-Identifier: MIT

//! Tests added by the 2026-10-25 grade-1 audit (axis A1): each one kills a
//! mutant of `root.zig`/`sharded.zig` that the original suite let survive.
//! Public API plus public fields only (no private methods), so the file
//! does not depend on the internal helper signatures.

const std = @import("std");
const testing = std.testing;
const root = @import("root.zig");
const Cache = root.Cache;
const Sharded = root.Sharded;
const EvictReason = root.EvictReason;

fn testCache(max_bytes: usize, max_entries: usize) Cache {
    return Cache.init(testing.allocator, .{ .max_bytes = max_bytes, .max_entries = max_entries });
}

const Sink = struct {
    fired: usize = 0,
    reason: EvictReason = .cleared,
    dirty: bool = false,

    fn hook(ctx: ?*anyopaque, key: []const u8, value: []const u8, dirty: bool, reason: EvictReason) void {
        _ = key;
        _ = value;
        const s: *Sink = @ptrCast(@alignCast(ctx.?));
        s.fired += 1;
        s.reason = reason;
        s.dirty = dirty;
    }
};

/// Allocator that refuses every 64-byte-aligned request (the frequency
/// sketch's counter block) and counts the refusals.
const Blocker = struct {
    backing: std.mem.Allocator,
    blocked: usize = 0,

    fn allocator(self: *Blocker) std.mem.Allocator {
        return .{ .ptr = self, .vtable = &vtable };
    }

    const vtable: std.mem.Allocator.VTable = .{ .alloc = alloc, .resize = resize, .remap = remap, .free = free };

    fn alloc(ctx: *anyopaque, len: usize, a: std.mem.Alignment, ra: usize) ?[*]u8 {
        const self: *Blocker = @ptrCast(@alignCast(ctx));
        if (a.toByteUnits() >= 64) {
            self.blocked += 1;
            return null;
        }
        return self.backing.rawAlloc(len, a, ra);
    }
    fn resize(ctx: *anyopaque, mem: []u8, a: std.mem.Alignment, new_len: usize, ra: usize) bool {
        const self: *Blocker = @ptrCast(@alignCast(ctx));
        return self.backing.rawResize(mem, a, new_len, ra);
    }
    fn remap(ctx: *anyopaque, mem: []u8, a: std.mem.Alignment, new_len: usize, ra: usize) ?[*]u8 {
        const self: *Blocker = @ptrCast(@alignCast(ctx));
        return self.backing.rawRemap(mem, a, new_len, ra);
    }
    fn free(ctx: *anyopaque, mem: []u8, a: std.mem.Alignment, ra: usize) void {
        const self: *Blocker = @ptrCast(@alignCast(ctx));
        self.backing.rawFree(mem, a, ra);
    }
};

// ── sketch ──────────────────────────────────────────────────────────────────

test "sketch: every access is a sample, and the aging reset fires at exactly sample_limit" {
    var c = testCache(1 << 20, 16);
    defer c.deinit();
    c.put("a", "v", 0, 0, 0); // sample 1
    try testing.expectEqual(@as(u64, 1), c.sketch.?.samples);
    try testing.expectEqual(@as(u64, 160), c.sketch.?.sample_limit); // 10 x 16
    for (0..158) |_| _ = c.get("a", 0, 0); // samples 2..159
    try testing.expectEqual(@as(u64, 159), c.sketch.?.samples);
    _ = c.get("a", 0, 0); // sample 160 = the limit: halve at once
    try testing.expectEqual(@as(u64, 80), c.sketch.?.samples);
}

test "sketch: all sixteen nibbles of a counter word are in use" {
    var c = testCache(1 << 30, 1000);
    defer c.deinit();
    var buf: [16]u8 = undefined;
    for (0..400) |i| {
        const k = std.mem.print(&buf, "key{d}", .{i}) catch unreachable;
        c.put(k, "v", 0, 0, 0);
        _ = c.get(k, 0, 0); // second sighting passes the doorkeeper into the counters
    }
    var high = false;
    for (c.sketch.?.counters) |w| {
        if (w >> 32 != 0) high = true;
    }
    try testing.expect(high);
}

test "sketch: put, pin hit and reserve each record a sample; a miss records none" {
    var c = testCache(1 << 20, 16);
    defer c.deinit();
    c.put("a", "1", 0, 10, 0);
    try testing.expectEqual(@as(u64, 1), c.sketch.?.samples);
    try testing.expect(c.pin("zz", 0, 0) == null);
    try testing.expectEqual(@as(u64, 1), c.sketch.?.samples);
    const b = c.pin("a", 5, 0).?;
    c.release(b);
    try testing.expectEqual(@as(u64, 2), c.sketch.?.samples);
    const f = c.reserve("r", 2, 0, 0, 0).?;
    c.discard(f);
    try testing.expectEqual(@as(u64, 3), c.sketch.?.samples);
}

test "sketch OOM: the failed allocation is tried once, and the cache admits like a plain LRU" {
    var bl = Blocker{ .backing = testing.allocator };
    var c = Cache.init(bl.allocator(), .{ .max_bytes = 1 << 20, .max_entries = 2 });
    defer c.deinit();
    var buf: [8]u8 = undefined;
    for (0..12) |i| {
        const k = std.mem.print(&buf, "k{d}", .{i}) catch unreachable;
        c.put(k, "v", 0, 0, 0);
        _ = c.get(k, 0, 0);
    }
    try testing.expectEqual(false, c.sketch != null);
    try testing.expectEqual(@as(usize, 1), bl.blocked);
    try testing.expectEqual(@as(u64, 0), c.stats.rejections);
    try testing.expectEqual(true, c.stats.admissions > 0);
}

// ── basics ──────────────────────────────────────────────────────────────────

test "a zero-entry cache has a zero window; the hill climber starts by shrinking" {
    var c0 = testCache(1, 0);
    defer c0.deinit();
    try testing.expectEqual(@as(usize, 0), c0.window_adapt);
    var c = testCache(1 << 20, 100);
    defer c.deinit();
    try testing.expectEqual(@as(usize, 1), c.window_adapt);
    try testing.expect(c.hc_step < 0);
}

test "get: a hit moves the entry to its region's most-recent end" {
    var c = testCache(1 << 20, 1000);
    defer c.deinit();
    c.put("a", "1", 0, 0, 0);
    c.put("b", "2", 0, 0, 0);
    c.put("c", "3", 0, 0, 0);
    try testing.expectEqualStrings("c", c.lru[0].tail.?.key);
    _ = c.get("a", 0, 0);
    try testing.expectEqualStrings("a", c.lru[0].tail.?.key);
    try testing.expectEqualStrings("b", c.lru[0].head.?.key);
}

test "replace stores the new generation; the old one is stale" {
    var c = testCache(1 << 20, 16);
    defer c.deinit();
    c.put("k", "v1", 0, 0, 1);
    c.put("k", "v2", 0, 0, 2);
    try testing.expectEqualStrings("v2", c.get("k", 0, 2).?);
    c.put("k", "v3", 0, 0, 2);
    try testing.expect(c.get("k", 0, 1) == null);
}

test "on_evict: a replace reports the outgoing value's own dirty bit; a replace over a borrow says .replaced" {
    var sink = Sink{};
    var c = Cache.init(testing.allocator, .{ .max_bytes = 1 << 20, .max_entries = 16, .on_evict = Sink.hook, .on_evict_ctx = &sink });
    defer c.deinit();
    c.put("k", "v1", 0, 0, 0);
    c.put("k", "v2", 0, 0, 0); // v1 was dirty
    try testing.expectEqual(@as(usize, 1), sink.fired);
    try testing.expect(sink.dirty);
    try testing.expect(c.markClean("k"));
    c.put("k", "v3", 0, 0, 0); // v2 was clean
    try testing.expectEqual(@as(usize, 2), sink.fired);
    try testing.expect(!sink.dirty);
    // overwrite of a borrowed entry: parked, reason .replaced
    const b = c.pin("k", 0, 0).?;
    c.put("k", "v4", 0, 0, 0);
    try testing.expectEqual(@as(usize, 3), sink.fired);
    try testing.expectEqual(EvictReason.replaced, sink.reason);
    try testing.expectEqualStrings("v3", b.bytes);
    c.release(b);
}

test "TTL entries are always reachable from the expiry heap, whichever allocation fails" {
    for (0..16) |fi| {
        var fa = std.testing.FailingAllocator.init(testing.allocator, .{ .fail_index = fi });
        var c = Cache.init(fa.allocator(), .{ .max_bytes = 1 << 20, .max_entries = 16 });
        defer c.deinit();
        c.put("k", "v", 0, 100, 0);
        c.put("k2", "v", 0, 100, 0);
        try testing.expectEqual(c.map.count(), c.exp.items.len);
    }
}

// ── pin / reserve ───────────────────────────────────────────────────────────

test "pin: hit, miss, TTL-expired and generation-stale are counted and the stale entry is dropped" {
    var c = testCache(1 << 20, 16);
    defer c.deinit();
    c.put("a", "1", 0, 10, 0);
    c.put("g", "2", 0, 0, 3);
    try testing.expect(c.pin("zz", 0, 0) == null);
    try testing.expectEqual(@as(u64, 1), c.stats.misses);
    const b = c.pin("a", 5, 0).?;
    c.release(b);
    try testing.expectEqual(@as(u64, 1), c.stats.hits);
    try testing.expect(c.pin("a", 11, 0) == null); // expired
    try testing.expectEqual(@as(u64, 1), c.stats.expired);
    try testing.expectEqual(@as(u64, 2), c.stats.misses);
    try testing.expectEqual(@as(usize, 1), c.stats.entries);
    try testing.expect(!c.isDirty("a"));
    try testing.expect(c.pin("g", 0, 4) == null); // stale generation
    try testing.expectEqual(@as(u64, 2), c.stats.expired);
    try testing.expectEqual(@as(usize, 0), c.stats.entries);
}

test "adaptive: get and pin feed the hit-rate sample on every outcome, and pin can start a climb" {
    var c = Cache.init(testing.allocator, .{ .max_bytes = 1 << 20, .max_entries = 100, .adaptive_window = true });
    defer c.deinit();
    c.put("e", "v", 0, 5, 0);
    _ = c.get("e", 10, 0); // expired
    try testing.expectEqual(@as(u64, 1), c.hc_misses);
    c.put("e", "v", 0, 5, 0);
    _ = c.pin("e", 10, 0); // expired
    try testing.expectEqual(@as(u64, 2), c.hc_misses);
    _ = c.pin("absent", 0, 0);
    try testing.expectEqual(@as(u64, 3), c.hc_misses);
    c.put("h", "v", 0, 0, 0);
    c.release(c.pin("h", 0, 0).?);
    try testing.expectEqual(@as(u64, 1), c.hc_hits);
    // 1000 lookups = one sample; the next pin starts the climb
    while (c.hc_hits + c.hc_misses < 1000) _ = c.get("absent", 0, 0);
    try testing.expectEqual(@as(u64, 0), c.climbs);
    _ = c.pin("absent", 0, 0);
    try testing.expectEqual(@as(u64, 1), c.climbs);
}

test "pin: a refused borrow (parking slot OOM) is still a counted miss" {
    for (0..14) |fi| {
        var fa = std.testing.FailingAllocator.init(testing.allocator, .{ .fail_index = fi });
        var c = Cache.init(fa.allocator(), .{ .max_bytes = 1 << 20, .max_entries = 16, .adaptive_window = true });
        defer c.deinit();
        c.put("k", "v", 0, 0, 0);
        if (c.pin("k", 0, 0)) |b| c.release(b);
        try testing.expectEqual(@as(u64, 1), c.stats.hits + c.stats.misses);
        try testing.expectEqual(@as(u64, 1), c.hc_hits + c.hc_misses);
    }
}

test "reserve: generation, dirty bit and stats are set before commit" {
    var c = testCache(1 << 20, 16);
    defer c.deinit();
    const f = c.reserve("r", 4, 0, 0, 7).?;
    try testing.expectEqual(@as(usize, 1), c.stats.entries);
    try testing.expectEqual(@as(usize, 4), c.stats.bytes);
    @memcpy(f.bytes, "abcd");
    const b = c.commit(f);
    c.release(b);
    try testing.expect(c.isDirty("r"));
    try testing.expectEqualStrings("abcd", c.get("r", 0, 7).?);
    try testing.expect(c.get("r", 0, 8) == null);
}

test "discard counts a removal; a doomed (borrowed) removal fires the hook, counts, and parks key-less" {
    var sink = Sink{};
    var c = Cache.init(testing.allocator, .{ .max_bytes = 1 << 20, .max_entries = 100, .on_evict = Sink.hook, .on_evict_ctx = &sink });
    defer c.deinit();
    const f = c.reserve("r", 2, 0, 0, 0).?;
    c.discard(f);
    try testing.expectEqual(@as(u32, 1), c.removals);
    try testing.expectEqual(@as(usize, 0), sink.fired);

    c.put("a", "xy", 0, 0, 0);
    c.put("b", "z", 0, 0, 0); // a moves to probation
    _ = c.get("a", 0, 0); // a is protected
    try testing.expectEqual(@as(usize, 1), c.protected_count);
    const before = c.removals;
    const b = c.pin("a", 0, 0).?;
    try testing.expect(c.remove("a"));
    try testing.expectEqual(before + 1, c.removals);
    try testing.expectEqual(@as(usize, 1), sink.fired);
    try testing.expectEqual(EvictReason.evicted, sink.reason);
    try testing.expectEqual(@as(usize, 0), c.protected_count);
    try testing.expectEqual(@as(usize, 1), c.stats.entries); // only "b" left, stats already synced
    try testing.expectEqual(@as(usize, 1), c.doomed.items.len);
    try testing.expectEqual(@as(usize, 0), c.doomed.items[0].key.len);
    try testing.expectEqual(@as(usize, 0), c.doomed.items[0].entry.value.len);
    try testing.expectEqual(@as(usize, 2), c.doomed.items[0].owned.len);
    try testing.expectEqualStrings("xy", b.bytes);
    c.release(b);
    try testing.expectEqual(@as(usize, 0), c.doomed.items.len);
}

// ── expiry heap / idle ──────────────────────────────────────────────────────

test "idle ttl: the heap files an entry under the EARLIER of write TTL and idle deadline" {
    var c = Cache.init(testing.allocator, .{ .max_bytes = 1 << 20, .max_entries = 2, .idle_ttl_ns = 1000 });
    defer c.deinit();
    c.put("a", "1", 0, 100, 0); // write deadline 100, idle deadline 1000
    c.put("b", "2", 0, 0, 0); // idle deadline 1000 only
    c.put("c", "3", 500, 0, 0); // over the cap: the expired entry goes first
    try testing.expectEqual(@as(u64, 1), c.stats.evictions);
    try testing.expect(!c.isDirty("a"));
    try testing.expect(c.isDirty("b"));
    try testing.expect(c.isDirty("c"));
}

test "idle ttl: a hit on a borrowed entry re-files its deadline at release" {
    var c = Cache.init(testing.allocator, .{ .max_bytes = 1 << 20, .max_entries = 16, .idle_ttl_ns = 100 });
    defer c.deinit();
    c.put("a", "1", 0, 0, 0);
    const b = c.pin("a", 0, 0).?;
    try testing.expect(c.get("a", 80, 0) != null);
    c.release(b);
    try testing.expectEqual(@as(usize, 1), c.exp.items.len);
    try testing.expectEqual(@as(i64, 180), c.exp.items[0].deadline);
}

test "eviction consults the expiry heap only when it holds something" {
    var visits: [2]u64 = undefined;
    for (0..2) |variant| {
        var c = testCache(1 << 20, 2);
        defer c.deinit();
        var buf: [8]u8 = undefined;
        for (0..8) |i| {
            const k = std.mem.print(&buf, "k{d}", .{i}) catch unreachable;
            c.put(k, "v", 0, if (variant == 1) 1_000_000 else 0, 0);
        }
        visits[variant] = c.maintenance_visits;
    }
    try testing.expect(visits[1] > visits[0]);
}

// ── adaptive window (hill climber) ──────────────────────────────────────────

/// Top the current sample up to `h` hits out of one full period, then nothing
/// else: the NEXT lookup starts the climb.
fn sampleTo(c: *Cache, h: usize) void {
    const period = c.options.max_entries * 10;
    const hits = h - @as(usize, @intCast(c.hc_hits));
    const misses = period - h - @as(usize, @intCast(c.hc_misses));
    for (0..hits) |_| _ = c.get("k0", 0, 0);
    for (0..misses) |_| _ = c.get("absent", 0, 0);
}

fn fillKeys(c: *Cache, n: usize) void {
    var buf: [16]u8 = undefined;
    for (0..n) |i| c.put(std.mem.print(&buf, "k{d}", .{i}) catch unreachable, "v", 0, 0, 0);
}

test "adaptive window: a falling hit rate grows the window by the step, from probation first, up to 80 % and no further" {
    var c = Cache.init(testing.allocator, .{ .max_bytes = 1 << 30, .max_entries = 102, .adaptive_window = true });
    defer c.deinit();
    fillKeys(&c, 102);
    var buf: [16]u8 = undefined;
    for (0..80) |i| _ = c.get(std.mem.print(&buf, "k{d}", .{i}) catch unreachable, 0, 0);
    try testing.expectEqual(@as(usize, 80), c.protected_count);
    try testing.expectEqual(@as(f64, -6.375), c.hc_step);

    sampleTo(&c, 900);
    try testing.expectEqual(@as(u64, 0), c.climbs);
    _ = c.get("absent", 0, 0); // climb 1: rate rose from 0, step stays negative, window is at its minimum
    try testing.expectEqual(@as(u64, 1), c.climbs);
    try testing.expectEqual(@as(usize, 1), c.window_adapt);
    try testing.expectEqual(@as(f64, -6.375), c.hc_step);

    sampleTo(&c, 300);
    _ = c.get("absent", 0, 0); // climb 2: rate fell by 0.58 -> restart at +6.375, window grows by 6
    try testing.expectEqual(@as(u64, 2), c.climbs);
    try testing.expectEqual(@as(f64, 6.375), c.hc_step);
    try testing.expectEqual(@as(usize, 7), c.window_adapt);
    try testing.expectEqual(@as(usize, 7), c.window_count);
    try testing.expectEqual(@as(usize, 76), c.protected_count); // 80 -> cap (102-7)*4/5, demoted at once
    try testing.expectEqual(@as(usize, 19), c.probation_count);

    // a slowly rising rate keeps growing the window with a decaying step: it stops at 80 % of 102 (= 80)
    var h: usize = 300;
    for (0..40) |_| {
        h += 10;
        sampleTo(&c, h);
        _ = c.get("absent", 0, 0);
        try testing.expect(c.window_adapt <= 80);
        try testing.expectEqual(c.map.count(), c.window_count + c.probation_count + c.protected_count);
    }
    try testing.expectEqual(@as(usize, 80), c.window_adapt);

    // the same rate twice (change == 0) keeps the step's sign
    sampleTo(&c, h);
    _ = c.get("absent", 0, 0);
    try testing.expect(c.hc_step > 0);
}

test "adaptive window: a step that would cross 80 % is clipped to the room left" {
    // 112 entries: bound 88, the last step (quota 5) has room for 1
    var c = Cache.init(testing.allocator, .{ .max_bytes = 1 << 30, .max_entries = 112, .adaptive_window = true });
    defer c.deinit();
    fillKeys(&c, 112);
    sampleTo(&c, 900);
    _ = c.get("absent", 0, 0);
    sampleTo(&c, 300);
    _ = c.get("absent", 0, 0); // restart at +7: window 1 + 7
    try testing.expectEqual(@as(usize, 8), c.window_adapt);
    var h: usize = 300;
    for (0..40) |_| {
        h += 10;
        sampleTo(&c, h);
        _ = c.get("absent", 0, 0);
        try testing.expect(c.window_adapt <= 88);
        try testing.expect(c.window_count <= c.window_adapt);
    }
    try testing.expectEqual(@as(usize, 88), c.window_adapt);
}

test "adaptive window: the part of a step that cannot be realised is not added to the limit; protected entries follow once probation is empty" {
    var c = Cache.init(testing.allocator, .{ .max_bytes = 1 << 30, .max_entries = 100, .adaptive_window = true });
    defer c.deinit();
    fillKeys(&c, 5); // k4 in the window, k0..k3 in probation
    for (0..4) |i| {
        var buf: [8]u8 = undefined;
        _ = c.get(std.mem.print(&buf, "k{d}", .{i}) catch unreachable, 0, 0);
    }
    try testing.expectEqual(@as(usize, 4), c.protected_count);
    sampleTo(&c, 900);
    _ = c.get("absent", 0, 0);
    sampleTo(&c, 300);
    _ = c.get("absent", 0, 0); // grow by 6, only 4 main entries exist
    try testing.expectEqual(@as(usize, 5), c.window_adapt);
    try testing.expectEqual(@as(usize, 5), c.window_count);
    try testing.expectEqual(@as(usize, 0), c.protected_count);
    try testing.expectEqual(@as(usize, 0), c.probation_count);
}

test "adaptive window: sample length, restart threshold and decay" {
    // exactly 10 x max_entries lookups form a sample; the climb starts with the NEXT lookup
    var c = Cache.init(testing.allocator, .{ .max_bytes = 1 << 30, .max_entries = 100, .adaptive_window = true });
    defer c.deinit();
    for (0..1000) |_| _ = c.get("absent", 0, 0);
    try testing.expectEqual(@as(u64, 0), c.climbs);
    _ = c.get("absent", 0, 0);
    try testing.expectEqual(@as(u64, 1), c.climbs);

    // a rate change of exactly 0.05 restarts the step at the full size, with the sign kept
    var c2 = Cache.init(testing.allocator, .{ .max_bytes = 1 << 30, .max_entries = 100, .adaptive_window = true });
    defer c2.deinit();
    c2.put("k0", "v", 0, 0, 0);
    sampleTo(&c2, 50);
    _ = c2.get("absent", 0, 0);
    try testing.expectEqual(@as(f64, -6.25), c2.hc_step);

    // a smaller change decays the step by 2 %
    var c3 = Cache.init(testing.allocator, .{ .max_bytes = 1 << 30, .max_entries = 100, .adaptive_window = true });
    defer c3.deinit();
    c3.put("k0", "v", 0, 0, 0);
    sampleTo(&c3, 10);
    _ = c3.get("absent", 0, 0);
    try testing.expectApproxEqAbs(@as(f64, -6.125), c3.hc_step, 1e-9);
}

test "adaptive window: off, or a zero-capacity cache, never samples or climbs" {
    var c = testCache(1 << 20, 100);
    defer c.deinit();
    for (0..5) |_| _ = c.get("absent", 0, 0);
    try testing.expectEqual(@as(u64, 0), c.hc_misses);
    try testing.expectEqual(@as(u64, 0), c.hc_hits);

    var z = Cache.init(testing.allocator, .{ .max_bytes = 1, .max_entries = 0, .adaptive_window = true });
    defer z.deinit();
    for (0..5) |_| _ = z.get("absent", 0, 0);
    try testing.expectEqual(@as(u64, 0), z.climbs);
}

// ── index tombstones ────────────────────────────────────────────────────────

fn firstRebuildAt(live: usize) !struct { removals: u32, cap: u32 } {
    var c = Cache.init(testing.allocator, .{ .max_bytes = 1 << 30, .max_entries = 4096 });
    defer c.deinit();
    var buf: [16]u8 = undefined;
    for (0..live + 1) |i| c.put(std.mem.print(&buf, "k{d}", .{i}) catch unreachable, "v", 0, 0, 0);
    _ = c.remove("k0");
    const cap = c.map.capacity();
    for (0..2000) |it| {
        const r = c.removals;
        const before = c.stats.rehashes;
        c.put(std.mem.print(&buf, "k{d}", .{live + 1 + it}) catch unreachable, "v", 0, 0, 0);
        if (c.stats.rehashes > before) {
            try testing.expectEqual(@as(u32, 0), c.removals);
            return .{ .removals = r, .cap = cap };
        }
        _ = c.remove(std.mem.print(&buf, "k{d}", .{1 + it}) catch unreachable);
    }
    return error.NeverRebuilt;
}

test "the index is rebuilt once removals reach max(32, capacity/4), not before and not later" {
    const small = try firstRebuildAt(10);
    try testing.expect(small.cap / 4 < 32);
    try testing.expectEqual(@as(u32, 32), small.removals);
    const large = try firstRebuildAt(300);
    try testing.expect(large.cap / 4 > 32);
    try testing.expectEqual(@as(u32, large.cap / 4), large.removals);
}

// ── Sharded ─────────────────────────────────────────────────────────────────

test "Sharded: a zero shard request means one shard; adaptive_window reaches every shard" {
    var one = try Sharded.init(testing.allocator, .{ .max_bytes = 1 << 20, .max_entries = 64, .shards = 0 });
    defer one.deinit();
    try testing.expectEqual(@as(usize, 1), one.shardCount());

    var sc = try Sharded.init(testing.allocator, .{ .max_bytes = 1 << 20, .max_entries = 64, .shards = 2, .adaptive_window = true });
    defer sc.deinit();
    for (sc.shards) |*s| try testing.expect(s.cache.options.adaptive_window);
}

test "audit MED1: an uncommitted reservation is a miss for isDirty, markClean and markCleanIf" {
    var c = Cache.init(testing.allocator, .{ .max_bytes = 1 << 10, .max_entries = 8 });
    defer c.deinit();
    c.put("k", "old", 0, 0, 0);
    // The flusher persisted "old"; before its ack lands a reserve replaces it.
    const f = c.reserve("k", 3, 1, 0, 0).?;
    @memcpy(f.bytes, "old"); // even bytes that match must not be acked before commit
    try testing.expect(!c.isDirty("k"));
    try testing.expect(!c.markClean("k"));
    try testing.expect(!c.markCleanIf("k", "old"));
    @memcpy(f.bytes, "new");
    c.release(c.commit(f));
    // The replacement is still owed a write-behind.
    try testing.expect(c.isDirty("k"));
    try testing.expect(c.markCleanIf("k", "new"));
    try testing.expect(!c.isDirty("k"));
}

test "audit LOW4: freshness at the far ends of the clock saturates instead of trapping" {
    // Write TTL alone, then idle TTL alone: each predicate on its own.
    var c = Cache.init(testing.allocator, .{ .max_bytes = 1 << 10, .max_entries = 8 });
    defer c.deinit();
    c.put("k", "v", std.math.minInt(i64) + 1, 10, 0);
    try testing.expect(c.get("k", std.math.maxInt(i64), 0) == null); // expired, no overflow
    var i = Cache.init(testing.allocator, .{ .max_bytes = 1 << 10, .max_entries = 8, .idle_ttl_ns = 10 });
    defer i.deinit();
    i.put("k", "v", std.math.minInt(i64) + 1, 0, 0);
    try testing.expect(i.get("k", std.math.maxInt(i64), 0) == null);
}
