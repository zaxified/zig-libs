// SPDX-License-Identifier: MIT

//! No-panic sweep § GQ (gq-b): tests for `Cache` in root.zig. Each test kills
//! the mutant of its finding ID (see the sweep report).

const std = @import("std");
const testing = std.testing;
const root = @import("root.zig");
const Cache = root.Cache;
const EvictReason = root.EvictReason;

test "Options.max_entries near the top of usize degrades instead of overflowing (sweep RC-1)" {
    // maxInt(usize) is the natural spelling of "unlimited": the protected-region
    // cap (`main * 4 / 5`) wrapped. 1 << 61: the sketch's `base * 8` wrapped.
    // 1 << 60: `depth * width` wrapped. The sketch cannot be allocated for any
    // of them; the cache must fall back to plain LRU and keep working.
    const sizes = [_]usize{ std.math.maxInt(usize), 1 << 61, 1 << 60 };
    for (sizes) |max_entries| {
        var c = Cache.init(testing.allocator, .{ .max_bytes = 1 << 20, .max_entries = max_entries });
        defer c.deinit();
        for (0..40) |i| {
            var kb: [8]u8 = undefined;
            const key = std.mem.print(&kb, "k{d}", .{i}) catch unreachable;
            c.put(key, "value", 1, 0, 0);
            try testing.expectEqualStrings("value", c.get(key, 2, 0).?);
        }
        // A second hit promotes probation -> protected, which reads protectedCap.
        for (0..40) |i| {
            var kb: [8]u8 = undefined;
            try testing.expect(c.get(std.mem.print(&kb, "k{d}", .{i}) catch unreachable, 3, 0) != null);
        }
        try testing.expectEqual(@as(usize, 40), c.stats.entries);
    }
}

test "a pin count at its ceiling refuses the next borrow instead of wrapping (sweep RC-2)" {
    var c = Cache.init(testing.allocator, .{ .max_bytes = 1 << 20, .max_entries = 16 });
    defer c.deinit();
    c.put("k", "v", 0, 0, 0);
    const b = c.pin("k", 0, 0).?;
    // 2^32 - 2 further borrows would take minutes; set the counter directly.
    b.node.pins = std.math.maxInt(u32);
    try testing.expect(c.pin("k", 0, 0) == null); // refused: caller copies instead
    try testing.expectEqual(@as(u32, std.math.maxInt(u32)), b.node.pins);
    b.node.pins = 1;
    c.release(b);
    try testing.expectEqual(@as(usize, 0), c.stats.pinned);
    try testing.expectEqualStrings("v", c.get("k", 0, 0).?);
}

test "a second release of a live entry's borrow is ignored (sweep RC-2)" {
    var c = Cache.init(testing.allocator, .{ .max_bytes = 1 << 20, .max_entries = 4 });
    defer c.deinit();
    c.put("k", "v", 0, 0, 0);
    const b = c.pin("k", 0, 0).?;
    c.release(b);
    c.release(b); // double release: used to wrap `pins` / underflow `pinned_entries`
    try testing.expectEqual(@as(usize, 0), c.stats.pinned);
    // The entry is a normal, evictable resident afterwards, and can be borrowed again.
    const b2 = c.pin("k", 0, 0).?;
    try testing.expectEqual(@as(usize, 1), c.stats.pinned);
    c.release(b2);
    for (0..8) |i| {
        var kb: [8]u8 = undefined;
        c.put(std.mem.print(&kb, "n{d}", .{i}) catch unreachable, "v", 0, 0, 0);
    }
    try testing.expect(c.stats.entries <= 4);
}

const Probe = struct {
    cache: *Cache,
    keys: []const []const u8,
    fired: usize = 0,
    reads: usize = 0,
    wrong: usize = 0,

    fn onEvict(ctx: ?*anyopaque, key: []const u8, value: []const u8, dirty: bool, reason: EvictReason) void {
        _ = key;
        _ = value;
        _ = dirty;
        _ = reason;
        const p: *Probe = @ptrCast(@alignCast(ctx.?));
        p.fired += 1;
        // Read-only re-entrancy: every resident key must still be readable.
        for (p.keys) |k| {
            p.reads += 1;
            const v = p.cache.get(k, 0, 0) orelse {
                p.wrong += 1;
                continue;
            };
            if (!std.mem.eql(u8, v, "payload")) p.wrong += 1;
        }
    }
};

test "clear: an on_evict hook that reads the cache never sees a freed entry (sweep RC-3)" {
    const keys = [_][]const u8{ "a", "b", "c", "d", "e", "f", "g", "h" };
    var probe = Probe{ .cache = undefined, .keys = &keys };
    var c = Cache.init(testing.allocator, .{
        .max_bytes = 1 << 20,
        .max_entries = 64,
        .on_evict = Probe.onEvict,
        .on_evict_ctx = &probe,
    });
    defer c.deinit();
    probe.cache = &c;
    for (keys) |k| c.put(k, "payload", 0, 0, 0);
    c.clear();
    try testing.expectEqual(keys.len, probe.fired);
    try testing.expectEqual(keys.len * keys.len, probe.reads);
    // Before the fix the hooks ran interleaved with the frees: later hooks
    // looked up keys whose nodes were already freed.
    try testing.expectEqual(@as(usize, 0), probe.wrong);
    try testing.expectEqual(@as(usize, 0), c.stats.entries);
}

test "drainDirty and replace hooks may read and clean the cache (sweep RC-3)" {
    const keys = [_][]const u8{ "a", "b" };
    var probe = Probe{ .cache = undefined, .keys = &keys };
    var c = Cache.init(testing.allocator, .{
        .max_bytes = 1 << 20,
        .max_entries = 64,
        .on_evict = Probe.onEvict,
        .on_evict_ctx = &probe,
    });
    defer c.deinit();
    probe.cache = &c;
    for (keys) |k| c.put(k, "payload", 0, 0, 0);
    // Replace hook reading the very key being replaced still sees live bytes.
    c.put("a", "payload", 1, 0, 0);
    try testing.expectEqual(@as(usize, 1), probe.fired);
    try testing.expectEqual(@as(usize, 0), probe.wrong);

    const Drain = struct {
        cache: *Cache,
        seen: usize = 0,
        fn cb(ctx: ?*anyopaque, key: []const u8, value: []const u8) void {
            const d: *@This() = @ptrCast(@alignCast(ctx.?));
            d.seen += 1;
            std.debug.assert(std.mem.eql(u8, value, "payload"));
            _ = d.cache.get(key, 0, 0); // hit: allowed
            _ = d.cache.markClean(key);
        }
    };
    var d = Drain{ .cache = &c };
    c.drainDirty(Drain.cb, &d);
    try testing.expectEqual(@as(usize, 2), d.seen);
    try testing.expect(!c.isDirty("a"));
}

test "a key longer than max_key_len is refused everywhere, a key at the limit is stored (sweep RC-4)" {
    var c = Cache.init(testing.allocator, .{ .max_bytes = 1 << 20, .max_entries = 16, .max_key_len = 64 });
    defer c.deinit();
    const ok: []const u8 = &@as([64]u8, @splat('k'));
    const long: []const u8 = &@as([65]u8, @splat('k'));
    c.put(ok, "v", 0, 0, 0);
    try testing.expectEqualStrings("v", c.get(ok, 0, 0).?);
    c.put(long, "v", 0, 0, 0);
    c.putDefault(long, "v", 0, 0);
    try testing.expect(c.get(long, 0, 0) == null);
    try testing.expectEqual(@as(usize, 1), c.stats.entries);
    try testing.expect(c.reserve(long, 4, 0, 0, 0) == null);
    try testing.expectEqual(@as(usize, 0), c.stats.pinned);
    try testing.expect(c.reserve(ok, 4, 0, 0, 0) != null);

    const L = struct {
        fn load(_: ?*anyopaque, gpa: std.mem.Allocator, _: []const u8) root.LoadError![]u8 {
            return gpa.dupe(u8, "loaded");
        }
    };
    const got = try c.getOrLoad(testing.allocator, long, 0, 0, 0, 0, .{ .ctx = null, .load = L.load });
    defer testing.allocator.free(got);
    try testing.expectEqualStrings("loaded", got); // loaded and returned...
    try testing.expect(c.get(long, 0, 0) == null); // ...but not stored
    try testing.expectEqual(@as(usize, 1), c.stats.entries);
}

test "default max_key_len is 4096 (sweep RC-4)" {
    var c = Cache.init(testing.allocator, .{ .max_bytes = 1 << 20, .max_entries = 16 });
    defer c.deinit();
    c.put(&@as([4096]u8, @splat('a')), "v", 0, 0, 0);
    c.put(&@as([4097]u8, @splat('b')), "v", 0, 0, 0);
    try testing.expectEqual(@as(usize, 1), c.stats.entries);
}

fn removeMatchingVisits(n: usize) !u64 {
    var c = Cache.init(testing.allocator, .{ .max_bytes = 1 << 30, .max_entries = n * 2 });
    defer c.deinit();
    var kb: [24]u8 = undefined;
    for (0..n) |i| c.put(std.mem.print(&kb, "p{d}", .{i}) catch unreachable, "v", 0, 0, 0);
    try testing.expectEqual(n, c.stats.entries);
    try testing.expectEqual(n, c.removeMatching("p"));
    try testing.expectEqual(@as(usize, 0), c.stats.entries);
    return c.match_visits;
}

test "removeMatching is linear in the matches, not quadratic (sweep RC-6)" {
    // Work counter instead of a clock (a removal costs far more than a slot
    // visit in Debug, which hides the quadratic part at feasible sizes):
    // linear ~ 4x for 4x the entries, a full map scan per 512 removals ~ 16x.
    const v1 = try removeMatchingVisits(2000);
    const v4 = try removeMatchingVisits(8000);
    try testing.expect(v4 < 9 * v1);
}

test "removeMatching still reaches borrowed entries and non-queued reservations (sweep RC-6)" {
    var c = Cache.init(testing.allocator, .{ .max_bytes = 1 << 20, .max_entries = 64 });
    defer c.deinit();
    c.put("p1", "a", 0, 0, 0);
    c.put("p2", "b", 0, 0, 0);
    c.put("q1", "c", 0, 0, 0);
    _ = c.get("p1", 1, 0);
    _ = c.get("p1", 2, 0); // promotes to protected
    const b = c.pin("p2", 0, 0).?;
    const f = c.reserve("p3", 4, 0, 0, 0).?;
    try testing.expectEqual(@as(usize, 3), c.removeMatching("p"));
    try testing.expectEqualStrings("b", b.bytes); // borrow survives the removal
    try testing.expect(c.get("q1", 0, 0) != null);
    try testing.expectEqual(@as(usize, 1), c.stats.entries);
    c.release(b);
    c.discard(f);
}

// ── round 3 (blind review) ──────────────────────────────────────────────────

/// Walks the three region queues: links, region tags, lengths and the
/// counters must agree. Bounded so a cycle fails instead of hanging.
fn expectStructure(c: *Cache) !void {
    const lens = [_]usize{ c.window_count, c.probation_count, c.protected_count };
    for (0..3) |r| {
        var cur = c.lru[r].head;
        var prev: @TypeOf(cur) = null;
        var count: usize = 0;
        while (cur) |n| : (cur = n.next) {
            try testing.expect(count < 100_000);
            try testing.expect(n.queued);
            try testing.expectEqual(@as(usize, r), @as(usize, @backingInt(n.region)));
            try testing.expect(n.prev == prev);
            prev = n;
            count += 1;
        }
        try testing.expect(c.lru[r].tail == prev);
        try testing.expectEqual(c.lru[r].len, count);
        try testing.expectEqual(lens[r], count);
    }
    try testing.expectEqual(c.map.count(), lens[0] + lens[1] + lens[2] + c.pinned_entries - c.doomed.items.len);
}

const ClimbProbe = struct {
    cache: *Cache,
    victim_seen: bool = false,
    climbs_before: u64 = 0,
    climbs_after: u64 = 0,
    fn onEvict(ctx: ?*anyopaque, key: []const u8, value: []const u8, dirty: bool, reason: EvictReason) void {
        _ = key;
        _ = value;
        _ = dirty;
        _ = reason;
        const p: *ClimbProbe = @ptrCast(@alignCast(ctx.?));
        p.climbs_before = p.cache.climbs;
        _ = p.cache.get("k200", 0, 0); // hit: allowed from a hook
        p.climbs_after = p.cache.climbs;
        p.victim_seen = true;
    }
};

test "adaptive window: a hook's get on the sample boundary does not move the admission candidate (sweep REV-RC-1)" {
    var probe = ClimbProbe{ .cache = undefined };
    var c = Cache.init(testing.allocator, .{
        .max_bytes = 1 << 20,
        .max_entries = 400,
        .adaptive_window = true,
        .on_evict = ClimbProbe.onEvict,
        .on_evict_ctx = &probe,
    });
    defer c.deinit();
    probe.cache = &c;
    var kb: [8]u8 = undefined;
    for (0..400) |i| c.put(std.mem.print(&kb, "k{d}", .{i}) catch unreachable, "v", 0, 0, 0);
    // Window = k396..k399 (head k396). Make the head hot, keep it the head.
    for (0..4) |_| _ = c.get("k396", 0, 0);
    for ([_][]const u8{ "k397", "k398", "k399" }) |k| _ = c.get(k, 0, 0);
    // Land the sample counter exactly on the period (4000): the next lookup climbs.
    while (c.hc_hits + c.hc_misses < 4000) _ = c.get("absent", 0, 0);
    try testing.expectEqual(@as(u64, 0), c.climbs);
    c.put("fresh", "v", 0, 0, 0); // evicts k0 (hot candidate wins) -> hook -> get
    try testing.expect(probe.victim_seen);
    try testing.expect(c.stats.admissions >= 1);
    try testing.expectEqual(probe.climbs_before, probe.climbs_after); // climber stayed out of the hook
    try expectStructure(&c);
}

const StaleProbe = struct {
    cache: *Cache,
    nulls: usize = 0,
    fn onEvict(ctx: ?*anyopaque, key: []const u8, value: []const u8, dirty: bool, reason: EvictReason) void {
        _ = key;
        _ = value;
        _ = dirty;
        _ = reason;
        const p: *StaleProbe = @ptrCast(@alignCast(ctx.?));
        if (p.cache.get("ttl", 100, 0) == null) p.nulls += 1;
        if (p.cache.get("gen", 100, 2) == null) p.nulls += 1;
        if (p.cache.pin("ttl", 100, 0) == null) p.nulls += 1;
    }
};

test "a hook's get/pin on a stale entry misses without dropping it (sweep REV-RC-2)" {
    var probe = StaleProbe{ .cache = undefined };
    var c = Cache.init(testing.allocator, .{
        .max_bytes = 1 << 20,
        .max_entries = 16,
        .on_evict = StaleProbe.onEvict,
        .on_evict_ctx = &probe,
    });
    defer c.deinit();
    probe.cache = &c;
    c.put("ttl", "v", 0, 10, 0); // expired at t=100
    c.put("gen", "v", 0, 0, 1); // stale for generation 2
    c.put("other", "v", 0, 0, 0);
    _ = c.remove("other"); // fires the hook -> stale lookups inside it
    try testing.expectEqual(@as(usize, 3), probe.nulls);
    try testing.expect(c.stats.expired >= 3);
    try testing.expectEqual(@as(usize, 2), c.stats.entries); // still resident
    probe.cache = undefined; // hook quiet from here
    c.options.on_evict = null;
    try testing.expect(c.get("ttl", 100, 0) == null); // a normal call drops it
    try testing.expectEqual(@as(usize, 1), c.stats.entries);
}

test "reserve and pin are refused past max_pinned_bytes, accepted after a release (sweep REV-RC-3)" {
    var c = Cache.init(testing.allocator, .{ .max_bytes = 100, .max_entries = 16 }); // cap = max_bytes
    defer c.deinit();
    const f1 = c.reserve("a", 60, 0, 0, 0).?;
    try testing.expectEqual(@as(usize, 60), c.pinned_bytes);
    try testing.expect(c.reserve("b", 60, 0, 0, 0) == null); // 120 > 100
    const f2 = c.reserve("c", 40, 0, 0, 0).?; // exactly the cap
    try testing.expect(c.reserve("d", 1, 0, 0, 0) == null);
    c.release(c.commit(f1));
    try testing.expectEqual(@as(usize, 40), c.pinned_bytes);
    const f3 = c.reserve("d", 50, 0, 0, 0).?; // fits after the release
    c.discard(f3);
    c.release(c.commit(f2));
    try testing.expectEqual(@as(usize, 0), c.pinned_bytes);
}

test "pin counts resident entries against max_pinned_bytes (sweep REV-RC-3)" {
    var c = Cache.init(testing.allocator, .{ .max_bytes = 1000, .max_entries = 16, .max_pinned_bytes = 70 });
    defer c.deinit();
    c.put("p1", &@as([40]u8, @splat('x')), 0, 0, 0);
    c.put("p2", &@as([40]u8, @splat('y')), 0, 0, 0);
    const b1 = c.pin("p1", 0, 0).?;
    try testing.expect(c.pin("p2", 0, 0) == null); // 80 > 70: copy path instead
    try testing.expectEqual(@as(usize, 40), c.pinned_bytes);
    c.release(b1);
    try testing.expectEqual(@as(usize, 0), c.pinned_bytes);
    try testing.expect(c.pin("p2", 0, 0) != null);
}

test "a custom max_pinned_bytes overrides max_bytes (sweep REV-RC-3)" {
    var c = Cache.init(testing.allocator, .{ .max_bytes = 100, .max_entries = 16, .max_pinned_bytes = 10 });
    defer c.deinit();
    try testing.expect(c.reserve("a", 11, 0, 0, 0) == null);
    c.release(c.commit(c.reserve("a", 10, 0, 0, 0).?));
}

test "overwriting a pinned key over and over cannot park more than the cap (sweep REV-RC-3)" {
    var c = Cache.init(testing.allocator, .{ .max_bytes = 1000, .max_entries = 16, .max_pinned_bytes = 250 });
    defer c.deinit();
    var held: [8]?Cache.Borrow = @splat(null);
    var refused: usize = 0;
    const val = @as([100]u8, @splat('v'));
    for (0..8) |i| {
        c.put("hot", &val, @intCast(i), 0, 0);
        if (c.pin("hot", @intCast(i), 0)) |b| held[i] = b else refused += 1;
        c.put("hot", &val, @intCast(i), 0, 0); // overwrite: parks the pinned copy
        try testing.expect(c.pinned_bytes <= 250);
        try expectStructure(&c);
    }
    try testing.expect(refused >= 6); // only 2 x 100 bytes fit under 250
    for (held) |h| if (h) |b| c.release(b);
    try testing.expectEqual(@as(usize, 0), c.pinned_bytes);
    try testing.expectEqual(@as(usize, 0), c.doomed.items.len);
}

test "discard of a doomed or single reservation keeps pinned_bytes exact (sweep REV-RC-3)" {
    var c = Cache.init(testing.allocator, .{ .max_bytes = 1000, .max_entries = 16 });
    defer c.deinit();
    const f = c.reserve("r", 30, 0, 0, 0).?;
    c.discard(f);
    try testing.expectEqual(@as(usize, 0), c.pinned_bytes);
    const g = c.reserve("r", 30, 0, 0, 0).?;
    c.clear(); // parks the unfilled node
    try testing.expectEqual(@as(usize, 30), c.pinned_bytes);
    c.discard(g); // doomed path: must not trip the forged-Borrow check
    try testing.expectEqual(@as(usize, 0), c.pinned_bytes);
    try testing.expectEqual(@as(usize, 0), c.stats.pinned);
}
