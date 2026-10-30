// SPDX-License-Identifier: MIT

//! No-panic sweep tests for `Sharded` (wave GQ). Names end with
//! "(sweep <ID>)".

const std = @import("std");
const builtin = @import("builtin");
const Sharded = @import("sharded.zig").Sharded;

const linux = std.os.linux;
const testing = std.testing;

const Outcome = enum { exited_ok, exited_bad, signaled, hung };

/// Run `body` in a forked child (a hang or a panic must not take the test
/// binary with it) and report how it ended. `body` returns true for "all
/// fine"; a child past five seconds counts as hung.
fn runChild(comptime body: fn () bool) !Outcome {
    if (builtin.os.tag != .linux) return error.SkipZigTest;
    const rc = linux.fork();
    if (linux.errno(rc) != .SUCCESS) return error.SkipZigTest;
    if (rc == 0) linux.exit_group(if (body()) 0 else 1);
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
            return .hung;
        }
        const ts: linux.timespec = .{ .sec = 0, .nsec = 10 * std.time.ns_per_ms };
        _ = linux.nanosleep(&ts, null);
        waited_ms += 10;
    }
    if (linux.W.IFSIGNALED(status)) return .signaled;
    return if (linux.W.EXITSTATUS(status) == 0) .exited_ok else .exited_bad;
}

fn newCache(on_evict: ?@import("root.zig").OnEvictFn, ctx: ?*anyopaque) !Sharded {
    return Sharded.init(testing.allocator, .{
        .max_bytes = 1 << 20,
        .max_entries = 64,
        .shards = 1,
        .on_evict = on_evict,
        .on_evict_ctx = ctx,
    });
}

test "shardStats: an index past shardCount is an empty Stats, not an out-of-bounds read (sweep RS-H-1)" {
    var sc = try newCache(null, null);
    defer sc.deinit();
    sc.put("k", "v", 0, 0, 0);
    try testing.expectEqual(@as(usize, 1), sc.shardStats(0).entries);
    const none = sc.shardStats(sc.shardCount());
    try testing.expectEqual(@as(usize, 0), none.entries);
    try testing.expectEqual(@as(u64, 0), none.hits);
    try testing.expectEqual(@as(usize, 0), sc.shardStats(std.math.maxInt(usize)).bytes);
}

// ── RS-H-2: a loader asking for its own key ─────────────────────────────────

var reentrant_sc: *Sharded = undefined;
var reentrant_inner: ?anyerror = null;

fn reentrantLoad(_: ?*anyopaque, gpa: std.mem.Allocator, key: []const u8) @import("root.zig").LoadError![]u8 {
    // Same key, same thread: used to wait for itself forever.
    if (reentrant_sc.getOrLoad(gpa, key, 0, 0, 0, 0, .{ .ctx = null, .load = nestedLoaderUnused })) |v| {
        gpa.free(v);
    } else |e| reentrant_inner = e;
    return gpa.dupe(u8, "outer");
}

fn nestedLoaderUnused(_: ?*anyopaque, _: std.mem.Allocator, _: []const u8) @import("root.zig").LoadError![]u8 {
    return error.LoadFailed;
}

fn reentrantLoaderBody() bool {
    var sc = newCache(null, null) catch return false;
    defer sc.deinit();
    reentrant_sc = &sc;
    const outer = sc.getOrLoad(testing.allocator, "k", 0, 0, 0, 0, .{ .ctx = null, .load = reentrantLoad }) catch return false;
    defer testing.allocator.free(outer);
    return std.mem.eql(u8, outer, "outer") and reentrant_inner != null and reentrant_inner.? == error.LoadFailed;
}

test "getOrLoad: a loader that asks for its own key gets LoadFailed instead of waiting for itself (sweep RS-H-2)" {
    try testing.expectEqual(Outcome.exited_ok, try runChild(reentrantLoaderBody));
}

// ── RS-H-3: a callback calling back into the same Sharded ───────────────────

var cb_sc: *Sharded = undefined;

fn evictReenters(_: ?*anyopaque, _: []const u8, _: []const u8, _: bool, _: @import("root.zig").EvictReason) void {
    var buf: [8]u8 = undefined;
    _ = cb_sc.getBuf("other", 0, 0, &buf); // same (only) shard: used to hang
}

fn evictReentersBody() bool {
    var sc = newCache(evictReenters, null) catch return false;
    defer sc.deinit();
    cb_sc = &sc;
    sc.put("a", "1", 0, 0, 0);
    sc.put("a", "2", 0, 0, 0); // replaces: on_evict(.replaced) fires under the lock
    return true; // not reached when the re-entry is diagnosed
}

test "on_evict calling a method of the same Sharded dies with a diagnosis, it does not hang (sweep RS-H-3)" {
    try testing.expectEqual(Outcome.signaled, try runChild(evictReentersBody));
}

fn drainReenters(_: ?*anyopaque, _: []const u8, _: []const u8) void {
    _ = cb_sc.markClean("a");
}

fn drainReentersBody() bool {
    var sc = newCache(null, null) catch return false;
    defer sc.deinit();
    cb_sc = &sc;
    sc.put("a", "1", 0, 0, 0);
    sc.drainDirty(drainReenters, null);
    return true;
}

test "drainDirty callback calling a method of the same Sharded dies with a diagnosis, it does not hang (sweep RS-H-3)" {
    try testing.expectEqual(Outcome.signaled, try runChild(drainReentersBody));
}

const Seen = struct { evict: usize = 0, drain: usize = 0, saw_ctx: bool = true };

fn countEvict(ctx: ?*anyopaque, _: []const u8, _: []const u8, dirty: bool, _: @import("root.zig").EvictReason) void {
    const s: *Seen = @ptrCast(@alignCast(ctx.?));
    s.evict += 1;
    if (!dirty) s.saw_ctx = false;
}

fn countDrain(ctx: ?*anyopaque, _: []const u8, _: []const u8) void {
    const s: *Seen = @ptrCast(@alignCast(ctx.?));
    s.drain += 1;
}

test "the callbacks still get the caller's ctx and fire once per event, and the marker is cleared after (sweep RS-H-3)" {
    var seen: Seen = .{};
    var sc = try newCache(countEvict, &seen);
    defer sc.deinit();
    sc.put("a", "1", 0, 0, 0);
    sc.put("a", "2", 0, 0, 0);
    sc.drainDirty(countDrain, &seen);
    try testing.expectEqual(@as(usize, 1), seen.evict);
    try testing.expectEqual(@as(usize, 1), seen.drain);
    try testing.expect(seen.saw_ctx);
    // After the callbacks returned this thread holds nothing: ordinary calls
    // on the same shard, even contended ones, must not be taken for re-entry.
    sc.put("b", "3", 0, 0, 0);
    var buf: [4]u8 = undefined;
    try testing.expect(sc.getBuf("b", 1, 0, &buf) == .ok);
}

test "Options.max_key_len reaches every shard: 65-byte key refused, 64-byte stored (sweep REV-SH-4)" {
    var sc = try Sharded.init(testing.allocator, .{ .max_bytes = 1 << 20, .max_entries = 64, .shards = 4, .max_key_len = 64 });
    defer sc.deinit();
    const k64: [64]u8 = @splat('k');
    const k65: [65]u8 = @splat('k');
    sc.put(&k65, "v", 0, 0, 0);
    sc.put(&k64, "v", 0, 0, 0);
    var buf: [4]u8 = undefined;
    try testing.expect(sc.getBuf(&k65, 1, 0, &buf) == .miss);
    try testing.expect(sc.getBuf(&k64, 1, 0, &buf) == .ok);
    try testing.expectEqual(@as(usize, 1), sc.stats().entries);
}

test "Options.shards is clamped to max_shards, not honoured and not refused (sweep REV-SH-4)" {
    var sc = try Sharded.init(testing.allocator, .{ .max_bytes = 1 << 40, .max_entries = 1 << 30, .shards = std.math.maxInt(usize) });
    defer sc.deinit();
    try testing.expectEqual(Sharded.max_shards, sc.shardCount());
    var sc2 = try Sharded.init(testing.allocator, .{ .max_bytes = 1 << 40, .max_entries = 1 << 30, .shards = 100_000 });
    defer sc2.deinit();
    try testing.expectEqual(Sharded.max_shards, sc2.shardCount());
}
