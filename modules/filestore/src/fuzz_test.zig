// SPDX-License-Identifier: MIT

//! Model-based fuzz harness for `Store` (added 2026-11-01): random sequences
//! of every public operation on one store, each answer compared with an
//! in-memory model of what the store must hold — record bytes per key, the
//! `.expiry` deadline per key, a manual clock. The model encodes the
//! documented semantics, including the surprising ones: `putBytes` keeps an
//! old deadline, `list`/`delete`/`eraseKind` see an expired-but-unswept
//! record, `casPutBytes` compares against the LIVE version.
//!
//! Driver: `FILESTORE_FUZZ=<runs>[,<first seed>]` (testkit's fuzz driver;
//! `_MS`, `_SEEDFILE`, `_INPUT`, `_ONLY` as documented there). Harness name:
//! `ops`. Every op is durable (fsync), so runs cost disk time: the in-test
//! sweep is small, longer runs go through the driver.

const std = @import("std");
const testing = std.testing;
const testkit = @import("testkit");
const fuzz_driver = testkit.fuzz.driver;
const fs = @import("root.zig");

pub const Label = enum { put, get_hit, get_miss, delete_hit, delete_miss, has, cas_ok, cas_mismatch, ttl_put, expired_seen, sweep_reaped, list, list_prefix, stream, open_hit, erase, put_many, import_copy, import_move };
var reach: [@typeInfo(Label).@"enum".field_names.len]usize = @splat(0);

fn mark(l: Label) void {
    reach[@backingInt(l)] += 1;
    switch (l) {
        inline else => |c| fuzz_driver.hit(@tagName(c)),
    }
}

const key_pool = [_][]const u8{ "a", "b", "dev-1", "dev-2", "x.y", "Z_9" };
const max_val = 48;

const Model = struct {
    present: [key_pool.len]bool = @splat(false),
    len: [key_pool.len]usize = @splat(0),
    val: [key_pool.len][max_val]u8 = undefined,
    deadline: [key_pool.len]?i64 = @splat(null),

    fn live(m: *const Model, i: usize, now: i64) bool {
        if (!m.present[i]) return false;
        const d = m.deadline[i] orelse return true;
        return now < d;
    }
    fn bytes(m: *const Model, i: usize) []const u8 {
        return m.val[i][0..m.len[i]];
    }
    fn set(m: *Model, i: usize, v: []const u8) void {
        m.present[i] = true;
        m.len[i] = v.len;
        @memcpy(m.val[i][0..v.len], v);
    }
    fn remove(m: *Model, i: usize) void {
        m.present[i] = false;
        m.deadline[i] = null;
    }
};

const ManualClock = struct {
    now_ns: i64,
    fn clock(mc: *ManualClock) fs.Clock {
        return .{ .ctx = mc, .nowFn = now };
    }
    fn now(ctx: ?*anyopaque) i64 {
        const mc: *ManualClock = @ptrCast(@alignCast(ctx.?));
        return mc.now_ns;
    }
};

fn drawVal(comptime S: type, src: *S, buf: *[max_val]u8) []const u8 {
    const n = src.valueRangeAtMost(u8, 0, max_val);
    src.bytes(buf[0..n]);
    return buf[0..n];
}

pub fn opsHarness(comptime S: type, src: *S, gpa: std.mem.Allocator) anyerror!void {
    var tmp = testing.tmpDir(.{});
    defer tmp.cleanup();
    var base_buf: [256]u8 = undefined;
    const base = try std.mem.print(&base_buf, ".zig-cache/tmp/{s}/store", .{&tmp.sub_path});
    var store = try fs.Store.init(testing.io, base);
    var clk: ManualClock = .{ .now_ns = 1_000_000 };
    store.clock = clk.clock();
    const io = testing.io;
    const kind = "k";

    var arena_state = std.heap.ArenaAllocator.init(gpa);
    defer arena_state.deinit();
    const arena = arena_state.allocator();

    var m: Model = .{};
    var vbuf: [max_val]u8 = undefined;
    const n_ops = src.valueRangeAtMost(u8, 1, 24);
    for (0..n_ops) |_| {
        _ = arena_state.reset(.retain_capacity);
        const i = src.index(key_pool.len);
        const key = key_pool[i];
        const now = clk.now_ns;
        switch (src.valueRangeAtMost(u8, 0, 15)) {
            0 => {
                const v = drawVal(S, src, &vbuf);
                try store.putBytes(kind, key, v);
                m.set(i, v);
                mark(.put);
            },
            1 => {
                const got = try store.getBytes(arena, kind, key);
                if (m.live(i, now)) {
                    try testing.expectEqualSlices(u8, m.bytes(i), got orelse return error.ModelMismatch);
                    mark(.get_hit);
                } else {
                    if (got != null) return error.ModelMismatch;
                    if (m.present[i]) mark(.expired_seen) else mark(.get_miss);
                }
            },
            2 => {
                const existed = try store.delete(kind, key);
                try testing.expectEqual(m.present[i], existed);
                mark(if (existed) .delete_hit else .delete_miss);
                m.remove(i);
            },
            3 => {
                try testing.expectEqual(m.live(i, now), try store.has(kind, key));
                mark(if (m.present[i] and !m.live(i, now)) .expired_seen else .has);
            },
            4 => {
                const v = drawVal(S, src, &vbuf);
                // Expected: the live version, null, or a wrong one.
                const expected: ?fs.Version = switch (src.valueRangeAtMost(u8, 0, 2)) {
                    0 => if (m.live(i, now)) fs.versionOf(m.bytes(i)) else null,
                    1 => null,
                    else => fs.versionOf("never stored") +% 1,
                };
                const ok = if (expected) |e| m.live(i, now) and fs.versionOf(m.bytes(i)) == e else !m.live(i, now);
                if (store.casPutBytes(arena, kind, key, v, expected)) |ver| {
                    if (!ok) return error.ModelMismatch;
                    try testing.expectEqual(fs.versionOf(v), ver);
                    m.set(i, v);
                    mark(.cas_ok);
                } else |e| {
                    if (e != error.VersionMismatch or ok) return e;
                    mark(.cas_mismatch);
                }
            },
            5 => {
                const v = drawVal(S, src, &vbuf);
                const ttl: i64 = src.valueRangeAtMost(u8, 1, 20);
                try store.putWithTTL(kind, key, v, ttl);
                m.set(i, v);
                m.deadline[i] = now + ttl;
                mark(.ttl_put);
                // Half the time the deadline passes at once: expiry must be
                // common, or get/has/open/sweep rarely see an expired record.
                if (src.value(bool)) clk.now_ns += ttl;
            },
            6 => clk.now_ns += src.valueRangeAtMost(u8, 0, 40),
            7 => {
                var want: usize = 0;
                for (0..key_pool.len) |j| {
                    if (m.present[j] and m.deadline[j] != null and now >= m.deadline[j].?) {
                        want += 1;
                        m.remove(j);
                    }
                }
                try testing.expectEqual(want, try store.sweep(arena, kind));
                if (want > 0) mark(.sweep_reaped);
            },
            8, 9 => {
                const prefix: []const u8 = if (src.value(bool)) "dev-" else "";
                const keys = try store.listPrefix(arena, kind, prefix);
                var want: usize = 0;
                for (0..key_pool.len) |j| {
                    if (!m.present[j] or !std.mem.startsWith(u8, key_pool[j], prefix)) continue;
                    want += 1;
                    var found = false;
                    for (keys) |k| found = found or std.mem.eql(u8, k, key_pool[j]);
                    if (!found) return error.ModelMismatch;
                }
                try testing.expectEqual(want, keys.len);
                mark(if (prefix.len > 0) .list_prefix else .list);
            },
            10 => {
                const v = drawVal(S, src, &vbuf);
                var tb: [1024]u8 = undefined;
                const t = try store.createTemp(kind, key, &tb);
                {
                    var wb: [16]u8 = undefined;
                    var w = t.file.writer(io, &wb);
                    try w.interface.writeAll(v);
                    try w.interface.flush();
                }
                t.file.close(io);
                if (src.value(bool)) {
                    try store.commit(kind, key, t.tmp);
                    m.set(i, v);
                } else store.discardTemp(t.tmp);
                mark(.stream);
            },
            11 => {
                const f = try store.openRecord(kind, key);
                if (m.live(i, now)) {
                    const file = f orelse return error.ModelMismatch;
                    defer file.close(io);
                    var rb: [max_val + 1]u8 = undefined;
                    const n = try file.readPositionalAll(io, &rb, 0);
                    try testing.expectEqualSlices(u8, m.bytes(i), rb[0..n]);
                    mark(.open_hit);
                } else if (f) |file| {
                    file.close(io);
                    return error.ModelMismatch;
                } else if (m.present[i]) mark(.expired_seen);
            },
            12 => {
                var want: usize = 0;
                for (0..key_pool.len) |j| if (m.present[j]) {
                    want += 1;
                    m.remove(j);
                };
                try testing.expectEqual(want, try store.eraseKind(kind));
                mark(.erase);
            },
            13 => {
                var entries: [3]fs.Store.Entry = undefined;
                var vals: [3][max_val]u8 = undefined;
                const n = src.valueRangeAtMost(u8, 1, 3);
                var idx: [3]usize = undefined;
                for (0..n) |e| {
                    idx[e] = src.index(key_pool.len);
                    entries[e] = .{ .key = key_pool[idx[e]], .bytes = drawVal(S, src, &vals[e]) };
                }
                try store.putManyBytes(kind, entries[0..n]);
                for (0..n) |e| m.set(idx[e], entries[e].bytes);
                mark(.put_many);
            },
            else => {
                const v = drawVal(S, src, &vbuf);
                try tmp.dir.writeFile(io, .{ .sub_path = "import-src", .data = v });
                const move = src.value(bool);
                try store.importFile(kind, key, tmp.dir, "import-src", .{ .move = move });
                m.set(i, v);
                mark(if (move) .import_move else .import_copy);
            },
        }
    }

    // After every sequence: the kind directory holds records and sidecars
    // only — no ingest/stream temp survived a completed op.
    var pb: [320]u8 = undefined;
    var d = std.Io.Dir.cwd().openDir(io, try std.mem.print(&pb, "{s}/{s}", .{ base, kind }), .{ .iterate = true }) catch |e| switch (e) {
        error.FileNotFound => return,
        else => return e,
    };
    defer d.close(io);
    var it = d.iterate();
    while (try it.next(io)) |e| {
        if (std.mem.endsWith(u8, e.name, ".part")) {
            std.debug.print("leftover temp {s}\n", .{e.name});
            return error.LeftoverTemp;
        }
    }
}

/// `testing.fuzz`'s source: the bytes come FIRST, in one `slice` draw, and
/// every choice is read from them by a cursor.
const ScriptSource = struct {
    cur: testkit.fuzz.Cursor,

    pub fn valueRangeAtMost(self: *ScriptSource, comptime T: type, at_least: T, at_most: T) T {
        return @intCast(self.cur.ranged(at_least, at_most));
    }
    pub fn value(self: *ScriptSource, comptime T: type) T {
        return switch (T) {
            bool => self.cur.byte() & 1 == 1,
            else => @compileError("ScriptSource.value: unsupported type"),
        };
    }
    pub fn bytes(self: *ScriptSource, buf: []u8) void {
        for (buf) |*b| b.* = self.cur.byte();
    }
    pub fn index(self: *ScriptSource, len: usize) usize {
        return self.cur.ranged(0, @intCast(len - 1));
    }
};

fn fuzzOps(_: void, smith: *std.testing.Smith) !void {
    var raw: [512]u8 = undefined;
    const n: usize = smith.slice(&raw);
    var src: ScriptSource = .{ .cur = .{ .bytes = raw[0..n] } };
    try opsHarness(ScriptSource, &src, testing.allocator);
}

test "fuzz: Store operations agree with the model" {
    try testing.fuzz({}, fuzzOps, .{});
}

test "fuzz driver: FILESTORE_FUZZ (ops)" {
    try fuzz_driver.run(opsHarness, .{ .prefix = "FILESTORE_FUZZ", .name = "ops" });
}

test "fuzz harness: 100 seeds in every test run, and every label is reached" {
    reach = @splat(0);
    for (0..100) |seed| {
        var prng = std.Random.DefaultPrng.init(seed);
        var rng: fuzz_driver.Rng = .{ .r = prng.random() };
        opsHarness(fuzz_driver.Rng, &rng, testing.allocator) catch |err| {
            std.debug.print("filestore ops seed {d}: {t}\n", .{ seed, err });
            return err;
        };
    }
    for (reach, 0..) |n, i| if (n == 0) {
        std.debug.print("reach: label {t} never hit\n", .{@as(Label, @fromBackingInt(@intCast(i)))});
        return error.HarnessDoesNotReach;
    };
}
