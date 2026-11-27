// SPDX-License-Identifier: MIT
//! Tests that came out of the 2026-11-25 whole-module mutation run of filestore.
//! What they add over the older tests: an `Io` wrapper (`Wrap`) that sits between
//! the store and the real `std.testing.io`, counts `fsync`s (file and directory
//! apart), and injects the failures a disk gives and a unit test cannot: a
//! cross-device rename, a failing write or open, a rename that "crashes" at a chosen
//! call, a readdir that reports no file types. Everything else here is plain
//! boundary / leak checking with the public API.

const std = @import("std");
const t = std.testing;
const fs = @import("root.zig");
const Store = fs.Store;

/// The real io with a few vtable entries replaced. The userdata stays the real one,
/// so every entry that is not replaced works unchanged; the replaced ones read their
/// knobs from this struct's file-level state (tests run one at a time).
const Wrap = struct {
    var vt: std.Io.VTable = undefined;
    var inner: *const std.Io.VTable = undefined;
    var file_syncs: u32 = 0;
    var dir_syncs: u32 = 0;
    var renames: u32 = 0;
    /// The first rename fails with `error.CrossDevice`.
    var cross_device_first: bool = false;
    /// The n-th rename (1-based) fails; 0 = none.
    var fail_rename_at: u32 = 0;
    /// The next `openFile` of a path ending in this fails with AccessDenied (once).
    var fail_open_suffix: ?[]const u8 = null;
    var fail_writes: bool = false;
    /// The kernel-side file copy reports `Unimplemented` (the buffered fallback runs).
    var no_sendfile: bool = false;
    /// `readdir` reports every entry with an unknown type.
    var unknown_kinds: bool = false;
    var stat_fails_for: ?[]const u8 = null;
    var delete_missing_for: ?[]const u8 = null;
    /// Absolute paths (`/x`) are served from this directory instead of the real root.
    var redirect: ?std.Io.Dir = null;

    fn reset() void {
        file_syncs = 0;
        dir_syncs = 0;
        renames = 0;
        cross_device_first = false;
        fail_rename_at = 0;
        fail_open_suffix = null;
        fail_writes = false;
        no_sendfile = false;
        unknown_kinds = false;
        stat_fails_for = null;
        delete_missing_for = null;
        redirect = null;
    }

    fn io() std.Io {
        inner = t.io.vtable;
        vt = inner.*;
        vt.fileSync = fileSync;
        vt.dirRename = dirRename;
        vt.dirCreateFile = dirCreateFile;
        vt.dirOpenDir = dirOpenDir;
        vt.dirOpenFile = dirOpenFile;
        vt.operate = operate;
        vt.fileWritePositional = fileWritePositional;
        vt.fileWriteFileStreaming = fileWriteFileStreaming;
        vt.fileWriteFilePositional = fileWriteFilePositional;
        vt.dirRead = dirRead;
        vt.dirStatFile = dirStatFile;
        vt.dirDeleteFile = dirDeleteFile;
        reset();
        return .{ .userdata = t.io.userdata, .vtable = &vt };
    }

    fn fileSync(ud: ?*anyopaque, file: std.Io.File) std.Io.File.SyncError!void {
        const st = inner.fileStat(ud, file) catch null;
        if (st != null and st.?.kind == .directory) dir_syncs += 1 else file_syncs += 1;
        return inner.fileSync(ud, file);
    }

    fn dirRename(ud: ?*anyopaque, od: std.Io.Dir, op: []const u8, nd: std.Io.Dir, np: []const u8) std.Io.Dir.RenameError!void {
        renames += 1;
        if (redirect) |rd| if (op.len > 0 and op[0] == '/' and np.len > 0 and np[0] == '/') return inner.dirRename(ud, rd, op[1..], rd, np[1..]);
        if (cross_device_first and renames == 1) return error.CrossDevice;
        if (fail_rename_at != 0 and renames == fail_rename_at) return error.AccessDenied;
        return inner.dirRename(ud, od, op, nd, np);
    }

    fn dirCreateFile(ud: ?*anyopaque, d: std.Io.Dir, p: []const u8, o: std.Io.Dir.CreateFileOptions) std.Io.File.OpenError!std.Io.File {
        if (redirect) |rd| if (p.len > 0 and p[0] == '/') return inner.dirCreateFile(ud, rd, p[1..], o);
        return inner.dirCreateFile(ud, d, p, o);
    }

    fn dirOpenDir(ud: ?*anyopaque, d: std.Io.Dir, p: []const u8, o: std.Io.Dir.OpenOptions) std.Io.Dir.OpenError!std.Io.Dir {
        if (redirect) |rd| if (std.mem.eql(u8, p, "/")) return inner.dirOpenDir(ud, rd, ".", o);
        return inner.dirOpenDir(ud, d, p, o);
    }

    fn dirOpenFile(ud: ?*anyopaque, d: std.Io.Dir, p: []const u8, o: std.Io.Dir.OpenFileOptions) std.Io.File.OpenError!std.Io.File {
        if (fail_open_suffix) |s| if (std.mem.endsWith(u8, p, s)) {
            fail_open_suffix = null;
            return error.AccessDenied;
        };
        return inner.dirOpenFile(ud, d, p, o);
    }

    fn operate(ud: ?*anyopaque, op: std.Io.Operation) std.Io.Cancelable!std.Io.Operation.Result {
        if (fail_writes) switch (op) {
            .file_write_streaming => return .{ .file_write_streaming = error.NoSpaceLeft },
            else => {},
        };
        return inner.operate(ud, op);
    }

    fn fileWritePositional(ud: ?*anyopaque, f: std.Io.File, h: []const u8, d: []const []const u8, splat: usize, off: u64) std.Io.File.WritePositionalError!usize {
        if (fail_writes) return error.NoSpaceLeft;
        return inner.fileWritePositional(ud, f, h, d, splat, off);
    }

    fn fileWriteFileStreaming(ud: ?*anyopaque, f: std.Io.File, h: []const u8, r: *std.Io.File.Reader, l: std.Io.Limit) std.Io.File.Writer.WriteFileError!usize {
        if (no_sendfile) return error.Unimplemented;
        return inner.fileWriteFileStreaming(ud, f, h, r, l);
    }

    fn fileWriteFilePositional(ud: ?*anyopaque, f: std.Io.File, h: []const u8, r: *std.Io.File.Reader, l: std.Io.Limit, off: u64) std.Io.File.WriteFilePositionalError!usize {
        if (no_sendfile) return error.Unimplemented;
        return inner.fileWriteFilePositional(ud, f, h, r, l, off);
    }

    fn dirRead(ud: ?*anyopaque, r: *std.Io.Dir.Reader, es: []std.Io.Dir.Entry) std.Io.Dir.Reader.Error!usize {
        const n = try inner.dirRead(ud, r, es);
        if (unknown_kinds) for (es[0..n]) |*e| {
            e.kind = .unknown;
        };
        return n;
    }

    fn dirStatFile(ud: ?*anyopaque, d: std.Io.Dir, p: []const u8, o: std.Io.Dir.StatFileOptions) std.Io.Dir.StatFileError!std.Io.File.Stat {
        if (stat_fails_for) |s| if (std.mem.eql(u8, p, s)) return error.FileNotFound;
        return inner.dirStatFile(ud, d, p, o);
    }

    fn dirDeleteFile(ud: ?*anyopaque, d: std.Io.Dir, p: []const u8) std.Io.Dir.DeleteFileError!void {
        if (delete_missing_for) |s| if (std.mem.eql(u8, p, s)) return error.FileNotFound;
        return inner.dirDeleteFile(ud, d, p);
    }
};

fn wrapped(tmp: *std.testing.TmpDir, bb: []u8) !Store {
    const base = try std.mem.print(bb, ".zig-cache/tmp/{s}/store", .{&tmp.sub_path});
    return Store.init(Wrap.io(), base);
}

fn plain(tmp: *std.testing.TmpDir, bb: []u8) !Store {
    const base = try std.mem.print(bb, ".zig-cache/tmp/{s}/store", .{&tmp.sub_path});
    return Store.init(t.io, base);
}

fn fdCount() !usize {
    var d = try std.Io.Dir.openDirAbsolute(t.io, "/proc/self/fd", .{ .iterate = true });
    defer d.close(t.io);
    var it = d.iterate();
    var n: usize = 0;
    while (try it.next(t.io)) |_| n += 1;
    return n;
}

fn countParts(tmp: *std.testing.TmpDir, sub: []const u8) !usize {
    var d = try tmp.dir.openDir(t.io, sub, .{ .iterate = true });
    defer d.close(t.io);
    var it = d.iterate();
    var n: usize = 0;
    while (try it.next(t.io)) |e| {
        if (std.mem.endsWith(u8, e.name, ".part")) n += 1;
    }
    return n;
}

/// A clock that answers from a script, one value per call (the last one repeats).
const ScriptClock = struct {
    vals: []const i64,
    calls: usize = 0,
    fn now(ctx: ?*anyopaque) i64 {
        const s: *ScriptClock = @ptrCast(@alignCast(ctx.?));
        const v = s.vals[@min(s.calls, s.vals.len - 1)];
        s.calls += 1;
        return v;
    }
    fn clock(s: *ScriptClock) fs.Clock {
        return .{ .ctx = s, .nowFn = now };
    }
};

fn fixedNow(_: ?*anyopaque) i64 {
    return 0;
}

test "mutation 2026-11-25: fsync counts per operation and durability level (file and directory apart)" {
    var tmp = t.tmpDir(.{});
    defer tmp.cleanup();
    var bb: [256]u8 = undefined;
    var store = try wrapped(&tmp, &bb);
    const gpa = t.allocator;
    try tmp.dir.writeFile(t.io, .{ .sub_path = "src", .data = "payload" });
    const levels = [_]Store.Durability{ .full, .data, .none };
    for (levels) |d| {
        store.durability = d;
        const f: u32 = if (d == .none) 0 else 1; // a file fsync per record
        const dd: u32 = if (d == .full) 1 else 0; // a directory fsync per call
        // putBytes
        Wrap.reset();
        try store.putBytes("k", "a", "1");
        try t.expectEqual(f, Wrap.file_syncs);
        try t.expectEqual(dd, Wrap.dir_syncs);
        // putManyBytes: a file fsync per record, one directory fsync for the batch
        Wrap.reset();
        try store.putManyBytes("k", &.{ .{ .key = "b", .bytes = "2" }, .{ .key = "c", .bytes = "3" }, .{ .key = "d", .bytes = "4" } });
        try t.expectEqual(3 * f, Wrap.file_syncs);
        try t.expectEqual(dd, Wrap.dir_syncs);
        // an empty batch syncs nothing
        Wrap.reset();
        try store.putManyBytes("k", &.{});
        try t.expectEqual(@as(u32, 0), Wrap.file_syncs + Wrap.dir_syncs);
        // createTemp + commit
        var tb: [1024]u8 = undefined;
        const tf = try store.createTemp("k", "e", &tb);
        tf.file.close(t.io);
        Wrap.reset();
        try store.commit("k", "e", tf.tmp);
        try t.expectEqual(f, Wrap.file_syncs);
        try t.expectEqual(dd, Wrap.dir_syncs);
        // importFile, copy and move (same device)
        Wrap.reset();
        try store.importFile("k", "f", tmp.dir, "src", .{});
        try t.expectEqual(f, Wrap.file_syncs);
        try t.expectEqual(dd, Wrap.dir_syncs);
        try tmp.dir.writeFile(t.io, .{ .sub_path = "src2", .data = "payload" });
        Wrap.reset();
        try store.importFile("k", "g", tmp.dir, "src2", .{ .move = true });
        try t.expectEqual(f, Wrap.file_syncs);
        try t.expectEqual(dd, Wrap.dir_syncs);
        // eraseKind: one directory fsync when something was erased, none for an empty kind
        Wrap.reset();
        try t.expectEqual(@as(usize, 7), try store.eraseKind("k"));
        try t.expectEqual(@as(u32, 0), Wrap.file_syncs);
        try t.expectEqual(dd, Wrap.dir_syncs);
        Wrap.reset();
        try t.expectEqual(@as(usize, 0), try store.eraseKind("k"));
        try t.expectEqual(@as(u32, 0), Wrap.dir_syncs);
    }
    // writeFileAtomic's own switches
    const io = Wrap.io();
    const cases = [_]struct { f: bool, d: bool }{ .{ .f = false, .d = false }, .{ .f = true, .d = false }, .{ .f = false, .d = true }, .{ .f = true, .d = true } };
    for (cases) |c| {
        Wrap.reset();
        try fs.writeFileAtomic(io, tmp.dir, "state", "s", .{ .sync_file = c.f, .sync_dir = c.d });
        try t.expectEqual(@as(u32, @intFromBool(c.f)), Wrap.file_syncs);
        try t.expectEqual(@as(u32, @intFromBool(c.d)), Wrap.dir_syncs);
    }
    _ = gpa;
}

test "mutation 2026-11-25: no descriptor is left open by sweep, lockKey, iterate, writeFileAtomic or a failed import" {
    var tmp = t.tmpDir(.{});
    defer tmp.cleanup();
    var bb: [256]u8 = undefined;
    var store = try wrapped(&tmp, &bb);
    var arena_state = std.heap.ArenaAllocator.init(t.allocator);
    defer arena_state.deinit();
    const arena = arena_state.allocator();
    var clk: i64 = 0;
    _ = &clk;
    store.clock = .{ .nowFn = fixedNow };
    try store.putWithTTL("k", "gone", "x", -1); // already expired
    try store.putBytes("k", "stay", "y");
    // sweep, with a swept key and a kept one
    const before = try fdCount();
    try t.expectEqual(@as(usize, 1), try store.sweep(arena, "k"));
    try t.expectEqual(before, try fdCount());
    // lockKey / unlock
    var kl = try store.lockKey("k", "stay");
    kl.unlock();
    try t.expectEqual(before, try fdCount());
    // iterate + deinit
    var it = try store.iterate("k");
    while (try it.next()) |_| {}
    it.deinit();
    try t.expectEqual(before, try fdCount());
    // writeFileAtomic
    try fs.writeFileAtomic(t.io, tmp.dir, "state", "s", .{});
    try t.expectEqual(before, try fdCount());
    // a copy that fails after the temp was created: the temp is closed and removed
    try tmp.dir.writeFile(t.io, .{ .sub_path = "src", .data = "payload" });
    Wrap.fail_open_suffix = "src";
    try t.expectError(error.AccessDenied, store.importFile("k", "imp", tmp.dir, "src", .{}));
    try t.expectEqual(before, try fdCount());
    var sb: [64]u8 = undefined;
    try t.expectEqual(@as(usize, 0), try countParts(&tmp, try std.mem.print(&sb, "store/k", .{})));
    try t.expect(!(try store.has("k", "imp")));
}

test "mutation 2026-11-25: a failing write or rename leaves neither a temp nor a descriptor, and the old record stays" {
    var tmp = t.tmpDir(.{});
    defer tmp.cleanup();
    var bb: [256]u8 = undefined;
    const store = try wrapped(&tmp, &bb);
    var arena_state = std.heap.ArenaAllocator.init(t.allocator);
    defer arena_state.deinit();
    const arena = arena_state.allocator();
    try store.putBytes("k", "r", "old");
    const before = try fdCount();
    // the temp's write fails
    Wrap.fail_writes = true;
    try t.expectError(error.WriteFailed, store.putBytes("k", "r", "new"));
    Wrap.fail_writes = false;
    try t.expectEqual(before, try fdCount());
    try t.expectEqual(@as(usize, 0), try countParts(&tmp, "store/k"));
    try t.expectEqualStrings("old", (try store.getBytes(arena, "k", "r")).?);
    // the rename fails (a directory sits at the record's path)
    try tmp.dir.createDirPath(t.io, "store/k/dirrec");
    try t.expectError(error.IsDir, store.putBytes("k", "dirrec", "x"));
    try t.expectEqual(@as(usize, 0), try countParts(&tmp, "store/k"));
    // the same through importFile (copy): commit fails, its temp is discarded
    try tmp.dir.writeFile(t.io, .{ .sub_path = "src", .data = "payload" });
    try t.expectError(error.IsDir, store.importFile("k", "dirrec", tmp.dir, "src", .{}));
    try t.expectEqual(@as(usize, 0), try countParts(&tmp, "store/k"));
    try t.expectEqual(before, try fdCount());
}

test "mutation 2026-11-25: importFile move across devices copies, then removes the source; the copy is flushed" {
    var tmp = t.tmpDir(.{});
    defer tmp.cleanup();
    var bb: [256]u8 = undefined;
    const store = try wrapped(&tmp, &bb);
    var arena_state = std.heap.ArenaAllocator.init(t.allocator);
    defer arena_state.deinit();
    const arena = arena_state.allocator();
    try tmp.dir.writeFile(t.io, .{ .sub_path = "src", .data = "moved across" });
    Wrap.cross_device_first = true;
    try store.importFile("k", "m", tmp.dir, "src", .{ .move = true });
    try t.expectEqualStrings("moved across", (try store.getBytes(arena, "k", "m")).?);
    try t.expectError(error.FileNotFound, tmp.dir.statFile(t.io, "src", .{}));
    // a copy that cannot use the kernel's file copy goes through the buffered writer: flushed
    Wrap.reset();
    Wrap.no_sendfile = true;
    try tmp.dir.writeFile(t.io, .{ .sub_path = "src3", .data = "buffered copy" });
    try store.importFile("k", "c", tmp.dir, "src3", .{});
    try t.expectEqualStrings("buffered copy", (try store.getBytes(arena, "k", "c")).?);
}

test "mutation 2026-11-25: putWithTTL crashing between its two writes leaves no record (sidecar first)" {
    var tmp = t.tmpDir(.{});
    defer tmp.cleanup();
    var bb: [256]u8 = undefined;
    var store = try wrapped(&tmp, &bb);
    var arena_state = std.heap.ArenaAllocator.init(t.allocator);
    defer arena_state.deinit();
    const arena = arena_state.allocator();
    store.clock = .{ .nowFn = fixedNow };
    // rename 1 is the deadline sidecar, rename 2 the record: "crash" at the second
    Wrap.fail_rename_at = 2;
    try t.expectError(error.AccessDenied, store.putWithTTL("k", "x", "v", 1000));
    Wrap.fail_rename_at = 0;
    try t.expect((try store.getBytes(arena, "k", "x")) == null);
    try t.expect(!(try store.has("k", "x")));
    // the other order would have left a permanent record: it is never visible
    try store.putWithTTL("k", "y", "v", 1000);
    try t.expectEqualStrings("v", (try store.getBytes(arena, "k", "y")).?);
}

test "mutation 2026-11-25: a readdir without file types (DT_UNKNOWN) is resolved by stat; a vanished entry is skipped" {
    var tmp = t.tmpDir(.{});
    defer tmp.cleanup();
    var bb: [256]u8 = undefined;
    const store = try wrapped(&tmp, &bb);
    var arena_state = std.heap.ArenaAllocator.init(t.allocator);
    defer arena_state.deinit();
    const arena = arena_state.allocator();
    try store.putBytes("k", "a", "1");
    try store.putBytes("k", "gone", "2");
    try tmp.dir.createDirPath(t.io, "store/k/subdir");
    Wrap.unknown_kinds = true;
    Wrap.stat_fails_for = "gone";
    const keys = try store.list(arena, "k");
    try t.expectEqual(@as(usize, 1), keys.len);
    try t.expectEqualStrings("a", keys[0]);
}

test "mutation 2026-11-25: eraseKind skips a record that a concurrent delete already removed" {
    var tmp = t.tmpDir(.{});
    defer tmp.cleanup();
    var bb: [256]u8 = undefined;
    const store = try wrapped(&tmp, &bb);
    try store.putBytes("k", "a", "1");
    try store.putBytes("k", "ghost", "2");
    Wrap.delete_missing_for = "ghost";
    try t.expectEqual(@as(usize, 1), try store.eraseKind("k"));
}

test "mutation 2026-11-25: casPutBytes over a live TTL record reads the clock once and keeps the deadline" {
    var tmp = t.tmpDir(.{});
    defer tmp.cleanup();
    var bb: [256]u8 = undefined;
    var store = try plain(&tmp, &bb);
    var arena_state = std.heap.ArenaAllocator.init(t.allocator);
    defer arena_state.deinit();
    const arena = arena_state.allocator();
    store.clock = .{ .nowFn = fixedNow };
    try store.putWithTTL("k", "cas", "v1", 100); // deadline 100
    // CAS: getBytes sees the record live (clock 50); the CAS must not look at the clock again
    // for a record that exists; if it did (clock 200) it would clear the deadline.
    var sc = ScriptClock{ .vals = &.{ 50, 200 } };
    store.clock = sc.clock();
    _ = try store.casPutBytes(arena, "k", "cas", "v2", fs.versionOf("v1"));
    var late = ScriptClock{ .vals = &.{200} };
    store.clock = late.clock();
    try t.expect((try store.getBytes(arena, "k", "cas")) == null); // the old deadline still holds
}

test "mutation 2026-11-25: sweep leaves a key alone whose deadline was renewed between pre-check and lock" {
    var tmp = t.tmpDir(.{});
    defer tmp.cleanup();
    var bb: [256]u8 = undefined;
    var store = try plain(&tmp, &bb);
    var arena_state = std.heap.ArenaAllocator.init(t.allocator);
    defer arena_state.deinit();
    const arena = arena_state.allocator();
    store.clock = .{ .nowFn = fixedNow };
    try store.putWithTTL("s", "only", "v", 100);
    var sc = ScriptClock{ .vals = &.{ 200, 50, 50, 50 } };
    store.clock = sc.clock();
    try t.expectEqual(@as(usize, 0), try store.sweep(arena, "s"));
    try t.expectEqualStrings("v", (try store.getBytes(arena, "s", "only")).?);
}

test "mutation 2026-11-25: names are validated on createTemp, lockKey, putManyBytes (empty batch too)" {
    var tmp = t.tmpDir(.{});
    defer tmp.cleanup();
    var bb: [256]u8 = undefined;
    const store = try plain(&tmp, &bb);
    var tb: [1024]u8 = undefined;
    try t.expectError(error.InvalidName, store.createTemp("a/b", "k", &tb));
    try t.expectError(error.InvalidName, store.createTemp("..", "k", &tb));
    try t.expectError(error.InvalidName, store.lockKey("a/b", "k"));
    try t.expectError(error.InvalidName, store.lockKey("k", "a/b"));
    try t.expectError(error.InvalidName, store.putManyBytes("..", &.{}));
    try t.expectError(error.InvalidName, store.putManyBytes(".", &.{.{ .key = "x", .bytes = "1" }}));
}

test "mutation 2026-11-25: ttl=false opens and has() ignore an expired deadline; has() is false for a directory" {
    var tmp = t.tmpDir(.{});
    defer tmp.cleanup();
    var bb: [256]u8 = undefined;
    var store = try plain(&tmp, &bb);
    store.clock = .{ .nowFn = fixedNow };
    try store.putWithTTL("k", "old", "v", -1); // expired
    try t.expect(!(try store.has("k", "old")));
    try t.expect((try store.openRecord("k", "old")) == null);
    var opt = store;
    opt.ttl = false;
    try t.expect(try opt.has("k", "old"));
    const f = (try opt.openRecord("k", "old")).?;
    f.close(t.io);
    // a directory at a record path is no live record
    try tmp.dir.createDirPath(t.io, "store/k/adir");
    try t.expect(!(try store.has("k", "adir")));
}

test "mutation 2026-11-25: putBytesVersioned returns the version of what it wrote" {
    var tmp = t.tmpDir(.{});
    defer tmp.cleanup();
    var bb: [256]u8 = undefined;
    const store = try plain(&tmp, &bb);
    const v = try store.putBytesVersioned("k", "a", "payload");
    try t.expectEqual(fs.versionOf("payload"), v);
    try t.expect(v != 0);
    var arena_state = std.heap.ArenaAllocator.init(t.allocator);
    defer arena_state.deinit();
    const cas = try store.casPutBytes(arena_state.allocator(), "k", "a", "next", v);
    try t.expectEqual(fs.versionOf("next"), cas);
}

test "mutation 2026-11-25: iterateTyped goes on past a record that is expired (absent), it does not stop" {
    var tmp = t.tmpDir(.{});
    defer tmp.cleanup();
    var bb: [256]u8 = undefined;
    var store = try plain(&tmp, &bb);
    var arena_state = std.heap.ArenaAllocator.init(t.allocator);
    defer arena_state.deinit();
    const arena = arena_state.allocator();
    store.clock = .{ .nowFn = fixedNow };
    var names: [24][8]u8 = undefined;
    for (&names, 0..) |*n, i| {
        const name = try std.mem.print(n, "{s}{d:0>2}", .{ if (i % 2 == 0) "x" else "l", i });
        if (i % 2 == 0) try store.putWithTTL("k", name, "1", -1) else try store.putBytes("k", name, "2");
    }
    const r = try store.listTyped(u32, arena, "k");
    try t.expectEqual(@as(usize, 12), r.items.len);
    try t.expectEqual(@as(usize, 0), r.skipped);
}

test "mutation 2026-11-25: encodeKey: 128 bytes fit, 129 are NameTooLong, a buffer of exactly the size fits" {
    var big: [300]u8 = undefined;
    const raw128: [128]u8 = @splat('a');
    const raw129: [129]u8 = @splat('a');
    const k = try fs.encodeKey(&big, &raw128);
    try t.expectEqual(@as(usize, 128), k.len);
    try t.expectError(error.NameTooLong, fs.encodeKey(&big, &raw129));
    var exact: [5]u8 = undefined;
    try t.expectEqualStrings("abcde", try fs.encodeKey(&exact, "abcde"));
    try t.expectError(error.NameTooLong, fs.encodeKey(&exact, "abcdef"));
    try t.expectError(error.InvalidName, fs.encodeKey(&big, ""));
}

test "mutation 2026-11-25: writeFileAtomic accepts a 900-byte path and refuses 901" {
    var tmp = t.tmpDir(.{});
    defer tmp.cleanup();
    var path: [901]u8 = undefined;
    var n: usize = 0;
    const seg: [200]u8 = @splat('d');
    for (0..4) |_| {
        @memcpy(path[n..][0..200], &seg);
        path[n + 200] = '/';
        n += 201;
        try tmp.dir.createDirPath(t.io, path[0 .. n - 1]);
    }
    // 900 bytes: 804 of directories + a 96-byte name
    @memset(path[n..900], 'f');
    try fs.writeFileAtomic(t.io, tmp.dir, path[0..900], "ok", .{});
    @memset(path[n..901], 'g');
    try t.expectError(error.NoSpaceLeft, fs.writeFileAtomic(t.io, tmp.dir, path[0..901], "no", .{}));
}

test "mutation 2026-11-25: a temp that already exists under the next name is truncated, not appended to" {
    var tmp = t.tmpDir(.{});
    defer tmp.cleanup();
    var bb: [256]u8 = undefined;
    const store = try plain(&tmp, &bb);
    var tb: [1024]u8 = undefined;
    const first = try store.createTemp("k", "rec", &tb);
    first.file.close(t.io);
    // ".rec-<pid>-<n>.part": the next call gets n+1
    const dash = std.mem.lastIndexOfScalar(u8, first.tmp, '-').?;
    const n = try std.fmt.parseInt(u64, first.tmp[dash + 1 .. first.tmp.len - ".part".len], 10);
    var nb: [1024]u8 = undefined;
    const next_path = try std.mem.print(&nb, "{s}-{d}.part", .{ first.tmp[0..dash], n + 1 });
    try std.Io.Dir.cwd().writeFile(t.io, .{ .sub_path = next_path, .data = "JUNKJUNKJUNKJUNKJUNKJUNKJUNKJUNK" });
    var tb2: [1024]u8 = undefined;
    const second = try store.createTemp("k", "rec", &tb2);
    try t.expectEqualStrings(next_path, second.tmp);
    try second.file.writePositionalAll(t.io, "abc", 0);
    second.file.close(t.io);
    try store.commit("k", "rec", second.tmp);
    const got = (try store.getBytes(t.allocator, "k", "rec")).?;
    defer t.allocator.free(got);
    try t.expectEqualStrings("abc", got);
    store.discardTemp(first.tmp);
}

test "mutation 2026-11-25: writeFileAtomic into the root directory syncs the root directory, not an empty path" {
    var tmp = t.tmpDir(.{});
    defer tmp.cleanup();
    const io = Wrap.io();
    Wrap.redirect = tmp.dir; // a writable stand-in for "/"
    try fs.writeFileAtomic(io, std.Io.Dir.cwd(), "/rootfile", "x", .{});
    Wrap.redirect = null;
    var buf: [8]u8 = undefined;
    const got = try tmp.dir.readFile(t.io, "rootfile", &buf);
    try t.expectEqualStrings("x", got);
    try t.expectEqual(@as(u32, 1), Wrap.dir_syncs);
}
