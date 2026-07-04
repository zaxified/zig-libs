// SPDX-License-Identifier: MIT

//! Deterministic fault-simulating `Storage` backend — the mini-VOPR seam.
//!
//! `SimStorage` implements the `kv.Storage` interface entirely in memory and
//! models what an OS + disk guarantee (and, more importantly, what they do
//! NOT guarantee) across a crash:
//!
//!   * every file is `content` (the volatile view: what the process observes
//!     through the page cache) plus a `durable_len` watermark (the prefix
//!     guaranteed to be on media — advanced only by a completed `sync`);
//!   * the *namespace* (which name maps to which file) has the same split:
//!     `open`-created names, `rename`s and `delete`s land in the volatile
//!     namespace immediately but become durable only at `syncDir` — exactly
//!     the POSIX contract that makes the temp+fsync+rename+dirfsync dance
//!     necessary;
//!   * a **crash** can be scheduled at the N-th storage side effect
//!     (`ops_until_crash`). When it fires, the side effect does not complete,
//!     `error.Crashed` is returned, and the simulated media is collapsed to
//!     its post-crash state per `crash_mode`:
//!       - `.lose_unsynced` — nothing beyond the last `sync`/`syncDir`
//!         survives (the strict model);
//!       - `.keep_unsynced` — the OS happened to flush everything before
//!         dying (writes survive *without* an fsync — catches code that
//!         confuses "visible" with "durable" in the other direction);
//!       - `.torn_tail`   — half of each file's un-synced tail survives, and
//!         the write the crash landed on is itself torn in half (a partial
//!         sector flush → a torn trailing record).
//!     After the crash every further call fails with `error.Crashed` (the
//!     process is dead) until `reboot()` — so a `defer close()` in the code
//!     under test cannot accidentally mutate post-crash state.
//!
//! Everything is deterministic: no clock, no randomness, no real I/O. The
//! sweep in `fault_test.zig` replays a scripted workload once per (crash
//! point × crash mode) pair and asserts recovery invariants after each.
//!
//! Injection points (side effects that count toward `ops_until_crash`):
//! `open`, `writeAll`, `sync`, `truncate`, `rename`, `delete`, `syncDir`.
//! Pure reads (`pread`, `size`) and `close` are not side effects — crashing
//! "at" them is indistinguishable from crashing before the next side effect.

const std = @import("std");
const root = @import("root.zig");
const Storage = root.Storage;
const Allocator = std.mem.Allocator;

/// What survives of un-synced state when the simulated machine dies.
pub const CrashMode = enum {
    /// Only fsync'd data / syncDir'd namespace survives (strict).
    lose_unsynced,
    /// Everything written before the crash survives (lucky flush).
    keep_unsynced,
    /// Half of each un-synced tail survives; the in-flight write is torn.
    torn_tail,
};

pub const SimStorage = struct {
    gpa: Allocator,
    /// Volatile namespace: what the running process sees.
    names: std.StringHashMapUnmanaged(*SimFile) = .empty,
    /// Durable namespace: what is on media (advanced by `syncDir`).
    durable_names: std.StringHashMapUnmanaged(*SimFile) = .empty,
    /// Every file ever created — owner of the SimFile allocations (files
    /// unlinked from both namespaces stay here until `deinit`, like an
    /// inode held open).
    all_files: std.ArrayListUnmanaged(*SimFile) = .empty,
    handles: std.ArrayListUnmanaged(?*SimFile) = .empty,
    crash_mode: CrashMode = .lose_unsynced,
    /// When non-null: the side effect after this many more side effects
    /// crashes (0 = the very next one). Null = never crash.
    ops_until_crash: ?usize = null,
    /// True after a crash fired; every op fails until `reboot()`.
    crashed: bool = false,
    /// Total side effects observed (counting run → sweep bound).
    ops_seen: usize = 0,

    const SimFile = struct {
        content: std.ArrayListUnmanaged(u8) = .empty,
        durable_len: usize = 0,
    };

    pub fn init(gpa: Allocator) SimStorage {
        return .{ .gpa = gpa };
    }

    pub fn deinit(self: *SimStorage) void {
        freeNames(self.gpa, &self.names);
        freeNames(self.gpa, &self.durable_names);
        for (self.all_files.items) |f| {
            f.content.deinit(self.gpa);
            self.gpa.destroy(f);
        }
        self.all_files.deinit(self.gpa);
        self.handles.deinit(self.gpa);
        self.* = undefined;
    }

    /// The `Storage` interface view of this simulator.
    pub fn storage(self: *SimStorage) Storage {
        return .{ .ctx = self, .vtable = &vtable };
    }

    /// Clear the crashed flag so the "machine" can be booted again. The
    /// post-crash media state (applied when the crash fired) is what the
    /// next `open` sees. Also disables further injection.
    pub fn reboot(self: *SimStorage) void {
        self.crashed = false;
        self.ops_until_crash = null;
    }

    /// Test helper: current volatile content of `path` (null if absent).
    pub fn fileContent(self: *SimStorage, path: []const u8) ?[]u8 {
        const f = self.names.get(path) orelse return null;
        return f.content.items;
    }

    /// Test helper: corrupt one byte of `path` at `off`, in both the
    /// volatile view and (by construction) the durable prefix.
    pub fn flipByte(self: *SimStorage, path: []const u8, off: usize) void {
        const f = self.names.get(path).?;
        f.content.items[off] ^= 0x40;
    }

    /// Test helper: append raw bytes to `path` and mark them durable —
    /// simulates a torn tail already on media (e.g. from a foreign writer
    /// or a pre-crash partial flush).
    pub fn appendDurable(self: *SimStorage, path: []const u8, bytes: []const u8) !void {
        const f = self.names.get(path).?;
        try f.content.appendSlice(self.gpa, bytes);
        f.durable_len = f.content.items.len;
    }

    /// Test helper: create `path` with `bytes` as durable content and a
    /// durable name (as if it had been fully written and synced long ago).
    pub fn installFile(self: *SimStorage, path: []const u8, bytes: []const u8) !void {
        const f = try self.newFile();
        try f.content.appendSlice(self.gpa, bytes);
        f.durable_len = bytes.len;
        try putName(self.gpa, &self.names, path, f);
        try putName(self.gpa, &self.durable_names, path, f);
    }

    // ── crash machinery ─────────────────────────────────────────────────────

    /// Count a side effect; fire the scheduled crash if this is the one.
    /// Returns true when the caller must abort with `error.Crashed`
    /// (media already collapsed).
    fn inject(self: *SimStorage) bool {
        self.ops_seen += 1;
        if (self.ops_until_crash) |*n| {
            if (n.* == 0) {
                self.doCrash();
                return true;
            }
            n.* -= 1;
        }
        return false;
    }

    fn doCrash(self: *SimStorage) void {
        for (self.all_files.items) |f| {
            switch (self.crash_mode) {
                .lose_unsynced => f.content.shrinkRetainingCapacity(f.durable_len),
                .keep_unsynced => f.durable_len = f.content.items.len,
                .torn_tail => {
                    const keep = f.durable_len + (f.content.items.len - f.durable_len) / 2;
                    f.content.shrinkRetainingCapacity(keep);
                    f.durable_len = keep;
                },
            }
        }
        switch (self.crash_mode) {
            // The dying OS flushed the directory too.
            .keep_unsynced => copyNames(self.gpa, &self.durable_names, &self.names),
            // Volatile namespace changes since the last syncDir are gone.
            .lose_unsynced, .torn_tail => copyNames(self.gpa, &self.names, &self.durable_names),
        }
        self.crashed = true;
    }

    fn newFile(self: *SimStorage) !*SimFile {
        const f = try self.gpa.create(SimFile);
        errdefer self.gpa.destroy(f);
        f.* = .{};
        try self.all_files.append(self.gpa, f);
        return f;
    }

    fn freeNames(gpa: Allocator, map: *std.StringHashMapUnmanaged(*SimFile)) void {
        var it = map.iterator();
        while (it.next()) |kv| gpa.free(kv.key_ptr.*);
        map.deinit(gpa);
    }

    fn putName(gpa: Allocator, map: *std.StringHashMapUnmanaged(*SimFile), name: []const u8, f: *SimFile) !void {
        const gop = try map.getOrPut(gpa, name);
        if (!gop.found_existing) gop.key_ptr.* = try gpa.dupe(u8, name);
        gop.value_ptr.* = f;
    }

    /// dst := src (dupe keys; dst's old keys freed). OOM here would make the
    /// simulation lie, so it is a test-harness panic, not an error.
    fn copyNames(
        gpa: Allocator,
        dst: *std.StringHashMapUnmanaged(*SimFile),
        src: *const std.StringHashMapUnmanaged(*SimFile),
    ) void {
        var it = dst.iterator();
        while (it.next()) |kv| gpa.free(kv.key_ptr.*);
        dst.clearRetainingCapacity();
        var sit = src.iterator();
        while (sit.next()) |kv| {
            putName(gpa, dst, kv.key_ptr.*, kv.value_ptr.*) catch @panic("SimStorage OOM");
        }
    }

    // ── Storage vtable ──────────────────────────────────────────────────────

    const vtable = Storage.VTable{
        .open = vOpen,
        .size = vSize,
        .pread = vPread,
        .writeAll = vWriteAll,
        .sync = vSync,
        .truncate = vTruncate,
        .close = vClose,
        .rename = vRename,
        .delete = vDelete,
        .syncDir = vSyncDir,
    };

    fn cast(ctx: *anyopaque) *SimStorage {
        return @ptrCast(@alignCast(ctx));
    }

    fn vOpen(ctx: *anyopaque, path: []const u8, mode: Storage.OpenMode) Storage.Error!Storage.Handle {
        const self = cast(ctx);
        if (self.crashed) return error.Crashed;
        if (self.inject()) return error.Crashed;
        const f: *SimFile = blk: {
            if (self.names.get(path)) |existing| {
                if (mode == .create_truncate) {
                    // Model O_TRUNC as immediately effective (see module doc).
                    existing.content.clearRetainingCapacity();
                    existing.durable_len = 0;
                }
                break :blk existing;
            }
            const f = self.newFile() catch return error.OutOfMemory;
            // A newly created name is volatile until syncDir.
            putName(self.gpa, &self.names, path, f) catch return error.OutOfMemory;
            break :blk f;
        };
        // Reuse a free slot or append.
        for (self.handles.items, 0..) |slot, i| {
            if (slot == null) {
                self.handles.items[i] = f;
                return @intCast(i);
            }
        }
        self.handles.append(self.gpa, f) catch return error.OutOfMemory;
        return @intCast(self.handles.items.len - 1);
    }

    fn fileOf(self: *SimStorage, h: Storage.Handle) *SimFile {
        return self.handles.items[h].?;
    }

    fn vSize(ctx: *anyopaque, h: Storage.Handle) Storage.Error!u64 {
        const self = cast(ctx);
        if (self.crashed) return error.Crashed;
        return self.fileOf(h).content.items.len;
    }

    fn vPread(ctx: *anyopaque, h: Storage.Handle, buf: []u8, off: u64) Storage.Error!usize {
        const self = cast(ctx);
        if (self.crashed) return error.Crashed;
        const c = self.fileOf(h).content.items;
        if (off >= c.len) return 0;
        const start: usize = @intCast(off);
        const n = @min(buf.len, c.len - start);
        @memcpy(buf[0..n], c[start .. start + n]);
        return n;
    }

    fn vWriteAll(ctx: *anyopaque, h: Storage.Handle, bytes: []const u8, off: u64) Storage.Error!void {
        const self = cast(ctx);
        if (self.crashed) return error.Crashed;
        const f = self.fileOf(h);
        // The store never overwrites already-durable bytes (append-only +
        // truncate-first discipline) — a violation is a store bug.
        std.debug.assert(off >= f.durable_len or self.crash_mode == .keep_unsynced);
        self.ops_seen += 1;
        if (self.ops_until_crash) |*n| {
            if (n.* == 0) {
                // The crash lands on this very write: apply the part of it
                // that reached the page cache before dying.
                const applied: usize = switch (self.crash_mode) {
                    .lose_unsynced => 0,
                    .keep_unsynced => bytes.len,
                    .torn_tail => (bytes.len + 1) / 2,
                };
                self.writeBytes(f, bytes[0..applied], off) catch return error.OutOfMemory;
                self.doCrash();
                return error.Crashed;
            }
            n.* -= 1;
        }
        self.writeBytes(f, bytes, off) catch return error.OutOfMemory;
    }

    fn writeBytes(self: *SimStorage, f: *SimFile, bytes: []const u8, off: u64) !void {
        const end: usize = @intCast(off + bytes.len);
        if (end > f.content.items.len) {
            const old = f.content.items.len;
            try f.content.resize(self.gpa, end);
            @memset(f.content.items[old..end], 0);
        }
        @memcpy(f.content.items[@intCast(off)..end], bytes);
    }

    fn vSync(ctx: *anyopaque, h: Storage.Handle) Storage.Error!void {
        const self = cast(ctx);
        if (self.crashed) return error.Crashed;
        if (self.inject()) return error.Crashed; // crash BEFORE durability advances
        const f = self.fileOf(h);
        f.durable_len = f.content.items.len;
    }

    fn vTruncate(ctx: *anyopaque, h: Storage.Handle, len: u64) Storage.Error!void {
        const self = cast(ctx);
        if (self.crashed) return error.Crashed;
        if (self.inject()) return error.Crashed;
        const f = self.fileOf(h);
        std.debug.assert(len <= f.content.items.len);
        f.content.shrinkRetainingCapacity(@intCast(len));
        f.durable_len = @min(f.durable_len, f.content.items.len);
    }

    fn vClose(ctx: *anyopaque, h: Storage.Handle) void {
        const self = cast(ctx);
        if (h < self.handles.items.len) self.handles.items[h] = null;
    }

    fn vRename(ctx: *anyopaque, old_path: []const u8, new_path: []const u8) Storage.Error!void {
        const self = cast(ctx);
        if (self.crashed) return error.Crashed;
        if (self.inject()) return error.Crashed;
        const kv = self.names.fetchRemove(old_path) orelse return error.FileNotFound;
        self.gpa.free(kv.key);
        putName(self.gpa, &self.names, new_path, kv.value) catch return error.OutOfMemory;
    }

    fn vDelete(ctx: *anyopaque, path: []const u8) Storage.Error!void {
        const self = cast(ctx);
        if (self.crashed) return error.Crashed;
        if (self.inject()) return error.Crashed;
        const kv = self.names.fetchRemove(path) orelse return error.FileNotFound;
        self.gpa.free(kv.key);
        // The SimFile stays in all_files (open handles stay usable), and in
        // durable_names until syncDir — a crash resurrects the name.
    }

    fn vSyncDir(ctx: *anyopaque) Storage.Error!void {
        const self = cast(ctx);
        if (self.crashed) return error.Crashed;
        if (self.inject()) return error.Crashed;
        copyNames(self.gpa, &self.durable_names, &self.names);
    }
};

// ── tests ────────────────────────────────────────────────────────────────────

const testing = std.testing;

test "sim: write is volatile until sync; crash loses unsynced tail" {
    var sim = SimStorage.init(testing.allocator);
    defer sim.deinit();
    const st = sim.storage();

    const h = try st.open("f", .open_or_create);
    try st.writeAll(h, "durable", 0);
    try st.sync(h);
    try st.syncDir();
    try st.writeAll(h, "-volatile", 7);
    try testing.expectEqual(@as(u64, 16), try st.size(h));

    sim.ops_until_crash = 0;
    try testing.expectError(error.Crashed, st.sync(h)); // crash before durability advances
    try testing.expectError(error.Crashed, st.writeAll(h, "x", 0)); // machine is dead
    sim.reboot();

    const h2 = try st.open("f", .open_or_create);
    try testing.expectEqual(@as(u64, 7), try st.size(h2));
    var buf: [7]u8 = undefined;
    try testing.expectEqual(@as(usize, 7), try st.pread(h2, &buf, 0));
    try testing.expectEqualStrings("durable", &buf);
}

test "sim: keep_unsynced crash keeps everything written" {
    var sim = SimStorage.init(testing.allocator);
    defer sim.deinit();
    sim.crash_mode = .keep_unsynced;
    const st = sim.storage();

    const h = try st.open("f", .open_or_create);
    try st.writeAll(h, "abc", 0);
    sim.ops_until_crash = 0;
    try testing.expectError(error.Crashed, st.sync(h));
    sim.reboot();

    const h2 = try st.open("f", .open_or_create);
    try testing.expectEqual(@as(u64, 3), try st.size(h2));
}

test "sim: torn_tail crash tears the in-flight write in half" {
    var sim = SimStorage.init(testing.allocator);
    defer sim.deinit();
    sim.crash_mode = .torn_tail;
    const st = sim.storage();

    const h = try st.open("f", .open_or_create);
    try st.writeAll(h, "base", 0);
    try st.sync(h);
    try st.syncDir();
    sim.ops_until_crash = 0;
    try testing.expectError(error.Crashed, st.writeAll(h, "12345678", 4));
    sim.reboot();

    const h2 = try st.open("f", .open_or_create);
    // Half of the in-flight write reached the cache (4+4=8), then the
    // global crash tears the un-synced tail in half again → 4 + 2 = 6.
    try testing.expectEqual(@as(u64, 6), try st.size(h2));
}

test "sim: rename + delete are volatile until syncDir" {
    var sim = SimStorage.init(testing.allocator);
    defer sim.deinit();
    const st = sim.storage();

    try sim.installFile("a", "A");
    try sim.installFile("b", "B");
    try st.rename("a", "c");
    try st.delete("b");
    // Crash before syncDir → both namespace changes roll back.
    sim.ops_until_crash = 0;
    try testing.expectError(error.Crashed, st.syncDir());
    sim.reboot();
    try testing.expect(sim.fileContent("a") != null);
    try testing.expect(sim.fileContent("b") != null);
    try testing.expect(sim.fileContent("c") == null);

    // Now do it again with the syncDir completing → changes stick.
    try st.rename("a", "c");
    try st.delete("b");
    try st.syncDir();
    const hc = try st.open("c", .open_or_create);
    sim.ops_until_crash = 0;
    try testing.expectError(error.Crashed, st.sync(hc));
    sim.reboot();
    try testing.expect(sim.fileContent("a") == null);
    try testing.expect(sim.fileContent("b") == null);
    try testing.expect(sim.fileContent("c") != null);
}

test "sim: created file name vanishes on crash without syncDir" {
    var sim = SimStorage.init(testing.allocator);
    defer sim.deinit();
    const st = sim.storage();

    const h = try st.open("new", .open_or_create);
    try st.writeAll(h, "data", 0);
    try st.sync(h); // content durable, but the NAME is not
    sim.ops_until_crash = 0;
    try testing.expectError(error.Crashed, st.sync(h));
    sim.reboot();
    try testing.expect(sim.fileContent("new") == null);
}

test "sim: injection counting is deterministic" {
    var counts: [2]usize = undefined;
    for (&counts) |*c| {
        var sim = SimStorage.init(testing.allocator);
        defer sim.deinit();
        const st = sim.storage();
        const h = try st.open("f", .open_or_create);
        try st.writeAll(h, "x", 0);
        try st.sync(h);
        try st.syncDir();
        c.* = sim.ops_seen;
    }
    try testing.expectEqual(counts[0], counts[1]);
}
