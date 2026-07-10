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
//!       - `.reorder_unsynced` — models **non-contiguous durability**: within
//!         a fsync-free multi-write window, real write-caching storage can
//!         persist a LATER write while losing an EARLIER one (no ordering
//!         barrier between them). Every `writeAll` since the last durability
//!         barrier is tracked as a byte-range; on crash a seed-driven SUBSET
//!         of those ranges survives, so dropping an earlier range while
//!         keeping a later one leaves a zero-filled *hole* between persisted
//!         regions. This is the only mode that can produce a non-prefix
//!         surviving state; it targets `compact()`'s write-loop-then-single-
//!         `sync` temp-file window (root.zig). Deterministic: the subset is a
//!         function of `reorder_seed` (splitmix64), never a clock/OS-rng.
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
    /// A seed-driven SUBSET of the un-synced write-ranges survives — a later
    /// write may persist while an earlier one is lost, leaving a zero-filled
    /// hole between persisted regions (non-contiguous / out-of-order
    /// durability). Driven by `reorder_seed`.
    reorder_unsynced,
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
    /// `.reorder_unsynced` only: seeds the deterministic keep/drop choice
    /// over each file's un-synced write-ranges (splitmix64, no OS-rng).
    reorder_seed: u64 = 0,
    /// `.reorder_unsynced` only: count of crashes that produced a genuine
    /// non-contiguous hole (an earlier un-synced range dropped while a later
    /// one survived). The teeth witness for the new mode — a sweep that never
    /// punches a hole has not exercised out-of-order durability.
    holes_punched: usize = 0,

    /// A byte-range written to a file since its last durability barrier.
    const Range = struct { off: usize, len: usize };

    const SimFile = struct {
        content: std.ArrayListUnmanaged(u8) = .empty,
        durable_len: usize = 0,
        /// Byte-ranges written (in issue order) since the last `sync` /
        /// `truncate` / `create_truncate` on this file. Consumed by
        /// `.reorder_unsynced` to drop a subset; cleared by every barrier.
        unsynced_writes: std.ArrayListUnmanaged(Range) = .empty,
    };

    /// splitmix64 step (public-domain, S. Vigna) — the harness's only PRNG.
    fn splitmix(state: *u64) u64 {
        state.* +%= 0x9e3779b97f4a7c15;
        var z = state.*;
        z = (z ^ (z >> 30)) *% 0xbf58476d1ce4e5b9;
        z = (z ^ (z >> 27)) *% 0x94d049bb133111eb;
        return z ^ (z >> 31);
    }

    pub fn init(gpa: Allocator) SimStorage {
        return .{ .gpa = gpa };
    }

    pub fn deinit(self: *SimStorage) void {
        freeNames(self.gpa, &self.names);
        freeNames(self.gpa, &self.durable_names);
        for (self.all_files.items) |f| {
            f.content.deinit(self.gpa);
            f.unsynced_writes.deinit(self.gpa);
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
        f.unsynced_writes.clearRetainingCapacity(); // all content is now durable
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
                .reorder_unsynced => self.crashReorder(f),
            }
            // The surviving content is now what is on media; the un-synced
            // window is consumed. (Post-crash the machine is dead until
            // `reboot`, after which a fresh `open` reads only `content`.)
            f.durable_len = f.content.items.len;
            f.unsynced_writes.clearRetainingCapacity();
        }
        switch (self.crash_mode) {
            // The dying OS flushed the directory too.
            .keep_unsynced => copyNames(self.gpa, &self.durable_names, &self.names),
            // Volatile namespace changes since the last syncDir are gone.
            .lose_unsynced, .torn_tail, .reorder_unsynced => copyNames(self.gpa, &self.names, &self.durable_names),
        }
        self.crashed = true;
    }

    /// `.reorder_unsynced` collapse for one file: keep the fsync'd durable
    /// prefix plus a seed-chosen SUBSET of the un-synced write-ranges. A
    /// dropped range that sits below a kept later range becomes a zero-filled
    /// hole — the non-contiguous / out-of-order durability the other modes
    /// (which only ever keep a contiguous prefix) cannot express.
    fn crashReorder(self: *SimStorage, f: *SimFile) void {
        const ranges = f.unsynced_writes.items;
        if (ranges.len == 0) {
            // No un-synced window (or a single-write window that got dropped):
            // nothing beyond the durable prefix survives — same as `.lose`.
            f.content.shrinkRetainingCapacity(f.durable_len);
            return;
        }
        // Pass 1: the surviving length = durable prefix ∪ (ends of kept ranges).
        // Two passes over the same seed reproduce the identical keep/drop
        // decisions without allocating a bitmap.
        var s1 = self.reorder_seed;
        var new_len: usize = f.durable_len;
        for (ranges) |r| {
            if (splitmix(&s1) & 1 == 0) new_len = @max(new_len, r.off + r.len);
        }
        // Pass 2: zero every dropped range that lies below `new_len` — the
        // holes — and detect whether a genuine hole was produced.
        var s2 = self.reorder_seed;
        var punched = false;
        for (ranges) |r| {
            const keep = splitmix(&s2) & 1 == 0;
            if (!keep and r.off < new_len) {
                const end = @min(r.off + r.len, new_len);
                @memset(f.content.items[r.off..end], 0);
                punched = true;
            }
        }
        f.content.shrinkRetainingCapacity(new_len);
        if (punched) self.holes_punched += 1;
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
                    existing.unsynced_writes.clearRetainingCapacity();
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
                    // The in-flight write fully reached the page cache; whether
                    // it survives is then decided by the reorder subset (it is
                    // just the last range in the un-synced window).
                    .reorder_unsynced => bytes.len,
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
        if (bytes.len == 0) return;
        const end: usize = @intCast(off + bytes.len);
        if (end > f.content.items.len) {
            const old = f.content.items.len;
            try f.content.resize(self.gpa, end);
            @memset(f.content.items[old..end], 0);
        }
        @memcpy(f.content.items[@intCast(off)..end], bytes);
        // Track the write as un-synced (for `.reorder_unsynced`). The store is
        // append-only over the durable prefix, so these ranges never overlap.
        try f.unsynced_writes.append(self.gpa, .{ .off = @intCast(off), .len = bytes.len });
    }

    fn vSync(ctx: *anyopaque, h: Storage.Handle) Storage.Error!void {
        const self = cast(ctx);
        if (self.crashed) return error.Crashed;
        if (self.inject()) return error.Crashed; // crash BEFORE durability advances
        const f = self.fileOf(h);
        f.durable_len = f.content.items.len;
        f.unsynced_writes.clearRetainingCapacity(); // barrier: all writes durable
    }

    fn vTruncate(ctx: *anyopaque, h: Storage.Handle, len: u64) Storage.Error!void {
        const self = cast(ctx);
        if (self.crashed) return error.Crashed;
        if (self.inject()) return error.Crashed;
        const f = self.fileOf(h);
        std.debug.assert(len <= f.content.items.len);
        f.content.shrinkRetainingCapacity(@intCast(len));
        f.durable_len = @min(f.durable_len, f.content.items.len);
        dropUnsyncedAbove(f, @intCast(len)); // ranges past the cut are gone
    }

    /// Drop/clamp un-synced ranges lying at or beyond `len` (order-preserving).
    fn dropUnsyncedAbove(f: *SimFile, len: usize) void {
        var w: usize = 0;
        for (f.unsynced_writes.items) |r| {
            if (r.off >= len) continue; // fully truncated away
            var rr = r;
            if (rr.off + rr.len > len) rr.len = len - rr.off; // clamp straddler
            f.unsynced_writes.items[w] = rr;
            w += 1;
        }
        f.unsynced_writes.shrinkRetainingCapacity(w);
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

test "sim: reorder_unsynced can drop an earlier write while keeping a later one (a hole)" {
    // Find a seed whose keep/drop choice keeps the LAST of three un-synced
    // writes but drops an earlier one — the defining non-contiguous case.
    var seed: u64 = 0;
    const hole_seed: u64 = while (seed < 64) : (seed += 1) {
        var sim = SimStorage.init(testing.allocator);
        defer sim.deinit();
        sim.crash_mode = .reorder_unsynced;
        sim.reorder_seed = seed;
        const st = sim.storage();
        const h = try st.open("f", .open_or_create);
        try st.writeAll(h, "AAAA", 0); // durable base
        try st.sync(h);
        try st.syncDir();
        // Three un-synced writes, no sync between them (a compact-like window).
        try st.writeAll(h, "1111", 4);
        try st.writeAll(h, "2222", 8);
        try st.writeAll(h, "3333", 12);
        sim.ops_until_crash = 0;
        try testing.expectError(error.Crashed, st.sync(h));
        if (sim.holes_punched == 1) break seed; // a genuine hole was punched
    } else {
        return error.NoHoleSeedFound;
    };

    // Re-run that seed and assert the exact surviving shape: the durable base
    // survives, at least one middle range is a zero hole, and the file extends
    // past the hole to a kept later range (length > 8).
    var sim = SimStorage.init(testing.allocator);
    defer sim.deinit();
    sim.crash_mode = .reorder_unsynced;
    sim.reorder_seed = hole_seed;
    const st = sim.storage();
    const h = try st.open("f", .open_or_create);
    try st.writeAll(h, "AAAA", 0);
    try st.sync(h);
    try st.syncDir();
    try st.writeAll(h, "1111", 4);
    try st.writeAll(h, "2222", 8);
    try st.writeAll(h, "3333", 12);
    sim.ops_until_crash = 0;
    try testing.expectError(error.Crashed, st.sync(h));
    sim.reboot();

    const h2 = try st.open("f", .open_or_create);
    const size = try st.size(h2);
    try testing.expect(size > 8); // extends past a dropped middle → a hole
    var buf: [16]u8 = undefined;
    _ = try st.pread(h2, buf[0..@intCast(size)], 0);
    try testing.expectEqualStrings("AAAA", buf[0..4]); // durable prefix intact
    // At least one 4-byte window in [4, size) is all-zero (the hole).
    var found_hole = false;
    var off: usize = 4;
    while (off + 4 <= size) : (off += 4) {
        if (std.mem.allEqual(u8, buf[off .. off + 4], 0)) found_hole = true;
    }
    try testing.expect(found_hole);
}

test "sim: reorder_unsynced is deterministic for a fixed seed" {
    var sizes: [2]u64 = undefined;
    for (&sizes) |*sz| {
        var sim = SimStorage.init(testing.allocator);
        defer sim.deinit();
        sim.crash_mode = .reorder_unsynced;
        sim.reorder_seed = 0xabcd_1234;
        const st = sim.storage();
        const h = try st.open("f", .open_or_create);
        try st.writeAll(h, "base", 0);
        try st.sync(h);
        try st.writeAll(h, "aaaa", 4);
        try st.writeAll(h, "bbbb", 8);
        try st.writeAll(h, "cccc", 12);
        sim.ops_until_crash = 0;
        try testing.expectError(error.Crashed, st.sync(h));
        sim.reboot();
        const h2 = try st.open("f", .open_or_create);
        sz.* = try st.size(h2);
    }
    try testing.expectEqual(sizes[0], sizes[1]);
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
