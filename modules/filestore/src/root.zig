// SPDX-License-Identifier: MIT
//! filestore — DB-less durable keyed document store: kind/key files with
//! atomic temp-then-rename writes + typed-JSON convenience. std-only.
//!
//! Layout: `<base>/<kind>/<key>` — one flat file per record, grouped under a
//! per-kind directory. `putBytes`/`getBytes`/`delete`/`list` are opaque bytes;
//! `put`/`get`/`listTyped` (typed JSON) round-trip through the very same files
//! — JSON encode/decode is the only difference, not a separate layout.
//!
//! **Crash safety.** Every write lands in a hidden `.part` temp (named with a
//! process-local ingest counter, so concurrent writers *within one process*
//! never collide on the same temp path) and is made visible by a single
//! `rename(2)` — atomic on POSIX. A crash mid-write leaves only an orphaned
//! temp (never listed, never read); a live record is never torn or partial.
//!
//! **Path safety.** `kind` and `key` are each validated by `segmentSafe`
//! (`[A-Za-z0-9._-]`, no leading dot, no `.`/`..`, no `/`), checked on every
//! public entry point, so a request can never escape `base`.
//!
//! Provenance: original work of the zig-libs authors (MIT). A `kind/id.json`
//! layout with a read/list/delete shape, atomic temp-then-rename writes,
//! `segmentSafe` path validation (no traversal escape), a
//! raw-bytes-vs-typed-JSON split, and a `listTyped` skipped-count report
//! (unparseable files are tolerantly skipped but *counted*, never silently
//! dropped).

const std = @import("std");

pub const meta = .{
    .platform = .posix, // atomic rename-on-commit; std.Io filesystem API
    .role = .util,
    .concurrency = .reentrant, // no shared state bar a process-local ingest counter
    .model_after = "content-addressed / flat-file document store",
    .deps = .{},
};

pub const Error = error{
    /// A `kind`/`key` argument is not a safe single path segment (`segmentSafe`).
    InvalidName,
};

/// Process-local monotonically increasing counter for collision-free ingest
/// temp names within a process (mirrors the sibling `blobstore` module).
/// Cross-process uniqueness is out of scope — see the README backlog.
var ingest_counter: std.atomic.Value(u64) = .init(0);

pub const Store = struct {
    io: std.Io,
    base: []const u8,

    /// Ensure `base` exists.
    pub fn init(io: std.Io, base: []const u8) !Store {
        try ensureDir(io, base);
        return .{ .io = io, .base = base };
    }

    fn kindDir(self: Store, buf: []u8, kind: []const u8) ![]const u8 {
        return std.fmt.bufPrint(buf, "{s}/{s}", .{ self.base, kind });
    }

    /// `<base>/<kind>/<key>` written into `buf`. Validates both segments.
    fn recordPath(self: Store, buf: []u8, kind: []const u8, key: []const u8) ![]const u8 {
        if (!segmentSafe(kind) or !segmentSafe(key)) return error.InvalidName;
        return std.fmt.bufPrint(buf, "{s}/{s}/{s}", .{ self.base, kind, key });
    }

    // ── raw bytes layer (atomic, opaque) ────────────────────────────────────

    /// Write (overwrite) `bytes` as `<base>/<kind>/<key>`, atomically (temp +
    /// rename). Crash-safe: a partial write never becomes a live record.
    pub fn putBytes(self: Store, kind: []const u8, key: []const u8, bytes: []const u8) !void {
        if (!segmentSafe(kind) or !segmentSafe(key)) return error.InvalidName;
        var dbuf: [640]u8 = undefined;
        const dir = try self.kindDir(&dbuf, kind);
        try ensureDir(self.io, dir);

        var uniq_buf: [24]u8 = undefined;
        const uniq = nextUniq(&uniq_buf);
        var tbuf: [768]u8 = undefined;
        const tmp = try std.fmt.bufPrint(&tbuf, "{s}/.{s}-{s}.part", .{ dir, key, uniq });
        const cwd = std.Io.Dir.cwd();
        try cwd.writeFile(self.io, .{ .sub_path = tmp, .data = bytes });

        var pbuf: [768]u8 = undefined;
        const path = try std.fmt.bufPrint(&pbuf, "{s}/{s}", .{ dir, key });
        cwd.rename(tmp, cwd, path, self.io) catch |e| {
            cwd.deleteFile(self.io, tmp) catch {};
            return e;
        };
    }

    /// Read `<base>/<kind>/<key>` (allocated in `arena`), or null if absent.
    pub fn getBytes(self: Store, arena: std.mem.Allocator, kind: []const u8, key: []const u8) !?[]u8 {
        var pbuf: [768]u8 = undefined;
        const path = try self.recordPath(&pbuf, kind, key);
        return std.Io.Dir.cwd().readFileAlloc(self.io, path, arena, .limited(64 * 1024 * 1024)) catch |e| switch (e) {
            error.FileNotFound => return null,
            else => return e,
        };
    }

    /// Delete `<base>/<kind>/<key>`. Returns false if it did not exist.
    pub fn delete(self: Store, kind: []const u8, key: []const u8) !bool {
        var pbuf: [768]u8 = undefined;
        const path = try self.recordPath(&pbuf, kind, key);
        std.Io.Dir.cwd().deleteFile(self.io, path) catch |e| switch (e) {
            error.FileNotFound => return false,
            else => return e,
        };
        return true;
    }

    /// List a kind's record keys. Missing kind dir ⇒ empty. Hidden files (our
    /// `.<key>-<n>.part` ingest temps) are skipped. Allocations in `arena`.
    pub fn list(self: Store, arena: std.mem.Allocator, kind: []const u8) ![][]const u8 {
        if (!segmentSafe(kind)) return error.InvalidName;
        var keys: std.ArrayList([]const u8) = .empty;
        var dbuf: [640]u8 = undefined;
        const dir_path = try self.kindDir(&dbuf, kind);
        var dir = std.Io.Dir.cwd().openDir(self.io, dir_path, .{ .iterate = true }) catch |e| switch (e) {
            error.FileNotFound => return keys.toOwnedSlice(arena),
            else => return e,
        };
        defer dir.close(self.io);

        var it = dir.iterate();
        while (try it.next(self.io)) |entry| {
            if (entry.kind != .file) continue;
            if (entry.name.len > 0 and entry.name[0] == '.') continue; // ingest temp
            try keys.append(arena, try arena.dupe(u8, entry.name));
        }
        return keys.toOwnedSlice(arena);
    }

    // ── typed JSON convenience (same files, JSON-encoded) ───────────────────

    /// Serialize `value` as JSON and write it as `<base>/<kind>/<key>` (via
    /// `putBytes` — same atomicity guarantee, no separate layout).
    pub fn put(self: Store, gpa: std.mem.Allocator, comptime T: type, kind: []const u8, key: []const u8, value: T) !void {
        const json = try std.json.Stringify.valueAlloc(gpa, value, .{});
        defer gpa.free(json);
        try self.putBytes(kind, key, json);
    }

    /// Read `<base>/<kind>/<key>` and parse it as `T`, or null if absent.
    /// Allocations (including `T`'s, e.g. any strings/slices it holds) live in
    /// `arena`.
    pub fn get(self: Store, comptime T: type, arena: std.mem.Allocator, kind: []const u8, key: []const u8) !?T {
        const bytes = try self.getBytes(arena, kind, key) orelse return null;
        return try std.json.parseFromSliceLeaky(T, arena, bytes, .{});
    }

    /// Parse every `<base>/<kind>/*` file as `T`. A missing kind dir ⇒ empty
    /// result, not an error. Unparseable files are tolerantly skipped — but
    /// *counted* (`skipped`), never silently discarded via a bare
    /// `catch continue`. Allocations in `arena`.
    pub fn listTyped(self: Store, comptime T: type, arena: std.mem.Allocator, kind: []const u8) !struct { items: []T, skipped: usize } {
        const keys = try self.list(arena, kind);
        var items: std.ArrayList(T) = .empty;
        var skipped: usize = 0;
        for (keys) |key| {
            // A key could vanish between `list` and here (concurrent delete);
            // treat that the same as "not present in this snapshot".
            const bytes = (try self.getBytes(arena, kind, key)) orelse continue;
            const value = std.json.parseFromSliceLeaky(T, arena, bytes, .{}) catch {
                skipped += 1;
                continue;
            };
            try items.append(arena, value);
        }
        return .{ .items = try items.toOwnedSlice(arena), .skipped = skipped };
    }
};

/// A path segment is safe if it is non-empty, ≤128 chars, not `.`/`..`, has no
/// leading dot (reserves the `.part` temp convention), and contains only
/// `[A-Za-z0-9._-]` (so it cannot contain `/` or traverse the store).
pub fn segmentSafe(s: []const u8) bool {
    if (s.len == 0 or s.len > 128) return false;
    if (s[0] == '.') return false;
    for (s) |c| {
        const ok = std.ascii.isAlphanumeric(c) or c == '-' or c == '_' or c == '.';
        if (!ok) return false;
    }
    return true;
}

fn ensureDir(io: std.Io, path: []const u8) !void {
    std.Io.Dir.cwd().createDir(io, path, .default_dir) catch |e| switch (e) {
        error.PathAlreadyExists => {},
        else => return e,
    };
}

fn nextUniq(buf: []u8) []const u8 {
    const n = ingest_counter.fetchAdd(1, .monotonic);
    return std.fmt.bufPrint(buf, "{d}", .{n}) catch unreachable; // u64 fits in 24
}

// ── tests ──────────────────────────────────────────────────────────────────────

const t = std.testing;

/// Open a fresh store rooted in a throwaway tmpdir. Returns the store; caller
/// keeps `tmp` alive and cleans it up.
fn testStore(tmp: *std.testing.TmpDir, base_buf: []u8) !Store {
    const io = std.testing.io;
    const base = try std.fmt.bufPrint(base_buf, ".zig-cache/tmp/{s}/store", .{&tmp.sub_path});
    return Store.init(io, base);
}

test "segmentSafe accepts kind/key names, rejects traversal" {
    try t.expect(segmentSafe("devices"));
    try t.expect(segmentSafe("2026-06-28.snap"));
    try t.expect(segmentSafe("dev_SN-001"));
    try t.expect(!segmentSafe(""));
    try t.expect(!segmentSafe(".."));
    try t.expect(!segmentSafe("."));
    try t.expect(!segmentSafe(".hidden"));
    try t.expect(!segmentSafe("a/b"));
    try t.expect(!segmentSafe("a b"));
    try t.expect(!segmentSafe("../etc/passwd"));
}

test "segmentSafe rejects traversal on every public entry point" {
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    var base_buf: [256]u8 = undefined;
    const store = try testStore(&tmp, &base_buf);
    const gpa = std.testing.allocator;

    try t.expectError(error.InvalidName, store.putBytes("..", "k", "x"));
    try t.expectError(error.InvalidName, store.putBytes("k", "../../etc/passwd", "x"));
    try t.expectError(error.InvalidName, store.getBytes(gpa, "..", "k"));
    try t.expectError(error.InvalidName, store.delete("k", "a/b"));
    try t.expectError(error.InvalidName, store.list(gpa, "."));
}

test "putBytes/getBytes/list/delete round-trip" {
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    var base_buf: [256]u8 = undefined;
    const store = try testStore(&tmp, &base_buf);
    const gpa = std.testing.allocator;

    // absent ⇒ null, not error
    try t.expect((try store.getBytes(gpa, "devices", "dev-1")) == null);

    try store.putBytes("devices", "dev-1", "hello device");
    try store.putBytes("devices", "dev-2", "hello device 2");
    try store.putBytes("hosts", "host-1", "unrelated kind");

    const got = (try store.getBytes(gpa, "devices", "dev-1")).?;
    defer gpa.free(got);
    try t.expectEqualStrings("hello device", got);

    // overwrite semantics
    try store.putBytes("devices", "dev-1", "rewritten");
    const got2 = (try store.getBytes(gpa, "devices", "dev-1")).?;
    defer gpa.free(got2);
    try t.expectEqualStrings("rewritten", got2);

    // list is scoped per kind and hides nothing but temps
    const keys = try store.list(gpa, "devices");
    defer {
        for (keys) |k| gpa.free(k);
        gpa.free(keys);
    }
    try t.expectEqual(@as(usize, 2), keys.len);

    // missing kind ⇒ empty, not error
    const none = try store.list(gpa, "nope");
    defer gpa.free(none);
    try t.expectEqual(@as(usize, 0), none.len);

    try t.expect(try store.delete("devices", "dev-1"));
    try t.expect(!try store.delete("devices", "dev-1")); // already gone
    try t.expect((try store.getBytes(gpa, "devices", "dev-1")) == null);
}

test "atomicity-by-construction: a stray .part temp is invisible to list/get" {
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    var base_buf: [256]u8 = undefined;
    const store = try testStore(&tmp, &base_buf);
    const io = std.testing.io;
    const gpa = std.testing.allocator;

    try store.putBytes("devices", "dev-1", "live record");

    // simulate a torn/abandoned ingest: write a hidden temp directly into the
    // kind dir, exactly like an in-flight `putBytes` that never reached rename.
    var pbuf: [768]u8 = undefined;
    const kind_dir = try std.fmt.bufPrint(&pbuf, "{s}/devices", .{store.base});
    var tbuf: [800]u8 = undefined;
    const stray = try std.fmt.bufPrint(&tbuf, "{s}/.dev-2-crashed.part", .{kind_dir});
    try std.Io.Dir.cwd().writeFile(io, .{ .sub_path = stray, .data = "half-written garbage" });

    // the stray temp's name is not even a valid key (leading dot) — rejected,
    // not silently treated as absent
    try t.expectError(error.InvalidName, store.getBytes(gpa, "devices", ".dev-2-crashed.part"));

    // and it is hidden from list
    const keys = try store.list(gpa, "devices");
    defer {
        for (keys) |k| gpa.free(k);
        gpa.free(keys);
    }
    try t.expectEqual(@as(usize, 1), keys.len);
    try t.expectEqualStrings("dev-1", keys[0]);

    // the live record is untouched
    const got = (try store.getBytes(gpa, "devices", "dev-1")).?;
    defer gpa.free(got);
    try t.expectEqualStrings("live record", got);
}

const TestRecord = struct {
    id: []const u8,
    count: u32,
};

test "typed JSON: put/get round-trip" {
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    var base_buf: [256]u8 = undefined;
    const store = try testStore(&tmp, &base_buf);
    const gpa = std.testing.allocator;
    var arena_state = std.heap.ArenaAllocator.init(gpa);
    defer arena_state.deinit();
    const arena = arena_state.allocator();

    try t.expect((try store.get(TestRecord, arena, "records", "r1")) == null);

    try store.put(gpa, TestRecord, "records", "r1", .{ .id = "r1", .count = 7 });
    const rec = (try store.get(TestRecord, arena, "records", "r1")).?;
    try t.expectEqualStrings("r1", rec.id);
    try t.expectEqual(@as(u32, 7), rec.count);

    // overwrite
    try store.put(gpa, TestRecord, "records", "r1", .{ .id = "r1", .count = 8 });
    const rec2 = (try store.get(TestRecord, arena, "records", "r1")).?;
    try t.expectEqual(@as(u32, 8), rec2.count);
}

test "listTyped: parses every record, tolerantly skips corrupt JSON, reports count" {
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    var base_buf: [256]u8 = undefined;
    const store = try testStore(&tmp, &base_buf);
    const gpa = std.testing.allocator;
    var arena_state = std.heap.ArenaAllocator.init(gpa);
    defer arena_state.deinit();
    const arena = arena_state.allocator();

    try store.put(gpa, TestRecord, "records", "r1", .{ .id = "r1", .count = 1 });
    try store.put(gpa, TestRecord, "records", "r2", .{ .id = "r2", .count = 2 });
    // corrupt: not valid JSON for TestRecord at all
    try store.putBytes("records", "r3", "{not json");
    // corrupt: valid JSON but wrong shape (missing required fields)
    try store.putBytes("records", "r4", "{\"unexpected\":true}");

    const result = try store.listTyped(TestRecord, arena, "records");
    try t.expectEqual(@as(usize, 2), result.items.len);
    try t.expectEqual(@as(usize, 2), result.skipped);

    var seen1 = false;
    var seen2 = false;
    for (result.items) |r| {
        if (std.mem.eql(u8, r.id, "r1")) seen1 = true;
        if (std.mem.eql(u8, r.id, "r2")) seen2 = true;
    }
    try t.expect(seen1);
    try t.expect(seen2);

    // missing kind ⇒ empty, zero skipped, not an error
    const none = try store.listTyped(TestRecord, arena, "nope");
    try t.expectEqual(@as(usize, 0), none.items.len);
    try t.expectEqual(@as(usize, 0), none.skipped);
}
