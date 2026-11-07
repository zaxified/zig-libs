// SPDX-License-Identifier: MIT

//! filewriter.zig -- `RotatingFile`, a size-rotated log file as a
//! `std.Io.Writer` (the role of phuslu/log's `FileWriter`; Apache and nginx
//! leave this to `rotatelogs` / `logrotate`).
//!
//! ```zig
//! var dir = try std.Io.Dir.cwd().openDir(io, "/var/log/app", .{ .iterate = true });
//! var rf = try accesslog.RotatingFile.open(dir, io, "access.log", .{ .max_size = 10 << 20, .max_backups = 7 });
//! defer rf.close();
//! var sink = accesslog.Sink.init(rf.interface(), .{ .format = .combined });
//! ```
//!
//! ## Behaviour
//!
//! * The file is opened (created if missing, never truncated) and written at
//!   its end through `writePositional`; there is no thread and no buffer of
//!   its own. `interface()` is an unbuffered `std.Io.Writer`: each `drain`
//!   call is one unit, so a `Sink` batch (whole lines) is never split by a
//!   rotation. Wrap it in your own buffered writer only if you flush at line
//!   boundaries.
//! * **Rotation on write:** before a write of `n` bytes, when the file is not
//!   empty and `size + n > max_size`, the file is renamed to
//!   `<stem>.<YYYY-MM-DDThh-mm-ss><ext>` (`access.2026-11-06T14-05-09.log`;
//!   same second again: `..._01`, `_02`, ... never overwriting a backup) and a
//!   fresh file is created with `file_permissions`. A single write larger than
//!   `max_size` goes into a fresh file whole; records are never split.
//!   `max_size == 0` never rotates. The backup timestamp is UTC shifted by
//!   `utc_offset_min` (phuslu's `LocalTime`: the caller supplies the zone, the
//!   standard library has no time zone database). The format is fixed so the
//!   pruner recognises its own backups.
//! * **Pruning:** after a successful rotation, when `max_backups > 0`, the
//!   oldest backups (by name = by time) beyond `max_backups` are deleted. Only
//!   names of the exact shape above are touched. Needs a `Dir` opened with
//!   `.iterate = true`; `max_backups == 0` (default) keeps every backup, as
//!   phuslu's `MaxBackups = 0`. A pruning failure is recorded, not raised.
//! * **A failed rotation never loses a record.** The write goes to the
//!   current file anyway (it grows past `max_size`), `write` returns success,
//!   `rotate_failures` is bumped and `last_rotate_error` set; rotation is
//!   retried on the next write. If the rename succeeded but the new file could
//!   not be created, records keep going into the renamed (backup) file until a
//!   later write manages to create the new one. Only a failing write itself is
//!   an error (`error.WriteFailed` from the `Writer`, the cause in
//!   `last_write_error`; `write` returns it directly); the `Sink` swallows it
//!   by design.
//! * No panic on any input: the name is validated (`error.InvalidName`) and
//!   every OS error is returned or recorded.
//! * Not thread-safe by itself: serialise `write` (a `Sink` does).
//!   Concurrent writers from several *processes* to one file are not
//!   coordinated.

const std = @import("std");
const datefmt = @import("datefmt");

const Dir = std.Io.Dir;
const File = std.Io.File;

pub const RotatingFile = struct {
    dir: Dir,
    io: std.Io,
    name: []const u8,
    options: Options,
    file: ?File,
    /// `dir` reopened with `.iterate = true` for pruning (when `max_backups`
    /// > 0): the caller's `Dir` may be an O_PATH handle, on which std's
    /// directory read is an `errnoBug` panic in Debug (audit H F3).
    list_dir: ?Dir = null,
    size: u64,
    /// The rename succeeded but the new file was not created yet; `file` is
    /// the renamed (backup) file.
    reopen_pending: bool = false,
    /// Rotations that failed (the record was still written).
    rotate_failures: u64 = 0,
    last_rotate_error: ?anyerror = null,
    last_prune_error: ?anyerror = null,
    last_write_error: ?anyerror = null,
    writer: std.Io.Writer,

    pub const max_name_len = 200;

    pub const Options = struct {
        /// Rotate when a write would grow the file past this. 0 = never.
        max_size: u64 = 100 * 1024 * 1024,
        /// Backups to keep; 0 = keep all.
        max_backups: u32 = 0,
        /// Permissions of every file this writer creates.
        file_permissions: File.Permissions = .default_file,
        /// Minutes east of UTC for the backup timestamp (clamped to +-23:59).
        utc_offset_min: i16 = 0,
        /// Wall clock in Unix seconds for the backup name; null = the `io`'s
        /// real-time clock. Present so tests (and callers with their own clock)
        /// control it.
        now_s: ?*const fn () i64 = null,
    };

    pub const OpenError = error{InvalidName} || File.OpenError || File.StatError || Dir.OpenError;

    /// Open `name` (a plain file name inside `dir`: no separator, 1 to
    /// `max_name_len` bytes) for appending, creating it when missing. `name`
    /// must outlive the writer; `dir` stays the caller's.
    pub fn open(dir: Dir, io: std.Io, name: []const u8, options: Options) OpenError!RotatingFile {
        if (!validName(name)) return error.InvalidName;
        const f = try dir.createFile(io, name, .{ .truncate = false, .permissions = options.file_permissions });
        errdefer f.close(io);
        const st = try f.stat(io);
        const list_dir: ?Dir = if (options.max_backups > 0) try dir.openDir(io, ".", .{ .iterate = true }) else null;
        return .{
            .dir = dir,
            .io = io,
            .name = name,
            .options = options,
            .file = f,
            .list_dir = list_dir,
            .size = st.size,
            .writer = .{ .vtable = &.{ .drain = drain }, .buffer = &.{} },
        };
    }

    fn validName(name: []const u8) bool {
        if (name.len == 0 or name.len > max_name_len) return false;
        if (std.mem.eql(u8, name, ".") or std.mem.eql(u8, name, "..")) return false;
        for (name) |c| if (c == '/' or c == '\\' or c < 0x20 or c == 0x7F or c == ':') return false;
        return true;
    }

    /// The `std.Io.Writer` to hand to a `Sink`. Valid while `self` does not move.
    pub fn interface(self: *RotatingFile) *std.Io.Writer {
        return &self.writer;
    }

    pub fn close(self: *RotatingFile) void {
        if (self.file) |f| f.close(self.io);
        self.file = null;
        if (self.list_dir) |d| d.close(self.io);
        self.list_dir = null;
    }

    /// Append `bytes` as one unit (see the module doc for rotation).
    pub fn write(self: *RotatingFile, bytes: []const u8) (File.WritePositionalError || error{Closed})!void {
        if (bytes.len == 0) return;
        if (self.file == null) return error.Closed;
        const max = self.options.max_size;
        if (max != 0 and self.size > 0 and self.size +| bytes.len > max) self.rotate();
        const f = self.file orelse return error.Closed;
        f.writePositionalAll(self.io, bytes, self.size) catch |e| {
            self.last_write_error = e;
            return e;
        };
        self.size += bytes.len;
    }

    fn drain(w: *std.Io.Writer, data: []const []const u8, splat: usize) std.Io.Writer.Error!usize {
        const self: *RotatingFile = @fieldParentPtr("writer", w);
        // Closed first: rotation would reach for the file (audit H F1).
        const f = self.file orelse {
            self.last_write_error = error.Closed;
            return error.WriteFailed;
        };
        // One unit: the rotation decision sees the whole call. Saturating:
        // a huge `splat` must not overflow (audit H F4).
        var total: u64 = 0;
        for (data[0 .. data.len - 1]) |d| total +|= d.len;
        const last = data[data.len - 1];
        total +|= std.math.mul(u64, last.len, splat) catch std.math.maxInt(u64);
        if (total == 0) return 0;
        const consumed = std.math.cast(usize, total) orelse return error.WriteFailed;
        self.beforeWrite(total);
        const out = self.file orelse f;
        var off = self.size;
        for (data[0 .. data.len - 1]) |d| {
            out.writePositionalAll(self.io, d, off) catch |e| return self.failWrite(e, off);
            off += d.len;
        }
        for (0..splat) |_| {
            out.writePositionalAll(self.io, last, off) catch |e| return self.failWrite(e, off);
            off += last.len;
        }
        self.size = off;
        return consumed;
    }

    fn failWrite(self: *RotatingFile, e: anyerror, off: u64) std.Io.Writer.Error {
        self.last_write_error = e;
        self.size = off; // bytes before the failing slice did reach the file
        return error.WriteFailed;
    }

    fn beforeWrite(self: *RotatingFile, n: u64) void {
        const max = self.options.max_size;
        if (max != 0 and self.size > 0 and self.size +| n > max) self.rotate();
    }

    /// Try to rotate; a failure is recorded and the caller writes on.
    fn rotate(self: *RotatingFile) void {
        self.rotateInner() catch |e| {
            self.rotate_failures += 1;
            self.last_rotate_error = e;
        };
    }

    fn rotateInner(self: *RotatingFile) !void {
        const old = self.file orelse return error.Closed;
        if (!self.reopen_pending) {
            var nb: [max_name_len + 40]u8 = undefined;
            const backup = try self.freshBackupName(&nb);
            self.dir.rename(self.name, self.dir, backup, self.io) catch |e| switch (e) {
                // The live file was moved or deleted under us (logrotate
                // without copytruncate): writing on would go to an unlinked
                // inode. Start a new file (audit H F5).
                error.FileNotFound => {},
                else => return e,
            };
            self.reopen_pending = true;
        }
        // Not truncating: a file another process created under the name in
        // the meantime is appended to, never emptied (audit H F6).
        const nf = try self.dir.createFile(self.io, self.name, .{ .truncate = false, .permissions = self.options.file_permissions });
        errdefer nf.close(self.io);
        const st = try nf.stat(self.io);
        old.close(self.io);
        self.file = nf;
        self.size = st.size;
        self.reopen_pending = false;
        self.last_rotate_error = null;
        if (self.options.max_backups > 0) self.prune() catch |e| {
            self.last_prune_error = e;
        };
    }

    const stamp_len = "YYYY-MM-DDThh-mm-ss".len;

    fn splitName(name: []const u8) struct { stem: []const u8, ext: []const u8 } {
        const dot = std.mem.findScalarLast(u8, name, '.');
        if (dot) |d| if (d > 0) return .{ .stem = name[0..d], .ext = name[d..] };
        return .{ .stem = name, .ext = "" };
    }

    fn nowSeconds(self: *const RotatingFile) i64 {
        if (self.options.now_s) |f| return f();
        const ns = std.Io.Timestamp.now(self.io, .real).nanoseconds;
        return @intCast(std.math.clamp(@divFloor(ns, std.time.ns_per_s), std.math.minInt(i64), std.math.maxInt(i64)));
    }

    fn freshBackupName(self: *RotatingFile, buf: []u8) ![]const u8 {
        const off: i64 = std.math.clamp(@as(i64, self.options.utc_offset_min), -1439, 1439);
        // Clamped to years 1970..9999 so the name stays 4+2+2+... digits for any clock.
        const t = std.math.clamp(self.nowSeconds() +| off * 60, 0, 253_402_300_799);
        const p = datefmt.unixToParts(t);
        const sn = splitName(self.name);
        var seq: u32 = 0;
        while (seq < 100) : (seq += 1) {
            var w: std.Io.Writer = .fixed(buf);
            w.print("{s}.{d:0>4}-{d:0>2}-{d:0>2}T{d:0>2}-{d:0>2}-{d:0>2}", .{ sn.stem, @as(u32, @intCast(@max(p.year, 0))), p.month, p.day, p.hour, p.minute, p.second }) catch return error.NameTooLong;
            if (seq > 0) w.print("_{d:0>2}", .{seq}) catch return error.NameTooLong;
            w.writeAll(sn.ext) catch return error.NameTooLong;
            const cand = w.buffered();
            if (self.dir.statFile(self.io, cand, .{ .follow_symlinks = false })) |_| {
                continue; // taken: never replace a backup
            } else |e| switch (e) {
                error.FileNotFound => return cand,
                else => return e,
            }
        }
        return error.TooManyBackups;
    }

    /// Is `entry` one of our backups: `<stem>.<stamp>[_NN]<ext>`?
    fn isBackup(self: *const RotatingFile, entry: []const u8) bool {
        const sn = splitName(self.name);
        if (!std.mem.startsWith(u8, entry, sn.stem)) return false;
        var rest = entry[sn.stem.len..];
        if (rest.len == 0 or rest[0] != '.') return false;
        rest = rest[1..];
        if (!std.mem.endsWith(u8, rest, sn.ext)) return false;
        rest = rest[0 .. rest.len - sn.ext.len];
        if (rest.len != stamp_len and rest.len != stamp_len + 3) return false;
        const shape = "dddd-dd-ddTdd-dd-dd";
        for (shape, rest[0..stamp_len]) |s, c| {
            if (s == 'd') {
                if (c < '0' or c > '9') return false;
            } else if (s != c) return false;
        }
        if (rest.len == stamp_len + 3) {
            if (rest[stamp_len] != '_') return false;
            for (rest[stamp_len + 1 ..]) |c| if (c < '0' or c > '9') return false;
        }
        // `access.log` vs a stem of `access`: the exact-name file is not a backup
        return true;
    }

    /// Delete the oldest backups beyond `max_backups` (names sort by time).
    fn prune(self: *RotatingFile) !void {
        while (true) {
            var count: u32 = 0;
            var oldest: [max_name_len + 40]u8 = undefined;
            var oldest_len: usize = 0;
            const ld = self.list_dir orelse return;
            var it = ld.iterate();
            while (try it.next(self.io)) |e| {
                // `.unknown`: file systems that do not report the kind.
                if ((e.kind != .file and e.kind != .unknown) or e.name.len > oldest.len or !self.isBackup(e.name)) continue;
                count += 1;
                if (oldest_len == 0 or std.mem.lessThan(u8, e.name, oldest[0..oldest_len])) {
                    @memcpy(oldest[0..e.name.len], e.name);
                    oldest_len = e.name.len;
                }
            }
            if (count <= self.options.max_backups or oldest_len == 0) return;
            try self.dir.deleteFile(self.io, oldest[0..oldest_len]);
        }
    }
};

// ── tests ────────────────────────────────────────────────────────────────

const testing = std.testing;

var fake_now: i64 = 0;
fn fakeNow() i64 {
    return fake_now;
}

fn readAll(dir: Dir, name: []const u8, buf: []u8) ![]const u8 {
    const f = try dir.openFile(testing.io, name, .{});
    defer f.close(testing.io);
    const n = try f.readPositionalAll(testing.io, buf, 0);
    return buf[0..n];
}

fn names(dir: Dir, out: *[16][64]u8, lens: *[16]usize) !usize {
    var n: usize = 0;
    var it = dir.iterate();
    while (try it.next(testing.io)) |e| {
        @memcpy(out[n][0..e.name.len], e.name);
        lens[n] = e.name.len;
        n += 1;
    }
    return n;
}

fn has(dir: Dir, name: []const u8) bool {
    _ = dir.statFile(testing.io, name, .{}) catch return false;
    return true;
}

test "RotatingFile: appends to an existing file, rotates at max_size, names backups by time" {
    var tmp = testing.tmpDir(.{ .iterate = true });
    defer tmp.cleanup();
    try tmp.dir.writeFile(testing.io, .{ .sub_path = "a.log", .data = "old\n" });
    fake_now = 1_793_973_909; // 2026-11-06 14:05:09 UTC
    var rf = try RotatingFile.open(tmp.dir, testing.io, "a.log", .{ .max_size = 20, .now_s = fakeNow });
    defer rf.close();
    try testing.expectEqual(@as(u64, 4), rf.size);
    try rf.write("0123456789\n"); // 15
    try rf.write("abcd\n"); // 20: fits exactly
    var buf: [128]u8 = undefined;
    try testing.expectEqualStrings("old\n0123456789\nabcd\n", try readAll(tmp.dir, "a.log", &buf));
    try testing.expect(!has(tmp.dir, "a.2026-11-06T14-05-09.log"));
    try rf.write("X\n"); // 22 > 20: rotate first
    try testing.expectEqualStrings("old\n0123456789\nabcd\n", try readAll(tmp.dir, "a.2026-11-06T14-05-09.log", &buf));
    try testing.expectEqualStrings("X\n", try readAll(tmp.dir, "a.log", &buf));
    // same second again: never overwrites the backup
    try rf.write("0123456789012345678\n"); // 2 + 20 > 20
    try testing.expectEqualStrings("X\n", try readAll(tmp.dir, "a.2026-11-06T14-05-09_01.log", &buf));
    try testing.expectEqualStrings("old\n0123456789\nabcd\n", try readAll(tmp.dir, "a.2026-11-06T14-05-09.log", &buf));
    // an oversize record goes whole into a fresh file
    try rf.write("0123456789012345678901234567890123456789\n");
    try testing.expectEqual(@as(u64, 41), rf.size);
    try testing.expectEqual(@as(u64, 0), rf.rotate_failures);
}

test "RotatingFile: max_backups prunes the oldest, only its own backups, offset in the name" {
    var tmp = testing.tmpDir(.{ .iterate = true });
    defer tmp.cleanup();
    try tmp.dir.writeFile(testing.io, .{ .sub_path = "a.log.keep", .data = "x" });
    try tmp.dir.writeFile(testing.io, .{ .sub_path = "a.2020-01-01T00-00-00.txt", .data = "x" });
    try tmp.dir.writeFile(testing.io, .{ .sub_path = "a.notatime.log", .data = "x" });
    try tmp.dir.writeFile(testing.io, .{ .sub_path = "b.2020-01-01T00-00-00.log", .data = "x" });
    var rf = try RotatingFile.open(tmp.dir, testing.io, "a.log", .{ .max_size = 4, .max_backups = 2, .utc_offset_min = 120, .now_s = fakeNow });
    defer rf.close();
    var t: i64 = 1_793_973_909;
    for (0..5) |_| {
        fake_now = t;
        try rf.write("abcd");
        t += 10;
    }
    // writes 2..5 each rotated (at :19 :29 :39 :49); the two newest remain. +02:00 shows in the name.
    try testing.expect(!has(tmp.dir, "a.2026-11-06T16-05-19.log"));
    try testing.expect(!has(tmp.dir, "a.2026-11-06T16-05-29.log"));
    try testing.expect(has(tmp.dir, "a.2026-11-06T16-05-39.log"));
    try testing.expect(has(tmp.dir, "a.2026-11-06T16-05-49.log"));
    try testing.expect(has(tmp.dir, "a.log"));
    // foreign files untouched
    try testing.expect(has(tmp.dir, "a.log.keep"));
    try testing.expect(has(tmp.dir, "a.2020-01-01T00-00-00.txt"));
    try testing.expect(has(tmp.dir, "a.notatime.log"));
    try testing.expect(has(tmp.dir, "b.2020-01-01T00-00-00.log"));
    try testing.expectEqual(@as(?anyerror, null), rf.last_prune_error);
}

test "RotatingFile: Sink batches go through the Writer interface as units" {
    var tmp = testing.tmpDir(.{ .iterate = true });
    defer tmp.cleanup();
    fake_now = 1_793_973_909;
    var rf = try RotatingFile.open(tmp.dir, testing.io, "s.log", .{ .max_size = 30, .now_s = fakeNow });
    defer rf.close();
    const w = rf.interface();
    try w.writeAll("line one 12345\n");
    try w.writeAll("line two 12345\n"); // 30 exactly
    try w.writeAll("line three\n"); // rotates
    var buf: [64]u8 = undefined;
    try testing.expectEqualStrings("line three\n", try readAll(tmp.dir, "s.log", &buf));
    try testing.expectEqualStrings("line one 12345\nline two 12345\n", try readAll(tmp.dir, "s.2026-11-06T14-05-09.log", &buf));
    try w.print("{d}\n", .{42});
    try testing.expectEqualStrings("line three\n42\n", try readAll(tmp.dir, "s.log", &buf));
}

test "RotatingFile: a taken backup name (even a directory) gets a suffix, nothing is replaced" {
    var tmp = testing.tmpDir(.{ .iterate = true });
    defer tmp.cleanup();
    fake_now = 1_793_973_909;
    var rf = try RotatingFile.open(tmp.dir, testing.io, "r.log", .{ .max_size = 4, .now_s = fakeNow });
    defer rf.close();
    try rf.write("aaaa");
    try tmp.dir.createDir(testing.io, "r.2026-11-06T14-05-09.log", .default_dir);
    try rf.write("bbbb");
    try testing.expectEqual(@as(u64, 0), rf.rotate_failures);
    var buf: [16]u8 = undefined;
    try testing.expectEqualStrings("aaaa", try readAll(tmp.dir, "r.2026-11-06T14-05-09_01.log", &buf));
    try testing.expectEqualStrings("bbbb", try readAll(tmp.dir, "r.log", &buf));
}

test "RotatingFile: exhausted backup names fail the rotation, not the record" {
    var tmp = testing.tmpDir(.{ .iterate = true });
    defer tmp.cleanup();
    fake_now = 1_793_973_909;
    var rf = try RotatingFile.open(tmp.dir, testing.io, "e.log", .{ .max_size = 4, .now_s = fakeNow });
    defer rf.close();
    try tmp.dir.writeFile(testing.io, .{ .sub_path = "e.2026-11-06T14-05-09.log", .data = "keep0" });
    for (1..100) |i| {
        var nm: [64]u8 = undefined;
        const n = try std.fmt.bufPrint(&nm, "e.2026-11-06T14-05-09_{d:0>2}.log", .{i});
        try tmp.dir.writeFile(testing.io, .{ .sub_path = n, .data = "keep" });
    }
    try rf.write("aaaa");
    try rf.write("bbbb"); // rotation impossible: written on, file grows
    try testing.expectEqual(@as(u64, 8), rf.size);
    try testing.expectEqual(@as(u64, 1), rf.rotate_failures);
    try testing.expect(rf.last_rotate_error != null);
    var buf: [16]u8 = undefined;
    try testing.expectEqualStrings("aaaabbbb", try readAll(tmp.dir, "e.log", &buf));
    try testing.expectEqualStrings("keep0", try readAll(tmp.dir, "e.2026-11-06T14-05-09.log", &buf));
    // time moves on: the next write rotates
    fake_now += 1;
    try rf.write("cccc");
    try testing.expectEqual(@as(?anyerror, null), rf.last_rotate_error);
    try testing.expectEqualStrings("cccc", try readAll(tmp.dir, "e.log", &buf));
    try testing.expectEqualStrings("aaaabbbb", try readAll(tmp.dir, "e.2026-11-06T14-05-10.log", &buf));
}

test "RotatingFile: names, max_size 0, file mode, closed writer, extreme clock" {
    var tmp = testing.tmpDir(.{ .iterate = true });
    defer tmp.cleanup();
    for ([_][]const u8{ "", ".", "..", "a/b", "a\\b", "a\nb", "c:d" }) |bad|
        try testing.expectError(error.InvalidName, RotatingFile.open(tmp.dir, testing.io, bad, .{}));
    var long: [RotatingFile.max_name_len + 1]u8 = @splat('x');
    try testing.expectError(error.InvalidName, RotatingFile.open(tmp.dir, testing.io, &long, .{}));

    var rf = try RotatingFile.open(tmp.dir, testing.io, "noext", .{ .max_size = 0, .file_permissions = .fromMode(0o600) });
    for (0..50) |_| try rf.write("0123456789");
    try testing.expectEqual(@as(u64, 500), rf.size);
    const st = try tmp.dir.statFile(testing.io, "noext", .{});
    try testing.expectEqual(@as(u32, 0), @as(u32, @intCast(st.permissions.toMode() & 0o077)));
    try rf.write(""); // no-op
    rf.close();
    try testing.expectError(error.Closed, rf.write("x"));
    try testing.expectError(error.WriteFailed, rf.interface().writeAll("x"));

    // a name without extension and a hostile clock: no trap, name still well formed
    var rf2 = try RotatingFile.open(tmp.dir, testing.io, "n", .{ .max_size = 1, .now_s = fakeNow, .utc_offset_min = 32767 });
    defer rf2.close();
    for ([_]i64{ std.math.minInt(i64), std.math.maxInt(i64), -1 }) |t| {
        fake_now = t;
        try rf2.write("ab");
        try rf2.write("cd");
    }
}

fn listCount(dir: Dir, prefix: []const u8) !usize {
    var n: usize = 0;
    var it = dir.iterate();
    while (try it.next(testing.io)) |e| {
        if (std.mem.startsWith(u8, e.name, prefix)) n += 1;
    }
    return n;
}

test "RotatingFile: names at the length limit, DEL, a first oversize record into an empty file" {
    var tmp = testing.tmpDir(.{ .iterate = true });
    defer tmp.cleanup();
    try testing.expectError(error.InvalidName, RotatingFile.open(tmp.dir, testing.io, "a\x7fb", .{}));
    // the longest accepted name still rotates: its backup name fits
    var long: [RotatingFile.max_name_len]u8 = @splat('x');
    fake_now = 1_793_973_909;
    var rf = try RotatingFile.open(tmp.dir, testing.io, &long, .{ .max_size = 4, .now_s = fakeNow });
    try rf.write("aaaa");
    try rf.write("bbbb");
    try testing.expectEqual(@as(u64, 0), rf.rotate_failures);
    try testing.expectEqual(@as(?anyerror, null), rf.last_rotate_error);
    try testing.expectEqual(@as(usize, 2), try listCount(tmp.dir, "x"));
    rf.close();
    // a record larger than max_size into an EMPTY file rotates nothing
    var rf2 = try RotatingFile.open(tmp.dir, testing.io, "e.log", .{ .max_size = 4, .now_s = fakeNow });
    defer rf2.close();
    try rf2.write("0123456789");
    try testing.expectEqual(@as(usize, 1), try listCount(tmp.dir, "e."));
    try rf2.interface().writeAll("0123456789"); // now it does
    try testing.expectEqual(@as(usize, 2), try listCount(tmp.dir, "e."));
}

test "RotatingFile: the backup name follows the clock, clamped to years 1970..9999 and the offset to +-23:59" {
    var tmp = testing.tmpDir(.{ .iterate = true });
    defer tmp.cleanup();
    const T = struct {
        fn run(dir: Dir, name: []const u8, now: i64, off: i16, want: []const u8) !void {
            fake_now = now;
            var rf = try RotatingFile.open(dir, testing.io, name, .{ .max_size = 1, .now_s = fakeNow, .utc_offset_min = off });
            defer rf.close();
            try rf.write("a");
            try rf.write("b");
            try testing.expectEqual(@as(u64, 0), rf.rotate_failures);
            try testing.expect(has(dir, want));
        }
    };
    try T.run(tmp.dir, "c1", std.math.minInt(i64), 0, "c1.1970-01-01T00-00-00");
    try T.run(tmp.dir, "c2", std.math.maxInt(i64), 0, "c2.9999-12-31T23-59-59");
    try T.run(tmp.dir, "c3", 0, 32767, "c3.1970-01-01T23-59-00");
    try T.run(tmp.dir, "c4", 0, -32768, "c4.1970-01-01T00-00-00");
    try T.run(tmp.dir, "c5", 2 * 86400, -32768, "c5.1970-01-02T00-01-00");
    try T.run(tmp.dir, "c6", 0, 90, "c6.1970-01-01T01-30-00");
    // a dotfile has no extension; several dots: the last one splits
    try T.run(tmp.dir, ".hid", 0, 0, ".hid.1970-01-01T00-00-00");
    try T.run(tmp.dir, "a.b.log", 0, 0, "a.b.1970-01-01T00-00-00.log");
}

test "RotatingFile: pruning counts _NN backups, keeps exactly max_backups, spares look-alikes and directories" {
    var tmp = testing.tmpDir(.{ .iterate = true });
    defer tmp.cleanup();
    const own = [_][]const u8{
        "p.2026-11-06T14-05-09.log",
        "p.2026-11-06T14-05-09_01.log",
        "p.2026-11-06T14-05-09_02.log",
    };
    const foreign = [_][]const u8{
        "p.2026-11-06T14-05-09_x1.log", // suffix not digits
        "p.2026-11-06T14-05-09_1.log", // suffix too short
        "p.2026-11-06T14-05-09-01.log", // separator
        "p.2026-11-06T14-05-09__01.log",
        "p.2026-11-06T14-05-0a.log",
        "p.2026-11-06 14-05-09.log",
        "p.2026-11-06T14:05:09.log",
        "px.2026-11-06T14-05-09.log",
        "p2026-11-06T14-05-09.log",
        "p.2026-11-06T14-05-09.lo",
        "p", // exactly the stem
        "p_2026-11-06T14-05-09.log", // one byte where the dot belongs
    };
    for (own) |n| try tmp.dir.writeFile(testing.io, .{ .sub_path = n, .data = "x" });
    for (foreign) |n| try tmp.dir.writeFile(testing.io, .{ .sub_path = n, .data = "x" });
    // a directory with a backup-shaped name is neither counted nor deleted
    try tmp.dir.createDir(testing.io, "p.2020-01-01T00-00-00.log", .default_dir);
    fake_now = 1_793_973_909 + 100;
    var rf = try RotatingFile.open(tmp.dir, testing.io, "p.log", .{ .max_size = 1, .max_backups = 2, .now_s = fakeNow });
    defer rf.close();
    try rf.write("a");
    try rf.write("b"); // rotates: 4 backups, keep the 2 newest
    try testing.expect(!has(tmp.dir, own[0]));
    try testing.expect(!has(tmp.dir, own[1]));
    try testing.expect(has(tmp.dir, own[2]));
    try testing.expect(has(tmp.dir, "p.2026-11-06T14-06-49.log"));
    for (foreign) |n| try testing.expect(has(tmp.dir, n));
    try testing.expect(has(tmp.dir, "p.2020-01-01T00-00-00.log"));
    try testing.expectEqual(@as(?anyerror, null), rf.last_prune_error);
    // exactly max_backups backups: nothing is deleted
    fake_now += 100;
    try rf.write("c");
    try testing.expect(!has(tmp.dir, own[2]));
    try testing.expect(has(tmp.dir, "p.2026-11-06T14-06-49.log"));
    try testing.expect(has(tmp.dir, "p.2026-11-06T14-08-29.log"));
}

test "RotatingFile: a Writer call with several slices and a splat is one unit; a dead fd is WriteFailed" {
    var tmp = testing.tmpDir(.{ .iterate = true });
    defer tmp.cleanup();
    fake_now = 1_793_973_909;
    var rf = try RotatingFile.open(tmp.dir, testing.io, "u.log", .{ .max_size = 10, .now_s = fakeNow });
    try rf.write("12345678");
    const w = rf.interface();
    const n = try w.writeSplat(&.{ "ab", "c" }, 3); // "abccc"
    try testing.expectEqual(@as(usize, 5), n);
    var buf: [16]u8 = undefined;
    try testing.expectEqualStrings("abccc", try readAll(tmp.dir, "u.log", &buf));
    try testing.expectEqualStrings("12345678", try readAll(tmp.dir, "u.2026-11-06T14-05-09.log", &buf));
    try testing.expectEqual(@as(u64, 5), rf.size);
    // the descriptor is gone: the failure is the Writer's WriteFailed, the cause is kept, the size is not advanced
    rf.file.?.close(testing.io);
    try testing.expectError(error.WriteFailed, w.writeAll("zz"));
    try testing.expect(rf.last_write_error != null);
    try testing.expectEqual(@as(u64, 5), rf.size);
    rf.last_write_error = null;
    try testing.expectError(error.NotOpenForWriting, rf.write("zz"));
    try testing.expect(rf.last_write_error != null);
    rf.file = null; // already closed above
}

test "RotatingFile: a rename that succeeds but a create that fails keeps writing to the backup, then recovers" {
    var tmp = testing.tmpDir(.{ .iterate = true });
    defer tmp.cleanup();
    fake_now = 1_793_973_909;
    var rf = try RotatingFile.open(tmp.dir, testing.io, "f.log", .{ .max_size = 4, .now_s = fakeNow });
    defer rf.close();
    try rf.write("aaaa");

    // Fill the descriptor table so createFile fails (EMFILE) after the rename.
    const posix = std.posix;
    const probe = try tmp.dir.openFile(testing.io, "f.log", .{});
    const first: i32 = probe.handle;
    probe.close(testing.io);
    const old = try posix.getrlimit(.NOFILE);
    try posix.setrlimit(.NOFILE, .{ .cur = @intCast(first + 6), .max = old.max });
    var fillers: [16]File = undefined;
    var nf: usize = 0;
    while (nf < fillers.len) : (nf += 1) {
        fillers[nf] = tmp.dir.openFile(testing.io, "f.log", .{}) catch break;
    }
    defer {
        posix.setrlimit(.NOFILE, old) catch {};
    }
    try testing.expect(nf > 0 and nf < fillers.len);

    try rf.write("bbbb"); // rename ok, create fails: the record goes on into the backup
    try testing.expectEqual(@as(u64, 1), rf.rotate_failures);
    try testing.expect(rf.reopen_pending);
    try testing.expectEqual(@as(u64, 8), rf.size);
    try rf.write("cccc"); // retried: still no descriptor, still no second rename
    try testing.expectEqual(@as(u64, 2), rf.rotate_failures);
    try testing.expectEqual(@as(u64, 12), rf.size);
    try testing.expectEqual(@as(usize, 1), try listCount(tmp.dir, "f.2026"));

    // a descriptor frees up: the next write creates the new file
    fillers[0].close(testing.io);
    try rf.write("dddd");
    try testing.expect(!rf.reopen_pending);
    try testing.expectEqual(@as(?anyerror, null), rf.last_rotate_error);
    try testing.expectEqual(@as(u64, 4), rf.size);
    for (fillers[1..nf]) |f| f.close(testing.io);
    var buf: [32]u8 = undefined;
    try testing.expectEqualStrings("aaaabbbbcccc", try readAll(tmp.dir, "f.2026-11-06T14-05-09.log", &buf));
    try testing.expectEqualStrings("dddd", try readAll(tmp.dir, "f.log", &buf));
}

fn openFds() !usize {
    var d = try Dir.openDirAbsolute(testing.io, "/proc/self/fd", .{ .iterate = true });
    defer d.close(testing.io);
    var n: usize = 0;
    var it = d.iterate();
    while (try it.next(testing.io)) |_| n += 1;
    return n;
}

test "RotatingFile: rotation closes the old descriptor; an empty drain never rotates; the real clock names backups" {
    var tmp = testing.tmpDir(.{ .iterate = true });
    defer tmp.cleanup();
    var rf = try RotatingFile.open(tmp.dir, testing.io, "r.log", .{ .max_size = 1 }); // no now_s: the io's real-time clock
    defer rf.close();
    try rf.write("a");
    const fds = try openFds();
    for (0..12) |_| try rf.write("bb");
    try testing.expectEqual(fds, try openFds());
    try testing.expectEqual(@as(u64, 0), rf.rotate_failures);
    // the real clock: some backup is named with a year in 2026..2999
    var it = tmp.dir.iterate();
    var seen = false;
    while (try it.next(testing.io)) |e| {
        if (!std.mem.startsWith(u8, e.name, "r.2")) continue;
        const year = try std.fmt.parseInt(u32, e.name[2..6], 10);
        try testing.expect(year >= 2026 and year <= 2999);
        seen = true;
    }
    try testing.expect(seen);
    // size > max_size now (oversize record), yet an empty drain must not rotate
    const before = try listCount(tmp.dir, "r.");
    try testing.expectEqual(@as(usize, 0), try RotatingFile.drain(rf.interface(), &.{""}, 1));
    try testing.expectEqual(before, try listCount(tmp.dir, "r."));
}

test "RotatingFile: the last free suffix is _99; a dangling symlink holds its name" {
    var tmp = testing.tmpDir(.{ .iterate = true });
    defer tmp.cleanup();
    fake_now = 1_793_973_909;
    var rf = try RotatingFile.open(tmp.dir, testing.io, "s.log", .{ .max_size = 4, .now_s = fakeNow });
    defer rf.close();
    try tmp.dir.symLink(testing.io, "nowhere", "s.2026-11-06T14-05-09.log", .{});
    for (1..99) |i| {
        var nm: [64]u8 = undefined;
        const n = try std.fmt.bufPrint(&nm, "s.2026-11-06T14-05-09_{d:0>2}.log", .{i});
        try tmp.dir.writeFile(testing.io, .{ .sub_path = n, .data = "keep" });
    }
    try rf.write("aaaa");
    try rf.write("bbbb");
    try testing.expectEqual(@as(u64, 0), rf.rotate_failures);
    var buf: [16]u8 = undefined;
    try testing.expectEqualStrings("aaaa", try readAll(tmp.dir, "s.2026-11-06T14-05-09_99.log", &buf));
    // the symlink is still a dangling symlink, not replaced by a backup
    var lb: [64]u8 = undefined;
    const n = try tmp.dir.readLink(testing.io, "s.2026-11-06T14-05-09.log", &lb);
    try testing.expectEqualStrings("nowhere", lb[0..n]);
}

test "RotatingFile: write after close is error.Closed even when it would rotate; an empty write never rotates" {
    var tmp = testing.tmpDir(.{ .iterate = true });
    defer tmp.cleanup();
    fake_now = 1_793_973_909;
    var rf = try RotatingFile.open(tmp.dir, testing.io, "c.log", .{ .max_size = 10, .now_s = fakeNow });
    try rf.write("0123456789012"); // oversize: size 13 > max_size
    try rf.write(""); // size > max_size, but nothing to write: no rotation
    try testing.expectEqual(@as(usize, 1), try listCount(tmp.dir, "c."));
    rf.close();
    try testing.expectError(error.Closed, rf.write("x"));
    try testing.expectError(error.Closed, rf.write("0123456789"));
}

test "RotatingFile: an oversize first record through the Writer goes whole into the empty file" {
    var tmp = testing.tmpDir(.{ .iterate = true });
    defer tmp.cleanup();
    fake_now = 1_793_973_909;
    var rf = try RotatingFile.open(tmp.dir, testing.io, "w.log", .{ .max_size = 4, .now_s = fakeNow });
    defer rf.close();
    try rf.interface().writeAll("0123456789");
    try testing.expectEqual(@as(usize, 1), try listCount(tmp.dir, "w."));
    try testing.expectEqual(@as(u64, 10), rf.size);
}

test "RotatingFile: a failing slice keeps the size of the slices that did reach the file" {
    const posix = std.posix;
    var tmp = testing.tmpDir(.{ .iterate = true });
    defer tmp.cleanup();
    var rf = try RotatingFile.open(tmp.dir, testing.io, "x.log", .{ .max_size = 0 });
    defer rf.close();
    // The file size limit makes the second slice fail with EFBIG (SIGXFSZ ignored meanwhile).
    const ign: posix.Sigaction = .{ .handler = .{ .handler = posix.SIG.IGN }, .mask = posix.sigemptyset(), .flags = 0 };
    var old_act: posix.Sigaction = undefined;
    posix.sigaction(.XFSZ, &ign, &old_act);
    defer posix.sigaction(.XFSZ, &old_act, null);
    const old = try posix.getrlimit(.FSIZE);
    try posix.setrlimit(.FSIZE, .{ .cur = 100, .max = old.max });
    defer posix.setrlimit(.FSIZE, old) catch {};
    const a: [60]u8 = @splat('a');
    const b: [60]u8 = @splat('b');
    var vec = [_][]const u8{ &a, &b };
    try testing.expectError(error.WriteFailed, rf.interface().writeVecAll(&vec));
    try testing.expect(rf.last_write_error != null);
    try testing.expectEqual(@as(u64, 60), rf.size);
}

test "RotatingFile: the Writer after close is WriteFailed, never a panic, even when it would rotate (audit H F1)" {
    var tmp = testing.tmpDir(.{ .iterate = true });
    defer tmp.cleanup();
    fake_now = 1_793_973_909;
    var rf = try RotatingFile.open(tmp.dir, testing.io, "c.log", .{ .max_size = 10, .now_s = fakeNow });
    try rf.write("12345678");
    rf.close();
    try testing.expectError(error.WriteFailed, rf.interface().writeAll("abcdef"));
    try testing.expectEqual(@as(?anyerror, error.Closed), rf.last_write_error);
}

test "RotatingFile: a Sink line is never split across files, synchronized or not (audit H F2)" {
    const root = @import("root.zig");
    const tpl = comptime root.LogFormat.comptimeParse("%m %U %s");
    for ([_]bool{ false, true }) |synchronized| {
        var tmp = testing.tmpDir(.{ .iterate = true });
        defer tmp.cleanup();
        fake_now = 1_793_973_909;
        var rf = try RotatingFile.open(tmp.dir, testing.io, "p.log", .{ .max_size = 30, .now_s = fakeNow });
        defer rf.close();
        var sink = root.Sink.init(rf.interface(), .{ .synchronized = synchronized, .template = &tpl });
        sink.log(.{ .timestamp_ns = 1, .method = "GET", .target = "/aaaaaaaa", .status = 200 }); // 18 + nl
        sink.log(.{ .timestamp_ns = 2, .method = "GET", .target = "/bbbbbbbb", .status = 200 });
        var buf: [128]u8 = undefined;
        try testing.expectEqualStrings("GET /bbbbbbbb 200\n", try readAll(tmp.dir, "p.log", &buf));
        try testing.expectEqualStrings("GET /aaaaaaaa 200\n", try readAll(tmp.dir, "p.2026-11-06T14-05-09.log", &buf));
    }
}

test "RotatingFile: pruning works on a Dir opened without .iterate (audit H F3)" {
    var tmp = testing.tmpDir(.{});
    defer tmp.cleanup();
    var rf = try RotatingFile.open(tmp.dir, testing.io, "q.log", .{ .max_size = 4, .max_backups = 1, .now_s = fakeNow });
    defer rf.close();
    var t: i64 = 1_793_973_909;
    for (0..4) |_| {
        fake_now = t;
        try rf.write("abcd");
        t += 10;
    }
    try testing.expectEqual(@as(?anyerror, null), rf.last_prune_error);
    // Rotations at :19, :29, :39; max_backups = 1 keeps only the newest.
    try testing.expect(!has(tmp.dir, "q.2026-11-06T14-05-19.log"));
    try testing.expect(!has(tmp.dir, "q.2026-11-06T14-05-29.log"));
    try testing.expect(has(tmp.dir, "q.2026-11-06T14-05-39.log"));
}

test "RotatingFile: the live file deleted under it starts a new file instead of writing to an unlinked inode (audit H F5)" {
    var tmp = testing.tmpDir(.{ .iterate = true });
    defer tmp.cleanup();
    fake_now = 1_793_973_909;
    var rf = try RotatingFile.open(tmp.dir, testing.io, "d.log", .{ .max_size = 8, .now_s = fakeNow });
    defer rf.close();
    try rf.write("1234");
    try tmp.dir.deleteFile(testing.io, "d.log");
    try rf.write("567890"); // would pass 8: rotation finds no file to rename
    try testing.expectEqual(@as(u64, 0), rf.rotate_failures);
    var buf: [64]u8 = undefined;
    try testing.expectEqualStrings("567890", try readAll(tmp.dir, "d.log", &buf));
}

// ── mutation run 2026-11-07 (whole module): tests for the survivors ──────

test "mutation 2026-11-07: a space is a legal name byte, 0x1F is not" {
    var tmp = testing.tmpDir(.{ .iterate = true });
    defer tmp.cleanup();
    var rf = try RotatingFile.open(tmp.dir, testing.io, "a b.log", .{});
    rf.close();
    try testing.expectError(error.InvalidName, RotatingFile.open(tmp.dir, testing.io, "a\x1fb", .{}));
}

test "mutation 2026-11-07: close releases both handles, and a second close touches no descriptor" {
    var tmp = testing.tmpDir(.{ .iterate = true });
    defer tmp.cleanup();
    const before = try openFds();
    var rf = try RotatingFile.open(tmp.dir, testing.io, "c.log", .{ .max_backups = 1 });
    try testing.expectEqual(before + 2, try openFds());
    rf.close();
    try testing.expectEqual(before, try openFds());
    var held: [8]File = undefined;
    for (&held) |*h| h.* = try tmp.dir.openFile(testing.io, "c.log", .{});
    rf.close(); // must not close a descriptor that has been reused since
    for (held) |h| _ = try h.stat(testing.io);
    for (held) |h| h.close(testing.io);
}

test "mutation 2026-11-07: a write on a closed file does not even try to rotate" {
    var tmp = testing.tmpDir(.{ .iterate = true });
    defer tmp.cleanup();
    fake_now = 1_793_973_909;
    var rf = try RotatingFile.open(tmp.dir, testing.io, "c.log", .{ .max_size = 10, .now_s = fakeNow });
    try rf.write("0123456789012"); // oversize: size 13 > max_size
    rf.close();
    try testing.expectError(error.Closed, rf.write("0123456789"));
    try testing.expectEqual(@as(u64, 0), rf.rotate_failures);
    try testing.expectError(error.WriteFailed, rf.interface().writeAll("0123456789"));
    try testing.expectEqual(@as(u64, 0), rf.rotate_failures);
}

test "mutation 2026-11-07: max_size 0 never rotates through the Writer; a size at the top of u64 rotates instead of wrapping" {
    var tmp = testing.tmpDir(.{ .iterate = true });
    defer tmp.cleanup();
    fake_now = 1_793_973_909;
    var rf0 = try RotatingFile.open(tmp.dir, testing.io, "z.log", .{ .max_size = 0, .now_s = fakeNow });
    defer rf0.close();
    for (0..3) |_| try rf0.interface().writeAll("0123456789");
    try testing.expectEqual(@as(usize, 1), try listCount(tmp.dir, "z."));
    try testing.expectEqual(@as(u64, 30), rf0.size);

    for ([_]bool{ false, true }) |via_writer| {
        const nm = if (via_writer) "sat1.log" else "sat0.log";
        var rf = try RotatingFile.open(tmp.dir, testing.io, nm, .{ .max_size = 4, .now_s = fakeNow });
        defer rf.close();
        try rf.write("a");
        rf.size = std.math.maxInt(u64) - 2; // 5 more bytes would wrap a plain addition to 2
        if (via_writer) try rf.interface().writeAll("abcde") else try rf.write("abcde");
        try testing.expectEqual(@as(u64, 5), rf.size);
        try testing.expectEqual(@as(u64, 0), rf.rotate_failures);
        try testing.expectEqual(@as(usize, 2), try listCount(tmp.dir, nm[0..5]));
    }
}

test "mutation 2026-11-07: a pending reopen adopts a file created meanwhile, without renaming or truncating it" {
    var tmp = testing.tmpDir(.{ .iterate = true });
    defer tmp.cleanup();
    fake_now = 1_793_973_909;
    var rf = try RotatingFile.open(tmp.dir, testing.io, "n.log", .{ .max_size = 4, .now_s = fakeNow });
    defer rf.close();
    try rf.write("aaaa");
    try tmp.dir.rename("n.log", tmp.dir, "n.moved", testing.io);
    try tmp.dir.writeFile(testing.io, .{ .sub_path = "n.log", .data = "xx" }); // another process
    rf.reopen_pending = true;
    try rf.write("bbbb");
    try testing.expectEqual(@as(u64, 0), rf.rotate_failures);
    try testing.expect(!rf.reopen_pending);
    try testing.expectEqual(@as(u64, 6), rf.size);
    var buf: [16]u8 = undefined;
    try testing.expectEqualStrings("xxbbbb", try readAll(tmp.dir, "n.log", &buf));
    try testing.expectEqualStrings("aaaa", try readAll(tmp.dir, "n.moved", &buf));
    try testing.expectEqual(@as(usize, 0), try listCount(tmp.dir, "n.2"));
}

test "mutation 2026-11-07: the file created by a rotation has file_permissions" {
    var tmp = testing.tmpDir(.{ .iterate = true });
    defer tmp.cleanup();
    fake_now = 1_793_973_909;
    var rf = try RotatingFile.open(tmp.dir, testing.io, "m.log", .{ .max_size = 4, .now_s = fakeNow, .file_permissions = .fromMode(0o600) });
    defer rf.close();
    try rf.write("aaaa");
    try rf.write("bbbb");
    try testing.expectEqual(@as(usize, 2), try listCount(tmp.dir, "m."));
    const st = try tmp.dir.statFile(testing.io, "m.log", .{});
    try testing.expectEqual(@as(u32, 0), @as(u32, @intCast(st.permissions.toMode() & 0o077)));
}

test "mutation 2026-11-07: isBackup accepts exactly <stem>.<stamp>[_NN]<ext>" {
    var tmp = testing.tmpDir(.{ .iterate = true });
    defer tmp.cleanup();
    var rf = try RotatingFile.open(tmp.dir, testing.io, "p.log", .{});
    defer rf.close();
    for ([_][]const u8{
        "p.2026-11-06T14-05-09.log",
        "p.2026-11-06T14-05-09_00.log",
        "p.2026-11-06T14-05-09_99.log",
        "p.0000-00-00T00-00-00_19.log",
        "p.9999-99-99T99-99-99.log",
    }) |n| try testing.expect(rf.isBackup(n));
    for ([_][]const u8{
        "p.log",
        "p.",
        "px2026-11-06T14-05-09.log",
        "q.2026-11-06T14-05-09.log",
        "p.2026-11-06T14-05-09",
        "p.2026-11-06T14-05-09.txt",
        "p.202.-11-06T14-05-09.log", // '.' sits just below '0'
        "p.202:-11-06T14-05-09.log", // ':' sits just above '9'
        "p.2026x11-06T14-05-09.log",
        "p.2026-11-06X14-05-09.log",
        "p.2026-11-06T14:05-09.log",
        "p.2026-11-06T14-05-09_9.log",
        "p.2026-11-06T14-05-09_099.log",
        "p.2026-11-06T14-05-09-99.log",
        "p.2026-11-06T14-05-09_a9.log",
        "p.2026-11-06T14-05-09_9a.log",
        "p.2026-11-06T14-05-09_0.log", // '.' below '0' in the suffix
        "p.2026-11-06T14-05-09_.9.log",
        "p.2026-11-06T14-05-09_9:.log",
    }) |n| try testing.expect(!rf.isBackup(n));
}

test "mutation 2026-11-07: a failed prune is recorded, the rotation itself is not a failure" {
    var tmp = testing.tmpDir(.{ .iterate = true });
    defer tmp.cleanup();
    try tmp.dir.createDir(testing.io, "other", .default_dir);
    var other = try tmp.dir.openDir(testing.io, "other", .{ .iterate = true });
    defer other.close(testing.io);
    for ([_][]const u8{ "k.2020-01-01T00-00-00.log", "k.2020-01-02T00-00-00.log", "k.2020-01-03T00-00-00.log" }) |n|
        try other.writeFile(testing.io, .{ .sub_path = n, .data = "x" });
    fake_now = 1_793_973_909;
    var rf = try RotatingFile.open(tmp.dir, testing.io, "k.log", .{ .max_size = 4, .max_backups = 1, .now_s = fakeNow });
    const real_list = rf.list_dir;
    rf.list_dir = other; // the pruner lists three backups here, but deleting them in `dir` fails
    defer {
        rf.list_dir = real_list;
        rf.close();
    }
    try rf.write("aaaa");
    try rf.write("bbbb");
    try testing.expectEqual(@as(u64, 0), rf.rotate_failures);
    try testing.expectEqual(@as(?anyerror, null), rf.last_rotate_error);
    try testing.expect(rf.last_prune_error != null);
}

test "mutation 2026-11-07: max_backups 0 keeps every backup, also when it is set after open" {
    var tmp = testing.tmpDir(.{ .iterate = true });
    defer tmp.cleanup();
    var rf = try RotatingFile.open(tmp.dir, testing.io, "b.log", .{ .max_size = 4, .max_backups = 1, .now_s = fakeNow });
    defer rf.close();
    rf.options.max_backups = 0;
    var t: i64 = 1_793_973_909;
    for (0..4) |_| {
        fake_now = t;
        try rf.write("abcd");
        t += 10;
    }
    try testing.expectEqual(@as(usize, 4), try listCount(tmp.dir, "b."));
    try testing.expectEqual(@as(?anyerror, null), rf.last_prune_error);
}

test "mutation 2026-11-07: a clock at the top of i64 with a positive offset names the backup year 9999, not 1970" {
    var tmp = testing.tmpDir(.{ .iterate = true });
    defer tmp.cleanup();
    var rf = try RotatingFile.open(tmp.dir, testing.io, "t.log", .{ .max_size = 1, .now_s = fakeNow, .utc_offset_min = 60 });
    defer rf.close();
    fake_now = std.math.maxInt(i64);
    try rf.write("ab");
    try rf.write("cd");
    try testing.expect(has(tmp.dir, "t.9999-12-31T23-59-59.log"));
}

test "mutation 2026-11-07: a rename that fails for a reason other than a missing file fails the rotation, not the record" {
    if (std.os.linux.geteuid() == 0) return error.SkipZigTest; // root renames in a read-only directory
    var tmp = testing.tmpDir(.{ .iterate = true });
    defer tmp.cleanup();
    fake_now = 1_793_973_909;
    var rf = try RotatingFile.open(tmp.dir, testing.io, "h.log", .{ .max_size = 4, .now_s = fakeNow });
    defer rf.close();
    try rf.write("aaaa");
    try tmp.dir.setPermissions(testing.io, .fromMode(0o500));
    defer tmp.dir.setPermissions(testing.io, .fromMode(0o700)) catch {};
    try rf.write("bbbb"); // the rename is refused: the record still goes on into the file
    try testing.expectEqual(@as(u64, 1), rf.rotate_failures);
    try testing.expect(rf.last_rotate_error != null);
    try testing.expectEqual(@as(u64, 8), rf.size);
}
