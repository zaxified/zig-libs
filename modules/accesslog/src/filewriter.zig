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

    pub const OpenError = error{InvalidName} || File.OpenError || File.StatError;

    /// Open `name` (a plain file name inside `dir`: no separator, 1 to
    /// `max_name_len` bytes) for appending, creating it when missing. `name`
    /// must outlive the writer; `dir` stays the caller's.
    pub fn open(dir: Dir, io: std.Io, name: []const u8, options: Options) OpenError!RotatingFile {
        if (!validName(name)) return error.InvalidName;
        const f = try dir.createFile(io, name, .{ .truncate = false, .permissions = options.file_permissions });
        errdefer f.close(io);
        const st = try f.stat(io);
        return .{
            .dir = dir,
            .io = io,
            .name = name,
            .options = options,
            .file = f,
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
        // One unit: the rotation decision sees the whole call.
        var total: u64 = 0;
        for (data[0 .. data.len - 1]) |d| total += d.len;
        const last = data[data.len - 1];
        total += @as(u64, last.len) * splat;
        if (total == 0) return 0;
        self.beforeWrite(total);
        const f = self.file orelse {
            self.last_write_error = error.Closed;
            return error.WriteFailed;
        };
        var off = self.size;
        for (data[0 .. data.len - 1]) |d| {
            f.writePositionalAll(self.io, d, off) catch |e| return self.failWrite(e, off);
            off += d.len;
        }
        for (0..splat) |_| {
            f.writePositionalAll(self.io, last, off) catch |e| return self.failWrite(e, off);
            off += last.len;
        }
        self.size = off;
        return @intCast(total);
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
        const old = self.file.?;
        if (!self.reopen_pending) {
            var nb: [max_name_len + 40]u8 = undefined;
            const backup = try self.freshBackupName(&nb);
            try self.dir.rename(self.name, self.dir, backup, self.io);
            self.reopen_pending = true;
        }
        const nf = try self.dir.createFile(self.io, self.name, .{ .truncate = true, .permissions = self.options.file_permissions });
        old.close(self.io);
        self.file = nf;
        self.size = 0;
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
            var it = self.dir.iterate();
            while (try it.next(self.io)) |e| {
                if (e.kind != .file or e.name.len > oldest.len or !self.isBackup(e.name)) continue;
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
