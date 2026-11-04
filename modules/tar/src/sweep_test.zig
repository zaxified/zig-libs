// SPDX-License-Identifier: MIT
//! No-panic sweep tests for tar (wave GW). Findings TA-1 .. TA-3, see
//! ~/CML/20261029-panic-sweep/tar-sweep.report.md. The hostile-archive tests at
//! the end pin the reader's "clean" verdicts (they pass without any fix).
const std = @import("std");
const builtin = @import("builtin");
const linux = std.os.linux;
const testing = std.testing;
const tar = @import("root.zig");

// ── forked child for checked panics ─────────────────────────────────────────

const Child = struct { died: bool, len: usize };

fn runChild(comptime body: fn () void, buf: []u8) !Child {
    if (builtin.os.tag != .linux) return error.SkipZigTest;
    var fds: [2]i32 = undefined;
    if (linux.errno(linux.pipe2(&fds, .{})) != .SUCCESS) return error.SkipZigTest;
    const rc = linux.fork();
    if (linux.errno(rc) != .SUCCESS) return error.SkipZigTest;
    if (rc == 0) {
        _ = linux.dup2(fds[1], 2);
        _ = linux.close(fds[0]);
        _ = linux.close(fds[1]);
        body();
        linux.exit_group(0);
    }
    _ = linux.close(fds[1]);
    defer _ = linux.close(fds[0]);
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
            return error.ChildHung;
        }
        const ts: linux.timespec = .{ .sec = 0, .nsec = 10 * std.time.ns_per_ms };
        _ = linux.nanosleep(&ts, null);
        waited_ms += 10;
    }
    const n = linux.read(fds[0], buf.ptr, buf.len);
    return .{ .died = linux.W.IFSIGNALED(status), .len = if (linux.errno(n) == .SUCCESS) n else 0 };
}

// Needles live in consts, never inline in the call: the child's stack trace prints the caller's source line.
const needle_content = "tar: writeEntry content given for a non-file entry";

fn expectPanicMessage(comptime body: fn () void, needle: []const u8) !void {
    var buf: [8192]u8 = undefined;
    const c = try runChild(body, &buf);
    try testing.expect(c.died);
    try testing.expect(std.mem.find(u8, buf[0..c.len], needle) != null);
}

// ── TA-1: writeEntry content for a non-file kind ────────────────────────────

fn dirWithContent() void {
    var aw: std.Io.Writer.Allocating = .init(std.heap.page_allocator); // global-alloc-ok: forked sweep child that exits or panics; testing.allocator cannot follow it into the child
    const w = tar.Writer.init(&aw.writer);
    w.writeEntry(.{ .path = "d", .kind = .dir }, "payload") catch {};
}

test "writeEntry: content for a non-file entry is a checked tar panic (sweep TA-1)" {
    var aw: std.Io.Writer.Allocating = .init(testing.allocator);
    defer aw.deinit();
    const w = tar.Writer.init(&aw.writer);
    try w.writeEntry(.{ .path = "d", .kind = .dir }, ""); // the legal form
    try expectPanicMessage(dirWithContent, needle_content);
}

// ── TA-2: packDir on a deep tree must not recurse on the stack ──────────────

const deep_levels = 400;

const DeepJob = struct {
    root: []const u8,
    stats: ?tar.PackStats = null,
    err: ?anyerror = null,
    bytes: usize = 0,

    fn run(job: *DeepJob) void {
        var aw: std.Io.Writer.Allocating = .init(std.heap.page_allocator); // global-alloc-ok: forked sweep child that exits or panics; testing.allocator cannot follow it into the child
        defer aw.deinit();
        job.stats = tar.packDir(testing.io, std.heap.page_allocator, &.{job.root}, &aw.writer) catch |e| { // global-alloc-ok: forked sweep child that exits or panics; testing.allocator cannot follow it into the child
            job.err = e;
            return;
        };
        job.bytes = aw.writer.buffered().len;
    }
};

test "packDir: a 400-level deep tree packs on a 1 MiB stack (sweep TA-2)" {
    if (builtin.os.tag != .linux) return error.SkipZigTest;
    const io = testing.io;
    var tmp = testing.tmpDir(.{});
    defer tmp.cleanup();
    try tmp.dir.createDir(io, "t", .default_dir);
    var cur = try tmp.dir.openDir(io, "t", .{});
    var i: usize = 0;
    while (i < deep_levels) : (i += 1) {
        try cur.createDir(io, "a", .default_dir);
        const next = try cur.openDir(io, "a", .{});
        cur.close(io);
        cur = next;
    }
    try cur.writeFile(io, .{ .sub_path = "leaf.txt", .data = "deep" });
    cur.close(io);

    var rb: [std.fs.max_path_bytes]u8 = undefined;
    const n = try tmp.dir.realPath(io, &rb);
    var root: [std.fs.max_path_bytes]u8 = undefined;
    const root_path = try std.mem.print(&root, "{s}/t", .{rb[0..n]});

    var job: DeepJob = .{ .root = root_path };
    // 1 MiB: the recursive walk needed ~18 KiB per level and died at ~55 levels.
    const th = try std.Thread.spawn(.{ .stack_size = 1 << 20 }, DeepJob.run, .{&job});
    th.join();
    try testing.expectEqual(@as(?anyerror, null), job.err);
    const st = job.stats.?;
    try testing.expectEqual(@as(usize, deep_levels + 1), st.dirs);
    try testing.expectEqual(@as(usize, 1), st.files);
}

// ── TA-3: an unopenable file is skipped and counted, not zero-filled ────────

test "packDir: a file that cannot be opened is skipped and counted (sweep TA-3)" {
    if (builtin.os.tag != .linux) return error.SkipZigTest;
    if (linux.getuid() == 0) return error.SkipZigTest; // root opens mode-000 files
    const gpa = testing.allocator;
    const io = testing.io;
    var tmp = testing.tmpDir(.{});
    defer tmp.cleanup();
    try tmp.dir.createDir(io, "t", .default_dir);
    try tmp.dir.writeFile(io, .{ .sub_path = "t/secret.bin", .data = &@as([5000]u8, @splat('x')) });
    try tmp.dir.writeFile(io, .{ .sub_path = "t/ok.txt", .data = "ok" });
    var f = try tmp.dir.openFile(io, "t/secret.bin", .{});
    try testing.expectEqual(linux.E.SUCCESS, linux.errno(linux.fchmod(f.handle, 0)));
    f.close(io);

    var rb: [std.fs.max_path_bytes]u8 = undefined;
    const n = try tmp.dir.realPath(io, &rb);
    var root: [std.fs.max_path_bytes]u8 = undefined;
    const root_path = try std.mem.print(&root, "{s}/t", .{rb[0..n]});

    var aw: std.Io.Writer.Allocating = try .initCapacity(gpa, 4096);
    defer aw.deinit();
    const st = try tar.packDir(io, gpa, &.{root_path}, &aw.writer);
    try testing.expectEqual(@as(usize, 1), st.files);
    try testing.expectEqual(@as(usize, 1), st.skipped);

    var src: std.Io.Reader = .fixed(aw.writer.buffered());
    const window = try gpa.alloc(u8, std.compress.flate.max_window_len);
    defer gpa.free(window);
    var dec = std.compress.flate.Decompress.init(&src, .gzip, window);
    var tr = tar.Reader.init(gpa, &dec.reader);
    defer tr.deinit();
    var names: usize = 0;
    while (try tr.next()) |e| {
        names += 1;
        try testing.expect(!std.mem.endsWith(u8, e.path, "secret.bin"));
    }
    try testing.expectEqual(@as(usize, 2), names); // t/ and t/ok.txt
}

test "packDir: a root at or over PATH_MAX is PathTooLong (regression)" {
    if (builtin.os.tag != .linux) return error.SkipZigTest;
    var aw: std.Io.Writer.Allocating = .init(testing.allocator);
    defer aw.deinit();
    const long: [std.fs.max_path_bytes + 10]u8 = @splat('a');
    try testing.expectError(error.PathTooLong, tar.packDir(testing.io, testing.allocator, &.{&long}, &aw.writer));
    try testing.expectError(error.PathTooLong, tar.packDir(testing.io, testing.allocator, &.{long[0..std.fs.max_path_bytes]}, &aw.writer));
}

// ── hostile archives: clean-verdict pins (no fix needed) ────────────────────

fn mkHeader(name: []const u8, size_field: [12]u8, typeflag: u8) [512]u8 {
    var b: [512]u8 = @splat(0);
    @memcpy(b[0..name.len], name);
    @memcpy(b[100..107], "0000644");
    @memcpy(b[108..115], "0000000");
    @memcpy(b[116..123], "0000000");
    @memcpy(b[124..136], &size_field);
    @memcpy(b[136..147], "00000000000");
    b[156] = typeflag;
    @memcpy(b[257..263], "ustar\x00");
    @memcpy(b[263..265], "00");
    @memset(b[148..156], ' ');
    var sum: u32 = 0;
    for (b) |c| sum += c;
    _ = std.mem.print(b[148..155], "{o:0>6}", .{sum}) catch unreachable;
    b[154] = 0;
    b[155] = ' ';
    return b;
}

fn octal12(v: u64) [12]u8 {
    var f: [12]u8 = undefined;
    _ = std.mem.print(f[0..11], "{o:0>11}", .{v}) catch unreachable;
    f[11] = 0;
    return f;
}

fn expectNextError(archive: []const u8, want: anyerror) !void {
    var src: std.Io.Reader = .fixed(archive);
    var tr = tar.Reader.init(testing.allocator, &src);
    defer tr.deinit();
    try testing.expectError(want, tr.next());
}

test "reader clean: size fields and pax records that lie are errors (hostile archive)" {
    // base-256 size = 2^64 - 1 + 1 (11 bytes of magnitude, bit 64 set)
    var big: [12]u8 = @splat(0);
    big[0] = 0x80;
    big[3] = 1; // 2^64 > u64
    try expectNextError(&mkHeader("f", big, '0'), error.BadHeader);
    // base-256 size = u64 max: rejected (size + padding would overflow)
    var max: [12]u8 = @splat(0xff);
    max[0] = 0x80;
    try expectNextError(&mkHeader("f", max, '0'), error.BadHeader);
    // GNU long name of 70000 bytes: refused before any allocation
    try expectNextError(&mkHeader("L", octal12(70000), 'L'), error.BadHeader);
    // pax payload over the cap
    try expectNextError(&mkHeader("x", octal12(tar.max_pax_len + 1), 'x'), error.BadHeader);

    // pax record whose length points past the end / is smaller than its digits
    inline for (.{ "99999 path=x\n", "1 path=x\n", "0 path=x\n", "12 path=x", "5 pathx\n" }) |rec| {
        var a: [1024]u8 = @splat(0);
        const h = mkHeader("x", octal12(rec.len), 'x');
        @memcpy(a[0..512], &h);
        @memcpy(a[512 .. 512 + rec.len], rec);
        try expectNextError(&a, error.BadHeader);
    }
    // pax size = u64 max
    const rec = "30 size=18446744073709551615\n";
    var a: [2048]u8 = @splat(0);
    @memcpy(a[0..512], &mkHeader("x", octal12(rec.len), 'x'));
    @memcpy(a[512 .. 512 + rec.len], rec);
    @memcpy(a[1024..1536], &mkHeader("f", octal12(0), '0'));
    try expectNextError(&a, error.BadHeader);
}

test "reader clean: a declared size beyond the stream is TruncatedArchive, bounded memory" {
    var a: [1024]u8 = @splat(0);
    @memcpy(a[0..512], &mkHeader("f", octal12(0o77777777777), '0'));
    var src: std.Io.Reader = .fixed(&a);
    var tr = tar.Reader.init(testing.allocator, &src);
    defer tr.deinit();
    const e = (try tr.next()).?;
    try testing.expectEqual(@as(u64, 0o77777777777), e.size);
    var buf: [4096]u8 = undefined;
    try testing.expectEqual(@as(usize, 512), try tr.read(&buf));
    try testing.expectError(error.TruncatedArchive, tr.read(&buf));
    try testing.expectError(error.TruncatedArchive, tr.next());
}

// ── TA-4: a file that comes up short while read does not abort the archive ──

test "packDir: a file shorter at read time than at statx is zero-padded and counted (sweep TA-4)" {
    if (builtin.os.tag != .linux) return error.SkipZigTest;
    const gpa = testing.allocator;
    const io = testing.io;
    // A sysfs attribute stats as 4096 bytes and reads as a few: a deterministic
    // stand-in for a log file truncated between statx and read.
    const path = "/sys/devices/system/cpu/online";
    var sx: linux.Statx = undefined;
    if (linux.errno(linux.statx(linux.AT.FDCWD, path, 0, linux.STATX.BASIC_STATS, &sx)) != .SUCCESS) return error.SkipZigTest;
    if (sx.size != 4096) return error.SkipZigTest;
    var tmp = testing.tmpDir(.{});
    defer tmp.cleanup();
    try tmp.dir.createDir(io, "t", .default_dir);
    try tmp.dir.writeFile(io, .{ .sub_path = "t/after.txt", .data = "after" });
    var rb: [std.fs.max_path_bytes]u8 = undefined;
    const n = try tmp.dir.realPath(io, &rb);
    var root: [std.fs.max_path_bytes]u8 = undefined;
    const root_path = try std.mem.print(&root, "{s}/t", .{rb[0..n]});

    var aw: std.Io.Writer.Allocating = try .initCapacity(gpa, 4096);
    defer aw.deinit();
    const st = try tar.packDir(io, gpa, &.{ path, root_path }, &aw.writer);
    try testing.expectEqual(@as(usize, 1), st.skipped);
    try testing.expectEqual(@as(usize, 1), st.files); // t/after.txt, after the short one

    var src: std.Io.Reader = .fixed(aw.writer.buffered());
    const window = try gpa.alloc(u8, std.compress.flate.max_window_len);
    defer gpa.free(window);
    var dec = std.compress.flate.Decompress.init(&src, .gzip, window);
    var tr = tar.Reader.init(gpa, &dec.reader);
    defer tr.deinit();
    const first = (try tr.next()).?;
    try testing.expectEqual(@as(u64, 4096), first.size);
    var total: usize = 0;
    var buf: [1024]u8 = undefined;
    while (true) {
        const k = try tr.read(&buf);
        if (k == 0) break;
        total += k;
    }
    try testing.expectEqual(@as(usize, 4096), total); // header size honoured
    var seen_after = false;
    while (try tr.next()) |e| {
        if (std.mem.endsWith(u8, e.path, "after.txt")) seen_after = true;
    }
    try testing.expect(seen_after); // the archive continued past the short file
}

// ── delta audit GW (gwa-a) ──────────────────────────────────────────────────

fn tmpRoot(tmp: *std.testing.TmpDir, rb: []u8, name: []const u8) ![]const u8 {
    const n = try tmp.dir.realPath(testing.io, rb);
    const tail = try std.mem.print(rb[n..], "/{s}", .{name});
    return rb[0 .. n + tail.len];
}

fn setMtime(path: []const u8, sec: i64, nofollow: bool) !void {
    var pz: [std.fs.max_path_bytes:0]u8 = undefined;
    const z = std.mem.printSentinel(&pz, "{s}", .{path}, 0) catch return error.SkipZigTest;
    const ts = [2]linux.timespec{ linux.UTIME.OMIT, .{ .sec = std.math.cast(@FieldType(linux.timespec, "sec"), sec) orelse return error.SkipZigTest, .nsec = 0 } };
    if (linux.errno(linux.utimensat(linux.AT.FDCWD, z, &ts, if (nofollow) linux.AT.SYMLINK_NOFOLLOW else 0)) != .SUCCESS) return error.SkipZigTest;
    var sx: linux.Statx = undefined;
    if (linux.errno(linux.statx(linux.AT.FDCWD, z, if (nofollow) linux.AT.SYMLINK_NOFOLLOW else 0, linux.STATX.BASIC_STATS, &sx)) != .SUCCESS) return error.SkipZigTest;
    if (sx.mtime.sec != sec) return error.SkipZigTest; // the filesystem clamps it
}

test "packDir: a header the writer refuses is skipped and counted, a refused directory once with its subtree (sweep audit GW-TA5)" {
    if (builtin.os.tag != .linux) return error.SkipZigTest;
    const gpa = testing.allocator;
    const io = testing.io;
    var tmp = testing.tmpDir(.{});
    defer tmp.cleanup();
    try tmp.dir.createDirPath(io, "t/fdir/sub");
    try tmp.dir.writeFile(io, .{ .sub_path = "t/fdir/a.txt", .data = "a" });
    try tmp.dir.writeFile(io, .{ .sub_path = "t/fdir/sub/b.txt", .data = "b" });
    try tmp.dir.writeFile(io, .{ .sub_path = "t/ffile.txt", .data = "f" });
    try tmp.dir.writeFile(io, .{ .sub_path = "t/ok.txt", .data = "ok" });
    try tmp.dir.symLink(io, "ok.txt", "t/flink", .{});
    var rb: [std.fs.max_path_bytes]u8 = undefined;
    const root_path = try tmpRoot(&tmp, &rb, "t");
    // mtime past 0o77777777777 (year 2242) does not fit a ustar field: the header is refused
    const future: i64 = 9_000_000_000;
    var pb: [std.fs.max_path_bytes]u8 = undefined;
    try setMtime(try std.mem.print(&pb, "{s}/fdir", .{root_path}), future, false);
    try setMtime(try std.mem.print(&pb, "{s}/ffile.txt", .{root_path}), future, false);
    try setMtime(try std.mem.print(&pb, "{s}/flink", .{root_path}), future, true);

    var aw: std.Io.Writer.Allocating = try .initCapacity(gpa, 4096);
    defer aw.deinit();
    const st = try tar.packDir(io, gpa, &.{root_path}, &aw.writer);
    try testing.expectEqual(@as(usize, 3), st.skipped); // dir (once), file, symlink
    try testing.expectEqual(@as(usize, 1), st.files); // ok.txt
    try testing.expectEqual(@as(usize, 1), st.dirs); // t itself
    try testing.expectEqual(@as(usize, 0), st.symlinks);

    var src: std.Io.Reader = .fixed(aw.writer.buffered());
    const window = try gpa.alloc(u8, std.compress.flate.max_window_len);
    defer gpa.free(window);
    var dec = std.compress.flate.Decompress.init(&src, .gzip, window);
    var tr = tar.Reader.init(gpa, &dec.reader);
    defer tr.deinit();
    var names: usize = 0;
    while (try tr.next()) |e| {
        names += 1;
        try testing.expect(std.mem.endsWith(u8, e.path, "/t") or std.mem.endsWith(u8, e.path, "/t/") or std.mem.endsWith(u8, e.path, "ok.txt"));
    }
    try testing.expectEqual(@as(usize, 2), names);
}

test "packDir: a directory's subtree is contiguous after its header (depth-first order) (sweep audit GW-TA6)" {
    if (builtin.os.tag != .linux) return error.SkipZigTest;
    const gpa = testing.allocator;
    const io = testing.io;
    var tmp = testing.tmpDir(.{});
    defer tmp.cleanup();
    try tmp.dir.createDirPath(io, "t/a/q");
    try tmp.dir.createDirPath(io, "t/b");
    try tmp.dir.createDirPath(io, "t/c");
    inline for (.{ "t/a/x", "t/a/y", "t/a/q/r", "t/b/z", "t/b/w", "t/c/v", "t/top" }) |p|
        try tmp.dir.writeFile(io, .{ .sub_path = p, .data = "1" });
    var rb: [std.fs.max_path_bytes]u8 = undefined;
    const root_path = try tmpRoot(&tmp, &rb, "t");
    var aw: std.Io.Writer.Allocating = try .initCapacity(gpa, 4096);
    defer aw.deinit();
    const st = try tar.packDir(io, gpa, &.{root_path}, &aw.writer);
    try testing.expectEqual(@as(usize, 5), st.dirs);
    try testing.expectEqual(@as(usize, 7), st.files);

    var src: std.Io.Reader = .fixed(aw.writer.buffered());
    const window = try gpa.alloc(u8, std.compress.flate.max_window_len);
    defer gpa.free(window);
    var dec = std.compress.flate.Decompress.init(&src, .gzip, window);
    var tr = tar.Reader.init(gpa, &dec.reader);
    defer tr.deinit();
    var paths: std.ArrayList([]u8) = .empty;
    defer {
        for (paths.items) |p| gpa.free(p);
        paths.deinit(gpa);
    }
    var kinds: std.ArrayList(bool) = .empty;
    defer kinds.deinit(gpa);
    while (try tr.next()) |e| {
        try paths.append(gpa, try gpa.dupe(u8, std.mem.trimEnd(u8, e.path, "/")));
        try kinds.append(gpa, e.kind == .dir);
    }
    try testing.expectEqual(@as(usize, 12), paths.items.len);
    for (paths.items, kinds.items, 0..) |p, is_dir, i| {
        if (!is_dir) continue;
        var n_sub: usize = 0;
        for (paths.items) |o| {
            if (o.len > p.len and std.mem.startsWith(u8, o, p) and o[p.len] == '/') n_sub += 1;
        }
        for (paths.items[i + 1 ..][0..n_sub]) |o| {
            try testing.expect(o.len > p.len and std.mem.startsWith(u8, o, p) and o[p.len] == '/');
        }
    }
}

test "packDir: a child path of PATH_MAX-1 bytes is packed, one of PATH_MAX bytes is skipped (sweep audit GW-TA7)" {
    if (builtin.os.tag != .linux) return error.SkipZigTest;
    const gpa = testing.allocator;
    const io = testing.io;
    var tmp = testing.tmpDir(.{});
    defer tmp.cleanup();
    try tmp.dir.createDir(io, "t", .default_dir);
    var rb: [std.fs.max_path_bytes]u8 = undefined;
    const root_path = try tmpRoot(&tmp, &rb, "t");
    var cur = try tmp.dir.openDir(io, "t", .{});
    var cur_len = root_path.len;
    const target = std.fs.max_path_bytes - 1; // longest path `statx` accepts (NUL included in PATH_MAX)
    var dirs: usize = 1;
    var name: [256]u8 = undefined;
    while (target - cur_len > 255) {
        const rem = target - cur_len;
        const d: usize = @min(255, rem - 3);
        @memset(name[0..d], 'd');
        try cur.createDir(io, name[0..d], .default_dir);
        const next = try cur.openDir(io, name[0..d], .{});
        cur.close(io);
        cur = next;
        cur_len += 1 + d;
        dirs += 1;
    }
    const rem = target - cur_len; // 2..255
    @memset(name[0 .. rem - 1], 'a');
    try cur.writeFile(io, .{ .sub_path = name[0 .. rem - 1], .data = "A" }); // path length == target
    @memset(name[0..rem], 'b');
    try cur.writeFile(io, .{ .sub_path = name[0..rem], .data = "B" }); // path length == target + 1
    cur.close(io);

    var aw: std.Io.Writer.Allocating = try .initCapacity(gpa, 4096);
    defer aw.deinit();
    const st = try tar.packDir(io, gpa, &.{root_path}, &aw.writer);
    try testing.expectEqual(@as(usize, 1), st.files);
    try testing.expectEqual(@as(usize, dirs), st.dirs);
    try testing.expectEqual(@as(usize, 0), st.skipped);
}

test "packDir: a file whose read fails is zero-padded and counted like a short one (sweep audit GW-TA8)" {
    if (builtin.os.tag != .linux) return error.SkipZigTest;
    // std.Io turns EINVAL from read() into a panic ("programmer bug") in Debug builds only.
    if (builtin.mode == .debug) return error.SkipZigTest;
    const gpa = testing.allocator;
    const io = testing.io;
    // sysfs `speed` of the loopback device stats as a 4096-byte regular file and
    // fails every read with EINVAL: a deterministic stand-in for an EIO mid-file.
    const path = "/sys/class/net/lo/speed";
    var sx: linux.Statx = undefined;
    if (linux.errno(linux.statx(linux.AT.FDCWD, path, 0, linux.STATX.BASIC_STATS, &sx)) != .SUCCESS) return error.SkipZigTest;
    if (sx.size != 4096 or sx.mode & linux.S.IFMT != linux.S.IFREG) return error.SkipZigTest;
    const ofd = linux.open(path, .{}, 0);
    if (linux.errno(ofd) != .SUCCESS) return error.SkipZigTest;
    var one: [1]u8 = undefined;
    const rr = linux.read(@intCast(ofd), &one, 1);
    _ = linux.close(@intCast(ofd));
    if (linux.errno(rr) == .SUCCESS) return error.SkipZigTest;

    var tmp = testing.tmpDir(.{});
    defer tmp.cleanup();
    try tmp.dir.createDir(io, "t", .default_dir);
    try tmp.dir.writeFile(io, .{ .sub_path = "t/after.txt", .data = "after" });
    var rb: [std.fs.max_path_bytes]u8 = undefined;
    const root_path = try tmpRoot(&tmp, &rb, "t");
    var aw: std.Io.Writer.Allocating = try .initCapacity(gpa, 4096);
    defer aw.deinit();
    const st = try tar.packDir(io, gpa, &.{ path, root_path }, &aw.writer);
    try testing.expectEqual(@as(usize, 1), st.skipped);
    try testing.expectEqual(@as(usize, 1), st.files);

    var src: std.Io.Reader = .fixed(aw.writer.buffered());
    const window = try gpa.alloc(u8, std.compress.flate.max_window_len);
    defer gpa.free(window);
    var dec = std.compress.flate.Decompress.init(&src, .gzip, window);
    var tr = tar.Reader.init(gpa, &dec.reader);
    defer tr.deinit();
    const first = (try tr.next()).?;
    try testing.expectEqual(@as(u64, 4096), first.size);
    var total: usize = 0;
    var buf: [1024]u8 = undefined;
    while (true) {
        const k = try tr.read(&buf);
        if (k == 0) break;
        for (buf[0..k]) |c| try testing.expectEqual(@as(u8, 0), c);
        total += k;
    }
    try testing.expectEqual(@as(usize, 4096), total);
    var seen_after = false;
    while (try tr.next()) |e| {
        if (std.mem.endsWith(u8, e.path, "after.txt")) seen_after = true;
    }
    try testing.expect(seen_after);
}

test "packDir: a destination that fails ends the call with WriteFailed (sweep audit GW-TA9)" {
    if (builtin.os.tag != .linux) return error.SkipZigTest;
    const gpa = testing.allocator;
    const io = testing.io;
    var tmp = testing.tmpDir(.{});
    defer tmp.cleanup();
    try tmp.dir.createDir(io, "t", .default_dir);
    var noise: [20000]u8 = undefined;
    var prng = std.Random.DefaultPrng.init(0x7a11);
    prng.random().bytes(&noise); // incompressible, so the gzip stream outgrows the sink
    try tmp.dir.writeFile(io, .{ .sub_path = "t/noise.bin", .data = &noise });
    var rb: [std.fs.max_path_bytes]u8 = undefined;
    const root_path = try tmpRoot(&tmp, &rb, "t");
    var sink: [1024]u8 = undefined;
    var w: std.Io.Writer = .fixed(&sink);
    try testing.expectError(error.WriteFailed, tar.packDir(io, gpa, &.{root_path}, &w));
}

// ── extraction-safety API and sparse members (2026-11-04) ───────────────────

test "checkPath: refuses empty, NUL, absolute and `..` names by default" {
    const bad = [_]struct { p: []const u8, e: anyerror }{
        .{ .p = "", .e = error.EmptyPath },
        .{ .p = "a\x00b", .e = error.NulInPath },
        .{ .p = "/etc/passwd", .e = error.AbsolutePath },
        .{ .p = "/", .e = error.AbsolutePath },
        .{ .p = "..", .e = error.ParentEscape },
        .{ .p = "../x", .e = error.ParentEscape },
        .{ .p = "a/../../x", .e = error.ParentEscape },
        .{ .p = "a/b/..", .e = error.ParentEscape },
        .{ .p = "a//..//b", .e = error.ParentEscape },
    };
    for (bad) |c| try testing.expectError(c.e, tar.checkPath(c.p, .{}));
    for ([_][]const u8{ "./", ".", "a", "a/b/c.txt", "a/./b", "..a", "a..", "a/..b/c", "a//b" }) |ok| try tar.checkPath(ok, .{});
    try tar.checkPath("/abs", .{ .allow_absolute = true });
    try tar.checkPath("../up", .{ .allow_parent = true });
    try testing.expectError(error.AbsolutePath, tar.checkPath("/abs", .{ .allow_parent = true }));
}

test "checkEntry: symlink and hard-link escapes, special files" {
    const sym = struct {
        fn e(path: []const u8, target: []const u8) tar.Entry {
            return .{ .path = path, .kind = .symlink, .link_target = target };
        }
    }.e;
    try tar.checkEntry(sym("a/l", "b"), .{});
    try tar.checkEntry(sym("a/l", "../b"), .{}); // lands in the root
    try tar.checkEntry(sym("a/b/l", "../../x"), .{});
    try testing.expectError(error.LinkEscape, tar.checkEntry(sym("l", "a/../b"), .{})); // `..` after a name (fix round)
    try testing.expectError(error.LinkEscape, tar.checkEntry(sym("l", "../x"), .{}));
    try testing.expectError(error.LinkEscape, tar.checkEntry(sym("a/l", "../../x"), .{}));
    try testing.expectError(error.LinkEscape, tar.checkEntry(sym("l", "/etc/passwd"), .{}));
    try testing.expectError(error.LinkEscape, tar.checkEntry(sym("l", ""), .{}));
    try testing.expectError(error.LinkEscape, tar.checkEntry(sym("l", "a/../.."), .{}));
    try testing.expectError(error.LinkEscape, tar.checkEntry(sym("./l", ".."), .{}));
    try tar.checkEntry(sym("l", "/etc"), .{ .allow_absolute = true });
    try tar.checkEntry(sym("l", "../x"), .{ .allow_parent = true });
    try testing.expectError(error.LinkEscape, tar.checkEntry(.{ .path = "h", .kind = .hardlink, .link_target = "/etc/passwd" }, .{}));
    try testing.expectError(error.LinkEscape, tar.checkEntry(.{ .path = "h", .kind = .hardlink, .link_target = "../x" }, .{}));
    try tar.checkEntry(.{ .path = "h", .kind = .hardlink, .link_target = "a/b" }, .{});
    try testing.expectError(error.SpecialFile, tar.checkEntry(.{ .path = "fifo", .kind = .other, .typeflag = '6' }, .{}));
    try tar.checkEntry(.{ .path = "fifo", .kind = .other, .typeflag = '6' }, .{ .allow_special = true });
    try testing.expectError(error.ParentEscape, tar.checkEntry(.{ .path = "../f" }, .{}));
}

fn archiveOf(gpa: std.mem.Allocator, entries: []const tar.Entry) ![]u8 {
    var out: std.Io.Writer.Allocating = .init(gpa);
    errdefer out.deinit();
    const w = tar.Writer.init(&out.writer);
    for (entries) |e| try w.writeEntry(e, if (e.kind == .file) "x" else "");
    try w.finish();
    return out.toOwnedSlice();
}

test "checkArchive: counts members, refuses the first bad one, and an empty archive is not ok" {
    const gpa = testing.allocator;
    const good = try archiveOf(gpa, &.{ .{ .path = "d/", .kind = .dir }, .{ .path = "d/f", .size = 1 }, .{ .path = "d/l", .kind = .symlink, .link_target = "f" } });
    defer gpa.free(good);
    var r: std.Io.Reader = .fixed(good);
    try testing.expectEqual(@as(u64, 3), try tar.checkArchive(gpa, &r, .{}));

    const evil = try archiveOf(gpa, &.{ .{ .path = "a", .size = 1 }, .{ .path = "../../etc/cron.d/x", .size = 1 } });
    defer gpa.free(evil);
    r = .fixed(evil);
    try testing.expectError(error.ParentEscape, tar.checkArchive(gpa, &r, .{}));

    const abs = try archiveOf(gpa, &.{.{ .path = "/etc/passwd", .size = 1 }});
    defer gpa.free(abs);
    r = .fixed(abs);
    try testing.expectError(error.AbsolutePath, tar.checkArchive(gpa, &r, .{}));
    r = .fixed(abs);
    try testing.expectEqual(@as(u64, 1), try tar.checkArchive(gpa, &r, .{ .allow_absolute = true }));

    const empty = try archiveOf(gpa, &.{});
    defer gpa.free(empty);
    r = .fixed(empty);
    try testing.expectError(error.EmptyArchive, tar.checkArchive(gpa, &r, .{}));
    r = .fixed("");
    try testing.expectError(error.EmptyArchive, tar.checkArchive(gpa, &r, .{}));
    r = .fixed(good[0..700]);
    try testing.expectError(error.TruncatedArchive, tar.checkArchive(gpa, &r, .{}));
}

test "checkPath / checkEntry never panic on arbitrary bytes" {
    var prng = std.Random.DefaultPrng.init(0x7a4);
    const rnd = prng.random();
    var buf: [48]u8 = undefined;
    for (0..4000) |_| {
        const n = rnd.uintAtMost(usize, buf.len);
        for (buf[0..n]) |*b| b.* = "./a\x00b-"[rnd.uintLessThan(usize, 6)];
        const split = rnd.uintAtMost(usize, n);
        const kind = rnd.enumValue(tar.Kind);
        const pol: tar.Policy = .{ .allow_absolute = rnd.boolean(), .allow_parent = rnd.boolean(), .allow_special = rnd.boolean() };
        tar.checkEntry(.{ .path = buf[0..split], .kind = kind, .link_target = buf[split..n] }, pol) catch {};
    }
}

test "sparse fixtures: every truncation of each is an error or a short read, never a panic" {
    if (!tar.sparse_enabled) return error.SkipZigTest;
    inline for (.{ "gnu_old", "pax_10", "pax_01", "pax_00" }) |v| {
        const bytes = @embedFile("testdata/read_sparse_" ++ v ++ ".tar");
        var cut: usize = 0;
        while (cut < bytes.len) : (cut += 389) {
            var src: std.Io.Reader = .fixed(bytes[0..cut]);
            var tr = tar.Reader.init(testing.allocator, &src);
            defer tr.deinit();
            var buf: [8192]u8 = undefined;
            walk: while (true) {
                const e = (tr.next() catch break :walk) orelse break :walk;
                _ = e;
                while (true) {
                    const n = tr.read(&buf) catch break :walk;
                    if (n == 0) break;
                }
            }
        }
    }
}

// ── fix round 2026-11-04 ────────────────────────────────────────────────────

test "checkEntry: a symlink target with `..` after a name is refused unless the policy allows it" {
    const sym = struct {
        fn e(path: []const u8, target: []const u8) tar.Entry {
            return .{ .path = path, .kind = .symlink, .link_target = target };
        }
    }.e;
    try testing.expectError(error.LinkEscape, tar.checkEntry(sym("l", "a/../b"), .{}));
    try testing.expectError(error.LinkEscape, tar.checkEntry(sym("l2", "x/l1/.."), .{}));
    try testing.expectError(error.LinkEscape, tar.checkEntry(sym("l2", "x/l1/../.."), .{}));
    try tar.checkEntry(sym("l", "a/../b"), .{ .allow_link_dotdot_after_name = true });
    // The depth check still applies when it is allowed.
    try testing.expectError(error.LinkEscape, tar.checkEntry(sym("l", "a/../../b"), .{ .allow_link_dotdot_after_name = true }));
    // Hard-link targets are root-relative names: any `..` is already refused by checkPath.
    try testing.expectError(error.LinkEscape, tar.checkEntry(.{ .path = "h", .kind = .hardlink, .link_target = "x/l1/.." }, .{}));
    // A backslash is an ordinary byte (POSIX): not a separator.
    try tar.checkPath("a\\..\\b", .{});
}

/// Where `target` (read from the directory `dir`) lands, following the links of
/// `links` at every component; true when it climbs above the root. A loop or a
/// runaway chain counts as not escaping.
fn escapes(arena: std.mem.Allocator, links: *const std.StringHashMapUnmanaged([]const u8), dir: []const []const u8, target: []const u8, budget: *usize) !bool {
    var stack: std.ArrayList([]const u8) = .empty;
    try stack.appendSlice(arena, dir);
    var it = std.mem.splitScalar(u8, target, '/');
    return walkTarget(arena, links, &stack, &it, budget);
}

fn walkTarget(arena: std.mem.Allocator, links: *const std.StringHashMapUnmanaged([]const u8), stack: *std.ArrayList([]const u8), it: *std.mem.SplitIterator(u8, .scalar), budget: *usize) !bool {
    while (it.next()) |c| {
        if (c.len == 0 or std.mem.eql(u8, c, ".")) continue;
        if (std.mem.eql(u8, c, "..")) {
            if (stack.items.len == 0) return true;
            _ = stack.pop();
            continue;
        }
        try stack.append(arena, c);
        const key = try std.mem.join(arena, "/", stack.items);
        if (links.get(key)) |t| {
            if (budget.* == 0) return false;
            budget.* -= 1;
            _ = stack.pop();
            var inner = std.mem.splitScalar(u8, t, '/');
            if (try walkTarget(arena, links, stack, &inner, budget)) return true;
        }
    }
    return false;
}

test "checkEntry: no accepted set of symlinks escapes the root when resolved link by link (chains of up to 8)" {
    var prng = std.Random.DefaultPrng.init(0x11c4);
    const rnd = prng.random();
    const names = [_][]const u8{ "a", "b", "c" };
    const tcomps = [_][]const u8{ "a", "b", "c", "..", ".", "..", "a" };
    var accepted_total: usize = 0;
    var chained: usize = 0;
    for (0..4000) |_| {
        var arena_state = std.heap.ArenaAllocator.init(testing.allocator);
        defer arena_state.deinit();
        const arena = arena_state.allocator();
        var links: std.StringHashMapUnmanaged([]const u8) = .empty;
        var order: std.ArrayList([]const u8) = .empty;
        for (0..8) |_| {
            var pbuf: std.ArrayList(u8) = .empty;
            const pn = 1 + rnd.uintLessThan(usize, 3);
            for (0..pn) |i| {
                if (i != 0) try pbuf.append(arena, '/');
                try pbuf.appendSlice(arena, names[rnd.uintLessThan(usize, names.len)]);
            }
            var tbuf: std.ArrayList(u8) = .empty;
            const tn = 1 + rnd.uintLessThan(usize, 6);
            for (0..tn) |i| {
                if (i != 0) try tbuf.append(arena, '/');
                try tbuf.appendSlice(arena, tcomps[rnd.uintLessThan(usize, tcomps.len)]);
            }
            const path = pbuf.items;
            // The entry must not be written through a link the archive made earlier: that is the
            // extractor's to refuse and not what the lexical check claims.
            var through = links.contains(path);
            for (order.items) |l| {
                if (path.len > l.len and std.mem.startsWith(u8, path, l) and path[l.len] == '/') through = true;
            }
            if (through) continue;
            tar.checkEntry(.{ .path = path, .kind = .symlink, .link_target = tbuf.items }, .{}) catch continue;
            try links.put(arena, path, tbuf.items);
            try order.append(arena, path);
        }
        accepted_total += order.items.len;
        for (order.items) |l| {
            const t = links.get(l).?;
            var dir: std.ArrayList([]const u8) = .empty;
            var pit = std.mem.splitScalar(u8, l, '/');
            var parts: std.ArrayList([]const u8) = .empty;
            while (pit.next()) |c| try parts.append(arena, c);
            try dir.appendSlice(arena, parts.items[0 .. parts.items.len - 1]);
            var budget: usize = 40;
            if (std.mem.indexOf(u8, t, "a") != null or std.mem.indexOf(u8, t, "b") != null) chained += 1;
            if (try escapes(arena, &links, dir.items, t, &budget)) {
                std.debug.print("link {s} -> {s} escapes; set:\n", .{ l, t });
                for (order.items) |o| std.debug.print("  {s} -> {s}\n", .{ o, links.get(o).? });
                return error.AcceptedLinkEscapes;
            }
        }
    }
    try testing.expect(accepted_total > 4000 and chained > 1000); // the generator reaches deep sets
}

test "uname/gname: round trip in both modes, the limits, and dupe" {
    const gpa = testing.allocator;
    const long40: []const u8 = &@as([40]u8, @splat('u'));
    const long41: []const u8 = &@as([41]u8, @splat('g'));
    const un33: []const u8 = &@as([33]u8, @splat('u'));
    const u32s: []const u8 = &@as([32]u8, @splat('u'));
    const g32s: []const u8 = &@as([32]u8, @splat('g'));
    const un300: []const u8 = &@as([300]u8, @splat('u'));
    for ([_]tar.LongNames{ .gnu, .pax }) |mode| {
        var out: std.Io.Writer.Allocating = .init(gpa);
        defer out.deinit();
        const w = tar.Writer.initOptions(&out.writer, .{ .long_names = mode });
        try w.writeEntry(.{ .path = "f", .uid = 1000, .gid = 100, .uname = "alice", .gname = "staff", .size = 1 }, "x");
        if (mode == .pax) try w.writeEntry(.{ .path = "g", .uname = long40, .gname = long41 }, "");
        try w.finish();
        var src: std.Io.Reader = .fixed(out.written());
        var tr = tar.Reader.init(gpa, &src);
        defer tr.deinit();
        var e = (try tr.next()).?;
        try testing.expectEqualStrings("alice", e.uname);
        try testing.expectEqualStrings("staff", e.gname);
        var owned = try e.dupe(gpa);
        defer owned.deinit(gpa);
        if (mode == .pax) {
            e = (try tr.next()).?;
            try testing.expectEqualStrings(long40, e.uname);
            try testing.expectEqualStrings(long41, e.gname);
        }
        try testing.expectEqualStrings("alice", owned.uname);
        try testing.expectEqualStrings("staff", owned.gname);
    }
    var sink: std.Io.Writer.Discarding = .init(&.{});
    const gw = tar.Writer.init(&sink.writer);
    try testing.expectError(error.FieldOutOfRange, gw.writeEntry(.{ .path = "f", .uname = un33 }, ""));
    try testing.expectError(error.FieldOutOfRange, gw.writeEntry(.{ .path = "f", .gname = "a\x00b" }, ""));
    try gw.writeEntry(.{ .path = "f", .uname = u32s, .gname = g32s }, "");
    // A pax record over 255 bytes is not surfaced: the (empty) ustar field stands.
    var out: std.Io.Writer.Allocating = .init(gpa);
    defer out.deinit();
    const pw = tar.Writer.initOptions(&out.writer, .{ .long_names = .pax });
    try pw.writeEntry(.{ .path = "f", .uname = un300 }, "");
    try pw.finish();
    var src: std.Io.Reader = .fixed(out.written());
    var tr = tar.Reader.init(gpa, &src);
    defer tr.deinit();
    try testing.expectEqualStrings("", (try tr.next()).?.uname);
}
