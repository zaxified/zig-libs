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
    var aw: std.Io.Writer.Allocating = .init(std.heap.page_allocator);
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
        var aw: std.Io.Writer.Allocating = .init(std.heap.page_allocator);
        defer aw.deinit();
        job.stats = tar.packDir(testing.io, std.heap.page_allocator, &.{job.root}, &aw.writer) catch |e| {
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
    const ts = [2]linux.timespec{ linux.UTIME.OMIT, .{ .sec = sec, .nsec = 0 } };
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
