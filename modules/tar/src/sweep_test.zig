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
