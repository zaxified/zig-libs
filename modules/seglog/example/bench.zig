// SPDX-License-Identifier: MIT

//! seglog-bench — the measurement behind seglog's numbers, and the Zig half of
//! the comparison with other logs (`../tools/bench-go` runs the same scenarios
//! against tidwall/wal and Prometheus's wlog).
//!
//!     seglog-bench <scenario> <dir> <payload bytes> <records> [batch] [prealloc]
//!
//! `dir` must not exist; it is created, used and removed. Put it on the disk
//! being measured, never on tmpfs, where fsync costs nothing.
//!
//! Scenarios:
//! - `append`  one record per `append`, so one fsync per record
//! - `batch`   `batch` records per `appendMany`, one fsync per batch
//! - `read`    write the records (batches of 1000), reopen, time a full scan
//! - `open`    write the records into one unsealed segment, time `Log.open`
//!             (the recovery walk of the newest segment)
//! - `seek`    write the records, reopen, then `batch` random reads by LSN:
//!             `seek` + one iterator step each (ops/s = reads/s)
//! - `group`   `batch` threads share a `Concurrent`, each appending its part
//!             one record at a time with `.always`: group commit
//! - `compress` write meter-like text records (not random bytes: those do
//!             not compress), rotate, time `compress` of the closed segment;
//!             the last column is compressed bytes per record
//! - `zread`   the same, then reopen and time a full scan of the compressed
//!             segment
//!
//!     seglog-bench realz <dir> <payload file> <level> [frame bytes]
//!
//! `realz`: real records — a file of `u32 length ++ payload`, each payload
//! starting with its i64 timestamp (egw-hub's raw records) — appended, the
//! segment closed and compressed; prints two lines: `compress` (its time,
//! compressed bytes per record) and `zread` (a full scan of the compressed
//! segment).
//!
//! `prealloc`: `Options.preallocate` in bytes for the writing phase (default
//! 0); the impl column then reads `seglog+pa`.
//!
//! One TSV line on stdout:
//! impl scenario payload records batch seconds ops_per_s MB_per_s bytes_per_record

const std = @import("std");
const seglog = @import("seglog");

const Scenario = enum { append, batch, read, open, group, seek, compress, zread };

pub fn main(init: std.process.Init.Minimal) u8 {
    var it = init.args.iterate();
    _ = it.next();
    const scen_s = it.next() orelse return usage();
    const dir = it.next() orelse return usage();
    if (std.mem.eql(u8, scen_s, "realz")) {
        const file = it.next() orelse return usage();
        const level = std.fmt.parseInt(i32, it.next() orelse return usage(), 10) catch return usage();
        const frame = if (it.next()) |f| std.fmt.parseInt(u32, f, 10) catch return usage() else 256 * 1024;
        const gpa0 = std.heap.smp_allocator;
        var th: std.Io.Threaded = .init(gpa0, .{});
        defer th.deinit();
        runRealz(gpa0, th.io(), dir, file, level, frame) catch |err| {
            std.debug.print("seglog-bench: {s}\n", .{@errorName(err)});
            return 1;
        };
        return 0;
    }
    const payload_len = std.fmt.parseInt(usize, it.next() orelse return usage(), 10) catch return usage();
    const records = std.fmt.parseInt(u64, it.next() orelse return usage(), 10) catch return usage();
    const batch_n = if (it.next()) |s| std.fmt.parseInt(usize, s, 10) catch return usage() else 1;
    const prealloc = if (it.next()) |s| std.fmt.parseInt(u64, s, 10) catch return usage() else 0;
    const scen = std.meta.stringToEnum(Scenario, scen_s) orelse return usage();
    if (batch_n == 0 or records == 0) return usage();

    const gpa = std.heap.smp_allocator;
    var threaded: std.Io.Threaded = .init(gpa, .{});
    defer threaded.deinit();
    const io = threaded.io();

    run(gpa, io, scen, dir, payload_len, records, batch_n, prealloc) catch |err| {
        std.debug.print("seglog-bench: {s}\n", .{@errorName(err)});
        return 1;
    };
    return 0;
}

fn usage() u8 {
    std.debug.print("usage: seglog-bench append|batch|read|open|seek|group <new dir> <payload bytes> <records> [batch] [prealloc]\n", .{});
    return 2;
}

fn monoNs() u64 {
    var ts: std.os.linux.timespec = undefined;
    _ = std.os.linux.clock_gettime(.MONOTONIC, &ts);
    return @as(u64, @intCast(ts.sec)) * std.time.ns_per_s + @as(u64, @intCast(ts.nsec));
}

fn run(gpa: std.mem.Allocator, io: std.Io, scen: Scenario, path: []const u8, payload_len: usize, records: u64, batch_arg: usize, prealloc: u64) !void {
    const cwd = std.Io.Dir.cwd();
    try cwd.createDir(io, path, .default_dir);
    const d = try cwd.openDir(io, path, .{});
    defer {
        d.close(io);
        cwd.deleteDir(io, path) catch {};
    }
    var fs = seglog.FsStorage.init(io, d);
    const st = fs.storage();

    // Incompressible payloads, a different one per slot, so nothing below
    // the log (a compressing filesystem, say) makes the numbers flattering.
    if (scen == .group) return runGroup(gpa, io, st, d, payload_len, records, batch_arg, prealloc);
    const batch_n: usize = switch (scen) {
        .append => 1,
        .batch => batch_arg,
        .read, .open, .seek, .compress, .zread => 1000,
        .group => unreachable,
    };
    const buf = try gpa.alloc(u8, payload_len * batch_n);
    defer gpa.free(buf);
    var prng = std.Random.DefaultPrng.init(0x5e9109);
    prng.random().bytes(buf);
    const text = scen == .compress or scen == .zread;
    const views = try gpa.alloc([]const u8, batch_n);
    defer gpa.free(views);
    for (views, 0..) |*v, i| v.* = buf[i * payload_len ..][0..payload_len];

    var log = try seglog.Log.open(gpa, st, .{ .create = true, .max_record_len = @intCast(@max(payload_len, 1 << 20)), .preallocate = prealloc });
    var log_open = true;
    defer if (log_open) log.close();
    try log.rotate(1);

    var elapsed: u64 = 0;
    var compressed: ?u64 = null;
    const t0 = monoNs();
    var written: u64 = 0;
    while (written < records) {
        const n: usize = @intCast(@min(batch_n, records - written));
        if (text) for (views[0..n], 0..) |v, i| meterText(@constCast(v), written + i, prng.random());
        if (n == 1) _ = try log.append(views[0]) else _ = try log.appendMany(views[0..n]);
        written += n;
    }
    elapsed = monoNs() - t0;
    const file_bytes = log.end().?.offset;

    switch (scen) {
        .append, .batch => {},
        .compress, .zread => {
            try log.rotate(2);
            const c0 = monoNs();
            const cs = try log.compress(1);
            elapsed = monoNs() - c0;
            compressed = cs.bytes_after;
            if (scen == .zread) {
                log.close();
                log_open = false;
                log = try seglog.Log.open(gpa, st, .{ .max_record_len = @intCast(@max(payload_len, 1 << 20)) });
                log_open = true;
                const r0 = monoNs();
                var iter = log.iterator(null);
                defer iter.deinit();
                var seen: u64 = 0;
                while (try iter.next()) |_| seen += 1;
                elapsed = monoNs() - r0;
                if (seen != records) return error.CountMismatch;
            }
        },
        .group => unreachable,
        .seek => {
            log.close();
            log_open = false;
            log = try seglog.Log.open(gpa, st, .{ .max_record_len = @intCast(@max(payload_len, 1 << 20)) });
            log_open = true;
            var rng = std.Random.DefaultPrng.init(42);
            const s0 = monoNs();
            for (0..batch_arg) |_| {
                const lsn = rng.random().intRangeAtMost(u64, 1, records);
                var it = log.iterator((try log.seek(lsn)).?);
                defer it.deinit();
                const r = (try it.next()).?;
                if (r.lsn != lsn) return error.SeekMismatch;
            }
            elapsed = monoNs() - s0;
        },
        .read => {
            log.close();
            log_open = false;
            log = try seglog.Log.open(gpa, st, .{ .max_record_len = @intCast(@max(payload_len, 1 << 20)) });
            log_open = true;
            const r0 = monoNs();
            var iter = log.iterator(null);
            defer iter.deinit();
            var seen: u64 = 0;
            var sum: u64 = 0;
            while (try iter.next()) |rec| {
                seen += 1;
                sum +%= rec.payload[0];
            }
            elapsed = monoNs() - r0;
            std.mem.doNotOptimizeAway(sum);
            if (seen != records) return error.CountMismatch;
        },
        .open => {
            log.close();
            log_open = false;
            const o0 = monoNs();
            log = try seglog.Log.open(gpa, st, .{ .max_record_len = @intCast(@max(payload_len, 1 << 20)) });
            elapsed = monoNs() - o0;
            log_open = true;
            if (log.end().?.offset != file_bytes) return error.SizeMismatch;
        },
    }

    // Remove what the log made: its files are known by name.
    const segs = try gpa.dupe(u64, log.segments());
    defer gpa.free(segs);
    log.close();
    log_open = false;
    for (segs) |id| {
        var nb: [64]u8 = undefined;
        for ([_][]const u8{ "log", "zst", "idx" }) |ext| d.deleteFile(io, try std.mem.print(&nb, "seg-{d:0>20}.{s}", .{ id, ext })) catch {};
    }
    for ([_][]const u8{ "MANIFEST", "MANIFEST.tmp", "LOCK" }) |name| d.deleteFile(io, name) catch {};

    const secs = @as(f64, @floatFromInt(elapsed)) / 1e9;
    const recs_f: f64 = @floatFromInt(if (scen == .seek) batch_arg else records);
    const payload_mb = recs_f * @as(f64, @floatFromInt(payload_len)) / 1e6;
    const per_rec = if (compressed) |c|
        @as(f64, @floatFromInt(c)) / @as(f64, @floatFromInt(records))
    else
        (@as(f64, @floatFromInt(file_bytes - seglog.segment_header_len)) / @as(f64, @floatFromInt(records))) - @as(f64, @floatFromInt(payload_len));
    var out_buf: [512]u8 = undefined;
    var ow = std.Io.File.stdout().writerStreaming(io, &out_buf);
    const w = &ow.interface;
    try w.print("{s}\t{s}\t{d}\t{d}\t{d}\t{d:.4}\t{d:.0}\t{d:.1}\t{d:.1}\n", .{
        if (prealloc != 0) "seglog+pa" else "seglog", @tagName(scen), payload_len, records, batch_n, secs, recs_f / secs, payload_mb / secs, per_rec,
    });
    try w.flush();
}

fn runRealz(gpa: std.mem.Allocator, io: std.Io, path: []const u8, file: []const u8, level: i32, frame: u32) !void {
    const cwd = std.Io.Dir.cwd();
    const data = try cwd.readFileAlloc(io, file, gpa, .limited(1 << 30));
    defer gpa.free(data);
    try cwd.createDir(io, path, .default_dir);
    const d = try cwd.openDir(io, path, .{});
    defer {
        d.close(io);
        cwd.deleteDir(io, path) catch {};
    }
    var fs = seglog.FsStorage.init(io, d);
    const st = fs.storage();
    const opts: seglog.Options = .{ .create = true, .sync = .manual, .compression = .{ .level = level, .frame_size = frame } };
    var log = try seglog.Log.open(gpa, st, opts);
    var log_open = true;
    defer if (log_open) log.close();
    try log.rotate(1);
    var off: usize = 0;
    var records: u64 = 0;
    var payload_bytes: u64 = 0;
    while (off + 4 <= data.len) {
        const len = std.mem.readInt(u32, data[off..][0..4], .little);
        const p = data[off + 4 ..][0..len];
        _ = try log.appendAt(std.mem.readInt(i64, p[0..8], .little), p);
        off += 4 + len;
        records += 1;
        payload_bytes += len;
    }
    try log.sync();
    const raw = log.end().?.offset;
    try log.rotate(2);
    const c0 = monoNs();
    const cs = try log.compress(1);
    const c_ns = monoNs() - c0;
    log.close();
    log_open = false;
    log = try seglog.Log.open(gpa, st, opts);
    log_open = true;
    const r0 = monoNs();
    var iter = log.iterator(null);
    var seen: u64 = 0;
    while (try iter.next()) |_| seen += 1;
    iter.deinit();
    const r_ns = monoNs() - r0;
    if (seen != records) return error.CountMismatch;

    const segs = try gpa.dupe(u64, log.segments());
    defer gpa.free(segs);
    log.close();
    log_open = false;
    for (segs) |id| {
        var nb: [64]u8 = undefined;
        for ([_][]const u8{ "log", "zst", "idx" }) |ext| d.deleteFile(io, try std.mem.print(&nb, "seg-{d:0>20}.{s}", .{ id, ext })) catch {};
    }
    for ([_][]const u8{ "MANIFEST", "MANIFEST.tmp", "LOCK" }) |name| d.deleteFile(io, name) catch {};

    const recs_f: f64 = @floatFromInt(records);
    const raw_mb = @as(f64, @floatFromInt(raw)) / 1e6;
    var out_buf: [512]u8 = undefined;
    var ow = std.Io.File.stdout().writerStreaming(io, &out_buf);
    const w = &ow.interface;
    try w.print("seglog\tcompress-l{d}-f{d}\t{d:.0}\t{d}\t1\t{d:.4}\t{d:.0}\t{d:.1}\t{d:.1}\n", .{
        level,                                        frame,                                        @as(f64, @floatFromInt(payload_bytes)) / recs_f,  records, @as(f64, @floatFromInt(c_ns)) / 1e9,
        recs_f * 1e9 / @as(f64, @floatFromInt(c_ns)), raw_mb * 1e9 / @as(f64, @floatFromInt(c_ns)), @as(f64, @floatFromInt(cs.bytes_after)) / recs_f,
    });
    try w.print("seglog\tzread-l{d}-f{d}\t{d:.0}\t{d}\t1\t{d:.4}\t{d:.0}\t{d:.1}\t{d:.3}\n", .{
        level,                                        frame,                                        @as(f64, @floatFromInt(payload_bytes)) / recs_f,                        records, @as(f64, @floatFromInt(r_ns)) / 1e9,
        recs_f * 1e9 / @as(f64, @floatFromInt(r_ns)), raw_mb * 1e9 / @as(f64, @floatFromInt(r_ns)), @as(f64, @floatFromInt(raw)) / @as(f64, @floatFromInt(cs.bytes_after)),
    });
    try w.flush();
}

/// A meter reading as text, `buf.len` bytes: what egw-hub's records look
/// like to a compressor — repeated field names, slowly moving numbers.
fn meterText(buf: []u8, i: u64, rnd: std.Random) void {
    var w: std.Io.Writer = .fixed(buf);
    w.print("{{\"dev\":\"egw-{x:0>4}\",\"ts\":{d},\"p\":{d}.{d:0>3},\"e\":{d}", .{
        i % 37, 1_790_000_000 + i / 37, rnd.intRangeAtMost(u32, 0, 4000), rnd.intRangeAtMost(u32, 0, 999), 1_000_000 + i / 3,
    }) catch {};
    var k: u32 = 0;
    while (w.end < buf.len) : (k += 1) w.print(",\"r{d}\":{d}", .{ k, rnd.intRangeAtMost(u32, 0, 250) }) catch break;
    @memset(buf[w.end..], ' ');
}

fn groupWorker(c: *seglog.Concurrent, payload: []const u8, n: u64, failed: *std.atomic.Value(bool)) void {
    for (0..n) |_| _ = c.append(payload) catch {
        failed.store(true, .monotonic);
        return;
    };
}

fn runGroup(gpa: std.mem.Allocator, io: std.Io, st: seglog.Storage, d: std.Io.Dir, payload_len: usize, records: u64, threads_n: usize, prealloc: u64) !void {
    const payload = try gpa.alloc(u8, payload_len);
    defer gpa.free(payload);
    @memset(payload, 0x5a);
    var c = try seglog.Concurrent.open(gpa, st, io, .{ .create = true, .preallocate = prealloc });
    try c.rotate(1);
    var failed: std.atomic.Value(bool) = .init(false);
    const threads = try gpa.alloc(std.Thread, threads_n);
    defer gpa.free(threads);
    const per = records / threads_n;
    const t0 = monoNs();
    for (threads) |*t| t.* = try std.Thread.spawn(.{}, groupWorker, .{ &c, payload, per, &failed });
    for (threads) |t| t.join();
    const elapsed = monoNs() - t0;
    if (failed.load(.monotonic)) return error.AppendFailed;
    const done = per * threads_n;
    const segs = try gpa.dupe(u64, c.log.segments());
    defer gpa.free(segs);
    c.close();
    for (segs) |id| {
        var nb: [64]u8 = undefined;
        for ([_][]const u8{ "log", "zst", "idx" }) |ext| d.deleteFile(io, try std.mem.print(&nb, "seg-{d:0>20}.{s}", .{ id, ext })) catch {};
    }
    for ([_][]const u8{ "MANIFEST", "MANIFEST.tmp", "LOCK" }) |name| d.deleteFile(io, name) catch {};
    const secs = @as(f64, @floatFromInt(elapsed)) / 1e9;
    const recs_f: f64 = @floatFromInt(done);
    var out_buf: [512]u8 = undefined;
    var ow = std.Io.File.stdout().writerStreaming(io, &out_buf);
    const w = &ow.interface;
    try w.print("{s}\tgroup\t{d}\t{d}\t{d}\t{d:.4}\t{d:.0}\t{d:.1}\t{d:.1}\n", .{
        if (prealloc != 0) "seglog+pa" else "seglog", payload_len, done, threads_n, secs, recs_f / secs, recs_f * @as(f64, @floatFromInt(payload_len)) / 1e6 / secs, @as(f64, 25),
    });
    try w.flush();
}
