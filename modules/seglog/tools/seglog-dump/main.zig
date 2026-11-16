// SPDX-License-Identifier: MIT

//! seglog-dump — offline inspection of a seglog directory (the role of Kafka's
//! `kafka-dump-log` and etcd's `etcd-dump-logs`). Uses only the public seglog
//! API plus one `std.Io.Dir` listing (for `rebuild-manifest`; the library
//! itself never lists a directory).
//!
//!     zig build install-dump-seglog          # -> zig-out/dump/seglog-dump
//!     seglog-dump segments <dir>             # id, form (raw|zst), first LSN, size
//!     seglog-dump verify <dir>               # Log.verify report; exit 1 on damage
//!     seglog-dump seek <dir> --lsn N         # the Position of LSN N
//!     seglog-dump seek <dir> --time T        # the Position seekTime(T) answers
//!     seglog-dump get <dir> --lsn N [--hex]  # one record: lsn, ts, length, payload
//!     seglog-dump rebuild-manifest <dir>     # Log.rebuildManifest over the ids found
//!
//! Every command but `rebuild-manifest` opens the log read-only (`openReadOnly`,
//! no lock, nothing written), so it is safe beside a running writer.
//! `rebuild-manifest` writes only what `Log.rebuildManifest` writes (a new
//! MANIFEST, and only when none decodes). Exit codes: 0 ok, 1 the answer is
//! "no" (damage, no such record) or an error, 2 usage.

const std = @import("std");
const seglog = @import("seglog");

const Out = std.Io.Writer;

pub fn main(init: std.process.Init.Minimal) u8 {
    const gpa = std.heap.smp_allocator;
    var threaded: std.Io.Threaded = .init(gpa, .{});
    defer threaded.deinit();
    const io = threaded.io();

    var it = init.args.iterate();
    _ = it.next();
    const cmd = it.next() orelse return usage();
    const dir = it.next() orelse return usage();

    var lsn: ?u64 = null;
    var time: ?i64 = null;
    var hex = false;
    while (it.next()) |a| {
        if (std.mem.eql(u8, a, "--hex")) {
            hex = true;
        } else if (std.mem.eql(u8, a, "--lsn")) {
            lsn = std.fmt.parseInt(u64, it.next() orelse return usage(), 10) catch return usage();
        } else if (std.mem.eql(u8, a, "--time")) {
            time = std.fmt.parseInt(i64, it.next() orelse return usage(), 10) catch return usage();
        } else return usage();
    }

    var out_buf: [4096]u8 = undefined;
    var ow = std.Io.File.stdout().writerStreaming(io, &out_buf);
    const w = &ow.interface;

    const rc = run(gpa, io, w, cmd, dir, lsn, time, hex) catch |err| {
        w.flush() catch {};
        std.debug.print("seglog-dump {s}: {s}\n", .{ cmd, @errorName(err) });
        return 1;
    };
    w.flush() catch return 1;
    return rc;
}

fn usage() u8 {
    std.debug.print(
        \\usage: seglog-dump segments <dir>
        \\       seglog-dump verify <dir>
        \\       seglog-dump seek <dir> (--lsn N | --time T)
        \\       seglog-dump get <dir> --lsn N [--hex]
        \\       seglog-dump rebuild-manifest <dir>
        \\
    , .{});
    return 2;
}

fn run(gpa: std.mem.Allocator, io: std.Io, w: *Out, cmd: []const u8, path: []const u8, lsn: ?u64, time: ?i64, hex: bool) !u8 {
    const is_rebuild = std.mem.eql(u8, cmd, "rebuild-manifest");
    const d = try std.Io.Dir.cwd().openDir(io, path, .{ .iterate = is_rebuild });
    defer d.close(io);
    var fs = seglog.FsStorage.init(io, d);

    if (is_rebuild) return rebuild(gpa, io, w, d, fs.storage());

    var log = try seglog.Log.openReadOnly(gpa, fs.storage(), .{});
    defer log.close();

    if (std.mem.eql(u8, cmd, "segments")) return segments(io, w, d, &log);
    if (std.mem.eql(u8, cmd, "verify")) return verify(gpa, w, &log);
    if (std.mem.eql(u8, cmd, "seek")) {
        const pos = if (lsn) |n|
            try log.seek(n)
        else if (time) |t|
            try log.seekTime(t)
        else
            return usage();
        const p = pos orelse {
            try w.writeAll("none\n");
            return 1;
        };
        try w.print("segment {d} offset {d}", .{ p.segment, p.offset });
        if (p.lsn) |l| try w.print(" lsn {d}", .{l});
        try w.writeByte('\n');
        return 0;
    }
    if (std.mem.eql(u8, cmd, "get")) return get(w, &log, lsn orelse return usage(), hex);
    return usage();
}

fn segments(io: std.Io, w: *Out, d: std.Io.Dir, log: *seglog.Log) !u8 {
    try w.writeAll("id\tform\tfirst_lsn\tsize\n");
    for (log.segments()) |id| {
        var nbuf: [32]u8 = undefined;
        // The form is a property of the file, not of the log API: try the
        // raw name first, then the seekable-zstd one.
        var form: []const u8 = "raw";
        var size: u64 = 0;
        const raw = std.fmt.bufPrint(&nbuf, "seg-{d:0>20}.log", .{id}) catch unreachable;
        if (d.statFile(io, raw, .{})) |st| {
            size = st.size;
        } else |_| {
            const zst = std.fmt.bufPrint(&nbuf, "seg-{d:0>20}.zst", .{id}) catch unreachable;
            form = "zst";
            size = (try d.statFile(io, zst, .{})).size;
        }
        try w.print("{d}\t{s}\t", .{ id, form });
        if (log.segmentFirstLsn(id)) |l| try w.print("{d}", .{l}) else try w.writeByte('-');
        try w.print("\t{d}\n", .{size});
    }
    return 0;
}

fn verify(gpa: std.mem.Allocator, w: *Out, log: *seglog.Log) !u8 {
    var r = try log.verify(gpa);
    defer r.deinit(gpa);
    try w.print("segments {d}\nrecords {d}\nlast_lsn {d}\n", .{ r.segments, r.records, r.last_lsn });
    for (r.damage.items, r.gaps.items) |dm, gap| {
        try w.print("damage segment {d} offset {d} reason {s}", .{ dm.segment, dm.offset, @tagName(dm.reason) });
        if (gap.from_lsn) |f| try w.print(" gap {d}", .{f}) else try w.writeAll(" gap ?");
        if (gap.to_lsn) |t| try w.print("..{d}", .{t}) else try w.writeAll("..?");
        try w.writeByte('\n');
    }
    try w.writeAll(if (r.clean()) "clean\n" else "DAMAGED\n");
    return if (r.clean()) 0 else 1;
}

fn get(w: *Out, log: *seglog.Log, lsn: u64, hex: bool) !u8 {
    // `Log.get` gives the payload only; the timestamp comes from one iterator step
    // at the same position.
    const pos = (try log.seek(lsn)) orelse {
        try w.print("lsn {d}: not found\n", .{lsn});
        return 1;
    };
    if (pos.lsn != lsn) {
        try w.print("lsn {d}: not found\n", .{lsn});
        return 1;
    }
    var it = log.iterator(pos);
    defer it.deinit();
    const rec = (try it.next()) orelse {
        try w.print("lsn {d}: not found\n", .{lsn});
        return 1;
    };
    if (rec.lsn != lsn) {
        try w.print("lsn {d}: not found\n", .{lsn});
        return 1;
    }
    try w.print("lsn {d}\nts {d}\nlength {d}\npayload ", .{ rec.lsn, rec.ts, rec.payload.len });
    if (hex) {
        for (rec.payload) |c| try w.print("{x:0>2}", .{c});
    } else {
        for (rec.payload) |c| switch (c) {
            '\\' => try w.writeAll("\\\\"),
            '\n' => try w.writeAll("\\n"),
            '\r' => try w.writeAll("\\r"),
            '\t' => try w.writeAll("\\t"),
            0x20...0x5b, 0x5d...0x7e => try w.writeByte(c),
            else => try w.print("\\x{x:0>2}", .{c}),
        };
    }
    try w.writeByte('\n');
    return 0;
}

/// `seg-<20 digits>.log` or `.zst` -> the id; anything else is not a segment.
fn segmentId(name: []const u8) ?u64 {
    if (name.len != 28 or !std.mem.startsWith(u8, name, "seg-")) return null;
    const ext = name[24..];
    if (!std.mem.eql(u8, ext, ".log") and !std.mem.eql(u8, ext, ".zst")) return null;
    return std.fmt.parseInt(u64, name[4..24], 10) catch null;
}

fn rebuild(gpa: std.mem.Allocator, io: std.Io, w: *Out, d: std.Io.Dir, store: seglog.Storage) !u8 {
    var ids: std.ArrayList(u64) = .empty;
    defer ids.deinit(gpa);
    var it = d.iterate();
    while (try it.next(io)) |e| {
        if (e.kind != .file) continue;
        if (segmentId(e.name)) |id| try ids.append(gpa, id);
    }
    std.mem.sort(u64, ids.items, {}, std.sort.asc(u64));
    // A segment may leave both names behind a crashed compress: one id.
    var n: usize = 0;
    for (ids.items) |id| {
        if (n > 0 and ids.items[n - 1] == id) continue;
        ids.items[n] = id;
        n += 1;
    }
    ids.shrinkRetainingCapacity(n);
    try seglog.Log.rebuildManifest(gpa, store, ids.items);
    try w.print("MANIFEST rebuilt over {d} segments ({d}..{d})\n", .{ n, ids.items[0], ids.items[n - 1] });
    return 0;
}
