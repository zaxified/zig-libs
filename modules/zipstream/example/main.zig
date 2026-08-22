// SPDX-License-Identifier: MIT

//! What a report exporter does with `zipstream`: write a small archive with
//! `ArchiveWriter` (Store + Deflate mixed), then read it back with the
//! streaming `Archive`/`EntryReader` pair — the two halves a consumer that
//! both produces and later re-opens its own archives actually uses. Also
//! shows the zip-slip guard rejecting an unsafe member name up front.

const std = @import("std");
const zipstream = @import("zipstream");

const archive_path = "/tmp/zipstream-example.zip";

pub fn main() !void {
    var da: std.heap.DebugAllocator(.{}) = .init;
    defer if (da.deinit() == .leak) @panic("leak");
    const gpa = da.allocator();

    var threaded: std.Io.Threaded = .init(gpa, .{});
    defer threaded.deinit();
    const io = threaded.io();

    // ── write ────────────────────────────────────────────────────────────
    {
        var out_file = try std.Io.Dir.createFileAbsolute(io, archive_path, .{});
        defer out_file.close(io);
        var wbuf: [8192]u8 = undefined;
        var fw = out_file.writer(io, &wbuf);

        var writer = zipstream.ArchiveWriter.init(gpa, &fw.interface);
        defer writer.deinit();

        try writer.addEntry("summary.csv", "id,total\n1,42\n2,17\n", .{ .method = .store });
        const long_text = "row,value\n" ** 200; // compresses well
        try writer.addEntry("detail.csv", long_text, .{ .method = .deflate });

        // A member name that would escape the extraction directory on
        // unpack: `addEntry` gates it through the same `isSafeEntryName`
        // check a caller extracting to disk is told to use itself.
        if (writer.addEntry("../../etc/passwd", "pwned", .{})) |_| {
            std.debug.print("unexpected: unsafe entry name accepted\n", .{});
        } else |err| switch (err) {
            error.ZipUnsafeEntryName => std.debug.print("addEntry(\"../../etc/passwd\"): ZipUnsafeEntryName (expected)\n", .{}),
            else => return err,
        }

        try writer.finish();
        try fw.interface.flush();
    }
    defer std.Io.Dir.deleteFileAbsolute(io, archive_path) catch {};

    // ── read back ────────────────────────────────────────────────────────
    var in_file = try std.Io.Dir.openFileAbsolute(io, archive_path, .{});
    defer in_file.close(io);

    var archive: zipstream.Archive = undefined;
    try archive.init(io, gpa, in_file);
    defer archive.deinit();

    std.debug.print("archive has {d} member(s)\n", .{archive.entries.items.len});
    for (archive.entries.items) |e| {
        std.debug.print("  {s}: {d} -> {d} bytes ({s})\n", .{ e.name, e.compressed_size, e.uncompressed_size, @tagName(e.compression) });
    }

    const entry = archive.find("summary.csv") orelse return error.MemberNotFound;
    var window: [std.compress.flate.max_window_len]u8 = undefined;
    var er: zipstream.EntryReader = undefined;
    try er.init(&archive, entry, &window);

    var content: std.ArrayList(u8) = .empty;
    defer content.deinit(gpa);
    try er.reader().appendRemaining(gpa, &content, .unlimited);
    std.debug.print("summary.csv content:\n{s}", .{content.items});
    std.debug.print("crc32 verified: {}\n", .{!er.crcMismatch()});
}
