// SPDX-License-Identifier: MIT

//! What a backup/deploy consumer does with `tar`: write a small archive with
//! real ownership/mtime metadata (the reason this module exists instead of
//! `std.tar` — see its doc comment), read it back and confirm every field
//! round-tripped, then feed the reader a truncated copy of the same archive
//! to show a malformed-input error surfaces by name instead of a panic.
//!
//! This is an example in the gate sense — it is built by
//! `zig build check-examples` against the PUBLISHED module (`deps` only, no
//! `test_deps`, no access to anything the module does not export). If a type
//! needed to drive the reader/writer is not public, or an error cannot be
//! named from outside, this file stops compiling.

const std = @import("std");
const tar = @import("tar");

pub fn main() !void {
    var da: std.heap.DebugAllocator(.{}) = .init;
    defer if (da.deinit() == .leak) @panic("leak");
    const gpa = da.allocator();

    // ── write: a small "etc" snapshot with real uid/gid/mtime ──────────────
    var aw: std.Io.Writer.Allocating = .init(gpa);
    defer aw.deinit();
    const tw = tar.Writer.init(&aw.writer);

    try tw.writeEntry(.{
        .path = "etc",
        .kind = .dir,
        .mode = 0o755,
        .uid = 0,
        .gid = 0,
        .mtime = 1_700_000_000,
    }, "");
    try tw.writeEntry(.{
        .path = "etc/hostname",
        .mode = 0o644,
        .uid = 1000,
        .gid = 1000,
        .mtime = 1_700_000_001,
    }, "router\n");
    try tw.writeEntry(.{
        .path = "etc/hostname.link",
        .kind = .symlink,
        .link_target = "hostname",
        .mode = 0o777,
        .uid = 1000,
        .gid = 1000,
        .mtime = 1_700_000_002,
    }, "");
    try tw.finish();

    const archive = aw.writer.buffered();
    std.debug.print("wrote archive: {d} bytes\n", .{archive.len});

    // ── read back: every entry's metadata must have survived ───────────────
    var src: std.Io.Reader = .fixed(archive);
    var tr = tar.Reader.init(gpa, &src);
    defer tr.deinit();

    var files: usize = 0;
    while (try tr.next()) |entry| {
        std.debug.print("entry: path={s} kind={s} mode={o} uid={d} gid={d} mtime={d}\n", .{
            entry.path, @tagName(entry.kind), entry.mode, entry.uid, entry.gid, entry.mtime,
        });
        if (entry.kind == .file) {
            var buf: [64]u8 = undefined;
            var total: usize = 0;
            while (true) {
                const n = try tr.read(buf[total..]);
                if (n == 0) break;
                total += n;
            }
            std.debug.print("  content: {s}", .{buf[0..total]});
            files += 1;
        }
    }
    if (files != 1) @panic("expected exactly one file entry to round-trip");

    // ── malformed input: a header truncated mid-block is a named error, not
    // a panic ───────────────────────────────────────────────────────────────
    var bad_src: std.Io.Reader = .fixed(archive[0 .. tar.block_size / 2]);
    var bad_tr = tar.Reader.init(gpa, &bad_src);
    defer bad_tr.deinit();
    _ = bad_tr.next() catch |err| switch (err) {
        error.TruncatedArchive => std.debug.print("correctly rejected a half-block header\n", .{}),
        error.BadHeader => @panic("unexpected: half a real header parsed as BadHeader, not truncation"),
        else => return err,
    };
}
