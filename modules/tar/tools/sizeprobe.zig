// SPDX-License-Identifier: MIT
//! Size probe for the `small` lane (CONVENTIONS §4.2): what axp uses of tar, a
//! `Reader` walk and a `Writer` that re-emits each entry (axp-vault's backup
//! ingest and axp-core's packer). Built at ReleaseSmall under `-Dprofile=default`
//! and `-Dprofile=small` by `scripts/checks/small-sizes.sh`; the difference is the
//! sparse reader (`-Dtar-sparse`), held to its floor in
//! `scripts/checks/small-size-expected.tsv`.
const std = @import("std");
const tar = @import("tar");

pub fn main(init: std.process.Init) !void {
    const io = init.io;
    const gpa = init.gpa;
    var rbuf: [4096]u8 = undefined;
    var fr = std.Io.File.stdin().readerStreaming(io, &rbuf);
    var wbuf: [4096]u8 = undefined;
    var fw = std.Io.File.stdout().writerStreaming(io, &wbuf);
    const tw = tar.Writer.init(&fw.interface);
    var tr = tar.Reader.init(gpa, &fr.interface);
    defer tr.deinit();
    var buf: [4096]u8 = undefined;
    var n_entries: u64 = 0;
    while (try tr.next()) |e| {
        n_entries += 1;
        while (true) {
            const n = try tr.read(&buf);
            if (n == 0) break;
        }
        const kind: tar.Kind = switch (e.kind) {
            .dir => .dir,
            .symlink => .symlink,
            else => .file,
        };
        try tw.writeEntry(.{ .path = e.path, .kind = kind, .mode = e.mode, .uid = e.uid, .gid = e.gid, .mtime = e.mtime, .link_target = e.link_target }, "");
    }
    try tw.finish();
    try fw.interface.flush();
    std.process.exit(@intCast(n_entries & 0x7f));
}
