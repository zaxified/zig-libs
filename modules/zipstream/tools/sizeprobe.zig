// SPDX-License-Identifier: MIT
//! Size probe for the `small` lane (CONVENTIONS §4.2): a consumer that only
//! reads, the shape of bxp-cli (the request that split the codec table and added
//! `zipstream-builtin-decoders`). Built at ReleaseSmall under `-Dprofile=default`
//! and `-Dprofile=small` by `scripts/checks/small-sizes.sh`; the size difference
//! is held to its floor in `scripts/checks/small-size-expected.tsv`.
const std = @import("std");
const zipstream = @import("zipstream");

pub fn main(init: std.process.Init) !void {
    var args = init.minimal.args.iterate();
    _ = args.next();
    const path = args.next() orelse return error.Usage;
    const file = try std.Io.Dir.openFileAbsolute(init.io, path, .{});
    defer file.close(init.io);
    var archive: zipstream.Archive = undefined;
    try archive.init(init.io, init.gpa, file);
    defer archive.deinit();
    var window: [std.compress.flate.max_window_len]u8 = undefined;
    for (archive.entries.items) |*entry| {
        var er: zipstream.EntryReader = undefined;
        try er.init(&archive, entry, &window);
        var buf: [4096]u8 = undefined;
        _ = try er.reader().readSliceShort(&buf);
    }
}
