// SPDX-License-Identifier: MIT
//! Size probe for the `small` lane (CONVENTIONS §4.2): a consumer that
//! compresses with a level only known at run time and reads the frame back,
//! the shape of a storage layer with a configurable compression level. Built
//! at ReleaseSmall under `-Dprofile=default` and `-Dprofile=small` by
//! `scripts/checks/small-sizes.sh`; the size difference (`zstd-all-strategies`)
//! is held to its floor in `scripts/checks/small-size-expected.tsv`. The level
//! comes from the pid so nothing folds at comptime.
const std = @import("std");
const zstd = @import("zstd");

pub fn main(init: std.process.Init) void {
    const pid: u32 = @bitCast(std.os.linux.getpid());
    const level: i32 = @intCast(pid % 22 + 1);
    var src: [4096]u8 = undefined;
    for (&src, 0..) |*b, i| b.* = @truncate((i *% 7) ^ (i >> 3) ^ pid);
    var dst: [zstd.compressBound(src.len)]u8 = undefined;
    const n = zstd.compress(init.gpa, &dst, &src, .{ .level = level }) catch std.os.linux.exit(2);
    var back: [src.len]u8 = undefined;
    const m = zstd.decompress(init.gpa, &back, dst[0..n]) catch std.os.linux.exit(3);
    std.os.linux.exit(@intCast((m ^ n) & 1));
}
