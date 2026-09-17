// SPDX-License-Identifier: MIT
//
// Minimal buffered stdout shared by this directory's probes. No `std.Io`
// instance and no allocator: the module under test allocates nothing, so its
// instruments do not either — otherwise `allocprobe`-style questions could
// never be asked of the pair.

const std = @import("std");

var buf: [1 << 20]u8 = undefined;
var n: usize = 0;

pub fn print(comptime fmt: []const u8, args: anytype) void {
    if (n > buf.len - 4096) flush();
    const s = std.fmt.bufPrint(buf[n..], fmt, args) catch unreachable;
    n += s.len;
}

pub fn flush() void {
    var off: usize = 0;
    while (off < n) off += std.os.linux.write(1, buf[off..n].ptr, n - off);
    n = 0;
}
