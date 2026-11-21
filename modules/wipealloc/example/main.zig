// SPDX-License-Identifier: MIT
//! Two ways to keep a secret out of freed memory: `WipingAllocator` under a growing buffer (every
//! block that is given back is zeroed first), and `SecureAllocator` for a key that lives in its own
//! guard-paged, locked mapping.

const std = @import("std");
const wipealloc = @import("wipealloc");

pub fn main(init: std.process.Init) !void {
    var wiper = wipealloc.WipingAllocator.init(init.gpa);
    const a = wiper.allocator();
    var secret: std.ArrayList(u8) = .empty;
    defer secret.deinit(a); // every grown-out block and the last one are zeroed
    try secret.appendSlice(a, "correct horse battery staple");
    try secret.appendSlice(a, " and a much longer tail that forces the list to grow");

    var secure = try wipealloc.SecureAllocator.init(.best_effort);
    const sa = secure.allocator();
    const key = try sa.alloc(u8, 32);
    defer sa.free(key); // zeroed, then unmapped
    @memset(key, 0x42);
    if (!secure.canaryIntact(key)) std.debug.panic("example check failed: canary overwritten", .{});

    var buf: [128]u8 = undefined;
    var w = std.Io.File.stdout().writer(init.io, &buf);
    try w.interface.print("wiped list: {d} bytes; secure key: {d} bytes, canary intact: {}\n", .{ secret.items.len, key.len, secure.canaryIntact(key) });
    try w.interface.flush();
}
