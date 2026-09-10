const std = @import("std");
const na = @import("netaddr30.zig");

pub fn main() void {
    // Canary either side of the format buffer.
    var guard: struct { pre: u64, buf: [na.max_ip_text_len]u8, post: u64 } = .{
        .pre = 0xAAAAAAAAAAAAAAAA,
        .buf = @splat(0),
        .post = 0xBBBBBBBBBBBBBBBB,
    };
    const ip: na.Ip = .{ .v6 = @splat(0xff) }; // ffff:ffff:...:ffff -> 39 chars
    const s = na.formatIp(ip, &guard.buf);
    var w: [256]u8 = undefined;
    const msg = std.fmt.bufPrint(&w, "returned_len={d} pre=0x{x} post=0x{x} text='{s}'\n", .{
        s.len, guard.pre, guard.post, s,
    }) catch return;
    _ = std.os.linux.write(1, msg.ptr, msg.len);
}
