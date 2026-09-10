const std = @import("std");
const na = @import("netaddr.zig");
var prng = std.Random.DefaultPrng.init(7);
pub fn main() void {
    const r = prng.random();
    var fails: usize = 0;
    var i: usize = 0;
    while (i < 2_000_000) : (i += 1) {
        const v4 = (i % 2) == 0;
        var addr: na.Ip = undefined;
        if (v4) {
            var q: [4]u8 = undefined;
            r.bytes(&q);
            addr = .{ .v4 = q };
        } else {
            var b: [16]u8 = undefined;
            r.bytes(&b);
            for (0..8) |k| if (r.boolean()) {
                b[k * 2] = 0;
                b[k * 2 + 1] = 0;
            };
            addr = .{ .v6 = b };
        }
        const p: na.Prefix = .{ .addr = addr, .bits = r.intRangeAtMost(u8, 0, if (v4) 32 else 128) };
        var buf: [na.max_prefix_text_len]u8 = undefined;
        const t = na.formatPrefix(p, &buf);
        const back = na.parsePrefix(t);
        if (back == null or !back.?.eql(p)) fails += 1;
    }
    var w: [128]u8 = undefined;
    const m = std.fmt.bufPrint(&w, "prefix round-trip: 2000000 cases, failures={d}\n", .{fails}) catch return;
    _ = std.os.linux.write(1, m.ptr, m.len);
}
