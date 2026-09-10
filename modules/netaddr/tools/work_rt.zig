const std = @import("std");
const na = @import("netaddr.zig");

var outbuf: [1 << 22]u8 = undefined;
var outlen: usize = 0;
fn flush() void {
    var off: usize = 0;
    while (off < outlen) {
        const n = std.os.linux.write(1, outbuf[off..].ptr, outlen - off);
        if (std.os.linux.errno(n) != .SUCCESS or n == 0) return;
        off += n;
    }
    outlen = 0;
}
fn emit(comptime fmt: []const u8, args: anytype) void {
    if (outlen + 256 > outbuf.len) flush();
    const s = std.fmt.bufPrint(outbuf[outlen..], fmt, args) catch return;
    outlen += s.len;
}

var prng = std.Random.DefaultPrng.init(0xC0FFEE);

/// Random v6 with a controllable density of zero groups, to stress `::`.
fn randV6(r: std.Random) [16]u8 {
    var b: [16]u8 = undefined;
    const zero_p = r.intRangeAtMost(u8, 0, 100);
    var i: usize = 0;
    while (i < 8) : (i += 1) {
        if (r.intRangeAtMost(u8, 0, 99) < zero_p) {
            b[i * 2] = 0;
            b[i * 2 + 1] = 0;
        } else {
            b[i * 2] = r.int(u8);
            b[i * 2 + 1] = r.int(u8);
        }
    }
    return b;
}

pub fn main() !void {
    const r = prng.random();
    const emit_lines: usize = 400_000;
    const total: usize = 8_000_000;

    var fails: usize = 0;
    var i: usize = 0;
    while (i < total) : (i += 1) {
        const is4 = (i % 4) == 0;
        const ip: na.Ip = if (is4) blk: {
            var q: [4]u8 = undefined;
            r.bytes(&q);
            break :blk .{ .v4 = q };
        } else .{ .v6 = randV6(r) };

        var buf: [na.max_ip_text_len]u8 = undefined;
        const text = na.formatIp(ip, &buf);
        const back = na.parseIp(text);
        var ok = false;
        if (back) |bk| ok = bk.eql(ip);
        if (!ok) {
            fails += 1;
            if (fails < 20) {
                emit("ROUNDTRIP-FAIL ", .{});
                switch (ip) {
                    .v4 => |q| for (q) |c| emit("{x:0>2}", .{c}),
                    .v6 => |b| for (b) |c| emit("{x:0>2}", .{c}),
                }
                emit(" -> '{s}'\n", .{text});
            }
        }
        if (i < emit_lines) {
            switch (ip) {
                .v4 => |q| {
                    emit("4 ", .{});
                    for (q) |c| emit("{x:0>2}", .{c});
                },
                .v6 => |b| {
                    emit("6 ", .{});
                    for (b) |c| emit("{x:0>2}", .{c});
                },
            }
            emit(" {s}\n", .{text});
        }
    }
    emit("SUMMARY total={d} roundtrip_fails={d}\n", .{ total, fails });
    flush();
}
