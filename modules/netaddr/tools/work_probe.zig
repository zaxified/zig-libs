const std = @import("std");
const na = @import("netaddr.zig");

var outbuf: [1 << 22]u8 = undefined;
var outlen: usize = 0;
var input: [1 << 24]u8 = undefined;

fn emit(comptime fmt: []const u8, args: anytype) void {
    const s = std.fmt.bufPrint(outbuf[outlen..], fmt, args) catch {
        flush();
        return emit(fmt, args);
    };
    outlen += s.len;
}
fn flush() void {
    var off: usize = 0;
    while (off < outlen) {
        const n = std.os.linux.write(1, outbuf[off..].ptr, outlen - off);
        if (std.os.linux.errno(n) != .SUCCESS or n == 0) return;
        off += n;
    }
    outlen = 0;
}

fn hex(b: []const u8) void {
    for (b) |c| emit("{x:0>2}", .{c});
}

pub fn main() !void {
    var ilen: usize = 0;
    while (true) {
        const n = std.os.linux.read(0, input[ilen..].ptr, input.len - ilen);
        if (std.os.linux.errno(n) != .SUCCESS or n == 0) break;
        ilen += n;
        if (ilen == input.len) break;
    }
    var it = std.mem.splitScalar(u8, input[0..ilen], '\n');
    const mode = it.next() orelse "ip";
    while (it.next()) |raw| {
        var line = raw;
        if (line.len > 0 and line[line.len - 1] == '\r') line = line[0 .. line.len - 1];
        // allow encoding of arbitrary bytes: lines are hex-encoded when mode ends in 'x'
        if (std.mem.eql(u8, mode, "ip")) {
            if (na.parseIp(line)) |ip| {
                switch (ip) {
                    .v4 => |q| {
                        emit("4:", .{});
                        hex(&q);
                    },
                    .v6 => |b| {
                        emit("6:", .{});
                        hex(&b);
                    },
                }
                var fb: [na.max_ip_text_len]u8 = undefined;
                emit(":{s}\n", .{na.formatIp(ip, &fb)});
            } else emit("-\n", .{});
        } else if (std.mem.eql(u8, mode, "prefix")) {
            if (na.parsePrefix(line)) |p| {
                var fb: [na.max_prefix_text_len]u8 = undefined;
                emit("P:{s}:", .{na.formatPrefix(p, &fb)});
                const m = p.masked();
                emit("{s}\n", .{na.formatPrefix(m, &fb)});
            } else emit("-\n", .{});
        } else if (std.mem.eql(u8, mode, "hostport")) {
            if (na.parseHostPort(line)) |hp| {
                emit("H:{s}:{d}\n", .{ hp.host, hp.port });
            } else emit("-\n", .{});
        }
    }
    flush();
}
