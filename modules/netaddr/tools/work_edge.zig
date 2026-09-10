const std = @import("std");
const na = @import("netaddr.zig");
var ob: [1 << 20]u8 = undefined;
var ol: usize = 0;
fn e(comptime f: []const u8, a: anytype) void {
    const s = std.fmt.bufPrint(ob[ol..], f, a) catch return;
    ol += s.len;
}
fn flush() void {
    _ = std.os.linux.write(1, &ob, ol);
    ol = 0;
}
fn ip(t: []const u8) void {
    if (na.parseIp(t)) |v| {
        var b: [na.max_ip_text_len]u8 = undefined;
        e("  ACCEPT {s:<52} -> {s} ({s})\n", .{ t, na.formatIp(v, &b), @tagName(v) });
    } else e("  reject {s}\n", .{t});
}
fn hp(t: []const u8) void {
    if (na.parseHostPort(t)) |v| e("  ACCEPT {s:<30} -> host='{s}' port={d}\n", .{ t, v.host, v.port }) else e("  reject {s}\n", .{t});
}

pub fn main() !void {
    var da: std.heap.DebugAllocator(.{}) = .init;
    const gpa = da.allocator();

    e("== brief: embedded IPv4 ==\n", .{});
    for ([_][]const u8{ "::ffff:192.0.2.1", "64:ff9b::192.0.2.33", "::ffff:192.0.2.1.5", "::192.0.2.256", "::ffff:010.0.0.1", "1:2:3:4:5:6:1.2.3.4", "1:2:3:4:5:6:7:1.2.3.4", "::1.2.3.4", "1.2.3.4::", "::1.2.3.4:5", "1::1.2.3.4::2" }) |t| ip(t);

    e("== brief: :: compression ==\n", .{});
    for ([_][]const u8{ "::", "1::", "::1", "1::2:3:4:5:6:7:8", "1:2:3:4:5:6:7:8", "1:2:3:4:5:6:7::8", "1::2::3", "::::", ":::", "1:::2", ":1::2", "1::2:" }) |t| ip(t);

    e("== brief: leading zeros / length limits ==\n", .{});
    for ([_][]const u8{ "0001:0002::", "00001::", "010.0.0.1", "1.2.3.04", "0.0.0.0", "1.2.3", "1.2.3.4.5", "0x7f.0.0.1", "2130706433", "127.1" }) |t| ip(t);

    e("== brief: zone / case / NUL ==\n", .{});
    for ([_][]const u8{ "fe80::1%eth0", "fe80::1%", "%", "fe80::1%0", "FE80::1", "2001:DB8::ABcD", "\x001.2.3.4", "1.2.3.4\x00", "1.2.3\x004" }) |t| ip(t);

    e("== brief: text at exactly max_ip_text_len (45) and around ==\n", .{});
    {
        var buf: [64]u8 = undefined;
        // longest possible canonical v6 = 39 chars
        const longest: na.Ip = .{ .v6 = @splat(0xff) };
        var fb: [na.max_ip_text_len]u8 = undefined;
        const t = na.formatIp(longest, &fb);
        e("  longest formatIp output len = {d} (max_ip_text_len = {d})\n", .{ t.len, na.max_ip_text_len });
        const mapped: na.Ip = .{ .v6 = [_]u8{0} ** 10 ++ [_]u8{ 0xff, 0xff, 255, 255, 255, 255 } };
        e("  longest mapped output   len = {d} '{s}'\n", .{ na.formatIp(mapped, &fb).len, na.formatIp(mapped, &fb) });
        var pb: [na.max_prefix_text_len]u8 = undefined;
        const wp = na.formatPrefix(.{ .addr = longest, .bits = 255 }, &pb);
        e("  worst formatPrefix      len = {d} '{s}' (max_prefix_text_len = {d})\n", .{ wp.len, wp, na.max_prefix_text_len });
        @memset(buf[0..45], 'a');
        ip(buf[0..45]);
        @memset(buf[0..46], 'a');
        ip(buf[0..46]);
        @memset(buf[0..64], 58);
        ip(buf[0..64]);
    }

    e("== brief: parseHostPort ==\n", .{});
    for ([_][]const u8{ "[::1]:80", "[::1]:0", "[::1]:65535", "[::1]:65536", "[::1]", "[::1]:", "::1:80", "2001:db8::1:443", "host:0", "host:00080", "host:", ":80", "[]:80", "[fe80::1%eth0]:22", "host:80:90", "[::1]x80", "1.2.3.4:80", "[1.2.3.4]:80", "[::1]:+80", "[::1]: 80", "a:b:c" }) |t| hp(t);

    e("== C2: what bounds the allocation README says does not exist ==\n", .{});
    {
        const worst4: na.IpRange = .{ .from = .{ .v4 = .{ 0, 0, 0, 1 } }, .to = .{ .v4 = .{ 255, 255, 255, 254 } } };
        const p4 = try na.summarize(gpa, worst4);
        defer gpa.free(p4);
        e("  v4 worst case 0.0.0.1-255.255.255.254 -> {d} prefixes ({d} bytes)\n", .{ p4.len, p4.len * @sizeOf(na.Prefix) });
        var lo: [16]u8 = @splat(0);
        lo[15] = 1;
        var hi: [16]u8 = @splat(0xff);
        hi[15] = 0xfe;
        const p6 = try na.summarize(gpa, .{ .from = .{ .v6 = lo }, .to = .{ .v6 = hi } });
        defer gpa.free(p6);
        e("  v6 worst case ::1 - ffff..fffe        -> {d} prefixes ({d} bytes)\n", .{ p6.len, p6.len * @sizeOf(na.Prefix) });
        e("  sizeOf(Prefix) = {d}\n", .{@sizeOf(na.Prefix)});
    }

    e("== hand-constructed out-of-range Prefix (bits > width) ==\n", .{});
    {
        const p: na.Prefix = .{ .addr = .{ .v4 = .{ 192, 0, 2, 1 } }, .bits = 200 };
        var pb: [na.max_prefix_text_len]u8 = undefined;
        e("  formatPrefix  = '{s}'\n", .{na.formatPrefix(p, &pb)});
        e("  masked        = '{s}'\n", .{na.formatPrefix(p.masked(), &pb)});
        e("  hostCount     = {d}\n", .{p.hostCount()});
        e("  contains self = {}\n", .{p.contains(.{ .v4 = .{ 192, 0, 2, 1 } })});
        e("  isSingleIp    = {}\n", .{p.isSingleIp()});
        e("  broadcast     = {}\n", .{p.broadcast() != null});
        const r = p.range();
        e("  range ok      = {}\n", .{r.from.eql(r.to)});
        e("  reparse of formatPrefix output = {}\n", .{na.parsePrefix(na.formatPrefix(p, &pb)) != null});
    }

    e("== v4-mapped comparison semantics (the allow-list question) ==\n", .{});
    {
        const v4 = na.parseIp("1.2.3.4").?;
        const m = na.parseIp("::ffff:1.2.3.4").?;
        e("  Ip.eql(1.2.3.4, ::ffff:1.2.3.4)          = {}\n", .{v4.eql(m)});
        e("  Ip.eql(unmap, unmap)                     = {}\n", .{v4.unmap().eql(m.unmap())});
        const p = na.parsePrefix("1.2.3.0/24").?;
        e("  Prefix(1.2.3.0/24).contains(::ffff:1.2.3.4) = {}\n", .{p.contains(m)});
        e("  ... .contains(unmap)                     = {}\n", .{p.contains(m.unmap())});
        const p6 = na.parsePrefix("::ffff:0:0/96").?;
        e("  Prefix(::ffff:0:0/96).contains(1.2.3.4)  = {}\n", .{p6.contains(v4)});
    }
    flush();
}
