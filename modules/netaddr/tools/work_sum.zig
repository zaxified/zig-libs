const std = @import("std");
const na = @import("netaddr.zig");

var outbuf: [1 << 24]u8 = undefined;
var outlen: usize = 0;
var input: [1 << 24]u8 = undefined;
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
    if (outlen + 4096 > outbuf.len) flush();
    const s = std.fmt.bufPrint(outbuf[outlen..], fmt, args) catch return;
    outlen += s.len;
}

fn ipFromHex(h: []const u8) ?na.Ip {
    if (h.len == 8) {
        var q: [4]u8 = undefined;
        _ = std.fmt.hexToBytes(&q, h) catch return null;
        return .{ .v4 = q };
    } else if (h.len == 32) {
        var b: [16]u8 = undefined;
        _ = std.fmt.hexToBytes(&b, h) catch return null;
        return .{ .v6 = b };
    }
    return null;
}

pub fn main() !void {
    var da: std.heap.DebugAllocator(.{}) = .init;
    defer if (da.deinit() == .leak) @panic("LEAK");
    const gpa = da.allocator();

    var ilen: usize = 0;
    while (true) {
        const n = std.os.linux.read(0, input[ilen..].ptr, input.len - ilen);
        if (std.os.linux.errno(n) != .SUCCESS or n == 0) break;
        ilen += n;
        if (ilen == input.len) break;
    }
    var lines = std.mem.splitScalar(u8, input[0..ilen], '\n');
    const mode = lines.next() orelse return;

    var maxlen: usize = 0;
    var maxdesc: [512]u8 = undefined;
    var maxdesc_len: usize = 0;

    while (lines.next()) |line| {
        if (line.len == 0) continue;
        if (std.mem.eql(u8, mode, "sum")) {
            var f = std.mem.splitScalar(u8, line, ' ');
            const a = ipFromHex(f.next() orelse continue) orelse {
                emit("ERR\n", .{});
                continue;
            };
            const b = ipFromHex(f.next() orelse continue) orelse {
                emit("ERR\n", .{});
                continue;
            };
            const ps = na.summarize(gpa, .{ .from = a, .to = b }) catch |e| {
                emit("E:{s}\n", .{@errorName(e)});
                continue;
            };
            defer gpa.free(ps);
            if (ps.len > maxlen) {
                maxlen = ps.len;
                maxdesc_len = (std.fmt.bufPrint(&maxdesc, "{s}", .{line}) catch @as([]u8, &.{})).len;
            }
            var pbuf: [na.max_prefix_text_len]u8 = undefined;
            for (ps, 0..) |p, k| {
                if (k != 0) emit(",", .{});
                emit("{s}", .{na.formatPrefix(p, &pbuf)});
            }
            emit("\n", .{});
        } else if (std.mem.eql(u8, mode, "merge")) {
            // line: comma-separated CIDR texts
            var list: std.ArrayList(na.Prefix) = .empty;
            defer list.deinit(gpa);
            var f = std.mem.splitScalar(u8, line, ',');
            var bad = false;
            while (f.next()) |t| {
                if (t.len == 0) continue;
                const p = na.parsePrefix(t) orelse {
                    bad = true;
                    break;
                };
                try list.append(gpa, p);
            }
            if (bad) {
                emit("ERR\n", .{});
                continue;
            }
            const ps = try na.mergePrefixes(gpa, list.items);
            defer gpa.free(ps);
            if (ps.len > maxlen) {
                maxlen = ps.len;
                maxdesc_len = (std.fmt.bufPrint(&maxdesc, "{s}", .{line[0..@min(line.len, 400)]}) catch @as([]u8, &.{})).len;
            }
            var pbuf: [na.max_prefix_text_len]u8 = undefined;
            for (ps, 0..) |p, k| {
                if (k != 0) emit(",", .{});
                emit("{s}", .{na.formatPrefix(p, &pbuf)});
            }
            emit("\n", .{});
        }
    }
    emit("MAXLEN {d} FROM {s}\n", .{ maxlen, maxdesc[0..maxdesc_len] });
    flush();
}
