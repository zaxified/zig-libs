// SPDX-License-Identifier: MIT
//! Live-oracle peer for PCCC over CIP (CONVENTIONS §9, kept instrument: a
//! differential oracle driving a foreign implementation through the wire).
//! Serves an `Adapter` with an integer file N7, a float file F8 and a timer
//! file T4 on a loopback TCP port so a stock `pycomm3.SLCDriver` can read and
//! write them (`tools/pccc_oracle.py`).
//!
//!     zig build-exe -OReleaseSafe --dep enip -Mroot=modules/enip/tools/pccc_serve.zig \
//!         --dep netaddr -Menip=modules/enip/src/root.zig -Mnetaddr=modules/netaddr/src/root.zig \
//!         -femit-bin=.zig-cache/pccc_serve
//!     .zig-cache/pccc_serve 44818   # then: python3 modules/enip/tools/pccc_oracle.py 127.0.0.1:44818
//!
//! A test peer, never run by the build.
const std = @import("std");
const enip = @import("enip");

var n7: [40]u8 = blk: {
    var b: [40]u8 = @splat(0);
    std.mem.writeInt(i16, b[0..2], -7, .little);
    std.mem.writeInt(i16, b[2..4], 1234, .little);
    break :blk b;
};
var f8: [16]u8 = blk: {
    var b: [16]u8 = @splat(0);
    std.mem.writeInt(u32, b[0..4], @bitCast(@as(f32, 3.5)), .little);
    break :blk b;
};
// T4:0 -- control word with EN and DN set, preset 100, accumulator 42.
var t4: [12]u8 = .{ 0x00, 0xA0, 100, 0, 42, 0, 0, 0, 0, 0, 0, 0 };

pub fn main(init: std.process.Init) !void {
    const io = init.io;
    var args = init.minimal.args.iterate();
    _ = args.next();
    const port = std.fmt.parseInt(u16, args.next() orelse "44818", 10) catch 44818;
    const addr: std.Io.net.IpAddress = .{ .ip4 = .loopback(port) };
    var server = try addr.listen(io, .{ .reuse_address = true });
    defer server.deinit(io);

    const files = [_]enip.pccc.File{
        .{ .number = 7, .file_type = .integer, .data = &n7 },
        .{ .number = 8, .file_type = .float, .data = &f8 },
        .{ .number = 4, .file_type = .timer, .data = &t4 },
    };
    var adapter = enip.Adapter.init(.{ .pccc_files = &files, .pccc_processor = "1747-L552B " }, &.{});
    while (true) {
        const stream = server.accept(io) catch continue;
        var tt = enip.TcpTransport.fromStream(io, stream);
        defer tt.close();
        const t = tt.transport();
        var buf: [8192]u8 = undefined;
        var out: [8192]u8 = undefined;
        while (true) {
            const n = t.read(&buf) catch break;
            if (n == 0) continue;
            const reply = (adapter.handle(buf[0..n], &out) catch break) orelse break;
            t.write(reply) catch break;
        }
    }
}
