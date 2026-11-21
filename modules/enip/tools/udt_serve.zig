// SPDX-License-Identifier: MIT
//! Live-oracle peer for the Template Object (CONVENTIONS §9, kept instrument:
//! a differential oracle driving a foreign implementation through the wire).
//! Serves an `Adapter` with two user-defined types on a loopback TCP port so
//! a stock `pycomm3.LogixDriver` can browse them (`tools/udt_oracle.py`).
//!
//!     zig build-exe -OReleaseSafe --dep enip -Mroot=modules/enip/tools/udt_serve.zig \
//!         --dep netaddr -Menip=modules/enip/src/root.zig -Mnetaddr=modules/netaddr/src/root.zig \
//!         -femit-bin=.zig-cache/udt_serve
//!     .zig-cache/udt_serve 44818          # then: python3 modules/enip/tools/udt_oracle.py 127.0.0.1:44818
//!
//! A test peer, never run by the build.
const std = @import("std");
const enip = @import("enip");

var motor_bytes: [12]u8 = .{ 0x00, 0x00, 0xC0, 0x3F, 0x2A, 0x00, 0x00, 0x00, 1, 2, 3, 4 }; // Speed 1.5, Count 42, Flags 1..4
var site_bytes: [16]u8 = .{ 0x00, 0x00, 0x80, 0x40, 7, 0, 0, 0, 0, 0, 0, 0, 0x64, 0, 0, 0 }; // P1.Speed 4.0, P1.Count 7, Total 100

const pump_members = [_]enip.adapter.UdtMember{
    .{ .name = "Speed", .type = .real, .offset = 0 },
    .{ .name = "Count", .type = .dint, .offset = 4 },
    .{ .name = "Flags", .type = .sint, .array_len = 4, .offset = 8 },
};
const pump: enip.adapter.Udt = .{ .id = 1, .name = "Pump", .handle = 0x1234, .size = 12, .members = &pump_members };
const plant_members = [_]enip.adapter.UdtMember{
    .{ .name = "P1", .type = .structure, .udt = &pump, .offset = 0 },
    .{ .name = "Total", .type = .dint, .offset = 12 },
};
const plant: enip.adapter.Udt = .{ .id = 2, .name = "Plant", .handle = 0x4321, .size = 16, .members = &plant_members };
const udts = [_]enip.adapter.Udt{ pump, plant };

pub fn main(init: std.process.Init) !void {
    const io = init.io;
    var args = init.minimal.args.iterate();
    _ = args.next();
    const port = std.fmt.parseInt(u16, args.next() orelse "44818", 10) catch 44818;
    const addr: std.Io.net.IpAddress = .{ .ip4 = .loopback(port) };
    var server = try addr.listen(io, .{ .reuse_address = true });
    defer server.deinit(io);

    var scalar: [4]u8 = .{ 9, 0, 0, 0 };
    const tags = [_]enip.TagBinding{
        .{ .name = "Count", .type = .dint, .bytes = &scalar },
        .{ .name = "Motor", .type = .structure, .bytes = &motor_bytes, .udt = &pump },
        .{ .name = "Site", .type = .structure, .bytes = &site_bytes, .udt = &plant },
    };
    var adapter = enip.Adapter.init(.{ .udts = &udts }, &tags);
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
