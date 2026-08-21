// SPDX-License-Identifier: MIT

//! What a consumer decoding link-local IS-IS traffic does with `isis`: build
//! a LAN Hello PDU with a small set of TLVs the way a router would emit one,
//! dispatch it back through the top-level `decode()`, and walk its TLVs to
//! recover the neighbour's area and hostname. Then feed a truncated buffer
//! through the same decoder to show the untrusted-decode guarantee: a lying
//! length is a typed error, never an out-of-bounds read.
//!
//! This is an example in the gate sense — it is built by
//! `zig build check-examples` against the PUBLISHED module (`deps` only, no
//! `test_deps`, no access to anything the module does not export). If a type
//! needed to call the API is not public, or an error cannot be named from
//! outside, this file stops compiling. The module's own tests cannot notice
//! either, because they live inside it.

const std = @import("std");
const isis = @import("isis");

pub fn main() !void {
    // isis is zero-copy, zero-allocation: no allocator anywhere in the API.
    var buf: [256]u8 = undefined;
    var b = try isis.pdu.LanHelloBuilder.init(&buf, .{
        .is_l2 = true,
        .source_id = .{ 0x00, 0x1a, 0x2b, 0x3c, 0x4d, 0x5e },
        .holding_time = 30,
        .lan_id = .{ 0x00, 0x1a, 0x2b, 0x3c, 0x4d, 0x5e, 0x00 },
    });
    try isis.tlvs.addAreaAddresses(&b.tlvs, &.{&.{ 0x49, 0x00, 0x01 }});
    try isis.tlvs.addProtocolsSupported(&b.tlvs, &.{isis.tlvs.nlpid_ipv4});
    try isis.tlvs.addHostname(&b.tlvs, "core-switch-1");
    const wire = b.finish();
    std.debug.print("built LAN Hello: {d} bytes\n", .{wire.len});

    // A real consumer would have received `wire` off the wire; dispatch it
    // through the top-level decoder the way an unknown-type-tolerant
    // listener does.
    const decoded = try isis.decode(wire);
    switch (decoded) {
        .lan_hello => |hello| {
            std.debug.print("LAN Hello from {x:0>2}{x:0>2}{x:0>2}{x:0>2}{x:0>2}{x:0>2}, holding_time={d}s\n", .{
                hello.source_id[0], hello.source_id[1], hello.source_id[2],
                hello.source_id[3], hello.source_id[4], hello.source_id[5],
                hello.holding_time,
            });

            var it = hello.tlvIterator();
            while (try it.next()) |t| {
                switch (t.code) {
                    isis.tlvs.code.area_addresses => {
                        var areas = isis.tlvs.AreaAddressIterator.init(t.value);
                        while (try areas.next()) |area| {
                            std.debug.print("  area address: {x}\n", .{area});
                        }
                    },
                    isis.tlvs.code.dynamic_hostname => std.debug.print("  hostname: {s}\n", .{t.value}),
                    else => std.debug.print("  TLV code={d} len={d}\n", .{ t.code, t.value.len }),
                }
            }
        },
        else => return error.UnexpectedPduType,
    }

    // Untrusted input: chopping bytes off the end leaves the PDU Length
    // field claiming more than the buffer actually holds — the decoder
    // must reject this by name, not panic or over-read.
    const truncated = wire[0 .. wire.len - 3];
    _ = isis.decode(truncated) catch |err| switch (err) {
        error.BadPduLength => {
            std.debug.print("truncated PDU correctly rejected: PDU Length exceeds buffer\n", .{});
        },
        else => return err,
    };
}
