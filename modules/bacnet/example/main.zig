// SPDX-License-Identifier: MIT

//! What a BACnet/IP supervisory controller does with `bacnet`: stand up a
//! device with one Analog Value object, drive a `Client` through a real
//! ReadProperty round trip against it, decode the answer, and see the
//! device's typed refusal when a property it does not have is requested —
//! all over `LoopTransport`, the module's own in-memory `Transport`, so no
//! real socket is ever opened. This is the same seam `writebehind`'s example
//! uses for its WAL storage, applied to a datagram link instead of a file.
//!
//! This is an example in the gate sense — it is built by
//! `zig build check-examples` against the PUBLISHED module (`deps` only —
//! `netaddr`, `websocket` — no `test_deps`, no access to anything the
//! module does not export). If a type needed to call the API is not
//! public, or an error cannot be named from outside, this file stops
//! compiling.

const std = @import("std");
const bacnet = @import("bacnet");

pub fn main() !void {
    // ── wire a device and a client onto one in-memory network ───────────
    var net: bacnet.transport.LoopNetwork = .{};
    var dev_ep: bacnet.transport.LoopTransport = .init(.{ .ip = .{ 192, 0, 2, 10 } });
    var cli_ep: bacnet.transport.LoopTransport = .init(.{ .ip = .{ 192, 0, 2, 20 } });
    net.attach(&dev_ep);
    net.attach(&cli_ep);

    var zone_temp_props = [_]bacnet.device.Property{
        .{ .id = .present_value, .value = .{ .real = 21.5 }, .writable = true },
        .{ .id = .object_name, .value = .{ .string = "Zone Temp 1" }, .writable = false },
    };
    var objects = [_]bacnet.device.Object{
        .{ .id = .{ .type = .analog_value, .instance = 1 }, .properties = &zone_temp_props },
    };
    var device: bacnet.Device = .init(dev_ep.transport(), .{ .instance = 1001 }, &objects);
    var client: bacnet.Client = .init(cli_ep.transport(), .{});

    const dev_addr = dev_ep.address;
    const target: bacnet.ObjectId = .{ .type = .analog_value, .instance = 1 };

    // ── a real ReadProperty round trip ───────────────────────────────────
    var now_ms: u64 = 0;
    const invoke_id = try client.readProperty(dev_addr, target, .present_value, null, now_ms);

    // Pump both sides until the client sees the answer: the device consumes
    // the request off the wire and replies, then the client consumes the
    // reply. A real caller drives this from its own event loop's poll tick.
    _ = try device.poll(now_ms);
    now_ms += 1;
    const answer = try client.poll(now_ms);
    // `Event`'s slice-carrying variants borrow the client's own receive
    // buffer and are invalidated by the next `poll` — copy the ack bytes out
    // before driving any further traffic.
    var ack_buf: [bacnet.transport.max_datagram]u8 = undefined;
    var ack_len: usize = 0;
    switch (answer) {
        .complex_ack => |ca| {
            std.debug.assert(ca.invoke_id == invoke_id);
            ack_len = ca.data.len;
            @memcpy(ack_buf[0..ack_len], ca.data);
            const ack = try bacnet.service.ReadPropertyAck.decode(ack_buf[0..ack_len]);
            const value = try ack.scalar();
            std.debug.print("present_value = {d}\n", .{value.real});
        },
        else => return error.UnexpectedEvent,
    }

    // ── a property the object does not have: a typed refusal, not a hang ─
    now_ms += 1;
    const bad_invoke = try client.readProperty(dev_addr, target, .description, null, now_ms);
    _ = try device.poll(now_ms);
    now_ms += 1;
    const refusal = try client.poll(now_ms);
    switch (refusal) {
        .err => |e| {
            std.debug.assert(e.invoke_id == bad_invoke);
            std.debug.print("read 'description' refused: class={s} code={s}\n", .{ @tagName(e.class), @tagName(e.code) });
        },
        else => return error.UnexpectedEvent,
    }

    // ── a ComplexACK payload truncated mid-value is rejected by name ─────
    // (the good ack copied above, minus its last byte).
    _ = bacnet.service.ReadPropertyAck.decode(ack_buf[0 .. ack_len - 1]) catch |err| switch (err) {
        error.Truncated => std.debug.print("truncated ReadProperty-ACK correctly rejected\n", .{}),
        else => return err,
    };
}
