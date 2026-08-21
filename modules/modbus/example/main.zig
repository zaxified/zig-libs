// SPDX-License-Identifier: MIT

//! What a SCADA master does with `modbus`: drive a `Client` against a real
//! slave over Modbus TCP framing, read holding registers, write one back,
//! and handle an out-of-range address as the typed exception it is — never
//! a crash. The "wire" here is an in-process loopback straight into
//! `modbus.server.Server`, the module's own slave responder, so the whole
//! request/response round-trip (encode, frame, respond, decode) runs for
//! real without a socket.
//!
//! This is an example in the gate sense — it is built by
//! `zig build check-examples` against the PUBLISHED module (`deps` only, no
//! `test_deps`, no access to anything the module does not export). If a type
//! needed to call the API is not public, or an error cannot be named from
//! outside, this file stops compiling. The module's own tests cannot notice
//! either, because they live inside it.

const std = @import("std");
const modbus = @import("modbus");

/// Wires `modbus.Transport` straight into a `modbus.server.Server` — no
/// socket, but a real ADU round-trip (TCP framing, PDU dispatch, exception
/// mapping) exactly as a networked slave would produce.
fn loopbackExchange(ctx: *anyopaque, request: []const u8, reply_buf: []u8) modbus.TransportError!usize {
    const srv: *modbus.server.Server = @ptrCast(@alignCast(ctx));
    const reply = srv.handleAdu(request, reply_buf) catch return error.TransportFailed;
    const r = reply orelse return error.TransportFailed; // no silent-broadcast case in this example
    return r.len;
}

pub fn main() !void {
    // modbus is allocation-free end to end: no allocator anywhere in the API.
    var holding_regs = [_]u16{ 100, 200, 300, 400 };
    const db: modbus.server.DataBank = .{
        .holding_registers = .{ .base = 0, .values = &holding_regs },
    };
    var server: modbus.server.Server = .init(.{ .unit_id = 1, .framing = .tcp }, db);

    const transport: modbus.Transport = .{ .ctx = &server, .exchangeFn = loopbackExchange };
    var client: modbus.Client = .init(.tcp, transport);

    // Read the four holding registers back.
    var out: [4]u16 = undefined;
    try client.readHoldingRegisters(1, 0, &out);
    std.debug.print("read holding registers: {any}\n", .{out});

    // Write one register, then confirm it stuck.
    try client.writeSingleRegister(1, 2, 999);
    var readback: [1]u16 = undefined;
    try client.readHoldingRegisters(1, 2, &readback);
    std.debug.print("register[2] after write: {d}\n", .{readback[0]});

    // An address outside the configured window comes back as a typed
    // exception, not a crash — the error has to be nameable from outside.
    var oob: [1]u16 = undefined;
    client.readHoldingRegisters(1, 100, &oob) catch |err| switch (err) {
        error.IllegalDataAddress => std.debug.print("out-of-range read correctly rejected\n", .{}),
        else => return err,
    };
}
