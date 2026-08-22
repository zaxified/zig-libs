// SPDX-License-Identifier: MIT

//! What an S7 driver does with `s7comm`: connect to a PLC (here, an
//! in-process `Responder` standing in for one), write a value by STEP 7
//! address notation, read it back, and read the CPU status via SZL — the
//! same calls a real driver makes over a TCP socket.
//!
//! This is an example in the gate sense — it is built by
//! `zig build check-examples` against the PUBLISHED module (`deps` only, no
//! `test_deps`, no access to anything the module does not export). If a type
//! needed to call the API is not public, or an error cannot be named from
//! outside, this file stops compiling. The module's own tests cannot notice
//! either, because they live inside it.

const std = @import("std");
const s7comm = @import("s7comm");

/// Ties every client write straight to the responder and queues its reply,
/// so a full request/response round trip is ordinary synchronous code —
/// built entirely from the public `Transport`/`TransportError`/`Responder`
/// surface (no private helper reused from the module's own tests).
const PairedTransport = struct {
    responder: *s7comm.Responder,
    out: [4096]u8 = undefined,
    queue: [8192]u8 = undefined,
    queue_len: usize = 0,
    queue_pos: usize = 0,

    fn seam(self: *PairedTransport) s7comm.Transport {
        return .{ .ctx = self, .vtable = &.{ .read = readFn, .write = writeFn } };
    }

    fn readFn(ctx: *anyopaque, buf: []u8) s7comm.TransportError!usize {
        const self: *PairedTransport = @ptrCast(@alignCast(ctx));
        const avail = self.queue_len - self.queue_pos;
        if (avail == 0) return 0;
        const n = @min(avail, buf.len);
        @memcpy(buf[0..n], self.queue[self.queue_pos..][0..n]);
        self.queue_pos += n;
        return n;
    }

    fn writeFn(ctx: *anyopaque, bytes: []const u8) s7comm.TransportError!void {
        const self: *PairedTransport = @ptrCast(@alignCast(ctx));
        const reply = self.responder.handle(bytes, &self.out) catch return;
        const r = reply orelse return;
        if (self.queue_len + r.len > self.queue.len) return error.WriteFailed;
        @memcpy(self.queue[self.queue_len..][0..r.len], r);
        self.queue_len += r.len;
    }
};

pub fn main() !void {
    var db1: [256]u8 = @splat(0);
    var areas = [_]s7comm.AreaBinding{.{ .area = .db, .db_number = 1, .bytes = &db1 }};
    var responder = s7comm.Responder.init(.{}, &areas);
    var paired = PairedTransport{ .responder = &responder };

    var buf: [1024]u8 = undefined;
    var client = try s7comm.Client.init(paired.seam(), &buf, .{
        .remote_tsap = s7comm.Tsap.rackSlot(.pg, 0, 2),
    });
    try client.connect();
    std.debug.print("connected, negotiated PDU length: {d}\n", .{client.pduLength()});

    // Write a word by STEP 7 notation, then read it back.
    try client.writeAddress("DB1.DBW20", 2, &[_]u8{ 0x12, 0x34, 0x56, 0x78 });
    var out: [4]u8 = undefined;
    const read_back = try client.readAddress("DB1.DBW20", 2, &out);
    std.debug.print("DB1.DBW20 read back: {x}\n", .{std.fmt.bytesToHex(read_back[0..4].*, .lower)});

    // CPU status via Read SZL.
    const status = try client.cpuStatus();
    std.debug.print("CPU status: {t}\n", .{status});

    // A malformed STEP 7 address string must be a nameable error, not a
    // panic — a driver loading addresses from a config file needs this.
    if (s7comm.parseAddress("NOTREAL1.2")) |_| {
        unreachable;
    } else |err| switch (err) {
        error.UnknownArea => std.debug.print("unknown area mnemonic correctly rejected\n", .{}),
        else => return err,
    }

    // A well-formed address pointing at an unregistered DB must fail with a
    // nameable per-item error, not silently read garbage.
    if (client.readAddress("DB99.DBB0", 1, out[0..1])) |_| {
        unreachable;
    } else |err| switch (err) {
        error.ItemError => std.debug.print("unregistered DB correctly rejected\n", .{}),
        else => return err,
    }

    client.disconnect();
    std.debug.print("disconnected, responder saw the disconnect: {}\n", .{!responder.connected});
}
