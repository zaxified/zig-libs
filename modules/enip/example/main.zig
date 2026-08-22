// SPDX-License-Identifier: MIT

//! What an EtherNet/IP client does with `enip`: register a session with a
//! target, write a tag, read it back, and batch three tag reads into one
//! Multiple Service Packet exchange — driven here against the module's own
//! `Adapter` over an in-memory transport (no socket), the same pairing the
//! module's README calls out as doubling for fleet simulation. Also shows
//! the named failure a request for a tag that does not exist gets back.
//!
//! Built by `zig build check-examples` against the PUBLISHED module — no
//! access to anything `enip` (or its declared dep `netaddr`) does not
//! export.

const std = @import("std");
const enip = @import("enip");

/// Hands every message the client writes straight to an `Adapter` and
/// queues its reply — a full CIP round trip as ordinary synchronous code,
/// no socket, no thread. Built entirely from `enip.Transport`'s public
/// vtable seam.
const PairedTransport = struct {
    target: *enip.Adapter,
    out: [4096]u8 = undefined,
    queue: [8192]u8 = undefined,
    queue_len: usize = 0,
    queue_pos: usize = 0,

    fn seam(self: *PairedTransport) enip.Transport {
        return .{ .ctx = self, .vtable = &.{ .read = readFn, .write = writeFn } };
    }

    fn readFn(ctx: *anyopaque, buf: []u8) enip.TransportError!usize {
        const self: *PairedTransport = @ptrCast(@alignCast(ctx));
        const avail = self.queue_len - self.queue_pos;
        if (avail == 0) return 0;
        const n = @min(avail, buf.len);
        @memcpy(buf[0..n], self.queue[self.queue_pos..][0..n]);
        self.queue_pos += n;
        return n;
    }

    fn writeFn(ctx: *anyopaque, bytes: []const u8) enip.TransportError!void {
        const self: *PairedTransport = @ptrCast(@alignCast(ctx));
        const reply = self.target.handle(bytes, &self.out) catch return error.WriteFailed;
        const r = reply orelse return;
        @memcpy(self.queue[self.queue_len..][0..r.len], r);
        self.queue_len += r.len;
    }
};

pub fn main() !void {
    // A target with three tags: an INT array, a DINT, and a REAL.
    var scada: [200]u8 = @splat(0);
    var count: [40]u8 = @splat(0);
    var setpoint: [20]u8 = @splat(0);
    var tags = [_]enip.TagBinding{
        .{ .name = "SCADA", .type = .int, .bytes = &scada },
        .{ .name = "Count", .type = .dint, .bytes = &count },
        .{ .name = "Setpoint", .type = .real, .bytes = &setpoint },
    };
    var target = enip.Adapter.init(.{}, &tags);
    var paired = PairedTransport{ .target = &target };

    var buf: [4096]u8 = undefined;
    // The adapter is a leaf device — it does not route — so the client
    // sends bare CIP rather than wrapping every request in Unconnected_Send.
    var client = try enip.Client.init(paired.seam(), &buf, .{ .routing = .direct });

    const handle = try client.registerSession();
    std.debug.print("session registered: 0x{x:0>8}\n", .{handle});

    const ident = try client.listIdentity();
    std.debug.print("target identity: \"{s}\" serial=0x{x:0>8}\n", .{ ident.product_name, ident.serial_number });

    // Write element 5 of SCADA, then read it back.
    var value: [2]u8 = undefined;
    std.mem.writeInt(i16, &value, -42, .little);
    try client.writeTag("SCADA[5]", .int, 1, &value);
    const back = try client.readTag("SCADA[5]", 1);
    std.debug.print("SCADA[5] round-trip: {d}\n", .{(try back.at(0)).asInt().?});

    // Batch three tags into one Multiple Service Packet — one exchange
    // instead of three, the way a real SCADA poll cycle would.
    const names = [_][]const u8{ "SCADA[0]", "Count", "NoSuchTag" };
    var results: [3]?enip.TagData = undefined;
    const n = try client.readTags(&names, &results);
    std.debug.print("batched read: {d}/{d} embedded replies present\n", .{ n, names.len });

    // A tag that does not exist fails by name at the CIP layer rather than
    // returning zeroed or stale data — the batch above already showed this
    // as a `null` slot; here it is the direct single-tag form.
    if (client.readTag("NoSuchTag", 1)) |_| {
        std.debug.print("unexpectedly read a nonexistent tag\n", .{});
    } else |err| switch (err) {
        error.CipError => std.debug.print("unknown tag correctly refused (CipError)\n", .{}),
        else => return err,
    }

    try client.unregisterSession();
}
