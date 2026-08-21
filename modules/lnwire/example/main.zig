// SPDX-License-Identifier: MIT

//! What a Lightning node's peer-connection handler does with `lnwire`:
//! serialize an outgoing `update_add_htlc` (forward a payment to the next
//! hop), parse it back the way the peer on the other end of the wire would,
//! then serialize the `update_fulfill_htlc` that settles it once the
//! preimage is known. Also shows a decoder correctly refusing a frame whose
//! type byte does not match — a peer that sends the wrong message type is
//! routine, not exceptional, on a real wire.
//!
//! This is an example in the gate sense — it is built by
//! `zig build check-examples` against the PUBLISHED module (`deps` only, no
//! `test_deps`, no access to anything the module does not export). If a type
//! needed to call the API is not public, or an error cannot be named from
//! outside, this file stops compiling. The module's own tests cannot notice
//! either, because they live inside it.

const std = @import("std");
const lnwire = @import("lnwire");

pub fn main() !void {
    var da: std.heap.DebugAllocator(.{}) = .init;
    defer if (da.deinit() == .leak) @panic("leak");
    const gpa = da.allocator();

    const preimage = [_]u8{0x42} ** 32;
    var payment_hash: [32]u8 = undefined;
    std.crypto.hash.sha2.Sha256.hash(&preimage, &payment_hash, .{});

    const add: lnwire.UpdateAddHtlc = .{
        .channel_id = [_]u8{0xAA} ** 32,
        .id = 7,
        .amount_msat = 150_000,
        .payment_hash = payment_hash,
        .cltv_expiry = 800_000,
        .onion_routing_packet = [_]u8{0} ** lnwire.bolt2.ONION_ROUTING_PACKET_LEN,
    };

    const wire_add = try lnwire.serializeUpdateAddHtlc(gpa, add);
    defer gpa.free(wire_add);
    std.debug.print("serialized update_add_htlc: {d} bytes\n", .{wire_add.len});

    var decoded_add = try lnwire.decodeUpdateAddHtlc(gpa, wire_add);
    defer decoded_add.deinit(gpa);
    std.debug.print("decoded htlc id={d} amount_msat={d} cltv_expiry={d}\n", .{ decoded_add.id, decoded_add.amount_msat, decoded_add.cltv_expiry });

    // The receiving hop settles by revealing the preimage.
    const fulfill: lnwire.UpdateFulfillHtlc = .{
        .channel_id = decoded_add.channel_id,
        .id = decoded_add.id,
        .payment_preimage = preimage,
    };
    const wire_fulfill = try lnwire.serializeUpdateFulfillHtlc(gpa, fulfill);
    defer gpa.free(wire_fulfill);

    var decoded_fulfill = try lnwire.decodeUpdateFulfillHtlc(gpa, wire_fulfill);
    defer decoded_fulfill.deinit(gpa);

    // The settling peer must be able to check the revealed preimage
    // actually hashes to the HTLC's committed payment_hash.
    var check: [32]u8 = undefined;
    std.crypto.hash.sha2.Sha256.hash(&decoded_fulfill.payment_preimage, &check, .{});
    std.debug.print("preimage validates against payment_hash: {}\n", .{std.mem.eql(u8, &check, &decoded_add.payment_hash)});

    // A frame with the wrong leading type must be rejected by name, not
    // silently misparsed — a peer sending `ping` where `update_add_htlc`
    // was expected is a routine wire event, not a crash.
    const ping_wire = try lnwire.serializePing(gpa, .{ .num_pong_bytes = 0, .ignored = &.{} });
    defer gpa.free(ping_wire);
    _ = lnwire.decodeUpdateAddHtlc(gpa, ping_wire) catch |err| switch (err) {
        error.WrongType => std.debug.print("mistyped frame correctly rejected: WrongType\n", .{}),
        else => return err,
    };
}
