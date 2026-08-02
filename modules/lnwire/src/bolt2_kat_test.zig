// SPDX-License-Identifier: MIT
//! BOLT#2 channel management, anchored on rust-lightning's frozen encoder
//! output. See `bolt2_channel_management_kat_vectors.zig` for provenance.
//!
//! The check is deliberately round-trip-through-foreign-bytes: decode the
//! vector's wire bytes, re-serialize, and require byte equality. Our codec
//! was written from BOLT#2 independently of rust-lightning, so agreement on
//! these bytes is evidence from outside — and it is what makes the vectors
//! themselves trustworthy, since a fabricated hex string would not survive
//! being parsed and rebuilt by an unrelated implementation.

const std = @import("std");
const testing = std.testing;
const bolt2 = @import("bolt2.zig");
const vectors = @import("bolt2_channel_management_kat_vectors.zig");

fn framed(a: std.mem.Allocator, msg_type: u16, payload_hex: []const u8) ![]u8 {
    const out = try a.alloc(u8, 2 + payload_hex.len / 2);
    std.mem.writeInt(u16, out[0..2], msg_type, .big);
    _ = try std.fmt.hexToBytes(out[2..], payload_hex);
    return out;
}

/// Decode `payload_hex` (type-prefixed with `msg_type`) with `decodeFn`,
/// re-serialize with `serializeFn`, and require the bytes come back
/// identical to what rust-lightning emitted.
fn checkA(
    comptime decodeFn: anytype,
    comptime serializeFn: anytype,
    msg_type: u16,
    payload_hex: []const u8,
) !void {
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();
    const want = try framed(a, msg_type, payload_hex);
    const got = try serializeFn(a, try decodeFn(a, want));
    try testing.expectEqualSlices(u8, want, got);
}

fn checkN(
    comptime decodeFn: anytype,
    comptime serializeFn: anytype,
    msg_type: u16,
    payload_hex: []const u8,
) !void {
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();
    const want = try framed(a, msg_type, payload_hex);
    const got = try serializeFn(a, try decodeFn(want));
    try testing.expectEqualSlices(u8, want, got);
}

test "BOLT#2 anchor: open_channel, every upstream parameter combination" {
    for (vectors.open_channel_vectors) |v| {
        checkA(
            bolt2.decodeOpenChannel,
            bolt2.serializeOpenChannel,
            bolt2.OPEN_CHANNEL_TYPE,
            v.payload_hex,
        ) catch |e| {
            std.debug.print("open_channel vector failed: {s}\n", .{v.description});
            return e;
        };
    }
}

test "BOLT#2 anchor: accept_channel, every upstream parameter combination" {
    for (vectors.accept_channel_vectors) |v| {
        checkA(
            bolt2.decodeAcceptChannel,
            bolt2.serializeAcceptChannel,
            bolt2.ACCEPT_CHANNEL_TYPE,
            v.payload_hex,
        ) catch |e| {
            std.debug.print("accept_channel vector failed: {s}\n", .{v.description});
            return e;
        };
    }
}

test "BOLT#2 anchor: funding_created / funding_signed / channel_ready" {
    try checkN(
        bolt2.decodeFundingCreated,
        bolt2.serializeFundingCreated,
        bolt2.FUNDING_CREATED_TYPE,
        vectors.funding_created_vector.payload_hex,
    );
    try checkN(
        bolt2.decodeFundingSigned,
        bolt2.serializeFundingSigned,
        bolt2.FUNDING_SIGNED_TYPE,
        vectors.funding_signed_vector.payload_hex,
    );
    try checkA(
        bolt2.decodeChannelReady,
        bolt2.serializeChannelReady,
        bolt2.CHANNEL_READY_TYPE,
        vectors.channel_ready_vector.payload_hex,
    );
}

test "BOLT#2 anchor: shutdown and closing_signed, every upstream combination" {
    for (vectors.shutdown_vectors) |v| {
        checkN(
            bolt2.decodeShutdown,
            bolt2.serializeShutdown,
            bolt2.SHUTDOWN_TYPE,
            v.payload_hex,
        ) catch |e| {
            std.debug.print("shutdown vector failed: {s}\n", .{v.description});
            return e;
        };
    }
    for (vectors.closing_signed_vectors) |v| {
        checkA(
            bolt2.decodeClosingSigned,
            bolt2.serializeClosingSigned,
            bolt2.CLOSING_SIGNED_TYPE,
            v.payload_hex,
        ) catch |e| {
            std.debug.print("closing_signed vector failed: {s}\n", .{v.description});
            return e;
        };
    }
}

test "BOLT#2 anchor: HTLC update messages and commitment_signed" {
    try checkA(
        bolt2.decodeUpdateAddHtlc,
        bolt2.serializeUpdateAddHtlc,
        bolt2.UPDATE_ADD_HTLC_TYPE,
        vectors.update_add_htlc_vector.payload_hex,
    );
    try checkA(
        bolt2.decodeUpdateFulfillHtlc,
        bolt2.serializeUpdateFulfillHtlc,
        bolt2.UPDATE_FULFILL_HTLC_TYPE,
        vectors.update_fulfill_htlc_vector.payload_hex,
    );
    try checkA(
        bolt2.decodeUpdateFailHtlc,
        bolt2.serializeUpdateFailHtlc,
        bolt2.UPDATE_FAIL_HTLC_TYPE,
        vectors.update_fail_htlc_vector.payload_hex,
    );
    for (vectors.commitment_signed_vectors) |v| {
        try checkA(
            bolt2.decodeCommitmentSigned,
            bolt2.serializeCommitmentSigned,
            bolt2.COMMITMENT_SIGNED_TYPE,
            v.payload_hex,
        );
    }
}

test "BOLT#2 anchor: revoke_and_ack and update_fee" {
    try checkN(
        bolt2.decodeRevokeAndAck,
        bolt2.serializeRevokeAndAck,
        bolt2.REVOKE_AND_ACK_TYPE,
        vectors.revoke_and_ack_vector.payload_hex,
    );
    try checkN(
        bolt2.decodeUpdateFee,
        bolt2.serializeUpdateFee,
        bolt2.UPDATE_FEE_TYPE,
        vectors.update_fee_vector.payload_hex,
    );
}
