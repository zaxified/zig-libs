// SPDX-License-Identifier: MIT
//! BOLT#2 channel management, anchored on rust-lightning's frozen encoder
//! output. See `bolt2_channel_management_kat_vectors.zig` for provenance.
//!
//! Two independent checks run over the same vectors:
//!
//!  1. **round-trip through foreign bytes** — decode the vector's wire
//!     bytes, re-serialize, require byte equality. Our codec was written
//!     from BOLT#2 independently of rust-lightning, so agreement on these
//!     bytes is evidence from outside — and it is what makes the vectors
//!     themselves trustworthy, since a fabricated hex string would not
//!     survive being parsed and rebuilt by an unrelated implementation.
//!
//!  2. **field-by-field against the vendored breakdown** — the vectors also
//!     carry rust-lightning's own value for every field (`funding_satoshis`,
//!     `push_msat`, each basepoint, each TLV …), and the tests below assert
//!     the decoded struct against them.
//!
//! (2) exists because (1) alone is blind to a *consistent* misreading of
//! the layout: any transposition of two same-width adjacent fields applied
//! to both decode and encode re-emits identical bytes and passes. Consuming
//! only `payload_hex` from a corpus that ships the whole breakdown throws
//! away the half of the oracle that names which bytes are which field.

const std = @import("std");
const testing = std.testing;
const bolt2 = @import("bolt2.zig");
const message = @import("message.zig");
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

// ── field-by-field: the half of the corpus the round trip throws away ─────
//
// rust-lightning's `msgs.rs` tests build each `target_value` from a struct
// literal whose every field is spelled out; those values are vendored
// alongside `payload_hex`. Asserting them pins WHICH bytes are which field,
// which no round trip can: swapping two same-width adjacent fields in both
// `decode*` and `serialize*` re-emits the same bytes.

const Allocator = std.mem.Allocator;

fn expectHex(a: Allocator, want_hex: []const u8, got: []const u8) !void {
    const want = try a.alloc(u8, want_hex.len / 2);
    _ = try std.fmt.hexToBytes(want, want_hex);
    try testing.expectEqualSlices(u8, want, got);
}

/// The vector's value for an optional TLV: present ⇒ byte-equal, absent ⇒
/// the record must not be in the decoded extension either.
fn expectTlv(a: Allocator, ext: message.Extension, tlv_type: u64, want_hex: ?[]const u8) !void {
    const got = ext.find(tlv_type);
    if (want_hex) |h| {
        try expectHex(a, h, got orelse return error.ExpectedTlvRecordMissing);
    } else {
        try testing.expect(got == null);
    }
}

test "BOLT#2 field anchor: open_channel — every vendored field" {
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();
    for (vectors.open_channel_vectors) |v| {
        const m = try bolt2.decodeOpenChannel(a, try framed(a, bolt2.OPEN_CHANNEL_TYPE, v.payload_hex));
        errdefer std.debug.print("open_channel vector: {s}\n", .{v.description});
        try expectHex(a, v.chain_hash_hex, &m.chain_hash);
        try expectHex(a, v.temporary_channel_id_hex, &m.temporary_channel_id);
        try testing.expectEqual(v.funding_satoshis, m.funding_satoshis);
        try testing.expectEqual(v.push_msat, m.push_msat);
        try testing.expectEqual(v.dust_limit_satoshis, m.dust_limit_satoshis);
        try testing.expectEqual(v.max_htlc_value_in_flight_msat, m.max_htlc_value_in_flight_msat);
        try testing.expectEqual(v.channel_reserve_satoshis, m.channel_reserve_satoshis);
        try testing.expectEqual(v.htlc_minimum_msat, m.htlc_minimum_msat);
        try testing.expectEqual(v.feerate_per_kw, m.feerate_per_kw);
        try testing.expectEqual(v.to_self_delay, m.to_self_delay);
        try testing.expectEqual(v.max_accepted_htlcs, m.max_accepted_htlcs);
        try expectHex(a, v.funding_pubkey_hex, &m.funding_pubkey);
        try expectHex(a, v.revocation_basepoint_hex, &m.revocation_basepoint);
        try expectHex(a, v.payment_basepoint_hex, &m.payment_basepoint);
        try expectHex(a, v.delayed_payment_basepoint_hex, &m.delayed_payment_basepoint);
        try expectHex(a, v.htlc_basepoint_hex, &m.htlc_basepoint);
        try expectHex(a, v.first_per_commitment_point_hex, &m.first_per_commitment_point);
        try testing.expectEqual(v.channel_flags, m.channel_flags);
        try expectTlv(a, m.extension, 0, v.upfront_shutdown_script_hex);
        try expectTlv(a, m.extension, 1, v.channel_type_hex);
    }
}

test "BOLT#2 field anchor: accept_channel — every vendored field" {
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();
    for (vectors.accept_channel_vectors) |v| {
        const m = try bolt2.decodeAcceptChannel(a, try framed(a, bolt2.ACCEPT_CHANNEL_TYPE, v.payload_hex));
        errdefer std.debug.print("accept_channel vector: {s}\n", .{v.description});
        try expectHex(a, v.temporary_channel_id_hex, &m.temporary_channel_id);
        try testing.expectEqual(v.dust_limit_satoshis, m.dust_limit_satoshis);
        try testing.expectEqual(v.max_htlc_value_in_flight_msat, m.max_htlc_value_in_flight_msat);
        try testing.expectEqual(v.channel_reserve_satoshis, m.channel_reserve_satoshis);
        try testing.expectEqual(v.htlc_minimum_msat, m.htlc_minimum_msat);
        try testing.expectEqual(v.minimum_depth, m.minimum_depth);
        try testing.expectEqual(v.to_self_delay, m.to_self_delay);
        try testing.expectEqual(v.max_accepted_htlcs, m.max_accepted_htlcs);
        try expectHex(a, v.funding_pubkey_hex, &m.funding_pubkey);
        try expectHex(a, v.revocation_basepoint_hex, &m.revocation_basepoint);
        try expectHex(a, v.payment_basepoint_hex, &m.payment_basepoint);
        try expectHex(a, v.delayed_payment_basepoint_hex, &m.delayed_payment_basepoint);
        try expectHex(a, v.htlc_basepoint_hex, &m.htlc_basepoint);
        try expectHex(a, v.first_per_commitment_point_hex, &m.first_per_commitment_point);
        try expectTlv(a, m.extension, 0, v.upfront_shutdown_script_hex);
    }
}

test "BOLT#2 field anchor: funding_created / funding_signed / channel_ready" {
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();

    const fc = vectors.funding_created_vector;
    const m1 = try bolt2.decodeFundingCreated(try framed(a, bolt2.FUNDING_CREATED_TYPE, fc.payload_hex));
    try expectHex(a, fc.temporary_channel_id_hex, &m1.temporary_channel_id);
    try expectHex(a, fc.funding_txid_hex, &m1.funding_txid);
    try testing.expectEqual(fc.funding_output_index, m1.funding_output_index);
    try expectHex(a, fc.signature_hex, &m1.signature);

    const fs = vectors.funding_signed_vector;
    const m2 = try bolt2.decodeFundingSigned(try framed(a, bolt2.FUNDING_SIGNED_TYPE, fs.payload_hex));
    try expectHex(a, fs.channel_id_hex, &m2.channel_id);
    try expectHex(a, fs.signature_hex, &m2.signature);

    const cr = vectors.channel_ready_vector;
    const m3 = try bolt2.decodeChannelReady(a, try framed(a, bolt2.CHANNEL_READY_TYPE, cr.payload_hex));
    try expectHex(a, cr.channel_id_hex, &m3.channel_id);
    try expectHex(a, cr.second_per_commitment_point_hex, &m3.second_per_commitment_point);
}

test "BOLT#2 field anchor: shutdown and closing_signed" {
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();
    for (vectors.shutdown_vectors) |v| {
        const m = try bolt2.decodeShutdown(try framed(a, bolt2.SHUTDOWN_TYPE, v.payload_hex));
        errdefer std.debug.print("shutdown vector: {s}\n", .{v.description});
        try expectHex(a, v.channel_id_hex, &m.channel_id);
        try expectHex(a, v.scriptpubkey_hex, m.scriptpubkey);
    }
    for (vectors.closing_signed_vectors) |v| {
        const m = try bolt2.decodeClosingSigned(a, try framed(a, bolt2.CLOSING_SIGNED_TYPE, v.payload_hex));
        errdefer std.debug.print("closing_signed vector: {s}\n", .{v.description});
        try expectHex(a, v.channel_id_hex, &m.channel_id);
        try testing.expectEqual(v.fee_satoshis, m.fee_satoshis);
        try expectHex(a, v.signature_hex, &m.signature);
        if (v.fee_range) |want| {
            const got = m.extension.find(1) orelse return error.ExpectedTlvRecordMissing;
            try testing.expectEqual(@as(usize, 16), got.len);
            try testing.expectEqual(want.min_fee_satoshis, std.mem.readInt(u64, got[0..8], .big));
            try testing.expectEqual(want.max_fee_satoshis, std.mem.readInt(u64, got[8..16], .big));
        } else {
            try testing.expect(m.extension.find(1) == null);
        }
    }
}

test "BOLT#2 field anchor: HTLC update messages and commitment_signed" {
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();

    const ua = vectors.update_add_htlc_vector;
    const m1 = try bolt2.decodeUpdateAddHtlc(a, try framed(a, bolt2.UPDATE_ADD_HTLC_TYPE, ua.payload_hex));
    try expectHex(a, ua.channel_id_hex, &m1.channel_id);
    try testing.expectEqual(ua.id, m1.id);
    try testing.expectEqual(ua.amount_msat, m1.amount_msat);
    try expectHex(a, ua.payment_hash_hex, &m1.payment_hash);
    try testing.expectEqual(ua.cltv_expiry, m1.cltv_expiry);
    try expectHex(a, ua.onion_routing_packet_hex, &m1.onion_routing_packet);

    const uff = vectors.update_fulfill_htlc_vector;
    const m2 = try bolt2.decodeUpdateFulfillHtlc(a, try framed(a, bolt2.UPDATE_FULFILL_HTLC_TYPE, uff.payload_hex));
    try expectHex(a, uff.channel_id_hex, &m2.channel_id);
    try testing.expectEqual(uff.id, m2.id);
    try expectHex(a, uff.payment_preimage_hex, &m2.payment_preimage);

    const ufa = vectors.update_fail_htlc_vector;
    const m3 = try bolt2.decodeUpdateFailHtlc(a, try framed(a, bolt2.UPDATE_FAIL_HTLC_TYPE, ufa.payload_hex));
    try expectHex(a, ufa.channel_id_hex, &m3.channel_id);
    try testing.expectEqual(ufa.id, m3.id);
    try expectHex(a, ufa.reason_hex, m3.reason);
    try expectTlv(a, m3.extension, 1, ufa.attribution_data_hex);

    for (vectors.commitment_signed_vectors) |v| {
        const m = try bolt2.decodeCommitmentSigned(a, try framed(a, bolt2.COMMITMENT_SIGNED_TYPE, v.payload_hex));
        errdefer std.debug.print("commitment_signed vector: {s}\n", .{v.description});
        try expectHex(a, v.channel_id_hex, &m.channel_id);
        try expectHex(a, v.signature_hex, &m.signature);
        try testing.expectEqual(v.htlc_signature_hexes.len, m.htlc_signatures.len);
        for (v.htlc_signature_hexes, 0..) |want_hex, i| {
            try expectHex(a, want_hex, &m.htlc_signatures[i]);
        }
        try expectTlv(a, m.extension, 1, v.funding_txid_hex);
    }
}

test "BOLT#2 field anchor: revoke_and_ack and update_fee" {
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();

    const ra = vectors.revoke_and_ack_vector;
    const m1 = try bolt2.decodeRevokeAndAck(try framed(a, bolt2.REVOKE_AND_ACK_TYPE, ra.payload_hex));
    try expectHex(a, ra.channel_id_hex, &m1.channel_id);
    try expectHex(a, ra.per_commitment_secret_hex, &m1.per_commitment_secret);
    try expectHex(a, ra.next_per_commitment_point_hex, &m1.next_per_commitment_point);

    const uf = vectors.update_fee_vector;
    const m2 = try bolt2.decodeUpdateFee(try framed(a, bolt2.UPDATE_FEE_TYPE, uf.payload_hex));
    try expectHex(a, uf.channel_id_hex, &m2.channel_id);
    try testing.expectEqual(uf.feerate_per_kw, m2.feerate_per_kw);
}
