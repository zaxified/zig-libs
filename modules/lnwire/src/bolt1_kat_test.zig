// SPDX-License-Identifier: MIT
//! BOLT#1 base-protocol messages (`init`/`error`/`warning`/`ping`/`pong`),
//! anchored on rust-lightning's frozen encoder output. Until this file,
//! these five were the only BOLT#1 layer covered by self round-trip and
//! hostile-truncation tests alone — the BigSize/TLV sub-layer underneath
//! them was already fully external. See `bolt1_kat_vectors.zig` for
//! provenance.
//!
//! Two independent checks run over each vector, same shape as
//! `bolt2_kat_test.zig`:
//!
//!  1. **round-trip through foreign bytes** — decode the vector's wire
//!     bytes, re-serialize, require byte equality. Our codec was written
//!     from BOLT#1 independently of rust-lightning.
//!  2. **field-by-field against the vendored breakdown** — a consistent
//!     misreading of the layout (e.g. swapping which length field is which)
//!     would still round-trip; asserting against the known field values
//!     closes that blind spot.

const std = @import("std");
const testing = std.testing;
const bolt1 = @import("bolt1.zig");
const message = @import("message.zig");
const vectors = @import("bolt1_kat_vectors.zig");

fn framed(a: std.mem.Allocator, msg_type: u16, payload_hex: []const u8) ![]u8 {
    const out = try a.alloc(u8, 2 + payload_hex.len / 2);
    std.mem.writeInt(u16, out[0..2], msg_type, .big);
    _ = try std.fmt.hexToBytes(out[2..], payload_hex);
    return out;
}

test "BOLT#1 anchor: init, no TLV extension (upstream sub-case 2)" {
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();
    const want = try framed(a, bolt1.INIT_TYPE, vectors.init_no_tlv_payload_hex);

    const msg = try bolt1.decodeInit(a, want);
    try testing.expectEqualSlices(u8, &vectors.init_no_tlv_features, msg.globalfeatures);
    try testing.expectEqualSlices(u8, &vectors.init_no_tlv_features, msg.features);
    try testing.expectEqual(@as(usize, 0), msg.extension.records.len);

    const got = try bolt1.serializeInit(a, msg);
    try testing.expectEqualSlices(u8, want, got);
}

test "BOLT#1 anchor: init, networks TLV carrying Bitcoin mainnet's chain hash (upstream sub-case 3)" {
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();
    const want = try framed(a, bolt1.INIT_TYPE, vectors.init_networks_payload_hex);

    const msg = try bolt1.decodeInit(a, want);
    try testing.expectEqualSlices(u8, &.{}, msg.globalfeatures);
    try testing.expectEqualSlices(u8, &.{}, msg.features);

    var hash_buf: [32]u8 = undefined;
    _ = try std.fmt.hexToBytes(&hash_buf, vectors.init_networks_chain_hash);
    const networks = msg.extension.find(1) orelse return error.MissingNetworksTlv;
    try testing.expectEqualSlices(u8, &hash_buf, networks);

    const got = try bolt1.serializeInit(a, msg);
    try testing.expectEqualSlices(u8, want, got);
}

test "BOLT#1 anchor: error, channel_id + ASCII data" {
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();
    const want = try framed(a, bolt1.ERROR_TYPE, vectors.error_payload_hex);

    const msg = try bolt1.decodeError(want);
    try testing.expectEqualSlices(u8, &vectors.error_channel_id, &msg.channel_id);
    try testing.expectEqualStrings(vectors.error_data, msg.data);

    const got = try bolt1.serializeError(a, msg);
    try testing.expectEqualSlices(u8, want, got);
}

test "BOLT#1 anchor: warning shares error's wire layout, same vector re-typed" {
    // Upstream's `encoding_warning` test drives the identical struct/bytes
    // as `encoding_error` -- BOLT#1 defines the two with one shared layout.
    // Re-type the same vendored vector rather than duplicate it.
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();
    const want = try framed(a, bolt1.WARNING_TYPE, vectors.error_payload_hex);

    const msg = try bolt1.decodeWarning(want);
    try testing.expectEqualSlices(u8, &vectors.error_channel_id, &msg.channel_id);
    try testing.expectEqualStrings(vectors.error_data, msg.data);

    const got = try bolt1.serializeWarning(a, msg);
    try testing.expectEqualSlices(u8, want, got);
}

test "BOLT#1 anchor: ping" {
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();
    const want = try framed(a, bolt1.PING_TYPE, vectors.ping_payload_hex);

    const msg = try bolt1.decodePing(want);
    try testing.expectEqual(vectors.ping_num_pong_bytes, msg.num_pong_bytes);
    try testing.expectEqual(vectors.ping_ignored_len, msg.ignored.len);
    for (msg.ignored) |b| try testing.expectEqual(@as(u8, 0), b);

    const got = try bolt1.serializePing(a, msg);
    try testing.expectEqualSlices(u8, want, got);
}

test "BOLT#1 anchor: pong" {
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();
    const want = try framed(a, bolt1.PONG_TYPE, vectors.pong_payload_hex);

    const msg = try bolt1.decodePong(want);
    try testing.expectEqual(vectors.pong_ignored_len, msg.ignored.len);
    for (msg.ignored) |b| try testing.expectEqual(@as(u8, 0), b);

    const got = try bolt1.serializePong(a, msg);
    try testing.expectEqualSlices(u8, want, got);
}
