// SPDX-License-Identifier: MIT

//! Tests added by the 2026-11-25 delta mutation run over `blinded.zig`.

const std = @import("std");
const testing = std.testing;
const Secp256k1 = @import("k256").Secp256k1;
const bl = @import("root.zig").blinded;

/// Node key 1, so its node id is the generator and `createPath` output can be
/// opened with `unblind`.
fn nodeOne() struct { k: [32]u8, id: [bl.pubkey_len]u8 } {
    var k: [32]u8 = @splat(0);
    k[31] = 1;
    return .{ .k = k, .id = Secp256k1.basePoint.toCompressedSec1() };
}

test "mutation 2026-11-25: createPath checks the payload count and the out count each against the node count" {
    const n = nodeOne();
    const s: [32]u8 = @splat(2);
    var buf: [19]u8 = undefined;
    var out = [_]bl.BlindedHop{.{ .blinded_node_id = undefined, .encrypted_data = &buf }};
    const ids = [_][bl.pubkey_len]u8{n.id};
    // payloads match the nodes, out does not
    try testing.expectError(error.LengthMismatch, bl.createPath(&s, &ids, &.{"abc"}, out[0..0]));
    // out matches the nodes, payloads do not
    try testing.expectError(error.LengthMismatch, bl.createPath(&s, &ids, &.{}, &out));
}

test "mutation 2026-11-25: unblind opens an empty payload (encrypted is exactly the tag)" {
    const n = nodeOne();
    const s: [32]u8 = @splat(2);
    var buf: [bl.tag_len]u8 = undefined;
    var out = [_]bl.BlindedHop{.{ .blinded_node_id = undefined, .encrypted_data = &buf }};
    const ids = [_][bl.pubkey_len]u8{n.id};
    const first = try bl.createPath(&s, &ids, &.{""}, &out);
    var u: bl.Unblinded = undefined;
    var plain: [0]u8 = .{};
    try bl.unblind(&n.k, &first, &buf, &plain, &u);
}

test "mutation 2026-11-25: unblind zeroes plain_out when authentication fails" {
    const n = nodeOne();
    const s: [32]u8 = @splat(2);
    var buf: [19]u8 = undefined;
    var out = [_]bl.BlindedHop{.{ .blinded_node_id = undefined, .encrypted_data = &buf }};
    const ids = [_][bl.pubkey_len]u8{n.id};
    const first = try bl.createPath(&s, &ids, &.{"abc"}, &out);
    buf[0] ^= 1;
    var plain: [3]u8 = @splat(0x55);
    var u: bl.Unblinded = undefined;
    try testing.expectError(error.DecryptionFailed, bl.unblind(&n.k, &first, &buf, &plain, &u));
    try testing.expectEqualSlices(u8, &[_]u8{ 0, 0, 0 }, &plain);
}
