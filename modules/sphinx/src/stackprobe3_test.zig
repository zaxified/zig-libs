// SPDX-License-Identifier: MIT

//! Dead-stack probe (`testkit.stackprobe`) for BOLT#4 route blinding
//! (`blinded.zig`): `createPath` and `unblind`, both burned with
//! `blind_burn`. ReleaseFast/ReleaseSmall only (`skipUnlessOptimized`).
//!
//! Needles, re-derived here from the BOLT#4 formulas over the public pieces:
//! the session key `e_0` and every path private key `e_i`, each hop's
//! `ss_i = SHA256(e_i * N_i)`, `rho_i`, the blinding factor
//! `HMAC256("blinded_node_id", ss_i)` and the next-key factor
//! `SHA256(E_i || ss_i)`; at the receiving node also `k_i` and the blinded
//! private key `b_i` (the `out` it writes).

const std = @import("std");
const sphinx = @import("root.zig");
const bl = sphinx.blinded;
const Secp256k1 = @import("k256").Secp256k1;
const Sha256 = std.crypto.hash.sha2.Sha256;
const HmacSha256 = std.crypto.auth.hmac.sha2.HmacSha256;
const sp = @import("testkit").stackprobe;

const P = sp.Probe(.{ .window = 64 * 1024 });

const n_hops = 3;
const payload_len = 40;

var session: [32]u8 = undefined;
var node_keys: [n_hops][32]u8 = undefined;
var node_ids: [n_hops][bl.pubkey_len]u8 = undefined;
var payload_bufs: [n_hops][payload_len]u8 = undefined;
var payloads: [n_hops][]const u8 = undefined;
var enc_bufs: [n_hops][payload_len + bl.tag_len]u8 = undefined;
var out: [n_hops]bl.BlindedHop = undefined;
var plain: [payload_len]u8 = undefined;
var unblinded: bl.Unblinded = undefined;

/// Per hop: e_i, ss_i, rho_i, the two factors (32 bytes each).
var hop_secrets: [n_hops][5][32]u8 = undefined;

fn label(comptime tag: []const u8, i: usize, dst: *[32]u8) void {
    Sha256.hash(&[_]u8{ 's', 'p', 'h', 'b', 'l', @intCast(i) } ++ tag, dst, .{});
}

/// The BOLT#4 derivations of `blinded.zig`'s header, written out again.
fn deriveHopSecrets() !void {
    var e = session;
    var point = try Secp256k1.basePoint.mul(e, .big);
    for (0..n_hops) |i| {
        const n_point = try Secp256k1.fromSec1(&node_ids[i]);
        var ss: [32]u8 = undefined;
        Sha256.hash(&(try n_point.mul(e, .big)).toCompressedSec1(), &ss, .{});
        var rho: [32]u8 = undefined;
        sphinx.generateKey(&rho, .rho, &ss);
        var f_blind: [32]u8 = undefined;
        HmacSha256.create(&f_blind, &ss, "blinded_node_id");
        var f_next: [32]u8 = undefined;
        var h = Sha256.init(.{});
        h.update(&point.toCompressedSec1());
        h.update(&ss);
        h.final(&f_next);
        hop_secrets[i] = .{ e, ss, rho, f_blind, f_next };
        point = try point.mul(f_next, .big);
        e = try Secp256k1.scalar.mul(e, f_next, .big);
    }
}

fn reversed(b: [32]u8) [32]u8 {
    var r = b;
    std.mem.reverse(u8, &r);
    return r;
}

test "STACKPROBE: route blinding createPath / unblind leave no secret in any frame" {
    try sp.skipUnlessOptimized();
    label("session", 0, &session);
    for (0..n_hops) |i| {
        label("node", i, &node_keys[i]);
        node_ids[i] = (try Secp256k1.basePoint.mul(node_keys[i], .big)).toCompressedSec1();
        label("payload", i, payload_bufs[i][0..32]);
        @memset(payload_bufs[i][32..], @intCast(i));
        payloads[i] = &payload_bufs[i];
        out[i] = .{ .blinded_node_id = undefined, .encrypted_data = &enc_bufs[i] };
    }
    try deriveHopSecrets();

    // Sender: every hop's secrets, both byte orders for the scalars.
    var needles: [n_hops * 7][]const u8 = undefined;
    var rev: [n_hops][2][32]u8 = undefined;
    var nn: usize = 0;
    for (0..n_hops) |i| {
        for (&hop_secrets[i]) |*s| {
            needles[nn] = s;
            nn += 1;
        }
        rev[i] = .{ reversed(hop_secrets[i][0]), reversed(hop_secrets[i][4]) };
        needles[nn] = &rev[i][0];
        needles[nn + 1] = &rev[i][1];
        nn += 2;
    }
    _ = try P.run("blinded.createPath", bl.createPath, .{ &session, @as([]const [bl.pubkey_len]u8, &node_ids), @as([]const []const u8, &payloads), @as([]bl.BlindedHop, &out) }, needles[0..nn], .{});

    // Receiver: each node with its own path key E_i.
    var path_key = (try Secp256k1.basePoint.mul(session, .big)).toCompressedSec1();
    for (0..n_hops) |i| {
        const pk = path_key;
        const k_le = reversed(node_keys[i]);
        _ = try P.run("blinded.unblind", bl.unblind, .{ &node_keys[i], &pk, @as([]const u8, &enc_bufs[i]), @as([]u8, &plain), &unblinded }, &.{
            &node_keys[i],      &k_le,              &hop_secrets[i][1],         &hop_secrets[i][2],
            &hop_secrets[i][3], &hop_secrets[i][4], &unblinded.blinded_privkey,
        }, .{});
        try std.testing.expectEqualSlices(u8, &payload_bufs[i], &plain); // the probed call did the work
        try std.testing.expectEqualSlices(u8, &out[i].blinded_node_id, &(try Secp256k1.basePoint.mul(unblinded.blinded_privkey, .big)).toCompressedSec1());
        path_key = unblinded.next_path_key;
    }
}
