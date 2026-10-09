// SPDX-License-Identifier: MIT

//! Dead-stack probe, second file (`testkit.stackprobe`): the per-message
//! `protect` / `unprotect` and the out-param `deriveContextInto`. Needles are
//! the master secret and the context keys (inputs / out buffers), plus the
//! needle-free residue rule. ReleaseFast only (`skipUnlessOptimized`).

const std = @import("std");
const root = @import("root.zig");
const sp = @import("testkit").stackprobe;

const P = sp.Probe(.{ .window = 64 * 1024 });

var master: [32]u8 = undefined;
var client: root.SecurityContext = undefined;
var server: root.SecurityContext = undefined;
const salt = "9e7ca92223786340";
const client_id: []const u8 = &.{0x01};
const server_id: []const u8 = &.{0x02};
const plaintext = "oscore dead-stack probe payload";
const aad: root.AadParams = .{ .request_kid = &.{0x01}, .request_piv = &.{0x05} };

test "STACKPROBE: no OSCORE context key residue after deriveContextInto / protect / unprotect" {
    try sp.skipUnlessOptimized();
    std.crypto.hash.sha2.Sha256.hash("oscore probe secret 2", &master, .{});
    const gpa = std.heap.page_allocator;

    _ = try P.run("deriveContextInto", root.deriveContextInto, .{ &client, gpa, &master, salt, null, client_id, server_id, .aes_ccm_16_64_128 }, &.{ &master, std.mem.asBytes(&client) }, .{});
    try root.deriveContextInto(&server, gpa, &master, salt, null, server_id, client_id, .aes_ccm_16_64_128);

    const keys = &[_][]const u8{ &client.sender.key, &server.recipient.key };

    // A ciphertext for `unprotect`, made once from a copy so `client` keeps its sequence number.
    var scratch = client;
    scratch.sender.sequence_number = 5;
    const made = try root.protect(gpa, &scratch, plaintext, aad, false, null);

    _ = try P.run("protect", root.protect, .{ gpa, &client, plaintext, aad, true, null }, keys, .{});
    // Response with an explicit Partial IV (is_request = false): no replay-window state, so
    // the repeated runs all take the full decrypt path.
    _ = try P.run("unprotect", root.unprotect, .{ gpa, &server, root.OscoreOption{ .partial_iv = 5 }, made.ciphertext, aad, null, false }, keys, .{});
}
