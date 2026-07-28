// SPDX-License-Identifier: MIT
//! mls.kat_secrettree_test — the official RFC 9420 secret-tree interop
//! vectors (`mlswg/mls-implementations` `test-vectors/secret-tree.json`),
//! embedded verbatim and driven end-to-end against `secrettree.zig`. See
//! `NOTICE` for the exact source commit and fetch date.
//!
//! Three things this pins that a self-consistency test could not:
//!
//! * the tree walk's LEFT/RIGHT assignment. Every leaf in a 32-leaf tree
//!   derives from the same root by a different left/right sequence; swap
//!   the two labels and leaf 0's keys become leaf 31's. The vector supplies
//!   per-leaf keys for trees of 1, 8 and 32 leaves, so the whole mapping is
//!   checked, not just its shape.
//! * the ratchet's generation encoding and step order. Generations 0 and 15
//!   are given for every leaf, so reaching 15 requires fifteen correct
//!   `DeriveTreeSecret(., "secret", j, ...)` steps with the right `j` at
//!   each one — an off-by-one in the generation fed to the KDF still
//!   produces a perfectly good key at generation 15, just the wrong one.
//! * §6.3.2's sender-data sampling.
//!
//! Each leaf's generations are driven TWICE: once forward through a bare
//! `Ratchet` (the sender's path) and once in REVERSE generation order
//! through a `Window` (the receiver's out-of-order path, which must retain
//! the skipped keys and hand back the identical bytes). Same expected
//! vector, two different code paths.
//!
//! Parsed as generic `std.json.Value`, matching `kat_test.zig`'s reasoning.

const std = @import("std");
const suite = @import("suite.zig");
const secrettree = @import("secrettree.zig");

const secret_tree_json = @embedFile("data/secret-tree.json");

const testing = std.testing;
const S = suite.default;

/// The vector's largest leaf generation is 15; a window that can hold every
/// generation of the largest case is what lets the reverse-order pass be a
/// real check rather than an eviction test.
const window_capacity = 32;

fn hexDecode(allocator: std.mem.Allocator, hex: []const u8) ![]u8 {
    const out = try allocator.alloc(u8, hex.len / 2);
    _ = try std.fmt.hexToBytes(out, hex);
    return out;
}

fn hexSecret(hex: []const u8) ![S.Nh]u8 {
    var out: [S.Nh]u8 = undefined;
    const decoded = try std.fmt.hexToBytes(&out, hex);
    try testing.expectEqual(@as(usize, S.Nh), decoded.len);
    return out;
}

fn asI64(v: std.json.Value) i64 {
    return switch (v) {
        .integer => |i| i,
        else => unreachable,
    };
}

fn expectStage(name: []const u8, leaf: usize, generation: u32, want: []const u8, got: []const u8) !void {
    testing.expectEqualSlices(u8, want, got) catch |err| {
        std.debug.print(
            "secret-tree KAT: '{s}' diverged at leaf {d}, generation {d}\n",
            .{ name, leaf, generation },
        );
        return err;
    };
}

test "secret-tree.json: RFC 9420 §9's tree, ratchets and §6.3.2 sender data for suite 0x0001, byte-exact" {
    var parsed = try std.json.parseFromSlice(std.json.Value, testing.allocator, secret_tree_json, .{});
    defer parsed.deinit();
    const arena = parsed.arena.allocator();

    var found_suite_1 = false;
    var skipped_other_suites: usize = 0;
    var checked_generations: usize = 0;
    var max_leaves: usize = 0;

    for (parsed.value.array.items) |entry| {
        const cs = asI64(entry.object.get("cipher_suite").?);
        if (cs != @as(i64, @intFromEnum(S.id))) {
            skipped_other_suites += 1;
            continue; // this module only wires suite 0x0001 — see suite.zig
        }
        found_suite_1 = true;

        // ── §6.3.2: sender-data key and nonce ──
        {
            const sd = entry.object.get("sender_data").?.object;
            const sds = try hexSecret(sd.get("sender_data_secret").?.string);
            const ciphertext = try hexDecode(arena, sd.get("ciphertext").?.string);
            const got = try secrettree.senderDataKeys(S, sds, ciphertext);
            try expectStage("sender_data_key", 0, 0, try hexDecode(arena, sd.get("key").?.string), &got.key);
            try expectStage("sender_data_nonce", 0, 0, try hexDecode(arena, sd.get("nonce").?.string), &got.nonce);
        }

        // ── §9: the secret tree itself ──
        const encryption_secret = try hexSecret(entry.object.get("encryption_secret").?.string);
        const leaves = entry.object.get("leaves").?.array.items;
        const n_leaves = leaves.len;
        max_leaves = @max(max_leaves, n_leaves);

        for (leaves, 0..) |leaf_v, leaf_index| {
            const generations = leaf_v.array.items;

            inline for (.{
                .{ secrettree.RatchetKind.handshake, "handshake_key", "handshake_nonce" },
                .{ secrettree.RatchetKind.application, "application_key", "application_nonce" },
            }) |spec| {
                const kind = spec[0];
                const key_field = spec[1];
                const nonce_field = spec[2];

                const base = try secrettree.ratchetBaseSecret(S, encryption_secret, n_leaves, leaf_index, kind);

                // Pass 1 — the sender's path: advance a bare ratchet
                // forward through every generation the vector names.
                {
                    var ratchet = secrettree.Ratchet(S).init(base);
                    for (generations) |g_v| {
                        const g: u32 = @intCast(asI64(g_v.object.get("generation").?));
                        while (ratchet.generation < g) try ratchet.advance();
                        try testing.expectEqual(g, ratchet.generation);
                        const kn = try ratchet.current();
                        try expectStage(key_field, leaf_index, g, try hexDecode(arena, g_v.object.get(key_field).?.string), &kn.key);
                        try expectStage(nonce_field, leaf_index, g, try hexDecode(arena, g_v.object.get(nonce_field).?.string), &kn.nonce);
                        checked_generations += 1;
                    }
                }

                // Pass 2 — the receiver's out-of-order path: ask for the
                // SAME generations newest-first, so every earlier one has
                // to come back out of the retained window.
                {
                    var window = secrettree.Window(S, window_capacity).init(base);
                    var i = generations.len;
                    while (i > 0) {
                        i -= 1;
                        const g_v = generations[i];
                        const g: u32 = @intCast(asI64(g_v.object.get("generation").?));
                        const kn = try window.get(g);
                        try expectStage(key_field, leaf_index, g, try hexDecode(arena, g_v.object.get(key_field).?.string), &kn.key);
                        try expectStage(nonce_field, leaf_index, g, try hexDecode(arena, g_v.object.get(nonce_field).?.string), &kn.nonce);
                    }
                }
            }
        }
    }

    try testing.expect(found_suite_1);
    // The 32-leaf case is what makes the left/right walk falsifiable — a
    // one-leaf tree would pass with no tree math at all.
    try testing.expect(max_leaves >= 32);
    try testing.expect(checked_generations >= 80);
    // Suites 0x0002-0x0007 appear for each of the three tree sizes.
    try testing.expectEqual(@as(usize, 18), skipped_other_suites);
}
