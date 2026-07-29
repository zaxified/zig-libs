// SPDX-License-Identifier: MIT
//! mls.kat_passive_test — the official RFC 9420 "passive client" interop
//! vectors (`mlswg/mls-implementations` `test-vectors/passive-client-*.json`),
//! which are the strongest end-to-end evidence this module has.
//!
//! **Why these are different from every other vector here.** The other
//! embedded vectors pin ONE derivation, ONE codec, or ONE message: they
//! prove a function is right. These replay a whole recorded session — a
//! client is added to a real group by a real implementation, then follows
//! that group through a sequence of Commits made by other members — and
//! compare the `epoch_authenticator` at EVERY step. Getting one of these
//! green means this module's group state machine agrees, epoch by epoch,
//! with the implementation that recorded the session; there is nothing else
//! available at this revision that comes closer to interoperating.
//!
//! It is also the harshest possible harness, because the state machine has
//! no way to resynchronize. `epoch_authenticator` is
//! `DeriveSecret(epoch_secret, "authentication")`, and `epoch_secret`
//! depends on the `GroupContext` (hence on the tree hash and the whole
//! transcript) and on the previous epoch's `init_secret`. One wrong bit
//! anywhere — a proposal applied in the wrong order, a provisional
//! GroupContext built with the wrong `confirmed_transcript_hash`, a leaf
//! placed at the wrong index — and every subsequent epoch is wrong too.
//! A test that gets to epoch 200 has had 200 independent chances to fail.
//!
//! **Upstream's verification procedure**, from the repository's own
//! `test-vectors.md`, is followed exactly: check the three private keys
//! against the KeyPackage's public keys, join with the Welcome (and the
//! out-of-band `ratchet_tree` when the vector supplies one, and the
//! `external_psks`), compare `initial_epoch_authenticator`, then for each
//! entry in `epochs` apply the Commit using the `proposals` it references
//! and compare that epoch's `epoch_authenticator`.
//!
//! **What the embedded files are reduced to, and the assertion that guards
//! it.** Both are filtered to cipher suite `0x0001` (the only suite
//! `suite.zig` wires) — the exact `jq` expression is in `NOTICE`. The
//! filter keeps whole entries, so no recorded session is truncated: every
//! session that runs here runs to its last Commit. The coverage the
//! reduction rests on is ASSERTED below (`passive-client-welcome`'s four
//! combinations of tree-source × PSK-presence; `passive-client-handling-
//! commit`'s epochs with no proposals, with one, and with several; and, for
//! both, that every message really is a `PublicMessage`), so a future
//! re-filter that quietly drops a case fails the test instead of passing.
//!
//! Parsed as generic `std.json.Value`, matching `kat_test.zig`'s reasoning.

const std = @import("std");
const codec = @import("codec.zig");
const crypto = @import("crypto.zig");
const framing = @import("framing.zig");
const group = @import("group.zig");
const keypackage = @import("keypackage.zig");
const suite = @import("suite.zig");

const welcome_json = @embedFile("data/passive-client-welcome.json");
const handling_commit_json = @embedFile("data/passive-client-handling-commit.json");
const random_json = @embedFile("data/passive-client-random.json");

const testing = std.testing;
const S = suite.default;
const G = group.Group(S);

fn hexDecode(allocator: std.mem.Allocator, hex: []const u8) ![]u8 {
    const out = try allocator.alloc(u8, hex.len / 2);
    _ = try std.fmt.hexToBytes(out, hex);
    return out;
}

fn hexArray(comptime n: usize, hex: []const u8) ![n]u8 {
    var out: [n]u8 = undefined;
    const got = try std.fmt.hexToBytes(&out, hex);
    if (got.len != n) return error.WrongKeyLength;
    return out;
}

/// A divergence must name the session and the epoch it happened in, or a
/// failure at epoch 137 of 200 says nothing about what went wrong.
fn expectAuthenticator(
    vector: []const u8,
    entry: usize,
    epoch_label: []const u8,
    want: []const u8,
    got: []const u8,
) !void {
    testing.expectEqualSlices(u8, want, got) catch |err| {
        std.debug.print(
            "passive-client KAT [{s}] entry {d}, {s}: epoch_authenticator diverged\n",
            .{ vector, entry, epoch_label },
        );
        return err;
    };
}

/// The whole of upstream's stated procedure for one vector entry: join,
/// check the initial authenticator, then replay every recorded epoch.
/// Returns the number of Commits replayed.
fn runEntry(
    vector: []const u8,
    entry_index: usize,
    obj: std.json.ObjectMap,
) !usize {
    const alloc = testing.allocator;

    var scratch = std.heap.ArenaAllocator.init(alloc);
    defer scratch.deinit();
    const sa = scratch.allocator();

    const key_package_msg = try hexDecode(sa, obj.get("key_package").?.string);
    const welcome_msg = try hexDecode(sa, obj.get("welcome").?.string);
    const init_priv = try hexArray(S.Kem.Nsk, obj.get("init_priv").?.string);
    const encryption_priv = try hexArray(S.Kem.Nsk, obj.get("encryption_priv").?.string);
    const signature_priv = try hexArray(32, obj.get("signature_priv").?.string);

    const ratchet_tree: ?[]const u8 = switch (obj.get("ratchet_tree").?) {
        .string => |h| try hexDecode(sa, h),
        .null => null,
        else => return error.Malformed,
    };

    var psks: std.ArrayList(group.ExternalPsk) = .empty;
    for (obj.get("external_psks").?.array.items) |p| {
        try psks.append(sa, .{
            .psk_id = try hexDecode(sa, p.object.get("psk_id").?.string),
            .psk = try hexDecode(sa, p.object.get("psk").?.string),
        });
    }

    // ── upstream's first bullet: the three private keys really are the
    // private halves of the KeyPackage's three public keys. Without this a
    // later HPKE failure could not be told apart from "wrong key supplied".
    {
        var r = codec.Reader.init(key_package_msg);
        const msg = try framing.MLSMessage.decode(sa, &r);
        try testing.expect(r.atEnd());
        const kp = msg.key_package;
        const init_kp = try S.Kem.KeyPair.generateDeterministic(init_priv);
        const enc_kp = try S.Kem.KeyPair.generateDeterministic(encryption_priv);
        const sig_kp = try S.Sig.KeyPair.generateDeterministic(signature_priv);
        try testing.expectEqualSlices(u8, kp.init_key, &init_kp.public_key);
        try testing.expectEqualSlices(u8, kp.leaf_node.encryption_key, &enc_kp.public_key);
        try testing.expectEqualSlices(u8, kp.leaf_node.signature_key, &sig_kp.public_key.toBytes());
    }

    // ── join.
    var g = G.fromWelcome(alloc, .{
        .welcome_msg = welcome_msg,
        .key_package_msg = key_package_msg,
        .init_priv = init_priv,
        .encryption_priv = encryption_priv,
        .ratchet_tree = ratchet_tree,
        .external_psks = psks.items,
    }) catch |err| {
        std.debug.print(
            "passive-client KAT [{s}] entry {d}: fromWelcome failed: {s}\n",
            .{ vector, entry_index, @errorName(err) },
        );
        return err;
    };
    defer g.deinit();

    {
        const want = try hexDecode(sa, obj.get("initial_epoch_authenticator").?.string);
        const got = g.epochAuthenticator();
        try expectAuthenticator(vector, entry_index, "initial (post-Welcome)", want, &got);
    }

    // ── replay every recorded epoch.
    var replayed: usize = 0;
    for (obj.get("epochs").?.array.items, 0..) |epoch_value, epoch_index| {
        const epoch = epoch_value.object;

        var proposals: std.ArrayList([]const u8) = .empty;
        for (epoch.get("proposals").?.array.items) |p| {
            try proposals.append(sa, try hexDecode(sa, p.string));
        }
        const commit_msg = try hexDecode(sa, epoch.get("commit").?.string);

        var label_buf: [64]u8 = undefined;
        const label = try std.fmt.bufPrint(&label_buf, "epoch index {d}", .{epoch_index});

        g.processCommit(.{
            .commit_msg = commit_msg,
            .proposal_msgs = proposals.items,
            .external_psks = psks.items,
        }) catch |err| {
            std.debug.print(
                "passive-client KAT [{s}] entry {d}, {s}: processCommit failed: {s}\n",
                .{ vector, entry_index, label, @errorName(err) },
            );
            return err;
        };

        const want = try hexDecode(sa, epoch.get("epoch_authenticator").?.string);
        const got = g.epochAuthenticator();
        try expectAuthenticator(vector, entry_index, label, want, &got);
        replayed += 1;
    }
    return replayed;
}

/// Every entry in an embedded file is already suite `0x0001` — the filter
/// is applied before embedding, not here (see `NOTICE`). This asserts that,
/// so a re-filter that let another suite through fails loudly rather than
/// silently skipping the entries this module cannot drive.
fn expectOnlySuite1(items: []const std.json.Value) !void {
    for (items) |e| {
        try testing.expectEqual(@as(i64, @intFromEnum(S.id)), e.object.get("cipher_suite").?.integer);
    }
}

test "passive-client-welcome.json: join a recorded group and match its epoch_authenticator" {
    var parsed = try std.json.parseFromSlice(std.json.Value, testing.allocator, welcome_json, .{});
    defer parsed.deinit();
    const items = parsed.value.array.items;
    try expectOnlySuite1(items);

    for (items, 0..) |entry, i| {
        const replayed = try runEntry("welcome", i, entry.object);
        // This vector records the join and nothing after it — see the
        // coverage test below, which pins that as a property rather than
        // leaving it as an accident of the data.
        try testing.expectEqual(@as(usize, 0), replayed);
    }
}

test "passive-client-handling-commit.json: replay each recorded session Commit by Commit" {
    var parsed = try std.json.parseFromSlice(std.json.Value, testing.allocator, handling_commit_json, .{});
    defer parsed.deinit();
    const items = parsed.value.array.items;
    try expectOnlySuite1(items);

    var total: usize = 0;
    for (items, 0..) |entry, i| {
        total += try runEntry("handling-commit", i, entry.object);
    }
    // Every entry contributed at least one replayed Commit; a vector that
    // silently degenerated to a join-only file would otherwise pass this
    // test while proving nothing about commit processing.
    try testing.expect(total >= items.len);
}

// ── the reduction's coverage properties ───────────────────────────────────
//
// `NOTICE` justifies embedding a suite-filtered subset by pointing at what
// that subset still covers. These tests turn that justification into
// something that FAILS if a future re-filter breaks it.

test "reduction coverage: passive-client-welcome still spans both tree sources and both PSK cases" {
    var parsed = try std.json.parseFromSlice(std.json.Value, testing.allocator, welcome_json, .{});
    defer parsed.deinit();

    var tree_in_welcome = false;
    var tree_out_of_band = false;
    var without_psk = false;
    var with_psk = false;
    for (parsed.value.array.items) |e| {
        const obj = e.object;
        switch (obj.get("ratchet_tree").?) {
            .null => tree_in_welcome = true,
            .string => tree_out_of_band = true,
            else => return error.Malformed,
        }
        if (obj.get("external_psks").?.array.items.len == 0) without_psk = true else with_psk = true;
        // Join-only: the epoch list is what distinguishes this vector from
        // the other two, and the test above asserts zero Commits replayed.
        try testing.expectEqual(@as(usize, 0), obj.get("epochs").?.array.items.len);
    }
    // §12.4.3.3's two ways to obtain the tree exercise DIFFERENT code:
    // the extension path decodes it out of the signed GroupInfo, the
    // out-of-band path takes the caller's bytes and leans entirely on
    // `verifyTreeHash` to make them safe.
    try testing.expect(tree_in_welcome);
    try testing.expect(tree_out_of_band);
    // §8.4: a PSK in the Welcome changes `welcome_secret` itself, so the
    // no-PSK entries cannot stand in for the PSK ones.
    try testing.expect(without_psk);
    try testing.expect(with_psk);
}

test "reduction coverage: passive-client-handling-commit still spans empty and non-empty proposal lists" {
    var parsed = try std.json.parseFromSlice(std.json.Value, testing.allocator, handling_commit_json, .{});
    defer parsed.deinit();

    var no_proposals = false;
    var one_proposal = false;
    var many_proposals = false;
    var epochs_seen: usize = 0;
    for (parsed.value.array.items) |e| {
        // Every entry in this vector injects an external PSK, which is the
        // only place `processCommit`'s PSK resolution is driven by a
        // vector at all.
        try testing.expect(e.object.get("external_psks").?.array.items.len > 0);
        for (e.object.get("epochs").?.array.items) |epoch| {
            epochs_seen += 1;
            switch (epoch.object.get("proposals").?.array.items.len) {
                0 => no_proposals = true,
                1 => one_proposal = true,
                else => many_proposals = true,
            }
        }
    }
    try testing.expect(epochs_seen > 0);
    // An empty proposal list forces §12.4.2's "path value is populated if
    // ... it's empty" rule; a non-empty one exercises by-reference
    // resolution and §12.3's ordering. Neither substitutes for the other.
    try testing.expect(no_proposals);
    try testing.expect(one_proposal);
    try testing.expect(many_proposals);
}

test "reduction coverage: every recorded message is a PublicMessage" {
    // `group.zig` refuses `PrivateMessage` handshakes
    // (`error.PrivateHandshakeNotSupported`) — a documented scope boundary.
    // That boundary is only honest while the vectors driving it contain no
    // PrivateMessage, so assert it rather than assume it: a re-filter that
    // introduced one would otherwise turn a green suite into a silent
    // "this case is never tested".
    const files = [_][]const u8{ welcome_json, handling_commit_json };
    for (files) |json| {
        var parsed = try std.json.parseFromSlice(std.json.Value, testing.allocator, json, .{});
        defer parsed.deinit();
        for (parsed.value.array.items) |e| {
            for (e.object.get("epochs").?.array.items) |epoch| {
                const obj = epoch.object;
                try expectPublicMessage(obj.get("commit").?.string);
                for (obj.get("proposals").?.array.items) |p| try expectPublicMessage(p.string);
            }
        }
    }
}

/// An `MLSMessage` header is `ProtocolVersion` (2) then `WireFormat` (2), so
/// the first four hex-encoded bytes name the form without decoding the body.
fn expectPublicMessage(hex: []const u8) !void {
    try testing.expect(hex.len >= 8);
    const header = try hexArray(4, hex[0..8]);
    var r = codec.Reader.init(&header);
    try testing.expectEqual(@as(u16, 1), try r.readU16()); // mls10
    try testing.expectEqual(framing.WireFormat.mls_public_message, try r.readEnum(framing.WireFormat));
}

// ── the endurance vector ──────────────────────────────────────────────────

test "passive-client-random.json: replay a 200-Commit recorded session end to end" {
    var parsed = try std.json.parseFromSlice(std.json.Value, testing.allocator, random_json, .{});
    defer parsed.deinit();
    const items = parsed.value.array.items;
    try expectOnlySuite1(items);
    // Upstream ships this as a single recorded session; if that ever
    // changes, the per-entry loop below still works but the "one long
    // chain" property this vector exists for would not, so pin it.
    try testing.expectEqual(@as(usize, 1), items.len);

    const replayed = try runEntry("random", 0, items[0].object);
    // The whole value of this vector is the LENGTH of the chain: each
    // Commit is an independent chance for a systematic error to surface,
    // and a truncated file would still pass every other assertion here.
    try testing.expectEqual(@as(usize, 200), replayed);
}

test "reduction coverage: passive-client-random is embedded whole, and still spans every shape it is kept for" {
    // This file is embedded VERBATIM — see `NOTICE` for why no reduction
    // is available for it (the only axis is an epoch prefix, and the
    // session length is the property under test). These assertions exist
    // so that a future attempt to shrink it FAILS rather than quietly
    // removing the coverage that justifies its size.
    var parsed = try std.json.parseFromSlice(std.json.Value, testing.allocator, random_json, .{});
    defer parsed.deinit();
    const epochs = parsed.value.array.items[0].object.get("epochs").?.array.items;
    try testing.expectEqual(@as(usize, 200), epochs.len);

    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();

    var max_path_depth: usize = 0;
    var saw_path = false;
    var saw_no_path = false;
    var saw_inline = false;
    var saw_by_reference = false;
    var saw_empty_proposal_list = false;
    for (epochs) |epoch| {
        const obj = epoch.object;
        if (obj.get("proposals").?.array.items.len == 0) saw_empty_proposal_list = true;
        const bytes = try hexDecode(a, obj.get("commit").?.string);
        var r = codec.Reader.init(bytes);
        const msg = try framing.MLSMessage.decode(a, &r);
        const commit = msg.public_message.content.body.commit;
        if (commit.path) |path| {
            saw_path = true;
            if (path.nodes.len > max_path_depth) max_path_depth = path.nodes.len;
        } else saw_no_path = true;
        for (commit.proposals) |por| switch (por) {
            .proposal => saw_inline = true,
            .reference => saw_by_reference = true,
        };
    }
    try testing.expect(saw_path);
    try testing.expect(saw_no_path);
    try testing.expect(saw_inline);
    try testing.expect(saw_by_reference);
    try testing.expect(saw_empty_proposal_list);
    // The group grows until an `UpdatePath` spans seven levels — a tree of
    // up to 128 leaves, with correspondingly deep filtered direct paths and
    // large copath resolutions. That depth is not reached until epoch 110,
    // which is the concrete reason a short prefix of this file would not
    // substitute for it.
    try testing.expectEqual(@as(usize, 7), max_path_depth);
}
