// SPDX-License-Identifier: MIT
//! mls.kat_commit_test — **Part 8**'s KAT harness: the two things that can
//! be said about Commit CREATION with a recorded vector rather than with
//! this module's own decoder.
//!
//! **The honest problem with testing creation.** A Commit is not a function
//! of its inputs. §7.4 samples `path_secret[0]` at random, §7.5 samples a
//! fresh leaf key pair, and every `HPKECiphertext` in it draws an HPKE
//! ephemeral — so no interop vector can pin the BYTES a correct
//! implementation produces, and there is no upstream "active client" vector
//! at the pinned revision either. Left there, everything about creation
//! would be a round trip against this module's own receive path: real
//! evidence of self-consistency, no evidence of conformance.
//!
//! Two things break out of that, and this file is both of them.
//!
//! **1. Seed the generation from a recorded vector's own path secret.**
//! `treekem.json` publishes, per update path, the path secret that each
//! receiving leaf decrypts at its overlap node. For the receiver whose
//! overlap is the FIRST node of the sender's filtered direct path, that
//! value IS the sender's `path_secret[0]` — the one random input. Feeding
//! it to `treekem.stageUpdatePath` makes generation deterministic and makes
//! three of its outputs comparable byte-for-byte against what another
//! implementation actually produced:
//!
//!   * every `node_pub[n]` along the filtered direct path (which pins §7.4's
//!     chain, `DeriveKeyPair`, and the §4.1.2 filter's ORDER and LENGTH);
//!   * the `commit_secret` (which pins the extra `DeriveSecret(., "path")`
//!     past the last node);
//!   * the committer leaf's `parent_hash` — and because §7.9's
//!     `ParentHashInput` embeds the parent's own stored `parent_hash`, one
//!     matching digest at the leaf transitively pins the WHOLE root-to-leaf
//!     parent-hash chain the merge wrote.
//!
//! None of those three depend on the committer's leaf content, which is why
//! a dummy leaf is enough here: `ParentHashInput` for any node on the path
//! reads only that node's key, its stored hash, and the tree hash of a
//! COPATH subtree — and no copath subtree contains the sender's own leaf.
//!
//! **2. Make the encryption side face the vector's real receivers.** The
//! ciphertexts cannot be compared (fresh ephemerals), but who can OPEN them
//! can be: this file seals an `UpdatePath` over the vector's tree and then
//! hands it to `treekem.processUpdatePath` for every one of that vector's
//! `leaves_private` entries, using THEIR recorded private keys and prior
//! path secrets, and requires each to recover the vector's recorded
//! `path_secrets[leaf]` and `commit_secret`. A wrong resolution order, a
//! wrong exclusion set, a wrong `EncryptWithLabel` label or a wrong HPKE
//! context all fail that. It is still a round trip through this module's own
//! decap — but over another implementation's tree, another implementation's
//! keys, and against another implementation's expected plaintexts.
//!
//! **3. Create Commits on top of a recorded session.** The
//! `passive-client-*.json` replays leave this module holding a group state
//! that came from another implementation — a real tree with blank nodes,
//! unmerged leaves and a real transcript. This file then commits from THAT
//! state and checks a new member joining by the resulting Welcome derives
//! the committer's `epoch_authenticator`. The starting state is external;
//! the transition is a round trip, and this file says so rather than
//! implying otherwise.
//!
//! Model: RFC 9420 §7.4, §7.5 (sender half), §11, §12.4.1, §12.4.3.1.
//! KAT provenance: see `NOTICE`.

const std = @import("std");
const codec = @import("codec.zig");
const crypto = @import("crypto.zig");
const framing = @import("framing.zig");
const gate = @import("gate.zig");
const group = @import("group.zig");
const keypackage = @import("keypackage.zig");
const suite = @import("suite.zig");
const tree = @import("tree.zig");
const treehash = @import("treehash.zig");
const treekem = @import("treekem.zig");
const treemath = @import("treemath.zig");
const wire = @import("wire_lists.zig");

const treekem_json = @embedFile("data/treekem.json");
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

fn asU64(v: std.json.Value) !u64 {
    return switch (v) {
        .integer => |i| @intCast(i),
        .number_string => |s| try std.fmt.parseInt(u64, s, 10),
        else => error.Malformed,
    };
}

/// Same shape `kat_treekem_test.zig` uses: the tree's fields ALIAS the
/// hex-decoded bytes, so both are freed together and in the right order.
const DecodedTree = struct {
    tree: tree.RatchetTree,
    bytes: []u8,

    fn deinit(self: *DecodedTree, allocator: std.mem.Allocator) void {
        self.tree.deinit();
        allocator.free(self.bytes);
    }
};

fn decodeTree(allocator: std.mem.Allocator, hex: []const u8) !DecodedTree {
    const bytes = try hexDecode(allocator, hex);
    errdefer allocator.free(bytes);
    var r = codec.Reader.init(bytes);
    const t = try tree.RatchetTree.decode(allocator, &r);
    return .{ .tree = t, .bytes = bytes };
}

/// The provisional `GroupContext` (§8.1) the vector's sender sealed its
/// ciphertexts under, per upstream's `test-vectors.md` treekem procedure —
/// `tree_hash` is the per-update-path `tree_hash_after`. Identical to
/// `kat_treekem_test.zig`'s helper; duplicated rather than shared because
/// each KAT file in this module stands alone (see `kat_test.zig`).
fn buildGroupContext(
    allocator: std.mem.Allocator,
    group_id: []const u8,
    epoch: u64,
    tree_hash: []const u8,
    confirmed_transcript_hash: []const u8,
) ![]u8 {
    const total = 2 + 2 +
        wire.varintLen(group_id.len) + group_id.len +
        8 +
        wire.varintLen(tree_hash.len) + tree_hash.len +
        wire.varintLen(confirmed_transcript_hash.len) + confirmed_transcript_hash.len +
        1;
    const buf = try allocator.alloc(u8, total);
    errdefer allocator.free(buf);
    var w = codec.Writer.init(buf);
    try w.writeU16(1);
    try w.writeU16(1);
    try w.writeVector(group_id);
    try w.writeU64(epoch);
    try w.writeVector(tree_hash);
    try w.writeVector(confirmed_transcript_hash);
    try w.writeVector("");
    std.debug.assert(w.pos == total);
    return buf;
}

/// A leaf the generation side needs but the vector cannot supply: the
/// content of the committer's NEW `LeafNode`. Nothing anchored in this file
/// depends on it — see the module doc comment — so it is a fixed dummy, and
/// the signature key is deterministic so a failure reproduces.
const dummy_capabilities: tree.Capabilities = .{
    .versions = &.{1},
    .cipher_suites = &.{1},
    .extensions = &.{},
    .proposals = &.{},
    .credentials = &.{1},
};

fn freeProcessed(allocator: std.mem.Allocator, p: treekem.ProcessedUpdatePath) void {
    allocator.free(p.commit_secret);
    for (p.derived_path_secrets) |e| allocator.free(e.path_secret);
    allocator.free(p.derived_path_secrets);
}

// ── 1 + 2: generation seeded from the vector, sealed for the vector's own
// receivers ───────────────────────────────────────────────────────────────

test "treekem.json: an UpdatePath GENERATED from the vector's own path_secret[0] reproduces its node public keys, commit_secret and leaf parent_hash byte-exact (GATED)" {
    if (!gate.treekem_core_implemented) return error.SkipZigTest;

    var threaded = std.Io.Threaded.init(testing.allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();

    var parsed = try std.json.parseFromSlice(std.json.Value, testing.allocator, treekem_json, .{});
    defer parsed.deinit();

    const sig_kp = try S.Sig.KeyPair.generateDeterministic(@splat(0x77));

    var anchored_paths: usize = 0;
    var anchored_nodes: usize = 0;
    var round_trip_receivers: usize = 0;
    var total_paths: usize = 0;

    for (parsed.value.array.items) |entry| {
        const group_id = try hexDecode(testing.allocator, entry.object.get("group_id").?.string);
        defer testing.allocator.free(group_id);
        const epoch = try asU64(entry.object.get("epoch").?);
        const confirmed = try hexDecode(testing.allocator, entry.object.get("confirmed_transcript_hash").?.string);
        defer testing.allocator.free(confirmed);
        const ratchet_tree_hex = entry.object.get("ratchet_tree").?.string;
        const leaves_private = entry.object.get("leaves_private").?.array.items;

        for (entry.object.get("update_paths").?.array.items) |up_entry| {
            total_paths += 1;
            const sender: usize = @intCast(try asU64(up_entry.object.get("sender").?));
            const up_bytes = try hexDecode(testing.allocator, up_entry.object.get("update_path").?.string);
            defer testing.allocator.free(up_bytes);
            var upr = codec.Reader.init(up_bytes);
            const want_path = try treekem.UpdatePath.decode(testing.allocator, &upr);
            defer want_path.deinit(testing.allocator);

            const want_commit_secret = try hexDecode(testing.allocator, up_entry.object.get("commit_secret").?.string);
            defer testing.allocator.free(want_commit_secret);
            const tree_hash_after = try hexDecode(testing.allocator, up_entry.object.get("tree_hash_after").?.string);
            defer testing.allocator.free(tree_hash_after);
            const group_context = try buildGroupContext(testing.allocator, group_id, epoch, tree_hash_after, confirmed);
            defer testing.allocator.free(group_context);
            const up_path_secrets = up_entry.object.get("path_secrets").?.array.items;

            // `pristine` stays as the vector published it — that is the tree
            // a RECEIVER computes its resolutions against. `staging` is the
            // one the sender mutates.
            var pristine = try decodeTree(testing.allocator, ratchet_tree_hex);
            defer pristine.deinit(testing.allocator);
            var staging = try decodeTree(testing.allocator, ratchet_tree_hex);
            defer staging.deinit(testing.allocator);
            var arena = std.heap.ArenaAllocator.init(testing.allocator);
            defer arena.deinit();

            // Which leaf's recorded path secret is the sender's
            // `path_secret[0]`? The one whose OVERLAP is the first node of
            // the sender's filtered direct path — i.e. a leaf sitting under
            // that node's copath child. `treekem.json` carries no Add
            // proposals, so §7.5's excluded set is empty throughout — and
            // §4.1.2's filter never takes one anyway.
            const fdp = try treekem.filteredDirectPath(testing.allocator, &pristine.tree, 2 * sender);
            defer testing.allocator.free(fdp);
            var seed: ?[S.Nh]u8 = null;
            if (fdp.len > 0) {
                for (leaves_private) |lp| {
                    const idx: usize = @intCast(try asU64(lp.object.get("index").?));
                    if (idx == sender) continue;
                    if (!treekem.inSubtree(2 * idx, fdp[0].copath_child)) continue;
                    if (idx >= up_path_secrets.len) continue;
                    switch (up_path_secrets[idx]) {
                        .string => |hex| seed = try hexArray(S.Nh, hex),
                        else => {},
                    }
                    if (seed != null) break;
                }
            }
            // Every vector entry must yield a seed; if a future re-fetch
            // brought in a shape where none does, that would silently turn
            // this whole test into a round trip.
            const path_secret_0 = seed orelse return error.NoSeedableReceiverInVector;

            const staged = try treekem.stageUpdatePath(S, arena.allocator(), &staging.tree, sender, .{
                .group_id = group_id,
                .signature_key_pair = sig_kp,
                .leaf_key_pair = try S.Kem.KeyPair.generateDeterministic(@splat(0x5c)),
                .path_secret_0 = path_secret_0,
                .signature_key = &sig_kp.public_key.toBytes(),
                .credential = .{ .basic = "kat-committer" },
                .capabilities = dummy_capabilities,
            });

            // ── ANCHORED. The generated filtered direct path must have the
            // vector's own length, and every derived node_pub[n] must be the
            // key the vector announced at that position.
            try testing.expectEqual(want_path.nodes.len, staged.nodes.len);
            for (want_path.nodes, staged.nodes) |want, got| {
                try testing.expectEqualSlices(u8, want.encryption_key, got.public_key);
                anchored_nodes += 1;
            }
            // ── ANCHORED. commit_secret = DeriveSecret(path_secret[n],
            // "path").
            try testing.expectEqualSlices(u8, want_commit_secret, &staged.commit_secret);
            // ── ANCHORED. The committer leaf's parent hash, which by §7.9's
            // recursive ParentHashInput pins every parent hash the merge
            // wrote above it.
            try testing.expectEqualSlices(u8, want_path.leaf_node.parent_hash.?, staged.leaf_node.parent_hash.?);
            anchored_paths += 1;

            // ── ROUND TRIP over anchored ground: seal to the vector's real
            // members and require each of them to open it with its own
            // recorded keys and land on the vector's recorded secrets.
            const sealed = try treekem.sealUpdatePath(
                S,
                testing.allocator,
                io,
                &staging.tree,
                staged,
                group_context,
                &.{},
            );
            defer sealed.deinitSealed(testing.allocator);

            // The ciphertext COUNT per node is anchored too — it is the size
            // of the copath child's resolution, which is what §7.6 makes a
            // receiver index by.
            for (want_path.nodes, sealed.nodes) |want, got| {
                try testing.expectEqual(want.encrypted_path_secret.len, got.encrypted_path_secret.len);
            }

            for (leaves_private) |lp| {
                const receiver_index: usize = @intCast(try asU64(lp.object.get("index").?));
                if (receiver_index == sender) continue;
                const enc_priv = try hexDecode(testing.allocator, lp.object.get("encryption_priv").?.string);
                defer testing.allocator.free(enc_priv);

                const ps_json = lp.object.get("path_secrets").?.array.items;
                const known = try testing.allocator.alloc(treekem.PathSecretEntry, ps_json.len);
                defer {
                    for (known) |k| testing.allocator.free(@constCast(k.path_secret));
                    testing.allocator.free(known);
                }
                for (ps_json, known) |ps, *slot| {
                    slot.* = .{
                        .node = @intCast(try asU64(ps.object.get("node").?)),
                        .path_secret = try hexDecode(testing.allocator, ps.object.get("path_secret").?.string),
                    };
                }

                const processed = try treekem.processUpdatePath(S, testing.allocator, &pristine.tree, .{
                    .leaf_index = receiver_index,
                    .encryption_priv = enc_priv,
                    .known_path_secrets = known,
                }, sender, sealed, group_context, &.{});
                defer freeProcessed(testing.allocator, processed);

                try testing.expectEqualSlices(u8, want_commit_secret, processed.commit_secret);
                if (receiver_index < up_path_secrets.len) switch (up_path_secrets[receiver_index]) {
                    .string => |hex| {
                        const want_ps = try hexDecode(testing.allocator, hex);
                        defer testing.allocator.free(want_ps);
                        try testing.expect(processed.derived_path_secrets.len > 0);
                        try testing.expectEqualSlices(u8, want_ps, processed.derived_path_secrets[0].path_secret);
                    },
                    else => {},
                };
                round_trip_receivers += 1;
            }
        }
    }

    // The same 62 update paths `kat_treekem_test.zig` drives in the receive
    // direction, now driven in the send direction as well — and every one of
    // them anchored, not a subset.
    try testing.expectEqual(@as(usize, 62), total_paths);
    try testing.expectEqual(@as(usize, 62), anchored_paths);
    try testing.expectEqual(@as(usize, 328), round_trip_receivers);
    try testing.expect(anchored_nodes >= 100);
}

test "treekem.json: a generated UpdatePath is REJECTED when one derived key is corrupted (negative control)" {
    if (!gate.treekem_core_implemented) return error.SkipZigTest;

    var threaded = std.Io.Threaded.init(testing.allocator, .{});
    defer threaded.deinit();

    var parsed = try std.json.parseFromSlice(std.json.Value, testing.allocator, treekem_json, .{});
    defer parsed.deinit();

    // The check above compares this module's output with the vector's. That
    // only has teeth if a WRONG output would differ — so drive the same
    // generation from a path secret that is one bit off and require every
    // anchored comparison to fail.
    const entry = parsed.value.array.items[0].object;
    const up_entry = entry.get("update_paths").?.array.items[0].object;
    const sender: usize = @intCast(try asU64(up_entry.get("sender").?));

    const up_bytes = try hexDecode(testing.allocator, up_entry.get("update_path").?.string);
    defer testing.allocator.free(up_bytes);
    var upr = codec.Reader.init(up_bytes);
    const want_path = try treekem.UpdatePath.decode(testing.allocator, &upr);
    defer want_path.deinit(testing.allocator);
    const want_commit_secret = try hexDecode(testing.allocator, up_entry.get("commit_secret").?.string);
    defer testing.allocator.free(want_commit_secret);

    const group_id = try hexDecode(testing.allocator, entry.get("group_id").?.string);
    defer testing.allocator.free(group_id);

    var staging = try decodeTree(testing.allocator, entry.get("ratchet_tree").?.string);
    defer staging.deinit(testing.allocator);
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();

    const sig_kp = try S.Sig.KeyPair.generateDeterministic(@splat(0x77));
    var wrong_seed: [S.Nh]u8 = @splat(0xa5);
    wrong_seed[0] ^= 0x01;
    const staged = try treekem.stageUpdatePath(S, arena.allocator(), &staging.tree, sender, .{
        .group_id = group_id,
        .signature_key_pair = sig_kp,
        .leaf_key_pair = try S.Kem.KeyPair.generateDeterministic(@splat(0x5c)),
        .path_secret_0 = wrong_seed,
        .signature_key = &sig_kp.public_key.toBytes(),
        .credential = .{ .basic = "kat-committer" },
        .capabilities = dummy_capabilities,
    });

    // The FILTER is a property of the tree, so the shape still matches — it
    // is the derived material that must not.
    try testing.expectEqual(want_path.nodes.len, staged.nodes.len);
    try testing.expect(!std.mem.eql(u8, want_commit_secret, &staged.commit_secret));
    for (want_path.nodes, staged.nodes) |want, got| {
        try testing.expect(!std.mem.eql(u8, want.encryption_key, got.public_key));
    }
    // ... while the parent hashes, which do NOT depend on the path secrets
    // (only on the derived public keys), must differ for exactly that
    // reason — a control that the leaf parent_hash comparison is measuring
    // the merge and not a constant.
    try testing.expect(!std.mem.eql(u8, want_path.leaf_node.parent_hash.?, staged.leaf_node.parent_hash.?));
}

// ── 3: creating a Commit on top of a recorded session ─────────────────────

/// A fresh joiner: a `KeyPackage` plus the private halves, all allocated
/// from `arena`.
const Newcomer = struct {
    kp: keypackage.KeyPackage,
    kp_msg: []u8,
    init_priv: [S.Kem.Nsk]u8,
    enc_priv: [S.Kem.Nsk]u8,

    fn init(arena: std.mem.Allocator, seed: u8) !Newcomer {
        const sig = try S.Sig.KeyPair.generateDeterministic(@splat(seed));
        const init_kp = try S.Kem.KeyPair.generateDeterministic(@splat(seed +% 64));
        const enc_kp = try S.Kem.KeyPair.generateDeterministic(@splat(seed +% 128));
        const kp = try keypackage.create(S, arena, .{
            .signature_key_pair = sig,
            .init_key = init_kp.public_key,
            .encryption_key = enc_kp.public_key,
            .credential = .{ .basic = "newcomer" },
            .capabilities = dummy_capabilities,
            .lifetime = .{ .not_before = 0, .not_after = std.math.maxInt(u64) },
        });
        const msg: framing.MLSMessage = .{ .key_package = kp };
        return .{
            .kp = kp,
            .kp_msg = try msg.encodeAlloc(arena),
            .init_priv = init_kp.secret_key,
            .enc_priv = enc_kp.secret_key,
        };
    }
};

/// Replay one recorded session exactly as `kat_passive_test.zig` does, then
/// hand back the live group and the signing key the recorded client owns.
fn replay(gpa: std.mem.Allocator, sa: std.mem.Allocator, obj: std.json.ObjectMap) !struct {
    g: G,
    sig: S.Sig.KeyPair,
    psks: []const group.ExternalPsk,
} {
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

    var g = try G.fromWelcome(gpa, .{
        .welcome_msg = welcome_msg,
        .key_package_msg = key_package_msg,
        .init_priv = init_priv,
        .encryption_priv = encryption_priv,
        .ratchet_tree = ratchet_tree,
        .external_psks = psks.items,
    });
    errdefer g.deinit();

    for (obj.get("epochs").?.array.items) |epoch_value| {
        const epoch = epoch_value.object;
        var proposals: std.ArrayList([]const u8) = .empty;
        for (epoch.get("proposals").?.array.items) |p| {
            try proposals.append(sa, try hexDecode(sa, p.string));
        }
        try g.processCommit(.{
            .commit_msg = try hexDecode(sa, epoch.get("commit").?.string),
            .proposal_msgs = proposals.items,
            .external_psks = psks.items,
        });
    }
    // The replay's own anchor is asserted in `kat_passive_test.zig`; this
    // one only needs the state it produced, but the LAST authenticator is
    // re-checked here so a silently-diverged replay cannot make the
    // creation test look meaningful.
    const epochs = obj.get("epochs").?.array.items;
    if (epochs.len > 0) {
        const want = try hexDecode(sa, epochs[epochs.len - 1].object.get("epoch_authenticator").?.string);
        try testing.expectEqualSlices(u8, want, &g.epochAuthenticator());
    }
    return .{ .g = g, .sig = try S.Sig.KeyPair.generateDeterministic(signature_priv), .psks = psks.items };
}

/// Commit from a group state produced by another implementation, add a new
/// member, and require the joiner to derive the committer's epoch.
fn commitFromReplayedState(gpa: std.mem.Allocator, obj: std.json.ObjectMap, seed: u8) !void {
    var threaded = std.Io.Threaded.init(gpa, .{});
    defer threaded.deinit();
    const io = threaded.io();

    var scratch = std.heap.ArenaAllocator.init(gpa);
    defer scratch.deinit();
    const sa = scratch.allocator();

    const replayed = try replay(gpa, sa, obj);
    var g = replayed.g;
    defer g.deinit();

    const before_epoch = g.epoch;
    const before_size = g.treeSize();
    const newcomer = try Newcomer.init(sa, seed);

    const created = try g.createCommit(gpa, .{
        .io = io,
        .signature_key_pair = replayed.sig,
        .proposals = &.{.{ .by_value = .{ .add = newcomer.kp } }},
        .external_psks = replayed.psks,
    });
    defer created.deinit(gpa);

    try testing.expectEqual(before_epoch + 1, g.epoch);
    try testing.expect(g.treeSize() >= before_size);
    try testing.expect(created.welcome != null);

    var joined = try G.fromWelcome(gpa, .{
        .welcome_msg = created.welcome.?,
        .key_package_msg = newcomer.kp_msg,
        .init_priv = newcomer.init_priv,
        .encryption_priv = newcomer.enc_priv,
        .external_psks = replayed.psks,
    });
    defer joined.deinit();

    // `fromWelcome` verified the tree hash, the whole §7.9.2 parent-hash
    // chain, the GroupInfo signature and the confirmation tag before
    // getting here — over a tree that the Commit just rewrote. The
    // authenticator is the derived value that ties it all together.
    try testing.expectEqual(g.epoch, joined.epoch);
    try testing.expectEqualSlices(u8, &g.tree_hash, &joined.tree_hash);
    try testing.expectEqualSlices(u8, &g.epochAuthenticator(), &joined.epochAuthenticator());

    // Two more epochs, one from each side. This is where the joiner's
    // PRIVATE state gets exercised rather than merely constructed: the
    // next Commit from the original member encrypts to resolutions that
    // include nodes the joiner only holds because §12.4.3.1's `path_secret`
    // was expanded correctly up the committer's FILTERED direct path.
    // Recorded trees are the ones worth doing this on — they carry the
    // blank nodes and unmerged leaves a synthetic group never accumulates.
    {
        const c2 = try g.createCommit(gpa, .{
            .io = io,
            .signature_key_pair = replayed.sig,
            .external_psks = replayed.psks,
        });
        defer c2.deinit(gpa);
        try joined.processCommit(.{ .commit_msg = c2.commit, .external_psks = replayed.psks });
        try testing.expectEqualSlices(u8, &g.epochAuthenticator(), &joined.epochAuthenticator());
    }
    {
        const c3 = try joined.createCommit(gpa, .{
            .io = io,
            .signature_key_pair = try S.Sig.KeyPair.generateDeterministic(@splat(seed)),
            .external_psks = replayed.psks,
        });
        defer c3.deinit(gpa);
        try g.processCommit(.{ .commit_msg = c3.commit, .external_psks = replayed.psks });
        try testing.expectEqualSlices(u8, &g.epochAuthenticator(), &joined.epochAuthenticator());
    }
}

test "passive-client-handling-commit.json: commit from each replayed session's final state and land a new member in the same epoch" {
    var parsed = try std.json.parseFromSlice(std.json.Value, testing.allocator, handling_commit_json, .{});
    defer parsed.deinit();

    var runs: usize = 0;
    for (parsed.value.array.items, 0..) |entry, i| {
        commitFromReplayedState(testing.allocator, entry.object, @intCast(0x30 + i)) catch |err| {
            std.debug.print("commit-from-replay [handling-commit] entry {d}: {s}\n", .{ i, @errorName(err) });
            return err;
        };
        runs += 1;
    }
    try testing.expect(runs > 0);
}

test "passive-client-random.json: commit from the 200-Commit session's final state — a real 100-plus-leaf tree, not a synthetic one" {
    var parsed = try std.json.parseFromSlice(std.json.Value, testing.allocator, random_json, .{});
    defer parsed.deinit();
    const items = parsed.value.array.items;
    try testing.expectEqual(@as(usize, 1), items.len);

    // The value of THIS one over the shorter sessions is the tree: 200
    // Commits of adds, removes and updates leave blank nodes, unmerged
    // leaves and deep filtered direct paths that no hand-built group
    // reaches. Generating an UpdatePath over it exercises the §4.1.2 filter
    // and the copath resolutions at a scale the synthetic tests cannot.
    var g_before: usize = 0;
    {
        var scratch = std.heap.ArenaAllocator.init(testing.allocator);
        defer scratch.deinit();
        var replayed = try replay(testing.allocator, scratch.allocator(), items[0].object);
        defer replayed.g.deinit();
        g_before = replayed.g.treeSize();
    }
    try testing.expect(g_before >= 16);

    try commitFromReplayedState(testing.allocator, items[0].object, 0x91);
}
