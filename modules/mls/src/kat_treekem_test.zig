// SPDX-License-Identifier: MIT
//! mls.kat_treekem_test — **Part 2**'s KAT harness: the official RFC 9420
//! interop vectors `tree-validation.json`/`tree-operations.json`/
//! `treekem.json`, embedded (filtered to cipher suite `0x0001` — see
//! `NOTICE`) and driven end-to-end against `tree.zig`/`treehash.zig`/
//! `treekem.zig`. Mirrors Part 1's `kat_test.zig` shape (generic
//! `std.json.Value` navigation, not typed structs — see that file's
//! module doc comment for why) plus this Part's own allocator-owning
//! decode convention (`tree.zig`'s module doc comment).
//!
//! **Real vs. gated, at a glance** (see `gate.zig`):
//!   * `tree-validation.json`'s tree-hash and leaf-signature checks (plus
//!     a tampered-signature NEGATIVE control) — REAL, ungated.
//!   * `tree-validation.json`'s resolution/parent-hash-chain checks —
//!     GATED (`resolution`/`validateParentHashes` Fable cores).
//!   * `tree-operations.json`'s whole Add/Update/Remove-application run —
//!     REAL, ungated (§7.7/§12.1.1-§12.1.3 tree-editing is mechanical, NOT
//!     one of the five Fable cores — see `tree.zig`'s module doc comment).
//!     Uses a MINIMAL test-local `Proposal`/`KeyPackage` parser (full
//!     `KeyPackage`/`Proposal` types are Part 3/5's public API per
//!     `SPEC.md` — this Part only needs to pull a `LeafNode`/leaf-index
//!     out of the wire bytes to drive `RatchetTree.addLeaf`/`updateLeaf`/
//!     `removeLeaf`).
//!   * `treekem.json` (the UpdatePath/path-secret/commit-secret vector) —
//!     GATED in full (`processUpdatePath` Fable core).
//!
//! Model: RFC 9420 §7.8 (tree hash)/§7.2-§7.3 (leaf signature)/§7.7,
//! §12.1.1-§12.1.3 (tree-operations application)/§7.4-§7.6 (treekem.json).
//! KAT provenance: see `NOTICE`.

const std = @import("std");
const codec = @import("codec.zig");
const suite = @import("suite.zig");
const tree = @import("tree.zig");
const treehash = @import("treehash.zig");
const treekem = @import("treekem.zig");
const wire = @import("wire_lists.zig");
const gate = @import("gate.zig");

const tree_validation_json = @embedFile("data/tree-validation.json");
const tree_operations_json = @embedFile("data/tree-operations.json");
const treekem_json = @embedFile("data/treekem.json");

const testing = std.testing;
const S = suite.default;

fn hexDecode(allocator: std.mem.Allocator, hex: []const u8) ![]u8 {
    const out = try allocator.alloc(u8, hex.len / 2);
    _ = try std.fmt.hexToBytes(out, hex);
    return out;
}

fn asI64(v: std.json.Value) i64 {
    return switch (v) {
        .integer => |i| i,
        else => unreachable,
    };
}

/// `tree.RatchetTree.decode`'s `LeafNode`/`ParentNode` fields ALIAS the
/// input buffer (`tree.zig`'s no-copy convention, matching `codec.Reader`)
/// — so the hex-decoded wire bytes must outlive the tree. Bundled here so
/// every call site frees them in the right order (`tree` first, then
/// `bytes`) via one `deinit`, instead of each test having to remember the
/// ordering by hand (an earlier version of this harness freed `bytes`
/// immediately inside a `decodeTree` helper via `defer`, before the
/// caller ever touched the returned tree — a use-after-free the
/// `DebugAllocator`'s 0xAA free-poison pattern caught immediately once a
/// test actually read a `LeafNode` field).
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

// ── tree-validation.json: tree hash (REAL) ───────────────────────────────

test "tree-validation.json: tree hash of every node index is byte-exact (ungated — treehash.zig is real)" {
    var parsed = try std.json.parseFromSlice(std.json.Value, testing.allocator, tree_validation_json, .{});
    defer parsed.deinit();

    var checked: usize = 0;
    for (parsed.value.array.items) |entry| {
        var dt = try decodeTree(testing.allocator, entry.object.get("tree").?.string);
        defer dt.deinit(testing.allocator);

        const hashes = entry.object.get("tree_hashes").?.array.items;
        try testing.expectEqual(dt.tree.nodes.len, hashes.len);

        var idx: usize = 0;
        while (idx < dt.tree.nodes.len) : (idx += 1) {
            const want = try hexDecode(testing.allocator, hashes[idx].string);
            defer testing.allocator.free(want);
            const got = try treehash.treeHash(S, testing.allocator, &dt.tree, idx);
            try testing.expectEqualSlices(u8, want, &got);
            checked += 1;
        }
    }
    // 14 suite-0x0001 trees, 3..127 nodes each (see NOTICE) — sanity that
    // this ran over real ground, not a vacuously-empty vector list.
    try testing.expect(checked >= 300);
}

// ── tree-validation.json: leaf signatures (REAL) ─────────────────────────

test "tree-validation.json: every leaf's signature verifies against the vector's group_id (ungated)" {
    var parsed = try std.json.parseFromSlice(std.json.Value, testing.allocator, tree_validation_json, .{});
    defer parsed.deinit();

    var checked: usize = 0;
    for (parsed.value.array.items) |entry| {
        var dt = try decodeTree(testing.allocator, entry.object.get("tree").?.string);
        defer dt.deinit(testing.allocator);
        const group_id = try hexDecode(testing.allocator, entry.object.get("group_id").?.string);
        defer testing.allocator.free(group_id);

        var idx: usize = 0;
        while (idx < dt.tree.nodes.len) : (idx += 2) {
            const node = dt.tree.nodes[idx] orelse continue;
            const leaf = switch (node) {
                .leaf => |l| l,
                .parent => return error.Malformed,
            };
            try leaf.verifySignature(S, testing.allocator, group_id, @intCast(idx / 2));
            checked += 1;
        }
    }
    try testing.expect(checked >= 150); // 161 leaves total across the 14 suite-0x0001 trees
}

test "tree-validation.json: a tampered LeafNode (TBS content) fails signature verification (ungated, negative control)" {
    var parsed = try std.json.parseFromSlice(std.json.Value, testing.allocator, tree_validation_json, .{});
    defer parsed.deinit();
    const entry = parsed.value.array.items[0];

    var dt = try decodeTree(testing.allocator, entry.object.get("tree").?.string);
    defer dt.deinit(testing.allocator);
    const group_id = try hexDecode(testing.allocator, entry.object.get("group_id").?.string);
    defer testing.allocator.free(group_id);

    var idx: usize = 0;
    while (idx < dt.tree.nodes.len) : (idx += 2) {
        const node = dt.tree.nodes[idx] orelse continue;
        var leaf = switch (node) {
            .leaf => |l| l,
            .parent => return error.Malformed,
        };
        // Tamper a byte of `encryption_key` (part of the SIGNED content,
        // LeafNodeTBS, but structurally opaque — flipping a bit here
        // can't produce an invalid Ed25519 POINT/SCALAR encoding the way
        // tampering `signature` itself risks, so this negative control
        // deterministically lands on SignatureVerificationFailed rather
        // than a curve-decoding error).
        var tampered = try testing.allocator.dupe(u8, leaf.encryption_key);
        defer testing.allocator.free(tampered);
        tampered[0] ^= 0x01;
        leaf.encryption_key = tampered;
        try testing.expectError(error.SignatureVerificationFailed, leaf.verifySignature(S, testing.allocator, group_id, @intCast(idx / 2)));
        return;
    }
    return error.NoLeafFoundInVector;
}

// ── tree-validation.json: resolution / parent-hash chain (GATED) ────────

test "tree-validation.json: resolution(tree, i) matches for every node (GATED — resolution is a Fable core)" {
    if (!gate.treekem_core_implemented) return error.SkipZigTest;

    var parsed = try std.json.parseFromSlice(std.json.Value, testing.allocator, tree_validation_json, .{});
    defer parsed.deinit();

    for (parsed.value.array.items) |entry| {
        var dt = try decodeTree(testing.allocator, entry.object.get("tree").?.string);
        defer dt.deinit(testing.allocator);
        const resolutions = entry.object.get("resolutions").?.array.items;

        var idx: usize = 0;
        while (idx < dt.tree.nodes.len) : (idx += 1) {
            const got = try treekem.resolution(testing.allocator, &dt.tree, idx);
            defer testing.allocator.free(got);
            const want = resolutions[idx].array.items;
            try testing.expectEqual(want.len, got.len);
            for (want, got) |w, g| try testing.expectEqual(@as(usize, @intCast(asI64(w))), g);
        }
    }
}

test "tree-validation.json: validateParentHashes accepts all well-formed trees and rejects EVERY single-byte parent_hash tamper (GATED)" {
    if (!gate.treekem_core_implemented) return error.SkipZigTest;

    var parsed = try std.json.parseFromSlice(std.json.Value, testing.allocator, tree_validation_json, .{});
    defer parsed.deinit();

    var trees_accepted: usize = 0;
    var tampers_rejected: usize = 0;
    for (parsed.value.array.items) |entry| {
        var dt = try decodeTree(testing.allocator, entry.object.get("tree").?.string);
        defer dt.deinit(testing.allocator);

        // Positive: the well-formed tree's whole §7.9.2 parent-hash chain
        // must verify.
        try treekem.validateParentHashes(S, testing.allocator, &dt.tree);
        trees_accepted += 1;

        // Negative: flip one byte of EVERY parent_hash the §7.9.2 chain
        // covers — every non-blank ParentNode's `parent_hash` AND every
        // commit-source LeafNode's `parent_hash` — and require rejection
        // each time, restoring the field afterwards so every tamper is
        // exercised against an otherwise-pristine tree. (The original
        // harness stopped after the first parent — and indexed
        // `tampered[0]` on the root's zero-length hash, an OOB panic before
        // the algorithm ran at all.) The root's parent_hash is the
        // zero-length string (§7.5) and has no byte to flip, so it is
        // skipped.
        var idx: usize = 0;
        while (idx < dt.tree.nodes.len) : (idx += 1) {
            const node = dt.tree.nodes[idx] orelse continue;
            const orig_ph: []const u8 = switch (node) {
                .parent => |p| p.parent_hash,
                .leaf => |l| if (l.leaf_node_source == .commit and l.parent_hash != null) l.parent_hash.? else continue,
            };
            if (orig_ph.len == 0) continue; // root's (or a placeholder's) zero-length hash: nothing to flip

            const tampered = try testing.allocator.dupe(u8, orig_ph);
            defer testing.allocator.free(tampered);
            tampered[0] ^= 0x01;
            switch (node) {
                .parent => |p| {
                    var tp = p;
                    tp.parent_hash = tampered;
                    dt.tree.nodes[idx] = .{ .parent = tp };
                },
                .leaf => |l| {
                    var tl = l;
                    tl.parent_hash = tampered;
                    dt.tree.nodes[idx] = .{ .leaf = tl };
                },
            }
            try testing.expectError(error.Malformed, treekem.validateParentHashes(S, testing.allocator, &dt.tree));
            tampers_rejected += 1;

            // Restore the original (aliased) field for the next iteration.
            dt.tree.nodes[idx] = node;
        }

        // Sanity: after restoring every tampered field the tree validates
        // again (proves the restore path, not just the tamper path).
        try treekem.validateParentHashes(S, testing.allocator, &dt.tree);
    }
    try testing.expectEqual(@as(usize, 14), trees_accepted); // 14 suite-0x0001 trees (see NOTICE)
    // One tamper per parent_hash the §7.9.2 chain covers across all 14
    // trees: every non-blank, non-root ParentNode plus every commit-source
    // LeafNode — every one must be REJECTED (a superset of the 145 the
    // Fable scratch driver proved, which covered parent nodes alone).
    try testing.expectEqual(@as(usize, 275), tampers_rejected);
}

// ── tree-operations.json: Add/Update/Remove application (REAL) ──────────

const LocalProposalType = enum(u16) { add = 1, update = 2, remove = 3, _ };

/// Test-local, minimal `Proposal`/`KeyPackage` decode — see this file's
/// module doc comment for why this isn't part of `tree.zig`'s public API.
fn applyProposal(allocator: std.mem.Allocator, t: *tree.RatchetTree, proposal_bytes: []const u8, sender: u32) !void {
    var r = codec.Reader.init(proposal_bytes);
    const ptype = try r.readEnum(LocalProposalType);
    switch (ptype) {
        .add => {
            _ = try r.readU16(); // KeyPackage.version
            _ = try r.readU16(); // KeyPackage.cipher_suite
            _ = try r.readVector(); // KeyPackage.init_key
            const leaf = try tree.LeafNode.decode(allocator, &r);
            const kp_exts = try tree.decodeExtensionList(allocator, &r); // KeyPackage.extensions
            allocator.free(kp_exts);
            _ = try r.readVector(); // KeyPackage.signature
            _ = try t.addLeaf(leaf);
        },
        .update => {
            const leaf = try tree.LeafNode.decode(allocator, &r);
            try t.updateLeaf(sender, leaf);
        },
        .remove => {
            const removed = try r.readU32();
            try t.removeLeaf(removed);
        },
        else => return error.UnsupportedProposalType,
    }
}

test "tree-operations.json: applying add/update/remove reproduces tree_after byte-exact (ungated — mechanical tree editing, not a Fable core)" {
    var parsed = try std.json.parseFromSlice(std.json.Value, testing.allocator, tree_operations_json, .{});
    defer parsed.deinit();

    var checked: usize = 0;
    for (parsed.value.array.items) |entry| {
        var dt = try decodeTree(testing.allocator, entry.object.get("tree_before").?.string);
        defer dt.deinit(testing.allocator);

        const tree_hash_before = try hexDecode(testing.allocator, entry.object.get("tree_hash_before").?.string);
        defer testing.allocator.free(tree_hash_before);
        const got_before = try treehash.rootHash(S, testing.allocator, &dt.tree);
        try testing.expectEqualSlices(u8, tree_hash_before, &got_before);

        const proposal_bytes = try hexDecode(testing.allocator, entry.object.get("proposal").?.string);
        defer testing.allocator.free(proposal_bytes);
        const sender: u32 = @intCast(asI64(entry.object.get("proposal_sender").?));
        try applyProposal(testing.allocator, &dt.tree, proposal_bytes, sender);

        const got_tree_after = try dt.tree.encode(testing.allocator);
        defer testing.allocator.free(got_tree_after);
        const want_tree_after = try hexDecode(testing.allocator, entry.object.get("tree_after").?.string);
        defer testing.allocator.free(want_tree_after);
        try testing.expectEqualSlices(u8, want_tree_after, got_tree_after);

        const tree_hash_after = try hexDecode(testing.allocator, entry.object.get("tree_hash_after").?.string);
        defer testing.allocator.free(tree_hash_after);
        const got_after = try treehash.rootHash(S, testing.allocator, &dt.tree);
        try testing.expectEqualSlices(u8, tree_hash_after, &got_after);

        checked += 1;
    }
    try testing.expectEqual(@as(usize, 5), checked); // 5 suite-0x0001 vectors, see NOTICE
}

// ── treekem.json: UpdatePath / path secrets / commit secret (GATED) ─────

fn asU64(v: std.json.Value) !u64 {
    return switch (v) {
        .integer => |i| @intCast(i),
        .number_string => |s| try std.fmt.parseInt(u64, s, 10),
        else => error.Malformed,
    };
}

/// The **provisional GroupContext** (RFC 9420 §8.1) the sender sealed the
/// UpdatePath ciphertexts under, and therefore the exact `context` bytes
/// `processUpdatePath` must hand to `DecryptWithLabel` (HPKE `info`). Per
/// the mlswg `test-vectors.md` treekem procedure, `tree_hash` is the tree
/// hash *after* the UpdatePath is applied — the per-update-path
/// `tree_hash_after` field, NOT the initial `ratchet_tree`'s hash. Any
/// other value (e.g. the empty string the pre-fix harness passed) makes the
/// very first AEAD open fail `AuthenticationFailed` regardless of whether
/// `processUpdatePath` is correct.
///
/// ```
/// struct {
///     ProtocolVersion version = mls10;   // uint16 1
///     CipherSuite cipher_suite;          // uint16 1 (0x0001)
///     opaque group_id<V>;
///     uint64 epoch;
///     opaque tree_hash<V>;               // = tree_hash_after
///     opaque confirmed_transcript_hash<V>;
///     Extension extensions<V>;           // empty
/// } GroupContext;
/// ```
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
        1; // empty extensions vector = varint(0), one byte
    const buf = try allocator.alloc(u8, total);
    errdefer allocator.free(buf);
    var w = codec.Writer.init(buf);
    try w.writeU16(1); // ProtocolVersion mls10
    try w.writeU16(1); // CipherSuite 0x0001
    try w.writeVector(group_id);
    try w.writeU64(epoch);
    try w.writeVector(tree_hash);
    try w.writeVector(confirmed_transcript_hash);
    try w.writeVector(""); // extensions<V>: empty
    std.debug.assert(w.pos == total);
    return buf;
}

fn freeProcessed(allocator: std.mem.Allocator, p: treekem.ProcessedUpdatePath) void {
    allocator.free(p.commit_secret);
    for (p.derived_path_secrets) |e| allocator.free(e.path_secret);
    allocator.free(p.derived_path_secrets);
}

test "treekem.json: processUpdatePath yields byte-exact commit_secret + first path_secret for every receiver view under the provisional GroupContext; UpdatePath round-trips byte-exact (GATED — processUpdatePath is a Fable core)" {
    if (!gate.treekem_core_implemented) return error.SkipZigTest;

    var parsed = try std.json.parseFromSlice(std.json.Value, testing.allocator, treekem_json, .{});
    defer parsed.deinit();

    var checked_paths: usize = 0;
    var checked_receivers: usize = 0;
    for (parsed.value.array.items) |entry| {
        var dt = try decodeTree(testing.allocator, entry.object.get("ratchet_tree").?.string);
        defer dt.deinit(testing.allocator);

        const group_id = try hexDecode(testing.allocator, entry.object.get("group_id").?.string);
        defer testing.allocator.free(group_id);
        const epoch = try asU64(entry.object.get("epoch").?);
        const confirmed = try hexDecode(testing.allocator, entry.object.get("confirmed_transcript_hash").?.string);
        defer testing.allocator.free(confirmed);

        const leaves_private = entry.object.get("leaves_private").?.array.items;
        const update_paths = entry.object.get("update_paths").?.array.items;

        for (update_paths) |up_entry| {
            const sender: usize = @intCast(asI64(up_entry.object.get("sender").?));
            const up_bytes = try hexDecode(testing.allocator, up_entry.object.get("update_path").?.string);
            defer testing.allocator.free(up_bytes);
            var r = codec.Reader.init(up_bytes);
            const update_path = try treekem.UpdatePath.decode(testing.allocator, &r);
            defer update_path.deinit(testing.allocator);

            // Byte-exact wire round-trip: re-encoding the decoded UpdatePath
            // must reproduce the vector's bytes exactly (proves the §7.6
            // codec both ways, not just decode).
            const reencoded = try testing.allocator.alloc(u8, update_path.encodedLen());
            defer testing.allocator.free(reencoded);
            var w = codec.Writer.init(reencoded);
            try update_path.encode(&w);
            try testing.expectEqualSlices(u8, up_bytes, w.finish());

            const want_commit_secret = try hexDecode(testing.allocator, up_entry.object.get("commit_secret").?.string);
            defer testing.allocator.free(want_commit_secret);

            // The provisional GroupContext uses THIS update path's
            // tree_hash_after (the tree hash after it is applied).
            const tree_hash_after = try hexDecode(testing.allocator, up_entry.object.get("tree_hash_after").?.string);
            defer testing.allocator.free(tree_hash_after);
            const group_context = try buildGroupContext(testing.allocator, group_id, epoch, tree_hash_after, confirmed);
            defer testing.allocator.free(group_context);

            // path_secrets[] is indexed by leaf: null for the sender, else
            // the path secret that leaf decrypts at its overlap node
            // (path_secret[0] of the chain it walks up).
            const up_path_secrets = up_entry.object.get("path_secrets").?.array.items;

            for (leaves_private) |lp| {
                const receiver_index: usize = @intCast(asI64(lp.object.get("index").?));
                if (receiver_index == sender) continue;
                const enc_priv = try hexDecode(testing.allocator, lp.object.get("encryption_priv").?.string);
                defer testing.allocator.free(enc_priv);

                // Seed the receiver's prior-epoch private state from the
                // vector's leaves_private[receiver].path_secrets (each a
                // {node, path_secret}). processUpdatePath needs these to
                // find a decryptable resolution entry whenever the receiver
                // is covered by an ANCESTOR (not its own leaf) in the
                // copath child's resolution.
                const ps_json = lp.object.get("path_secrets").?.array.items;
                const known = try testing.allocator.alloc(treekem.PathSecretEntry, ps_json.len);
                defer {
                    for (known) |k| testing.allocator.free(@constCast(k.path_secret));
                    testing.allocator.free(known);
                }
                for (ps_json, 0..) |ps, i| {
                    const node: usize = @intCast(try asU64(ps.object.get("node").?));
                    const secret = try hexDecode(testing.allocator, ps.object.get("path_secret").?.string);
                    known[i] = .{ .node = node, .path_secret = secret };
                }

                const receiver: treekem.PrivateLeafState = .{
                    .leaf_index = receiver_index,
                    .encryption_priv = enc_priv,
                    .known_path_secrets = known,
                };
                const processed = try treekem.processUpdatePath(S, testing.allocator, &dt.tree, receiver, sender, update_path, group_context);
                defer freeProcessed(testing.allocator, processed);

                // commit_secret = path_secret[n+1] (one DeriveSecret(·,
                // "path") past the root secret, RFC §12.4.2) — byte-exact.
                try testing.expectEqualSlices(u8, want_commit_secret, processed.commit_secret);

                // The receiver's first derived (decrypted) path secret must
                // equal the vector's path_secrets[receiver], when present.
                if (receiver_index < up_path_secrets.len) {
                    switch (up_path_secrets[receiver_index]) {
                        .string => |hex| {
                            const want_ps = try hexDecode(testing.allocator, hex);
                            defer testing.allocator.free(want_ps);
                            try testing.expect(processed.derived_path_secrets.len > 0);
                            try testing.expectEqualSlices(u8, want_ps, processed.derived_path_secrets[0].path_secret);
                        },
                        .null => {},
                        else => return error.Malformed,
                    }
                }
                checked_receivers += 1;
            }
            checked_paths += 1;
        }
    }
    try testing.expectEqual(@as(usize, 62), checked_paths); // 62 update paths across 11 suite-0x0001 entries
    try testing.expectEqual(@as(usize, 328), checked_receivers); // 328 receiver views total
}

test "treekem.json: applyUpdatePath merges each UpdatePath into the public tree and reproduces tree_hash_after byte-exact (GATED — applyUpdatePath is a Fable core)" {
    if (!gate.treekem_core_implemented) return error.SkipZigTest;

    var parsed = try std.json.parseFromSlice(std.json.Value, testing.allocator, treekem_json, .{});
    defer parsed.deinit();

    var checked: usize = 0;
    for (parsed.value.array.items) |entry| {
        const ratchet_tree_hex = entry.object.get("ratchet_tree").?.string;
        const update_paths = entry.object.get("update_paths").?.array.items;

        for (update_paths) |up_entry| {
            const sender: usize = @intCast(asI64(up_entry.object.get("sender").?));
            const up_bytes = try hexDecode(testing.allocator, up_entry.object.get("update_path").?.string);
            defer testing.allocator.free(up_bytes);
            var r = codec.Reader.init(up_bytes);
            const update_path = try treekem.UpdatePath.decode(testing.allocator, &r);
            defer update_path.deinit(testing.allocator);

            const want_tree_hash_after = try hexDecode(testing.allocator, up_entry.object.get("tree_hash_after").?.string);
            defer testing.allocator.free(want_tree_hash_after);

            // A FRESH mutable copy of the tree — applyUpdatePath mutates in
            // place (blanks the sender's direct path, adopts the new leaf +
            // filtered-path keys, recomputes parent hashes root→leaf, and
            // enforces the committer leaf's `parent_hash == parentHash(leaf)`
            // §7.9.2 check). The parent-hash digests it stores are NOT owned
            // by the tree (`ParentNode.deinit` frees only `unmerged_leaves`);
            // an arena collects them exactly as `applyUpdatePath`'s doc
            // comment prescribes. Defer order (LIFO) frees the arena, then
            // the tree, then `update_path`/`up_bytes` — so the tree's
            // freshly-adopted nodes (whose `encryption_key`/leaf bytes alias
            // `up_bytes`) are torn down before the buffers they alias.
            var dt = try decodeTree(testing.allocator, ratchet_tree_hex);
            defer dt.deinit(testing.allocator);
            var arena = std.heap.ArenaAllocator.init(testing.allocator);
            defer arena.deinit();

            try treekem.applyUpdatePath(arena.allocator(), &dt.tree, sender, update_path);

            const got = try treehash.rootHash(S, testing.allocator, &dt.tree);
            try testing.expectEqualSlices(u8, want_tree_hash_after, &got);
            checked += 1;
        }
    }
    try testing.expectEqual(@as(usize, 62), checked); // all 62 update paths merged
}
