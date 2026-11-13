// SPDX-License-Identifier: MIT
//! BIP371 taproot fields: the BIP's own valid/invalid PSBTs, typed accessors and setters.
const std = @import("std");
const testing = std.testing;
const Allocator = std.mem.Allocator;
const psbt = @import("root.zig");
const bip371 = psbt.bip371;
const vec = @import("bip_vectors.zig");

fn unhex(allocator: Allocator, hex: []const u8) ![]u8 {
    const out = try allocator.alloc(u8, hex.len / 2);
    _ = try std.fmt.hexToBytes(out, hex);
    return out;
}

fn key32(hex: []const u8) [32]u8 {
    var b: [32]u8 = undefined;
    _ = std.fmt.hexToBytes(&b, hex) catch unreachable;
    return b;
}

test "BIP371 invalid vectors: each is refused with the error for its defect" {
    const a = testing.allocator;
    // Order of the BIP371 "invalid PSBTs" list.
    const want = [_]anyerror{
        error.InvalidFixedFieldLength, // IN_TAP_INTERNAL_KEY value too long (33-byte DER key)
        error.InvalidFixedFieldLength, // IN_TAP_KEY_SIG too short
        error.InvalidFixedFieldLength, // IN_TAP_KEY_SIG too long
        error.InvalidKeyDataLength, // IN_TAP_BIP32_DERIVATION key too long
        error.InvalidFixedFieldLength, // OUT_TAP_INTERNAL_KEY value too long
        error.InvalidKeyDataLength, // OUT_TAP_BIP32_DERIVATION key too long
        error.InvalidKeyDataLength, // IN_TAP_SCRIPT_SIG key too long
        error.InvalidFixedFieldLength, // IN_TAP_SCRIPT_SIG signature too long
        error.InvalidFixedFieldLength, // IN_TAP_SCRIPT_SIG signature too short
        error.InvalidKeyDataLength, // IN_TAP_LEAF_SCRIPT control block too long
        error.InvalidKeyDataLength, // IN_TAP_LEAF_SCRIPT control block too short
    };
    try testing.expectEqual(want.len, vec.bip371_invalid.len);
    for (vec.bip371_invalid, want) |c, e| {
        const bytes = try unhex(a, c.hex);
        defer a.free(bytes);
        try testing.expectError(e, psbt.parse(a, bytes));
        // and through Base64 as well
        try testing.expectError(e, psbt.fromBase64(a, c.b64));
    }
}

test "BIP371 valid vectors: parse, byte-exact round trip, Base64 twin" {
    const a = testing.allocator;
    for (vec.bip371_valid) |c| {
        const bytes = try unhex(a, c.hex);
        defer a.free(bytes);
        var ps = try psbt.parse(a, bytes);
        defer ps.deinit(a);
        const again = try psbt.serialize(a, ps);
        defer a.free(again);
        try testing.expectEqualSlices(u8, bytes, again);
        const text = try psbt.toBase64(a, ps);
        defer a.free(text);
        try testing.expectEqualStrings(c.b64, text);
    }
}

test "BIP371 valid vector 0 (key-path input): internal key and its derivation" {
    const a = testing.allocator;
    const bytes = try unhex(a, vec.bip371_valid[0].hex);
    defer a.free(bytes);
    var ps = try psbt.parse(a, bytes);
    defer ps.deinit(a);
    const ik = key32("fe349064c98d6e2a853fa3c9b12bd8b304a19c195c60efa7ee2393046d3fa232");
    try testing.expectEqualSlices(u8, &ik, &bip371.inputTapInternalKey(ps.inputs[0]).?);
    try testing.expectEqual(@as(?[32]u8, null), bip371.inputTapMerkleRoot(ps.inputs[0]));
    const d = bip371.inputTapBip32Derivation(ps.inputs[0], ik).?;
    try testing.expectEqual(@as(usize, 0), d.leafHashCount());
    try testing.expectEqualSlices(u8, &.{ 0x77, 0x2b, 0x2d, 0xa7 }, &d.path.fingerprint);
    try testing.expectEqual(@as(usize, 5), d.path.len());
    try testing.expectEqual(@as(u32, 0x80000056), d.path.at(0));
    try testing.expectEqual(@as(?[32]u8, null), bip371.inputTapInternalKey(ps.outputs[0]));
}

test "BIP371 valid vector 1: TAP_KEY_SIG is what finalize would use" {
    const a = testing.allocator;
    const bytes = try unhex(a, vec.bip371_valid[1].hex);
    defer a.free(bytes);
    var ps = try psbt.parse(a, bytes);
    defer ps.deinit(a);
    try testing.expectEqual(@as(usize, 64), psbt.inputTapKeySig(ps.inputs[0]).?.len);
}

test "BIP371 valid vector 3 (script path input): leaf scripts, merkle root, derivations with leaf hashes" {
    const a = testing.allocator;
    const bytes = try unhex(a, vec.bip371_valid[3].hex);
    defer a.free(bytes);
    var ps = try psbt.parse(a, bytes);
    defer ps.deinit(a);
    const m = ps.inputs[0];
    try testing.expectEqualSlices(u8, &key32("50929b74c1a04954b78b4b6035e97a5e078a5a0f28ec96d547bfee9ace803ac0"), &bip371.inputTapInternalKey(m).?);
    try testing.expectEqualSlices(u8, &key32("f0362e2f75a6f420a5bde3eb221d96ae6720cf25f81890c95b1d775acb515e65"), &bip371.inputTapMerkleRoot(m).?);
    var n: usize = 0;
    var it = bip371.inputTapLeafScripts(m);
    while (it.next()) |leaf| {
        n += 1;
        try testing.expectEqual(@as(u8, 0xc0), leaf.leaf_version);
        try testing.expectEqual(@as(usize, 34), leaf.script.len); // <key> OP_CHECKSIG
        try testing.expect(leaf.control_block.len == 33 + 32 or leaf.control_block.len == 33 + 64); // depth 1 and depth 2 leaves
    }
    try testing.expectEqual(@as(usize, 3), n);
    const k = key32("2cb13ac68248de806aa6a3659cf3c03eb6821d09c8114a4e868febde865bb6d2");
    const d = bip371.inputTapBip32Derivation(m, k).?;
    try testing.expectEqual(@as(usize, 1), d.leafHashCount());
    try testing.expectEqual(@as(u8, 0xcd), d.leafHash(0)[0]);
}

test "BIP371 valid vector 4 (script path output): tap tree and key derivations" {
    const a = testing.allocator;
    const bytes = try unhex(a, vec.bip371_valid[4].hex);
    defer a.free(bytes);
    var ps = try psbt.parse(a, bytes);
    defer ps.deinit(a);
    const m = ps.outputs[0];
    try testing.expectEqualSlices(u8, &key32("50929b74c1a04954b78b4b6035e97a5e078a5a0f28ec96d547bfee9ace803ac0"), &bip371.outputTapInternalKey(m).?);
    var it = bip371.outputTapTree(m).?;
    var n: usize = 0;
    while (it.next()) |leaf| {
        n += 1;
        try testing.expectEqual(@as(u8, 0xc0), leaf.leaf_version);
    }
    try testing.expectEqual(@as(usize, 3), n);
    const d = bip371.outputTapBip32Derivation(m, key32("50929b74c1a04954b78b4b6035e97a5e078a5a0f28ec96d547bfee9ace803ac0")).?;
    try testing.expectEqual(@as(usize, 0), d.leafHashCount());
}

test "BIP371 vector 5: TAP_SCRIPT_SIG lookup by (key, leaf hash)" {
    const a = testing.allocator;
    const bytes = try unhex(a, vec.bip371_valid[5].hex);
    defer a.free(bytes);
    var ps = try psbt.parse(a, bytes);
    defer ps.deinit(a);
    const k = key32("2cb13ac68248de806aa6a3659cf3c03eb6821d09c8114a4e868febde865bb6d2");
    var lh: [32]u8 = undefined;
    _ = try std.fmt.hexToBytes(&lh, "cd970e15f53fc0c82f950fd560ffa919b76172be017368a89913af074f400b09");
    const sig = bip371.inputTapScriptSig(ps.inputs[0], k, lh).?;
    try testing.expectEqual(@as(usize, 64), sig.len);
    try testing.expectEqual(@as(u8, 0xbf), sig[0]);
    try testing.expectEqual(@as(?[]const u8, null), bip371.inputTapScriptSig(ps.inputs[0], k, k));
}

test "BIP371 setters build what parse accepts and the accessors read back" {
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();
    const bytes = try unhex(a, vec.creator.hex);
    var ps = try psbt.parse(a, bytes);
    const ik = key32("50929b74c1a04954b78b4b6035e97a5e078a5a0f28ec96d547bfee9ace803ac0");
    const leaf_hash: [32]u8 = @splat(9);
    const cb = [_]u8{0xc0} ++ ik ++ leaf_hash;
    try bip371.setInputTapInternalKey(a, &ps, 0, ik);
    try bip371.setInputTapMerkleRoot(a, &ps, 0, leaf_hash);
    try bip371.addInputTapLeafScript(a, &ps, 0, &cb, &.{0x51}, 0xc0);
    try bip371.setInputTapScriptSig(a, &ps, 0, ik, leaf_hash, &(@as([65]u8, @splat(1))));
    try bip371.setInputTapKeySig(a, &ps, 0, &(@as([64]u8, @splat(2))));
    try bip371.setInputTapBip32Derivation(a, &ps, 0, ik, &.{leaf_hash}, .{ 1, 2, 3, 4 }, &.{ 0x80000000, 7 });
    try bip371.setOutputTapInternalKey(a, &ps, 1, ik);
    // a tree of three leaves: depths 1, 2, 2
    try bip371.setOutputTapTree(a, &ps, 1, &.{
        .{ .depth = 1, .leaf_version = 0xc0, .script = &.{0x51} },
        .{ .depth = 2, .leaf_version = 0xc0, .script = &.{0x52} },
        .{ .depth = 2, .leaf_version = 0xc0, .script = &.{0x53} },
    });
    try bip371.setOutputTapBip32Derivation(a, &ps, 1, ik, &.{}, .{ 1, 2, 3, 4 }, &.{});

    const out = try psbt.serialize(a, ps);
    const back = try psbt.parse(a, out);
    try testing.expectEqualSlices(u8, out, try psbt.serialize(a, back));
    try testing.expectEqualSlices(u8, &ik, &bip371.inputTapInternalKey(back.inputs[0]).?);
    var it = bip371.inputTapLeafScripts(back.inputs[0]);
    try testing.expectEqualSlices(u8, &.{0x51}, it.next().?.script);
    try testing.expect(it.next() == null);
    const d = bip371.inputTapBip32Derivation(back.inputs[0], ik).?;
    try testing.expectEqualSlices(u8, &leaf_hash, &d.leafHash(0));
    try testing.expectEqual(@as(u32, 7), d.path.at(1));
    var tree = bip371.outputTapTree(back.outputs[1]).?;
    try testing.expectEqual(@as(u8, 1), tree.next().?.depth);

    // shape refusals
    try testing.expectError(error.InvalidFixedFieldLength, bip371.setInputTapKeySig(a, &ps, 0, &(@as([63]u8, @splat(2)))));
    try testing.expectError(error.InvalidKeyDataLength, bip371.addInputTapLeafScript(a, &ps, 0, cb[0..40], &.{0x51}, 0xc0));
    try testing.expectError(error.InputIndexOutOfRange, bip371.setInputTapInternalKey(a, &ps, 5, ik));
}

test "TAP_TREE: only the depth-first listing of one complete tree is accepted" {
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();
    const bytes = try unhex(a, vec.creator.hex);
    var ps = try psbt.parse(a, bytes);
    const L = bip371.TapTreeLeaf;
    const s: []const u8 = &.{0x51};
    const ok = [_][]const L{
        &.{.{ .depth = 0, .leaf_version = 0xc0, .script = s }}, // a single leaf
        &.{ .{ .depth = 1, .leaf_version = 0xc0, .script = s }, .{ .depth = 1, .leaf_version = 0xc0, .script = s } },
        &.{ .{ .depth = 1, .leaf_version = 0xc0, .script = s }, .{ .depth = 2, .leaf_version = 0xc2, .script = s }, .{ .depth = 2, .leaf_version = 0xc0, .script = s } },
        &.{ .{ .depth = 2, .leaf_version = 0xc0, .script = s }, .{ .depth = 2, .leaf_version = 0xc0, .script = s }, .{ .depth = 1, .leaf_version = 0xc0, .script = s } },
    };
    for (ok) |t| try bip371.setOutputTapTree(a, &ps, 0, t);
    const bad = [_][]const L{
        &.{}, // empty
        &.{.{ .depth = 1, .leaf_version = 0xc0, .script = s }}, // incomplete
        &.{ .{ .depth = 0, .leaf_version = 0xc0, .script = s }, .{ .depth = 0, .leaf_version = 0xc0, .script = s } }, // two roots
        &.{ .{ .depth = 2, .leaf_version = 0xc0, .script = s }, .{ .depth = 1, .leaf_version = 0xc0, .script = s }, .{ .depth = 2, .leaf_version = 0xc0, .script = s } }, // not DFS
        &.{ .{ .depth = 1, .leaf_version = 0xc1, .script = s }, .{ .depth = 1, .leaf_version = 0xc0, .script = s } }, // odd leaf version
        &.{ .{ .depth = 129, .leaf_version = 0xc0, .script = s }, .{ .depth = 129, .leaf_version = 0xc0, .script = s } }, // too deep
    };
    for (bad) |t| try testing.expectError(error.InvalidTapTree, bip371.setOutputTapTree(a, &ps, 0, t));
}

test "hostile: TAP_BIP32_DERIVATION with a leaf-hash count far beyond the value is refused, no overflow" {
    var rec = [_]psbt.Record{.{
        .keytype = psbt.input_key.TAP_BIP32_DERIVATION,
        .keydata = &(@as([32]u8, @splat(1))),
        .value = &([_]u8{ 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff } ++ @as([8]u8, @splat(0))),
    }};
    try testing.expectError(error.InvalidFixedFieldLength, psbt.validateInputRecord(rec[0]));
    rec[0].value = &.{ 0x00, 1, 2, 3, 4 }; // no leaf hashes, fingerprint only, no path: fine
    try psbt.validateInputRecord(rec[0]);
    rec[0].value = &.{ 0x00, 1, 2, 3, 4, 5 }; // a stray octet
    try testing.expectError(error.InvalidFixedFieldLength, psbt.validateInputRecord(rec[0]));
}
