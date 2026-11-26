// SPDX-License-Identifier: MIT
//! BIP341 annex commitment, anchored by real signatures: every key-path spend
//! with an annex in Bitcoin Core's `script_assets_test.json`
//! (`bip341_annex_kat_vectors.zig`) carries a BIP340 signature that verifies
//! over `keyPathSighash(.., annex)` and over nothing else (no annex, the
//! script-path `spend_type`, or a changed annex byte).

const std = @import("std");
const testing = std.testing;
const bip340 = @import("bip340");
const tx = @import("tx.zig");
const bip341 = @import("sighash_bip341.zig");
const vectors = @import("bip341_annex_kat_vectors.zig");
const testutil = @import("testutil.zig");

fn decodeTxOut(bytes: []const u8) !tx.TxOut {
    if (bytes.len < 9) return error.Truncated;
    const len = try tx.decodeCompactSize(bytes[8..]);
    const start = 8 + len.consumed;
    if (bytes.len != start + len.value) return error.TrailingBytes;
    return .{ .value = std.mem.readInt(i64, bytes[0..8], .little), .script_pubkey = bytes[start..] };
}

fn verifies(pk: bip340.XOnlyPublicKey, msg: *const [32]u8, sig: bip340.Signature) bool {
    return bip340.verify(pk, msg, sig);
}

test "BIP341 annex: corpus signatures verify over keyPathSighash with the annex only" {
    try testing.expectEqual(@as(usize, 31), vectors.vectors.len);
    for (vectors.vectors) |v| {
        var arena = std.heap.ArenaAllocator.init(testing.allocator);
        defer arena.deinit();
        const a = arena.allocator();

        var t = try tx.deserialize(a, try testutil.hexToBytesAlloc(a, v.tx_hex));
        const spent = try a.alloc(tx.TxOut, v.prevouts_hex.len);
        for (v.prevouts_hex, 0..) |h, i| spent[i] = try decodeTxOut(try testutil.hexToBytesAlloc(a, h));
        try testing.expectEqual(t.vin.len, spent.len);

        const sig_bytes = try testutil.hexToBytesAlloc(a, v.signature_hex);
        const annex = try testutil.hexToBytesAlloc(a, v.annex_hex);
        const hash_type: u8 = if (sig_bytes.len == 65) sig_bytes[64] else bip341.SIGHASH_DEFAULT;
        const sig = try bip340.Signature.fromBytes(sig_bytes[0..64].*);
        const program = spent[v.index].script_pubkey[2..34];
        const pk = try bip340.XOnlyPublicKey.fromBytes(program[0..32].*);

        const with_annex = try bip341.keyPathSighash(a, null, t, v.index, hash_type, spent, annex);
        if (!verifies(pk, &with_annex, sig)) {
            std.debug.print("annex vector {d} ({s}): signature does not verify over the annex sighash\n", .{ v.corpus_entry, v.comment });
            return error.VectorMismatch;
        }

        // The cached route is byte-identical.
        const pre = try bip341.precompute(a, t, spent);
        try testing.expectEqualSlices(u8, &with_annex, &(try bip341.keyPathSighash(a, pre, t, v.index, hash_type, spent, annex)));

        // Teeth: without the annex, with another annex byte, or as a
        // script-path message, the signature must not verify.
        const plain = try bip341.keyPathSighash(a, null, t, v.index, hash_type, spent, null);
        try testing.expect(!verifies(pk, &plain, sig));
        const other = try a.dupe(u8, annex);
        other[other.len - 1] ^= 0x01;
        const changed = try bip341.keyPathSighash(a, null, t, v.index, hash_type, spent, other);
        try testing.expect(!verifies(pk, &changed, sig));
        t.deinit(a);
    }
}

test "annexHash: compact-size prefix classes" {
    // SHA256(compact_size(len) || annex), checked against the hash of the explicit bytes.
    const lens = [_]usize{ 1, 0xfc, 0xfd, 0x100, 0xffff };
    for (lens) |n| {
        const annex = try testing.allocator.alloc(u8, n);
        defer testing.allocator.free(annex);
        @memset(annex, 0x50);
        var buf: std.ArrayList(u8) = .empty;
        defer buf.deinit(testing.allocator);
        try tx.appendCompactSize(&buf, testing.allocator, n);
        try buf.appendSlice(testing.allocator, annex);
        var want: [32]u8 = undefined;
        std.crypto.hash.sha2.Sha256.hash(buf.items, &want, .{});
        try testing.expectEqualSlices(u8, &want, &bip341.annexHash(annex));
    }
}

test "mutation 2026-11-25: annexHash prefixes a 4-byte length with 0xfe (65536 and 65537 bytes)" {
    for ([_]usize{ 0x10000, 0x10001 }) |n| {
        const annex = try testing.allocator.alloc(u8, n);
        defer testing.allocator.free(annex);
        @memset(annex, 0x50);
        var h = std.crypto.hash.sha2.Sha256.init(.{});
        var prefix: [5]u8 = undefined;
        prefix[0] = 0xfe;
        std.mem.writeInt(u32, prefix[1..5], @intCast(n), .little);
        h.update(&prefix);
        h.update(annex);
        try testing.expectEqualSlices(u8, &h.finalResult(), &bip341.annexHash(annex));
    }
}
