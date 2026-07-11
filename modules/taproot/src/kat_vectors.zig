// SPDX-License-Identifier: MIT
//! The official BIP341 "wallet test vectors", transcribed from
//! `bip-0341/wallet-test-vectors.json` in the `bitcoin/bips` repository
//! (fetched from
//! https://raw.githubusercontent.com/bitcoin/bips/master/bip-0341/wallet-test-vectors.json
//! for this pass — a public BIP specification artifact, not copied from any
//! other implementation's test suite; see `../NOTICE`).
//!
//! Each row pairs the `scriptPubKey` fixture (public-key tweaking: given
//! `internalPubkey` + `scriptTree` → intermediary `merkleRoot`/`tweak`/
//! `tweakedPubkey`) with its matching `keyPathSpending[0].inputSpending`
//! fixture (secret-key tweaking: same `internalPubkey`, plus
//! `internalPrivkey` → intermediary `tweakedPrivkey`) — matched here by
//! `internalPubkey` equality (the two JSON sections use different row
//! orders/indices upstream; re-paired once, here, rather than re-derived by
//! every test). `parity` is the output key's y-parity, recovered from the
//! leading byte of `expected.scriptPathControlBlocks[0]` (`0xc0` = even,
//! `0xc1` = odd — BIP341's control-block leaf-version-or-parity encoding);
//! `null` for the one key-path-only row (index 0, no script tree → no
//! control block, so no independent parity source in this JSON fixture).
//!
//! Row 0 is the key-path-only case (`merkle_root = null`, no script tree at
//! all — distinct from an all-zero-but-present Merkle root). Rows 1-6 each
//! carry a real script-tree Merkle root (single leaf: rows 1/2/3; multi-leaf
//! trees: rows 4/5/6 per the upstream `scriptTree` shape, collapsed here to
//! just the final `merkleRoot` value, which is all the tweak computation
//! needs).

/// One paired row. `tweak` is BIP341's `t = int(taggedHash("TapTweak", P_x
/// ‖ merkle_root))`, given here as its 32-byte big-endian hex representation
/// (the tagged-hash output bytes themselves — no reduction has ever been
/// applied to any row in this set, since none of these hash outputs happen
/// to exceed the curve order `n`).
pub const Vector = struct {
    index: u8,
    /// 64 hex chars (32-byte x-only internal public key P).
    internal_pubkey: []const u8,
    /// 64 hex chars (32-byte internal secret scalar d0, NOT yet even-y
    /// normalized).
    internal_privkey: []const u8,
    /// 64 hex chars (32-byte script-tree Merkle root), or null for the
    /// key-path-only row.
    merkle_root: ?[]const u8,
    /// 64 hex chars (32-byte tweak hash `t`).
    tweak: []const u8,
    /// 64 hex chars (32-byte x-only output key Q).
    tweaked_pubkey: []const u8,
    /// 64 hex chars (32-byte tweaked secret scalar q).
    tweaked_privkey: []const u8,
    /// Output key Q's y-parity (0 = even, 1 = odd), or null where the JSON
    /// fixture has no control block to recover it from (row 0).
    parity: ?u1,
};

pub const vectors = [_]Vector{
    .{
        .index = 0,
        .internal_pubkey = "d6889cb081036e0faefa3a35157ad71086b123b2b144b649798b494c300a961d",
        .internal_privkey = "6b973d88838f27366ed61c9ad6367663045cb456e28335c109e30717ae0c6baa",
        .merkle_root = null,
        .tweak = "b86e7be8f39bab32a6f2c0443abbc210f0edac0e2c53d501b36b64437d9c6c70",
        .tweaked_pubkey = "53a1f6e454df1aa2776a2814a721372d6258050de330b3c6d10ee8f4e0dda343",
        .tweaked_privkey = "2405b971772ad26915c8dcdf10f238753a9b837e5f8e6a86fd7c0cce5b7296d9",
        .parity = null,
    },
    .{
        .index = 1,
        .internal_pubkey = "187791b6f712a8ea41c8ecdd0ee77fab3e85263b37e1ec18a3651926b3a6cf27",
        .internal_privkey = "1e4da49f6aaf4e5cd175fe08a32bb5cb4863d963921255f33d3bc31e1343907f",
        .merkle_root = "5b75adecf53548f3ec6ad7d78383bf84cc57b55a3127c72b9a2481752dd88b21",
        .tweak = "cbd8679ba636c1110ea247542cfbd964131a6be84f873f7f3b62a777528ed001",
        .tweaked_pubkey = "147c9c57132f6e7ecddba9800bb0c4449251c92a1e60371ee77557b6620f3ea3",
        .tweaked_privkey = "ea260c3b10e60f6de018455cd0278f2f5b7e454be1999572789e6a9565d26080",
        .parity = 1,
    },
    .{
        .index = 2,
        .internal_pubkey = "93478e9488f956df2396be2ce6c5cced75f900dfa18e7dabd2428aae78451820",
        .internal_privkey = "d3c7af07da2d54f7a7735d3d0fc4f0a73164db638b2f2f7c43f711f6d4aa7e64",
        .merkle_root = "c525714a7f49c28aedbbba78c005931a81c234b2f6c99a73e4d06082adc8bf2b",
        .tweak = "6af9e28dbf9d6aaf027696e2598a5b3d056f5fd2355a7fd5a37a0e5008132d30",
        .tweaked_pubkey = "e4d810fd50586274face62b8a807eb9719cef49c04177cc6b76a9a4251d5450e",
        .tweaked_privkey = "97323385e57015b75b0339a549c56a948eb961555973f0951f555ae6039ef00d",
        .parity = 0,
    },
    .{
        .index = 3,
        .internal_pubkey = "ee4fe085983462a184015d1f782d6a5f8b9c2b60130aff050ce221ecf3786592",
        .internal_privkey = "c7b0e81f0a9a0b0499e112279d718cca98e79a12e2f137c72ae5b213aad0d103",
        .merkle_root = "6c2dc106ab816b73f9d07e3cd1ef2c8c1256f519748e0813e4edd2405d277bef",
        .tweak = "9e0517edc8259bb3359255400b23ca9507f2a91cd1e4250ba068b4eafceba4a9",
        .tweaked_pubkey = "712447206d7a5238acc7ff53fbe94a3b64539ad291c7cdbc490b7577e4b17df5",
        .tweaked_privkey = "65b6000cd2bfa6b7cf736767a8955760e62b6649058cbc970b7c0871d786346b",
        .parity = 0,
    },
    .{
        .index = 4,
        .internal_pubkey = "f9f400803e683727b14f463836e1e78e1c64417638aa066919291a225f0e8dd8",
        .internal_privkey = "77863416be0d0665e517e1c375fd6f75839544eca553675ef7fdf4949518ebaa",
        .merkle_root = "ab179431c28d3b68fb798957faf5497d69c883c6fb1e1cd9f81483d87bac90cc",
        .tweak = "639f0281b7ac49e742cd25b7f188657626da1ad169209078e2761cefd91fd65e",
        .tweaked_pubkey = "77e30a5522dd9f894c3f8b8bd4c4b2cf82ca7da8a3ea6a239655c39c050ab220",
        .tweaked_privkey = "ec18ce6af99f43815db543f47b8af5ff5df3b2cb7315c955aa4a86e8143d2bf5",
        .parity = 1,
    },
    .{
        .index = 5,
        .internal_pubkey = "e0dfe2300b0dd746a3f8674dfd4525623639042569d829c7f0eed9602d263e6f",
        .internal_privkey = "f36bb07a11e469ce941d16b63b11b9b9120a84d9d87cff2c84a8d4affb438f4e",
        .merkle_root = "ccbd66c6f7e8fdab47b3a486f59d28262be857f30d4773f2d5ea47f7761ce0e2",
        .tweak = "b57bfa183d28eeb6ad688ddaabb265b4a41fbf68e5fed2c72c74de70d5a786f4",
        .tweaked_pubkey = "91b64d5324723a985170e4dc5a0f84c041804f2cd12660fa5dec09fc21783605",
        .tweaked_privkey = "a8e7aa924f0d58854185a490e6c41f6efb7b675c0f3331b7f14b549400b4d501",
        .parity = 0,
    },
    .{
        .index = 6,
        .internal_pubkey = "55adf4e8967fbd2e29f20ac896e60c3b0f1d5b0efa9d34941b5958c7b0a0312d",
        .internal_privkey = "415cfe9c15d9cea27d8104d5517c06e9de48e2f986b695e4f5ffebf230e725d8",
        .merkle_root = "2f6b2c5397b6d68ca18e09a3f05161668ffe93a988582d55c6f07bd5b3329def",
        .tweak = "6579138e7976dc13b6a92f7bfd5a2fc7684f5ea42419d43368301470f3b74ed9",
        .tweaked_pubkey = "75169f4001aa68f15bbed28b218df1d0a62cbbcf1188c6665110c293c907b831",
        .tweaked_privkey = "241c14f2639d0d7139282aa6abde28dd8a067baa9d633e4e7230287ec2d02901",
        .parity = 1,
    },
};

test "vector count matches the paired BIP341 wallet-test-vectors.json rows (7)" {
    const std = @import("std");
    try std.testing.expectEqual(@as(usize, 7), vectors.len);
}

test "hex field lengths are well-formed" {
    const std = @import("std");
    for (vectors) |vec| {
        try std.testing.expectEqual(@as(usize, 64), vec.internal_pubkey.len);
        try std.testing.expectEqual(@as(usize, 64), vec.internal_privkey.len);
        if (vec.merkle_root) |mr| try std.testing.expectEqual(@as(usize, 64), mr.len);
        try std.testing.expectEqual(@as(usize, 64), vec.tweak.len);
        try std.testing.expectEqual(@as(usize, 64), vec.tweaked_pubkey.len);
        try std.testing.expectEqual(@as(usize, 64), vec.tweaked_privkey.len);
    }
}

test "exactly one key-path-only row (null merkle_root)" {
    const std = @import("std");
    var count: usize = 0;
    for (vectors) |vec| {
        if (vec.merkle_root == null) count += 1;
    }
    try std.testing.expectEqual(@as(usize, 1), count);
}
