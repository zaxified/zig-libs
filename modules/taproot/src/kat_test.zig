// SPDX-License-Identifier: MIT
//! Tests against the official BIP341 wallet test vectors (`kat_vectors.zig`,
//! transcribed from `bip-0341/wallet-test-vectors.json`).
//!
//! Coverage:
//!   - `tapTweakHash` (REAL, passes today): every one of the 7 vectors'
//!     `tweak` field is reproduced exactly, including the one key-path-only
//!     row (`merkle_root = null`, index 0) and all 6 script-tree rows
//!     (indices 1-6, each carrying a real 32-byte Merkle root).
//!   - `tweakPublicKey` / `tweakSecretKey` (REAL): KATs against the exact
//!     same 7 vectors — `tweakedPubkey` + control-block-recovered `parity`
//!     + returned `tweak` for the public core; the published
//!     `tweakedPrivkey` scalar for the secret core; plus a full
//!     sign→verify round-trip (`bip340.sign` under the tweaked scalar
//!     verifies against the tweaked output key) for every vector.

const std = @import("std");
const taproot = @import("root.zig");
const bip340 = @import("bip340");
const v = @import("kat_vectors.zig");

fn hex32(hex_str: []const u8) ![32]u8 {
    var out: [32]u8 = undefined;
    _ = try std.fmt.hexToBytes(&out, hex_str);
    return out;
}

test "KAT: tapTweakHash reproduces the published `tweak` field for all 7 vectors" {
    for (v.vectors) |vec| {
        const internal_x = try hex32(vec.internal_pubkey);
        const merkle_root: ?[32]u8 = if (vec.merkle_root) |mr| try hex32(mr) else null;
        const want = try hex32(vec.tweak);
        const got = taproot.tapTweakHash(internal_x, merkle_root);
        try std.testing.expectEqualSlices(u8, &want, &got);
    }
}

test "KAT: tapTweakHash on the key-path-only row (index 0) hashes over P_x alone" {
    // Distinguishes "no script tree at all" (merkle_root = null, this row)
    // from "a script tree whose root happens to be all-zero" — the two
    // must NOT hash the same way (null appends nothing; an all-zero root
    // would append 32 zero bytes). Pinned here so a future refactor can't
    // quietly conflate the two.
    const vec = v.vectors[0];
    try std.testing.expect(vec.merkle_root == null);
    const internal_x = try hex32(vec.internal_pubkey);
    const want = try hex32(vec.tweak);
    const got = taproot.tapTweakHash(internal_x, null);
    try std.testing.expectEqualSlices(u8, &want, &got);

    // Sanity: hashing with an explicit all-zero root gives a DIFFERENT
    // result than passing null (proves the two code paths are distinct,
    // not accidentally equivalent for this particular internal key).
    const with_zero_root = taproot.tapTweakHash(internal_x, [_]u8{0} ** 32);
    try std.testing.expect(!std.mem.eql(u8, &want, &with_zero_root));
}

test "KAT: tweakPublicKey matches the published tweakedPubkey + parity" {
    for (v.vectors) |vec| {
        const internal = try bip340.XOnlyPublicKey.fromBytes(try hex32(vec.internal_pubkey));
        const merkle_root: ?[32]u8 = if (vec.merkle_root) |mr| try hex32(mr) else null;
        const result = try taproot.tweakPublicKey(internal, merkle_root);

        const want_x = try hex32(vec.tweaked_pubkey);
        try std.testing.expectEqualSlices(u8, &want_x, &result.output.x);

        if (vec.parity) |want_parity| {
            try std.testing.expectEqual(want_parity, result.output.parity);
        }

        const want_tweak = try hex32(vec.tweak);
        try std.testing.expectEqualSlices(u8, &want_tweak, &result.tweak);
    }
}

test "KAT: tweakSecretKey matches the published tweakedPrivkey" {
    for (v.vectors) |vec| {
        const sk = try bip340.SecretKey.fromBytes(try hex32(vec.internal_privkey));
        const merkle_root: ?[32]u8 = if (vec.merkle_root) |mr| try hex32(mr) else null;
        const got = try taproot.tweakSecretKey(sk, merkle_root);

        const want = try hex32(vec.tweaked_privkey);
        try std.testing.expectEqualSlices(u8, &want, &got);
    }
}

test "tweaked key pair signs and verifies: bip340.sign under q verifies against Q (all 7 vectors)" {
    // The pub/priv halves must agree not just field-by-field against the
    // vectors but OPERATIONALLY: a key-path spend signs with the tweaked
    // scalar q and is verified against the tweaked output key Q's x-only
    // encoding. Proves the two cores are mutually consistent (q*G's even-y
    // x-coordinate == x(Q)) and that the result plugs into bip340
    // sign/verify exactly as a wallet would use it.
    const gpa = std.testing.allocator;
    var threaded = std.Io.Threaded.init(gpa, .{});
    defer threaded.deinit();
    const io = threaded.io();

    const msg = "taproot key-path spend round-trip";
    const aux = [_]u8{0} ** 32;

    for (v.vectors) |vec| {
        const internal = try bip340.XOnlyPublicKey.fromBytes(try hex32(vec.internal_pubkey));
        const sk = try bip340.SecretKey.fromBytes(try hex32(vec.internal_privkey));
        const merkle_root: ?[32]u8 = if (vec.merkle_root) |mr| try hex32(mr) else null;

        const result = try taproot.tweakPublicKey(internal, merkle_root);
        const q_bytes = try taproot.tweakSecretKey(sk, merkle_root);

        // Structural agreement: q's own derived x-only public key IS the
        // tweaked output key's x (bip340's derivation even-y-normalizes q
        // internally, so this holds regardless of Q's parity bit).
        const q_sk = try bip340.SecretKey.fromBytes(q_bytes);
        const q_pub = try bip340.PublicKey.fromSecretKey(q_sk);
        try std.testing.expectEqualSlices(u8, &result.output.x, &q_pub.xonly.toBytes());

        // Operational agreement: sign with q, verify under Q-as-x-only.
        const sig_bytes = try bip340.sign(q_sk, msg, aux, io);
        const sig = try bip340.Signature.fromBytes(sig_bytes);
        try std.testing.expect(bip340.verify(result.output.asXOnly(), msg, sig));
    }
}

test "TweakedPublicKey.toBytes / asXOnly round-trip (no crypto core needed)" {
    // Exercises the codec half of TweakedPublicKey independent of the
    // crypto cores: a hand-built value round-trips through toBytes and
    // reinterprets cleanly as a bip340.XOnlyPublicKey (a real on-curve x,
    // taken from vector 0's already-validated tweakedPubkey).
    const x = try hex32(v.vectors[0].tweaked_pubkey);
    const k = taproot.TweakedPublicKey{ .x = x, .parity = 1 };
    try std.testing.expectEqualSlices(u8, &x, &k.toBytes());

    const xonly = k.asXOnly();
    try std.testing.expectEqualSlices(u8, &x, &xonly.toBytes());
    // The underlying x is a real on-curve point (BIP341 output keys always
    // are) — lift() must succeed.
    _ = try xonly.lift();
}
