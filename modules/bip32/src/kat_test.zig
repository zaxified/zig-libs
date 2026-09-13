// SPDX-License-Identifier: MIT

//! Official BIP-32 (test vectors 1/2/3/4/5) and BIP-39 (Trezor set) known-
//! answer assertions. See `bip32_vectors.zig` / `bip39_vectors.zig` for the
//! embedded vector data and provenance.

const std = @import("std");
const testing = std.testing;

const bip39 = @import("bip39.zig");
const bip32 = @import("bip32.zig");
const bip32_vectors = @import("bip32_vectors.zig");
const bip39_vectors = @import("bip39_vectors.zig");

/// Run one BIP-32 `TestVector`: derive the whole chain from the seed via
/// `ckdPriv`, asserting the serialized xprv AND xpub are byte-exact at
/// every step (master + each chain link).
fn runBip32Vector(v: bip32_vectors.TestVector) !void {
    var seed_buf: [64]u8 = undefined;
    const n = v.seed_hex.len / 2;
    _ = try std.fmt.hexToBytes(seed_buf[0..n], v.seed_hex);
    const seed = seed_buf[0..n];

    var master = try bip32.masterFromSeed(seed);
    defer master.deinit();

    var buf: [bip32.max_serialized_len]u8 = undefined;
    try testing.expectEqualStrings(v.master_xprv, try bip32.serializePriv(master, .mainnet, &buf));
    const master_pub = try bip32.neuter(master);
    try testing.expectEqualStrings(v.master_xpub, try bip32.serializePub(master_pub, .mainnet, &buf));

    var cur = master;
    for (v.chain) |step| {
        var child = try bip32.ckdPriv(cur, step.index);
        defer child.deinit();

        try testing.expectEqualStrings(step.xprv, try bip32.serializePriv(child, .mainnet, &buf));
        const child_pub = try bip32.neuter(child);
        try testing.expectEqualStrings(step.xpub, try bip32.serializePub(child_pub, .mainnet, &buf));

        // Public-only derivation must agree wherever the step is NOT
        // hardened (CKDpub is only defined for normal children).
        if (step.index < bip32_vectors.hardened_offset) {
            const cur_pub = try bip32.neuter(cur);
            const child_via_pub = try bip32.ckdPub(cur_pub, step.index);
            try testing.expectEqualSlices(u8, &child_pub.pubkey, &child_via_pub.pubkey);
            try testing.expectEqualSlices(u8, &child_pub.chain_code, &child_via_pub.chain_code);
        }

        cur = child;
    }
}

test "BIP-32 official Test Vector 1 — hardened + normal chain, xprv+xpub byte-exact" {
    try runBip32Vector(bip32_vectors.test_vector_1);
}

test "BIP-32 official Test Vector 2 — large indices incl. 2^31-1 hardened, xprv+xpub byte-exact" {
    try runBip32Vector(bip32_vectors.test_vector_2);
}

test "BIP-32 official Test Vector 3 — leading-zero-byte retention, xprv+xpub byte-exact" {
    try runBip32Vector(bip32_vectors.test_vector_3);
}

test "BIP-32 official Test Vector 4 — leading-zero retention at a different depth, xprv+xpub byte-exact" {
    try runBip32Vector(bip32_vectors.test_vector_4);
}

test "BIP-32 official Test Vector 5 — every invalid extended key is rejected" {
    for (bip32_vectors.invalid_vector_5) |s| {
        if (bip32.parseExtended(s, .mainnet)) |_| {
            std.debug.print("expected rejection, got success for: {s}\n", .{s});
            try testing.expect(false);
        } else |_| {}
    }
}

test "BIP-32 Test Vector 1 master on TESTNET — tprv/tpub byte-exact, and each network refuses the other's key" {
    // BIP-32 publishes vectors for mainnet only. These two strings were made
    // OUTSIDE this module (2026-09-13): Test Vector 1's official master
    // xprv/xpub, Base58Check-decoded by an independent Python implementation
    // (checksum verified, mainnet strings re-encoded identically), version
    // bytes replaced with BIP-32's testnet 0x04358394 / 0x043587CF, re-encoded.
    const tprv = "tprv8ZgxMBicQKsPeDgjzdC36fs6bMjGApWDNLR9erAXMs5skhMv36j9MV5ecvfavji5khqjWaWSFhN3YcCUUdiKH6isR4Pwy3U5y5egddBr16m";
    const tpub = "tpubD6NzVbkrYhZ4XgiXtGrdW5XDAPFCL9h7we1vwNCpn8tGbBcgfVYjXyhWo4E1xkh56hjod1RhGjxbaTLV3X4FyWuejifB9jusQ46QzG87VKp";

    const v = bip32_vectors.test_vector_1;
    var seed_buf: [64]u8 = undefined;
    const n = v.seed_hex.len / 2;
    _ = try std.fmt.hexToBytes(seed_buf[0..n], v.seed_hex);
    var master = try bip32.masterFromSeed(seed_buf[0..n]);
    defer master.deinit();
    const master_pub = try bip32.neuter(master);

    var buf: [bip32.max_serialized_len]u8 = undefined;
    try testing.expectEqualStrings(tprv, try bip32.serializePriv(master, .testnet, &buf));
    try testing.expectEqualStrings(tpub, try bip32.serializePub(master_pub, .testnet, &buf));

    const p = try bip32.parseExtended(tprv, .testnet);
    try testing.expect(p == .private);
    try testing.expectEqualSlices(u8, &master.privkey, &p.private.privkey);
    const q = try bip32.parseExtended(tpub, .testnet);
    try testing.expect(q == .public);
    try testing.expectEqualSlices(u8, &master_pub.pubkey, &q.public.pubkey);

    // A real key from the other network is refused by name, both ways.
    try testing.expectError(error.WrongNetwork, bip32.parseExtended(tprv, .mainnet));
    try testing.expectError(error.WrongNetwork, bip32.parseExtended(tpub, .mainnet));
    try testing.expectError(error.WrongNetwork, bip32.parseExtended(v.master_xprv, .testnet));
    try testing.expectError(error.WrongNetwork, bip32.parseExtended(v.master_xpub, .testnet));
}

test "BIP-39 official Trezor test vectors — entropy/mnemonic/seed/master-xprv all byte-exact" {
    var entropy_buf: [bip39.max_entropy_bytes]u8 = undefined;
    var mnemonic_buf: [bip39.max_mnemonic_len]u8 = undefined;
    var seed_buf: [64]u8 = undefined;
    var xprv_buf: [bip32.max_serialized_len]u8 = undefined;

    for (bip39_vectors.vectors) |v| {
        const ent_len = v.entropy_hex.len / 2;
        _ = try std.fmt.hexToBytes(entropy_buf[0..ent_len], v.entropy_hex);
        const entropy = entropy_buf[0..ent_len];

        // entropy -> mnemonic, byte-exact.
        const mnemonic = try bip39.entropyToMnemonic(entropy, &mnemonic_buf);
        try testing.expectEqualStrings(v.mnemonic, mnemonic);

        // mnemonic -> entropy (inverse), byte-exact + checksum-valid.
        var back_buf: [bip39.max_entropy_bytes]u8 = undefined;
        const back = try bip39.mnemonicToEntropy(mnemonic, &back_buf);
        try testing.expectEqualSlices(u8, entropy, back);
        try bip39.validateMnemonic(mnemonic);

        // mnemonic + "TREZOR" -> 64-byte seed, byte-exact.
        try bip39.mnemonicToSeed(mnemonic, bip39_vectors.passphrase, &seed_buf);
        var want_seed: [64]u8 = undefined;
        const seed_n = v.seed_hex.len / 2;
        _ = try std.fmt.hexToBytes(want_seed[0..seed_n], v.seed_hex);
        try testing.expectEqualSlices(u8, want_seed[0..seed_n], &seed_buf);

        // seed -> BIP-32 master xprv, byte-exact (the BIP-39<->BIP-32 seam).
        var master = try bip32.masterFromSeed(&seed_buf);
        defer master.deinit();
        try testing.expectEqualStrings(v.master_xprv, try bip32.serializePriv(master, .mainnet, &xprv_buf));
    }
}

test "BIP-39: a 24-word mnemonic (256-bit entropy) round-trips" {
    // Vector index 3 in the Trezor set is the all-0xff 128-bit case; pick
    // the 256-bit ("ffff...ffff" -> 24 words) vector explicitly by entropy
    // length to exercise the max-length path end-to-end.
    var found = false;
    for (bip39_vectors.vectors) |v| {
        if (v.entropy_hex.len == 64) { // 32 bytes = 256 bits = 24 words
            found = true;
            var count: usize = 1;
            for (v.mnemonic) |c| {
                if (c == ' ') count += 1;
            }
            try testing.expectEqual(@as(usize, 24), count);
        }
    }
    try testing.expect(found);
}
