// SPDX-License-Identifier: MIT

//! SLIP-0132 version prefixes (ypub/zpub/...). Anchors: the registry's own
//! Bitcoin test vectors (mnemonic "abandon ... about", accounts m/44'/0'/0',
//! m/49'/0'/0', m/84'/0'/0': the xprv/xpub, yprv/ypub and zprv/zpub strings,
//! derived here from the mnemonic and compared byte for byte), and a table of
//! the same m/84'/0'/0' key under all ten registered version pairs. SLIP-0132
//! publishes vectors only for x/y/z; the other eighteen strings were made by
//! an independent Base58Check implementation (version bytes swapped in the
//! published zpub/zprv payload, checksum recomputed), with every produced
//! string's first four characters asserted against the registry's prefix.

const std = @import("std");
const testing = std.testing;
const bech32 = @import("bech32");

const bip32 = @import("bip32.zig");
const bip39 = @import("bip39.zig");

const mnemonic = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";
const h = bip32.hardened_offset;

const Account = struct {
    script: bip32.Slip132Script,
    purpose: u32,
    xprv: []const u8,
    xpub: []const u8,
};

const accounts = [_]Account{
    .{
        .script = .p2pkh_or_p2sh,
        .purpose = 44,
        .xprv = "xprv9xpXFhFpqdQK3TmytPBqXtGSwS3DLjojFhTGht8gwAAii8py5X6pxeBnQ6ehJiyJ6nDjWGJfZ95WxByFXVkDxHXrqu53WCRGypk2ttuqncb",
        .xpub = "xpub6BosfCnifzxcFwrSzQiqu2DBVTshkCXacvNsWGYJVVhhawA7d4R5WSWGFNbi8Aw6ZRc1brxMyWMzG3DSSSSoekkudhUd9yLb6qx39T9nMdj",
    },
    .{
        .script = .p2wpkh_in_p2sh,
        .purpose = 49,
        .xprv = "yprvAHwhK6RbpuS3dgCYHM5jc2ZvEKd7Bi61u9FVhYMpgMSuZS613T1xxQeKTffhrHY79hZ5PsskBjcc6C2V7DrnsMsNaGDaWev3GLRQRgV7hxF",
        .xpub = "ypub6Ww3ibxVfGzLrAH1PNcjyAWenMTbbAosGNB6VvmSEgytSER9azLDWCxoJwW7Ke7icmizBMXrzBx9979FfaHxHcrArf3zbeJJJUZPf663zsP",
    },
    .{
        .script = .p2wpkh,
        .purpose = 84,
        .xprv = "zprvAdG4iTXWBoARxkkzNpNh8r6Qag3irQB8PzEMkAFeTRXxHpbF9z4QgEvBRmfvqWvGp42t42nvgGpNgYSJA9iefm1yYNZKEm7z6qUWCroSQnE",
        .xpub = "zpub6rFR7y4Q2AijBEqTUquhVz398htDFrtymD9xYYfG1m4wAcvPhXNfE3EfH1r1ADqtfSdVCToUG868RvUUkgDKf31mGDtKsAYz2oz2AGutZYs",
    },
};

fn accountKey(purpose: u32, out: *bip32.ExtendedPrivKey) !void {
    var seed: [64]u8 = undefined;
    defer std.crypto.secureZero(u8, &seed);
    try bip39.mnemonicToSeed(mnemonic, "", &seed);
    var master: bip32.ExtendedPrivKey = undefined;
    try bip32.masterFromSeed(&seed, &master);
    defer master.deinit();
    try bip32.derivePath(&master, &.{ h + purpose, h + 0, h + 0 }, out);
}

test "SLIP-0132 test vectors: serialize with the script's prefix, byte-exact" {
    var buf: [bip32.max_serialized_len]u8 = undefined;
    for (accounts) |a| {
        var k: bip32.ExtendedPrivKey = undefined;
        try accountKey(a.purpose, &k);
        defer k.deinit();
        try testing.expectEqualStrings(a.xprv, try bip32.serializePrivSlip132(&k, .mainnet, a.script, &buf));
        const p = try bip32.neuter(&k);
        try testing.expectEqualStrings(a.xpub, try bip32.serializePubSlip132(p, .mainnet, a.script, &buf));
    }
}

test "SLIP-0132 test vectors: parseSlip132 decodes them to the derived key and names the prefix" {
    for (accounts) |a| {
        var k: bip32.ExtendedPrivKey = undefined;
        try accountKey(a.purpose, &k);
        defer k.deinit();
        var got: bip32.ParsedKey = undefined;
        const e = try bip32.parseSlip132(a.xprv, &got);
        try testing.expectEqual(bip32.Network.mainnet, e.network);
        try testing.expectEqual(a.script, e.script);
        try testing.expectEqualSlices(u8, &k.privkey, &got.private.privkey);
        try testing.expectEqualSlices(u8, &k.chain_code, &got.private.chain_code);
        try testing.expectEqual(@as(u8, 3), got.private.depth);

        var gp: bip32.ParsedKey = undefined;
        const ep = try bip32.parseSlip132(a.xpub, &gp);
        try testing.expectEqual(a.script, ep.script);
        const p = try bip32.neuter(&k);
        try testing.expectEqualSlices(u8, &p.pubkey, &gp.public.pubkey);
    }
}

const Row = struct { network: bip32.Network, script: bip32.Slip132Script, pub_str: []const u8, priv_str: []const u8 };

/// The m/84'/0'/0' key under every registered version pair.
const all_rows = [_]Row{
    .{ .network = .mainnet, .script = .p2pkh_or_p2sh, .pub_str = "xpub6CatWdiZiodmUeTDp8LT5or8nmbKNcuyvz7WyksVFkKB4RHwCD3XyuvPEbvqAQY3rAPshWcMLoP2fMFMKHPJ4ZeZXYVUhLv1VMrjPC7PW6V", .priv_str = "xprv9ybY78BftS5UGANki6oSifuQEjkpyAC8ZmBvBNTshQnCBcxnefjHS7buPMkkqhcRzmoGZ5bokx7GuyDAiktd5HemohAU4wV1ZPMDRmLpBMm" },
    .{ .network = .mainnet, .script = .p2wpkh_in_p2sh, .pub_str = "ypub6XR9pJPUsVBFKweLeV85HtwdxjjmKEuUr6djm9mNdkh47X7ASsD6byaXFotRAKByFoWgSzCuoTjaYdrv2yoJroLAPtBuHFjVm5vNmhyNehE", .priv_str = "yprvAJRoQnrb37cx7TZsYTb4vkzuQhuGunBdUsi8xmMm5RA5Ein1uKtr4BG3QZiLqcGMQQv5JZCNDcTpoFpjSTJdsXLNg2rterJVq7QrpHUxFQt" },
    .{ .network = .mainnet, .script = .p2wpkh, .pub_str = "zpub6rFR7y4Q2AijBEqTUquhVz398htDFrtymD9xYYfG1m4wAcvPhXNfE3EfH1r1ADqtfSdVCToUG868RvUUkgDKf31mGDtKsAYz2oz2AGutZYs", .priv_str = "zprvAdG4iTXWBoARxkkzNpNh8r6Qag3irQB8PzEMkAFeTRXxHpbF9z4QgEvBRmfvqWvGp42t42nvgGpNgYSJA9iefm1yYNZKEm7z6qUWCroSQnE" },
    .{ .network = .mainnet, .script = .p2wsh_in_p2sh, .pub_str = "Ypub6iKEwY7vSSjckWoib9b47yHSgXn2Xbb5ANHQgR2v1XXTjhg5DGbNh6ST4WqtikQsVGafKaD2gg85foUgLCxG1HSqEMJJgfCVepCFMi9sffi", .priv_str = "YprvAVKtY2b2c5BKY2jFV843kqLi8VwY88sDo9Mot2dJTBzUruLvfjH89J7yDGfpQ3VFdsz4B9CV6prKvRSVjgTb21T3WVyJ4FmViqgjQHPKyFB" },
    .{ .network = .mainnet, .script = .p2wsh, .pub_str = "Zpub739WFCnqb8H6bozqRWNgL4NwrVvUUDaa5UodTovoPXuLnoVJTvkwKA6b5ioUif4ntuhU53ob9LUdZ66F3uNGoX8S6gzjGa1yvYFtkDRknR2", .priv_str = "ZprvApA9qhFwkkioPKvNKUqfxvSDJU5z4kriiFt2fRXBqCNMv1A9vPSgmMn7EUdQPx9B3X6rvco3ZVCsoi44TNsbpF8eNqfieAayzZkNnquACTC" },
    .{ .network = .testnet, .script = .p2pkh_or_p2sh, .pub_str = "tpubDCxX2sYFS5bDkSe5GKKYHjBW7tgyN1R3UchpLJvdbf54ohxeGRtd8MbDUe1cguVHe4vnK68DsuD5MXjxi9EXx16rb9EnNsaF5KT99CinaJz", .priv_str = "tprv8gGUtTW1HhuYrycHNfewtKXPYsB3CgE8uK733ntLBPGfyDhse352wryMJXvQr4zkNDL3ZBDZvJh5NpkuqyEZtLvNLLNmjJD4UV6dsRECvrC" },
    .{ .network = .testnet, .script = .p2wpkh_in_p2sh, .pub_str = "upub5E66bdhpGm1KvkssK3yaTYZdGs9yYkwVBeYrdaBq7jBXu7rFSEYr7iwyAz45AgaHdF3TT5pfxpKP1VQfAC9FfrbkvXQCwcTYgBfoDTNH1hz", .priv_str = "uprv916kC8AvSPT2iGoQD2Sa6QctiqKV9JDdpRdFqBnDZPeZ2KX6thEbZvdVKjszqyefmrSrJep8Ny3dG7NUZfeagabyCg5CKD2YkDAHG3kPQgG" },
    .{ .network = .testnet, .script = .p2wpkh, .pub_str = "vpub5YvMuJNjRSYon44z9QmCfdf8SqJRVNvz6m55Qy5iVjZQxDfUgtiQjnc7CC1fAbED2tAGCZRERUfvtn2DstZGU6HMns6dXXH2wujSc2wfi2x", .priv_str = "vprv9Kw1Vnqqb4zWZZzX3PECJViPtoTw5vD8jY9Ucag6wQ2S5RLL9MQABzHdLwqaqtJbBVZf48QgqdQB9Pz3HN4bUpHa51mcu7r31wDveZokZ6z" },
    .{ .network = .testnet, .script = .p2wsh_in_p2sh, .pub_str = "Upub5QzBisSFqiZhML3FFiSZHcuRzfCEm7d5VvCXYqTNVW1wXJRACdw8Cqotyh1Yj7oBri7SKfpnr2ht8f2RTRJCpLiRkzWcM1vYZuwfoM3opLR", .priv_str = "Uprv9BzqKMuN1M1Q8qxn9guYvUxhSdMkMeuE8hGvkT3kwAUxeW61f6csf3VR8SqUQQsa1KWqBEpFGBS8PGzErtoXq4ie39BbicVYdwS9qvRN7iT" },
    .{ .network = .testnet, .script = .p2wsh, .pub_str = "Vpub5jpT2Y7AzQ7BCdEN65EBVhzwAdLghjcaR2ikLEMFsWPpaQEPTJ6gpuU2zty8j2T7GMEF59RMJh4S1wdzB7iDcaQ2dLD2vvk2qe1KByf7ky3", .priv_str = "Vprv1D8Qt84vr2RWKACaCRZb6JLpbbpkYQRfqj7y3iJxTEbRjuycpuH6eQrApnsvtBxZzVdWKEWhM6YS3EewJwiFYvDYNXM2HMNrEoeovFe9w8M" },
};

test "SLIP-0132 table: every row round-trips and carries its registered prefix" {
    try testing.expectEqual(all_rows.len, bip32.slip132_table.len);
    var k: bip32.ExtendedPrivKey = undefined;
    try accountKey(84, &k);
    defer k.deinit();
    const pubk = try bip32.neuter(&k);
    var buf: [bip32.max_serialized_len]u8 = undefined;
    for (all_rows, bip32.slip132_table) |r, e| {
        try testing.expectEqual(r.network, e.network);
        try testing.expectEqual(r.script, e.script);
        try testing.expect(std.mem.startsWith(u8, r.pub_str, e.pub_prefix));
        try testing.expect(std.mem.startsWith(u8, r.priv_str, e.priv_prefix));
        // serialize
        try testing.expectEqualStrings(r.pub_str, try bip32.serializePubSlip132(pubk, r.network, r.script, &buf));
        try testing.expectEqualStrings(r.priv_str, try bip32.serializePrivSlip132(&k, r.network, r.script, &buf));
        // parse
        var got: bip32.ParsedKey = undefined;
        const ep = try bip32.parseSlip132(r.pub_str, &got);
        try testing.expectEqual(e.pub_version, bip32.slip132Find(e.pub_version).?.entry.pub_version);
        try testing.expectEqual(r.network, ep.network);
        try testing.expectEqual(r.script, ep.script);
        try testing.expectEqualSlices(u8, &pubk.pubkey, &got.public.pubkey);
        const er = try bip32.parseSlip132(r.priv_str, &got);
        try testing.expectEqual(r.network, er.network);
        try testing.expectEqual(r.script, er.script);
        try testing.expectEqualSlices(u8, &k.privkey, &got.private.privkey);
        got.private.deinit();
        // lookup
        const e2 = bip32.slip132Entry(r.network, r.script);
        try testing.expectEqual(e.pub_version, e2.pub_version);
        try testing.expectEqual(e.priv_version, e2.priv_version);
        const m_pub = bip32.slip132Find(e.pub_version).?;
        const m_priv = bip32.slip132Find(e.priv_version).?;
        try testing.expect(!m_pub.is_private);
        try testing.expect(m_priv.is_private);
        try testing.expectEqual(r.script, m_pub.entry.script);
        try testing.expectEqual(r.network, m_priv.entry.network);
    }
}

test "SLIP-0132 table: version words are distinct; x and t rows are BIP-32's constants" {
    var seen: [2 * bip32.slip132_table.len]u32 = undefined;
    for (bip32.slip132_table, 0..) |e, i| {
        seen[2 * i] = e.pub_version;
        seen[2 * i + 1] = e.priv_version;
    }
    for (seen, 0..) |a, i| for (seen[i + 1 ..]) |b| try testing.expect(a != b);
    const x = bip32.slip132Entry(.mainnet, .p2pkh_or_p2sh);
    try testing.expectEqual(bip32.version_mainnet_pub, x.pub_version);
    try testing.expectEqual(bip32.version_mainnet_priv, x.priv_version);
    const t = bip32.slip132Entry(.testnet, .p2pkh_or_p2sh);
    try testing.expectEqual(bip32.version_testnet_pub, t.pub_version);
    try testing.expectEqual(bip32.version_testnet_priv, t.priv_version);
    // not registered here: Litecoin's Ltub (0x019da462), zero, a neighbour of xpub
    try testing.expect(bip32.slip132Find(0x019da462) == null);
    try testing.expect(bip32.slip132Find(0) == null);
    try testing.expect(bip32.slip132Find(bip32.version_mainnet_pub + 1) == null);
    try testing.expect(bip32.slip132Find(bip32.version_mainnet_priv -% 1) == null);
}

test "parseExtended is unchanged: it still refuses a SLIP-0132 prefix, parseSlip132 takes x and t too" {
    var got: bip32.ParsedKey = undefined;
    // `.mainnet` accepts xpub/xprv only; y/z are unknown to BIP-32, the testnet pair is the other network's.
    try testing.expectError(error.UnknownVersion, bip32.parseExtended(accounts[1].xpub, .mainnet, &got));
    try testing.expectError(error.UnknownVersion, bip32.parseExtended(accounts[2].xprv, .mainnet, &got));
    try testing.expectError(error.UnknownVersion, bip32.parseExtended(all_rows[7].pub_str, .testnet, &got));
    try testing.expectError(error.WrongNetwork, bip32.parseExtended(all_rows[5].pub_str, .mainnet, &got));
    try bip32.parseExtended(accounts[0].xpub, .mainnet, &got);
    const e = try bip32.parseSlip132(accounts[0].xpub, &got);
    try testing.expectEqual(bip32.Slip132Script.p2pkh_or_p2sh, e.script);
    try testing.expectEqual(bip32.Network.mainnet, e.network);
    const t = try bip32.parseSlip132(all_rows[5].pub_str, &got);
    try testing.expectEqual(bip32.Network.testnet, t.network);
}

/// Re-encode `s` with another version word.
fn withVersion(s: []const u8, version: u32, out: []u8) ![]const u8 {
    var buf: [bech32.base58.max_payload_len]u8 = undefined;
    const n = (try bech32.base58.checkDecode(s, &buf)).len;
    const payload = buf[0..n];
    std.mem.writeInt(u32, payload[0..4], version, .big);
    return bech32.base58.checkEncode(payload, out);
}

test "parseSlip132 refuses unregistered version words and keeps parseExtended's other checks" {
    var got: bip32.ParsedKey = undefined;
    var buf: [bip32.max_serialized_len]u8 = undefined;
    const zpub = accounts[2].xpub;
    // Litecoin's Ltub, and words one off a registered one, in either key type.
    for ([_]u32{ 0x019da462, 0x04b24745, 0x04b24747, 0x04b2430d, 0 }) |v| {
        try testing.expectError(error.UnknownVersion, bip32.parseSlip132(try withVersion(zpub, v, &buf), &got));
    }
    // A public payload under a private version word: the key-type marker is wrong.
    try testing.expectError(error.InvalidPrivateKeyMarker, bip32.parseSlip132(try withVersion(zpub, bip32.slip132Entry(.mainnet, .p2wpkh).priv_version, &buf), &got));
    // A private payload under a public version word: not a point.
    try testing.expectError(error.InvalidPublicKey, bip32.parseSlip132(try withVersion(accounts[2].xprv, bip32.slip132Entry(.mainnet, .p2wpkh).pub_version, &buf), &got));
    // Checksum and length are still checked.
    var bad: [bip32.max_serialized_len]u8 = undefined;
    @memcpy(bad[0..zpub.len], zpub);
    bad[zpub.len - 1] = if (bad[zpub.len - 1] == '2') '3' else '2';
    try testing.expectError(error.ChecksumMismatch, bip32.parseSlip132(bad[0..zpub.len], &got));
    const short = try bech32.base58.checkEncode(&[_]u8{ 0x04, 0xb2, 0x47, 0x46, 0, 0, 0, 0, 0, 0 }, &buf);
    try testing.expectError(error.InvalidLength, bip32.parseSlip132(short, &got));
}

test "SLIP-0132 zero-depth rule applies to every prefix" {
    // A depth-0 payload with a non-zero fingerprint is refused under a zpub version word too.
    var buf: [bip32.max_serialized_len]u8 = undefined;
    var raw: [bech32.base58.max_payload_len]u8 = undefined;
    const n = (try bech32.base58.checkDecode(accounts[2].xpub, &raw)).len;
    const payload = raw[0..n];
    payload[4] = 0; // depth 0, fingerprint still non-zero
    const s = try bech32.base58.checkEncode(payload, &buf);
    var got: bip32.ParsedKey = undefined;
    try testing.expectError(error.ZeroDepthNonZeroFingerprint, bip32.parseSlip132(s, &got));
}
