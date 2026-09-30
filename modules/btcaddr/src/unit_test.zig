// SPDX-License-Identifier: MIT
//! Typed rejection reasons, network sets, and the script helpers. Expected
//! values for the helpers were derived independently (Python hashlib, BIP143
//! and BIP173 examples), not with this module.

const std = @import("std");
const testing = std.testing;
const btcaddr = @import("root.zig");
const bech32 = @import("bech32");

fn hex(comptime s: []const u8) *const [s.len / 2]u8 {
    const out = comptime blk: {
        var o: [s.len / 2]u8 = undefined;
        _ = std.fmt.hexToBytes(&o, s) catch unreachable;
        break :blk o;
    };
    return &out;
}

const g_pub = hex("0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798");

test "network sets are honest about shared encodings" {
    // mainnet is unambiguous
    const m = try btcaddr.toScriptPubKey("1BgGZ9tcN4rm9KBzDn7KprQz87SZ26SAMH");
    try testing.expectEqual(btcaddr.Network.mainnet, m.chains.unique().?);
    // base58 test-network versions: testnet, signet and regtest all match
    const t = try btcaddr.toScriptPubKey("mrCDrCybB6J1vRfbwM5hemdJz73FwDBC8r");
    try testing.expectEqual(@as(u3, 3), t.chains.count());
    try testing.expect(t.chains.contains(.testnet) and t.chains.contains(.signet) and t.chains.contains(.regtest));
    try testing.expectEqual(@as(?btcaddr.Network, null), t.chains.unique());
    // `tb`: testnet + signet, not regtest; `bcrt`: regtest only
    const tb = try btcaddr.toScriptPubKey("tb1qw508d6qejxtdg4y5r3zarvary0c5xw7kxpjzsx");
    try testing.expect(tb.chains.contains(.testnet) and tb.chains.contains(.signet) and !tb.chains.contains(.regtest));
    const rt = try btcaddr.fromScriptPubKey(hex("0014751e76e8199196d454941c45d1b3a323f1433bd6"), .regtest);
    try testing.expect(std.mem.startsWith(u8, rt.slice(), "bcrt1q"));
    const rtd = try btcaddr.toScriptPubKey(rt.slice());
    try testing.expectEqual(btcaddr.Network.regtest, rtd.chains.unique().?);
}

test "BIP173 / BIP350 examples: kinds, payloads and round trip" {
    const p2wpkh = try btcaddr.toScriptPubKey("bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t4");
    try testing.expectEqual(btcaddr.ScriptKind.p2wpkh, p2wpkh.kind);
    try testing.expectEqualSlices(u8, hex("751e76e8199196d454941c45d1b3a323f1433bd6"), p2wpkh.payload());
    const p2wsh = try btcaddr.toScriptPubKey("bc1qrp33g0q5c5txsp9arysrx4k6zdkfs4nce4xj0gdcccefvpysxf3qccfmv3");
    try testing.expectEqual(btcaddr.ScriptKind.p2wsh, p2wsh.kind);
    // BIP350 v1 with a 32-byte program is taproot; v16 with 2 bytes is "unknown"
    const tr = try btcaddr.toScriptPubKey("bc1p0xlxvlhemja6c4dqv22uapctqupfhlxm9h8z3k2e72q4k9hcz7vqzk5jj0");
    try testing.expectEqual(btcaddr.ScriptKind.p2tr, tr.kind);
    const v16 = try btcaddr.toScriptPubKey("bc1sw50qgdz25j");
    try testing.expectEqual(btcaddr.ScriptKind.witness_unknown, v16.kind);
    try testing.expectEqualSlices(u8, hex("6002751e"), v16.script());
    const back = try btcaddr.fromScriptPubKey(v16.script(), .mainnet);
    try testing.expectEqualStrings("bc1sw50qgdz25j", back.slice());
    // v1 with a 20-byte program: encodable, not taproot
    const s1 = hex("5114751e76e8199196d454941c45d1b3a323f1433bd6");
    try testing.expectEqual(btcaddr.ScriptKind.witness_unknown, btcaddr.classify(s1).?);
    _ = try btcaddr.fromScriptPubKey(s1, .mainnet);
}

test "fromScriptPubKey: non-standard scripts are UnsupportedScript" {
    const h20 = "751e76e8199196d454941c45d1b3a323f1433bd6";
    const bad = [_][]const u8{
        &.{}, // empty
        hex("6a0468656c6c6f"), // OP_RETURN
        hex("21" ++ "0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798" ++ "ac"), // P2PK
        hex("76a914" ++ h20 ++ "88ac00"), // P2PKH + trailing byte
        hex("76a913" ++ h20[0..38] ++ "88ac"), // 19-byte hash
        hex("a914" ++ h20 ++ "88"), // wrong terminator
        hex("0010" ++ "751e76e8199196d454941c45d1b3a323"), // v0, 16-byte program
        hex("0015" ++ h20 ++ "00"), // v0, 21-byte program
        hex("0114" ++ h20), // OP_PUSH1 is not a witness version
        hex("5114" ++ h20 ++ "00"), // push length != remaining bytes
        hex("5101ff"), // 1-byte program
        hex("6029" ++ ("00" ** 41)), // 41-byte program
        hex("004c14" ++ h20), // OP_PUSHDATA1 (non-minimal) form
    };
    for (bad) |s| {
        try testing.expectError(error.UnsupportedScript, btcaddr.fromScriptPubKey(s, .mainnet));
        try testing.expect(btcaddr.classify(s) == null);
    }
}

test "toScriptPubKey: typed rejection reasons" {
    // bech32 side (BIP173/BIP350 invalid vectors)
    try testing.expectError(error.InvalidVariant, btcaddr.toScriptPubKey("bc1p0xlxvlhemja6c4dqv22uapctqupfhlxm9h8z3k2e72q4k9hcz7vqh2y7hd"));
    try testing.expectError(error.InvalidVariant, btcaddr.toScriptPubKey("tb1z0xlxvlhemja6c4dqv22uapctqupfhlxm9h8z3k2e72q4k9hcz7vqglt7rf"));
    try testing.expectError(error.InvalidWitnessVersion, btcaddr.toScriptPubKey("BC130XLXVLHEMJA6C4DQV22UAPCTQUPFHLXM9H8Z3K2E72Q4K9HCZ7VQ7ZWS8R"));
    try testing.expectError(error.InvalidProgramLength, btcaddr.toScriptPubKey("bc1pw5dgrnzv"));
    try testing.expectError(error.InvalidProgramLength, btcaddr.toScriptPubKey("BC1QR508D6QEJXTDG4Y5R3ZARVARYV98GJ9P"));
    try testing.expectError(error.MixedCase, btcaddr.toScriptPubKey("tb1p0xlxvlhemja6c4dqv22uapctqupfhlxm9h8z3k2e72q4k9hcz7vq47Zagq"));
    try testing.expectError(error.InvalidChecksum, btcaddr.toScriptPubKey("bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t5"));

    // foreign HRP: valid bech32, not ours
    const ltc = try bech32.encode("ltc", &[_]u5{ 0, 1, 2 }, .bech32);
    try testing.expectError(error.UnknownHrp, btcaddr.toScriptPubKey(ltc.slice()));
    // "bc1" prefix but the real HRP is longer
    const bc1x = try bech32.encode("bc1x", &[_]u5{ 0, 1, 2 }, .bech32);
    try testing.expectError(error.UnknownHrp, btcaddr.toScriptPubKey(bc1x.slice()));

    // base58 side
    try testing.expectError(error.ChecksumMismatch, btcaddr.toScriptPubKey("1BgGZ9tcN4rm9KBzDn7KprQz87SZ26SAMJ"));
    try testing.expectError(error.InvalidChar, btcaddr.toScriptPubKey("1BgGZ9tcN4rm9KBzDn7KprQz87SZ26SAM0"));
    var buf: [64]u8 = undefined;
    const short = try bech32.base58.checkEncode(&([_]u8{0x00} ++ ([_]u8{7} ** 19)), &buf);
    try testing.expectError(error.InvalidPayloadLength, btcaddr.toScriptPubKey(short));
    const unk = try bech32.base58.checkEncode(&([_]u8{0x01} ++ ([_]u8{7} ** 20)), &buf);
    try testing.expectError(error.UnknownVersionByte, btcaddr.toScriptPubKey(unk));
    try testing.expectError(error.InvalidPayloadLength, btcaddr.toScriptPubKey("1" ** 180));
    try testing.expectError(error.TooShort, btcaddr.toScriptPubKey("11"));
    // wrong network is its own reason
    const rt = try btcaddr.fromScriptPubKey(hex("0014751e76e8199196d454941c45d1b3a323f1433bd6"), .regtest);
    try testing.expectError(error.WrongNetwork, btcaddr.toScriptPubKeyFor("bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t4", .testnet));
    try testing.expectError(error.WrongNetwork, btcaddr.toScriptPubKeyFor(rt.slice(), .testnet));
}

test "WIF: typed rejection reasons and well-known key 1" {
    var one = [_]u8{0} ** 32;
    one[31] = 1;
    var out: [btcaddr.max_wif_len]u8 = undefined;
    defer std.crypto.secureZero(u8, &out);
    try testing.expectEqualStrings("5HpHagT65TZzG1PH3CSu63k8DbpvD8s5ip4nEB3kEsreAnchuDf", try btcaddr.wifEncode(&one, false, .mainnet, &out));
    try testing.expectEqualStrings("KwDiBf89QgGbjEhKnhXJuH7LrciVrZi3qYjgd9M7rFU73sVHnoWn", try btcaddr.wifEncode(&one, true, .mainnet, &out));
    try testing.expectEqualStrings("cMahea7zqjxrtgAbB7LSGbcQUr1uX1ojuat9jZodMN87JcbXMTcA", try btcaddr.wifEncode(&one, true, .signet, &out));

    var w = try btcaddr.wifDecode("KwDiBf89QgGbjEhKnhXJuH7LrciVrZi3qYjgd9M7rFU73sVHnoWn");
    try testing.expect(w.compressed and w.chains.unique() == .mainnet);
    try testing.expectEqualSlices(u8, &one, &w.key);
    w.wipe();
    try testing.expectEqualSlices(u8, &([_]u8{0} ** 32), &w.key);

    var buf: [64]u8 = undefined;
    var payload: [35]u8 = undefined;
    // flag byte other than 0x01
    payload[0] = 0x80;
    payload[1..33].* = one;
    payload[33] = 0x02;
    try testing.expectError(error.InvalidCompressionFlag, btcaddr.wifDecode(try bech32.base58.checkEncode(payload[0..34], &buf)));
    // lengths
    try testing.expectError(error.InvalidPayloadLength, btcaddr.wifDecode(try bech32.base58.checkEncode(payload[0..32], &buf)));
    payload[33] = 0x01;
    payload[34] = 0x01;
    try testing.expectError(error.InvalidPayloadLength, btcaddr.wifDecode(try bech32.base58.checkEncode(payload[0..35], &buf)));
    // version byte
    payload[0] = 0x81;
    try testing.expectError(error.UnknownVersionByte, btcaddr.wifDecode(try bech32.base58.checkEncode(payload[0..33], &buf)));
    // scalar out of range: zero, n, n-1 is fine
    payload[0] = 0x80;
    @memset(payload[1..33], 0);
    try testing.expectError(error.InvalidKey, btcaddr.wifDecode(try bech32.base58.checkEncode(payload[0..33], &buf)));
    const n = hex("fffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364141");
    payload[1..33].* = n.*;
    try testing.expectError(error.InvalidKey, btcaddr.wifDecode(try bech32.base58.checkEncode(payload[0..33], &buf)));
    var nm1 = n.*;
    nm1[31] -= 1;
    payload[1..33].* = nm1;
    var ok = try btcaddr.wifDecode(try bech32.base58.checkEncode(payload[0..33], &buf));
    ok.wipe();
    try testing.expectError(error.InvalidKey, btcaddr.wifEncode(n, true, .mainnet, &out));
    try testing.expectError(error.InvalidKey, btcaddr.wifEncode(&([_]u8{0} ** 32), true, .mainnet, &out));
    // checksum
    try testing.expectError(error.ChecksumMismatch, btcaddr.wifDecode("KwDiBf89QgGbjEhKnhXJuH7LrciVrZi3qYjgd9M7rFU73sVHnoWm"));
    // an address is not a WIF key
    try testing.expectError(error.InvalidPayloadLength, btcaddr.wifDecode("1BgGZ9tcN4rm9KBzDn7KprQz87SZ26SAMH"));
    // buffer too small is reported, not truncated
    var tiny: [10]u8 = undefined;
    try testing.expectError(error.BufferTooSmall, btcaddr.wifEncode(&one, true, .mainnet, &tiny));
}

test "helpers: keys, P2SH, P2WSH, P2SH-P2WPKH" {
    // P2PKH / P2WPKH of the generator key (BIP173: same hash160)
    const p2pkh = try btcaddr.p2pkhOfPublicKey(g_pub);
    try testing.expectEqualSlices(u8, hex("76a914751e76e8199196d454941c45d1b3a323f1433bd688ac"), &p2pkh);
    try testing.expectEqualStrings("1BgGZ9tcN4rm9KBzDn7KprQz87SZ26SAMH", (try btcaddr.fromScriptPubKey(&p2pkh, .mainnet)).slice());
    try testing.expectEqualStrings("mrCDrCybB6J1vRfbwM5hemdJz73FwDBC8r", (try btcaddr.fromScriptPubKey(&p2pkh, .testnet)).slice());
    const p2wpkh = try btcaddr.p2wpkhOfPublicKey(g_pub);
    try testing.expectEqualStrings("bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t4", (try btcaddr.fromScriptPubKey(&p2wpkh, .mainnet)).slice());

    // BIP143 native P2SH-P2WPKH example: scriptPubKey a9144733f3...2387
    const bip143_pub = hex("03ad1d8e89212f0b92c74d23bb710c00662ad1470198ac48c43f7d6f93a2a26873");
    const nested = try btcaddr.p2shP2wpkhOfPublicKey(bip143_pub);
    try testing.expectEqualSlices(u8, hex("a9144733f37cf4db86fbc2efed2500b4f4e49f31202387"), &nested);
    try testing.expectEqualStrings("38BW8nqpHSWpkf5sXrQd2xYwvnPJwP59ic", (try btcaddr.fromScriptPubKey(&nested, .mainnet)).slice());
    try testing.expectEqualStrings("2MyjiCXmqtu2AxSiRCz2VeuYD98bUhXRzNR", (try btcaddr.fromScriptPubKey(&nested, .testnet)).slice());

    // P2SH of a 1-of-1 multisig redeem script (hash derived with Python hashlib)
    const redeem = hex("5121" ++ "0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798" ++ "51ae");
    const p2sh = try btcaddr.p2shOfRedeemScript(redeem);
    try testing.expectEqualSlices(u8, hex("a91483eebb7d79aa1d388e3b0ac65b98ac580c4da01a87"), &p2sh);
    try testing.expectEqualStrings("3DicS6C8JZm59RsrgXr56iVHzYdQngiehV", (try btcaddr.fromScriptPubKey(&p2sh, .mainnet)).slice());

    // BIP173 P2WSH: witness script is <G> OP_CHECKSIG
    const ws = hex("21" ++ "0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798" ++ "ac");
    const p2wsh = try btcaddr.p2wshOfWitnessScript(ws);
    try testing.expectEqualSlices(u8, hex("00201863143c14c5166804bd19203356da136c985678cd4d27a1b8c6329604903262"), &p2wsh);
    try testing.expectEqualStrings("bc1qrp33g0q5c5txsp9arysrx4k6zdkfs4nce4xj0gdcccefvpysxf3qccfmv3", (try btcaddr.fromScriptPubKey(&p2wsh, .mainnet)).slice());
    // P2SH-P2WSH is the P2SH of that 34-byte script
    const nested_wsh = try btcaddr.p2shP2wshOfWitnessScript(ws);
    try testing.expectEqualSlices(u8, &btcaddr.scriptP2sh(&btcaddr.hash160(&p2wsh)), &nested_wsh);

    // P2TR from an output key (BIP350 vector program)
    const tr_key = hex("79be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798");
    const tr = btcaddr.scriptP2tr(tr_key);
    try testing.expectEqualStrings("bc1p0xlxvlhemja6c4dqv22uapctqupfhlxm9h8z3k2e72q4k9hcz7vqzk5jj0", (try btcaddr.fromScriptPubKey(&tr, .mainnet)).slice());
}

test "helpers: typed rejections" {
    const uncompressed = [_]u8{0x04} ++ [_]u8{0x11} ** 64;
    _ = try btcaddr.p2pkhOfPublicKey(&uncompressed);
    try testing.expectError(error.UncompressedPublicKey, btcaddr.p2wpkhOfPublicKey(&uncompressed));
    try testing.expectError(error.UncompressedPublicKey, btcaddr.p2shP2wpkhOfPublicKey(&uncompressed));
    try testing.expectError(error.InvalidPublicKey, btcaddr.p2pkhOfPublicKey(g_pub[0..32]));
    var bad_prefix = g_pub.*;
    bad_prefix[0] = 0x05;
    try testing.expectError(error.InvalidPublicKey, btcaddr.p2pkhOfPublicKey(&bad_prefix));
    try testing.expectError(error.InvalidPublicKey, btcaddr.p2wpkhOfPublicKey(&.{}));

    var big: [10001]u8 = undefined;
    @memset(&big, 0x51);
    _ = try btcaddr.p2shOfRedeemScript(big[0..520]);
    try testing.expectError(error.RedeemScriptTooLarge, btcaddr.p2shOfRedeemScript(big[0..521]));
    _ = try btcaddr.p2wshOfWitnessScript(big[0..10000]);
    try testing.expectError(error.WitnessScriptTooLarge, btcaddr.p2wshOfWitnessScript(big[0..10001]));
    try testing.expectError(error.WitnessScriptTooLarge, btcaddr.p2shP2wshOfWitnessScript(big[0..10001]));
}

// ── fuzz: the two entry points that take untrusted strings ────────────────

const testkit = @import("testkit");

const fuzz_seeds = [_][]const u8{
    testkit.fuzz.seed("1FsSia9rv4NeEwvJ2GvXrX7LyxYspbN2mo"),
    testkit.fuzz.seed("36j4NfKv6Akva9amjWrLG6MuSQym1GuEmm"),
    testkit.fuzz.seed("bc1qvyq0cc6rahyvsazfdje0twl7ez82ndmuac2lhv"),
    testkit.fuzz.seed("BC1P83N3AU0RJYLEFXQ2NC2XH2Y4JZZ4PM6ZXJ4MW5PAGDJJR2A9F36S6JJNNU"),
    testkit.fuzz.seed("tb1p35n52jy6xkm4wd905tdy8qtagrn73kqdz73xe4zxpvq9t3fp50aqk3s6gz"),
    testkit.fuzz.seed("bcrt1pfwxjqvtt4tcxrtdluukfmy2dv7xd2qzdfy6kajv5nwn4yam3wxkq3553uh"),
    testkit.fuzz.seed("L5nJeqKmpHp4P7F8ZYyjwc5a7P4d8EabuGAzfGJk7yC1BJyzNaEd"),
    testkit.fuzz.seed("cV83kKisF3RQSvXbUCm9ox3kaz5JjEUBWcx8tNydfGJcyeUxuH47"),
    testkit.fuzz.seed(""),
};

test "fuzz: toScriptPubKey and wifDecode never panic; what they accept round-trips" {
    try testing.fuzz({}, fuzzDecode, .{ .corpus = &fuzz_seeds });
}

fn fuzzDecode(_: void, smith: *testing.Smith) !void {
    var text: [128]u8 = undefined;
    const len: usize = smith.slice(&text);
    const s = text[0..len];

    if (btcaddr.toScriptPubKey(s)) |d| {
        // An accepted address is the canonical encoding of its script on
        // one of the chains it claims (bech32: modulo case).
        const net: btcaddr.Network = inline for (.{ .mainnet, .testnet, .signet, .regtest }) |n| {
            if (d.chains.contains(n)) break n;
        } else return error.NoChain;
        const back = try btcaddr.fromScriptPubKey(d.script(), net);
        try testing.expect(std.ascii.eqlIgnoreCase(back.slice(), s));
    } else |_| {}

    if (btcaddr.wifDecode(s)) |w_const| {
        var w = w_const;
        defer w.wipe();
        const net: btcaddr.Network = if (w.chains.contains(.mainnet)) .mainnet else .testnet;
        var out: [btcaddr.max_wif_len]u8 = undefined;
        defer std.crypto.secureZero(u8, &out);
        try testing.expectEqualStrings(s, try btcaddr.wifEncode(&w.key, w.compressed, net, &out));
    } else |_| {}
}
