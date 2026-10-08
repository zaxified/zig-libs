// SPDX-License-Identifier: MIT

//! Byte-exact KATs for `hash.zig` and the scalar operations an RFC 9497
//! OPRF exercises, against two EXTERNAL sources:
//!
//!   - **RFC 9380 Appendix K.6** — `expand_message_xof(SHAKE256)`, DST
//!     `QUUX-V01-CS02-with-expander-SHAKE256`, ten vectors (five messages ×
//!     `len_in_bytes` 0x20 and 0x80).
//!   - **RFC 9497 Appendix A.2** — the decaf448-SHAKE256 suite: OPRF mode
//!     test vectors 1 and 2 (`skSm` from `DeriveKeyPair`, `Blind`,
//!     `BlindedElement`, `EvaluationElement`, `Output`) and the VOPRF mode's
//!     `skSm`/`pkSm`. RFC 9496 publishes no hash-to-group vectors of its own
//!     beyond Appendix B.3's one-way map (already in `kat_test.zig`), so
//!     RFC 9497 is where `hash_to_decaf448` with a real DST is anchored.
//!
//! What each RFC 9497 value pins, recomputed here from the RFC's §3 recipes:
//!
//!   - `skSm` = `DeriveKeyPair(seed, keyInfo)` — `hash.hashToScalar` (64-byte
//!     `expand_message_xof` + `scalar.reduce`) with DST
//!     `"DeriveKeyPair" || contextString`.
//!   - `pkSm` = `ScalarMultGen(skSm)` — `Element.scalarMul` + `encode`.
//!   - `BlindedElement` = `blind * HashToGroup(input)` — `hash.hashToElement`
//!     with DST `"HashToGroup-" || contextString`.
//!   - `EvaluationElement` = `skSm * BlindedElement` — `decode` + `scalarMul`.
//!   - `Output` = `SHAKE256(len(input) || input || len(N) || N || "Finalize", 64)`
//!     with `N = encode(invert(blind) * EvaluationElement)` — this is the
//!     external anchor for `scalar.invert`.
//!
//! Transcription: the hex below was taken from the CFRG drafts' generator
//! output (`cfrg/draft-irtf-cfrg-hash-to-curve` `poc/vectors/
//! expand_message_xof_SHAKE256_36.json` and `cfrg/draft-irtf-cfrg-voprf`
//! `poc/vectors/allVectors.json`), which is what the two RFCs print in the
//! appendices named above; rfc-editor.org itself was not reachable from the
//! host that wrote this. A transcription error cannot pass silently — every
//! value is an output of a hash or a scalar multiplication, so a wrong digit
//! fails the test rather than agreeing with it.

const std = @import("std");
const testing = std.testing;

const element = @import("element.zig");
const scalar = @import("scalar.zig");
const hash = @import("hash.zig");

const Element = element.Element;

fn hexN(comptime n: usize, comptime hex: *const [2 * n:0]u8) [n]u8 {
    @setEvalBranchQuota(100_000);
    var buf: [n]u8 = undefined;
    _ = std.fmt.hexToBytes(&buf, hex) catch unreachable;
    return buf;
}

// ── RFC 9380 Appendix K.6: expand_message_xof(SHAKE256) ──────────────────

const k6_dst = "QUUX-V01-CS02-with-expander-SHAKE256";
const k6_q128 = "q128_" ++ "q" ** 128;
const k6_a512 = "a512_" ++ "a" ** 512;

const K6Short = struct { msg: []const u8, out: [0x20]u8 };
const K6Long = struct { msg: []const u8, out: [0x80]u8 };

const k6_short = [_]K6Short{
    .{ .msg = "", .out = hexN(0x20, "2ffc05c48ed32b95d72e807f6eab9f7530dd1c2f013914c8fed38c5ccc15ad76") },
    .{ .msg = "abc", .out = hexN(0x20, "b39e493867e2767216792abce1f2676c197c0692aed061560ead251821808e07") },
    .{ .msg = "abcdef0123456789", .out = hexN(0x20, "245389cf44a13f0e70af8665fe5337ec2dcd138890bb7901c4ad9cfceb054b65") },
    .{ .msg = k6_q128, .out = hexN(0x20, "719b3911821e6428a5ed9b8e600f2866bcf23c8f0515e52d6c6c019a03f16f0e") },
    .{ .msg = k6_a512, .out = hexN(0x20, "9181ead5220b1963f1b5951f35547a5ea86a820562287d6ca4723633d17ccbbc") },
};

const k6_long = [_]K6Long{
    .{ .msg = "", .out = hexN(0x80, "7a1361d2d7d82d79e035b8880c5a3c86c5afa719478c007d96e6c88737a3f631dd74a2c88df79a4cb5e5d9f7504957c7" ++
        "0d669ec6bfedc31e01e2bacc4ff3fdf9b6a00b17cc18d9d72ace7d6b81c2e481b4f73f34f9a7505dccbe8f5485f3d20c" ++
        "5409b0310093d5d6492dea4e18aa6979c23c8ea5de01582e9689612afbb353df") },
    .{ .msg = "abc", .out = hexN(0x80, "a54303e6b172909783353ab05ef08dd435a558c3197db0c132134649708e0b9b4e34fb99b92a9e9e28fc1f1d8860d858" ++
        "97a8e021e6382f3eea10577f968ff6df6c45fe624ce65ca25932f679a42a404bc3681efe03fcd45ef73bb3a8f79ba784" ++
        "f80f55ea8a3c367408f30381299617f50c8cf8fbb21d0f1e1d70b0131a7b6fbe") },
    .{ .msg = "abcdef0123456789", .out = hexN(0x80, "e42e4d9538a189316e3154b821c1bafb390f78b2f010ea404e6ac063deb8c0852fcd412e098e231e43427bd2be1330bb" ++
        "47b4039ad57b30ae1fc94e34993b162ff4d695e42d59d9777ea18d3848d9d336c25d2acb93adcad009bcfb9cde12286d" ++
        "f267ada283063de0bb1505565b2eb6c90e31c48798ecdc71a71756a9110ff373") },
    .{ .msg = k6_q128, .out = hexN(0x80, "4ac054dda0a38a65d0ecf7afd3c2812300027c8789655e47aecf1ecc1a2426b17444c7482c99e5907afd9c25b9919904" ++
        "90bb9c686f43e79b4471a23a703d4b02f23c669737a886a7ec28bddb92c3a98de63ebf878aa363a501a60055c048bea1" ++
        "1840c4717beae7eee28c3cfa42857b3d130188571943a7bd747de831bd6444e0") },
    .{ .msg = k6_a512, .out = hexN(0x80, "09afc76d51c2cccbc129c2315df66c2be7295a231203b8ab2dd7f95c2772c68e500bc72e20c602abc9964663b7a03a38" ++
        "9be128c56971ce81001a0b875e7fd17822db9d69792ddf6a23a151bf470079c518279aef3e75611f8f828994a9988f4a" ++
        "8a256ddb8bae161e658d5a2a09bcfe839c6396dc06ee5c8ff3c22d3b1f9deb7e") },
};

test "RFC 9380 K.6: expand_message_xof(SHAKE256), len_in_bytes = 0x20" {
    for (k6_short) |v| {
        var out: [0x20]u8 = undefined;
        try hash.expandMessageXof(&out, v.msg, k6_dst);
        try testing.expectEqualSlices(u8, &v.out, &out);
    }
}

test "RFC 9380 K.6: expand_message_xof(SHAKE256), len_in_bytes = 0x80" {
    for (k6_long) |v| {
        var out: [0x80]u8 = undefined;
        try hash.expandMessageXof(&out, v.msg, k6_dst);
        try testing.expectEqualSlices(u8, &v.out, &out);
    }
}

// ── RFC 9497 Appendix A.2: decaf448-SHAKE256 ─────────────────────────────

fn contextString(comptime mode: u8) *const [26]u8 {
    return "OPRFV1-" ++ [1]u8{mode} ++ "-decaf448-SHAKE256";
}

const seed = hexN(32, "a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3");
const key_info = "test key";

const oprf_sk = hexN(56, "e8b1375371fd11ebeb224f832dcc16d371b4188951c438f751425699ed29ecc80c6c13e558ccd67634fd82eac94aa8d1f0d7fee990695d1e");
const voprf_sk = hexN(56, "e3c01519a076a326a0eb566343e9b21c115fa18e6e85577ddbe890b33104fcc2835ddfb14a928dc3f5d79b936e17c76b99e0bf6a1680930e");
const voprf_pk = hexN(56, "945fc518c47695cf65217ace04b86ac5e4cbe26ca649d52854bb16c494ce09069d6add96b20d4b0ae311a87c9a73e3a146b525763ab2f955");
const group_dst = hexN(38, "48617368546f47726f75702d4f50524656312d002d64656361663434382d5348414b45323536");

const OprfVector = struct {
    input: []const u8,
    blind: [56]u8,
    blinded: [56]u8,
    evaluated: [56]u8,
    output: [64]u8,
};

const oprf_vectors = [_]OprfVector{
    .{
        .input = &[_]u8{0x00},
        .blind = hexN(56, "64d37aed22a27f5191de1c1d69fadb899d8862b58eb4220029e036ec65fa3833a26e9388336361686ff1f83df55046504dfecad8549ba112"),
        .blinded = hexN(56, "e0ae01c4095f08e03b19baf47ffdc19cb7d98e583160522a3c7d6a0b2111cd93a126a46b7b41b730cd7fc943d4e28e590ed33ae475885f6c"),
        .evaluated = hexN(56, "50ce4e60eed006e22e7027454b5a4b8319eb2bc8ced609eb19eb3ad42fb19e06ba12d382cbe7ae342a0cad6ead0ef8f91f00bb7f0cd9c0a2"),
        .output = hexN(64, "37d3f7922d9388a15b561de5829bbf654c4089ede89c0ce0f3f85bcdba09e382ce0ab3507e021f9e79706a1798ffeac68ebd5cf62e5eb9838c7068351d97ae37"),
    },
    .{
        .input = &([_]u8{0x5a} ** 17),
        .blind = hexN(56, "64d37aed22a27f5191de1c1d69fadb899d8862b58eb4220029e036ec65fa3833a26e9388336361686ff1f83df55046504dfecad8549ba112"),
        .blinded = hexN(56, "86a88dc5c6331ecfcb1d9aacb50a68213803c462e377577cacc00af28e15f0ddbc2e3d716f2f39ef95f3ec1314a2c64d940a9f295d8f13bb"),
        .evaluated = hexN(56, "162e9fa6e9d527c3cd734a31bf122a34dbd5bcb7bb23651f1768a7a9274cc116c03b58afa6f0dede3994a60066c76370e7328e7062fd5819"),
        .output = hexN(64, "a2a652290055cb0f6f8637a249ee45e32ef4667db0b4c80c0a70d2a64164d01525cfdad5d870a694ec77972b9b6ec5d2596a5223e5336913f945101f0137f55e"),
    },
};

/// RFC 9497 §3.2.1 `DeriveKeyPair`, private key half.
fn deriveSecretKey(comptime mode: u8) ![56]u8 {
    var derive_input: [32 + 2 + key_info.len + 1]u8 = undefined;
    derive_input[0..32].* = seed;
    std.mem.writeInt(u16, derive_input[32..34], key_info.len, .big);
    @memcpy(derive_input[34 .. 34 + key_info.len], key_info);
    const dst = "DeriveKeyPair" ++ contextString(mode);
    var counter: u16 = 0;
    while (counter <= 255) : (counter += 1) {
        derive_input[derive_input.len - 1] = @intCast(counter);
        const sk = try hash.hashToScalar(&derive_input, dst);
        if (!std.mem.eql(u8, &sk, &scalar.zero)) return sk;
    }
    return error.DeriveKeyPairError;
}

test "RFC 9497 A.2: contextString / HashToGroup DST match the published groupDST" {
    try testing.expectEqualSlices(u8, &group_dst, "HashToGroup-" ++ contextString(0x00));
}

test "RFC 9497 A.2: DeriveKeyPair reproduces skSm (OPRF) and skSm/pkSm (VOPRF) — hashToScalar" {
    try testing.expectEqualSlices(u8, &oprf_sk, &(try deriveSecretKey(0x00)));
    try testing.expectEqualSlices(u8, &voprf_sk, &(try deriveSecretKey(0x01)));
    try testing.expectEqualSlices(u8, &voprf_pk, &Element.generator.scalarMul(&voprf_sk).encode());
}

test "RFC 9497 A.2 OPRF vectors 1-2: Blind/Evaluate/Finalize — hashToElement, scalarMul, invert" {
    for (oprf_vectors) |v| {
        // Blind: blindedElement = blind * HashToGroup(input)
        const h = try hash.hashToElement(v.input, &group_dst);
        const blinded = h.scalarMul(&v.blind);
        try testing.expectEqualSlices(u8, &v.blinded, &blinded.encode());

        // BlindEvaluate: evaluatedElement = skS * blindedElement
        const evaluated = (try Element.decode(v.blinded)).scalarMul(&oprf_sk);
        try testing.expectEqualSlices(u8, &v.evaluated, &evaluated.encode());

        // Finalize: N = blind^-1 * evaluatedElement, then the output hash
        const n = (try Element.decode(v.evaluated)).scalarMul(&scalar.invert(v.blind));
        const unblinded = n.encode();
        var sh = std.crypto.hash.sha3.Shake256.init(.{});
        var len_be: [2]u8 = undefined;
        std.mem.writeInt(u16, &len_be, @intCast(v.input.len), .big);
        sh.update(&len_be);
        sh.update(v.input);
        std.mem.writeInt(u16, &len_be, unblinded.len, .big);
        sh.update(&len_be);
        sh.update(&unblinded);
        sh.update("Finalize");
        var out: [64]u8 = undefined;
        sh.squeeze(&out);
        try testing.expectEqualSlices(u8, &v.output, &out);

        // and the unblinded element is skS * HashToGroup(input) directly
        try testing.expect(n.equals(h.scalarMul(&oprf_sk)));
    }
}
