// SPDX-License-Identifier: MIT
//! Tests added by the 2026-11-17 whole-module mutation of `bech32.zig`,
//! `segwit.zig` and `base58.zig`: the boundary cases the BIP vectors and the
//! round-trip tests did not pin (single-letter case mixing, the HRP byte
//! range ends, uppercase HRP checksums, program lengths just outside 2..40,
//! exact-size output buffers, the zeroed tail of `encodeSecret`, a real
//! public key through `encodeP2PKH`).
const std = @import("std");
const t = std.testing;
const bech32 = @import("bech32.zig");
const segwit = @import("segwit.zig");
const base58 = @import("base58.zig");

test "decode: one lowercase letter 'a' or 'z' against an uppercase letter is MixedCase, ahead of every other error" {
    try t.expectError(error.MixedCase, bech32.decode("Z1a"));
    try t.expectError(error.MixedCase, bech32.decode("A1z"));
    try t.expectError(error.MixedCase, bech32.decode("a1Z"));
    try t.expectError(error.MixedCase, bech32.decode("z1A"));
}

test "HRP bytes 33 and 126 are accepted both ways and round-trip" {
    const data = [_]u5{ 1, 2, 3 };
    inline for (.{ "!", "~", "!~", "~!" }) |hrp| {
        const enc = try bech32.encode(hrp, &data, .bech32);
        const dec = try bech32.decode(enc.slice());
        try t.expectEqualStrings(hrp, dec.hrp());
        try t.expectEqualSlices(u5, &data, dec.data());
    }
}

test "encode lowers the HRP before the checksum: BC and bc give the same string, and it decodes" {
    const data = [_]u5{ 0, 14, 20, 15, 7, 13, 26, 0, 25, 18, 6, 11 };
    const upper = try bech32.encode("BC", &data, .bech32);
    const lower = try bech32.encode("bc", &data, .bech32);
    try t.expectEqualStrings(lower.slice(), upper.slice());
    const dec = try bech32.decode(upper.slice());
    try t.expectEqualStrings("bc", dec.hrp());
    const mixed = try bech32.encode("Bc", &data, .bech32m);
    try t.expectEqual(bech32.Encoding.bech32m, (try bech32.decode(mixed.slice())).encoding);
}

test "encodeSegwit: program lengths 0, 1, 41 and 42 are InvalidProgramLength for every version" {
    var prog: [42]u8 = @splat(0x5a);
    for ([_]u5{ 0, 1, 16 }) |v| {
        for ([_]usize{ 0, 1, 41, 42 }) |n| {
            try t.expectError(error.InvalidProgramLength, segwit.encodeSegwit("bc", v, prog[0..n]));
        }
    }
    // the neighbours inside the range are fine for v1+
    _ = try segwit.encodeSegwit("bc", 1, prog[0..2]);
    _ = try segwit.encodeSegwit("bc", 16, prog[0..40]);
}

test "base58 encode / decode: an output buffer of exactly the result size works, one byte less is BufferTooSmall" {
    const data = [_]u8{ 0, 0, 1, 2, 3, 4, 5, 6, 7, 8 };
    var big: [64]u8 = undefined;
    const s = try base58.encode(&data, &big);
    var exact: [64]u8 = undefined;
    try t.expectEqualStrings(s, try base58.encode(&data, exact[0..s.len]));
    try t.expectError(error.BufferTooSmall, base58.encode(&data, exact[0 .. s.len - 1]));
    var back: [64]u8 = undefined;
    try t.expectEqualSlices(u8, &data, try base58.decode(s, back[0..data.len]));
    try t.expectError(error.BufferTooSmall, base58.decode(s, back[0 .. data.len - 1]));
}

test "base58check encode / decode: exact-size outputs, a too-small payload buffer, and a payload far over the limit" {
    const payload = [_]u8{ 0x00, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20 };
    var big: [64]u8 = undefined;
    const s = try base58.checkEncode(&payload, &big);
    var back: [64]u8 = undefined;
    try t.expectEqualSlices(u8, &payload, try base58.checkDecode(s, back[0..payload.len]));
    try t.expectError(error.BufferTooSmall, base58.checkDecode(s, back[0 .. payload.len - 1]));
    try t.expectEqualSlices(u8, &payload, try base58.checkDecodeSecret(s, back[0..payload.len]));
    try t.expectError(error.BufferTooSmall, base58.checkDecodeSecret(s, back[0 .. payload.len - 1]));
    var enc: [base58.max_encoded_len]u8 = undefined;
    const long: [200]u8 = @splat(7);
    try t.expectError(error.PayloadTooLarge, base58.checkEncode(&long, &enc));
    try t.expectError(error.PayloadTooLarge, base58.checkEncodeSecret(&long, &enc));
}

test "encodeSecret: an exact-size buffer is enough, and the bytes past the returned string are zero" {
    var prng = std.Random.DefaultPrng.init(0x6d75_7461);
    var shorter: usize = 0;
    for (0..64) |round| {
        var payload: [37]u8 = undefined;
        prng.random().bytes(&payload);
        payload[0] = if (round % 2 == 0) 1 else 0; // small top byte: fewer digits than the bound
        const ld = base58.maxEncodedLenFor(payload.len);
        var out: [base58.max_encoded_len]u8 = @splat(0xff);
        const got = try base58.encodeSecret(&payload, out[0..ld]);
        var oracle: [base58.max_encoded_len]u8 = undefined;
        try t.expectEqualStrings(try base58.encode(&payload, &oracle), got);
        for (out[got.len..ld]) |b| try t.expectEqual(@as(u8, 0), b);
        for (out[ld..]) |b| try t.expectEqual(@as(u8, 0xff), b);
        if (got.len < ld) shorter += 1;
    }
    try t.expect(shorter > 0); // the barrel shift was exercised
}

test "encodeP2PKH: the compressed generator key gives the well-known address; version 0x6f is carried" {
    var pubkey: [33]u8 = undefined;
    _ = std.fmt.hexToBytes(&pubkey, "0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798") catch unreachable;
    var out: [64]u8 = undefined;
    try t.expectEqualStrings("1BgGZ9tcN4rm9KBzDn7KprQz87SZ26SAMH", try base58.encodeP2PKH(0x00, &pubkey, &out));
    const testnet = try base58.encodeP2PKH(0x6f, &pubkey, &out);
    var back: [64]u8 = undefined;
    const payload = try base58.checkDecode(testnet, &back);
    try t.expectEqual(@as(usize, base58.p2pkh_payload_len), payload.len);
    try t.expectEqual(@as(u8, 0x6f), payload[0]);
    try t.expectEqualSlices(u8, &.{ 0x75, 0x1e, 0x76, 0xe8, 0x19, 0x91, 0x96, 0xd4, 0x54, 0x94, 0x1c, 0x45, 0xd1, 0xb3, 0xa3, 0x23, 0xf1, 0x43, 0x3b, 0xd6 }, payload[1..]);
}
