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

// ── locateErrors (delta mutation 2026-11-25) ────────────────────────────

test "mutation 2026-11-25: locateErrors: the letter ends 'A' 'Z' 'a' 'z' count as letters in the case check" {
    const cases = [_][]const u8{ "Ab1qqqqqq", "Zb1qqqqqq", "Xa1qqqqqq", "Xz1qqqqqq", "bA1qqqqqq", "bZ1qqqqqq" };
    for (cases) |s| {
        const l = bech32.locateErrors(s, null);
        try t.expectEqual(bech32.Fault.mixed_case, l.fault);
        try t.expectEqualSlices(u8, &.{1}, l.positions());
    }
}

test "mutation 2026-11-25: locateErrors: a '1' inside the HRP, the HRP bytes 33 and 126, and an 83-byte HRP are valid, not faults" {
    const data = [_]u5{ 1, 2, 3, 4 };
    const hrp83: [bech32.max_hrp_len]u8 = @splat('a');
    const hrps = [_][]const u8{ "x1y", "!", "~", "!~", &hrp83 };
    for (hrps) |hrp| {
        // the 83-byte HRP leaves room for the checksum only
        const n: usize = if (hrp.len == bech32.max_hrp_len) 0 else data.len;
        const enc = try bech32.encode(hrp, data[0..n], .bech32);
        const l = bech32.locateErrors(enc.slice(), null);
        try t.expectEqual(bech32.Fault.none, l.fault);
        try t.expectEqual(@as(?bech32.Encoding, .bech32), l.encoding);
    }
}

test "mutation 2026-11-25: locateErrors: an HRP byte outside [33,126] is reported even when the checksum is wrong too" {
    const l = bech32.locateErrors("x\x7fy1pzry9x0s0mux", null);
    try t.expectEqual(bech32.Fault.invalid_character, l.fault);
    try t.expectEqualSlices(u8, &.{1}, l.positions());
    // ... and ahead of the separator check: five data characters would otherwise be a bad separator.
    const short = bech32.locateErrors("x\x7fy1pzry", null);
    try t.expectEqual(bech32.Fault.invalid_character, short.fault);
    try t.expectEqualSlices(u8, &.{1}, short.positions());
}

test "mutation 2026-11-25: locateErrors: `expected` restricts the repair to one checksum constant" {
    // A bech32m string with one wrong character: repairable as bech32m, not as bech32.
    const s = "bc1r23alxd5mzfsh79vn6pgufs6c0";
    const m = bech32.locateErrors(s, .bech32m);
    try t.expectEqual(bech32.Fault.bad_checksum, m.fault);
    try t.expectEqual(@as(?bech32.Encoding, .bech32m), m.encoding);
    const b = bech32.locateErrors(s, .bech32);
    try t.expectEqual(bech32.Fault.bad_checksum_unlocated, b.fault);
}

/// The repaired copy of `s` by `l`, decoded: the encoding it checksums as.
fn repairedEncoding(s: []const u8, l: bech32.Located) !bech32.Encoding {
    var fixed: [bech32.max_len]u8 = undefined;
    @memcpy(fixed[0..s.len], s);
    for (l.positions(), l.fixes()) |p, f| fixed[p] = f;
    return (try bech32.decode(fixed[0..s.len])).encoding;
}

test "mutation 2026-11-25: locateErrors with expected = null: the repair with fewer errors wins, bech32 on a tie, positions ascending" {
    // Three strings built (see the comments) so that the residue is explained under BOTH constants.
    // Tie: bech32 with two errors (data indexes 0 and 1) is also a bech32m string with two other errors.
    const tie = "bc1vl3clxd5mzfsh79vn6uzma6q";
    const lt = bech32.locateErrors(tie, null);
    try t.expectEqual(bech32.Fault.bad_checksum, lt.fault);
    try t.expectEqual(@as(?bech32.Encoding, .bech32), lt.encoding);
    try t.expectEqualSlices(u8, &.{ 3, 4 }, lt.positions());
    try t.expectEqual(bech32.Encoding.bech32, try repairedEncoding(tie, lt));
    // One error as bech32 (data index 1), two as bech32m: the single repair wins.
    const s1 = "bc1rt3clxd5mzfsh79vn6pg0kaytjeq8w4ur23clxd5mzfsh79vn6pg0kaytjeq8w4ur23clxd5mzfsh7sgr994";
    const l1 = bech32.locateErrors(s1, null);
    try t.expectEqual(bech32.Fault.bad_checksum, l1.fault);
    try t.expectEqual(@as(?bech32.Encoding, .bech32), l1.encoding);
    try t.expectEqualSlices(u8, &.{4}, l1.positions());
    try t.expectEqual(bech32.Encoding.bech32, try repairedEncoding(s1, l1));
    // The mirror image: one error as bech32m, two as bech32.
    const s2 = "bc1rt3clxd5mzfsh79vn6pg0kaytjeq8w4ur23clxd5mzfsh79vn6pg0kaytjeq8w4ur23clxd5mzfsh795nfqh";
    const l2 = bech32.locateErrors(s2, null);
    try t.expectEqual(bech32.Fault.bad_checksum, l2.fault);
    try t.expectEqual(@as(?bech32.Encoding, .bech32m), l2.encoding);
    try t.expectEqualSlices(u8, &.{4}, l2.positions());
    try t.expectEqual(bech32.Encoding.bech32m, try repairedEncoding(s2, l2));
}
