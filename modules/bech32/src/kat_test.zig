// SPDX-License-Identifier: MIT
//! Drives `kat_vectors.zig` (the official BIP173/BIP350 test vectors)
//! through the actual `bech32.zig`/`segwit.zig` implementation.

const std = @import("std");
const testing = std.testing;
const bech32 = @import("bech32.zig");
const segwit = @import("segwit.zig");
const kat_vectors = @import("kat_vectors.zig");

fn lowerInto(s: []const u8, out: []u8) []const u8 {
    for (s, 0..) |c, i| out[i] = if (c >= 'A' and c <= 'Z') c + 32 else c;
    return out[0..s.len];
}

test "BIP173: official valid bech32 vectors decode, and re-encode byte-exact (lowercased)" {
    var lowered_buf: [bech32.max_len]u8 = undefined;
    for (kat_vectors.valid_bech32) |v| {
        const dec = bech32.decode(v) catch |err| {
            std.debug.print("unexpected decode failure for valid vector {s}: {}\n", .{ v, err });
            return err;
        };
        try testing.expectEqual(bech32.Encoding.bech32, dec.encoding);

        const enc = try bech32.encode(dec.hrp(), dec.data(), dec.encoding);
        try testing.expectEqualStrings(lowerInto(v, &lowered_buf), enc.slice());
    }
}

test "BIP350: official valid bech32m vectors decode, and re-encode byte-exact (lowercased)" {
    var lowered_buf: [bech32.max_len]u8 = undefined;
    for (kat_vectors.valid_bech32m) |v| {
        const dec = bech32.decode(v) catch |err| {
            std.debug.print("unexpected decode failure for valid vector {s}: {}\n", .{ v, err });
            return err;
        };
        try testing.expectEqual(bech32.Encoding.bech32m, dec.encoding);

        const enc = try bech32.encode(dec.hrp(), dec.data(), dec.encoding);
        try testing.expectEqualStrings(lowerInto(v, &lowered_buf), enc.slice());
    }
}

test "BIP173: official invalid bech32 vectors each rejected with the documented typed error" {
    for (kat_vectors.invalid_bech32) |v| {
        _ = bech32.decode(v.s) catch |err| {
            if (err != v.err) {
                std.debug.print("vector {s}: expected {} got {}\n", .{ v.s, v.err, err });
                return error.WrongErrorForVector;
            }
            continue;
        };
        std.debug.print("vector {s}: expected {} but decode succeeded\n", .{ v.s, v.err });
        return error.VectorUnexpectedlyDecoded;
    }
}

test "BIP350: official invalid bech32m vectors each rejected with the documented typed error" {
    for (kat_vectors.invalid_bech32m) |v| {
        _ = bech32.decode(v.s) catch |err| {
            if (err != v.err) {
                std.debug.print("vector {s}: expected {} got {}\n", .{ v.s, v.err, err });
                return error.WrongErrorForVector;
            }
            continue;
        };
        std.debug.print("vector {s}: expected {} but decode succeeded\n", .{ v.s, v.err });
        return error.VectorUnexpectedlyDecoded;
    }
}

test "BIP350: official valid segwit vectors decode to the exact witver+program, and re-encode byte-exact" {
    var lowered_buf: [bech32.max_len]u8 = undefined;
    var program_buf: [segwit.max_program_len]u8 = undefined;
    for (kat_vectors.valid_segwit) |v| {
        const dec = segwit.decodeSegwit(v.hrp, v.address) catch |err| {
            std.debug.print("unexpected decodeSegwit failure for {s}: {}\n", .{ v.address, err });
            return err;
        };
        try testing.expectEqual(v.witver, dec.witver);

        const expected_program_len = v.program_hex.len / 2;
        const expected_program = program_buf[0..expected_program_len];
        _ = std.fmt.hexToBytes(expected_program, v.program_hex) catch unreachable;
        try testing.expectEqualSlices(u8, expected_program, dec.program());

        const enc = try segwit.encodeSegwit(v.hrp, v.witver, dec.program());
        try testing.expectEqualStrings(lowerInto(v.address, &lowered_buf), enc.slice());
    }
}

test "BIP350: official invalid segwit vectors each rejected with the documented typed error" {
    for (kat_vectors.invalid_segwit) |v| {
        _ = segwit.decodeSegwit(v.hrp, v.address) catch |err| {
            if (err != v.err) {
                std.debug.print("vector {s}: expected {} got {}\n", .{ v.address, v.err, err });
                return error.WrongErrorForVector;
            }
            continue;
        };
        std.debug.print("vector {s}: expected {} but decodeSegwit succeeded\n", .{ v.address, v.err });
        return error.VectorUnexpectedlyDecoded;
    }
}

test "vector counts match the official BIP173/BIP350 appendices" {
    try testing.expectEqual(@as(usize, 7), kat_vectors.valid_bech32.len);
    try testing.expectEqual(@as(usize, 12), kat_vectors.invalid_bech32.len);
    try testing.expectEqual(@as(usize, 7), kat_vectors.valid_bech32m.len);
    try testing.expectEqual(@as(usize, 14), kat_vectors.invalid_bech32m.len);
    try testing.expectEqual(@as(usize, 8), kat_vectors.valid_segwit.len);
    try testing.expectEqual(@as(usize, 15), kat_vectors.invalid_segwit.len);
}
