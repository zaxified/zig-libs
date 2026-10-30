// SPDX-License-Identifier: MIT

//! No-panic sweep tests (wave GT, gt-a).

const std = @import("std");
const testing = std.testing;
const root = @import("root.zig");

const E = root.EcdsaP521Sha512;
const N = 66;

test "toDer is total for any raw r||s and round-trips through fromDer (sweep P5-1)" {
    var prng = std.Random.DefaultPrng.init(0x5eed_66);
    const rnd = prng.random();
    var raw: [2 * N]u8 = undefined;
    var buf: [E.Signature.der_encoded_length_max]u8 = undefined;
    // All-0xff is the longest encoding (each INTEGER = sign byte + N bytes).
    @memset(&raw, 0xff);
    var cases: usize = 0;
    var pass: usize = 0;
    while (pass < 3000) : (pass += 1) {
        switch (pass) {
            0 => {},
            1 => @memset(&raw, 0),
            2 => {
                @memset(&raw, 0);
                raw[0] = 0x80;
                raw[N] = 0x80;
            },
            else => {
                rnd.bytes(&raw);
                // Vary the leading zero run and the top bit of each half.
                const za = rnd.uintLessThan(usize, N + 1);
                const zb = rnd.uintLessThan(usize, N + 1);
                @memset(raw[0..za], 0);
                @memset(raw[N..][0..zb], 0);
            },
        }
        const sig = E.Signature.fromBytes(raw);
        const der = sig.toDer(&buf);
        try testing.expect(der.len <= buf.len);
        const back = try E.Signature.fromDer(der);
        try testing.expectEqualSlices(u8, &raw, &back.toBytes());
        cases += 1;
    }
    try testing.expectEqual(@as(usize, 3000), cases);
}

test "fromDer: every truncation and single-byte substitution is an error or a canonical round trip (sweep P5-2)" {
    var raw: [2 * N]u8 = undefined;
    for (&raw, 0..) |*b, i| b.* = @truncate(0x81 +% i);
    var buf: [E.Signature.der_encoded_length_max]u8 = undefined;
    const der = E.Signature.fromBytes(raw).toDer(&buf);
    var tmp: [E.Signature.der_encoded_length_max + 4]u8 = undefined;
    for (0..der.len) |l| {
        if (E.Signature.fromDer(der[0..l])) |_| return error.TestUnexpectedResult else |_| {}
    }
    for (0..der.len) |i| {
        for (0..256) |v| {
            @memcpy(tmp[0..der.len], der);
            tmp[i] = @intCast(v);
            if (E.Signature.fromDer(tmp[0..der.len])) |s| {
                var b2: [E.Signature.der_encoded_length_max]u8 = undefined;
                try testing.expectEqualSlices(u8, tmp[0..der.len], s.toDer(&b2));
            } else |_| {}
        }
    }
    // Trailing bytes.
    @memcpy(tmp[0..der.len], der);
    tmp[der.len] = 0;
    try testing.expectError(error.InvalidEncoding, E.Signature.fromDer(tmp[0 .. der.len + 1]));
}

test "SEC1 decode and ECDH refuse every wrong length, prefix and secret range without panicking (sweep P5-3)" {
    const G = root.P521.basePoint;
    const good = G.toUncompressedSec1();
    var pt: [good.len + 8]u8 = undefined;
    var secret: [N]u8 = @splat(0);
    secret[N - 1] = 1;
    for (0..pt.len + 1) |len| {
        for ([_]u8{ 0, 2, 3, 4, 5, 0xff }) |tag| {
            for ([_]u8{ 0x00, 0xff, 0x5a }) |fill| {
                @memset(&pt, fill);
                pt[0] = tag;
                const s = pt[0..len];
                if (root.P521.fromSec1(s)) |p| {
                    // Accepted: only the exact lengths, and a real point.
                    try testing.expect(len == 1 or len == 1 + N or len == 1 + 2 * N);
                    _ = p.affineCoordinates();
                } else |_| {}
                if (E.PublicKey.fromSec1(s)) |_| {} else |_| {}
                if (root.ecdh(secret, s)) |_| {} else |_| {}
            }
        }
    }
    // Secret out of range or zero: errors, not panics.
    var big: [N]u8 = @splat(0xff);
    try testing.expectError(error.NonCanonical, root.ecdh(big, &good));
    big = @splat(0);
    try testing.expectError(error.IdentityElement, root.ecdh(big, &good));
    // The identity encoding is refused as a peer / public key.
    try testing.expectError(error.IdentityElement, root.ecdh(secret, &.{0}));
    try testing.expectError(error.IdentityElement, E.PublicKey.fromSec1(&.{0}));
}
