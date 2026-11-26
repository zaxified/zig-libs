// SPDX-License-Identifier: MIT

//! Killing tests from the 2026-11-25 whole-module mutation run.

const std = @import("std");
const testing = std.testing;
const ecvrf = @import("ecvrf.zig");
const p256vrf = @import("p256vrf.zig");

test "mutation 2026-11-25: stringToPoint refuses a set sign bit on x = 0 (y = 1 and y = -1)" {
    // RFC 8032 §5.1.3: x = 0 with the sign bit set has no valid decoding.
    var identity: [32]u8 = @splat(0);
    identity[0] = 1;
    try testing.expectEqual(identity, (try ecvrf.stringToPoint(identity)).toBytes());
    identity[31] = 0x80;
    try testing.expectError(error.InvalidEncoding, ecvrf.stringToPoint(identity));
    // y = p - 1 = 2^255 - 20 also has x = 0.
    var minus_one: [32]u8 = @splat(0xff);
    minus_one[0] = 0xec;
    minus_one[31] = 0x7f;
    _ = try ecvrf.stringToPoint(minus_one);
    minus_one[31] = 0xff;
    try testing.expectError(error.InvalidEncoding, ecvrf.stringToPoint(minus_one));
}

test "mutation 2026-11-25: P-256 proofToHash refuses a proof whose Gamma is not a curve point" {
    const S = p256vrf.tai;
    var sk: [32]u8 = @splat(0x24);
    sk[0] = 0x11;
    var kp: S.KeyPair = undefined;
    try S.KeyPair.init(&kp, &sk);
    var pi = kp.prove("alpha");
    _ = try S.proofToHash(&pi);
    pi[0] = 0x05; // not a SEC1 prefix
    try testing.expectError(error.InvalidProof, S.proofToHash(&pi));
    pi[0] = 0x02;
    pi[1..33].* = @splat(0xff); // x >= p
    try testing.expectError(error.InvalidProof, S.proofToHash(&pi));
}
