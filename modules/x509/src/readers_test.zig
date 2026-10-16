// SPDX-License-Identifier: MIT
//! The single-field readers (`chain.certValidity`, `chain.certAuthorityKeyId`,
//! `names.nameAttribute`) against what `openssl x509 -noout -issuer -startdate
//! -enddate -ext authorityKeyIdentifier` (OpenSSL 3.5.5) prints for the
//! `data/p521/` fixtures, plus every truncation and single-byte change of
//! the input erroring or answering without an out-of-bounds read.

const std = @import("std");
const testing = std.testing;
const chain = @import("chain.zig");
const names = @import("names.zig");

const leaf256 = @embedFile("data/p521/leaf256.der");
const interB521 = @embedFile("data/p521/interB521.der");

test "certValidity, certAuthorityKeyId, nameAttribute agree with openssl" {
    const v = try chain.certValidity(leaf256);
    try testing.expectEqual(@as(u64, 1735689600), v.not_before); // Jan  1 00:00:00 2025 GMT
    try testing.expectEqual(@as(u64, 1893456000), v.not_after); // Jan  1 00:00:00 2030 GMT

    const aki = (try chain.certAuthorityKeyId(leaf256)).?;
    try testing.expectEqualSlices(u8, &.{
        0x34, 0x03, 0x33, 0x2F, 0x6C, 0x64, 0x56, 0xE8, 0x4E, 0x31,
        0x44, 0x11, 0xAD, 0xCB, 0xF7, 0xBB, 0x8B, 0x3F, 0x43, 0x6D,
    }, aki);

    // issuer=O=zig-libs p521 test, CN=p521 inter / CN=p384 root
    const issuer = (try chain.certSerialAndIssuer(leaf256)).issuer;
    try testing.expectEqualStrings("p521 inter", (try names.nameAttribute(issuer, &names.oid_common_name)).?);
    try testing.expectEqualStrings("zig-libs p521 test", (try names.nameAttribute(issuer, &.{ 0x55, 0x04, 0x0a })).?);
    try testing.expectEqual(@as(?[]const u8, null), try names.nameAttribute(issuer, &.{ 0x55, 0x04, 0x06 })); // no C
    const issuer_b = (try chain.certSerialAndIssuer(interB521)).issuer;
    try testing.expectEqualStrings("p384 root", (try names.nameAttribute(issuer_b, &names.oid_common_name)).?);
    try testing.expectEqual(@as(?[]const u8, null), try names.nameAttribute("", &names.oid_common_name));
}

test "readers on every truncation and single-byte change: error or answer, never out of bounds" {
    var buf: [leaf256.len]u8 = undefined;
    for (0..leaf256.len) |n| {
        // A fresh heap copy per prefix, so a read past `n` is a fault, not a
        // read of the fixture's tail.
        const prefix = try testing.allocator.dupe(u8, leaf256[0..n]);
        defer testing.allocator.free(prefix);
        _ = chain.certValidity(prefix) catch {};
        _ = chain.certAuthorityKeyId(prefix) catch {};
    }
    const issuer = (try chain.certSerialAndIssuer(leaf256)).issuer;
    for (0..issuer.len) |n| {
        const prefix = try testing.allocator.dupe(u8, issuer[0..n]);
        defer testing.allocator.free(prefix);
        _ = names.nameAttribute(prefix, &names.oid_common_name) catch {};
    }
    for (0..leaf256.len) |i| {
        for ([_]u8{ 0x00, 0x80, 0xff }) |x| {
            @memcpy(&buf, leaf256);
            buf[i] ^= x | 1;
            _ = chain.certValidity(&buf) catch {};
            _ = chain.certAuthorityKeyId(&buf) catch {};
            const parts = chain.certSerialAndIssuer(&buf) catch continue;
            _ = names.nameAttribute(parts.issuer, &names.oid_common_name) catch {};
        }
    }
}
