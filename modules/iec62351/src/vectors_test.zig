// SPDX-License-Identifier: MIT

//! Known-answer tests for every authentication profile this module offers.
//!
//! IEC 62351-6 publishes no test vectors (the standard is paywalled and
//! vector-free), so each vector below is labelled with where it actually came
//! from. **Nothing self-derived is presented as authoritative.**
//!
//! - **`standard`** — reproduced from a published specification: RFC 4231
//!   (HMAC-SHA-224/256/384/512 test vectors) and the GCM specification's /
//!   NIST SP 800-38D's AES-GCM test cases. These pin the *primitive* and the
//!   *truncation rule*, which is where a MAC profile actually goes wrong.
//! - **`self`** — produced by this module and frozen. These pin the *wire
//!   format and the covered range*: a change to the header layout, the
//!   extension encoding, or the MAC domain moves these bytes. They prove
//!   self-consistency and nothing about interoperability.
//!
//! The bridge between the two is deliberate: the truncated tags the module
//! emits are checked to be exact prefixes of the RFC 4231 answers, so the
//! self-derived frame vectors sit on top of a standard-derived primitive
//! rather than on top of themselves.

const std = @import("std");
const testing = std.testing;
const goose = @import("goose.zig");
const rsa = @import("rsa");
const keys = @import("test_keys.zig");

const EcdsaP256 = std.crypto.sign.ecdsa.EcdsaP256Sha256;

// ── standard-derived: RFC 4231 HMAC-SHA-256 ─────────────────────────────────

/// RFC 4231 §4 test cases, HMAC-SHA-256 column. Verbatim from the RFC.
const rfc4231 = struct {
    const Case = struct {
        name: []const u8,
        key: []const u8,
        data: []const u8,
        hmac_sha256: [32]u8,
    };

    const key1 = [_]u8{0x0b} ** 20;
    const key3 = [_]u8{0xaa} ** 20;
    const key4 = [_]u8{
        0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c,
        0x0d, 0x0e, 0x0f, 0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18,
        0x19,
    };
    const key_long = [_]u8{0xaa} ** 131;
    const data3 = [_]u8{0xdd} ** 50;
    const data4 = [_]u8{0xcd} ** 50;

    const cases = [_]Case{
        .{
            .name = "RFC 4231 test case 1",
            .key = &key1,
            .data = "Hi There",
            .hmac_sha256 = .{
                0xb0, 0x34, 0x4c, 0x61, 0xd8, 0xdb, 0x38, 0x53, 0x5c, 0xa8, 0xaf, 0xce,
                0xaf, 0x0b, 0xf1, 0x2b, 0x88, 0x1d, 0xc2, 0x00, 0xc9, 0x83, 0x3d, 0xa7,
                0x26, 0xe9, 0x37, 0x6c, 0x2e, 0x32, 0xcf, 0xf7,
            },
        },
        .{
            .name = "RFC 4231 test case 2",
            .key = "Jefe",
            .data = "what do ya want for nothing?",
            .hmac_sha256 = .{
                0x5b, 0xdc, 0xc1, 0x46, 0xbf, 0x60, 0x75, 0x4e, 0x6a, 0x04, 0x24, 0x26,
                0x08, 0x95, 0x75, 0xc7, 0x5a, 0x00, 0x3f, 0x08, 0x9d, 0x27, 0x39, 0x83,
                0x9d, 0xec, 0x58, 0xb9, 0x64, 0xec, 0x38, 0x43,
            },
        },
        .{
            .name = "RFC 4231 test case 3",
            .key = &key3,
            .data = &data3,
            .hmac_sha256 = .{
                0x77, 0x3e, 0xa9, 0x1e, 0x36, 0x80, 0x0e, 0x46, 0x85, 0x4d, 0xb8, 0xeb,
                0xd0, 0x91, 0x81, 0xa7, 0x29, 0x59, 0x09, 0x8b, 0x3e, 0xf8, 0xc1, 0x22,
                0xd9, 0x63, 0x55, 0x14, 0xce, 0xd5, 0x65, 0xfe,
            },
        },
        .{
            .name = "RFC 4231 test case 4",
            .key = &key4,
            .data = &data4,
            .hmac_sha256 = .{
                0x82, 0x55, 0x8a, 0x38, 0x9a, 0x44, 0x3c, 0x0e, 0xa4, 0xcc, 0x81, 0x98,
                0x99, 0xf2, 0x08, 0x3a, 0x85, 0xf0, 0xfa, 0xa3, 0xe5, 0x78, 0xf8, 0x07,
                0x7a, 0x2e, 0x3f, 0xf4, 0x67, 0x29, 0x66, 0x5b,
            },
        },
        .{
            .name = "RFC 4231 test case 6 (key longer than the block size)",
            .key = &key_long,
            .data = "Test Using Larger Than Block-Size Key - Hash Key First",
            .hmac_sha256 = .{
                0x60, 0xe4, 0x31, 0x59, 0x1e, 0xe0, 0xb6, 0x7f, 0x0d, 0x8a, 0x26, 0xaa,
                0xcb, 0xf5, 0xb7, 0x7f, 0x8e, 0x0b, 0xc6, 0x21, 0x37, 0x28, 0xc5, 0x14,
                0x05, 0x46, 0x04, 0x0f, 0x0e, 0xe3, 0x7f, 0x54,
            },
        },
        .{
            .name = "RFC 4231 test case 7 (long key and long data)",
            .key = &key_long,
            .data = "This is a test using a larger than block-size key and a larger " ++
                "than block-size data. The key needs to be hashed before being used" ++
                " by the HMAC algorithm.",
            .hmac_sha256 = .{
                0x9b, 0x09, 0xff, 0xa7, 0x1b, 0x94, 0x2f, 0xcb, 0x27, 0x63, 0x5f, 0xbc,
                0xd5, 0xb0, 0xe9, 0x44, 0xbf, 0xdc, 0x63, 0x64, 0x4f, 0x07, 0x13, 0x93,
                0x8a, 0x7f, 0x51, 0x53, 0x5c, 0x3a, 0x35, 0xe2,
            },
        },
    };
};

test "standard: RFC 4231 HMAC-SHA-256 vectors reproduce byte-exactly" {
    for (rfc4231.cases) |c| {
        var mac: [32]u8 = undefined;
        std.crypto.auth.hmac.sha2.HmacSha256.create(&mac, c.data, c.key);
        testing.expectEqualSlices(u8, &c.hmac_sha256, &mac) catch |err| {
            std.debug.print("failing case: {s}\n", .{c.name});
            return err;
        };
    }
}

test "standard: the 62351-6 truncations are exact prefixes of the RFC 4231 answers" {
    // RFC 2104 §5 / NIST SP 800-107: a truncated HMAC is the *leftmost* t bits
    // of the full output. Getting the truncation from the wrong end is a
    // silent interoperability failure that still looks like a MAC, so it is
    // pinned here against published bytes rather than against ourselves.
    const profiles = [_]struct { alg: goose.MacAlgorithm, len: usize }{
        .{ .alg = .hmac_sha256_80, .len = 10 },
        .{ .alg = .hmac_sha256_128, .len = 16 },
        .{ .alg = .hmac_sha256_256, .len = 32 },
    };
    for (rfc4231.cases) |c| {
        for (profiles) |p| {
            var out: [goose.max_mac_len]u8 = undefined;
            const tag = try goose.computeMac(p.alg, c.key, c.data, null, &out);
            try testing.expectEqual(p.len, tag.len);
            try testing.expectEqualSlices(u8, c.hmac_sha256[0..p.len], tag);
            try testing.expect(goose.verifyMac(p.alg, c.key, c.data, null, tag));
            // ...and the *rightmost* t bits must NOT be what we emit.
            try testing.expect(!goose.verifyMac(
                p.alg,
                c.key,
                c.data,
                null,
                c.hmac_sha256[32 - p.len ..],
            ) or p.len == 32);
        }
    }
}

// ── standard-derived: AES-GCM / GMAC ────────────────────────────────────────

test "standard: AES-GCM test cases 1 and 13 (the GMAC primitive)" {
    // The GCM specification's test case 1: AES-128, all-zero key and IV, empty
    // plaintext and empty AAD.
    {
        var tag: [16]u8 = undefined;
        std.crypto.aead.aes_gcm.Aes128Gcm.encrypt(&.{}, &tag, &.{}, &.{}, [_]u8{0} ** 12, [_]u8{0} ** 16);
        try testing.expectEqualSlices(u8, &.{
            0x58, 0xe2, 0xfc, 0xce, 0xfa, 0x7e, 0x30, 0x61,
            0x36, 0x7f, 0x1d, 0x57, 0xa4, 0xe7, 0x45, 0x5a,
        }, &tag);
    }
    // Test case 13: the same, with AES-256.
    {
        var tag: [16]u8 = undefined;
        std.crypto.aead.aes_gcm.Aes256Gcm.encrypt(&.{}, &tag, &.{}, &.{}, [_]u8{0} ** 12, [_]u8{0} ** 32);
        try testing.expectEqualSlices(u8, &.{
            0x53, 0x0f, 0x8a, 0xfb, 0xc7, 0x45, 0x36, 0xb9,
            0xa9, 0x63, 0xb4, 0xf1, 0xc4, 0xcb, 0x73, 0x8b,
        }, &tag);
    }
}

test "standard: AES-GMAC-64/128 truncate the GCM tag from the left" {
    const key = [_]u8{0} ** 16;
    const iv = [_]u8{0} ** 12;
    const full = [_]u8{
        0x58, 0xe2, 0xfc, 0xce, 0xfa, 0x7e, 0x30, 0x61,
        0x36, 0x7f, 0x1d, 0x57, 0xa4, 0xe7, 0x45, 0x5a,
    };
    var out: [goose.max_mac_len]u8 = undefined;
    const t64 = try goose.computeMac(.aes_gmac_64, &key, &.{}, iv, &out);
    try testing.expectEqualSlices(u8, full[0..8], t64);
    var out2: [goose.max_mac_len]u8 = undefined;
    const t128 = try goose.computeMac(.aes_gmac_128, &key, &.{}, iv, &out2);
    try testing.expectEqualSlices(u8, full[0..16], t128);
}

test "standard: an AES-GMAC key that is neither 128 nor 256 bits is refused" {
    var out: [goose.max_mac_len]u8 = undefined;
    try testing.expectError(error.KeyLength, goose.computeMac(
        .aes_gmac_128,
        &[_]u8{0} ** 24,
        &.{},
        [_]u8{0} ** 12,
        &out,
    ));
    try testing.expectError(error.IvRequired, goose.computeMac(
        .aes_gmac_128,
        &[_]u8{0} ** 16,
        &.{},
        null,
        &out,
    ));
}

// ── self-derived: the frame-level vectors ───────────────────────────────────

/// The frozen input every self-derived frame vector below is built from.
/// Chosen to be boring and fixed: any change to these values, to the header
/// layout, to the extension encoding or to the covered range changes the
/// expected bytes.
const kat = struct {
    const appid: u16 = 0x3001;
    const key_id: u32 = 0x0000_0007;
    const time_of_current_key: u32 = 0x5f00_0000;
    const time_to_next_key: u16 = 60;
    /// RFC 4231 test case 1's key, reused so the MAC input is the only novel
    /// part of the vector.
    const hmac_key = [_]u8{0x0b} ** 20;
    const gmac_key = [_]u8{0x2a} ** 16;
    const iv = [_]u8{0x11} ** 12;
    /// Stand-in APDU octets — this module never parses an APDU.
    const apdu = [_]u8{
        0x61, 0x1a, 0x80, 0x04, 0x74, 0x65, 0x73, 0x74, 0x81, 0x02, 0x03, 0xe8,
        0x82, 0x02, 0x00, 0x01, 0x83, 0x01, 0x00, 0x84, 0x08, 0x66, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00,
    };

    fn buildFrame(out: []u8, alg: goose.MacAlgorithm) ![]u8 {
        const key: []const u8 = if (alg.needsIv()) &gmac_key else &hmac_key;
        return goose.build(out, .{
            .appid = appid,
            .apdu = &apdu,
            .auth = .{
                .time_of_current_key = time_of_current_key,
                .time_to_next_key = time_to_next_key,
                .key_id = key_id,
                .iv = if (alg.needsIv()) iv else null,
                .tag = &.{},
            },
        }, .{ .mac = .{ .algorithm = alg, .key = key } });
    }
};

/// self-derived — the complete authenticated frame for HMAC-SHA256-128 over
/// `kat`. Pins the header encoding (EtherType, APPID, `Length` including the
/// extension, `Reserved 1` presence flag, `Reserved 2` extension length), the
/// extension encoding, and the covered range all at once.
const kat_frame_hmac128 = [_]u8{
    0x88, 0xb8, 0x30, 0x01, 0x00, 0x44, 0x80, 0x00, 0x00, 0x1f, 0x61, 0x1a,
    0x80, 0x04, 0x74, 0x65, 0x73, 0x74, 0x81, 0x02, 0x03, 0xe8, 0x82, 0x02,
    0x00, 0x01, 0x83, 0x01, 0x00, 0x84, 0x08, 0x66, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x30, 0x1d, 0x85, 0x1b, 0x01, 0x5f, 0x00, 0x00, 0x00,
    0x00, 0x3c, 0x00, 0x00, 0x00, 0x07, 0x5a, 0x78, 0xa1, 0x3b, 0xb9, 0x48,
    0xea, 0x4a, 0xa1, 0xa5, 0x3a, 0x57, 0xbd, 0xdf, 0xb8, 0x2d,
};

/// self-derived — the tag alone for each modelled MAC algorithm over the same
/// `kat` frame.
const kat_tags = struct {
    const hmac_sha256_80 = [_]u8{
        0x8e, 0x4b, 0xea, 0x34, 0x25, 0x24, 0x42, 0x32, 0xbd, 0xdb,
    };
    const hmac_sha256_128 = [_]u8{
        0x5a, 0x78, 0xa1, 0x3b, 0xb9, 0x48, 0xea, 0x4a, 0xa1, 0xa5, 0x3a, 0x57,
        0xbd, 0xdf, 0xb8, 0x2d,
    };
    const hmac_sha256_256 = [_]u8{
        0x6f, 0x46, 0x94, 0x7c, 0xcf, 0x3f, 0x1e, 0xcc, 0x90, 0xa3, 0x5c, 0x88,
        0x25, 0x51, 0xcc, 0x69, 0x5c, 0x6e, 0xcf, 0xf5, 0x17, 0x52, 0x36, 0x94,
        0x62, 0x46, 0x4b, 0x63, 0x3f, 0xe3, 0xbd, 0x22,
    };
    const aes_gmac_64 = [_]u8{
        0x17, 0xd8, 0x82, 0x21, 0x9b, 0x02, 0x0d, 0x87,
    };
    const aes_gmac_128 = [_]u8{
        0x38, 0x41, 0xe8, 0x71, 0x66, 0xf8, 0x8f, 0xc0, 0xf3, 0x3c, 0x0d, 0xb3,
        0xbf, 0x9e, 0xca, 0x01,
    };
};

test "self: the frozen HMAC-SHA256-128 frame reproduces byte-exactly" {
    var out: [256]u8 = undefined;
    const frame = try kat.buildFrame(&out, .hmac_sha256_128);
    try testing.expectEqualSlices(u8, &kat_frame_hmac128, frame);
    // ...and the frozen bytes verify.
    const r = try goose.verify(&kat_frame_hmac128, .ed2020, .{
        .mac = .{ .algorithm = .hmac_sha256_128, .key = &kat.hmac_key },
    });
    try testing.expectEqual(kat.key_id, r.auth.key_id);
    try testing.expectEqual(kat.time_of_current_key, r.auth.time_of_current_key);
}

test "self: the frozen tag for each modelled algorithm reproduces byte-exactly" {
    const table = [_]struct { alg: goose.MacAlgorithm, want: []const u8 }{
        .{ .alg = .hmac_sha256_80, .want = &kat_tags.hmac_sha256_80 },
        .{ .alg = .hmac_sha256_128, .want = &kat_tags.hmac_sha256_128 },
        .{ .alg = .hmac_sha256_256, .want = &kat_tags.hmac_sha256_256 },
        .{ .alg = .aes_gmac_64, .want = &kat_tags.aes_gmac_64 },
        .{ .alg = .aes_gmac_128, .want = &kat_tags.aes_gmac_128 },
    };
    var out: [256]u8 = undefined;
    for (table) |row| {
        const frame = try kat.buildFrame(&out, row.alg);
        const parsed = try goose.parse(frame, .ed2020);
        const av = try goose.AuthenticationValue.parse(
            parsed.extension,
            row.alg.needsIv(),
            goose.max_mac_len,
        );
        try testing.expectEqualSlices(u8, row.want, av.tag);
    }
}

test "self: every frozen tag is exactly the MAC of the frame's own covered range" {
    // The bridge from the self-derived vectors back to the standard-derived
    // primitive: recompute the frozen tag straight from `macDomain` with the
    // RFC-4231-validated HMAC, without going through `build`.
    const parsed = try goose.parse(&kat_frame_hmac128, .ed2020);
    var mac: [32]u8 = undefined;
    std.crypto.auth.hmac.sha2.HmacSha256.create(&mac, parsed.macDomain(), &kat.hmac_key);
    try testing.expectEqualSlices(u8, &kat_tags.hmac_sha256_128, mac[0..16]);
}

// ── self-derived: the signature profiles ────────────────────────────────────

/// self-derived — an RSASSA-PSS/SHA-256 signature over the `kat` frame's
/// covered range, produced once with this repository's `rsa` module and the
/// synthetic 2048-bit key in `test_keys.zig`. PSS is randomised, so the value
/// cannot be regenerated; it is frozen as a *verification* vector.
const kat_pss_signature = [_]u8{
    0xb5, 0xd1, 0x5b, 0xb2, 0x67, 0x10, 0xf3, 0xbe, 0xe3, 0x94, 0x17, 0x36,
    0x6b, 0x4a, 0x8c, 0x3b, 0x35, 0x19, 0xd3, 0x7d, 0x14, 0xe2, 0xf6, 0xcf,
    0x10, 0xc7, 0x6c, 0x3a, 0xb7, 0x38, 0x18, 0x16, 0x9b, 0x1b, 0x50, 0x0e,
    0x2c, 0x61, 0x8a, 0xf6, 0x71, 0x6d, 0x0a, 0x6d, 0x2b, 0x4f, 0xd7, 0x68,
    0x48, 0x2d, 0x83, 0xa1, 0x60, 0xac, 0xaa, 0xb6, 0x28, 0x70, 0x30, 0x00,
    0x0a, 0xc0, 0x03, 0x90, 0x21, 0xb7, 0x71, 0xe3, 0x51, 0x7e, 0x0a, 0xd8,
    0x2e, 0x20, 0xab, 0xad, 0xca, 0xc6, 0x93, 0x97, 0x1b, 0x0a, 0xf9, 0xc8,
    0xed, 0x70, 0x1d, 0x45, 0x09, 0x4d, 0x08, 0xd7, 0xbc, 0x36, 0x39, 0x3a,
    0xfe, 0x2a, 0xc1, 0x61, 0xb7, 0xe6, 0x7e, 0xd3, 0x54, 0xbc, 0xfd, 0xc0,
    0x28, 0x1e, 0x22, 0x3e, 0xb6, 0xe5, 0xdc, 0xe8, 0xe1, 0x2e, 0x8a, 0x2b,
    0xc4, 0xbb, 0x75, 0x81, 0xc9, 0x41, 0x74, 0xd6, 0x63, 0x32, 0x73, 0x3e,
    0xdf, 0x8c, 0x6b, 0xff, 0x05, 0xc7, 0x13, 0x14, 0x33, 0x90, 0x40, 0x66,
    0x85, 0xf7, 0xaa, 0x4e, 0x71, 0x1f, 0x62, 0xb9, 0x18, 0xff, 0x7e, 0x56,
    0x7e, 0xfa, 0x7a, 0x1a, 0x19, 0xca, 0x3b, 0x3b, 0x0a, 0xc4, 0xc2, 0x56,
    0x8c, 0xf5, 0x93, 0x7a, 0xc6, 0x75, 0x2b, 0x10, 0x5d, 0xb9, 0x3f, 0xc4,
    0xaa, 0xa3, 0x12, 0x43, 0xb2, 0xfc, 0x06, 0x93, 0xa9, 0xc8, 0x34, 0xe4,
    0x0f, 0x25, 0x3a, 0x8c, 0x21, 0x75, 0xc4, 0x38, 0xec, 0xcb, 0x7a, 0xe6,
    0x8a, 0x79, 0x84, 0xbe, 0xd5, 0x85, 0xbd, 0xe2, 0x30, 0xa1, 0x04, 0x39,
    0x2b, 0x8e, 0x11, 0x3d, 0x6c, 0x7d, 0xca, 0x3e, 0x1a, 0x57, 0x34, 0xb5,
    0x34, 0xe9, 0x7e, 0x0a, 0xb3, 0x8d, 0xb1, 0xa6, 0x42, 0x4f, 0x27, 0x92,
    0x96, 0x35, 0x89, 0x00, 0x31, 0xb2, 0x39, 0x1d, 0x93, 0x96, 0xaf, 0x9a,
    0x61, 0x5e, 0xa8, 0x11,
};

test "self: a frozen RSASSA-PSS signature over the covered range verifies" {
    const pk = try keys.rsa2048PublicKey();
    const parsed = try goose.parse(&kat_frame_hmac128, .ed2020);
    const Sha256 = std.crypto.hash.sha2.Sha256;
    try rsa.verifyPss(pk, Sha256, parsed.macDomain(), &kat_pss_signature, Sha256.digest_length);

    // A one-bit change anywhere in the covered range breaks it.
    var tampered: [kat_frame_hmac128.len]u8 = kat_frame_hmac128;
    tampered[goose.apdu_offset] ^= 0x01;
    const tampered_parsed = try goose.parse(&tampered, .ed2020);
    try testing.expectError(error.SignatureVerificationFailed, rsa.verifyPss(
        pk,
        Sha256,
        tampered_parsed.macDomain(),
        &kat_pss_signature,
        Sha256.digest_length,
    ));
}

/// self-derived — ECDSA P-256/SHA-256 over the `kat` frame's covered range
/// with a fixed key seed and fixed signing noise, so the value *is*
/// reproducible (unlike PSS above).
const kat_ecdsa_seed = [_]u8{0x17} ** EcdsaP256.KeyPair.seed_length;
const kat_ecdsa_noise = [_]u8{0x5c} ** EcdsaP256.noise_length;
const kat_ecdsa_signature = [_]u8{
    0x7e, 0x87, 0xa8, 0xa2, 0xec, 0x51, 0x3e, 0x7f, 0x1b, 0xce, 0xf0, 0xd2,
    0xdf, 0x7e, 0x12, 0x23, 0x48, 0xdc, 0x0e, 0x55, 0x67, 0xba, 0x0a, 0xec,
    0x64, 0x98, 0x1e, 0x91, 0x57, 0x24, 0x5e, 0xd8, 0x92, 0xd0, 0xe0, 0xfb,
    0x3f, 0xf3, 0x0b, 0xf6, 0x3c, 0x85, 0x70, 0x27, 0x16, 0xcd, 0x2b, 0x75,
    0x25, 0x7b, 0x7c, 0x08, 0x2e, 0x37, 0x68, 0x19, 0x37, 0x34, 0x0c, 0x8b,
    0xf9, 0x75, 0x93, 0x10,
};

test "self: the frozen ECDSA P-256 signature reproduces and verifies" {
    const kp = try EcdsaP256.KeyPair.generateDeterministic(kat_ecdsa_seed);
    const parsed = try goose.parse(&kat_frame_hmac128, .ed2020);
    const sig = try kp.sign(parsed.macDomain(), kat_ecdsa_noise);
    try testing.expectEqualSlices(u8, &kat_ecdsa_signature, &sig.toBytes());
    try sig.verify(parsed.macDomain(), kp.public_key);
}
