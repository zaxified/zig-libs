// SPDX-License-Identifier: MIT
//! kat_test — Falcon-512 against the official NIST Round-3 known-answer
//! vectors (see kat_vectors.zig for provenance): verification accepts every
//! vector, canonical re-encoding is byte-exact, the secret key reproduces
//! the public key, and tampered inputs are rejected.

const std = @import("std");
const falcon = @import("root.zig");
const codec = @import("codec.zig");
const poly = @import("poly.zig");
const v = @import("kat_vectors.zig");

fn hexAlloc(gpa: std.mem.Allocator, hex_str: []const u8) ![]u8 {
    const out = try gpa.alloc(u8, hex_str.len / 2);
    _ = std.fmt.hexToBytes(out, hex_str) catch unreachable;
    return out;
}

const Decoded = struct {
    msg: []u8,
    pk_bytes: []u8,
    sk_bytes: []u8,
    sm: []u8,

    fn init(gpa: std.mem.Allocator, vec: v.Vector) !Decoded {
        return .{
            .msg = try hexAlloc(gpa, vec.msg),
            .pk_bytes = try hexAlloc(gpa, vec.pk),
            .sk_bytes = try hexAlloc(gpa, vec.sk),
            .sm = try hexAlloc(gpa, vec.sm),
        };
    }

    fn deinit(d: *const Decoded, gpa: std.mem.Allocator) void {
        gpa.free(d.msg);
        gpa.free(d.pk_bytes);
        gpa.free(d.sk_bytes);
        gpa.free(d.sm);
    }
};

test "NIST Round-3 KAT: every vector's signed message verifies and opens" {
    const gpa = std.testing.allocator;
    for (v.falcon512) |vec| {
        const d = try Decoded.init(gpa, vec);
        defer d.deinit(gpa);

        try std.testing.expectEqual(@as(usize, 897), d.pk_bytes.len);
        try std.testing.expectEqual(@as(usize, 1281), d.sk_bytes.len);
        const pk = try falcon.PublicKey.fromBytes(d.pk_bytes[0..897]);

        const opened = try falcon.openNistSignedMessage(&pk, d.sm);
        try std.testing.expectEqualSlices(u8, d.msg, opened);
    }
}

test "NIST Round-3 KAT: compressed signature re-encodes byte-exactly" {
    const gpa = std.testing.allocator;
    for (v.falcon512) |vec| {
        const d = try Decoded.init(gpa, vec);
        defer d.deinit(gpa);

        const sig_len = (@as(usize, d.sm[0]) << 8) | d.sm[1];
        const sig_field = d.sm[d.sm.len - sig_len ..];
        try std.testing.expectEqual(falcon.sig_header, sig_field[0]);
        var s2: [poly.n]i16 = undefined;
        try codec.compDecode(&s2, sig_field[1..]);

        var buf: [falcon.max_sig_field_length]u8 = undefined;
        const enc_len = try codec.compEncode(&buf, &s2);
        try std.testing.expectEqualSlices(u8, sig_field[1..], buf[0..enc_len]);
    }
}

test "NIST Round-3 KAT: secret key decodes and reproduces the public key" {
    const gpa = std.testing.allocator;
    for (v.falcon512) |vec| {
        const d = try Decoded.init(gpa, vec);
        defer d.deinit(gpa);

        const sk = try falcon.SecretKey.fromBytes(d.sk_bytes[0..1281]);
        const pk_from_sk = try sk.publicKey();
        const pk = try falcon.PublicKey.fromBytes(d.pk_bytes[0..897]);
        try std.testing.expectEqualSlices(u16, &pk.h, &pk_from_sk.h);
    }
}

test "NIST Round-3 KAT: public key re-encodes byte-exactly" {
    const gpa = std.testing.allocator;
    for (v.falcon512) |vec| {
        const d = try Decoded.init(gpa, vec);
        defer d.deinit(gpa);
        const pk = try falcon.PublicKey.fromBytes(d.pk_bytes[0..897]);
        try std.testing.expectEqualSlices(u8, d.pk_bytes, &pk.toBytes());
    }
}

test "tampered message is rejected" {
    const gpa = std.testing.allocator;
    const d = try Decoded.init(gpa, v.falcon512[0]);
    defer d.deinit(gpa);
    const pk = try falcon.PublicKey.fromBytes(d.pk_bytes[0..897]);

    // Flip one bit of the embedded message.
    d.sm[2 + falcon.nonce_length] ^= 0x01;
    try std.testing.expectError(
        error.SignatureVerificationFailed,
        falcon.openNistSignedMessage(&pk, d.sm),
    );
}

test "tampered nonce is rejected" {
    const gpa = std.testing.allocator;
    const d = try Decoded.init(gpa, v.falcon512[0]);
    defer d.deinit(gpa);
    const pk = try falcon.PublicKey.fromBytes(d.pk_bytes[0..897]);
    d.sm[2] ^= 0x80;
    try std.testing.expectError(
        error.SignatureVerificationFailed,
        falcon.openNistSignedMessage(&pk, d.sm),
    );
}

test "tampered, truncated, or malformed signature field is rejected" {
    const gpa = std.testing.allocator;
    const d = try Decoded.init(gpa, v.falcon512[0]);
    defer d.deinit(gpa);
    const pk = try falcon.PublicKey.fromBytes(d.pk_bytes[0..897]);
    const sig_len = (@as(usize, d.sm[0]) << 8) | d.sm[1];

    // Corrupt a byte in the middle of the compressed signature: either the
    // decoding becomes non-canonical (InvalidSignature) or the recovered
    // vector fails the norm check — both must reject.
    {
        const sm2 = try gpa.dupe(u8, d.sm);
        defer gpa.free(sm2);
        sm2[sm2.len - sig_len / 2] ^= 0x40;
        const r = falcon.openNistSignedMessage(&pk, sm2);
        try std.testing.expect(r == error.InvalidSignature or
            r == error.SignatureVerificationFailed);
    }

    // Wrong header byte.
    {
        const sm2 = try gpa.dupe(u8, d.sm);
        defer gpa.free(sm2);
        sm2[sm2.len - sig_len] = 0x2a; // logn=10 header on a 512 signature
        try std.testing.expectError(
            error.InvalidSignature,
            falcon.openNistSignedMessage(&pk, sm2),
        );
    }

    // Truncated envelope (drop the last signature byte, keep length field).
    {
        const sm2 = try gpa.dupe(u8, d.sm[0 .. d.sm.len - 1]);
        defer gpa.free(sm2);
        try std.testing.expectError(
            error.InvalidSignature,
            falcon.openNistSignedMessage(&pk, sm2),
        );
    }

    // Nonsense length field.
    {
        const sm2 = try gpa.dupe(u8, d.sm);
        defer gpa.free(sm2);
        sm2[0] = 0xff;
        sm2[1] = 0xff;
        try std.testing.expectError(
            error.InvalidSignature,
            falcon.openNistSignedMessage(&pk, sm2),
        );
    }
}

test "signature does not verify under a different vector's public key" {
    const gpa = std.testing.allocator;
    const d0 = try Decoded.init(gpa, v.falcon512[0]);
    defer d0.deinit(gpa);
    const d1 = try Decoded.init(gpa, v.falcon512[1]);
    defer d1.deinit(gpa);
    const wrong_pk = try falcon.PublicKey.fromBytes(d1.pk_bytes[0..897]);
    try std.testing.expectError(
        error.SignatureVerificationFailed,
        falcon.openNistSignedMessage(&wrong_pk, d0.sm),
    );
}

test "bad key headers are rejected" {
    const gpa = std.testing.allocator;
    const d = try Decoded.init(gpa, v.falcon512[0]);
    defer d.deinit(gpa);

    d.pk_bytes[0] = 0x0a; // Falcon-1024 header
    try std.testing.expectError(
        error.InvalidPublicKey,
        falcon.PublicKey.fromBytes(d.pk_bytes[0..897]),
    );
    d.sk_bytes[0] = 0x5a;
    try std.testing.expectError(
        error.InvalidSecretKey,
        falcon.SecretKey.fromBytes(d.sk_bytes[0..1281]),
    );
}
