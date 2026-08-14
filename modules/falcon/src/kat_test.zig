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

// ---- Falcon-1024: the same battery against falcon1024-KAT.rsp. ----

const pk1024_len = falcon.PublicKey1024.encoded_length; // 1793
const sk1024_len = falcon.SecretKey1024.encoded_length; // 2305

test "NIST Round-3 KAT (1024): every vector's signed message verifies and opens" {
    const gpa = std.testing.allocator;
    for (v.falcon1024) |vec| {
        const d = try Decoded.init(gpa, vec);
        defer d.deinit(gpa);

        try std.testing.expectEqual(@as(usize, pk1024_len), d.pk_bytes.len);
        try std.testing.expectEqual(@as(usize, sk1024_len), d.sk_bytes.len);
        const pk = try falcon.PublicKey1024.fromBytes(d.pk_bytes[0..pk1024_len]);

        const opened = try falcon.openNistSignedMessage1024(&pk, d.sm);
        try std.testing.expectEqualSlices(u8, d.msg, opened);
    }
}

test "NIST Round-3 KAT (1024): compressed signature re-encodes byte-exactly" {
    const gpa = std.testing.allocator;
    for (v.falcon1024) |vec| {
        const d = try Decoded.init(gpa, vec);
        defer d.deinit(gpa);

        const sig_len = (@as(usize, d.sm[0]) << 8) | d.sm[1];
        const sig_field = d.sm[d.sm.len - sig_len ..];
        try std.testing.expectEqual(falcon.sig_header_1024, sig_field[0]);
        var s2: [poly.Ring1024.n]i16 = undefined;
        try codec.Codec1024.compDecode(&s2, sig_field[1..]);

        var buf: [falcon.max_sig_field_length_1024]u8 = undefined;
        const enc_len = try codec.Codec1024.compEncode(&buf, &s2);
        try std.testing.expectEqualSlices(u8, sig_field[1..], buf[0..enc_len]);
    }
}

test "NIST Round-3 KAT (1024): secret key decodes and reproduces the public key" {
    const gpa = std.testing.allocator;
    for (v.falcon1024) |vec| {
        const d = try Decoded.init(gpa, vec);
        defer d.deinit(gpa);

        const sk = try falcon.SecretKey1024.fromBytes(d.sk_bytes[0..sk1024_len]);
        const pk_from_sk = try sk.publicKey();
        const pk = try falcon.PublicKey1024.fromBytes(d.pk_bytes[0..pk1024_len]);
        try std.testing.expectEqualSlices(u16, &pk.h, &pk_from_sk.h);
    }
}

test "NIST Round-3 KAT (1024): public key re-encodes byte-exactly" {
    const gpa = std.testing.allocator;
    for (v.falcon1024) |vec| {
        const d = try Decoded.init(gpa, vec);
        defer d.deinit(gpa);
        const pk = try falcon.PublicKey1024.fromBytes(d.pk_bytes[0..pk1024_len]);
        try std.testing.expectEqualSlices(u8, d.pk_bytes, &pk.toBytes());
    }
}

test "tampered message is rejected (1024)" {
    const gpa = std.testing.allocator;
    const d = try Decoded.init(gpa, v.falcon1024[0]);
    defer d.deinit(gpa);
    const pk = try falcon.PublicKey1024.fromBytes(d.pk_bytes[0..pk1024_len]);

    // Flip one bit of the embedded message.
    d.sm[2 + falcon.nonce_length] ^= 0x01;
    try std.testing.expectError(
        error.SignatureVerificationFailed,
        falcon.openNistSignedMessage1024(&pk, d.sm),
    );
}

test "tampered nonce is rejected (1024)" {
    const gpa = std.testing.allocator;
    const d = try Decoded.init(gpa, v.falcon1024[0]);
    defer d.deinit(gpa);
    const pk = try falcon.PublicKey1024.fromBytes(d.pk_bytes[0..pk1024_len]);
    d.sm[2] ^= 0x80;
    try std.testing.expectError(
        error.SignatureVerificationFailed,
        falcon.openNistSignedMessage1024(&pk, d.sm),
    );
}

test "tampered, truncated, or malformed signature field is rejected (1024)" {
    const gpa = std.testing.allocator;
    const d = try Decoded.init(gpa, v.falcon1024[0]);
    defer d.deinit(gpa);
    const pk = try falcon.PublicKey1024.fromBytes(d.pk_bytes[0..pk1024_len]);
    const sig_len = (@as(usize, d.sm[0]) << 8) | d.sm[1];

    // Corrupt a byte in the middle of the compressed signature: either the
    // decoding becomes non-canonical (InvalidSignature) or the recovered
    // vector fails the norm check — both must reject.
    {
        const sm2 = try gpa.dupe(u8, d.sm);
        defer gpa.free(sm2);
        sm2[sm2.len - sig_len / 2] ^= 0x40;
        const r = falcon.openNistSignedMessage1024(&pk, sm2);
        try std.testing.expect(r == error.InvalidSignature or
            r == error.SignatureVerificationFailed);
    }

    // Wrong header byte (a Falcon-512 header on a 1024 signature).
    {
        const sm2 = try gpa.dupe(u8, d.sm);
        defer gpa.free(sm2);
        sm2[sm2.len - sig_len] = 0x29; // logn=9 header
        try std.testing.expectError(
            error.InvalidSignature,
            falcon.openNistSignedMessage1024(&pk, sm2),
        );
    }

    // Truncated envelope (drop the last signature byte, keep length field).
    {
        const sm2 = try gpa.dupe(u8, d.sm[0 .. d.sm.len - 1]);
        defer gpa.free(sm2);
        try std.testing.expectError(
            error.InvalidSignature,
            falcon.openNistSignedMessage1024(&pk, sm2),
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
            falcon.openNistSignedMessage1024(&pk, sm2),
        );
    }
}

test "signature does not verify under a different vector's public key (1024)" {
    const gpa = std.testing.allocator;
    const d0 = try Decoded.init(gpa, v.falcon1024[0]);
    defer d0.deinit(gpa);
    const d1 = try Decoded.init(gpa, v.falcon1024[1]);
    defer d1.deinit(gpa);
    const wrong_pk = try falcon.PublicKey1024.fromBytes(d1.pk_bytes[0..pk1024_len]);
    try std.testing.expectError(
        error.SignatureVerificationFailed,
        falcon.openNistSignedMessage1024(&wrong_pk, d0.sm),
    );
}

test "bad key headers are rejected (1024)" {
    const gpa = std.testing.allocator;
    const d = try Decoded.init(gpa, v.falcon1024[0]);
    defer d.deinit(gpa);

    d.pk_bytes[0] = 0x09; // Falcon-512 header
    try std.testing.expectError(
        error.InvalidPublicKey,
        falcon.PublicKey1024.fromBytes(d.pk_bytes[0..pk1024_len]),
    );
    d.sk_bytes[0] = 0x59;
    try std.testing.expectError(
        error.InvalidSecretKey,
        falcon.SecretKey1024.fromBytes(d.sk_bytes[0..sk1024_len]),
    );
}

test "Falcon-512 verify entry rejects a Falcon-1024 signature envelope" {
    const gpa = std.testing.allocator;
    const d = try Decoded.init(gpa, v.falcon1024[0]);
    defer d.deinit(gpa);
    // A 1024 pk is 1793 B, not 897 B — the 512 decoder must not accept it,
    // and its header byte (0x0a) is wrong for the 512 path anyway.
    try std.testing.expect(d.pk_bytes.len != falcon.PublicKey.encoded_length);
    try std.testing.expectError(
        error.InvalidPublicKey,
        falcon.PublicKey.fromBytes(d.pk_bytes[0..falcon.PublicKey.encoded_length]),
    );
}

// ── fuzz: PublicKey.verify on hostile compressed signature bytes ────────
//
// `verify` is the module's real untrusted-input surface: a compressed
// signature field arrives from whoever produced it, over a fixed public
// key/message/nonce, and must reduce to `VerifyError` alone — never panic,
// never read out of bounds — however the Golomb-Rice compression is
// corrupted. Biased toward "nearly valid" by starting from a real NIST-KAT
// signature field and flipping a handful of bytes; pure random bytes are
// rejected by `compDecode`'s canonical-encoding check almost every time,
// never reaching the NTT/norm-check machinery this exists to exercise.
fn fuzzVerify(_: void, smith: *std.testing.Smith) !void {
    const gpa = std.testing.allocator;
    const d = Decoded.init(gpa, v.falcon512[0]) catch return;
    defer d.deinit(gpa);
    const pk = falcon.PublicKey.fromBytes(d.pk_bytes[0..897]) catch return;

    const sig_len = (@as(usize, d.sm[0]) << 8) | d.sm[1];
    if (sig_len < 1 or sig_len > d.sm.len - 2 - falcon.nonce_length) return;
    const nonce = d.sm[2 .. 2 + falcon.nonce_length];
    const msg = d.sm[2 + falcon.nonce_length .. d.sm.len - sig_len];
    const real_sig = d.sm[d.sm.len - sig_len ..];

    var buf: [falcon.max_sig_field_length]u8 = undefined;
    const len = @min(real_sig.len, buf.len);
    @memcpy(buf[0..len], real_sig[0..len]);

    const n_flips = smith.valueRangeAtMost(u8, 0, 6);
    var i: u8 = 0;
    while (i < n_flips) : (i += 1) {
        const pos = smith.index(len);
        buf[pos] = smith.value(u8);
    }

    pk.verify(msg, nonce[0..falcon.nonce_length], buf[0..len]) catch return;
}

test "fuzz: PublicKey.verify never panics on corrupted compressed signatures" {
    try std.testing.fuzz({}, fuzzVerify, .{});
}
