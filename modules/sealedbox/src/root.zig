// SPDX-License-Identifier: MIT
//! sealedbox — NaCl `crypto_box_seal`: anonymous-sender public-key encryption.
//!
//! Encrypt to a recipient's X25519 public key with **no sender key**: a fresh
//! ephemeral keypair is generated per message, so the recipient cannot identify
//! the sender. This is a thin, faithful wrapper over `std.crypto.nacl.SealedBox`
//! — we do NOT roll our own crypto; the nonce derivation and AEAD are std's.
//! (X25519 keys are Curve25519, so a WireGuard pubkey doubles as a recipient key.)
//!
//! Provenance: extracted from the authors' axp project — `axp-core/src/sealed.zig`
//! (the enrollment sealed-box wrapper); Apache-2.0, relicensed MIT by the
//! copyright holder. Model after libsodium `crypto_box_seal` / Go `nacl/box`.
//! No third-party source copied — the construction is the public NaCl standard.

const std = @import("std");

pub const meta = .{
    .status = .extract,
    .platform = .any,
    .role = .util,
    .concurrency = .reentrant,
    .model_after = "libsodium crypto_box_seal / Go nacl/box",
    .deps = .{},
};

pub const SealedBox = std.crypto.nacl.SealedBox;
pub const KeyPair = SealedBox.KeyPair;

/// Recipient public-key length (32, Curve25519).
pub const public_length = SealedBox.public_length;
/// Bytes a sealed message adds over the plaintext (ephemeral pubkey + Poly1305 tag = 48).
pub const overhead = SealedBox.seal_length;

/// Ciphertext length for a plaintext of `plaintext_len` bytes.
pub fn sealedLen(plaintext_len: usize) usize {
    return plaintext_len + overhead;
}

// ── buffer API (no allocation; matches the axp seed) ──────────────────────────

/// Seal `msg` to `recipient_pk`. `out` must be exactly `msg.len + overhead` bytes.
/// `io` supplies entropy for the per-message ephemeral keypair. (Seed: axp sealed.zig.)
pub fn seal(io: std.Io, out: []u8, msg: []const u8, recipient_pk: [public_length]u8) !void {
    std.debug.assert(out.len == msg.len + overhead);
    try SealedBox.seal(io, out, msg, recipient_pk);
}

/// Open a sealed message with the recipient keypair. `out` must be exactly
/// `sealed.len - overhead` bytes. Returns an error (never panics) on a too-short
/// or tampered ciphertext. (Seed: axp sealed.zig.)
pub fn open(out: []u8, sealed: []const u8, kp: KeyPair) !void {
    if (sealed.len < overhead or sealed.len != out.len + overhead)
        return error.InvalidCiphertext;
    try SealedBox.open(out, sealed, kp);
}

// ── allocating convenience ────────────────────────────────────────────────────

/// Seal `msg`, returning a freshly allocated ciphertext (`msg.len + overhead`).
pub fn sealAlloc(gpa: std.mem.Allocator, io: std.Io, msg: []const u8, recipient_pk: [public_length]u8) ![]u8 {
    const out = try gpa.alloc(u8, sealedLen(msg.len));
    errdefer gpa.free(out);
    try seal(io, out, msg, recipient_pk);
    return out;
}

/// Open a sealed message, returning the freshly allocated plaintext.
/// Errors (never panics) on a too-short/tampered ciphertext.
pub fn openAlloc(gpa: std.mem.Allocator, sealed: []const u8, kp: KeyPair) ![]u8 {
    if (sealed.len < overhead) return error.InvalidCiphertext;
    const out = try gpa.alloc(u8, sealed.len - overhead);
    errdefer gpa.free(out);
    try open(out, sealed, kp);
    return out;
}

// ── tests ────────────────────────────────────────────────────────────────────

test "round-trip: buffer API, various sizes including empty" {
    const io = std.testing.io;
    const kp = KeyPair.generate(io);

    const msgs = [_][]const u8{ "", "x", "hello sealed box", "a" ** 100 };
    inline for (msgs) |msg| {
        var boxed: [msg.len + overhead]u8 = undefined;
        try seal(io, &boxed, msg, kp.public_key);
        try std.testing.expectEqual(sealedLen(msg.len), boxed.len);

        var opened: [msg.len]u8 = undefined;
        try open(&opened, &boxed, kp);
        try std.testing.expectEqualSlices(u8, msg, &opened);
    }
}

test "round-trip: sealAlloc/openAlloc" {
    const io = std.testing.io;
    const gpa = std.testing.allocator;
    const kp = KeyPair.generate(io);

    const msgs = [_][]const u8{ "", "allocating convenience round-trip" };
    for (msgs) |msg| {
        const boxed = try sealAlloc(gpa, io, msg, kp.public_key);
        defer gpa.free(boxed);
        try std.testing.expectEqual(sealedLen(msg.len), boxed.len);
        try std.testing.expectEqual(msg.len + overhead, boxed.len);

        const opened = try openAlloc(gpa, boxed, kp);
        defer gpa.free(opened);
        try std.testing.expectEqualSlices(u8, msg, opened);
    }
}

test "tamper: flipped byte in box or ephemeral pk fails authentication" {
    const io = std.testing.io;
    const kp = KeyPair.generate(io);
    const msg = "tamper me";

    var boxed: [msg.len + overhead]u8 = undefined;
    try seal(io, &boxed, msg, kp.public_key);
    var opened: [msg.len]u8 = undefined;

    // flip a byte in the box portion (past the ephemeral pk prefix)
    var t1 = boxed;
    t1[t1.len - 1] ^= 0x01;
    try std.testing.expectError(error.AuthenticationFailed, open(&opened, &t1, kp));

    // flip a byte in the ephemeral pk prefix
    var t2 = boxed;
    t2[0] ^= 0x01;
    try std.testing.expectError(error.AuthenticationFailed, open(&opened, &t2, kp));
}

test "wrong recipient keypair fails authentication" {
    const io = std.testing.io;
    const kp = KeyPair.generate(io);
    const wrong_kp = KeyPair.generate(io);
    const msg = "for someone else";

    var boxed: [msg.len + overhead]u8 = undefined;
    try seal(io, &boxed, msg, kp.public_key);
    var opened: [msg.len]u8 = undefined;
    try std.testing.expectError(error.AuthenticationFailed, open(&opened, &boxed, wrong_kp));
}

test "too-short/garbage ciphertext: clean error, no panic" {
    const io = std.testing.io;
    const gpa = std.testing.allocator;
    const kp = KeyPair.generate(io);

    var opened: [4]u8 = undefined;

    // shorter than the overhead
    const short = [_]u8{0xaa} ** (overhead - 1);
    try std.testing.expectError(error.InvalidCiphertext, open(&opened, &short, kp));
    try std.testing.expectError(error.InvalidCiphertext, openAlloc(gpa, &short, kp));

    // empty ciphertext
    try std.testing.expectError(error.InvalidCiphertext, open(&opened, "", kp));
    try std.testing.expectError(error.InvalidCiphertext, openAlloc(gpa, "", kp));

    // long enough but out-length mismatch
    const mismatched = [_]u8{0xbb} ** (overhead + 10);
    try std.testing.expectError(error.InvalidCiphertext, open(&opened, &mismatched, kp));

    // well-sized garbage: must fail authentication, never panic
    var garbage: [4 + overhead]u8 = undefined;
    io.random(&garbage);
    try std.testing.expectError(error.AuthenticationFailed, open(&opened, &garbage, kp));
}
