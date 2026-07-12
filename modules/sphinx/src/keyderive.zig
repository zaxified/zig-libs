// SPDX-License-Identifier: MIT
//! BOLT#4 "Key Generation" + "Pseudo Random Byte Stream": the two REAL,
//! keyless-of-any-particular-hop primitives every Sphinx crypto core
//! (`core.zig`'s `deriveHopSecrets`/`construct`/`process`) is built
//! from. Both are plain `std.crypto` — no elliptic-curve math here at all.
//!
//! - `generateKey`: BOLT#4 "Key Generation" — `HMAC-SHA256(key_type_label,
//!   shared_secret)`. Four key types are named by the spec: `rho` (streams
//!   the obfuscating keystream), `mu` (the packet-integrity HMAC key), `um`
//!   (the error-message HMAC key — return-path only, not used by
//!   `construct`/`process` in this module), `pad` (seeds the initial
//!   1300-byte random padding). Per the spec: "the key-type does not
//!   include a C-style 0x00-termination-byte" — `"rho"` is exactly 3 bytes
//!   as the HMAC key, not 4.
//! - `generateCipherStream`: BOLT#4 "Pseudo Random Byte Stream" —
//!   `ChaCha20(key, nonce=0^96)` used purely as a keystream generator (the
//!   plaintext is conceptually all-zero, so the keystream IS the output;
//!   nothing is actually being encrypted here). Reusing a fixed all-zero
//!   nonce is safe per the spec because every `key` here is itself
//!   HMAC-derived from a fresh, never-reused shared secret or session key —
//!   the nonce would only be dangerous if the SAME key were used twice.

const std = @import("std");
const HmacSha256 = std.crypto.auth.hmac.sha2.HmacSha256;
const ChaCha20IETF = std.crypto.stream.chacha.ChaCha20IETF;

/// BOLT#4 "Key Generation"'s four named key types, with their exact
/// (unterminated) ASCII HMAC-key labels.
pub const KeyType = enum {
    rho,
    mu,
    um,
    pad,

    fn label(self: KeyType) []const u8 {
        return switch (self) {
            .rho => "rho",
            .mu => "mu",
            .um => "um",
            .pad => "pad",
        };
    }
};

/// BOLT#4 "Key Generation": `HMAC-SHA256(key = key_type's ASCII label, msg =
/// shared_secret)`. Note the HMAC-key/message roles: the fixed short label
/// is the HMAC KEY, the 32-byte per-hop shared secret is the MESSAGE —
/// swapping them would silently derive a different (wrong, non-interop)
/// key.
pub fn generateKey(key_type: KeyType, shared_secret: [32]u8) [32]u8 {
    var out: [32]u8 = undefined;
    HmacSha256.create(&out, &shared_secret, key_type.label());
    return out;
}

/// BOLT#4 "Pseudo Random Byte Stream": fills all of `out` with
/// `ChaCha20(key, counter=0, nonce=0^96)`'s keystream — i.e. `out` is
/// OVERWRITTEN (not XORed into), since there is no real plaintext, only the
/// keystream itself. `std.crypto.stream.chacha.ChaCha20IETF.stream` is
/// exactly this: the IETF ChaCha20 variant with a 96-bit nonce and a
/// 32-bit block counter (`ChaCha20IETF.nonce_length == 12`,
/// `.key_length == 32`), called with an explicit all-zero nonce and a
/// starting counter of 0 — matching the spec's "encrypting a 0x00-byte
/// stream ... initialized with a key derived from the shared secret and a
/// 96-bit zero-nonce" verbatim (there is no separate "encrypt zeros" step
/// to perform; `.stream` IS that operation).
pub fn generateCipherStream(key: [32]u8, out: []u8) void {
    const zero_nonce = [_]u8{0} ** ChaCha20IETF.nonce_length;
    ChaCha20IETF.stream(out, 0, key, zero_nonce);
}

// ── tests ────────────────────────────────────────────────────────────────

test "generateKey: distinct key types yield distinct keys for the same secret" {
    const ss = [_]u8{0x42} ** 32;
    const rho = generateKey(.rho, ss);
    const mu = generateKey(.mu, ss);
    const um = generateKey(.um, ss);
    const pad = generateKey(.pad, ss);
    try std.testing.expect(!std.mem.eql(u8, &rho, &mu));
    try std.testing.expect(!std.mem.eql(u8, &rho, &um));
    try std.testing.expect(!std.mem.eql(u8, &rho, &pad));
    try std.testing.expect(!std.mem.eql(u8, &mu, &um));
    try std.testing.expect(!std.mem.eql(u8, &mu, &pad));
    try std.testing.expect(!std.mem.eql(u8, &um, &pad));
}

test "generateKey: deterministic, and matches a std-only recomputation (HMAC-key/message roles)" {
    const ss = [_]u8{0x7a} ** 32;
    const a = generateKey(.rho, ss);
    const b = generateKey(.rho, ss);
    try std.testing.expectEqualSlices(u8, &a, &b);

    // Independent recomputation directly against std.crypto, spelling out
    // BOLT#4's "key-type as HMAC-key, shared secret as message" (the
    // opposite of the more common "key material as HMAC key" idiom) —
    // proves generateKey did not swap the two arguments.
    var expected: [32]u8 = undefined;
    std.crypto.auth.hmac.sha2.HmacSha256.create(&expected, &ss, "rho");
    try std.testing.expectEqualSlices(u8, &expected, &a);
}

test "generateKey: the four labels have no 0x00 terminator (3/2/2/3 bytes)" {
    try std.testing.expectEqual(@as(usize, 3), KeyType.rho.label().len);
    try std.testing.expectEqual(@as(usize, 2), KeyType.mu.label().len);
    try std.testing.expectEqual(@as(usize, 2), KeyType.um.label().len);
    try std.testing.expectEqual(@as(usize, 3), KeyType.pad.label().len);
}

test "generateCipherStream: deterministic, full-length, and matches raw ChaCha20IETF.stream" {
    const key = [_]u8{0x11} ** 32;
    var a: [1300]u8 = undefined;
    var b: [1300]u8 = undefined;
    generateCipherStream(key, &a);
    generateCipherStream(key, &b);
    try std.testing.expectEqualSlices(u8, &a, &b);

    var expected: [1300]u8 = undefined;
    ChaCha20IETF.stream(&expected, 0, key, [_]u8{0} ** ChaCha20IETF.nonce_length);
    try std.testing.expectEqualSlices(u8, &expected, &a);

    // Not all-zero (sanity: this is really ChaCha20 output, not a memset).
    try std.testing.expect(!std.mem.allEqual(u8, &a, 0));
}

test "generateCipherStream: different keys produce different streams" {
    var a: [64]u8 = undefined;
    var b: [64]u8 = undefined;
    generateCipherStream([_]u8{1} ** 32, &a);
    generateCipherStream([_]u8{2} ** 32, &b);
    try std.testing.expect(!std.mem.eql(u8, &a, &b));
}
