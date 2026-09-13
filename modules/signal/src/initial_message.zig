// SPDX-License-Identifier: MIT

//! The initial ciphertext both handshakes carry. X3DH and PQXDH say the same
//! thing (§ "Sending the initial message" / "Receiving the initial message"):
//! Alice encrypts it "with some AEAD encryption scheme using AD as associated
//! data and using an encryption key which is either SK or the output from some
//! cryptographic PRF keyed by SK", and Bob, "if the initial ciphertext fails to
//! decrypt, aborts the protocol and deletes SK". Shared by `x3dh.zig` and
//! `pqxdh.zig` so the two handshakes cannot drift apart; not re-exported.
//!
//! Until 2026-09-13 neither handshake did this: `initiate` took the ciphertext
//! as an opaque caller argument BEFORE `SK` existed, so no caller could satisfy
//! the spec, and `respond` succeeded whatever the message carried. For PQXDH
//! that left the third `AD` term, `Encode(PQPKB)`, authenticating nothing.

const std = @import("std");
const chachapoly = @import("chachapoly");
const HkdfSha256 = std.crypto.kdf.hkdf.HkdfSha256;
const ChaCha20Poly1305 = chachapoly.ChaCha20Poly1305;

/// HKDF `info` for the key/nonce expansion below.
pub const info = "zig-libs/signal/initial-message/v1";

pub const tag_length: usize = ChaCha20Poly1305.tag_length; // 16

pub const OpenError = error{
    /// The initial ciphertext did not authenticate under `SK` and the full
    /// `AD`: a wrong `SK` (substituted prekey, wrong identity key), a tampered
    /// or truncated ciphertext, or a different `AD`. `respond` has already
    /// zeroed its copy of `SK`.
    InitialMessageAuthenticationFailed,
} || std.mem.Allocator.Error;

const KeyNonce = struct {
    key: [ChaCha20Poly1305.key_length]u8,
    nonce: [ChaCha20Poly1305.nonce_length]u8,
};

/// The spec's "PRF keyed by SK". `SK` is also the Double Ratchet's first root
/// key, so it is never used as a cipher key itself. The nonce is fixed per
/// `SK`, which is safe because an `SK` seals exactly one message: every
/// `initiate` draws a fresh ephemeral key, and so a fresh `SK`.
fn keyNonce(sk: [32]u8) KeyNonce {
    var okm: [ChaCha20Poly1305.key_length + ChaCha20Poly1305.nonce_length]u8 = undefined;
    defer std.crypto.secureZero(u8, &okm);
    HkdfSha256.expand(&okm, info, sk);
    return .{
        .key = okm[0..ChaCha20Poly1305.key_length].*,
        .nonce = okm[ChaCha20Poly1305.key_length..].*,
    };
}

/// Returns `ciphertext ‖ tag`, heap-owned.
pub fn seal(
    allocator: std.mem.Allocator,
    sk: [32]u8,
    ad: []const u8,
    plaintext: []const u8,
) std.mem.Allocator.Error![]u8 {
    const out = try allocator.alloc(u8, plaintext.len + tag_length);
    var kn = keyNonce(sk);
    defer std.crypto.secureZero(u8, &kn.key);
    var tag: [tag_length]u8 = undefined;
    ChaCha20Poly1305.encrypt(out[0..plaintext.len], &tag, plaintext, ad, kn.nonce, kn.key);
    out[plaintext.len..][0..tag_length].* = tag;
    return out;
}

/// Opens `ciphertext ‖ tag`, returning heap-owned plaintext. Fail-closed: no
/// partial plaintext escapes a failed open.
pub fn open(
    allocator: std.mem.Allocator,
    sk: [32]u8,
    ad: []const u8,
    ciphertext: []const u8,
) OpenError![]u8 {
    if (ciphertext.len < tag_length) return error.InitialMessageAuthenticationFailed;
    const ct_len = ciphertext.len - tag_length;
    const tag: [tag_length]u8 = ciphertext[ct_len..][0..tag_length].*;

    var kn = keyNonce(sk);
    defer std.crypto.secureZero(u8, &kn.key);

    const pt = try allocator.alloc(u8, ct_len);
    ChaCha20Poly1305.decrypt(pt, ciphertext[0..ct_len], tag, ad, kn.nonce, kn.key) catch {
        allocator.free(pt);
        return error.InitialMessageAuthenticationFailed;
    };
    return pt;
}
