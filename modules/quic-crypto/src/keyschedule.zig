// SPDX-License-Identifier: MIT

//! quic-crypto.keyschedule — RFC 9001 §5.1 (packet-protection key/iv/hp from
//! a traffic secret) and §6 (key update). Engine-agnostic: every function
//! takes a caller-supplied traffic secret (from `initial.zig` for the
//! Initial level, or a TLS-derived `Derive-Secret` output the QUIC engine
//! hands in for every other level) and returns derived key material — no
//! I/O, no key storage, no packet-number/epoch state.
//!
//! **Implemented and KAT-validated** against RFC 9001 Appendix A.1 / A.5:
//! the `sanity` tests prove the chain via `std.crypto` directly (independent
//! oracle), and the API tests drive the same vectors through
//! `derivePacketKeys`/`advanceKeys` byte-exact.
//!
//! **The key finding (why this is NOT `dtls.keyschedule`).** DTLS 1.3
//! (RFC 9147 §5.9) forks TLS's HKDF-Expand-Label prefix from `"tls13 "` to
//! `"dtls13"`, so `dtls.keyschedule` re-implements the `HkdfLabel`
//! construction with a parameterized prefix and deliberately does NOT call
//! `std.crypto.tls.hkdfExpandLabel`. QUIC v1 (RFC 9001 §5.1) does the
//! OPPOSITE: it uses the TLS 1.3 HKDF-Expand-Label UNCHANGED — same `"tls13 "`
//! prefix, only the LABELS differ (`"quic key"`/`"quic iv"`/`"quic hp"`/
//! `"quic ku"` instead of `"key"`/`"iv"`). So these functions are thin
//! wrappers over `std.crypto.tls.hkdfExpandLabel` (the `tlsresume.psk`
//! pattern), which is exactly correct here and must NOT be forked.

const std = @import("std");

/// The per-secret packet-protection material RFC 9001 §5.1 derives. `key`
/// and `hp` are `key_len` wide (16 for AES-128-GCM, 32 for AES-256-GCM /
/// ChaCha20-Poly1305); `iv` is always 12 (RFC 9001 §5.1: the AEAD nonce
/// length, or 8 if larger — all QUIC v1 AEADs use 12).
pub fn PacketKeys(comptime key_len: usize) type {
    return struct {
        key: [key_len]u8,
        iv: [12]u8,
        hp: [key_len]u8,
    };
}

/// RFC 9001 §5.1: from a traffic secret,
/// ```
/// key = HKDF-Expand-Label(secret, "quic key", "", key_len)
/// iv  = HKDF-Expand-Label(secret, "quic iv",  "", 12)
/// hp  = HKDF-Expand-Label(secret, "quic hp",  "", key_len)
/// ```
/// `Hkdf` is the negotiated suite's HKDF (`HkdfSha256` for the two SHA-256
/// suites, `Hkdf(HmacSha384)` for AES-256-GCM's SHA-384). `key_len` is the
/// AEAD key length: 16 (AES-128-GCM) or 32 (AES-256-GCM / ChaCha20-Poly1305).
/// The header-protection key `hp` is the SAME length as the AEAD key for all
/// QUIC v1 suites.
///
/// **Implement via `std.crypto.tls.hkdfExpandLabel` UNCHANGED** (see the
/// module doc's "key finding") — one call per output with the QUIC label.
pub fn derivePacketKeys(
    comptime Hkdf: type,
    comptime key_len: usize,
    traffic_secret: [Hkdf.prk_length]u8,
) PacketKeys(key_len) {
    return .{
        .key = std.crypto.tls.hkdfExpandLabel(Hkdf, traffic_secret, "quic key", "", key_len),
        .iv = std.crypto.tls.hkdfExpandLabel(Hkdf, traffic_secret, "quic iv", "", 12),
        .hp = std.crypto.tls.hkdfExpandLabel(Hkdf, traffic_secret, "quic hp", "", key_len),
    };
}

/// The result of one RFC 9001 §6 key update: the advanced traffic secret and
/// the fresh key+iv it produces. Note `hp` is intentionally absent — §6.1:
/// "The header protection key is not updated" (this lets header protection
/// keep protecting the Key Phase bit across updates).
pub fn KeyUpdate(comptime Hkdf: type, comptime key_len: usize) type {
    return struct {
        next_secret: [Hkdf.prk_length]u8,
        key: [key_len]u8,
        iv: [12]u8,
    };
}

/// RFC 9001 §6.1: advance a write/read secret by one key-update epoch and
/// derive its new key+iv:
/// ```
/// next_secret = HKDF-Expand-Label(current_secret, "quic ku", "", Hash.length)
/// key = HKDF-Expand-Label(next_secret, "quic key", "", key_len)
/// iv  = HKDF-Expand-Label(next_secret, "quic iv",  "", 12)
/// ```
/// The header-protection key does NOT change (§6.1) — the caller keeps the
/// `hp` from `derivePacketKeys`. `Hash.length` is `Hkdf.prk_length`.
///
/// The QUIC engine drives this once per Key-Phase toggle, maintaining old +
/// current (+ optionally next) key sets per §6.3 so out-of-order and
/// key-update-straddling packets still decrypt (see SPEC.md's key-update
/// epoch threat note).
pub fn advanceKeys(
    comptime Hkdf: type,
    comptime key_len: usize,
    current_secret: [Hkdf.prk_length]u8,
) KeyUpdate(Hkdf, key_len) {
    const next_secret = std.crypto.tls.hkdfExpandLabel(Hkdf, current_secret, "quic ku", "", Hkdf.prk_length);
    return .{
        .next_secret = next_secret,
        .key = std.crypto.tls.hkdfExpandLabel(Hkdf, next_secret, "quic key", "", key_len),
        .iv = std.crypto.tls.hkdfExpandLabel(Hkdf, next_secret, "quic iv", "", 12),
        // hp is intentionally NOT re-derived — RFC 9001 §6.1.
    };
}

// ── tests ────────────────────────────────────────────────────────────────
//
// RFC 9001 Appendix A.1 (AES-128-GCM key/iv/hp) + A.5 (ChaCha20-Poly1305
// key/iv/hp + the "quic ku" key-update output). Every hex constant was
// extracted verbatim from https://www.rfc-editor.org/rfc/rfc9001.txt and
// cross-checked against a from-scratch Python hmac/hashlib HKDF and the
// `cryptography` package before being committed here.

const testing = std.testing;
const HkdfSha256 = std.crypto.kdf.hkdf.HkdfSha256;

fn hexTo(comptime n: usize, s: []const u8) [n]u8 {
    var out: [n]u8 = undefined;
    _ = std.fmt.hexToBytes(&out, s) catch unreachable;
    return out;
}

// App. A.1 — client Initial traffic secret → key/iv/hp.
const rfc_client_initial_secret = hexTo(32, "c00cf151ca5be075ed0ebfb5c80323c42d6b7db67881289af4008f1f6c357aea");
const rfc_client_key = hexTo(16, "1f369613dd76d5467730efcbe3b1a22d");
const rfc_client_iv = hexTo(12, "fa044b2f42a3fd3b46fb255c");
const rfc_client_hp = hexTo(16, "9f50449e04a0e810283a1e9933adedd2");
// App. A.1 — server Initial.
const rfc_server_initial_secret = hexTo(32, "3c199828fd139efd216c155ad844cc81fb82fa8d7446fa7d78be803acdda951b");
const rfc_server_key = hexTo(16, "cf3a5331653c364c88f0f379b6067e37");
const rfc_server_iv = hexTo(12, "0ac1493ca1905853b0bba03e");
const rfc_server_hp = hexTo(16, "c206b8d9b9f0f37644430b490eeaa314");
// App. A.5 — ChaCha20-Poly1305 (32-byte key/hp), plus the key-update secret.
const rfc_a5_secret = hexTo(32, "9ac312a7f877468ebe69422748ad00a15443f18203a07d6060f688f30f21632b");
const rfc_a5_key = hexTo(32, "c6d98ff3441c3fe1b2182094f69caa2ed4b716b65488960a7a984979fb23e1c8");
const rfc_a5_iv = hexTo(12, "e0459b3474bdd0e44a41c144");
const rfc_a5_hp = hexTo(32, "25a282b9e82f06f21f488917a4fc8f1b73573685608597d0efcb076b0ab7a7a4");
const rfc_a5_ku = hexTo(32, "1223504755036d556342ee9361d253421a826c9ecdf3c7148684b36b714881f9");

test "sanity: RFC 9001 App. A.1 client key/iv/hp match std.crypto directly" {
    const key = std.crypto.tls.hkdfExpandLabel(HkdfSha256, rfc_client_initial_secret, "quic key", "", 16);
    const iv = std.crypto.tls.hkdfExpandLabel(HkdfSha256, rfc_client_initial_secret, "quic iv", "", 12);
    const hp = std.crypto.tls.hkdfExpandLabel(HkdfSha256, rfc_client_initial_secret, "quic hp", "", 16);
    try testing.expectEqualSlices(u8, &rfc_client_key, &key);
    try testing.expectEqualSlices(u8, &rfc_client_iv, &iv);
    try testing.expectEqualSlices(u8, &rfc_client_hp, &hp);
}

test "sanity: RFC 9001 App. A.1 server key/iv/hp match std.crypto directly" {
    const key = std.crypto.tls.hkdfExpandLabel(HkdfSha256, rfc_server_initial_secret, "quic key", "", 16);
    const iv = std.crypto.tls.hkdfExpandLabel(HkdfSha256, rfc_server_initial_secret, "quic iv", "", 12);
    const hp = std.crypto.tls.hkdfExpandLabel(HkdfSha256, rfc_server_initial_secret, "quic hp", "", 16);
    try testing.expectEqualSlices(u8, &rfc_server_key, &key);
    try testing.expectEqualSlices(u8, &rfc_server_iv, &iv);
    try testing.expectEqualSlices(u8, &rfc_server_hp, &hp);
}

test "sanity: RFC 9001 App. A.5 ChaCha20 32-byte key/iv/hp match std.crypto directly" {
    const key = std.crypto.tls.hkdfExpandLabel(HkdfSha256, rfc_a5_secret, "quic key", "", 32);
    const iv = std.crypto.tls.hkdfExpandLabel(HkdfSha256, rfc_a5_secret, "quic iv", "", 12);
    const hp = std.crypto.tls.hkdfExpandLabel(HkdfSha256, rfc_a5_secret, "quic hp", "", 32);
    try testing.expectEqualSlices(u8, &rfc_a5_key, &key);
    try testing.expectEqualSlices(u8, &rfc_a5_iv, &iv);
    try testing.expectEqualSlices(u8, &rfc_a5_hp, &hp);
}

test "sanity: RFC 9001 App. A.5 key-update (\"quic ku\") secret matches std.crypto directly" {
    const ku = std.crypto.tls.hkdfExpandLabel(HkdfSha256, rfc_a5_secret, "quic ku", "", 32);
    try testing.expectEqualSlices(u8, &rfc_a5_ku, &ku);
}

test "derivePacketKeys: App. A.1 client + server, App. A.5 chacha" {
    const c = derivePacketKeys(HkdfSha256, 16, rfc_client_initial_secret);
    try testing.expectEqualSlices(u8, &rfc_client_key, &c.key);
    try testing.expectEqualSlices(u8, &rfc_client_iv, &c.iv);
    try testing.expectEqualSlices(u8, &rfc_client_hp, &c.hp);

    const s = derivePacketKeys(HkdfSha256, 16, rfc_server_initial_secret);
    try testing.expectEqualSlices(u8, &rfc_server_key, &s.key);
    try testing.expectEqualSlices(u8, &rfc_server_iv, &s.iv);
    try testing.expectEqualSlices(u8, &rfc_server_hp, &s.hp);

    const a5 = derivePacketKeys(HkdfSha256, 32, rfc_a5_secret);
    try testing.expectEqualSlices(u8, &rfc_a5_key, &a5.key);
    try testing.expectEqualSlices(u8, &rfc_a5_iv, &a5.iv);
    try testing.expectEqualSlices(u8, &rfc_a5_hp, &a5.hp);
}

test "advanceKeys: App. A.5 \"quic ku\" secret + its key/iv (hp unchanged)" {
    const ku = advanceKeys(HkdfSha256, 32, rfc_a5_secret);
    try testing.expectEqualSlices(u8, &rfc_a5_ku, &ku.next_secret);
    // The RFC does not publish the post-update key/iv, so derive the expected
    // values from rfc_a5_ku via the same sanity path the A.1/A.5 tests use.
    const expect_key = std.crypto.tls.hkdfExpandLabel(HkdfSha256, rfc_a5_ku, "quic key", "", 32);
    const expect_iv = std.crypto.tls.hkdfExpandLabel(HkdfSha256, rfc_a5_ku, "quic iv", "", 12);
    try testing.expectEqualSlices(u8, &expect_key, &ku.key);
    try testing.expectEqualSlices(u8, &expect_iv, &ku.iv);
    // hp unchanged on key update (§6.1): KeyUpdate carries no hp field at all,
    // and the pre-update hp still derives only from the ORIGINAL secret.
    try testing.expect(!@hasField(@TypeOf(ku), "hp"));
}
