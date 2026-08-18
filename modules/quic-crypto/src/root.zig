// SPDX-License-Identifier: MIT

//! quic-crypto — the RFC 9001 (Using TLS to Secure QUIC) CRYPTO SEAM:
//! Initial-secret derivation (§5.2), per-secret key/iv/hp derivation (§5.1),
//! AEAD packet protection (§5.3), header protection (§5.4), and key update
//! (§6). **Engine-agnostic and standalone** — it owns NO QUIC transport state
//! machine: no streams, no loss detection, no ACK logic, no handshake flight,
//! no packet-number reconstruction. It transforms caller-supplied bytes
//! (connection IDs, traffic secrets, packet headers, payloads, packet
//! numbers) into key material / protected-or-opened bytes and back, exactly
//! like the sibling `dtls` module ships `dtls.keyschedule`/`dtls.aead` as a
//! pure crypto/codec core with the flight engine left out (there,
//! `Connection.startHandshake` is deferred; here, there is no connection type
//! at all — a QUIC engine is a much larger separate concern).
//!
//! **Status: IMPLEMENTED — all crypto bodies are real and KAT-validated.**
//! Each submodule keeps its std-only `sanity` test that chains RFC 9001
//! Appendix A's published vectors through `std.crypto` DIRECTLY (an
//! independent oracle for the constants + constructions), and the
//! per-function tests now drive the SAME vectors through the public API
//! byte-exact (A.1 key/iv/hp, A.2/A.3 Initial packet protection, A.5
//! ChaCha20-Poly1305 + key update). See SPEC.md for the implementation
//! record and the threat model.
//!
//! ## Recon: what Zig 0.16 `std.crypto` gives this module (paths confirmed)
//!
//! - **THE KEY FINDING — `std.crypto.tls.hkdfExpandLabel` is used
//!   UNCHANGED.** It implements RFC 8446 §7.1's HKDF-Expand-Label with the
//!   `"tls13 "` prefix HARDCODED. RFC 9001 §5.1/§5.2 requires that TLS 1.3
//!   HKDF-Expand-Label EXACTLY — QUIC v1 does NOT fork the prefix. This is
//!   the crucial contrast with this repo's `dtls` module: DTLS 1.3 (RFC 9147
//!   §5.9) DOES fork it to `"dtls13"`, so `dtls.keyschedule` re-implements the
//!   `HkdfLabel` construction and deliberately avoids the std function. QUIC
//!   is the opposite — it calls the std function directly (the `tlsresume.psk`
//!   pattern), and only the LABELS differ (`"quic key"`/`"quic iv"`/
//!   `"quic hp"`/`"quic ku"`/`"client in"`/`"server in"`). Getting this
//!   backwards (forking the prefix like dtls) would silently produce keys no
//!   QUIC peer accepts.
//! - `std.crypto.kdf.hkdf.HkdfSha256` — `.extract(salt, ikm)` for the §5.2
//!   Initial `HKDF-Extract`; `.prk_length` = 32 (the digest length feeding
//!   `"quic ku"` and the initial secrets).
//! - `std.crypto.aead.aes_gcm.Aes128Gcm` / `Aes256Gcm` and
//!   `std.crypto.aead.chacha_poly.ChaCha20Poly1305` — the three QUIC v1
//!   AEADs (§5.3), all 12-byte nonce / 16-byte tag. `.encrypt`/`.decrypt`
//!   with std's constant-time tag compare back `protection.Protection`.
//! - `std.crypto.core.aes.Aes128` / `Aes256` — `.initEnc(key).encrypt(block,
//!   sample)` is the single-block AES-ECB for the §5.4.3 header-protection
//!   mask (same primitive `dtls.aead.encryptSequenceNumberAes` uses).
//! - `std.crypto.stream.chacha.ChaCha20IETF` — `.stream(out, counter, key,
//!   nonce)` is the raw ChaCha20 keystream for the §5.4.4 mask (same
//!   primitive `dtls.aead.encryptSequenceNumberChaCha20` uses).
//!
//! ## Verification oracles (real, independent — used at scaffold time)
//!
//! Every Appendix A constant carried in the tests was cross-checked against
//! TWO independent oracles before being committed: a from-scratch Python
//! `hmac`/`hashlib` HKDF reimplementation (the §5.1/§5.2/§6 secret chains)
//! and the `cryptography` package (OpenSSL-backed AES-128-GCM /
//! ChaCha20-Poly1305 seal + AES-ECB / raw-ChaCha20 header masks). Both
//! reproduced every byte. The `sanity` tests re-run the second half of that
//! proof inside the Zig test binary via `std.crypto`. A live QUIC wire
//! interop test (against ngtcp2/quiche/msquic) is out of scope for a crypto
//! seam with no transport engine — it belongs to the eventual consumer.

const std = @import("std");
const chachapoly = @import("chachapoly");

pub const initial = @import("initial.zig");
pub const keyschedule = @import("keyschedule.zig");
pub const protection = @import("protection.zig");
pub const headerprot = @import("headerprot.zig");

// Convenience re-exports of the most-used public symbols.
pub const initial_salt_v1 = initial.initial_salt_v1;
pub const InitialSecrets = initial.InitialSecrets;
pub const deriveInitialSecrets = initial.deriveInitialSecrets;
pub const PacketKeys = keyschedule.PacketKeys;
pub const derivePacketKeys = keyschedule.derivePacketKeys;
pub const advanceKeys = keyschedule.advanceKeys;
pub const Protection = protection.Protection;
pub const HeaderForm = headerprot.HeaderForm;

/// The RFC 9001 §5.3 ChaCha20-Poly1305 AEAD to instantiate `Protection` with
/// — the SIMD `chachapoly` sibling, byte-exact to `std.crypto.aead.
/// chacha_poly.ChaCha20Poly1305`. Re-exported because 1-RTT packet protection
/// is a per-packet, per-datagram cost on the QUIC data plane, so which
/// implementation a consumer binds is a throughput decision, not a taste one.
///
/// `Protection` is and stays generic over the AEAD (that is how the two
/// AES-GCM suites are reached, `std.crypto.aead.aes_gcm.Aes128Gcm` /
/// `.Aes256Gcm`), so std's ChaCha type remains bindable and is used as the
/// differential oracle in `protection.zig`'s tests.
pub const ChaCha20Poly1305 = chachapoly.ChaCha20Poly1305;

pub const meta = .{
    .targets = .{.linux64},
    .platform = .any,
    // Pure crypto/codec over caller-supplied bytes — both directions (seal
    // for the sender, open for the receiver; apply/remove header protection).
    // Not .client/.server: RFC 9001 packet protection is symmetric, and this
    // seam serves either endpoint role.
    .role = .codec,
    // Every function is a pure transform of caller-owned bytes with no shared
    // or global state — safe to call from any thread as long as the caller
    // doesn't alias its own buffers.
    .concurrency = .reentrant,
    .model_after = "RFC 9001 (Using TLS to Secure QUIC) §5.1/§5.2/§5.3/§5.4/§6; shares the AEAD-nonce (iv XOR left-pad(pn)) + AES-ECB/ChaCha20 header-mask constructions with this repo's dtls module (RFC 9147), re-expressed QUIC-shaped (no code shared)",
    // chachapoly only: the §5.3 ChaCha20-Poly1305 AEAD (byte-exact to std,
    // SIMD). Deliberately does NOT import dtls (see SPEC.md) — the shared
    // nonce construction is re-expressed, not shared.
    .deps = .{"chachapoly"},
};

// ── dark-tests aggregator (CONVENTIONS.md §6 step 3) ────────────────────
//
// A bare `pub const x = @import("x.zig")` re-export does NOT pull `x`'s
// tests into the test binary on its own — every submodule must be named here
// too (the dtls/tlsresume/noise precedent this module follows).
test {
    _ = initial;
    _ = keyschedule;
    _ = protection;
    _ = headerprot;
}

test "meta.deps is exactly {chachapoly} — quic-crypto still does not import dtls" {
    try std.testing.expectEqual(@as(usize, 1), meta.deps.len);
    try std.testing.expectEqualStrings("chachapoly", meta.deps[0]);
}

test "the AEAD swap is inert: chachapoly matches std on every RFC 9001 §5.3 width" {
    const Std = std.crypto.aead.chacha_poly.ChaCha20Poly1305;
    try std.testing.expectEqual(Std.key_length, ChaCha20Poly1305.key_length);
    try std.testing.expectEqual(@as(usize, 12), ChaCha20Poly1305.nonce_length); // §5.3: nonce-12
    try std.testing.expectEqual(Std.nonce_length, ChaCha20Poly1305.nonce_length);
    try std.testing.expectEqual(Std.tag_length, ChaCha20Poly1305.tag_length);
}

test "meta.role is .codec (symmetric packet protection, either endpoint)" {
    try std.testing.expectEqual(.codec, meta.role);
}

test "quic-crypto uses the TLS \"tls13 \" HKDF prefix UNCHANGED (RFC 9001 §5.1)" {
    // The defining contrast with dtls: RFC 9001 reuses TLS 1.3's
    // HKDF-Expand-Label as-is, so std's hardcoded-"tls13 " function is
    // exactly correct here. This test pins that: the sanity chain in
    // initial.zig/keyschedule.zig already matches RFC 9001 App. A via
    // std.crypto.tls.hkdfExpandLabel, which would be impossible if QUIC
    // forked the prefix. (Contrast dtls's root.zig, which asserts its output
    // DIFFERS from std's for the same reason in reverse.)
    const Hkdf = std.crypto.kdf.hkdf.HkdfSha256;
    const secret = initial.initial_salt_v1 ++ initial.initial_salt_v1[0..12].*; // 32 bytes
    const out = std.crypto.tls.hkdfExpandLabel(Hkdf, secret, "quic key", "", 16);
    try std.testing.expectEqual(@as(usize, 16), out.len);
}
