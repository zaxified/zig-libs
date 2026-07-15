// SPDX-License-Identifier: MIT

//! dtls — DTLS 1.3 (RFC 9147), PRE-SHARED-KEY (PSK) mode only. No X.509/
//! certificate path (this collection's certificate-chain validator, the
//! `x509` module, is itself a scaffold — see its SPEC.md — and PSK mode
//! needs no certificates at all, which is exactly why this module targets
//! it first). Intended transport for the `coap` module's secure-UDP needs
//! (IoT/SCADA fleet management: CoAP-over-DTLS is RFC 7925's constrained-
//! device profile).
//!
//! **What is implemented and validated (crypto core, real — no stubs):**
//! - The full TLS-1.3/DTLS-1.3 PSK key schedule (`keyschedule.zig`):
//!   early/binder/handshake/master/application secrets, the PSK binder,
//!   Finished verify-data (constant-time compare), traffic key+IV, and the
//!   DTLS sequence-number key — using the RFC 9147 §5.9 `"dtls13"` label
//!   prefix (NOT TLS's `"tls13 "`; this is the one key-schedule difference,
//!   and the scaffold's std pass-through, which hardcoded `"tls13 "`, was a
//!   latent interop bug now fixed). Validated byte-for-byte against RFC 8448
//!   §3/§4 (TLS 1.3 traces + PSK binder) and an independent Python
//!   hmac/hashlib reimplementation of the `"dtls13"`-prefixed chain.
//! - AEAD record protection (`aead.zig`): the RFC 9147 §4.2.2 per-record
//!   nonce (`static_iv XOR right-aligned seq64`; epoch NOT mixed in, per the
//!   RFC), seal/open with the unified header as additional data, and §4.2.3
//!   sequence-number encryption for AES (AES-ECB sample mask) and ChaCha20
//!   (ChaCha20-block sample mask). Validated byte-for-byte against OpenSSL
//!   (via the `cryptography` package). Suites: `aes_128_gcm_sha256` and
//!   `chacha20_poly1305_sha256`.
//! - `Connection.zig` application-data path: `installApplicationKeys` +
//!   `send`/`recv` do real record protection + sequence-number encryption,
//!   proven by client↔server self-consistency (identical derived keys,
//!   round-trip both directions, tamper→`error.DecryptionFailed`).
//! - `Connection.zig`'s handshake FLIGHT ENGINE (`startHandshake`/
//!   `handleFlight`/`poll`): a real RFC 9147 §5 PSK-only client+server
//!   handshake, sequencing every sibling module above into a live wire
//!   exchange — ClientHello (with a real PSK binder over the running
//!   transcript) → ServerHello → {EncryptedExtensions, Finished} (epoch 2,
//!   AEAD-protected under the derived handshake traffic keys) → client
//!   Finished → application keys installed on both sides via the existing
//!   `installApplicationKeys`. Both Finished `verify_data`s and the PSK
//!   binder are checked with constant-time compares
//!   (`std.crypto.timing_safe.eql`). `poll` retransmits the last flight on
//!   a caller-clocked `flight.RetransmitTimer` if the peer's next flight
//!   hasn't arrived. Proven by an in-memory client↔server interop test —
//!   no external DTLS peer required (see `Connection.zig`'s tests).
//!
//!   SCOPE CAVEAT (honest): the flight engine is validated for SELF-interop
//!   (this module's client with this module's server), NOT yet as a drop-in
//!   for a third-party DTLS 1.3 peer. Two deliberate wire simplifications
//!   stand in the way of real-peer interop and are called out rather than
//!   hidden: (1) the epoch-0 ServerHello is framed with the legacy
//!   `PlaintextHeader` rather than RFC 9147's unified-header form, and (2)
//!   the ClientHello omits the `supported_versions`/`cookie` extensions a
//!   real peer expects for version negotiation. Closing these (plus
//!   cross-`handleFlight` fragment reassembly, currently single-fragment
//!   only) is the remaining work before an OpenSSL `s_server -dtls1_3 -psk`
//!   live-interop test.
//!
//! **What is real framing (used directly by the flight engine, not just
//! unit-tested in isolation):** the unified + legacy record headers
//! (`record.zig`), handshake message framing + fragmentation/reassembly
//! (`handshake.zig`), the RFC 9147 §7 ACK message + caller-clocked
//! retransmission timer + flight bookkeeping (`flight.zig`), and
//! ClientHello/ServerHello/EncryptedExtensions/Finished/HRR message bodies
//! incl. the PSK extensions (`messages.zig`).
//!
//! **Out of scope (deliberate, not deferred-as-a-stub):** HelloRetryRequest
//! / the stateless-cookie retry round trip (a HelloRetryRequest ServerHello
//! is detected — RFC 8446 §4.1.3's magic `random` — and rejected with a
//! typed error rather than silently mishandled); 0-RTT/early data; session
//! resumption (`res binder`/NewSessionTicket); key update
//! (RFC 8446 §4.6.3); X.509/certificate auth (this module is PSK-only by
//! design, see above); and the CCM suites (Zig 0.16 std ships only a
//! 13-byte-nonce CCM; the TLS/DTLS profile needs 12 — see `aead.zig`'s CCM
//! caveat).
//!
//! **AEAD/CCM recon correction:** the scaffold claimed "AES-CCM is NOT a std
//! gap." That is true for a 13-byte nonce but WRONG for the TLS/DTLS 1.3
//! profile, which requires a 12-byte nonce; std's CCM presets are all
//! nonce-13 and the parametric `AesCcm` is private, so CCM cannot be wired
//! from std presets without a wrong-width nonce. CCM is therefore left
//! unwired here (documented, not silently broken).
//!
//! ## Recon: what Zig 0.16 `std.crypto.tls`/`std.crypto` give this module
//!
//! - `std.crypto.tls.hkdfExpandLabel` implements RFC 8446 §7.1's
//!   HKDF-Expand-Label with the `"tls13 "` prefix HARDCODED. DTLS 1.3
//!   (RFC 9147 §5.9) requires the `"dtls13"` prefix instead, so this module
//!   does NOT forward to it — `keyschedule.expandLabel` re-implements the
//!   `HkdfLabel` construction with a parameterized prefix (defaulting to
//!   `"dtls13"`; the `"tls13 "` path exists only for RFC 8448 KATs). The
//!   scaffold's original "thin pass-through to std" plan would have produced
//!   TLS-prefixed keys that no DTLS peer accepts.
//! - Cipher-suite→AEAD binding: `aead.zig`'s `Protection(comptime Aead)`
//!   mirrors std TLS's generic per-suite shape, instantiated here for
//!   `Aes128Gcm` and `ChaCha20Poly1305`. `AES_128_CCM_8_SHA256` (the CoAP
//!   profile default) is NOT wired: std's CCM presets are all 13-byte-nonce
//!   and the parametric `AesCcm` is private, so a TLS/DTLS-correct 12-byte
//!   nonce is unavailable from std (see the AEAD/CCM correction above).
//! - `std.crypto.core.aes.Aes128`/`Aes256` `.initEnc(key).encrypt(...)` is a
//!   real single-block AES-ECB primitive, used directly for the RFC 9147
//!   §4.2.3 sequence-number mask; `std.crypto.stream.chacha.ChaCha20IETF`
//!   provides the ChaCha20 block keystream for the ChaCha suite's mask.
//! - `std.crypto.tls.hello_retry_request_sequence` is a spec-mandated public
//!   constant reused directly by `messages.zig`.
//!
//! ## Verification oracles (security-critical — real, independent)
//!
//! - **Key schedule + PSK binder:** RFC 8448 "Example Handshake Traces for
//!   TLS 1.3" §3/§4, byte-for-byte (the schedule is identical to DTLS's bar
//!   the label prefix). The `"dtls13"`-prefixed chain is additionally locked
//!   with vectors from an independent Python `hmac`/`hashlib`
//!   reimplementation.
//! - **AEAD record protection + sequence-number masks:** byte-for-byte
//!   against OpenSSL (via the `cryptography` package) — nonce XOR, AES-GCM
//!   and ChaCha20-Poly1305 seal/open, AES-ECB and ChaCha20 seq masks.
//! - **Full crypto-core composition:** client↔server self-consistency in
//!   `Connection.zig` (identical derived keys, `send`→`recv` round-trip both
//!   directions, sequence numbers encrypted on the wire, tamper→reject).
//! - **Live DTLS 1.3 PSK wire handshake:** a real in-memory client↔server
//!   interop test drives `startHandshake`/`handleFlight` end to end for
//!   both validated suites, asserting both sides reach `.connected` with
//!   byte-identical derived application keys, a real `send`/`recv`
//!   application-data round trip in both directions over those
//!   freshly-installed keys, and rejection (typed errors, never a panic) of
//!   a wrong PSK, a mismatched PSK identity, a corrupted ServerHello, and a
//!   dropped-then-retransmitted (fake-clock-driven) ClientHello. No
//!   external DTLS peer is used — see `Connection.zig`'s tests.

const std = @import("std");

pub const record = @import("record.zig");
pub const handshake = @import("handshake.zig");
pub const flight = @import("flight.zig");
pub const messages = @import("messages.zig");
pub const keyschedule = @import("keyschedule.zig");
pub const aead = @import("aead.zig");
pub const engine = @import("engine.zig");
pub const connection = @import("Connection.zig");

/// TLS/DTLS 1.3 CertificateVerify signature construction (RFC 8446 §4.4.3,
/// reused verbatim by DTLS 1.3 -- RFC 9147 does not redefine it). Purely
/// additive and self-contained: it does not touch, call into, or get called
/// by the PSK flight engine above (`connection`/`messages`/`keyschedule`/
/// `engine`) or the handshake state machine -- see `certverify.zig`'s module
/// doc comment for its scope. Standalone verify/sign only; wiring it into a
/// full cert-mode handshake flow (which this module's PSK engine does not
/// have) is future work.
pub const certverify = @import("certverify.zig");

pub const Connection = connection.Connection;
pub const Config = connection.Config;
pub const Role = connection.Role;
pub const CipherSuite = connection.CipherSuite;

pub const meta = .{
    .platform = .any,
    .role = .both, // client (Connection.clientInit) and server (Connection.serverInit)
    // One Connection instance = one caller-owned association with its own
    // epoch/sequence-number/key state; nothing shared/global (mirrors the
    // `ssh` module's Transport reasoning).
    .concurrency = .single_owner,
    .model_after = "RFC 9147 (DTLS 1.3, PSK mode) + RFC 8446 (TLS 1.3 shared key schedule/handshake message shapes; RFC 9147 §5.8/§5.9 reuse these with the \"dtls13\" label prefix); RFC 8446 §4.4.3 (CertificateVerify, in `certverify.zig`)",
    // `rsa`: solely for `certverify.zig`'s RSASSA-PSS dispatch
    // (rsa_pss_rsae_sha{256,384,512}) -- the PSK-only flight engine itself
    // still needs no sibling modules, see the "meta.deps" test below.
    .deps = .{"rsa"},
};

// ── dark-tests aggregator (CONVENTIONS.md §6 step 3) ────────────────────
//
// A bare `pub const x = @import("x.zig")` re-export does NOT pull `x`'s
// tests into the test binary on its own — every submodule must be named
// here too. All submodules below now carry real `test` blocks
// (`keyschedule`/`aead` included, with KATs). `certverify` included -- its
// `test` block carries buildSignedContent unit tests, dispatch reject-path
// tests, and byte-exact sign/verify + tamper KATs, all passing.
test {
    _ = record;
    _ = handshake;
    _ = flight;
    _ = messages;
    _ = keyschedule;
    _ = aead;
    _ = engine;
    _ = connection;
    _ = certverify;
}

test "meta.deps is {\"rsa\"} (only certverify.zig's RSASSA-PSS dispatch needs it; the PSK flight engine itself needs no sibling modules)" {
    try std.testing.expectEqual(@as(usize, 1), meta.deps.len);
    try std.testing.expectEqualStrings("rsa", meta.deps[0]);
}

test "keyschedule.hkdfExpandLabel: uses the DTLS \"dtls13\" prefix (RFC 9147 §5.9)" {
    // DTLS 1.3 changes the HKDF-Expand-Label prefix from TLS 1.3's "tls13 "
    // to "dtls13" (RFC 9147 §5.9). The module's hkdfExpandLabel MUST use the
    // DTLS prefix, so its output MUST DIFFER from std's hardcoded-tls13
    // function on the same inputs (proving the prefix fix is in place). The
    // tls13-prefix variant is validated against std + RFC 8448 in
    // keyschedule.zig's own tests.
    const Hkdf = std.crypto.kdf.hkdf.HkdfSha256;
    const secret = [_]u8{0x42} ** 32;
    const out = keyschedule.hkdfExpandLabel(Hkdf, secret, "test label", "", 16);
    try std.testing.expectEqual(@as(usize, 16), out.len);
    const tls13 = std.crypto.tls.hkdfExpandLabel(Hkdf, secret, "test label", "", 16);
    try std.testing.expect(!std.mem.eql(u8, &tls13, &out));
}
