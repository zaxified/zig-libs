// SPDX-License-Identifier: MIT

//! dtls — DTLS 1.3 (RFC 9147). Key-exchange modes (`Config.key_exchange`,
//! see `Connection.KeyExchange`):
//!   - `.psk` (default): PSK-only (`psk_ke`, no (EC)DHE), with an ADDITIVE
//!     certificate-mode AUTHENTICATION layer (RFC 8446 §4.4 Certificate/
//!     CertificateVerify/CertificateRequest) that can sit on top of the
//!     unchanged PSK key exchange — see `Connection.zig`'s "certificate mode"
//!     section for the full design + deferred-scope notes.
//!   - `.cert_dhe`: a PSK-LESS certificate-only handshake with ephemeral
//!     (EC)DHE (RFC 8446 §4.2.8 `key_share`) for forward secrecy — the
//!     standard TLS-1.3 `certificate` handshake. TWO groups are wired:
//!     **X25519** (offered by default) and **secp256r1** (offered when a
//!     server asks for it in a HelloRetryRequest — see the HRR section
//!     below). The ECDHE shared secret is fed into the SAME key schedule
//!     (`keyschedule.deriveHandshakeSecret` with a zero-PSK early secret,
//!     RFC 8446 §7.1 — the schedule was already DHE-capable; no forked
//!     crypto), and certificate auth reuses the same `certverify`/`certauth`
//!     plumbing. Validated: the X25519 key_share + key-schedule feed against
//!     RFC 8448 §3's external ECDHE vector, the secp256r1 ECDH against a
//!     Python-`cryptography`/OpenSSL vector (X coordinate only, RFC 8446
//!     §7.4.2), and the full flow against a live wolfSSL peer in BOTH roles.
//!     **Fails closed**: `Config.validate` rejects a `.cert_dhe` client with
//!     no `peer_verify` policy and a `.cert_dhe` server with no `cert`, so a
//!     Config that sets nothing but the mode can no longer complete an
//!     unauthenticated handshake in the mode named for authentication.
//!
//!     ⚠ **Both groups are classical — there is no post-quantum hybrid here.**
//!     A `.cert_dhe` session is recorded-now-decrypted-later. Do not assume
//!     parity with the other TLS-family paths a consumer might reach for:
//!     `std.crypto.tls.Client` offers `x25519_ml_kem768` and `ssh` offers
//!     `mlkem768x25519-sha256` first, so choosing `dtls` silently drops to a
//!     classical exchange. The primitive is not the obstacle (`std.crypto.kem
//!     .hybrid.MlKem768X25519` is ready-made and measures faster than std's
//!     own X25519); nobody has wired the group. SPEC.md's threat-model
//!     section carries the numbers and what wiring it would take.
//!   - `.cert_dhe_insecure_unauthenticated`: the same (EC)DHE exchange with
//!     peer authentication switched off — encryption to an unknown party,
//!     indistinguishable from encryption to an active MITM. Spelled out in
//!     full so it can only be chosen deliberately.
//! Certificate mode reuses `std.crypto.Certificate.Parsed.verify` for the
//! actual issuer/validity/signature checks plus this module's existing
//! `rsa` dependency (`certauth.zig`), but — unlike an earlier pass of this
//! module — DER parsing is now routed through this collection's `x509`
//! module's bounds-checked `spkiOf`/`safeCertificate` bridge rather than
//! calling `std.crypto.Certificate.parse` directly (see `certauth.zig`'s
//! "CLOSED GAP" note for why: std's own parser is not panic-safe against
//! adversarial DER in Zig 0.16). `meta.deps` below is therefore
//! `.{"rsa", "x509"}`, not `.{"rsa"}` alone. Intended transport for the
//! `coap` module's secure-UDP
//! needs (IoT/SCADA fleet management: CoAP-over-DTLS is RFC 7925's
//! constrained-device profile) — the PSK+certificate combination in
//! particular targets devices provisioned with both a shared secret AND a
//! per-device X.509 identity.
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
//!   ALSO proven against a THIRD-PARTY stack: `wolfssl_interop.zig` runs a
//!   real DTLS 1.3 PSK handshake over a loopback UDP socket against wolfSSL
//!   5.9.1 in both roles, each followed by an application-data round trip.
//!   That mattered: self-interop passed for four separate wire defects
//!   (missing `legacy_cookie`, a PSK-binder transcript two bytes too long,
//!   no `supported_versions` in either Hello, and no §7 ACK for the client's
//!   final flight), because both of its sides made each mistake together.
//!   An earlier version of this note claimed the epoch-0 ServerHello's
//!   legacy `PlaintextHeader` framing was a blocker; it is not — RFC 9147 §4
//!   uses `DTLSPlaintext` for exactly those unprotected records, and a real
//!   peer accepts it.
//!
//!   RECEIVE-side fragment REASSEMBLY across `handleFlight` calls is now
//!   implemented (RFC 9147 §5.2): a handshake message split across
//!   datagrams is buffered and reassembled by `fragment_offset` — never by
//!   arrival order — tolerating out-of-order and duplicate fragments, with
//!   the connection rolled back to its pre-call state while the flight is
//!   still incomplete (`HandshakeResult.need_more_data`). Because those
//!   buffered bytes are UNAUTHENTICATED at handshake time, the surface is
//!   explicitly bounded: `max_flight_bytes` (4 KiB) buffered per flight,
//!   exactly ONE in-progress message, and a fragment that contradicts bytes
//!   already received is rejected (`error.OverlappingFragment`) rather than
//!   overwriting them — see `Connection.zig`'s "incoming-flight reassembly
//!   bounds" section for the sizing argument. SENDING is still
//!   single-fragment: this engine never splits a message it emits.
//!
//!   Certificate mode is ALSO live now: `wolfssl_interop.zig` drives a
//!   PSK-less `.cert_dhe` handshake (X25519 (EC)DHE + an ECDSA P-256 chain
//!   verified against this repo's own trust anchor) against a real wolfSSL
//!   certificate server, and repeats it at a 256-byte peer MTU where
//!   wolfSSL must fragment its Certificate — so reassembly and cert mode
//!   are proven by the same external oracle. That found a FIFTH defect of
//!   the same shape as the four above: the `.cert_dhe` ClientHello carried
//!   no `supported_versions`, so a real DTLS 1.3 server negotiated 1.2.
//!
//!   Certificate mode is now live in BOTH DIRECTIONS and BOTH IDENTITIES —
//!   the two gaps an earlier version of this note flagged are closed:
//!     * MUTUAL authentication: a wolfSSL server configured
//!       `VERIFY_PEER | FAIL_IF_NO_PEER_CERT`, with the fixture anchor as
//!       its only trusted CA, verifies OUR client's Certificate +
//!       CertificateVerify;
//!     * our SERVER's chain: a real wolfSSL certificate client verifies what
//!       we present (`wolfSSL_get_verify_result` asserted inside the peer)
//!       and round-trips application data under the keys our server derived.
//!   The first of those found a SIXTH defect of exactly the same family: the
//!   client decoded a CertificateRequest's `signature_algorithms` with
//!   `decodeU16ListExtension` into a fixed `[8]u16`, so a real peer's list
//!   (wolfSSL sends 16) came back `error.TooManyExtensions` -> `Malformed`.
//!   The ClientHello path had already been fixed the same way, against the
//!   same peer; the CertificateRequest path survived because only this
//!   module's own server had ever sent one.
//!
//! **Certificate mode (RFC 8446 §4.4, ADDITIVE):** `Connection.Config` gains
//! optional `cert`/`peer_verify`/`request_client_cert`/`require_peer_cert`/
//! `now_sec` fields (all default to the original PSK-only behavior). When
//! set, the flight engine sends/verifies real Certificate +
//! CertificateVerify (+ optionally CertificateRequest for mutual auth)
//! messages, reusing `certverify.sign`/`.verify` for the signature and
//! `certauth.zig` (a `std.crypto.Certificate` + this module's `rsa`
//! dependency bridge — no new module dependency) for DER parsing and a
//! minimal one-hop chain-to-trust-anchor check. In `.psk` mode the PSK still
//! supplies ALL session-key material unchanged — that mode stays `psk_ke`
//! and the certificates add a real signature-based identity check ON TOP,
//! not a replacement key exchange. (The (EC)DHE machinery an earlier version
//! of this note called "out of scope" does exist, but it belongs to
//! `.cert_dhe`; wiring it into `psk_ke` would make the exchange
//! `psk_dhe_ke`, which this engine still does not do — see
//! `HelloRetryRequestUnsupported`.)
//! See `Connection.zig`'s "certificate mode" section for the full design
//! rationale. `signature_algorithms` extension negotiation (RFC 8446 §4.2.3)
//! IS implemented (`Connection.zig`'s `selectSignatureScheme` +
//! `verifyPeerCert`'s downgrade guard) — what remains deferred is full RFC
//! 5280 path building and `CertificateEntry` extensions. See also
//! `certauth.zig`'s module doc "KNOWN GAP" note — `std.crypto.Certificate
//! .parse` is confirmed (by fuzzing) NOT panic-safe against adversarial DER
//! in Zig 0.16, which this module inherits and cannot fix without a
//! from-scratch hardened parser.
//!
//! **What is real framing (used directly by the flight engine, not just
//! unit-tested in isolation):** the unified + legacy record headers
//! (`record.zig`), handshake message framing + fragmentation/reassembly
//! (`handshake.zig`), the RFC 9147 §7 ACK message + caller-clocked
//! retransmission timer + flight bookkeeping (`flight.zig`), and
//! ClientHello/ServerHello/EncryptedExtensions/Finished/HRR/Certificate/
//! CertificateVerify/CertificateRequest message bodies incl. the PSK
//! extensions (`messages.zig`).
//!
//! **HelloRetryRequest / the stateless-cookie exchange (RFC 9147 §5.1, RFC
//! 8446 §4.1.4/§4.2.2):** implemented in BOTH roles, BOTH key-exchange
//! modes, and proven against wolfSSL in each. A client always answers one:
//!   * the COOKIE half (`psk_ke` and `.cert_dhe` alike) — echo it back in a
//!     ClientHello2 that is otherwise ClientHello1 verbatim;
//!   * the (EC)DHE half (`.cert_dhe` only, RFC 8446 §4.1.4) — when the retry
//!     names a `supported_groups` group other than the one we offered a
//!     share in, generate a FRESH share in that group. That is what makes
//!     secp256r1 a real group here rather than an advertisement we could not
//!     honour. Live-anchored three ways against a wolfSSL certificate
//!     server: cookie only, group change only (wolfSSL restricted to
//!     secp256r1 with its cookie exchange off, so the retry's sole content
//!     is the group), and both in one retry.
//! The refusals matter as much as the retry: a second HelloRetryRequest, one
//! naming a group we never advertised (`error.UnsupportedGroup`), one naming
//! a group we ALREADY offered a share in (`error.IllegalHelloRetryRequest` —
//! a client that obliged could be driven round a retry loop by the peer),
//! one with nothing to change at all, and a ServerHello that switches cipher
//! suite after the retry committed to one. None of those has a live
//! counterpart, because no conforming server sends them.
//! A cookie-only retry deliberately leaves the `key_share` BYTE-IDENTICAL:
//! §4.1.2 permits the listed changes and no others, and a gratuitously
//! regenerated share is the same class of violation as a fresh `random`.
//! A server performs the
//! return-routability check when `Config.hello_retry` is set — it answers a
//! cookie-less ClientHello with a HelloRetryRequest and keeps NOTHING,
//! rebuilding the transcript on ClientHello2 from the cookie alone (RFC 8446
//! §4.4.1's `message_hash` rewrite is what makes that possible). The cookie
//! is bound to a caller-supplied `peer_binding` — this module never touches
//! a socket, so the peer's address is an input, like `Config.now_sec` and
//! the `Entropy` arguments. Off by default (source compatibility), which
//! is NOT the posture RFC 9147 §5.1 recommends for an internet-facing
//! server: without it, a spoofed ClientHello turns the server into an
//! amplifier.
//!
//! ## Randomness — a choice the caller names, at every call site
//!
//! `Connection.startHandshake` and `Connection.handleFlight` take a
//! `Connection.Entropy`, a two-armed tagged union: `.csprng` (production) and
//! `.seeded_for_test`. std 0.16 removed `std.crypto.random`, so this module
//! has no hidden RNG — the generator is the caller's to supply, as in
//! `jwt`/`jwe` — but WHICH KIND of generator is no longer inferred from
//! whatever happened to be in scope. It **MUST be a cryptographically secure
//! source** (`std.Random.DefaultCsprng` seeded from real OS entropy), and
//! saying so now costs the caller a word they have to type.
//!
//! The stake is the ephemeral (EC)DHE private key: in `.cert_dhe` mode those
//! calls reach `ecdheGenerate`, and under a seeded PRNG a passive eavesdropper
//! who learns the seed derives the same private key, recomputes the shared
//! secret and decrypts every recorded session from that peer RETROACTIVELY —
//! forward secrecy, the reason an ephemeral key exists, is gone. Smaller but
//! real: a constant ClientHello/ServerHello `random` (byte-identical, linkable
//! handshakes) and a repeated RSA-PSS CertificateVerify salt.
//!
//! `std.Random` is a vtable: a seeded generator is indistinguishable from
//! `getrandom(2)` INSIDE either arm, so **this module still cannot judge the
//! quality of what it is handed and does not try to.** What the type removes is
//! the accident — the weak path exists (this module's own suites and its
//! wolfSSL harness need a replayable handshake) but it can only be entered by
//! writing `.seeded_for_test`. The `io: std.Io` arm that `coconut`/`bbs`/`ibe`
//! use is deliberately absent: `Connection` is a sans-I/O state machine (no
//! socket, no clock, no allocator; every external fact is an input value) and
//! `handleFlight` is the only way to drive it, so a capability handle threaded
//! through it per datagram would contradict that design. A union is a value, so
//! it does not. `certverify.sign` keeps its own, different shape: it takes
//! `?std.Random` and fails closed with `error.RandomRequired` for RSA-PSS,
//! while the ECDSA/Ed25519 arms fall back to RFC 6979/8032 deterministic
//! derivation.
//!
//! **Out of scope (deliberate, not deferred-as-a-stub):** 0-RTT/early data; session
//! resumption (`res binder`/NewSessionTicket); key update (RFC 8446
//! §4.6.3); and the CCM
//! suites (Zig 0.16 std ships only a 13-byte-nonce CCM; the TLS/DTLS
//! profile needs 12 — see `aead.zig`'s CCM caveat).
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
//!   mirrors std TLS's generic per-suite shape, instantiated in
//!   `Connection.zig`'s suite dispatch for `Aes128Gcm` (std) and
//!   `ChaCha20Poly1305` (the `chachapoly` sibling, RFC 8439's plain
//!   ChaCha20-Poly1305 — the `chacha20_poly1305_sha256` suite is not
//!   XChaCha, so the sibling applies; std's ChaCha20-Poly1305 stays
//!   reachable in `aead.zig`'s own tests as the OpenSSL differential
//!   oracle). `AES_128_CCM_8_SHA256` (the CoAP profile default) is NOT
//!   wired: std's CCM presets are all 13-byte-nonce and the parametric
//!   `AesCcm` is private, so a TLS/DTLS-correct 12-byte nonce is
//!   unavailable from std (see the AEAD/CCM correction above).
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
/// reused verbatim by DTLS 1.3 -- RFC 9147 does not redefine it). Standalone
/// sign/verify over a caller-supplied transcript hash + typed key -- no
/// wire framing, no X.509 DER handling. Wired into the actual handshake by
/// `connection`/`certauth` (see the "Certificate mode" section below).
pub const certverify = @import("certverify.zig");

/// The bridge between raw X.509 DER bytes (as carried in a `Certificate`
/// wire message) and `certverify`'s typed `PublicKey`, plus a minimal
/// chain-to-trust-anchor check -- see `certauth.zig`'s module doc comment,
/// including its "KNOWN GAP" note (std's own DER parser is not panic-safe
/// against adversarial input in Zig 0.16 -- read before feeding
/// PEER-supplied certificate bytes through this in a live deployment).
pub const certauth = @import("certauth.zig");

pub const Connection = connection.Connection;
pub const Config = connection.Config;
pub const Role = connection.Role;
pub const CipherSuite = connection.CipherSuite;
/// PSK (`.psk`) vs. PSK-less ephemeral-X25519 certificate (`.cert_dhe`, or
/// its unauthenticated `.cert_dhe_insecure_unauthenticated` sibling) mode
/// selector for `Config.key_exchange` — see `Connection.KeyExchange`.
pub const KeyExchange = connection.KeyExchange;
/// Where `startHandshake`/`handleFlight` get their randomness, as a choice the
/// caller makes by name: `.csprng` for production, `.seeded_for_test` for a
/// reproducible handshake. See "Randomness" above and `Connection.Entropy`.
pub const Entropy = connection.Entropy;

pub const meta = .{
    // The module catalog's one-line entry. This IS the source of truth:
    // README.md's table is rendered from it by `zig build gen-catalog`.
    .doc = "DTLS 1.3 (RFC 9147), PSK mode — key schedule, AEAD record layer, handshake fragmentation/reassembly, anti-replay window.",
    // The catalog's Platform cell. Prose, because it carries nuance the
    // `platform` enum below cannot -- "any (packer: linux)", "amd64 asm +
    // portable fallback". Rendered by `gen-catalog` alongside `doc`.
    .platform_note = "any",
    .targets = .{.linux64},
    .platform = .any,
    .role = .both, // client (Connection.clientInit) and server (Connection.serverInit)
    // One Connection instance = one caller-owned association with its own
    // epoch/sequence-number/key state; nothing shared/global (mirrors the
    // `ssh` module's Transport reasoning).
    .concurrency = .single_owner,
    .model_after = "RFC 9147 (DTLS 1.3, PSK mode + PSK-less cert-only ephemeral-X25519 mode) + RFC 8446 (TLS 1.3 shared key schedule/handshake message shapes; RFC 9147 §5.8/§5.9 reuse these with the \"dtls13\" label prefix); RFC 8446 §4.2.7/§4.2.8 (supported_groups/key_share) + RFC 7748 (X25519); RFC 8446 §4.4.3 (CertificateVerify, in `certverify.zig`)",
    // `rsa`: `certverify.zig`'s RSASSA-PSS dispatch (rsa_pss_rsae_sha{256,384,512}).
    // `x509`: `certauth.zig`'s certificate-DER parsing, routed through
    // `x509.spkiOf`/`x509.safe.safeCertificate` instead of
    // `std.crypto.Certificate.parse` (see certauth.zig's doc comment).
    // `chachapoly`: `Connection.zig`'s suite dispatch uses the SIMD sibling
    // for the negotiated `chacha20_poly1305_sha256` suite (RFC 8439's plain
    // ChaCha20-Poly1305 — NOT XChaCha, so the sibling applies); std's
    // ChaCha20-Poly1305 stays reachable in `aead.zig`'s tests as the
    // OpenSSL-anchored differential oracle.
    // The PSK-only flight engine itself still needs no sibling modules,
    // see the "meta.deps" test below.
    .deps = .{ "rsa", "x509", "chachapoly" },
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
    _ = certauth;
    _ = @import("wolfssl_interop.zig");
}

test "meta.deps is {\"rsa\", \"x509\", \"chachapoly\"} (certverify.zig's RSASSA-PSS dispatch + certauth.zig's cert parsing + Connection.zig's ChaCha20-Poly1305 suite; the PSK flight engine itself needs no sibling modules)" {
    try std.testing.expectEqual(@as(usize, 3), meta.deps.len);
    try std.testing.expectEqualStrings("rsa", meta.deps[0]);
    try std.testing.expectEqualStrings("x509", meta.deps[1]);
    try std.testing.expectEqualStrings("chachapoly", meta.deps[2]);
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
