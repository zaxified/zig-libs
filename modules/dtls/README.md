# dtls

DTLS 1.3 (RFC 9147). Two key-exchange modes (`Config.key_exchange`): `.psk`
(default, pre-shared-key, no (EC)DHE) with an additive X.509
Certificate/CertificateVerify/CertificateRequest authentication layer on top,
and `.cert_dhe` (PSK-less, ephemeral-X25519, the standard TLS-1.3-style
certificate handshake). Secure-UDP transport, intended primarily for the
`coap` module's IoT/SCADA fleet-management use case (CoAP-over-DTLS is
RFC 7925's constrained-device profile).

**Status: crypto core + handshake flight engine both implemented and
validated; third-party-peer interop not yet proven.**

Implemented and validated:
- **PSK key schedule** (`src/keyschedule.zig`) — early/binder/handshake/
  master/application secrets, PSK binder, Finished verify-data (constant-time
  compare), traffic key+IV, DTLS sequence-number key. Uses the RFC 9147 §5.9
  `"dtls13"` label prefix (the one difference from TLS 1.3's `"tls13 "`).
  Validated byte-for-byte against RFC 8448 §3/§4 and an independent Python
  `hmac`/`hashlib` reimplementation.
- **AEAD record protection** (`src/aead.zig`) — the RFC 9147 §4.2.2 per-record
  nonce, seal/open over the unified header, and §4.2.3 sequence-number
  encryption (AES-ECB and ChaCha20 masks). Suites `aes_128_gcm_sha256` and
  `chacha20_poly1305_sha256`. Validated byte-for-byte against OpenSSL.
- **Handshake flight engine** (`src/Connection.zig`'s `startHandshake` /
  `handleFlight` / `poll`) — a real RFC 9147 §5 PSK client+server handshake
  (ClientHello with a real PSK binder → ServerHello → EncryptedExtensions +
  Finished → client Finished → application keys installed), plus the
  additive certificate-mode messages and the `.cert_dhe` ephemeral-X25519
  mode (validated against RFC 8448 §3's external ECDHE vector). Proven by an
  in-memory client↔server interop suite: both validated suites reach
  `.connected` with byte-identical derived keys, a real `send`/`recv`
  round trip, caller-clocked retransmission on a dropped ClientHello, and
  typed-error (never panic) rejection of a wrong PSK, mismatched PSK
  identity, corrupted ServerHello, and HelloRetryRequest. **Not yet proven
  against a third-party DTLS 1.3 peer** — see "Scope caveat" below.
- **Application-data path** (`src/Connection.zig`) — `installApplicationKeys`
  + `send`/`recv` do real record protection, proven by client↔server
  self-consistency (round-trip both directions, tamper→`DecryptionFailed`).
- **Certificate mode** (RFC 8446 §4.4, additive) — real
  Certificate/CertificateVerify/CertificateRequest, `signature_algorithms`
  negotiation with a downgrade guard, and a minimal one-hop
  leaf-to-trust-anchor check (`certauth.zig`) that routes PEER-supplied DER
  through the `x509` module's bounds-checked `spkiOf`/`safeCertificate`
  bridge rather than `std.crypto.Certificate.parse` directly (that std path
  was confirmed by fuzzing to crash on adversarial DER in Zig 0.16 — closed
  here, see `certauth.zig`'s "CLOSED GAP" note).

Real framing (as before): unified + legacy record headers, handshake
fragmentation/reassembly, RFC 9147 §7 ACK + retransmission timer + flight
bookkeeping, and the handshake message bodies incl. the PSK and cert-mode
extensions.

**Scope caveat (honest):** the flight engine is validated for SELF-interop
(this module's client against this module's own server), not yet as a
drop-in for a third-party DTLS 1.3 stack. Two deliberate wire
simplifications stand in the way: the epoch-0 ServerHello uses the legacy
`PlaintextHeader` rather than RFC 9147's unified-header form, and the
ClientHello omits `supported_versions`/`cookie`. Closing these (plus
cross-`handleFlight` fragment reassembly, currently single-fragment only) is
the remaining work before a live interop test against e.g. OpenSSL's
`s_server -dtls1_3 -psk`.

**Deferred / out of scope:** full RFC 5280 §6 certification-path building
(multi-hop chains, name constraints, revocation — `.trust_anchor` is a
minimal one-hop check only), `CertificateEntry` extensions (OCSP/SCT),
HelloRetryRequest's stateless-cookie retry round trip (detected and
rejected with a typed error, not silently mishandled), 0-RTT/early data,
session resumption, key update, and the CCM suites (Zig 0.16 std ships only
a 13-byte-nonce CCM; the TLS/DTLS profile needs a 12-byte nonce — see
`src/aead.zig`).

## Import

```zig
const dtls = @import("dtls");
```

## API surface (real framing, real crypto, real flight engine)

```zig
const cfg = dtls.Config{
    .role = .client,
    .psk_identity = "device-042",
    .psk = "a-real-pre-shared-key",
};
var conn = try dtls.Connection.clientInit(cfg); // real, validated, no panic

// The handshake flight engine drives a real RFC 9147 §5 PSK handshake:
var out: [1500]u8 = undefined;
const client_hello = try conn.startHandshake(random, now_ms, &out);
// send client_hello to the peer, feed its reply to conn.handleFlight(...);
// see Connection.zig's tests for a full client<->server loopback.

// The application-data record path IS real. Given the traffic secrets a
// completed handshake produces (dtls.keyschedule.deriveApplicationTrafficSecrets):
try conn.installApplicationKeys(.aes_128_gcm_sha256, client_ap_secret, server_ap_secret);
const record = try conn.send("hello", &out);   // AEAD + seq-number encryption
// peer:  const msg = try peer.recv(record, &buf);
```

The `dtls.keyschedule` and `dtls.aead` modules are the KAT-validated crypto
core; `dtls.record`/`handshake`/`flight`/`messages` are the pure framing
layer — all usable standalone.

## Verify

```sh
zig build test-dtls
```

## Provenance

Clean-room from RFC 9147 (DTLS 1.3) and RFC 8446 (TLS 1.3, shared key
schedule/handshake shapes only — see `NOTICE`). The key schedule uses its own
`expandLabel` (parameterized on the RFC 9147 §5.9 `"dtls13"` prefix), NOT
std's `"tls13 "`-hardcoded `hkdfExpandLabel`; `hello_retry_request_sequence`
is reused from `std.crypto.tls` as a spec-mandated public constant. See
`NOTICE` for the full statement.
