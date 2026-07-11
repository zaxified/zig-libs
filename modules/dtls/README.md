# dtls

DTLS 1.3 (RFC 9147), **pre-shared-key (PSK) mode only** — no X.509/
certificate path. Secure-UDP transport, intended primarily for the `coap`
module's IoT/SCADA fleet-management use case (CoAP-over-DTLS is RFC 7925's
constrained-device profile).

**Status: crypto core implemented + KAT/OpenSSL-validated; handshake flight
engine deferred.**

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
- **Application-data path** (`src/Connection.zig`) — `installApplicationKeys`
  + `send`/`recv` do real record protection, proven by client↔server
  self-consistency (round-trip both directions, tamper→`DecryptionFailed`).

Real framing (as before): unified + legacy record headers, handshake
fragmentation/reassembly, RFC 9147 §7 ACK + retransmission timer + flight
bookkeeping, and the handshake message bodies incl. the PSK extensions.

**Deferred / out of scope:** the full handshake FLIGHT ENGINE —
`Connection.startHandshake` returns `error.HandshakeEngineNotImplemented`
(all primitives it needs exist and are tested; the state machine, and with
it a live wire-interop test against a real DTLS 1.3 PSK peer, is not built).
Also out of scope: X.509/certificate auth, 0-RTT/early data, resumption, key
update, and the CCM suites (Zig 0.16 std ships only a 13-byte-nonce CCM; the
TLS/DTLS profile needs a 12-byte nonce — see `src/aead.zig`).

## Import

```zig
const dtls = @import("dtls");
```

## API surface (real framing, stubbed crypto)

```zig
const cfg = dtls.Config{
    .role = .client,
    .psk_identity = "device-042",
    .psk = "a-real-pre-shared-key",
};
var conn = try dtls.Connection.clientInit(cfg); // real, validated, no panic

// The handshake flight engine is not built yet:
var out: [1500]u8 = undefined;
_ = conn.startHandshake(&out); // => error.HandshakeEngineNotImplemented

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
