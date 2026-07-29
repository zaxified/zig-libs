# dtls

DTLS 1.3 (RFC 9147). Two key-exchange modes (`Config.key_exchange`): `.psk`
(default, pre-shared-key, no (EC)DHE) with an additive X.509
Certificate/CertificateVerify/CertificateRequest authentication layer on top,
and `.cert_dhe` (PSK-less, ephemeral-X25519, the standard TLS-1.3-style
certificate handshake). Secure-UDP transport, intended primarily for the
`coap` module's IoT/SCADA fleet-management use case (CoAP-over-DTLS is
RFC 7925's constrained-device profile).

**Status: crypto core + handshake flight engine both implemented and
validated, including live interop against a third-party stack (wolfSSL
5.9.1) in both roles.**

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
  additive certificate-mode messages and the `.cert_dhe` ephemeral-(EC)DHE
  mode — X25519 (validated against RFC 8448 §3's external ECDHE vector) and
  secp256r1 (against a Python-`cryptography`/OpenSSL vector). Proven by an
  in-memory client↔server interop suite: both validated suites reach
  `.connected` with byte-identical derived keys, a real `send`/`recv`
  round trip, caller-clocked retransmission on a dropped ClientHello, and
  typed-error (never panic) rejection of a wrong PSK, mismatched PSK
  identity, corrupted ServerHello, and a malformed HelloRetryRequest — and
  additionally against a live wolfSSL peer (see "Third-party interop").
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

**Third-party interop (`src/wolfssl_interop.zig`):** real DTLS 1.3
handshakes over a loopback UDP socket against **wolfSSL 5.9.1**, each
followed by an application-data round trip. The peer is a small C program
compiled at test time; the tests skip loudly when `cc` or wolfSSL is missing
(`sudo apt install libwolfssl-dev`). Covered live:

- **PSK, both roles** — our client against its server, our server against
  its client;
- **HelloRetryRequest, both roles** (see below);
- **Certificate mode** — our `.cert_dhe` client (PSK-less X25519 (EC)DHE +
  ECDSA P-256) against a wolfSSL certificate server, verifying its chain
  against this repo's own trust anchor;
- **the same certificate handshake at a 256-byte peer MTU**, where wolfSSL
  must split its Certificate across datagrams, so it only completes if the
  reassembly above is real;
- **HelloRetryRequest in certificate mode, all three shapes** — cookie only,
  a group change only (wolfSSL restricted to secp256r1, so the retry's sole
  content is the group and the handshake then runs on P-256 ECDHE), and both
  in one retry;
- **mutual authentication** — a wolfSSL server with
  `VERIFY_PEER | FAIL_IF_NO_PEER_CERT` and our anchor as its only CA
  verifying OUR client certificate;
- **our server's chain, verified by a third party** — a real wolfSSL
  certificate client checking what we present.

That test found four defects that self-interop is structurally incapable of
finding, because both sides of a self-interop suite make the same mistake
together:

- the ClientHello omitted DTLS's `legacy_cookie` field entirely (RFC 9147
  §5.3) — the peer answered `alert(decode_error)`;
- the PSK binder was computed over a transcript two bytes too long: RFC 8446
  §4.2.11.2 truncates the ClientHello before the binders **list**, and the
  list's own 2-byte length prefix was being left in;
- neither Hello carried `supported_versions`, so nothing on the wire ever
  said DTLS 1.3 (every version field reads 1.2);
- the server never sent the RFC 9147 §7 ACK for the client's final flight —
  the one flight the spec explicitly excludes from implicit acknowledgement
  — so a conforming client waited forever.

Extending it to certificate mode found a fifth of exactly the same shape:
the `.cert_dhe` ClientHello carried no `supported_versions` at all, so a real
DTLS 1.3 server negotiated 1.2 and the handshake died on the first record.
Self-interop never noticed, because this module's own server did not look.

Extending it to MUTUAL auth found a sixth: the client decoded a
CertificateRequest's `signature_algorithms` into a fixed `[8]u16`, so a real
peer's list (wolfSSL sends 16) came back `TooManyExtensions` → `Malformed`.
The ClientHello path had already been fixed the same way against the same
peer; this one survived because only our own server — whose list is short —
had ever sent a CertificateRequest.

**HelloRetryRequest / the stateless-cookie exchange** (RFC 9147 §5.1, RFC
8446 §4.1.4/§4.2.2) is implemented in **both roles**, each proven against
wolfSSL playing the other.

*Client:* always answers one — the posture a stock DTLS 1.3 server ships
with, so without it this module could not talk to a default-configured peer
at all. It applies whichever of §4.1.2's permitted changes the retry asked
for: echo the **cookie**, and — in `.cert_dhe` — generate a fresh
**`key_share` in the group the retry named** (§4.1.4's (EC)DHE half, which
is what makes `secp256r1` real here rather than merely advertised).
Everything else in ClientHello2 is ClientHello1 verbatim, including the
`random` and, for a cookie-only retry, the key share itself. Retries that
must be REFUSED — a second one, a group we never advertised
(`error.UnsupportedGroup`), a group we already offered a share in
(`error.IllegalHelloRetryRequest`, the peer-driven retry loop), one with
nothing to change, and a ServerHello that switches cipher suite after the
retry committed to one — have no live counterpart, since no conforming
server sends them, and are covered by unit tests instead.

*Server:* opt in with `Config.hello_retry`. A cookie-less ClientHello is
answered with a HelloRetryRequest and **nothing is kept** — no transcript, no
state transition, no cached flight, and not even a PSK-binder check, because
the whole point is that an unverified (possibly spoofed) address costs the
server one HMAC rather than a flight. Everything needed to continue is in the
cookie, so a *brand-new* `Connection` finishes the handshake from
ClientHello2; that is how the live test is written, which makes statelessness
structural rather than asserted. RFC 8446 §4.4.1's `message_hash` transcript
rewrite is what makes it possible.

The cookie is `HMAC-SHA256(cookie_secret, label || peer_binding ||
version || cipher_suite || Hash(ClientHello1))`. `peer_binding` is
**caller-supplied** — typically the peer's packed address and port. It has to
be: this module never touches a socket (the caller owns the datagram I/O), so
the peer's address is an input in the same way the clock (`Config.now_sec`)
and randomness (`std.Random` arguments) are. A cookie that is not bound to an
address is not a return-routability check, so an empty `peer_binding` is a
config error rather than a documented footgun.

Off by default, which is *not* what RFC 9147 §5.1 recommends ("The default
SHOULD be that the exchange is performed") — the default is chosen for source
compatibility. A server reachable from the open internet that leaves it off
is an amplifier: a spoofed ClientHello makes it spray a much larger flight at
the victim.

## Reassembly across datagrams (RFC 9147 §5.2)

A flight need not arrive in one datagram, and neither does a single handshake
message — a certificate chain routinely exceeds the path MTU, so a real peer
fragments it. `handleFlight` therefore buffers a flight's datagrams and
reassembles by `fragment_offset` (never by arrival order), tolerating
out-of-order and duplicate fragments. While a flight is incomplete it returns
`HandshakeResult.need_more_data` with an empty `out` and the connection
**rolled back** to exactly its pre-call state, so a half-processed flight
never leaves the state machine, transcript, key schedule or anti-replay
windows half-advanced.

Because those buffered bytes are not authenticated yet, every dimension is
capped: 4096 bytes per flight (`error.FlightTooLarge` past that, buffer
dropped), exactly one in-progress message (`error.InterleavedFragments` for a
fragment of a later one), and a fragment that re-covers already-received
bytes with *different* content is `error.OverlappingFragment` — byte-identical
re-delivery is fine, contradiction is not, because "last writer wins" would
let an off-path attacker steer what ends up in the transcript hash.

Sending is still single-fragment: this engine never splits a message it
emits, so it needs a peer MTU that fits the messages it sends (bounded by
`max_cert_message_body` and friends). And what the accumulator tolerates is a
peer that *fragments*, not one that retransmits a whole flight verbatim into
the middle of an incomplete one — see `handleFlight`'s "KNOWN LIMIT".

**Deferred / out of scope:** full RFC 5280 §6 certification-path building
(multi-hop chains, name constraints, revocation — `.trust_anchor` is a
minimal one-hop check only), `CertificateEntry` extensions (OCSP/SCT),
0-RTT/early data,
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
