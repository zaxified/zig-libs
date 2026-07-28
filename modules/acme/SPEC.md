# acme — spec

ACME v2 (RFC 8555) client: account registration, HTTP-01 and TLS-ALPN-01 (RFC 8737) challenge
issuance, and renewal. Usage: see ./README.md. Attribution/provenance: see /NOTICE.

## Design & invariants
- **Flow:** new-nonce → new-account → new-order → authorization → finalize with a CSR → poll →
  download the certificate chain. Renewal re-runs the order. Two challenge types (per
  `Options.challenge_type`) share the account/order/notify/poll machinery — only the proof differs:
  - **HTTP-01** (default): serve the key-authorization token at
    `/.well-known/acme-challenge/<token>` via the `Responder` `router` middleware.
  - **TLS-ALPN-01** (RFC 8737): the library computes `acmeIdentifier = SHA-256(keyAuthorization)`
    (`jws.acmeIdentifier`) and builds a **self-signed validation certificate** (`x509.tlsAlpnCertDer`
    / `x509.tlsAlpnCert`) carrying a dNSName SAN for the domain plus the **critical
    `id-pe-acmeIdentifier` extension** (OID `1.3.6.1.5.5.7.1.31`, extnValue =
    `OCTET STRING( OCTET STRING(32-byte identifier) )` — the RFC 8737 §3 double wrap). The order flow
    stores the cert+key in `TlsAlpnResponder` keyed by domain; the caller's TLS listener serves it
    under ALPN `acme-tls/1` (via `TlsAlpnResponder.getMaterial(sni)`). **The library provides the
    certificate + key + store; running the TLS listener that answers the `acme-tls/1` handshake is
    app-side (out of scope).** No system clock: the ephemeral cert uses a fixed wide UTCTime window
    (`tls_alpn_not_before`/`tls_alpn_not_after`). Keygen takes randomness from the caller (the `io`
    in the order flow; a `std.Random` for the standalone `x509.tlsAlpnCert`) — no `std.crypto.random`.
- **ES256 JWS** signs every ACME request (JWK for new-account, then the account `kid`); the replay
  nonce threads from each response's `Replay-Nonce`.
- Threadsafe; account key + order state are caller-held. All crypto is `std.crypto` — no bespoke
  ASN.1/crypto beyond std's `Certificate`/ECDSA. Key/cert PEM I/O covers RFC 5915 `EC PRIVATE KEY`
  (no PKCS#8).

## Threat model / out of scope
- **Account-key custody is the security boundary** — whoever holds the ES256 account key controls
  the ACME account; the module does not store or protect it (caller's job, no zeroization).
- HTTP-01 proves control of port 80 for the domain; TLS-ALPN-01 proves control of port 443. A caller
  serving either proof on an attacker-influenced host would mis-issue — the caller must only run this
  for domains it controls.
- Replay-nonce handling follows the RFC; the CA enforces anti-replay.
- Out of scope: DNS-01 challenge, wildcard certs (need DNS-01), certificate storage/rotation
  scheduling, OCSP, and **running the TLS listener** — for TLS-ALPN-01 the caller must serve the
  validation cert from `TlsAlpnResponder` under ALPN `acme-tls/1` (BYO-TLS `http` seam or a proxy);
  for HTTP-01 the caller runs the port-80 `http.Server`. RSA account keys not supported (ES256 only).

## Verification
`zig build test-acme` — all offline + loopback, no real CA ever contacted. Offline units:
ES256 KAT (RFC 7515 A.3), JWK thumbprint (RFC 7638 §3.1), key-authorization computation, **RFC 8737
acmeIdentifier = SHA-256(keyAuthorization) against a hand-computed oracle**, base64url vectors, JWS
sign→verify round-trips (jwk + kid, tampering fails), CSR DER build→parse-back (SANs + self-signature,
cross-checked with `openssl req -verify`), **TLS-ALPN-01 validation-cert build: byte-exact
`id-pe-acmeIdentifier` extension (OID + critical + double-`OCTET STRING` wrap per RFC 8737 §3) + dNSName
SAN + self-signature verified over the TBSCertificate + deterministic rebuild**, `TlsAlpnResponder`
store set/getMaterial/remove semantics, `parseAuthz` tls-alpn-01 selection + identifier capture,
PEM/EC-key round-trips against openssl fixtures, `certNotAfter`/`needsRenewal` boundaries, challenge
responder over the socket-free server codec. Mock-ACME integration (HTTP-01): a fake CA on
`http.Server`+`router` serves the full RFC 8555 state machine on loopback while the real `Client`
drives it — the mock verifies every JWS signature, enforces one-time nonce freshness, injects a
`badNonce` rejection to prove the retry, fetches the key authorization over real HTTP, and
parses+verifies the CSR before issuing the fixture chain. Skips only if the loopback bind fails. The
TLS-ALPN-01 extension encoding is asserted structurally + self-verified (labeled **constructed** — not
cross-checked against a live `acme-tls/1` handshake, since running the TLS listener is out of scope);
the E2E `acme-tls/1` handshake against a CA is app/ianic territory.

## Backlog / deferred
Reviewed 2026-07-10 (adversarial security pass) — clean: JWS/ES256/nonce/CSR construction and the
ACME v2 (RFC 8555) replay/downgrade paths all confirmed correct. A manual staging/production recipe
(real domain, port 80) is documented in README but is out of CI scope by design.

## Status
`gap · any · client · threadsafe` + deps `http`, `router`, `std.crypto` (ECDSA P-256, `Certificate`),
`std.json` — canonical source is `pub const meta` in src/root.zig.
