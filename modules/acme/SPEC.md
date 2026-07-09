# acme — spec

ACME v2 (RFC 8555) client: account registration, HTTP-01 challenge issuance, and renewal. Usage: see
./README.md. Attribution/provenance: see /NOTICE.

## Design & invariants
- **Flow:** new-nonce → new-account → new-order → HTTP-01 authorization (serve the
  key-authorization token at `/.well-known/acme-challenge/<token>` via a `router` handler) →
  finalize with a CSR → poll → download the certificate chain. Renewal re-runs the order.
- **ES256 JWS** signs every ACME request (JWK for new-account, then the account `kid`); the replay
  nonce threads from each response's `Replay-Nonce`.
- Threadsafe; account key + order state are caller-held. All crypto is `std.crypto` — no bespoke
  ASN.1/crypto beyond std's `Certificate`/ECDSA. Key/cert PEM I/O covers RFC 5915 `EC PRIVATE KEY`
  (no PKCS#8).

## Threat model / out of scope
- **Account-key custody is the security boundary** — whoever holds the ES256 account key controls
  the ACME account; the module does not store or protect it (caller's job, no zeroization).
- HTTP-01 proves control of port 80 for the domain; a caller serving the challenge on an
  attacker-influenced host would mis-issue — the caller must only run this for domains it controls.
- Replay-nonce handling follows the RFC; the CA enforces anti-replay.
- Out of scope: DNS-01 and TLS-ALPN-01 challenges (HTTP-01 only), wildcard certs (need DNS-01),
  certificate storage/rotation scheduling, OCSP, and running the TLS listener (BYO-TLS `http` seam
  or a proxy). RSA account keys not supported (ES256 only).

## Verification
`zig build test-acme` — 25 tests, all offline + loopback, no real CA ever contacted. Offline units:
ES256 KAT (RFC 7515 A.3), JWK thumbprint (RFC 7638 §3.1), key-authorization computation, base64url
vectors, JWS sign→verify round-trips (jwk + kid, tampering fails), CSR DER build→parse-back (SANs +
self-signature, cross-checked with `openssl req -verify`), PEM/EC-key round-trips against openssl
fixtures, `certNotAfter`/`needsRenewal` boundaries, challenge responder over the socket-free server
codec. Mock-ACME integration: a fake CA on `http.Server`+`router` serves the full RFC 8555 state
machine on loopback while the real `Client` drives it — the mock verifies every JWS signature,
enforces one-time nonce freshness, injects a `badNonce` rejection to prove the retry, fetches the
key authorization over real HTTP, and parses+verifies the CSR before issuing the fixture chain.
Skips only if the loopback bind fails.

## Backlog / deferred
Pending pre-public **security/similarity review** (PLAN.md): JWS/CSR review pass, adversarial
multi-agent. A manual staging/production recipe (real domain, port 80) is documented in README but
is out of CI scope by design.

## Status
`gap · any · client · threadsafe` + deps `http`, `router`, `std.crypto` (ECDSA P-256, `Certificate`),
`std.json` — canonical source is `pub const meta` in src/root.zig.
