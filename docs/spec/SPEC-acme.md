# SPEC — `acme`

**Purpose** — Obtain and renew TLS certificates from Let's Encrypt / any ACME v2 CA (RFC 8555):
account registration, HTTP-01 challenge issuance, and renewal, producing a key + certificate the
BYO-TLS `http` deployment (or a proxy) can serve. Closes the "get a real cert without certbot" gap.

**Model after / Seed** — golang.org/x/crypto/acme + certbot flow semantics; wire per RFC 8555
(ACME), RFC 7515 (JWS), RFC 7638 (JWK thumbprint). Greenfield. Signatures + CSR via `std.crypto`
(ECDSA P-256, `Certificate`); JSON via `std.json`; transport via the `http` client. See NOTICE.

**Design & invariants**
- **Flow:** new-nonce → new-account → new-order → HTTP-01 authorization (serve the key-authorization
  token at `/.well-known/acme-challenge/<token>` via a `router` handler) → finalize with a CSR →
  poll → download the certificate chain. Renewal re-runs the order.
- **ES256 JWS** signs every ACME request (JWK for new-account, then the account `kid`); the
  replay nonce is threaded from each response's `Replay-Nonce`.
- Threadsafe; the account key + order state are caller-held. All crypto is `std.crypto` — no bespoke
  ASN.1/crypto beyond std's `Certificate`/ECDSA.

**Threat model / out of scope**
- **Account-key custody is the security boundary** — whoever holds the ES256 account key controls
  the ACME account; the module does not store or protect it (caller's job, no zeroization).
- HTTP-01 proves control of port 80 for the domain; a caller serving the challenge on an
  attacker-influenced host would mis-issue — the caller must only run this for domains it controls.
- Replay-nonce handling follows the RFC; the CA enforces anti-replay.
- **Out of scope:** DNS-01 and TLS-ALPN-01 challenges (HTTP-01 only), wildcard certs (need DNS-01),
  certificate *storage*/rotation scheduling, OCSP, and running the TLS listener (that's the
  BYO-TLS `http` seam / a proxy). RSA account keys not supported (ES256 only).

**Verification** — Offline tests against a scripted ACME transport: JWS/JWK-thumbprint KATs, the
directory→nonce→account→order→finalize sequence, HTTP-01 key-authorization computation, CSR shape,
and error/poll handling. 25 tests.

**Status** — `gap · any · client · threadsafe` · deps: `http`, `router` (+ `std.crypto`, `std.json`).
