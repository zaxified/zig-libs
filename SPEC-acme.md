# SPEC — `acme`

ACME v2 (RFC 8555) client — automated Let's Encrypt certificate issuance + renewal over HTTP,
using the HTTP-01 challenge. Direct-HTTPS story (T5.12). `gap · any · client · tsafe`. Model after:
`certbot` / Go `golang.org/x/crypto/acme` / Caddy's ACME. Deps: `http`, `router` (challenge
responder), uses `std.crypto` (ecdsa P-256, Certificate) + `std.json`. New `build.zig` entry
`.{ .name = "acme", .deps = &.{ "http", "router" } }`.

## Why

For a directly-internet-facing server we want automatic HTTPS: obtain and renew a real Let's Encrypt
certificate with no manual steps. This is the provisioning half (the cert then feeds a TLS server —
separate task). ACME is pure HTTP+JSON+crypto, so it's buildable on our `http` client now.

## Scope

1. **ACME protocol flow (RFC 8555):** directory fetch; nonce management (`newNonce` + `Replay-Nonce`
   header tracking); **account** (`newAccount`, ES256 account key, terms-of-service agreement);
   **order** (`newOrder` for one or more DNS identifiers); fetch authorizations; **HTTP-01
   challenge** (compute the key authorization = `token + "." + base64url(JWK thumbprint)`, serve it,
   POST the challenge to tell the CA to validate); poll authorization/order status; **finalize** with
   a CSR; download the issued certificate chain (PEM).
2. **JWS signing (ES256):** every ACME POST is a JWS (flattened JSON) signed by the account key
   (`std.crypto.sign.ecdsa` P-256 / SHA-256); protected header carries `alg`, `nonce`, `url`, and
   `jwk` (newAccount) or `kid` (account URL, thereafter). Base64url everywhere. JWK thumbprint per
   RFC 7638.
3. **HTTP-01 challenge responder:** a `router` handler / middleware serving
   `GET /.well-known/acme-challenge/<token>` → the key authorization, wired to the running
   `http.Server` (so the CA can reach it). Token→keyauth map is set by the order flow.
4. **CSR + keys:** generate the certificate key (P-256) and a **PKCS#10 CSR** (DER — the ASN.1
   encoding is the fiddly part; write a minimal encoder for the CSR structure) with the domain(s) as
   SAN. PEM read/write for account key, cert key, and the issued chain.
5. **Client + renewal:** `Client.obtain(domains)` runs the whole flow → cert chain + key; a helper to
   check a cert's `notAfter` and decide renewal (e.g. renew < 30 days left). Staging + production
   directory URLs (default **staging** for safety — document loudly).

## Public API sketch (final shape your call)

```zig
pub const Client = struct {
    pub fn init(io, gpa, Options) Client;   // Options: directory_url (staging default), account_key, http_client
    pub fn register(self) !void;            // newAccount (idempotent)
    pub fn obtain(self, domains: []const []const u8) !Certificate;  // full order→finalize→download
    pub fn challengeResponder(self) router.Handler;  // serves /.well-known/acme-challenge/*
};
pub fn needsRenewal(cert_pem: []const u8, now_unix: i64, within_days: u32) bool;
```

## Acceptance / verification

- **Offline unit tests (deterministic, NO real CA):** ES256 JWS sign → verify round-trip + a known
  test vector; JWK thumbprint (RFC 7638 example vector); key-authorization computation; base64url;
  CSR DER structure (parse it back / check the ASN.1 SEQUENCE + SAN + signature validates); PEM
  read/write round-trip; `needsRenewal` boundary.
- **Mock-ACME integration (dogfood — must NOT skip normally):** stand up a **fake ACME server on
  `http.Server`/loopback** that serves canned `directory`/`newNonce`/`newAccount`/`newOrder`/
  challenge/finalize/cert responses per RFC 8555, and drive the real `acme.Client` against it with
  our `http.Client`; assert the client sends well-formed JWS (verify the signature server-side),
  follows the state machine, serves the challenge token via the responder, and ends with the mock
  cert. This proves the whole flow without a real domain/CA.
- `zig build test-acme` + `zig build test` (all) green, Debug + ReleaseFast; `zig fmt --check` clean.
- **Note:** a real Let's Encrypt **staging** end-to-end needs a public domain + inbound :80 — out of
  scope for CI; leave a documented manual recipe. Do NOT hit the real/staging CA from tests.

## Notes for the implementer

- Use the **zig skill** (std.crypto.sign.ecdsa EcdsaP256Sha256, std.crypto.Certificate, std.json,
  std.base64 url-safe no-pad, std.crypto.hash.sha2). Reuse `http.Client` for all ACME requests and
  `router`/`http.Server` for the challenge responder — do NOT reinvent HTTP.
- The CSR/ASN.1 DER encoder is the trickiest bit — keep it minimal (just PKCS#10 with SAN) and test
  by parsing it back. Nonce handling must be robust (every response may carry a fresh `Replay-Nonce`).
- Default to the **staging** directory; make production an explicit opt-in (avoid rate-limit/lockout).
- SPDX header + a `Provenance:` line (clean-room; design refs x/crypto/acme BSD-3 / certbot Apache-2.0
  / RFC 8555 — behavior only, no code copied).
