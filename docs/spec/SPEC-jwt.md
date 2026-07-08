# SPEC — `jwt`

**Purpose** — A JWT/JWS validator for OAuth2/OIDC **resource servers**: turn an incoming
`Authorization: Bearer <token>` into a verified identity, or reject it. Compact-serialization
parsing → registered-claims validation → signature verification → (optionally) networked JWKS/OIDC
key discovery → a `router` middleware that guards routes. Verification only — this is not a token
*issuer*.

**Model after / Seed** — clean-room from the JOSE/OAuth2 RFCs (7515 JWS, 7519 JWT, 7517 JWK/JWKS,
7518 JWA, 8037 EdDSA-in-JOSE, 8017 PKCS#1 v2.2, 8725 JWT BCP, OIDC Discovery 1.0 / RFC 8414, 6750
Bearer). Greenfield. No third-party JWT library source (jose / jsonwebtoken / golang-jwt) consulted;
signatures use `std.crypto` (RSA via `std.crypto.Certificate.rsa` PKCS1-v1_5 over `std.crypto.ff`).

**Design & invariants**
- **Layered, offline core first:** parse+claims (P1) → HS/ES/EdDSA verify (P2) → RS256/384/512 (P3)
  → JWKS by-`kid` (P4) → networked `Provider` = OIDC discovery + JWKS fetch + cache (P5) →
  `ResourceServer` `router` middleware (P6). The offline core (P1–P4) has no I/O and no `http` dep
  in its hot path; only the `Provider`/`HttpFetcher` reach the network, behind a `Fetcher` seam.
- **std-only crypto:** `std.base64.url_safe_no_pad`, `std.json`, `std.crypto` — no bespoke crypto.
- **Concurrency:** reentrant **except** `Provider` (one mutable key cache) — the caller injects a
  lock (`ResourceServer.lock`) under a threaded server; the clock is injected too (testable expiry).

**Threat model / out of scope** — This is the security core; the defenses are the point:
- **Algorithm confusion (RFC 8725):** `alg` is never trusted from the token to pick a key *class* —
  `none` is rejected; an HMAC `alg` can never verify against an asymmetric key (no RS/ES→HS
  downgrade); the expected algorithm/key type is fixed by the verifier, not the attacker.
- **JWKS smuggling:** key selection is by `kid` against the *trusted* key set; an embedded `jwk`/
  `jku`/`x5u` in the token header is ignored — keys come only from the configured JWKS/Provider.
- **Claims:** `exp`/`nbf`/`iat` validated against an injected clock with configurable skew; `iss`/
  `aud` checked; scope enforced by P6 → **403 `insufficient_scope`**, missing/invalid credential →
  **401 `invalid_token`** (RFC 6750 challenge). HMAC compares are constant-time (`std.crypto`).
- **Out of scope:** token *issuance*/signing; encryption (JWE); `x5c` chain validation; revocation
  lists / token introspection (RFC 7662); OIDC ID-token-specific `nonce`/`c_hash` (this is a
  resource-server access-token validator, not an OIDC relying party). Provider trust rests on TLS
  to the issuer (via the `http` client / `Fetcher`).

**Verification** — RFC known-answer vectors transcribed from the RFCs for tests: JWS 7515 A.1
(HS256) / A.2 (RS256) / A.3 (ES256), 8037 A.4 (Ed25519); JWK/JWKS 7517 vectors; plus adversarial
negatives (alg=none, alg-confusion downgrade, kid mismatch, embedded-jwk ignored, expired/nbf,
tampered signature) and Provider cache/rotation/TTL tests behind a scripted fetcher. 60 tests.

**Status** — `gap · any · server · reentrant (Provider: externally synced)` · deps: `http`, `router`.
