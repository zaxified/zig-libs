# jwt — spec

Design + threat notes for auditors. Usage: see ./README.md. Attribution/provenance: see /NOTICE.

## Design & invariants

- **Layered, offline core first:** parse+claims (P1) → HS/ES/EdDSA verify (P2) → RS256/384/512
  (P3) → JWKS by-`kid` (P4) → networked `Provider` = OIDC discovery + JWKS fetch + cache (P5) →
  `ResourceServer` `router` middleware (P6). P1–P4 do no I/O and have no `http` dep in the hot
  path; only `Provider`/`HttpFetcher` reach the network, behind a `Fetcher` seam.
- **std-only crypto:** `std.base64.url_safe_no_pad`, `std.json`, `std.crypto` (RSA via
  `std.crypto.Certificate.rsa` PKCS1-v1_5 over `std.crypto.ff`) — no bespoke crypto. Modeled after
  the JOSE/OAuth2 RFCs (7515/7519/7517/7518/8037/8017/8725, OIDC Discovery/RFC 8414, RFC 6750); see
  NOTICE for full citation list.
- **Concurrency:** reentrant except `Provider` (one mutable key cache) — the caller injects a lock
  (`ResourceServer.lock`) under a threaded server; the clock is injected too (testable expiry).

## Threat model / out of scope

This is the security core; the defenses are the point:
- **Algorithm confusion (RFC 8725):** `alg` is never trusted from the token to pick a key *class* —
  `none` is rejected; an HMAC `alg` can never verify against an asymmetric key (no RS/ES→HS
  downgrade); the expected algorithm/key type is fixed by the verifier, not the attacker.
- **JWKS smuggling:** key selection is by `kid` against the *trusted* key set; an embedded `jwk`/
  `jku`/`x5u` in the token header is ignored — keys come only from the configured JWKS/Provider.
- **Claims:** `exp`/`nbf`/`iat` validated against an injected clock with configurable skew; scope
  enforced by P6 → 403 `insufficient_scope`, missing/invalid credential → 401 `invalid_token`
  (RFC 6750 challenge). HMAC compares are constant-time (`std.crypto`).
- **Mandatory audience/issuer — confused deputy (RFC 8725 §3.9), FIXED 2026-07-09:** `iss` and
  `aud` validation are safe-by-default and cannot be skipped by omission. `Options.issuer`/
  `Options.audience` are typed unions (`IssuerPolicy`/`AudiencePolicy`) with **no default** —
  the caller must write `.{ .required = "…" }` (must match) or the explicit, greppable `.any`
  (conscious opt-out). `Provider.ClaimOptions.audience` is likewise mandatory; its `.issuer`
  defaults to `.provider` (enforce the discovered/configured issuer) and a jwks_uri-only provider
  with no configured issuer **fails closed** (`IssuerNotConfigured`) rather than silently skipping.
  Previously a same-IdP token minted for a *different* service was accepted unless the operator
  opted in — the classic confused-deputy hole.
- **Symmetric key from a fetched JWKS (RFC 8725 §3.5 / §2.1), FIXED 2026-07-09:** a network-fetched
  JWKS (`fetchJwks`/`Provider`) **refuses** `kty:"oct"` keys (`JwkSkipReason.oct_from_network`) — a
  published JWKS is attacker-readable, so a symmetric key there would let anyone forge HS\* tokens.
  Symmetric keys are trusted only from a locally-configured `parseJwks` set.
- **Out of scope:** token *issuance*/signing; encryption (JWE); `x5c` chain validation; revocation
  lists / token introspection (RFC 7662); OIDC ID-token-specific `nonce`/`c_hash` (this is a
  resource-server access-token validator, not an OIDC relying party). Provider trust rests on TLS
  to the issuer (via the `http` client / `Fetcher`).

## Verification

RFC known-answer vectors transcribed from the RFCs: JWS 7515 A.1 (HS256) / A.2 (RS256) / A.3
(ES256), 8037 A.4 (Ed25519); JWK/JWKS 7517 vectors; plus adversarial negatives (alg=none,
alg-confusion downgrade, kid mismatch, embedded-jwk ignored, expired/nbf, tampered signature,
mandatory-audience confused-deputy rejection, oct-from-network refusal) and Provider
cache/rotation/TTL tests behind a scripted fetcher. 61 tests. Run: `zig build test-jwt`.

## Backlog / deferred

- **Mandatory audience/issuer + oct-from-network** were flagged as open decisions in the pre-public
  review — now **RESOLVED** (safe-by-default, 2026-07-09; see Threat model above). The repo-wide
  adversarial security pass (2026-07-10) confirmed the rest: const-time compare, alg-confusion
  resistance, and JWKS `kid`-smuggling/rotation correctness are all clean for `jwt`; the paired
  `aaa-gate` throttle-key amplification issue found in that pass was fixed.
- No other module-local backlog recorded (README has no Deferred section).

## Status

`gap · any · server · reentrant (Provider: externally synced)` + deps `http`, `router` — canonical
source is `pub const meta` in src/root.zig.
