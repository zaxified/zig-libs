# jwt — spec

Design + threat notes for auditors. Usage: see ./README.md. Attribution/provenance: see /NOTICE.

## Design & invariants

- **Layered, offline core first:** parse+claims (P1) → HS/ES/EdDSA verify (P2) → RS256/384/512
  (P3) → JWKS by-`kid` (P4) → networked `Provider` = OIDC discovery + JWKS fetch + cache (P5) →
  `ResourceServer` `router` middleware **+ framework-agnostic `Guard`** (P6) → OAuth2/OIDC
  relying-party flow (P7). P1–P4 do no I/O
  and have no `http` dep in the hot path; only `Provider`/`HttpFetcher` reach the network, behind a
  `Fetcher` seam. P7 also does no I/O — it builds requests and parses responses; the caller's HTTP
  client sends the request (same seam philosophy as P5's `Fetcher`).
- **std-only crypto:** `std.base64.url_safe_no_pad`, `std.json`, `std.crypto` (RSA via
  `std.crypto.Certificate.rsa` PKCS1-v1_5 over `std.crypto.ff`) — no bespoke crypto. Modeled after
  the JOSE/OAuth2 RFCs (7515/7519/7517/7518/8037/8017/8725, OIDC Discovery/RFC 8414, RFC 6750, RFC
  6749, RFC 7636); see NOTICE for full citation list.
- **Concurrency:** reentrant except `Provider` (one mutable key cache) — the caller injects a lock
  (`ResourceServer.lock`) under a threaded server; the clock is injected too (testable expiry).
- **No hidden RNG (P7):** `pkceGenerateS256`/`pkceGeneratePlain`/`generateState`/`generateNonce`
  all take a caller-supplied `std.Random` — the same injected-seam rule as the caller-supplied
  clock, and required because std 0.16 removed `std.crypto.random` (mirrors the `jwe` sibling's
  `std.Random` parameter). Production callers must pass a real CSPRNG
  (`std.Random.DefaultCsprng` seeded from OS entropy); tests use a deterministic one.
- **P7 reuses, never duplicates, P1–P5:** `acceptIdToken`/`acceptIdTokenJwks`/
  `acceptIdTokenProvider` call straight into `parseAndVerify`/`parseVerifyJwks`/`Provider.verify`
  for parsing, signature verification and `iss`/`aud`/`exp`/`nbf` — the OIDC-specific `azp`/`nonce`
  checks are the only new logic, layered on top of the returned `ParsedToken`.

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
- **Resource-server surface (P6):** two entry points over the *same* `Provider.verify` — no
  crypto is duplicated. `ResourceServer` is the `router`-native middleware (attaches a borrowed
  `Identity` to `ctx.data`). `Guard` is the framework-agnostic form: `authenticate(req)` returns an
  owned `AuthContext` (principal = `sub`/`claims`/scopes) or a structured `AuthError`
  (`MissingToken`/`InvalidToken` → 401, `InsufficientScope` → 403, `OutOfMemory` → 500 via
  `authStatus`); `challengeFor` yields the precomputed `WWW-Authenticate` value. Both build their
  challenge strings with the public `writeBearerChallenge` helper (RFC 6750 §3 formatting).
- **Scope model:** granted scopes are read from BOTH the space-delimited `scope` string (RFC 6749
  §3.3 / RFC 8693, the form RFC 9068 §2.2.3 uses) and the `scp` claim (JSON-array or space-string,
  RFC 9068 examples / Microsoft-identity). Standalone helpers `scopeGranted` /
  `requireScope` / `requireAllScopes` / `requireAnyScope` operate on a `Claims`; `Guard` /
  `ResourceServer` enforce a conjunction via `required_scopes`.
- **RFC 9068 `at+jwt` typ (optional):** `Guard.require_at_jwt_typ` enforces the access-token JOSE
  header `typ` = `at+jwt` (or `application/at+jwt`, case-insensitive). Off by default — many issuers
  still omit it — so it is a conscious opt-in, not a silent gate.
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
  lists / token introspection (RFC 7662); `c_hash`/`at_hash` (implicit/hybrid-flow-only checks —
  P7 covers the authorization *code* flow, where they do not apply). Provider trust rests on TLS to
  the issuer (via the `http` client / `Fetcher`); P7's `TokenRequest`/`buildAuthorizationUrl` carry
  no transport of their own, so the same TLS-to-issuer assumption applies to whatever HTTP client
  the caller sends them with.
- **PKCE is mandatory in the P7 API surface, not optional-by-omission:** every
  `AuthorizationRequest`/`TokenRequestParams` field for `code_challenge`/`code_verifier` is
  required (no default) — there is no code path that builds a code-flow request without PKCE. S256
  (`pkceGenerateS256`) is the constructor callers reach for; `plain` (`pkceGeneratePlain`) exists
  only for a non-conformant AS and is documented DISCOURAGED (RFC 7636 §4.2: `plain`'s guarantee is
  materially weaker — it only defeats a code interception that does not also observe the identical
  challenge).
- **`nonce` is mandatory and checked byte-for-byte, RFC 8725 §3.9-style safe-by-default:**
  `IdTokenOptions.nonce`/`IdTokenProviderOptions.nonce` are required fields (no default, no `.any`
  opt-out — unlike `Options.issuer`/`.audience` elsewhere, an OIDC RP has no legitimate reason to
  skip nonce checking). A token with no `nonce` claim is rejected (`MissingNonce`), and a
  cryptographically valid token with the WRONG `nonce` is rejected (`NonceMismatch`) — this is what
  stops replay/injection of an ID Token minted for a different authentication attempt. Verified by
  a positive-control test: a token that `verify()` accepts on its own is still rejected by
  `acceptIdToken` when the nonce differs.
- **`azp` enforced only when `aud` is ambiguous (OIDC Core §3.1.3.7 steps 3-4):** a single-audience
  token needs no `azp` (the mandatory `aud` check already pins it to this RP); a multi-audience
  token without a matching `azp` is rejected (`AzpMismatch`) — an OP is not trusted to imply which
  of several audiences actually authorized the token.
- **Discovery `authorization_endpoint`/`token_endpoint` are additive, not required:** `Metadata`
  gained these two optional fields for P7; a discovery document from an issuer that only ever
  served this module's original resource-server (P5) scope, and never populated them, still parses
  unchanged — only a wrong JSON *type* (not absence) is an error, matching
  `id_token_signing_alg_values_supported`'s existing rule.

## Verification

RFC known-answer vectors transcribed from the RFCs: JWS 7515 A.1 (HS256) / A.2 (RS256) / A.3
(ES256), 8037 A.4 (Ed25519); JWK/JWKS 7517 vectors; PKCE RFC 7636 Appendix B (S256 challenge,
byte-exact); plus adversarial negatives (alg=none, alg-confusion downgrade, kid mismatch,
embedded-jwk ignored, expired/nbf, tampered signature, mandatory-audience confused-deputy
rejection, oct-from-network refusal, ID-token nonce-mismatch positive control, azp/iss/aud/exp
rejection) and Provider cache/rotation/TTL tests behind a scripted fetcher. The P6 resource-server
guard adds self-constructed policy tests (own signer, not external interop KATs — the correct
approach for policy logic): `Guard.authenticate` valid/missing/garbage/expired/insufficient/
alg=none/RS→HS-confusion decisions, RFC 9068 `at+jwt` typ on/off, `scope`+`scp` scope helpers
(single/all/any), and `writeBearerChallenge` header formatting. 82 tests. Run: `zig build test-jwt`.

## Backlog / deferred

- **Mandatory audience/issuer + oct-from-network** were flagged as open decisions in the pre-public
  review — now **RESOLVED** (safe-by-default, 2026-07-09; see Threat model above). The repo-wide
  adversarial security pass (2026-07-10) confirmed the rest: const-time compare, alg-confusion
  resistance, and JWKS `kid`-smuggling/rotation correctness are all clean for `jwt`; the paired
  `aaa-gate` throttle-key amplification issue found in that pass was fixed.
- **DPoP (RFC 9449)** — DEFERRED. Proof-of-possession access tokens need client-held key
  management (generate/persist a signing key per client) and a per-request DPoP proof JWT (bound to
  the HTTP method+URL+access-token hash, with replay-window `jti`/`iat` tracking on the resource
  server) — a materially bigger, separable feature from the authorization-code+PKCE flow this pass
  adds. `ResourceServer`'s Bearer-only enforcement is unaffected; a future pass would add a DPoP
  variant alongside it, not replace it.
- **`client_secret_basic` (HTTP Basic client auth)** — DEFERRED at the builder level:
  `buildTokenRequest`'s `ClientAuth` covers the public-client (PKCE-only) and
  `client_secret_post` cases; a confidential client wanting Basic auth sets the `Authorization`
  header on the returned `TokenRequest` itself (one `base64(client_id:client_secret)` line at the
  call site) — not worth a builder-side seam for a single header.
- **OAuth2 error-response parsing (RFC 6749 §5.2)** — DEFERRED: `parseTokenResponse` assumes a
  200-status success body; a non-200 response's `{"error": …}` shape is a caller concern (check the
  HTTP status before parsing) rather than a second typed parser this pass adds.
- No other module-local backlog recorded (README has no Deferred section).

## Status

`gap · any · both · reentrant (Provider: externally synced)` + deps `http`, `router` — canonical
source is `pub const meta` in src/root.zig.
