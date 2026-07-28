# jwt

A JWT/JWS toolkit for OAuth2/OIDC — both a resource-server token *validator*
and an OIDC *relying party* (RP). The validator side: compact-serialization
parsing (RFC 7515 §3.1) into typed models, registered-claims validation
(RFC 7519 §4.1), JWS signature verification (RFC 7515 §5.2 + RFC 7518)
for **HS256/384/512** (HMAC-SHA-2), **ES256/ES384** (ECDSA P-256/P-384),
**EdDSA** (Ed25519, RFC 8037) and **RS256/384/512** (RSASSA-PKCS1-v1_5,
RFC 8017 — the OIDC default), and **JWKS key sets** (RFC 7517): parse a
`{"keys":[…]}` document into a typed `JwkSet`, select the key by the token
header's `kid`, verify via `verifyWithJwks`/`parseVerifyJwks`. The signature
core is std-only — `std.base64.url_safe_no_pad` for the segments, `std.json`
for header/payload/JWKS, `std.crypto` for the signatures (RSA via
`std.crypto.Certificate.rsa`'s PKCS1-v1_5 verify over `std.crypto.ff`
modexp).

On top of the offline core sit two turnkey layers: the **networked
`Provider`** (P5) — OpenID Connect Discovery 1.0 (`<issuer>/.well-known/
openid-configuration` → `jwks_uri`), JWKS fetch through a `Fetcher` seam
(`HttpFetcher` adapts the `http` client), and a cache with TTL + key-rotation
refresh — whose `Provider.verify` is the one-call resource-server check; and
the **`ResourceServer` `router` middleware** (P6, RFC 6750) that reads
`Authorization: Bearer <token>`, runs `Provider.verify`, and either attaches a
verified `Identity` to the request (`identityOf(ctx)`) or short-circuits with
the Bearer challenge — **401** `error="invalid_token"` (bare `Bearer` when no
credential is presented) or **403** `error="insufficient_scope"`. For hosts
that don't use `router`, P6 also ships **`Guard`** — the same RFC 6750
enforcement as a framework-agnostic `authenticate(req)` call that returns an
owned `AuthContext` or a structured `AuthError` (with `authStatus`/
`writeBearerChallenge` for the caller to render its own 401/403), plus
`scopeGranted`/`requireScope`/`requireAllScopes`/`requireAnyScope` and
optional RFC 9068 `at+jwt` `typ` enforcement.

The **RP flow** (P7) is the mirror image — this module is also an OAuth2/OIDC
*client*: **PKCE** (RFC 7636 — `pkceGenerateS256`/`pkceGeneratePlain`/
`pkceChallengeS256`), CSRF `state` + OIDC `nonce` generation
(`generateState`/`generateNonce`), the authorization-request URL builder
(`buildAuthorizationUrl`), the authorization-code token-exchange request
builder (`buildTokenRequest` — this module does no I/O; it returns
method/url/headers/body for your HTTP client) + response parser
(`parseTokenResponse`), and ID-token RP-side acceptance
(`acceptIdToken`/`acceptIdTokenJwks`/`acceptIdTokenProvider`, OIDC Core
§3.1.3.7: `iss`/`aud`/`azp`/`exp`/`nbf` + mandatory `nonce` match) — all
layered on the SAME `verify`/`Provider` machinery above, no duplicated
crypto. DPoP (RFC 9449) is a documented DEFER (see SPEC.md).

Provenance: clean-room from RFC 7515 (JWS), RFC 7517 (JWK), RFC 7519 (JWT),
RFC 7518 (JWA), RFC 8037 (EdDSA in JOSE), RFC 8017 (PKCS #1 v2.2), RFC 8725
(JWT Best Current Practices), OpenID Connect Discovery 1.0 / RFC 8414 (issuer
metadata, `Provider`), RFC 6750 (Bearer resource-server middleware), RFC 6749
(OAuth 2.0) and RFC 7636 (PKCE). No third-party JWT source consulted or
copied.

- **Model after:** RFC 7515 (JWS) + RFC 7519 (JWT) + RFC 7518 (JWA) verify
  incl. RS256 (RSASSA-PKCS1-v1_5, RFC 8017) + RFC 7517 (JWK/JWKS key sets),
  RFC 8725 hardening + OpenID Connect Discovery 1.0 / RFC 8414 (`Provider`) +
  RFC 6750 Bearer middleware; RFC 7636 PKCE + OIDC Core 1.0 §3.1 authorization
  code flow + §3.1.3.7 ID Token validation; OAuth2/OIDC resource server AND
  relying party.
- **Platform:** any. **Role:** both — server (P6's `router` middleware
  guarding routes) and client (P7's RP flow builds auth/token requests and
  accepts ID Tokens); the offline core is pure logic either way.
  **Concurrency:** reentrant — the offline core has no shared state (each
  `ParsedToken`/`JwkSet` owns its arena; a `JwkSet` is immutable after parse),
  **except `Provider`**, which holds one mutable JWKS cache and needs external
  sync under a threaded server — inject `ResourceServer.lock` (see its docs).
- **Deps:** `http` (the `HttpFetcher` + the middleware's request/response
  types, and P7's `TokenRequest.method`), `router` (the middleware), `p256`
  (the fast ES256 curve — byte-exact to `std.crypto.sign.ecdsa.EcdsaP256Sha256`).
  The signature core and P7's request/response builders need neither `http`
  nor `router`.

## SECURITY

`parse()` alone does **not** verify signatures — a `ParsedToken` is
**untrusted, attacker-controlled input** until `verify(parsed, key)` (or
the all-in-one `parseAndVerify`) has run; anyone can mint a syntactically
valid token with any claims, and passing `validateClaims` does not change
that. Never authorize from a `ParsedToken` alone.

`verify` implements the RFC 8725 hardening rules:

- **`alg: "none"` is always rejected** (`UnsecuredToken`), key or no key.
- **The token's `alg` must match the provided key's type**
  (`AlgKeyMismatch`) — an HS token offered an EC/Ed public key refuses
  *before any MAC math*, which blocks the classic RS/ES→HS downgrade where
  an attacker HMACs a forged token with the server's *public* key bytes.
  The wrong curve within a family (ES256 vs a P-384 key) also refuses.
- **HMAC comparison is constant-time** (`std.crypto.timing_safe.eql`).
- **JWS ECDSA signatures are the raw fixed-width `R‖S`** (RFC 7518 §3.4;
  32+32 for P-256, 48+48 for P-384) — not DER.
- **RS\* signatures must be exactly the modulus length** (RFC 7518 §3.3);
  the full EMSA-PKCS1-v1_5 encoding (`0x00 01 FF…FF 00 || DigestInfo`) is
  checked, including the SHA-2 OID — wrong length, `s ≥ n`, bad padding or
  a wrong-hash DigestInfo are all `BadSignature`. Keys are validated at
  construction (2048/3072/4096-bit modulus; odd exponent in `[3, 2^32)`).
- Unknown or not-yet-implemented algs (`PS*` — RSA-PSS; ES512 — no P-521
  in std) → `UnsupportedAlg`; wrong-length or garbage signatures →
  `BadSignature`, never a panic.
- **JWKS selection cannot smuggle a mismatched key**: whatever
  `JwkSet.selectKey` resolves still goes through `verify`'s key-type check
  — a token whose `kid` points at the wrong key family gets
  `AlgKeyMismatch`, not a downgrade. Selection itself honors the JWK's
  `use` (only absent or `"sig"` is selectable; `"enc"` and unknown values
  fail closed) and `alg` (when pinned, it must equal the token's `alg`).
  A token without `kid` resolves only against a set with exactly one
  usable key — the module never guesses among keys.

Delivery plan (**all seven done**): P1 parse + claims · P2 signature verify
(HS/ES/EdDSA) · P3 RSA (RS256/384/512) · P4 JWKS key sets · P5 OIDC
discovery + JWKS fetch + caching `Provider` · P6 `ResourceServer` `router`
middleware + framework-agnostic `Guard` · P7 OAuth2/OIDC relying-party flow
(PKCE, state/nonce, authorization-request + token-exchange builders,
ID-token acceptance).

## API

| Item | What |
|---|---|
| `parse(gpa, token) ParseError!ParsedToken` | split → base64url-decode → JSON → typed models; owns copies (one arena), input may be freed immediately |
| `ParsedToken` | `header`, `claims`, `signing_input`, `signature` (raw bytes), `alg` (typed enum) + `deinit()` |
| `Header` | `alg` (required), `typ`/`kid`/`cty` (optional) |
| `Claims` | `iss`/`sub`/`aud`/`exp`/`nbf`/`iat`/`jti` + `raw` payload; `claim`/`claimStr`/`claimInt`/`claimBool` getters for custom claims (`scope`, …) |
| `Audience` | `none` \| `single` \| `many` — the parsed `aud` (string OR array), with `contains()` |
| `AudiencePolicy` / `IssuerPolicy` | mandatory-choice unions for `Options`: `.{ .required = "…" }` (must match) \| `.any` (conscious opt-out). No default — see "Mandatory audience/issuer" |
| `validateClaims(claims, Options) ValidateError!void` | RFC 7519 §4.1 checks; pure, allocation-free |
| `Alg` | RFC 7518 names (`HS256`…`EdDSA`, `none`, `unknown`) — the verify dispatch |
| `Key` | tagged union: `.hmac` (secret bytes) \| `.ecdsa_p256` \| `.ecdsa_p384` \| `.ed25519` (std public keys) \| `.rsa` (`RsaPublicKey`); constructors `ecdsaP256FromCoords(x, y)` / `ecdsaP384FromCoords(x, y)` / `ed25519FromBytes(x)` / `rsaFromModExp(n, e)` take exactly a JWK's decoded parameters (`KeyError.InvalidKey` on bad points/moduli/exponents) |
| `verify(&parsed, key) VerifyError!void` | recompute/check the signature over `signing_input`; RFC 8725 defenses baked in |
| `parseAndVerify(gpa, token, key, Options) !ParsedToken` | the one-call API: parse → verify → validateClaims; frees on any failure |
| `parseJwks(gpa, json) JwksError!JwkSet` | parse an RFC 7517 `{"keys":[…]}` document; per-JWK problems skip that key (recorded in `skipped`), only a non-JWKS document errors |
| `JwkSet` | `keys: []const Jwk` (converted, usable) + `skipped: []const SkippedJwk` (index + `JwkSkipReason`) + `deinit()`; one arena owns everything |
| `Jwk` | `key: Key` + selection metadata: `kid`, `use` (`sig`/`enc`/`other`), `alg` (pinned `Alg`) |
| `JwkSet.keyForKid(kid) ?ResolvedKey` | first sig-usable key with that `kid` (no alg context) |
| `JwkSet.selectKey(header) ?ResolvedKey` | header-aware selection: by `kid` (honoring `use` + pinned `alg`), or the single usable key when the token has no `kid` |
| `verifyWithJwks(&parsed, jwks) VerifyError!void` | `selectKey` → `verify`; no usable key → `NoMatchingKey` |
| `parseVerifyJwks(gpa, token, jwks, Options) !ParsedToken` | the one-call JWKS API: parse → resolve by `kid` + verify → validateClaims |
| `Fetcher` / `HttpFetcher` | GET-a-URL seam (offline-testable); `HttpFetcher` adapts `http.Client` |
| `discover(gpa, fetcher, issuer) !Metadata` · `fetchJwks(gpa, fetcher, url) !JwkSet` | OIDC discovery + JWKS fetch |
| `Provider.init(gpa, fetcher, .{issuer OR jwks_uri, ttl_s, min_refresh_interval_s})` | cached, rotation-aware key source |
| `Provider.verify(gpa, token, now_s, ClaimOptions) !ParsedToken` | turnkey: lazy-load/TTL-refresh JWKS, resolve `kid` (one rate-limited refresh on rotation), verify + validateClaims. `ClaimOptions.audience` REQUIRED; `.issuer` = `IssuerCheck` (default `.provider` = enforce discovered/configured issuer, else `IssuerNotConfigured`) |
| `ResourceServer.init(gpa, Options) !ResourceServer` (+ `deinit`) | build the `router` middleware; `Options`: `provider`, `claim_opts`, `required_scopes`, `protect` (`all`/`mutations`), `clock`, `lock`, `realm` |
| `ResourceServer.middleware() router.Middleware` | register before routes; verifies each request's Bearer token |
| `identityOf(ctx) ?*Identity` | the attached identity — `subject()`, `claims()`, `scopes()` (RFC 6749 space-split), `hasScope()` |
| `Guard.authenticate(req) AuthError!AuthContext` | framework-agnostic RFC 6750 check (no `router` dependency): same `Provider.verify` underneath, returns an owned `AuthContext` or a structured `AuthError` |
| `authStatus(AuthError) u16` / `writeBearerChallenge(...)` | map an `AuthError` to 401/403 and render the matching `WWW-Authenticate: Bearer` challenge, for a host that renders its own responses |
| `scopeGranted` / `requireScope` / `requireAllScopes` / `requireAnyScope` | scope-string / `scp`-array helpers shared by `Guard` and `ResourceServer` |
| `Clock` / `Lock` | injected wall-clock (`.system`) and Provider-serialization seams (`.none` default) |
| `Metadata.authorization_endpoint` / `.token_endpoint` | Discovery's OP endpoints (P7) — optional, so a resource-server-only discovery document (P5's original scope) still parses when it omits them |
| `pkceGenerateS256(random) Pkce` / `pkceGeneratePlain(random) Pkce` | RFC 7636 PKCE pair from a caller-supplied `std.Random` (a real CSPRNG in production); `.plain` is DISCOURAGED — see SPEC.md |
| `pkceChallengeS256(verifier, out)` | derive the S256 `code_challenge` for an externally-supplied `code_verifier` |
| `Pkce.verifier()` / `.challenge()` / `.method` | the generated pair — `verifier()` into the token request, `challenge()`/`method` into the authorization request |
| `generateState(random) [43]u8` / `generateNonce(random) [43]u8` | CSRF `state` (RFC 6749 §10.12) and OIDC `nonce` (Core §3.1.2.1) generators |
| `buildAuthorizationUrl(gpa, authorization_endpoint, AuthorizationRequest) ![]u8` | the full redirect URL (always `response_type=code`); percent-encoded, gpa-owned |
| `buildTokenRequest(gpa, token_endpoint, TokenRequestParams) !TokenRequest` | the code→token exchange request (method/url/content_type/body — no I/O, `+deinit`); `ClientAuth` = `.none` (public/PKCE-only) \| `.client_secret_post` |
| `parseTokenResponse(gpa, json) TokenResponseError!TokenResponse` | parse a 200-status token-endpoint body: `access_token`/`token_type` (required) + `id_token`/`expires_in`/`refresh_token`/`scope` (optional) |
| `acceptIdToken(gpa, id_token, key, IdTokenOptions) IdTokenError!ParsedToken` | RP-side ID Token acceptance (OIDC Core §3.1.3.7) over a direct `Key` — reuses `parseAndVerify`, then enforces `azp` (multi-`aud`) + mandatory `nonce` match |
| `acceptIdTokenJwks(gpa, id_token, jwks, IdTokenOptions) IdTokenError!ParsedToken` | same, over a `JwkSet` — reuses `parseVerifyJwks` |
| `acceptIdTokenProvider(provider, gpa, id_token, now_s, IdTokenProviderOptions) !ParsedToken` | same, over the turnkey `Provider` — reuses `Provider.verify` (issuer enforced automatically) |

`Options`: `now_s` (REQUIRED — caller-supplied seconds since epoch, no
hidden clock, same injected-time rule as `resilience`/`probe`), `leeway_s`
(default 60), `issuer` and `audience` (**both REQUIRED, no default** — see
"Mandatory audience/issuer" below), `require_exp` (default true),
`reject_future_iat` (default false — `iat` is informational per RFC 7519).

### Mandatory audience/issuer (safe by default, RFC 8725 §3.9)

Audience and issuer validation are **not optional and not skippable by
omission** — that closes the confused-deputy foot-gun where a same-IdP token
minted for a *different* service was silently accepted. Both are typed unions
with **no default**, so the caller MUST choose:

- `.issuer` / `.audience` = `.{ .required = "…" }` — the value MUST match
  (`iss` equal / value contained in `aud`), else `IssuerMismatch` /
  `AudienceMismatch`.
- `.issuer` / `.audience` = `.any` — an **explicit, greppable, conscious
  opt-out** of that check. This is the only way to skip validation.

For the turnkey `Provider` / `ResourceServer`, `Provider.ClaimOptions.issuer`
additionally defaults to `.provider` (enforce the discovered/configured
issuer). A **jwks_uri-only** provider that configured no issuer has nothing to
enforce, so `verify` **fails closed** with `IssuerNotConfigured` unless you
pin `.issuer = .{ .required = "…" }` or opt out with `.issuer = .any`.
`audience` has no default anywhere — it is always a conscious choice.

Typed errors, never a panic: `ParseError` = `MalformedToken` ·
`InvalidBase64` · `InvalidJson` · `NotAnObject` · `MissingAlg` ·
`InvalidClaim` · `OutOfMemory`; `ValidateError` = `Expired` · `NotYetValid`
· `IssuedInFuture` · `IssuerMismatch` · `AudienceMismatch` · `MissingExp`;
`VerifyError` = `UnsecuredToken` · `AlgKeyMismatch` · `UnsupportedAlg` ·
`BadSignature` · `InvalidKey` · `NoMatchingKey` (JWKS resolution only);
`JwksError` = `InvalidJson` · `NotAJwks` · `OutOfMemory`. `Provider.verify`
adds `IssuerNotConfigured` (default `.provider` issuer policy on a
jwks_uri-only provider with no configured issuer — fail closed).

`TokenResponseError` = `InvalidJson` · `NotAnObject` · `MissingAccessToken`
· `MissingTokenType` · `InvalidField` · `OutOfMemory` (from
`parseTokenResponse`; a non-200 response is a caller concern — check the
status before parsing). `IdTokenError` = `ParseAndVerifyError` (signature +
claims, from the underlying `verify`/`validateClaims`) plus `AzpMismatch` ·
`MissingNonce` · `NonceMismatch` (from `acceptIdToken`/`acceptIdTokenJwks`/
`acceptIdTokenProvider`'s OIDC-specific checks — see "Mandatory nonce" below).

### Mandatory nonce (RP flow, OIDC Core §3.1.3.7)

Unlike `Options.issuer`/`.audience`, `IdTokenOptions.nonce` /
`IdTokenProviderOptions.nonce` have **no `.any` opt-out** — an OIDC relying
party has no legitimate reason to skip nonce checking, so it is always
enforced: a token with no `nonce` claim is `MissingNonce`; a token whose
`nonce` differs from the one generated for this authorization attempt
(`generateNonce`) is `NonceMismatch` — including a token that is otherwise
**cryptographically valid** (right signature, right `iss`/`aud`). This is the
defense against ID Token replay/injection across separate login attempts.
`azp` is enforced only when `aud` names more than one audience (OIDC Core
§3.1.3.7 steps 3-4) — a single-audience token needs no `azp`.

## Usage

```zig
const jwt = @import("jwt");

// One call: parse → verify signature → validate claims. Issuer and audience
// validation are MANDATORY: pin them with `.required`, or write `.any` to
// consciously opt out. There is no silent skip (RFC 8725 §3.9).
var token = try jwt.parseAndVerify(gpa, bearer_token, .{ .hmac = secret }, .{
    .now_s = now_seconds, // caller-supplied clock
    .issuer = .{ .required = "https://issuer.example" },
    .audience = .{ .required = "api://my-service" },
});
defer token.deinit();
const scope = token.claims.claimStr("scope") orelse "";

// With a JWKS — the issuer's published key set, fetched by the caller
// (Part 5 adds the fetch/cache; this stays offline):
var jwks = try jwt.parseJwks(gpa, jwks_json);
defer jwks.deinit();
var token2 = try jwt.parseVerifyJwks(gpa, bearer_token, jwks, .{
    .now_s = now_seconds,
    .issuer = .{ .required = "https://issuer.example" },
    .audience = .{ .required = "api://my-service" },
});
defer token2.deinit();

// Or step by step — e.g. pick the key from the header's kid first:
var parsed = try jwt.parse(gpa, bearer_token);
defer parsed.deinit();
const jwk = jwks.selectKey(parsed.header) orelse return error.NoMatchingKey;
try jwt.verify(&parsed, jwk.key);
try jwt.validateClaims(parsed.claims, .{
    .now_s = now_seconds,
    .issuer = .{ .required = "https://issuer.example" },
    .audience = .{ .required = "api://my-service" },
});

// P7: the relying-party flow — starting an OIDC login (authorization code +
// PKCE). `random` MUST be a real CSPRNG (std 0.16 removed `std.crypto.random`
// — same caller-injected seam as `jwe`).
var csprng = std.Random.DefaultCsprng.init(seed);
const random = csprng.random();
const pkce = jwt.pkceGenerateS256(random);
const state = jwt.generateState(random);
const nonce = jwt.generateNonce(random);
// persist pkce.verifier(), state and nonce server-side (session/cookie) —
// they're checked back in below.
const auth_url = try jwt.buildAuthorizationUrl(gpa, metadata.authorization_endpoint.?, .{
    .client_id = "my-client-id",
    .redirect_uri = "https://my-app.example/callback",
    .scope = "openid profile email",
    .state = &state,
    .nonce = &nonce,
    .code_challenge = pkce.challenge(),
    .code_challenge_method = pkce.method,
});
defer gpa.free(auth_url);
// redirect the user-agent to `auth_url` …

// … the callback returns `code` (after checking `state` matches what you
// persisted):
var token_req = try jwt.buildTokenRequest(gpa, metadata.token_endpoint.?, .{
    .code = code_from_callback,
    .redirect_uri = "https://my-app.example/callback",
    .client_id = "my-client-id",
    .code_verifier = pkce.verifier(),
});
defer token_req.deinit(gpa);
// send `token_req` (method/url/content_type/body) with your own HTTP client —
// this module does no I/O.
var token_resp = try jwt.parseTokenResponse(gpa, response_body_json);
defer token_resp.deinit();
var id_token = try jwt.acceptIdToken(gpa, token_resp.id_token.?, .{ .hmac = secret }, .{
    .now_s = now_seconds,
    .issuer = "https://issuer.example",
    .client_id = "my-client-id",
    .nonce = &nonce, // MUST match — replay/injection defense
});
defer id_token.deinit();
```

## Semantics notes

- **base64url, no padding** (RFC 7515 §2): URL alphabet only; `=`, `+`, `/`
  and impossible lengths are rejected as `InvalidBase64`.
- **NumericDate** (RFC 7519 §2): seconds since epoch as `i64`; a fractional
  JSON number is truncated toward zero; NaN/inf/out-of-range → `InvalidClaim`.
- **Leeway** applies to `exp`, `nbf` and `iat` symmetrically; the boundary
  is inclusive (`exp + leeway == now` still passes). Comparisons use
  saturating arithmetic — extreme i64 timestamps cannot overflow the check.
- **Unsecured JWTs** (`alg: "none"`, empty third segment) *parse* (typed as
  `Alg.none`, empty `signature`) — `verify` then always rejects them
  (`UnsecuredToken`, RFC 8725 §2.1).
- Wrong-typed registered claims (string `exp`, numeric `iss`, non-string
  entry in an `aud` array, …) are rejected at parse time (`InvalidClaim`)
  rather than silently dropped.
- **HMAC keys are borrowed** — `Key.hmac` slices are not copied; they only
  need to outlive the `verify` call itself. (An `oct` JWK's decoded `k` is
  arena-owned by its `JwkSet`, so this holds automatically there.)
- **JWKS is skip-tolerant per key, strict per document** (RFC 7517 §5): a
  set routinely publishes keys a verifier does not use, so an individual
  JWK that is unsupported (`P-521`, `X25519`, unknown `kty`) or malformed
  (bad base64url, wrong-length coordinates, off-curve point, bad
  modulus/exponent, wrong-typed members) is *skipped* and recorded in
  `JwkSet.skipped` with a `JwkSkipReason` — only a document that is not a
  JWKS at all errors (`InvalidJson`/`NotAJwks`). Arbitrary bytes never
  panic.
- **`kty:"oct"` (symmetric) keys are trusted only from a LOCAL set.** A
  network-fetched JWKS (`fetchJwks` / `Provider`) **refuses** `oct` entries
  (`JwkSkipReason.oct_from_network`): a published JWKS is attacker-readable, so
  a symmetric key there is a forgery vector (anyone who reads it can mint HS\*
  tokens — RFC 8725 §3.5 / §2.1). `parseJwks` — a locally-configured, trusted
  set for HS\* dev/test setups — still accepts them.

## Verification

`zig build test-jwt` — fully offline tests spanning P1 (incl. the
mandatory-audience confused-deputy test) through P7 (see below), green under
Debug and ReleaseFast. A dedicated `SECURITY: mandatory audience …` test
proves a token minted for a sibling service is rejected by default and
accepted only when the `aud` matches or `.any` is set; the P5 `fetchJwks`
test proves a network-fetched `oct` key is refused (`oct_from_network`)
while the same set is accepted locally. P5 drives the `Provider` over a
scripted `Fetcher` (discovery, fetch, TTL/rotation refresh, rate limit, typed
failures); P6 runs the `ResourceServer` middleware end-to-end over a real
`router` + `http.Server.serveStream` (valid → 200 + identity;
missing/invalid/expired/wrong-scheme → 401 with the right challenge;
insufficient scope → 403; `protect=.mutations` lets reads through untouched;
`ScopeIter` + `InvalidRealm`), plus the shared scope helpers and
`writeBearerChallenge` formatting, and separately exercises
`Guard.authenticate` directly (valid/missing/garbage/expired/
insufficient-scope/wrong-alg/algorithm-confusion denials, plus RFC 9068
`at+jwt` `typ` enforcement on and off and an end-to-end `scp`-array scope
check).

P7 (relying-party flow): PKCE's S256 challenge reproduces RFC 7636 Appendix
B's known-answer vector byte-exact; `pkceGenerateS256`/`pkceGeneratePlain`/
`generateState`/`generateNonce` are checked for correct length, base64url
alphabet, and distinctness across draws from the same CSPRNG stream (not a
fixed/reused value); `buildAuthorizationUrl` and `buildTokenRequest` are
checked against exact expected percent-encoded strings (incl. an endpoint
that already carries a query string, and a round-trip through
`http.body.urlencoded` proving the encoding is decoder-compatible);
`parseTokenResponse` covers a full response, a minimal required-only
response, and each missing-required/wrong-typed-optional error.
`acceptIdToken`/`acceptIdTokenJwks`/`acceptIdTokenProvider` cover the happy
path; a **positive-control SECURITY test** — a token that `verify()` accepts
on its own cryptographic merits, but carries the WRONG `nonce` — proves
`acceptIdToken` still rejects it (`NonceMismatch`); a token with no `nonce`
claim at all (`MissingNonce`); `iss`/`aud`/`exp` failures each surfacing the
right typed error; and the multi-audience `azp` matrix (absent → mismatch,
wrong value → mismatch, correct value → accepted).

P1 (parse + claims): the RFC 7519 §3.1 example token end-to-end (header,
claims incl. the `http://example.com/is_root` custom claim, signing input,
32-byte HS256 signature base64url round-trip); `aud` as string and as array
with membership checks; claims-validation KATs (expired /
just-expired-within-leeway / boundary / `nbf` future / opt-in future-`iat` /
issuer+audience match & mismatch / missing `exp` vs `require_exp`);
i64-extreme saturation; malformed-token matrix (1/2/4 segments, empty
segments, bad base64url incl. standard-alphabet chars and padding, non-JSON
and non-object header/payload, missing/non-string `alg`, wrong-typed
claims); and a 512-case deterministic garbage-bytes sweep (never panics,
never leaks).

P2 (signature verify) — RFC known-answer vectors, all transcribed from the
RFCs and cryptographically self-checking:

- **RFC 7515 A.1 (HS256)**: the RFC's exact token + HMAC key verify; a
  flipped signature byte, a truncated signature and a wrong secret each →
  `BadSignature`.
- **RFC 7515 A.3 (ES256)**: the RFC's exact token + public key (from the
  JWK `x`/`y` coordinates) verify; the same signature over a tampered
  payload → `BadSignature`.
- **RFC 8037 A.4 (Ed25519)**: the RFC's exact signing input, public key and
  signature verify (its payload is a plain string, not JSON, so this vector
  exercises `verify` directly); flipped signature byte / signing input →
  `BadSignature`.

Plus generated round-trips for every family (HS384/HS512 computed MACs;
ES256/ES384 and EdDSA with deterministic std keypairs: sign → assemble
token → parse → verify OK; tampered payload, corrupted signature and
wrong-keypair key each → `BadSignature`); the RFC 8725 alg-confusion
matrix (`alg:none` with any key → `UnsecuredToken`; HS token vs EC/Ed keys
and ES/EdDSA tokens vs HMAC keys and cross-curve keys → `AlgKeyMismatch`;
unknown/`PS*`/`ES512` → `UnsupportedAlg`); wrong-length and
garbage-but-right-length signatures → `BadSignature`, never a panic;
invalid key bytes (off-curve points, non-canonical Ed25519) →
`KeyError.InvalidKey`; and `parseAndVerify` end-to-end (good → claims
readable; bad key / wrong key type / expired / malformed → the right typed
error, with `std.testing.allocator` proving nothing leaks on failure).

P3 (RSA, RS256/384/512):

- **RFC 7515 A.2 (RS256)**: the RFC's exact token verifies against the key
  built by `rsaFromModExp` from the RFC JWK's `n`/`e` — exactly the path
  Part 4's JWKS will feed; a flipped signature byte and the RFC signature
  over a tampered payload each → `BadSignature`.
- **RS256/RS384/RS512 round-trips** with a test-local RFC 8017 §8.2.1
  signer (EMSA-PKCS1-v1_5 encode + `em^d mod n` via `std.crypto.ff`, using
  the RFC A.2 private exponent `d`): verify OK; tampered payload /
  corrupted signature / an RS256 signature under an RS512 header (right
  length, wrong DigestInfo) each → `BadSignature`.
- **Alg confusion**: the RS256 token vs HMAC/EC/Ed keys and HS/ES/EdDSA
  tokens vs the RSA key → `AlgKeyMismatch`; `alg:none` with an RSA key →
  `UnsecuredToken`.
- **Robustness**: every wrong signature length (0/1/64/255/257/384/512 vs
  the 256-byte modulus) and right-length garbage (`s ≥ n`, all-zero, …) →
  `BadSignature`; `rsaFromModExp` rejects empty/all-zero, too-small,
  odd-sized and oversized moduli, even moduli, and even/tiny/oversized
  exponents → `InvalidKey` — never a panic.
- **`parseAndVerify` RS256 end-to-end** (good → claims readable; expired /
  wrong key type → typed errors; the RFC KAT through the one-call API).

P4 (JWKS, RFC 7517):

- **RFC 7517 A.1 example set**: parses into the typed EC P-256 + RSA keys
  with `kid`/`use`/`alg` intact; `keyForKid` finds the RSA signature key
  and refuses the `use:"enc"` EC key.
- **RFC keys as JWKs verify the RFC tokens**: the RFC 7515 A.2 RSA JWK
  (`n`/`e`, `alg:"RS256"` pinned) verifies the A.2 RS256 token, the A.3
  P-256 JWK (`x`/`y`) verifies the A.3 ES256 token, the A.1 `oct` JWK
  verifies the A.1 HS256 token (all via the no-`kid` single-key path);
  the RFC 8037 A.2 OKP JWK parses to an Ed25519 key.
- **Selection by `kid`**: a 4-key mixed set (oct + EC + RSA + OKP) where
  real HS256/ES256/RS256/EdDSA tokens each verify against their own `kid`;
  an unpublished `kid` → `NoMatchingKey`.
- **No smuggling**: an HS256 token whose `kid` points at the RSA JWK (the
  RFC 8725 downgrade shape) and an ES256 token pointing at the OKP key →
  `AlgKeyMismatch` from `verify`'s type check; `alg:"none"` with a valid
  `kid` → `UnsecuredToken`.
- **`use`/`alg` constraints**: `enc`-only and unknown-`use` sets →
  `NoMatchingKey`; a JWK pinned `alg:"RS384"` refuses an RS256 token *with
  a valid RS256 signature* (`NoMatchingKey`) yet verifies the RS384 one —
  on both the `kid` and the no-`kid` path.
- **Skip tolerance**: a set mixing P-521 / unknown-`kty` / X25519 /
  `use:"enc"` with one good RSA key — three skipped with the right
  reasons, the good key still verifies by `kid`; an 11-way malformed-JWK
  matrix (non-object, missing/wrong-typed `kty`, bad base64url, missing
  members, wrong-length and off-curve coordinates, non-canonical Ed25519,
  empty `oct` secret, wrong-typed `kid`) — every reason asserted, the one
  good key survives, never a panic.
- **Document-level errors**: garbage / truncated JSON → `InvalidJson`;
  valid-JSON non-JWKS shapes → `NotAJwks`; `{"keys":[]}` parses and
  resolves nothing (`NoMatchingKey`).
- **`parseVerifyJwks` end-to-end** (good → claims readable; expired /
  rotated-away `kid` / corrupted signature / malformed token → the right
  typed error, `std.testing.allocator` proving nothing leaks).
