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
- **No bespoke crypto:** `std.base64.url_safe_no_pad`, `std.json`, `std.crypto` (RSA via
  `std.crypto.Certificate.rsa` PKCS1-v1_5 over `std.crypto.ff`; HMAC, Ed25519 and ES384 from
  `std.crypto` too) — plus the **in-repo `p256` module for ES256** since `3403d47`, which is
  byte-exact to `std.crypto.sign.ecdsa.EcdsaP256Sha256` and carries that module's own KAT /
  differential evidence. Nothing is hand-rolled here. Modeled after
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

- **Token issuance** (2026-09-28, requested by qap): `encode(gpa, claims, key, opts)` /
  `encodeJson(gpa, claims_json, key, opts)` in `encode.zig` build the compact JWS. The key is a
  `SigningKey` whose variant fixes `alg` (RFC 8725 §2.1: never the caller's word alone; `none` is
  unrepresentable); `SigningKey.verificationKey()` gives the matching `Key`. HMAC secrets shorter
  than the hash output are refused (RFC 7518 §3.2 MUST); `encodeJson` refuses a payload that is
  not one JSON object. Signatures are deterministic (ECDSA per RFC 6979, Ed25519, ML-DSA with an
  empty context per RFC 9964). Every algorithm is tested by a round trip through
  `parseAndVerify`.

- **Verified-token cache** (2026-09-28, requested by qap): `VerifiedCache(Value)` in
  `cache.zig`, opt-in. See § "Verified-token cache" below for the argument that a hit answers
  exactly what verifying again would.

## Threat model / out of scope

This is the security core; the defenses are the point:
- **Algorithm confusion (RFC 8725):** `alg` is never trusted from the token to pick a key *class* —
  `none` is rejected; an HMAC `alg` can never verify against an asymmetric key (no RS/ES→HS
  downgrade); the expected algorithm/key type is fixed by the verifier, not the attacker.
  The same binding covers the post-quantum family: `.ml_dsa_44`/`.ml_dsa_65`/`.ml_dsa_87` are
  three distinct `Key` variants over three distinct Zig types, so crossing the parameter sets is
  a compile error inside `verify` rather than a runtime path, and an ML-DSA `alg` offered a
  classical key (or the reverse) is `AlgKeyMismatch`.
- **ML-DSA / RFC 9964 (`kty:"AKP"`):** the parameter set is read from the JWK's REQUIRED `alg`
  and **never inferred from the length of `pub`**, even though the three lengths are distinct —
  inferring it would accept a key whose `alg` names one set and whose bytes are another. `pub` is
  length-checked against the named set before it is decoded. Verification is pure ML-DSA with an
  EMPTY FIPS-204 context and a raw (unframed) signature, as RFC 9964 §2 requires; HashML-DSA has
  no `Alg` name here, so it is `UnsupportedAlg` rather than silently treated as pure.
- **A published private key is refused (RFC 7517 §4, RFC 9964 §3 — both MUST NOT):** a JWKS
  fetched over the network whose key carries `d` (RSA/EC/OKP) or `priv` (AKP) is skipped with
  reason `priv_from_network`, alongside the existing `oct_from_network`. The module never reads
  the private half — but a published one means the issuer's signing key is readable by anyone
  who can GET the document, so every token it "verifies" is forgeable, and continuing to trust it
  would authenticate forgeries as genuine. A locally-configured set may still carry private
  material; that is a legitimate place to hold it.
- **Critical header parameters (RFC 7515 §4.1.11 / RFC 8725 §3.3):** a token whose header carries
  `crit` is **rejected in `parse`**, so every entry point (offline verify, JWKS, `Provider`,
  `ResourceServer`, `Guard`, the RP's `acceptIdToken*`) inherits the rejection and no path can
  verify-and-ignore an extension the producer marked as MUST-understand. `understood_crit_headers`
  is the (currently empty) set of names this implementation both understands and processes; any
  name outside it is `UnsupportedCritHeader`. The syntactic rules are enforced too
  (`InvalidCrit`): non-array, empty array, non-string or empty entry, duplicate entry, a name not
  actually present in the header, and any RFC-registered header parameter name — the last of which
  is what would otherwise let a producer "critically" redefine `alg`/`kid`/`typ`.
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
- **Out of scope:** RS*/PS*/ES512 *signing* (issuance covers HS*, ES256/384, EdDSA, ML-DSA); encryption (JWE); `x5c` chain validation; revocation
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
- **`azp` verified whenever it is present, at any `aud` arity (OIDC Core §3.1.3.7 steps 3-4):**
  step 4 ("If an `azp` Claim is present, the Client SHOULD verify that its `client_id` is the Claim
  Value") has **no audience-count precondition** — only step 3 (`azp` SHOULD be *present*) is
  conditioned on multiple audiences. So a present `azp` that is not this `client_id` is rejected
  (`AzpMismatch`) even for a single-audience token: that is the cross-client-identity shape, an
  ID Token minted **for another client** at the same OP and merely audienced at us. A wrong-typed
  `azp` fails the same way. Absent `azp` is fine for a single audience (the mandatory `aud` check
  already pins the token to this RP) but is rejected for a multi-audience token — an OP is not
  trusted to imply which of several audiences actually authorized it.
- **Discovery `authorization_endpoint`/`token_endpoint` are additive, not required:** `Metadata`
  gained these two optional fields for P7; a discovery document from an issuer that only ever
  served this module's original resource-server (P5) scope, and never populated them, still parses
  unchanged — only a wrong JSON *type* (not absence) is an error, matching
  `id_token_signing_alg_values_supported`'s existing rule.

## Verified-token cache

`VerifiedCache(Value)` remembers a token that verified until its `exp`, so a repeat skips the
signature. Measured motive (qap audit): ES256 through `p256` ~1.6 k verifications/s per core
under load (~4 k quiet), RS256 slower through std's bignum — a JWT API is capped at a few
thousand requests per second per core by verification alone, while a client sends the same
access token on every request.

**Contract: a hit answers exactly what `parseVerifyJwks` (+ the caller's `derive`) would.**
`parseVerifyJwks` is a deterministic function of (token bytes, key set, `Options`); the cache
fixes the first two and every part of the third except the clock, and re-evaluates the clock:

- **Key = SipHash-2-4-128 under a per-cache secret key, over (domain tag ‖ policy ‖ context ‖
  token).** The policy is every `Options` field but `now_s` (`leeway_s`, `issuer`, `audience`,
  `require_exp`, `reject_future_iat`), length-prefixed, with the token last; a comptime check
  fails the build when a field is added to `Options` without being folded in or excluded. So the
  same token under another audience, issuer or leeway is another entry — one cache may even be
  shared between verifiers. The 16-byte MAC key is drawn at `init` with `io.randomSecure`
  (fail-closed, CONVENTIONS §2.2) and wiped at `deinit`. Without it an attacker cannot compute a
  single tag offline, and a request whose bytes differ from a cached token's hits only if the two
  tags collide — 2^-128 per request, and each attempt is an online request that learns one bit
  (hit or miss). That is the sense in which a hit implies these exact bytes verified before.
  *Why keyed and not SHA-256/BLAKE3 (measured, table below):* on this host (no SHA extensions)
  hashing a 682-byte token costs SHA-256 ≈ 3.1–4.2 µs and BLAKE3 ≈ 2.3–3.0 µs against SipHash-2-4
  ≈ 0.37–0.51 µs, and the digest is almost the whole hit path: the first version of this cache
  used BLAKE3 and its ES256 hit measured 2.6–3.5 µs, the keyed one 0.70 µs. The price is one
  assumption: **the key must stay secret.** An attacker who can read the process's memory (the
  key and a stored tag) could search offline for a byte string with the same tag — SipHash is a
  PRF, not collision-resistant under a known key — and a hit never parses, so such a string
  would authenticate as that entry's principal until its `exp`. An attacker with that read
  already holds every bearer token passing through the process's buffers, so this widens an
  existing compromise rather than opening a new one; a consumer who must not accept even that
  should not enable the cache.
- **Bound to `JwkSet.id`.** Every set `parseJwksSource` builds (so every `fetchJwks` result and
  every `Provider` refresh) takes the next value of a process-wide counter, never reused; a hit
  requires the entry's id to equal the set passed in. Replacing the set therefore invalidates
  everything verified under the old one — no generation to bump by hand, no ABA from a freed
  set's address being reused, and "a key the set drops stops verifying at the next fetch" holds.
  A set with `id == 0` (assembled by hand) is never cached. A set is immutable after parse (its
  `keys` are `[]const`), which is what makes the id a sound stand-in for its contents.
- **Time claims re-checked on every hit** by `checkTimes`, the same function `validateClaims`
  runs (it was factored out for this), against the caller's `now_s`. `validateClaims` checks
  `exp`, `nbf`, `iat` before `iss`/`aud`, and `iss`/`aud` are fixed by the key, so the first
  failure a hit reports is the one a fresh verify would report. An `Expired` entry is evicted;
  a `NotYetValid` one (a clock stepped back) stays, since it may pass again.
- **Only successes are stored.** A failure is never cached: caching one would let an attacker
  pin a refusal on a token or fill the table with junk. `verifyJwks` stores only after
  `parseVerifyJwks` and `derive` both succeed; the public `insert` additionally refuses a
  `parsed` that is not `token`'s parse (signing input must be the token's prefix) and claims
  that fail `validateClaims` now. The signature precondition of `insert` cannot be re-checked
  cheaply and is the caller's (documented) — `verifyJwks` is the entry point that needs no trust.
- **What is stored is the caller's `Value`, not claims.** `Value` is plain data, rejected at
  compile time if it contains a pointer or slice (it outlives the parsed token). This keeps the
  hit path allocation-free and bounds an entry: a token whose claims do not fit the caller's
  `Value` is refused by `derive` and simply not cached. `derive` must be a pure function of the
  token; what else it reads (which claim names the principal, which scopes map to which bits)
  goes into `Config.context`, which is folded into the key.

**Residual differences — none in the answer, under one assumption.** With the MAC key secret, a
hit returns what verifying again would, except with probability 2^-128 per request. What does
differ, deliberately:
(1) the key-secrecy assumption itself (above): a disclosure of process memory becomes forgeable
hits for cached principals until their `exp`. (2) Timing: a hit is faster, so someone who can
already present a token can tell whether it was recently verified; learning that needs the token
itself. (3) Residency: each cached token's tag and derived `Value` stay in memory until evicted or
`deinit` (both wipe); the token itself is never stored. (4) Staleness of the key *source* stays
the caller's: a remote set too old to use must still be refused before the lookup (qap's
`Remote.acquire` returns null), exactly as before. None of these changes an accept/refuse
decision, so a consumer may enable the cache by default; one whose threat model counts a memory
disclosure as survivable for bearer tokens not currently in flight should leave it off.

**Concurrency.** A 4-way set-associative table of power-of-two buckets, each with its own
spin lock (`std.atomic.Mutex`, cache-line aligned). The MAC is computed before the lock is
taken and the signature is verified after it is released, so the lock covers a probe of four
16-byte tags and one copy of `Value` — nothing that blocks or allocates. Per-bucket striping
makes two workers contend only when their tokens hash to the same bucket. Per-thread caches
were rejected: they divide the hit rate by the worker count (a client's connections spread over
workers), multiply memory, and need thread identity plumbed through the caller; a sharded table
costs one uncontended atomic swap on the hit path. There are deliberately no shared hit/miss
counters — one atomic incremented by every worker on every request is exactly the cache line
the striping exists to avoid; a caller counts per worker. Tested by four threads hammering an
8-entry table with 24 tokens and 200-byte values (a torn copy would show as mixed bytes); a
mutant that reads without the lock fails it.

**Eviction.** A bucket's victim is, in order: the same token's slot (another set, a racing
insert), a free slot, a slot past its `exp + leeway`, else CLOCK — the first slot from the
bucket's hand whose second-chance bit (set on each hit) is clear, clearing bits as it passes.
Capacity is the caller's (`Config.capacity`, rounded up to a power-of-two bucket count × 4).

**Flooding.** Only tokens that verified can occupy slots. An attacker holding one valid token
can make a handful of distinct-byte variants that still verify (ECDSA `s ↔ n−s`, unused
base64url tail bits) — each costs a full verification before it is stored, and filling the
table only evicts other clients' entries, which then re-verify: the worst case is the cost
without a cache, never a wrong answer.

**Measured** (ReleaseFast, `taskset -c 1`, this host — i7-7920HQ, no SHA extensions — under
other jobs' load; µs per Bearer verify, `parseVerifyJwks` vs the cache):

| | `parseVerifyJwks` | cache miss (MAC + verify + insert) | **cache hit** |
|---|---|---|---|
| ES256, 682-byte token, `p256` | 313–435 µs | 402–449 µs | **0.70–0.73 µs** |
| RS256, RFC 7515 A.2 (2048-bit), 458 bytes | 218–317 µs | 209–297 µs | **0.42–0.55 µs** |

Three runs each; the machine was running other jobs (load average 4–12), so the verify columns
are noisy and the miss/no-cache difference (one MAC and one insert, < 1 µs) is inside that noise.
A hit is two to three orders of magnitude cheaper than a verify. Digest candidates over the same
682 bytes, same runs: SHA-256 3.1–4.2 µs, BLAKE3 2.3–3.0 µs, SipHash-1-3-128 0.20–0.25 µs,
SipHash-2-4-128 0.37–0.51 µs (the standard parameters were kept; 1-3 would save ~0.2 µs). The
bench was a throwaway test in the worktree's `.zig-cache`, deleted after.

Not wired into `Provider`/`Guard`/`ResourceServer` — see Backlog.

## Verification

RFC known-answer vectors transcribed from the RFCs: JWS 7515 A.1 (HS256) / A.2 (RS256) / A.3
(ES256), 8037 A.4 (Ed25519); JWK/JWKS 7517 vectors; PKCE RFC 7636 Appendix B (S256 challenge,
byte-exact); plus adversarial negatives (alg=none, alg-confusion downgrade, kid mismatch,
embedded-jwk ignored, expired/nbf, tampered signature, mandatory-audience confused-deputy
rejection, oct-from-network refusal, ID-token nonce-mismatch positive control, azp/iss/aud/exp
rejection) and Provider cache/rotation/TTL tests behind a scripted fetcher. `VerifiedCache`: hit/miss
(derive count), `exp` crossing while cached (same error as a fresh verify, then evicted), `nbf`/`iat`
re-check, set replacement and key rotation, policy/context separation, one-byte-different tokens,
failures never stored (bad signature, expired, underivable, misused `insert`, id-less set),
capacity/CLOCK eviction, four-thread hammering, ES256 end to end. Mutation check at landing (mutant schemata,
one ReleaseSafe build): ten mutants — set-id check dropped, time re-check dropped, audience not folded
into the key, context not folded into the key, CLOCK bit ignored, expired entry not evicted, `insert`
prefix guard dropped, both locks dropped, lookup without the lock, MAC key not wiped — all killed. The P6 resource-server
guard adds self-constructed policy tests (own signer, not external interop KATs — the correct
approach for policy logic): `Guard.authenticate` valid/missing/garbage/expired/insufficient/
alg=none/RS→HS-confusion decisions, RFC 9068 `at+jwt` typ on/off, `scope`+`scp` scope helpers
(single/all/any), and `writeBearerChallenge` header formatting. Run: `zig build test-jwt`.

## Backlog / deferred

- **`Provider` measures its JWKS intervals on the wall clock (found from qap, research register H6,
  2026-09-29).** `Provider.verify(gpa, token, now_s, …)` uses one caller-supplied `now_s` for the
  token's `exp`/`nbf` AND for `ttl_s` / `min_refresh_interval_s` (`src/root.zig` `fetched_at_s`,
  `last_attempt_s`, `refreshAllowed`); `ResourceServer`/`Guard` feed it `Clock.system`
  (`CLOCK_REALTIME`). After a backward step of Δ (NTP, a VM restored from a snapshot) neither the
  TTL re-fetch nor the unknown-`kid` refresh can fire for Δ — a rotated key is a 401 for Δ. qap
  hit the same bug in its own refresher and fixed it there (`src/auth_jwt.zig`: interval clock
  `CLOCK_BOOTTIME` by default + rebase on a backward step); qap does not use `Provider`. Ideal
  API: a second, interval clock on `Provider.Options` (default boot/monotonic) — or `verify`
  taking `mono_s` beside `now_s` — with wall time used only for claims; and a `Clock.boot`
  beside `Clock.system`.
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
- **RS\* signing** — `encode` does not offer RS256/384/512: std has no RSA signing, and the
  `rsa` module's `signPkcs1v15` would become a new dependency of jwt (a root `build.zig`
  change). Add it when a consumer needs RSA-issued tokens. Still open.
- ~~**`Guard` over a static `JwkSet`**~~ — DONE 2026-09-28 (found by qap): `Guard.Options.jwks`
  (exactly one of `provider`/`jwks`, else `error.InvalidKeySource`) runs the same Bearer
  extraction, `at+jwt` check, scope policy and RFC 6750 challenges over a caller-held set;
  nothing is fetched, so an unknown `kid` is refused at once. A static set has no issuer to
  default to, so `claim_opts.issuer = .provider` fails `init` (`error.IssuerNotConfigured`).
- **`VerifiedCache` behind `Provider`/`Guard`/`ResourceServer`** — not wired. `Provider.verify`
  returns an owned `ParsedToken`, which a hit cannot produce without allocating, and its TTL
  refresh must run before a lookup (else a hit would outlive a dropped key). The fit is a
  `derive`-style entry point on `Provider` that refreshes first and then calls
  `VerifiedCache.verifyJwks` with its current set. Add it when a consumer of those types asks.
- No other module-local backlog recorded (README has no Deferred section).

- ~~**Refuse a plain-HTTP key source**~~ — DONE 2026-09-28 (from qap M11.8): `discover`,
  `fetchJwks` and `Provider` refuse an `http://` (or scheme-less) issuer, discovered `jwks_uri` or
  configured `jwks_uri` with `error.InsecureKeySource`, before any fetch — anyone on a plain-HTTP
  path could serve their own keys and mint any token. `KeySourceOptions.allow_plain_http` /
  `ProviderOptions.allow_plain_http` opt out (tests, a loopback issuer), through the new
  `discoverWith`/`fetchJwksWith`; the three-argument calls keep their signatures.

## Status

`gap · any · both · reentrant (Provider: externally synced)` + deps `http`, `router`, `p256` —
canonical source is `pub const meta` in src/root.zig.

## Anchoring

**Anchor grade:** class A · oracle EXTERNAL

- **Class A** — wire/interop format — other implementations must byte-agree with it.
- **Oracle EXTERNAL** — published vectors, goldens captured from a foreign implementation, or a test run against a live foreign peer.

**What the tests actually contain.** RFC 7515 A.1-A.3/8037 A.4 full JWS compact-token vectors + PKCE 7636 App B
+ **RFC 9964 Appendix A.1** — all three published (AKP JWK, ML-DSA JWS) pairs, verbatim, in
`src/rfc9964_vectors.zig`. That last one is the module's strongest external anchor and was
missing from this list until 2026-09-01: the vectors landed in `e5d6d947` and this section had
been written in `4f75fc51` a week earlier. It matters more than a line-count omission, because
the RFC's private seed is 32 zero bytes and the module can regenerate all three public keys
itself — so internal evidence alone cannot tell a genuine RFC vector from a self-generated one.
The audit that added this line fetched the RFC and compared character by character (and
recomputed each `kid` as the RFC 7638 thumbprint over `{alg, kty, pub}`); all three match.
