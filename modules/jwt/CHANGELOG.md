# jwt — changelog

Newest first. See the root [`CHANGELOG.md`](../../CHANGELOG.md) for which
release tag each entry shipped in, and `CONVENTIONS.md` §8 for the policy.

## Unreleased

- **2026-10-28** — **NO CONSUMER-VISIBLE CHANGE:** Delta audit of the no-panic sweep: its independent review plus 8 mutants over the changed code, 8 killed, 0 equivalent. Survivors of the first run became tests. Checked panics are not mutated (a test cannot observe a panic in-process). Cumulative 460/495, 35 eq. Card A1 again.
- **2026-10-28** — **Fix (no-panic sweep):** no consumer-reachable panic or UB left (sweep of every pub entry point, `~/CML/20261028-panic-sweep/jwt-sweep.report.md`). Consumer-visible: `parse` (so every verify path) refuses a token longer than the new `max_token_len` (16 KiB) with `error.MalformedToken` before allocating; a `crit` list of more than 16 entries is `error.InvalidCrit` (bounds the quadratic duplicate scan); a FAILED `Provider` refresh is no longer retried by every `verify` -- within `min_refresh_interval_s` of the failed attempt `verify` returns the same error without a fetch -- still fail closed, no stale keys (new `Provider.last_refresh_err`). `Claims.claim*` and `scopeGranted` are total on a hand-built `Claims` whose `raw` is not an object. Caller-contract `std.debug.assert`/`.?` (UB in ReleaseFast) are checked panics with a message: `Provider.init` with neither `issuer` nor `jwks_uri`, `VerifiedCache` used after `deinit`. Docs: a refreshing `.provider` under a threaded server needs a real `lock`.

- **2026-10-26** — Delta audit of the HS* move to `sha2` and the verify-side key floor (A2 → A1, grade 1). 11 mutants, all killed (452/487, 35 eq overall). New test pins the floor at exactly the hash size for HS256/384/512 on both sides (a single 32-byte floor and an off-by-one survived before). The stack probe now also looks for the ipad/opad message schedule (`W`, `W + K`), which the CRYPTOGAMS assembly spills: it finds it when the burn is skipped or 512 B deep, and none with the shipped 4 KiB (2 KiB still passes). No API change.

- **2026-10-26** — HS256/HS384/HS512 compute std's `Hmac` over the `sha2` module (new dependency) instead of `std.crypto.hash.sha2`. The bytes are the same (RFC 7515/7520 vectors, 81-row golang-jwt oracle). On an x86-64 CPU without SHA-NI it is faster: hs256_sign 1.32× → 1.05× jsonwebtoken, hs256_verify 1.23× → 1.07×. Card: fastest 1.21× (P1). No API change.

- **2026-10-25** — **BREAKING (consumer-visible):** `verify` — so `parseAndVerify`, JWKS `oct` keys, `Provider`, `Guard`, `acceptIdToken*` — refuses an HMAC secret shorter than the hash output (32/48/64 bytes for HS256/384/512) with `InvalidKey`, as `encode` already did (RFC 7518 §3.2; owner decision on audit F3). Before, any non-empty secret verified. Test fixtures with short secrets were lengthened.

- **2026-10-25** — **Fix (consumer-visible, one second):** a token was accepted at exactly `exp + leeway`; RFC 7519 §4.1.4 requires the current time to be *before* `exp`, and golang-jwt refuses it there. `validateClaims`, `VerifiedCache` hits and every entry point built on them now return `Expired` at `now == exp + leeway` (found by the new `interop-jwt`, case exp-equals-now). Four tests moved one second. Also `encodeJson` reports an allocation failure inside its claims check as `OutOfMemory` (it said `InvalidClaims`; audit F6).

- **2026-10-25** — **Faster EdDSA verification, same verdicts:** `verify`'s EdDSA arm runs `ed25519.zig` — std's checks and cofactored equation, over a width-5/width-7 wNAF double-scalar multiplication on ref10's point representations — instead of `std.crypto.sign.Ed25519.Signature.verify` (bench-jwt: 79.7 → 67.1 µs per token, 1.44× → 1.21× jsonwebtoken/ring). Held to std on valid, corrupted, torsion-shifted and small-order inputs (tests in `ed25519.zig`). Also `encodeJson` builds the header on the stack and `parse` sizes its arena once (HS256 sign 2.69 → 2.35 µs).

- **2026-10-25** — **Added (tools):** `zig build interop-jwt` — golang-jwt v5.3.1 judges 81 tokens (every algorithm both ways, alg none/confusion, crit, exp/nbf edges, claim types, base64url padding and unused bits, ECDSA/EdDSA/RSA signature encodings) and each verdict is compared with `parseAndVerify`'s; `--write` freezes the table into `src/go_oracle_vectors.zig`, replayed by `test-jwt`. `bench-jwt` gains Keats/jsonwebtoken 9.3.1 as the fastest-in-the-field side (`tools/rust_fast_bench`, `BENCH_FAST=0` skips).

- **2026-10-24** — **NO CONSUMER-VISIBLE CHANGE:** the `strRepeat` helper (the Zig 0.17 stand-in for `**`) builds its string with one `@splat` + `@bitCast` instead of a comptime loop, which Sema evaluated in O(n²) (http's test binary: 323 s → 13 s). Same bytes, faster compile.

- **2026-10-20** — **Fix:** RS256/384/512 and PS256/384/512 verification read the RSA modulus through a dangling pointer (`rsaKey` took the `Key` by value and returned a pointer into that parameter), so optimized builds refused valid tokens — our own and golang-jwt's — depending on code layout (found by `bench-jwt`'s interop check on Zig 0.17, ReleaseFast and ReleaseSafe; Debug passed). `rsaKey` now takes `*const Key`. Since 2026-10-13 (`0517cb9b`).

- **2026-10-19** — **Fix:** `HttpFetcher` (discovery and JWKS fetches) refuses a redirect from an `https://` URL to `http://`; the https-only key-source check covered only the configured URL, a redirect bypassed it. Test: `refuseSchemeDowngrade` truth table.

- **2026-10-19** — **NO CONSUMER-VISIBLE CHANGE:** Deprecated std names replaced by their Zig 0.17 spellings (`mem.indexOf*` -> `mem.find*`, `fmt.bufPrint` -> `mem.print`, `fmt.allocPrint(a, …)` -> `a.print(…)`, `bufPrintSentinel` -> `mem.printSentinel`, `@intFromEnum` -> `@backingInt`); the old names are aliases, so behaviour is identical.

- **2026-10-18** — Ported to Zig 0.17.0. Non-mechanical: `cache.zig` reflection over `Options`/`Value` uses `field_names`/`field_types` (struct `.fields` is gone); the `ReadCueIo` test seam counts `Operation.net_read` through `vtable.operate` (`netRead` slot is gone).
- **2026-10-18** — **Constant time:** `parseJwks` key material (`oct` `k` and every other base64url member, RSA/EC private components included) decodes with `b64ct.url_safe_no_pad` instead of `std.base64` (new dep). Same acceptance and `InvalidBase64` errors.
- **2026-10-14** — follows rsa's 8192-bit cap: RS*/PS* keys up to 8192 bits are accepted (was 4096; golang-jwt has no upper bound below Go's). Test boundary moved to `rsa.max_modulus_len + 1`.
- **2026-10-13** — ES384 runs on the new `p384` module (new dep) instead of std's P-384: sign 4.21× → 0.52×, verify 2.80× → 0.59× golang-jwt. `EcdsaP384Sha384` is now `p384.EcdsaP384Sha384` (std's surface; `KeyPair` methods take `*const KeyPair`, `fromSecretKey` refuses d ≥ n). Verification accepts what std's did; ES384 signature BYTES change, because p384's nonces are RFC 6979 exactly — a test pins that std and jwt accept each other's ES384 tokens. Card Performance measured again (ref 0.20–0.99×, P2); ctgrind ec 18 → 10 (std's 8 ES384 contexts gone).
- **2026-10-13** — PS256/384/512 verification and RS256/384/512 + PS256/384/512 signing through the `rsa` module (new dep; `jwt.rsa` re-exported); `SigningKey.sign` for a raw signing input; RFC 7520 §4.1 (RS256, byte-exact signer) and §4.2 (PS384) vectors. BREAKING: `RsaPublicKey.inner` is now `rsa.VerifyKey` (was std's `Certificate.rsa.PublicKey`, whose PSS verify asserts on 8k+1-bit moduli) and RSA keys are accepted from 2048 to 4096 bits (were 256/384/512-byte moduli, i.e. 2041+). EdDSA signing takes `R = r·B` from the `ct25519` comb (new dep): byte-identical to std, ~1.6× faster. OAuth2 error responses: `parseOAuthError` (RFC 6749 §5.2), `parseAuthorizationError` (§4.1.2.1), `parseTokenEndpointResponse`. `bench-jwt` covers ES384/ES512/RS256/PS256 too. Card Scope core → parity.
- **2026-10-12** — `http.Method` grew `.connect`, `.trace`, `.other` (http R9): under
  `ResourceServer` `protect = .mutations` TRACE is a read (RFC 9110 §9.2.1), CONNECT and any
  extension method need a token (fail closed).

- **2026-10-10** — tools: comparative benchmark `tools/bench.zig` + `tools/go_bench/` (`zig build bench-jwt`) against golang-jwt v5.3.1 on Go 1.26.0 (HS256/ES256/EdDSA sign + verify, cross-verified tokens); card Performance filled (0.40–1.63×), SPEC "Performance — bench-jwt" section and the levers in Backlog.
- **2026-10-10** — ES512 (ECDSA P-521 + SHA-512): verify (`Key.ecdsa_p521`, `Key.ecdsaP521FromCoords`), sign (`SigningKey.es512`), and JWK `kty:"EC"`, `crv:"P-521"` with exact 66-byte coordinates, through the new `p521` module (new dep). `ES512` tokens no longer return `UnsupportedAlg`. Anchored to RFC 7515 A.4 (known-answer signature; the A.4 JWK through JWKS; `d` derives `x`/`y`).
- **2026-10-09** — tests: deterministic fuzz driver `JWT_FUZZ` over the existing harnesses (`parse`, `parseJwks`, `parseTokenResponse`, plus a new sign/verify oracle: a token this module issued is accepted, a flipped one, a truncation and a wrong key are refused).
- **2026-10-09** — dead-stack lint: `SigningKey.alg` / `verificationKey` / `encode` / `encodeJson` (the key is a union of borrowed slices and pointers) and `buildTokenRequest` (string assembly into a heap body) are marked as reviewed false positives. No code or signature change; no new probe needed (signing is probed in `stackprobe_test.zig`).
- **2026-10-09** — **BREAKING (HIGH, secret residue): token signing and HS\* verification left keys,
  nonces and keyed HMAC state on the dead stack; `SigningKey` now borrows its key pairs.**
  Found by a new stack probe (`src/stackprobe_test.zig`, ReleaseFast, 16-byte windows of every secret
  image, 2 keys × 5 `encodeJson` / `verify` calls each; BEFORE counts are over those 10 calls).
  Before: ES256 `d` 40 (by-value key copies; the nonce was already burned inside p256); **ES384** `d` 60 (std P-384, no burn);
  **Ed25519** seed 20; **ML-DSA**
  (44 / 65 / 87): `K` 20, the NTT-domain `s1`/`s2`/`t0` copies 2560 / 3200–3840 / 4480–5120
  windows each, `ρ'` 40 (ML-DSA-87 reached past the 256 KiB probe window; its `SigningKey` copy is
  ~100 KiB per pass, three passes deep); **HS256/384/512 verification**: the `key ⊕ opad` block 30 /
  55 / 60 and the inner hash state 10 / 40 / 40 on every verify (success or not); HS signing showed 0
  in this run (luck of what the base64 step overwrote afterwards, not a guarantee). After: 0 for every
  needle, NEG 0, POS ≥ 1, in all of them.
  - `SigningKey` key-pair variants are pointers: `es256`, `es384`, `ed25519`, `ml_dsa_44/65/87` are
    `*const …KeyPair` (borrowed for the call, never copied into a frame of ours). HMAC variants
    stay `[]const u8`. Migrate `.{ .es256 = kp }` to `.{ .es256 = &kp }` (the pair must outlive the
    call, so keep it in a `var`/`const` of its own, not a temporary).
  - Signing runs one frame down per algorithm family (`src/burn.zig`) and the stack that frame dirtied
    is zeroed afterwards: HMAC 4 KiB (body dirties 2.4 KiB), ES256/ES384/Ed25519 16 KiB (9.6 / 5.5 /
    4.2 KiB), ML-DSA 112 / 192 / 288 KiB for set 44 / 65 / 87 (96.6 / 166.2 / 262.9 KiB) — sized per
    set because a burn deeper than the body is stack the caller may not have. ML-DSA signs through
    the streaming `signer` on the borrowed pair (std's `KeyPair.sign` copies the ~100 KiB pair by
    value, twice). The HMAC compare of `verify` (HS256/384/512) runs the same way, 4 KiB.
  - ⚠ Out of reach here, in the caller: the caller's own key storage and anything it copies the pair
    into; std's `EcdsaP384Sha384` / `Ed25519` / `MlDsa*` key generation (not part of this module).

- **2026-10-04** — Tests: first dated mutation run (111 mutants, 105 killed, 6 equivalent;
  `SPEC.md` § "Mutation run 2026-10-04"). No defect; 12 new tests close the 29 test gaps it found
  — case-sensitive `alg`, inclusive `nbf`/`iat` edges, exact `iss`/`aud`/scope matching, exact
  signature lengths for every alg, exact JWK material lengths, the discovered-issuer spelling,
  DELETE under `protect = .mutations`, strict `Bearer SP` extraction, CR/LF in a realm, the
  one-element `aud` array, `acceptIdTokenProvider`'s audience, NumericDate at ±2^63. No source
  change.
- **2026-09-29** — **`Provider` can measure its refresh intervals on a clock that never steps.**
  `ProviderOptions.interval_clock` (default null: the intervals follow the caller's `now_s`, as
  before) and `Clock.boot` (seconds since boot counting suspend: CLOCK_BOOTTIME on Linux,
  CLOCK_MONOTONIC on other POSIX, QueryPerformanceCounter on Windows). With it a wall-clock step
  forward no longer expires the JWKS TTL early and a step back cannot touch the intervals at all;
  `ttl_s` and `min_refresh_interval_s` both run on it, the claims (`exp`/`nbf`/`iat`) stay on
  `now_s`. Additive, no behaviour change unless set.

- **2026-09-29** — Fixed: `Provider` froze both JWKS refreshes after a backward clock step.
  One wall-clock `now_s` drives the claims and the `ttl_s` / `min_refresh_interval_s`
  bookkeeping, so after a step back of Δ (NTP, a VM restored from a snapshot) `now_s -
  fetched_at_s` stayed negative for Δ: no TTL re-fetch, no unknown-`kid` refresh, and a key
  the issuer rotated inside that window was `NoMatchingKey` (a 401) for Δ. A `now_s` before a
  recorded mark now counts as the interval having passed; the refresh re-bases the mark.
  Found from qap (research register H6), which had the same bug in its own refresher.

- **2026-09-28** — **Verified-token cache** (opt-in): `VerifiedCache(Value)` remembers a token
  that verified until its `exp`, keyed by a SipHash-2-4-128 MAC (random per-cache key from
  `io.randomSecure`, so `init` takes an `Io`) over the exact token bytes and the claim policy,
  bound to the key set it verified under, re-checking `exp`/`nbf`/`iat` on every hit and storing
  only successes; `verifyJwks` puts it in front of `parseVerifyJwks`, `lookup`/`insert` are the
  halves. New `JwkSet.id` (process-unique, stamped by `parseJwks`/`fetchJwks`; 0 on a hand-built
  set, which is never cached) is what invalidates entries when a set is replaced. Additive:
  `validateClaims` behaves as before (its time checks moved into a shared helper). Wanted by
  qap, whose ES256/RS256 verification capped a JWT API at a few thousand requests/s per core.

- **2026-09-28** — ⚠ **Plain-HTTP key sources are refused**: `discover`, `fetchJwks` and
  `Provider.refresh` return `error.InsecureKeySource` for an `http://` (or scheme-less) issuer or
  `jwks_uri`, including a `jwks_uri` named by an https discovery document. Opt out with the new
  `discoverWith`/`fetchJwksWith` (`KeySourceOptions.allow_plain_http`) or
  `ProviderOptions.allow_plain_http`. Signatures unchanged; the error sets gain
  `InsecureKeySource`. Wanted by qap M11.8, which checked the scheme itself.

- **2026-09-28** — `Guard` over a static `JwkSet`: `Guard.Options.jwks` as an alternative to
  `provider` (now optional; exactly one must be set, `error.InvalidKeySource` otherwise). The
  guard's `provider` field became `source: Guard.KeySource`. `Guard.InitError` gains
  `InvalidKeySource` and `IssuerNotConfigured` (static set + `issuer = .provider`). Existing
  `.provider = &p` callers compile unchanged. Wanted by qap.

- **2026-09-28** — **Token issuance**: `encode` (claims serialized by `std.json`) and `encodeJson`
  (a JSON object verbatim) over a new `SigningKey` (HS256/384/512, ES256, ES384, EdDSA,
  ML-DSA-44/65/87) whose variant fixes `alg`; `EncodeOptions` sets `typ`/`kid`. Short HMAC
  secrets are refused (RFC 7518 §3.2). Additive. Wanted by qap, whose tests hand-rolled tokens.

- **2026-09-15** — **NO CONSUMER-VISIBLE CHANGE:** tests only. The `HttpFetcher` body-read cancel test canceled after a fixed
  sleep. It now cancel once the client is inside the socket read under test (`ReadCueIo`, a
  `std.Io` double that counts `netRead` entries), and the peer is released from `accept`
  before `join`. On a loaded full gate the sleep could land the cancel before the connect. The
  peer thread then waited in `accept` forever, the shape that hung `http` in full-gate attempt 3.

- **2026-09-09** — Licensing: added `NOTICE` (kind `third-party attribution`). No code
  changed. `src/rfc9964_vectors.zig` reproduces RFC 9964 Appendix A.1's JOSE examples
  verbatim, which the module's `Provenance:` statement never mentioned — it lists the
  eleven RFCs the code implements. The record rests on the IETF Trust's written grant,
  TLP 5.0 §4.c Revised BSD, reproduced in the new file.
- **2026-09-07** — **All three fuzz harnesses were replaying an EMPTY input; each now
  has a corpus and a measured reach guard.**

  `fuzzParse`, `fuzzParseJwks` and `fuzzParseTokenResponse` all opened with
  `smith.bytes(&buf)` followed by `smith.valueRangeAtMost(u16, 0, buf.len)`. `bytes`
  consumes `min(buf.len, in.len)` octets and a ranged draw then reads eight *more* as
  a little-endian u64, returning the range minimum when fewer remain — so the drawn
  length was 0 for every input a seed can carry, and `parse`, `parseJwksSource` and
  `parseTokenResponse` were each handed a zero-length slice while the token sat unread
  in `buf` (measured on `rfc7519_example_token`: `buf[0] == 'e'`, `len == 0`). All
  three now take the bytes in one `smith.slice(&buf)` draw, and all three have a
  corpus: 27 compact tokens, 28 JWK Sets, 13 token-endpoint bodies.

  Each corpus has a guard test that runs in the ordinary lane and pins numbers that
  were measured, not guessed: 27/28/13 seeds non-empty (0 before), 7 tokens accepted
  carrying 102 signature octets and 16 typed registered claims, 21 key-set documents
  accepted yielding 7 usable keys and 14 recorded skip reasons, 4 token responses
  accepted with 5 typed optional members. Acceptance alone would not have been reach —
  an unsecured JWT has a legitimately empty signature, `{"keys":[]}` is a legal key
  set, and a two-member token response parses — so each guard pins a second number the
  empty input cannot produce.

  ⭐ The `.network` column of the JWKS guard came out **1 against 7**: every symmetric
  seed the module's own value tests supply is refused as `oct_from_network`, so the
  second trust source — the reason `fuzzParseJwks` calls `parseJwksSource` twice —
  converted nothing until an EC key was added to the corpus.

- **2026-09-01** — **Security audit: the ML-DSA signature-length guard was blind, and
  a published private key was served happily.**

  `verifyMlDsa`'s length check sits in front of a slice-to-array coercion of
  2420/3309/4627 bytes. Deleting it left the whole suite green — ML-DSA was
  the only signature family without the wrong-length test its siblings have
  had all along. The guard was correct as shipped; nothing stopped a future
  edit from removing it. In Debug that regression is a remote panic; in
  ReleaseFast, which this suite also builds, there is no bounds check and it
  becomes a silent read of adjacent heap fed into `Signature.fromBytes`. Now
  pinned, including the two sizes a real mix-up produces — the other
  parameter sets'. The same blindness covered the AKP `pub`-length guards for
  ML-DSA-44 and -87 (only -65 was pinned); both now have tests.

  A JWKS fetched over the network whose key carries its PRIVATE component —
  `d` for RSA/EC/OKP, `priv` for AKP — is now skipped as `priv_from_network`,
  alongside the existing `oct_from_network`. RFC 7517 §4 and RFC 9964 §3 both
  say MUST NOT. The module never reads the private half, which is why this
  looked harmless; but a published one means the issuer's signing key is
  readable by anyone who can GET the document, so every token it "verifies"
  is forgeable and trusting it authenticates forgeries as genuine. A
  locally-configured set may still carry private material.

- **2026-09-01** — **Half of `fuzzParseJwks` never ran, and its comment claimed
  otherwise.** The harness opened with
  `parseJwksSource(…, .local) catch return`, and nearly every random byte
  string is a parse error — so the `.network` call after it was unreachable,
  and `std.testing.fuzz` without `--fuzz` runs the body once with an all-zero
  smith, which does not parse either. The comment above it claimed the
  harness proved the no-panic property "for both `.local` and `.network`
  trust sources (the latter has an extra oct-key rejection branch `.local`
  never takes)" — the branch it named was the one that never executed.

  This module already carries the lesson: `fuzzParseTokenResponse` has a
  comment warning that an early return is the skip-as-pass shape. The fix
  landed only where it had bitten. A probe placed after the `.network` call
  fires with the fix and never fires without it.

- **2026-09-01** — Docs and the outside caller caught up with RFC 9964:
  `SPEC.md` had no mention of ML-DSA, AKP or RFC 9964 anywhere, and its
  Anchoring inventory omitted the module's strongest external anchor (the
  three published Appendix A.1 vector pairs); README's API table listed
  neither the `.ml_dsa_*` `Key` variants nor their constructors; `meta.doc`,
  which is the source of truth for the generated catalog row, still described
  the module as "HS/ES/EdDSA/RSA". The example — the only thing that crosses
  the published-module boundary — was HS256-only, so the new family had zero
  outside-caller coverage; it now mints an ML-DSA-65 token, verifies it
  through a `kty:"AKP"` JWKS by `kid`, and demonstrates the published-private-key
  refusal.

  The audit verified the RFC 9964 vectors against the RFC itself
  (character-by-character, plus recomputing each `kid` as the RFC 7638
  thumbprint over `{alg, kty, pub}`) — **they are genuine**. That check
  mattered: the RFC's private seed is 32 zero bytes, so the module can
  regenerate all three public keys, and internal evidence alone could not
  have distinguished a real vector from a self-generated one.


- **2026-08-22** — `HttpFetcher.fetchFn` no longer folds a canceled body read into
  `error.FetchFailed`: `FetchError` gained a `Canceled` variant, and the request +
  both `readSliceShort` sites now consult `http.Client.Response.readFailure()`
  (added in `2c03d99` for exactly this) via a new `mapFetchError` widener. Public
  API addition — a caller matching exhaustively on `FetchError`, `DiscoverError`,
  `FetchJwksError`, or any error set built from them needs a new arm.
  `RefreshError`'s own `discover`/`fetchJwks` catches stay unaffected: they already
  widen with `else`, so a cancelation lands as `DiscoveryFailed`/`JwksFetchFailed`,
  consistent with `RefreshError`'s documented collapsing of the detailed sets.
  Proven by mutation: reverting the widener to always return `FetchFailed` fails
  the new cancellation test.
- **2026-08-22** — ML-DSA (FIPS 204) verification per RFC 9964: `alg` values
  `ML-DSA-44`/`-65`/`-87`, `kty:"AKP"` JWKs (`pub` + a REQUIRED `alg`), and the
  matching `Key` variants and constructors. Pure ML-DSA with an empty context
  string, which is what the RFC requires; HashML-DSA is not offered because the
  RFC does not specify it. The parameter set is read from `alg` and never
  inferred from the key length, even though the three lengths differ — the
  inference would accept a key whose `alg` and bytes disagree.

  Anchored on RFC 9964 Appendix A.1 rather than on a round trip: all three
  published (JWK, JWS) pairs verify, and because the RFC publishes the
  all-zero FIPS-204 seed, its public keys are also reproduced byte-exactly
  from `generateDeterministic` — so key generation is pinned by an outside
  authority too, not just verification. The vectors are JWS over plain text,
  so they cannot go through `parse` (a JWT payload must be JSON); that is
  asserted rather than glossed, and a JWT signed with the RFC's own key
  exercises the full `parse` -> `verifyWithJwks` path.

  Signature sizes are worth planning for: an ML-DSA-65 signature is 3309 bytes
  (~4.4 kB of base64url in the token) against Ed25519's 64.
- **2026-08-11** — Security audit: the `crit` header extension (RFC 7515 §4.1.11) was
  neither parsed nor rejected, so a token declaring a critical parameter this module
  does not understand was accepted anyway; fixed, along with an OIDC `azp` check that
  was only enforced for multi-audience tokens (RFC 8725 §4 requires it whenever `azp` is
  present at all), a CSRF/nonce generator whose own test asserted length and alphabet
  but not entropy, and 5 further findings.
- **2026-07-08** — New module: JWT/JWS + OIDC resource-server validator (RFC
  7515/7519/7517/8725).
