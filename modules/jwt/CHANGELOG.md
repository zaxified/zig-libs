# jwt — changelog

Newest first. See the root [`CHANGELOG.md`](../../CHANGELOG.md) for which
release tag each entry shipped in, and `CONVENTIONS.md` §8 for the policy.

## Unreleased

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
