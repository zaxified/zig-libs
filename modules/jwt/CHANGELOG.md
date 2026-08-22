# jwt — changelog

Newest first. See the root [`CHANGELOG.md`](../../CHANGELOG.md) for which
release tag each entry shipped in, and `CONVENTIONS.md` §8 for the policy.

## Unreleased

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
