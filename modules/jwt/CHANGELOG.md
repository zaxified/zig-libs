# jwt — changelog

Newest first. See the root [`CHANGELOG.md`](../../CHANGELOG.md) for which
release tag each entry shipped in, and `CONVENTIONS.md` §8 for the policy.

## Unreleased

- **2026-08-11** — Security audit: the `crit` header extension (RFC 7515 §4.1.11) was
  neither parsed nor rejected, so a token declaring a critical parameter this module
  does not understand was accepted anyway; fixed, along with an OIDC `azp` check that
  was only enforced for multi-audience tokens (RFC 8725 §4 requires it whenever `azp` is
  present at all), a CSRF/nonce generator whose own test asserted length and alphabet
  but not entropy, and 5 further findings.
- **2026-07-08** — New module: JWT/JWS + OIDC resource-server validator (RFC
  7515/7519/7517/8725).
