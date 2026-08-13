# aeadframe — changelog

Newest first. See the root [`CHANGELOG.md`](../../CHANGELOG.md) for which
release tag each entry shipped in, and `CONVENTIONS.md` §8 for the policy.

## Unreleased

- **2026-08-06** — Security audit: four findings fixed (part of the collection-wide
  audit; the root changelog records no further detail than this). Modeled on IPsec ESP
  (RFC 4303) / DTLS 1.3 record layer (design reference, not a test anchor).
- **2026-07-24** — New module: Per-key AEAD record layer — seal/open with a monotonic
  counter nonce (never reused), epoch rekey, sliding-window anti-replay + AAD binding;
  generic over the AEAD.
