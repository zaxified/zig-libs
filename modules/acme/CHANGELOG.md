# acme — changelog

Newest first. See the root [`CHANGELOG.md`](../../CHANGELOG.md) for which
release tag each entry shipped in, and `CONVENTIONS.md` §8 for the policy.

## Unreleased

- **2026-08-13** — New `jws.generateKeyPair(io)`, and both certificate-key draws
  (`Client.obtain`'s issuance key and `publishTlsAlpn01`'s TLS-ALPN-01
  validation key) now use it. It is
  `std.crypto.sign.ecdsa.EcdsaP256Sha256.KeyPair.generate` verbatim with
  the seed taken from `entropy.fill` (`std.Io.randomSecure`) rather than
  `io.random`, whose contract permits a silent fallback to a weaker seed
  (`std/Io.zig:2462`). **Not breaking:** no signature changed and
  `jws.KeyPair` is still the same std type. New dep: `entropy`.

  Callers should mint the **account key** with `jws.generateKeyPair(io)`
  too — the doc comments on `Client.init` and the module example now say
  so. The account key authenticates every request to the CA for the life
  of the account and a certificate key is what a publicly-trusted
  certificate attests to; neither is recoverable after the fact.
- **2026-07-18** — Security audit: two findings fixed (part of the collection-wide
  audit; the root changelog records no further detail than this). Verified against RFC
  8555 §6.2.
