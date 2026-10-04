# `tlsclient` — changelog

Newest first. See the root [`CHANGELOG.md`](../../CHANGELOG.md) for which
release tag each entry shipped in, and `CONVENTIONS.md` §8 for the policy.

## Unreleased

- **2026-10-04** — **mvp → core.** Two opt-in additions to std's client, every
  edit marked `zig-libs tlsclient`; with default options the handshake is std's
  byte for byte (tested against std's own ClientHello). **ALPN** (RFC 7301):
  `Options.alpn_protocols`, `Client.alpn_protocol`; the answer must be exactly
  one offered name (`TlsIllegalParameter` otherwise). **TLS 1.3 client
  certificates** (RFC 8446 §4.4.2-4.4.3): `Options.client_auth` (`ClientAuth`:
  DER chain + ECDSA P-256/P-384 or Ed25519 key); a request that excludes our
  scheme gets an empty Certificate (§4.4.2.3); key copies wiped after signing.
  New `InitError` members `AlpnProtocolsInvalid`, `ClientCertificateTooLarge`,
  `ClientKeyInvalid` (reachable only through the new options). openssl
  `s_server` interop for both (loopback, throwaway fixtures); mutation 23
  mutants, 1 surviving with a reason (SPEC). Session resumption, TLS 1.2 client
  auth and RSA client keys stay deferred.
- **2026-09-25** — Test fix: the chain fuzzer's corpus seeds are now wrapped
  by `testkit.fuzz.seedInto`. `Smith.slice` reads a 4-byte length first, so
  the raw seeds lost their first bytes and never reached the verifier. The
  corpus test now reads the seeds back through `Smith`, as the fuzzer does
  (raw seeds fail it). Reported by qap.
- **2026-09-25** — New module: Zig 0.16's `std.crypto.tls.Client` with the
  server chain verified by `x509.verifyChain` (RFC 5280: basicConstraints,
  keyUsage, pathLen, nameConstraints, extKeyUsage serverAuth) and every peer
  certificate guarded by `x509.safe` -- closes ziglang/zig #35877, where any
  certificate holder could impersonate any host. Anchored against
  `openssl s_server` (honest chain accepted, forged chain refused, std's own
  client still accepting it as the retirement tripwire). Found by qap's
  M6.2 security review.
