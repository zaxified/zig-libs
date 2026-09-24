# `tlsclient` — changelog

Newest first. See the root [`CHANGELOG.md`](../../CHANGELOG.md) for which
release tag each entry shipped in, and `CONVENTIONS.md` §8 for the policy.

## Unreleased

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
