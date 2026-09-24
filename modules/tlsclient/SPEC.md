# `tlsclient` — specification

## What this module is, and what it is not

A copy of Zig 0.16.0's `std.crypto.tls.Client` whose handling of the
server's Certificate message is replaced: std parses each certificate bare
and verifies it link by link against the next (issuer name, validity,
signature), stopping at the first one the bundle vouches for. That walk
never reads basicConstraints (ziglang/zig #35877, open since 2026-06-21), so
a leaf signed by another leaf is accepted -- anyone with one certificate can
impersonate any host. Here:

1. every certificate is proven well-formed by `x509.safe.validateCertificate`
   before `std.crypto.Certificate.parse` sees it (std's DER element parser
   reads out of bounds on malformed input -- `x509` SPEC, `safe.zig`);
2. the leaf is parsed for the hostname check (std's `verifyHostName`,
   unchanged) and the CertificateVerify key, as before;
3. the whole chain goes to `x509.verifyChain` with the bundle's certificates
   for every issuer name the chain mentions as trust anchors, and
   `required_eku = .server_auth` (`verify.zig`).

**Not here, on purpose:** any other change to std's client. No new options,
no new API: a consumer changes one import. Not revocation (OCSP/CRL), not
certificate transparency -- std has neither, and adding them is not this
module's job. `.ca = .self_signed` and `.no_verification` behave as in std.

## Limits and refusals

- **At most 10 certificates** in a server's Certificate message
  (`verify.max_chain_len`): real chains are 2-4; `x509.Options.max_intermediates`
  is 8. More is `error.TlsCertificateNotVerified`.
- **A certificate over `x509.safe.max_certificate_len` (8 KiB)** is refused.
- **An empty Certificate message** is refused at once (std failed on the
  next message instead).
- `verifyChain` runs in a 16 KiB stack `FixedBufferAllocator`; running out is
  a refusal, never a partial verification.

## Updating the copy

A comptime check in `root.zig` refuses any Zig but 0.16. On an upgrade:
first check #35877. If std now checks CA constraints, the tripwire test in
`interop_test.zig` ("std's client still accepts the forged chain") is red --
retire this module and point `http` back at `std.crypto.tls`. If not,
re-copy the new std `Client.zig`, re-apply the Certificate-message change
(search for `zig-libs tlsclient`) and the `@import("std")` line, and record
the new file's sha256 in NOTICE.

## Anchoring

- **External anchor:** `interop_test.zig` drives the handshake against
  `openssl s_server` (skipped when `openssl` is absent) with openssl-made
  chains (`src/testdata/`, recipe in its README): the honest chain verifies,
  the forged chain (leaf signed by another leaf's key -- OpenSSL's own
  `verify` refuses it with "invalid CA certificate") is refused, and std's
  client still accepts it. The verification decision itself is `x509`'s,
  anchored in that module.
- A mutant that drops the `verifyAgainstBundle` call turns the forged-chain
  interop test red (checked 2026-09-25).

**Anchor grade:** class A · oracle EXTERNAL
