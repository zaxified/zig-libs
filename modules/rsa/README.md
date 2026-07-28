# rsa

Pure-Zig RSA (PKCS#1 v2.2, RFC 8017) over `std.crypto.ff` — no bignum
reimplementation, no libc, no `@cImport`.

**Status: ALL PHASES (P1–P6) IMPLEMENTED.** No `@panic`/TODO stub remains
in `src/root.zig` or `src/openssh.zig`. `zig build test-rsa` is green across
`root.zig` and `openssh.zig`, anchored against OpenSSL-generated known-answer
vectors (see "Verification" below).

- **P1** — `signPkcs1v15`/`verifyPkcs1v15`: EMSA-PKCS1-v1_5
  signatures (RFC 8017 §8.2, §9.2) — the classic, still most widely deployed
  RSA signature scheme (TLS, JWT `RS256`, code signing).
- **P2** — `encryptOaep`/`decryptOaep`: RSAES-OAEP (RFC 8017 §7.1), plus
  the decoupled-hash `encryptOaepH`/`decryptOaepH` (label/digest hash and
  MGF1 hash may differ, e.g. XML-Enc `rsa-oaep` digest=SHA-256/MGF1=SHA-1).
- **P3** — `signPss`/`verifyPss`: RSASSA-PSS (RFC 8017 §8.1).
- **P4** — `fromDer`/`fromPem`/`fromPkcs8`/`fromOpenSSH`: key parsing
  (DER/PEM PKCS#1/PKCS#8/SPKI, and OpenSSH `PROTOCOL.key` incl. bcrypt/
  aes256-ctr/aes256-cbc encrypted private keys).
- **P5** — `generate`: keypair generation (probable primes via sieve +
  Miller-Rabin, FIPS 186-5-style constraints).
- **P6** — `selfSignedCert`: self-signed X.509 v3 certificate generation
  (RFC 5280).

- **Model after:** RFC 8017 (PKCS#1 v2.2); the shape of `PublicKey`/`SecretKey`/
  the RSAEP/RSAVP1 primitive is designed with reference to Zig std's own
  internal RSA verifier (`std.crypto.Certificate.rsa`, not `pub`) — this
  module is a clean, public, sign-capable superset of that shape (std's
  internal `rsa` only verifies signatures over certificates; it has no
  `SecretKey`, no CRT, no signing at all).
- **Platform:** any. **Role:** util (pure computation, no I/O of its own).
  **Concurrency:** reentrant — `PublicKey`/`SecretKey` are plain value types,
  no shared/global state.
- **Modular exponentiation:** the hot path (CRT private op, non-CRT
  private op, public op) is routed through the sibling `montint` module (a
  full-radix-2^64, Montgomery-resident, constant-time modexp — ~3× faster
  than `std.crypto.ff` on the portable path); `std.crypto.ff` (`Modulus`/
  `Fe`) remains the carrier for key material, CRT recombination, and
  serialization. This module does not implement its own bignum.
- **Hardening:** the CRT private op carries fault detection (Bellcore/BDL:
  re-encrypt-and-compare, `error.FaultDetected` on mismatch rather than
  leaking a faulty value) and base blinding when an rng is available.

## Provenance

Clean-room implementation from RFC 8017 (PKCS#1 v2.2) — a public IETF
specification, not a copyrightable work (see `CONVENTIONS.md` §5 / `NOTICE`
§0 policy). Design references: Zig std's internal `std.crypto.Certificate.rsa`
(MIT-licensed, part of the Zig standard library the authors already build on)
— consulted for the `Modulus`/`Fe`/`PublicKey` shape and the RSAEP/RSAVP1
verification primitive's structure; **no source was copied**, and this
module's `SecretKey`/CRT/signing surface has no counterpart in std's internal
type to copy from in the first place (std's `rsa` struct is private and
verify-only). The OpenSSH `PROTOCOL.key` private-key container format and
OpenBSD's `bcrypt_pbkdf` (both format/algorithm shape only) are additional
design references for the P4 key-parsing phase — see `NOTICE` for the full
design-reference list (RFC 5280, RFC 5208, RFC 7468, RFC 4251 §5, Blowfish's
published spec).

Explicitly: **no GPL/LGPL dependency, no copied foreign source** anywhere in
this module — spec-derived only, same as `hashdigest`/`sealedbox`. See
`NOTICE` for the canonical design-reference entry.

## API

```zig
const rsa = @import("rsa");

const pk: rsa.PublicKey = ...;   // n: rsa.Modulus, e: rsa.Fe
const sk: rsa.SecretKey = ...;   // n, d, p, q, dp, dq, qinv

// P1 — PKCS1-v1.5 sign/verify:
var sig_buf: [512]u8 = undefined; // >= modulus byte length
const sig = try rsa.signPkcs1v15(sk, std.crypto.hash.sha2.Sha256, msg, &sig_buf);
try rsa.verifyPkcs1v15(pk, std.crypto.hash.sha2.Sha256, msg, sig);
```

See `src/root.zig` for the full P1–P6 API surface, each function documented
with its RFC 8017 section reference.

## Verification

`zig build test-rsa` is green across `root.zig` and `openssh.zig`. Anchored
against OpenSSL-generated known-answer vectors: keys via
`openssl genpkey -algorithm RSA`, signatures via `openssl dgst -shaN -sign`
(PKCS1-v1.5) and `openssl dgst -sigopt rsa_padding_mode:pss` (PSS).
`generate`, `selfSignedCert`, and the OpenSSH bcrypt-pbkdf are additionally
cross-checked against `std.crypto.Certificate` / `std.crypto.pwhash.bcrypt.
opensshKdf` as independent oracles. The OAEP decoupled-hash configuration
(digest≠MGF1) has no external byte-exact vector — only an internal
round-trip test; see `SPEC.md`'s backlog.
