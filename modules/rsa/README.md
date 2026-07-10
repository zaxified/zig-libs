# rsa

Pure-Zig RSA (PKCS#1 v2.2, RFC 8017) over `std.crypto.ff` — no bignum
reimplementation, no libc, no `@cImport`.

**Status: SKELETON — not yet implemented.** This module currently exposes
only the intended public API shape (types fully defined, function bodies
`@panic("TODO(agent): ...")`). It compiles and `zig build test-rsa` passes a
placeholder test, but calling any function beyond that panics. Planned phases:

- **P1 (next up)** — `signPkcs1v15`/`verifyPkcs1v15`: EMSA-PKCS1-v1_5
  signatures (RFC 8017 §8.2, §9.2) — the classic, still most widely deployed
  RSA signature scheme (TLS, JWT `RS256`, code signing).
- **P2** — `encryptOaep`/`decryptOaep`: RSAES-OAEP (RFC 8017 §7.1).
- **P3** — `signPss`/`verifyPss`: RSASSA-PSS (RFC 8017 §8.1).
- **P4** — `fromPkcs8`/`fromOpenSSH`: private-key parsing.
- **P5** — `generate`: keypair generation.
- **P6** — `selfSignedCert`: self-signed X.509 certificate generation.

- **Model after:** RFC 8017 (PKCS#1 v2.2); the shape of `PublicKey`/`SecretKey`/
  the RSAEP/RSAVP1 primitive is designed with reference to Zig std's own
  internal RSA verifier (`std.crypto.Certificate.rsa`, not `pub`) — this
  module is a clean, public, sign-capable superset of that shape (std's
  internal `rsa` only verifies signatures over certificates; it has no
  `SecretKey`, no CRT, no signing at all).
- **Platform:** any. **Role:** util (pure computation, no I/O of its own).
  **Concurrency:** reentrant — `PublicKey`/`SecretKey` are plain value types,
  no shared/global state.
- **Modular exponentiation:** via `std.crypto.ff` (`Modulus.pow` for
  secret-exponent/constant-time operations, `Modulus.powPublic` for
  public-exponent operations) — this module does not implement its own
  bignum or modexp.

## Provenance

Clean-room implementation from RFC 8017 (PKCS#1 v2.2) — a public IETF
specification, not a copyrightable work (see `CONVENTIONS.md` §5 / `NOTICE`
§0 policy). Design reference: Zig std's internal `std.crypto.Certificate.rsa`
(MIT-licensed, part of the Zig standard library the authors already build on)
— consulted for the `Modulus`/`Fe`/`PublicKey` shape and the RSAEP/RSAVP1
verification primitive's structure; **no source was copied**, and this
module's `SecretKey`/CRT/signing surface has no counterpart in std's internal
type to copy from in the first place (std's `rsa` struct is private and
verify-only).

When phase **P4** (key parsing) is implemented, it will add design references
to the OpenSSH `PROTOCOL.key` private-key format and OpenBSD's
`bcrypt_pbkdf` (both consulted for format/algorithm shape only, per the same
clean-room policy) — recorded here and in `NOTICE` at that time.

Explicitly: **no GPL/LGPL dependency, no copied foreign source** anywhere in
this module — spec-derived only, same as `hashdigest`/`sealedbox`. See
`NOTICE` for the canonical design-reference entry.

## API

```zig
const rsa = @import("rsa");

// Types (fully defined; constructors are stubs — see "Status" above).
const pk: rsa.PublicKey = ...;   // n: rsa.Modulus, e: rsa.Fe
const sk: rsa.SecretKey = ...;   // n, d, p, q, dp, dq, qinv

// P1 (stubbed — panics until implemented):
var sig_buf: [512]u8 = undefined; // >= modulus byte length
const sig = try rsa.signPkcs1v15(sk, std.crypto.hash.sha2.Sha256, msg, &sig_buf);
try rsa.verifyPkcs1v15(pk, std.crypto.hash.sha2.Sha256, msg, sig);
```

See `src/root.zig` for the full P1–P6 signature list (all reserved stubs are
documented there with their RFC 8017 section reference).
