# rsa

Pure-Zig RSA (PKCS#1 v2.2, RFC 8017) over `std.crypto.ff` — no bignum
reimplementation, no libc, no `@cImport`.

Phases P1–P6 below are all implemented, anchored against OpenSSL-generated known-answer vectors and
Wycheproof (see *Verification*). Dependencies: `montint` (the modexp hot path), `aescbc` and `aes192` (PBES2 encrypted
PKCS#8), `b64ct` (constant-time PEM base64 of private keys), `keycodec` (the PEM block walk, PKCS#8 and SPKI readers).

- **P1** — `signPkcs1v15`/`verifyPkcs1v15`: EMSA-PKCS1-v1_5
  signatures (RFC 8017 §8.2, §9.2) — the classic, still most widely deployed
  RSA signature scheme (TLS, JWT `RS256`, code signing).
- **P2** — `encryptOaep`/`decryptOaep`: RSAES-OAEP (RFC 8017 §7.1), plus
  the decoupled-hash `encryptOaepH`/`decryptOaepH` (label/digest hash and
  MGF1 hash may differ, e.g. XML-Enc `rsa-oaep` digest=SHA-256/MGF1=SHA-1).
- **P3** — `signPss`/`verifyPss`: RSASSA-PSS (RFC 8017 §8.1); salt
  recovery `verifyPssAuto`, `maxPssSaltLen`, decoupled MGF1 `signPssH`/`verifyPssH`.
- **Digests** — `*Prehashed` (comptime hash) and `*Digest` (run-time
  `HashId`: SHA-1, SHA-2 incl. 512/224, 512/256, SHA-3) sign and verify a
  digest the caller already holds (Go `SignPKCS1v15(hash, digest)`).
- **P4** — `fromDer`/`fromPem`/`fromPkcs8`/`fromOpenSSH`: key parsing
  (DER/PEM PKCS#1/PKCS#8/SPKI, and OpenSSH `PROTOCOL.key` incl. bcrypt/
  aes256-ctr/aes256-cbc encrypted private keys); password-protected PKCS#8
  (PBES2/PBKDF2/AES-CBC, what `openssl genpkey -aes256` writes) through
  `fromPkcs8Encrypted`/`SecretKey.fromPemEncrypted` (`…Limited` twins take
  a caller's PBKDF2 iteration cap). On-disk `n`/`d`/CRT fields are checked
  against the key derived from `p`, `q`, `e`; primality of `p`, `q` is not
  tested (as Go and BoringSSL) unless `fromPrimesWith(.., .{ .check_primality
  = true })` asks for it.
- **Writing keys** — `toPkcs1Der`/`toSpkiDer`/`toPkcs8Der`/`toPem` and
  `toPkcs8Encrypted`/`toPemEncrypted`: byte-identical to OpenSSL 3's output
  for the same key (encrypted: same shape, fresh salt and IV).
- **P5** — `generate`: keypair generation (probable primes via sieve +
  Miller-Rabin, FIPS 186-5-style constraints).
- **P6** — `selfSignedCert`: self-signed X.509 v3 certificate generation
  (RFC 5280).
- **`der_writer`** — the arena-backed DER encoder `selfSignedCert` uses,
  shared with `acme` and `ocsp` (`Builder.seq`, `.integer`, `.explicit`, …).

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
  full-radix-2^64, Montgomery-resident, constant-time modexp, much faster
  than `std.crypto.ff`); `std.crypto.ff` (`Modulus`/
  `Fe`) remains the carrier for key material, CRT recombination, and
  serialization. This module does not implement its own bignum.
- **Hardening:** the CRT private op carries fault detection (Bellcore/BDL:
  re-encrypt-and-compare, `error.FaultDetected` on mismatch rather than
  leaking a faulty value) and, when a `Blinding.csprng` is supplied, base
  blinding.
- **The blinding seam:** `signPss` blinds always. The deterministic entry
  points — `signPkcs1v15`, `decryptOaep`/`decryptOaepH`, `rsadpCrt` — take no
  generator (std removed `std.crypto.random` in 0.16; still absent in 0.17) and default to
  `Blinding.none`; each has a `…Blinded` twin taking an explicit `Blinding`,
  so a consumer whose input is attacker-chosen (an OAEP decryption oracle
  above all) can turn masking on without editing the module. Output is
  byte-identical either way; only the side-channel posture differs.
- **Cached blinding** (`Blinding.cached`, the OpenSSL scheme): a server that
  blinds every op keeps one `BlindingCache` per thread and saves ~5 % of a
  2048-bit op over `.csprng`. The cache holds key material — wipe it:

  ```zig
  var cache = rsa.BlindingCache.init(csprng.random());
  defer cache.deinit();
  const pt = try rsa.decryptOaepBlinded(&sk, Sha256, .{ .cached = &cache }, ct, "", &buf);
  ```

## Provenance

Clean-room implementation from RFC 8017 (PKCS#1 v2.2) — a public IETF
specification, not a copyrightable work (see `CONVENTIONS.md` §5 / root
`NOTICE` §0 policy). Design references: Zig std's internal
`std.crypto.Certificate.rsa` (MIT-licensed, part of the Zig standard library
the authors already build on) — consulted for the `Modulus`/`Fe`/`PublicKey`
shape and the RSAEP/RSAVP1 verification primitive's structure; **no source was
copied**, and this module's `SecretKey`/CRT/signing surface has no counterpart
in std's internal type to copy from in the first place (std's `rsa` struct is
private and verify-only). The OpenSSH `PROTOCOL.key` private-key container
format and OpenBSD's `bcrypt_pbkdf` (Ted Unangst) — both format/algorithm shape
only, implemented from their published descriptions — are additional design
references for the P4 key-parsing phase, as is Schneier's published Blowfish
paper (FSE '93), whose P-array/S-box pi constants were independently
recomputed, not copied. See [`NOTICE`](NOTICE) beside this file for the full
design-reference list (RFC 5280, RFC 5208, RFC 7468, RFC 4251 §5) and for the
validation-only test-vector sources.

Explicitly: **no GPL/LGPL dependency, no copied foreign source** anywhere in
this module — spec-derived only, same as `hashdigest`/`sealedbox`.
## API

```zig
const rsa = @import("rsa");

const pk: rsa.PublicKey = ...;   // n: rsa.Modulus, e: rsa.Fe
const sk: rsa.SecretKey = ...;   // n, d, p, q, dp, dq, qinv

// P1 — PKCS1-v1.5 sign/verify:
var sig_buf: [512]u8 = undefined; // >= modulus byte length
const sig = try rsa.signPkcs1v15(&sk, std.crypto.hash.sha2.Sha256, msg, &sig_buf);
try rsa.verifyPkcs1v15(pk, std.crypto.hash.sha2.Sha256, msg, sig);
```

See `src/root.zig` for the full P1–P6 API surface, each function documented
with its RFC 8017 section reference.

## Limits

- **Modulus size:** 1024 to 8192 bits (`max_modulus_bits`; the build option `rsa-max-modulus-bits` lowers the cap to as
  little as 4096, and `-Dprofile=small` sets 4096). Smaller moduli are refused by every public-key constructor, by
  `generate` and by every private-key constructor (the testing-only escape is the `insecure_allow_small_modulus` option of
  the `…With` constructors); larger ones are refused, never truncated.
- **Blinding is off by default** in the deterministic entry points (`signPkcs1v15`, `decryptOaep*`, `rsadpCrt`); use the
  `…Blinded` twins when the input is attacker-chosen. The constant-time modexp and the CRT fault check run either way.
- **`SecretKey.fromPrimes` trusts `p` and `q` to be prime** (it checks structure, not primality); a composite fails late,
  at the first signature.
- **Encrypted keys:** PBES2 with PBKDF2 and AES-CBC only (PBKDF2 iterations capped at 2^20), and OpenSSH containers
  with bcrypt rounds capped at 2048. A `BlindingCache` is one per thread and must be wiped.

## Not provided

RSAES-PKCS1-v1_5 encryption and decryption, multi-prime keys, scrypt/PBES1/legacy `DEK-Info` PEM encryption and moduli above
8192 bits; see `SPEC.md` *What is deliberately not done* (reasons) and *Backlog / deferred* (scrypt).

## Verification

`scripts/modtest rsa`. The scheme tests are anchored against OpenSSL-generated known-answer vectors (keys from
`openssl genpkey -algorithm RSA`, signatures from `openssl dgst -shaN -sign`, PSS with `-sigopt rsa_padding_mode:pss`) and
Wycheproof's RSA vectors (PKCS#1 v1.5 and PSS verify, OAEP decrypt, including the digest≠MGF1 configuration of
`decryptOaepH`); `generate`, `selfSignedCert` and the OpenSSH bcrypt-pbkdf are cross-checked against `std.crypto.Certificate` /
`std.crypto.pwhash.bcrypt.opensshKdf`. See `SPEC.md` *Verification*.
