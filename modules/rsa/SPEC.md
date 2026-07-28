# rsa — spec

Design + threat notes for auditors. Usage: see ./README.md. Attribution/provenance: see
./README.md "Provenance" + /NOTICE.

## Design & invariants

**ALL PHASES (P1–P6) IMPLEMENTED** — no `@panic`/TODO stub remains in `src/root.zig` or
`src/openssh.zig`. Low-level primitives named after RFC 8017 §5 (`rsaep`/`rsadp`/`rsadpCrt`/
`rsasp1`/`rsavp1`) sit under phase-named public schemes:

- **P1** `signPkcs1v15`/`verifyPkcs1v15` (EMSA-PKCS1-v1_5, RFC 8017 §8.2/§9.2, SHA-1/224/256/384/512).
- **P2** `encryptOaep`/`decryptOaep` (RSAES-OAEP, RFC 8017 §7.1, MGF1, constant-time decode) plus
  the decoupled-hash variant `encryptOaepH`/`decryptOaepH` (label/digest hash and MGF1 hash may
  differ per RFC 8017 §7.1 — e.g. XML-Encryption `rsa-oaep` with digest=SHA-256, MGF1=SHA-1); the
  coupled forms delegate to the decoupled ones with both hashes equal.
- **P3** `signPss`/`verifyPss` (RSASSA-PSS, RFC 8017 §8.1, branch-clean verify).
- **P4a** DER/PEM key parsing (`PublicKey.fromDer`/`fromPem`, `SecretKey.fromDer`/`fromPkcs8`/
  `fromPem`, cleartext PEM only).
- **P4b** OpenSSH `PROTOCOL.key` private-key parsing (`fromOpenSSH`: unencrypted and
  bcrypt/aes256-ctr/aes256-cbc encrypted, with a from-scratch Blowfish + bcrypt-pbkdf in
  `openssh.zig`).
- **P5** `generate` (keypair generation: probable primes via sieve + Miller-Rabin, FIPS
  186-5-style constraints).
- **P6** `selfSignedCert` (X.509 v3 self-signed certificate generation, RFC 5280).

All modular exponentiation routes through the sibling `montint` module (a full-radix-2^64,
Montgomery-resident, constant-time modexp, ~3× faster than `std.crypto.ff` on the portable path —
see "Speed" below); `std.crypto.ff` (`Modulus`/`Fe`) remains the canonical big-integer carrier for
key material, CRT recombination (Garner), reductions, and serialization. This module must never
implement its own bignum or a non-constant-time exponentiation over secret data. `rsasp1`/
`rsadpCrt` are the CRT fast path (RFC 8017 §5.1.2 form (2)); `rsadp`/non-CRT `d` exist as the
straightforward form and a correctness cross-check. Modeled after RFC 8017 (PKCS#1 v2.2);
`PublicKey`/`Modulus`/`Fe` shape designed with reference to Zig std's internal
`std.crypto.Certificate.rsa` (not `pub` — this module is a clean public superset, not a re-export).

**Speed.** The modular-exponentiation hot path (CRT private op mod p / mod q, non-CRT private op
mod n, public op mod n) is routed through `montint`; the deep audit measured plain `std.crypto.ff`
at ~29× OpenSSL for the CRT sign, and `montint` closes most of that gap. `MontParams` are
precomputed once per key at construction, so no per-operation setup cost is paid.

**Hardening (post-audit, see `~/CML/audit/modules/rsa.md`).** The CRT private op (`privateOpCrt`)
carries both fault- and side-channel countermeasures: F3 (Bellcore/BDL) — every CRT private op
re-encrypts the recovered `m` and checks `m^e ≡ c (mod n)`, returning `error.FaultDetected` on
mismatch rather than handing an attacker a faulty value that could factor `n`; F2 (base blinding) —
when an rng is available, the op runs on `c·r^e mod n` for a fresh random unit `r` and unblinds by
`r⁻¹ mod n`.

## Threat model / out of scope

Constant-time requirements on every secret-dependent operation (`rsadp`/`rsadpCrt`/`rsasp1`/CRT
parameter handling — routes through `montint`/`Modulus.pow`, never a public-exponent path, and
never branches on secret data); signature-verification failure is a clean typed error, never a
panic, on attacker-controlled `sig`/`msg`/DER/OpenSSH input. Bleichenbacher-style padding-oracle
exposure is addressed by OAEP's constant-time single-generic-error decrypt path (P2) and by
PKCS1-v1.5 decrypt/verify never branching on which padding check failed. CRT fault injection is
addressed by the F3 re-encrypt-and-compare check (see "Hardening" above). Minimum modulus-size /
small-public-exponent sanity checks apply to parsed keys (`fromBytes`/`fromDer`/`fromPkcs8`/
`fromOpenSSH`).

## Verification

`zig build test-rsa` is green across `root.zig` and `openssh.zig`. Anchored
against OpenSSL-generated known-answer vectors: keys generated with `openssl genpkey -algorithm
RSA` (OpenSSL 3.5.5, 2026-07-10), components dumped via `openssl pkey -text`, signatures produced
with `openssl dgst -shaN -sign` for PKCS1-v1.5 (deterministic, so these are byte-exact KATs) and
`openssl dgst -sigopt rsa_padding_mode:pss` for PSS. `generate`, `selfSignedCert`, and the
bcrypt-pbkdf inside OpenSSH parsing are additionally cross-checked against `std.crypto.Certificate`
/ `std.crypto.pwhash.bcrypt.opensshKdf` as independent oracles (not just this module's own code).
The OAEP mismatched-hash case (`encryptOaepH`/`decryptOaepH` with digest≠MGF1) has no external
byte-exact vector (the shipped OpenSSL OAEP KATs are all equal-hash) — it is covered only by a
constructed round-trip test, which proves internal consistency but not agreement with an external
implementation for that specific configuration.

## Backlog / deferred

- The OAEP decoupled-hash (digest≠MGF1) configuration has no external KAT — see "Verification"
  above.
- Anything not covered by the phase list above (there is no known scope gap versus RFC 8017 P1–P6
  today; flag here if one is found).

## Status

`extract · any · util · reentrant` + deps: `montint` (hot-path modexp), `std.crypto.ff` (key
material/serialization) — canonical source is `pub const meta` in src/root.zig.
