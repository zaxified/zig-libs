# rsa — spec

Design + threat notes for auditors. Usage: see ./README.md. Attribution/provenance: see
./README.md "Provenance" + /NOTICE.

## Design & invariants

**SKELETON — no design to audit yet.** This module is a pre-scaffold: `PublicKey`/`SecretKey`
have real fields (`n`/`e`; `n`/`d`/`p`/`q`/`dp`/`dq`/`qinv` — RFC 8017 §3.1/§3.2 CRT form), but
every function body that would perform actual modular arithmetic is
`@panic("TODO(agent): ...")`. The intended design (for the follow-up crypto-implementation agent):
low-level primitives named after RFC 8017 §5 (`rsaep`/`rsadp`/`rsadpCrt`/`rsasp1`/`rsavp1`) sit
under phase-named public schemes (`signPkcs1v15`/`verifyPkcs1v15` for P1, then OAEP/PSS/parsing/
keygen/cert-gen for P2–P6). All modular exponentiation routes through `std.crypto.ff`
(`Modulus.pow` for secret-exponent operations — constant-time; `Modulus.powPublic` for
public-exponent operations); this module must never implement its own bignum or a non-constant-time
exponentiation over secret data. `rsasp1`/`rsadpCrt` are the CRT fast path (RFC 8017 §5.1.2 form
(2)); `rsadp`/`d` (non-CRT) exist as the straightforward form and a correctness cross-check.
Modeled after RFC 8017 (PKCS#1 v2.2); `PublicKey`/`Modulus`/`Fe` shape designed with reference to
Zig std's internal `std.crypto.Certificate.rsa` (not `pub` — this module is a clean public
superset, not a re-export).

## Threat model / out of scope

**Not applicable yet** — no cryptographic operation is implemented, so there is nothing to attack
or defend. Once P1 lands, this section must be filled in before any consumer treats `rsa` as
production-ready, at minimum covering: constant-time requirements on every secret-dependent
operation (`rsadp`/`rsadpCrt`/`rsasp1`/CRT parameter handling — must use `Modulus.pow`, never
`powPublic`, and must not branch on secret data), signature-verification failure must be a clean
typed error (never a panic on attacker-controlled `sig`/`msg`/DER input), and the classic RSA
pitfalls: Bleichenbacher-style padding-oracle exposure (OAEP/PKCS1v1.5 decrypt, P2/P4), and
minimum modulus-size / small-public-exponent sanity checks on parsed keys (`fromBytes`/`fromDer`/
`fromPkcs8`).

## Verification

**None yet** — only a placeholder `test "rsa module compiles"` exists (asserts `true`, touches no
stub). Once P1 (`signPkcs1v15`/`verifyPkcs1v15`) is implemented it must be verified against RFC
8017's own worked examples / a recognized KAT set (e.g. NIST CAVP RSA2 vectors, or the RFC's own
Appendix C examples) before merging, following this repo's "Protocol codecs ... RFC known-answer
test vectors" verification-harness convention (CONVENTIONS.md §7). Run: `zig build test-rsa`.

## Backlog / deferred

- **P1** `signPkcs1v15`/`verifyPkcs1v15` (EMSA-PKCS1-v1_5, RFC 8017 §8.2/§9.2) — next up.
- **P2** `encryptOaep`/`decryptOaep` (RSAES-OAEP, RFC 8017 §7.1).
- **P3** `signPss`/`verifyPss` (RSASSA-PSS, RFC 8017 §8.1).
- **P4** `fromPkcs8`/`fromOpenSSH` (key parsing; OpenSSH `PROTOCOL.key` + `bcrypt_pbkdf` design refs
  will be added to README.md/NOTICE at that time).
- **P5** `generate` (keypair generation).
- **P6** `selfSignedCert` (self-signed X.509 certificate generation).
- Every item above is currently a `@panic("TODO(agent): ...")` stub — see `src/root.zig`.

## Status

`gap · any · util · reentrant` + deps: none (`std.crypto.ff` only) — canonical source is `pub const
meta` in src/root.zig. ("`gap`" here follows this repo's catalog-maturity vocabulary for "not yet
built"/"real gap remains" — see `extract` vs `gap` usage across other modules' SPEC.md Status
lines; CONVENTIONS.md's `meta` tag vocabulary itself has no separate "status" tag, so this is the
closest existing convention for "skeleton, not yet implemented.")
