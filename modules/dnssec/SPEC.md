# dnssec — spec

Design + threat notes for auditors. Usage: see ./README.md. Provenance: see
./README.md "Provenance" (no `NOTICE` entry needed — clean-room from RFC,
no third-party source ported).

## Design & invariants

**Validation core implemented + oracle-verified.** Real, tested:
`wire.zig` (uncompressed-name decode + canonical name encoding), `rdata.zig`
(DNSKEY/RRSIG/DS/NSEC/NSEC3/NSEC3PARAM parsing, Type Bit Maps, key tag),
`nsec3.zig`'s base32hex + iterated-SHA-1 hash AND its RFC 5155 §8 denial
proof (`proveDenial`), `keys.zig`'s per-algorithm DNSKEY decode + signature
verify dispatch, `ds.zig`'s digest computation, `canonical.buildSignedData`
(RFC 4034 §3.1.8.1), `chain.validateDnskeySet`, and `root.zig`'s
`rrsigTimeValid` + `validate`. All four protocol-logic pieces
(`buildSignedData`, `proveDenial`, `validateDnskeySet`, `validate`) are
validated against an `ldns`-signed, `ldns-verify-zone`-cross-checked oracle
(algorithms 8/13/14/15; NSEC + NSEC3 + Opt-Out; wildcard; NODATA + NXDOMAIN)
— see README.md "Validation core" + `src/oracle_test.zig`.

The plain-NSEC (non-NSEC3) denial proof analogous to `nsec3.proveDenial` IS now
built (`nsec.proveDenial`: RFC 4035 §5.4 gap coverage over the RFC 4034 §6.1
canonical name order, NODATA, wildcard, and insecure-delegation), unit-tested
but not yet `ldns`-oracle-verified the way the NSEC3 proof is.

Out of scope in this module (see "Threat model" below): RFC 8624
algorithm-downgrade policy, RFC 9276 NSEC3 iteration caps, and the
multi-zone-cut resolver orchestration.

- **Bounds-checked, no panics on attacker input.** `rdata.zig`/`wire.zig`
  follow the same discipline as `dns.message`: malformed RDATA is a typed
  error, never a panic. The validation core fails closed — any
  parse/decode/verify error on attacker-controlled bytes collapses to
  `.bogus` (only `error.OutOfMemory` propagates). No `@panic("TODO...")`
  stubs remain.
- **No new cryptographic primitive.** Every signature-verify call routes
  through `std.crypto.sign.ecdsa`/`std.crypto.sign.Ed25519` (public, std
  0.16) or this repo's own `rsa.verifyPkcs1v15` (std's own RSA verifier,
  `std.crypto.Certificate.rsa`, is not `pub`). This module's only original
  logic is DNSSEC's own wire formats (RFC 3110/6605/8080 key encodings, the
  RRSIG/DS/NSEC/NSEC3 RDATA shapes), the canonical signed-data assembly, and
  the denial-of-existence proof — never bignum/ECC/EdDSA math itself.
- **Single-zone-cut scope for `validate`/`chain.validateDnskeySet`.**
  Climbing the full delegation chain from a root trust anchor down to the
  target name (multiple zone cuts, each needing its own DNSKEY/DS round
  trip) is the future secure-resolver consumer's job, calling this module
  once per cut. This module validates one RRset against one already-fetched
  DNSKEY set — see `chain.zig`'s doc comment for the reasoning (matches how
  unbound/BIND/Knot Resolver factor the same problem).
- **RRSIG time-window uses RFC 1982 serial arithmetic** (`rrsigTimeValid`),
  not a naive integer compare — the 32-bit inception/expiration fields wrap
  in 2106, and a naive compare would silently misvalidate near that
  boundary. Cheap to get right now, so it is; see the wraparound unit test.

## Threat model / out of scope

The `.secure`/`.bogus` verdict IS attackable now, so:

- `rdata.zig`/`wire.zig` parsers reject malformed RDATA (bad lengths,
  out-of-range Type Bit Map windows, oversized names) with a typed error;
  the validation core (`canonical`/`chain`/`nsec3`/`validate`) turns every
  non-OOM error into `.bogus`. Corpus-fuzzing these the way `dns.message`
  fuzzes its own decoder remains a natural follow-up (not done yet).
- `keys.zig`'s signature verification fails closed: any decode or verify
  error collapses to `error.SignatureVerificationFailed`/
  `error.InvalidKeyEncoding`/`error.InvalidSignatureEncoding` — never a
  panic on attacker-controlled key/signature bytes, and never a
  Bleichenbacher-style distinguishable-error channel (the underlying
  `rsa.verifyPkcs1v15` already commits to constant-time, full-encoding
  comparison — see `rsa`'s own SPEC.md).
- **Still out of scope, must land before production use as a resolver:**
  - **Algorithm-downgrade resistance (RFC 8624).** `validate` verifies the
    RRSIG it is handed; it does not enforce a policy that rejects a
    weak/deprecated algorithm when a stronger one is present in the same
    DNSKEY set. A consumer must apply RFC 8624 algorithm selection.
  - **NSEC3 iteration-count DoS (RFC 9276).** `nsec3.proveDenial` /
    `iteratedHash` honour whatever iteration count the record carries; there
    is no cap, so a malicious high count is an amplification vector. A
    consumer must reject/limit per RFC 9276 (recommended: 0).
  - **Plain-NSEC denial proof.** `nsec.proveDenial` implements the NSEC-based
    NXDOMAIN/NODATA/wildcard/insecure-delegation reasoning (the analogue of
    `nsec3.proveDenial`) over the RFC 4034 §6.1 canonical name order. Like the
    NSEC3 proof it assumes the NSEC RRs were already signature-validated
    (`validate`); it verifies the *logic* of the denial, not the RRs' own
    authenticity. Unit-tested, not yet `ldns`-oracle-verified.
  - **Opt-Out** is handled (`proveDenial` downgrades an opt-out NXDOMAIN to
    `.insecure` rather than asserting secure non-existence), but the wider
    "opt-out cannot hide an otherwise-signed delegation" property is the
    resolver's to enforce across cuts.

## Verification

`zig build test-dnssec` — runs entirely offline (Debug + ReleaseFast, both
green; `zig fmt --check` clean). Mechanical unit tests over the
parsers/hashers plus end-to-end known-answer tests. The KATs use a REAL
offline oracle:
zones signed by `ldns-signzone`/`ldns-keygen` across algorithms 8/13/14/15
(RSA-SHA256, ECDSA-P256, ECDSA-P384, Ed25519), with NSEC, NSEC3 and NSEC3
Opt-Out, a wildcard, and NODATA/NXDOMAIN denial cases — each source zone
independently accepted by **`ldns-verify-zone`** (an independent reference
validator, so the KATs are not self-referential). Because a real RRSIG only
verifies over byte-exact RFC 4034 §3.1.8.1 canonical data, a `.secure`
verdict is itself the byte-exactness proof; the matching tampered
(signature/digest byte flipped) cases return `.bogus`. Vectors:
`src/oracle_vectors.zig`; KATs: `src/oracle_test.zig`; reproduction harness
(zone + `extract.py`, using `dnspython`): `scratchpad/dnssec-oracle/`.
Remaining: corpus-fuzz the parsers; external RFC 6605/8080 published test
vectors as a second independent cross-check.
