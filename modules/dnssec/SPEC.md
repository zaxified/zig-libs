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
  - ~~NSEC3 iteration-count DoS (RFC 9276).~~ **Fixed.** `nsec3.proveDenial`
    rejects (`.insecure`, before any hashing work) any set whose iteration
    count exceeds `max_nsec3_iterations` (100, RFC 9276 §3.2's recommended
    ceiling) — this bullet used to say "there is no cap"; there has been one
    since the 07-19 audit round (this file had drifted from the code).
    ⭐ **Also fixed (audit A1 F2, 2026-09-10):** the closest-encloser search's
    OTHER amplification axis, record-set size, is now bounded too
    (`max_nsec3_records`) and the per-candidate owner-hash decode that used to
    re-run once per closest-encloser candidate now runs once per `proveDenial`
    call — O(depth) candidates × O(1) amortized lookup instead of O(depth ×
    |set|). Measured (ReleaseFast, 885 records, 253-octet/127-label qname):
    22.6 ms → 1.1 ms, ~20×.
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
  - **Wildcard expansion is not accompanied by a denial-of-existence
    requirement (audit A1 F7).** `validate` accepts an RRSIG whose `labels`
    is less than the owner name's own label count (a wildcard-synthesized
    answer, RFC 4034 §3.1.3) purely on the signature verifying — it does not
    itself demand a matching NSEC/NSEC3 proof that no exact-match record
    exists for the queried name (RFC 4035 §5.3.4: a resolver accepting a
    wildcard answer MUST also verify that proof). `nsec.proveDenial` and
    `nsec3.proveDenial` both already implement that denial, so this is a
    responsibility split, not a missing capability: `validate` authenticates
    one RRset against one RRSIG (the "is this signature genuine" question);
    stitching a wildcard RRSIG to its required denial proof is the
    multi-RRset, multi-record resolver logic above it, the same scope
    boundary `chain.zig`'s header draws for delegation walking. A consumer
    that accepts a `.secure` wildcard-synthesized answer without separately
    calling `proveDenial` for the exact-match qname is NOT RFC 4035
    §5.3.4-compliant — spelled out here explicitly because "the module has
    the denial machinery so it must be doing this already" is the wrong
    inference.

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
`src/oracle_vectors.zig`; KATs: `src/oracle_test.zig`.

⚠ **The reproduction harness was not in the repo.** Both this file and
`README.md` credited `scratchpad/dnssec-oracle/` (zone + `extract.py`, using
`dnspython`), and README called it "ephemeral" — accurately: a scratchpad does
not survive a reboot, so the module's strongest anchor had no re-takeable
recipe. Same shape as the drift-ranking script this campaign had to move out of
a session scratchpad. `scripts/gen-dnssec-oracle.sh` now restores the
provenance CHAIN: it builds a zone, signs it once per algorithm this module
implements a verifier for (8, 13, 15) plus an NSEC3 pass, and has `ldns` —
an independent implementation, not this repo — verify each result. What it
deliberately does NOT do is reproduce the committed vectors byte for byte:
those were signed with keys that no longer exist. The extraction step (wire
rdata → the `Vec` literals) is the piece that was lost and is not
reconstructed.
Remaining: corpus-fuzz the parsers; external RFC 6605/8080 published test
vectors as a second independent cross-check.

## Anchoring

**Anchor grade:** class A · oracle EXTERNAL

- **Class A** — wire/interop format — other implementations must byte-agree with it.
- **Oracle EXTERNAL** — published vectors, goldens captured from a foreign implementation, or a test run against a live foreign peer.

**What the tests actually contain.** oracle_vectors.zig: real zones signed by ldns-signzone, accepted by ldns-verify-zone
