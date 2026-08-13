# dnssec

Resolver-side DNSSEC validation: RFC 4033/4034/4035 core, RFC 5155 NSEC3,
RFC 6605 ECDSA, RFC 8080 Ed25519.

**Status: validation core implemented + oracle-verified.** The full path is
real: DNSKEY/RRSIG/DS/NSEC/NSEC3/NSEC3PARAM RDATA parsing, the Type Bit Maps
field, the DNSKEY key tag checksum, canonical name encoding, NSEC3's
base32hex + iterated-SHA-1 owner hash, DS digest computation, per-algorithm
DNSKEY decode + signature verification (wrapping
`std.crypto.sign.ecdsa`/`std.crypto.sign.Ed25519` and this repo's own `rsa`
module — no crypto primitive is reimplemented here), the RFC 4034 §3.1.8.1
canonical signed-data construction (`canonical.buildSignedData`, incl.
wildcard-name + original-TTL handling), the DS→DNSKEY delegation link
(`chain.validateDnskeySet`), the NSEC3 denial-of-existence proof incl.
Opt-Out (`nsec3.proveDenial`), the plain-NSEC (non-NSEC3) denial-of-existence
proof — canonical-order gap coverage, NODATA, wildcard, and insecure-delegation
(`nsec.proveDenial`) — and the top-level per-RRset `validate` verdict.

Verified against real zones signed by `ldns-signzone` across algorithms
**8/13/14/15** (RSA-SHA256, ECDSA-P256, ECDSA-P384, Ed25519) with both **NSEC
and NSEC3** (incl. an **Opt-Out** span) and a **wildcard**; every source zone
was independently accepted by `ldns-verify-zone`. A valid RRSIG only verifies
over byte-exact canonical data, so a `.secure` verdict on those vectors is
itself the byte-exactness proof; the matching tampered cases return `.bogus`.
See `src/oracle_test.zig` + `src/oracle_vectors.zig`.

**Not (yet) implemented:** RFC 8624 algorithm-downgrade policy; and RFC 9276
NSEC3 iteration-count caps. The plain-NSEC (non-NSEC3) denial proof
(`nsec.proveDenial`) is implemented and unit-tested against the RFC 4034 §6.1
canonical ordering plus positive/adversarial cases, but is not yet
`ldns`-oracle-verified the way the NSEC3 proof is. See SPEC.md "Threat model /
out of scope". The
multi-zone-cut resolver that walks the chain root→TLD→… is also out of scope
(this module is one cut — see `chain.zig`).

- **Model after:** RFC 4033/4034/4035 (DNSSEC core), RFC 5155 (NSEC3),
  RFC 6605 (ECDSA), RFC 8080 (Ed25519). Structure cross-checked against Go
  `miekg/dns`'s `dnssec.go` and NLnet Labs' unbound/ldns validator behavior —
  behavioral/API-shape reference only, no source copied.
- **Deps:** `dns` (this module reads `dns.Record`/`dns.Message`; DNSSEC RR
  types are not in `dns.message.Type`, so they arrive as
  `Record.Data.unknown` raw RDATA — see "Recon notes" below), `rsa` (RSA
  signature verification; std's own internal RSA verifier is not `pub`).

## Layout

| File | Role | Status |
|------|------|--------|
| `src/wire.zig` | Uncompressed name decode (RRSIG signer name / NSEC next name) + canonical name encoding (RFC 4034 §6.2) | real, tested |
| `src/rdata.zig` | DNSKEY/RRSIG/DS/NSEC/NSEC3/NSEC3PARAM RDATA parsing, Type Bit Maps, key tag | real, tested |
| `src/nsec3.zig` | base32hex (RFC 4648 §7) + NSEC3 iterated-SHA-1 hash (RFC 5155 §5); closest-encloser / next-closer denial proof incl. Opt-Out (RFC 5155 §8) | real, oracle-verified |
| `src/nsec.zig` | plain-NSEC (non-NSEC3) denial proof (RFC 4035 §5.4): canonical-order gap coverage (RFC 4034 §6.1), NODATA, wildcard, insecure-delegation | real, tested |
| `src/keys.zig` | DNSKEY public-key wire decode (RFC 3110/6605/8080) + per-algorithm signature verify dispatch | real, tested |
| `src/ds.zig` | DS digest computation (RFC 4034 §5.1.4) + DNSKEY matching | real, tested |
| `src/canonical.zig` | RFC 4034 §3.1.8.1 canonical RRset signed-data construction (wildcard + original-TTL + embedded-name lowering) | real, oracle-verified |
| `src/chain.zig` | DS-to-DNSKEY delegation-chain link (one zone cut) | real, oracle-verified |
| `src/root.zig` | `meta`, RRSIG validity-window check, top-level `validate` | real, oracle-verified |
| `src/oracle_vectors.zig` / `src/oracle_test.zig` | KAT vectors from `ldns-signzone` + the validation KATs | test-only |

## Usage

```zig
const dnssec = @import("dnssec");

const dnskey = try dnssec.rdata.parseDnskey(dnskey_record.data.unknown);
const rrsig = try dnssec.rdata.parseRrsig(gpa, rrsig_record.data.unknown);

// Validate one RRset whose signing key is vouched for by `trust_anchor`
// (a pinned DNSKEY, or a DS naming that key — the apex DNSKEY-RRset case):
const result = try dnssec.validate(gpa, rrset, rrsig, owner_name, dnskey, trust_anchor, .{ .now = now });
switch (result) {
    .secure => {}, // signature + trust chain hold; serve the answer
    .insecure => {}, // zone is provably unsigned; serve as plain DNS
    .bogus, .indeterminate => {}, // treat like SERVFAIL, never serve
}

// Establish a zone's DNSKEY set from a parent DS (one delegation cut):
const verdict = try dnssec.chain.validateDnskeySet(gpa, zone, dnskey_rrset, dnskey_rrsig, .{ .ds = ds });

// Prove denial of existence from an authority-section NSEC3 set (RFC 5155 §8):
const denial = dnssec.nsec3.proveDenial(qname, qtype, .{ .records = nsec3_set }, salt, iterations);
```

For a ZSK-signed RRset a resolver first calls `chain.validateDnskeySet` to
trust the zone's keys, then `validate` with the now-trusted ZSK as a
`.dnskey_rdata` anchor. Walking multiple zone cuts is the resolver's job.

## Recon notes (why `dnssec` is a sibling module, not a `dns` extension)

- `dns.message.Type` has no DNSKEY(48)/RRSIG(46)/DS(43)/NSEC(47)/NSEC3(50)/
  NSEC3PARAM(51) tags; `dns.decode` already decodes anything it doesn't
  recognize as `Record.Data.unknown` with the raw RDATA bytes preserved —
  which is exactly what this module needs, so `dns` did not need to change.
  Naming these type numbers (`rdata.rr_type`) lives here instead of in `dns`,
  to keep `dns` crypto-free and avoid pulling `rsa` into every `dns`
  consumer's dependency graph — the same sibling-module-with-a-dep pattern
  `ssh`/`opcua` already establish over `rsa`.
- RRSIG's Signer's Name and NSEC's Next Domain Name are, per RFC 4034 §6.2,
  never compressed — so this module parses them with its own bounds-checked
  uncompressed-only decoder (`wire.decodeUncompressedName`) rather than
  needing access to `dns.message`'s (private) full-packet decompression
  logic.
- `std.crypto` (0.16) has real, public verify-capable APIs for every
  algorithm this module targets: `std.crypto.sign.ecdsa.EcdsaP256Sha256`/
  `EcdsaP384Sha384` (algorithms 13/14) and `std.crypto.sign.Ed25519`
  (algorithm 15) — both directly usable, no gap. RSA (algorithms 5/7/8/10)
  is the one std gap: `std.crypto.Certificate.rsa` exists internally but is
  not `pub`, which is exactly why this repo's own `rsa` module
  (`rsa.verifyPkcs1v15`) exists and is reused here instead of reimplementing
  RSA verification a second time.

## Validation core

Four pieces make up the validation core (see each file for the full spec):

1. **`canonical.buildSignedData`** (RFC 4034 §3.1.8.1) — the exact byte
   stream an RRSIG signature is computed over: canonical RR ordering
   (§6.3), owner-name canonicalization + wildcard-name substitution when
   `rrsig.labels` indicates the RRset was wildcard-synthesized (§3.1.3),
   original-TTL substitution, and lowercasing any domain name embedded
   *inside* an RR's own RDATA (NS/CNAME/PTR/MX/SOA/SRV targets, §6.2).
2. **`nsec3.proveDenial`** (RFC 5155 §8, RFC 4035 §5.4) — the
   closest-encloser / next-closer denial-of-existence proof: direct NODATA,
   NXDOMAIN, wildcard-NODATA, wildcard-answer, and Opt-Out (§8.9) downgrade
   to insecure.
3. **`chain.validateDnskeySet`** — matching a DS (or pinned trust anchor) to
   a DNSKEY and confirming that DNSKEY actually self-signed its RRset.
4. **`root.validate`** — the top-level per-RRset verdict: time window,
   covered-type check, trust-anchor match, and signature verify over #1.

**Oracle used:** offline known-answer tests built from real zones signed by
`ldns-signzone`/`ldns-keygen` (algorithms 8/13/14/15; NSEC, NSEC3, NSEC3
Opt-Out; a wildcard; NODATA + NXDOMAIN denial). Each signed zone was
independently accepted by **`ldns-verify-zone`** (the independent reference
validator, so the KATs aren't self-referential). The vectors are extracted
into `src/oracle_vectors.zig`; the KATs live in `src/oracle_test.zig`.
Reproduce with `scratchpad/dnssec-oracle/` (zone + `extract.py`, ephemeral).

## Provenance

Clean-room from the DNSSEC RFCs (4033/4034/4035 core, 5155 NSEC3, 6605 ECDSA,
8080 Ed25519, 1982 serial arithmetic) — all open, public specifications, so the
spec citations need no attribution. Reuses Zig std's `std.crypto` (ECDSA
P-256/P-384, Ed25519, SHA-1/256/384) and this repo's own `rsa` module (RFC 8017
PKCS#1 v1.5 verify, for algs 8/10) and `dns` module (message/record wire
parsing); no source ported or copied. The "model after" implementations above
were consulted for structure/behavior only, no source copied. Validation KATs
are cross-checked against `ldns` (`ldns-signzone`/`ldns-verify-zone`,
**BSD-3-Clause**) as an independent oracle — used to generate/verify test zones
only, not consulted as source.
## Tests

`zig build test-dnssec` — all tests run offline. The mechanical unit
tests (RDATA parsing incl. a hand-computed RFC 4034 Appendix B key-tag
vector, Type Bit Map bounds checks, base32hex round-trips, NSEC3
iterated-hash vs. manual SHA-1 chaining, DS digest vs. manual hashing,
RSA/ECDSA/Ed25519 decode + sign/verify round-trips, RFC 1982 time-window
wraparound) plus end-to-end known-answer tests over the `ldns`-signed
oracle: every RRset (SOA/NS/MX/TXT/A/NSEC/DNSKEY) across algorithms
8/13/14/15 verifies `.secure` and turns `.bogus` on a single flipped
signature byte; typed SOA/MX/NS/A records canonicalize byte-exact; a
wildcard-expanded A verifies via RRSIG.labels substitution; DNSKEY sets
validate against a parent DS (and go `.bogus` on a tampered digest or
tampered self-signature); and NSEC3 NODATA/NXDOMAIN/wildcard/Opt-Out denial
proofs return the expected verdicts. Green in Debug and ReleaseFast;
`zig fmt --check modules/dnssec` clean.
