# x509 — spec

Design + threat notes for auditors. Usage: see ./README.md. Attribution/provenance: see
./README.md "Provenance" + /NOTICE.

## Design & invariants

**Two-layer module.** `extensions.zig` (real, tested) does purely mechanical,
bounds-checked DER TLV decoding of the X.509v3 extension fields
`std.crypto.Certificate.Parsed` does not expose — no policy decisions, no
cryptography, just "turn these bytes into a typed Zig value." `chain.zig`
(API real, algorithm stubbed) is the RFC 5280 §6 path-validation DECISION
layer built on top: given a peer-supplied certificate chain and a trust
store, decide whether to trust it. That decision requires, per RFC 5280:

- Path building (finding a chain of issuer/subject matches from leaf to a
  trust anchor, potentially among multiple same-subject-DN candidates —
  RFC 5280 doesn't specify an algorithm for this; RFC 4158 is the closest
  reference).
- Per-link cryptographic verification — **delegated entirely to
  `std.crypto.Certificate.Parsed.verify`**, not reimplemented, except for
  the RSA-PSS gap (`verifyPssLink`, still stubbed) since std cannot even
  parse a PSS-signed certificate.
- basicConstraints/keyUsage enforcement (every non-leaf cert must be a CA
  with `keyCertSign`) — real values come from `extensions.zig`; the
  enforcement DECISION is `chain.zig`'s stub.
- pathLenConstraint bookkeeping with the self-issued-certificate exception
  (RFC 5280 §6.1.4 (l) — the single most commonly-mis-implemented rule in
  this whole algorithm: self-issued certificates, subject==issuer
  byte-for-byte, do not count against ANY CA's path-length budget).
- Name-constraint matching (§6.1.4 (g), §4.2.1.10) — per-`GeneralName`-type
  matching rules (dNSName label-suffix, directoryName RDN-prefix
  containment, iPAddress CIDR, etc.) applied to the accumulated permitted/
  excluded subtrees from every CA in the path.
- Extended-key-usage consistency/chaining and the leaf's required-purpose
  check.
- Hostname matching — **delegated to `std.crypto.Certificate.Parsed.verifyHostName`**,
  already RFC-6125-tested by std, not reimplemented.

Every stub in `chain.zig` has a doc comment naming exactly which of the
above it covers and why it's algorithm work rather than parsing. See
`src/root.zig`'s module doc comment for the full `std.crypto.Certificate`
recon this design decision (build on std, don't reparse/reverify) is based
on.

**Explicitly out of scope, not silently skipped:** revocation checking
(CRL/OCSP, RFC 5280 §6.3 — a separate online/offline data-fetching concern)
and certificate policy processing (§6.1.5's explicit-policy/policy-mapping
state machine — most TLS/mTLS/OPC-UA deployments don't rely on policy OIDs).
A consumer needing either must add it explicitly; `verifyChain` must never
be mistaken for covering them.

## Threat model / out of scope

Both `extensions.zig` and `chain.zig` parse attacker-controlled bytes (a
peer-supplied certificate chain). Every raw DER offset either file computes
goes through `extensions.parseElement`, which wraps
`std.crypto.Certificate.der.Element.parse` with its own bounds checks: the
std primitive alone does *not* validate that a TLV's encoded length fits
within the buffer, so a single malformed length field, read through a
direct slice index rather than another `parse` call, could otherwise abort
the process instead of surfacing `error.CertificateFieldHasInvalidLength`
(found and fixed during development — a hand-built `nameConstraints` test
fixture with a truncated `GeneralSubtree` triggered exactly this). The one
hand-rolled bit-index arithmetic (`parseKeyUsage`'s `bitAt`) is exercised
against both a real generated fixture (CA vs. leaf, via
`rsa.selfSignedCert`) and boundary reasoning in its own doc comment.

`chain.zig`'s algorithm addresses, and `chain_test.zig` exercises:

- A forged/omitted `basicConstraints`/`keyUsage` must not silently pass
  (e.g. a leaf certificate presented as if it were a CA to sign further
  certificates in a supplied chain) — `checkIsCaSigner`, tested via the
  "non-CA certificate used as issuer" case.
- pathLenConstraint bypass via crafted self-issued certificates —
  `checkPathLength`'s self-issued exception, tested both as a rejection
  (pathLenConstraint exceeded) and as a positive case (a self-issued
  rollover certificate correctly NOT counted).
- The RSA-PSS gap (`verifyPssLink`) never treats "certificate uses PSS" as
  "skip verification" — a PSS-signed link is fully verified via this
  module's own DER walk + `rsa.verifyPss`, including RFC 4055's exact
  parameter DEFAULTs (a certificate omitting `hashAlgorithm`/
  `maskGenAlgorithm`/`saltLength` must be checked as sha1/MGF1-sha1/salt-20,
  not have the check skipped).
- Multiple trust-anchor/intermediate candidates sharing a subject DN are
  all tried via backtracking (`findIssuerAndVerify`/`acceptCandidate`), not
  just the first found.

Remaining, NOT addressed by this module (see "Explicitly out of scope"
above and README.md): CRL/OCSP revocation, certificate-policy processing,
and name-constraint bypass via `GeneralName` types this module doesn't match
against (`rfc822Name`, `uniformResourceIdentifier`, etc. — parsed but not
enforced) or via Unicode/punycode confusables in `dNSName`/IPv4-mapped IPv6
in `iPAddress` (this module does exact-bytes/CIDR matching only, no
normalization).

## Status

`extensions.zig`: DONE for the fields listed in README.md; `authorityKeyIdentifier`'s
`[1]`/`[2]` (name+serial) forms intentionally not parsed (add only if a
consumer needs them — `keyIdentifier [0]` covers essentially every CA in
practice). `chain.zig`: **DONE** — `verifyChain` plus the five named
sub-algorithms (`buildPath`, `checkNameConstraints`, `checkPathLength`,
`checkExtendedKeyUsage`, `verifyPssLink`) are implemented and covered by
`chain_test.zig`'s 40 tests (`zig build test-x509`, green in Debug and
ReleaseFast), including an openssl-3.5-generated oracle chain per supported
signature algorithm (RSA PKCS1v15, RSASSA-PSS, ECDSA P-256, ECDSA P-384,
Ed25519) and dedicated rejection-case hierarchies (expired/not-yet-valid,
name-constraint violation, non-CA issuer, pathLenConstraint exceeded,
self-issued not counted, tampered signature, EKU mismatch, unknown anchor).

Not implemented, and not silently skipped (see "Explicitly out of scope"
above): CRL/OCSP revocation checking, certificate-policy processing
(§6.1.5), and name-constraint matching for `GeneralName` types other than
`dNSName`/`directoryName`/`iPAddress` (a constraint on `rfc822Name`,
`uniformResourceIdentifier`, etc. is parsed but never matched against —
fail-open for that specific name type only).
