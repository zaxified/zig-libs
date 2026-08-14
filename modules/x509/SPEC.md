# x509 — spec

Design + threat notes for auditors. Usage: see ./README.md. Attribution/provenance: see
./README.md "Provenance" + /NOTICE.

## Design & invariants

**Two-layer module.** `extensions.zig` (real, tested) does purely mechanical,
bounds-checked DER TLV decoding of the X.509v3 extension fields
`std.crypto.Certificate.Parsed` does not expose — no policy decisions, no
cryptography, just "turn these bytes into a typed Zig value." `chain.zig`
(API and algorithm both real, **DONE** — see "Status" below) is the RFC
5280 §6 path-validation DECISION layer built on top: given a peer-supplied
certificate chain and a trust store, decide whether to trust it. That
decision requires, per RFC 5280 — and `verifyChain` implements all of it:

- Path building (finding a chain of issuer/subject matches from leaf to a
  trust anchor, potentially among multiple same-subject-DN candidates —
  RFC 5280 doesn't specify an algorithm for this; RFC 4158 is the closest
  reference) — `buildPath`, with backtracking over alternate candidates.
- Per-link cryptographic verification — **delegated entirely to
  `std.crypto.Certificate.Parsed.verify`**, not reimplemented, except for
  the RSA-PSS gap (`verifyPssLink`, implemented and KAT-tested against
  OpenSSL — see "Status") since std cannot even parse a PSS-signed
  certificate.
- basicConstraints/keyUsage enforcement (every non-leaf cert must be a CA
  with `keyCertSign`) — real values come from `extensions.zig`; the
  enforcement DECISION is `chain.zig`'s `checkIsCaSigner`.
- pathLenConstraint bookkeeping with the self-issued-certificate exception
  (RFC 5280 §6.1.4 (l) — the single most commonly-mis-implemented rule in
  this whole algorithm: self-issued certificates, subject==issuer
  byte-for-byte, do not count against ANY CA's path-length budget) —
  `checkPathLength`.
- Name-constraint matching (§6.1.4 (g), §4.2.1.10) — per-`GeneralName`-type
  matching rules (dNSName label-suffix, directoryName RDN-prefix
  containment, iPAddress CIDR, etc.) applied to the accumulated permitted/
  excluded subtrees from every CA in the path — `checkNameConstraints`.
- Extended-key-usage consistency/chaining and the leaf's required-purpose
  check — `checkExtendedKeyUsage`.
- Hostname matching — **delegated to `std.crypto.Certificate.Parsed.verifyHostName`**,
  already RFC-6125-tested by std, not reimplemented.

Every named sub-algorithm in `chain.zig` has a doc comment naming exactly
which of the above it covers. See `src/root.zig`'s module doc comment for
the full `std.crypto.Certificate` recon this design decision (build on std,
don't reparse/reverify) is based on.

**Explicitly out of scope, not silently skipped:** revocation checking
(CRL/OCSP, RFC 5280 §6.3 — a separate online/offline data-fetching concern)
and certificate policy processing (§6.1.5's explicit-policy/policy-mapping
state machine — most TLS/mTLS/OPC-UA deployments don't rely on policy OIDs).
A consumer needing either must add it explicitly; `verifyChain` must never
be mistaken for covering them.

## `safe.zig` — the shared certificate-DER safety guard

`safe.zig` is the canonical home for guarding `std.crypto.Certificate.parse`
against its own unchecked DER reader, consolidating three previously
independent copies (`x509`'s per-element `extensions.parseElement`, which
stays for the per-field walks that need it; `iec62351`'s
`tlsprofile.structurallySafe`; and `opcua`'s `security.safeCertificate`).
Both `iec62351` and `opcua` now route through it.

**The hazard.** `std.crypto.Certificate.der.Element.parse` reads its
identifier/length octets with plain `bytes[i]` indexing and computes an
element's end as `start + declared_length` without clamping it to the buffer.
`Certificate.parse` then walks the tbsCertificate field by field and at
several points probes for an OPTIONAL sibling at a boundary without first
checking a byte exists there. On a malformed, attacker-supplied certificate
(a TLS/OPC-UA/GOOSE peer certificate is fully attacker-controlled) this
indexes past the buffer. **Verified on Zig 0.16.0 out of band**: in **Debug**
it panics (`index out of bounds`, aborting the process); in **ReleaseFast**
the same inputs either read out of bounds *silently* — returning a `Parsed`
built from whatever lay past the buffer — or segfault. Reproductions used for
the regression test: `30 02 30 00` (`SEQUENCE { SEQUENCE {} }`) panics at
`Certificate.zig:905` in Debug and reads OOB (returns a bogus "parsed OK") in
ReleaseFast; `30 82` (truncated length) segfaults in ReleaseFast.

**Public surface.**

- `safe.validate(bytes)` / `safe.validateCertificate(bytes)` — a
  recursive-descent DER well-formedness validator with its own bounds-checked
  header decoder (it does *not* trust std's reader). Returns a typed
  `safe.Error` for a length that overruns its container, a truncated tag or
  length, a length-of-length that itself overruns, an indefinite-length
  encoding (BER, illegal in DER), a high-tag-number identifier, a
  length-of-length beyond four octets, or nesting past `safe.max_depth` (32).
  `validateCertificate` additionally requires a single outer `SEQUENCE`
  filling the buffer.
- `safe.safeCertificate(der, scratch)` — validate, copy into caller scratch,
  zero-pad by `safe.parse_slack` (64), and return a `std.crypto.Certificate`
  safe to `parse`. `safe.max_certificate_len` (8192) bounds the input so a
  caller can size `[max_certificate_len + parse_slack]u8` on the stack.
- `safe.spkiOf(certificate_der)` (lifted as `x509.spkiOf`) — the certificate's
  `SubjectPublicKeyInfo`, extracted without `std.crypto.Certificate.parse` at
  all. See the section below.

### `spkiOf` — SubjectPublicKeyInfo extraction

**Why it exists.** Several consumers need only to *name* an untrusted
certificate's public key — Holder-of-Key subject confirmation in `saml`, key
pinning, comparing a certificate against a bare public key — with no interest
in its dates, extensions or signature. Routing that through
`Certificate.parse` would drag the whole hazard above into an authentication
path for no benefit, and would additionally fail outright on a PSS-signed
certificate whose SubjectPublicKeyInfo is a perfectly ordinary field.

**How it stays safe.** `validateCertificate` runs first, so every TLV in the
buffer is proven to sit wholly inside it and to tile its container exactly.
The field walk that follows (version `[0]` OPTIONAL → serialNumber →
signature → issuer → validity → subject → subjectPublicKeyInfo, RFC 5280
§4.1) uses only `safe.zig`'s own `decodeHeader`, and decodes no field
*contents* whatsoever — not a single date, OID enum or bit flag. The
`subjectPublicKeyInfo` is then required to be exactly
`SEQUENCE { AlgorithmIdentifier SEQUENCE { OBJECT IDENTIFIER, parameters
OPTIONAL }, BIT STRING }` with no extra fields and a zero unused-bit count;
anything else is `error.MalformedSubjectPublicKeyInfo`. Fails closed
throughout: `SpkiError` (= `safe.Error` + `MalformedTbsCertificate` +
`MalformedSubjectPublicKeyInfo`), never a panic, never a partial result.

**Borrowing contract.** `Spki.der` (the full SPKI TLV), `.algorithm_oid` (OID
content bytes), `.parameters` (full TLV or null) and `.key_bits` (BIT STRING
content, unused-bits octet stripped) are all sub-slices of the caller's
`certificate_der`. Nothing is copied, nothing is allocated, the input is never
mutated, and the whole `Spki` dangles the moment that buffer does. A caller
needing the key to outlive the certificate bytes must copy it or parse it into
an owned key type (`rsa.PublicKey.fromDer` copies).

**What it does NOT prove.** Only that the returned bytes are the certificate's
SubjectPublicKeyInfo field. Nothing about the signature, validity window,
issuer or extensions — it is a field accessor, not a verifier. `verifyChain`
is the verifier.

**Verification.** Cross-checked against std's *own* independent field walk
(reached through `safeCertificate`, so it cannot panic): for every fixture
certificate std can parse — RSA, EC P-256, EC P-384, Ed25519, at root,
intermediate and leaf positions — `spkiOf(...).key_bits` must equal
`Parsed.pubKey()` byte for byte, although the two walks share no code. Plus:
the RSA fixture's SPKI round-trips through `rsa.PublicKey.fromDer` (both as
the whole TLV and as the bare PKCS#1 key bits), the P-256 fixture's key bits
are accepted by `fromSec1` and its `namedCurveOid` is `prime256v1`, the three
PSS fixtures extract cleanly (with a paired assertion that std's own
`parse` rejects one of them), and hostile-input sweeps — every prefix of three
real certificates, every single-byte mutation of one under eight substituted
values, explicit shapes with too-few TBS fields / a non-SEQUENCE SPKI / a
non-zero unused-bit count, and a `std.testing.fuzz` walk feeding arbitrary
bytes into `spkiOf` and on into `rsa.PublicKey.fromDer` / `fromSec1`.

**Why the zero-padded copy is kept, not dropped.** Well-formedness is
necessary but **not sufficient** to make `std.crypto.Certificate.parse`
total, so the scratch-copy convenience is required rather than optional. The
well-formed input `30 02 30 00` passes `validateCertificate`, yet std, having
consumed the empty inner element as the tbsCertificate, then parses the next
field at the buffer boundary and indexes off the end (the Debug panic /
ReleaseFast OOB read above). The `parse_slack` zero bytes behind a validated
copy turn every such boundary probe into an empty `00 00` TLV read out of the
padding; because every loop std runs is bounded by an element end the
validator already proved in-bounds, a bounded number of probes cannot walk
through 64 zero bytes. With the guard, `30 02 30 00` yields a clean
`error.CertificateFieldHasWrongDataType` in **both** Debug and ReleaseFast
(verified). `safe.zig`'s tests take the union of the three former guards'
coverage — every-prefix and every-single-byte-mutation sweeps of a real
fixture certificate, a `std.testing.fuzz` walk, explicit hostile shapes, and
a regression test pinned to the reproduced std hazard.

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
`chain_test.zig` (`zig build test-x509`, green in Debug and
ReleaseFast), including an openssl-3.5-generated oracle chain per supported
signature algorithm (RSA PKCS1v15, RSASSA-PSS, ECDSA P-256, ECDSA P-384,
Ed25519) and dedicated rejection-case hierarchies (expired/not-yet-valid,
name-constraint violation, non-CA issuer, pathLenConstraint exceeded,
self-issued not counted, tampered signature, EKU mismatch, unknown anchor).

`safe.zig`: **DONE** — `validate`/`validateCertificate`/`safeCertificate`
plus the union test suite described under "the shared certificate-DER safety
guard" above (`zig build test-x509`, green in Debug and ReleaseFast).

Not implemented, and not silently skipped (see "Explicitly out of scope"
above): CRL/OCSP revocation checking, certificate-policy processing
(§6.1.5), and name-constraint matching for `GeneralName` types other than
`dNSName`/`directoryName`/`iPAddress` (a constraint on `rfc822Name`,
`uniformResourceIdentifier`, etc. is parsed but never matched against —
fail-open for that specific name type only).

## Anchoring

**Anchor grade:** class A · oracle EXTERNAL

- **Class A** — wire/interop format — other implementations must byte-agree with it.
- **Oracle EXTERNAL** — published vectors, goldens captured from a foreign implementation, or a test run against a live foreign peer.

**What the tests actually contain.** chains generated by real OpenSSL 3.5, cross-checked with openssl verify
