# x509 — changelog

Newest first. See the root [`CHANGELOG.md`](../../CHANGELOG.md) for which
release tag each entry shipped in, and `CONVENTIONS.md` §8 for the policy.

## Unreleased

- **2026-10-19** — **Fix (BEHAVIOUR CHANGE):** (name-constraints bypass) directoryName constraints compared a constraint's whole `Name` (`[4] EXPLICIT Name`, a SEQUENCE) with the certificate subject's RDN content as given, so on real certificates an excluded directoryName never matched (bypass) and a permitted one refused every subject. `names.match` now compares RDN sequences on both sides (`rdnSequence`: a value that is exactly one SEQUENCE is unwrapped; SAN directoryName entries likewise). A chain whose CA carries a permitted directoryName now verifies when the subject is inside it. Test in `src/chain_test.zig` ("a real directoryName constraint …"), real DER; the earlier test fed RDNs straight inside `[4]`, a shape no certificate has.

- **2026-10-19** — **Fix (BEHAVIOUR CHANGE):** (name-constraints bypass) the permitted subtrees of the CAs on a path were walked as one union (`checkOneName` over all accumulated blobs), so a CA constrained to `example.org` could issue a sub-CA permitting `evil.com` and a leaf for `www.evil.com` verified. Now they intersect as RFC 5280 §6.1.4 (g)(1) and Go require: every CA's permitted set that restricts the name's type must admit it (entries inside one CA's set are still alternatives; excluded subtrees stay a union; types a CA does not restrict stay unrestricted). A chain that relied on the union is now `NameConstraintViolated`. Test in `src/chain_test.zig` ("permitted subtrees of successive CAs intersect …"); negative control checked (the union walk fails it).

- **2026-10-19** — **Fix:** (remote CPU exhaustion; peer or on-path attacker, no trusted key needed) path building had no bound on the signature checks of its backtracking search: a chain of n self-made CAs sharing one DN and one key made `verifyChain` verify about e·n! links (leaf + 8 CAs through `tlsclient`: ~10^5 Ed25519/ECDSA verifications per handshake, seconds of CPU). Now at most 100 signature checks per call, as Go (`maxChainSignatureChecks`); past it `ChainTooLong` / `NoTrustedPath`. No API change. Tests in `src/chain.zig`: the adversarial chain stops within the bound (negative control: 1956 checks without it), and a chain needing backtracking past a failing same-DN candidate still verifies.

- **2026-10-19** — **NO CONSUMER-VISIBLE CHANGE:** Deprecated std names replaced by their Zig 0.17 spellings (`mem.indexOf*` -> `mem.find*`, `fmt.bufPrint` -> `mem.print`, `fmt.allocPrint(a, …)` -> `a.print(…)`, `bufPrintSentinel` -> `mem.printSentinel`, `@intFromEnum` -> `@backingInt`); the old names are aliases, so behaviour is identical.

- **2026-10-18** — **NO CONSUMER-VISIBLE CHANGE:** Docs: README/SPEC statements about std's unchecked DER reader (`Certificate.parse`) re-read against the 0.17.0 std (unchanged); 0.16-only measurements are labelled as such.

- **2026-10-18** — Ported to Zig 0.17.0. `safe.zig` `std_descent_points_verified_against` raised 0.16.0 -> 0.17.0 after diffing `std.crypto.Certificate.parse` between the two toolchains (identical descent points). `EnumSet.initEmpty()` -> `.empty` (chain.zig); test-only `std.meta.fields` -> `@typeInfo(..).field_names`.
- **2026-10-17** — `names.parseIp4`/`parseIp6` are now `netaddr`'s parsers (new dep `netaddr`) instead of a second implementation in this module. Same API, same answers: a differential run over 20 M random and mutated inputs found no disagreement (negative-controlled with a planted leading-zero mutant). Existing `names` tests and the `x509-names` fuzz harness now exercise the shared parser.
- **2026-10-16** — single-field readers for consumers (acme): `chain.certValidity` (notBefore/notAfter over the bounded shape walk), `chain.certAuthorityKeyId` (the AKI keyIdentifier), `names.nameAttribute` + `names.oid_common_name` (first value of an attribute in a `Name`, e.g. the issuer CN). Tests: values equal to openssl's reading of `data/p521/` fixtures; every truncation and single-byte change errors without an out-of-bounds read.

- **2026-10-11** — **Go `crypto/x509` Verify parity (scope S3 → S2).** Behaviour pinned against Go 1.26 by a replayed corpus of 395 recorded verdicts (`src/s2_oracle_test.zig`, `src/data/s2/corpus.bin`, recipe `tools/gen_names_fixtures.py` + `tools/go_oracle`); differences listed in SPEC § "Go Verify parity". **New:** rfc822Name and URI name constraints (`names.zig`, Go's domain rule; was fail-closed), certificate policy processing on every path (`policy.zig`, RFC 5280 §6.1 with the RFC 9618 graph; `Options.policy`), `verifyChainPath` (returns the path), `Options.usages_any_of` (Go `KeyUsages`), `Options.max_constraint_comparisons` (250 000, `TooManyConstraints`), `Options.ignore_critical_oids`, `Options.check_anchor_validity`, `Options.allow_sha1_signatures`, a v1 trust anchor is accepted. **Behaviour changes (accept → reject):** `expected_host` no longer falls back to the subject commonName and matches IP hosts (own `hostname.zig` replaces std's `verifyHostName`); a critical extension the module does not act on is `UnhandledCriticalExtension`, a repeated extension `DuplicateExtension`; an expired or not-yet-valid trust anchor fails; SHA-1 certificate signatures are `WeakSignatureAlgorithm`; a dNSName with a trailing dot under any dNSName constraint fails closed; a CA's `requireExplicitPolicy` is enforced (`PolicyViolation`). New `VerifyChainError` members; `CheckNameConstraintsError` gains `CertificateFieldHasWrongDataType` (a SAN that is not a `GeneralNames`). Fuzz harnesses `x509-names` (against label-list references) and `x509-policy` (the graph against a literal RFC 5280 tree).
- **2026-10-11** — **Fixed (SECURITY):** dNSName name constraints matched nothing for two base shapes, so as an *excluded* subtree they excluded nothing: a leading-dot base (`.bad.example.com`, read by Go and rustls-webpki as "subdomains only") let `x.bad.example.com` through, and the empty base (RFC 5280 §4.2.1.10: every name extends it) excluded no name. As *permitted* subtrees both falsely rejected. `dnsNameMatches` now implements both; test in `chain_test.zig`, negative-controlled. Found by the S2 scope survey.
- **2026-10-11** — perf: **chain verify 6.4–7.3× → 0.81–0.92× Go 1.26.0 crypto/x509** (`bench-x509`). Profile: all of it was std's signature math — `pcurves` P-256 (~0.7 ms per verify) and `Certificate.rsa` (an `ff.Modulus` built per call). `verifyParsed` replaces `Parsed.verify` check for check (issuer, validity, std's RSA gates and errors) and sends PKCS#1 v1.5 to `rsa.VerifyKey` and ECDSA under a P-256 key to `p256` (new dep); P-384 and Ed25519 stay on std. Also for CRL signatures (`verifySignedBy`). Behaviour change: an RSA issuer key with exponent 1 (any `EM` is its own signature) — accepted by std — now fails as `CertificateSignatureInvalid`.
- **2026-10-10** — Comparative benchmark `tools/bench.zig` (`zig build bench-x509`): **6.46–7.54× Go crypto/x509 chain verify** — over 2×, P4. Card stays `not measured` with the numbers in *Backlog* until the module is sped up (owner 2026-10-10: a consumed module must grade 3 or better). Tooling only, no code change.

- **2026-10-10** — New: ECDSA P-521 certificates and CRLs. Links (and CRLs) whose issuer key is EC secp521r1 — which std's `Parsed.verify` refuses with `CertificateSignatureNamedCurveUnsupported` — are verified through the new `p521` module (new dep): ecdsa-with-SHA224/256/384/512, std's issuer/validity/signature order and error mapping, strict-DER signatures. `safe.oid_secp521r1` added. Tests: `src/p521_test.zig` over OpenSSL-checked fixtures (`src/data/p521/`, recipe `tools/gen_p521_fixtures.py`).
- **2026-10-10** — **Fixed (SECURITY):** `safe.validateForStdParse` (and with it `verifyChain`) let
  through a certificate that ends at `signatureAlgorithm` without its signatureValue; std's
  `Certificate.parse` then reads the missing header at the end of the caller's buffer
  (out of bounds: a panic in safe builds, a read past the buffer in ReleaseFast).
  `requireStdDescentPoints` now requires the trailing BIT STRING, which keeps every std probe
  inside the buffer and closes the SPEC's open `parse_slack`-in-`verifyChain` question without an
  API change.
- **2026-10-10** — **Fixed (SECURITY):** `verifyChain` / `buildPath` passed the peer's certificates to
  std's `Certificate.parse` and `Parsed.verify` unguarded: a malformed intermediate made std index far
  out of bounds (a safety panic in safe builds, an out-of-bounds read in ReleaseFast), both inside
  `parse` and inside std's RSA key parser, which reads the RSAPublicKey in the subjectPublicKey BIT
  STRING unchecked. Every chain entry now goes through the new `safe.validateForStdParse`
  (`validateCertificate` + the std descent points + an exact `SEQUENCE { INTEGER, INTEGER }` RSA key)
  before anything else; trust anchors are the caller's configuration and are not re-checked.
  **Fixed (malleability):** `parseShape` read every RFC 5280 field by position without checking its
  tag, and bounded elements by the buffer rather than by their parent, so the UNSIGNED outer encoding
  could be altered and the same signature still verified under another fingerprint: the outer
  SEQUENCE tag, the signature BIT STRING tag, the outer length, the outer signatureAlgorithm (now
  required byte-equal to the signed tbsCertificate.signature, RFC 5280 §4.1.1.2), and the tags of the
  TBS fields. Found by the chain fuzz driver once its damage range covered the whole certificate;
  regression tests red without the fixes (one accepted, one std panic).

- **2026-10-10** — tests: deterministic fuzz driver `X509_FUZZ` over the existing harnesses (`spkiOf`, the validator and safe parser, the extension walk, `parsePssParams`, plus chain verification: the OpenSSL-signed fixture chains are accepted, a damaged leaf or intermediate and an out-of-validity time refused).
- **2026-10-10** — **Fixed (SECURITY, DoS):** `extensions.parseElement` checked that a long-form length's
  octets were in the buffer but not that `start + length` fits: std's `der.Element.parse` computes that
  end in u32, so a 4-octet length near 2^32 overflowed — a safety panic (process abort) in safe builds,
  a wrapped end that passed the bounds check in ReleaseFast. The end is now computed in u64 and
  bounded before std sees the element. Reached through `ocsp.parseResponse` on an attacker-supplied
  OCSP response (found by the ocsp deterministic fuzz driver); regression test red without the fix.

- **2026-10-08** — **NO CONSUMER-VISIBLE CHANGE:** a test and the example build their RSA key through
  rsa's out-param constructors (rsa 2026-10-08).
- **2026-09-30** — CRL checking wired into `chain.verifyChain`: opt-in `Options.revocation`
  (`chain.Revocation`: `crls`, `scope` `.full_chain`/`.leaf_only`, `unknown` `.reject`/`.allow`,
  `max_age_sec`). Checked per link after the signature and CA checks, so a revoked intermediate
  makes path building backtrack to another same-subject candidate; any `.revoked` (holds
  included) is the new `error.CertificateRevoked`, no verdict is `error.RevocationStatusUnknown`
  under `.reject`; trust anchors are not checked. `null` (default) changes nothing. Three-level
  fixtures `data/crl/chain_*` (`tools/gen_crl_chain_fixtures.py`, confirmed by
  `openssl verify -crl_check_all` / `-crl_check`) and `chain_crl_test.zig`.

- **2026-09-30** — CRL revocation checking (maturity task B2): new `x509.crl` with `parse` and
  `checkRevocation(crl_der, cert_der, issuer_der, .{ .now_sec })` → `.good` /
  `.revoked{time, reason, invalidity}`. Checks structure, algorithm agreement, issuer names,
  signature, `cRLSign`, AKI/SKI, freshness and IDP scope (partitioned CRLs such as Let's
  Encrypt's are matched against the certificate's CRL distribution points); fails closed on
  delta and indirect CRLs, reason-limited scopes and unknown critical extensions. New
  `chain.verifySignedBy` (a CRL or other certificate-shaped signed object, with the same
  algorithm dispatch as a chain link), `chain.certSerialAndIssuer`, `chain.certExtensionValue`,
  `chain.certIsCa`. Fixtures from Python `cryptography` + OpenSSL 3.5
  (`tools/gen_crl_fixtures.py`), every good/revoked/out-of-scope verdict confirmed by
  `openssl verify -crl_check`; RSA, RSASSA-PSS, P-256, P-384, Ed25519 and ML-DSA-44 CRLs;
  every truncation and single-byte tampering tested. Schemata mutation run over `crl.zig`:
  25 of 25 killed (after four fixtures added for the first-round survivors).

- **2026-09-16** — documentation only: the PKCS#1 v1.5 dispatch numbers are
  re-measured on today's tree (audit X2). `rsa.PublicKey.fromDer` is 453 µs
  against the 352 µs threshold that would make switching worth it, and a
  2-link RSA chain verifies in 726 µs. The dispatch is unchanged; the comment
  in `chain.zig` and SPEC.md now carry a number from this tree instead of one
  from 2026-09-08.

- **2026-09-14** — **ADDITIVE:** audit X3, round-2 decision Q8 (safe default plus a switch).
  `safe.safeCertificate` refuses anything over `max_certificate_len` = 8192 whatever scratch the
  caller passes, and its doc justified the number with a 4096-bit RSA certificate — while 12 of
  this module's 28 fixtures, every SLH-DSA certificate but the 128s roots and intermediates, are
  over it (8 224 B for a 128s-signed leaf up to 50 193 B for a 256f self-signed one). The default
  stays: seven consumers size a stack scratch from it. New `safe.safeCertificateOpts(der, scratch,
  .{ .max_len })` raises the bound per call, and `safe.max_pq_certificate_len` = 65536 covers every
  FIPS 205 set. `safeCertificate` is now that call with the defaults; no behaviour changes for an
  existing caller. The doc comment says what 8192 does and does not cover.

- **2026-09-08** — **Docs: say why the PKCS#1 v1.5 path calls `std.crypto`
  rather than this repository's `rsa`.** It reads backwards — `rsa` verifies the
  same signature in 36 us against std's 388 us — but path validation builds a
  key per link and no key repeats inside a chain, so cold the comparison
  reverses to ~535 us against 388 us. `fromDer` must drop below 352 us before
  switching pays. `SPEC.md` gains a "Performance" section with the chain
  numbers, the decomposition showing a chain verify is its signatures and
  nothing else, and the measurement that `safeCertificate` is 0.04% of one, so
  optimising the guard buys nothing.
  NO CONSUMER-VISIBLE CHANGE (documentation only).

- **2026-09-07** — All **four** fuzz targets in this module had run exactly one input each,
  for ever, and that input was the empty slice. Each drew `smith.bytes(&buf)` and then a
  ranged length, which returns the range minimum when fewer than eight input octets remain,
  so the length was 0; with no corpus the lane replays one round on `in = ""`. So
  `parsePssParams("")`, `findExtensions` on an empty buffer, `spkiOf("")` and `validate("")`
  were the entire fuzz coverage of this module — the one that exists to stand between
  untrusted DER and `std.crypto.Certificate.parse`. ⛔ Two of the four (in `safe.zig`) were
  written as inline `struct { fn … }` literals, which is why `check-fuzz-reach` reported
  them UNJUDGED rather than collapsed; they are named functions now so the gate can judge
  them. ⛔ Three buffers were also too small for this module's own artifacts:
  `fuzzExtensions` held 768 octets against a 920-octet `inter_pss` fixture — Shape 1 treats
  the whole buffer as a certificate, so no real certificate could have gone through it — and
  both `safe.zig` targets held 1024 against a `max_certificate_len` of 8192, which put every
  post-quantum certificate in `data/` (4–8 KB) out of reach and made the
  `n <= max_certificate_len` branch constant-true, so the over-length refusal had never run.
  Every target now draws with one `smith.slice` into a buffer sized against the module's own
  largest artifact, and carries a corpus: the RFC 4055 PSS parameter encodings this module's
  tests build, the byte-literal certificate fixtures, bare `extnValue` contents, and two
  `@embedFile`d PQ certificates (4064 and 8186 octets). Measured, before → after in
  non-empty seeds reaching the parser: 0 → 8/9, 0 → 21/22, 0 → 15/16, 0 → 15/16. Accepted
  and the second pinned number: PSS 4 accepted over **3** distinct salt lengths (every field
  of that structure has a DEFAULT, so a parse that walked nothing still returns
  `salt_len = 20`); extensions 8 certificates with an extensions block, **35** extension
  entries walked and 15 `extnValue`s parsed; `spkiOf` 10 accepted yielding **6** usable RSA
  or P-256 public keys; the validator 11 accepted with **8** certificates coming out of
  `safeCertificate` + `Certificate.parse`.

- **2026-09-01** — **Security audit: the DER guard did not guard, in three
  separate ways.** `safe.zig` advertised `safeCertificate` as returning a
  certificate "safe to hand to `std.crypto.Certificate.parse` without any risk
  of panic, out-of-bounds read, or segfault regardless of optimisation mode".
  It was not, and the argument in `SPEC.md` that said so was unsound.

  `walk` descends into **constructed** elements; `Certificate.parse` descends
  into an element's content by **field position**, whatever the constructed
  bit says. Nine bytes exploit the difference: `30 07 04 05 30 83 01 00 00` is
  a `SEQUENCE` holding a primitive `OCTET STRING` whose content declares 65536
  bytes. It passed the guard, and std then indexed at offset 65545 — abort in
  Debug, segfault in ReleaseFast. Reshaped, the same trick made `parse` return
  **successfully** with a `pub_key_slice` ending 172 bytes past the buffer,
  which the caller hands to a signature verifier as key material. `parse_slack`
  cannot help: an attacker-chosen 32-bit length is not a boundary probe.
  `requireStdDescentPoints` now requires a constructed element at every
  position std descends into, which is what carries the tiling proof over to
  std's walk. It runs in `safeCertificate`; `validateCertificate` keeps the
  narrower well-formedness contract and its doc no longer claims otherwise.

  Third shape, needing no primitive at all: an **empty BIT STRING**. std's
  `parseBitString` reads the unused-bits octet without checking one exists and
  returns `start + 1` regardless, so `03 00` yields a slice whose start is one
  past its end. Here the padding made things *worse* — it satisfied the
  unguarded read, so instead of aborting loudly the corruption surfaced
  downstream as a 4 GB `Parsed.signature()` in ReleaseFast. X.690 §8.6.2.3
  requires that octet, so `walk` rejects the encoding.

  Reachable from `iec62351`'s TLS profile, `opcua`'s `SenderCertificate`
  handling, `webauthn`'s `x5c[0]` and `dtls`'s anchor check — all peer bytes.

- **2026-09-01** — **`chain.zig` had the same BIT STRING defect and does not
  use the guard at all.** `parseShape` calls std's `parseBitString` on the
  SubjectPublicKeyInfo and signatureValue elements, both attacker-controlled.
  `verifyChain` reaches the first of them via `buildPath` on the peer's leaf
  certificate **before any signature is checked**, and `verifyMlDsaLink` /
  `verifySlhDsaLink` / `verifyPssLink` each call `parseShape` as their first
  statement. Now routed through a local `parseBitStringSafe`; two regression
  tests drive a crafted certificate through the public `verifyChain` and abort
  the test binary when the guard is removed.

- **2026-09-01** — **The public single-link PQ helpers now chain the issuer's
  name.** `verifyMlDsaLink` and `verifySlhDsaLink` checked the parameter set,
  both lengths, the validity window and the signature, but not RFC 5280
  §6.1.3 (a)(4) — so an issuer whose subject DN is not the subject's issuer DN
  was accepted. `verifyChain` was never affected (path building only offers
  candidates whose subject matches), but the doc comment invites direct use and
  their std counterpart `Parsed.verify` makes the check. Ordered after the
  parameter-set comparison so an algorithm mismatch is still reported as one.

- **2026-09-01** — **Three checks the SPEC said were pinned by tests, and were
  not.** SPEC claimed each of the ML-DSA path's four checks went red when
  removed; the key-length and signature-length comparisons did not, and the
  SLH-DSA validity window had no test while SPEC called the two paths "the
  same shape". They guard slice-to-array coercions, so in ReleaseFast their
  absence is an out-of-bounds read of up to 4627 bytes fed into verification.
  Tests added by renaming a real certificate's algorithm OIDs rather than by
  DER surgery — SHA2-128s and SHA2-128f share a key length and differ only in
  signature size, which is what makes the signature-length check expressible.

- **2026-09-01** — **Docs: the name-constraint gap fails CLOSED, not open.**
  `chain.zig`, `root.zig` and `SPEC.md` all described an unmatchable
  `GeneralName` type (`rfc822Name`, `uniformResourceIdentifier`) as a
  fail-*open* bypass. Since the `constraintTypeSupported` change both the
  excluded and the permitted side reject. The real exposure is the opposite
  one and was undocumented: a CA carrying an rfc822Name constraint turns away
  every subordinate certificate with an rfc822Name SAN, including one inside
  the permitted subtree.


- **2026-08-22** — **SLH-DSA (RFC 9882) certificates verify — all twelve FIPS
  205 parameter sets.** `x509.verifySlhDsaLink` joins the ML-DSA path added
  the same day; the module gained a `slhdsa` dependency, since std has no
  SLH-DSA at all (unlike ML-DSA, where only the X.509 *name* was missing).
  This is what owning the OID table bought: the algorithm is one table entry
  and one dispatch arm, not a redesign.

  The parameter-set check carries more weight here than for ML-DSA. `s` and
  `f` share a public-key length, and the two hash families at the same
  security category share both lengths — so SHA2-128s against SHAKE-128s is
  distinguished from a forged signature by the set comparison alone.

  Coverage is two-tier and stated rather than implied: two full OpenSSL 3.5.5
  hierarchies (one per hash family) plus one self-signed certificate per
  parameter set — a self-signed certificate is a link whose issuer is itself.
  Twelve full hierarchies would be 1.2 MB of fixtures to re-prove path
  building eleven more times. All fourteen certificates were accepted by
  `openssl verify` at generation time.

- **2026-08-22** — **ML-DSA (RFC 9881) certificates verify.** `verifyChain`
  now accepts ML-DSA-44/65/87 links and leaves, via the new
  `x509.verifyMlDsaLink` and std's `std.crypto.sign.mldsa`. The obstacle was
  never the cryptography, which std already had: `std.crypto.Certificate`'s
  OID table is an exhaustive enum with no seam to extend, so a certificate
  signed with an OID std does not carry fails at `Certificate.parse` with
  `error.CertificateHasUnrecognizedObjectId` before anything is verified. The
  new `x509.algorithm` is this module's own table — it consults std's first
  and passes std's answers through unchanged, so nothing that verified before
  resolves differently. Cross-checked against three full OpenSSL 3.5.5
  hierarchies (one per parameter set), each accepted by `openssl verify` at
  generation time.

- **2026-08-22** — **Breaking:** `VerifiedChain.leaf` is now
  `?std.crypto.Certificate.Parsed`, and two fields joined it: `leaf_der` (the
  leaf's bytes, always present) and `leaf_pub_key_algo` (this module's own
  algorithm union, which unlike std's can name every algorithm this module
  verifies). `leaf` is null exactly when std cannot parse the leaf at all —
  RSASSA-PSS, and now ML-DSA and SLH-DSA — because `Parsed.signature_algorithm` is an
  exhaustive enum with no variant for either, so any value there would be a
  wrong answer a caller could not distinguish from a right one.

  This is also a fix: a PSS-signed **leaf** previously failed `verifyChain`
  outright (only PSS-signed non-leaf links worked), which
  `chain.zig`'s doc comment recorded as a known limitation. Such a chain now
  verifies. Hostname matching for these leaves runs against the certificate's
  real `subjectAltName`/`commonName` through this module's own walk, so it is
  neither skipped nor weakened — `expected_host` is honoured on every path.

- **2026-08-22** — `extensions.ExtensionEntry` gained `value_slice`, the
  `extnValue` content as offsets rather than bytes. Additive; existing
  callers are unaffected. Needed because `std.crypto.Certificate.Parsed`
  stores slices into the certificate, not pointers.

- **2026-07-28** — New `x509.spkiOf(certificate_der)` → `x509.Spki` — a certificate's
  `SubjectPublicKeyInfo` (full TLV + algorithm OID + parameters + key
  bits) extracted over the defensive `safe.zig` walk, never through
  `std.crypto.Certificate.parse`. Every returned slice borrows the
  caller's buffer. Works on RSASSA-PSS-signed certificates, which std
  cannot parse at all. Adds `safe.oid_*` OID constants.
- **2026-07-19** — Security audit: fixed a memory-safety finding rated CRIT/HIGH (part of
  the collection-wide audit; the root changelog records no further detail
  than this).
