# ocsp — SPEC

RFC 6960 OCSP request building + response parsing/verification; see
[README.md](README.md) for purpose and API. Provenance: see [NOTICE](NOTICE).

## Scope

- **Request** (`buildRequest`): a DER `OCSPRequest` with a single `Request`
  whose `reqCert` is a `CertID` = { hashAlgorithm (SHA-1 per the classic
  profile, or SHA-256), issuerNameHash = H(issuer subject `Name` DER TLV),
  issuerKeyHash = H(issuer `subjectPublicKey` BIT STRING value, unused-bits
  octet excluded), serialNumber (the subject cert's serial, re-emitted
  verbatim) }. Optional `id-pkix-ocsp-nonce` (`1.3.6.1.5.5.7.48.1.2`), encoded
  as an OCTET STRING nested inside the extnValue OCTET STRING. No optional
  request signature (not needed for stapling fetches).
- **Response** (`parseResponse`): DER-decode `OCSPResponse` = { responseStatus
  (successful/malformedRequest/internalError/tryLater/sigRequired/unauthorized),
  responseBytes }. For `id-pkix-ocsp-basic` (`…48.1.1`), decode
  `BasicOCSPResponse` = { tbsResponseData, signatureAlgorithm, signature,
  certs? }; `ResponseData` = { version?, responderID (byName/byKey), producedAt,
  SEQUENCE OF SingleResponse, responseExtensions? }; `SingleResponse` = {
  certID, certStatus (good [0] / revoked [1] {revocationTime, reason?} /
  unknown [2]), thisUpdate, nextUpdate?, singleExtensions? }. Decoding is
  **allocation-free** — every field is a view into the caller's buffer.
- **Verification** (`verify`): the security core (below).

## Verification model

The check order is security-significant: the responder is authorized and the
`tbsResponseData` signature is verified **before** any per-certificate status is
trusted; the CertID binding then confirms the response applies to the subject
certificate; freshness and nonce are checked last. Every step fails **closed**.

1. **Responder authorization.**
   - *Direct* — the `ResponderID` names the issuing CA itself: `byName` equals
     the issuer's subject `Name` TLV, or `byKey` equals SHA-1 of the issuer's
     public key. The issuer's public key verifies the signature.
   - *Delegated* (RFC 6960 §4.2.2.2) — the `ResponderID` names a certificate
     carried in `certs`. That certificate MUST (a) be **directly signed by the
     issuer** (verified cryptographically — the only chaining RFC 6960
     requires, since the responder must be issued by the CA that issued the
     certificate in question), (b) carry the **`id-kp-OCSPSigning`** extended
     key usage (`1.3.6.1.5.5.7.3.9`; checked via the `x509` module's
     extension walk + `Purpose.ocsp_signing`), and (c) be within its validity
     window at `now_unix`. Its public key then verifies the response signature.
   - Failure of every path ⇒ `UntrustedResponder` / `ResponderMissingOcspSigning`
     / `ResponderCertExpired`.
2. **Signature** over `tbsResponseData`: RSA PKCS#1 v1.5 (SHA-1/256/384/512, via
   `rsa.verifyPkcs1v15`) or ECDSA-P256 (SHA-256, via `p256.sign.ecdsaVerify`
   after decoding the DER `SEQUENCE { r, s }` to `r‖s`). A tampered tbs, a wrong
   key, or an unsupported algorithm ⇒ `SignatureInvalid` /
   `UnsupportedSignatureAlgorithm` / `InvalidResponderKey`.
3. **CertID binding.** For each `SingleResponse`, the `CertID` is recomputed
   against the subject/issuer certificates *using the hash algorithm the CertID
   names* (SHA-1 or SHA-256): issuerNameHash = H(issuer subject Name TLV),
   issuerKeyHash = H(issuer public-key value), serialNumber = the subject's
   serial. All three must match, else that SingleResponse does not apply. No
   match in any SingleResponse ⇒ `CertIdMismatch`. This prevents a valid signed
   response for a *different* certificate being accepted for this one.
4. **Freshness.** `thisUpdate ≤ now_unix ≤ nextUpdate`. `now_unix` is a caller
   parameter — the module reads **no system clock** and links no time syscall.
   When `nextUpdate` is absent, a configurable `max_age_seconds` (default 24 h)
   bounds acceptance from `thisUpdate`. `now < thisUpdate` ⇒
   `ResponseNotYetValid`; past the window ⇒ `ResponseStale`.
5. **Nonce.** If `expected_nonce` is set, the response's `id-pkix-ocsp-nonce`
   value must be present and equal (constant-time compare); absent or unequal ⇒
   `NonceMismatch`. Binds a request to its response against replay.

The `Verdict` returns the matched cert status (good / revoked{time, reason?} /
unknown), the responder identity, whether a delegated responder was used, and
the validity window.

## Defensive-DER posture

A stapled OCSP response — and the delegated-responder certificate inside it —
is fully attacker-influenceable (a MITM supplies it in the handshake). Every
byte decoded here goes through `x509.extensions.parseElement`, the sibling
module's **bounds-safe** wrapper around
`std.crypto.Certificate.der.Element.parse` that pre/post-validates every offset
so a malformed length yields a catchable error instead of a process abort.
Consequences:

- The module **never** calls `std.crypto.Certificate.parse` on untrusted input
  (its extension-walk can panic on hostile DER under Zig 0.16). It walks
  certificate structure itself (`parseCert`) with the same bounded reader, and
  decodes the ECDSA `SEQUENCE { r, s }` itself rather than via a std parser.
- The outer `OCSPResponse` SEQUENCE must consume the whole buffer — **trailing
  garbage is rejected**. All context tags are matched on the raw identifier
  octet (the idiom x509 itself uses). A malformed-input fuzz batch asserts *no
  panic, always a typed error*.

## Reuse of x509 DER machinery

- **DER reader**: `x509.extensions.parseElement` (the bounded element parser)
  and the `std.crypto.Certificate.der.Element`/`Tag` types are reused directly —
  no second ASN.1 parser is written.
- **EKU**: the `id-kp-OCSPSigning` check reuses `x509.extensions.findExtensions`
  / `iterate` / `hasPurpose` + `Purpose.ocsp_signing`.
- **Friction noted**: x509's own certificate-field extractor (`chain.parseShape`
  → `Shape`) is **private**, so the narrow cert-structure walk that locates the
  subject DN / SPKI / serial / validity / tbs / signature is re-implemented here
  (on the same bounded `parseElement`). If x509 later exposes `parseShape`,
  `parseCert` here can delegate to it.

## Fixture provenance (Validation)

All OCSP responses in `ocsp_test.zig` are **CONSTRUCTED**, not captured from a
public CA: a `BasicOCSPResponse` is hand-built with this module's own DER writer
(`der_writer.zig`) and signed with the sibling `rsa` (1024-bit PKCS#1 v1.5) or
`p256` (ECDSA) modules — the same self-signed-fixture approach the other crypto
modules in this repo use — so every verification branch runs against a **real
signature over real DER** while staying hermetic (no network, no third-party
certs). Issuer/subject/delegate certificates come from `rsa.selfSignedCert`
(itself cross-validated against `std.crypto.Certificate`); the delegated
responder certificate is signed by the issuer key via the writer + `rsa`. A
separate test oracle (`extractBits`, an independent cert walker) cross-checks
`buildRequest`'s CertID hashes so the request side is validated against a second
extraction, not against the module's own `parseCert`.

Covered: good accepted (direct issuer, RSA); revoked{time, reason}; a tampered
`tbsResponseData` → `SignatureInvalid`; a CertID for a different serial →
`CertIdMismatch`; `now > nextUpdate` → `ResponseStale`; `now < thisUpdate` →
`ResponseNotYetValid`; missing `nextUpdate` honouring `max_age`; nonce match
accepted and mismatch → `NonceMismatch`; `responseStatus != successful` →
`UnsuccessfulResponse`; a delegated responder **with** OCSPSigning EKU accepted
(and `delegated == true`); a delegated responder **without** the EKU →
`ResponderMissingOcspSigning`; ECDSA-P256 direct-issuer signature accepted; a
malformed/truncated-DER batch that must never panic.

A real captured Let's Encrypt / DigiCert response + issuer could be dropped in
as an additional fixture later (parse + verify against the real issuer key); the
constructed fixtures already exercise the full verification path.

## Deferred (out of scope, not silently skipped)

- **OCSP stapling wire integration** — embedding/reading the response in the
  TLS `status_request` (RFC 6066) / `status_request_v2` extension is the TLS
  server's job; this module is the response library it calls.
- **CRL-based revocation** — a separate mechanism (a distinct future module).
- **Full path building for a delegated responder** beyond the single
  issuer→responder link RFC 6960 §4.2.2.2 mandates.
- **ECDSA-P256 with SHA-384/512** responder signatures — SHA-256 is the standard
  pairing and the only one seen in practice; RSA covers all three digests. Add a
  generic-hash ECDSA path if a responder ever needs it.
- **Request signing** (`optionalSignature`) — not needed for stapling fetches.

## Status

Implemented: request build (SHA-1/SHA-256 CertID + nonce), response parse
(allocation-free, bounds-safe), and full verification (direct + delegated
responder, RSA + ECDSA-P256, CertID binding, freshness, nonce). `zig build
test-ocsp` — green in Debug and ReleaseFast.
