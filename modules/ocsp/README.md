# ocsp

RFC 6960 Online Certificate Status Protocol — build an `OCSPRequest`, and (the
security-critical half) parse + **cryptographically verify** an `OCSPResponse`
and extract a certificate's revocation status. The intended consumer is the P2
production HTTPS server's **OCSP-stapling** path: the server fetches a signed
OCSP response for its own certificate and staples it into the TLS handshake,
and a client validates the stapled response before trusting the connection.

**Status: implemented.** `buildRequest` produces a DER `OCSPRequest`
(SHA-1/SHA-256 `CertID`, optional nonce). `parseResponse` does a bounds-checked,
allocation-free decode of an `OCSPResponse` into views over the caller's
buffer. `verify` is the security core: it authorizes the responder (issuing CA
itself, matched by name or key hash, **or** a delegated responder cert carried
in the response, directly signed by the issuer and bearing the
`id-kp-OCSPSigning` EKU — RFC 6960 §4.2.2.2), verifies the `tbsResponseData`
signature (RSA PKCS#1 v1.5 SHA-1/256/384/512, ECDSA-P256 SHA-256), confirms the
`CertID` binds to the subject certificate (recomputed issuerNameHash /
issuerKeyHash / serial), checks freshness against a caller-supplied `now_unix`,
and matches a request nonce if one was sent. `zig build test-ocsp` (Debug +
ReleaseFast) covers good / revoked / unknown, tampered signature,
CertID mismatch, stale, not-yet-valid, missing-nextUpdate max-age, nonce
mismatch, unsuccessful status, both delegated-responder cases, the ECDSA path,
and a malformed-DER fuzz batch.

```zig
const ocsp = @import("ocsp");

// 1. Build a request for `subject_cert` under `issuer_cert`.
const req = try ocsp.buildRequest(gpa, subject_cert, issuer_cert, .{
    .hash = .sha1,          // classic profile; .sha256 also supported
    .nonce = my_nonce,      // optional
});
defer gpa.free(req);
// … POST `req` to the responder / receive a stapled response …

// 2. Parse + verify the response (zero-copy; keep `resp_der` alive).
const parsed = try ocsp.parseResponse(resp_der);
const verdict = try ocsp.verify(parsed, issuer_cert, subject_cert, .{
    .now_unix = current_unix_time,   // NEVER a system clock inside the module
    .expected_nonce = my_nonce,      // bind request ↔ response (optional)
});

switch (verdict.status) {
    .good => {},                                  // usable
    .revoked => |r| { _ = r.revocation_time_unix; _ = r.reason; },
    .unknown => {},                               // responder has no record
}
```

## Public API

- `buildRequest(gpa, subject_cert_der, issuer_cert_der, RequestOptions) ![]u8`
- `parseResponse(der_bytes) ParseError!Response` — `Response.status`
  (`ResponseStatus`) and, for a successful basic response, `Response.basic`
  (`Basic`: `tbs_response_data`, `responder`, `produced_at_unix`, `responses`,
  `sig_alg_oid`, `signature`, `certs`, `nonce`).
- `verify(response, issuer_cert_der, subject_cert_der, VerifyOptions) VerifyError!Verdict`
  — `Verdict{ status: CertStatus, responder: Responder, delegated: bool,
  this_update_unix, next_update_unix, produced_at_unix }`.
- Error sets `BuildRequestError`, `ParseError`, `VerifyError` — every failure
  mode is typed (bad signature, CertID mismatch, stale/not-yet-valid, untrusted
  responder, missing OCSPSigning EKU, nonce mismatch, malformed, …).

- **Model after:** RFC 6960 (OCSP). Built on this repo's `x509` (DER reader +
  `id-kp-OCSPSigning` EKU check), `rsa` (RFC 8017 PKCS#1 v1.5 verify) and
  `p256` (ECDSA-P256 verify). Never calls `std.crypto.Certificate.parse` on
  attacker-influenced input.
- **Deferred, by design:** OCSP *stapling* wire integration (the TLS server's
  job), CRL-based revocation (separate mechanism), full delegated-responder
  path building beyond the single issuer→responder link RFC 6960 requires, and
  ECDSA-P256 with SHA-384/512 (SHA-256 is the standard pairing). See `SPEC.md`.

Provenance: clean-room from RFC 6960 (a public IETF specification). See
`SPEC.md` and `NOTICE`.
