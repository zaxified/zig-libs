# saml — SAML 2.0 Web Browser SSO (Service-Provider side)

Layer 3 (top) of the SAML cluster: **`xml`** (hardened, namespace-aware,
C14N-ready parser) → **`xmldsig`** (Exclusive/Canonical C14N + XML-Signature
*verify*) → **`saml`** (this module). It consumes an IdP's `<samlp:Response>` and
returns a trusted `AuthnResult`, or a typed error.

## Profile supported

- **SAML 2.0 Web Browser SSO, relying-party (SP) side** only.
- **HTTP-POST binding** for the Response (base64 of the XML) is the priority.
  A **HTTP-Redirect** decode helper (`decodeRedirectField`: base64 → raw
  DEFLATE, capped at 1 MiB) is provided for completeness (Redirect is used mostly
  for *requests*); URL-decoding is the caller's job.
- Signed **Assertion** and/or signed **Response** are both accepted
  (`Config.signature_policy` = `.assertion` | `.response` | `.either`, default
  `.either`).
- Signature algorithms and canonicalization are whatever `xmldsig` allows:
  RSA-SHA256/384/512 and ECDSA-P256-SHA256 (SHA-1 only behind
  `allow_weak_sha1`), Exclusive/Canonical C14N, enveloped-signature transform.

## Trust model

- The IdP signing key is supplied out-of-band in `Config.idp_key`
  (`xmldsig.VerifyKey` — an `rsa.PublicKey` or a SEC1 P-256 point). Signatures
  are verified against **this key only**.
- `<KeyInfo>` / `<X509Certificate>` is **never** trusted to supply the key. The
  certificate DER seen on the verifying signature is surfaced as
  `AuthnResult.x509_cert_der` (marked UNTRUSTED) purely so the caller may pin it.
- The module **never reads the system clock**: `Config.now_unix` (+
  `clock_skew_secs`) drives every time comparison. This is a testability and
  ambient-authority decision.
- Adversarial DER is never parsed here. `parseIdpMetadata` hands back raw
  certificate DER for the caller to parse/pin — it does **not** feed it to
  `std.crypto.Certificate` (which is not panic-safe on hostile DER in Zig 0.16).

## The XML-Signature-Wrapping (XSW) defense (the headline property)

`xmldsig` answers exactly one cryptographic question: *"is this `ds:Signature`
valid, and does it cover the element whose ID = X?"*. It deliberately does **not**
decide which element the SP may trust — that is this module's job and the #1
SAML vulnerability class ("On Breaking SAML: Be Whoever You Want to Be", a decade
of CVEs).

The mechanism (`signedTargetMatches` in `root.zig`):

1. Exactly **one** `<samlp:Response>` is processed, and exactly **one**
   `<saml:Assertion>` is permitted **as a direct child** of it. More than one
   assertion → `error.MultipleAssertions`.
2. For the candidate signature that `xmldsig` reports as valid, we require:
   - it carries **exactly one** `<Reference>`;
   - the `URI` is a **non-empty same-document `#id`** (empty, external, or
     multi-reference → rejected);
   - resolving that id — through the **SAML `ID` attribute**, the *same*
     unique-ID lookup `xmldsig` used — yields a node **pointer** that is
     *identical* (pointer equality, shared Document arena) to the assertion we
     are about to consume (or, for a Response-level signature, to the Response
     element that directly contains that assertion).
3. Because `xml` rejects duplicate IDs at parse time (`error.DuplicateId`), the
   id lookup is unambiguous, so pointer identity is a sound proof that the signed
   octets *are* the consumed assertion. We do **not** rely on the duplicate-ID
   guard alone — the pointer pin is the primary defense.
4. A signature that is valid but resolves elsewhere is
   `error.SignatureWrappingDetected` (never silently ignored). A response with no
   signature covering the consumed assertion is `error.SignatureMissing` — there
   is **no** optional-signature downgrade.

### XSW attack fixtures (all rejected; see `test_xsw.zig`)

Every attack fixture is a *string manipulation* of the genuinely-signed control
document — the realistic XSW model, since an attacker never holds the signing
key and can only wrap/inject/move the existing valid signature:

| Attack | Outcome |
|--------|---------|
| pristine control | **passes** |
| tamper content under the signature (NameID/attr) | `SignatureInvalid` (digest) |
| strip the signature entirely | `SignatureMissing` |
| inject a second sibling assertion (attacker NameID) | `MultipleAssertions` |
| inject a same-ID assertion | `MalformedResponse` (parser duplicate-ID) |
| classic wrap: evil consumed assertion carries a signature pointing at a buried legit assertion (digest still matches via exclusive C14N) | `SignatureWrappingDetected` |
| moved signature: Response-level signature that references the child assertion | `SignatureWrappingDetected` |
| Reference repointed to a non-existent decoy id | `SignatureInvalid` |
| `.response` policy vs an assertion-only signature | `SignatureMissing` |

## Encrypted assertions — the eIDAS encrypt profile

`<saml:EncryptedAssertion>` (XML-Encryption) is supported **when the SP opts in**
by configuring its RSA decryption key. It is decrypted via the sibling `xmlenc`
module (AES-128/256 GCM or CBC content, RSA-OAEP / — gated — RSA-1_5 key
transport, or `kw-aes*` key wrap), then the recovered `<saml:Assertion>` runs
through the **same** signature-verify + XSW + conditions/subject/audience path a
cleartext assertion does.

- **Key config** (`Config`, all optional; null ⇒ old refuse-behavior):
  - `sp_decrypt_key: ?rsa.SecretKey` — the SP's private key. **Null (default) ⇒
    an EncryptedAssertion is refused with `error.EncryptedAssertionUnsupported`**
    (unchanged for callers who did not opt in).
  - `allow_weak_rsa15: bool = false` — pass-through gate for RSA-1_5 key
    transport (Bleichenbacher / Jager–Somorovsky; off by default).
  - `decrypt_kek: ?[]const u8` — pass-through symmetric KEK for `kw-aes*`.
- **Decrypt-then-verify.** The IdP signs the assertion *before* encrypting it, so
  the signature lives inside the ciphertext and is verified only after
  decryption. This ordering is what makes the CBC/RSA-1_5 padding-oracle surface
  safe: a manipulated ciphertext yields a well-formed-but-wrong plaintext that
  then **fails the signature check** (`error.SignatureInvalid`). Decryption
  failures collapse to one generic `error.AssertionDecryptionFailed` (no oracle
  signal), mirroring `xmlenc`'s posture.
- **Exactly-one discipline spans both kinds.** A cleartext + an encrypted
  assertion, or two encrypted assertions, as direct children of the Response are
  refused (`error.MultipleAssertions`) — the XSW hardening is not weakened.
- **XSW within the decrypted document.** The decrypted assertion is the **root of
  its own standalone document**, not a direct child of the Response, so the
  "assertion must be a direct child of Response" rule does not (and cannot) apply
  to it. The pointer-pin still holds *inside* that inner document: the
  assertion-level signature's single `#id` `<Reference>` must resolve — through
  the same SAML `ID` index — to the inner document's root by pointer identity
  (`.assertion` / `.either`). Under `.response` policy the enclosing (outer)
  Response signature over the `<EncryptedAssertion>` ciphertext is verified
  against the outer document and pinned to the outer Response, with the
  EncryptedAssertion required to be its direct child.

## Validation performed on the trusted assertion

- **`<Conditions>`**: `NotBefore` / `NotOnOrAfter` (xsd:dateTime) vs `now ± skew`
  → `AssertionNotYetValid` / `AssertionExpired`. `<AudienceRestriction>` must
  name `sp_entity_id` (multiple restrictions are ANDed; fail-closed if none) →
  `AudienceMismatch`. `<OneTimeUse>` presence is flagged (`AuthnResult.one_time_use`).
- **Bearer `<SubjectConfirmationData>`** (Web SSO default): `Recipient` must equal
  `acs_url` (`RecipientMismatch`); `NotOnOrAfter` enforced; `InResponseTo` must
  equal `expected_in_response_to` (or be absent only when `allow_idp_initiated`)
  → `InResponseToMismatch`. The subject is confirmed if at least one Bearer
  confirmation fully validates; otherwise the most specific reason is returned.
- **Response level**: `<Status><StatusCode>` must be `…:status:Success`
  (`StatusNotSuccess`); `<Issuer>`, when present, must equal `idp_entity_id`
  (`IssuerMismatch`); `Destination`, when present, must equal `acs_url`
  (`DestinationMismatch`).

## Extraction (`AuthnResult`, arena-owned — nothing borrows the input)

`name_id` (+ `name_id_format`, `name_id_sp_qualifier`), `session_index`,
`authn_context_class_ref`, `attributes` (name → values, multi-value aware),
`assertion_id`, `session_not_on_or_after`, `one_time_use`, and the untrusted
`x509_cert_der`.

## Also included

- **`buildAuthnRequest`** (SP-initiated SSO): emits a `<samlp:AuthnRequest>` with
  a **caller-supplied** ID and IssueInstant (no RNG, no clock in the module),
  `AssertionConsumerServiceURL`, `Issuer`, optional `NameIDPolicy`. The caller
  applies the binding (deflate+base64+URL-encode for Redirect).
- **`parseIdpMetadata`**: `<md:EntityDescriptor>` → entityID, SSO endpoints, and
  `<md:KeyDescriptor use="signing">` certificate **DER** (raw bytes only, for the
  caller to parse/pin).

## Deferred / out of scope

- **Encrypted `<saml:EncryptedID>` / `<saml:EncryptedAttribute>`** — only the
  whole-assertion `<saml:EncryptedAssertion>` form is decrypted (see above); an
  encrypted NameID or individual encrypted attribute inside an otherwise
  cleartext assertion is not yet unwrapped (eIDAS follow-up).
- **Single Logout (SLO)**, artifact binding, and the IdP side — not implemented.
- Holder-of-Key / sender-vouches subject confirmation (only Bearer is validated).

## Fixture provenance (be honest about interop)

The end-to-end positive control (`fixtures.signed_response`) is a SAML 2.0
Response whose Assertion carries a genuine **enveloped RSA-SHA256 / Exclusive
C14N** signature. It is **not** a capture from a live IdP. It was generated with
an **independent toolchain** — **openssl** for the RSA-SHA256 signature and
**libxml2/lxml** for Exclusive XML Canonicalization — and openssl-verified before
embedding. A green verify therefore proves our `xmldsig` C14N + RSA agree
byte-for-byte with those reference implementations (**cross-implementation
interop**), not merely with themselves. The 2048-bit key is test material only.

Note on the common public fixtures: the widely-circulated `python3-saml`
`valid_response.xml` is **not** self-cryptographically-valid — its embedded
`<KeyInfo>` certificate is a placeholder, not the signer (those suites re-sign
dynamically at test time). It is unsuitable as a static end-to-end signature
fixture, which is precisely why the independent-toolchain fixture above is used.

## DRY / hazard follow-ups

- **xsd:dateTime parsing** is reproduced here (civil→epoch via Hinnant's
  algorithm) because `saml` depends only on `xmldsig`+`xml`. `datefmt.partsToUnix`
  does the same arithmetic; a shared `datetime`/`iso8601` helper would let `saml`,
  a future `xmldsig` conditions check, and `jwt` (`exp`/`nbf`) share one parser.
- **`std.crypto.Certificate.parse`** is avoided on adversarial DER (metadata /
  KeyInfo certs handed back as raw bytes) — the caller pins.
