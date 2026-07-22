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

## Encrypted `<saml:EncryptedID>` / `<saml:EncryptedAttribute>`

Both wrap a `<xenc:EncryptedData>` exactly like `<EncryptedAssertion>`, but sit
INSIDE the (signed) assertion, so they are decrypted **after** the enclosing
assertion is signature-verified — the ciphertext is authenticated by enclosure
before the SP private key ever runs. Opt-in via the same `Config.sp_decrypt_key`
as EncryptedAssertion; the pass-throughs (`allow_weak_rsa15`, `decrypt_kek`)
apply.

- **`<saml:EncryptedID>`** (Subject): when the Subject carries an `<EncryptedID>`
  instead of a `<NameID>`, it is decrypted (via `xmlenc.decryptData`) to a
  `<saml:NameID>`, which drives NameID extraction as the cleartext form would.
  No key configured ⇒ `error.EncryptedIdUnsupported` (mirrors the EncryptedAssertion
  null-key discipline). A crypto/structure failure, or a plaintext that is not a
  `<saml:NameID>`, collapses to the generic `error.IdDecryptionFailed`.
- **`<saml:EncryptedAttribute>`** (AttributeStatement): each decrypts to a
  `<saml:Attribute>` and is merged into the attribute set alongside any cleartext
  `<Attribute>`s. No key ⇒ `error.EncryptedAttributeUnsupported`; failure ⇒
  generic `error.AttributeDecryptionFailed`.

Both generic decrypt errors mirror `xmlenc`'s oracle-safe collapse (no padding /
key-validity signal leaks); the safe composition is verify-enclosure-then-decrypt.

## Holder-of-Key subject confirmation

`Config.subject_confirmation` (`.bearer` default | `.holder_of_key` | `.either`)
selects which `<SubjectConfirmation Method>` may confirm the subject. For HoK
(`urn:oasis:names:tc:SAML:2.0:cm:holder-of-key`) the presenter must actually hold
the key named in the confirmation's `<ds:KeyInfo>`, which the relying party proves
by supplying the transport key it authenticated the client with
(`Config.presented_holder_cert_der`, e.g. the TLS client certificate DER).

- **Key match — X.509-DER byte-equality.** The confirmation's
  `<ds:KeyInfo><ds:X509Data><ds:X509Certificate>` DER is base64-decoded and
  compared **byte-for-byte** to `presented_holder_cert_der`. The certificate is
  **never parsed** (Zig 0.16 `std.crypto.Certificate.parse` is not panic-safe on
  hostile DER — the same policy as `parseIdpMetadata`). **Limitation:** a
  re-encoded but cryptographically-equivalent certificate, or a bare
  `<ds:KeyValue>` public key (no X509Certificate), will NOT match — the SP and its
  transport must present the identical certificate DER. This is a deliberate
  safety/simplicity trade; SubjectPublicKeyInfo-level matching would require DER
  parsing.
- **HoK vs Bearer checks.** The HoK key check **replaces** the Bearer `Recipient`
  check. Per the SAML HoK Web-SSO profile, `Recipient` / `InResponseTo` MAY be
  omitted for HoK; when present they are still honored (`RecipientMismatch` /
  `InResponseToMismatch`). `NotBefore` / `NotOnOrAfter`, when present, are enforced.
- **Errors.** A method disallowed by policy (a HoK confirmation under `.bearer`,
  or a Bearer confirmation under `.holder_of_key`) →
  `error.SubjectConfirmationMethodNotAllowed`. HoK required but no presented key →
  `error.PresentedKeyMissing`. KeyInfo present but no matching X509Certificate →
  `error.HolderOfKeyMismatch`. Defaults keep the Bearer path byte-for-byte
  unchanged.

## Validation performed on the trusted assertion

- **`<Conditions>`**: `NotBefore` / `NotOnOrAfter` (xsd:dateTime) vs `now ± skew`
  → `AssertionNotYetValid` / `AssertionExpired`. `<AudienceRestriction>` must
  name `sp_entity_id` (multiple restrictions are ANDed; fail-closed if none) →
  `AudienceMismatch`. `<OneTimeUse>` presence is flagged (`AuthnResult.one_time_use`).
- **`<SubjectConfirmation>`** (see the two sections above for the method policy):
  Bearer (Web SSO default) requires `Recipient` == `acs_url` (`RecipientMismatch`),
  `NotOnOrAfter` enforced, and `InResponseTo` == `expected_in_response_to` (or
  absent only when `allow_idp_initiated`) → `InResponseToMismatch`. Holder-of-Key
  requires the presented-key match instead of `Recipient`. The subject is confirmed
  if at least one permitted-method confirmation fully validates; otherwise the most
  specific reason is returned.
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

- **Sender-vouches** subject confirmation
  (`urn:oasis:names:tc:SAML:2.0:cm:sender-vouches`) — only Bearer and
  Holder-of-Key are validated; a sender-vouches confirmation is ignored (never
  satisfies the subject).
- **Holder-of-Key `<ds:KeyValue>` matching** — HoK confirmation is matched by
  X.509-DER byte-equality only; a bare `<ds:KeyValue>` (RSA/EC public key without
  an X509Certificate) is not matched (would require DER parsing). See
  "Holder-of-Key subject confirmation".
- **Single Logout (SLO)**, artifact binding, and the IdP side — not implemented.

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

### EncryptedID / EncryptedAttribute / Holder-of-Key fixtures (constructed)

These features put new content **inside** the signed assertion (an encrypted
NameID in the Subject, an encrypted Attribute in the AttributeStatement, a HoK
`<SubjectConfirmation>`), which no string edit of the openssl/lxml fixture can
produce without breaking its digest. So `test_sign.zig` **mints a fresh signed
assertion** under a locally-generated RSA key — `xmldsig.c14n` for Exclusive-C14N
+ `rsa.signPkcs1v15` for RSA-SHA256, exactly as `xmldsig`'s own round-trip tests
do (no signing API is exposed by the modules). This is a **CONSTRUCTED** fixture
(our canonicalizer feeds our verifier), **not** cross-implementation interop: the
byte-exact interop anchors remain the openssl/lxml fixture (`test_fixture.zig`)
and the NIST/RFC KATs in `xmlenc`. The minted-fixture suites prove the
EncryptedID / EncryptedAttribute / HoK **logic** on top of those anchors. Each is
paired with a positive control (cleartext-equivalent NameID; matching HoK cert).
The HoK "certificate DER" in the tests is an opaque byte blob — the match is a
byte comparison that never parses it, so a blob exercises the exact code path a
real cert would. All RSA keys in these tests are test material only.

## DRY / hazard follow-ups

- **xsd:dateTime parsing** is reproduced here (civil→epoch via Hinnant's
  algorithm) because `saml` depends only on `xmldsig`+`xml`. `datefmt.partsToUnix`
  does the same arithmetic; a shared `datetime`/`iso8601` helper would let `saml`,
  a future `xmldsig` conditions check, and `jwt` (`exp`/`nbf`) share one parser.
- **`std.crypto.Certificate.parse`** is avoided on adversarial DER (metadata /
  KeyInfo certs handed back as raw bytes) — the caller pins.
