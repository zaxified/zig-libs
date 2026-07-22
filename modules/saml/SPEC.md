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

`Config.subject_confirmation` (`.bearer` default | `.holder_of_key` |
`.sender_vouches` | `.either`) selects which `<SubjectConfirmation Method>` may
confirm the subject. For HoK (`urn:oasis:names:tc:SAML:2.0:cm:holder-of-key`) the
presenter must actually hold the key named in the confirmation's `<ds:KeyInfo>`,
which the relying party proves by supplying the transport key it authenticated the
client with — as a certificate DER (`Config.presented_holder_cert_der`, e.g. the
TLS client certificate) and/or as a bare public key
(`Config.presented_holder_key`, a `PresentedKey` union mirroring
`xmldsig.VerifyKey`).

- **Key match — three SAME-FORM structural comparisons, no DER parsing.**
  - `<ds:X509Data><ds:X509Certificate>`: the DER is base64-decoded and compared
    **byte-for-byte** to `presented_holder_cert_der`. The certificate is **never
    parsed** (Zig 0.16 `std.crypto.Certificate.parse` is not panic-safe on hostile
    DER — the same policy as `parseIdpMetadata`).
  - `<ds:KeyValue><ds:RSAKeyValue>`: `<Modulus>` + `<Exponent>` are base64-decoded
    and compared as big-endian integers (leading-zero tolerant) to the presented
    `PresentedKey.rsa` (`rsa.PublicKey`) `n` / `e`. No signature op.
  - `<ds:KeyValue><ds:ECKeyValue>` (or the older `<dsig11:ECKeyValue>`):
    `<NamedCurve URI=…>` must identify P-256 (`urn:oid:1.2.840.10045.3.1.7`; the
    only EC curve `xmldsig.VerifyKey` supports) and the base64 `<PublicKey>` point
    is compared **byte-for-byte** to the presented `PresentedKey.ec_sec1`
    (SEC1-encoded point).
- **Limitations.** A re-encoded but equivalent certificate, or a differently
  encoded EC point (compressed vs uncompressed), will not match — the same
  deliberate safety/simplicity trade throughout. **Cross-form is deferred:** if the
  confirmation names the key ONLY as an `<X509Certificate>` while the caller
  configured only `presented_holder_key` (or the confirmation carries only a bare
  `<ds:KeyValue>` while the caller configured only `presented_holder_cert_der`),
  matching would require extracting the SubjectPublicKeyInfo from the certificate
  DER — i.e. parsing untrusted DER via `std.crypto.Certificate`, a Zig 0.16 panic
  hazard the module avoids. That case is `error.HolderOfKeyCrossFormUnsupported`;
  supply the matching form. (A defensive DER→SPKI extractor would lift this.)
- **HoK vs Bearer checks.** The HoK key check **replaces** the Bearer `Recipient`
  check. Per the SAML HoK Web-SSO profile, `Recipient` / `InResponseTo` MAY be
  omitted for HoK; when present they are still honored (`RecipientMismatch` /
  `InResponseToMismatch`). `NotBefore` / `NotOnOrAfter`, when present, are enforced.
- **Errors.** A method disallowed by policy (a HoK confirmation under `.bearer`,
  etc.) → `error.SubjectConfirmationMethodNotAllowed`. HoK required but neither
  presented cert nor presented key configured → `error.PresentedKeyMissing`. A
  same-form comparison was possible but nothing matched →
  `error.HolderOfKeyMismatch`. Only a cross-form pairing was possible →
  `error.HolderOfKeyCrossFormUnsupported`. Defaults keep the Bearer path
  byte-for-byte unchanged.

## Sender-vouches subject confirmation

`urn:oasis:names:tc:SAML:2.0:cm:sender-vouches` is accepted only under the
`.sender_vouches` or `.either` policy. Sender-vouches imposes **no** key or
recipient binding on the subject: the assertion's trust derives **entirely** from
its already-verified signature (which `saml` enforces against the configured
`idp_key`) plus the normal `<Conditions>` (`NotBefore` / `NotOnOrAfter` /
`AudienceRestriction`, all enforced before the subject-confirmation step). The
Bearer `Recipient` / `InResponseTo` correlation and the HoK key check are
therefore **not** applied.

**Trust assumption (caller-critical):** because nothing binds the presenter to a
key or channel, the caller MUST ensure the configured `idp_key` **is** the trusted
attesting authority for the subject — the signature is the *only* thing vouching.
Sender-vouches is gated behind the policy so it is never silently accepted when the
caller expects Bearer / HoK (`error.SubjectConfirmationMethodNotAllowed`
otherwise).

## Level of Assurance (eIDAS)

`Config.required_loa: ?[]const u8` (default null ⇒ no check) imposes a minimum on
the returned `<AuthnStatement><AuthnContext><AuthnContextClassRef>`. When set:

- For the eIDAS URIs (`http://eidas.europa.eu/LoA/{low,substantial,high}`) the
  natural ordering **low < substantial < high** is used; the returned level must be
  ≥ the required one.
- For any **non-eIDAS** class ref, an **exact string match** is required (there is
  no cross-family ordering: an eIDAS requirement against a non-eIDAS returned class
  ref, or vice-versa, does not meet).
- An **absent** `<AuthnContextClassRef>` never meets a requirement.

Failing the check is `error.LevelOfAssuranceInsufficient`. The returned level is
also surfaced verbatim in `AuthnResult.authn_context_class_ref`.

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

- **Holder-of-Key cross-form match (cert ↔ `<ds:KeyValue>`)** — same-form matches
  (cert-DER ↔ `presented_holder_cert_der`, `<KeyValue>` ↔ `presented_holder_key`)
  are supported; matching an `<X509Certificate>` confirmation against a bare
  presented key (or vice-versa) is `error.HolderOfKeyCrossFormUnsupported`, pending
  a defensive DER→SubjectPublicKeyInfo extractor (parsing untrusted DER via
  `std.crypto.Certificate` is a Zig 0.16 panic hazard). See "Holder-of-Key".
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

### EncryptedID / EncryptedAttribute / Holder-of-Key / sender-vouches / LoA fixtures (constructed)

These features put new content **inside** the signed assertion (an encrypted
NameID in the Subject, an encrypted Attribute in the AttributeStatement, a HoK /
sender-vouches `<SubjectConfirmation>`, an `<AuthnContextClassRef>`), which no
string edit of the openssl/lxml fixture can produce without breaking its digest.
So `test_sign.zig` **mints a fresh signed assertion** under a locally-generated
RSA key — `xmldsig.c14n` for Exclusive-C14N + `rsa.signPkcs1v15` for RSA-SHA256,
exactly as `xmldsig`'s own round-trip tests do (no signing API is exposed by the
modules). This is a **CONSTRUCTED** fixture (our canonicalizer feeds our
verifier), **not** cross-implementation interop: the byte-exact interop anchors
remain the openssl/lxml fixture (`test_fixture.zig`) and the NIST/RFC KATs in
`xmlenc`. The minted-fixture suites prove the EncryptedID / EncryptedAttribute /
HoK / sender-vouches / LoA **logic** on top of those anchors. Each is paired with
a positive control. The HoK "certificate DER" and the EC SEC1 point in the tests
are opaque byte blobs — the match is a byte/integer comparison that never parses
them, so a blob exercises the exact code path a real key would; the HoK
`<RSAKeyValue>` case, by contrast, embeds the signing key's real modulus/exponent
and matches them against the same `rsa.PublicKey`, exercising the genuine
integer-equality path. All RSA keys in these tests are test material only.

## DRY / hazard follow-ups

- **xsd:dateTime parsing** is reproduced here (civil→epoch via Hinnant's
  algorithm) because `saml` depends only on `xmldsig`+`xml`. `datefmt.partsToUnix`
  does the same arithmetic; a shared `datetime`/`iso8601` helper would let `saml`,
  a future `xmldsig` conditions check, and `jwt` (`exp`/`nbf`) share one parser.
- **`std.crypto.Certificate.parse`** is avoided on adversarial DER (metadata /
  KeyInfo certs handed back as raw bytes) — the caller pins.
