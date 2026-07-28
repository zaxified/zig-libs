# saml — SAML 2.0 Web Browser SSO (Service-Provider side)

Layer 3 (top) of the SAML cluster: **`xml`** (hardened, namespace-aware,
C14N-ready parser) → **`xmldsig`** (Exclusive/Canonical C14N + XML-Signature
*verify*) → **`saml`** (this module). It consumes an IdP's `<samlp:Response>` and
returns a trusted `AuthnResult`, or a typed error.

## Profile supported

- **SAML 2.0 Web Browser SSO, relying-party (SP) side** only. **Single Logout
  (SLO)** and the **Artifact binding** (message layer) are also implemented —
  see their own sections below. The IdP side is out of scope throughout.
- **HTTP-POST binding** for the Response (base64 of the XML) is the priority.
  A **HTTP-Redirect** codec (`decodeRedirectField` / `encodeRedirectField`:
  base64 ↔ raw DEFLATE, capped at 1 MiB on decode) is provided; URL-encoding
  is the caller's job. SLO messages fully support Redirect, including the
  query-string signing scheme (`buildSignedRedirectQuery` /
  `verifyRedirectSignature`) — see "Single Logout" below.
- Signed **Assertion** and/or signed **Response** are both accepted
  (`Config.signature_policy` = `.assertion` | `.response` | `.either`, default
  `.either`).
- Signature algorithms and canonicalization, for VERIFYING an IdP's
  signatures, are whatever `xmldsig` allows: RSA-SHA256/384/512 and
  ECDSA-P256-SHA256 (SHA-1 only behind `allow_weak_sha1`), Exclusive/Canonical
  C14N, enveloped-signature transform. For the SP's OWN outgoing signatures
  (SLO, Artifact) it is RSA-SHA256/exclusive-C14N only — see "SP-side signing"
  below.

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
- **Key match — two CROSS-FORM comparisons** (the confirmation names the key in
  the other form from the one the caller supplied). Both run only after every
  same-form pairing has been tried and has not matched.
  - `<X509Certificate>` vs `presented_holder_key`: the certificate's
    `SubjectPublicKeyInfo` is extracted with **`x509.spkiOf`**, a defensive
    raw-DER walk that validates the whole TLV structure and never calls
    `std.crypto.Certificate.parse` (see the `x509` module's SPEC). The recovered
    key is then compared with the presented one **by parameters**: RSA by
    big-endian modulus + exponent (the same comparison the same-form
    `<RSAKeyValue>` path uses), P-256 by the affine point recovered through
    `fromSec1`.
  - `<ds:KeyValue>` vs `presented_holder_cert_der`: the certificate is reduced to
    a key once, up front, the same way; an `<RSAKeyValue>` is then matched with
    the very same `rsaKeyValueMatches` the same-form path uses, and an
    `<ECKeyValue>` by canonical point comparison.
- **Why cross-form cannot be spoofed by re-encoding.** Nothing in the cross-form
  path compares encodings. An RSA key is (n, e), compared as integers with
  leading zeros stripped — two encodings of one key compare equal and two
  distinct keys cannot. A P-256 key is an affine point: both sides go through
  `fromSec1`, which rejects malformed and off-curve inputs and yields the
  canonical uncompressed form, so a compressed `<PublicKey>` naming the
  certificate's key matches while no other byte string can. Different
  algorithms never match each other (an RSA certificate is never confirmed by
  any EC point, whatever its bytes). Anything that cannot be reduced to a key —
  malformed DER, an algorithm outside RSA/P-256, an EC key without a
  `namedCurve`, a non-P-256 curve — is **incomparable**, which is a rejection,
  never a match.
- **Remaining same-form limitations (unchanged).** Same-form certificate
  matching is still DER byte-equality, so a re-encoded but equivalent
  certificate does not match it; same-form `<ECKeyValue>` matching is still
  point-byte equality against the caller's opaque `.ec_sec1` blob. Both are
  deliberately left as they were: the cross-form path is where curve context
  exists on both sides, so it is the one that canonicalizes. In practice a
  re-encoded certificate now still matches *via* the cross-form key comparison
  whenever the caller also supplies `presented_holder_key`.
- **HoK vs Bearer checks.** The HoK key check **replaces** the Bearer `Recipient`
  check. Per the SAML HoK Web-SSO profile, `Recipient` / `InResponseTo` MAY be
  omitted for HoK; when present they are still honored (`RecipientMismatch` /
  `InResponseToMismatch`). `NotBefore` / `NotOnOrAfter`, when present, are enforced.
- **Errors.** A method disallowed by policy (a HoK confirmation under `.bearer`,
  etc.) → `error.SubjectConfirmationMethodNotAllowed`. HoK required but neither
  presented cert nor presented key configured → `error.PresentedKeyMissing`. At
  least one comparison ran to a verdict and none matched →
  `error.HolderOfKeyMismatch`. Key material was named but NONE of it could be
  reduced to a comparable key → `error.HolderOfKeyCrossFormUnsupported` (kept,
  with its meaning narrowed from "cross-form is not implemented" to "nothing
  here could be compared"). Defaults keep the Bearer path byte-for-byte
  unchanged.

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

## SP-side signing (`SigningKey`) — the one departure from "verify-only"

Every capability above this point (and everything before this section was
added) is pure verification — this module checks an IdP's signature, never
produces one, mirroring `xmldsig`'s own stated scope. Single Logout and the
Artifact binding both require the SP to sign its own OUTGOING message (a
`LogoutRequest`/`LogoutResponse` it sends, or the `ArtifactResolve`
back-channel call), so a small signing primitive was added for exactly that:

- **RSA-SHA256 / exclusive C14N only.** This is already the primary algorithm
  everywhere else in this module. ECDSA-P256 signing is deliberately **not**
  implemented for the SP's own signatures: XML-DSig ECDSA needs a fresh
  per-signature nonce, and this module's standing rule is "no RNG, no clock"
  (the caller supplies IDs and timestamps — see `AuthnRequestOptions`, unchanged).
  A safe nonce-supplying API is separate work from the two gaps this closes.
  **Verifying** the IdP's own signatures is entirely unaffected and still
  accepts RSA-SHA256/384/512 and ECDSA-P256 via `xmldsig.verify`.
- `signProtocolMessage` (private) is the shared two-pass signer
  (`buildLogoutRequest`, `buildLogoutResponse`, `buildArtifactResolveSoap` all
  call it): assemble with a placeholder digest → canonicalize the whole
  element minus the (still-placeholder) `<ds:Signature>` (enveloped transform +
  exclusive C14N) → hash → splice the digest in → canonicalize the now-real
  `<ds:SignedInfo>` → RSA-sign → splice the `<ds:SignatureValue>` in. Same
  recipe `test_sign.zig` already used to mint fixtures; this is the PRODUCTION
  copy the SP runs on its own messages.
- Failure modes: `error.SigningAssemblyFailed` (an internal invariant — the
  self-generated, pre-escaped XML failed to parse — should never happen, typed
  rather than a panic) and `error.SigningFailed` (the configured RSA key was
  rejected by `rsa.signPkcs1v15`: too small for SHA-256 PKCS1v15 padding, or a
  computation-integrity fault).

## Single Logout (SAML Core §3.7 / Bindings) — SLO

`LogoutRequest`/`LogoutResponse`: build (+ optionally RSA-SHA256-sign) an
outgoing message, or parse + verify an incoming one, over both the POST and
Redirect bindings.

- **Mandatory signature, no downgrade.** An incoming `LogoutRequest` is ALWAYS
  signature-verified before its `NameID`/`SessionIndex` are trusted — same
  "no optional signature" posture as the Response/Assertion path. This matters
  specifically because an unauthenticated `LogoutRequest` is a
  denial-of-service against the named session: anyone who could forge one
  could log out any user at will. `LogoutResponse` is held to the same
  standard for consistency (a forged failure/success status is otherwise
  trivially spoofable), even though SAML Core does not strictly mandate it.
- **`NameID` may be `<saml:EncryptedID>`.** Symmetrically with the existing
  Response/Subject path, `decryptWrappedElement` (generalized — see "DRY"
  below) decrypts it via `Config.sp_decrypt_key`; null ⇒
  `error.EncryptedIdUnsupported`. Because `LogoutRequest` has no enclosing
  signed Assertion the way a Subject's `EncryptedID` does, the decryption here
  runs on the ALREADY signature-verified `LogoutRequest` itself (verify → then
  decrypt, same safe ordering).
- **The two bindings are mutually exclusive by construction (SAML Bindings
  §3.4 vs §3.5).** POST embeds a `<ds:Signature>` in the XML; Redirect signs
  the QUERY STRING instead and the message XML carries none. `SignatureSource`
  (`.embedded` | `.redirect_verified`) makes the caller state which trust
  mechanism already ran — `.embedded` looks for and verifies a `<ds:Signature>`
  itself; `.redirect_verified` is the caller's ATTESTATION that
  `verifyRedirectSignature` already returned `true` out-of-band. There is no
  way to enforce that attestation from inside a pure codec with no side
  channel to the HTTP layer — the naming and doc comments are the safeguard,
  same as e.g. `Config.allow_idp_initiated`'s trust-the-caller precedent
  elsewhere in this module.
- **Redirect query-string signing (`buildSignedRedirectQuery` /
  `verifyRedirectSignature`, SAML Bindings §3.4.4.1)** — did not exist in this
  module before. The SigningInput is the exact percent-encoded
  `SAMLRequest=`/`SAMLResponse=` value, then (if present) `&RelayState=`
  value, then `&SigAlg=` value, in that fixed order, nothing else.
  `appendPercentEncoded` is RFC 3986 percent-encoding (unreserved
  `A-Za-z0-9-_.~` pass through, everything else `%XX` uppercase) — applied
  identically when signing and when reconstructing the SigningInput to verify,
  so it is deterministic regardless of how a peer implementation happened to
  percent-encode the same bytes. RSA-SHA256 only, matching `SigningKey`; a
  `sig_alg` naming anything else is `error.UnsupportedAlgorithm` (an IdP
  configured for ECDSA-P256 here is out of scope — the POST binding, an
  embedded XML signature via `xmldsig.verify`, is unaffected and already
  accepts it).
- **Replay — caller responsibility (this module does no I/O and keeps no
  state).** A captured, genuinely-signed `LogoutRequest` replayed later must
  not terminate a session established AFTER it was issued. Two properties
  combine to bound this:
  1. **`SessionIndex` scoping.** The IdP mints a FRESH `SessionIndex` on every
     new authentication, so a `LogoutRequest` naming index X can only ever
     affect the (single) local session recorded under X — a session
     re-established after logout gets a NEW index, so a replayed request for
     the old one is inert against it. **The caller MUST key its session store
     by `SessionIndex`** (or `NameID`+`SessionIndex`), never "the current
     session for this NameID" without checking the index.
  2. **`ID`/`IssueInstant` deduplication.** Nothing stops an attacker replaying
     the EXACT SAME captured request against the SAME still-live session
     before it naturally expires. **The caller MUST maintain a seen-`ID`
     cache** (keyed by `LogoutRequestResult.id`) for at least the message's
     validity window (`not_on_or_after` if present, else a caller-chosen bound
     from `issue_instant` + clock skew) and reject a repeat. This module
     surfaces `id`/`issue_instant`/`not_on_or_after` precisely so the caller
     can implement this — it cannot do so itself.
- **`LogoutResponse` status is checked, never assumed.** The top-level
  `<samlp:StatusCode>` must be the Success URI or `error.StatusNotSuccess`; a
  NESTED second-level `<samlp:StatusCode>` (e.g.
  `urn:oasis:names:tc:SAML:2.0:status:PartialLogout`, used by some responders
  to flag that not every session participant was reached, on an otherwise
  Success top-level status) is surfaced as
  `LogoutResponseResult.second_level_status_code` — **the caller MUST inspect
  it** to detect a partial logout.
- **XSW.** `LogoutRequest`/`LogoutResponse` have only one element that could
  ever be the signing target (the message root itself — no nested Assertion
  the way Response has), but the pointer-pin (`signedTargetMatches`, reused
  verbatim) still matters: a moved signature whose `#id` Reference resolves to
  a buried decoy copy of the genuinely-signed original, rather than to the
  (attacker-forged) outer root, is `error.SignatureWrappingDetected` — proven
  in `test_slo.zig`, not merely assumed because the defense exists for
  Response/Assertion.

## Artifact binding (SAML Bindings §3.6) — message layer only

`Artifact`/`encodeArtifact`/`decodeArtifact` (the `SAMLart` wire format: 2-byte
TypeCode `0x0004` + 2-byte EndpointIndex + 20-byte SourceID + 20-byte
MessageHandle, all big-endian/raw, base64'd for transport) and the
`ArtifactResolve`/`ArtifactResponse` SOAP payloads.

- **The library/application boundary, stated plainly.** The back-channel
  resolution step is an HTTP round trip to the IdP's
  ArtifactResolutionService (typically over mutual TLS) — this is a LIBRARY,
  not an HTTP client, so PERFORMING that call is explicitly NOT this module's
  job. `buildArtifactResolveSoap` constructs the request bytes; the caller
  sends them over their own HTTP/SOAP client and gets a response body;
  `consumeArtifactResponseSoap` verifies that response body and extracts the
  enclosed message. This mirrors how the rest of this module already separates
  codec from I/O (`parseIdpMetadata` hands back endpoints/DER for the caller
  to dereference/pin, never fetches anything itself).
- **`SourceID`** is conventionally (not mandatorily, per the format) SHA-1 of
  the issuing entityID — `sourceIdFromEntityId`. **`MessageHandle`** gets NO
  RNG from this module (the standing "no RNG, no clock" rule): the caller
  generates it securely and owns its uniqueness.
- **`ArtifactResponse`'s own signature is mandatory**, pointer-pinned exactly
  like every other message this module verifies — no optional-signature
  downgrade. Verifying it authenticates every byte inside via the enveloped
  transform, including the enclosed message.
- **Extracting the enclosed message.** `consumeArtifactResponseSoap` returns
  it re-serialized via `xmldsig.c14n.canonicalize` (Exclusive C14N) into a
  self-contained standalone document, safe to re-parse and hand to
  `consumeResponseXml`/`consumeLogoutResponseXml`/etc., which perform their OWN
  full independent verification. This is sound specifically because Exclusive
  C14N is, by design, independent of ancestor context — an embedded signature
  inside the enclosed message (over its own content) canonicalizes identically
  whether it is still nested inside the `ArtifactResponse` or has been lifted
  out into its own document, exactly the property the existing
  `EncryptedAssertion`-inside-a-signed-`Response` path already relies on with
  the reverse operation (decrypt-and-re-parse rather than serialize-and-lift).
- **The IdP side (building `ArtifactResponse`, consuming `ArtifactResolve`) is
  out of scope**, unchanged from every other message type in this module.

## Deferred / out of scope

- **Holder-of-Key cross-form match (cert ↔ `<ds:KeyValue>`)** — **DONE**, over
  `x509.spkiOf` (the defensive DER→SubjectPublicKeyInfo extractor this was
  waiting on). Only RSA and EC P-256 keys are comparable, matching what
  `PresentedKey` can express; anything else is
  `error.HolderOfKeyCrossFormUnsupported`. See "Holder-of-Key".
- **Single Logout (SLO)** — **DONE**, see above.
- **Artifact binding** — **DONE** (message layer; the back-channel HTTP round
  trip is explicitly the caller's job), see above.
- **The IdP side** — still not implemented, and not planned: this module is
  the SP (relying-party) side only, as stated in its header.
- **ECDSA-P256 for the SP's OWN outgoing signatures** (`SigningKey` is
  RSA-SHA256 only) — see "SP-side signing" above. Verifying the IdP's
  signatures is unaffected.

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

### Single Logout / Redirect-signing / Artifact fixtures (be honest about interop)

- **`test_slo.zig`** (LogoutRequest/LogoutResponse): every signed fixture is a
  **CONSTRUCTED, SELF round-trip** — a locally-generated RSA key signs (via
  the module's own `signProtocolMessage`) and the module's own
  `consumeLogoutRequestXml`/`consumeLogoutResponseXml` verify. There is no
  OASIS-published byte-exact `LogoutRequest`/`LogoutResponse` fixture to anchor
  against, so this follows the SAME precedent `test_sign.zig` already set for
  the EncryptedID/HoK suites: the underlying RSA-SHA256/exclusive-C14N
  enveloped-signature PRIMITIVE is already externally anchored elsewhere in
  this module (`test_fixture.zig`, openssl+lxml, byte-exact; the W3C C14N
  vectors in `xmldsig`) — what these tests newly prove is the ORCHESTRATION on
  top: schema assembly, NameID/SessionIndex/status extraction, and — the part
  that most needed re-proving rather than assuming — that the
  mandatory-signature and XSW pointer-pin defenses are actually wired in for
  this NEW message type. That last property is proven by MUTATION, not merely
  by a positive test: with `consumeLogoutRequestXml`'s signature check
  temporarily reduced to `.embedded => {}` (an actual edit made and reverted
  during development, not a hypothetical), the "unsigned rejected", "flipped
  SignatureValue", and "XSW moved-signature" tests all genuinely FAILED —
  including the XSW case, which the mutation caused to return the
  attacker-forged `NameID` as if it were the victim's. That confirms the tests
  fail for the reason they claim, not for some unrelated defect.
- **`test_redirect_binding.zig`** (HTTP-Redirect query-string signing) carries
  the one genuine EXTERNAL anchor this task added:
  `verifyRedirectSignature: EXTERNAL anchor` signs a fixed 120-byte
  SigningInput (chosen to exercise `+`, `/`, `=`, space, `&`, `:`, `#`
  percent-encoding all at once) OFFLINE with `openssl dgst -sha256 -sign`
  under a throwaway 2048-bit RSA key (private key discarded after signing;
  only the public key and the resulting signature are embedded in the test),
  independently confirmed with `openssl dgst -sha256 -verify` before being
  pasted in. A green `verifyRedirectSignature` against that fixed signature is
  real cross-implementation interop for the percent-encoding + SigningInput
  construction + RSA-SHA256/PKCS1v15 verification path — nothing in this
  module reproduces the anchor value at test time. A paired tamper test
  (`EXTERNAL anchor tamper`) flips one byte of `RelayState` and confirms the
  SAME openssl signature then fails, proving the anchor actually exercises
  message content. Every other test in that file (`buildSignedRedirectQuery`
  round-trips, the flipped-signature/wrong-key/tampered-message negative
  tests, the end-to-end Redirect-binding `LogoutRequest` test) is explicitly a
  CONSTRUCTED self round-trip — this module's own signer feeding its own
  verifier — because there was, before this task, no prior anchor for this
  mechanism to reuse; anchoring it externally once (above) and self-testing
  the rest is the same posture `test_sign.zig` takes for minted assertion
  fixtures.
- **`test_artifact.zig`**: `Artifact` encode/decode is pure bit-twiddling
  (byte-order/length checks), not a signature scheme, so no external anchor
  applies. `buildArtifactResolveSoap`'s signed output is checked against
  `xmldsig.verify` DIRECTLY (an independent code path from this module's own
  wrapper) rather than round-tripped through `saml`'s own consumer — a
  slightly stronger self-check than a pure round-trip, though still
  CONSTRUCTED, not external interop. `consumeArtifactResponseSoap` needs a
  stand-in "IdP-signed" `ArtifactResponse` to test against; since `saml` is
  SP-only and never builds that message type (the IdP side is out of scope,
  same as `<samlp:Response>`), `signArtifactResponse` in the test file mints
  one with the same two-pass recipe `test_sign.zig` already uses for
  `<samlp:Response>` fixtures, for the identical reason. The
  missing-signature and flipped-SignatureValue tests are a matched pair
  (`SignatureMissing` vs `SignatureInvalid`) proving the rejection reasons are
  distinct, not merely "some check failed".

## DRY / hazard follow-ups

- **xsd:dateTime parsing** is reproduced here (civil→epoch via Hinnant's
  algorithm) because `saml` depends only on `xmldsig`+`xml`. `datefmt.partsToUnix`
  does the same arithmetic; a shared `datetime`/`iso8601` helper would let `saml`,
  a future `xmldsig` conditions check, and `jwt` (`exp`/`nbf`) share one parser.
  Its return type is now the minimal `error{InvalidDateTime}` rather than the
  wider `ConsumeError`, specifically so the Single-Logout/Artifact code (their
  own, narrower error sets) can `try` it directly — Zig widens a narrower
  error set at the call site automatically, so this is a compatible narrowing,
  not a behavior change for existing callers.
- **`std.crypto.Certificate.parse`** is avoided on adversarial DER (metadata /
  KeyInfo certs handed back as raw bytes) — the caller pins.
- **Signature-algorithm URI string constants** (`sig_alg_rsa_sha256`,
  `dig_alg_sha256`, `alg_enveloped_sig`) are duplicated from `xmldsig`'s own
  (private, unexported) equivalents, for the same reason the xsd:dateTime
  parsing is duplicated: `saml` depends on `xmldsig` but these URI strings are
  not part of its public API. If `xmldsig` ever exports them, `signProtocolMessage`
  and the Redirect-signing code should switch to the shared constants.
- **`decryptWrappedElement`** is now generic over the caller's error-set type
  (`comptime E: type`) instead of hardcoding `ConsumeError`, and takes
  `sp_decrypt_key`/`allow_weak_rsa15`/`decrypt_kek` directly instead of a whole
  `Config` — this is what let the Single-Logout `EncryptedID` path reuse it
  without duplicating the decrypt-then-reparse logic a third time.
