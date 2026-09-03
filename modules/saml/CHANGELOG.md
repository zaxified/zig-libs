# saml — changelog

Newest first. See the root [`CHANGELOG.md`](../../CHANGELOG.md) for which
release tag each entry shipped in, and `CONVENTIONS.md` §8 for the policy.

## Unreleased

- **2026-09-03** — Drift re-audit (last audited `d163578`, ~721 lines since). ⭐ **No
  authentication-bypass path.** The XSW defence was re-probed rather than taken on trust,
  including against the C reference: `xmlsec1 --verify` reports a classic wrapping forgery —
  the legitimate signature copied onto an evil consumed assertion, the real one buried in a
  `<wrapper>` — as validly **signed**, and `saml` refuses it with
  `SignatureWrappingDetected`. Two further wrapping shapes the suite does not name (the
  assertion hidden in `<samlp:Extensions>`, and in a `<ds:Object>` inside the copied
  signature) are refused too, and no input was found where `saml` accepts what `xmlsec1`
  rejects — every measured divergence ran the other way.
  - ⛔ **`max_redirect_inflated` bounded the octets; the parse tree is what grows.** The cap
    is real and hard-enforced, and it limits the INFLATED BYTES while the quantity that
    grows is the document `xml.parse` builds from them the very next line — and the relation
    is **superlinear**. Measured in ReleaseFast on `<a/>`-dense, perfectly well-formed XML:
    64 KiB of source → 6,339,414 peak live bytes (96.7x), 256 KiB → 32,177,512 (122.7x),
    1 MiB → **163,139,946 (155.6x)**. At the old 1 MiB ceiling a **1,496-byte**
    `SAMLRequest` query field — one unauthenticated GET, no session, no credentials —
    reached ~163 MB, every byte of it before any signature exists to check, because the
    redirect binding carries no `<ds:Signature>` inside the document at all. A handful of
    concurrent requests is an OOM.
    Fixed where the defect is, not only where it was found: `xml.Options` gained
    `max_elements` (`error.TooManyElements`), because `max_depth` bounds NESTING and says
    nothing about BREADTH, and a flat document is the cheap shape. `saml` sets it to 8192
    for every parse of peer-supplied bytes and drops `max_redirect_inflated` to 64 KiB, so
    two bounds compose instead of one bounding the wrong thing. Same input, after: refused
    at **2,812,884** peak live bytes.
  - ⛔ **`saml` requires exactly ONE `<ds:Reference>` and was paying for `xmldsig`'s default
    eight.** `signedTargetMatches` refuses anything else, so references 2..8 were
    guaranteed-discarded work — and `xmldsig` gained `max_references` **in this same
    window**, with its own doc naming `saml` as the reason ("reaches this directly from an
    unauthenticated POST-binding `<Response>`"). The neighbour shipped the bound and this
    side did not collect it. Measured on the same ~800 KB document: eight `URI=""`
    references cost 244 ms and 114,805,252 peak live bytes against 78 ms and 80,104,334 for
    one — **3.1x the pre-authentication CPU** for an identical verdict. `xmldsig` refuses
    reference N+1 *before* canonicalizing it, so `.max_references = 1` removes the work
    rather than capping it.
  - **CONVENTIONS §2.1 Z2 sentences added to `AuthnResult.name_id` and `.attributes`.** The
    zeroization pass wiped the three transient decrypted buffers (Z1) and did not discharge
    the Z2 obligation on the longest-lived copy of the same secret: the decrypted subject
    identity and every `<EncryptedAttribute>` value are duped into the result arena, whose
    `deinit` is a bare `arena.deinit()`. §2.1 is explicit that this class MUST NOT be wiped
    by the module but MUST be documented; `xmlenc`, one layer down, carries the sentence.
  - ⚠ **A structural claim that was false when written, and is now checked.** The new
    `untrustedXmlOptions()` helper's doc said the budget "cannot be forgotten at one call
    site" — while three sites still inlined equivalent options. The property held, the
    guarantee did not. All six untrusted parses now route through that helper or
    `untrustedMetadataXmlOptions` (metadata keeps `xml`'s default `id_attr_names`, the one
    reason it cannot share), and a test reads the module's own source and fails if any parse
    taking the caller's allocator bypasses them.
- **2026-08-07** — ⏪ *Backfilled 2026-09-03; these entries were missing.* **BREAKING (additive):**
  closing the SAML issuer bypass added `IssuerMissing` to four exported error sets —
  `ConsumeError`, `LogoutRequestError`, `LogoutResponseError`, `ArtifactResponseError` — so
  an exhaustive `switch` written before it does not compile, and the accept/reject behaviour
  changed on every message type (the Assertion's own `<Issuer>` had never been validated).
  Also on the same day: `secureZero` applied to the three transient decrypted buffers on the
  `EncryptedAssertion` / `EncryptedID` / `EncryptedAttribute` paths.

- **2026-09-03** — Handle `xmldsig.c14n`'s new `error.MaxDepthExceeded` at all
  three `canonicalize` call sites (two on the signing path, one on the artifact
  -response path). `c14n` gained a depth bound because its `writeElement`
  recurses on the machine stack; nothing this module signs is near the limit,
  so it folds into `SigningAssemblyFailed` on the signing side and
  `MalformedSoap` for an inbound artifact response.


- **2026-08-22** — Re-exported `VerifyKey`. It is the type of `Config.idp_key`, a field on
  this module's own public config, but `xmldsig` was imported privately here, so a consumer
  had to take a direct dependency on `xmldsig` just to name the value it hands to `saml`.
  Additive. Found by writing `example/main.zig` — the first code to configure this module
  from outside.

- **2026-08-06** — Security audit: five findings fixed (part of the collection-wide
  audit; the root changelog records no further detail than this). Verified: against real
  `xmlsec1`-produced XML-Encryption and OpenSSL-signed fixtures.
- **2026-07-28** — Holder-of-Key subject confirmation now performs **cross-form** matching
  (an `<ds:X509Certificate>` confirmation against a configured bare
  `presented_holder_key`, and a `<ds:KeyValue>` confirmation against a
  configured `presented_holder_cert_der`) over `x509.spkiOf`, comparing
  key parameters — RSA modulus/exponent, P-256 affine point — never
  encodings. **BREAKING (behavioral, not signature):** pairings that
  previously always returned `error.HolderOfKeyCrossFormUnsupported` can
  now confirm a subject, and that error's meaning narrows to "key
  material was named but none of it could be reduced to a comparable
  key". Same-form matching, and every non-HoK path, are unchanged. New
  sibling dependency: `x509`.
