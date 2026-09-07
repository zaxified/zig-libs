# saml — changelog

Newest first. See the root [`CHANGELOG.md`](../../CHANGELOG.md) for which
release tag each entry shipped in, and `CONVENTIONS.md` §8 for the policy.

## Unreleased

- **2026-09-08** — Test-only, no production change: `fuzzParseIdpMetadata`'s corpus comment
  said the per-octet substitution words were what "one seed here deliberately does not"
  omit. That was false when it was written — every seed used a bare `testkit.fuzz.seed`,
  which appends nothing, so the `boolWeighted(1, 3)` draw was `false` on every octet of
  every seed and the substitution loop had made **0 substitutions** across the whole corpus.
  A new `seedSubst` builder writes the per-octet words, one seed uses it, and the corpus
  guard now replays the substitution loop (it did not before, so it was measuring a
  different computation from the harness) and pins the count at **6**, all on that one seed.
  The five document seeds still arrive verbatim, which is what a corpus of real documents
  wants; the pin is what would notice them acquiring a tail and being mangled into
  something the parser refuses.


- **2026-09-07** — Test-only, no production change: both fuzz targets ran one input, and
  the metadata one could not have run its own reference document even with a working draw.
  `fuzzDecodeFields` and `fuzzParseIdpMetadata` each opened `smith.bytes(&buf)` and then
  drew a length with `smith.valueRangeAtMost`; a ranged `Smith` draw reads eight octets as
  a little-endian `u64` and returns the range MINIMUM when fewer than eight remain, and
  `bytes` had already eaten them - so `len` was **0** every round and all three decoders
  were handed `""`. Separately, `fuzzParseIdpMetadata`'s buffer was **512 octets** while
  the module's only complete IdP metadata document (the one in `test "parseIdpMetadata:
  endpoints + signing cert DER"`) is **718** - and a seed longer than the buffer reads back
  EMPTY rather than truncated, so that document could never have passed through its own
  harness. Buffer raised to 2048, both targets draw with `smith.slice`, and both gained a
  corpus. Measured by the two new `corpus:` guards - binding fields: 6 non-empty seeds, 5
  POST decodes, **1 Redirect decode**, 182 XML octets recovered; IdP metadata: 5 non-empty,
  1 parsed, **1 SSO endpoint and 1 signing cert**, which is the 718-octet document getting
  through. The endpoint and cert counts are pinned rather than a parse count because an
  empty `<md:EntityDescriptor/>` would parse to an empty `Metadata`. The Redirect seed was
  added after the first draft measured `redirect_ok == 0` - a corpus of refusals only
  exercises the refusal path.

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
- **2026-09-03** — **A sender-vouches `<SubjectConfirmationData>` was never read**, so a
  signed `NotOnOrAfter` on it was discarded. SAMLCore §2.4.1.2 lists `NotBefore`/
  `NotOnOrAfter` there as "optional attributes that can apply to ANY method"; the Bearer and
  HoK arms both honour them and this arm returned without fetching the element. Since
  `<Conditions>`' own two time attributes are enforced only IF PRESENT, an assertion whose
  `<Conditions>` carries just an `<AudienceRestriction>` had **no expiry bound anywhere** on
  that path — measured: accepted 75 years after the `NotOnOrAfter` its own signed
  `<SubjectConfirmationData>` declared. Not injection (the assertion is signature-protected
  and the policy is opt-in): a replay window with no upper bound, on the IdP's own attempt to
  set one. Now enforced through a shared `validateConfirmationTimeBounds`, mutation-checked.
- **2026-09-03** — ⛔ **Recorded, NOT fixed.** (a) An extension `<saml:Condition>` the SP does
  not understand is silently IGNORED, where SAMLCore §2.5.1.1 says the assertion "is
  considered to be Indeterminate" and "MUST be rejected", and SAMLProf §4.1.4.2 repeats it.
  Fail-OPEN against a restriction the IdP deliberately attached (step-up, delegation limit,
  eIDAS constraint). Measured: a genuinely signed assertion carrying
  `<saml:Condition xsi:type="ext:StepUpRequiredType"/>` and `<saml:ProxyRestriction Count="0"/>`
  is accepted. Refusing changes acceptance behaviour for existing deployments, so it is an
  **owner decision**, not a drive-by fix. (b) Under `.either`, `validateSubjectConfirmation`
  returns on the first fully-valid confirmation, so a leading sender-vouches one makes a
  following Bearer confirmation's `Recipient`/`InResponseTo` checks unreachable — measured
  with `Recipient=https://attacker.example/acs`. Same class of decision. (c) Ten live guards
  still have no regression test (33-mutation sweep): the fail-closed audience rule, the
  bearer `NotOnOrAfter`, the absent-`InResponseTo` rule, the ArtifactResponse XSW pin, the
  Response-level `res.valid`, the two decrypted-root type checks, and both HoK data checks.
  (d) `Version` is never read (SAMLCore §4.1.2 MUST); at-least-one `<AuthnStatement>`
  (SAMLProf §4.1.4.2) is not required; `<AttributeStatement>`/`<AuthnStatement>` are read
  first-match though the schema allows repeats — and `required_loa` gates on the first.
  (e) `ArtifactResponseResult`'s doc claims extraction leaves an embedded inner signature
  "unaffected"; true for exclusive C14N, false for inclusive, which is XML-DSig's default.
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
