# xmldsig — XML Canonicalization + XML-Signature verification

Auditor-facing. Consumer surface is in `README.md`; canonical metadata is
`pub const meta` in `src/root.zig`. This is **layer 2** of the SAML cluster:
`xml` (parser) → **`xmldsig`** (C14N + signature verify) → `saml` (SP).

## Purpose & scope

`xmldsig` answers one question about untrusted IdP input: *is this
`ds:Signature` cryptographically valid, and does it cover the element I care
about?* It implements the two things that requires — **XML Canonicalization**
and **XML-Signature verification** — per W3C *XML Signature Syntax and
Processing (xmldsig-core 1.1)*, *Exclusive XML Canonicalization 1.0* and
*Canonical XML 1.0*.

**Out of scope (deliberate):**

- **Signing / signature generation.** We are the relying party (service
  provider) verifying an IdP's signature, never producing one. There is no
  signing API. (The test suite drives the sibling `rsa` / `p256` *signers* to
  build round-trip fixtures, but that is test scaffolding, not exported API.)
- **XPath / XSLT / arbitrary transforms** — rejected by policy (attack surface).
- **Arbitrary XPath node-sets** — the node-set model is "a subtree, optionally
  minus one omitted descendant element", which is exactly what the
  enveloped-signature transform needs and nothing more.
- **External (non-same-document) references** — rejected.
- **DTD-typed attribute normalization** (`ID`/`NMTOKENS` collapse) — the `xml`
  layer does not process DTDs, so neither do we.

## Canonicalization (`c14n.zig`)

Four modes over the `xml` infoset tree, producing canonical UTF-8 octets:

| Mode | Algorithm URI |
|------|---------------|
| `exclusive` | `http://www.w3.org/2001/10/xml-exc-c14n#` |
| `exclusive_with_comments` | `…/xml-exc-c14n#WithComments` |
| `inclusive` | `http://www.w3.org/TR/2001/REC-xml-c14n-20010315` |
| `inclusive_with_comments` | `…-20010315#WithComments` |

Shared serialization rules (both families): document order; namespace
declarations rendered before attributes, sorted by prefix (default declaration
first); attributes sorted by `(namespace-URI, local-name)`; empty elements as
explicit start+end tag pairs; CDATA replaced by its (line-ending-normalized)
content; text escaping `& < > → &amp; &lt; &gt;` and CR `→ &#xD;`; attribute
escaping `& < " → &amp; &lt; &quot;` and TAB/LF/CR `→ &#x9;/&#xA;/&#xD;`
(`>` is **not** escaped in attributes); PIs as `<?target data?>`; comments
emitted only in the WithComments variants.

**Exclusive specifics** (the subtle part): a namespace declaration is emitted at
an element only if its prefix is **visibly utilized** by that element or one of
its attributes AND the same prefix→URI is not already in force in the *output*
(the novelty rule, tracked through the output-ancestor stack). Ancestor
namespaces are **not** inherited; `xml:*` attributes are **not** inherited. The
`InclusiveNamespaces` `PrefixList` parameter is supported — listed prefixes
(and the token `#default`/`""` for the default namespace) are forced in
inclusively when in scope. The reserved `xml` namespace is never emitted as a
declaration.

**Inclusive specifics**: the apex element receives the full in-scope namespace
axis (nearest-wins) and inherited `xml:base`/`xml:lang`/`xml:space` attributes
from ancestors above the apex; descendants drop superfluous namespace
declarations (a declaration equal to the inherited one is not re-emitted).

### Enveloped-signature omission

The node-set model exposes one `omit: ?*Element` — the enveloped-signature
transform maps to "canonicalize the subtree but skip this element (the
enveloping `ds:Signature`) and its whole subtree". Only the enveloping signature
is removed; it is located as the exact `ds:Signature` element passed to
`verify`, not by name-matching.

## Signature verification (`root.zig`)

`verify(alloc, doc, signature, options) → Result`:

1. Parse `<SignedInfo>` → `<CanonicalizationMethod>`, `<SignatureMethod>`,
   one-or-more `<Reference>`.
2. **Per reference**: resolve `URI` (`""` = whole document; `#id` via the
   parser's unique-ID lookup, or a caller-named ID attribute); apply
   `<Transforms>` in order (enveloped-signature → sets the omission; exc/incl
   C14N → sets the canonicalization + any `PrefixList`); canonicalize the
   transformed subtree; digest with `<DigestMethod>`; constant-time compare to
   the base64 `<DigestValue>`.
3. **Signature**: canonicalize `<SignedInfo>` with its `CanonicalizationMethod`;
   verify the base64 `<SignatureValue>` over those octets with the configured
   key and `<SignatureMethod>`.
4. `Result.valid` = every reference digest matched **and** the SignedInfo
   signature verified.

Structural / algorithm / resolution problems return a typed `VerifyError`
(`MalformedSignature`, `UnsupportedAlgorithm`, `UnsupportedTransform`,
`UriNotResolved`, `KeyAlgorithmMismatch`, plus `OutOfMemory`); a structurally
valid signature that simply fails to verify returns `Result{ .valid = false }`
with per-reference detail. **No input path panics.**

## Algorithm allow-list (everything else rejected)

| Class | Accepted |
|-------|----------|
| C14N / transform | exclusive & inclusive C14N (both comment variants); enveloped-signature |
| Digest | SHA-256 (primary), SHA-384, SHA-512; SHA-1 only if `allow_weak_sha1` |
| Signature | RSA-SHA256 (primary), RSA-SHA384, RSA-SHA512 (RSASSA-PKCS1-v1_5); ECDSA-P256-SHA256; RSA-SHA1 only if `allow_weak_sha1` |

RSA verification uses `@import("rsa").verifyPkcs1v15`. ECDSA uses
`@import("p256").sign.ecdsaVerify` — the XML-DSig ECDSA signature is raw
`r‖s` (IEEE P1363), **not** DER; we require exactly 64 bytes. Any unlisted
algorithm URI → `error.UnsupportedAlgorithm`; any unlisted transform →
`error.UnsupportedTransform`.

## KeyInfo trust model (`saml` must understand this)

Signatures are verified **against `options.key`** — the SP's out-of-band
configured IdP key (an `rsa.PublicKey` or a SEC1 P-256 point). `<KeyInfo>` is
**never** trusted to supply the verification key. We *do* parse the first
`<KeyInfo><X509Data><X509Certificate>` (base64 DER) and return the raw DER in
`Result.x509_cert_der` so the caller can pin / compare it against their
configured certificate — but the trust decision is the caller's. This is the
correct SP posture: an attacker can always attach their own cert + matching
signature, so a self-consistent `<KeyInfo>` proves nothing.

We deliberately do **not** feed the embedded cert into
`std.crypto.Certificate.parse`: in Zig 0.16 that path is not panic-safe on
adversarial DER (a tracked library hazard). We only base64-decode and surface
the bytes; extracting a public key from the cert (with DER-defensive parsing) is
left to the caller / a future helper.

## Security posture (untrusted input)

- **Algorithm allow-list** — closed set above; unknown/dangerous algorithms and
  all XPath/XSLT/filter/base64 transforms are rejected, not executed.
- **Unambiguous reference resolution** — a `URI="#x"` must resolve to *exactly
  one* element; zero and two-or-more both fail with `UriNotResolved`. Which
  mechanism supplies the "at most one" half depends on the branch, and the
  difference matters:
  - **Default (`Options.id_attr == null`)** — the lookup goes through the `xml`
    parser's ID index, which is deduplicated at parse (`error.DuplicateId`), so
    a hit is unique by construction.
  - **`Options.id_attr` set** — the lookup is `Document.findByAttr`, which is
    first-match-in-document-order and asserts nothing, and the caller's chosen
    attribute name need not be one of the `xml.Options.id_attr_names` the
    document was parsed with, so `DuplicateId` may never have examined it.
    `resolveReference` therefore counts the carriers itself and refuses when
    there is more than one. Resolving first-match here would let "the element we
    digested" and "the element the caller reads" diverge — signature wrapping in
    one step.

  This is the DSig-layer half of the XML-Signature-Wrapping defense (the SAML
  layer adds "the signature must cover the element I actually consume").
- **No panics** — every malformed-signature path is a typed error.

### Dependency note (fixed during this work)

The `xml` parser's `parseDocument` originally skipped whitespace even inside an
element, dropping significant leading whitespace in element content — fatal for
C14N (the signer's whitespace is part of the signed octets). Fixed so that
inside an element **all** character data, including whitespace-only runs, is
preserved; document-level inter-element whitespace is still ignored. All `xml`
tests remain green.

## Validation & external-vector provenance

Green in Debug and ReleaseFast (UB-checked).

**Canonicalization — external-vector-backed (byte-exact):** the worked examples
of the W3C *Exclusive XML Canonicalization 1.0* and *Canonical XML 1.0* specs.

- exc-c14n §2.3 **Example 1** — visibly-utilized pruning (ancestor `n0` dropped)
  and its inclusive counterpart (ancestor `n0` retained).
- exc-c14n §2.3 **Example 2** — utilized-only rendering, `xml:lang` not
  inherited in exclusive, `n3` pulled in at point of use; and its inclusive
  counterpart (full axis + superfluous-namespace drop).
- Canonical XML 1.0 **§3.2** (content whitespace preserved), **§3.3**
  (namespace/attribute ordering; nested default-namespace redeclaration and
  superfluous-declaration removal), **§3.4** (text/attribute escaping, numeric
  character references, CDATA→text, control-character references). The
  DTD-typed rows of §3.4 (`normNames`/`normId`) are omitted — DTD attribute
  typing is out of scope.

**Signature verification — EXTERNAL anchor (`test_external.zig`, byte-exact
cross-tool interop):** every fixture below was produced ONCE, offline, by a
genuinely independent tool and committed as a literal byte string; nothing
shells out at test time.

- **`xmlsec1`** (C, OpenSSL backend) signed: an enveloped RSA-SHA256 document
  (and its tampered-content twin, which `xmlsec1 --verify` itself rejects with
  `Failure reason: REFERENCE`); an **enveloping** RSA-SHA256 document (the
  `<ds:Signature>` is the document root, the signed content a same-document
  `#id` `<ds:Object>` reference — the first test in this module to exercise
  successful non-empty-URI reference resolution, every prior test used
  `URI=""`); and an enveloped ECDSA-P256-SHA256 document (confirming
  `xmlsec1`'s OpenSSL backend emits the raw 64-byte IEEE-P1363 `r‖s` form this
  module requires, not DER).
- **`signxml`** (pure Python, shares no code with xmlsec1/OpenSSL) signed an
  enveloped RSA-SHA256 document independently, then `xmlsec1 --verify`
  re-confirmed it — so two mutually-independent external verifiers agree with
  this module's verifier on the same bytes. signxml's `<KeyInfo>` carries a
  real `<ds:RSAKeyValue>` (not `X509Certificate`), exercising the
  never-trust-KeyInfo path with genuine key material instead of an opaque
  blob.
- **The reverse direction** ("`xmlsec1` verifies OUR signature") is anchored
  via determinism rather than a shell-out: RSASSA-PKCS1-v1_5 (RFC 8017 §8.2)
  has no salt or nonce, so for a fixed key and message there is exactly one
  valid signature. `openssl dgst -sha256 -sign` was run OFFLINE over the
  identical canonical `<SignedInfo>` bytes `buildSignedRsaDoc` constructs
  (computed independently with `xmllint --exc-c14n`) under the SAME embedded
  test key, and `xmlsec1 --verify` confirmed the result — then a test asserts
  `buildSignedRsaDoc`'s own output is byte-identical to that externally-signed
  value. See the `EXTERNAL anchor` test next to `buildSignedRsaDoc` in
  `root.zig` for the exact reproduction commands.

**Signature verification — constructed round-trip fixtures (honestly labelled,
`root.zig`):** built by signing `<SignedInfo>` / computing reference digests
with the sibling `rsa` / `p256` signers (test-only), then driving `verify` end
to end. These fixtures prove reference-digest + SignedInfo-signature +
enveloped-transform verification agree with a real signer, and that each
mutation fails; the EXTERNAL anchors above are what make that signer's output
authoritative rather than merely self-consistent:

- valid RSA-SHA256 enveloped signature → `valid`.
- tampered signed content → reference digest mismatch → invalid.
- flipped `SignatureValue` byte → signature mismatch (digest still valid).
- wrong key → invalid.
- valid ECDSA-P256-SHA256 enveloped signature (raw `r‖s`) → `valid`.
- unsupported transform (XPath) → `UnsupportedTransform`.
- SHA-1 digest without `allow_weak_sha1` → `UnsupportedAlgorithm`.
- unresolved `URI` → `UriNotResolved`.
- `KeyInfo` X509Certificate surfaced (for pinning) while verification still uses
  the configured key.
- a non-`Signature` element → `MalformedSignature` (typed, never a panic).

The RSA test key is a 2048-bit `openssl genrsa` keypair embedded as PEM (test
material only); the ECDSA test key is a fixed 32-byte scalar. No real personal
data or production keys appear.
