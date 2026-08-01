# xmldsig

XML Canonicalization (C14N) + XML-Signature **verification** (W3C xmldsig-core
1.1) over the [`xml`](../xml) infoset tree. Layer 2 of the SAML cluster:
`xml` → **`xmldsig`** → `saml`.

Verification only — this is the relying-party / service-provider side that
checks an IdP's signature. There is no signing API. Depends on `xml`, `rsa`,
`p256` and `std` (SHA + base64); no other dependencies.

Provenance: clean-room from W3C *XML Signature Syntax and Processing* 1.1 and
*Exclusive* / *Canonical XML* 1.0 — public specifications, whose own worked
examples are the byte-exact canonicalization anchors. No third-party XML-DSig
implementation was consulted, so no `NOTICE` entry is required (root
[`NOTICE`](../../NOTICE) §0).

## What it does

- **Canonicalization** — Exclusive XML C14N 1.0 (`…/xml-exc-c14n#`, the
  algorithm SAML uses) and Canonical XML 1.0 (`…/REC-xml-c14n-20010315`), each
  in comment-stripping and `#WithComments` variants, with the exclusive
  `InclusiveNamespaces` `PrefixList` parameter.
- **Signature verification** — reference-digest validation (with the
  enveloped-signature and C14N transforms), then `SignatureValue` verification
  over the canonicalized `SignedInfo`.

## Trust model

Signatures are verified against a **caller-supplied key** (`Options.key`) — the
IdP key you configured out of band. `<KeyInfo>` is **never** trusted for the
key; the embedded X.509 certificate is surfaced (`Result.x509_cert_der`) only so
you can pin / compare it against your configured cert.

## Algorithms accepted (everything else is rejected)

- C14N / transforms: exclusive & inclusive C14N (both comment variants),
  enveloped-signature. XPath / XSLT / base64 / other transforms → rejected.
- Digest: SHA-256, SHA-384, SHA-512 (SHA-1 only with `allow_weak_sha1`).
- Signature: RSA-SHA256/384/512 (PKCS#1 v1.5), ECDSA-P256-SHA256
  (RSA-SHA1 only with `allow_weak_sha1`).

## Usage

```zig
const std = @import("std");
const xml = @import("xml");
const xmldsig = @import("xmldsig");

// 1. Parse untrusted input with the hardened xml parser.
var doc = try xml.parse(gpa, idp_response_bytes, .{});
defer doc.deinit();

// 2. Locate the ds:Signature element you want to check (SAML does this).
const sig = firstSignatureIn(doc.root) orelse return error.NoSignature;

// 3. Verify against your configured IdP key (loaded via the `rsa` module).
const rsa = @import("rsa");
const idp_key = try rsa.PublicKey.fromPem(idp_public_key_pem);
var result = try xmldsig.verify(gpa, &doc, sig, .{
    .key = .{ .rsa = idp_key },
    // .id_attr = "ID",             // if your profile uses a non-heuristic ID attr
    // .allow_weak_sha1 = false,
});
defer result.deinit(gpa);

if (!result.valid) return error.BadSignature;
// result.references[i].digest_valid, result.x509_cert_der (pin it), …
```

Direct canonicalization is available too:

```zig
const bytes = try xmldsig.c14n.canonicalize(gpa, element, .{ .mode = .exclusive });
defer gpa.free(bytes);
```

## Status

Green in Debug and ReleaseFast. Canonicalization is validated
byte-exact against the W3C exc-c14n / c14n-1.0 spec examples; signature
verification is validated against genuine external fixtures — `xmlsec1`
(OpenSSL) and `signxml` (pure Python) signed enveloped/enveloping RSA and
ECDSA documents this module's `verify()` accepts, and `xmlsec1 --verify`
independently confirmed this module's own signer output — plus constructed
round-trip fixtures (sign with the sibling `rsa`/`p256` signers, then verify
and mutate). See `SPEC.md`.
