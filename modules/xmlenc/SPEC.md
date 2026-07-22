# xmlenc — SPEC

W3C XML-Encryption (xmlenc-core-1) **decryption** for the SAML cluster. The
relying party (SP) holds the RSA private key and recovers the plaintext
`<saml:Assertion>` octets from a `<xenc:EncryptedData>` (typically wrapped in
`<saml:EncryptedAssertion>`), so the existing `saml` parse → signature-verify →
XSW path can run on the decrypted assertion.

## Scope

Decryption only. We are the receiving party with the private key. Encryption /
ciphertext generation is **out of scope**.

Also out of scope, and actively rejected:

- **`<xenc:CipherReference>`** (ciphertext by external URI) — dereferencing it
  is an SSRF / XXE surface. Rejected with `error.CipherReferenceUnsupported`
  before any cryptographic operation.
- **`ds:Transforms` on the ciphertext** — same dereference/transform surface;
  not honored (only inline `<xenc:CipherValue>` base64 is read).
- Super-encryption, EncryptedData referencing external key material by
  RetrievalMethod, and any KeyInfo *trust* — the caller supplies the key
  (`sk` / `Options.kek`); KeyInfo inside the EncryptedKey is never consulted.

## Algorithm allow-list (reject everything else → `UnsupportedAlgorithm`)

### Key transport / key wrap (the EncryptedKey EncryptionMethod)

| URI | Meaning | Gate |
|-----|---------|------|
| `…2001/04/xmlenc#rsa-oaep-mgf1p` | RSAES-OAEP, MGF1-SHA1, label-hash SHA-1 | default |
| `…2009/xmlenc11#rsa-oaep` | RSAES-OAEP, DigestMethod ∈ {SHA-1, SHA-256}, MGF matches digest | default |
| `…2001/04/xmlenc#rsa-1_5` | RSAES-PKCS#1 v1.5 | **gated** by `allow_weak_rsa15` |
| `…2001/04/xmlenc#kw-aes128` | RFC 3394 AES-128 key wrap | needs `Options.kek` (16 B) |
| `…2001/04/xmlenc#kw-aes256` | RFC 3394 AES-256 key wrap | needs `Options.kek` (32 B) |

**OAEP hash coupling.** The sibling `rsa` module's `decryptOaep` uses a single
`Hash` type for both the OAEP label hash and MGF1. This module therefore
supports only OAEP configurations where the DigestMethod hash equals the MGF1
hash: `rsa-oaep-mgf1p` (SHA-1/SHA-1), and xenc11 `rsa-oaep` with SHA-1/SHA-1 or
SHA-256/SHA-256. A digest/MGF mismatch (e.g. digest SHA-256 with MGF1-SHA1)
returns `UnsupportedAlgorithm`. When xenc11 `rsa-oaep` omits the `MGF` element,
the MGF is assumed to match the DigestMethod (the expressible case), not the
literal spec default of MGF1-SHA1. OAEPparams (the OAEP label `L`) is honored
when present, empty otherwise.

### Content (data) encryption (the EncryptedData EncryptionMethod)

| URI | Mode | Key |
|-----|------|-----|
| `…2001/04/xmlenc#aes128-cbc` | AES-128-CBC | 16 B |
| `…2001/04/xmlenc#aes256-cbc` | AES-256-CBC | 32 B |
| `…2009/xmlenc11#aes128-gcm` | AES-128-GCM | 16 B |
| `…2009/xmlenc11#aes256-gcm` | AES-256-GCM | 32 B |

- **GCM** (preferred): ciphertext = `IV(12) ‖ ciphertext ‖ tag(16)`, AAD empty;
  AEAD-verified, fail-closed on tag mismatch.
- **CBC**: ciphertext = `IV(16) ‖ ciphertext`; XML-Enc padding — the final byte
  `N` (1..16) is the pad length, the preceding `N-1` pad bytes are arbitrary.

**AES-192 (`aes192-cbc`/`aes192-gcm`) is `UnsupportedAlgorithm`, not a stub:**
std 0.16 ships only `Aes128`/`Aes256` block ciphers (same gap `jwe` documents
for A192*). The CEK length must match the content algorithm's key size, else
`DecryptionError`.

## Security posture (this decrypts attacker-influenced ciphertext)

- **GCM + OAEP are the safe defaults.** Use them.
- **`rsa-1_5` is Bleichenbacher-vulnerable** and, composed with XML-Enc, enables
  the Jager–Somorovsky "How to Break XML Encryption" (2011) attack. It is OFF by
  default (`allow_weak_rsa15 = false` → `WeakRsa15NotAllowed`). When enabled, the
  v1.5 unpadding accumulates every check (leading `00 02`, PS ≥ 8 nonzero octets,
  the `00` separator, message-length bound) into a single validity flag and
  returns one generic `error.DecryptionError`, so it does not branch on padding
  validity. std's RSADP range check on the (public) ciphertext is the one early
  path that is not hidden — and it is on public data. Only enable v1.5 for an IdP
  that offers nothing else; prefer migrating the IdP.
- **CBC is the padding-oracle surface.** Unpadding validates only the length
  bound and returns the same generic `error.DecryptionError` on any failure. The
  robust composition remains **decrypt → signature-verify**: because the
  decrypted assertion is then run through XML-DSig signature verification, a
  padding/oracle probe that produces a well-formed-but-wrong plaintext still
  fails the signature check. Prefer GCM where the IdP supports it.
- **Generic errors.** Every cryptographic failure (wrong key, RSA/CBC bad
  padding, GCM tag mismatch, RSADP out-of-range) maps to `DecryptionError`; the
  distinct typed errors are reserved for *structural* / *policy* conditions
  (`MalformedStructure`, `UnsupportedAlgorithm`, `WeakRsa15NotAllowed`,
  `CipherReferenceUnsupported`, `KekNotProvided`, `CiphertextTooLarge`).
- **No trust in embedded key material.** The private key / KEK come from the
  caller; KeyInfo inside the EncryptedKey is ignored.
- **Bounds & hygiene.** Decoded content is capped by `Options.max_ciphertext_len`
  (default 4 MiB). The recovered CEK is `secureZero`'d after use; RSA EM /
  OAEP scratch buffers are zeroized. Never panics — all failures are typed
  errors.

## Validation

- **Byte-exact / KAT-anchored:**
  - AES-CBC core cross-checked against **NIST SP800-38A** (F.2.5, AES-256-CBC),
    byte-exact (`root.zig` test).
  - AES key unwrap cross-checked against **RFC 3394 §4.1**, byte-exact.
  - RSA OAEP/v1.5 primitives inherit the sibling `rsa` module's own
    OpenSSL/RFC KATs.
- **Constructed round-trips** (`test_roundtrip.zig`): a locally generated
  1024-bit RSA key encrypts a CEK (OAEP-SHA1, OAEP-SHA256, PKCS1-v1.5, or
  kw-aes256) and a plaintext `<saml:Assertion>` (AES-128/256 GCM and CBC); the
  public decrypt path recovers the exact plaintext. These are self-consistency /
  interop-shape tests, **not** external byte-exact vectors — **no real external
  SAML EncryptedAssertion fixture with its private key was available**; if one is
  obtained later it should be added and cited here.
- **Teeth (with positive controls):** GCM tag tamper → `DecryptionError`; CBC
  corrupted block → `DecryptionError`; unknown content/key algorithm →
  `UnsupportedAlgorithm`; AES-192 → `UnsupportedAlgorithm`; `rsa-1_5` without
  opt-in → `WeakRsa15NotAllowed`; wrong private key → `DecryptionError`;
  CipherReference → `CipherReferenceUnsupported`; non-base64 CipherValue →
  `MalformedStructure`; kw-aes* without KEK → `KekNotProvided`.

## Status

`extract` — implemented and tested (22 tests, green in Debug and ReleaseFast).
Decryption side only. Depends on `xml` (structure walk) and `rsa` (OAEP / v1.5 /
RSADP); AES-GCM/CBC and base64 from std; RFC 3394 AES key unwrap mirrored
locally (no `jwe` dependency).
