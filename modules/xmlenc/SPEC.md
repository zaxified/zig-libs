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

The kw-aes* unwrap is delegated to the shared `aeskw` module (`aeskw.unwrap`,
RFC 3394 §2.2.2) — xmlenc no longer carries its own key-unwrap core; any
`aeskw` error (bad length, unsupported KEK length, integrity-check failure)
collapses to this module's generic `DecryptionError`.

**Decoupled OAEP digest / MGF1 hash (digest != MGF1 is supported).** The
sibling `rsa` module exposes `decryptOaepH(sk, LabelHash, MgfHash, ...)`,
which treats the OAEP label-digest hash and the MGF1 hash as independent
parameters (RFC 8017 §7.1.2 does not couple them). This module resolves both
independently from the EncryptedKey's `ds:DigestMethod` and xenc11 `MGF`
elements and dispatches to `decryptOaepH` with whichever pair was requested —
`rsa-oaep-mgf1p` is SHA-1/SHA-1 fixed; xenc11 `rsa-oaep` supports any of
{SHA-1, SHA-256} for DigestMethod crossed with any of {MGF1-SHA1, MGF1-SHA256}
for MGF, **including a mismatched pair** (e.g. DigestMethod=SHA-256 with
MGF1=SHA-1 — a real-world interop shape some IdPs emit). Only a genuinely
unrecognized digest or MGF algorithm URI (not SHA-1/SHA-256, or MGF1-SHA384/
SHA512, which this module does not implement) returns `UnsupportedAlgorithm`.
When xenc11 `rsa-oaep` omits the `MGF` element, the MGF defaults to the
xenc11-spec default MGF1-SHA1 (not "assumed to match the digest" — that
assumption is no longer needed now that the hashes are decoupled).
OAEPparams (the OAEP label `L`) is honored when present, empty otherwise.

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
  The raw CBC core and the XML-Enc unpad are both delegated to the shared
  `aescbc` module (`aescbc.decrypt` + `aescbc.unpadXmlEnc`) — xmlenc no longer
  carries its own CBC loop or unpad logic; any `aescbc` error (misaligned
  input, invalid pad) collapses to this module's generic `DecryptionError`.

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
  that offers nothing else; prefer migrating the IdP. See **Constant-time
  posture** below for exactly how far that claim has been verified.
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

## Constant-time posture

Scoped to `rsaPkcs1v15Unwrap`, the one place in this module that makes a
secret-dependent decision of its own. (GCM tag comparison is std's; AES-KW
integrity uses `std.crypto.timing_safe.eql`; OAEP is delegated to
`rsa.decryptOaepH`; algorithm-URI comparisons are over public strings.)

**What the code does.**

- Every validity check — leading `00`, block type `02`, the `00` separator's
  existence, PS ≥ 8, the message-length bounds — is an all-ones/all-zeros mask
  produced by `ctEqByteMask` / `ctEqMaskUsize` / `ctGeMaskUsize`, which are pure
  integer arithmetic (`|`, `&`, `~`, `-%`, shift). No comparison operator is
  applied to a secret-derived value.
- The separator scan always walks the whole block. The message extraction tries
  every *public* separator position under a mask instead of reading `em` at the
  secret offset `sep_idx + 1`, so the memory-access pattern is a function of the
  modulus length only.
- The write into the caller's CEK buffer is a fixed 64-byte masked copy on every
  path. A rejected block leaves the buffer all-zero; it is neither skipped nor
  sized by `msg_len`, and no recovered plaintext survives there.
- **One** branch on secret-derived data remains: the final accept/reject. It is
  the outcome itself and nothing follows it but the return. Both outcomes
  collapse to the same `error.DecryptionError` at every caller, and `saml`
  collapses them again into `AssertionDecryptionFailed`.

**What is verified, and what is not.**

- *Verified by the suite:* the fixed-length, unconditional, zero-on-reject shape
  of the message copy (two `TEETH (F3)` tests in `src/root.zig`, both of which go
  red against the previous `@memcpy(out[0..msg_len], em[sep_idx + 1 ..])` behind
  an early `return error`); and the mask helpers, exhaustively over all 65 536
  byte pairs plus a boundary table for the `usize` forms. The helpers are
  load-bearing — a wrong mask turns the RFC 8017 §7.2.2 teeth tests red.
- *NOT verified:* that the emitted machine code is branch-free. **No test in this
  repo measures timing**, and none can: a unit test cannot see a conditional
  move, cannot time a cache miss, and cannot prevent a future compiler from
  lowering the mask arithmetic into a branch. `std.crypto.timing_safe.classify`
  (valgrind/ctgrind) and a dudect-style statistical harness are the tools that
  would close this; neither is wired into this repo, and `classify` is a silent
  no-op without valgrind. Treat the constant-time property as *argued from the
  source, not measured*.
- The residual risk is therefore compiler-dependent, which is one more reason
  `allow_weak_rsa15` stays off by default. Migrating the IdP off `rsa-1_5`
  remains the only complete answer.

## Validation

- **Byte-exact / KAT-anchored:**
  - AES-CBC core cross-checked against **NIST SP800-38A** (F.2.5, AES-256-CBC
    and F.2.1, AES-128-CBC), byte-exact — now anchored in the shared `aescbc`
    module's own tests (single source of truth); this module's CBC coverage
    comes from the round-trip tests exercising the full `aesCbcDecrypt` path.
  - AES key unwrap cross-checked against **RFC 3394 §4.1, §4.3, §4.5, §4.6**,
    byte-exact — anchored in the shared `aeskw` module's own tests, plus a
    local §4.1 byte-exact test here exercising this module's `aesKwUnwrap`
    wrapper.
  - RSA OAEP/v1.5 primitives (including the decoupled-hash `decryptOaepH`
    path) inherit the sibling `rsa` module's own OpenSSL/RFC KATs.
- **Constructed round-trips** (`test_roundtrip.zig`): a locally generated
  1024-bit RSA key encrypts a CEK (OAEP-SHA1, OAEP-SHA256, OAEP with a
  mismatched SHA-256-digest/MGF1-SHA1 pair, PKCS1-v1.5, or kw-aes256) and a
  plaintext `<saml:Assertion>` (AES-128/256 GCM and CBC); the public decrypt
  path recovers the exact plaintext. These are self-consistency /
  interop-shape tests, **not** external byte-exact vectors.
- **EXTERNAL anchor** (`test_external.zig`): a real `<xenc:EncryptedData>`
  produced ONCE, offline, by `xmlsec1 --encrypt` (C, OpenSSL backend — a
  genuinely independent XML-Enc implementation) against a freshly-generated
  2048-bit RSA keypair, committed as a literal fixture:
  - RSA-OAEP-mgf1p key transport + AES-256-GCM content — decrypts to the exact
    plaintext.
  - xenc11 `rsa-oaep` (DigestMethod=SHA-256, **MGF element omitted** — a real
    interop shape that exercises the xenc11-spec MGF1-SHA1 default, not merely
    an explicit MGF value) + AES-256-CBC content — decrypts to the exact
    plaintext.
  - A tampered copy (one base64 char flipped in the content `CipherValue`)
    that `xmlsec1 --decrypt` itself refuses is refused here too
    (`error.DecryptionError`).
  `xmlsec1 --decrypt` independently confirmed all three outcomes on these exact
  bytes before they were pasted in. The reverse direction ("xmlsec1 decrypts
  what we produce") does not apply: this module is decrypt-only by design (see
  README "Scope") and has no encrypt API to hand xmlsec1 anything.
- **Teeth (with positive controls):** GCM tag tamper → `DecryptionError`; CBC
  corrupted block → `DecryptionError`; unknown content/key algorithm →
  `UnsupportedAlgorithm`; AES-192 → `UnsupportedAlgorithm`; `rsa-1_5` without
  opt-in → `WeakRsa15NotAllowed`; wrong private key → `DecryptionError`;
  CipherReference → `CipherReferenceUnsupported`; non-base64 CipherValue →
  `MalformedStructure`; kw-aes* without KEK → `KekNotProvided`; a genuinely
  unrecognized xenc11 MGF algorithm URI → `UnsupportedAlgorithm` (the positive
  control confirming the allow-list gate still holds now that digest != MGF
  is otherwise accepted).

## Status

`extract` — implemented and tested (green in Debug and ReleaseFast).
Decryption side only. Depends on `xml` (structure walk), `rsa` (OAEP / v1.5 /
RSADP, including decoupled-hash OAEP), `aescbc` (CBC core + XML-Enc unpad),
and `aeskw` (RFC 3394 key unwrap) — this module no longer carries any local
hand-rolled CBC or key-wrap implementation; those are single-sourced in their
respective sibling modules. AES-GCM and base64 remain from std.
