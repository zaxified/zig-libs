# jwe — spec

Design + threat notes for auditors. Usage: see ./README.md.
Attribution/provenance: see ./NOTICE (module-local — see its own note on
placement).

## Design & invariants

- **Layout:** `header.zig` (JOSE Protected Header build/parse, pure
  `std.json` + `std.base64.url_safe_no_pad`, no crypto) → `enc.zig` (content
  encryption, RFC 7518 §5) and `alg.zig` (key management, RFC 7518 §4), both
  dispatched from `root.zig`'s `encryptCompact`/`decryptCompact`. `enc.zig`'s
  `cbc_hmac` builds on the shared `aescbc` module (raw AES-CBC + PKCS#7
  padding — see `modules/aescbc/SPEC.md`) for its CBC half; `alg.zig`'s
  AxxxKW/PBES2-* paths wrap/unwrap through the shared `aeskw` module (RFC
  3394 AES Key Wrap — see `modules/aeskw/SPEC.md`). Both were extracted FROM
  this module's own original implementations, so their KATs and error
  shapes are unchanged. `kat_rfc7516.zig` carries the two RFC 7516 Appendix A
  full-token worked examples as tests.
- **Compact serialization only** (RFC 7516 §3.1). The General/Flattened JSON
  serializations (§7.2) are explicitly out of scope for v1: they exist to
  carry **multiple recipients** (one `encrypted_key` per recipient, one
  shared `ciphertext`/`tag`) sharing one CEK — this module's
  `KeyMaterial`/`encryptCompact` shape is single-recipient by construction
  (one `alg` + one key in, one `encrypted_key` out). Adding JSON
  serialization later means adding a multi-recipient encrypt entry point,
  not just a different framing — a real API change, not a formatting detail.
- **`gpa`-owned results, not caller-supplied fixed buffers.** Unlike `rsa`
  (bounded by a fixed max modulus) or `jwt` (bounded token/claim sizes via an
  arena), JWE plaintext is arbitrary application data with no natural upper
  bound. `encryptCompact`/`decryptCompact` allocate their result from the
  caller's `gpa` (mirroring `jwt`'s arena-owned `ParsedToken`); every
  internally-bounded value (CEK, encrypted key, IV, tag, header JSON) still
  uses fixed-size stack scratch — the zero-alloc rule applies wherever a size
  genuinely is bounded.
- **AAD = the raw header segment bytes**, never a re-encoding. Both
  `encryptCompact` (which builds the header once and reuses those exact
  base64 bytes for both the wire segment and the AAD) and `decryptCompact`
  (which uses the token's original header substring directly, never
  re-serializing the parsed JSON) avoid any JSON-canonicalization mismatch
  between "the header as written" and "the header the tag was computed
  over" — a classic JOSE interop footgun sidestepped by construction.
- **AES-192 is a std gap, not a design choice.** Zig 0.16's
  `std.crypto.core.aes` ships only `Aes128`/`Aes256` (no AES-192 block
  cipher in ANY backend — aesni/armcrypto/soft all verified), so
  `std.crypto.aead.aes_gcm` has no `Aes192Gcm` either. `A192GCM`,
  `A192GCMKW`, `A192KW`, and `A192CBC-HS384` therefore return
  `error.UnsupportedKeyLength` — a real, typed limitation; there is
  currently no std primitive to call. Two halves of the A192 story ARE
  proven where std allows: `aeskw`'s wrap/unwrap logic is key-size-generic
  above the block cipher, and `A192CBC-HS384`'s HMAC-SHA-384 half is
  validated byte-exact against the RFC 7518 B.2 vector's `E`/`T` in
  `enc.zig`'s tests — the only missing piece is genuinely the AES-192 key
  schedule.

## Threat model

- **Key-material confusion** (the JWE analogue of `jwt`'s RFC 8725
  algorithm-confusion defense): `KeyMaterial` is a tagged union
  (`symmetric`/`rsa_public`/`rsa_private`/`password`), and both
  `encryptCompact` and `decryptCompact` check the header's `alg` against the
  *kind* of key material supplied before doing any crypto —
  `error.KeyMaterialMismatch` on any mismatch (an `RSA-OAEP` token can never
  be "verified" against a symmetric key, etc.).
- **`zip`-bomb rejection:** `header.parse` refuses any header carrying a
  `zip` member outright (`error.UnsupportedZip`), encode or decode. This
  module implements no decompression; "decrypt attacker-controlled
  ciphertext, then decompress the result" is precisely the shape of a
  compression/zip-bomb amplification attack (and the general class CRIME/
  BREACH belong to, whenever compression crosses a trust boundary) — refusing
  it outright is cheaper and safer than trying to bound it.
- **RSA-OAEP randomness:** `encryptOaep`'s security proof requires an
  unpredictable seed; `rsaOaepWrap`'s `random` parameter is never optional
  and is documented as MUST-be-cryptographically-secure at every call site
  (`alg.zig`, `root.zig`, README). Because OAEP is randomized, `KAT`
  round-trip testing of the RFC 7516 A.1 vector can only assert the DECRYPT
  direction — see `kat_rfc7516.zig`.
- **Header-size-bounded decode:** `decryptCompact` rejects a base64url
  header segment longer than `header.max_header_b64_len` (16 KiB) before
  doing any base64/JSON work — bounds the allocation a decrypt call performs
  on fully attacker-controlled input (the header segment) before any crypto
  or authentication has run.
- **Fail-closed authentication:** GCM tag mismatches return
  `error.AuthenticationFailed` and never write partial/garbage plaintext to
  the caller-visible result (std's `aead.decrypt` itself does not write on
  failure). The CBC-HMAC core (`enc.zig`) verifies the tag via
  `std.crypto.timing_safe.eql` BEFORE running any CBC decryption (a
  Vaudenay-style padding oracle is exactly what verify-after-decrypt, or a
  non-constant-time compare, reopens), and its PKCS#7 padding validation is
  branch-free over the final block with any failure surfacing as the SAME
  `error.AuthenticationFailed` as a tag mismatch — a padding error is
  indistinguishable from an authentication error to the caller.
- **The `AL` (AAD length) encoding footgun** (RFC 7518 §5.1 step 5 / §5.2.2.1
  step 4): `AL` is the **bit** length of the AAD, as an **8-byte big-endian**
  integer — not the byte length, not little-endian, not the ciphertext's
  length. Getting this wrong produces a tag that "looks like" it should
  verify and doesn't (or, on crafted inputs, a genuine forgery surface).
  Handled in `cbc_hmac.computeTag` and pinned by the RFC 7518 Appendix B
  KATs (which carry the expected `AL` bytes verbatim).
- **Const-time AES-KW integrity check** (`aeskw.unwrap`): the final
  comparison of the recovered register against `default_iv` goes through
  `std.crypto.timing_safe.eql` — an early-exit compare would turn a
  wrong-KEK/corrupted-input unwrap into a timing oracle. On failure the
  output buffer is zeroed (`std.crypto.secureZero`) so no partially-unwrapped
  key material leaks to the caller.
- **Out of scope for v1:** General/Flattened JSON serialization (multiple
  recipients — see Design above), and any `enc`/`alg` this file doesn't
  list. `ECDH-ES` / `ECDH-ES+A128KW` / `ECDH-ES+A256KW` (RFC 7518 §4.6,
  elliptic-curve key agreement on P-256 or X25519 + the Concat KDF) ARE in
  scope and implemented — see `ecdhes.zig`, byte-exact against RFC 7518
  Appendix C. Only `ECDH-ES+A192KW` is unsupported, for the same AES-192 std
  gap as the other `A192*` algorithms.

## `TODO(fable)` checklist — done-record (completed 2026-07-11)

1. ✅ **`alg.aeskw` (the shared `aeskw` module): `wrap`/`unwrap`** (RFC 3394
   AES Key Wrap, AES-128/256 KEK). Originally hand-rolled in this module as
   `aeskw.zig` (itself mirrored from `modules/dnp3/src/sa.zig`'s `aeskw`
   namespace, re-expressed against the RFC text, not imported); later
   extracted verbatim into the standalone `aeskw` module — identical
   signatures and `Error` set — so `dnp3`/`xmlenc`/`jwe` could all collapse
   onto one core. `jwe` now imports it rather than shipping a local copy.
   Byte-exact against RFC 3394 §4.1 both directions; extra tests cover
   AES-256 multi-block round-trip, wrong-KEK/corrupted-input `Unauthentic`
   (with zeroed output), and length/KEK validation. Integrity-IV compare is
   `std.crypto.timing_safe.eql`.
2. ✅ **`enc.zig`: `cbc_hmac.encrypt`/`decrypt`** (RFC 7518 §5.2 AES-CBC +
   HMAC-SHA-2, encrypt-then-MAC). The CBC + PKCS#7 mechanics were similarly
   extracted into the standalone `aescbc` module (shared with `xmlenc`);
   `cbc_hmac` now calls `aescbc.encrypt`/`decrypt`/`padPkcs7`/`unpadPkcs7` and
   keeps only the AEAD composition (AAD, the `AL` bit-length encoding, HMAC
   computation, verify-before-decrypt ordering, and remapping
   `aescbc`'s padding error onto the same `error.AuthenticationFailed` as a
   tag mismatch) local. Byte-exact against RFC 7518 Appendix B.1 and B.3, `E`
   and `T`, both directions; agrees with the std-only sanity-oracle test.
   B.2 (A192CBC-HS384): the CBC half is typed-unsupported (AES-192 std gap,
   see Design), but its HMAC-SHA-384 half is validated byte-exact against the
   B.2 vector. Tag compare is `std.crypto.timing_safe.eql`,
   verify-before-decrypt; padding and tag failures return the identical
   `error.AuthenticationFailed`.
3. ✅ **End-to-end:** `kat_rfc7516.zig`'s RFC 7516 A.3 test (A128KW +
   A128CBC-HS256) asserts byte-exact BOTH directions — decrypt recovers the
   exact plaintext, the raw key wrap reproduces §A.3.3's Encrypted Key, and
   encrypt (with the RFC's CEK + IV pinned through a fixed-stream `random`)
   reproduces §A.3.7's exact compact token through `root.zig`'s dispatch.
4. **Optional follow-up, still open (out of scope here):** an AES-192
   block-cipher core (std gap — see Design above) to unlock
   `A192GCM`/`A192GCMKW`/`A192KW`/`A192CBC-HS384` for real. A separate
   primitive, independent of (1)-(3).

## Verification

`zig build test-jwe`: all pass, no skips (header round-trips + `zip`
rejection, `A128GCM`/`A256GCM` real round-trips + tamper detection,
AES-192 documented-std-gap checks, `dir`/`RSA-OAEP-256`/GCMKW/PBES2 wiring,
RFC 3394 §4.1 AES-KW KAT + fail-closed tests, RFC 7518 B.1/B.3 CBC-HMAC
KATs both directions + B.2 HMAC-half + padding-vs-tag indistinguishability,
the RFC 7518 Appendix C ECDH-ES KATs (P-256 ECDH `Z` and Concat-KDF-derived
key, both byte-exact) plus cross-curve/invalid-peer-material/zeroing tests
for both P-256 and X25519, full `encryptCompact`/`decryptCompact`
round-trips including key-material-confusion and malformed-token rejection,
and the byte-exact RFC 7516 A.1 (decrypt-direction) and A.3
(both-directions) token KATs). Run: `zig build test-jwe` (Debug + ReleaseFast
both green).

## Status

`gap · any · codec · reentrant` + deps `rsa`, `p256`, `aescbc`, `aeskw` —
canonical source is `pub const meta` in src/root.zig ("gap" = fills a genuine
ecosystem gap, same category as `jwt`). Everything this module lists is real
and KAT-validated; the only limitation is the typed AES-192 std gap (see
Design).
