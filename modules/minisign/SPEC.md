# minisign — SPEC

The minisign file format; see [README.md](README.md) for purpose and API.
Provenance: see [NOTICE](NOTICE).

## Wire format

All three files (public key, secret key, signature) are the same shape: a
`# <n>` fixed-size binary struct, base64-encoded (standard RFC 4648 alphabet,
`=`-padded — the exact alphabet minisign's own hand-rolled `base64.c` uses,
same as `std.base64.standard`), framed by one or two comment lines. Struct
layouts are confirmed against `minisign.h`/`minisign.c`
(github.com/jedisct1/minisign, tag closest to the installed `minisign 0.12`)
and cross-checked byte-exact against that binary's real output (see
`kat_vectors.zig`).

- **`RawPublicKey`** (42 bytes): `sig_alg(2)="Ed" || key_number(8) || key(32)`.
- **`RawSignature`** (74 bytes): `sig_alg(2) || key_number(8) || signature(64)`.
  `sig_alg` is `"Ed"` (legacy) or `"ED"` (prehashed) — the two are otherwise
  identical containers, only the signed bytes differ (see below).
- **`RawSecretKey`** (158 bytes): `sig_alg(2)="Ed" || kdf_alg(2) ||
  chk_alg(2)="B2" || salt(32) || ops_limit_le(8) || mem_limit_le(8) ||
  key_number(8) || secret_key(64) || checksum(32)`. `kdf_alg` is `"Sc"`
  (scrypt-encrypted) or all-zero (plaintext — the CLI's `-W`).

File framing:

```
untrusted comment: <text>\n
<base64(struct)>\n
```

for public/secret keys (2 lines), and

```
untrusted comment: <text>\n
<base64(RawSignature)>\n
trusted comment: <text>\n
<base64(global_signature, 64 bytes)>\n
```

for signatures (4 lines). The untrusted comment is never authenticated
(display-only, like a git commit's `Reviewed-by`); the trusted comment IS
authenticated — that's what the global signature is for.

## Algorithms

- **`sig_alg_legacy` (`"Ed"`)**: the message signed is the file's raw bytes.
- **`sig_alg_prehashed` (`"ED"`, the modern default since minisign 0.9)**:
  the message signed is the unkeyed **BLAKE2b-512** digest of the file
  (`std.crypto.hash.blake2.Blake2b512`, libsodium's
  `crypto_generichash_BYTES_MAX` = 64). This is plain Ed25519 over a
  64-byte message — **not** RFC 8032's Ed25519ph (which has its own
  domain-separated `dom2` prefix); minisign's "prehashed" mode is simpler
  than that.
- **Global (trusted-comment) signature**: a second, ordinary Ed25519
  signature over `signature.signature (64 bytes) || trusted_comment_bytes`
  (that exact order, no separator, trusted comment has no trailing
  newline). This is a ~64-to-few-hundred-byte message, small enough that
  `signTrustedComment`/`verifyTrustedComment` allocate a scratch
  concatenation buffer rather than exposing a streaming API.
- **Determinism**: minisign's own `crypto_sign_detached` is deterministic
  (RFC 8032 EdDSA — nonce = `SHA-512(prefix || message)`, no external
  randomness) unless built with `ED25519_NONDETERMINISTIC`. This module
  always calls `Ed25519.KeyPair.sign(msg, null)` (`noise = null`), which is
  the same deterministic construction — this is *why* `kat_test.zig` can
  assert **byte-exact** signature output against real `minisign`-produced
  fixtures, not just "verifies".
- **Why not the incremental `Signer`**: `std.crypto.sign.Ed25519.KeyPair
  .signer`/`.signerWithBaseNonce` mix an extra base-nonce into the EdDSA
  nonce derivation (a deliberate safety property for multi-part streaming
  use — it decouples the nonce from having to hash the whole message
  first). That means it does **not** reproduce the plain `sign()` result
  over the same bytes, so it cannot be used here without breaking
  byte-exact parity with the reference. The global signature is small
  enough that a single `sign()` call over an allocated concatenation is
  the simpler and byte-exact choice.

## Secret-key encryption

- **KDF**: RFC 7914 scrypt (`std.crypto.pwhash.scrypt.kdf`), keystream
  length 104 bytes (`key_number(8) || secret_key(64) || checksum(32)`),
  XORed with the plaintext block. Salt is 32 bytes
  (libsodium `crypto_pwhash_scryptsalsa208sha256_SALTBYTES`).
- **Parameter encoding**: the file stores `ops_limit`/`mem_limit` as two
  8-byte little-endian integers — **not** scrypt's own `(N, r, p)`.
  libsodium derives `(N, r, p)` from those two limits via its
  `pickparams()` algorithm (`crypto_pwhash_scryptsalsa208sha256.c`); Zig
  std already implements the *identical* algorithm as
  `std.crypto.pwhash.scrypt.Params.fromLimits` (confirmed line-for-line
  against libsodium's `pickparams` — `r = 8` fixed, `N`/`p` derived the
  same way from `ops_limit`/`mem_limit`). This module calls
  `Params.fromLimits` directly; nothing is re-derived or hand-rolled.
  `ops_limit_sensitive`/`mem_limit_sensitive` (33554432 /
  1073741824 — the CLI's own default, "offline usage" preset) and
  `ops_limit_interactive`/`mem_limit_interactive` (524288 / 16777216) are
  exported to match `std`'s own `Params.sensitive`/`.interactive`, which
  were derived from the identical libsodium constants.
- **Checksum (`chk`)**: BLAKE2b-256 (`std.crypto.hash.blake2.Blake2b256`,
  libsodium's default `crypto_generichash_BYTES` = 32) over
  `sig_alg || key_number || secret_key`, all **plaintext**. It is computed
  **only when a password is set** — an unencrypted (`-W`) secret key file
  has an all-zero `chk` that is never checked on load. This exactly
  mirrors `minisign.c`: `seckey_compute_chk` is called only from inside
  `encrypt_key()`, and `seckey_load()` only calls `decrypt_key()` (which
  checks `chk`) when `kdf_alg == "Sc"`. `openSecretKey` replicates both
  halves: `password = null` skips the check entirely (matching an
  unencrypted key); a wrong password against an encrypted key is a typed
  `error.WrongPassword` from a **constant-time** compare
  (`std.crypto.timing_safe.eql`) of the recomputed vs. stored checksum —
  never a silently-wrong derived key.
- **Ed25519 key layout**: the 64-byte `secret_key` field is `seed(32) ||
  public_key(32)`, libsodium/minisign's own layout — which is *exactly*
  `std.crypto.sign.Ed25519.SecretKey`'s byte layout too
  (`SecretKey.seed()`/`.publicKeyBytes()` slice the same halves). No
  repacking is needed converting either direction; `openSecretKey` passes
  the (decrypted) bytes straight to `Ed25519.SecretKey.fromBytes` +
  `Ed25519.KeyPair.fromSecretKey`, which under `std.debug.runtime_safety`
  (Debug/ReleaseSafe) additionally re-derives the public key from the seed
  and checks it matches — a free extra integrity check in test builds.

## Comment handling

- **Untrusted comment**: display-only, not authenticated. `checkComment`
  rejects an embedded `\n`/`\r` on the write side (never emits a malformed
  multi-line file); no other restriction.
- **Trusted comment**: authenticated by the global signature. Both parse
  and write additionally require `isPrintableComment` — ASCII tab/printable,
  or a structurally-valid (non-overlong, non-surrogate) UTF-8 sequence,
  ported algorithm-for-algorithm from minisign.c's `is_printable`. This
  defends a *verifier's* terminal: without it, a maliciously crafted (but
  validly signed by someone else's key — the point is these files are often
  passed around before verification) trusted comment could carry ANSI
  escape sequences into whatever prints it.
- Neither comment string is length-capped by this module (the reference's
  `COMMENTMAXBYTES`/`TRUSTEDCOMMENTMAXBYTES` are `fgets` buffer sizes for a
  line-oriented file reader, not format invariants); callers reading
  attacker-controlled files should cap total input size themselves before
  calling `parse*File`.

## Out of scope

- The minisign CLI itself (key generation prompts, `-C`/`-R`/`-Q` flows,
  file I/O, terminal password entry) — this module is the format + crypto
  library underneath such a tool, not the tool.
- `-P <base64 pubkey>` is covered (`parsePublicKeyBase64`); nothing else
  CLI-specific.

## Validation

`kat_test.zig` asserts, in Debug and ReleaseFast, against real fixtures
generated by (and round-trip-verified with) the `minisign` 0.12 reference
binary (`kat_vectors.zig` documents the exact commands):

- Parse + verify both signature algorithms (legacy and prehashed) and both
  key states (unencrypted and password-encrypted secret key) against real
  `minisign`-produced signature files.
- **Byte-exact re-signing**: decrypt the real secret keys (one plaintext,
  one scrypt-encrypted with a known real password) with `openSecretKey`,
  re-sign the same message + trusted comment with `signFile`, and assert
  the produced `RawSignature`/global signature bytes equal the real
  `minisign`-produced ones exactly — the strongest evidence of wire
  compatibility, well beyond "verifies".
- Negative: tampered payload, tampered trusted comment, wrong key id, wrong
  password, and truncated files at several distinct cut points (missing
  line vs. corrupted base64 length), each asserted against the specific
  typed error it must produce.
