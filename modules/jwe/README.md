# jwe

JSON Web Encryption (RFC 7516) with the JWA (RFC 7518) encryption algorithms,
compact serialization only. `jwe` is the encryption sibling of this repo's
`jwt` module (which does JWS/signing) — where `jwt` proves a token wasn't
tampered with, `jwe` hides its contents. Real consumer: encrypted
tokens/claims where the payload itself must not be readable by anyone
without the key (as opposed to `jwt`'s signed-but-plaintext claims).

A JWE compact token is five base64url segments:
`header.encrypted_key.iv.ciphertext.tag`. `header` names the key-management
algorithm (`alg`) and content-encryption algorithm (`enc`); `encrypted_key`
is the per-message Content Encryption Key (CEK) wrapped under `alg`;
`iv`/`ciphertext`/`tag` are the `enc` algorithm's authenticated encryption of
the plaintext, with `header` itself as Additional Authenticated Data.

All listed algorithms are implemented and KAT-validated — see "Status"
below (AES-192 variants are the one typed gap: std 0.16 has no AES-192
cipher).

- **Model after:** RFC 7516 (JWE) + RFC 7518 (JWA encryption algorithms) +
  RFC 3394 (AES Key Wrap).
- **Platform:** any. **Role:** codec (pure wire format + crypto dispatch, no
  I/O). **Concurrency:** reentrant — no shared/global state.
- **Deps:** `rsa` (RSA-OAEP / RSA-OAEP-256 key wrap), `p256` (ECDH-ES's
  P-256 curve — X25519 stays on `std`), `aescbc` + `aeskw` (the shared
  CBC content-encryption and RFC 3394 key-wrap cores).

## Status

| Algorithm | Status |
|---|---|
| `dir` (key management) | **REAL** |
| `RSA-OAEP` / `RSA-OAEP-256` (key management) | **REAL** (wraps `rsa`'s OAEP; RFC 7516 A.1 KAT) |
| `A128GCMKW` / `A256GCMKW` (key management) | **REAL** (`std.crypto.aead.aes_gcm`) |
| `A128KW` / `A256KW` (key management) | **REAL** (RFC 3394 AES Key Wrap; §4.1 + RFC 7516 A.3 KATs) |
| `PBES2-HS256+A128KW` / `PBES2-HS512+A256KW` | **REAL** (PBKDF2 KDF feeding the AES Key Wrap above) |
| `ECDH-ES` / `ECDH-ES+A128KW` / `ECDH-ES+A256KW` (key management) | **REAL** (ephemeral-static ECDH on P-256 or X25519 + Concat KDF; RFC 7518 Appendix C KAT) |
| `A128GCM` / `A256GCM` (content encryption) | **REAL** (`std.crypto.aead.aes_gcm`) |
| `A128CBC-HS256` / `A256CBC-HS512` (content encryption) | **REAL** (AES-CBC + HMAC encrypt-then-MAC; RFC 7518 B.1/B.3 KATs) |
| `A192GCM` / `A192GCMKW` / `A192KW` / `A192CBC-HS384` / `PBES2-HS384+A192KW` / `ECDH-ES+A192KW` | **UNSUPPORTED** — std 0.16 has no AES-192 cipher |

"UNSUPPORTED" means std 0.16 has no AES-192 primitive at all
(`std.crypto.core.aes` ships only `Aes128`/`Aes256`, in every backend) — a
typed `error.UnsupportedKeyLength`, never a panic or a silent wrong-key-size
substitution. `A192CBC-HS384`'s HMAC-SHA-384 half IS validated against the
RFC 7518 B.2 vector in tests; only its AES-192-CBC half has no primitive to
call.

## Usage

```zig
const jwe = @import("jwe");

// `dir` + A256GCM: fully real, end to end.
const key = [_]u8{0x2b} ** 32;
var csprng = std.Random.DefaultCsprng.init(seed); // your own CSPRNG, not std.crypto.random (removed in 0.16)
const token = try jwe.encryptCompact(
    gpa, .dir, .A256GCM, .{ .symmetric = &key }, "attack at dawn", "",
    csprng.random(), .{},
);
defer gpa.free(token);

const plaintext = try jwe.decryptCompact(gpa, .{ .symmetric = &key }, token, .{});
defer gpa.free(plaintext);

// RSA-OAEP-256 + A128GCM: also fully real.
const token2 = try jwe.encryptCompact(
    gpa, .@"RSA-OAEP-256", .A128GCM, .{ .rsa_public = pk }, "top secret", "",
    csprng.random(), .{},
);
defer gpa.free(token2);
const plaintext2 = try jwe.decryptCompact(gpa, .{ .rsa_private = sk }, token2, .{});
defer gpa.free(plaintext2);
```

`KeyMaterial` is a tagged union (`symmetric` / `rsa_public` / `rsa_private` /
`password`) — its tag must match what the header's `alg` expects, or decrypt
fails closed with `error.KeyMaterialMismatch` (the JWE analogue of `jwt`'s
`AlgKeyMismatch` algorithm-confusion defense).

`encryptCompact`/`decryptCompact` return `gpa`-owned buffers (free with the
same allocator) — unlike e.g. the `rsa` module's fixed-size buffers, JWE
plaintext is arbitrary application data with no natural upper bound, so an
allocator-owned result (mirroring `jwt`'s arena-owned `ParsedToken`) is the
honest fit here.

## SECURITY

- **Fail-closed authentication everywhere** — GCM tag, CBC-HMAC tag (verified
  constant-time BEFORE any CBC decryption; a PKCS#7 padding failure returns
  the SAME error as a tag failure — no padding oracle), and AES-KW's
  integrity IV (constant-time compare; failed unwraps zero their output).
- **`zip` (compression) is always rejected**, encode or decode — this module
  implements no decompression, and "decrypt untrusted ciphertext, then
  decompress" is exactly the shape of a zip-bomb/compression-oracle attack.
- **`random` MUST be cryptographically secure** — it supplies the CEK (when
  `alg` isn't `dir`), the content IV, the AxxxGCMKW wrap IV, and the PBES2
  salt input. `std.crypto.random` was removed in Zig 0.16; supply your own
  CSPRNG (e.g. `std.Random.DefaultCsprng` seeded from real OS entropy).
- **Compact serialization carries no extra AAD** (RFC 7516 §5.1) — a
  non-empty `aad_extra` to `encryptCompact` is `error.CompactSerializationNoAad`.
- See SPEC.md for the full threat model (constant-time tag compare,
  RSA-OAEP randomness, the AES-CBC-HMAC `AL`-encoding footgun, key-material
  confusion).

## Provenance

Clean-room from RFC 7516 (JWE), RFC 7518 (JWA), RFC 3394 (AES Key Wrap); see
`NOTICE` (module-local) and SPEC.md.
