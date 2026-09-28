# aesgcm — changelog

Newest first. See the root [`CHANGELOG.md`](../../CHANGELOG.md) for which
release tag each entry shipped in, and `CONVENTIONS.md` §8 for the policy.

## Unreleased

- **2026-09-28** — New module: AES-GCM (AES-128/256, 96-bit nonce) as a
  drop-in for `std.crypto.aead.aes_gcm` (`encrypt`/`decrypt`, `key_length`,
  `nonce_length`, `tag_length`, `error.AuthenticationFailed`) plus a stateful
  `Context` (`init`, `encrypt`, `decrypt`, `wipe`) that keeps the key schedule
  and GHASH powers across messages. x86-64 AES-NI + PCLMULQDQ stitched
  one-pass kernel chosen at run time, std's primitives elsewhere; 1.7–1.8× std
  at 16 KiB, 2.2× at 480 bytes, ~3× at 64 bytes. Anchored to the McGrew–Viega
  GCM test cases and to OpenSSL-generated long-message vectors, differentially
  to std. Requested by qap's TLS record path.
