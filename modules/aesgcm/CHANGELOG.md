# aesgcm — changelog

Newest first. See the root [`CHANGELOG.md`](../../CHANGELOG.md) for which
release tag each entry shipped in, and `CONVENTIONS.md` §8 for the policy.

## Unreleased

- **2026-09-28** — **NO CONSUMER-VISIBLE CHANGE:** a ctgrind harness
  (`src/ctgrind_harness.zig`, a separate program, not part of the API)
  measures the constant-time claim: with key and plaintext tainted, the only
  secret-dependent branch on every backend is the tag check's pass/fail.
- **2026-09-28** — New module: AES-GCM (AES-128/256, 96-bit nonce) as a
  drop-in for `std.crypto.aead.aes_gcm` (`encrypt`/`decrypt`, `key_length`,
  `nonce_length`, `tag_length`, `error.AuthenticationFailed`) plus a stateful
  `Context` (`init`, `encrypt`, `decrypt`, `wipe`) that keeps the key schedule
  and GHASH powers across messages. x86-64 AES-NI + PCLMULQDQ stitched
  one-pass kernel chosen at run time, std's primitives elsewhere; 1.6–1.8× std
  at 16 KiB, 2.0–2.2× at 480 bytes, ~3× at 64 bytes. Anchored to the McGrew–Viega
  GCM test cases and to OpenSSL-generated long-message vectors, differentially
  to std. Requested by qap's TLS record path.
