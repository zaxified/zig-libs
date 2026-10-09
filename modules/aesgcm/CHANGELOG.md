# aesgcm — changelog

Newest first. See the root [`CHANGELOG.md`](../../CHANGELOG.md) for which
release tag each entry shipped in, and `CONVENTIONS.md` §8 for the policy.

## Unreleased

- **2026-10-09** — Dead-stack sweep (`CONVENTIONS.md` §2.1.1). `Context.init`/`initWith`,
  `AesGcm.init`/`initWith` and the stateless `encrypt`/`decrypt` now run under a 4 KiB per-message
  burn (`src/burn.zig`). Their `key: [N]u8` by-value surface is kept (std shape) with new pointer
  twins: `initInto(out, *const key)`, `initWithInto(out, b, *const key) bool`,
  `encryptInto(..., *const key)`, `decryptInto(..., *const key)` -- no key copy and no `Context`
  in the caller's frame. Additive, no existing signature changed. `stackprobe_test.zig` probes the
  twins in ReleaseFast.
- **2026-10-06** — **NO CONSUMER-VISIBLE CHANGE:** Wycheproof `aes_gcm_test.json` anchors the module
  (`tools/wycheproof.py` → `src/testdata/wycheproof.zig`): 79 valid vectors encrypt and decrypt
  exactly on every backend and the stateless path, 54 modified tags are refused with the output
  zeroed. No defect. The vectors are Apache-2.0 data: the module now carries a `NOTICE`.

- **2026-10-04** — **NO CONSUMER-VISIBLE CHANGE:** independent review of the
  whole module (tag check, failure wiping, length block, inc32, GHASH power
  count, in-place overlap, constant-time posture); no defect found. Recorded
  in SPEC § Anchoring.
- **2026-09-29** — Fix: a Debug build for a baseline x86_64 target (`-Dtarget=x86_64-linux`,
  or any CPU model without the instruction) failed to compile — Zig 0.16's self-hosted x86_64
  backend cannot encode the run-time-dispatched AES-NI kernel for such a CPU. That build now uses
  `.generic`; LLVM builds and targets that have the instruction are unchanged. Found by qap's
  portability check.
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
