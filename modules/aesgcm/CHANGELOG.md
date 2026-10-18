# aesgcm — changelog

Newest first. See the root [`CHANGELOG.md`](../../CHANGELOG.md) for which
release tag each entry shipped in, and `CONVENTIONS.md` §8 for the policy.

## Unreleased

- **2026-10-18** — Test fix: the `Context` size bounds in the backend test apply only when std's AES key schedule is plain round keys; on targets with software AES (s390x, mips) the schedule is 3-4 KiB, so the bound measured std, not this module. No source change.
- **2026-10-18** — Ported to Zig 0.17.0. No source change beyond the repo-wide codemod (all `@bitCast` sites audited; aesgcm's are x86-64-only, so LE memory order is unchanged).
- **2026-10-10** — Nonce and tag lengths: `pub fn AesGcm(key_bits, Options)` with
  `Options{ .nonce_length = 12, .tag_length = 16 }` — any nonce of 1 byte or more (J0 by
  GHASH, SP 800-38D §7.1) and tags of 16/15/14/13/12, or 8/4 under Appendix C; other
  lengths are compile errors. `Aes128Gcm`/`Aes192Gcm`/`Aes256Gcm` are `AesGcm(n, .{})`,
  unchanged in API and code path (a 12-byte nonce still builds J0 directly; the stateless
  generic path still calls std's AEAD for 128/256). The generic backend's CTR now wraps the
  32-bit counter as inc32 when a hashed nonce puts J0 near the wrap (std's `modes.ctr` alone
  would carry into the nonce bits). Anchors: Wycheproof's 113 non-96-bit-IV tests incl.
  CounterWrap, 147 OpenSSL long-message rows with 8/16/60/128-byte and counter-wrapping
  nonces, every shorter tag against the full one with each bit flipped; fuzz harness draws
  eight nonce/tag shapes (backends and stateless must agree). ctgrind re-measured: same 6
  in-file contexts per row (the tag-check verdict), digests updated. Scope core → parity.

- **2026-10-10** — tools: comparative benchmark `tools/bench.zig` + `tools/c_bench/foreign_bench.c` (`zig build bench-aesgcm`) against OpenSSL 3.5.5 EVP AES-GCM; card Performance filled (0.23–1.00×, fastest not measured) and a SPEC "Performance" section with the raw table.
- **2026-10-10** — AES-192: new `Aes192Gcm` (same API). Generic backend and stateless generic path over the new `aes192` module (dep added; std 0.16 has no AES-192); the x86-64 stitched kernel runs it with Nr = 12 and its own `aesenclast` Nk = 6 key expansion (checked against `aes192`). Anchors: McGrew–Viega 7–10, 17 OpenSSL long-message rows, Wycheproof's 64 AES-192 tests (37 valid, 27 forged); differential, bit-flip, inc32 and fuzz harnesses cover all three sizes. ctgrind rows 4 → 6 in-file (the tag-check verdict for the third key size).
- **2026-10-09** — tests: deterministic fuzz driver `AESGCM_FUZZ` over the existing harnesses (the harness also checks that the genuine tag is accepted and decrypts to the message).
- **2026-10-09** — **NO CONSUMER-VISIBLE CHANGE:** documented why `Context.encrypt`/`decrypt` carry
  no dead-stack burn (keyed-transform state, §2.1 Z3; the owning protocol entry point burns).
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
