# oscore — changelog

Newest first. See the root [`CHANGELOG.md`](../../CHANGELOG.md) for which
release tag each entry shipped in, and `CONVENTIONS.md` §8 for the policy.

## Unreleased

- **2026-09-06** — A1 security audit, the HIGH findings fixed. **Consumer-visible:**
  three new error values. `protect` returns `error.MessageTooLong` for a plaintext
  over `max_plaintext_len` (65 535 B — AES-CCM-16-64-128's 2-byte length field);
  `unprotect` returns it for a payload over `max_ciphertext_len` (that plus the
  tag) BEFORE the AEAD runs — previously an oversized payload panicked in
  Debug/ReleaseSafe ahead of the tag check (a keyless remote crash) and
  `protect` in ReleaseFast emitted a non-CCM length field. `computeNonce` (and
  `unprotect`, via `request_nonce_source.partial_iv`) returns
  `error.PartialIvTooLarge` instead of truncating a Partial IV `>= 2^40` to the
  nonce of `partial_iv mod 2^40`. New API for RFC 8613 §7.5 / Appendix B.1
  restart recovery: `SenderContext.needsCheckpoint`/`resumeAfterRestart`
  (SSN2 = SSN1 + K + F) and `ReplayWindow.resumeAtLowerLimit`; SPEC.md gains a
  "Persistence" section — re-deriving a used context was a two-time pad and a
  500/500 replay, and nothing in the module said so. `deriveContext` wipes its
  derived-key locals and scrubs the stack its HKDF callees vacated. Tests: a
  request delivered twice through `unprotect`, the default window width at its
  edge, a response opened with a nonce-source id that differs from the
  recipient id, non-empty Class I `options`, both `kid` fields non-empty, the
  three previously untested fail-closed guards, and every new guard above —
  each pinned by a mutation that turns the suite red. The fuzz harness draws
  one `smith.slice` and carries a ten-seed corpus (it had decoded the empty
  option once per run). NOTICE no longer describes the cores as stubs.
- **2026-08-23** — Added `OscoreOption.encodePartialIv`, the minimal-length
  big-endian Partial IV encoding `encode()` already used internally, now
  public. Found writing the consumer example: `AadParams.request_piv` (§5.4)
  must carry a request's own Partial IV in this exact wire form, but a
  caller protecting its own request has no `Protected.option.partial_iv`
  bstr to read it back from before calling `protect` — this module's own
  README usage sample worked around the gap with `&.{@intCast(seq)}`, which
  truncates (and panics in Debug/ReleaseSafe) for any sequence number
  `>= 256`. `encode()` now calls the same helper instead of duplicating the
  logic inline; README fixed to use it.
- **2026-07-18** — Security audit: one finding fixed (part of the collection-wide audit;
  the root changelog records no further detail than this). Byte-exact against RFC 8613
  Appendix C's published test vectors.
- **2026-07-12** — New module: OSCORE — Object Security for Constrained RESTful
  Environments (RFC 8613) — end-to-end object security for CoAP: §3.2.1 HKDF-SHA-256
  security-context derivation.
