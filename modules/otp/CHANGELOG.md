# otp — changelog

Newest first. See the root [`CHANGELOG.md`](../../CHANGELOG.md) for which
release tag each entry shipped in, and `CONVENTIONS.md` §8 for the policy.

## Unreleased

- **2026-10-10** — Constant time: the RFC 4226 dynamic truncation read the four code bytes at `mac[offset]`, where `offset` is the low nibble of the MAC under the secret key — a secret-dependent load address. New private `truncateCt` reads all 16 candidate windows and selects one by mask; identical output (new test over every offset). New `src/ctgrind_harness.zig` (targets `code`, `uri`, ReleaseFast): `code` went from 18 to 0 in-file contexts. `uri` (`otpauth.format` writing the secret through the `base32` module) went from 8 to 0 once `base32` became constant-time the same day. No API change.
- **2026-10-09** — Dead-stack sweep (`CONVENTIONS.md` §2.1.1). `dynamicTruncate` (the one HMAC call
  under `hotp`/`hotpFmt`/`totp`/`totpFmt`/`totpVerify` and the `KeyUri` code methods) and
  `otpauth.format` now run under a 4 KiB burn (`src/burn.zig`, per code, tight). No signature
  changed: every secret already came in as a slice. `stackprobe_test.zig` probes them.
- **2026-10-04** — Tests: first mutation run (57 mutants, 56 killed, 1 equivalent); 5 tests added in
  `otpauth.zig` (truncated `%3` label, `0x1F`/DEL rejection, `u64` multiply overflow, exact-fit
  buffer, `format` of `period = 86400` and `~`). No source change.
- **2026-09-30** — New: `otp.otpauth` — `parse` / `format` for `otpauth://totp/`
  and `otpauth://hotp/` provisioning URIs (Google Key Uri Format; output shape as
  pyotp's `provisioning_uri`), bounded and allocation-free, with `KeyUri.totpCode`
  / `hotpCode`. Secrets are base32 via the new `base32` module: `otp` now
  **depends on `base32`** (`meta.deps`, `build.zig`). The module's former
  `EMIT-ONLY` fuzz exemption is withdrawn; `parse` has a fuzz harness. Additive;
  no existing API changed.
- **2026-08-23** — **Breaking:** `fmtCode`, `hotpFmt`, and `totpFmt` return
  `FmtCodeError![]u8` (`error{OutputTooSmall}`) instead of `[]u8`. `fmtCode`
  used to guard `out.len >= digits` with `std.debug.assert` before writing
  `out[i]` in a loop; ReleaseFast compiles the assert (and the bounds check
  on those writes) out together, so an out buffer undersized for the
  requested digit count was a silent out-of-bounds write in the build that
  ships. Found by an audit sweep for this shape.
- **2026-08-14** — Docs-only: `SPEC.md` gained a `**Fuzz exemption:** EMIT-ONLY`
  entry — every public function's byte-accepting parameter is the long-lived
  shared secret `key`, provisioned out of band, never resubmitted per
  authentication attempt; the per-attempt untrusted input (`code`) is a `u32`,
  not bytes to decode. No production or test code changed; **neither breaking
  nor behavioural**.
- **2026-07-18** — Security audit: one finding fixed (part of the collection-wide audit;
  the root changelog records no further detail than this). Byte-exact against RFC 4226
  Appendix D's published test vectors.
- **2026-07-12** — New module: HOTP + TOTP one-time passwords (RFC 4226 / RFC 6238).
