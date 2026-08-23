# otp — changelog

Newest first. See the root [`CHANGELOG.md`](../../CHANGELOG.md) for which
release tag each entry shipped in, and `CONVENTIONS.md` §8 for the policy.

## Unreleased

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
