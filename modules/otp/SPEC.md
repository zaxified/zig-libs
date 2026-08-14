# otp — SPEC

HOTP (RFC 4226) + TOTP (RFC 6238) one-time passwords; see
[README.md](README.md) for purpose and API. Provenance: see
[NOTICE](NOTICE).

## Design

- **Source of truth**: RFC 4226 (HOTP + dynamic truncation, HMAC-SHA-1)
  and RFC 6238 (TOTP time-step mapping; extends HOTP to HMAC-SHA-256 and
  HMAC-SHA-512, §1.2). The module adds nothing beyond the two RFCs.
- **std recon (0.16.0)**: everything needed is in std —
  `std.crypto.auth.hmac.HmacSha1`, `.sha2.HmacSha256`, `.sha2.HmacSha512`
  (`create(out, msg, key)`, arbitrary key length per RFC 2104, digest
  length via `mac_length`) plus `std.mem.writeInt(u64, .., .big)` for the
  8-byte big-endian counter. No allocator, no clock, no RNG anywhere in
  the module: the caller passes the counter / unix time.
- **Dynamic truncation** (RFC 4226 §5.3): `offset` = low nibble of the
  *last* digest byte (`mac[mac_length - 1] & 0x0f`, which is byte 19 for
  SHA-1 exactly as the RFC writes it); `P` = 4 bytes at `offset` read
  big-endian, top bit masked (`& 0x7fffffff`). RFC 6238 applies the same
  rule to the longer SHA-256/SHA-512 digests. `offset ≤ 15` and
  `offset + 4 ≤ 19 ≤ mac_length` for every supported hash, so the slice
  is always in bounds. `dynamicTruncate` is exported so the RFC 4226 §5.4
  intermediate value (count 0 → `1284755224`) is directly assertable.
- **Digits**: 1..9, asserted (not an error union — an out-of-range
  `digits` is a caller bug). 9 is the hard ceiling: `P < 2^31 < 10^10`
  and `10^d` must fit in `u32`. RFC deployments use 6..8.
- **TOTP**: `T = floor((unix_time - t0) / period)`, unsigned unix time
  (pre-1970 out of scope, asserted), `period != 0` asserted. RFC defaults
  `period = 30`, `t0 = 0` are the caller's to pass — no hidden defaults.
- **Verification** (`totpVerify`): checks the code against all steps in
  `±skew_steps` (RFC 6238 §5.2), skipping steps that would underflow
  below `t0`. The whole window is always evaluated (no early exit), so
  the HMAC count doesn't leak which step matched. The final compare is a
  plain `u32` equality: OTP codes are low-entropy, short-lived,
  online-submitted secrets — the defense is server-side rate limiting
  (RFC 4226 §7.3), not constant-time digit comparison.

## Out of scope

- Base32 secret decoding and `otpauth://` URI parsing (Google
  Authenticator provisioning) — belongs in a thin layer above, with the
  `encoding` module.
- Server-side throttling/lockout state, last-accepted-step persistence
  (replay prevention) — policy and storage, not primitive.
- The RFC 4226 §7.5 resynchronization protocol for HOTP counter drift.

## Validation

`kat_test.zig` asserts, in Debug and ReleaseFast:

- RFC 4226 Appendix D, counts 0..9: the intermediate HMAC-SHA-1 digests
  (hex-exact), the pre-modulo truncated integers, the 6-digit codes, and
  the zero-padded ASCII forms.
- RFC 6238 Appendix B, all 6 times × 3 hashes (18 codes, 8 digits): the
  time-step counters (`T` column) and every code; the leading-zero code
  `07081804` checked as a formatted string.
- `totpVerify`: exact-step accept; ±1/±2 window accept/reject in both
  directions; wrong-code reject across a window; underflow clamp at `t0`;
  non-default `t0`.

## Fuzz exemption

**Fuzz exemption:** EMIT-ONLY

Every public function's one byte-accepting parameter is `key: []const
u8` — the long-lived shared secret RFC 4226/6238 assume is provisioned
out of band (typically server-generated at enrollment and never
resubmitted), not a value that arrives per-authentication from an
untrusted peer. The one thing an attacker DOES submit per attempt —
`totpVerify`'s `code` — is a decimal integer (`u32`) checked with
`std.crypto.timing_safe.eql` after `hotp` recomputes the expected value;
there is no byte-parsing/decoding step anywhere in this module for a
peer-supplied string to reach. (Base32 secret decoding and
`otpauth://` URI parsing are explicitly out of scope — see "Out of
scope" above — and belong in a layer above.) Overturn this exemption if
`key` is ever threaded from a request body rather than a local
credential store.

## Anchoring

**Anchor grade:** class B · oracle EXTERNAL

- **Class B** — published cryptographic or algorithmic construction with published vectors.
- **Oracle EXTERNAL** — published vectors, goldens captured from a foreign implementation, or a test run against a live foreign peer.

**What the tests actually contain.** RFC 4226/6238 appendix vectors embedded byte-exact
