# otp

HOTP (RFC 4226) and TOTP (RFC 6238) one-time passwords — the primitives
behind 2FA authenticator apps. Pure `std.crypto.auth.hmac`
(SHA-1/SHA-256/SHA-512); no allocator, no internal clock or RNG (the
caller passes the counter / unix time).

**Status: complete — KAT-validated byte-exact against RFC 4226 Appendix D
(all counts 0..9, including the intermediate HMAC digests) and the full
RFC 6238 Appendix B table (all 6 times × 3 hash functions).** See
`SPEC.md` for design notes and scope.

| File | Contents |
|---|---|
| `src/root.zig` | `Algorithm`, `dynamicTruncate`, `hotp`/`hotpFmt`, `timeStep`, `totp`/`totpFmt`, `totpVerify`, `fmtCode` |
| `src/kat_vectors.zig` | RFC 4226 Appendix D + RFC 6238 Appendix B tables, embedded |
| `src/kat_test.zig` | Full KAT assertions + verify-window tests |

Provenance: clean-room from RFC 4226 (HOTP) and RFC 6238 (TOTP) — the algorithms
are given as pseudocode in the RFCs themselves, and both appendices' vectors are
embedded byte-exact. No third-party OTP source consulted. Detail in this
module's own [`NOTICE`](NOTICE); it carries no condition beyond zig-libs' MIT
license.

## Import

```zig
const otp = @import("otp");
```

## API surface

```zig
pub const Algorithm = enum { sha1, sha256, sha512 };

// HOTP (RFC 4226) — counter-based
pub fn hotp(comptime alg: Algorithm, key: []const u8, counter: u64, digits: u5) u32;
pub fn hotpFmt(comptime alg: Algorithm, key: []const u8, counter: u64, digits: u5, out: []u8) []u8;
pub fn dynamicTruncate(comptime alg: Algorithm, key: []const u8, counter: u64) u32;

// TOTP (RFC 6238) — time-based (RFC defaults: period = 30, t0 = 0)
pub fn timeStep(unix_time: u64, period: u32, t0: u64) u64;
pub fn totp(comptime alg: Algorithm, key: []const u8, unix_time: u64, period: u32, t0: u64, digits: u5) u32;
pub fn totpFmt(comptime alg: Algorithm, key: []const u8, unix_time: u64, period: u32, t0: u64, digits: u5, out: []u8) []u8;
pub fn totpVerify(comptime alg: Algorithm, key: []const u8, unix_time: u64, period: u32, t0: u64, digits: u5, code: u32, skew_steps: u32) bool;

// Zero-left-padded ASCII rendering of a code
pub fn fmtCode(code: u32, digits: u5, out: []u8) []u8;
```

`digits` must be 1..9 (asserted); authenticator apps use 6..8. Codes are
returned as numbers — use the `*Fmt` helpers (or `fmtCode`) for the exact
zero-left-padded string an app displays (e.g. `07081804`).

## Example

```zig
// Google-Authenticator-style: 6 digits, SHA-1, 30 s period.
const code = otp.totp(.sha1, secret, now_unix, 30, 0, 6);

var buf: [6]u8 = undefined;
const shown = otp.totpFmt(.sha1, secret, now_unix, 30, 0, 6, &buf);

// Server side: accept the previous/current/next step.
const ok = otp.totpVerify(.sha1, secret, now_unix, 30, 0, 6, submitted, 1);
```

Secrets here are raw bytes: decode the Base32 form from a provisioning
URI before calling (out of scope for this module — see `SPEC.md`).

## Tests

```
zig build test-otp
```
