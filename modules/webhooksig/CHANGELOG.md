# webhooksig — changelog

Newest first. See the root [`CHANGELOG.md`](../../CHANGELOG.md) for which
release tag each entry shipped in, and `CONVENTIONS.md` §8 for the policy.

## Unreleased

- **2026-09-07** — `fuzzVerify` ran exactly one input for its whole existence, and one of its
  two calls was a duplicate of the other. It opened with `smith.bytes(&secret_buf)` plus a
  ranged length, then the same for the body, then `smith.value(bool)` to choose between a raw
  and a structured presented value; a ranged `Smith` draw returns the range MINIMUM when fewer
  than eight octets remain, `bool` is a 1-bit range, and `Smith` discards the rest of its
  input after the first short read — so every run used secret `"\x00"`, an empty body, and a
  presented value of seven NUL octets followed by sixty-four `'0'`s (`smith.index` was 0 for
  every character). Separately, `_ = verifyWithPrefix("sha256=", …)` beside `_ = verify(…)` is
  literally the same call twice, since `verify` expands to exactly that. Now one
  `smith.slice(&presented_buf)` call as the first draw, an eleven-value corpus built around
  the module's own demo HMAC vector (so a genuinely CORRECT signature is in it), the secret
  and body derived from the drawn bytes with `testkit.fuzz.Cursor` instead of drawn after
  them, and the second call made with the EMPTY prefix, which is the case that actually
  differs. Measured: **0 of 11 seeds non-empty, 0 MACs decoded, 0 signatures accepted and
  exactly 1 distinct secret before; 10 of 11 non-empty, 5 decoded, 4 accepted and 8 distinct
  secrets after.**
- **2026-08-23** — **Breaking:** `sign` and `signWithPrefix` return
  `SignError![]const u8` (`error{OutputTooSmall}`) instead of `[]const u8`.
  `signWithPrefix` used to guard `out_buf.len` with `std.debug.assert` before
  two `@memcpy` calls; ReleaseFast compiles the assert (and the bounds check
  on those memcpys) out together, so an `out_buf` undersized relative to
  `signatureBufLen(prefix)` was a silent out-of-bounds write in the build
  that ships. Found by an audit sweep for this shape.
- **2026-07-18** — Security audit: one finding fixed (part of the collection-wide audit;
  the root changelog records no further detail than this). Verified: Byte-exact
  HMAC-SHA256 KAT (key="key", "The quick brown fox…" → `f7bc83f4…a3cd8`),
  `src/root.zig:360-368`.
- **2026-07-08** — New module: HMAC webhook signatures (GitHub style: `sha256=<hex>`).
