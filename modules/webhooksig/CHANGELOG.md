# webhooksig — changelog

Newest first. See the root [`CHANGELOG.md`](../../CHANGELOG.md) for which
release tag each entry shipped in, and `CONVENTIONS.md` §8 for the policy.

## Unreleased

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
