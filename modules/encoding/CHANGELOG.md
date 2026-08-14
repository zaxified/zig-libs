# encoding — changelog

Newest first. See the root [`CHANGELOG.md`](../../CHANGELOG.md) for which
release tag each entry shipped in, and `CONVENTIONS.md` §8 for the policy.

## Unreleased

- **2026-08-14** — `zig build check-fuzz` coverage: a `testing.fuzz` harness on
  `decodeToUtf8`/`encodeFromUtf8` (the read-edge decode and write-edge encode entry
  points), run under `std.testing.allocator` with the result freed on every path. Both
  are data-lenient (never error on malformed input) so no structural bias was needed —
  arbitrary bytes already reach every branch. No panic, hang or leak found.
- **2026-07-18** — Security audit: one finding fixed (part of the collection-wide audit;
  the root changelog records no further detail than this). Verified: The five supported
  code pages (windows-1250/1252, iso-8859-1/2/15) are the WHATWG Encoding Standard's
  published single-byte tables.
- **2026-07-09** — New module: Legacy single-byte code page ↔ UTF-8 transcoding (5
  European code pages: windows-125x, ISO-8859-1/2/15).
