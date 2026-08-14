# csvstream — changelog

Newest first. See the root [`CHANGELOG.md`](../../CHANGELOG.md) for which
release tag each entry shipped in, and `CONVENTIONS.md` §8 for the policy.

## Unreleased

- **2026-08-14** — `zig build check-fuzz` coverage restored: `src/line.zig` already had
  two `testing.fuzz` harnesses on the real decode entry points (`LineIterator.next`,
  `splitFields`) — genuinely running, catching nothing — but they were spelled `t.fuzz(`
  through this file's `const t = std.testing;` alias, and the gate greps source text for
  the literal substring `testing.fuzz(`, so they were structurally invisible to it. Both
  now call `std.testing.fuzz(` spelled out. No behavior change; no new coverage — the
  module was already fuzzed, the gate just couldn't see it.
- **2026-07-19** — Security audit: three findings fixed (part of the collection-wide
  audit; the root changelog records no further detail than this). Modeled on Go
  `encoding/csv` (LazyQuotes), Python `csv`, `libcsv` (design reference, not a test
  anchor).
- **2026-07-09** — New module: Streaming RFC 4180 CSV reader that preserves byte
  offsets, bounded memory regardless of file size.
