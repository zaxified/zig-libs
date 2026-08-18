# yaml — changelog

Newest first. See the root [`CHANGELOG.md`](../../CHANGELOG.md) for which
release tag each entry shipped in, and `CONVENTIONS.md` §8 for the policy.

## Unreleased

- **2026-08-18** — Portability fix (`check-portable`), test-only: "arbitrary input never
  panics" computed two fuzz bounds (`n = 1 + (s % buf.len)`, an alphabet index `(s >> 33)
  % alphabet.len`) as `u64` and used them to slice/index `buf`/`alphabet`, which fails to
  compile on a 32-bit target. Both moduli are always `< buf.len`/`< alphabet.len`
  (24/26-ish) regardless of `s`'s width, so the cast can never truncate a value that
  reaches it — an unconditionally-safe `@intCast`, not a real 64-bit quantity. Compile-only,
  identical semantics — no new test. Verified: `zig build portable-yaml` no longer errors
  on these two sites (the module still fails that gate via `testkit`'s
  `std.process.Environ` `[wasi-surface]` gap, pulled in through `suite_test.zig`,
  unrelated to this fix) and `zig build test-yaml --summary all` (47/47) is green.
- **2026-08-06** — Security audit: five findings fixed (part of the collection-wide
  audit; the root changelog records no further detail than this). Modeled on `libyaml`
  (the staging is explicitly modelled on it, `root.zig:70`); oracle is the
  **yaml-test-suite** (design reference, not a test anchor).
- **2026-07-30** — New module: YAML 1.2 reader (not 1.1) — scanner (tokens) → parser
  (events) → composer (native `Value`), tappable at either of the last two stages. Block
  sequences/mappings, all five scalar styles with their.
