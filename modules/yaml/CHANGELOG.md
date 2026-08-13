# yaml — changelog

Newest first. See the root [`CHANGELOG.md`](../../CHANGELOG.md) for which
release tag each entry shipped in, and `CONVENTIONS.md` §8 for the policy.

## Unreleased

- **2026-08-06** — Security audit: five findings fixed (part of the collection-wide
  audit; the root changelog records no further detail than this). Modeled on `libyaml`
  (the staging is explicitly modelled on it, `root.zig:70`); oracle is the
  **yaml-test-suite** (design reference, not a test anchor).
- **2026-07-30** — New module: YAML 1.2 reader (not 1.1) — scanner (tokens) → parser
  (events) → composer (native `Value`), tappable at either of the last two stages. Block
  sequences/mappings, all five scalar styles with their.
