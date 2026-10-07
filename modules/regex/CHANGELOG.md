# `regex` — changelog

Newest first. See the root [`CHANGELOG.md`](../../CHANGELOG.md) for which
release tag each entry shipped in, and `CONVENTIONS.md` §8 for the policy.

## Unreleased

- **2026-10-07** — New module: RE2-syntax regular expressions (Go `regexp/syntax` grammar) on a
  Pike VM — linear time, leftmost-first, compiled without an allocator (also at comptime),
  `isMatch`/`fullMatch` without one, `Matcher` for submatches and non-overlapping iteration.
  Anchored on Go `regexp` as a differential oracle (791 patterns, 11,277 inputs). For `router`'s
  `{id:[0-9]+}` constraints.
