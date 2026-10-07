# `regex` — changelog

Newest first. See the root [`CHANGELOG.md`](../../CHANGELOG.md) for which
release tag each entry shipped in, and `CONVENTIONS.md` §8 for the policy.

## Unreleased

- **2026-10-07** — Review fixes: nested counted repetitions multiply to at most 1000, as in Go
  (`(?:(?:a{0}){1000}){2}` is `error.InvalidRepeatSize`; before, such a pattern could make the
  compiler run ~10⁹ steps); `max_depth` 1000 → 250 so compiling fits a small thread stack;
  `a(?i)*` repeats `a`; `\` before a control character is a literal; `\x{…}` takes any number of
  hex digits and no sign or `_`; `Matcher.find`/`captures` past the input end find nothing.
- **2026-10-07** — Tests: mutation schemata run (34 mutants, 31 killed, 2 equivalent, 1 simplified
  away — `runeBefore` now reads only whether the byte before is ASCII, all the assertions look at);
  seven crafted oracle patterns added (a star over an assertion, `(?m)^` after an inner newline).
  No behaviour change.
- **2026-10-07** — `Regex.compileUsing(gpa, builder, pattern)`: `compile` with the caller's
  `Builder` (the ~70 KiB compile scratch), so many patterns compiled into an arena share one.
- **2026-10-07** — New module: RE2-syntax regular expressions (Go `regexp/syntax` grammar) on a
  Pike VM — linear time, leftmost-first, compiled without an allocator (also at comptime),
  `isMatch`/`fullMatch` without one, `Matcher` for submatches and non-overlapping iteration.
  Anchored on Go `regexp` as a differential oracle (791 patterns, 11,277 inputs). For `router`'s
  `{id:[0-9]+}` constraints.
