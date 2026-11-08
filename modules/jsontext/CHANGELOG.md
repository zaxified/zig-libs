# jsontext — changelog

Newest first. See the root [`CHANGELOG.md`](../../CHANGELOG.md) for which
release tag each entry shipped in, and `CONVENTIONS.md` §8 for the policy.

## Unreleased

- **2026-11-08** — **AUDIT:** review, mutation 146/153 (7 equivalent), fuzz 4,000,000 seeds, no-panic sweep, frozen CPython/Go vectors (`src/testdata`, `tools/gen_vectors.py`, `tools/go_vectors`), comparative bench against Go `encoding/json` (`tools/bench.zig`). Behaviour changes: `.reject` now writes everything before the bad sequence (the old code withheld the last verbatim run); escapes and short runs are gathered in a 256-byte block (control-heavy input 2.04x to 0.90x of Go). Output bytes are unchanged for every other input (the vectors pin them). `depthWithin` gained tests for `{`, closers and escapes (four mutants had survived); `decodeScalar` is tested over every scalar. `build.zig`: `jsontext` has `testkit` as a test dependency (fuzz driver).
- **2026-11-08** — **NEW MODULE:** `jsontext` — `writeString` / `writeStringContents` (JSON string literal from arbitrary bytes; ill-formed UTF-8 as U+FFFD per maximal subpart, byte escapes or an error; optional ASCII-only and HTML-safe output) and `depthWithin` (string-aware nesting prescan). The writer is `accesslog`'s table-driven escaper moved here unchanged for the default options; other consumers (framing, mcp, jsonshape, health, openapi …) move onto it in a later wave.
