# json5

Single-pass **JSON5→JSON preprocessor**: converts a permissive JSON5-ish
source into standard JSON accepted by `std.json.parseFromSlice`. Strips
`//` and `/* */` comments, quotes unquoted object keys (`foo:` →
`"foo":`), removes trailing commas before `}`/`]`, and converts
single-quoted strings to double-quoted (respecting all string contexts,
so none of the above are applied inside string literals).

A second entry point, `preprocessAnnotated`, is a lenient variant for
GUI/editor use: instead of failing on malformed input it recovers —
missing colons, missing commas, unterminated strings, invalid bare
literals — and surfaces each recovered problem as a synthetic
`"$err_<N>": "<message>"` sibling entry in the emitted JSON, so the
caller can still get a parseable document plus diagnostics pointing at
the offending source line.

```zig
const json5 = @import("json5");

const out = try json5.preprocess(alloc, "{ // cfg\n  foo: 'bar', }");
defer alloc.free(out);
// out == "{ \n  \"foo\": \"bar\" }" — feed straight into std.json

const r = try json5.preprocessAnnotated(alloc, src);
defer alloc.free(r.out);
// r.out is always valid JSON; r.next_id is the next unused $err_<N> id
```

- **Role:** codec. **Platform:** any.
  **Concurrency:** reentrant (no shared state; both functions take an
  allocator and a borrowed input slice). **Deps:** std-only.
- **Model after:** the JSON5 spec (json5.org) preprocessor-to-JSON
  approach — this module does not implement the full JSON5 grammar (see
  Deferred below), just the subset needed by a config/editor
  use case.

Provenance: original work of the zig-libs authors (MIT), ~949 LOC. The
conformance test suite additionally vendors the official `json5/json5-tests`
fixture corpus (test data only, no source code) — see NOTICE.

## Deferred (not covered — full JSON5 spec gaps)

This module implements a practical JSON5 subset, not the complete json5.org
grammar. Not covered:

- Hex numeric literals (`0x1A`).
- Leading-dot / trailing-dot numbers (`.5`, `5.`).
- `+Infinity`, `-Infinity`, `NaN` numeric literals.
- Line-continuations inside strings (backslash-newline).
- Leading `+` sign on numbers (`+15`, `+0.5`) — same root cause as the above:
  the preprocessor never touches numeric-literal bytes, and JSON (what
  `std.json` enforces downstream) has no leading-`+` production. Found by the
  `json5/json5-tests` corpus (numbers/positive-*.json5); not previously
  documented.
- JSON5-only extra whitespace characters (form feed `U+000C`, vertical tab,
  and the Unicode space/BOM separators JSON5 permits beyond JSON's
  space/tab/CR/LF). This preprocessor only ever rewrites comments, unquoted
  keys, trailing commas, and quote style — it never rewrites whitespace, so a
  byte `std.json` doesn't accept as whitespace passes through unchanged and
  fails downstream. Found by the corpus (misc/valid-whitespace.json5); not
  previously documented.
- Formalizing `AnnotatedResult` against a future `diagnostics` module
  (currently a raw `{ out, next_id }` pair; no structured
  line/col/severity type yet).

## Verification

`zig build test-json5` — covers the base preprocessor, annotated recovery
variants, an OOB-safety regression test, fuzz targets covering
`preprocess`/`preprocessAnnotated` on arbitrary bytes, and the vendored
`json5/json5-tests` conformance corpus (112 fixtures: 74 asserted pass/reject
normally, 1 asserted as a documented "known disagreement", 37 documented
out-of-scope — see `src/json5_tests_test.zig`); green in Debug and
`-Doptimize=ReleaseFast`.
`zig fmt --check modules/json5` clean.
