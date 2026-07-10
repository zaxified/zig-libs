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

Provenance: original work of the zig-libs authors (MIT), ~949 LOC / 20 tests.

## Deferred (not covered — full JSON5 spec gaps)

This module implements a practical JSON5 subset, not the complete json5.org
grammar. Not covered:

- Hex numeric literals (`0x1A`).
- Leading-dot / trailing-dot numbers (`.5`, `5.`).
- `+Infinity`, `-Infinity`, `NaN` numeric literals.
- Line-continuations inside strings (backslash-newline).
- Formalizing `AnnotatedResult` against a future `diagnostics` module
  (currently a raw `{ out, next_id }` pair; no structured
  line/col/severity type yet).

## Verification

`zig build test-json5` — 20 tests (11 base preprocessor + 9 annotated
recovery variants), green in Debug and `-Doptimize=ReleaseFast`.
`zig fmt --check modules/json5` clean.
