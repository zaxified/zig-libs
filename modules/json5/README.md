# json5

Single-pass **JSON5→JSON preprocessor**: converts a permissive JSON5-ish
source into standard JSON accepted by `std.json.parseFromSlice`. Strips
`//` and `/* */` comments, quotes unquoted object keys (`foo:` →
`"foo":`), removes trailing commas before `}`/`]`, and converts
single-quoted strings to double-quoted (respecting all string contexts,
so none of the above are applied inside string literals). It also rewrites
JSON5 **numbers** (`0x1A`, `.5`, `5.`, `+1`), removes **line continuations**
(backslash-newline) from strings and turns JSON5-only **whitespace** (form
feed, NBSP, BOM, U+2028/2029, Unicode spaces) into plain spaces.

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
// r.out parses exactly when preprocess's output does — diagnostics never
// change the verdict (SPEC § Threat model); r.next_id is the next unused id
```

```zig
// JSON5 numbers become plain JSON numbers; hex is the exact decimal integer:
//   {timeout: .5, mask: 0xDEADbeef, retries: +3, half: 5.}
//   -> {"timeout": 0.5, "mask": 3735928559, "retries": 3, "half": 5}

// Infinity / -Infinity / +Infinity / NaN are an ERROR by default
// (error.NonFiniteNumber; the optional Diagnostic gives line + message):
var diag: json5.Diagnostic = .{};
_ = json5.preprocessWithOptions(alloc, "{t: Infinity}", .{ .diagnostic = &diag }) catch {};
// opt in to strings, which std.json reads into an f64 field as inf / nan:
const q = try json5.preprocessWithOptions(alloc, "{t: Infinity, u: NaN}", .{ .non_finite = .quoted });
defer alloc.free(q);
// q == "{\"t\": \"Infinity\", \"u\": \"NaN\"}"
```

- **Numbers:** hex of up to `json5.hex_digits_max` (256) significant digits
  becomes its exact decimal integer (`std.json` reads it as a float or an
  integer that fits); a longer one is `error.HexLiteralTooLarge`. Malformed
  tokens (`01`, `0x`, `0x1.5`, `1.2.3`) pass through untouched, so `std.json`
  rejects them. Nothing inside a string, comment or object key is rewritten.
- **`Options`:** `non_finite` (`.reject` default | `.quoted`) and `diagnostic`
  (`?*Diagnostic`). `preprocessAnnotated` never fails: under `.reject` it passes
  a non-finite token through and `std.json` rejects it.
- **Role:** codec. **Platform:** any.
  **Concurrency:** reentrant (no shared state; both functions take an
  allocator and a borrowed input slice). **Deps:** std-only.
- **Model after:** the JSON5 spec (json5.org) preprocessor-to-JSON
  approach — this module rewrites every JSON5 numeric, string-continuation and
  whitespace form; the few string escapes JSON lacks are deferred (see below).

Provenance: original work of the zig-libs authors (MIT), ~949 LOC. The
conformance test suite additionally vendors the official `json5/json5-tests`
fixture corpus (test data only, no source code) — see NOTICE.

## Deferred (not covered)

Since 2026-09-30 hex numbers, `.5`/`5.`, `+1`, string line continuations and
the JSON5 whitespace characters are handled (see above); `Infinity`/`NaN` are
an error by default with an opt-in `.quoted`. Still not covered:

- JSON5 string escapes that JSON lacks (`\x41`, `\0`, `\v`, an escaped
  non-escape character like `\a`): passed through, `std.json` rejects them.
- Formalizing `AnnotatedResult` against a future `diagnostics` module
  (currently a raw `{ out, next_id }` pair; no structured
  line/col/severity type yet).

## Verification

`zig build test-json5` — covers the base preprocessor, annotated recovery
variants, an OOB-safety regression test, fuzz targets covering
`preprocess`/`preprocessAnnotated` on arbitrary bytes, and the vendored
`json5/json5-tests` conformance corpus (112 fixtures: 105 asserted pass/reject
normally, 2 asserted as documented "known disagreements", 5 with `Infinity`/`NaN`
asserted by their own test: error by default, parse under `.quoted` — see
`src/json5_tests_test.zig`); green in Debug and
`-Doptimize=ReleaseFast`.
`zig fmt --check modules/json5` clean.
