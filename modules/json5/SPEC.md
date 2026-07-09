# json5 — spec

Design + threat notes for auditors. Usage: see ./README.md. Attribution/provenance: see /NOTICE.

## Design & invariants

- **Single-pass JSON5→JSON preprocessor:** converts a permissive JSON5-ish source into standard
  JSON accepted by `std.json.parseFromSlice`. Strips `//` and `/* */` comments, quotes unquoted
  object keys (`foo:` → `"foo":`), removes trailing commas before `}`/`]`, and converts
  single-quoted strings to double-quoted — all string contexts are respected so none of the above
  transformations are applied inside string literals. Modeled after the JSON5 spec (json5.org)
  preprocessor-to-JSON approach, but implements the practical subset the seed's config/editor use
  case needs, not the full grammar (see Backlog). Extracted from `bxp-core/src/json5.zig`, ported
  verbatim — see NOTICE.
- **`preprocessAnnotated`** is a lenient variant for GUI/editor use: instead of failing on malformed
  input it recovers — missing colons, missing commas, unterminated strings, invalid bare literals —
  and surfaces each recovered problem as a synthetic `"$err_<N>": "<message>"` sibling entry in the
  emitted JSON, so the caller still gets a parseable document plus diagnostics pointing at the
  offending source line.
- **Both entry points are reentrant:** take an allocator and a borrowed input slice, no shared
  state; std-only deps.

## Threat model / out of scope

Not a security boundary; it is a lenient text preprocessor over untrusted/hand-edited config or
editor input. It guarantees `preprocess`'s output is either valid transformed JSON or an error
(never a panic on malformed input), and `preprocessAnnotated`'s output is *always* valid JSON (the
recovered-error markers keep the document parseable even when the source was broken). It does not
implement the full JSON5 grammar (see Backlog for the specific gaps) and does not validate
semantic correctness of the resulting document — only `std.json` syntax validity.

## Verification

20 tests (11 base preprocessor + 9 annotated recovery variants), green in Debug and
`-Doptimize=ReleaseFast`; `zig fmt --check modules/json5` clean. Run: `zig build test-json5`.

## Backlog / deferred

Full JSON5 spec gaps, not covered and not added in this extraction:
- Hex numeric literals (`0x1A`).
- Leading-dot/trailing-dot numbers (`.5`, `5.`).
- `+Infinity`, `-Infinity`, `NaN` numeric literals.
- Line-continuations inside strings (backslash-newline).
- Formalizing `AnnotatedResult` against a future `diagnostics` module (currently a raw
  `{ out, next_id }` pair; no structured line/col/severity type yet) — PLAN.md wave-3 findings flag
  this the same way.

## Status

`extract · any · codec · reentrant` + deps: none (std only) — canonical source is `pub const meta`
in src/root.zig.
