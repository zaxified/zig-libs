# json5 — spec

Design + threat notes for auditors. Usage: see ./README.md. Attribution/provenance: original work of
the zig-libs authors (MIT).

## Design & invariants

- **Single-pass JSON5→JSON preprocessor:** converts a permissive JSON5-ish source into standard
  JSON accepted by `std.json.parseFromSlice`. Strips `//` and `/* */` comments, quotes unquoted
  object keys (`foo:` → `"foo":`), removes trailing commas before `}`/`]`, and converts
  single-quoted strings to double-quoted — all string contexts are respected so none of the above
  transformations are applied inside string literals. Modeled after the JSON5 spec (json5.org)
  preprocessor-to-JSON approach, but implements the practical subset a config/editor use
  case needs, not the full grammar (see Backlog). Original work of the zig-libs authors (MIT).
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

Covers the base preprocessor, annotated recovery variants, an OOB-safety
regression test, fuzz targets over `preprocess`/`preprocessAnnotated`, and the
vendored `json5/json5-tests` conformance corpus (NOTICE); green in Debug and
`-Doptimize=ReleaseFast`; `zig fmt --check modules/json5` clean.
Run: `zig build test-json5`.

### json5/json5-tests corpus coverage

`src/testdata/json5-tests/` vendors 112 fixtures from the upstream corpus
(pinned commit in NOTICE). The corpus's own convention — confirmed from its
README, not assumed — is that the file extension encodes the verdict:
`.json`/`.json5` must parse, `.js`/`.txt` must be rejected.
`json5_tests_test.zig` drives every fixture through `preprocess` +
`std.json.parseFromSlice` (this module never claims to be a standalone JSON5
decoder — `preprocess` hands off to `std.json` for actual syntax enforcement)
and asserts against that convention, with two carved-out exceptions:

- **37 out-of-scope fixtures** require a JSON5 feature this module has never
  implemented (see README "Deferred"): hex numerics, leading/trailing-dot
  numbers, `Infinity`/`NaN`, string line-continuations, leading `+` on
  numbers, or JSON5's extra whitespace characters. Counted but not asserted —
  see `json5_tests_vectors.zig`'s `out_of_scope` field.
- **1 "known disagreement" fixture** (`objects/illegal-unquoted-key-symbol.txt`)
  is asserted to *succeed* rather than fail: this module's pre-existing
  malformed-unquoted-key recovery (root.zig's `$err_trace_N` synthetic-entry
  path, already pinned by the "error recovery: space inside unquoted key"
  test) deliberately turns what the corpus calls a must-reject case into
  parseable output. Both behaviors are correct for what they're each testing;
  see `json5_tests_test.zig`'s `known_disagreements` comment.
  `objects/illegal-unquoted-key-number.txt` looks like the same shape but
  needs no carve-out: empirically it already rejects correctly (the leading
  digits break object structure before recovery gets a chance).

## Backlog / deferred

Full JSON5 spec gaps, not covered and not added in this extraction:
- Hex numeric literals (`0x1A`).
- Leading-dot/trailing-dot numbers (`.5`, `5.`).
- `+Infinity`, `-Infinity`, `NaN` numeric literals.
- Line-continuations inside strings (backslash-newline).
- Leading `+` sign on numbers — found by the json5-tests corpus; same root
  cause as the above (numeric-literal bytes pass through untouched).
- JSON5-only extra whitespace characters (form feed, vertical tab, Unicode
  space/BOM separators) — found by the corpus; this preprocessor never
  rewrites whitespace, only comments/keys/commas/quotes.
- Formalizing `AnnotatedResult` against a future `diagnostics` module (currently a raw
  `{ out, next_id }` pair; no structured line/col/severity type yet).

## Status

`extract · any · codec · reentrant` + deps: none (std only) — canonical source is `pub const meta`
in src/root.zig.

## Anchoring

**Anchor grade:** class A · oracle MIXED

- **Class A** — wire/interop format — other implementations must byte-agree with it.
- **Oracle MIXED** — anchored for some paths, self for others — the evidence below names which.

**What the tests actually contain.** src/json5_tests_test.zig drives preprocess through the upstream json5/json5-tests corpus (src/testdata/json5-tests) honouring its extension convention in both directions, with one known_disagreement pinned; the error-recovery design ($err_trace_N) that root.zig's 27 tests cover is this module's own invention and has no external answer

**How it got there.** The anchoring work landed. DONE b8d7144: json5-tests corpus adopted, THREE real bugs fixed
