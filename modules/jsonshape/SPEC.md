# jsonshape — spec

Design + threat notes for auditors. Usage: see ./README.md. Attribution/provenance: original work of
the zig-libs authors (MIT).

## Design & invariants

- **Reshape JSON into a canonical `dataset`:** path descent to array item(s) + typed column
  projection — a jq-style minimal subset (a bounded JSONPath dialect, not the full JSONPath
  spec — no `..` on the root wildcard-of-everything, no boolean-composed filters). Original work
  of the zig-libs authors (MIT), designed as the `http` connector's normalizer for `getDataview`/
  `dataviewGet`-shaped remote feeds, with ownership/error semantics as deliberate design choices.
- **Algorithm:** parse the whole document (`std.json.parseFromSliceLeaky`) into an arena; resolve
  `spec.path` to item(s) to project into rows via either generic columns (`spec.columns`: one
  `JsonCol{name, key, type}` per column, empty `key` = "the whole item") or the `[x,y]` default
  shorthand (two columns from `spec.x`/`spec.y` keys, or positional/index fallback). Each cell is
  coerced from `std.json.Value` into a canonical `dataset.Value` honoring the column's declared
  `ColumnType`, including JSON's `number_string` variant and numbers-encoded-as-strings.
  - **Path dialect:** two tiers, dispatched by a cheap syntax scan (`isLegacyPath`) so the
    original code path is untouched byte-for-byte for anything that looks like the original
    dot-path:
    - **Legacy dot-path** (no `[`, `*`, `?`, `..`, or leading `$`): unchanged since v1 — a
      dot-separated chain of object-key lookups to exactly one node, which must be an array (else
      empty dataset).
    - **JSONPath subset** (anything else): a small segment parser (`parsePath` → `[]Seg`)
      supporting object-key, array **index** (`a.b[2]`), **wildcard** (`a.b[*]`, `a.*` — array
      elements or object values), **recursive descent** (`..name`, depth-capped at
      `MAX_PATH_DEPTH = 64`), and a bounded **filter** segment (see below) — evaluated against the
      parsed tree by `evalSegs`/`recursiveFind`, collecting every matched node. Row items are then
      derived per match: an `.array` match is flattened (its elements become items — this is what
      lets `pages[*].items` concatenate several paginated arrays into one row set); any other
      match becomes a single item itself (this is what lets `..name` or `a.*` pull scattered
      scalars/objects out as rows without requiring an enclosing array).
- **Filter expressions:** one-level, non-composable predicate on array elements —
  `[?(@.field OP literal)]` (parens optional, e.g. `[?@.field OP literal]` also parses), `OP` ∈
  `== != < <= > >=`, `literal` a quoted string, `true`/`false`, `null`, or a number. No `&&`/`||`,
  no nested filters, no comparing two fields — deliberately narrow to keep the predicate
  trivially bounded (`parseFilter`/`matchFilter` are O(1) per element, no recursion).
- **Bounded by construction, not by external limit:** `MAX_PATH_DEPTH` caps recursive-descent and
  general segment-eval recursion so a crafted path can't stack-overflow on a deep document; syntax
  errors in a path or filter (unterminated `[`, unknown operator, bad literal) degrade to a
  `.never`-segment (matches nothing) rather than an error, consistent with the module's existing
  "malformed shape input never fails except BadJson" contract.
- **Missing path → empty dataset, not an error.** If the path doesn't resolve to any array/item
  (wrong key, or resolves to a non-array under the legacy dialect, or a JSONPath-subset path with
  no matches at all), the result is a `Dataset` with the declared columns and zero rows — lets a
  caller declare a spec against an endpoint that sometimes omits the array without special-casing
  it.
- **Arena-scoped strings.** Text cells parsed from JSON strings borrow the parse tree living in the
  caller's allocator (normally an arena) — freed all at once, same memory model as `dataset` itself.
- **Concurrency:** reentrant, no shared state; pure logic, no I/O of its own.

## Threat model / out of scope

Not a security boundary; it is a data-shaping codec over JSON that may originate from a remote
feed. The only error it raises is `Error.BadJson` on malformed JSON — everything else (missing
keys, type mismatches per cell, a path that resolves to nothing) degrades to `.null` cells or an
empty dataset rather than failing, so a shape mismatch never panics or propagates as an error. It
does not validate the *semantics* of the resulting data (values are taken as given from the remote
source) and does no network/file I/O itself. The JSONPath-subset engine (indices/wildcards/
recursive-descent/filters) is deliberately not the full JSONPath spec — see Backlog for what's
still out of scope: nested-object flattening, streaming/bounded-memory parse, JSON→JSON reshape,
schema inference, a strict wrong-path-vs-empty distinguishing mode, and boolean-composed/multi-hop
filter expressions.

## Verification

Tests cover the original set (generic-column projection, the `[x,y]` default shorthand in its
object-key/positional-array/scalar-item forms, missing-path → empty-dataset, malformed-JSON →
`Error.BadJson`) plus a set with teeth for the JSONPath-subset engine — array index
(`a.b[2]`), array wildcard (`a.b[*]`), object wildcard (`a.*`), recursive descent (`..name`,
3 matches at 3 different depths), multi-array concatenation (`pages[*].items` flattening two
paginated arrays into one 5-row set), a filter positive control (`list[?(@.status == "ok")]` —
asserts the *excluded* element is actually gone from every row, not just deprioritized), a
numeric-operator filter (`arr[?(@.n>5)]`, no spaces), an explicit back-compat check that an
existing legacy dot-path spec still resolves byte-identically, and a malformed-path-syntax case
(unterminated `[`) degrading to an empty dataset rather than a crash. Verified green in Debug and
ReleaseFast; `zig fmt --check modules/jsonshape` clean. Run: `zig build test-jsonshape`.

## Backlog / deferred

- **Nested-object flattening** — a dotted column key like `meta.ts` to pull a value out of a nested
  object per-row is not supported; `JsonCol.key` is a single top-level field name. (`JsonCol.key`
  could itself become a path through the same engine — natural follow-on, not done here.)
- **Streaming/bounded-memory parse — deferred, not a modest addition.** The whole document is
  parsed with `parseFromSliceLeaky` up front; very large payloads have no streaming/bounded-memory
  path. Evaluated for this pass and deliberately not built: the JSONPath-subset engine added here
  (wildcards, recursive descent, filters) fundamentally needs random access and multi-pass
  re-visitation over the parsed tree — `..name` walks the whole document looking for every
  occurrence, a filter re-scans an array, a wildcard fans out into N independent sub-walks. None of
  that maps onto a single forward SAX/token pass without effectively re-materializing the same
  tree structure incrementally (i.e., reimplementing `parseFromSliceLeaky` by hand) or restricting
  the path dialect to a linear, non-branching subset — which would mean shipping two incompatible
  engines with different capabilities. The reshape API is whole-document by design (`shape()`
  returns a complete `Dataset`, not a row iterator); a genuinely bounded-memory/incremental
  consumer is a different API shape (produce rows as they're found, streaming from a token
  reader) and belongs in a separate module/function, not a retrofit here.
- **JSON→JSON reshape** — output is always a `dataset.Dataset`, not a jq-style JSON-to-JSON
  transform.
- **Schema inference** — no auto-sniff of the first object's keys to build `columns`; the caller
  always declares the spec.
- **A `strict` mode** — a wrong path and a genuinely-empty array/no-matches are currently
  indistinguishable (both give zero rows).
- **Full JSONPath compliance** — the filter grammar is intentionally one-level (`@.field OP
  literal`, no `&&`/`||`, no nested filters, no field-vs-field comparison); there's no `$..*`
  (recursive-descent-then-wildcard-everything), no slice syntax (`[1:3]`), no union of multiple
  indices/names (`['a','b']` or `[0,2]`), and no script/function expressions. These are real
  JSONPath (RFC 9535) features left out to keep the engine small and its DoS surface easy to
  reason about (`MAX_PATH_DEPTH`-bounded recursion, O(1)-per-element filters); add on demonstrated
  need.

## Status

`extract · any · codec · reentrant` + deps: `dataset` — canonical source is `pub const meta` in
src/root.zig.
