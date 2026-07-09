# jsonshape — spec

Design + threat notes for auditors. Usage: see ./README.md. Attribution/provenance: original work of
the zig-libs authors (MIT).

## Design & invariants

- **Reshape JSON into a canonical `dataset`:** dot-path descent to an array node + typed column
  projection — a jq-style minimal subset (one path, not a full JSONPath engine). Original work of
  the zig-libs authors (MIT), designed as the `http` connector's normalizer for `getDataview`/
  `dataviewGet`-shaped remote feeds, with ownership/error semantics as deliberate design choices.
- **Algorithm:** parse the whole document (`std.json.parseFromSliceLeaky`) into an arena; walk
  `spec.path` as a dot-separated chain of object-key lookups from the root to find an array node
  (empty path = the root itself); project each array item into a row via either generic columns
  (`spec.columns`: one `JsonCol{name, key, type}` per column, empty `key` = "the whole item") or the
  `[x,y]` default shorthand (two columns from `spec.x`/`spec.y` keys, or positional/index fallback).
  Each cell is coerced from `std.json.Value` into a canonical `dataset.Value` honoring the column's
  declared `ColumnType`, including JSON's `number_string` variant and numbers-encoded-as-strings.
- **Missing path → empty dataset, not an error.** If the dot-path doesn't resolve to an array
  (wrong key, or resolves to a non-array), the result is a `Dataset` with the declared columns and
  zero rows — lets a caller declare a spec against an endpoint that sometimes omits the array
  without special-casing it.
- **Arena-scoped strings.** Text cells parsed from JSON strings borrow the parse tree living in the
  caller's allocator (normally an arena) — freed all at once, same memory model as `dataset` itself.
- **Concurrency:** reentrant, no shared state; pure logic, no I/O of its own.

## Threat model / out of scope

Not a security boundary; it is a data-shaping codec over JSON that may originate from a remote
feed. The only error it raises is `Error.BadJson` on malformed JSON — everything else (missing
keys, type mismatches per cell, a path that resolves to nothing) degrades to `.null` cells or an
empty dataset rather than failing, so a shape mismatch never panics or propagates as an error. It
does not validate the *semantics* of the resulting data (values are taken as given from the remote
source) and does no network/file I/O itself. Out of scope (see Backlog for detail): full JSONPath,
filter expressions, nested-object flattening, streaming/bounded-memory parse, JSON→JSON reshape,
schema inference, a strict wrong-path-vs-empty distinguishing mode.

## Verification

5 tests exercising generic-column projection, the `[x,y]` default shorthand (object-key, positional
array, and scalar-item fallback forms), missing-path → empty-dataset behavior, and malformed-JSON →
`Error.BadJson`. Verified green in Debug and ReleaseFast; `zig fmt --check modules/jsonshape`
clean. Run: `zig build test-jsonshape`.

## Backlog / deferred

Flagged by the extraction scope as follow-on work, intentionally out of scope for this v1 lift:
- **Full JSONPath** — array indexing (`items[0]`), wildcards, and multiple/repeated array nodes
  (e.g. paginated pages spread across several array fields) are not supported; the module walks
  exactly one dot-path of object-key lookups to exactly one array node.
- **Filter expressions** (`items[?(@.x > 0)]`-style predicates) — callers filter the resulting
  `Dataset` themselves.
- **Nested-object flattening** — a dotted column key like `meta.ts` to pull a value out of a nested
  object per-row is not supported; `JsonCol.key` is a single top-level field name.
- **Streaming/bounded-memory parse** — the whole document is parsed with `parseFromSliceLeaky` up
  front; very large payloads have no streaming/bounded-memory path.
- **JSON→JSON reshape** — output is always a `dataset.Dataset`, not a jq-style JSON-to-JSON
  transform.
- **Schema inference** — no auto-sniff of the first object's keys to build `columns`; the caller
  always declares the spec.
- **A `strict` mode** — a wrong path and a genuinely-empty array are currently indistinguishable
  (both give zero rows).

## Status

`extract · any · codec · reentrant` + deps: `dataset` — canonical source is `pub const meta` in
src/root.zig.
