# jsonshape

Reshape JSON into a canonical [`dataset`](../dataset/README.md): dot-path
descent to an array node + typed column projection (a jq-style minimal
subset — one path, not a full JSONPath engine).

- **Status:** `extract` — lifted from the authors' wgs `src/jsonshape.zig`,
  the `http` connector's normalizer for `getDataview`/`dataviewGet`-shaped
  remote feeds.
- **Model after:** jq-style path projection (minimal: one dot-path + field
  extraction), not a full JSONPath implementation.
- **Platform:** any (pure logic, no I/O). **Role:** codec (parses JSON,
  produces a `Dataset`; does no network/file I/O itself).
  **Concurrency:** reentrant (no shared state).
- **Deps:** [`dataset`](../dataset/README.md).

Provenance: extracted from the authors' wgs project (`src/jsonshape.zig`,
MIT, same authors) — a faithful lift; ownership/error semantics preserved
exactly. No third-party code (see [NOTICE](../../NOTICE)).

## What it does

Given raw JSON bytes and a `ShapeSpec`:

1. Parse the whole document (`std.json.parseFromSliceLeaky`) into an arena.
2. Walk `spec.path` as a dot-separated chain of object-key lookups from the
   root to find an array node. Empty path = the root itself.
3. Project each array item into a row, in one of two modes:
   - **generic columns** (`spec.columns` non-empty): one column per
     `JsonCol{name, key, type}` — `key` names the field inside each item
     (object key); empty `key` means "the whole item" (useful for
     array-of-scalars).
   - **`[x,y]` default** (`spec.columns` empty, poc-compatible shorthand):
     two columns, `x` (text) and `y` (float), taken from `spec.x`/`spec.y`
     object keys, or positionally from `item[0]`/`item[1]` when items are
     arrays, or as `[row-index, item]` when items are scalars.

Each cell is coerced from `std.json.Value` into a canonical `dataset.Value`
honoring the column's declared `ColumnType`, including JSON's
`number_string` variant and numbers-encoded-as-strings (`"20"` → `.int`
20).

## Behavior contract

- **Missing path node → empty dataset, not an error.** If the dot-path
  doesn't resolve to an array (wrong key, or resolves to a non-array), you
  get a `Dataset` with the declared columns and zero rows. This lets a
  caller declare a spec against an endpoint that sometimes omits the array
  without special-casing it.
- **Malformed JSON → `Error.BadJson`.** The only error this module raises;
  everything else (missing keys, type mismatches per cell) degrades to
  `.null` cells or an empty dataset.
- **Arena-scoped strings.** Text cells parsed from JSON strings borrow the
  parse tree living in the caller's allocator (normally an arena) — free
  everything at once via that arena, same memory model as `dataset` itself.

## API

```zig
const jsonshape = @import("jsonshape");

const JsonCol = jsonshape.JsonCol; // { name, key = "", type: ColumnType = .float }
const ShapeSpec = jsonshape.ShapeSpec; // { path = "", columns = &.{}, x = "", y = "" }
const Error = jsonshape.Error; // error{ BadJson, OutOfMemory }

fn shape(a: Allocator, bytes: []const u8, spec: ShapeSpec) Error!Dataset;
```

## Verify

```
zig build test-jsonshape
zig build test-jsonshape -Doptimize=ReleaseFast
zig fmt --check modules/jsonshape
```

## Deferred (backlog, not implemented here)

Flagged by the extraction scope as follow-on work, intentionally out of
scope for this v1 lift:

- **Full JSONPath** — array indexing (`items[0]`), wildcards, and
  multiple/repeated array nodes (e.g. paginated pages spread across several
  array fields) are not supported; the module walks exactly one dot-path
  of object-key lookups to exactly one array node.
- **Filter expressions** (`items[?(@.x > 0)]`-style predicates) — no
  filtering during descent or projection; callers filter the resulting
  `Dataset` themselves.
- **Nested-object flattening** — a dotted column key like `meta.ts` to pull
  a value out of a nested object per-row is not supported; `JsonCol.key`
  is a single top-level field name inside each item, not its own path.
- **Streaming / bounded-memory parse** — the whole document is parsed with
  `parseFromSliceLeaky` up front (matching the seed); very large payloads
  are not handled with a streaming/bounded-memory parser.
- **JSON→JSON reshape** — output is always a `dataset.Dataset`; reshaping
  JSON into JSON (a jq-style transform staying in JSON) is a different
  problem this module doesn't address.
- **Schema inference** — there is no "sniff the first object's keys to
  build `columns` automatically" mode; the caller always declares the
  spec.
- **A `strict` mode** — currently a wrong path and a genuinely-empty array
  are indistinguishable (both give zero rows); a mode that reports which
  case occurred would need a richer return type.
