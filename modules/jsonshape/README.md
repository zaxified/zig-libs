# jsonshape

Reshape JSON into a canonical [`dataset`](../dataset/README.md): path
descent to array item(s) + typed column projection (a jq-style minimal
subset — a bounded JSONPath dialect, not the full JSONPath spec).

- A normalizer for `http`-connector-style remote
  feeds shaped like `getDataview`/`dataviewGet` responses.
- **Model after:** jq-style path projection (minimal: one dot-path + field
  extraction), not a full JSONPath implementation.
- **Platform:** any (pure logic, no I/O). **Role:** codec (parses JSON,
  produces a `Dataset`; does no network/file I/O itself).
  **Concurrency:** reentrant (no shared state).
- **Deps:** [`dataset`](../dataset/README.md).

Provenance: original work of the zig-libs authors (MIT); ownership/error
semantics are deliberate design choices. No third-party code.

## What it does

Given raw JSON bytes and a `ShapeSpec`:

1. Parse the whole document (`std.json.parseFromSliceLeaky`) into an arena.
2. Resolve `spec.path` to the item(s) to project. Empty path = the root
   itself. Two dialects, auto-detected from the path's syntax:
   - **Legacy dot-path** (no `[`, `*`, `?`, `..`, no leading `$`): a
     dot-separated chain of object-key lookups to one node, which must be
     an array (e.g. `"data.prices"`) — unchanged since v1.
   - **JSONPath subset** (anything else): object keys, array **indices**
     (`a.b[2]`), **wildcards** (`a.b[*]` over an array, `a.*` over an
     object's values), **recursive descent** (`..name`, finds every `name`
     field anywhere under the current node), and **filter expressions**
     (`items[?(@.field == "x")]`, `items[?(@.n > 5)]` — one comparison,
     ops `== != < <= > >=`, literal a quoted string/number/`true`/`false`/
     `null`; no `&&`/`||`, no nesting). Any of these can match multiple
     nodes (a wildcard, a recursive-descent hit in several places, several
     array nodes under a wildcard); each match becomes item(s): an
     `.array` match is flattened (its elements become items — this is how
     `pages[*].items` concatenates several paginated arrays into one row
     set), any other match becomes a single item itself.
3. Project each item into a row, in one of two modes:
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

- **Missing path node → empty dataset, not an error.** If the path doesn't
  resolve to any item (wrong key, resolves to a non-array under the legacy
  dot-path dialect, or a JSONPath-subset path with zero matches — including
  malformed path/filter *syntax*, e.g. an unterminated `[...]`), you get a
  `Dataset` with the declared columns and zero rows. This lets a caller
  declare a spec against an endpoint that sometimes omits the array without
  special-casing it.
- **Malformed JSON → `Error.BadJson`.** The only error this module raises;
  everything else (missing keys, type mismatches per cell, bad path/filter
  syntax) degrades to `.null` cells or an empty dataset.
- **Bounded recursion.** Recursive descent (`..name`) and general path
  evaluation are capped at a fixed depth so a crafted path can't
  stack-overflow on a deeply-nested document; filter predicates are
  single-level (no recursion of their own).
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

Full JSONPath and filter expressions are now supported (see above); the
following remain out of scope — see `SPEC.md` Backlog for the full
rationale, especially why streaming is a deliberate non-goal rather than
an oversight:

- **Nested-object flattening** — a dotted column key like `meta.ts` to pull
  a value out of a nested object per-row is not supported; `JsonCol.key`
  is a single top-level field name inside each item, not its own path.
- **Streaming / bounded-memory parse** — the whole document is parsed with
  `parseFromSliceLeaky` up front. Deliberately deferred, not just
  unscheduled: the JSONPath-subset engine (wildcards, recursive descent,
  filters) needs random access and multi-pass re-visitation over the
  parsed tree, which doesn't map onto a single forward SAX/token pass
  without either re-materializing the same tree by hand or shipping a
  second, more restricted engine. A genuinely streaming/incremental
  consumer is a different API shape (rows produced as found, from a token
  reader) and belongs in a separate module, not a retrofit here.
- **JSON→JSON reshape** — output is always a `dataset.Dataset`; reshaping
  JSON into JSON (a jq-style transform staying in JSON) is a different
  problem this module doesn't address.
- **Schema inference** — there is no "sniff the first object's keys to
  build `columns` automatically" mode; the caller always declares the
  spec.
- **A `strict` mode** — currently a wrong path and a genuinely-empty
  array/no-matches are indistinguishable (both give zero rows); a mode
  that reports which case occurred would need a richer return type.
- **Full JSONPath (RFC 9535) compliance** — the filter grammar is
  one-level only (no `&&`/`||`, no nested filters, no field-vs-field
  comparison); no slice syntax (`[1:3]`), no multi-index/name union
  (`['a','b']`, `[0,2]`), no script/function expressions.
