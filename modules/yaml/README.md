# yaml

**YAML 1.2 reader** — not 1.1. Source bytes go through a scanner (tokens), a
parser (events) and a composer (native values), and the caller can tap the
pipeline at either of the last two stages.

Covered: block sequences and mappings, plain, single- and double-quoted scalars
with their escape and folding rules, flow collections, literal `|` and folded
`>` block scalars with every indentation and chomping indicator, comments,
multi-document streams, `%YAML` / `%TAG` directives, anchors and aliases,
explicit `?` / `:` keys, tag shorthands and verbatim tags, and **YAML 1.2 core
schema** tag resolution.

## Values

```zig
const yaml = @import("yaml");

const doc = try yaml.compose(gpa, "port: 8080\nhosts: [a, b]\ndebug: no\n", .{});
defer doc.deinit();

const port = doc.root.get("port").?.int;         // 8080 — an int, not "8080"
const host = doc.root.get("hosts").?.at(0).?;    // .{ .string = "a" }
const dbg  = doc.root.get("debug").?.string;     // "no" — 1.2 has no yes/no bools
```

`Value` is a small by-value union: `.null`, `.bool`, `.int`, `.float`,
`.string`, `.sequence`, `.mapping`. A mapping is an **ordered slice of pairs**,
not a hash map, because YAML mapping keys may be any node (a sequence, a
mapping, an empty scalar) — flattening that away would lose documents the
format allows.

**A repeated mapping key is rejected by default** (`error.DuplicateKey`), per
`Options.reject_duplicate_keys` (default `true`). See "Duplicate mapping
keys" below.

For a multi-document stream use `composeAll`, which returns one `Value` per
document; `compose` is the single-document convenience and errors otherwise.
`composeAllLeaky` allocates from an arena you already own and frees nothing.

**Core schema, not 1.1** (§10.2.2): `null`/`~`/empty → null; `true`/`True`/`TRUE`
and the `false` trio → bool; `[-+]?[0-9]+`, `0o…`, `0x…` → int; the decimal /
exponent forms plus `.inf`/`.nan` → float; everything else → string. So `yes`,
`no`, `on`, `off` are **strings**, `0777` is decimal **777** (not octal), and
`1:30` is a **string** (no sexagesimals). Only *plain* scalars are resolved —
`"true"` is the string `true`. An explicit tag overrides resolution, and a tag
the schema does not know (`!foo`, `tag:example.com,2000:app/light`) leaves the
scalar as its literal text, since only the application that defined the tag can
say what it means.

## Events

Reach for `Parser` when the event stream itself is the point: streaming over a
document too large to hold in memory, or preserving what the value layer
deliberately drops (scalar style, which nodes were aliases, the text of unknown
tags).

```zig
var p = yaml.Parser.init(gpa, source);
defer p.deinit();
while (try p.next()) |ev| switch (ev) {
    .scalar => |s| std.debug.print("scalar {s}\n", .{s.value}),
    else => {},
};
// On error.InvalidYaml, p.problem / p.problem_mark carry the detail.

// Or render the whole stream in yaml-test-suite `test.event` form:
const text = try yaml.dumpEvents(gpa, source);
defer gpa.free(text);
```

## Aliases, sharing and cycles

An alias **shares** the anchored node rather than copying it, so `Value`'s
collection slices are genuinely shared and the result is a DAG. That is also the
defence against the "billion laughs" expansion bomb: an input that would expand
to 2^n nodes composes into n. `Options.max_nodes` and `Options.max_depth` bound
the rest.

**A cyclic alias — one naming an ancestor — is rejected** with
`error.AliasCycle`, though YAML 1.2 permits it. The reasoning is in
[SPEC.md](SPEC.md) §7; the short version is that a cycle makes `Value`
unwalkable by any consumer that does not carry its own visited-set, and no JSON
oracle can express one anyway.

## Duplicate mapping keys

YAML 1.2.2 §3.2.1.1 says a mapping node's keys are unique ("the content of a
mapping node is an unordered set of key/value node pairs, with the
restriction that each of the keys is unique"), and the de-facto reference
implementation for Go enforces it: `go-yaml/yaml` branch `v3`'s `newDecoder()`
sets `uniqueKeys: true`, so a repeated key is a decode error there unless the
caller opts out (`yaml.v2` is the other way round — lenient unless you call
`UnmarshalStrict` — so it is not the precedent to follow).

This composer matches v3: **`Options.reject_duplicate_keys` defaults to
`true`**, and a repeated key composes to `error.DuplicateKey`. Set it `false`
to opt into the permissive behaviour instead — every pair is preserved, in
wire order, including the duplicates — for a caller that already owns the
ambiguity itself (interop with a producer that duplicates keys on purpose, or
a consumer implementing its own first-/last-wins policy).

## Lifetime

Everything is arena-backed. `Parser` owns an arena; so do `Composed` and
`Single`, necessarily, because a shared DAG cannot be freed node by node. In
every case the source slice is borrowed only for the duration of the call — the
returned tree copies what it needs.

- **Role:** codec. **Platform:** any.
  **Concurrency:** reentrant (no shared state; each parser/composer owns its own
  arena and cursor). **Deps:** std-only.
- **Model after:** the YAML 1.2.2 specification (yaml.org/spec/1.2.2), with the
  scanner/parser/composer staging that every production YAML implementation
  converged on. Written from the spec and from the test suite's own expected
  outputs; no existing parser's source was read or ported.

Provenance: original work of the zig-libs authors (MIT). Clean-room from the
YAML 1.2.2 spec, so no `NOTICE` entry is required (CONVENTIONS.md §5) — the
spec citation lives in `SPEC.md`. Test data: `src/testdata/ledger.txt` is this
repo's own record of verdicts — one line per yaml-test-suite case ID with our
pass/fail/reject classification. It cites those IDs but reproduces none of the
suite's documents, so nothing of yaml-test-suite is vendored here.

## Deferred

- **Emitter.** Writing YAML back out. Nothing here serializes.
- **`parseInto(T, …)`.** Mapping a `Value` onto a user struct, the way
  `std.json.parseFromSlice` does. The dynamic `Value` is the whole API today.
- **Schemas other than core.** The failsafe and JSON schemas, and the `!!binary`
  / `!!timestamp` / `!!set` / `!!omap` types, are not resolved; those tags leave
  their scalars as text.
- **Integers outside `i64`** stay strings holding their exact text — see
  SPEC.md §9.
- **UTF-16/UTF-32 input.** §5.2 allows a BOM to select them; only the UTF-8 BOM
  is handled.

## Verification

The oracle is **yaml-test-suite** (`github.com/yaml/yaml-test-suite`, `data`
branch), at both layers, from implementations that have never seen this code:

| layer | oracle | score |
|---|---|---|
| events (scanner + parser) | `test.event`, byte-exact | **402/402**, including all 94 must-reject cases |
| values (composer + core schema) | `in.json`, structural | **279/279** |

279, not 282: three `in.json` files belong to must-reject cases, where they are
a prefix artefact rather than a pass condition. A further 29 non-error cases
have no `in.json` at all — their YAML has non-string mapping keys, which JSON
cannot express.

The suite is fetched, never vendored:

```
git clone -b data --depth 1 https://github.com/yaml/yaml-test-suite \
    ~/.cache/zig-libs-yaml/yaml-test-suite-data
```

`src/suite_test.zig` runs every case and asserts the committed ledger
(`src/testdata/ledger.txt`) exactly, in both directions — a listed pass that
regresses is red, and a known-fail that starts passing is red too. Point
`ZIG_LIBS_YAML_SUITE` at another checkout to override the path; without a suite
the test **skips loudly** (`SKIPPED: …`), never silently.

`zig build test-yaml` — green in Debug and `-Doptimize=ReleaseFast`.
`zig fmt --check modules/yaml` clean.
