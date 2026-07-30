# yaml

**YAML 1.2 streaming event parser** — not 1.1. Source bytes go through a
scanner (tokens) and a parser (events); the caller pulls one `Event` at a time
until the stream ends. This is the layer every YAML implementation builds on:
it decides where collections begin and end, what a scalar's text actually is
after folding and chomping, and which inputs are malformed — without deciding
what any of it *means*.

**This is Part 1 of the module: events only.** There is no composer, no alias
resolution into a node graph, no core-schema tag resolution (`null` / `bool` /
`int` / `float`) and no native-value API. Those are an event *consumer* and are
not built yet — see Deferred.

Covered at the event layer: block sequences and mappings, plain, single- and
double-quoted scalars with their escape and folding rules, flow collections,
literal `|` and folded `>` block scalars with every indentation and chomping
indicator, comments, multi-document streams, `%YAML` / `%TAG` directives,
anchors and aliases, explicit `?` / `:` keys, tag shorthands and verbatim tags.

```zig
const yaml = @import("yaml");

var p = yaml.Parser.init(alloc, source);
defer p.deinit();
while (try p.next()) |ev| switch (ev) {
    .scalar => |s| std.debug.print("scalar {s}\n", .{s.value}),
    .mapping_start => |m| std.debug.print("map (anchor {?s})\n", .{m.anchor}),
    else => {},
};
// On error.InvalidYaml, p.problem / p.problem_mark carry the detail.

// Or render the whole stream in yaml-test-suite `test.event` form:
const text = try yaml.dumpEvents(alloc, source);
defer alloc.free(text);
```

`Parser` owns an arena. Every slice reachable from an `Event` — scalar text,
anchor names, resolved tags — lives in that arena and stays valid until
`deinit()`, so events are cheap to hold across `next()` calls. The cost is that
the arena grows with the document; a consumer that must bound memory over a
huge stream should copy what it needs and run one `Parser` per document. The
source slice is **borrowed**, not copied, and must outlive the parser.

- **Role:** codec. **Platform:** any.
  **Concurrency:** reentrant (no shared state; each `Parser` owns its own arena
  and cursor). **Deps:** std-only.
- **Model after:** the YAML 1.2.2 specification (yaml.org/spec/1.2.2), with the
  scanner/parser/event staging that every production YAML implementation
  converged on. Written from the spec and from the test suite's own expected
  outputs; no existing parser's source was read or ported.

Provenance: original work of the zig-libs authors (MIT). Clean-room from the
YAML 1.2.2 spec, so no `NOTICE` entry is required (CONVENTIONS.md §5) — the
spec citation lives in `SPEC.md`.

## Deferred (Part 2 — an event consumer, not a change to this layer)

- **Composer.** Turning the event stream into a node graph, including alias
  resolution and the cycle detection that comes with it.
- **Core schema.** Resolving untagged scalars to `null` / `bool` / `int` /
  `float` per the YAML 1.2 Core Schema, and the `!!` tag family.
- **Native-value API.** A `parseInto(T, …)` / dynamic `Value` surface.
- **Emitter.** Writing YAML back out. Nothing here serializes.
- **Duplicate-key detection.** A composer-level concern: at the event layer a
  mapping is just an alternating run of nodes.

## Verification

The oracle is **yaml-test-suite** (`github.com/yaml/yaml-test-suite`, `data`
branch): 402 cases, each carrying a byte-exact expected event dump produced by
an implementation that has never seen this code, 94 of them inputs that must be
*rejected*. **All 402 pass.**

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
