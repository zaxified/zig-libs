# zig-libs

A curated collection of **foundational Zig modules** — performance-minded,
universal where possible, each modeled after a proven implementation in another
language rather than invented from scratch.

Not a dumping ground: ship **solid, not many**. Most members are *extracted* from
working code across sibling projects (bxp, axp, zig-fping, poc-wf-analytic); a few
fill genuine gaps in the Zig ecosystem.

## Layout

```
zig-libs/
  build.zig          # single root build (see below), exposes every module by name
  build.zig.zon      # one package manifest for the whole collection
  CONVENTIONS.md     # naming + `meta` tag vocabulary + sub-library rule
  modules/
    _template/       # copy this to start a new module
    <name>/
      src/root.zig   # module entry: `pub const meta` + public API + tests
      README.md      # what it is, status, model-after, seed location
```

**Why one root `build.zig`:** `zig fetch` cannot target a subdirectory
(ziglang/zig#23012). A consumer fetches the whole repo and imports just the module
it wants; the root build wires modules and their inter-dependencies.

## Using a module

- **Local dev (no tags/push):** a consumer's `build.zig.zon` can depend on this repo by
  path — `.zig_libs = .{ .path = "../zig-libs" }` — then import the named module.
- The root build exposes each module under its `name` (e.g. `@import("ramcache")`).

## Build

```
zig build test           # run all module tests
zig build test-<name>    # run one module's tests
```

## Module index

See the live candidate catalog + per-module notes in `~/CML/zig-libs-plan.md`
(discussion doc) and the CML memory `project_zig_libs_catalog.md`. Currently
scaffolded: `netaddr`, `ramcache` (stubs — real extraction pending).
