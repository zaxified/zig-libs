# zig-libs conventions

## Naming

Follows the community Zig style (Nathan Craddock / std): a module that is a
**namespace** (a struct with no fields, never instantiated) is `snake_case`.
Our module names are therefore:

- **`snake_case`, capability-based, no `zig-` prefix, no platform/role in the name.**
  `dns`, `http`, `decimal`, `netlink`, `ramcache`, `netaddr`.
- Split into `_client` / `_server` **only** when both are separate deliverables.
  Default = one module that exposes both via submodules (e.g. `http.Client` / `http.Server`).
- Inside a module: types → `TitleCase`; type-returning fns → `TitleCase`;
  other callables → `camelCase`; everything else → `snake_case`.

Rationale: Zig naming does not cram platform/role/concurrency into the identifier.
We keep names clean and carry those attributes as **metadata tags** instead — so you
can still see "linux-only / server / threadsafe" at a glance, in the tag table, not the name.

## `meta` tags (per module)

Every `modules/<name>/src/root.zig` declares a `pub const meta` block. Vocabulary:

- `status`: `.extract` (already seeded in one of our projects, just carve out) ·
  `.gap` (missing in Zig, build/port) · `.adopt` (a good pure-Zig lib exists — don't build).
- `platform`: `.any` (cross-OS) · `.posix` · `.linux` (raw syscalls / no-libc — a
  conscious ceiling, not a bug).
- `role`: `.client` · `.server` · `.codec` (pure wire, no I/O) · `.both` · `.util`.
- `concurrency`: `.reentrant` (no shared state — safe if not shared) · `.threadsafe`
  (internally synchronized) · `.single_owner` (one thread/loop owns the state, lock-free) ·
  `.blocking`.
- `model_after`: the proven implementation in another language we mirror rather than
  inventing from scratch (e.g. "c-ares", "Java BigDecimal", "nghttp2 + h2spec").
- `deps`: sibling modules / std it builds on.

## Recursive sub-libraries

A module may need its own building blocks (e.g. `dns` over DoH would want http + tls + json).
Rule: **prefer Zig 0.16 std** for a dep; only promote a sub-dependency to its own module when
std has a *real gap* and it makes sense to own it. (std already has `std.json`, `std.crypto.tls`
client, `std.compress` flate/zstd decode — adopt those; build where they fall short.)

## Adding a module

1. `cp -r modules/_template modules/<name>` and fill in `src/root.zig` + `README.md`.
2. Add `.{ .name = "<name>", .deps = &.{...} }` to `module_list` in `build.zig`.
3. `zig build test-<name>`.
