# zig-libs conventions

This file is the sole repo-rules document — every durable *rule* lives here.
Per-module design/threat-model lives in each module's `SPEC.md`.

## 1. Prime directives

1. **Model after a proven implementation in another language.** Every module names a
   reference impl (c-ares, nghttp2, Java BigDecimal, …) or a public spec/RFC. Mirror its
   design; do NOT invent novel algorithms from scratch. Correctness > cleverness.
2. **Performance + universality.** Design for parallelism/streaming where relevant (the
   `⚡` tag). Prefer zero-allocation hot paths, caller-supplied allocators, no hidden
   globals.
3. **Prefer std; build a dep only where std 0.16 has a real gap** (recursive-sublib
   rule, §5). `std.json`, `std.crypto.tls` (client), `std.compress` (flate/zstd decode)
   already exist — use them, don't reimplement.
4. **Every module is headless-verifiable.** Ship tests. Where a conformance/golden
   oracle exists (h2spec, fping golden-diff, RFC KATs, `nft --debug`), verify against it.
5. **Do NOT depend on `std.http.Client`** — its API churns; replacing that dependency is
   a reason this collection exists.

## 2. Hard invariants

- **100% pure Zig — no C, no libc, no external deps.** `build.zig.zon` dependencies stay
  empty; zero `@cImport`/`linkLibrary`/`.c` source anywhere in `modules/`. (A
  compile-time `builtin.link_libc` *type* branch that only adapts IF a consumer already
  links libc, e.g. in `procrun`, is not a violation — the module itself never forces
  libc.)
  - **0.16 gotcha:** there is no `std.Thread.Mutex`/`Condition` in this era — use
    `std.posix` primitives / an atomic spinlock. Don't reach for `std.c.*` either.
- **Zero-dep rule.** Any capability whose value is fundamentally **C-level** (a hardened
  SQLite wrapper's `sqlite3_set_authorizer`/`PRAGMA query_only`/`open_v2(READONLY)`
  enforcement, `libssh2`/`librdkafka` bindings, OPC-UA stacks) does **not** belong in the
  module set, even if a thin pure-Zig policy layer around it could. It stays in the
  **ADOPT** table (see the Non-goals section of README.md) and lives **consumer-side**, wired over the
  external binding by the application. zig-libs may ship the pure-Zig *policy/validation*
  half of such a thing, never the C enforcement half.
- **TLS = proxy-terminate / bring-your-own.** No module implements a TLS *server*; the
  h2 stack (and anything else that wants TLS-terminated transport) takes an
  already-terminated stream via a BYO-TLS/ALPN seam. Revisit when std ships a native TLS
  server (gated on `std.Io`, ~0.18/post-1.0) or via an opportunistic spike; until then,
  this is the permanent shape, not a stopgap.

## 3. Naming & structure

- **`snake_case`, capability-based, no `zig-` prefix, no platform/role in the name** —
  `dns`, `http`, `decimal`, `netlink`, `ramcache`, `netaddr`. Zig naming does not cram
  platform/role/concurrency into the identifier; those are carried as **metadata tags**
  instead (§4), visible in the tag table, not the name.
- **Client/server split rule.** Split into `_client` / `_server` modules **only** when
  both are separate deliverables. Default = one module exposing both via submodules
  (e.g. `http.Client` / `http.Server`).
- **Internal casing.** Types → `TitleCase`; type-returning fns → `TitleCase`; other
  callables → `camelCase`; everything else → `snake_case`.
- **Recursive sub-libraries.** A module may need its own building blocks (e.g. `dns` over
  DoH wants http + tls + json). Rule: prefer Zig 0.16 std for a dep; only promote a
  sub-dependency to its own module when std has a *real gap* and it makes sense to own
  it long-term.
- **Repo shape:**

  ```
  build.zig            # registers each module by name + `test` / `test-<name>` steps
  build.zig.zon        # one manifest for the whole collection
  CONVENTIONS.md        # this file — all repo rules
  NOTICE                 # canonical provenance + third-party design-refs + licenses
  docs/pre-public-review.md  # living pre-release audit checklist (deleted once done)
  modules/
    _template/           # copy to start a module
    <name>/
      src/root.zig        # SPDX line + `pub const meta` + API + tests
      README.md            # how to use — consumer-facing
      SPEC.md              # how/why built + threats — auditor-facing (module-local)
  ```

## 4. The `meta` tag vocabulary

Every `modules/<name>/src/root.zig` declares a `pub const meta` block — **this is the
canonical source of a module's metadata**; a module's README shows a *derived* view of
it, and SPEC.md does not restate it. Vocabulary:

- `platform`: `.any` (cross-OS) · `.posix` · `.linux` (raw syscalls / no-libc — a
  conscious ceiling, not a bug).
- `role`: `.client` · `.server` · `.codec` (pure wire, no I/O) · `.both` · `.util`.
- `concurrency`: `.reentrant` (no shared state — safe if not shared) · `.threadsafe`
  (internally synchronized) · `.single_owner` (one thread/loop owns the state, lock-free)
  · `.blocking`.
- `model_after`: the proven implementation in another language mirrored rather than
  invented from scratch (e.g. "c-ares", "Java BigDecimal", "nghttp2 + h2spec").
- `deps`: sibling modules / std it builds on.

## 5. Doc ownership — single source of truth

One fact lives in exactly one place; everywhere else links to it, never restates it.

| Fact | Lives in | Everywhere else |
|---|---|---|
| meta tags (platform/role/concurrency/model_after/deps) | `pub const meta` in `src/root.zig` | README shows a derived view; SPEC does not restate |
| one-line module purpose | root `README.md` catalog table | — |
| paragraph purpose + API + import + verify steps | `modules/<m>/README.md` | — |
| design & invariants, threat-model, verification detail, per-module backlog | `modules/<m>/SPEC.md` | — |
| license attribution / provenance | `NOTICE` | README/SPEC only point to it, never restate the terms |
| all repo rules | this file (`CONVENTIONS.md`) | — |
| module catalog | root `README.md` table | — |

**When does NOTICE need an entry?** A public spec/RFC is not a copyrightable work (merger
doctrine — implementing one, however closely, is not "derived from" anyone's code). A module that
is pure clean-room-from-spec, with no third-party source ported and no third-party implementation
studied as a design reference, needs **no NOTICE entry** — its RFC/spec citation lives in the
module's own SPEC.md instead (see whois/rdap/tar). NOTICE is reserved for (1) **required
attribution** — third-party source actually ported, license terms reproduced; and (2) **design
references** — a named third-party implementation consulted for behavior/algorithm/API shape even
without copying source. Running an installed third-party binary purely as a black-box compatibility
test oracle (e.g. diffing output against `tar`/`nft`) is neither of the above and needs no entry.

**Non-overlap rule:** README answers "how do I use this" (consumer altitude); SPEC
answers "how/why was this built, and what could go wrong" (auditor altitude). A module's
purpose is a full paragraph in the README and only a title + link back to the README in
SPEC. Seed/provenance detail lives in `NOTICE`; README/SPEC merely reference it (a short
`Provenance:` line pointing at the NOTICE entry, not a restatement of it).

## 6. How to add a module

1. `cp -r modules/_template modules/<name>`, fill `src/root.zig` (SPDX line first,
   `pub const meta`, public API + doc-comments, tests) and `README.md` (incl. a
   `Provenance:` line). Add a `SPEC.md` for anything with a real threat model or
   non-obvious design invariant.
2. Add `.{ .name = "<name>", .deps = &.{ "dep1", ... } }` to `module_list` in
   `build.zig`.
3. **Multi-file modules:** add every new submodule to `root.zig`'s `test { _ = …; }`
   aggregator — a bare `pub const x = @import("x.zig")` re-export does **not** pull `x`'s
   tests into the test binary (the dark-tests rule; it hid 92 never-run tests before it
   was caught — see the dark-tests check in `docs/pre-public-review.md`).
4. `zig build test-<name>` (per module) and `zig build test` (all) — both green in
   **Debug and ReleaseFast**; `zig fmt --check modules/<name>` clean.
5. Update `NOTICE` with any third-party design reference + its license.

## 7. Verification harness per module type

- **Protocol codecs** (`icmp`, `dns`, `l2disco`, `http` h2): golden bytes / **h2spec**
  for h2 / RFC known-answer test vectors where the spec publishes them.
- **Syscall/netlink/raw** (`netlink`, `rawsock`, `wireguard`): a network namespace
  (`unshare -rn`).
- **Pure logic** (`decimal`, `datefmt`, `ramcache`, `finstats`): unit tests +
  property/round-trip.
- **Clients** (`dns`, `whois`, `rdap`, `http` client): a live round-trip against a real
  server when the network is available, plus offline unit tests on parsing.
- No shared `testkit` harness exists yet — it was scoped and **deferred** (see the Roadmap
  section of README.md); each module hand-rolls its own wire-test/fake-clock helpers for now.
