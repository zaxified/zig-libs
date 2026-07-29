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
  NOTICE                 # third-party DESIGN REFERENCES only — no license conditions
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
module's own SPEC.md instead (see whois/rdap/tar). The root NOTICE is reserved for **design
references** — a named third-party implementation consulted for behavior/algorithm/API shape
without copying source. Those are provenance records, never license conditions.

**Required attribution goes in the module, not the root.** If a module ports third-party source,
its license terms are reproduced in `modules/<name>/NOTICE`, beside the code that owes them, so the
notice travels with the module (see `falcon`). Never add such an entry to the root NOTICE: keeping
the root free of redistribution conditions is what lets zig-libs be consumed as plain MIT.

Running an installed third-party binary purely as a black-box compatibility
test oracle (e.g. diffing output against `tar`/`nft`) is neither of the above and needs no entry.

**Non-overlap rule:** README answers "how do I use this" (consumer altitude); SPEC
answers "how/why was this built, and what could go wrong" (auditor altitude). A module's
purpose is a full paragraph in the README and only a title + link back to the README in
SPEC. Seed/provenance detail lives in `NOTICE`; README/SPEC merely reference it (a short
`Provenance:` line pointing at the NOTICE entry, not a restatement of it).

**On length (they answer different questions, so neither is "the longer doc"):** a
README's length tracks the module's **API surface** — a rich module (`http`, `jwt`) has a
long README full of usage; a small one has a short README. A SPEC's length tracks its
**design/threat complexity** — a module that is simple to reason about has a short SPEC,
even if its API is large. So a big README + a terse SPEC is normal and correct; do **not**
pad a SPEC to match a README (or vice-versa). The SPEC is a focused auditor/design
reference, not a re-explanation of everything the README already covers.

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
   was caught). Verify: `cat modules/<m>/src/*.zig | grep -c '^\s*test '` (blocks on
   disk) must equal the running count from `zig build test-<m> --summary all`.
4. `zig build test-<name>` (per module) and `zig build test` (all) — both green in
   **Debug and ReleaseFast**; `zig fmt --check modules/<name>` clean.
5. Update the root `NOTICE` with any third-party design reference + its license. If you
   actually ported third-party source, its terms go in `modules/<name>/NOTICE` instead —
   never in the root file.

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

### 7.1 Optimize modes — what each CI lane proves

This workspace ships **source**, never a binary. The optimize mode of the artifact is
the integrator's decision, made in their build; we have no deployment to hold an
opinion about. Our modes exist purely to test, benchmark and prove the code, and each
lane proves something the others cannot:

| Lane | What it proves |
|------|----------------|
| default (Debug, heavy modules at `ReleaseSafe`) | correctness with every safety check armed, fast enough to run on each change |
| `-Dstrict-debug` | real Debug for the heavy modules too — the default lane relaxes them for wall-clock, so on its own it no longer proves Debug |
| `-Doptimize=ReleaseFast` | the code is free of undefined behaviour that the safety checks would otherwise mask, and of anything that only holds because of them |
| `-Doptimize=ReleaseSafe` | the middle mode is green — integrators build in all three, so all three must pass |

**A note worth passing to integrators** (belongs in module docs where a parser is
exposed, not enforced here): every parser that touches bytes it did not produce is
held to a "never panic on arbitrary input" threat model, backed by **301 fuzz
harnesses across 84 modules**. Those harnesses assert that arbitrary input never trips
a safety check — an assertion that only carries meaning in a build where the checks
exist. Compiled `ReleaseFast`, the bound the fuzzer proved untripped is simply gone,
and the input that would have panicked reads out of bounds instead. So the fuzz corpus
is evidence about a Debug or `ReleaseSafe` build of the consuming binary, and says
nothing about a `ReleaseFast` one. What an integrator does with that is their call.

## 8. Versioning, releases & spin-offs

- **One semver for the whole collection.** A release = a git tag (`vX.Y.Z`) on `main` with
  CI green. Pre-1.0 semantics: a minor bump may break any module's API; a patch bump is
  fixes-only. There are no per-module version numbers.
- **CHANGELOG.md per release, grouped by module.** Every release tag gets a section listing
  added modules and, per existing module, behavior/API changes — breaking changes flagged
  **BREAKING**. Routine internal refactors need no entry.
- **Maturity = explicit caveats, not tier labels.** Every module meets the same bar (§6/§7:
  tests green in Debug + ReleaseFast, oracle/KAT verification where one exists). What varies
  is *scope*: anything unfinished or unverified is stated as an explicit caveat in the
  module's README-catalog row and SPEC (e.g. dnp3's "Secure Authentication scaffolded only",
  ebpf's "real-kernel verifier acceptance unverified"). A per-module `stability` tier tag
  (stable/beta/experimental) was considered and rejected: coarse tiers hide exactly the
  detail the caveat lines carry, and would rot.
- **Catalog consistency is enforced**: `zig build check-catalog` (run by CI) fails when
  `build.zig`'s `module_list`, the `modules/` directory, and the README catalog table
  disagree, or when the README's module count goes stale.
- **Spin-off policy — when a module leaves the monorepo: by default, never.** The
  collection's dense sibling-dependency graph is version-skew-free only because everything
  builds from one tree (Zig pins dependencies by URL+hash; two repos pinning different
  hashes of a shared dep hand consumers two type-incompatible copies of it). Extract a
  module into its own repository only when at least one of:
  1. it has real external traction — consumers/issues asking for standalone releases;
  2. it needs a C dependency or a different build model (which would break §2 here); or
  3. it needs a release cadence the collection cannot follow.
  Extraction = `git filter-repo` preserving the module's history + a deprecation pointer
  left in `modules/<name>/README.md` for one release cycle.
- **Download-size escape valve (documented, deliberately not built).** If whole-repo fetch
  size ever becomes a real consumer complaint, attach per-module tarballs (module +
  transitive sibling deps + a minimal `build.zig`) to GitHub releases — `zig fetch`
  accepts any tarball URL. That is the answer to "the repo is too big to fetch";
  splitting the repository is not.
