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

### 2.1 Zeroization of secret material

`std.crypto.secureZero` clears **the storage you name it on, and nothing else**. The compiler is
free to keep the same bytes in registers and stack spill slots, and no `secureZero` call can reach
those. A wipe therefore earns its line only where it removes a copy that would otherwise **outlive
the call**; where every copy dies with the call frame regardless, it removes one of an unknown
number of equally short-lived copies and buys nothing an attacker model can name. That asymmetry —
not "these bytes are secret" — decides each case below.

Classify the *storage*, then apply the rule. This is settled repo-wide; it is not re-decided per
module.

**Z1 — storage this module owns and knows the death of → MUST wipe.**
A copy of the *secret itself* in storage we control: a struct field, a heap buffer we allocate and
free, or a local holding a private key, a decrypted plaintext, or derived key material. Anything
that is a secret in module-controlled storage and is not on Z3's list below is Z1. Here we know
exactly when the secret dies, and the copy the wipe
removes is genuinely the long-lived one — a freed heap block goes straight back to the allocator
and on to unrelated code. Wipe in `deinit`/`wipe()`, or via `defer`; **register the `defer` before
the fallible call that fills the buffer**, never after it, or the error path skips the wipe. This
matches `std` (`Poly1305.final`, `Ghash.final`, and the plaintext-plus-tag wipe on AEAD
authentication failure) and the 46 modules here that already do it.

**Z2 — caller-owned storage → MUST NOT wipe; MUST document.**
A secret the caller passed in by value, or one we hand back inside a decoded struct
(`lnwire.UpdateFulfillHtlc.payment_preimage`, the static keypair `s` in `noise`). The module cannot
know when the caller is finished with it, so wiping is either a use-after-wipe for them or a no-op
on our own dying copy. The deliverable is a `///` sentence naming the field and stating that the
caller must `std.crypto.secureZero` it when done. `noise/src/state.zig:511-516` is the reference:
it wipes `e`, `ck` and `k`, deliberately leaves `s`, and says why. **A doc sentence is a complete
fix for a Z2 site** — do not "upgrade" it to a wipe.

**Z3 — the internal working state of a transform → NOT wiped, by convention.**
Hash chaining variables and message blocks, sponge/permutation state, AES round-key schedules:
storage that secret-derived bytes merely *passed through*. `std` takes exactly this position —
`sha2`, `sha3`, `blake2`, `blake3`, `hmac` and `hkdf` contain no `secureZero` at all (`hmac` keeps
a real MAC key in `o_key_pad` and still does not wipe it), while `keccak_p` and `ascon` expose an
**opt-in** `secureZero()` method that their own hash paths never call. We do not diverge: no wipe
inside the transform, and where a caller has a concrete reason to want one, expose an opt-in
`secureZero()`/`wipe()` on the state instead of charging every call for it. This is also where the
register/spill argument bites hardest — a compression function holds the chaining variables in
registers for its entire run, so wiping the struct afterwards clears the copy least likely to be
the one that leaks.

**A zeroization finding against a Z3 site is not a finding.** Cite this section and close it.

**Which build mode a heap wipe is actually for.** `std.mem.Allocator.free` runs
`@memset(bytes, undefined)` *before* it calls the vtable, so in Debug and ReleaseSafe every freed
block is already scrubbed to `0xaa` and a `secureZero` before `free` changes nothing. In
ReleaseFast that memset compiles to nothing — so the wipe is load-bearing in exactly one mode, and
it is the mode an integrator ships. Write the wipe; just do not claim the safe lanes prove it.

**What a Z1 wipe can and cannot be tested for.** A wipe of a *struct field* is testable in any
mode, and must ship with a test asserting the field is zero after `wipe()` — with a precondition
assert that the field was non-zero first, or the test passes vacuously
(`tenantkex/src/root.zig`'s `SessionKeys.wipe` test is the model). A wipe of a *heap buffer before
`free`* is testable only under `-Doptimize=ReleaseFast`, for the reason above: route the
allocation through a test-local allocator wrapper that inspects the bytes handed to `rawFree`, and
gate the test on `builtin.mode == .ReleaseFast` with `error.SkipZigTest` so the skip is visible
rather than a silent pass (`xmlenc/src/test_roundtrip.zig`'s `FreeScanner` is the model). A wipe
of a **stack local is not testable at all**, and no reviewer should ask for a red test on one: the
dead frame lies below the stack pointer, so any function that reads it must first build a frame
there — and in Debug/ReleaseSafe Zig initializes that frame's `undefined` locals to `0xaa`,
scrubbing the very residue the probe wants to see (measured: 2048/2048 bytes overwritten; in
ReleaseFast the residue is gone for a different reason, register and slot reuse). Z1 stack wipes
are justified by this rule and by review, not by a regression test.

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

**Two kinds of `modules/<name>/NOTICE`, and the first line says which.** A module-local NOTICE is
either

| First line | Kind | Meaning |
|---|---|---|
| `<name> — third-party attribution` | **condition-bearing** | ported source/data; its terms are reproduced here and travel with the module |
| `<name> — provenance note` | **record only** | a §2-style design-reference record kept beside the module instead of in the root NOTICE |

A provenance note is the right home when a module's provenance is long enough to drown the root
file — the self-contained crypto/protocol modules run to hundreds of lines each (`bls12_381` is
over 800). It is a placement choice, nothing more: a provenance note **must not** carry any
condition, and the root NOTICE §1 lists the condition-bearing files exhaustively so a consumer can
answer "what do I owe?" by reading those and nothing else. `zig build check-catalog` enforces the
first-line discriminator, that every condition-bearing file is listed in root §1, and that no
provenance note is.

**Never justify placement by pointing at a sibling.** Cite this section instead. Chained
"same placement as the sibling X/Y/Z modules" reasoning is how the practice drifted for 38 modules
without anyone deciding it, and how the root NOTICE came to claim one module carried its own file
while four did.

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

   > **Install the commit-time formatting guard once per clone:**
   > `git config core.hooksPath scripts/hooks`
   >
   > It refuses a commit whose **staged** Zig/ZON blobs are not `zig fmt` clean. Three
   > format gates already exist (`test.sh all`, `test.sh changed`, CI), and all three are
   > gates you have to remember to reach — `a23a933` is what that costs. Formatting drift
   > cannot change behaviour; what it breaks is a gate, and a gate that reddens for a
   > reason nobody caused on purpose is one people learn to ignore. `--no-verify` bypasses
   > when you mean it.
5. Update the root `NOTICE` with any third-party design reference + its license. If you
   actually ported third-party source, its terms go in `modules/<name>/NOTICE` instead —
   never in the root file.

### 6.1 Test-only dependencies

A module a consumer imports must not carry a test harness. Use `test_deps`, not `deps`:

```zig
.{ .name = "netlink", .test_deps = &.{"testkit"} },
```

`build.zig` then compiles the tests against a second module object with the extra
imports; the object `b.addModule` publishes never sees them. They still appear in
`module-graph`'s deps column, because that graph answers "what must be re-tested when
X changes" and a test-only import is a real answer to it.

**`zig build check-testonly` is what makes the claim true rather than aspirational.**
Zig analyses container-level decls lazily, so an unused `@import("testkit")` sitting in
a module's non-test code is never looked at and no ordinary build notices — verified by
planting `pub const leaked_probe = testkit.verbose_skip_env;` in `netlink`, after which
every dependent still built green. The step forces the analysis with a consumer-shaped
probe. It is part of `zig build test`.

Reach for [`testkit`](modules/testkit) rather than writing a local helper when one of
its pieces fits, and **only add to testkit what is already duplicated** — every entry
there replaced at least 18 copies. Anything that legitimately differs per module
(netns setup, capability probing) stays local: a shared abstraction over those hides
the distinctions that make the skips correct.

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
- **The Non-goals section is enforced in the other direction**: the same gate fails when
  README's "Non-goals — deliberately not built here" names a module that exists, so a
  decision not to build something cannot outlive the day we build it. Five rows had
  already outlived it (`websocket`, `smtp` and `jinja` were still pointing at third-party
  libraries) before the check existed. When a non-goal legitimately mentions a module —
  e.g. `taskqueue` explaining that it was folded into `jobqueue` — append
  `<!-- non-goal-ok: jobqueue -->` to that line. Exemptions are per name, and an exemption
  for a name the line does not actually mention is itself an error.
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
