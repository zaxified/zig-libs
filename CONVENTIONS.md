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
- **TLS = proxy-terminate / bring-your-own.** No module terminates TLS on a *stream*
  transport; the h2 stack (and anything else that wants TLS-terminated transport) takes an
  already-terminated stream via a BYO-TLS/ALPN seam. Revisit when std ships a native TLS
  server (gated on `std.Io`, ~0.18/post-1.0) or via an opportunistic spike; until then,
  this is the permanent shape, not a stopgap.
  **Datagram DTLS is deliberately outside this rule.** `dtls` ships a full RFC 9147
  DTLS 1.3 *server* (`Connection.serverInit` — PSK and cert modes, optional mutual auth,
  live-interop'd against wolfSSL), and that is not an exception grudgingly granted: the
  rule above exists because a TLS-terminating proxy is a mature, ubiquitous thing to put
  in front of a *stream* server, so shipping our own would duplicate hardened
  infrastructure for no gain. Neither half holds for datagrams — there is no equivalent
  DTLS-terminating front end to hand an association to, and `std.crypto.tls` has no DTLS
  at all, so a consumer has nothing to bring. The line is "don't reimplement what a proxy
  or std already does safely", not "no handshake code in this repo".

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

### 2.2 Where secret-bearing randomness comes from

`std.Io.random` is a CSPRNG **with a documented silent-degrade clause** — "seeded by
`randomSecure`, or a less secure mechanism upon failure" — and `std.Io.Threaded` honours it
literally: on `error.EntropyUnavailable` it seeds from a zeroed buffer plus an ASLR pointer,
`getpid()` and a clock. That failure is invisible to every test anything downstream could write.
`std.Io.randomSecure` is the fail-closed twin. The rule:

- **Draws that become secrets** — keys, private scalars, nonces/IVs, salts, session ids,
  ephemeral key material: `try io.randomSecure(buf)` where the signature already returns an
  error; [`entropy.fill(io, buf)`](modules/entropy) where it cannot. Prefer the former — `fill`
  aborts the process, which is right only when there is no error channel to use instead.
  `entropy.SecureSource` is the fail-closed `std.Random` adapter (`std.Random.IoSource` binds the
  degrading call).
- **Everything else** — jitter, backoff, tiebreaks, hash-table seeds, test fixtures: `io.random`.
  Do not pay a syscall, let alone an abort, for these.

Deliberate exceptions, which stay as they are:

- `ssh` and `bulletproofs` hand-roll a `getrandom(2)` loop that panics on failure. Same
  fail-closed posture, reached before `entropy` existed, and both are deliberately
  `platform = .linux` for it. Not a defect; do not open a task to migrate them.
- `sealedbox` and `signal`'s KAT seams use `io.random` **on purpose**: feeding a scripted stream
  into it is what makes their published vectors reproducible. A fail-closed draw there would
  delete the anchor.

A new module that draws a secret and does neither of the above is a finding.

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

- `targets`: **a claim `zig build check-portable` enforces, not documentation.** A
  non-empty, duplicate-free set drawn from `PortableTarget` (`build.zig`):
  - `.linux64` — Linux, amd64 or arm64. The collection's baseline: every module in
    `module_list` already proves this by existing (§6/§7 — tests green in all three
    release lanes on the native runner, plus the CI matrix's arm64 lane), so it is
    **mandatory in every module's set** and is never itself cross-compiled by the gate.
  - `.linux32` — 32-bit, **big-endian, soft-float** Linux, representative target
    `mips-linux-musl` + `mips32,soft_float` (taken verbatim from a downstream device
    agent's own cross-compile probe: an ath79 24Kc has no FPU, so soft-float is
    load-bearing here, not a default). Named as that
    specific architecture rather than a wider "any 32-bit Linux" class on purpose: endianness is a
    defect class a little-endian 32-bit probe (wasm32, i686, mipsel, arm) cannot catch — a
    module with an implicit little-endian assumption in a multi-byte wire field passes
    every OTHER lane here (all little-endian, all but this one 64-bit) and only breaks on
    a real big-endian target. A wider class would let a module pass on a little-endian
    32-bit probe and claim readiness for the big-endian target it was never actually
    built for — an unverified claim wearing a verified one's label, which is what this
    schema exists to stop doing.
  - `.windows` — `x86_64-windows-gnu` (a downstream GUI bridge ships a DLL there).
  - `.wasm32` — `wasm32-wasi` (qr/qrscan's static-footprint use case; wasi supplies the OS
    surface the default test runner needs while keeping 32-bit pointers — see
    `build.zig`'s `check-portable` comment for why wasi and not freestanding).

  **This is a claim about what the gate has checked, not about where the code might
  incidentally run.** Declare a target only once `zig build portable-<name>-<target>`
  either passes or is added to `scripts/portable-known-failures.tsv` with the real
  compiler error as the reason — never because the code "should" work there. A module
  that never intends a target (raw `std.Thread`/libc/`std.os.linux` use with no wasm or
  embedded audience) simply omits it; that is not a defect and does not need a baseline
  row. `check-portable` fails on either direction of drift: a declared target that is not
  swept, and a declared-and-swept target whose compile is red without a baseline entry.
  A module with no `.targets` field at all (or one missing `.linux64`) fails the gate —
  "undeclared" is not read as "any", the confusion this schema replaces.

  **What a declared target covers: the tests AND the whole public surface.** Each declared
  pair compiles twice — the module's test binary, and the same forcing root
  `check-pubfn-reach` uses on the native target, which takes a reference to every
  non-generic public declaration. Without the second compile the claim silently shrinks to
  "the part of the module some test happens to call compiles there", because Zig analyses
  a body only when something references it (measured on native, 2026-08-21: 403 of 9626
  public functions are reachable from no test). Demonstrated on `decimal`, 2026-08-22, with
  a `pub fn` no test calls whose body fails to compile for Windows: `zig build test-decimal`
  green, `check-pubfn-reach` green (the body is fine on Linux), the pair's test compile
  green — only the pair's forcing compile red.
- `platform`: `.any` (cross-OS) · `.posix` · `.linux` (raw syscalls / no-libc — a
  conscious ceiling, not a bug). **Historical/descriptive only as of 2026-08-18 — not
  gate-enforced.** It predates `targets` and conflated two different claims (where a
  module's author *intends* it to run, versus where anyone has *proven* it runs) into one
  field consumers read as the latter; measured proof was 41 `.any` modules failing to
  cross-compile for Windows and 64 failing for wasm32 while all of them claimed `.any`.
  `targets` is the enforceable claim now. `platform` is kept, unchanged, because ~40
  existing SPEC.md/README.md/root.zig doc-comment references quote it in prose (grepped
  2026-08-18 — all prose, no machine reader besides the removed `declaresAnyPlatform` in
  `build.zig`); a new module may still set it for that coarse, human-facing description,
  but `targets` is what a consumer should trust and what CI checks.
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
   `pub const meta`, public API + doc-comments, tests — the template's placeholder
   test **fails on purpose** until a real one replaces it) and `README.md` (incl. a
   `Provenance:` line). Add a `SPEC.md` for anything with a real threat model or
   non-obvious design invariant.
2. Add `.{ .name = "<name>", .deps = &.{ "dep1", ... } }` to `module_list` in
   `build.zig`.
3. **Multi-file modules:** add every new submodule to `root.zig`'s `test { _ = …; }`
   aggregator — a bare `pub const x = @import("x.zig")` re-export does **not** pull `x`'s
   tests into the test binary (the dark-tests rule; it hid 92 never-run tests before it
   was caught). Verify with the gate, not by hand: `zig build check-dark-tests
   -Ddark-module=<name>` (or `scripts/dark-tests.sh <name>`) requires the declared count to
   EQUAL the `(N total)` field of the run-test summary line. `scripts/test.sh` runs the same
   check over every module, reading the `--summary all` output its own suite already
   produced. Do not reconstruct this by hand: the obvious `cat modules/<m>/src/*.zig | grep
   -c '^\s*test '` is not recursive (it misses `src/testdata/*.zig` and any other
   subdirectory the compilation does analyse) and invites comparing against the *pass* count
   rather than the total, which is exactly the bug that let `ratelimit` report `18/18 passed`
   with 3 tests dark. See `scripts/dark-tests.sh`'s header for why this must ask the compiler
   instead of matching source statically.
4. `zig build test-<name>` (per module) and `zig build test` (all) — green in **all three
   release lanes**: `-Doptimize=ReleaseSafe`, `-Doptimize=ReleaseFast`, `-Dstrict-debug`
   (§7.1 says what each one proves that the others cannot); `zig fmt --check
   modules/<name>` clean.

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
6. Fill in the `CHANGELOG.md` the template ships (a dated `New module:` entry). It is
   required from the module's first commit and `zig build check-changelog` fails without it
   (§8). Nothing needs adding to the root `CHANGELOG.md`: it carries no per-module index
   (removed 2026-08-14, §8).

7. If either trigger in §7.2 fires — 25 or more `pub fn`, or a public `init` plus three
   or more `self` methods — write `modules/<name>/example/main.zig` and set
   `.example = true` on the `module_list` entry. `zig build example-<name>` builds it
   alone; `zig build check-example-decls` fails if the flag and the file disagree.

`modules/_template/README.md` carries the complete step-by-step list, including the two
things this narrative does not repeat because a gate owns them: the root README catalog row
+ module count (`zig build check-catalog`) and the module's own anchor grade in its SPEC.md.

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
- **`testkit`** is the shared harness for what is genuinely duplicated (KAT hex decoding,
  golden byte-comparison, the verbose-skip convention); it is wired via `test_deps`, so it
  never reaches the module a consumer imports (§6.1). Anything that legitimately differs per
  module — netns setup, capability probing, fake clocks — stays hand-rolled locally.

### 7.2 Consumer examples — when a module must ship one

A module's own tests live inside the module. They therefore cannot notice the one class
of defect that only shows up at the import boundary: a type needed to call the API that
the root never re-exports, an error nobody outside can name, a config default that does
not work, memory handed to a caller with no way to release it. Nothing in a green test
run says the published API is *sufficient*.

`modules/<name>/example/main.zig` is that missing consumer, and `zig build check-examples`
compiles it against the **published** module — declared `deps` only, no `test_deps`, no
private declarations. `zig build example-<name>` builds one on its own.
`zig build check-example-decls` keeps the tree and `module_list`'s `.example` flags in
agreement in both directions, **and fails a module that is over either trigger below and
has no example at all** — otherwise the scope below would be a list picked by hand once,
and the next module to cross the threshold would cross it silently.

**A module ships an example when either trigger fires:**

* **Size — 25 or more `pub fn`.** Past that, the surface has an assembly order, and
  assembly order is what an outside caller gets wrong first. Every defect this gate has
  found so far was in a module over the threshold.
* **State — a public `init` plus three or more methods on `self`.** Here the sequence of
  calls *is* the API, however few functions there are, and a test that drives the sequence
  from inside proves nothing about whether an outsider can.

**Deliberately not a trigger: "the module allocates."** It fires on roughly half the
collection, and the ownership contract it worries about is already provable from inside
with `std.testing.allocator`. What is *not* provable from inside is a leak masked by an
arena — a module whose own tests allocate from an `ArenaAllocator` cannot distinguish a
function that frees its scratch from one that does not. That is a test-allocator problem,
not an example problem; an example is an expensive way to reach it.

**Equally not a trigger: "another module in this collection already imports it."** That
was the original rule and it selected against complexity — it exempted the ten largest
modules here, because size and in-collection reuse correlate. This workspace ships source
to integrators it never meets; an in-repo importer is a late check on the loudest
mistakes, not a substitute for the first outside caller.

The trigger counts are textual and line-anchored (`pub fn` must start the line), so a
signature that wraps its first parameter onto the next line is undercounted. That error
is one-directional on purpose: the gate can ask for fewer examples than the rule does,
never more, and a build script that parsed Zig to do better would be a second
implementation of the language.

Write the example as the smallest *coherent* thing a real caller does — parse a real
frame, drive a handshake to completion, run the state machine through its states — not a
tour of every function. If the module allocates, allocate from `std.heap.DebugAllocator`
and panic on `.leak`, so the example is also a leak detector. Handle at least one error by
name — unless the module's public surface is genuinely infallible, which three of them
are (`ramcache`, `liveness-hyst`, `isis-dis`); there, exercise the effects instead of
inventing a failure. `modules/l2disco/example/main.zig` is the reference for register and
length.

If writing the example needs something the module does not publish, that is the finding:
fix the module, do not reach around the boundary.

### 7.1 Optimize modes — what each CI lane proves

This workspace ships **source**, never a binary. The optimize mode of the artifact is
the integrator's decision, made in their build; we have no deployment to hold an
opinion about. Our modes exist purely to test, benchmark and prove the code, and each
lane proves something the others cannot:

| Lane | What it proves |
|------|----------------|
| default (Debug, heavy modules at `ReleaseSafe`) | correctness with every safety check armed, fast enough to run on each change |
| `-Dstrict-debug` | **compile only, no tests run.** That the collection *builds* in real Debug, heavy modules included — the default lane relaxes those to `ReleaseSafe` for wall-clock, so nothing else compiles them in Debug at all. It is a live question because an integrator developing against these modules builds them in Debug even though nobody ships that way. Running the tests here was measured (2026-08-15) to prove nothing the `ReleaseSafe` lane does not: Debug arms the same safety checks and merely skips optimisation, which makes it *weaker* at exposing UB; tests that run only in Debug: **0**; tests that skip in Debug: **15**, so the lane returned 48/63 where its siblings returned 63/63. If a Debug-only test is ever written, this lane has to go back to running them — that count is how you would notice |
| `-Doptimize=ReleaseFast` | the code is free of undefined behaviour that the safety checks would otherwise mask, and of anything that only holds because of them |
| `-Doptimize=ReleaseSafe` | the combination the other two never form — optimisations *and* safety checks armed. Not a formality: it is the lane that caught the only real defect of 2026-08-12 (a use-after-scope) while Debug and ReleaseFast both passed it by luck (`f88a102`). Integrators build in all three, so all three must pass |

**A note worth passing to integrators** (belongs in module docs where a parser is
exposed, not enforced here): every parser that touches bytes it did not produce is
held to a "never panic on arbitrary input" threat model, backed by **440 fuzz
harnesses across 144 modules**. Those harnesses assert that arbitrary input never trips
a safety check — an assertion that only carries meaning in a build where the checks
exist. Compiled `ReleaseFast`, the bound the fuzzer proved untripped is simply gone,
and the input that would have panicked reads out of bounds instead. So the fuzz corpus
is evidence about a Debug or `ReleaseSafe` build of the consuming binary, and says
nothing about a `ReleaseFast` one. What an integrator does with that is their call.

## 8. Versioning, releases & spin-offs

- **Dated tags, not semver.** A release = a git tag `YYYY-MM-DD` on `main`, cut by
  `scripts/tag.sh`, which refuses unless all three CI lanes — `ReleaseSafe`, `ReleaseFast`,
  `-Dstrict-debug` — are green at that commit. The tag
  asserts exactly that and nothing more: *every module passed every lane here*. There are no
  per-module version numbers and no collection-wide semantic version.
  **Why three and not four.** The default (Debug) lane was dropped because `heavy_optimize`
  in `build.zig` substitutes `ReleaseSafe` for Debug on the heavy modules, which makes every
  (module, mode) pair of the default lane a subset of the other two. It cost gate time and
  proved nothing the remaining lanes do not already cover.
  **Why not semver.** Zig resolves dependencies by URL + hash — no resolver reads a version
  string — so a semver tag carries no mechanism, only signal, and on a 225-module collection
  the signal would be false: one number cannot describe modules ranging from externally
  anchored to never consumed. It is also uninformative in the direction semver exists for.
  A consumer using three modules learns nothing from "the collection went 2.0"; a major bump
  tells them "something, somewhere, broke" and they must read the changelog anyway. So the
  per-module changelog below does not supplement a collection version — it replaces it.
  Same-day re-tags get `.1`, `.2`, … so names stay sortable and never collide. `v0.1.0`
  remains as history; nothing after it is a semantic version.
- **A tag is not a GitHub Release, and that is deliberate.** They are separate objects: a
  tag is git, a Release is a GitHub record someone creates explicitly. Nothing here creates
  one — `tag.sh` pushes a tag, and CI holds `contents: read` precisely so the gate cannot
  publish anything. So `v0.1.0` has a Release and no dated tag does, which looks like an
  omission and is not: **Releases are cut BY HAND over selected tags** (owner's decision,
  2026-08-15). A dated tag says "every module passed every lane at this commit" and is cut
  whenever that becomes true, several times a day when the day goes badly; a Release is an
  announcement, and announcing every green matrix would make the announcement worthless.
  Automating it would also mean handing the gate `contents: write`, which trades the whole
  point of least privilege for a convenience nobody asked for.
- **CHANGELOG per module.** **Every module in `module_list` has a
  `modules/<name>/CHANGELOG.md`** — not only the ones with a code change to record. A module
  whose only history is being created still gets its dated `New module:` entry, so per-module
  maturity is answerable from the module itself; `modules/_template/CHANGELOG.md` is the
  skeleton, and a module without one fails `zig build check-changelog`. Within the file, a
  change to behaviour or API is recorded newest first, each entry naming the tag it shipped in
  and flagging breaking changes **BREAKING**. Routine internal refactors need no entry. The root
  `CHANGELOG.md` stays as the per-release index — which modules a tag touched — and does not
  restate the detail. A consumer of three modules should be able to answer "what changed for
  me" by reading three files, not by scanning every release section of one.
- **The root file carries no per-module index** (removed 2026-08-14). It used to: one pointer
  bullet per module, 225 of them, 437 of the file's 503 lines, each a link plus a one-line
  summary and some tagged `BREAKING`. It is gone, and so are the two gate checks that existed
  only to police it — index membership, and the `BREAKING` mirror.
  **Why.** Once *every* module has a changelog, "which modules have one" is answered by the
  premise and the list adds nothing; and a summary that restates its own target is a copy, not
  an index. That was checked before deleting rather than assumed: all 225 bullets were compared
  against the file each pointed at, and all 225 were derivable — including every one of the 128
  finding-counts they asserted (125 stated verbatim in the target, 3 countable from its entries)
  and every specific figure (`isis-flood`'s 256, `netconf`'s 159s→0.015s, `bacnet`'s ~15 sites).
  Zero contradictions, so nothing was lost.
  **The one thing the index alone carried** was which modules have a **BREAKING** change
  pending — not derivable without opening 225 files. Dropping it is deliberate, on three
  grounds. `## Unreleased` is by definition not released, so the *consumer* the index was
  justified by never reads it; the mirror served a maintainer during the pending window. For
  that maintainer it is dominated by asking the tree — `rg -l '\*\*BREAKING' modules/*/CHANGELOG.md`
  returned exactly the 12 modules the index tagged at the moment of removal, with no second
  place to keep in sync (it over-reports once a tag is cut and the tag section keeps its
  `BREAKING` text, so narrow it to the `## Unreleased` section then). And a check whose only
  subject is a copy is a closed loop: 12 duplicated lines kept so one check can notice those
  12 lines went stale. **Deleting the copy deletes the drift, and the check with it** — which
  is the opposite of fail-open, since there is no longer a claim that can be silently wrong.
  A half-kept index with a half-kept gate would have been the fail-open shape; that is why the
  choice was all or nothing. `BEHAVIOURAL, not breaking` remains a **third** classification and
  not a synonym for either — `cors`, `ratelimit`, `router` and `throttle` carry it — and that
  distinction now lives only in the module changelogs, which is where it was always decided.
- **Every entry carries the date it landed.** The form is exactly

  ```
  - **YYYY-MM-DD** — the entry text…
  ```

  on the top-level bullet; continuation paragraphs and nested bullets belong to the entry
  above and carry nothing. The date is `20YY-MM-DD` — the same shape `scripts/tag.sh`
  accepts for a tag name, so there is one date format in this repo and not two. Any bold
  tag (`**BREAKING:**`, `**BEHAVIOURAL, not breaking**`) goes *after* the date, never
  instead of it.

  **It is the day the change landed on `main`, not the day the entry was typed**, and it
  comes out of git — `git log -S` on a distinctive phrase of the entry — never out of
  memory. A wrong date is worse than none, because it looks authoritative. An entry written
  alongside its change makes the two the same day and needs no archaeology; only a backfill
  has to go looking. An entry whose landing genuinely cannot be pinned takes the date of the
  commit that records it, which always exists — so there is no "undated" spelling and the
  gate accepts none.

  **Why a per-entry date at all, given that a tag already dates a release.** The tag answers
  "when did this ship", and only once it exists; until then the section is `Unreleased` and
  the file cannot say when anything happened. The two facts also stay distinct after a tag
  is cut — the section heading says when it shipped, the bullet says when it landed, and a
  release here spans weeks (the first retrofit covered 2026-07-18 to 2026-08-13 under one
  `Unreleased`), so one release date cannot stand in for the entries beneath it.

  **No commit hash.** It rots — the spin-off procedure below prescribes `git filter-repo`,
  which rewrites every hash of the extracted module — and a module CHANGELOG is
  consumer-facing (§5), where a hash serves a reader who already has the clone and can find
  the commit from the entry's own wording anyway. Hashes belong in commit messages and in
  SPEC.md, where rot is cheap. **The root file carries no per-entry dates either**: the date is
  owned by the module changelog, and the root file dates *tags*, not the entries beneath them.
- **The per-module changelog is enforced**: `zig build check-changelog` (run by
  `scripts/test.sh` in both the `all` and `changed` lanes, so CI runs it) fails when a module
  in `module_list` has no `CHANGELOG.md` at all, when the file at that path **is not a
  changelog** — its first line must be a `# ` title naming the module and it must have an
  `## Unreleased` heading — when a `modules/<name>/CHANGELOG.md` has an entry with a missing
  or malformed date, or when a module-changelog link in the root `CHANGELOG.md` points at a
  file that does not exist. The first two were themselves holes, both closed on 2026-08-13 and
  each measured rather than assumed. The loop read each module changelog with "skip if
  unreadable", so a module with no changelog was skipped along with every claim about it, and
  the state a new module arrives in — no file, and (then) no index bullet — passed. The fix
  left the same reflex one layer in: truncating a module changelog to **zero bytes** still
  passed, because an empty file has no entries to date, no `## Unreleased` to compare, and its
  index link still resolved. "Exists" and "is a changelog" are different facts, and a
  placeholder that satisfies only the first reads to a consumer as a fully documented module.
  Note that with the index gone, the existence check is now the **only** thing behind "every
  module has a changelog" — there is no dangling-link path that would catch a deleted file by
  accident. Neither rule demands an ENTRY under `## Unreleased`: once a tag is cut that section
  legitimately stands empty, and a gate that then asked for a bullet would be asking modules
  to invent one. `modules/_template/` is not in `module_list` and is deliberately outside the
  requirement — which is also why the title rule is "names the module" and not the exact
  `# <name> — changelog` that all 225 happen to use: the template writes it with backticks,
  and a gate that failed the skeleton it tells you to copy is a gate that gets deleted.
  The date check covers **every** `## ` section,
  not just `## Unreleased` — a rule that stopped applying the moment a tag was cut would be
  a gate switching itself off, and dating an entry is a fact about the past, so a frozen
  release section never needs editing to stay green. The link check **matches nothing today**,
  since the root file carries no module link at all once the index is removed; it is kept
  because its subject is the root file's links rather than the index, and the first dated tag
  section — which names the modules that tag touched — reintroduces them, where a typo'd module
  name is exactly what it catches. A check that currently matches nothing makes no claim that
  can be silently false, which is what separates it from the index checks it outlived.
  The module-count sentence in the root prose is deliberately NOT checked: `check-catalog`
  already owns that fact against `module_list.len` in the README, and the sentence is release
  notes that freeze when a tag is cut. See `checkChangelog` in `build.zig` for the full
  calibration and for what a green run does not prove.
- **Maturity = explicit caveats, not tier labels.** Every module meets the same bar (§6/§7:
  tests green in all three release lanes — `ReleaseSafe`, `ReleaseFast`, `-Dstrict-debug` —
  plus oracle/KAT verification where one exists). What varies
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
