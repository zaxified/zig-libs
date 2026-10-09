# zig-libs

[![CI](https://github.com/zaxified/zig-libs/actions/workflows/ci.yml/badge.svg)](https://github.com/zaxified/zig-libs/actions/workflows/ci.yml)

A curated collection of **foundational Zig modules** — performance-minded, universal where
possible, and built against something that already exists: a published specification, a set of
released test vectors, or a proven implementation in another language, rather than invented from
scratch. Which of those a module was built against is stated in its own README's `Provenance:`
line, and they are not interchangeable — many modules here are clean-room from a spec and studied
no third-party implementation at all.

Not a dumping ground: ship **solid, not many**. Every member is a foundational,
cross-project-reusable capability — a production-grade implementation of a protocol/format/algorithm,
or a fill for a genuine gap in the Zig ecosystem. zig-libs is the canonical home for these; the
authors' other projects depend on it, not the reverse.

**Status:** 244 modules (Zig 0.16, tests green in `ReleaseSafe` and `ReleaseFast`)
· **MIT** (see `LICENSE`). `NOTICE` answers one question —
whether consuming zig-libs obliges you to anything beyond MIT — and lists the modules that
carry their own attribution; it does not catalogue provenance.

> ### ⚠ Written by an AI agent. Read this before a sensitive deployment.
>
> Every module here was implemented by an LLM agent working under human direction, then
> reviewed, tested and audited the same way. That is worth knowing because the failure
> mode differs from human code: it is fluent, it is consistent, and it is confident in
> exactly the places it is wrong. Several defects found here had passed a green suite for
> weeks — a guard compiled out in `ReleaseFast`, a test asserting the shape of the bug it
> was meant to catch, a public entry point no non-test consumer could compile.
>
> **What has been done about it**, so you can judge rather than take a word for it:
> tests run in three release modes; mutation audits across the collection ask whether each
> test would actually go red; constant-time claims are machine-checked where a row in
> `scripts/checks/ctgrind-expected.tsv` says so; `zig build check-fuzz` requires a fuzz harness on
> every module that parses foreign bytes; `zig build check-portable` cross-compiles every
> module for each target it declares beyond 64-bit Linux (32-bit big-endian Linux, Windows,
> wasm32 — see "Portability" below), which no CI lane runs natively; and each module's
> `SPEC.md` carries an
> **anchor grade** saying where its expected values come from — `EXTERNAL` (published
> vectors, bytes captured from a foreign implementation, or a live foreign peer) down to
> `SELF` (we wrote them from our own reading of the spec).
>
> **What that still cannot tell you.** A green gate means nothing contradicted the code, not
> that the code is right; a grade of `EXTERNAL` on one path says nothing about the others,
> which is what `MIXED` is for. **Nothing here has been through third-party review or a
> security audit.** If you are putting a module in front of untrusted input or in anything
> safety- or money-critical, read that module's `SPEC.md` first — start with its maturity
> card and anchor grade, its constant-time section and its "deliberately not done" list — and review the
> code yourself. The documentation is written to make that possible, including where it
> says the evidence is weak.

## Using a module

Three ways to declare the dependency, and a fourth that overrides whichever you picked. The
`build.zig` half is identical for all of them.

**1. Local path** — developing against an unpushed checkout. Relative, so the manifest
carries no home-dir path:

```zig
// build.zig.zon
.zig_libs = .{ .path = "../zig-libs" },
```

**2. Fetch, unpinned** — `zig fetch` writes the entry for you, resolving the default branch
to whatever it points at today:

```
zig fetch --save git+https://github.com/zaxified/zig-libs
```

```zig
// build.zig.zon — what --save leaves behind
.zig_libs = .{
    .url = "git+https://github.com/zaxified/zig-libs#<resolved-commit>",
    .hash = "zig_libs-0.0.0-<content-hash>",
},
```

**3. Fetch, pinned to a release** — what every consumer here uses. `?ref=` records *which*
tag was meant, the `#` fragment is the commit it stood for:

```
zig fetch --save "git+https://github.com/zaxified/zig-libs?ref=2026-08-15#84332afefbbc22f2e6254ee9412cd5e9f91f27fd"
```

```zig
// build.zig.zon
.zig_libs = .{
    .url = "git+https://github.com/zaxified/zig-libs?ref=2026-08-15#84332afefbbc22f2e6254ee9412cd5e9f91f27fd",
    .hash = "zig_libs-0.0.0-WiQ0Gkuq3gJ9oVeW_X5KH_WCwedy4T3uXFl5-DAcgr3J",
},
```

Pin a tag or commit, never a branch.

⚠ **`?ref=` is an annotation, not a pin.** Zig's fetcher ignores the query string entirely
and reads only the `#` fragment. Measured 2026-09-17 against this repo: `?ref=2026-09-02`,
`?ref=no-such-ref-xyz`, and no ref at all all resolve to the *same* thing — the tip of the
default branch — and none of them errors. Only `#2026-09-02` resolves to the tag, and a
fragment naming nothing (`#no-such-ref-xyz`) fails loudly with *ref not found*. The tag name
in the query is there for the next human to read; drop the fragment while keeping it and you
get an untagged commit that looks pinned. (`?ref=` is a Nix flake convention. It is easy to
reach for, and it fails silently here.)

Two things are enforced mechanically, and neither is the one that sounds most reassuring:

- **The url must carry a fragment** — `?ref=2026-09-02` with no `#` is rejected (*url field
  is missing an explicit ref*). But `?ref=main` is rejected for exactly the same reason: the
  check asks whether a fragment exists, not whether the ref names a tag. A branch in the
  **fragment** (`#main`) is accepted without complaint.
- **A url naming a commit must carry a `hash`** (*dependency is missing hash field*).

So the `hash` is what actually holds the pin. It is content-addressed, which means a ref that
moves under you fails the build rather than silently changing it — that, not the ref syntax,
is why there is no floating "latest" to opt into. Upstream movement can only arrive as a
deliberate re-run of the command above, which is what makes a bump reviewable.
`CHANGELOG.md` says what each release changed.

**4. `--fork`, on top of any of the above** — build against a live checkout without touching
the manifest. Useful when you are changing a module and its consumer together, and the
honest alternative to editing a pinned entry down to a `.path` and remembering to put it
back:

```
zig build --fork=../zig-libs
→ info: fork ../zig-libs matched 1 zig_libs packages
```

It overrides every package matching that project across the whole dependency tree, so a
module reached only transitively is covered too. The manifest stays pinned and reproducible;
the override lives in the command that asked for it.

Then, in `build.zig`, whichever declaration you chose:

```zig
const libs = b.dependency("zig_libs", .{ .target = target, .optimize = optimize });
exe.root_module.addImport("http", libs.module("http"));
exe.root_module.addImport("jwt", libs.module("jwt"));
```

Two things that bite if skipped:

- **Pass `.target` and `.optimize` through.** The modules are declared with this build's own
  `standardTargetOptions`/`standardOptimizeOption`, so an empty `.{}` resolves them against
  *this* package's defaults instead of yours.
- **Resolve the dependency once** and hand the same module object to everyone who needs it.
  Two `dependency()` graphs make one module's types two incompatible types — and this bites
  transitively: a module that imports a sibling (`tz` imports `datefmt`) resolves that
  sibling within its own graph, so a consumer wanting both must take both from the one
  handle or end up with two date cores.

`zig fetch` can't target a subdirectory (ziglang/zig#23012), so the whole collection is one
package however you declare it. You still import only the modules you name; the rest are
never compiled.

## Build

```
scripts/test.sh          # the gate — every module not yet proven at its current content
scripts/test.sh all      # every check and every module, ignoring what is proven
zig build test           # run all module tests
zig build test-<name>    # run one module's tests
zig build check-catalog  # verify build.zig's module_list ↔ modules/ ↔ this README agree
zig build check-changelog # verify every module has a dated, well-formed CHANGELOG.md
zig build check-portable  # verify every meta.targets claim against scripts/checks/portable-known-failures.tsv
zig build check-portable-table # verify the README "Portability" table matches meta.targets + the baseline
zig build gen-portable-table   # regenerate that table (run after changing a module's meta.targets)
```

`scripts/test.sh` is the entry point for contributors: `scripts/test.sh changed` runs each
module that has no green stamp at its current fingerprint (its own sources, its dependencies,
the build machinery) together with the `check-*` gates the change can affect, and a change to
the harness itself adds every check plus a smoke run. See `scripts/README.md`, "Which modules
run: stamps". Reach for `zig build test` when you actually want everything regardless of what
changed.

`zig build -l` lists the rest, including the other `check-*` gates.

## Versioning & stability

Releases are dated git tags (`YYYY-MM-DD`), **not** semantic versions, and there are no
per-module versions; a tag asserts exactly one thing, that every module cleared every lane at
that commit. `scripts/tag.sh` cuts one, on the owner's word and over a green full matrix,
and every tag gets a GitHub Release. `v0.1.0` remains as history and is not a version
anything after it follows; dated releases exist, so pin the newest one that suits you
(`git tag`, or the tags page) rather than a bare commit. Detail
lives in `modules/<name>/CHANGELOG.md` with breaking changes flagged `BREAKING`;
`zig build check-changelog` enforces that every module has one and that it is dated and
well-formed. The root `CHANGELOG.md` carries the release policy and per-release notes — it
stopped indexing which modules have a changelog on 2026-08-14, since all of them do and the
index was a copy kept only so a gate could notice the copy had gone stale. Module maturity is carried
by the **grade** in the catalog below (see [Module grades](#module-grades)), computed from each
module's `## Maturity` card, and by the explicit caveat lines beside it — every module meets the
same floor (tests green in both test lanes — `ReleaseSafe` and `ReleaseFast`; plus
oracle/KAT verification where one exists); what varies above it is scope, evidence, audit, hardening and
performance, and the card says which. The full versioning + spin-off policy is `CONVENTIONS.md` §8.

## Layout & conventions

```
build.zig      # single root build — registers every module by name + a test step each
build.zig.zon  # one package manifest for the whole collection
CHANGELOG.md   # per-release changes, grouped by module
CONVENTIONS.md # naming + `meta` tag vocabulary + provenance/SPDX + versioning rules
SURVEY-PLAYBOOK.md # how a module is surveyed against other implementations before it ships an example
modules/<name>/src/root.zig  # `// SPDX-License-Identifier: MIT`, `pub const meta`, API, tests
modules/<name>/README.md     # what it is + a Provenance line
modules/<name>/SPEC.md       # wire format, limits, anchoring, what is deliberately not done
modules/<name>/CHANGELOG.md  # dated entries, breaking changes flagged
modules/<name>/NOTICE        # only when something is attributed or a provenance argument is needed
```

`CONVENTIONS.md` has the full rules; `modules/_template/` is the starting point for a new module.
What a module still owes is in its own `SPEC.md`, under "What is deliberately not done".

## Licensing

zig-libs is MIT. Using or redistributing it requires nothing beyond the MIT license's own terms.

Detailed provenance — third-party origin, design references and any upstream license notices — is
recorded with each module that has any, not at the repository root.

## Modules

### Module grades

Every catalog row carries a **grade on the school scale, 1 (best) to 5 (do not consume yet)**,
so you can tell at a glance whether a module is ready for production or still being filled in
(scale revised 2026-10-07 — every module was re-graded, most went down one step):

| Grade | Means | In production? |
|:-:|---|---|
| **1** | **Ahead of the competition**: parity, plus a measured lead — faster than the fastest implementation in the field, a defect in the reference our oracle found, or a feature users notice the reference lacks. | yes |
| **2** | **Parity** with the reference implementation: nothing a user would notice is missing. | yes |
| **3** | **Core**: the main use cases; the known gaps are listed in its `SPEC.md`. | yes, mind the listed gaps |
| **4** | **MVP**: the happy path works, gaps a user will hit. | no |
| **5** | A **proof of concept**, or a **known open defect** — finish or fix it before anything consumes it. | no |
| **`?`** | *Provisional*: the module has not been surveyed against other implementations, or the survey is over a year old, so the number is an upper bound — the survey can lower it, never raise it. |  |

The number is the **worst** of five axes recorded in the `## Maturity` card at the top of each
module's `SPEC.md`, and the card prints all of them as a profile, e.g. `S2 E1 A1 H1 P2`:

| Axis | 1 | 2 | 3 | 4 | 5 |
|---|---|---|---|---|---|
| **S** scope | ahead (lead ≤ 180 days old) | parity | core | mvp | poc |
| **E** evidence | external oracle, run live (`tools/interop.zig`) | external, frozen vectors | mixed | re-derived | self |
| **A** audit | review + mutation run, clean score, over the current source | both, but the source changed since or unscored | only one | none | |
| **H** hardening | fuzz driver and ctgrind runs recorded where they apply | | partly | none | |
| **P** performance | ≤ 1× the reference and ≤ 1.25× the fastest in the field | ≤ 1× the reference | ≤ 2×, or not measured | > 2× slower | |

A known open defect sets the grade to 5 whatever the axes say. For modules with no outside truth
(internal algorithms, class C/D) the evidence axis asks what the tests are checked against
instead: an independent reference model compared by fuzzing (1), a model or invariant (2), or
hand-computed values (3). The catalog cell shows the grade and, in brackets, the axes that cap
it — `3 (S,P)` is core, and also not yet measured for speed.

The grade is not chosen, it is computed: the rule is `maturityGrade` in `build.zig`;
`zig build gen-catalog` writes the card's Grade line and this column from the same computation,
and `zig build check-catalog-table` fails when either is stale — and when a module that a project
outside this repository depends on grades 4 or 5. `zig build maturity-report` lists every module
worst first, with its profile and whether its audit still matches its source.

<!-- BEGIN GENERATED: check-libs-table (source: build.zig module_list `.libs`; regenerate with `zig build gen-libs-table`; do not hand-edit) -->
### Libraries

`zig-libs` is a plural: a **lib** is one of the six groupings below, and every
module is filed in exactly one of them — the section its catalog row is printed
under. A module may additionally be tagged into libraries it is worth reaching
for from, which is what the last column lists: if you are building on `net`,
those crypto and format modules are yours too without going looking.

| Library | Filed here | Also worth reaching for from here (own library in brackets) |
|---|---:|---|
| `web` | 35 | [`netaddr`](modules/netaddr/README.md) (net) · [`zstd`](modules/zstd/README.md) (format) · [`entropy`](modules/entropy/README.md) (crypto) · [`rsa`](modules/rsa/README.md) (crypto) · [`regex`](modules/regex/README.md) (format) · [`protobuf`](modules/protobuf/README.md) (format) · [`p256`](modules/p256/README.md) (crypto) |
| `net` | 75 | [`http`](modules/http/README.md) (web) · [`ramcache`](modules/ramcache/README.md) (storage) · [`resilience`](modules/resilience/README.md) (web) · [`kvtree`](modules/kvtree/README.md) (storage) · [`rsa`](modules/rsa/README.md) (crypto) · [`xml`](modules/xml/README.md) (web) · [`x509`](modules/x509/README.md) (crypto) · [`tlsclient`](modules/tlsclient/README.md) (crypto) · [`sphinx`](modules/sphinx/README.md) (crypto) · [`aesgcm`](modules/aesgcm/README.md) (crypto) |
| `storage` | 15 | [`zstd`](modules/zstd/README.md) (format) · [`crc32`](modules/crc32/README.md) (format) · [`crc32c`](modules/crc32c/README.md) (format) · [`hashdigest`](modules/hashdigest/README.md) (crypto) |
| `crypto` | 81 | [`http`](modules/http/README.md) (web) · [`aescbc`](modules/aescbc/README.md) (web) |
| `format` | 25 | [`http`](modules/http/README.md) (web) · [`decimal`](modules/decimal/README.md) (storage) |
| `os` | 13 | [`framing`](modules/framing/README.md) (format) |
<!-- END GENERATED: check-libs-table -->


Every module is imported by its `name` (`@import("http")`); hyphenated names work too
(`@import("security-headers")`). `Deps` are sibling modules; everything else is `std`-only.

<!-- BEGIN GENERATED: check-portable-table (source: build.zig; regenerate with `zig build gen-portable-table`; do not hand-edit) -->
### Portability — claimed vs. verified

Every one of the 244 modules above claims `.linux64` (Linux, amd64 or arm64) — the collection's mandatory baseline (CONVENTIONS.md §4), and the one target actually **run**, not merely compiled: the CI matrix executes every module's tests in `ReleaseSafe` and `ReleaseFast`, plus a separate arm64 lane. That claim is not repeated below for all 244 modules — a linux64-only module has nothing further to show here.

40 of them additionally claim a cross-compile target in `meta.targets` (CONVENTIONS.md §4). `zig build check-portable` *compiles* (never runs — none of these targets has a host to run on here) each declared pair TWICE — the test binary, and a second root that takes a reference to every non-generic public declaration, because Zig analyses a body only when something references it and a `pub fn` no test reaches would otherwise never meet this target at all — and checks the result against [`scripts/checks/portable-known-failures.tsv`](scripts/checks/portable-known-failures.tsv): of 43 declared pairs, 42 currently compile clean and 1 are known-failing, tracked there with the real compiler error rather than silently dropped.

**A blank cell means the module never claimed that target.** That is a different fact from a `known-failing` cell next to it — one is an absent claim, the other is a claim currently broken and tracked — and this table exists so the two are never shown as the same thing.

**A row states that the module's tests and its whole public surface compile for that target. It does not state that a binary containing the module links for it.** Link-time reach limits are a property of the consuming binary's total text size, not of any single module: on 32-bit MIPS a branch's `PC16` fixup reaches ±128 KB, and a large enough consumer overruns it no matter which modules it picked. What that looks like, and what to do about it, is under *Consumer gotchas* below.

| Module | linux32 | windows | wasm32 |
|---|---|---|---|
| `blobmsg` | compiles | — | — |
| `brotli` | compiles | compiles | — |
| `conntrack` | compiles | — | — |
| `csvstream` | — | compiles | — |
| `datefmt` | — | compiles | — |
| `decimal` | — | compiles | — |
| `diagnostics` | — | compiles | — |
| `diskfree` | compiles | — | — |
| `diskusage` | compiles | — | — |
| `dns` | compiles | — | — |
| `encoding` | — | compiles | — |
| `framing` | compiles | — | — |
| `hashdigest` | compiles | — | — |
| `icmp` | compiles | — | — |
| `json5` | — | compiles | — |
| `l2disco` | compiles | — | — |
| `mcp` | — | compiles | — |
| `minisign` | — | compiles | — |
| `mqtt` | compiles | — | — |
| `netlink` | compiles | — | — |
| `nl80211` | compiles | — | — |
| `numparse` | — | compiles | — |
| `pathmtu` | compiles | — | — |
| `probe` | compiles | — | — |
| `procnet` | compiles | — | — |
| `procrun` | — | compiles | — |
| `qr` | — | — | compiles |
| `qrscan` | — | — | compiles |
| `rawsock` | compiles | — | — |
| `reconcilable` | — | compiles | compiles |
| `sealedbox` | compiles | — | — |
| `sntp` | compiles | — | — |
| `stun` | compiles | — | — |
| `tar` | compiles | — | — |
| `traceroute` | compiles | — | — |
| `tz` | — | compiles | — |
| `uci` | compiles | — | — |
| `wireguard` | known-failing | — | — |
| `zipstream` | — | compiles | — |
| `zstd` | compiles | compiles | — |

<!-- END GENERATED: check-portable-table -->

### Consumer gotchas

Failures that are not a defect in any module, and whose error message does not say so.

**`out of range PC16 fixup` when cross-building for 32-bit MIPS.** Seen on
`mips-linux-musl` with `-Dcpu=mips32,soft_float` in `ReleaseSmall`: a large function that
inlines many call-site bodies grows past the ±128 KB reach of a MIPS `PC16` branch fixup,
and the link fails. The message names no symbol, no module and no file, so the natural
first suspect is whichever module was added last — but the threshold belongs to the
binary's total text size, and adding *any* code can cross it. The fix is on the consumer
side: mark the inlined leaf bodies `noinline`, at the cost of one call each. Neither
`mips32r2` nor `ReleaseSafe` reproduces it, so comparing against either one is the quickest
way to recognise it.

### Web / HTTP & API — an internet-facing service, no reverse proxy required

| Module | [Grade](#module-grades) | What it does | Platform | Deps |
|---|:-:|---|---|---|
| [`aaa-gate`](modules/aaa-gate/README.md) | 3 (S,E,H,P) | Bearer + API-key auth (constant-time) + audit hook + denied-request throttle | any | router, http |
| [`abuseguard`](modules/abuseguard/README.md) | 3 (S,E,P) | Per-IP + global connection caps, ban/greylist, strike→ban (accept-time) | posix | http, netaddr, router |
| [`accesslog`](modules/accesslog/README.md) | 3 (S,P) | Structured HTTP access-log formatter — JSON Lines/logfmt/Apache Combined with log-injection escaping (untrusted UA/path/referer can't forge a line); http-request→Entry bridge; thread-safe group-commit `Sink` for one shared log file | any | http |
| [`acme`](modules/acme/README.md) | 3 (S,H,P) | Let's Encrypt / ACME v2 (RFC 8555) — HTTP-01, TLS-ALPN-01 and DNS-01 (wildcard) issuance + renewal, ES256 JWS, CSR | any | http, router, entropy, p256 |
| [`aescbc`](modules/aescbc/README.md) | 3 (S,H,P) | Raw AES-CBC (NIST SP800-38A) + PKCS#7/XML-Enc padding helpers, zero-alloc; padding-oracle caveat — consumers own authenticate-before-unpad | any | — |
| [`aeskw`](modules/aeskw/README.md) | 3 (S,H,P) | RFC 3394 AES Key Wrap (AES-128/256 KEK) — constant-time integrity check + scratch zeroization, byte-exact vs RFC 3394 test vectors | any | — |
| [`brotli`](modules/brotli/README.md) | 3 (S,P) | Pure-Zig Brotli (RFC 7932) — byte-exact decompressor + a compressing encoder (LZ77 + Huffman, ~2.8x on text); the `Content-Encoding: br` companion to std gzip | any | — |
| [`cors`](modules/cors/README.md) | 3 (S,P) | CORS preflight + header injection (secure defaults) | any | router, http |
| [`grpc`](modules/grpc/README.md) | 4 (S) | gRPC client **and** server over HTTP/2 (over `protobuf`) — no code generation; all four call shapes (unary/streaming/bidi); untrusted declared length never sizes an allocation | any | http, protobuf |
| [`health`](modules/health/README.md) | 3 (S,E,P) | Liveness (`/healthz`) + readiness (`/readyz`) probe middleware — 200/503 from registered dependency checks (k8s probe contract) | any | router, http |
| [`http`](modules/http/README.md) | 3 (S,P) | HTTP/1.1 client **and** server, hardened for direct exposure (slowloris caps, gzip, multipart, Range, negotiation); also speaks HTTP/2 (h2c/h2 client+server). Not `std.http`. | any | netaddr, datefmt, tlsclient, crc32 |
| [`idempotency`](modules/idempotency/README.md) | 3 (S,E,P) | Idempotency-Key dedup of unsafe retries — middleware + ramcache-backed store replaying a cached response without re-running the handler | any | router, http, ramcache |
| [`jwe`](modules/jwe/README.md) | 3 (S,H,P) | JSON Web Encryption (RFC 7516/7518) compact serialization — RSA-OAEP/AxxxKW/ECDH-ES key management + AES-GCM/CBC-HMAC content encryption; A192* unsupported (no AES-192 in std) | any | rsa, p256, aescbc, aeskw |
| [`jwt`](modules/jwt/README.md) | 3 (S,H,P) | JWT/JWS + OIDC resource-server validator — parse/claims/verify (HS/ES/EdDSA/RSA and post-quantum ML-DSA per RFC 9964, alg-confusion-safe), JWKS-by-kid incl. kty:AKP, OIDC discovery, plus a router Bearer middleware | any | http, router, p256 |
| [`llmclient`](modules/llmclient/README.md) | 3 (S,E,H,P) | Anthropic Messages API client (buffered + streaming SSE) over `http` — no third-party SDK | any | http |
| [`metrics`](modules/metrics/README.md) | 3 (S,P) | Prometheus registry (counter/gauge/histogram) + `/metrics` + request middleware with a per-request hook (access logging: `accesslog`) | posix | router, http |
| [`openapi`](modules/openapi/README.md) | 3 (S,P) | OpenAPI 3.1 spec generated from the route table + `/openapi.json` | any | router, http |
| [`ratelimit`](modules/ratelimit/README.md) | 3 (S,P) | Token-bucket per-client rate limit → 429 + Retry-After; per-user connection-rate limit for `on_connect` | any | router, http, netaddr |
| [`rbac`](modules/rbac/README.md) | 3 (S,P) | Authorization decision engine — NIST RBAC (hierarchical + static SoD) and a depth-bounded ABAC condition-tree evaluator with structural default-deny | any | — |
| [`requestid`](modules/requestid/README.md) | 3 (S,E,P) | Request/correlation-ID middleware — adopts incoming `X-Request-Id` or generates one, echoes on response, exposed via `current()` | any | router, http |
| [`resilience`](modules/resilience/README.md) | 3 (S,E,P) | Circuit breaker + retry/backoff + timeout + bulkhead (concurrency limiter) for calling upstreams (generic) | posix | — |
| [`router`](modules/router/README.md) | 2 (S,A,P) | REST routing, go-chi/chi parity — trie matcher ({name}, in-segment, regexp, wildcard), middleware, groups/mount, host routing, 404/405 | any | http, regex |
| [`saml`](modules/saml/README.md) | 3 (S,E,H,P) | SAML 2.0 SSO **service-provider** — XSW-hardened Response verification against an IdP key, AuthnRequest builder, SP-metadata generator, IdP-metadata parser, multi-key IdP rollover; decrypts `EncryptedAssertion` via `xmlenc` | any | xmldsig, xml, xmlenc, rsa, x509, datefmt |
| [`security-headers`](modules/security-headers/README.md) | 3 (S,P) | Secure-by-default response headers (HSTS/CSP/nosniff/frame/referrer/COOP/CORP) | any | router, http |
| [`sessions`](modules/sessions/README.md) | 3 (S,E,P) | Server-side web sessions + OWASP-hardened cookies + signed double-submit CSRF middleware | any | router, http, cookies, ramcache, entropy, kv |
| [`staticfiles`](modules/staticfiles/README.md) | 3 (S,P) | Path-traversal-safe static file handler over `http` — MIME by extension, ETag/conditional 304, byte-range 206/416; symlinks not followed, dotfiles refused by default | any | http |
| [`throttle`](modules/throttle/README.md) | 3 (S,P) | Global concurrency limit + load-shedding → 503 | posix | router, http |
| [`tracecontext`](modules/tracecontext/README.md) | 3 (S,P) | W3C Trace Context — `traceparent`/`tracestate` parse + generate + propagation middleware (child span per hop) for distributed tracing | any | router, http |
| [`upstream`](modules/upstream/README.md) | 3 (S,P) | Load-balanced upstream pool + failover — round-robin/weighted/least-conn/P2C/EWMA/consistent-hash ring, add/remove/drain while serving, per-upstream breaker+bulkhead, active+passive health checks | any | resilience, probe |
| [`validate`](modules/validate/README.md) | 3 (S,P) | Request body/query/params validation → aggregated 400 (typed + schema + string-format checks) + JSON DoS caps (depth/array/field size) | any | router, http, netaddr |
| [`webhooksig`](modules/webhooksig/README.md) | 3 (S,E,H,P) | Webhook signatures: Standard Webhooks (v1 HMAC + v1a Ed25519), Stripe, Slack, GitHub-style `<prefix><hex|base64>` (SHA-1/256/512) — constant-time sign/verify, replay tolerance, key rotation, gating middleware | any | router, http |
| [`websocket`](modules/websocket/README.md) | 3 (S,P) | RFC 6455 WebSocket — handshake + frame layer (masking, fragmentation, UTF-8 validation, size caps), transport-agnostic client + server; no permessage-deflate | any | http |
| [`xml`](modules/xml/README.md) | 3 (S,E,P) | Namespace-aware, security-hardened XML 1.0 parser → C14N-ready infoset tree; DOCTYPE-reject default blocks XXE/billion-laughs/depth-bomb. Foundation for `xmldsig`/`saml` | any | — |
| [`xmldsig`](modules/xmldsig/README.md) | 3 (S,E,H,P) | XML Canonicalization (C14N) + XML-Signature **verification only** — RSA/ECDSA, algorithm allow-list (XSLT/XPath rejected); KeyInfo cert is untrusted, caller must pin trust | any | xml, rsa, p256 |
| [`xmlenc`](modules/xmlenc/README.md) | 3 (S,E,H,P) | XML-Encryption (xmlenc-core-1) **decryption only** — recovers `EncryptedAssertion` plaintext (RSA-OAEP/AES-KW key transport + AES-GCM/CBC content), decrypt-then-verify | any | xml, rsa, aescbc, aeskw |

**Also worth reaching for from `web`** — these are filed under another library (in brackets), and appear here because a consumer working in `web` has a use for them:

| Module | [Grade](#module-grades) | What it does | Platform | Deps |
|---|:-:|---|---|---|
| [`entropy`](modules/entropy/README.md) *(crypto)* | 4 (P) | Fail-closed entropy source — `fill` draws from `std.Io.randomSecure` or aborts the process; no generator, no silent degrade. **Panics on failure.** | any | — |
| [`netaddr`](modules/netaddr/README.md) *(net)* | 2 (S,A,P) | IP parse/format (RFC 5952) + RFC 6724 source/dest selection + CIDR/Prefix ops + Go netip/netipx parity (zones, AddrPort, ordering, IpRange, IpSet) | any | — |
| [`p256`](modules/p256/README.md) *(crypto)* | 3 (S,P) | asm-accelerated NIST P-256 — Solinas field, constant-time comb sign, vartime wNAF verify; bit-exact vs `std.crypto.ecc.P256` and RFC 6979. | amd64 asm + portable fallback | — |
| [`protobuf`](modules/protobuf/README.md) *(format)* | 3 (S,E,P) | Protocol Buffers wire format (proto3) codec — schema derived at comptime from Zig structs (oneof, map, well-known types incl. Any/Struct), no `.proto` compiler; untrusted-input hardened. | any | — |
| [`regex`](modules/regex/README.md) *(format)* | 2 (S,A,P) | RE2-syntax regular expressions at parity with Go regexp — linear time, comptime compile, alloc-free match | any | — |
| [`rsa`](modules/rsa/README.md) *(crypto)* | 3 (S,P) | Pure-Zig RSA (PKCS#1 v2.2, RFC 8017) — keygen, PKCS1-v1.5/PSS sign+verify, OAEP/PKCS1 encrypt+decrypt, DER/PEM/OpenSSH key parsing. | any | montint |
| [`zstd`](modules/zstd/README.md) *(format)* | 2 (S,E,A,P) | Zstandard (RFC 8878) compressor, levels 1-22 and negative levels — byte-identical to libzstd 1.5.7 `ZSTD_compress2` and `ZSTD_compressStream2`, with libzstd's advanced parameters (magicless frames, explicit window/strategy, splitters, block size, long-distance matching as `--long`, targetCBlockSize superblocks), the sequence-level API (compressSequences, generateSequences, a block-level sequence producer) and reusable contexts in one workspace of exactly estimated size, caller-provided if wanted — and a decoder ported from libzstd's, one-shot and streaming (`ZSTD_decompressStream`, a `std.Io.Reader`), checksums, concatenated and skippable frames, frame queries | any | — |

### Networking

| Module | [Grade](#module-grades) | What it does | Platform | Deps |
|---|:-:|---|---|---|
| [`bacnet`](modules/bacnet/README.md) | 4 (S) | BACnet building automation over BACnet/IP **and** BACnet/SC — BVLL/BVLC framing, core APDU services (Read/WriteProperty, WhoIs/IAm, COV), SC secure-connect over `websocket` | any | netaddr, websocket |
| [`bumtree`](modules/bumtree/README.md) | 4 (S) | SPB per-source loop-free BUM distribution tree + RPF check over `spf-ect` — per-node replication next-hops (pruned source SPT) + single RPF ingress for an I-SID member set | any | spf-ect |
| [`coap`](modules/coap/README.md) | 4 (S) | CoAP (RFC 7252) — full client **and** server stack: message codec, options (URI↔options), reliability (CON retransmission + dedup), correlated client/server. Zero-alloc | any | — |
| [`conntrack`](modules/conntrack/README.md) | 3 (S,P) | Linux ctnetlink (NETLINK_NETFILTER) client — typed conntrack flow dump/get/delete plus event subscription, over `netlink`'s write engine | **linux** | netlink, netaddr |
| [`devlink`](modules/devlink/README.md) | 4 (S) | Linux devlink over genetlink — device/port enumeration, port split/unsplit, parameter/resource inspection, region snapshots, health reporters, eswitch mode | **linux** | genetlink, netlink |
| [`df-elect`](modules/df-elect/README.md) | 4 (S) | EVPN-style Designated-Forwarder election for N-member segments (RFC 7432 mod-N, RFC 8584 HRW) with DF-wait failover + split-horizon, from a link-state flood; model-checked in netsim | any | netsim |
| [`dnp3`](modules/dnp3/README.md) | 4 (S) | DNP3 (IEEE 1815) base protocol — data-link framing + CRC-16/DNP, application layer, core object library; master + outstation. Secure Auth (g120) scaffolded only, no crypto | any | aeskw |
| [`dns`](modules/dns/README.md) | 3 (S,P) | RFC 1035 resolver — A/AAAA/PTR/CNAME/NS/MX/TXT/SOA/SRV/CAA over UDP/TCP + DoH | any | netaddr, http |
| [`dnssec`](modules/dnssec/README.md) | 3 (S,H,P) | Resolver-side DNSSEC validation (RFC 4033/4034/4035 + NSEC3) — DNSKEY/RRSIG/DS parsing, signature verify (ECDSA/Ed25519/RSA), NSEC/NSEC3 denial-of-existence | any | dns, rsa, base32 |
| [`ebpf`](modules/ebpf/README.md) | 4 (S) | eBPF program generation over `std.os.linux.bpf` — bytecode builders (kprobe counter, XDP filter, ring-buffer emitter); real-kernel verifier acceptance unverified in CI | **linux** | netlink |
| [`enip`](modules/enip/README.md) | 4 (S) | EtherNet/IP + CIP — encapsulation layer (register/SendRRData/SendUnitData), CIP messaging, connection manager, tag/symbolic path client for Logix controllers | any | netaddr |
| [`ethfrag`](modules/ethfrag/README.md) | 3 (S,E,H,P) | Hardened inner-frame fragmentation/reassembly codec — RFC 5722 overlap rejection, bounded per-datagram memory, caller-clocked timeout, fuzz-tested never-panic | any | — |
| [`ethtool`](modules/ethtool/README.md) | 3 (S,A,H,P) | Ethernet device control over the ethtool netlink family — link settings/state, ring/coalesce/pause/channel params, feature flags, per-queue/driver stats | **linux** | genetlink, netlink |
| [`fleetsim`](modules/fleetsim/README.md) | 3 (S,H,P) | In-process simulated device fleet — hosts protocol responders (Modbus, DNP3, IEC 104, S7comm, BACnet, EtherNet/IP, OPC UA) as nodes on one deterministic scheduler | any | modbus, dnp3, iec104, s7comm, bacnet, enip, opcua, netsim |
| [`genetlink`](modules/genetlink/README.md) | 3 (S,H,P) | Generic-netlink (genl) transport — genlmsghdr framing + nlctrl family-id resolution; shared foundation for ethtool/devlink/nl80211/wireguard clients | **linux** | netlink |
| [`icmp`](modules/icmp/README.md) | 2 (S,E,A) | ICMP echo (ping) engine — v4/v6 codec, batched socket, pacing | **linux** | seqmap, netaddr |
| [`iec104`](modules/iec104/README.md) | 3 (S,H,P) | IEC 60870-5-104 telecontrol — APCI/APDU framing, I/S/U formats with k/w flow control, ASDU codec, transport-agnostic master (controlling station) | any | — |
| [`iec61850`](modules/iec61850/README.md) | 3 (S,H,P) | IEC 61850 substation automation — MMS (ISO 9506) client over ISO-on-TCP with the ACSI object model, plus GOOSE publish/subscribe + SV sampled values | any | xml |
| [`iec62351`](modules/iec62351/README.md) | 3 (S,E,H,P) | IEC 62351 power-systems security — GOOSE/SV authentication (62351-6) over caller-supplied PDU bytes, MMS application authentication (62351-4), checkable TLS policy | any | x509, rsa, p256 |
| [`imap`](modules/imap/README.md) | 4 (S) | IMAP4rev2 (RFC 9051) client — mailbox-name codec, wire grammar, FETCH/ENVELOPE/BODYSTRUCTURE, SEARCH, IDLE; transport-agnostic (owns no socket, speaks no TLS) | any | — |
| [`isis`](modules/isis/README.md) | 4 (S) | IS-IS (ISO/IEC 10589) PDU codec — common header + TLV framework + IIH/LSP PDUs + SPB (802.1aq) TLVs; pure bounds-checked encode/decode, wire foundation for an SPB control plane | any | — |
| [`isis-adj`](modules/isis-adj/README.md) | 4 (S) | IS-IS point-to-point adjacency state machine (ISO 10589 §8.2 + RFC 5303) — pure time-injected FSM driving one P2P neighbour Down→Init→Up from IIH PDUs | any | isis |
| [`isis-dis`](modules/isis-dis/README.md) | 3 (S,E,P) | IS-IS LAN Designated-IS election (ISO 10589 §8.4.5) — elects DIS from priority + SNPA (tie-break, preemptive), derives the pseudonode LSP-ID; pure time-injected | any | isis |
| [`isis-flood`](modules/isis-flood/README.md) | 4 (S) | IS-IS flooding transmit scheduler — drains `isis-lsdb` SRM/SSN flags into ordered PDUs to send, paces LSP (re)transmission + periodic CSNPs; pure time-injected | any | isis, isis-lsdb |
| [`isis-lsdb`](modules/isis-lsdb/README.md) | 4 (S) | IS-IS link-state database — stores LSPs by LSP-ID, ISO 10589 §7.3 newer-LSP comparison, time-injected aging + MaxAge purge, per-interface SRM/SSN flooding flags; pure | any | isis |
| [`isis-sim`](modules/isis-sim/README.md) | 4 (S) | Headless multi-node IS-IS/SPB fabric convergence simulator over `netsim` — asserts LSDBs synchronise and reconverge after an injected link failure | any | netsim, isis, isis-lsdb, isis-flood, isis-spf, isis-dis |
| [`isis-spf`](modules/isis-spf/README.md) | 4 (S) | Computes IS-IS shortest-path forwarding table from an `isis-lsdb` — TLVs → topology graph → Dijkstra + ECT tie-break → route table (dest → next-hop + metric); pure | any | isis, isis-lsdb, spf-ect |
| [`l2disco`](modules/l2disco/README.md) | 3 (S,P) | Layer-2/neighbor discovery codec — LLDP (802.1AB) + CDP + ARP (RFC 826) + DHCP options (RFC 2131/2132) + MAC helper | any | netaddr |
| [`l2encap`](modules/l2encap/README.md) | 3 (S,H,P) | Tenant-tagged (24-bit I-SID) L2-over-tunnel encapsulation for a multi-tenant L2VPN fabric — lean versioned header over a customer Ethernet frame; bounds-checked decode | any | — |
| [`l2forward`](modules/l2forward/README.md) | 4 (S) | E-LAN edge forwarding table — per-I-SID customer-MAC learning (MAC→remote PE) with aging + BUM ingress-replication set + split-horizon; pairs with `l2encap` | any | — |
| [`latency-stats`](modules/latency-stats/README.md) | 3 (S,P) | Online RTT stats — min/max/mean/stddev + RFC 3550 jitter + loss %, O(1)/sample, no alloc; plus an HdrHistogram for bounded-error percentiles (p50–p99.9) | any | — |
| [`liveness-hyst`](modules/liveness-hyst/README.md) | 3 (S,P) | BFD-like link-liveness estimator with EWMA hysteresis — echo-probe timing + jitter/loss stats, Babel-style metric smoothing; fast detection without flap-driven oscillation | any | netsim, latency-stats |
| [`lockfree`](modules/lockfree/README.md) | 3 (S,P) | Lock-free concurrency primitives for shared-memory worker pools — generic Michael & Scott MPMC queue + Fraser/crossbeam epoch-based reclamation under a strict seq_cst discipline, a bounded allocation-free Vyukov MPMC ring, and a growable Chase-Lev work-stealing deque | any | — |
| [`loopfree-reconv`](modules/loopfree-reconv/README.md) | 4 (S) | Loop-free reconvergence transitions — two-class ordered-FIB schedule (provably no transient forwarding loop, TTL backstop); netsim-verified under fuzzing | any | netsim, spf-ect |
| [`loopix`](modules/loopix/README.md) | 3 (S,H,P) | Loopix mixnet simulator (Piotrowska et al. — Nym's design) — Poisson mixing, cover traffic, providers with mailboxes and n−1 detection in netsim, scored per mix and end to end against a global passive adversary; no real network I/O | any | netsim, sphinx |
| [`modbus`](modules/modbus/README.md) | 3 (S,A,H,P) | Modbus TCP (MBAP) + RTU (CRC-16) codec, master client **and slave server** — core function codes, diagnostics, exceptions, transport-agnostic seam | any | — |
| [`mqtt`](modules/mqtt/README.md) | 3 (S,P) | MQTT 3.1.1 + 5.0 client and broker — all control packets incl. AUTH and properties, QoS 0/1/2 both ways, sessions with expiry, shared subscriptions, transport-agnostic seam | any | — |
| [`netaddr`](modules/netaddr/README.md) | 2 (S,A,P) | IP parse/format (RFC 5952) + RFC 6724 source/dest selection + CIDR/Prefix ops + Go netip/netipx parity (zones, AddrPort, ordering, IpRange, IpSet) | any | — |
| [`netconf`](modules/netconf/README.md) | 3 (S,E,A,H,P) | NETCONF client (RFC 6241) over SSH — RFC 6242 framing, hello/capability exchange, get/get-config/edit-config/commit RPCs with typed replies | any | ssh, xml |
| [`netlink`](modules/netlink/README.md) | 3 (S,P) | rtnetlink read **and** write — dumps (links/addresses/routes/neighbors) and RTM_NEW*/DEL* writes; byte-exact vs iproute2 goldens + netns round-trip | **linux** | — |
| [`netsim`](modules/netsim/README.md) | 3 (S,P) | Deterministic seeded discrete-event network simulator (latency/loss/partition/clock-skew, failure fuzzer, byte-exact replay) — model-checking harness for fabric algorithms | any | — |
| [`nftables`](modules/nftables/README.md) | 3 (S,P) | Typed firewall-ruleset builder → libnftables JSON for `nft -j -f -` (families/chains/rules/sets, match + verdict statements) | any (apply: linux) | netlink |
| [`nl80211`](modules/nl80211/README.md) | 3 (S,P) | Wi-Fi control over nl80211 genetlink — interface/wiphy enumeration, scan trigger + BSS results, connect/disconnect, station/link stats, regulatory domain | **linux** | genetlink, netlink |
| [`opcua`](modules/opcua/README.md) | 4 (S) | OPC-UA (IEC 62541) **client and server** — opc.tcp transport, secure channel (`#None` or Basic256Sha256 at Sign/SignAndEncrypt, both client and server), sessions, Read/Write/Browse/Call + subscriptions | any | rsa, x509 |
| [`pagecache`](modules/pagecache/README.md) | 3 (S,E,P) | Bounded write-through page cache between `kvtree`'s pager and its `Storage` — hot-cold tiering (W-TinyLFU via ramcache) with an RSS budget; transparent to callers | any | kvtree, ramcache |
| [`pathmtu`](modules/pathmtu/README.md) | 3 (S,P) | Path MTU discovery — kernel-cache read (`query`) **and** an authoritative DF-bit binary search (`probe`) that detects ICMP black holes the cache can't see | **linux** | icmp, netaddr |
| [`pbb`](modules/pbb/README.md) | 3 (S,E,H,P) | IEEE 802.1ah Provider Backbone Bridge (MAC-in-MAC) codec — wraps a customer frame in a backbone header + I-TAG (24-bit I-SID); real-Ethernet SPB encap, distinct from `l2encap` | any | — |
| [`pping`](modules/pping/README.md) | 3 (S,E,H,P) | Passive RTT estimation from TCP TSval/TSecr echo matching (RFC 7323 / Pollere pping) and ICMP/ICMPv6 echo request/reply pairing — bounded per-direction table, no double-counting of duplicate ACKs or duplicate replies | any | — |
| [`probe`](modules/probe/README.md) | 3 (S,E,P) | TCP-connect reachability prober — up/refused/timeout + RTT, fan-out with bounded concurrency, latency aggregation | any | netaddr, latency-stats |
| [`procnet`](modules/procnet/README.md) | 3 (S,P) | Linux `/proc`+`/sys` parsers — ARP/routes/TCP+UDP sockets/conntrack/process stats/device health, typed | **linux** | netaddr |
| [`raft`](modules/raft/README.md) | 4 (S) | Raft consensus (Ongaro & Ousterhout) — a runnable server (`Node`: tick/step/propose → ready/advance over your transport and disk), model-checked in netsim against all five formal safety properties; no snapshots or membership changes yet | any | netsim |
| [`rawsock`](modules/rawsock/README.md) | 3 (S,E,P) | Linux AF_PACKET raw-frame capture + inject — BPF filter, promiscuous mode, typed frame decode | **linux** | netaddr |
| [`rdap`](modules/rdap/README.md) | 3 (S,E,H,P) | RDAP client (RFC 7480–7484) — JSON-over-HTTPS whois successor: query URLs, typed response model, IANA bootstrap, fetch seam | any | http, netaddr |
| [`readthrough`](modules/readthrough/README.md) | 3 (S,E,P) | Backend-agnostic read-through cache coordinator — serve-from-cache or single-flight-coalesce a miss into one backend fetch, TTL + invalidation + negative caching | any | ramcache |
| [`reconcilable`](modules/reconcilable/README.md) | 3 (S,A,P) | Generic desired-vs-actual reconciler (controller-runtime shape) — bounded, deduplicating work queue with backoff+jitter; caller-driven `tick()`, no clock or thread | any | resilience |
| [`s7comm`](modules/s7comm/README.md) | 4 (S) | Siemens S7 communication — ISO-on-TCP (RFC 1006) plus S7 protocol: connection setup, area read/write (DB/M/I/Q/T/C), PLC info and cyclic services | any | — |
| [`seqmap`](modules/seqmap/README.md) | 3 (S,E,P) | Fixed 65,536-slot 16-bit request/reply correlation map, O(1) | any | — |
| [`shardstore`](modules/shardstore/README.md) | 3 (S,P) | Key-sharding router over N independent `kvtree` stores — multi-core write parallelism (per-shard single-writer, cross-shard parallel) | any | kvtree |
| [`simio`](modules/simio/README.md) | 3 (S,P) | Deterministic std.Io for simulation testing — real std.Io code runs unchanged on fibers in virtual time, over simulated streams, datagrams and ICMP on routed faulty links, a crash-consistent disk, host crashes and a shrinking fault search | linux (x86_64, aarch64, riscv64: std.Io.fiber) | netsim |
| [`smtp`](modules/smtp/README.md) | 3 (S,A,H,P) | SMTP client (RFC 5321) — ESMTP EHLO negotiation, STARTTLS seam, AUTH PLAIN/LOGIN, pipelining, MIME message composition (RFC 5322/2045) | any | netaddr |
| [`snmp`](modules/snmp/README.md) | 3 (S,H,P) | SNMP v1/v2c/v3 — BER/ASN.1 codec, manager client (get/next/bulk/set/walk) + trap/notification receiver + USM auth (HMAC-MD5/SHA-1 and RFC 7860 SHA-224/256/384/512, constant-time) and privacy (DES-CBC, AES-128-CFB), KAT- and net-snmp-anchored | any | — |
| [`sntp`](modules/sntp/README.md) | 3 (S,P) | SNTP client (RFC 4330) — NTP packet codec + UDP query, clock offset / round-trip delay | any | — |
| [`spbfib`](modules/spbfib/README.md) | 4 (S) | SPB (802.1aq) forwarding addressing — unicast B-MAC FIB from an `isis-spf` route table + SPBM multicast-DA construction; one congruent ECT path per dest, no per-flow ECMP | any | isis-spf |
| [`spf-ect`](modules/spf-ect/README.md) | 4 (S) | Deterministic symmetric shortest-path (Dijkstra) with a reversal-invariant ECT tie-break (RFC 6329 idea generalized) + maximally-disjoint second tree; pure graph algorithm | any | — |
| [`ssh`](modules/ssh/README.md) | 3 (S,E,P) | SSH-2.0 (RFC 4253) **client + server** — KEX incl. ML-KEM-768 hybrid, rekeying + strict KEX, userauth (publickey/password/keyboard-interactive), multiplexed channels (exec/subsystem/shell/pty/env/signal) and client TCP/IP forwarding; vs OpenSSH-validated. **Linux-only** | linux | rsa, montint |
| [`stun`](modules/stun/README.md) | 3 (S,P) | STUN client (RFC 8489) — NAT reflexive-address discovery: XOR-MAPPED-ADDRESS + MESSAGE-INTEGRITY + FINGERPRINT | any | netaddr |
| [`syslog`](modules/syslog/README.md) | 3 (S,P) | RFC 5424 syslog formatter + emitter, RFC 3164 legacy encoder, RFC 6587 TCP octet framing, local delivery (unix socket, journald native protocol) | any (local delivery: linux) | datefmt |
| [`tc`](modules/tc/README.md) | 4 (S) | Traffic control over rtnetlink — qdiscs (netem/htb/tbf/fq_codel/cake), htb classes, u32/flower filters + action families; byte-exact to iproute2 (retires `tc` shell-outs) | **linux** | netlink |
| [`tcplan`](modules/tcplan/README.md) | 3 (S,E,P) | Compiles a hierarchical shaping topology (site→AP→subscriber) into a deterministic ordered plan of `tc` ops — mq root + per-CPU HTB trees + CAKE leaves; pure, caller executes | linux | tc |
| [`traceroute`](modules/traceroute/README.md) | 3 (S,P) | ICMP-echo path discovery — TTL-stepped probes, per-hop address + RTT stats, load-balanced-path aware | **linux** | icmp, netaddr, latency-stats |
| [`whois`](modules/whois/README.md) | 3 (S,E,H,P) | RFC 3912 whois client — query format + referral chasing (IANA→registrar) + field extraction, transport-agnostic seam | any | netaddr |
| [`wireguard`](modules/wireguard/README.md) | 3 (S,H,P) | Native WireGuard device config over genetlink (retires `wg` shell-outs), plus the Noise_IKpsk2 handshake **and** the transport-data seal/open crypto data plane | **linux** | netlink, genetlink, chachapoly, entropy, netaddr |
| [`workerpool`](modules/workerpool/README.md) | 3 (S,P) | In-process fixed-width worker pool over `lockfree.MpmcQueue` — type-erased closure jobs, Io-futex idle wakeup (no busy-spin, no lost-wakeup), graceful drain / abrupt shutdown | any | lockfree |
| [`writebehind`](modules/writebehind/README.md) | 4 (S) | Crash-safe write-behind cache coordinator — fast in-memory acks, async flush to a durable `Sink` via `workerpool`; WAL written before ack so a crash-recovered write survives | any | ramcache, workerpool, jobqueue, kvtree |
| [`xdp-classifier`](modules/xdp-classifier/README.md) | 3 (S,E,H,P) | XDP packet classifier for a LibreQoS-style edge shaper — IPv4/IPv6 prefix→traffic-class via LPM-trie lookup behind 0-2 VLAN tags (802.1Q/QinQ), per-CPU scratch handoff, CPUMAP steering (bpf_redirect_map) | **linux** | ebpf |

**Also worth reaching for from `net`** — these are filed under another library (in brackets), and appear here because a consumer working in `net` has a use for them:

| Module | [Grade](#module-grades) | What it does | Platform | Deps |
|---|:-:|---|---|---|
| [`aesgcm`](modules/aesgcm/README.md) *(crypto)* | 3 (S,P) | AES-GCM (AES-128/256) — stateful context caching the key schedule and GHASH powers, x86-64 AES-NI+PCLMULQDQ stitched one-pass kernel picked at run time, std fallback; std-shaped stateless API. | any (x86-64 AES-NI/PCLMULQDQ asm, run-time detected + std fallback) | — |
| [`http`](modules/http/README.md) *(web)* | 3 (S,P) | HTTP/1.1 client **and** server, hardened for direct exposure (slowloris caps, gzip, multipart, Range, negotiation); also speaks HTTP/2 (h2c/h2 client+server). Not `std.http`. | any | netaddr, datefmt, tlsclient, crc32 |
| [`kvtree`](modules/kvtree/README.md) *(storage)* | 3 (S,P) | Ordered transactional KV store — copy-on-write B-tree (LMDB/BoltDB lineage), MVCC snapshots, crash-safe range scans. | any | kv, crc32 |
| [`ramcache`](modules/ramcache/README.md) *(storage)* | 3 (S,P) | Bounded in-memory cache — W-TinyLFU admission/eviction, TTL, generation invalidation; sharded thread-safe wrapper. | any | — |
| [`resilience`](modules/resilience/README.md) *(web)* | 3 (S,E,P) | Circuit breaker + retry/backoff + timeout + bulkhead (concurrency limiter) for calling upstreams (generic) | posix | — |
| [`rsa`](modules/rsa/README.md) *(crypto)* | 3 (S,P) | Pure-Zig RSA (PKCS#1 v2.2, RFC 8017) — keygen, PKCS1-v1.5/PSS sign+verify, OAEP/PKCS1 encrypt+decrypt, DER/PEM/OpenSSH key parsing. | any | montint |
| [`sphinx`](modules/sphinx/README.md) *(crypto)* | 4 (S) | Lightning BOLT#4 Sphinx onion routing — forward ECDH blinding chain, layered packet construction, constant-time layer peeling. | any | k256 |
| [`tlsclient`](modules/tlsclient/README.md) *(crypto)* | 3 (S,H,P) | std's TLS 1.3/1.2 client with the server chain verified by RFC 5280 (x509.verifyChain) — closes ziglang/zig #35877; opt-in ALPN and TLS 1.3 client certificates, std's handshake byte for byte by default. | any | x509 |
| [`x509`](modules/x509/README.md) *(crypto)* | 3 (S,P) | X.509 certificate-chain / path validation (RFC 5280 §6) — trust-store chain building, extension, name, and signature checks, including post-quantum ML-DSA (RFC 9881) and SLH-DSA (RFC 9882) certificates, plus CRL revocation checking (RFC 5280 §6.3). | any | rsa, slhdsa |
| [`xml`](modules/xml/README.md) *(web)* | 3 (S,E,P) | Namespace-aware, security-hardened XML 1.0 parser → C14N-ready infoset tree; DOCTYPE-reject default blocks XXE/billion-laughs/depth-bomb. Foundation for `xmldsig`/`saml` | any | — |

### Data & storage

| Module | [Grade](#module-grades) | What it does | Platform | Deps |
|---|:-:|---|---|---|
| [`blobstore`](modules/blobstore/README.md) | 3 (S,E,P) | Content-addressed blob store (git-object/restic style) with refcounted GC, configurable fan-out and a cross-process ingest lock, plus name-addressed and small named-record layers; crash-safe. | posix | hashdigest |
| [`dataset`](modules/dataset/README.md) | 3 (S,P) | Canonical in-memory columnar-typed table — the normalization seam between data sources and consumers. | any | — |
| [`decimal`](modules/decimal/README.md) | 3 (S,P) | Exact i128 fixed-point decimal for money math with IEEE/GDA rounding modes and rescale — float-free arithmetic, f64 only at an explicit fromFloat/toFloat boundary. | any | — |
| [`filestore`](modules/filestore/README.md) | 3 (S,E,P) | DB-less durable keyed document store — one atomically-written file per record, plus a typed-JSON convenience layer. | posix | — |
| [`finstats`](modules/finstats/README.md) | 3 (S,E,P) | Portfolio/financial statistics over `dataset` — XIRR, TWR, risk, beta, Monte-Carlo, correlation matrix. | any | dataset |
| [`fuzzysearch`](modules/fuzzysearch/README.md) | 3 (S,H,P) | Bounded-edit-distance typo-tolerant lookup over a static string set — DoS-bounded, the typo-tolerant sibling of `trie`. | any | trie |
| [`geoindex`](modules/geoindex/README.md) | 4 (S) | Static spatial index for bbox and nearest-neighbour queries over a large fixed geo-point set — DoS-bounded, zero-copy. | any | — |
| [`jobqueue`](modules/jobqueue/README.md) | 3 (S,P) | Durable background-job queue over `kv` — lease/retry/dead-letter queue, per-partition FIFO under priority. | posix | kv |
| [`jsonshape`](modules/jsonshape/README.md) | 3 (S,E,P) | JSON → `dataset` reshaping — dot-path descent and typed column projection (a minimal jq-style subset). | any | dataset |
| [`kv`](modules/kv/README.md) | 3 (S,P) | Crash-consistent embedded KV store, Bitcask-style log, with randomized fuzz-tested crash recovery. | any | — |
| [`kvtree`](modules/kvtree/README.md) | 3 (S,P) | Ordered transactional KV store — copy-on-write B-tree (LMDB/BoltDB lineage), MVCC snapshots, crash-safe range scans. | any | kv, crc32 |
| [`ramcache`](modules/ramcache/README.md) | 3 (S,P) | Bounded in-memory cache — W-TinyLFU admission/eviction, TTL, generation invalidation; sharded thread-safe wrapper. | any | — |
| [`tabular`](modules/tabular/README.md) | 3 (S,E,P) | Dataset algebra (pandas/dplyr-style verbs) over `dataset` — aggregate/pivot/resample/rolling/join, fx-aware. | any | dataset |
| [`trie`](modules/trie/README.md) | 3 (S,P) | Prefix index for instant autocomplete over a large static string set. | any | — |
| [`tsdb`](modules/tsdb/README.md) | 3 (S,P) | Time-series persistence over `kvtree` — ordered (series, timestamp) key codec, streaming range scans, Gorilla-compressed blocks, crash-safe retention by age or size budget. | any | kvtree |

**Also worth reaching for from `storage`** — these are filed under another library (in brackets), and appear here because a consumer working in `storage` has a use for them:

| Module | [Grade](#module-grades) | What it does | Platform | Deps |
|---|:-:|---|---|---|
| [`crc32`](modules/crc32/README.md) *(format)* | 2 (S,E,A,P) | CRC-32 (IEEE: gzip/zlib/PNG) — x86-64 PCLMULQDQ folding and ARMv8 CRC instructions picked at run time, slicing-by-8 fallback; drop-in for std.hash.Crc32, streaming, extend, combine. | any (x86-64 PCLMULQDQ / arm64 CRC asm + portable fallback) | — |
| [`crc32c`](modules/crc32c/README.md) *(format)* | 2 (S,E,A,P) | CRC-32C (Castagnoli) — SSE4.2 and ARMv8 CRC instructions picked at run time (three interleaved streams), slicing-by-8 fallback; streaming, extend, combine. | any (x86-64 SSE4.2 / arm64 CRC asm + portable fallback) | — |
| [`hashdigest`](modules/hashdigest/README.md) *(crypto)* | 3 (S,E,P) | Streaming digests — one-shot, incremental, and file hashing; SHA-256 convenience plus a multi-algorithm SHA-2/SHA-3/BLAKE2b/BLAKE3 layer. | any | — |
| [`zstd`](modules/zstd/README.md) *(format)* | 2 (S,E,A,P) | Zstandard (RFC 8878) compressor, levels 1-22 and negative levels — byte-identical to libzstd 1.5.7 `ZSTD_compress2` and `ZSTD_compressStream2`, with libzstd's advanced parameters (magicless frames, explicit window/strategy, splitters, block size, long-distance matching as `--long`, targetCBlockSize superblocks), the sequence-level API (compressSequences, generateSequences, a block-level sequence producer) and reusable contexts in one workspace of exactly estimated size, caller-provided if wanted — and a decoder ported from libzstd's, one-shot and streaming (`ZSTD_decompressStream`, a `std.Io.Reader`), checksums, concatenated and skippable frames, frame queries | any | — |

### Crypto

| Module | [Grade](#module-grades) | What it does | Platform | Deps |
|---|:-:|---|---|---|
| [`adaptor`](modules/adaptor/README.md) | 3 (S,E,H,P) | Schnorr adaptor signatures over BIP340 (scriptless scripts for Lightning PTLCs / atomic swaps) — preSign, adapt, extract. | any | bip340, k256 |
| [`aeadframe`](modules/aeadframe/README.md) | 3 (S,H,P) | Per-key AEAD record layer — seal/open with a monotonic nonce (never reused), epoch rekey, anti-replay window, AAD binding. | any | chachapoly |
| [`aesgcm`](modules/aesgcm/README.md) | 3 (S,P) | AES-GCM (AES-128/256) — stateful context caching the key schedule and GHASH powers, x86-64 AES-NI+PCLMULQDQ stitched one-pass kernel picked at run time, std fallback; std-shaped stateless API. | any (x86-64 AES-NI/PCLMULQDQ asm, run-time detected + std fallback) | — |
| [`bbs`](modules/bbs/README.md) | 3 (S,H,P) | BBS selective-disclosure signatures over `bls12_381` (draft-irtf-cfrg-bbs-signatures-12) — sign many messages, later reveal a chosen subset in zero knowledge. | any | bls12_381, entropy |
| [`bech32`](modules/bech32/README.md) | 3 (S,H,P) | Bitcoin address encodings — bech32 (BIP173) / bech32m (BIP350) codec, segwit address encode/decode, base58check, P2PKH/P2WPKH. | any | ripemd160 |
| [`bfv`](modules/bfv/README.md) | 4 (S,E) | BFV leveled homomorphic encryption (Fan-Vercauteren) over `Z_q[X]/(X^N+1)`, RNS — exact-integer keygen/encrypt/decrypt/multiply/relinearize. **No security level claimed.** | any | entropy |
| [`bip32`](modules/bip32/README.md) | 3 (S,H,P) | BIP-39 mnemonic seed phrases + BIP-32 hierarchical-deterministic keys over secp256k1 — the wallet key-derivation foundation. | any | k256, ripemd160, bech32 |
| [`bip340`](modules/bip340/README.md) | 4 (P) | BIP340 Schnorr signatures over secp256k1 (Bitcoin Taproot's signature scheme) — sign, verify, batch verify, x-only keys. | any | k256 |
| [`bitcoinscript`](modules/bitcoinscript/README.md) | 3 (S,H,P) | Bitcoin Script consensus interpreter — full opcode set, CHECKSIG/CHECKMULTISIG; verifies bare/P2SH/segwit/P2TR key-path scripts. | any | bitcointx, k256, bip340, ripemd160 |
| [`bitcointx`](modules/bitcointx/README.md) | 3 (S,E,H,P) | Bitcoin transaction (de)serialization + signature hashing — legacy, BIP143 segwit-v0, and BIP341 taproot key-path sighash. | any | bip340 |
| [`blindrsa`](modules/blindrsa/README.md) | 4 (P) | RSA Blind Signatures (RFC 9474, RSABSSA) over `rsa` — the anonymous-token / Privacy Pass primitive: blind, sign, finalize, verify. | any | rsa |
| [`bls12_381`](modules/bls12_381/README.md) | 3 (S,E,H,P) | BLS12-381 pairing-friendly curve — field tower/groups, optimal-ate pairing, hash-to-curve, BLS signatures (all six draft ciphersuites, batch verification), EIP-2333 key derivation, G1/G2 MSM, KZG commitments, threshold BLS. | any | entropy, montint |
| [`bn254`](modules/bn254/README.md) | 3 (S,H,P) | BN254 / alt-bn128 curve — field tower/groups, optimal-ate pairing, EIP-196/197 EVM precompiles, and a Groth16 zkSNARK **verifier**. | any | montint |
| [`bolt3`](modules/bolt3/README.md) | 4 (S) | Lightning BOLT#3 key derivation — per-commitment blinded keys, split-secret revocation keys, shachain secret generation. | any | k256 |
| [`bolt8`](modules/bolt8/README.md) | 3 (P) | Lightning BOLT#8 encrypted transport (`Noise_XK_secp256k1_ChaChaPoly_SHA256`) — handshake plus transport with periodic key rotation. | any | noise, k256 |
| [`btcaddr`](modules/btcaddr/README.md) | 3 (S,H,P) | Bitcoin address layer -- scriptPubKey <-> address (P2PKH/P2SH/P2WPKH/P2WSH/P2TR/witness v1-16), network detection, WIF keys, P2SH/P2WSH helpers. | any | bech32, ripemd160 |
| [`btcp2p`](modules/btcp2p/README.md) | 4 (S) | Bitcoin P2P wire-message codec — envelope, version/verack handshake, inventory/data messages. Codec only: no chain state or validation. | any | bitcointx |
| [`bulletproofs`](modules/bulletproofs/README.md) | 3 (S,H,P) | Bulletproofs — zero-knowledge range proofs over Ristretto255, proving a Pedersen-committed value is in range with logarithmic proof size. | any | ct25519 |
| [`chachapoly`](modules/chachapoly/README.md) | 3 (S,P) | SIMD-accelerated ChaCha20-Poly1305 AEAD (RFC 8439) — a throughput-specialized, byte-exact duplicate of `std.crypto.aead.chacha_poly`. | any (SIMD via `@Vector`) | — |
| [`coconut`](modules/coconut/README.md) | 4 (S) | Coconut threshold-issuance anonymous credentials over `bls12_381` — t-of-n issued Pointcheval-Sanders credentials with selective-disclosure showing. | any | bls12_381 |
| [`ct25519`](modules/ct25519/README.md) | 3 (S,P) | Constant-time-on-secrets scalar multiplication for Edwards25519/Ristretto255 — drops std's secret-dependent `rejectIdentity` branch. Caller must validate points. `X25519` with key generation on the fixed-base comb (2.4× std). | any | — |
| [`ctap2`](modules/ctap2/README.md) | 3 (S,H,P) | CTAP2 (FIDO2) `authenticatorClientPIN` command layer over a caller-supplied transport: GetInfo, PIN retries/set/change/token-with-permissions, both PIN protocols, CTAPHID packet codec. | any | cbor, ctap2pin |
| [`ctap2pin`](modules/ctap2pin/README.md) | 3 (S,E,H,P) | CTAP2 `pinUvAuthProtocol` (FIDO2/WebAuthn) — both protocol versions: ECDH-P256 key agreement, encrypt/decrypt, authenticate/verify. | any | p256 |
| [`decaf448`](modules/decaf448/README.md) | 3 (S,H,P) | decaf448 prime-order group (RFC 9496) over `ed448` — eliminates cofactor-4 pitfalls for threshold signing, VRFs, anonymous credentials. | any | ed448 |
| [`dkg`](modules/dkg/README.md) | 4 (S,E) | Dealer-free Distributed Key Generation (GJKR) for `threshold_ecdsa` — bias-resistant secp256k1 key sharing feeding threshold signing. | any | threshold_ecdsa, paillier |
| [`drand`](modules/drand/README.md) | 3 (S,H,P) | drand randomness-beacon client — chain-info and round codec, BLS-verifies a round signature against the chain public key. Transport-agnostic. | any | bls12_381, tlock |
| [`dtls`](modules/dtls/README.md) | 4 (S) | DTLS 1.3 (RFC 9147), PSK mode — key schedule, AEAD record layer, handshake fragmentation/reassembly, anti-replay window. | any | rsa, x509, chachapoly |
| [`ecvrf`](modules/ecvrf/README.md) | 3 (S,H,P) | ECVRF-EDWARDS25519-SHA512-TAI (RFC 9381 Verifiable Random Function) — prove/verify a deterministic, unbiasable output under a public key. | any | ct25519 |
| [`ed448`](modules/ed448/README.md) | 4 (P) | Ed448 + X448 — the 448-bit "Goldilocks" curve (RFC 8032 + RFC 7748): constant-time X448 DH and Ed448/Ed448ph EdDSA signing. | any | entropy |
| [`entropy`](modules/entropy/README.md) | 4 (P) | Fail-closed entropy source — `fill` draws from `std.Io.randomSecure` or aborts the process; no generator, no silent degrade. **Panics on failure.** | any | — |
| [`falcon`](modules/falcon/README.md) | 3 (S,H,P) | FN-DSA — Falcon-512 and Falcon-1024 NIST post-quantum lattice signatures: keygen, sign, verify, and key/signature codecs. | any | — |
| [`frost`](modules/frost/README.md) | 4 (S) | FROST threshold Schnorr signatures (RFC 9591), secp256k1 — t-of-n keygen, 2-round signing, aggregate. **Not BIP340-compatible.** | any | bip340, k256 |
| [`fss`](modules/fss/README.md) | 4 (S,E) | Function Secret Sharing — 2-party single-point Distributed Point Function (BGI16), plus multi-point FSS; the primitive under `pir` and private analytics. | any | — |
| [`groth16`](modules/groth16/README.md) | 3 (S,E,H,P) | Groth16 zk-SNARK **prover** over BN254 — proves from snarkjs `.zkey` + circom `.wtns` (snarkjs accepts the proofs); phase-2 setup, contribution and key verification over a `.ptau`. `setup` is a toy, **insecure** trusted setup for tests. | any | bn254 |
| [`hashdigest`](modules/hashdigest/README.md) | 3 (S,E,P) | Streaming digests — one-shot, incremental, and file hashing; SHA-256 convenience plus a multi-algorithm SHA-2/SHA-3/BLAKE2b/BLAKE3 layer. | any | — |
| [`hpke`](modules/hpke/README.md) | 3 (S,A,P) | HPKE — Hybrid Public Key Encryption (RFC 9180): DHKEM(X25519/P-256) encap/decap, all four key-schedule modes, AEAD seal/open + export. | any | p256, chachapoly, entropy |
| [`hqc`](modules/hqc/README.md) | 2 (S,E,A,P) | HQC — code-based post-quantum KEM, NIST's structurally-independent backup to lattice-based ML-KEM. Complete keygen, encrypt, decrypt. | any | — |
| [`ibe`](modules/ibe/README.md) | 3 (S,E,A,H,P) | Standalone Boneh-Franklin Identity-Based Encryption over `bls12_381` — a self-run PKG extracts per-identity keys. Not post-quantum; key escrow is inherent. | any | bls12_381, entropy |
| [`k256`](modules/k256/README.md) | 3 (S,H,P) | asm-accelerated secp256k1 — Solinas field + GLV verify, bit-exact vs `std.crypto.ecc.Secp256k1`/BIP340. GLV is vartime/public-only, not for secrets. | amd64 asm + portable fallback | — |
| [`lms`](modules/lms/README.md) | 3 (S,E,H,P) | LMS / HSS (RFC 8554), SHA-256 — **stateful** hash-based signatures (SP 800-208, CNSA 2.0). A leaf signs once; `sign` advances the position first. | any | — |
| [`lninvoice`](modules/lninvoice/README.md) | 3 (S,H,P) | Lightning BOLT#11 payment requests (+ BOLT#12 offer decode) — decode/verify and encode/sign, with node-pubkey signature recovery. | any | bech32, k256, lnwire, bip340 |
| [`lnwire`](modules/lnwire/README.md) | 3 (S,H,P) | Lightning BOLT#1/2/7 wire messages — base frame, BigSize/TLV codec, channel-management (incl. reestablish) and gossip messages, address descriptors and feature bits, over `bolt8`. | any | — |
| [`megolm`](modules/megolm/README.md) | 3 (S,E,H,P) | Megolm — Matrix's group-messaging ratchet: a one-way HMAC hash ratchet (fast-forward only, never rewinds) plus Ed25519-signed message frames. | any | aescbc, entropy, chachapoly |
| [`minisign`](modules/minisign/README.md) | 3 (H,P) | minisign file format (jedisct1/minisign) — Ed25519 sign/verify for signed files/releases, including scrypt-encrypted secret keys. | any | entropy |
| [`mls`](modules/mls/README.md) | 4 (S) | MLS — Messaging Layer Security (RFC 9420): cipher-suite/codec foundation plus TreeKEM (ratchet tree), for scalable group messaging. | any | hpke |
| [`montint`](modules/montint/README.md) | 3 (S,H,P) | Constant-time Montgomery modular arithmetic over arbitrary odd moduli — faster native-Zig alternative to `std.crypto.ff`, x86-64 asm + portable fallback. | x86-64 asm + portable fallback | — |
| [`musig2`](modules/musig2/README.md) | 3 (S,H,P) | MuSig2 multi-signature (BIP327) producing BIP340 signatures — rogue-key-safe key aggregation, 2-round nonces, partial sign/verify. | any | bip340, k256 |
| [`noise`](modules/noise/README.md) | 3 (S,H,P) | Generic Noise Protocol Framework (spec rev 34) — all 38 one-way/fundamental/deferred patterns, PSK modifiers, protocol-name parsing, checked init, pluggable DH/AEAD/hash suite; cacophony vectors byte-exact. | any | chachapoly |
| [`ocsp`](modules/ocsp/README.md) | 3 (S,E,P) | RFC 6960 OCSP — build an OCSP request and cryptographically verify an OCSP response, for TLS OCSP-stapling. | any | x509, rsa, p256 |
| [`ocspcache`](modules/ocspcache/README.md) | 3 (S,E,P) | OCSP-stapling fetch + cache over `ocsp` — AIA responder discovery, verify-before-cache, refresh-ahead expiry, soft-fail on outage. | any | ocsp, http, x509 |
| [`opaque`](modules/opaque/README.md) | 4 (S) | OPAQUE — an asymmetric PAKE (RFC 9807), ristretto255-SHA-512 + 3DH — registration and login/AKE. Server compromise reveals no password. | any | voprf, ct25519 |
| [`oscore`](modules/oscore/README.md) | 3 (S,H,P) | OSCORE (RFC 8613) — end-to-end object security for CoAP: HKDF context derivation, AES-CCM AEAD, anti-replay sliding window. | any | — |
| [`otp`](modules/otp/README.md) | 3 (S,H,P) | HOTP + TOTP one-time passwords (RFC 4226 / RFC 6238) — the 2FA-authenticator primitive; caller supplies the counter/time (no wall clock); `otpauth://` provisioning-URI parse/format (base32 secrets). | any | base32 |
| [`p256`](modules/p256/README.md) | 3 (S,P) | asm-accelerated NIST P-256 — Solinas field, constant-time comb sign, vartime wNAF verify; bit-exact vs `std.crypto.ecc.P256` and RFC 6979. | amd64 asm + portable fallback | — |
| [`paillier`](modules/paillier/README.md) | 3 (S,H,P) | Paillier additively-homomorphic public-key encryption (EUROCRYPT 1999) — 2048-bit keygen, encrypt/decrypt, homomorphic add; const-time decrypt path. | any | montint |
| [`pir`](modules/pir/README.md) | 4 (E) | Two-server Private Information Retrieval over `fss`'s DPF — fetch a record without either server learning the index. **Two colluding servers recover it immediately.** | any | fss |
| [`poseidon`](modules/poseidon/README.md) | 3 (A,P) | Poseidon — the ZK-friendly hash over prime fields (HADES permutation), for BN254 and BLS12-381; cheap Merkle/commitment hashing inside circuits. | any | bn254, bls12_381 |
| [`psbt`](modules/psbt/README.md) | 4 (S) | BIP174 Partially Signed Bitcoin Transaction (PSBT) v0 — binary (de)serialization plus the Combiner (merge) role, over `bitcointx`. | any | bitcointx, bitcoinscript, ripemd160 |
| [`quic-crypto`](modules/quic-crypto/README.md) | 3 (S,H,P) | RFC 9001 (TLS for QUIC) crypto seam — secret derivation, AEAD packet protection, header protection, key update, Retry integrity tag, QUIC v1 + v2 (RFC 9369); engine-agnostic. | any | chachapoly |
| [`rescue`](modules/rescue/README.md) | 3 (S,A,H,P) | Rescue-Prime Optimized (RPO) — arithmetization-oriented hash over the Goldilocks field, the alternative to `poseidon` for STARK circuits. | any | — |
| [`ripemd160`](modules/ripemd160/README.md) | 2 (S,E,A,P) | RIPEMD-160 (ISO/IEC 10118-3) streaming hash, plus `hash160` (`RIPEMD160(SHA256(x))`), the Bitcoin pubkey-hash primitive. | any | — |
| [`rsa`](modules/rsa/README.md) | 3 (S,P) | Pure-Zig RSA (PKCS#1 v2.2, RFC 8017) — keygen, PKCS1-v1.5/PSS sign+verify, OAEP/PKCS1 encrypt+decrypt, DER/PEM/OpenSSH key parsing. | any | montint |
| [`sealedbox`](modules/sealedbox/README.md) | 3 (P) | NaCl `crypto_box_seal` — anonymous-sender X25519 public-key encryption, plus base64/hex key serialization. | any | ct25519 |
| [`sha2`](modules/sha2/README.md) | 3 (S,E,H,P) | SHA-224/256/384/512 (FIPS 180-4) — drop-in for std.crypto.hash.sha2 (also under std's Hmac/Hkdf); an AVX2 multi-block message schedule makes runs of 2+ blocks 1.24–1.40× std on x86-64 without SHA-NI, std's own SHA-NI/ARMv8 path where the target has it. | any (AVX2 SIMD schedule on x86-64 + portable scalar fallback) | — |
| [`signal`](modules/signal/README.md) | 4 (S) | Signal Protocol — X3DH and PQXDH key agreement, XEdDSA signing, and the Double Ratchet: E2EE sessions with forward secrecy, post-compromise security and a post-quantum initial handshake. | any | chachapoly, ct25519, entropy |
| [`slhdsa`](modules/slhdsa/README.md) | 3 (S,H,P) | SLH-DSA (FIPS 205, standardized SPHINCS+) — post-quantum stateless hash-based signatures, all twelve parameter sets, NIST-KAT-verified. | any | — |
| [`spake2plus`](modules/spake2plus/README.md) | 3 (S,H,P) | SPAKE2+ — an augmented PAKE (RFC 9383), P-256/SHA-256 (the Matter/Thread commissioning PAKE); resists server-compromise. | any | p256 |
| [`sphinx`](modules/sphinx/README.md) | 4 (S) | Lightning BOLT#4 Sphinx onion routing — forward ECDH blinding chain, layered packet construction, constant-time layer peeling. | any | k256 |
| [`taproot`](modules/taproot/README.md) | 3 (S,H,P) | BIP341 Taproot output construction — key tweaking (`tweakPublicKey`/`tweakSecretKey`) and script trees (Merkle root, per-leaf control blocks) built over `bip340`. | any | bip340, k256 |
| [`tenantkex`](modules/tenantkex/README.md) | 3 (S,H,P) | Per-tenant key exchange — a Noise_IK handshake (via `noise`) between provider edges, deriving directional channel keys for `aeadframe`. | any | noise |
| [`tfhe`](modules/tfhe/README.md) | 3 (S,H,P) | TFHE gate bootstrapping — unbounded-depth FHE on encrypted bits: binary gates, programmable bootstrap, tfhe-rs's boolean parameter sets and key/ciphertext layouts (interoperates with tfhe-rs 1.8.1 both ways). | any | entropy |
| [`threshold_ecdsa`](modules/threshold_ecdsa/README.md) | 3 (S,E,H,P) | GG20 threshold ECDSA over secp256k1 (t-of-n) — dealer keygen, per-signer presigning state machine with identifiable abort, one-round online signing; standard verifiable ECDSA sigs. **Audit warranted before production use.** | any | paillier, montint |
| [`timelock_envelope`](modules/timelock_envelope/README.md) | 3 (S,E,H,P) | Hybrid sealed envelope — unlocks only once both a drand timelock round publishes AND the recipient holds the PQ-KEM secret; AEAD-sealed content. | any | tlock, hqc, chachapoly, entropy |
| [`tlock`](modules/tlock/README.md) | 3 (S,H,P) | drand-style timelock encryption (Boneh-Franklin IBE over `bls12_381`) — encrypt to a future drand round; decryptable once it publishes. Not post-quantum. | any | bls12_381, entropy, chachapoly |
| [`tlsclient`](modules/tlsclient/README.md) | 3 (S,H,P) | std's TLS 1.3/1.2 client with the server chain verified by RFC 5280 (x509.verifyChain) — closes ziglang/zig #35877; opt-in ALPN and TLS 1.3 client certificates, std's handshake byte for byte by default. | any | x509 |
| [`tlsresume`](modules/tlsresume/README.md) | 3 (S,H,P) | Server-side TLS 1.3 session-ticket resumption (RFC 8446) — ticket seal/open, PSK binder derivation, 0-RTT early-data key schedule. | any | — |
| [`vdf`](modules/vdf/README.md) | 4 (S,E) | Wesolowski Verifiable Delay Function over an RSA hidden-order group — sequential-squaring delay with prove/verify. A caller-supplied modulus needs a trusted setup. | any | montint |
| [`voprf`](modules/voprf/README.md) | 4 (S) | (V)OPRF — Oblivious Pseudorandom Functions (RFC 9497), ristretto255-SHA-512: OPRF, verifiable, and partially-oblivious modes with DLEQ proofs. | any | ct25519 |
| [`webauthn`](modules/webauthn/README.md) | 3 (S,H,P) | WebAuthn / FIDO2 Relying-Party **verifier** (W3C Level 3) — assertion + registration ceremony checks, plus attestation verification. Verification only. | any | cbor, rsa, p256, x509 |
| [`x509`](modules/x509/README.md) | 3 (S,P) | X.509 certificate-chain / path validation (RFC 5280 §6) — trust-store chain building, extension, name, and signature checks, including post-quantum ML-DSA (RFC 9881) and SLH-DSA (RFC 9882) certificates, plus CRL revocation checking (RFC 5280 §6.3). | any | rsa, slhdsa |
| [`xmss`](modules/xmss/README.md) | 4 (S) | XMSS (RFC 8391), single-tree SHA-256 — **stateful** hash-based signatures. Index reuse breaks the scheme; `sign` advances the index first. | any | — |

**Also worth reaching for from `crypto`** — these are filed under another library (in brackets), and appear here because a consumer working in `crypto` has a use for them:

| Module | [Grade](#module-grades) | What it does | Platform | Deps |
|---|:-:|---|---|---|
| [`aescbc`](modules/aescbc/README.md) *(web)* | 3 (S,H,P) | Raw AES-CBC (NIST SP800-38A) + PKCS#7/XML-Enc padding helpers, zero-alloc; padding-oracle caveat — consumers own authenticate-before-unpad | any | — |
| [`http`](modules/http/README.md) *(web)* | 3 (S,P) | HTTP/1.1 client **and** server, hardened for direct exposure (slowloris caps, gzip, multipart, Range, negotiation); also speaks HTTP/2 (h2c/h2 client+server). Not `std.http`. | any | netaddr, datefmt, tlsclient, crc32 |

### Serialization / formats

| Module | [Grade](#module-grades) | What it does | Platform | Deps |
|---|:-:|---|---|---|
| [`base32`](modules/base32/README.md) | 3 (S,H,P) | Base32 codec (RFC 4648 §6 + base32hex §7) — strict by default (canonical trailing bits, exact padding), opt-in lenient decode (optional padding, lowercase, whitespace); the encoding of TOTP secrets. | any | — |
| [`blobmsg`](modules/blobmsg/README.md) | 3 (S,P) | OpenWRT ubus client + blob/blobmsg wire codec. | **linux** (codec itself: any) | — |
| [`cbor`](modules/cbor/README.md) | 3 (S,P) | CBOR (RFC 8949) codec — all 8 major types, deterministic encoding and strict decoding, sequences, diagnostic notation, streaming reader/writer, typed struct mapping; untrusted-input hardened; plus a minimal COSE (RFC 9052) layer. | any | — |
| [`cookies`](modules/cookies/README.md) | 3 (S,P) | HTTP cookies (RFC 6265) — request `Cookie` parser plus `Set-Cookie` builder (Secure/HttpOnly/SameSite), injection-guarded. | any | http |
| [`crc32`](modules/crc32/README.md) | 2 (S,E,A,P) | CRC-32 (IEEE: gzip/zlib/PNG) — x86-64 PCLMULQDQ folding and ARMv8 CRC instructions picked at run time, slicing-by-8 fallback; drop-in for std.hash.Crc32, streaming, extend, combine. | any (x86-64 PCLMULQDQ / arm64 CRC asm + portable fallback) | — |
| [`crc32c`](modules/crc32c/README.md) | 2 (S,E,A,P) | CRC-32C (Castagnoli) — SSE4.2 and ARMv8 CRC instructions picked at run time (three interleaved streams), slicing-by-8 fallback; streaming, extend, combine. | any (x86-64 SSE4.2 / arm64 CRC asm + portable fallback) | — |
| [`csvsafe`](modules/csvsafe/README.md) | 3 (S,E,P) | CSV formula-injection guard: OWASP's `=`/`+`/`-`/`@`/tab/CR cell leads, plus LF, `|` and `%`. | any | — |
| [`csvstream`](modules/csvstream/README.md) | 3 (S,P) | Streaming RFC 4180 CSV reader that preserves byte offsets, with bounded memory regardless of file size. | any | — |
| [`datefmt`](modules/datefmt/README.md) | 3 (S,P) | Civil calendar plus token-based date/time parse/format and calendar arithmetic, correct before 1970. | any | — |
| [`encoding`](modules/encoding/README.md) | 3 (S,P) | Text decoding to and from UTF-8: 5 European single-byte code pages, UTF-8 and UTF-16 with BOM sniffing, streaming and fatal modes (WHATWG semantics). | any | — |
| [`framing`](modules/framing/README.md) | 3 (S,E,P) | Length-prefixed stream framing (`writeFrame`/`readFrame`) plus a generic JSON tagged-union envelope codec. | any | — |
| [`ini`](modules/ini/README.md) | 3 (S,P) | INI reader — sections, key = value, comments; Python configparser and Desktop Entry (GKeyFile) dialects. | any | — |
| [`jinja`](modules/jinja/README.md) | 4 (S) | Jinja2-compatible template engine — expressions, control flow, template inheritance/macros/imports, over a symlink-contained loader. | any | — |
| [`json5`](modules/json5/README.md) | 3 (S,P) | Single-pass JSON5→JSON preprocessor (comments, unquoted keys, trailing commas, single-quoted strings, JSON5 numbers, line continuations). | any | — |
| [`linkheader`](modules/linkheader/README.md) | 3 (S,E,H,P) | Web Linking (RFC 8288) `Link` header build + parse: every param (anchor/media/title*/extensions), RFC 8187 ext-values, unquote, RFC 3986 target resolution, `pagination` + `find(rel)`; zero-alloc, injection-safe builder. | any | — |
| [`numparse`](modules/numparse/README.md) | 3 (S,P) | Locale-aware grouped-number parsing (thousands/decimal separators) into an exact `decimal.Decimal`. | any | decimal |
| [`protobuf`](modules/protobuf/README.md) | 3 (S,E,P) | Protocol Buffers wire format (proto3) codec — schema derived at comptime from Zig structs (oneof, map, well-known types incl. Any/Struct), no `.proto` compiler; untrusted-input hardened. | any | — |
| [`qr`](modules/qr/README.md) | 3 (S,E,H,P) | QR Code encoder and decoder (ISO/IEC 18004 model 2) — versions 1–40, levels L/M/Q/H, numeric/alphanumeric/byte modes, Reed-Solomon error correction, structured append; SVG and terminal renderers, allocation-free. | any | — |
| [`qrscan`](modules/qrscan/README.md) | 4 (S) | Locate a QR symbol in a grayscale image (luma + stride, camera or canvas) at any rotation and moderate tilt, and sample it into a `qr.Matrix`; block-adaptive binarisation, connected-component finder location, allocation-free. | any | qr |
| [`regex`](modules/regex/README.md) | 2 (S,A,P) | RE2-syntax regular expressions at parity with Go regexp — linear time, comptime compile, alloc-free match | any | — |
| [`tar`](modules/tar/README.md) | 3 (S,P) | ustar/GNU tar reader+writer (preserves uid/gid/mtime) + gzip. | any (packer: linux) | — |
| [`tz`](modules/tz/README.md) | 3 (S,P) | IANA time-zone offset lookup — zone name → UTC offset/DST at a given instant (598 zones + POSIX-TZ footer). | any | datefmt |
| [`yaml`](modules/yaml/README.md) | 3 (S,P) | YAML 1.2 reader and emitter (not 1.1) — scanner → parser → composer over the core schema (no `yes`/`no` booleans), typed struct mapping, opt-in `<<` merge keys; cyclic aliases rejected. | any | — |
| [`zipstream`](modules/zipstream/README.md) | 3 (S,P) | Streaming ZIP archive reader — walks the central directory once, streams decompressed member bytes on demand. | any | — |
| [`zstd`](modules/zstd/README.md) | 2 (S,E,A,P) | Zstandard (RFC 8878) compressor, levels 1-22 and negative levels — byte-identical to libzstd 1.5.7 `ZSTD_compress2` and `ZSTD_compressStream2`, with libzstd's advanced parameters (magicless frames, explicit window/strategy, splitters, block size, long-distance matching as `--long`, targetCBlockSize superblocks), the sequence-level API (compressSequences, generateSequences, a block-level sequence producer) and reusable contexts in one workspace of exactly estimated size, caller-provided if wanted — and a decoder ported from libzstd's, one-shot and streaming (`ZSTD_decompressStream`, a `std.Io.Reader`), checksums, concatenated and skippable frames, frame queries | any | — |

**Also worth reaching for from `format`** — these are filed under another library (in brackets), and appear here because a consumer working in `format` has a use for them:

| Module | [Grade](#module-grades) | What it does | Platform | Deps |
|---|:-:|---|---|---|
| [`decimal`](modules/decimal/README.md) *(storage)* | 3 (S,P) | Exact i128 fixed-point decimal for money math with IEEE/GDA rounding modes and rescale — float-free arithmetic, f64 only at an explicit fromFloat/toFloat boundary. | any | — |
| [`http`](modules/http/README.md) *(web)* | 3 (S,P) | HTTP/1.1 client **and** server, hardened for direct exposure (slowloris caps, gzip, multipart, Range, negotiation); also speaks HTTP/2 (h2c/h2 client+server). Not `std.http`. | any | netaddr, datefmt, tlsclient, crc32 |

### Host / OS / agent — process, sandboxing, IPC, and the agent-side glue

| Module | [Grade](#module-grades) | What it does | Platform | Deps |
|---|:-:|---|---|---|
| [`argsafe`](modules/argsafe/README.md) | 3 (S,E,P) | Allowlist validators + a typed argv builder — neutralizes argument/flag injection into an exec `argv`. | any | — |
| [`diagnostics`](modules/diagnostics/README.md) | 3 (S,E,P) | LSP-style structured validation-finding collector — severity, dot-path, position, code, suggestion. | any | — |
| [`diskfree`](modules/diskfree/README.md) | 3 (S,P) | `statfs`/`statfs64` disk-space query (total/free/available, inodes, block size) + `/proc/self/mounts`+`mountinfo` parsers — what's mounted and how full, no `df`/`mount` subprocess | **linux** | — |
| [`diskusage`](modules/diskusage/README.md) | 3 (S,E,H,P) | `du`-style tree walk over a raw `statx`/`fstatat` metadata wrapper — apparent size and real allocation in one pass, hard links counted once, one-filesystem boundary | **linux** | — |
| [`fastmem`](modules/fastmem/README.md) | 3 (P) | Vectorised memset (32-byte stores, overlapping head/tail) that an executable without libc can export to replace compiler_rt's byte-at-a-time one for every caller, std included; opt-in. | any (portable @Vector code; the export refuses libc-linked builds) | — |
| [`ipcbus`](modules/ipcbus/README.md) | 4 (S) | Same-host unix-socket control plane — a request/reply server plus a capped in-memory scratch key→bytes bus. | **linux** | framing |
| [`mcp`](modules/mcp/README.md) | 3 (S,P) | Model Context Protocol server (JSON-RPC 2.0) — tools, resources, prompts, plus server→client sampling and elicitation requests. | any | — |
| [`mcp-http`](modules/mcp-http/README.md) | 3 (S,E,A,H,P) | MCP Streamable HTTP transport (2026-07-28 stateless + 2025-06-18 sessions) — `POST /mcp` with JSON or live SSE, header/body validation, Origin (DNS-rebind) guard. | any | router, http, mcp |
| [`pollworker`](modules/pollworker/README.md) | 4 (S) | Single-owner `poll(2)` loop plus a lock-free fork/exec job table, for offloading blocking work off the loop thread. | **linux** | — |
| [`procrun`](modules/procrun/README.md) | 3 (S,E,P) | Subprocess runner — reap-race-tolerant wait, deadlock-free capped stdio capture, timeout, streaming, and cancel. | any | argsafe |
| [`sandbox`](modules/sandbox/README.md) | 3 (S,P) | Process self-hardening for an internet-facing server — privilege drop, `setrlimit`/no core dumps, Landlock fs allow-list, seccomp-bpf. | **linux** | — |
| [`testkit`](modules/testkit/README.md) | 3 (S,A,H,P) | Test-only shared harness (hex decoding for KAT vectors, golden byte-comparison, verbose-skip convention); wired via build.zig test_deps, absent from consumer imports | any | — |
| [`uci`](modules/uci/README.md) | 3 (S,P) | OpenWRT UCI config parser + serializer + typed model, with stable round-trip. | any | — |

**Also worth reaching for from `os`** — these are filed under another library (in brackets), and appear here because a consumer working in `os` has a use for them:

| Module | [Grade](#module-grades) | What it does | Platform | Deps |
|---|:-:|---|---|---|
| [`framing`](modules/framing/README.md) *(format)* | 3 (S,E,P) | Length-prefixed stream framing (`writeFrame`/`readFrame`) plus a generic JSON tagged-union envelope codec. | any | — |

## Non-goals — deliberately not built here

Capabilities this collection will not own, and what to reach for instead. A row here is a
scope decision with a reason, not a promise — the reason is what to argue with if it should
change. `zig build check-catalog` refuses to let this table name a capability that has since
become a module.

| Capability | Adopt instead | Why not a module |
|---|---|---|
| Hardened/read-only SQLite | `vrischmann/zig-sqlite` or `karlseguin/zqlite.zig`, wrapped consumer-side | The enforcement (`authorizer`/`PRAGMA query_only`/`open_v2(READONLY)`) is raw C-API — breaks the pure-Zig/no-libc invariant |
| Kafka | bind `librdkafka` | A choice, not an impossibility: the wire protocol is public and binary, so a port is perfectly writable — it is just long and uninteresting (dozens of API keys, each independently versioned). The trade is one C dependency against a lot of mechanical work, and the dependency wins until a consumer says otherwise |
| PostgreSQL (wire v3) | `karlseguin/pg.zig` | Mature MIT lib, pooling + TLS |
| MySQL/MariaDB | `speed2exe/myzql` | Only viable option |
| TOML | `mattyhall/tomlz` | Mature MIT config parser |
| Structured logging | `karlseguin/log.zig` | Cleanest "just use it" |
| S3 | `lobo/aws-sdk-for-zig` | SigV4 built in |
| Redis/Valkey | `kristoff-it/zig-okredis` (partial/alpha) | Best available design |
| xz compression | bind `liblzma`; or compress outside the process (the `xz` CLI in the consumer's pipeline) | Decoding is covered: std 0.16 ships an `std.compress.xz` decoder, and zstd is a module both ways (`zstd`: every level 1–22, and a decoder). What remains is an LZMA2 encoder — a large arc with no in-process consumer yet; today's consumers write plain bytes and compress in a backup/build step <!-- non-goal-ok: zstd --> |
| HTTP/3 transport | `ngtcp2` | The transport (streams, loss detection, ACK logic, flight scheduling) is a bigger arc than SSH or OPC-UA were, and ngtcp2 is crypto-agnostic by design — it takes a TLS backend, which is the shape `quic-crypto` already has. The RFC 9001 crypto seam is ours; the state machine is not <!-- non-goal-ok: http, quic-crypto, ssh --> |
