# zig-libs — agent brief (READ FIRST)

You are building **zig-libs**, a curated collection of foundational Zig 0.16 modules,
extracted from four sibling projects and/or filling real gaps in the Zig ecosystem.
This brief is self-contained — you do not need any other context to work here.

## Prime directives

1. **Model after a proven implementation in another language.** Every module names a
   reference impl (c-ares, nghttp2, Java BigDecimal, …). Mirror its design; do NOT invent
   novel algorithms from scratch. Correctness > cleverness.
2. **Performance + universality.** Design for parallelism/streaming where relevant (see the
   `⚡` tag). Prefer zero-allocation hot paths, caller-supplied allocators, no hidden globals.
3. **Prefer std; build a dep only where std 0.16 has a real gap** (recursive-sublib rule).
   `std.json`, `std.crypto.tls` (client), `std.compress` (flate/zstd decode) already exist — use them.
4. **Every module is headless-verifiable.** Ship tests. Where a conformance/golden oracle
   exists (h2spec, fping golden-diff, `nft --debug`), verify against it.
5. **Do NOT depend on `std.http.Client`** — its API churns; replacing that dependency is a
   reason this collection exists.

## Decisions (fixed — do not relitigate)

- **Packaging = one repo = one package.** Single root `build.zig` + one `build.zig.zon`
  (because `zig fetch` can't target a subdirectory — ziglang/zig#23012). Consumers fetch the
  whole repo and import a named module: `dep.module("http")` / `@import("http")`. The automatic
  whole-repo `zon` fetch **must keep working** — never break `zig build test`.
- **Naming:** module = `snake_case`, capability-based, no `zig-` prefix, no platform/role in the
  name. Split `_client`/`_server` only if separate deliverables; else one module with submodules
  (`http.Client`/`http.Server`). Inside: types `TitleCase`, type-returning fns `TitleCase`, other
  callables `camelCase`, else `snake_case`.
- **`http` = one module, `Client` + `Server` submodules.**
- **`dns` includes DoH now** (composes `http` + `std.crypto.tls` + `std.json`).
- **Linux-only members are fine** (icmp/rawsock/netlink/procnet/ipcbus/pollworker use raw
  syscalls) — no portable fallback required.
- Full conventions + the `meta` tag vocabulary: see `CONVENTIONS.md`.

## Licensing & provenance (IMPORTANT)

- **License = MIT** (see `LICENSE`). Put `// SPDX-License-Identifier: MIT` as the first line of
  every module's `src/root.zig`.
- **Only take code from:** our own seed projects (bxp/axp = Apache-2.0, relicensed to MIT here by
  the copyright holder; poc-wf-analytic; zig-fping) — OR **clean-room reimplement from a public
  spec/RFC**. NEVER copy from GPL/AGPL/LGPL or unknown-license third-party source. "Model after X"
  means study the design and reimplement — do not paste code.
- **Record provenance** in the module `README.md`: a `Provenance:` line = the seed (+ its license)
  and/or "clean-room from <spec>", plus any third-party design reference and its license.
- `netaddr` is fping-derived → the fping attribution is in `NOTICE`. If you introduce a new
  third-party design reference, add it to `NOTICE`.

## Repo shape

```
build.zig          # registers each module by name + `test` / `test-<name>` steps
build.zig.zon      # one manifest for the whole collection
CONVENTIONS.md       # naming + meta tags + sublib rule
BRIEF.md             # this file
PLAN.md              # roadmap: status, in-flight, backlog, decisions, definition-of-done
NOTICE               # canonical provenance + third-party design-refs + licenses
docs/CANDIDATES.md   # full candidate catalog + per-module Model-after / Seed / discussion
docs/spec/SPEC-*.md  # historical/partial design specs (older modules; see docs/spec/README.md)
modules/
  _template/         # copy to start a module
  <name>/src/root.zig + README.md
```

## How to add / build a module

1. `cp -r modules/_template modules/<name>`, fill `src/root.zig` (`pub const meta` + API + tests)
   and `README.md`.
2. Add `.{ .name = "<name>", .deps = &.{ "dep1", ... } }` to `module_list` in `build.zig`.
3. `zig build test-<name>` (per module) and `zig build test` (all) — both must be green.

## Verification harnesses (per module type)

- protocol codecs (`icmp`, `dns`, `l2disco`, `http` h2): golden bytes / **h2spec** for h2.
- syscall/netlink/raw (`netlink`, `rawsock`, `wireguard`): a network namespace (`unshare -rn`).
- pure logic (`decimal`, `datefmt`, `ramcache`, `finstats`): unit tests + property/round-trip.
- clients (`dns`, `whois`, `rdap`, `http` client): a live round-trip against a real server when
  the network is available, plus offline unit tests on parsing.
- Later: a shared `testkit` module will provide golden-diff / netns / VOPR-sim helpers.

## Seed map (where working code already lives — extract, don't reinvent)

Sibling repos under `~/workspace/` and `~/CML/`:
- **zig-fping** (`~/workspace/zig-fping/src/`): `netutil.zig` (netaddr/RFC 6724), `pinger.zig`/
  `socket.zig` (icmp), `seqmap.zig`, `rdns.zig` (dns PTR).
- **axp** (`~/workspace/axp/`): `axp-core/http.zig` + `httpclient.zig` (http), `ubus.zig`
  (blobmsg), `tar.zig`, `sealed.zig`, `digest.zig`, `wire.zig`/`message.zig`; `task.zig`
  (l2disco/stun/sntp/procnet/argsafe parsers); `axp-central/rest.zig` (router/aaa-gate);
  `axp-vault/store.zig` (blobstore).
- **bxp** (`~/workspace/bxp/bxp-core/src/`): `decimal.zig`, `datefmt.zig`, `tz.zig`,
  `encoding.zig`, `unicode.zig`, `json5.zig`, `zipstream.zig`, `csv.zig`, `diagnostics.zig`,
  `expr.zig`; `bxp-mcp/src/` (mcp).
- **poc-wf-analytic** (`~/CML/poc-wf-analytic/src/`): `cache.zig` (ramcache), `reader.zig` +
  `frontend/widgets.js` (finstats), `main.zig` (ipcbus/pollworker/chunkframe).

When extracting: lift the pure logic, drop the app-specific coupling, add a clean caller-supplied
allocator + a `meta` block, and write tests. Keep byte-for-byte behavior where a golden test exists.
