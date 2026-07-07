# zig-libs

A curated collection of **foundational Zig modules** — performance-minded, universal where
possible, each modeled after a proven implementation in another language rather than invented from
scratch.

Not a dumping ground: ship **solid, not many**. Most members are *extracted* from working code
across sibling projects (bxp, axp, zig-fping, poc-wf-analytic); a few fill genuine gaps in the Zig
ecosystem.

**Status:** 27 modules · 654 tests (Zig 0.16, green in Debug + ReleaseFast) · **MIT** (see `LICENSE`;
third-party-derived wire formats & required attributions in `NOTICE`).

## Modules

Every module is imported by its `name` (`@import("http")`); hyphenated names work too
(`@import("security-headers")`). `Deps` are sibling modules; everything else is `std`-only.

### Web / HTTP & API — an internet-facing service, no reverse proxy required

| Module | What it does | Deps |
|---|---|---|
| `http` | HTTP/1.1 client (TLS via `std.crypto.tls`) **and** server, hardened for direct exposure (peer addr, conn caps, size limits, slowloris timeouts, gzip). Includes an **HPACK** (RFC 7541) codec + **HTTP/2 framing & stream state machine** (RFC 9113). Not `std.http`. | netaddr |
| `router` | REST routing — trie matcher (params/wildcards), middleware chain, groups, 404/405 | http |
| `ratelimit` | Token-bucket per-client rate limit → 429 + Retry-After | router, http |
| `abuseguard` | Per-IP + global connection caps, ban/greylist, strike→ban (accept-time) | http, netaddr, router |
| `throttle` | Global concurrency limit + load-shedding → 503 | router, http |
| `security-headers` | Secure-by-default response headers (HSTS/CSP/nosniff/frame/referrer/COOP/CORP) | router, http |
| `cors` | CORS preflight + header injection (secure defaults) | router, http |
| `validate` | Request body/query/params validation → aggregated 400 (typed + schema) | router, http |
| `metrics` | Prometheus registry (counter/gauge/histogram) + `/metrics` + request middleware | router, http |
| `resilience` | Circuit breaker + retry/backoff + timeout for calling upstreams (generic) | — |
| `openapi` | OpenAPI 3.1 spec generated from the route table + `/openapi.json` | router, http |
| `aaa-gate` | Bearer-token auth (constant-time) + audit hook + denied-request throttle | router, http |
| `acme` | Let's Encrypt / ACME v2 (RFC 8555): HTTP-01 issuance + renewal, ES256 JWS, CSR | http, router |

### Networking

| Module | What it does | Platform | Deps |
|---|---|---|---|
| `netaddr` | IP parse/format (RFC 5952) + RFC 6724 source/dest selection | any | — |
| `dns` | RFC 1035 resolver — A/AAAA + PTR over UDP/TCP + DoH | any | netaddr, http |
| `netlink` | rtnetlink dumps: links / addresses / routes / neighbors | linux | — |
| `icmp` | ICMP echo (ping) engine — v4/v6 codec, batched socket, pacing | linux | seqmap, netaddr |
| `seqmap` | Fixed 65 536-slot 16-bit request/reply correlation map, O(1) | any | — |
| `latency-stats` | Online RTT stats — min/max/mean/stddev + RFC 3550 jitter + loss %, O(1)/sample, no alloc | any | — |

### Data & storage

| Module | What it does | Deps |
|---|---|---|
| `kv` | Crash-consistent embedded KV store (Bitcask-style log + **randomized seeded VOPR**: model-checked crash recovery across fuzzed fault schedules) | — |
| `ramcache` | Bounded in-memory cache — **W-TinyLFU** admission/eviction (window+SLRU+CMS sketch) + TTL + generation invalidation | — |
| `decimal` | Exact i128 fixed-point decimal (money math), float-free | — |

### Crypto

| Module | What it does | Platform | Deps |
|---|---|---|---|
| `hashdigest` | Streaming SHA-256 — one-shot / incremental / file (reads to EOF, so correct on size-0 `/proc` files) | any | — |
| `sealedbox` | NaCl `crypto_box_seal` — anonymous-sender X25519 public-key encryption (thin over `std.crypto`) | any | — |

### Serialization / OS / agent

| Module | What it does | Platform | Deps |
|---|---|---|---|
| `tar` | ustar/GNU tar reader+writer (preserves uid/gid/mtime) + gzip | any (packer: linux) | — |
| `blobmsg` | OpenWRT ubus client + blob/blobmsg wire codec | any (client: linux) | — |
| `mcp` | Model Context Protocol server (JSON-RPC 2.0 + tools, app-state ctx) | any | — |

## Using a module

- **Local path (dev, no tags/push):** in the consumer's `build.zig.zon`,
  `.zig_libs = .{ .path = "../zig-libs" }`, then in `build.zig`
  `exe.root_module.addImport("http", b.dependency("zig_libs", .{}).module("http"));`
- **Fetch:** `zig fetch --save git+https://github.com/.../zig-libs` then the same `dependency().module(...)`.
  (`zig fetch` can't target a subdirectory — ziglang/zig#23012 — so the whole repo is one package;
  you still import only the module you name. Unused modules aren't compiled.)

## Build

```
zig build test           # run all module tests
zig build test-<name>    # run one module's tests
```

## Layout & conventions

```
build.zig      # single root build — registers every module by name + a test step each
build.zig.zon  # one package manifest for the whole collection
CONVENTIONS.md # naming + `meta` tag vocabulary + provenance/SPDX rules
modules/<name>/src/root.zig  # `// SPDX-License-Identifier: MIT`, `pub const meta`, API, tests
modules/<name>/README.md     # what it is + a Provenance line
```

`CONVENTIONS.md` has the full rules; `modules/_template/` is the starting point for a new module.
Design/roadmap notes live in `PLAN.md`.
