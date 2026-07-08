# zig-libs

A curated collection of **foundational Zig modules** — performance-minded, universal where
possible, each modeled after a proven implementation in another language rather than invented from
scratch.

Not a dumping ground: ship **solid, not many**. Most members are *extracted* from working code
across sibling projects (bxp, axp, zig-fping, poc-wf-analytic); a few fill genuine gaps in the Zig
ecosystem.

**Status:** 40 modules · 1157 tests (Zig 0.16, green in Debug + ReleaseFast) · **MIT** (see `LICENSE`;
third-party-derived wire formats & required attributions in `NOTICE`).

## Modules

Every module is imported by its `name` (`@import("http")`); hyphenated names work too
(`@import("security-headers")`). `Deps` are sibling modules; everything else is `std`-only.

### Web / HTTP & API — an internet-facing service, no reverse proxy required

| Module | What it does | Deps |
|---|---|---|
| `http` | HTTP/1.1 client (TLS via `std.crypto.tls`) **and** server, hardened for direct exposure (peer addr, conn caps, size limits, slowloris timeouts, gzip, **conditional requests** ETag/If-\* → 304/412, **request-body parsing** — `Content-Type`, urlencoded, **multipart/form-data** RFC 7578). Also speaks **HTTP/2** (bidirectional, TLS-deployable) — HPACK (RFC 7541) + framing/flow-control (RFC 9113) + a **DoS-hardened h2c server** + a **multiplexing h2 client** + an **ALPN/bring-your-own-TLS seam**. Not `std.http`. | netaddr |
| `router` | REST routing — trie matcher (params/wildcards), middleware chain, groups, 404/405 | http |
| `ratelimit` | Token-bucket per-client rate limit → 429 + Retry-After | router, http |
| `abuseguard` | Per-IP + global connection caps, ban/greylist, strike→ban (accept-time) | http, netaddr, router |
| `throttle` | Global concurrency limit + load-shedding → 503 | router, http |
| `security-headers` | Secure-by-default response headers (HSTS/CSP/nosniff/frame/referrer/COOP/CORP) | router, http |
| `cors` | CORS preflight + header injection (secure defaults) | router, http |
| `validate` | Request body/query/params validation → aggregated 400 (typed + schema + string `format`: email/uri/uuid/ip/hostname/date-time/…) + **JSON DoS caps** (depth/array/field) | router, http, netaddr |
| `metrics` | Prometheus registry (counter/gauge/histogram) + `/metrics` + request middleware + **access-log writer** (combined/JSON) | router, http |
| `resilience` | Circuit breaker + retry/backoff + timeout + **bulkhead** (concurrency limiter) for calling upstreams (generic) | — |
| `upstream` | Load-balanced upstream pool + failover — round-robin/weighted/least-conn/EWMA strategies, per-upstream breaker+bulkhead, active+passive health | resilience, probe |
| `openapi` | OpenAPI 3.1 spec generated from the route table + `/openapi.json` | router, http |
| `aaa-gate` | Bearer + **API-key** auth (constant-time) + audit hook + denied-request throttle | router, http |
| `jwt` | JWT/JWS + **OIDC resource-server** validator (RFC 7515/7519/7517/8725) — parse + claims + verify (HS/ES/EdDSA/RSA, alg-confusion-safe) + JWKS-by-`kid` + **OIDC discovery/fetch** (cache + key-rotation) + a **`router` Bearer middleware** (RFC 6750 challenge, scope check, identity on ctx) | http, router |
| `acme` | Let's Encrypt / ACME v2 (RFC 8555): HTTP-01 issuance + renewal, ES256 JWS, CSR | http, router |

### Networking

| Module | What it does | Platform | Deps |
|---|---|---|---|
| `netaddr` | IP parse/format (RFC 5952) + RFC 6724 source/dest selection + **CIDR/Prefix** ops (contains/overlaps/supernet, range↔prefix summarize) | any | — |
| `dns` | RFC 1035 resolver — A/AAAA/PTR/CNAME/NS/MX/TXT/SOA/SRV/CAA over UDP/TCP + DoH | any | netaddr, http |
| `netlink` | rtnetlink dumps: links / addresses / routes / neighbors | linux | — |
| `wireguard` | Native WireGuard device config over genetlink — get/set device, peers, allowed-ips (retires `wg` shell-outs) | linux | netlink |
| `nftables` | Typed firewall-ruleset builder → libnftables JSON for `nft -j -f -` (families/chains/rules/sets, match + verdict statements) | any (apply: linux) | — |
| `modbus` | Modbus TCP (MBAP) + RTU (CRC-16) codec + master client — core function codes, exceptions, transport-agnostic seam | any | — |
| `mqtt` | MQTT 3.1.1 client — all 14 control packets, QoS 0/1/2 state machine, topic-filter wildcards, transport-agnostic seam | any | — |
| `snmp` | SNMP v1/v2c — BER/ASN.1 codec + OID + all 8 PDUs + manager client (get/next/bulk/set/walk), transport-agnostic seam | any | — |
| `whois` | RFC 3912 whois client — query format + referral chasing (IANA→registrar) + field extraction, transport-agnostic seam | any | — |
| `rdap` | RDAP client (RFC 7480–7484) — JSON-over-HTTPS whois successor: query URLs, typed response model, IANA bootstrap, fetch seam | any | http, netaddr |
| `icmp` | ICMP echo (ping) engine — v4/v6 codec, batched socket, pacing | linux | seqmap, netaddr |
| `traceroute` | ICMP-echo path discovery — TTL-stepped probes, per-hop address + RTT stats, load-balanced-path aware | linux | icmp, netaddr, latency-stats |
| `probe` | TCP-connect reachability prober — up/refused/timeout + RTT, fan-out with bounded concurrency, latency aggregation | any | netaddr, latency-stats |
| `l2disco` | Layer-2 / neighbor discovery codec — LLDP (802.1AB) + CDP + ARP (RFC 826) + DHCP options (RFC 2131/2132) + MAC helper | any | netaddr |
| `seqmap` | Fixed 65 536-slot 16-bit request/reply correlation map, O(1) | any | — |
| `latency-stats` | Online RTT stats — min/max/mean/stddev + RFC 3550 jitter + loss % (O(1)/sample, no alloc) + an **HdrHistogram** for bounded-error percentiles (p50–p99.9) | any | — |

### Data & storage

| Module | What it does | Deps |
|---|---|---|
| `kv` | Crash-consistent embedded KV store (Bitcask-style log + **randomized seeded VOPR**: model-checked crash recovery across fuzzed fault schedules) | — |
| `ramcache` | Bounded in-memory cache — **W-TinyLFU** admission/eviction (window+SLRU+CMS sketch) + TTL + generation invalidation | — |
| `decimal` | Exact i128 fixed-point decimal (money math), float-free — with IEEE/GDA rounding modes, rescale + rounded division | — |

### Crypto

| Module | What it does | Platform | Deps |
|---|---|---|---|
| `hashdigest` | Streaming digests — one-shot / incremental / file (EOF-read, size-0 `/proc` safe); SHA-256 convenience + a multi-algorithm layer (SHA-2/SHA-3/BLAKE2b/BLAKE3) | any | — |
| `sealedbox` | NaCl `crypto_box_seal` — anonymous-sender X25519 public-key encryption (thin over `std.crypto`) + base64/hex key serialization | any | — |

### Serialization / OS / agent

| Module | What it does | Platform | Deps |
|---|---|---|---|
| `tar` | ustar/GNU tar reader+writer (preserves uid/gid/mtime) + gzip | any (packer: linux) | — |
| `blobmsg` | OpenWRT ubus client + blob/blobmsg wire codec | any (client: linux) | — |
| `mcp` | Model Context Protocol server (JSON-RPC 2.0) — tools + resources + prompts, app-state ctx | any | — |
| `uci` | OpenWRT UCI config parser + serializer + typed model (stable round-trip) | any | — |

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
