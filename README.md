# zig-libs

A curated collection of **foundational Zig modules** — performance-minded, universal where
possible, each modeled after a proven implementation in another language rather than invented from
scratch.

Not a dumping ground: ship **solid, not many**. Most members are *extracted* from working code
across sibling projects (bxp, axp, zig-fping, poc-wf-analytic); a few fill genuine gaps in the Zig
ecosystem.

**Status:** 77 modules · 1809 tests (Zig 0.16, green in Debug + ReleaseFast) · **MIT** (see `LICENSE`;
third-party-derived wire formats & required attributions in `NOTICE`).

### Licensing note

zig-libs' own code is MIT throughout. Four modules — `icmp`, `seqmap`, `netaddr`, `dns` — descend
from fping (https://github.com/schweikert/fping), which carries a non-standard Stanford
"BSD-with-advertising" license, not a plain permissive one. That license affirmatively requires
that documentation and advertising materials for redistributions acknowledge the software was
developed by Stanford University. Redistributors of those four modules (or of zig-libs as a whole)
must preserve that fping attribution, reproduced in full in `NOTICE` §1.

## Modules

Every module is imported by its `name` (`@import("http")`); hyphenated names work too
(`@import("security-headers")`). `Deps` are sibling modules; everything else is `std`-only.

### Web / HTTP & API — an internet-facing service, no reverse proxy required

| Module | What it does | Deps |
|---|---|---|
| `http` | HTTP/1.1 client (TLS via `std.crypto.tls`) **and** server, hardened for direct exposure (peer addr, conn caps, size limits, slowloris timeouts, gzip, **conditional requests** ETag/If-\* → 304/412, **request-body parsing** — `Content-Type`, urlencoded, **multipart/form-data** RFC 7578, **Server-Sent Events** encoder + incremental `flush()`, **inbound gzip** request bodies (zip-bomb-capped), **multiple Set-Cookie**, chunked-trailer capture, **`Range` / 206 Partial Content** RFC 7233 — `bytes=` parser + resolve-against-length → `Content-Range` + 206/416 response staging + `multipart/byteranges` body for multi-range requests, **content negotiation** — `Accept` / `Accept-Language` (RFC 4647) / `Accept-Encoding` parsers + `negotiate` server-offers→best-match / 406, RFC 9110 §12.5). Also speaks **HTTP/2** (bidirectional, TLS-deployable) — HPACK (RFC 7541) + framing/flow-control (RFC 9113) + a **DoS-hardened h2c server** + a **multiplexing h2 client** + an **ALPN/bring-your-own-TLS seam**. Not `std.http`. | netaddr |
| `router` | REST routing — trie matcher (params/wildcards), middleware chain, groups, 404/405 | http |
| `ratelimit` | Token-bucket per-client rate limit → 429 + Retry-After | router, http, netaddr |
| `abuseguard` | Per-IP + global connection caps, ban/greylist, strike→ban (accept-time) | http, netaddr, router |
| `throttle` | Global concurrency limit + load-shedding → 503 | router, http |
| `security-headers` | Secure-by-default response headers (HSTS/CSP/nosniff/frame/referrer/COOP/CORP) | router, http |
| `cors` | CORS preflight + header injection (secure defaults) | router, http |
| `validate` | Request body/query/params validation → aggregated 400 (typed + schema + string `format`: email/uri/uuid/ip/hostname/date-time/…) + **JSON DoS caps** (depth/array/field) | router, http, netaddr |
| `metrics` | Prometheus registry (counter/gauge/histogram) + `/metrics` + request middleware + **access-log writer** (combined/JSON) | router, http |
| `health` | Liveness (`/healthz`) + readiness (`/readyz`) probe middleware — 200/503 from registered dependency checks (k8s probe contract) | router, http |
| `requestid` | Request/correlation-ID middleware — adopt incoming `X-Request-Id` or generate, echo on the response, expose via `current()` (composes with auth) | router, http |
| `tracecontext` | **W3C Trace Context** — `traceparent`/`tracestate` parse + generate + a propagation middleware (child span per hop, `current()`) for distributed tracing | router, http |
| `webhooksig` | **HMAC webhook signatures** (GitHub/Stripe style) — `sign`/`verify` (constant-time) + a middleware gating requests by `HMAC-SHA256(secret, body)`, key rotation | router, http |
| `idempotency` | **Idempotency-Key** dedup of unsafe retries — a middleware + ramcache-backed `Store` replaying a key's cached response without re-running the handler | router, http, ramcache |
| `resilience` | Circuit breaker + retry/backoff + timeout + **bulkhead** (concurrency limiter) for calling upstreams (generic) | — |
| `upstream` | Load-balanced upstream pool + failover — round-robin/weighted/least-conn/EWMA strategies, per-upstream breaker+bulkhead, active+passive health | resilience, probe |
| `openapi` | OpenAPI 3.1 spec generated from the route table + `/openapi.json` | router, http |
| `aaa-gate` | Bearer + **API-key** auth (constant-time) + audit hook + denied-request throttle | router, http |
| `jwt` | JWT/JWS + **OIDC resource-server** validator (RFC 7515/7519/7517/8725) — parse + claims + verify (HS/ES/EdDSA/RSA, alg-confusion-safe) + JWKS-by-`kid` + **OIDC discovery/fetch** (cache + key-rotation) + a **`router` Bearer middleware** (RFC 6750 challenge, scope check, identity on ctx) | http, router |
| `acme` | Let's Encrypt / ACME v2 (RFC 8555): HTTP-01 issuance + renewal, ES256 JWS, CSR | http, router |
| `sessions` | Server-side web sessions + OWASP-hardened cookies + signed double-submit **CSRF** middleware | router, http, cookies, ramcache |
| `llmclient` | Anthropic Messages API client (buffered + streaming SSE) over `http` — no third-party SDK | http |

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
| `coap` | CoAP (RFC 7252) — a full client/server stack: message codec (header/token/**delta-encoded options**/payload), `options` (registry, CoAP uint, **URI ↔ options** §6), `reliability` (CON **retransmission** §4.2 + message-ID **dedup** §4.5), `client` (URI→request + reply correlation), `server` (dispatch + piggyback/separate responses). Zero-alloc, transport-/clock-agnostic (block-wise + observe are follow-ups) | any | — |
| `snmp` | SNMP v1/v2c — BER/ASN.1 codec + OID + all 8 PDUs + manager client (get/next/bulk/set/walk) + a **trap/notification receiver** (v1 Trap / v2c Trap / Inform → one normalized `TrapEvent` + `Dispatcher` + `ackInform` byte-faithful Response ack) + **SNMPv3** (RFC 3412 message framing + ScopedPDU, plaintext/noAuthNoPriv) + **USM** (RFC 3414) — `UsmSecurityParameters` (de)serializer + **auth**: password→key localization + HMAC-MD5-96 / HMAC-SHA-1-96 sign/verify (constant-time, RFC A.3 KAT-checked; privacy crypto in progress), transport-agnostic seam | any | — |
| `whois` | RFC 3912 whois client — query format + referral chasing (IANA→registrar) + field extraction, transport-agnostic seam | any | — |
| `rdap` | RDAP client (RFC 7480–7484) — JSON-over-HTTPS whois successor: query URLs, typed response model, IANA bootstrap, fetch seam | any | http, netaddr |
| `icmp` | ICMP echo (ping) engine — v4/v6 codec, batched socket, pacing | linux | seqmap, netaddr |
| `traceroute` | ICMP-echo path discovery — TTL-stepped probes, per-hop address + RTT stats, load-balanced-path aware | linux | icmp, netaddr, latency-stats |
| `probe` | TCP-connect reachability prober — up/refused/timeout + RTT, fan-out with bounded concurrency, latency aggregation | any | netaddr, latency-stats |
| `l2disco` | Layer-2 / neighbor discovery codec — LLDP (802.1AB) + CDP + ARP (RFC 826) + DHCP options (RFC 2131/2132) + MAC helper | any | netaddr |
| `seqmap` | Fixed 65 536-slot 16-bit request/reply correlation map, O(1) | any | — |
| `latency-stats` | Online RTT stats — min/max/mean/stddev + RFC 3550 jitter + loss % (O(1)/sample, no alloc) + an **HdrHistogram** for bounded-error percentiles (p50–p99.9) | any | — |
| `procnet` | Linux `/proc`+`/sys` parsers — ARP/routes/TCP+UDP sockets/conntrack/process stats/device health, typed | linux | netaddr |
| `rawsock` | Linux **AF_PACKET** raw-frame capture + inject — BPF filter, promiscuous mode, typed frame decode | linux | netaddr |
| `stun` | STUN client (RFC 8489) — NAT reflexive-address discovery: XOR-MAPPED-ADDRESS + MESSAGE-INTEGRITY + FINGERPRINT | any | netaddr |
| `sntp` | SNTP client (RFC 4330) — NTP packet codec + UDP query, clock offset / round-trip delay | any | — |
| `syslog` | RFC 5424 syslog formatter + emitter, RFC 3164 legacy encoder, RFC 6587 TCP octet framing | any | — |

### Data & storage

| Module | What it does | Deps |
|---|---|---|
| `kv` | Crash-consistent embedded KV store (Bitcask-style log + **randomized seeded VOPR**: model-checked crash recovery across fuzzed fault schedules) | — |
| `ramcache` | Bounded in-memory cache — **W-TinyLFU** admission/eviction (window+SLRU+CMS sketch) + TTL + generation invalidation | — |
| `decimal` | Exact i128 fixed-point decimal (money math), float-free — with IEEE/GDA rounding modes, rescale + rounded division | — |
| `jobqueue` | Durable background-job queue over `kv` — lease/retry/DLQ, per-partition FIFO under priority, scheduled visibility | kv |
| `blobstore` | Content-addressed blob store (git-object/restic style) + name-addressed + small named-record layers, crash-safe | hashdigest |
| `filestore` | DB-less durable keyed document store — one atomically-written file per record + a typed-JSON convenience layer | — |
| `dataset` | Canonical in-memory columnar-typed table — the normalization seam between data sources and consumers | — |
| `tabular` | Dataset algebra (pandas/dplyr-style verbs) over `dataset` — aggregate/pivot/resample/rolling/join, fx-aware | dataset |
| `jsonshape` | JSON → `dataset` reshaping — dot-path descent + typed column projection (jq-style minimal subset) | dataset |
| `finstats` | Portfolio/financial statistics over `dataset` — XIRR/TWR/risk/beta/Monte-Carlo/correlation matrix | dataset |

### Crypto

| Module | What it does | Platform | Deps |
|---|---|---|---|
| `hashdigest` | Streaming digests — one-shot / incremental / file (EOF-read, size-0 `/proc` safe); SHA-256 convenience + a multi-algorithm layer (SHA-2/SHA-3/BLAKE2b/BLAKE3) | any | — |
| `sealedbox` | NaCl `crypto_box_seal` — anonymous-sender X25519 public-key encryption (thin over `std.crypto`) + base64/hex key serialization | any | — |

### Serialization / OS / agent

| Module | What it does | Platform | Deps |
|---|---|---|---|
| `tar` | ustar/GNU tar reader+writer (preserves uid/gid/mtime) + gzip | any (packer: linux) | — |
| `linkheader` | Web Linking (RFC 8288) `Link` header build + parse (rel/title/type), `pagination` (first/prev/next/last), `find(rel)` — zero-alloc | any | — |
| `cookies` | HTTP cookies (RFC 6265) — `Cookie` request parser (`parse`/`find`) **and** `Set-Cookie` builder (`SetCookie` w/ Path/Domain/Max-Age/Expires/**Secure/HttpOnly/SameSite**, injection-guarded, SameSite=None⇒Secure) + `get`/`set` http helpers | any | http |
| `blobmsg` | OpenWRT ubus client + blob/blobmsg wire codec | any (client: linux) | — |
| `mcp` | Model Context Protocol server (JSON-RPC 2.0) — tools + resources + prompts, app-state ctx | any | — |
| `mcp-http` | MCP **Streamable HTTP** transport (2025-06-18) — `POST /mcp` → JSON-RPC response (`application/json` **or live SSE** with tool-progress streaming) / 202, as a `router` middleware over a `mcp.Server`. Optional **sessions** (`Mcp-Session-Id` + `GET /mcp` server→client SSE stream with `Last-Event-ID` resumable replay + `DELETE` teardown); built-in **Origin** (DNS-rebinding) guard, size cap, Lock seam | any | router, http, mcp |
| `uci` | OpenWRT UCI config parser + serializer + typed model (stable round-trip) | any | — |
| `argsafe` | Allowlist validators + a typed argv builder — neutralizes argument/flag injection into an exec `argv` | any | — |
| `procrun` | Subprocess runner: reap-race-tolerant wait, deadlock-free capped stdio capture, timeout, streaming + cancel | any | — |
| `pollworker` | Single-owner `poll(2)` loop + a lock-free fork/exec job table for offloading blocking work off the loop thread | linux | — |
| `ipcbus` | Same-host unix-socket control plane — request/reply server + a capped in-memory scratch key→bytes bus | linux | framing |
| `framing` | Length-prefixed stream framing (`writeFrame`/`readFrame`) + a generic JSON tagged-union envelope codec | any | — |
| `csvstream` | Streaming RFC 4180 CSV reader that preserves byte offsets, bounded memory regardless of file size | any | — |
| `csvsafe` | OWASP CSV formula-injection guard (`=`/`+`/`-`/`@` cell leads) | any | — |
| `json5` | Single-pass JSON5→JSON preprocessor (comments, unquoted keys, trailing commas, single-quoted strings) | any | — |
| `zipstream` | Streaming ZIP archive reader — walk the central directory once, stream decompressed member bytes on demand | any | — |
| `encoding` | Legacy single-byte code page ↔ UTF-8 transcoding (5 European code pages: windows-125x, ISO-8859-1/2/15) | any | — |
| `datefmt` | Civil calendar + token-based date/time parse/format + calendar arithmetic, correct before 1970 | any | — |
| `tz` | IANA time-zone offset lookup — zone name → UTC offset/DST at a given instant (600 zones + POSIX-TZ footer) | any | datefmt |
| `numparse` | Locale-aware grouped-number parsing (thousands/decimal separators) into an exact `decimal.Decimal` | any | decimal |
| `diagnostics` | LSP-style structured validation-finding collector — severity, dot-path, position, code, suggestion | any | — |

## Roadmap / not yet built

Research-verdicted **DON'T-BUILD-YET** — no consumer demands them today; see each
module's `SPEC.md` (once built) or the git history for the full reasoning and the
"when greenlit" path for each:

- **`testkit`** (shared test harness) — deferred; the honest remaining scope (a
  `runWire` HTTP-wire test wrapper + `expectStatus` family + fake-clocks) needs a
  `build.zig` test-only-dep mechanism with no precedent in this repo, plus a 19-module
  refactor to pay off.
- **`Reconcilable(T)`** (generic desired-vs-actual reconciler) — no second consumer
  exists yet; extract a small `RollbackTimer` (arm/confirm/overdue) first, once one
  appears.
- **`kv` on-disk MVCC / transactions / ordered scans** — a multi-week B-tree + WAL build
  with zero current consumers demanding scans or transactions; the existing Bitcask-style
  log is enough until one does.

## Non-goals — deliberately not built here

Durable scope decisions (candidate audit, 2026-07-09): capabilities this collection will
not own, and what to reach for instead.

### Adopt instead of building

| Capability | Adopt instead | Why not a module |
|---|---|---|
| Hardened/read-only SQLite | `vrischmann/zig-sqlite` or `karlseguin/zqlite.zig`, wrapped consumer-side | The enforcement (`authorizer`/`PRAGMA query_only`/`open_v2(READONLY)`) is raw C-API — breaks the pure-Zig/no-libc invariant |
| SSH | bind `libssh2` | Pure-Zig SSH is a huge build; externally-coupled, stays consumer-side |
| Kafka | bind `librdkafka` | External C client, no pure-Zig alternative |
| gRPC | build over our HTTP/2 + adopt `Arwalk/zig-protobuf` | Needs an external protobuf codec; no trustworthy pure-Zig gRPC exists |
| OPC-UA | adopt/bind an existing stack | Huge industrial protocol stack, not a Zig-native win |
| Regex | `mnemnion/mvzr` (no captures) or `zig-utils/zig-regex` (captures) | Two mature pure-Zig libs already exist |
| PostgreSQL (wire v3) | `karlseguin/pg.zig` | Mature MIT lib, pooling + TLS |
| MySQL/MariaDB | `speed2exe/myzql` | Only viable option |
| SMTP | `karlseguin/smtp_client.zig` | Mature MIT lib (TLS-1.2 caveat) |
| WebSocket | `karlseguin/websocket.zig` | Mature MIT lib, both roles |
| protobuf | `Arwalk/zig-protobuf` | De-facto pure-Zig implementation |
| TOML | `mattyhall/tomlz` | Mature MIT config parser |
| Templates | `jetzig/zmpl` (comptime-typed) / `batiati/mustache-zig` (logic-less) / `gremlin-labs/vibe-jinja` (runtime `.jinja` corpora only, pilot) | Zig comptime makes a runtime engine mostly unnecessary |
| Structured logging | `karlseguin/log.zig` | Cleanest "just use it" |
| S3 | `lobo/aws-sdk-for-zig` | SigV4 built in |
| Redis/Valkey | `kristoff-it/zig-okredis` (partial/alpha) | Best available design |
| YAML (flat/nested config) | `kubkon/zig-yaml` / `pwbh/ymlz` (both partial — no anchors/tags) | Fine for config; not 1.2-complete (see full YAML below) |

### Dropped modules (considered, rejected)

- **`exprcalc`** — app-specific spreadsheet/rules engine, not reused cross-project, and needs external regex.
- **`unaccent`** — fully dependent on external `uucode` tables; stays in bxp.
- **`roquery`** — C-level SQLite hardening (authorizer/query_only enforcement); lives consumer-side over adopted zig-sqlite.
- **`taskqueue`** — folded into `jobqueue`.
- **`chunkframe`** — too small to be a module; a documented ~20-LOC pattern instead.

### Fully dropped formats/protocols

- **YAML 1.2 (full spec)** — no adoptable complete pure-Zig implementation; the partial libs above cover config use.
- **Jinja** — Zig comptime templating covers dev-authored use; `vibe-jinja` is a consumer-side pilot option for runtime `.jinja` corpora only.
- **IMAP** — no mature pure-Zig lib; stays unbuilt.
- **HTTP/3 (QUIC)** — not researched, stays dropped.

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
Roadmap notes live in the "Roadmap / not yet built" section above and the git history.
