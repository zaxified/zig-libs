# zig-libs — module plan & discussion

Working doc to discuss each candidate module **one at a time**. Skeleton is this repo
(`zig build test` green, Zig 0.16.0). Durable index = CML memory `project_zig_libs_catalog.md`.

Each entry: **`name`** ⚡(if perf-critical) `status·platform·role·concurrency` — what it does & why.
Then deps / model-after / seed / a **Decision:** field to fill during discussion.

**Tags** — status: `extract` (seeded in our code, carve out) · `gap` (missing in Zig) · `adopt` (good Zig lib exists, don't build).
platform: `any` (cross-OS) · `posix` · `linux` (raw syscalls/no-libc — conscious ceiling).
role: `client`·`server`·`codec` (pure wire, no I/O)·`both`·`util`.
conc: `reent` (no shared state)·`tsafe` (synchronized)·`owned` (single loop owns it, lock-free)·`block`.
Deps `(std)` = use Zig 0.16 std, don't rebuild.

---

## Packaging decision (settle first — blocks repo shape)

`zig fetch` **cannot** target a subdirectory of a git repo ([#23012](https://github.com/ziglang/zig/issues/23012), still open). So a GitHub dep URL is the **repo root**, never `.../zig-libs/modules/http`. Note: per-module *import* ≠ per-module *zon* — you get per-module import from a single package via named modules.

- **A) one repo = one package** (current skeleton). Fetch whole `zig-libs`, `@import("http")`. One zon. ✅ recommended.
- **B) repo per module** (`zig-http`, `zig-dns`…). Own zon/version each; fetch only what you use. Cost: many repos, cross-module edits span repos.
- **C) monorepo + per-module zon, local-path-dep only** (`.path="../zig-libs/modules/http"`). Fine for our sibling projects; GitHub subdir fetch still impossible → external users fetch the whole repo anyway.

**Decision:** A — one repo = one package; automatic `zon` fetch of the whole repo, import named modules. (Must Just Work: `zig fetch --save git+https://github.com/zaxified/zig-libs` → `dep.module("http")`.)

---

## 1. Net — wire codecs & probing

- **`netaddr`** `extract·any·util·reent` — Parse/format IP addresses and pick the right source/dest when a host has several (IPv4/IPv6 dual-stack, RFC 6724). Why: std has no selection; every net lib needs it. Deps: (std). Model: glibc getaddrinfo / Go addrselect. Seed: zig-fping netutil.zig. **Decision:** —
- **`icmp`** ⚡ `extract·linux·client·owned` — Send ICMP echo (ping) at scale with global pacing/batching — "which of N thousand hosts are up, how fast". Why: the fping engine; no small pure-Zig ICMP. Deps: netaddr, rawsock. Model: C fping (golden-diff). Seed: zig-fping. **Decision:** —
- **`seqmap`** ⚡ `extract·any·util·reent` — Fixed 65k-slot table mapping a 16-bit request id → in-flight state, O(1), zero-alloc. Why: any request/reply protocol must correlate replies to requests; reusable beyond ICMP. Deps: (std). Model: fping seqmap.c. Seed: zig-fping. **Decision:** —
- **`dns`** `extract+gap·any·client·block` — Resolve names→IPs (A/AAAA), IPs→names (PTR/reverse) over UDP/TCP **and DoH (DNS-over-HTTPS)**. Why: std is forward-only; PTR hand-rolled; DoH = privacy/firewall-friendly. `dig` CLI on top. Deps: (std udp/tcp), **http + tls(std.crypto.tls) + json(std)** for DoH. Model: c-ares / Go dnsclient / RFC 8484 (DoH). Seed: zig-fping rdns + AXP dns-probe. **Decision:** DoH now (composes http+tls+json → build after `http`).
- **`l2disco`** `extract·linux/any·codec·reent` — Parse layer-2 neighbor frames (LLDP/CDP) + ARP/DHCP — "what switch/port/device is on this wire". Why: no Zig LLDP lib exists. Deps: rawsock. Model: IEEE 802.1AB / packet(7). Seed: AXP task.zig. **Decision:** —
- **`stun`** `extract·any·client·reent` — Ask a STUN server "what's my public IP:port" through NAT. Why: phone-home from behind NAT; no small Zig STUN. Deps: (std udp). Model: pion/stun. Seed: AXP parseStunXor. **Decision:** —
- **`sntp`** `extract·any·client·reent` — Query an NTP server for time / clock offset / stratum. Why: clock-sync check; small. Deps: (std udp). Model: chrony/ntpd. Seed: AXP parseNtp. **Decision:** —
- **`latency-stats`** ⚡ `extract·any·util·reent` — Aggregate a batch of RTT samples into min/avg/max/jitter/loss (smokeping-style). Why: pairs with icmp for monitoring. Deps: (std). Model: smokeping. Seed: AXP latencyStats. **Decision:** —
- **`traceroute`** `extract·linux·client·block` — Discover the router hops on the path to a host. Why: path diagnostics; consumes icmp. Deps: icmp, netaddr. Model: mtr. Seed: AXP traceroute. **Decision:** —
- **`probe`** `extract·posix·client·block` — Test TCP reachability of host:port (connect check). Why: "is this service up" without ICMP. Deps: (std net). Model: —. Seed: AXP tcp-connect. **Decision:** —
- **`whois`** `gap·any·client·block` — Query WHOIS registries for domain/IP ownership, following referrals (RFC 3912). Why: none exists; rounds out net tooling. Deps: dns, (std tcp). Model: —. Seed: greenfield. **Decision:** —
- **`rdap`** `gap·any·client·block` — Query RDAP (Registration Data Access Protocol) — the modern **JSON-over-HTTPS** successor to WHOIS for domain/IP registration data (bootstrap → registry redirect chain). Why: structured JSON vs whois free-text; pairs with `whois` as fallback. Deps: http, json(std). Model: ICANN RDAP / Go openrdap. Seed: greenfield. **Decision:** —
- **`modbus`** `gap·any·both·block` — Talk Modbus (industrial PLC/SCADA protocol). Why: SCADA sim building block + real device control. Deps: (std tcp/serial). Model: libmodbus (BSD, 1:1). Seed: parked. **Decision:** —

## 2. Net — transport & control

- **`netlink`** ⚡ `gap·linux·client·block` — Talk to the kernel's netlink API to read/set routes, links, neighbors (instead of shelling `ip` / parsing /proc). Why: biggest lever — retires many shell-outs; substrate for wireguard. Deps: (std socket). Model: libmnl/libnl, vishvananda/netlink. Seed: none (unbuilt). **Decision:** —
- **`rawsock`** ⚡ `extract·linux·util·reent` — Open raw AF_PACKET sockets to send/recv raw Ethernet frames + query interfaces (ifindex/hwaddr). Why: std raw sockets still settling; needed by l2disco/icmp. Deps: std.os.linux. Model: libpcap (minimal). Seed: AXP openPacketCapture. **Decision:** —
- **`wireguard`** `extract·linux·client·reent` — Configure WireGuard peers/keys via netlink (instead of `wg set`). Why: native, no shell. Deps: netlink. Model: wgctrl-go. Seed: AXP wg-peer-add/del. **Decision:** —
- **`nftables`** `gap·linux·client·reent` — Build/apply firewall rules by emitting nftables JSON to `nft -j -f -`. Why: firewall control without reimplementing netlink (decided: JSON, not netlink). Deps: json(std), spawn `nft`. Model: —. Seed: AXP nft shell-out. **Decision:** —
- **`uci`** `gap·linux·both·reent` — Read/write OpenWRT UCI config natively (instead of shelling `uci`). Why: OpenWRT config; no Zig lib. Deps: (std). Model: libuci. Seed: AXP uci.zig adapter. **Decision:** —

## 3. HTTP / RPC transport

- **`http`** ⚡ `extract+gap·any·both·async` — HTTP client (and server codec) over TLS; HTTP/1.1 now, HTTP/2 later (submodules `Client`/`Server`). Why: 3 consumers; no mature pure-Zig h2 client; replaces curl. Deps: tls *(std.crypto.tls)*, netaddr; h2 = framing+HPACK. Model: dusty(1.1)+nghttp2; verify h2spec. Seed: AXP http.zig/httpclient.zig. **Decision:** one module + submodules (naming call).
- **`mcp`** `extract·any·server·reent` — Speak Model Context Protocol (JSON-RPC 2.0 over stdio/HTTP) so a tool exposes itself to AI agents. Why: bxp+axp both need it; existing Zig MCP libs too thin. Deps: json(std), http/stdio. Model: MCP spec 2025-11. Seed: bxp-mcp ↔ axp-mcp. **Decision:** —
- **`lenframe`+`jsonwire`** `extract·any·codec·reent` — Length-prefix framing + encode/decode a typed JSON message-union over a socket. Why: reusable wire skeleton for IPC/telemetry. Deps: json(std). Model: netstrings / gRPC framing. Seed: AXP wire.zig/message.zig. **Decision:** —

## 4. Serialization / archive

- **`blobmsg`** `extract·linux/any·client·reent` — Talk to OpenWRT's ubus bus (its blob/blobmsg binary format) over a unix socket. Why: no pure impl to port; the OpenWRT control core. Deps: unix sock, json. Model: openwrt libubox (wire only). Seed: AXP ubus.zig. **Decision:** —
- **`tar`** ⚡ `extract·any·both·block` — Read/write tar preserving uid/gid/mtime (which std.tar hides) + gzip pack. Why: backups; std.tar too lossy. Deps: gzip *(std flate)*. Model: GNU tar / libarchive. Seed: AXP tar.zig + vault backup.zig. **Decision:** —
- **`zipstream`** ⚡ `extract·any·codec·owned` — Read one ZIP entry at a time, streaming, bounded memory (not whole-file). Why: big xlsx/zip without loading it all; std.zip is whole-file. Deps: inflate *(std)*. Model: Go archive/zip, Py zipfile.open. Seed: bxp zipstream.zig. **Decision:** —
- **`json5`** `gap·any·codec·reent` — Turn JSON5 (comments, trailing commas, unquoted keys) into plain JSON for std.json. Why: readable config; existing Zig json5 libs rejected. Deps: json(std). Model: json5 spec. Seed: bxp json5.zig. **Decision:** —
- **`blobstore`** `extract·posix·util·reent` — Content-addressed blob store: files keyed by their sha256, deduplicated, + manifest. **(Renamed from `cas` — read as Czech "čas"/time, confusing.)** Why: backup/dedup storage; generic. Deps: sha256 *(std)*. Model: git object store / restic. Seed: AXP vault store.zig. **Decision:** renamed cas→blobstore.

## 5. Text / calendar / encoding / math

- **`decimal`** ⚡ `gap·any·util·reent` — Exact base-10 fixed-point numbers (money math where 0.1+0.2==0.3). Why: Zig has no decimal; float is wrong for money. Deps: (std). Model: Java BigDecimal / DECIMAL(38,12). Seed: bxp decimal.zig. **Decision:** —
- **`numparse`** `extract·any·util·reent` — Parse locale-grouped numbers (`1,234.56` vs `1.234,56`). Why: importing data; no std answer. Deps: decimal. Model: ICU NumberFormat. Seed: bxp expr numeric path. **Decision:** —
- **`datefmt`** ⚡ `extract·any·util·reent` — Parse/format dates with strftime-like patterns + a correct civil calendar (incl. pre-1970). Why: std has no date parse/format. Deps: (std). Model: Hinnant date/chrono. Seed: bxp datefmt.zig. **Decision:** —
- **`tz`** `extract·any·util·reent` — Given a zone name + instant, return the DST-correct UTC offset (committed IANA tables). Why: std.Tz only parses TZif, no name→offset. Deps: std.Tz (build-time gen). Model: ICU / IANA tzdb. Seed: bxp tz.zig + tools/tz-gen. **Decision:** —
- **`encoding`** `gap·any·codec·reent` — Convert legacy single-byte code pages (Windows-1250/1252, ISO-8859-*) ↔ UTF-8. Why: the iconv job; neither Zig unicode lib has it. Deps: (std). Model: iconv / WHATWG Encoding. Seed: bxp encoding.zig. **Decision:** —
- **`unaccent`** `extract·any·util·reent` — Fold UTF-8 text: upper/lower incl. ß→SS, strip accents (slugify/search-normalize). Why: common need, no std answer (case tables from uucode). Deps: uucode *(adopt ext)*. Model: ICU translit / PG unaccent. Seed: bxp unicode.zig. **Decision:** —
- **`finstats`** ⚡ `extract·any·util·tsafe` — Portfolio/return analytics, **advanced set**: XIRR/TWR, vol/Sharpe/Sortino/Calmar, max-drawdown + recovery, correlation, quantiles/EMA, Monte-Carlo — **plus** beta/alpha (CAPM), tracking error, information ratio, historical + parametric VaR/CVaR, Omega/Ulcer, rolling windows, Brinson attribution. Why: currently duplicated Zig + JS; consolidate and go deep. Deps: (std math). Model: Python empyrical/ffn, QuantLib subset. Seed: poc-wf reader.zig + widgets.js. **Decision:** advanced set.

## 6. Storage / concurrency / IPC / crypto

- **`kv`** ⚡ `gap·any·both·tsafe` — Embedded key-value/document store (no SQL) — the pure-Zig local DB. Why: no production pure-Zig DB; KV is feasible in months. Deps: (std). Model: xitdb / LMDB; reliability = TigerBeetle VOPR sim. Seed: none (storage landscape). **Decision:** —
- **`ramcache`** ⚡ `extract·any·util·owned` — In-memory cache expiring by both TTL and a generation counter (bump gen = invalidate all, lazy drop). Why: done+tested, cleanest lift-out. Deps: (std). Model: groupcache / ristretto. Seed: poc-wf cache.zig. **Decision:** —
- **`ipcbus`** `extract·linux·server·owned` — A single owner process holding all state, serving worker processes over a unix socket + in-memory pub/sub. Why: the multi-process app pattern. Deps: unix sock. Model: —. Seed: poc-wf controller. **Decision:** —
- **`pollworker`** ⚡ `extract·linux·util·owned` — One poll loop owns state lock-free; blocking work offloaded to detached fork/exec workers via an atomic job table. Why: concurrency pattern for non-blocking single-owner designs. Deps: std.os.linux (fork). Model: Seastar / LMAX Disruptor. Seed: poc-wf DATA-PLANE. **Decision:** —
- **`chunkframe`** `extract·any·codec·reent` — Move payloads bigger than a channel's message cap by base64-chunking them (`{total,off,len,data}`). Why: bridge/IPC size caps. Deps: base64(std). Model: —. Seed: poc-wf ctlDataGet. **Decision:** —
- **`sealedbox`** `extract·any·util·reent` — Anonymous public-key encryption (NaCl sealed box): encrypt to a recipient key without a sender key. Why: enrollment; thin over std.crypto. Deps: std.crypto. Model: libsodium / Go nacl. Seed: AXP sealed.zig. **Decision:** —
- **`hashdigest`** ⚡ `extract·any·util·reent` — Streaming sha256 hex + content-match, works on size-0 /proc files. Why: file hashing/verify. Deps: std.crypto. Model: Go crypto/sha256. Seed: AXP digest.zig. **Decision:** —

## 7. Introspection / hardening / DSL

- **`procnet`** `extract·linux·util·reent` — Parse Linux /proc and /sys: routes, connections, sockets, ARP, process stats, meminfo, thermal, leases, disk. Why: everyone re-parses /proc; no canonical Zig lib. Deps: std.fs. Model: gopsutil / procps-ng. Seed: AXP *Outcome fns. **Decision:** —
- **`argsafe`** `extract·any·util·reent` — Validate argv strings before spawning subprocesses (block flag-injection, `..`, control chars). Why: safe shell-outs; reused across many call sites. Deps: (std). Model: —. Seed: AXP *Safe validators. **Decision:** —
- **`aaa-gate`** ⚡ `extract·any·server·tsafe` — Bearer-token auth + audit log + throttle for denied writes — an API gateway front. Why: any API server needs it. Deps: (std). Model: envoy / oauth2-proxy (minimal). Seed: AXP rest.zig AuditThrottle. **Decision:** —
- **`diagnostics`** `extract·any·util·reent` — Collect structured validation errors (path/line/severity/code + "did you mean") — LSP-style. Why: any config/DSL validator. Deps: (std). Model: LSP Diagnostic / rustc. Seed: bxp diagnostics.zig. **Decision:** —
- **`csvstream`** ⚡ `extract·any·codec·owned` — Stream-read RFC 4180 CSV records with byte offsets (for parallel processing + drill-back-to-source). Why: no std CSV; offset-tracking is the value. Deps: (std). Model: Go encoding/csv, Rust csv. Seed: bxp csv.zig + ChunkReader. **Decision:** —
- **`csvsafe`** `extract·any·util·reent` — Sanitize CSV cells against spreadsheet formula injection (`=`,`+`,`@`…). Why: security primitive when emitting CSV. Deps: (std). Model: OWASP CSV-injection. Seed: bxp writeSafeValue. **Decision:** —
- **`exprcalc`** ⚡ `extract·any·util·tsafe` — An embeddable Excel-like formula/expression evaluator (70+ builtins). Why: rules engines/config transforms; **capstone** that composes decimal/datefmt/encoding — do last. Deps: decimal, datefmt, tz, encoding, regex *(adopt)*, numparse. Model: CEL / HyperFormula. Seed: bxp expr.zig. **Decision:** —
- **`testkit`** `gap·any·util·reent` — Shared test-harness helpers: golden-diff runner, network-namespace (`unshare -rn`) setup, and a VOPR-style deterministic fault-injection simulator. Why: so each lib doesn't re-invent verification (decided). Deps: (std). Model: TigerBeetle VOPR / fping golden-diff. Seed: patterns across zig-fping + AXP wg-lab. **Decision:** yes (one shared).

## 8. Web service / API (internet-facing behind Caddy)

Goal: expose services on the internet **behind a Caddy reverse proxy** (Caddy owns TLS + HTTP/2/3 + edge DDoS). These app-layer modules compose on `http` (server) + `aaa-gate` (auth) + `ramcache`.

- **`router`** `extract·any·server·reent` — REST routing: method+path patterns, path params, middleware chain, typed handlers. Why: every API needs it. Deps: http. Model: Go chi / httprouter. Seed: AXP rest.zig routes. **Decision:** —
- **`ratelimit`** ⚡ `gap·any·util·tsafe` — Token-bucket / sliding-window rate limiting per IP / API key. Why: abuse control at the app layer. Deps: (std), ramcache. Model: Go x/time/rate, nginx limit_req. Seed: greenfield. **Decision:** —
- **`throttle`** ⚡ `extract·any·util·tsafe` — Concurrency limiting / backpressure / load-shedding (bound in-flight work, shed on overload). Why: survive spikes without falling over. Deps: (std). Model: Netflix concurrency-limits / SEDA. Seed: AXP AuditThrottle (generalize). **Decision:** —
- **`abuseguard`** ⚡ `gap·posix·server·tsafe` — App-layer DoS/abuse defense: per-IP connection caps, slowloris/read timeouts, request-size caps, greylist/ban. Why: Caddy handles edge DDoS; this is the app-layer complement. Deps: http. Model: nginx limits / Caddy / fail2ban. Seed: greenfield. **Decision:** —
- **`openapi`** `gap·any·util·reent` — Self-documenting API: generate an OpenAPI/Swagger spec (and serve docs) from typed route + schema declarations. Why: "self-documentation" — docs can't drift from code. Deps: json(std), router. Model: FastAPI auto-docs; ties to bxp FnDoc + MCP outputSchema. Seed: bxp docs codegen pattern. **Decision:** —
- **`validate`** `extract·any·util·reent` — Validate request body/query/params against a schema → structured errors. Why: reject bad input at the edge, uniformly. Deps: json(std), diagnostics. Model: pydantic / JSON Schema. Seed: bxp config validation. **Decision:** —
- **`cors`** `gap·any·util·reent` — CORS headers + preflight handling. Why: browser clients. Deps: http. Model: Go rs/cors. Seed: greenfield. **Decision:** —
- **`resilience`** `gap·any·util·tsafe` — Client-side circuit breaker + retry-with-backoff + timeout for calling upstreams. Why: don't cascade failures from flaky deps. Deps: (std). Model: resilience4j / Polly / Hystrix. Seed: greenfield. **Decision:** —
- **`metrics`** `gap·any·util·tsafe` — Counters/gauges/histograms + a Prometheus text-format endpoint + structured access logging. Why: observability for anything internet-facing. Deps: (std). Model: Prometheus client. Seed: greenfield. **Decision:** —

(Auth = `aaa-gate`, cat 7. TLS / HTTP2 / HTTP3 are Caddy's job — not reimplemented here.)

---

## ADOPT — don't build (good pure-Zig exists, verified web 2026-07-02)

`regex` (ezi-gex — SIMD/Unicode/ReDoS-safe) · JSON/serde/protobuf (zimdjson, mattnite/protobuf) ·
WebSocket (websocket.zig) · TUI (libvaxis) · logging · compression-**decode** (std.compress flate+zstd).
These become `deps` of our modules, not modules themselves. Confirmed real gaps we DO own:
decimal/bignum, compression-**encoders** (only LZ4), SSH/MQTT, production crypto/TLS beyond std.

## Decisions (2026-07-02)

1. **Packaging = A** — one repo = one package; automatic whole-repo `zon` fetch, import named modules.
2. **Name = `zig-libs`.**
3. **`dns` = DoH now** (composes http + tls + json).
4. **Shared test-harness = yes → `testkit`.**
5. **`http` = one module, `Client`/`Server` submodules.**
6. **Linux-only members = accept the ceiling.** *(Q5 was: some modules — icmp/rawsock/netlink/procnet/ipcbus/pollworker — must use raw Linux syscalls, so they run only on Linux, not macOS/Windows. Option A = leave them Linux-only, which is their nature. Option B = also write a portable fallback so they'd run elsewhere = extra work, rarely needed. Chose A.)*
7. **`cas` renamed → `blobstore`** (collided with Czech "čas").

## Priority / build order

Rule (user): **complex / high-value first**, then extractions of what we already have or will soon improve. Dependency order still forces a few foundations early (noted).

**P0 — complex & high-value (Fable5 first):**
1. `http` — h2 framing+HPACK + TLS client; the "worth-owning" ceiling; 3 consumers; unblocks dns/rdap/rest. *(needs `netaddr` first — trivial.)*
2. `dns` + DoH — composes http+tls+json; immediately needed.
3. `netlink` — biggest unbuilt systems lever (standalone); unblocks wireguard.
4. **REST/API cluster core** — `router` → `ratelimit` → `abuseguard` → `throttle` → `openapi` (the internet-behind-Caddy goal).
5. `kv` — research-grade (xitdb-style + VOPR sim); hardest; standalone.
6. `finstats` (advanced) · `exprcalc` (capstone — after its deps decimal/datefmt/encoding).

**P1 — soon-needed extractions (mostly lift-outs):**
`ramcache` · `netaddr` · `icmp`+`seqmap` · `decimal` · `blobmsg` · `mcp` · `aaa-gate` · `testkit`.

**P2 — remaining extractions & niceties:**
datefmt · tz · encoding · unaccent · numparse · tar · zipstream · blobstore · csvstream · csvsafe · diagnostics · procnet · argsafe · sealedbox · hashdigest · validate · cors · resilience · metrics · stun · sntp · latency-stats · traceroute · probe · rawsock · wireguard · nftables · uci · l2disco · ipcbus · pollworker · chunkframe · lenframe/jsonwire · whois · rdap · modbus.
