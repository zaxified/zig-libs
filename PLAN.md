# zig-libs — roadmap

Forward-looking plan and status. The **candidate catalog** (per-module what/why/`Model after`/
`Seed`) is [`docs/CANDIDATES.md`](docs/CANDIDATES.md); agent rules + prime directives are
[`BRIEF.md`](BRIEF.md); canonical provenance + third-party attributions are [`NOTICE`](NOTICE);
the cross-project index is CML memory `project_zig_libs_catalog.md`. **Per-module build narrative
lives in each `modules/<name>/README.md` + doc-comments + `git log`** — this file is the roadmap,
not a changelog.

## Definition of done (every task)

Module folder from `_template`; `// SPDX-License-Identifier: MIT` first line; `pub const meta`
filled; public API + doc-comments; tests; registered in `build.zig`; `zig build test-<name>` **and**
`zig build test` green in **Debug + ReleaseFast**; `zig fmt --check` clean; `README.md` with a
`Provenance:` line; NOTICE updated with any design reference + its license. Where an oracle exists
(golden bytes / live round-trip / cross-check tool / RFC KAT), run it. **Multi-file modules: add the
new submodule to root.zig's `test { _ = … }` aggregator** — a bare `pub const` re-export does NOT
pull its tests in (see the dark-tests note under Decisions). **Agents never edit this file / commit /
touch build.zig · README · PLAN · NOTICE — they report back; the owner verifies + commits.**

## Status (2026-07-08)

**49 modules · 1423 tests** (1420 pass + 3 env-gated skips: ubus/wireguard/blobmsg live checks) ·
Debug + ReleaseFast green · `zig fmt` clean · MIT. Latest commit `d57a667`.
Web/API cluster, HTTP/1.1+HTTP/2 stack, `kv` (+VOPR), network family, crypto leaves, MCP (+HTTP/SSE
transport), and the content-negotiation + Range/206 HTTP feature families are complete.

## Working policy — extraction vs value-add

zig-libs ships the **good** (RFC/spec-complete) version of each library, not a copy of the minimal
"for-purpose" versions in axp/bxp/wgs/poc. Division of labour:
- **Mechanical extraction / faithful port of a minimal seed → Opus inline** (scaffold + carve-out +
  verify + commit). No Fable spend on pure copying. Integration, small fixes, and all research/audits
  are also Opus (they don't consume Fable budget).
- **Fable = value-add only**: complete a module to full RFC/IETF/spec compliance, or port a mature
  advanced library, so the result beats the minimal seed. Every Fable brief points at the spec /
  reference impl and gives the working minimum to surpass.
- **License discipline (stricter on value-add)**: work **clean-room from the spec/paper**, never copy
  source, and record the reference + its license in NOTICE (feeds the pre-public audit).
- **Token-saving workflow** (proven): pre-scaffold the API + spec + `@panic("TODO(agent)")` bodies so
  the module compiles (rescue-safe), then one Fable agent fills only the irreducible core + tests;
  split large tasks into independently-committable parts; MAX ONE Fable agent at a time. Detail in CML
  memory `zig_libs_handoff.md`. **⚠️ Fable5 limit reached 2026-07-08 — value-add paused until reset.**

## In-flight / next

- **SNMP v3 / USM** (`snmp.receiver`/`v3`/`usm`) — v1/v2c trap receiver + Inform ack ✅; v3 framing ✅;
  USM params ✅ + auth (HMAC-MD5/SHA-1-96 + key localization, RFC 3414 A.3 KAT-verified) ✅.
  **Remaining: T-G** privacy (DES-CBC + AES-128-CFB, RFC 3826) · **T-H** engineBoots/Time anti-replay
  window (§3.2). Opus-inline while Fable is capped; DES likely from-scratch (real value-add).
- **coap** (RFC 7252) — C1–C5 full client/server stack ✅. Deferred: **C6** block-wise (RFC 7959) ·
  **C7** observe (RFC 7641).

## Candidate program (2026-07-09 audit — full backlog, categorized)

Every candidate from the audit (sibling-seed sweep + ecosystem adopt-vs-build) + the prior catalog,
with **why** and who builds it. Full per-candidate detail (Model-after/Seed) in
[`docs/CANDIDATES.md`](docs/CANDIDATES.md). Legend — **Type:** `extract` (real seed in a sibling →
lift+harden) · `build` (greenfield gap) · `adopt` (mature external lib → wire as a dep, don't
rebuild). **By:** **Opus** = extraction, integration, adoption-glue, standard-pattern builds,
research (no Fable budget). **Fable** = RFC/spec-complete value-add + non-trivial crypto/algorithms
(⚠️ Fable5 capped 2026-07-08 — Fable rows are paused until reset; Opus can pinch-hit on the smaller
RFC codecs). Archetypes: ① HTTP/SaaS backend · ② netops · ③ IoT · ④ AI-agent/MCP · ⑤ data/analytics.

### ADOPT — wire as `deps`, do NOT build (Opus writes any thin integration/glue only)
| Capability | Lib (MIT unless noted) | Why adopt |
|---|---|---|
| PostgreSQL wire v3 | `karlseguin/pg.zig` (→0.16) | proven; **makes ① backend cheap** — no build |
| SQLite | `vrischmann/zig-sqlite` / `zqlite.zig` | poc uses it; substrate for `roquery`, `jobqueue` |
| MySQL/MariaDB | `speed2exe/myzql` | only option (smaller community) |
| SMTP | `karlseguin/smtp_client.zig` | ① email; recheck TLS-1.2 on 0.16 |
| WebSocket | `karlseguin/websocket.zig` | ①④ realtime; upgrades from our http |
| protobuf | `Arwalk/zig-protobuf` | enables a contained gRPC build on our h2 |
| TOML | `mattyhall/tomlz` | config |
| Template (mustache) | `batiati/mustache-zig` | HTML; Jinja-with-logic still a BUILD gap |
| Regex | `mnemnion/mvzr` / `zig-utils/zig-regex` | (already ADOPT) |
| Structured logging | `karlseguin/log.zig` | every app; cleanest "just use it" |
| S3 | `lobo/aws-sdk-for-zig` | object storage; SigV4 built in |
| Redis/Valkey · YAML · cron-parse | okredis · ymlz · dying-will-bullet/cron | PARTIAL — usable, verify per use |

### EXTRACT → Opus (real seed; low value-add headroom, so no Fable)
| Candidate | Unlocks | Why chosen |
|---|---|---|
| **`procrun`** ⭐ | universal (agent-tools/CI/ETL) | battle-tested subprocess + cross-platform reap-race fix (bxp-bridge) |
| `dataset`→`tabular`→`jsonshape` | ⑤ (anchor family) | mature, tested wgs seeds; the analytics spine |
| `roquery` | ⑤ + safe reporting | hardened read-only SQLite (adopts zig-sqlite); real security sliver |
| `finstats` | ⑤ finance | wgs `finance.zig` is already advanced (VaR/sortino/monte-carlo) |
| `filestore` | ① DB-less persist | third storage shape between `kv`/`blobstore`; add atomic rename |
| `taskqueue` | ③ fleet C2 | proven offline-device job pattern (or fold into `jobqueue`) |
| `rawsock` | ② capture/inject | real AF_PACKET in axp; base for l2disco/arp/icmp on the wire |
| `procnet` · `argsafe` · `blobstore` | ②/hardening | /proc-parse · argv-injection guard · CAS store (axp seeds) |
| bxp text libs: `datefmt`·`tz`·`encoding`·`unaccent`·`numparse`·`json5`·`zipstream`·`csvstream`·`csvsafe`·`diagnostics` | ⑤ + i18n | copy-tier; `tz`/`encoding` have spec headroom → could be Fable |
| `ipcbus`·`pollworker`·`chunkframe`·`lenframe`/`jsonwire` | same-host IPC | thin glue seeds (poc/axp) |

### BUILD → Opus (greenfield, standard pattern / integration)
| Candidate | Unlocks | Why chosen |
|---|---|---|
| **`sessions`** + CSRF | ① stateful web | no lib/seed; small, standard, composes `cookies` |
| **`jobqueue`** (SQLite lease/retry/DLQ + cron loop) | ①③ background work | nothing durable pure-Zig; medium; fits zig-sqlite + adopted cron |
| **`llmclient`** (Anthropic/OpenAI) | ④ AI-agent | cheap on our `http`+`sse`+`json`; types + streaming |
| `testkit` | all (verification) | shared golden-diff/netns/VOPR harness; stop re-inventing |
| `ssh` (bind `libssh2` first) | ② netops automation | pure-Zig SSH is huge → ergonomic binding first, Zig automation API |

### BUILD → Fable (RFC/spec-complete value-add + crypto — paused until reset)
| Candidate | Unlocks | Why Fable |
|---|---|---|
| **SNMP T-G** priv (DES-CBC + AES-128-CFB) + **T-H** time-window | ② finish v3 | in-flight; crypto value-add (Opus-inline possible now) |
| `coap` **C6** block-wise (7959) + **C7** observe (7641) | ③ | RFC-complete protocol value-add |
| `stun` (8489) · `sntp` (4330) · `syslog` (5424) | ②/netops | clean-room RFC codecs (syslog small → Opus-able) |
| `exprcalc` (capstone) | ③ rules / config transforms | Excel-like evaluator; composes decimal/datefmt/tz/encoding/numparse/regex |
| `grpc` (framing/streaming/status over our h2 + adopted protobuf) | microservices | no trustworthy pure-Zig; contained since we own h2 |
| **MQTT broker** | ③ IoT hub | server side of `mqtt`; large protocol value-add |

### Deferred / big commitments (decide per product need)
`kafka` (large / bind librdkafka) · full **YAML 1.2** (upgrade ymlz) · **Jinja** template engine ·
`imap` (only if a product ingests mail) · **`Reconcilable(T)`** (generalize axp `resource.zig`
desired/applied-generation + anti-brick rollback → k8s-controller-lite for config-mgmt/fleet) ·
`kv` on-disk/MVCC/txn/ordered-scans · pure-Zig SSH (post-binding) · OPC-UA (huge, IoT).

### Recommended sequence
1. **Wave 1 (cheap, high unlock, Opus, now):** `procrun` + `sessions`+CSRF → with adopted pg/smtp/ws/
   log/toml this makes ① a deployable backend stack.
2. **Wave 2 (Opus):** `jobqueue` · `llmclient` · `filestore`/`taskqueue`.
3. **Big cheap win (Opus, parallel track):** the **wgs data family** (`dataset`→`tabular`→
   `jsonshape`→`roquery`→`finstats`) → unlocks ⑤ wholesale; seeds ready.
4. **When Fable resets:** finish SNMP T-G/T-H, then `stun`/`sntp`/`syslog`, `exprcalc`, MQTT broker,
   coap C6/C7.
5. **Then decide:** `ssh` (bind), `grpc`, and the deferred big items per which product you commit to.

## Key decisions & deferred

- **TLS = proxy / bring-your-own.** The h2 stack takes an already-terminated (TLS) stream via the
  `serveStream` / `connectH2Over` + ALPN seam. 0.17 std TLS server is stalled (PR #23005); revisit
  when it ships or via an opportunistic ianic spike. kTLS = phase 2.
- **HTTP/2 is complete + deployable** — HPACK + framing + DoS-hardened h2c server + multiplexing client
  + BYO-TLS/ALPN seam. Optional future: concurrent stream multiplexing on the h2c *server* (today
  sequential-per-conn, bounded by the DoS caps).
- **MCP HTTP/SSE = drain-and-close**, not a held-open loop — io-less handlers can't park a connection
  on a future push; EventSource auto-reconnect + Last-Event-ID replay makes it lossless.
- **`kv` on-disk features deferred** — the randomized VOPR is done; MVCC/HAMT/ordered-scans/txns/
  secondary-indexes/cross-process-lock remain deferred.
- **Linux-only members accepted** (icmp/rawsock/netlink/wireguard/l2disco/procnet) — raw-syscall nature,
  no portable fallback.
- **ADOPT, don't build** (deps, not modules): regex (ezi-gex), JSON/serde (zimdjson), websocket.zig,
  libvaxis, std.compress decode. Full list in `docs/CANDIDATES.md`.
- **🐛 Dark-tests rule (found 2026-07-08):** `pub const x = @import("x.zig")` does NOT pull `x`'s tests
  into the module test binary — they run only via a `test { _ = x; }` aggregator (or refAllDecls).
  This hid 92 never-run tests (http + coap) and 3 latent bugs. Audited clean repo-wide; the
  files-vs-running test-count check is now on the pre-public list.

## Pre-public checklist (not started — deferred per user 2026-07-08)

- ✅ SPDX on every source file · Provenance line in every module README (incl. `probe`, added
  2026-07-08) · README module index kept current.
- 🟡 NOTICE covers all third-party design-refs + code lineage (metrics/validate/http gaps closed
  2026-07-08 doc-audit); a final completeness sweep — the NOTICE policy for pure-clean-room-from-RFC
  modules (whois/rdap/tar), the `Provenance:` line format consistency (13 modules use a bold-list
  variant), and the latency-stats/dns citation nits — is folded into the security/similarity review.
- ☐ **Security / similarity review pass** (adversarial multi-agent, Opus 4.8): `acme` JWS/CSR ·
  `aaa-gate`/`jwt` const-time + alg-confusion + JWKS smuggling + rotation · `snmp.usm` const-time +
  md5/sha1 alg-confusion · `kv` fault-sweep · `http` redirect/auth-strip + h2 DoS + the parser cluster
  (body/multipart/mcp-http/webhooksig/cookies/range/conneg) · `sealedbox`/`hashdigest` · `roquery`
  (once built). Plus the line-level provenance/similarity audit **and** the files-vs-running test-count
  check. Highest-value step before any release.
- ☐ Optional `testkit` shared harness (golden-diff / netns / VOPR helpers).
- ☐ Re-run the axp qemu `ubus -S` parity check against the extracted `blobmsg`.

## Build history — cumulative tests per commit (through the 27-module era)

Each module was independently re-verified (Debug + ReleaseFast + fmt) before commit.

| Module | Cumulative tests | Commit |
|---|---|---|
| `netaddr` + `http` client (TLS) | 56 | `55245f3` |
| `dns` + DoH | 98 | `400174a` |
| `http` server (Ph2) | 125 | `445f597` |
| `router` | 151 | `5741ce0` |
| `ratelimit` | 166 | `e28456a` |
| Licensing (MIT + NOTICE) | — | `29515a7` |
| `http` hardening (Ph2.1) | 176 | `6207c49` |
| `abuseguard` | 198 | `0d62a43` |
| `throttle` | 213 | `cab3480` |
| `security-headers` | 224 | `d02aa54` |
| `cors` | 238 | `0ce4c4d` |
| `metrics` | 254 | `2c5f1d7` |
| `validate` | 290 | `010bce7` |
| `resilience` | 310 | `820ceeb` |
| router route-enum + `openapi` | 321 | `c2e3119` |
| `acme` (Let's Encrypt) | 346 | `29e1435` |
| `http` gzip (Ph2.2) | 363 | `12683e4` |
| `netlink` | 393 | `4373dd7` |
| `decimal` | 411 | `85337ff` |
| `ramcache` (replaced stub) | 425 | `3fa82db` |
| `icmp` + `seqmap` | 456 | `7ff4d7c` |
| `aaa-gate` | 476 | `ca36228` |
| `mcp` | 500 | `c570ba2` |
| `kv` (flagship) | 529 | `bfdb009` |
| `blobmsg` (ubus) | 553 | `1e3836e` |
| `tar` | 573 | `15fbdc2` |
| license audit (SPDX+Provenance) | — | `8b9094e` |
| README module index | — | `b71377e` |
| `latency-stats` | 580 | `ea476cf` |
| `hashdigest` + `sealedbox` | 592 | `6ab35e8` |

Since then (2026-07-07 → 07-08), +22 modules and value-add passes to **49 modules / 1423 tests**:
the network tail (`wireguard`/`traceroute`/`probe`/`l2disco`), the HTTP/2 completion + hardening
batches, `modbus`/`whois`/`uci`/`rdap`/`mqtt`/`snmp`/`coap`, `jwt`/`upstream`/`mcp-http`, the
prod-API hardening + nice-to-have cluster (`requestid`/`health`/`conditional`/`multipart`/`cookies`/
`linkheader`/`idempotency`/`webhooksig`/`tracecontext`/`range`/`conneg`), and SNMP v3/USM.
Full detail: `git log` + each module's README + NOTICE.
