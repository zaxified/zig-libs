# zig-libs — execution plan

Sequenced build plan. Rule: **complex/high-value first, then extractions of what we already
have or will soon improve.** Dependency order forces a few foundations early (noted).
Catalog + per-module descriptions: `zig-libs-plan.md`. Context/rules: `BRIEF.md`.

Definition of done (every task): module folder created, `pub const meta` filled, public API +
doc-comments, tests, registered in `build.zig`, `zig build test-<name>` **and** `zig build test`
green, `README.md` written. Where an oracle exists (h2spec / golden bytes / live round-trip), run it.

---

## Wave P0 — complex & high-value

- **T1 `netaddr`** *(foundation for http/dns; small)* — extract from zig-fping `netutil.zig`.
  Spec: `SPEC-netaddr.md`.
- **T2 `http`** *(the ceiling; 3 consumers; unblocks dns/rdap/rest)* — Phase 1 = HTTP/1.1 client
  over TCP+TLS; Phase 2 = server codec; Phase 3 = HTTP/2 (framing+HPACK), verify **h2spec**.
  Spec: `SPEC-http.md`. Depends: T1.
- **T3 `dns` + DoH** — A/AAAA + PTR over UDP/TCP + DNS-over-HTTPS. Depends: T1, T2 (DoH), std.json.
- **T4 `netlink`** *(biggest unbuilt systems lever; standalone)* — rtnetlink transport
  (routes/links/neighbors); model libmnl/libnl. Verify in a netns.
- **T5 REST/API core** *(internet-behind-Caddy goal)* — in order: `router` → `ratelimit` →
  `abuseguard` → `throttle` → `openapi`. Depends: T2 (http server), later `aaa-gate`, `ramcache`.
- **T6 `kv`** *(research-grade; hardest; standalone)* — xitdb-style embedded KV + a VOPR-style
  deterministic fault-injection sim for reliability. Model xitdb / LMDB / TigerBeetle VOPR.
- **T7 `finstats` (advanced)** + **`exprcalc` (capstone)** — finstats standalone; exprcalc LAST
  (composes decimal/datefmt/tz/encoding/numparse + adopted regex).

## Wave P1 — soon-needed extractions (mostly lift-outs)

`ramcache` (poc-wf cache.zig — nearly copy-paste) · `netaddr` (done in T1) · `icmp`+`seqmap`
(zig-fping core) · `decimal` (bxp) · `blobmsg` (axp ubus) · `mcp` (bxp-mcp↔axp-mcp) ·
`aaa-gate` (axp rest.zig) · `testkit` (shared golden-diff/netns/VOPR harness).

## Wave P2 — remaining extractions & niceties

datefmt · tz · encoding · unaccent · numparse · tar · zipstream · blobstore · csvstream ·
csvsafe · diagnostics · procnet · argsafe · sealedbox · hashdigest · validate · cors ·
resilience · metrics · stun · sntp · latency-stats · traceroute · probe · rawsock · wireguard ·
nftables · uci · l2disco · ipcbus · pollworker · chunkframe · lenframe/jsonwire · whois · rdap · modbus.

---

## Progress

- ✅ **T1 `netaddr`** — done + verified (RFC 6724, zero-alloc). Committed.
- ✅ **T2 `http` Phase 1** — done + verified (HTTP/1.1 client over TLS). Committed `55245f3`.
- ✅ **T2 `http` Phase 2** — done + verified (HTTP/1.1 server codec + serving loop, `http.Server`; 125/125). Committed `445f597`. *(Ph3 h2 = later.)*
- ✅ **T3 `dns` + DoH** — done + verified (codec golden/fuzz, UDP+TC→TCP, TCP, DoH POST/GET + DoH-JSON,
  hosts/resolv.conf/search, PTR via netaddr; live round-trips green, skip cleanly in a netns). Committed `400174a`.

- ✅ **T5.1 `router`** — done + verified (trie matcher, middleware struct, 404/405). Committed `5741ce0`.

- ✅ **T5.2 `ratelimit`** — done + verified (token bucket + 429/Retry-After, XFF rightmost-trusted). Committed `e28456a`.
- ✅ **Licensing** — MIT + NOTICE (fping attribution) + provenance discipline. Committed `29515a7`.
- ✅ **T5.3 `http.Server` hardening (Phase 2.1)** — done + verified (peer address + request index
  on `Request`, `on_connect` accept/reject + `activeConnections()`, ConnState observer,
  431/414/413 limits with streamed body cap, whole-request read deadline + write timeout;
  `ratelimit` peer fallback rewired). 176/176 Debug + ReleaseFast. Uncommitted (awaiting review).

## Scope note (2026-07-02): direct-internet is IN SCOPE

The API may run **directly on the internet without Caddy** → build the Web/API cluster **max
security / feature-rich** (abuseguard is NOT redundant; it's the edge). Consequence: peer IP = the
real client, so `http.Server` must expose it. TLS-terminating server + gzip response are noted as
later additions.

- ✅ **T5.4 `abuseguard`** — done + verified (per-IP/global conn caps, ban/greylist, strike→ban; 198/198). Committed `0d62a43`.
- ✅ **T5.5 `throttle`** — done + verified (max-in-flight semaphore, atomics-only; 503 +
  Retry-After middleware; optional bounded wait via Io futex + capped waiter queue;
  213/213 Debug + ReleaseFast, integration exercised over loopback). Uncommitted (awaiting review).

- ✅ **T5.5 `throttle`** — done + verified (max-in-flight semaphore + 503 load-shedding, bounded wait; 213/213). Committed `cab3480`.

- ✅ **T5.6 `security-headers`** — done + verified (stateless secure-by-default header middleware:
  HSTS/CSP-opt-in/nosniff/XFO-DENY/Referrer/Permissions/COOP/CORP/COEP-opt-in + Server replacement;
  precomputed values, allocation-free hot path; `@import("security-headers")` hyphen name proven;
  224/224 Debug + ReleaseFast, integration over loopback). Uncommitted (awaiting review).

- ✅ **T5.6 `security-headers`** — done + verified (secure-by-default header middleware; 224/224). Committed `d02aa54`.

- ✅ **T5.7 `cors`** — done + verified (global-middleware CORS: preflight interception → 204 no-body
  before 404/405, origin/method/header gates, `.none` opt-in default, `*`+credentials rejected at
  init, reflect-or-list allowed headers, init-time joins = allocation-free hot path; 238/238 Debug +
  ReleaseFast, integration over loopback). Uncommitted (awaiting review).

- ✅ **T5.7 `cors`** — done + verified (global-middleware CORS; 238/238). Committed `0ce4c4d`.

- ✅ **T5.8 `metrics`** — done + verified (thread-safe registry: atomic counter/gauge +
  spinlocked histogram, get-or-register semantics per client_golang; exact Prometheus text
  exposition incl. escaping + cumulative `le="+Inf"` buckets, golden-byte tested; `Endpoint`
  intercepting middleware serves GET/HEAD /metrics (router.Handler can't close over state —
  documented deviation); `RequestMetrics` middleware records method+class counter, latency
  histogram (injectable clock), in-flight gauge + access-log hook; cardinality footgun
  documented, route-pattern label deferred until router exposes matched patterns;
  254/254 Debug + ReleaseFast, integration over loopback). Uncommitted (awaiting review).

## Current agent assignment

**T5.8 `metrics`** (spec: `SPEC-metrics.md`) — thread-safe registry (counter/gauge/histogram) +
Prometheus text exposition + `/metrics` handler + request-metrics middleware. Read `BRIEF.md`,
`CONVENTIONS.md`, `SPEC-metrics.md`. Then: `validate` → `resilience` → (router route-enumeration) → `openapi`.
