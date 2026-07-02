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

## Current agent assignment

**First run (Fable5): T1 `netaddr` → T2 `http` Phase 1 (HTTP/1.1 client + TLS).**
Server codec (T2 Ph2) and HTTP/2 (T2 Ph3) are deferred to follow-up specs. Do not start h2 yet.
Read `BRIEF.md`, `CONVENTIONS.md`, `SPEC-netaddr.md`, `SPEC-http.md` first.
