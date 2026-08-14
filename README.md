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

**Status:** 225 modules (Zig 0.16, green in all three release lanes — `ReleaseSafe`,
`ReleaseFast`, `-Dstrict-debug`) · **MIT** (see `LICENSE`). `NOTICE` answers one question —
whether consuming zig-libs obliges you to anything beyond MIT — and lists the modules that
carry their own attribution; it does not catalogue provenance.

## Using a module

- **Local path (dev, no tags/push):** in the consumer's `build.zig.zon`,
  `.zig_libs = .{ .path = "../zig-libs" }`, then in `build.zig`
  `exe.root_module.addImport("http", b.dependency("zig_libs", .{}).module("http"));`
- **Fetch:** `zig fetch --save git+https://github.com/.../zig-libs` then the same `dependency().module(...)`.
  (`zig fetch` can't target a subdirectory — ziglang/zig#23012 — so the whole repo is one package;
  you still import only the module you name. Unused modules aren't compiled.)
- **Pin for reproducible builds:** `zig fetch --save git+https://github.com/.../zig-libs#<tag-or-commit>`
  — pin a release tag or commit, never a branch; `CHANGELOG.md` says what each release changed.

## Build

```
zig build test           # run all module tests
zig build test-<name>    # run one module's tests
zig build check-catalog  # verify build.zig's module_list ↔ modules/ ↔ this README agree
zig build check-changelog # verify every module has a dated, well-formed CHANGELOG.md
```

`zig build -l` lists the rest, including the other `check-*` gates.

## Versioning & stability

Releases are dated git tags (`YYYY-MM-DD`), **not** semantic versions, and there are no
per-module versions; a tag asserts exactly one thing, that every module passed every lane at
that commit. `scripts/tag.sh` cuts one. `v0.1.0` remains as history and is still the only tag
in the repository — no dated release has been cut yet, so pin a commit until one is. Detail
lives in `modules/<name>/CHANGELOG.md` with breaking changes flagged `BREAKING`;
`zig build check-changelog` enforces that every module has one and that it is dated and
well-formed. The root `CHANGELOG.md` carries the release policy and per-release notes — it
stopped indexing which modules have a changelog on 2026-08-14, since all of them do and the
index was a copy kept only so a gate could notice the copy had gone stale. Module maturity is carried
by the explicit caveat lines in the catalog
below (and each module's `SPEC.md`), not by stability-tier labels — every module meets the
same bar (tests green in all three release lanes — `ReleaseSafe`, `ReleaseFast`,
`-Dstrict-debug` — plus oracle/KAT verification where one exists);
what varies is *scope*, and anything unfinished is stated where it lives. The full
versioning + spin-off policy is `CONVENTIONS.md` §8.

## Layout & conventions

```
build.zig      # single root build — registers every module by name + a test step each
build.zig.zon  # one package manifest for the whole collection
CHANGELOG.md   # per-release changes, grouped by module
CONVENTIONS.md # naming + `meta` tag vocabulary + provenance/SPDX + versioning rules
modules/<name>/src/root.zig  # `// SPDX-License-Identifier: MIT`, `pub const meta`, API, tests
modules/<name>/README.md     # what it is + a Provenance line
modules/<name>/SPEC.md       # wire format, limits, anchoring, what is deliberately not done
modules/<name>/CHANGELOG.md  # dated entries, breaking changes flagged
modules/<name>/NOTICE        # only when something is attributed or a provenance argument is needed
```

`CONVENTIONS.md` has the full rules; `modules/_template/` is the starting point for a new module.
Roadmap notes live in the "Roadmap / not yet built" section below and the git history.

## Licensing

zig-libs is MIT. Using or redistributing it requires nothing beyond the MIT license's own terms.

Detailed provenance — third-party origin, design references and any upstream license notices — is
recorded with each module that has any, not at the repository root.

## Modules

Every module is imported by its `name` (`@import("http")`); hyphenated names work too
(`@import("security-headers")`). `Deps` are sibling modules; everything else is `std`-only.

### Web / HTTP & API — an internet-facing service, no reverse proxy required

| Module | What it does | Platform | Deps |
|---|---|---|---|
| `http` | HTTP/1.1 client **and** server, hardened for direct exposure (slowloris caps, gzip, multipart, Range, negotiation); also speaks HTTP/2 (h2c/h2 client+server). Not `std.http`. | any | netaddr |
| `router` | REST routing — trie matcher (params/wildcards), middleware chain, groups, 404/405 | any | http |
| `ratelimit` | Token-bucket per-client rate limit → 429 + Retry-After; per-user connection-rate limit for `on_connect` | any | router, http, netaddr |
| `abuseguard` | Per-IP + global connection caps, ban/greylist, strike→ban (accept-time) | posix | http, netaddr, router |
| `throttle` | Global concurrency limit + load-shedding → 503 | posix | router, http |
| `security-headers` | Secure-by-default response headers (HSTS/CSP/nosniff/frame/referrer/COOP/CORP) | any | router, http |
| `cors` | CORS preflight + header injection (secure defaults) | any | router, http |
| `validate` | Request body/query/params validation → aggregated 400 (typed + schema + string-format checks) + JSON DoS caps (depth/array/field size) | any | router, http, netaddr |
| `metrics` | Prometheus registry (counter/gauge/histogram) + `/metrics` + request middleware + access-log writer (combined/JSON) | posix | router, http |
| `health` | Liveness (`/healthz`) + readiness (`/readyz`) probe middleware — 200/503 from registered dependency checks (k8s probe contract) | any | router, http |
| `requestid` | Request/correlation-ID middleware — adopts incoming `X-Request-Id` or generates one, echoes on response, exposed via `current()` | any | router, http |
| `tracecontext` | W3C Trace Context — `traceparent`/`tracestate` parse + generate + propagation middleware (child span per hop) for distributed tracing | any | router, http |
| `webhooksig` | HMAC webhook signatures (GitHub-style `sha256=<hex>`) — sign/verify (constant-time) + gating middleware, key rotation. Stripe's scheme not implemented | any | router, http |
| `idempotency` | Idempotency-Key dedup of unsafe retries — middleware + ramcache-backed store replaying a cached response without re-running the handler | any | router, http, ramcache |
| `resilience` | Circuit breaker + retry/backoff + timeout + bulkhead (concurrency limiter) for calling upstreams (generic) | posix | — |
| `upstream` | Load-balanced upstream pool + failover — round-robin/weighted/least-conn/EWMA, per-upstream breaker+bulkhead, active+passive health checks | any | resilience, probe |
| `openapi` | OpenAPI 3.1 spec generated from the route table + `/openapi.json` | any | router, http |
| `aaa-gate` | Bearer + API-key auth (constant-time) + audit hook + denied-request throttle | any | router, http |
| `jwt` | JWT/JWS + OIDC resource-server validator — parse/claims/verify (HS/ES/EdDSA/RSA, alg-confusion-safe), JWKS-by-kid, OIDC discovery, plus a router Bearer middleware | any | http, router, p256 |
| `rbac` | Authorization decision engine — NIST RBAC (hierarchical + static SoD) and a depth-bounded ABAC condition-tree evaluator with structural default-deny | any | — |
| `xml` | Namespace-aware, security-hardened XML 1.0 parser → C14N-ready infoset tree; DOCTYPE-reject default blocks XXE/billion-laughs/depth-bomb. Foundation for `xmldsig`/`saml` | any | — |
| `xmldsig` | XML Canonicalization (C14N) + XML-Signature **verification only** — RSA/ECDSA, algorithm allow-list (XSLT/XPath rejected); KeyInfo cert is untrusted, caller must pin trust | any | xml, rsa, p256 |
| `saml` | SAML 2.0 SSO **service-provider** — XSW-hardened Response verification against an IdP key, AuthnRequest builder, IdP-metadata parser; decrypts `EncryptedAssertion` via `xmlenc` | any | xmldsig, xml, xmlenc, rsa, x509, datefmt |
| `aescbc` | Raw AES-CBC (NIST SP800-38A) + PKCS#7/XML-Enc padding helpers, zero-alloc; padding-oracle caveat — consumers own authenticate-before-unpad | any | — |
| `aeskw` | RFC 3394 AES Key Wrap (AES-128/256 KEK) — constant-time integrity check + scratch zeroization, byte-exact vs RFC 3394 test vectors | any | — |
| `xmlenc` | XML-Encryption (xmlenc-core-1) **decryption only** — recovers `EncryptedAssertion` plaintext (RSA-OAEP/AES-KW key transport + AES-GCM/CBC content), decrypt-then-verify | any | xml, rsa, aescbc, aeskw |
| `jwe` | JSON Web Encryption (RFC 7516/7518) compact serialization — RSA-OAEP/AxxxKW/ECDH-ES key management + AES-GCM/CBC-HMAC content encryption; A192* unsupported (no AES-192 in std) | any | rsa, p256, aescbc, aeskw |
| `acme` | Let's Encrypt / ACME v2 (RFC 8555) — HTTP-01 issuance + renewal, ES256 JWS, CSR | any | http, router, entropy |
| `staticfiles` | Path-traversal-safe static file handler over `http` — MIME by extension, ETag/conditional 304, byte-range 206/416; symlinks not followed, dotfiles refused by default | any | http |
| `brotli` | Pure-Zig Brotli (RFC 7932) — byte-exact decompressor + a compressing encoder (LZ77 + Huffman, ~2.8x on text); the `Content-Encoding: br` companion to std gzip | any | — |
| `accesslog` | Structured HTTP access-log formatter — JSON Lines/logfmt/Apache Combined with log-injection escaping (untrusted UA/path/referer can't forge a line); http-request→Entry bridge | any | http |
| `websocket` | RFC 6455 WebSocket — handshake + frame layer (masking, fragmentation, UTF-8 validation, size caps), transport-agnostic client + server; no permessage-deflate | any | http |
| `sessions` | Server-side web sessions + OWASP-hardened cookies + signed double-submit CSRF middleware | any | router, http, cookies, ramcache, entropy |
| `llmclient` | Anthropic Messages API client (buffered + streaming SSE) over `http` — no third-party SDK | any | http |
| `grpc` | gRPC client **and** server over HTTP/2 (over `protobuf`) — no code generation; all four call shapes (unary/streaming/bidi); untrusted declared length never sizes an allocation | any | http, protobuf |

### Networking

| Module | What it does | Platform | Deps |
|---|---|---|---|
| `netaddr` | IP parse/format (RFC 5952) + RFC 6724 source/dest selection + CIDR/Prefix ops (contains/overlaps/supernet, range↔prefix) | any | — |
| `dns` | RFC 1035 resolver — A/AAAA/PTR/CNAME/NS/MX/TXT/SOA/SRV/CAA over UDP/TCP + DoH | any | netaddr, http |
| `dnssec` | Resolver-side DNSSEC validation (RFC 4033/4034/4035 + NSEC3) — DNSKEY/RRSIG/DS parsing, signature verify (ECDSA/Ed25519/RSA), NSEC/NSEC3 denial-of-existence | any | dns, rsa |
| `netlink` | rtnetlink read **and** write — dumps (links/addresses/routes/neighbors) and RTM_NEW*/DEL* writes; byte-exact vs iproute2 goldens + netns round-trip | **linux** | — |
| `genetlink` | Generic-netlink (genl) transport — genlmsghdr framing + nlctrl family-id resolution; shared foundation for ethtool/devlink/nl80211/wireguard clients | **linux** | netlink |
| `nl80211` | Wi-Fi control over nl80211 genetlink — interface/wiphy enumeration, scan trigger + BSS results, connect/disconnect, station/link stats, regulatory domain | **linux** | genetlink, netlink |
| `devlink` | Linux devlink over genetlink — device/port enumeration, port split/unsplit, parameter/resource inspection, region snapshots, health reporters, eswitch mode | **linux** | genetlink, netlink |
| `ethtool` | Ethernet device control over the ethtool netlink family — link settings/state, ring/coalesce/pause/channel params, feature flags, per-queue/driver stats | **linux** | genetlink, netlink |
| `wireguard` | Native WireGuard device config over genetlink (retires `wg` shell-outs), plus the Noise_IKpsk2 handshake **and** the transport-data seal/open crypto data plane | **linux** | netlink, genetlink, chachapoly, entropy |
| `tc` | Traffic control over rtnetlink — qdiscs (netem/htb/tbf/fq_codel/cake), htb classes, u32/flower filters + action families; byte-exact to iproute2 (retires `tc` shell-outs) | **linux** | netlink |
| `tcplan` | Compiles a hierarchical shaping topology (site→AP→subscriber) into a deterministic ordered plan of `tc` ops — mq root + per-CPU HTB trees + CAKE leaves; pure, caller executes | linux | tc |
| `nftables` | Typed firewall-ruleset builder → libnftables JSON for `nft -j -f -` (families/chains/rules/sets, match + verdict statements) | any (apply: linux) | netlink |
| `bacnet` | BACnet building automation over BACnet/IP **and** BACnet/SC — BVLL/BVLC framing, core APDU services (Read/WriteProperty, WhoIs/IAm, COV), SC secure-connect over `websocket` | any | netaddr, websocket |
| `s7comm` | Siemens S7 communication — ISO-on-TCP (RFC 1006) plus S7 protocol: connection setup, area read/write (DB/M/I/Q/T/C), PLC info and cyclic services | any | — |
| `enip` | EtherNet/IP + CIP — encapsulation layer (register/SendRRData/SendUnitData), CIP messaging, connection manager, tag/symbolic path client for Logix controllers | any | netaddr |
| `iec62351` | IEC 62351 power-systems security — GOOSE/SV authentication (62351-6) over caller-supplied PDU bytes, MMS application authentication (62351-4), checkable TLS policy | any | x509, rsa |
| `iec61850` | IEC 61850 substation automation — MMS (ISO 9506) client over ISO-on-TCP with the ACSI object model, plus GOOSE publish/subscribe + SV sampled values | any | xml |
| `fleetsim` | In-process simulated device fleet — hosts protocol responders (Modbus, DNP3, IEC 104, S7comm, BACnet, EtherNet/IP, OPC UA) as nodes on one deterministic scheduler | any | modbus, dnp3, iec104, s7comm, bacnet, enip, opcua, netsim |
| `smtp` | SMTP client (RFC 5321) — ESMTP EHLO negotiation, STARTTLS seam, AUTH PLAIN/LOGIN, pipelining, MIME message composition (RFC 5322/2045) | any | netaddr |
| `imap` | IMAP4rev2 (RFC 9051) client — mailbox-name codec, wire grammar, FETCH/ENVELOPE/BODYSTRUCTURE, SEARCH, IDLE; transport-agnostic (owns no socket, speaks no TLS) | any | — |
| `iec104` | IEC 60870-5-104 telecontrol — APCI/APDU framing, I/S/U formats with k/w flow control, ASDU codec, transport-agnostic master (controlling station) | any | — |
| `modbus` | Modbus TCP (MBAP) + RTU (CRC-16) codec, master client **and slave server** — core function codes, diagnostics, exceptions, transport-agnostic seam | any | — |
| `mqtt` | MQTT 3.1.1 client — all 14 control packets, QoS 0/1/2 state machine, topic-filter wildcards, transport-agnostic seam | any | — |
| `coap` | CoAP (RFC 7252) — full client **and** server stack: message codec, options (URI↔options), reliability (CON retransmission + dedup), correlated client/server. Zero-alloc | any | — |
| `snmp` | SNMP v1/v2c/v3 — BER/ASN.1 codec, manager client (get/next/bulk/set/walk) + trap/notification receiver + USM auth (HMAC-MD5/SHA-1, constant-time); privacy crypto in progress | any | — |
| `dnp3` | DNP3 (IEEE 1815) base protocol — data-link framing + CRC-16/DNP, application layer, core object library; master + outstation. Secure Auth (g120) scaffolded only, no crypto | any | aeskw |
| `opcua` | OPC-UA (IEC 62541) **client and server** — opc.tcp transport, secure channel (Basic256Sha256 on client, None-only on server), sessions, Read/Write/Browse/Call + subscriptions | any | rsa, x509 |
| `whois` | RFC 3912 whois client — query format + referral chasing (IANA→registrar) + field extraction, transport-agnostic seam | any | netaddr |
| `rdap` | RDAP client (RFC 7480–7484) — JSON-over-HTTPS whois successor: query URLs, typed response model, IANA bootstrap, fetch seam | any | http, netaddr |
| `icmp` | ICMP echo (ping) engine — v4/v6 codec, batched socket, pacing | **linux** | seqmap, netaddr |
| `traceroute` | ICMP-echo path discovery — TTL-stepped probes, per-hop address + RTT stats, load-balanced-path aware | **linux** | icmp, netaddr, latency-stats |
| `probe` | TCP-connect reachability prober — up/refused/timeout + RTT, fan-out with bounded concurrency, latency aggregation | any | netaddr, latency-stats |
| `l2disco` | Layer-2/neighbor discovery codec — LLDP (802.1AB) + CDP + ARP (RFC 826) + DHCP options (RFC 2131/2132) + MAC helper | any | netaddr |
| `isis` | IS-IS (ISO/IEC 10589) PDU codec — common header + TLV framework + IIH/LSP PDUs + SPB (802.1aq) TLVs; pure bounds-checked encode/decode, wire foundation for an SPB control plane | any | — |
| `isis-adj` | IS-IS point-to-point adjacency state machine (ISO 10589 §8.2 + RFC 5303) — pure time-injected FSM driving one P2P neighbour Down→Init→Up from IIH PDUs | any | isis |
| `isis-dis` | IS-IS LAN Designated-IS election (ISO 10589 §8.4.5) — elects DIS from priority + SNPA (tie-break, preemptive), derives the pseudonode LSP-ID; pure time-injected | any | isis |
| `isis-lsdb` | IS-IS link-state database — stores LSPs by LSP-ID, ISO 10589 §7.3 newer-LSP comparison, time-injected aging + MaxAge purge, per-interface SRM/SSN flooding flags; pure | any | isis |
| `isis-flood` | IS-IS flooding transmit scheduler — drains `isis-lsdb` SRM/SSN flags into ordered PDUs to send, paces LSP (re)transmission + periodic CSNPs; pure time-injected | any | isis, isis-lsdb |
| `isis-spf` | Computes IS-IS shortest-path forwarding table from an `isis-lsdb` — TLVs → topology graph → Dijkstra + ECT tie-break → route table (dest → next-hop + metric); pure | any | isis, isis-lsdb, spf-ect |
| `isis-sim` | Headless multi-node IS-IS/SPB fabric convergence simulator over `netsim` — asserts LSDBs synchronise and reconverge after an injected link failure | any | netsim, isis, isis-lsdb, isis-flood, isis-spf |
| `seqmap` | Fixed 65,536-slot 16-bit request/reply correlation map, O(1) | any | — |
| `latency-stats` | Online RTT stats — min/max/mean/stddev + RFC 3550 jitter + loss %, O(1)/sample, no alloc; plus an HdrHistogram for bounded-error percentiles (p50–p99.9) | any | — |
| `pping` | Passive RTT estimation from TCP TSval/TSecr echo matching (RFC 7323 / Pollere pping) — bounded per-direction table, no double-counting of duplicate/delayed ACKs | any | — |
| `procnet` | Linux `/proc`+`/sys` parsers — ARP/routes/TCP+UDP sockets/conntrack/process stats/device health, typed | **linux** | netaddr |
| `conntrack` | Linux ctnetlink (NETLINK_NETFILTER) client — typed conntrack flow dump/get/delete plus event subscription, over `netlink`'s write engine | **linux** | netlink, netaddr |
| `rawsock` | Linux AF_PACKET raw-frame capture + inject — BPF filter, promiscuous mode, typed frame decode | **linux** | netaddr |
| `stun` | STUN client (RFC 8489) — NAT reflexive-address discovery: XOR-MAPPED-ADDRESS + MESSAGE-INTEGRITY + FINGERPRINT | any | netaddr |
| `sntp` | SNTP client (RFC 4330) — NTP packet codec + UDP query, clock offset / round-trip delay | any | — |
| `syslog` | RFC 5424 syslog formatter + emitter, RFC 3164 legacy encoder, RFC 6587 TCP octet framing | any | — |
| `ssh` | SSH-2.0 (RFC 4253) **client + server** — KEX incl. ML-KEM-768 hybrid, userauth (publickey/password) + channels (exec/subsystem); vs OpenSSH-validated. **Linux-only** | linux | rsa |
| `netconf` | NETCONF client (RFC 6241) over SSH — RFC 6242 framing, hello/capability exchange, get/get-config/edit-config/commit RPCs with typed replies | any | ssh, xml |
| `ebpf` | eBPF program generation over `std.os.linux.bpf` — bytecode builders (kprobe counter, XDP filter, ring-buffer emitter); real-kernel verifier acceptance unverified in CI | **linux** | netlink |
| `xdp-classifier` | XDP packet classifier for a LibreQoS-style edge shaper — IPv4 prefix→traffic-class via LPM-trie lookup, per-CPU scratch handoff, CPUMAP steering (bpf_redirect_map) | **linux** | ebpf |
| `testkit` | Test-only shared harness (hex decoding for KAT vectors, golden byte-comparison, verbose-skip convention); wired via build.zig test_deps, absent from consumer imports | any | — |
| `netsim` | Deterministic seeded discrete-event network simulator (latency/loss/partition/clock-skew, failure fuzzer, byte-exact replay) — model-checking harness for fabric algorithms | any | — |
| `spf-ect` | Deterministic symmetric shortest-path (Dijkstra) with a reversal-invariant ECT tie-break (RFC 6329 idea generalized) + maximally-disjoint second tree; pure graph algorithm | any | — |
| `loopfree-reconv` | Loop-free reconvergence transitions — two-class ordered-FIB schedule (provably no transient forwarding loop, TTL backstop); netsim-verified under fuzzing | any | netsim, spf-ect |
| `df-elect` | Partition-correct Designated-Forwarder election (static link-state total order, duplicate-freedom argument) + split-horizon; bounded-badness model-checked in netsim | any | netsim |
| `raft` | Raft consensus (Ongaro & Ousterhout) — leader election + log replication, model-checked in netsim against all five formal safety properties; membership changes are design-only | any | netsim |
| `reconcilable` | Generic desired-vs-actual reconciler (controller-runtime shape) — bounded, deduplicating work queue with backoff+jitter; caller-driven `tick()`, no clock or thread | any | resilience |
| `liveness-hyst` | BFD-like link-liveness estimator with EWMA hysteresis — echo-probe timing + jitter/loss stats, Babel-style metric smoothing; fast detection without flap-driven oscillation | any | netsim, latency-stats |
| `loopix` | Loopix mixnet (Piotrowska et al. — Nym's design) — Poisson mix + cover traffic over `sphinx`, model-checked in netsim against a global-passive-adversary anonymity invariant | any | netsim, sphinx |
| `workerpool` | In-process fixed-width worker pool over `lockfree.MpmcQueue` — type-erased closure jobs, Io-futex idle wakeup (no busy-spin, no lost-wakeup), graceful drain / abrupt shutdown | any | lockfree |
| `shardstore` | Key-sharding router over N independent `kvtree` stores — multi-core write parallelism (per-shard single-writer, cross-shard parallel) | any | kvtree |
| `writebehind` | Crash-safe write-behind cache coordinator — fast in-memory acks, async flush to a durable `Sink` via `workerpool`; WAL written before ack so a crash-recovered write survives | any | ramcache, workerpool, jobqueue, kvtree |
| `readthrough` | Backend-agnostic read-through cache coordinator — serve-from-cache or single-flight-coalesce a miss into one backend fetch, TTL + invalidation + negative caching | any | ramcache |
| `pagecache` | Bounded write-through page cache between `kvtree`'s pager and its `Storage` — hot-cold tiering (W-TinyLFU via ramcache) with an RSS budget; transparent to callers | any | kvtree, ramcache |
| `lockfree` | Lock-free concurrency primitives for shared-memory worker pools — Michael & Scott MPMC queue + Fraser/crossbeam epoch-based reclamation, under a strict seq_cst discipline | any | — |
| `ethfrag` | Hardened inner-frame fragmentation/reassembly codec — RFC 5722 overlap rejection, bounded per-datagram memory, caller-clocked timeout, fuzz-tested never-panic | any | — |
| `l2encap` | Tenant-tagged (24-bit I-SID) L2-over-tunnel encapsulation for a multi-tenant L2VPN fabric — lean versioned header over a customer Ethernet frame; bounds-checked decode | any | — |
| `l2forward` | E-LAN edge forwarding table — per-I-SID customer-MAC learning (MAC→remote PE) with aging + BUM ingress-replication set + split-horizon; pairs with `l2encap` | any | — |
| `pbb` | IEEE 802.1ah Provider Backbone Bridge (MAC-in-MAC) codec — wraps a customer frame in a backbone header + I-TAG (24-bit I-SID); real-Ethernet SPB encap, distinct from `l2encap` | any | — |
| `bumtree` | SPB per-source loop-free BUM distribution tree + RPF check over `spf-ect` — per-node replication next-hops (pruned source SPT) + single RPF ingress for an I-SID member set | any | spf-ect |
| `spbfib` | SPB (802.1aq) forwarding addressing — unicast B-MAC FIB from an `isis-spf` route table + SPBM multicast-DA construction; one congruent ECT path per dest, no per-flow ECMP | any | isis-spf |

### Data & storage

| Module | What it does | Platform | Deps |
|---|---|---|---|
| `kv` | Crash-consistent embedded KV store, Bitcask-style log, with randomized fuzz-tested crash recovery. | any | — |
| `tsdb` | Time-series persistence over `kvtree` — ordered (series, timestamp) key codec, streaming range scans, crash-safe retention-by-age. | any | kvtree |
| `kvtree` | Ordered transactional KV store — copy-on-write B-tree (LMDB/BoltDB lineage), MVCC snapshots, crash-safe range scans. | any | kv |
| `ramcache` | Bounded in-memory cache — W-TinyLFU admission/eviction, TTL, generation invalidation; sharded thread-safe wrapper. | any | — |
| `decimal` | Exact i128 fixed-point decimal for money math, float-free, with IEEE/GDA rounding modes and rescale. | any | — |
| `jobqueue` | Durable background-job queue over `kv` — lease/retry/dead-letter queue, per-partition FIFO under priority. | posix | kv |
| `blobstore` | Content-addressed blob store (git-object/restic style), plus name-addressed and small named-record layers; crash-safe. | posix | hashdigest |
| `filestore` | DB-less durable keyed document store — one atomically-written file per record, plus a typed-JSON convenience layer. | posix | — |
| `dataset` | Canonical in-memory columnar-typed table — the normalization seam between data sources and consumers. | any | — |
| `tabular` | Dataset algebra (pandas/dplyr-style verbs) over `dataset` — aggregate/pivot/resample/rolling/join, fx-aware. | any | dataset |
| `jsonshape` | JSON → `dataset` reshaping — dot-path descent and typed column projection (a minimal jq-style subset). | any | dataset |
| `finstats` | Portfolio/financial statistics over `dataset` — XIRR, TWR, risk, beta, Monte-Carlo, correlation matrix. | any | dataset |
| `trie` | Prefix index for instant autocomplete over a large static string set. | any | — |
| `fuzzysearch` | Bounded-edit-distance typo-tolerant lookup over a static string set — DoS-bounded, the typo-tolerant sibling of `trie`. | any | trie |
| `geoindex` | Static spatial index for bbox and nearest-neighbour queries over a large fixed geo-point set — DoS-bounded, zero-copy. | any | — |

### Crypto

| Module | What it does | Platform | Deps |
|---|---|---|---|
| `entropy` | Fail-closed entropy source — `fill` draws from `std.Io.randomSecure` or aborts the process; no generator, no silent degrade. **Panics on failure.** | any | — |
| `hashdigest` | Streaming digests — one-shot, incremental, and file hashing; SHA-256 convenience plus a multi-algorithm SHA-2/SHA-3/BLAKE2b/BLAKE3 layer. | any | — |
| `ripemd160` | RIPEMD-160 (ISO/IEC 10118-3) streaming hash, plus `hash160` (`RIPEMD160(SHA256(x))`), the Bitcoin pubkey-hash primitive. | any | — |
| `bech32` | Bitcoin address encodings — bech32 (BIP173) / bech32m (BIP350) codec, segwit address encode/decode, base58check, P2PKH/P2WPKH. | any | ripemd160 |
| `sealedbox` | NaCl `crypto_box_seal` — anonymous-sender X25519 public-key encryption, plus base64/hex key serialization. | any | — |
| `minisign` | minisign file format (jedisct1/minisign) — Ed25519 sign/verify for signed files/releases, including scrypt-encrypted secret keys. | any | entropy |
| `rsa` | Pure-Zig RSA (PKCS#1 v2.2, RFC 8017) — keygen, PKCS1-v1.5/PSS sign+verify, OAEP/PKCS1 encrypt+decrypt, DER/PEM/OpenSSH key parsing. | any | montint |
| `x509` | X.509 certificate-chain / path validation (RFC 5280 §6) — trust-store chain building, extension, name, and signature checks. | any | rsa |
| `paillier` | Paillier additively-homomorphic public-key encryption (EUROCRYPT 1999) — 2048-bit keygen, encrypt/decrypt, homomorphic add; const-time decrypt path. | any | montint |
| `threshold_ecdsa` | GG20 threshold ECDSA over secp256k1 (t-of-n) — dealer keygen through online signing, producing standard verifiable ECDSA sigs. **Audit warranted before production use.** | any | paillier, montint |
| `dkg` | Dealer-free Distributed Key Generation (GJKR) for `threshold_ecdsa` — bias-resistant secp256k1 key sharing feeding threshold signing. | any | threshold_ecdsa, paillier |
| `vdf` | Wesolowski Verifiable Delay Function over an RSA hidden-order group — sequential-squaring delay with prove/verify. A caller-supplied modulus needs a trusted setup. | any | montint |
| `montint` | Constant-time Montgomery modular arithmetic over arbitrary odd moduli — faster native-Zig alternative to `std.crypto.ff`, x86-64 asm + portable fallback. | x86-64 asm + portable fallback | — |
| `chachapoly` | SIMD-accelerated ChaCha20-Poly1305 AEAD (RFC 8439) — a throughput-specialized, byte-exact duplicate of `std.crypto.aead.chacha_poly`. | any (SIMD via `@Vector`) | — |
| `aeadframe` | Per-key AEAD record layer — seal/open with a monotonic nonce (never reused), epoch rekey, anti-replay window, AAD binding. | any | chachapoly |
| `tenantkex` | Per-tenant key exchange — a Noise_IK handshake (via `noise`) between provider edges, deriving directional channel keys for `aeadframe`. | any | noise |
| `k256` | asm-accelerated secp256k1 — Solinas field + GLV verify, bit-exact vs `std.crypto.ecc.Secp256k1`/BIP340. GLV is vartime/public-only, not for secrets. | amd64 asm + portable fallback | — |
| `p256` | asm-accelerated NIST P-256 — Solinas field, constant-time comb sign, vartime wNAF verify; bit-exact vs `std.crypto.ecc.P256` and RFC 6979. | amd64 asm + portable fallback | — |
| `bip32` | BIP-39 mnemonic seed phrases + BIP-32 hierarchical-deterministic keys over secp256k1 — the wallet key-derivation foundation. | any | k256, ripemd160, bech32 |
| `blindrsa` | RSA Blind Signatures (RFC 9474, RSABSSA) over `rsa` — the anonymous-token / Privacy Pass primitive: blind, sign, finalize, verify. | any | rsa |
| `signal` | Signal Protocol — X3DH key agreement, XEdDSA signing, and the Double Ratchet: E2EE sessions with forward secrecy and post-compromise security. | any | chachapoly, ct25519, entropy |
| `mls` | MLS — Messaging Layer Security (RFC 9420): cipher-suite/codec foundation plus TreeKEM (ratchet tree), for scalable group messaging. | any | hpke |
| `megolm` | Megolm — Matrix's group-messaging ratchet: a one-way HMAC hash ratchet (fast-forward only, never rewinds) plus Ed25519-signed message frames. | any | aescbc, entropy |
| `ed448` | Ed448 + X448 — the 448-bit "Goldilocks" curve (RFC 8032 + RFC 7748): constant-time X448 DH and Ed448/Ed448ph EdDSA signing. | any | entropy |
| `decaf448` | decaf448 prime-order group (RFC 9496) over `ed448` — eliminates cofactor-4 pitfalls for threshold signing, VRFs, anonymous credentials. | any | ed448 |
| `slhdsa` | SLH-DSA (FIPS 205, standardized SPHINCS+) — post-quantum stateless hash-based signatures, all twelve parameter sets, NIST-KAT-verified. | any | — |
| `falcon` | FN-DSA — Falcon-512 and Falcon-1024 NIST post-quantum lattice signatures: keygen, sign, verify, and key/signature codecs. | any | — |
| `hqc` | HQC — code-based post-quantum KEM, NIST's structurally-independent backup to lattice-based ML-KEM. Complete keygen, encrypt, decrypt. | any | — |
| `dtls` | DTLS 1.3 (RFC 9147), PSK mode — key schedule, AEAD record layer, handshake fragmentation/reassembly, anti-replay window. | any | rsa, x509, chachapoly |
| `ocsp` | RFC 6960 OCSP — build an OCSP request and cryptographically verify an OCSP response, for TLS OCSP-stapling. | any | x509, rsa, p256 |
| `ocspcache` | OCSP-stapling fetch + cache over `ocsp` — AIA responder discovery, verify-before-cache, refresh-ahead expiry, soft-fail on outage. | any | ocsp, http, x509 |
| `tlsresume` | Server-side TLS 1.3 session-ticket resumption (RFC 8446) — ticket seal/open, PSK binder derivation, 0-RTT early-data key schedule. | any | — |
| `quic-crypto` | RFC 9001 (TLS for QUIC) crypto seam — secret derivation, AEAD packet protection, header protection, key update; engine-agnostic. | any | chachapoly |
| `bip340` | BIP340 Schnorr signatures over secp256k1 (Bitcoin Taproot's signature scheme) — sign, verify, batch verify, x-only keys. | any | k256 |
| `taproot` | BIP341 Taproot key-path output-key tweaking — `tweakPublicKey`/`tweakSecretKey` built over `bip340`. | any | bip340, k256 |
| `bitcointx` | Bitcoin transaction (de)serialization + signature hashing — legacy, BIP143 segwit-v0, and BIP341 taproot key-path sighash. | any | bip340 |
| `psbt` | BIP174 Partially Signed Bitcoin Transaction (PSBT) v0 — binary (de)serialization plus the Combiner (merge) role, over `bitcointx`. | any | bitcointx, bitcoinscript |
| `bitcoinscript` | Bitcoin Script consensus interpreter — full opcode set, CHECKSIG/CHECKMULTISIG; verifies bare/P2SH/segwit/P2TR key-path scripts. | any | bitcointx, k256, bip340, ripemd160 |
| `btcp2p` | Bitcoin P2P wire-message codec — envelope, version/verack handshake, inventory/data messages. Codec only: no chain state or validation. | any | bitcointx |
| `musig2` | MuSig2 multi-signature (BIP327) producing BIP340 signatures — rogue-key-safe key aggregation, 2-round nonces, partial sign/verify. | any | bip340, k256 |
| `sphinx` | Lightning BOLT#4 Sphinx onion routing — forward ECDH blinding chain, layered packet construction, constant-time layer peeling. | any | k256 |
| `noise` | Generic Noise Protocol Framework (spec rev 34) — handshake patterns (NN/NK/XX/IK) over a comptime-parameterized DH/AEAD/hash suite. | any | chachapoly |
| `bolt8` | Lightning BOLT#8 encrypted transport (`Noise_XK_secp256k1_ChaChaPoly_SHA256`) — handshake plus transport with periodic key rotation. | any | noise, k256 |
| `bolt3` | Lightning BOLT#3 key derivation — per-commitment blinded keys, split-secret revocation keys, shachain secret generation. | any | k256 |
| `lnwire` | Lightning BOLT#1/2/7 wire messages — base frame, BigSize/TLV codec, channel-management and gossip messages, over `bolt8`. | any | — |
| `lninvoice` | Lightning BOLT#11 payment requests (+ BOLT#12 offer decode) — decode/verify and encode/sign, with node-pubkey signature recovery. | any | bech32, k256, lnwire, bip340 |
| `hpke` | HPKE — Hybrid Public Key Encryption (RFC 9180): DHKEM(X25519/P-256) encap/decap, all four key-schedule modes, AEAD seal/open + export. | any | p256, chachapoly, entropy |
| `adaptor` | Schnorr adaptor signatures over BIP340 (scriptless scripts for Lightning PTLCs / atomic swaps) — preSign, adapt, extract. | any | bip340, k256 |
| `frost` | FROST threshold Schnorr signatures (RFC 9591), secp256k1 — t-of-n keygen, 2-round signing, aggregate. **Not BIP340-compatible.** | any | bip340, k256 |
| `oscore` | OSCORE (RFC 8613) — end-to-end object security for CoAP: HKDF context derivation, AES-CCM AEAD, anti-replay sliding window. | any | — |
| `spake2plus` | SPAKE2+ — an augmented PAKE (RFC 9383), P-256/SHA-256 (the Matter/Thread commissioning PAKE); resists server-compromise. | any | p256 |
| `ct25519` | Constant-time-on-secrets scalar multiplication for Edwards25519/Ristretto255 — drops std's secret-dependent `rejectIdentity` branch. Caller must validate points. | any | — |
| `voprf` | (V)OPRF — Oblivious Pseudorandom Functions (RFC 9497), ristretto255-SHA-512: OPRF, verifiable, and partially-oblivious modes with DLEQ proofs. | any | ct25519 |
| `bulletproofs` | Bulletproofs — zero-knowledge range proofs over Ristretto255, proving a Pedersen-committed value is in range with logarithmic proof size. | linux | ct25519 |
| `ctap2pin` | CTAP2 `pinUvAuthProtocol` (FIDO2/WebAuthn) — both protocol versions: ECDH-P256 key agreement, encrypt/decrypt, authenticate/verify. | any | p256 |
| `webauthn` | WebAuthn / FIDO2 Relying-Party **verifier** (W3C Level 3) — assertion + registration ceremony checks, plus attestation verification. Verification only. | any | cbor, rsa, p256, x509 |
| `otp` | HOTP + TOTP one-time passwords (RFC 4226 / RFC 6238) — the 2FA-authenticator primitive; caller supplies the counter/time (no wall clock). | any | — |
| `xmss` | XMSS (RFC 8391), single-tree SHA-256 — **stateful** hash-based signatures. Index reuse breaks the scheme; `sign` advances the index first. | any | — |
| `bls12_381` | BLS12-381 pairing-friendly curve — field tower/groups, optimal-ate pairing, hash-to-curve, BLS signatures, KZG commitments, threshold BLS. | any | entropy |
| `bbs` | BBS selective-disclosure signatures over `bls12_381` (draft-irtf-cfrg-bbs-04) — sign many messages, later reveal a chosen subset in zero knowledge. | any | bls12_381, entropy |
| `coconut` | Coconut threshold-issuance anonymous credentials over `bls12_381` — t-of-n issued Pointcheval-Sanders credentials with selective-disclosure showing. | any | bls12_381 |
| `tlock` | drand-style timelock encryption (Boneh-Franklin IBE over `bls12_381`) — encrypt to a future drand round; decryptable once it publishes. Not post-quantum. | any | bls12_381, entropy |
| `drand` | drand randomness-beacon client — chain-info and round codec, BLS-verifies a round signature against the chain public key. Transport-agnostic. | any | bls12_381, tlock |
| `timelock_envelope` | Hybrid sealed envelope — unlocks only once both a drand timelock round publishes AND the recipient holds the PQ-KEM secret; AEAD-sealed content. | any | tlock, hqc, chachapoly, entropy |
| `ibe` | Standalone Boneh-Franklin Identity-Based Encryption over `bls12_381` — a self-run PKG extracts per-identity keys. Not post-quantum; key escrow is inherent. | any | bls12_381, entropy |
| `bn254` | BN254 / alt-bn128 curve — field tower/groups, optimal-ate pairing, EIP-196/197 EVM precompiles, and a Groth16 zkSNARK **verifier**. | any | — |
| `opaque` | OPAQUE — an asymmetric PAKE (RFC 9807), ristretto255-SHA-512 + 3DH — registration and login/AKE. Server compromise reveals no password. | any | voprf, ct25519 |
| `ecvrf` | ECVRF-EDWARDS25519-SHA512-TAI (RFC 9381 Verifiable Random Function) — prove/verify a deterministic, unbiasable output under a public key. | any | ct25519 |
| `fss` | Function Secret Sharing — 2-party single-point Distributed Point Function (BGI16), plus multi-point FSS; the primitive under `pir` and private analytics. | any | — |
| `pir` | Two-server Private Information Retrieval over `fss`'s DPF — fetch a record without either server learning the index. **Two colluding servers recover it immediately.** | any | fss |
| `bfv` | BFV leveled homomorphic encryption (Fan-Vercauteren) over `Z_q[X]/(X^N+1)`, RNS — exact-integer keygen/encrypt/decrypt/multiply/relinearize. **No security level claimed.** | any | entropy |
| `groth16` | Groth16 zk-SNARK **prover** over BN254 — R1CS→QAP, produces proofs `bn254.groth16Verify` accepts. `setup` is a toy, **insecure** trusted setup. | any | bn254 |
| `poseidon` | Poseidon — the ZK-friendly hash over prime fields (HADES permutation), for BN254 and BLS12-381; cheap Merkle/commitment hashing inside circuits. | any | bn254, bls12_381 |
| `rescue` | Rescue-Prime Optimized (RPO) — arithmetization-oriented hash over the Goldilocks field, the alternative to `poseidon` for STARK circuits. | any | — |
| `tfhe` | TFHE/FHEW programmable gate bootstrapping — unbounded-depth FHE via blind rotation over a power-of-two torus. **Toy parameters only, no security level claimed.** | any | entropy |

### Serialization / OS / agent

| Module | What it does | Platform | Deps |
|---|---|---|---|
| `tar` | ustar/GNU tar reader+writer (preserves uid/gid/mtime) + gzip. | any (packer: linux) | — |
| `linkheader` | Web Linking (RFC 8288) `Link` header build + parse (rel/title/type), plus `pagination` helpers and `find(rel)`; zero-alloc. | any | — |
| `cookies` | HTTP cookies (RFC 6265) — request `Cookie` parser plus `Set-Cookie` builder (Secure/HttpOnly/SameSite), injection-guarded. | any | http |
| `blobmsg` | OpenWRT ubus client + blob/blobmsg wire codec. | **linux** (codec itself: any) | — |
| `mcp` | Model Context Protocol server (JSON-RPC 2.0) — tools, resources, prompts, plus server→client sampling and elicitation requests. | any | — |
| `mcp-http` | MCP Streamable HTTP transport (2025-06-18) — `POST /mcp` with JSON or live SSE, resumable sessions, Origin (DNS-rebind) guard. | any | router, http, mcp |
| `uci` | OpenWRT UCI config parser + serializer + typed model, with stable round-trip. | any | — |
| `argsafe` | Allowlist validators + a typed argv builder — neutralizes argument/flag injection into an exec `argv`. | any | — |
| `procrun` | Subprocess runner — reap-race-tolerant wait, deadlock-free capped stdio capture, timeout, streaming, and cancel. | any | argsafe |
| `pollworker` | Single-owner `poll(2)` loop plus a lock-free fork/exec job table, for offloading blocking work off the loop thread. | **linux** | — |
| `ipcbus` | Same-host unix-socket control plane — a request/reply server plus a capped in-memory scratch key→bytes bus. | **linux** | framing |
| `sandbox` | Process self-hardening for an internet-facing server — privilege drop, `setrlimit`/no core dumps, Landlock fs allow-list, seccomp-bpf. | **linux** | — |
| `framing` | Length-prefixed stream framing (`writeFrame`/`readFrame`) plus a generic JSON tagged-union envelope codec. | any | — |
| `csvstream` | Streaming RFC 4180 CSV reader that preserves byte offsets, with bounded memory regardless of file size. | any | — |
| `csvsafe` | OWASP CSV formula-injection guard (`=`/`+`/`-`/`@` cell leads). | any | — |
| `json5` | Single-pass JSON5→JSON preprocessor (comments, unquoted keys, trailing commas, single-quoted strings). | any | — |
| `yaml` | YAML 1.2 reader (not 1.1) — scanner → parser → composer over the core schema (no `yes`/`no` booleans); cyclic aliases rejected. | any | — |
| `jinja` | Jinja2-compatible template engine — expressions, control flow, template inheritance/macros/imports, over a symlink-contained loader. | any | — |
| `cbor` | CBOR (RFC 8949) codec — all 8 major types, canonical encoding option, untrusted-input hardened; plus a minimal COSE (RFC 9052) layer. | any | — |
| `protobuf` | Protocol Buffers wire format (proto3) codec — schema derived at comptime from Zig structs, no `.proto` compiler; untrusted-input hardened. | any | — |
| `zipstream` | Streaming ZIP archive reader — walks the central directory once, streams decompressed member bytes on demand. | any | — |
| `encoding` | Legacy single-byte code page ↔ UTF-8 transcoding (5 European code pages: windows-125x, ISO-8859-1/2/15). | any | — |
| `datefmt` | Civil calendar plus token-based date/time parse/format and calendar arithmetic, correct before 1970. | any | — |
| `tz` | IANA time-zone offset lookup — zone name → UTC offset/DST at a given instant (600 zones + POSIX-TZ footer). | any | datefmt |
| `numparse` | Locale-aware grouped-number parsing (thousands/decimal separators) into an exact `decimal.Decimal`. | any | decimal |
| `diagnostics` | LSP-style structured validation-finding collector — severity, dot-path, position, code, suggestion. | any | — |

## Roadmap / not yet built

Work deferred with a reason, not forgotten. A module's own `SPEC.md` carries its
deferred list; only cross-module scope decisions belong here.

- **`kv` on-disk MVCC / transactions / ordered scans** — shipped as the separate
  `kvtree` module (copy-on-write B-tree; `kv` v0 stays for point-store consumers
  like `jobqueue`). The transactional core, the randomized VOPR and freelist
  chaining are all implemented. What remains is in `modules/kvtree/SPEC.md`'s
  deferred list — overflow pages for oversized entries, node merge/rebalance on
  underflow, and automatic reclamation thresholds — not here.

Nothing is currently queued to build. The **IMAP client** that stood here was
built on 2026-07-31 and ships as the `imap` module in the catalog above.

## Non-goals — deliberately not built here

Durable scope decisions (candidate audit, 2026-07-09): capabilities this collection will
not own, and what to reach for instead.

### Adopt instead of building

| Capability | Adopt instead | Why not a module |
|---|---|---|
| Hardened/read-only SQLite | `vrischmann/zig-sqlite` or `karlseguin/zqlite.zig`, wrapped consumer-side | The enforcement (`authorizer`/`PRAGMA query_only`/`open_v2(READONLY)`) is raw C-API — breaks the pure-Zig/no-libc invariant |
| Kafka | bind `librdkafka` | A choice, not an impossibility: the wire protocol is public and binary, so a port is perfectly writable — it is just long and uninteresting (dozens of API keys, each independently versioned). The trade is one C dependency against a lot of mechanical work, and the dependency wins until a consumer says otherwise |
| Regex | `mnemnion/mvzr` (no captures) or `zig-utils/zig-regex` (captures) | Two mature pure-Zig libs already exist |
| PostgreSQL (wire v3) | `karlseguin/pg.zig` | Mature MIT lib, pooling + TLS |
| MySQL/MariaDB | `speed2exe/myzql` | Only viable option |
| TOML | `mattyhall/tomlz` | Mature MIT config parser |
| Structured logging | `karlseguin/log.zig` | Cleanest "just use it" |
| S3 | `lobo/aws-sdk-for-zig` | SigV4 built in |
| Redis/Valkey | `kristoff-it/zig-okredis` (partial/alpha) | Best available design |
| HTTP/3 transport | `ngtcp2` | The transport (streams, loss detection, ACK logic, flight scheduling) is a bigger arc than SSH or OPC-UA were, and ngtcp2 is crypto-agnostic by design — it takes a TLS backend, which is the shape `quic-crypto` already has. The RFC 9001 crypto seam is ours; the state machine is not <!-- non-goal-ok: http, quic-crypto, ssh --> |

### Won't build

- **`exprcalc`** — app-specific spreadsheet/rules engine, not reused cross-project, and needs external regex.
- **`unaccent`** — fully dependent on external `uucode` tables; not included.
- **`roquery`** — C-level SQLite hardening (authorizer/query_only enforcement); lives consumer-side over adopted zig-sqlite.
- **`taskqueue`** — folded into `jobqueue`. <!-- non-goal-ok: jobqueue -->
- **`chunkframe`** — too small to be a module: ~20 lines of clamps with no state. Written out instead at its consumer, `poc-wf-analytic/docs/DATA-PLANE.md` ("The chunk-framing pattern"), where both copies of it live. <!-- non-goal-ok: framing -->
- **Classic McEliece / BIKE** — code-based KEMs with no consumer here; `hqc` already occupies the post-quantum KEM slot. <!-- non-goal-ok: hqc -->
- **Isogeny-based crypto** — SIKE is broken (Castryck–Decru), and its successors have no consumer here.
- **Nostr / Matrix / Tor as protocols** — application protocols rather than foundational libraries; the primitives they rest on (`megolm`, `k256`, `bip340`) already ship. <!-- non-goal-ok: megolm, k256, bip340 -->
- **SQL sink / DL7-style concurrent store** — app-level storage shapes, not library-level ones; `kvtree`, `tsdb` and `shardstore` are the answer here. <!-- non-goal-ok: kvtree, tsdb, shardstore -->
