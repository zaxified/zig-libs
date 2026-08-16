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
> `scripts/ctgrind-expected.tsv` says so; `zig build check-fuzz` requires a fuzz harness on
> every module that parses foreign bytes; and each module's `SPEC.md` carries an
> **anchor grade** saying where its expected values come from — `EXTERNAL` (published
> vectors, bytes captured from a foreign implementation, or a live foreign peer) down to
> `SELF` (we wrote them from our own reading of the spec).
>
> **What that still cannot tell you.** A green gate means nothing contradicted the code, not
> that the code is right; a grade of `EXTERNAL` on one path says nothing about the others,
> which is what `MIXED` is for. **Nothing here has been through third-party review or a
> security audit.** If you are putting a module in front of untrusted input or in anything
> safety- or money-critical, read that module's `SPEC.md` first — start with its anchor
> grade, its constant-time section and its "deliberately not done" list — and review the
> code yourself. The documentation is written to make that possible, including where it
> says the evidence is weak.

## Using a module

Three ways to declare the dependency; the `build.zig` half is identical for all three.

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

Pin a tag or commit, never a branch. `hash` is mandatory and content-addressed, so upstream
movement can only ever arrive as a deliberate re-run of the command above — there is no
floating "latest". `CHANGELOG.md` says what each release changed.

Then, in `build.zig`, whichever of the three you chose:

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
scripts/test.sh          # the gate — tests what changed, escalates on its own
scripts/test.sh all      # every module; what CI and the pre-commit hook run
zig build test           # run all module tests
zig build test-<name>    # run one module's tests
zig build check-catalog  # verify build.zig's module_list ↔ modules/ ↔ this README agree
zig build check-changelog # verify every module has a dated, well-formed CHANGELOG.md
```

`scripts/test.sh` is the entry point for contributors: it maps changed files onto the
modules they affect, runs the `check-*` gates alongside them, and widens to the full set by
itself when the change is one that warrants it (`build.zig`, the harness). Reach for
`zig build test` when you actually want everything regardless of what changed.

`zig build -l` lists the rest, including the other `check-*` gates.

## Versioning & stability

Releases are dated git tags (`YYYY-MM-DD`), **not** semantic versions, and there are no
per-module versions; a tag asserts exactly one thing, that every module cleared every lane at
that commit (see the bar below — two lanes run the tests, the third only compiles). `scripts/tag.sh` cuts one. `v0.1.0` remains as history and is not a version
anything after it follows; dated releases exist, so pin the newest one that suits you
(`git tag`, or the tags page) rather than a bare commit. Detail
lives in `modules/<name>/CHANGELOG.md` with breaking changes flagged `BREAKING`;
`zig build check-changelog` enforces that every module has one and that it is dated and
well-formed. The root `CHANGELOG.md` carries the release policy and per-release notes — it
stopped indexing which modules have a changelog on 2026-08-14, since all of them do and the
index was a copy kept only so a gate could notice the copy had gone stale. Module maturity is carried
by the explicit caveat lines in the catalog
below (and each module's `SPEC.md`), not by stability-tier labels — every module meets the
same bar (tests green in both test lanes — `ReleaseSafe` and `ReleaseFast` — and compiling
clean in the third, `-Dstrict-debug`, which builds every module in real Debug but runs no
tests; plus oracle/KAT verification where one exists);
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
What a module still owes is in its own `SPEC.md`, under "What is deliberately not done".

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
| [`http`](modules/http/README.md) | HTTP/1.1 client **and** server, hardened for direct exposure (slowloris caps, gzip, multipart, Range, negotiation); also speaks HTTP/2 (h2c/h2 client+server). Not `std.http`. | any | netaddr |
| [`router`](modules/router/README.md) | REST routing — trie matcher (params/wildcards), middleware chain, groups, 404/405 | any | http |
| [`ratelimit`](modules/ratelimit/README.md) | Token-bucket per-client rate limit → 429 + Retry-After; per-user connection-rate limit for `on_connect` | any | router, http, netaddr |
| [`abuseguard`](modules/abuseguard/README.md) | Per-IP + global connection caps, ban/greylist, strike→ban (accept-time) | posix | http, netaddr, router |
| [`throttle`](modules/throttle/README.md) | Global concurrency limit + load-shedding → 503 | posix | router, http |
| [`security-headers`](modules/security-headers/README.md) | Secure-by-default response headers (HSTS/CSP/nosniff/frame/referrer/COOP/CORP) | any | router, http |
| [`cors`](modules/cors/README.md) | CORS preflight + header injection (secure defaults) | any | router, http |
| [`validate`](modules/validate/README.md) | Request body/query/params validation → aggregated 400 (typed + schema + string-format checks) + JSON DoS caps (depth/array/field size) | any | router, http, netaddr |
| [`metrics`](modules/metrics/README.md) | Prometheus registry (counter/gauge/histogram) + `/metrics` + request middleware + access-log writer (combined/JSON) | posix | router, http |
| [`health`](modules/health/README.md) | Liveness (`/healthz`) + readiness (`/readyz`) probe middleware — 200/503 from registered dependency checks (k8s probe contract) | any | router, http |
| [`requestid`](modules/requestid/README.md) | Request/correlation-ID middleware — adopts incoming `X-Request-Id` or generates one, echoes on response, exposed via `current()` | any | router, http |
| [`tracecontext`](modules/tracecontext/README.md) | W3C Trace Context — `traceparent`/`tracestate` parse + generate + propagation middleware (child span per hop) for distributed tracing | any | router, http |
| [`webhooksig`](modules/webhooksig/README.md) | HMAC webhook signatures (GitHub-style `sha256=<hex>`) — sign/verify (constant-time) + gating middleware, key rotation. Stripe's scheme not implemented | any | router, http |
| [`idempotency`](modules/idempotency/README.md) | Idempotency-Key dedup of unsafe retries — middleware + ramcache-backed store replaying a cached response without re-running the handler | any | router, http, ramcache |
| [`resilience`](modules/resilience/README.md) | Circuit breaker + retry/backoff + timeout + bulkhead (concurrency limiter) for calling upstreams (generic) | posix | — |
| [`upstream`](modules/upstream/README.md) | Load-balanced upstream pool + failover — round-robin/weighted/least-conn/EWMA, per-upstream breaker+bulkhead, active+passive health checks | any | resilience, probe |
| [`openapi`](modules/openapi/README.md) | OpenAPI 3.1 spec generated from the route table + `/openapi.json` | any | router, http |
| [`aaa-gate`](modules/aaa-gate/README.md) | Bearer + API-key auth (constant-time) + audit hook + denied-request throttle | any | router, http |
| [`jwt`](modules/jwt/README.md) | JWT/JWS + OIDC resource-server validator — parse/claims/verify (HS/ES/EdDSA/RSA, alg-confusion-safe), JWKS-by-kid, OIDC discovery, plus a router Bearer middleware | any | http, router, p256 |
| [`rbac`](modules/rbac/README.md) | Authorization decision engine — NIST RBAC (hierarchical + static SoD) and a depth-bounded ABAC condition-tree evaluator with structural default-deny | any | — |
| [`xml`](modules/xml/README.md) | Namespace-aware, security-hardened XML 1.0 parser → C14N-ready infoset tree; DOCTYPE-reject default blocks XXE/billion-laughs/depth-bomb. Foundation for `xmldsig`/`saml` | any | — |
| [`xmldsig`](modules/xmldsig/README.md) | XML Canonicalization (C14N) + XML-Signature **verification only** — RSA/ECDSA, algorithm allow-list (XSLT/XPath rejected); KeyInfo cert is untrusted, caller must pin trust | any | xml, rsa, p256 |
| [`saml`](modules/saml/README.md) | SAML 2.0 SSO **service-provider** — XSW-hardened Response verification against an IdP key, AuthnRequest builder, IdP-metadata parser; decrypts `EncryptedAssertion` via `xmlenc` | any | xmldsig, xml, xmlenc, rsa, x509, datefmt |
| [`aescbc`](modules/aescbc/README.md) | Raw AES-CBC (NIST SP800-38A) + PKCS#7/XML-Enc padding helpers, zero-alloc; padding-oracle caveat — consumers own authenticate-before-unpad | any | — |
| [`aeskw`](modules/aeskw/README.md) | RFC 3394 AES Key Wrap (AES-128/256 KEK) — constant-time integrity check + scratch zeroization, byte-exact vs RFC 3394 test vectors | any | — |
| [`xmlenc`](modules/xmlenc/README.md) | XML-Encryption (xmlenc-core-1) **decryption only** — recovers `EncryptedAssertion` plaintext (RSA-OAEP/AES-KW key transport + AES-GCM/CBC content), decrypt-then-verify | any | xml, rsa, aescbc, aeskw |
| [`jwe`](modules/jwe/README.md) | JSON Web Encryption (RFC 7516/7518) compact serialization — RSA-OAEP/AxxxKW/ECDH-ES key management + AES-GCM/CBC-HMAC content encryption; A192* unsupported (no AES-192 in std) | any | rsa, p256, aescbc, aeskw |
| [`acme`](modules/acme/README.md) | Let's Encrypt / ACME v2 (RFC 8555) — HTTP-01 issuance + renewal, ES256 JWS, CSR | any | http, router, entropy |
| [`staticfiles`](modules/staticfiles/README.md) | Path-traversal-safe static file handler over `http` — MIME by extension, ETag/conditional 304, byte-range 206/416; symlinks not followed, dotfiles refused by default | any | http |
| [`brotli`](modules/brotli/README.md) | Pure-Zig Brotli (RFC 7932) — byte-exact decompressor + a compressing encoder (LZ77 + Huffman, ~2.8x on text); the `Content-Encoding: br` companion to std gzip | any | — |
| [`accesslog`](modules/accesslog/README.md) | Structured HTTP access-log formatter — JSON Lines/logfmt/Apache Combined with log-injection escaping (untrusted UA/path/referer can't forge a line); http-request→Entry bridge | any | http |
| [`websocket`](modules/websocket/README.md) | RFC 6455 WebSocket — handshake + frame layer (masking, fragmentation, UTF-8 validation, size caps), transport-agnostic client + server; no permessage-deflate | any | http |
| [`sessions`](modules/sessions/README.md) | Server-side web sessions + OWASP-hardened cookies + signed double-submit CSRF middleware | any | router, http, cookies, ramcache, entropy |
| [`llmclient`](modules/llmclient/README.md) | Anthropic Messages API client (buffered + streaming SSE) over `http` — no third-party SDK | any | http |
| [`grpc`](modules/grpc/README.md) | gRPC client **and** server over HTTP/2 (over `protobuf`) — no code generation; all four call shapes (unary/streaming/bidi); untrusted declared length never sizes an allocation | any | http, protobuf |

### Networking

| Module | What it does | Platform | Deps |
|---|---|---|---|
| [`netaddr`](modules/netaddr/README.md) | IP parse/format (RFC 5952) + RFC 6724 source/dest selection + CIDR/Prefix ops (contains/overlaps/supernet, range↔prefix) | any | — |
| [`dns`](modules/dns/README.md) | RFC 1035 resolver — A/AAAA/PTR/CNAME/NS/MX/TXT/SOA/SRV/CAA over UDP/TCP + DoH | any | netaddr, http |
| [`dnssec`](modules/dnssec/README.md) | Resolver-side DNSSEC validation (RFC 4033/4034/4035 + NSEC3) — DNSKEY/RRSIG/DS parsing, signature verify (ECDSA/Ed25519/RSA), NSEC/NSEC3 denial-of-existence | any | dns, rsa |
| [`netlink`](modules/netlink/README.md) | rtnetlink read **and** write — dumps (links/addresses/routes/neighbors) and RTM_NEW*/DEL* writes; byte-exact vs iproute2 goldens + netns round-trip | **linux** | — |
| [`genetlink`](modules/genetlink/README.md) | Generic-netlink (genl) transport — genlmsghdr framing + nlctrl family-id resolution; shared foundation for ethtool/devlink/nl80211/wireguard clients | **linux** | netlink |
| [`nl80211`](modules/nl80211/README.md) | Wi-Fi control over nl80211 genetlink — interface/wiphy enumeration, scan trigger + BSS results, connect/disconnect, station/link stats, regulatory domain | **linux** | genetlink, netlink |
| [`devlink`](modules/devlink/README.md) | Linux devlink over genetlink — device/port enumeration, port split/unsplit, parameter/resource inspection, region snapshots, health reporters, eswitch mode | **linux** | genetlink, netlink |
| [`ethtool`](modules/ethtool/README.md) | Ethernet device control over the ethtool netlink family — link settings/state, ring/coalesce/pause/channel params, feature flags, per-queue/driver stats | **linux** | genetlink, netlink |
| [`wireguard`](modules/wireguard/README.md) | Native WireGuard device config over genetlink (retires `wg` shell-outs), plus the Noise_IKpsk2 handshake **and** the transport-data seal/open crypto data plane | **linux** | netlink, genetlink, chachapoly, entropy |
| [`tc`](modules/tc/README.md) | Traffic control over rtnetlink — qdiscs (netem/htb/tbf/fq_codel/cake), htb classes, u32/flower filters + action families; byte-exact to iproute2 (retires `tc` shell-outs) | **linux** | netlink |
| [`tcplan`](modules/tcplan/README.md) | Compiles a hierarchical shaping topology (site→AP→subscriber) into a deterministic ordered plan of `tc` ops — mq root + per-CPU HTB trees + CAKE leaves; pure, caller executes | linux | tc |
| [`nftables`](modules/nftables/README.md) | Typed firewall-ruleset builder → libnftables JSON for `nft -j -f -` (families/chains/rules/sets, match + verdict statements) | any (apply: linux) | netlink |
| [`bacnet`](modules/bacnet/README.md) | BACnet building automation over BACnet/IP **and** BACnet/SC — BVLL/BVLC framing, core APDU services (Read/WriteProperty, WhoIs/IAm, COV), SC secure-connect over `websocket` | any | netaddr, websocket |
| [`s7comm`](modules/s7comm/README.md) | Siemens S7 communication — ISO-on-TCP (RFC 1006) plus S7 protocol: connection setup, area read/write (DB/M/I/Q/T/C), PLC info and cyclic services | any | — |
| [`enip`](modules/enip/README.md) | EtherNet/IP + CIP — encapsulation layer (register/SendRRData/SendUnitData), CIP messaging, connection manager, tag/symbolic path client for Logix controllers | any | netaddr |
| [`iec62351`](modules/iec62351/README.md) | IEC 62351 power-systems security — GOOSE/SV authentication (62351-6) over caller-supplied PDU bytes, MMS application authentication (62351-4), checkable TLS policy | any | x509, rsa |
| [`iec61850`](modules/iec61850/README.md) | IEC 61850 substation automation — MMS (ISO 9506) client over ISO-on-TCP with the ACSI object model, plus GOOSE publish/subscribe + SV sampled values | any | xml |
| [`fleetsim`](modules/fleetsim/README.md) | In-process simulated device fleet — hosts protocol responders (Modbus, DNP3, IEC 104, S7comm, BACnet, EtherNet/IP, OPC UA) as nodes on one deterministic scheduler | any | modbus, dnp3, iec104, s7comm, bacnet, enip, opcua, netsim |
| [`smtp`](modules/smtp/README.md) | SMTP client (RFC 5321) — ESMTP EHLO negotiation, STARTTLS seam, AUTH PLAIN/LOGIN, pipelining, MIME message composition (RFC 5322/2045) | any | netaddr |
| [`imap`](modules/imap/README.md) | IMAP4rev2 (RFC 9051) client — mailbox-name codec, wire grammar, FETCH/ENVELOPE/BODYSTRUCTURE, SEARCH, IDLE; transport-agnostic (owns no socket, speaks no TLS) | any | — |
| [`iec104`](modules/iec104/README.md) | IEC 60870-5-104 telecontrol — APCI/APDU framing, I/S/U formats with k/w flow control, ASDU codec, transport-agnostic master (controlling station) | any | — |
| [`modbus`](modules/modbus/README.md) | Modbus TCP (MBAP) + RTU (CRC-16) codec, master client **and slave server** — core function codes, diagnostics, exceptions, transport-agnostic seam | any | — |
| [`mqtt`](modules/mqtt/README.md) | MQTT 3.1.1 client — all 14 control packets, QoS 0/1/2 state machine, topic-filter wildcards, transport-agnostic seam | any | — |
| [`coap`](modules/coap/README.md) | CoAP (RFC 7252) — full client **and** server stack: message codec, options (URI↔options), reliability (CON retransmission + dedup), correlated client/server. Zero-alloc | any | — |
| [`snmp`](modules/snmp/README.md) | SNMP v1/v2c/v3 — BER/ASN.1 codec, manager client (get/next/bulk/set/walk) + trap/notification receiver + USM auth (HMAC-MD5/SHA-1, constant-time); privacy crypto in progress | any | — |
| [`dnp3`](modules/dnp3/README.md) | DNP3 (IEEE 1815) base protocol — data-link framing + CRC-16/DNP, application layer, core object library; master + outstation. Secure Auth (g120) scaffolded only, no crypto | any | aeskw |
| [`opcua`](modules/opcua/README.md) | OPC-UA (IEC 62541) **client and server** — opc.tcp transport, secure channel (Basic256Sha256 on client, None-only on server), sessions, Read/Write/Browse/Call + subscriptions | any | rsa, x509 |
| [`whois`](modules/whois/README.md) | RFC 3912 whois client — query format + referral chasing (IANA→registrar) + field extraction, transport-agnostic seam | any | netaddr |
| [`rdap`](modules/rdap/README.md) | RDAP client (RFC 7480–7484) — JSON-over-HTTPS whois successor: query URLs, typed response model, IANA bootstrap, fetch seam | any | http, netaddr |
| [`icmp`](modules/icmp/README.md) | ICMP echo (ping) engine — v4/v6 codec, batched socket, pacing | **linux** | seqmap, netaddr |
| [`traceroute`](modules/traceroute/README.md) | ICMP-echo path discovery — TTL-stepped probes, per-hop address + RTT stats, load-balanced-path aware | **linux** | icmp, netaddr, latency-stats |
| [`probe`](modules/probe/README.md) | TCP-connect reachability prober — up/refused/timeout + RTT, fan-out with bounded concurrency, latency aggregation | any | netaddr, latency-stats |
| [`l2disco`](modules/l2disco/README.md) | Layer-2/neighbor discovery codec — LLDP (802.1AB) + CDP + ARP (RFC 826) + DHCP options (RFC 2131/2132) + MAC helper | any | netaddr |
| [`isis`](modules/isis/README.md) | IS-IS (ISO/IEC 10589) PDU codec — common header + TLV framework + IIH/LSP PDUs + SPB (802.1aq) TLVs; pure bounds-checked encode/decode, wire foundation for an SPB control plane | any | — |
| [`isis-adj`](modules/isis-adj/README.md) | IS-IS point-to-point adjacency state machine (ISO 10589 §8.2 + RFC 5303) — pure time-injected FSM driving one P2P neighbour Down→Init→Up from IIH PDUs | any | isis |
| [`isis-dis`](modules/isis-dis/README.md) | IS-IS LAN Designated-IS election (ISO 10589 §8.4.5) — elects DIS from priority + SNPA (tie-break, preemptive), derives the pseudonode LSP-ID; pure time-injected | any | isis |
| [`isis-lsdb`](modules/isis-lsdb/README.md) | IS-IS link-state database — stores LSPs by LSP-ID, ISO 10589 §7.3 newer-LSP comparison, time-injected aging + MaxAge purge, per-interface SRM/SSN flooding flags; pure | any | isis |
| [`isis-flood`](modules/isis-flood/README.md) | IS-IS flooding transmit scheduler — drains `isis-lsdb` SRM/SSN flags into ordered PDUs to send, paces LSP (re)transmission + periodic CSNPs; pure time-injected | any | isis, isis-lsdb |
| [`isis-spf`](modules/isis-spf/README.md) | Computes IS-IS shortest-path forwarding table from an `isis-lsdb` — TLVs → topology graph → Dijkstra + ECT tie-break → route table (dest → next-hop + metric); pure | any | isis, isis-lsdb, spf-ect |
| [`isis-sim`](modules/isis-sim/README.md) | Headless multi-node IS-IS/SPB fabric convergence simulator over `netsim` — asserts LSDBs synchronise and reconverge after an injected link failure | any | netsim, isis, isis-lsdb, isis-flood, isis-spf |
| [`seqmap`](modules/seqmap/README.md) | Fixed 65,536-slot 16-bit request/reply correlation map, O(1) | any | — |
| [`latency-stats`](modules/latency-stats/README.md) | Online RTT stats — min/max/mean/stddev + RFC 3550 jitter + loss %, O(1)/sample, no alloc; plus an HdrHistogram for bounded-error percentiles (p50–p99.9) | any | — |
| [`pping`](modules/pping/README.md) | Passive RTT estimation from TCP TSval/TSecr echo matching (RFC 7323 / Pollere pping) — bounded per-direction table, no double-counting of duplicate/delayed ACKs | any | — |
| [`procnet`](modules/procnet/README.md) | Linux `/proc`+`/sys` parsers — ARP/routes/TCP+UDP sockets/conntrack/process stats/device health, typed | **linux** | netaddr |
| [`conntrack`](modules/conntrack/README.md) | Linux ctnetlink (NETLINK_NETFILTER) client — typed conntrack flow dump/get/delete plus event subscription, over `netlink`'s write engine | **linux** | netlink, netaddr |
| [`rawsock`](modules/rawsock/README.md) | Linux AF_PACKET raw-frame capture + inject — BPF filter, promiscuous mode, typed frame decode | **linux** | netaddr |
| [`stun`](modules/stun/README.md) | STUN client (RFC 8489) — NAT reflexive-address discovery: XOR-MAPPED-ADDRESS + MESSAGE-INTEGRITY + FINGERPRINT | any | netaddr |
| [`sntp`](modules/sntp/README.md) | SNTP client (RFC 4330) — NTP packet codec + UDP query, clock offset / round-trip delay | any | — |
| [`syslog`](modules/syslog/README.md) | RFC 5424 syslog formatter + emitter, RFC 3164 legacy encoder, RFC 6587 TCP octet framing | any | — |
| [`ssh`](modules/ssh/README.md) | SSH-2.0 (RFC 4253) **client + server** — KEX incl. ML-KEM-768 hybrid, userauth (publickey/password) + channels (exec/subsystem); vs OpenSSH-validated. **Linux-only** | linux | rsa |
| [`netconf`](modules/netconf/README.md) | NETCONF client (RFC 6241) over SSH — RFC 6242 framing, hello/capability exchange, get/get-config/edit-config/commit RPCs with typed replies | any | ssh, xml |
| [`ebpf`](modules/ebpf/README.md) | eBPF program generation over `std.os.linux.bpf` — bytecode builders (kprobe counter, XDP filter, ring-buffer emitter); real-kernel verifier acceptance unverified in CI | **linux** | netlink |
| [`xdp-classifier`](modules/xdp-classifier/README.md) | XDP packet classifier for a LibreQoS-style edge shaper — IPv4 prefix→traffic-class via LPM-trie lookup, per-CPU scratch handoff, CPUMAP steering (bpf_redirect_map) | **linux** | ebpf |
| [`testkit`](modules/testkit/README.md) | Test-only shared harness (hex decoding for KAT vectors, golden byte-comparison, verbose-skip convention); wired via build.zig test_deps, absent from consumer imports | any | — |
| [`netsim`](modules/netsim/README.md) | Deterministic seeded discrete-event network simulator (latency/loss/partition/clock-skew, failure fuzzer, byte-exact replay) — model-checking harness for fabric algorithms | any | — |
| [`spf-ect`](modules/spf-ect/README.md) | Deterministic symmetric shortest-path (Dijkstra) with a reversal-invariant ECT tie-break (RFC 6329 idea generalized) + maximally-disjoint second tree; pure graph algorithm | any | — |
| [`loopfree-reconv`](modules/loopfree-reconv/README.md) | Loop-free reconvergence transitions — two-class ordered-FIB schedule (provably no transient forwarding loop, TTL backstop); netsim-verified under fuzzing | any | netsim, spf-ect |
| [`df-elect`](modules/df-elect/README.md) | Partition-correct Designated-Forwarder election (static link-state total order, duplicate-freedom argument) + split-horizon; bounded-badness model-checked in netsim | any | netsim |
| [`raft`](modules/raft/README.md) | Raft consensus (Ongaro & Ousterhout) — leader election + log replication, model-checked in netsim against all five formal safety properties; membership changes are design-only | any | netsim |
| [`reconcilable`](modules/reconcilable/README.md) | Generic desired-vs-actual reconciler (controller-runtime shape) — bounded, deduplicating work queue with backoff+jitter; caller-driven `tick()`, no clock or thread | any | resilience |
| [`liveness-hyst`](modules/liveness-hyst/README.md) | BFD-like link-liveness estimator with EWMA hysteresis — echo-probe timing + jitter/loss stats, Babel-style metric smoothing; fast detection without flap-driven oscillation | any | netsim, latency-stats |
| [`loopix`](modules/loopix/README.md) | Loopix mixnet (Piotrowska et al. — Nym's design) — Poisson mix + cover traffic over `sphinx`, model-checked in netsim against a global-passive-adversary anonymity invariant | any | netsim, sphinx |
| [`workerpool`](modules/workerpool/README.md) | In-process fixed-width worker pool over `lockfree.MpmcQueue` — type-erased closure jobs, Io-futex idle wakeup (no busy-spin, no lost-wakeup), graceful drain / abrupt shutdown | any | lockfree |
| [`shardstore`](modules/shardstore/README.md) | Key-sharding router over N independent `kvtree` stores — multi-core write parallelism (per-shard single-writer, cross-shard parallel) | any | kvtree |
| [`writebehind`](modules/writebehind/README.md) | Crash-safe write-behind cache coordinator — fast in-memory acks, async flush to a durable `Sink` via `workerpool`; WAL written before ack so a crash-recovered write survives | any | ramcache, workerpool, jobqueue, kvtree |
| [`readthrough`](modules/readthrough/README.md) | Backend-agnostic read-through cache coordinator — serve-from-cache or single-flight-coalesce a miss into one backend fetch, TTL + invalidation + negative caching | any | ramcache |
| [`pagecache`](modules/pagecache/README.md) | Bounded write-through page cache between `kvtree`'s pager and its `Storage` — hot-cold tiering (W-TinyLFU via ramcache) with an RSS budget; transparent to callers | any | kvtree, ramcache |
| [`lockfree`](modules/lockfree/README.md) | Lock-free concurrency primitives for shared-memory worker pools — Michael & Scott MPMC queue + Fraser/crossbeam epoch-based reclamation, under a strict seq_cst discipline | any | — |
| [`ethfrag`](modules/ethfrag/README.md) | Hardened inner-frame fragmentation/reassembly codec — RFC 5722 overlap rejection, bounded per-datagram memory, caller-clocked timeout, fuzz-tested never-panic | any | — |
| [`l2encap`](modules/l2encap/README.md) | Tenant-tagged (24-bit I-SID) L2-over-tunnel encapsulation for a multi-tenant L2VPN fabric — lean versioned header over a customer Ethernet frame; bounds-checked decode | any | — |
| [`l2forward`](modules/l2forward/README.md) | E-LAN edge forwarding table — per-I-SID customer-MAC learning (MAC→remote PE) with aging + BUM ingress-replication set + split-horizon; pairs with `l2encap` | any | — |
| [`pbb`](modules/pbb/README.md) | IEEE 802.1ah Provider Backbone Bridge (MAC-in-MAC) codec — wraps a customer frame in a backbone header + I-TAG (24-bit I-SID); real-Ethernet SPB encap, distinct from `l2encap` | any | — |
| [`bumtree`](modules/bumtree/README.md) | SPB per-source loop-free BUM distribution tree + RPF check over `spf-ect` — per-node replication next-hops (pruned source SPT) + single RPF ingress for an I-SID member set | any | spf-ect |
| [`spbfib`](modules/spbfib/README.md) | SPB (802.1aq) forwarding addressing — unicast B-MAC FIB from an `isis-spf` route table + SPBM multicast-DA construction; one congruent ECT path per dest, no per-flow ECMP | any | isis-spf |

### Data & storage

| Module | What it does | Platform | Deps |
|---|---|---|---|
| [`kv`](modules/kv/README.md) | Crash-consistent embedded KV store, Bitcask-style log, with randomized fuzz-tested crash recovery. | any | — |
| [`tsdb`](modules/tsdb/README.md) | Time-series persistence over `kvtree` — ordered (series, timestamp) key codec, streaming range scans, crash-safe retention-by-age. | any | kvtree |
| [`kvtree`](modules/kvtree/README.md) | Ordered transactional KV store — copy-on-write B-tree (LMDB/BoltDB lineage), MVCC snapshots, crash-safe range scans. | any | kv |
| [`ramcache`](modules/ramcache/README.md) | Bounded in-memory cache — W-TinyLFU admission/eviction, TTL, generation invalidation; sharded thread-safe wrapper. | any | — |
| [`decimal`](modules/decimal/README.md) | Exact i128 fixed-point decimal for money math, float-free, with IEEE/GDA rounding modes and rescale. | any | — |
| [`jobqueue`](modules/jobqueue/README.md) | Durable background-job queue over `kv` — lease/retry/dead-letter queue, per-partition FIFO under priority. | posix | kv |
| [`blobstore`](modules/blobstore/README.md) | Content-addressed blob store (git-object/restic style), plus name-addressed and small named-record layers; crash-safe. | posix | hashdigest |
| [`filestore`](modules/filestore/README.md) | DB-less durable keyed document store — one atomically-written file per record, plus a typed-JSON convenience layer. | posix | — |
| [`dataset`](modules/dataset/README.md) | Canonical in-memory columnar-typed table — the normalization seam between data sources and consumers. | any | — |
| [`tabular`](modules/tabular/README.md) | Dataset algebra (pandas/dplyr-style verbs) over `dataset` — aggregate/pivot/resample/rolling/join, fx-aware. | any | dataset |
| [`jsonshape`](modules/jsonshape/README.md) | JSON → `dataset` reshaping — dot-path descent and typed column projection (a minimal jq-style subset). | any | dataset |
| [`finstats`](modules/finstats/README.md) | Portfolio/financial statistics over `dataset` — XIRR, TWR, risk, beta, Monte-Carlo, correlation matrix. | any | dataset |
| [`trie`](modules/trie/README.md) | Prefix index for instant autocomplete over a large static string set. | any | — |
| [`fuzzysearch`](modules/fuzzysearch/README.md) | Bounded-edit-distance typo-tolerant lookup over a static string set — DoS-bounded, the typo-tolerant sibling of `trie`. | any | trie |
| [`geoindex`](modules/geoindex/README.md) | Static spatial index for bbox and nearest-neighbour queries over a large fixed geo-point set — DoS-bounded, zero-copy. | any | — |

### Crypto

| Module | What it does | Platform | Deps |
|---|---|---|---|
| [`entropy`](modules/entropy/README.md) | Fail-closed entropy source — `fill` draws from `std.Io.randomSecure` or aborts the process; no generator, no silent degrade. **Panics on failure.** | any | — |
| [`hashdigest`](modules/hashdigest/README.md) | Streaming digests — one-shot, incremental, and file hashing; SHA-256 convenience plus a multi-algorithm SHA-2/SHA-3/BLAKE2b/BLAKE3 layer. | any | — |
| [`ripemd160`](modules/ripemd160/README.md) | RIPEMD-160 (ISO/IEC 10118-3) streaming hash, plus `hash160` (`RIPEMD160(SHA256(x))`), the Bitcoin pubkey-hash primitive. | any | — |
| [`bech32`](modules/bech32/README.md) | Bitcoin address encodings — bech32 (BIP173) / bech32m (BIP350) codec, segwit address encode/decode, base58check, P2PKH/P2WPKH. | any | ripemd160 |
| [`sealedbox`](modules/sealedbox/README.md) | NaCl `crypto_box_seal` — anonymous-sender X25519 public-key encryption, plus base64/hex key serialization. | any | — |
| [`minisign`](modules/minisign/README.md) | minisign file format (jedisct1/minisign) — Ed25519 sign/verify for signed files/releases, including scrypt-encrypted secret keys. | any | entropy |
| [`rsa`](modules/rsa/README.md) | Pure-Zig RSA (PKCS#1 v2.2, RFC 8017) — keygen, PKCS1-v1.5/PSS sign+verify, OAEP/PKCS1 encrypt+decrypt, DER/PEM/OpenSSH key parsing. | any | montint |
| [`x509`](modules/x509/README.md) | X.509 certificate-chain / path validation (RFC 5280 §6) — trust-store chain building, extension, name, and signature checks. | any | rsa |
| [`paillier`](modules/paillier/README.md) | Paillier additively-homomorphic public-key encryption (EUROCRYPT 1999) — 2048-bit keygen, encrypt/decrypt, homomorphic add; const-time decrypt path. | any | montint |
| [`threshold_ecdsa`](modules/threshold_ecdsa/README.md) | GG20 threshold ECDSA over secp256k1 (t-of-n) — dealer keygen through online signing, producing standard verifiable ECDSA sigs. **Audit warranted before production use.** | any | paillier, montint |
| [`dkg`](modules/dkg/README.md) | Dealer-free Distributed Key Generation (GJKR) for `threshold_ecdsa` — bias-resistant secp256k1 key sharing feeding threshold signing. | any | threshold_ecdsa, paillier |
| [`vdf`](modules/vdf/README.md) | Wesolowski Verifiable Delay Function over an RSA hidden-order group — sequential-squaring delay with prove/verify. A caller-supplied modulus needs a trusted setup. | any | montint |
| [`montint`](modules/montint/README.md) | Constant-time Montgomery modular arithmetic over arbitrary odd moduli — faster native-Zig alternative to `std.crypto.ff`, x86-64 asm + portable fallback. | x86-64 asm + portable fallback | — |
| [`chachapoly`](modules/chachapoly/README.md) | SIMD-accelerated ChaCha20-Poly1305 AEAD (RFC 8439) — a throughput-specialized, byte-exact duplicate of `std.crypto.aead.chacha_poly`. | any (SIMD via `@Vector`) | — |
| [`aeadframe`](modules/aeadframe/README.md) | Per-key AEAD record layer — seal/open with a monotonic nonce (never reused), epoch rekey, anti-replay window, AAD binding. | any | chachapoly |
| [`tenantkex`](modules/tenantkex/README.md) | Per-tenant key exchange — a Noise_IK handshake (via `noise`) between provider edges, deriving directional channel keys for `aeadframe`. | any | noise |
| [`k256`](modules/k256/README.md) | asm-accelerated secp256k1 — Solinas field + GLV verify, bit-exact vs `std.crypto.ecc.Secp256k1`/BIP340. GLV is vartime/public-only, not for secrets. | amd64 asm + portable fallback | — |
| [`p256`](modules/p256/README.md) | asm-accelerated NIST P-256 — Solinas field, constant-time comb sign, vartime wNAF verify; bit-exact vs `std.crypto.ecc.P256` and RFC 6979. | amd64 asm + portable fallback | — |
| [`bip32`](modules/bip32/README.md) | BIP-39 mnemonic seed phrases + BIP-32 hierarchical-deterministic keys over secp256k1 — the wallet key-derivation foundation. | any | k256, ripemd160, bech32 |
| [`blindrsa`](modules/blindrsa/README.md) | RSA Blind Signatures (RFC 9474, RSABSSA) over `rsa` — the anonymous-token / Privacy Pass primitive: blind, sign, finalize, verify. | any | rsa |
| [`signal`](modules/signal/README.md) | Signal Protocol — X3DH key agreement, XEdDSA signing, and the Double Ratchet: E2EE sessions with forward secrecy and post-compromise security. | any | chachapoly, ct25519, entropy |
| [`mls`](modules/mls/README.md) | MLS — Messaging Layer Security (RFC 9420): cipher-suite/codec foundation plus TreeKEM (ratchet tree), for scalable group messaging. | any | hpke |
| [`megolm`](modules/megolm/README.md) | Megolm — Matrix's group-messaging ratchet: a one-way HMAC hash ratchet (fast-forward only, never rewinds) plus Ed25519-signed message frames. | any | aescbc, entropy |
| [`ed448`](modules/ed448/README.md) | Ed448 + X448 — the 448-bit "Goldilocks" curve (RFC 8032 + RFC 7748): constant-time X448 DH and Ed448/Ed448ph EdDSA signing. | any | entropy |
| [`decaf448`](modules/decaf448/README.md) | decaf448 prime-order group (RFC 9496) over `ed448` — eliminates cofactor-4 pitfalls for threshold signing, VRFs, anonymous credentials. | any | ed448 |
| [`slhdsa`](modules/slhdsa/README.md) | SLH-DSA (FIPS 205, standardized SPHINCS+) — post-quantum stateless hash-based signatures, all twelve parameter sets, NIST-KAT-verified. | any | — |
| [`falcon`](modules/falcon/README.md) | FN-DSA — Falcon-512 and Falcon-1024 NIST post-quantum lattice signatures: keygen, sign, verify, and key/signature codecs. | any | — |
| [`hqc`](modules/hqc/README.md) | HQC — code-based post-quantum KEM, NIST's structurally-independent backup to lattice-based ML-KEM. Complete keygen, encrypt, decrypt. | any | — |
| [`dtls`](modules/dtls/README.md) | DTLS 1.3 (RFC 9147), PSK mode — key schedule, AEAD record layer, handshake fragmentation/reassembly, anti-replay window. | any | rsa, x509, chachapoly |
| [`ocsp`](modules/ocsp/README.md) | RFC 6960 OCSP — build an OCSP request and cryptographically verify an OCSP response, for TLS OCSP-stapling. | any | x509, rsa, p256 |
| [`ocspcache`](modules/ocspcache/README.md) | OCSP-stapling fetch + cache over `ocsp` — AIA responder discovery, verify-before-cache, refresh-ahead expiry, soft-fail on outage. | any | ocsp, http, x509 |
| [`tlsresume`](modules/tlsresume/README.md) | Server-side TLS 1.3 session-ticket resumption (RFC 8446) — ticket seal/open, PSK binder derivation, 0-RTT early-data key schedule. | any | — |
| [`quic-crypto`](modules/quic-crypto/README.md) | RFC 9001 (TLS for QUIC) crypto seam — secret derivation, AEAD packet protection, header protection, key update; engine-agnostic. | any | chachapoly |
| [`bip340`](modules/bip340/README.md) | BIP340 Schnorr signatures over secp256k1 (Bitcoin Taproot's signature scheme) — sign, verify, batch verify, x-only keys. | any | k256 |
| [`taproot`](modules/taproot/README.md) | BIP341 Taproot key-path output-key tweaking — `tweakPublicKey`/`tweakSecretKey` built over `bip340`. | any | bip340, k256 |
| [`bitcointx`](modules/bitcointx/README.md) | Bitcoin transaction (de)serialization + signature hashing — legacy, BIP143 segwit-v0, and BIP341 taproot key-path sighash. | any | bip340 |
| [`psbt`](modules/psbt/README.md) | BIP174 Partially Signed Bitcoin Transaction (PSBT) v0 — binary (de)serialization plus the Combiner (merge) role, over `bitcointx`. | any | bitcointx, bitcoinscript |
| [`bitcoinscript`](modules/bitcoinscript/README.md) | Bitcoin Script consensus interpreter — full opcode set, CHECKSIG/CHECKMULTISIG; verifies bare/P2SH/segwit/P2TR key-path scripts. | any | bitcointx, k256, bip340, ripemd160 |
| [`btcp2p`](modules/btcp2p/README.md) | Bitcoin P2P wire-message codec — envelope, version/verack handshake, inventory/data messages. Codec only: no chain state or validation. | any | bitcointx |
| [`musig2`](modules/musig2/README.md) | MuSig2 multi-signature (BIP327) producing BIP340 signatures — rogue-key-safe key aggregation, 2-round nonces, partial sign/verify. | any | bip340, k256 |
| [`sphinx`](modules/sphinx/README.md) | Lightning BOLT#4 Sphinx onion routing — forward ECDH blinding chain, layered packet construction, constant-time layer peeling. | any | k256 |
| [`noise`](modules/noise/README.md) | Generic Noise Protocol Framework (spec rev 34) — handshake patterns (NN/NK/XX/IK) over a comptime-parameterized DH/AEAD/hash suite. | any | chachapoly |
| [`bolt8`](modules/bolt8/README.md) | Lightning BOLT#8 encrypted transport (`Noise_XK_secp256k1_ChaChaPoly_SHA256`) — handshake plus transport with periodic key rotation. | any | noise, k256 |
| [`bolt3`](modules/bolt3/README.md) | Lightning BOLT#3 key derivation — per-commitment blinded keys, split-secret revocation keys, shachain secret generation. | any | k256 |
| [`lnwire`](modules/lnwire/README.md) | Lightning BOLT#1/2/7 wire messages — base frame, BigSize/TLV codec, channel-management and gossip messages, over `bolt8`. | any | — |
| [`lninvoice`](modules/lninvoice/README.md) | Lightning BOLT#11 payment requests (+ BOLT#12 offer decode) — decode/verify and encode/sign, with node-pubkey signature recovery. | any | bech32, k256, lnwire, bip340 |
| [`hpke`](modules/hpke/README.md) | HPKE — Hybrid Public Key Encryption (RFC 9180): DHKEM(X25519/P-256) encap/decap, all four key-schedule modes, AEAD seal/open + export. | any | p256, chachapoly, entropy |
| [`adaptor`](modules/adaptor/README.md) | Schnorr adaptor signatures over BIP340 (scriptless scripts for Lightning PTLCs / atomic swaps) — preSign, adapt, extract. | any | bip340, k256 |
| [`frost`](modules/frost/README.md) | FROST threshold Schnorr signatures (RFC 9591), secp256k1 — t-of-n keygen, 2-round signing, aggregate. **Not BIP340-compatible.** | any | bip340, k256 |
| [`oscore`](modules/oscore/README.md) | OSCORE (RFC 8613) — end-to-end object security for CoAP: HKDF context derivation, AES-CCM AEAD, anti-replay sliding window. | any | — |
| [`spake2plus`](modules/spake2plus/README.md) | SPAKE2+ — an augmented PAKE (RFC 9383), P-256/SHA-256 (the Matter/Thread commissioning PAKE); resists server-compromise. | any | p256 |
| [`ct25519`](modules/ct25519/README.md) | Constant-time-on-secrets scalar multiplication for Edwards25519/Ristretto255 — drops std's secret-dependent `rejectIdentity` branch. Caller must validate points. | any | — |
| [`voprf`](modules/voprf/README.md) | (V)OPRF — Oblivious Pseudorandom Functions (RFC 9497), ristretto255-SHA-512: OPRF, verifiable, and partially-oblivious modes with DLEQ proofs. | any | ct25519 |
| [`bulletproofs`](modules/bulletproofs/README.md) | Bulletproofs — zero-knowledge range proofs over Ristretto255, proving a Pedersen-committed value is in range with logarithmic proof size. | linux | ct25519 |
| [`ctap2pin`](modules/ctap2pin/README.md) | CTAP2 `pinUvAuthProtocol` (FIDO2/WebAuthn) — both protocol versions: ECDH-P256 key agreement, encrypt/decrypt, authenticate/verify. | any | p256 |
| [`webauthn`](modules/webauthn/README.md) | WebAuthn / FIDO2 Relying-Party **verifier** (W3C Level 3) — assertion + registration ceremony checks, plus attestation verification. Verification only. | any | cbor, rsa, p256, x509 |
| [`otp`](modules/otp/README.md) | HOTP + TOTP one-time passwords (RFC 4226 / RFC 6238) — the 2FA-authenticator primitive; caller supplies the counter/time (no wall clock). | any | — |
| [`xmss`](modules/xmss/README.md) | XMSS (RFC 8391), single-tree SHA-256 — **stateful** hash-based signatures. Index reuse breaks the scheme; `sign` advances the index first. | any | — |
| [`bls12_381`](modules/bls12_381/README.md) | BLS12-381 pairing-friendly curve — field tower/groups, optimal-ate pairing, hash-to-curve, BLS signatures, KZG commitments, threshold BLS. | any | entropy |
| [`bbs`](modules/bbs/README.md) | BBS selective-disclosure signatures over `bls12_381` (draft-irtf-cfrg-bbs-04) — sign many messages, later reveal a chosen subset in zero knowledge. | any | bls12_381, entropy |
| [`coconut`](modules/coconut/README.md) | Coconut threshold-issuance anonymous credentials over `bls12_381` — t-of-n issued Pointcheval-Sanders credentials with selective-disclosure showing. | any | bls12_381 |
| [`tlock`](modules/tlock/README.md) | drand-style timelock encryption (Boneh-Franklin IBE over `bls12_381`) — encrypt to a future drand round; decryptable once it publishes. Not post-quantum. | any | bls12_381, entropy |
| [`drand`](modules/drand/README.md) | drand randomness-beacon client — chain-info and round codec, BLS-verifies a round signature against the chain public key. Transport-agnostic. | any | bls12_381, tlock |
| [`timelock_envelope`](modules/timelock_envelope/README.md) | Hybrid sealed envelope — unlocks only once both a drand timelock round publishes AND the recipient holds the PQ-KEM secret; AEAD-sealed content. | any | tlock, hqc, chachapoly, entropy |
| [`ibe`](modules/ibe/README.md) | Standalone Boneh-Franklin Identity-Based Encryption over `bls12_381` — a self-run PKG extracts per-identity keys. Not post-quantum; key escrow is inherent. | any | bls12_381, entropy |
| [`bn254`](modules/bn254/README.md) | BN254 / alt-bn128 curve — field tower/groups, optimal-ate pairing, EIP-196/197 EVM precompiles, and a Groth16 zkSNARK **verifier**. | any | — |
| [`opaque`](modules/opaque/README.md) | OPAQUE — an asymmetric PAKE (RFC 9807), ristretto255-SHA-512 + 3DH — registration and login/AKE. Server compromise reveals no password. | any | voprf, ct25519 |
| [`ecvrf`](modules/ecvrf/README.md) | ECVRF-EDWARDS25519-SHA512-TAI (RFC 9381 Verifiable Random Function) — prove/verify a deterministic, unbiasable output under a public key. | any | ct25519 |
| [`fss`](modules/fss/README.md) | Function Secret Sharing — 2-party single-point Distributed Point Function (BGI16), plus multi-point FSS; the primitive under `pir` and private analytics. | any | — |
| [`pir`](modules/pir/README.md) | Two-server Private Information Retrieval over `fss`'s DPF — fetch a record without either server learning the index. **Two colluding servers recover it immediately.** | any | fss |
| [`bfv`](modules/bfv/README.md) | BFV leveled homomorphic encryption (Fan-Vercauteren) over `Z_q[X]/(X^N+1)`, RNS — exact-integer keygen/encrypt/decrypt/multiply/relinearize. **No security level claimed.** | any | entropy |
| [`groth16`](modules/groth16/README.md) | Groth16 zk-SNARK **prover** over BN254 — R1CS→QAP, produces proofs `bn254.groth16Verify` accepts. `setup` is a toy, **insecure** trusted setup. | any | bn254 |
| [`poseidon`](modules/poseidon/README.md) | Poseidon — the ZK-friendly hash over prime fields (HADES permutation), for BN254 and BLS12-381; cheap Merkle/commitment hashing inside circuits. | any | bn254, bls12_381 |
| [`rescue`](modules/rescue/README.md) | Rescue-Prime Optimized (RPO) — arithmetization-oriented hash over the Goldilocks field, the alternative to `poseidon` for STARK circuits. | any | — |
| [`tfhe`](modules/tfhe/README.md) | TFHE/FHEW programmable gate bootstrapping — unbounded-depth FHE via blind rotation over a power-of-two torus. **Toy parameters only, no security level claimed.** | any | entropy |

### Serialization / OS / agent

| Module | What it does | Platform | Deps |
|---|---|---|---|
| [`tar`](modules/tar/README.md) | ustar/GNU tar reader+writer (preserves uid/gid/mtime) + gzip. | any (packer: linux) | — |
| [`linkheader`](modules/linkheader/README.md) | Web Linking (RFC 8288) `Link` header build + parse (rel/title/type), plus `pagination` helpers and `find(rel)`; zero-alloc. | any | — |
| [`cookies`](modules/cookies/README.md) | HTTP cookies (RFC 6265) — request `Cookie` parser plus `Set-Cookie` builder (Secure/HttpOnly/SameSite), injection-guarded. | any | http |
| [`blobmsg`](modules/blobmsg/README.md) | OpenWRT ubus client + blob/blobmsg wire codec. | **linux** (codec itself: any) | — |
| [`mcp`](modules/mcp/README.md) | Model Context Protocol server (JSON-RPC 2.0) — tools, resources, prompts, plus server→client sampling and elicitation requests. | any | — |
| [`mcp-http`](modules/mcp-http/README.md) | MCP Streamable HTTP transport (2025-06-18) — `POST /mcp` with JSON or live SSE, resumable sessions, Origin (DNS-rebind) guard. | any | router, http, mcp |
| [`uci`](modules/uci/README.md) | OpenWRT UCI config parser + serializer + typed model, with stable round-trip. | any | — |
| [`argsafe`](modules/argsafe/README.md) | Allowlist validators + a typed argv builder — neutralizes argument/flag injection into an exec `argv`. | any | — |
| [`procrun`](modules/procrun/README.md) | Subprocess runner — reap-race-tolerant wait, deadlock-free capped stdio capture, timeout, streaming, and cancel. | any | argsafe |
| [`pollworker`](modules/pollworker/README.md) | Single-owner `poll(2)` loop plus a lock-free fork/exec job table, for offloading blocking work off the loop thread. | **linux** | — |
| [`ipcbus`](modules/ipcbus/README.md) | Same-host unix-socket control plane — a request/reply server plus a capped in-memory scratch key→bytes bus. | **linux** | framing |
| [`sandbox`](modules/sandbox/README.md) | Process self-hardening for an internet-facing server — privilege drop, `setrlimit`/no core dumps, Landlock fs allow-list, seccomp-bpf. | **linux** | — |
| [`framing`](modules/framing/README.md) | Length-prefixed stream framing (`writeFrame`/`readFrame`) plus a generic JSON tagged-union envelope codec. | any | — |
| [`csvstream`](modules/csvstream/README.md) | Streaming RFC 4180 CSV reader that preserves byte offsets, with bounded memory regardless of file size. | any | — |
| [`csvsafe`](modules/csvsafe/README.md) | OWASP CSV formula-injection guard (`=`/`+`/`-`/`@` cell leads). | any | — |
| [`json5`](modules/json5/README.md) | Single-pass JSON5→JSON preprocessor (comments, unquoted keys, trailing commas, single-quoted strings). | any | — |
| [`yaml`](modules/yaml/README.md) | YAML 1.2 reader (not 1.1) — scanner → parser → composer over the core schema (no `yes`/`no` booleans); cyclic aliases rejected. | any | — |
| [`jinja`](modules/jinja/README.md) | Jinja2-compatible template engine — expressions, control flow, template inheritance/macros/imports, over a symlink-contained loader. | any | — |
| [`cbor`](modules/cbor/README.md) | CBOR (RFC 8949) codec — all 8 major types, canonical encoding option, untrusted-input hardened; plus a minimal COSE (RFC 9052) layer. | any | — |
| [`protobuf`](modules/protobuf/README.md) | Protocol Buffers wire format (proto3) codec — schema derived at comptime from Zig structs, no `.proto` compiler; untrusted-input hardened. | any | — |
| [`zipstream`](modules/zipstream/README.md) | Streaming ZIP archive reader — walks the central directory once, streams decompressed member bytes on demand. | any | — |
| [`encoding`](modules/encoding/README.md) | Legacy single-byte code page ↔ UTF-8 transcoding (5 European code pages: windows-125x, ISO-8859-1/2/15). | any | — |
| [`datefmt`](modules/datefmt/README.md) | Civil calendar plus token-based date/time parse/format and calendar arithmetic, correct before 1970. | any | — |
| [`tz`](modules/tz/README.md) | IANA time-zone offset lookup — zone name → UTC offset/DST at a given instant (600 zones + POSIX-TZ footer). | any | datefmt |
| [`numparse`](modules/numparse/README.md) | Locale-aware grouped-number parsing (thousands/decimal separators) into an exact `decimal.Decimal`. | any | decimal |
| [`diagnostics`](modules/diagnostics/README.md) | LSP-style structured validation-finding collector — severity, dot-path, position, code, suggestion. | any | — |

## Non-goals — deliberately not built here

Capabilities this collection will not own, and what to reach for instead. A row here is a
scope decision with a reason, not a promise — the reason is what to argue with if it should
change. `zig build check-catalog` refuses to let this table name a capability that has since
become a module.

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
