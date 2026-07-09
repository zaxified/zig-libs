# rdap — spec

Design + threat notes for auditors. Usage: see ./README.md. Attribution/provenance: see ./README.md (no NOTICE entry — greenfield, clean-room from public RFCs).

## Design & invariants

- **Four layers, each usable alone, offline-testable:** query URLs (`buildPath`/`buildUrl`) produce
  the `domain`/`ip`/`autnum`/`nameserver`/`entity` paths with RFC 3986 percent-encoding (unreserved +
  `:` for IPv6 pass through; the `/` of a CIDR is encoded), plus the `application/rdap+json` Accept
  header. Response model (`parseResponse`) maps RDAP JSON into a typed `Object` (class, handle,
  names, status, events, entities with roles + best-effort jCard fn/org/email, nameservers, links,
  notices/remarks, ip-network + autnum ranges) or a typed `RdapError`. Bootstrap (`parseBootstrap`)
  reads an IANA registry file; `lookupDomain`/`lookupIp` (longest-prefix CIDR match via `netaddr`)/
  `lookupAsn` resolve the authoritative base URL. `Client.query` = build URL → fetch → parse,
  optionally following one `rel:"related"` link (registry → registrar). Clean-room from RFCs
  7480/7482/7483/7484/9224 (plus the 9082/9083 renumberings) — no third-party RDAP implementation
  consulted; no NOTICE entry (greenfield, original work).
- **Fetch seam:** I/O goes through a `Fetcher` ("GET url → status + body"); `HttpFetcher` adapts the
  `http.Client` for real use — the only network-touching code. Concurrency: reentrant, no shared
  state.
- **Tolerant by policy:** servers vary wildly, so missing/extra/wrong-typed members degrade to
  defaults, never panic; only malformed JSON errors out. Status mapping: HTTP 404 →
  `error.NotFound`; a non-2xx with an RDAP error body → the typed `rdap_error` document; non-2xx
  without one → `error.HttpStatus`.

## Threat model / out of scope

Trust rests on **TLS to the RDAP server** (via the `http` client / `Fetcher`); this module does no
TLS itself and validates no server identity beyond what the fetcher enforces. The parser is the
attack surface, and its guarantee is that **hostile/oversized/wrong-typed JSON from an untrusted
server never panics** — arena-owned, tolerant parsing with a caller-bounded body buffer. The
`related`-link follow is capped at **one hop** so a server cannot chain the client through an
unbounded redirect graph. RDAP data is registrant-supplied and unauthenticated beyond the transport
— callers must not treat fields as verified. Out of scope: RDAP search queries, RDAP-over-HTTP
conformance/authentication extensions, and JSON schema validation beyond the tolerant model.

## Verification

19 offline tests (no test touches the network): `buildPath` KATs for all query types +
percent-encoding, Accept-header check, base-join with/without trailing slash; response KATs for
domain / ip-network / autnum shapes (RFC 9083 §5.3–5.5) and the typed error object (RFC 7480 §5.3),
plus sparse, malformed/wrong-top-level, and wrong-typed-member (degrade-not-panic) cases; bootstrap
KATs (RFC 9224 shape) with IPv4/IPv6 longest-prefix and ASN-range matching and malformed-input
tolerance; end-to-end client tests over a canned fetcher (domain query, 404→NotFound, related-link
follow and its fallback when the second hop fails). Run: `zig build test-rdap`.

## Backlog / deferred

None beyond the explicit out-of-scope list above (RDAP
search, auth extensions, full schema validation are deliberate non-goals, not v1 gaps).

## Status

`gap · any (logic over a Fetcher seam; HttpFetcher uses http) · client · reentrant` + deps: `http`,
`netaddr` — canonical source is `pub const meta` in src/root.zig.
