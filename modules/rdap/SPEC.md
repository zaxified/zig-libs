# rdap — spec

Design + threat notes for auditors. Usage: see ./README.md. Attribution/provenance: see ./README.md (no NOTICE entry — greenfield, clean-room from public RFCs).

## Design & invariants

- **Four layers, each usable alone, offline-testable:** query URLs (`buildPath`/`buildUrl`) produce
  the `domain`/`ip`/`autnum`/`nameserver`/`entity` paths with RFC 3986 percent-encoding (unreserved +
  `:` for IPv6 pass through; the `/` of a CIDR is encoded), plus the `application/rdap+json` Accept
  header. Response model (`parseResponse`) maps RDAP JSON into a typed `Object` (class, handle,
  names, status, events, `rdapConformance`, entities with roles + best-effort jCard fn/org/email +
  their own nested entities (RFC 9083 §5.1, e.g. registrar → abuse contact — bounded by
  `max_entity_depth`, see below), nameservers with handle/status/glue addresses, links, notices/
  remarks, `publicIds`, GDPR `redacted` disclosures (RFC 9537), ip-network + autnum ranges) or a
  typed `RdapError`. Bootstrap (`parseBootstrap`) reads an IANA registry file; `lookupDomain`/
  `lookupIp` (longest-prefix CIDR match via `netaddr`)/`lookupAsn` resolve the authoritative base
  URL. `Client.query` = build URL → fetch → parse, optionally following one `rel:"related"` link
  (registry → registrar). Clean-room from RFCs 7480/7482/7483/7484/9224/9537 (plus the 9082/9083
  renumberings) — no third-party RDAP implementation consulted; no NOTICE entry (greenfield,
  original work).
- **Fetch seam:** I/O goes through a `Fetcher` ("GET url → status + body"); `HttpFetcher` adapts the
  `http.Client` for real use — the only network-touching code. Concurrency: reentrant, no shared
  state.
- **Tolerant by policy:** servers vary wildly, so missing/extra/wrong-typed members degrade to
  defaults, never panic; only malformed JSON errors out. Status mapping: HTTP 404 →
  `error.NotFound`; a non-2xx with an RDAP error body → the typed `rdap_error` document; non-2xx
  without one → `error.HttpStatus`, with the real HTTP status (e.g. distinguishing 429 from 500 for
  a caller implementing backoff) delivered through `Client.query`'s optional `status_out: ?*u16`
  out-pointer — the idiom this repo already uses for `sntp`'s Kiss-o'-Death code and `ebpf`'s
  `first_bad_id`, chosen over a richer error payload because Zig error values cannot carry data at
  all, and over widening the error set (`HttpStatus429`, `HttpStatus500`, …) because the status
  space is 3-digit and open-ended, not a small enum.
- **Nested entities:** `Entity.entities` holds an entity's own `entities[]` (RFC 9083 §5.1) — RDAP's
  shape for role-specific sub-contacts, most commonly a registrar's abuse contact. Recursion is
  capped at `max_entity_depth` (8) levels; a server nesting deeper than that has those deeper levels
  silently dropped rather than rejecting the response (tolerant-by-policy, above) — nothing on the
  wire bounds nesting depth, and 8 is generous for anything a real registry has been observed to
  emit (the real captured golden nests exactly one level).

## Threat model / out of scope

Trust rests on **TLS to the RDAP server** (via the `http` client / `Fetcher`); this module does no
TLS itself and validates no server identity beyond what the fetcher enforces. The parser is the
attack surface, and its guarantee is that **hostile/oversized/wrong-typed JSON from an untrusted
server never panics** — arena-owned, tolerant parsing with a caller-bounded body buffer. The
`related`-link follow is capped at **one hop** so a server cannot chain the client through an
unbounded redirect graph, and the target host is checked with `isSpecialUseHost` before that hop is
fetched — a `related` `href` naming loopback/RFC 1918/link-local/unique-local/unspecified/multicast
space or `localhost` is refused (falls back to the first document) rather than fetched, since RDAP's
whole point is cross-registry redirection and a hostile/compromised registry controls that URL
(SSRF hardening; a hostname other than `localhost` is not classified here and relies on the
`Fetcher`'s own resolver). RDAP data is registrant-supplied and unauthenticated beyond the transport
— callers must not treat fields as verified. Out of scope: RDAP search queries, RDAP-over-HTTP
conformance/authentication extensions, and JSON schema validation beyond the tolerant model.

## Verification

33 offline tests (no test touches the network): `buildPath` KATs for all query types +
percent-encoding, Accept-header check, base-join with/without trailing slash; response KATs for
domain / ip-network / autnum shapes (RFC 9083 §5.3–5.5) and the typed error object (RFC 7480 §5.3),
nested entities (RFC 9083 §5.1) including the `max_entity_depth` tolerant-drop boundary,
`rdapConformance`/`publicIds`/`redacted` (RFC 9537), and nameserver `ipAddresses`, plus sparse,
malformed/wrong-top-level, and wrong-typed-member (degrade-not-panic) cases; bootstrap KATs (RFC
9224 shape) with IPv4/IPv6 longest-prefix and ASN-range matching and malformed-input tolerance;
`isSpecialUseHost` classification; end-to-end client tests over a canned fetcher (domain query,
404→NotFound, `status_out` carrying the real HTTP status on `error.HttpStatus` (429 vs. 500 vs.
403), related-link follow and its fallback when the second hop fails or when the `related` href
names a loopback/RFC 1918 host — never dialed). Run: `zig build test-rdap`.

## Backlog / deferred

- **`secureDNS` (delegationSigned/dsData, RFC 9083 §5.3) is not modeled.** Considered during the
  2026-08-22 competitive-survey sweep (the real captured golden carries it) and dismissed: unlike
  `redacted`/`publicIds`/`rdapConformance`/nested entities/nameserver glue addresses (all reused
  existing string/string-list/nested-object helpers), `secureDNS` needs a boolean-field helper this
  module has never needed before plus a new nested numeric-record family (`dsData[]`: keyTag,
  algorithm, digest, digestType) — DNSSEC zone-security posture, not identity/contact data, which is
  what every other field in this sweep serves. A legitimate future addition, not a v1 gap.
- Otherwise none beyond the explicit out-of-scope list above (RDAP search, auth extensions, full
  schema validation are deliberate non-goals, not v1 gaps).

## Status

`gap · any (logic over a Fetcher seam; HttpFetcher uses http) · client · reentrant` + deps: `http`,
`netaddr` — canonical source is `pub const meta` in src/root.zig.

## Anchoring

**Anchor grade:** class A · oracle MIXED

- **Class A** — wire/interop format — other implementations must byte-agree with it.
- **Oracle MIXED** — anchored for some paths, self for others — the evidence below names which.

**What the tests actually contain.** src/goldens.zig carries a real rdap.publicinterestregistry.org response for iana.org captured live 2026-08-01 (GDPR-redacted handle, nested entities, publicIds, nameserver glue addresses) plus the real IANA bootstrap file; the remaining client fixtures in root.zig are hand-authored.

**How it got there.** The anchoring work landed in two passes. DONE ea2d000: captured the real registry response, which surfaced the GDPR-redacted handle and nested-entities shapes as gaps (asserted then as documented limitations). DONE 2026-08-22 (competitive survey against `icann-rdap`/`openrdap`): closed those gaps — `Entity.entities`, `Object.redacted`/`public_ids`/`rdap_conformance`, nameserver handle/status/glue addresses — and re-anchored the same golden fixture's assertions against the new, not the old, behavior.
