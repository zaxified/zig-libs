# ocspcache — SPEC

OCSP-stapling fetch + cache: discover a certificate's OCSP responder URL,
fetch a fresh signed response, verify it, and cache it until it needs
refreshing. See [README.md](README.md) for the API and a usage example.

## Scope

This module is the **feeder** for OCSP stapling, not the stapling itself:

- **In scope**: responder-URL discovery (AIA), the fetch (POST/GET,
  injectable transport), verify-before-cache, the cache's expiry/refresh
  bookkeeping, and the soft-fail serving posture.
- **Out of scope**: embedding the cached response into the TLS handshake
  (the `status_request` extension, RFC 6066) — that is the TLS server's job.
  A caller wires `Cache.getStapled` into its handshake path and a scheduler
  (a timer loop, not part of this module) calls `Cache.refresh` when
  `Cache.needsRefresh` says so.

## Responder URL discovery (AIA)

`discoverResponderUrl` walks the subject certificate's Authority Information
Access extension (RFC 5280 §4.2.2.1, OID `1.3.6.1.5.5.7.1.1`  —
`std.crypto.Certificate.ExtensionId.info_access`, which the sibling `x509`
module's extension walk already recognizes by that exact OID). The AIA
extension's own structure (`AuthorityInfoAccessSyntax ::= SEQUENCE OF
AccessDescription`, `AccessDescription ::= SEQUENCE { accessMethod OID,
accessLocation GeneralName }`) is **not** parsed by `x509` — no sibling
module exposes it — so this module walks it locally, on the same bounds-safe
primitive (`x509.extensions.parseElement`) `ocsp` and `x509` themselves use.
It looks for an `AccessDescription` whose `accessMethod` is `id-ad-ocsp`
(`1.3.6.1.5.5.7.48.1`) and whose `accessLocation` is a
`uniformResourceIdentifier [6]` `GeneralName`; the first match wins. A
certificate with no v3 extensions, no AIA extension, or an AIA extension with
no OCSP entry yields `null` — a legitimate "no stapling available for this
cert" outcome, not an error. A structurally malformed AIA extension (hostile
or corrupt DER) yields `error.Malformed`; this never panics, mirroring
`ocsp`'s and `x509`'s own defensive-DER posture — nothing here calls
`std.crypto.Certificate.parse` on the certificate either.

## Fetch: the injectable `Transport` seam

`Cache.refresh` never talks to a socket directly. It calls
`Transport.fetch(gpa, FetchRequest) FetchError!FetchResponse` — a
context-pointer + function-pointer pair (the same by-hand vtable idiom
`std.mem.Allocator` uses), so:

- **Production**: `httpTransport(&my_http_client)` adapts the sibling `http`
  module's `Client` — `POST` with `Content-Type: application/ocsp-request`
  and the DER request as the body (RFC 6960 §4.2.1), or `GET` with the
  base64url-ish path form (`buildGetUrl`, RFC 6960 Appendix A.1.1, reserved
  base64 characters percent-encoded). The response body is read via
  `Response.readAllAlloc` bounded by `FetchRequest.max_response_bytes` — an
  oversized reply is `error.ResponseTooLarge`, never buffered unbounded.
- **Tests**: a mock `Transport` returns a canned, pre-verified-fixture
  response, so `Cache.refresh`'s full verify-before-cache path is exercised
  without a network dependency (see "Fixture provenance" below and the
  doc-comment at the top of `ocspcache_test.zig`).

POST is the priority form per the task (`Config.fetch_method` defaults to
`.post`); GET is supported for responders/CDNs that require or prefer it
(some OCSP responders cache GET requests more aggressively — the classic
reason to prefer it for stapling specifically, since GET requests are
naturally cacheable by intermediate HTTP caches while POST bodies are not).

## Verify-before-cache

`Cache.refresh` is the only place bytes enter the cache, and it never skips
a step:

1. Discover the responder URL (AIA) — `NoResponderUrl` / `Malformed` if this
   fails.
2. Build the request (`ocsp.buildRequest`) and fetch it (`Transport.fetch`,
   bounded).
3. Reject anything but HTTP 200 (`ResponderHttpError`).
4. `ocsp.parseResponse` the body; reject anything but
   `responseStatus == successful` with an `id-pkix-ocsp-basic` payload
   (`ResponderUnsuccessful` / `UnsupportedResponseType`) — this is where a
   responder's `tryLater` (or any other non-success status) is caught.
5. `ocsp.verify` the parsed response against the **caller-supplied**
   `now_unix` and the issuer certificate — this is `ocsp`'s full security
   core (responder authorization, signature verification, CertID binding,
   freshness, nonce if used): any rejection is `VerifyFailed`. **No response
   is cached or ever handed to `getStapled` without passing this.**
6. Only a verified `Verdict.status == .good` is cached. A verified `revoked`
   returns `CertRevoked` **and evicts any cached entry** (see "Soft-fail"); a
   verified `unknown` returns `CertStatusUnknown` and leaves the cache alone.
   Neither is ever stapled; the caller (not this module) decides what a
   revoked server certificate means for its own operation, but it can tell
   the two apart — and apart from a mere outage — from the error alone.
7. `Config.max_entries` bounds the number of distinct certificates cached
   (`CacheFull`) — a production TLS server serves a handful of its own
   certificates, not an open-ended set.

Every one of steps 1–7 that fails returns a typed `RefreshError` and touches
**nothing** in the cache — see "Soft-fail" below.

## Expiry: `nextUpdate` + refresh-ahead margin

A cache entry's expiry is `Verdict.next_update_unix` when the response
carried one, else `this_update_unix + Config.max_age_seconds` — the same
bound `ocsp.verify` itself already applied to accept the response in the
first place (a response with no `nextUpdate` that `ocsp.verify` accepted is,
by construction, no older than `max_age_seconds`).

- `needsRefresh(subject, now_unix)` is true when there is no entry, or
  `now_unix > nextUpdate - Config.refresh_margin_seconds` — the signal a
  scheduler uses to call `refresh` proactively, well before the cached
  response actually expires, so a replacement is normally ready in time.
- `getStapled(gpa, subject, now_unix)` returns a **caller-owned copy** of the
  cached DER (never a borrow of cache storage — see "Staple ownership") only
  while `now_unix <= nextUpdate` — past that point it returns `null` even if
  `refresh` has never been retried, rather than staple a response known to
  be outside its validity window. This is a deliberate reading of the task's
  "or null if none-fresh": staleness is checked against the *actual*
  validity window, not the proactive refresh margin — the margin only
  governs `needsRefresh`.

## Soft-fail posture

A responder outage, a `tryLater`, a malformed reply, an `unknown` status, or
a single unverifiable fetch must never evict a still-valid cached response — that
would turn a transient responder problem into an unnecessary stapling
outage. `Cache.refresh` enforces this structurally, not by exception
handling: the cache map (`entries`) is mutated in exactly one place, at the
very end of `refresh`, after every check above has already succeeded. Every
early return leaves `entries` untouched. `getStapled` and `needsRefresh`
never call `refresh` themselves and never look at the last `refresh`
outcome — they only ever look at what's actually in the cache and
`now_unix`. Concretely: if `refresh` fails at 2pm but the cache still holds
a response valid until 6pm, `getStapled` keeps returning it, unaffected,
right up until 6pm; only past actual expiry does it start returning `null`,
regardless of how many failed refresh attempts came before.

**The one exception — a verified `revoked`.** Soft-fail exists so that a
failure to *learn* anything does not become a stapling outage. A verified
`revoked` is not that: it is the CA's authenticated statement that the
certificate is dead, and it arrives through the same `ocsp.verify` that every
accepted response passes. Treating it like an outage would mean the cached
`good` response keeps being stapled for the remainder of its own `nextUpdate`
window — days, given the shipped 12-hour refresh margin against a typical
week-long OCSP validity — after revocation was positively proven. So
`refresh` evicts the entry and returns `CertRevoked`, which is a distinct
error from every "could not get an answer" outcome. `Cache.invalidate` exposes
the same eviction for a revocation learned out of band (a CRL, a CA notice).

## Staple ownership

`getStapled` returns bytes the caller owns and frees, allocated from an
allocator the caller passes. It is deliberately not a view into the cache's
own storage: the next successful `refresh` for that certificate frees exactly
the buffer it replaces (and a `CertRevoked` refresh frees it outright), and
the caller holding a staple is a TLS server whose refresh scheduler runs
independently of its handshakes by design — `needsRefresh` exists precisely to
make it do so. A borrow would therefore dangle with no ordering rule the
caller could have followed, and the bytes in question are written into a live
`status_request` extension, so the failure mode is freed heap on the wire, not
just a crash. The copy costs a couple of kilobytes of memcpy against a
handshake that already does asymmetric crypto; callers with a per-connection
arena pay nothing to free it.

## Cache keying and bounds

The cache key is SHA-256 of the subject certificate's DER bytes — a
fixed-size key regardless of certificate size, stable for the same cert
across calls, and requiring no certificate-content assumptions (no reliance
on a serial number being globally unique, for instance). `Config.max_entries`
bounds the map's size; `Config.max_response_bytes` bounds each fetch. Every
cached response is `gpa`-owned and freed on `Cache.deinit` or on
replacement by a subsequent successful `refresh` for the same key.

## Fixture provenance (Validation)

`build.zig`'s module graph gives `ocspcache` exactly `ocsp` + `http` +
`x509` (per the repo's dependency-declaration convention, module
dependencies are not transitive — `ocsp`'s own `rsa`/`p256` deps are not
visible here), so `ocspcache_test.zig` cannot generate RSA-signed fixtures
inside its own test binary. Its fixtures (an issuer cert, three AIA-bearing
or AIA-less leaf certs, and matching signed `BasicOCSPResponse`s, one
tampered) are **CONSTRUCTED, not captured from a public CA** — generated by
a throwaway, uncommitted offline generator that invoked `ocsp`'s own
`der_writer` + `rsa.signPkcs1v15`/`rsa.selfSignedCert` (the exact same
construction `ocsp`'s own `ocsp_test.zig` uses — see ocsp/SPEC.md "Fixture
provenance") via a direct `zig build-exe` call mirroring `build.zig`'s own
module-graph flags, entirely outside this repo's build graph. The resulting
byte arrays are baked into `ocspcache_test.zig` as `const` data with a
doc-comment recording exactly what each one is and how it was made — real
signatures over real DER, verified by the real `ocsp.verify`, with no
network and no third-party certificate involved.

Covered: AIA discovery (present → URL; absent → `null`, never an error;
several malformed-DER shapes → `Malformed` or a safe `null`, never a panic);
a full fetch→verify→cache→serve round trip via a mock `Transport`; the
`needsRefresh` proactive-margin flip versus `getStapled`'s hard
actual-expiry cutoff, checked as two distinct instants; a tampered response
(bad signature) never cached; a `tryLater` response soft-failed while the
prior good entry keeps serving; a non-200 HTTP status soft-failed; a
certificate with no AIA entry rejected before ever calling the transport;
the GET-form request path; and `Config.max_entries` rejecting a second
distinct certificate once the bound is reached without disturbing the first.

## Real captured fixture (`goldens.zig`, added 2026-08-01)

The fixtures above (this file's earlier "Fixture provenance" section) are all
CONSTRUCTED — an offline generator, never a real CA — and their `CertID`s are
SHA-256-hashed like `ocsp`'s own constructed fixtures. `goldens.zig` adds a
real, live-captured round trip reusing the GoDaddy capture documented in
`ocsp`'s own `SPEC.md`/`goldens.zig` (delegated responder, real AIA
extension, SHA-1 `CertID`): `discoverResponderUrl` against the real leaf
certificate's actual Authority Information Access extension (resolves
`http://ocsp.godaddy.com/`, independently confirmed via
`openssl x509 -text`), and a full `Cache.refresh` → verify (delegated
responder, real 4096-bit RSA responder key) → cache → `getStapled` round trip
via a mock `Transport` that returns the real captured response bytes
verbatim. `now_unix` is pinned to a fixed instant inside the response's real
`[thisUpdate, nextUpdate]` window, never the wall clock.

A shared-root-cause teeth-check: re-applying the same mutation used for
`ocsp`'s own teeth-check (dropping the SHA-1 arm of `hashAlgoFromOid` in
`ocsp/src/root.zig`) turns exactly the real-fixture `Cache.refresh` test red
(`VerifyFailed` ← `CertIdMismatch`) while all twelve constructed-fixture
tests in `ocspcache_test.zig` — and the other two real-fixture tests, which
don't touch `CertID` verification — stay green. The blind spot in `ocsp`
propagates transitively through this module's dependency, and only the real
captured response in `ocspcache`'s own suite catches it.

Attribution: none required (same reasoning as `ocsp`'s `NOTICE` — a
black-box compatibility test oracle, CONVENTIONS.md §5 / root NOTICE §0); no
root NOTICE change accompanies this addition. `ocspcache` has no
module-local `NOTICE` file of its own (nothing here ports third-party source
or a design reference), so this note lives in SPEC.md only.

## Deferred (out of scope, not silently skipped)

- **TLS handshake stapling wire integration** (RFC 6066 `status_request`) —
  the consuming TLS server's job.
- **OCSP-stapling for the GET-form response cache-control interplay** (some
  responders publish `Cache-Control`/`Expires` on their HTTP response, which
  a caching HTTP layer in front of the responder could honor) — this module
  relies solely on the OCSP `nextUpdate` field, the authoritative signal RFC
  6960 defines; HTTP-level cache headers are not consulted.
- **Multi-responder / CDN failover** — `refresh` fetches from exactly the
  one URL AIA names; a caller wanting fallback responders composes that
  above this module.
- **A background scheduler loop** — `needsRefresh`/`refresh` are the
  primitives; running them on a timer is the consuming application's job
  (this module has no threads, no timers, no system clock).

## Status

Implemented: AIA-based responder discovery, an injectable fetch `Transport`
(POST priority + GET form + an `http`-backed production adapter), and a
`Cache` (`getStapled` / `needsRefresh` / `refresh`) with verify-before-cache
and the soft-fail posture. `zig build test-ocspcache` — green in
Debug and ReleaseFast.

## Anchoring

**Anchor grade:** class A · oracle MIXED

- **Class A** — wire/interop format — other implementations must byte-agree with it.
- **Oracle MIXED** — anchored for some paths, self for others — the evidence below names which.

**What the tests actually contain.** src/goldens.zig carries a real www.godaddy.com leaf+issuer and the real OCSP response its responder returned, captured 2026-08-01, exercised through fetch/verify/cache; src/ocspcache_test.zig states in its own header that its byte arrays are NOT captured from a public source but constructed via ocsp's der_writer+rsa, so that half stays self

**How it got there.** The anchoring work landed. DONE 6c2d6d9: same real CA fixtures; blind spot shown to propagate through the sibling
