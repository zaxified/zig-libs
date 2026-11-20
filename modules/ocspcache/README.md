# ocspcache

OCSP-stapling **fetch + cache** library: discover a certificate's OCSP
responder URL, fetch a fresh signed response for it, verify it, and cache it
until it needs refreshing. A TLS server staples the cached response into its
handshake (RFC 6066 `status_request`) instead of forcing every client to
query the CA itself — this module is the feeder that keeps that cache warm;
embedding the response into the TLS handshake itself is the server's job,
not this module's (see SPEC.md "Scope").

`discoverResponderUrl` extracts the OCSP responder URL from a certificate's
Authority Information Access extension (RFC 5280 §4.2.2.1); only `http://` and
`https://` locations count. `Cache.refresh` builds a request (`ocsp.buildRequest`),
fetches it through an injectable `Transport` (POST by default, RFC 6960 §4.2.1;
or the GET form, Appendix A.1.1; redirects are not followed, a response body is
read under a size bound and a deadline), and — only if `ocsp.verify` accepts the
response **and** its status is `good` — caches the raw bytes. Every other
outcome (unreachable responder, `tryLater`, a bad signature, an `unknown`
status) is a typed error that leaves any existing cache entry untouched — the
soft-fail posture. ⚠ **`revoked` is the exception, and deliberately so:** it is
an authenticated answer rather than an absence of one, so it EVICTS the cached
entry and returns `error.CertRevoked`. `Cache.getStapled` serves the cached DER
while it's genuinely still valid; `Cache.needsRefresh` tells a scheduler when to
call `refresh` again, ahead of actual expiry. `scripts/modtest ocspcache` runs
the offline tests (mock transport, a loopback server for the HTTP adapter, and
a real fetch→verify→cache round trip against a live-CA delegated OCSP
response); see `SPEC.md` "Verification".

```zig
const ocspcache = @import("ocspcache");
const http = @import("http");

// Production wiring: back the fetch with a real http.Client.
var client = http.Client.init(io, gpa, .{});
defer client.deinit();

var cache = ocspcache.Cache.init(gpa, ocspcache.httpTransport(&client), .{
    // defaults: POST, 64 KiB response bound, 24h max-age fallback,
    // 12h refresh-ahead margin, 64 distinct certs, 10 s body deadline.
});
defer cache.deinit();

// Periodically (your own scheduler — this module has no timer/clock):
if (cache.needsRefresh(my_leaf_cert_der, now_unix)) {
    cache.refresh(my_leaf_cert_der, my_issuer_cert_der, now_unix) catch |err| switch (err) {
        // A verified `revoked` is the CA's signed statement that this
        // certificate is dead; the cache entry has already been evicted, so
        // getStapled below returns null from here on. Soft-fail does NOT
        // apply — this is an answer, not a failure to get one.
        error.CertRevoked => stopServingThisCertificate(),
        // Everything else: log and move on — any still-valid cached response
        // keeps being served by getStapled below regardless.
        else => {},
    };
}

// In the TLS handshake path (wiring the bytes into status_request is the
// TLS server's job — out of scope here):
// The staple is a copy the caller owns (a borrow would dangle the moment the
// scheduler above ran a refresh). A per-connection arena works well here.
if (try cache.getStapled(handshake_gpa, my_leaf_cert_der, now_unix)) |ocsp_response_der| {
    defer handshake_gpa.free(ocsp_response_der);
    // staple `ocsp_response_der`
}
```

## Public API

- `discoverResponderUrl(cert_der) DiscoverError!?[]const u8` — the
  `id-ad-ocsp` `accessLocation` URI from the cert's AIA extension, or `null`
  if there isn't one.
- `Transport` — `{ context: *anyopaque, fetchFn }`, the injectable fetch
  seam; `Transport.fetch(gpa, FetchRequest) FetchError!FetchResponse`.
  - `httpTransport(client: *http.Client) Transport` — the production adapter.
  - `buildGetUrl(gpa, responder_url, req_der) ![]u8` — RFC 6960 Appendix
    A.1.1 GET-form URL, reserved base64 characters percent-encoded.
- `Cache` — `init(gpa, transport, Config) Cache`, `deinit()`.
  - `getStapled(gpa, subject_cert_der, now_unix) !?[]u8` — caller owns the result
  - `invalidate(subject_cert_der) bool`
  - `needsRefresh(subject_cert_der, now_unix) bool`
  - `refresh(subject_cert_der, issuer_cert_der, now_unix) RefreshError!void`
  - `exportEntries(gpa, now_unix) ![]Exported` / `freeExported(gpa, list)` /
    `subjectKey(cert_der)` and `importStaple(subject_cert_der, issuer_cert_der,
    response_der, now_unix) RefreshError!void` — persistence across a restart
    without any I/O: export the still-servable staples (DER + key), write them
    wherever you like, and at startup import each one. Import re-verifies the
    bytes like a fetched response (a stale, tampered, foreign or revoked one is
    refused as `refresh` would), so nothing read back is trusted.
- `Config` — `hash` (CertID hash algo), `fetch_method` (`.post`/`.get`),
  `max_response_bytes`, `max_age_seconds`, `refresh_margin_seconds`,
  `max_entries`, `body_read_timeout_ms` (deadline for the response body,
  `0` = none).
  - `Cache.evictExpired(now_unix) usize` — drops entries past their
    `nextUpdate` (`refresh` does this itself before refusing with `CacheFull`).
- Error sets `DiscoverError`, `FetchError`, `RefreshError` — every failure
  mode is typed (no responder URL, malformed DER, transport failure,
  cancellation, body timeout, oversized response, non-200 (a redirect
  included), unsuccessful OCSP status, verify failure, non-good status, cache
  full).

- **Model after:** RFC 6960 §4.2.2 (OCSP over HTTP) + RFC 5280 §4.2.2.1
  (Authority Information Access); the nginx/Apache OCSP-stapling soft-fail
  posture. Built on this repo's `ocsp` (request/verify), `http` (fetch), and
  `x509` (bounds-safe DER reader) modules.

## Not provided

Embedding the cached response into the TLS handshake (the consuming server's
job), CRL-based revocation, multi-responder failover, HTTP cache headers and any
background scheduler loop (this module has no timers/threads/system clock —
`now_unix` is always caller-supplied). See `SPEC.md` "What is deliberately not
done".

Provenance: clean-room from RFC 6960 §4.2.2 and RFC 5280 §4.2.2.1 (both
public IETF specifications). See `SPEC.md`.
 DATA: `src/goldens.zig` holds a real leaf certificate, its issuer, and the OCSP response a real CA responder returned for them, captured live once and frozen. Those are a public responder's answers to requests we sent — observed behaviour, exempt per root `NOTICE` §0 — not any project's test corpus.
