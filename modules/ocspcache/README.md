# ocspcache

OCSP-stapling **fetch + cache** library: discover a certificate's OCSP
responder URL, fetch a fresh signed response for it, verify it, and cache it
until it needs refreshing. A TLS server staples the cached response into its
handshake (RFC 6066 `status_request`) instead of forcing every client to
query the CA itself — this module is the feeder that keeps that cache warm;
embedding the response into the TLS handshake itself is the server's job,
not this module's (see SPEC.md "Scope").

**Status: implemented.** `discoverResponderUrl` extracts the OCSP responder
URL from a certificate's Authority Information Access extension (RFC 5280
§4.2.2.1). `Cache.refresh` builds a request (`ocsp.buildRequest`), fetches it
through an injectable `Transport` (POST by default, RFC 6960 §4.2.1; or the
GET form, Appendix A.1.1), and — only if `ocsp.verify` accepts the response
**and** its status is `good` — caches the raw bytes; every other outcome
(unreachable responder, `tryLater`, a bad signature, a `revoked`/`unknown`
status) is a typed error that leaves any existing cache entry untouched (the
soft-fail posture). `Cache.getStapled` serves the cached DER while it's
genuinely still valid; `Cache.needsRefresh` tells a scheduler when to call
`refresh` again, ahead of actual expiry. `zig build test-ocspcache` (Debug +
ReleaseFast) covers AIA discovery (present/absent/malformed),
a full fetch→verify→cache→serve round trip via a mock transport (no
network), the proactive-margin vs. hard-expiry distinction, a tampered
response never being cached, a `tryLater` response being soft-failed while
the prior good entry keeps serving, a non-200 HTTP status, a
certificate with no AIA entry, the GET-form path, and the cache-size bound.

```zig
const ocspcache = @import("ocspcache");
const http = @import("http");

// Production wiring: back the fetch with a real http.Client.
var client = http.Client.init(io, gpa, .{});
defer client.deinit();

var cache = ocspcache.Cache.init(gpa, ocspcache.httpTransport(&client), .{
    // defaults: POST, 64 KiB response bound, 24h max-age fallback,
    // 12h refresh-ahead margin, 64 distinct certs.
});
defer cache.deinit();

// Periodically (your own scheduler — this module has no timer/clock):
if (cache.needsRefresh(my_leaf_cert_der, now_unix)) {
    cache.refresh(my_leaf_cert_der, my_issuer_cert_der, now_unix) catch |err| {
        // Soft-fail: log `err` and move on — any still-valid cached
        // response keeps being served by getStapled below regardless.
    };
}

// In the TLS handshake path (wiring the bytes into status_request is the
// TLS server's job — out of scope here):
if (cache.getStapled(my_leaf_cert_der, now_unix)) |ocsp_response_der| {
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
  - `getStapled(subject_cert_der, now_unix) ?[]const u8`
  - `needsRefresh(subject_cert_der, now_unix) bool`
  - `refresh(subject_cert_der, issuer_cert_der, now_unix) RefreshError!void`
- `Config` — `hash` (CertID hash algo), `fetch_method` (`.post`/`.get`),
  `max_response_bytes`, `max_age_seconds`, `refresh_margin_seconds`,
  `max_entries`.
- Error sets `DiscoverError`, `FetchError`, `RefreshError` — every failure
  mode is typed (no responder URL, malformed DER, transport failure,
  oversized response, non-200, unsuccessful OCSP status, verify failure,
  non-good status, cache full).

- **Model after:** RFC 6960 §4.2.2 (OCSP over HTTP) + RFC 5280 §4.2.2.1
  (Authority Information Access); the nginx/Apache OCSP-stapling soft-fail
  posture. Built on this repo's `ocsp` (request/verify), `http` (fetch), and
  `x509` (bounds-safe DER reader) modules.
- **Deferred, by design:** embedding the cached response into the TLS
  handshake (the consuming server's job), CRL-based revocation, multi-
  responder failover, and any background scheduler loop (this module has no
  timers/threads/system clock — `now_unix` is always caller-supplied). See
  `SPEC.md`.

Provenance: clean-room from RFC 6960 §4.2.2 and RFC 5280 §4.2.2.1 (both
public IETF specifications). See `SPEC.md`.
