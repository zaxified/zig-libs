# http — changelog

Newest first. See the root [`CHANGELOG.md`](../../CHANGELOG.md) for which
release tag each entry shipped in, and `CONVENTIONS.md` §8 for the policy.

## Unreleased

- **BREAKING** `SetHeaderError` and `TrailerError` gain
  `error.HeaderBytesExhausted`. An exhaustive `switch` over either set stops
  compiling until it handles the new case; a `catch |e| switch (e) { ... else
  => }` is unaffected. It exists because header and trailer name/value bytes
  are now COPIED into the response writer rather than borrowed from the
  caller, which buys a byte budget the borrowing version did not have.
- Header and trailer bytes are copied at `setHeader` / `setTrailer` /
  `addSetCookie` time. **This fixes a use-after-scope**: `writeHead` runs
  inside `end()`, which both servers call after the handler returns, so a
  handler that formatted a value into a stack buffer had those bytes read
  after its frame was gone. The old contract ("name/value slices must outlive
  the response") was documented and unmeetable. Callers that worked around it
  with `threadlocal` buffers, or by forcing an early `end()`, no longer need
  to. Debug and ReleaseFast passed the defect by luck; only ReleaseSafe
  exposed it.

- Response **trailers** — the write side, which was previously documented
  as out of scope. `ResponseWriter.declareTrailers` + `setTrailer` emit a
  trailer section after the terminating chunk on HTTP/1.1 (RFC 9112
  §7.1.2) and as a trailing HEADERS frame carrying END_STREAM on HTTP/2
  (RFC 9113 §8.1 — the last DATA frame therefore does not carry it), from
  the same handler code. Declaring trailers commits the response to
  chunked framing, so `Trailer` and `Content-Length` can never coexist,
  and every framing that cannot carry a trailer section (HTTP/1.0 peer,
  declared `Content-Length`, HEAD/1xx/204/304) is a typed error at set
  time rather than silently dropped output. Field policy is **deny-list ∧
  allow-list**: the RFC 9110 §6.5.1 forbidden set (framing, routing,
  request modifiers, auth, response control data, payload processing,
  plus connection-specific fields, `Cookie`/`Set-Cookie` and any `:`
  pseudo-header) is refused unconditionally, *and* a field must have been
  advertised in `Trailer` first — unconstrained trailers are a
  request-smuggling and cache-poisoning vector because intermediaries
  handle them inconsistently. The h2 **read** gaps closed with it: request
  trailers now reach the handler through the same `Request.trailer`
  surface as h1, and `h2_client.Response.trailers`/`.trailer(name)`
  surfaces response trailers (a trailer block containing pseudo-headers is
  dropped whole, §8.1). Anchored against **live curl 8.18 / nghttp2 1.68**
  on both protocols (`src/curl_interop.zig`), not only against our own
  client.
- Security audit: hardened against HTTP request-smuggling (part of the
  collection-wide CRIT/HIGH audit; the root changelog records no further
  detail than this).
