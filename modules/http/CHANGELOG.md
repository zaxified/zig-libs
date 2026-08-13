# http — changelog

Newest first. See the root [`CHANGELOG.md`](../../CHANGELOG.md) for which
release tag each entry shipped in, and `CONVENTIONS.md` §8 for the policy.

## Unreleased

- **2026-08-13** — **BEHAVIOURAL, not breaking** (`proxy`) — a backend response header the
  proxy cannot put on its own response is no longer dropped silently. Both
  relay loops (h1 and h2) used `catch {}`, so once the writer's copied-header
  budget or its 32-field table ran out, the client received a response that
  *looked* complete while missing whatever came after the limit: the
  `Location` of a redirect, the `WWW-Authenticate` of a 401, the `Set-Cookie`
  of a login, the `Content-Encoding` of a compressed body (which the client
  then decodes as plaintext). Neither end could tell. Such a response now
  answers **502** with the body `Bad Gateway: backend response headers could
  not be relayed`, carrying `Via` so the failing hop is identifiable; the
  half-relayed header set is discarded first, so nothing the backend sent
  rides along on the 502. **What changes for a consumer:** a backend whose
  response headers exceed this proxy's limits used to yield a mutilated 200
  and now yields a 502. Everything inside the limits is byte-for-byte
  unchanged. The injected response-side `Via` is treated the same way (an
  over-long `Via` chain is a 502, not a silently omitted hop); the *request*
  side keeps omitting it, since a header the backend never sees does not
  change what the client believes.
- **2026-08-13** — **BEHAVIOURAL, not breaking** (`proxy`) — the forced early
  `ResponseWriter.end()` at the end of both forward paths is gone. It existed
  so `writeHead` read the relayed header slices before the deferred
  `res.deinit()` freed the backend head buffer they pointed into; those bytes
  are copied now. **What changes for a consumer:** the response head reaches
  the wire when the serving loop ends the response rather than inside the
  handler, so middleware wrapped *around* the proxy can still touch headers
  after it returns — which is a gain (`sessions` saves its cookie there,
  `csrf` issues its token there, and both were silently losing the write on a
  proxied response), but it is an observable change of ordering.
- **2026-08-13** — `ResponseWriter.reset` is now **public**. It discards everything composed so
  far — status, header table, copied bytes, declared trailers, buffered body —
  and is legal only while nothing is on the wire. A handler that composes a
  response and only then discovers it cannot finish it (`proxy` above)
  otherwise has no way to stop the half-built answer from riding along with
  the error status that replaces it. Purely an addition.
- **2026-08-12** — Docs: `setTrailer`'s doc still claimed name and value are stored **without**
  copying and must stay valid until `end`. They have been copied since the
  fix below; the doc was describing the defect it repaired.
- **2026-08-12** — **BREAKING** `Client.Error` gains `error.EntropyUnavailable`. An exhaustive
  `switch` over it stops compiling until it handles the new case; a `catch |e|
  switch (e) { ... else => }` is unaffected, and every in-repo consumer
  (`proxy.statusForBackendError`, `llmclient.mapHttpError`, `h2_upstream`)
  already uses `else`. It exists because `dialConn` now draws TLS key material
  with `io.randomSecure` instead of `io.random`. `std.Io.random` is a CSPRNG
  whose contract permits a silent fallback to a weaker seed
  (`std/Io.zig:2462`), and the default `Io.Threaded` takes it — seeding from
  pid + wall clock + an ASLR pointer. This is the one place in the library
  where that mattered most: the caller hands over `io` because they want
  **sockets**, and the ClientHello random and key share for every HTTPS
  request were being drawn from that same capability with no signal at the
  call site. Now it fails closed instead.
- **2026-08-12** — **BREAKING** `SetHeaderError` and `TrailerError` gain
  `error.HeaderBytesExhausted`. An exhaustive `switch` over either set stops
  compiling until it handles the new case; a `catch |e| switch (e) { ... else
  => }` is unaffected. It exists because header and trailer name/value bytes
  are now COPIED into the response writer rather than borrowed from the
  caller, which buys a byte budget the borrowing version did not have.
- **2026-08-12** — Header and trailer bytes are copied at `setHeader` / `setTrailer` /
  `addSetCookie` time. **This fixes a use-after-scope**: `writeHead` runs
  inside `end()`, which both servers call after the handler returns, so a
  handler that formatted a value into a stack buffer had those bytes read
  after its frame was gone. The old contract ("name/value slices must outlive
  the response") was documented and unmeetable. Callers that worked around it
  with `threadlocal` buffers, or by forcing an early `end()`, no longer need
  to. Debug and ReleaseFast passed the defect by luck; only ReleaseSafe
  exposed it.

- **2026-07-29** — Response **trailers** — the write side, which was previously documented
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
- **2026-07-19** — Security audit: hardened against HTTP request-smuggling (part of the
  collection-wide CRIT/HIGH audit; the root changelog records no further
  detail than this).
