# http — changelog

Newest first. See the root [`CHANGELOG.md`](../../CHANGELOG.md) for which
release tag each entry shipped in, and `CONVENTIONS.md` §8 for the policy.

## Unreleased

- **2026-08-18** — **BREAKING (narrow) + additive** — three fixes from the same audit report,
  landed together: this module has the most consumers in the collection (three, two outside
  the repo), so every change was checked for "does an existing caller passing no new options
  still get the same bytes on the wire".
  **(1) `Options.server_name`/`Date` can now be suppressed through `Server`, not only through
  `serveStream`.** `StreamOptions.server_name` was always `?[]const u8` and `.now` was always
  `?Now` (null = omit), because `serveStream` is the composable codec layer meant to be driven
  with no `Server` at all — but `Server.Options.server_name` was a non-optional `[]const u8` and
  `connMain` always synthesized a non-null `Now`, so a caller going through `Server` (the entry
  point almost everyone uses) had no way to reach the header-free state the socket-free path
  always could. `Options.server_name` is now `?[]const u8` (default unchanged: `"zig-libs-http/0.1"`;
  null = omit `Server`) and `Options.emit_date: bool = true` governs `Date` the same way `false` =
  omit, matching `StreamOptions.now = null`'s effect without spending the `Now` type on a surface
  that only ever wants "the server's own clock or nothing". Pinned by three new `serveStream`
  goldens (each suppression alone, then both together) and two live-loopback `Server` tests, one
  of which asserts the socket path's suppressed head is byte-identical to the socket-free one —
  that agreement is the fix. **Source-breaking, narrowly:** any caller constructing `Options` with
  a string literal or a `[]const u8` value for `server_name` is unaffected (still coerces); a
  caller that *reads* `options.server_name` back out and treats it as non-optional (e.g. passes it
  directly where `[]const u8` is expected) stops compiling. No in-workspace consumer does this —
  verified before landing — and none sets `server_name` at all today.
  **(2) `Server.bind` no longer discards the underlying `std.Io.net` error.** `BindError` stays the
  same two-tag shape (`BadAddress`/`ListenFailed`/`Canceled` — no exhaustive `switch` breaks), but
  the real error each collapsed (`IpAddress.parse`'s `ParseError`, or `IpAddress.listen`'s
  `ListenError` such as `AddressInUse`/`AddressUnavailable`) now survives in the new
  `bindErrorName()` accessor (`@errorName`, a static string — same shape `probe.ConnectOutcome`
  uses for the same reason: `std.Io.net` reports an `anyerror` here, not an errno, so there is no
  numeric code to carry). Purely additive. Pinned by two new tests: a forced `AddressInUse` (a
  second listener on an already-bound port, no `SO_REUSEADDR`) asserts the exact tag survives; a
  forced address-parse failure asserts *a* name survives without pinning which std parse-error tag
  produced it.
  **(3) Documentation only, no code change:** `Options.max_body_bytes` defaults to 1 MiB — any route
  that streams or accepts real uploads must set it to `null` or every body over 1 MiB gets a 413
  before the handler runs, now stated in README where a new consumer meets the option, not only in
  SPEC. Its struct-level asymmetry with `h2_server.Options.max_body_bytes` (`null`) is now documented
  rather than left implicit: `connMain` forwards `Options.max_body_bytes` verbatim into
  `h2_server.Options` for an `enable_h2c` connection, so a `Server`-based consumer gets the same
  hardened default on both protocols — the null default only matters for a caller invoking
  `h2_server.serve`/`.serveStream` directly (BYO-TLS, same permissive-by-default reasoning as
  `StreamOptions.max_body_bytes`). Both defaults are unchanged; nothing was silently uncapped or
  capped as part of this. Also documented: a response over `response_buffer_size` (default 4 KiB)
  switches to chunked framing silently, which has bitten a consumer whose own minimal HTTP client
  does not decode chunked — it now sets an explicit `Content-Length` on every such reply, and the
  README says so next to the option instead of only in a SPEC bullet.
- **2026-08-13** — **BEHAVIOURAL, not source-breaking** — `Client`'s two timeout
  options now bound blocking I/O. Neither did before: `connectTimeout()` was
  `_ = c; return .none;` (the real body commented out behind a
  `TODO(zig-0.16.0)`, because `Io.Threaded` **panics** — "TODO implement
  netConnectIpPosix with timeout" — on a non-`.none` `ConnectOptions.timeout`),
  so `connect_timeout_ms` was read by nothing while being advertised and
  defaulted to 5000; and `total_timeout_ms` had exactly one enforcement site,
  `checkDeadline` at the top of the *redirect* loop, so nothing checked it
  inside the dial, the TLS handshake or any read. Measured against a peer that
  accepts and then says nothing, a request hung indefinitely (>25 s, killed) in
  Debug, ReleaseSafe and ReleaseFast alike — over TLS and over plain http, so
  not a handshake quirk — and the same held for a connect the peer never
  accepted. No option value avoided it.
  The fix does not wait for std to grow a per-read deadline; it uses the
  mechanism std already has. Each blocking phase runs on a concurrent task
  (`runBounded`), and blowing the deadline **cancels** it: `Io.Threaded`
  implements cancelation by signalling the task's thread until the in-flight
  syscall returns `EINTR`, so a blocked `readv`/`connect` unwinds with
  `error.Canceled` instead of never returning. `connect_timeout_ms` now bounds
  name resolution + `connect` (`ConnectOptions.timeout` stays `.none`
  forever — that is the field that panics); `total_timeout_ms` bounds a whole
  `request` and, from the call, an `Upload.finish`. All four scenarios now
  return `error.Timeout` at 300–301 ms against a 300 ms budget in all three
  optimize modes, pinned by four tests that each run the call under a hard
  8 s watchdog so a regression is RED rather than hung, plus a fifth that
  drives the no-concurrency fallback on an `Io` with `concurrent_limit =
  .nothing`.
  Two consequences worth naming. Response **body** reads are still unbounded
  (the caller drives them), as is an `H2Session` past its dial and *everything*
  on an `Io` with no unit of concurrency to give — all three are now stated in
  `Options`, the module doc and the README instead of being implied by a knob
  that did nothing. And cancelation had to be made visible to the client:
  `std.Io.Reader`/`Writer` collapse it into `ReadFailed`/`WriteFailed`, which
  `isStaleConnError` treats as a dead pooled connection worth retrying — the
  retry would have absorbed the one cancelation the task gets and blocked
  again, with `Future.cancel` waiting on it forever. `Conn.readFailure` /
  `writeFailure` recover `error.Canceled` from the socket reader/writer, and
  the retry site now re-checks the deadline before starting fresh work.
- **2026-08-13** — *no behaviour change* — two paths that had never been executed are
  now covered. (1) `proxy.relayFailed`'s **h2** arm (`forwardH2`, `:347`/`:350`/`:351`):
  the existing 502-instead-of-mutilated-200 test drove the h1 forward path only,
  so the second relay loop was asserted by shape alone. The new h2c integration
  test reaches it with a real `http.Server` backend — which cannot overrun the
  copy-store *byte* budget (it has the same one) but can overrun the *field
  count*, because the backend's managed `Date`/`Server`/`Content-Length` cost it
  no table slot yet arrive at the proxy as ordinary headers that do, and the
  proxy adds `Via` on top. Restoring the old `catch {}` on the h2 arm alone
  turns it red (`expected 502, found 200`) while the h1 test stays green.
  (2) `Client`'s `error.EntropyUnavailable` (`dialConn:1099`) is now driven by a
  fault-injected `Io`. Replacing `try io.randomSecure` with the `io.random` that
  line rejects reports `expected error.EntropyUnavailable, found error.TlsFailed`.
- **2026-08-13** — **BEHAVIOURAL, not breaking** — a **failed** `declareTrailers` /
  `declareTrailer` no longer leaves the trailer half-declared. Both
  `trailer_decl_len` and `declared_trailers_len` were advanced *before* the
  `Trailer` advert was re-registered through `putHeader`, and that call can
  fail on the copy-store budget; neither error arm restored either counter.
  The consequence was not counter hygiene. `declared_trailers` **is**
  `setTrailer`'s allow-list, so after a refused declaration `declaredTrailer`
  answered *true*: the caller's retry short-circuited as "already declared"
  and never re-advertised the name, yet `setTrailer` accepted it — putting a
  trailer field on the wire with no `Trailer` header naming it (**RFC 9110
  §6.6.2**), after a call that reported failure. The stuck counter also
  committed the response to chunked framing (`end` branches on
  `declared_trailers_len` alone) and made `setHeader("Content-Length", …)`
  return `InvalidHeader`, both for a trailer that was never declared. The
  second counter had its own effect: the refused name stayed in the generated
  advert text, so it reappeared in — and inflated the byte cost of — every
  later declaration, which could then fail for a budget it was not spending.
  Both are now rewound with an `errdefer`, the same shape `setHeader`'s
  `Trailer` branch already used; the two no longer disagree about what a
  refused declaration costs. Pinned by two tests (allow-list + framing, and
  advert poisoning). No error set or signature changed.
- **2026-08-13** — **BREAKING** `ResponseWriter.reset` returns `ResetError!void` (`error{HeadersSent}`)
  instead of `void`. Callers must `try` it or handle the error; `rw.reset();`
  stops compiling. It was made public earlier today guarded only by
  `std.debug.assert(!rw.sent_head)` — **which is compiled out in ReleaseFast
  and ReleaseSmall**, i.e. a fail-open precondition on a public API in the
  modes people deploy. Measured: an A/B probe whose two arms differed only by
  the `reset()` call put **two complete response heads on one connection** in
  ReleaseFast (`HTTP/1.1 200 OK … Transfer-Encoding: chunked\r\n\r\nHTTP/1.1
  200 OK\r\nContent-Length: 2\r\n\r\nbb`), with the first, chunked body never
  terminated — a response-splitting shape reached by ordinary API misuse, not
  by hostile input. `reset` clears `ended` and sets `body = .buffering` while
  leaving `sent_head` true, so the next `end()` calls `writeHead` again. Worse,
  `setHeader` still returned `HeadersSent` throughout, so a caller checking its
  return values saw nothing wrong. Debug and ReleaseSafe panicked instead. The
  precondition is now a returned error, so it holds in every optimize mode, and
  is pinned by a test that counts status lines on the wire.
- **2026-08-13** — **BEHAVIOURAL, not breaking** — a header or trailer rejected for
  byte exhaustion no longer keeps its name's bytes. `putHeader` and
  `setTrailer` dupe the name and *then* the value into a bump allocator that
  never rewinds, so a rejected pair permanently cost `name.len` of the copy
  store: a handler that retried with a shorter value had strictly less room
  than before it asked. Both now rewind to a mark on failure. This budget is
  what decides `proxy`'s relay-versus-502, so leaking it changed answers.
- **2026-08-13** — **BEHAVIOURAL, not breaking** — `declareTrailers` reports a byte-budget
  exhaustion as `error.HeaderBytesExhausted` rather than flattening it into
  `error.TooManyTrailers`. `TrailerError` carries both members precisely so the
  two limits can be told apart, and `setTrailer` already kept them apart; this
  one call site collapsed them and told a caller that declared ONE trailer that
  it had declared too many. No error set changed, so no exhaustive `switch`
  breaks — only the value a caller receives.
- **2026-08-13** — `Server.header_copy_bytes` (4096) is now **public**, and pinned by value.
  It was a private `const`, which meant `cookies.max_set_cookie_bytes` could
  not import it and the documented "same size as `http`'s copy store" coupling
  was a duplicated literal maintained by a comment in each file. `cookies` now
  imports it and asserts the relation at comptime. The value itself was
  unpinned downward: measured, 4096 → **2048 left the whole http + cookies
  suite green, 451/451, exit 0** — the only test that spends the budget is
  written as `header_copy_bytes / 4` and so follows the constant wherever it
  goes. Since `proxy.relayFailed` this number decides whether a proxied
  response relays or answers 502, so it is now pinned in both directions.
  Purely an addition.
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
  proxied response), but it is an observable change of ordering. **Two halves
  of that this entry originally left out.** First, the same window lets a
  wrapping middleware `setStatus` over the *backend's* status and `setHeader`
  over a relayed backend header; those writes were previously inert
  `HeadersSent` no-ops, so a middleware that always sets a header now silently
  overrides the origin instead of losing to it. Second, the gain is
  conditional: it holds only while the proxied body fits the response buffer.
  A larger body trips `beginStreaming` → `writeHead` inside `streamRemaining`,
  so the head goes out inside the handler exactly as before and the
  post-proxy middleware write is lost again — on precisely the large
  responses where it is least likely to be noticed.
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
