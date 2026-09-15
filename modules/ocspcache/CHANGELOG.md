# ocspcache — changelog

Newest first. See the root [`CHANGELOG.md`](../../CHANGELOG.md) for which
release tag each entry shipped in, and `CONVENTIONS.md` §8 for the policy.

## Unreleased

- **2026-09-17** — **NO CONSUMER-VISIBLE CHANGE:** tests only. The two `httpFetch` cancel tests (connect/head wait, body wait) canceled after a fixed
  sleep. They now cancel once the client is inside the socket read under test (`ReadCueIo`, a
  `std.Io` double that counts `netRead` entries), and the peer is released from `accept`
  before `join`. On a loaded full gate the sleep could land the cancel before the connect. The
  peer thread then waited in `accept` forever, the shape that hung `http` in full-gate attempt 3.

- **2026-09-10** — **BEHAVIOURAL, not breaking: a responder that answers a head and then
  sends no body no longer parks `refresh` forever (F2).** `httpFetch`'s response-BODY
  read had no deadline of its own — `Config.max_response_bytes` bounds SIZE, never TIME,
  and `http.Client`'s own `total_timeout_ms` explicitly does not cover the body (its own
  module doc says so: "wrap the read in your own `runBounded`-shaped race if you need
  one"). `Config` gains `body_read_timeout_ms` (default 10000ms; `0` disables it, the old
  unbounded behaviour), `FetchRequest` gains the matching `body_timeout_ms` that
  `refresh` now always sets from it, and both `FetchError` and `RefreshError` gain
  `Timeout`, kept apart from `Canceled` (nothing external canceled this — the task gave
  up on its own deadline) and from `TransportFailed` for the same reason `Canceled` is.
  **BREAKING (narrow):** an exhaustive `switch` over `FetchError` or `RefreshError` stops
  compiling until it handles `error.Timeout`; every in-repo caller uses `else =>` and is
  unaffected. Measured against a loopback peer that sends `Content-Length: 5` and no
  body: before this, the only way to get the call back was an external `Future.cancel`
  (still covered by the pre-existing cancellation test right above the new one); after,
  the SAME peer shape makes `httpFetch` return `error.Timeout` on its own, bounded (test
  asserts under 3000ms against a 200ms deadline), with a positive control confirming a
  promptly-answering peer is unaffected by the same 200ms bound.
- **2026-09-10** — **NO CONSUMER-VISIBLE CHANGE:** the `next_update_unix orelse (...)`
  fallback inside `refresh` — RFC 6960 makes a responder's `nextUpdate` optional, and a
  response omitting it falls back to `this_update_unix + Config.max_age_seconds` — had
  zero test coverage; every fixture in this suite carries a real `nextUpdate`, so the
  `None` arm, a legal wire shape, had never actually run. Split into a private
  `Cache.nextUpdateFor` so it is unit-testable without a full signed-response round trip
  through `ocsp.verify` (which is what building a fixture without `nextUpdate` would
  otherwise require). Two new direct tests cover both arms; an off-by-one mutant of the
  fallback arithmetic was confirmed to fail one of them before being reverted.
- **2026-09-07** — Test-only, no production change: both fuzz targets replayed a single
  input, and in `fuzzRefresh` that pinned every branch it selects. Each opened
  `smith.bytes(&raw)` and then drew `raw_len` from a ranged draw, which returns the range
  MINIMUM when fewer than eight octets remain - so `raw_len` was **0** on every input the
  ordinary lane ever ran and every "fuzzed bytes" argument was the empty slice. Every knob
  drawn after it was its own minimum too: in `fuzzAia` the accessLocation tag was always
  index 0, the mutation count 0 and the truncation always the zero-length cut; in
  `fuzzRefresh` the body mode was always 0, so the mutate, truncate and arbitrary-bytes
  responder bodies had **never been produced**, the status came from a false
  `smith.value(bool)` and was always 0, the fetch method was always GET, and `now` was
  always the capture's own timestamp. Both now draw with one `smith.slice(&raw)` and carry
  a corpus whose seeds each supply the `u64` words their own branches read. Measured by the
  two new `corpus:` guards - AIA: 7 non-empty seeds, 1 resolved URL, **8 mutations applied**
  and all five accessLocation tags exercised, truncations totalling 14875 octets; refresh:
  **all four body modes and all three `now` modes**, 3 non-200 statuses and 2 POST fetches.
  A note for the next author: the AIA guard was first written with a mutation loop that did
  not mirror the harness's own `@min(draw, raw_len)`, so it consumed a different word
  stream and reported a truncation total less than half the real one.

- **2026-09-03** — Drift re-audit. **The responder no longer chooses where the
  fetch goes.** `httpFetch` left `http.Client`'s `follow_redirects` at its
  DEFAULT of `true` (up to 10 hops), and `isHttpUrl` screens the AIA URI once
  and is never re-applied to a redirect target — so a `302` pointed the fetch
  at any host the responder named, and a `307`/`308` replayed the OCSP request
  BODY there. Reproduced against two loopback servers. This is worse than an
  attacker-supplied-certificate problem: OCSP is fetched over cleartext
  `http://` by deployment, so any on-path attacker could aim it, against the
  module's DOCUMENTED use — a server stapling its own certificate. Now refused,
  and a redirect arrives as a non-200 status that `refresh` rejects as
  `ResponderHttpError`.
- **2026-09-03** — **An expired entry no longer holds a cache slot forever.**
  `invalidate` and `deinit` were the only removals, so entries past their
  `next_update_unix` — already unservable, since `getStapled` reports them
  absent — occupied `max_entries` permanently. No attacker: the cache key is
  the certificate and every ACME renewal makes a new one, so `max_entries`
  renewals into a long-lived server `refresh` starts answering `CacheFull` for
  the certificate actually being served and stapling silently stops,
  unrecoverable short of `deinit`. `refresh` now reclaims expired entries
  before refusing; `evictExpired` is public for an operator with its own tick.
- **2026-09-03** — **The response-size ceiling is enforced by this module**, not
  only by the `Transport` it hands `max_response_bytes` to. Every mock in this
  repo ignores that field, so a third-party transport doing the same silently
  removed the documented bound — and unplumbing it at the one call site left
  the whole suite green.
- **2026-09-03** — Docs: README claimed a `revoked` status "leaves any existing
  cache entry untouched", contradicting both the code and its own example
  thirty lines later; and the 2026-08-06 entry below claimed a live capture
  from nginx/Apache that does not exist. Both corrected in place rather than
  rewritten away.
- **2026-09-03** — ⛔ **Recorded, NOT fixed.** `httpFetch` sets no deadline on the response BODY
  (`total_timeout_ms` explicitly does not cover it), so a responder that sends
  a head and goes quiet parks the refresh indefinitely — needs a
  `Config.fetch_timeout_ms` plumbed through `io.concurrent`/`Future.cancel`.
  The `verdict.next_update_unix orelse …` fallback has zero coverage: every
  fixture carries a `nextUpdate`, so a legal RFC 6960 shape is never
  exercised, and the synthesized-expiry constant is unpinned. The two fuzz
  harnesses reach almost nothing in the deterministic lane (`fuzzRefresh` gets
  `status = 0` and never reaches `ocsp.parseResponse`).


- **2026-08-22** — `FetchError`/`RefreshError` gain `error.Canceled`, and `httpFetch`
  (the production `Transport` behind `httpTransport`) no longer folds a canceled
  `http.Client` call into `error.TransportFailed`. Both of its `catch` sites named
  the variant explicitly: the initial `client.request`, and the `readAllAlloc` body
  read one call later (the second only became fixable once `http`'s own root cause —
  `Response.readAllAlloc`'s blind `else` arm — was fixed; see `http`'s
  `CHANGELOG.md`). `Cache.refresh`'s own `self.transport.fetch(...)` switch was
  exhaustive over `FetchError`'s old three variants and needed the fourth arm added
  to keep compiling. **BREAKING (narrow):** an exhaustive `switch` over `FetchError`
  or `RefreshError` stops compiling until it handles `error.Canceled`; a
  `catch |e| switch (e) { ... else => }` (every in-repo caller, including the
  `example/`) is unaffected. Two new loopback tests, one per fixed `catch` site (a
  peer that never answers, and a peer that answers a `Content-Length: 5` head and
  then no body), each confirmed to fail with its own fix reverted
  (`expected error.Canceled, found error.TransportFailed`) and to pass restored,
  without disturbing the other. `zig build test-ocspcache` — 34/34.
- **2026-08-06** — Security audit: six findings fixed, one documented as accepted (not
  defects) — part of the collection-wide audit. ⚠ **This entry used to end
  "Verified against a live capture from nginx `ngx_ssl_stapling` / Apache
  `mod_ssl` stapling cache". There is no such capture** — corrected 2026-09-03.
  What nginx/Apache are to this module is a *design* reference, which is what
  `root.zig`'s `meta.model_after` actually says ("nginx/Apache OCSP-stapling
  soft-fail **posture**"); the sentence was a template that renders a
  C-reference-implementation field as a claim of a verified capture. The
  module's real external anchor is the committed GoDaddy OCSP capture in
  `src/goldens.zig`, independently accepted by `openssl ocsp -respin`.
- **2026-07-22** — New module: OCSP-stapling fetch + cache on top of `ocsp`.
