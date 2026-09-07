# mcp-http — changelog

Newest first. See the root [`CHANGELOG.md`](../../CHANGELOG.md) for which
release tag each entry shipped in, and `CONVENTIONS.md` §8 for the policy.

## Unreleased

- **2026-09-07** — **Test-only: all twelve real JSON-RPC bodies in the fuzz
  corpus reached the pre-parse scanners as the EMPTY body**, including the
  `initialize` request the scanners exist to recognise. `buildJsonRpcish`
  opened with `smith.valueRangeAtMost(u8, 0, 5)` to choose between "arbitrary
  bytes" and "assemble a JSON object". A ranged `Smith` draw reads EIGHT
  octets as a little-endian `u64` and returns the range MINIMUM unless that
  whole word already lies inside the range — `{"jsonrpc` is nowhere near 0..5
  — so every seed took the arbitrary-bytes branch, `smith.bytes(&raw)` ate the
  rest of the body, and the ranged length after it found nothing left and
  returned 0. Measured 2026-09-07: **0 of 12 seeds carried an octet, and
  neither scanner ever got past `object_begin`** — so the hand-written scan
  loop, the whole reason this target exists, had never run. One `smith.slice`
  draw now, read as a script whose first octet selects "the rest is the body
  verbatim" or "the rest assembles a JSON object" through
  `testkit.fuzz.Cursor`. Corpus 12 → 18, adding a string `id`, the `method`
  key repeated, and the empty object. Measured after: **17 of 18 seeds
  non-empty over 1129 octets, 3 `initialize` requests recognised and 2
  correlatable responses found.** ⭐ The guard pins those two decisions rather
  than "the scanner returned without an error": `{}` is legal JSON with no
  keys, so an error-free return would have read green on a corpus that walked
  nothing.

- **2026-09-02** — Follow-on from the `mcp` drift re-audit: `mcp.Server` now keeps handshake state
  **per peer**, and a peer handle is this transport's session tag — so the server has to be told
  when a session ends or its peer table only grows, and past `Server.max_peers` it starts refusing
  new handshakes outright. Session teardown now writes back: `destroy` and `evictIdle` report the
  freed session's tag (`bool` → `?u64`, `Created` gains `evicted`), and every teardown path —
  `DELETE`, a `close()`d session's final `GET`, and eviction under `max_sessions` — calls
  `Server.forgetPeer` under the transport lock.


- **2026-09-02** — Drift re-audit (W2, window `0575340..HEAD`). Three findings, all fixed:

  - **HIGH, broken isolation:** session ids were **guessable**, and possession of an id is the
    entire gate on `GET`/`POST`/`DELETE` for that session — so the peer-scoping property this
    module advertises ("a response POSTed on session B can never resolve a request issued to
    session A") rested on it. An id was `monoNs() ^ (@intFromPtr(store) *% K)` in the high 64 bits
    and a plain incrementing counter in the low 64, under a comment calling that "hard to guess".
    Bracketing a victim's `initialize` with two of your own pins the counter exactly, and XORing
    two of your own ids cancels the process-constant `K` completely — leaving the monotonic-clock
    delta between two closely-spaced calls, **≈2^20 candidates**, each testable over the wire as
    one `GET`. Reproduced end to end: read another session's pending `sampling/createMessage` and
    answer it with forged content. Ids are now 128 bits from `getrandom(2)`.
    ⚠ Note the prior audit's `session-id-not-a-secret: PASS` was written **before** the
    peer-scoping work made unguessability load-bearing — a PASS that went stale without the code
    it was about changing.
  - **MEDIUM, availability:** `max_sessions` had no expiry and no eviction. Nothing but an explicit
    `DELETE` ever freed a session, so `max_sessions` abandoned `initialize`s pinned the table full
    **forever** and every later client got 429 indefinitely — the cap that fixed an unbounded-memory
    DoS had turned it into a permanent lockout. `create` may now reclaim the least-recently-touched
    session once it is idle past the new `max_idle_ns` (30 min). Deliberately not a plain LRU:
    evicting a live session to admit a new one would turn a flood into a cross-client denial.
  - **LOW:** `Sessions.close()` was inert. It set a `closing` flag that nothing read — `handleGet`
    discarded `drainAfter`'s bool — so after `close` the session still accepted `push`, still
    existed, and was never torn down, against its own doc ("its next `GET` drains what is queued
    and ends"). `handleGet` now honours it. The regression test drives the wire, not `drainAfter`:
    a test that asserts the flag comes back passes with the wiring removed.

- **2026-08-14** — `zig build check-fuzz` coverage: a `testing.fuzz` harness on
  `isInitialize`/`correlatableResponse`, the hand-written single-pass `std.json.Scanner`
  walk that pre-parses a POST body BEFORE `mcp.Server.handleMessageFrom`'s authoritative
  parse. Generates both arbitrary bytes and JSON objects built from the field names the
  scanners branch on, with scalar/nested/long/escaped values so the forced-allocation
  paths (`.allocated_string`/`.allocated_number`) are exercised, run under
  `std.testing.allocator` so a leak on any error path fails loudly. No panic, hang or
  leak found. `mcp.Server.handleMessageFrom` itself is `mcp`'s own decode surface, not
  this module's.
- **2026-07-29** — Carries the transport half of `mcp`'s new server→client requests
  (`sampling/createMessage`, `elicitation/create`; see the sibling `mcp`
  changelog for the protocol-level design). Because this transport
  receives the client's answer on a *separate POST* rather than on a
  held connection, the request/response pair is issue-now /
  correlate-later, and correlation is scoped **per session** — one
  session's answer cannot resolve another session's pending request.
  **Fix:** the `application/json` response body previously concatenated
  every line the server wrote instead of emitting just the response.
- **2026-07-19** — Security audit: two findings fixed (part of the collection-wide
  audit; the root changelog records no further detail than this). Modeled on the
  official MCP Streamable HTTP transport implementations (TypeScript SDK, `mcp_dart` —
  cited in the module's own `model_after`) (design reference, not a test anchor).
