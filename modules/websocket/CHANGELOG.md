# websocket — changelog

Newest first. See the root [`CHANGELOG.md`](../../CHANGELOG.md) for which
release tag each entry shipped in, and `CONVENTIONS.md` §8 for the policy.

## Unreleased

- **2026-09-28** — **BEHAVIOURAL, not breaking** (found by qap's Autobahn lane, 2026-09-26):
  `Connection.receive` now validates a text message's UTF-8 (§5.6) incrementally, per fragment, via
  the new `IncrementalUtf8` (`connection.zig`) — invalid UTF-8 in an early fragment is now refused
  (`error.InvalidUtf8`, close 1007) at that fragment, not only once the whole message has been
  reassembled at `FIN`. Before this, Autobahn|Testsuite scored §6.4.1-4 NON-STRICT: RFC 6455 §8.1
  requires the failure, not its timing, but every other library checked (autobahn-python, gorilla,
  tungstenite) fails at the fragment. A code point legitimately split across fragments (§5.4) is
  still accepted; a message that ends (`FIN`) with a multi-byte sequence still pending is now also
  refused, which it previously was not by construction (there was no cross-fragment state to notice
  it). `IncrementalUtf8` is `std.unicode.utf8ValidateSlice`'s own algorithm decomposed into one
  state transition per byte, not a second implementation — proven equivalent to it over the frozen
  Kuhn corpus and 500 fixed-seed-random byte strings, at every possible fragment split point
  (`connection.zig`'s new equivalence tests). The single-frame (unfragmented) text path is now
  routed through the same validator for the same reason (`utf8ValidateSlice` survives only as a
  `std.debug.assert` cross-check on the accept path, compiled out in ReleaseFast). **Behavioural,
  not breaking:** no signature changed, and every message that was already accepted or already
  rejected keeps that same verdict (proven by the new equivalence tests) — the only observable
  difference is *when* a message that was always going to be rejected gets rejected: at the
  fragment carrying the offending byte instead of only once `FIN` arrives. A message ending
  mid-code-point was already caught at `FIN` by the old whole-message check and still is; that case
  is unchanged. See SPEC.md's "Connection" paragraph for the design and equivalence argument.

- **2026-09-28** — **BEHAVIOURAL, not breaking** (requested by qap security review M6.2,
  2026-09-24): `acceptHandshake` now checks the request's `Origin` header.
  `ServerAcceptOptions` gains `origins: []const []const u8 = &.{}` (new field with a default, so
  every existing call site — including `bacnet`'s `sc_ws.serverAccept`, which never sends an
  `Origin`, and this module's own `example/main.zig` — keeps compiling and behaving unchanged for
  requests with no `Origin` header). The default policy: no `Origin` header is allowed (RFC 6455
  requires browsers to send one, so its absence means a non-browser caller); an `Origin` whose
  authority matches the request's `Host` header, case-insensitively and byte-for-byte (no
  default-port guessing — this module never learns the transport, so it cannot assume a scheme's
  default port), is allowed; anything else is the new `error.OriginNotAllowed` (a typical caller
  maps it to HTTP 403). Passing a non-empty `origins` list replaces the same-host default with an
  explicit allow-list (`"*"` = any origin), the same shape as gorilla's `Upgrader.CheckOrigin`. A
  duplicated `Origin` header is `error.DuplicateHeader`, same as the other handshake-critical
  headers this module already checks. **Behavioural, not breaking, because no signature changed**
  — but a caller whose clients send a cross-origin `Origin` header and relied on it being ignored
  will now see `acceptHandshake` reject those requests; pass `.origins = &.{"*"}` to keep the old
  "don't check" behavior explicitly. See SPEC.md's "`Origin` allow-list" for the full design and
  matching rule, and `handshake.zig`'s `ServerAcceptOptions.origins` doc comment for the exact
  API. Fixes the one case flagged stale in `tools/README.md`'s differential-oracle result (the
  module now diverges from python-websockets' bare `ServerProtocol`, which enforces no `Origin`
  policy of its own — a deliberate, documented divergence, not a regression).

- **2026-09-24** — **New `handshake.respond(rw, accept)`**: answers a validated handshake from an
  `http.Server` handler — `Sec-WebSocket-Accept` (+ `Sec-WebSocket-Protocol`) and the 101 through
  `http`'s new `ResponseWriter.upgrade`. `writeResponse` stays for callers that own the raw writer.
  `error.Unsupported` (HTTP/2, a body, HEAD) sets no header, so the handler can still answer an
  error. Tested end to end through `http.Server.serveStep` on the RFC §1.3 example, including the
  client's first frame left in the reader. Additive.

- **2026-09-14** — **BREAKING (error set):** A1 F6, round-2 decision Q7 (API change allowed, consumer
  fixed in the same batch). `writeFrame` guarded the control-frame invariants (`fin`, payload ≤ 125)
  with `std.debug.assert`: in ReleaseFast a 200-byte ping went out as `89 7e 00 c8`, which this
  module's own parser rejects, and in Debug/ReleaseSafe the same call panicked the process — while
  `pongFor` builds `WriteOptions` from a received payload. `writeFrame` now returns the new
  `frame.WriteError` (`std.Io.Writer.Error || error{FragmentedControlFrame, ControlFrameTooLarge}`)
  and refuses such a frame before writing a byte. Consumer `bacnet` (`sc_ws.writeMessage`, always
  one binary frame) keeps its signature and maps the two new variants to `unreachable`.

- **2026-09-11** — A1 fix campaign, F5's second half (test-only, no
  production behavior change): `connection.zig` and `handshake.zig` had zero
  fuzz harnesses, and the `.client` role had none anywhere in the module, so
  `error.MaskedServerFrame` (the one rule that only exists for that role)
  was never exercised by anything adversarial. Three new fuzz targets, each
  with a paired `corpus: ...` reach test that replays the same corpus
  deterministically (no `--fuzz` needed) and pins how many seeds produce
  each class of outcome -- the discipline this campaign's `opaque` module
  needed and didn't have, where three harnesses never got past `fromBytes`
  and so could never have found anything:
  - `Connection.receive`, `.client` role: fragment reassembly across two
    frames, the close handshake, `MessageTooLarge` mid-reassembly,
    `TooManyFragments`, `DataAfterClose`, and -- the named gap --
    `MaskedServerFrame` (a masked frame is illegal from a server).
  - `handshake.verifyResponse`, `.client` role: fuzzes
    `h1.ResponseHead.parse` and `verifyResponse` together (the real
    attacker-controlled input is the raw bytes, not the pre-parsed head),
    covering every one of its seven error variants including
    `AcceptMismatch`, the core anti-cache-poisoning check.
  - `handshake.acceptHandshake`, `.server` role: same shape, the other
    direction, covering all eight of its error variants.

  scripts/modtest websocket: 85/85 (Debug and ReleaseFast); consumer
  `bacnet` unaffected (257/260, 3 pre-existing environment-gated skips).

- **2026-09-10** — **BEHAVIOURAL, not breaking:** `verifyResponse` now rejects a `101` response
  that carries a `Sec-WebSocket-Extensions` header (`error.UnexpectedExtension` — this module
  never offers an extension, so any value there is unrequested per RFC 6455 §4.1 point 5) or a
  duplicated `Upgrade`/`Sec-WebSocket-Accept`/`Sec-WebSocket-Protocol` header
  (`error.DuplicateHeader`, mirroring the server side). `acceptHandshake` now also rejects a
  duplicated `Sec-WebSocket-Protocol`. `writeRequest` now validates `host`/`target`/`key`/
  `protocols`/`extra_headers` for CR/LF/NUL injection before writing anything
  (`error.InvalidRequestField` — new member on `writeRequest`'s return type, additive). A caller
  passing well-formed fields (the only kind a conforming implementation sends) sees no change.
  `connection.Connection` gained `max_fragments` (default 65536, new field with a default) —
  `error.TooManyFragments` once a single reassembled message exceeds it — and any error from
  `receive` now resets in-progress fragmentation state instead of leaving it for a later,
  unrelated frame to splice onto.
- **2026-09-07** — Fuzz reach: both `frame.zig` harnesses ran on an empty input, and one of
  them never called the parser at all. Each opened with `smith.bytes(&buf)` followed by a
  ranged length draw; a ranged draw reads eight octets as a little-endian u64 and returns the
  range MINIMUM when fewer than eight remain, and `bytes` had already eaten the seed, so `len`
  was **0 on every input**. In `fuzzParseFrameServer` that `len` is the bound of the
  parse-and-advance loop, so `parseFrame` was **never invoked** — while the comment above it
  promised multi-frame streams and `.need_more` retries. In `fuzzDecodeCloseBody` the collapse
  looked healthy instead: `decodeCloseBody("")` succeeds by design (§5.5.1), so the harness
  returned a `CloseInfo` on all 19 rounds without ever reading a close code. Both now draw with
  one `smith.slice(&buf)` and carry a commented corpus with a guard pinning measured numbers.
  Measured 2026-09-07, before → after: `fuzzParseFrameServer` 0/18 seeds reaching `parseFrame`
  and 0 frames parsed → 18/18 and 7; `fuzzDecodeCloseBody` 19/19 "accepted" with 0 close codes
  read → 11 accepted, 10 codes and 131 reason octets validated.

- **2026-08-06** — Security audit: six findings fixed (part of the collection-wide
  audit; the root changelog records no further detail than this). Byte-exact against RFC
  6455 §5.7's published test vectors.
- **2026-07-22** — New module: RFC 6455 WebSocket — opening handshake + frame layer
  (masking direction enforced, fragmentation, control frames, UTF-8 validation, close
  codes, per-frame + aggregate size caps), transport-agnostic.
