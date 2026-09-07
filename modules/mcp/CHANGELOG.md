# mcp — changelog

Newest first. See the root [`CHANGELOG.md`](../../CHANGELOG.md) for which
release tag each entry shipped in, and `CONVENTIONS.md` §8 for the policy.

## Unreleased

- **2026-09-07** — Fuzz reach: neither fuzz target reached what it names. `fuzzHandleMessage`
  opened `smith.bytes(&buf)` and then drew the length with `smith.valueRangeAtMost`;
  `bytes` consumes `@min(buf.len, in.len)` octets and a ranged draw reads EIGHT more as a
  little-endian `u64`, returning the range MINIMUM when fewer remain, so the length was 0
  — and with no corpus the one input it ever ran was empty. `handleMessage("")` is a
  -32700 parse error and not one dispatch branch was entered; the peer id was
  `smith.value(u64)` drawn AFTER the bytes, so the `handleMessageFrom` arm the comment
  calls out as "the peer arm the harness above never exercised" was itself always called
  with peer 0. `fuzzClientResponse` opened `smith.index(2)`, so all four of its fuzzed
  rounds were `.sampling` on peer 0 carrying byte-identical answers, and its miss-path
  round used id 0 and peer 0 — a peer that IS armed, so it was not the miss it is named
  for. ⚠ Its hand-written aim canary kept passing throughout, which is why the target
  looked healthy: it asserts three correlating answers that do not depend on the fuzzer at
  all. ⭐ And reaching `tools/call` for the first time crashed immediately:
  `testServer(null)` leaves the registered `echo` tool's `ctx` null while `echoHandler`
  opens with `ctx.?`, so the fixture the harness chose could not survive the
  param-validation path its own comment says it exists to reach. The harness now passes a
  live `TestApp`. `fuzzHandleMessage` draws byte-first with one `smith.slice` over 19
  written JSON-RPC lines (one per dispatch branch, plus the malformed shapes) and runs
  both peers on every input instead of drawing one. `fuzzClientResponse` draws a SHAPE, so
  it reads every choice — kind, peer and the whole JSON tree — out of one byte-first slice
  through `testkit.fuzz.Cursor`, over eight scripts of which the first is the EMPTY one,
  reproducing the collapsed harness exactly. Guards pin 1661 reply octets / 9 error
  replies, and 8 distinct response lines over 470 octets (1 distinct before).

- **2026-09-02** — Drift re-audit (window `15486ba..HEAD`, +1219 lines). Five findings, all fixed:

  - **HIGH, cross-session capability grant:** `client_capabilities`, `negotiated_version` and
    `client_initialized` were three fields on the `Server`, and a `Server` is deliberately shared —
    `mcp-http` serves every session from one. So `initialize` from *any* peer replaced the gate for
    *all* of them: a party that could POST opened a session, declared `elicitation`, and
    `elicitation/create` — the phishing primitive this module documents at length — was then
    written to a client that had declared nothing, in a revision it never negotiated. The reverse
    handle worked too: a session declaring `capabilities:{}` revoked every other session's
    sampling/elicitation, and the single `max_pending` budget let one session starve the rest.
    Peer scoping already existed for response *correlation*; it now covers the handshake as well.
    **BREAKING (minor):** the three fields are gone, replaced by `PeerState` and the accessors
    `clientCapabilities(peer)` / `clientInitialized(peer)` / `negotiatedVersion(peer)`;
    `max_pending` is counted per peer. New: `forgetPeer(peer)`, which a multiplexing transport
    calls when a session ends, and `max_peers` (default 4096), which bounds what accumulates if it
    does not.

  - **HIGH, unparseable responses:** `structuredContent` was gated on a brace *count* that shared
    one counter between `{}` and `[]`, so `{]`, `{"a":1]` and `{[}]` all read as "exactly one
    top-level JSON object" and were spliced into the response verbatim. `allow_structured` defaults
    to true and the spliced text is the tool's output, so **one ordinary `tools/call` against any
    pass-through tool made the server emit a line the client cannot parse**. The check is now a
    real `std.json` validation.

  - **MEDIUM, one state and two readers:** the same count could not see a raw control character
    inside a string — invalid JSON, which the newline-strip then *repaired* into valid JSON holding
    a different value than the text block beside it. A tool output of `{"a":"x<LF>y"}` produced
    `text` = `x\ny` and `structuredContent.a` = `xy`, the divergence chosen by the caller. Closed
    by the same validation: the strip now only ever removes insignificant whitespace.

  - **MEDIUM, host confusion in the elicitation URL guard:** the authority ended at the first of
    `/?#`, per RFC 3986. The WHATWG URL Standard — which is what every browser and JS-SDK client
    uses, i.e. the party that actually *opens* the URL — also ends it at `\`. So in
    `http://evil.example\@localhost/` this module read the host as `localhost` (loopback, http
    allowed) while the client navigates to `http://evil.example/` in plaintext. The delimiter set
    now includes `\`, which also fixes the mirror-image error (a genuinely loopback
    `http://localhost\@evil.example/` was refused).

  - **LOW, a request with no response:** `notifications/initialized` was handled *before* the id
    check, so the shape carrying an `id` mutated server state and got nothing written back —
    against this module's own stated invariant that a request gets exactly one response. It is now
    answered `-32600`, and a message being rejected no longer sets the flag.


- **2026-08-22** — Two transport-boundary fixes:
  - `readLine` now discards an unterminated final line — the stream ends, or a
    cancelable read is canceled, mid-line — instead of handing the fragment
    to `handleMessage` as if it were complete. Previously that produced a
    `-32700` parse-error response written to a peer that, in the EOF/cancel
    case, is already gone. Matches the official Python SDK (silently
    discards a trailing fragment on EOF, verified up to ~4 MiB) and the Rust
    SDK's own reversal (PR #833 answered it, PR #940 reverted after issue
    #938 showed it causes an error-bounce loop: the peer reads the error
    response as more invalid input and answers with another error). The
    `max_line_len` overflow path already worked this way; this makes the
    plain-EOF/cancel path match it.
  - **BREAKING (minor):** `Error` gains a `Canceled` variant — a public API
    widening affecting every function that returns `Error!…`, though only
    `serveStdio` can actually produce it: a `std.Io` cancelation of its
    blocked read now surfaces as `error.Canceled` instead of being folded
    into the ordinary `{}` "session end" return. `serve` cannot make this
    distinction itself (it is handed only a foreign `*std.Io.Reader`
    interface, not the concrete reader the cancelation state lives on) and
    keeps returning `{}` for EOF, cancelation and a dead peer alike — see
    its doc comment for how a caller with its own concrete reader recovers
    the distinction, and `serveStdio`'s for how it does. A consumer with an
    exhaustive `switch` over `mcp.Error` needs a new arm (or an `else`). `initialize` no longer advertises the `resources`/`prompts`
  capability keys unconditionally. Each is now present only when its own catalog is non-empty at
  the moment `initialize` is answered (`resources` also counts resource templates); `tools` is
  unchanged — still present in every result, empty catalog or not. A server that registers only
  tools now serves an `initialize.capabilities` object with a single `tools` key instead of three.
  Per the spec's `ServerCapabilities` schema ("Present if the server offers any …") and
  basic/lifecycle.mdx's Operation-phase MUST ("only use capabilities that were successfully
  negotiated"), the old behavior was misleading: a tools-only server was telling a
  spec-conformant client it could call `resources/list`/`prompts/list` for real content. See
  SPEC.md's "Advertised capabilities track the registered catalog" for the design note.
- **2026-07-29** — Server→client requests — `sampling/createMessage` and
  `elicitation/create`. Both are gated on the capabilities the client
  declares at `initialize`, which are now *stored*
  (`Server.client_capabilities`, all-false before a handshake, replaced
  wholesale on re-`initialize`) rather than parsed and discarded. Because
  `handleMessage` owns no reader, the API is issue-now / correlate-later:
  `sendSamplingRequest`/`sendElicitationRequest` allocate a never-reused
  id, write one request line and register it pending; `handleMessage`
  correlates the inbound response and invokes the registered
  `ResponseHandler` (a tool that needs the answer is therefore two
  calls). No handler ever blocks and no async runtime was added. (The
  sibling `mcp-http` transport receives the client's answer on a
  *separate POST*; see its own changelog for the transport-specific
  half of this feature.) Elicitation schemas are validated against the
  spec's restricted JSON-Schema subset, and form-mode schemas with
  credential-shaped fields are **refused** (`SchemaSensitiveField`) — the
  spec's "MUST NOT ask for secrets" enforced rather than documented, with
  URL mode as the sanctioned alternative. Request lines are pinned
  byte-for-byte against the specification's own JSON examples.
  **Fixes:** a client's JSON-RPC *response* previously hit the "Missing
  method" branch and got a `-32600` reply (JSON-RPC forbids answering a
  response); and `negotiateVersion` echoed the caller's slice, which
  lives on the per-message arena.
- **2026-07-19** — Security audit: a CRIT/HIGH finding was fixed (part of the
  collection-wide audit; the root changelog records no further detail
  than this).
