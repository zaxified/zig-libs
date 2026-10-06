# mcp — changelog

Newest first. See the root [`CHANGELOG.md`](../../CHANGELOG.md) for which
release tag each entry shipped in, and `CONVENTIONS.md` §8 for the policy.

## Unreleased

- **2026-10-06** — **Evidence MIXED → EXTERNAL: the official MCP Python SDK 2.3.0 as a differential
  client** (`tools/sdk_oracle/drive.py`; frozen transcript replayed by `src/sdk_oracle.zig`). Both eras
  — `initialize` session and stateless 2026-07-28 with `server/discover` and a multi round-trip tool —
  over tools, resources, templates, prompts and ping: every answer accepted by the SDK's typed client,
  40 checks passed (teeth: the SDK refuses a stub's malformed `tools/list`). No defect. The SDK still
  sends `ping` on the 2026-07-28 path, which that revision removed; our -32601 stands.
- **2026-10-02** — `Server.addTool` checks the tool's `x-mcp-header`
  annotations (spec 2026-07-28) and refuses a tool that breaks them —
  `HeaderAnnotationNotReachable`, `HeaderAnnotationInvalidName`,
  `HeaderAnnotationDuplicate`, `HeaderAnnotationInvalidType`. Such a tool is one
  a Streamable HTTP client must drop from `tools/list`; before, it vanished for
  those clients without anyone being told. New `header_annotations` namespace.
  **Source-breaking for an exhaustive `switch`** over `addTool`'s errors (a
  `try` is unaffected); `mcp-http`'s example had one.

- **2026-09-30** — **`subscriptions/listen`** (spec 2026-07-28, basic/patterns/subscriptions.mdx):
  answered with the acknowledgment of an empty filter (`notifications/subscriptions/acknowledged`,
  `_meta.io.modelcontextprotocol/subscriptionId`) followed at once by the graceful-close result, since
  this server emits no change notifications. New `DispatchMethod.@"subscriptions/listen"`,
  `OriginatedMethod.@"notifications/subscriptions/acknowledged"`, `meta_key.subscription_id`. ⚠ An
  exhaustive `switch` over either enum needs the new arm.

- **2026-09-30** — **Multi round-trip requests (spec 2026-07-28, basic/patterns/mrtr.mdx).** A modern
  `tools/call`, `prompts/get` or `resources/read` can ask the client for input: new `InputRound` on
  `ToolCall.input`, `PromptRequest.input`, `ResourceRequest.input` — `ask(key, InputRequest)` (sampling or
  elicitation, gated by the request's `_meta` capabilities, same checks as the session path), `setState`,
  and on the retry `response`/`elicitation`/`sampling`/`receivedState`. Anything asked turns the reply into
  an `InputRequiredResult` (`resultType:"input_required"`). A malformed `inputResponses`/`requestState` is
  -32602. New `StateSeal` (HMAC-SHA-256 integrity for `requestState`, bound to method, target, principal
  and expiry; `InputRound.sealState`/`openState`), `InputError`, `InputRequest`, `RequestCheckError`.
  Session-path replies unchanged; `SendError` unchanged. Anchored on the spec's `InputRequests`,
  `InputResponses` and state-only `InputRequiredResult` examples.

- **2026-09-30** — **MCP spec 2026-07-28, served alongside the `initialize` revisions** (plan M1–M4 in
  SPEC.md). A request whose `params._meta` carries `io.modelcontextprotocol/protocolVersion` is served
  statelessly: capabilities and client identity from that `_meta` (`ModernRequest`, reached through
  `ToolCall.modern`; `call.clientCapabilities()`/`clientInfo()` read it, new `call.protocolVersion()`),
  results with `resultType` and `_meta.io.modelcontextprotocol/serverInfo`, `ttlMs`/`cacheScope` on
  `server/discover`, the list methods and `resources/read` (new `CacheHint`, `Server.list_cache`,
  `Server.read_cache`, `ResourceRequest.cache`; default 0 ms / private). New `server/discover`. Refusals:
  malformed `_meta` -32602, unknown revision -32022 with `data.supported`/`requested`, `ping` and the
  handshake -32601, missing resource -32602 with `data.uri`. New constants `modern_protocol_version`,
  `modern_versions`, `all_versions`, `meta_key`, `error_code.{header_mismatch, missing_required_client_capability,
  unsupported_protocol_version}`; `DispatchMethod.servedStatelessly`, `modern_spec_anchor_index`.
  ⚠ `SendError` gains `StatelessRequest` (a modern tool call cannot send a server→client request): an
  exhaustive `switch` over `SendError` needs the arm. Also new, in both eras: optional `title`/`icons` on
  `Tool`/`Resource`/`ResourceTemplate`/`Prompt` (`Icon`) and `Tool.annotations` (`ToolAnnotations`); a
  modern call to a tool with an `output_schema` may return any JSON value as `structuredContent`.
  Session-path replies are byte-identical to before.

- **2026-09-28** — `initialize`'s `clientInfo` (`name`, `version`, optional `title`) is now
  recorded per peer, requested by ttydesk (2026-09-27): previously only `capabilities` and the
  negotiated version were kept in `PeerState`, so a server that wants to name which client made
  a call had to re-parse the `initialize` line itself. New `pub const ClientInfo` (`name`,
  `version`, `title: ?[]const u8`), `PeerState.client: ?ClientInfo`, `Server.clientInfo(peer)` and
  `ToolCall.clientInfo()` (mirroring `clientCapabilities`). Each field is copied onto the
  `Server`'s own allocator (the parsed value lives on the per-message arena) and capped at the new
  `Server.max_client_info_field_len` (default 256 bytes, truncated at a UTF-8 boundary). A missing
  or malformed `clientInfo` records `null` and — unlike a malformed `capabilities` — never fails
  the handshake: `clientInfo` is self-reported metadata this module never gates a decision on. A
  re-`initialize` frees the previous copy before installing the new one; `forgetPeer` and
  `Server.deinit` free it too. Purely additive — `PeerState` still constructs the same way for
  existing callers (`client` defaults to `null`), and no existing behavior changed.

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
