# mcp — changelog

Newest first. See the root [`CHANGELOG.md`](../../CHANGELOG.md) for which
release tag each entry shipped in, and `CONVENTIONS.md` §8 for the policy.

## Unreleased

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
