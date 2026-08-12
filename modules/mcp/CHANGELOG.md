# mcp — changelog

Newest first. See the root [`CHANGELOG.md`](../../CHANGELOG.md) for which
release tag each entry shipped in, and `CONVENTIONS.md` §8 for the policy.

## Unreleased

- Server→client requests — `sampling/createMessage` and
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
- Security audit: a CRIT/HIGH finding was fixed (part of the
  collection-wide audit; the root changelog records no further detail
  than this).
