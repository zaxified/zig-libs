# mcp-http — changelog

Newest first. See the root [`CHANGELOG.md`](../../CHANGELOG.md) for which
release tag each entry shipped in, and `CONVENTIONS.md` §8 for the policy.

## Unreleased

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
