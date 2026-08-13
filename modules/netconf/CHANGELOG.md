# netconf — changelog

Newest first. See the root [`CHANGELOG.md`](../../CHANGELOG.md) for which
release tag each entry shipped in, and `CONVENTIONS.md` §8 for the policy.

## Unreleased

- **2026-08-06** — Security audit: the RFC 6242 chunked framer was quadratic in the
  number of chunks — 159s of CPU for 655KB of attacker-chosen wire bytes; fixed (down to
  ~0.015s for the same input), along with 5 further findings.
- **2026-07-22** — New module: NETCONF client (RFC 6241) over SSH — RFC 6242
  end-of-message + chunked framing, hello/capability exchange,
  get/get-config/edit-config/commit RPCs with typed replies.
