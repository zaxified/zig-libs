# proxyproto — changelog

Newest first. See the root [`CHANGELOG.md`](../../CHANGELOG.md) for which
release tag each entry shipped in, and `CONVENTIONS.md` §8 for the policy.

## Unreleased

- **2026-11-15** — FIX: `read` for an untrusted peer no longer returns `TooLarge` or `Truncated` for a stream that merely starts like a signature (`PRO` + EOF, a too-small reader buffer): it returns null and keeps the bytes; `writeV2` refuses (`InvalidHeader`) a unix path with an embedded NUL that the parser would truncate; `read` docs warn about `required = false` with a trusted peer.
- **2026-11-15** — New module: PROXY protocol v1/v2 parser (pure `parse` with `need_more`/`absent`, `read` over a `std.Io.Reader` with the trusted-peers rule as the default, TLV walker with ALPN/authority/CRC32C/SSL/unique-id/netns helpers, CRC32C verified on parse) and v1/v2 writer. Verified against hand-built vectors from the specification's layouts and a 40M-run deterministic fuzz.
