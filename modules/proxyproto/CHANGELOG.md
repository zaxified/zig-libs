# proxyproto — changelog

Newest first. See the root [`CHANGELOG.md`](../../CHANGELOG.md) for which
release tag each entry shipped in, and `CONVENTIONS.md` §8 for the policy.

## Unreleased

- **2026-11-15** — **NO CONSUMER-VISIBLE CHANGE:** whole-module mutation audit (224 schemata mutants: 220 killed, 4 equivalent); 13 new tests (CRC TLV size and span, `Ssl` flag bits, port digit edges, v1 missing fields and bare LF, command mask, mapped-peer prefixes, `max_v2_len`, exact-size buffers, no read past the decision, unix writer guards, the 65535 payload edge); card Audit line recorded over the current source.
- **2026-11-15** — New module: PROXY protocol v1/v2 parser (pure `parse` with `need_more`/`absent`, `read` over a `std.Io.Reader` with the trusted-peers rule as the default, TLV walker with ALPN/authority/CRC32C/SSL/unique-id/netns helpers, CRC32C verified on parse) and v1/v2 writer. Verified against hand-built vectors from the specification's layouts and a 40M-run deterministic fuzz.
