# proxyproto — changelog

Newest first. See the root [`CHANGELOG.md`](../../CHANGELOG.md) for which
release tag each entry shipped in, and `CONVENTIONS.md` §8 for the policy.

## Unreleased

- **2026-11-16** — **NO CONSUMER-VISIBLE CHANGE:** interop oracle against pires/go-proxyproto v0.16.0 (`tools/interop.zig` + `tools/go_oracle/`, `zig build interop-proxyproto`): 160 085 seeded cases (parse, our writer read by Go, Go's writer read here, SSL TLV), 0 unexplained disagreements, eight documented differences listed in SPEC § Interop oracle; the anchor oracle moves from SELF to EXTERNAL.
- **2026-11-16** — **NO CONSUMER-VISIBLE CHANGE:** `example/main.zig` (CONVENTIONS §7.2: 34 `pub fn`): a balancer writes a v2 header with ALPN and CRC32C, the server reads it from a trusted peer and keeps the client's bytes, an untrusted peer is refused, a connection without a header keeps every byte, and the v1 line round-trips.
- **2026-11-15** — **NO CONSUMER-VISIBLE CHANGE:** delta mutation audit of the review fixes in `read` (untrusted prefix) and `writeV2` (NUL in a unix path), 12 schemata mutants, all killed by the existing tests; card Audit line re-recorded over the current source.
- **2026-11-15** — FIX: `read` for an untrusted peer no longer returns `TooLarge` or `Truncated` for a stream that merely starts like a signature (`PRO` + EOF, a too-small reader buffer): it returns null and keeps the bytes; `writeV2` refuses (`InvalidHeader`) a unix path with an embedded NUL that the parser would truncate; `read` docs warn about `required = false` with a trusted peer.
- **2026-11-15** — **NO CONSUMER-VISIBLE CHANGE:** whole-module mutation audit (224 schemata mutants: 220 killed, 4 equivalent); 13 new tests (CRC TLV size and span, `Ssl` flag bits, port digit edges, v1 missing fields and bare LF, command mask, mapped-peer prefixes, `max_v2_len`, exact-size buffers, no read past the decision, unix writer guards, the 65535 payload edge); card Audit line recorded over the current source.
- **2026-11-15** — New module: PROXY protocol v1/v2 parser (pure `parse` with `need_more`/`absent`, `read` over a `std.Io.Reader` with the trusted-peers rule as the default, TLV walker with ALPN/authority/CRC32C/SSL/unique-id/netns helpers, CRC32C verified on parse) and v1/v2 writer. Verified against hand-built vectors from the specification's layouts and a 40M-run deterministic fuzz.
