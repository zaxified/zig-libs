# proxyproto — changelog

Newest first. See the root [`CHANGELOG.md`](../../CHANGELOG.md) for which
release tag each entry shipped in, and `CONVENTIONS.md` §8 for the policy.

## Unreleased

- **2026-11-16** — Independent review fixes. **Behaviour change:** `default_max_v2_len` is 16 + 4096 (go-proxyproto's cap)
  instead of the specification's 536, which is a sender's guideline and refused legitimate TLV-heavy headers (set
  `max_v2_len = 536` for the old bound; a `read` buffer sized with `default_max_v2_len` grows accordingly). `uniqueId()`
  refuses a value over 128 bytes (`max_unique_id_len`). Documented: the writer's payload range vs the reader's cap, the raw
  `writeV2` TLV area, LOCAL/UNSPEC blocks discarded unchecked, and a read deadline as the caller's job.
- **2026-11-16** — **NO CONSUMER-VISIBLE CHANGE:** `example/main.zig` (CONVENTIONS §7.2: 34 `pub fn`): a balancer writes a v2 header with ALPN and CRC32C, the server reads it from a trusted peer and keeps the client's bytes, an untrusted peer is refused, a connection without a header keeps every byte, and the v1 line round-trips.
- **2026-11-15** — FIX: `read` for an untrusted peer no longer returns `TooLarge` or `Truncated` for a stream that merely starts like a signature (`PRO` + EOF, a too-small reader buffer): it returns null and keeps the bytes; `writeV2` refuses (`InvalidHeader`) a unix path with an embedded NUL that the parser would truncate; `read` docs warn about `required = false` with a trusted peer.
- **2026-11-15** — New module: PROXY protocol v1/v2 parser (pure `parse` with `need_more`/`absent`, `read` over a `std.Io.Reader` with the trusted-peers rule as the default, TLV walker with ALPN/authority/CRC32C/SSL/unique-id/netns helpers, CRC32C verified on parse) and v1/v2 writer. Verified against hand-built vectors from the specification's layouts and a 40M-run deterministic fuzz.
