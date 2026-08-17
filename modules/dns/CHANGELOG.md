# dns — changelog

Newest first. See the root [`CHANGELOG.md`](../../CHANGELOG.md) for which
release tag each entry shipped in, and `CONVENTIONS.md` §8 for the policy.

## Unreleased

- **2026-08-18** — Re-export `message.max_query_len`, `message.QueryOptions` and
  `message.EncodeError` from the module root, so a codec-only consumer sizing/calling
  `encodeQuery` never has to name `dns.message` directly (which would put `Resolver`,
  and therefore the `http` dependency, in its import graph for no reason).
- **2026-07-19** — Security audit: one finding fixed (part of the collection-wide audit;
  the root changelog records no further detail than this). Live-tested against real
  UDP/TCP/DoH/DoH-JSON resolvers over the network (decode/encode vectors are
  self-authored, not captured).
- **2026-07-02** — New module: RFC 1035 resolver —
  A/AAAA/PTR/CNAME/NS/MX/TXT/SOA/SRV/CAA over UDP/TCP + DoH.
