# whois — changelog

Newest first. See the root [`CHANGELOG.md`](../../CHANGELOG.md) for which
release tag each entry shipped in, and `CONVENTIONS.md` §8 for the policy.

## Unreleased

- **2026-08-23** — **Behavioural:** `TransportError` gains `Canceled`, and
  `TcpTransport` recovers it from the concrete reader and writer instead of
  folding every failure into `TransportFailed`. A canceled lookup was
  indistinguishable from a dead WHOIS server, so a consumer retried a query
  its own caller had already abandoned. `whois` was the one module with this
  shape that the cancelation campaign missed -- its sibling `rdap`, shipped in
  the same commits, was fixed. Covered by a loopback test that parks a real
  read against a peer that never answers; mutation-confirmed by folding the
  reader check back and watching the test report `TransportFailed`.

- **2026-07-19** — Security audit: one finding fixed (part of the collection-wide audit;
  the root changelog records no further detail than this). Modeled on GNU `whois`
  (Debian), BSD `whois` (design reference, not a test anchor).
- **2026-07-07** — New module: RFC 3912 whois client — query format + referral chasing
  (IANA→registrar) + field extraction, transport-agnostic seam.
