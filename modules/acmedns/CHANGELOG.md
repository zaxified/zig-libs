# acmedns — changelog

Newest first. See the root [`CHANGELOG.md`](../../CHANGELOG.md) for which
release tag each entry shipped in, and `CONVENTIONS.md` §8 for the policy.

## Unreleased

- **2026-10-16** — New module: ACME DNS-01 for `acme` — `Dns01Solver` (CNAME delegation, SOA zone walk,
  propagation check against the zone's authoritative servers, lego's and certmagic's options) and the
  generic publishers `Rfc2136` (TSIG), `AcmeDns`, `HttpReq`, `Exec`. Verified by issuance from Pebble
  v2.10.1 through each publisher, with Pebble resolving through a live RFC 2136 server
  (`tools/interop.sh`, 48 checks).
