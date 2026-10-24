# acmedns — changelog

Newest first. See the root [`CHANGELOG.md`](../../CHANGELOG.md) for which
release tag each entry shipped in, and `CONVENTIONS.md` §8 for the policy.

## Unreleased

- **2026-10-24** — **NO CONSUMER-VISIBLE CHANGE:** the `strRepeat` helper (the Zig 0.17 stand-in for `**`) builds its string with one `@splat` + `@bitCast` instead of a comptime loop, which Sema evaluated in O(n²) (http's test binary: 323 s → 13 s). Same bytes, faster compile.

- **2026-10-18** — **Constant time:** `basicAuth` (the httpreq password in the `Authorization` header) encodes with `b64ct` instead of `std.base64` (new dep). Output unchanged.
- **2026-10-17** — Interop: `findZone` of a name the authoritative-only peer REFUSEs expects `ResolverFailed` (the 2026-10-16 review made REFUSED/SERVFAIL "could not find out"); the program is now run by the interop lane through `tools/interop.sh`. Tooling only.

- **2026-10-16** — review fixes: the propagation check no longer passes without a nameserver whose address lookup failed (NS addresses resolved every pass, `zone.nameserverIps`, rcode-aware); `followCname` / `findZone` fail with the new `error.ResolverFailed` on SERVFAIL/REFUSED instead of reading it as "no CNAME" / "no SOA"; a failed `present` is cleaned up once; HttpReq / acme-dns URLs keep the endpoint's query string and fragment; basic auth refuses a `:` in the user (RFC 7617) with its own note and wipes the encoded header; a challenge name outside `Options.zone` is refused before publishing. **API:** `zone.Error` gains `ResolverFailed`. Tests: `zone_test.zig` (scripted DNS server on loopback).

- **2026-10-16** — New module: ACME DNS-01 for `acme` — `Dns01Solver` (CNAME delegation, SOA zone walk,
  propagation check against the zone's authoritative servers, lego's and certmagic's options) and the
  generic publishers `Rfc2136` (TSIG), `AcmeDns`, `HttpReq`, `Exec`. Verified by issuance from Pebble
  v2.10.1 through each publisher, with Pebble resolving through a live RFC 2136 server
  (`tools/interop.sh`, 48 checks).
