# acmedns — changelog

Newest first. See the root [`CHANGELOG.md`](../../CHANGELOG.md) for which
release tag each entry shipped in, and `CONVENTIONS.md` §8 for the policy.

## Unreleased

- **2026-11-23** — **Fix (heap residue), NO API CHANGE:** `AcmeDns.Store.toJson` (and so `save`) wrote through a growing `Writer.Allocating`, which frees each outgrown buffer unwiped: copies of the account passwords stayed in freed heap memory. It now counts first (an unbuffered `Discarding` writer) and writes into one exact allocation; a test pins two allocations and one free over 40 accounts. Same bytes as before.
- **2026-11-21** — **ADDED / FIXED** (wave 14 backlog): `Publisher.note` (an optional function returning the publisher's last failure note; the four built-in publishers set it) and `Dns01Solver.note` carries it after a failed publish instead of only `the publisher failed`; new `AcmeDns.Store` (accounts of several domains in lego's / go-acmedns' JSON account file: `register`, `put`, `find`, `accounts`, `load`, `parse`, `toJson`, `save` at mode 0600) ; **Behaviour change:** `zone.followCname` of a CNAME whose target is the root is `error.ResolverFailed` (it returned an empty name, found by the new fuzz of the zone walks).
- **2026-11-21** — **Behaviour change:** the `Solver` from `Dns01Solver.solver()` returns `error.Canceled` when the io cancels `present` (a delay or the propagation wait); it was `error.SolverFailed`, and the client reported a failed solver instead of its own `Canceled`. Needs acme's `SolverError.Canceled` (same release).
- **2026-11-20** — **Behaviour change:** `Dns01Solver.present` of a (domain, value) that is already pending takes a reference instead of keeping a second record, and `cleanup` removes the DNS value only at the last reference (before, the first `cleanup` removed the value for both). `deinit` is documented to leave pending records in DNS.
- **2026-11-20** — New `AcmeDns.deinitRegistration`: frees a `register` / `parseRegistration` result after wiping its password (the account's API key); `register` also wipes the reply body before freeing it. Additive; `Parsed.deinit` still works and frees unwiped. ReleaseFast free-scanner test.
- **2026-11-14** — **Fixed (no API change):** an allocation failure while reading the zone's NS records (`zone.nameservers`) freed the name list in the wrong order — a use-after-free and double free instead of `error.OutOfMemory` — and leaked the name being added; the same leak in the `Options.authoritative` list of the propagation check. Found by an allocation-failure sweep over `present` (`zone_test.zig`).
- **2026-11-14** — **BEHAVIOURAL, not breaking:** (no-panic sweep, hostile network input) `propagation_timeout_ms` now also ends a pass over many or mute servers (the NS list and each name's address list come off the network; before, one pass could outlast the timeout by servers x addresses x `query_timeout_ms`): `Dns01Solver` checks the budget before every query, the first query is always made. `AcmeDns`, `HttpReq` and `AcmeDns.register` read the response body under the HTTP client's `total_timeout_ms` (a server that sent its head and stalled parked the call forever). The basic-auth limit is documented as 378 bytes (was 379; behaviour unchanged). Tests: `hostile_test.zig`, `zone_test.zig`.
- **2026-11-06** — **Changed:** `Dns01Solver.Error` gains `InvalidDomain` (a domain over 253 bytes, from `acme.Client.dns01RecordName`, which no longer panics).
- **2026-10-31** — publishers: explicit note for the new `dns.Resolver.Error.RequestTooLarge`.
- **2026-10-24** — **NO CONSUMER-VISIBLE CHANGE:** the `strRepeat` helper (the Zig 0.17 stand-in for `**`) builds its string with one `@splat` + `@bitCast` instead of a comptime loop, which Sema evaluated in O(n²) (http's test binary: 323 s → 13 s). Same bytes, faster compile.

- **2026-10-18** — **Constant time:** `basicAuth` (the httpreq password in the `Authorization` header) encodes with `b64ct` instead of `std.base64` (new dep). Output unchanged.
- **2026-10-17** — Interop: `findZone` of a name the authoritative-only peer REFUSEs expects `ResolverFailed` (the 2026-10-16 review made REFUSED/SERVFAIL "could not find out"); the program is now run by the interop lane through `tools/interop.sh`. Tooling only.

- **2026-10-16** — review fixes: the propagation check no longer passes without a nameserver whose address lookup failed (NS addresses resolved every pass, `zone.nameserverIps`, rcode-aware); `followCname` / `findZone` fail with the new `error.ResolverFailed` on SERVFAIL/REFUSED instead of reading it as "no CNAME" / "no SOA"; a failed `present` is cleaned up once; HttpReq / acme-dns URLs keep the endpoint's query string and fragment; basic auth refuses a `:` in the user (RFC 7617) with its own note and wipes the encoded header; a challenge name outside `Options.zone` is refused before publishing. **API:** `zone.Error` gains `ResolverFailed`. Tests: `zone_test.zig` (scripted DNS server on loopback).

- **2026-10-16** — New module: ACME DNS-01 for `acme` — `Dns01Solver` (CNAME delegation, SOA zone walk,
  propagation check against the zone's authoritative servers, lego's and certmagic's options) and the
  generic publishers `Rfc2136` (TSIG), `AcmeDns`, `HttpReq`, `Exec`. Verified by issuance from Pebble
  v2.10.1 through each publisher, with Pebble resolving through a live RFC 2136 server
  (`tools/interop.sh`, 48 checks).
