# netaddr — spec

Design + threat notes for auditors. Usage: see ./README.md. Attribution/provenance: see /NOTICE.

## Design & invariants
Allocation model: none in the scalar API — parse/format work on caller buffers
(`max_ip_text_len`/`max_prefix_text_len`), `sortDestinations` uses a fixed `max_sort_candidates`
stack array; only `summarize`/`mergePrefixes` allocate, via a caller allocator, returning an owned
slice. Never-panic parsing: `parseIp*`/`parsePrefix`/`parseHostPort` return `null` on malformed
input, strict like Go `netip` (no leading zeros, no zone suffix, `::` must elide ≥1 group). Strict
family distinction: an IPv4-mapped v6 address stays `.v6`; a v4 `Prefix` never contains a mapped-v6
address — mixing requires explicit `Ip.unmap`. All prefix bit math runs on the address as a
big-endian unsigned int, so numeric order equals address order for both families. RFC 6724
destination-rule coverage matches Go: rules 1/2/5/6/8/9 (rule 9 IPv6-only, per Go issues
13283/18518); source rules 1/2/6/8. Rules needing OS state (deprecated/home/interface/transport)
are skipped, as glibc and Go document. Sorts are stable (rule 10) via insertion sort. `Scope` is a
numeric-backed non-exhaustive enum so unnamed multicast scopes order correctly. The RFC 6724
selection logic derives from fping's address-selection logic
(`sortByDestinationPolicy`/`policyPrecedence`/`destinationReachable`), extended to the full rule
set and cross-checked row-for-row against Go `net/addrselect.go` + glibc getaddrinfo; CIDR/prefix
ops model after Go `net/netip.Prefix` + `go4.org/netipx` (behavior only, clean-room) — see NOTICE.

## Threat model / out of scope
Not security-sensitive; pure logic. `systemSource` is the only impure, Linux-only surface — a
UDP-`connect` route probe (no packet sent) + `getsockname` to learn the OS-chosen source (the
glibc trick); needs no privileges, returns `null` on an unreachable destination. Out of scope: DNS
resolution, actually connecting, zone/scope-id handling (zones are rejected by the parsers, passed
through untouched by `parseHostPort`), and the RFC 6724 rules that require per-interface OS state.

## Verification
Unit tests only (the core needs no network): strict parse accept/reject tables for
v4/v6/prefix/host:port, RFC 5952 canonical-format round-trips (zero-compression edge cases, mixed
mapped-v4 notation), the RFC 6724 §2.1 policy table + §2.2 `commonPrefixLen` + §10.2 worked
pairwise-ordering examples, source-selection rules, CIDR ops (contains/overlaps/first-last-host/
broadcast/supernet/iterator), `summarize`/`mergePrefixes` minimal-covering checks. One Linux-only
live test exercises `systemSource` against loopback. Run: `zig build test-netaddr`.

## Backlog / deferred
None beyond the documented out-of-scope items above (zone/scope-id handling, OS-state-dependent
RFC 6724 rules). Consumed downstream by `http`/`dns`/`icmp`/`probe`/`procnet` as the shared address
substrate.

## Status
`extract · any · util · reentrant` + deps: none (std only; `systemSource` Linux-only) — canonical
source is `pub const meta` in src/root.zig.
