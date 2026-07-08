# SPEC — `netaddr`

**Purpose** — The pure address logic a dual-stack networking stack needs before it touches a
socket: parse/format IPv4 & IPv6 literals (RFC 5952 canonical form), split `host:port`, do
CIDR/prefix math, and answer "given several candidate addresses for a host, which do I connect to,
in what order" (RFC 6724). No I/O in the core — it is the shared substrate `http`, `dns` and `icmp`
build on.

**Model after / Seed** — the RFC 6724 selection logic is *extracted* from zig-fping's
`src/netutil.zig` (`sortByDestinationPolicy` / `policyPrecedence` / `destinationReachable`) and
extended to the full destination rule set, cross-checked row-for-row against Go's
`net/addrselect.go` + the glibc getaddrinfo algorithm. The CIDR/prefix ops model after Go
`net/netip.Prefix` + `go4.org/netipx` (behavior only, clean-room). fping attribution + the Go/glibc/
netipx design refs are in `NOTICE` (fping block shared with dns/icmp/seqmap).

**Design & invariants**
- **Allocation:** none in the scalar API — parse/format work on caller buffers (`max_ip_text_len` /
  `max_prefix_text_len`), `sortDestinations` uses a fixed `max_sort_candidates` stack array. Only
  `summarize` / `mergePrefixes` allocate, via a caller allocator, and return an owned slice.
- **Never-panic parsing:** `parseIp*` / `parsePrefix` / `parseHostPort` return `null` on malformed
  input; strict like Go `netip` (no leading zeros, no zone suffix, `::` must elide ≥ 1 group).
- **Strict family distinction:** an IPv4-mapped v6 address stays `.v6`; a v4 `Prefix` never contains
  a mapped-v6 address — mixing requires an explicit `Ip.unmap`. All prefix bit math runs on the
  address as a big-endian unsigned int, so numeric order equals address order for both families.
- **RFC 6724 rule coverage matches Go:** destination rules 1/2/5/6/8/9 (rule 9 IPv6-only, per Go
  issues 13283/18518); source rules 1/2/6/8. Rules needing OS state (deprecated/home/interface/
  transport) are skipped, as glibc and Go document. Sorts are stable (rule 10) via insertion sort.
- **Scope** is a numeric-backed non-exhaustive enum so unnamed multicast scopes order correctly.

**Threat model / out of scope** — Not security-sensitive; pure logic. `systemSource` is the only
impure, Linux-only surface — a UDP-`connect` route probe (no packet is sent) + `getsockname` to
learn the OS-chosen source, the glibc trick; it needs no privileges and returns `null` on an
unreachable destination. Out of scope: DNS resolution, actually connecting, zone/scope-id handling
(zones are rejected by the parsers, passed through untouched by `parseHostPort`), and the RFC 6724
rules that require per-interface OS state.

**Verification** — Unit tests only (the core needs no network): strict parse accept/reject tables
for v4/v6/prefix/host:port, RFC 5952 canonical-format round-trips (zero-compression edge cases,
mixed-notation mapped v4), the RFC 6724 §2.1 policy table + §2.2 `commonPrefixLen` + §10.2 worked
pairwise-ordering examples, source-selection rules, CIDR ops (contains/overlaps/first-last-host/
broadcast/supernet/iterator), and `summarize` / `mergePrefixes` minimal-covering checks. One
Linux-only live test exercises `systemSource` against loopback.

**Status** — `extract · any · util · reentrant` · deps: none (std only; `systemSource` Linux-only).
