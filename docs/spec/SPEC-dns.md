# SPEC — `dns`

**Purpose** — A DNS resolver where std stops short: `std.Io.net.HostName.lookup` is forward-only
and opaque — no PTR, no explicit server/transport control, no DoH. `dns` is an RFC 1035 message
codec plus a blocking client that does forward (A/AAAA) and reverse (PTR) lookups over UDP, TCP, and
DNS-over-HTTPS, decoding the common record set (A/AAAA/PTR/CNAME/NS/MX/TXT/SOA, SRV, CAA) plus
EDNS(0) OPT; anything else surfaces as raw rdata.

**Model after / Seed** — codec modelled on `miekg/dns` and c-ares behavior (RFC 1035 wire, RFC 2782
SRV, RFC 8659 CAA, RFC 8484 DoH); the resolver's control flow follows Go `net`'s dnsclient. The
`/etc/hosts` + UDP-PTR core is **extracted** from the authors' `zig-fping` `src/rdns.zig` (fping-
derived — shared fping attribution in `NOTICE`, with netaddr/icmp/seqmap); the general codec, TCP,
EDNS(0) and DoH are clean-room from the RFCs.

**Design & invariants**
- **Layered like `http`:** `message.zig` is the pure, transport-agnostic wire codec — the part that
  must be bulletproof, golden-byte testable and fuzzed offline; `config.zig` is pure string logic
  (`/etc/resolv.conf` + `/etc/hosts` parse, Go-`nameList` search-list expansion); `Resolver.zig` is
  the blocking client over `std.Io.net` (UDP with TC→TCP retry, length-prefixed TCP) and the sibling
  `http` module (DoH POST/GET `application/dns-message`, plus the DoH-JSON variant via `std.json`);
  `root.zig` owns the shared vocabulary and the netaddr bridges (`reverseName`, `recordIp`).
- **Name-compression safety:** pointers must point strictly backwards (Go dnsmessage rule); combined
  with the 253-char name cap and a 16-jump budget, adversarial pointer loops always fail fast with a
  typed error rather than spinning.
- **Concurrency:** every lookup blocks; one owner per `Resolver` (no shared state to synchronize).
- **Error policy:** malformed packets are typed errors, never panics. `resolve` returns the last
  response even on NXDOMAIN/empty (inspect `Message.rcode()`); `lookupIp` returns an empty slice
  when nothing resolves.

**Threat model / out of scope** — Not a validating resolver: **no DNSSEC**, so answers are trusted
as far as the transport is. UDP is spoofable; the query-id + compression-loop guards are robustness,
not authentication — use DoH (TLS to the resolver, RFC 8484) when the path is untrusted. TLS/DoH
transport security is the `http` client's concern, not this module's. Decoded names are dotted text
without the trailing root dot and with no `\DDD` escape handling — labels are raw bytes; callers
displaying them must escape. TCP/DoH connect timeouts fall back to the OS default until std's
`Io.Threaded` grows a timeout on `netConnectIp*` (same TODO as `http.Client`).

**Verification** — 46 offline tests: golden query bytes; canned responses (name compression, CNAME
chain, MX/TXT/SOA/OPT, PTR); adversarial packets (truncations at every offset, pointer loops, bad
rdata lengths, hostile section counts); a fuzzed `decode`; resolv.conf/hosts fixtures and search-
list ordering; reverse-name goldens incl. the RFC 3596 example and a codec round-trip. Live tests
(UDP, TCP, DoH POST/GET, DoH-JSON, PTR of 8.8.8.8) skip via `error.SkipZigTest` when offline.

**Status** — `extract+gap · any (RFC 6724 result order is Linux-only) · client · blocking` · deps:
`netaddr`, `http`, `std.json`, `std.Io.net`.
