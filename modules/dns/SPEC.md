# dns — spec

Design + threat notes for auditors. Usage: see ./README.md. Attribution/provenance: see /NOTICE.

## Design & invariants
Layered like `http`: `message.zig` is the pure, transport-agnostic wire codec (golden-byte
testable, fuzzed offline); `config.zig` is pure string logic (`/etc/resolv.conf` + `/etc/hosts`
parse, Go-`nameList` search-list expansion); `Resolver.zig` is the blocking client over
`std.Io.net` (UDP with TC→TCP retry, length-prefixed TCP) and the sibling `http` module (DoH
POST/GET `application/dns-message`, plus DoH-JSON via `std.json`); `root.zig` owns the shared
vocabulary and netaddr bridges (`reverseName`, `recordIp`). Name-compression safety: pointers must
point strictly backwards (Go dnsmessage rule); combined with a 253-char name cap and a 16-jump
budget, adversarial pointer loops always fail fast with a typed error rather than spinning.
Concurrency: every lookup blocks, one owner per `Resolver` (no shared state to synchronize). Error
policy: malformed packets are typed errors, never panics; `resolve` returns the last response even
on NXDOMAIN/empty (inspect `Message.rcode()`); `lookupIp` returns an empty slice when nothing
resolves. The `/etc/hosts` + UDP-PTR core is extracted from zig-fping `src/rdns.zig`; codec/TCP/
EDNS(0)/DoH are clean-room from RFC 1035/2782/8659/8484 — see NOTICE.

## Threat model / out of scope
Not a validating resolver: **no DNSSEC**, so answers are trusted as far as the transport is. UDP is
spoofable; the query-id + compression-loop guards are robustness, not authentication — use DoH
(TLS to the resolver) when the path is untrusted. TLS/DoH transport security is the `http` client's
concern, not this module's. Decoded names are dotted text without the trailing root dot and with no
`\DDD` escape handling — labels are raw bytes; callers displaying them must escape. Out of scope:
DNSSEC validation, anti-spoofing beyond query-id matching. TCP/DoH connect timeouts fall back to
the OS default until std's `Io.Threaded` grows a timeout on `netConnectIp*` (same TODO as
`http.Client`).

## Verification
46 offline tests: golden query bytes; canned responses (name compression, CNAME chain, MX/TXT/SOA/
OPT, PTR); adversarial packets (truncations at every offset, pointer loops, bad rdata lengths,
hostile section counts); a fuzzed `decode`; resolv.conf/hosts fixtures and search-list ordering;
reverse-name goldens incl. the RFC 3596 example and a codec round-trip. Live tests (UDP, TCP, DoH
POST/GET, DoH-JSON, PTR of 8.8.8.8) skip via `error.SkipZigTest` when offline. Run: `zig build
test-dns`.

## Backlog / deferred
None recorded beyond the design-level TODO already in Threat model (OS-default connect timeout on
`Io.Threaded`, shared with `http.Client`). No deferred-gap entry beyond citation nits folded
into the security/similarity review pass.

## Status
`extract+gap · any (RFC 6724 result order is Linux-only) · client · blocking` · deps: `netaddr`,
`http`, `std.json`, `std.Io.net` — canonical source is `pub const meta` in src/root.zig.
