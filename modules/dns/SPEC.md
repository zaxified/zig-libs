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
resolves. The `/etc/hosts` + UDP-PTR core, codec, TCP and
EDNS(0)/DoH are clean-room from RFC 1035/2782/8659/8484 — see NOTICE.

## Threat model / out of scope
Not a validating resolver: **no DNSSEC**, so answers are trusted as far as the transport is. UDP is
spoofable; what the resolver does demand of a reply is RFC 5452 §9.1's full set — it must come
from the server queried (address AND port), carry the transaction id (fresh per datagram sent,
so a retry is not a second shot at a known id), have QR set, and echo **exactly our question**:
one question, our name (ASCII case-insensitive, RFC 4343), our type, class IN. Anything else is
`MalformedResponse`. That is robustness against an off-path guesser (~31 bits of work with the
random source port), not authentication — use DoH (TLS to the resolver) when the path is
untrusted. TLS/DoH transport security is the `http` client's concern, not this module's.

`lookupIp` and `reverse` apply a bailiwick rule on top: only answer records whose owner is the
queried name, or a CNAME target reachable from it through CNAME records in the same answer
section (at most 8 hops; a loop cannot extend the chain), are returned. An A record for
`victim.test` in a reply to `example.com` used to come back from `lookupIp("example.com")`; it is
now ignored. `resolve`/`query` return the whole message untouched — a caller reading `answers`
itself owns that check.

Decoded names are dotted text without the trailing root dot and with no `\DDD` escape handling —
labels are raw bytes, so a label containing `.` is indistinguishable from two labels in the text
form and `writeName` is not its inverse; callers displaying them must escape, and callers that
need wire structure (label counts — `dnssec` does) must not take it from the text. Out of scope:
DNSSEC validation. **Timeouts:** `timeout_ms` bounds every UDP attempt (`receiveTimeout`) and
every TCP attempt end to end — connect, write and both reads — by running the exchange on its own
task and canceling it at the deadline (`runBounded`; std 0.16.0 has no per-read deadline on a
stream). It is a per-attempt, per-server budget, not a per-call one: `query` may take
`timeout_ms × attempts × servers`, `lookupIp` that again per (search candidate × {A, AAAA}); see
`Error.Timeout`. DoH attempts are bounded by `http.Client`'s `total_timeout_ms`, set from the same
value. The DoH-JSON `name` is validated by the wire path's rule and percent-encoded into the URL.

## Verification
`zig build test-dns`: 63 offline tests + 7 live (70). Offline: golden query bytes; canned responses
(name compression, CNAME chain, MX/TXT/SOA/OPT, PTR); adversarial packets (truncations at every
offset, pointer loops, bad rdata lengths incl. SOA/MX shorter than their fields, hostile section
counts **under a 4 KiB memory limit** so the up-front count guard is pinned by the allocation it
prevents, not by the error name); a fuzzed `decode` seeded with the six live captures; resolv.conf/
hosts fixtures and search-list ordering; reverse-name goldens incl. the RFC 3596 example; the
response-correlation rule (wrong name / no question / two questions / wrong type / wrong class
refused, case and root dot accepted); the bailiwick rule on a five-record answer with an
out-of-order CNAME chain, a loop and an over-long chain; DoH-JSON URL encoding against parameter
and request-line injection; and loopback stubs — a UDP server that lies about the question or
slips in an off-bailiwick record, and a TCP server that accepts and never answers (reached both
via `transport = .tcp` and via a TC-bit UDP reply), each bounded by `timeout_ms`.

⚠ The 7 `live:` tests (UDP, TCP, DoH POST/GET, DoH-JSON, PTR of 8.8.8.8, lookupIp) **query
public resolvers when the network is up** — they skip via `error.SkipZigTest` only when it is not.
A gate run on a connected machine is therefore not offline.

## Backlog / deferred
- resolv.conf `options timeout:`/`attempts:` are parsed and capped but never read
  (`Options.timeout_ms`/`attempts` win unconditionally) — a decision on whether to honour or drop them.
- A UDP reply larger than the receive buffer is truncated by the kernel without `MSG_TRUNC` being
  consulted, so it fails as `MalformedResponse` instead of retrying over TCP.
- A per-CALL deadline for `resolve`/`lookupIp` (today the budget is per attempt per server).
- The text name form collapses distinct wire names (see Threat model); a structured name type
  would be an API change.

## Status
`extract+gap · any (RFC 6724 result order is Linux-only) · client · blocking` · deps: `netaddr`,
`http`, `std.json`, `std.Io.net` — canonical source is `pub const meta` in src/root.zig.

## Anchoring

**Anchor grade:** class A · oracle MIXED

- **Class A** — wire/interop format — other implementations must byte-agree with it.
- **Oracle MIXED** — anchored for some paths, self for others — the evidence below names which.

**What the tests actually contain.** message.zig goldens hand-built; Resolver has live UDP/TCP/DoH tests vs real 8.8.8.8

**How it got there.** The anchoring work landed. DONE ea2d000: 6 real Google DNS responses incl. compression, CNAME chain, NXDOMAIN
