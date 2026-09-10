# whois — spec

Design + threat notes for auditors. Usage: see ./README.md. Attribution/provenance: see ./README.md (no NOTICE entry — clean-room from public RFC 3912, no third-party code).

## Design & invariants
Transport seam, zero allocation: `Transport` is one function — connect to `server:port`, send the
formatted query, read the whole text reply until close — so everything is offline-testable from
canned buffers. All buffers are caller-provided and fixed; the module never allocates. An optional
blocking `TcpTransport` over `std.Io.net` is the only network-touching code. Bounded, guarded chase:
`lookup` starts at `whois.iana.org` and follows referrals depth-capped (default max 5 referrals, hard
chain cap 8), cycle-guarded (case-insensitive, so a self-referral or two-server loop stops cleanly),
and byte-capped (per-response cap → `error.ResponseTooLarge`); it reports `truncated` when the depth
cap stops the chase and returns the ordered `chain` of servers consulted. Deliberately minimal
parsing: replies are NOT parsed beyond the referral keys — every registry has its own freeform
format; `fieldValue` (case-insensitive key, trimmed value) is the only concession; `nextServer`/
`parseServerRef` never error on garbage. Query safety: `formatQuery` rejects embedded CR/LF (would
inject a second WHOIS command) and enforces `max_query_len`. Reentrant — no shared state anywhere.
Clean-room from RFC 3912 plus the documented IANA/registry referral-line conventions (IANA `refer:`,
ARIN `ReferralServer:`, Verisign `Registrar WHOIS Server:`, the `whois://` URL form) — no third-party
whois implementation consulted or copied; nothing to attribute (no NOTICE entry needed).

## Threat model / out of scope
WHOIS is plaintext over TCP/43 with no authentication or encryption; transport security is out of
scope and largely unavailable for the protocol. The threats this module actually contains are (a)
**CRLF injection** via the query — blocked at `formatQuery`. `formatQuery` does not otherwise inspect
the query text: a leading `-` or an embedded NUL reaches the wire unchanged, and a server that parses
`-`-prefixed tokens as switches (several real WHOIS servers do) receives whatever the query names —
this module treats query content as the caller's choice, not a second thing to sanitize (audit F5).
(b) a **malicious/looping referral graph** — bounded by the depth cap, cycle guard, and per-response
byte cap so a hostile server cannot drive an unbounded chase or memory blowup. The cycle guard is on
**hostname only**, not host:port, and the port a referral names is otherwise unrestricted (`1..65535`,
only `0` is rejected) — a wildcard-DNS-controlling attacker can steer a single `lookup` at up to
`max_referrals` different ports of hosts they name, all on the loopback/private addresses the SSRF
guard below already refuses, or on whatever public hosts the guard lets through (audit F3: this is
cross-protocol forgery against a third party, not an internal-network reach — no test or doc claimed a
port restriction beyond `!= 0` and none is added here). A referral the SSRF guard refuses is reported
identically to a genuine terminal reply (`truncated = false`, `chain` unchanged, `response` is the
line that named the refused host) — a caller cannot currently tell "chain ended" from "chain was
blocked" without inspecting `response` itself (audit F6). (c) **referral SSRF** — a MITM'd or hostile server in the
chain naming a loopback/RFC 1918/link-local/unique-local/unspecified/multicast host (or `localhost`)
in a `refer:`/`ReferralServer:`/`whois:` line; `isSpecialUseHost` default-denies before `lookup` ever
dials that host, so it cannot be turned into an internal-port-connect oracle (a referral naming an
*external* hostname that itself resolves to special-use space is out of scope here — this module
never resolves DNS; a `Transport` that does its own resolution should re-check the resolved address);
and (d) **untrusted reply text** — treated as opaque bytes, never parsed into structure, so there is
no field-parsing attack surface. Callers must still treat WHOIS answers as unauthenticated.

`isSpecialUseHost` classifies the referral **string** and normalizes a trailing root dot before
comparing (`localhost.` is `localhost` to every resolver). `TcpTransport` additionally classifies the
**resolved** address before connecting (`deny_special_use`, default true) — this is the re-check the
paragraph above asks a resolving `Transport` to perform, done in the one this module ships, so a host
string spelled in an encoding `isSpecialUseHost` does not recognise (an octal/decimal-integer IPv4
literal, say) cannot reach special-use space by resolving there instead of being classified there
(audit F1/F2, 2026-09-10). It is fail-closed over the whole answer set and does not distinguish the
caller's own `LookupOptions.root` from a referral — a caller who wants this transport to reach a
loopback/private server on purpose (a local mirror, or a test peer) sets `deny_special_use = false`.

## Verification
43 tests (`zig build test-whois` → 43/43; 36 named tests in `root.zig` plus the 6 in `goldens.zig`
it imports, plus the runner's own `test {}` import block), all but one offline from canned buffers: `formatQuery` round-trip + CRLF-injection and
length rejection; the documented ARIN/Verisign query conveniences; `fieldValue` and `parseServerRef`
(whois:// URL, ports, scheme/garbage rejection); a known-answer referral extraction; `isSpecialUseHost`
classification (loopback/RFC 1918/link-local/unique-local/`localhost`, the trailing-dot spelling, and
that a normal public host passes); the full `lookup` behavior over a scripted transport —
IANA→Verisign→registrar chain, self-referral and two-server-cycle termination, depth-cap `truncated`
reporting, byte-cap `ResponseTooLarge`, referral port carried from a `whois://` URL, up-front rejection
of bad root/oversized query, transport-failure propagation, and the SSRF guard refusing a
loopback/RFC 1918 referral (string form and, over real loopback sockets, resolved form) while a normal
public referral still proceeds. The one exception dials loopback on purpose: `TcpTransport`'s
cancellation test binds its own listener and connects to it (`deny_special_use = false`) to prove a
canceled read surfaces `error.Canceled` rather than `error.TransportFailed`; no test ever dials a real
registry. Run: `zig build test-whois`.

## Backlog / deferred
None recorded.

## Status
`gap · any (logic over a transport seam; optional TcpTransport is posix) · client · reentrant` +
deps: `netaddr` (special-use address classification for the referral SSRF guard) — canonical source is
`pub const meta` in src/root.zig.

## Anchoring

**Anchor grade:** class A · oracle MIXED

- **Class A** — wire/interop format — other implementations must byte-agree with it.
- **Oracle MIXED** — anchored for some paths, self for others — the evidence below names which.

**What the tests actually contain.** src/goldens.zig carries real port-43 replies captured live from IANA and Verisign, including a real referral cycle; root.zig's own canned replies say in their comment that they are only `modeled on the real line conventions`, so the transport and the remaining parse paths stay self

**How it got there.** The anchoring work landed. DONE ea2d000: real IANA+Verisign port-43 replies; real referral CYCLE exercised
