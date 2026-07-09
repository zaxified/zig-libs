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
**CRLF injection** via the query — blocked at `formatQuery`; (b) a **malicious/looping referral
graph** — bounded by the depth cap, cycle guard, and per-response byte cap so a hostile server cannot
drive an unbounded chase or memory blowup; and (c) **untrusted reply text** — treated as opaque
bytes, never parsed into structure, so there is no field-parsing attack surface. Callers must still
treat WHOIS answers as unauthenticated.

## Verification
17 offline tests (no test ever dials): `formatQuery` round-trip + CRLF-injection and length rejection;
the documented ARIN/Verisign query conveniences; `fieldValue` and `parseServerRef` (whois:// URL,
ports, scheme/garbage rejection); a known-answer referral extraction; the full `lookup` behavior over
a scripted transport — IANA→Verisign→registrar chain, self-referral and two-server-cycle termination,
depth-cap `truncated` reporting, byte-cap `ResponseTooLarge`, referral port carried from a `whois://`
URL, up-front rejection of bad root/oversized query, transport-failure propagation. Run: `zig build
test-whois`.

## Backlog / deferred
None recorded.

## Status
`gap · any (logic over a transport seam; optional TcpTransport is posix) · client · reentrant` +
deps: none (std only) — canonical source is `pub const meta` in src/root.zig.
