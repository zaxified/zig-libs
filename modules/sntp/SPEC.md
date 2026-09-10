# sntp — spec

Design + threat notes for auditors. Usage: see ./README.md. Attribution/provenance: see /NOTICE.

## Design & invariants

- **A pure 48-byte NTP packet codec plus a blocking UDP query** (RFC 4330: SNTP for IPv4/IPv6).
  `encodeRequest`/`decodeResponse` are transport-agnostic (no I/O); `query` opens a UDP socket over
  `std.Io.net`, sends a client-mode request, and computes offset/round-trip delay from the four
  timestamps. Clean-room from RFC 4330 (and RFC 5905 for the timestamp format); packet layout and
  the T1–T4 offset/delay arithmetic mirror the design of `FObersteiner/ntp_client` (Codeberg,
  `src/ntp.zig`, MIT) — a clean-room re-derivation, no code copied. Original work of the zig-libs
  authors (MIT) — see NOTICE.
- **Epoch & fixed-point model:** NTP timestamps are 64-bit fixed-point seconds since 1900-01-01
  (`Timestamp{ seconds, fraction }`, big-endian on the wire, fraction in units of 1/2^32 s). Unix
  time is `NTP − 2_208_988_800 s` (`ntp_unix_offset_s`). `Timestamp` converts both ways
  (`nanosSinceNtpEpoch`/`fromNanosSinceNtpEpoch` via `frac * 1e9 >> 32` and `ns << 32 / 1e9`;
  `toUnixNanos`/`fromUnixNanos`). Offset/delay differences are computed in **i128 nanoseconds** so
  they stay exact and can be negative. `root_delay`/`root_dispersion` stay raw 16.16 NTP-short
  fixed point; `rootDelaySeconds`/`rootDispersionSeconds` interpret them.
- **Local timestamps** come from the libc-free `clock_gettime(REALTIME)` errno form
  (`RtlGetSystemTimePrecise` on Windows) — same pattern as sibling `jwt`/`jobqueue`.
- **Concurrency:** reentrant, no shared state — every call is self-contained.

## Threat model / out of scope

Not a security primitive: SNTP has no authentication in this module — a response is trusted at face
value once its shape validates. `decodeResponse` guarantees a **malformed/hostile packet from any
UDP peer never panics**: it validates, in order, length (exactly 48 bytes → `error.InvalidLength`),
version (`error.InvalidVersion` if VN = 0 — RFC 4330 §5 sanity check 4, as corrected by the
verified RFC Errata 2263: the published text names the LI field, but the errata confirms the
intended field is VN), mode (`error.NotServerMode` if mode ≠ 4), stratum (`error.KissOfDeath` on
stratum 0 — the parsed reason code and raw `reference_id` bytes are returned via the optional
`kiss_out: ?*KissOfDeath` parameter, per RFC 5905 §7.4's registered Kiss Code table;
`error.UnsynchronizedStratum` on stratum ≥ 16, per RFC 5905 §7.3 Figure 11 — 16 is "unsynchronized",
17-255 "reserved"), Leap Indicator (`error.UnsynchronizedLeap` if LI = 3 — RFC 4330 §4's own "alarm
condition, clock not synchronized"; audit finding F7 — this used to be checked on the stratum field
only, an inconsistency, not a deliberate leniency), and the Receive and Transmit timestamps
(`error.ReceiveTimestampUnset` / `error.TransmitTimestampUnset` if either is all-zero, RFC 4330 §5
sanity check 4 — audit finding F3 found only Transmit was checked, so a server reporting Receive = 0
drove `query`'s offset to an unbounded, measured -63 years) before any field is trusted.

`query` layers RFC 4330 §5's *other* sanity check on top of `decodeResponse` — matching the reply
against the client's own outstanding request — and it is fully implemented, not out of scope: the
reply must come from the same source address **and port** as `server` (or it's ignored and `query`
keeps waiting, RFC 4330 §5), and must echo an anti-spoof origin nonce in its `originate` field or
it's rejected as `error.OriginateMismatch`. The nonce isn't `query`'s literal T1 clock reading —
audit finding F4 measured the clock-derived timestamp at only 21-24 bits of unpredictability against
`verifyOriginate`'s claimed 64, so `query` sends the true send second with 32 CSPRNG bits (from
`std.Io.randomSecure`, fail-closed — `error.EntropyUnavailable` rather than a weaker degraded seed)
in place of the fraction, and uses the real clock reading (not the nonce) for the offset/delay math,
so the substitution costs no accuracy. The receive-side guards (peer match, nonce echo, and a
truncated-datagram check for audit finding F2 — the kernel silently hands back exactly 48 bytes for
an oversized datagram too, distinguishable only via the receive call's truncation flag) live in
`processReply`/`validateReply`, unit-tested directly without a socket (audit finding F1: `query`'s
own receive loop held these guards in a form no test reached before).

Reading the local clock can itself fail; `nowUnixNanos`/`nowTimestamp` fail closed with
`error.ClockUnavailable` rather than the previous silent fallback to the Unix epoch (audit finding
F11 — an untested path, but a fail-open default that would have produced a garbage T1/T4 with no
signal to the caller).

Out of scope: NTP authentication (the optional MAC/extension fields — longer packets are rejected as
`error.InvalidLength`, not parsed), server-side responder, multi-server sampling/racing and
best-sample selection, full NTP (RFC 5905) intersection/clustering/combining algorithms, leap-second
handling beyond surfacing the raw `LeapIndicator` flag, and the "truly paranoid," explicitly-optional
Root Delay/Root Dispersion bound. A caller needing tamper-resistant time sync (e.g. NTS) must layer
that itself — this module is a single unauthenticated query/response, and its offset/delay should
never by itself step a security-sensitive clock (TLS validity windows, TOTP, Kerberos, log
ordering): a single unauthenticated UDP exchange, even with every check above passing, is not a
substitute for authenticated time sync on a hostile network (audit finding F12 — this caveat existed
only as half a sentence in this file before, not anywhere a caller reading the API would see it; see
also README.md).

**Known bound — NTP era 0 (expires 2036-02-07):** `Timestamp.seconds` is a bare `u32` count of
seconds since 1900-01-01, with no era pivot. It wraps at 2^32 seconds, i.e. at **2036-02-07T06:28:16
UTC**, after which every timestamp arithmetic path in this module (`nanosSinceNtpEpoch`,
`toUnixNanos`, offset/delay computation) silently reinterprets a post-rollover instant as an
era-0 one unless the caller supplies external era context. This is not fixed here — `sntpc` (Rust)
documents the identical gap and calls its own era-disambiguation heuristic "a nearest-era guess, not
a verified result"; no anchored implementation in the survey has actually solved it. Track this as a
hard deprecation date for any deployment of this module, not a someday-maybe: revisit before 2036.
**One of this module's own tests is a tripwire for that date, not just a comment** (audit finding
F9): `nowTimestamp is in a sane modern range` asserts the live clock reads before
2036-02-05T06:00:00Z, two days ahead of the actual rollover — so `zig build test-sntp` starts failing
on its own, unattended, before the wrap, rather than waiting for someone to remember the date.

## Verification

Offline, no live server: golden request bytes (the `LI|VN|Mode` byte + T1 placement), packet
encode/decode round-trip, a canned server response (stratum/precision/timestamps/ref-id), the
reject paths (length, version 0, mode, Kiss-o'-Death — including the parsed `KissCode`/`raw` surfaced
via `kiss_out` for both a registered code and an unrecognized one, `parseKissCode` against every
RFC 5905 §7.4 registered code, stratum ≥ 16, Leap Indicator 3, an all-zero Receive Timestamp, an
all-zero Transmit Timestamp), NTP↔Unix epoch conversion at a known instant, fraction↔nanosecond
round-trips, offset/delay against hand-computed T1..T4 (including a negative offset), and
`processReply`/`validateReply` (peer-address match, truncation, origin-nonce echo, and that the
offset math uses the real T1 rather than the wire nonce) exercised directly, without a socket. The
live `query` test is gated behind `error.SkipZigTest`. Run: `zig build test-sntp`.

## Backlog / deferred

- **Full NTP (RFC 5905)** — the intersection/clustering/combining algorithms are not built.
- **Server side** — not built; client/query only.
- **NTP authentication** — the optional MAC/extension fields are not parsed; longer packets are
  rejected as `InvalidLength` rather than accepted-with-auth.
- **Leap-second handling** — only the raw `LeapIndicator` flag surfaces; no adjustment logic.
- **Multi-server sampling / racing and best-sample selection** — not built; `query` is a single
  one-shot request to one server.
- **NTP era 0 rollover (2036-02-07)** — documented, not fixed; see "Known bound" above.

## Status

`gap · any (portable codec; local timestamps via libc-free clock_gettime/RtlGetSystemTimePrecise) ·
client · reentrant` + deps: none (std only; `std.Io.net` for the UDP query) — canonical source is
`pub const meta` in src/root.zig.

## Anchoring

**Anchor grade:** class A · oracle MIXED

- **Class A** — wire/interop format — other implementations must byte-agree with it.
- **Oracle MIXED** — anchored for some paths, self for others — the evidence below names which.

**What the tests actually contain.** src/root.zig:890 decodes one real 48-byte reply captured from time.google.com together with the originate timestamp the request actually sent, so verifyOriginate meets a genuinely echoed value; the live query test is SkipZigTest by design and every other fixture is canned

**How it got there.** The anchoring work landed. DONE d0e30ca: real time.google.com reply frozen; live test stays skipped by design
