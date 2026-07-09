# sntp — spec

Design + threat notes for auditors. Usage: see ./README.md. Attribution/provenance: see /NOTICE.

## Design & invariants

- **A pure 48-byte NTP packet codec plus a blocking UDP query** (RFC 4330: SNTP for IPv4/IPv6).
  `encodeRequest`/`decodeResponse` are transport-agnostic (no I/O); `query` opens a UDP socket over
  `std.Io.net`, sends a client-mode request, and computes offset/round-trip delay from the four
  timestamps. Clean-room from RFC 4330 (and RFC 5905 for the timestamp format); packet layout and
  the T1–T4 offset/delay arithmetic mirror the design of `FObersteiner/ntp_client` (Codeberg,
  `src/ntp.zig`, MIT) — a clean-room re-derivation, no code copied. RFC 4330 and the `ntp_client`
  design reference are to be added to the repository NOTICE.
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
UDP peer never panics**: it validates length (exactly 48 bytes → `error.InvalidLength`), mode
(`error.NotServerMode` if mode ≠ 4), and stratum (`error.KissOfDeath` on stratum 0 — the 4-byte
ASCII kiss code sits in `reference_id`) before any field is trusted. Out of scope: NTP
authentication (the optional MAC/extension fields — longer packets are rejected as
`error.InvalidLength`, not parsed), server-side responder, multi-server sampling/racing and
best-sample selection, full NTP (RFC 5905) intersection/clustering/combining algorithms, leap-second
handling beyond surfacing the raw `LeapIndicator` flag. A caller needing tamper-resistant time
sync (e.g. NTS) must layer that itself — this module is a single unauthenticated query/response.

## Verification

Offline, no live server: golden request bytes (the `LI|VN|Mode` byte + T1 placement), packet
encode/decode round-trip, a canned server response (stratum/precision/timestamps/ref-id), the
reject paths (length, mode, Kiss-o'-Death), NTP↔Unix epoch conversion at a known instant,
fraction↔nanosecond round-trips, and offset/delay against hand-computed T1..T4 (including a
negative offset). The live `query` test is gated behind `error.SkipZigTest`. Run:
`zig build test-sntp`.

## Backlog / deferred

- **Full NTP (RFC 5905)** — the intersection/clustering/combining algorithms are not built.
- **Server side** — not built; client/query only.
- **NTP authentication** — the optional MAC/extension fields are not parsed; longer packets are
  rejected as `InvalidLength` rather than accepted-with-auth.
- **Leap-second handling** — only the raw `LeapIndicator` flag surfaces; no adjustment logic.
- **Multi-server sampling / racing and best-sample selection** — not built; `query` is a single
  one-shot request to one server.

## Status

`gap · any (portable codec; local timestamps via libc-free clock_gettime/RtlGetSystemTimePrecise) ·
client · reentrant` + deps: none (std only; `std.Io.net` for the UDP query) — canonical source is
`pub const meta` in src/root.zig.
