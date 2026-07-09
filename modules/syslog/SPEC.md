# syslog — spec

Design + threat notes for auditors. Usage: see ./README.md. Attribution/provenance: see /NOTICE.

## Design & invariants
RFC 5424 message formatter with a legacy RFC 3164 (BSD) encoder and RFC 6587 octet-counting TCP
framing. Wire shape: `<PRI>1 TIMESTAMP HOSTNAME APP-NAME PROCID MSGID STRUCTURED-DATA [SP MSG]`; PRI
= `facility * 8 + severity`; TIMESTAMP is RFC 3339 with millisecond precision. Timestamps are
**injected** (`Timestamp{ .unix_ms, .offset_minutes }`) so formatting is deterministic — `nowTimestamp()`
is the only place that reads the clock (posix `clock_gettime`). Absent/empty header fields render as
the NILVALUE `-`; header fields are truncated to their RFC limits (HOSTNAME ≤255, APP-NAME ≤48,
PROCID ≤128, MSGID ≤32) and non-printable bytes map to `-`; structured-data param values escape `"`
→ `\"`, `\` → `\\`, `]` → `\]`. Pure codec core, no allocation — fixed buffers throughout
(`bufPrint`/`format` write straight onto any `std.Io.Writer`). `UdpEmitter`/`TcpEmitter` are the only
network-touching code: UDP sends one datagram (truncated with a marker past ~1024 bytes), TCP uses
RFC 6587 octet-counted framing (`"<len> <msg>"`). Reentrant — no shared state. Clean-room from RFC
5424, RFC 6587, RFC 3164; the `Message`/`Sender` design split (pure codec vs. network emitter,
RFC 3339-ms timestamps, SD escaping, field-length validation, octet framing) is referenced from
`joelreymont/pz` (MIT) — design only, no code copied — see NOTICE.

## Threat model / out of scope
Not a security boundary; this is a formatter/emitter, not a parser of untrusted input (it only ever
formats caller-supplied structured data, escaping the three characters that would otherwise break the
SD-PARAM grammar). Failure modes it bounds: header-field overflow (truncated to the RFC limit rather
than corrupting the wire shape), non-printable bytes in header fields (mapped to `-` rather than
emitted raw), and oversized UDP payloads (truncated with a marker rather than silently dropped or
fragmented unpredictably). Out of scope: parser/receiver side (RFC 5424 and RFC 3164 message
*parsing* — this module only encodes), TLS transport (RFC 5425 — left as a BYO-TLS seam), reliable
delivery (reconnect/retry/backpressure policy for TCP is the caller's), full RFC 3164 parsing
tolerance.

## Verification
Offline golden-byte tests (no live socket): a full message with structured data, a minimal
all-NILVALUE message, SD escaping of `"`/`\`/`]`, PRI for several facility/severity pairs,
timezone-offset timestamps, field truncation at the length limits, and the RFC 6587 octet-count
prefix. The real UDP/TCP send paths are compile-checked only and gated behind runtime construction /
`error.SkipZigTest`. 19 tests (README states 20 incl. a live-gated case). Run: `zig build
test-syslog` (Debug and `-Doptimize=ReleaseFast`).

## Backlog / deferred
Parser/receiver side (RFC 5424 and RFC 3164 message parsing); TLS transport (RFC 5425, BYO-TLS seam);
reliable delivery (reconnect/retry/backpressure for TCP); full RFC 3164 parsing tolerance (encoder
only is provided today). (README "Not implemented (DEFER)".) Owner note carried from README: add a
NOTICE entry for RFC 5424/6587/3164 + the `pz` design reference if not already present.

## Status
`gap · any · both (codec+client) · reentrant` + deps: none (std only) — canonical source is
`pub const meta` in src/root.zig.
