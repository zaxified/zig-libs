# syslog — changelog

Newest first. See the root [`CHANGELOG.md`](../../CHANGELOG.md) for which
release tag each entry shipped in, and `CONVENTIONS.md` §8 for the policy.

## Unreleased

- **2026-10-05** — **Anchoring: a real rsyslogd and a real systemd-journald judge every encoder and emitter**
  (`tools/rsyslog_oracle.py`, `tools/interop.zig`, `src/rsyslog_oracle_test.zig`, replay in `unix.zig`): 617 cases.
  rsyslogd 8.2512 (unconfined copy, `unshare -rn`) parses each RFC 5424 message from `buildDatagram` (UDP) and the
  `writeOctetCounted` frame (TCP), and each RFC 3164 line, back to what it meant -- PRI, the timestamp's instant,
  each header field, every SD-PARAM value (mmpstrucdata), MSG. systemd-journald 259 (`unshare -rm`) stores exactly
  the fields of each `journal.Emitter` datagram, keeps exactly the field names `validFieldName` accepts, and reads
  `UnixEmitter`'s datagrams on dev-log (`/dev/log` on a systemd host). Anchor grade MIXED → EXTERNAL.
  - **DEFECT fixed, BEHAVIOURAL:** `bsd.Message.hostname` defaulted to `"-"`, which rsyslogd reads as the TAG (the
    real TAG and PID then land in MSG); so did an IPv6 literal, `host:1`, and a hostname like `evil app[1]:`, which
    forged TAG and PID. `hostname` is now `?[]const u8 = null`, and is sent only when `bsd.validHostname` holds
    (RFC 1123 labels plus `_`, i.e. a host name or IPv4 address); otherwise the field is omitted, glibc's shape.
  - **DEFECT fixed, BEHAVIOURAL:** `UnixEmitter.sendBsd` sent the HOSTNAME; journald (the `/dev/log` of a systemd
    host) then parsed no SYSLOG_IDENTIFIER at all. It now never sends one (local delivery needs none; glibc sends
    none).
  - **DEFECT fixed:** a UTC offset past ±23:59 shifted the clock by the full offset but printed the clamped
    `±23:59`, so the line named a different instant (offset 1440: one minute off at rsyslogd). The offset is now
    clamped before the shift.
  - **DEFECT fixed:** `journal.Emitter.send` failed `error.WriteFailed` (`EFAULT`) when a field value was an empty
    slice from an allocator: Linux checks the address of a zero-length `iovec`, and `alloc(u8, 0)` returns a
    sentinel. `UnixEmitter.sendRaw` had the same shape. A valid address is substituted for an empty buffer.
  - **Fixed:** a PID holding `[` or `]` closed `[PID]` early (`a]b` arrived as PID `a`); both now map to `-`. An
    empty SD-ID or PARAM-NAME is written `-` (SD-NAME is `1*32PRINTUSASCII`; rsyslogd accepted the empty one).
  - Documented, not ours: rsyslogd refuses an RFC 5424 year ≥ 2100 (listed divergence); journald does not parse
    RFC 5424 at all on `/dev/log` (everything after `<PRI>` is MESSAGE) -- use `journal` or `sendBsd` there.

- **2026-10-04** — Fix: `buildDatagram` (and so `UdpEmitter.send` with `udp_limit >= 2048`)
  sent a message longer than its scratch buffer cut short WITHOUT the truncation marker — the
  overflow left exactly `scratch.len` bytes, which the `> udp_limit` check did not see. The
  marker now replaces the tail whenever the message did not fit.
- **2026-10-04** — **Tests:** mutation run (33 schemata mutants, 32 killed, 1 equivalent). New
  tests for the fix and for the year-9999 edge, an empty header field, the 32-byte SD-NAME cap,
  a budget shorter than the marker, a 108-byte unix socket path and `sendMessage` over
  `max_fields`.

- **2026-09-28** — **New local delivery (Additive, requested by ttydesk)**: `UnixEmitter`
  (`src/unix.zig`) sends this module's existing RFC 5424/RFC 3164 encoders as one datagram to a
  unix `SOCK_DGRAM` socket, default `"/dev/log"` (`open`/`openDefault`, `send`/`sendBsd`, plus
  `sendRaw` for a caller with its own larger pre-formatted buffer — `error.NoSpaceLeft` rather
  than truncation if the convenience path's internal buffer is too small). `journal` speaks
  systemd's native protocol (`Emitter.open`/`send`/`sendMessage`) over
  `"/run/systemd/journal/socket"`: `KEY=value\n` text fields, the binary form
  (`KEY\n` + 8-byte little-endian length + value + `\n`) automatically for any value containing a
  newline, and `validFieldName` enforcing `sd_journal_send`'s field-name rule (uppercase, digits,
  `_`; not starting with a digit or `_`; ≤64 bytes) — an invalid name refuses the WHOLE send before
  anything is written, never a partial datagram. Field values are referenced zero-copy via a
  `sendmsg` scatter-gather list, so there is no internal size cap on a value; a datagram the kernel
  itself rejects as too large (`EMSGSIZE`) is `error.MessageTooLarge` — journald's own memfd/
  `SCM_RIGHTS` fallback past that limit is not implemented (optional per the request). Linux only
  (raw `AF_UNIX` syscalls — `std.Io.net.UnixAddress` has no datagram-socket API). Lets ttydesk
  delete its own workaround (`src/audit.zig`'s `toJournal`/`field`/`sendDatagram`, marked
  `zig-libs request: syslog — local delivery`) once it switches over. Tested over a real kernel
  unix socket (no daemon needed — see SPEC.md's Verification section), not compile-checked only.
- **2026-09-10** — A1 audit fix (P1: 0 consumers in the repo). `bsd.Message.format`
  wrote HOSTNAME/TAG/PID verbatim, so an untrusted field containing `\n` could
  forge a second RFC 3164 record for a receiver that frames on newline (RFC 3164
  has no in-band framing of its own), and a space or `:` inside TAG could shift
  where a receiver believes CONTENT begins. HOSTNAME and PID now map every byte
  outside printable US-ASCII (33‥126) to `-` — the same bound `message.zig`'s
  `writeField` already holds for the RFC 5424 header fields, and the one
  SPEC.md's "non-printable bytes in header fields" already claimed for the whole
  module. TAG additionally restricts to alphanumeric only (RFC 3164 §5.3, already
  documented on `max_tag` but not previously enforced). MSG stays untouched,
  deliberately — matches the RFC 5424 encoder and the external rsyslogd anchor
  ("MSG passed through raw").
- **2026-08-22** — `TcpEmitter.send` now returns the explicit `TcpEmitter.SendError`
  (`NoSpaceLeft`, `WriteFailed`, `Canceled`) instead of an inferred `!void`, and
  recovers `Canceled` from the concrete `std.Io.net.Stream.Writer`'s out-of-band
  `err` field before falling back to `WriteFailed` — a `std.Io` cancellation
  (`Future.cancel`) mid-write is now distinguishable from a real transport failure.
  `UdpEmitter.send` needed no change: `Socket.SendError` already carries
  `Io.Cancelable` directly, with nothing narrowing it away. No blocking-write test
  was added — each `send` call is bounded to the module's own small formatted
  message (well under any realistic kernel socket buffer), so it does not actually
  block against the established loopback test probe; forcing a block would need
  artificial socket-buffer starvation outside that probe's shape, which was not
  fabricated. There is no blocking read path in this module at all (emit-only).
- **2026-08-14** — `zig build check-fuzz` exemption: `**Fuzz exemption:** EMIT-ONLY`
  recorded in SPEC.md. This module formats and sends syslog messages and has no
  receiver/parser in its public surface (already documented in the module doc and
  `meta.role = .client`); the one byte-accepting public function
  (`writeOctetCounted`'s RFC 6587 framer) only ever length-prefixes this module's own
  formatted output, never bytes read off a socket or out of a file.
- **2026-07-19** — Security audit: two findings fixed (part of the collection-wide
  audit; the root changelog records no further detail than this). Byte-exact against RFC
  5424 §6.5's published test vectors.
- **2026-07-09** — New module: RFC 5424 syslog formatter + emitter, RFC 3164 legacy
  encoder, RFC 6587 TCP octet framing.
