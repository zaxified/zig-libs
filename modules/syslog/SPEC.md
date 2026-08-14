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
`error.SkipZigTest`. Run: `zig build
test-syslog` (Debug and `-Doptimize=ReleaseFast`).

### External-anchor investigation: a real rsyslogd (2026-08-01, done)

The send path (`UdpEmitter`/`TcpEmitter`) genuinely speaks the wire protocol a
real syslog receiver expects — unlike a self-authored format, this is a case
where a real conformant listener is the correct oracle. `rsyslogd 8.2512.0` is
installed on this machine. It was run, unprivileged, and it worked:

**Oracle reachable, with one workaround.** `rsyslogd`'s own AppArmor profile
(`/etc/apparmor.d/usr.sbin.rsyslogd`, present and enforced) confines it to
reading `/etc/rsyslog.conf`+`/etc/rsyslog.d/**` and writing
`/var/log/**`+`/var/spool/rsyslog/**` — both root-owned, so a throwaway config
or output path could not simply be passed on the command line (confirmed via
`journalctl -k`: `apparmor="DENIED" ... profile="rsyslogd"` for a scratch
config path). No sudo/setcap/host change was used to lift this. Instead, an
unprivileged `unshare --user --map-root-user --mount --net` namespace
bind-mounted a throwaway config over `/etc/rsyslog.conf` and a throwaway
directory over `/var/log`, both visible only inside that private mount
namespace — the real `/etc/rsyslog.conf` and `/var/log` were never touched.
Inside that same namespace, `rsyslogd -n -iNONE -f /etc/rsyslog.conf` listened
on UDP and TCP (`imudp`/`imtcp`) on a high port, and a template rendered every
parsed RFC 5424 property to a file: `%syslogfacility-text% %syslogseverity-text%
%pri% %timereported:::date-rfc3339% %hostname% %programname% %procid% %msgid%
%structured-data% %msg% %inputname%`.

**What was frozen.** A one-off Zig program (not part of the module; built and
run, then deleted) called this module's actual `UdpEmitter.send` and
`TcpEmitter.send` — not hand-built bytes — with a message exercising every
header field, an SD element with 3 params, and a MSG containing raw `"` `\` `]`
(unescaped, since only SD values are escaped, not MSG). rsyslogd's real,
independent RFC 5424 parser re-rendered, identically on both transports:

```
RCVD facility=local3 severity=warning pri=156 timereported=[2026-07-09T13:34:56.123+01:00]
  hostname=[probe-host] appname=[live-probe] procid=[4242] msgid=[ORACLE]
  structured-data=[[exampleSDID@32473 iut="3" eventSource="Application" eventID="1011"]]
  msg=[live rsyslogd oracle probe: quotes " backslash \ bracket ] end] protocol=imudp
(byte-identical second line, protocol=imtcp)
```

Every field matches what this module intended byte-for-byte: PRI arithmetic
(`local3*8+warning` = 156), the `+01:00`-shifted millisecond timestamp,
truncation-free header fields, SD element/param syntax (proving the escaping
rules produce real, externally-parseable SD grammar, not just
internally-consistent output), and MSG passed through raw. **No disagreement
was found** — a real third-party implementation accepted every message this
encoder can produce, on both UDP and RFC 6587 octet-counted TCP.

That exact message and its frozen wire string are now a permanent offline
golden test (`external anchor: message live-verified by a real rsyslogd`,
`src/root.zig`) — asserted against the literal bytes, not re-run against
rsyslogd at test time (the governing rule: run the foreign thing once, freeze
its bytes, assert offline). No `/NOTICE` entry: `rsyslogd` was used purely as a
black-box receiving oracle — its own parser's rendering was observed, no
rsyslog source was read or consulted (root `NOTICE` §0, the same relationship
as `icmp`/`genetlink`/`nftables`/`traceroute`).

## Backlog / deferred
Parser/receiver side (RFC 5424 and RFC 3164 message parsing); TLS transport (RFC 5425, BYO-TLS seam);
reliable delivery (reconnect/retry/backpressure for TCP); full RFC 3164 parsing tolerance (encoder
only is provided today). (README "Not implemented (DEFER)".)

## Status
`gap · any · both (codec+client) · reentrant` + deps: none (std only) — canonical source is
`pub const meta` in src/root.zig.

## Anchoring

**Anchor grade:** class A · oracle MIXED

- **Class A** — wire/interop format — other implementations must byte-agree with it.
- **Oracle MIXED** — anchored for some paths, self for others — the evidence below names which.

**What the tests actually contain.** src/root.zig:157 freezes what a real rsyslogd received and re-rendered over BOTH transports (UDP and TCP octet-counted) for a message carrying quote/backslash/bracket escaping; bsd.zig and the remainder of message.zig are hand-authored fixtures

**How it got there.** The anchoring work landed. DONE a58d626: real rsyslogd receives+re-renders both transports; MSG escaping bug class
