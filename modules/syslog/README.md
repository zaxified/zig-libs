# syslog

**RFC 5424** syslog message formatter + emitter, with a legacy **RFC 3164**
(BSD) encoder, **RFC 6587** octet-counting TCP framing, and **local
delivery** (a unix-socket emitter and the systemd journal's native protocol).

- No spec-correct, I/O-agnostic RFC 5424 formatter in the
  Zig ecosystem (the one correct reference is in another project; the popular
  `logly.zig` formatter emits a non-conformant timestamp).
- **Model after:** RFC 5424 (message + wire format), RFC 6587 (transport
  framing), RFC 3164 (legacy BSD format), the systemd Journal Native Protocol
  (https://systemd.io/JOURNAL_NATIVE_PROTOCOL/) for `journal`. Design mirrors
  the `Message` / emitter split of `joelreymont/pz` `src/core/syslog.zig`
  (MIT).
- **Platform:** any for the codec + `UdpEmitter`/`TcpEmitter` (`std.Io.net`,
  `nowTimestamp` uses posix `clock_gettime`); **Linux only** for local
  delivery (`UnixEmitter`/`journal`, raw `AF_UNIX` syscalls — `std.Io.net` has
  no unix-*datagram*-socket API).
  **Role:** client (the canonical value is `meta.role` in src/root.zig, which
  explains why this is deliberately not `both`: `both` reads as "also a syslog
  server" and would sit on the wrong side of a client/server survey). **Concurrency:** reentrant (no shared
  state). **Allocation:** none — fixed buffers throughout (`journal.Emitter.send`
  references a caller's field values zero-copy via `sendmsg` scatter-gather,
  rather than copying them into a buffer at all).

Provenance: clean-room from RFC 5424 (syslog protocol), RFC 6587 (TCP octet
framing) and RFC 3164 (BSD legacy). The `Message`/`Sender` *design* (a pure
message codec split from the network emitter, RFC 3339-ms timestamps,
structured-data escaping, field-length validation, octet framing) is modeled
after `joelreymont/pz` `src/core/syslog.zig` (MIT) — no third-party code was
copied; all code here targets `std.Io.net` and was written from the RFCs.

## API

```zig
const syslog = @import("syslog");

// ── RFC 5424 formatting (pure codec, deterministic, injected timestamp) ──
const msg = syslog.Message{
    .facility = .local0,
    .severity = .info,
    .timestamp = .{ .unix_ms = 1783600496789 }, // or syslog.nowTimestamp()
    .hostname = "web-1",
    .app_name = "api",
    .procid = "8143",
    .msgid = "REQ",
    .structured_data = &.{
        .{ .id = "meta@32473", .params = &.{
            .{ .name = "path", .value = "/health" },
            .{ .name = "status", .value = "200" },
        } },
    },
    .msg = "served /health 200",
};

var buf: [1024]u8 = undefined;
const line = try syslog.bufPrint(&msg, &buf);
// <134>1 2026-07-09T12:34:56.789Z web-1 api 8143 REQ [meta@32473 path="/health" status="200"] served /health 200

// msg.format(writer) / "{f}" work too, straight onto any std.Io.Writer.

// ── PRI ──
const pri = syslog.priority(.auth, .crit); // 34

// ── RFC 3164 (BSD) legacy line ──
const bmsg = syslog.bsd.Message{
    .facility = .local0, .severity = .warning,
    .timestamp = .{ .unix_ms = 1783600496000 },
    .hostname = "host", .tag = "app", .pid = "123", .msg = "hello",
};
var bbuf: [256]u8 = undefined;
_ = try syslog.bsd.bufPrint(&bmsg, &bbuf); // <132>Jul  9 12:34:56 host app[123]: hello

// ── transport (only touches the network when constructed) ──
// UDP: one datagram, truncated with a marker past ~1024 bytes.
var udp = try syslog.UdpEmitter.open(io, peer, .{});
defer udp.close();
try udp.send(&msg);

// TCP: RFC 6587 octet-counted framing "<len> <msg>".
var tcp = try syslog.TcpEmitter.connect(io, peer);
defer tcp.close();
try tcp.send(&msg);

// ── local delivery (Linux only; no `io` needed -- raw AF_UNIX syscalls) ──
// unix socket, this module's own RFC 5424/3164 encoders, default "/dev/log":
var ulog = try syslog.UnixEmitter.openDefault();
defer ulog.close();
try ulog.send(&msg); // or .sendBsd(&bmsg)

// systemd journal native protocol, default
// "/run/systemd/journal/socket" -- structured fields stay queryable
// (`journalctl TTYDESK_ACTION=unit.restart`) instead of being flattened
// into free text.
var jrnl = try syslog.journal.Emitter.openDefault();
defer jrnl.close();
try jrnl.sendMessage(.{
    .message = "unit restarted",
    .priority = .notice, // journal PRIORITY=5
    .identifier = "ttydesk", // SYSLOG_IDENTIFIER=ttydesk
    .fields = &.{.{ .name = "TTYDESK_ACTION", .value = "unit.restart" }},
});
// or build the field list yourself for full control:
try jrnl.send(&.{
    .{ .name = "MESSAGE", .value = "multi-line\nvalues switch to the binary form automatically" },
    .{ .name = "PRIORITY", .value = "6" },
});
```

## Wire format (RFC 5424 §6)

```
<PRI>1 TIMESTAMP HOSTNAME APP-NAME PROCID MSGID STRUCTURED-DATA [SP MSG]
```

- `PRI` = `facility * 8 + severity`.
- `TIMESTAMP` = RFC 3339 with **millisecond** precision (`…T12:34:56.789Z` or
  `…+02:00`). Timestamps are **injected** (`Timestamp{ .unix_ms, .offset_minutes }`)
  so formatting is deterministic; `nowTimestamp()` is the live helper.
- Absent/empty header fields render as the NILVALUE `-`.
- Header fields are truncated to their RFC limits (HOSTNAME ≤ 255, APP-NAME
  ≤ 48, PROCID ≤ 128, MSGID ≤ 32) and non-printable bytes map to `-`.
- Structured-data param values escape `"` → `\"`, `\` → `\\`, `]` → `\]`.

## Local delivery

- **`UnixEmitter`** — `open(path)` / `openDefault()` (`"/dev/log"`) / `close()` / `send(msg)` (RFC
  5424) / `sendBsd(msg)` (RFC 3164) / `sendRaw(bytes)` (already-formatted bytes, no internal size
  cap). One datagram per call to a unix `SOCK_DGRAM` socket. `error.NoSpaceLeft` if `send`/`sendBsd`'s
  internal formatting buffer is too small (use `sendRaw` with your own buffer instead);
  `error.MessageTooLarge` if the kernel itself rejects the datagram as too large (`EMSGSIZE`).
- **`journal`** — the systemd Journal Native Protocol. `Emitter.open(path)` /
  `openDefault()` (`"/run/systemd/journal/socket"`) / `close()` / `send(fields)` /
  `sendMessage(.{ .message, .priority, .identifier, .fields })` (the `MESSAGE`/`PRIORITY`/
  `SYSLOG_IDENTIFIER` convenience). `Field = struct { name, value }`; a value containing a newline
  is sent in the protocol's binary form automatically, otherwise as plain `NAME=value\n`.
  `validFieldName(name)` is `sd_journal_send`'s own rule (uppercase `A`-`Z`, `0`-`9`, `_`; not
  starting with a digit or `_`; ≤ 64 bytes) — `send` checks every field name before writing
  anything, so one bad name refuses the whole call rather than half-sending it.
  `error.TooManyFields` past `journal.max_fields` (64); `error.MessageTooLarge` on `EMSGSIZE`
  (journald's own `memfd`/`SCM_RIGHTS` fallback past that limit is not implemented here).

Both are **Linux only** — raw `AF_UNIX` syscalls, since `std.Io.net` has no unix-*datagram*-socket
API — and neither binds or listens; they dial the well-known path like every other local syslog/
journal client.

## Tests

Offline golden-byte tests (no live socket): a full message with structured
data, a minimal all-NILVALUE message, SD escaping of `"`/`\`/`]`, PRI for
several facility/severity pairs, timezone-offset timestamps, field truncation
at the length limits, and the RFC 6587 octet-count prefix. The real UDP/TCP
send paths are compile-checked only and gated behind runtime construction /
`error.SkipZigTest`. Local delivery (`UnixEmitter`/`journal`) is tested for
real instead, over throwaway `AF_UNIX` sockets bound in `.zig-cache/tmp/` —
no daemon needed, see SPEC.md.

```
zig build test-syslog                          # Debug
zig build test-syslog -Doptimize=ReleaseFast   # ReleaseFast
```

## Not implemented (DEFER)

- **Parser / receiver side** — RFC 5424 and RFC 3164 message *parsing*.
- **TLS transport** (RFC 5425) — left as a BYO-TLS seam.
- **Reliable delivery** — reconnect / retry / backpressure policy for TCP.
- Full RFC 3164 parsing tolerance (the encoder is provided; parsing is not).
