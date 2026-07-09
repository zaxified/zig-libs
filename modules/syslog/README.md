# syslog

**RFC 5424** syslog message formatter + emitter, with a legacy **RFC 3164**
(BSD) encoder and **RFC 6587** octet-counting TCP framing.

- **Status:** `gap` — no spec-correct, I/O-agnostic RFC 5424 formatter in the
  Zig ecosystem (the one correct reference is in another project; the popular
  `logly.zig` formatter emits a non-conformant timestamp).
- **Model after:** RFC 5424 (message + wire format), RFC 6587 (transport
  framing), RFC 3164 (legacy BSD format). Design mirrors the `Message` /
  emitter split of `joelreymont/pz` `src/core/syslog.zig` (MIT).
- **Platform:** any (pure codec core; the optional `UdpEmitter`/`TcpEmitter`
  use `std.Io.net`, `nowTimestamp` uses posix `clock_gettime`).
  **Role:** both (codec + client). **Concurrency:** reentrant (no shared
  state). **Allocation:** none — fixed buffers throughout.

Provenance: clean-room from RFC 5424, RFC 6587 and RFC 3164. The
`Message`/`Sender` *design* (a pure message codec split from the network
emitter, RFC 3339-ms timestamps, structured-data escaping, field-length
validation, octet framing) is referenced from `joelreymont/pz` (MIT) — no
third-party code was copied; all code here targets `std.Io.net` and was
written from the RFCs. See `NOTICE`.

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

## Tests

Offline golden-byte tests (no live socket): a full message with structured
data, a minimal all-NILVALUE message, SD escaping of `"`/`\`/`]`, PRI for
several facility/severity pairs, timezone-offset timestamps, field truncation
at the length limits, and the RFC 6587 octet-count prefix. The real UDP/TCP
send paths are compile-checked only and gated behind runtime construction /
`error.SkipZigTest`.

```
zig build test-syslog                          # Debug
zig build test-syslog -Doptimize=ReleaseFast   # ReleaseFast
```

## Not implemented (DEFER)

- **Parser / receiver side** — RFC 5424 and RFC 3164 message *parsing*.
- **TLS transport** (RFC 5425) — left as a BYO-TLS seam.
- **Reliable delivery** — reconnect / retry / backpressure policy for TCP.
- Full RFC 3164 parsing tolerance (the encoder is provided; parsing is not).
