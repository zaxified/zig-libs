# syslog

**RFC 5424** syslog: formatter + emitters, a strict parser, a legacy **RFC 3164**
(BSD) encoder and lenient parser, **RFC 6587** framing both ways, **RFC 5425**
through a TLS seam, **local delivery** (unix sockets and the systemd journal's
native protocol), and a `Logger` with a `std.log` sink.

- No spec-correct, I/O-agnostic RFC 5424 formatter in the
  Zig ecosystem (the one correct reference is in another project; the popular
  `logly.zig` formatter emits a non-conformant timestamp).
- **Model after:** RFC 5424 (message + wire format), RFC 6587 (transport
  framing), RFC 3164 (legacy BSD format), the systemd Journal Native Protocol
  (https://systemd.io/JOURNAL_NATIVE_PROTOCOL/) for `journal`. Design mirrors
  the `Message` / emitter split of `joelreymont/pz` `src/core/syslog.zig`
  (MIT).
- **Platform:** any for the codec; **Linux only** for the emitters (raw
  socket syscalls for `connect` deadlines and unix sockets, and `std.Io.net` has no
  unix-*datagram*-socket API).
  **Role:** client (the canonical value is `meta.role` in src/root.zig: the parser
  is a codec over the caller's bytes and there is no listener; `both` reads as "also
  a syslog server"). **Concurrency:** reentrant; `Logger` is safe from several
  threads. **Allocation:** none — fixed buffers throughout (`journal.Emitter.send`
  references a caller's field values zero-copy via `sendmsg` scatter-gather; the
  parser returns slices of its input).
- **Deps:** `datefmt` (RFC 3339 / BSD timestamp rendering).

Provenance: clean-room from RFC 5424 (syslog protocol), RFC 6587 (TCP octet
framing) and RFC 3164 (BSD legacy). The `Message`/`Sender` *design* (a pure
message codec split from the network emitter, RFC 3339-ms timestamps,
structured-data escaping, field-length validation, octet framing) is modeled
after `joelreymont/pz` `src/core/syslog.zig` (MIT) — no third-party code was
copied; all code here targets `std.Io.net` and was written from the RFCs.
DATA: `src/rsyslog_oracle_vectors.zig` holds messages our tooling drew
(`tools/rsyslog_oracle.py`), the bytes this module encoded and sent for them, and
whether a real rsyslogd and a real systemd-journald (both run as black boxes, no
source read) read each back as meant — observed behaviour, exempt per root
`NOTICE` §0.

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
// HOSTNAME goes out only when `bsd.validHostname` holds (a host name or IPv4 address); null, empty or
// anything else is omitted -- a receiver would read it as the TAG. `UnixEmitter.sendBsd` never sends it.

// ── transport (only touches the network when constructed) ──
// UDP: one datagram, truncated with a marker past ~1024 bytes, at a UTF-8 boundary.
var udp = try syslog.UdpEmitter.open(io, peer, .{});
defer udp.close();
try udp.send(&msg); // or .sendBsd(&bmsg), .sendRaw(bytes)

// TCP: RFC 6587 octet-counted framing "<len> <msg>".
var tcp = try syslog.TcpEmitter.connect(io, peer);
defer tcp.close();
try tcp.send(&msg); // or .sendBsd(&bmsg), .sendRaw(bytes)

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

## TCP emitter

- **`TcpEmitter`** -- also a unix stream socket: `connectUnix(io, path, ms)`, for a `/dev/log` a
  daemon serves that way. `connect(io, address)` (gives up after `default_connect_timeout_ms` = 5000 with
  `error.Timeout`) / `connectTimeout(io, address, ms)` / `close()` / `send(msg)`. One frame per call with ONE deadline `send_timeout_ms` (field, default 1000; 0 = fail if the first
  write would block) -> `error.Timeout`; `error.Canceled` on `std.Io` cancellation.
  A failure after the first byte of a frame (timeout, write error, cancel) leaves the stream
  desynchronised: the emitter is then **broken** and every later `send` returns `error.Broken`
  without touching the socket -- `close()` and connect again. A failure with nothing written (a
  timeout on the first write, `NoSpaceLeft` while formatting) keeps it usable. `connect` uses a raw
  non-blocking socket + `poll` because std 0.17's `Io.Threaded` panics on a connect timeout; an IPv6
  address is connected with scope id 0.

## Local delivery

- **`UnixEmitter`** — `open(path)` / `openDefault()` (`"/dev/log"`) / `close()` / `send(msg)` (RFC
  5424) / `sendBsd(msg)` (RFC 3164) / `sendRaw(bytes)` (already-formatted bytes, no internal size
  cap). One datagram per call to a unix `SOCK_DGRAM` socket. `error.NoSpaceLeft` if `send`/`sendBsd`'s
  internal formatting buffer is too small (use `sendRaw` with your own buffer instead);
  `error.MessageTooLarge` if the kernel itself rejects the datagram as too large (`EMSGSIZE`).
  `error.WouldBlock` if the receiver's queue stays full for `send_timeout_ms` (field, default
  1000; 0 = fail at once) -- the record is dropped instead of blocking the caller forever.
  `sendBsd` never sends the HOSTNAME (glibc's local shape). On a systemd host `/dev/log` is
  journald, which does not parse RFC 5424 (everything after `<PRI>` becomes MESSAGE) but reads
  `sendBsd`'s TAG and PID -- or use `journal`, which keeps every field.
- **`journal`** — the systemd Journal Native Protocol. `Emitter.open(path)` /
  `openDefault()` (`"/run/systemd/journal/socket"`) / `close()` / `send(fields)` /
  `sendMessage(.{ .message, .priority, .identifier, .fields })` (the `MESSAGE`/`PRIORITY`/
  `SYSLOG_IDENTIFIER` convenience). `Field = struct { name, value }`; a value containing a newline
  is sent in the protocol's binary form automatically, otherwise as plain `NAME=value\n`.
  `validFieldName(name)` is `sd_journal_send`'s own rule (uppercase `A`-`Z`, `0`-`9`, `_`; not
  starting with a digit or `_`; ≤ 64 bytes) — `send` checks every field name before writing
  anything, so one bad name refuses the whole call rather than half-sending it.
  `error.TooManyFields` past `journal.max_fields` (64). An entry past the datagram limit goes
  through a sealed `memfd` by `SCM_RIGHTS` as `sd_journal_send` does (a real journald stored 3 MiB
  in `tools/live_oracle.py`); `memfd_fallback = false` gives `error.MessageTooLarge` instead.
  `error.WouldBlock` and `send_timeout_ms` as for `UnixEmitter` (a stuck journald drops the record
  after the deadline).

Both are **Linux only** — raw `AF_UNIX` syscalls, since `std.Io.net` has no unix-*datagram*-socket
API — and neither binds or listens; they dial the well-known path like every other local syslog/
journal client.

## Logger and `std.log`

```zig
// std.log through syslog:
pub const std_options: std.Options = .{ .logFn = syslog.stdLogFn };

var em = try syslog.UnixEmitter.openDefault();
defer em.close();
var logger = syslog.Logger.init(.fromUnix(&em), .{ .facility = .daemon });
syslog.setStdLogger(&logger);
std.log.info("up on port {d}", .{port}); // <30>Jul  9 12:34:56 myapp[8143]: up on port 80

// or directly, as with Go's `syslog.Writer` and Rust's `syslog::Logger`:
try logger.warning("disk almost full");
try logger.print(.err, "lost {d} records", .{n});
try logger.logFull(.notice, "ID47", &.{.{ .id = "a@1" }}, "text"); // MSGID + SD (RFC 5424)
```

`Sink.fromUnix`, `fromUdp`, `fromReconnecting`, `fromWriter`, or a `Sink` of your own.
Hostname, program name and pid are detected unless given (`""`: none). A local sink
defaults to RFC 3164 without HOSTNAME, because journald on `/dev/log` reads no RFC 5424;
anything else to RFC 5424. A line past `max_line` (default 2048, floor 128) goes out cut at a
UTF-8 boundary with a marker. `std.log`'s scope becomes the MSGID (RFC 3164: a `scope: ` prefix
of MSG); a log call cannot return an error, so a line the sink refused counts in
`Logger.dropped`. `max_severity` is `setlogmask`. With `.lf`/`.nul` framing a trailer byte in
a record becomes a space. Tested on `std.Io.Threaded`: the lock is the OS thread's, so fibers
sharing a thread must not suspend in a sink.

## Reconnecting, framing, TLS

```zig
// Survives a collector restart; `init` does no I/O.
var e = syslog.ReconnectingEmitter.init(io, .{ .tcp = addr }, .{});   // or .{ .unix = "/dev/log" }
defer e.close();
try e.send(&msg);
```

Delivery is at-least-once. A failed write is retried on a new connection (`retries`,
default 1), and before each send it checks whether the peer has already closed: Go's
`log/syslog` and Rust's `syslog` write into the half-closed socket there, the kernel takes
it and the record is gone. `error.Timeout` is not retried (a collector that stopped
reading would cost `retries + 1` deadlines per record). After a failed connect, `send`
answers `error.Backoff` at once for `backoff_ms` (1000).

`TcpEmitter.framing` / `Config.framing`: `.octet_counting` (RFC 6587 §3.4.1, the default on
TCP), `.lf` (§3.4.2, for old collectors), `.nul` (glibc's on a local stream socket, the
default for `connectUnix`). With `.lf`/`.nul`, `send` replaces the trailer byte in the
message with a space, which would otherwise forge a record; `sendRaw` refuses
(`error.DelimiterInMessage`). `sendRaw` has no 2048-byte cap.

**RFC 5425 (TLS)** is octet counting inside TLS, so it goes through a writer; the session
stays yours, with its certificate and name checks (RFC 5425 §4.2). `tools/live_oracle.py`
holds this against OpenSSL:

```zig
var client = try tlsclient.Client.init(&sr.interface, &sw.interface, .{ .host = .{ .explicit = name }, .ca = ..., ... });
var e: syslog.WriterEmitter = .{ .writer = &client.writer, .downstream = &sw.interface };
try e.send(&msg); // flushed through the session and the socket
// Before closing: client.end(), flush, and read to the peer's close. Unread session
// tickets would turn the close into an RST, which discards what the server has not read.
```

The module does not import a TLS stack: the cost stays with whoever needs one.

## Parsing

```zig
const m = try syslog.parse(line); // strict RFC 5424: slices of `line`, no allocation
m.facility; m.severity; m.timestamp.?.unix_us; m.hostname; m.msgid; m.msg; m.msg_utf8;
var els = m.elements();
while (els.next()) |el| {
    var ps = el.params();
    while (ps.next()) |p| _ = try p.value(&buf); // unescaped into your buffer
}

const b = syslog.parseBsd(line);  // lenient RFC 3164; never fails, what it cannot tell stays in msg
const any = syslog.parseAny(line); // RFC 5424 when it holds, else RFC 3164

// RFC 6587 frames off a TCP stream's buffered bytes; null = not all here yet:
while (try syslog.nextFrame(pending, syslog.default_max_frame)) |f| {
    handle(f.payload);
    pending = pending[f.consumed..];
}
```

There is no listener: bytes come from wherever you read them, and everything here takes
hostile input (fuzzed, and differentially checked against go-syslog and rsyslogd). `parse`
differs from go-syslog on purpose in three listed ways (`tools/go_oracle/main.go`).

## Tests

Offline golden-byte tests (no live socket): a full message with structured
data, a minimal all-NILVALUE message, SD escaping of `"`/`\`/`]`, PRI for
several facility/severity pairs, timezone-offset timestamps, field truncation
at the length limits, and the RFC 6587 octet-count prefix. `TcpEmitter` and
`ReconnectingEmitter` run over loopback and unix stream sockets, local delivery
over throwaway `AF_UNIX` sockets in `.zig-cache/tmp/` — no daemon needed; a real
UDP send is the one path no unit test opens. Every encoder and emitter is anchored
by a real rsyslogd and a real systemd-journald (`zig build interop-syslog`,
`tools/README.md`), whose verdicts the tests replay offline; the parser by those
same vectors and by go-syslog (`tools/go_oracle`). `SYSLOG_FUZZ=<runs>` runs the
fuzz driver.

```
zig build test-syslog                          # Debug
zig build test-syslog -Doptimize=ReleaseFast   # ReleaseFast
```

## Not implemented, on purpose

- **A listener / daemon**: rsyslogd's job; the parser is the part a program needs.
- **macOS / BSD local paths**: the emitters are Linux syscalls; `open(path)` takes any path.
- **A TLS stack in the module**: a seam, above.
- **Microseconds in the encoder**: milliseconds are what it prints; the parser reads up to six digits.
