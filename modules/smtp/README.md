# smtp

An **SMTP client** (RFC 5321) with **MIME message composition** (RFC 5322 / 2045 / 2046 /
2047), in pure Zig — ESMTP capability negotiation, STARTTLS as a seam, AUTH PLAIN/LOGIN,
PIPELINING, SIZE, 8BITMIME, SMTPUTF8, correct DATA transparency, and a composer that
builds `multipart/mixed` and `multipart/alternative` trees with attachments.

- **The reply model, properly.** A reply is one or more lines that all carry the same
  three-digit code; the fourth octet is `-` on a continuation and SP on the last line.
  Getting that wrong desynchronises the whole session, so it is a pure incremental parser
  (`feed`/`next`) with the same result whether bytes arrive one at a time or in one read.
  Codes map to **typed** errors that keep the distinction a caller needs:
  `error.TransientFailure` (4yz — retry this later) versus `error.PermanentFailure` (5yz —
  do not). RFC 3463 enhanced status codes are parsed when the server sends them.
- **ESMTP negotiation.** The EHLO reply is resolved into a capability set — `STARTTLS`,
  `AUTH`, `PIPELINING`, `SIZE`, `8BITMIME`, `SMTPUTF8`, `ENHANCEDSTATUSCODES`,
  `CHUNKING`/`BINARYMIME`/`DSN` (reported, not implemented) — with unknown keywords kept
  verbatim rather than rejected, and a `HELO` fallback for a server that refuses EHLO.
- **STARTTLS is a seam, not an implementation** (CONVENTIONS.md §2). The module negotiates
  it, the caller performs the handshake and returns the upgraded transport. The pre-TLS
  capability set is **discarded** and EHLO re-issued (RFC 3207 §4.2 — trusting it is a
  downgrade vulnerability), and any byte buffered across the handshake is
  `error.PlaintextInjection`, not leftover data.
- **AUTH** PLAIN (RFC 4616) and LOGIN, refused on an unencrypted link unless the caller
  sets `allow_plaintext_auth` (RFC 4954 §14).
- **DATA transparency.** Dot-stuffing on send, un-stuffing on receive, and the `CRLF.CRLF`
  terminator. A body line that is exactly `.` is the canonical case and is tested
  everywhere, including end-to-end against a real server. The terminator is *only*
  `CRLF.CRLF`: a bare `LF.LF` does not end the data, which is the parser disagreement
  "SMTP smuggling" turns into message injection.
- **MIME composition.** RFC 5322 header folding, RFC 2047 encoded words (`B` and `Q`, never
  splitting a UTF-8 sequence), quoted-printable and base64, `multipart/mixed`,
  `multipart/alternative` and `multipart/related`, attachments with `Content-Disposition`
  and RFC 2231 filenames, RFC 5322 dates, generated `Message-ID`. Boundaries are checked
  against the rendered parts, not assumed unique. The 998-octet line limit is enforced on
  the finished document.
- **Injection is closed on both sides.** A CR, LF or NUL in any command argument is
  `error.ControlCharacterInArgument`; the same in a header value, display name or filename
  is `error.ControlCharacterInHeader`. A `Subject` from a web form cannot grow a `Bcc:`.
- **A pure `Session`.** The entire conversation is a state machine with no I/O, driven by
  `next()` / `feedReply()`, so a transcript replays without a socket. `Client` is the thin
  loop over a `Transport` and is the only place that blocks.

No clock and no ambient randomness are read anywhere: the `Date` is an input
(`mime.DateTime`) and boundaries / `Message-ID` come from a caller-supplied `std.Random`,
so the same message renders to the same bytes every time.

Consumers: anything that has to send mail — alerting from the `metrics`/`health` stack,
bounce/DSN generation, a device fleet mailing reports, and any place you would otherwise
shell out to `sendmail`.

## Import

```zig
const smtp = @import("smtp");
```

## Usage

Compose and send in one call:

```zig
var t = MyTransport.init(socket);            // one blocking read, one write
var c = try smtp.Client.init(gpa, t.transport(), .{ .session = .{
    .ehlo_domain = "client.example.org",
    .tls = .required,                        // .disabled | .opportunistic | .required
    .credentials = .{ .username = "user@example.com", .password = pw },
}, .tls = .{ .ctx = &tls_ctx, .upgrade = myStartTls } });
defer c.deinit();

try c.connect();                             // greeting → EHLO → STARTTLS → EHLO → AUTH

var prng = std.Random.DefaultPrng.init(seed);
const sent = try c.sendMessage(.{
    .from = .{ .name = "Alice Example", .addr = "alice@example.com" },
    .to = &.{.{ .name = "Bob Example", .addr = "bob@example.net" }},
    .subject = "Žluťoučký kůň",              // encoded-word encoded for you
    .date = .{ .unix = now_seconds, .offset_minutes = 120 },
    .body = .{ .multipart = .{ .subtype = .mixed, .parts = &.{
        .{ .multipart = .{ .subtype = .alternative, .parts = &.{
            .{ .text = .{ .body = "plain version\r\n" } },
            .{ .text = .{ .subtype = "html", .body = "<p>html version</p>\r\n" } },
        } } },
        .{ .attachment = .{
            .filename = "účtenka.pdf",
            .content_type = "application/pdf",
            .data = pdf_bytes,
        } },
    } } },
}, prng.random(), .{}, .{ .to = &.{"bob@example.net"} });
defer gpa.free(sent);                        // the exact octets that went out

for (c.recipients()) |r| std.debug.print("{s}: {d}\n", .{ r.addr, r.code });
try c.quit();
```

Envelope only, when the message bytes come from somewhere else:

```zig
try c.sendEnvelope(.{
    .from = "bounce@example.com",            // null = the `<>` reverse-path
    .to = &.{ "a@example.net", "b@example.net" },
    .body = already_composed_rfc5322,        // the client dot-stuffs it
});
```

The composer with no session at all:

```zig
const doc = try smtp.render(gpa, msg, prng.random(), .{});
defer gpa.free(doc);
```

The pieces on their own — a reply parser, a dot-stuffer, an EHLO capability set:

```zig
var p: smtp.ReplyParser = .init(gpa, .{}, .{});
try p.feed(bytes_from_anywhere);
while (try p.next()) |r| try r.check();             // Transient / Permanent

const wire = try smtp.stuffAlloc(gpa, body, .{});   // dot-stuffed + CRLF.CRLF
const back = try smtp.unstuffAlloc(gpa, wire, .{}); // == body
```

### Driving the session yourself

`Client` is a ten-line loop over `Session`; write your own if you want a different I/O
model (an event loop, a proxy, a test harness):

```zig
while (true) switch (try s.next()) {
    .send      => |b| try conn.write(b),
    .send_body => |b| try smtp.writeData(&conn_writer, b, .{}),  // dot-stuffs + terminates
    .recv      => try s.feedReply(try readOneReply()),
    .start_tls => { try upgrade(); try s.tlsEstablished(); },
    .done      => break,
};
```

### Read timeouts

Exactly one call blocks — `Client.pumpOnce`, one `Transport.read` — and everything below it
is a pure state machine. This module owns no thread and no timer. To bound a wait,
implement `Transport.read` with the deadline you want:

```zig
fn readFn(ctx: *anyopaque, buf: []u8) smtp.TransportError!usize {
    const self: *MyTransport = @ptrCast(@alignCast(ctx));
    if (!try self.waitReadable(self.deadline_ns)) return 0;   // 0 = nothing this round
    return self.inner.read(buf);
}
```

`read` returning **0 means "no data this round"**, not end of stream (that is
`error.EndOfStream`), so a timed-out read leaves a half-received reply intact.

### STARTTLS

No TLS lives in this repo. Supply a `TlsUpgrade`: it performs the handshake on the current
socket and returns the `Transport` that speaks TLS.

```zig
fn myStartTls(ctx: *anyopaque) smtp.TransportError!smtp.Transport { ... }
```

With `tls = .required` and no hook, a server that offers STARTTLS gives
`error.TlsUnavailable` — the session never silently continues in the clear.

## API

### Client / Session

| Call | Meaning |
|---|---|
| `Client.init(gpa, transport, Options)` / `.deinit()` | one connection |
| `.connect()` | greeting → EHLO → STARTTLS → AUTH |
| `.sendEnvelope(Envelope)` | one MAIL/RCPT/DATA transaction |
| `.sendMessage(Message, Random, RenderOptions, .{ .to = … })` | compose + send; returns the octets sent |
| `.quit()` | QUIT and consume the 221 |
| `.pumpOnce() !usize` | **the one blocking call** — one `Transport.read` |
| `.receiveReply() !Reply` | next complete reply (loops `pumpOnce`) |
| `.serverCapabilities()` / `.lastReply()` / `.recipients()` / `.state()` | what happened |
| `Session.next() !Step` / `.feedReply(Reply)` | the pure state machine |
| `Session.beginTransaction(Envelope)` / `.requestQuit()` / `.tlsEstablished()` | queue work |

`Step` = `.send` / `.send_body` / `.recv` / `.start_tls` / `.done`.

### Types

- `Transport` — `{ ctx, vtable{ read, write } }`; `TransportError` = `ReadFailed` /
  `WriteFailed` / `EndOfStream`. `TlsUpgrade` is the STARTTLS hook.
- `Options` (session) — `ehlo_domain`, `tls` (`TlsPolicy`), `credentials`,
  `allow_plaintext_auth`, `pipelining`, `announce_size`, `require_all_recipients`,
  `max_recipients`, plus the command/capability limit structs.
- `Envelope` — `from` (`null` = `<>`), `to`, `body`, `eight_bit`, `smtputf8`.
  `RecipientStatus` carries each recipient's code and whether it stuck.
- `Reply` — `.code`, `.enhanced`, `.text`, `.lines`; `check()`, `expectCode()`, `class()`,
  `clone()`. `ReplyParser` = `init(gpa, Limits, Options)`, `feed`, `next`, `atBoundary`.
- `Capabilities` — resolved flags plus `has()` / `params()` / `line()` for anything not
  modelled, and `max_size` / `sizeExceeded()`.
- `Message` / `Part` (`.text` / `.attachment` / `.multipart`) / `Address` / `DateTime` /
  `Header`; `render(gpa, msg, random, RenderOptions)`.
- `Stuffer` / `Unstuffer` and `writeData` / `stuffAlloc` / `unstuffAlloc` for DATA
  transparency on its own.

Errors: `ClientError` unions the transport, parser and session errors, so one `catch`
covers a call. The interesting ones are `error.TransientFailure` / `error.PermanentFailure`
(the retry decision), `error.AllRecipientsRejected`, `error.RecipientRejected`,
`error.AuthenticationFailed`, `error.PlaintextAuthRefused`, `error.TlsNotOffered`,
`error.TlsUnavailable`, `error.PlaintextInjection`, `error.MessageTooLarge`,
`error.ControlCharacterInArgument` / `ControlCharacterInHeader` (injection),
`error.BoundaryCollision` and `error.LineTooLong`.

## Verify

```sh
zig build test-smtp                 # unit/golden/fuzz; the live test prints SKIPPED and passes
zig build test-smtp --release=fast  # same, optimized

# With a real SMTP server (see SPEC.md for a ready-made aiosmtpd oracle):
SMTP_TEST_SERVER=127.0.0.1:8025 SMTP_TEST_USER=tester SMTP_TEST_PASSWORD=s3cret \
SMTP_TEST_CAPTURE=/tmp/last.eml \
  zig build test-smtp               # + EHLO → AUTH → MAIL/RCPT/DATA → QUIT, then asserts
                                    #   the file the SERVER wrote equals what we sent
```

SPEC.md records which server the live run used, which goldens are real captures, how the
independent MIME parser cross-check was done, and the deferred list.

Provenance: clean-room from RFC 5321 / 5322 / 1869 / 1870 / 2045 / 2046 / 2047 / 2231 /
2920 / 3207 / 3461 / 3463 / 4616 / 4954 / 6152 / 6531. No third-party source was ported or
studied, so there is no `/NOTICE` entry — `aiosmtpd`, `swaks` and Python's `email` module
were used only as black-box oracles.
