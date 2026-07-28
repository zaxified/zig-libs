# smtp — spec

Design + threat notes for auditors. Usage: see ./README.md. Attribution/provenance: see
/NOTICE (this module needs no entry — see "Provenance" below).

## Design & invariants

### Layering, and what each layer is allowed to know

| File | Contents | Knows about I/O? |
|---|---|---|
| `reply.zig` | RFC 5321 §4.2 multi-line replies + RFC 3463 enhanced codes (`Parser.feed`/`next`) | no |
| `capabilities.zig` | RFC 5321 §4.1.1.1 / RFC 1869 EHLO keyword set | no |
| `command.zig` | RFC 5321 §4.1 command serialisation + §4.5.3.1 ceilings + address grammar | no |
| `data.zig` | RFC 5321 §4.5.2 dot-stuffing and un-stuffing | no |
| `auth.zig` | RFC 4954 / RFC 4616 SASL PLAIN + LOGIN | no |
| `mime.zig` | RFC 5322 folding, RFC 2047 encoded words, QP, base64, dates | no |
| `message.zig` | the composer: headers, multipart trees, attachments, boundaries | no |
| `session.zig` | the conversation state machine (`next`/`feedReply`) | no |
| `client.zig` | `Transport`, the drive loop, STARTTLS hook, live test | one call |
| `live_golden.zig` | the captured live transcript, replayed | no |
| `root.zig` | re-exports + `meta` | no |

Only `client.zig` touches a byte stream, and inside it exactly one function blocks:
`Client.pumpOnce`, one `Transport.read` fed to the reply parser. Everything else is a loop
over that call. That is the module's whole concurrency policy: it has none, and it never
starts a thread or a timer. Time and randomness are inputs too (`mime.DateTime`,
`std.Random`), so `render` is a pure function of its arguments.

### The `-` versus SP test

RFC 5321 §4.2.1: `Reply-line = *( Reply-code "-" [ textstring ] CRLF ) Reply-code [ SP
textstring ] CRLF`. A client that returns after the first line reads every later reply one
command too early and stays desynchronised for the rest of the connection. So:

* all lines of a reply must carry the same code (`error.ReplyCodeMismatch` otherwise);
* the fourth octet must be SP or `-` (`error.MalformedReply`);
* a bare three-octet line (`250`) is a legal last line with empty text;
* the number of continuation lines and the accumulated text are both bounded
  (`error.ReplyTooLong`) — that is the "continuation that never terminates" case.

The parser is fed one byte at a time as well as in one piece in every decode test, and both
must agree, including on which error a hostile input produces.

### Permanent versus transient is a type, not a comment

`Reply.check()` maps 4yz to `error.TransientFailure` and 5yz to `error.PermanentFailure`,
and every layer above propagates them unchanged — including `Session.feedReply`, so a
greylisting 451 on MAIL FROM surfaces as `error.TransientFailure` and a 550 as
`error.PermanentFailure`. A caller's retry logic is a `switch` on that, not a string match
on the server's prose. `Reply.expectCode(354)` preserves the class of a wrong-but-valid
reply for the same reason.

RFC 3463 enhanced codes are parsed out of the first line only when the leading token really
is `class.subject.detail` **and** the class digit equals `code / 100`; otherwise the token
is prose and `enhanced` stays null (real servers do start messages with "5.0 " style text).
The enhanced prefix is deliberately *not* stripped from `Reply.text`: it is part of what the
server said.

### STARTTLS: three separate protections

1. **The capability set learned in the clear is discarded.** RFC 3207 §4.2. An active
   attacker owns every byte of the pre-TLS EHLO reply: it can *remove* `STARTTLS`
   (downgrade) or *add* `AUTH PLAIN` to a server that never offered it. `Session.
   tlsEstablished` frees `caps`, clears `esmtp`, and moves back to the `.ehlo` state; a
   test asserts that a pre-TLS `AUTH PLAIN` claim does not survive.
2. **Buffered plaintext across the handshake is refused.** `Client.drive` checks
   `parser.atBoundary()` before calling the TLS hook and returns
   `error.PlaintextInjection` if anything is buffered, then discards the parser entirely.
   This is the plaintext-command-injection class (CVE-2011-0411 and its many siblings): a
   server or a man in the middle appends `250 injected\r\n` to the `220 Ready to start
   TLS`, and a client that keeps its buffer executes it as though it had arrived inside
   TLS. A test drives exactly those bytes.
3. **`tls = .required` never continues in the clear.** No STARTTLS advertised is
   `error.TlsNotOffered`; a caller with no TLS hook is `error.TlsUnavailable`; a refused
   STARTTLS keeps the reply's transient/permanent class. Only `.opportunistic` falls back,
   and then only after the server itself refused.

### AUTH

PLAIN and LOGIN both send the password in a base64 that is not encryption, so
`Session.afterTlsDecision` returns `error.PlaintextAuthRefused` unless `tls_active` or the
caller set `allow_plaintext_auth` (RFC 4954 §14). The refusal happens **before** any AUTH
command is written; the test asserts the wire carries no `AUTH` at all in that case.

Credentials are validated before encoding: a NUL would forge RFC 4616's field separator, a
CR/LF would forge a command line (`error.InvalidCredential`). The plaintext staging buffer
and the session's command buffer are `secureZero`ed after use — a mitigation, not a
guarantee (the caller's own copies are the caller's problem).

LOGIN's challenge text is advisory: the *order* of the exchange is authoritative, because
servers send "Username:", "User Name", or nothing. A challenge that clearly asks for the
password first is honoured; anything else follows the order.

### DATA transparency, and the SMTP-smuggling shape

`Stuffer` doubles a period that starts a line and guarantees the closing `CRLF.CRLF`;
`Unstuffer` is the exact inverse. A body whose second line is `.` is the canonical case and
appears in the unit tests, the fake-server tests, the live test and the captured golden.

Both directions are strict about line endings, and that strictness is the point:

| Input | Verdict |
|---|---|
| `CRLF.CRLF` | terminates the data |
| `LF.LF` / `CR.CR` | does **not** terminate; a bare LF is `error.BareLineFeed` by default |
| a CR not followed by LF | `error.BareCarriageReturn` |
| a line over 998 octets (§4.5.3.1.6) | `error.LineTooLong`, on send and on receive |
| data after the terminator | `error.DataAfterTerminator` |

That is the 2023 "SMTP smuggling" family: two hops disagreeing about what ends the data let
an attacker inject a second, forged message into an authenticated session. A sender may opt
into `.normalize` (lone LF/CR rewritten to CRLF, the default for composing) or `.strict`
(refused); a receiver may opt into `allow_bare_lf`, and has to say so.

### Injection is closed on both sides

* **Commands.** Any CR, LF or NUL in an argument is `error.ControlCharacterInArgument`
  before a byte is formatted. `RCPT TO:<a@example.com>\r\nRCPT TO:<victim@example.net>`
  built from an unvalidated form is how a closed relay becomes an open one.
* **Headers.** The same octets in a header value, display name, filename or `Message-ID`
  are `error.ControlCharacterInHeader`. A `Subject` from a web form cannot grow a `Bcc:`.
* **Addresses** are validated against RFC 5321 §4.1.2 `Mailbox` (dot-string or
  quoted-string local part; `Domain` or an address literal parsed by the sibling `netaddr`
  module) with the §4.5.3.1 ceilings (local-part 64, domain 255, path 256, command line
  512). Non-ASCII is refused unless the caller says SMTPUTF8 was negotiated.
* **`Bcc` is not emitted** unless `RenderOptions.include_bcc` — a `Bcc` header that reaches
  the recipients is a privacy incident, and the default protects against forgetting.

### Boundaries are checked, not assumed

RFC 2046 §5.1.1 requires the boundary not to occur in any body part. `renderMultipart`
renders **every child first**, then draws a boundary and searches all of those bytes for
it; a hit redraws, and after `max_boundary_attempts` it is `error.BoundaryCollision`. Two
tests cover it: one learns the boundary a fixed seed produces, embeds it in a body, and
asserts the next render picks a different one; the other sets `boundary_entropy = 0` so no
draw can ever succeed and asserts the error rather than a corrupt message.

The CRLF before a delimiter line belongs to the delimiter, not to the part, so a part's
content is written exactly as encoded and the container adds the separator. That is what
makes `decode(render(x)) == x` hold for bodies that do and do not end in a line break — and
it is what the independent Python parse below actually verifies.

### Encoded words

RFC 2047 §2 caps a word at 75 octets, but a word must also *fit the fold width where it
lands*, or every header degenerates to one word per line. `writeEncodedWords` therefore
sizes each word to the room left on the current line (folding first when there is not
enough), never splits a UTF-8 sequence across two words, and picks `Q` or `B` by whichever
is shorter — with space costed as `_` (one octet), because forgetting that makes every
ASCII-mostly subject pick `B` and become unreadable. A literal `=?` in an otherwise-ASCII
value is encoded too, so it cannot be read back as the start of a word.

### Pipelining

With `PIPELINING` advertised, `MAIL FROM`, every `RCPT TO` and `DATA` go out in one write —
RFC 2920 §3.1 permits exactly that group and requires `DATA` to be last in it. Every reply
of the group is consumed **even after a failure**, because the server has already queued
answers for the commands it received and skipping them desynchronises the connection; the
recorded error is returned once the group is drained. A test asserts the drain by counting
that all scripted replies were read.

Once the server has answered `354` there is no way out of data mode, so the data must be
terminated. Two cases, both deliberate:

* the only complaint is our own `require_all_recipients` policy → the real message is sent
  (the accepted recipients are real) and the policy error is reported after the 250;
* anything else (the envelope failed, or no recipient stuck) → an empty body is sent so the
  connection stays usable, and the failure is reported.

## Verification

### Live interop — a real, third-party SMTP server

The live test in `client.zig` is gated on `SMTP_TEST_SERVER` (plus optional
`SMTP_TEST_USER` / `SMTP_TEST_PASSWORD` / `SMTP_TEST_CAPTURE`) and prints `SKIPPED:` and
passes without it, the pattern used by `netconf`, `ssh` and `tc`.

It was run, and passes, against **Python `aiosmtpd` 1.4.6** (with `atpublic` 7.0.0, on
CPython 3.14.4) — an independent async SMTP *server* implementation — listening on
`127.0.0.1:8025`, with a ~40-line handler that writes `envelope.content` verbatim to a
capture file. What ran, in one session:

1. `EHLO client.example.org` → the server's 7-line 250 (SIZE 33554432, 8BITMIME, SMTPUTF8,
   AUTH LOGIN PLAIN, PIPELINING, HELP), parsed into the capability set;
2. `AUTH PLAIN AHRlc3RlcgBzM2NyZXQ=` → `235 2.7.0 Authentication successful`;
3. `MAIL FROM:<sender@example.com> SIZE=1058` + `RCPT TO:<rcpt@example.net>` + `DATA` **as
   one pipelined group**, replies read in order;
4. the message: `multipart/mixed` containing a `multipart/alternative`
   (`text/plain` + `text/html`, both quoted-printable, both with a line that is **exactly
   `.`**) and a base64 attachment with an RFC 2231 non-ASCII filename, dot-stuffed and
   terminated with `CRLF.CRLF` → `250 2.0.0 Message accepted for delivery`;
5. `QUIT` → `221 Bye`.

The test then reads the file **the server wrote** and asserts it is byte-identical to the
1058 octets the client produced. The server's own JSON summary confirms the envelope it
saw: `mail_from='sender@example.com'`, `rcpt_tos=['rcpt@example.net']`,
`mail_options=['SIZE=1058']`, `authenticated=True`, `auth_user='tester'`,
`host_name='client.example.org'`, `content_len=1058`.

Reproducing the oracle (no root, high port):

```sh
python3 -m pip install --target ./pylib aiosmtpd
# ~40 lines: a handler whose handle_DATA writes envelope.content to CAPTURE, an
# authenticator accepting one fixed user, and
#   Controller(Handler(), hostname="127.0.0.1", port=8025,
#              server_hostname="oracle.example.com",
#              authenticator=..., auth_require_tls=False,
#              enable_SMTPUTF8=True, decode_data=False)
PYTHONPATH=./pylib python3 server.py 127.0.0.1 8025 /tmp/last.eml
```

`aiosmtpd` does not implement PIPELINING itself; its `handle_EHLO` hook was used to add the
`250-PIPELINING` line so the RFC 2920 path could be exercised against a real peer (it reads
commands from an asyncio stream, so a grouped write works). Everything else is stock.

**What was not available on this machine:** no root, so no `postfix`/`exim`; and no TLS, so
the STARTTLS path was *not* exercised live — it is covered by the in-memory tests only
(including the plaintext-injection case). That is an honest gap: the STARTTLS state
transitions are verified, the interaction with a real TLS-terminating MTA is not.

### Byte-exact goldens — which are real captures

`live_golden.zig` contains **two verbatim captures of the session above**, recorded by a
40-line TCP proxy that logged both directions to disk:

| Golden | Origin |
|---|---|
| `live_server` (297 octets) | every octet `aiosmtpd` sent, unedited |
| `live_client` (1202 octets) | every octet this module sent, unedited |

The only edit anywhere: the server was started with `server_hostname="oracle.example.com"`
so the transcript carries no local machine name.

Three tests use them:

1. the captured EHLO reply is parsed and every resolved capability asserted — the reply
   parser fed foreign bytes, including a 7-line reply where only the last line has a space
   separator;
2. **the replay test**: the captured server bytes are fed into the *pure* `Session`, the
   same message is re-composed from the same seed, and the produced wire bytes are compared
   to `live_client` **octet for octet**. Any drift in the reply parser, the capability
   resolution, the AUTH encoding, the pipelining grouping, the `SIZE=` parameter, the MIME
   composition, the encoded words, the quoted-printable, the boundaries or the dot-stuffing
   changes that string. It also asserts every reply in the capture was consumed;
3. the DATA payload is extracted from the client capture, un-stuffed byte at a time, and
   compared with a fresh `render` — with an explicit assertion that the wire carried `..`
   where the document has `.`.

Every other golden in the module is **self-derived** (our own canonical output, pinned
against accidental change) or **taken from an RFC**: the RFC 4616 §4 / RFC 4954 §4 AUTH
PLAIN examples, the RFC 2045 §6.7 quoted-printable rules, and the RFC 5322 §3.3 date
format. These are labelled as such in the test names.

### Independent MIME parser cross-check

The captured `.eml` — the bytes the *server* received — was parsed with **Python's `email`
module** (`BytesParser(policy=policy.default)`), which is an entirely independent
implementation of RFC 5322/2045/2047/2231. Result:

```
Subject : 'Živá zkouška — live interop'          # RFC 2047 B-word decoded
To      : 'Recipient Ř <rcpt@example.net>'       # RFC 2047 Q-word decoded
Date    : 'Wed, 22 Jul 2026 12:00:00 +0200'
defects : []                                     # at every level of the tree
multipart/mixed
  multipart/alternative
    text/plain  cte=quoted-printable  payload='první\r\n.\r\ntřetí\r\n'
    text/html   cte=quoted-printable  payload='<p>první</p>\r\n<p>.</p>\r\n'
  text/plain    cte=base64  disp=attachment  filename='účtenka.txt'
                payload='attachment line 1\n.\nattachment line 3\n'
```

Both encoded-word forms decode to the intended text, the tree structure and every
`Content-Type` / `Content-Transfer-Encoding` / `Content-Disposition` match what was
composed, the RFC 2231 filename decodes to `účtenka.txt`, **zero defects are reported at
any level**, and each payload — including the line that is exactly `.` — comes back byte
for byte. That is the strongest available evidence that the composer is not merely
self-consistent.

### Third-party client cross-check

`swaks` (DEVRELEASE), an unrelated SMTP client, was pointed at the same server with the
same credentials and the same kind of body. It emitted `AUTH PLAIN AHRlc3RlcgBzM2NyZXQ=` —
byte-identical to ours — and dot-stuffed its `.` line to `..` exactly as we do. A test in
`live_golden.zig` pins that agreement.

### Hostile input and fuzzing

Every one of these is a typed error, asserted from both a whole-buffer feed and a
one-byte-at-a-time feed where the layer is incremental:

| Input | Verdict |
|---|---|
| a reply line with no code / a non-digit / a leading 0 or 7 | `error.InvalidReplyCode` |
| fewer than three octets, or a fourth octet that is not SP/`-` | `error.MalformedReply` |
| a continuation whose code differs from the first line | `error.ReplyCodeMismatch` |
| a continuation that never terminates | `error.ReplyTooLong` |
| a reply line longer than any sane limit | `error.ReplyLineTooLong` (before it is buffered whole) |
| a bare LF / a bare CR in a reply | `error.BareLineFeed` / `error.BareCarriageReturn` |
| more buffered input than `max_pending` | `error.PendingTooLarge` |
| malformed dot-stuffing (`LF.LF`, data after the terminator, a 999-octet line) | `error.BareLineFeed` / `DataAfterTerminator` / `LineTooLong` |
| a header line over 998 octets that cannot fold | `error.LineTooLong` |
| CR/LF/NUL in a header value, display name, filename or command argument | `ControlCharacterInHeader` / `ControlCharacterInArgument` |
| a bad-base64 or non-base64 AUTH challenge | `error.MalformedChallenge` |
| a boundary that appears inside a part | redrawn; `error.BoundaryCollision` if impossible |
| an unknown / syntactically invalid EHLO keyword | kept verbatim, ignored (RFC 1869 §4.5) |
| more capability lines than the limit | `error.TooManyCapabilities` |
| an empty multipart / too-deep nesting / too many recipients | `EmptyMultipart` / `DepthExceeded` / `TooManyRecipients` |

Seven `std.testing.fuzz` targets: the reply parser (both bare-LF policies), the capability
parser, the command builders (asserting no output ever contains a bare CR/LF and no line
exceeds 512), the dot-stuffer/un-stuffer (asserting `unstuff(stuff(x))` equals an
*independently computed* canonicalisation of `x`, so the round-trip is not the encoder
checking itself), the AUTH encoders, the header writers (asserting every CR is followed by
LF, every LF preceded by CR, and every line within 998), and the whole message renderer
(asserting the line limit and that the boundary occurs exactly four times — the
`Content-Type` parameter, two delimiters and the closer).

`zig build test-smtp` is green in both `Debug` and `--release=fast`. Without a live server,
the one live test prints `SKIPPED:` and passes; with `SMTP_TEST_SERVER` set, it runs for real.

## Provenance

Clean-room from RFC 5321 (SMTP), RFC 5322 (message format), RFC 1869 (ESMTP), RFC 1870
(SIZE), RFC 2045/2046/2047 (MIME), RFC 2231 (parameter encoding), RFC 2920 (PIPELINING),
RFC 3207 (STARTTLS), RFC 3461 (DSN, negotiation only), RFC 3463 (enhanced status codes),
RFC 4616 (SASL PLAIN), RFC 4954 (AUTH), RFC 6152 (8BITMIME) and RFC 6531 (SMTPUTF8). No
third-party source was ported and no third-party implementation was studied as a design
reference, so per CONVENTIONS.md §5 this module needs **no `/NOTICE` entry** — the RFC
citations live here. `aiosmtpd`, `swaks` and Python's `email` module were used purely as
black-box compatibility oracles (nothing read from or copied out of them), which
CONVENTIONS.md §5 also puts outside NOTICE's scope.

## Deferred

Honest list of what this module does **not** do:

* **DKIM signing / verification (RFC 6376), ARC, SPF, DMARC.** A `raw` header lets a caller
  attach a signature produced elsewhere; nothing here canonicalises or signs. DKIM's
  relaxed/simple body canonicalisation plus key management is a module of its own.
* **DSN (RFC 3461).** The capability is parsed and the null reverse-path `<>` that bounces
  require is supported, but there are no `RET=`/`ENVID=`/`NOTIFY=`/`ORCPT=` parameters and
  no `multipart/report` composer.
* **BDAT / CHUNKING / BINARYMIME (RFC 3030).** Advertised capabilities are reported;
  transmission is always `DATA`.
* **A server side.** Client only. `data.Unstuffer` is the receive half of DATA and is fully
  tested (it is how the sender is verified), and `reply.zig` would serve a server's writer,
  but nothing here listens or answers.
* **TLS.** By repo policy (CONVENTIONS.md §2): STARTTLS is negotiated, the handshake is the
  caller's. Consequently the STARTTLS path has **no live verification** — see above.
  Implicit TLS on port 465 (RFC 8314) needs no code here at all: hand the client an
  already-encrypted `Transport` and set `tls = .disabled`.
* **SASL beyond PLAIN and LOGIN.** No CRAM-MD5 (obsolete and requires storing
  password-equivalent material), no SCRAM, no GSSAPI, no XOAUTH2. `Capabilities.auth.other`
  reports that the server offered something else so a caller can say why it gave up.
* **IMAP, POP3, message *parsing*.** This composes and sends. Reading mailboxes and parsing
  arbitrary inbound MIME (a far bigger hostile-input surface) are separate problems.
* **Name resolution and MX lookup.** The caller connects; the sibling `dns` module has
  `MX` if you need it. No queueing, no retry scheduling, no bounce handling — the
  transient/permanent distinction is surfaced so a caller's queue can make those decisions.
* **RFC 6531 SMTPUTF8 end to end.** Negotiated, and non-ASCII envelope addresses are
  permitted once it is, but there is no downgrade path (RFC 6530 §6) and no live test with
  a UTF-8 mailbox — the live server advertises it, we did not use it.
* **`VRFY`/`EXPN`/`HELP`/`TURN`.** `VRFY` has a builder for completeness; the session never
  uses any of them.
* **Header *parsing*.** `Message` is write-only: there is no RFC 5322 parser, no
  encoded-word decoder outside the tests, and no address-list parser.
* **A timeout implementation.** By design (see above) — the seam is there, the policy is the
  caller's.
