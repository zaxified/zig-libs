# imap

An **IMAP4rev2 (RFC 9051) client** in pure Zig, transport-agnostic: it owns no
socket and speaks no TLS, so it drops onto plain TCP, `std.crypto.tls.Client`,
or a test buffer unchanged — the same seam `smtp` and `dtls` use.

**Status: COMPLETE.** Modified UTF-7, the wire grammar, the response reader,
the command encoder, the session, and — from part 2 — `FETCH` with `ENVELOPE`
and `BODYSTRUCTURE`, `SEARCH` in both reply shapes, and `IDLE`.

**Anchored against a live server.** Alongside the RFC transcripts (which pin
the *parsing*), a LIVE test drives the client against **pymap** — an
independent IMAP server: different author, different language, no shared code
with the go-imap this module was ported from. That independence is the point;
go-imap ships its own server, but there client and server share one wire layer,
so a shared misreading of the grammar would be invisible to both.

```
python3 -m venv ~/.cache/zig-libs-imap
~/.cache/zig-libs-imap/bin/pip install pymap
```

The test starts the server itself on a high port, runs greet -> login ->
select -> fetch -> search -> idle -> logout, and **skips loudly** when pymap is
not installed (`scripts/test.sh` prints the install line). It never touches a
service it did not start.

**Provenance:** a PORT of [`emersion/go-imap`](https://github.com/emersion/go-imap)
v2 (MIT), chosen over `rust-imap` and Python `imapclient` on the transport
seam — go-imap's client takes an already-connected socket and runs every
protocol path over reader/writer interfaces, while `rust-imap` keeps its
grammar in a separate crate and `imapclient` is a layer over CPython's
`imaplib`. No pure-Zig IMAP existed to adopt. The three copyright lines MIT
requires are in `NOTICE`; per-file divergences are listed at the bottom of each
ported file.

## Modified UTF-7

Mailbox names travel in the encoding of RFC 3501 §5.1.3 — UTF-7 with `&` as the
shift character and `,` as the 64th base64 character:

```zig
const name = try imap.utf7.decodeAlloc(gpa, "~peter/mail/&U,BTFw-/&ZeVnLIqe-");
defer gpa.free(name);
// name == "~peter/mail/台北/日本語"

const wire = try imap.utf7.encodeAlloc(gpa, name);
defer gpa.free(wire);
// wire is byte-identical to the input above
```

RFC 9051 servers may send raw UTF-8 instead; the decoder passes it through, so
one call handles both server generations.

The encoding is **canonical**, and the decoder enforces it: no padding, no
base64 run encoding a character that could have been written directly, no two
runs back to back, no unpaired surrogate, no CR/LF inside a run. That matters
because mailbox names are compared as byte strings — a second spelling of one
name is a bug waiting to happen, not a tolerance.

## The wire grammar

`wire.Decoder` reads RFC 9051 §9 primitives from a `std.Io.Reader` — atoms,
quoted strings, literals, `NIL`, numbers, parenthesised lists, mailbox names:

```zig
var r = std.Io.Reader.fixed("* 172 EXISTS\r\n");
var d = imap.wire.Decoder.init(arena, &r, .{});

try d.expect('*');
try d.expectSp();
const n = try d.expectNumber();       // 172
try d.expectSp();
const kind = try d.expectAtom();      // "EXISTS"
try d.expectCrlf();
```

Two decisions in here are load-bearing rather than stylistic:

- **A literal's length arrives from the network and is used to allocate**, so
  `Options.max_literal` is checked *before* the allocation. That is the exact
  shape of three real bugs found elsewhere in this repo.
- **A server may not send `{123+}`.** The non-synchronising literal is a
  client-to-server construct (RFC 7888); go-imap accepts it only when decoding
  as a server, and so this rejects it outright rather than being liberal about
  a frame no legitimate peer produces.

It also carries go-imap's tolerances for what servers actually send, each with
a test naming the behaviour: a space immediately before CRLF is trailing
whitespace and not a field separator; a missing space before a parenthesised
list is accepted; a lone LF ends a line; `body-fld-octets` of `-1` reads as 0.

## Responses

`response.Reader` turns each line into one of the three shapes a server can
send — a continuation request, a tagged completion, or untagged data:

```zig
var rd = imap.response.Reader.init(arena, &stream, .{});
switch (try rd.next()) {
    .continuation => |text| { … },
    .tagged => |t| { … t.tag, t.status.type, t.status.code … },
    .data => |d| switch (d) {
        .exists => |n| { … },
        .flags => |f| { … },
        .status => |s| { … },
        .other => |o| { … o.kind, o.rest … },   // still in sync
        else => {},
    },
}
```

**Anything unparsed stays in sync rather than failing.** An untagged kind this
module does not implement yet comes back as `.other` with the line's remainder
verbatim, and an unknown `[RESPONSE-CODE]` is skipped to its closing bracket —
so a server extension cannot desynchronise the stream or fail a command.

The tolerances are ported deliberately, each named by a test: a status response
with **no text at all** (RFC 9051 requires one; servers omit it — go-imap
issues 500 and 502), and a **flag list that opens with a space** (go-imap PR
633). Capability names are upper-cased except `IMAP4rev1` and `IMAP4rev2`,
the only two spelled in mixed case.

## Commands

`command.Encoder` writes the command side, and `Tagger` hands out tags that
never repeat on a connection so a late response can always be matched:

```zig
var e = imap.command.Encoder.init(gpa, &out, .{});
try e.login(try tagger.next(gpa), "user", "pass");
try e.select(try tagger.next(gpa), "INBOX", false);
```

The interesting decision is **where a literal forces the protocol to become
synchronous**. `astring` permits quoting, so the encoder quotes — unless the
value contains NUL, CR or LF, exceeds 4096 bytes, or carries raw UTF-8 without
`UTF8=ACCEPT`. Then it must be a literal, and a plain literal means writing
`{n}` and *waiting for the server's `+`* before the payload.

That wait belongs to the session, so the encoder does not fake it: it returns
`error.SyncLiteralRequired`. With `LITERAL+` (any size) or `LITERAL-` (up to
4096) it emits `{n+}` and no wait is needed. A password containing a newline is
therefore either a clean literal or an explicit error — never a command line
the server will misread.

Mailbox names go out as modified UTF-7, except `INBOX`, which is a bare atom in
any case. Under `UTF8=ACCEPT` the name stays UTF-8 — but `&` is still escaped
to `&-`, because it introduces a shift sequence even there and leaving it bare
would silently rename the mailbox.

## The session

```zig
var c = imap.Client.init(gpa, &reader, &writer, .{});
defer c.deinit();

_ = try c.greet();                     // capabilities often arrive here
_ = try c.startTls();                  // then handshake on your own transport
_ = try c.tlsEstablished(&tls_reader, &tls_writer);
_ = try c.login("user", "pass");
_ = try c.select("INBOX", false);
// c.mailbox.exists / .flags / .permanent_flags / .uid_validity / .uid_next
try c.logout();
```

Three things live here because nothing below can own them:

- **Untagged data arrives unsolicited.** `* 23 EXISTS` can land between any two
  responses, so "read the reply" is really "read until my tag comes back,
  handling everything else on the way". Anything the session does not consume
  goes to the `on_unilateral` observer.
- **The synchronising literal is a handshake.** Write `{n}`, wait for `+`, then
  the payload — and untagged data may arrive *before* the `+`, which a client
  that treats the next line as the continuation gets wrong. Advertising
  `LITERAL+` removes the round trip; the session sets the encoder's policy from
  the capabilities the server actually sent.
- **STARTTLS is a state transition, not a command.** This module speaks no TLS,
  so the upgrade is split: `startTls` writes the command, reads its completion,
  and **refuses** the upgrade if anything is already buffered from the server
  (`error.PlaintextInjection` — the 2011 STARTTLS response-injection class, the
  same guard `smtp` has). The caller then performs the handshake on its own
  transport and hands the upgraded streams to `tlsEstablished`, which discards
  the pre-TLS capability list per RFC 9051 §6.2.1 — **and** the encoder policy
  (`LITERAL+`/`LITERAL-`/`UTF8=ACCEPT`) that was derived from it — before
  re-running `CAPABILITY` over the encrypted link.
- **The password is not handed to just anyone.** `login` refuses with
  `error.LoginDisabled` when the server advertised `LOGINDISABLED` (RFC 9051
  §6.2.3 says a client MUST NOT issue `LOGIN` then), and with
  `error.PlaintextAuth` on a link this client has not seen encrypted unless
  `Options.allow_plaintext_auth` is set — same default, and the same reasoning,
  as `smtp`.
- **State gates commands.** `LOGIN` after authentication is a local error, not
  a password sent into a session that cannot use it.

A failed `SELECT` leaves **no** mailbox selected (RFC 9051 §6.3.2) — including
when the server emitted untagged data before refusing, which is what makes
clearing state on failure load-bearing rather than redundant.

## FETCH, SEARCH, IDLE

```zig
var out = std.heap.ArenaAllocator.init(gpa);   // results outlive the response lines
defer out.deinit();

const msgs = try c.fetchMessages(out.allocator(), "1:*", false, .{
    .uid = true, .flags = true, .envelope = true, .body_structure = true,
});

const hits = try c.searchMessages(out.allocator(), true, .{ .count = true },
    &.{ .since = "1-Feb-1994", .flag = &.{"\\Flagged"} });

try c.idleBegin();
const data = try c.idlePoll();     // unsolicited EXISTS / EXPUNGE / FETCH
_ = try c.idleDone();
```

**`BODYSTRUCTURE` recurses and the input is remote**, so nesting is bounded by
`fetch.Options.max_depth`, checked on the way *in* rather than discovered when
the stack runs out. A `message/rfc822` part carries a whole nested message —
envelope, structure and line count — so the recursion is real, not theoretical.

**`BODY.PEEK[…]` is the default.** Fetching a body with plain `BODY[…]` sets
`\Seen`, so the naive spelling marks mail as read behind the user's back.

**`SEARCH` has two reply shapes and both are parsed.** IMAP4rev1 answers `*
SEARCH 2 84 882` — no tag, no aggregates. IMAP4rev2 answers `* ESEARCH (TAG
"A282") MIN 2 COUNT 3`. The `ALL` set is kept **verbatim**: expanding
`1:4294967295` into numbers is how a client runs out of memory.

**`IDLE` is explicit.** `idleBegin` waits for the server's continuation before
reporting success, and no other command may be sent until `idleDone`. The
caller owns the timing — RFC 2177 wants IDLE re-issued within 29 minutes, and
this client runs no timer because it owns no thread.

FETCH and SEARCH results are allocated from an allocator **you** pass, not the
session's per-line arena, because they span many response lines.

## What the live peer found

The offline suite was 107 tests green. The first run against a real server
failed — and the cause was a design gap no scripted peer would have shown: the
synchronising-literal handshake had been wired into `LOGIN` **only**. A
perfectly legal `SEARCH BODY "a\r\nb"`, which can travel no other way, came
back as `error.SyncLiteralRequired` instead of doing the handshake.

The fix moved the wait behind a seam in the encoder (`Options.on_sync`) that
the session installs, so every command gets it rather than one. Arming happens
in each command entry rather than in the caller: a forgotten call would
silently lose the handshake, which is the bug the seam exists to prevent.

## Tests

`zig build test-imap`. Anchoring is stated per tier (CONVENTIONS §5):

- **Tier 1** — the worked example published in RFC 3501 §5.1.3, asserted in
  both directions, plus the alphabet distinction from RFC 2152 UTF-7.
- **Tier 1** — for the grammar, field-by-field parses of the response shapes
  printed in RFC 9051 (`* 172 EXISTS`, the `FLAGS` list, a `{n}` literal).
- **Tier 2** — the vector table from go-imap's own `internal/utf7`
  `decoder_test.go`, including all 25 rejection cases. This is the source that
  was ported, so it catches transcription slips and **cannot** catch a shared
  misreading of the RFC; it is not counted as an external anchor.

Every rule that could be quietly dropped has a test proven to fail when it is:
four in the UTF-7 codec (alphabet, canonical-run check, null shift, surrogate
arithmetic), six in the grammar (non-sync literal rejection, the literal cap
firing before allocation, the trailing-space rule, the depth guard, `]` in
astrings, INBOX case-folding), eight in the response reader (the `\\*`
flag-perm wildcard, the capability exceptions, both server tolerances, the
unknown-code skip, tagged PREAUTH/BYE rejection, the numeric prefix, and
keeping an unknown line's remainder), eight in the encoder (each rule that
decides quoted-vs-literal, `&` escaping, the INBOX atom, quote escaping, the
flag grammar, and `LITERAL-`'s ceiling), eight in the session (tag
matching, the continuation wait, the state gate, capability-driven literal
policy, BYE handling, response-code absorption, and both halves of the
failed-SELECT cleanup), and ten across part 2 (the BODYSTRUCTURE depth guard,
the 7bit default, `text/*` line counts, parameter-key folding, `BODY.PEEK`,
system-flag search keys, the `ALL` fallback, the ESEARCH correlator, the IDLE
state gate, and FETCH results being allocated where they can outlive the line). Verified by planting each defect and
watching the suite go red, then confirming the revert byte-for-byte. A planted
defect that fails to COMPILE proves nothing, so six of those were rewritten
until they built and then failed — and one of them turned out to pass, which
exposed a test with no teeth: clearing mailbox state on a failed SELECT was
already covered by clearing it on entry, so the test could not tell the two
apart. The transcript now emits untagged data before the refusal, which only
the failure path can clean up.
