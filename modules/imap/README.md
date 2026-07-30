# imap

An **IMAP4rev2 (RFC 9051) client** in pure Zig, transport-agnostic: it owns no
socket and speaks no TLS, so it drops onto plain TCP, `std.crypto.tls.Client`,
or a test buffer unchanged — the same seam `smtp` and `dtls` use.

**Status: part 1 of 2, in progress.** Landed: the modified-UTF-7 mailbox-name
codec, the wire grammar (decode side), and the response reader. Next: the
command encoder and the session — `CAPABILITY` / `LOGIN` / `SELECT`. Then
part 2: `FETCH` / `BODYSTRUCTURE` / `SEARCH` / `IDLE`.

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
astrings, INBOX case-folding), and eight in the response reader (the `\\*`
flag-perm wildcard, the capability exceptions, both server tolerances, the
unknown-code skip, tagged PREAUTH/BYE rejection, the numeric prefix, and
keeping an unknown line's remainder). Verified by planting each defect and
watching the suite go red, then confirming the revert byte-for-byte.
