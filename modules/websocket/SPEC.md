# websocket — spec

Design + threat notes for auditors. Usage: see ./README.md. Attribution/provenance: see this module's README "Provenance" note — clean-room, so there is deliberately no root `/NOTICE` entry to point at (root `NOTICE` §0).

## Design & invariants

Submodules: `handshake` (§1.3/§4 opening handshake), `frame` (§5 wire codec), `connection` (a
small optional per-connection state machine on top of `frame`). Transport-agnostic throughout —
this module never opens a socket or touches TLS; it operates on caller-owned byte buffers and
`std.Io.Writer`s, so the P2 HTTPS server drops it onto its already-terminated TLS stream (same
seam pattern as `http`'s `serveStream`/`h2_server.serveStream`).

**Handshake.** `handshake.acceptHandshake` validates a parsed `http.h1.RequestHead` against §4.2.1:
GET, HTTP/1.1+, `Upgrade: websocket`, `Connection: Upgrade`, `Sec-WebSocket-Version: 13`, and a
`Sec-WebSocket-Key` that decodes to exactly 16 bytes. `computeAcceptKey` is
`base64(SHA1(key ++ "258EAFA5-E914-47DA-95CA-C5AB0DC85B11"))` (§1.3) — hashes the raw base64 *key
string*, not its decoded bytes, per spec. Subprotocol negotiation (`Sec-WebSocket-Protocol`) picks
the first client-offered token (client preference order) present in the caller's allowed set;
absent that header or an empty allowed set, no subprotocol is negotiated. Client side mirrors this:
`generateKey` takes a caller-supplied `std.Random` (never `std.crypto.random` — this module has no
opinion on the CSPRNG source, matching the rest of zig-libs' caller-supplied-randomness
convention), and `verifyResponse` recomputes the expected accept value and rejects on any mismatch
— this is the handshake's core integrity check (RFC 6455 §4.1 point 9): it catches a transparent
cache, proxy, or non-WebSocket-aware server that answered `101` without actually understanding the
protocol.

**Frame layer.** `frame.parseFrame(buf: []u8, role, max_frame_size)` is a streaming, allocation-free
parser: `buf` is mutable because a masked payload is unmasked **in-place**, so `Frame.payload`
always aliases plaintext application data regardless of whether the wire frame was masked. Three
possible outcomes: a decoded `Frame`, `.need_more` (the buffer doesn't yet hold a complete frame —
not an error, the normal "read more and retry" signal for a streaming transport), or a typed
`FrameError`. `writeFrame` is the inverse, serializing to a `std.Io.Writer`; masking on the write
side is never inferred — the caller passes `mask_key: ?[4]u8` explicitly (null = unmasked, a key =
masked-with-that-key), which is also what makes the RFC §5.7 vectors byte-exact-reproducible in
tests (the masking key in those vectors is fixed, not random).

**Connection.** `connection.Connection` reassembles a fragmented message (§5.4: start frame
text/binary with `FIN=0`, zero or more `continuation` frames, a final `continuation` with `FIN=1`)
into a caller-owned `message_buf`; that buffer's length **is** the aggregate max-message-size cap
(a fragmented message can exceed any single frame's `max_frame_size` even with every individual
frame compliant, so this is a separate bound from the per-frame one). The cap applies to an
**unfragmented** message as well, even though such a message is never copied into `message_buf`:
the buffer's *length* is the caller's stated memory budget for one message, and a bound that a
one-frame message could walk past would not be a budget at all. Control frames (ping/pong/
close) are dispatched before fragmentation state is even consulted, which is what makes
interleaving them mid-fragmentation "just work" — no special-casing needed. UTF-8 validation
(§5.6, required for `text`/`.continuation`-reassembled-as-text) runs against the **complete**
message: a single unfragmented frame validates directly against its payload with no copy; a
reassembled one validates `message_buf[0..message_len]` once the final fragment arrives. This is
correct per the RFC's actual requirement (the *message* must be valid UTF-8) and is exercised by a
test that deliberately splits a multi-byte codepoint across two fragments — the split bytes are
*not* independently valid UTF-8, only the reassembled whole is, proving the deferred-validation
design doesn't false-positive on legitimate fragmentation.

## Threat model / out of scope

This module parses untrusted network input end to end (the handshake request/response headers and
every frame byte) — no panics on malformed input anywhere; every rejection is a typed error.

- **Masking direction (§5.3) is the security-critical invariant**, not a nicety: a client that
  fails to mask makes its traffic indistinguishable from a raw TCP/HTTP stream to any
  packet-inspecting intermediary sitting between it and the server, which is the basis of several
  cross-protocol attacks documented alongside RFC 6455 (e.g. smuggling non-WebSocket traffic past a
  cache that thinks it's looking at opaque masked bytes). `parseFrame` enforces the *inbound*
  direction unconditionally from its `role` parameter: a server-role parser rejects any unmasked
  frame (`error.UnmaskedClientFrame`, close 1002), a client-role parser rejects any masked one
  (`error.MaskedServerFrame`, close 1002). There is no configuration flag to disable this.
- **RSV bits / reserved opcodes:** this module negotiates no extensions, so any RSV bit set is
  immediately `error.ReservedRsvBits` (close 1002) — never silently ignored, which matters because
  silently ignoring an RSV bit is exactly how an extension-confusion attack would look. Opcodes
  0x3-0x7 and 0xB-0xF → `error.ReservedOpcode` (close 1002).
- **Size caps (DoS bound):** `max_frame_size` is checked as soon as the length prefix is decoded —
  *before* the parser waits for (or would need to buffer) the payload bytes, so an attacker cannot
  force buffering of an oversized frame merely by claiming a huge length (`error.FrameTooLarge`,
  close 1009). `Connection.message_buf.len` bounds the aggregate reassembled-message size
  (`error.MessageTooLarge`, close 1009) — this is the fragmentation-amplification bound: many
  small, individually-compliant frames could otherwise build an unbounded message.
- **Control-frame constraints (§5.5):** `FIN=0` on close/ping/pong → `error.FragmentedControlFrame`
  (close 1002); payload over 125 bytes → `error.ControlFrameTooLarge` (close 1002). Both checked
  before any payload bytes are required to be present.
- **Non-minimal length encoding:** a 126/127-prefixed frame whose extended length field encodes a
  value the shorter form could have carried, or a 64-bit length with the MSB set (RFC requires it
  0), is `error.InvalidPayloadLength` (close 1002) — not a spec nicety, a classic length-encoding
  confusion vector (parsers that accept multiple encodings of the same length disagree with each
  other about frame boundaries, which is a request-smuggling-shaped bug in this protocol too).
- **UTF-8:** invalid UTF-8 in a text message (`error.InvalidUtf8`, close 1007) or a close-frame
  reason (same error) is rejected; binary messages are never validated.
- **Fragmentation sequencing:** a continuation frame with no message in progress, or a new
  text/binary frame while one is already in progress, is `error.InvalidFragmentation` (close 1002).
- **Close-code validation (RFC 6455 §7.4.1):** a close frame's status code is checked against the
  ranges the RFC actually permits on the wire — `1000-1003`, `1007-1011`, `3000-4999` — before its
  reason is even read. Codes `0-999` (unused), `1004`/`1005`/`1006`/`1015` (each specified "MUST NOT
  be set as a status code in a Close frame by an endpoint" — they name conditions with no
  corresponding close frame, not values a peer may legitimately send) and the unassigned
  `1012-2999`/`5000+` ranges are `error.InvalidCloseCode` (close 1002). This is Autobahn|Testsuite's
  7.9.x class.
- **Data frames after `close_received`:** RFC 6455 §1.4 — "after receiving a control frame
  indicating the connection should be closed, a peer discards any further data received." A
  text/binary/continuation frame arriving once `Connection.close_received` is set is
  `error.DataAfterClose` (close 1002) rather than being reassembled or delivered as a message; the
  peer's own close/ping/pong frames are unaffected.
- **Every error maps to an RFC close code** via `frame.closeCode(err: anyerror) u16` (1002/1007/
  1009 per the table above; everything else defaults to 1002) so the caller doesn't need its own
  mapping switch to build the failing close frame.
- **Out of scope:** TLS/TCP transport (the caller's — see `http`'s BYO-TLS seam for the pattern),
  **permessage-deflate (RFC 7692)** — no extension negotiation of any kind is implemented, so
  `Sec-WebSocket-Extensions` is never read or written and any RSV bit is always rejected (deferred:
  a real perf win for text-heavy workloads, but a distinct, security-sensitive feature — DEFLATE
  decompression bombs are a known WebSocket DoS vector — that deserves its own audited pass rather
  than a token-budget afterthought here), origin-header policy / CSRF-via-WebSocket-handshake
  checks (the caller's — this module surfaces the `Origin` header like any other but doesn't police
  it, since the correct policy is application-specific), and automatic ping/keepalive scheduling
  (the caller drives the event loop; `frame.pongFor` is the one building block provided).

## Verification

`zig build test-websocket` — 62 offline tests, green in Debug + ReleaseFast.
- **RFC 6455 vector-backed (byte-exact):** the §1.3 handshake worked example
  (`dGhlIHNhbXBsZSBub25jZQ==` → `s3pPLMBiTxaQ9kYGzzhZRbK+xOo=`, both as a standalone
  `computeAcceptKey` check and as a full `acceptHandshake` + `writeResponse` round trip over the
  verbatim §1.3 example request/response headers); the §5.7 frame examples — unmasked text
  "Hello", masked text "Hello" (exact mask key + masked bytes), fragmented "Hel"+"lo", unmasked
  ping "Hello", unmasked pong "Hello", 256-byte binary (16-bit length form), 64KiB binary (64-bit
  length form) — each both parsed from and re-serialized to the literal RFC bytes.
- **Constructed (Autobahn-style) teeth, each with a positive control alongside it:** unmasked
  client frame rejected / masked server frame rejected, RSV-bit rejection, reserved-opcode
  rejection, oversized-frame rejection (checked before the payload is even available), fragmented-
  control-frame rejection, oversized-control-payload rejection, non-minimal 16-bit and 64-bit
  length encodings rejected, 64-bit length with MSB set rejected, masking round-trip
  (`applyMask` is its own inverse), close-body encode/decode round trip + malformed cases (1-byte
  payload, invalid-UTF-8 reason), handshake rejections (non-GET, missing Upgrade/Connection/
  version, missing/malformed key, unoffered-subprotocol echo, accept mismatch, non-101 status),
  `Connection` fragmentation-sequencing errors (orphan continuation, new frame before finishing
  the previous one), aggregate message-size cap on **both** the reassembled and the unfragmented
  path (the latter with an at-exactly-the-cap positive control that also asserts the payload is
  still borrowed from the read buffer), single-frame and reassembled invalid-UTF-8
  rejection, the split-codepoint-across-fragments positive control, and control-frame interleaving
  mid-fragmentation.
- **External anchor (Markus Kuhn's UTF-8 stress-test corpus, frozen 2026-08-08):** a ~45-vector
  subset of `http://www.cl.cam.ac.uk/~mgk25/ucs/examples/UTF-8-test.txt`, transcribed from the
  installed (but unrunnable — see below) `autobahntestsuite` package's own
  `case/case6_x_x.py`, each wrapped in a real single-frame text message and driven through
  `Connection.receive` (`connection.zig`, "external anchor: Autobahn|Testsuite's frozen UTF-8
  stress-test corpus"). This is independent of both this module's own understanding and of RFC
  6455's prose (RFC 6455 §5.6 only requires "valid UTF-8 per RFC 3629"; it enumerates none of the
  overlong-encoding, lonely-continuation-byte or surrogate-half cases the corpus covers), so it is
  a genuine third-party oracle, not a restatement of the spec in test form. See "External-anchor
  investigation" below for how it was obtained and what remains unanchored.
- **External anchor (three foreign WebSocket peers, executed and frozen 2026-08-09):**
  `connection.zig`'s `foreign_peer_corpus` — 54 masked client→server byte strings, each put in
  front of **python-websockets 15.0.1**, **github.com/coder/websocket v1.8.15** and
  **github.com/gorilla/websocket v1.5.3**, with what each of the three actually did recorded next
  to it. 24 rows all three accepted, 23 all three rejected (with the close code they agreed on),
  7 are divergences or splits, individually documented. This is what closes the §7.9 gap the
  2026-08-08 investigation left open — see "Foreign-peer corpus" below.

### External-anchor investigation: Autobahn|Testsuite (2026-08-08)

F5 asked for a real `Autobahn|Testsuite` run, frozen the way `netconf` froze its live server's
bytes. That turned out not to be obtainable as a *running* suite on this host, but part of it was
obtainable as *data*, which changes the outcome from a flat gap to a partial anchor plus one
precisely-scoped remaining gap.

**`wstest` is broken here, confirmed directly, nothing patched or installed.**
`wstest --help` (and any other invocation) fails immediately:
```
File ".../autobahntestsuite/__init__.py", line 19, in <module>
    from _version import __version__
ModuleNotFoundError: No module named '_version'
```
`from _version import __version__` is an implicit relative import — valid in Python 2, removed by
[PEP 328](https://peps.python.org/pep-0328/) in Python 3. This host runs Python 3.14;
`autobahntestsuite` (last released 2013) is Python-2-era and unmaintained upstream. Per this
campaign's constraints, it was not patched and nothing was installed to work around it.

**The case *definitions* are data, not runner logic, and some of them are obtainable without
`wstest` running at all.** `autobahntestsuite/case/*.py` is plain, readable Python source — the
package cannot be *imported* (every submodule transitively hits the same broken `__init__.py`
and separately uses its own Python-2-era implicit relative imports, e.g. `from case import Case`),
but it can be *read as text*, which is all a byte-exact freeze needs. Two kinds of content live
there, with two different verdicts:

- **§6 (UTF-8 validation): a real external anchor, frozen above.** `case6_x_x.py` embeds Markus
  Kuhn's UTF-8 decoder stress test verbatim, with an explicit citation to its origin in the source
  comment. That corpus is independently authored, predates this module and this repository, and is
  not something reading RFC 6455 would reproduce (see the Verification bullet above for why). A
  representative subset covering every category the corpus distinguishes — boundary lengths,
  unexpected continuation bytes, lonely start bytes, truncated sequences, three different overlong
  encodings, single and paired UTF-16 surrogates, and the non-character code points RFC 3629 still
  permits — was transcribed into `connection.zig` and is asserted through the real `Connection`
  message path.
- **§7.9 (close-code validation): not a genuine external anchor, so none was manufactured.**
  `case7_9_X.py` (the section covering F2's close-code gap) turns out to carry no data beyond what
  RFC 6455 §7.4.1 already states: its test list is `[0, 999, 1004, 1005, 1006, 1016, 1100, 2000,
  2999]` — samples from the RFC's own reserved/unassigned close-code ranges — and its expectation
  is "clean close with protocol error code or drop TCP", i.e. RFC 6455 §7.4.1's MUST-fail-with-1002
  rule restated in Python. Freezing these values and asserting this module rejects them would be
  indistinguishable from writing a test against our own reading of RFC 6455 — exactly the
  fabricated-anchor shape this repo has flagged before. **That refusal stands and was correct.**
  What was missing was not better case data but a different *kind* of oracle — see below.

### Foreign-peer corpus: three implementations, executed (2026-08-09)

The §7.9 gap above is now closed, not by resurrecting `wstest` (which stays dead) but by
replacing the suite with **real peers**. A conformance suite reports pass/fail against its
author's interpretation; a real peer emits *bytes*, and bytes are what freeze.

**What was run.** 54 masked client→server frames (mask key `37 fa 21 3d`, the RFC 6455 §5.7 key)
covering valid traffic, header-level violations, length-form boundaries, and every close-code
class, were put in front of three independently authored implementations in two languages:

| Implementation | Licence | How it was driven |
|---|---|---|
| python-websockets 15.0.1 | BSD-3-Clause | its sans-io `ServerProtocol` state machine, fed directly |
| github.com/coder/websocket v1.8.15 | ISC | real server on loopback; its close frame read off a raw socket |
| github.com/gorilla/websocket v1.5.3 | BSD-2-Clause | likewise |

Nobody's source was read for a conclusion; all three were *executed* and their behaviour
recorded. The distinction from the refused §7.9 case data is the whole point — this is an oracle
that can disagree with us, and on its first run it did.

**What it caught immediately: close codes 1012-1014 were wrongly rejected.** `isValidCloseCode`
permitted `1000-1003, 1007-1011, 3000-4999`, which is exactly what RFC 6455 §7.4.1's own text
enumerates — and is wrong. §7.4.2/§11.7 make the IANA *WebSocket Close Code Number Registry* the
authority for the 1000-2999 range, and that registry has since assigned **1012 Service Restart,
1013 Try Again Later, 1014 Bad Gateway**. All three peers accept 1012 and 1013; two of the three
accept 1014. The module now accepts 1012-1014 and still rejects 1015 and 1016-2999, which all
three peers also reject. The pre-existing self-authored close-code tests were green throughout —
they asserted the same misreading, because they were written from the same paragraph.

**Divergences, kept rather than smoothed over.** Seven rows do not produce a clean shared verdict
and are recorded as such instead of being dropped:

- **Non-minimal length encodings (3 rows).** RFC 6455 §5.2 requires "the minimal number of bytes
  MUST be used to encode the length". *None of the three enforces it* — a 126/127 form carrying a
  value the shorter form could hold is accepted by all of them. This module rejects it
  (`InvalidPayloadLength`, close 1002) and keeps doing so; the divergence is pinned so the choice
  cannot drift silently.
- **UTF-8 validation on receive (4 rows).** RFC 6455 §8.1 requires failing an invalid-UTF-8 text
  message with close 1007. *None of the three validates UTF-8 at this layer* — invalid text
  payloads pass through all of them. This is precisely why Autobahn has a §6 section at all, and
  why the Kuhn corpus above, not these peers, is what carries that half of the anchor.
- **Genuine three-way splits (4 rows, `.split`).** `close_code_1014` (gorilla rejects, the other
  two accept), `close_body_1byte` (gorilla treats a 1-byte body as a no-code close; the other two
  reject 1002), `close_reason_bad_utf8` (python 1007 — matching this module; gorilla 1002; coder
  accepts), and a 64-bit length with the MSB set (both Go peers drop the TCP connection with no
  close frame; python's reader simply waits for the 2^63 bytes). No majority verdict was
  manufactured for these; the three answers are recorded and *this module's* answer is pinned.

**Offline and non-skipping.** The capture scripts live outside the repository in
`~/.cache/zig-libs-websocket/`; `build.zig.zon` stays empty. All three implementations can be
deleted and the tests are unchanged — they never skip. Licence reasoning is in this module's
`NOTICE`.

**Teeth, demonstrated.** Restoring `isValidCloseCode` to its previous range *together with* the
previous self-authored close-code tests reproduces the module's state before this corpus existed:
`zig build test-websocket` then reports 62/63 passing — every self-authored test green — with the
**only** failure being `close_code_1012: all three peers accepted but we rejected with close 1002`.
The RED comes from the foreign corpus and from nothing else.

## Backlog / deferred

- permessage-deflate (RFC 7692) extension negotiation + DEFLATE framing — see "Out of scope" above.
- No automatic keepalive/ping-interval scheduling — event-loop-specific, left to the caller.
