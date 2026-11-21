# coap

CoAP (RFC 7252) **message codec** — the binary wire format of the Constrained
Application Protocol, the REST-over-UDP protocol used by constrained / IoT
devices. The message layer (C1) is `parse` and `serialize` of a CoAP message
— header, token, **delta-encoded options** and payload; the layers above it
are listed below.

Zero-allocation and transport-agnostic: `parse` fills a caller-provided option
array from a datagram (values borrow the datagram); `serialize` writes a message
into a caller buffer; `encodedLen` sizes it. Wire it to any UDP/DTLS transport.

**Transport security.** Every layer here — codec, reliability, client/server,
block-wise, observe — only ever touches in-memory buffers; the caller owns the
socket. That means the module runs unmodified over plain UDP *or* over a
caller-terminated **DTLS** session (RFC 7252 §9's mandated CoAP transport
security), the same "bring your own transport" seam this repo uses for BYO-TLS
on TCP. **Production CoAP over an untrusted network MUST use that DTLS seam** —
plain UDP is unauthenticated, so a source identity (needed by the Observe
admission hook below) and duplicate suppression (`reliability.Dedup`) are only
as trustworthy as the transport underneath them. See `SPEC.md`'s "Threat model"
for the full reasoning.

```zig
var opts: [16]coap.Option = undefined;
const msg = try coap.parse(datagram, &opts);
// msg.type / msg.code / msg.message_id / msg.token / msg.options / msg.payload

var out: [1152]u8 = undefined;
const n = try coap.serialize(.{
    .type = .confirmable, .code = .get, .message_id = 0x1234,
    .options = &.{ .{ .number = 11, .value = "sensors" } }, // Uri-Path
}, &out);
```

Codes carry their `class()`/`detail()` (`Code.content.class() == 2`), and any
code builds with `Code.init(class, detail)`. Options are value-agnostic in this codec layer —
the typed registry (Uri-Path = 11, Content-Format = 12, …) lives in `coap.options` (below).

- **Role:** util. **Platform:** any. **Deps:** none (std
  only). **Concurrency:** reentrant — no shared state; results borrow the
  caller's buffers.

Provenance: clean-room from RFC 7252 (the Constrained Application Protocol),
an open IETF standard: the §3 message format (header / token / delta-encoded
options / payload), the §5.10 option registry + §5.4.6 class bits + §3.2 uint
value format, the §6 URI ↔ options mapping (with RFC 3986 percent-encoding),
the §4 message layer (§4.2 Confirmable retransmission timers, §4.5 message-ID
deduplication, §4.8 transmission parameters) and the §5 request/response model
(token/message-id correlation §5.3, piggybacked/separate responses §5.2), plus
RFC 7959 (block-wise transfer — Block1/Block2 options) and RFC 7641 (Observe).
No third-party CoAP source (libcoap, aiocoap, Californium, …) consulted or
copied. DATA: `src/external_goldens.zig` holds datagrams captured once off the wire from independent CoAP implementations run as black-box peers, frozen so the test needs no subprocess. That is observed behaviour on our own exchanges, exempt per root `NOTICE` §0; no upstream test corpus is reproduced.

## Typed options (`coap.options`)

On top of the value-agnostic codec, `coap.options` gives options their meaning
(RFC 7252 §5.10 / §6):

- **Registry + class bits** — named `number.*` (Uri-Path = 11, Content-Format =
  12, …), `content_format.*`, and `isCritical`/`isUnsafe`/`noCacheKey` (§5.4.6).
- **CoAP uint** (§3.2) — `decodeUint`/`encodeUint` (minimal big-endian, no
  leading zeros, empty = 0).
- **Accessors** over a parsed `Message` — `contentFormat`, `accept`, `maxAge`
  (default 60), and the `uriPath` / `uriQuery` segment iterators.
- **URI ↔ options** (§6) — `optionsFromUri("coap://h/a/b?x=1", out, scratch)` → Uri-Host /
  Uri-Port (non-default) / Uri-Path* / Uri-Query* in ascending order (feeds
  `serialize` directly), and `uriFromOptions` back, with RFC 3986
  percent-encoding.

## Reliability (`coap.reliability`)

The RFC 7252 §4 message layer, clock- and transport-agnostic (the caller drives
it with an absolute `now_ms` and its own socket):

- **`Retransmit`** — a just-sent Confirmable message's retransmission schedule:
  exponential backoff from `ACK_TIMEOUT` with a deterministic jitter (§4.2),
  `poll(now_ms)` → `waiting` / `retransmit` / `timed_out`, `ack()`/`onReset()`
  to stop. `MAX_RETRANSMIT` retransmissions then a final wait → failure.
- **`Dedup`** — a bounded, time-windowed set of recently-seen message IDs
  (§4.5) over caller storage; `check(mid, now_ms)` → `fresh` / `duplicate`
  (window from first sight, soonest-to-expire eviction when full). Both the
  table size (the caller's storage slice) and the remembered-duration
  (`lifetime_ms`, an `init` argument) are caller-configurable — size them for
  your expected authenticated-peer/exchange count. **`Dedup` is a reliability
  control, not a replay-security control**: on plain UDP an attacker can flood
  the window with distinct message IDs to evict a legitimate exchange before
  its retransmission window elapses; it becomes a security boundary only once
  the source is authenticated (the DTLS seam above).
- **`emptyAck(mid)` / `reset(mid)`** and the §4.8 `Params` / `exchange_lifetime_ms`.

## Client / server (`coap.client`, `coap.server`)

The §5 request/response endpoints, transport-agnostic (the caller owns the UDP
socket and drives a `reliability.Retransmit`):

- **`client.Client`** — `buildRequest(method, uri, .{payload, content_format,
  accept, confirmable}, …)` turns a URI into a sorted-option datagram + an
  `Exchange` (fresh message id + token). `Exchange.match(msg)` correlates a
  reply: `piggybacked` / `separate` / `empty_ack` / `reset` / `unrelated`
  (§5.3.2, by token + message id).
- **`server`** — `isRequest(msg)` gates routing; `piggyback(req, code, opts,
  payload)` builds the ACK-carried response, `ackOnly(req)` the bare ACK, and
  `Server.separate(...)` a fresh-id CON/NON response (§5.2). Route with
  `options.uriPath`, dedup with `reliability.Dedup`.

## Block-wise transfer (`coap.block`)

RFC 7959 — moving a payload larger than one datagram in numbered blocks (C6),
same caller-driven, borrow-the-buffer style:

- **`Block`** — the Block1 (option 27) / Block2 (option 23) value codec: the
  packed `NUM : M : SZX` field, `encode`/`decode` (minimal 0..3-byte value, no
  leading zero bytes), `size()` = `2^(SZX+4)` (16 … 1024).
- **`split(payload, szx, num)`** — carve block `num` out of a full payload, with
  the `more` flag set at the boundary.
- **`Assembler`** — reassemble arriving blocks into a caller buffer (written at
  `num * blockSize`), `isComplete()` once the final (`M==0`) block lands — the
  `Dedup`-style caller-storage pattern.
- Also: response codes `2.31 Continue` / `4.08 Request Entity Incomplete` and the
  `block1` / `block2` / `size2` option numbers.

The assembler tolerates a constant block size only (see *Not provided* below).

## Observe (`coap.observe`)

RFC 7641 — a client subscribes with an `Observe` option (number 6) and the
server pushes a notification on each change (C7):

- **`Registry`** — the server's `(token, resource) → last sequence` table over
  caller storage (`Dedup`-style bounded array + FIFO eviction): `register`,
  `notify` (freshness-checked), `cancel`, `count`.
- **`Sequence`** — the monotonic 24-bit notification-sequence generator, and
  **`isNewer`** — the RFC 1982 "lollipop" comparison (accept newer, reject
  stale/out-of-order), plus `encodeValue`/`decodeValue` for the option.
- **Server push reuses `server.Server.separate` unchanged**: a notification is a
  separate response echoing the observed token with an `Observe` option added —
  no fresh request. A CON notification that exhausts `reliability.Retransmit`
  (`.timed_out`) or is answered with a Reset cancels the subscription (caller
  loop glue; `reliability.zig` is untouched).
- **Notification budget (`Registry.notificationType`, `acknowledged`)** — RFC
  7641 §7: without client authentication, non-confirmable notifications MUST
  be interspersed with confirmable ones. Ask `notificationType` before each
  notification: after `max_non_between_acks` NONs (default 5) it answers
  `.confirmable` until the client's ACK is reported, and it also forces a CON
  every 24 hours (§4.5). `max_non_between_acks = null` turns the budget off —
  only for an authenticated (DTLS) client. Record each CON notification's
  Message ID with `confirmableSent` and report an ACK with
  `acknowledged(tok, resource, mid, now_ms)`: it resets the budget only for the
  outstanding id. Seed `Server.init` from a CSPRNG: an empty ACK carries no
  token, so a predictable notification id is all a spoofer needs to forge one.
- **Admission (`Registry.tryRegister`, `AdmitFn`)** — on plain UDP, anyone can
  send an Observe registration, and unconditional FIFO eviction lets an
  attacker evict legitimate subscribers by registering enough new ones. Use
  `tryRegister(source_id, tok, resource, seq, now_ms)` instead of `register` on an
  untrusted transport: it consults an optional `admit_fn`/`admit_ctx` hook
  (`?*anyopaque` ctx, function pointer, no allocation/closures) and an optional
  per-`source_id` cap (`max_per_source`) *before* touching the table, so a
  rejected registration never evicts an existing one. `source_id` is the
  caller's opaque peer identity — make it meaningful by deriving it from an
  authenticated DTLS session (the seam above); a hook keyed off the
  unauthenticated UDP source address isn't a real mitigation. `register`
  itself is unchanged and still admits unconditionally, for callers that gate
  admission themselves.

## Resources, link-format and RFC extras

- **`coap.linkformat`** (RFC 6690) — `Writer` appends links to a caller buffer
  (`link`, and `resource` with the typed `Params`), `Parser` validates and
  iterates a link-format document, `Filter` implements the §4.1 query filter.
- **`coap.resource`** — a `Registry` over caller storage routes a request by
  Uri-Path to a `Handler` (method mask GET/POST/PUT/DELETE/FETCH/PATCH/iPATCH),
  answers 4.04 / 4.05, serves `/.well-known/core` (filtered discovery; a
  multicast request with no match is not answered) and applies RFC 7967
  No-Response; `Registry.dispatch` returns the piggybacked response.
- **Named RFC extras** — the RFC 8132 codes (`Code.fetch/patch/ipatch`), a few
  more named codes and content formats, the RFC 9175 Echo / Request-Tag
  options with typed accessors, RFC 7967 No-Response, and RFC 8974 extended
  token lengths (`parseExtended` / `serializeExtended` / `encodedLenExtended`,
  opt-in: plain `parse`/`serialize` refuse TKL 9..15).

## More RFC pieces

- **Block-wise answers and discovery** — `Resource.blockwise` serves a handler's
  payload in Block2 blocks, and `/.well-known/core` goes out block-wise when it
  exceeds `DispatchOptions.max_payload` (give `DispatchOptions.scratch` to
  generate it per block, so it may be larger than `doc_buf`). `Resource.observe_hook`
  and `Reply.observe/block1/block2/size2` wire Observe and Block options into
  the dispatcher.
- **Combined Block1+Block2 and size renegotiation** — `block.Transfer` is the
  client state machine of one exchange with a blocked request body and a blocked
  response; `block.Sender` and `Assembler` follow a smaller SZX mid-transfer.
- **`coap.tcp`** — RFC 8323 framing for TCP/TLS (`serialize`, `decode`,
  `frameLen`) and signaling (`Csm`, Ping/Pong, Release, Abort, `Session`). TLS
  is the caller's seam.
- **`coap.echo`** — RFC 9175 server logic: `EchoVerifier` / `challenge` (the Echo
  freshness challenge, stateless) and `RequestTagTracker` (block-wise request
  operations told apart by Request-Tag).
- **`coap.multicast`** — RFC 7252 §8: Non-confirmable requests, Leisure and the
  random answer delay, error suppression, the "All CoAP Nodes" addresses.

## Not provided

CoAP over WebSockets (RFC 8323 §4) and RFC 7390 group-management resources are
not implemented; `SPEC.md` "What is deliberately not done" gives the reasons.
Congestion control beyond the §4.8 transmission parameters is out of scope
(`SPEC.md` "Threat model").

## Verify

`scripts/modtest coap` runs the offline tests: the codec error matrix and golden
bytes, options and URI mapping, reliability, client/server round trips,
block-wise and Observe end to end, link-format and dispatch goldens from the
RFC examples, and real `aiocoap` datagrams (`src/external_goldens.zig`).
Fuzz harnesses run under `COAP_FUZZ`; see `SPEC.md` "Verification".
