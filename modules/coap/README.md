# coap

CoAP (RFC 7252) **message codec** — the binary wire format of the Constrained
Application Protocol, the REST-over-UDP protocol used by constrained / IoT
devices. This is the message layer (C1): `parse` and `serialize` a CoAP message
— header, token, **delta-encoded options** and payload.

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
code builds with `Code.init(class, detail)`. Options are value-agnostic here —
the typed registry (Uri-Path = 11, Content-Format = 12, …) is the next part.

- **Status:** `gap`. **Role:** util. **Platform:** any. **Deps:** none (std
  only). **Concurrency:** reentrant — no shared state; results borrow the
  caller's buffers.

Provenance: clean-room from RFC 7252 §3 (the CoAP message format: header /
token / delta-encoded options / payload). No third-party CoAP source (libcoap,
aiocoap, Californium, …) consulted or copied.

## Typed options (`coap.options`)

On top of the value-agnostic codec, `coap.options` gives options their meaning
(RFC 7252 §5.10 / §6):

- **Registry + class bits** — named `number.*` (Uri-Path = 11, Content-Format =
  12, …), `content_format.*`, and `isCritical`/`isUnsafe`/`noCacheKey` (§5.4.6).
- **CoAP uint** (§3.2) — `decodeUint`/`encodeUint` (minimal big-endian, no
  leading zeros, empty = 0).
- **Accessors** over a parsed `Message` — `contentFormat`, `accept`, `maxAge`
  (default 60), and the `uriPath` / `uriQuery` segment iterators.
- **URI ↔ options** (§6) — `optionsFromUri("coap://h/a/b?x=1")` → Uri-Host /
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

**Deferred** (documented in `block.zig`, not built): combined Block1+Block2 in a
single exchange (RFC 7959 §3.3), and SZX renegotiation mid-transfer (the
assembler tolerates a constant block size only).

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
- **Admission (`Registry.tryRegister`, `AdmitFn`)** — on plain UDP, anyone can
  send an Observe registration, and unconditional FIFO eviction lets an
  attacker evict legitimate subscribers by registering enough new ones. Use
  `tryRegister(source_id, tok, resource, seq)` instead of `register` on an
  untrusted transport: it consults an optional `admit_fn`/`admit_ctx` hook
  (`?*anyopaque` ctx, function pointer, no allocation/closures) and an optional
  per-`source_id` cap (`max_per_source`) *before* touching the table, so a
  rejected registration never evicts an existing one. `source_id` is the
  caller's opaque peer identity — make it meaningful by deriving it from an
  authenticated DTLS session (the seam above); a hook keyed off the
  unauthenticated UDP source address isn't a real mitigation. `register`
  itself is unchanged and still admits unconditionally, for callers that gate
  admission themselves.

## Scope

Done: the full client/server stack — message codec (C1), typed options / URI
mapping (C2), the §4 reliability layer (C3), the §5 client (C4) / server (C5),
plus block-wise transfer (C6, RFC 7959) and Observe (C7, RFC 7641). Deferred
within C6: combined Block1+Block2 in one exchange (RFC 7959 §3.3) and SZX
renegotiation mid-transfer.

## Verification

`zig build test-coap` — 65 offline tests. Block-wise / Observe (16): the Block
value codec (field packing, SZX sizes, minimal encoding, reserved-SZX / too-long
/ over-large-NUM errors), `split` boundary + `Assembler` completion, and two
end-to-end block transfers (a 3000-byte Block2 GET loop reassembled and compared
byte-for-byte; a Block1 PUT with `2.31 Continue` per non-final block); the
Observe `Sequence` wrap, `isNewer` lollipop comparison, value round-trip, the
`Registry` (freshness-checked notify, FIFO eviction, re-register refresh),
`Registry.tryRegister` admission policy (no-hook/no-cap parity with `register`,
a rejected hook neither registers nor evicts an existing entry, an admitted
source still registers when the table is full, a per-source cap bounds one
source's share without evicting), an end-to-end observe register →
notifications → stale-reject → cancel, and the CON-notification-timeout / RST
cancellation glue. Client/server (7): `buildRequest`
option assembly + counter advance, `Exchange.match` across all five reply
kinds, NON typing, `isRequest` gating, `piggyback`/`ackOnly`/`separate`
builders, and an end-to-end client→server→client round-trip. Reliability (9): the retransmit
schedule (jitter selection, the full 4-retransmit backoff to `timed_out`,
`ack`/`onReset`, custom `max_retransmit`) and the dedup window (fresh/duplicate,
expiry-from-first-sight, independence, full-storage eviction). Codec (7): a hand-built CON GET
datagram round-trips to exact bytes; extended option nibbles across the 13/269
boundaries; payload marker + lone `0xFF`; the full parse/serialize error matrix;
`encodedLen` agreement. Options (19): class bits, `decodeUint`/`encodeUint`
boundaries + no-leading-zeros round-trip, the typed accessors, and
`optionsFromUri`/`uriFromOptions` (host/port/path/query, percent-en/decoding,
coaps, bad-scheme, URI round-trips). Original codec details: a hand-built CON GET datagram with a
token and repeated Uri-Path options round-trips to exact bytes; the extended
option nibble forms across the 13 and 269 boundaries (incl. option number 300 →
`0xE1 0x00 0x1F`); payload marker parse/serialize + a lone `0xFF` → EmptyPayload;
the full parse-error matrix (TooShort / BadVersion / BadTokenLength / Truncated /
BadOption / TooManyOptions) and serialize errors (OptionsNotSorted /
BadTokenLength / BufferTooSmall); `encodedLen` agreement; `Code` helpers. Green
in Debug + ReleaseFast.
