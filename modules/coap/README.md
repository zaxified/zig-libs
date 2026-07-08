# coap

CoAP (RFC 7252) **message codec** — the binary wire format of the Constrained
Application Protocol, the REST-over-UDP protocol used by constrained / IoT
devices. This is the message layer (C1): `parse` and `serialize` a CoAP message
— header, token, **delta-encoded options** and payload.

Zero-allocation and transport-agnostic: `parse` fills a caller-provided option
array from a datagram (values borrow the datagram); `serialize` writes a message
into a caller buffer; `encodedLen` sizes it. Wire it to any UDP/DTLS transport.

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
  (window from first sight, soonest-to-expire eviction when full).
- **`emptyAck(mid)` / `reset(mid)`** and the §4.8 `Params` / `exchange_lifetime_ms`.

## Scope

Done: the message codec (C1) + typed options / URI mapping (C2) + the §4
reliability layer (C3). Follow-ups: the client (C4) / server (C5) over a UDP
seam; block-wise transfer (RFC 7959) and Observe (RFC 7641) later.

## Verification

`zig build test-coap` — 35 offline tests. Reliability (9): the retransmit
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
