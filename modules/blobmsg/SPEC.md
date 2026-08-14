# blobmsg — spec

OpenWRT ubus wire codec + Linux unix-socket client. Usage: see ./README.md. Attribution/provenance:
see /NOTICE.

## Design & invariants
- **The codec is the security boundary, and it is platform-pure.** `codec.zig` has no I/O, compiles
  on any OS. Big-endian, 4-byte-aligned wire format: `blob_attr` `id_len =
  (EXTENDED<<31)|(id<<24)|len` (len counts the 4-byte header, pad does not); a `blobmsg` is a
  blob_attr with EXTENDED set, `id` = value type, data = `blobmsg_hdr` (BE u16 namelen + name + NUL
  + pad) + value. Every id_len/namelen is validated against the enclosing buffer before any slice is
  formed; scalar sizes are exact (per libubox `blobmsg_check_attr`); each walk step advances ≥4
  bytes; JSON decode caps nesting at `max_depth` (64). Malformed input →
  `error.Truncated`/`BadLength`/`TooDeep`, never a panic or OOB read.
- JSON↔blobmsg mapping mirrors ubus's own: object→TABLE, array→ARRAY, string→STRING, bool→INT8,
  integer→INT32 (INT64 on i32 overflow), float→DOUBLE (BE u64 of the f64 bits).
- **Client = one persistent connection, reentrant** (one `Client` per thread/loop, no globals). All
  socket work is errno-encoded `std.os.linux`, bounded recv timeout, `SOCK_CLOEXEC`, 1 MiB reply cap
  (= ubusd's `UBUS_MAX_MSG_LEN`). Each request gets a fresh sequence number, replies matched on it
  (stragglers skipped); the HELLO greeting is required.
- **Two daemon behaviors the ubusd daemon requires** (both mandatory): an INVOKE must carry
  `UBUS_ATTR_DATA` even with no args (INVALID_ARGUMENT otherwise); INVOKE reply choreography is
  ack-STATUS (no OBJID) → DATA → completion-STATUS (OBJID + return code), while ubusd-internal
  objects (event registry) answer directly with a single STATUS. `subscribe` opens a dedicated
  connection (events are unsolicited INVOKEs that must not interleave with request/reply) and its
  registered "object" id must be a blobmsg INT32, not the generic JSON-int mapping.
- Hardening choices (wire format untouched): one persistent connection with sequence-
  matched replies; LOOKUP replies drained to closing STATUS; `SOCK_CLOEXEC`; reply cap is ubusd's
  own limit; HELLO required; no hidden allocators. There is no CLI-fallback layer — this module
  reports typed errors.

## Threat model / out of scope
Trust boundary is a bit-flipped or hostile daemon reply: walkers + JSON decoder are fuzzed and
bounds-check every length, so no reply can panic, loop, read OOB, or blow the stack (nesting cap);
reply-size cap bounds memory. Does not authenticate the daemon or peers (ubus access control is
unix-socket permissions + ubusd ACLs — out of scope), does not implement the ubus server/
object-provider side, no TLS/remote transport (local unix socket only). JSON args must be an object
whose values all have a blobmsg mapping (null/non-object → `error.Unsupported`).

## Verification
A scripted in-process daemon (unix socket + thread) speaks the exact reply choreography and asserts
both required daemon behaviors from the daemon side, covering list/filtered-list/invoke-with-args/
void/error/unknown-object and subscribe→event-delivery→EOF. Codec tests pin golden wire bytes
(hand-derived from the documented libubox `blob.h`/`blobmsg.h` format), decode nested TABLE/ARRAY,
round-trip JSON→blobmsg→JSON, split INT32/INT64 at the i32 boundary, golden DOUBLE bits, reject
truncated/bad-length/OOB/hostile-nesting/oversized input; a `std.testing.fuzz` case asserts walkers +
JSON decoder never crash/loop/read OOB. A real-ubusd integration test runs when
`/var/run/ubus/ubus.sock` exists and skips cleanly otherwise.

**Real-daemon capture (closes the byte-parity backlog below).** `codec.zig`'s "real ubusd capture"
section freezes bytes from a single real run inside the `scripts/vm/` OpenWRT VM (25.12.4): a
throwaway byte-relay (never committed) was spliced between the real `ubus` CLI and the real `ubusd`
via `ubus -s <socket>`, capturing the exact wire bytes of a LOOKUP + reply, an INVOKE with an empty
args gotcha + reply, and an INVOKE with JSON args + reply, across four different real provider
objects (`system.board`, `system.info`, `network.device.status`, `network.interface.lan.status`).
The frozen DATA replies are asserted to decode **byte-identical** to the real `ubus -S` CLI's own
JSON stdout for the same calls (captured in the same run) — a genuine textual byte-parity check, not
merely "parses without error". Two encode-direction tests independently confirm this module's own
`encodeMessage`/`appendAttr*`/`encodeArgs` reproduce the real `ubus` CLI's INVOKE bytes exactly, for
both the empty-args and the JSON-args case. The real signature table also confirms this module's
`BM.*` type constants match the daemon's own encoding (`"Boolean"` decodes to `7 == BM.INT8`,
`"Table"` to `2 == BM.TABLE`, etc.).

**Findings from the capture:**
- The client-visible INVOKE reply is exactly DATA then a completion STATUS (OBJID + status code) —
  confirmed across all four real provider objects above. No separate "ack STATUS (no OBJID)" was
  ever observed before DATA on the client's own connection, though `Client.invoke`'s loop already
  tolerates zero-or-more such acks before the completion, so this is not a functional bug — only the
  scripted mock daemon's ack is exercised by any test; the real corpus never hits that branch.
- The real `ubus` CLI independently confirms daemon gotcha #1 (an INVOKE always carries
  `UBUS_ATTR_DATA`, empty when there are no arguments) — previously verified only against this
  module's own scripted mock daemon.
- No `BM.DOUBLE` or `BM.INT16` value appears anywhere in this real corpus (`ubus`'s own blobmsg-JSON
  codec only ever emits STRING/INT8(bool)/INT32/INT64/TABLE/ARRAY); both remain covered only by the
  hand-derived goldens, which is documented rather than left silently unstated.
- No disagreement between this module's encoder and the real client's bytes was found.

## Backlog / deferred
None beyond the documented DOUBLE/INT16 real-corpus gap noted above (the module's own encode/decode
API supports both; the real daemon's JSON codepath simply never produces them on the captured
OpenWRT build).

## Status
`extract · linux (codec: any) · client · reentrant` + deps: none (std only — `std.json` for the
JSON↔blobmsg mapping) — canonical source is `pub const meta` in src/root.zig.

## Anchoring

**Anchor grade:** class A · oracle MIXED

- **Class A** — wire/interop format — other implementations must byte-agree with it.
- **Oracle MIXED** — anchored for some paths, self for others — the evidence below names which.

**What the tests actually contain.** hand-derived libubox-spec goldens (SELF); live ubusd peer test when reachable (EXTERNAL)

**How it got there.** The anchoring work landed. DONE 463e443: real ubusd captures; ARRAY/TABLE tag swap blind to all 32 old tests
