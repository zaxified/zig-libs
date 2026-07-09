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
void/error/unknown-object and subscribe→event-delivery→EOF. Codec tests pin golden wire bytes, decode
nested TABLE/ARRAY, round-trip JSON→blobmsg→JSON, split INT32/INT64 at the i32 boundary, golden
DOUBLE bits, reject truncated/bad-length/OOB/hostile-nesting/oversized input; a `std.testing.fuzz`
case asserts walkers + JSON decoder never crash/loop/read OOB. A real-ubusd integration test runs
when `/var/run/ubus/ubus.sock` exists and skips cleanly otherwise. Ground truth is a qemu parity
check (native output == `ubus -S`). Run: `zig build test-blobmsg`.

## Backlog / deferred
Re-run the qemu `ubus -S` parity check against the module on real hardware (not yet done).

## Status
`extract · linux (codec: any) · client · reentrant` + deps: none (std only — `std.json` for the
JSON↔blobmsg mapping) — canonical source is `pub const meta` in src/root.zig.
