# SPEC — `blobmsg`

**Purpose** — Talk OpenWRT's ubus message bus natively: list objects (with decoded method
signatures), invoke methods with JSON arguments, and subscribe to events — over the ubus unix
socket, with no `ubus` CLI shell-outs, no libubox binding, no libc. Pairs a platform-pure
blob/blobmsg wire **codec** (`codec.zig`) with a Linux socket **client**. No pure-Zig ubus/blobmsg
implementation exists elsewhere (goubus is HTTP/rpcd; python-ubus/golangwrt are cgo wrappers).

**Model after / Seed** — the OpenWRT libubox/ubus wire format, clean-room. Extracted from the
authors' axp `axp-core/src/ubus.zig` (Apache-2.0, relicensed MIT), where it replaced per-read `ubus`
CLI forks on real devices. The wire format was clean-room ported byte-for-byte from the OpenWRT C
sources (libubox `blob.h`/`blobmsg.h`, ubus `ubusmsg.h`/`libubus-io.c` — ISC / LGPL-2.1, **design
reference only, no source copied for this extraction**) and byte-parity verified against `ubus -S`
on real hardware. See `NOTICE`.

**Design & invariants**
- **The codec is the security boundary, and it is platform-pure.** `codec.zig` has no I/O and
  compiles/tests on any OS. Big-endian, 4-byte-aligned wire format: `blob_attr`
  `id_len = (EXTENDED<<31)|(id<<24)|len` (len counts the 4-byte header, pad does not); a `blobmsg`
  is a blob_attr with EXTENDED set, `id` = value type, data = `blobmsg_hdr` (BE u16 namelen + name +
  NUL + pad) + value. Every id_len/namelen is validated against the enclosing buffer before any
  slice is formed; scalar sizes are exact (per libubox `blobmsg_check_attr`); each walk step advances
  ≥4 bytes (iteration capped by construction); JSON decode caps nesting at `max_depth` (64). Malformed
  input → `error.Truncated`/`BadLength`/`TooDeep`, never a panic or OOB read.
- **JSON↔blobmsg mapping mirrors ubus's own:** object→TABLE, array→ARRAY, string→STRING, bool→INT8,
  integer→INT32 (INT64 on i32 overflow), float→DOUBLE (BE u64 of the f64 bits).
- **Client = one persistent connection, reentrant.** One `Client` per thread/loop (no globals). All
  socket work is errno-encoded `std.os.linux` (Linux-only by `@compileError` elsewhere), with a
  bounded recv timeout, `SOCK_CLOEXEC`, and a 1 MiB reply cap (= ubusd's `UBUS_MAX_MSG_LEN`). Each
  request gets a fresh sequence number and replies are matched on it, so a prior request's stragglers
  are skipped rather than misread; the HELLO greeting (its peer = the daemon-assigned client id) is
  required.
- **Two daemon behaviors ported verbatim** (ubusd depends on both): an INVOKE must carry a
  `UBUS_ATTR_DATA` attr even with no args (INVALID_ARGUMENT otherwise); the INVOKE reply
  choreography is ack-STATUS (no OBJID) → DATA → completion-STATUS (OBJID + return code), while
  ubusd-internal objects (the event registry) answer directly with a single STATUS. `subscribe`
  opens a dedicated connection (events are unsolicited INVOKEs that must not interleave with the
  request/reply stream) and the "object" id it registers must be a blobmsg INT32, not the generic
  JSON-int mapping.

**Threat model / out of scope** — Trust boundary is a bit-flipped or hostile daemon reply: the codec
walkers and JSON decoder are fuzzed and bounds-check every length, so no reply can panic, loop, read
OOB, or blow the stack (nesting cap). The reply-size cap bounds memory. It does **not** authenticate
the daemon or peers (ubus access control is the socket's unix permissions + ubusd ACLs — out of
scope here), does not implement the ubus *server*/object-provider side, does not do TLS/remote
transport (it is a local unix socket), and does not carry over the seed's CLI-fallback layer — this
module reports typed errors and lets the caller decide. JSON args must be an object whose values all
have a blobmsg mapping (null/non-object → `error.Unsupported`).

**Verification** — A scripted in-process daemon (unix socket + thread) speaks the exact reply
choreography — HELLO, LOOKUP DATA/STATUS, the ack→DATA→completion-STATUS(OBJID) sequence — and
asserts **both daemon gotchas from the daemon side** (every INVOKE carried DATA; args round-tripped),
covering list/filtered-list/invoke-with-args/void/error(UbusError)/unknown-object(NotFound) and the
subscribe → event-delivery → EOF path, all without OpenWRT hardware. Codec tests pin golden wire
bytes (blobmsg field encode, a LOOKUP frame, the empty-DATA INVOKE), decode nested TABLE/ARRAY,
JSON→blobmsg→JSON round-trips, the INT32/INT64 split at the i32 boundary, DOUBLE golden BE bits, and
reject truncated/bad-length/OOB attrs, hostile nesting depth, and oversized name/attr; a
`std.testing.fuzz` case asserts the walkers + JSON decoder never crash/loop/read OOB. A real-ubusd
integration test runs when `/var/run/ubus/ubus.sock` exists and skips cleanly otherwise. Ground truth
remains the seed's qemu parity check (native output == `ubus -S`).

**Status** — `extract · linux (codec: any) · client · reentrant` · deps: none (std only —
`std.json` for the JSON↔blobmsg mapping).
