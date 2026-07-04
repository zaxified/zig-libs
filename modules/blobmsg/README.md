# blobmsg

Native **ubus** client + **blob/blobmsg** wire codec for OpenWRT's typed
message bus: list objects (with decoded method signatures), invoke methods
with JSON arguments, and subscribe to events — no `ubus` CLI shell-outs, no
libubox binding, no libc. No pure-Zig ubus/blobmsg implementation exists
elsewhere (goubus is HTTP/rpcd, python-ubus/golangwrt are cgo wrappers).

- **Status:** `extract` — carved out of the authors' axp agent, where it
  replaced per-read `ubus` CLI forks on real OpenWRT devices.
- **Model after:** the OpenWRT libubox/ubus wire format (clean-room).
- **Platform:** the codec (`codec.zig`) is platform-pure — no I/O, compiles
  and tests anywhere; the socket client is linux (raw `std.os.linux`
  errno-encoded syscalls — a conscious ceiling). **Role:** client.
  **Concurrency:** reentrant (no globals; one `Client` per thread/loop).
- **Deps:** none (std only — `std.json` for the JSON↔blobmsg mapping).

Provenance: extracted from the authors' axp project (`axp-core/src/ubus.zig`;
same authors, Apache-2.0, relicensed MIT by the copyright holder). The wire
format was clean-room ported byte-for-byte from the OpenWRT UAPI/C sources
(openwrt/libubox `blob.h`/`blobmsg.h`, openwrt/ubus `ubusmsg.h`/
`libubus-io.c` — design reference only, no source copied) and byte-parity
verified against `ubus -S` on real hardware. See `NOTICE`.

## API

```zig
const blobmsg = @import("blobmsg");

var c = try blobmsg.Client.open(gpa, null); // tries /var/run/ubus/ubus.sock, /var/run/ubus.sock
defer c.close();

// `ubus list` — objects + ids + method signatures decoded to JSON text.
const objs = try c.list(null); // or c.list("network.*")
defer blobmsg.freeObjects(gpa, objs);
for (objs) |o| _ = .{ o.name, o.id, o.signature_json };

// `ubus call` — optional JSON args in, decoded JSON result out ("{}" for void).
const board = try c.invoke("system", "board", null);
defer gpa.free(board);
const set = try c.invoke("uci", "set", "{\"config\":\"system\"}");
defer gpa.free(set);

// `ubus listen` — dedicated event connection; drain with poll().
var es = try c.subscribe("network.*"); // null = all events
defer es.close();
var lines: std.ArrayList(u8) = .empty;
defer lines.deinit(gpa);
const eof = try es.poll(&lines); // appends `{"<event>":<data>}\n` per event
```

Low-level, for custom messages (all `pub`): `blobmsg.codec` — bounds-checked
`AttrIterator` (raw blob attrs) and `FieldIterator` (typed blobmsg fields),
`decodeToJson`/`decodeToJsonAlloc`/`streamInto` (blobmsg → JSON),
`encodeArgs`/`encodeJson` (JSON → blobmsg), the `appendField`/`appendString`/
`appendInt32`/… blobmsg builders, the `appendAttr*` raw ubus-attr builders,
`encodeMessage`/`parseMsgHeader` framing, and the `MSG`/`ATTR`/`BM` wire
constants.

## Wire format (as implemented, byte-exact)

```text
ubus_msghdr:  u8 version(0) | u8 type | u16 seq (BE) | u32 peer (BE)   (8 bytes)
blob_attr:    u32 id_len (BE) | data | pad-to-4
              id_len = (EXTENDED<<31) | (id<<24) | len;  len counts the 4B header
blobmsg:      blob_attr with EXTENDED set, id = value type;
              data = blobmsg_hdr (u16 namelen BE + name + NUL + pad-to-4) + value
```

A message = msghdr + one top blob_attr (id 0) wrapping the children.
Top-level ubus attrs are raw blob attrs (OBJID/STATUS = BE u32,
METHOD/OBJPATH = NUL-terminated string, DATA/SIGNATURE = nested blobmsg);
blobmsg value types: INT8 = bool, INT16/32/64 = signed BE, DOUBLE = BE u64 of
the f64 bits, STRING = NUL-terminated, TABLE/ARRAY = nested. JSON mapping
(mirrors ubus's own parser): object→TABLE, array→ARRAY, string→STRING,
bool→INT8, integer→INT32 (INT64 when it overflows i32), float→DOUBLE.

## Design notes

- **The codec is the security boundary.** Every id_len/namelen is validated
  against the enclosing buffer before any slice is formed; scalar sizes are
  exact (per libubox `blobmsg_check_attr`); each walk step advances ≥ 4
  bytes, so iteration is capped by construction; JSON nesting is capped at
  `max_depth` (64) so hostile 16 MiB-deep nesting cannot blow the stack.
  Malformed input → `error.Truncated`/`BadLength`/`TooDeep`, never a panic
  or OOB read. Walkers and the JSON decoder are fuzzed (`std.testing.fuzz`).
- **Two daemon gotchas ported verbatim from the seed** (ubusd depends on
  both): an INVOKE must carry `UBUS_ATTR_DATA` even with no arguments
  (INVALID_ARGUMENT otherwise), and the INVOKE reply choreography is
  ack-STATUS (no OBJID) → DATA → completion-STATUS (OBJID + return code) —
  while ubusd-internal objects (the event registry) answer directly with a
  single STATUS. The event "object" id must be blobmsg INT32, not the
  generic JSON-int mapping.
- **Deltas vs the seed** (hardening, wire format untouched): one persistent
  connection with per-request sequence numbers and reply matching on seq
  (the seed reconnected per call and ignored seq); LOOKUP replies are
  drained to their closing STATUS so the stream stays in sync; SOCK_CLOEXEC
  on the socket; the reply cap raised to ubusd's own 1 MiB UBUS_MAX_MSG_LEN;
  the HELLO greeting is required (its peer = the daemon-assigned
  `client_id`); no hidden allocators (the seed drained HELLO with
  `page_allocator`). The seed's CLI-fallback layer stayed in axp — this
  module reports errors and lets the caller decide.
- **Testing without hardware:** a scripted in-process daemon (unix socket +
  thread) speaks the exact reply choreography, asserting both gotchas from
  the daemon side; golden byte tests pin the wire format; a real-ubusd
  integration test runs when `/var/run/ubus/ubus.sock` exists and skips
  cleanly otherwise. Ground truth remains the seed's qemu parity check
  (native output == `ubus -S`).
