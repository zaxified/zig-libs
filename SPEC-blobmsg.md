# SPEC — `blobmsg`

Native **ubus** client + **blob/blobmsg** wire codec (OpenWRT's typed message bus). Wave P2 (AXP
extraction). `extract · linux · client · reentrant` (the codec is platform-pure; the socket client
is Linux). **Seed: extract from `~/workspace/axp/axp-core/ubus.zig`** (same authors' Apache-2.0
code, relicensed MIT) — that code was itself **clean-room ported byte-for-byte from the OpenWRT C
wire sources** (openwrt/libubox `blob.h`/`blobmsg.h`, openwrt/ubus `ubusmsg.h`/`libubus-io.c`) and
**byte-parity-verified against `ubus -S` on real hardware**. Deps: **none (std only — `std.json`
for JSON↔blobmsg)**. New `build.zig` entry `.{ .name = "blobmsg" }`.

## Why

OpenWRT's real control API is ubus (network/dhcp/system/wireless/firewall/service/file/log…).
**No pure-Zig ubus/blobmsg lib exists** (goubus=HTTP/rpcd, python-ubus/golangwrt=cgo wrappers) — the
axp module is a genuinely novel clean-room impl. High reuse for any OpenWRT/ubox tooling.

## Scope

1. **blob/blobmsg codec (platform-pure, byte-parity, the security-critical core):** encode/decode
   the wire format exactly as the seed does — top `blob_attr` (id 0) wrapping children; blob
   `id_len` BE = `(EXTENDED<<31)|(id<<24)|len` where len counts the 4B header, attrs **4-byte
   padded**; blobmsg = a blob attr with EXTENDED set, data = `blobmsg_hdr` (namelen BE16 + name +
   NUL + pad-to-4) + value; types INT8→bool, INT16/32/64 signed, DOUBLE=BE64 bits, STRING, TABLE/
   ARRAY nested. **Bounds-checked** — a truncated/hostile buffer returns an error, never OOB/panic.
   `JSON↔blobmsg`: decode blobmsg→`std.json`-shaped value/text; encode JSON args→blobmsg (object→
   TABLE, array→ARRAY, string→STRING, bool→INT8, int→INT32/INT64, float→DOUBLE).
2. **ubus unix-socket client:** connect to the ubus socket (`/var/run/ubus/ubus.sock`, overridable),
   the msghdr (8B: version u8, type u8, seq BE16, peer BE32), and the operations the seed has:
   **LOOKUP** (list objects/methods), **INVOKE** (call `<object>.<method>` with optional JSON args →
   blobmsg-decoded result), and **event register/listen** (subscribe + drain events). Errno-encoded
   `std.os.linux` unix socket (repo no-libc discipline). Port the seed's two decisive daemon
   gotchas verbatim (INVOKE must carry a `UBUS_ATTR_DATA` even when empty; the ack-STATUS → DATA →
   completion-STATUS(objid) reply sequence).

## Public API sketch (final = the seed's shape)

```zig
// codec (platform-pure, separately testable)
pub const blob = struct { pub const Iterator = ...; pub fn encode(...); };
pub fn decodeToJson(gpa, blobmsg_bytes, out: *std.Io.Writer) !void;
pub fn encodeArgs(gpa, json_value) ![]u8;   // JSON args → blobmsg DATA
// client
pub const Client = struct {
    pub fn open(gpa, path: ?[]const u8) !Client;   pub fn close(*Client) void;
    pub fn list(self, pattern: ?[]const u8) ![]Object;         // LOOKUP
    pub fn invoke(self, object, method, args_json: ?[]const u8) ![]u8;  // → blobmsg-decoded JSON
    pub fn subscribe(self, pattern) !EventStream;              // register + drain
};
```

## Acceptance / verification

- **Offline unit tests (the codec must be byte-exact + bulletproof — port the seed's):** blob/
  blobmsg encode → **golden wire bytes** (hand-crafted, matching `ubus -S` output as the seed
  verified); decode of canned frames → the right typed values incl. nested TABLE/ARRAY; JSON→blobmsg
  →JSON round-trip; truncated / bad-len / OOB attrs → error (no panic — fuzz the walker); the
  id_len/EXTENDED/padding edge cases.
- **Integration (gate via `error.SkipZigTest` if the ubus socket is absent — it almost certainly is
  in this environment):** if `/var/run/ubus/ubus.sock` exists, `list()` returns objects and
  `invoke("system","board",null)` decodes typed data; otherwise SKIP cleanly.
- `zig build test-blobmsg` + `zig build test` (all) green, Debug + ReleaseFast; `zig fmt --check`
  clean. Registered with no deps.

## Notes for the implementer

- Use the **zig skill** for Zig 0.16 (errno-encoded `std.os.linux` unix socket, `std.json`
  Value/Stringify, BE integer reads). No libc.
- EXTRACTION: the seed is a proven byte-parity port — **keep the wire format exactly**, port its
  tests, adapt module layout + any 0.16 drift. The codec is the value; make it separately testable
  from the socket.
- Provenance: README `Provenance:` line = "extracted from axp `axp-core/ubus.zig` (same authors,
  Apache-2.0, relicensed MIT); the wire format is clean-room from the OpenWRT UAPI/C sources — see
  NOTICE". Add a NOTICE design-ref entry (openwrt libubox/ubus, LGPL-2.1/ISC — **wire format only,
  clean-room, no source copied**; byte-parity verified vs `ubus -S`). SPDX MIT header.
- Codec is portable (any); the socket client is Linux — structure so the codec compiles/tests
  everywhere and only the client is Linux-gated.
