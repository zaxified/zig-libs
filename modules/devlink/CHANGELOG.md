# devlink — changelog

Newest first. See the root [`CHANGELOG.md`](../../CHANGELOG.md) for which
release tag each entry shipped in, and `CONVENTIONS.md` §8 for the policy.

## Unreleased

- **2026-09-07** — **all seven fuzz harnesses fetched their input and threw it away — and the
  collapse made them look perfect.** Each opened `smith.bytes(&buf)` and then sliced the buffer
  to `smith.valueRangeAtMost(u16, 0, buf.len)`; a `Smith` ranged draw reads eight input octets
  as a little-endian u64 and returns the range MINIMUM unless that word already lies inside the
  range, so the length was 0 for every seed and every parser was called with an empty attribute
  list. ⛔ And an empty attribute list is a **legal** devlink reply — every field of a port, a
  device, a reporter, a parameter, a region or a resource is optional — so every parser
  *succeeded* on it. Measured with the old draws in place against the new corpora:
  `fuzzPort` 7 of 7 "decoded", `fuzzDev` 6 devices and 6 infos, `fuzzHealth` 6 of 6,
  `fuzzParam` 7 of 7, `fuzzRegion` 7 of 7, `fuzzResource` 7 of 7, `fuzzNotification` 5 of 5 —
  a clean sheet across the module while not one TLV was ever walked. All seven now draw with
  one `smith.slice(&buf)` call and carry a corpus built at run time by the value tests' own
  builders and this module's encoders (a devlink attribute is a netlink TLV, whose length and
  scalars are HOST byte order, so a hex corpus would be a little-endian one). After:
  `fuzzPort` 4 ports decoded; `fuzzDev` 5 devices, 3 infos, 4 versions; `fuzzHealth` 4 decoded
  of which 2 carry a reporter name; `fuzzParam` 5 decoded of which 4 carry a value;
  `fuzzRegion` 5 decoded and 64 octets assembled; `fuzzResource` 5 decoded and 11 resources
  found; `fuzzNotification` 3 parsed and 2 recognised as notifications. Every harness carries a
  corpus guard pinning both numbers — the "decoded" count alone cannot distinguish a real reply
  from the empty one, which is exactly how this hid.
- **2026-09-07** — `client.fuzzNotification` also drew its genl command byte with
  `valueRangeAtMost(u8, 0, 255)`, so `cmd` was **0 on every round** — not a devlink command at
  all, and `Notification.isNotification()` was therefore false for every input the harness ever
  built. The command is a full-width `smith.value(u64)` now and travels in the seed.

- **2026-09-02** — **Audit (drift campaign): 2 MEDIUM, 4 LOW.** ⭐ No memory-safety or
  wrong-write defect is live; the new public `buildX` request layer is well anchored (the request
  goldens are real `strace` captures of iproute2 6.19.0, and reply goldens now exist twice — UAPI
  constructed *and* captured from a live `netdevsim`, with iproute2's own decode as the oracle).
  What the audit found is two verification holes, one on the hardware-write path.
  **MEDIUM — the standing UAPI gate checked NONE of this module's 35 kernel-ABI enum values.**
  `scripts/check-uapi-consts.py` built `DEVLINK_PORTTYPE_ETH` from `PortType.eth` where the
  kernel spells it `DEVLINK_PORT_TYPE_ETH`, so every member of eight enums landed in an
  "unresolved" bucket that was never printed — not even under `--verbose` — and never failed.
  **20 of the 35 could be given a wrong value with the whole suite green**, including the ones
  that drive `setPortType`, `setParam` (device NVRAM) and `setEswitch`. The checker snake_cases
  CamelCase namespaces now, strips Zig's keyword-escape underscore, takes a per-module
  `namespace_aliases` map read out of the header (`InlineMode` → `ESWITCH_INLINE_MODE`,
  `ParamType` → `VAR_ATTR_TYPE`, …), **prints every unresolved name**, and **fails** when a
  module exceeds its recorded budget. devlink: 154 → **187 matched, 7 unresolved** (all six
  repo-local sizing constants plus one name this host's header does not carry). ⚠ The same
  blind spot is recorded for `ethtool` (120 unresolved) and `nl80211` (25) — budgets pin them
  where they are, and resolving them is follow-up work.
  **MEDIUM — the `value_max` bound between a wire attribute and a 128-byte buffer had no test.**
  Widening it left the suite green in both modes; removing it makes a 200-byte
  `PARAM_VALUE_DATA` panic in Debug (`index out of bounds: index 200, len 128`) and, in
  **ReleaseFast, be accepted silently** — the `@memcpy` runs past `Bytes.buf` and clobbers the
  `len` field with the payload's own bytes. Pinned at `value_max` and `value_max + 1`, on both
  the `.binary` and the unknown-type branch.
  **LOW — `newSnapshot` was the one single-object method with no reply correlation.** Seven
  siblings call `checkHandleEcho`; this one called neither that nor a region-name compare, so a
  reply naming a different device and region handed back its snapshot id — which then selects
  what `readRegion` reads. Both checks now.
  **LOW — `max_walk_messages` bounded datagrams, not messages**, so the documented 65 536-message
  ceiling was really 65 536 datagrams of up to 16 MiB each. Counted where a message is one.
  **LOW — docs:** `EventSocket.waitForNotification` promised "exactly one `recvmsg`" while a
  datagram of non-devlink messages costs another; corrected in both places it was claimed.
  **LOW — an unguarded slice in the live kernel-echo test** (`m.payload[4..]`, then
  `echoed[0..16]`) would panic in Debug on a short capped ACK. Bounded.
  Ledger: `~/CML/20260931-zig-libs-audit/devlink.md`.

- **2026-08-24** — Public request builders: one `buildX` per request-performing
  `Devlink` method (`buildDevices`, `buildInfo`, `buildPorts`, `buildPort`,
  `buildSetPortType`, `buildSplitPort`, `buildUnsplitPort`, `buildParams`,
  `buildParam`, `buildSetParam`, `buildResources`, `buildSetResourceSize`,
  `buildRegions`, `buildRegion`, `buildNewSnapshot`, `buildDelSnapshot`,
  `buildReadRegion`, `buildHealthReporters`, `buildHealthReporter`,
  `buildRecoverHealthReporter`, `buildEswitch`, `buildSetEswitch`), each
  returning a complete netlink message for a caller-supplied family id and
  sequence number. Additive: the client methods now call these, so every
  command has exactly one encoder. Brings devlink in line with the sibling
  `nl80211` and `nftables` bindings, which already expose request encoding.
- **2026-08-06** — Security audit: six findings fixed (part of the collection-wide
  audit; the root changelog records no further detail than this). Verified against a
  live capture from `devlink` (iproute2 6.19) over libmnl — used in-repo as a black-box
  capture oracle.
- **2026-07-23** — New module: Linux devlink over genetlink — device/port enumeration,
  port split/unsplit, parameter and resource inspection, region snapshots, health
  reporters and eswitch mode.
