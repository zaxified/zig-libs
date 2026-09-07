# ethtool — changelog

Newest first. See the root [`CHANGELOG.md`](../../CHANGELOG.md) for which
release tag each entry shipped in, and `CONVENTIONS.md` §8 for the policy.

## Unreleased

- **2026-09-07** — **all four fuzz harnesses fetched their input and threw it away — and the
  collapse made them look perfect.** Each opened `smith.bytes(&raw)` and then sliced the buffer
  to `smith.valueRangeAtMost(u16, 0, raw.len)`; a `Smith` ranged draw reads eight input octets
  as a little-endian u64 and returns the range MINIMUM unless that word already lies inside the
  range, so the length was 0 for every seed and every decoder ran on an empty attribute list.
  ⛔ And an empty list is a **legal** reply throughout this module — `bitset.zig` even has a
  test called "empty bitset decodes to an empty set, not an error", and `params.zig` has
  "absent attributes stay null (n/a), they do not become zero". Measured with the old draws in
  place against the new corpora: `fuzzBitset` 10 of 10 "parsed", `fuzzParams` **36 of 36**
  (seed, decoder) pairs decoded, `fuzzStats` 8 of 8 twice over, `fuzzNotification` 5 of 5 — a
  clean sheet, with **0 bits set, 0 fields recovered, 0 statistics groups, 0 strings and 0
  mcast group ids.** All four now draw with one `smith.slice` call and carry a corpus built at
  run time by this module's own encoders (an ethtool attribute is a netlink TLV, whose length
  and scalars are HOST byte order). After: `fuzzBitset` 5 parsed and 11 bits set; `fuzzParams`
  15 pairs decoded and 22 fields recovered — the pair count went *down*, which is the point;
  `fuzzStats` 3 stats and 5 string-set replies, 3 groups and 2 strings; `fuzzNotification` 4
  parsed, 2 recognised as notifications and 1 group id. Each harness carries a corpus guard
  pinning both numbers.
- **2026-09-07** — two knob draws with the same defect. `client.fuzzNotification` drew the
  ethtool reply command with `valueRangeAtMost(u8, 0, 255)`, so `cmd` was **0 on every round**
  and `Notification.isNotification()` was false for every input the harness ever built.
  `bitset.fuzzBitset` drew its bit index with `valueRangeAtMost(u32, 0, 100_000)`, so `isSet`,
  `inMask` and `nameOf` were asked about **bit 0** every time — the one index that reaches no
  bounds arithmetic in any of the three. Both are full-width `smith.value(u64)` draws now and
  both travel in the seed.

- **2026-09-02** — Drift re-audit (W2, window `d163578..HEAD`). Six findings, all fixed:

  - **Breaking (error set):** the bitset encoders (`appendCompact`, `appendNameList`,
    `appendNamedValues`, `appendIndexedValues`) now return `bitset.BuildError`
    (`{OutOfMemory, InvalidRequest}`) instead of the decode-side `bitset.Error`. An encoder
    cannot meet a truncated message; it can only be handed arguments the wire format cannot
    express. Reporting those as `codec.Error.BadLength` made the client classify a
    caller-argument fault as `MalformedReply` — the *peer's* fault, for a request that was
    never sent. `client.mapParse` now takes the parsers' concrete error set instead of
    `anyerror`, so a build error can no longer reach it and a new error variant can no longer
    land silently on `MalformedReply`.
  - **Breaking (signature):** `features.SetResult.honouredByName` returns `?bool`. A compact
    `FEATURES_SET_REPLY` carries no names, so the question is unanswerable — it used to answer
    `true` (honoured) for every feature, including on a reply that had refused all of them.
    Same shape as its sibling `bitset.isSetByName`.
  - The C-10 device-echo binding now covers **every** path that collects a reply, not just
    `exchangeGet`: the SETs (`setLinkInfo`, `setLinkModes`, `setRings`, `setChannels`,
    `setCoalesce`, `setPause`, `setModulePowerPolicy`, `setFeaturesBy*`) and the three GETs that
    collect their own reply (`stats`, `stringSet`, `moduleEeprom`). A `*_SET_REPLY` is the
    message a caller reads to decide whether a change stuck, so it is exactly the one that must
    not be about another device. A test counts the two call sites against each other in the
    module's own source, so a new path cannot skip the check.
  - `parseEeprom` tracks the presence of `MODULE_EEPROM_DATA` with a flag, not with
    `data.len != 0` — a first `DATA` of length 0 let a second one through and silently win.
  - Tests: the repo-wide `codec.nestEnd` fix of 2026-09-02 was mapped at every call site here
    but driven past 65535 bytes by nothing, so deleting the whole guard left the suite green.
    Three encoders are now each pushed over the limit, and the compact-bitset ceiling is pinned
    at exactly `max_bits` and `max_bits + 1`.
  - Docs: `SPEC.md` and `goldens.zig` pointed at `client.zig`'s `setFeaturesImpl`, which the
    2026-08-24 refactor replaced with `features.buildSetFeaturesByName`/`ByIndex`.

  Out of scope but found here: `scripts/check-uapi-consts.py` was resolving 207 of this
  module's 340 constants and silently skipping 120 — every reply/notification message id, every
  `StringSetId`, and the `Port`/`Duplex`/`MdiX`/`Transceiver`/`MasterSlave*` enums the reply
  decoders `@enumFromInt` into. All 120 turned out to be **correct**; the gate simply could not
  see them. It now resolves 325 of 340 with 2 unresolved (`I2C_ADDRESS_LOW`/`_HIGH`, which have
  no kernel spelling).

- **2026-09-02** — `codec.nestEnd` became fallible (`netlink`, audit: it used to truncate a nest
  longer than 65535 bytes silently). Its `AttrTooLong` is mapped here onto this module's existing
  "the request cannot be encoded" error at each call site, the way `appendAttr`'s already was.

- **2026-08-24** — Additive API: public offline request encoders, one per request-performing
  `Ethtool` method — `buildLinkInfo`, `buildSetLinkInfo`, `buildLinkModes`, `buildSetLinkModes`,
  `buildLinkState`, `buildRings`, `buildSetRings`, `buildChannels`, `buildSetChannels`,
  `buildCoalesce`, `buildSetCoalesce`, `buildPauseParams`, `buildSetPause`, `buildFeatures`,
  `buildSetFeaturesByName`, `buildSetFeaturesByIndex`, `buildStats`, `buildStringSet`,
  `buildModuleInfo`, `buildSetModulePowerPolicy`, `buildModuleEeprom`. Each returns a complete
  netlink datagram for a caller-supplied family id and sequence number. The sibling `nl80211`
  and `nftables` bindings already answered this way; `ethtool` did not. The client methods now
  call these encoders instead of assembling their own messages, so there is exactly one encoder
  per operation. `client.BitsetForm` is now an alias of the new `header.BitsetForm`; the shared
  `nlmsghdr`+`genlmsghdr` frame is `header.beginRequest`/`header.finishRequest`.
- **2026-08-06** — Security audit: five findings fixed, one documented as accepted (not
  defects) — part of the collection-wide audit. Verified: Genuine, and stronger than the
  module claims.
- **2026-07-22** — New module: Ethernet device control over the ethtool netlink family —
  link settings/state, ring/coalesce/pause/channel parameters, feature flags, per-queue
  and driver statistics, EEPROM/module info.
