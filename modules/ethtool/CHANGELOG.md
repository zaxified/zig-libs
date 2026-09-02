# ethtool — changelog

Newest first. See the root [`CHANGELOG.md`](../../CHANGELOG.md) for which
release tag each entry shipped in, and `CONVENTIONS.md` §8 for the policy.

## Unreleased

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
