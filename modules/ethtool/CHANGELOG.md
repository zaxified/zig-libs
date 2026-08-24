# ethtool — changelog

Newest first. See the root [`CHANGELOG.md`](../../CHANGELOG.md) for which
release tag each entry shipped in, and `CONVENTIONS.md` §8 for the policy.

## Unreleased

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
