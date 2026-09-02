# nl80211 — changelog

Newest first. See the root [`CHANGELOG.md`](../../CHANGELOG.md) for which
release tag each entry shipped in, and `CONVENTIONS.md` §8 for the policy.

## Unreleased

- **2026-09-02** — `codec.nestEnd` became fallible (`netlink`, audit: it used to truncate a nest
  longer than 65535 bytes silently). Its `AttrTooLong` is mapped here onto this module's existing
  "the request cannot be encoded" error at each call site, the way `appendAttr`'s already was.

- **2026-08-06** — Security audit: six findings fixed, one documented as accepted (not
  defects) — part of the collection-wide audit. Verified against a live capture from
  `iw` 6.17 over libnl — used in-repo as a black-box `strace` capture oracle;
  `wpa_supplicant` explicitly out of scope.
- **2026-07-22** — New module: Wi-Fi control over the nl80211 genetlink family —
  interface/wiphy enumeration, scan trigger + BSS results, connect/disconnect, station
  and link statistics, regulatory domain.
